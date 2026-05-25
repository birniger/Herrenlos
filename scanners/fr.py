"""
FR scanner — Fribourg
=====================
- EGRID enumeration : swisstopo identify API grid scan over FR bounding box
                      (replaces broken sequential numbering — real parcels only)
- Owner lookup      : POST  keycloak.fr.ch/rfpublic/v2TAffImmx01.jsp
- Herrenlos signals:
    Type 2 (not in Grundbuch): "INFORMATION INTROUVABLE" or response < 800 B
                                for a parcel that EXISTS in the official cadaster
    Type 1 (dereliktion):      valid full response, table.proprio exists but
                                no owner name found
- Rate limit        : 1 query per JSESSIONID → rotate session every query
- Throughput        : ~600-800 queries/hr (QUERIES_PER_SESSION=3)

FR commune codes (selcom) format:  "{bfs_nr} FR{sector_code}"
Full commune list fetched live from selectCommune.jsp on each session init.
"""

import re
import time
import logging
import requests
from bs4 import BeautifulSoup

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from db import get_conn, init_db, already_scanned, upsert_parcel, enum_cached, store_enum
from scanners.wfs_enum import enumerate_canton as wfs_enumerate_canton
from scanners.utils import is_herrenlos_owner_text, claim_possible_for

log = logging.getLogger("FR")

BASE     = "https://keycloak.fr.ch/rfpublic"
INDEX    = f"{BASE}/indexD.html"
COMMUNE  = f"{BASE}/selectCommune.jsp"
QUERY    = f"{BASE}/v2TAffImmx01.jsp"
UA       = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"

# FR bounding box (LV95 / EPSG:2056)
FR_EMIN, FR_EMAX = 2_556_000, 2_617_000
FR_NMIN, FR_NMAX = 1_153_000, 1_213_000
FR_GRID_STEP     = 200   # metres — ~93k grid points, one-time enumeration

SWISSTOPO_IDENTIFY = "https://api3.geo.admin.ch/rest/services/api/MapServer/identify"

NOT_FOUND_NEEDLE  = "INFORMATION INTROUVABLE"
NOT_FOUND_MAX_B   = 800    # bytes; valid response is ~8–10 KB
RATE_LIMIT_NEEDLE = "dépassement de la limite"
QUERIES_PER_SESSION = 3    # 3 queries per JSESSIONID → ~2-3x throughput vs 1
# Observed 2026-05-18: FR portal rate-limits session creation (~1 every 12s).
# QUERIES_PER_SESSION=1 gave ~300/hr because new_session() overhead (~4 s of
# HTTP round-trips) was paid for every single parcel. At QPS=3 the overhead
# is amortised across 3 parcels. ~27% of 2nd/3rd queries get session_exhausted;
# the scanner retries once with a fresh session. Even with retries this yields
# ~600-800/hr. Parcels that fail both attempts are stored with is_herrenlos=NULL
# and error='session_exhausted'; the next run picks them up automatically.
# 2-3 scan passes converge to ~100% coverage.


# ── Parcel enumeration via swisstopo ─────────────────────────────────────────

def enumerate_parcels_swisstopo(
        emin=FR_EMIN, emax=FR_EMAX,
        nmin=FR_NMIN, nmax=FR_NMAX,
        step=FR_GRID_STEP) -> list[dict]:
    """
    Grid scan using swisstopo federal identify API to enumerate real FR parcels.
    Returns list of {bfs_nr, parcel_nr, commune} dicts (only parcels that
    actually exist in the official cadaster).

    One-time cost: ~93k requests at 200m step ≈ 2.5h.
    Results are stored in the DB so subsequent runs skip already-scanned parcels.
    """
    seen:    set[tuple] = set()
    parcels: list[dict] = []
    session = requests.Session()

    e_range = range(emin, emax + 1, step)
    n_range = range(nmin, nmax + 1, step)
    total   = len(e_range) * len(n_range)
    checked = 0

    log.info("FR swisstopo grid scan: %d × %d = %d points at %dm step",
             len(e_range), len(n_range), total, step)

    for e in e_range:
        for n in n_range:
            checked += 1
            try:
                r = session.get(SWISSTOPO_IDENTIFY, params={
                    "geometry":      f"{e},{n}",
                    "geometryType":  "esriGeometryPoint",
                    "layers":        "all:ch.swisstopo-vd.amtliche-vermessung",
                    "tolerance":     0,
                    "mapExtent":     "0,0,1,1",
                    "imageDisplay":  "1,1,96",
                    "returnGeometry": "false",
                    "lang":          "de",
                    "sr":            2056,
                }, timeout=10)

                if r.status_code != 200:
                    continue

                for feat in r.json().get("results", []):
                    attrs = feat.get("attributes", {})
                    if attrs.get("ak", "").upper() != "FR":
                        continue
                    key = (str(attrs.get("bfsnr", "")), str(attrs.get("number", "")))
                    if key not in seen:
                        seen.add(key)
                        parcels.append({
                            "bfs_nr":    str(attrs.get("bfsnr", "")),
                            "parcel_nr": str(attrs.get("number", "")),
                            "commune":   attrs.get("label", ""),
                            # Capture EGRID so herrenlos parcels can be geocoded
                            # for the website map (otherwise lat/lng are NULL).
                            "egrid":     attrs.get("egris_egrid", ""),
                        })
            except Exception:
                pass

            if checked % 2000 == 0:
                log.info("Grid %d/%d  unique FR parcels=%d", checked, total, len(parcels))
            time.sleep(0.1)   # swisstopo fair-use

    log.info("Grid scan complete: %d unique FR parcels found", len(parcels))
    return parcels


# ── Session management ───────────────────────────────────────────────────────

def new_session() -> tuple[requests.Session, str, list[tuple]]:
    """
    Create a fresh JSESSIONID session and return:
      (session, xv1_token, commune_options)
    commune_options: list of (selcom_value, label)
    """
    s = requests.Session()
    s.headers["User-Agent"] = UA

    s.get(INDEX, timeout=15)

    r = s.get(COMMUNE, timeout=15)
    soup = BeautifulSoup(r.text, "lxml")

    xv1_tag = soup.find("input", {"name": "xv1"})
    if not xv1_tag:
        m = re.search(r'name\s*=\s*"xv1"\s+value\s*=\s*"([^"]+)"', r.text)
        xv1 = m.group(1) if m else ""
    else:
        xv1 = xv1_tag.get("value", "")

    options = [
        (opt["value"], re.sub(r'\s+', ' ', opt.get_text(strip=True)).strip())
        for opt in soup.select("select[name='selcom'] option")
        if opt.get("value", "").strip()
    ]
    log.debug("New FR session — %d communes, xv1=%s…", len(options), xv1[:8])
    return s, xv1, options


# ── Owner check ─────────────────────────────────────────────────────────────

def check_owner(session: requests.Session, xv1: str,
                selcom: str, parcel_nr: str) -> dict:
    """
    POST one FR owner query.

    Returns:
      error='parcel_not_found'  — parcel number doesn't exist in the Grundbuch
                                  (NOT flagged as herrenlos — was never registered)
      is_herrenlos=1            — parcel exists in cadaster, found in Grundbuch,
                                  but no owner registered (Type 1: dereliktion)
                                  OR parcel in cadaster but completely absent from
                                  Grundbuch (Type 2: never registered)
      is_herrenlos=0            — parcel has a registered owner
    """
    # Split compound parcel numbers into numeric prefix + suffix index.
    # The FR portal's form has TWO fields: noIm (numeric) and indexIm (suffix).
    # Before this split, parcels like "135ba", "29b", "118.00901" were sent
    # whole as noIm with indexIm="", which the portal rejected as INFORMATION
    # INTROUVABLE — generating 100% false-positive herrenlos flags for any
    # compound number.  Splitting matches the portal's expected form layout.
    m = re.match(r"^(\d+)(.*)$", parcel_nr or "")
    if m:
        no_im, index_im = m.group(1), m.group(2)
    else:
        no_im, index_im = parcel_nr, ""

    try:
        r = session.post(QUERY, data={
            "xv1": xv1, "selcom": selcom, "noIm": no_im,
            "indexIm": index_im, "rue": "", "noass": "", "selImm": "rechercher",
        }, headers={"Referer": COMMUNE}, timeout=20)

        raw  = r.text
        size = len(raw.encode())

        if RATE_LIMIT_NEEDLE in raw:
            return {"error": "session_exhausted", "is_herrenlos": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "owner": None, "owner_address": None, "raw_response": None}

        # A tiny response without NOT_FOUND_NEEDLE is a blank session-expired
        # page (body commented out, no content) — treat as session_exhausted so
        # the parcel gets retried, not permanently marked as herrenlos.
        if size < NOT_FOUND_MAX_B and NOT_FOUND_NEEDLE not in raw:
            return {"error": "session_exhausted", "is_herrenlos": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "owner": None, "owner_address": None, "raw_response": None}

        # With swisstopo enumeration we only query real cadaster parcels, so
        # "INFORMATION INTROUVABLE" means the parcel IS in the official survey
        # but has NO Grundbuch entry → Type 2 herrenlos.
        if NOT_FOUND_NEEDLE in raw:
            return {"owner": None, "owner_address": None,
                    "is_herrenlos": 1,
                    "herrenlos_type": "not_in_grundbuch", "claim_possible": 0,
                    "raw_response": raw[:300], "error": None}

        # Parse owner from table.proprio
        soup = BeautifulSoup(raw, "lxml")
        proprio = soup.find("table", class_="proprio")
        owner = None
        if proprio:
            rows = proprio.find_all("tr")
            owner_names = []
            herrenlos_texts = []
            skip = {"propriété", "miteigentum", "gesamteigentum",
                    "informations sur la propriété:", "angaben zur liegenschaft:"}
            for row in rows:
                td = row.find("td")
                if td:
                    text = td.get_text(" ", strip=True)
                    if not text or text.lower() in skip or len(text) <= 1:
                        continue
                    if is_herrenlos_owner_text(text):
                        herrenlos_texts.append(text)
                    else:
                        owner_names.append(text)
            owner = "; ".join(owner_names) if owner_names else None

        if owner is None:
            reason = f"explicit herrenlos text: {herrenlos_texts}" if herrenlos_texts \
                     else "no owner found in Grundbuch entry"
            log.info("Potential Type 1 herrenlos — %s (selcom=%s nr=%s)",
                     reason, selcom, parcel_nr)

        return {"owner": owner, "owner_address": None,
                "is_herrenlos": 0 if owner else 1,
                "herrenlos_type": None if owner else "dereliktion",
                "claim_possible": None if owner else claim_possible_for("FR", "dereliktion"),
                "raw_response": raw[:300] if owner is None else None,
                "error": None}

    except Exception as exc:
        return {"owner": None, "owner_address": None,
                "is_herrenlos": None,
                "herrenlos_type": None, "claim_possible": None,
                "raw_response": None, "error": str(exc)}


# ── Main scanner ─────────────────────────────────────────────────────────────

def scan(communes: list[str] | None = None,
         limit: int | None = None,
         skip_existing: bool = True,
         delay: float = 1.5):
    """
    Scan FR parcels for herrenlos detection.

    Enumeration: swisstopo identify API grid scan (real cadaster parcels only).
    This replaces sequential number guessing and eliminates false positives.

    communes  : list of selcom values to restrict scan (None = all FR communes)
    limit     : stop after N queries
    delay     : seconds between queries
    """
    init_db()

    log.info("Fetching FR commune list …")
    _, _, all_options = new_session()

    # Build selcom → label mapping.  Each FR commune has a SELCOM value of the
    # form "{bfs_nr} {NBIdent}" (e.g. "2234 FR221512").  Merged communes have
    # MULTIPLE selcoms for the same BFS — one per pre-merger sector.  Example:
    #   bfs=2234 La Brillaz has 3 sectors: Lentigny, Lovens, Onnens
    #   bfs=2236 Gibloux has 8 sectors after merger
    # We previously mapped {bfs → selcom} which kept only the LAST sector and
    # routed every parcel to it — so parcels in other sectors hit the wrong
    # selcom and returned INFORMATION INTROUVABLE → 100% false-positive
    # herrenlos for those sectors.
    #
    # Fix: route each parcel to its actual sector using NBIdent (the cantonal
    # cadastre district identifier) which the geodienste WFS returns alongside
    # BFSNr.  parcel_enum.commune holds NBIdent — combine bfs + NBIdent to
    # reconstruct the correct selcom.

    def bfs_from_selcom(selcom: str) -> str:
        return selcom.split()[0]

    def nbident_from_selcom(selcom: str) -> str:
        parts = selcom.split()
        return parts[1] if len(parts) > 1 else ""

    def clean_label(lbl: str) -> str:
        lbl = re.sub(r'^\[\s*\d+\.\w+\s*\]\s*', '', lbl)
        return re.sub(r'\s+', ' ', lbl).strip()

    # Index by (bfs, NBIdent) → selcom, label.  Falls back to first selcom for
    # the bfs if NBIdent isn't in our enum (rare edge case, e.g. test rows).
    selcom_by_key:    dict[tuple[str, str], str] = {}
    label_by_key:     dict[tuple[str, str], str] = {}
    selcoms_by_bfs:   dict[str, list[str]]       = {}
    labels_by_bfs:    dict[str, list[str]]       = {}
    for v, lbl in all_options:
        bfs = bfs_from_selcom(v)
        nb  = nbident_from_selcom(v)
        selcom_by_key[(bfs, nb)] = v
        label_by_key [(bfs, nb)] = clean_label(lbl)
        selcoms_by_bfs.setdefault(bfs, []).append(v)
        labels_by_bfs .setdefault(bfs, []).append(clean_label(lbl))

    # Determine which BFS numbers to include
    if communes:
        wanted_bfs = {bfs_from_selcom(c) for c in communes}
    else:
        wanted_bfs = None

    multi_sector_bfs = {bfs for bfs, lst in selcoms_by_bfs.items() if len(lst) > 1}
    log.info("FR communes with multi-sector mergers: %d (e.g. %s)",
             len(multi_sector_bfs), sorted(multi_sector_bfs)[:5])

    # FR has ~120k parcels in 130+ communes. The swisstopo 200m grid scan
    # only captured 19,428 (24% of canton) and 0% EGRID. WFS finds all of
    # them in ~2 min with 100% EGRID coverage.
    with get_conn() as conn:
        cached = enum_cached(conn, "FR")
    if cached and len(cached) >= 80_000:
        log.info("Using cached FR parcel list (%d parcels)", len(cached))
        raw_parcels = cached
    else:
        if cached:
            log.info("FR cache incomplete (%d parcels, grid-scan undercount) — "
                     "re-enumerating via WFS", len(cached))
            with get_conn() as conn:
                conn.execute("DELETE FROM parcel_enum WHERE canton='FR'")
                conn.commit()
        log.info("Enumerating FR parcels via geodienste WFS (~2 min) …")
        raw_parcels = wfs_enumerate_canton("FR")
        with get_conn() as conn:
            store_enum(conn, "FR", raw_parcels)
        log.info("Cached %d FR parcels (WFS, 100%% EGRID)", len(raw_parcels))

    # Map each parcel to its specific (bfs, NBIdent) selcom — NOT just the bfs.
    # parcel_enum.commune stores NBIdent from the geodienste WFS.  This routes
    # each parcel to the correct sub-sector of merged communes.
    parcels = []
    skipped_no_selcom = 0
    skipped_unknown_nbident = 0
    for p in raw_parcels:
        bfs = p["bfs_nr"]
        if wanted_bfs and bfs not in wanted_bfs:
            continue
        nb = p.get("commune", "") or ""

        # Exact (bfs, NBIdent) match — works for both single- and multi-sector
        # communes since the WFS NBIdent matches the portal's selcom suffix.
        selcom = selcom_by_key.get((bfs, nb))
        label  = label_by_key.get((bfs, nb))

        if not selcom:
            # Fall back: bfs only has one selcom anyway → use it
            candidates = selcoms_by_bfs.get(bfs, [])
            if len(candidates) == 1:
                selcom = candidates[0]
                label  = labels_by_bfs[bfs][0]
            elif candidates:
                # Multi-sector bfs with NBIdent we don't recognise — skip rather
                # than guess; would re-introduce false positives.
                skipped_unknown_nbident += 1
                continue
            else:
                skipped_no_selcom += 1
                continue

        parcels.append({
            "bfs_nr":    bfs,
            "parcel_nr": p["parcel_nr"],
            "selcom":    selcom,
            "commune":   label or p.get("commune", ""),
            "egrid":     p.get("egrid"),
        })

    if skipped_no_selcom or skipped_unknown_nbident:
        log.warning("Skipped %d parcels (no selcom mapping) + %d (multi-sector bfs with unknown NBIdent)",
                    skipped_no_selcom, skipped_unknown_nbident)

    log.info("%d real FR parcels to scan", len(parcels))
    if limit:
        parcels = parcels[:limit]

    session, xv1, _ = new_session()
    queries_this_session = 0
    scanned = errors = herrenlos = total = 0

    with get_conn() as conn:
        for p in parcels:
            bfs    = p["bfs_nr"]
            pnr    = p["parcel_nr"]
            selcom = p["selcom"]
            commune_label = p["commune"]

            if limit and total >= limit:
                break

            if skip_existing and already_scanned(conn, "FR", bfs, pnr):
                continue

            # Rotate session every QUERIES_PER_SESSION queries
            if queries_this_session >= QUERIES_PER_SESSION:
                log.debug("Rotating FR session after %d queries", queries_this_session)
                time.sleep(1)
                session, xv1, _ = new_session()
                queries_this_session = 0

            result = check_owner(session, xv1, selcom, pnr)
            queries_this_session += 1
            total += 1

            if result.get("error") == "session_exhausted":
                log.warning("Session exhausted early — rotating")
                session, xv1, _ = new_session()
                queries_this_session = 0
                result = check_owner(session, xv1, selcom, pnr)
                queries_this_session += 1

            # Carry the EGRID through from the enum row (FR scanner doesn't
            # rediscover it from the portal response — but the cantonal WFS
            # has it; we have it cached in parcel_enum).
            upsert_parcel(conn, {
                "egrid":       p.get("egrid"),
                "canton":      "FR",
                "commune":     commune_label,
                "bfs_nr":      bfs,
                "parcel_nr":   pnr,
                "parcel_type": "Liegenschaft",
                **result,
            })

            scanned += 1
            if result.get("is_herrenlos") == 1:
                herrenlos += 1
                log.info("HERRENLOS  %s Nr.%s", commune_label, pnr)
            if result.get("error") and result["error"] not in ("session_exhausted",):
                errors += 1

            if scanned % 50 == 0:
                log.info("Progress %d  herrenlos=%d  errors=%d", scanned, herrenlos, errors)

            time.sleep(delay)

    log.info("FR scan done — scanned=%d  herrenlos=%d  errors=%d", scanned, herrenlos, errors)
    return {"scanned": scanned, "herrenlos": herrenlos, "errors": errors}
