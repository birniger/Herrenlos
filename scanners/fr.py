"""
FR scanner — Fribourg
=====================
- EGRID enumeration : geodienste.ch WFS (wfs_enum.py) — all ~147k FR parcels in
                      ~2 min, 100% EGRID coverage. Cached in parcel_enum table.
                      (Old swisstopo 200m grid scan only found 19k of 147k; WFS replaced it.)
- Owner lookup      : POST  keycloak.fr.ch/rfpublic/v2TAffImmx01.jsp
- Herrenlos signals:
    Type 2 (not in Grundbuch): "INFORMATION INTROUVABLE" or response < 800 B
                                for a parcel that EXISTS in the official cadaster
    Type 1 (dereliktion):      valid full response, table.proprio exists but
                                no owner name found
- Rate limit        : session creation rate-limited ~1/12s per IP; rotate every QUERIES_PER_SESSION queries
- Throughput        : ~1,200 queries/hr (QUERIES_PER_SESSION=3, delay=0.3s)
- Bandwidth         : ~10 KB/parcel query + ~20 KB/session rotation (2 requests via
                      _rotate_session). Full scan ~147k parcels ≈ ~2.4 GB via proxy.
                      (Old approach reused new_session() for rotations = 8 requests/rotation
                      × ~110 KB = ~5.4 GB overhead alone. _rotate_session saves ~4.4 GB.)

FR commune codes (selcom) format:  "{bfs_nr} FR{sector_code}"
Full commune list fetched live: portal uses 7 districts (BRF=10..16 via selectDistrict.jsp).
Default GET of selectCommune.jsp only returns Saane/Sarine (40 selcoms, ~28k parcels).
new_session() now POSTs each BRF to fetch all 183 selcoms → ~147k parcel coverage.
"""

import re
import time
import logging
import requests
from bs4 import BeautifulSoup

import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from db import get_conn, init_db, already_scanned, upsert_parcel, enum_cached, store_enum
from scanners.wfs_enum import enumerate_canton as wfs_enumerate_canton
from scanners.utils import (
    is_herrenlos_owner_text, claim_possible_for,
    DEFAULT_UA, load_proxies,
)

log = logging.getLogger("FR")

BASE     = "https://keycloak.fr.ch/rfpublic"
INDEX    = f"{BASE}/indexD.html"
COMMUNE  = f"{BASE}/selectCommune.jsp"
QUERY    = f"{BASE}/v2TAffImmx01.jsp"
UA       = DEFAULT_UA  # alias kept for call sites within this file; imported from utils

NOT_FOUND_NEEDLE   = "INFORMATION INTROUVABLE"
NOT_FOUND_MAX_B    = 800    # bytes; valid response is ~8–10 KB
# Rate-limit page indicators — any of these means the session/IP quota is spent.
# The portal serves at least three different rate-limit page variants:
#   "dépassement de la limite" — standard French quota-exceeded text
#   "StopConsult"              — portal-specific rate-limit class/marker
#   "Abfragelimite"            — German-language quota text
RATE_LIMIT_NEEDLES = (
    "dépassement de la limite",
    "StopConsult",
    "Abfragelimite",
)
# Server-error page indicators — portal errors that are NOT valid Grundbuch results.
ERROR_PAGE_NEEDLES = (
    "error_msg",               # error page HTML marker (class/id in the portal)
)
# Queries per JSESSIONID before proactive rotation.
# Empirically: ~2-3 succeed before exhaustion; ~27% of 2nd/3rd queries fail.
# Higher values mean fewer _rotate_session() calls (each costs ~20 KB) — but also
# more session_exhausted retries when the session dies early.  Each retry adds
# one failed query + one _rotate_session() so net savings still positive above 3.
# Set via FR_QUERIES_PER_SESSION env var; default 5 (safe, reduces rotation 40%).
# FR portal rate-limits session creation (~1 every 12s per IP). new_session()
# takes ~4 s. Parcels that fail both attempts (original + retry) are stored with
# is_herrenlos=NULL and error='session_exhausted'; next run picks them up.
# 2-3 scan passes converge to ~100% coverage.
import os as _os
QUERIES_PER_SESSION = int(_os.environ.get("FR_QUERIES_PER_SESSION", "5"))


# ── Session management ───────────────────────────────────────────────────────

def _rotate_session(proxy_url: str | None = None) -> tuple[requests.Session, str]:
    """
    Create a bare JSESSIONID session for mid-scan rotation.

    Only 2 requests: GET INDEX (establishes cookie) + GET COMMUNE (gets xv1).
    Does NOT re-fetch the 7 district commune pages — those are static and already
    collected once at scan startup via new_session().  Skipping those 6 POSTs
    saves ~90 KB per rotation × ~49k rotations ≈ 4.4 GB per full FR scan.
    """
    s = requests.Session()
    s.headers["User-Agent"] = UA
    if proxy_url:
        s.proxies.update({"http": proxy_url, "https": proxy_url})

    s.get(INDEX, timeout=15)
    r = s.get(COMMUNE, timeout=15)

    xv1_tag = BeautifulSoup(r.text, "lxml").find("input", {"name": "xv1"})
    if not xv1_tag:
        m = re.search(r'name\s*=\s*"xv1"\s+value\s*=\s*"([^"]+)"', r.text)
        xv1 = m.group(1) if m else ""
    else:
        xv1 = xv1_tag.get("value", "")

    return s, xv1


def new_session(proxy_url: str | None = None) -> tuple[requests.Session, str, list[tuple]]:
    """
    Create a fresh JSESSIONID session and return:
      (session, xv1_token, commune_options)
    commune_options: list of (selcom_value, label)

    Called ONCE at scan startup to collect the full 183-selcom commune list.
    Mid-scan rotations use _rotate_session() instead (2 requests vs 8 here).

    The FR portal uses frames: selectDistrict.jsp lists 7 districts (BRF=10..16),
    and POSTing BRF to selectCommune.jsp loads that district's communes.  The
    default GET of selectCommune.jsp only shows Saane/Sarine (BRF=10, ~40 options).
    We must iterate over all 7 districts to get the full 183-selcom list that
    covers all 147k enum parcels (vs 28k with Saane only).

    proxy_url: optional HTTP proxy (e.g. DataImpulse residential) — keycloak.fr.ch
               geo-blocks datacenter IPs, so a Swiss residential proxy is required
               when running from GitHub Actions / non-Swiss IPs.
    """
    # BRF district codes: 10=Saane, 11=Greyerz, 12=Sense, 13=Broye,
    #                     14=See, 15=Vivisbach, 16=Glane
    DISTRICT_BRF = [10, 11, 12, 13, 14, 15, 16]

    s = requests.Session()
    s.headers["User-Agent"] = UA
    if proxy_url:
        s.proxies.update({"http": proxy_url, "https": proxy_url})
        log.debug("FR session via proxy %s…", proxy_url.split("@")[-1])

    s.get(INDEX, timeout=15)

    # First request establishes JSESSIONID and fetches Saane communes (default).
    r = s.get(COMMUNE, timeout=15)
    soup = BeautifulSoup(r.text, "lxml")

    xv1_tag = soup.find("input", {"name": "xv1"})
    if not xv1_tag:
        m = re.search(r'name\s*=\s*"xv1"\s+value\s*=\s*"([^"]+)"', r.text)
        xv1 = m.group(1) if m else ""
    else:
        xv1 = xv1_tag.get("value", "")

    def _parse_options(html: str) -> list[tuple[str, str]]:
        sp = BeautifulSoup(html, "lxml")
        return [
            (opt["value"], re.sub(r'\s+', ' ', opt.get_text(strip=True)).strip())
            for opt in sp.select("select[name='selcom'] option")
            if opt.get("value", "").strip()
        ]

    options: list[tuple[str, str]] = _parse_options(r.text)  # BRF=10 Saane

    # Fetch remaining 6 districts and merge.
    for brf in DISTRICT_BRF[1:]:
        try:
            r2 = s.post(COMMUNE, data={"BRF": brf}, timeout=15)
            options.extend(_parse_options(r2.text))
        except Exception as exc:
            log.warning("FR new_session: district BRF=%d fetch failed: %s", brf, exc)

    log.debug("New FR session — %d selcoms across all districts, xv1=%s…",
              len(options), xv1[:8])
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

        if any(n in raw for n in RATE_LIMIT_NEEDLES):
            return {"error": "session_exhausted", "is_herrenlos": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "owner": None, "owner_address": None, "raw_response": None}

        if any(n in raw for n in ERROR_PAGE_NEEDLES):
            log.warning("Error page in %d-byte response (selcom=%s nr=%s) — "
                        "will retry", size, selcom, parcel_nr)
            return {"error": "server_error", "is_herrenlos": None,
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
                    # Store the full response (not truncated) so classification
                    # can be verified post-hoc by inspecting the portal HTML.
                    "raw_response": raw, "error": None}

        # Parse owner from table.proprio
        soup = BeautifulSoup(raw, "lxml")
        proprio = soup.find("table", class_="proprio")

        # GUARD 1: No table.proprio → not a valid Grundbuch result.
        # Rate-limit and server-error pages are normally caught by the text
        # checks above, but occasionally slip through (e.g. a new page variant
        # we haven't seen).  If proprio is missing from a full-size response,
        # it's still not a real Grundbuch result — retry rather than flag herrenlos.
        if proprio is None:
            log.warning("No table.proprio in %d-byte response (selcom=%s nr=%s) — "
                        "server error, parcel will be retried", size, selcom, parcel_nr)
            return {"error": "server_error", "is_herrenlos": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "owner": None, "owner_address": None, "raw_response": None}

        # GUARD 2: Cross-reference link to another parcel inside proprio.
        # The FR portal renders some servient parcels (Dienstbarkeits- or
        # Eigentumsbeschränkungs-einträge) with a data row whose cells are
        # orphaned <td>s outside any <tr> (malformed HTML).  lxml adopts them
        # onto a phantom row that row.find("td") cannot see, so the scanner
        # previously missed the content and returned "no owner → herrenlos".
        # A parcel with a Grundbuch cross-reference link is NOT herrenlos.
        _PARCEL_LINK = re.compile(r'v2TAffImmx01\.jsp', re.I)
        if proprio.find("a", href=_PARCEL_LINK):
            link_text = proprio.find("a", href=_PARCEL_LINK).get_text(" ", strip=True)
            log.debug("table.proprio has parcel cross-reference '%s' (selcom=%s nr=%s) "
                      "— not herrenlos", link_text, selcom, parcel_nr)
            return {"owner": f"parcel_ref({link_text})", "owner_address": None,
                    "is_herrenlos": 0, "herrenlos_type": None, "claim_possible": None,
                    "raw_response": None, "error": None}

        # Use find_all("td") on the table rather than iterating find_all("tr") →
        # find("td"), because the FR portal occasionally emits data cells as
        # orphaned <td>s outside any <tr> (invalid HTML).  find_all("td") on the
        # table element catches those rows too.
        owner_names:     list[str] = []
        herrenlos_texts: list[str] = []
        skip = {
            "propriété", "miteigentum", "gesamteigentum",
            "informations sur la propriété:", "angaben zur liegenschaft:",
            # Column headers occasionally rendered as <td> instead of <th>:
            "commune", "no immeuble", "type de propriété", "propriété de:",
            "gemeinde", "liegenschaftsnr.", "art des eigentums", "grundeigentümer:",
        }
        for td in proprio.find_all("td"):
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
                # Store the full response for herrenlos parcels so the proprio
                # table HTML can be inspected to verify the classification.
                "raw_response": raw if owner is None else None,
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
         delay: float = 0.3):
    """
    Scan FR parcels for herrenlos detection.

    Enumeration: geodienste.ch WFS (wfs_enum.py) — ~2 min, 100% EGRID coverage.
    Cached in parcel_enum; subsequent runs skip re-enumeration.

    communes  : list of selcom values to restrict scan (None = all FR communes)
    limit     : stop after N queries
    delay     : seconds between queries (0.3s optimises throughput; session
                creation rate-limit dominates, not per-query delay)
    """
    init_db()

    # keycloak.fr.ch geo-blocks datacenter IPs — Swiss residential proxy required
    # when running from CI / non-Swiss machines.
    proxy_list = load_proxies("FR_PROXY_LIST")
    proxy_url  = proxy_list[0] if proxy_list else None
    if proxy_url:
        log.info("FR using proxy: %s…", proxy_url.split("@")[-1])
    else:
        log.info("FR running without proxy (needs Swiss IP for keycloak.fr.ch)")

    log.info("Fetching FR commune list …")
    _, _, all_options = new_session(proxy_url)

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
    # Also builds a NBIdent-only index for post-merger bfs_nr mismatches:
    # After FR commune mergers the WFS uses the new merged bfs_nr, but parcels
    # retain their old pre-merger NBIdent (e.g. FR202911 stays on the land even
    # after its commune merged into a new bfs entity). The portal's selcom uses
    # the OLD bfs code as the sector key, so (new_bfs, old_NBIdent) never matches
    # selcom_by_key. Matching by NBIdent alone recovers those ~118k parcels.
    selcom_by_key:    dict[tuple[str, str], str] = {}
    label_by_key:     dict[tuple[str, str], str] = {}
    selcoms_by_bfs:   dict[str, list[str]]       = {}
    labels_by_bfs:    dict[str, list[str]]       = {}
    selcom_by_nbident: dict[str, str]            = {}   # NBIdent → selcom fallback
    label_by_nbident:  dict[str, str]            = {}
    for v, lbl in all_options:
        bfs = bfs_from_selcom(v)
        nb  = nbident_from_selcom(v)
        selcom_by_key[(bfs, nb)] = v
        label_by_key [(bfs, nb)] = clean_label(lbl)
        selcoms_by_bfs.setdefault(bfs, []).append(v)
        labels_by_bfs .setdefault(bfs, []).append(clean_label(lbl))
        # NBIdent-only index: first entry wins (NBIdents are unique per sector)
        selcom_by_nbident.setdefault(nb, v)
        label_by_nbident .setdefault(nb, clean_label(lbl))

    # Determine which BFS numbers to include
    if communes:
        wanted_bfs = {bfs_from_selcom(c) for c in communes}
    else:
        wanted_bfs = None

    multi_sector_bfs = {bfs for bfs, lst in selcoms_by_bfs.items() if len(lst) > 1}
    log.info("FR communes with multi-sector mergers: %d (e.g. %s)",
             len(multi_sector_bfs), sorted(multi_sector_bfs)[:5])

    # FR has ~147k parcels in 130+ communes (verified by WFS).  The swisstopo 200m grid scan
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
                conn.execute("DELETE FROM enum.parcel_enum WHERE canton='FR'")  # MED-7 fix: must qualify with 'enum.' schema
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
                # Multi-sector new-bfs with unknown NBIdent — try NBIdent-only
                # lookup (post-merger: old NBIdent survives but bfs changed).
                selcom = selcom_by_nbident.get(nb)
                label  = label_by_nbident.get(nb)
                if not selcom:
                    skipped_unknown_nbident += 1
                    continue
            else:
                # bfs not in portal at all — try NBIdent-only fallback for
                # parcels whose municipality merged into a new bfs_nr.
                selcom = selcom_by_nbident.get(nb)
                label  = label_by_nbident.get(nb)
                if not selcom:
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

    session, xv1, _ = new_session(proxy_url)
    queries_this_session = 0
    scanned = errors = herrenlos = total = 0
    # Circuit breaker: if this many consecutive parcels double-fail (original +
    # retry both return session_exhausted), the daily IP quota is spent — exit
    # cleanly with "quota exhausted" in the log so run_local.py applies a
    # midnight cooldown instead of immediately retrying.
    consecutive_exhausted = 0
    MAX_CONSECUTIVE_EXHAUSTED = 20

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

            # Rotate session every QUERIES_PER_SESSION queries.
            # Use _rotate_session() not new_session() — saves 6 district POSTs
            # (~90 KB) per rotation; ~4.4 GB over a full 147k-parcel FR scan.
            if queries_this_session >= QUERIES_PER_SESSION:
                log.debug("Rotating FR session after %d queries", queries_this_session)
                time.sleep(1)
                session, xv1 = _rotate_session(proxy_url)
                queries_this_session = 0

            result = check_owner(session, xv1, selcom, pnr)
            queries_this_session += 1
            total += 1

            if result.get("error") == "session_exhausted":
                log.warning("Session exhausted early — rotating")
                session, xv1 = _rotate_session(proxy_url)
                queries_this_session = 0
                result = check_owner(session, xv1, selcom, pnr)
                queries_this_session += 1

                # If the fresh session is ALSO exhausted, the daily IP quota is
                # gone.  Count consecutive double-failures and bail out early so
                # we don't hammer the portal for thousands of pointless requests.
                if result.get("error") == "session_exhausted":
                    consecutive_exhausted += 1
                    if consecutive_exhausted >= MAX_CONSECUTIVE_EXHAUSTED:
                        log.warning(
                            "FR quota exhausted — %d consecutive double-failures. "
                            "Exiting early; cooldown until midnight.",
                            consecutive_exhausted,
                        )
                        break
                # HIGH-6 fix: do NOT reset consecutive_exhausted when the RETRY
                # succeeds.  If the quota is near-exhausted, ~1-in-20 retries may
                # succeed by luck — resetting the counter on those lucky retries
                # prevents the circuit breaker from ever firing.
                # Only reset when the INITIAL request succeeds (else branch below).
            else:
                # Clean initial success: no quota pressure, reset the counter.
                consecutive_exhausted = 0

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
