"""
GR scanner — Graubünden
========================
- EGRID enumeration : swisstopo identify API grid scan (step=500m, ~2h one-time)
                      Cached in parcel_enum table — only runs once ever.
- Owner lookup      : GET https://lkgr.geogr.ch/terravis/egrid/{EGRID}
                      Returns JSON with owner data.
                      reCAPTCHA header IS present in the JS but the server
                      NEVER validates the token — confirmed by live testing.
- Rate limit        : 10 req/day per IP (anonymous). 429 → sleep → continue.
                      For full scan use Tor or VPN rotation (CHF 1–7 one-time).
                      Optional: OIDC login at lkgr.geogr.ch → 50/day (free acct).
- Herrenlos signal  : empty eigentuemer list  OR  404  OR  {"error": "not_found"}
- Parcels           : ~85,000 (largest Swiss canton, ~7,100 km²)
"""

import re
import time
import logging
import requests

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from db import get_conn, init_db, already_scanned, upsert_parcel, enum_cached, store_enum
from scanners.utils import is_herrenlos_owner_text, claim_possible_for

log = logging.getLogger("GR")

TERRAVIS_URL       = "https://lkgr.geogr.ch/terravis/egrid/{egrid}"
SWISSTOPO_IDENTIFY = "https://api3.geo.admin.ch/rest/services/api/MapServer/identify"
UA                 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"

# GR LV95 bounding box — largest Swiss canton
GR_EMIN, GR_EMAX = 2_682_000, 2_834_000
GR_NMIN, GR_NMAX = 1_111_000, 1_219_000
GR_GRID_STEP     = 500   # metres — ~65k grid points, one-time ≈2h


# ── Parcel enumeration via swisstopo ─────────────────────────────────────────

def enumerate_parcels_swisstopo(
        emin=GR_EMIN, emax=GR_EMAX,
        nmin=GR_NMIN, nmax=GR_NMAX,
        step=GR_GRID_STEP) -> list[dict]:
    """
    Grid scan using swisstopo federal identify API.
    Returns list of {egrid, bfs_nr, parcel_nr, commune} dicts.
    One-time cost (~2h). Results cached in parcel_enum DB table.
    """
    seen:    set[str]  = set()
    parcels: list[dict] = []
    session = requests.Session()
    session.headers["User-Agent"] = UA

    e_range = range(emin, emax + 1, step)
    n_range = range(nmin, nmax + 1, step)
    total   = len(e_range) * len(n_range)
    checked = 0

    log.info("GR swisstopo grid scan: %d × %d = %d points at %dm step",
             len(e_range), len(n_range), total, step)

    for e in e_range:
        for n in n_range:
            checked += 1
            try:
                r = session.get(SWISSTOPO_IDENTIFY, params={
                    "geometry":       f"{e},{n}",
                    "geometryType":   "esriGeometryPoint",
                    "layers":         "all:ch.swisstopo-vd.amtliche-vermessung",
                    "tolerance":      0,
                    "mapExtent":      "0,0,1,1",
                    "imageDisplay":   "1,1,96",
                    "returnGeometry": "false",
                    "lang":           "de",
                    "sr":             2056,
                }, timeout=10)

                if r.status_code != 200:
                    continue

                for feat in r.json().get("results", []):
                    attrs = feat.get("attributes", {})
                    if attrs.get("ak", "").upper() != "GR":
                        continue
                    eg = attrs.get("egris_egrid", "")
                    if eg and eg not in seen:
                        seen.add(eg)
                        parcels.append({
                            "egrid":     eg,
                            "bfs_nr":    str(attrs.get("bfsnr", "")),
                            "parcel_nr": str(attrs.get("number", "")),
                            "commune":   attrs.get("label", ""),
                        })
            except Exception:
                pass

            if checked % 5000 == 0:
                log.info("Grid %d/%d  unique GR parcels=%d", checked, total, len(parcels))
            time.sleep(0.1)   # swisstopo fair-use

    log.info("Grid scan complete: %d unique GR parcels", len(parcels))
    return parcels


# ── Owner check ─────────────────────────────────────────────────────────────

def check_owner(session: requests.Session, egrid: str) -> dict:
    """
    Query owner for one GR parcel via Terravis JSON API.

    The frontend sends an X-Captcha-Token header, but live testing confirmed
    the server ignores it completely — no captcha validation whatsoever.

    Rate limit: 10 req/day per IP (anonymous).
    Returns HTTP 429 when limit exceeded.

    Confirmed live response structure (2025):
    {
      "parcels": [{
        "id": "...",
        "person": [{
          "nummer": "...",
          "inhalt_natuerliche_person_gb": [{"name": ..., "vorname": ...}],
          "inhalt_juristische_person_gb": [{"name_firma": ...}],
          "person_stamm": {
            "oeffentliche_koerperschaft": {"name": ..., "adresse": {...}}
          }
        }],
        "grundstueck": [...],
        "recht": [...]
      }],
      "missing": []   ← non-empty means EGRID not found (Type 2 herrenlos)
    }
    """
    try:
        r = session.get(
            TERRAVIS_URL.format(egrid=egrid),
            headers={"Referer": "https://lkgr.geogr.ch/owner"},
            timeout=15,
        )

        if r.status_code == 429:
            return {"error": "rate_limited", "is_herrenlos": None,
                    "owner": None, "owner_address": None, "raw_response": None}

        if r.status_code in (404, 400):
            # EGRID not found in Terravis / Grundbuch at all.
            # This is Type 2 herrenlos (Art. 664 ZGB) — parcel exists in the
            # cadastre but has no Grundbuch entry. Falls to canton by law.
            # NOT claimable by private persons.
            return {"owner": None, "owner_address": None,
                    "is_herrenlos": 1,
                    "herrenlos_type": "not_in_grundbuch",
                    "claim_possible": 0,
                    "raw_response": None, "error": None}

        if r.status_code != 200:
            return {"error": f"http_{r.status_code}", "is_herrenlos": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "owner": None, "owner_address": None, "raw_response": None}

        data = r.json()

        # ── Type 2 herrenlos: EGRID listed in Terravis "missing" list ────────
        missing = data.get("missing") or []
        if missing and egrid in str(missing):
            return {"owner": None, "owner_address": None,
                    "is_herrenlos": 1,
                    "herrenlos_type": "not_in_grundbuch",
                    "claim_possible": 0,
                    "raw_response": str(data)[:300], "error": None}

        # ── Parse Terravis "parcels[].person[]" structure ────────────────────
        owners: list[str] = []
        addrs:  list[str] = []

        def _addr_str(adr) -> str:
            """Extract address string from various Terravis address shapes."""
            if isinstance(adr, list) and adr:
                # Shape: [{"adresse": {"strasse": ..., "plz": ..., "ort": ...}}]
                adr = adr[0]
            if isinstance(adr, dict):
                # Unwrap nested "adresse" key
                inner = adr.get("adresse")
                if isinstance(inner, dict):
                    adr = inner
                return ", ".join(filter(None, [
                    adr.get("strasse") or adr.get("Strasse") or adr.get("street") or "",
                    (adr.get("hausnummer") or adr.get("Hausnummer") or ""),
                    adr.get("plz") or adr.get("Plz") or "",
                    adr.get("ort") or adr.get("Ort") or adr.get("city") or "",
                ]))
            return str(adr).strip() if adr else ""

        parcels_list = data.get("parcels") or []
        if not parcels_list:
            # Terravis returned 200 but parcels[] is empty — parcel IS registered
            # in the Grundbuch but has no entries. Treat as Type 1 dereliktion
            # (the most actionable herrenlos signal in GR).
            log.info("No parcels in Terravis response (EGRID=%s) — potential dereliktion", egrid)
            return {"owner": None, "owner_address": None,
                    "is_herrenlos": 1,
                    "herrenlos_type": "dereliktion",
                    "claim_possible": claim_possible_for("GR", "dereliktion"),
                    "raw_response": str(data)[:300], "error": None}

        for parcel in (parcels_list if isinstance(parcels_list, list) else []):
            person_list = parcel.get("person") or []
            for person in (person_list if isinstance(person_list, list) else []):
                name = ""
                addr = ""

                # 1. Natural person (inhalt_natuerliche_person_gb)
                nat_list = person.get("inhalt_natuerliche_person_gb") or []
                for nat in (nat_list if isinstance(nat_list, list) else [nat_list]):
                    if not isinstance(nat, dict):
                        continue
                    n = " ".join(filter(None, [
                        nat.get("name") or nat.get("nachname") or nat.get("Name") or "",
                        nat.get("vorname") or nat.get("Vorname") or "",
                    ])).strip()
                    if n:
                        name = n
                        adr = nat.get("adresse") or nat.get("Adresse") or {}
                        addr = _addr_str(adr)
                        break

                # Helper: grab address from person_stamm.oeffentliche_koerperschaft
                stamm = person.get("person_stamm") or {}
                oek   = stamm.get("oeffentliche_koerperschaft") or {}

                # 2. Legal person (inhalt_juristische_person_gb)
                if not name:
                    jur_list = person.get("inhalt_juristische_person_gb") or []
                    for jur in (jur_list if isinstance(jur_list, list) else [jur_list]):
                        if not isinstance(jur, dict):
                            continue
                        n = (jur.get("name_firma") or jur.get("name") or
                             jur.get("Name") or jur.get("firmaname") or "").strip()
                        if n:
                            name = n
                            # Address lives in oek, not in jur itself
                            if isinstance(oek, dict):
                                adr = oek.get("adresse") or oek.get("Adresse") or {}
                            else:
                                adr = jur.get("adresse") or jur.get("Adresse") or {}
                            addr = _addr_str(adr)
                            break

                # 3. Public body (person_stamm.oeffentliche_koerperschaft)
                if not name:
                    if isinstance(oek, dict):
                        n = (oek.get("name") or oek.get("Name") or "").strip()
                        if n:
                            name = n
                            adr = oek.get("adresse") or oek.get("Adresse") or {}
                            addr = _addr_str(adr)

                # 4. Fallback: direct name fields on person object
                if not name:
                    name = (person.get("name") or person.get("Name") or
                            person.get("bezeichnung") or "").strip()

                if name and not is_herrenlos_owner_text(name):
                    owners.append(name)
                    if addr:
                        addrs.append(addr)

        # Deduplicate while preserving order
        seen_owners: set[str] = set()
        unique_owners: list[str] = []
        unique_addrs:  list[str] = []
        for i, o in enumerate(owners):
            if o not in seen_owners:
                seen_owners.add(o)
                unique_owners.append(o)
                if i < len(addrs):
                    unique_addrs.append(addrs[i])

        owner = "; ".join(unique_owners) if unique_owners else None
        if owner is None:
            log.info("Potential herrenlos — no owner in Terravis response (EGRID=%s)", egrid)

        # Parcel IS in Grundbuch (200 response, parcels[] non-empty) but person[]
        # parsed out no owner names → most likely genuine dereliktion (Art. 964 ZGB)
        h_type = None if owner else "dereliktion"
        return {
            "owner":          owner,
            "owner_address":  "; ".join(unique_addrs) or None,
            "is_herrenlos":   0 if owner else 1,
            "herrenlos_type": h_type,
            "claim_possible": claim_possible_for("GR", h_type) if h_type else None,
            "raw_response":   str(data)[:300] if owner is None else None,
            "error":          None,
        }

    except Exception as exc:
        return {"owner": None, "owner_address": None,
                "is_herrenlos": None, "herrenlos_type": None, "claim_possible": None,
                "raw_response": None, "error": str(exc)}


# ── Main scanner ─────────────────────────────────────────────────────────────

def scan(limit: int | None = None,
         skip_existing: bool = True,
         delay: float = 2.0):
    """
    Scan GR parcels for herrenlos detection.

    First run: ~2h swisstopo grid scan to enumerate parcels (cached to DB).
    Subsequent runs: use cached list directly.

    Rate limit: 10 queries/day per IP.  At delay=2s that's 5/min → hits the
    limit in ~2 min.  For a full ~85k scan use VPN/Tor IP rotation:
      - Tor (free): rotate circuit every 9 queries via stem library
      - Residential proxies (~CHF 1–7 one-time for 85k parcels)

    limit         : stop after N queries (None = all)
    skip_existing : skip parcels already in DB
    delay         : seconds between requests
    """
    init_db()

    with get_conn() as conn:
        cached = enum_cached(conn, "GR")
    if cached:
        log.info("Using cached GR parcel list (%d parcels)", len(cached))
        parcels = cached
    else:
        log.info("No cache — running swisstopo grid scan (~2h) …")
        parcels = enumerate_parcels_swisstopo()
        with get_conn() as conn:
            store_enum(conn, "GR", parcels)
        log.info("Cached %d GR parcels", len(parcels))

    if limit:
        parcels = parcels[:limit]

    session = requests.Session()
    session.headers["User-Agent"] = UA

    scanned = errors = herrenlos = 0
    rate_wait_until = 0.0

    with get_conn() as conn:
        for p in parcels:
            egrid  = p["egrid"]
            bfs    = p["bfs_nr"]
            nr     = p["parcel_nr"]
            commune = p.get("commune", "")

            if skip_existing and already_scanned(conn, "GR", bfs, nr):
                continue

            # Respect rate limit
            now = time.time()
            if now < rate_wait_until:
                wait = rate_wait_until - now
                log.warning("Rate-limited — sleeping %.0fs", wait)
                time.sleep(wait + 5)

            result = check_owner(session, egrid)

            if result.get("error") == "rate_limited":
                # GR resets at midnight — sleep until then + buffer
                rate_wait_until = time.time() + 86_400
                log.warning("GR rate limit hit — sleeping 24h or use VPN rotation")
                time.sleep(5)
                result = check_owner(session, egrid)

            upsert_parcel(conn, {
                "egrid":       egrid,
                "canton":      "GR",
                "commune":     commune,
                "bfs_nr":      bfs,
                "parcel_nr":   nr,
                "parcel_type": "Liegenschaft",
                **result,
            })

            scanned += 1
            if result.get("is_herrenlos") == 1:
                herrenlos += 1
                log.info("HERRENLOS  %s Nr.%s  EGRID=%s", commune, nr, egrid)
            if result.get("error") and result["error"] != "rate_limited":
                errors += 1

            if scanned % 50 == 0:
                log.info("Progress %d  herrenlos=%d  errors=%d", scanned, herrenlos, errors)

            time.sleep(delay)

    log.info("GR scan done — scanned=%d  herrenlos=%d  errors=%d", scanned, herrenlos, errors)
    return {"scanned": scanned, "herrenlos": herrenlos, "errors": errors}
