"""
BS scanner — Basel-Stadt
========================
- EGRID enumeration : api3.geo.admin.ch identify  (swisstopo, no auth)
                      Grid scan over BS bounding box, step=50m (small canton)
- Owner lookup      : api.geo.bs.ch/grundstueckinfo/v1/realestatesinformation
                      → OwnershipInformation link → api.geo.bs.ch/eigentum/{s}/{p}
- Auth              : Free API key from  https://api.geo.bs.ch/
                      Register once, paste key below.
- Herrenlos signal  : owner endpoint returns empty list OR 404
- Rate limit        : Personal API key — no documented limit (unlimited per api.geo.bs.ch docs).
                      Test key (no registration): 10 req/min — not suitable for scanning.
                      No IP rotation needed.
- Full scan         : ~7 000 parcels × 2 requests × 1 s delay ≈ ~4 h

API KEY SETUP:
    1. Go to https://api.geo.bs.ch/
    2. Register for a free account
    3. Copy your API key and set BS_API_KEY below (or env var BS_API_KEY)
"""

import os
import re
import time
import logging
import requests

import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from db import get_conn, init_db, already_scanned, upsert_parcel, enum_cached, store_enum
from scanners.utils import annotate_herrenlos, claim_possible_for
from scanners.wfs_enum import enumerate_canton as wfs_enumerate_canton

log = logging.getLogger("BS")

SWISSTOPO_IDENTIFY = "https://api3.geo.admin.ch/rest/services/api/MapServer/identify"
BS_INFO_URL  = "https://api.geo.bs.ch/grundstueckinfo/v1/realestatesinformation"
BS_OWNER_URL = "https://api.geo.bs.ch/eigentum/{section}/{parcel}"

# ── Paste your free API key here or set env var BS_API_KEY ──
BS_API_KEY = os.environ.get("BS_API_KEY", "YOUR_FREE_KEY_HERE")

# BS LV95 bounding box (small canton, ~37 km²)
BS_EMIN, BS_EMAX = 2_610_000, 2_622_000
BS_NMIN, BS_NMAX = 1_263_000, 1_272_000
GRID_STEP = 50   # metres — small canton, fine grid


# ── EGRID enumeration via swisstopo identify API ─────────────────────────────

def enumerate_egrids(emin=BS_EMIN, emax=BS_EMAX,
                     nmin=BS_NMIN, nmax=BS_NMAX,
                     step=GRID_STEP) -> list[dict]:
    """
    Grid scan using swisstopo federal identify API.
    Returns unique parcel dicts: {egrid, parcel_nr, commune, bfs_nr}
    """
    seen:    set[str] = set()
    parcels: list[dict] = []
    session  = requests.Session()

    e_range = range(emin, emax + 1, step)
    n_range = range(nmin, nmax + 1, step)
    checked = 0
    total   = len(e_range) * len(n_range)

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
                    eg = attrs.get("egris_egrid")
                    if eg and eg not in seen:
                        # only keep BS parcels (canton code)
                        if attrs.get("ak", "").upper() != "BS":
                            continue
                        seen.add(eg)
                        parcels.append({
                            "egrid":     eg,
                            "parcel_nr": attrs.get("number", ""),
                            "commune":   attrs.get("label", ""),
                            "bfs_nr":    str(attrs.get("bfsnr", "")),
                        })
            except Exception:
                pass

            if checked % 200 == 0:
                log.info("Grid %d/%d  unique parcels=%d", checked, total, len(parcels))
            time.sleep(0.1)   # swisstopo fair-use: 20 req/min

    log.info("Grid scan complete: %d unique BS parcels", len(parcels))
    return parcels


# ── Owner check ─────────────────────────────────────────────────────────────

def check_owner_bs(egrid: str, api_key: str = BS_API_KEY) -> dict:
    """
    BS public-API parcel check.

    IMPORTANT (verified 2026-05-18 against the live OpenAPI spec at
    https://api.geo.bs.ch/grundstueckinfo/v1/openapi.yaml):

      The BS REST API exposes ONLY parcel metadata (area, buildings, land covers,
      type). It does NOT expose owner names. The `OwnershipInformation` field in
      the response is a URL to the HTML viewer at /eigentum/{section}/{parcel},
      which is Keycloak + reCAPTCHA protected — same architecture as SO.

      Consequence: this scanner can only detect Type A herrenlos
      (parcel NOT present in BS Grundbuch → Art. 664 ZGB). It CANNOT detect
      Type B herrenlos (dereliktion) because owner data isn't in the API.

      For full BS owner coverage, a reCAPTCHA-solving scanner (mirror of
      scanners/so_public.py) would need to be built against the HTML viewer.
      Until then, BS scans return is_herrenlos=None for parcels that DO exist
      in BS, with error='owner_lookup_needs_html_path'.
    """
    try:
        r = requests.get(BS_INFO_URL, params={"ids": egrid, "apikey": api_key}, timeout=15)
        if r.status_code == 401:
            return {"error": "invalid_api_key", "is_herrenlos": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "owner": None, "owner_address": None, "raw_response": None}
        if r.status_code != 200:
            return {"error": f"http_{r.status_code}", "is_herrenlos": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "owner": None, "owner_address": None, "raw_response": None}

        data = r.json()
        # Schema (case-sensitive, verified against OpenAPI):
        #   {"Date": ..., "Service": {...}, "RealEstates": [{"Egrid": ...}, ...]}
        real_estates = data.get("RealEstates", []) if isinstance(data, dict) else []
        # Filter to the EGRID we asked for — API may include linked parcels
        match = next((re for re in real_estates if re.get("Egrid") == egrid), None)

        if match is None:
            # EGRID not in BS Grundbuch at all → Type A herrenlos (Art. 664 ZGB).
            # The federal swisstopo identify says this parcel is in BS canton,
            # but BS's own Grundbuch doesn't know about it. Real herrenlos signal.
            return {"owner": None, "owner_address": None,
                    "is_herrenlos": 1,
                    "herrenlos_type": "not_in_grundbuch",
                    "claim_possible": claim_possible_for("BS", "not_in_grundbuch"),
                    "raw_response": None, "error": None}

        # Parcel exists in BS Grundbuch. Owner data is not accessible via this
        # API; we'd need a reCAPTCHA-solving scanner against the HTML viewer.
        # Honestly report this as unknown rather than guess herrenlos.
        return {"owner": None, "owner_address": None,
                "is_herrenlos": None,
                "herrenlos_type": None,
                "claim_possible": None,
                "raw_response": None,
                "error": "owner_lookup_needs_html_path"}

    except Exception as exc:
        return {"owner": None, "owner_address": None,
                "is_herrenlos": None,
                "herrenlos_type": None, "claim_possible": None,
                "raw_response": None, "error": str(exc)}


# ── Main scanner ─────────────────────────────────────────────────────────────

def scan(api_key: str = BS_API_KEY,
         limit: int | None = None,
         skip_existing: bool = True,
         delay: float = 0.5):
    """Scan BS parcels for herrenlos detection."""
    if api_key in ("", "YOUR_FREE_KEY_HERE"):
        print("\n[BS] No API key set. Register at https://api.geo.bs.ch/ (free).")
        print("     Then set env var  BS_API_KEY=<your_key>  or edit scanners/bs.py\n")
        return

    init_db()
    with get_conn() as conn:
        parcels = enum_cached(conn, "BS")
    if not parcels:
        log.info("Enumerating BS parcels via geodienste WFS (~30s) …")
        parcels = wfs_enumerate_canton("BS")
        with get_conn() as conn:
            store_enum(conn, "BS", parcels)
        log.info("Cached %d BS parcels (WFS)", len(parcels))
    if limit:
        parcels = parcels[:limit]
    log.info("Will scan %d BS parcels", len(parcels))

    scanned = errors = herrenlos = 0

    with get_conn() as conn:
        for p in parcels:
            egrid = p["egrid"]
            bfs   = p["bfs_nr"]
            nr    = p["parcel_nr"]

            if skip_existing and already_scanned(conn, "BS", bfs, str(nr)):
                continue

            result = check_owner_bs(egrid, api_key)
            annotate_herrenlos(result, "BS")

            upsert_parcel(conn, {
                "egrid":       egrid,
                "canton":      "BS",
                "commune":     p.get("commune"),
                "bfs_nr":      bfs,
                "parcel_nr":   str(nr),
                "parcel_type": "Liegenschaft",
                **result,
            })

            scanned += 1
            if result.get("is_herrenlos") == 1:
                herrenlos += 1
                log.info("HERRENLOS  %s Nr.%s  EGRID=%s",
                         p.get("commune", "BS"), nr, egrid)
            if result.get("error"):
                errors += 1
                if result["error"] == "invalid_api_key":
                    log.error("Invalid BS API key — aborting")
                    break

            if scanned % 50 == 0:
                log.info("Progress %d/%d  herrenlos=%d  errors=%d",
                         scanned, len(parcels), herrenlos, errors)

            time.sleep(delay)

    log.info("BS scan done — scanned=%d  herrenlos=%d  errors=%d", scanned, herrenlos, errors)
    return {"scanned": scanned, "herrenlos": herrenlos, "errors": errors}
