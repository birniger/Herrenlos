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

# Confirmed live 2026-06-09: the `ids` parameter accepts comma-separated EGRIDs.
# api.geo.bs.ch returns all matching RealEstates in one response.
BS_BATCH_SIZE = 20   # parcels per API request; API has no documented batch limit

def check_owner_bs_batch(egrids: list[str], api_key: str = BS_API_KEY) -> dict[str, dict]:
    """
    Batch BS owner check — up to BS_BATCH_SIZE EGRIDs per HTTP request.

    Returns {egrid: result_dict} for all requested EGRIDs.
    EGRIDs absent from the API response are marked is_herrenlos=1 (not in Grundbuch).
    """
    try:
        r = requests.get(BS_INFO_URL,
                         params={"ids": ",".join(egrids), "apikey": api_key},
                         timeout=15)
        if r.status_code == 401:
            return {e: {"error": "invalid_api_key", "is_herrenlos": None,
                        "herrenlos_type": None, "claim_possible": None,
                        "owner": None, "owner_address": None, "raw_response": None}
                    for e in egrids}
        if r.status_code != 200:
            return {e: {"error": f"http_{r.status_code}", "is_herrenlos": None,
                        "herrenlos_type": None, "claim_possible": None,
                        "owner": None, "owner_address": None, "raw_response": None}
                    for e in egrids}

        data = r.json()
        found = {re["Egrid"] for re in data.get("RealEstates", [])
                 if isinstance(re, dict) and "Egrid" in re}

        results = {}
        for e in egrids:
            if e not in found:
                results[e] = {"owner": None, "owner_address": None,
                               "is_herrenlos": 1,
                               "herrenlos_type": "not_in_grundbuch",
                               "claim_possible": claim_possible_for("BS", "not_in_grundbuch"),
                               "raw_response": None, "error": None}
            else:
                results[e] = {"owner": None, "owner_address": None,
                               "is_herrenlos": None,
                               "herrenlos_type": None, "claim_possible": None,
                               "raw_response": None,
                               "error": "owner_lookup_needs_html_path"}
        return results

    except Exception as exc:
        return {e: {"owner": None, "owner_address": None,
                    "is_herrenlos": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "raw_response": None, "error": str(exc)}
                for e in egrids}


def check_owner_bs(egrid: str, api_key: str = BS_API_KEY) -> dict:
    """Single-EGRID wrapper around check_owner_bs_batch (kept for compatibility)."""
    return check_owner_bs_batch([egrid], api_key).get(egrid, {})


def _check_owner_bs_single_doc(egrid: str, api_key: str = BS_API_KEY) -> dict:
    """
    Original single-EGRID BS public-API parcel check (kept for reference).

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
         delay: float = 0.3):
    """
    Scan BS parcels for herrenlos detection.

    Uses batch API requests (BS_BATCH_SIZE=20 EGRIDs per request) — confirmed
    live 2026-06-09: api.geo.bs.ch accepts comma-separated ids.  Reduces 8,600
    single-EGRID requests to ~430 batch requests (20× fewer HTTP round-trips).
    """
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
    log.info("Will scan %d BS parcels (batch size=%d)", len(parcels), BS_BATCH_SIZE)

    scanned = errors = herrenlos = 0

    with get_conn() as conn:
        # Build list of pending (not-yet-scanned) parcels, then process in batches.
        pending = [p for p in parcels
                   if not (skip_existing and
                           already_scanned(conn, "BS", p["bfs_nr"], str(p["parcel_nr"])))]

        log.info("Pending after skip_existing filter: %d parcels", len(pending))

        for batch_start in range(0, len(pending), BS_BATCH_SIZE):
            batch = pending[batch_start:batch_start + BS_BATCH_SIZE]
            egrids = [p["egrid"] for p in batch]

            results = check_owner_bs_batch(egrids, api_key)

            # Abort on invalid key
            if any(r.get("error") == "invalid_api_key" for r in results.values()):
                log.error("Invalid BS API key — aborting")
                break

            for p in batch:
                egrid  = p["egrid"]
                result = results.get(egrid, {"error": "missing_from_batch_response",
                                             "is_herrenlos": None,
                                             "herrenlos_type": None, "claim_possible": None,
                                             "owner": None, "owner_address": None,
                                             "raw_response": None})
                annotate_herrenlos(result, "BS")
                upsert_parcel(conn, {
                    "egrid":       egrid,
                    "canton":      "BS",
                    "commune":     p.get("commune"),
                    "bfs_nr":      p["bfs_nr"],
                    "parcel_nr":   str(p["parcel_nr"]),
                    "parcel_type": "Liegenschaft",
                    **result,
                })
                scanned += 1
                if result.get("is_herrenlos") == 1:
                    herrenlos += 1
                    log.info("HERRENLOS  %s Nr.%s  EGRID=%s",
                             p.get("commune", "BS"), p["parcel_nr"], egrid)
                if result.get("error"):
                    errors += 1

            if scanned % 200 == 0:
                log.info("Progress %d/%d  herrenlos=%d  errors=%d",
                         scanned, len(pending), herrenlos, errors)

            time.sleep(delay)

    log.info("BS scan done — scanned=%d  herrenlos=%d  errors=%d", scanned, herrenlos, errors)
    return {"scanned": scanned, "herrenlos": herrenlos, "errors": errors}
