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

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from db import get_conn, init_db, already_scanned, upsert_parcel
from scanners.utils import annotate_herrenlos

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
    Two-step owner lookup for BS:
      1. realestatesinformation  → get section/parcel number + OwnershipInformation URL
      2. /eigentum/{section}/{parcel} → get owner name/address
    """
    try:
        # Step 1: get parcel metadata + owner URL
        r1 = requests.get(BS_INFO_URL, params={"ids": egrid, "apikey": api_key}, timeout=15)
        if r1.status_code == 401:
            return {"error": "invalid_api_key", "is_herrenlos": None,
                    "owner": None, "owner_address": None, "raw_response": None}
        if r1.status_code != 200:
            return {"error": f"http_{r1.status_code}", "is_herrenlos": None,
                    "owner": None, "owner_address": None, "raw_response": None}

        data1 = r1.json()
        # data1 may be a list or dict; normalise
        items = data1 if isinstance(data1, list) else data1.get("realEstates", [data1])
        if not items:
            # EGRID not in the realestates API → no Grundbuch entry (Art. 664 ZGB)
            return {"owner": None, "owner_address": None,
                    "is_herrenlos": 1,
                    "herrenlos_type": "not_in_grundbuch",
                    "claim_possible": 0,
                    "raw_response": None, "error": None}

        item = items[0]
        owner_url = item.get("OwnershipInformation") or item.get("ownershipInformation")

        if not owner_url:
            # Parcel in realestates API but no ownership section → dereliktion
            return {"owner": None, "owner_address": None,
                    "is_herrenlos": 1,
                    "herrenlos_type": "dereliktion",
                    "claim_possible": None,  # annotate_herrenlos fills (BS → 0)
                    "raw_response": str(item)[:300], "error": None}

        # Step 2: fetch owner data
        r2 = requests.get(owner_url, timeout=15)
        if r2.status_code == 404:
            # Ownership URL exists but owner record absent → not_in_grundbuch
            return {"owner": None, "owner_address": None,
                    "is_herrenlos": 1,
                    "herrenlos_type": "not_in_grundbuch",
                    "claim_possible": 0,
                    "raw_response": None, "error": None}
        if r2.status_code != 200:
            return {"error": f"owner_http_{r2.status_code}", "is_herrenlos": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "owner": None, "owner_address": None, "raw_response": None}

        data2 = r2.json()
        owners = data2 if isinstance(data2, list) else data2.get("owners", [])
        if not owners:
            # Owner record present but empty → dereliktion
            return {"owner": None, "owner_address": None,
                    "is_herrenlos": 1,
                    "herrenlos_type": "dereliktion",
                    "claim_possible": None,  # annotate_herrenlos fills (BS → 0)
                    "raw_response": str(data2)[:300], "error": None}

        names = "; ".join(
            " ".join(filter(None, [o.get("lastname"), o.get("firstname"),
                                   o.get("name"), o.get("companyName")]))
            for o in owners
        )
        addrs = "; ".join(o.get("address", "") for o in owners if o.get("address"))
        return {"owner": names or None, "owner_address": addrs or None,
                "is_herrenlos": 0, "raw_response": None, "error": None}

    except Exception as exc:
        return {"owner": None, "owner_address": None,
                "is_herrenlos": None, "raw_response": None, "error": str(exc)}


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
    log.info("Enumerating BS parcels via swisstopo grid …")
    parcels = enumerate_egrids()
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
