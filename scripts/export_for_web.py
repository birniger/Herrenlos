#!/usr/bin/env python3
"""
Export herrenlos.db → JSON files for the static dashboard at docs/.

Produces:
  docs/data/progress.json       — per-canton scan progress (small, cheap to refresh)
  docs/data/herrenlos.json      — every herrenlos parcel + WGS84 coordinates
  docs/data/coords_cache.json   — swisstopo lookups cached so we never repeat them

Designed to be safe to run repeatedly (idempotent) and on every CI run.
"""

from __future__ import annotations
import json
import sys
import pathlib
import time
import datetime as dt
import requests

# Make the project root importable so we can reuse db.py / test_fixtures.py
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from db import get_conn                                             # noqa: E402
from test_fixtures import CANTON_STATUS                              # noqa: E402

# ── Output paths ─────────────────────────────────────────────────────────────
DATA_DIR        = PROJECT_ROOT / "docs" / "data"
PROGRESS_JSON   = DATA_DIR / "progress.json"
HERRENLOS_JSON  = DATA_DIR / "herrenlos.json"
HERRENLOS_GEOJSON = DATA_DIR / "herrenlos.geojson"   # opens in QGIS / Mapbox / any GIS tool
HERRENLOS_CSV   = DATA_DIR / "herrenlos.csv"          # opens in Excel / Numbers / pandas
COORDS_CACHE    = DATA_DIR / "coords_cache.json"

# Federal swisstopo cadastral parcel identify endpoint — returns geometry.
SWISSTOPO_IDENTIFY = "https://api3.geo.admin.ch/rest/services/api/MapServer/identify"
UA = "herrenlos-scanner-export"


# Cantons we can never automate (SMS-per-query, mail-only, professional auth).
# Pulled dynamically from CANTON_STATUS so additions are picked up automatically.
UNSCANNABLE_ACCESS = {"blocked", "cant_get"}


def _is_scannable(canton: str) -> bool:
    return CANTON_STATUS.get(canton, {}).get("access") not in UNSCANNABLE_ACCESS


# ── 1. PROGRESS — per-canton scan stats ──────────────────────────────────────

def build_progress() -> dict:
    """One row per canton: enumeration size, scans so far, herrenlos, errors."""
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT canton,
                   (SELECT COUNT(*) FROM parcel_enum pe WHERE pe.canton=p.canton)            AS enumerated,
                   SUM(CASE WHEN is_herrenlos IS NOT NULL THEN 1 ELSE 0 END)                 AS scanned,
                   SUM(CASE WHEN is_herrenlos=1                THEN 1 ELSE 0 END)            AS herrenlos,
                   SUM(CASE WHEN error IS NOT NULL             THEN 1 ELSE 0 END)            AS errors,
                   MAX(scanned_at)                                                            AS last_scan_at
              FROM parcels p
             GROUP BY canton
             ORDER BY canton
        """).fetchall()

    # Rough total-parcel estimates from cantonal docs (used as the % denominator
    # when our parcel_enum table is just a small test seed — for those cantons,
    # `enumerated` will be tiny but the canton's real size is in the thousands).
    CANTON_TOTAL_ESTIMATE = {
        "BS":   7_000,  "UR":  20_000, "FR":  80_000, "JU":  16_000, "SZ":  18_000,
        "BL":  70_000,  "SH":  30_000, "GR": 150_000, "NE":  80_000, "GE":  69_000,
        "BE": 400_000,  "VS": 210_000, "SO":  70_000, "LU": 110_000, "ZH": 450_000,
        "AG": 130_000,  "TG": 100_000, "SG": 115_000, "TI": 190_000, "VD": 250_000,
        "AR":  15_000,  "AI":   5_000, "GL":  15_000, "NW":  14_000, "OW":  13_000,
        "ZG":  30_000,
    }

    out_cantons = []
    for r in rows:
        canton     = r["canton"]
        # Skip cantons that we will never scan — they only ever appear here
        # because of stale test seeding. Stops noise like ZG showing 0/30000.
        if not _is_scannable(canton):
            continue
        status     = CANTON_STATUS.get(canton, {})
        enumerated = r["enumerated"] or 0
        scanned    = r["scanned"]    or 0
        # Denominator for the progress %: prefer the canton's real size estimate
        # when enumeration is a small test seed (heuristic: enum < 100 means seed).
        denom = enumerated if enumerated >= 100 else CANTON_TOTAL_ESTIMATE.get(canton, enumerated or 1)
        pct = round(100 * scanned / denom, 1) if denom else 0.0
        out_cantons.append({
            "canton":             canton,
            "enumerated":         enumerated,
            "scanned":            scanned,
            "herrenlos":          r["herrenlos"] or 0,
            "errors":             r["errors"] or 0,
            "percent":            min(pct, 100.0),
            "estimated_total":    CANTON_TOTAL_ESTIMATE.get(canton),
            "last_scan_at":       r["last_scan_at"],
            "access":             status.get("access"),
            "test_group":         status.get("test_group"),
            "rate_limit":         status.get("rate_limit"),
        })

    # Also include cantons that have an enum but no scans yet
    with get_conn() as conn:
        empty_rows = conn.execute("""
            SELECT canton, COUNT(*) AS enumerated
              FROM parcel_enum
             WHERE canton NOT IN (SELECT DISTINCT canton FROM parcels)
             GROUP BY canton
        """).fetchall()
    seen = {c["canton"] for c in out_cantons}
    for r in empty_rows:
        if not _is_scannable(r["canton"]):
            continue   # don't surface enumerations for unscannable cantons
        if r["canton"] not in seen:
            status = CANTON_STATUS.get(r["canton"], {})
            out_cantons.append({
                "canton":          r["canton"],
                "enumerated":      r["enumerated"] or 0,
                "scanned": 0, "herrenlos": 0, "errors": 0, "percent": 0.0,
                "estimated_total": CANTON_TOTAL_ESTIMATE.get(r["canton"]),
                "last_scan_at":    None,
                "access":          status.get("access"),
                "test_group":      status.get("test_group"),
                "rate_limit":      status.get("rate_limit"),
            })

    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "cantons":      sorted(out_cantons, key=lambda c: c["canton"]),
        "totals": {
            "scanned":   sum(c["scanned"] for c in out_cantons),
            "herrenlos": sum(c["herrenlos"] for c in out_cantons),
            "errors":    sum(c["errors"] for c in out_cantons),
        },
    }


# ── 2. HERRENLOS — every flagged parcel with map coordinates ─────────────────

def _load_coords_cache() -> dict:
    if COORDS_CACHE.exists():
        try:
            return json.loads(COORDS_CACHE.read_text())
        except Exception:
            pass
    return {}


def _save_coords_cache(cache: dict) -> None:
    COORDS_CACHE.write_text(json.dumps(cache, separators=(",", ":")))


def _lookup_wgs84(egrid: str) -> tuple[float, float] | None:
    """
    Resolve an EGRID to a WGS84 (lat, lng) centroid via swisstopo identify.
    Returns None on any failure — caller handles graceful degradation.
    """
    try:
        # Find the parcel by EGRID using a swisstopo "find" search.
        r = requests.get(
            "https://api3.geo.admin.ch/rest/services/api/SearchServer",
            params={
                "type":      "locations",
                "searchText": egrid,
                "sr":         4326,    # WGS84
                "limit":      1,
            },
            headers={"User-Agent": UA},
            timeout=10,
        )
        if r.status_code != 200:
            return None
        results = r.json().get("results", [])
        if not results:
            return None
        attrs = results[0].get("attrs", {})
        lat = attrs.get("lat"); lon = attrs.get("lon")
        if lat is not None and lon is not None:
            return (float(lat), float(lon))
    except Exception:
        pass
    return None


def build_herrenlos(coords_cache: dict) -> dict:
    """Every is_herrenlos=1 parcel, joined with WGS84 coords for map display."""
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT canton, commune, bfs_nr, parcel_nr, egrid,
                   owner, owner_address,
                   herrenlos_type, claim_possible,
                   scanned_at
              FROM parcels
             WHERE is_herrenlos = 1
             ORDER BY canton, commune, parcel_nr
        """).fetchall()

    parcels = []
    new_lookups = 0
    for r in rows:
        egrid = r["egrid"]
        coords = None
        if egrid:
            if egrid in coords_cache:
                coords = coords_cache[egrid]
            else:
                # Be polite — at most 10 fresh lookups per export run
                if new_lookups < 10:
                    looked = _lookup_wgs84(egrid)
                    if looked:
                        coords = list(looked)
                        coords_cache[egrid] = coords
                    else:
                        coords_cache[egrid] = None
                    new_lookups += 1
                    time.sleep(0.2)

        parcels.append({
            "egrid":           egrid,
            "canton":          r["canton"],
            "commune":         r["commune"],
            "bfs_nr":          r["bfs_nr"],
            "parcel_nr":       r["parcel_nr"],
            "owner":           r["owner"],
            "owner_address":   r["owner_address"],
            "herrenlos_type":  r["herrenlos_type"],
            "claim_possible":  r["claim_possible"],
            "scanned_at":      r["scanned_at"],
            "lat":             coords[0] if coords else None,
            "lng":             coords[1] if coords else None,
        })

    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "count":        len(parcels),
        "parcels":      parcels,
    }


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    progress = build_progress()
    PROGRESS_JSON.write_text(json.dumps(progress, indent=2))
    print(f"Wrote {PROGRESS_JSON.relative_to(PROJECT_ROOT)}  "
          f"({len(progress['cantons'])} cantons, "
          f"{progress['totals']['scanned']} scanned, "
          f"{progress['totals']['herrenlos']} herrenlos)")

    coords_cache = _load_coords_cache()
    herrenlos = build_herrenlos(coords_cache)
    HERRENLOS_JSON.write_text(json.dumps(herrenlos, indent=2))
    _save_coords_cache(coords_cache)
    geocoded = sum(1 for p in herrenlos["parcels"] if p["lat"])
    print(f"Wrote {HERRENLOS_JSON.relative_to(PROJECT_ROOT)}  "
          f"({herrenlos['count']} herrenlos parcels, {geocoded} geocoded)")

    # GeoJSON — drop into QGIS / Mapbox / any GIS tool
    features = []
    for p in herrenlos["parcels"]:
        if p["lat"] is None or p["lng"] is None:
            continue
        features.append({
            "type": "Feature",
            "geometry": {"type": "Point", "coordinates": [p["lng"], p["lat"]]},
            "properties": {k: p[k] for k in p if k not in ("lat", "lng")},
        })
    geojson = {
        "type": "FeatureCollection",
        "generated_at": herrenlos["generated_at"],
        "features": features,
    }
    HERRENLOS_GEOJSON.write_text(json.dumps(geojson, indent=2))
    print(f"Wrote {HERRENLOS_GEOJSON.relative_to(PROJECT_ROOT)}  "
          f"({len(features)} features)")

    # CSV — Excel / Numbers / pandas / anything that reads tabular
    import csv as _csv
    csv_cols = ["canton", "commune", "bfs_nr", "parcel_nr", "egrid",
                "owner", "owner_address", "herrenlos_type", "claim_possible",
                "lat", "lng", "scanned_at"]
    with HERRENLOS_CSV.open("w", newline="", encoding="utf-8") as f:
        w = _csv.DictWriter(f, fieldnames=csv_cols, extrasaction="ignore")
        w.writeheader()
        for p in herrenlos["parcels"]:
            w.writerow(p)
    print(f"Wrote {HERRENLOS_CSV.relative_to(PROJECT_ROOT)}  "
          f"({herrenlos['count']} rows)")

    print(f"Wrote {COORDS_CACHE.relative_to(PROJECT_ROOT)}  "
          f"({len(coords_cache)} cached lookups)")


if __name__ == "__main__":
    main()
