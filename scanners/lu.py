"""
LU scanner — Luzern
====================
STATUS (re-verified 2026-05-18 via direct portal inspection): BLOCKED.

The LU Eigentümerabfrage at grundbuch.lu.ch/onlinedienste/eigentuemerabfrage
requires a Swiss mobile number + SMS PIN per query (4 form fields: Grundbuch,
Grundstück-Nr, Mobile-Nummer, PIN-from-SMS). This is the same operational
dead-end as ZH / ZG / TG — cannot be solved by IP rotation or proxies,
because each query requires a human SMS action.

The earlier "5/day public" research underweighted the SMS requirement.

This file remains as a SKELETON (with TODO_LU_API markers) only because the
module structure was already done before the SMS gate was discovered. It is
NOT used by the test framework (CANTON_STATUS["LU"]["access"] == "blocked").
Kept for documentation of the failure mode.

NO RECLASSIFICATION PATH known unless LU launches an SMS-free public path.

PLATFORM — grundbuch.lu.ch:
  Public form at https://grundbuch.lu.ch/onlinedienste/eigentuemerabfrage
  Confirmed 2026-05-18 via Chrome DevTools direct inspection.

RATE LIMIT: 5/day per Mobile-Nummer (SMS PIN per query).

EGRID enumeration:
  swisstopo identify API grid scan (same pattern as BL/SZ/UR/SH).
  LU is mid-sized (~110,000 parcels, ~1500 km²) → grid step 200 m.

CHECK_OWNER FLOW (TO BE COMPLETED via browser inspection):
  Based on Luzerner Zeitung + grundbuch.lu.ch site analysis, the flow is:
    1. POST /onlinedienste/eigentuemerabfrage/query with parcel-nr or EGRID,
       sending the session cookie obtained at registration.
    2. Response: HTML or JSON with owner name + address, or "kein Eintrag".
  The EXACT endpoint URL and request shape need browser-level inspection
  (DevTools → Network tab) on a registered LU session.

HERRENLOS SIGNAL:
  Two types (same vocabulary as our other scanners):
    not_in_grundbuch  — parcel exists in cadastre but not in RF (Art.664 ZGB)
    dereliktion       — in RF but owner field empty (Art.964 ZGB)

PARCELS:
  ~110 000

REQUIRES:
  Set LU_API_KEY in .env after registering at
  https://grundbuch.lu.ch/onlinedienste/eigentuemerabfrage

REFERENCE PATTERN:
  Closest existing scanner is scanners/bs.py (free-key REST + swisstopo grid).
"""

import os
import time
import logging
import requests

import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from db import get_conn, init_db, already_scanned, upsert_parcel, enum_cached, store_enum, log_captcha  # noqa: F401
from scanners.utils import is_herrenlos_owner_text, claim_possible_for

log = logging.getLogger("LU")

# ── Endpoints ────────────────────────────────────────────────────────────────
LU_BASE        = "https://grundbuch.lu.ch"
LU_QUERY_PAGE  = f"{LU_BASE}/onlinedienste/eigentuemerabfrage"
# TODO_LU_API: the exact POST endpoint and request body shape — see check_owner()
# below.  Determine by registering a free account at LU_QUERY_PAGE, then watching
# the Network tab in browser DevTools when a query is submitted.

SWISSTOPO_IDENTIFY = "https://api3.geo.admin.ch/rest/services/api/MapServer/identify"
UA                 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"

# ── Credentials (set in .env or env var) ─────────────────────────────────────
LU_API_KEY = os.environ.get("LU_API_KEY", "").strip()

# ── LU LV95 bounding box ──────────────────────────────────────────────────────
LU_EMIN, LU_EMAX = 2_628_000, 2_695_000
LU_NMIN, LU_NMAX = 1_198_000, 1_248_000
LU_GRID_STEP     = 200   # metres — ~85k grid points, one-time ~1 h


# ── Parcel enumeration via swisstopo ─────────────────────────────────────────

def enumerate_parcels_swisstopo(
        emin=LU_EMIN, emax=LU_EMAX,
        nmin=LU_NMIN, nmax=LU_NMAX,
        step=LU_GRID_STEP) -> list[dict]:
    """Grid scan over LU bbox; returns list of {egrid, bfs_nr, parcel_nr, commune} dicts."""
    seen:    set[str]  = set()
    parcels: list[dict] = []
    session = requests.Session()
    session.headers["User-Agent"] = UA

    e_range = range(emin, emax + 1, step)
    n_range = range(nmin, nmax + 1, step)
    total   = len(e_range) * len(n_range)
    checked = 0

    log.info("LU swisstopo grid scan: %d × %d = %d points at %dm",
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
                    if attrs.get("ak", "").upper() != "LU":
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
                log.info("Grid %d/%d  unique LU parcels=%d",
                         checked, total, len(parcels))
            time.sleep(0.1)

    log.info("LU grid scan complete: %d unique parcels", len(parcels))
    return parcels


# ── Owner check (REQUIRES BROWSER INSPECTION TO COMPLETE) ────────────────────

def check_owner(session: requests.Session, egrid: str,
                bfs_nr: str = "", parcel_nr: str = "") -> dict:
    """
    Query owner for one LU parcel via grundbuch.lu.ch.

    TODO_LU_API
    -----------
    The exact request shape is unknown — register at LU_QUERY_PAGE, log in,
    submit a sample query, capture the Network request in DevTools. Likely:

        POST {LU_BASE}/onlinedienste/eigentuemerabfrage/api/query
        Headers: Cookie: <session cookie>  or  Authorization: Bearer {LU_API_KEY}
        Body:    JSON or form-encoded; may take egrid, bfs+parcel, address, or all

    Expected response: HTML page or JSON with owner name + address; or
    "Kein Grundbuch-Eintrag" for not_in_grundbuch.

    Until that's captured, this function returns error="not_implemented" — the
    test framework records this as a SKIP with the documented blocker rather
    than a false positive.
    """
    if not LU_API_KEY:
        return {"owner": None, "owner_address": None,
                "is_herrenlos": None,
                "herrenlos_type": None, "claim_possible": None,
                "raw_response": None,
                "error": "lu_api_key_missing"}

    return {"owner": None, "owner_address": None,
            "is_herrenlos": None,
            "herrenlos_type": None, "claim_possible": None,
            "raw_response": None,
            "error": "not_implemented_needs_browser_capture"}


# ── Main scanner ─────────────────────────────────────────────────────────────

def scan(limit: int | None = None,
         skip_existing: bool = True,
         delay: float = 1.0):
    """
    Scan LU parcels for herrenlos detection.

    First run: ~1h swisstopo grid scan (cached). Each query is rate-limited
    server-side to 5/day/user — paid residential proxies needed for full scan.

    limit         : stop after N parcels
    skip_existing : skip parcels already in DB
    delay         : seconds between queries
    """
    init_db()

    with get_conn() as conn:
        cached = enum_cached(conn, "LU")
    if cached:
        log.info("Using cached LU parcel list (%d parcels)", len(cached))
        parcels = cached
    else:
        log.info("No cache — running swisstopo grid scan (~1h) …")
        parcels = enumerate_parcels_swisstopo()
        with get_conn() as conn:
            store_enum(conn, "LU", parcels)
        log.info("Cached %d LU parcels", len(parcels))

    if limit:
        parcels = parcels[:limit]

    session = requests.Session()
    session.headers["User-Agent"] = UA
    # TODO_LU_API: when implementing, set Authorization or Cookie header here.

    scanned = errors = herrenlos = 0
    with get_conn() as conn:
        for p in parcels:
            egrid   = p["egrid"]
            bfs     = p["bfs_nr"]
            nr      = p["parcel_nr"]
            commune = p.get("commune", "")

            if skip_existing and already_scanned(conn, "LU", bfs, nr):
                continue

            result = check_owner(session, egrid, bfs, nr)

            upsert_parcel(conn, {
                "egrid":       egrid,
                "canton":      "LU",
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
            if result.get("error"):
                errors += 1

            if scanned % 50 == 0:
                log.info("Progress %d  herrenlos=%d  errors=%d",
                         scanned, herrenlos, errors)
            time.sleep(delay)

    log.info("LU scan done — scanned=%d  herrenlos=%d  errors=%d",
             scanned, herrenlos, errors)
    return {"scanned": scanned, "herrenlos": herrenlos, "errors": errors}
