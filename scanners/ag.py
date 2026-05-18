"""
AG scanner — Aargau
====================
STATUS (2026-05-18): RE-ROUTED to public path. Previous implementation targeted
  the professional `geoportal.ch ktag.owner.search` endpoint (still available
  at the bottom of this file as scan_ktag_professional() for institutional
  callers). The new default `scan()` targets the PUBLIC ag.ch AGIS Viewer
  which is open to private persons after free registration.

PLATFORM — public AGIS Viewer (verified 2026-05):
  Web app at https://www.ag.ch/app/agisviewer4/v1/agisviewer.html
  (redirects to https://www.ag.ch/geoportal/apps/onlinekarten)
  Free registration at https://www.ag.ch/de/smartserviceportal/konto/registrierung

AUTH:
  Free smartserviceportal account (open to private persons). 10 free queries
  per registered user. Login is interactive via AGOV/SwissID (similar to BE).
  Token can be cached after first login (see BE scanner for the pattern).

RATE LIMIT:
  10 free queries per registered user.  Hard limit.  Paid residential proxies
  needed for full canton scan (~$30 — similar profile to GR).

EGRID enumeration:
  swisstopo identify API grid scan. AG is ~130k parcels, ~1400 km².

CHECK_OWNER FLOW (TO BE COMPLETED via browser inspection):
  1. POST/GET request from the AGIS Viewer JS SPA to the smartserviceportal
     backend, sending the OAuth Bearer token and the parcel id.
  2. Response: JSON with owner name + address (verified by aargauerzeitung.ch
     article: "in seconds, find out who owns a property").
  Determine endpoint URL + request shape by registering a free account, then
  watching the Network tab in browser DevTools.

HERRENLOS SIGNAL:
  not_in_grundbuch  — parcel exists in cadastre but no AGOBIS record
  dereliktion       — record exists, owner field empty / blocked

PARCELS:
  ~130 000

REQUIRES:
  Set AG_API_KEY (or AG_BEARER_TOKEN) in .env after registering at
  https://www.ag.ch/de/smartserviceportal/konto/registrierung

REFERENCE PATTERN:
  Closest existing scanners:
    - BE (scanners/be.py)  for the interactive OIDC login + token cache pattern
    - BS (scanners/bs.py)  for the simple REST + free-key pattern
"""

import os
import time
import logging
import requests

import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from db import get_conn, init_db, already_scanned, upsert_parcel, enum_cached, store_enum
from scanners.utils import is_herrenlos_owner_text, claim_possible_for  # noqa: F401

log = logging.getLogger("AG")

# ── Endpoints ────────────────────────────────────────────────────────────────
AG_BASE           = "https://www.ag.ch"
AG_AGIS_VIEWER    = f"{AG_BASE}/geoportal/apps/onlinekarten"
AG_REGISTER_URL   = f"{AG_BASE}/de/smartserviceportal/konto/registrierung"
# TODO_AG_API: the exact owner-query endpoint URL and request shape — see
# check_owner() below. Determine by registering an account at AG_REGISTER_URL,
# then watching the Network tab in browser DevTools when you click a parcel
# and request owner info.

SWISSTOPO_IDENTIFY = "https://api3.geo.admin.ch/rest/services/api/MapServer/identify"
UA                 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"

# ── Credentials (set in .env or env var) ─────────────────────────────────────
AG_BEARER_TOKEN = os.environ.get("AG_BEARER_TOKEN", "").strip()

# ── AG LV95 bounding box ──────────────────────────────────────────────────────
AG_EMIN, AG_EMAX = 2_618_000, 2_680_000
AG_NMIN, AG_NMAX = 1_232_000, 1_270_000
AG_GRID_STEP     = 200


# ── Parcel enumeration via swisstopo ─────────────────────────────────────────

def enumerate_parcels_swisstopo(
        emin=AG_EMIN, emax=AG_EMAX,
        nmin=AG_NMIN, nmax=AG_NMAX,
        step=AG_GRID_STEP) -> list[dict]:
    """Grid scan over AG bbox; same pattern as BL/LU."""
    seen:    set[str]  = set()
    parcels: list[dict] = []
    session = requests.Session()
    session.headers["User-Agent"] = UA

    e_range = range(emin, emax + 1, step)
    n_range = range(nmin, nmax + 1, step)
    total   = len(e_range) * len(n_range)
    checked = 0
    log.info("AG swisstopo grid scan: %d × %d = %d points at %dm",
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
                    if attrs.get("ak", "").upper() != "AG":
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
                log.info("Grid %d/%d  unique AG parcels=%d",
                         checked, total, len(parcels))
            time.sleep(0.1)
    log.info("AG grid scan complete: %d unique parcels", len(parcels))
    return parcels


# ── Owner check (REQUIRES BROWSER INSPECTION TO COMPLETE) ────────────────────

def check_owner(session: requests.Session, egrid: str,
                bfs_nr: str = "", parcel_nr: str = "") -> dict:
    """
    Query owner for one AG parcel via the public AGIS Viewer.

    TODO_AG_API
    -----------
    Register a free account at AG_REGISTER_URL, log in, open the AGIS Viewer,
    click on a parcel, and inspect the Network tab to capture:
      - The owner-query endpoint URL  (likely under /geoportal/api/… or
        /smartserviceportal/api/…)
      - The Bearer token format (OAuth) and any extra headers
      - The request body shape (probably contains EGRID or internal parcel id)
      - The response JSON schema (look for fields like 'eigentuemer', 'name',
        'adresse')

    Until that's captured this returns error="not_implemented_needs_browser_capture".
    """
    if not AG_BEARER_TOKEN:
        return {"owner": None, "owner_address": None,
                "is_herrenlos": None,
                "herrenlos_type": None, "claim_possible": None,
                "raw_response": None,
                "error": "ag_bearer_token_missing"}

    return {"owner": None, "owner_address": None,
            "is_herrenlos": None,
            "herrenlos_type": None, "claim_possible": None,
            "raw_response": None,
            "error": "not_implemented_needs_browser_capture"}


# ── Main scanner ─────────────────────────────────────────────────────────────

def scan(limit: int | None = None,
         skip_existing: bool = True,
         delay: float = 1.5):
    """
    Scan AG parcels via the PUBLIC AGIS Viewer (re-routed 2026-05-18).
    For the legacy professional ktag.owner.search path, call
    scan_ktag_professional() instead.
    """
    init_db()

    with get_conn() as conn:
        cached = enum_cached(conn, "AG")
    if cached:
        log.info("Using cached AG parcel list (%d parcels)", len(cached))
        parcels = cached
    else:
        log.info("No cache — running swisstopo grid scan …")
        parcels = enumerate_parcels_swisstopo()
        with get_conn() as conn:
            store_enum(conn, "AG", parcels)
        log.info("Cached %d AG parcels", len(parcels))

    if limit:
        parcels = parcels[:limit]

    session = requests.Session()
    session.headers["User-Agent"] = UA
    # TODO_AG_API: set Authorization header with AG_BEARER_TOKEN here.

    scanned = errors = herrenlos = 0
    with get_conn() as conn:
        for p in parcels:
            egrid   = p["egrid"]
            bfs     = p["bfs_nr"]
            nr      = p["parcel_nr"]
            commune = p.get("commune", "")

            if skip_existing and already_scanned(conn, "AG", bfs, nr):
                continue

            result = check_owner(session, egrid, bfs, nr)

            upsert_parcel(conn, {
                "egrid":       egrid,
                "canton":      "AG",
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

    log.info("AG scan done — scanned=%d  herrenlos=%d  errors=%d",
             scanned, herrenlos, errors)
    return {"scanned": scanned, "herrenlos": herrenlos, "errors": errors}


# ── Legacy: professional ktag.owner.search path ─────────────────────────────
def scan_ktag_professional(limit=None, skip_existing=True, delay=1.5):
    """
    Old implementation: targets geoportal.ch ktag.owner.search permission
    (notaries / surveyors / banks / public authorities only).
    Kept for institutional callers; not used by default.
    """
    from scanners.geoportal_base import run_scan
    return run_scan(
        canton_code  = "AG",
        primary_area = "ktag",
        username_env = "AG_USERNAME",
        password_env = "AG_PASSWORD",
        e_min=AG_EMIN, e_max=AG_EMAX,
        n_min=AG_NMIN, n_max=AG_NMAX,
        grid_step=AG_GRID_STEP, limit=limit, skip_existing=skip_existing,
        delay=delay, log=log,
    )
