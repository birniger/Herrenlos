"""
AR scanner — Appenzell Ausserrhoden
=====================================
STATUS: REQUIRES PROFESSIONAL ACCOUNT (not obtainable by private persons).
  geoportal.ch restricts the ktar.owner.search permission to notaries,
  surveyors, banks, and public authorities. Registration for private
  individuals is denied. This scanner is only usable with institutional access.

Platform : geoportal.ch (shared SPA platform by GEOINFO Applications AG)
Canton   : ktar

- EGRID enumeration : api3.geo.admin.ch/rest/services/ech/MapServer/identify
                      Grid scan over AR bounding box, step=200m
                      Filters results to canton AR (ak="AR")
- Owner lookup      : GET www.geoportal.ch/search/ownerinfo/
                      params: bfs={bfsnr}, liegnr={parcel_nr}, egrid={egrid}, lang=de
                      Requires authenticated session (login cookie).
- Authentication    : POST /api/login with AR_USERNAME + AR_PASSWORD env vars.
                      GET /api/login checks current session validity.
- Herrenlos signal  : response data=[] (empty) OR
                      data[0]["Owner"] is None/empty after auth

REQUIREMENTS
    pip install requests
    env vars:
        AR_USERNAME   — geoportal.ch username with ktar.owner.search permission
        AR_PASSWORD   — geoportal.ch password

    To obtain an account: contact the Amt für Geoinformation Kanton AR
    or GEOINFO Applications AG (support@geoportal.ch).

RATE LIMIT
    No explicit rate limit published; scanner uses 1.5s delay between queries.
    AR has ~20 000 parcels; full scan takes ~8 hours.
"""

import os
import time
import logging
import requests

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from db import get_conn, init_db, already_scanned, upsert_parcel
from scanners.utils import claim_possible_for

log = logging.getLogger("AR")

GEOPORTAL_BASE   = "https://www.geoportal.ch"
LOGIN_URL        = f"{GEOPORTAL_BASE}/api/login"
OWNER_INFO_URL   = f"{GEOPORTAL_BASE}/search/ownerinfo/"
PRIMARY_AREA     = "ktar"

# AR bounding box in LV95 (EPSG:2056)
AR_EMIN, AR_EMAX = 2_725_000, 2_766_000
AR_NMIN, AR_NMAX = 1_240_000, 1_265_000
GRID_STEP = 200   # metres; smaller = more parcels found, more requests

SWISSTOPO_IDENTIFY = (
    "https://api3.geo.admin.ch/rest/services/ech/MapServer/identify"
)

SESSION_LIFETIME = 3600   # re-login after ~1 hour


# ── Auth helpers ──────────────────────────────────────────────────────────────

class GeoportalSession:
    """
    Maintains a logged-in requests.Session for geoportal.ch.
    Reads credentials from AR_USERNAME / AR_PASSWORD env vars.
    """

    def __init__(self):
        self._session    = requests.Session()
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; herrenlos-scanner/1.0)",
            "Accept":     "application/json, text/plain, */*",
            "Origin":     GEOPORTAL_BASE,
            "Referer":    f"{GEOPORTAL_BASE}/{PRIMARY_AREA}",
        })
        self._logged_in_at = 0.0

    @property
    def username(self):
        return os.environ.get("AR_USERNAME", "")

    @property
    def password(self):
        return os.environ.get("AR_PASSWORD", "")

    def login(self):
        if not self.username or not self.password:
            raise RuntimeError(
                "AR_USERNAME and AR_PASSWORD env vars must be set. "
                "Register at geoportal.ch/ktar and obtain ktar.owner.search permission."
            )
        log.info("Logging in to geoportal.ch as %s …", self.username)
        r = self._session.post(
            LOGIN_URL,
            json={"username": self.username, "password": self.password},
            timeout=15,
        )
        if r.status_code not in (200, 201):
            raise RuntimeError(
                f"geoportal.ch login failed ({r.status_code}): {r.text[:200]}"
            )
        user = r.json()
        log.info("Logged in as %s (id=%s)", user.get("username"), user.get("id"))
        self._logged_in_at = time.monotonic()

    def ensure_logged_in(self):
        """Re-login if session has expired or was never started."""
        if time.monotonic() - self._logged_in_at > SESSION_LIFETIME:
            # Check if session is still valid
            r = self._session.get(LOGIN_URL, timeout=10)
            if r.status_code == 200 and r.json():
                self._logged_in_at = time.monotonic()   # still valid
            else:
                self.login()

    def get_owner_info(self, bfs: int, liegnr: str, egrid: str) -> dict | None:
        """
        Query owner info for a parcel.

        Returns:
            None                   — on HTTP / network error
            {"challenge": True}    — session is invalid (not authorised)
            {}                     — herrenlos (empty owner data)
            {"name": ..., ...}     — owner found, parcel has owner
        """
        self.ensure_logged_in()
        params = {
            "bfs":    bfs,
            "liegnr": liegnr,
            "egrid":  egrid,
            "lang":   "de",
        }
        try:
            r = self._session.get(OWNER_INFO_URL, params=params, timeout=15)
        except requests.RequestException as exc:
            log.warning("ownerinfo network error for %s: %s", egrid, exc)
            return None

        if r.status_code != 200:
            log.warning("ownerinfo HTTP %d for %s", r.status_code, egrid)
            return None

        try:
            payload = r.json()
        except ValueError:
            log.warning("ownerinfo non-JSON response for %s: %s", egrid, r.text[:100])
            return None

        # {error:false, data:[{challenge:true}]} → not authorised
        if isinstance(payload, dict):
            data = payload.get("data", [])
            if data and isinstance(data[0], dict) and data[0].get("challenge"):
                log.warning(
                    "ownerinfo returned challenge for %s — session may lack "
                    "ktar.owner.search permission", egrid
                )
                return {"challenge": True}
            # data is a list of owner objects; empty list = herrenlos
            return {"owner_data": data}

        # [] (empty list) — invalid token response / herrenlos
        if isinstance(payload, list):
            return {"owner_data": payload}

        return None


# ── EGRID enumeration ─────────────────────────────────────────────────────────

def _enumerate_egrids(limit: int | None = None, skip_existing: bool = True):
    """
    Yield (egrid, bfsnr, parcel_nr) tuples for all AR parcels via the
    swisstopo AV identify API.  Grid step: GRID_STEP metres.
    """
    seen_egrids = set()
    count       = 0

    with get_conn() as conn:
        if skip_existing:
            rows = conn.execute(
                "SELECT egrid FROM parcels WHERE canton='AR'"
            ).fetchall()
            seen_egrids = {r["egrid"] for r in rows if r["egrid"]}

    identify_session = requests.Session()
    identify_session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; herrenlos-scanner/1.0)"
    })

    e = AR_EMIN
    while e <= AR_EMAX:
        n = AR_NMIN
        while n <= AR_NMAX:
            # Skip if limit reached
            if limit is not None and count >= limit:
                return

            try:
                r = identify_session.get(
                    SWISSTOPO_IDENTIFY,
                    params={
                        "geometry":       f"{e},{n}",
                        "geometryType":   "esriGeometryPoint",
                        "imageDisplay":   "500,500,96",
                        "mapExtent":      f"{e-GRID_STEP},{n-GRID_STEP},{e+GRID_STEP},{n+GRID_STEP}",
                        "tolerance":      5,
                        "layers":         "all:ch.swisstopo-vd.amtliche-vermessung",
                        "sr":             2056,
                        "lang":           "de",
                        "returnGeometry": "false",
                    },
                    timeout=15,
                )
            except requests.RequestException:
                n += GRID_STEP
                continue

            if r.status_code != 200:
                n += GRID_STEP
                continue

            for feat in r.json().get("results", []):
                props = feat.get("properties") or feat.get("attributes") or {}
                if props.get("ak") != "AR":
                    continue
                egrid     = props.get("egris_egrid", "")
                bfsnr     = props.get("bfsnr")
                parcel_nr = props.get("number", props.get("name", ""))

                if not egrid or egrid in seen_egrids:
                    continue
                if skip_existing and already_scanned("AR", egrid):
                    seen_egrids.add(egrid)
                    continue

                seen_egrids.add(egrid)
                count += 1
                yield egrid, bfsnr, parcel_nr

            n += GRID_STEP
        e += GRID_STEP


# ── Owner-data parser ─────────────────────────────────────────────────────────

def _parse_owner(owner_response: dict) -> tuple[bool, str | None]:
    """
    Return (is_herrenlos, owner_str) from the ownerinfo response dict.
    """
    if not owner_response:
        return False, None

    if owner_response.get("challenge"):
        # Not authorised — cannot determine status
        return False, None

    data = owner_response.get("owner_data", [])
    if not data:
        # Empty owner list — parcel has no recorded owner
        return True, None

    # Build a human-readable owner string from the first entry
    entry = data[0] if isinstance(data[0], dict) else {}
    owner = entry.get("Owner") or entry.get("owner") or {}
    if not owner:
        return True, None

    name_parts = []
    for key in ("firstName", "lastName", "name", "Name", "organisation", "Organisation"):
        v = owner.get(key)
        if v:
            name_parts.append(str(v))
    owner_str = " ".join(name_parts).strip() or None
    is_herrenlos = owner_str is None
    return is_herrenlos, owner_str


# ── Main scan function ────────────────────────────────────────────────────────

def scan(limit: int | None = None, skip_existing: bool = True, delay: float = 1.5):
    """
    Full AR scan.  Requires AR_USERNAME + AR_PASSWORD env vars.
    """
    init_db()

    gp = GeoportalSession()
    try:
        gp.login()
    except RuntimeError as exc:
        log.error("%s", exc)
        return

    scanned = 0
    herrenlos = 0

    for egrid, bfsnr, parcel_nr in _enumerate_egrids(limit=limit, skip_existing=skip_existing):
        if limit is not None and scanned >= limit:
            break

        log.info("AR  bfs=%s  parcel=%s  egrid=%s", bfsnr, parcel_nr, egrid)

        owner_response = gp.get_owner_info(bfsnr, parcel_nr, egrid)

        if owner_response is None:
            # Network error — skip, will retry on next run
            time.sleep(delay)
            continue

        if owner_response.get("challenge"):
            log.error(
                "Stopping scan: session lacks ktar.owner.search permission. "
                "Ensure your account has been granted owner search access for AR."
            )
            break

        is_herrenlos, owner_str = _parse_owner(owner_response)

        if is_herrenlos:
            herrenlos += 1
            log.warning("HERRENLOS  AR  bfs=%s  parcel=%s  egrid=%s", bfsnr, parcel_nr, egrid)

        upsert_parcel(
            canton      = "AR",
            commune     = str(bfsnr),
            parcel_nr   = parcel_nr,
            egrid       = egrid,
            owner       = owner_str,
            is_herrenlos= is_herrenlos,
        )

        scanned += 1
        if scanned % 100 == 0:
            log.info("AR progress: %d scanned, %d herrenlos", scanned, herrenlos)

        time.sleep(delay)

    log.info("AR scan complete: %d scanned, %d herrenlos", scanned, herrenlos)
