"""
geoportal_base.py — shared base for all geoportal.ch canton scanners
=====================================================================
Used by: AG, TG, SG, ZG, GL, NW, OW, TI, VD, GE

Platform : geoportal.ch (Angular SPA by GEOINFO Applications AG)
Auth     : POST /api/login  →  server-side session cookie
Owner API: GET /search/ownerinfo/?bfs=&liegnr=&egrid=&lang=de
Enumerate: swisstopo AV identify (public, no auth)

Each canton needs:
  - USERNAME_ENV / PASSWORD_ENV   (env var names, e.g. AG_USERNAME / AG_PASSWORD)
  - PRIMARY_AREA                  (e.g. "ktag")
  - CANTON_CODE                   (e.g. "AG", matches swisstopo "ak" field)
  - BBOX                          (E_MIN, E_MAX, N_MIN, N_MAX in LV95/EPSG:2056)
  - GRID_STEP                     (metres, default 200)

Shared credentials (fallback):
  Set GEOPORTAL_USERNAME + GEOPORTAL_PASSWORD once to use the same aGov/geoportal.ch
  account for all cantons. Canton-specific env vars (e.g. AG_USERNAME) take priority.
"""

import os
import time
import logging
import requests

import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from db import get_conn, init_db, upsert_parcel
from scanners.utils import is_herrenlos_owner_text, is_sdr_parcel, claim_possible_for

GEOPORTAL_BASE     = "https://www.geoportal.ch"
LOGIN_URL          = f"{GEOPORTAL_BASE}/api/login"
OWNER_INFO_URL     = f"{GEOPORTAL_BASE}/search/ownerinfo/"
SWISSTOPO_IDENTIFY = "https://api3.geo.admin.ch/rest/services/ech/MapServer/identify"

SESSION_LIFETIME   = 3600   # re-login after ~1 hour


# ── Auth / session ────────────────────────────────────────────────────────────

class GeoportalSession:
    """
    Authenticated session for geoportal.ch.
    Reads credentials from the given env-var names.
    """

    def __init__(self, username_env: str, password_env: str, primary_area: str,
                 log: logging.Logger):
        self._session     = requests.Session()
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; herrenlos-scanner/1.0)",
            "Accept":     "application/json, text/plain, */*",
            "Origin":     GEOPORTAL_BASE,
            "Referer":    f"{GEOPORTAL_BASE}/{primary_area}",
        })
        self._username_env = username_env
        self._password_env = password_env
        self._primary_area = primary_area
        self._logged_in_at = 0.0
        self._log          = log

    @property
    def username(self):
        # Canton-specific env var takes priority; fall back to shared GEOPORTAL_USERNAME
        return (os.environ.get(self._username_env)
                or os.environ.get("GEOPORTAL_USERNAME", ""))

    @property
    def password(self):
        return (os.environ.get(self._password_env)
                or os.environ.get("GEOPORTAL_PASSWORD", ""))

    def login(self):
        if not self.username or not self.password:
            raise RuntimeError(
                f"{self._username_env} and {self._password_env} env vars must be set "
                f"(or set GEOPORTAL_USERNAME + GEOPORTAL_PASSWORD as shared fallback). "
                f"Register at geoportal.ch/{self._primary_area} and obtain "
                f"{self._primary_area}.owner.search permission."
            )
        self._log.info("Logging in to geoportal.ch as %s …", self.username)
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
        self._log.info("Logged in as %s (id=%s)", user.get("username"), user.get("id"))
        self._logged_in_at = time.monotonic()

    def ensure_logged_in(self):
        if time.monotonic() - self._logged_in_at > SESSION_LIFETIME:
            r = self._session.get(LOGIN_URL, timeout=10)
            if r.status_code == 200 and r.json():
                self._logged_in_at = time.monotonic()
            else:
                self.login()

    def get_owner_info(self, bfs: int, liegnr: str, egrid: str) -> dict | None:
        """
        Returns:
            None                   — network / HTTP error (skip, retry later)
            {"challenge": True}    — session lacks owner.search permission
            {"owner_data": [...]}  — owner records (may be empty = herrenlos)
        """
        self.ensure_logged_in()
        params = {"bfs": bfs, "liegnr": liegnr, "egrid": egrid, "lang": "de"}
        try:
            r = self._session.get(OWNER_INFO_URL, params=params, timeout=15)
        except requests.RequestException as exc:
            self._log.warning("ownerinfo network error for %s: %s", egrid, exc)
            return None

        if r.status_code != 200:
            self._log.warning("ownerinfo HTTP %d for %s", r.status_code, egrid)
            return None

        try:
            payload = r.json()
        except ValueError:
            self._log.warning("ownerinfo non-JSON for %s: %s", egrid, r.text[:100])
            return None

        if isinstance(payload, dict):
            data = payload.get("data", [])
            if data and isinstance(data[0], dict) and data[0].get("challenge"):
                self._log.warning(
                    "ownerinfo challenge for %s — session lacks %s.owner.search",
                    egrid, self._primary_area,
                )
                return {"challenge": True}
            return {"owner_data": data}

        if isinstance(payload, list):
            return {"owner_data": payload}

        return None


# ── EGRID enumeration (swisstopo, public) ─────────────────────────────────────

def enumerate_egrids(
    canton_code: str,
    e_min: int, e_max: int, n_min: int, n_max: int,
    grid_step: int = 200,
    limit: int | None = None,
    skip_existing: bool = True,
):
    """
    Yield (egrid, bfsnr, parcel_nr, commune) via swisstopo AV identify.
    Filters to parcels whose canton abbreviation (ak) == canton_code.
    Skips SDR/Baurecht parcels (BGE 118 II 115 — cannot be derelicted).
    """
    seen_egrids: set[str] = set()
    count = 0

    with get_conn() as conn:
        if skip_existing:
            rows = conn.execute(
                "SELECT egrid, bfs_nr, parcel_nr FROM parcels WHERE canton=? AND is_herrenlos IS NOT NULL",
                (canton_code,)
            ).fetchall()
            seen_egrids = {r["egrid"] for r in rows if r["egrid"]}

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; herrenlos-scanner/1.0)"
    })

    e = e_min
    while e <= e_max:
        n = n_min
        while n <= n_max:
            if limit is not None and count >= limit:
                return

            try:
                r = session.get(
                    SWISSTOPO_IDENTIFY,
                    params={
                        "geometry":       f"{e},{n}",
                        "geometryType":   "esriGeometryPoint",
                        "imageDisplay":   "500,500,96",
                        "mapExtent":      f"{e-grid_step},{n-grid_step},{e+grid_step},{n+grid_step}",
                        "tolerance":      5,
                        "layers":         "all:ch.swisstopo-vd.amtliche-vermessung",
                        "sr":             2056,
                        "lang":           "de",
                        "returnGeometry": "false",
                    },
                    timeout=15,
                )
            except requests.RequestException:
                n += grid_step
                continue

            if r.status_code != 200:
                n += grid_step
                continue

            for feat in r.json().get("results", []):
                props = feat.get("attributes") or feat.get("properties") or {}
                if props.get("ak") != canton_code:
                    continue
                egrid     = props.get("egris_egrid", "")
                bfsnr     = props.get("bfsnr")
                parcel_nr = props.get("number", props.get("name", ""))
                commune   = props.get("label", "")
                obj_type  = props.get("objektart", "")

                if not egrid or egrid in seen_egrids:
                    continue
                if is_sdr_parcel(obj_type):
                    seen_egrids.add(egrid)
                    continue

                seen_egrids.add(egrid)
                count += 1
                yield egrid, bfsnr, parcel_nr, commune

            n += grid_step
        e += grid_step


# ── Owner parser ─────────────────────────────────────────────────────────────

def parse_owner(owner_response: dict) -> tuple[bool, str | None]:
    """Return (is_herrenlos, owner_str)."""
    if not owner_response or owner_response.get("challenge"):
        return False, None

    data = owner_response.get("owner_data", [])
    if not data:
        return True, None

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

    # Portal may return literal herrenlos text in the owner field — treat as herrenlos
    if owner_str and is_herrenlos_owner_text(owner_str):
        return True, None

    return (owner_str is None), owner_str


# ── Generic scan runner ───────────────────────────────────────────────────────

def run_scan(
    canton_code: str,
    primary_area: str,
    username_env: str,
    password_env: str,
    e_min: int, e_max: int, n_min: int, n_max: int,
    grid_step: int = 200,
    limit: int | None = None,
    skip_existing: bool = True,
    delay: float = 1.5,
    log: logging.Logger | None = None,
):
    """
    Full scan for a geoportal.ch canton.
    Requires {username_env} + {password_env} env vars with {primary_area}.owner.search permission.
    """
    if log is None:
        log = logging.getLogger(canton_code)

    init_db()
    gp = GeoportalSession(username_env, password_env, primary_area, log)
    try:
        gp.login()
    except RuntimeError as exc:
        log.error("%s", exc)
        return

    scanned   = 0
    herrenlos = 0

    with get_conn() as conn:
        for egrid, bfsnr, parcel_nr, commune in enumerate_egrids(
            canton_code, e_min, e_max, n_min, n_max,
            grid_step=grid_step, limit=limit, skip_existing=skip_existing,
        ):
            if limit is not None and scanned >= limit:
                break

            log.info("%s  bfs=%s  parcel=%s  egrid=%s", canton_code, bfsnr, parcel_nr, egrid)
            owner_response = gp.get_owner_info(bfsnr, parcel_nr, egrid)

            if owner_response is None:
                time.sleep(delay)
                continue

            if owner_response.get("challenge"):
                log.error(
                    "Stopping: session lacks %s.owner.search permission.",
                    primary_area,
                )
                break

            is_herrenlos, owner_str = parse_owner(owner_response)
            if is_herrenlos:
                herrenlos += 1
                log.warning(
                    "HERRENLOS  %s  bfs=%s  parcel=%s  egrid=%s",
                    canton_code, bfsnr, parcel_nr, egrid,
                )

            h_type = "dereliktion" if is_herrenlos else None
            upsert_parcel(conn, {
                "egrid":          egrid,
                "canton":         canton_code,
                "commune":        commune or str(bfsnr),
                "bfs_nr":         str(bfsnr),
                "parcel_nr":      parcel_nr,
                "parcel_type":    "Liegenschaft",
                "owner":          owner_str,
                "owner_address":  None,
                "is_herrenlos":   1 if is_herrenlos else 0,
                "herrenlos_type": h_type,
                "claim_possible": claim_possible_for(canton_code, h_type) if is_herrenlos else None,
                "raw_response":   None,
                "error":          None,
            })

            scanned += 1
            if scanned % 100 == 0:
                log.info("%s progress: %d scanned, %d herrenlos", canton_code, scanned, herrenlos)

            time.sleep(delay)

    log.info("%s scan complete: %d scanned, %d herrenlos", canton_code, scanned, herrenlos)
