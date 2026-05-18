"""
VS scanner — Valais / Wallis
==============================
- EGRID enumeration : swisstopo identify API grid scan (step=400 m, ~2 h one-time)
                      Cached in parcel_enum table.
- Owner lookup      : capweb-public.apps.vs.ch/capweb-public/api/gb/
                        GET /gb/grundstueck?egrid={EGRID}&historisiert=OHNE_HIST
                        → internal grundstueckId
                        GET /gb/eigentum/sicht/grundstueck?grundstueckIds={id}
                        → eigentuemer list
                      Requires a SwissID account linked to the VS etatvs Keycloak
                      realm (OIDC PKCE). Playwright handles the OAuth flow once;
                      Bearer token cached in ~/.herrenlos_scanner/vs_token.json.
- Herrenlos signal  : 404 on /gb/grundstueck (not in Grundbuch, Type 2)
                      OR eigentuemer list empty / no real owner (Type 1)
- Rate limit        : Basic JSON endpoints appear unlimited; ICP-extract has 10/day.
                      We only touch the JSON API; conservative 1.5 s delay applied.
- Parcels           : ~210 000

SETUP
-----
1. Register a free SwissID account at https://www.swissid.ch/   (one-time)
2. First run:
     python main.py vs --limit 50
   A visible Chromium window opens — complete the SwissID login manually
   (incl. the SwissID 2FA app push or SMS). The OIDC access_token is then
   cached so subsequent runs are silent until the refresh_token expires.
   No env-var credentials are needed (and would not work anyway — SwissID
   requires 2FA).

LOGIN FLOW
----------
  CAPWEB Angular SPA
    → Keycloak  sso.apps.vs.ch/auth/realms/etatvs  (PKCE, OIDC)
        → SwissID IDP button  →  login.swissid.ch  (2-step: email then password)
    → redirect back through Keycloak → CAPWEB stores access_token in localStorage
  We extract the access_token via playwright.evaluate() and use it in requests.

REQUIRES
--------
  pip install playwright playwright-stealth
  playwright install chromium
"""

import os
import re
import json
import time
import logging
import pathlib
import hashlib
import base64
import secrets
import webbrowser
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests

import sys
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from db import get_conn, init_db, already_scanned, upsert_parcel, enum_cached, store_enum
from scanners.utils import annotate_herrenlos

log = logging.getLogger("VS")

# ── Constants ────────────────────────────────────────────────────────────────

CAPWEB_BASE        = "https://capweb-public.apps.vs.ch/capweb-public"
CAPWEB_UI          = f"{CAPWEB_BASE}/ui/"
CAPWEB_API         = f"{CAPWEB_BASE}/api"

GRUNDSTUECK_EP     = f"{CAPWEB_API}/gb/grundstueck"
EIGENTUM_EP        = f"{CAPWEB_API}/gb/eigentum/sicht/grundstueck"

KEYCLOAK_ISSUER    = "https://sso.apps.vs.ch/auth/realms/etatvs"
KEYCLOAK_CLIENT    = "capitastra-public-client"
KEYCLOAK_AUTH_EP   = f"{KEYCLOAK_ISSUER}/protocol/openid-connect/auth"
KEYCLOAK_TOKEN_EP  = f"{KEYCLOAK_ISSUER}/protocol/openid-connect/token"
CALLBACK_PORT      = 8765
CALLBACK_URI       = f"http://localhost:{CALLBACK_PORT}/callback"

SWISSTOPO_IDENTIFY = "https://api3.geo.admin.ch/rest/services/api/MapServer/identify"

UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

# No credentials needed — login happens via the browser (see oidc_login_browser)

TOKEN_CACHE = pathlib.Path.home() / ".herrenlos_scanner" / "vs_token.json"

# VS LV95 bounding box (tight — starts inside VS territory)
VS_EMIN, VS_EMAX = 2_548_000, 2_682_000   # Monthey → Simplon
VS_NMIN, VS_NMAX = 1_082_000, 1_165_000   # southern Alps → Bernese border
VS_GRID_STEP     = 400   # metres — ~73k points for a large mountainous canton

# Centre of Sion/Sitten — used as the starting point for quick scans
VS_SION_E, VS_SION_N = 2_594_000, 1_119_000


# ── Parcel enumeration via swisstopo ─────────────────────────────────────────

def enumerate_parcels_swisstopo(
        emin=VS_EMIN, emax=VS_EMAX,
        nmin=VS_NMIN, nmax=VS_NMAX,
        step=VS_GRID_STEP,
        max_parcels: int | None = None) -> list[dict]:
    """
    Grid scan — returns {egrid, bfs_nr, parcel_nr, commune} dicts.

    max_parcels: stop as soon as this many unique parcels are found.
                 Used for quick tests; result is NOT cached when set.
    """
    seen:    set[str]  = set()
    parcels: list[dict] = []
    session = requests.Session()
    session.headers["User-Agent"] = UA

    e_range = range(emin, emax + 1, step)
    n_range = range(nmin, nmax + 1, step)
    total   = len(e_range) * len(n_range)
    checked = 0

    if max_parcels:
        # Quick mode: scan a small 4 km × 4 km grid centred on Sion at 200 m steps.
        # Sion is the VS capital — guaranteed dense parcel coverage.
        log.info(
            "VS swisstopo quick scan: 4 km grid around Sion, stopping after %d parcels",
            max_parcels,
        )
        for e in range(VS_SION_E - 2_000, VS_SION_E + 2_001, 200):
            for n in range(VS_SION_N - 2_000, VS_SION_N + 2_001, 200):
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
                    }, timeout=12)
                    if r.status_code == 200:
                        for feat in r.json().get("results", []):
                            attrs = feat.get("attributes", {})
                            if attrs.get("ak", "").upper() != "VS":
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
                time.sleep(0.1)
                if len(parcels) >= max_parcels:
                    break
            if len(parcels) >= max_parcels:
                break
        log.info("Quick scan complete: %d VS parcels found (%d points checked)",
                 len(parcels), checked)
        return parcels

    # Full grid scan
    log.info(
        "VS swisstopo grid scan: %d × %d = %d points at %d m",
        len(e_range), len(n_range), total, step,
    )
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
                }, timeout=12)

                if r.status_code != 200:
                    continue

                for feat in r.json().get("results", []):
                    attrs = feat.get("attributes", {})
                    if attrs.get("ak", "").upper() != "VS":
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
                log.info(
                    "Grid %d/%d  unique VS parcels=%d", checked, total, len(parcels)
                )
            time.sleep(0.1)

    log.info("Grid scan complete: %d unique VS parcels found", len(parcels))
    return parcels


# ── Token cache helpers ───────────────────────────────────────────────────────

def _load_cached_token() -> dict | None:
    """Load cached Bearer token from disk; return None if absent/expired."""
    try:
        if TOKEN_CACHE.exists():
            data = json.loads(TOKEN_CACHE.read_text())
            token = data.get("access_token", "")
            expires_at = data.get("expires_at", 0)
            if token and time.time() < expires_at - 60:
                log.info("Loaded cached VS Bearer token (expires in %ds)",
                         int(expires_at - time.time()))
                return data
            if token:
                log.info("Cached token present but expired — will refresh")
    except Exception as exc:
        log.debug("Token cache load error: %s", exc)
    return None


def _save_token(token_data: dict):
    """Persist token data to disk."""
    try:
        TOKEN_CACHE.parent.mkdir(parents=True, exist_ok=True)
        TOKEN_CACHE.write_text(json.dumps(token_data, indent=2))
        log.info("Cached VS Bearer token to %s", TOKEN_CACHE)
    except Exception as exc:
        log.debug("Token cache save error: %s", exc)


# ── OIDC login — browser + network interception ──────────────────────────────
#
# Flow:
#   1. Open a visible Playwright browser and navigate to CAPWEB_UI
#   2. Angular triggers the PKCE redirect to Keycloak automatically
#   3. User logs in with whatever SwissID method they prefer (passkey, SMS, …)
#   4. Angular exchanges the auth code — we intercept the token endpoint response
#      via Playwright's page.on("response") and grab the access_token from it
#
# No localhost redirect URI needed, no storage extraction.
# Requires: pip install playwright playwright-stealth && playwright install chromium

def oidc_login() -> dict | None:
    """
    Open a visible browser to CAPWEB and capture the Bearer token by
    intercepting Keycloak's token-endpoint response.

    The user logs in however SwissID allows (passkey, SMS, password, …).
    Returns {access_token, refresh_token, expires_at} or None on failure.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise RuntimeError(
            "playwright not installed.\n"
            "Run: pip install playwright playwright-stealth && playwright install chromium"
        )

    captured: dict = {}

    def _on_response(response):
        """Intercept the Keycloak token endpoint response."""
        if "openid-connect/token" not in response.url:
            return
        try:
            data = response.json()
            if "access_token" in data:
                captured.update(data)
                log.info("Token intercepted from Keycloak token endpoint")
        except Exception:
            pass

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=False,
            args=["--disable-blink-features=AutomationControlled"],
        )
        ctx = browser.new_context(
            user_agent=UA,
            viewport={"width": 1280, "height": 800},
            locale="fr-CH",
            timezone_id="Europe/Zurich",
        )
        page = ctx.new_page()

        # Listen for ALL responses before we navigate
        page.on("response", _on_response)

        print(
            "\n[VS] A browser window has opened. Please log in with SwissID.\n"
            "     Use any method — passkey, SMS code, password, etc.\n"
            "     The scanner continues automatically once login is complete.\n"
        )

        try:
            page.goto(CAPWEB_UI, wait_until="networkidle", timeout=30_000)
        except Exception:
            pass   # networkidle may fire before Angular finishes

        # Wait up to 3 minutes for the token to be captured
        deadline = time.time() + 180
        while time.time() < deadline:
            if captured.get("access_token"):
                break
            try:
                page.wait_for_timeout(500)
            except Exception:
                break

        browser.close()

    if not captured.get("access_token"):
        log.error("No token captured — login may have timed out or failed")
        return None

    expires_in = captured.get("expires_in", 300)
    token_data = {
        "access_token":  captured["access_token"],
        "refresh_token": captured.get("refresh_token"),
        "expires_at":    time.time() + expires_in,
    }
    _save_token(token_data)
    log.info("VS login successful — token valid for %ds", expires_in)
    return token_data


def _refresh_access_token(refresh_token: str) -> dict | None:
    """Use a stored refresh_token to get a new access_token without re-opening the browser."""
    try:
        resp = requests.post(
            f"{KEYCLOAK_ISSUER}/protocol/openid-connect/token",
            data={
                "grant_type":    "refresh_token",
                "refresh_token": refresh_token,
                "client_id":     KEYCLOAK_CLIENT,
            },
            timeout=15,
        )
        if resp.status_code != 200:
            log.warning("Token refresh failed: HTTP %d", resp.status_code)
            return None
        data = resp.json()
        token_data = {
            "access_token":  data["access_token"],
            "refresh_token": data.get("refresh_token", refresh_token),
            "expires_at":    time.time() + data.get("expires_in", 300),
        }
        _save_token(token_data)
        log.info("Access token refreshed — valid for %ds", data.get("expires_in", 300))
        return token_data
    except Exception as exc:
        log.warning("Token refresh error: %s", exc)
        return None


# ── Owner lookup ─────────────────────────────────────────────────────────────

def check_owner(session: requests.Session, egrid: str) -> dict:
    """
    Two-step owner query against CAPWEB API.

    Step 1: GET /gb/grundstueck?egrid={EGRID}&historisiert=OHNE_HIST
            → returns grundstueck metadata including internal `id`
            → 404 = no Grundbuch entry (herrenlos Type 2)

    Step 2: GET /gb/eigentum/sicht/grundstueck?grundstueckIds={id}
            → returns eigentuemer list
            → empty list = no owner (herrenlos Type 1)
    """
    # ── Step 1: grundstueck lookup ────────────────────────────────────────────
    try:
        r1 = session.get(GRUNDSTUECK_EP, params={
            "egrid":        egrid,
            "historisiert": "OHNE_HIST",
        }, timeout=20)
    except Exception as exc:
        return {"owner": None, "owner_address": None,
                "is_herrenlos": None, "raw_response": None, "error": str(exc)}

    if r1.status_code in (401, 403):
        return {"error": "auth_expired", "is_herrenlos": None,
                "owner": None, "owner_address": None, "raw_response": None}

    if r1.status_code == 404:
        # No Grundbuch entry (Type 2 herrenlos)
        return {"owner": None, "owner_address": None,
                "is_herrenlos": 1, "raw_response": None, "error": None}

    if r1.status_code == 429:
        return {"error": "rate_limited", "is_herrenlos": None,
                "owner": None, "owner_address": None,
                "raw_response": r1.text[:200]}

    if r1.status_code != 200:
        return {"error": f"http_{r1.status_code}", "is_herrenlos": None,
                "owner": None, "owner_address": None,
                "raw_response": r1.text[:200]}

    try:
        gs_data = r1.json()
    except Exception:
        return {"error": "json_parse_1", "is_herrenlos": None,
                "owner": None, "owner_address": None,
                "raw_response": r1.text[:200]}

    # Extract the internal grundstueck ID.
    # Response is a dict; the id is NESTED: {"id": {"id": "81D8098..."}}
    gs_id = None
    if isinstance(gs_data, dict):
        id_field = gs_data.get("id")
        if isinstance(id_field, dict):
            gs_id = id_field.get("id")          # nested: {"id": {"id": "..."}}
        elif isinstance(id_field, str):
            gs_id = id_field                    # plain string
    elif isinstance(gs_data, list) and gs_data:
        id_field = gs_data[0].get("id", {})
        gs_id = id_field.get("id") if isinstance(id_field, dict) else id_field

    if not gs_id:
        log.debug("No grundstueckId in response for EGRID=%s  keys=%s",
                  egrid, list(gs_data.keys()) if isinstance(gs_data, dict) else type(gs_data))
        return {"error": "no_gs_id", "is_herrenlos": None,
                "owner": None, "owner_address": None,
                "raw_response": str(gs_data)[:300]}

    # ── Step 2: eigentum lookup ───────────────────────────────────────────────
    # Full parameter set from Angular bundle (loadEigentumSichtGrundstueck):
    #   id, eigentumErweitert, mode, historisiert  — all required server-side
    try:
        r2 = session.get(EIGENTUM_EP, params={
            "id":                gs_id,
            "eigentumErweitert": "false",
            "mode":              "BELASTET",
            "historisiert":      "OHNE_HIST",
        }, timeout=20)
    except Exception as exc:
        return {"owner": None, "owner_address": None,
                "is_herrenlos": None, "raw_response": None, "error": str(exc)}

    if r2.status_code == 401:
        return {"error": "auth_expired", "is_herrenlos": None,
                "owner": None, "owner_address": None, "raw_response": None}
    if r2.status_code == 403:
        log.warning("EIGENTUM 403 for EGRID=%s gs_id=%s body=%s", egrid, gs_id, r2.text[:200])
        return {"error": f"eigentum_403", "is_herrenlos": None,
                "owner": None, "owner_address": None, "raw_response": r2.text[:300]}

    if r2.status_code == 404:
        # Eigentum entry missing — treat as herrenlos Type 2
        return {"owner": None, "owner_address": None,
                "is_herrenlos": 1, "raw_response": None, "error": None}

    if r2.status_code == 429:
        return {"error": "rate_limited", "is_herrenlos": None,
                "owner": None, "owner_address": None,
                "raw_response": r2.text[:200]}

    if r2.status_code != 200:
        return {"error": f"http_eigentum_{r2.status_code}", "is_herrenlos": None,
                "owner": None, "owner_address": None,
                "raw_response": r2.text[:200]}

    try:
        ei_data = r2.json()
    except Exception:
        return {"error": "json_parse_2", "is_herrenlos": None,
                "owner": None, "owner_address": None,
                "raw_response": r2.text[:200]}

    # ── Parse eigentum response ───────────────────────────────────────────────
    # CAPWEB eigentum/sicht/grundstueck response structure (confirmed via API):
    # {
    #   "entries": [
    #     {
    #       "eigentumanteilArt": "PERSON",
    #       "versions": [{"eigentumsform": "ALLEINEIGENTUM", "quote": {...}}],
    #       "berechtigtePersonen": [{"personGbVersionId": {"id": "..."}}],
    #       ...
    #     }
    #   ]
    # }
    #
    # Person names are NOT returned by the public API (access denied on all
    # person-lookup endpoints for public SwissID accounts).
    # We use the PRESENCE of entries as the herrenlos signal:
    #   entries non-empty → parcel has owner(s) → NOT herrenlos
    #   entries empty     → no owner             → herrenlos Type 1
    #
    # The owner field is populated with eigentumsform + person count as a
    # summary (the actual name is hidden by the API).

    entries: list = []
    if isinstance(ei_data, dict):
        entries = ei_data.get("entries") or []
    elif isinstance(ei_data, list):
        entries = ei_data

    has_owner = len(entries) > 0

    return {
        "owner":         "registered" if has_owner else None,
        "owner_address": None,
        "is_herrenlos":  0 if has_owner else 1,
        "raw_response":  None,
        "error":         None,
    }


# ── Main scanner ─────────────────────────────────────────────────────────────

def scan(
        limit:    int | None = None,
        skip_existing: bool = True,
        delay:    float = 1.5,
):
    """
    Scan VS parcels for herrenlos detection via CAPWEB public API.

    No credentials needed up front — login opens your default browser.
    Log in with SwissID using whatever method you prefer (passkey, SMS, password).

    First run: ~2 h swisstopo grid scan (cached).
    Then SwissID browser login + CAPWEB API queries.

    limit         : stop after N parcels
    skip_existing : skip parcels already in DB
    delay         : seconds between API calls (default 1.5 s)
    """
    init_db()

    # ── Parcel enumeration ───────────────────────────────────────────────────
    with get_conn() as conn:
        cached = enum_cached(conn, "VS")
    if cached:
        log.info("Using cached VS parcel list (%d parcels)", len(cached))
        parcels = cached[:limit] if limit else cached
    else:
        if limit:
            # Quick mode: scan just enough grid points to find `limit` parcels.
            # Result is intentionally NOT cached so a later full run builds the
            # complete list from scratch.
            log.info(
                "No parcel cache — quick scan for first %d VS parcels "
                "(run without --limit to build full cache)", limit
            )
            parcels = enumerate_parcels_swisstopo(max_parcels=limit)
        else:
            log.info("No parcel cache — running full swisstopo grid scan (~2 h) …")
            parcels = enumerate_parcels_swisstopo()
            with get_conn() as conn:
                store_enum(conn, "VS", parcels)
            log.info("Cached %d VS parcels", len(parcels))

    # ── Token acquisition ────────────────────────────────────────────────────
    token_data = _load_cached_token()
    if not token_data:
        token_data = oidc_login()
        if not token_data:
            log.error("Login failed — aborting")
            return

    access_token  = token_data["access_token"]
    refresh_token = token_data.get("refresh_token")
    expires_at    = token_data["expires_at"]

    session = requests.Session()
    session.headers.update({
        "User-Agent":    UA,
        "Authorization": f"Bearer {access_token}",
        "Accept":        "application/json",
        "Origin":        "https://capweb-public.apps.vs.ch",
        "Referer":       CAPWEB_UI,
    })

    def _do_refresh():
        """Try refresh_token first; fall back to full browser login."""
        nonlocal access_token, refresh_token, expires_at
        new_td = None
        if refresh_token:
            new_td = _refresh_access_token(refresh_token)
        if not new_td:
            log.warning("Refresh failed — opening browser for re-login …")
            new_td = oidc_login()
        if not new_td:
            log.error("Re-login failed — aborting")
            return False
        access_token  = new_td["access_token"]
        refresh_token = new_td.get("refresh_token", refresh_token)
        expires_at    = new_td["expires_at"]
        session.headers["Authorization"] = f"Bearer {access_token}"
        return True

    scanned = errors = herrenlos = 0

    with get_conn() as conn:
        for p in parcels:
            egrid   = p["egrid"]
            bfs     = p["bfs_nr"]
            nr      = p["parcel_nr"]
            commune = p.get("commune", "")

            if skip_existing and already_scanned(conn, "VS", bfs, nr):
                continue

            # Proactive token refresh if expiry is imminent (< 60 s)
            if time.time() > expires_at - 60:
                if not _do_refresh():
                    break

            result = check_owner(session, egrid)

            # Handle auth errors
            if result.get("error") == "auth_expired":
                if not _do_refresh():
                    break
                result = check_owner(session, egrid)

            # Rate-limit back-off
            if result.get("error") == "rate_limited":
                log.warning("Rate-limited — waiting 60 s …")
                time.sleep(60)
                result = check_owner(session, egrid)

            annotate_herrenlos(result, "VS")

            upsert_parcel(conn, {
                "egrid":       egrid,
                "canton":      "VS",
                "commune":     commune,
                "bfs_nr":      bfs,
                "parcel_nr":   nr,
                "parcel_type": "Liegenschaft",
                **result,
            })

            scanned += 1
            if result.get("is_herrenlos") == 1:
                herrenlos += 1
                log.info("HERRENLOS  %s  Nr.%s  EGRID=%s", commune, nr, egrid)
            if result.get("error") and result["error"] not in ("auth_expired", "rate_limited"):
                errors += 1

            if scanned % 50 == 0:
                log.info(
                    "Progress %d  herrenlos=%d  errors=%d", scanned, herrenlos, errors
                )

            time.sleep(delay)

    log.info(
        "VS scan done — scanned=%d  herrenlos=%d  errors=%d", scanned, herrenlos, errors
    )
    return {"scanned": scanned, "herrenlos": herrenlos, "errors": errors}
