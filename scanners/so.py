"""
SO scanner — Solothurn  (legacy professional Capitastra path)
=============================================================
THE PUBLIC PATH IS BUILT — see scanners/so_public.py (built 2026-05-18).
  Captured via Chrome DevTools at geo.so.ch:
    captcha bootstrap → reCAPTCHA v3 (site key 6Lf1zcYUAAAAAEggUTd-...)
    owner query → /api/v1/plotinfo/plot_owner/{EGRID}?token={recaptcha_token}
  Live test confirmed end-to-end: token captured, server reached, response
  parsed. Only remaining gate is Google reCAPTCHA score-validation rejecting
  our datacenter IP — same as GE, fixed by residential proxies.
  The test framework dispatches SO to scanners.so_public (see SCANNER_IMPORTS).
  This file (scanners/so.py) is preserved as the LEGACY PROFESSIONAL PATH
  for institutional callers with Capitastra credentials.

STATUS (2026-05-17): RE-ENGINEERED against lts2026 Capitastra/intercapi platform.

PLATFORM CHANGE — lts2026 (deployed 08.04.2026):
  geo.so.ch migrated to a new GIS platform. All plot_owner/* endpoints and the
  reCAPTCHA-protected owner API were removed.  Owner data now lives exclusively
  in intercapi.so.ch (Capitastra by Informatica, Canton SO installation).

ACCESS — verified 2026-05-17 (NO public registration):
  Keycloak login page (capi-keycloak.so.ch/auth/realms/capitastra):
    - Only options: username/password  OR  EntraID (Microsoft Azure AD)
    - No "Register" / "Konto erstellen" link — registrationAllowed is disabled
  Canton SO Grundbuch page (so.ch/verwaltung/finanzdepartement/grundbuchaemter/):
    - No mention of online access, intercapi, or self-registration
    - All listed services are in-person at six regional offices
  Contrast: BE offers grudis-public.apps.be.ch with free AGOV registration.
  SO has no equivalent public portal — restricted to canton employees, notaries,
  surveyors, and other registered professionals.

AUTHENTICATION — Keycloak OIDC via capi-keycloak.so.ch:
  intercapi.so.ch requires login with either:
    (a) EntraID (Microsoft Azure AD) — for canton/professional accounts
    (b) Local Capitastra account
  grant_type=password is supported; tokens are cached in ~/.herrenlos_scanner/so_token.json

  To get a token:
    1. Open https://intercapi.so.ch/intercapi/ui/ in your browser and log in
    2. Once the dashboard loads, open DevTools → Console (F12)
    3. Paste and run this one-liner:
       (function(){var s=sessionStorage;var d=JSON.stringify({access_token:s.getItem('capi_SO_access_token'),refresh_token:s.getItem('capi_SO_refresh_token'),expires_at:parseInt(s.getItem('capi_SO_id_token_expires_at')||0)/1000});var a=document.createElement('a');a.href=URL.createObjectURL(new Blob([d],{type:'application/json'}));a.download='so_token.json';document.body.appendChild(a);a.click();document.body.removeChild(a)})()
    4. This downloads so_token.json to ~/Downloads/. The scanner loads it automatically.
  Token lifetime: access_token ~5 min, refresh_token ~30 min (rotating).

OWNER LOOKUP FLOW (3 steps, all require Bearer token):
  1. GET intercapi.so.ch/intercapi/api/gb/grundstueck?egrid={EGRID}&historisiert=OHNE_HIST
       → returns grundstueck object with 'id' (internal fachId)
       → 404  : EGRID not in Grundbuch (herrenlos Type A)
  2. GET intercapi.so.ch/intercapi/api/gb/eigentum/sicht/grundstueck
           ?id={fachId}&eigentumErweitert=false&mode=BELASTET&historisiert=OHNE_HIST
       → returns { entries: [...] }
       → entries=[] : no owner registered (herrenlos Type B / dereliktion)
       → entries[i].berechtigtePersonen[j].personGbVersionId → owner version IDs
  3. GET intercapi.so.ch/intercapi/api/gb/person/master
           ?versionId={vid}&historisiert=OHNE_HIST
       → returns { versions: [{ name, vorname, ... }] }

STORAGE KEYS (angular-oauth2-oidc with prefix capi_SO_):
  sessionStorage: capi_SO_access_token, capi_SO_refresh_token, capi_SO_id_token_expires_at

DEAD ENDPOINTS (all 404 since lts2026, 2026-04-08):
  - geo.so.ch/plot_owner/captcha/{egrid}    (was: reCAPTCHA v3 owner API)
  - geo.so.ch/plot_owner/{egrid}            (was: owner API with token query param)
  - geo.so.ch/api/v1/plot_owner/{egrid}     (was: direct owner API, no CAPTCHA)
  WMS/WFS layer ch.so.agi.av.grundbuch.liegenschaften  (removed)
  reCAPTCHA site key 6Lf1zcYUAAAAAEggUTd-dzwF8UuoXmt_az29LFO-  (no longer served)

WORKING ENDPOINTS (public, no auth):
  - geo.so.ch/api/v1/plotinfo/?x={E}&y={N}  ← EGRID enumeration (still works)

REQUIRES:
    pip install requests
    Valid so_token.json (see AUTHENTICATION above)
"""

import re
import time
import json
import logging
import pathlib
import webbrowser
import requests

import sys
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from db import get_conn, init_db, already_scanned, upsert_parcel
from scanners.utils import claim_possible_for

log = logging.getLogger("SO")

# ── Constants ─────────────────────────────────────────────────────────────────

PLOTINFO_URL = "https://geo.so.ch/api/v1/plotinfo/"

INTERCAPI_BASE   = "https://intercapi.so.ch/intercapi/api"
GRUNDSTUECK_EP   = f"{INTERCAPI_BASE}/gb/grundstueck"
EIGENTUM_EP      = f"{INTERCAPI_BASE}/gb/eigentum/sicht/grundstueck"
PERSON_EP        = f"{INTERCAPI_BASE}/gb/person/master"

INTERCAPI_UI     = "https://intercapi.so.ch/intercapi/ui/"
KEYCLOAK_TOKEN_EP = (
    "https://capi-keycloak.so.ch/auth/realms/capitastra"
    "/protocol/openid-connect/token"
)
KEYCLOAK_CLIENT  = "capitastra-client"

TOKEN_CACHE = pathlib.Path.home() / ".herrenlos_scanner" / "so_token.json"

# SO bounding box in LV95
SO_EMIN, SO_EMAX = 2_590_000, 2_640_000
SO_NMIN, SO_NMAX = 1_220_000, 1_260_000
GRID_STEP = 200   # metres

# JS snippet to download token from an authenticated intercapi.so.ch session
_EXTRACT_JS = (
    "(function(){"
    "var s=sessionStorage;"
    "var d=JSON.stringify({"
    "access_token:s.getItem('capi_SO_access_token'),"
    "refresh_token:s.getItem('capi_SO_refresh_token'),"
    "expires_at:parseInt(s.getItem('capi_SO_id_token_expires_at')||0)/1000"
    "});"
    "var a=document.createElement('a');"
    "a.href=URL.createObjectURL(new Blob([d],{type:'application/json'}));"
    "a.download='so_token.json';"
    "document.body.appendChild(a);a.click();document.body.removeChild(a);"
    "})()"
)


# ── EGRID enumeration via coordinate grid ─────────────────────────────────────

def enumerate_egrids_grid(emin=SO_EMIN, emax=SO_EMAX,
                          nmin=SO_NMIN, nmax=SO_NMAX,
                          step=GRID_STEP) -> list[dict]:
    """
    Grid scan over SO territory.  Returns list of unique parcel dicts:
      {egrid, label, commune}
    Takes ~10-30 min at step=200 depending on network.
    """
    seen:    set[str]  = set()
    parcels: list[dict] = []
    session = requests.Session()

    e_range = range(emin, emax + 1, step)
    n_range = range(nmin, nmax + 1, step)
    total   = len(e_range) * len(n_range)
    checked = 0

    for e in e_range:
        for n in n_range:
            checked += 1
            try:
                r = session.get(PLOTINFO_URL, params={"x": e, "y": n}, timeout=10)
                if r.status_code != 200:
                    continue
                for plot in r.json().get("plots", []):
                    eg = plot.get("egrid")
                    if eg and eg not in seen:
                        seen.add(eg)
                        parcels.append({
                            "egrid":   eg,
                            "label":   plot.get("label", ""),
                            "commune": plot.get("municipality", ""),
                        })
            except Exception:
                pass

            if checked % 500 == 0:
                log.info("Grid scan: %d/%d pts  %d unique parcels",
                         checked, total, len(parcels))
            time.sleep(0.05)

    log.info("Grid scan complete: %d unique SO parcels", len(parcels))
    return parcels


# ── Token cache helpers ───────────────────────────────────────────────────────

def _load_cached_token() -> dict | None:
    """Return cached token if still valid; None if absent / expired."""
    try:
        if TOKEN_CACHE.exists():
            data = json.loads(TOKEN_CACHE.read_text())
            token = data.get("access_token", "")
            expires_at = data.get("expires_at", 0)
            if token and time.time() < expires_at - 60:
                log.info("Loaded cached SO Bearer token (expires in %ds)",
                         int(expires_at - time.time()))
                return data
            if token:
                log.info("Cached SO token present but expired — will refresh")
    except Exception as exc:
        log.debug("Token cache load error: %s", exc)
    return None


def _save_token(token_data: dict):
    """Persist token data to disk."""
    try:
        TOKEN_CACHE.parent.mkdir(parents=True, exist_ok=True)
        TOKEN_CACHE.write_text(json.dumps(token_data, indent=2))
        log.info("Cached SO Bearer token to %s", TOKEN_CACHE)
    except Exception as exc:
        log.debug("Token cache save error: %s", exc)


def _refresh_access_token(refresh_token: str) -> dict | None:
    """Use a stored refresh_token to get a new access_token."""
    try:
        resp = requests.post(
            KEYCLOAK_TOKEN_EP,
            data={
                "grant_type":    "refresh_token",
                "refresh_token": refresh_token,
                "client_id":     KEYCLOAK_CLIENT,
            },
            timeout=15,
        )
        if resp.status_code != 200:
            log.warning("SO token refresh failed: HTTP %d — %s",
                        resp.status_code, resp.text[:200])
            return None
        data = resp.json()
        token_data = {
            "access_token":  data["access_token"],
            "refresh_token": data.get("refresh_token", refresh_token),
            "expires_at":    time.time() + data.get("expires_in", 300),
        }
        _save_token(token_data)
        log.info("SO access token refreshed — valid for %ds",
                 data.get("expires_in", 300))
        return token_data
    except Exception as exc:
        log.warning("SO token refresh error: %s", exc)
        return None


def intercapi_login() -> dict | None:
    """
    Obtain a fresh intercapi.so.ch Bearer token when cached token / refresh fail.

    Flow:
      1. Opens intercapi.so.ch/intercapi/ui/ in the user's default browser.
         If the Keycloak / EntraID session is still active, auto-login occurs.
         Otherwise the user logs in with their EntraID or local Capitastra account.
      2. Prints a one-liner JavaScript snippet.
         Paste it in DevTools Console (F12 → Console tab) and press Enter.
         This downloads so_token.json to ~/Downloads/.
      3. Scanner polls ~/Downloads/so_token.json and loads it automatically.

    Returns {access_token, refresh_token, expires_at} or None on timeout.

    NOTE: intercapi.so.ch is a restricted system (canton employees, notaries,
    surveyors).  Unlike BE (free AGOV registration), SO requires an authorised
    account.  Contact the Grundbuchamt Solothurn for access.
    """
    downloads_token = pathlib.Path.home() / "Downloads" / "so_token.json"
    if downloads_token.exists():
        try:
            downloads_token.unlink()
        except Exception:
            pass

    webbrowser.open(INTERCAPI_UI)

    print()
    print("=" * 70)
    print("[SO] intercapi.so.ch opened in your browser.")
    print("     Log in with your EntraID or local Capitastra account.")
    print("     If the Keycloak session is still active, auto-login occurs.")
    print()
    print("     NOTE: intercapi.so.ch is restricted to registered users")
    print("     (canton employees, notaries, surveyors).  If you do not have")
    print("     an account, contact the Grundbuchamt Solothurn for access.")
    print()
    print("     Once the intercapi dashboard is visible:")
    print("       1. Press F12 → click the Console tab")
    print("       2. Paste this one line and press Enter:")
    print()
    print(f"          {_EXTRACT_JS}")
    print()
    print("     This downloads 'so_token.json' to your Downloads folder.")
    print("     The scanner continues automatically.")
    print("=" * 70)
    print()
    log.info("Waiting up to 3 minutes for ~/Downloads/so_token.json …")

    deadline = time.time() + 180
    while time.time() < deadline:
        if downloads_token.exists():
            try:
                data = json.loads(downloads_token.read_text())
                if data.get("access_token") and data.get("refresh_token"):
                    _save_token(data)
                    try:
                        downloads_token.unlink()
                    except Exception:
                        pass
                    log.info("SO token loaded from Downloads/so_token.json")
                    return data
            except Exception as exc:
                log.debug("so_token.json parse error: %s", exc)
        time.sleep(2)

    log.error("Timed out waiting for so_token.json — login not completed")
    return None


# ── Owner check ───────────────────────────────────────────────────────────────

def _resolve_person_name(session: requests.Session, version_id: str) -> str | None:
    """
    Resolve an owner name from an intercapi person/master versionId.

    GET /intercapi/api/gb/person/master?versionId={id}&historisiert=OHNE_HIST
    Response: { versions: [{ name: "Müller", vorname: "Hans", ... }] }
    """
    try:
        r = session.get(
            PERSON_EP,
            params={"versionId": version_id, "historisiert": "OHNE_HIST"},
            timeout=10,
        )
        if r.status_code != 200:
            return None
        data = r.json()
        versions = data.get("versions") or []
        if not versions:
            return None
        v = versions[0]
        parts = []
        for key in ("vorname", "name"):
            val = v.get(key)
            if val:
                parts.append(str(val))
        return " ".join(parts).strip() or None
    except Exception:
        return None


def check_owner(session: requests.Session, egrid: str) -> dict:
    """
    Query intercapi.so.ch to determine ownership of one SO parcel.

    Flow:
      1. GET /gb/grundstueck?egrid={EGRID}&historisiert=OHNE_HIST
         404 → not in Grundbuch → herrenlos (Type A, Art. 664 II ZGB)
      2. GET /gb/eigentum/sicht/grundstueck?id={fachId}&mode=BELASTET
         entries=[] → no registered owner → herrenlos (Type B, dereliktion)
         entries[i].berechtigtePersonen[j].personGbVersionId → owner version IDs
      3. GET /gb/person/master?versionId={vid} → resolve owner name
    """
    try:
        # ── Step 1: grundstueck lookup ────────────────────────────────────────
        r = session.get(
            GRUNDSTUECK_EP,
            params={"egrid": egrid, "historisiert": "OHNE_HIST"},
            timeout=20,
        )

        if r.status_code in (401, 403):
            return {"error": "auth_expired", "is_herrenlos": None,
                    "owner": None, "owner_address": None, "raw_response": None}

        if r.status_code == 404:
            # EGRID not in Grundbuch — Type A herrenlos (Art. 664 II ZGB)
            return {"owner": None, "owner_address": None,
                    "is_herrenlos": 1,
                    "herrenlos_type": "not_in_grundbuch",
                    "claim_possible": 0,
                    "raw_response": None, "error": None}

        if r.status_code != 200:
            return {"error": f"http_{r.status_code}", "is_herrenlos": None,
                    "owner": None, "owner_address": None,
                    "raw_response": r.text[:200]}

        gs_data = r.json()

        # Extract internal grundstueck id (may be plain value or nested dict)
        gs_id_raw = gs_data.get("id")
        if isinstance(gs_id_raw, dict):
            gs_id = gs_id_raw.get("id")
        else:
            gs_id = gs_id_raw

        if not gs_id:
            log.debug("No grundstueck id for EGRID=%s  keys=%s",
                      egrid, list(gs_data.keys())[:8])
            return {"error": "no_gs_id", "is_herrenlos": None,
                    "owner": None, "owner_address": None,
                    "raw_response": str(gs_data)[:200]}

        # ── Step 2: Eigentum (ownership) lookup ───────────────────────────────
        try:
            r2 = session.get(EIGENTUM_EP, params={
                "id":                gs_id,
                "eigentumErweitert": "false",
                "mode":              "BELASTET",
                "historisiert":      "OHNE_HIST",
                "off":               0,
                "lim":               100,
            }, timeout=20)
        except Exception as exc:
            return {"owner": None, "owner_address": None,
                    "is_herrenlos": None, "raw_response": None, "error": str(exc)}

        if r2.status_code in (401, 403):
            return {"error": "auth_expired", "is_herrenlos": None,
                    "owner": None, "owner_address": None, "raw_response": None}
        if r2.status_code == 404:
            return {"owner": None, "owner_address": None,
                    "is_herrenlos": 1,
                    "herrenlos_type": "not_in_grundbuch",
                    "claim_possible": 0,
                    "raw_response": None, "error": None}
        if r2.status_code != 200:
            return {"error": f"eigentum_{r2.status_code}", "is_herrenlos": None,
                    "owner": None, "owner_address": None,
                    "raw_response": r2.text[:200]}

        try:
            ei_data = r2.json()
        except Exception:
            return {"error": "eigentum_json", "is_herrenlos": None,
                    "owner": None, "owner_address": None,
                    "raw_response": r2.text[:200]}

        entries: list = (
            ei_data.get("entries") or [] if isinstance(ei_data, dict) else ei_data
        )

        if not entries:
            # No ownership records → parcel is herrenlos (Type B)
            return {
                "owner":          None,
                "owner_address":  None,
                "is_herrenlos":   1,
                "herrenlos_type": "dereliktion",
                "claim_possible": claim_possible_for("SO", "dereliktion"),
                "raw_response":   None,
                "error":          None,
            }

        # ── Step 3: resolve owner name via person/master ──────────────────────
        owner_names: list[str] = []
        for entry in entries[:3]:
            for person in (entry.get("berechtigtePersonen") or [])[:5]:
                vid_raw = person.get("personGbVersionId")
                if isinstance(vid_raw, dict):
                    vid = vid_raw.get("id")
                else:
                    vid = vid_raw
                if not vid:
                    continue
                name = _resolve_person_name(session, vid)
                if name and name not in owner_names:
                    owner_names.append(name)

        owner_str = "; ".join(owner_names) if owner_names else "registered"

        return {
            "owner":          owner_str,
            "owner_address":  None,
            "is_herrenlos":   0,
            "herrenlos_type": None,
            "claim_possible": None,
            "raw_response":   None,
            "error":          None,
        }

    except Exception as exc:
        return {"owner": None, "owner_address": None,
                "is_herrenlos": None, "raw_response": None, "error": str(exc)}


# ── Main scanner ──────────────────────────────────────────────────────────────

def scan(limit: int | None = None,
         skip_existing: bool = True,
         grid_step: int = GRID_STEP,
         delay: float = 1.0):
    """
    Scan SO parcels for herrenlos detection via intercapi.so.ch.

    Requires a valid Capitastra Bearer token for intercapi.so.ch.
    Automatically tries: cached token → silent refresh → browser login flow.

    NOTE: intercapi.so.ch requires an authorised account (EntraID or local
    Capitastra account).  Contact the Grundbuchamt Solothurn if you need access.
    """
    # ── Token acquisition ─────────────────────────────────────────────────────
    token_data = _load_cached_token()

    if not token_data:
        try:
            stored = json.loads(TOKEN_CACHE.read_text()) if TOKEN_CACHE.exists() else {}
            rt = stored.get("refresh_token")
            if rt:
                token_data = _refresh_access_token(rt)
        except Exception as exc:
            log.debug("Token file read error: %s", exc)

    if not token_data:
        token_data = intercapi_login()
        if not token_data:
            log.error("SO login failed — aborting")
            return

    access_token  = token_data["access_token"]
    refresh_token = token_data.get("refresh_token")
    expires_at    = token_data.get("expires_at", 0)

    init_db()

    # ── EGRID enumeration ─────────────────────────────────────────────────────
    log.info("Enumerating SO parcels via coordinate grid (step=%dm) …", grid_step)
    parcels = enumerate_egrids_grid(step=grid_step)
    if limit:
        parcels = parcels[:limit]
    log.info("Will scan %d SO parcels", len(parcels))

    # ── Scan loop ─────────────────────────────────────────────────────────────
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {access_token}",
        "Accept":        "application/json",
    })

    scanned = errors = herrenlos = 0

    with get_conn() as conn:
        for p in parcels:
            egrid = p["egrid"]

            if skip_existing and already_scanned(conn, "SO", "SO", egrid):
                continue

            # Proactive token refresh: refresh ~60s before expiry
            if refresh_token and time.time() > expires_at - 90:
                new_tok = _refresh_access_token(refresh_token)
                if new_tok:
                    access_token  = new_tok["access_token"]
                    refresh_token = new_tok.get("refresh_token", refresh_token)
                    expires_at    = new_tok.get("expires_at", 0)
                    session.headers["Authorization"] = f"Bearer {access_token}"
                else:
                    # Refresh failed — try browser login
                    new_tok = intercapi_login()
                    if not new_tok:
                        log.error("SO token refresh and re-login both failed — aborting")
                        break
                    access_token  = new_tok["access_token"]
                    refresh_token = new_tok.get("refresh_token")
                    expires_at    = new_tok.get("expires_at", 0)
                    session.headers["Authorization"] = f"Bearer {access_token}"

            result = check_owner(session, egrid)

            if result.get("error") == "auth_expired":
                log.warning("Auth expired during scan — refreshing token")
                new_tok = _refresh_access_token(refresh_token or "")
                if not new_tok:
                    new_tok = intercapi_login()
                if not new_tok:
                    log.error("Token refresh failed — aborting")
                    break
                access_token  = new_tok["access_token"]
                refresh_token = new_tok.get("refresh_token", refresh_token)
                expires_at    = new_tok.get("expires_at", 0)
                session.headers["Authorization"] = f"Bearer {access_token}"
                result = check_owner(session, egrid)

            # Extract parcel number from label: "Liegenschaft Nr. 4006" → "4006"
            label    = p.get("label", "")
            nr_match = re.search(r"Nr\.\s*(\S+)", label)
            parcel_nr = nr_match.group(1) if nr_match else egrid

            upsert_parcel(conn, {
                "egrid":       egrid,
                "canton":      "SO",
                "commune":     p.get("commune"),
                "bfs_nr":      "SO",
                "parcel_nr":   parcel_nr,
                "parcel_type": "Liegenschaft",
                **result,
            })

            scanned += 1
            if result.get("is_herrenlos") == 1:
                herrenlos += 1
                log.info("HERRENLOS  %s  %s  EGRID=%s",
                         p.get("commune", "?"), label, egrid)
            if result.get("error") and result["error"] not in ("auth_expired",):
                errors += 1

            if scanned % 50 == 0:
                log.info("Progress %d/%d  herrenlos=%d  errors=%d",
                         scanned, len(parcels), herrenlos, errors)

            time.sleep(delay)

    log.info("SO scan done — scanned=%d  herrenlos=%d  errors=%d",
             scanned, herrenlos, errors)
    return {"scanned": scanned, "herrenlos": herrenlos, "errors": errors}
