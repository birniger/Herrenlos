"""
BE scanner — Bern
=================
Platform : grudis-public.apps.be.ch (Keycloak OIDC PKCE via sso.be.ch / AGOV)
Canton   : BE

- EGRID enumeration : swisstopo identify API grid scan (step=300m, ~3h one-time)
                      Cached in parcel_enum table.
- Owner lookup      : GET /api/gb/eigentum/sicht/grundstueck?mode=BELASTET
                        entries = ownership records (Eigentum) for this parcel
                        entries[].berechtigtePersonen = the owner(s)
                        owner name: GET /api/gb/person/master?versionId=...
                                    → versions[0].name + versions[0].vorname
                      Requires: AGOV Bearer token (free registration at belogin.ch)
- Herrenlos signal  : (a) grundstueck 404 → not in Grundbuch
                      (b) grundstueck 200 + eigentum entries=[] → registered but
                          no owner → herrenlos (Art. 679/664 ZGB)
- Parcels           : ~400,000+ (second-largest Swiss canton by parcel count)

API NOTES (2026-05-17 investigation):
  The eigentum/sicht/grundstueck endpoint has two relevant modes:
    mode=BELASTET                    → Eigentum entries (ownership records)
    mode=BERECHTIGT_SUBJEKTIV_DINGLICH → rights the parcel holds over others
  Mode names EIGENTUEMER / ALLEINEIGENTUM / EIGENTUM are HTTP 400 (not valid).
  The "Eigentum" section on the GRUDIS public page IS served by mode=BELASTET.
  Owner names (Zoratti Stefano, Burgergemeinde Bern etc.) are fully visible
  with a free AGOV login — no elevated identification required for 3rd-party
  parcels.  The GRUDIS dashboard note about "erhöhte Identifizierungsstufe"
  refers only to viewing ONE'S OWN non-public parcel data.

AUTHENTICATION:
  BE-Login (belogin.ch) via AGOV, free registration.
  Keycloak OIDC PKCE: access_token (5 min), refresh_token (30 min, rotating).
  Token cached in ~/.herrenlos_scanner/be_token.json
  BE-Login form has Cloudflare Turnstile → automated browser login blocked.
  Solution: open GRUDIS in user's browser (existing Keycloak session auto-logs in),
  paste one-liner JS snippet in DevTools console to download be_token.json.
"""

import os
import re
import json
import time
import logging
import requests

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from db import get_conn, init_db, already_scanned, upsert_parcel, enum_cached, store_enum
from scanners.utils import is_herrenlos_owner_text, annotate_herrenlos

log = logging.getLogger("BE")

GRUDIS_BASE        = "https://grudis-public.apps.be.ch/grudis-public"
GRUDIS_UI          = f"{GRUDIS_BASE}/ui/"
GRUDIS_API         = f"{GRUDIS_BASE}/api/gb/grundstueck"
SWISSTOPO_IDENTIFY = "https://api3.geo.admin.ch/rest/services/api/MapServer/identify"
UA                 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

KEYCLOAK_ISSUER    = "https://sso.be.ch/auth/realms/a51-grudis-public-agov"
KEYCLOAK_CLIENT    = "intercapi-public-client"
KEYCLOAK_TOKEN_EP  = f"{KEYCLOAK_ISSUER}/protocol/openid-connect/token"

GRUNDSTUECK_EP     = f"{GRUDIS_API}"  # GET ?egrid=...&historisiert=OHNE_HIST
EIGENTUM_EP        = f"{GRUDIS_BASE}/api/gb/eigentum/sicht/grundstueck"

# Where to cache GRUDIS Bearer token between runs
TOKEN_CACHE = pathlib.Path.home() / ".herrenlos_scanner" / "be_token.json"

# BE LV95 bounding box (~5,959 km²)
BE_EMIN, BE_EMAX = 2_548_000, 2_700_000
BE_NMIN, BE_NMAX = 1_120_000, 1_250_000
BE_GRID_STEP     = 300   # metres — ~170k grid points, ~5h one-time

# Centre of Bern city — used for quick test scans
BE_BERN_E, BE_BERN_N = 2_600_000, 1_200_000


# ── Parcel enumeration via swisstopo ─────────────────────────────────────────

def enumerate_parcels_swisstopo(
        emin=BE_EMIN, emax=BE_EMAX,
        nmin=BE_NMIN, nmax=BE_NMAX,
        step=BE_GRID_STEP,
        max_parcels: int | None = None) -> list[dict]:
    """
    Grid scan — returns {egrid, bfs_nr, parcel_nr, commune} dicts.
    max_parcels: stop early (quick-test mode, result not cached).
    """
    seen:    set[str]  = set()
    parcels: list[dict] = []
    session = requests.Session()
    session.headers["User-Agent"] = UA

    if max_parcels:
        # Quick mode: 4 km × 4 km grid centred on Bern at 200 m steps
        log.info("BE quick scan: 4 km grid around Bern, stopping after %d parcels",
                 max_parcels)
        for e in range(BE_BERN_E - 2_000, BE_BERN_E + 2_001, 200):
            for n in range(BE_BERN_N - 2_000, BE_BERN_N + 2_001, 200):
                try:
                    r = session.get(SWISSTOPO_IDENTIFY, params={
                        "geometry": f"{e},{n}", "geometryType": "esriGeometryPoint",
                        "layers": "all:ch.swisstopo-vd.amtliche-vermessung",
                        "tolerance": 0, "mapExtent": "0,0,1,1", "imageDisplay": "1,1,96",
                        "returnGeometry": "false", "lang": "de", "sr": 2056,
                    }, timeout=12)
                    if r.status_code == 200:
                        for feat in r.json().get("results", []):
                            attrs = feat.get("attributes", {})
                            if attrs.get("ak", "").upper() != "BE":
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
                import time as _t; _t.sleep(0.1)
                if len(parcels) >= max_parcels:
                    break
            if len(parcels) >= max_parcels:
                break
        log.info("Quick scan: %d BE parcels found", len(parcels))
        return parcels

    e_range = range(emin, emax + 1, step)
    n_range = range(nmin, nmax + 1, step)
    total   = len(e_range) * len(n_range)
    checked = 0

    log.info("BE swisstopo grid scan: %d × %d = %d points at %dm",
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
                    if attrs.get("ak", "").upper() != "BE":
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
                log.info("Grid %d/%d  unique BE parcels=%d", checked, total, len(parcels))
            time.sleep(0.1)

    log.info("Grid scan complete: %d unique BE parcels", len(parcels))
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
                log.info("Loaded cached BE Bearer token (expires in %ds)",
                         int(expires_at - time.time()))
                return data
            if token:
                log.info("Cached BE token present but expired — will refresh")
    except Exception as exc:
        log.debug("Token cache load error: %s", exc)
    return None


def _save_token(token_data: dict):
    """Persist token data to disk."""
    try:
        TOKEN_CACHE.parent.mkdir(parents=True, exist_ok=True)
        TOKEN_CACHE.write_text(json.dumps(token_data, indent=2))
        log.info("Cached BE Bearer token to %s", TOKEN_CACHE)
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
            log.warning("BE token refresh failed: HTTP %d", resp.status_code)
            return None
        data = resp.json()
        token_data = {
            "access_token":  data["access_token"],
            "refresh_token": data.get("refresh_token", refresh_token),
            "expires_at":    time.time() + data.get("expires_in", 300),
        }
        _save_token(token_data)
        log.info("BE access token refreshed — valid for %ds", data.get("expires_in", 300))
        return token_data
    except Exception as exc:
        log.warning("BE token refresh error: %s", exc)
        return None


# ── BE-Login token extraction ─────────────────────────────────────────────────
#
# BE-Login uses Cloudflare Turnstile on the login form — automated browsers
# (Playwright) are blocked even with headless=False.
#
# The reliable approach:
#   1. Silent HTTP refresh (no browser, no Cloudflare) — covers most cases.
#      Refresh token is valid for 30 minutes and rotates on each use.
#   2. When refresh also expires: open GRUDIS in the user's DEFAULT browser.
#      The existing Keycloak session cookie (sso.be.ch) auto-logs in without
#      showing the BE-Login form → no Cloudflare challenge.
#      A one-liner JavaScript snippet downloads be_token.json from sessionStorage.
#      The scanner polls ~/Downloads/ for the file.
#
# OIDC storage keys in GRUDIS sessionStorage:
#   icp_BE_access_token         — JWT Bearer token
#   icp_BE_refresh_token        — rotating refresh token
#   icp_BE_id_token_expires_at  — expiry in epoch-milliseconds

_EXTRACT_JS = (
    "(function(){"
    "var d=JSON.stringify({"
    "access_token:sessionStorage.getItem('icp_BE_access_token'),"
    "refresh_token:sessionStorage.getItem('icp_BE_refresh_token'),"
    "expires_at:parseInt(sessionStorage.getItem('icp_BE_id_token_expires_at')||0)/1000"
    "});"
    "var a=document.createElement('a');"
    "a.href=URL.createObjectURL(new Blob([d],{type:'application/json'}));"
    "a.download='be_token.json';"
    "document.body.appendChild(a);a.click();document.body.removeChild(a);"
    "})()"
)

# Plain JS that just RETURNS the token JSON (used by AppleScript path).
# We can't use document.body.appendChild here — AppleScript wants a value back.
_EXTRACT_JS_RETURN = (
    "(function(){"
    "return JSON.stringify({"
    "access_token:sessionStorage.getItem('icp_BE_access_token'),"
    "refresh_token:sessionStorage.getItem('icp_BE_refresh_token'),"
    "expires_at:parseInt(sessionStorage.getItem('icp_BE_id_token_expires_at')||0)/1000"
    "});"
    "})()"
)


def _extract_token_via_safari_applescript() -> dict | None:
    """
    macOS-only: pull the BE OIDC token directly from Safari's sessionStorage via
    AppleScript — no F12/paste step.

    Requires (one-time user setup):
      1. Safari → Settings → Advanced → check "Show features for web developers"
         (or "Show Develop menu in menu bar" on older Safari).
      2. Safari → Develop menu → check "Allow JavaScript from Apple Events".
      3. First run will prompt macOS: "Terminal/Python wants to control Safari" →
         click Allow. (Saved in System Settings → Privacy → Automation.)

    Returns the token dict on success, or None if:
      - not macOS
      - osascript not present
      - Apple Events permission missing
      - GRUDIS tab not open
      - user hasn't logged in yet (sessionStorage values still null)
    The caller falls back to the manual paste path on None.
    """
    import subprocess, platform
    if platform.system() != "Darwin":
        return None

    # AppleScript: find the GRUDIS tab across all windows and eval the extractor JS.
    # Note: JS uses single quotes; AppleScript string uses double quotes — no escaping needed.
    applescript = f'''
    tell application "Safari"
        try
            repeat with w in windows
                repeat with t in tabs of w
                    if URL of t contains "grudis" then
                        return (do JavaScript "{_EXTRACT_JS_RETURN}" in t)
                    end if
                end repeat
            end repeat
        on error errMsg
            return "ERR:" & errMsg
        end try
        return ""
    end tell
    '''

    try:
        r = subprocess.run(
            ["osascript", "-e", applescript],
            capture_output=True, text=True, timeout=10,
        )
    except FileNotFoundError:
        return None        # osascript not installed (non-macOS pretending to be Darwin?)
    except Exception as exc:
        log.debug("osascript exception: %s", exc)
        return None

    out = (r.stdout or "").strip()
    if r.returncode != 0:
        log.debug("osascript rc=%d stderr=%s", r.returncode, (r.stderr or "").strip()[:200])
        return None
    if not out or out.startswith("ERR:"):
        log.debug("osascript returned %r — Apple Events permission missing or GRUDIS tab not open", out[:120])
        return None

    try:
        data = json.loads(out)
    except Exception as exc:
        log.debug("Cannot JSON-parse osascript output %r: %s", out[:120], exc)
        return None

    if data.get("access_token") and data.get("refresh_token"):
        return data
    # Page is loaded but sessionStorage is empty → user not logged in yet.
    log.debug("AppleScript extracted but tokens empty — user still logging in")
    return None


def grudis_login() -> dict | None:
    """
    Obtain a fresh GRUDIS Bearer token when cached token and refresh both fail.

    Flow:
      1. Opens GRUDIS in the user's default browser.
         If the Keycloak session is still valid (typically hours after last login),
         GRUDIS auto-authenticates without showing the BE-Login form.
         If the session expired, the user logs in once with BE-Login credentials.
      2. Prints a one-liner JavaScript snippet.
         The user pastes it in the GRUDIS browser console (F12 → Console).
         This downloads be_token.json to ~/Downloads/.
      3. Scanner polls ~/Downloads/be_token.json and loads it automatically.

    Returns {access_token, refresh_token, expires_at} or None on timeout.
    """
    import webbrowser

    downloads_token = pathlib.Path.home() / "Downloads" / "be_token.json"
    if downloads_token.exists():
        downloads_token.unlink()

    webbrowser.open(GRUDIS_UI)

    import platform
    is_mac = platform.system() == "Darwin"

    print()
    print("=" * 70)
    print("[BE] GRUDIS opened in your browser.")
    print("     Wait for the dashboard to load (auto-login if Keycloak session is")
    print("     still active — no password needed). If prompted, log in with your")
    print("     BE-Login account at https://www.belogin.ch/")
    print()
    if is_mac:
        print("     macOS: the scanner will pull the token from Safari automatically")
        print("     via AppleScript. ONE-TIME SETUP if you've never run this before:")
        print("       1. Safari → Settings → Advanced → enable 'Show Develop menu'")
        print("       2. Safari → Develop → check 'Allow JavaScript from Apple Events'")
        print("       3. First run macOS will ask 'Allow control of Safari' → Allow.")
        print()
        print("     If AppleScript can't get the token (e.g. permission denied or you")
        print("     used a different browser), fall back to the manual paste:")
    else:
        print("     Once the GRUDIS dashboard is visible:")
    print("       a. Press F12 → click the Console tab")
    print("       b. Paste this one line and press Enter:")
    print()
    print(f"          {_EXTRACT_JS}")
    print()
    print("     This downloads 'be_token.json' to your Downloads folder.")
    print("     The scanner continues automatically.")
    print("=" * 70)
    print()
    log.info("Polling for token (AppleScript + Downloads/be_token.json), up to 3 min …")

    deadline = time.time() + 180
    while time.time() < deadline:
        # Path 1 (zero-click on macOS): AppleScript to Safari
        if is_mac:
            token = _extract_token_via_safari_applescript()
            if token:
                _save_token(token)
                log.info("BE token loaded from Safari via AppleScript (no paste needed)")
                return token

        # Path 2 (cross-platform fallback): the user pasted the JS, file appeared
        if downloads_token.exists():
            try:
                data = json.loads(downloads_token.read_text())
                if data.get("access_token") and data.get("refresh_token"):
                    _save_token(data)
                    try:
                        downloads_token.unlink()
                    except Exception:
                        pass
                    log.info("BE token loaded from Downloads/be_token.json (manual paste)")
                    return data
            except Exception as exc:
                log.debug("be_token.json parse error: %s", exc)
        time.sleep(2)

    log.error("Timed out waiting for BE token — login not completed")
    return None


# ── Owner check ──────────────────────────────────────────────────────────────

def _resolve_person_name(session: requests.Session, version_id: str) -> str | None:
    """
    Resolve an owner name from a GRUDIS person/master versionId.

    GET /api/gb/person/master?versionId={id}&historisiert=OHNE_HIST
    Response: { versions: [{ name: "Zoratti", vorname: "Stefano", ... }] }
    """
    try:
        r = session.get(
            f"{GRUDIS_BASE}/api/gb/person/master",
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
    Query GRUDIS public API to determine ownership of one BE parcel.

    Flow:
      1. GET /api/gb/grundstueck?egrid=...  → retrieve internal grundstueck id
         404 → not in Grundbuch → herrenlos (Type A)
      2. GET /api/gb/eigentum/sicht/grundstueck?id=...&mode=BELASTET
         → Eigentum (ownership) entries for this parcel.
         entries=[] → parcel has no registered owner → herrenlos (Type B)
         entries[i].berechtigtePersonen[j].personGbVersionId → owner versionIds
      3. GET /api/gb/person/master?versionId=... → resolve owner name.

    The mode=BELASTET endpoint returns OWNERSHIP records, not Dienstbarkeiten.
    Dienstbarkeiten are exposed via the separate standardrecht endpoint.
    """
    try:
        # ── Step 1: grundstueck lookup ────────────────────────────────────────
        r = session.get(GRUDIS_API, params={
            "egrid":        egrid,
            "historisiert": "OHNE_HIST",
        }, timeout=20)

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
                    "owner": None, "owner_address": None, "raw_response": None}

        gs_data = r.json()

        # Extract the internal grundstueck UUID.
        # The 'id' field may be a plain string or a nested {"id": "..."} object.
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
        # mode=BELASTET returns the Eigentum entries for this parcel:
        # each entry has berechtigtePersonen[] = the owner(s).
        # empty entries list → no registered owner → herrenlos.
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
                    "owner": None, "owner_address": None, "raw_response": r2.text[:200]}

        entries: list = ei_data.get("entries") or [] if isinstance(ei_data, dict) else ei_data

        if not entries:
            # No ownership records — parcel is herrenlos (Type B)
            return {
                "owner":          None,
                "owner_address":  None,
                "is_herrenlos":   1,
                "herrenlos_type": "dereliktion",
                "claim_possible": None,
                "raw_response":   None,
                "error":          None,
            }

        # ── Step 3: resolve owner name via person/master ──────────────────────
        # Three outcomes possible per person:
        #   real name     → "Burgergemeinde Bern", "Zoratti Stefano", …  → has owner
        #   sentinel name → "herrenlos", "vakant", "sans propriétaire"   → herrenlos signal
        #   None          → person/master HTTP error or empty record     → unknown
        # We treat the parcel as herrenlos ONLY if EVERY resolved entry was
        # a sentinel AND no resolution failed (network errors aren't a herrenlos signal).
        owner_names: list[str] = []
        sentinel_seen = False
        resolution_failed = False
        for entry in entries[:3]:   # usually 1 entry (Alleineigentum/Miteigentum)
            for person in (entry.get("berechtigtePersonen") or [])[:5]:
                # personGbVersionId may be a plain string or {"id": "..."}
                vid_raw = person.get("personGbVersionId")
                if isinstance(vid_raw, dict):
                    vid = vid_raw.get("id")
                else:
                    vid = vid_raw
                if not vid:
                    continue
                name = _resolve_person_name(session, vid)
                if name is None:
                    resolution_failed = True
                    continue
                if is_herrenlos_owner_text(name):
                    sentinel_seen = True
                    continue
                if name and name not in owner_names:
                    owner_names.append(name)

        if owner_names:
            # At least one real name — parcel has an owner
            return {
                "owner":          "; ".join(owner_names),
                "owner_address":  None,
                "is_herrenlos":   0,
                "herrenlos_type": None,
                "claim_possible": None,
                "raw_response":   None,
                "error":          None,
            }

        if sentinel_seen and not resolution_failed:
            # Every resolved name was a sentinel string ("herrenlos" etc.) and
            # no transport errors clouded the picture — genuine herrenlos.
            return {
                "owner":          None,
                "owner_address":  None,
                "is_herrenlos":   1,
                "herrenlos_type": "dereliktion",
                "claim_possible": None,   # BE EG ZGB consultation 2026 — see project memory
                "raw_response":   None,
                "error":          None,
            }

        # Got entries from API but couldn't extract any usable name — keep the
        # pre-existing "registered" placeholder behaviour. is_herrenlos=0 because
        # the API DID return ownership entries; we just couldn't read the names.
        return {
            "owner":          "registered",
            "owner_address":  None,
            "is_herrenlos":   0,
            "herrenlos_type": None,
            "claim_possible": None,
            "raw_response":   None,
            "error":          "name_resolution_failed" if resolution_failed else None,
        }

    except Exception as exc:
        return {"owner": None, "owner_address": None,
                "is_herrenlos": None, "raw_response": None, "error": str(exc)}


# ── Main scanner ─────────────────────────────────────────────────────────────

def scan(limit: int | None = None,
         skip_existing: bool = True,
         delay: float = 3.0):
    """
    Scan BE parcels for herrenlos detection via GRUDIS public portal.

    Requires a valid AGOV / BE-Login Bearer token.  The scanner automatically
    tries (in order): cached token → silent HTTP refresh → browser login flow.
    """
    # ── Token acquisition ─────────────────────────────────────────────────────
    # 1. Try cached access_token (still valid)
    token_data = _load_cached_token()

    # 2. Expired? Try silent HTTP refresh (no browser, works within 30 min window)
    if not token_data:
        try:
            stored = json.loads(TOKEN_CACHE.read_text()) if TOKEN_CACHE.exists() else {}
            rt = stored.get("refresh_token")
            if rt:
                token_data = _refresh_access_token(rt)
        except Exception as exc:
            log.debug("Token file read error: %s", exc)

    # 3. Both expired? Open GRUDIS in browser, provide console snippet
    if not token_data:
        token_data = grudis_login()
        if not token_data:
            log.error("BE login failed — aborting")
            return

    access_token  = token_data["access_token"]
    refresh_token = token_data.get("refresh_token")
    expires_at    = token_data["expires_at"]

    init_db()

    # Parcel enumeration
    with get_conn() as conn:
        cached = enum_cached(conn, "BE")
    if cached:
        log.info("Using cached BE parcel list (%d parcels)", len(cached))
        parcels = cached[:limit] if limit else cached
    else:
        if limit:
            # Quick mode: small grid around Bern — result NOT cached
            log.info("No parcel cache — quick scan for first %d BE parcels "
                     "(run without --limit to build full cache)", limit)
            parcels = enumerate_parcels_swisstopo(max_parcels=limit)
        else:
            log.info("No cache — running swisstopo grid scan (~5h) …")
            parcels = enumerate_parcels_swisstopo()
            with get_conn() as conn:
                store_enum(conn, "BE", parcels)
            log.info("Cached %d BE parcels", len(parcels))

    session = requests.Session()
    session.headers.update({
        "User-Agent":    UA,
        "Authorization": f"Bearer {access_token}",
        "Accept":        "application/json",
        "Origin":        GRUDIS_BASE,
        "Referer":       GRUDIS_UI,
    })

    def _do_refresh():
        nonlocal access_token, refresh_token, expires_at
        new_td = None
        if refresh_token:
            new_td = _refresh_access_token(refresh_token)
        if not new_td:
            log.warning("Refresh failed — opening browser for re-login …")
            new_td = grudis_login()
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

            if skip_existing and already_scanned(conn, "BE", bfs, nr):
                continue

            # Proactive token refresh
            if time.time() > expires_at - 60:
                if not _do_refresh():
                    break

            result = check_owner(session, egrid)

            # Re-login if session expired
            if result.get("error") == "auth_expired":
                if not _do_refresh():
                    break
                result = check_owner(session, egrid)

            # 429 backoff — GRUDIS rate-limits aggressively; back off and retry
            if result.get("error") == "http_429":
                for _wait in (30, 60, 120):
                    log.info("GRUDIS 429 — backing off %ds …", _wait)
                    time.sleep(_wait)
                    result = check_owner(session, egrid)
                    if result.get("error") != "http_429":
                        break

            annotate_herrenlos(result, "BE")

            upsert_parcel(conn, {
                "egrid":       egrid,
                "canton":      "BE",
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
            if result.get("error") and result["error"] != "auth_expired":
                errors += 1

            if scanned % 50 == 0:
                log.info("Progress %d  herrenlos=%d  errors=%d", scanned, herrenlos, errors)

            time.sleep(delay)

    log.info("BE scan done — scanned=%d  herrenlos=%d  errors=%d", scanned, herrenlos, errors)
    return {"scanned": scanned, "herrenlos": herrenlos, "errors": errors}
