"""
SO scanner — Solothurn (PUBLIC PATH)
=====================================
STATUS (2026-05-18): NEWLY BUILT against the public geo.so.ch path captured via
  Chrome DevTools network inspection. Companion scanner to scanners/so.py which
  targets the professional intercapi.so.ch (Capitastra Keycloak) endpoint.

PLATFORM:
  Public Web GIS at https://geo.so.ch/map/grundstuecksinformation
  Click on a parcel → "Eigentümerinformationen" → owner returned via GDBDS Schnittstelle.

CAPTURED ENDPOINTS:
  1. Captcha bootstrap:
       GET https://geo.so.ch/api/v1/plotinfo/plot_owner/captcha/{EGRID}
     Returns an HTML page that loads grecaptcha and runs:
       grecaptcha.execute('6Lf1zcYUAAAAAEggUTd-dzwF8UuoXmt_az29LFO-',
                          {action: 'plotOwnerInfo'})
         .then(t => window.top.plotOwnerInfo.loadOwnerInfo('<EGRID>', t));

  2. Owner query:
       GET https://geo.so.ch/api/v1/plotinfo/plot_owner/{EGRID}?token={recaptcha_v3_token}
     → 200 + JSON {"success": true, "eigentuemer": "Staat Solothurn", "eigentumsform": "Alleineigentum", ...}
     → 200 + JSON {"error": "Captcha verification failed", "success": false}

  3. Search (used for enumeration / commune→parcel mapping):
       GET https://geo.so.ch/api/search/v2/?searchtext=...&filter=...
       https://geo.so.ch/api/data/v1/ch.so.agi.av.grundstuecke.rechtskraeftig/?filter=[["t_id","=","..."]]

AUTH (reCAPTCHA v3 invisible, score-based):
  No registration. No SMS. Google reCAPTCHA Enterprise scores each request by
  IP/UA/behaviour and the server enforces a minimum score. To pass:
    - Use Playwright with stealth (same pattern as GE).
    - Let grecaptcha.execute run inside the loaded HTML page — it returns a
      token tied to the action 'plotOwnerInfo'.
    - We intercept that token via a tiny shim that replaces
      window.top.plotOwnerInfo.loadOwnerInfo with a token capture function.
    - Then call the owner endpoint with the captured token using the same
      browser context (so the cookies/UA match).

  This is the SAME technique as the working GE scanner — see scanners/ge.py.

RATE LIMIT / IP:
  No documented hard daily limit. Access is purely score-based (reCAPTCHA v3).
  From a Swiss residential IP the score passes — no rotation needed even for
  bulk scanning. Datacenter IPs (GitHub Actions etc.) score too low and are
  rejected. Run locally on your laptop; proxies are NOT needed.

EGRID enumeration:
  swisstopo identify API grid scan (standard pattern). ~70k parcels in SO,
  ~800 km². Grid step 200m.

PARCELS:
  ~70 000

REQUIRES:
    pip install playwright playwright-stealth beautifulsoup4 lxml
    playwright install chromium

REFERENCE PATTERN:
  scanners/ge.py — same Playwright + stealth + reCAPTCHA approach, except GE
  uses an image CAPTCHA (post-Imperva-challenge) and SO uses invisible v3.
"""

import os
import re
import json
import time
import logging
import requests

import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from db import get_conn, init_db, already_scanned, upsert_parcel, enum_cached, store_enum
from scanners.wfs_enum import enumerate_canton as wfs_enumerate_canton
from scanners.utils import claim_possible_for

log = logging.getLogger("SO")

# ── Endpoints captured from Chrome DevTools (2026-05-18) ─────────────────────
SO_BASE             = "https://geo.so.ch"
SO_CAPTCHA_URL      = f"{SO_BASE}/api/v1/plotinfo/plot_owner/captcha/{{egrid}}"
SO_OWNER_URL        = f"{SO_BASE}/api/v1/plotinfo/plot_owner/{{egrid}}"
SO_RECAPTCHA_SITEKEY = "6Lf1zcYUAAAAAEggUTd-dzwF8UuoXmt_az29LFO-"
SO_RECAPTCHA_ACTION  = "plotOwnerInfo"

SWISSTOPO_IDENTIFY = "https://api3.geo.admin.ch/rest/services/api/MapServer/identify"
UA                 = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/131.0.0.0 Safari/537.36")

# ── SO LV95 bounding box (~790 km²) ───────────────────────────────────────────
SO_EMIN, SO_EMAX = 2_592_000, 2_647_000
SO_NMIN, SO_NMAX = 1_215_000, 1_257_000
SO_GRID_STEP     = 200


# ── Playwright bootstrap (mirrors GE pattern) ────────────────────────────────

def _init_playwright():
    try:
        from playwright.sync_api import sync_playwright
        # Support both old (stealth_sync) and new (Stealth class) playwright_stealth APIs.
        stealth_fn = None
        try:
            from playwright_stealth import Stealth   # type: ignore  (>=1.3)
            stealth_fn = lambda page: Stealth().apply_stealth_sync(page)
        except ImportError:
            try:
                from playwright_stealth import stealth_sync   # type: ignore  (<1.3)
                stealth_fn = stealth_sync
            except ImportError:
                pass
        return sync_playwright, stealth_fn
    except ImportError as e:
        raise RuntimeError(
            "SO scanner requires:  pip install playwright playwright-stealth"
            "  &&  playwright install chromium"
        ) from e


def _make_page(pw, stealth_sync, proxy_url: str | None = None):
    """Create a stealth Chromium page, optionally behind a residential proxy."""
    browser = pw.chromium.launch(
        headless=True,
        proxy={"server": proxy_url} if proxy_url else None,
        args=[
            "--no-sandbox",
            "--disable-blink-features=AutomationControlled",
        ],
    )
    ctx = browser.new_context(
        user_agent=UA,
        viewport={"width": 1366, "height": 768},
        locale="de-CH",
        timezone_id="Europe/Zurich",
    )
    page = ctx.new_page()
    if stealth_sync is not None:
        try:
            stealth_sync(page)
        except Exception as exc:
            log.debug("stealth_sync failed: %s", exc)
    return browser, page


# ── Owner check via the captured reCAPTCHA v3 flow ───────────────────────────

def warm_up_session(page) -> bool:
    """
    Visit the main map page like a real user would, BEFORE hitting the captcha
    endpoint. This gives grecaptcha v3 time to observe "real browsing" signals
    (cookies set, page rendered, JS executed, no immediate bot signals) — which
    materially affects the score the server gets when it validates the token.

    Empirically: cold-load straight to /captcha/{egrid} → low score → rejected.
                Warm-up visit to /map first → higher score → accepted.

    Idempotent: only warms up once per page (skip if cookies already set).
    """
    try:
        if page.evaluate("document.cookie").strip():
            return True   # already warm
        page.goto("https://geo.so.ch/map/grundstuecksinformation",
                  wait_until="domcontentloaded", timeout=20_000)
        # Small, realistic delay — grecaptcha needs >1s of "human" idle to score well
        page.wait_for_timeout(2500)
        # Move the mouse slightly to add a behavior signal
        page.mouse.move(500, 400)
        page.wait_for_timeout(500)
        return True
    except Exception as exc:
        log.debug("warm_up_session failed: %s", exc)
        return False


def check_owner_public(page, egrid: str, max_retries: int = 3) -> dict:
    """
    Capture a reCAPTCHA v3 token by loading the captcha bootstrap page in
    Playwright, then call the owner endpoint with that token.

    Returns the canonical 7-key dict.

    Score-improvement steps (in increasing cost):
      1. Session warm-up via warm_up_session() — visit the map page first.
      2. playwright-stealth — reduces headless-browser fingerprint.
      3. Residential proxies (SO_PROXY_LIST) — IP reputation.
      4. 2captcha service (paid, ~$0.003/solve) — bypasses score entirely.

    Step 1 is free and idempotent. Steps 2-4 are progressively more expensive.
    """
    last_err = None
    # Warm-up once per page (no-op after first call)
    warm_up_session(page)

    for attempt in range(1, max_retries + 1):
        try:
            captcha_url = SO_CAPTCHA_URL.format(egrid=egrid)

            # Install a shim BEFORE navigation so the captcha HTML page's
            # call to window.top.plotOwnerInfo.loadOwnerInfo(egrid, token)
            # captures the token onto window._so_token.
            page.add_init_script("""
                window.plotOwnerInfo = window.plotOwnerInfo || {};
                window.plotOwnerInfo.loadOwnerInfo = function(egrid, token) {
                    window._so_token = token;
                };
            """)

            # Clear any leftover token from a previous attempt
            page.evaluate("window._so_token = null")

            page.goto(captcha_url, wait_until="domcontentloaded", timeout=20_000)
            # grecaptcha v3 typically resolves within 2-5 s on a clean IP.
            page.wait_for_function("window._so_token", timeout=20_000)
            token = page.evaluate("window._so_token")

            if not token or not isinstance(token, str) or len(token) < 50:
                last_err = "no_token"
                time.sleep(1)
                continue

            # Fetch owner JSON using the captured token — same browser context
            # so cookies / UA match the captcha session.
            owner_url = SO_OWNER_URL.format(egrid=egrid) + "?token=" + token
            resp = page.context.request.get(owner_url, timeout=15_000)
            if resp.status != 200:
                last_err = f"http_{resp.status}"
                time.sleep(1)
                continue

            data = resp.json()
            if not data.get("success"):
                # Token may have been rejected; retry with a fresh one
                err = data.get("error") or "captcha_rejected"
                if "captcha" in str(err).lower() and attempt < max_retries:
                    last_err = "captcha_wrong"
                    # Re-warm-up before retry — score may have decayed
                    page.wait_for_timeout(3000)
                    continue
                return _empty_result(error=err)

            return _parse_owner(data)

        except Exception as exc:
            last_err = str(exc)[:120]
            log.debug("SO public check_owner attempt %d failed: %s", attempt, last_err)
            time.sleep(1)

    return _empty_result(error=last_err or "unknown")


def _empty_result(error: str | None = None) -> dict:
    return {"owner": None, "owner_address": None,
            "is_herrenlos": None,
            "herrenlos_type": None, "claim_possible": None,
            "raw_response": None, "error": error}


def _parse_owner(data: dict) -> dict:
    """
    Map the SO JSON response to our 7-key canonical dict.

    Confirmed SO response schema (verified 2026-05-23 against live data):
      {
        "eigentum": {
          "grundstueck": "GB-Nr. 4000 Grenchen",
          "eigentumsform": "Alleineigentum",
          "eigentuemer": [
            {"berechtigte": ["Bürgergemeinde Grenchen"]},
            ...                                    # one entry per share
          ]
        },
        "success": true
      }

    Earlier versions of this scanner assumed `data["eigentuemer"]` was a top-
    level string — that was wrong and produced false positives (any parcel with
    a real owner was classified herrenlos because the lookup found None). The
    real owner data is nested in `data["eigentum"]["eigentuemer"]` and is a
    list of dicts with `berechtigte` arrays.
    """
    # Real SO responses nest everything under `eigentum`. Fall back to root
    # for forward compatibility if the API ever flattens.
    inner = data.get("eigentum") or data

    # Owner extraction: walk the eigentuemer list and collect every name in
    # the `berechtigte` arrays. Each entry is one ownership share; multiple
    # entries = co-ownership (Miteigentum / Stockwerkeigentum).
    owners_field = inner.get("eigentuemer")
    names: list[str] = []
    if isinstance(owners_field, list):
        for entry in owners_field:
            if not isinstance(entry, dict):
                continue
            berechtigte = entry.get("berechtigte") or []
            if isinstance(berechtigte, list):
                names.extend(str(n).strip() for n in berechtigte if n)
            elif isinstance(berechtigte, str):
                names.append(berechtigte.strip())
    elif isinstance(owners_field, str):
        names.append(owners_field.strip())
    # Filter out any blank strings that crept in
    names = [n for n in names if n]
    owner_name = "; ".join(names) if names else None

    owner_form = inner.get("eigentumsform") or inner.get("ownership_form")

    addr_parts = []
    for k in ("strasse", "adresse", "plz", "ort"):
        v = inner.get(k)
        if v:
            addr_parts.append(str(v))
    address = ", ".join(addr_parts) or None

    if owner_name and owner_form:
        owner = f"{owner_name} ({owner_form})"
    else:
        owner = owner_name

    is_herrenlos = 0 if owner else 1
    herrenlos_type = None if owner else "dereliktion"
    claim_possible = None if owner else claim_possible_for("SO", herrenlos_type)

    return {
        "owner":          owner,
        "owner_address":  address,
        "is_herrenlos":   is_herrenlos,
        "herrenlos_type": herrenlos_type,
        "claim_possible": claim_possible,
        "raw_response":   json.dumps(data) if not owner else None,
        "error":          None,
    }


# ── EGRID enumeration via swisstopo ──────────────────────────────────────────

def enumerate_parcels_swisstopo(
        emin=SO_EMIN, emax=SO_EMAX,
        nmin=SO_NMIN, nmax=SO_NMAX,
        step=SO_GRID_STEP) -> list[dict]:
    """Standard swisstopo grid scan — same pattern as BL/UR/LU."""
    seen: set[str] = set()
    parcels: list[dict] = []
    session = requests.Session()
    session.headers["User-Agent"] = UA

    e_range = range(emin, emax + 1, step)
    n_range = range(nmin, nmax + 1, step)
    total = len(e_range) * len(n_range)
    checked = 0
    log.info("SO swisstopo grid scan: %d × %d = %d points at %dm",
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
                    if attrs.get("ak", "").upper() != "SO":
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
                log.info("Grid %d/%d  unique SO parcels=%d",
                         checked, total, len(parcels))
            time.sleep(0.1)
    log.info("SO grid scan complete: %d unique parcels", len(parcels))
    return parcels


def _load_proxies() -> list[str]:
    """Load SO_PROXY_LIST from env (comma-separated residential proxy URLs)."""
    raw = os.environ.get("SO_PROXY_LIST", "").strip()
    if not raw:
        return []
    return [p.strip() for p in raw.split(",") if p.strip()]


# ── Main scanner ─────────────────────────────────────────────────────────────

def scan(limit: int | None = None,
         skip_existing: bool = True,
         delay: float = 2.0,
         rotate_every: int = 25):
    """
    Scan SO parcels via the PUBLIC geo.so.ch reCAPTCHA-v3 path.

    First run: ~1h swisstopo grid scan (cached). Each parcel:
      1. Open Playwright tab on captcha bootstrap page → grecaptcha v3 executes
      2. Token captured via window.top.plotOwnerInfo.loadOwnerInfo shim
      3. GET owner endpoint with token → owner JSON

    limit         : stop after N parcels
    skip_existing : skip parcels already in DB
    delay         : seconds between queries
    rotate_every  : rotate Playwright browser context every N requests
                    (only effective if SO_PROXY_LIST is set in env)
    """
    init_db()

    with get_conn() as conn:
        cached = enum_cached(conn, "SO")
    if cached:
        log.info("Using cached SO parcel list (%d parcels)", len(cached))
        parcels = cached
    else:
        log.info("Enumerating SO parcels via geodienste WFS …")
        parcels = wfs_enumerate_canton("SO")
        with get_conn() as conn:
            store_enum(conn, "SO", parcels)
        log.info("Cached %d SO parcels (WFS)", len(parcels))

    if limit:
        parcels = parcels[:limit]

    proxies = _load_proxies()
    if proxies:
        log.info("SO proxy rotation: %d proxies, rotating every %d requests",
                 len(proxies), rotate_every)

    sync_playwright, stealth_sync = _init_playwright()
    scanned = errors = herrenlos = 0
    pi = 0

    with sync_playwright() as pw:
        proxy_url = proxies[pi % len(proxies)] if proxies else None
        browser, page = _make_page(pw, stealth_sync, proxy_url)
        try:
            with get_conn() as conn:
                for p in parcels:
                    egrid   = p["egrid"]
                    bfs     = p["bfs_nr"]
                    nr      = p["parcel_nr"]
                    commune = p.get("commune", "")

                    if skip_existing and already_scanned(conn, "SO", bfs, nr):
                        continue

                    # Rotate browser context every N requests if proxies are set
                    if proxies and scanned > 0 and scanned % rotate_every == 0:
                        try: browser.close()
                        except Exception: pass
                        pi += 1
                        proxy_url = proxies[pi % len(proxies)]
                        browser, page = _make_page(pw, stealth_sync, proxy_url)
                        log.info("Rotated proxy → %s",
                                 (proxy_url or "direct").split("@")[-1])

                    result = check_owner_public(page, egrid)

                    upsert_parcel(conn, {
                        "egrid":       egrid,
                        "canton":      "SO",
                        "commune":     commune,
                        "bfs_nr":      bfs,
                        "parcel_nr":   nr,
                        "parcel_type": "Liegenschaft",
                        **result,
                    })
                    scanned += 1
                    if result.get("is_herrenlos") == 1:
                        herrenlos += 1
                        log.info("HERRENLOS  %s Nr.%s  EGRID=%s",
                                 commune, nr, egrid)
                    if result.get("error"):
                        errors += 1

                    if scanned % 50 == 0:
                        log.info("Progress %d  herrenlos=%d  errors=%d",
                                 scanned, herrenlos, errors)
                    time.sleep(delay)
        finally:
            try: browser.close()
            except Exception: pass

    log.info("SO public scan done — scanned=%d  herrenlos=%d  errors=%d",
             scanned, herrenlos, errors)
    return {"scanned": scanned, "herrenlos": herrenlos, "errors": errors}
