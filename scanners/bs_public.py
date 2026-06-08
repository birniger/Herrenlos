"""
BS scanner — Basel-Stadt (PUBLIC OWNER PATH)
=============================================
STATUS (2026-05-18): NEWLY BUILT. Companion to scanners/bs.py.

Architecture:
  scanners/bs.py        — metadata-only via api.geo.bs.ch REST + BS_API_KEY.
                          Detects Type A herrenlos (Art. 664: not in Grundbuch).
                          CANNOT detect Type B (owner data not in REST API).
  scanners/bs_public.py — Playwright + reCAPTCHA Enterprise against the
                          /eigentum/{section}/{parcel_nr} HTML viewer.
                          Detects Type B (Art. 964: dereliktion) AND extracts
                          actual owner names + addresses.

Together they cover both herrenlos types. This file is the test framework's
default for BS because it's the only one that returns owner names.

CAPTURED ENDPOINTS (via Chrome DevTools + JS bundle source, 2026-05-18):

  Page (loads grecaptcha + has the "Grundeigentum anzeigen" button):
    GET https://api.geo.bs.ch/eigentum/{section}/{parcel_nr}

  reCAPTCHA Enterprise execute (inside the loaded page):
    await grecaptcha.enterprise.execute(
        '6LepM5YsAAAAAN5CN9iJ3zh_HF9nirKCo70tB_55',
        {action: 'EGT'}
    )

  Owner data fetch:
    GET https://api.geo.bs.ch/eigentumsauskunftngeo/api/
        sektion={section}&parznr={parcel_nr}&token={recaptcha_token}
    (note the literal "&" between the params + non-standard URL — that's how the
     BS SPA builds it; reproduced verbatim here)

  Response shape:
    {
      "grundstueck": {...},
      "adressen":    [{"strasse": "Holbeinstrasse", "hausnummer": "29", ...}],
      "grundstuecke":[{"grundstueckartid": 3, ...}],
      "indexav":     {"nummerindex": <int>, ...},
      "pdfuuid":     "/grundstueckinfo/v1/landregister?uuid=...",
      "eigentum":    [        # ← the owner array
         {
            "eigentuemer":  "Audidiere Laure Marie Annick",
            "pers_adresse": "Holbeinstrasse 29" | null,
            "pers_plz":     "4051"             | null,
            "pers_ort":     "Basel"            | null,
            "zusatz":       "ja"|"no",
            "grundstueck":  true|false,
            ...
         }
      ]
    }

RATE LIMIT (verified by viewer message):
  10 queries per day per IP. The BS page itself shows the remaining quota
  ("Ihrer IP X.X.X.X verbleiben heute noch N Abfragen."). After 10/day, the
  API returns an error. For full ~7,000-parcel BS coverage, paid residential
  proxies are needed (same model as GR).

EGRID enumeration:
  scanners.bs.enumerate_parcels uses swisstopo identify + the BS metadata API
  to populate parcel_enum with (egrid, bfs_nr, parcel_nr) AND also captures
  SectionNumber from the metadata API into extra={"section": "3"}.
  bs_public.scan() reads (section, parcel_nr) from there.

REQUIRES:
  pip install playwright playwright-stealth
  playwright install chromium
  BS_API_KEY in .env (for the enumeration / section lookup step)
"""

import os
import json
import time
import logging
import requests

import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from db import get_conn, init_db, already_scanned, upsert_parcel, enum_cached, store_enum
from scanners.utils import is_herrenlos_owner_text, claim_possible_for
from scanners.wfs_enum import enumerate_canton as wfs_enumerate_canton

log = logging.getLogger("BS")

# ── Endpoints (verified 2026-05-18 via Chrome + JS-bundle inspection) ─────────
BS_BASE         = "https://api.geo.bs.ch"
BS_PAGE_URL     = f"{BS_BASE}/eigentum/{{section}}/{{parcel_nr}}"
BS_OWNER_API    = (f"{BS_BASE}/eigentumsauskunftngeo/api/"
                   "sektion={section}&parznr={parcel_nr}&token={token}")
BS_INFO_URL     = f"{BS_BASE}/grundstueckinfo/v1/realestatesinformation"
BS_RECAPTCHA_SITEKEY = "6LepM5YsAAAAAN5CN9iJ3zh_HF9nirKCo70tB_55"
BS_RECAPTCHA_ACTION  = "EGT"

SWISSTOPO_IDENTIFY = "https://api3.geo.admin.ch/rest/services/api/MapServer/identify"
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
      "AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/131.0.0.0 Safari/537.36")

BS_API_KEY = os.environ.get("BS_API_KEY", "").strip()

# BS LV95 bounding box (small canton)
BS_EMIN, BS_EMAX = 2_610_000, 2_622_000
BS_NMIN, BS_NMAX = 1_263_000, 1_272_000
BS_GRID_STEP     = 50

# Daily rate-limit (per the portal's own message)
BS_DAILY_LIMIT_PER_IP = 10


# ── Playwright bootstrap (mirrors so_public.py) ──────────────────────────────

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
            "BS public scanner requires:  pip install playwright playwright-stealth"
            "  &&  playwright install chromium"
        ) from e


def _make_page(pw, stealth_sync, proxy_url: str | None = None):
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


def _load_proxies() -> list[str]:
    """BS_PROXY_LIST — comma-separated residential proxy URLs."""
    raw = os.environ.get("BS_PROXY_LIST", "").strip()
    if not raw:
        return []
    return [p.strip() for p in raw.split(",") if p.strip()]


# ── Section lookup (uses the metadata API) ───────────────────────────────────

def _get_section_for_egrid(egrid: str, api_key: str) -> str | None:
    """Resolve EGRID → SectionNumber via the BS metadata API."""
    if not api_key:
        return None
    try:
        r = requests.get(BS_INFO_URL,
                         params={"ids": egrid, "apikey": api_key},
                         timeout=15)
        if r.status_code != 200:
            return None
        for re_ in r.json().get("RealEstates", []):
            if re_.get("Egrid") == egrid:
                s = re_.get("SectionNumber")
                if s is not None:
                    return str(s)
    except Exception as exc:
        log.debug("BS metadata fetch failed for %s: %s", egrid, exc)
    return None


# ── Owner check via reCAPTCHA Enterprise + eigentumsauskunftngeo API ─────────

def check_owner_public(page, section: str, parcel_nr: str,
                       max_retries: int = 3) -> dict:
    """
    Resolve owner data via the BS /eigentum HTML viewer:
      1. Load /eigentum/{section}/{parcel_nr} so grecaptcha Enterprise loads.
      2. Execute grecaptcha.enterprise.execute(SITEKEY, {action: 'EGT'}) → token.
      3. GET /eigentumsauskunftngeo/api/sektion=<S>&parznr=<P>&token=<token>.
      4. Parse the `eigentum` array.

    Returns the canonical 7-key dict. is_herrenlos / herrenlos_type follow
    the universal contract: empty owner OR sentinel-string owner → herrenlos.
    """
    last_err = None
    for attempt in range(1, max_retries + 1):
        try:
            page.goto(BS_PAGE_URL.format(section=section, parcel_nr=parcel_nr),
                      wait_until="domcontentloaded", timeout=20_000)
            # Wait for grecaptcha Enterprise to be ready
            page.wait_for_function(
                "typeof grecaptcha !== 'undefined' && grecaptcha.enterprise"
                " && typeof grecaptcha.enterprise.execute === 'function'",
                timeout=20_000,
            )
            # Brief human-idle gives Google's risk analysis a better score
            page.wait_for_timeout(1500)

            # Execute Enterprise reCAPTCHA to get a token
            token = page.evaluate(f"""
                async () => {{
                    return await grecaptcha.enterprise.execute(
                        '{BS_RECAPTCHA_SITEKEY}',
                        {{action: '{BS_RECAPTCHA_ACTION}'}}
                    );
                }}
            """)
            if not token or not isinstance(token, str) or len(token) < 50:
                last_err = "no_token"
                time.sleep(2)
                continue

            owner_url = BS_OWNER_API.format(
                section=section, parcel_nr=parcel_nr, token=token,
            )
            resp = page.context.request.get(owner_url, timeout=15_000)
            if resp.status == 429:
                return _empty(error="rate_limited")
            if resp.status == 403:
                return _empty(error="forbidden_country")  # see JS handler
            if resp.status != 200:
                last_err = f"http_{resp.status}"
                time.sleep(2)
                continue

            try:
                data = resp.json()
            except Exception:
                last_err = "json_parse"
                time.sleep(1)
                continue

            return _parse_owner(data)

        except Exception as exc:
            last_err = str(exc)[:120]
            log.debug("BS public check_owner attempt %d failed: %s",
                      attempt, last_err)
            time.sleep(1)

    return _empty(error=last_err or "unknown")


def _empty(error: str | None = None) -> dict:
    return {"owner": None, "owner_address": None,
            "is_herrenlos": None,
            "herrenlos_type": None, "claim_possible": None,
            "raw_response": None, "error": error}


def _parse_owner(data: dict) -> dict:
    """
    Map the BS eigentumsauskunftngeo response into the canonical 7-key dict.

    The `eigentum` array contains one entry per owner. Each entry has:
      eigentuemer   — name string (may sometimes be a sentinel)
      pers_adresse  — street, sometimes null
      pers_plz      — postal code, sometimes null
      pers_ort      — city, sometimes null

    Apply is_herrenlos_owner_text() to filter sentinel names (universal contract).
    """
    owners_raw = data.get("eigentum") or []

    owner_strs:    list[str] = []
    address_strs:  list[str] = []
    sentinel_seen = False
    for o in owners_raw:
        name = (o.get("eigentuemer") or "").strip()
        if not name:
            continue
        if is_herrenlos_owner_text(name):
            sentinel_seen = True
            continue
        # Build "Name, Street, PLZ Ort" if address parts present
        addr_bits = []
        if o.get("pers_adresse"): addr_bits.append(str(o["pers_adresse"]).strip())
        plz = (o.get("pers_plz") or "").strip()
        ort = (o.get("pers_ort") or "").strip()
        if plz or ort:
            addr_bits.append(f"{plz} {ort}".strip())
        owner_strs.append(name)
        if addr_bits:
            address_strs.append(", ".join(addr_bits))

    if owner_strs:
        return {
            "owner":          "; ".join(owner_strs),
            "owner_address":  "; ".join(address_strs) if address_strs else None,
            "is_herrenlos":   0,
            "herrenlos_type": None,
            "claim_possible": None,
            "raw_response":   None,
            "error":          None,
        }

    # No real owners — either empty array OR all sentinels. Either way, herrenlos.
    return {
        "owner":          None,
        "owner_address":  None,
        "is_herrenlos":   1,
        "herrenlos_type": "dereliktion",
        "claim_possible": claim_possible_for("BS", "dereliktion"),
        "raw_response":   json.dumps(data),
        "error":          None,
    }


# ── Main scanner ─────────────────────────────────────────────────────────────

def scan(limit: int | None = None,
         skip_existing: bool = True,
         delay: float = 5.0,
         rotate_every: int = 10):
    """
    Scan BS parcels via the PUBLIC reCAPTCHA-Enterprise path.

    Rate limit is 10/day per IP — hard. Without residential proxies you can
    realistically do at most 10 parcels per day per IP. Set BS_PROXY_LIST in
    .env to rotate; default rotate_every=10 (matches the daily cap).

    Per-parcel: needs section + parcel_nr. If parcel_enum doesn't have section,
    it's fetched from the metadata API at scan time using BS_API_KEY.
    """
    init_db()
    if not BS_API_KEY:
        log.error("BS_API_KEY not set — needed to look up section per EGRID.")
        return {"scanned": 0, "herrenlos": 0, "errors": 1}

    with get_conn() as conn:
        cached = enum_cached(conn, "BS")
    if not cached:
        log.info("No BS parcel cache — enumerating via geodienste WFS (~30s) …")
        cached = wfs_enumerate_canton("BS")
        with get_conn() as conn:
            store_enum(conn, "BS", cached)
        log.info("Cached %d BS parcels (WFS)", len(cached))

    if limit:
        cached = cached[:limit]

    proxies = _load_proxies()
    if proxies:
        log.info("BS proxy rotation: %d proxies, rotating every %d requests",
                 len(proxies), rotate_every)
    elif limit and limit > BS_DAILY_LIMIT_PER_IP:
        log.warning("BS has a HARD 10/day/IP cap. Without proxies, expect ≤10 "
                    "successful queries before rate-limit errors. Set "
                    "BS_PROXY_LIST in .env for full coverage.")

    sync_playwright, stealth_sync = _init_playwright()
    scanned = errors = herrenlos = 0
    pi = 0

    with sync_playwright() as pw:
        proxy_url = proxies[pi % len(proxies)] if proxies else None
        browser, page = _make_page(pw, stealth_sync, proxy_url)
        try:
            with get_conn() as conn:
                for p in cached:
                    egrid     = p["egrid"]
                    bfs       = p["bfs_nr"]
                    parcel_nr = p["parcel_nr"]
                    commune   = p.get("commune", "")
                    extra     = p.get("extra") or {}

                    if skip_existing and already_scanned(conn, "BS", bfs, parcel_nr):
                        continue

                    # Section: from enum's extra, or fall back to metadata API.
                    section = extra.get("section") if isinstance(extra, dict) else None
                    if not section:
                        section = _get_section_for_egrid(egrid, BS_API_KEY)
                    if not section:
                        # Not in the BS Grundbuch metadata API → Type A herrenlos
                        result = {
                            "owner": None, "owner_address": None,
                            "is_herrenlos":   1,
                            "herrenlos_type": "not_in_grundbuch",
                            "claim_possible": claim_possible_for(
                                                "BS", "not_in_grundbuch"),
                            "raw_response": None, "error": None,
                        }
                    else:
                        # Rotate browser context every N requests if proxies set
                        if proxies and scanned > 0 and scanned % rotate_every == 0:
                            try: browser.close()
                            except Exception: pass
                            pi += 1
                            proxy_url = proxies[pi % len(proxies)]
                            browser, page = _make_page(pw, stealth_sync, proxy_url)
                            log.info("Rotated proxy → %s",
                                     (proxy_url or "direct").split("@")[-1])
                        result = check_owner_public(page, section, parcel_nr)

                    upsert_parcel(conn, {
                        "egrid":       egrid,
                        "canton":      "BS",
                        "commune":     commune,
                        "bfs_nr":      bfs,
                        "parcel_nr":   parcel_nr,
                        "parcel_type": "Liegenschaft",
                        **result,
                    })
                    scanned += 1
                    if result.get("is_herrenlos") == 1:
                        herrenlos += 1
                        log.info("HERRENLOS  %s Nr.%s  EGRID=%s",
                                 commune, parcel_nr, egrid)
                    if result.get("error"):
                        errors += 1
                        if result["error"] == "rate_limited":
                            log.warning("BS daily quota exhausted. Stop here or "
                                        "rotate proxy. (set BS_PROXY_LIST)")
                            break

                    if scanned % 25 == 0:
                        log.info("Progress %d  herrenlos=%d  errors=%d",
                                 scanned, herrenlos, errors)
                    time.sleep(delay)
        finally:
            try: browser.close()
            except Exception: pass

    log.info("BS public scan done — scanned=%d  herrenlos=%d  errors=%d",
             scanned, herrenlos, errors)
    return {"scanned": scanned, "herrenlos": herrenlos, "errors": errors}
