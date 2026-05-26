"""
ZG scanner — Zug
=================
STATUS (2026-05): PERMANENTLY BLOCKED (no fix possible without institutional access).
  lr.zugmap.ch requires an SMS verification code per owner query.
  Every request returns a "Mobile-Nummer" form — a Swiss mobile number is mandatory.
  No workaround exists for private persons. Scanner emits error=sms_required
  and skips the parcel rather than mis-classifying as herrenlos.
  Alternative: request Grundbuch data directly from the Grundbuchamt Zug.

- Enumeration : swisstopo identify API grid scan (step=200m, ~2h one-time)
                Cached in parcel_enum table.
- Owner lookup: lr.zugmap.ch Grundstückreport, eigentum section.
                URL: https://lr.zugmap.ch/r/eigentum?egrid={EGRID}&back=lr&lrc=1
                WAF blocks plain HTTP → playwright-stealth is mandatory.
- Herrenlos   : Eigentum section absent / no owner name after page load.
- Rate limit  : None documented. Default delay=3s.
- Parcels     : ~85,000 (Kanton Zug, 239 km²)

REQUIRES:
    pip install playwright playwright-stealth beautifulsoup4 lxml
    playwright install chromium
"""

import re
import time
import logging
import requests
from bs4 import BeautifulSoup

import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from db import get_conn, init_db, already_scanned, upsert_parcel, enum_cached, store_enum
from scanners.wfs_enum import enumerate_canton as wfs_enumerate_canton
from scanners.utils import is_herrenlos_owner_text, claim_possible_for, page_text_contains_herrenlos

log = logging.getLogger("ZG")

EIGENTUM_URL       = "https://lr.zugmap.ch/r/eigentum"
LR_HOME            = "https://lr.zugmap.ch/"
SWISSTOPO_IDENTIFY = "https://api3.geo.admin.ch/rest/services/ech/MapServer/identify"
UA                 = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/131.0.0.0 Safari/537.36")

# ZG LV95 bounding box (~239 km²)
ZG_EMIN, ZG_EMAX = 2_670_000, 2_700_000
ZG_NMIN, ZG_NMAX = 1_215_000, 1_240_000
ZG_GRID_STEP     = 200   # metres


# ── Parcel enumeration via swisstopo ─────────────────────────────────────────

def enumerate_parcels_swisstopo(
        emin=ZG_EMIN, emax=ZG_EMAX,
        nmin=ZG_NMIN, nmax=ZG_NMAX,
        step=ZG_GRID_STEP) -> list[dict]:
    """Grid scan — returns {egrid, bfs_nr, parcel_nr, commune} dicts."""
    seen:    set[str]  = set()
    parcels: list[dict] = []
    session = requests.Session()
    session.headers["User-Agent"] = UA

    e_range = range(emin, emax + 1, step)
    n_range = range(nmin, nmax + 1, step)
    total   = len(e_range) * len(n_range)
    checked = 0

    log.info("ZG swisstopo grid scan: %d × %d = %d points at %dm",
             len(e_range), len(n_range), total, step)

    for e in e_range:
        for n in n_range:
            checked += 1
            try:
                r = session.get(SWISSTOPO_IDENTIFY, params={
                    "geometry":       f"{e},{n}",
                    "geometryType":   "esriGeometryPoint",
                    "imageDisplay":   "500,500,96",
                    "mapExtent":      f"{e-step},{n-step},{e+step},{n+step}",
                    "tolerance":      5,
                    "layers":         "all:ch.swisstopo-vd.amtliche-vermessung",
                    "sr":             2056,
                    "lang":           "de",
                    "returnGeometry": "false",
                }, timeout=10)

                if r.status_code != 200:
                    continue

                for feat in r.json().get("results", []):
                    attrs = feat.get("attributes", {})
                    if attrs.get("ak", "").upper() != "ZG":
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

            if checked % 2000 == 0:
                log.info("Grid %d/%d  unique ZG parcels=%d", checked, total, len(parcels))
            time.sleep(0.1)

    log.info("Grid scan complete: %d unique ZG parcels", len(parcels))
    return parcels


# ── Playwright helpers ────────────────────────────────────────────────────────

def _init_playwright():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise RuntimeError(
            "playwright not installed.\n"
            "Run: pip install playwright playwright-stealth && playwright install chromium"
        )
    # Support both old (stealth_sync function) and new (Stealth class) playwright-stealth APIs
    stealth_sync = None
    try:
        from playwright_stealth import stealth_sync as _ss   # legacy API
        stealth_sync = _ss
    except ImportError:
        try:
            from playwright_stealth import Stealth           # new API
            stealth_sync = Stealth().apply_stealth_sync
        except ImportError:
            log.warning("playwright-stealth not installed — WAF bypass may fail. "
                        "Run: pip install playwright-stealth")
    return sync_playwright, stealth_sync


def _make_page(pw, stealth_sync):
    browser = pw.chromium.launch(
        headless=True,
        args=["--disable-blink-features=AutomationControlled"],
    )
    ctx = browser.new_context(
        user_agent=UA,
        viewport={"width": 1280, "height": 800},
        locale="de-CH",
        timezone_id="Europe/Zurich",
    )
    page = ctx.new_page()
    if stealth_sync:
        stealth_sync(page)
    return browser, page


# ── Owner check ──────────────────────────────────────────────────────────────

def check_owner(page, egrid: str) -> dict:
    """
    Navigate the Playwright page to the ZG eigentum section and parse owner info.
    The page loads via lr.zugmap.ch which requires cookies (no SMS since Jan 2024).
    """
    url = f"{EIGENTUM_URL}?egrid={egrid}&back=lr&lrc=1"
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=30_000)
        page.wait_for_timeout(2500)
        return _parse_eigentum(page.content(), egrid)
    except Exception as exc:
        return {"owner": None, "owner_address": None, "is_herrenlos": None,
                "herrenlos_type": None, "claim_possible": None,
                "raw_response": None, "error": str(exc)[:200]}


def _parse_eigentum(html: str, egrid: str) -> dict:
    """
    Parse the lr.zugmap.ch eigentum section HTML.

    After cookies are accepted the page shows owner info or an explicit
    "no owner" indicator.  An empty eigentum section → dereliktion.
    """
    soup = BeautifulSoup(html, "lxml")
    text = soup.get_text(separator="\n")

    # Cookie gate still active
    if "zwingend" in text and "Cookies" in text:
        return {"owner": None, "owner_address": None, "is_herrenlos": None,
                "herrenlos_type": None, "claim_possible": None,
                "raw_response": text[:200], "error": "cookies_required"}

    # SMS verification gate (ZG re-enabled this after 2024-01-15)
    # Raw page is "Formular Mobile-Nummer / Bitte geben Sie Ihre Mobile-Nummer ein"
    if "Mobile-Nummer" in text or "Mobile Nummer" in text or "SMS-Code" in text:
        return {"owner": None, "owner_address": None, "is_herrenlos": None,
                "herrenlos_type": None, "claim_possible": None,
                "raw_response": text[:200], "error": "sms_required"}

    # Explicit herrenlos indicator anywhere on the page
    if page_text_contains_herrenlos(text):
        return {"owner": None, "owner_address": None, "is_herrenlos": 1,
                "herrenlos_type": "dereliktion",
                "claim_possible": claim_possible_for("ZG", "dereliktion"),
                "raw_response": text, "error": None}

    # Find owner names next to "Eigentümer" labels
    names: list[str] = []
    for el in soup.find_all(["td", "dd", "p", "span", "div"]):
        t = el.get_text(separator=" ", strip=True)
        if not t or len(t) < 3 or len(t) > 200:
            continue
        prev = el.find_previous(["th", "dt", "label", "strong", "h3", "h4", "b"])
        if prev and any(kw in prev.get_text(strip=True).lower()
                        for kw in ("eigentümer", "eigentuemer", "eigentum")):
            if not is_herrenlos_owner_text(t):
                names.append(t)
            else:
                return {"owner": None, "owner_address": None, "is_herrenlos": 1,
                        "herrenlos_type": "dereliktion",
                        "claim_possible": claim_possible_for("ZG", "dereliktion"),
                        "raw_response": text, "error": None}

    has_section = bool(re.search(r"eigentümer|eigentuemer|eigentum", text, re.I))

    if has_section and not names:
        log.info("HERRENLOS (no owner in eigentum section) EGRID=%s", egrid)
        return {"owner": None, "owner_address": None, "is_herrenlos": 1,
                "herrenlos_type": "dereliktion",
                "claim_possible": claim_possible_for("ZG", "dereliktion"),
                "raw_response": text, "error": None}

    if not has_section:
        return {"owner": None, "owner_address": None, "is_herrenlos": None,
                "herrenlos_type": None, "claim_possible": None,
                "raw_response": text[:300], "error": "eigentum_section_missing"}

    owner = "; ".join(names) or None
    return {
        "owner":          owner,
        "owner_address":  None,
        "is_herrenlos":   0 if owner else 1,
        "herrenlos_type": None if owner else "dereliktion",
        "claim_possible": None if owner else claim_possible_for("ZG", "dereliktion"),
        "raw_response":   None,
        "error":          None,
    }


# ── Main scanner ─────────────────────────────────────────────────────────────

def scan(limit: int | None = None,
         skip_existing: bool = True,
         delay: float = 3.0):
    """
    Scan ZG parcels for herrenlos detection via lr.zugmap.ch.

    No SMS or account required since 2024-01-15.
    Uses Playwright stealth (headless) — WAF blocks plain HTTP.

    First run: ~2h swisstopo grid scan (cached to DB). Then Playwright queries.

    limit         : stop after N parcels
    skip_existing : skip parcels already in DB
    delay         : seconds between queries
    """
    init_db()

    with get_conn() as conn:
        cached = enum_cached(conn, "ZG")
    if cached:
        log.info("Using cached ZG parcel list (%d parcels)", len(cached))
        parcels = cached
    else:
        log.info("Enumerating ZG parcels via geodienste WFS …")
        parcels = wfs_enumerate_canton("ZG")
        with get_conn() as conn:
            store_enum(conn, "ZG", parcels)
        log.info("Cached %d ZG parcels (WFS)", len(parcels))

    if limit:
        parcels = parcels[:limit]

    sync_playwright, stealth_sync = _init_playwright()
    scanned = errors = herrenlos = 0

    with sync_playwright() as pw:
        browser, page = _make_page(pw, stealth_sync)

        # Warm-up: visit home page to satisfy cookie check
        try:
            page.goto(LR_HOME, wait_until="domcontentloaded", timeout=20_000)
            page.wait_for_timeout(2000)
        except Exception:
            pass

        with get_conn() as conn:
            for p in parcels:
                egrid   = p["egrid"]
                bfs     = p["bfs_nr"]
                nr      = p["parcel_nr"]
                commune = p.get("commune", "")

                if skip_existing and already_scanned(conn, "ZG", bfs, nr):
                    continue

                result = check_owner(page, egrid)

                # Re-warm session on cookie gate
                if result.get("error") == "cookies_required":
                    log.debug("Cookie gate — re-warming session")
                    try:
                        page.goto(LR_HOME, wait_until="domcontentloaded", timeout=15_000)
                        page.wait_for_timeout(3000)
                    except Exception:
                        pass
                    result = check_owner(page, egrid)

                upsert_parcel(conn, {
                    "egrid":       egrid,
                    "canton":      "ZG",
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
                if result.get("error") and result["error"] not in ("cookies_required",):
                    errors += 1

                if scanned % 50 == 0:
                    log.info("Progress %d  herrenlos=%d  errors=%d",
                             scanned, herrenlos, errors)

                time.sleep(delay)

        browser.close()

    log.info("ZG scan done — scanned=%d  herrenlos=%d  errors=%d",
             scanned, herrenlos, errors)
    return {"scanned": scanned, "herrenlos": herrenlos, "errors": errors}
