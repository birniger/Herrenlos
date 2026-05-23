"""
GE scanner — Geneva / Genève
==============================
STATUS (2026-05-17): SCANNER BUILT — needs GE_PROXY_LIST + ANTHROPIC_API_KEY to run
  at any meaningful scale.
  - Imperva TSPD blocks after ~30 req/IP even from residential IPs → proxy rotation
    required from the first parcel batch (set GE_PROXY_LIST in .env).
  - Per-parcel image CAPTCHA: ddddocr struggles with GE style; Claude vision gives
    best results (~$0.003/parcel × 69k = ~$200 total; set ANTHROPIC_API_KEY in .env).
  - False positive fix (2026-05-17): TSPD challenge pages were misclassified as
    herrenlos ("no Propriétaire section"). Fixed by adding TSPD phrases to
    _is_service_error(). Confirmed via GE SITG TYPE_PROPRI field on affected EGRIDs.

- Enumeration : GE SITG BIENS_FONDS REST layer (public, no auth)
                https://ge.ch/terags/rest/services/ECADASTRE_rdppf_map/MapServer/19/query
                Returns EGRID, NO_COMM (commune ID for URL), NO_PARCELLE, commune name.
                69,099 parcels cached (test 2026-05-17). Cached in parcel_enum table.

- Owner lookup: ge.ch/terextraitfoncier/rapport.aspx?commune={NO_COMM}&parcelle={NO_PARCELLE}
                Protected by TSPD (Imperva JS challenge — Playwright stealth handles it).
                Then image CAPTCHA per query (OCR: ddddocr → tesseract → Claude vision).
                CAPTCHA accuracy: ddddocr struggles with GE's style. Claude vision gives
                best results but costs ~$0.003/parcel. Consider making Claude primary
                (not fallback) when running at scale.

- Herrenlos   : "Propriétaire" section absent or empty after CAPTCHA success.

- Rate limit  : No explicit rate limit. Imperva scores IP reputation over time:
                  - Fresh IP: ~20–30 requests before service_unavailable rate increases
                  - After ~100 requests on same IP: degraded CAPTCHA or hard blocks
                  - Rotate IP every 20–30 requests for sustained scanning (implemented)
                Default delay=2.0s is a minimum — increase to 3–5s for longer runs.
                IP rotation: NOT required for runs ≤20 parcels.
                             REQUIRED for production scale.

- Parcels     : ~69,099 (Canton de Genève, 282 km²)

TO SCALE (IP rotation):
  Set GE_PROXY_LIST in .env as comma-separated residential proxy URLs:
    GE_PROXY_LIST=http://user:pass@host1:port,http://user:pass@host2:port,...
  Rotation happens every GE_PROXY_ROTATE_EVERY requests (default 25).
  Recommended providers: smartproxy.com, oxylabs.io, brightdata.com (residential tier).
  Without proxies: scanner still works but will hit Imperva blocks after ~30 requests.

  CAPTCHA at 69k parcels: ddddocr-primary + Claude fallback. Claude costs ~$0.003/parcel
  → full scan budget ~$200. Use ANTHROPIC_API_KEY in .env.
  Full scan at delay=2s + IP rotation ≈ 38h wall-clock (single thread).

COMMUNE MAPPING (BFS → GE internal NO_COMM):
    Queried from GE SITG CAD_COMMUNE layer (layer 49).
    Genève (BFS 6621) is split into 4 cadastral sections: 21, 22, 23, 24.

REQUIRES:
    pip install playwright playwright-stealth beautifulsoup4 lxml
    playwright install chromium
    Optional (better CAPTCHA accuracy):  pip install ddddocr pytesseract Pillow
    Optional (best CAPTCHA accuracy):    ANTHROPIC_API_KEY in .env (Claude vision)
    Optional (reduce Imperva errors):    GE_PROXY_LIST in .env (residential proxies)
"""

import re
import time
import logging
import requests
from bs4 import BeautifulSoup

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from db import get_conn, init_db, already_scanned, upsert_parcel, enum_cached, store_enum
from scanners.utils import is_herrenlos_owner_text, claim_possible_for, page_text_contains_herrenlos

log = logging.getLogger("GE")

BIENS_FONDS_URL = ("https://ge.ch/terags/rest/services/"
                   "ECADASTRE_rdppf_map/MapServer/19/query")
RAPPORT_URL     = "https://ge.ch/terextraitfoncier/rapport.aspx"
UA              = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/131.0.0.0 Safari/537.36")

# GE BFS → NO_COMM mapping (from GE SITG CAD_COMMUNE layer, queried 2026-05)
# Genève (BFS 6621) has 4 cadastral sub-sections.
GE_BFS_TO_COMMUNES: dict[int, list[int]] = {
    6601: [1],   # Aire-la-Ville
    6602: [2],   # Anières
    6603: [3],   # Avully
    6604: [4],   # Avusy
    6605: [5],   # Bardonnex
    6606: [6],   # Bellevue
    6607: [7],   # Bernex
    6608: [8],   # Carouge
    6609: [9],   # Cartigny
    6610: [10],  # Céligny
    6611: [11],  # Chancy
    6612: [12],  # Chêne-Bougeries
    6613: [13],  # Chêne-Bourg
    6614: [14],  # Choulex
    6615: [15],  # Collex-Bossy
    6616: [16],  # Collonge-Bellerive
    6617: [17],  # Cologny
    6618: [18],  # Confignon
    6619: [19],  # Corsier
    6620: [20],  # Dardagny
    6621: [21, 22, 23, 24],  # Genève (Cité / Eaux-Vives / Petit-Saconnex / Plainpalais)
    6622: [25],  # Genthod
    6623: [26],  # Grand-Saconnex
    6624: [27],  # Gy
    6625: [28],  # Hermance
    6626: [29],  # Jussy
    6627: [30],  # Laconnex
    6628: [31],  # Lancy
    6629: [32],  # Meinier
    6630: [33],  # Meyrin
    6631: [34],  # Onex
    6632: [35],  # Perly-Certoux
    6633: [36],  # Plan-les-Ouates
    6634: [37],  # Pregny-Chambésy
    6635: [38],  # Presinge
    6636: [39],  # Puplinge
    6637: [40],  # Russin
    6638: [41],  # Satigny
    6639: [42],  # Soral
    6640: [43],  # Thônex
    6641: [44],  # Troinex
    6642: [45],  # Vandoeuvres
    6643: [46],  # Vernier
    6644: [47],  # Versoix
    6645: [48],  # Veyrier
}


# ── Parcel enumeration via GE SITG ───────────────────────────────────────────

def enumerate_parcels_sitg() -> list[dict]:
    """
    Paginate through the GE SITG BIENS_FONDS layer.
    Returns {egrid, bfs_nr, parcel_nr, commune, extra} dicts where
    extra = {"no_comm": X} (commune ID for the rapport URL).
    Max 2000 records per request; ~73k parcels → ~37 requests.
    """
    parcels: list[dict] = []
    session = requests.Session()
    session.headers["User-Agent"] = UA

    offset     = 0
    batch_size = 2000

    log.info("GE SITG enumeration — paginating BIENS_FONDS layer …")

    while True:
        try:
            r = session.get(BIENS_FONDS_URL, params={
                "where":             "1=1",
                "outFields":         "EGRID,NO_COMM,NO_PARCELLE,COMMUNE,NUFECO",
                "f":                 "json",
                "returnGeometry":    "false",
                "resultRecordCount": batch_size,
                "resultOffset":      offset,
            }, timeout=30)

            if r.status_code != 200:
                log.warning("SITG enumeration HTTP %d at offset %d", r.status_code, offset)
                break

            features = r.json().get("features", [])
            if not features:
                break

            for feat in features:
                a = feat["attributes"]
                egrid    = a.get("EGRID") or ""
                no_comm  = int(a.get("NO_COMM") or 0)
                parcel   = str(a.get("NO_PARCELLE") or "")
                commune  = a.get("COMMUNE") or ""
                bfs      = str(int(a.get("NUFECO") or 0))

                if not egrid or not no_comm or not parcel:
                    continue

                parcels.append({
                    "egrid":     egrid,
                    "bfs_nr":    bfs,
                    "parcel_nr": parcel,
                    "commune":   commune,
                    "extra":     f'{{"no_comm":{no_comm}}}',
                })

            log.info("SITG enumeration: offset=%d  total so far=%d",
                     offset, len(parcels))
            offset += batch_size

            if len(features) < batch_size:
                break   # last page

            time.sleep(0.5)

        except Exception as exc:
            log.warning("SITG enumeration error at offset %d: %s", offset, exc)
            break

    log.info("GE SITG enumeration complete: %d parcels", len(parcels))
    return parcels


# ── CAPTCHA solving (reused from BL/SZ pattern) ──────────────────────────────

def _solve_ddddocr(img_bytes: bytes) -> str | None:
    try:
        import ddddocr
        ocr    = ddddocr.DdddOcr(show_ad=False)
        result = re.sub(r"[^a-z0-9]", "", ocr.classification(img_bytes).lower())
        return result if len(result) >= 3 else None
    except ImportError:
        log.debug("ddddocr not installed")
    except Exception as exc:
        log.debug("ddddocr: %s", exc)
    return None


def _solve_ocr(img_bytes: bytes) -> str | None:
    try:
        import io
        import pytesseract
        from PIL import Image
        img    = Image.open(io.BytesIO(img_bytes)).convert("RGB")
        config = "--psm 7 --oem 3 -c tessedit_char_whitelist=abcdefghijklmnopqrstuvwxyz0123456789"
        text   = re.sub(r"[^a-z0-9]", "",
                        pytesseract.image_to_string(img, config=config).strip().lower())
        return text if len(text) >= 3 else None
    except ImportError:
        log.debug("pytesseract not installed")
    except Exception as exc:
        log.debug("tesseract: %s", exc)
    return None


def _solve_claude(img_bytes: bytes) -> str | None:
    import base64
    try:
        import anthropic, os, json
        api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()

        # JSON config files
        if not api_key:
            for cfg in [
                pathlib.Path.home() / ".claude" / "config.json",
                pathlib.Path.home() / ".config" / "anthropic" / "config.json",
            ]:
                if cfg.exists():
                    try:
                        data = json.loads(cfg.read_text())
                        api_key = data.get("apiKey") or data.get("api_key") or ""
                        if api_key:
                            break
                    except Exception:
                        pass

        # .env files: project .env first, then ~/.env
        if not api_key:
            _proj_root = pathlib.Path(__file__).parent.parent
            for env_file in [_proj_root / ".env", pathlib.Path.home() / ".env"]:
                if env_file.exists():
                    try:
                        for line in env_file.read_text().splitlines():
                            line = line.strip()
                            if line.startswith("#") or "=" not in line:
                                continue
                            k, _, v = line.partition("=")
                            k = k.strip().removeprefix("export").strip()
                            if k == "ANTHROPIC_API_KEY":
                                api_key = v.strip().strip('"').strip("'")
                                if api_key:
                                    break
                    except Exception:
                        pass
                if api_key:
                    break

        if not api_key:
            log.debug("_solve_claude: no API key — set ANTHROPIC_API_KEY in .env")
            return None

        client = anthropic.Anthropic(api_key=api_key)
        b64    = base64.standard_b64encode(img_bytes).decode()
        msg    = client.messages.create(
            model="claude-haiku-4-5",
            max_tokens=32,
            messages=[{"role": "user", "content": [
                {"type": "image", "source": {"type": "base64",
                                              "media_type": "image/png", "data": b64}},
                {"type": "text", "text":
                 "CAPTCHA image: 4-6 lowercase letters/digits. Reply with ONLY the characters."},
            ]}],
        )
        return re.sub(r"[^a-z0-9]", "", msg.content[0].text.strip().lower()) or None
    except ImportError:
        log.debug("anthropic not installed")
    except Exception as exc:
        log.debug("Claude fallback: %s", exc)
    return None


def solve_captcha(img_bytes: bytes) -> str | None:
    return _solve_ddddocr(img_bytes) or _solve_ocr(img_bytes) or _solve_claude(img_bytes)


# ── Playwright helpers ────────────────────────────────────────────────────────

def _init_playwright():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise RuntimeError(
            "playwright not installed.\n"
            "Run: pip install playwright playwright-stealth && playwright install chromium"
        )
    try:
        from playwright_stealth import stealth_sync           # legacy API
    except ImportError:
        try:
            from playwright_stealth import Stealth             # new API
            stealth_sync = Stealth().apply_stealth_sync
        except ImportError:
            stealth_sync = None
            log.warning("playwright-stealth not installed — TSPD bypass may fail.")
    return sync_playwright, stealth_sync


def _make_page(pw, stealth_sync, proxy_url: str | None = None):
    """
    Launch a Playwright browser (optionally via proxy) and return (browser, page).

    proxy_url format: "http://user:pass@host:port"  (residential proxy recommended)
    """
    browser = pw.chromium.launch(
        headless=True,
        args=["--disable-blink-features=AutomationControlled"],
        proxy={"server": proxy_url} if proxy_url else None,
    )
    ctx = browser.new_context(
        user_agent=UA,
        viewport={"width": 1280, "height": 800},
        locale="fr-CH",
        timezone_id="Europe/Zurich",
    )
    page = ctx.new_page()
    if stealth_sync:
        stealth_sync(page)
    return browser, page


def _load_proxies() -> list[str]:
    """
    Load proxy list from GE_PROXY_LIST env var or .env file.

    Format: comma-separated proxy URLs, e.g.:
      GE_PROXY_LIST=http://user:pass@host1:port,http://user:pass@host2:port

    Returns empty list if not configured (scanner runs without proxies).
    """
    import os
    raw = os.environ.get("GE_PROXY_LIST", "").strip()
    if not raw:
        _proj_root = pathlib.Path(__file__).parent.parent
        for env_file in [_proj_root / ".env", pathlib.Path.home() / ".env"]:
            if env_file.exists():
                try:
                    for line in env_file.read_text().splitlines():
                        line = line.strip()
                        if line.startswith("#") or "=" not in line:
                            continue
                        k, _, v = line.partition("=")
                        k = k.strip().removeprefix("export").strip()
                        if k == "GE_PROXY_LIST":
                            raw = v.strip().strip('"').strip("'")
                            if raw:
                                break
                except Exception:
                    pass
            if raw:
                break
    proxies = [p.strip() for p in raw.split(",") if p.strip()]
    return proxies


# ── Owner check ──────────────────────────────────────────────────────────────

def check_owner(page, no_comm: int, parcel_nr: str, egrid: str,
                max_retries: int = 4) -> dict:
    """
    Load ge.ch/terextraitfoncier/rapport.aspx for one parcel.

    Flow:
      Playwright navigates to rapport.aspx?commune=X&parcelle=Y
      → TSPD JS challenge handled automatically by the real browser
      → image CAPTCHA solved with OCR
      → parse Propriétaire section
    """
    url = f"{RAPPORT_URL}?commune={no_comm}&parcelle={parcel_nr}"

    for attempt in range(max_retries):
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30_000)
            page.wait_for_timeout(2000)

            html = page.content()
            soup = BeautifulSoup(html, "lxml")
            text = soup.get_text(separator="\n")

            # TSPD challenge still loading — wait longer
            if "loaderConfig" in html or "TSPD" in html:
                page.wait_for_timeout(4000)
                html = page.content()
                soup = BeautifulSoup(html, "lxml")
                text = soup.get_text(separator="\n")

            # Check for image CAPTCHA
            captcha_img = (
                soup.find("img", {"id": re.compile(r"captcha", re.I)})
                or soup.find("img", {"src": re.compile(r"captcha|image\.ashx", re.I)})
                or soup.find("img", {"class": re.compile(r"captcha", re.I)})
            )

            if captcha_img:
                img_src = captcha_img.get("src", "")
                if not img_src.startswith("http"):
                    img_src = "https://ge.ch" + img_src

                # Download captcha via requests (same session cookies via page)
                cookies_dict = {c["name"]: c["value"] for c in page.context.cookies()}
                r_img = requests.get(img_src, cookies=cookies_dict,
                                     headers={"User-Agent": UA}, timeout=10)
                solution = solve_captcha(r_img.content)

                if not solution:
                    log.debug("GE CAPTCHA unsolved (attempt %d) egrid=%s", attempt, egrid)
                    continue

                log.debug("GE CAPTCHA solved: %r (attempt %d)", solution, attempt)

                # Submit CAPTCHA form
                form   = soup.find("form")
                action = (form.get("action", url) if form else url)
                if not action.startswith("http"):
                    action = "https://ge.ch" + action

                # Extract hidden ASP.NET form fields
                form_data: dict[str, str] = {}
                if form:
                    for inp in form.find_all("input", {"type": "hidden"}):
                        name = inp.get("name", "")
                        val  = inp.get("value", "")
                        if name:
                            form_data[name] = val

                for field in ("captcha", "captcha_answer", "CaptchaValue",
                              "ctl00$ContentPlaceHolder1$CaptchaControl1",
                              "code"):
                    form_data[field] = solution

                # Submit via Playwright to keep session cookies
                page.evaluate(f"""
                    const form = document.querySelector('form');
                    if (form) {{
                        const inp = document.createElement('input');
                        inp.type = 'hidden';
                        inp.name = 'captcha';
                        inp.value = {repr(solution)};
                        form.appendChild(inp);
                        form.submit();
                    }}
                """)
                page.wait_for_timeout(3000)
                html = page.content()
                soup = BeautifulSoup(html, "lxml")
                text = soup.get_text(separator="\n")

            return _parse_rapport(soup, text, egrid)

        except Exception as exc:
            log.debug("check_owner error (attempt %d): %s", attempt, exc)
            time.sleep(2)

    return {"owner": None, "owner_address": None, "is_herrenlos": None,
            "herrenlos_type": None, "claim_possible": None,
            "raw_response": None,
            "error": f"failed_after_{max_retries}_retries"}


# French error phrases and Imperva/TSPD bot-challenge patterns that mean the page is
# NOT a valid rapport — NOT that the parcel has no owner.
# Root cause of 2026-05-17 false positives: TSPD challenge pages (loaderConfig,
# Please Wait, etc.) were parsed as having no "Propriétaire" section → herrenlos.
_GE_SERVICE_ERROR_PHRASES = [
    # French service errors
    "service est actuellement indisponible",
    "service is currently unavailable",
    "essayer à nouveau",
    "veuillez réessayer",
    "temporarily unavailable",
    "service temporairement indisponible",
    "erreur interne",
    "erreur du serveur",
    # Imperva / TSPD JS challenge pages (the pages that caused false positives)
    "loaderconfig",           # Imperva JS loader
    "tspd_101",               # TSPD cookie name
    "_tspd",                  # TSPD JS variable
    "imperva",                # Imperva branding
    "please wait",            # "Please Wait..." TSPD challenge page
    "checking your browser",  # Cloudflare / Imperva challenge message
    "enable javascript",      # Bot-challenge page
    "access denied",          # Hard block
    "bot protection",         # Generic bot-protection page
]


def _is_service_error(text: str) -> bool:
    """
    Return True if the page is a transient error or bot-challenge, NOT a real rapport.

    This guards against Imperva TSPD challenge pages being misclassified as
    herrenlos (empty Propriétaire section).  Any match here → error, not herrenlos.
    """
    tl = text.lower()
    return any(phrase in tl for phrase in _GE_SERVICE_ERROR_PHRASES)


def _parse_rapport(soup: BeautifulSoup, text: str, egrid: str) -> dict:
    """
    Parse ge.ch/terextraitfoncier rapport page (French).

    The page shows:
      "Immeuble"         → parcel info
      "Propriétaire(s)"  → owner table
    If the Propriétaire section is absent or empty → herrenlos.
    """
    # Transient service error — do NOT classify as herrenlos
    if _is_service_error(text):
        log.debug("GE service error page for EGRID=%s — counting as error", egrid)
        return {"owner": None, "owner_address": None, "is_herrenlos": None,
                "herrenlos_type": None, "claim_possible": None,
                "raw_response": text[:300], "error": "service_unavailable"}

    # Herrenlos indicator anywhere on the page (covers all languages)
    if page_text_contains_herrenlos(text):
        return {"owner": None, "owner_address": None, "is_herrenlos": 1,
                "herrenlos_type": "dereliktion",
                "claim_possible": claim_possible_for("GE", "dereliktion"),
                "raw_response": text[:300], "error": None}

    # Look for Propriétaire section
    has_section = bool(re.search(r"propri[eé]taire", text, re.I))

    names: list[str] = []
    addrs: list[str] = []

    # Try multiple selectors for the owner table
    for sel in [
        "table.proprietaire td", ".proprietaire", "[class*='propri']",
        "td", "tr td",
    ]:
        for el in soup.select(sel):
            t = el.get_text(separator=" ", strip=True)
            if not t or len(t) < 3 or len(t) > 150:
                continue
            prev = el.find_previous(
                string=re.compile(r"propri[eé]taire", re.I)
            )
            if prev:
                if not is_herrenlos_owner_text(t):
                    # Filter out known non-name values
                    if not re.match(r"^\d{4,}$", t):   # skip bare numbers
                        names.append(t)
        if names:
            break

    # Fallback: look for names near "Propriétaire" text
    if not names and has_section:
        for tag in soup.find_all(string=re.compile(r"propri[eé]taire", re.I)):
            parent = tag.find_parent()
            if parent:
                siblings = parent.find_next_siblings(["td", "p", "div", "span"])[:3]
                for sib in siblings:
                    t = sib.get_text(separator=" ", strip=True)
                    if t and len(t) > 2 and not is_herrenlos_owner_text(t):
                        names.append(t)

    if has_section and not names:
        log.info("HERRENLOS (empty Propriétaire section) EGRID=%s", egrid)
        return {"owner": None, "owner_address": None, "is_herrenlos": 1,
                "herrenlos_type": "dereliktion",
                "claim_possible": claim_possible_for("GE", "dereliktion"),
                "raw_response": text[:300], "error": None}

    # Parcel not in RF at all (page shows nothing useful)
    if not has_section and "immeuble" not in text.lower():
        return {"owner": None, "owner_address": None, "is_herrenlos": 1,
                "herrenlos_type": "not_in_grundbuch",
                "claim_possible": claim_possible_for("GE", "not_in_grundbuch"),
                "raw_response": text[:300], "error": None}

    if not has_section:
        return {"owner": None, "owner_address": None, "is_herrenlos": None,
                "herrenlos_type": None, "claim_possible": None,
                "raw_response": text[:300], "error": "proprietaire_section_missing"}

    owner = "; ".join(dict.fromkeys(names)) or None   # deduplicate, preserve order
    return {
        "owner":          owner,
        "owner_address":  "; ".join(dict.fromkeys(addrs)) or None,
        "is_herrenlos":   0 if owner else 1,
        "herrenlos_type": None if owner else "dereliktion",
        "claim_possible": None if owner else claim_possible_for("GE", "dereliktion"),
        "raw_response":   None,
        "error":          None,
    }


# ── Main scanner ─────────────────────────────────────────────────────────────

def scan(limit: int | None = None,
         skip_existing: bool = True,
         delay: float = 2.0,
         rotate_every: int | None = None):
    """
    Scan GE parcels for herrenlos detection via ge.ch/terextraitfoncier.

    Enumeration uses the public GE SITG BIENS_FONDS REST layer (no auth).
    Owner lookup uses Playwright stealth to handle TSPD bot protection,
    plus image CAPTCHA OCR (ddddocr → tesseract → Claude vision).

    First run: ~5 min SITG enumeration (cached to DB). Then Playwright queries.

    IP Rotation (Imperva/TSPD):
      Set GE_PROXY_LIST in .env with comma-separated residential proxy URLs.
      A new Playwright browser context is opened every `rotate_every` requests,
      cycling through the proxy list. Without proxies the scanner still works
      but hits Imperva blocks after ~20-30 requests.

    limit         : stop after N parcels
    skip_existing : skip parcels already in DB
    delay         : seconds between queries (minimum 2.0)
    rotate_every  : rotate proxy every N requests (default from GE_PROXY_ROTATE_EVERY
                    env var, or 25)
    """
    import json as _json, os

    init_db()

    with get_conn() as conn:
        cached = enum_cached(conn, "GE")
    if cached:
        log.info("Using cached GE parcel list (%d parcels)", len(cached))
        parcels = cached
    else:
        log.info("No cache — enumerating via GE SITG (~5 min) …")
        parcels = enumerate_parcels_sitg()
        with get_conn() as conn:
            store_enum(conn, "GE", parcels)
        log.info("Cached %d GE parcels", len(parcels))

    if limit:
        parcels = parcels[:limit]

    # Proxy rotation setup
    proxies = _load_proxies()
    if rotate_every is None:
        try:
            rotate_every = int(os.environ.get("GE_PROXY_ROTATE_EVERY", "25"))
        except ValueError:
            rotate_every = 25
    proxy_idx = 0

    if proxies:
        log.info("IP rotation enabled: %d proxies, rotate every %d requests",
                 len(proxies), rotate_every)
    else:
        log.info("No proxies configured — running without IP rotation")

    sync_playwright, stealth_sync = _init_playwright()
    scanned = errors = herrenlos = 0

    def _open_browser(pw, proxy_list, idx):
        """Open a fresh Playwright browser, cycling through proxy_list."""
        proxy_url = proxy_list[idx % len(proxy_list)] if proxy_list else None
        if proxy_url:
            log.info("Opening browser with proxy #%d (%s…)", idx % len(proxy_list),
                     proxy_url.split("@")[-1] if "@" in proxy_url else proxy_url[:30])
        browser, page = _make_page(pw, stealth_sync, proxy_url)
        # Warm up: complete TSPD JS challenge on portal home
        try:
            page.goto("https://ge.ch/terextraitfoncier/",
                      wait_until="domcontentloaded", timeout=20_000)
            page.wait_for_timeout(3000)
        except Exception:
            pass
        return browser, page

    with sync_playwright() as pw:
        browser, page = _open_browser(pw, proxies, proxy_idx)
        requests_on_current_ip = 0

        with get_conn() as conn:
            for p in parcels:
                egrid   = p["egrid"]
                bfs     = p["bfs_nr"]
                nr      = p["parcel_nr"]
                commune = p.get("commune", "")

                # no_comm stored in extra (dict from enum_cached, or JSON string from enumerate)
                extra = p.get("extra") or {}
                if isinstance(extra, str):
                    try:
                        extra = _json.loads(extra)
                    except Exception:
                        extra = {}
                no_comm = int(extra.get("no_comm", 0)) if isinstance(extra, dict) else 0

                if not no_comm:
                    log.warning("Missing no_comm for GE parcel %s/%s", bfs, nr)
                    errors += 1
                    continue

                if skip_existing and already_scanned(conn, "GE", bfs, nr):
                    continue

                # Rotate IP if threshold reached and proxies are available
                if proxies and requests_on_current_ip >= rotate_every:
                    log.info("Rotating IP after %d requests", requests_on_current_ip)
                    try:
                        browser.close()
                    except Exception:
                        pass
                    proxy_idx += 1
                    browser, page = _open_browser(pw, proxies, proxy_idx)
                    requests_on_current_ip = 0

                result = check_owner(page, no_comm, nr, egrid)
                requests_on_current_ip += 1

                upsert_parcel(conn, {
                    "egrid":       egrid,
                    "canton":      "GE",
                    "commune":     commune,
                    "bfs_nr":      bfs,
                    "parcel_nr":   nr,
                    "parcel_type": "Bien-fonds",
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

        try:
            browser.close()
        except Exception:
            pass

    log.info("GE scan done — scanned=%d  herrenlos=%d  errors=%d",
             scanned, herrenlos, errors)
    return {"scanned": scanned, "herrenlos": herrenlos, "errors": errors}
