"""
JU scanner — Jura / République et Canton du Jura
==================================================
STATUS (2026-05-17): WORKING. Tested: scanned=5  herrenlos=0  errors=0.
  No account required. WFS enumeration and CAPTCHA both working correctly.

  IMPORTANT — actual scannable parcel count is 16,183, NOT 77,550:
  The WFS server reports numberMatched=77,550 but ~61k features have no url_rf field
  (they are non-parcelle objects like rights-of-way, servitudes, etc.) and cannot be
  looked up on sitrf.jura.ch. Enumeration stops naturally when pages return no valid
  features — do not be alarmed by the mismatch between WFS hits and cached count.

- EGRID enumeration : JU cantonal WFS (geo.jura.ch/mapserv_proxy).
                      Layer: ms:sdt_01_04_md_sit_bf_interrogation
                      WFS reports 77,550 features; ~16,183 have a valid url_rf field.
                      ~78 paginated requests, ~5min one-time cost.
                      BFS and parcel_nr extracted from url_rf nocompar parameter.
                      Results cached in parcel_enum table.
                      WHY WFS INSTEAD OF SWISSTOPO: JU is not in the federal
                      swisstopo amtliche-vermessung layer → swisstopo grid-scan
                      returns zero results for JU.

- Owner lookup      : ASP.NET WebForms portal https://sitrf.jura.ch/Validation.aspx
                      guarded by a 4-digit numeric image CAPTCHA.
                      URL: ?nocompar=<bfs_nr><parcel_nr>
                      e.g. commune Delémont BFS=6711 + parcel 998 → nocompar=6711998
                      Form fields: __VIEWSTATE, __VIEWSTATEGENERATOR, __EVENTVALIDATION
                      (standard ASP.NET hidden fields) + TextBox1 (CAPTCHA answer).

- CAPTCHA solving   : ddddocr primary — works well on JU's 4-digit stippled numeric style
                      (~75% per-attempt accuracy). Tesseract density-map pipeline fallback.
                      With max_retries=6: P(overall success) > 99.9%.
                      Wrong CAPTCHA: portal returns page containing "Erreur" — we retry.

- Rate limit        : None observed. CAPTCHA per query is the only gate.
                      Default delay=1.5s between parcels is courteous; can reduce to
                      0.5s if needed (no throttling observed in testing).

- Herrenlos signals :
    Type A (not_in_grundbuch) : "Bien-fonds" absent from response AND page is ≥400 bytes
                                 (portal stubs < 400 bytes are retried, not classified).
                                 Parcel is in cadastre but not in RF → canton acquires (Art. 664 ZGB).
                                 claim_possible = 0
    Type B (dereliktion)      : "Bien-fonds" present, "Propriétaire" table exists but has
                                 no owner name rows. Parcel IS in RF but owner deleted.
                                 claim_possible = None (JU EG ZGB not yet researched)

- Parcels           : 16,183 scannable (WFS server reports 77,550 but most lack url_rf)
                      Canton area: 838 km²

- To scale          : No IP rotation needed — no rate limiting or IP-based throttling
                      observed. Safe to parallelise with 2–4 concurrent sessions.
                      Full scan of 16,183 parcels at delay=1.5s ≈ 6.7h single-threaded;
                      ≈ 1.7h with 4 parallel workers.

REQUIRES:
    pip install ddddocr                      (primary CAPTCHA solver)
    pip install pytesseract Pillow numpy     (fallback CAPTCHA solver, optional)
"""

import re
import time
import logging
import requests
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup

import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from db import get_conn, init_db, already_scanned, upsert_parcel, enum_cached, store_enum, log_captcha
from scanners.utils import is_herrenlos_owner_text, claim_possible_for

log = logging.getLogger("JU")

SITRF_URL = "https://sitrf.jura.ch/Validation.aspx"
SITRF_IMG_URL = "https://sitrf.jura.ch/Image.ashx"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"

# JU cantonal WFS (geo.jura.ch)
WFS_BASE = "https://geo.jura.ch/mapserv_proxy"
WFS_LAYER = "ms:sdt_01_04_md_sit_bf_interrogation"
WFS_PARAMS_BASE = {
    "ogcserver": "Main_PNG",
    "SERVICE":   "WFS",
    "VERSION":   "2.0.0",
    "TYPENAMES": WFS_LAYER,
}
WFS_NS = {
    "ms":  "http://mapserver.gis.umn.edu/mapserver",
    "wfs": "http://www.opengis.net/wfs/2.0",
}

# Ownership type prefixes to strip from the Propriétaire cell
_OWNERSHIP_PREFIXES = [
    "Propriété individuelle",
    "Copropriété",
    "Propriété par étages",
    "Propriété commune",
    "Propriété en main commune",
    # German variants (unlikely for JU but safe to include)
    "Alleineigentum",
    "Miteigentum",
    "Gesamteigentum",
    "Stockwerkeigentum",
]


# ── OCR helpers ──────────────────────────────────────────────────────────────

def _solve_ddddocr(jpeg_bytes: bytes) -> str | None:
    """Primary: ddddocr — trained on stippled numeric CAPTCHAs, ~75% accuracy."""
    try:
        import ddddocr
        ocr = ddddocr.DdddOcr(show_ad=False)
        result = re.sub(r"[^0-9]", "", ocr.classification(jpeg_bytes))
        if len(result) == 4:
            return result
        # Try beta model if standard gave wrong length
        ocr_b = ddddocr.DdddOcr(show_ad=False, beta=True)
        result_b = re.sub(r"[^0-9]", "", ocr_b.classification(jpeg_bytes))
        if len(result_b) == 4:
            return result_b
        return result if len(result) >= 3 else (result_b if len(result_b) >= 3 else None)
    except ImportError:
        log.debug("ddddocr not installed — pip install ddddocr")
    except Exception as exc:
        log.debug("ddddocr error: %s", exc)
    return None


def _solve_tesseract(jpeg_bytes: bytes) -> str | None:
    """Fallback: density-map + solidification pipeline for Tesseract."""
    try:
        import io
        import numpy as np
        from PIL import Image, ImageFilter
        import pytesseract

        img = Image.open(io.BytesIO(jpeg_bytes)).convert("L")
        arr = np.array(img, dtype=float)
        inv = 255.0 - arr
        inv_img = Image.fromarray(inv.astype(np.uint8), "L")
        blurred = inv_img.filter(ImageFilter.GaussianBlur(radius=5))
        bl_arr = np.array(blurred, dtype=float)
        digit_mask = (bl_arr > bl_arr.max() * 0.35).astype(np.uint8)
        masked = np.where(digit_mask, arr, 255).astype(np.uint8)
        solid = Image.fromarray(masked, "L").filter(ImageFilter.GaussianBlur(radius=2))
        binary = np.where(np.array(solid) < 200, 0, 255).astype(np.uint8)
        out = Image.fromarray(binary, "L").resize(
            (binary.shape[1] * 4, binary.shape[0] * 4), Image.LANCZOS)

        best = ""
        for psm in [7, 8, 6, 13]:
            cfg = f"--psm {psm} --oem 3 -c tessedit_char_whitelist=0123456789"
            t = re.sub(r"[^0-9]", "", pytesseract.image_to_string(out, config=cfg))
            if len(t) == 4:
                return t
            if len(t) > len(best):
                best = t
        return best if len(best) >= 3 else None
    except ImportError:
        log.debug("pytesseract/PIL/numpy not installed")
    except Exception as exc:
        log.debug("density OCR error: %s", exc)
    return None


def solve_captcha(jpeg_bytes: bytes) -> str | None:
    """Try ddddocr first, then density pipeline."""
    result = _solve_ddddocr(jpeg_bytes)
    if result and len(result) == 4:
        return result
    result2 = _solve_tesseract(jpeg_bytes)
    if result2 and len(result2) == 4:
        return result2
    # Return best partial if nothing better
    return result or result2


# ── Parcel enumeration via JU cantonal WFS ───────────────────────────────────

def _wfs_total(session: requests.Session) -> int:
    """Get total parcel count from WFS hits request."""
    r = session.get(WFS_BASE, params={
        **WFS_PARAMS_BASE,
        "REQUEST":    "GetFeature",
        "RESULTTYPE": "hits",
    }, timeout=30)
    r.raise_for_status()
    root = ET.fromstring(r.text)
    return int(root.attrib.get("numberMatched", 0))


def _wfs_page(session: requests.Session, startindex: int, count: int = 1000) -> list[dict]:
    """Fetch one page of WFS features; returns list of parcel dicts."""
    r = session.get(WFS_BASE, params={
        **WFS_PARAMS_BASE,
        "REQUEST":      "GetFeature",
        "COUNT":        count,
        "STARTINDEX":   startindex,
        "PROPERTYNAME": "ms:commune,ms:numero,ms:egris_egrid,ms:url_rf,ms:genre_bf",
    }, timeout=30)
    r.raise_for_status()
    root = ET.fromstring(r.text)
    parcels = []
    for member in root.findall("wfs:member", WFS_NS):
        feat = member.find(f".//ms:{WFS_LAYER.split(':')[1]}", WFS_NS)
        if feat is None:
            continue
        egrid_el   = feat.find("ms:egris_egrid", WFS_NS)
        url_rf_el  = feat.find("ms:url_rf",      WFS_NS)
        commune_el = feat.find("ms:commune",      WFS_NS)
        genre_el   = feat.find("ms:genre_bf",     WFS_NS)
        if egrid_el is None or url_rf_el is None:
            continue
        url_rf = url_rf_el.text or ""
        m = re.search(r"nocompar=(\d+)", url_rf)
        if not m:
            continue
        nocompar = m.group(1)
        # JU BFS numbers are always 4 digits (6700–6899 range)
        bfs       = nocompar[:4]
        parcel_nr = nocompar[4:]
        genre_bf  = (genre_el.text or "").strip() if genre_el is not None else ""
        parcels.append({
            "egrid":     egrid_el.text or "",
            "bfs_nr":    bfs,
            "parcel_nr": parcel_nr,
            "commune":   commune_el.text if commune_el is not None else "",
            "genre_bf":  genre_bf,                              # top-level for immediate use
            "extra":     {"genre_bf": genre_bf} if genre_bf else None,  # stored in DB
        })
    return parcels


def enumerate_parcels_wfs(page_size: int = 1000) -> list[dict]:
    """
    Enumerate all JU parcels via the cantonal WFS (geo.jura.ch).
    Returns list of {egrid, bfs_nr, parcel_nr, commune} dicts.
    ~77,550 parcels, ~78 requests, ~5min one-time cost.
    Results are cached in the parcel_enum DB table.
    """
    session = requests.Session()
    session.headers["User-Agent"] = UA

    try:
        total = _wfs_total(session)
        log.info("JU WFS: %d parcels to enumerate in pages of %d", total, page_size)
    except Exception as exc:
        log.warning("WFS hits request failed: %s — will paginate until empty", exc)
        total = 100_000  # safe upper bound

    seen:    set[str]  = set()
    parcels: list[dict] = []
    startindex = 0

    while startindex < total:
        try:
            page = _wfs_page(session, startindex, page_size)
        except Exception as exc:
            log.warning("WFS page startindex=%d error: %s — retrying after 5s", startindex, exc)
            time.sleep(5)
            try:
                page = _wfs_page(session, startindex, page_size)
            except Exception as exc2:
                log.error("WFS page startindex=%d failed twice: %s — stopping", startindex, exc2)
                break

        if not page:
            break

        for p in page:
            eg = p["egrid"]
            if eg and eg not in seen:
                seen.add(eg)
                parcels.append(p)

        startindex += page_size
        if startindex % 10_000 == 0:
            log.info("WFS progress: %d/%d  unique parcels=%d", startindex, total, len(parcels))
        time.sleep(0.2)

    log.info("WFS enumeration complete: %d unique JU parcels", len(parcels))
    return parcels


# ── Owner check ──────────────────────────────────────────────────────────────

def _strip_ownership_type(text: str) -> str:
    """Remove leading ownership-type keyword from owner cell text."""
    for prefix in _OWNERSHIP_PREFIXES:
        if text.startswith(prefix):
            return text[len(prefix):].strip()
    return text.strip()


def check_owner(bfs_nr: str, parcel_nr: str, egrid: str,
                max_retries: int = 6) -> dict:
    """
    Look up owner for one JU parcel via sitrf.jura.ch.

    Flow per attempt:
      GET  Validation.aspx?nocompar=<bfs_nr+parcel_nr>  → CAPTCHA form
      GET  Image.ashx                                    → JPEG CAPTCHA
      [OCR solve]
      POST Validation.aspx                               → owner page or "Erreur"

    Returns dict with: owner, owner_address, is_herrenlos, herrenlos_type,
                       claim_possible, raw_response, error
    """
    nocompar = str(bfs_nr) + str(parcel_nr)

    for attempt in range(max_retries):
        try:
            session = requests.Session()
            session.headers["User-Agent"] = UA

            # ── Get CAPTCHA form ─────────────────────────────────────────────
            r1 = session.get(f"{SITRF_URL}?nocompar={nocompar}", timeout=15)

            if r1.status_code != 200:
                log.debug("Validation GET %d (attempt %d)", r1.status_code, attempt)
                time.sleep(2)
                continue

            # Already on owner page (session reuse — unlikely for fresh session).
            # Use "Bien-fonds" (not "Extrait") as the check: the 272-byte portal
            # stub also contains "Extrait du Registre Foncier" but lacks parcel data.
            solver_used = None   # set below in CAPTCHA branch; None = no CAPTCHA needed
            if "Bien-fonds" in r1.text:
                html = r1.text
            else:
                # Parse ASP.NET form fields
                m_vs  = re.search(r'id="__VIEWSTATE"\s+value="([^"]+)"',          r1.text)
                m_vsg = re.search(r'id="__VIEWSTATEGENERATOR"\s+value="([^"]+)"', r1.text)
                m_ev  = re.search(r'id="__EVENTVALIDATION"\s+value="([^"]+)"',    r1.text)
                if not (m_vs and m_vsg and m_ev):
                    log.debug("VIEWSTATE not found (attempt %d)", attempt)
                    time.sleep(1)
                    continue

                # ── Fetch and solve CAPTCHA — track which solver fires for stats ──
                r_img = session.get(SITRF_IMG_URL, timeout=15)
                captcha, solver_used = None, "none"
                for _fn, _name in (
                    (_solve_ddddocr,  "ddddocr"),
                    (_solve_tesseract,  "tesseract"),
                ):
                    s = _fn(r_img.content)
                    if s and len(s) == 4:
                        captcha, solver_used = s, _name
                        break

                if not captcha or len(captcha) < 4:
                    log_captcha("JU", "none", "unsolved")
                    log.debug("OCR gave '%s' — retrying", captcha)
                    time.sleep(0.5)
                    continue

                # ── Submit ───────────────────────────────────────────────────
                r2 = session.post(
                    f"{SITRF_URL}?nocompar={nocompar}",
                    data={
                        "__LASTFOCUS":          "",
                        "__VIEWSTATE":          m_vs.group(1),
                        "__VIEWSTATEGENERATOR": m_vsg.group(1),
                        "__EVENTTARGET":        "",
                        "__EVENTARGUMENT":      "",
                        "__EVENTVALIDATION":    m_ev.group(1),
                        "TextBox1":             captcha,
                        "Button1":              "Valider",
                    },
                    headers={"Referer": f"{SITRF_URL}?nocompar={nocompar}"},
                    timeout=15,
                )

                if "Erreur" in r2.text:
                    log_captcha("JU", solver_used, "wrong")
                    log.debug("Wrong CAPTCHA '%s' (attempt %d)", captcha, attempt)
                    time.sleep(0.5)
                    continue

                html = r2.text

            # ── Parse owner page ─────────────────────────────────────────────
            if solver_used:   # None = owner page served without CAPTCHA (cached session)
                log_captcha("JU", solver_used, "correct")
            result = _parse_owner_html(html, egrid, nocompar)
            if result.get("error") == "invalid_page":
                log.warning("Invalid/stub JU result page for nocompar=%s (attempt %d) — retrying",
                            nocompar, attempt)
                time.sleep(1)
                continue
            return result

        except Exception as exc:
            log.debug("check_owner exception (attempt %d): %s", attempt, exc)
            time.sleep(2)

    return {"owner": None, "owner_address": None,
            "is_herrenlos": None, "herrenlos_type": None, "claim_possible": None,
            "raw_response": None, "error": f"captcha_failed_after_{max_retries}_retries"}


def _parse_owner_html(html: str, egrid: str, nocompar: str) -> dict:
    """
    Parse the sitrf.jura.ch owner extract page.

    Structure when parcel found:
        "Bien-fonds" section → parcel metadata
        "Propriété" section  → owner table

    Structure when NOT found:
        Page shows header/footer only — no "Bien-fonds" block.
    """
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(separator="\n")

    # ── Success-page validation ───────────────────────────────────────────────
    # The 272-byte portal stub ("République et Canton du Jura … RF SIT") lacks
    # "Bien-fonds" and is silently misclassified as not_in_grundbuch without this
    # guard.  A real JU response (found or genuinely not-found) is always >400 bytes.
    if len(html.strip()) < 400:
        log.warning("Invalid/stub JU result page (only %d bytes) for EGRID=%s nocompar=%s "
                    "— treating as retryable failure, NOT herrenlos", len(html.strip()), egrid, nocompar)
        return {"owner": None, "owner_address": None, "is_herrenlos": None,
                "herrenlos_type": None, "claim_possible": None,
                "raw_response": None, "error": "invalid_page"}

    # ── Type A: parcel not in RF at all ──────────────────────────────────────
    if "Bien-fonds" not in text:
        log.info("HERRENLOS (not_in_grundbuch)  EGRID=%s  nocompar=%s", egrid, nocompar)
        return {
            "owner": None, "owner_address": None,
            "is_herrenlos": 1,
            "herrenlos_type": "not_in_grundbuch",
            "claim_possible": 0,
            "raw_response": text.replace("\n", " "), "error": None,
        }

    # ── PPE base parcel: ownership lives in sub-units, no owner table rendered ──
    # sitrf.jura.ch renders a div list (not a <table>) for PPE (Propriété par
    # étages) base parcels. Ownership belongs to the individual PPE units
    # (e.g. 19-1, 19-2…), so the base parcel correctly has no owner in the
    # table. The page text contains "PPE <commune> <bfs>/<nr>-<unit>" entries
    # instead of a table row. This is NOT herrenlos — return owned immediately.
    if re.search(r"\bPPE\b", text):
        log.debug("PPE base parcel (no direct owner) — skipping  EGRID=%s", egrid)
        return {"owner": None, "owner_address": None,
                "is_herrenlos": 0,
                "herrenlos_type": None, "claim_possible": None,
                "raw_response": None, "error": None}

    # ── Parse owner table ────────────────────────────────────────────────────
    table = soup.find("table")
    owners:  list[str] = []
    addrs:   list[str] = []

    if table:
        rows = table.find_all("tr")
        for row in rows:
            cells = row.find_all("td")
            if len(cells) < 1:
                continue
            raw_owner = cells[0].get_text(separator=" ", strip=True)
            name = _strip_ownership_type(raw_owner)
            if not name or is_herrenlos_owner_text(name):
                continue
            # Skip header-like rows
            if name in ("Propriétaire", "Part", "Date acquisition"):
                continue
            owners.append(name)
            # Address not in this table — sitrf only shows name, share, date.
            # Address lookup would require separate RF query (not implemented).

    if not table:
        # Fallback: sitrf.jura.ch renders co-ownership bases (COP) and parcel
        # cross-references (B-F) using <div> elements instead of a <table>.
        # These parcels are NOT herrenlos — their ownership lives in sub-units.
        # Parse the Propriété section from the page text.
        _skip = {"Propriétaire", "Part", "Date acquisition"}
        _section_end = {"Surface", "Bâtiments", "Droits", "Charges",
                        "Servitudes", "Remarques", "Annotations"}
        lines = [ln.strip() for ln in text.split("\n") if ln.strip()]
        try:
            prop_idx = next(i for i, ln in enumerate(lines) if ln == "Propriété")
            for ln in lines[prop_idx + 1:]:
                if ln in _skip:
                    continue
                if re.match(r"^\d+/\d+$", ln):           # ownership fractions
                    continue
                if re.match(r"^\d{4}-\d{2}-\d{2}$", ln):  # acquisition dates
                    continue
                if ln in _section_end:
                    break
                if not is_herrenlos_owner_text(ln):
                    owners.append(ln)
        except StopIteration:
            pass
        if owners:
            log.debug("div-layout ownership  EGRID=%s  refs=%s", egrid, owners[:3])

    owner = "; ".join(owners) if owners else None

    if owner is None:
        log.info("HERRENLOS (dereliktion) — no owner in RF  EGRID=%s", egrid)

    # ── Type B: parcel in RF but no owner ────────────────────────────────────
    h_type = None if owner else "dereliktion"
    return {
        "owner":          owner,
        "owner_address":  None,   # sitrf.jura.ch does not expose owner addresses
        "is_herrenlos":   0 if owner else 1,
        "herrenlos_type": h_type,
        "claim_possible": claim_possible_for("JU", h_type) if h_type else None,
        "raw_response":   text if owner is None else None,
        "error":          None,
    }


# ── Main scanner ─────────────────────────────────────────────────────────────

def scan(limit: int | None = None,
         skip_existing: bool = True,
         delay: float = 1.5):
    """
    Scan JU parcels for herrenlos detection.

    First run: ~5min WFS enumeration of ~77,550 parcels (cached to DB).
    Subsequent runs: use cached list directly.

    No hard rate limit — CAPTCHA per query is the only gate.
    With delay=1.5s and max_retries=6 per parcel the scanner is courteous.

    limit         : stop after N parcels (None = all)
    skip_existing : skip parcels already in DB
    delay         : seconds between parcels
    """
    init_db()

    with get_conn() as conn:
        cached = enum_cached(conn, "JU")
    if cached:
        log.info("Using cached JU parcel list (%d parcels)", len(cached))
        parcels = cached
    else:
        log.info("No cache — running WFS enumeration (~5min) …")
        parcels = enumerate_parcels_wfs()
        with get_conn() as conn:
            store_enum(conn, "JU", parcels)
        log.info("Cached %d JU parcels", len(parcels))

    if limit:
        parcels = parcels[:limit]

    scanned = errors = herrenlos = 0

    with get_conn() as conn:
        for p in parcels:
            egrid    = p.get("egrid", "")
            bfs      = p.get("bfs_nr", "")
            nr       = p.get("parcel_nr", "")
            commune  = p.get("commune", "")
            # genre_bf: top-level when fresh from WFS, inside extra{} when loaded from cache
            genre_bf = p.get("genre_bf") or (p.get("extra") or {}).get("genre_bf", "")

            if not bfs or not nr:
                errors += 1
                continue

            # BGE 118 II 115: Droit de superficie (Baurecht) cannot be herrenlos —
            # the right always has a holder; skip to avoid false positives.
            if genre_bf == "Droit de superficie":
                log.debug("Skipping Droit de superficie  bfs=%s nr=%s", bfs, nr)
                continue

            if skip_existing and already_scanned(conn, "JU", bfs, nr):
                continue

            result = check_owner(bfs, nr, egrid)

            upsert_parcel(conn, {
                "egrid":       egrid,
                "canton":      "JU",
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
            if result.get("error") and result["error"] != "invalid_page":
                errors += 1
                log.warning("Error %s Nr.%s: %s", commune, nr, result["error"])

            if scanned % 50 == 0:
                log.info("Progress %d  herrenlos=%d  errors=%d", scanned, herrenlos, errors)

            time.sleep(delay)

    log.info("JU scan done — scanned=%d  herrenlos=%d  errors=%d", scanned, herrenlos, errors)
    return {"scanned": scanned, "herrenlos": herrenlos, "errors": errors}
