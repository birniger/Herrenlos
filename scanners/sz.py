"""
SZ scanner — Schwyz
====================
- EGRID enumeration : geodienste.ch WFS (wfs_enum.py)
                      Cached in parcel_enum table — only runs once ever.
- Owner lookup      : GET  https://service2.geo.sz.ch/ownership/captcha/access/{EGRID}.html
                      → Django simple_captcha form
                      POST form with csrfmiddlewaretoken + captcha_0 (hash) + captcha_1 (answer)
                      → HTML response with owner table
- Captcha           : Django simple_captcha — image served at
                      /dokumente/c/service/image/{hash}/ (greyscale PNG, 6 alphanumeric chars)
                      Solved with ddddocr (primary) → tesseract (fallback)
- Rate limit        : No documented limit; 1–2 s delay is polite
- Herrenlos signal  : No "Eigentümer" row in response table, OR empty owner cell
- Parcels           : ~50,000 (verified by WFS)
"""

import re
import time
import logging
import requests
from bs4 import BeautifulSoup

import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from db import get_conn, init_db, already_scanned, upsert_parcel, enum_cached, store_enum, log_captcha
from scanners.wfs_enum import enumerate_canton as wfs_enumerate_canton
from scanners.utils import (
    is_herrenlos_owner_text, claim_possible_for,
    DEFAULT_UA,
)

log = logging.getLogger("SZ")

BASE_URL        = "https://service2.geo.sz.ch"
OWNER_URL       = f"{BASE_URL}/ownership/captcha/access/{{egrid}}.html"
CAPTCHA_IMG_URL = f"{BASE_URL}/dokumente/c/service/image/{{hash}}/"


# ── CAPTCHA solvers ───────────────────────────────────────────────────────────

def _solve_ddddocr(png_bytes: bytes) -> str | None:
    """Primary solver — try standard + beta models; collect both predictions."""
    candidates = []
    try:
        import ddddocr
        ocr = ddddocr.DdddOcr(show_ad=False)
        raw = ocr.classification(png_bytes)
        clean = re.sub(r"[^a-z0-9]", "", raw.lower())
        if 4 <= len(clean) <= 6:
            candidates.append(clean)
        elif len(clean) >= 3:
            candidates.append(clean)
        ocr_b = ddddocr.DdddOcr(show_ad=False, beta=True)
        raw_b = ocr_b.classification(png_bytes)
        clean_b = re.sub(r"[^a-z0-9]", "", raw_b.lower())
        if 4 <= len(clean_b) <= 6:
            candidates.append(clean_b)
        elif len(clean_b) >= 3:
            candidates.append(clean_b)
        log.debug("ddddocr candidates=%s", candidates)
        # Prefer the one with canonical length (4-6 chars typical)
        for c in candidates:
            if 4 <= len(c) <= 6:
                return c
        return candidates[0] if candidates else None
    except ImportError:
        log.debug("ddddocr not installed — pip install ddddocr")
    except Exception as exc:
        log.debug("ddddocr error: %s", exc)
    return None


def _preprocess_for_tesseract(png_bytes: bytes):
    """Image preprocessing pipeline: upscale + grayscale + denoise + threshold."""
    try:
        from PIL import Image, ImageFilter, ImageOps
        import io
        img = Image.open(io.BytesIO(png_bytes)).convert("L")
        # 4x upscale (tesseract works best at 300+ DPI equivalent)
        w, h = img.size
        img = img.resize((w * 4, h * 4), Image.LANCZOS)
        # Soft denoise then otsu-style threshold
        img = img.filter(ImageFilter.MedianFilter(size=3))
        img = ImageOps.autocontrast(img, cutoff=2)
        return img
    except ImportError:
        return None


def _solve_tesseract(png_bytes: bytes) -> str | None:
    """Fallback solver — tesseract with multiple PSM modes and preprocessing."""
    try:
        import pytesseract
        from PIL import Image
        import io

        # Try both raw and preprocessed image, multiple PSM modes
        raw_img = Image.open(io.BytesIO(png_bytes)).convert("L")
        pre_img = _preprocess_for_tesseract(png_bytes) or raw_img

        for img in (pre_img, raw_img):
            for psm in (7, 8, 6, 13):
                cfg = f"--oem 3 --psm {psm} -c tessedit_char_whitelist=abcdefghijklmnopqrstuvwxyz0123456789"
                raw = pytesseract.image_to_string(img, config=cfg).strip().lower()
                clean = re.sub(r"[^a-z0-9]", "", raw)
                if 4 <= len(clean) <= 6:
                    log.debug("tesseract psm=%d clean=%r", psm, clean)
                    return clean
    except ImportError:
        log.debug("pytesseract/PIL not installed")
    except Exception as exc:
        log.debug("tesseract error: %s", exc)
    return None


def _solve_captcha(png_bytes: bytes) -> str | None:
    return _solve_ddddocr(png_bytes) or _solve_tesseract(png_bytes)


# ── Owner check ───────────────────────────────────────────────────────────────

def check_owner(session: requests.Session, egrid: str) -> dict:
    """
    Query owner for one SZ parcel via Django captcha-protected form.

    Flow:
    1. GET /ownership/captcha/access/{EGRID}.html
       → HTML with csrfmiddlewaretoken, captcha_0 (hash key), captcha image URL
    2. GET /dokumente/c/service/image/{hash}/ → PNG
    3. Solve captcha (ddddocr → tesseract)
    4. POST form with csrfmiddlewaretoken + captcha_0 + captcha_1 (solved text)
       → HTML with owner table (or "nicht gefunden" / empty)
    """
    url = OWNER_URL.format(egrid=egrid)

    try:
        # Step 1: fetch captcha form
        r = session.get(url, timeout=15)

        if r.status_code == 404:
            return {"owner": None, "owner_address": None,
                    "is_herrenlos": 1,
                    "herrenlos_type": "not_in_grundbuch", "claim_possible": 0,
                    "raw_response": None, "error": None}
        if r.status_code != 200:
            return {"owner": None, "owner_address": None, "is_herrenlos": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "raw_response": None, "error": f"http_{r.status_code}"}

        soup = BeautifulSoup(r.text, "html.parser")

        # Extract CSRF token
        csrf_input = soup.find("input", {"name": "csrfmiddlewaretoken"})
        csrf       = csrf_input["value"] if csrf_input else ""

        # Extract captcha_0 (hash key) — hidden input
        cap0_input = soup.find("input", {"name": "captcha_0"})
        if not cap0_input:
            log.debug("No captcha_0 found for EGRID=%s", egrid)
            return {"owner": None, "owner_address": None, "is_herrenlos": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "raw_response": r.text[:300], "error": "no_captcha_field"}
        captcha_hash = cap0_input["value"]

        # Step 2: fetch captcha image
        img_url  = CAPTCHA_IMG_URL.format(hash=captcha_hash)
        img_r    = session.get(img_url, timeout=10)
        if img_r.status_code != 200:
            return {"owner": None, "owner_address": None, "is_herrenlos": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "raw_response": None, "error": f"captcha_img_http_{img_r.status_code}"}
        png_bytes = img_r.content

        # Step 3: solve captcha — track which solver fires for stats
        solution, solver_used = None, "none"
        for _fn, _name in (
            (_solve_ddddocr,   "ddddocr"),
            (_solve_tesseract, "tesseract"),
        ):
            s = _fn(png_bytes)
            if s:
                solution, solver_used = s, _name
                break

        if not solution:
            log_captcha("SZ", "none", "unsolved")
            log.debug("CAPTCHA unsolved for EGRID=%s", egrid)
            return {"owner": None, "owner_address": None, "is_herrenlos": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "raw_response": None, "error": "captcha_unsolved"}

        log.debug("CAPTCHA solution=%r for EGRID=%s", solution, egrid)

        # Step 4: POST form
        post_r = session.post(
            url,
            data={
                "csrfmiddlewaretoken": csrf,
                "captcha_0":           captcha_hash,
                "captcha_1":           solution,
            },
            headers={
                "Referer": url,
                "X-CSRFToken": csrf,
            },
            timeout=15,
        )

        html = post_r.text

        # Check for wrong captcha (Django form re-renders with error)
        if "captcha" in html.lower() and post_r.status_code == 200:
            # Check if it's a new captcha form (captcha wrong) vs. results page
            post_soup = BeautifulSoup(html, "html.parser")
            if post_soup.find("input", {"name": "captcha_0"}):
                log_captcha("SZ", solver_used, "wrong")
                log.debug("CAPTCHA rejected (wrong answer) for EGRID=%s", egrid)
                return {"owner": None, "owner_address": None, "is_herrenlos": None,
                        "herrenlos_type": None, "claim_possible": None,
                        "raw_response": None, "error": "captcha_wrong"}

        # Parse owner from response HTML
        log_captcha("SZ", solver_used, "correct")
        return _parse_owner_html(html, egrid)

    except Exception as exc:
        return {"owner": None, "owner_address": None,
                "is_herrenlos": None,
                "herrenlos_type": None, "claim_possible": None,
                "raw_response": None, "error": str(exc)}


def _parse_owner_html(html: str, egrid: str) -> dict:
    """
    Extract owner name + address from SZ Grundbuch response HTML.

    Current SZ portal (2026-05) uses Bootstrap div layout:
      <div class="list-group-header"> <div class="row">
        <div class="col-5">Nummer</div>
        <div class="col-7 fw-bold">Eigentümer</div>
      </div></div>
      <div class="list-group">
        <div class="list-group-item"> <div class="row">
            <div class="col-5">680</div>
            <div class="col-7"> <div>Genossame Schwyz<br>Studenmatt 2<br>6438 Ibach</div> </div>
        </div></div>
        ... more owners ...
      </div>

    Legacy structure (still try as fallback): <table><tr><th>Eigentümer</th><td>...</td></tr></table>

    Herrenlos signals:
      - No list-group-item / Eigentümer cells at all
      - Empty cells
      - "nicht gefunden", "nicht vorhanden", "herrenlos"
    """
    soup = BeautifulSoup(html, "html.parser")
    owner_names: list[str] = []
    addr_parts: list[str] = []

    # ── New layout: list-group-item divs ──────────────────────────────────────
    for item in soup.select(".list-group-item"):
        row = item.find("div", class_="row")
        if not row:
            continue
        cols = row.find_all("div", class_=re.compile(r"\bcol-"))
        if len(cols) < 2:
            continue
        # The owner cell is the LAST col, usually with name<br>street<br>plz city
        owner_div = cols[-1]
        # Capture text with <br>-separated lines
        text = owner_div.get_text(separator="\n", strip=True)
        if not text:
            continue
        lines = [ln.strip() for ln in text.split("\n") if ln.strip()]
        if not lines:
            continue
        name = lines[0]
        if is_herrenlos_owner_text(name):
            continue  # explicit herrenlos signal — skip this row
        owner_names.append(name)
        if len(lines) > 1:
            addr_parts.append(", ".join(lines[1:]))

    # ── Legacy: table-based <th>Eigentümer</th><td>... ────────────────────────
    if not owner_names:
        for th in soup.find_all(["th", "td"]):
            label = th.get_text(strip=True).lower()
            if label in ("eigentümer", "eigentuemer", "eigentümerschaft",
                         "propriétaire", "proprietaire"):
                sibling = th.find_next_sibling("td")
                if sibling:
                    val = sibling.get_text(separator=" ", strip=True)
                    if val and not is_herrenlos_owner_text(val):
                        owner_names.append(val)
                break
        for th in soup.find_all(["th", "td"]):
            label = th.get_text(strip=True).lower()
            if label in ("adresse", "address"):
                sibling = th.find_next_sibling("td")
                if sibling:
                    addr_parts.append(sibling.get_text(separator=", ", strip=True))
                break

    owner = "; ".join(owner_names) if owner_names else None
    addr  = "; ".join(addr_parts) if addr_parts else None

    # "nicht gefunden" / error page
    page_text = soup.get_text(separator=" ", strip=True).lower()
    not_found_signals = ("nicht gefunden", "nicht vorhanden", "no result", "kein ergebnis",
                         "grundstück nicht", "parcel not found")
    if any(sig in page_text for sig in not_found_signals):
        return {"owner": None, "owner_address": None,
                "is_herrenlos": 1,
                "herrenlos_type": "not_in_grundbuch", "claim_possible": 0,
                "raw_response": html, "error": None}

    # ── Success-page validation ───────────────────────────────────────────────
    # A genuine SZ result page ALWAYS renders the parcel header (Grundstück-Nr,
    # Gemeinde, Eigentumsform).  A degraded/broken response — e.g. after a wrong
    # captcha solve that the portal renders without re-prompting — echoes only the
    # E-GRID (taken from the URL) plus "Keine Eigentümer erfasst", omitting those
    # header fields.  Such a page is a FAILED lookup, not a parcel without an owner.
    # Without this guard it is misclassified as herrenlos/dereliktion (e.g. parcel
    # 426 / CH344022798511, which actually has an owner).  Treat it as a retryable
    # failure instead.
    if owner is None:
        has_header = ("grundstück-nr" in page_text
                      and "gemeinde" in page_text
                      and "eigentumsform" in page_text)
        if not has_header:
            log.warning("Invalid/degraded SZ result page (no parcel header) for "
                        "EGRID=%s — treating as retryable failure, NOT herrenlos", egrid)
            return {"owner": None, "owner_address": None, "is_herrenlos": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "raw_response": None, "error": "invalid_page"}
        log.info("No owner found in valid result page (EGRID=%s) — potential herrenlos", egrid)

    return {
        "owner":          owner,
        "owner_address":  addr or None,
        "is_herrenlos":   0 if owner else 1,
        "herrenlos_type": None if owner else "dereliktion",
        "claim_possible": None if owner else claim_possible_for("SZ", "dereliktion"),
        "raw_response":   html if owner is None else None,
        "error":          None,
    }


# ── Main scanner ──────────────────────────────────────────────────────────────

def scan(limit: int | None = None,
         skip_existing: bool = True,
         delay: float = 1.5,
         max_captcha_retries: int = 3):
    """
    Scan SZ parcels for herrenlos detection.

    First run: ~3 min WFS enumeration via geodienste.ch (wfs_enum.py).
    Subsequent runs: use cached list directly.

    limit               : stop after N owner queries (None = all)
    skip_existing       : skip parcels already in DB
    delay               : seconds between requests
    max_captcha_retries : retry captcha-wrong errors N times before giving up
    """
    init_db()

    # SZ has ~50k parcels in 29 communes (verified by WFS).  The swisstopo 200m grid scan only
    # captured 6,372 (35% of canton). WFS finds all of them in ~30s.
    with get_conn() as conn:
        cached = enum_cached(conn, "SZ")
    if cached and len(cached) >= 20_000:
        log.info("Using cached SZ parcel list (%d parcels)", len(cached))
        parcels = cached
    else:
        if cached:
            log.info("SZ cache incomplete (%d parcels) — re-enumerating via WFS", len(cached))
            with get_conn() as conn:
                conn.execute("DELETE FROM enum.parcel_enum WHERE canton='SZ'")  # MED-7: must qualify with 'enum.' schema
                conn.commit()
        log.info("Enumerating SZ parcels via geodienste WFS (~30s) …")
        parcels = wfs_enumerate_canton("SZ")
        with get_conn() as conn:
            store_enum(conn, "SZ", parcels)
        log.info("Cached %d SZ parcels (WFS)", len(parcels))

    if limit:
        parcels = parcels[:limit]

    session = requests.Session()
    session.headers.update({
        "User-Agent": DEFAULT_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "de-CH,de;q=0.9",
    })

    scanned = errors = herrenlos = captcha_fails = 0

    with get_conn() as conn:
        for p in parcels:
            egrid   = p.get("egrid", "")
            bfs     = p["bfs_nr"]
            nr      = p["parcel_nr"]
            commune = p.get("commune", "")

            if skip_existing and already_scanned(conn, "SZ", bfs, nr):
                continue

            result = None
            for attempt in range(1, max_captcha_retries + 1):
                result = check_owner(session, egrid)
                if result.get("error") not in ("captcha_wrong", "captcha_unsolved", "invalid_page"):
                    break
                log.debug("Captcha attempt %d/%d failed for EGRID=%s",
                          attempt, max_captcha_retries, egrid)
                time.sleep(1)

            if result.get("error") in ("captcha_wrong", "captcha_unsolved", "invalid_page"):
                captcha_fails += 1
                # Store as error, don't skip — will be retried next run
                result = {"owner": None, "owner_address": None,
                          "is_herrenlos": None,
                          "herrenlos_type": None, "claim_possible": None,
                          "raw_response": None,
                          "error": result.get("error")}

            upsert_parcel(conn, {
                "egrid":       egrid,
                "canton":      "SZ",
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
            if result.get("error") and result["error"] not in ("captcha_wrong", "captcha_unsolved", "invalid_page"):
                errors += 1

            if scanned % 50 == 0:
                log.info("Progress %d  herrenlos=%d  errors=%d  captcha_fails=%d",
                         scanned, herrenlos, errors, captcha_fails)

            time.sleep(delay)

    log.info("SZ scan done — scanned=%d  herrenlos=%d  errors=%d  captcha_fails=%d",
             scanned, herrenlos, errors, captcha_fails)
    return {"scanned": scanned, "herrenlos": herrenlos, "errors": errors,
            "captcha_fails": captcha_fails}
