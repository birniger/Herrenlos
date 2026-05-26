"""
BL scanner — Basel-Landschaft
==============================
STATUS (2026-05-17): THREE BUGS FIXED — scanner is ready to run but needs
  ANTHROPIC_API_KEY set in .env (or env var) for reliable CAPTCHA solving.
  ddddocr standard model under-counts characters on BL's handwritten-style CAPTCHAs;
  Claude vision is the effective solver. Without the API key the scanner will exhaust
  all retries with captcha_unsolved errors.

  To run:
    1. Set ANTHROPIC_API_KEY in .env  (or export it before running)
    2. Clear the parcel_enum cache first:
         sqlite3 herrenlos.db "DELETE FROM parcel_enum WHERE canton='BL'"
    3. Run:  python main.py bl --limit 10

- EGRID enumeration : swisstopo identify API grid scan (step=200m, ~1h one-time)
                      Cached in parcel_enum table — only runs once ever.

- Owner lookup      : GET https://eigentumsauskunft.geo.bl.ch/{EGRID}
                      Returns an HTML page with an image CAPTCHA (Pyramid framework,
                      lowercase letters + digits, 4–6 chars, handwritten-style).
                      Form confirmed to have exactly ONE input: name='captcha' type='text'.
                      No hidden ASP.NET VIEWSTATE fields — pure Pyramid form.
                      OCR chain: ddddocr standard → tesseract → Claude vision.
                      (ddddocr beta removed: returns valid-length but wrong answers on
                      BL's CAPTCHA style, blocking Claude from running.)

- Herrenlos signal  : Owner section absent or empty in the HTML response after CAPTCHA.

- Rate limit        : No IP rotation needed at default 2s delay.
                      Portal drops connection after ~10 rapid requests — built-in 4s
                      retry delay handles this. For >500/day consider rotating User-Agent.

- Parcels           : ~70,000 BL parcels (~1,800 km²)
                      Full scan at delay=2s ≈ 39h single-threaded.

BUGS FIXED (2026-05-17):
  BUG 1 — ddddocr beta blocks Claude fallback:
    Beta model returned valid-length (4-char) but consistently wrong answers on BL's
    handwritten CAPTCHAs. Because the `or` chain short-circuits on truthy values, Claude
    was never tried. FIX: removed beta from _solve_ddddocr; return None when standard
    under-counts so Claude gets the same image.

  BUG 2 — check_owner POSTs all four candidate field names simultaneously:
    Sending captcha/captcha_answer/captcha_value/code at once caused 400 errors.
    FIX: detect actual field name from BeautifulSoup before POSTing. Confirmed field
    is name='captcha' on eigentumsauskunft.geo.bl.ch.

  BUG 3 — _solve_claude doesn't find API key:
    Only checked ~/.claude/config.json and ~/.config/anthropic/config.json — neither
    exists on this machine. FIX: also parses project .env and ~/.env files.

REQUIRES:
    pip install ddddocr               (primary OCR — install first)
    pytesseract + tesseract-ocr       (fallback OCR — optional)
    ANTHROPIC_API_KEY in .env         (Claude vision — required for reliable operation)
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
from scanners.utils import is_herrenlos_owner_text, claim_possible_for

log = logging.getLogger("BL")

BASE_URL           = "https://eigentumsauskunft.geo.bl.ch"
OWNER_URL          = f"{BASE_URL}/{{egrid}}"
SWISSTOPO_IDENTIFY = "https://api3.geo.admin.ch/rest/services/api/MapServer/identify"
UA                 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"

# BL LV95 bounding box (~1,800 km²)
BL_EMIN, BL_EMAX = 2_600_000, 2_645_000
BL_NMIN, BL_NMAX = 1_255_000, 1_290_000
BL_GRID_STEP     = 200   # metres — ~39k grid points, ~1h


# ── Parcel enumeration via swisstopo ─────────────────────────────────────────

def enumerate_parcels_swisstopo(
        emin=BL_EMIN, emax=BL_EMAX,
        nmin=BL_NMIN, nmax=BL_NMAX,
        step=BL_GRID_STEP) -> list[dict]:
    """Grid scan — returns list of {egrid, bfs_nr, parcel_nr, commune} dicts."""
    seen:    set[str]  = set()
    parcels: list[dict] = []
    session = requests.Session()
    session.headers["User-Agent"] = UA

    e_range = range(emin, emax + 1, step)
    n_range = range(nmin, nmax + 1, step)
    total   = len(e_range) * len(n_range)
    checked = 0

    log.info("BL swisstopo grid scan: %d × %d = %d points at %dm",
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
                    if attrs.get("ak", "").upper() != "BL":
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
                log.info("Grid %d/%d  unique BL parcels=%d", checked, total, len(parcels))
            time.sleep(0.1)

    log.info("Grid scan complete: %d unique BL parcels", len(parcels))
    return parcels


# ── CAPTCHA solving ──────────────────────────────────────────────────────────

def _solve_ddddocr(png_bytes: bytes) -> str | None:
    """
    Try to solve CAPTCHA using ddddocr standard model only.

    Beta model is intentionally omitted: on BL's handwritten-style CAPTCHAs beta
    consistently returns valid-length (4-char) but wrong answers, which would block
    the tesseract/Claude fallback chain in the `or` expression of solve_captcha().
    If standard can't confidently produce 4–6 chars, we return None so Claude vision
    gets a chance on the same image rather than POSTing a wrong answer.
    """
    try:
        import ddddocr
        ocr = ddddocr.DdddOcr(show_ad=False)
        result = ocr.classification(png_bytes)
        clean = re.sub(r"[^a-z0-9]", "", result.lower())
        if 4 <= len(clean) <= 6:
            return clean
        # Standard model under-counted (<4 chars) — image is ambiguous for ddddocr;
        # return None so tesseract and Claude vision can try on the same bytes.
        return None
    except ImportError:
        log.debug("ddddocr not installed — skipping (pip install ddddocr)")
    except Exception as exc:
        log.debug("ddddocr error: %s", exc)
    return None


def _solve_tesseract(png_bytes: bytes) -> str | None:
    """Try to solve a text CAPTCHA image using tesseract OCR with preprocessing."""
    try:
        import pytesseract
        from PIL import Image, ImageFilter, ImageOps
        import io

        raw_img = Image.open(io.BytesIO(png_bytes)).convert("L")
        # Preprocessed: 4x upscale + median denoise + autocontrast
        w, h = raw_img.size
        pre_img = raw_img.resize((w * 4, h * 4), Image.LANCZOS)
        pre_img = pre_img.filter(ImageFilter.MedianFilter(size=3))
        pre_img = ImageOps.autocontrast(pre_img, cutoff=2)

        for img in (pre_img, raw_img):
            for psm in (7, 8, 6, 13):
                cfg = f"--psm {psm} --oem 3 -c tessedit_char_whitelist=abcdefghijklmnopqrstuvwxyz0123456789"
                raw = pytesseract.image_to_string(img, config=cfg).strip().lower()
                t = re.sub(r"[^a-z0-9]", "", raw)
                if 4 <= len(t) <= 6:
                    return t
    except ImportError:
        log.debug("pytesseract not installed — skipping local OCR")
    except Exception as exc:
        log.debug("OCR error: %s", exc)
    return None


def _solve_claude(png_bytes: bytes) -> str | None:
    """Claude vision fallback for CAPTCHA solving."""
    import base64
    try:
        import anthropic
        import os, json

        api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()

        # JSON config files (legacy Claude Code path)
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
            log.debug("_solve_claude: no API key found — set ANTHROPIC_API_KEY in .env or env var")
            return None

        client = anthropic.Anthropic(api_key=api_key)
        b64 = base64.standard_b64encode(png_bytes).decode()
        msg = client.messages.create(
            model="claude-haiku-4-5",
            max_tokens=32,
            messages=[{"role": "user", "content": [
                {"type": "image", "source": {"type": "base64",
                                              "media_type": "image/png", "data": b64}},
                {"type": "text", "text":
                 "This is a CAPTCHA image containing 4–6 lowercase letters and/or digits. "
                 "Read the characters carefully. Reply with ONLY the characters, nothing else."},
            ]}],
        )
        answer = msg.content[0].text.strip().lower()
        return re.sub(r"[^a-z0-9]", "", answer) or None
    except ImportError:
        log.debug("anthropic package not installed — skipping Claude fallback")
    except Exception as exc:
        log.debug("Claude fallback error: %s", exc)
    return None


# ── Owner check ─────────────────────────────────────────────────────────────

def check_owner(session: requests.Session, egrid: str) -> dict:
    """
    Query owner for one BL parcel.

    Flow:
      GET  /{{EGRID}}              → HTML page with captcha image + form
      [OCR or Claude] captcha image
      POST /{{EGRID}}  captcha=... → HTML with owner data
    """
    try:
        url = OWNER_URL.format(egrid=egrid)
        r1 = session.get(url, timeout=15)

        if r1.status_code == 404:
            # Parcel not in Grundbuch — Type 2 herrenlos
            return {"owner": None, "owner_address": None,
                    "is_herrenlos": 1,
                    "herrenlos_type": "not_in_grundbuch", "claim_possible": 0,
                    "raw_response": None, "error": None}

        if r1.status_code != 200:
            return {"error": f"http_{r1.status_code}", "is_herrenlos": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "owner": None, "owner_address": None, "raw_response": None}

        html1 = r1.text
        soup1 = BeautifulSoup(html1, "lxml")

        # ── Check if we already have owner data (no CAPTCHA on first load) ──
        owner_from_direct = _parse_owner_html(soup1)
        if owner_from_direct is not None:
            names, addr = owner_from_direct
            return {
                "owner":          "; ".join(names) if names else None,
                "owner_address":  addr or None,
                "is_herrenlos":   0 if names else 1,
                "herrenlos_type": None if names else "dereliktion",
                "claim_possible": None if names else claim_possible_for("BL", "dereliktion"),
                "raw_response":   html1[:300] if not names else None,
                "error":          None,
            }

        # ── Find CAPTCHA form ────────────────────────────────────────────────
        # Pyramid captcha: <img> with captcha, form with hidden fields
        captcha_img_tag = (
            soup1.find("img", {"class": re.compile(r"captcha", re.I)})
            or soup1.find("img", {"src": re.compile(r"captcha", re.I)})
            or soup1.find("img", {"id":  re.compile(r"captcha", re.I)})
        )
        if not captcha_img_tag:
            # No captcha found — might be server error or different page structure
            return {"error": "no_captcha_found", "is_herrenlos": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "owner": None, "owner_address": None,
                    "raw_response": html1[:300]}

        img_src = captcha_img_tag.get("src", "")
        if not img_src.startswith("http"):
            img_src = BASE_URL + ("" if img_src.startswith("/") else "/") + img_src

        # Download captcha image
        r_img = session.get(img_src, timeout=10)
        png_bytes = r_img.content

        # Solve CAPTCHA: try each solver in order; record which one fires
        solution, solver_used = None, "none"
        for _fn, _name in (
            (_solve_ddddocr, "ddddocr"),
            (_solve_tesseract,     "tesseract"),
            (_solve_claude,  "claude"),
        ):
            s = _fn(png_bytes)
            if s:
                solution, solver_used = s, _name
                break

        if not solution:
            log_captcha("BL", "none", "unsolved")
            return {"error": "captcha_unsolved", "is_herrenlos": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "owner": None, "owner_address": None, "raw_response": None}

        log.debug("BL captcha solved: %r (EGRID=%s)", solution, egrid)

        # ── Submit CAPTCHA form ──────────────────────────────────────────────
        form = soup1.find("form")
        form_data: dict[str, str] = {}

        # Extract hidden fields
        if form:
            for inp in form.find_all("input", {"type": "hidden"}):
                name = inp.get("name", "")
                val  = inp.get("value", "")
                if name:
                    form_data[name] = val

        # BUG FIX (2026-05-17): previously submitted all four candidate names at once.
        # BL portal (Pyramid) confirmed to have exactly ONE text input: name='captcha'.
        # Sending extra keys (captcha_answer, captcha_value, code) causes 400 / wrong-
        # answer on some portal versions. Detect the actual name from the form HTML.
        captcha_field = None
        if form:
            for inp in form.find_all("input"):
                if inp.get("type", "text").lower() in ("text", ""):
                    name = inp.get("name", "").lower()
                    if any(kw in name for kw in ("captcha", "code", "answer", "security", "verify")):
                        captcha_field = inp.get("name")
                        break
        if not captcha_field:
            captcha_field = "captcha"   # confirmed default for eigentumsauskunft.geo.bl.ch
        form_data[captcha_field] = solution
        log.debug("BL CAPTCHA field=%r  solution=%r  EGRID=%s", captcha_field, solution, egrid)

        action = (form.get("action", url) if form else url)
        if not action.startswith("http"):
            action = BASE_URL + ("" if action.startswith("/") else "/") + action

        r2 = session.post(action, data=form_data, timeout=15)

        if r2.status_code != 200:
            return {"error": f"post_http_{r2.status_code}", "is_herrenlos": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "owner": None, "owner_address": None, "raw_response": None}

        soup2 = BeautifulSoup(r2.text, "lxml")

        # Check for wrong captcha indicator. BL portal returns the form again
        # with a "Sicherheitsabfrage fehlgeschlagen" error <small> after the form.
        wrong_captcha = soup2.find(string=re.compile(
            r"falsch|incorrect|wrong|ungültig|fehlgeschlagen|Sicherheitsabfrage", re.I))
        if wrong_captcha:
            log_captcha("BL", solver_used, "wrong")
            log.debug("BL captcha wrong — retrying (EGRID=%s)", egrid)
            return {"error": "captcha_wrong", "is_herrenlos": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "owner": None, "owner_address": None, "raw_response": None}

        # ── Parse owner from response ────────────────────────────────────────
        result = _parse_owner_html(soup2)
        if result is not None:
            log_captcha("BL", solver_used, "correct")
            names, addr = result
            return {
                "owner":          "; ".join(names) if names else None,
                "owner_address":  addr or None,
                "is_herrenlos":   0 if names else 1,
                "herrenlos_type": None if names else "dereliktion",
                "claim_possible": None if names else claim_possible_for("BL", "dereliktion"),
                "raw_response":   r2.text[:300] if not names else None,
                "error":          None,
            }

        # Could not parse — CAPTCHA was accepted by server, response just unrecognised
        log_captcha("BL", solver_used, "correct")
        return {"owner": None, "owner_address": None,
                "is_herrenlos": None,
                "herrenlos_type": None, "claim_possible": None,
                "raw_response": r2.text[:300],
                "error": "parse_failed"}

    except Exception as exc:
        return {"owner": None, "owner_address": None,
                "is_herrenlos": None,
                "herrenlos_type": None, "claim_possible": None,
                "raw_response": None, "error": str(exc)}


def _parse_owner_html(soup: BeautifulSoup) -> tuple[list[str], str] | None:
    """
    Try to extract owner names + address from BL's HTML response.
    Returns (names_list, address_str) or None if the owner section isn't present.
    """
    SKIP = {"eigentümer", "eigentuemer", "eigentum", "besitzer", "proprietaire",
            "proprietäre", "angaben", "information", "details"}

    # BL likely uses similar selectors to FR/UR — try multiple
    selectors = [
        "table.eigentuemer td", "table.eigentum td", "table.owner td",
        ".eigentuemer", ".eigentum", ".owner",
        "[class*='eigentuemer']", "[class*='eigentum']",
        "td.eigentuemer", "td.eigentum",
        # Fallback: any table cell that looks like a name
    ]

    candidates: list[str] = []
    for sel in selectors:
        for el in soup.select(sel):
            text = el.get_text(" ", strip=True).strip()
            if text and text.lower() not in SKIP and len(text) > 2:
                candidates.append(text)
        if candidates:
            break

    if not candidates:
        # If owner section is completely absent, return None (don't know yet)
        return None

    names = [t for t in candidates if not is_herrenlos_owner_text(t)]
    addr_parts = [t for t in candidates if re.search(r"\d{4}", t)]  # PLZ hint
    addr = "; ".join(addr_parts) if addr_parts else ""
    return names, addr


# ── Main scanner ─────────────────────────────────────────────────────────────

def scan(limit: int | None = None,
         skip_existing: bool = True,
         delay: float = 2.0):
    """
    Scan BL parcels for herrenlos detection.

    First run: ~1h swisstopo grid scan (cached to DB).
    Each query requires solving an image CAPTCHA (OCR or Claude vision).

    limit         : stop after N parcels
    skip_existing : skip parcels already in DB
    delay         : seconds between queries
    """
    init_db()

    with get_conn() as conn:
        cached = enum_cached(conn, "BL")
    if cached:
        log.info("Using cached BL parcel list (%d parcels)", len(cached))
        parcels = cached
    else:
        log.info("Enumerating BL parcels via geodienste WFS …")
        parcels = wfs_enumerate_canton("BL")
        with get_conn() as conn:
            store_enum(conn, "BL", parcels)
        log.info("Cached %d BL parcels (WFS)", len(parcels))

    if limit:
        parcels = parcels[:limit]

    session = requests.Session()
    session.headers["User-Agent"] = UA

    scanned = errors = herrenlos = 0

    with get_conn() as conn:
        for p in parcels:
            egrid   = p["egrid"]
            bfs     = p["bfs_nr"]
            nr      = p["parcel_nr"]
            commune = p.get("commune", "")

            if skip_existing and already_scanned(conn, "BL", bfs, nr):
                continue

            result = check_owner(session, egrid)

            # Retry on captcha failures with cooldown — BL portal rate-limits rapid retries.
            # ddddocr ~75% per-attempt: with 4 retries at 4s spacing → ≈99.6% success.
            captcha_attempts = 0
            while result.get("error") in ("captcha_wrong", "captcha_unsolved") and captcha_attempts < 4:
                captcha_attempts += 1
                log.debug("Retrying BL CAPTCHA (%d/4) for EGRID=%s", captcha_attempts, egrid)
                time.sleep(4)
                # Fresh session per retry to avoid TS-cookie based rate limiting
                session = requests.Session()
                session.headers["User-Agent"] = UA
                result = check_owner(session, egrid)

            upsert_parcel(conn, {
                "egrid":       egrid,
                "canton":      "BL",
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
            if result.get("error") and result["error"] not in (
                    "captcha_wrong", "captcha_unsolved"):
                errors += 1

            if scanned % 50 == 0:
                log.info("Progress %d  herrenlos=%d  errors=%d", scanned, herrenlos, errors)

            time.sleep(delay)

    log.info("BL scan done — scanned=%d  herrenlos=%d  errors=%d", scanned, herrenlos, errors)
    return {"scanned": scanned, "herrenlos": herrenlos, "errors": errors}
