"""
UR math CAPTCHA solver
======================
After ~14 requests/day the UR grundbuchauskunft endpoint returns HTTP 429
with an SVG math CAPTCHA:
  GET  /grundbuchauskunft/captcha_math.jpg   → SVG image of a math equation
  POST /grundbuchauskunft/reset-by-captcha?gem={bfs}&nr={nr}
       body: captcha=<answer>

Two-tier solver:
  1. Local OCR  : SVG → PNG (cairosvg) → HSV masking → pytesseract
                  Fast, free.  Works ~30% of the time.
  2. Claude API : send PNG to claude-haiku-4-5 vision  (< $0.001/call)
                  Reliable fallback.  Used when OCR returns None.

Total cost for all ~1,430 CAPTCHAs in a full 20k UR scan: ~$1.40 worst-case.

REQUIRES (install once):
    pip install cairosvg pillow pytesseract anthropic
    brew install tesseract          # macOS
    # OR: apt-get install tesseract-ocr
    export ANTHROPIC_API_KEY=sk-...
"""

import re
import io
import base64
import logging

log = logging.getLogger("UR.captcha")


def _svg_to_png_bytes(svg_bytes: bytes) -> bytes:
    """Rasterize SVG to PNG bytes using cairosvg."""
    import cairosvg
    return cairosvg.svg2png(bytestring=svg_bytes, scale=2)


def _ocr_png(png_bytes: bytes) -> str:
    """
    Preprocess and OCR the UR math CAPTCHA PNG.

    The CAPTCHA has:
    - Pastel salmon background (low saturation)
    - Colorful characters (high saturation: brown, teal, purple)
    - A decorative curve through the image

    Strategy: isolate characters using HSV saturation channel,
    then threshold to black-on-white before OCR.
    """
    from PIL import Image
    import pytesseract
    import numpy as np

    img = Image.open(io.BytesIO(png_bytes)).convert("RGB")

    # Convert to HSV and extract saturation channel
    arr = np.array(img).astype(np.float32) / 255.0
    r, g, b = arr[:,:,0], arr[:,:,1], arr[:,:,2]
    cmax = np.maximum(np.maximum(r, g), b)
    cmin = np.minimum(np.minimum(r, g), b)
    saturation = np.where(cmax > 0, (cmax - cmin) / cmax, 0)

    # Characters have saturation > 0.15–0.25 (brown can be lower); background is ~0.10.
    # The decorative curve has moderate saturation — exclude it by also
    # checking that pixel brightness is not too high (curve is light teal/pastel).
    value = cmax  # V channel
    mask = (saturation > 0.15) & (value < 0.90)

    # Convert mask to PIL grayscale: characters=black, background=white
    binary = Image.fromarray(((~mask) * 255).astype(np.uint8), mode="L")

    # Upscale for better OCR
    w, h = binary.size
    binary = binary.resize((w * 3, h * 3), Image.NEAREST)

    binary.save("/tmp/ur_captcha_processed.png")

    # Characters are rendered as hollow outlines (SVG stroked paths).
    # Dilate to fill them, then OCR each strip separately to avoid
    # the decorative arc line interfering.
    from PIL import ImageFilter
    W, H = binary.size
    # Invert: characters become white blobs on black; dilate to fill holes
    inv = Image.fromarray((255 - np.array(binary)).astype(np.uint8), mode="L")
    # Multiple dilations to fill hollow strokes
    for _ in range(4):
        inv = inv.filter(ImageFilter.MaxFilter(3))
    filled = Image.fromarray((255 - np.array(inv)).astype(np.uint8), mode="L")
    filled.save("/tmp/ur_captcha_filled.png")

    # Crop to character zone (exclude arc-heavy top area)
    top_cut    = int(H * 0.28)
    bottom_cut = int(H * 0.90)
    strip_w    = W // 3

    tokens = []
    for i in range(3):
        x0 = max(0, i * strip_w - 25)
        x1 = min(W, (i + 1) * strip_w + 25)
        strip = filled.crop((x0, top_cut, x1, bottom_cut))
        strip.save(f"/tmp/ur_strip_{i}.png")
        best = ""
        for psm in [10, 8, 7]:
            cfg = f"--psm {psm} -c tessedit_char_whitelist=0123456789+-x"
            t = pytesseract.image_to_string(strip, config=cfg).strip()
            t = t.replace(" ", "").replace("\n", "")
            if t:
                best = t
                break
        tokens.append(best)
        log.debug("Strip %d OCR: %r", i, best)

    return " ".join(tokens)


def _solve(equation: str) -> int | None:
    """
    Parse and solve a simple math equation string like:
      "7 + 3 = ?"  or  "12 - 4 = ?"  or  "3 × 5 = ?"
      "2  6"       (operator missing → try all operators, prefer +)

    Returns integer answer or None if parsing fails.
    """
    eq = equation.replace("×", "*").replace("x", "*").replace("X", "*")
    eq = eq.replace("=", "").replace("?", "").strip()
    eq = re.sub(r"[^0-9+\-*/\s]", " ", eq).strip()

    # Try direct evaluation first
    try:
        clean = re.sub(r"\s+", "", eq)
        if re.fullmatch(r"\d+[+\-*/]\d+", clean):
            return int(eval(clean))
    except Exception:
        pass

    # If only digits remain (operator missing), extract numbers and try operators
    nums = re.findall(r"\d+", eq)
    if len(nums) == 2:
        a, b = int(nums[0]), int(nums[1])
        # Try all operators; addition is most common in these CAPTCHAs
        for op, fn in [("+", a + b), ("-", a - b), ("*", a * b)]:
            result = fn
            if 0 <= result <= 99:   # sanity check: result should be small positive
                log.debug("Inferred operator %s: %d %s %d = %d", op, a, op, b, result)
                return result

    return None


def _get_api_key() -> str | None:
    """
    Locate an Anthropic API key from environment or common config files.
    Priority: ANTHROPIC_API_KEY env var → ~/.claude/config.json → ~/.anthropic/credentials
    """
    import os, json, pathlib

    # 1. Standard env var (may be set by Claude Code or user)
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if key:
        return key

    # 2. Claude Code stores the key in its config
    for cfg_path in [
        pathlib.Path.home() / ".claude" / "config.json",
        pathlib.Path.home() / ".config" / "anthropic" / "config.json",
    ]:
        if cfg_path.exists():
            try:
                data = json.loads(cfg_path.read_text())
                key = data.get("apiKey") or data.get("api_key") or ""
                if key:
                    return key
            except Exception:
                pass

    return None


def _solve_with_claude(png_bytes: bytes) -> int | None:
    """
    Send the rasterized CAPTCHA PNG to Claude Haiku vision and ask for the answer.
    Reliable fallback when local OCR fails.  < $0.001 per call.
    Returns integer answer or None on failure.
    """
    try:
        import anthropic

        api_key = _get_api_key()
        if not api_key:
            log.debug("No Anthropic API key found — set ANTHROPIC_API_KEY to enable Claude vision fallback")
            return None

        client = anthropic.Anthropic(api_key=api_key)
        b64 = base64.standard_b64encode(png_bytes).decode()

        message = client.messages.create(
            model="claude-haiku-4-5",
            max_tokens=32,
            messages=[{
                "role": "user",
                "content": [
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": "image/png",
                            "data": b64,
                        },
                    },
                    {
                        "type": "text",
                        "text": (
                            "This image contains a simple arithmetic equation such as "
                            "'7 + 3 = ?' or '12 - 4 = ?'. "
                            "Read the numbers and operator carefully. "
                            "Reply with ONLY the integer answer (no units, no explanation)."
                        ),
                    },
                ],
            }],
        )

        answer_text = message.content[0].text.strip()
        m = re.search(r"-?\d+", answer_text)
        if m:
            result = int(m.group())
            log.debug("Claude vision answer: %d (raw: %r)", result, answer_text)
            return result

    except ImportError:
        log.debug("anthropic package not installed — skipping Claude fallback")
    except Exception as exc:
        log.debug("Claude vision fallback error: %s", exc)

    return None


def solve_captcha_from_session(session, gem: str, nr: str) -> bool:
    """
    Fetch the current math CAPTCHA SVG, OCR it, solve it, POST the answer.
    Returns True if the CAPTCHA was solved and the session is unblocked.

    Falls back gracefully if cairosvg/pytesseract are not installed
    (logs a warning and returns False).
    """
    try:
        import cairosvg  # noqa — check availability
        import pytesseract  # noqa
    except ImportError:
        log.warning(
            "CAPTCHA solver deps missing. Run:\n"
            "  pip install cairosvg pillow pytesseract\n"
            "  brew install tesseract\n"
            "Skipping CAPTCHA — this parcel will be retried next run."
        )
        return False

    captcha_url  = "https://geo.ur.ch/grundbuchauskunft/captcha_math.jpg"
    reset_url    = f"https://geo.ur.ch/grundbuchauskunft/reset-by-captcha?gem={gem}&nr={nr}"
    alt_url      = f"https://geo.ur.ch/grundbuchauskunft/math?gem={gem}&nr={nr}"

    try:
        # Fetch SVG CAPTCHA
        r = session.get(captcha_url, timeout=15,
                        headers={"Referer": f"https://geo.ur.ch/grundbuchauskunft/?gem={gem}&nr={nr}"})
        svg_bytes = r.content

        # Try multiple OCR attempts (ask for a new question if first fails)
        for attempt in range(3):
            if attempt > 0:
                # Request a different question
                session.get(alt_url, timeout=10)
                r = session.get(captcha_url, timeout=15)
                svg_bytes = r.content

            try:
                png = _svg_to_png_bytes(svg_bytes)
            except Exception as exc:
                log.debug("SVG rasterization attempt %d failed: %s", attempt + 1, exc)
                png = None

            answer = None

            # Tier 1: local OCR (fast, free)
            if png is not None:
                try:
                    raw_text = _ocr_png(png)
                    log.debug("CAPTCHA OCR attempt %d: %r", attempt + 1, raw_text)
                    answer = _solve(raw_text)
                except Exception as exc:
                    log.debug("OCR attempt %d failed: %s", attempt + 1, exc)

            # Tier 2: Claude vision fallback (reliable, ~$0.001/call)
            if answer is None and png is not None:
                log.debug("OCR returned no answer — trying Claude vision fallback")
                answer = _solve_with_claude(png)

            if answer is not None:
                # POST answer
                resp = session.post(reset_url, data={"captcha": str(answer)},
                                    headers={"Referer": f"https://geo.ur.ch/grundbuchauskunft/?gem={gem}&nr={nr}"},
                                    timeout=15)
                if resp.status_code == 200 and "errorpage" not in resp.text:
                    log.info("CAPTCHA solved (answer=%d)", answer)
                    return True
                log.debug("CAPTCHA answer %d rejected (status=%d)", answer, resp.status_code)

        log.warning("Failed to solve CAPTCHA after 3 attempts")
        return False

    except Exception as exc:
        log.error("CAPTCHA solving error: %s", exc)
        return False
