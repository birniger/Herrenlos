"""
UR scanner — Uri
================
- EGRID enumeration : WFS  geo.ur.ch/webmercator/wfs  (~20,339 parcels)
- Owner lookup      : GET  geo.ur.ch/grundbuchauskunft/?gem={bfs}&nr={nr}
- Herrenlos signal  : response ≤ 500 B  OR  contains "existiert nicht"
- Rate limit        : ~30 req/day per IP  (X-RateLimit-Remaining header)
"""

import time
import logging
import requests
from bs4 import BeautifulSoup

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from db import get_conn, init_db, already_scanned, upsert_parcel
from scanners.utils import is_herrenlos_owner_text, is_unknown_owner, is_public_owner, is_sdr_parcel, annotate_herrenlos

log = logging.getLogger("UR")

WFS_URL   = "https://geo.ur.ch/webmercator/wfs"
OWNER_URL = "https://geo.ur.ch/grundbuchauskunft/"
LAYERS    = [
    "av:ch059_liegenschaften_flaechen",
    "av:ch059_liegenschaften_selbstrechte",
]
WFS_PAGE = 500
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"

HERRENLOS_NEEDLE  = "existiert nicht"
HERRENLOS_MAX_B   = 500   # bytes; valid response is ~5 KB


# ── Enumeration ─────────────────────────────────────────────────────────────

def fetch_all_parcels() -> list[dict]:
    """Return all UR parcels as a list of WFS property dicts."""
    parcels = []
    for layer in LAYERS:
        offset = 0
        while True:
            try:
                r = requests.get(WFS_URL, params={
                    "version": "1.0.0", "request": "GetFeature",
                    "typeName": layer, "outputFormat": "JSON",
                    "maxFeatures": WFS_PAGE, "startIndex": offset,
                }, timeout=30)
                r.raise_for_status()
                features = r.json().get("features", [])
                parcels.extend(f["properties"] for f in features)
                log.info("WFS %s  offset=%d  total=%d", layer.split(":")[-1], offset, len(parcels))
                if len(features) < WFS_PAGE:
                    break
                offset += WFS_PAGE
                time.sleep(0.3)
            except Exception as exc:
                log.error("WFS error at offset %d: %s — retrying in 10s", offset, exc)
                time.sleep(10)
    return parcels


# ── Owner check ─────────────────────────────────────────────────────────────

def check_owner(session: requests.Session, bfs_nr: str, parcel_nr: str) -> dict:
    """
    Query owner for one parcel.
    Returns a dict ready for upsert_parcel (owner, is_herrenlos, …).
    On rate-limit returns {"error": "rate_limited:<seconds>"}.
    """
    try:
        r = session.get(OWNER_URL, params={"gem": bfs_nr, "nr": parcel_nr}, timeout=15)

        if r.status_code == 429:
            # UR returns a math CAPTCHA challenge after ~5 requests/day.
            # Try to solve it automatically, then retry.
            if "captcha_math" in r.text or "reset-by-captcha" in r.text:
                log.info("Math CAPTCHA triggered — attempting OCR solve …")
                from scanners.ur_captcha import solve_captcha_from_session
                solved = solve_captcha_from_session(session, bfs_nr, parcel_nr)
                if solved:
                    r = session.get(OWNER_URL, params={"gem": bfs_nr, "nr": parcel_nr}, timeout=15)
                    if r.status_code == 200:
                        # Fall through to normal parsing below
                        raw  = r.text
                        size = len(raw.encode())
                        if HERRENLOS_NEEDLE in raw or size < HERRENLOS_MAX_B:
                            return {"owner": None, "owner_address": None,
                                    "is_herrenlos": 1, "raw_response": raw[:300], "error": None}
                        # Continue to owner parsing by re-entering logic
                        return check_owner(session, bfs_nr, parcel_nr)
            retry = int(float(r.headers.get("retry-after", r.headers.get("x-ratelimit-reset", "3600"))))
            return {"error": f"rate_limited:{retry}", "is_herrenlos": None,
                    "owner": None, "owner_address": None, "raw_response": None}

        raw   = r.text
        size  = len(raw.encode())

        # ── Geo-IP block detection ───────────────────────────────────────────
        # geo.ur.ch denies access from non-Swiss IPs (e.g. GitHub Actions).
        # Do NOT classify these as herrenlos — store as retriable error.
        if "access to this page is denied for your country" in raw \
                or "security reasons" in raw.lower() and "denied" in raw.lower():
            log.warning("Geo-IP block from geo.ur.ch — bfs=%s nr=%s. "
                        "Run from a Swiss IP or add UR to proxy pool.", bfs_nr, parcel_nr)
            return {"owner": None, "owner_address": None,
                    "is_herrenlos": None, "herrenlos_type": None,
                    "claim_possible": None,
                    "raw_response": raw[:200], "error": "geo_blocked"}

        # ── Herrenlos detection ──────────────────────────────────────────────
        if HERRENLOS_NEEDLE in raw or size < HERRENLOS_MAX_B:
            # "existiert nicht" = parcel not in Grundbuch at all (Art. 664 Type B)
            # Tiny response without that needle = Grundbuch entry exists, owner absent (Type A)
            h_type = "not_in_grundbuch" if HERRENLOS_NEEDLE in raw else "dereliktion"
            from scanners.utils import claim_possible_for
            return {
                "owner": None, "owner_address": None,
                "is_herrenlos": 1,
                "herrenlos_type": h_type,
                "claim_possible": claim_possible_for("UR", h_type),
                "raw_response": raw[:300],
                "error": None,
            }

        # ── Parse owner name + members ───────────────────────────────────────
        # The UR grundbuchauskunft HTML uses p.eigentum for owner and
        # p.mitglied for co-owner shares.  We try multiple selectors robustly.
        soup    = BeautifulSoup(raw, "lxml")
        SKIP    = {"laut grundbuch", "eigentümer", "eigentum", "eigentuemer", ""}

        def _texts(selector: str) -> list[str]:
            out = []
            for el in soup.select(selector):
                t = el.get_text(" ", strip=True).strip()
                if not t or t.lower() in SKIP:
                    continue
                out.append(t)
            return out

        # Priority order of known selector patterns
        owner_candidates = (
            _texts("p.eigentum")
            or _texts(".eigentum")
            or _texts("td.eigentum")
            or _texts("[class*='eigentum']")
        )

        # Filter owner candidates:
        #  - herrenlos text  → True dereliktion (owner field shows "herrenlos" etc.)
        #  - unknown owner   → BGE 114 II 318: NOT herrenlos; owner exists but unknown
        #  - public body     → Kanton/Gemeinde/Bund; already owned, not herrenlos
        real_owners: list[str] = []
        has_unknown = False
        for t in owner_candidates:
            if is_herrenlos_owner_text(t):
                pass  # signals herrenlos — will be caught by explicit_herrenlos below
            elif is_unknown_owner(t):
                has_unknown = True
                real_owners.append(t)   # treat as having an owner (BGE 114 II 318)
            else:
                real_owners.append(t)

        explicit_herrenlos = len(owner_candidates) > 0 and len(real_owners) == 0

        owner = "; ".join(real_owners) if real_owners else None

        members = _texts("p.mitglied") or _texts(".mitglied")

        # Full-size response with no owner = Type 1 herrenlos (dereliktion):
        # either the owner field is blank, or it explicitly says "herrenlos" /
        # "sans propriétaire" / equivalent.
        if owner is None and size > 1000:
            reason = "explicit herrenlos text in owner field" if explicit_herrenlos \
                     else "no owner found in Grundbuch entry"
            log.info("Potential Type 1 herrenlos — %s (size=%d). "
                     "raw_response saved.", reason, size)

        h_type = None if owner else "dereliktion"
        from scanners.utils import claim_possible_for
        return {
            "owner":          owner,
            "owner_address":  "; ".join(members) or None,
            "is_herrenlos":   0 if owner else 1,
            "herrenlos_type": h_type,
            "claim_possible": claim_possible_for("UR", h_type) if h_type else None,
            "raw_response":   raw[:400] if owner is None else None,
            "error":          None,
        }

    except Exception as exc:
        return {"owner": None, "owner_address": None,
                "is_herrenlos": None, "raw_response": None, "error": str(exc)}


# ── Main scanner ─────────────────────────────────────────────────────────────

def scan(limit: int | None = None, skip_existing: bool = True, delay: float = 2.0):
    """
    Scan all UR parcels for herrenlos detection.

    limit         : stop after N parcels (None = all ~20k)
    skip_existing : skip parcels already in DB
    delay         : seconds between requests  (2s ≈ 30/min, safe under daily cap)
    """
    init_db()

    log.info("Fetching UR parcel list from WFS …")
    parcels = fetch_all_parcels()
    log.info("WFS returned %d parcels total", len(parcels))

    if limit:
        parcels = parcels[:limit]

    session = requests.Session()
    session.headers["User-Agent"] = UA

    scanned = errors = herrenlos = 0
    rate_wait_until = 0.0

    with get_conn() as conn:
        for p in parcels:
            bfs      = str(p.get("bfsnr", ""))
            nr       = str(p.get("nummer", ""))
            obj_type = str(p.get("objektart", "Liegenschaft"))

            # BGE 118 II 115: SDR/Baurecht cannot be derelicted — skip
            if is_sdr_parcel(obj_type):
                continue

            if skip_existing and already_scanned(conn, "UR", bfs, nr):
                continue

            # ── Respect rate limit ───────────────────────────────────────────
            now = time.time()
            if now < rate_wait_until:
                wait = rate_wait_until - now
                log.warning("Rate-limited — sleeping %.0fs", wait)
                time.sleep(wait + 5)

            result = check_owner(session, bfs, nr)
            annotate_herrenlos(result, "UR")

            # Retry once after rate-limit sleep
            if isinstance(result.get("error"), str) and result["error"].startswith("rate_limited:"):
                secs = int(result["error"].split(":")[1])
                rate_wait_until = time.time() + secs
                log.warning("429 received — sleeping %ds then retrying", secs)
                time.sleep(secs + 5)
                result = check_owner(session, bfs, nr)
                annotate_herrenlos(result, "UR")

            upsert_parcel(conn, {
                "egrid":        p.get("egris_egrid"),
                "canton":       "UR",
                "commune":      p.get("gemeinde"),
                "bfs_nr":       bfs,
                "parcel_nr":    nr,
                "parcel_type":  p.get("objektart", "Liegenschaft"),
                **result,
            })

            scanned += 1
            if result.get("is_herrenlos") == 1:
                herrenlos += 1
                log.info("HERRENLOS  %s Nr.%-6s  EGRID=%s",
                         p.get("gemeinde", "?"), nr, p.get("egris_egrid", "?"))
            if result.get("error") and not str(result["error"]).startswith("rate_limited"):
                errors += 1

            if scanned % 50 == 0:
                log.info("Progress %d/%d  herrenlos=%d  errors=%d",
                         scanned, len(parcels), herrenlos, errors)

            time.sleep(delay)

    log.info("UR scan done — scanned=%d  herrenlos=%d  errors=%d", scanned, herrenlos, errors)
    return {"scanned": scanned, "herrenlos": herrenlos, "errors": errors}
