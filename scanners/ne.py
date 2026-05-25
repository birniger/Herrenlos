"""
NE scanner — Neuchâtel
=======================
STATUS (2026-05): WORKING — uses Playwright to handle Altcha v3 widget.
  WFS enumeration (sitn.ne.ch WFS) provides EGRIDs + UUIDs.
  Owner lookup uses a persistent headless Chromium browser:
    - navigate to /owner?uuid=<UUID>
    - intercept the POST /owner response (Altcha auto-solves PoW)
    - parse owner HTML from response body
  The requests-based Altcha solver is kept as documentation but is NOT used
  (Altcha v3 PBKDF2/SHA-256 payload format differs from what the server expects).

- EGRID enumeration : WFS GetFeature on sitn.ne.ch layer "ms:parcelles"
                      Returns egrid + url_terris_v2 (contains owner UUID).
                      Paginated, ~86k parcels (verified). Cached in enum.parcel_enum.
- Owner lookup      : Playwright navigates to /owner?uuid={UUID}
                      Altcha widget auto-solves PoW (PBKDF2/SHA-256)
                      POST /owner response intercepted → parsed for owner
- Rate limit        : ~50 queries/day per IP (anonymous). Altcha CPU ~3-30s/query.
- Herrenlos signal  : Empty "Propriétaire" cell, "sans propriétaire", or 404
- Parcels           : ~50,000
- Note              : NE is NOT in the federal swisstopo cadastral layer —
                      EGRIDs must be enumerated from sitn.ne.ch WFS directly.

REQUIRES:
    pip install playwright
    playwright install chromium
"""

import re
import json
import base64
import hashlib
import time
import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlencode

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from db import get_conn, init_db, already_scanned, upsert_parcel, enum_cached, store_enum
from scanners.utils import is_herrenlos_owner_text, claim_possible_for, load_proxies

log = logging.getLogger("NE")

BASE_URL     = "https://sitn.ne.ch"
OWNER_URL    = f"{BASE_URL}/owner"
CAPTCHA_URL  = f"{BASE_URL}/captcha"
WFS_URL      = "https://sitn.ne.ch/services/wms"
UA           = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"

# WFS pagination page size
WFS_PAGE_SIZE      = 1000   # features per WFS request
WFS_MAX_EMPTY_RUNS = 10     # stop after N consecutive pages with 0 UUID parcels


# ── Altcha PoW solver ─────────────────────────────────────────────────────────

def _solve_altcha(challenge: dict) -> str | None:
    """
    Solve an Altcha PBKDF2/SHA-256 proof-of-work challenge.

    Challenge structure (from GET /captcha):
    {
      "parameters": {
        "algorithm":  "PBKDF2/SHA-256",
        "cost":       250000,       # PBKDF2 iterations
        "keyLength":  32,           # bytes
        "keyPrefix":  "00",         # hex prefix the derived key must start with
        "nonce":      "12a6...",    # hex — prepended to counter to form password
        "salt":       "d144...",    # hex — used as PBKDF2 salt parameter
        "expiresAt":  1778707195    # unix timestamp
      },
      "signature":   "6216..."      # server's HMAC signature
    }

    Algorithm (from Altcha@3.0.1 JS PasswordBuffer + deriveKey source):
      password   = bytes.fromhex(nonce) + counter.to_bytes(4, 'big')
      salt_bytes = bytes.fromhex(salt)
      key = PBKDF2-HMAC-SHA256(password, salt_bytes, iterations=cost, dklen=keyLength)
      if key.hex().startswith(keyPrefix): → found!

    Token payload (base64-encoded JSON) — V2 format (parameters wrapper):
    {
      "challenge": {
        "parameters": { ...original params... },
        "signature": "6216..."
      },
      "solution": {
        "counter":    <found_number>,
        "derivedKey": <hex of derived key>,
        "time":       <ms elapsed>
      }
    }
    Token = base64(json.dumps(payload, separators=(',',':')))
    """
    params    = challenge.get("parameters") or challenge
    algorithm = params.get("algorithm", "PBKDF2/SHA-256")
    cost      = int(params.get("cost", 250_000))
    key_len   = int(params.get("keyLength", 32))
    prefix    = params.get("keyPrefix", "00")
    nonce_hex = params.get("nonce", "")
    salt_hex  = params.get("salt", "")
    signature = challenge.get("signature", "")

    if not nonce_hex or not salt_hex or not signature:
        log.error("Altcha challenge missing required fields: %s", challenge)
        return None

    try:
        nonce_bytes = bytes.fromhex(nonce_hex)
        salt_bytes  = bytes.fromhex(salt_hex)
    except ValueError as exc:
        log.error("Altcha: invalid hex in challenge: %s", exc)
        return None

    log.debug("Altcha: cost=%d keyPrefix=%r salt=%s nonce=%s", cost, prefix, salt_hex, nonce_hex)

    # Brute-force: try counter 0, 1, 2, … until derived key starts with keyPrefix
    # At cost=250000 PBKDF2 iterations: ~25-50ms per attempt on a modern CPU.
    # Typical winning counter is < 1000 (mean ≈ 256 for 2-hex prefix "00").
    MAX_COUNTER = 100_000

    t0 = time.time()
    for counter in range(MAX_COUNTER):
        # PasswordBuffer in uint32 mode: nonce || counter as big-endian uint32
        password = nonce_bytes + counter.to_bytes(4, "big")
        derived  = hashlib.pbkdf2_hmac("sha256", password, salt_bytes, cost, dklen=key_len)
        if derived.hex().startswith(prefix):
            elapsed_ms = int((time.time() - t0) * 1000)
            log.debug("Altcha solved: counter=%d  time=%dms", counter, elapsed_ms)

            # V2 token format (used when challenge has 'parameters' wrapper)
            payload = {
                "challenge": {
                    "parameters": params,
                    "signature":  signature,
                },
                "solution": {
                    "counter":    counter,
                    "derivedKey": derived.hex(),
                    "time":       elapsed_ms,
                },
            }
            token = base64.b64encode(
                json.dumps(payload, separators=(",", ":")).encode()
            ).decode()
            return token

    log.warning("Altcha: no solution found in %d counters (cost=%d)", MAX_COUNTER, cost)
    return None


# ── WFS parcel enumeration ────────────────────────────────────────────────────

def _extract_uuid_from_url(url_terris: str) -> str | None:
    """Extract UUID from url_terris_v2 field value (HTML-encoded URL)."""
    # Format: https://sitn.ne.ch/owner?uuid=d47f5e31-ceff-4146-8254-8e2f7b189072
    # May be HTML-encoded: &amp; instead of &
    url_clean = url_terris.replace("&amp;", "&")
    m = re.search(r"uuid=([0-9a-f\-]{36})", url_clean)
    return m.group(1) if m else None


def enumerate_parcels_wfs(page_size: int = WFS_PAGE_SIZE) -> list[dict]:
    """
    Enumerate NE parcels via sitn.ne.ch WFS GetFeature on layer ms:parcelles.
    Returns GML (geojson not permitted by this server).

    Confirmed field names from live GML response (2026-05):
      egrid       → EGRID (e.g. CH699778984662)
      url_terris_v2 → HTML link containing uuid= parameter
      nummai      → parcel number (e.g. "2147", "DP68")
      idemai      → "{bfs}_{nummai}" (e.g. "37_2147") — bfs is commune number
      cadastre    → commune name (e.g. "CERNIER (37)")
      typimm      → parcel type ("BIEN-FONDS", "DP COMM", "DP CANT", ...)

    Each parcel is stored with:
      bfs_nr   = BFS commune number (from idemai prefix or cadastre)
      parcel_nr = nummai value
      uuid      = UUID extracted from url_terris_v2 (stored in extra)
    """
    import xml.etree.ElementTree as ET

    session = requests.Session()
    session.headers["User-Agent"] = UA

    GML_NS = "http://www.opengis.net/gml"
    MS_NS  = "http://mapserver.gis.umn.edu/mapserver"

    parcels: list[dict] = []
    seen:    set[str]   = set()
    offset       = 0
    empty_runs   = 0   # consecutive pages with 0 new UUID parcels

    log.info("NE WFS parcel enumeration (GML, page_size=%d) …", page_size)

    while True:
        try:
            r = session.get(WFS_URL, params={
                "MAP":         "services",
                "SERVICE":     "WFS",
                "VERSION":     "1.1.0",
                "REQUEST":     "GetFeature",
                "TYPENAME":    "ms:parcelles",
                "MAXFEATURES": page_size,
                "STARTINDEX":  offset,
            }, timeout=60)

            if r.status_code != 200:
                log.warning("WFS HTTP %d at offset=%d", r.status_code, offset)
                break

            root = ET.fromstring(r.content)

            # Find feature members (GML 3)
            features = root.findall(f".//{{{GML_NS}}}featureMember")
            if not features:
                features = root.findall(f".//{{{GML_NS}}}member")

            if not features:
                log.info("No features at offset=%d — end of dataset", offset)
                break

            batch_uuid = 0
            for feat_member in features:
                # Find the ms:parcelles element inside featureMember
                parcel_el = feat_member.find(f"{{{MS_NS}}}parcelles")
                if parcel_el is None:
                    continue

                def _get(tag: str) -> str:
                    el = parcel_el.find(f"{{{MS_NS}}}{tag}")
                    return (el.text or "").strip() if el is not None else ""

                egrid = _get("egrid")
                if not egrid or egrid in seen:
                    continue
                seen.add(egrid)

                # Extract UUID from url_terris_v2
                url_terris = _get("url_terris_v2")
                uuid = _extract_uuid_from_url(url_terris)
                if not uuid:
                    continue  # no owner link — skip (DP not in RF, water, etc.)

                batch_uuid += 1

                # Parse BFS number from idemai ("37_2147" → bfs="37", par="2147")
                idemai   = _get("idemai")
                nummai   = _get("nummai")
                cadastre = _get("cadastre")  # e.g. "CERNIER (37)"

                bfs_nr = ""
                if "_" in idemai:
                    bfs_nr = idemai.split("_")[0]
                if not bfs_nr:
                    m = re.search(r"\((\d+)\)", cadastre)
                    if m:
                        bfs_nr = m.group(1)

                typimm = _get("typimm")   # "BIEN-FONDS", "DP COMM", "DP CANT", ...
                parcels.append({
                    "egrid":      egrid,
                    "uuid":       uuid,
                    "bfs_nr":     bfs_nr,
                    "parcel_nr":  nummai or idemai,
                    "commune":    re.sub(r"\s*\(\d+\)$", "", cadastre).strip(),
                    "parcel_type": typimm,          # preserve for DB parcel_type field
                })

            log.info("WFS offset=%5d  new_uuid=%3d  total=%d",
                     offset, batch_uuid, len(parcels))
            offset += len(features)

            # Stop if WFS returned fewer features than requested (last page)
            if len(features) < page_size:
                break

            # Stop if many consecutive pages yield no UUID parcels
            if batch_uuid == 0:
                empty_runs += 1
                if empty_runs >= WFS_MAX_EMPTY_RUNS:
                    log.info("WFS: %d consecutive empty pages — stopping early", empty_runs)
                    break
            else:
                empty_runs = 0

            time.sleep(0.3)

        except Exception as exc:
            log.warning("WFS error at offset=%d: %s — retrying", offset, exc)
            # Retry with backoff (connection resets are common for large WFS scans)
            retries = getattr(enumerate_parcels_wfs, "_retry_count", 0) + 1
            enumerate_parcels_wfs._retry_count = retries
            if retries > 5:
                log.error("WFS: too many errors, stopping at offset=%d", offset)
                break
            time.sleep(min(5 * retries, 30))
            # Recreate session on connection error
            session = requests.Session()
            session.headers["User-Agent"] = UA
            continue

    log.info("NE WFS enumeration complete: %d parcels with UUID", len(parcels))
    return parcels


# ── Playwright browser pool ───────────────────────────────────────────────────

class NEBrowser:
    """
    Persistent headless Chromium browser for NE owner queries.

    One browser context is kept alive across all parcel queries in a scan run.
    Each query:
      1. Creates a fresh page (new browser context per query for clean cookie state)
      2. Navigates to /owner?uuid=<UUID>
      3. Intercepts the POST /owner network response (sent by Altcha widget)
      4. Returns the response body for parsing

    The Altcha widget on sitn.ne.ch auto-solves the PBKDF2/SHA-256 PoW and
    submits the form without user interaction (typically 3–30 s CPU time).
    """

    def __init__(self, proxy_url: str | None = None):
        self._pw        = None
        self._browser   = None
        self._proxy_url = proxy_url

    def start(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise RuntimeError(
                "playwright not installed.\n"
                "Run: pip install playwright && playwright install chromium"
            )
        proxy_cfg = {"server": self._proxy_url} if self._proxy_url else None
        self._pw      = sync_playwright().start()
        self._browser = self._pw.chromium.launch(
            headless=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                # Prevent Chromium from throttling JS timers / SubtleCrypto in
                # headless/background mode — Altcha PBKDF2 can otherwise take
                # minutes instead of seconds.
                "--disable-background-timer-throttling",
                "--disable-renderer-backgrounding",
                "--disable-backgrounding-occluded-windows",
            ],
            proxy=proxy_cfg,
        )
        log.info("NE headless browser started%s",
                 f" via {self._proxy_url.split('@')[-1]}" if self._proxy_url else "")

    def query(self, uuid: str, egrid: str, timeout_s: int = 60) -> dict:
        """
        Navigate to the NE owner page for one UUID, intercept POST response.

        Flow:
          1. GET /owner?uuid=... → disclaimer page ("J'ai lu !")
          2. Click the disclaimer button → /owner?uuid=...&has_confirmed=true
          3. GET returns page with <altcha-widget> auto-computing PoW
          4. Widget submits POST /owner → we intercept the response body
          5. Parse owner HTML from response

        If a 400 is returned after the disclaimer click the UUID is stale
        (parcel RF record was updated since last WFS enumeration).
        Re-enumerate and retry rather than marking as herrenlos.

        Returns a result dict with owner/is_herrenlos/error keys.
        """
        if self._browser is None:
            self.start()

        url = f"{OWNER_URL}?uuid={uuid}"
        captured: dict = {}

        # Fresh context per query → clean cookies, no cross-contamination
        ctx = self._browser.new_context(
            user_agent=UA,
            locale="fr-CH",
            timezone_id="Europe/Zurich",
        )
        page = ctx.new_page()

        def _on_response(response):
            """Capture the POST /owner response body."""
            if (response.url.startswith(OWNER_URL)
                    and response.request.method == "POST"
                    and response.status == 200):
                try:
                    body = response.text()
                    if "altcha-widget" not in body:
                        captured["html"]   = body
                        captured["status"] = response.status
                except Exception:
                    pass
            elif (response.url.startswith(OWNER_URL)
                  and response.request.method == "POST"
                  and response.status in (400, 404, 429)):
                captured["status"] = response.status
                captured["html"]   = ""
            elif (response.url.startswith(OWNER_URL)
                  and response.request.method == "GET"
                  and response.status == 400):
                # 400 on the GET after disclaimer click = stale UUID
                captured["status"] = 400
                captured["html"]   = ""

        page.on("response", _on_response)

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30_000)
        except Exception as exc:
            log.debug("NE goto error for UUID=%s: %s", uuid, exc)

        # Step 2: click the "J'ai lu !" disclaimer if present
        try:
            if page.locator("#confirmed").count() > 0:
                page.locator("#confirmed").click()
                # wait_for_timeout yields to the Playwright event loop so the
                # load + Altcha PoW POST response can be captured via _on_response.
                page.wait_for_timeout(2000)
        except Exception as exc:
            log.debug("NE disclaimer click error for UUID=%s: %s", uuid, exc)

        # Poll for captured response using wait_for_timeout (NOT time.sleep) so
        # the Playwright event loop can dispatch the on_response callback.
        polls = int(timeout_s / 0.5)
        for _ in range(polls):
            if captured:
                break
            page.wait_for_timeout(500)

        ctx.close()

        status = captured.get("status")
        html   = captured.get("html", "")

        if not captured:
            log.warning("NE timeout after %ds — no POST captured (EGRID=%s UUID=%s). "
                        "Re-enumerate to refresh UUIDs.", timeout_s, egrid, uuid)

        if status == 429:
            return {"error": "rate_limited", "is_herrenlos": None,
                    "owner": None, "owner_address": None, "raw_response": None}
        if status == 400:
            # Stale UUID (RF record updated since last WFS enumeration).
            # Re-run enumeration to refresh UUIDs and retry.
            log.warning("NE stale UUID for EGRID=%s — run python3 main.py ne --refresh-enum "
                        "to re-enumerate before next scan.", egrid)
            return {"owner": None, "owner_address": None,
                    "is_herrenlos": None, "raw_response": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "error": "stale_uuid"}
        if status == 404:
            # Server confirmed: parcel not in land register
            return {"owner": None, "owner_address": None,
                    "is_herrenlos": 1, "raw_response": None,
                    "herrenlos_type": "not_in_grundbuch", "claim_possible": 0,
                    "error": None}
        if status is None and not html:
            return {"owner": None, "owner_address": None,
                    "is_herrenlos": None, "raw_response": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "error": "playwright_no_post"}
        if not html:
            return {"owner": None, "owner_address": None, "is_herrenlos": None,
                    "raw_response": None, "error": f"playwright_status_{status}"}

        return _parse_owner_html(html, egrid, uuid)

    def close(self):
        try:
            if self._browser:
                self._browser.close()
            if self._pw:
                self._pw.stop()
        except Exception:
            pass
        self._browser = None
        self._pw      = None


def check_owner(browser: "NEBrowser", egrid: str, uuid: str) -> dict:
    """Query owner for one NE parcel via Playwright (Altcha widget handles PoW)."""
    if not uuid:
        return {"owner": None, "owner_address": None,
                "is_herrenlos": None, "raw_response": None, "error": "no_uuid"}
    return browser.query(uuid, egrid)


def _parse_owner_html(html: str, egrid: str, uuid: str) -> dict:
    """
    Parse owner name + address from NE sitn.ne.ch owner page HTML.

    Confirmed HTML structure (from live tests 2026-05):
      <table>
        <tr><td class="normalbold">Propriétaire(s) :</td></tr>
        <tr class="graybg"><td>
            SINGELE
            Claude André
        </td></tr>
        <!-- multiple owners each in their own <tr class=graybg> -->
      </table>

    Herrenlos / special signals:
      - "Non-immatriculé au Registre Foncier" → not in land register (DP parcels)
      - No <tr class=graybg> rows after the Propriétaire label
      - "sans propriétaire", "sans maître", "vacant" in owner text
    """
    soup = BeautifulSoup(html, "html.parser")

    owner  = None
    addr   = None
    owners: list[str] = []

    def _is_gray_row(tr_el, td_el) -> bool:
        """
        NE uses two HTML variants for owner rows:
          v1: <tr class="graybg"><td>Owner name</td></tr>
          v2: <tr><td class="graybg" (or class=graybg)>Owner name</td></tr>
        Accept either form.
        """
        for el in (tr_el, td_el):
            cls = el.get("class", [])
            cls_str = " ".join(cls) if isinstance(cls, list) else str(cls)
            if "graybg" in cls_str or "gray" in cls_str:
                return True
        return False

    # Primary parser: find the "Propriétaire(s)" label then collect graybg rows
    prop_label_found = False
    for tr in soup.find_all("tr"):
        tds = tr.find_all("td")
        if not tds:
            continue

        # Detect the Propriétaire header row
        label_td = tds[0]
        label = label_td.get_text(strip=True).lower().rstrip(" :")
        if not prop_label_found:
            if any(x in label for x in ("propriétaire", "proprietaire", "titulaire", "ayant droit")):
                prop_label_found = True
            continue

        # Rows AFTER the label: collect owner-value rows (graybg on tr OR first td)
        if _is_gray_row(tr, tds[0]):
            val = tds[0].get_text(separator=" ", strip=True)
            # Collapse internal whitespace
            val = re.sub(r"\s+", " ", val).strip()
            # NE encodes co-ownership as "#NNNN, N de part de copropriété".
            # This IS an owner reference (another GB entry), not herrenlos — treat
            # as a non-empty owner to avoid false positives.
            if val and (val.startswith("#") or "copropriété" in val.lower()
                        or "copropriet" in val.lower()):
                owners.append(val)   # co-ownership: parcel has owners
            elif val and not is_herrenlos_owner_text(val):
                owners.append(val)
        else:
            # Non-graybg row after label = end of owner list
            if prop_label_found and owners:
                break

    if owners:
        owner = "; ".join(owners)

    # Fallback: search for th/td pairs with Propriétaire label
    if owner is None:
        for th in soup.find_all(["th", "td"]):
            label = th.get_text(strip=True).lower().rstrip(" :")
            if any(x in label for x in ("propriétaire", "proprietaire", "titulaire")):
                td = th.find_next_sibling("td")
                if td:
                    val = re.sub(r"\s+", " ", td.get_text(separator=" ", strip=True)).strip()
                    if val and not is_herrenlos_owner_text(val):
                        owner = val
                break

    # Herrenlos / not-in-register signals (page text)
    page_text = soup.get_text(separator=" ", strip=True).lower()

    # sitn.ne.ch in-page rate-limit (HTTP 200, but body says "trop de consultations").
    # Must be checked before herrenlos detection to avoid false positives.
    if ("trop de consultations" in page_text
            or "service de consultation" in page_text and "désactivé" in page_text
            or "too many" in page_text):
        log.warning("NE in-page rate limit hit (EGRID=%s)", egrid)
        return {"owner": None, "owner_address": None,
                "is_herrenlos": None, "raw_response": None,
                "herrenlos_type": None, "claim_possible": None,
                "error": "rate_limited"}

    # "Non-immatriculé au Registre Foncier" → parcel NOT in land register.
    # This is Type 2 herrenlos (Art. 664 ZGB) — under cantonal sovereignty.
    # NOT claimable by private persons.
    if "non-immatriculé" in page_text or "non immatriculé" in page_text:
        log.info("Not in Grundbuch (EGRID=%s UUID=%s) — non-immatriculé (Art.664)", egrid, uuid)
        return {"owner": None, "owner_address": None,
                "is_herrenlos": 1,
                "herrenlos_type": "not_in_grundbuch",
                "claim_possible": 0,
                "raw_response": html[:400], "error": None}

    not_found_signals = ("introuvable", "aucun résultat", "pas de résultat",
                         "not found", "no result", "nicht gefunden")
    if any(sig in page_text for sig in not_found_signals):
        return {"owner": None, "owner_address": None,
                "is_herrenlos": 1,
                "herrenlos_type": "not_in_grundbuch",
                "claim_possible": 0,
                "raw_response": html[:400], "error": None}

    if owner is None:
        log.info("No owner found (EGRID=%s UUID=%s) — potential dereliktion", egrid, uuid)

    # Parcel IS in Grundbuch (we got a 200 result page) but no Propriétaire found
    # → potential Type 1 dereliktion (Art. 964 ZGB)
    h_type = None if owner else "dereliktion"
    return {
        "owner":          owner,
        "owner_address":  addr or None,
        "is_herrenlos":   0 if owner else 1,
        "herrenlos_type": h_type,
        "claim_possible": claim_possible_for("NE", h_type) if h_type else None,
        "raw_response":   html[:400] if owner is None else None,
        "error":          None,
    }


# ── Main scanner ──────────────────────────────────────────────────────────────

def scan(limit: int | None = None,
         skip_existing: bool = True,
         delay: float = 2.0,
         refresh_enum: bool = False):
    """
    Scan NE parcels for herrenlos detection.

    Uses Playwright headless browser to handle Altcha v3 PoW automatically.
    One browser instance is kept alive for the entire scan run.

    First run: WFS enumeration to get EGRIDs + UUIDs (cached to DB).
    Subsequent runs: use cached list directly.

    NOTE: NE UUIDs are short-lived session tokens embedded in the WFS data.
    If you see stale_uuid errors, the cached enumeration is outdated — re-run
    with refresh_enum=True (--refresh-enum flag) to re-enumerate and get fresh UUIDs.

    Rate limit: ~50 queries/day per IP. Altcha PoW takes 3–30s per parcel.

    limit         : stop after N owner queries (None = all)
    skip_existing : skip parcels already in DB
    delay         : minimum seconds between queries (Playwright time counts too)
    refresh_enum  : discard cached parcel list and re-enumerate from WFS
    """
    init_db()

    NE_UUID_MAX_AGE_DAYS = 3  # NE UUIDs expire; re-enumerate if cache is older

    with get_conn() as conn:
        cached = enum_cached(conn, "NE")
        # Check cache age — NE UUIDs are short-lived WFS session tokens.
        # If the cache is older than NE_UUID_MAX_AGE_DAYS, force re-enumeration.
        if cached and not refresh_enum:
            try:
                row = conn.execute(
                    "SELECT MIN(enumerated_at) FROM parcel_enum WHERE canton='NE'"
                ).fetchone()
                if row and row[0]:
                    from datetime import datetime, timezone
                    cached_dt = datetime.fromisoformat(str(row[0]).replace("Z", "+00:00"))
                    if cached_dt.tzinfo is None:
                        cached_dt = cached_dt.replace(tzinfo=timezone.utc)
                    age_days = (datetime.now(timezone.utc) - cached_dt).days
                    if age_days >= NE_UUID_MAX_AGE_DAYS:
                        log.warning(
                            "NE UUID cache is %d days old (>=%d) — forcing re-enumeration "
                            "to refresh short-lived WFS UUIDs.",
                            age_days, NE_UUID_MAX_AGE_DAYS,
                        )
                        refresh_enum = True
            except Exception as exc:
                log.warning("Could not check NE cache age: %s", exc)

    if cached and not refresh_enum:
        log.info("Using cached NE parcel list (%d parcels)", len(cached))
        parcels = cached
    else:
        if refresh_enum and cached:
            log.info("Refreshing NE parcel enum (discarding %d cached entries) …", len(cached))
            with get_conn() as conn:
                # MUST use schema-qualified name: enum.parcel_enum lives in enum.db
                conn.execute("DELETE FROM enum.parcel_enum WHERE canton='NE'")
                conn.commit()
            # Also clear stale_uuid / playwright_no_post errors so fresh UUIDs are tried
            with get_conn() as conn:
                conn.execute(
                    "DELETE FROM parcels WHERE canton='NE' AND is_herrenlos IS NULL "
                    "AND error IN ('stale_uuid','playwright_no_post')"
                )
                conn.commit()
        else:
            log.info("No cache — running WFS enumeration …")
        parcels = enumerate_parcels_wfs()
        with get_conn() as conn:
            store_enum(conn, "NE", parcels)
        log.info("Cached %d NE parcels", len(parcels))

    if limit:
        parcels = parcels[:limit]

    proxies = load_proxies("NE_PROXY_LIST")
    proxy_idx = 0
    queries_on_proxy = 0
    ROTATE_EVERY = 45  # stay under ~50/day limit per IP

    if proxies:
        log.info("NE proxy rotation: %d proxies, rotate every %d queries", len(proxies), ROTATE_EVERY)

    def _start_browser(idx: int) -> "NEBrowser":
        proxy_url = proxies[idx % len(proxies)] if proxies else None
        b = NEBrowser(proxy_url=proxy_url)
        b.start()
        return b

    try:
        browser = _start_browser(0)
    except RuntimeError as exc:
        log.error("%s", exc)
        return

    scanned = errors = herrenlos = 0
    rate_wait_until = 0.0

    try:
        with get_conn() as conn:
            for p in parcels:
                egrid   = p.get("egrid", "")
                bfs     = p["bfs_nr"]
                nr      = p["parcel_nr"]
                commune = p.get("commune", "")

                # UUID stored directly or inside extra dict (packed by store_enum)
                uuid = p.get("uuid", "")
                if not uuid:
                    extra = p.get("extra")
                    if isinstance(extra, dict):
                        uuid = extra.get("uuid", "")
                    elif isinstance(extra, str):
                        try:
                            uuid = json.loads(extra).get("uuid", "")
                        except Exception:
                            pass

                if skip_existing and already_scanned(conn, "NE", bfs, nr):
                    continue

                # Proactive proxy rotation (before hitting the hard limit)
                if proxies and queries_on_proxy >= ROTATE_EVERY:
                    proxy_idx = (proxy_idx + 1) % len(proxies)
                    browser.close()
                    browser = _start_browser(proxy_idx)
                    queries_on_proxy = 0
                    log.info("NE proactive proxy rotate → proxy #%d", proxy_idx)

                # Rate limit guard (no-proxy fallback — belt-and-suspenders)
                if time.time() < rate_wait_until:
                    log.warning("NE daily quota exhausted — stopping scan.")
                    break

                result = check_owner(browser, egrid, uuid)
                queries_on_proxy += 1

                # playwright_no_post = proxy is blocked / too slow; rotate immediately
                if result.get("error") == "playwright_no_post" and proxies:
                    log.warning("NE playwright timeout — rotating proxy (was #%d)", proxy_idx)
                    proxy_idx = (proxy_idx + 1) % len(proxies)
                    browser.close()
                    browser = _start_browser(proxy_idx)
                    queries_on_proxy = 0
                    result = check_owner(browser, egrid, uuid)
                    queries_on_proxy += 1

                if result.get("error") == "rate_limited":
                    if proxies:
                        proxy_idx = (proxy_idx + 1) % len(proxies)
                        browser.close()
                        browser = _start_browser(proxy_idx)
                        queries_on_proxy = 0
                        log.warning("NE rate limit — rotated to proxy #%d", proxy_idx)
                        time.sleep(2)
                        result = check_owner(browser, egrid, uuid)
                        queries_on_proxy += 1
                    else:
                        # No proxies — daily quota exhausted on this IP.
                        # Don't sleep for 24h (would waste CI minutes or block the laptop).
                        # Just stop scanning and let the next run continue from here.
                        log.warning(
                            "NE rate limit hit with no proxies — stopping scan for today. "
                            "Set NE_PROXY_LIST to rotate IPs, or run again tomorrow."
                        )
                        break

                upsert_parcel(conn, {
                    "egrid":       egrid,
                    "canton":      "NE",
                    "commune":     commune,
                    "bfs_nr":      bfs,
                    "parcel_nr":   nr,
                    "parcel_type": p.get("parcel_type") or "Immeuble",
                    **result,
                })

                scanned += 1
                if result.get("is_herrenlos") == 1:
                    herrenlos += 1
                    log.info("HERRENLOS  %s Nr.%s  EGRID=%s", commune, nr, egrid)
                if result.get("error") and result["error"] not in ("rate_limited",):
                    errors += 1
                    if result["error"] == "stale_uuid":
                        log.warning("Stale UUID — consider re-running with --refresh-enum")

                if scanned % 50 == 0:
                    log.info("Progress %d  herrenlos=%d  errors=%d", scanned, herrenlos, errors)

                time.sleep(delay)

    finally:
        browser.close()
        log.info("NE browser closed")

    log.info("NE scan done — scanned=%d  herrenlos=%d  errors=%d", scanned, herrenlos, errors)
    return {"scanned": scanned, "herrenlos": herrenlos, "errors": errors}
