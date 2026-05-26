"""
SH scanner — Schaffhausen
==========================
- EGRID enumeration : geodienste.ch WFS (wfs_enum.py) — includes LV95 centroid coords
                      needed for owner API. Cached in parcel_enum.extra as
                      {"east": E, "north": N}.

- Token             : POST https://api.geo.sh.ch/token
                      grant_type=client_credentials with fresh random UUID client_id
                      and client_secret. The server accepts any GUIDs — no
                      pre-registered clients required. Returns {"access_token": "..."}.
                      Honeypot field "value" must be sent empty.

- Owner lookup      : 2-step coordinate-based API under https://api.geo.sh.ch/geosec/

    Step 1 — resolve EGRID coordinates → internal UUID:
        GET /geosec/grundstueckeigentumbycoord1a519997-0363-4024-a2b9-36e23205d6f7/json/
            ?east=E&north=N&art=Liegenschaft
        Authorization: Bearer <token>
        Returns: [{"link": "<uuid>", ...}]  or []

    Step 2 — fetch owner by UUID:
        GET /geosec/eigentumbyuuidea8228b0-c5d1-4f23-ba37-d91dc64e5b4e/json/?uuid=<uuid>
        Authorization: Bearer <token>
        Returns: [{"g_titel":..., "p_name":..., "p_strasse":..., "p_ort":..., "link":...}]

- Rate limit        : Server enforces 100 step-1 queries/day per IP (HTTP 429).
                      The portal UI says "10" but the actual 429 message says "100".
                      Refreshing the token (new UUID pair) does NOT reset the limit.

- Herrenlos signals :
    Type A — empty array in Step 1 → parcel exists in cadastre but not in Grundbuch
             (Art. 664 ZGB: not_in_grundbuch, claim_possible=0)
    Type B — empty array in Step 2 → parcel IS in Grundbuch but owner deleted
             (dereliktion, potentially claimable — GR None, pending legal research)
    Both types: "Es wurde kein Eigentümer gefunden" in the portal UI.

- Parcels           : ~9,000 (small canton, 298 km²)
"""

import json
import time
import uuid
import logging
import requests

import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from db import get_conn, init_db, already_scanned, upsert_parcel, enum_cached, store_enum
from scanners.wfs_enum import enumerate_canton as wfs_enumerate_canton
from scanners.utils import (
    is_herrenlos_owner_text, claim_possible_for, load_proxies,
    DEFAULT_UA,
)

log = logging.getLogger("SH")

# ── API constants ────────────────────────────────────────────────────────────

API_BASE = "https://api.geo.sh.ch"
TOKEN_URL = f"{API_BASE}/token"

# These UUIDs are part of the endpoint path (obfuscation in the JS source)
COORD_LOOKUP_URL = (
    f"{API_BASE}/geosec/"
    "grundstueckeigentumbycoord1a519997-0363-4024-a2b9-36e23205d6f7"
    "/json/"
)
UUID_LOOKUP_URL = (
    f"{API_BASE}/geosec/"
    "eigentumbyuuidea8228b0-c5d1-4f23-ba37-d91dc64e5b4e"
    "/json/"
)
# Person-UUID lookup (for link type 2 — named co-owners/legal entities)
PERSON_UUID_LOOKUP_URL = (
    f"{API_BASE}/geosec/"
    "eigentumpbyuuidc6883cf8-7529-4e6e-b5e2-ca9d11e43d07"
    "/json/"
)

UA = DEFAULT_UA  # alias kept for call sites within this file; imported from utils


# ── Token management ─────────────────────────────────────────────────────────

def fetch_token(session: requests.Session) -> str | None:
    """
    Obtain a short-lived Bearer token from the SH geosec API.
    Uses client_credentials grant with fresh random UUIDs.
    The server accepts any syntactically valid UUIDs as client_id/client_secret.
    The 'value' field is an anti-bot honeypot (must be empty).
    Returns the access_token string, or None on failure.
    """
    client_id     = str(uuid.uuid4())
    client_secret = str(uuid.uuid4())
    try:
        r = session.post(
            TOKEN_URL,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type":    "client_credentials",
                "client_id":     client_id,
                "client_secret": client_secret,
                "value":         "",   # honeypot — must stay empty
            },
            timeout=15,
        )
        if r.status_code == 200:
            tok = r.json().get("access_token")
            log.debug("Token obtained (client_id=%s)", client_id[:8])
            return tok
        log.warning("Token request failed: HTTP %d", r.status_code)
        return None
    except Exception as exc:
        log.warning("Token request exception: %s", exc)
        return None


# ── Owner check ──────────────────────────────────────────────────────────────

def check_owner(session: requests.Session, east: int, north: int,
                token: str, egrid: str) -> dict:
    """
    2-step owner lookup for one SH parcel.

    Step 1: coordinate → internal link UUID
    Step 2: UUID → owner details

    Returns dict with: owner, owner_address, is_herrenlos, herrenlos_type,
                       claim_possible, raw_response, error
    Also returns 'new_token' key if the token was refreshed (set to None if not).
    """
    auth_headers = {
        "Authorization":  f"Bearer {token}",
        "Cache-Control":  "no-cache, no-store, must-revalidate",
        "Pragma":         "no-cache",
        "Expires":        "0",
    }

    # ── Step 1: coordinate → UUID list ───────────────────────────────────────
    try:
        r1 = session.get(
            COORD_LOOKUP_URL,
            params={"east": east, "north": north, "art": "Liegenschaft"},
            headers=auth_headers,
            timeout=15,
        )
    except Exception as exc:
        return _err(str(exc))

    if r1.status_code == 401:
        # Token expired — caller should refresh
        return {"error": "token_expired", "is_herrenlos": None,
                "owner": None, "owner_address": None, "raw_response": None}

    if r1.status_code == 429:
        return {"error": "rate_limited", "is_herrenlos": None,
                "owner": None, "owner_address": None, "raw_response": None}

    if r1.status_code != 200:
        return _err(f"step1_http_{r1.status_code}")

    try:
        data1 = r1.json()
    except Exception:
        return _err("step1_json_parse")

    if not data1:
        # Empty array in Step 1 → parcel is in cadastre but has no Grundbuch entry.
        # Art. 664 ZGB: ownerless by default, canton acquires automatically.
        log.info("HERRENLOS (not_in_grundbuch)  EGRID=%s  E=%d N=%d", egrid, east, north)
        return {
            "owner": None, "owner_address": None,
            "is_herrenlos": 1,
            "herrenlos_type": "not_in_grundbuch",
            "claim_possible": 0,
            "raw_response": "[]", "error": None,
        }

    # ── Step 2: UUID → owner details ─────────────────────────────────────────
    link_uuid = data1[0].get("link") if isinstance(data1, list) and data1 else None
    if not link_uuid:
        return _err("step1_no_link_uuid")

    try:
        r2 = session.get(
            UUID_LOOKUP_URL,
            params={"uuid": link_uuid},
            headers=auth_headers,
            timeout=15,
        )
    except Exception as exc:
        return _err(str(exc))

    if r2.status_code == 429:
        return {"error": "rate_limited", "is_herrenlos": None,
                "owner": None, "owner_address": None, "raw_response": None}

    if r2.status_code != 200:
        return _err(f"step2_http_{r2.status_code}")

    try:
        data2 = r2.json()
    except Exception:
        return _err("step2_json_parse")

    if not data2:
        # Empty array in Step 2 → parcel IS in Grundbuch but has no owner entries.
        # Dereliktion (Art. 964 ZGB) — the most actionable herrenlos type.
        log.info("HERRENLOS (dereliktion)  EGRID=%s  E=%d N=%d", egrid, east, north)
        return {
            "owner": None, "owner_address": None,
            "is_herrenlos": 1,
            "herrenlos_type": "dereliktion",
            "claim_possible": claim_possible_for("SH", "dereliktion"),
            "raw_response": "[]", "error": None,
        }

    # ── Parse owner records ───────────────────────────────────────────────────
    owners: list[str] = []
    addrs:  list[str] = []

    for rec in (data2 if isinstance(data2, list) else [data2]):
        if not isinstance(rec, dict):
            continue

        name = (rec.get("p_name") or "").strip()
        if not name:
            # Fallback: SH API uses g_name for corporate/collective ownership
            # identified by a Grundbuch cross-reference (e.g. "GB 7083, Hallau").
            # p_name is None for these entities — not herrenlos.
            name = (rec.get("g_name") or "").strip()
        if not name or is_herrenlos_owner_text(name):
            continue

        owners.append(name)
        parts = filter(None, [
            (rec.get("p_strasse") or "").strip(),
            (rec.get("p_ort") or "").strip(),
        ])
        addr = ", ".join(parts)
        if addr:
            addrs.append(addr)

    # Deduplicate
    seen_set: set[str] = set()
    unique_owners: list[str] = []
    unique_addrs:  list[str] = []
    for i, o in enumerate(owners):
        if o not in seen_set:
            seen_set.add(o)
            unique_owners.append(o)
            if i < len(addrs):
                unique_addrs.append(addrs[i])

    owner = "; ".join(unique_owners) if unique_owners else None
    if owner is None:
        log.info("Potential herrenlos — no parseable owner (EGRID=%s)", egrid)

    h_type = None if owner else "dereliktion"
    return {
        "owner":          owner,
        "owner_address":  "; ".join(unique_addrs) or None,
        "is_herrenlos":   0 if owner else 1,
        "herrenlos_type": h_type,
        "claim_possible": claim_possible_for("SH", h_type) if h_type else None,
        "raw_response":   str(data2) if owner is None else None,
        "error":          None,
    }


def _err(msg: str) -> dict:
    return {"owner": None, "owner_address": None,
            "is_herrenlos": None, "herrenlos_type": None, "claim_possible": None,
            "raw_response": None, "error": msg}


# ── Main scanner ─────────────────────────────────────────────────────────────

def _sh_session(proxy_url: str | None = None) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = UA
    if proxy_url:
        s.proxies.update({"http": proxy_url, "https": proxy_url})
    return s


def scan(limit: int | None = None,
         skip_existing: bool = True,
         delay: float = 1.5):
    """
    Scan SH parcels for herrenlos detection.

    First run: ~3 min WFS enumeration via geodienste.ch (wfs_enum.py), including
    LV95 centroid coordinates required for the owner API.
    Subsequent runs: use cached list directly.

    Rate limit: 100 step-1 queries/day per IP (server-enforced 429).
    Set SH_PROXY_LIST in .env (comma/newline-separated proxy URLs or
    Webshare host:port:user:pass format) to rotate IPs automatically.
    With 10 proxies: full 9k scan completes in a single day.

    limit         : stop after N parcels (None = all)
    skip_existing : skip parcels already in DB
    delay         : seconds between parcel requests
    """
    init_db()

    # SH has ~43k parcels in 26 communes. Use geodienste WFS for full coverage
    # (the swisstopo grid scan at 500m step only found 857 = 2% of the canton).
    with get_conn() as conn:
        cached = enum_cached(conn, "SH")
    if cached and len(cached) >= 30_000:
        log.info("Using cached SH parcel list (%d parcels)", len(cached))
        parcels = cached
    else:
        if cached:
            log.info("SH cache incomplete (%d parcels) — re-enumerating via WFS", len(cached))
            with get_conn() as conn:
                conn.execute("DELETE FROM enum.parcel_enum WHERE canton='SH'")  # MED-7 fix: must qualify with 'enum.' schema
                conn.commit()
        log.info("Enumerating SH parcels via geodienste WFS (~10s) …")
        parcels = wfs_enumerate_canton("SH")
        with get_conn() as conn:
            store_enum(conn, "SH", parcels)
        log.info("Cached %d SH parcels (WFS)", len(parcels))

    if limit:
        parcels = parcels[:limit]

    proxies = load_proxies("SH_PROXY_LIST")
    proxy_idx = 0
    queries_on_proxy = 0
    ROTATE_EVERY = 100  # full 100/day per proxy (was 90 — wasted 10 slots per proxy)
    consecutive_429 = 0
    MAX_CONSECUTIVE_429 = max(len(proxies) * 2, 5) if proxies else 5

    if proxies:
        log.info("SH proxy rotation: %d proxies, rotate every %d queries "
                 "(circuit breaker after %d consecutive 429s)",
                 len(proxies), ROTATE_EVERY, MAX_CONSECUTIVE_429)

    session = _sh_session(proxies[0] if proxies else None)

    # Obtain initial token
    token = fetch_token(session)
    if not token:
        log.error("Failed to obtain initial token — aborting")
        return {"scanned": 0, "herrenlos": 0, "errors": 1}

    scanned = errors = herrenlos = 0

    with get_conn() as conn:
        for p in parcels:
            egrid   = p.get("egrid", "")
            bfs     = p.get("bfs_nr", "")
            nr      = p.get("parcel_nr", "")
            commune = p.get("commune", "")
            extra   = p.get("extra") or {}

            # Coordinates stored in extra during enumeration
            east  = int(extra.get("east", 0)) if isinstance(extra, dict) else 0
            north = int(extra.get("north", 0)) if isinstance(extra, dict) else 0

            if not east or not north:
                log.warning("No coordinates for EGRID=%s — skipping", egrid)
                errors += 1
                continue

            if skip_existing and already_scanned(conn, "SH", bfs, nr):
                continue

            # Proactive proxy rotation (before hitting the hard limit)
            if proxies and queries_on_proxy >= ROTATE_EVERY:
                proxy_idx = (proxy_idx + 1) % len(proxies)
                session = _sh_session(proxies[proxy_idx])
                token = fetch_token(session) or token
                queries_on_proxy = 0
                log.info("SH proactive proxy rotate → proxy #%d", proxy_idx)

            result = check_owner(session, east, north, token, egrid)
            queries_on_proxy += 1

            # Token expired → refresh and retry once
            if result.get("error") == "token_expired":
                log.info("Token expired — refreshing …")
                token = fetch_token(session)
                if token:
                    result = check_owner(session, east, north, token, egrid)
                else:
                    result = _err("token_refresh_failed")

            # Rate limited → rotate proxy; circuit-break when all are spent
            # HIGH-3 fix: count ONE consecutive 429 per parcel (same bug as GR).
            # Original code double-incremented (initial + retry), halving the
            # effective threshold. Rotate + retry first; count only if both fail.
            if result.get("error") == "rate_limited":
                if proxies:
                    proxy_idx = (proxy_idx + 1) % len(proxies)
                    session = _sh_session(proxies[proxy_idx])
                    token = fetch_token(session) or token
                    queries_on_proxy = 0
                    log.warning("SH rate limit — rotated to proxy #%d", proxy_idx)
                    time.sleep(2)
                    result = check_owner(session, east, north, token, egrid)
                    queries_on_proxy += 1
                    if result.get("error") == "rate_limited":
                        consecutive_429 += 1
                        if consecutive_429 >= MAX_CONSECUTIVE_429:
                            log.warning(
                                "SH all proxies exhausted — %d consecutive 429s. "
                                "Daily quota fully used.", consecutive_429
                            )
                            break
                    else:
                        consecutive_429 = 0
                else:
                    log.warning(
                        "SH rate limit hit (100/day) with no proxies — stopping scan for today. "
                        "Set SH_PROXY_LIST to rotate IPs, or run again tomorrow."
                    )
                    break
            else:
                consecutive_429 = 0

            upsert_parcel(conn, {
                "egrid":       egrid,
                "canton":      "SH",
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
            if result.get("error") and result["error"] not in ("rate_limited",):
                errors += 1

            if scanned % 50 == 0:
                log.info("Progress %d  herrenlos=%d  errors=%d", scanned, herrenlos, errors)

            time.sleep(delay)

    log.info("SH scan done — scanned=%d  herrenlos=%d  errors=%d", scanned, herrenlos, errors)
    return {"scanned": scanned, "herrenlos": herrenlos, "errors": errors}
