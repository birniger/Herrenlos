"""
GR scanner — Graubünden
========================
- EGRID enumeration : geodienste.ch WFS (wfs_enum.py)
                      Cached in parcel_enum table — only runs once ever.
- Owner lookup      : GET https://lkgr.geogr.ch/terravis/egrid/{EGRID}
                      Returns JSON with owner data.
                      reCAPTCHA header IS present in the JS but the server
                      NEVER validates the token — confirmed by live testing.
- Rate limit        : 10 req/day per IP (anonymous). 429 → sleep → continue.
                      For full scan use Tor or VPN rotation (CHF 1–7 one-time).
                      Optional: OIDC login at lkgr.geogr.ch → 50/day (free acct).
- Herrenlos signal  : empty eigentuemer list  OR  404  OR  {"error": "not_found"}
- Parcels           : ~85,000 (largest Swiss canton, ~7,100 km²)
"""

import re
import time
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

log = logging.getLogger("GR")

TERRAVIS_URL = "https://lkgr.geogr.ch/terravis/egrid/{egrid}"
UA           = DEFAULT_UA  # alias kept for call sites within this file


# ── Owner check ─────────────────────────────────────────────────────────────

def check_owner(session: requests.Session, egrid: str) -> dict:
    """
    Query owner for one GR parcel via Terravis JSON API.

    The frontend sends an X-Captcha-Token header, but live testing confirmed
    the server ignores it completely — no captcha validation whatsoever.

    Rate limit: 10 req/day per IP (anonymous).
    Returns HTTP 429 when limit exceeded.

    Confirmed live response structure (2025):
    {
      "parcels": [{
        "id": "...",
        "person": [{
          "nummer": "...",
          "inhalt_natuerliche_person_gb": [{"name": ..., "vorname": ...}],
          "inhalt_juristische_person_gb": [{"name_firma": ...}],
          "person_stamm": {
            "oeffentliche_koerperschaft": {"name": ..., "adresse": {...}}
          }
        }],
        "grundstueck": [...],
        "recht": [...]
      }],
      "missing": []   ← non-empty means EGRID not found (Type 2 herrenlos)
    }
    """
    try:
        r = session.get(
            TERRAVIS_URL.format(egrid=egrid),
            headers={"Referer": "https://lkgr.geogr.ch/owner"},
            timeout=15,
        )

        if r.status_code == 429:
            return {"error": "rate_limited", "is_herrenlos": None,
                    "owner": None, "owner_address": None, "raw_response": None}

        if r.status_code in (404, 400):
            # EGRID not found in Terravis / Grundbuch at all.
            # This is Type 2 herrenlos (Art. 664 ZGB) — parcel exists in the
            # cadastre but has no Grundbuch entry. Falls to canton by law.
            # NOT claimable by private persons.
            return {"owner": None, "owner_address": None,
                    "is_herrenlos": 1,
                    "herrenlos_type": "not_in_grundbuch",
                    "claim_possible": 0,
                    "raw_response": None, "error": None}

        if r.status_code != 200:
            return {"error": f"http_{r.status_code}", "is_herrenlos": None,
                    "herrenlos_type": None, "claim_possible": None,
                    "owner": None, "owner_address": None, "raw_response": None}

        data = r.json()

        # ── Type 2 herrenlos: EGRID listed in Terravis "missing" list ────────
        missing = data.get("missing") or []
        # MED-8 fix: use list membership (`in missing`) not substring search
        # (`in str(missing)`) — the latter would false-match any EGRID whose
        # digits appear in another EGRID's string representation.
        if missing and egrid in missing:
            return {"owner": None, "owner_address": None,
                    "is_herrenlos": 1,
                    "herrenlos_type": "not_in_grundbuch",
                    "claim_possible": 0,
                    "raw_response": str(data), "error": None}

        # ── Parse Terravis "parcels[].person[]" structure ────────────────────
        owners: list[str] = []
        addrs:  list[str] = []

        def _addr_str(adr) -> str:
            """Extract address string from various Terravis address shapes."""
            if isinstance(adr, list) and adr:
                # Shape: [{"adresse": {"strasse": ..., "plz": ..., "ort": ...}}]
                adr = adr[0]
            if isinstance(adr, dict):
                # Unwrap nested "adresse" key
                inner = adr.get("adresse")
                if isinstance(inner, dict):
                    adr = inner
                return ", ".join(filter(None, [
                    adr.get("strasse") or adr.get("Strasse") or adr.get("street") or "",
                    (adr.get("hausnummer") or adr.get("Hausnummer") or ""),
                    adr.get("plz") or adr.get("Plz") or "",
                    adr.get("ort") or adr.get("Ort") or adr.get("city") or "",
                ]))
            return str(adr).strip() if adr else ""

        parcels_list = data.get("parcels") or []
        if not parcels_list:
            # Terravis returned 200 but parcels[] is empty — parcel IS registered
            # in the Grundbuch but has no entries. Treat as Type 1 dereliktion
            # (the most actionable herrenlos signal in GR).
            log.info("No parcels in Terravis response (EGRID=%s) — potential dereliktion", egrid)
            return {"owner": None, "owner_address": None,
                    "is_herrenlos": 1,
                    "herrenlos_type": "dereliktion",
                    "claim_possible": claim_possible_for("GR", "dereliktion"),
                    "raw_response": str(data), "error": None}

        for parcel in (parcels_list if isinstance(parcels_list, list) else []):
            # ── Check recht[] for ownership before person[] ──────────────────
            # Stockwerkseigentum (condominium) and similar structures store
            # ownership through recht[].inhalt_eigentum_anteil rather than
            # person[].  If any recht entry carries an eigentum_anteil the
            # parcel IS owned — skip to next parcel without flagging herrenlos.
            recht_list = parcel.get("recht") or []
            for recht in (recht_list if isinstance(recht_list, list) else []):
                if recht.get("inhalt_eigentum_anteil"):
                    # Ownership registered via StWE/MitEigentum recht entry.
                    # Mark as owned with a synthetic label so the scanner
                    # records a non-herrenlos result.
                    owners.append("[StWE/MitEigentum]")
                    break

            person_list = parcel.get("person") or []
            for person in (person_list if isinstance(person_list, list) else []):
                name = ""
                addr = ""

                # 1. Natural person (inhalt_natuerliche_person_gb)
                nat_list = person.get("inhalt_natuerliche_person_gb") or []
                for nat in (nat_list if isinstance(nat_list, list) else [nat_list]):
                    if not isinstance(nat, dict):
                        continue
                    n = " ".join(filter(None, [
                        nat.get("name") or nat.get("nachname") or nat.get("Name") or "",
                        nat.get("vorname") or nat.get("Vorname") or "",
                    ])).strip()
                    if n:
                        name = n
                        adr = nat.get("adresse") or nat.get("Adresse") or {}
                        addr = _addr_str(adr)
                        break

                # Helper: grab address from person_stamm.oeffentliche_koerperschaft
                stamm = person.get("person_stamm") or {}
                oek   = stamm.get("oeffentliche_koerperschaft") or {}

                # 2. Legal person (inhalt_juristische_person_gb)
                if not name:
                    jur_list = person.get("inhalt_juristische_person_gb") or []
                    for jur in (jur_list if isinstance(jur_list, list) else [jur_list]):
                        if not isinstance(jur, dict):
                            continue
                        n = (jur.get("name_firma") or jur.get("name") or
                             jur.get("Name") or jur.get("firmaname") or "").strip()
                        if n:
                            name = n
                            # Address lives in oek, not in jur itself
                            if isinstance(oek, dict):
                                adr = oek.get("adresse") or oek.get("Adresse") or {}
                            else:
                                adr = jur.get("adresse") or jur.get("Adresse") or {}
                            addr = _addr_str(adr)
                            break

                # 3. Public body (person_stamm.oeffentliche_koerperschaft)
                if not name:
                    if isinstance(oek, dict):
                        n = (oek.get("name") or oek.get("Name") or "").strip()
                        if n:
                            name = n
                            adr = oek.get("adresse") or oek.get("Adresse") or {}
                            addr = _addr_str(adr)

                # 4. Fallback: direct name fields on person object
                if not name:
                    name = (person.get("name") or person.get("Name") or
                            person.get("bezeichnung") or "").strip()

                if name and not is_herrenlos_owner_text(name):
                    owners.append(name)
                    if addr:
                        addrs.append(addr)

        # Deduplicate while preserving order
        seen_owners: set[str] = set()
        unique_owners: list[str] = []
        unique_addrs:  list[str] = []
        for i, o in enumerate(owners):
            if o not in seen_owners:
                seen_owners.add(o)
                unique_owners.append(o)
                if i < len(addrs):
                    unique_addrs.append(addrs[i])

        owner = "; ".join(unique_owners) if unique_owners else None
        if owner is None:
            log.info("Potential herrenlos — no owner in Terravis response (EGRID=%s)", egrid)

        # Parcel IS in Grundbuch (200 response, parcels[] non-empty) but person[]
        # parsed out no owner names → most likely genuine dereliktion (Art. 964 ZGB)
        h_type = None if owner else "dereliktion"
        return {
            "owner":          owner,
            "owner_address":  "; ".join(unique_addrs) or None,
            "is_herrenlos":   0 if owner else 1,
            "herrenlos_type": h_type,
            "claim_possible": claim_possible_for("GR", h_type) if h_type else None,
            # Store full JSON for herrenlos parcels so we can inspect the
            # Terravis response and verify the classification post-hoc.
            "raw_response":   str(data) if owner is None else None,
            "error":          None,
        }

    except Exception as exc:
        return {"owner": None, "owner_address": None,
                "is_herrenlos": None, "herrenlos_type": None, "claim_possible": None,
                "raw_response": None, "error": str(exc)}


# ── Main scanner ─────────────────────────────────────────────────────────────

def _gr_session(proxy_url: str | None = None) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = UA
    if proxy_url:
        s.proxies.update({"http": proxy_url, "https": proxy_url})
    return s


def scan(limit: int | None = None,
         skip_existing: bool = True,
         delay: float = 2.0):
    """
    Scan GR parcels for herrenlos detection.

    First run: ~3 min WFS enumeration via geodienste.ch (wfs_enum.py).
    Subsequent runs: use cached list directly.

    Rate limit: 10 queries/day per IP.
    Set GR_PROXY_LIST in .env (comma/newline-separated proxy URLs or
    Webshare host:port:user:pass format) to rotate IPs automatically.
    With 10 proxies: 100 queries/day → full 226k scan in ~6 years.
    With 100 proxies: ~7 months. For faster coverage add more proxies.

    limit         : stop after N queries (None = all)
    skip_existing : skip parcels already in DB
    delay         : seconds between requests
    """
    init_db()

    # GR has ~226k parcels in 100+ communes (verified by WFS).  The swisstopo 500m grid scan
    # only found 6,292 (7% of the canton); WFS finds all of them in ~3 min.
    with get_conn() as conn:
        cached = enum_cached(conn, "GR")
    if cached and len(cached) >= 80_000:
        log.info("Using cached GR parcel list (%d parcels)", len(cached))
        parcels = cached
    else:
        if cached:
            log.info("GR cache incomplete (%d parcels) — re-enumerating via WFS", len(cached))
            with get_conn() as conn:
                conn.execute("DELETE FROM enum.parcel_enum WHERE canton='GR'")  # MED-7 fix: must qualify with 'enum.' schema
                conn.commit()
        log.info("Enumerating GR parcels via geodienste WFS (~3 min) …")
        parcels = wfs_enumerate_canton("GR")
        with get_conn() as conn:
            store_enum(conn, "GR", parcels)
        log.info("Cached %d GR parcels (WFS)", len(parcels))

    if limit:
        parcels = parcels[:limit]

    proxies = load_proxies("GR_PROXY_LIST")
    proxy_idx = 0
    queries_on_proxy = 0
    ROTATE_EVERY = 10   # full 10/day per proxy (was 9 — wasted 1 slot per proxy)
    consecutive_429 = 0
    # All proxies are exhausted once we've seen more consecutive 429s than we
    # have proxies (each proxy rotated and still returned 429 on both attempts).
    MAX_CONSECUTIVE_429 = max(len(proxies) * 2, 5) if proxies else 5

    if proxies:
        log.info("GR proxy rotation: %d proxies, rotate every %d queries "
                 "(circuit breaker after %d consecutive 429s)",
                 len(proxies), ROTATE_EVERY, MAX_CONSECUTIVE_429)

    session = _gr_session(proxies[0] if proxies else None)

    scanned = errors = herrenlos = 0

    with get_conn() as conn:
        for p in parcels:
            egrid  = p["egrid"]
            bfs    = p["bfs_nr"]
            nr     = p["parcel_nr"]
            commune = p.get("commune", "")

            if skip_existing and already_scanned(conn, "GR", bfs, nr):
                continue

            # Proactive proxy rotation (before hitting the hard limit)
            if proxies and queries_on_proxy >= ROTATE_EVERY:
                proxy_idx = (proxy_idx + 1) % len(proxies)
                session = _gr_session(proxies[proxy_idx])
                queries_on_proxy = 0
                log.info("GR proactive proxy rotate → proxy #%d", proxy_idx)

            result = check_owner(session, egrid)
            queries_on_proxy += 1

            if result.get("error") == "rate_limited":
                # HIGH-2 fix: count ONE consecutive 429 per parcel, not two.
                # Original code incremented both on the initial 429 AND on a
                # failed retry, causing the circuit breaker to fire at half the
                # intended threshold (N proxies instead of N*2).
                # New logic: rotate + retry first; if retry also 429, count once.
                if proxies:
                    proxy_idx = (proxy_idx + 1) % len(proxies)
                    session = _gr_session(proxies[proxy_idx])
                    queries_on_proxy = 0
                    log.warning("GR rate limit — rotated to proxy #%d", proxy_idx)
                    time.sleep(2)
                    result = check_owner(session, egrid)
                    queries_on_proxy += 1
                    if result.get("error") == "rate_limited":
                        consecutive_429 += 1
                        if consecutive_429 >= MAX_CONSECUTIVE_429:
                            log.warning(
                                "GR all proxies exhausted — %d consecutive 429s. "
                                "Daily quota fully used.", consecutive_429
                            )
                            break
                    else:
                        consecutive_429 = 0
                else:
                    log.warning(
                        "GR rate limit hit with no proxies — stopping scan for today. "
                        "Set GR_PROXY_LIST to rotate IPs, or run again tomorrow."
                    )
                    break
            else:
                consecutive_429 = 0

            upsert_parcel(conn, {
                "egrid":       egrid,
                "canton":      "GR",
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
            if result.get("error") and result["error"] != "rate_limited":
                errors += 1

            if scanned % 50 == 0:
                log.info("Progress %d  herrenlos=%d  errors=%d", scanned, herrenlos, errors)

            time.sleep(delay)

    log.info("GR scan done — scanned=%d  herrenlos=%d  errors=%d", scanned, herrenlos, errors)
    return {"scanned": scanned, "herrenlos": herrenlos, "errors": errors}
