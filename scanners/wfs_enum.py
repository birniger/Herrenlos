"""
wfs_enum.py — universal cantonal parcel enumeration via geodienste.ch AV WFS
============================================================================

Replaces the swisstopo `identify` grid scan that systematically under-counted
urban parcels (each grid cell only returns ONE parcel at the centre, so dense
communes were missing ~75-90% of their parcels).

geodienste.ch publishes every canton's Amtliche Vermessung as a single WFS
service (`ms:RESF` = Liegenschaften). It returns ALL parcels with full
attributes (BFSNr, parcel number, EGRID, commune identifier) and supports
pagination via STARTINDEX. No authentication required — this is federally
mandated public AV data per Art. 10 GeoIG.

Supported cantons (per the FILTER_ALLOWED_CANTONS list returned by the WFS):
  AG, AI, AR, BE, BL, BS, FR, GE, GL, GR, SG, SH, SO, SZ, TG, TI, UR, VS,
  ZG, ZH

NOT supported (use canton-specific approach instead):
  JU, NE, LU, NW, OW   — these publish AV via their own portals
                          (we already have working enumeration for those)

Throughput: ~5000 features per request, ~3 requests/sec → a full canton scan
finishes in 1-10 minutes depending on size (BE ~120s, GR ~60s, SH ~10s).
"""

import logging
import re
import time
from typing import Iterator

import requests

log = logging.getLogger("WFS-Enum")

WFS_URL    = "https://wfs.geodienste.ch/av_0/deu"
PAGE_SIZE  = 5000  # WFS allows up to this; larger pages = fewer requests
REQ_DELAY  = 0.3   # polite to geodienste

SUPPORTED_CANTONS = {
    "AG", "AI", "AR", "BE", "BL", "BS", "FR", "GE", "GL", "GR",
    "SG", "SH", "SO", "SZ", "TG", "TI", "UR", "VS", "ZG", "ZH",
}


# Pre-compile field regexes for speed (~5x faster than per-feature re.search).
_PATTERNS = {
    "bfs":    re.compile(r"<ms:BFSNr>([^<]+)</ms:BFSNr>"),
    "ident":  re.compile(r"<ms:NBIdent>([^<]+)</ms:NBIdent>"),
    "nummer": re.compile(r"<ms:Nummer>([^<]+)</ms:Nummer>"),
    "egrid":  re.compile(r"<ms:EGRIS_EGRID>([^<]+)</ms:EGRIS_EGRID>"),
    "flaeche": re.compile(r"<ms:Flaeche>([^<]+)</ms:Flaeche>"),
    "kanton": re.compile(r"<ms:Kanton>([^<]+)</ms:Kanton>"),
}
_MEMBER_RE  = re.compile(r"<wfs:member>(.*?)</wfs:member>", re.DOTALL)
_MATCHED_RE = re.compile(r'numberMatched="([^"]+)"')
_RETURN_RE  = re.compile(r'numberReturned="([^"]+)"')
_POS_LIST_RE = re.compile(r'<gml:posList[^>]*>([^<]+)</gml:posList>')


def _centroid_lv95(pos_str: str) -> tuple[int, int] | None:
    """Return (east, north) centroid in LV95 integers from a gml:posList string."""
    try:
        nums = [float(x) for x in pos_str.split()]
        if len(nums) < 2:
            return None
        easts  = nums[0::2]
        norths = nums[1::2]
        return (round(sum(easts) / len(easts)), round(sum(norths) / len(norths)))
    except Exception:
        return None


def _canton_filter(canton: str) -> str:
    """OGC XML filter for canton equality. The simpler CQL_FILTER syntax
    triggers a server-side query rewrite that ignores the filter and returns
    all cantons — XML filter is the only form that actually filters."""
    return (
        f'<Filter xmlns="http://www.opengis.net/ogc">'
        f'<PropertyIsEqualTo>'
        f'<PropertyName>Kanton</PropertyName>'
        f'<Literal>{canton.upper()}</Literal>'
        f'</PropertyIsEqualTo>'
        f'</Filter>'
    )


def _parse_features(xml: str) -> Iterator[dict]:
    """Yield {bfs_nr, parcel_nr, egrid, commune, flaeche, extra} dicts from one WFS page."""
    for member in _MEMBER_RE.finditer(xml):
        body = member.group(1)
        bfs    = _PATTERNS["bfs"].search(body)
        ident  = _PATTERNS["ident"].search(body)
        nummer = _PATTERNS["nummer"].search(body)
        egrid  = _PATTERNS["egrid"].search(body)
        flaeche = _PATTERNS["flaeche"].search(body)
        if not (bfs and nummer):
            continue   # malformed; skip
        pos_m = _POS_LIST_RE.search(body)
        coords = _centroid_lv95(pos_m.group(1)) if pos_m else None
        yield {
            "bfs_nr":    bfs.group(1),
            "parcel_nr": nummer.group(1),
            "commune":   ident.group(1) if ident else "",
            "egrid":     egrid.group(1) if egrid else "",
            "flaeche":   flaeche.group(1) if flaeche else None,
            "extra":     {"east": coords[0], "north": coords[1]} if coords else None,
        }


def enumerate_canton(canton: str, max_pages: int | None = None) -> list[dict]:
    """
    Enumerate all parcels for `canton` via geodienste.ch WFS.

    Returns: list of {bfs_nr, parcel_nr, commune (NBIdent), egrid, flaeche} dicts.
    Each parcel appears once.  Use `max_pages` to cap during testing.
    """
    canton = canton.upper()
    if canton not in SUPPORTED_CANTONS:
        raise ValueError(
            f"{canton} not supported by geodienste WFS. "
            f"Supported: {sorted(SUPPORTED_CANTONS)}"
        )

    session = requests.Session()
    session.headers["User-Agent"] = "herrenlos-scanner/wfs_enum (research)"

    parcels: list[dict] = []
    seen: set[tuple] = set()
    start_index = 0
    page = 0

    log.info("WFS enumeration starting for %s (geodienste.ch)", canton)

    while True:
        params = {
            "SERVICE": "WFS",
            "VERSION": "2.0.0",
            "REQUEST": "GetFeature",
            "TypeName": "ms:RESF",
            "COUNT": str(PAGE_SIZE),
            "STARTINDEX": str(start_index),
            "FILTER": _canton_filter(canton),
        }
        try:
            r = session.get(WFS_URL, params=params, timeout=60)
            if r.status_code != 200:
                log.warning("WFS returned HTTP %d at offset %d — stopping",
                            r.status_code, start_index)
                break

            xml = r.text
            mr = _RETURN_RE.search(xml)
            returned = int(mr.group(1)) if mr else 0

            added = 0
            for feat in _parse_features(xml):
                key = (feat["bfs_nr"], feat["parcel_nr"])
                if key in seen:
                    continue
                seen.add(key)
                parcels.append(feat)
                added += 1

            page += 1
            log.info("  page %d: returned=%d new=%d total=%d",
                     page, returned, added, len(parcels))

            if returned < PAGE_SIZE:
                # Last page — WFS returned less than a full page
                break
            if max_pages and page >= max_pages:
                log.info("  stopping at max_pages=%d", max_pages)
                break

            start_index += PAGE_SIZE
            time.sleep(REQ_DELAY)

        except Exception as e:
            log.error("WFS error at offset %d: %s — retrying once", start_index, e)
            time.sleep(2.0)
            try:
                r2 = session.get(WFS_URL, params=params, timeout=60)
                if r2.status_code == 200:
                    for feat in _parse_features(r2.text):
                        key = (feat["bfs_nr"], feat["parcel_nr"])
                        if key not in seen:
                            seen.add(key)
                            parcels.append(feat)
                    page += 1
                    start_index += PAGE_SIZE
                    time.sleep(REQ_DELAY)
                    continue
            except Exception as e2:
                log.error("WFS retry also failed at offset %d: %s — skipping page", start_index, e2)
            # Give up this page; advance to avoid infinite loop
            start_index += PAGE_SIZE

    log.info("WFS enumeration complete: %d unique %s parcels", len(parcels), canton)
    return parcels


if __name__ == "__main__":
    # CLI: python -m scanners.wfs_enum BE
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s")
    canton = sys.argv[1].upper() if len(sys.argv) > 1 else "SH"
    pages = int(sys.argv[2]) if len(sys.argv) > 2 else None
    rows = enumerate_canton(canton, max_pages=pages)
    print(f"\n{canton}: {len(rows)} parcels enumerated")
    if rows:
        print("Sample:", rows[0])
        # show coverage stats
        communes = {r["bfs_nr"] for r in rows}
        print(f"Communes: {len(communes)}")
        with_egrid = sum(1 for r in rows if r["egrid"])
        print(f"With EGRID: {with_egrid}/{len(rows)} ({100*with_egrid/len(rows):.1f}%)")
