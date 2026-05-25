#!/usr/bin/env python3
"""
Picks which canton the next GitHub Actions scan run should work on.

Strategy:
  0. If any eligible canton has no real enumeration yet (enum count below
     REAL_ENUM_MIN), pick it first — in ELIGIBLE order — to kick off
     enumeration before a large already-enumerated canton dominates the gap.
  1. Among fully-enumerated eligible cantons, pick the one with the largest
     gap = enumerated − scanned.
  2. As a last fallback (all gaps zero), rotate to the first eligible canton.

Why strategy 0 matters:
  If canton A has 16,000 enumerated parcels and canton B only has test seeds
  (5–11 rows), strategy 1 always picks A even though B has never been
  enumerated.  Strategy 0 fixes this by prioritising unenumerated cantons
  so every canton eventually gets scanned.

Prints the chosen canton's lower-case code on stdout. The workflow YAML
captures it via $(python scripts/pick_canton.py).

Eligibility criteria (all must be true):
  - Accessible from a GitHub Actions datacenter IP (no residential proxy)
  - No interactive login (OAuth / password / reCAPTCHA Enterprise)
  - Scanner can run headless in CI (no Playwright requirement)

Current eligible cantons (set via ELIGIBLE_CANTONS env var in scan.yml):
  ju  — public + OCR-solvable CAPTCHA (ddddocr), no login       (~14k parcels)
  sz  — public + OCR-solvable CAPTCHA (ddddocr), no login       (~50k parcels)
  sh  — pure requests; 100 req/day/IP; rotated via SH_PROXY_LIST (~43k parcels)
  gr  — pure requests; 10 req/day/IP;  rotated via GR_PROXY_LIST (~226k parcels)

NOT eligible (excluded reasons):
  fr  — keycloak.fr.ch geo-blocks datacenter IPs; laptop scan loop only
  ne  — sitn.ne.ch blocks datacenter proxies; laptop only (residential IP req.)
  ur  — geo.ur.ch blocks datacenter IPs ("access denied for your country")
  bs  — cmd_bs is metadata-only (no owner names, no Type B detection)
  ge  — Imperva + image CAPTCHA; needs proxies + ANTHROPIC_API_KEY
  so  — Playwright + reCAPTCHA; needs proxies
  bl  — handwritten cursive CAPTCHA, OCR 0% accuracy
"""

from __future__ import annotations
import os
import sys
import pathlib

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from db import init_db, get_conn   # noqa: E402

# Cantons that work cleanly from a GitHub Actions datacenter IP.
# Order is the priority for strategy 0 (enumeration) and strategy 2 (fallback).
ELIGIBLE_DEFAULT = ["ju", "sz", "sh", "gr"]

# A real enumeration produces at least this many parcel_enum rows.
# Below this threshold the canton is treated as "not yet enumerated".
# Values well above known test-seed counts (≤11) but below smallest real
# canton (SZ ~18k → use 100 as a safe floor for all).
REAL_ENUM_MIN = 100


def pick() -> str | None:
    eligible = os.environ.get("ELIGIBLE_CANTONS", " ".join(ELIGIBLE_DEFAULT)).split()
    if not eligible:
        eligible = ELIGIBLE_DEFAULT

    # Cantons to skip this invocation (e.g. already exhausted their proxy
    # quota in the current CI job).  Passed via EXCLUDE_CANTONS env var.
    exclude = set(os.environ.get("EXCLUDE_CANTONS", "").lower().split())
    eligible = [c for c in eligible if c not in exclude]
    if not eligible:
        return None

    init_db()
    with get_conn() as conn:
        # enum_count  = rows in parcel_enum for this canton
        # scanned     = subset that already has a result in parcels
        rows = conn.execute("""
            SELECT LOWER(pe.canton)                                              AS canton,
                   COUNT(pe.id)                                                 AS enum_count,
                   COUNT(pe.id) - COALESCE(SUM(
                       CASE WHEN p.is_herrenlos IS NOT NULL THEN 1 ELSE 0 END), 0) AS gap
              FROM enum.parcel_enum pe
              LEFT JOIN parcels p
                     ON p.canton = pe.canton
                    AND p.bfs_nr = pe.bfs_nr
                    AND p.parcel_nr = pe.parcel_nr
             GROUP BY LOWER(pe.canton)
        """).fetchall()

    enum_count = {r["canton"]: r["enum_count"] for r in rows}
    by_gap     = {r["canton"]: r["gap"]        for r in rows}

    # Strategy 0: kick off enumeration for any canton that hasn't been properly
    # enumerated yet (missing entirely or only has test seeds).
    for c in eligible:
        if enum_count.get(c, 0) < REAL_ENUM_MIN:
            return c

    # Strategy 1: pick the eligible canton with the largest positive gap.
    best, best_gap = None, 0
    for c in eligible:
        gap = by_gap.get(c, 0)
        if gap > best_gap:
            best, best_gap = c, gap
    if best is not None:
        return best

    # Strategy 2: all gaps zero — rotate to first eligible canton for re-scan.
    return eligible[0]


if __name__ == "__main__":
    result = pick()
    if result is None:
        sys.exit(1)   # signals the caller (scan loop) that no cantons remain
    print(result)
