#!/usr/bin/env python3
"""
Picks which canton the next GitHub Actions scan run should work on.

Strategy:
  1. Among the ELIGIBLE list (cantons known to work from a datacenter IP),
     pick the one with the largest gap = enumerated - scanned.
  2. If every eligible canton is fully scanned (no gap), pick the first
     eligible one that hasn't been enumerated yet — this kicks off enumeration.
  3. As a last fallback, just rotate to the first eligible canton.

Prints the chosen canton's lower-case code on stdout. The workflow YAML
captures it via $(python scripts/pick_canton.py).

Eligibility criteria (all must be true):
  - Accessible from a GitHub Actions datacenter IP (no residential proxy)
  - No interactive login (OAuth / password / reCAPTCHA Enterprise)
  - Scanner can run headless in CI (no Playwright requirement)

Current eligible cantons:
  ur  — swisstopo REST + cantonal WFS, no CAPTCHA, no login
  fr  — keycloak public session, no CAPTCHA, no residential IP
  ju  — public + OCR-solvable CAPTCHA (ddddocr), no login
  sz  — public + OCR-solvable CAPTCHA (ddddocr), no login

NOT eligible (excluded reasons):
  bs  — cmd_bs only collects metadata (Type A only, no owner names).
         Full detection needs bs_public (Playwright + reCAPTCHA Enterprise,
         10 req/day/IP). Add bs back once bs_public can run in CI.
  ne  — reCAPTCHA Enterprise + ip_rotation deferred
  ge  — reCAPTCHA Enterprise + ip_rotation deferred
  so  — Playwright + reCAPTCHA, ip_rotation deferred
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
# Order matters only for the strategy-3 fallback (all-zeros case).
# Strategy 1 (biggest gap) dominates in practice.
ELIGIBLE_DEFAULT = ["ur", "fr", "ju", "sz"]


def pick() -> str:
    eligible = os.environ.get("ELIGIBLE_CANTONS", " ".join(ELIGIBLE_DEFAULT)).split()
    if not eligible:
        eligible = ELIGIBLE_DEFAULT

    init_db()
    with get_conn() as conn:
        # Gap = enumerated parcels − parcels with is_herrenlos IS NOT NULL.
        # Larger gap = more work outstanding for that canton.
        rows = conn.execute("""
            SELECT LOWER(pe.canton)                                              AS canton,
                   COUNT(pe.id) - COALESCE(SUM(
                       CASE WHEN p.is_herrenlos IS NOT NULL THEN 1 ELSE 0 END), 0) AS gap
              FROM parcel_enum pe
              LEFT JOIN parcels p
                     ON p.canton = pe.canton
                    AND p.bfs_nr = pe.bfs_nr
                    AND p.parcel_nr = pe.parcel_nr
             GROUP BY LOWER(pe.canton)
        """).fetchall()

    by_canton = {r["canton"]: r["gap"] for r in rows}

    # Strategy 1: pick the eligible canton with the largest positive gap.
    best, best_gap = None, 0
    for c in eligible:
        gap = by_canton.get(c, 0)
        if gap > best_gap:
            best, best_gap = c, gap
    if best is not None:
        return best

    # Strategy 2: pick the first eligible canton with no enumeration yet —
    # this triggers a one-time enumeration on first run.
    enumerated = set(by_canton)
    for c in eligible:
        if c not in enumerated:
            return c

    # Strategy 3: just rotate to the first eligible canton.
    return eligible[0]


if __name__ == "__main__":
    print(pick())
