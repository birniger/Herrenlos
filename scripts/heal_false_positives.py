#!/usr/bin/env python3
"""
Heal stuck false-positive herrenlos rows so the fixed scanners re-evaluate them.

WHY THIS EXISTS
---------------
Two scanner bugs flagged parcels as herrenlos that are not:

  • GR — proxy IPs at their daily limit made Terravis return HTTP 400 with
    {"detail":"GetParcelByIdFault"} / {"detail":"Unknown fault occured"} instead
    of 429.  The old scanner read that as "not in Grundbuch".
  • BS — api.geo.bs.ch occasionally returned 200 with an empty RealEstates[]
    for a whole batch; the old scanner marked every EGRID in the batch absent.

Both scanners are now fixed (they classify these as retriable errors, not
herrenlos).  But a row already committed with is_herrenlos=1 is SKIPPED by
already_scanned() — so the fixed code never gets a chance to re-evaluate it.
The bad classification is carried forward forever.

THE HEAL
--------
Reset each matching row to is_herrenlos=NULL with a FRESH scanned_at timestamp:

  • is_herrenlos=NULL  → already_scanned() returns False → scanner re-queries it.
  • fresh scanned_at   → the prefer-newer merge in merge_dbs.py propagates this
    correction across concurrent CI runs instead of letting a stale copy win.

After the next scan pass each parcel gets its correct classification
(owner found → is_herrenlos=0, or a genuine signal preserved).

TIMING
------
Only effective once every in-flight run is using the prefer-newer merge
(commit 9091c22 or later).  A run still on the old INSERT-OR-IGNORE merge will
clobber the heal, because its working copy wins every key conflict.  Verify no
pre-fix run is active (gh run list) before relying on this.

USAGE
-----
    python scripts/heal_false_positives.py            # apply
    python scripts/heal_false_positives.py --dry-run  # report only
"""
from __future__ import annotations

import sqlite3
import sys
import os

DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "herrenlos.db")

# Each entry: (label, WHERE clause) selecting confirmed false positives.
# Keep these SIGNATURE-BASED, never blanket "all herrenlos in canton X", so a
# genuine future finding is never wiped.
HEAL_RULES = [
    # GR Terravis error-envelope false positives.  A 404/400 from Terravis is
    # always a transient error, never a herrenlos signal — the genuine "not in
    # Grundbuch" case is a 200 with missing[] (Python-repr'd as {'parcels': [],
    # 'missing': [...]} — single-quoted, no "detail" key).  Every JSON error
    # envelope {"detail": ...} (GetParcelByIdFault, "Unknown fault occured",
    # "Upstream server is not available", …) was a transient failure on a real
    # parcel.  Matching the double-quoted "detail": key catches them all while
    # never touching the genuine single-quoted missing[] response.
    ("GR Terravis error-envelope false positives",
     "canton='GR' AND is_herrenlos=1 AND raw_response LIKE '%\"detail\":%'"),

    # All 89 BS is_herrenlos=1 rows were live-probed 2026-06-10 and confirmed
    # present in api.geo.bs.ch (empty-batch artifacts).  BS cannot yet detect a
    # genuine herrenlos anyway (owner data is behind the HTML/captcha path), so
    # any is_herrenlos=1 here is by definition an empty-batch false positive.
    ("BS empty-batch false positives",
     "canton='BS' AND is_herrenlos=1"),

    # Old-code artifact: a parcel with no EGRID can't be looked up; resetting it
    # lets the scanner record a proper error instead of a phantom herrenlos.
    ("SZ no-EGRID artifact",
     "canton='SZ' AND is_herrenlos=1 AND (egrid IS NULL OR egrid='')"),

    # GR partial-response false positives: a 200 with parcels[] present but the
    # ownership section empty (person[]=[] AND recht[]=[]) was flagged dereliktion
    # even though the data had simply failed to load (e.g. CH187008007792 / parcel
    # 300 Vaz/Obervaz — a StWE condominium with 3 recht shares on re-fetch).  The
    # scanner now returns a retriable partial_response for this shape; reset the
    # already-committed ones so they re-scan.  Signature-based on the empty-both
    # ownership sections, so genuine dereliktion (populated section, no owner)
    # is never matched.
    ("GR partial-response false positives",
     "canton='GR' AND is_herrenlos=1 AND herrenlos_type='dereliktion' "
     "AND raw_response LIKE '%''person'': []%' AND raw_response LIKE '%''recht'': []%'"),
]


def main() -> int:
    dry_run = "--dry-run" in sys.argv
    conn = sqlite3.connect(DB, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")

    total = 0
    for label, where in HEAL_RULES:
        n = conn.execute(f"SELECT COUNT(*) FROM parcels WHERE {where}").fetchone()[0]
        total += n
        print(f"[heal] {label}: {n} rows")
        if not dry_run and n:
            conn.execute(
                f"UPDATE parcels SET "
                f"  is_herrenlos=NULL, herrenlos_type=NULL, claim_possible=NULL, "
                f"  owner=NULL, owner_address=NULL, "
                f"  error='reset_false_positive', "
                f"  scanned_at=datetime('now') "
                f"WHERE {where}"
            )

    if dry_run:
        print(f"[heal] DRY RUN — would reset {total} rows. No changes written.")
    else:
        conn.commit()
        print(f"[heal] reset {total} rows to is_herrenlos=NULL (fresh timestamp).")
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
