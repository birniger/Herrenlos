#!/usr/bin/env python3
"""
migrate_parcel_enum.py — finalise the parcel_enum split.

Drops the legacy `parcel_enum` table from herrenlos.db once data has been
copied to enum.db (done automatically by init_db()).  Then VACUUMs
herrenlos.db so the freed pages are reclaimed (the file shrinks from ~120 MB
back to ~7 MB).

Run when no scanner processes are writing to the DB:

    ./scripts/migrate_parcel_enum.py

Safe to re-run: skips work if the legacy table is already gone.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
DB   = ROOT / "herrenlos.db"


def main() -> int:
    conn = sqlite3.connect(DB, timeout=30)
    legacy = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='parcel_enum'"
    ).fetchone()
    if not legacy:
        print("[migrate] main.parcel_enum already dropped — nothing to do.")
        conn.close()
        return 0

    # Confirm data was already copied to enum.db
    conn.execute(f"ATTACH DATABASE '{ROOT / 'enum.db'}' AS enum")
    main_count = conn.execute("SELECT COUNT(*) FROM main.parcel_enum").fetchone()[0]
    enum_count = conn.execute("SELECT COUNT(*) FROM enum.parcel_enum").fetchone()[0]
    print(f"[migrate] main.parcel_enum: {main_count:,} rows")
    print(f"[migrate] enum.parcel_enum: {enum_count:,} rows")
    if enum_count < main_count:
        print(f"[migrate] REFUSING — enum.db has fewer rows than main, copy first")
        conn.close()
        return 1

    try:
        conn.execute("DROP TABLE main.parcel_enum")
        conn.commit()
        print("[migrate] Dropped main.parcel_enum")
    except sqlite3.OperationalError as e:
        print(f"[migrate] DROP failed (DB locked? scanner running?): {e}")
        conn.close()
        return 2

    conn.close()
    # Reclaim freed pages — must VACUUM in a separate connection with no
    # active transactions.
    conn = sqlite3.connect(DB, timeout=60)
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    print("[migrate] VACUUMing herrenlos.db (may take a minute)…")
    conn.execute("VACUUM")
    conn.close()

    size_mb = DB.stat().st_size / 1024 / 1024
    print(f"[migrate] herrenlos.db now {size_mb:.1f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
