#!/usr/bin/env python3
"""
Merge one herrenlos SQLite database into another.

Usage:
    python scripts/merge_dbs.py <src.db> <dst.db>

Copies every row from src that does not already exist in dst
(judged by the UNIQUE(canton, bfs_nr, parcel_nr) constraint on both
parcel_enum and parcels).  The auto-increment 'id' column is excluded so
SQLite assigns fresh IDs and there are no primary-key collisions.

Typical use — pull in concurrent local scans before CI commits:

    git show origin/main:herrenlos.db > _origin.db
    python scripts/merge_dbs.py _origin.db herrenlos.db
    rm _origin.db

Or merge two local databases:

    python scripts/merge_dbs.py other.db herrenlos.db
"""
from __future__ import annotations

import os
import sqlite3
import sys

# Per-table merge plan.  parcel_enum lives in the sibling enum.db file
# (gitignored, regenerable), NOT in herrenlos.db, so we never merge it here —
# enum data is reconstructible via geodienste WFS and merging stale enum rows
# from a remote DB would just leave outdated cache around.
MAIN_TABLES = ["parcels"]


def merge_one_table(conn: sqlite3.Connection, tbl: str, src_path: str) -> None:
    cols = [
        row[1]
        for row in conn.execute(f"PRAGMA main.table_info({tbl})")
        if row[1] != "id"
    ]
    if not cols:
        print(f"[merge_dbs] {tbl}: table not found in dst — skipping")
        return
    col_str = ", ".join(cols)
    try:
        cur = conn.execute(
            f"INSERT OR IGNORE INTO main.{tbl} ({col_str}) "
            f"SELECT {col_str} FROM src.{tbl}"
        )
        added = cur.rowcount
    except Exception as exc:
        print(f"[merge_dbs] {tbl}: ERROR — {exc}")
        return
    total_src = conn.execute(f"SELECT COUNT(*) FROM src.{tbl}").fetchone()[0]
    print(f"[merge_dbs] {tbl}: {added} / {total_src} rows added from {os.path.basename(src_path)}")


def merge(src_path: str, dst_path: str) -> None:
    """Merge src_path into dst_path in-place."""
    if not os.path.exists(src_path):
        print(f"[merge_dbs] src not found: {src_path!r} — skipping")
        return
    if not os.path.exists(dst_path):
        print(f"[merge_dbs] dst not found: {dst_path!r} — skipping")
        return

    conn = sqlite3.connect(dst_path, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("ATTACH DATABASE ? AS src", (src_path,))

    # Handle legacy DBs that still have parcel_enum in herrenlos.db:
    # if src has it, copy into the local enum.db so we don't lose anything.
    src_has_legacy_enum = conn.execute(
        "SELECT name FROM src.sqlite_master WHERE type='table' AND name='parcel_enum'"
    ).fetchone() is not None

    for tbl in MAIN_TABLES:
        merge_one_table(conn, tbl, src_path)

    if src_has_legacy_enum:
        # Open the local enum.db and pull rows in.  Done in a separate
        # connection so SQLite doesn't tangle WAL state across attached DBs.
        enum_db = os.path.join(os.path.dirname(dst_path), "enum.db")
        ec = sqlite3.connect(enum_db, timeout=30)
        ec.execute("PRAGMA journal_mode=WAL")
        ec.execute("ATTACH DATABASE ? AS src", (src_path,))
        # Recreate the table if enum.db is brand new
        ec.execute("""
            CREATE TABLE IF NOT EXISTS parcel_enum (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                canton        TEXT NOT NULL,
                bfs_nr        TEXT NOT NULL,
                parcel_nr     TEXT NOT NULL,
                commune       TEXT,
                egrid         TEXT,
                extra         TEXT,
                enumerated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(canton, bfs_nr, parcel_nr)
            )
        """)
        try:
            cur = ec.execute("""
                INSERT OR IGNORE INTO main.parcel_enum
                  (canton, bfs_nr, parcel_nr, commune, egrid, extra, enumerated_at)
                SELECT canton, bfs_nr, parcel_nr, commune, egrid, extra, enumerated_at
                  FROM src.parcel_enum
            """)
            print(f"[merge_dbs] parcel_enum (legacy → enum.db): {cur.rowcount} rows added")
        except Exception as e:
            print(f"[merge_dbs] parcel_enum legacy merge skipped: {e}")
        ec.commit()
        ec.close()

    conn.commit()
    conn.execute("DETACH DATABASE src")
    conn.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <src.db> <dst.db>")
        sys.exit(1)
    src, dst = sys.argv[1], sys.argv[2]
    merge(src, dst)
    print("[merge_dbs] done.")
