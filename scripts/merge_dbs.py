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

TABLES = ["parcel_enum", "parcels"]


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

    for tbl in TABLES:
        # Exclude the auto-increment PK so SQLite assigns fresh IDs in dst,
        # avoiding collisions when both DBs were built independently.
        cols = [
            row[1]
            for row in conn.execute(f"PRAGMA main.table_info({tbl})")
            if row[1] != "id"
        ]
        if not cols:
            print(f"[merge_dbs] {tbl}: table not found in dst — skipping")
            continue

        col_str = ", ".join(cols)
        try:
            cur = conn.execute(
                f"INSERT OR IGNORE INTO main.{tbl} ({col_str}) "
                f"SELECT {col_str} FROM src.{tbl}"
            )
            added = cur.rowcount
        except Exception as exc:
            print(f"[merge_dbs] {tbl}: ERROR — {exc}")
            continue

        total_src = conn.execute(f"SELECT COUNT(*) FROM src.{tbl}").fetchone()[0]
        print(f"[merge_dbs] {tbl}: {added} / {total_src} rows added from {os.path.basename(src_path)}")

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
