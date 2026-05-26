import json
import sqlite3
from pathlib import Path

# Module-level guards to avoid repeated PRAGMA calls per upsert/enum operation.
# These are set to True the first time the migration check runs; after that
# we skip the PRAGMA table_info() round-trips entirely.
_parcels_migrated: bool = False
_parcel_enum_migrated: bool = False

DB_PATH      = Path(__file__).parent / "herrenlos.db"
ENUM_DB_PATH = Path(__file__).parent / "enum.db"


def get_conn() -> sqlite3.Connection:
    """
    Open a connection with robust concurrency settings.

    The scanner runs multiple processes against the same DB file:
      - launchd `run_local.py` and its `main.py <canton>` subprocess
      - manual scripts (export_for_web.py, push_local.sh's checkpoint)
      - the CI scanner during its run window
    Without `busy_timeout`, a writer holding the lock for >5s causes the
    other writer to fail with "database is locked" — and if it fails
    mid-transaction the indexes can end up inconsistent (we've seen
    "wrong # of entries in index idx_egrid" several times after concurrent
    writes during enum backfills).

    Settings:
      - timeout=30          : Python's default is 5s; bump to 30 so brief
                              WAL checkpoints don't fail concurrent writers.
      - PRAGMA busy_timeout : SQLite-level wait when another process holds
                              the lock (separate from Python's `timeout=`).
      - WAL journal mode    : allows one writer + many readers in parallel.
      - synchronous=NORMAL  : safe with WAL, much faster than FULL.
    """
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")     # 30s waits for locks
    conn.execute("PRAGMA synchronous=NORMAL")     # WAL-safe, faster than FULL
    conn.execute("PRAGMA wal_autocheckpoint=1000")  # checkpoint every 1000 pages
    # Attach the enumeration cache as a separate database (`enum.db`).
    # parcel_enum lives there (~90 MB for a fully-enumerated all-cantons run)
    # because:
    #   1. It's regenerable: any canton can be re-enumerated via the geodienste
    #      WFS in 1-10 minutes (see scanners/wfs_enum.py).
    #   2. Keeping it in `herrenlos.db` pushed the file over GitHub's 100 MB
    #      hard limit; splitting it lets us commit `herrenlos.db` (~7 MB) again.
    # The `enum.db` file is gitignored.  All scripts that join parcels with
    # enumeration use the `enum.parcel_enum` qualified table name.
    conn.execute(f"ATTACH DATABASE '{ENUM_DB_PATH}' AS enum")
    conn.execute("PRAGMA enum.journal_mode=WAL")
    conn.execute("PRAGMA enum.busy_timeout=30000")
    conn.execute("PRAGMA enum.synchronous=NORMAL")
    return conn


def init_db():
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS parcels (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                egrid           TEXT,
                canton          TEXT NOT NULL,
                commune         TEXT,
                bfs_nr          TEXT,
                parcel_nr       TEXT,
                parcel_type     TEXT,
                owner           TEXT,
                owner_address   TEXT,
                is_herrenlos    INTEGER,   -- 1=herrenlos, 0=has owner, NULL=not scanned
                herrenlos_type  TEXT,      -- 'dereliktion'|'not_in_grundbuch'|'no_owner'|NULL
                                           --   dereliktion    = Art.964 ZGB: parcel IS in GB, owner deleted → potentially claimable
                                           --   not_in_grundbuch = Art.664 ZGB: parcel not in GB, auto-cantonal → NOT claimable
                                           --   no_owner       = in GB, owner field blank (parse ambiguity or old entry)
                claim_possible  INTEGER,   -- 1=potentially claimable, 0=not claimable, NULL=unknown
                raw_response    TEXT,
                error           TEXT,
                scanned_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(canton, bfs_nr, parcel_nr)
            );

            CREATE TABLE IF NOT EXISTS captcha_stats (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                canton    TEXT NOT NULL,
                solver    TEXT NOT NULL,   -- 'ddddocr' | 'tesseract' | 'claude' | 'none'
                outcome   TEXT NOT NULL,   -- 'correct' | 'wrong' | 'unsolved'
                noted_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- Persistent test-run history. Every invocation of run_tests() stores
            -- one row per canton/tier so we can answer "what works today and what
            -- doesn't, and why" without re-running tests.
            CREATE TABLE IF NOT EXISTS test_runs (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                canton              TEXT NOT NULL,
                tier                TEXT NOT NULL,    -- 'A' | 'B'
                test_group          TEXT,             -- 'rest' | 'captcha_ocr' | 'captcha_pow' | 'own_login' | 'blocked'
                status              TEXT NOT NULL,    -- 'pass' | 'fail' | 'skip' | 'blocked' | 'warn'
                parcels_attempted   INTEGER DEFAULT 0,
                parcels_scanned     INTEGER DEFAULT 0,
                false_positives     INTEGER DEFAULT 0,
                errors              INTEGER DEFAULT 0,
                blocker             TEXT,             -- short reason if status != 'pass'
                needs               TEXT,             -- what would unblock
                notes               TEXT,             -- free-form details
                run_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_canton          ON parcels(canton);
            CREATE INDEX IF NOT EXISTS idx_herrenlos       ON parcels(is_herrenlos);
            CREATE INDEX IF NOT EXISTS idx_egrid           ON parcels(egrid);
            -- NOTE: no explicit (canton, bfs_nr, parcel_nr) index needed here.
            -- The UNIQUE constraint already creates sqlite_autoindex_parcels_1 on
            -- those columns; EXPLAIN QUERY PLAN confirms SQLite uses it for every
            -- already_scanned() lookup and ON CONFLICT resolution.
            CREATE INDEX IF NOT EXISTS idx_captcha_canton  ON captcha_stats(canton);
            CREATE INDEX IF NOT EXISTS idx_testruns_canton ON test_runs(canton);
            CREATE INDEX IF NOT EXISTS idx_testruns_runat  ON test_runs(run_at);

            -- parcel_enum lives in the attached `enum` database (enum.db).
            -- This file is gitignored and regenerable; keeping it out of
            -- herrenlos.db lets that file stay small enough to commit.
            CREATE TABLE IF NOT EXISTS enum.parcel_enum (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                canton      TEXT NOT NULL,
                bfs_nr      TEXT NOT NULL,
                parcel_nr   TEXT NOT NULL,
                commune     TEXT,
                egrid       TEXT,
                extra       TEXT,
                enumerated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(canton, bfs_nr, parcel_nr)
            );
            CREATE INDEX IF NOT EXISTS enum.idx_enum_canton ON parcel_enum(canton);
        """)

    # One-time migration: copy parcel_enum data from herrenlos.db to enum.db
    # if it still exists in the old location and enum.db is still empty.
    with get_conn() as conn:
        legacy = conn.execute(
            "SELECT name FROM main.sqlite_master WHERE type='table' AND name='parcel_enum'"
        ).fetchone()
        if legacy:
            already_migrated = conn.execute(
                "SELECT COUNT(*) FROM enum.parcel_enum"
            ).fetchone()[0]
            if already_migrated == 0:
                print("[db] Migrating parcel_enum from herrenlos.db → enum.db…")
                n = conn.execute("""
                    INSERT OR IGNORE INTO enum.parcel_enum
                        (canton, bfs_nr, parcel_nr, commune, egrid, extra, enumerated_at)
                    SELECT canton, bfs_nr, parcel_nr, commune, egrid, extra, enumerated_at
                      FROM main.parcel_enum
                """).rowcount
                conn.commit()
                print(f"[db] Copied {n} rows to enum.db")

    # Permanent guard: drop legacy tables from herrenlos.db whenever they appear.
    # merge_dbs.py can re-introduce parcel_enum (750 k rows, ~85 MB) and
    # lost_and_found (90 k rows) from a pre-migration CI DB, bloating herrenlos.db
    # past GitHub's 100 MB hard limit.  Running this guard on every init_db()
    # call prevents that from ever sticking.
    # CRIT-4 fix: wrap both DROPs in an explicit transaction so they are atomic.
    # In Python's sqlite3, DDL statements cause an implicit COMMIT of any pending
    # transaction, then run in autocommit mode — so without BEGIN/COMMIT the two
    # drops are NOT atomic (a crash between them leaves a half-dropped state).
    with get_conn() as conn:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM main.sqlite_master WHERE type='table'"
        ).fetchall()}
        to_drop = [t for t in ("parcel_enum", "lost_and_found") if t in tables]
        if to_drop:
            conn.execute("BEGIN EXCLUSIVE")
            for _legacy in to_drop:
                conn.execute(f"DROP TABLE IF EXISTS main.{_legacy}")
            conn.commit()
            print(f"[db] Dropped legacy tables from herrenlos.db: {', '.join(to_drop)}")


def _migrate_parcel_enum(conn):
    """Add egrid / extra columns to parcel_enum if they don't exist yet (one-time migration).

    Uses a module-level guard so the PRAGMA table_info() round-trip only happens
    once per process lifetime — not on every enum_cached() / store_enum() call.
    """
    global _parcel_enum_migrated
    if _parcel_enum_migrated:
        return
    existing = {row[1] for row in conn.execute("PRAGMA enum.table_info(parcel_enum)").fetchall()}
    if "egrid" not in existing:
        conn.execute("ALTER TABLE enum.parcel_enum ADD COLUMN egrid TEXT")
    if "extra" not in existing:
        conn.execute("ALTER TABLE enum.parcel_enum ADD COLUMN extra TEXT")
    conn.commit()
    _parcel_enum_migrated = True


def enum_cached(conn, canton: str) -> list[dict] | None:
    """
    Return cached enumeration for *canton*, or None if not yet enumerated.
    Returns a list of {bfs_nr, parcel_nr, commune, egrid, extra} dicts.
    extra is a JSON string that canton scanners may use for additional data
    (e.g. NE stores the owner UUID there).
    """
    _migrate_parcel_enum(conn)
    rows = conn.execute(
        "SELECT bfs_nr, parcel_nr, commune, egrid, extra FROM enum.parcel_enum WHERE canton=?",
        (canton,)
    ).fetchall()
    if not rows:
        return None
    result = []
    for r in rows:
        d = dict(r)
        # Decode extra JSON blob into a nested dict if present
        if d.get("extra"):
            try:
                d["extra"] = json.loads(d["extra"])
            except Exception:
                pass
        result.append(d)
    return result


def store_enum(conn, canton: str, parcels: list[dict]):
    """
    Persist enumeration results for *canton* into the cache.
    Each dict must have bfs_nr, parcel_nr, commune keys.
    Optional keys: egrid, extra (dict or str; dicts are JSON-serialised).
    """
    _migrate_parcel_enum(conn)
    rows = []
    for p in parcels:
        extra = p.get("extra")
        if isinstance(extra, dict):
            extra = json.dumps(extra, separators=(",", ":"))
        # If the parcel has a uuid field (NE-style), pack it into extra
        if extra is None and p.get("uuid"):
            extra = json.dumps({"uuid": p["uuid"]}, separators=(",", ":"))
        rows.append({
            "canton":    canton,
            "bfs_nr":    p.get("bfs_nr", ""),
            "parcel_nr": p.get("parcel_nr", ""),
            "commune":   p.get("commune", ""),
            "egrid":     p.get("egrid", ""),
            "extra":     extra,
        })
    conn.executemany("""
        INSERT OR IGNORE INTO enum.parcel_enum (canton, bfs_nr, parcel_nr, commune, egrid, extra)
        VALUES (:canton, :bfs_nr, :parcel_nr, :commune, :egrid, :extra)
    """, rows)
    conn.commit()


def already_scanned(conn, canton: str, bfs_nr: str, parcel_nr: str) -> bool:
    row = conn.execute(
        "SELECT id FROM parcels WHERE canton=? AND bfs_nr=? AND parcel_nr=? AND is_herrenlos IS NOT NULL",
        (canton, str(bfs_nr), str(parcel_nr))
    ).fetchone()
    return row is not None


def upsert_parcel(conn, data: dict):
    # Migrate: add herrenlos_type and claim_possible columns if missing.
    # Use module-level guard to avoid PRAGMA table_info() on every call.
    global _parcels_migrated
    if not _parcels_migrated:
        existing_cols = {r[1] for r in conn.execute("PRAGMA table_info(parcels)").fetchall()}
        if "herrenlos_type" not in existing_cols:
            conn.execute("ALTER TABLE parcels ADD COLUMN herrenlos_type TEXT")
        if "claim_possible" not in existing_cols:
            conn.execute("ALTER TABLE parcels ADD COLUMN claim_possible INTEGER")
        _parcels_migrated = True

    # Provide defaults for new fields if caller didn't set them
    data.setdefault("herrenlos_type", None)
    data.setdefault("claim_possible", None)

    conn.execute("""
        INSERT INTO parcels
            (egrid, canton, commune, bfs_nr, parcel_nr, parcel_type,
             owner, owner_address, is_herrenlos, herrenlos_type, claim_possible,
             raw_response, error)
        VALUES
            (:egrid, :canton, :commune, :bfs_nr, :parcel_nr, :parcel_type,
             :owner, :owner_address, :is_herrenlos, :herrenlos_type, :claim_possible,
             :raw_response, :error)
        ON CONFLICT(canton, bfs_nr, parcel_nr) DO UPDATE SET
            egrid           = excluded.egrid,
            -- Only overwrite ownership fields when the new scan produced a
            -- definitive result (is_herrenlos IS NOT NULL).  A session error /
            -- transient failure (is_herrenlos = NULL) must never erase a
            -- previously confirmed herrenlos=1 or herrenlos=0 finding.
            owner           = CASE WHEN excluded.is_herrenlos IS NOT NULL
                                   THEN excluded.owner          ELSE owner          END,
            owner_address   = CASE WHEN excluded.is_herrenlos IS NOT NULL
                                   THEN excluded.owner_address  ELSE owner_address  END,
            is_herrenlos    = CASE WHEN excluded.is_herrenlos IS NOT NULL
                                   THEN excluded.is_herrenlos   ELSE is_herrenlos   END,
            herrenlos_type  = CASE WHEN excluded.is_herrenlos IS NOT NULL
                                   THEN excluded.herrenlos_type ELSE herrenlos_type END,
            claim_possible  = CASE WHEN excluded.is_herrenlos IS NOT NULL
                                   THEN excluded.claim_possible ELSE claim_possible END,
            raw_response    = CASE WHEN excluded.is_herrenlos IS NOT NULL
                                   THEN excluded.raw_response   ELSE raw_response   END,
            error           = excluded.error,   -- always record the latest attempt
            scanned_at      = CURRENT_TIMESTAMP
    """, data)
    conn.commit()


def log_captcha(canton: str, solver: str, outcome: str):
    """Record one CAPTCHA attempt. Never raises — stats must not crash a scan."""
    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO captcha_stats (canton, solver, outcome) VALUES (?, ?, ?)",
                (canton.upper(), solver, outcome),
            )
            conn.commit()
    except Exception:
        pass


def print_captcha_stats(canton: str = None):
    with get_conn() as conn:
        where  = "WHERE canton=?" if canton else ""
        params = (canton.upper(),) if canton else ()
        rows   = conn.execute(f"""
            SELECT canton, solver,
                   SUM(CASE WHEN outcome='correct'  THEN 1 ELSE 0 END) AS correct,
                   SUM(CASE WHEN outcome='wrong'    THEN 1 ELSE 0 END) AS wrong,
                   SUM(CASE WHEN outcome='unsolved' THEN 1 ELSE 0 END) AS unsolved,
                   COUNT(*) AS total
            FROM captcha_stats
            {where}
            GROUP BY canton, solver
            ORDER BY canton, solver
        """, params).fetchall()

    if not rows:
        label = canton.upper() if canton else "ALL"
        print(f"[{label}] No CAPTCHA stats recorded yet.")
        return

    print(f"\n{'Canton':<6} {'Solver':<12} {'Correct':>8} {'Wrong':>7} {'Unsolved':>9} {'Total':>7} {'Success%':>9}")
    print("-" * 62)
    for r in rows:
        c, w, u, t = r["correct"] or 0, r["wrong"] or 0, r["unsolved"] or 0, r["total"] or 0
        pct = f"{100 * c // t}%" if t else "—"
        print(f"{r['canton']:<6} {r['solver']:<12} {c:>8} {w:>7} {u:>9} {t:>7} {pct:>9}")
    print()


def requests_today(canton: str) -> int:
    """
    Best-effort count of how many real owner-lookup requests have been made for
    *canton* today (local time). Used by the test runner to respect daily-limit
    cantons like GR (10/day) and NE (~50/day) so a test invocation does not
    consume the entire daily IP quota.

    Counts:
      - parcels.scanned_at rows for this canton with date = today
      - test_runs.run_at rows for this canton with date = today (parcels_attempted)

    The two are summed because a scan in production and a test from the same IP
    both consume the same quota. This intentionally over-counts a little (a
    failed scan still counted as a request server-side) which is the safe side.
    """
    with get_conn() as conn:
        # MED-5 fix: scanned_at is stored as UTC (CURRENT_TIMESTAMP).
        # Use DATE(scanned_at, 'localtime') to convert to local time before
        # comparing — without this, scans done after midnight UTC but before
        # midnight Europe/Zurich are counted in the wrong day.
        scanned = conn.execute("""
            SELECT COUNT(*) FROM parcels
             WHERE canton=? AND DATE(scanned_at, 'localtime') = DATE('now', 'localtime')
        """, (canton.upper(),)).fetchone()[0]
        tested = conn.execute("""
            SELECT COALESCE(SUM(parcels_attempted), 0) FROM test_runs
             WHERE canton=? AND DATE(run_at, 'localtime') = DATE('now', 'localtime')
        """, (canton.upper(),)).fetchone()[0]
    return int(scanned) + int(tested)


def store_test_run(canton: str, tier: str, status: str, *,
                   test_group: str | None = None,
                   parcels_attempted: int = 0,
                   parcels_scanned:   int = 0,
                   false_positives:   int = 0,
                   errors:            int = 0,
                   blocker: str | None = None,
                   needs:   str | None = None,
                   notes:   str | None = None):
    """Persist one test-run outcome. Never raises."""
    try:
        with get_conn() as conn:
            conn.execute("""
                INSERT INTO test_runs
                    (canton, tier, test_group, status,
                     parcels_attempted, parcels_scanned, false_positives, errors,
                     blocker, needs, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (canton.upper(), tier, test_group, status,
                  parcels_attempted, parcels_scanned, false_positives, errors,
                  blocker, needs, notes))
            conn.commit()
    except Exception:
        pass


def latest_test_status() -> dict[str, dict]:
    """
    For every canton that has ever been tested, return the most recent test_run row.
    Returns: { 'JU': {tier, group, status, run_at, false_positives, blocker, needs}, ... }
    """
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT canton, tier, test_group AS `group`, status, run_at,
                   parcels_attempted, parcels_scanned, false_positives, errors,
                   blocker, needs
              FROM test_runs t1
             WHERE id = (
                 SELECT MAX(id) FROM test_runs t2
                  WHERE t2.canton = t1.canton AND t2.tier = t1.tier
             )
             ORDER BY canton, tier
        """).fetchall()
    out: dict[str, dict] = {}
    for r in rows:
        # Prefer TIER B over TIER A for "production readiness" view
        existing = out.get(r["canton"])
        if existing and existing["tier"] == "B" and r["tier"] == "A":
            continue
        out[r["canton"]] = dict(r)
    return out


def print_test_history(canton: str | None = None, days: int = 7, limit: int = 50):
    """Print recent test_runs rows. If `canton` given, filter to that canton."""
    with get_conn() as conn:
        where, params = [], []
        if canton:
            where.append("canton=?"); params.append(canton.upper())
        where.append("run_at >= datetime('now', ?)"); params.append(f"-{days} days")
        sql = f"""
            SELECT run_at, canton, tier, test_group, status,
                   parcels_attempted, parcels_scanned, false_positives, errors,
                   blocker, needs
              FROM test_runs
             WHERE {' AND '.join(where)}
             ORDER BY run_at DESC
             LIMIT {int(limit)}
        """
        rows = conn.execute(sql, params).fetchall()

    if not rows:
        label = canton.upper() if canton else "ALL"
        print(f"[{label}] No test_runs in the last {days} days.")
        return

    print(f"\n{'When':<19} {'Canton':<6} {'Tier':<4} {'Group':<13} {'Status':<7} {'Att':>4} {'Scan':>4} {'FP':>3} {'Err':>3}  Blocker / Needs")
    print("-" * 110)
    for r in rows:
        when = (r["run_at"] or "")[:19]
        block = r["blocker"] or ""
        needs = f"  ← needs: {r['needs']}" if r["needs"] else ""
        print(f"{when:<19} {r['canton']:<6} {r['tier']:<4} {(r['test_group'] or ''):<13} {r['status']:<7} "
              f"{(r['parcels_attempted'] or 0):>4} {(r['parcels_scanned'] or 0):>4} "
              f"{(r['false_positives'] or 0):>3} {(r['errors'] or 0):>3}  {block}{needs}")
    print()


def print_stats(canton: str = None):
    with get_conn() as conn:
        where = "WHERE canton=?" if canton else ""
        params = (canton,) if canton else ()
        total     = conn.execute(f"SELECT COUNT(*) FROM parcels {where}", params).fetchone()[0]
        scanned   = conn.execute(f"SELECT COUNT(*) FROM parcels {where} {'AND' if canton else 'WHERE'} is_herrenlos IS NOT NULL", params).fetchone()[0]
        herrenlos = conn.execute(f"SELECT COUNT(*) FROM parcels {where} {'AND' if canton else 'WHERE'} is_herrenlos=1", params).fetchone()[0]
        errors    = conn.execute(f"SELECT COUNT(*) FROM parcels {where} {'AND' if canton else 'WHERE'} error IS NOT NULL", params).fetchone()[0]
    label = canton or "ALL"
    print(f"[{label}] total={total}  scanned={scanned}  herrenlos={herrenlos}  errors={errors}")
