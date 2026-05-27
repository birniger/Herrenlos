#!/usr/bin/env bash
# push_local.sh — commit and push local scan results (BE/VS/FR) safely.
#
# Merges any CI-committed data (JU/SZ) that landed while the local scanner was
# running into herrenlos.db before committing, so the push is conflict-free.
#
# Usage (from repo root):
#   ./scripts/push_local.sh
#   ./scripts/push_local.sh "optional commit message suffix"

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [ -x ".venv/bin/python" ]; then
    PYTHON=".venv/bin/python"
else
    PYTHON="$(command -v python3)"
fi

MSG_SUFFIX="${1:-}"
DATE="$(date '+%Y-%m-%d %H:%M')"
COMMIT_MSG="local: be/vs/fr scan ${DATE}${MSG_SUFFIX:+ — $MSG_SUFFIX}"

echo "[push_local] Fetching origin/main..."
git fetch origin main

# Merge any new CI rows (JU/SZ) into the local DB before committing.
# This means our push will be fast-forward (or trivially rebased).
if git show origin/main:herrenlos.db > _origin.db 2>/dev/null; then
    echo "[push_local] Merging origin/main DB into local herrenlos.db..."
    "$PYTHON" scripts/merge_dbs.py _origin.db herrenlos.db
    rm -f _origin.db
else
    echo "[push_local] No herrenlos.db on origin/main yet — skipping merge."
fi

# Stage a consistent DB snapshot using Python's backup API.
#
# WHY NOT "PRAGMA wal_checkpoint + git add herrenlos.db":
#   PASSIVE checkpoint only flushes frames not held by active writers — if the
#   scanner is mid-write, some frames stay in the WAL and git stages a stale DB.
#   TRUNCATE (previously used post-rebase) is worse: it wipes WAL frames that the
#   running scanner still holds in memory → "database disk image is malformed".
#
# sqlite3.backup() reads through the WAL transparently and produces a complete,
# self-contained snapshot WITHOUT touching the live herrenlos.db or its WAL at all.
# git hash-object + update-index stages that snapshot in the git index without
# writing it back to the working tree — so the live file and its WAL are never
# disturbed.
_stage_db_snapshot() {
    "$PYTHON" - <<'PYEOF'
import sqlite3, subprocess, tempfile, os, sys

db = "herrenlos.db"
tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
tmp.close()
try:
    src = sqlite3.connect(db, timeout=30)
    dst = sqlite3.connect(tmp.name)
    src.backup(dst)         # reads through WAL — complete, consistent view
    src.close()
    dst.close()
    blob = subprocess.check_output(
        ["git", "hash-object", "-w", tmp.name]
    ).decode().strip()
    subprocess.run(
        ["git", "update-index", "--cacheinfo", f"100644,{blob},herrenlos.db"],
        check=True,
    )
    size_kb = os.path.getsize(tmp.name) // 1024
    print(f"[push_local] DB snapshot staged ({size_kb} KB)")
except Exception as e:
    print(f"[push_local] DB snapshot failed: {e}", file=sys.stderr)
    sys.exit(1)
finally:
    try:
        os.unlink(tmp.name)
    except Exception:
        pass
PYEOF
}

_stage_db_snapshot

# Regenerate dashboard exports, then stage everything.
"$PYTHON" scripts/export_for_web.py 2>/dev/null || true

git add docs/data/*.json docs/data/*.geojson docs/data/*.csv 2>/dev/null || true

if git diff --staged --quiet; then
    echo "[push_local] Nothing to commit."
    exit 0
fi

git commit -m "$COMMIT_MSG"

# Push with one rebase retry in case CI landed a commit between our fetch and push.
if git push; then
    echo "[push_local] Pushed OK."
    exit 0
fi

echo "[push_local] Push rejected — rebasing on origin/main..."
git fetch origin main
if git show origin/main:herrenlos.db > _origin.db 2>/dev/null; then
    "$PYTHON" scripts/merge_dbs.py _origin.db herrenlos.db
    rm -f _origin.db
fi

# CRIT-2 fix: amend the scan commit with the freshly-merged DB BEFORE rebasing.
# Without this the rebase replays the pre-merge DB, discarding merge_dbs.py output.
_stage_db_snapshot
git commit --amend --no-edit

# Use -X ours (not -X theirs) so git keeps OUR herrenlos.db (which already
# contains origin's rows via merge_dbs.py above).  -X theirs would replace it
# with origin's unmerged version, leaving the scanner's in-progress WAL pointing
# at a different DB salt → "database disk image is malformed" on next connection.
git rebase origin/main -X ours || git rebase --abort

# After the rebase, herrenlos.db on disk = our snapshot (same content and salt
# as what the running scanner's WAL was written against) so WAL consistency is
# intact.  Use PASSIVE (never TRUNCATE) to flush what we can; TRUNCATE would wipe
# WAL frames that an active scanner writer still holds in memory → corruption.
"$PYTHON" -c "
import sqlite3, sys
try:
    c = sqlite3.connect('herrenlos.db', timeout=10)
    total, done = c.execute('PRAGMA wal_checkpoint(PASSIVE)').fetchone()[1:]
    c.close()
    extra = f' ({total - done} held by active writer, OK)' if total > done else ''
    print(f'[push_local] post-rebase WAL checkpoint: {done}/{total} pages flushed{extra}')
except Exception as e:
    print(f'[push_local] post-rebase WAL checkpoint warning: {e}', file=sys.stderr)
"

git push
echo "[push_local] Pushed OK (after rebase)."
