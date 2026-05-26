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

# Checkpoint WAL into the main DB file before staging.
# Without this, rows written since the last checkpoint sit in herrenlos.db-wal
# and are invisible to git (which reads the raw file, not SQLite's WAL view).
# PASSIVE: checkpoints all frames it can without blocking active writers.
# CRIT-3 fix: warn if checkpoint is incomplete (active writers still holding WAL frames).
"$PYTHON" -c "
import sqlite3, sys, time
for attempt in range(3):
    try:
        c = sqlite3.connect('herrenlos.db', timeout=10)
        wal_pages, checkpointed = c.execute('PRAGMA wal_checkpoint(PASSIVE)').fetchone()[1:]
        c.close()
        print(f'[push_local] WAL checkpoint: {checkpointed}/{wal_pages} pages flushed')
        if wal_pages > 0 and checkpointed < wal_pages:
            print(f'[push_local] WARNING: {wal_pages - checkpointed} WAL pages not flushed '
                  f'(active writers present) — DB snapshot may be slightly stale', file=sys.stderr)
        break
    except Exception as e:
        print(f'[push_local] WAL checkpoint attempt {attempt+1} failed: {e}')
        time.sleep(2)
"

# Stage the DB and any dashboard exports.
git add herrenlos.db
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
    git add herrenlos.db
    rm -f _origin.db
fi
# CRIT-2 fix: amend the scan commit with the freshly-merged DB BEFORE rebasing.
# Without this the rebase replays the pre-merge DB, discarding merge_dbs.py output.
git commit --amend --no-edit

# Use -X ours (not -X theirs) so git keeps OUR herrenlos.db (which already
# contains origin's rows via merge_dbs.py above).  -X theirs would replace it
# with origin's unmerged version, leaving the scanner's in-progress WAL pointing
# at a different DB salt → "database disk image is malformed" on next connection.
git rebase origin/main -X ours || git rebase --abort

# After any rebase, truncate the WAL so the file on disk is fully self-contained.
# Running scanners may have stale WAL state from before the rebase; TRUNCATE
# forces a clean checkpoint that any new connection will see consistently.
"$PYTHON" -c "
import sqlite3, sys
try:
    c = sqlite3.connect('herrenlos.db', timeout=10)
    total, done = c.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[1:]
    c.close()
    print(f'[push_local] WAL truncated after rebase ({done}/{total} pages)')
except Exception as e:
    print(f'[push_local] WAL truncate warning: {e}', file=sys.stderr)
"

git push
echo "[push_local] Pushed OK (after rebase)."
