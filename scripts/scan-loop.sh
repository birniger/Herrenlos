#!/usr/bin/env bash
#
# scan-loop.sh — keep the local scanner running through crashes, network
# disconnects, and laptop sleep/wake cycles.
#
# Loops forever: each iteration runs scripts/run_local.py (which itself loops
# canton → canton). If run_local.py exits non-zero (Python crash, OOM, network
# stack failure, etc.) this wrapper waits 60s and restarts it. If it exits 0
# (Ctrl+C) the wrapper exits too — that's the user telling us to stop.
#
# Usage:
#   ./scripts/scan-loop.sh
#
# Stop with Ctrl+C — both the inner Python loop and this wrapper exit cleanly.
#
# Optional: pass extra eligibility via environment variable:
#   LOCAL_ELIGIBLE_CANTONS="ur sh ne so" ./scripts/scan-loop.sh
#
# For unattended runs across reboots on macOS, see the launchd recipe at the
# bottom of this file.

set -u

# Resolve repo root from this script's location (works from any cwd)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Prefer the project venv if it exists
if [ -x ".venv/bin/python" ]; then
    PYTHON=".venv/bin/python"
else
    PYTHON="$(command -v python3 || command -v python)"
fi

if [ -z "$PYTHON" ]; then
    echo "ERROR: no python interpreter found." >&2
    exit 1
fi

# Forward SIGINT/SIGTERM to the child cleanly
trap 'echo; echo "[scan-loop] interrupted, exiting."; exit 0' INT TERM

# Checkpoint any stale WAL before starting.
# Blindly deleting herrenlos.db-wal loses committed rows that haven't been
# flushed to the main DB file yet — the root cause of lost herrenlos findings.
# Instead: checkpoint first (flushes WAL into the main file), THEN remove only
# the now-empty shm/wal files.
if [ -f "herrenlos.db-wal" ]; then
    echo "[scan-loop] stale WAL detected — checkpointing before startup"
    # CRIT-1 fix: only remove WAL files if the checkpoint fully succeeded.
    # Blindly deleting herrenlos.db-wal without a successful TRUNCATE checkpoint
    # loses committed rows that haven't been flushed to the main DB file yet.
    if "$PYTHON" -c "
import sqlite3, sys
try:
    c = sqlite3.connect('herrenlos.db', timeout=10)
    wal_pages, checkpointed = c.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[1:]
    c.close()
    print(f'[scan-loop] WAL checkpoint: {checkpointed}/{wal_pages} pages flushed')
    if wal_pages > 0 and checkpointed < wal_pages:
        print(f'[scan-loop] WARNING: WAL not fully checkpointed ({checkpointed}/{wal_pages}) — NOT removing WAL files', file=sys.stderr)
        sys.exit(1)
except Exception as e:
    print(f'[scan-loop] WAL checkpoint failed: {e}', file=sys.stderr)
    sys.exit(1)
" 2>&1; then
        rm -f herrenlos.db-wal herrenlos.db-shm
    else
        echo "[scan-loop] WAL checkpoint failed or incomplete — NOT removing WAL files; data is safe" >&2
    fi
fi

RESTART_DELAY=60
attempt=1

# ── Sync helpers ─────────────────────────────────────────────────────────────

_pull_from_github() {
    # Merge any new CI rows from origin/main into the local DB.
    # Read-only from git's perspective — no commit, no push.
    echo "[scan-loop] syncing CI rows from origin/main..."
    git fetch origin main 2>/dev/null || { echo "[scan-loop] git fetch failed — skipping sync"; return; }
    if git show origin/main:herrenlos.db > _origin.db 2>/dev/null; then
        "$PYTHON" scripts/merge_dbs.py _origin.db herrenlos.db
        rm -f _origin.db
    else
        echo "[scan-loop] no herrenlos.db on origin/main yet — skipping merge"
    fi
}

_push_to_github() {
    # Checkpoint WAL, merge CI data, commit, push.  Uses push_local.sh which
    # already handles rebase-on-conflict with retries.
    echo "[scan-loop] pushing local scan results to GitHub..."
    bash scripts/push_local.sh "auto" 2>&1 || echo "[scan-loop] push failed — will retry next cycle"
}

_sync_proxies() {
    # Refresh Webshare proxy list in .env + GitHub secret so stale/replaced
    # proxies never silently kill GR/SH/NE progress.  Non-fatal if API is down.
    "$PYTHON" scripts/sync_proxies.py --update-secret 2>&1 || true
}

# ── Main loop ─────────────────────────────────────────────────────────────────

while true; do
    # Sync Webshare proxy list so replaced proxies don't silently break GR/SH/NE.
    _sync_proxies

    # Pull latest CI data before each run so the picker gap numbers are fresh
    # and we don't re-scan parcels CI already covered.
    _pull_from_github

    echo "[scan-loop $(date '+%Y-%m-%d %H:%M:%S')] starting run_local.py (attempt $attempt)"
    "$PYTHON" scripts/run_local.py
    rc=$?

    if [ "$rc" -eq 0 ]; then
        echo "[scan-loop $(date '+%Y-%m-%d %H:%M:%S')] run_local.py exited cleanly (rc=0). Bye."
        exit 0
    fi

    # run_local.py crashed — push whatever was scanned before the crash.
    _push_to_github
    echo "[scan-loop $(date '+%Y-%m-%d %H:%M:%S')] run_local.py exited rc=$rc — sleeping ${RESTART_DELAY}s before restart."
    sleep "$RESTART_DELAY"
    attempt=$((attempt + 1))
done

# ── Optional: auto-start at login on macOS ──────────────────────────────────
#
# Create ~/Library/LaunchAgents/ch.herrenlos.scanloop.plist with:
#
#   <?xml version="1.0" encoding="UTF-8"?>
#   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
#       "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
#   <plist version="1.0">
#   <dict>
#     <key>Label</key>          <string>ch.herrenlos.scanloop</string>
#     <key>ProgramArguments</key>
#       <array>
#         <string>/path/to/herrenlos_scanner/scripts/scan-loop.sh</string>
#       </array>
#     <key>RunAtLoad</key>      <true/>
#     <key>KeepAlive</key>      <true/>
#     <key>StandardOutPath</key><string>/tmp/herrenlos-scan.log</string>
#     <key>StandardErrorPath</key><string>/tmp/herrenlos-scan.err</string>
#   </dict>
#   </plist>
#
# Then:
#   launchctl load ~/Library/LaunchAgents/ch.herrenlos.scanloop.plist
#   launchctl start ch.herrenlos.scanloop
#
# This launches scan-loop.sh at every login and restarts it if it crashes.
# Logs land in /tmp/herrenlos-scan.log. Stop with:
#   launchctl unload ~/Library/LaunchAgents/ch.herrenlos.scanloop.plist
