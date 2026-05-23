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

RESTART_DELAY=60
attempt=1

while true; do
    echo "[scan-loop $(date '+%Y-%m-%d %H:%M:%S')] starting run_local.py (attempt $attempt)"
    "$PYTHON" scripts/run_local.py
    rc=$?

    if [ "$rc" -eq 0 ]; then
        echo "[scan-loop $(date '+%Y-%m-%d %H:%M:%S')] run_local.py exited cleanly (rc=0). Bye."
        exit 0
    fi

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
