#!/usr/bin/env bash
# install-watchdog.sh — wire up the launchd watchdog for the herrenlos scanner.
#
# What it does:
#   • Installs a LaunchAgent plist that starts scan-loop.sh at login
#   • launchd keeps scan-loop.sh alive (auto-restarts if it crashes or exits)
#   • Throttle interval: 5 min — prevents restart storms on repeated failure
#   • Logs: /tmp/herrenlos-scanner.log  (stdout)
#           /tmp/herrenlos-scanner.err  (stderr)
#
# Usage:
#   bash scripts/install-watchdog.sh          # install and start
#   bash scripts/install-watchdog.sh stop     # stop and remove
#   bash scripts/install-watchdog.sh status   # print current status
#
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PLIST_TEMPLATE="$SCRIPT_DIR/com.herrenlos.watchdog.plist"
PLIST_DST="$HOME/Library/LaunchAgents/com.herrenlos.watchdog.plist"
LABEL="com.herrenlos.watchdog"
SCAN_LOOP="$PROJECT_DIR/scripts/scan-loop.sh"
LOG_OUT="/tmp/herrenlos-scanner.log"
LOG_ERR="/tmp/herrenlos-scanner.err"

# ── Helpers ───────────────────────────────────────────────────────────────────

die() { echo "✗  $*" >&2; exit 1; }
info() { echo "   $*"; }

# ── Sub-commands ──────────────────────────────────────────────────────────────

cmd_stop() {
    if launchctl list "$LABEL" &>/dev/null; then
        launchctl unload "$PLIST_DST" 2>/dev/null && echo "✓  Watchdog stopped."
    else
        echo "   Watchdog is not loaded."
    fi
    [ -f "$PLIST_DST" ] && rm -f "$PLIST_DST" && echo "   Plist removed from LaunchAgents."
}

cmd_status() {
    echo "Herrenlos scanner watchdog"
    echo "  Plist:        $PLIST_DST"
    echo "  scan-loop:    $SCAN_LOOP"
    echo "  Log (stdout): $LOG_OUT"
    echo "  Log (stderr): $LOG_ERR"
    echo ""
    if launchctl list "$LABEL" &>/dev/null; then
        pid=$(launchctl list "$LABEL" | awk '/PID/ {print $NF}' 2>/dev/null || true)
        echo "  Status:  LOADED (PID ${pid:-unknown})"
    else
        echo "  Status:  NOT loaded"
    fi
    echo ""
    echo "  Recent log (last 20 lines of $LOG_OUT):"
    [ -f "$LOG_OUT" ] && tail -20 "$LOG_OUT" || echo "  (no log yet)"
}

# ── Main: install ─────────────────────────────────────────────────────────────

main() {
    case "${1:-}" in
        stop)   cmd_stop;   exit 0 ;;
        status) cmd_status; exit 0 ;;
    esac

    echo ""
    echo "Herrenlos scanner — watchdog installer"
    echo "======================================"
    echo ""

    # Sanity checks
    [ -f "$PLIST_TEMPLATE" ] || die "Plist template not found: $PLIST_TEMPLATE"
    [ -f "$SCAN_LOOP" ]      || die "scan-loop.sh not found: $SCAN_LOOP"
    chmod +x "$SCAN_LOOP"

    # Ensure LaunchAgents directory exists
    mkdir -p "$HOME/Library/LaunchAgents"

    # Unload any existing version first (ignore error if not loaded)
    if launchctl list "$LABEL" &>/dev/null; then
        info "Unloading existing watchdog..."
        launchctl unload "$PLIST_DST" 2>/dev/null || true
    fi

    # Materialise the plist with real paths
    sed \
        -e "s|__SCAN_LOOP__|${SCAN_LOOP}|g" \
        -e "s|__PROJECT_DIR__|${PROJECT_DIR}|g" \
        -e "s|__HOME__|${HOME}|g" \
        "$PLIST_TEMPLATE" > "$PLIST_DST"

    info "Plist written to: $PLIST_DST"

    # Load (and start immediately because RunAtLoad=true)
    launchctl load "$PLIST_DST"

    echo ""
    echo "✓  Watchdog installed and started."
    echo ""
    info "scan-loop.sh will start automatically at every login."
    info "launchd restarts it within 5 min if it crashes or exits."
    echo ""
    info "Logs:     tail -f $LOG_OUT"
    info "Errors:   tail -f $LOG_ERR"
    info "Status:   bash scripts/install-watchdog.sh status"
    info "Stop:     bash scripts/install-watchdog.sh stop"
    echo ""
}

main "$@"
