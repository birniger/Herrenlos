#!/usr/bin/env bash
# install-tokencheck.sh — wire up the daily token health-check LaunchAgent.
#
# What it does:
#   • Installs a LaunchAgent plist that runs check_tokens.py every morning at 08:57
#   • If BE or VS tokens are expired it fires a clickable macOS notification
#     (requires terminal-notifier: brew install terminal-notifier)
#   • Tapping the notification opens Terminal and runs the relevant scanner,
#     which will do the login flow and then continue scanning automatically
#
# Usage:
#   bash scripts/install-tokencheck.sh           # install and arm
#   bash scripts/install-tokencheck.sh stop      # stop and remove
#   bash scripts/install-tokencheck.sh status    # show current state
#   bash scripts/install-tokencheck.sh run       # run the check right now
#
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PLIST_TEMPLATE="$SCRIPT_DIR/com.herrenlos.tokencheck.plist"
PLIST_DST="$HOME/Library/LaunchAgents/com.herrenlos.tokencheck.plist"
LABEL="com.herrenlos.tokencheck"
CHECK_TOKENS="$SCRIPT_DIR/check_tokens.py"
LOG_OUT="/tmp/herrenlos-tokencheck.log"
LOG_ERR="/tmp/herrenlos-tokencheck.err"

# Prefer venv python, fall back to system python3
if [ -x "$PROJECT_DIR/.venv/bin/python" ]; then
    PYTHON="$PROJECT_DIR/.venv/bin/python"
else
    PYTHON="$(command -v python3)"
fi

# ── Helpers ───────────────────────────────────────────────────────────────────

die()  { echo "✗  $*" >&2; exit 1; }
info() { echo "   $*"; }

# ── Sub-commands ──────────────────────────────────────────────────────────────

cmd_stop() {
    if launchctl list "$LABEL" &>/dev/null; then
        launchctl unload "$PLIST_DST" 2>/dev/null && echo "✓  Token-check job stopped."
    else
        echo "   Token-check job is not loaded."
    fi
    [ -f "$PLIST_DST" ] && rm -f "$PLIST_DST" && echo "   Plist removed from LaunchAgents."
}

cmd_status() {
    echo "Herrenlos token health-check"
    echo "  Plist:        $PLIST_DST"
    echo "  check_tokens: $CHECK_TOKENS"
    echo "  Log (stdout): $LOG_OUT"
    echo "  Log (stderr): $LOG_ERR"
    echo ""
    if launchctl list "$LABEL" &>/dev/null; then
        echo "  Status:  LOADED — fires daily at 08:57"
    else
        echo "  Status:  NOT loaded"
    fi
    echo ""
    echo "  Token status right now:"
    "$PYTHON" "$CHECK_TOKENS" || true
    echo ""
    echo "  Recent log (last 20 lines of $LOG_OUT):"
    [ -f "$LOG_OUT" ] && tail -20 "$LOG_OUT" || echo "  (no log yet)"
}

cmd_run() {
    echo "Running token check now (with --notify) …"
    "$PYTHON" "$CHECK_TOKENS" --notify
}

# ── Main: install ─────────────────────────────────────────────────────────────

main() {
    case "${1:-}" in
        stop)   cmd_stop;   exit 0 ;;
        status) cmd_status; exit 0 ;;
        run)    cmd_run;    exit 0 ;;
    esac

    echo ""
    echo "Herrenlos scanner — token health-check installer"
    echo "================================================="
    echo ""

    # Sanity checks
    [ -f "$PLIST_TEMPLATE" ]  || die "Plist template not found: $PLIST_TEMPLATE"
    [ -f "$CHECK_TOKENS" ]    || die "check_tokens.py not found: $CHECK_TOKENS"
    command -v terminal-notifier &>/dev/null || {
        echo "⚠️  terminal-notifier not found — notifications will be non-clickable."
        echo "   Install it with:  brew install terminal-notifier"
        echo ""
    }

    # Ensure LaunchAgents directory exists
    mkdir -p "$HOME/Library/LaunchAgents"

    # Unload any existing version first
    if launchctl list "$LABEL" &>/dev/null; then
        info "Unloading existing token-check job..."
        launchctl unload "$PLIST_DST" 2>/dev/null || true
    fi

    # Materialise the plist with real paths
    sed \
        -e "s|__PYTHON__|${PYTHON}|g" \
        -e "s|__CHECK_TOKENS__|${CHECK_TOKENS}|g" \
        -e "s|__PROJECT_DIR__|${PROJECT_DIR}|g" \
        -e "s|__HOME__|${HOME}|g" \
        "$PLIST_TEMPLATE" > "$PLIST_DST"

    info "Plist written to: $PLIST_DST"

    # Load
    launchctl load "$PLIST_DST"

    echo ""
    echo "✓  Token health-check installed."
    echo ""
    info "check_tokens.py will run every morning at 08:57."
    info "If BE or VS tokens are expired, a notification fires."
    info "Tapping the notification opens Terminal and starts the scanner."
    echo ""
    info "Test it now:  bash scripts/install-tokencheck.sh run"
    info "Logs:         tail -f $LOG_OUT"
    info "Status:       bash scripts/install-tokencheck.sh status"
    info "Stop:         bash scripts/install-tokencheck.sh stop"
    echo ""
}

main "$@"
