#!/usr/bin/env python3
"""
Local bulk scanner — runs all eligible cantons in parallel, each in its own
thread with its own subprocess, cooldown, and error handling.

Eligible for bulk scanning from the laptop:

    BE  — one-time AGOV/BE-Login (Safari + AppleScript on macOS); ~400k parcels
          NOTE: GRUDIS enforces a per-account daily quota (account-level, not IP).
          When the quota is exhausted the loop cools BE down until midnight Bern time.
    VS  — one-time SwissID 2FA (Playwright window); ~210k parcels
    FR  — no login, no CAPTCHA; needs residential IP (keycloak.fr.ch geo-blocks
          GitHub Actions datacenter IPs). ~80k parcels; ~600-800/hr.
    BL  — needs ANTHROPIC_API_KEY (Claude vision for handwritten CAPTCHA); ~70k parcels

NOT included by design:
  - JU, SZ, SH, NE, GR : handled by GitHub Actions. NE/GR share the same Webshare
                          proxy quota — running them here too would just compete with CI
                          for the same 90-450 queries/day without adding throughput.
  - UR              : daily quota (10/day), geo-blocked from CI; use `python main.py ur`.
  - GE              : Imperva blocks ~30/IP even from residential; needs proxies
                      AND ANTHROPIC_API_KEY. Use `python main.py ge` separately.
  - SO              : the scanner is wired (scanners/so_public.py) but in practice
                      Google reCAPTCHA v3 degrades the score after ~2 successful
                      queries even from a Swiss residential IP — empirically
                      observed 96%+ failure rate. SO actually needs proxies
                      (was previously thought not to). Run via `python main.py so`
                      only after proxies/CAPTCHA service are wired.
  - BS-public, etc. : need proxies / institutional accounts.

Parallel mode: one thread per canton, each running `python main.py <canton>
--limit ROTATION_LIMIT` in a tight loop. Cantons no longer take turns; FR,
VS, BE, and BL scan simultaneously and restart as soon as their slice finishes.

Push to GitHub is debounced: at most one push every PUSH_DEBOUNCE_SECONDS
regardless of how many cantons finish around the same time.

Pre-flight: at startup, checks each eligible canton's prerequisites:
  - BE  : ~/.herrenlos_scanner/be_token.json exists?
  - VS  : ~/.herrenlos_scanner/vs_token.json exists?
  - BL  : ANTHROPIC_API_KEY in env / .env?
  - FR  : nothing -- just needs a Swiss residential IP

Configuration:
  LOCAL_ELIGIBLE_CANTONS env var (space-separated) overrides the default list.
  LOCAL_ROTATION_LIMIT   env var overrides ROTATION_LIMIT (default 3000).

Usage:
  python scripts/run_local.py                 # full default set
  LOCAL_ELIGIBLE_CANTONS="fr bl" python scripts/run_local.py

For auto-restart across crashes / network outages, use the bash wrapper:
  ./scripts/scan-loop.sh
"""
from __future__ import annotations

import datetime
import json
import logging
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import zoneinfo

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from db import init_db, get_conn  # noqa: E402

# Auto-load .env so ANTHROPIC_API_KEY (etc.) is visible to this process and to
# subprocesses. Mirrors main.py's own .env loader.
_env_file = PROJECT_ROOT / ".env"
if _env_file.exists():
    for _line in _env_file.read_text().splitlines():
        _line = _line.strip()
        if not _line or _line.startswith("#"):
            continue
        if _line.startswith("export "):
            _line = _line[7:]
        if "=" in _line:
            _k, _, _v = _line.partition("=")
            _k = _k.strip()
            _v = _v.strip().strip('"').strip("'")
            if _k and _v and _k not in os.environ:
                os.environ[_k] = _v

# ── Configuration ────────────────────────────────────────────────────────────

LOCAL_ELIGIBLE_DEFAULT = ["be", "vs", "fr", "bl"]

# enum_count below this = "not yet enumerated" (test seeds / empty).
REAL_ENUM_MIN = 100

# Backoff between failures, with a cap so we don't sleep forever.
RETRY_BASE_SECONDS = 30
RETRY_MAX_SECONDS  = 600

# Brief pause between consecutive rotation restarts for a given canton.
# In parallel mode this is only applied per-canton (other cantons aren't waiting).
INTER_CANTON_DELAY_SECONDS = 5

# Maximum parcels per canton invocation before restarting the subprocess.
# In parallel mode each canton loops independently so this is just a natural
# "restart checkpoint" — not a fairness mechanism.
ROTATION_LIMIT = int(os.environ.get("LOCAL_ROTATION_LIMIT", "3000"))

# Push debounce: even if 3 cantons finish simultaneously, only one push fires.
# Set low enough that results reach GitHub promptly, high enough to avoid races.
PUSH_DEBOUNCE_SECONDS = 120  # 2 minutes

# Token keepalive interval: refresh idle tokens during long cooldowns.
KEEPALIVE_INTERVAL = 900  # 15 min — well within any Keycloak idle timeout

# Login notification timing for BE/VS quota-reset cooldowns.
LOGIN_POLL_INTERVAL     = 180   # 3 min fast-poll after notification sent
LOGIN_NOTIFY_AHEAD_SECS = 900   # notify 15 min before quota reset when token dead
LOGIN_REPEAT_NOTIFY_INTERVAL = 86400  # at most 1 follow-up notification per day per canton

# Token cache (created on first interactive login by BE/VS scanners)
TOKEN_DIR = pathlib.Path.home() / ".herrenlos_scanner"

# Substrings in scanner output that suggest an authentication failure rather
# than a transient network/server hiccup.
AUTH_FAILURE_KEYWORDS = [
    "401", "unauthorized", "token expired", "refresh failed",
    "login required", "re-authenticate", "auth_failed",
    "invalid token", "no token cached",
]

# Substrings that indicate the scanner opened a login browser window but the
# user didn't complete the login within the timeout. The scanner exits rc=0
# in this case so we can't rely on exit code — detect these keywords instead.
LOGIN_TIMEOUT_KEYWORDS = [
    "timed out waiting for be token",
    "timed out waiting for vs token",
    "be login failed",
    "vs login failed",
    "re-login failed",
    "login not completed",
    "no token captured",
    "login failed",
    "login timed out",
]

log = logging.getLogger("local")

# ── Thread-safe subprocess registry (for clean Ctrl+C kill) ──────────────────

_active_procs: dict[str, "subprocess.Popen[bytes]"] = {}
_active_procs_lock = threading.Lock()

# Lock for stdout so parallel canton prefixes don't interleave mid-line.
_stdout_lock = threading.Lock()


# ── Per-canton token metadata ─────────────────────────────────────────────────

_TOKEN_META: dict[str, tuple[pathlib.Path, str, str]] = {
    "be": (
        pathlib.Path.home() / ".herrenlos_scanner" / "be_token.json",
        "https://sso.be.ch/auth/realms/a51-grudis-public-agov"
        "/protocol/openid-connect/token",
        "intercapi-public-client",
    ),
    "vs": (
        pathlib.Path.home() / ".herrenlos_scanner" / "vs_token.json",
        "https://sso.apps.vs.ch/auth/realms/etatvs"
        "/protocol/openid-connect/token",
        "capitastra-public-client",
    ),
}


# ── Pre-flight: per-canton prerequisite checks ───────────────────────────────

def _check_be() -> tuple[bool, str]:
    token = TOKEN_DIR / "be_token.json"
    if token.exists():
        return True, f"BE token found ({token})"
    return False, "BE token not found — needs one-time AGOV/BE-Login"


def _check_vs() -> tuple[bool, str]:
    token = TOKEN_DIR / "vs_token.json"
    if token.exists():
        return True, f"VS token found ({token})"
    return False, "VS token not found — needs one-time SwissID 2FA login"


def _check_bl() -> tuple[bool, str]:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return True, "ANTHROPIC_API_KEY set"
    return False, "ANTHROPIC_API_KEY not set in env/.env (needed for handwritten CAPTCHA)"


def _check_fr() -> tuple[bool, str]:
    return True, "FR needs no token (residential IP only)"


PREFLIGHT_CHECKS = {
    "be": {
        "check":      _check_be,
        "setup_cmd":  [sys.executable, "main.py", "be", "--limit", "1"],
        "setup_note": (
            "BE setup: Safari will open to grudis.apps.be.ch. Log in with your "
            "AGOV / BE-Login account. The scanner extracts the token via AppleScript "
            "('Allow JavaScript from Apple Events' must be enabled in Safari → Develop)."
        ),
    },
    "vs": {
        "check":      _check_vs,
        "setup_cmd":  [sys.executable, "main.py", "vs", "--limit", "1"],
        "setup_note": (
            "VS setup: a Playwright Chromium window opens. Log in with your SwissID "
            "account and complete 2FA. The token is cached automatically."
        ),
    },
    "bl": {
        "check":      _check_bl,
        "setup_cmd":  None,
        "setup_note": (
            "BL setup: add ANTHROPIC_API_KEY=sk-ant-... to .env, then rerun."
        ),
    },
    "fr": {
        "check":      _check_fr,
        "setup_cmd":  None,
        "setup_note": "FR needs no setup — just run from a Swiss residential IP.",
    },
}


# ── Persistent cooldown state ────────────────────────────────────────────────
# Survives run_local.py restarts (scan-loop.sh crash-recovery, watchdog
# reboots, etc.) so a canton that exhausted its daily quota doesn't burn
# more API calls before the quota resets at midnight.

_COOLDOWN_FILE = TOKEN_DIR / "cooldowns.json"
_cooldown_file_lock = threading.Lock()


def _load_cooldown(canton: str) -> float:
    """Return the persisted cooldown-until timestamp for *canton* (0 if none)."""
    try:
        with _cooldown_file_lock:
            if not _COOLDOWN_FILE.exists():
                return 0.0
            data = json.loads(_COOLDOWN_FILE.read_text())
        until = float(data.get(canton.lower(), 0))
        # Ignore stale entries from previous days
        return until if until > time.time() else 0.0
    except Exception:
        return 0.0


def _save_cooldown(canton: str, until: float) -> None:
    """Persist a cooldown-until timestamp for *canton* to disk."""
    try:
        TOKEN_DIR.mkdir(parents=True, exist_ok=True)
        with _cooldown_file_lock:
            data: dict = {}
            if _COOLDOWN_FILE.exists():
                try:
                    data = json.loads(_COOLDOWN_FILE.read_text())
                except Exception:
                    data = {}
            # Prune expired canton cooldown timestamps while we're here, but
            # preserve metadata keys (those starting with "fr_") which store
            # window-search state (durations / past timestamps, not future ones).
            # HIGH-1 fix: only re-add the entry if the new cooldown is in the
            # future.  Without this guard, calling _save_cooldown(canton, 0) or
            # a past timestamp would prune-then-re-add a stale entry to the file.
            now = time.time()
            data = {k: v for k, v in data.items()
                    if k.startswith("fr_") or k.endswith("_last_notify") or v > now}
            if until > now:
                data[canton.lower()] = until
            _COOLDOWN_FILE.write_text(json.dumps(data, indent=2))
    except Exception as exc:
        log.debug("_save_cooldown failed: %s", exc)


def _load_last_notify(canton: str) -> float:
    """Return the wall-clock time of the last login notification for *canton* (0 if none)."""
    try:
        with _cooldown_file_lock:
            if not _COOLDOWN_FILE.exists():
                return 0.0
            data = json.loads(_COOLDOWN_FILE.read_text())
        return float(data.get(f"{canton.lower()}_last_notify", 0))
    except Exception:
        return 0.0


def _save_last_notify(canton: str, ts: float) -> None:
    """Persist the last-notification timestamp for *canton* to disk."""
    try:
        TOKEN_DIR.mkdir(parents=True, exist_ok=True)
        with _cooldown_file_lock:
            data: dict = {}
            if _COOLDOWN_FILE.exists():
                try:
                    data = json.loads(_COOLDOWN_FILE.read_text())
                except Exception:
                    data = {}
            data[f"{canton.lower()}_last_notify"] = ts
            _COOLDOWN_FILE.write_text(json.dumps(data, indent=2))
    except Exception as exc:
        log.debug("_save_last_notify failed: %s", exc)


# ── macOS desktop notifications ──────────────────────────────────────────────

def notify(title: str, message: str, sound: bool = False,
           execute: str | None = None, group: str | None = None) -> None:
    """Show a macOS desktop notification. Silently no-ops on other OSes."""
    print(f"\n🔔 {title}: {message}\n", flush=True)

    tn = shutil.which("terminal-notifier")
    if tn:
        cmd = [tn, "-title", title, "-message", message]
        if sound:
            cmd += ["-sound", "Glass"]
        if execute:
            cmd += ["-execute", execute]
        if group:
            # Replace the previous notification in the same group instead of
            # stacking — prevents old tapped notifications from opening windows.
            cmd += ["-group", group]
        try:
            subprocess.run(cmd, check=False)
            return
        except Exception as e:
            log.debug("terminal-notifier failed: %s", e)

    osascript = shutil.which("osascript")
    if not osascript:
        return
    msg = message.replace('"', '\\"')
    ttl = title.replace('"', '\\"')
    script = f'display notification "{msg}" with title "{ttl}"'
    if sound:
        script += ' sound name "Glass"'
    try:
        subprocess.run([osascript, "-e", script], check=False)
    except Exception as e:
        log.debug("osascript notification failed: %s", e)


def _send_login_notification(canton: str, reason: str = "reauth",
                             reset_at: float | None = None,
                             force: bool = False) -> bool:
    """
    Send a macOS push notification prompting the user to log in for *canton*.
    Opens the pre-built .command file (which immediately starts a scan) on tap.

    Returns True if the notification was sent, False if throttled.

    The last send time is persisted in cooldowns.json so the LOGIN_REPEAT_NOTIFY_INTERVAL
    rate-limit survives process restarts (prevents scan-loop.sh crash-restart spam and
    reauth-cycle spam every 30 min through the night).

    reason values
    -------------
    "reauth"        — session expired during an active scan
    "login_timeout" — interactive login window was not completed in time
    "quota_reset"   — quota just reset; token dead; time to log in and scan
    "token_expired" — token died during quiet cooldown; early heads-up with reset time
    "reminder"      — repeat nudge while waiting for user to tap during fast-poll
    """
    # Rate-limit: never send two notifications for the same canton within
    # LOGIN_REPEAT_NOTIFY_INTERVAL (30 min) unless force=True.
    # This is persisted so rapid process restarts and the reauth loop both respect it.
    last = _load_last_notify(canton)
    since_last = time.time() - last
    if not force and since_last < LOGIN_REPEAT_NOTIFY_INTERVAL:
        log.debug("[%s] notification throttled (%.0f s since last, interval=%d s).",
                  canton.upper(), since_last, LOGIN_REPEAT_NOTIFY_INTERVAL)
        return False

    _ln = PROJECT_ROOT / "scripts" / f"start_{canton.lower()}_scan.command"
    execute = f"open '{_ln}'" if _ln.exists() else None

    # Human-readable reset time ("23:58") or None if unknown.
    reset_str = (datetime.datetime.fromtimestamp(reset_at).strftime("%H:%M")
                 if reset_at else None)

    if reason == "login_timeout":
        title   = f"Herrenlos — {canton.upper()} login timed out"
        message = "Tap to open a fresh login window and start scanning."
    elif reason == "quota_reset":
        title   = f"Herrenlos — {canton.upper()} quota reset, login needed"
        message = "Daily quota just reset. Tap to log in and scan now."
    elif reason == "token_expired":
        # Fired as soon as the token dies during a cooldown — gives the user
        # a heads-up hours before reset so they can pre-login at their leisure.
        reset_info = f" Quota resets at {reset_str}." if reset_str else ""
        title   = f"Herrenlos — {canton.upper()} token expired"
        message = (f"Session dead.{reset_info} Tap to pre-login — "
                   "scanning starts automatically after reset.")
    elif reason == "reminder":
        # Repeat nudge during fast-poll: user hasn't logged in yet.
        reset_info = f" until {reset_str}" if reset_str else ""
        title   = f"Herrenlos — {canton.upper()} still waiting for login"
        message = (f"Scanner is idle{reset_info}. Tap to log in and start scanning.")
    else:  # "reauth"
        reset_info = f" (retry window: until {reset_str})" if reset_str else ""
        title   = f"Herrenlos — {canton.upper()} re-login needed"
        message = f"Session expired{reset_info}. Tap to re-authenticate and start scanning."

    notify(title=title, message=message, sound=True, execute=execute,
           group=f"herrenlos-{canton.lower()}")
    _save_last_notify(canton, time.time())
    log.info("[%s] login notification sent (reason=%s).", canton.upper(), reason)
    return True


# ── Pre-flight orchestration ─────────────────────────────────────────────────

def preflight(eligible: list[str]) -> list[str]:
    """Check prerequisites for every eligible canton. Returns ready cantons."""
    print()
    print("──  Pre-flight checks  ──")

    ready: list[str] = []
    for c in eligible:
        cfg = PREFLIGHT_CHECKS.get(c)
        if cfg is None:
            print(f"  ?  {c.upper():<3} — no pre-flight check, will run blind")
            ready.append(c)
            continue
        ok, msg = cfg["check"]()
        if ok:
            print(f"  ✓  {c.upper():<3} — {msg}")
            ready.append(c)
        else:
            print(f"  ✗  {c.upper():<3} — {msg}")

    not_ready = [c for c in eligible if c not in ready]
    if not not_ready:
        print()
        return ready

    print()
    print("Some cantons need setup before they can scan.")
    for c in not_ready:
        cfg = PREFLIGHT_CHECKS[c]
        print()
        print(f"  {c.upper()}: {cfg['setup_note']}")
        if cfg["setup_cmd"] is None:
            print("  → Skipping this run. Set up the prerequisite, then rerun.")
            continue
        try:
            answer = input(f"  Run setup for {c.upper()} now? [Y/n/skip] ").strip().lower()
        except EOFError:
            answer = "skip"
        if answer in ("", "y", "yes"):
            print(f"  Running: {' '.join(cfg['setup_cmd'])}")
            rc = subprocess.run(cfg["setup_cmd"], cwd=PROJECT_ROOT).returncode
            ok, msg = cfg["check"]()
            if ok:
                print(f"  ✓ {c.upper()} setup complete — {msg}")
                ready.append(c)
            else:
                print(f"  ✗ {c.upper()} setup did not produce a token. Skipping.")
        else:
            print(f"  Skipping {c.upper()} for this run.")

    print()
    return ready


# ── Canton runner ─────────────────────────────────────────────────────────────

def run_canton(canton: str) -> tuple[int, str]:
    """
    Run `python main.py <canton> --limit ROTATION_LIMIT`.

    Lines are prefixed with [CANTON] so parallel output is readable.
    The last 4 KB of output is returned for post-mortem keyword inspection.
    The subprocess is registered in _active_procs so Ctrl+C can kill it.
    """
    cmd = [sys.executable, "main.py", canton, "--limit", str(ROTATION_LIMIT)]
    prefix = f"[{canton.upper()}] "
    tail = bytearray()
    TAIL_MAX = 4096
    try:
        proc = subprocess.Popen(
            cmd, cwd=PROJECT_ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            bufsize=1,
        )
        with _active_procs_lock:
            _active_procs[canton] = proc
        assert proc.stdout is not None
        for raw_line in proc.stdout:
            line_str = raw_line.decode("utf-8", errors="replace").rstrip("\n")
            with _stdout_lock:
                sys.stdout.write(f"{prefix}{line_str}\n")
                sys.stdout.flush()
            tail += raw_line
            if len(tail) > TAIL_MAX:
                tail = tail[-TAIL_MAX:]
        proc.wait()
        return proc.returncode, tail.decode("utf-8", errors="replace")
    except FileNotFoundError as e:
        log.error("[%s] Could not start subprocess: %s", canton.upper(), e)
        return 127, str(e)
    finally:
        with _active_procs_lock:
            _active_procs.pop(canton, None)


# ── Auth / login failure detection ───────────────────────────────────────────

def looks_like_auth_failure(canton: str, output: str) -> bool:
    o = output.lower()
    return any(kw in o for kw in AUTH_FAILURE_KEYWORDS)


def looks_like_login_timeout(output: str) -> bool:
    o = output.lower()
    return any(kw in o for kw in LOGIN_TIMEOUT_KEYWORDS)


_LOGIN_REQUIRED = {"be", "vs"}


def _is_login_failed(canton: str, tail: str) -> bool:
    """
    Return True if the canton scan appears to have failed at the login step.

    Two signals:
      1. Keyword detection in subprocess output (fast).
      2. Structural: BE/VS enumerate parcels on every successful run. If
         parcel_enum is still empty after a clean exit, login never completed.
    """
    if looks_like_login_timeout(tail):
        return True
    if canton not in _LOGIN_REQUIRED:
        return False
    try:
        with get_conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM enum.parcel_enum WHERE canton = UPPER(?)", (canton,)
            ).fetchone()
            enum_count = row[0] if row else 0
        if enum_count < REAL_ENUM_MIN:
            log.debug("[%s] parcel_enum empty after clean exit (%d rows) — "
                      "login likely failed", canton.upper(), enum_count)
            return True
    except Exception as exc:
        log.debug("_is_login_failed DB check error: %s", exc)
    return False


# ── Timing helpers ────────────────────────────────────────────────────────────

def _next_midnight_bern() -> float:
    tz = zoneinfo.ZoneInfo("Europe/Zurich")
    tomorrow = datetime.date.today() + datetime.timedelta(days=1)
    return datetime.datetime(tomorrow.year, tomorrow.month, tomorrow.day,
                             tzinfo=tz).timestamp()


# ── FR adaptive rate-limit window discovery (binary search) ───────────────────
# The FR portal uses a rolling rate-limit window, not a hard daily quota.
# We find the actual reset period to the minute using binary search on a
# [lo, hi] bracket of elapsed seconds since the last exhaustion:
#
#   Each time the circuit breaker fires we know:
#     • How long has elapsed since the previous exhaustion  (= actual_elapsed)
#     • How many parcels were scanned                        (= last_scanned)
#
#   Update the bracket:
#     scanned >= _FR_MIN_PRODUCTIVE  → portal was ready at actual_elapsed
#                                      → hi = min(hi, actual_elapsed)
#     scanned <  _FR_MIN_PRODUCTIVE  → portal was NOT ready at actual_elapsed
#                                      → lo = max(lo, actual_elapsed)
#
#   Next wait = midpoint(lo, hi), clamped to [_FR_MIN_WAIT, midnight].
#
# Convergence to ±1 min from a [0, 4h] range takes ≈ log2(240) ≈ 8 runs.
# In practice it converges much faster because the first productive run
# immediately collapses hi from 4h to the observed elapsed time.
#
# Example trace  (real reset window = 25 min):
#   Exhausted at T=0.
#   lo=0  hi=240  → wait 120 min  → elapsed=120  scanned=160  → hi=120
#   lo=0  hi=120  → wait  60 min  → elapsed= 60  scanned=140  → hi= 60
#   lo=0  hi= 60  → wait  30 min  → elapsed= 30  scanned=110  → hi= 30
#   lo=0  hi= 30  → wait  15 min  → elapsed= 15  scanned=  4  → lo= 15
#   lo=15 hi= 30  → wait  22 min  → elapsed= 22  scanned= 90  → hi= 22
#   lo=15 hi= 22  → wait  18 min  → elapsed= 18  scanned= 10  → lo= 18
#   lo=18 hi= 22  → wait  20 min  → elapsed= 20  scanned=115  → hi= 20
#   lo=18 hi= 20  → wait  19 min  ← converged to ±1 min

_FR_MIN_PRODUCTIVE  = 1           # parcels scanned; 0 means every JSESSIONID failed
                                   # (circuit breaker fired with zero successes) → not ready.
                                   # Even 1 means at least one valid session was granted → portal
                                   # was accepting, regardless of how few parcels it yielded.
_FR_MIN_WAIT        = 5 * 60      # never retry faster than 5 min (avoid hammering)
_FR_WINDOW_HI_INIT  = 4 * 3600   # conservative initial upper bound (4 h)

# Keys stored inside cooldowns.json alongside the per-canton cooldown timestamps.
_FR_KEY_LO           = "fr_window_lo"       # longest elapsed that was insufficient
_FR_KEY_HI           = "fr_window_hi"       # shortest elapsed that was sufficient
_FR_KEY_EXHAUSTED_AT = "fr_exhausted_at"    # when the last circuit breaker fired


def _fr_load_state() -> dict:
    """Load the full cooldowns dict from disk (all keys, not just canton stamps)."""
    try:
        with _cooldown_file_lock:
            if not _COOLDOWN_FILE.exists():
                return {}
            return json.loads(_COOLDOWN_FILE.read_text())
    except Exception:
        return {}


def _fr_save_state(updates: dict) -> None:
    """Merge *updates* into the cooldowns file atomically."""
    try:
        TOKEN_DIR.mkdir(parents=True, exist_ok=True)
        with _cooldown_file_lock:
            data: dict = {}
            if _COOLDOWN_FILE.exists():
                try:
                    data = json.loads(_COOLDOWN_FILE.read_text())
                except Exception:
                    data = {}
            data.update(updates)
            _COOLDOWN_FILE.write_text(json.dumps(data, indent=2))
    except Exception as exc:
        log.debug("_fr_save_state failed: %s", exc)


def _fr_adaptive_cooldown(tail: str) -> tuple[float, float]:
    """
    Binary-search the FR portal's rate-limit reset window.

    Uses the PLANNED wait (cooldown_until - last_exhausted_at from the
    previous circuit-breaker) as the measurement signal, so the bracket
    converges on the actual portal reset window rather than total elapsed
    time (which includes the scan run-time and inflates the measurement).

    No midnight cap — the portal resets in minutes, not hours.  Capping
    to midnight would inflate planned_wait on the next measurement and
    cause bracket inversion.

    Returns (cooldown_until, next_wait_secs).
    """
    m = re.search(r"scanned=(\d+)", tail)
    last_scanned = int(m.group(1)) if m else 0

    now   = time.time()
    state = _fr_load_state()

    lo             = float(state.get(_FR_KEY_LO, 0))
    hi             = float(state.get(_FR_KEY_HI, _FR_WINDOW_HI_INIT))
    last_exhausted = float(state.get(_FR_KEY_EXHAUSTED_AT, 0))

    # planned_wait = how long we slept after the previous circuit-breaker.
    # state['fr'] holds the cooldown_until set by the previous adaptive call.
    # Falls back to hi/2 on the very first run (no prior state).
    prev_cooldown_until = float(state.get("fr", 0))
    if last_exhausted > 0 and prev_cooldown_until > last_exhausted:
        planned_wait = prev_cooldown_until - last_exhausted
    else:
        planned_wait = hi / 2

    # Guard: if planned_wait was inflated (e.g. by a midnight-capped cooldown
    # from old code or an unusually long sleep), the measurement is noise —
    # skip the bracket update and just use the midpoint of the current window.
    # Threshold: more than 2× hi means the wait far exceeded our estimate.
    if planned_wait > hi * 2:
        verdict = (f"skip measurement — planned_wait={planned_wait/60:.0f} min "
                   f"exceeds 2×hi={hi/60:.0f} min (likely inflated)")
    elif last_scanned >= _FR_MIN_PRODUCTIVE:
        # Portal was ready after planned_wait seconds → tighten upper bound.
        hi = min(hi, planned_wait)
        verdict = f"productive ({last_scanned} parcels) → hi={hi/60:.1f} min"
    else:
        # Portal was NOT ready after planned_wait seconds → tighten lower bound.
        lo = max(lo, planned_wait)
        verdict = f"unproductive ({last_scanned} parcels) → lo={lo/60:.1f} min"

    # Guard: if bounds crossed (shouldn't happen), reset.
    if lo >= hi:
        log.warning("[FR] window bracket inverted (lo=%.0fs hi=%.0fs) — resetting.",
                    lo, hi)
        lo, hi = 0, _FR_WINDOW_HI_INIT

    next_wait      = max((lo + hi) / 2, _FR_MIN_WAIT)
    # No midnight cap — portal resets in minutes; capping to midnight would
    # inflate planned_wait on the next measurement and invert the bracket.
    cooldown_until = now + next_wait

    _fr_save_state({
        _FR_KEY_LO:           round(lo),
        _FR_KEY_HI:           round(hi),
        _FR_KEY_EXHAUSTED_AT: round(now),
    })

    log.info("[FR] window [%.0f–%.0f min] | %s | planned_wait=%.0f min | next wait %.0f min",
             lo / 60, hi / 60, verdict, planned_wait / 60, next_wait / 60)

    return cooldown_until, next_wait


def _stop_sleep(stop_event: threading.Event, seconds: float) -> None:
    """Sleep for *seconds* but wake immediately if stop_event is set."""
    deadline = time.time() + seconds
    while not stop_event.is_set():
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        time.sleep(min(1.0, remaining))


# ── Token keepalive ───────────────────────────────────────────────────────────

def _keepalive_token(canton: str) -> bool:
    """
    Silently refresh the stored token so the session doesn't idle-expire.

    Returns True if the token is healthy (refreshed or not needed).
    Returns False if the refresh_token itself is dead (HTTP 4xx) — caller
    should trigger re-login immediately rather than waiting out the cooldown.
    """
    meta = _TOKEN_META.get(canton)
    if not meta:
        return True
    token_file, token_ep, client_id = meta
    if not token_file.exists():
        return True
    try:
        cached = json.loads(token_file.read_text())
        refresh_token = cached.get("refresh_token")
        if not refresh_token:
            return True
        body = urllib.parse.urlencode({
            "grant_type":    "refresh_token",
            "client_id":     client_id,
            "refresh_token": refresh_token,
        }).encode()
        req = urllib.request.Request(token_ep, data=body, method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        if "access_token" not in data:
            log.warning("[%s] keepalive: refresh failed — %s",
                        canton.upper(), data.get("error", "unknown"))
            return False   # server rejected our token
        cached["access_token"] = data["access_token"]
        cached["expires_at"]   = time.time() + data.get("expires_in", 300)
        if "refresh_token" in data:
            cached["refresh_token"] = data["refresh_token"]
            # Keep refresh_token_expires_at current so the cooldown loop can
            # tighten its sleep chunk as the rolling window narrows.
            # Critical for VS whose refresh token only lasts 30 min.
            if "refresh_expires_in" in data:
                cached["refresh_token_expires_at"] = (
                    time.time() + data["refresh_expires_in"]
                )
        token_file.write_text(json.dumps(cached))
        log.debug("[%s] keepalive: token refreshed OK", canton.upper())
        return True
    except urllib.error.HTTPError as exc:
        if exc.code in (400, 401):
            # Refresh token is expired/revoked — no point retrying every 15 min.
            log.warning("[%s] keepalive: refresh token dead (HTTP %d) — "
                        "triggering re-login", canton.upper(), exc.code)
            return False
        log.warning("[%s] keepalive: %s", canton.upper(), exc)
        return True   # transient network error; don't trigger re-login
    except Exception as exc:
        log.warning("[%s] keepalive: %s", canton.upper(), exc)
        return True   # transient; don't trigger re-login


# ── GitHub push (debounced) ───────────────────────────────────────────────────

def _push_results() -> None:
    """Push local scan results to GitHub (merge + commit + push)."""
    try:
        log.info("Pushing local results to GitHub...")
        r = subprocess.run(
            ["bash", "scripts/push_local.sh", "auto"],
            cwd=PROJECT_ROOT, capture_output=True, text=True,
        )
        for line in (r.stdout + r.stderr).splitlines():
            if line.strip():
                log.info("  [push] %s", line)
    except Exception as exc:
        log.warning("push_local.sh failed: %s", exc)


def _push_debounced(push_lock: threading.Lock, last_push: list[float]) -> None:
    """
    Push at most once per PUSH_DEBOUNCE_SECONDS across all canton threads.

    The lock is held only long enough to read/update the timestamp; the
    actual push runs outside the lock so other threads aren't blocked.
    """
    with push_lock:
        now = time.time()
        since_last = now - last_push[0]
        if since_last < PUSH_DEBOUNCE_SECONDS:
            log.debug("Push debounced (last push %.0fs ago)", since_last)
            return
        last_push[0] = now
    # Outside the lock — other threads can proceed
    _push_results()


# ── Per-canton worker thread ──────────────────────────────────────────────────

def _canton_loop(
    canton: str,
    stop_event: threading.Event,
    push_lock: threading.Lock,
    last_push: list[float],
) -> None:
    """
    Worker thread for one canton. Runs `main.py <canton>` in a tight loop,
    handling rate-limit cooldowns, login timeouts, auth failures, and
    transient errors independently of all other canton threads.

    Login state machine (BE/VS only)
    ---------------------------------
    login_needed=False                 Normal: keepalive every KEEPALIVE_INTERVAL.
    login_needed=True, alerted=True    Notification already sent (token_expired or
                                       quota_reset).  Fast-poll every LOGIN_POLL_INTERVAL.
                                       Re-notify (quota_reset / reminder) in the last
                                       LOGIN_REPEAT_NOTIFY_INTERVAL before reset, or
                                       every LOGIN_REPEAT_NOTIFY_INTERVAL for short
                                       reauth cooldowns (<1h).  Clear cooldown and scan
                                       immediately when token comes back.
    (login_needed=True, alerted=False  is never reached — first notification is
                                       always sent immediately when login_needed is set)
    """
    # Restore any cooldown that was active before this process started
    # (e.g. quota exhausted before a crash/restart).
    cooldown_until = _load_cooldown(canton)
    consecutive_failures = 0

    # login_needed  = True: refresh token is dead; re-auth required.
    # login_alerted = True: first notification already sent; fast-poll active.
    # last_notify_at: wall-clock time of last notification (for repeat throttle).
    #   Restored from disk so restarts and the reauth loop honour the rate-limit.
    login_needed   = False
    login_alerted  = False
    last_notify_at = _load_last_notify(canton)

    if cooldown_until > time.time():
        resume = datetime.datetime.fromtimestamp(cooldown_until).strftime("%H:%M")
        log.info("[%s] worker started — restoring cooldown until %s",
                 canton.upper(), resume)
        # On restart with an active cooldown, check whether the token is dead and
        # notify if so — subject to the persistent throttle so rapid restarts
        # (scan-loop.sh crash-recovery) don't send duplicate notifications.
        if canton in _LOGIN_REQUIRED and not _keepalive_token(canton):
            login_needed = True
            remaining_now = cooldown_until - time.time()
            reason = ("quota_reset" if remaining_now <= LOGIN_NOTIFY_AHEAD_SECS
                      else "token_expired")
            sent = _send_login_notification(canton, reason=reason,
                                            reset_at=cooldown_until)
            login_alerted  = True
            if sent:
                last_notify_at = time.time()
                log.info("[%s] token dead on restart — notified user (reset at %s).",
                         canton.upper(), resume)
            else:
                log.info("[%s] token dead on restart — notification throttled "
                         "(sent recently). Fast-polling.", canton.upper())
    else:
        log.info("[%s] worker started", canton.upper())

    while not stop_event.is_set():
        # ── Cooldown wait ───────────────────────────────────────────────────
        while not stop_event.is_set() and time.time() < cooldown_until:
            now       = time.time()
            remaining = cooldown_until - now

            if login_needed:
                if login_alerted:
                    # ── Fast-poll: wake up every 3 min and check token ──────
                    # The user tapped the notification → .command file ran →
                    # fresh token written to disk.  We detect it here and start
                    # scanning immediately without waiting for cooldown expiry.
                    _stop_sleep(stop_event, min(LOGIN_POLL_INTERVAL, remaining))
                    if _keepalive_token(canton):
                        log.info("[%s] fresh token detected after login — "
                                 "clearing cooldown, scanning now.", canton.upper())
                        cooldown_until = 0.0
                        _save_cooldown(canton, 0.0)
                        login_needed  = False
                        login_alerted = False
                        break
                    # Still dead — send a reminder if:
                    #   a) within the last LOGIN_REPEAT_NOTIFY_INTERVAL of reset
                    #      ("quota_reset" final call), OR
                    #   b) short reauth/login_timeout cooldown (<1h), so the user
                    #      keeps hearing about it until they act.
                    # _send_login_notification is self-throttling (LOGIN_REPEAT_NOTIFY_INTERVAL
                    # persisted on disk), so calling it here is safe even on restart.
                    near_reset    = remaining <= LOGIN_REPEAT_NOTIFY_INTERVAL
                    short_cooldown = remaining < 3600
                    if near_reset or short_cooldown:
                        reason = ("quota_reset" if remaining <= LOGIN_NOTIFY_AHEAD_SECS
                                  else "reminder")
                        sent = _send_login_notification(canton, reason=reason,
                                                        reset_at=cooldown_until)
                        if sent:
                            last_notify_at = time.time()

            else:
                # ── Normal: keepalive every KEEPALIVE_INTERVAL ──────────────
                # Tighten the sleep chunk as the refresh token approaches
                # expiry — gives multiple retry shots per rolling window.
                # Essential for VS whose refresh token only lasts 30 min:
                # half the remaining lifetime → ≥2 shots always available.
                # Falls back to KEEPALIVE_INTERVAL when expiry is unknown.
                rt_expires_at = 0.0
                if canton in _LOGIN_REQUIRED:
                    try:
                        meta = _TOKEN_META.get(canton)
                        if meta:
                            rt_expires_at = float(
                                json.loads(meta[0].read_text())
                                .get("refresh_token_expires_at", 0)
                            )
                    except Exception:
                        pass
                rt_margin = (max(60.0, (rt_expires_at - now) / 2)
                             if rt_expires_at > now else KEEPALIVE_INTERVAL)
                chunk = min(KEEPALIVE_INTERVAL, remaining, rt_margin)
                if chunk > 0:
                    log.debug("[%s] in cooldown — sleeping %.0fs (until %s)",
                              canton.upper(), chunk,
                              datetime.datetime.fromtimestamp(
                                  cooldown_until).strftime("%H:%M"))
                    _stop_sleep(stop_event, chunk)

                if not _keepalive_token(canton):
                    login_needed   = True
                    login_alerted  = True
                    remaining_now  = cooldown_until - time.time()
                    reason = ("quota_reset" if remaining_now <= LOGIN_NOTIFY_AHEAD_SECS
                              else "token_expired")
                    sent = _send_login_notification(canton, reason=reason,
                                                    reset_at=cooldown_until)
                    if sent:
                        last_notify_at = time.time()
                    log.warning(
                            "[%s] refresh token dead — %s; "
                            "quota reset at %s.",
                            canton.upper(),
                            "notified user" if sent else "notification throttled (sent recently)",
                            datetime.datetime.fromtimestamp(
                                cooldown_until).strftime("%H:%M"),
                        )

        if stop_event.is_set():
            break

        # Reset login state — we're entering a fresh rotation (either cooldown
        # expired or fast-poll detected a fresh token and broke early).
        login_needed   = False
        login_alerted  = False
        # Keep last_notify_at from disk so repeat throttle survives across
        # rotations (prevents reauth-cycle spam if auth fails repeatedly).
        last_notify_at = _load_last_notify(canton)

        # ── Run one rotation ────────────────────────────────────────────────
        # Refresh token right before launching so the 30-min rotating
        # refresh_token never expires during the scan→restart transition.
        # This prevents grudis_login() from firing at midnight just because
        # the keepalive last ran >15 min ago.
        #
        # IMPORTANT: if the keepalive fails (refresh token dead), do NOT call
        # run_canton — that would open an unwanted browser window.  Instead
        # arm fast-poll and wait for the user to log in manually.
        if canton in _LOGIN_REQUIRED:
            if not _keepalive_token(canton):
                cooldown_until = time.time() + 1800
                _save_cooldown(canton, cooldown_until)
                sent = _send_login_notification(canton, reason="login_timeout",
                                                reset_at=cooldown_until)
                login_needed  = True
                login_alerted = True
                if sent:
                    last_notify_at = time.time()
                resume_str = datetime.datetime.fromtimestamp(
                    cooldown_until).strftime("%H:%M")
                log.warning("[%s] token dead before rotation — skipping scanner "
                            "(no browser window), fast-polling until %s. %s",
                            canton.upper(), resume_str,
                            "Notification sent." if sent
                            else "(Notification throttled — sent recently.)")
                continue  # back to the cooldown loop, no run_canton

        rc, tail = run_canton(canton)

        if stop_event.is_set():
            break

        # ── Handle clean exit (rc=0) ────────────────────────────────────────
        if rc == 0:
            # Fully scanned — scanner skipped every parcel (all already have
            # results). Sleep until the next day so new parcels can appear
            # in the cadastre before we bother re-picking.
            if "scanned=0" in tail or "scan done — scanned=0" in tail:
                cooldown_until = _next_midnight_bern()
                _save_cooldown(canton, cooldown_until)
                log.info("[%s] fully scanned — no remaining parcels. "
                         "Sleeping until midnight.", canton.upper())
                consecutive_failures = 0
                _push_debounced(push_lock, last_push)

            # Rate-limited / quota exhausted.
            # FR uses adaptive backoff (discovers the real reset window).
            # Other cantons have hard daily quotas → always wait until midnight.
            elif ("rate-limiting" in tail
                    or "consecutive 429" in tail
                    or "quota exhausted" in tail):
                if canton.lower() == "fr":
                    cooldown_until, backoff = _fr_adaptive_cooldown(tail)
                    _save_cooldown(canton, cooldown_until)
                    resume = datetime.datetime.fromtimestamp(
                        cooldown_until).strftime("%H:%M")
                    log.info("[FR] rate-limited — adaptive backoff %.0f min → "
                             "retry at %s.", backoff / 60, resume)
                else:
                    cooldown_until = _next_midnight_bern()
                    _save_cooldown(canton, cooldown_until)
                    resume = datetime.datetime.fromtimestamp(
                        cooldown_until).strftime("%H:%M")
                    log.info("[%s] rate-limited — daily quota exhausted. "
                             "Cooling down until midnight (%s).",
                             canton.upper(), resume)
                consecutive_failures = 0
                _push_debounced(push_lock, last_push)

            # Login window timed out — notify immediately, short cooldown,
            # fast-poll so scan starts as soon as the user logs in.
            elif _is_login_failed(canton, tail):
                cooldown_until = time.time() + 1800  # 30 min; fast-poll clears early
                _save_cooldown(canton, cooldown_until)
                sent = _send_login_notification(canton, reason="login_timeout",
                                               reset_at=cooldown_until)
                login_needed   = True
                login_alerted  = True   # notification already sent (or throttled)
                if sent:
                    last_notify_at = time.time()
                resume_str = datetime.datetime.fromtimestamp(
                    cooldown_until).strftime("%H:%M")
                log.warning("[%s] login timed out — fast-polling until %s. %s",
                            canton.upper(), resume_str,
                            "Notification sent." if sent
                            else "(Notification throttled — sent recently.)")
                consecutive_failures = 0

            # Normal clean rotation — push and immediately restart.
            else:
                consecutive_failures = 0
                log.info("[%s] rotation complete — restarting after %ds.",
                         canton.upper(), INTER_CANTON_DELAY_SECONDS)
                _push_debounced(push_lock, last_push)
                _stop_sleep(stop_event, INTER_CANTON_DELAY_SECONDS)

        # ── Handle failure (rc != 0) ────────────────────────────────────────
        else:
            consecutive_failures += 1
            backoff = min(RETRY_BASE_SECONDS * consecutive_failures,
                          RETRY_MAX_SECONDS)

            if looks_like_auth_failure(canton, tail):
                # Token expired during an active scan — notify (subject to throttle),
                # short cooldown (30 min), fast-poll for fresh token.
                cooldown_until = time.time() + 1800
                _save_cooldown(canton, cooldown_until)
                sent = _send_login_notification(canton, reason="reauth",
                                                reset_at=cooldown_until)
                login_needed   = True
                login_alerted  = True
                if sent:
                    last_notify_at = time.time()
                resume_str = datetime.datetime.fromtimestamp(
                    cooldown_until).strftime("%H:%M")
                log.warning("[%s] auth failure — fast-polling until %s. %s",
                            canton.upper(), resume_str,
                            "Tap notification to re-authenticate." if sent
                            else "(Notification throttled — sent recently.)")
                consecutive_failures = 0

            else:
                log.warning("[%s] scan exited rc=%d (failure #%d) — "
                            "sleeping %ds before retry.",
                            canton.upper(), rc,
                            consecutive_failures, backoff)
                _stop_sleep(stop_event, backoff)

    log.info("[%s] worker stopped.", canton.upper())


# ── Canton gap picker (utility — not used in the parallel main loop) ──────────

def pick_canton(eligible: list[str]) -> str | None:
    """Pick the canton with the most unscanned parcels. Used by external tools."""
    if not eligible:
        return None
    init_db()
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT LOWER(pe.canton)                                              AS canton,
                   COUNT(pe.id)                                                  AS enum_count,
                   COUNT(pe.id) - COALESCE(SUM(
                       CASE WHEN p.is_herrenlos IS NOT NULL THEN 1 ELSE 0 END), 0) AS gap
              FROM enum.parcel_enum pe
              LEFT JOIN parcels p
                     ON p.canton = pe.canton
                    AND p.bfs_nr = pe.bfs_nr
                    AND p.parcel_nr = pe.parcel_nr
             GROUP BY LOWER(pe.canton)
        """).fetchall()
    enum_count = {r["canton"]: r["enum_count"] for r in rows}
    by_gap     = {r["canton"]: r["gap"]        for r in rows}

    for c in eligible:
        if enum_count.get(c, 0) < REAL_ENUM_MIN:
            return c

    best, best_gap = None, 0
    for c in eligible:
        gap = by_gap.get(c, 0)
        if gap > best_gap:
            best, best_gap = c, gap
    return best if best is not None else eligible[0]


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(name)-6s  %(levelname)-7s  %(message)s",
        datefmt="%H:%M:%S",
    )

    raw = os.environ.get("LOCAL_ELIGIBLE_CANTONS", "")
    eligible = raw.split() if raw.strip() else list(LOCAL_ELIGIBLE_DEFAULT)
    eligible = [c.lower() for c in eligible]

    print(f"\nHerrenlos local bulk scanner  [parallel mode]")
    print(f"  CI cantons (JU, SZ, SH, NE, GR): handled by GitHub Actions.")
    print(f"  Eligible for this run: {', '.join(c.upper() for c in eligible)}")
    print(f"  Rotation limit per canton: {ROTATION_LIMIT:,} parcels")
    print(f"  Push debounce: {PUSH_DEBOUNCE_SECONDS}s")

    ready = preflight(eligible)
    if not ready:
        print("Nothing ready to scan. Set up the prerequisites above and rerun.")
        return 1

    init_db()

    print(f"\nStarting {len(ready)} parallel scanner(s): "
          f"{', '.join(c.upper() for c in ready)}")
    print("Ctrl+C to stop all scanners cleanly.\n")

    stop_event = threading.Event()
    push_lock  = threading.Lock()
    last_push: list[float] = [0.0]

    threads: list[threading.Thread] = []
    for canton in ready:
        t = threading.Thread(
            target=_canton_loop,
            args=(canton, stop_event, push_lock, last_push),
            name=f"scanner-{canton.upper()}",
            daemon=True,
        )
        t.start()
        threads.append(t)

    def _shutdown(signum=None, frame=None) -> None:
        """Signal handler: stop all threads and terminate active subprocesses."""
        log.info("Signal received — stopping all scanner threads...")
        stop_event.set()
        # Best-effort terminate: if the lock is held, skip rather than deadlock.
        if _active_procs_lock.acquire(blocking=False):
            try:
                for p in list(_active_procs.values()):
                    try:
                        p.terminate()
                    except Exception:
                        pass
            finally:
                _active_procs_lock.release()

    signal.signal(signal.SIGTERM, _shutdown)

    try:
        # Main thread just monitors. Worker threads do all the work.
        while not stop_event.is_set() and any(t.is_alive() for t in threads):
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        _shutdown()

    # Give threads time to notice stop_event and finish their current line
    for t in threads:
        t.join(timeout=15)

    log.info("All scanners stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
