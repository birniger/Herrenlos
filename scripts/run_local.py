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
                    if k.startswith("fr_") or v > now}
            if until > now:
                data[canton.lower()] = until
            _COOLDOWN_FILE.write_text(json.dumps(data, indent=2))
    except Exception as exc:
        log.debug("_save_cooldown failed: %s", exc)


# ── macOS desktop notifications ──────────────────────────────────────────────

def notify(title: str, message: str, sound: bool = False,
           execute: str | None = None) -> None:
    """Show a macOS desktop notification. Silently no-ops on other OSes."""
    print(f"\n🔔 {title}: {message}\n", flush=True)

    tn = shutil.which("terminal-notifier")
    if tn:
        cmd = [tn, "-title", title, "-message", message]
        if sound:
            cmd += ["-sound", "Glass"]
        if execute:
            cmd += ["-execute", execute]
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

_FR_MIN_PRODUCTIVE  = 50          # parcels scanned; below → "portal not ready"
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

    Reads elapsed time since the last exhaustion, updates the [lo, hi]
    bracket, and returns (cooldown_until, next_wait_secs).
    """
    m = re.search(r"scanned=(\d+)", tail)
    last_scanned = int(m.group(1)) if m else 0

    now   = time.time()
    state = _fr_load_state()

    lo           = float(state.get(_FR_KEY_LO, 0))
    hi           = float(state.get(_FR_KEY_HI, _FR_WINDOW_HI_INIT))
    last_exhausted = float(state.get(_FR_KEY_EXHAUSTED_AT, 0))

    # How long did we actually wait since the last exhaustion?
    # Falls back to hi/2 on the very first run (no prior exhaustion recorded).
    elapsed = (now - last_exhausted) if last_exhausted > 0 else (hi / 2)

    if last_scanned >= _FR_MIN_PRODUCTIVE:
        # Portal was ready after `elapsed` seconds → tighten upper bound.
        hi = min(hi, elapsed)
        verdict = f"productive ({last_scanned} parcels) → hi={hi/60:.1f} min"
    else:
        # Portal was NOT ready after `elapsed` seconds → tighten lower bound.
        lo = max(lo, elapsed)
        verdict = f"unproductive ({last_scanned} parcels) → lo={lo/60:.1f} min"

    # Guard: if bounds crossed (shouldn't happen), reset.
    if lo >= hi:
        log.warning("[FR] window bracket inverted (lo=%.0fs hi=%.0fs) — resetting.",
                    lo, hi)
        lo, hi = 0, _FR_WINDOW_HI_INIT

    next_wait      = max((lo + hi) / 2, _FR_MIN_WAIT)
    cooldown_until = min(now + next_wait, _next_midnight_bern())

    _fr_save_state({
        _FR_KEY_LO:           round(lo),
        _FR_KEY_HI:           round(hi),
        _FR_KEY_EXHAUSTED_AT: round(now),
    })

    log.info("[FR] window [%.0f–%.0f min] | %s | next wait %.0f min",
             lo / 60, hi / 60, verdict, next_wait / 60)

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
    """
    # Restore any cooldown that was active before this process started
    # (e.g. quota exhausted before a crash/restart).
    cooldown_until = _load_cooldown(canton)
    consecutive_failures = 0

    if cooldown_until > time.time():
        resume = datetime.datetime.fromtimestamp(cooldown_until).strftime("%H:%M")
        log.info("[%s] worker started — restoring cooldown until %s",
                 canton.upper(), resume)
    else:
        log.info("[%s] worker started", canton.upper())

    while not stop_event.is_set():
        # ── Cooldown wait ───────────────────────────────────────────────────
        while not stop_event.is_set() and time.time() < cooldown_until:
            # Sleep in KEEPALIVE_INTERVAL chunks, refreshing token each time
            # so a BE/VS session doesn't idle-expire during an overnight wait.
            chunk = min(KEEPALIVE_INTERVAL, cooldown_until - time.time())
            if chunk > 0:
                remaining_str = datetime.datetime.fromtimestamp(
                    cooldown_until).strftime("%H:%M")
                log.debug("[%s] in cooldown — sleeping %.0fs (until %s)",
                          canton.upper(), chunk, remaining_str)
                _stop_sleep(stop_event, chunk)
            token_alive = _keepalive_token(canton)
            if not token_alive:
                # Refresh token is dead — skip remaining cooldown and trigger
                # re-login immediately instead of waiting up to 2h doing nothing.
                _ln = PROJECT_ROOT / "scripts" / f"start_{canton.lower()}_scan.command"
                notify(
                    title=f"Herrenlos — {canton.upper()} re-login needed",
                    message=f"{canton.upper()} token expired. Tap to re-authenticate.",
                    sound=True,
                    execute=f"open '{_ln}'" if _ln.exists() else None,
                )
                cooldown_until = time.time() + 2 * 3600
                _save_cooldown(canton, cooldown_until)
                resume_str = datetime.datetime.fromtimestamp(
                    cooldown_until).strftime("%H:%M")
                log.warning("[%s] refresh token dead — re-login cooldown until %s",
                            canton.upper(), resume_str)
                break   # exit inner cooldown loop; outer loop will handle the new cooldown

        if stop_event.is_set():
            break

        # ── Run one rotation ────────────────────────────────────────────────
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

            # Login window timed out — fire push notification, 2 h cooldown.
            elif _is_login_failed(canton, tail):
                _ln = PROJECT_ROOT / "scripts" / f"start_{canton.lower()}_scan.command"
                notify(
                    title=f"Herrenlos — {canton.upper()} login needed",
                    message=f"Log in to {canton.upper()} then tap to scan",
                    sound=True,
                    execute=f"open '{_ln}'" if _ln.exists() else None,
                )
                cooldown_until = time.time() + 2 * 3600
                _save_cooldown(canton, cooldown_until)
                resume_str = datetime.datetime.fromtimestamp(
                    cooldown_until).strftime("%H:%M")
                log.warning("[%s] login timed out — cooldown until %s. "
                            "Tap push notification to scan now.",
                            canton.upper(), resume_str)
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
                # Token expired: notify with sound + 2 h cooldown so the thread
                # keeps running (and other cantons aren't affected). The user
                # taps the notification to re-authenticate via the .command file.
                _ln = PROJECT_ROOT / "scripts" / f"start_{canton.lower()}_scan.command"
                notify(
                    title="Herrenlos Scanner — re-login needed",
                    message=(f"{canton.upper()} token expired. "
                             "Tap to open Terminal and re-authenticate."),
                    sound=True,
                    execute=f"open '{_ln}'" if _ln.exists() else None,
                )
                cooldown_until = time.time() + 2 * 3600
                _save_cooldown(canton, cooldown_until)
                resume_str = datetime.datetime.fromtimestamp(
                    cooldown_until).strftime("%H:%M")
                log.warning("[%s] auth failure — cooling down until %s. "
                            "Tap push notification to re-authenticate.",
                            canton.upper(), resume_str)
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
