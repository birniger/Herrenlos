#!/usr/bin/env python3
"""
Local bulk scanner — cycles through the cantons that CAN'T run on GitHub Actions
but CAN run unattended from your laptop on a single Swiss residential IP.

Eligible (no rotation needed for full-canton bulk; all have NO daily quota):

    SO  — reCAPTCHA v3, no daily limit, residential IP passes; ~70k parcels
    BE  — one-time AGOV/BE-Login (Safari + AppleScript on macOS); ~400k parcels
    VS  — one-time SwissID 2FA (Playwright window); ~210k parcels
    BL  — needs ANTHROPIC_API_KEY (Claude vision for handwritten CAPTCHA); ~70k parcels

NOT included by design:
  - FR, JU, SZ      : already scheduled on GitHub Actions every 6h. Duplicating
                      from your laptop would race the CI commits.
  - UR, SH, NE, GR  : daily quotas (10–100 req/day) make true bulk infeasible
                      without rotation. Use `python main.py <canton>` directly
                      for slow-background runs.
  - GE              : Imperva blocks ~30/IP even from residential; needs proxies
                      AND ANTHROPIC_API_KEY. Use `python main.py ge` separately.
  - BS-public, etc. : need proxies / institutional accounts.

Pre-flight: at startup, checks each eligible canton's prerequisites:
  - BE  : ~/.herrenlos_scanner/be_token.json exists?
  - VS  : ~/.herrenlos_scanner/vs_token.json exists?
  - BL  : ANTHROPIC_API_KEY in env / .env?
  - SO  : nothing — just needs to be on a Swiss residential IP

For each missing prerequisite you'll be offered:
  (1) Set it up now (opens the relevant interactive flow), or
  (2) Skip that canton for this run, or
  (3) Exit so you can configure manually and rerun.

During the loop: each canton scan runs unattended. If a scan exits with what
looks like an auth failure (token expired, 401, etc.), a macOS desktop
notification is fired so you know to re-authenticate. Other failures are
retried with exponential backoff.

Resumption: every parcel commits to the DB immediately. Crash, Ctrl+C, network
drop, power loss, and sleep-wake all resume cleanly.

Configuration:
  LOCAL_ELIGIBLE_CANTONS env var (space-separated) overrides the default list.

Usage:
  python scripts/run_local.py                 # full default set
  LOCAL_ELIGIBLE_CANTONS="so bl" python scripts/run_local.py

For auto-restart across crashes / network outages, use the bash wrapper:
  ./scripts/scan-loop.sh
"""
from __future__ import annotations

import logging
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import time

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

LOCAL_ELIGIBLE_DEFAULT = ["so", "be", "vs", "bl"]

# enum_count below this = "not yet enumerated" (test seeds / empty). Strategy 0
# picks these first so every canton gets bootstrapped before gap comparison.
REAL_ENUM_MIN = 100

# Backoff between failures, with a cap so we don't sleep forever.
RETRY_BASE_SECONDS = 30
RETRY_MAX_SECONDS  = 600
INTER_CANTON_DELAY_SECONDS = 5

# Maximum parcels per canton invocation before rotating. Without this, the
# scanner runs until the canton is fully done — which can be days. Rotation
# lets us make visible progress on every canton each night.
# The one-time per-canton enumeration (swisstopo grid scan, ~1-3h) is NOT
# bounded by this limit — it runs to completion before parcel scanning starts.
# Override via env var if you want to dedicate a whole night to one canton.
ROTATION_LIMIT = int(os.environ.get("LOCAL_ROTATION_LIMIT", "3000"))

# Token cache (created on first interactive login by BE/VS scanners)
TOKEN_DIR = pathlib.Path.home() / ".herrenlos_scanner"

# Substrings in scanner output that suggest an authentication failure rather
# than a transient network/server hiccup. Used only to decide whether to fire a
# notification — actual retry is the same for both kinds of failures.
AUTH_FAILURE_KEYWORDS = [
    "401", "unauthorized", "token expired", "refresh failed",
    "login required", "re-authenticate", "auth_failed",
    "invalid token", "no token cached",
]

log = logging.getLogger("local")


# ── Pre-flight: per-canton prerequisite checks ───────────────────────────────

def _check_be() -> tuple[bool, str]:
    """Returns (ready?, human-readable status)."""
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


def _check_so() -> tuple[bool, str]:
    # SO needs only a Swiss residential IP — we can't reliably introspect that
    # without making a real request, so we just optimistically pass and let the
    # scanner surface the error if the IP fails reCAPTCHA scoring.
    return True, "SO needs a Swiss residential IP (no token / no key required)"


PREFLIGHT_CHECKS = {
    "be": {
        "check":   _check_be,
        "setup_cmd": [sys.executable, "main.py", "be", "--limit", "1"],
        "setup_note": (
            "BE setup: Safari will open to grudis.apps.be.ch. Log in with your "
            "AGOV / BE-Login account. The scanner then extracts the token via "
            "AppleScript (you must have 'Allow JavaScript from Apple Events' "
            "enabled in Safari → Develop). The token is cached for future runs."
        ),
    },
    "vs": {
        "check":   _check_vs,
        "setup_cmd": [sys.executable, "main.py", "vs", "--limit", "1"],
        "setup_note": (
            "VS setup: a Playwright Chromium window opens. Log in with your "
            "SwissID account and complete 2FA (app push or SMS). The token "
            "is then cached automatically."
        ),
    },
    "bl": {
        "check":   _check_bl,
        "setup_cmd": None,                   # not interactive — user edits .env
        "setup_note": (
            "BL setup: get an Anthropic API key at https://console.anthropic.com, "
            "then add to .env:    ANTHROPIC_API_KEY=sk-ant-...\n"
            "Then rerun this script."
        ),
    },
    "so": {
        "check":   _check_so,
        "setup_cmd": None,
        "setup_note": "SO needs no setup — just run from a Swiss residential IP.",
    },
}


# ── Picker (same strategy as scripts/pick_canton.py) ─────────────────────────

def pick_canton(eligible: list[str]) -> str | None:
    if not eligible:
        return None
    init_db()
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT LOWER(pe.canton)                                              AS canton,
                   COUNT(pe.id)                                                  AS enum_count,
                   COUNT(pe.id) - COALESCE(SUM(
                       CASE WHEN p.is_herrenlos IS NOT NULL THEN 1 ELSE 0 END), 0) AS gap
              FROM parcel_enum pe
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
            log.info("Picking %s — not yet enumerated (enum=%d)",
                     c.upper(), enum_count.get(c, 0))
            return c

    best, best_gap = None, 0
    for c in eligible:
        gap = by_gap.get(c, 0)
        if gap > best_gap:
            best, best_gap = c, gap
    if best is not None:
        log.info("Picking %s — largest gap (%d parcels remaining)",
                 best.upper(), best_gap)
        return best

    log.info("All gaps zero — rotating to %s", eligible[0].upper())
    return eligible[0]


# ── macOS desktop notifications ──────────────────────────────────────────────

def notify(title: str, message: str, sound: bool = False) -> None:
    """Show a macOS desktop notification. Silently no-ops on other OSes."""
    print(f"\n🔔 {title}: {message}\n", flush=True)
    osascript = shutil.which("osascript")
    if not osascript:
        return
    # Escape double-quotes in the message
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
    """
    Check prerequisites for every eligible canton. Interactively offer to set
    up missing ones. Returns the filtered list of cantons that are ready to
    scan in this run.
    """
    print()
    print("──  Pre-flight checks  ──")

    ready: list[str] = []
    for c in eligible:
        cfg = PREFLIGHT_CHECKS.get(c)
        if cfg is None:
            # Unknown canton — be permissive, let the scanner surface its own error.
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

    # For each not-ready canton, ask user what to do
    print()
    print("Some cantons need setup before they can scan.")
    for c in not_ready:
        cfg = PREFLIGHT_CHECKS[c]
        print()
        print(f"  {c.upper()}: {cfg['setup_note']}")
        if cfg["setup_cmd"] is None:
            # User must edit .env manually
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


# ── Scan runner with auth-failure detection ──────────────────────────────────

def run_canton(canton: str) -> tuple[int, str]:
    """
    Run `python main.py <canton>` and stream output to terminal while also
    capturing it for post-mortem keyword inspection. Returns (rc, tail_output).
    Only the last 4 KB of output is retained — enough to spot auth failures
    without holding hundreds of MB for a many-hour scan.

    Uses ROTATION_LIMIT so the loop cycles between cantons rather than getting
    stuck on the first one for days.
    """
    cmd = [sys.executable, "main.py", canton, "--limit", str(ROTATION_LIMIT)]
    log.info("→ Running: %s", " ".join(cmd))
    tail = bytearray()
    TAIL_MAX = 4096
    try:
        proc = subprocess.Popen(
            cmd, cwd=PROJECT_ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            bufsize=1,
        )
        assert proc.stdout is not None
        for raw_line in proc.stdout:
            sys.stdout.buffer.write(raw_line)
            sys.stdout.flush()
            tail += raw_line
            if len(tail) > TAIL_MAX:
                tail = tail[-TAIL_MAX:]
        proc.wait()
        return proc.returncode, tail.decode("utf-8", errors="replace")
    except FileNotFoundError as e:
        log.error("Could not start subprocess: %s", e)
        return 127, str(e)


def looks_like_auth_failure(canton: str, output: str) -> bool:
    o = output.lower()
    return any(kw in o for kw in AUTH_FAILURE_KEYWORDS)


# ── Signal handling ──────────────────────────────────────────────────────────

def install_signal_handlers():
    def _term(signum, frame):
        log.info("Received signal %d — exiting after current parcel", signum)
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, _term)


# ── Main loop ────────────────────────────────────────────────────────────────

def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(name)-6s  %(levelname)-7s  %(message)s",
        datefmt="%H:%M:%S",
    )
    install_signal_handlers()

    raw = os.environ.get("LOCAL_ELIGIBLE_CANTONS", "")
    eligible = raw.split() if raw.strip() else list(LOCAL_ELIGIBLE_DEFAULT)
    eligible = [c.lower() for c in eligible]
    print(f"\nHerrenlos local bulk scanner")
    print(f"  CI cantons (FR, JU, SZ): handled by GitHub Actions — NOT run here.")
    print(f"  Eligible for this run:   {', '.join(c.upper() for c in eligible)}")

    ready = preflight(eligible)
    if not ready:
        print("Nothing ready to scan. Set up the prerequisites above and rerun.")
        return 1
    print(f"Starting scan loop with: {', '.join(c.upper() for c in ready)}")
    print("Ctrl+C to stop cleanly.\n")

    consecutive_failures = 0

    while True:
        try:
            canton = pick_canton(ready)
            if canton is None:
                log.error("No eligible cantons remain — exiting.")
                return 2

            rc, tail = run_canton(canton)
            if rc == 0:
                log.info("%s scan exited cleanly. Sleeping %ds.",
                         canton.upper(), INTER_CANTON_DELAY_SECONDS)
                consecutive_failures = 0
                time.sleep(INTER_CANTON_DELAY_SECONDS)
                continue

            consecutive_failures += 1
            backoff = min(RETRY_BASE_SECONDS * consecutive_failures, RETRY_MAX_SECONDS)

            if looks_like_auth_failure(canton, tail):
                # Token likely expired. Notify the user with sound, then offer
                # to launch the interactive re-auth flow right now. If they
                # decline (or there's no TTY), skip this canton for the rest
                # of this run; preflight will catch it on next startup.
                notify(
                    title="Herrenlos Scanner — re-login needed",
                    message=(f"{canton.upper()} scan exited with what looks like "
                             f"an auth failure. Re-authentication needed."),
                    sound=True,
                )
                cfg = PREFLIGHT_CHECKS.get(canton, {})
                setup_cmd = cfg.get("setup_cmd")
                offered_reauth = False
                if setup_cmd is not None and sys.stdin.isatty():
                    try:
                        print()
                        print(f"  {canton.upper()} appears to need re-authentication.")
                        print(f"  Setup: {cfg.get('setup_note', '')}")
                        answer = input(f"  Re-auth {canton.upper()} now? "
                                       f"[Y/n/skip] ").strip().lower()
                    except EOFError:
                        answer = "skip"
                    if answer in ("", "y", "yes"):
                        rc2 = subprocess.run(setup_cmd, cwd=PROJECT_ROOT).returncode
                        ok, msg = cfg["check"]()
                        offered_reauth = True
                        if ok:
                            log.info("%s re-auth complete — %s", canton.upper(), msg)
                            consecutive_failures = 0
                            continue   # back to picker; canton still in `ready`
                        log.warning("%s re-auth attempt failed (rc=%d). Skipping for this run.",
                                    canton.upper(), rc2)
                if not offered_reauth:
                    print(f"\n  Auto-skipping {canton.upper()} (no TTY or user declined).")
                    print(f"  To re-enable, rerun this script and complete the preflight.\n")
                # Remove the offender from the eligible set so the loop doesn't
                # immediately hit the same auth wall again.
                ready = [c for c in ready if c != canton]
                if not ready:
                    log.error("All eligible cantons require re-auth — exiting.")
                    return 3
                consecutive_failures = 0
                continue

            log.warning("%s scan exited rc=%d (failure #%d) — sleeping %ds before next pick",
                        canton.upper(), rc, consecutive_failures, backoff)
            time.sleep(backoff)

        except KeyboardInterrupt:
            log.info("Interrupted — exiting cleanly.")
            return 0
        except Exception as e:
            consecutive_failures += 1
            backoff = min(RETRY_BASE_SECONDS * consecutive_failures, RETRY_MAX_SECONDS)
            log.exception("Loop error: %s — sleeping %ds", e, backoff)
            time.sleep(backoff)


if __name__ == "__main__":
    sys.exit(main())
