#!/usr/bin/env python3
"""
check_tokens.py — fast token health check for BE and VS.

Tries to silently refresh each token via HTTP; reports whether
the scanner can run without manual re-login.

Exit codes:
  0  — all tokens OK (or not needed)
  1  — one or more tokens need renewal
"""
import json, pathlib, shutil, subprocess, sys, time, requests

TOKEN_DIR = pathlib.Path.home() / ".herrenlos_scanner"

CANTONS = {
    "BE": {
        "token_file":   TOKEN_DIR / "be_token.json",
        "token_ep":     "https://sso.be.ch/auth/realms/a51-grudis-public-agov/protocol/openid-connect/token",
        "client_id":    "intercapi-public-client",
        "login_hint":   "run:  python3 main.py be\n"
                        "  → browser opens GRUDIS → paste JS snippet in DevTools → token saved",
    },
    "VS": {
        "token_file":   TOKEN_DIR / "vs_token.json",
        "token_ep":     "https://sso.apps.vs.ch/auth/realms/etatvs/protocol/openid-connect/token",
        "client_id":    "capitastra-public-client",
        "login_hint":   "run:  python3 main.py vs\n"
                        "  → visible Chromium window opens → complete SwissID login manually",
    },
}

def try_refresh(token_ep: str, client_id: str, refresh_token: str) -> bool:
    """Return True if the refresh_token is still accepted."""
    try:
        r = requests.post(
            token_ep,
            data={"grant_type": "refresh_token",
                  "refresh_token": refresh_token,
                  "client_id": client_id},
            timeout=10,
        )
        return r.status_code == 200
    except Exception:
        return False


def check() -> dict:
    """
    Returns a dict keyed by canton with status dicts:
      {
        "status": "ok" | "need_renewal" | "no_token",
        "message": str,
      }
    """
    results = {}
    for canton, cfg in CANTONS.items():
        f = cfg["token_file"]
        if not f.exists():
            results[canton] = {"status": "no_token",
                               "message": f"No token cached — {cfg['login_hint']}"}
            continue

        try:
            data = json.loads(f.read_text())
        except Exception:
            results[canton] = {"status": "no_token",
                               "message": "Token file corrupt — delete and re-login"}
            continue

        access_token  = data.get("access_token", "")
        refresh_token = data.get("refresh_token", "")
        expires_at    = data.get("expires_at", 0)

        # 1. Access token still valid?
        if access_token and time.time() < expires_at - 30:
            secs = int(expires_at - time.time())
            results[canton] = {"status": "ok",
                               "message": f"Access token valid for {secs}s"}
            continue

        # 2. Try silent HTTP refresh
        if refresh_token and try_refresh(cfg["token_ep"], cfg["client_id"], refresh_token):
            results[canton] = {"status": "ok",
                               "message": "Refresh token still valid — silent refresh succeeded"}
            continue

        # 3. Both expired
        results[canton] = {"status": "need_renewal",
                           "message": f"Tokens expired — {cfg['login_hint']}"}

    return results


def _fire_notification(canton: str) -> None:
    """
    Fire a macOS notification for an expired canton token.

    With terminal-notifier installed (brew install terminal-notifier):
      - Shows a proper Notification Center alert with a click action.
      - Tapping the notification opens a new Terminal window and runs
        `python3 main.py <canton>`, which handles login then scans.

    Falls back to a plain osascript banner (no click action) if
    terminal-notifier is not installed.
    """
    proj     = pathlib.Path(__file__).parent.parent
    launcher = proj / "scripts" / f"start_{canton.lower()}_scan.command"
    title    = "Herrenlos Scanner"
    subtitle = f"{canton.upper()} login required"
    msg      = "Tap to open Terminal — log in, then scan starts automatically"

    tn = shutil.which("terminal-notifier")
    if tn and launcher.exists():
        cmd = [
            tn,
            "-title",    title,
            "-subtitle", subtitle,
            "-message",  msg,
            "-sound",    "Funk",
            "-execute",  f"open '{str(launcher)}'",
        ]
        try:
            subprocess.run(cmd, check=False)
            return
        except Exception:
            pass  # fall through to osascript

    osa = shutil.which("osascript")
    if osa:
        script = (f'display notification "{msg}" with title "{title}" '
                  f'subtitle "{subtitle}" sound name "Funk"')
        subprocess.run([osa, "-e", script], check=False)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Token health check for BE and VS scanners.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exit codes:\n"
            "  0 — all tokens OK\n"
            "  1 — one or more tokens need renewal\n"
        ),
    )
    parser.add_argument(
        "--notify", action="store_true",
        help="Fire a macOS notification for each expired token (requires "
             "terminal-notifier for clickable alerts: brew install terminal-notifier)",
    )
    args = parser.parse_args()

    results = check()
    all_ok = all(r["status"] == "ok" for r in results.values())

    for canton, r in results.items():
        icon = "✅" if r["status"] == "ok" else "❌"
        print(f"{icon} {canton}: {r['message']}")
        if args.notify and r["status"] in ("need_renewal", "no_token"):
            _fire_notification(canton)

    if not all_ok:
        print()
        print("One or more tokens need renewal before BE/VS scanning can continue.")
        sys.exit(1)
    else:
        print("\nAll tokens OK — scanners can run without manual re-login.")
        sys.exit(0)


if __name__ == "__main__":
    main()
