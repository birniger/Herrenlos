#!/usr/bin/env python3
"""
sync_proxies.py — fetch the current Webshare proxy list and update local .env
and (optionally) the GitHub Actions secret so CI stays in sync automatically.

Usage:
    python scripts/sync_proxies.py                  # update .env only
    python scripts/sync_proxies.py --update-secret  # update .env + GitHub secret

Requires WEBSHARE_API_TOKEN in environment or .env.
Non-fatal: if the token is missing or the API call fails, the script exits 0
so it never breaks scan-loop.sh.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.request

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
ENV_FILE     = PROJECT_ROOT / ".env"

WEBSHARE_API = "https://proxy.webshare.io/api/v2"
PROXY_KEYS   = ["SH_PROXY_LIST", "NE_PROXY_LIST", "GR_PROXY_LIST"]
UA           = "WebshareSkill/1.0 (LLM; sync_proxies.py)"


# ── API helpers ───────────────────────────────────────────────────────────────

def _api_get(path: str, token: str) -> dict:
    req = urllib.request.Request(
        f"{WEBSHARE_API}{path}",
        headers={"Authorization": f"Token {token}", "X-Webshare-Source": UA},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def fetch_proxy_list(token: str) -> str:
    """Return comma-separated host:port:user:pass for all valid proxies."""
    config  = _api_get("/proxy/config/", token)
    user    = config["username"]
    passwd  = config["password"]
    proxies = _api_get("/proxy/list/?mode=direct&page_size=100", token)
    entries = [
        f"{p['proxy_address']}:{p['port']}:{user}:{passwd}"
        for p in proxies["results"]
        if p.get("valid")
    ]
    return ",".join(entries)


# ── Local .env update ─────────────────────────────────────────────────────────

def update_env(proxy_list: str) -> bool:
    """Rewrite SH/NE/GR_PROXY_LIST in .env. Returns True if anything changed."""
    if not ENV_FILE.exists():
        print(f"[sync_proxies] .env not found — skipping local update", file=sys.stderr)
        return False

    content  = ENV_FILE.read_text()
    original = content
    for key in PROXY_KEYS:
        content = re.sub(
            rf'^(export {re.escape(key)}=")([^"]*)"',
            lambda m: f'{m.group(1)}{proxy_list}"',
            content,
            flags=re.MULTILINE,
        )

    if content == original:
        print(f"[sync_proxies] .env already up to date ({len(proxy_list.split(','))} proxies)")
        return False

    ENV_FILE.write_text(content)
    print(f"[sync_proxies] .env updated — {len(proxy_list.split(','))} proxies")
    return True


# ── GitHub secret update ──────────────────────────────────────────────────────

def update_github_secret(proxy_list: str) -> None:
    """Push proxy list to WEBSHARE_PROXY_LIST GitHub secret via gh CLI."""
    result = subprocess.run(
        ["gh", "secret", "set", "WEBSHARE_PROXY_LIST", "--body", proxy_list],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        print("[sync_proxies] GitHub secret WEBSHARE_PROXY_LIST updated")
    else:
        print(f"[sync_proxies] gh secret set failed: {result.stderr.strip()}", file=sys.stderr)


# ── Main ──────────────────────────────────────────────────────────────────────

def _load_token() -> str | None:
    token = os.environ.get("WEBSHARE_API_TOKEN", "").strip()
    if token:
        return token
    # Fall back to .env
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[7:]
            k, _, v = line.partition("=")
            if k.strip() == "WEBSHARE_API_TOKEN":
                v = v.strip().strip('"').strip("'")
                if v:
                    return v
    return None


def main() -> None:
    update_secret = "--update-secret" in sys.argv or bool(
        os.environ.get("UPDATE_GITHUB_SECRET")
    )

    token = _load_token()
    if not token:
        print("[sync_proxies] WEBSHARE_API_TOKEN not set — skipping proxy sync")
        return  # non-fatal

    try:
        proxy_list = fetch_proxy_list(token)
    except Exception as exc:
        print(f"[sync_proxies] Webshare API error: {exc} — skipping sync", file=sys.stderr)
        return  # non-fatal

    if not proxy_list:
        print("[sync_proxies] Webshare returned no valid proxies — skipping sync", file=sys.stderr)
        return

    print(f"[sync_proxies] {len(proxy_list.split(','))} valid proxies from Webshare")
    update_env(proxy_list)

    if update_secret:
        update_github_secret(proxy_list)


if __name__ == "__main__":
    main()
