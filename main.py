#!/usr/bin/env python3
"""
Herrenlos Scanner
=================
Detects ownerless Swiss land parcels (herrenlos under ZGB Art. 658/664/964)
across Swiss cantons using public geo portals.

── CI (GitHub Actions) ─────────────────────────────────────────────────────
    python main.py ju           # JU scan (~13k parcels; OCR-solvable CAPTCHA per query)
    python main.py sz           # SZ scan (~18k parcels; OCR-solvable CAPTCHA per query)
    python main.py sh           # SH scan (~50k parcels); 100 req/day/IP — proxied in CI
    python main.py gr           # GR scan (~85k parcels); 10 req/day/IP — proxied in CI
    All four are auto-scheduled every 6h; pick_canton.py selects by gap size.
    (FR removed: keycloak.fr.ch geo-blocks datacenter IPs.)

── Laptop — true bulk-capable (single IP completes the whole canton) ──────
    These are what scripts/run_local.py runs automatically in a loop.
    python main.py so           # SO scan (~70k parcels); reCAPTCHA v3, no daily limit;
                                #   residential IP passes, datacenter IPs fail
    python main.py be           # BE scan (~400k parcels); one-time AGOV/BE-Login:
                                #   Safari opens → log in → token cached
                                #   (macOS: enable 'Allow JavaScript from Apple Events' in Safari)
    python main.py vs           # VS scan (~210k parcels); one-time SwissID 2FA:
                                #   Playwright Chromium window opens → complete 2FA →
                                #   token extracted automatically; token cached
    python main.py bl           # BL scan (~70k parcels); handwritten CAPTCHA —
                                #   needs ANTHROPIC_API_KEY (~$0.003/parcel, ~$210 total)

── Laptop — slow-background only (daily quota, bulk infeasible without rotation)
    python main.py ur           # UR scan (~20k parcels); ~14-30/day before math
                                #   CAPTCHA (extendable via ANTHROPIC_API_KEY)
                                #   Geo-blocked from non-Swiss IPs.
    python main.py sh           # SH scan (~50k parcels); 100 req/day/IP
    python main.py ne           # NE scan (~50k parcels); ~50 Altcha PoW/day;
                                #   use --refresh-enum when stale_uuid errors appear
    python main.py gr           # GR scan (~85k parcels); 10 req/day/IP — VERY slow
                                #   solo (~2000 days without rotation)

── Needs proxies for bulk scanning ─────────────────────────────────────────
    python main.py ge           # GE scan (~69k parcels); Imperva TSPD ~30 req/IP +
                                #   image CAPTCHA per parcel; needs GE_PROXY_LIST in .env
                                #   AND ANTHROPIC_API_KEY (~$200 total); proxy plumbing wired
    python main.py bs           # BS metadata scan (Type A only); needs BS_API_KEY in .env
    python main.py bs-public    # BS full scan (Type A + B, owner names); reCAPTCHA Enterprise
                                #   on HTML viewer, 10 req/day/IP; needs BS_PROXY_LIST in .env

── Blocked — no automatable public path ────────────────────────────────────
    python main.py zg           # ZG — lr.zugmap.ch requires SMS per query (BLOCKED)
    python main.py tg           # TG — map.geo.tg.ch requires SMS per query (BLOCKED)
    python main.py ar           # AR — Terravis professional only; mail for private (BLOCKED)
    python main.py ai           # AI — same as AR (BLOCKED)
    python main.py gl           # GL — AGOV LoA-3; revisit Dec 2026 (BLOCKED)
    python main.py nw           # NW — form-mail only, not direct lookup (BLOCKED)
    python main.py ow           # OW — Terravis professional only (BLOCKED)
    python main.py ti           # TI — SIFTI requires registry authorization (BLOCKED)
    python main.py vd           # VD — form + 48h email turnaround, 5/day (BLOCKED)
    # ZH, LU: SMS-per-query (no cmd — no scanner built)
    # AG, SG: access possible but scanner not yet written

── Utilities ────────────────────────────────────────────────────────────────
    python main.py poc          # PoC: small sample from UR + FR
    python main.py stats        # print DB stats per canton
    python main.py herrenlos    # list all herrenlos parcels found so far
    python main.py captcha      # CAPTCHA solver accuracy (BL, SZ, JU, …)
    python main.py captcha bl   # CAPTCHA stats for BL only
    python main.py test         # false-positive guard tests (TIER A: fast, REST-only)
    python main.py test ge bs   # test specific cantons only
    python main.py test --tier b              # TIER A + B (slow portal/CAPTCHA tests)
    python main.py test --tier b ju sz        # TIER B for specific cantons
    python main.py test --seed                # seed parcel_enum for smoke runs
    python main.py test-history               # last 7 days of test_runs
    python main.py test-history bl --days 30  # one canton, 30-day window
    python main.py ready                      # production-readiness view per canton

    Add --limit N to any canton command to cap queries.
    Add --rescan   to re-scan parcels already in DB.
    Add --refresh-enum (NE only) to discard stale WFS UUIDs and re-enumerate.
"""

import argparse
import logging
import os
import pathlib
import sys

# Auto-load .env from the project root (if present) before anything else
_env_file = pathlib.Path(__file__).parent / ".env"
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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(name)-4s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)

from db import init_db, get_conn, print_stats


def cmd_poc(args):
    """Quick proof-of-concept: small sample from UR and FR."""
    print("\n=== PoC: UR (first 30 parcels) ===")
    from scanners.ur import scan as ur_scan
    ur_scan(limit=30, delay=2.0)

    print("\n=== PoC: FR (commune 2173 / Fribourg, first 20 real parcels) ===")
    from scanners.fr import scan as fr_scan
    fr_scan(communes=["2173 FR217312"], limit=20)

    print("\n=== DB Stats ===")
    print_stats("UR")
    print_stats("FR")
    print_herrenlos()


def cmd_ur(args):
    from scanners.ur import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_fr(args):
    from scanners.fr import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_so(args):
    # Use the PUBLIC scanner (scanners/so_public.py) — Playwright + invisible
    # reCAPTCHA v3 against geo.so.ch. Works from any Swiss residential IP, no
    # account needed. The legacy professional Capitastra path is still in
    # scanners/so.py but requires institutional Keycloak access; use it only
    # if you actually hold an intercapi.so.ch account.
    from scanners.so_public import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_bs(args):
    # scanners.bs — metadata REST only (no Playwright). Detects Type A herrenlos
    # (not in Grundbuch). Works from any IP including GitHub Actions.
    # For owner names + Type B, use:  python main.py bs-public
    from scanners.bs import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_bs_public(args):
    # scanners.bs_public — Playwright + reCAPTCHA Enterprise. Extracts owner names
    # and detects both Type A and Type B herrenlos. Requires:
    #   pip install playwright playwright-stealth && playwright install chromium
    #   BS_API_KEY in .env (for section lookup)
    # Rate limit: 10/day/IP — set BS_PROXY_LIST for residential proxy rotation.
    from scanners.bs_public import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_gr(args):
    from scanners.gr import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_bl(args):
    from scanners.bl import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_be(args):
    from scanners.be import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_ju(args):
    from scanners.ju import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_sh(args):
    from scanners.sh import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_vs(args):
    from scanners.vs import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_ne(args):
    from scanners.ne import scan
    scan(limit=args.limit, skip_existing=not args.rescan,
         refresh_enum=getattr(args, "refresh_enum", False))


def cmd_sz(args):
    from scanners.sz import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_ar(args):
    from scanners.ar import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_ai(args):
    from scanners.ai import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_ag(args):
    from scanners.ag import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_tg(args):
    from scanners.tg import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_sg(args):
    from scanners.sg import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_zg(args):
    from scanners.zg import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_gl(args):
    from scanners.gl import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_nw(args):
    from scanners.nw import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_ow(args):
    from scanners.ow import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_ti(args):
    from scanners.ti import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_vd(args):
    from scanners.vd import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_lu(args):
    from scanners.lu import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_ge(args):
    from scanners.ge import scan
    scan(limit=args.limit, skip_existing=not args.rescan)


def cmd_test(args):
    from test_fixtures import run_tests, seed_canton, CANTON_SEED_POINTS
    cantons = [c.lower() for c in args.cantons] if args.cantons else None
    if args.seed:
        for c in (cantons or list(CANTON_SEED_POINTS.keys())):
            seed_canton(c.upper())
        return
    sys.exit(run_tests(tier=args.tier, cantons=cantons))


def cmd_stats(args):
    # Print per-canton rows dynamically from the DB, then an ALL total.
    # Using the DB's own canton list avoids a hardcoded list that goes stale
    # every time a new canton is added.
    with get_conn() as conn:
        cantons = [r[0] for r in conn.execute(
            "SELECT DISTINCT canton FROM parcels ORDER BY canton"
        ).fetchall()]
    for c in cantons:
        print_stats(c)
    print_stats()  # ALL total as footer


def print_herrenlos():
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT canton, commune, parcel_nr, egrid, owner, scanned_at
            FROM   parcels
            WHERE  is_herrenlos = 1
            ORDER  BY canton, commune, CAST(parcel_nr AS INTEGER)
        """).fetchall()
    if not rows:
        print("No herrenlos parcels found yet.")
        return
    print(f"\n{'Canton':<6} {'Commune':<25} {'Parcel':<10} {'EGRID':<20} {'Scanned'}")
    print("-" * 80)
    for r in rows:
        print(f"{r['canton']:<6} {(r['commune'] or ''):<25} {r['parcel_nr']:<10} "
              f"{(r['egrid'] or 'N/A'):<20} {r['scanned_at']}")
    print(f"\nTotal herrenlos parcels: {len(rows)}")


def cmd_herrenlos(args):
    print_herrenlos()


def cmd_captcha(args):
    from db import print_captcha_stats
    canton = getattr(args, "canton", None)
    # With no canton: show all cantons that have any recorded data (no hardcoded list).
    # Currently instrumented: BL, SZ, JU.
    # GE uses Imperva/browser challenge; NE uses Altcha PoW — different mechanism, not OCR.
    print_captcha_stats(canton.upper() if canton else None)


def cmd_test_history(args):
    from db import print_test_history
    canton = getattr(args, "canton", None)
    days   = getattr(args, "days",   7)
    print_test_history(canton.upper() if canton else None, days=days)


def cmd_ready(args):
    """
    Production-readiness view per canton:
      ✅ Ready    : latest test_run was 'pass' and no open blockers
      ⚠️  Caveat  : pass but quota/credentials/notes
      ⬜ Not ready: never tested, last test failed, or has open blocker
    """
    from db import latest_test_status, requests_today
    from test_fixtures import CANTON_STATUS, SCANNER_IMPORTS, TEST_GROUP_ORDER

    latest = latest_test_status()

    print()
    print(f"{'Canton':<6} {'Group':<13} {'Last test':<19} {'Tier':<5} {'Status':<7} {'Ready':<6}  Note")
    print("-" * 105)

    # Sort by test_group then canton
    cantons = sorted(
        (c for c in CANTON_STATUS if c in SCANNER_IMPORTS or c == "BS"),
        key=lambda c: (TEST_GROUP_ORDER.index(CANTON_STATUS[c]["test_group"]), c),
    )

    for c in cantons:
        s   = CANTON_STATUS[c]
        rec = latest.get(c)

        # Determine readiness
        if rec is None:
            mark, when, tier, st = "⬜", "never", "-", "-"
            note = f"untested; {s.get('blocker') or ''}"
        else:
            when = (rec["run_at"] or "")[:19]
            tier = rec["tier"]
            st   = rec["status"]
            if st == "pass" and (rec["false_positives"] or 0) == 0:
                # Check quota state — flag caveat if close to limit
                daily = s.get("daily_limit")
                used  = requests_today(c) if daily else 0
                if daily and (daily - used) < s.get("max_test_parcels", 0):
                    mark, note = "⚠️ ", f"quota tight: {used}/{daily} used today"
                elif rec["errors"]:
                    mark, note = "⚠️ ", f"{rec['errors']} retryable errors last run"
                else:
                    mark, note = "✅", ""
            elif st == "skip":
                mark = "⬜"
                note = (rec.get("blocker") or s.get("blocker") or "")
            else:  # fail
                mark = "❌"
                note = rec.get("blocker") or "test failed"

        # Append "needs:" hint if blocked.
        # Prefer the LIVE CANTON_STATUS["needs"] over the test_run snapshot — the
        # readiness view is about the current state, not what the docs said at
        # test time. test-history still shows the historical snapshot.
        if mark in ("⬜", "❌", "⚠️ "):
            needs = s.get("needs") or (rec.get("needs") if rec else None)
            if needs:
                note = f"{note}  ← needs: {needs}" if note else f"needs: {needs}"

        print(f"{c:<6} {s['test_group']:<13} {when:<19} {tier:<5} {st:<7} {mark:<6}  {note}")
    print()
    print("Legend:  ✅ ready   ⚠️ caveat (quota/errors)   ⬜ untested or skipped   ❌ failed")
    print()


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Herrenlos Scanner PoC")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("poc",       help="Quick PoC: small sample from UR + FR")
    sub.add_parser("stats",     help="Print DB statistics")
    sub.add_parser("herrenlos", help="List all herrenlos parcels found")

    p_cap = sub.add_parser("captcha", help="Print CAPTCHA solver accuracy per canton")
    p_cap.add_argument("canton", nargs="?", help="Canton to show (default: all OCR cantons)")

    p_hist = sub.add_parser("test-history", help="Print recent test_runs history")
    p_hist.add_argument("canton", nargs="?", help="Canton to filter (default: all)")
    p_hist.add_argument("--days", type=int, default=7,
                        help="Window in days (default: 7)")

    sub.add_parser("ready", help="Production-readiness view per canton (latest test status)")

    p_test = sub.add_parser("test", help="Run false-positive test suite")
    p_test.add_argument("cantons", nargs="*",
                        help="Cantons to test (default: all). E.g.: ge bs bl")
    p_test.add_argument("--tier", choices=["a", "b"], default="a",
                        help="a=fast REST-only (default); b=also slow portal+CAPTCHA tests")
    p_test.add_argument("--seed", action="store_true",
                        help="Seed parcel_enum with one fixture parcel per canton, then exit")

    for canton in ("ur", "fr", "so", "bs", "bs-public", "gr", "bl", "be", "sh", "ju", "vs", "ne", "sz", "ar", "ai",
                   "ag", "tg", "sg", "zg", "gl", "nw", "ow", "ti", "vd", "ge", "lu"):
        p = sub.add_parser(canton, help=f"Scan canton {canton.upper()}")
        p.add_argument("--limit",  type=int, default=None,
                       help="Max parcels to scan")
        p.add_argument("--rescan", action="store_true",
                       help="Re-scan parcels already in DB")
        if canton == "ne":
            p.add_argument("--refresh-enum", dest="refresh_enum", action="store_true",
                           help="Discard cached NE parcel/UUID list and re-enumerate from WFS")

    args = parser.parse_args()

    init_db()

    dispatch = {
        "poc":       cmd_poc,
        "ur":        cmd_ur,
        "fr":        cmd_fr,
        "so":        cmd_so,
        "bs":        cmd_bs,
        "bs-public": cmd_bs_public,
        "gr":        cmd_gr,
        "bl":        cmd_bl,
        "be":        cmd_be,
        "sh":        cmd_sh,
        "ju":        cmd_ju,
        "vs":        cmd_vs,
        "ne":        cmd_ne,
        "sz":        cmd_sz,
        "ar":        cmd_ar,
        "ai":        cmd_ai,
        "ag":        cmd_ag,
        "tg":        cmd_tg,
        "sg":        cmd_sg,
        "zg":        cmd_zg,
        "gl":        cmd_gl,
        "nw":        cmd_nw,
        "ow":        cmd_ow,
        "ti":        cmd_ti,
        "vd":        cmd_vd,
        "lu":        cmd_lu,
        "ge":        cmd_ge,
        "test":         cmd_test,
        "test-history": cmd_test_history,
        "ready":        cmd_ready,
        "stats":        cmd_stats,
        "herrenlos":    cmd_herrenlos,
        "captcha":      cmd_captcha,
    }

    if args.cmd in dispatch:
        dispatch[args.cmd](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
