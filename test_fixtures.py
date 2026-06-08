"""
Herrenlos Scanner — Test Runner
================================

TESTING STRATEGY (read this first)
-----------------------------------
Real herrenlos parcels are ~0.01% of all Swiss parcels — too rare to encounter
randomly in testing. Our tests are FALSE-POSITIVE GUARDS, not discovery tests.
A known-owned parcel must never come back as `is_herrenlos=1`. That is the
realistic failure mode (e.g. service-error pages misclassified as herrenlos,
parser bugs, CAPTCHA wrong-answer treated as empty owner).

We answer three questions on every run:
  1. Does the scanner produce false positives on known-owned parcels?  → pass/fail
  2. What's blocking us from testing this canton?                      → blocker
  3. What would we need to enable testing?                             → needs

Both are persisted to the `test_runs` table so we can answer "what works today
and what doesn't and why" without re-running anything.

Two test tiers (cost-based)
---------------------------
TIER A — fast REST-only false-positive regression (seconds per canton):
    GE  SITG cadastre REST: verify TYPE_PROPRI on known parcels (no Playwright/CAPTCHA)
    BS  check_owner_bs() direct REST call (needs BS_API_KEY)

TIER B — slow portal/CAPTCHA smoke (minutes per canton):
    BL, SZ, JU, GE, NE, SH, GR, UR, FR
    Seeds N known-owned parcels via swisstopo identify, runs the canton's
    scanner with --limit N, asserts no false positives. CAPTCHA stats land
    in `captcha_stats` automatically.

Canton groups (`test_group` in CANTON_STATUS)
---------------------------------------------
  rest          — plain REST/HTTP, no CAPTCHA          UR FR GR SH BS
  captcha_ocr   — image CAPTCHA, OCR-solvable          BL SZ JU
  captcha_pow   — proof-of-work / browser challenge    NE GE
  own_login     — user has cantonal account in .env    BE VS
  blocked       — SMS / Keycloak / professional-only   ZG SO + 10 geoportal cantons

Rate-limit handling (separate from IP rotation)
------------------------------------------------
`daily_limit` is the documented per-IP daily request cap, or None if no limit.
Before each TIER B canton runs, the runner checks `requests_today(canton)`
against this limit and either caps the test size or skips entirely. This is
what stops a daily test loop from burning the GR 10/day quota.

`ip_rotation` is only set to "deferred" when rotation is needed for the
PRODUCTION-SCALE scan, not for testing — SH (100/day) and NE (~50/day) are
fine for an 11-parcel test from a single IP, but a 50k-parcel scan would
need rotation.

Self-documenting failures
-------------------------
Each CANTON_STATUS entry carries `blocker` (concise reason this canton is
limited/excluded) and `needs` (what would unblock). Every failed/skipped
test row writes these to `test_runs`, so `python main.py test-history`
shows exactly what's missing for each canton without reading code.

USAGE
-----
  python main.py test                     # TIER A only (fast)
  python main.py test --tier b            # TIER A + B (slow)
  python main.py test --tier b ju sz      # specific cantons
  python main.py test --seed              # seed parcel_enum (no scan)
  python main.py test-history             # show last 7 days
  python main.py test-history bl          # one canton
"""

import sys
import pathlib
import logging
import requests
import argparse
import time

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from db import (
    get_conn, init_db, enum_cached, store_enum,
    store_test_run, requests_today, print_test_history,
)

log = logging.getLogger("TEST")

# ── Canton access + rate-limit registry ──────────────────────────────────────
# Single source of truth.
# Keys per canton:
#   access            : "public" | "free_key" | "own_account" | "cant_get" | "blocked"
#   test_group        : "rest" | "captcha_ocr" | "captcha_pow" | "own_login" | "blocked"
#   ip_rotation       : None | "deferred"  (only "deferred" when needed for FULL scan)
#   daily_limit       : int | None         (documented per-IP daily request cap)
#   rate_limit        : str | None         (human-readable description)
#   max_test_parcels  : int                (default sample size for TIER B)
#   blocker           : str | None         (why testing is limited / impossible)
#   needs             : str | None         (what would unblock)
#   reason            : str | None         (legacy free-form note)

CANTON_STATUS: dict[str, dict] = {
    # ── REST (no CAPTCHA, no auth) ───────────────────────────────────────────
    # UR: works from any Swiss residential IP. Server enforces ~14 req/day per IP
    # before triggering an SVG math CAPTCHA (solvable via scanners/ur_captcha.py
    # with ANTHROPIC_API_KEY). Geo-blocked from non-Swiss IPs entirely
    # (e.g. GitHub Actions) — scanner emits error="geo_blocked".
    "UR": {"access": "public",   "test_group": "rest", "ip_rotation": "deferred",
           "daily_limit": 30, "rate_limit": "~14 req/day/IP before math CAPTCHA; geo-blocked from non-Swiss IPs",
           "max_test_parcels": 11,
           "blocker": "geo-blocked from GitHub Actions datacenter IPs; daily quota makes bulk impractical without rotation or CAPTCHA solver",
           "needs": "run locally from a Swiss IP; for full 20k-parcel scan either rotate IPs OR set ANTHROPIC_API_KEY (math CAPTCHA solver extends the daily window)"},
    "FR": {"access": "public",   "test_group": "rest", "ip_rotation": None,
           "daily_limit": None, "rate_limit": None, "max_test_parcels": 11,
           "blocker": None, "needs": None},
    "GR": {"access": "public",   "test_group": "rest", "ip_rotation": "wired",
           "daily_limit": 10,   "rate_limit": "10 req/day/IP", "max_test_parcels": 5,
           "blocker": "10 req/day/IP — full scan needs paid residential proxies",
           "needs": "paid residential proxies (GR_PROXY_LIST plumbing already wired in scanners/gr.py)"},
    # SH: existing scanner WORKS (passes TIER B regression). FOLLOW-UP (2026-05-18):
    # research agent flagged a Sept 2024 SH portal launch — verify our scanner
    # uses the current endpoint (api.geo.sh.ch confirmed in scanner docstring).
    "SH": {"access": "public",   "test_group": "rest", "ip_rotation": "wired",
           "daily_limit": 100,  "rate_limit": "100 req/day/IP", "max_test_parcels": 11,
           "blocker": None,
           "needs": "paid residential proxies for full scan (SH_PROXY_LIST plumbing already wired in scanners/sh.py). Optional: verify scanner uses post-2024-09 endpoints (research agent flagged a new SH portal launch)."},
    # BS — DUAL-SCANNER ARCHITECTURE (updated 2026-05-19):
    # The BS public REST API exposes ONLY parcel METADATA (area, buildings,
    # land covers, type). Owner data is NOT in any JSON endpoint — only behind
    # the HTML viewer at /eigentum/{section}/{parcel} which loads reCAPTCHA
    # Enterprise then calls /eigentumsauskunftngeo/api/ with the token.
    #
    # TWO scanners together cover both herrenlos types:
    #   scanners/bs.py        — metadata REST + BS_API_KEY. Detects Type A
    #                           (Art. 664: not in Grundbuch). TIER A test only.
    #   scanners/bs_public.py — Playwright + reCAPTCHA Enterprise against the
    #                           HTML viewer. Extracts owner names + addresses.
    #                           Detects Type A AND Type B (Art. 964: dereliktion).
    #                           TIER B; used as default in SCANNER_IMPORTS.
    #
    # Rate limit on the HTML viewer: 10 queries/day/IP (hard cap displayed by
    # the portal itself). Full ~7k-parcel BS scan needs paid residential proxies
    # (same model as GR and SO). BS_PROXY_LIST in .env enables rotation in
    # bs_public.scan().
    "BS": {"access": "free_key", "test_group": "captcha_pow", "ip_rotation": "deferred",
           "daily_limit": 10, "rate_limit": "HTML viewer: 10 req/day/IP (reCAPTCHA Enterprise); metadata API: unlimited with free key",
           "max_test_parcels": 5,
           "blocker": "10 req/day/IP hard cap on the BS HTML owner-viewer — full scan needs paid residential proxies",
           "needs": "paid residential proxies (BS_PROXY_LIST in .env) — proxy rotation already wired in bs_public.scan(); BS_API_KEY required for section lookup"},

    # ── OCR-image CAPTCHA ────────────────────────────────────────────────────
    # BL: handwritten cursive image CAPTCHA defeats local OCR.
    # captcha_stats from our actual test runs:
    #   BL  ddddocr   0/3 correct  (vs JU 95%, SZ 54%)
    #   BL  tesseract 0/1 correct
    # Claude vision is the only solver that reliably reads handwritten cursive.
    # No rate limit beyond the per-query CAPTCHA itself (portal cooldown after
    # ~10 rapid requests handled via internal 4s retry delay). No IP rotation
    # needed even at full scale.
    "BL": {"access": "public",   "test_group": "captcha_ocr", "ip_rotation": None,
           "daily_limit": None, "rate_limit": "CAPTCHA per query; portal cooldown after ~10 rapid (built-in 4s retry delay)",
           "max_test_parcels": 5,
           "blocker": "Handwritten cursive CAPTCHA — local OCR 0% accuracy in captcha_stats (vs 95% for JU, 54% for SZ). Without Claude all attempts retry-exhaust.",
           "needs": "ANTHROPIC_API_KEY in .env (Claude vision). ~$0.003/parcel × ~70k parcels = ~$210 for full BL scan. No proxies needed (no IP rate limit)."},
    "SZ": {"access": "public",   "test_group": "captcha_ocr", "ip_rotation": None,
           "daily_limit": None, "rate_limit": "CAPTCHA per query only",
           "max_test_parcels": 5,
           "blocker": None, "needs": None},
    "JU": {"access": "public",   "test_group": "captcha_ocr", "ip_rotation": None,
           "daily_limit": None, "rate_limit": "CAPTCHA per query only",
           "max_test_parcels": 11,
           "blocker": None, "needs": None},

    # ── PoW / browser challenge ──────────────────────────────────────────────
    # NE: working — but WFS-provided UUIDs are short-lived session tokens that
    # expire after a few hours. When test_runs show 100% 'stale_uuid' errors,
    # the fix is:  python main.py ne --refresh-enum --limit N
    # which re-enumerates the WFS and stores fresh UUIDs. Verified 2026-05-18:
    # after refresh, NE went from 11/11 errored back to 11/11 PASS.
    "NE": {"access": "public",   "test_group": "captcha_pow", "ip_rotation": "deferred",
           "daily_limit": 50,   "rate_limit": "~50 req/day/IP (Altcha PoW CAPTCHA); WFS UUIDs expire — periodic --refresh-enum needed",
           "max_test_parcels": 11,
           "blocker": None,
           "needs": "1) periodically refresh WFS UUIDs via `python main.py ne --refresh-enum` (UUIDs expire); 2) paid residential proxies + port GE's proxy plumbing into scanners/ne.py for full scan (currently not wired)"},
    # GE has TWO stacked gates (corrected 2026-05-18):
    #   1. Imperva TSPD — Playwright+stealth handles it for ~30 req/IP then blocks
    #   2. Image CAPTCHA per parcel — ddddocr→tesseract→Claude. Scanner author
    #      documented "ddddocr struggles with GE's style; Claude gives best results
    #      ~$0.003/parcel". CAPTCHA solver chain is implemented but NOT empirically
    #      verified — we never reached it in our test runs because Imperva blocks first.
    "GE": {"access": "public",   "test_group": "captcha_pow", "ip_rotation": "deferred",
           "daily_limit": 30,   "rate_limit": "Imperva TSPD ~30 req/IP + image CAPTCHA per parcel",
           "max_test_parcels": 5,
           "blocker": "Imperva TSPD blocks our test IP after ~30 req; even with proxies, post-Imperva image CAPTCHA needs Claude (ddddocr-hostile per scanner docstring)",
           "needs": "BOTH: paid residential proxies (~$30; GE_PROXY_LIST plumbing wired) AND ANTHROPIC_API_KEY (~$200 for 69k parcels × ~$0.003/parcel Claude vision). First-priority check on first proxied run: verify Claude actually solves GE's specific CAPTCHA style — accuracy unverified."},

    # ── Own personal accounts ────────────────────────────────────────────────
    # BE and VS both need interactive auth on first run; tokens then cache.
    # The two flows are DIFFERENT:
    #   BE — webbrowser.open() → Safari/default browser → user logs in →
    #        user must press F12 → Console → paste a JS snippet (printed by
    #        the scanner) → token JSON downloads to ~/Downloads → scanner
    #        polls and loads it. (BE-Login has Cloudflare Turnstile which
    #        blocks Playwright entirely, so no automated browser flow.)
    #   VS — Playwright opens its own Chromium window (headless=False) →
    #        user logs into SwissID with 2FA → scanner intercepts the
    #        access_token automatically. No console paste needed.
    #
    # AUTH PROVIDERS (different for each):
    #   BE — AGOV (be.ch identity portal); per-account quota confirmed on
    #        owner-name resolution endpoint (GET /api/gb/person/master).
    #        Run at conservative delays; 429s are real and per-account.
    #   VS — SwissID (swissid.ch); scan endpoints appear unlimited once
    #        authenticated. ICP-extract is 10/day but scanner avoids it.
    #        IP rotation is irrelevant (no quota to route around; 2FA
    #        binds session to a personal account regardless).
    #
    # Token lifecycle (both cantons):
    #   access_token  ~5 min — refreshed automatically by the scanner
    #   refresh_token ~30 min rotating — a new one is issued on each use
    #   Session stays alive indefinitely while the scanner runs continuously.
    #   Any gap >~30 min without a query causes the refresh_token to expire
    #   → manual re-auth required on next run.
    "BE": {"access": "own_account", "test_group": "own_login", "ip_rotation": None,
           "daily_limit": None,
           "rate_limit": "per-account (personal AGOV identity) — CONFIRMED per-account "
                         "(empirically verified: fresh browser session + new token still "
                         "returned 429, proving the limit is on the account, not the IP). "
                         "Limit appears to be on the person/owner-name resolution step "
                         "(GET /api/gb/person/master), not on parcel lookups. Threshold "
                         "count unknown. access_token 5min / refresh_token 30min rotating; "
                         "session alive while running, re-auth after >~30min gap; IP "
                         "rotation cannot help — account is the hard constraint",
           "max_test_parcels": 5,
           "blocker": "Interactive BE-Login (AGOV) — Safari opens; on macOS the scanner pulls the token automatically via AppleScript (one-time setup: enable 'Show Develop menu' + 'Allow JavaScript from Apple Events' in Safari); paste-in-console fallback otherwise",
           "needs": "free AGOV/BE-Login account; one-time enable Safari's Apple Events JS; run at conservative delay — 429s are real and per-account with no IP rotation workaround"},
    "VS": {"access": "own_account", "test_group": "own_login", "ip_rotation": None,
           "daily_limit": None,
           "rate_limit": "SwissID session, scan endpoints appear unlimited. VS uses SwissID "
                         "(login.swissid.ch) — NOT AGOV; BE and VS use different identity "
                         "providers. The ICP-extract endpoint is 10/day but the scanner "
                         "deliberately avoids it. Main scan endpoints (grundstueck + eigentum "
                         "JSON API) show no per-query quota. IP rotation is irrelevant: "
                         "SwissID 2FA means any session is bound to a personal account, but "
                         "there is no quota to route around. access_token ~5min / "
                         "refresh_token rotating; re-auth needed after any gap >~30min.",
           "max_test_parcels": 5,
           "blocker": "Interactive SwissID login — Playwright Chromium window opens; just log in there, scanner extracts token automatically",
           "needs": "free SwissID account at swissid.ch; complete login in the Chromium window that opens; scan endpoints appear unlimited once authenticated"},

    # ── geoportal.ch-based cantons + other restricted ones ──────────────────
    # VERIFICATION PASS — 2026-05-18 (agent + direct portal inspection):
    # All 10 cant_get/blocked classifications below were RE-CONFIRMED by both
    # web research and (where possible) direct Chrome DevTools inspection.
    # Detailed evidence and URLs are in each canton's `blocker` / `needs` field.
    # Summary of why each is excluded under our policy:
    #   AI, AR        : Terravis professional + private = mail-only (CHF 40, ~1 week)
    #   GL            : my.gl.ch needs AGOV LoA-3 (not self-service; federal e-ID
    #                   launches 1 Dec 2026 — revisit then)
    #   NW            : online form is purpose-bound, postal return, not direct lookup
    #   OW            : Terravis-only; 2021 public-portal plans never delivered
    #   TI            : SIFTI requires registry-issued auth (ORF Art. 28+)
    #   VD            : prestations.vd.ch/pub/101435 is form-mail with 48h turnaround
    # PARTIALLY BUILDABLE (still unbuilt; needs paid CAPTCHA solver or registration):
    #   SG            : reCAPTCHA Enterprise v2 visible checkbox → needs 2captcha service
    #   AG            : public AGIS path requires smartserviceportal account to inspect
    # See test_runs / `python main.py ready` for live status.
    # AR: Confirmed 2026-05 — Terravis online access for banks/insurance/notaries
    # only; private persons must request shortened extract by MAIL (Art. 970 ZGB).
    # Not solvable by IP rotation (no automatable online path for private persons).
    "AR": {"access": "cant_get", "test_group": "blocked", "ip_rotation": None,
           "daily_limit": None, "rate_limit": None, "max_test_parcels": 0,
           "blocker": "no automatable online path for private persons (Terravis = professional only; shortened extract for private persons is mail-only)",
           "needs": "no workaround — mail-only access is not automatable"},
    # AI: Same as AR — Terravis for professionals, mail-only for private persons.
    "AI": {"access": "cant_get", "test_group": "blocked", "ip_rotation": None,
           "daily_limit": None, "rate_limit": None, "max_test_parcels": 0,
           "blocker": "no automatable online path for private persons (same as AR — Terravis professional + mail-only for private)",
           "needs": "no workaround — mail-only access is not automatable"},
    # AG: VERIFIED 2026-05-18 via Chrome MCP — public AGIS Viewer is open without
    # login for MAP browsing, but the "Grundeigentümer abfragen" button on parcel
    # detail panel is GREYED OUT with message "Für Grundeigentümerabfrage anmelden"
    # (log in to query property owner). So the owner-query endpoint requires a
    # logged-in smartserviceportal account. Free registration is open to private
    # persons; ~10 free queries per user. Scanner pattern = BE (interactive OIDC
    # login → token cache → REST queries).
    "AG": {"access": "unbuilt", "test_group": "unbuilt", "ip_rotation": "deferred",
           "daily_limit": 10, "rate_limit": "~10 free queries per registered user (login required)",
           "max_test_parcels": 0,
           "blocker": "owner-query button is logged-in-only (smartserviceportal); no scanner module yet; account registration required to inspect actual API",
           # CONFIRMED 2026-06-08 via live fetch: registration requires only a valid
           # email address — no Swiss ID / phone proofing. Equivalent to BS/BE free-
           # registration paths. The 10-query cap per account is the real constraint
           # for full-scale scanning (130k parcels needs account cycling or proxy).
           "needs": "register at ag.ch/de/smartserviceportal/konto/registrierung "
                    "(email only — no Swiss ID/phone proofing required); capture "
                    "owner-query endpoint via browser DevTools; build BE-style OIDC "
                    "scanner; 10 free queries/account means full 130k-parcel scan "
                    "needs account cycling or proxy arrangement"},
    # TG remains blocked: SMS verification per query is a human-action gate, not
    # something IP rotation can solve. Same operational dead-end as ZG and ZH.
    "TG": {"access": "blocked", "test_group": "blocked", "ip_rotation": None,
           "daily_limit": None, "rate_limit": "Public path requires SMS per query",
           "max_test_parcels": 0,
           "blocker": "map.geo.tg.ch is publicly accessible BUT requires SMS verification per query — same operational dead-end as ZG/ZH (cannot be solved by IP rotation)",
           "needs": "no known workaround under our policy (SMS-per-query requires human action per request)"},
    # SG: ENDPOINT CAPTURED 2026-05-18 via Chrome MCP direct inspection.
    #   geoportal.ch/ktsg map → "Eigentümer | Anzeigen" button → reveals
    #     interactive reCAPTCHA Enterprise v2 ("I'm not a robot" checkbox).
    #   Backing endpoint: GET https://www.geoportal.ch/search/ownerinfo/
    #     (already used by scanners/geoportal_base.py for the professional path).
    #     Without owner.search permission OR a valid reCAPTCHA token, returns
    #     {"challenge": true}. With reCAPTCHA token, returns owner JSON.
    # Per Rheintaler 2024-10, after the 2023 cantonal ordinance revision virtually
    # ALL SG municipalities publish owners publicly (only Eichberg holds out).
    "SG": {"access": "unbuilt", "test_group": "unbuilt", "ip_rotation": "deferred",
           "daily_limit": None, "rate_limit": "Public via reCAPTCHA Enterprise v2 checkbox per parcel",
           "max_test_parcels": 0,
           "blocker": "no scanner module against the public CAPTCHA path; geoportal.ch/search/ownerinfo/ endpoint shared with professional path but needs reCAPTCHA v2 solving for anonymous use",
           # CONFIRMED 2026-06-08 via live API probe: GET /search/ownerinfo?egrid=...
           # returns {"challenge":true} without a valid token — endpoint is live.
           # CAPTCHA type confirmed: Enterprise v2 checkbox ("I'm not a robot"),
           # NOT v3 invisible. Playwright stealth cannot auto-click v2 checkbox —
           # requires a dedicated solver (2captcha 'enterprises' endpoint, not
           # standard v2). Cost: ~$0.003/solve × 115k parcels ≈ $345.
           "needs": "build scanner using geoportal_base.py + reCAPTCHA Enterprise v2 "
                    "solver (2captcha 'enterprises' endpoint ~$0.003/solve × 115k "
                    "parcels ≈ $345; NOT Playwright auto-click — v2 checkbox cannot "
                    "be auto-solved); paid residential proxies for full scan"},
    # GL: CONFIRMED BLOCKED (researched 2026-05-18) — my.gl.ch Grundbuch service
    # requires AGOV LoA-3 ("erhöht"), which currently requires manual identity
    # proofing and is NOT self-service. The federal Swiss e-ID that would unlock
    # self-service LoA-3 was postponed from summer 2026 to 1 December 2026 (SFAO
    # security audit). Until then, GL is effectively locked. Revisit Dec 2026.
    "GL": {"access": "cant_get", "test_group": "blocked", "ip_rotation": None,
           "daily_limit": None, "rate_limit": None, "max_test_parcels": 0,
           "blocker": "my.gl.ch requires AGOV LoA-3; only obtainable via manual identity proofing today; federal e-ID self-service path postponed to 1 December 2026",
           "needs": "wait for Swiss federal e-ID launch (postponed to Dec 2026); revisit then"},
    # NW: VERIFIED 2026-05 — nw.ch/online-schalter offers form-based ORDERING of
    # Grundbuchauszüge for specific purposes (building submissions, bank credits).
    # This is a request-by-purpose model, not a direct lookup — submit a request,
    # office processes it. Not automatable for "owner of arbitrary parcel" queries.
    "NW": {"access": "cant_get", "test_group": "blocked", "ip_rotation": None,
           "daily_limit": None, "rate_limit": None, "max_test_parcels": 0,
           "blocker": "online presence is a request form for ordering extracts by purpose (building submission, bank credit, etc.) — not a direct owner lookup; effectively form-mail equivalent",
           "needs": "no automatable workaround (would need to fake purpose codes — not legitimate)"},
    # OW: VERIFIED 2026-05 — Terravis professional portal launched April 2022 for
    # banks/insurance/notaries. Public Eigentumsabfrage was "planned" 2021 but
    # not delivered for private persons.
    "OW": {"access": "cant_get", "test_group": "blocked", "ip_rotation": None,
           "daily_limit": None, "rate_limit": None, "max_test_parcels": 0,
           "blocker": "Terravis portal serves professionals only; public Eigentumsabfrage was planned 2021 but not delivered for private persons (verified 2026-05)",
           "needs": "no public-path workaround currently; revisit if ow.ch announces public access"},
    # TI: VERIFIED 2026-05 — SIFTI-web requires authorization from registry section
    # under ORF Art. 28+; explicitly excludes "craftspeople, consultants, trust
    # companies, planners, architects, real estate agents." Public alternative via
    # Geoportale Ticino only shows lot numbers/EGRIDs; owner info requires a
    # manual mail request to the Land Registry Office (not automatable).
    "TI": {"access": "cant_get", "test_group": "blocked", "ip_rotation": None,
           "daily_limit": None, "rate_limit": None, "max_test_parcels": 0,
           "blocker": "SIFTI-web requires registry-issued authorization (professional-only); Geoportale Ticino shows lots only, owner info requires manual mail request to registry office",
           "needs": "no automatable public-path workaround (mail request is not automatable)"},
    # VD: RE-CORRECTED 2026-05 — prestations.vd.ch/pub/101435/ is form-based, NOT a
    # real-time query: 5 requests/day per person AND 48-hour response time (results
    # come by email, not instantly). Means a full ~200k-parcel canton scan would
    # take ~40,000 days. Not feasible as a real-time scanner; same operational
    # category as NW (form-mail-equivalent).
    "VD": {"access": "cant_get", "test_group": "blocked", "ip_rotation": None,
           "daily_limit": 5, "rate_limit": "5 req/day + 48h email turnaround",
           "max_test_parcels": 0,
           "blocker": "vd.ch consultation is form-based with 48h email turnaround (not real-time); full canton scan would take ~40k days — not viable as scanner",
           "needs": "no real-time public path. INTERCAPI is the only real-time option but requires professional accreditation (notaries/lawyers/surveyors/banks)"},

    # ── Explicitly blocked (no public access at all) ─────────────────────────
    "ZG": {"access": "blocked", "test_group": "blocked", "ip_rotation": None,
           "daily_limit": None, "rate_limit": None, "max_test_parcels": 0,
           "blocker": "lr.zugmap.ch requires SMS verification per query",
           "needs": "no known workaround for private persons"},
    # SO: ENDPOINT CAPTURED 2026-05-18 via Chrome MCP direct inspection.
    #   Captcha bootstrap: GET geo.so.ch/api/v1/plotinfo/plot_owner/captcha/{EGRID}
    #     → returns HTML page that loads grecaptcha and calls
    #       grecaptcha.execute('6Lf1zcYUAAAAAEggUTd-dzwF8UuoXmt_az29LFO-', {action:'plotOwnerInfo'})
    #       then posts the token via window.top.plotOwnerInfo.loadOwnerInfo(EGRID, token)
    #   Owner query: GET geo.so.ch/api/v1/plotinfo/plot_owner/{EGRID}?token={recaptcha_v3_token}
    #     → JSON with owner + ownership form on success
    #     → 200 {"error":"Captcha verification failed","success":false} without valid token
    # Implementation: Playwright stealth (like GE) loads the captcha HTML iframe;
    # grecaptcha auto-resolves invisibly (v3 score-based); intercept the token
    # before it's used. Site key + action are PUBLIC (in JS source).
    # SO: WIRED + LIVE-TESTED 2026-05-18 — scanners/so_public.py implements the
    # public reCAPTCHA v3 flow captured via Chrome DevTools. Existing scanners/so.py
    # professional path preserved alongside for institutional use.
    #
    # GE vs SO progress comparison (both are SKIP today; this matters for prioritising
    # which proxy budget to spend first):
    #   GE today: errors = "service_unavailable" / "failed_after_4_retries"
    #             → Imperva TSPD blocks BEFORE the CAPTCHA layer is even reached.
    #   SO today: errors = "Captcha verification failed" / occasional http_429
    #             → server reached, token captured, response parsed; only the
    #               Google reCAPTCHA SCORE rejects us at the last step.
    # SO is therefore "closer to working" than GE — same proxy fix unblocks both,
    # but SO has a shorter remaining diff (just a higher reCAPTCHA score, not
    # also bypassing Imperva).
    #
    # Tested 2026-05-18 with: headless=False + playwright-stealth + warm-up via
    # /map page + 2.5s human-idle delay. Token captured (2041 chars), endpoint
    # returns 200, but server's score-validation still rejects → confirms the
    # remaining gate is IP-reputation, not browser environment.
    "SO": {"access": "public", "test_group": "captcha_pow", "ip_rotation": "deferred",
           "daily_limit": None, "rate_limit": "reCAPTCHA v3 score-based; bot-detection blocks from datacenter IPs",
           "max_test_parcels": 5,
           "blocker": "scanner wired and proven end-to-end (token captured, endpoint reached). The ONLY remaining gate is Google reCAPTCHA score-validation rejecting our datacenter IP. NOT a browser-environment issue — verified with headless=False + stealth + warm-up.",
           "needs": "paid residential proxies (SO_PROXY_LIST in .env) — scanner has rotation plumbing already; ~$30 one-time for full scan. SO is closer to working than GE (server reaches us; only score-validation rejects)."},

    # ── Unbuilt — Swiss cantons we have NOT yet investigated or scanned ──────
    # Listed here so CANTON_STATUS sums to all 26 Swiss cantons. These are real
    # gaps in coverage, not blocked cantons: access mechanism is simply unknown.
    # LU: BLOCKED 2026-05-18 — direct portal inspection (Chrome MCP) revealed the
    # form at grundbuch.lu.ch/onlinedienste/eigentuemerabfrage requires:
    #   - Grundbuch (dropdown)
    #   - Grundstück-Nummer
    #   - Mobile-Nummer (Swiss mobile)
    #   - PIN sent via SMS ("hier PIN anfordern")
    # "Beachten Sie, dass für die Eigentümerabfrage eine gültige Schweizer
    # Mobile-Nummer benötigt wird". This is operationally the same dead-end as
    # ZH/ZG/TG — SMS gate cannot be solved by IP rotation. Earlier "5/day public"
    # research underweighted the SMS requirement.
    "LU": {"access": "blocked", "test_group": "blocked", "ip_rotation": None,
           "daily_limit": 5, "rate_limit": "5/day with Mobile-Nr + SMS PIN per query",
           "max_test_parcels": 0,
           "blocker": "grundbuch.lu.ch/onlinedienste/eigentuemerabfrage requires Swiss Mobile-Nr + SMS PIN per query — same operational dead-end as ZH/ZG/TG (verified by direct portal inspection 2026-05-18)",
           "needs": "no known workaround for private persons (SMS-per-query gate)"},
    # ZH is effectively BLOCKED for an automated scanner. Confirmed 2026-05 via
    # law.ch and NZZ: maps.zh.ch GIS-Browser requires SMS verification on each
    # query; Swiss mobile number required; 5 queries per day. Identical to ZG.
    "ZH": {"access": "blocked", "test_group": "blocked", "ip_rotation": None,
           "daily_limit": 5, "rate_limit": "5 req/day/person + SMS code per query",
           "max_test_parcels": 0,
           "blocker": "maps.zh.ch requires SMS verification per query (Swiss mobile number) — same operational dead-end as ZG; ~450k parcels makes automation prohibitive",
           "needs": "no known workaround for private persons (same SMS-per-query gate as ZG)"},
}

TESTABLE_CANTONS = {c for c, s in CANTON_STATUS.items()
                    if s["access"] in ("public", "free_key", "own_account")}

# Group iteration order — controls section ordering in summary output.
# "unbuilt" = Swiss cantons we have not yet built a scanner for (LU, ZH).
TEST_GROUP_ORDER = ["rest", "captcha_ocr", "captcha_pow", "own_login", "blocked", "unbuilt"]

# ── Swisstopo identify — used for seeding parcel_enum ────────────────────────
IDENTIFY = "https://api3.geo.admin.ch/rest/services/api/MapServer/identify"
UA = "Mozilla/5.0 herrenlos-scanner-tests"

# Known commune centres (LV95: E, N) — pick reliable residential parcels.
CANTON_SEED_POINTS: dict[str, tuple[int, int]] = {
    "ZG": (2682000, 1225000),   "GR": (2760000, 1190000),
    "BL": (2622000, 1259000),   "FR": (2578000, 1183000),
    "JU": (2593000, 1245000),   "NE": (2562000, 1205000),
    "SO": (2607000, 1228000),   "SH": (2690000, 1283000),
    "SZ": (2691000, 1208000),   "UR": (2691000, 1192000),
    "GE": (2500000, 1117000),   "BS": (2611000, 1267000),
    "BE": (2600000, 1199000),   "VS": (2593000, 1127000),
}


# ── Fixtures (TIER A reference data) ─────────────────────────────────────────

GE_FIXTURES: list[dict] = [
    {"label": "GE Vernier 3102 — false positive regression",
     "egrid": "CH616356658840", "no_comm": 46, "parcel_nr": "3102", "bfs_nr": "6643",
     "expect_herrenlos": False, "sitg_type_propri": "privé",
     "note": "Flagged herrenlos in first GE scan; TSPD challenge misclassified."},
    {"label": "GE Versoix 7403 — false positive regression (dépendance)",
     "egrid": "CH776392106563", "no_comm": 47, "parcel_nr": "7403", "bfs_nr": "6644",
     "expect_herrenlos": False, "sitg_type_propri": "dépendance",
     "note": "Flagged herrenlos in first GE scan; TSPD challenge misclassified."},
    {"label": "GE Aire-la-Ville 722 — historical bien-sans-maître (1999)",
     "egrid": "CH976389156507", "no_comm": 1, "parcel_nr": "722", "bfs_nr": "6601",
     "expect_herrenlos": False, "sitg_type_propri": "privé",
     "note": "Reported as 'bien sans maître' in Le Temps 1999. SITG now shows privé."},
]


# ── Seeding ──────────────────────────────────────────────────────────────────

def _lookup_parcel_swisstopo(canton: str, e: int, n: int) -> dict | None:
    """
    Resolve one swisstopo identify point to a parcel dict, or None.

    IMPORTANT: always stores `extra={"east": e, "north": n}` — some scanners
    (notably SH) look up ownership by coordinate, not by EGRID/parcel_nr, and
    fail with "No coordinates for EGRID" if extra is empty. Keeping the query
    point as the parcel's representative coordinate is exactly what SH's own
    enumeration does — any point inside the parcel works for the lookup.
    """
    try:
        r = requests.get(IDENTIFY, params={
            "geometry":       f"{e},{n}",
            "geometryType":   "esriGeometryPoint",
            "imageDisplay":   "500,500,96",
            "mapExtent":      f"{e-500},{n-500},{e+500},{n+500}",
            "tolerance":      5,
            "layers":         "all:ch.swisstopo-vd.amtliche-vermessung",
            "sr":             2056, "lang": "de", "returnGeometry": "false",
        }, headers={"User-Agent": UA}, timeout=10)
        if r.status_code != 200:
            return None
        for feat in r.json().get("results", []):
            attrs = feat.get("attributes", {})
            if attrs.get("ak", "").upper() != canton.upper():
                continue
            egrid = attrs.get("egris_egrid", "")
            if egrid:
                return {
                    "egrid":     egrid,
                    "bfs_nr":    str(attrs.get("bfsnr", "")),
                    "parcel_nr": str(attrs.get("number", "")),
                    "commune":   attrs.get("label", ""),
                    "extra":     {"east": e, "north": n},
                }
    except Exception as exc:
        log.warning("%s seed lookup error: %s", canton, exc)
    return None


def seed_canton(canton: str) -> dict | None:
    """Ensure parcel_enum has ≥1 entry for canton. Returns first parcel or None."""
    return _seed_canton_n_impl(canton, n=1, primary_only=True)


def seed_canton_n(canton: str, n: int) -> int:
    """
    Ensure parcel_enum has ≥ n entries for *canton*. Returns the actual count
    cached. Walks a small 100m grid around the canton's seed point until n
    unique parcels are found (or we run out of grid points).
    Cantons whose own enumeration is already cached (e.g. JU with 16k WFS
    entries) are returned as-is — no extra seeding needed.
    """
    _seed_canton_n_impl(canton, n=n, primary_only=False)
    with get_conn() as conn:
        cached = enum_cached(conn, canton.upper()) or []
    return len(cached)


def _seed_canton_n_impl(canton: str, n: int, primary_only: bool) -> dict | None:
    with get_conn() as conn:
        cached = enum_cached(conn, canton.upper()) or []
    if len(cached) >= n:
        log.info("%s: %d cached parcels — using existing", canton, len(cached))
        return cached[0] if cached else None

    pt = CANTON_SEED_POINTS.get(canton.upper())
    if not pt:
        log.warning("%s: no seed point defined", canton)
        return None
    e0, n0 = pt

    seen = {(p["bfs_nr"], p["parcel_nr"]) for p in cached}
    new: list[dict] = []

    # Spiral outward in 100m steps until we have enough; cap at 7x7 = 49 points
    grid: list[tuple[int, int]] = []
    for radius in range(0, 4):
        if radius == 0:
            grid.append((0, 0))
            continue
        for dx in range(-radius, radius + 1):
            grid.append((dx, -radius))
            grid.append((dx,  radius))
        for dy in range(-radius + 1, radius):
            grid.append((-radius, dy))
            grid.append(( radius, dy))

    for dx, dy in grid:
        if len(cached) + len(new) >= n:
            break
        parcel = _lookup_parcel_swisstopo(canton.upper(), e0 + dx*100, n0 + dy*100)
        if not parcel:
            continue
        key = (parcel["bfs_nr"], parcel["parcel_nr"])
        if key in seen:
            continue
        seen.add(key)
        new.append(parcel)
        if primary_only:
            break
        time.sleep(0.1)   # polite to swisstopo

    if new:
        log.info("%s: seeded %d new parcel(s)", canton, len(new))
        with get_conn() as conn:
            store_enum(conn, canton.upper(), new)

    with get_conn() as conn:
        cached = enum_cached(conn, canton.upper()) or []
    return cached[0] if cached else None


# ── TIER A (REST-only) ───────────────────────────────────────────────────────

SITG_URL = ("https://ge.ch/terags/rest/services/"
            "ECADASTRE_rdppf_map/MapServer/19/query")


def _sitg_query(egrid: str) -> dict | None:
    try:
        r = requests.get(SITG_URL, params={
            "where": f"EGRID='{egrid}'",
            "outFields": "EGRID,NO_COMM,NO_PARCELLE,COMMUNE,TYPE_PROPRI,SURFACE",
            "f": "json", "returnGeometry": "false",
        }, timeout=15)
        if r.status_code != 200:
            return None
        feats = r.json().get("features", [])
        return feats[0]["attributes"] if feats else None
    except Exception as exc:
        log.warning("SITG query error for %s: %s", egrid, exc)
        return None


def _run_tier_a_ge() -> list[dict]:
    """GE SITG cadastre regression — verify TYPE_PROPRI on known fixtures."""
    results = []
    for f in GE_FIXTURES:
        r = {"label": f["label"], "tier": "A", "canton": "GE", "group": "rest"}
        attrs = _sitg_query(f["egrid"])
        if attrs is None:
            r.update({"pass": False, "reason": f"EGRID {f['egrid']} not found in SITG"})
        elif not attrs.get("TYPE_PROPRI"):
            r.update({"pass": False,
                      "reason": f"TYPE_PROPRI empty for EGRID {f['egrid']} — may be herrenlos in cadastre"})
        elif attrs["TYPE_PROPRI"] != f["sitg_type_propri"]:
            r.update({"pass": None,
                      "reason": f"TYPE_PROPRI changed: expected {f['sitg_type_propri']!r} "
                                f"but got {attrs['TYPE_PROPRI']!r} — update fixture"})
        else:
            r.update({"pass": True, "reason": f"TYPE_PROPRI={attrs['TYPE_PROPRI']!r} confirmed"})
        results.append(r)
    return results


def _run_tier_a_bs() -> list[dict]:
    """BS REST smoke — call check_owner_bs() if BS_API_KEY is configured."""
    import os
    status = CANTON_STATUS["BS"]
    api_key = os.environ.get("BS_API_KEY", "").strip()
    if not api_key or api_key == "YOUR_FREE_KEY_HERE":
        return [{"label": "BS REST smoke", "tier": "A", "canton": "BS", "group": "rest",
                 "pass": None,
                 "reason": "BS_API_KEY not set — export BS_API_KEY=<key> or add to .env",
                 "needs": "free key from https://api.geo.bs.ch/"}]

    with get_conn() as conn:
        cached = enum_cached(conn, "BS")
    if not cached:
        return [{"label": "BS REST smoke", "tier": "A", "canton": "BS", "group": "rest",
                 "pass": None,
                 "reason": "No BS parcels in parcel_enum — run with --seed bs first",
                 "needs": "python main.py test --seed bs"}]

    egrid = cached[0]["egrid"]
    label = f"BS owned parcel egrid={egrid} nr={cached[0]['parcel_nr']}"
    try:
        from scanners.bs import check_owner_bs
        result = check_owner_bs(egrid, api_key)
    except Exception as exc:
        return [{"label": label, "tier": "A", "canton": "BS", "group": "rest",
                 "pass": False, "reason": f"Exception: {exc}"}]

    if result.get("is_herrenlos") == 1:
        return [{"label": label, "tier": "A", "canton": "BS", "group": "rest",
                 "pass": False, "reason": f"FALSE POSITIVE: is_herrenlos=1, owner={result.get('owner')!r}"}]
    if result.get("error") == "invalid_api_key":
        return [{"label": label, "tier": "A", "canton": "BS", "group": "rest",
                 "pass": False, "reason": "Invalid BS API key", "needs": "valid BS_API_KEY in .env"}]
    if result.get("error"):
        return [{"label": label, "tier": "A", "canton": "BS", "group": "rest",
                 "pass": None, "reason": f"Error (not a FP): {result['error']}"}]
    return [{"label": label, "tier": "A", "canton": "BS", "group": "rest",
             "pass": True, "reason": f"is_herrenlos=0, owner={result.get('owner')!r}"}]


# ── TIER B (portal / scanner) ────────────────────────────────────────────────
# Generalized smoke: seed N parcels, run scanner with limit=N, check zero FPs.

SCANNER_IMPORTS = {
    "BL": "scanners.bl",  "SZ": "scanners.sz",  "JU": "scanners.ju",
    "UR": "scanners.ur",  "FR": "scanners.fr",  "GR": "scanners.gr",
    "SH": "scanners.sh",  "NE": "scanners.ne",  "GE": "scanners.ge",
    "BE": "scanners.be",  "VS": "scanners.vs",
    # Scaffolds (2026-05-18) — check_owner() stubs return error="not_implemented"
    # until the canton portal's API is captured via browser inspection. These
    # entries let the test framework dispatch to them and record the SKIP cleanly.
    "LU": "scanners.lu",  "AG": "scanners.ag",
    # SO has TWO scanners:
    #   scanners.so         — legacy professional Capitastra/intercapi.so.ch path
    #                         (kept for institutional callers; needs Keycloak credentials)
    #   scanners.so_public  — NEW (2026-05-18): public reCAPTCHA-v3 path via geo.so.ch
    # The test framework points at the public one because it's testable without auth.
    "SO": "scanners.so_public",
    # BS has TWO scanners:
    #   scanners.bs         — metadata REST + BS_API_KEY. Detects Type A only.
    #                         Used in TIER A (_run_tier_a_bs) for the fast REST check.
    #   scanners.bs_public  — Playwright + reCAPTCHA Enterprise (2026-05-19).
    #                         Extracts owner names + detects Type A AND Type B.
    # TIER B points at the public one (the only one that returns owner names).
    "BS": "scanners.bs_public",
}


def _quota_check(canton: str) -> tuple[int, str | None]:
    """
    Return (allowed_n, blocker_reason). allowed_n = min(max_test_parcels, daily_limit - used).
    blocker_reason set when allowed_n <= 0.
    """
    status = CANTON_STATUS[canton]
    want = int(status.get("max_test_parcels", 0))
    if want <= 0:
        return 0, status.get("blocker")

    daily = status.get("daily_limit")
    if daily is None:
        return want, None

    used = requests_today(canton)
    remaining = daily - used
    if remaining <= 0:
        return 0, f"daily quota used ({used}/{daily}) — wait until tomorrow"
    return min(want, remaining), None


def _run_canton_smoke(canton: str) -> dict:
    """
    Generalized TIER B smoke test for one canton.
      1. Seed N parcels around the canton's seed point.
      2. Run scanner.scan(limit=N) (uses existing per-canton logic).
      3. Inspect DB: count is_herrenlos=1 (false positives), errors.
    """
    status = CANTON_STATUS[canton]
    group  = status["test_group"]
    r = {"tier": "B", "canton": canton, "group": group,
         "label": f"{canton} smoke ({group})"}

    # Pre-check 1: do we even support this canton in tests?
    if status["access"] in ("cant_get", "blocked"):
        r.update({"pass": None, "reason": status["blocker"], "needs": status["needs"]})
        return r

    # Pre-check 2: own-login cantons (BE/VS) use Playwright interactive login.
    # The scanner opens a visible browser; user completes SwissID/AGOV (2FA) once,
    # and the token gets cached for subsequent runs. We cannot pre-check for "logged
    # in" cheaply — the scanner itself will either reuse a cached token (silent) or
    # open the browser (interactive). Both are fine: just let scan() run.
    # NOTE: env-var USERNAME/PASSWORD pre-checks are IMPOSSIBLE here because SwissID
    # and AGOV both require 2FA (SMS / app push), so no headless credential flow exists.

    # Pre-check 3: daily-limit quota
    allowed_n, quota_block = _quota_check(canton)
    if allowed_n <= 0:
        r.update({"pass": None, "reason": quota_block or status["blocker"],
                  "needs": status["needs"]})
        return r

    # Seed N parcels (if not already cached)
    n_cached = seed_canton_n(canton, allowed_n)
    if n_cached == 0:
        r.update({"pass": None, "reason": "could not seed any parcel (swisstopo returned nothing)",
                  "needs": "verify seed point / canton coverage in swisstopo"})
        return r

    n = min(allowed_n, n_cached)
    r["attempted"] = n

    # Run the canton scanner — uses its existing logic, captcha tracking included
    try:
        import importlib
        mod = importlib.import_module(SCANNER_IMPORTS[canton])
        result = mod.scan(limit=n, skip_existing=False)
    except Exception as exc:
        r.update({"pass": False, "reason": f"scanner exception: {exc}"})
        return r

    # Inspect the most recently scanned rows for this canton
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT is_herrenlos, error, owner FROM parcels
             WHERE canton=? ORDER BY scanned_at DESC LIMIT ?
        """, (canton, n)).fetchall()

    scanned = len(rows)
    fps     = sum(1 for x in rows if x["is_herrenlos"] == 1)
    errs    = sum(1 for x in rows if x["error"])

    r["scanned"] = scanned
    r["false_positives"] = fps
    r["errors"] = errs

    if fps > 0:
        r.update({"pass": False,
                  "reason": f"FALSE POSITIVES: {fps}/{scanned} parcels flagged herrenlos=1"})
    elif scanned == 0:
        r.update({"pass": None, "reason": "scanner produced no rows"})
    elif errs == scanned:
        # All errors — likely CAPTCHA pipeline failure (BL without API key, etc.)
        r.update({"pass": None,
                  "reason": f"all {scanned} attempts errored — likely solver / portal issue",
                  "needs": status.get("needs")})
    else:
        r.update({"pass": True,
                  "reason": f"{scanned} scanned, 0 false positives, {errs} retryable errors"})
    return r


# ── Output ───────────────────────────────────────────────────────────────────

def _print_canton_coverage() -> None:
    by_access = {a: [] for a in ("public", "free_key", "own_account",
                                  "cant_get", "blocked", "unbuilt")}
    for c, s in CANTON_STATUS.items():
        by_access[s["access"]].append(c)

    total = sum(len(v) for v in by_access.values())
    testable = sum(len(by_access[a]) for a in ("public", "free_key", "own_account"))

    print(f"Canton coverage (Switzerland has 26 cantons; "
          f"{total} catalogued; {testable} testable):")
    print(f"  Public (testable)      : {len(by_access['public']):>2}  {' '.join(sorted(by_access['public']))}")
    print(f"  Free key (testable)    : {len(by_access['free_key']):>2}  {' '.join(sorted(by_access['free_key']))}")
    print(f"  Own account (testable) : {len(by_access['own_account']):>2}  {' '.join(sorted(by_access['own_account']))}  (credentials/login in .env or via interactive prompt)")
    print(f"  Cant get (no path)     : {len(by_access['cant_get']):>2}  {' '.join(sorted(by_access['cant_get']))}")
    print(f"                                ↳ AR, AI = Terravis professional + mail-only for private persons")
    print(f"                                ↳ GL = my.gl.ch needs AGOV LoA-3 (only via manual proofing; federal e-ID postponed to Dec 2026)")
    print(f"                                ↳ NW = online form is request-by-purpose, not direct lookup")
    print(f"                                ↳ OW = Terravis professional-only; public access planned 2021 but not delivered")
    print(f"                                ↳ TI = SIFTI requires registry-issued auth (explicitly not for private persons)")
    print(f"                                ↳ VD = vd.ch is form-based with 48h email turnaround (not real-time scanner-viable)")
    print(f"  Blocked (SMS dead-end) : {len(by_access['blocked']):>2}  {' '.join(sorted(by_access['blocked']))}")
    print(f"                                ↳ All require SMS verification per query — operational dead-end (cannot be solved by IP rotation)")
    print(f"  Unbuilt (buildable!)   : {len(by_access['unbuilt']):>2}  {' '.join(sorted(by_access['unbuilt']))}")
    print(f"                                ↳ Real-time public paths verified to exist — just need scanner code + (likely) paid residential proxies for full scan")
    print()

    # ── Rate-limit / IP rotation table ───────────────────────────────────────
    # ip_rotation="deferred" = full canton scan needs paid residential proxies.
    # Testing at max_test_parcels is fine without rotation as long as quota holds.
    rotation_cantons = sorted(
        c for c, s in CANTON_STATUS.items()
        if s.get("ip_rotation") == "deferred"
        and s["access"] in ("public", "free_key", "own_account")
    )
    no_rotation = sorted(
        c for c, s in CANTON_STATUS.items()
        if s.get("ip_rotation") is None
        and s["access"] in ("public", "free_key", "own_account")
    )

    print("Rate limits & IP rotation:")
    print(f"  {'Canton':<6} {'Daily':>6} {'UsedToday':>10} {'Remaining':>10} {'TestCap':>7}  {'IPRotation':<10}  Rate-limit note")
    print("  " + "-" * 96)
    for c in rotation_cantons + no_rotation:
        s = CANTON_STATUS[c]
        daily = s.get("daily_limit")
        used  = requests_today(c) if daily else 0
        rem   = (daily - used) if daily is not None else None
        cap   = s.get("max_test_parcels", 0)
        rot   = s.get("ip_rotation") or "—"
        rate  = s.get("rate_limit") or "—"
        daily_s = str(daily) if daily is not None else "—"
        rem_s   = str(rem)   if rem   is not None else "—"
        used_s  = str(used)  if daily is not None else "—"
        print(f"  {c:<6} {daily_s:>6} {used_s:>10} {rem_s:>10} {cap:>7}  {rot:<10}  {rate}")
    print()
    print("  IPRotation='deferred' = paid residential proxies required for FULL canton scan")
    print("                          (testing at TestCap parcels works fine without rotation)")
    print()


def _ansi(code: str, txt: str) -> str:
    return f"\033[{code}m{txt}\033[0m"


def _print_results(results: list[dict]) -> int:
    """Pretty-print grouped by test_group; persist each row to test_runs."""
    failures = 0
    grouped: dict[str, list[dict]] = {}
    for r in results:
        grouped.setdefault(r.get("group", "rest"), []).append(r)

    print()
    for group in TEST_GROUP_ORDER:
        rs = grouped.get(group, [])
        if not rs:
            continue
        print(f"== {group} ==")
        for r in rs:
            passed = r.get("pass")
            if passed is True:
                status_str, status = _ansi("32", "PASS"), "pass"
            elif passed is False:
                status_str, status = _ansi("31", "FAIL"), "fail"
                failures += 1
            else:
                status_str, status = _ansi("33", "SKIP"), "skip"
            tier   = r.get("tier", "?")
            canton = r.get("canton", "?")
            label  = r.get("label", "?")
            print(f"  [{status_str}] [{tier}/{canton}] {label}")
            print(f"         {r.get('reason','')}")
            if r.get("needs"):
                print(f"         needs: {r['needs']}")

            # Persist to test_runs
            store_test_run(
                canton=canton, tier=tier, status=status,
                test_group=group,
                parcels_attempted=int(r.get("attempted", 0)),
                parcels_scanned=int(r.get("scanned", 0)),
                false_positives=int(r.get("false_positives", 0)),
                errors=int(r.get("errors", 0)),
                blocker=r.get("reason") if status != "pass" else None,
                needs=r.get("needs"),
                notes=r.get("label"),
            )
        print()

    if failures:
        print(_ansi("31", f"{failures} test(s) FAILED"))
    else:
        print(_ansi("32", "All tests passed (or skipped)"))
    print()
    return failures


# ── Entry point ──────────────────────────────────────────────────────────────

def run_tests(tier: str = "a", cantons: list[str] | None = None) -> int:
    """
    Returns number of FAIL outcomes (0 = clean).
    SKIP outcomes do NOT count as failures — they indicate a blocker, not a bug.
    """
    init_db()
    _print_canton_coverage()
    tier = tier.lower()
    cantons_uc = [c.upper() for c in cantons] if cantons else None

    results: list[dict] = []

    # ── TIER A ──
    if cantons_uc is None or "GE" in cantons_uc:
        log.info("TIER A — GE SITG validation …")
        results.extend(_run_tier_a_ge())
    if cantons_uc is None or "BS" in cantons_uc:
        log.info("TIER A — BS REST validation …")
        results.extend(_run_tier_a_bs())

    # ── TIER B ──
    if tier == "b":
        # Default selection: all testable cantons, ordered by group
        if cantons_uc is None:
            tier_b_cantons = [c for c in TESTABLE_CANTONS if c in SCANNER_IMPORTS]
        else:
            tier_b_cantons = [c for c in cantons_uc if c in SCANNER_IMPORTS]

        # Sort by test_group (TEST_GROUP_ORDER), then alphabetically
        tier_b_cantons.sort(key=lambda c: (
            TEST_GROUP_ORDER.index(CANTON_STATUS[c]["test_group"]),
            c,
        ))

        for c in tier_b_cantons:
            log.info("TIER B — %s smoke …", c)
            results.append(_run_canton_smoke(c))

    return _print_results(results)


def main():
    parser = argparse.ArgumentParser(description="Herrenlos scanner test runner")
    parser.add_argument("cantons", nargs="*",
                        help="Cantons to test (default: all). E.g.: ge bl bs")
    parser.add_argument("--tier", choices=["a", "b"], default="a",
                        help="a = fast REST-only (default); b = also slow portal tests")
    parser.add_argument("--seed", action="store_true",
                        help="Seed parcel_enum with fixture parcels, then exit")
    args = parser.parse_args()
    cantons = [c.lower() for c in args.cantons] if args.cantons else None

    if args.seed:
        init_db()
        targets = [c.upper() for c in (cantons or CANTON_SEED_POINTS.keys())]
        for c in targets:
            if c in CANTON_STATUS:
                n = CANTON_STATUS[c].get("max_test_parcels", 1)
                seed_canton_n(c, max(1, n))
        return

    sys.exit(run_tests(tier=args.tier, cantons=cantons))


# backwards-compat alias
def ensure_fixture(canton: str) -> dict | None:
    return seed_canton(canton)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(name)-4s  %(levelname)-7s  %(message)s",
        datefmt="%H:%M:%S",
    )
    main()
