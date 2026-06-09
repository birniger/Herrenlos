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
    # VERIFICATION PASS 1 — 2026-06-09 (independent agent, browser/HTTP probing only,
    # no code consulted). Initial corrections:
    #   AR/AI : Upgraded to "unbuilt" — appeared to show public owner on map click.
    #   GL    : Upgraded to "unbuilt" — public GeoViewer "Grundstücksinformation" exists.
    #   VD    : Corrected to real-time SMS portal (intercapi-public.vd.ch), not 48h form.
    #   NW/OW/TI : Made more specific (subscription costs, no free tier).
    # VERIFICATION PASS 2 — 2026-06-09 (live WMS/WFS HTTP probe, independent agent):
    #   AR    : DOWNGRADED back to cant_get — WMS public but returns geometry/EGRID only,
    #           NO owner name. geoportal.ch/search/ownerinfo/ = reCAPTCHA Enterprise v2.
    #   AI    : Same as AR — DOWNGRADED back to cant_get.
    #   GL    : DOWNGRADED to cant_get — wfs.geo.gl.ch WFS IS public and returns owner
    #           data with full name/address, BUT only for ~15% of parcels (public entities:
    #           canton, municipalities, Bund, utilities). Private parcels (~85%) not exposed.
    #           Public-entity parcels have institutional owners → not herrenlos by definition.
    #           Cannot reliably detect herrenlos from public WFS alone.
    # CONFIRMED BLOCKED (all passes):
    #   ZH, ZG, TG, LU — SMS gate enforced in JS (Swiss mobile regex confirmed in source)
    # UNBUILT (scanner possible, just not built yet):
    #   SG     : reCAPTCHA Enterprise v2 checkbox → needs 2captcha (~$345)
    #   AG     : smartserviceportal account → email-only registration, 10 queries/user

    # AR: CONFIRMED BLOCKED 2026-06-09 (live WMS probe, independent agent, no code consulted).
    # geoportal.ch/ktar WMS GetFeatureInfo IS publicly accessible without login
    # (Referer: https://www.geoportal.ch/ktar/map/40 + ?primaryArea=ktar param).
    # BUT the response contains only parcel geometry — Grundstücksnummer, E-GRID,
    # Art, Fläche (m²) — NO owner name, NO address. Live response example:
    #   {"Grundstücksnummer":"1758","E-GRID":"CH667752217223","Art":"Liegenschaft",
    #    "Fläche (m²)":"4487"}
    # The Grundbuch register (owner names) is NOT exposed by any public API endpoint.
    # geoportal.ch/search/ownerinfo/ returns {"challenge":true} for AR
    # — same reCAPTCHA Enterprise v2 gate as SG. No free automatable path.
    # Previous "unbuilt/owner confirmed" classification was wrong (based on UI
    # appearing to show data, which was state-owned parcel labels only).
    "AR": {"access": "cant_get", "test_group": "blocked", "ip_rotation": None,
           "daily_limit": None, "rate_limit": None, "max_test_parcels": 0,
           "blocker": "geoportal.ch/ktar WMS confirmed public (live probe 2026-06-09) but "
                      "returns geometry/EGRID only — no owner name in any public API. "
                      "geoportal.ch/search/ownerinfo/ returns {\"challenge\":true} for AR "
                      "(reCAPTCHA Enterprise v2 gate, same as SG). No free automatable path.",
           "needs": "same reCAPTCHA Enterprise v2 gate as SG — ~$345 in CAPTCHA solver "
                    "costs for full scan; not viable without paid solver"},
    # AI: CONFIRMED BLOCKED 2026-06-09 — same platform and same result as AR.
    # geoportal.ch/ktai WMS GetFeatureInfo works unauthenticated but returns only
    # parcel geometry (no owner). Live response example:
    #   {"Grundstücksnummer":"541","E-GRID":"CH589559417757",
    #    "Art":"Liegenschaft","Fläche (m²)":"240829"}
    # geoportal.ch/search/ownerinfo/ is also gated behind reCAPTCHA Enterprise v2.
    # Additionally, Terravis implementation in AI is partial (Gonten/Schlatt-Haslen/
    # Oberegg since 2019; Appenzell/Schwende/Rüte still pending 2026) — even if the
    # CAPTCHA gate were solved, coverage would be incomplete.
    "AI": {"access": "cant_get", "test_group": "blocked", "ip_rotation": None,
           "daily_limit": None, "rate_limit": None, "max_test_parcels": 0,
           "blocker": "geoportal.ch/ktai WMS confirmed public (live probe 2026-06-09) but "
                      "returns geometry/EGRID only — no owner name. Same reCAPTCHA Enterprise "
                      "v2 gate as AR/SG at geoportal.ch/search/ownerinfo/. Partial Terravis "
                      "rollout adds incomplete coverage even if CAPTCHA solved.",
           "needs": "same reCAPTCHA Enterprise v2 gate as SG/AR — ~$345 solver costs; "
                    "partial Terravis coverage further reduces utility"},
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
    # GL: CONFIRMED PARTIAL — live WFS probe 2026-06-09 (independent agent, no code consulted).
    # wfs.geo.gl.ch WFS is fully public, no auth, no Cloudflare:
    #   eigentum-kanton       — 270 parcels, owner = "Kanton Glarus" (+ address, EGRID)
    #   eigentum-gemeinden    — ~2,983 parcels, owner = municipality names
    #   eigentum-bund         — 176 parcels, owner = federal bodies
    #   eigentum-technischebetriebe — 233 parcels, utilities
    #   av_liegenschaften     — all ~24,739 parcels (geometry/EGRID, no owner)
    # Live response example (eigentum-kanton):
    #   {"aname":"Kanton Glarus","adresse":"Gemeindehausplatz 5",
    #    "plz_ortschaft":"8750 Glarus","egrid":"CH232278693789","nummer":"2264"}
    #
    # LIMITATION: Only ~3,662 public-entity parcels (~15%) have owner data.
    # Private parcels (~21,000, 85%) have NO owner data in any public endpoint.
    # Public-entity parcels (canton/municipality/Bund) are definitionally NOT
    # herrenlos — they have an institutional owner by definition.
    # A "not in any eigentum layer" check cannot reliably detect herrenlos because
    # the absent parcels are overwhelmingly private (owned), not ownerless.
    # Conclusion: the WFS is buildable but CANNOT meaningfully detect herrenlos.
    # my.gl.ch AGOV LoA-3 still correct for formal Grundbuchauszug ordering.
    "GL": {"access": "cant_get", "test_group": "blocked", "ip_rotation": None,
           "daily_limit": None, "rate_limit": None, "max_test_parcels": 0,
           "blocker": "wfs.geo.gl.ch WFS confirmed public (live probe 2026-06-09). "
                      "Owner data only for ~3,662 public-entity parcels (15%): canton, "
                      "municipalities, Bund, utilities — all have institutional owners "
                      "(definitionally not herrenlos). Private parcels (~85%) not in "
                      "any public endpoint. Cannot reliably detect herrenlos.",
           "needs": "no viable herrenlos detection path without Grundbuch access; "
                    "my.gl.ch AGOV LoA-3 required for full Grundbuchauszug"},
    # NW: RE-CONFIRMED 2026-06-09 (independent probe) — more specific finding:
    # The gis-daten.ch WebGIS has a NW/OW public GeoShop (credentials nwow-public/public)
    # but owner query requires WebGIS PRO subscription (CHF 300/yr NW). The public
    # GeoShop tier only shows parcel geometry; mapplus.ch legend explicitly marks NW
    # as having NO owner query available ("nur ÖREB: Direktlink").
    # nw.ch online-schalter offers purpose-bound extract ordering (building permit,
    # bank credit) — not an arbitrary parcel lookup.
    "NW": {"access": "cant_get", "test_group": "blocked", "ip_rotation": None,
           "daily_limit": None, "rate_limit": None, "max_test_parcels": 0,
           "blocker": "no free public owner query: gis-daten.ch WebGIS PRO costs CHF 300/yr (NW); public GeoShop tier shows geometry only; mapplus.ch: 'nur ÖREB: Direktlink' for NW",
           "needs": "no automatable public-path workaround; paid CHF 300/yr subscription not viable for automated scanning"},
    # OW: RE-CONFIRMED 2026-06-09 — same infrastructure as NW (gis-daten.ch WebGIS),
    # WebGIS PRO costs CHF 600/yr for OW. Terravis professional-only. mapplus.ch
    # legend marks OW as no owner query available.
    "OW": {"access": "cant_get", "test_group": "blocked", "ip_rotation": None,
           "daily_limit": None, "rate_limit": None, "max_test_parcels": 0,
           "blocker": "no free public owner query: gis-daten.ch WebGIS PRO costs CHF 600/yr (OW); Terravis professional-only; mapplus.ch: no owner query available for OW",
           "needs": "no automatable public-path workaround; CHF 600/yr subscription not viable"},
    # TI: RE-CONFIRMED 2026-06-09 (independent probe) — more specific finding:
    # geoticino.ch (commercial service, geoticino SA) charges CHF 15+VAT per extract
    # for unregistered users, or CHF 400+/yr subscription. No free tier exists.
    # mapplus.ch legend explicitly states "Eigentümer: nicht verfügbar" for TI.
    # SIFTI-web (SIFTI professional system) still requires registry-issued auth.
    "TI": {"access": "cant_get", "test_group": "blocked", "ip_rotation": None,
           "daily_limit": None, "rate_limit": None, "max_test_parcels": 0,
           "blocker": "geoticino.ch charges CHF 15/extract (no free tier); SIFTI-web is professional-only; mapplus.ch: 'Eigentümer: nicht verfügbar' for TI",
           "needs": "no automatable free path; CHF 15/parcel × ~200k parcels = CHF 3M — not viable"},
    # VD: CORRECTED 2026-06-09 — previous "48h form-mail" assessment was wrong.
    # intercapi-public.vd.ch is a REAL-TIME Keycloak-backed angular portal with SMS
    # authentication. 5 queries/day ("maximum de 5 consultations par jour"). Phone
    # type requirement: "numéro de téléphone mobile" — likely Swiss-only (Keycloak
    # realm 'capitastra' with Swiss-only hint found in JS). Same SMS gate as ZH/ZG.
    # The prestations.vd.ch form is a separate, older path for formal extracts.
    "VD": {"access": "blocked", "test_group": "blocked", "ip_rotation": None,
           "daily_limit": 5, "rate_limit": "5 queries/day per mobile number (SMS auth)",
           "max_test_parcels": 0,
           "blocker": "intercapi-public.vd.ch requires SMS authentication per session (mobile number, likely Swiss-only); 5 queries/day — same operational dead-end as ZH/ZG/TG/LU",
           "needs": "no workaround under our policy (SMS gate, Swiss phone likely required)"},

    # ── Explicitly blocked (SMS gate — confirmed in source code / official docs) ─
    # ZG: CONFIRMED 2026-06-09 — zugmap.ch click → Swiss mobile → SMS code (5-day
    # validity). 30 queries/24h per mobile number. No Swiss-phone = postal contact only.
    "ZG": {"access": "blocked", "test_group": "blocked", "ip_rotation": None,
           "daily_limit": 30, "rate_limit": "30 queries/24h per Swiss mobile number",
           "max_test_parcels": 0,
           "blocker": "zugmap.ch requires Swiss mobile number + SMS code per session",
           "needs": "no known workaround for private persons (Swiss mobile required)"},
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
    # ZH: CONFIRMED 2026-06-09 (independent probe) — maps.zh.ch → Swiss mobile →
    # SMS TAN valid 7 days; 5 queries/day/mobile. Terms: "Schweizer Mobiltelefonnummer".
    # Property owners can opt out (end-2024). ~450k parcels.
    "ZH": {"access": "blocked", "test_group": "blocked", "ip_rotation": None,
           "daily_limit": 5, "rate_limit": "5 queries/day per Swiss mobile number (7-day TAN)",
           "max_test_parcels": 0,
           "blocker": "maps.zh.ch requires Swiss mobile number + SMS TAN; terms explicitly state 'Schweizer Mobiltelefonnummer'; ~450k parcels",
           "needs": "no known workaround for private persons (Swiss mobile required by ordinance)"},
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
    print(f"                                ↳ AR, AI = geoportal.ch WMS public but returns geometry only (no owner); geoportal.ch/search/ownerinfo/ gated behind reCAPTCHA Enterprise v2")
    print(f"                                ↳ GL = wfs.geo.gl.ch public but only ~15% public-entity parcels have owner (canton/municipality/Bund); private owners not accessible; cannot detect herrenlos")
    print(f"                                ↳ NW = gis-daten.ch WebGIS PRO CHF 300/yr; public GeoShop shows geometry only")
    print(f"                                ↳ OW = gis-daten.ch WebGIS PRO CHF 600/yr; Terravis professional-only")
    print(f"                                ↳ TI = geoticino.ch CHF 15/extract (no free tier); SIFTI professional-only")
    print(f"                                ↳ VD = intercapi-public.vd.ch real-time SMS portal, 5/day (same dead-end as ZH/ZG)")
    print(f"  Blocked (SMS dead-end) : {len(by_access['blocked']):>2}  {' '.join(sorted(by_access['blocked']))}")
    print(f"                                ↳ All require SMS verification per query — operational dead-end (cannot be solved by IP rotation)")
    print(f"  Unbuilt (buildable!)   : {len(by_access['unbuilt']):>2}  {' '.join(sorted(by_access['unbuilt']))}")
    print(f"                                ↳ SG = reCAPTCHA Enterprise v2 checkbox per parcel (~$345 solver costs for full 115k-parcel scan)")
    print(f"                                ↳ AG = free smartserviceportal account (email-only registration) + 10 queries/user; needs BE-style OIDC scanner")
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
