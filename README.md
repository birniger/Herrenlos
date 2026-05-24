# Herrenlos — Switzerland's ownerless parcels

A scanner + live dashboard finding parcels with no Grundbuch entry across the
26 Swiss cantons.

## 🗺 Live map + dashboard

**👉 <https://birniger.github.io/Herrenlos/docs/> 👈**

Updates automatically after every scan run. Shows per-canton progress,
discovered `herrenlos` parcels on a Leaflet + swisstopo map, with filters
by canton and type.

---

## What this does

Detects Swiss parcels with no `Grundbuch` (land-register) entry — which under
[ZGB Art. 658](https://www.fedlex.admin.ch/eli/cc/24/233_245_233/en) means
they may be claimable by private persons (depending on canton).

The scanner queries each canton's public Grundbuch portal in turn, captures
the owner field (or the lack thereof), and writes results into a SQLite DB
that this repo carries with it.

## Status (Switzerland's 26 cantons, May 2026)

| Category | Cantons | Where it runs |
|----------|---------|---------------|
| ☁️ CI (GitHub Actions, no auth) | JU, SZ | Auto-scheduled every 6h — OCR CAPTCHA, no login |
| ☁️ CI (GitHub Actions, datacenter proxies) | SH, NE, GR | Auto-scheduled — 10 proxies via `WEBSHARE_PROXY_LIST`: SH 900/day, NE 450/day, GR 90/day |
| 💻 Laptop only — AGOV account required | BE | `./scripts/scan-loop.sh`; Safari AppleScript login; per-account quota |
| 💻 Laptop only — SwissID account required | VS | `./scripts/scan-loop.sh`; Playwright Chromium window + SwissID 2FA; ~unlimited on scan endpoints |
| 💻 Laptop only — geo-blocked from datacenter IPs | FR, UR | Works from any Swiss residential IP; run locally |
| 💻 Laptop only — Claude vision CAPTCHA | BL | `./scripts/scan-loop.sh`; needs `ANTHROPIC_API_KEY`; no IP limit |
| 💰 Needs paid residential proxies | GE (+ API key), SO, BS-public | Imperva / reCAPTCHA score |
| 🛠 Buildable but not wired | AG, SG | Scanner exists / endpoint captured; needs account or CAPTCHA solver |
| ❌ Operationally blocked | AI, AR, GL, LU, NW, OW, TG, TI, VD, ZG, ZH | SMS-per-query, mail-only, or professional-only |

Detailed reasoning per canton lives in `test_fixtures.py:CANTON_STATUS`.

**Rate limit types (important distinction):**
- **Per-IP limit** (SH, NE, GR, UR): solvable with proxy rotation or VPN
- **Per-account limit — confirmed (BE)**: 429s hit in production; empirically verified per-account (fresh browser session + new token still returned 429 → limit is on the AGOV account, not the IP). No proxy workaround. Limit appears to be on owner-name resolution specifically (`GET /api/gb/person/master`), not parcel lookups. Run conservatively.
- **VS — SwissID, scan endpoints appear unlimited**: VS uses SwissID (not AGOV — different provider from BE). The main scan endpoints (grundstueck + eigentum JSON) have no observed rate limit. The ICP-extract endpoint is 10/day but the scanner deliberately avoids it. IP rotation is irrelevant: the login requires SwissID 2FA so a session is always bound to a personal account; there is simply no per-query quota to route around.
- Token lifecycle (BE + VS): access_token ~5min, refresh_token ~30min rotating — session stays alive while scanner runs continuously; re-auth needed after any gap >~30min.
- **No limit / CAPTCHA only** (JU, SZ, BL, FR): throughput limited only by CAPTCHA solve time or IP geo-restriction
- **Proxies required from request #1** (GE, SO): Imperva / reCAPTCHA v3 score blocks datacenter IPs immediately

## How the data flow works

```
┌──────────────────┐    ┌────────────────┐    ┌──────────────────┐    ┌──────────────┐
│ GitHub Actions   │───▶│  herrenlos.db  │───▶│ export_for_web.py│───▶│  Leaflet map │
│ (cron every 6h)  │    │  (SQLite, in   │    │  → progress.json │    │  + dashboard │
│ JU,SZ,SH,NE,GR   │    │   the repo)    │    │  → herrenlos.json│    │  on Pages    │
│ + local BE,VS,FR │    │                │    │  → *.geojson/csv │    │              │
└──────────────────┘    └────────────────┘    └──────────────────┘    └──────────────┘
```

Markers on the map are colored by herrenlos type:
- **Red** = `dereliktion` (Art. 964 ZGB — owner deleted from Grundbuch; potentially claimable)
- **Orange** = `not_in_grundbuch` (Art. 664 ZGB — never registered; auto-cantonal, not claimable)

## Data exports

The dashboard fetches these JSON files from `docs/data/`, all auto-regenerated
on every scan commit:

| File | Format | Use case |
|------|--------|----------|
| `progress.json` | JSON | per-canton progress (dashboard sidebar) |
| `herrenlos.json` | JSON | every flagged parcel with WGS84 coords (dashboard map) |
| `herrenlos.geojson` | GeoJSON | drop into QGIS / Mapbox / any GIS tool |
| `herrenlos.csv` | CSV | open in Excel / Numbers / pandas |
| `coords_cache.json` | JSON | swisstopo geocode cache (persistent, prevents re-lookup) |

## Running scans

**Cloud (zero effort):** GitHub Actions cron runs `JU / SZ / SH / NE / GR` every 6h.
Picks the canton with the largest scan gap. Commits DB + JSON back to the repo.
See [`docs/SETUP.md`](docs/SETUP.md) for setup.

**Local — single canton (any of the laptop-runnable ones):**
```bash
python main.py be                      # BE: AGOV account, per-account quota
python main.py vs                      # VS: SwissID account, scan endpoints unlimited
python main.py fr                      # FR: no login, Swiss residential IP required
python main.py ur                      # UR: Swiss residential IP, ~10 req/day quota
python main.py test --tier b           # smoke tests
python main.py ready                   # live per-canton status
python scripts/export_for_web.py       # regenerate dashboard JSON
open docs/index.html                    # preview dashboard locally
```

**Local — unattended bulk loop (BE + VS + FR + BL):**
```bash
./scripts/scan-loop.sh                 # launchd-managed; auto-restarts on crash/reboot
# or, without the watchdog wrapper:
python scripts/run_local.py            # runs preflight, then loops canton→canton
```

`run_local.py` targets cantons that need a Swiss residential IP or interactive login
(BE, VS, FR, BL). It deliberately **excludes** JU/SZ/SH/NE/GR (handled by GitHub
Actions) and UR (10/day quota; too slow for the bulk loop).

At startup it checks for missing tokens / API keys and offers to launch the
relevant interactive setup. If a scan exits looking like an auth failure mid-loop,
a macOS desktop notification fires so you know to re-authenticate.

## Operational caveats

- Herrenlos parcels are genuinely rare (~0.01% nationwide). The CI-scannable
  cantons (JU, SZ, SH, NE, GR) cover ~175 000 parcels; expect maybe 0–5 actual herrenlos.
- BL: handwritten CAPTCHA defeats local OCR; needs `ANTHROPIC_API_KEY`.
- GE: Imperva blocks after ~30 req/IP — needs `GE_PROXY_LIST` + `ANTHROPIC_API_KEY`.
- SO: empirically fails reCAPTCHA v3 after ~2 queries even from Swiss residential IPs
  (96%+ failure rate observed overnight). Needs residential proxy rotation.
- BE: one-time AGOV login via Safari AppleScript (macOS only); per-account quota on
  owner-name resolution endpoint — run conservatively.
- VS: one-time SwissID 2FA login via Playwright Chromium window; scan endpoints
  appear unlimited once authenticated.
- LU, TG, ZG, ZH: portals require SMS verification per query — operational dead-end.

## Repo layout

```
├── main.py                       CLI entry: scan, test, ready, captcha, stats
├── db.py                         SQLite + helpers (parcels, parcel_enum, captcha_stats, test_runs)
├── test_fixtures.py              CANTON_STATUS classification + test framework
├── scanners/                     One module per canton (26 total)
│   ├── utils.py                    canonical scanner interface contract
│   ├── geoportal_base.py           shared geoportal.ch professional-API client
│   └── <canton>.py                 per-canton scanner (REST, CAPTCHA, OIDC, etc.)
├── scripts/
│   ├── pick_canton.py              GitHub Actions: choose canton with biggest gap
│   └── export_for_web.py           DB → JSON/GeoJSON/CSV for the dashboard
├── docs/                         GitHub Pages root
│   ├── index.html                  dashboard + map (single page)
│   ├── data/                       generated JSON / GeoJSON / CSV
│   └── SETUP.md                    GitHub setup walkthrough
├── .github/workflows/scan.yml    cron + manual trigger
└── herrenlos.db                  the database (force-added past *.db gitignore)
```

## GitHub repo metadata (suggested values to paste in Settings)

Empty by default; quick to fill in at <https://github.com/birniger/Herrenlos/settings>:

- **Description**: `Scanner + live map for parcels with no Grundbuch entry across all 26 Swiss cantons (ZGB Art. 658 herrenlos)`
- **Website**: `https://birniger.github.io/Herrenlos/docs/`
- **Topics**: `switzerland`, `grundbuch`, `cadastre`, `swiss-cantons`, `data-scraping`, `leaflet`, `swisstopo`, `legal-research`, `open-data`

## Licence

[MIT](LICENSE) — do whatever you like.

## Legal basis

- **ZGB Art. 658** — Aneignung of herrenlos parcels (subject to cantonal law)
- **ZGB Art. 664** — unregistered land → cantonal Hoheit; not privately claimable
- **ZGB Art. 666** — substantive rule: ownership lost by Dereliktion
- **ZGB Art. 964** — procedural: Verzichtserklärung filed with Grundbuchamt; owner deleted

Validation reference cases:
- Aire-la-Ville (GE), parcel 722 — *Le Temps*, 1999
- Schwyz canton — 26 parcels, *SZ Amtsblatt Nr. 12*, March 2025
