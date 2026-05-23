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
| ☁️ CI (GitHub Actions, datacenter proxies) | SH | Auto-scheduled — 10 proxies × 90 q/day = 900/day via `WEBSHARE_PROXY_LIST` secret |
| 💻 Laptop only — personal account required | BE, VS | `./scripts/scan-loop.sh`; token expires ~30min after last query → manual re-auth |
| 💻 Laptop only — geo-blocked from datacenter IPs | FR, UR | Works from any Swiss residential IP; run locally |
| 💻 Laptop with proxies (quota rotation) | NE, GR | `python main.py <canton>` with `NE_PROXY_LIST` / `GR_PROXY_LIST` in `.env` |
| 💻 Laptop only — Claude vision CAPTCHA | BL | `./scripts/scan-loop.sh`; needs `ANTHROPIC_API_KEY`; no IP limit |
| 💰 Needs paid residential proxies | GE (+ API key), SO, BS-public | Imperva / reCAPTCHA score |
| 🛠 Buildable but not wired | AG, SG | Scanner exists / endpoint captured; needs account or CAPTCHA solver |
| ❌ Operationally blocked | AI, AR, GL, LU, NW, OW, TG, TI, VD, ZG, ZH | SMS-per-query, mail-only, or professional-only |

Detailed reasoning per canton lives in `test_fixtures.py:CANTON_STATUS`.

**Rate limit types (important distinction):**
- **Per-IP limit** (SH, NE, GR, UR): solvable with proxy rotation or VPN
- **Per-account limit** (BE, VS): NOT solvable with proxies — the constraint is your personal AGOV / SwissID identity. Suspension = loss of portal access entirely. Run at conservative delays (≥1.0s BE, ≥1.5s VS). Token lifecycle: access_token ~5min, refresh_token ~30min rotating — session stays alive while scanner runs; re-auth needed after any gap >~30min.
- **No limit / CAPTCHA only** (JU, SZ, BL, FR): throughput limited only by CAPTCHA solve time or IP geo-restriction
- **Proxies required from request #1** (GE, SO): Imperva / reCAPTCHA v3 score blocks datacenter IPs immediately

## How the data flow works

```
┌──────────────────┐    ┌────────────────┐    ┌──────────────────┐    ┌──────────────┐
│ GitHub Actions   │───▶│  herrenlos.db  │───▶│ export_for_web.py│───▶│  Leaflet map │
│ (cron every 6h)  │    │  (SQLite, in   │    │  → progress.json │    │  + dashboard │
│   scans BS,UR,JU,│    │   the repo)    │    │  → herrenlos.json│    │  on Pages    │
│   SZ,FR on rotn  │    │                │    │  → *.geojson/csv │    │              │
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

**Cloud (zero effort):** GitHub Actions cron runs `FR / JU / SZ` every 6h.
Picks the canton with the largest scan gap. Commits DB + JSON back to the repo.
See [`docs/SETUP.md`](docs/SETUP.md) for setup.

**Local — single canton (any of the laptop-runnable ones):**
```bash
python main.py so                      # bulk: SO, BE, VS, BL all work end-to-end
python main.py ur                      # slow background: UR, SH, NE, GR (quota-limited)
python main.py test --tier b           # smoke tests
python main.py ready                   # live per-canton status
python scripts/export_for_web.py       # regenerate dashboard JSON
open docs/index.html                    # preview dashboard locally
```

**Local — unattended bulk loop (SO + BE + VS + BL):**
```bash
./scripts/scan-loop.sh                 # restart-on-crash wrapper around run_local.py
# or, without the auto-restart wrapper:
python scripts/run_local.py            # runs preflight, then loops canton→canton
```

`run_local.py` only targets the cantons that complete on one Swiss residential
IP without rotation (SO, BE, VS, BL). It deliberately **excludes** FR/JU/SZ
(handled by GitHub Actions) and UR/SH/NE/GR (daily quotas make bulk infeasible).

At startup it checks for missing tokens / API keys and offers to launch the
relevant interactive setup. If a scan exits looking like an auth failure mid-loop,
a macOS desktop notification fires so you know to re-authenticate.

## Operational caveats

- Herrenlos parcels are genuinely rare (~0.01% nationwide). The CI-scannable
  cantons (FR, JU, SZ) cover ~111 000 parcels; expect maybe 0–5 actual herrenlos.
- BL: handwritten CAPTCHA defeats local OCR; needs `ANTHROPIC_API_KEY`.
- GE: Imperva blocks after ~30 req/IP — needs `GE_PROXY_LIST` + `ANTHROPIC_API_KEY`.
- SO: works from any Swiss residential IP; datacenter IPs (GitHub Actions) fail Google reCAPTCHA score check.
- BE, VS: one-time interactive login; macOS only (Safari AppleScript for BE,
  Playwright Chromium window for VS SwissID 2FA).
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
