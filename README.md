# Herrenlos Scanner — Swiss ownerless-parcel discovery

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

| Category | Count | Cantons |
|----------|------:|---------|
| ✅ Fully working scanners | 12 | UR, FR, GE, GR, JU, NE, SH, SZ, BL, BS, BE, VS |
| 🟢 Buildable but not wired | 3 | AG, SG, SO (`scanners/so_public.py` wired but blocked by Google reCAPTCHA score on datacenter IPs) |
| 💰 Need paid residential proxies | (overlap) | GE, SO, GR, SH, NE for full-scale scans |
| 💰 Need ANTHROPIC_API_KEY | (overlap) | BL (handwritten CAPTCHA), GE (image CAPTCHA at scale) |
| ❌ Operationally blocked | 11 | AI, AR, GL, LU, NW, OW, TG, TI, VD, ZG, ZH (SMS-per-query, mail-only, or professional-only) |

Detailed reasoning per canton lives in `test_fixtures.py:CANTON_STATUS`.

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

**Cloud (zero effort):** GitHub Actions cron runs `BS / UR / JU / SZ / FR` every 6h.
Picks the canton with the largest scan gap. Commits DB + JSON back to the repo.
See [`docs/SETUP.md`](docs/SETUP.md) for setup.

**Local:**
```bash
python main.py ur                      # scan one canton
python main.py test --tier b           # run smoke tests
python main.py ready                   # see what's working + what needs setup
python scripts/export_for_web.py       # regenerate dashboard JSON
open docs/index.html                    # preview dashboard locally
```

## Operational caveats

- Herrenlos parcels are genuinely rare (~0.01% nationwide). The cloud-scannable
  cantons cover ~140 000 parcels; expect maybe 0–5 actual herrenlos in that subset.
- BL: handwritten CAPTCHA defeats local OCR; needs `ANTHROPIC_API_KEY`.
- GE, SO: pass-rate for the underlying CAPTCHA is IP-reputation-bound;
  residential proxies needed for sustained scanning.
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

## Legal basis

- **ZGB Art. 658** — Aneignung of herrenlos parcels (subject to cantonal law)
- **ZGB Art. 664** — unregistered land → cantonal Hoheit; not privately claimable
- **ZGB Art. 666** — substantive rule: ownership lost by Dereliktion
- **ZGB Art. 964** — procedural: Verzichtserklärung filed with Grundbuchamt; owner deleted

Validation reference cases:
- Aire-la-Ville (GE), parcel 722 — *Le Temps*, 1999
- Schwyz canton — 26 parcels, *SZ Amtsblatt Nr. 12*, March 2025
