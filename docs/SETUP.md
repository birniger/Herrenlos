# Setup — running scans on GitHub Actions + serving the dashboard on GitHub Pages

This kit gives you:
- **Cloud scanners** that run every 6 hours on GitHub Actions and commit results back to the repo
- **A static dashboard + Leaflet map** served from GitHub Pages, automatically refreshed after each scan

You don't need to keep your laptop on. Public repos get unlimited free Actions
minutes; private repos get 2000 min / month.

The cloud workflow handles cantons that work from datacenter IPs:
**BS, UR, JU, SZ, FR**. The other free-tier cantons (BE, VS) need
interactive logins and stay on your laptop for now. GE, SO, GR, SH, NE need
paid residential proxies — defer those.

---

## One-time setup (~5 minutes)

### 1. Push the repo to GitHub

```bash
git remote add origin git@github.com:<you>/herrenlos-scanner.git
git push -u origin main
```

The `.github/workflows/scan.yml`, `scripts/export_for_web.py`, and `docs/`
are committed, so GitHub picks them up immediately.

### 2. Enable GitHub Pages

GitHub → your repo → **Settings → Pages** →
- **Source**: Deploy from a branch
- **Branch**: `main` / `/docs`
- Save.

Within a minute your dashboard is live at
`https://<you>.github.io/<repo>/`.

### 3. (Optional) Add the BS API key

The BS scanner needs a free key from <https://api.geo.bs.ch/> — sign up,
copy your key. Then in GitHub:

**Settings → Secrets and variables → Actions → New repository secret**
- Name: `BS_API_KEY`
- Value: your key

Without this, the workflow skips BS automatically and just scans UR / JU / SZ / FR.

### 4. (Optional) Trigger the first scan immediately

The workflow runs every 6 hours, but you can kick it off now:

**Actions → "scan" workflow → Run workflow**
(leave the canton input empty to let it auto-pick).

---

## How it works

Each run:

1. Checks out the current repo (which contains the latest `herrenlos.db`).
2. Picks the canton with the largest enumeration-vs-scanned gap.
3. Runs `python main.py <canton> --limit X` for up to 5h45m.
4. Re-exports `docs/data/*.json` from the DB.
5. Commits the updated DB + JSON back to `main`.
6. GitHub Pages auto-redeploys the dashboard.

You'll see a new commit on `main` every ~6 hours during the scan campaign,
with a message like `scan: ur (auto)`.

## Watching it work

- **Action runs**: `https://github.com/<you>/<repo>/actions`
- **Dashboard**:   `https://<you>.github.io/<repo>/`
- **Raw data**:    `https://github.com/<you>/<repo>/blob/main/herrenlos.db`

The dashboard auto-refreshes the JSON on every page load (cache-busted with
a timestamp param). No manual refresh needed.

---

## Local development (still works the same)

```bash
python main.py <canton>              # scan locally
python scripts/export_for_web.py     # regenerate dashboard JSON
open docs/index.html                  # preview the dashboard
```

The dashboard works as a static file with no server needed — opening
`docs/index.html` directly in a browser shows the map.

---

## Production-realistic time estimates (cloud)

| Canton | Parcels | Compute time | Runs needed at 5h each |
|--------|---------:|-------------:|-----------------------:|
| BS     |  7,000   |  2h          | 1 |
| UR     | 20,000   |  5h          | 1 |
| JU     | 16,000   |  7h          | 2 |
| SZ     | 18,000   |  8h          | 2 |
| FR     | 80,000   | 30h          | 6 |
| **Total** | ~140k | **~52h** | **~12 runs ≈ 3 days at 4 runs/day** |

After ~3 days of cron firing every 6 hours, the cloud-friendly cantons
are done. Your laptop only needs to handle BE/VS (and later the proxied
cantons when you fund them).

---

## Adding a canton that needs special handling

- **Image CAPTCHA cantons that use ddddocr** (JU, SZ, BL, partial GE): already
  install `ddddocr` in the workflow. To add BL, also pass `ANTHROPIC_API_KEY`
  as a repo secret and add to the env block.
- **Datacenter-blocked cantons** (GE, SO, GR, SH, NE): would need residential
  proxies in `<CANTON>_PROXY_LIST` repo secrets. Not currently included.
- **Interactive-login cantons** (BE, VS): would need cached OIDC tokens
  uploaded as secrets and refreshed periodically — deferred.

---

## Troubleshooting

**Action fails immediately with `Permission denied`**: GitHub blocked the
auto-commit. Go to **Settings → Actions → General → Workflow permissions**
and select "Read and write permissions".

**Dashboard shows "data/progress.json not found"**: the first scan hasn't
completed yet — wait one cron cycle, or trigger manually.

**The DB is getting big**: SQLite committed to git is fine up to ~100MB
per file. After full national scans, expect maybe 50-80MB. If it ever
approaches the limit, switch to Git LFS (free for public repos).
