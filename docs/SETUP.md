# Setup — running scans on GitHub Actions + serving the dashboard on GitHub Pages

This kit gives you:
- **Cloud scanners** that run every 6 hours on GitHub Actions and commit results back to the repo
- **A static dashboard + Leaflet map** served from GitHub Pages, automatically refreshed after each scan

Public repos get unlimited free Actions minutes; private repos get 2000 min / month.

The cloud workflow handles cantons that work from GitHub Actions datacenter IPs:
**JU, SZ** (OCR-solvable CAPTCHA) and **SH, GR** (daily-quota cantons, proxy-rotated).
FR was removed: keycloak.fr.ch geo-blocks datacenter IPs.

Other cantons stay on your laptop:
- **UR** — geo-blocked from datacenter IPs (Swiss IP only)
- **NE** — daily quotas; rotation needed only for full-scale completion
- **SO** — reCAPTCHA v3 score fails from datacenter; passes from residential IP
- **BE, VS** — interactive login (Safari/Playwright on macOS), token cached after first run
- **BL** — needs `ANTHROPIC_API_KEY` for handwritten CAPTCHA
- **GE** — needs `GE_PROXY_LIST` (Imperva) + `ANTHROPIC_API_KEY` (image CAPTCHA)
- **BS** (full owner data) — needs `BS_PROXY_LIST` + `BS_API_KEY`

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

### 3. (Optional) Configure secrets

The current CI cantons (JU, SZ, SH, GR) need no secrets beyond a proxy list
for the rate-limited cantons. The workflow forwards a few optional secrets if
you've set them — useful only if you later expand `ELIGIBLE_CANTONS` in
`.github/workflows/scan.yml`:

**Settings → Secrets and variables → Actions → New repository secret**
- `BS_API_KEY` — only needed if you re-enable BS in CI (free key at <https://api.geo.bs.ch/>)

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

CI cantons only — laptop work is unbounded:

| Canton | Parcels | Compute time | Runs needed at 5h each |
|--------|---------:|-------------:|-----------------------:|
| JU     | 16,000   |  7h          | 2 |
| SZ     | 18,000   |  8h          | 2 |
| SH     | 50,000   | several days | ~50 (100 req/day/IP)   |
| GR     | 85,000   | many months  | ~425 (10 req/day/IP)   |

SH and GR are bounded by proxy capacity, not compute. With a WEBSHARE proxy
pool at 900 req/day (SH) or 90 req/day (GR), pick_canton.py rotates the pool
automatically. The rest are laptop-only (see laptop scan loop in README).

---

## Adding a canton that needs special handling

- **Image CAPTCHA cantons (ddddocr)** — JU, SZ already in CI. BL would also need
  `ANTHROPIC_API_KEY` because ddddocr fails on its handwritten CAPTCHA — and BL
  works fine from your laptop, so adding to CI is rarely worth it.
- **Datacenter-blocked cantons** (UR, SO, SH, NE, GR, GE, BS-public) — laptop
  runs work; full proxy plumbing exists in GE/BS but no equivalent for SH/NE/GR yet.
- **Interactive-login cantons** (BE, VS) — cannot be CI'd: VS requires SwissID
  2FA, BE has Cloudflare Turnstile + macOS Safari AppleScript. Laptop only.

---

## Avoiding push conflicts with cloud scans

The `herrenlos.db` file is a **binary** SQLite database, so concurrent commits
from your laptop AND from GitHub Actions can collide. The workflow now
auto-retries with rebase, but the **safe pattern** is:

- **The cloud owns `herrenlos.db`.** Only the Actions workflow should commit it.
- Locally, edit code / docs / `docs/data/*.json` freely — those merge fine.
- If you must touch the DB locally (cleanup, migration), check that no scan
  is running first: <https://github.com/birniger/Herrenlos/actions>
- After a local DB edit + push, the next cloud scan will rebase its work
  on top with `rebase -X ours` for the DB — meaning the cloud's fresh scan
  data wins on conflict. Your manual edit may be overwritten; redo it after
  the scan completes.

## Troubleshooting

**Action fails immediately with `Permission denied`**: GitHub blocked the
auto-commit. Go to **Settings → Actions → General → Workflow permissions**
and select "Read and write permissions".

**Dashboard shows "data/progress.json not found"**: the first scan hasn't
completed yet — wait one cron cycle, or trigger manually.

**The DB is getting big**: SQLite committed to git is fine up to ~100MB
per file. After full national scans, expect maybe 50-80MB. If it ever
approaches the limit, switch to Git LFS (free for public repos).
