# Terminal Commands — Herrenlos Scanner

All commands run from the repo root:
```
cd "/Users/basilirniger/Local Docs/herrenlos_scanner"
```

---

## Start / stop the overnight scan loop (BE + VS + BL)

**Start (detached, survives terminal close, prevents sleep):**
```bash
caffeinate -d -i nohup env LOCAL_ELIGIBLE_CANTONS="be vs" ./scripts/scan-loop.sh \
  > /tmp/herrenlos-scan.log 2>&1 &
echo "PID $! — tail -f /tmp/herrenlos-scan.log to watch"
```

**Stop:**
```bash
pkill -f scan-loop.sh   # kills the shell wrapper
pkill -f run_local.py   # kills the Python loop underneath
```

**Check if it's running:**
```bash
pgrep -fl "scan-loop\|run_local" || echo "Not running"
```

---

## Watch progress

**Live log tail:**
```bash
tail -f /tmp/herrenlos-scan.log
```

**DB summary — scanned vs total, per canton:**
```bash
python main.py ready
```

**Quick scanned-count by canton:**
```bash
sqlite3 herrenlos.db "
  SELECT canton, COUNT(*) AS scanned,
         (SELECT COUNT(*) FROM parcel_enum pe WHERE pe.canton=p.canton) AS enumerated
  FROM parcels p
  GROUP BY canton ORDER BY canton;"
```

**How many herrenlos found so far:**
```bash
sqlite3 herrenlos.db \
  "SELECT canton, herrenlos_type, COUNT(*) FROM parcels WHERE is_herrenlos=1 GROUP BY 1,2;"
```

---

## Re-authenticate when a token expires

**BE (Safari AppleScript — opens a Safari window):**
```bash
python main.py be --limit 1
```

**VS (Playwright Chromium window + SwissID 2FA):**
```bash
python main.py vs --limit 1
```

After logging in the token is cached and the loop picks it up automatically on the next parcel.

---

## Regenerate the dashboard JSON + preview locally

```bash
python scripts/export_for_web.py
open docs/index.html
```

---

## Sync with GitHub (pull CI commits before pushing)

```bash
git pull --rebase origin main
```

**Push your local commits after a CI scan landed:**
```bash
git fetch origin
git rebase origin/main
git push
```

---

## Run a single canton manually (foreground, with output)

```bash
python main.py be --limit 500    # BE, cap at 500 parcels
python main.py vs --limit 500    # VS
python main.py bl --limit 200    # BL (needs ANTHROPIC_API_KEY in .env)
python main.py ju --limit 1000   # JU (CI-eligible, no login)
python main.py fr --limit 1000   # FR (CI-eligible)
python main.py sz --limit 1000   # SZ (CI-eligible)
python main.py ur --limit 30     # UR (slow background — ~14-30/day)
python main.py sh --limit 100    # SH (100/day)
python main.py ne --limit 50     # NE (~50/day)
```

---

## Slow-background cantons (leave running in a separate terminal)

These have daily quotas; one IP can make progress but bulk needs months:

```bash
# UR — runs until daily math-CAPTCHA quota (~14-30 req/day) is hit, then exits
python main.py ur

# SH — 100 req/day
python main.py sh

# NE — ~50 Altcha PoW/day
python main.py ne
```

---

## Smoke tests

```bash
python main.py test --tier b          # all tier-B (bulk-capable) cantons
python main.py test --tier c          # slow-background cantons
python main.py test fr ju sz          # specific cantons
```

---

## Clean up bad data

**Delete all rows for a canton (careful — also wipes herrenlos finds):**
```bash
sqlite3 herrenlos.db "DELETE FROM parcels WHERE canton='so';"
```

**Delete only error rows for a canton:**
```bash
sqlite3 herrenlos.db "DELETE FROM parcels WHERE canton='so' AND status='error';"
```

**Delete false-positive herrenlos rows:**
```bash
sqlite3 herrenlos.db "DELETE FROM parcels WHERE canton='so' AND is_herrenlos=1;"
```

---

## Monitor GitHub Actions CI

**Latest run status (needs `gh` CLI):**
```bash
gh run list --limit 5 --workflow scan.yml
```

**Watch live logs of the running CI job:**
```bash
gh run watch
```

**Trigger a manual scan for a specific canton:**
```bash
gh workflow run scan.yml -f canton=fr
```

---

## Canton coverage at a glance

| Group | Cantons | How to run |
|-------|---------|------------|
| CI (GitHub Actions, automatic) | FR, JU, SZ | runs every 6h; no action needed |
| Laptop bulk (this loop) | BE, VS | `scan-loop.sh` above |
| Laptop bulk + API key | BL | add `BL` to `LOCAL_ELIGIBLE_CANTONS`; needs `ANTHROPIC_API_KEY` in `.env` |
| Slow background (daily quota) | UR, SH, NE, GR | `python main.py <canton>` separately |
| Needs proxies | SO, GE, BS-public | set `SO_PROXY_LIST` / `GE_PROXY_LIST` in `.env` first |
| Blocked (SMS/professional) | ZH, ZG, TG, LU, AR, AI, OW, NW, TI, VD, GL | no path |
