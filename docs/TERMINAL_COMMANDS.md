# Herrenlos — Terminal Commands

Paste these two lines once per terminal session:

```bash
cd "/Users/basilirniger/Local Docs/herrenlos_scanner"
source .venv/bin/activate
```

---

## Start / stop the overnight scan loop

```bash
# START — detached background, survives terminal close, prevents sleep
caffeinate -d -i nohup ./scripts/scan-loop.sh > /tmp/herrenlos-scan.log 2>&1 &
echo "PID $! started"
```

```bash
# STOP
pkill -f scan-loop.sh
pkill -f run_local.py
```

```bash
# CHECK if running
pgrep -fl "scan-loop|run_local" || echo "Not running"
```

---

## Watch progress

```bash
# Live log
tail -f /tmp/herrenlos-scan.log
```

```bash
# Status per canton (scanned / enumerated / herrenlos)
python main.py ready
```

```bash
# Raw DB counts
sqlite3 herrenlos.db "SELECT canton, COUNT(*) AS scanned FROM parcels GROUP BY canton ORDER BY canton;"
```

```bash
# Herrenlos finds so far
sqlite3 herrenlos.db "SELECT canton, herrenlos_type, COUNT(*) FROM parcels WHERE is_herrenlos=1 GROUP BY 1,2;"
```

---

## Re-authenticate when a token expires

```bash
# BE — opens a Safari window (macOS AppleScript)
python main.py be --limit 1
```

```bash
# VS — opens a Chromium window for SwissID 2FA
python main.py vs --limit 1
```

---

## Regenerate dashboard + preview locally

```bash
python scripts/export_for_web.py && open docs/index.html
```

---

## Sync with GitHub

```bash
# Pull CI commits that landed while you were scanning
git pull --rebase origin main
```

```bash
# Push your local changes after a CI scan landed
git fetch origin && git rebase origin/main && git push
```

---

## Run a single canton manually

```bash
python main.py be --limit 500
python main.py vs --limit 500
python main.py bl --limit 200    # needs ANTHROPIC_API_KEY in .env
python main.py fr --limit 1000   # CI canton, no login
python main.py ju --limit 1000   # CI canton, no login
python main.py sz --limit 1000   # CI canton, no login
python main.py ur --limit 30     # ~14-30/day quota
python main.py sh --limit 100    # 100/day quota
python main.py ne --limit 50     # ~50/day quota
```

---

## Slow-background cantons (daily quota — run in a separate terminal)

```bash
python main.py ur   # exits when daily math-CAPTCHA quota (~14-30) is hit
python main.py sh   # 100 req/day
python main.py ne   # ~50 Altcha PoW/day
```

---

## Smoke tests

```bash
python main.py test --tier b        # bulk-capable cantons
python main.py test --tier c        # slow-background cantons
python main.py test fr ju sz        # specific cantons
```

---

## Clean up bad data

```bash
# Delete error rows for a canton
sqlite3 herrenlos.db "DELETE FROM parcels WHERE canton='so' AND status='error';"
```

```bash
# Delete ALL rows for a canton (also wipes herrenlos finds)
sqlite3 herrenlos.db "DELETE FROM parcels WHERE canton='so';"
```

---

## Canton coverage

| Group | Cantons | Command |
|-------|---------|---------|
| CI — automatic every 6h | FR, JU, SZ | nothing needed |
| Laptop bulk | BE, VS | `scan-loop.sh` above |
| Laptop bulk + API key | BL | add BL to loop; needs `ANTHROPIC_API_KEY` in `.env` |
| Slow background | UR, SH, NE, GR | `python main.py <canton>` |
| Needs proxies | SO, GE, BS | set `SO_PROXY_LIST`/`GE_PROXY_LIST` in `.env` |
| Blocked | ZH, ZG, TG, LU, AR, AI, OW, NW, TI, VD, GL | no path |
