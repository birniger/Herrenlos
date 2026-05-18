"""
TG scanner — Thurgau
=====================
STATUS (re-verified 2026-05-18): BLOCKED for automation — SMS-per-query gate.

The PUBLIC path at map.geo.tg.ch ThurGIS Viewer is anonymous (no login) but
requires entering a Swiss mobile number and receiving an SMS code for EVERY
owner lookup. Hard cap of 50 queries/hour. This is operationally the same
dead-end as ZH/ZG/LU — cannot be solved by IP rotation or proxies because
each query requires a human SMS action.

No reclassification path identified for private-person automation.

LEGACY professional path (the code in this file): geoportal.ch kttg.owner.search
permission for notaries/surveyors/banks/authorities. Set TG_USERNAME/TG_PASSWORD
if you hold an institutional account. Not used by the test framework.

Platform : map.geo.tg.ch (SMS-gated)  |  legacy: geoportal.ch (kttg)
Parcels  : ~100 000  |  Full scan ~42 h at 1.5 s/query
Bbox LV95: E 2700000–2762000, N 1260000–1295000
"""
import logging
from scanners.geoportal_base import run_scan

log = logging.getLogger("TG")

def scan(limit=None, skip_existing=True, delay=1.5):
    run_scan(
        canton_code  = "TG",
        primary_area = "kttg",
        username_env = "TG_USERNAME",
        password_env = "TG_PASSWORD",
        e_min=2_700_000, e_max=2_762_000,
        n_min=1_260_000, n_max=1_295_000,
        grid_step=200, limit=limit, skip_existing=skip_existing,
        delay=delay, log=log,
    )
