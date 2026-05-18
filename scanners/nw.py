"""
NW scanner — Nidwalden
=======================
STATUS (re-verified 2026-05-18): CANT_GET for private persons.

NW's only public online presence (nw.ch/online-schalter/1067) is a PURPOSE-BOUND
ordering form: submit a request with a stated purpose (building application,
bank credit, etc.), staff processes it, postal delivery with CHF 30 invoice.
Not a direct lookup — not automatable for bulk owner queries on arbitrary parcels.
Faking purpose codes would be illegitimate.

No reclassification path identified. Federal e-ID won't help — the issue
is policy, not authentication.

LEGACY professional path (the code in this file): geoportal.ch ktnw.owner.search
permission for notaries/surveyors/banks/authorities. Set NW_USERNAME/NW_PASSWORD
if you hold an institutional account. Not used by the test framework.

Platform : nw.ch/online-schalter (form-mail)  |  legacy: geoportal.ch (ktnw)
Parcels  : ~14 000  |  Full scan ~6 h at 1.5 s/query
Bbox LV95: E 2655000–2682000, N 1188000–1210000
"""
import logging
from scanners.geoportal_base import run_scan

log = logging.getLogger("NW")

def scan(limit=None, skip_existing=True, delay=1.5):
    run_scan(
        canton_code  = "NW",
        primary_area = "ktnw",
        username_env = "NW_USERNAME",
        password_env = "NW_PASSWORD",
        e_min=2_655_000, e_max=2_682_000,
        n_min=1_188_000, n_max=1_210_000,
        grid_step=200, limit=limit, skip_existing=skip_existing,
        delay=delay, log=log,
    )
