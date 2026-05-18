"""
OW scanner — Obwalden
======================
STATUS (re-verified 2026-05-18): CANT_GET for private persons.

OW's electronic Grundbuch is gated to authorities and financial institutions
only (password-protected, no public registration). A public Eigentumsabfrage
portal was announced as planned in 2021 but never delivered as of May 2026.
Terravis serves the professional channel (banks/insurance/notaries) since
April 2022 — also closed to private persons.

REVISIT: monitor ow.ch announcements for a public-path launch.

LEGACY professional path (the code in this file): geoportal.ch ktow.owner.search
permission for notaries/surveyors/banks/authorities. Set OW_USERNAME/OW_PASSWORD
if you hold an institutional account. Not used by the test framework.

Platform : OW Grundbuchamt password-portal (closed)  |  legacy: geoportal.ch (ktow)
Parcels  : ~13 000  |  Full scan ~5 h at 1.5 s/query
Bbox LV95: E 2635000–2678000, N 1170000–1210000
"""
import logging
from scanners.geoportal_base import run_scan

log = logging.getLogger("OW")

def scan(limit=None, skip_existing=True, delay=1.5):
    run_scan(
        canton_code  = "OW",
        primary_area = "ktow",
        username_env = "OW_USERNAME",
        password_env = "OW_PASSWORD",
        e_min=2_635_000, e_max=2_678_000,
        n_min=1_170_000, n_max=1_210_000,
        grid_step=200, limit=limit, skip_existing=skip_existing,
        delay=delay, log=log,
    )
