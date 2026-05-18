"""
VD scanner — Vaud
==================
STATUS (re-verified 2026-05-18): CANT_GET for private-person AUTOMATION.

VD has a public path at prestations.vd.ch/pub/101435 — 5 requests/day per
person, no proof of interest needed. BUT it's a FORM with 48-hour business-day
turnaround (results by email), not a real-time lookup. A full ~250k-parcel
canton scan via that path would take ~40,000 days. Not viable as a scanner.

INTERCAPI is the only real-time option but requires professional accreditation
(notaries/lawyers/surveyors/banks).

No reclassification path identified for private-person automation.

LEGACY professional path (the code in this file): geoportal.ch ktvd.owner.search
permission for notaries/surveyors/banks/authorities. Set VD_USERNAME/VD_PASSWORD
if you hold an institutional account. Not used by the test framework.

Platform : prestations.vd.ch (form-mail, 48h)  |  INTERCAPI (professional only)
Parcels  : ~250 000  |  Full scan ~104 h at 1.5 s/query (institutional path)
Bbox LV95: E 2490000–2583000, N 1118000–1185000
"""
import logging
from scanners.geoportal_base import run_scan

log = logging.getLogger("VD")

def scan(limit=None, skip_existing=True, delay=1.5):
    run_scan(
        canton_code  = "VD",
        primary_area = "ktvd",
        username_env = "VD_USERNAME",
        password_env = "VD_PASSWORD",
        e_min=2_490_000, e_max=2_583_000,
        n_min=1_118_000, n_max=1_185_000,
        grid_step=200, limit=limit, skip_existing=skip_existing,
        delay=delay, log=log,
    )
