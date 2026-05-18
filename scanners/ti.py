"""
TI scanner — Ticino
====================
STATUS (re-verified 2026-05-18): CANT_GET for private persons.

TI's SIFTI-web requires registry-issued authorization under ORF Art. 28+,
explicitly EXCLUDING "craftspeople, consultants, trust companies, planners,
architects, real estate agents" — i.e. no private-person path. The public
Geoportale Ticino (map.geo.ti.ch using ngeo/c2cgeoportal) exposes ONLY parcel
numbers and EGRID — owner data requires a mail request to the registry office
(not automatable for bulk queries).

No reclassification path identified.

LEGACY professional path (the code in this file): geoportal.ch ktti.owner.search
permission for notaries/surveyors/banks/authorities. Set TI_USERNAME/TI_PASSWORD
if you hold an institutional account. Not used by the test framework.

Platform : SIFTI-web (ORF Art. 28+)  |  Geoportale Ticino (no owner data)
Parcels  : ~190 000  |  Full scan ~79 h at 1.5 s/query
Bbox LV95: E 2683000–2754000, N 1076000–1145000
"""
import logging
from scanners.geoportal_base import run_scan

log = logging.getLogger("TI")

def scan(limit=None, skip_existing=True, delay=1.5):
    run_scan(
        canton_code  = "TI",
        primary_area = "ktti",
        username_env = "TI_USERNAME",
        password_env = "TI_PASSWORD",
        e_min=2_683_000, e_max=2_754_000,
        n_min=1_076_000, n_max=1_145_000,
        grid_step=200, limit=limit, skip_existing=skip_existing,
        delay=delay, log=log,
    )
