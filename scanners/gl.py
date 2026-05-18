"""
GL scanner — Glarus
====================
STATUS (re-verified 2026-05-18): CANT_GET for private persons.

The real public path is via my.gl.ch (Glarus service portal with AGOV login),
but the Grundbuchauszug service (id=29) requires AGOV LoA-3 ("erhöhte
Identifizierungsstufe"). Plain AGOV self-service registration only gives LoA-1.
LoA-3 needs manual identity proofing today; the federal Swiss e-ID that
would automate this was postponed to 1 December 2026 (SFAO audit, Feb 2026).

REVISIT: 1 December 2026 — check if my.gl.ch lowers the LoA threshold once e-ID
is generally available.

LEGACY professional path (the code in this file): geoportal.ch ktgl.owner.search
permission for notaries/surveyors/banks/authorities. Set GL_USERNAME/GL_PASSWORD
if you hold an institutional account. Not used by the test framework.

Platform : my.gl.ch (LoA-3 gate)  |  legacy: geoportal.ch (ktgl) institutional
Parcels  : ~15 000  |  Full scan ~6 h at 1.5 s/query
Bbox LV95: E 2708000–2742000, N 1194000–1225000
"""
import logging
from scanners.geoportal_base import run_scan

log = logging.getLogger("GL")

def scan(limit=None, skip_existing=True, delay=1.5):
    run_scan(
        canton_code  = "GL",
        primary_area = "ktgl",
        username_env = "GL_USERNAME",
        password_env = "GL_PASSWORD",
        e_min=2_708_000, e_max=2_742_000,
        n_min=1_194_000, n_max=1_225_000,
        grid_step=200, limit=limit, skip_existing=skip_existing,
        delay=delay, log=log,
    )
