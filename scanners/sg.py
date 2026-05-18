"""
SG scanner — St. Gallen
========================
STATUS (re-verified 2026-05-18): UNBUILT-BUILDABLE (public path exists).

After the 2023 SG cantonal ordinance revision, virtually all SG municipalities
publish owners publicly via geoportal.ch/ktsg (only Eichberg holds out, per
Rheintaler 2024-10). The public path:
  1. Map → click parcel → expand "Eigentümer | Anzeigen"
  2. reCAPTCHA Enterprise v2 ("I'm not a robot" checkbox) appears
  3. On success: GET https://www.geoportal.ch/search/ownerinfo/?...&token={recaptcha}
                  returns owner JSON
  4. Without owner.search permission OR valid reCAPTCHA → {"challenge": true}

The endpoint is the SAME as the professional path used by geoportal_base.py;
only the auth differs (reCAPTCHA vs OAuth). A public-path scanner would extend
geoportal_base with a reCAPTCHA Enterprise v2 solver (2captcha-style service
~$0.003/solve, OR human-in-loop for first N parcels).

REVISIT: build sg_public.py when 2captcha integration is added across the
scanner suite (also benefits the GE image-CAPTCHA scaling story).

LEGACY professional path (the code in this file): geoportal.ch ktsg.owner.search
permission for notaries/surveyors/banks/authorities. Set SG_USERNAME/SG_PASSWORD
if you hold an institutional account. Not used by the test framework.

Platform : geoportal.ch/ktsg (public via reCAPTCHA Enterprise v2)
Parcels  : ~115 000  |  Full scan ~48 h at 1.5 s/query
Bbox LV95: E 2722000–2780000, N 1225000–1265000
"""
import logging
from scanners.geoportal_base import run_scan

log = logging.getLogger("SG")

def scan(limit=None, skip_existing=True, delay=1.5):
    run_scan(
        canton_code  = "SG",
        primary_area = "ktsg",
        username_env = "SG_USERNAME",
        password_env = "SG_PASSWORD",
        e_min=2_722_000, e_max=2_780_000,
        n_min=1_225_000, n_max=1_265_000,
        grid_step=200, limit=limit, skip_existing=skip_existing,
        delay=delay, log=log,
    )
