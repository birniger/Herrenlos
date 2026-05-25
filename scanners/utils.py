"""
Shared utilities for herrenlos scanners.

Legal basis (researched 2026-05):
  ZGB Art. 658  — Aneignung of herrenlos parcels (subject to cantonal law)
  ZGB Art. 664  — unregistered land → cantonal Hoheit; not privately claimable
  ZGB Art. 666  — substantive rule: ownership lost by Dereliktion
  ZGB Art. 964  — procedural rule: Verzichtserklärung filed with Grundbuchamt,
                  which deletes the owner entry (this is the operational signal
                  scanners detect in cantonal portals)
  BGE 118 II 115 — SDR/Baurecht cannot be derelicted (dingliche Rechte, no corpus)
  BGE 114 II 318 — "Owner unknown" ≠ herrenlos; only 30-yr Ersitzung (Art. 662)
  BGE 50 II 232  — Dereliktion requires unequivocal renunciation act

Known herrenlos cases (validation reference for tests):
  - Aire-la-Ville (GE, BFS 6601), parcel 722, ~11 m² (Le Temps, 1999)
  - Schwyz canton: 26 parcels listed in Schwyz Amtsblatt Nr. 12 (21 March 2025)
    after Jonas Lauwiner Aneignungsverfahren; ~19,000 m² total
"""

import os
import pathlib
import re


# ─────────────────────────────────────────────────────────────────────────────
# PROXY UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def load_proxies(env_key: str) -> list[str]:
    """
    Load a proxy list from an env var or .env file.

    env_key: e.g. "SH_PROXY_LIST", "GR_PROXY_LIST", "NE_PROXY_LIST"

    Accepts two formats (mixed is fine):
      • Webshare download format (one per line):  host:port:username:password
      • URL format (comma or newline separated):  http://username:password@host:port

    Returns a list of "http://username:password@host:port" strings.
    Returns [] if the env var is unset / .env has no matching key.
    """
    # If env var is explicitly set (even to empty string) honour it and skip .env.
    # This lets callers force no-proxy with: NE_PROXY_LIST= python3 main.py ne
    _env_explicitly_set = env_key in os.environ
    raw = os.environ.get(env_key, "").strip()
    if not raw and not _env_explicitly_set:
        proj_root = pathlib.Path(__file__).parent.parent
        for env_file in [proj_root / ".env", pathlib.Path.home() / ".env"]:
            if env_file.exists():
                try:
                    for line in env_file.read_text().splitlines():
                        line = line.strip()
                        if line.startswith("#") or "=" not in line:
                            continue
                        k, _, v = line.partition("=")
                        k = k.strip().lstrip("export").strip()
                        if k == env_key:
                            raw = v.strip().strip('"').strip("'")
                            break
                except Exception:
                    pass
            if raw:
                break

    proxies: list[str] = []
    for entry in re.split(r"[,\n]", raw):
        entry = entry.strip()
        if not entry:
            continue
        if entry.startswith("http"):
            proxies.append(entry)
        else:
            # Webshare host:port:username:password format
            parts = entry.split(":")
            if len(parts) == 4:
                host, port, user, passwd = parts
                proxies.append(f"http://{user}:{passwd}@{host}:{port}")
            else:
                pass  # unrecognised format — skip silently
    return proxies


# ─────────────────────────────────────────────────────────────────────────────
# CANONICAL SCANNER INTERFACE — every scanner module in scanners/ MUST honour
# this contract. The test framework (test_fixtures.py + db.py) depends on it.
# ─────────────────────────────────────────────────────────────────────────────
#
# 1. scan(limit=None, skip_existing=True, delay=…)
#    Returns a summary dict; persists results via upsert_parcel(). NE may also
#    accept `refresh_enum=False`. No other kwargs are required.
#
# 2. check_owner(...) returns a dict with EXACTLY these 7 canonical keys:
#       owner          : str | None        — owner names joined with "; ", or None
#       owner_address  : str | None        — address(es); None if portal doesn't expose
#       is_herrenlos   : 0 | 1 | None      — 1=herrenlos, 0=has owner, None=unknown/error
#       herrenlos_type : str | None        — one of:
#                                              "dereliktion"     (Art. 964 ZGB; in GB, owner deleted)
#                                              "not_in_grundbuch"(Art. 664 ZGB; never registered)
#                                              "no_owner"        (parse ambiguity / blank field)
#                                              None              (when has owner OR unknown)
#       claim_possible : 0 | 1 | None      — set via claim_possible_for(canton, type)
#       raw_response   : str | None        — short snippet (≤300 chars) for debugging
#       error          : str | None        — one of the canonical strings below,
#                                              or scanner-specific (transient/retryable)
#
# 3. Canonical error vocabulary (use when applicable; favour these over one-offs):
#
#      Auth / session
#        auth_expired             — token rejected; caller should re-login
#        token_expired            — refresh token expired
#        cookies_required         — portal demands session cookie we don't have
#        sms_required             — operational dead-end (e.g. ZG)
#        invalid_api_key          — server rejected the API key
#
#      Transport / rate-limit
#        http_<NNN>               — non-200 status from portal
#        rate_limited             — explicit 429 / "too many requests"
#        session_exhausted        — server-side session quota hit (FR pattern)
#        service_unavailable      — bot-protection (Imperva, Cloudflare) blocked us
#
#      CAPTCHA pipeline (BL, SZ, JU)
#        captcha_unsolved         — OCR could not produce a candidate answer
#        captcha_wrong            — answer submitted, server said wrong
#        no_captcha_found         — expected CAPTCHA element missing from HTML
#        no_captcha_field         — form has no <input> we recognise
#
#      Parsing
#        parse_failed             — CAPTCHA accepted but page structure unrecognised
#        <section>_section_missing — specific block (Eigentümer / Propriétaire) missing
#
# 4. OCR helper naming (BL, SZ, JU): always use these three function names so
#    the captcha-stats labels stay consistent across cantons.
#       _solve_ddddocr(...)       — primary (fast, ~75% on printed CAPTCHAs)
#       _solve_tesseract(...)     — fallback (with whatever preprocessing the
#                                    canton's CAPTCHA needs; the public name is
#                                    "tesseract" regardless of preprocessing)
#       _solve_claude(...)        — handwritten/hard CAPTCHAs only (BL); needs
#                                    ANTHROPIC_API_KEY
#    Always call log_captcha(canton, solver_name, outcome) after each attempt
#    so captcha_stats stays populated.
#
# 5. Module docstring SHOULD have these sections (terse is fine, but cover them):
#       STATUS, AUTHENTICATION, EGRID enumeration, Owner lookup, Herrenlos signal,
#       Rate limit, Parcels (approx count), REQUIRES (dependencies).
#
# ─────────────────────────────────────────────────────────────────────────────


# ── Herrenlos owner-text detection ───────────────────────────────────────────
#
# After formal Dereliktion a cantonal Grundbuch portal may write one of these
# strings in the owner (Eigentümer / Propriétaire) field instead of leaving it
# blank.  We detect them so the owner field is not mistakenly treated as a real
# owner name.
#
# German: herrenlos, ohne Eigentümer, kein Eigentümer, vakant, unbesetzt
# French (FR, JU, VS, NE, GE, VD): sans propriétaire / sans maître / bien vacant
# Italian (TI): senza proprietario / bene vacante / vacante

_HERRENLOS_EXACT: set[str] = {
    # ── German ──────────────────────────────────────────────────────────────
    "herrenlos",
    "ohne eigentümer",
    "kein eigentümer",
    "kein eigentümer eingetragen",
    "kein eigentümer vorhanden",
    "ohne eigentümer eingetragen",
    "ohne eintrag des eigentümers",
    "ohne eintrag eines eigentümers",
    "kein eintrag des eigentümers",
    "eigentümer fehlt",
    "vakant",
    "unbesetzt",
    "keine eigentümerschaft",
    "dereliktion",
    # ── French ──────────────────────────────────────────────────────────────
    "sans propriétaire",
    "sans proprietaire",
    "sans propriétaire inscrit",
    "sans proprietaire inscrit",
    "sans propriétaire enregistré",
    "sans proprietaire enregistre",
    "aucun propriétaire",
    "aucun proprietaire",
    "pas de propriétaire",
    "pas de proprietaire",
    "sans maître",
    "sans maitre",
    "biens sans maître",
    "biens sans maitre",
    "bien vacant",
    "biens vacants",
    "propriété vacante",
    "propriete vacante",
    "propriétés vacantes",
    "proprietes vacantes",
    "immeuble vacant",
    "immeubles vacants",
    "vacant",
    "abandonnée",
    "abandonné",
    "déreliction",
    # ── Italian (TI, GR) ────────────────────────────────────────────────────
    "senza proprietario",
    "senza padrone",
    "bene vacante",
    "beni vacanti",
    "vacante",
    "abbandonato",
    "abbandonata",
    "privo di proprietario",
}

_HERRENLOS_PATTERNS: list[re.Pattern] = [
    # ── German ──────────────────────────────────────────────────────────────
    # All adjective inflections: herrenlose/herrenloses/herrenlosen/herrenlosem/herrenloser
    re.compile(r'\bherrenlos(?:e[mrsn]?)?\b',         re.IGNORECASE),
    re.compile(r'\bohne\s+eigent[üu]mer\b',            re.IGNORECASE),
    re.compile(r'\bkein(?:e[rmsn]?)?\s+eigent[üu]mer\b', re.IGNORECASE),
    re.compile(r'\beigent[üu]mer\s+fehlt\b',          re.IGNORECASE),
    # "ohne Eintrag des Eigentümers" — common Grundbuch wording for derelicted parcels
    re.compile(r'\b(?:ohne|kein(?:er)?)\s+eintrag\s+(?:des|eines)\s+eigent[üu]mer', re.IGNORECASE),
    # "vakant" is safe in owner-field context but too generic for full-page search
    # (German job postings also use "vakant" = vacant position).
    # Included here for is_herrenlos_owner_text(); excluded from _HERRENLOS_PAGE_PATTERNS.
    re.compile(r'\bvakant\b',                          re.IGNORECASE),
    re.compile(r'\bderelikti(?:on|ert)\b',             re.IGNORECASE),
    # ── French ──────────────────────────────────────────────────────────────
    re.compile(r'\bsans\s+propri[eé]taire\b',         re.IGNORECASE),
    re.compile(r'\baucun(?:e)?\s+propri[eé]taire\b',  re.IGNORECASE),
    re.compile(r'\bpas\s+de\s+propri[eé]taire\b',     re.IGNORECASE),
    re.compile(r'\bsans\s+ma[iî]tre\b',               re.IGNORECASE),
    re.compile(r'\bbiens?\s+sans\s+ma[iî]tre\b',      re.IGNORECASE),
    re.compile(r'\bbiens?\s+vacants?\b',              re.IGNORECASE),
    re.compile(r'\bimmeubles?\s+vacants?\b',          re.IGNORECASE),
    re.compile(r'\bpropri[eé]t[eé]s?\s+vacantes?\b', re.IGNORECASE),
    re.compile(r'\bsans\s+propri[eé]t[eé]\b',        re.IGNORECASE),
    re.compile(r'\bd[eé]reliction\b',                 re.IGNORECASE),
    # ── Italian ─────────────────────────────────────────────────────────────
    re.compile(r'\bsenza\s+proprietario\b',           re.IGNORECASE),
    re.compile(r'\bsenza\s+padrone\b',                re.IGNORECASE),
    re.compile(r'\bben[ei]\s+vacanti?\b',             re.IGNORECASE),
    re.compile(r'\babbandonat[oa]\b',                 re.IGNORECASE),
    re.compile(r'\bprivo\s+di\s+proprietario\b',      re.IGNORECASE),
]

# Subset of _HERRENLOS_PATTERNS safe for full-page text search.
# Excludes bare \bvakant\b (fires on German job-vacancy text like "die Stelle ist vakant")
# and bare \babbandonat[oa]\b (could appear in property descriptions: "edificio abbandonato").
_HERRENLOS_PAGE_PATTERNS: list[re.Pattern] = [
    p for p in _HERRENLOS_PATTERNS
    if p.pattern not in (r'\bvakant\b', r'\babbandonat[oa]\b')
]


# ── "Owner unknown" detection ─────────────────────────────────────────────────
#
# BGE 114 II 318: "Eigentümer unbekannt" is NOT herrenlos.
# The parcel has an owner — their identity is simply unknown.
# Only 30-year adverse possession (Art. 662 ZGB) applies, not Aneignung.
# Scanners must NOT classify these as herrenlos.

_UNKNOWN_OWNER_EXACT: set[str] = {
    "unbekannt",
    "eigentümer unbekannt",
    "eigentuemer unbekannt",
    "eigentümerschaft unbekannt",
    "inconnu",
    "propriétaire inconnu",
    "proprietaire inconnu",
    "sconosciuto",
    "proprietario sconosciuto",
    "unknown",
}

_UNKNOWN_OWNER_PATTERNS: list[re.Pattern] = [
    re.compile(r'\bunbekannt\b',              re.IGNORECASE),
    re.compile(r'\binconnu[e]?\b',            re.IGNORECASE),
    re.compile(r'\bsconosciut[oa]\b',         re.IGNORECASE),
    re.compile(r'\bowner\s+unknown\b',        re.IGNORECASE),
    re.compile(r'\beigent[üu]mer\s+unbekannt\b', re.IGNORECASE),
]


# ── Public-body owner detection ───────────────────────────────────────────────
#
# Parcels owned by Kanton, Gemeinde, Bund, Korporation, Alp, etc. are already
# in public/collective ownership — they are NOT herrenlos in any private-law
# sense and must be classified is_herrenlos=0.
#
# Key public-body indicators:
#   German : Kanton, Gemeinde, Bund, Eidgenossenschaft, Korporation, Alp,
#             Allmend, Stadt, Bezirk, Kirchgemeinde, Ortsgemeinde,
#             Einwohnergemeinde, Bürgergemeinde, Ortsbürgergemeinde,
#             Munizipalgemeinde, Forst(korporation)
#   French : Commune, Canton, État, Confédération, République, Municipalité,
#             Patriciats (Fr, VS)
#   Italian: Comune, Cantone, Confederazione, Patriziato

_PUBLIC_OWNER_EXACT: set[str] = {
    # German tokens (bare)
    "kanton", "gemeinde", "bund", "eidgenossenschaft",
    "korporation", "korporationsgemeinde",
    "alp", "alpgenossenschaft", "alpengenossenschaft",
    "allmend", "allmendkorporation", "forst", "forstkorporation",
    "staat", "stadt", "bezirk",
    "kirchgemeinde", "ortsgemeinde", "einwohnergemeinde",
    "bürgergemeinde", "ortsbürgergemeinde", "munizipalgemeinde",
    "politische gemeinde",
    # German federal owners (frequent in real Grundbuch entries)
    "sbb", "sbb ag", "schweizerische bundesbahnen",
    "vbs", "armasuisse", "armasuisse immobilien",
    "post ag", "schweizerische post",
    # French
    "commune", "canton", "état", "confédération",
    "republique", "république", "municipalité",
    "patriciats", "bourgeoisie",
    "cff", "cff sa",   # Chemins de fer fédéraux suisses
    # Italian
    "comune", "cantone", "confederazione", "patriziato",
    "ffs", "ffs sa",
}

_PUBLIC_OWNER_PATTERNS: list[re.Pattern] = [
    re.compile(r'\bkanton\b',                       re.IGNORECASE),
    re.compile(r'\bgemeinde\b',                     re.IGNORECASE),
    re.compile(r'\beinwohnergemeinde\b',            re.IGNORECASE),
    re.compile(r'\bbürgergemeinde\b',               re.IGNORECASE),
    re.compile(r'\bortsgemeinde\b',                 re.IGNORECASE),
    re.compile(r'\bkirchgemeinde\b',                re.IGNORECASE),
    re.compile(r'\beidgenossenschaft\b',            re.IGNORECASE),
    re.compile(r'\bschweizerische\s+eidgenossenschaft\b', re.IGNORECASE),
    re.compile(r'\bkorporationsgemeinde\b',         re.IGNORECASE),
    re.compile(r'\balpgenossenschaft\b',            re.IGNORECASE),
    re.compile(r'\ballmendkorporation\b',           re.IGNORECASE),
    re.compile(r'\bforstkorporation\b',             re.IGNORECASE),
    re.compile(r'\bconfédération\s+suisse\b',       re.IGNORECASE),
    re.compile(r'\bconfédération\b',               re.IGNORECASE),
    re.compile(r'\brépublique\s+et\s+canton\b',    re.IGNORECASE),
    re.compile(r'\brepubblica\s+e\s+cantone\b',    re.IGNORECASE),
    # Federal-level entities frequently appearing in Grundbuch
    re.compile(r'\bbundesamt\s+für\b',              re.IGNORECASE),
    re.compile(r'\barmasuisse\b',                   re.IGNORECASE),
    re.compile(r'\bschweizerische\s+bundesbahnen\b', re.IGNORECASE),
    re.compile(r'\bschweizerische\s+post\b',        re.IGNORECASE),
    re.compile(r'\bsbb\s+ag\b',                     re.IGNORECASE),
    re.compile(r'\bcff\s+sa\b',                     re.IGNORECASE),
    re.compile(r'\bffs\s+sa\b',                     re.IGNORECASE),
    # Catches "Kanton Zug", "Einwohnergemeinde Aarau", "Stadt Zürich" etc.
    re.compile(r'^(kanton|gemeinde|einwohnergemeinde|bürgergemeinde|'
               r'ortsgemeinde|politische\s+gemeinde|stadt|bezirk)\s+\w',
               re.IGNORECASE),
    # French/Italian commune prefixes: "Commune de X", "Ville de X", "Comune di X"
    re.compile(r'^(commune|ville|cité|municipalité|comune|città|patriziato)\s+(?:de|di|d\'|\s)\s*\w',
               re.IGNORECASE),
]


# ── SDR / Baurecht parcel type detection ─────────────────────────────────────
#
# BGE 118 II 115: SDR (selbständiges und dauerndes Recht) and Baurecht are
# registered rights (dingliche Rechte on another's land), not corporeal
# parcels. They CANNOT be derelicted under ZGB Art. 666 and are therefore
# never privately claimable as herrenlos, even if the Grundbuch entry is empty.

_SDR_KEYWORDS: list[str] = [
    "sdr",
    "selbständiges und dauerndes recht",
    "selbstandiges und dauerndes recht",
    "baurecht",
    "quellenrecht",
    "quellenbenützungsrecht",
    "droit distinct et permanent",
    "ddp",
    "droit de superficie",
    "diritto distinto e permanente",
    "ddp",
]


# ── Per-canton claim_possible mapping ────────────────────────────────────────
#
# Legal research completed 2026-05.  Applies to Type A parcels (dereliktion):
# parcel IS in Grundbuch but owner has been deleted / Verzichtserklärung filed.
#
#   1    = private appropriation (Aneignung) permitted — file Aneignungserklärung
#          with Grundbuchamt, no purchase price, only land-registry fees
#   0    = canton or municipality acquires automatically; private claims blocked
#   None = insufficient research; treat as unknown
#
# Type B (not_in_grundbuch / Art. 664 ZGB) is NEVER privately claimable —
# see claim_possible_for() below.
#
# Sources per canton:
#   UR  Regierungsrat Anfrage 2025; no EG ZGB restriction found
#   SZ  Kantonsrat Antwort 2023; no EG ZGB restriction found (confirmed open)
#   ZG  KA Gössi 2018; no EG ZGB restriction; also confirmed by ZG Grundbuchamt
#   AG  Anfrage Landwirtschafts-Departement 2024; no legislative change
#   ZH  No EG ZGB restriction identified in ZH EG ZGB (§ 74–76); open default
#   LU  Confirmed open (no restriction); scanner not built (SMS-gated portal)
#   BE  Art. 77 EG ZGB BE: cantonal permit required, but appropriation possible
#       (Art. 75a revision not yet in force as of 2026-05)
#   BS  §§ 49–52 EG ZGB BS: automatic cantonal acquisition; private blocked
#   FR  Art. 111–113 EG ZGB FR: automatic cantonal acquisition; private blocked
#   GL  Art. 5 EG ZGB GL: automatic cantonal/municipal acquisition; private blocked
#   VS  Art. 162 EGZGB VS: municipality has pre-emptive priority right;
#       private claims effectively blocked in practice → treated as 0
#   VD  Art. 131 CDPJ VD (EG ZGB VD): municipal priority right;
#       private claims effectively blocked in practice → treated as 0
#   GE  No distinct EG ZGB restriction found, but GE communal practice
#       is for the commune to acquire; unclear → None pending verification
#   All others: insufficient research → None

CANTON_CLAIM_POSSIBLE: dict[str, int | None] = {
    "UR": 1,    # confirmed open — private Aneignung permitted
    "SZ": 1,    # confirmed open — Schwyz Kantonsrat 2023
    "ZG": 1,    # confirmed open — KA Gössi 2018
    "AG": 1,    # confirmed open — no legislative restriction
    "ZH": 1,    # no EG ZGB restriction identified
    "LU": 1,    # confirmed open (portal not built — SMS-gated)
    "BE": 1,    # cantonal permit required (Art. 77 EG ZGB BE); Art. 75a not yet in force
    "BS": 0,    # automatic cantonal acquisition (§§ 49–52 EG ZGB BS)
    "FR": 0,    # automatic cantonal acquisition (Art. 111–113 EG ZGB FR)
    "GL": 0,    # automatic cantonal/municipal acquisition (Art. 5 EG ZGB GL)
    "VS": 0,    # municipal pre-emptive priority (Art. 162 EGZGB VS); private blocked in practice
    "VD": 0,    # municipal priority right (Art. 131 CDPJ VD); private blocked in practice
    "OW": None,
    "NW": None,
    "SO": None,
    "BL": None,
    "SH": None,
    "AR": None,
    "AI": None,
    "SG": None,
    "GR": None,
    "TG": None,
    "TI": None,
    "NE": None,
    "GE": None,
    "JU": None,
}


def claim_possible_for(canton: str, herrenlos_type: str | None) -> int | None:
    """
    Return claim_possible flag (1/0/None) for a parcel given canton and type.

    Type B (not_in_grundbuch): NEVER privately claimable.
        Art. 664 ZGB — unregistered land under cantonal Hoheit.
        Even where private Aneignung is nominally open, Art. 664 Abs. 3
        requires cantonal EG ZGB to authorise it, and almost no canton does.

    Type A (dereliktion / no_owner): depends on cantonal EG ZGB.
        See CANTON_CLAIM_POSSIBLE for per-canton research results.

    SDR/Baurecht: always 0 — BGE 118 II 115.
        Call is_sdr_parcel() before calling this function and skip if True.
    """
    if herrenlos_type in ("not_in_grundbuch", "art664"):
        return 0
    return CANTON_CLAIM_POSSIBLE.get(canton.upper())


# ── Public API ────────────────────────────────────────────────────────────────

def page_text_contains_herrenlos(text: str) -> bool:
    """
    Return True if a full Grundbuch portal page text contains an explicit
    herrenlos indicator anywhere on the page (status badges, section headers,
    result messages, etc.).

    Use this for HTML-scraping scanners (ZG, GE, BL, SZ) that search the
    full rendered page rather than just the owner field value.

    Uses _HERRENLOS_PAGE_PATTERNS (not _HERRENLOS_PATTERNS) to exclude patterns
    that produce false positives in general text: bare "vakant" (matches German
    HR job-vacancy text) and bare "abbandonato/a" (matches Italian building
    descriptions).  These are safe only in the narrower owner-field context.
    """
    t = text.lower()
    # Phrases specific enough to be safe as substring matches in full page text
    safe_substrings = {
        "herrenlos",        # will also catch "herrenlose", "herrenloses" etc. as substrings
        "ohne eigentümer", "kein eigentümer", "eigentümer fehlt", "keine eigentümerschaft",
        "dereliktion", "déreliction",
        "sans propriétaire", "aucun propriétaire", "pas de propriétaire",
        "sans maître", "biens sans maître",
        "bien vacant", "biens vacants",
        "propriété vacante", "propriétés vacantes",
        "immeuble vacant", "immeubles vacants",
        "senza proprietario", "senza padrone",
        "bene vacante", "beni vacanti",
        "privo di proprietario",
    }
    for phrase in safe_substrings:
        if phrase in t:
            return True
    for pat in _HERRENLOS_PAGE_PATTERNS:
        if pat.search(text):
            return True
    return False


def is_herrenlos_owner_text(text: str) -> bool:
    """
    Return True if *text* (an owner field value from a Grundbuch portal)
    indicates the parcel is ownerless rather than being a real owner name.

    Handles German, French, and Italian variants used by Swiss cantonal portals.
    Does NOT return True for "owner unknown" strings — use is_unknown_owner()
    to detect those separately (BGE 114 II 318: unknown ≠ herrenlos).
    """
    t = text.strip().lower()
    if not t:
        return False
    if t in _HERRENLOS_EXACT:
        return True
    for pat in _HERRENLOS_PATTERNS:
        if pat.search(t):
            return True
    return False


def is_unknown_owner(text: str) -> bool:
    """
    Return True if *text* indicates the owner is unknown/unidentified.

    BGE 114 II 318: "Eigentümer unbekannt" is NOT herrenlos.
    Ownership exists; only 30-year Ersitzung (Art. 662 ZGB) can extinguish it.
    Scanners must classify these as is_herrenlos=0 (not herrenlos).
    """
    t = text.strip().lower()
    if not t:
        return False
    if t in _UNKNOWN_OWNER_EXACT:
        return True
    for pat in _UNKNOWN_OWNER_PATTERNS:
        if pat.search(t):
            return True
    return False


def is_public_owner(name: str) -> bool:
    """
    Return True if *name* indicates a public-law body (Kanton, Gemeinde,
    Bund, Korporation, Alp, etc.) that cannot hold herrenlos property.

    Parcels with public-body owners should be classified is_herrenlos=0.
    """
    t = name.strip().lower()
    if not t:
        return False
    if t in _PUBLIC_OWNER_EXACT:
        return True
    for pat in _PUBLIC_OWNER_PATTERNS:
        if pat.search(name):
            return True
    return False


def is_sdr_parcel(parcel_type: str | None) -> bool:
    """
    Return True if *parcel_type* indicates an SDR or Baurecht.

    BGE 118 II 115: SDR/Baurecht are dingliche Rechte, not corporeal land
    parcels — they cannot be derelicted under ZGB Art. 666 and are therefore
    never herrenlos in the Aneignung sense.  Scanners should skip or annotate
    these parcels rather than flagging them as herrenlos.
    """
    if not parcel_type:
        return False
    t = parcel_type.strip().lower()
    return any(kw in t for kw in _SDR_KEYWORDS)


def annotate_herrenlos(result: dict, canton: str) -> dict:
    """
    Fill in herrenlos_type and claim_possible in a check_owner result dict
    if the caller didn't already set them.

    Call this in every scanner's scan() loop after check_owner() returns.
    It is idempotent — scanners that already set these fields are unaffected.

    Rules applied:
      is_herrenlos=1  → default herrenlos_type="dereliktion" if not set;
                         fill claim_possible from CANTON_CLAIM_POSSIBLE
      is_herrenlos=0  → ensure herrenlos_type and claim_possible are None
      is_herrenlos=None → no change (error / not scanned)
    """
    is_h = result.get("is_herrenlos")
    if is_h == 1:
        ht = result.get("herrenlos_type") or "dereliktion"
        result["herrenlos_type"] = ht
        if result.get("claim_possible") is None:
            result["claim_possible"] = claim_possible_for(canton, ht)
    elif is_h == 0:
        result.setdefault("herrenlos_type", None)
        result.setdefault("claim_possible", None)
    return result
