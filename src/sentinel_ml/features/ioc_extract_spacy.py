"""spaCy-based IOC extraction — Fas 2 alternative to regex baseline.

Combines two layers:
  1. EntityRuler  — pattern-based rules for structured IOCs (IP, CVE, hash, URL, email).
                    Same coverage as regex but integrated in the spaCy pipeline.
  2. Pre-trained NER — en_core_web_sm detects PRODUCT/ORG/PERSON entities that
                       regex cannot find: malware family names, threat-actor groups,
                       software tools mentioned by name.

Use extract_iocs_spacy() as a drop-in complement to the regex extractor.
"""

from __future__ import annotations

from functools import lru_cache

import spacy
from spacy.language import Language
from spacy.tokens import Doc

from sentinel_ml.data.schemas import IOC, IOCType

# ── known threat actor aliases (APT groups, criminal crews) ─────────────────
# Source: MITRE ATT&CK + public threat intelligence reports
_THREAT_ACTORS: list[str] = [
    # Russian
    "Fancy Bear", "APT28", "Sofacy", "Pawn Storm", "Strontium", "Sednit",
    "Cozy Bear", "APT29", "The Dukes", "Midnight Blizzard", "Nobelium",
    "Sandworm", "Voodoo Bear", "TeleBots", "BlackEnergy",
    "Turla", "Snake", "Venomous Bear", "Waterbug",
    "Gamaredon", "Primitive Bear",
    # Chinese
    "APT1", "Comment Crew", "Comment Group",
    "APT10", "Stone Panda", "MenuPass",
    "APT40", "Bronze Mohawk", "Leviathan",
    "APT41", "Winnti", "Barium", "Double Dragon",
    "Volt Typhoon", "Bronze Silhouette",
    "Salt Typhoon",
    # North Korean
    "Lazarus Group", "Hidden Cobra", "Zinc", "Nickel Academy",
    "Kimsuky", "Velvet Chollima",
    "APT38", "Bluenoroff",
    # Iranian
    "APT33", "Elfin", "Refined Kitten", "Magnallium",
    "APT34", "OilRig", "Helix Kitten",
    "APT35", "Charming Kitten", "Phosphorus", "Mint Sandstorm",
    "Muddy Water", "MuddyWater", "Static Kitten",
    # Criminal / ransomware groups
    "LockBit", "Conti", "REvil", "DarkSide", "BlackCat", "ALPHV",
    "Cl0p", "Clop", "TA505",
    "Lazarus", "FIN7", "FIN8",
    "Scattered Spider", "UNC3944",
]

# Build EntityRuler phrase patterns for all aliases
_THREAT_ACTOR_PATTERNS = [
    {"label": "THREAT_ACTOR", "pattern": alias} for alias in _THREAT_ACTORS
]

# ── regex patterns reused as EntityRuler specs ──────────────────────────────
_IPV4_PAT   = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
_SHA256_PAT = r"\b[a-fA-F0-9]{64}\b"
_SHA1_PAT   = r"\b[a-fA-F0-9]{40}\b"
_MD5_PAT    = r"\b[a-fA-F0-9]{32}\b"
_CVE_PAT    = r"\bCVE-\d{4}-\d{4,7}\b"
_URL_PAT    = r"https?://[^\s\"'<>]+"
_EMAIL_PAT  = r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"

_RULER_PATTERNS = [
    {"label": "IOC_SHA256", "pattern": [{"TEXT": {"REGEX": _SHA256_PAT}}]},
    {"label": "IOC_SHA1",   "pattern": [{"TEXT": {"REGEX": _SHA1_PAT}}]},
    {"label": "IOC_MD5",    "pattern": [{"TEXT": {"REGEX": _MD5_PAT}}]},
    {"label": "IOC_CVE",    "pattern": [{"TEXT": {"REGEX": _CVE_PAT}}]},
    {"label": "IOC_IP",     "pattern": [{"TEXT": {"REGEX": _IPV4_PAT}}]},
    {"label": "IOC_URL",    "pattern": [{"TEXT": {"REGEX": _URL_PAT}}]},
    {"label": "IOC_EMAIL",  "pattern": [{"TEXT": {"REGEX": _EMAIL_PAT}}]},
]

# spaCy NER labels that may represent threat-relevant named entities
_NER_TO_IOC: dict[str, IOCType] = {
    "PRODUCT": IOCType.DOMAIN,   # malware/software names mapped to DOMAIN as best-fit
}
# Labels we treat as threat actor / malware mentions (stored with confidence < 1.0)
_THREAT_ACTOR_LABELS = {"ORG", "PERSON", "PRODUCT"}


@lru_cache(maxsize=1)
def _load_nlp() -> Language:
    nlp = spacy.load("en_core_web_sm", disable=["parser", "lemmatizer"])
    ruler = nlp.add_pipe("entity_ruler", before="ner")
    ruler.add_patterns(_RULER_PATTERNS + _THREAT_ACTOR_PATTERNS)  # type: ignore[arg-type]
    return nlp


def _is_valid_ipv4(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


_LABEL_MAP: dict[str, IOCType] = {
    "IOC_SHA256": IOCType.HASH_SHA256,
    "IOC_SHA1":   IOCType.HASH_SHA1,
    "IOC_MD5":    IOCType.HASH_MD5,
    "IOC_CVE":    IOCType.CVE,
    "IOC_IP":     IOCType.IP,
    "IOC_URL":    IOCType.URL,
    "IOC_EMAIL":  IOCType.EMAIL,
}


def extract_iocs_spacy(text: str, *, include_named_entities: bool = True) -> list[IOC]:
    """Extract IOCs using spaCy pipeline.

    Args:
        text: Raw threat-report text.
        include_named_entities: If True, also return PRODUCT/ORG/PERSON entities
            as low-confidence IOCs (malware names, threat actors, tools).
    """
    nlp = _load_nlp()
    doc: Doc = nlp(text)

    iocs: list[IOC] = []
    seen: set[tuple[IOCType, str]] = set()

    def _add(t: IOCType, val: str, offset: int, confidence: float = 1.0) -> None:
        key = (t, val.lower())
        if key in seen:
            return
        seen.add(key)
        iocs.append(IOC(type=t, value=val, confidence=confidence, source_offset=offset))

    for ent in doc.ents:
        ioc_type = _LABEL_MAP.get(ent.label_)
        if ioc_type is not None:
            val = ent.text.strip()
            if ioc_type == IOCType.IP and not _is_valid_ipv4(val):
                continue
            if ioc_type == IOCType.CVE:
                val = val.upper()
            elif ioc_type == IOCType.URL:
                val = val.rstrip(".,;")
            _add(ioc_type, val, ent.start_char)

        elif ent.label_ == "THREAT_ACTOR":
            # Known APT group / criminal crew — high confidence since it's a curated list.
            _add(IOCType.DOMAIN, ent.text.strip().lower(), ent.start_char, confidence=0.9)

        elif include_named_entities and ent.label_ in _THREAT_ACTOR_LABELS:
            # Other malware / tool names detected by NER — lower confidence.
            _add(IOCType.DOMAIN, ent.text.strip().lower(), ent.start_char, confidence=0.5)

    return iocs


def compare_extractors(text: str) -> dict[str, list[IOC]]:
    """Run both extractors on the same text. Returns dict with 'regex' and 'spacy' keys."""
    from sentinel_ml.features.ioc_extract import extract_iocs as regex_extract
    return {
        "regex": regex_extract(text),
        "spacy": extract_iocs_spacy(text),
    }
