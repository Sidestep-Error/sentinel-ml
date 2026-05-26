"""IOC extraction from free-text threat reports.

Baseline implementation: regex-based. Replace or augment with spaCy NER /
LLM-based extraction in Fas 2 — but the regex baseline must keep working
because (a) it's cheap, (b) it has zero attack surface (no model to poison),
and (c) it gives us a measurable floor to beat.
"""

from __future__ import annotations

import re

from sentinel_ml.data.schemas import IOC, IOCType

# IPv4 — non-greedy match against octets 0-255. The full regex would be huge,
# so we accept a permissive form and validate numerically below.
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Domain — at least one dot, TLD 2-24 chars. Excludes IPs.
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)

# Hashes — distinguished by length.
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

# CVE — fixed format CVE-YYYY-NNNN+
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# URL — http(s) plus path
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

# Email
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")


def _is_valid_ipv4(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def extract_iocs(text: str) -> list[IOC]:
    """Extract all IOCs from a single piece of text.

    Order: more specific patterns first (hashes, CVE, URL), then IPs, then
    domains. The deduplication step at the end removes overlaps when e.g.
    a URL string also matches the domain regex.
    """
    iocs: list[IOC] = []
    seen: set[tuple[IOCType, str]] = set()

    def _add(t: IOCType, val: str, offset: int | None = None) -> None:
        key = (t, val.lower())
        if key in seen:
            return
        seen.add(key)
        iocs.append(IOC(type=t, value=val, source_offset=offset))

    for m in _SHA256_RE.finditer(text):
        _add(IOCType.HASH_SHA256, m.group(), m.start())
    for m in _SHA1_RE.finditer(text):
        # Skip if already captured as part of a SHA-256 (shouldn't happen via word boundary, but cheap)
        _add(IOCType.HASH_SHA1, m.group(), m.start())
    for m in _MD5_RE.finditer(text):
        _add(IOCType.HASH_MD5, m.group(), m.start())
    for m in _CVE_RE.finditer(text):
        _add(IOCType.CVE, m.group().upper(), m.start())
    for m in _URL_RE.finditer(text):
        _add(IOCType.URL, m.group().rstrip(".,;"), m.start())
    for m in _EMAIL_RE.finditer(text):
        _add(IOCType.EMAIL, m.group(), m.start())
    for m in _IPV4_RE.finditer(text):
        candidate = m.group()
        if _is_valid_ipv4(candidate):
            _add(IOCType.IP, candidate, m.start())
    for m in _DOMAIN_RE.finditer(text):
        candidate = m.group()
        # Filter out matches that are part of an already-captured URL or email
        # by ignoring the domain part of those (heuristic, good enough for baseline).
        if any(candidate in existing for t, existing in seen if t in (IOCType.URL, IOCType.EMAIL)):
            continue
        # Filter out pure-numeric "domains" (these are usually IP fragments).
        if candidate.replace(".", "").isdigit():
            continue
        _add(IOCType.DOMAIN, candidate.lower(), m.start())

    return iocs
