"""Hash-bridge: match an upload's sha256 against known-malicious file hashes.

This is the link between threat intelligence and the upload-scanning path: if
an uploaded file's sha256 is already known to be malicious (seen as a hash IOC
in threat reports / feeds), we can flag it directly — independent of, and
complementary to, both ClamAV and the metadata classifier.

Pure functions only. The known-hash set is built from threat reports here and
held by the service layer; matching is a cheap set membership test.
"""

from __future__ import annotations

from collections.abc import Iterable

from sentinel_ml.data.schemas import IOCType, MalwareSample, ThreatReport
from sentinel_ml.features.ioc_extract import extract_iocs

# md5 / sha1 / sha256 hex lengths.
_HEX_HASH_LENGTHS = {32, 40, 64}
_HEX_CHARS = set("0123456789abcdef")
_HASH_IOC_TYPES = {IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256}


def normalize_hash(value: str) -> str:
    return value.strip().lower()


def build_hash_set(hashes: Iterable[str]) -> set[str]:
    """Normalize and keep only valid hex file hashes (md5/sha1/sha256)."""
    out: set[str] = set()
    for h in hashes:
        if not h:
            continue
        n = normalize_hash(h)
        if len(n) in _HEX_HASH_LENGTHS and set(n) <= _HEX_CHARS:
            out.add(n)
    return out


def collect_hashes_from_reports(reports: Iterable[ThreatReport]) -> set[str]:
    """Build a known-malicious hash set from threat reports.

    Collects hash IOCs both from each report's structured ``iocs`` and from
    regex extraction over its free text, then normalizes them into a set.
    """
    raw: list[str] = []
    for report in reports:
        raw.extend(ioc.value for ioc in report.iocs if ioc.type in _HASH_IOC_TYPES)
        raw.extend(ioc.value for ioc in extract_iocs(report.text) if ioc.type in _HASH_IOC_TYPES)
    return build_hash_set(raw)


def collect_hashes_from_malware_samples(samples: Iterable[MalwareSample]) -> set[str]:
    """Build a known-malicious hash set from malware-sample metadata.

    Every sample row (e.g. MalwareBazaar JSONL) carries the sha256 of a file
    that is malicious by definition — no IOC extraction needed.
    """
    return build_hash_set(s.sha256 for s in samples)


def match_upload_hash(sha256: str | None, known: set[str]) -> bool:
    """True when the upload's sha256 is present in the known-malicious set."""
    if not sha256:
        return False
    return normalize_hash(sha256) in known
