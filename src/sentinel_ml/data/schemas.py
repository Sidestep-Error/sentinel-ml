"""Pydantic schemas shared across the package.

These are the canonical shapes for threat reports, IOCs, and upload records.
External I/O (Mongo, files) must convert into these shapes before being
passed to features or models.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class IOCType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "md5"
    HASH_SHA1 = "sha1"
    HASH_SHA256 = "sha256"
    CVE = "cve"
    EMAIL = "email"


class IOC(BaseModel):
    """Single indicator extracted from text."""

    type: IOCType
    value: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source_offset: int | None = None


class ThreatReport(BaseModel):
    """A single threat-intel report or document used as training/inference input."""

    report_id: str
    text: str
    source: str | None = None
    published_at: datetime | None = None
    labels: list[str] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)


class MalwareSample(BaseModel):
    """Metadata record for malware-family modeling (Spår C).

    The shape mirrors generated/downloaded MalwareBazaar-style JSONL rows.
    """

    sha256: str
    file_name: str | None = None
    file_size: int = Field(default=0, ge=0)
    file_type: str | None = None
    file_type_mime: str | None = None
    signature: str | None = None
    tags: list[str] = Field(default_factory=list)
    imphash: str | None = None
    first_seen: str | None = None
    family: str | None = None


class UploadRecord(BaseModel):
    """Projection of sentinel-upload-api's `uploads` collection.

    Field shapes verified 2026-06-02 against upstream `app/models.py`
    after PR #68. All fields default to sensible empties so documents
    that predate a field (e.g. pre-PR-#68 records without `size_bytes`)
    still validate.
    """

    model_config = {"populate_by_name": True}

    filename: str
    content_type: str
    size_bytes: int | None = Field(default=None, ge=0)
    scan_status: str = "clean"  # "clean" | "malicious" | "error"
    decision: str = "accepted"  # "accepted" | "review" | "rejected"
    risk_score: int = Field(default=0, ge=0, le=100)
    created_at: datetime | None = None
    # Upstream fields previously not modeled in sentinel-ml.
    status: str = "accepted"  # "accepted" | "rejected"
    risk_reasons: list[str] = Field(default_factory=list)
    scan_engine: str = "unknown"
    scan_detail: str = ""
    deduplicated: bool = False


class Prediction(BaseModel):
    """Generic prediction envelope returned by all estimators."""

    label: str
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: dict[str, float] | None = None
