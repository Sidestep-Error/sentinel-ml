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


class UploadRecord(BaseModel):
    """Minimal projection of sentinel-upload-api's `uploads` collection."""

    model_config = {"populate_by_name": True}

    filename: str
    content_type: str
    sha256: str | None = None
    size_bytes: int | None = None
    scan_status: str | None = None  # "clean" | "malicious" | "error"
    decision: str | None = Field(default=None, alias="status")  # "accepted" | "review" | "rejected"
    risk_score: int | None = Field(default=None, ge=0, le=100)
    created_at: datetime | None = None


class Prediction(BaseModel):
    """Generic prediction envelope returned by all estimators."""

    label: str
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: dict[str, float] | None = None
