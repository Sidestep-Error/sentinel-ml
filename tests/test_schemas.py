"""Tests for data/schemas.py — covers backward-compatible UploadRecord parsing."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from sentinel_ml.data.schemas import UploadRecord


def test_upload_record_parses_full_upstream_document():
    """Document shape matches current upstream UploadRecord exactly."""
    doc = {
        "created_at": datetime.now(UTC),
        "filename": "report.pdf",
        "sha256": "a" * 64,
        "content_type": "application/pdf",
        "size_bytes": 12345,
        "status": "accepted",
        "decision": "accepted",
        "risk_score": 10,
        "risk_reasons": ["No malicious signature detected"],
        "scan_status": "clean",
        "scan_engine": "clamav",
        "scan_detail": "OK",
        "deduplicated": False,
    }
    record = UploadRecord.model_validate(doc)
    assert record.size_bytes == 12345
    assert record.scan_engine == "clamav"
    assert record.risk_reasons == ["No malicious signature detected"]
    assert record.deduplicated is False


def test_upload_record_parses_legacy_document_without_size_bytes():
    """Older documents predating upstream PR #68 lack size_bytes — must still validate."""
    doc = {
        "created_at": datetime.now(UTC),
        "filename": "old.txt",
        "sha256": "b" * 64,
        "content_type": "text/plain",
        # no size_bytes
        "status": "accepted",
        "decision": "accepted",
        "risk_score": 0,
        "risk_reasons": [],
        "scan_status": "clean",
        "scan_engine": "mock",
        "scan_detail": "",
        "deduplicated": False,
    }
    record = UploadRecord.model_validate(doc)
    assert record.size_bytes is None
    assert record.scan_status == "clean"


def test_upload_record_parses_minimal_document():
    """Ancient documents may lack everything except the required identifiers."""
    doc = {
        "filename": "ancient.txt",
        "sha256": "c" * 64,
        "content_type": "text/plain",
    }
    record = UploadRecord.model_validate(doc)
    assert record.size_bytes is None
    assert record.status == "accepted"
    assert record.risk_score == 0
    assert record.risk_reasons == []
    assert record.deduplicated is False


def test_upload_record_rejects_invalid_risk_score():
    doc = {
        "filename": "x.txt",
        "sha256": "d" * 64,
        "content_type": "text/plain",
        "risk_score": 999,
    }
    with pytest.raises(ValidationError):
        UploadRecord.model_validate(doc)


def test_upload_record_rejects_negative_size_bytes():
    doc = {
        "filename": "x.txt",
        "sha256": "e" * 64,
        "content_type": "text/plain",
        "size_bytes": -1,
    }
    with pytest.raises(ValidationError):
        UploadRecord.model_validate(doc)
