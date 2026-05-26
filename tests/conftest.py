"""Shared pytest fixtures."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sentinel_ml.data.schemas import UploadRecord


@pytest.fixture
def sample_upload_record() -> UploadRecord:
    return UploadRecord(
        sha256="a" * 64,
        filename="report.pdf",
        content_type="application/pdf",
        size_bytes=12345,
        scan_status="clean",
        decision="accepted",
        risk_score=10,
        created_at=datetime.now(UTC),
    )


@pytest.fixture
def threat_text_sample() -> str:
    return (
        "Observed C2 traffic to 8.8.8.8 and evil-domain.example, "
        "with payload SHA-256 "
        + "b" * 64
        + ". Affected by CVE-2024-12345. "
        "Reach out to reporter@example.com for details. "
        "More at https://example.com/report?id=42"
    )
