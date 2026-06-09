"""Tests for the hash-bridge: upload sha256 vs a known-malicious hash set."""

from __future__ import annotations

from fastapi.testclient import TestClient

from sentinel_ml.data.schemas import IOC, IOCType, ThreatReport
from sentinel_ml.features.hash_match import (
    build_hash_set,
    collect_hashes_from_reports,
    match_upload_hash,
    normalize_hash,
)
from sentinel_ml.service.api import create_app

SHA = "a" * 64
MD5 = "b" * 32


def test_normalize_hash_trims_and_lowercases():
    assert normalize_hash("  ABCdef  ") == "abcdef"


def test_build_hash_set_filters_invalid_and_normalizes():
    s = build_hash_set([SHA.upper(), "not-a-hash", "", MD5, "123", None])  # type: ignore[list-item]
    assert SHA in s
    assert MD5 in s
    assert "not-a-hash" not in s
    assert all(len(h) in (32, 40, 64) for h in s)


def test_collect_hashes_from_reports_uses_iocs_and_text():
    reports = [
        ThreatReport(report_id="r1", text=f"observed file {SHA} dropped by loader"),
        ThreatReport(
            report_id="r2",
            text="no hashes in this body",
            iocs=[IOC(type=IOCType.HASH_MD5, value=MD5.upper())],
        ),
    ]
    s = collect_hashes_from_reports(reports)
    assert SHA in s  # extracted from free text
    assert MD5 in s  # from structured iocs, normalized to lowercase


def test_match_upload_hash():
    known = {SHA}
    assert match_upload_hash(SHA.upper(), known) is True  # case-insensitive
    assert match_upload_hash("c" * 64, known) is False
    assert match_upload_hash(None, known) is False


def _client_with_hashes(hashes: set[str]) -> TestClient:
    # No `with` block => lifespan does not run, so the injected state persists.
    app = create_app()
    app.state.malicious_hashes = set(hashes)
    return TestClient(app)


def _ingest_payload(sha: str) -> dict:
    return {
        "upload_id": "u1",
        "filename": "x.bin",
        "content_type": "application/octet-stream",
        "sha256": sha,
        "scan_status": "clean",
    }


def test_upload_ingest_flags_known_malicious_hash():
    client = _client_with_hashes({SHA})
    r = client.post("/predict/upload-ingest", json=_ingest_payload(SHA.upper()))
    assert r.status_code == 200
    assert r.json()["known_malicious"] is True


def test_upload_ingest_unknown_hash_not_flagged():
    client = _client_with_hashes({SHA})
    r = client.post("/predict/upload-ingest", json=_ingest_payload("c" * 64))
    assert r.status_code == 200
    assert r.json()["known_malicious"] is False


def test_liveflow_summary_reflects_known_malicious_hash():
    client = _client_with_hashes({SHA})
    r = client.post("/predict/liveflow", json={"upload": _ingest_payload(SHA)})
    assert r.status_code == 200
    body = r.json()
    assert body["upload_result"]["known_malicious"] is True
    assert body["summary"]["known_malicious_hash"] is True
