"""Tests for the hash-bridge: upload sha256 vs a known-malicious hash set."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from sentinel_ml.data.loaders import load_malware_samples_jsonl
from sentinel_ml.data.schemas import IOC, IOCType, MalwareSample, ThreatReport
from sentinel_ml.features.hash_match import (
    build_hash_set,
    collect_hashes_from_malware_samples,
    collect_hashes_from_reports,
    match_upload_hash,
    normalize_hash,
)
from sentinel_ml.service.api import _load_malicious_hashes, create_app

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


def test_collect_hashes_from_malware_samples_normalizes():
    samples = [
        MalwareSample(sha256=SHA.upper()),
        MalwareSample(sha256="not-a-hash"),
    ]
    s = collect_hashes_from_malware_samples(samples)
    assert s == {SHA}


def test_load_malware_samples_jsonl_skips_malformed(tmp_path):
    p = tmp_path / "samples.jsonl"
    rows = [
        json.dumps({"sha256": SHA, "family": "Emotet"}),
        "{broken json",
        "",
        json.dumps({"sha256": "d" * 64}),
    ]
    p.write_text("\n".join(rows), encoding="utf-8")
    samples = list(load_malware_samples_jsonl(p))
    assert [s.sha256 for s in samples] == [SHA, "d" * 64]


def test_load_malicious_hashes_unions_both_sources(tmp_path):
    reports = tmp_path / "reports.jsonl"
    reports.write_text(
        json.dumps({"report_id": "r1", "text": f"dropper hash {'c' * 64} seen"}) + "\n",
        encoding="utf-8",
    )
    samples = tmp_path / "samples.jsonl"
    samples.write_text(json.dumps({"sha256": SHA}) + "\n", encoding="utf-8")

    hashes = _load_malicious_hashes(reports, samples)
    assert SHA in hashes  # from malware samples
    assert "c" * 64 in hashes  # from threat reports


def test_load_malicious_hashes_missing_sources_degrade(tmp_path):
    assert _load_malicious_hashes(None, None) == set()
    assert _load_malicious_hashes(tmp_path / "nope.jsonl", tmp_path / "nada.jsonl") == set()


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
