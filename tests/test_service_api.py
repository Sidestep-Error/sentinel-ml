"""Tests for the FastAPI service.

Covers both the fallback path (no trained artifact on disk) and the
happy path (lifespan loads a real joblib from a tmp models dir).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from sentinel_ml.data.schemas import UploadRecord
from sentinel_ml.features.upload_meta import build_feature_matrix
from sentinel_ml.models import threat_classifier, upload_classifier
from sentinel_ml.service import api as service_api
from sentinel_ml.service.api import app, create_app

# Module-level client uses the package's `app`, which was created without a
# trained artifact present. Lifespan is not triggered (no `with` block) so
# endpoints exercise the defensive getattr fallback in `_get_loaded`.
client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_predict_threat_returns_iocs():
    response = client.post(
        "/predict/threat",
        json={"text": "Reach IP 1.2.3.4 and CVE-2024-99999."},
    )
    assert response.status_code == 200
    payload = response.json()
    ioc_values = {i["value"] for i in payload["iocs"]}
    assert "1.2.3.4" in ioc_values
    assert "CVE-2024-99999" in ioc_values


def test_predict_threat_fallback_shape_when_no_model():
    response = client.post("/predict/threat", json={"text": "nothing here"})
    payload = response.json()
    assert payload["prediction"]["label"] == "unknown"
    assert payload["prediction"]["confidence"] == 0.0
    assert payload["model_version"] == "none"


def test_predict_upload_fallback_shape_when_no_model(sample_upload_record: UploadRecord):
    response = client.post(
        "/predict/upload",
        json=sample_upload_record.model_dump(mode="json"),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["prediction"]["label"] == "unknown"
    assert payload["prediction"]["confidence"] == 0.0
    assert payload["model_version"] == "none"


def test_predict_upload_ingest_fallback_shape_when_no_model():
    response = client.post(
        "/predict/upload-ingest",
        json={
            "upload_id": "upload-123",
            "filename": "invoice.eml",
            "content_type": "message/rfc822",
            "size_bytes": 58213,
            "scan_status": "malicious",
            "scan_engine": "clamav",
            "scan_detail": "Phishing.Email.Generic",
            "risk_score": 78,
            "source": "upload",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["upload_id"] == "upload-123"
    assert payload["source"] == "upload"
    assert payload["prediction"]["label"] == "unknown"
    assert payload["prediction"]["confidence"] == 0.0
    assert payload["model_version"] == "none"


def _make_upload_record(scan_status: str, filename: str, size: int) -> UploadRecord:
    return UploadRecord(
        sha256="a" * 64,
        filename=filename,
        content_type="application/pdf",
        size_bytes=size,
        scan_status=scan_status,
        decision="accepted",
        risk_score=10,
        created_at=datetime.now(UTC),
    )


@pytest.fixture
def app_with_models(tmp_path, monkeypatch):
    """Train tiny models, save them to a tmp dir, and return a fresh app."""
    models_dir = tmp_path / "models"
    models_dir.mkdir()

    # Threat classifier — two classes, enough samples for ngram_range/min_df=2.
    threat_texts = [
        "ransomware encrypts files on the host and leaves a readme",
        "another ransomware sample drops payload and encrypts data",
        "phishing email impersonates a bank and harvests credentials",
        "phishing campaign with credential harvesting login form",
    ]
    threat_labels = ["ransomware", "ransomware", "phishing", "phishing"]
    pipe = threat_classifier.train(threat_texts, threat_labels)
    threat_classifier.save(pipe, models_dir / "threat_classifier.joblib")

    # Upload classifier — two classes, two samples.
    records = [
        _make_upload_record("clean", "report.pdf", 1000),
        _make_upload_record("malicious", "invoice_2024_final_v3.pdf", 5_000_000),
    ]
    features, _ = build_feature_matrix(records)
    model = upload_classifier.train(features, ["clean", "malicious"])
    upload_classifier.save(model, models_dir / "upload_classifier.joblib")

    monkeypatch.setenv("MODELS_DIR", str(models_dir))
    return create_app()


def test_predict_threat_uses_loaded_model(app_with_models):
    with TestClient(app_with_models) as c:
        response = c.post(
            "/predict/threat",
            json={"text": "ransomware on host with payload"},
        )
    assert response.status_code == 200
    payload = response.json()
    assert payload["prediction"]["label"] in {"ransomware", "phishing"}
    assert 0.0 <= payload["prediction"]["confidence"] <= 1.0
    assert payload["model_version"] != "none"
    assert len(payload["model_version"]) == 12


def test_predict_upload_uses_loaded_model(
    app_with_models, sample_upload_record: UploadRecord
):
    with TestClient(app_with_models) as c:
        response = c.post(
            "/predict/upload",
            json=sample_upload_record.model_dump(mode="json"),
        )
    assert response.status_code == 200
    payload = response.json()
    assert payload["prediction"]["label"] in {"clean", "malicious"}
    assert 0.0 <= payload["prediction"]["confidence"] <= 1.0
    assert payload["model_version"] != "none"
    assert len(payload["model_version"]) == 12


def test_predict_upload_ingest_uses_loaded_model(app_with_models):
    with TestClient(app_with_models) as c:
        response = c.post(
            "/predict/upload-ingest",
            json={
                "upload_id": "upload-123",
                "filename": "invoice.eml",
                "content_type": "message/rfc822",
                "size_bytes": 58213,
                "scan_status": "malicious",
                "scan_engine": "clamav",
                "scan_detail": "Phishing.Email.Generic",
                "risk_score": 78,
                "source": "upload",
            },
        )
    assert response.status_code == 200
    payload = response.json()
    assert payload["upload_id"] == "upload-123"
    assert payload["source"] == "upload"
    assert payload["prediction"]["label"] in {"clean", "malicious"}
    assert 0.0 <= payload["prediction"]["confidence"] <= 1.0
    assert payload["model_version"] != "none"
    assert len(payload["model_version"]) == 12


def test_predict_cve_relevance_matches_sbom_components():
    response = client.post(
        "/predict/cve-relevance",
        json={
            "sbom_components": [
                {
                    "name": "openssl",
                    "version": "3.0.7",
                    "ecosystem": "debian",
                    "purl": "pkg:deb/debian/openssl@3.0.7",
                    "cpe": "cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*",
                }
            ],
            "cves": [
                {
                    "cve_id": "CVE-2024-12345",
                    "summary": "OpenSSL vulnerability affecting versions before 3.0.8",
                    "cvss_score": 8.8,
                    "severity": "high",
                    "affected_packages": [
                        {
                            "name": "openssl",
                            "ecosystem": "debian",
                            "fixed_version": "3.0.8",
                        }
                    ],
                }
            ],
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["total_cves"] == 1
    assert payload["summary"]["matched_cves"] == 1
    assert payload["summary"]["matched_high_or_critical"] == 1
    assert len(payload["results"]) == 1
    assert payload["results"][0]["cve_id"] == "CVE-2024-12345"
    assert payload["results"][0]["relevance_score"] > 0.0
    assert len(payload["results"][0]["matched_components"]) == 1


def test_predict_cve_relevance_prediction_returns_serializable_envelope():
    response = client.post(
        "/predict/cve-relevance-prediction",
        json={
            "sbom_components": [
                {
                    "name": "openssl",
                    "version": "3.0.7",
                    "ecosystem": "debian",
                    "purl": "pkg:deb/debian/openssl@3.0.7",
                    "cpe": "cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*",
                }
            ],
            "cves": [
                {
                    "cve_id": "CVE-2024-12345",
                    "summary": "OpenSSL vulnerability affecting versions before 3.0.8",
                    "cvss_score": 8.8,
                    "severity": "high",
                    "affected_packages": [
                        {
                            "name": "openssl",
                            "ecosystem": "debian",
                            "fixed_version": "3.0.8",
                        }
                    ],
                }
            ],
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["source"] == "deterministic"
    assert len(payload["related_cves"]) == 1
    assert payload["related_cves"][0]["cve_id"] == "CVE-2024-12345"
    assert payload["related_cves"][0]["relevance"] == "relevant"


def test_predict_cve_relevance_trivy_uses_adapter_path():
    response = client.post(
        "/predict/cve-relevance-trivy",
        json={
            "sbom_document": {
                "Results": [
                    {
                        "Packages": [
                            {
                                "PkgName": "openssl",
                                "InstalledVersion": "3.0.7",
                                "Type": "debian",
                                "PURL": "pkg:deb/debian/openssl@3.0.7",
                                "CPEs": [
                                    "cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*"
                                ],
                            }
                        ]
                    }
                ]
            },
            "vulnerability_document": {
                "Results": [
                    {
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2026-1000",
                                "PkgName": "openssl",
                                "PkgType": "debian",
                                "InstalledVersion": "3.0.7",
                                "FixedVersion": "3.0.8",
                                "Title": "OpenSSL vulnerability",
                                "Severity": "HIGH",
                                "CVSS": {"nvd": {"V3Score": 8.8}},
                            }
                        ]
                    }
                ]
            },
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["source"] == "deterministic"
    assert len(payload["related_cves"]) == 1
    assert payload["related_cves"][0]["cve_id"] == "CVE-2026-1000"
    assert payload["related_cves"][0]["relevance"] == "relevant"


def test_predict_upload_text_ingest_fallback_with_extracted_text():
    response = client.post(
        "/predict/upload-text-ingest",
        json={
            "upload_id": "upload-123",
            "filename": "invoice.eml",
            "content_type": "message/rfc822",
            "scan_status": "malicious",
            "scan_engine": "clamav",
            "scan_detail": "Phishing.Email.Generic",
            "extracted_text": "Please review and login at http://evil.example now",
            "source": "upload_text",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["upload_id"] == "upload-123"
    assert payload["source"] == "upload_text"
    assert payload["prediction"]["label"] == "unknown"
    assert payload["model_version"] == "none"
    assert payload["text_truncated"] is False
    assert "Inconclusive text signal" in payload["summary"]
    assert "1 URL" in payload["summary"]
    assert "http://evil.example" not in payload["summary"]
    ioc_values = {i["value"] for i in payload["iocs"]}
    assert "http://evil.example" in ioc_values


def test_predict_upload_text_ingest_extracts_eml_and_uses_model(app_with_models):
    raw_eml = (
        "From: attacker@example.com\n"
        "Subject: Payroll update\n"
        "\n"
        "Urgent ransomware activity detected on host. CVE-2024-99999"
    )
    with TestClient(app_with_models) as c:
        response = c.post(
            "/predict/upload-text-ingest",
            json={
                "upload_id": "upload-124",
                "filename": "invoice.eml",
                "content_type": "message/rfc822",
                "scan_status": "malicious",
                "scan_engine": "clamav",
                "scan_detail": "Phishing.Email.Generic",
                "raw_content": raw_eml,
                "source": "upload_text",
            },
        )
    assert response.status_code == 200
    payload = response.json()
    assert payload["model_version"] != "none"
    assert payload["prediction"]["label"] in {"ransomware", "phishing"}
    assert "signal for" in payload["summary"]
    assert "attacker@example.com" not in payload["summary"]
    assert "Subject: Payroll update" in payload["extracted_text"]
    ioc_values = {i["value"] for i in payload["iocs"]}
    assert "CVE-2024-99999" in ioc_values


def test_predict_upload_text_ingest_extracts_json_raw_content():
    with TestClient(app) as c:
        response = c.post(
            "/predict/upload-text-ingest",
            json={
                "upload_id": "upload-125",
                "filename": "alert.json",
                "content_type": "application/json",
                "raw_content": '{"message":"contact 1.2.3.4"}',
                "source": "upload_text",
            },
        )
    assert response.status_code == 200
    payload = response.json()
    assert payload["extracted_text"].startswith('{"message"')
    assert "1.2.3.4" not in payload["summary"]
    assert "1 IP address" in payload["summary"]
    ioc_values = {i["value"] for i in payload["iocs"]}
    assert "1.2.3.4" in ioc_values


def test_predict_upload_text_ingest_summary_without_indicators():
    response = client.post(
        "/predict/upload-text-ingest",
        json={
            "upload_id": "upload-126",
            "filename": "note.txt",
            "content_type": "text/plain",
            "extracted_text": "Just a harmless note without any indicator.",
            "source": "upload_text",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"].endswith("No indicators were found.")


def test_predict_liveflow_fallback_combines_all_parts():
    response = client.post(
        "/predict/liveflow",
        json={
            "upload": {
                "upload_id": "upload-123",
                "filename": "invoice.eml",
                "content_type": "message/rfc822",
                "size_bytes": 58213,
                "scan_status": "malicious",
                "scan_engine": "clamav",
                "scan_detail": "Phishing.Email.Generic",
                "risk_score": 78,
                "source": "upload",
            },
            "upload_text": {
                "upload_id": "upload-123",
                "filename": "invoice.eml",
                "content_type": "message/rfc822",
                "scan_status": "malicious",
                "scan_engine": "clamav",
                "scan_detail": "Phishing.Email.Generic",
                "extracted_text": "See CVE-2024-99999 at http://evil.example",
                "source": "upload_text",
            },
            "cve_relevance": {
                "sbom_components": [
                    {
                        "name": "openssl",
                        "version": "3.0.7",
                        "ecosystem": "debian",
                        "purl": "pkg:deb/debian/openssl@3.0.7",
                        "cpe": "cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*",
                    }
                ],
                "cves": [
                    {
                        "cve_id": "CVE-2024-12345",
                        "summary": "OpenSSL vulnerability affecting versions before 3.0.8",
                        "cvss_score": 8.8,
                        "severity": "high",
                        "affected_packages": [
                            {
                                "name": "openssl",
                                "ecosystem": "debian",
                                "fixed_version": "3.0.8",
                            }
                        ],
                    }
                ],
            },
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["has_upload"] is True
    assert payload["summary"]["has_upload_text"] is True
    assert payload["summary"]["has_cve_relevance"] is True
    assert payload["upload_result"]["model_version"] == "none" or len(
        payload["upload_result"]["model_version"]
    ) == 12
    assert payload["upload_text_result"]["model_version"] == "none" or len(
        payload["upload_text_result"]["model_version"]
    ) == 12
    assert payload["upload_text_result"]["summary"]
    assert payload["summary"]["ioc_count"] >= 1
    assert payload["summary"]["matched_cves"] == 1


def test_predict_liveflow_uses_loaded_models(app_with_models):
    with TestClient(app_with_models) as c:
        response = c.post(
            "/predict/liveflow",
            json={
                "upload": {
                    "upload_id": "upload-200",
                    "filename": "invoice.eml",
                    "content_type": "message/rfc822",
                    "size_bytes": 58213,
                    "scan_status": "malicious",
                    "scan_engine": "clamav",
                    "scan_detail": "Phishing.Email.Generic",
                    "risk_score": 78,
                    "source": "upload",
                },
                "upload_text": {
                    "upload_id": "upload-200",
                    "filename": "invoice.eml",
                    "content_type": "message/rfc822",
                    "scan_status": "malicious",
                    "scan_engine": "clamav",
                    "scan_detail": "Phishing.Email.Generic",
                    "extracted_text": "ransomware activity on host and CVE-2024-99999",
                    "source": "upload_text",
                },
            },
        )
    assert response.status_code == 200
    payload = response.json()
    assert payload["upload_result"]["prediction"]["label"] in {"clean", "malicious"}
    assert payload["upload_result"]["model_version"] != "none"
    assert payload["upload_text_result"]["prediction"]["label"] in {"ransomware", "phishing"}
    assert payload["upload_text_result"]["model_version"] != "none"
    assert payload["upload_text_result"]["summary"]


def test_predict_liveflow_rejects_raw_content_in_upload_text_contract():
    response = client.post(
        "/predict/liveflow",
        json={
            "upload_text": {
                "upload_id": "upload-201",
                "filename": "invoice.eml",
                "content_type": "message/rfc822",
                "scan_status": "malicious",
                "scan_engine": "clamav",
                "scan_detail": "Phishing.Email.Generic",
                "raw_content": "should not be accepted in liveflow",
                "source": "upload_text",
            },
        },
    )
    assert response.status_code == 422
    assert "extra_forbidden" in response.text or "Field required" in response.text


def test_predict_liveflow_rejects_wrong_upload_source():
    response = client.post(
        "/predict/liveflow",
        json={
            "upload": {
                "upload_id": "upload-202",
                "filename": "invoice.eml",
                "content_type": "message/rfc822",
                "size_bytes": 58213,
                "scan_status": "malicious",
                "scan_engine": "clamav",
                "scan_detail": "Phishing.Email.Generic",
                "risk_score": 78,
                "source": "upload_text",
            }
        },
    )
    assert response.status_code == 422


def test_predict_liveflow_document_wraps_response_for_ml_predictions():
    response = client.post(
        "/predict/liveflow-document",
        json={
            "upload": {
                "upload_id": "upload-300",
                "filename": "invoice.eml",
                "content_type": "message/rfc822",
                "size_bytes": 58213,
                "scan_status": "malicious",
                "scan_engine": "clamav",
                "scan_detail": "Phishing.Email.Generic",
                "risk_score": 78,
                "source": "upload",
            }
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["upload_id"] == "upload-300"
    assert payload["ml_provider"] == "sentinel-ml"
    assert payload["ml_liveflow"]["summary"]["has_upload"] is True
    assert payload["ml_liveflow"]["summary"]["has_upload_text"] is False
    assert payload["ml_liveflow"]["upload_result"]["source"] == "upload"
    assert payload["ml_liveflow"]["upload_result"]["prediction"]["label"] in {"unknown", "accepted", "rejected"}
    assert payload["created_at"].endswith("Z")


def test_predict_liveflow_document_uses_loaded_models(app_with_models):
    with TestClient(app_with_models) as c:
        response = c.post(
            "/predict/liveflow-document",
            json={
                "upload": {
                    "upload_id": "upload-301",
                    "filename": "invoice.eml",
                    "content_type": "message/rfc822",
                    "size_bytes": 58213,
                    "scan_status": "malicious",
                    "scan_engine": "clamav",
                    "scan_detail": "Phishing.Email.Generic",
                    "risk_score": 78,
                    "source": "upload",
                },
                "upload_text": {
                    "upload_id": "upload-301",
                    "filename": "invoice.eml",
                    "content_type": "message/rfc822",
                    "scan_status": "malicious",
                    "scan_engine": "clamav",
                    "scan_detail": "Phishing.Email.Generic",
                    "extracted_text": "ransomware activity on host and CVE-2024-99999",
                    "source": "upload_text",
                },
            },
        )
    assert response.status_code == 200
    payload = response.json()
    assert payload["upload_id"] == "upload-301"
    assert payload["ml_provider"] == "sentinel-ml"
    assert payload["ml_liveflow"]["upload_result"]["model_version"] != "none"
    assert payload["ml_liveflow"]["upload_text_result"]["model_version"] != "none"
    assert payload["ml_liveflow"]["upload_text_result"]["extracted_text"] == ""
    assert payload["ml_liveflow"]["summary"]["has_upload"] is True
    assert payload["ml_liveflow"]["summary"]["has_upload_text"] is True


def test_predict_liveflow_document_rejects_request_without_upload_id():
    response = client.post(
        "/predict/liveflow-document",
        json={
            "cve_relevance": {
                "sbom_components": [{"name": "openssl", "version": "3.0.7"}],
                "cves": [],
            }
        },
    )
    assert response.status_code == 400
    assert "upload_id" in response.json()["detail"]


def test_predict_liveflow_writeback_persists_document(monkeypatch):
    stored: dict[str, object] = {}

    def fake_upsert(document):
        stored["document"] = document.model_dump(mode="json")

    monkeypatch.setattr(service_api, "upsert_ml_prediction_document", fake_upsert)

    response = client.post(
        "/predict/liveflow-writeback",
        json={
            "upload": {
                "upload_id": "upload-400",
                "filename": "invoice.eml",
                "content_type": "message/rfc822",
                "size_bytes": 58213,
                "scan_status": "malicious",
                "scan_engine": "clamav",
                "scan_detail": "Phishing.Email.Generic",
                "risk_score": 78,
                "source": "upload",
            },
            "upload_text": {
                "upload_id": "upload-400",
                "filename": "invoice.eml",
                "content_type": "message/rfc822",
                "scan_status": "malicious",
                "scan_engine": "clamav",
                "scan_detail": "Phishing.Email.Generic",
                "extracted_text": "secret link http://evil.example",
                "source": "upload_text",
            }
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["persisted"] is True
    assert payload["collection"] == "ml_predictions"
    assert payload["document"]["upload_id"] == "upload-400"
    assert stored["document"]["upload_id"] == "upload-400"
    assert (
        payload["document"]["ml_liveflow"]["upload_text_result"]["extracted_text"] == ""
    )
    assert (
        stored["document"]["ml_liveflow"]["upload_text_result"]["extracted_text"] == ""
    )


def test_predict_liveflow_writeback_returns_503_on_persist_failure(monkeypatch):
    def fake_upsert(_document):
        raise RuntimeError("mongo unavailable")

    monkeypatch.setattr(service_api, "upsert_ml_prediction_document", fake_upsert)

    response = client.post(
        "/predict/liveflow-writeback",
        json={
            "upload": {
                "upload_id": "upload-401",
                "filename": "invoice.eml",
                "content_type": "message/rfc822",
                "size_bytes": 58213,
                "scan_status": "malicious",
                "scan_engine": "clamav",
                "scan_detail": "Phishing.Email.Generic",
                "risk_score": 78,
                "source": "upload",
            }
        },
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "failed to persist ml prediction document"
