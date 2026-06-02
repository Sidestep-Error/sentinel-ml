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
