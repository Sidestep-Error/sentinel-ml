"""Tests for the log_anomaly package and the /predict/log-anomaly API endpoint."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel_ml.log_anomaly import alert_manager, generate_data, tfidf_detector
from sentinel_ml.log_anomaly.attack import camouflage, run_attack
from sentinel_ml.service.api import app, create_app

client = TestClient(app)


# ---------------------------------------------------------------------------
# generate_data
# ---------------------------------------------------------------------------


def test_generate_logs_counts():
    records = generate_data.generate_logs(n_normal=10, n_attack=5, seed=0)
    assert len(records) == 15
    assert sum(1 for r in records if r["label"] == "normal") == 10
    assert sum(1 for r in records if r["label"] == "attack") == 5


def test_generate_logs_has_line_key():
    records = generate_data.generate_logs(n_normal=5, n_attack=5, seed=0)
    for rec in records:
        assert "line" in rec
        assert len(rec["line"]) > 0


def test_save_and_load_csv(tmp_path):
    records = generate_data.generate_logs(n_normal=5, n_attack=5, seed=1)
    csv_path = tmp_path / "logs.csv"
    generate_data.save_csv(records, csv_path)
    loaded = generate_data.load_csv(csv_path)
    assert len(loaded) == 10
    assert loaded[0]["line"] == records[0]["line"]


# ---------------------------------------------------------------------------
# tfidf_detector
# ---------------------------------------------------------------------------


@pytest.fixture
def small_pipeline():
    records = generate_data.generate_logs(n_normal=50, n_attack=10, seed=42)
    lines = [r["line"] for r in records]
    return tfidf_detector.train(lines, contamination=0.15, random_state=42)


def test_build_pipeline_steps():
    pipeline = tfidf_detector.build_pipeline()
    assert list(pipeline.named_steps.keys()) == ["tfidf", "iso"]


def test_train_returns_pipeline(small_pipeline):
    assert hasattr(small_pipeline, "predict")
    assert hasattr(small_pipeline, "decision_function")


def test_predict_shape(small_pipeline):
    lines = ["sshd: Failed password for root from 1.2.3.4", "systemd: Started nginx.service"]
    results = tfidf_detector.predict(small_pipeline, lines)
    assert len(results) == 2
    for r in results:
        assert "line" in r
        assert "score" in r
        assert isinstance(r["is_anomaly"], bool)


def test_evaluate_returns_metrics(small_pipeline):
    records = generate_data.generate_logs(n_normal=20, n_attack=5, seed=7)
    lines = [r["line"] for r in records]
    labels = [r["label"] for r in records]
    metrics = tfidf_detector.evaluate(small_pipeline, lines, labels)
    assert set(metrics.keys()) >= {"precision", "recall", "f1", "n_anomalies", "n_total"}
    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0


def test_save_and_load(tmp_path, small_pipeline):
    artifact = tmp_path / "model.joblib"
    tfidf_detector.save(small_pipeline, artifact)
    loaded = tfidf_detector.load(artifact)
    lines = ["sshd: Failed password for root"]
    assert tfidf_detector.predict(loaded, lines) == tfidf_detector.predict(small_pipeline, lines)


# ---------------------------------------------------------------------------
# alert_manager
# ---------------------------------------------------------------------------


def test_classify_alert_critical():
    assert alert_manager.classify_alert(zscore=3.5, isolation_score=-0.4) == "critical"


def test_classify_alert_medium():
    assert alert_manager.classify_alert(zscore=2.1, isolation_score=0.1) == "medium"


def test_classify_alert_none():
    assert alert_manager.classify_alert(zscore=0.5, isolation_score=0.5) is None


def test_create_alert_shape():
    alert = alert_manager.create_alert("2024-01-01T00:00:00", "high", {"event_count": 42})
    assert alert["severity"] == "high"
    assert alert["details"]["event_count"] == 42
    assert "detected_at" in alert


# ---------------------------------------------------------------------------
# attack
# ---------------------------------------------------------------------------


def test_camouflage_extends_line():
    original = "sshd: Failed password for root from 1.2.3.4"
    result = camouflage(original)
    assert original in result
    assert len(result) > len(original)


def test_run_attack_returns_stats(small_pipeline):
    attack_lines = [
        "sshd: Failed password for root from 1.2.3.4 port 22222 ssh2",
        "sudo: root : command not allowed ; COMMAND=/bin/bash",
        "kernel: audit: type=1400 AVC avc: denied execve for pid=999",
    ]
    stats = run_attack(small_pipeline, attack_lines, seed=42)
    assert stats["n_attack_logs"] == 3
    assert 0 <= stats["detected_before"] <= 3
    assert 0 <= stats["detected_after"] <= 3
    assert 0.0 <= stats["evasion_rate_after"] <= 1.0
    assert len(stats["camouflaged_examples"]) == 3


def test_run_attack_empty(small_pipeline):
    stats = run_attack(small_pipeline, [], seed=0)
    assert stats["n_attack_logs"] == 0
    assert stats["evasion_rate_after"] == 0.0


# ---------------------------------------------------------------------------
# API /predict/log-anomaly
# ---------------------------------------------------------------------------


def test_log_anomaly_fallback_no_model():
    response = client.post(
        "/predict/log-anomaly",
        json={"logs": ["sshd: Failed password for root", "systemd: Started nginx"]},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["model_version"] == "none"
    assert len(payload["predictions"]) == 2
    for p in payload["predictions"]:
        assert p["is_anomaly"] is False
        assert p["score"] == 0.0


def test_log_anomaly_fallback_empty_logs():
    response = client.post("/predict/log-anomaly", json={"logs": []})
    assert response.status_code == 200
    assert response.json()["predictions"] == []


@pytest.fixture
def app_with_log_anomaly_model(tmp_path, monkeypatch):
    """Train a tiny log anomaly model, save to tmp, return a fresh app."""
    models_dir = tmp_path / "models"
    models_dir.mkdir()

    records = generate_data.generate_logs(n_normal=50, n_attack=10, seed=42)
    lines = [r["line"] for r in records]
    pipeline = tfidf_detector.train(lines, contamination=0.15, random_state=42)
    tfidf_detector.save(pipeline, models_dir / tfidf_detector.LOG_ANOMALY_ARTIFACT)

    monkeypatch.setenv("MODELS_DIR", str(models_dir))
    return create_app()


def test_log_anomaly_with_loaded_model(app_with_log_anomaly_model):
    with TestClient(app_with_log_anomaly_model) as c:
        response = c.post(
            "/predict/log-anomaly",
            json={"logs": [
                "sshd: Failed password for root from 9.8.7.6 port 22 ssh2",
                "systemd[1]: Started nginx.service",
            ]},
        )
    assert response.status_code == 200
    payload = response.json()
    assert payload["model_version"] != "none"
    assert len(payload["predictions"]) == 2
    for p in payload["predictions"]:
        assert isinstance(p["is_anomaly"], bool)
        assert isinstance(p["score"], float)
