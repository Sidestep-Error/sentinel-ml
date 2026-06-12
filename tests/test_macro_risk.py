"""Tests for the deterministic macro-risk rule and its API surface."""

from __future__ import annotations

from fastapi.testclient import TestClient

from sentinel_ml.data.schemas import MacroAnalysis
from sentinel_ml.features.macro_risk import assess_macro_risk
from sentinel_ml.service.api import create_app


def test_no_macro_analysis_is_not_risky():
    risky, reason = assess_macro_risk(None)
    assert risky is False
    assert reason == ""


def test_no_macros_is_not_risky():
    risky, reason = assess_macro_risk(MacroAnalysis(has_macros=False))
    assert risky is False
    assert reason == ""


def test_macro_without_triggers_is_flagged_with_reason_only():
    risky, reason = assess_macro_risk(MacroAnalysis(has_macros=True))
    assert risky is False
    assert "VBA macro present" in reason


def test_autoexec_plus_suspicious_is_risky():
    macro = MacroAnalysis(has_macros=True, autoexec_keywords=1, suspicious_keywords=2)
    risky, reason = assess_macro_risk(macro)
    assert risky is True
    assert "auto-execution" in reason


def test_many_suspicious_without_autoexec_is_risky():
    macro = MacroAnalysis(has_macros=True, suspicious_keywords=3)
    risky, _ = assess_macro_risk(macro)
    assert risky is True


def test_few_suspicious_without_autoexec_is_not_risky():
    macro = MacroAnalysis(has_macros=True, suspicious_keywords=2)
    risky, _ = assess_macro_risk(macro)
    assert risky is False


def _payload(macro: dict | None) -> dict:
    body = {
        "upload_id": "u1",
        "filename": "invoice.xls",
        "content_type": "application/vnd.ms-excel",
        "sha256": "a" * 64,
        "scan_status": "clean",
    }
    if macro is not None:
        body["macro"] = macro
    return body


def test_upload_ingest_flags_macro_risk():
    client = TestClient(create_app())
    macro = {"has_macros": True, "autoexec_keywords": 2, "suspicious_keywords": 4}
    r = client.post("/predict/upload-ingest", json=_payload(macro))
    assert r.status_code == 200
    body = r.json()
    assert body["macro_risk"] is True
    assert "auto-execution" in body["macro_reason"]


def test_upload_ingest_without_macro_field_is_backward_compatible():
    client = TestClient(create_app())
    r = client.post("/predict/upload-ingest", json=_payload(None))
    assert r.status_code == 200
    body = r.json()
    assert body["macro_risk"] is False
    assert body["macro_reason"] == ""


def test_liveflow_summary_reflects_macro_risk():
    client = TestClient(create_app())
    macro = {"has_macros": True, "autoexec_keywords": 1, "suspicious_keywords": 1}
    r = client.post("/predict/liveflow", json={"upload": _payload(macro)})
    assert r.status_code == 200
    body = r.json()
    assert body["upload_result"]["macro_risk"] is True
    assert body["summary"]["macro_risk"] is True
