"""Outcome tests — verifierar att ML-modellerna ger rätt svar på kända indata.

Skiljer sig från test_service_api.py som bara kontrollerar struktur/schema.
Dessa tester fångar modellregressioner: om en omträning ändrar ett utfall bryts testet.

Förutsätter att tränade artefakter finns i models_store/. Hoppar över automatiskt
om artefakter saknas (CI utan träningsdata).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from sentinel_ml.config import get_settings
from sentinel_ml.log_anomaly import tfidf_detector
from sentinel_ml.models import threat_classifier
from sentinel_ml.service.api import create_app

settings = get_settings()
MODELS_DIR = Path(settings.models_dir)

THREAT_ARTIFACT = MODELS_DIR / "threat_classifier.joblib"
LOG_ANOMALY_ARTIFACT = MODELS_DIR / tfidf_detector.LOG_ANOMALY_ARTIFACT

requires_threat_model = pytest.mark.skipif(
    not THREAT_ARTIFACT.exists(),
    reason="threat_classifier.joblib saknas — kör: sentinel-ml train threat-classifier",
)
requires_log_model = pytest.mark.skipif(
    not LOG_ANOMALY_ARTIFACT.exists(),
    reason="log_anomaly_tfidf.joblib saknas — kör: sentinel-ml train log-anomaly",
)


@dataclass(frozen=True)
class LoadedModel:
    artifact: Any
    version: str


def _version(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


@pytest.fixture(scope="module")
def app_with_real_models():
    """FastAPI-app med riktiga tränade artefakter från models_store/."""
    app = create_app()
    if THREAT_ARTIFACT.exists():
        app.state.threat_model = LoadedModel(
            artifact=threat_classifier.load(THREAT_ARTIFACT),
            version=_version(THREAT_ARTIFACT),
        )
    else:
        app.state.threat_model = None

    if LOG_ANOMALY_ARTIFACT.exists():
        app.state.log_anomaly_model = LoadedModel(
            artifact=tfidf_detector.load(LOG_ANOMALY_ARTIFACT),
            version=_version(LOG_ANOMALY_ARTIFACT),
        )
    else:
        app.state.log_anomaly_model = None

    app.state.upload_model = None
    return app


# ── Threat classifier — demo-scenarion ───────────────────────────────────────

@requires_threat_model
def test_phishing_scenario_label(app_with_real_models):
    """Phishing-text ska klassificeras som 'phishing' med confidence > 0.5."""
    text = (
        "Phishing campaign observed distributing credential-harvesting pages mimicking "
        "a corporate VPN login portal. Victims received spear-phishing emails with "
        "subject 'Urgent: Your password expires today'. The fake login page at "
        "https://vpn-secure-login.net/auth collected username and password pairs. "
        "Sender address spoofed as it-support@company-internal.com. "
        "Over 400 employees submitted credentials before the phishing site was taken down."
    )
    with TestClient(app_with_real_models) as c:
        resp = c.post("/predict/threat", json={"text": text})
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["prediction"]["label"] == "phishing", (
        f"Förväntade 'phishing', fick '{payload['prediction']['label']}'"
    )
    assert payload["prediction"]["confidence"] > 0.5, (
        f"Confidence för låg: {payload['prediction']['confidence']:.3f}"
    )


@requires_threat_model
def test_ransomware_scenario_label(app_with_real_models):
    """Ransomware-text ska klassificeras som 'ransomware'."""
    text = (
        "Conti ransomware variant encrypted all files on 87 servers across the victim network. "
        "Ransom note demands 120 BTC for decryption key. All backup systems were wiped before "
        "encryption began. Files renamed with .conti extension. "
        "Payment portal hosted at conti-decrypt.onion. Double extortion: victim data "
        "published on leak site if ransom not paid within 72 hours. Recovery impossible "
        "without decryption key due to AES-256 encryption."
    )
    with TestClient(app_with_real_models) as c:
        resp = c.post("/predict/threat", json={"text": text})
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["prediction"]["label"] == "ransomware", (
        f"Förväntade 'ransomware', fick '{payload['prediction']['label']}'"
    )


@requires_threat_model
def test_intrusion_scenario_label(app_with_real_models):
    """Intrusion-text ska klassificeras som 'intrusion'."""
    text = (
        "Nation-state intrusion campaign detected across multiple government networks. "
        "Threat actor gained initial access via spear phishing and established persistence "
        "through scheduled tasks and registry run keys. Lateral movement across internal "
        "subnets using stolen administrative credentials. Sensitive documents exfiltrated "
        "to 203.0.113.100 over encrypted HTTPS channel. Adversary maintained access for "
        "over 90 days before detection. TTPs consistent with APT28 (Fancy Bear)."
    )
    with TestClient(app_with_real_models) as c:
        resp = c.post("/predict/threat", json={"text": text})
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["prediction"]["label"] == "intrusion", (
        f"Förväntade 'intrusion', fick '{payload['prediction']['label']}'"
    )


@requires_threat_model
def test_phishing_iocs_extracted(app_with_real_models):
    """Phishing-scenariot ska extrahera URL och e-postadress som IOCs."""
    text = (
        "Phishing campaign observed. Fake login at https://vpn-secure-login.net/auth. "
        "Sender: noreply@office365-verify.net."
    )
    with TestClient(app_with_real_models) as c:
        resp = c.post("/predict/threat", json={"text": text})
    ioc_values = {i["value"] for i in resp.json()["iocs"]}
    assert "https://vpn-secure-login.net/auth" in ioc_values
    assert "noreply@office365-verify.net" in ioc_values


@requires_threat_model
def test_ransomware_sha256_extracted(app_with_real_models):
    """Ransomware-scenariot ska extrahera SHA-256-hash som IOC."""
    sha = "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5"
    text = f"Ransomware sample SHA-256: {sha}. Payment at conti-decrypt.onion."
    with TestClient(app_with_real_models) as c:
        resp = c.post("/predict/threat", json={"text": text})
    ioc_values = {i["value"] for i in resp.json()["iocs"]}
    assert sha in ioc_values


# ── Log anomaly — SSH brute force ska flaggas ─────────────────────────────────

@requires_log_model
def test_ssh_brute_force_flagged_as_anomaly(app_with_real_models):
    """SSH-lösenordsfel mot root ska flaggas som anomali."""
    attack_logs = [
        "sshd[9999]: Failed password for root from 185.220.101.42 port 44512 ssh2",
        "sshd[9999]: Failed password for root from 185.220.101.42 port 44513 ssh2",
        "sshd[9999]: error: maximum authentication attempts exceeded for root from 185.220.101.42",
    ]
    with TestClient(app_with_real_models) as c:
        resp = c.post("/predict/log-anomaly", json={"logs": attack_logs})
    assert resp.status_code == 200
    predictions = resp.json()["predictions"]
    flagged = [p for p in predictions if p["is_anomaly"]]
    assert len(flagged) >= 1, (
        f"Förväntade minst 1 anomali i SSH-brute-force-loggar, fick 0. "
        f"Scores: {[p['score'] for p in predictions]}"
    )


@requires_log_model
def test_normal_logs_not_flagged(app_with_real_models):
    """Normala loggar ska inte flaggas som anomalier."""
    normal_logs = [
        "sshd[1234]: Accepted publickey for alice from 192.168.1.10 port 54321 ssh2",
        "systemd[1]: Started nginx.service",
        "cron[5678]: (ubuntu) CMD (/usr/local/bin/backup.sh)",
    ]
    with TestClient(app_with_real_models) as c:
        resp = c.post("/predict/log-anomaly", json={"logs": normal_logs})
    predictions = resp.json()["predictions"]
    flagged = [p for p in predictions if p["is_anomaly"]]
    assert len(flagged) == 0, (
        f"Förväntade 0 anomalier i normala loggar, fick {len(flagged)}: "
        f"{[p['line'] for p in flagged]}"
    )


@requires_log_model
def test_mixed_logs_partial_detection(app_with_real_models):
    """Blandade loggar — normal + SSH-brute-force — ska ge delmängd anomalier."""
    logs = [
        "sshd[1234]: Accepted publickey for alice from 192.168.1.10 port 54321 ssh2",
        "sshd[9999]: Failed password for root from 185.220.101.42 port 44512 ssh2",
        "systemd[1]: Started nginx.service",
        "sshd[9999]: Failed password for root from 185.220.101.42 port 44513 ssh2",
    ]
    with TestClient(app_with_real_models) as c:
        resp = c.post("/predict/log-anomaly", json={"logs": logs})
    predictions = resp.json()["predictions"]
    flagged_indices = [i for i, p in enumerate(predictions) if p["is_anomaly"]]
    # Minst en av attack-loggarna (index 1 och 3) ska vara flaggad
    assert any(i in flagged_indices for i in [1, 3]), (
        f"Ingen av SSH-attack-loggarna flaggades. Flaggade index: {flagged_indices}"
    )
