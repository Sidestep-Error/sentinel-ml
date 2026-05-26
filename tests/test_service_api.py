from fastapi.testclient import TestClient

from sentinel_ml.service.api import app

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
