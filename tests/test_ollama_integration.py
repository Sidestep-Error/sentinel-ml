from __future__ import annotations

import httpx
import pytest

from sentinel_ml.llm.classifier import classify_threat_report
from sentinel_ml.llm.ollama_client import OllamaClient


def _ollama_available(host: str) -> bool:
    try:
        response = httpx.get(f"{host}/api/tags", timeout=2.0)
        response.raise_for_status()
    except httpx.HTTPError:
        return False
    return True


@pytest.mark.integration
def test_classify_threat_report_against_local_ollama():
    client = OllamaClient()
    if not _ollama_available(client.host):
        pytest.skip("Ollama is not available locally")

    result = classify_threat_report(
        "Phishing campaign impersonating payroll with credential harvesting links.",
        client=client,
    )

    assert result.category in {
        "malware",
        "phishing",
        "ddos",
        "intrusion",
        "ransomware",
        "supply_chain",
        "insider",
        "other",
    }
    assert 0.0 <= result.confidence <= 1.0
    assert result.rationale
