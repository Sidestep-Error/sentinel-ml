"""The Ollama call must be gated behind settings.llm_enabled (default off).

The deployed path runs classical models and must not touch Ollama unless
explicitly opted in — see service/api.py::_call_ollama.
"""

from __future__ import annotations

import pytest

from sentinel_ml.service import api


class _FakeResponse:
    def __init__(self, text: str, model: str) -> None:
        self.text = text
        self.model = model


def test_call_ollama_disabled_by_default_short_circuits(monkeypatch: pytest.MonkeyPatch) -> None:
    """When LLM is disabled, _call_ollama returns None without constructing a client."""
    monkeypatch.setenv("LLM_ENABLED", "false")

    class _Boom:
        def __init__(self, *a, **k):
            raise AssertionError("OllamaClient must not be constructed when LLM is disabled")

    monkeypatch.setattr("sentinel_ml.llm.ollama_client.OllamaClient", _Boom)
    assert api._call_ollama("ransomware campaign") is None


def test_call_ollama_enabled_parses_response(monkeypatch: pytest.MonkeyPatch) -> None:
    """When enabled, _call_ollama uses the configured timeout and parses JSON output."""
    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setenv("OLLAMA_TIMEOUT_SECONDS", "2.5")
    seen = {}

    class _FakeClient:
        def __init__(self, timeout: float) -> None:
            seen["timeout"] = timeout

        def generate(self, prompt: str, system: str) -> _FakeResponse:
            return _FakeResponse(
                '{"category": "ransomware", "confidence": 0.82, "rationale": "locker"}',
                "llama3.2:3b",
            )

    monkeypatch.setattr("sentinel_ml.llm.ollama_client.OllamaClient", _FakeClient)

    result = api._call_ollama("a ransomware report")
    assert result is not None
    assert result.category == "ransomware"
    assert result.confidence == pytest.approx(0.82)
    assert result.model == "llama3.2:3b"
    assert seen["timeout"] == pytest.approx(2.5)  # uses configured timeout, not 30s


def test_call_ollama_enabled_degrades_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """When enabled but Ollama errors, _call_ollama degrades to None (never raises)."""
    monkeypatch.setenv("LLM_ENABLED", "true")

    class _FailingClient:
        def __init__(self, timeout: float) -> None:
            pass

        def generate(self, prompt: str, system: str):
            raise RuntimeError("ollama unreachable")

    monkeypatch.setattr("sentinel_ml.llm.ollama_client.OllamaClient", _FailingClient)
    assert api._call_ollama("text") is None
