"""The Ollama call must be gated behind settings.llm_enabled (default off).

The deployed path runs classical models and must not touch Ollama unless
explicitly opted in — see service/api.py::_call_ollama.
"""

from __future__ import annotations

import pytest

from sentinel_ml.service import api


def test_call_ollama_disabled_by_default_short_circuits(monkeypatch: pytest.MonkeyPatch) -> None:
    """When LLM is disabled, _call_ollama returns None without constructing a client."""
    monkeypatch.setenv("LLM_ENABLED", "false")

    class _Boom:
        def __init__(self, *a, **k):
            raise AssertionError("OllamaClient must not be constructed when LLM is disabled")

    monkeypatch.setattr("sentinel_ml.llm.ollama_client.OllamaClient", _Boom)
    assert api._call_ollama("ransomware campaign") is None


def test_call_ollama_enabled_uses_validated_classifier(monkeypatch: pytest.MonkeyPatch) -> None:
    """When enabled, _call_ollama uses the validated and sanitized classifier path."""
    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setenv("OLLAMA_TIMEOUT_SECONDS", "2.5")
    seen: dict[str, object] = {}

    class _FakeClient:
        def __init__(self, timeout: float) -> None:
            seen["timeout"] = timeout
            self.model = "llama3.2:3b"

        def generate(self, prompt: str, *, system: str, temperature: float = 0.0):
            from sentinel_ml.llm.ollama_client import LLMResponse

            seen["prompt"] = prompt
            return LLMResponse(
                '{"category": "ransomware", "confidence": 0.82, "rationale": "locker"}',
                "llama3.2:3b",
                {},
            )

    monkeypatch.setattr("sentinel_ml.llm.ollama_client.OllamaClient", _FakeClient)

    result = api._call_ollama("a ransomware report\u202e")
    assert result is not None
    assert result.category == "ransomware"
    assert result.confidence == pytest.approx(0.82)
    assert result.model == "llama3.2:3b"
    assert seen["timeout"] == pytest.approx(2.5)  # uses configured timeout, not 30s
    assert "<threat_report>" in str(seen["prompt"])
    assert "\u202e" not in str(seen["prompt"])


@pytest.mark.parametrize(
    "response_text",
    [
        "not json",
        '{"category": "ransomware", "confidence": 0.82}',
        '{"category": "safe", "confidence": 0.82, "rationale": "invalid category"}',
    ],
)
def test_call_ollama_enabled_degrades_on_invalid_output(
    monkeypatch: pytest.MonkeyPatch,
    response_text: str,
) -> None:
    """Invalid LLM output is rejected by the shared schema and degrades to None."""
    monkeypatch.setenv("LLM_ENABLED", "true")

    class _InvalidClient:
        def __init__(self, timeout: float) -> None:
            self.model = "llama3.2:3b"

        def generate(self, prompt: str, *, system: str, temperature: float = 0.0):
            from sentinel_ml.llm.ollama_client import LLMResponse

            return LLMResponse(response_text, self.model, {})

    monkeypatch.setattr("sentinel_ml.llm.ollama_client.OllamaClient", _InvalidClient)
    assert api._call_ollama("text") is None


def test_call_ollama_enabled_degrades_on_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When Ollama errors, _call_ollama degrades to None and never raises."""
    monkeypatch.setenv("LLM_ENABLED", "true")

    class _FailingClient:
        def __init__(self, timeout: float) -> None:
            self.model = "llama3.2:3b"

        def generate(self, prompt: str, *, system: str, temperature: float = 0.0):
            raise RuntimeError("ollama unreachable")

    monkeypatch.setattr("sentinel_ml.llm.ollama_client.OllamaClient", _FailingClient)
    assert api._call_ollama("text") is None
