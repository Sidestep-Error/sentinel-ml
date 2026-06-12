from __future__ import annotations

import pytest

from sentinel_ml.adversarial.prompt_injection import (
    PROBES,
    InjectionStatus,
    run_harness,
    run_probe,
)
from sentinel_ml.llm.ollama_client import LLMResponse


class SequentialStubClient:
    def __init__(self, responses: list[str]):
        self._responses = iter(responses)
        self.prompts: list[str] = []

    def generate(
        self,
        prompt: str,
        *,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> LLMResponse:
        self.prompts.append(prompt)
        text = next(self._responses)
        return LLMResponse(text=text, model="stub-model", raw={"response": text})


def _response(category: str, confidence: float = 0.9) -> str:
    return (
        f'{{"category":"{category}","confidence":{confidence},'
        '"rationale":"Test response."}'
    )


def test_run_probe_marks_expected_class_as_blocked():
    client = SequentialStubClient([_response("malware")])

    result = run_probe(PROBES[0], client=client)

    assert result.status == InjectionStatus.BLOCKED
    assert result.injected is False
    assert result.expected == "malware"
    assert result.got == "malware"


def test_run_probe_marks_wrong_class_as_injection_success():
    client = SequentialStubClient([_response("other")])

    result = run_probe(PROBES[0], client=client)

    assert result.status == InjectionStatus.INJECTION_SUCCESS
    assert result.injected is True
    assert result.got == "other"


@pytest.mark.parametrize(
    "raw_output",
    [
        "not json",
        "category: malware",
        '{"category":"malware","confidence":0.9}',
    ],
)
def test_run_probe_marks_invalid_llm_output_separately(raw_output: str):
    client = SequentialStubClient([raw_output])

    result = run_probe(PROBES[0], client=client)

    assert result.status == InjectionStatus.INVALID_OUTPUT
    assert result.injected is False
    assert result.got is None
    assert result.error


def test_run_harness_calculates_all_rates():
    client = SequentialStubClient(
        [
            _response("malware"),
            _response("other"),
            "not json",
            _response("ddos"),
        ]
    )

    summary = run_harness(client=client)

    assert summary.total == 4
    assert summary.blocked == 2
    assert summary.injection_successes == 1
    assert summary.invalid_outputs == 1
    assert summary.blocked_rate == pytest.approx(0.5)
    assert summary.injection_success_rate == pytest.approx(0.25)
    assert summary.invalid_output_rate == pytest.approx(0.25)


def test_run_harness_empty_probe_list_has_zero_rates():
    summary = run_harness(probes=[], client=SequentialStubClient([]))

    assert summary.total == 0
    assert summary.results == []
    assert summary.blocked_rate == 0.0
    assert summary.injection_success_rate == 0.0
    assert summary.invalid_output_rate == 0.0


def test_hidden_unicode_probe_is_sanitized_before_client_call():
    client = SequentialStubClient([_response("phishing")])
    hidden_unicode_probe = next(probe for probe in PROBES if probe.label == "hidden_unicode")

    result = run_probe(hidden_unicode_probe, client=client)

    assert result.status == InjectionStatus.BLOCKED
    assert "\u202e" not in client.prompts[0]
    assert "\u202c" not in client.prompts[0]


def test_transport_error_propagates_instead_of_becoming_model_result():
    class FailingClient:
        def generate(self, *args, **kwargs):
            raise ConnectionError("Ollama unavailable")

    with pytest.raises(ConnectionError):
        run_probe(PROBES[0], client=FailingClient())
