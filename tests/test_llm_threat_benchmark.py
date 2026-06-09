from __future__ import annotations

from sentinel_ml.data.schemas import ThreatReport
from sentinel_ml.eval.llm_threat_benchmark import (
    DEFAULT_THREAT_LABELS,
    INVALID_OUTPUT_LABEL,
    evaluate_llm_threat_classifier,
    select_test_reports,
)
from sentinel_ml.llm.ollama_client import LLMResponse


class SequentialStubClient:
    def __init__(self, responses: list[str]):
        self._responses = iter(responses)
        self.model = "stub-llm"

    def generate(self, prompt: str, *, system: str | None = None, temperature: float = 0.0) -> LLMResponse:
        response_text = next(self._responses)
        return LLMResponse(text=response_text, model=self.model, raw={"response": response_text})


def test_evaluate_llm_threat_classifier_tracks_valid_and_invalid_outputs():
    reports = [
        ThreatReport(report_id="1", text="phishing lure", labels=["phishing"]),
        ThreatReport(report_id="2", text="ransomware note", labels=["ransomware"]),
        ThreatReport(report_id="3", text="ddos flood", labels=["ddos"]),
    ]
    client = SequentialStubClient(
        [
            '{"category":"phishing","confidence":0.91,"rationale":"Looks like credential theft."}',
            "not json",
            '{"category":"ddos","confidence":0.83,"rationale":"Flooding language detected."}',
        ]
    )

    result = evaluate_llm_threat_classifier(reports, client=client, labels=DEFAULT_THREAT_LABELS)

    assert result.total_reports == 3
    assert result.valid_outputs == 2
    assert result.invalid_outputs == 1
    assert result.model_name == "stub-llm"
    assert INVALID_OUTPUT_LABEL in result.labels
    assert result.metrics.accuracy == 2 / 3


def test_evaluate_llm_threat_classifier_skips_unlabeled_reports():
    reports = [
        ThreatReport(report_id="1", text="phishing lure", labels=[]),
        ThreatReport(report_id="2", text="ransomware note", labels=["ransomware"]),
    ]
    client = SequentialStubClient(
        ['{"category":"ransomware","confidence":0.91,"rationale":"Extortion language present."}']
    )

    result = evaluate_llm_threat_classifier(reports, client=client, labels=DEFAULT_THREAT_LABELS)

    assert result.total_reports == 1
    assert result.valid_outputs == 1
    assert result.invalid_outputs == 0


def test_evaluate_llm_threat_classifier_requires_labeled_reports():
    reports = [ThreatReport(report_id="1", text="unlabeled", labels=[])]
    client = SequentialStubClient(
        ['{"category":"phishing","confidence":0.91,"rationale":"Credential theft."}']
    )

    import pytest

    with pytest.raises(ValueError):
        evaluate_llm_threat_classifier(reports, client=client, labels=DEFAULT_THREAT_LABELS)


def test_select_test_reports_uses_requested_split_and_skips_unlabeled_reports():
    reports = [
        ThreatReport(report_id=str(i), text=f"report {i}", labels=["phishing"])
        for i in range(10)
    ] + [
        ThreatReport(report_id="u1", text="unlabeled", labels=[]),
    ]

    test_reports = select_test_reports(reports, test_size=0.2, random_state=42)

    assert len(test_reports) == 2
    assert all(report.labels for report in test_reports)
