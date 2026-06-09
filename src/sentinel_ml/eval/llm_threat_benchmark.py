"""Benchmark helpers for LLM zero-shot threat-report classification."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from statistics import mean
from time import perf_counter

from sklearn.model_selection import train_test_split

from sentinel_ml.data.schemas import ThreatReport
from sentinel_ml.eval.metrics import ClassificationMetrics, evaluate_classifier
from sentinel_ml.llm.classifier import classify_threat_report
from sentinel_ml.llm.ollama_client import OllamaClient

DEFAULT_THREAT_LABELS = ("ransomware", "phishing", "ddos", "malware", "intrusion")
INVALID_OUTPUT_LABEL = "other"


@dataclass
class LLMThreatBenchmarkResult:
    """Aggregated benchmark output for one LLM evaluation run."""

    metrics: ClassificationMetrics
    total_reports: int
    valid_outputs: int
    invalid_outputs: int
    avg_latency_ms: float
    labels: list[str]
    model_name: str


def select_test_reports(
    reports: Sequence[ThreatReport],
    *,
    test_size: float = 0.2,
    random_state: int = 42,
) -> list[ThreatReport]:
    """Select the evaluation subset using the same split strategy as the baseline script."""
    labeled_reports = [report for report in reports if report.labels]
    if not labeled_reports:
        raise ValueError("No labeled threat reports available for evaluation")

    _, test_reports = train_test_split(
        labeled_reports,
        test_size=test_size,
        random_state=random_state,
    )
    return list(test_reports)


def evaluate_llm_threat_classifier(
    reports: Sequence[ThreatReport],
    *,
    client: OllamaClient | None = None,
    labels: Sequence[str] | None = None,
    temperature: float = 0.0,
) -> LLMThreatBenchmarkResult:
    """Evaluate the LLM classifier on a labeled threat-report dataset."""
    llm_client = client or OllamaClient()
    expected_labels = list(labels) if labels else list(DEFAULT_THREAT_LABELS)

    y_true: list[str] = []
    y_pred: list[str] = []
    latencies_ms: list[float] = []
    valid_outputs = 0
    invalid_outputs = 0

    for report in reports:
        if not report.labels:
            continue

        y_true.append(report.labels[0])
        started_at = perf_counter()
        try:
            result = classify_threat_report(report.text, client=llm_client, temperature=temperature)
            predicted_label = result.category
            valid_outputs += 1
        except Exception:  # noqa: BLE001 - benchmark records invalid model output as a miss
            predicted_label = INVALID_OUTPUT_LABEL
            invalid_outputs += 1
        latencies_ms.append((perf_counter() - started_at) * 1000.0)
        y_pred.append(predicted_label)

    if not y_true:
        raise ValueError("No labeled threat reports available for evaluation")

    metric_labels = list(expected_labels)
    if invalid_outputs and INVALID_OUTPUT_LABEL not in metric_labels:
        metric_labels.append(INVALID_OUTPUT_LABEL)

    metrics = evaluate_classifier(y_true, y_pred, labels=metric_labels)
    return LLMThreatBenchmarkResult(
        metrics=metrics,
        total_reports=len(y_true),
        valid_outputs=valid_outputs,
        invalid_outputs=invalid_outputs,
        avg_latency_ms=mean(latencies_ms) if latencies_ms else 0.0,
        labels=metric_labels,
        model_name=llm_client.model,
    )
