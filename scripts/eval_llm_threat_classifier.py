#!/usr/bin/env python
"""Evaluate LLM zero-shot threat-report classification on a JSONL dataset."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from sentinel_ml.data.loaders import load_threat_reports_jsonl
from sentinel_ml.eval.llm_threat_benchmark import (
    DEFAULT_THREAT_LABELS,
    evaluate_llm_threat_classifier,
    select_test_reports,
)


def main(
    dataset: Annotated[Path, typer.Argument(help="JSONL with labeled ThreatReport objects")] = Path(
        "data/real_threat_reports.jsonl"
    ),
    limit: Annotated[int | None, typer.Option(help="Optional max number of reports to evaluate")] = None,
    test_size: Annotated[float, typer.Option(help="Test split share matching the baseline evaluation")] = 0.2,
    random_state: Annotated[int, typer.Option(help="Random seed for selecting the test split")] = 42,
    full_dataset: Annotated[bool, typer.Option(help="Evaluate on the full dataset instead of the test split")] = False,
    temperature: Annotated[float, typer.Option(help="LLM sampling temperature")] = 0.0,
) -> None:
    reports = list(load_threat_reports_jsonl(dataset))
    evaluated_reports = reports if full_dataset else select_test_reports(
        reports,
        test_size=test_size,
        random_state=random_state,
    )
    if limit is not None:
        evaluated_reports = evaluated_reports[:limit]

    result = evaluate_llm_threat_classifier(
        evaluated_reports,
        labels=DEFAULT_THREAT_LABELS,
        temperature=temperature,
    )

    typer.echo(f"Model:           {result.model_name}")
    typer.echo(f"Dataset:         {dataset}")
    typer.echo(f"Evaluation set:  {'full dataset' if full_dataset else f'test split ({test_size:.0%})'}")
    typer.echo(f"Reports:         {result.total_reports}")
    typer.echo(f"Accuracy:        {result.metrics.accuracy:.3f}")
    typer.echo(f"Precision-macro: {result.metrics.precision_macro:.3f}")
    typer.echo(f"Recall-macro:    {result.metrics.recall_macro:.3f}")
    typer.echo(f"F1-macro:        {result.metrics.f1_macro:.3f}")
    typer.echo(f"Valid outputs:   {result.valid_outputs}")
    typer.echo(f"Invalid outputs: {result.invalid_outputs}")
    typer.echo(f"Avg latency ms:  {result.avg_latency_ms:.1f}")
    typer.echo("")

    for label in result.labels:
        values = result.metrics.per_class_report.get(label)
        if isinstance(values, dict):
            typer.echo(
                f"{label:12} P={values['precision']:.2f}  "
                f"R={values['recall']:.2f}  "
                f"F1={values['f1-score']:.2f}  "
                f"n={int(values['support'])}"
            )


if __name__ == "__main__":
    typer.run(main)
