"""Evaluation metrics.

Single source of truth for how we score every model. Anything that ends up
in the technical report goes through here so numbers are comparable across
runs.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


@dataclass
class ClassificationMetrics:
    accuracy: float
    precision_macro: float
    recall_macro: float
    f1_macro: float
    per_class_report: dict
    confusion: list[list[int]]


def evaluate_classifier(
    y_true: Sequence[str], y_pred: Sequence[str], *, labels: Sequence[str] | None = None
) -> ClassificationMetrics:
    """Compute the metrics we report in the technical document."""
    return ClassificationMetrics(
        accuracy=accuracy_score(y_true, y_pred),
        precision_macro=precision_score(y_true, y_pred, average="macro", zero_division=0),
        recall_macro=recall_score(y_true, y_pred, average="macro", zero_division=0),
        f1_macro=f1_score(y_true, y_pred, average="macro", zero_division=0),
        per_class_report=classification_report(
            y_true, y_pred, labels=list(labels) if labels else None, output_dict=True, zero_division=0
        ),
        confusion=confusion_matrix(y_true, y_pred, labels=list(labels) if labels else None).tolist(),
    )
