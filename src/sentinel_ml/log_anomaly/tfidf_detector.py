"""TF-IDF + IsolationForest log anomaly detector.

Text-based approach from r87-e/ais-grupp-logganomali: vectorize raw log lines
with TF-IDF, then detect anomalies with IsolationForest. This complements the
structured Wazuh-feature detector in detector.py and enables algorithm
comparison for VG requirements.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline

LOG_ANOMALY_ARTIFACT = "log_anomaly_tfidf.joblib"


def build_pipeline(contamination: float = 0.1, random_state: int = 42) -> Pipeline:
    """Construct a TF-IDF + IsolationForest pipeline."""
    return Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                analyzer="word",
                ngram_range=(1, 2),
                min_df=1,
                max_df=0.95,
                sublinear_tf=True,
            ),
        ),
        (
            "iso",
            IsolationForest(
                n_estimators=100,
                contamination=contamination,
                random_state=random_state,
            ),
        ),
    ])


def train(log_lines: list[str], contamination: float = 0.1, random_state: int = 42) -> Pipeline:
    """Fit a fresh TF-IDF + IsolationForest pipeline on log text lines."""
    pipeline = build_pipeline(contamination=contamination, random_state=random_state)
    pipeline.fit(log_lines)
    return pipeline


def predict(pipeline: Pipeline, log_lines: list[str]) -> list[dict]:
    """Return per-line anomaly results with score and boolean flag."""
    raw = pipeline.predict(log_lines)
    scores = pipeline.decision_function(log_lines)
    return [
        {"line": line, "score": float(score), "is_anomaly": int(pred) == -1}
        for line, pred, score in zip(log_lines, raw, scores, strict=True)
    ]


def evaluate(pipeline: Pipeline, log_lines: list[str], labels: list[str]) -> dict:
    """Compute precision/recall/F1 against binary 'normal'/'attack' labels."""
    results = predict(pipeline, log_lines)
    y_pred = [1 if r["is_anomaly"] else 0 for r in results]
    y_true = [1 if lbl == "attack" else 0 for lbl in labels]
    return {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "n_anomalies": int(np.sum(y_pred)),
        "n_total": len(y_pred),
    }


def save(pipeline: Pipeline, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, path)


def load(path: str | Path) -> Pipeline:
    return joblib.load(path)
