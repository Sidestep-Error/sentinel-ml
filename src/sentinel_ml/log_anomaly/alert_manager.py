"""Alert classification and routing for anomaly detection results."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import pandas as pd

_THRESHOLDS: dict[str, dict[str, float]] = {
    "critical": {"zscore": 3.0, "isolation_score": -0.3},
    "high":     {"zscore": 2.5, "isolation_score": -0.2},
    "medium":   {"zscore": 2.0, "isolation_score": -0.1},
}


def classify_alert(zscore: float, isolation_score: float) -> str | None:
    """Return the highest matching severity level, or None if below all thresholds."""
    for level, thresholds in sorted(
        _THRESHOLDS.items(), key=lambda item: item[1]["zscore"], reverse=True
    ):
        if abs(zscore) >= thresholds["zscore"] or isolation_score <= thresholds["isolation_score"]:
            return level
    return None


def create_alert(timestamp: Any, severity: str, details: dict[str, Any]) -> dict[str, Any]:
    return {
        "timestamp": str(timestamp),
        "severity": severity,
        "detected_at": datetime.now().isoformat(),
        "details": details,
    }


def process_anomaly_features(features: pd.DataFrame) -> list[dict[str, Any]]:
    """Convert a features DataFrame (from detector.py) into structured alert dicts."""
    alerts: list[dict[str, Any]] = []
    for idx, row in features.iterrows():
        severity = classify_alert(float(row["event_count_zscore"]), float(row["anomaly_score"]))
        if severity:
            alerts.append(create_alert(idx, severity, {
                "event_count": int(row["event_count"]),
                "avg_severity": round(float(row["avg_severity"]), 2),
                "unique_ips": int(row["unique_ips"]),
                "anomaly_score": round(float(row["anomaly_score"]), 4),
                "zscore": round(float(row["event_count_zscore"]), 2),
            }))
    return alerts
