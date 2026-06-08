"""Structured Wazuh-alert anomaly detector.

Reads Wazuh alert JSON (Elasticsearch hits format), extracts time-windowed
features, and applies IsolationForest + z-score statistical baseline.
Provides the structured-features counterpart to the TF-IDF detector in
tfidf_detector.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

_FEATURE_COLS = [
    "event_count",
    "unique_rules",
    "avg_severity",
    "max_severity",
    "unique_ips",
    "unique_ports",
    "is_night",
    "event_count_zscore",
]


def load_alerts(file_path: str | Path) -> pd.DataFrame:
    """Load Wazuh alerts from Elasticsearch hits JSON into a DataFrame."""
    with open(file_path, encoding="utf-8") as f:
        data = json.load(f)

    records = []
    for hit in data.get("hits", {}).get("hits", []):
        source = hit.get("_source", {})
        records.append({
            "timestamp": source.get("timestamp", ""),
            "rule_id": source.get("rule", {}).get("id", 0),
            "rule_level": source.get("rule", {}).get("level", 0),
            "description": source.get("rule", {}).get("description", ""),
            "src_ip": source.get("data", {}).get("srcip", "unknown"),
            "dst_port": source.get("data", {}).get("dstport", 0),
            "agent_name": source.get("agent", {}).get("name", "unknown"),
        })

    df = pd.DataFrame(records)
    if df.empty:
        return df
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["rule_level"] = pd.to_numeric(df["rule_level"], errors="coerce").fillna(0)
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce").fillna(0)
    return df.dropna(subset=["timestamp"])


def extract_features(df: pd.DataFrame, window: str = "1h") -> pd.DataFrame:
    """Aggregate raw alerts into time-windowed feature vectors."""
    if df.empty:
        return pd.DataFrame()

    features = (
        df.set_index("timestamp")
        .sort_index()
        .resample(window)
        .agg(
            event_count=("rule_id", "count"),
            unique_rules=("rule_id", "nunique"),
            avg_severity=("rule_level", "mean"),
            max_severity=("rule_level", "max"),
            unique_ips=("src_ip", "nunique"),
            unique_ports=("dst_port", "nunique"),
        )
        .fillna(0)
    )

    features["hour"] = features.index.hour
    features["is_night"] = (features["hour"].lt(6) | features["hour"].gt(22)).astype(int)
    features["event_count_rolling_mean"] = features["event_count"].rolling(6, min_periods=1).mean()
    features["event_count_rolling_std"] = (
        features["event_count"].rolling(6, min_periods=1).std().fillna(0)
    )
    mean = features["event_count"].mean()
    std = features["event_count"].std()
    scale = std if pd.notna(std) and std > 0 else 1.0
    features["event_count_zscore"] = (features["event_count"] - mean) / scale
    return features


def detect_anomalies(features: pd.DataFrame, contamination: float = 0.1) -> pd.DataFrame:
    """Run IsolationForest on the feature matrix and annotate with scores."""
    if features.empty:
        return features
    if len(features) < 2:
        features = features.copy()
        features["anomaly"] = 1
        features["anomaly_score"] = 0.0
        features["is_anomaly"] = False
        return features

    X = StandardScaler().fit_transform(features[_FEATURE_COLS].values)
    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    features = features.copy()
    features["anomaly"] = model.fit_predict(X)
    features["anomaly_score"] = model.decision_function(X)
    features["is_anomaly"] = features["anomaly"] == -1
    return features


def statistical_baseline(features: pd.DataFrame, threshold_sigma: float = 2.0) -> pd.DataFrame:
    """Flag windows where event_count z-score exceeds threshold_sigma."""
    if features.empty:
        features = features.copy()
        features["stat_anomaly"] = pd.Series(dtype=bool)
        return features
    features = features.copy()
    features["stat_anomaly"] = features["event_count_zscore"].abs() > threshold_sigma
    return features


def generate_report(features: pd.DataFrame) -> str:
    """Generate a text report of detected anomalies."""
    if features.empty:
        return "Ingen data kunde analyseras."

    anomalies = features[features["is_anomaly"]]
    stat_anomalies = features[features["stat_anomaly"]]
    lines = [
        "=" * 60,
        "Anomalidetekteringsrapport",
        "=" * 60,
        f"\nAnalyserad period: {features.index.min()} — {features.index.max()}",
        f"Antal tidsperioder: {len(features)}",
        "\n--- Isolation Forest ---",
        f"Anomalier detekterade: {len(anomalies)}",
        "\n--- Statistisk baslinje (z-score) ---",
        f"Statistiska anomalier: {len(stat_anomalies)}",
    ]
    if not anomalies.empty:
        lines.append("\nDetaljer:")
        for idx, row in anomalies.iterrows():
            lines.append(
                f"  {idx}: {int(row['event_count'])} händelser, "
                f"severity {row['avg_severity']:.1f}, "
                f"{int(row['unique_ips'])} unika IP:n, "
                f"score {row['anomaly_score']:.3f}"
            )
    lines.append("\n" + "=" * 60)
    return "\n".join(lines)
