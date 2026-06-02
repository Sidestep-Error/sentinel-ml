"""Training entry point for the TF-IDF + IsolationForest log anomaly detector.

Generates synthetic logs.csv if none exists, trains the model, reports
precision/recall/F1, and saves the artifact to models_store/.
"""

from __future__ import annotations

from pathlib import Path

from sentinel_ml.config import get_settings
from sentinel_ml.log_anomaly import generate_data, tfidf_detector


def run(
    csv_path: Path | None = None,
    out_path: Path | None = None,
    contamination: float = 0.2,
    seed: int | None = None,
) -> dict:
    """Train the log anomaly TF-IDF model. Returns evaluation metrics dict."""
    settings = get_settings()
    effective_seed = seed if seed is not None else settings.seed

    log_csv = csv_path or Path(settings.data_dir) / "logs.csv"
    artifact = out_path or Path(settings.models_dir) / tfidf_detector.LOG_ANOMALY_ARTIFACT

    if not log_csv.exists():
        print(f"{log_csv} saknas — genererar syntetisk data...")
        records = generate_data.generate_logs(n_normal=800, n_attack=200, seed=effective_seed)
        generate_data.save_csv(records, log_csv)
        print(f"Sparade {len(records)} loggrader till {log_csv}")

    records = generate_data.load_csv(log_csv)
    lines = [r["line"] for r in records]
    labels = [r.get("label", "normal") for r in records]

    n_attack = labels.count("attack")
    n_normal = labels.count("normal")
    print(f"Tränar på {len(lines)} loggrader ({n_attack} attack, {n_normal} normal)...")

    pipeline = tfidf_detector.train(lines, contamination=contamination, random_state=effective_seed)
    metrics = tfidf_detector.evaluate(pipeline, lines, labels)

    print(
        f"Precision: {metrics['precision']:.3f}  "
        f"Recall: {metrics['recall']:.3f}  "
        f"F1: {metrics['f1']:.3f}"
    )
    print(f"Detekterade {metrics['n_anomalies']} av {metrics['n_total']} loggrader som anomalier")

    tfidf_detector.save(pipeline, artifact)
    print(f"Modell sparad: {artifact}")
    return metrics
