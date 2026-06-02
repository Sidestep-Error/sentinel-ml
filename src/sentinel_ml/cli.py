"""Command-line interface.

Usage:
  python -m sentinel_ml.cli extract-iocs <file>
  python -m sentinel_ml.cli train threat-classifier --dataset <jsonl>
  python -m sentinel_ml.cli version
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from sentinel_ml import __version__
from sentinel_ml.data.loaders import load_threat_reports_jsonl
from sentinel_ml.features.ioc_extract import extract_iocs
from sentinel_ml.log_anomaly import tfidf_detector
from sentinel_ml.log_anomaly import train as log_anomaly_train
from sentinel_ml.models import threat_classifier

app = typer.Typer(no_args_is_help=True, add_completion=False, help="Sentinel ML CLI")
train_app = typer.Typer(no_args_is_help=True, help="Train models")
app.add_typer(train_app, name="train")


@app.command()
def version() -> None:
    """Print package version."""
    typer.echo(__version__)


@app.command("extract-iocs")
def extract_iocs_cmd(path: Path) -> None:
    """Extract IOCs from a text file and emit JSON to stdout."""
    text = path.read_text(encoding="utf-8")
    iocs = extract_iocs(text)
    typer.echo(json.dumps([i.model_dump(mode="json") for i in iocs], indent=2))


@train_app.command("threat-classifier")
def train_threat_classifier(
    dataset: Annotated[Path, typer.Option(help="JSONL with ThreatReport objects")],
    out: Annotated[Path, typer.Option()] = Path("models_store/threat_classifier.joblib"),
) -> None:
    """Train the baseline TF-IDF + LR threat classifier."""
    reports = list(load_threat_reports_jsonl(dataset))
    if not reports:
        typer.echo("No reports loaded — aborting.", err=True)
        raise typer.Exit(code=1)

    texts = [r.text for r in reports]
    # Use the first label per report; multi-label support comes in Fas 2.
    labels = [r.labels[0] if r.labels else "other" for r in reports]

    pipeline = threat_classifier.train(texts, labels)
    threat_classifier.save(pipeline, out)
    typer.echo(f"Saved classifier to {out}")


@train_app.command("log-anomaly")
def train_log_anomaly(
    dataset: Annotated[
        Path | None,
        typer.Option(help="CSV with 'line' and optional 'label' columns (auto-generated if absent)"),
    ] = None,
    out: Annotated[
        Path | None,
        typer.Option(help="Output path for joblib artifact"),
    ] = None,
    contamination: Annotated[float, typer.Option(help="Expected anomaly fraction")] = 0.2,
) -> None:
    """Train the TF-IDF + IsolationForest log anomaly detector."""
    log_anomaly_train.run(csv_path=dataset, out_path=out, contamination=contamination)


@app.command("detect-anomalies")
def detect_anomalies_cmd(
    dataset: Annotated[Path, typer.Argument(help="CSV with 'line' column to score")],
    model: Annotated[
        Path | None,
        typer.Option(help="Path to trained joblib artifact"),
    ] = None,
) -> None:
    """Score log lines in a CSV and print anomalies as JSON."""
    from sentinel_ml.config import get_settings
    from sentinel_ml.log_anomaly.generate_data import load_csv

    settings = get_settings()
    artifact = model or Path(settings.models_dir) / tfidf_detector.LOG_ANOMALY_ARTIFACT
    if not artifact.exists():
        typer.echo(f"Modell saknas: {artifact}. Kör: sentinel-ml train log-anomaly", err=True)
        raise typer.Exit(code=1)

    pipeline = tfidf_detector.load(artifact)
    records = load_csv(dataset)
    lines = [r["line"] for r in records]
    results = tfidf_detector.predict(pipeline, lines)
    anomalies = [r for r in results if r["is_anomaly"]]
    typer.echo(json.dumps(anomalies, indent=2, ensure_ascii=False))
    typer.echo(f"\nDetekterade {len(anomalies)} av {len(results)} loggrader som anomalier", err=True)


@app.command("attack-demo")
def attack_demo_cmd(
    model: Annotated[
        Path | None,
        typer.Option(help="Path to trained joblib artifact"),
    ] = None,
) -> None:
    """Run the mimicry attack demo against the TF-IDF log anomaly detector."""
    from sentinel_ml.log_anomaly.attack import demo

    demo(model_path=model)


if __name__ == "__main__":
    app()
