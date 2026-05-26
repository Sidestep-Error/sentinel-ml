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


if __name__ == "__main__":
    app()
