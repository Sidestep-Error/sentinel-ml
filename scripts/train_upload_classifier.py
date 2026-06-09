"""Träna upload-klassificeraren på genererad träningsdata.

Förväntar sig data/upload_training_data.jsonl — kör generate_upload_training_data.py
först om den saknas.

Usage:
  python scripts/train_upload_classifier.py
  python scripts/train_upload_classifier.py --dataset data/upload_training_data.jsonl
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import typer
from sklearn.model_selection import train_test_split

from sentinel_ml.data.schemas import UploadRecord
from sentinel_ml.eval.metrics import evaluate_classifier
from sentinel_ml.features.upload_meta import build_feature_matrix
from sentinel_ml.models import upload_classifier


def _load(path: Path) -> tuple[list[UploadRecord], list[str]]:
    records, labels = [], []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            label = raw.pop("label")
            try:
                records.append(UploadRecord.model_validate(raw))
                labels.append(label)
            except Exception as exc:
                typer.echo(f"Hoppar över felaktigt dokument: {exc}", err=True)
    return records, labels


def main(
    dataset: Path = typer.Argument(Path("data/upload_training_data.jsonl")),
    out: Path = typer.Option(Path("models_store/upload_classifier.joblib")),
    test_size: float = typer.Option(0.2),
) -> None:
    if not dataset.exists():
        typer.echo(f"Dataset saknas: {dataset}. Kör: python scripts/generate_upload_training_data.py", err=True)
        raise typer.Exit(1)

    records, labels = _load(dataset)
    typer.echo(f"Laddade {len(records)} poster")
    typer.echo(f"Klassfördelning: {dict(Counter(labels))}")

    features, col_names = build_feature_matrix(records)
    typer.echo(f"Features ({len(col_names)}): {col_names}")

    X_train, X_test, y_train, y_test = train_test_split(
        features, labels, test_size=test_size, random_state=42, stratify=labels
    )

    clf = upload_classifier.train(X_train, y_train)
    upload_classifier.save(clf, out)
    typer.echo(f"\nModell sparad: {out}")

    y_pred = clf.predict(X_test)
    m = evaluate_classifier(y_test, y_pred)

    print(f"\nAccuracy:         {m.accuracy:.3f}")
    print(f"Precision-macro:  {m.precision_macro:.3f}")
    print(f"Recall-macro:     {m.recall_macro:.3f}")
    print(f"F1-macro:         {m.f1_macro:.3f}")
    print()
    for cls, vals in m.per_class_report.items():
        if isinstance(vals, dict):
            print(
                f"  {cls:12} P={vals['precision']:.2f}  "
                f"R={vals['recall']:.2f}  F1={vals['f1-score']:.2f}  n={int(vals['support'])}"
            )

    # Feature importance
    importances = sorted(
        zip(col_names, clf.feature_importances_),
        key=lambda x: x[1],
        reverse=True,
    )
    print("\nFeature importance:")
    for name, imp in importances:
        bar = "█" * int(imp * 40)
        print(f"  {name:40} {imp:.3f} {bar}")


if __name__ == "__main__":
    typer.run(main)
