"""Träna en KALIBRERAD upload-classifier + ärlig utvärdering.

Varför (se docs/upload-classifier-honest-training.md):
- Med trivialt separerbar syntetisk data blev F1=1.00 och confidence 0.96-1.00
  på allt — oärligt. Den riktiga MalwareBazaar-datan (mest malicious OFFICE-filer)
  överlappar med clean office-filer, så modellen tvingas lära sig mer än "filtyp".
- CalibratedClassifierCV gör confidence till en ärlig sannolikhet i stället för
  nära 1.00 på allt.

Utvärdering rapporteras på ett held-out-set: per-klass precision/recall/F1,
confusion matrix, Brier score (kalibrering) och medel-confidence.

Förutsätter data/upload_training_data.jsonl (kör generate_upload_training_data.py).
Sparar en API-kompatibel modell (predict_proba + classes_) till models_store/.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import numpy as np
import typer
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import brier_score_loss, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from sentinel_ml.data.schemas import UploadRecord
from sentinel_ml.features.upload_meta import build_feature_matrix
from sentinel_ml.models import upload_classifier


def _load(path: Path) -> tuple[list[UploadRecord], list[str]]:
    records, labels = [], []
    with Path(path).open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            label = raw.pop("label")
            try:
                records.append(UploadRecord.model_validate(raw))
                labels.append(label)
            except Exception as exc:  # noqa: BLE001
                typer.echo(f"Hoppar över: {exc}", err=True)
    return records, labels


def main(
    dataset: Path = typer.Argument(Path("data/upload_training_data.jsonl")),
    out: Path = typer.Option(Path("models_store/upload_classifier.joblib")),
    test_size: float = typer.Option(0.2),
) -> None:
    records, labels = _load(dataset)
    typer.echo(f"Laddade {len(records)} poster | klassfördelning: {dict(Counter(labels))}")

    features, cols = build_feature_matrix(records)
    y = np.array(labels)
    x_tr, x_te, y_tr, y_te = train_test_split(
        features, y, test_size=test_size, random_state=42, stratify=y
    )

    # Kalibrerad RF — samma bas-estimator som prod (class_weight="balanced"),
    # men sannolikheterna kalibreras via 5-fold isotonic regression.
    base = upload_classifier.build_estimator(random_state=42)
    clf = CalibratedClassifierCV(base, method="isotonic", cv=5)
    clf.fit(x_tr, y_tr)
    upload_classifier.save(clf, out)
    typer.echo(f"\nKalibrerad modell sparad: {out}")

    y_pred = clf.predict(x_te)
    print("\n== Utvärdering (held-out 20%) ==")
    print(classification_report(y_te, y_pred, digits=3))

    classes = list(clf.classes_)
    print(f"Confusion matrix (rader=sant, kolumner=pred) {classes}:")
    print(confusion_matrix(y_te, y_pred, labels=classes))

    # Kalibrering: Brier score för 'rejected'-sannolikheten (0=perfekt, 0.25=slump)
    proba = clf.predict_proba(x_te)
    rej = classes.index("rejected")
    brier = brier_score_loss((y_te == "rejected").astype(int), proba[:, rej])
    print(f"\nBrier score (rejected): {brier:.4f}   (lägre = ärligare sannolikheter)")
    print(f"Medel-confidence:       {proba.max(axis=1).mean():.3f}   (spridd/lägre = ärligare än ~1.00 på allt)")

    # Feature importance (från en plain RF — CalibratedClassifierCV saknar attributet)
    base.fit(x_tr, y_tr)
    print("\nFeature importance:")
    for name, imp in sorted(zip(cols, base.feature_importances_), key=lambda kv: -kv[1]):
        print(f"  {name:40} {imp:.3f}")


if __name__ == "__main__":
    typer.run(main)
