"""Quick eval script — train/test split on a threat report dataset."""
from pathlib import Path

import typer
from sklearn.model_selection import train_test_split

from sentinel_ml.data.loaders import load_threat_reports_jsonl
from sentinel_ml.eval.metrics import evaluate_classifier
from sentinel_ml.models import threat_classifier


def main(dataset: Path = typer.Argument(Path("data/threat_reports_sample.jsonl"))) -> None:
    reports = list(load_threat_reports_jsonl(dataset))
    texts = [r.text for r in reports]
    labels = [r.labels[0] if r.labels else "other" for r in reports]

    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42)
    pipe = threat_classifier.train(X_train, y_train)
    y_pred = pipe.predict(X_test)

    m = evaluate_classifier(y_test, y_pred)
    print(f"Accuracy:  {m.accuracy:.3f}")
    print(f"Precision: {m.precision_macro:.3f}")
    print(f"Recall:    {m.recall_macro:.3f}")
    print(f"F1:        {m.f1_macro:.3f}")
    print()
    for cls, vals in m.per_class_report.items():
        if isinstance(vals, dict):
            print(f"{cls:12} P={vals['precision']:.2f}  R={vals['recall']:.2f}  F1={vals['f1-score']:.2f}  n={int(vals['support'])}")


if __name__ == "__main__":
    typer.run(main)
