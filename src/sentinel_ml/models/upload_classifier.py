"""Upload classifier (Spar B baseline).

Random Forest on numeric features extracted from UploadRecord. Designed to
complement ClamAV — flag uploads that look statistically anomalous even
when no malware signature matches.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from sentinel_ml.config import get_settings


def build_estimator(random_state: int | None = None) -> RandomForestClassifier:
    seed = random_state if random_state is not None else get_settings().seed
    return RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        n_jobs=-1,
        random_state=seed,
    )


def train(features: np.ndarray, labels: Sequence[str]) -> RandomForestClassifier:
    clf = build_estimator()
    clf.fit(features, list(labels))
    return clf


def save(model: RandomForestClassifier, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)


def load(path: str | Path) -> RandomForestClassifier:
    return joblib.load(path)
