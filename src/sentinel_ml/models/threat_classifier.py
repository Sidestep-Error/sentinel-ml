"""Threat-report classifier (Spar A baseline).

TF-IDF + LogisticRegression. Deliberately simple so we have a credible
floor to beat with spaCy NER / LLM in Fas 2.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from sentinel_ml.config import get_settings


def build_pipeline(random_state: int | None = None) -> Pipeline:
    """Construct the TF-IDF + LR pipeline. Same shape used for fit and inference."""
    seed = random_state if random_state is not None else get_settings().seed
    return Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    ngram_range=(1, 2),
                    min_df=2,
                    max_df=0.95,
                    sublinear_tf=True,
                    strip_accents="unicode",
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    max_iter=1000,
                    class_weight="balanced",
                    random_state=seed,
                ),
            ),
        ]
    )


def train(texts: Sequence[str], labels: Sequence[str]) -> Pipeline:
    """Fit a fresh pipeline. Returns the trained pipeline."""
    pipe = build_pipeline()
    pipe.fit(list(texts), list(labels))
    return pipe


def save(pipeline: Pipeline, path: str | Path) -> None:
    """Persist a trained pipeline to disk."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, path)


def load(path: str | Path) -> Pipeline:
    """Load a previously trained pipeline."""
    return joblib.load(path)
