"""Data-poisoning experiments.

Inject mislabeled samples into training data and measure how much the
model's F1 degrades. Output: a table suitable for the technical report.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass
class PoisonedDataset:
    texts: list[str]
    labels: list[str]
    n_poisoned: int
    poison_ratio: float


def poison_labels(
    texts: Sequence[str],
    labels: Sequence[str],
    *,
    ratio: float,
    classes: Sequence[str],
    seed: int = 42,
) -> PoisonedDataset:
    """Flip a fraction of labels to a different class chosen uniformly at random.

    `ratio` is the share of samples whose labels get rewritten (0.0–1.0).
    Returns a new dataset; inputs are not mutated.
    """
    if not 0.0 <= ratio <= 1.0:
        raise ValueError("ratio must be in [0.0, 1.0]")

    rng = random.Random(seed)
    new_texts = list(texts)
    new_labels = list(labels)

    n = len(new_labels)
    n_poison = int(n * ratio)
    indices = rng.sample(range(n), k=n_poison)

    for i in indices:
        original = new_labels[i]
        alternatives = [c for c in classes if c != original]
        new_labels[i] = rng.choice(alternatives)

    return PoisonedDataset(
        texts=new_texts,
        labels=new_labels,
        n_poisoned=n_poison,
        poison_ratio=ratio,
    )
