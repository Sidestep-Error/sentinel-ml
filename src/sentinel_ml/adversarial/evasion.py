"""Evasion attacks against Spar B (upload classifier).

Stub for Fas 2: real implementation uses ART (adversarial-robustness-toolbox)
to generate feature-space adversarial examples. Kept minimal here so the
package imports cleanly even when ART isn't installed (it's an optional dep).
"""

from __future__ import annotations

import numpy as np


def random_feature_perturbation(
    features: np.ndarray, *, epsilon: float = 0.1, seed: int = 42
) -> np.ndarray:
    """Naive baseline: add bounded uniform noise to every feature.

    Useful as a sanity check before bringing in ART — if even random noise
    flips predictions, the model is over-fit and a real attack is trivial.
    """
    rng = np.random.default_rng(seed)
    noise = rng.uniform(-epsilon, epsilon, size=features.shape).astype(features.dtype)
    return features + noise
