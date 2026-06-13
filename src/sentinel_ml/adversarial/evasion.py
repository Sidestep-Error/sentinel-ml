"""Evasion attacks against Spår B (upload classifier).

Includes both a numeric random-noise baseline and a metadata mimicry attack
that stays inside the valid UploadRecord domain.
"""

from __future__ import annotations

from collections.abc import Iterable

import numpy as np

from sentinel_ml.data.schemas import UploadRecord


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


def mimic_upload_metadata(
    record: UploadRecord,
    *,
    filename: str = "quarterly_report.pdf",
    content_type: str = "application/pdf",
    size_bytes: int = 500_000,
) -> UploadRecord:
    """Make attacker-controlled metadata look like a common benign upload.

    Security-derived fields such as sha256, scan_status and risk_score are
    deliberately preserved because an uploader cannot directly rewrite them.
    """
    return record.model_copy(
        update={
            "filename": filename,
            "content_type": content_type,
            "size_bytes": size_bytes,
        }
    )


def mimic_uploads(records: Iterable[UploadRecord]) -> list[UploadRecord]:
    """Apply the same reproducible benign-looking profile to many uploads."""
    return [mimic_upload_metadata(record) for record in records]
