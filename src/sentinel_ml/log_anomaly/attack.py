"""Mimicry attack demonstration against the TF-IDF log anomaly detector.

Keyword-based TF-IDF detection is vulnerable to paraphrasing: attack logs can
be camouflaged by prepending/appending benign-looking tokens. This module
demonstrates that vulnerability following the r87-e/ais-grupp-logganomali
adversarial testing approach and satisfies the VG robustness requirement.
"""

from __future__ import annotations

import random
from pathlib import Path

from sklearn.pipeline import Pipeline

from sentinel_ml.log_anomaly import tfidf_detector

_BENIGN_PREFIXES = [
    "systemd[1]: Started ",
    "cron[1234]: (root) CMD ",
    "sshd[5678]: Accepted password for ubuntu from 10.0.0.1 port 22 ssh2 ",
    "kernel: [UFW ALLOW] IN=eth0 -- ",
    "ntpd: synchronized to 10.0.0.1 -- ",
]

_BENIGN_SUFFIXES = [
    " -- normal operation",
    " -- scheduled maintenance",
    " -- authorized access",
    " -- backup job completed",
    " -- routine audit",
]


def camouflage(log_line: str, rng: random.Random | None = None) -> str:
    """Rewrite an attack log line with benign-looking prefix and suffix."""
    _rng = rng or random.Random(42)
    return f"{_rng.choice(_BENIGN_PREFIXES)}{log_line}{_rng.choice(_BENIGN_SUFFIXES)}"


def run_attack(
    pipeline: Pipeline,
    attack_logs: list[str],
    *,
    seed: int = 42,
) -> dict:
    """Evaluate mimicry attack effectiveness before and after camouflage.

    Returns a dict with detection counts and evasion rates.
    """
    if not attack_logs:
        return {
            "n_attack_logs": 0,
            "detected_before": 0,
            "detected_after": 0,
            "evasion_rate_before": 0.0,
            "evasion_rate_after": 0.0,
            "camouflaged_examples": [],
        }

    rng = random.Random(seed)

    original_results = tfidf_detector.predict(pipeline, attack_logs)
    detected_before = sum(1 for r in original_results if r["is_anomaly"])

    camouflaged = [camouflage(line, rng=rng) for line in attack_logs]
    camouflaged_results = tfidf_detector.predict(pipeline, camouflaged)
    detected_after = sum(1 for r in camouflaged_results if r["is_anomaly"])

    n = len(attack_logs)
    return {
        "n_attack_logs": n,
        "detected_before": detected_before,
        "detected_after": detected_after,
        "evasion_rate_before": round(1 - detected_before / n, 3),
        "evasion_rate_after": round(1 - detected_after / n, 3),
        "camouflaged_examples": camouflaged[:3],
    }


def demo(model_path: Path | None = None, seed: int = 42) -> None:
    """Print a mimicry attack demo against the trained TF-IDF model."""
    from sentinel_ml.config import get_settings
    from sentinel_ml.log_anomaly.generate_data import generate_logs

    settings = get_settings()
    artifact = model_path or Path(settings.models_dir) / tfidf_detector.LOG_ANOMALY_ARTIFACT

    if not artifact.exists():
        print(f"Ingen tränad modell hittad på {artifact}.")
        print("Kör: sentinel-ml train log-anomaly")
        return

    pipeline = tfidf_detector.load(artifact)
    attack_logs = [r["line"] for r in generate_logs(n_normal=0, n_attack=50, seed=seed)]
    stats = run_attack(pipeline, attack_logs, seed=seed)

    print("=" * 60)
    print("Mimicry Attack Demo — TF-IDF Log Anomaly Detector")
    print("=" * 60)
    print(f"Attackloggar:              {stats['n_attack_logs']}")
    print(f"Detekterade (original):    {stats['detected_before']}  "
          f"({(1 - stats['evasion_rate_before']) * 100:.0f}% detektionsgrad)")
    print(f"Detekterade (kamuflerade): {stats['detected_after']}  "
          f"({(1 - stats['evasion_rate_after']) * 100:.0f}% detektionsgrad)")
    print(f"Undanmanöverfrekvens:      {stats['evasion_rate_after'] * 100:.0f}%")
    print("\nExempel på kamuflerade loggar:")
    for ex in stats["camouflaged_examples"]:
        print(f"  {ex}")
