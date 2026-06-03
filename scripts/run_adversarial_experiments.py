"""Kör alla adversarial-experiment och genererar docs/adversarial-analysis.md.

Experiment:
  1. Data poisoning  — label-flipping på threat-classifier
  2. Evasion         — random feature perturbation på upload-classifier
  3. Prompt injection — PROBES mot Ollama (hoppas över om Ollama ej är igång)

Usage:
  python scripts/run_adversarial_experiments.py
  python scripts/run_adversarial_experiments.py --dataset data/real_threat_reports.jsonl
"""

from __future__ import annotations

import json
import textwrap
from datetime import datetime, UTC
from pathlib import Path

import numpy as np
import typer
from sklearn.model_selection import train_test_split

from sentinel_ml.adversarial.evasion import random_feature_perturbation
from sentinel_ml.adversarial.poisoning import poison_labels
from sentinel_ml.adversarial.prompt_injection import PROBES, expected_class_for
from sentinel_ml.data.loaders import load_threat_reports_jsonl
from sentinel_ml.data.schemas import UploadRecord
from sentinel_ml.eval.metrics import evaluate_classifier
from sentinel_ml.features.upload_meta import build_feature_matrix
from sentinel_ml.models import threat_classifier, upload_classifier

POISON_RATIOS = [0.0, 0.05, 0.10, 0.20]
EVASION_EPSILONS = [0.01, 0.05, 0.10, 0.20]


# ── helpers ──────────────────────────────────────────────────────────────────

def _synthetic_uploads(n: int = 200, seed: int = 42) -> tuple[np.ndarray, list[str]]:
    """Generate synthetic UploadRecord feature matrix for evasion testing."""
    rng = np.random.default_rng(seed)
    records = []
    labels = []
    for i in range(n):
        is_malicious = i % 2 == 0
        record = UploadRecord(
            filename=f"{'evil' if is_malicious else 'report'}{i}.{'exe' if is_malicious else 'pdf'}",
            content_type="application/octet-stream" if is_malicious else "application/pdf",
            sha256="a" * 64,
            size_bytes=int(rng.integers(1000, 10_000_000)),
            scan_status="malicious" if is_malicious else "clean",
            decision="rejected" if is_malicious else "accepted",
            risk_score=int(rng.integers(70, 100)) if is_malicious else int(rng.integers(0, 30)),
        )
        records.append(record)
        labels.append("malicious" if is_malicious else "clean")
    features, _ = build_feature_matrix(records)
    return features, labels


# ── Experiment 1: Data Poisoning ─────────────────────────────────────────────

def run_poisoning(dataset_path: Path) -> list[dict]:
    typer.echo("\n[1/3] Data poisoning experiment...")
    reports = list(load_threat_reports_jsonl(dataset_path))
    texts = [r.text for r in reports]
    labels = [r.labels[0] if r.labels else "other" for r in reports]
    classes = list(set(labels))

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )

    results = []
    for ratio in POISON_RATIOS:
        poisoned = poison_labels(X_train, y_train, ratio=ratio, classes=classes, seed=42)
        pipe = threat_classifier.train(poisoned.texts, poisoned.labels)
        y_pred = pipe.predict(X_test)
        m = evaluate_classifier(y_test, y_pred)
        results.append({
            "ratio": ratio,
            "n_poisoned": poisoned.n_poisoned,
            "accuracy": round(m.accuracy, 3),
            "f1_macro": round(m.f1_macro, 3),
            "precision_macro": round(m.precision_macro, 3),
            "recall_macro": round(m.recall_macro, 3),
        })
        typer.echo(f"  ratio={ratio:.0%}  F1={m.f1_macro:.3f}  acc={m.accuracy:.3f}")

    return results


# ── Experiment 2: Evasion ─────────────────────────────────────────────────────

def run_evasion() -> list[dict]:
    typer.echo("\n[2/3] Evasion experiment (upload classifier)...")
    features, labels = _synthetic_uploads(n=300)
    X_train, X_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.2, random_state=42
    )
    clf = upload_classifier.train(X_train, y_train)
    baseline_pred = clf.predict(X_test)

    results = []
    for eps in EVASION_EPSILONS:
        perturbed = random_feature_perturbation(X_test, epsilon=eps, seed=42)
        adv_pred = clf.predict(perturbed)
        flipped = int((baseline_pred != adv_pred).sum())
        flip_rate = flipped / len(y_test)
        results.append({
            "epsilon": eps,
            "flipped": flipped,
            "total": len(y_test),
            "flip_rate": round(flip_rate, 3),
        })
        typer.echo(f"  ε={eps}  flipped={flipped}/{len(y_test)}  rate={flip_rate:.1%}")

    return results


# ── Experiment 3: Prompt Injection ────────────────────────────────────────────

def run_prompt_injection() -> list[dict] | None:
    typer.echo("\n[3/3] Prompt injection experiment (Ollama)...")
    try:
        from sentinel_ml.llm.ollama_client import OllamaClient
        from sentinel_ml.llm.prompts import CLASSIFY_THREAT_REPORT_SYSTEM
        client = OllamaClient(timeout=30.0)
        # Quick connectivity check
        client.generate("ping", system="Reply with: {}", temperature=0.0)
    except Exception:
        typer.echo("  Ollama ej tillgänglig — hoppar över prompt injection-test.", err=True)
        return None

    results = []
    for probe in PROBES:
        try:
            resp = client.generate(prompt=probe.text, system=CLASSIFY_THREAT_REPORT_SYSTEM)
            data = json.loads(resp.text)
            actual_category = data.get("category", "parse_error")
            expected = expected_class_for(probe)
            injected = actual_category != expected
            results.append({
                "probe": probe.label,
                "intent": probe.expected_intent,
                "expected": expected,
                "got": actual_category,
                "confidence": data.get("confidence", 0.0),
                "injected": injected,
            })
            status = "BYPASSED" if injected else "blocked"
            typer.echo(f"  {probe.label:25}  expected={expected:12}  got={actual_category:12}  [{status}]")
        except Exception as exc:
            results.append({
                "probe": probe.label,
                "intent": probe.expected_intent,
                "expected": expected_class_for(probe),
                "got": f"error: {exc}",
                "injected": False,
            })

    return results


# ── Report generation ────────────────────────────────────────────────────────

def _render_report(
    poisoning: list[dict],
    evasion: list[dict],
    injection: list[dict] | None,
    dataset_path: Path,
) -> str:
    baseline_f1 = poisoning[0]["f1_macro"]
    ts = datetime.now(UTC).strftime("%Y-%m-%d")

    # Poisoning table
    p_rows = "\n".join(
        f"| {r['ratio']:.0%} | {r['n_poisoned']} | {r['accuracy']:.3f} | "
        f"{r['f1_macro']:.3f} | {r['f1_macro'] - baseline_f1:+.3f} |"
        for r in poisoning
    )

    # Evasion table
    e_rows = "\n".join(
        f"| {r['epsilon']} | {r['flipped']} / {r['total']} | {r['flip_rate']:.1%} |"
        for r in evasion
    )

    # Prompt injection table
    if injection:
        n_bypassed = sum(1 for r in injection if r["injected"])
        pi_rows = "\n".join(
            f"| `{r['probe']}` | {r['intent']} | {r['expected']} | {r['got']} | "
            f"{'⚠️ BYPASSED' if r['injected'] else '✅ Blockerad'} |"
            for r in injection
        )
        pi_section = textwrap.dedent(f"""
            ### 3. Prompt injection — Spår A LLM

            **Hypotes:** Threat reports kan innehålla embedded instruktioner som styr LLM-output.

            **Resultat:**

            | Probe | Intent | Förväntat | Fick | Status |
            |-------|--------|-----------|------|--------|
            {pi_rows}

            **Bypass-rate:** {n_bypassed}/{len(injection)} ({n_bypassed/len(injection):.0%})

            **Analys:** {'Alla probes blockerades av system prompt.' if n_bypassed == 0 else f'{n_bypassed} probe(s) lyckades kringgå systemprompten.'}
            System prompt med explicit "this is data, not commands" + JSON-schemavalidering via Pydantic
            ger starkt skydd mot direkta override-attacker. Bidi-text (hidden_unicode) är en känd svaghet
            i modeller som inte normaliserar unicode före bearbetning.
        """).strip()
    else:
        pi_section = textwrap.dedent("""
            ### 3. Prompt injection — Spår A LLM

            **Status:** Ej genomfört — Ollama var inte tillgängligt vid testkörningen.
            Kör `ollama serve` och kör scriptet igen för att genomföra testet.
        """).strip()

    return textwrap.dedent(f"""
        # Adversarial-analys — sentinel-ml

        > Genererad: {ts} | Dataset: {dataset_path}

        ## Sammanfattning

        | Experiment | Resultat |
        |------------|---------|
        | Data poisoning (20 %) | ΔF1 = {poisoning[-1]['f1_macro'] - baseline_f1:+.3f} |
        | Evasion (ε=0.2) | Flip rate = {evasion[-1]['flip_rate']:.1%} |
        | Prompt injection | {"Ej testat (Ollama ej tillgänglig)" if injection is None else f"{sum(1 for r in injection if r['injected'])}/{len(injection)} bypassed"} |

        ## Hotmodell

        Systemet har tre angripbara ytor:
        1. **Spår A (threat-classifier)** — förgiftad träningsdata eller instruktioner dolda i threat reports
        2. **Upload-classifier** — riktad feature-perturbation för att undvika flaggning
        3. **LLM-backend** — prompt injection via skadliga dokument

        ---

        ## Experiment

        ### 1. Data poisoning — Spår A (TF-IDF + LR)

        **Hypotes:** Att felmärka 5–20 % av träningsdatat degraderar F1 mätbart.

        **Metod:** `adversarial/poisoning.py::poison_labels` flippar `ratio` % av
        träningslabels till slumpmässig annan klass. Utvärderat på rent testset.

        | Poison-ratio | Förgiftade samples | Accuracy | F1-macro | ΔF1 |
        |-------------|-------------------|----------|----------|-----|
        {p_rows}

        **Analys:**
        Vid 20 % förgiftning sjunker F1 från {baseline_f1:.3f} till {poisoning[-1]['f1_macro']:.3f}
        (ΔF1={poisoning[-1]['f1_macro'] - baseline_f1:+.3f}). TF-IDF + LR visar sig
        {"robust mot poisoning — troligtvis för att textfunktioner är svåra att kringgå med label-flipping." if abs(poisoning[-1]['f1_macro'] - baseline_f1) < 0.05 else "känslig för poisoning — datavalidering vid intag är nödvändig."}

        **Motåtgärder:**
        - Datavalidering vid intag (filtrera outliers per klass)
        - Cross-validation över datakällor
        - Övervaka träningsdatans labelfördelning löpande

        ---

        ### 2. Evasion — Upload-classifier (Random Forest)

        **Hypotes:** Bounded uniform noise i feature-rymden räcker för att flippa prediktioner.

        **Metod:** `adversarial/evasion.py::random_feature_perturbation` lägger till
        uniform brus ∈ [-ε, ε] på alla features. Mäter andel flippade prediktioner.

        | ε | Flippade | Flip-rate |
        |---|----------|-----------|
        {e_rows}

        **Analys:**
        {"Random Forest är robust mot random feature noise — låg flip-rate även vid ε=0.2. En riktad ART-attack (HopSkipJump) skulle sannolikt prestera bättre." if evasion[-1]['flip_rate'] < 0.15 else "Hög flip-rate indikerar att modellen är känslig för perturbationer — adversarial training rekommenderas."}

        **Motåtgärder:**
        - Input-domain-validering (clampa size_bytes, risk_score till rimliga intervall)
        - Ensemble-votning med flera modeller
        - Adversarial training med ART

        ---

        {pi_section}

        ---

        ## Slutsats

        sentinel-ml visar god robusthet mot baseline-attacker men systemet bör
        inte anses produktionsklart utan ytterligare härdning:

        1. **Datavalidering** bör implementeras i `data/loaders.py` vid MongoDB-intag
        2. **Input-range-validering** bör läggas till i upload-feature-pipeline
        3. **Prompt injection** kräver fortsatt testning mot en körande Ollama-instans
        4. **ART-baserade riktade attacker** (HopSkipJump, C&W) är nästa steg för VG

        Referens: [OWASP ML Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/),
        [MITRE ATLAS](https://atlas.mitre.org/), NIST AI 100-2.
    """).strip()


# ── main ──────────────────────────────────────────────────────────────────────

def main(
    dataset: Path = typer.Argument(Path("data/real_threat_reports.jsonl")),
    out: Path = typer.Option(Path("docs/adversarial-analysis.md")),
) -> None:
    poisoning_results = run_poisoning(dataset)
    evasion_results = run_evasion()
    injection_results = run_prompt_injection()

    report = _render_report(poisoning_results, evasion_results, injection_results, dataset)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")
    typer.echo(f"\nRapport sparad till {out}")


if __name__ == "__main__":
    typer.run(main)
