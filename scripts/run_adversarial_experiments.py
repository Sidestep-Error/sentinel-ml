"""Kör alla adversarial-experiment och genererar docs/adversarial-analysis.md.

Experiment:
  1. Data poisoning  — label-flipping på threat-classifier
  2. Evasion         — random feature noise + giltig metadata-mimicry
  3. Prompt injection — PROBES mot Ollama (hoppas över om Ollama ej är igång)

Usage:
  python scripts/run_adversarial_experiments.py
  python scripts/run_adversarial_experiments.py --dataset data/real_threat_reports.jsonl
  python scripts/run_adversarial_experiments.py --upload-dataset data/upload_training_data.jsonl
"""

from __future__ import annotations

import json
import textwrap
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import typer
from sklearn.model_selection import train_test_split

from sentinel_ml.adversarial.evasion import mimic_uploads, random_feature_perturbation
from sentinel_ml.adversarial.poisoning import poison_labels
from sentinel_ml.adversarial.prompt_injection import run_harness
from sentinel_ml.data.loaders import load_threat_reports_jsonl
from sentinel_ml.data.schemas import UploadRecord
from sentinel_ml.eval.metrics import evaluate_classifier
from sentinel_ml.features.upload_meta import build_feature_matrix
from sentinel_ml.models import threat_classifier, upload_classifier

POISON_RATIOS = [0.0, 0.05, 0.10, 0.20]
EVASION_EPSILONS = [0.01, 0.05, 0.10, 0.20]


# ── helpers ──────────────────────────────────────────────────────────────────

def _synthetic_uploads(n: int = 200, seed: int = 42) -> tuple[list[UploadRecord], list[str]]:
    """Generate records for a reproducible metadata-evasion sanity check."""
    rng = np.random.default_rng(seed)
    records = []
    labels = []
    for i in range(n):
        is_malicious = i % 2 == 0
        label = "rejected" if is_malicious else "accepted"
        record = UploadRecord(
            filename=f"{'payload' if is_malicious else 'report'}_{i}.{'exe' if is_malicious else 'pdf'}",
            content_type="application/x-dosexec" if is_malicious else "application/pdf",
            sha256="a" * 64,
            size_bytes=int(rng.integers(1000, 10_000_000)),
            # Both classes simulate files ClamAV did not flag. The metadata
            # model must not receive the answer through security-derived fields.
            scan_status="clean",
            decision=label,
            risk_score=0,
        )
        records.append(record)
        labels.append(label)
    return records, labels


def _load_upload_dataset(path: Path) -> tuple[list[UploadRecord], list[str]]:
    """Load the av-bias:ed upload training JSONL used by the honest pipeline."""
    records: list[UploadRecord] = []
    labels: list[str] = []
    with path.open(encoding="utf-8") as file:
        for line in file:
            raw = json.loads(line)
            label = str(raw.pop("label"))
            records.append(UploadRecord.model_validate(raw))
            labels.append(label)
    return records, labels


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

def run_evasion(dataset_path: Path | None = None) -> list[dict]:
    typer.echo("\n[2/3] Evasion experiment (upload classifier)...")
    if dataset_path is not None and dataset_path.exists():
        records, labels = _load_upload_dataset(dataset_path)
        dataset_source = str(dataset_path)
    else:
        records, labels = _synthetic_uploads(n=300)
        dataset_source = "syntetisk sanity-check"
    typer.echo(f"  dataset={dataset_source}  records={len(records)}")

    train_records, test_records, y_train, y_test = train_test_split(
        records, labels, test_size=0.2, random_state=42, stratify=labels
    )
    X_train, _ = build_feature_matrix(train_records)
    X_test, _ = build_feature_matrix(test_records)
    clf = upload_classifier.train(X_train, y_train)
    baseline_pred = clf.predict(X_test)

    results = []
    for eps in EVASION_EPSILONS:
        perturbed = random_feature_perturbation(X_test, epsilon=eps, seed=42)
        adv_pred = clf.predict(perturbed)
        flipped = int((baseline_pred != adv_pred).sum())
        flip_rate = flipped / len(y_test)
        results.append({
            "attack": "random_noise",
            "parameter": f"ε={eps}",
            "successful": flipped,
            "total": len(y_test),
            "success_rate": round(flip_rate, 3),
            "dataset": dataset_source,
        })
        typer.echo(f"  ε={eps}  flipped={flipped}/{len(y_test)}  rate={flip_rate:.1%}")

    target_indices = [
        idx
        for idx, (label, prediction) in enumerate(zip(y_test, baseline_pred, strict=True))
        if label == "rejected" and prediction == "rejected"
    ]
    target_records = [test_records[idx] for idx in target_indices]
    mimicked_features, _ = build_feature_matrix(mimic_uploads(target_records))
    mimicked_pred = clf.predict(mimicked_features) if target_records else []
    successful = int(sum(prediction == "accepted" for prediction in mimicked_pred))
    total = len(target_records)
    success_rate = successful / total if total else 0.0
    results.append({
        "attack": "metadata_mimicry",
        "parameter": "benign PDF profile",
        "successful": successful,
        "total": total,
        "success_rate": round(success_rate, 3),
        "dataset": dataset_source,
    })
    typer.echo(
        f"  metadata mimicry  evaded={successful}/{total}  rate={success_rate:.1%}"
    )

    return results


def _write_poisoning_svg(results: list[dict], path: Path) -> None:
    """Write a dependency-free line plot of poison ratio against F1-macro."""
    width, height = 720, 420
    left, right, top, bottom = 80, 40, 40, 70
    chart_w = width - left - right
    chart_h = height - top - bottom
    max_ratio = max((result["ratio"] for result in results), default=1.0) or 1.0
    f1_values = [result["f1_macro"] for result in results]
    min_f1 = max(0.0, min(f1_values, default=0.0) - 0.05)
    max_f1 = min(1.0, max(f1_values, default=1.0) + 0.05)
    f1_span = max_f1 - min_f1 or 1.0

    def point(result: dict) -> tuple[float, float]:
        x = left + (result["ratio"] / max_ratio) * chart_w
        y = top + (max_f1 - result["f1_macro"]) / f1_span * chart_h
        return x, y

    points = [point(result) for result in results]
    polyline = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    markers = "\n".join(
        (
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5" fill="#b91c1c"/>'
            f'<text x="{x:.1f}" y="{y - 12:.1f}" text-anchor="middle" '
            f'font-size="13">{result["f1_macro"]:.3f}</text>'
        )
        for result, (x, y) in zip(results, points, strict=True)
    )
    x_labels = "\n".join(
        f'<text x="{x:.1f}" y="{height - 35}" text-anchor="middle" font-size="13">'
        f'{result["ratio"]:.0%}</text>'
        for result, (x, _) in zip(results, points, strict=True)
    )
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">
<rect width="100%" height="100%" fill="white"/>
<text x="{width / 2}" y="24" text-anchor="middle" font-size="18">Data poisoning: F1-macro</text>
<line x1="{left}" y1="{top}" x2="{left}" y2="{height - bottom}" stroke="black"/>
<line x1="{left}" y1="{height - bottom}" x2="{width - right}" y2="{height - bottom}" stroke="black"/>
<text x="20" y="{height / 2}" transform="rotate(-90 20 {height / 2})" text-anchor="middle">F1-macro</text>
<text x="{width / 2}" y="{height - 8}" text-anchor="middle">Poison-ratio</text>
<polyline points="{polyline}" fill="none" stroke="#b91c1c" stroke-width="3"/>
{markers}
{x_labels}
</svg>
"""
    path.write_text(svg, encoding="utf-8")


# ── Experiment 3: Prompt Injection ────────────────────────────────────────────

def run_prompt_injection() -> list[dict] | None:
    typer.echo("\n[3/3] Prompt injection experiment (Ollama)...")
    try:
        from sentinel_ml.llm.ollama_client import OllamaClient

        client = OllamaClient(timeout=30.0)
        # Quick connectivity check
        client.generate("ping", system="Reply with: {}", temperature=0.0)
    except Exception:
        typer.echo("  Ollama ej tillgänglig — hoppar över prompt injection-test.", err=True)
        return None

    summary = run_harness(client=client)
    for result in summary.results:
        got = result.got or "invalid_output"
        typer.echo(
            f"  {result.probe:25}  expected={result.expected:12}  "
            f"got={got:14}  [{result.status.value}]"
        )
    typer.echo(
        f"  injection success={summary.injection_success_rate:.1%}  "
        f"invalid output={summary.invalid_output_rate:.1%}  "
        f"blocked={summary.blocked_rate:.1%}"
    )
    return summary.as_dicts()


# ── Report generation ────────────────────────────────────────────────────────

def _render_report(
    poisoning: list[dict],
    evasion: list[dict],
    injection: list[dict] | None,
    dataset_path: Path,
    poisoning_plot_name: str = "adversarial-poisoning.svg",
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
        f"| `{r['attack']}` | {r['parameter']} | "
        f"{r['successful']} / {r['total']} | {r['success_rate']:.1%} |"
        for r in evasion
    )
    mimicry = next(result for result in evasion if result["attack"] == "metadata_mimicry")

    # Prompt injection table
    if injection:
        n_bypassed = sum(1 for r in injection if r["injected"])
        n_invalid = sum(1 for r in injection if r["status"] == "invalid_output")
        n_blocked = sum(1 for r in injection if r["status"] == "blocked")

        def _status_text(result: dict) -> str:
            if result["status"] == "injection_success":
                return "BYPASSED"
            if result["status"] == "invalid_output":
                return "Ogiltig output"
            return "Blockerad"

        pi_rows = "\n".join(
            f"| `{r['probe']}` | {r['intent']} | {r['expected']} | "
            f"{r['got'] or 'invalid_output'} | "
            f"{_status_text(r)} |"
            for r in injection
        )
        pi_section = textwrap.dedent(f"""
            ### 3. Prompt injection — Spår A LLM

            **Hypotes:** Threat reports kan innehålla embedded instruktioner som styr LLM-output.

            **Resultat:**

            | Probe | Intent | Förväntat | Fick | Status |
            |-------|--------|-----------|------|--------|
            {pi_rows}

            **Injection success rate:** {n_bypassed}/{len(injection)} ({n_bypassed/len(injection):.0%})

            **Ogiltig output-rate:** {n_invalid}/{len(injection)} ({n_invalid/len(injection):.0%})

            **Blocked-rate:** {n_blocked}/{len(injection)} ({n_blocked/len(injection):.0%})

            **Analys:** {'Ingen probe gav fel klass.' if n_bypassed == 0 else f'{n_bypassed} probe(s) lyckades kringgå systemprompten.'}
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
        | Metadata-mimicry | Success rate = {mimicry['success_rate']:.1%} |
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

        ![F1-macro per poison-ratio]({poisoning_plot_name})

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

        **Hypotes:** Angriparkontrollerad metadata kan ändras så att en skadlig
        upload liknar en vanlig PDF och klassificeras som accepterad.

        **Metod:** Random feature noise behålls som sanity-check. Den riktade
        metadata-mimicry-attacken ändrar endast filnamn, content-type och storlek
        till en benign PDF-profil. Hash, scan-status och risk-score bevaras.
        Dataset: `{mimicry['dataset']}`.

        | Attack | Parameter | Lyckade / möjliga | Success rate |
        |--------|-----------|-------------------|--------------|
        {e_rows}

        **Analys:**
        Metadata-mimicry lyckades för {mimicry['successful']} av {mimicry['total']}
        korrekt identifierade skadliga testposter ({mimicry['success_rate']:.1%}).
        Resultatet visar metadata-modellens gameability utan att skapa ogiltiga
        feature-vektorer. Hash-bryggan och makroregeln är separata skyddslager
        som inte mäts av klassificerarattacken.

        **Motåtgärder:**
        - Behandla metadata-modellen som triage-hint, inte ensam detektion
        - Behåll ClamAV, hash-brygga och makroanalys som separata skyddslager
        - Träna och utvärdera med realistiska, av-biasade filnamn

        ---

        {pi_section}

        ---

        ## Slutsats

        sentinel-ml visar god robusthet mot baseline-attacker men systemet bör
        inte anses produktionsklart utan ytterligare härdning:

        1. **Datavalidering** bör implementeras i `data/loaders.py` vid MongoDB-intag
        2. **Metadata-modellen** måste kombineras med innehålls- och hashbaserade skydd
        3. **Prompt injection** kräver fortsatt testning mot en körande Ollama-instans
        4. **ART-baserade attacker** är frivillig fördjupning om resultaten kan mappas till giltiga uploads

        Referens: [OWASP ML Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/),
        [MITRE ATLAS](https://atlas.mitre.org/), NIST AI 100-2.
    """).strip()


# ── main ──────────────────────────────────────────────────────────────────────

def main(
    dataset: Path = typer.Argument(Path("data/real_threat_reports.jsonl")),
    upload_dataset: Path = typer.Option(Path("data/upload_training_data.jsonl")),
    out: Path = typer.Option(Path("docs/adversarial-analysis.md")),
) -> None:
    poisoning_results = run_poisoning(dataset)
    evasion_results = run_evasion(upload_dataset)
    injection_results = run_prompt_injection()

    out.parent.mkdir(parents=True, exist_ok=True)
    poisoning_plot = out.with_name("adversarial-poisoning.svg")
    _write_poisoning_svg(poisoning_results, poisoning_plot)
    report = _render_report(
        poisoning_results,
        evasion_results,
        injection_results,
        dataset,
        poisoning_plot.name,
    )
    out.write_text(report, encoding="utf-8")
    typer.echo(f"Poisoning-graf sparad till {poisoning_plot}")
    typer.echo(f"\nRapport sparad till {out}")


if __name__ == "__main__":
    typer.run(main)
