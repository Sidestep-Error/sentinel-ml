"""Jämför regex- och spaCy-baserad IOC-extraktion.

Usage:
  python scripts/compare_ioc_extractors.py
  python scripts/compare_ioc_extractors.py --dataset data/real_threat_reports.jsonl --n 20
"""

from __future__ import annotations

from pathlib import Path

import typer

SAMPLE_TEXT = (
    "CTB-Locker ransomware (SHA-256: "
    "a3f1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1) "
    "was observed beaconing to 198.51.100.42 and evil-domain.example. "
    "CVE-2024-12345 was exploited. Phishing lure at https://fake-portal.example/login. "
    "Contact reporter@example.com. Attributed to Fancy Bear by analysts."
)


def _print_table(title: str, iocs: list) -> None:
    print(f"\n{'─'*60}")
    print(f"  {title}  ({len(iocs)} IOCs)")
    print(f"{'─'*60}")
    for ioc in sorted(iocs, key=lambda x: x.type):
        conf = f"  conf={ioc.confidence:.1f}" if ioc.confidence < 1.0 else ""
        print(f"  {ioc.type.value:10}  {ioc.value}{conf}")


def main(
    dataset: Path | None = typer.Option(None, help="JSONL to sample texts from"),
    n: int = typer.Option(3, help="Number of dataset texts to compare"),
) -> None:
    from sentinel_ml.features.ioc_extract_spacy import compare_extractors

    texts = [SAMPLE_TEXT]

    if dataset and dataset.exists():
        from sentinel_ml.data.loaders import load_threat_reports_jsonl
        reports = list(load_threat_reports_jsonl(dataset))[:n]
        texts = [r.text for r in reports]

    for i, text in enumerate(texts, 1):
        print(f"\n{'═'*60}")
        print(f"TEXT {i}: {text[:120]}...")
        results = compare_extractors(text)
        _print_table("REGEX", results["regex"])
        _print_table("spaCy", results["spacy"])

        regex_types = {(i.type, i.value) for i in results["regex"]}
        spacy_types = {(i.type, i.value) for i in results["spacy"] if i.confidence == 1.0}
        only_spacy = {(i.type, i.value) for i in results["spacy"] if i.confidence < 1.0}

        print(f"\n  Regex only:  {len(regex_types - spacy_types)}")
        print(f"  spaCy only (named entities): {len(only_spacy)}")
        print(f"  Gemensamma: {len(regex_types & spacy_types)}")


if __name__ == "__main__":
    typer.run(main)
