"""Download and convert mrmoor/cyber-threat-intelligence to ThreatReport JSONL.

License: CC-BY-4.0  https://huggingface.co/datasets/mrmoor/cyber-threat-intelligence
Label strategy: keyword-based document classification (ransomware > phishing > ddos > malware > intrusion).
Documents matching no category are skipped.

Usage:
  python scripts/download_real_threat_reports.py
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import typer
from datasets import load_dataset

CATEGORY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ransomware", re.compile(r"\bransomware\b", re.IGNORECASE)),
    ("phishing",   re.compile(r"\bspear.?phishing\b|\bphishing\b", re.IGNORECASE)),
    ("ddos",       re.compile(r"\bdd?os\b|\bdenial.of.service\b|\budp\s+flood\b|\bsyn\s+flood\b", re.IGNORECASE)),
    ("malware",    re.compile(r"\bmalware\b|\btrojan\b|\bbackdoor\b|\bbotnet\b|\bworm\b|\brootkit\b", re.IGNORECASE)),
    ("intrusion",  re.compile(r"\bintrusion\b|\bapt\b|\blateral.movement\b|\bexploit\b|\bbreach\b", re.IGNORECASE)),
]


def classify(text: str) -> str | None:
    for label, pattern in CATEGORY_PATTERNS:
        if pattern.search(text):
            return label
    return None


def main(
    out: Path = typer.Option(Path("data/real_threat_reports.jsonl"), help="Output JSONL path"),
    min_length: int = typer.Option(100, help="Minimum text length in characters"),
) -> None:
    typer.echo("Laddar dataset från HuggingFace...")
    ds = load_dataset("mrmoor/cyber-threat-intelligence", split="train")

    out.parent.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    skipped = 0

    with out.open("w", encoding="utf-8") as f:
        for row in ds:
            text: str = row["text"].strip()
            if len(text) < min_length:
                skipped += 1
                continue

            label = classify(text)
            if label is None:
                skipped += 1
                continue

            record = {
                "report_id": f"cti-{row['id']}",
                "text": text,
                "source": "mrmoor/cyber-threat-intelligence (CC-BY-4.0)",
                "labels": [label],
                "iocs": [],
            }
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            counts[label] = counts.get(label, 0) + 1

    total = sum(counts.values())
    typer.echo(f"\nSparade {total} rapporter till {out}  ({skipped} skippade)")
    for label, n in sorted(counts.items()):
        typer.echo(f"  {label:12} {n:4d}")


if __name__ == "__main__":
    typer.run(main)
