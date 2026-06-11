"""Generera träningsdata för upload-klassificeraren.

Malicious-klassen: mappas från data/malware_samples.jsonl (MalwareBazaar-metadata).
Clean-klassen: syntetiska realistiska filuppladdningar (PDF, PNG, CSV, TXT, etc.).

Alla poster sätts till scan_status="clean" och risk_score=0 för att simulera att
ClamAV inte flaggat filen — det är exakt det use-case upload-klassificeraren ska
täcka: fånga misstänkta filer som signaturskanningen missar.

Labels sparas som ett extra fält "label" i JSONL och används vid träning.

Usage:
  python scripts/generate_upload_training_data.py
  python scripts/generate_upload_training_data.py --n-clean 1500 --out data/upload_training_data.jsonl
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import typer

# --- Realistiska filnamn och typer för clean-klassen ---

_CLEAN_PROFILES = [
    # (extension, content_type, name_prefixes)
    (".pdf",  "application/pdf",   ["report", "invoice", "contract", "summary", "manual", "guide", "brief"]),
    (".png",  "image/png",         ["screenshot", "logo", "diagram", "photo", "chart", "banner"]),
    (".jpg",  "image/jpeg",        ["image", "photo", "scan", "picture", "portrait", "landscape"]),
    (".csv",  "text/csv",          ["data", "export", "results", "log", "metrics", "stats"]),
    (".txt",  "text/plain",        ["notes", "readme", "config", "changelog", "todo", "log"]),
    (".md",   "text/markdown",     ["README", "CHANGELOG", "docs", "notes", "spec"]),
    # Microsoft Office (modern OpenXML)
    (".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
     ["report", "letter", "memo", "proposal", "minutes", "policy", "handbook"]),
    (".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
     ["budget", "forecast", "expenses", "inventory", "schedule", "tracker", "timesheet"]),
    (".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation",
     ["presentation", "deck", "slides", "pitch", "overview", "review", "quarterly"]),
    # Microsoft Office (legacy)
    (".doc",  "application/msword",
     ["report", "letter", "memo", "draft", "notes", "agenda"]),
    (".xls",  "application/vnd.ms-excel",
     ["budget", "data", "expenses", "log", "tracker", "sales"]),
    (".ppt",  "application/vnd.ms-powerpoint",
     ["presentation", "slides", "deck", "demo", "training", "kickoff"]),
]

_MALICIOUS_MIME = {
    "exe": "application/x-dosexec",
    "dll": "application/x-dosexec",
    "ps1": "text/plain",
    "bat": "application/x-msdos-program",
    "vbs": "text/plain",
    "zip": "application/zip",
    "js":  "application/javascript",
    "lnk": "application/octet-stream",
}


def _clean_record(rng: random.Random, idx: int) -> dict:
    ext, ctype, prefixes = rng.choice(_CLEAN_PROFILES)
    prefix = rng.choice(prefixes)
    suffix = rng.randint(1, 9999)
    filename = f"{prefix}_{suffix}{ext}"
    size = int(rng.gauss(500_000, 300_000))
    size = max(1_000, min(size, 9_000_000))
    return {
        "filename": filename,
        "content_type": ctype,
        "sha256": f"{'a' * 64}",
        "size_bytes": size,
        "scan_status": "clean",
        "decision": "accepted",
        "risk_score": 0,
        "scan_engine": "clamav",
        "scan_detail": "No signature matched",
        "label": "accepted",
    }


def _malicious_record(raw: dict) -> dict:
    """Map a MalwareSample record to upload-classifier training format."""
    file_type = (raw.get("file_type") or "exe").lower()
    filename = raw.get("file_name") or f"malware.{file_type}"
    ctype = raw.get("file_type_mime") or _MALICIOUS_MIME.get(file_type, "application/octet-stream")
    size = raw.get("file_size") or 0
    signature = raw.get("signature") or ""
    return {
        "filename": filename,
        "content_type": ctype,
        "sha256": raw.get("sha256", "0" * 64),
        "size_bytes": size,
        # scan_status intentionally "clean" — simulates ClamAV miss, the case we train for
        "scan_status": "clean",
        "decision": "rejected",
        "risk_score": 0,
        "scan_engine": "clamav",
        "scan_detail": f"[training label from MalwareBazaar] family={raw.get('family','')} sig={signature}",
        "label": "rejected",
    }


def main(
    malware_jsonl: Path = typer.Option(Path("data/malware_samples.jsonl"), help="MalwareSample JSONL"),
    n_clean: int = typer.Option(1000, help="Number of synthetic clean records to generate"),
    out: Path = typer.Option(Path("data/upload_training_data.jsonl"), help="Output JSONL"),
    seed: int = typer.Option(42),
) -> None:
    rng = random.Random(seed)

    records: list[dict] = []

    # Malicious class: from MalwareBazaar metadata
    if malware_jsonl.exists():
        with malware_jsonl.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(_malicious_record(json.loads(line)))
        n_malicious = sum(1 for r in records if r["label"] == "rejected")
        typer.echo(f"Malicious (MalwareBazaar): {n_malicious} poster")
    else:
        typer.echo(f"OBS: {malware_jsonl} saknas — kör generate_malware_samples.py först", err=True)

    # Clean class: synthetic
    for i in range(n_clean):
        records.append(_clean_record(rng, i))
    typer.echo(f"Clean (syntetisk): {n_clean} poster")

    rng.shuffle(records)

    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    n_rej = sum(1 for r in records if r["label"] == "rejected")
    n_acc = sum(1 for r in records if r["label"] == "accepted")
    typer.echo(f"\nSparade {len(records)} poster till {out}")
    typer.echo(f"  accepted: {n_acc}")
    typer.echo(f"  rejected: {n_rej}")


if __name__ == "__main__":
    typer.run(main)
