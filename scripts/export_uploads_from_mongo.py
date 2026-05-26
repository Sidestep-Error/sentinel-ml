#!/usr/bin/env python
"""Dump uploads from sentinel-upload-api MongoDB into JSONL.

Run when you want to train without a live Mongo connection (e.g. in CI or
on a laptop without VPN).

Usage:
  python scripts/export_uploads_from_mongo.py --out data/uploads_export.jsonl
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from sentinel_ml.data.loaders import load_uploads_from_mongo


def main(
    out: Path = typer.Option(Path("data/uploads_export.jsonl"), help="Output JSONL path"),
    limit: int | None = typer.Option(None, help="Cap number of records (omit for all)"),
) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    records = load_uploads_from_mongo(limit=limit)
    with out.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(r.model_dump_json() + "\n")
    typer.echo(f"Wrote {len(records)} records to {out}")


if __name__ == "__main__":
    typer.run(main)
