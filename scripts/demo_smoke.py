#!/usr/bin/env python
"""Smoke-test the sentinel-ml FastAPI service.

Exercises /health, /predict/threat and /predict/upload against a running
service and prints a PASS/FAIL summary. Useful for the live demo (visa
att hela kedjan svarar) och som en snabb sanity check efter en deploy.

Starts no service of its own — assumes one is already running at the
configured --base-url (default http://localhost:8100).

Usage:
  # In one terminal:
  uvicorn sentinel_ml.service.api:app --reload --port 8100

  # In another:
  python scripts/demo_smoke.py
  python scripts/demo_smoke.py --base-url http://localhost:8100
  python scripts/demo_smoke.py --verbose

Exit code: 0 if all checks pass, 1 otherwise.
"""

from __future__ import annotations

import json

import httpx
import typer

THREAT_SAMPLE = (
    "Observed C2 traffic to 8.8.8.8 from infected hosts. "
    "Payload SHA-256 " + "a" * 64 + " distributed via "
    "malicious-domain.example. Exploits CVE-2024-12345. "
    "Reporter contact: analyst@example.com"
)

UPLOAD_SAMPLE = {
    "sha256": "b" * 64,
    "filename": "report.pdf",
    "content_type": "application/pdf",
    "size_bytes": 12345,
    "scan_status": "clean",
    "decision": "accepted",
    "risk_score": 10,
    "created_at": "2026-06-03T10:00:00+00:00",
}


def _smoke_health(client: httpx.Client, base_url: str) -> tuple[bool, str, dict | None]:
    try:
        r = client.get(f"{base_url}/health", timeout=5.0)
    except httpx.HTTPError as exc:
        return False, f"connection error: {exc.__class__.__name__}", None
    if r.status_code != 200:
        return False, f"status {r.status_code}", None
    payload = r.json()
    if payload.get("status") != "ok":
        return False, f"unexpected payload: {payload}", payload
    return True, f"version {payload.get('version', '?')}", payload


def _smoke_predict_threat(
    client: httpx.Client, base_url: str
) -> tuple[bool, str, dict | None]:
    try:
        r = client.post(
            f"{base_url}/predict/threat",
            json={"text": THREAT_SAMPLE},
            timeout=10.0,
        )
    except httpx.HTTPError as exc:
        return False, f"connection error: {exc.__class__.__name__}", None
    if r.status_code != 200:
        return False, f"status {r.status_code}: {r.text[:200]}", None
    payload = r.json()
    prediction = payload.get("prediction", {})
    iocs = payload.get("iocs", [])
    detail = (
        f"label={prediction.get('label')!r} "
        f"confidence={prediction.get('confidence'):.3f} "
        f"iocs={len(iocs)} "
        f"model_version={payload.get('model_version')!r}"
    )
    return True, detail, payload


def _smoke_predict_upload(
    client: httpx.Client, base_url: str
) -> tuple[bool, str, dict | None]:
    try:
        r = client.post(
            f"{base_url}/predict/upload",
            json=UPLOAD_SAMPLE,
            timeout=10.0,
        )
    except httpx.HTTPError as exc:
        return False, f"connection error: {exc.__class__.__name__}", None
    if r.status_code != 200:
        return False, f"status {r.status_code}: {r.text[:200]}", None
    payload = r.json()
    prediction = payload.get("prediction", {})
    detail = (
        f"label={prediction.get('label')!r} "
        f"confidence={prediction.get('confidence'):.3f} "
        f"model_version={payload.get('model_version')!r}"
    )
    return True, detail, payload


CHECKS = [
    ("GET  /health", _smoke_health),
    ("POST /predict/threat", _smoke_predict_threat),
    ("POST /predict/upload", _smoke_predict_upload),
]


def main(
    base_url: str = typer.Option(
        "http://localhost:8100",
        help="Base URL of the running service",
        show_default=True,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Print full JSON responses for each check",
    ),
) -> None:
    """Run a smoke-test pass against a running sentinel-ml service."""
    base_url = base_url.rstrip("/")
    typer.echo(f"Smoke-testing sentinel-ml service at {base_url}\n")

    failed = 0
    with httpx.Client() as client:
        for label, fn in CHECKS:
            ok, detail, payload = fn(client, base_url)
            status = "PASS" if ok else "FAIL"
            typer.echo(f"  [{status}] {label} -- {detail}")
            if verbose and payload is not None:
                typer.echo(json.dumps(payload, indent=2, ensure_ascii=False))
            if not ok:
                failed += 1

    total = len(CHECKS)
    typer.echo(f"\nResult: {total - failed}/{total} passed")
    raise typer.Exit(code=0 if failed == 0 else 1)


if __name__ == "__main__":
    typer.run(main)
