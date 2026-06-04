"""Smoke-test the smoke-test script itself.

Verifies that `scripts/demo_smoke.py` exits cleanly with a non-zero status
when the target service is unreachable, instead of crashing with a traceback.
That is the only behavior we can verify without spinning up a real uvicorn
process in CI — happy-path coverage lives in tests/test_service_api.py.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "demo_smoke.py"


def test_demo_smoke_script_exists():
    assert SCRIPT.exists(), f"{SCRIPT} not found"


def test_demo_smoke_reports_failure_when_no_service():
    """Pointing at a closed port must yield exit 1 with a FAIL line per check."""
    # 127.0.0.1:1 is reserved and reliably refuses connections on Windows + Linux.
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--base-url", "http://127.0.0.1:1"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 1, (
        f"expected exit 1, got {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    # Each of the three checks should produce a FAIL line.
    assert result.stdout.count("[FAIL]") == 3, result.stdout
    assert "0/3 passed" in result.stdout
