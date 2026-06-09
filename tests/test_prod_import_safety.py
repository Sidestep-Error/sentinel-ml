"""Guard against the prod-image startup crash from PR #38 / #44.

The production image installs base deps only — the ``[llm]`` extra (httpx) is
absent. If any module-level import pulls in an ``[llm]`` extra, directly or
transitively, the service crashes at startup and the Hetzner rollout fails.

These tests simulate "httpx not installed" and assert that the modules loaded
at service startup still import cleanly. The LLM path is expected to stay
available only behind lazy imports inside the functions that use it.
"""

from __future__ import annotations

import builtins
import importlib
import sys

import pytest

# Modules whose import chain must not require httpx (loaded at service startup).
PROD_SAFE_MODULES = [
    "sentinel_ml.service.api",
    "sentinel_ml.llm",
    "sentinel_ml.llm.prompts",
]


@pytest.fixture
def httpx_unavailable(monkeypatch: pytest.MonkeyPatch):
    """Make ``import httpx`` raise ImportError and force a fresh import chain."""
    real_import = builtins.__import__

    def fake_import(name: str, *args, **kwargs):
        if name == "httpx" or name.startswith("httpx."):
            raise ImportError("No module named 'httpx' (simulated prod image)")
        return real_import(name, *args, **kwargs)

    # Drop cached sentinel_ml/httpx modules so the import actually re-runs.
    for mod in list(sys.modules):
        if mod == "httpx" or mod.startswith("httpx.") or mod.startswith("sentinel_ml"):
            sys.modules.pop(mod, None)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    try:
        yield
    finally:
        # Re-import cleanly with the real importer so later tests are unaffected.
        for mod in list(sys.modules):
            if mod.startswith("sentinel_ml"):
                sys.modules.pop(mod, None)


@pytest.mark.parametrize("module_name", PROD_SAFE_MODULES)
def test_imports_without_httpx(httpx_unavailable, module_name: str) -> None:
    """Startup modules must import even when the [llm] extra (httpx) is missing."""
    importlib.import_module(module_name)


def test_httpx_unavailable_fixture_actually_blocks_httpx(httpx_unavailable) -> None:
    """Sanity check: the fixture really does make httpx unimportable.

    Uses a statement-level ``import`` (compiles to IMPORT_NAME -> builtins.__import__,
    the path real module code takes) rather than ``importlib.import_module``,
    which bypasses the patched importer.
    """
    with pytest.raises(ImportError):
        import httpx  # noqa: F401
