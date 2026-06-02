"""Drift-test mellan Settings-klassen och .env.example.

Säkerställer att varje fält i `Settings` är dokumenterat i `.env.example`.
Om någon lägger till en ny env-var i `config.py` utan att uppdatera mallen
fångas det här i CI istället för att tysta dyka upp som "varför funkar inte
min .env"-frågor i teamchatten.
"""

from __future__ import annotations

from pathlib import Path

from sentinel_ml.config import Settings


def _env_example_path() -> Path:
    return Path(__file__).resolve().parent.parent / ".env.example"


def test_env_example_file_exists():
    assert _env_example_path().exists(), ".env.example missing from repo root"


def test_env_example_documents_all_settings_aliases():
    """Every Settings field's alias must appear in .env.example."""
    text = _env_example_path().read_text(encoding="utf-8")
    for field_name, field_info in Settings.model_fields.items():
        alias = field_info.alias or field_name.upper()
        assert alias in text, (
            f"Settings field {field_name!r} (env var {alias!r}) is not documented "
            f"in .env.example — please add a line for it."
        )
