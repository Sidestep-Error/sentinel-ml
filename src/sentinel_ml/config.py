"""Env-driven configuration. Loaded once at process start."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central settings object. Values come from environment or .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- MongoDB (sentinel-upload-api data source) ---
    # Defaults match upstream sentinel-upload-api (see its app/db.py) so a
    # local dev setup with both services running uses the same Mongo instance.
    mongodb_uri: str = Field(
        default="mongodb://localhost:27017/sentinel_upload", alias="MONGODB_URI"
    )
    mongodb_db: str = Field(default="sentinel_upload", alias="MONGODB_DB")
    mongodb_db_upload: str = Field(default="sentinel_upload", alias="MONGODB_DB_UPLOAD")

    # --- LLM (Ollama, local) ---
    ollama_host: str = Field(default="http://localhost:11434", alias="OLLAMA_HOST")
    ollama_model: str = Field(default="llama3.2:3b", alias="OLLAMA_MODEL")

    # --- MLflow ---
    mlflow_tracking_uri: str = Field(default="file:./mlruns", alias="MLFLOW_TRACKING_URI")

    # --- Reproducibility ---
    seed: int = Field(default=42, alias="SENTINEL_ML_SEED")

    # --- Paths ---
    data_dir: Path = Field(default=Path("./data"), alias="DATA_DIR")
    models_dir: Path = Field(default=Path("./models_store"), alias="MODELS_DIR")


def get_settings() -> Settings:
    """Return a fresh settings instance.

    Not memoized on purpose — tests override env vars and expect to see
    the new values without monkeypatching a cache.
    """
    return Settings()
