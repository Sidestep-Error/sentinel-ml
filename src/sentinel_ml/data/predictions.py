"""Write-back helpers for ML predictions stored alongside Sentinel data."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel

from sentinel_ml.config import get_settings

ML_PREDICTIONS_COLLECTION = "ml_predictions"


def _get_predictions_collection():
    """Lazy Mongo client for prediction write-back."""
    from pymongo import MongoClient

    settings = get_settings()
    client = MongoClient(settings.mongodb_uri, serverSelectionTimeoutMS=5000)
    return client[settings.mongodb_db][ML_PREDICTIONS_COLLECTION]


def upsert_ml_prediction_document(document: BaseModel | Mapping[str, Any]) -> None:
    """Replace or insert one prediction document keyed by upload_id."""
    payload = (
        document.model_dump(mode="json")
        if isinstance(document, BaseModel)
        else dict(document)
    )
    upload_id = payload.get("upload_id")
    if not isinstance(upload_id, str) or not upload_id.strip():
        raise ValueError("prediction document requires a non-empty upload_id")

    collection = _get_predictions_collection()
    collection.replace_one({"upload_id": upload_id}, payload, upsert=True)
