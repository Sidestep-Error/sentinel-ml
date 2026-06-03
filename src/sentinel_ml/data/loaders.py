"""Data loaders — MongoDB + local files.

Read-only by design: this module never writes to Sentinel's collections.
Predictions go into a separate `ml_predictions` collection or onto disk.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

from sentinel_ml.config import get_settings
from sentinel_ml.data.schemas import ThreatReport, UploadRecord

if TYPE_CHECKING:
    from pymongo.collection import Collection

logger = logging.getLogger(__name__)


def _get_collection(name: str) -> Collection:
    """Lazy Mongo client. Imported inside fn so tests can run without pymongo I/O."""
    from pymongo import MongoClient

    settings = get_settings()
    client = MongoClient(settings.mongodb_uri, serverSelectionTimeoutMS=5000)
    db_name = settings.mongodb_db_upload if name == "uploads" else settings.mongodb_db
    return client[db_name][name]


def load_uploads_from_mongo(limit: int | None = None) -> list[UploadRecord]:
    """Load upload records from Sentinel's MongoDB.

    Used as training data for the upload-classifier (Spar B). Skips documents
    that don't conform to the expected shape so a single bad record doesn't
    poison the dataset.
    """
    coll = _get_collection("uploads")
    cursor = coll.find({}, projection=None)
    if limit is not None:
        cursor = cursor.limit(limit)

    records: list[UploadRecord] = []
    for doc in cursor:
        try:
            records.append(UploadRecord.model_validate(doc))
        except Exception:  # noqa: BLE001 - we explicitly want to skip any malformed doc
            logger.debug("Skipping malformed upload document", exc_info=True)
            continue
    return records


def load_threat_reports_jsonl(path: str | Path) -> Iterator[ThreatReport]:
    """Stream threat reports from a JSONL file.

    Format: one JSON object per line, conforming to `ThreatReport` schema.
    """
    path = Path(path)
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield ThreatReport.model_validate(json.loads(line))
