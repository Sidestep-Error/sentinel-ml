"""Feature extraction for Spår B (upload-classifier).

Input: UploadRecord. Output: numpy feature vector + a parallel list of
column names so we can interpret feature importances later.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable

import numpy as np

from sentinel_ml.data.schemas import UploadRecord

# Order matters — keep stable so saved models match feature columns.
FEATURE_COLUMNS = [
    "size_bytes_log",
    "filename_length",
    "filename_special_chars",
    "filename_digit_ratio",
    "extension_in_content_type_allowlist",
    "risk_score_normalized",
    "scan_status_clean",
    "scan_status_malicious",
    "scan_status_error",
]

_SPECIAL_CHAR_RE = re.compile(r"[^A-Za-z0-9_.\- ]")
_DIGIT_RE = re.compile(r"\d")


_CONTENT_TYPE_TO_EXTENSIONS: dict[str, set[str]] = {
    "text/plain": {".txt", ".text", ".log"},
    "text/markdown": {".md", ".markdown"},
    "text/csv": {".csv"},
    "image/png": {".png"},
    "image/jpeg": {".jpg", ".jpeg"},
    "application/pdf": {".pdf"},
    # Microsoft Office (modern OpenXML)
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {".docx"},
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {".xlsx"},
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": {".pptx"},
    # Microsoft Office (legacy)
    "application/msword": {".doc"},
    "application/vnd.ms-excel": {".xls"},
    "application/vnd.ms-powerpoint": {".ppt"},
    # OpenDocument (LibreOffice)
    "application/vnd.oasis.opendocument.text": {".odt"},
    "application/vnd.oasis.opendocument.spreadsheet": {".ods"},
    "application/vnd.oasis.opendocument.presentation": {".odp"},
}


def _extension(filename: str) -> str:
    idx = filename.rfind(".")
    return filename[idx:].lower() if idx >= 0 else ""


def _row(record: UploadRecord) -> list[float]:
    ext = _extension(record.filename)
    allow = _CONTENT_TYPE_TO_EXTENSIONS.get(record.content_type, set())
    name_len = len(record.filename)
    digits = len(_DIGIT_RE.findall(record.filename))

    return [
        math.log1p(record.size_bytes or 0),
        float(name_len),
        float(len(_SPECIAL_CHAR_RE.findall(record.filename))),
        digits / name_len if name_len else 0.0,
        1.0 if ext in allow else 0.0,
        record.risk_score / 100.0,
        1.0 if record.scan_status == "clean" else 0.0,
        1.0 if record.scan_status == "malicious" else 0.0,
        1.0 if record.scan_status == "error" else 0.0,
    ]


def build_feature_matrix(records: Iterable[UploadRecord]) -> tuple[np.ndarray, list[str]]:
    """Build a (n_samples, n_features) array and return alongside column names."""
    rows = [_row(r) for r in records]
    matrix = np.asarray(rows, dtype=np.float32) if rows else np.zeros((0, len(FEATURE_COLUMNS)), dtype=np.float32)
    return matrix, list(FEATURE_COLUMNS)
