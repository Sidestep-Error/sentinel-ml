"""FastAPI surface for sentinel-ml.

Endpoints:
  GET  /health             — liveness probe
  POST /predict/threat     — classify a threat report + extract IOCs
  POST /predict/upload     — predict malicious/clean for an upload metadata record

The service is stateless — models are loaded once at startup. Trained
artifacts live in `models_store/` (gitignored).
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from sentinel_ml import __version__
from sentinel_ml.data.schemas import IOC, UploadRecord
from sentinel_ml.features.ioc_extract import extract_iocs

app = FastAPI(
    title="Sentinel ML",
    version=__version__,
    description="ML-based security predictions for Sentinel Upload API.",
)


class ThreatRequest(BaseModel):
    text: str


class ThreatResponse(BaseModel):
    category: str
    confidence: float
    iocs: list[IOC]
    model_version: str


class UploadResponse(BaseModel):
    label: str
    confidence: float
    explanation: dict[str, Any] | None = None
    model_version: str


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.post("/predict/threat", response_model=ThreatResponse)
def predict_threat(req: ThreatRequest) -> ThreatResponse:
    """Stub: IOC extraction is implemented; classifier wiring lands in Fas 1."""
    iocs = extract_iocs(req.text)
    return ThreatResponse(
        category="unknown",
        confidence=0.0,
        iocs=iocs,
        model_version=__version__,
    )


@app.post("/predict/upload", response_model=UploadResponse)
def predict_upload(record: UploadRecord) -> UploadResponse:
    """Stub: returns a placeholder. Real prediction lands when Spar B is trained."""
    return UploadResponse(
        label="unknown",
        confidence=0.0,
        explanation=None,
        model_version=__version__,
    )
