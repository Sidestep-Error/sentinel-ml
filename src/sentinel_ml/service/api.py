"""FastAPI surface for sentinel-ml.

Endpoints:
  GET  /health             — liveness probe
  POST /predict/threat     — classify a threat report + extract IOCs
  POST /predict/upload     — predict malicious/clean for an upload metadata record

The service is stateless — models are loaded once at startup. Trained
artifacts live in ``models_store/`` (gitignored). If an artifact is missing
or fails to load, the corresponding endpoint degrades to a fallback
response (``label="unknown"``, ``model_version="none"``) so the service
still answers during development.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from pydantic import BaseModel

from sentinel_ml import __version__
from sentinel_ml.config import get_settings
from sentinel_ml.data.schemas import IOC, Prediction, UploadRecord
from sentinel_ml.features.ioc_extract import extract_iocs
from sentinel_ml.features.upload_meta import build_feature_matrix
from sentinel_ml.llm.prompts import CLASSIFY_THREAT_REPORT_SYSTEM
from sentinel_ml.log_anomaly import tfidf_detector
from sentinel_ml.models import threat_classifier, upload_classifier

logger = logging.getLogger(__name__)

THREAT_ARTIFACT_NAME = "threat_classifier.joblib"
UPLOAD_ARTIFACT_NAME = "upload_classifier.joblib"
LOG_ANOMALY_ARTIFACT_NAME = tfidf_detector.LOG_ANOMALY_ARTIFACT
FALLBACK_VERSION = "none"


@dataclass(frozen=True)
class LoadedModel:
    """Trained estimator paired with an artifact-derived version string."""

    artifact: Any
    version: str


class ThreatRequest(BaseModel):
    text: str


class LLMAnalysis(BaseModel):
    category: str
    confidence: float
    rationale: str
    model: str


class ThreatResponse(BaseModel):
    prediction: Prediction
    iocs: list[IOC]
    model_version: str
    llm_analysis: LLMAnalysis | None = None


class UploadResponse(BaseModel):
    prediction: Prediction
    model_version: str


class LogAnomalyRequest(BaseModel):
    logs: list[str]


class LogLinePrediction(BaseModel):
    line: str
    is_anomaly: bool
    score: float


class LogAnomalyResponse(BaseModel):
    predictions: list[LogLinePrediction]
    model_version: str


def _artifact_version(path: Path) -> str:
    """Short sha256 prefix of artifact bytes. Changes every retrain."""
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest[:12]


def _try_load(path: Path, loader: Callable[[Path], Any]) -> LoadedModel | None:
    if not path.exists():
        logger.info("Model artifact missing at %s — endpoint will use fallback", path)
        return None
    try:
        artifact = loader(path)
    except Exception:  # noqa: BLE001 — log and degrade rather than crash startup
        logger.exception("Failed to load model artifact at %s", path)
        return None
    return LoadedModel(artifact=artifact, version=_artifact_version(path))


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    models_dir = Path(settings.models_dir)
    app.state.threat_model = _try_load(
        models_dir / THREAT_ARTIFACT_NAME, threat_classifier.load
    )
    app.state.upload_model = _try_load(
        models_dir / UPLOAD_ARTIFACT_NAME, upload_classifier.load
    )
    app.state.log_anomaly_model = _try_load(
        models_dir / LOG_ANOMALY_ARTIFACT_NAME, tfidf_detector.load
    )
    yield


def _get_loaded(request: Request, attr: str) -> LoadedModel | None:
    """Read a loaded model off app state, tolerating tests that skip lifespan."""
    return getattr(request.app.state, attr, None)


def _call_ollama(text: str) -> LLMAnalysis | None:
    """Call Ollama for LLM-based threat classification. Returns None on any failure.

    The OllamaClient import is local so the optional ``[llm]`` dependency
    (httpx) is only required when the LLM path actually runs. The production
    image installs base deps only — a missing httpx degrades to None here
    instead of crashing the service at import time.
    """
    try:
        from sentinel_ml.llm.ollama_client import OllamaClient

        client = OllamaClient(timeout=30.0)
        response = client.generate(prompt=text, system=CLASSIFY_THREAT_REPORT_SYSTEM)
        data = json.loads(response.text)
        return LLMAnalysis(
            category=str(data.get("category", "unknown")),
            confidence=float(data.get("confidence", 0.0)),
            rationale=str(data.get("rationale", "")),
            model=response.model,
        )
    except Exception:
        logger.debug("Ollama unavailable or returned unexpected format — skipping LLM analysis", exc_info=True)
        return None


def _predict_with(loaded: LoadedModel, x: Any) -> Prediction:
    probas = loaded.artifact.predict_proba(x)[0]
    classes = loaded.artifact.classes_
    idx = int(probas.argmax())
    return Prediction(label=str(classes[idx]), confidence=float(probas[idx]))


def create_app() -> FastAPI:
    """Build a FastAPI app. Use this in tests to get a fresh lifespan."""
    app = FastAPI(
        title="Sentinel ML",
        version=__version__,
        description="ML-based security predictions for Sentinel Upload API.",
        lifespan=lifespan,
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.post("/predict/threat", response_model=ThreatResponse)
    def predict_threat(req: ThreatRequest, request: Request) -> ThreatResponse:
        iocs = extract_iocs(req.text)
        llm = _call_ollama(req.text)
        loaded = _get_loaded(request, "threat_model")
        if loaded is None:
            return ThreatResponse(
                prediction=Prediction(label="unknown", confidence=0.0),
                iocs=iocs,
                model_version=FALLBACK_VERSION,
                llm_analysis=llm,
            )
        prediction = _predict_with(loaded, [req.text])
        return ThreatResponse(
            prediction=prediction, iocs=iocs, model_version=loaded.version, llm_analysis=llm
        )

    @app.post("/predict/upload", response_model=UploadResponse)
    def predict_upload(record: UploadRecord, request: Request) -> UploadResponse:
        loaded = _get_loaded(request, "upload_model")
        if loaded is None:
            return UploadResponse(
                prediction=Prediction(label="unknown", confidence=0.0),
                model_version=FALLBACK_VERSION,
            )
        features, _ = build_feature_matrix([record])
        prediction = _predict_with(loaded, features)
        return UploadResponse(prediction=prediction, model_version=loaded.version)

    @app.post("/predict/log-anomaly", response_model=LogAnomalyResponse)
    def predict_log_anomaly(req: LogAnomalyRequest, request: Request) -> LogAnomalyResponse:
        loaded = _get_loaded(request, "log_anomaly_model")
        if loaded is None or not req.logs:
            return LogAnomalyResponse(
                predictions=[
                    LogLinePrediction(line=line, is_anomaly=False, score=0.0)
                    for line in req.logs
                ],
                model_version=FALLBACK_VERSION,
            )
        results = tfidf_detector.predict(loaded.artifact, req.logs)
        return LogAnomalyResponse(
            predictions=[
                LogLinePrediction(
                    line=r["line"],
                    is_anomaly=r["is_anomaly"],
                    score=r["score"],
                )
                for r in results
            ],
            model_version=loaded.version,
        )

    return app


app = create_app()
