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

import csv
import hashlib
import io
import json
import logging
import re
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from email import policy
from email.parser import Parser
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from sentinel_ml import __version__
from sentinel_ml.config import get_settings
from sentinel_ml.data.predictions import upsert_ml_prediction_document
from sentinel_ml.data.schemas import IOC, MacroAnalysis, Prediction, UploadRecord
from sentinel_ml.features.cve_relevance import (
    CVERelevancePrediction,
    build_cve_relevance_prediction,
    cve_records_from_normalized,
    cve_records_from_trivy,
    sbom_components_from_normalized,
    sbom_components_from_trivy,
)
from sentinel_ml.features.hash_match import (
    collect_hashes_from_malware_samples,
    collect_hashes_from_reports,
    match_upload_hash,
)
from sentinel_ml.features.ioc_extract import extract_iocs
from sentinel_ml.features.macro_risk import assess_macro_risk
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


class UploadIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    upload_id: str
    filename: str
    content_type: str
    sha256: str | None = None
    size_bytes: int | None = None
    scan_status: str = "clean"
    scan_engine: str = "unknown"
    scan_detail: str = ""
    risk_score: int = 0
    source: Literal["upload"] = "upload"
    # Static VBA analysis from upstream (None for non-Office files or when
    # the caller predates macro extraction).
    macro: MacroAnalysis | None = None


class UploadIngestResponse(BaseModel):
    upload_id: str
    source: str
    prediction: Prediction
    model_version: str
    scan_status: str
    scan_engine: str
    scan_detail: str
    risk_score: int
    known_malicious: bool = False
    macro_risk: bool = False
    macro_reason: str = ""


class UploadTextIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    upload_id: str
    filename: str
    content_type: str
    scan_status: str = "clean"
    scan_engine: str = "unknown"
    scan_detail: str = ""
    extracted_text: str | None = None
    raw_content: str | None = None
    source: Literal["upload_text"] = "upload_text"


class LiveFlowUploadTextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    upload_id: str
    filename: str
    content_type: str
    scan_status: str = "clean"
    scan_engine: str = "unknown"
    scan_detail: str = ""
    extracted_text: str
    source: Literal["upload_text"] = "upload_text"


class UploadTextIngestResponse(BaseModel):
    upload_id: str
    source: str
    prediction: Prediction
    model_version: str
    iocs: list[IOC]
    extracted_text: str
    text_truncated: bool


class SBOMComponent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    ecosystem: str | None = None
    purl: str | None = None
    cpe: str | None = None


class CVEAffectedPackage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    ecosystem: str | None = None
    fixed_version: str | None = None


class CVEItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: str
    summary: str
    cvss_score: float
    severity: str
    affected_packages: list[CVEAffectedPackage] = []


class CVERelevanceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sbom_components: list[SBOMComponent]
    cves: list[CVEItem]


class CVEMatchedComponent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    ecosystem: str | None = None
    purl: str | None = None


class CVERelevanceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: str
    severity: str
    cvss_score: float
    summary: str
    relevance_score: float
    matched_components: list[CVEMatchedComponent]
    reason: str


class CVERelevanceSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_cves: int
    matched_cves: int
    matched_high_or_critical: int


class CVERelevanceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    results: list[CVERelevanceItem]
    summary: CVERelevanceSummary


class TrivyCVERelevanceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sbom_document: dict[str, Any]
    vulnerability_document: dict[str, Any]


class LiveFlowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    upload: UploadIngestRequest | None = None
    upload_text: LiveFlowUploadTextRequest | None = None
    cve_relevance: CVERelevanceRequest | None = None


class LiveFlowSummary(BaseModel):
    has_upload: bool
    has_upload_text: bool
    has_cve_relevance: bool
    ioc_count: int = 0
    matched_cves: int = 0
    known_malicious_hash: bool = False
    macro_risk: bool = False


class LiveFlowResponse(BaseModel):
    upload_result: UploadIngestResponse | None = None
    upload_text_result: UploadTextIngestResponse | None = None
    cve_relevance_result: CVERelevanceResponse | None = None
    summary: LiveFlowSummary


class MLPredictionDocument(BaseModel):
    upload_id: str
    ml_provider: str = "sentinel-ml"
    ml_liveflow: LiveFlowResponse
    created_at: datetime


class MLPredictionWriteBackResponse(BaseModel):
    persisted: bool
    collection: str = "ml_predictions"
    document: MLPredictionDocument


class LogAnomalyRequest(BaseModel):
    logs: list[str]


class LogLinePrediction(BaseModel):
    line: str
    is_anomaly: bool
    score: float


class LogAnomalyResponse(BaseModel):
    predictions: list[LogLinePrediction]
    model_version: str


MAX_RAW_TEXT_CHARS = 200_000
MAX_EXTRACTED_TEXT_CHARS = 10_000
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


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


def _load_hash_source(path: Path | None, label: str, collect: Callable[[Path], set[str]]) -> set[str]:
    """Load one known-malicious hash source. Empty set on any problem."""
    if path is None:
        return set()
    p = Path(path)
    if not p.exists():
        logger.info("Hash-bridge: %s source missing at %s — skipped", label, p)
        return set()
    try:
        hashes = collect(p)
        logger.info("Hash-bridge: loaded %d hashes from %s (%s)", len(hashes), label, p)
        return hashes
    except Exception:  # noqa: BLE001 — degrade rather than crash startup
        logger.exception("Hash-bridge: failed to load %s from %s", label, p)
        return set()


def _load_malicious_hashes(reports_path: Path | None, samples_path: Path | None) -> set[str]:
    """Union the known-malicious hash set from both sources at startup.

    - threat reports JSONL: hash IOCs extracted from report text/iocs
    - malware samples JSONL: sha256 per row (MalwareBazaar metadata)
    """
    from sentinel_ml.data.loaders import load_malware_samples_jsonl, load_threat_reports_jsonl

    hashes = _load_hash_source(
        reports_path,
        "threat-reports",
        lambda p: collect_hashes_from_reports(load_threat_reports_jsonl(p)),
    )
    hashes |= _load_hash_source(
        samples_path,
        "malware-samples",
        lambda p: collect_hashes_from_malware_samples(load_malware_samples_jsonl(p)),
    )
    if hashes:
        logger.info("Hash-bridge: %d known-malicious hashes total", len(hashes))
    else:
        logger.info("Hash-bridge: no hash sources loaded — bridge reports no matches")
    return hashes


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
    app.state.malicious_hashes = _load_malicious_hashes(
        settings.known_malicious_hashes_path, settings.malware_samples_path
    )
    yield


def _get_loaded(request: Request, attr: str) -> LoadedModel | None:
    """Read a loaded model off app state, tolerating tests that skip lifespan."""
    return getattr(request.app.state, attr, None)


def _get_malicious_hashes(request: Request) -> set[str]:
    """Read the known-malicious hash set off app state (empty if lifespan skipped)."""
    return getattr(request.app.state, "malicious_hashes", set())


def _call_ollama(text: str) -> LLMAnalysis | None:
    """Call Ollama for LLM-based threat classification. Returns None on any failure.

    Gated behind ``settings.llm_enabled`` (default False): the deployed path
    runs the classical models and never touches Ollama unless explicitly opted
    in. When enabled, OllamaClient is imported locally so the optional ``[llm]``
    dependency (httpx) is only required at that point — the production image
    installs base deps only, so a missing httpx degrades to None here instead
    of crashing the service at import time.
    """
    settings = get_settings()
    if not settings.llm_enabled:
        return None
    try:
        from sentinel_ml.llm.ollama_client import OllamaClient

        client = OllamaClient(timeout=settings.ollama_timeout_seconds)
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


def _normalize(value: str | None) -> str:
    return (value or "").strip().lower()


def _sanitize_text(value: str) -> str:
    cleaned = _CONTROL_CHAR_RE.sub("", value)
    return cleaned.replace("\r\n", "\n").replace("\r", "\n")


def _extension(filename: str) -> str:
    idx = filename.rfind(".")
    return filename[idx:].lower() if idx >= 0 else ""


def _extract_text(raw_content: str, content_type: str, filename: str) -> str:
    ext = _extension(filename)
    ctype = _normalize(content_type)
    raw = raw_content[:MAX_RAW_TEXT_CHARS]

    if ctype == "message/rfc822" or ext == ".eml":
        msg = Parser(policy=policy.default).parsestr(raw)
        parts: list[str] = []
        subject = msg.get("subject", "")
        sender = msg.get("from", "")
        if subject:
            parts.append(f"Subject: {subject}")
        if sender:
            parts.append(f"From: {sender}")
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_content()
                    if isinstance(payload, str):
                        parts.append(payload)
        else:
            payload = msg.get_content()
            if isinstance(payload, str):
                parts.append(payload)
        return "\n".join(parts)

    if ctype == "application/json" or ext == ".json":
        parsed = json.loads(raw)
        return json.dumps(parsed, ensure_ascii=False)

    if ctype == "text/csv" or ext == ".csv":
        reader = csv.reader(io.StringIO(raw))
        rows = []
        for idx, row in enumerate(reader):
            rows.append(", ".join(col.strip() for col in row if col is not None))
            if idx >= 200:
                break
        return "\n".join(rows)

    # text/plain, markdown and any unknown text-like input fallback
    return raw


def _threat_predict_text(text: str, request: Request) -> tuple[Prediction, str]:
    loaded = _get_loaded(request, "threat_model")
    if loaded is None:
        return Prediction(label="unknown", confidence=0.0), FALLBACK_VERSION
    prediction = _predict_with(loaded, [text])
    return prediction, loaded.version


def _parse_simple_version(value: str | None) -> tuple[int, ...] | None:
    if not value:
        return None
    tokenized = [p for p in re.split(r"[^0-9]+", value) if p]
    if not tokenized:
        return None
    return tuple(int(p) for p in tokenized)


def _is_likely_affected(component_version: str, fixed_version: str | None) -> bool:
    if not fixed_version:
        return True
    comp = _parse_simple_version(component_version)
    fixed = _parse_simple_version(fixed_version)
    if comp is not None and fixed is not None:
        return comp < fixed
    return _normalize(component_version) != _normalize(fixed_version)


def _cve_relevance(req: CVERelevanceRequest) -> CVERelevanceResponse:
    results: list[CVERelevanceItem] = []
    matched_high_or_critical = 0

    for cve in req.cves:
        matched_components: list[CVEMatchedComponent] = []
        ecosystem_bonus = 0.0

        for comp in req.sbom_components:
            comp_name = _normalize(comp.name)
            comp_ecosystem = _normalize(comp.ecosystem)
            comp_matched = False
            eco_matched_for_component = False

            for pkg in cve.affected_packages:
                if _normalize(pkg.name) != comp_name:
                    continue

                pkg_ecosystem = _normalize(pkg.ecosystem)
                ecosystem_match = not pkg_ecosystem or pkg_ecosystem == comp_ecosystem
                if not ecosystem_match:
                    continue

                if _is_likely_affected(comp.version, pkg.fixed_version):
                    comp_matched = True
                    eco_matched_for_component = eco_matched_for_component or bool(pkg_ecosystem)
                    break

            if comp_matched:
                matched_components.append(
                    CVEMatchedComponent(
                        name=comp.name,
                        version=comp.version,
                        ecosystem=comp.ecosystem,
                        purl=comp.purl,
                    )
                )
                if eco_matched_for_component:
                    ecosystem_bonus = max(ecosystem_bonus, 0.2)

        if matched_components:
            cvss_norm = max(0.0, min(cve.cvss_score, 10.0)) / 10.0
            relevance = min(1.0, 0.5 + cvss_norm * 0.3 + ecosystem_bonus)
            reason = (
                f"{len(matched_components)} SBOM-komponent(er) matchar affected_packages "
                "och version bedöms påverkas."
            )
            if _normalize(cve.severity) in {"high", "critical"}:
                matched_high_or_critical += 1
        else:
            relevance = 0.0
            reason = "Ingen match mellan CVE affected_packages och SBOM-komponenter."

        results.append(
            CVERelevanceItem(
                cve_id=cve.cve_id,
                severity=cve.severity,
                cvss_score=cve.cvss_score,
                summary=cve.summary,
                relevance_score=round(relevance, 3),
                matched_components=matched_components,
                reason=reason,
            )
        )

    matched_cves = sum(1 for r in results if r.matched_components)
    return CVERelevanceResponse(
        results=results,
        summary=CVERelevanceSummary(
            total_cves=len(req.cves),
            matched_cves=matched_cves,
            matched_high_or_critical=matched_high_or_critical,
        ),
    )


def _cve_relevance_prediction(req: CVERelevanceRequest) -> CVERelevancePrediction:
    components = sbom_components_from_normalized(
        [component.model_dump(mode="json") for component in req.sbom_components]
    )
    cves = cve_records_from_normalized([cve.model_dump(mode="json") for cve in req.cves])
    return build_cve_relevance_prediction(cves, components)


def _cve_relevance_prediction_from_trivy(
    req: TrivyCVERelevanceRequest,
) -> CVERelevancePrediction:
    components = sbom_components_from_trivy(req.sbom_document)
    cves = cve_records_from_trivy(req.vulnerability_document)
    return build_cve_relevance_prediction(cves, components)


def _predict_upload_record(record: UploadRecord, request: Request) -> UploadResponse:
    loaded = _get_loaded(request, "upload_model")
    if loaded is None:
        return UploadResponse(
            prediction=Prediction(label="unknown", confidence=0.0),
            model_version=FALLBACK_VERSION,
        )
    features, _ = build_feature_matrix([record])
    prediction = _predict_with(loaded, features)
    return UploadResponse(prediction=prediction, model_version=loaded.version)


def _predict_upload_ingest(req: UploadIngestRequest, request: Request) -> UploadIngestResponse:
    record = UploadRecord(
        filename=req.filename,
        content_type=req.content_type,
        sha256=req.sha256,
        size_bytes=req.size_bytes,
        scan_status=req.scan_status,
        decision="accepted",
        risk_score=req.risk_score,
        status="accepted",
        scan_engine=req.scan_engine,
        scan_detail=req.scan_detail,
    )
    result = _predict_upload_record(record, request)
    macro_risk, macro_reason = assess_macro_risk(req.macro)
    return UploadIngestResponse(
        upload_id=req.upload_id,
        source=req.source,
        prediction=result.prediction,
        model_version=result.model_version,
        scan_status=req.scan_status,
        scan_engine=req.scan_engine,
        scan_detail=req.scan_detail,
        risk_score=req.risk_score,
        known_malicious=match_upload_hash(req.sha256, _get_malicious_hashes(request)),
        macro_risk=macro_risk,
        macro_reason=macro_reason,
    )


def _predict_upload_text_ingest(
    req: UploadTextIngestRequest | LiveFlowUploadTextRequest, request: Request
) -> UploadTextIngestResponse:
    text_source = req.extracted_text
    raw_content = getattr(req, "raw_content", None)
    if not text_source and raw_content:
        try:
            text_source = _extract_text(raw_content, req.content_type, req.filename)
        except Exception:  # noqa: BLE001
            logger.exception("Text extraction failed for upload_id=%s", req.upload_id)
            text_source = ""

    sanitized = _sanitize_text(text_source or "")
    truncated = len(sanitized) > MAX_EXTRACTED_TEXT_CHARS
    final_text = sanitized[:MAX_EXTRACTED_TEXT_CHARS]

    prediction, model_version = _threat_predict_text(final_text, request)
    iocs = extract_iocs(final_text)

    return UploadTextIngestResponse(
        upload_id=req.upload_id,
        source=req.source,
        prediction=prediction,
        model_version=model_version,
        iocs=iocs,
        extracted_text=final_text,
        text_truncated=truncated,
    )


def _predict_liveflow(req: LiveFlowRequest, request: Request) -> LiveFlowResponse:
    upload_result = _predict_upload_ingest(req.upload, request) if req.upload else None
    upload_text_result = (
        _predict_upload_text_ingest(req.upload_text, request) if req.upload_text else None
    )
    cve_result = _cve_relevance(req.cve_relevance) if req.cve_relevance else None

    ioc_count = len(upload_text_result.iocs) if upload_text_result else 0
    matched_cves = cve_result.summary.matched_cves if cve_result else 0

    return LiveFlowResponse(
        upload_result=upload_result,
        upload_text_result=upload_text_result,
        cve_relevance_result=cve_result,
        summary=LiveFlowSummary(
            has_upload=upload_result is not None,
            has_upload_text=upload_text_result is not None,
            has_cve_relevance=cve_result is not None,
            ioc_count=ioc_count,
            matched_cves=matched_cves,
            known_malicious_hash=upload_result.known_malicious if upload_result else False,
            macro_risk=upload_result.macro_risk if upload_result else False,
        ),
    )


def _storage_safe_liveflow_response(response: LiveFlowResponse) -> LiveFlowResponse:
    upload_text_result = response.upload_text_result
    if upload_text_result is None:
        return response
    redacted_upload_text_result = upload_text_result.model_copy(
        update={"extracted_text": ""}
    )
    return response.model_copy(update={"upload_text_result": redacted_upload_text_result})


def _resolve_upload_id(req: LiveFlowRequest) -> str:
    if req.upload is not None:
        return req.upload.upload_id
    if req.upload_text is not None:
        return req.upload_text.upload_id
    raise HTTPException(
        status_code=400,
        detail="liveflow-document requires upload or upload_text to provide upload_id",
    )


def _build_ml_prediction_document(
    req: LiveFlowRequest, response: LiveFlowResponse
) -> MLPredictionDocument:
    return MLPredictionDocument(
        upload_id=_resolve_upload_id(req),
        ml_liveflow=_storage_safe_liveflow_response(response),
        created_at=datetime.now(UTC),
    )


def _configure_logging() -> None:
    """Make sentinel_ml INFO logs visible in the service process.

    Uvicorn only configures its own loggers; module loggers propagate to the
    root logger, which drops INFO without a handler — so startup lines like
    the hash-bridge counts never reached `kubectl logs`. basicConfig is a
    no-op when the root logger already has handlers (e.g. under pytest), so
    test log capture is unaffected.
    """
    level = logging.getLevelNamesMapping().get(get_settings().log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def create_app() -> FastAPI:
    """Build a FastAPI app. Use this in tests to get a fresh lifespan."""
    _configure_logging()
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
        return _predict_upload_record(record, request)

    @app.post("/predict/upload-ingest", response_model=UploadIngestResponse)
    def predict_upload_ingest(req: UploadIngestRequest, request: Request) -> UploadIngestResponse:
        return _predict_upload_ingest(req, request)

    @app.post("/predict/upload-text-ingest", response_model=UploadTextIngestResponse)
    def predict_upload_text_ingest(req: UploadTextIngestRequest, request: Request) -> UploadTextIngestResponse:
        return _predict_upload_text_ingest(req, request)

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

    @app.post("/predict/cve-relevance", response_model=CVERelevanceResponse)
    def predict_cve_relevance(req: CVERelevanceRequest) -> CVERelevanceResponse:
        return _cve_relevance(req)

    @app.post("/predict/cve-relevance-prediction", response_model=CVERelevancePrediction)
    def predict_cve_relevance_prediction(
        req: CVERelevanceRequest,
    ) -> CVERelevancePrediction:
        return _cve_relevance_prediction(req)

    @app.post("/predict/cve-relevance-trivy", response_model=CVERelevancePrediction)
    def predict_cve_relevance_trivy(
        req: TrivyCVERelevanceRequest,
    ) -> CVERelevancePrediction:
        return _cve_relevance_prediction_from_trivy(req)

    @app.post("/predict/liveflow", response_model=LiveFlowResponse)
    def predict_liveflow(req: LiveFlowRequest, request: Request) -> LiveFlowResponse:
        return _predict_liveflow(req, request)

    @app.post("/predict/liveflow-document", response_model=MLPredictionDocument)
    def predict_liveflow_document(req: LiveFlowRequest, request: Request) -> MLPredictionDocument:
        response = _predict_liveflow(req, request)
        return _build_ml_prediction_document(req, response)

    @app.post("/predict/liveflow-writeback", response_model=MLPredictionWriteBackResponse)
    def predict_liveflow_writeback(
        req: LiveFlowRequest, request: Request
    ) -> MLPredictionWriteBackResponse:
        document = _build_ml_prediction_document(req, _predict_liveflow(req, request))
        try:
            upsert_ml_prediction_document(document)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to write ml_predictions for upload_id=%s", document.upload_id)
            raise HTTPException(
                status_code=503,
                detail="failed to persist ml prediction document",
            ) from exc
        return MLPredictionWriteBackResponse(persisted=True, document=document)

    return app


app = create_app()
