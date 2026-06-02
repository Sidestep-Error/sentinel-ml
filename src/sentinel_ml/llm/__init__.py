"""LLM wrappers. Isolated so backend can swap (Ollama -> OpenAI) without touching models."""

from sentinel_ml.llm.classifier import (
    LLMResponseError,
    LLMResponseParseError,
    LLMResponseValidationError,
    classify_cve_relevance,
    classify_threat_report,
    try_classify_threat_report,
)
from sentinel_ml.llm.ollama_client import LLMResponse, OllamaClient
from sentinel_ml.llm.schemas import CVERelevanceResult, ThreatClassificationResult

__all__ = [
    "CVERelevanceResult",
    "LLMResponse",
    "LLMResponseError",
    "LLMResponseParseError",
    "LLMResponseValidationError",
    "OllamaClient",
    "ThreatClassificationResult",
    "classify_cve_relevance",
    "classify_threat_report",
    "try_classify_threat_report",
]
