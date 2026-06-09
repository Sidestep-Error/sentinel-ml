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
"""LLM wrappers. Isolated so backend can swap (Ollama -> OpenAI) without touching models.

Import submodules explicitly (``from sentinel_ml.llm.classifier import ...``).

IMPORTANT: do NOT eagerly import ``classifier`` or ``ollama_client`` here. Those
modules import ``httpx``, which lives in the optional ``[llm]`` extra. The
production image installs base deps only, so any module-level import of the
``[llm]`` extras (directly or transitively via this package init) crashes the
service at startup — see PR #38 / #44. ``service.api`` imports
``sentinel_ml.llm.prompts``, which triggers this init, so keeping it light is
what lets the prod image start without httpx.
"""

from __future__ import annotations
