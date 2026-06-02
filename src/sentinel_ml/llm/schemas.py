"""Typed schemas for validated LLM output."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ThreatCategory = Literal[
    "malware",
    "phishing",
    "ddos",
    "intrusion",
    "ransomware",
    "supply_chain",
    "insider",
    "other",
]

SeverityLevel = Literal["low", "medium", "high", "critical"]


class ThreatClassificationResult(BaseModel):
    """Validated result for zero-shot threat-report classification."""

    model_config = ConfigDict(extra="forbid", strict=True)

    category: ThreatCategory
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(min_length=1, max_length=500)


class CVERelevanceResult(BaseModel):
    """Validated result for CVE relevance classification."""

    model_config = ConfigDict(extra="forbid", strict=True)

    relevant: bool
    severity: SeverityLevel
    rationale: str = Field(min_length=1, max_length=500)
