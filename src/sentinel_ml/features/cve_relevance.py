"""Deterministic CVE relevance matching against SBOM components.

This module intentionally starts with a rule-based core:

- normalize package identifiers
- match CVE affected packages against SBOM components
- compare installed versions against affected ranges or fixed versions
- rank results by relevance and CVSS severity

The LLM layer can later be used as a secondary signal when matching is
ambiguous, but the first-pass result here remains deterministic and testable.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ConfigDict, Field

SeverityLevel = Literal["low", "medium", "high", "critical", "unknown"]
RelevanceLevel = Literal["relevant", "uncertain", "not_relevant"]
MatchType = Literal["version_in_range", "below_fixed_version", "name_only", "none"]

_RELEVANCE_ORDER = {"relevant": 2, "uncertain": 1, "not_relevant": 0}
_MATCH_ORDER = {
    "version_in_range": 3,
    "below_fixed_version": 2,
    "name_only": 1,
    "none": 0,
}


class SBOMComponent(BaseModel):
    """Normalized SBOM component used for deterministic CVE matching."""

    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = Field(min_length=1)
    version: str | None = None
    ecosystem: str | None = None
    purl: str | None = None
    cpe: str | None = None


class CVEAffectedPackage(BaseModel):
    """Package and version information extracted from a CVE record."""

    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = Field(min_length=1)
    ecosystem: str | None = None
    version_range: str | None = None
    fixed_version: str | None = None


class CVERecord(BaseModel):
    """Minimal deterministic CVE record for relevance ranking."""

    model_config = ConfigDict(extra="forbid", strict=True)

    cve_id: str = Field(min_length=1)
    summary: str = ""
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    severity: SeverityLevel | None = None
    affected_packages: list[CVEAffectedPackage] = Field(default_factory=list)


class CVERelevanceAssessment(BaseModel):
    """Rankable CVE relevance output used before any LLM fallback."""

    model_config = ConfigDict(extra="forbid", strict=True)

    cve_id: str
    relevance: RelevanceLevel
    match_type: MatchType
    matched_component: str | None = None
    installed_version: str | None = None
    affected_range: str | None = None
    fixed_version: str | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    severity: SeverityLevel
    rationale: str = Field(min_length=1, max_length=500)


class CVERelevancePrediction(BaseModel):
    """Serializable output envelope for later write-back to ml_predictions."""

    model_config = ConfigDict(extra="forbid", strict=True)

    source: Literal["deterministic"] = "deterministic"
    related_cves: list[CVERelevanceAssessment] = Field(default_factory=list)


def normalize_package_name(name: str) -> str:
    """Normalize package identifiers across SBOM and CVE feeds."""
    return "-".join(name.strip().lower().replace("_", "-").split())


def normalize_ecosystem(ecosystem: str | None) -> str | None:
    """Normalize ecosystem aliases to a compact comparable form."""
    if ecosystem is None:
        return None
    cleaned = ecosystem.strip().lower()
    aliases = {
        "deb": "debian",
        "rpm": "rpm",
        "pip": "pypi",
        "python": "pypi",
        "npmjs": "npm",
        "golang": "go",
    }
    return aliases.get(cleaned, cleaned)


def infer_component_names(component: SBOMComponent) -> set[str]:
    """Collect candidate names from plain name, purl, and CPE."""
    names = {normalize_package_name(component.name)}
    if component.purl and "/" in component.purl:
        pkg_part = component.purl.rsplit("/", maxsplit=1)[-1]
        pkg_name = pkg_part.split("@", maxsplit=1)[0]
        if pkg_name:
            names.add(normalize_package_name(pkg_name))
    if component.cpe:
        parts = component.cpe.split(":")
        if len(parts) >= 5 and parts[4]:
            names.add(normalize_package_name(parts[4]))
    return names


def severity_from_cvss(cvss_score: float | None) -> SeverityLevel:
    """Derive a coarse severity level from a CVSS base score."""
    if cvss_score is None:
        return "unknown"
    if cvss_score >= 9.0:
        return "critical"
    if cvss_score >= 7.0:
        return "high"
    if cvss_score >= 4.0:
        return "medium"
    return "low"


def sbom_components_from_normalized(items: list[dict]) -> list[SBOMComponent]:
    """Parse already-normalized SBOM entries into strict component models."""
    return [SBOMComponent.model_validate(item) for item in items]


def sbom_components_from_syft(document: dict) -> list[SBOMComponent]:
    """Best-effort adapter for common Syft SBOM fields.

    Expected fields are intentionally conservative:

    - artifacts[].name
    - artifacts[].version
    - artifacts[].type
    - artifacts[].purl
    - artifacts[].cpes or artifact.metadata.cpes
    """
    components: list[SBOMComponent] = []
    for artifact in document.get("artifacts", []):
        cpes = artifact.get("cpes") or artifact.get("metadata", {}).get("cpes") or []
        component = SBOMComponent(
            name=str(artifact["name"]),
            version=_optional_str(artifact.get("version")),
            ecosystem=_optional_str(artifact.get("type")),
            purl=_optional_str(artifact.get("purl")),
            cpe=_first_string(cpes),
        )
        components.append(component)
    return components


def sbom_components_from_trivy(document: dict) -> list[SBOMComponent]:
    """Best-effort adapter for common Trivy SBOM/package fields."""
    components: list[SBOMComponent] = []
    for result in document.get("Results", []):
        for package in result.get("Packages", []):
            component = SBOMComponent(
                name=str(package.get("PkgName") or package.get("Name")),
                version=_optional_str(package.get("InstalledVersion") or package.get("Version")),
                ecosystem=_optional_str(package.get("Type") or package.get("PkgType")),
                purl=_optional_str(package.get("PURL") or package.get("PkgIdentifier", {}).get("PURL")),
                cpe=_first_string(package.get("CPEs") or package.get("PkgIdentifier", {}).get("CPEs") or []),
            )
            components.append(component)
    return components


def cve_records_from_normalized(items: list[dict]) -> list[CVERecord]:
    """Parse already-normalized vulnerability entries into CVE records."""
    return [CVERecord.model_validate(item) for item in items]


def cve_records_from_trivy(document: dict) -> list[CVERecord]:
    """Best-effort adapter for common Trivy vulnerability fields."""
    records: dict[str, CVERecord] = {}
    for result in document.get("Results", []):
        for vulnerability in result.get("Vulnerabilities", []):
            cve_id = _optional_str(vulnerability.get("VulnerabilityID"))
            package_name = _optional_str(vulnerability.get("PkgName"))
            if not cve_id or not package_name:
                continue

            affected = CVEAffectedPackage(
                name=package_name,
                ecosystem=_optional_str(vulnerability.get("PkgType") or vulnerability.get("Type")),
                fixed_version=_optional_str(vulnerability.get("FixedVersion")),
            )
            existing = records.get(cve_id)
            if existing is None:
                records[cve_id] = CVERecord(
                    cve_id=cve_id,
                    summary=_optional_str(vulnerability.get("Title")) or "",
                    cvss_score=_extract_trivy_cvss(vulnerability),
                    severity=normalize_severity(_optional_str(vulnerability.get("Severity"))),
                    affected_packages=[affected],
                )
            else:
                existing.affected_packages.append(affected)
    return list(records.values())


def build_cve_relevance_prediction(
    cves: list[CVERecord],
    sbom_components: list[SBOMComponent],
) -> CVERelevancePrediction:
    """Produce a serializable deterministic prediction envelope."""
    return CVERelevancePrediction(related_cves=rank_cve_relevance(cves, sbom_components))


def _parse_version(version: str | None) -> Version | None:
    if not version:
        return None
    try:
        return Version(version.strip())
    except InvalidVersion:
        return None


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _first_string(values: list[object]) -> str | None:
    for value in values:
        text = _optional_str(value)
        if text:
            return text
    return None


def _extract_trivy_cvss(vulnerability: dict) -> float | None:
    cvss = vulnerability.get("CVSS")
    if not isinstance(cvss, dict):
        return None

    scores: list[float] = []
    for vendor_data in cvss.values():
        if not isinstance(vendor_data, dict):
            continue
        score = vendor_data.get("V3Score") or vendor_data.get("Score")
        if isinstance(score, int | float):
            scores.append(float(score))
    return max(scores) if scores else None


def normalize_severity(severity: str | None) -> SeverityLevel | None:
    """Normalize severity values from vulnerability feeds."""
    if severity is None:
        return None
    normalized = severity.strip().lower()
    if normalized in {"low", "medium", "high", "critical", "unknown"}:
        return normalized
    return None


@lru_cache(maxsize=128)
def _parse_specifier(specifier: str) -> SpecifierSet | None:
    try:
        return SpecifierSet(specifier)
    except InvalidSpecifier:
        return None


def _version_matches_range(version: str | None, version_range: str | None) -> bool:
    if not version or not version_range:
        return False
    parsed_version = _parse_version(version)
    if parsed_version is None:
        return False
    specifier = _parse_specifier(version_range.strip())
    if specifier is None:
        return False
    return parsed_version in specifier


def _version_below_fixed(version: str | None, fixed_version: str | None) -> bool:
    parsed_version = _parse_version(version)
    parsed_fixed = _parse_version(fixed_version)
    if parsed_version is None or parsed_fixed is None:
        return False
    return parsed_version < parsed_fixed


def _ecosystems_compatible(component: SBOMComponent, affected: CVEAffectedPackage) -> bool:
    component_ecosystem = normalize_ecosystem(component.ecosystem)
    affected_ecosystem = normalize_ecosystem(affected.ecosystem)
    if component_ecosystem and affected_ecosystem:
        return component_ecosystem == affected_ecosystem
    return True


def match_sbom_component(
    component: SBOMComponent,
    affected: CVEAffectedPackage,
) -> tuple[MatchType, str]:
    """Return the best deterministic match type for one component/package pair."""
    if not _ecosystems_compatible(component, affected):
        return "none", "Package ecosystem does not match the affected package entry."

    normalized_target = normalize_package_name(affected.name)
    if normalized_target not in infer_component_names(component):
        return "none", "Package name does not match any SBOM component identifier."

    if affected.version_range:
        if _version_matches_range(component.version, affected.version_range):
            return (
                "version_in_range",
                "Installed version falls inside the affected version range.",
            )
        return "none", "Package name matches, but installed version is outside the affected range."

    if affected.fixed_version:
        if _version_below_fixed(component.version, affected.fixed_version):
            return "below_fixed_version", "Installed version is lower than the first fixed version."
        return "none", "Package name matches, but installed version is at or above the fixed version."

    return "name_only", "Package name matches, but no deterministic version constraint was provided."


def assess_cve_relevance(
    cve: CVERecord,
    sbom_components: list[SBOMComponent],
) -> CVERelevanceAssessment:
    """Assess one CVE against an SBOM and return the strongest deterministic match."""
    severity = cve.severity or severity_from_cvss(cve.cvss_score)
    best: CVERelevanceAssessment | None = None

    for affected in cve.affected_packages:
        for component in sbom_components:
            match_type, reason = match_sbom_component(component, affected)
            if match_type == "none":
                continue

            relevance: RelevanceLevel = "uncertain" if match_type == "name_only" else "relevant"
            assessment = CVERelevanceAssessment(
                cve_id=cve.cve_id,
                relevance=relevance,
                match_type=match_type,
                matched_component=component.name,
                installed_version=component.version,
                affected_range=affected.version_range,
                fixed_version=affected.fixed_version,
                cvss_score=cve.cvss_score,
                severity=severity,
                rationale=reason,
            )
            if best is None or _assessment_sort_key(assessment) > _assessment_sort_key(best):
                best = assessment

    if best is not None:
        return best

    return CVERelevanceAssessment(
        cve_id=cve.cve_id,
        relevance="not_relevant",
        match_type="none",
        cvss_score=cve.cvss_score,
        severity=severity,
        rationale="No affected package could be matched against the SBOM.",
    )


def rank_cve_relevance(
    cves: list[CVERecord],
    sbom_components: list[SBOMComponent],
) -> list[CVERelevanceAssessment]:
    """Assess and sort multiple CVEs by relevance and severity."""
    assessments = [assess_cve_relevance(cve, sbom_components) for cve in cves]
    return sorted(assessments, key=_assessment_sort_key, reverse=True)


def _assessment_sort_key(assessment: CVERelevanceAssessment) -> tuple[int, float, int]:
    return (
        _RELEVANCE_ORDER[assessment.relevance],
        assessment.cvss_score or -1.0,
        _MATCH_ORDER[assessment.match_type],
    )
