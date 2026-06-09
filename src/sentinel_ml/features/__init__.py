"""Feature extraction. Pure functions: raw data in, feature arrays out."""

from sentinel_ml.features.cve_relevance import (
    CVEAffectedPackage,
    CVERecord,
    CVERelevanceAssessment,
    CVERelevancePrediction,
    SBOMComponent,
    assess_cve_relevance,
    build_cve_relevance_prediction,
    cve_records_from_normalized,
    cve_records_from_trivy,
    match_sbom_component,
    normalize_package_name,
    normalize_severity,
    rank_cve_relevance,
    sbom_components_from_normalized,
    sbom_components_from_syft,
    sbom_components_from_trivy,
)

__all__ = [
    "CVEAffectedPackage",
    "CVERecord",
    "CVERelevanceAssessment",
    "CVERelevancePrediction",
    "SBOMComponent",
    "assess_cve_relevance",
    "build_cve_relevance_prediction",
    "cve_records_from_normalized",
    "cve_records_from_trivy",
    "match_sbom_component",
    "normalize_package_name",
    "normalize_severity",
    "rank_cve_relevance",
    "sbom_components_from_normalized",
    "sbom_components_from_syft",
    "sbom_components_from_trivy",
]
