"""Feature extraction. Pure functions: raw data in, feature arrays out."""

from sentinel_ml.features.cve_relevance import (
    CVEAffectedPackage,
    CVERecord,
    CVERelevanceAssessment,
    SBOMComponent,
    assess_cve_relevance,
    match_sbom_component,
    normalize_package_name,
    rank_cve_relevance,
)

__all__ = [
    "CVEAffectedPackage",
    "CVERecord",
    "CVERelevanceAssessment",
    "SBOMComponent",
    "assess_cve_relevance",
    "match_sbom_component",
    "normalize_package_name",
    "rank_cve_relevance",
]
