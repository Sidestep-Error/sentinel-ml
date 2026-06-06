from __future__ import annotations

from sentinel_ml.features.cve_relevance import (
    CVEAffectedPackage,
    CVERecord,
    SBOMComponent,
    assess_cve_relevance,
    match_sbom_component,
    normalize_package_name,
    rank_cve_relevance,
)


def test_normalize_package_name_lowercases_and_normalizes_spacing():
    assert normalize_package_name(" Open_SSL Package ") == "open-ssl-package"


def test_match_sbom_component_matches_version_range():
    component = SBOMComponent(name="openssl", version="3.0.7")
    affected = CVEAffectedPackage(name="OpenSSL", version_range=">=3.0.0,<3.0.8")

    match_type, rationale = match_sbom_component(component, affected)

    assert match_type == "version_in_range"
    assert "affected version range" in rationale


def test_match_sbom_component_matches_below_fixed_version():
    component = SBOMComponent(name="openssl", version="3.0.7")
    affected = CVEAffectedPackage(name="openssl", fixed_version="3.0.8")

    match_type, rationale = match_sbom_component(component, affected)

    assert match_type == "below_fixed_version"
    assert "first fixed version" in rationale


def test_assess_cve_relevance_marks_name_only_match_as_uncertain():
    cve = CVERecord(
        cve_id="CVE-2026-0001",
        summary="Affected package metadata lacks a precise version range.",
        cvss_score=5.4,
        affected_packages=[CVEAffectedPackage(name="nginx")],
    )
    components = [SBOMComponent(name="nginx", version="1.24.0")]

    result = assess_cve_relevance(cve, components)

    assert result.relevance == "uncertain"
    assert result.match_type == "name_only"
    assert result.matched_component == "nginx"
    assert result.severity == "medium"


def test_assess_cve_relevance_returns_not_relevant_when_no_match_exists():
    cve = CVERecord(
        cve_id="CVE-2026-0002",
        cvss_score=9.1,
        affected_packages=[CVEAffectedPackage(name="apache-httpd", version_range="<2.4.60")],
    )
    components = [SBOMComponent(name="openssl", version="3.0.7")]

    result = assess_cve_relevance(cve, components)

    assert result.relevance == "not_relevant"
    assert result.match_type == "none"
    assert result.matched_component is None
    assert result.severity == "critical"


def test_assess_cve_relevance_uses_purl_alias_when_component_name_differs():
    cve = CVERecord(
        cve_id="CVE-2026-0003",
        cvss_score=8.0,
        affected_packages=[CVEAffectedPackage(name="python-dateutil", version_range="<2.9.0")],
    )
    components = [
        SBOMComponent(
            name="dateutil",
            version="2.8.2",
            ecosystem="pypi",
            purl="pkg:pypi/python-dateutil@2.8.2",
        )
    ]

    result = assess_cve_relevance(cve, components)

    assert result.relevance == "relevant"
    assert result.match_type == "version_in_range"
    assert result.matched_component == "dateutil"


def test_rank_cve_relevance_orders_relevant_high_cvss_first():
    sbom = [SBOMComponent(name="openssl", version="3.0.7")]
    cves = [
        CVERecord(
            cve_id="CVE-2026-1000",
            cvss_score=5.0,
            affected_packages=[CVEAffectedPackage(name="openssl")],
        ),
        CVERecord(
            cve_id="CVE-2026-2000",
            cvss_score=9.8,
            affected_packages=[CVEAffectedPackage(name="openssl", fixed_version="3.0.8")],
        ),
        CVERecord(
            cve_id="CVE-2026-3000",
            cvss_score=9.9,
            affected_packages=[CVEAffectedPackage(name="nginx", fixed_version="1.25.0")],
        ),
    ]

    ranked = rank_cve_relevance(cves, sbom)

    assert [item.cve_id for item in ranked] == [
        "CVE-2026-2000",
        "CVE-2026-1000",
        "CVE-2026-3000",
    ]
