from __future__ import annotations

from sentinel_ml.features.cve_relevance import (
    CVEAffectedPackage,
    CVERecord,
    CVERelevancePrediction,
    SBOMComponent,
    assess_cve_relevance,
    build_cve_relevance_prediction,
    cve_records_from_trivy,
    match_sbom_component,
    normalize_package_name,
    normalize_severity,
    rank_cve_relevance,
    sbom_components_from_syft,
    sbom_components_from_trivy,
)

TRIVY_SBOM_FIXTURE = {
    "Results": [
        {
            "Packages": [
                {
                    "PkgName": "openssl",
                    "InstalledVersion": "3.0.7",
                    "Type": "debian",
                    "PURL": "pkg:deb/debian/openssl@3.0.7",
                    "CPEs": ["cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*"],
                }
            ]
        }
    ]
}

SYFT_SBOM_FIXTURE = {
    "artifacts": [
        {
            "name": "python-dateutil",
            "version": "2.8.2",
            "type": "python",
            "purl": "pkg:pypi/python-dateutil@2.8.2",
            "cpes": ["cpe:2.3:a:python-dateutil_project:python-dateutil:2.8.2:*:*:*:*:*:*:*"],
        }
    ]
}

TRIVY_VULNERABILITIES_FIXTURE = {
    "Results": [
        {
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2026-1000",
                    "PkgName": "openssl",
                    "PkgType": "debian",
                    "InstalledVersion": "3.0.7",
                    "FixedVersion": "3.0.8",
                    "Title": "OpenSSL vulnerability",
                    "Severity": "HIGH",
                    "CVSS": {"nvd": {"V3Score": 8.8}},
                }
            ]
        }
    ]
}


def test_normalize_package_name_lowercases_and_normalizes_spacing():
    assert normalize_package_name(" Open_SSL Package ") == "open-ssl-package"


def test_normalize_severity_accepts_known_values():
    assert normalize_severity("HIGH") == "high"
    assert normalize_severity("unknown") == "unknown"
    assert normalize_severity("weird") is None


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


def test_sbom_components_from_trivy_parses_common_package_fields():
    components = sbom_components_from_trivy(TRIVY_SBOM_FIXTURE)

    assert len(components) == 1
    assert components[0].name == "openssl"
    assert components[0].version == "3.0.7"
    assert components[0].ecosystem == "debian"
    assert components[0].purl == "pkg:deb/debian/openssl@3.0.7"


def test_sbom_components_from_syft_parses_common_artifact_fields():
    components = sbom_components_from_syft(SYFT_SBOM_FIXTURE)

    assert len(components) == 1
    assert components[0].name == "python-dateutil"
    assert components[0].version == "2.8.2"
    assert components[0].ecosystem == "python"
    assert components[0].purl == "pkg:pypi/python-dateutil@2.8.2"


def test_cve_records_from_trivy_parses_vulnerability_entries():
    records = cve_records_from_trivy(TRIVY_VULNERABILITIES_FIXTURE)

    assert len(records) == 1
    assert records[0].cve_id == "CVE-2026-1000"
    assert records[0].cvss_score == 8.8
    assert records[0].severity == "high"
    assert records[0].affected_packages[0].fixed_version == "3.0.8"


def test_build_cve_relevance_prediction_returns_serializable_envelope():
    sbom = sbom_components_from_trivy(TRIVY_SBOM_FIXTURE)
    cves = cve_records_from_trivy(TRIVY_VULNERABILITIES_FIXTURE)

    prediction = build_cve_relevance_prediction(cves, sbom)

    assert isinstance(prediction, CVERelevancePrediction)
    assert prediction.source == "deterministic"
    assert len(prediction.related_cves) == 1
    assert prediction.related_cves[0].cve_id == "CVE-2026-1000"
    assert prediction.related_cves[0].relevance == "relevant"
