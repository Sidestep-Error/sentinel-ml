from sentinel_ml.data.schemas import IOCType
from sentinel_ml.features.ioc_extract import extract_iocs


def test_extracts_ipv4(threat_text_sample):
    iocs = extract_iocs(threat_text_sample)
    ips = [i.value for i in iocs if i.type == IOCType.IP]
    assert "8.8.8.8" in ips


def test_rejects_invalid_ipv4():
    iocs = extract_iocs("not an ip: 999.999.999.999 nor 1.2.3")
    assert not any(i.type == IOCType.IP for i in iocs)


def test_extracts_sha256(threat_text_sample):
    iocs = extract_iocs(threat_text_sample)
    hashes = [i.value for i in iocs if i.type == IOCType.HASH_SHA256]
    assert any(h == "b" * 64 for h in hashes)


def test_extracts_cve(threat_text_sample):
    iocs = extract_iocs(threat_text_sample)
    cves = [i.value for i in iocs if i.type == IOCType.CVE]
    assert "CVE-2024-12345" in cves


def test_extracts_domain_and_skips_url_domain(threat_text_sample):
    iocs = extract_iocs(threat_text_sample)
    domains = [i.value for i in iocs if i.type == IOCType.DOMAIN]
    assert "evil-domain.example" in domains
    # example.com appears inside the URL — should not double-count as a separate domain
    assert domains.count("example.com") <= 1


def test_dedup_same_value():
    text = "Hit from 1.1.1.1 then again 1.1.1.1 and once more 1.1.1.1."
    iocs = extract_iocs(text)
    ips = [i.value for i in iocs if i.type == IOCType.IP]
    assert ips == ["1.1.1.1"]


def test_empty_input():
    assert extract_iocs("") == []
