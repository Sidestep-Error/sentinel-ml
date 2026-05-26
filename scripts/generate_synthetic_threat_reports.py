#!/usr/bin/env python
"""Generate a small synthetic threat-report dataset for baseline training.

Real datasets take time to source and license-check. This script gives
us something to iterate on while the real corpus is being downloaded.

Usage:
  python scripts/generate_synthetic_threat_reports.py --out data/threat_reports_sample.jsonl
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import typer

CATEGORIES = ["ransomware", "phishing", "ddos", "malware", "intrusion"]

TEMPLATES = {
    "ransomware": [
        "Observed ransomware variant encrypting files in /var with extension .{ext}. Demand note left as readme.txt.",
        "Ransomware sample SHA-256 {hash} spread via SMB share on the {subnet}/24 subnet.",
        "{family} ransomware family confirmed active. Payload sent to C2 at {ip}.",
    ],
    "phishing": [
        "Phishing email impersonating {brand} with credential-harvesting form at https://{domain}/login.",
        "Spear-phishing campaign targeting {sector} sector. Lure: invoice PDF dropping {family}.",
        "Phishing URL https://{domain}/{path} reported by {n} users in past 24h.",
    ],
    "ddos": [
        "DDoS flood at {gbps} Gbps saturating uplink. Source IPs span {country}.",
        "Botnet-driven DDoS hitting {sector} infrastructure. Mitigation via {vendor} active.",
        "UDP amplification DDoS via {protocol}. Reflector count: {n}.",
    ],
    "malware": [
        "Malware sample {hash} confirmed in the wild. Family: {family}. Behavior: process injection.",
        "PE file with SHA-256 {hash} drops {family} on Windows hosts via {vector}.",
        "{family} malware observed beaconing to {ip} every {sec} seconds.",
    ],
    "intrusion": [
        "Suspicious login from {ip} to {service} bypassed MFA via session-token replay.",
        "Lateral movement detected from {host} using {tool}. CVE-{cve_year}-{cve_id} exploited.",
        "Intrusion confirmed at {sector} customer. Initial access via {vector}.",
    ],
}

FILLERS = {
    "ext": ["locked", "crypt", "enc"],
    "hash": [lambda r: r.choice("0123456789abcdef") * 64],
    "subnet": ["10.0.0", "192.168.1", "172.16.5"],
    "family": ["LockBit", "Conti", "Emotet", "TrickBot", "AgentTesla", "RedLine"],
    "ip": ["198.51.100.42", "203.0.113.7", "192.0.2.55"],
    "brand": ["Microsoft", "Google", "Klarna", "Swedbank"],
    "domain": ["evil-login.example", "malicious.example.com", "fake-portal.test"],
    "sector": ["healthcare", "finance", "logistics", "government"],
    "path": ["secure-login", "verify-account", "update-password"],
    "n": ["12", "47", "183", "2401"],
    "gbps": ["12", "45", "180"],
    "country": ["RU, BR, CN", "VN, IN", "global"],
    "vendor": ["Cloudflare", "Akamai"],
    "protocol": ["DNS", "NTP", "memcached"],
    "vector": ["malspam", "drive-by download", "USB"],
    "sec": ["30", "60", "120"],
    "service": ["VPN gateway", "Outlook web access"],
    "host": ["DC01.corp.local", "FILESRV-7"],
    "tool": ["PsExec", "WMI", "PowerShell remoting"],
    "cve_year": ["2023", "2024"],
    "cve_id": ["12345", "98765", "44567"],
}


def fill(template: str, rng: random.Random) -> str:
    out = template
    while "{" in out:
        start = out.index("{")
        end = out.index("}", start)
        key = out[start + 1 : end]
        choices = FILLERS[key]
        choice = choices[rng.randrange(len(choices))]
        value = choice(rng) if callable(choice) else choice
        out = out[:start] + str(value) + out[end + 1 :]
    return out


def main(
    out: Path = typer.Option(Path("data/threat_reports_sample.jsonl"), help="Output JSONL path"),
    n_per_class: int = typer.Option(50, help="Reports per category"),
    seed: int = typer.Option(42, help="Random seed"),
) -> None:
    rng = random.Random(seed)
    out.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with out.open("w", encoding="utf-8") as f:
        for category in CATEGORIES:
            for i in range(n_per_class):
                template = rng.choice(TEMPLATES[category])
                text = fill(template, rng)
                record = {
                    "report_id": f"{category}-{i:04d}",
                    "text": text,
                    "source": "synthetic",
                    "labels": [category],
                    "iocs": [],
                }
                f.write(json.dumps(record) + "\n")
                count += 1

    typer.echo(f"Wrote {count} synthetic reports to {out}")


if __name__ == "__main__":
    typer.run(main)
