"""Automated incident-response playbook (SOAR integration).

Actions: IP blocking via iptables, agent isolation stub (Wazuh REST API),
and alert dispatch. iptables calls require the service to run as root or
with appropriate sudo rules on Linux.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _validate_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not addr.is_loopback and not addr.is_multicast
    except ValueError:
        return False


class IncidentResponder:
    def __init__(self, incident_log_path: Path | None = None) -> None:
        self.incidents: list[dict[str, Any]] = []
        self.blocked_ips: set[str] = set()
        self._log_path = incident_log_path or Path("incident_log.json")

    def block_ip(self, ip: str, reason: str, duration: int = 3600) -> None:
        """Block an IP via iptables INPUT and FORWARD chains."""
        if not _validate_ip(ip):
            logger.error("Invalid IP, blocking aborted: %r", ip)
            return
        if ip in self.blocked_ips:
            return
        try:
            for chain in ("INPUT", "FORWARD"):
                subprocess.run(["sudo", "iptables", "-I", chain, "-s", ip, "-j", "DROP"], check=True, capture_output=True, timeout=10)  # noqa: S603,S607
            self.blocked_ips.add(ip)
            logger.warning("BLOCKED: %s — %s (duration: %ds)", ip, reason, duration)
            self._log_incident("block_ip", {"ip": ip, "reason": reason, "duration": duration})
        except subprocess.TimeoutExpired:
            logger.error("Timeout blocking %s", ip)
        except subprocess.CalledProcessError as exc:
            logger.error("Could not block %s: %s", ip, exc)

    def isolate_agent(self, agent_id: str, reason: str) -> None:
        """Isolate a Wazuh agent (stub — extend with Wazuh REST API call)."""
        logger.warning("ISOLATE: %s — %s", agent_id, reason)
        self._log_incident("isolate_agent", {"agent_id": agent_id, "reason": reason})

    def send_alert(self, severity: str, message: str) -> None:
        """Dispatch an alert (log + extend with e-mail/webhook as needed)."""
        logger.warning("ALERT [%s]: %s", severity.upper(), message)
        self._log_incident("send_alert", {"severity": severity, "message": message})

    def _log_incident(self, action: str, details: dict[str, Any]) -> None:
        self.incidents.append({
            "action": action,
            "details": details,
            "timestamp": datetime.now().isoformat(),
        })
        try:
            self._log_path.write_text(
                json.dumps(self.incidents, indent=2, default=str, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.error("Could not write incident log: %s", exc)

    def process_alert(self, alert: dict[str, Any]) -> None:
        """Route an alert dict through the playbook based on severity."""
        severity = alert.get("severity", "medium")
        details = alert.get("details", {})
        timestamp = alert.get("timestamp", "unknown")
        src_ip: str = details.get("src_ip", "")

        if severity == "critical":
            if src_ip:
                self.block_ip(src_ip, "Critical anomaly detected")
            self.isolate_agent(f"agent@{timestamp}", "Critical anomaly detected")
            self.send_alert("critical", f"Critical incident at {timestamp}: {details}")
        elif severity == "high":
            if src_ip:
                self.block_ip(src_ip, "High anomaly detected", duration=1800)
            self.send_alert("high", f"High incident at {timestamp}: {details}")
        elif severity == "medium":
            self.send_alert("medium", f"Medium incident at {timestamp}: {details}")
