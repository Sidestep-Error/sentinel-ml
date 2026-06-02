"""
chas academy kurs 5 - Nätverks-, OT & AI-säkerhet
Grupp: Sidestep Error

Modulens ansvar:
Denna modul implementerar en automatiserad respons-playbook för säkerhetsincidenter.
Den tar emot larm från detektionsledet och utför fördefinierade åtgärder beroende
på allvarlighetsgrad, exempelvis IP-blockering, agentisolering, larmdistribution
och incidentloggning.

Praktiskt syfte:
Målet är att minska tiden mellan upptäckt och åtgärd, samt skapa en spårbar
incidenthistorik som stöd för efteranalys och rapportering.
"""

import ipaddress
import json
import logging
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).parent

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(BASE_DIR / 'incident_response.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def _validate_ip(ip: str) -> bool:
    """Validera att en IP-adress är användbar för blockering.

    Funktionen säkerställer att indata är en syntaktiskt giltig IP-adress och
    exkluderar adressklasser som normalt inte ska blockeras i denna kontext,
    till exempel loopback och multicast.

    Args:
        ip: IP-adress i textformat.

    Returns:
        `True` om adressen är giltig och lämplig för nätverksåtgärd, annars `False`.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return not addr.is_loopback and not addr.is_multicast
    except ValueError:
        return False


class IncidentResponder:
    """Inkapslar incidentresponslogik för larmdriven åtgärdshantering.

    Klassen håller intern status över utförda incidentåtgärder och redan blockerade
    IP-adresser. Den exponerar metoder för tekniska motåtgärder samt för loggning
    och notifiering.
    """

    def __init__(self) -> None:
        """Initiera responderns runtime-tillstånd.

        Skapar tom lista för incidenthändelser och en mängd för blockerade IP-adresser
        så att upprepade blockeringar kan undvikas.
        """
        self.incidents: list[dict[str, Any]] = []
        self.blocked_ips: set[str] = set()

    def block_ip(self, ip: str, reason: str, duration: int = 3600) -> None:
        """Blockera käll-IP på hostnivå med iptables-regler.

        Funktionen validerar först adressen, kontrollerar om den redan blockerats
        och försöker därefter införa DROP-regler i relevanta kedjor. Utfallet loggas
        och registreras som incidenthändelse.

        Args:
            ip: Källadress som ska blockeras.
            reason: Motivering som loggas tillsammans med åtgärden.
            duration: Avsedd varaktighet i sekunder (informativ metadata).
        """
        if not _validate_ip(ip):
            logger.error(f"Ogiltig IP-adress, blockering avbruten: {ip!r}")
            return

        if ip in self.blocked_ips:
            logger.info(f"IP {ip} redan blockerad")
            return

        try:
            subprocess.run(
                ['sudo', 'iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'],
                check=True, capture_output=True, timeout=10
            )
            subprocess.run(
                ['sudo', 'iptables', '-I', 'FORWARD', '-s', ip, '-j', 'DROP'],
                check=True, capture_output=True, timeout=10
            )
            self.blocked_ips.add(ip)
            logger.warning(f"BLOCKERAD: {ip} — {reason} (varaktighet: {duration}s)")
            self.log_incident('block_ip', {'ip': ip, 'reason': reason, 'duration': duration})
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout vid blockering av {ip}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Kunde inte blockera {ip}: {e}")

    def isolate_agent(self, agent_id: str, reason: str) -> None:
        """Markera isoleringsåtgärd för en agent.

        Metoden är en kontrollerad stub som idag loggar och journalför isoleringsbeslut.
        Den är avsedd att utökas med faktiska API-anrop mot Wazuh eller motsvarande
        endpoint för host-isolering.

        Args:
            agent_id: Identifierare för agent/system som ska isoleras.
            reason: Varför isolering initieras.
        """
        logger.warning(f"ISOLERING: Agent {agent_id} — {reason}")
        self.log_incident('isolate_agent', {'agent_id': agent_id, 'reason': reason})

    def send_alert(self, severity: str, message: str) -> None:
        """Publicera incidentlarm till lokal kanal och persistent loggfil.

        Funktionen skapar ett larmobjekt, skriver det till applikationslogg och
        appenderar samma information till en JSON-fil för spårbar notifieringshistorik.

        Args:
            severity: Allvarlighetsgrad för larmet.
            message: Läsbar larmtext till operatör eller integrationspunkt.
        """
        alert = {
            'severity': severity,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        logger.warning(f"LARM [{severity.upper()}]: {message}")

        alerts_file = BASE_DIR / 'response_alerts.json'
        try:
            existing: list = json.loads(alerts_file.read_text()) if alerts_file.exists() else []
        except (json.JSONDecodeError, OSError):
            logger.warning("response_alerts.json var korrupt — återställer tom lista")
            existing = []

        existing.append(alert)
        alerts_file.write_text(json.dumps(existing, indent=2, ensure_ascii=False))

    def log_incident(self, action: str, details: dict[str, Any]) -> None:
        """Journalför en utförd åtgärd i incidentloggen.

        Varje åtgärd serialiseras med tidsstämpel och detaljer, lagras i minnet
        under körning och skrivs sedan till JSON för beständig dokumentation.

        Args:
            action: Namn på åtgärden, exempelvis `block_ip`.
            details: Kontextdata för åtgärden.
        """
        incident = {
            'action': action,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.incidents.append(incident)

        with open(BASE_DIR / 'incident_log.json', 'w', encoding='utf-8') as f:
            json.dump(self.incidents, f, indent=2, default=str, ensure_ascii=False)

    def process_alert(self, alert: dict) -> None:
        """Tolka ett inkommande larm och verkställ playbook-regler.

        Metoden mappar larmets allvarlighetsgrad till en sekvens av responsåtgärder:
        - `critical`: blockering (om IP finns), isolering och omedelbart larm.
        - `high`: blockering (om IP finns) och larm.
        - `medium`: larm och loggning utan aktiv blockering.

        Args:
            alert: Larmobjekt med minst `severity`, `timestamp` och `details`.
        """
        severity = alert.get('severity', 'medium')
        details = alert.get('details', {})
        timestamp = alert.get('timestamp', 'okänd tid')

        # AI-larm är tidsfönsteraggregat och saknar enskild src_ip.
        # src_ip finns bara i regelbaserade direktlarm.
        src_ip: str = details.get('src_ip', '')

        logger.info(f"Behandlar larm: {severity} — {json.dumps(details, ensure_ascii=False)}")

        if severity == 'critical':
            # Blockera om specifik IP finns, isolera alltid, larma
            if src_ip:
                self.block_ip(src_ip, 'Kritisk anomali detekterad')
            else:
                logger.warning(
                    f"Kritisk anomali vid {timestamp}: ingen src_ip — "
                    f"{details.get('event_count', '?')} händelser, "
                    f"z={details.get('zscore', '?')}"
                )
            self.isolate_agent(f"agent@{timestamp}", 'Kritisk anomali detekterad')
            self.send_alert('critical', f'Kritisk incident vid {timestamp}: {details}')

        elif severity == 'high':
            # Blockera om IP finns, larma alltid
            if src_ip:
                self.block_ip(src_ip, 'Hög anomali detekterad', duration=1800)
            else:
                logger.warning(
                    f"Hög anomali vid {timestamp}: ingen src_ip — "
                    f"{details.get('event_count', '?')} händelser"
                )
            self.send_alert('high', f'Hög incident vid {timestamp}: {details}')

        elif severity == 'medium':
            # Enbart larm och loggning
            self.send_alert('medium', f'Medium incident vid {timestamp}: {details}')


if __name__ == '__main__':
    responder = IncidentResponder()

    alerts_path = BASE_DIR.parent / 'active_alerts.json'
    try:
        with open(alerts_path, encoding='utf-8') as f:
            alerts = json.load(f)
    except FileNotFoundError:
        print("Kör anomaly_detector.py och alert_manager.py först")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"active_alerts.json är korrupt: {e}")
        sys.exit(1)

    print(f"Behandlar {len(alerts)} larm...")
    for alert in alerts:
        responder.process_alert(alert)

    print(f"\nFärdigt. {len(responder.incidents)} åtgärder vidtagna.")
    if responder.blocked_ips:
        print(f"Blockerade IP:n: {responder.blocked_ips}")
    print("Se incident_log.json och incident_response.log för detaljer.")
