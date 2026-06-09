"""
Modulens ansvar:
Denna modul tar resultat från AI-baserad anomalidetektering och översätter dem
till operativa larm med tydlig allvarlighetsgrad. Larmen struktureras i JSON-format
och sparas så att de kan konsumeras av andra säkerhetskomponenter, till exempel
SOAR-flöden, SIEM-verktyg eller scripts för incidenthantering.

Översikt av arbetsflödet:
1. Läs in anomaliresultat från CSV.
2. Klassificera varje avvikelse till en allvarlighetsnivå.
3. Bygg ett konsekvent larmobjekt med metadata.
4. Spara alla larm till en JSON-fil för vidare behandling.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('alerts.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Ordning är viktig: högsta allvarlighetsgrad testas först
ALERT_THRESHOLDS = {
    'critical': {'zscore': 3.0, 'isolation_score': -0.3},
    'high':     {'zscore': 2.5, 'isolation_score': -0.2},
    'medium':   {'zscore': 2.0, 'isolation_score': -0.1},
}


def classify_alert(zscore: float, isolation_score: float) -> str | None:
    """Bestäm larmnivå utifrån statistisk och modellbaserad avvikelse.

    Funktionen jämför två signaler från detektionssteget:
    - `zscore`: hur långt observationen ligger från normalnivån.
    - `isolation_score`: modellens anomaliscore från Isolation Forest.

    Trösklarna utvärderas från högsta till lägsta allvarlighetsgrad så att den
    mest kritiska nivån vinner om flera villkor uppfylls samtidigt.

    Args:
        zscore: Z-score för aktuell tidsperiod.
        isolation_score: Decision score från Isolation Forest.

    Returns:
        Larmnivå (`critical`, `high`, `medium`) eller `None` om inget larm ska skapas.
    """
    sorted_levels = sorted(
        ALERT_THRESHOLDS.items(),
        key=lambda x: x[1]['zscore'],
        reverse=True,
    )
    for level, thresholds in sorted_levels:
        if abs(zscore) >= thresholds['zscore'] or isolation_score <= thresholds['isolation_score']:
            return level
    return None


def create_alert(timestamp: Any, severity: str, details: dict[str, Any]) -> dict[str, Any]:
    """Skapa ett standardiserat larmobjekt för incidentkedjan.

    Funktionen paketerar tidsstämpel, allvarlighetsgrad och detaljdata i ett
    konsekvent schema. Detta gör att nedströmskomponenter kan läsa och agera på
    larm utan att behöva känna till intern representation från detektorn.

    Args:
        timestamp: Tid för händelsen eller tidsfönstret där avvikelsen uppstod.
        severity: Klassificerad larmnivå.
        details: Nyckelvärden som beskriver avvikelsen, exempelvis event_count.

    Returns:
        Ett dictionary med larmdata och skapandetid (`detected_at`).
    """
    return {
        'timestamp': str(timestamp),
        'severity': severity,
        'detected_at': datetime.now().isoformat(),
        'details': details,
    }


def write_alerts_to_file(alerts: list[dict[str, Any]], filepath: str = 'active_alerts.json') -> None:
    """Persista larm till JSON så att andra system kan konsumera dem.

    Funktionen serialiserar hela larmmängden till fil med indentering för god
    läsbarhet. Filformatet används som överlämning mellan detektering och
    incidentrespons.

    Args:
        alerts: Lista med strukturerade larmobjekt.
        filepath: Målfil för JSON-utdata.
    """
    with open(filepath, 'w') as f:
        json.dump(alerts, f, indent=2, default=str)
    logger.info(f"Skrev {len(alerts)} larm till {filepath}")


def process_anomaly_results(csv_path: str = str(Path(__file__).parent / 'anomaly_detection_results.csv')) -> list[dict[str, Any]]:
    """Orkestrera konvertering från modellresultat till operativa larm.

    Funktionen läser CSV-utdata från anomalidetektorn, itererar över varje
    tidsfönster och skapar larm för de rader som passerar definierade trösklar.
    Resultatet skrivs till disk och returneras för direkt användning.

    Args:
        csv_path: Sökväg till CSV-filen med extraherade features och anomaliscore.

    Returns:
        Lista med genererade larm.
    """
    df = pd.read_csv(csv_path, index_col=0, parse_dates=True)

    alerts: list[dict[str, Any]] = []
    for idx, row in df.iterrows():
        severity = classify_alert(row['event_count_zscore'], row['anomaly_score'])
        if severity:
            alert = create_alert(idx, severity, {
                'event_count': int(row['event_count']),
                'avg_severity': round(row['avg_severity'], 2),
                'unique_ips': int(row['unique_ips']),
                'anomaly_score': round(row['anomaly_score'], 4),
                'zscore': round(row['event_count_zscore'], 2),
            })
            alerts.append(alert)
            logger.warning(f"[{severity.upper()}] Anomali vid {idx}: "
                           f"{int(row['event_count'])} händelser, z={row['event_count_zscore']:.2f}")

    write_alerts_to_file(alerts)
    return alerts


if __name__ == '__main__':
    alerts = process_anomaly_results()
    print(f"\nTotalt {len(alerts)} larm genererade")
    for a in alerts:
        print(f"  [{str(a['severity']).upper()}] {a['timestamp']} — "
              f"{a['details']['event_count']} händelser")
