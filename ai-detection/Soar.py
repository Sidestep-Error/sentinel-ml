"""
chas academy kurs 5 - Nätverks-, OT & AI-säkerhet
Grupp: Sidestep Error

Modulens ansvar:
Denna modul fungerar som ett enkelt SOAR-liknande exportsteg som översätter
aktiva AI-larm till en radbaserad logg med ett konsekvent JSON-format.

Syfte i kedjan:
Genom att skriva en separat loggström kan larmen skickas vidare till andra
automations- eller övervakningskomponenter utan att påverka originalkällan.
"""

import json
from pathlib import Path

CUSTOM_LOG = Path(__file__).parent / "ai-anomaly-detector.log"


def main() -> None:
    """Läs aktiva larm och skriv dem som JSON-rader till SOAR-logg.

    Funktionen hämtar larm från `active_alerts.json`, transformerar varje larm
    till ett förenklat och normaliserat loggobjekt och appenderar resultatet till
    en loggfil där varje rad är ett eget JSON-dokument.
    """

    with open(Path(__file__).parent.parent / "active_alerts.json") as f:
        alerts = json.load(f)

    with open(CUSTOM_LOG, "a") as f:
        for a in alerts:
            entry: dict[str, object] = {
                "ai_detector": True,
                "severity": a["severity"],
                "event_count": a["details"]["event_count"],
                "message": f'AI anomalidetektering: {a["severity"]} — {a["details"]["event_count"]} händelser',
            }
            f.write(json.dumps(entry) + "\n")

    print(f"Skrev {len(alerts)} larm till loggfil")


if __name__ == "__main__":
    main()
