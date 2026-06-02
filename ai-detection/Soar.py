import json
from pathlib import Path

CUSTOM_LOG = Path(__file__).parent / "ai-anomaly-detector.log"

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
