#!/bin/bash
# chas academy kurs 5 - Nätverks-, OT & AI-säkerhet
# Grupp: Sidestep Error
#
# Modulens ansvar:
# Detta shellscript orkestrerar hela AI-detektionskedjan från export av råa Wazuh-larm
# till analys, larmgenerering och automatiserad incidentrespons.
#
# Designidé:
# Skriptet kör stegvis och avbryter direkt vid fel för att undvika halvfärdiga körningar.
# Det loggar samtliga steg till pipeline.log för spårbarhet och felsökning.
# Kör hela AI-detektionspipeline: export → anomalidetektering → larm → respons

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$SCRIPT_DIR/../.venv/bin/python3"
LOG="$SCRIPT_DIR/pipeline.log"
ALERTS_FILE="$SCRIPT_DIR/pipeline_alerts.json"

# Funktion: log
# Skriver tidsstämplade statusrader till både terminal och loggfil.
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG"; }

log "=== Pipeline startar ==="

# Steg 1: Exportera larm från senaste 2 timmar (överlapp för att inte missa gränsen)
log "Exporterar larmdata (senaste 2h)..."
curl -sk -u admin:SecretPassword \
  "https://localhost:9200/wazuh-alerts-*/_search?size=10000" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"range":{"timestamp":{"gte":"now-2h"}}}}' \
  -o "$ALERTS_FILE"

HITS=$(python3 -c "import json,sys; d=json.load(open('$ALERTS_FILE')); print(d.get('hits',{}).get('total',{}).get('value',0))" 2>/dev/null || echo 0)
log "Larm exporterade: $HITS"

if [ "$HITS" -lt 5 ]; then
  log "För få larm ($HITS) — hoppar över AI-analys denna körning"
  log "=== Pipeline avslutad (otillräcklig data) ==="
  exit 0
fi

# Steg 2: AI-anomalidetektering
log "Kör anomalidetektering..."
"$PYTHON" "$SCRIPT_DIR/anomaly_detector.py" "$ALERTS_FILE" >> "$LOG" 2>&1
if [ $? -ne 0 ]; then
  log "FEL: anomaly_detector.py misslyckades"
  exit 1
fi

# Steg 3: Generera larm
log "Genererar larm..."
"$PYTHON" "$SCRIPT_DIR/alert_manager.py" >> "$LOG" 2>&1
if [ $? -ne 0 ]; then
  log "FEL: alert_manager.py misslyckades"
  exit 1
fi

# Steg 4: Incidentrespons
log "Kör incidentrespons..."
"$PYTHON" "$SCRIPT_DIR/response_playbook.py" >> "$LOG" 2>&1
if [ $? -ne 0 ]; then
  log "FEL: response_playbook.py misslyckades"
  exit 1
fi

log "=== Pipeline klar ==="
