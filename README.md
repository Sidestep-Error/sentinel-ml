# sentinel-ml

ML-baserat säkerhetsmodul som bygger vidare på
[sentinel-upload-api](https://github.com/Sidestep-Error/sentinel-upload-api).
Grupprojekt för kursen *Nätverks-, OT- & AI-säkerhet*
(ChasAcademy 2026), team **Sidestep Error**. Deadline: **2026-06-19**.

## Vad det är

Två sammankopplade ML-spår och ett genomgående adversarial-test-lager:

| Spår | Mål | Modell-kandidater |
|------|-----|-------------------|
| **A — Threat report NLP** | Klassificera threat reports per ATT&CK-tactic + extrahera IOCs (IP, hash, domän, CVE) | TF-IDF + LR (baseline), spaCy NER, LLM via Ollama |
| **B — Upload risk ML** | Komplement till ClamAV: klassificera filuppladdningar baserat på metadata + entropi | Random Forest, Gradient Boosting |
| **C — Adversarial harness** | Visa att vårt eget ML-system *själv* är angripbart | ART (evasion), data poisoning, prompt injection |

Allt integrerar mot Sentinels MongoDB (samma data som drift-appen samlar) och
exponerar en valfri FastAPI-service (`/predict`) som Sentinel kan ringa.

## Snabbstart

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
ruff check src tests
pytest -q
```

## Köra modulen

```powershell
# Träna baseline threat-report-klassificeraren på syntetisk data
python -m sentinel_ml.cli train threat-classifier --dataset data/threat_reports_sample.jsonl

# Extrahera IOCs från en textfil
python -m sentinel_ml.cli extract-iocs path/to/report.txt

# Starta FastAPI-service (för demo eller integration med sentinel-upload-api)
uvicorn sentinel_ml.service.api:app --reload --port 8100
```

## Struktur

Se [docs/architecture.md](docs/architecture.md) för fullständig översikt
och [docs/integration-with-sentinel-upload-api.md](docs/integration-with-sentinel-upload-api.md)
för hur modulen kopplas till det befintliga API:t.

## Säkerhet

ML-system är själva attackytor. Se
[docs/adversarial-analysis-plan.md](docs/adversarial-analysis-plan.md) för
vår plan för poisoning-, evasion- och prompt-injection-tester. Krävs för VG.

## Licens

Internt kursprojekt — ej för publik användning.
