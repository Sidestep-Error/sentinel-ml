# sentinel-ml

[![CI](https://github.com/Sidestep-Error/sentinel-ml/actions/workflows/ci.yml/badge.svg)](https://github.com/Sidestep-Error/sentinel-ml/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.5%2B-F7931E?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![License: Proprietary](https://img.shields.io/badge/license-proprietary-lightgrey)](#licens)
[![ChasAcademy 2026](https://img.shields.io/badge/ChasAcademy-2026-blue)](https://chasacademy.se/)
[![Status: scaffold](https://img.shields.io/badge/status-scaffold-orange)]()

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
Copy-Item .env.example .env   # initialisera lokal konfig (gitignored)
ruff check src tests
pytest -q
```

`.env.example` listar alla miljövariabler [config.py](src/sentinel_ml/config.py)
känner till. Justera värdena i `.env` för din lokala miljö — t.ex. Mongo-URI om
du kör mot Atlas istället för lokal Docker.

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
