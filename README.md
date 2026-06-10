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

# Smoke-testa servicen (i en separat terminal) — pingar /health,
# /predict/threat och /predict/upload med exempel-input
python scripts/demo_smoke.py
```

## Köra med Docker

För live-demo eller en självförsörjande dev-stack utan att behöva
installera Python-deps lokalt:

```powershell
docker compose build
docker compose up
```

Servicen lyssnar på `http://localhost:8100`. `/health`, `/predict/threat`
och `/predict/upload` är tillgängliga. Verifiera med smoke-scriptet i
en separat terminal:

```powershell
python scripts/demo_smoke.py
```

Lokal Mongo via compose-profile (för dev utan att starta upstream
sentinel-upload-api):

```powershell
docker compose --profile with-mongo up
```

Mongo körs då på `localhost:27017` med databasen `sentinel_upload`,
vilket matchar `MONGODB_URI`-defaulten i `.env.example`.

### Modellfiler

`models_store/` mountas read-only från host. Träna en modell på host
(`python -m sentinel_ml.cli train ...`) och restarta containern — den
plockar upp den nya artefakten vid lifespan-start. Tom `models_store/`
triggar fallback-svar i endpoints (`label="unknown"`, `model_version="none"`).

## Deploy

sentinel-ml körs som en **intern microservice** i samma `sentinel`-namespace
som [sentinel-upload-api](https://github.com/Sidestep-Error/sentinel-upload-api)
på Hetzner k3s. Ingen publik URL — bara upload-api:s pods får ringa
servicen via `sentinel-ml.sentinel.svc.cluster.local`.

CI/CD vid push till `main`: tester → Docker Hub-push → `kubectl rollout restart`.
**CI applicerar inte manifest-ändringar** — ändringar under `k8s/base/` (PVC,
volymer, ConfigMap, NetworkPolicy) måste appliceras manuellt på klustret med
`kubectl apply`. Modellerna (`.joblib`) ligger på en PVC, inte i imagen, och
populeras en gång via [runbooks/sentinel-ml-load-models.md](runbooks/sentinel-ml-load-models.md).

Manifest i [k8s/base/](k8s/base/). Setup-procedurer i
[runbooks/sentinel-ml-deploy.md](runbooks/sentinel-ml-deploy.md).
Hot-modell och RBAC-resonemang i [docs/security-analysis-deployment.md](docs/security-analysis-deployment.md).

## Struktur

Se [docs/architecture.md](docs/architecture.md) för fullständig översikt
och [docs/sentinel-ml-upload-api-integration-architecture.md](docs/sentinel-ml-upload-api-integration-architecture.md)
för hur modulen kopplas till det befintliga API:t.

## Säkerhet

ML-system är själva attackytor. Se
[docs/adversarial-analysis-plan.md](docs/adversarial-analysis-plan.md) för
vår plan för poisoning-, evasion- och prompt-injection-tester. Krävs för VG.

## Licens

Internt kursprojekt — ej för publik användning.
