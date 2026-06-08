# Arkitektur — sentinel-ml

## Översikt

```
                                    ┌─────────────────────┐
                                    │  sentinel-upload-   │
                                    │       api (prod)    │
                                    │  Hetzner k3s        │
                                    └──────────┬──────────┘
                                               │ MongoDB read
                                               │ /predict calls (valfritt)
                                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                         sentinel-ml                              │
│                                                                  │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐   │
│  │   data   │ →  │ features │ →  │  models  │ →  │   eval   │   │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘   │
│       │               │               │               │          │
│       │               ▼               ▼               ▼          │
│       │          ┌──────────┐    ┌──────────┐                    │
│       │          │   llm    │    │adversarial│                   │
│       │          │ (Ollama) │    │  (ART)    │                   │
│       │          └──────────┘    └──────────┘                    │
│       │                                                          │
│       └──────────────────────► service (FastAPI /predict) ──────►│
└─────────────────────────────────────────────────────────────────┘
```

## Komponenter

| Modul | Ansvar | Beroenden |
|-------|--------|-----------|
| `data/` | Ladda data från MongoDB och lokala JSONL-filer. Konvertera till `ThreatReport` / `UploadRecord`. | `pymongo`, `pydantic` |
| `features/` | Extrahera features. Rena funktioner — inga sidoeffekter. | `numpy`, `re` (+`spacy` i Fas 2) |
| `models/` | Estimatorer enligt sklearn-API. Train/save/load. | `scikit-learn`, `joblib` |
| `llm/` | Ollama-wrapper. Isolerad så vi kan byta backend. | `httpx` |
| `adversarial/` | Poisoning, evasion, prompt injection. | `numpy` (+ `art` när Fas 2 kör) |
| `eval/` | Metrics. Ett ställe för alla siffror vi rapporterar. | `scikit-learn` |
| `service/` | FastAPI `/predict`-endpoints. Stateless. | `fastapi`, `uvicorn` |
| `cli.py` | Train/eval/predict från kommandoraden. | `typer` |

## Designprinciper

1. **All I/O bakom `data/`.** Models och features rör aldrig disk eller MongoDB direkt. Gör enhetstester triviala.
2. **scikit-learn-API överallt.** `fit`, `predict`, `predict_proba`. Då fungerar `cross_val_score`, pipelines och ART utan glue-kod.
3. **LLM bakom interface.** `llm/ollama_client.py` är enda anropspunkten. Byte till OpenAI = byt fil, inte modeller.
4. **Konfig via env, inte argument.** `config.py` läser `.env`. Tests åsidosätter via miljövariabler.
5. **Inga dolda globala tillstånd.** Modeller laddas explicit i `service/api.py` startup; ingen modul-nivå-cache.

## Dataflöde (träning)

1. `data/loaders.py` → läser från MongoDB eller JSONL → returnerar pydantic-modeller.
2. `features/*.py` → transformerar till numpy/sparse-matriser.
3. `models/*.py` → `train()` returnerar tränat objekt.
4. `eval/metrics.py` → räknar precision/recall/F1.
5. `models/*.py` → `save()` skriver `.joblib` till `models_store/`.
6. (Valfritt) MLflow loggar params, metrics och artifact.

## Dataflöde (inferens)

1. `service/api.py` tar emot HTTP-anrop.
2. Laddar `.joblib` från `models_store/` (en gång vid startup).
3. Kör `predict_proba` → returnerar `Prediction`-objekt med confidence.

## Säkerhet

- **Read-only mot Sentinel-MongoDB** i `data/loaders.py`. Skriver bara till separat `ml_predictions`-collection (om alls).
- **Inga hemligheter i koden.** Mongo-URI, Ollama-host etc. kommer från `.env`/K8s Secret.
- **Hash-baserade IOC-uppslagningar logges, inte själva data.** Vi loggar att vi sett en SHA-256, inte filinnehållet.
- **LLM-output valideras** mot förväntad JSON-shape innan den passas vidare. Skyddar mot prompt injection.
- Se [adversarial-analysis-plan.md](adversarial-analysis-plan.md) för fullständig hotbild mot ML-systemet.

## Deploy (Hetzner k3s)

sentinel-ml deployas som en intern microservice i `sentinel`-namespace
bredvid sentinel-upload-api. Ingen publik URL — all trafik filtreras
via NetworkPolicy så att bara upload-api:s pods kan ringa servicen.

```
                  internet
                     │
                     │ TLS 443 (Let's Encrypt)
                     ▼
              ingress-nginx
                     │
                     ▼
      ┌──────────────────────────────┐
      │ sentinel namespace (k3s)     │
      │                              │
      │  ┌────────────────────────┐  │
      │  │ sentinel-upload-api    │  │  ← public-facing
      │  │  :8000                 │  │
      │  └───────────┬────────────┘  │
      │              │ HTTP :8100    │
      │              ▼               │
      │  ┌────────────────────────┐  │
      │  │ sentinel-ml            │  │  ← internal-only
      │  │  :80 → :8100           │  │
      │  │  ClusterIP             │  │
      │  └───────────┬────────────┘  │
      │              │               │
      └──────────────┼───────────────┘
                     │ :27017 (egress, TLS)
                     ▼
              MongoDB Atlas
```

**Resurser i [k8s/base/](../k8s/base/):**

| Manifest | Roll |
|----------|------|
| `deployment.yaml` | 1 replica, non-root UID 10001, read-only rootfs, resource limits |
| `service.yaml` | ClusterIP, port 80 → containerns 8100 |
| `configmap.yaml` | `MONGODB_DB`, `MODELS_DIR`, `SENTINEL_ML_SEED` |
| `secret.yaml` | `MONGODB_URI` (gitignored, kopieras från `secret.example.yaml`) |
| `networkpolicy.yaml` | Ingress endast från upload-api; egress DNS + Mongo + HTTPS |
| `kustomization.yaml` | Bundlar resurserna för `kubectl apply -k` |

**CI/CD-flöde:**

```
push till main
   ↓
lint-and-test (ruff, pytest på 3.11 + 3.12) + security (pip-audit)
   ↓
dockerhub-push (jonitsx/sentinel-ml:main, :latest, :<sha>)
   ↓
deploy-hetzner (kubectl rollout restart deployment/sentinel-ml -n sentinel)
```

Detaljer: [runbooks/sentinel-ml-deploy.md](../runbooks/sentinel-ml-deploy.md).
Hot-modell + RBAC: [docs/security-analysis-deployment.md](security-analysis-deployment.md).
