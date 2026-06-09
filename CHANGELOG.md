# Changelog

Alla märkbara ändringar i detta projekt dokumenteras här.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versionshantering: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased] — branch `stoffes_feature`

### Tillagt
- **Liveflow-integration (2026-06-08):**
  - `POST /predict/upload-ingest` — ingest av Upload+ClamAV-payload till upload-klassificeraren
  - `POST /predict/cve-relevance` — SBOM/CVE-relevans med komponentmatchning (namn/ekosystem/version)
  - `POST /predict/upload-text-ingest` — säkert text-ingestflöde för `.txt`, `.md`, `.json`, `.csv`, `.eml` med IOC-extraktion
  - `POST /predict/liveflow` — aggregator som sammanfogar upload, upload-text och cve-relevans i ett enhetligt demosvar
- **`docs/llm-cve-integration-guide.md`** — konkret integrationsguide för LLM/CVE-flöden, payloads, persistens och endpoint-exempel
- **`tests/test_service_api.py`** — nya API-tester för `upload-ingest`, `cve-relevance`, `upload-text-ingest` och `liveflow` (fallback + loaded-model paths)
- **`scripts/generate_synthetic_threat_reports.py`** — genererar 250 syntetiska threat reports (50/kategori) i JSONL-format för baseline-träning (#28)
- **`scripts/download_real_threat_reports.py`** — laddar ner och konverterar `mrmoor/cyber-threat-intelligence` (CC-BY-4.0, ~10k rader) till ThreatReport JSONL; keyword-baserad dokumentklassificering ger 1 582 lablade rapporter (#29)
- **`scripts/eval_threat_classifier.py`** — kör train/test-split och rapporterar accuracy/precision/recall/F1 per klass (#31)
- **`scripts/compare_ioc_extractors.py`** — jämförelseverktyg för regex- vs spaCy-extraktion (#33)
- **`src/sentinel_ml/features/ioc_extract_spacy.py`** — spaCy-baserad IOC-extraktion (Fas 2): EntityRuler för strukturerade IOCs + pre-trained NER för malware-namn och threat actors som regex inte kan hitta (#33)
- **`src/sentinel_ml/data/schemas.py`** — `UploadRecord` gjord flexibel med optionella fält för att matcha verklig Atlas-data; stöder `status`-alias för `decision`
- **`src/sentinel_ml/config.py`** — ny inställning `MONGODB_DB_UPLOAD` (default `sentinel_upload`) för att hantera att uploads och threat events ligger i separata databaser
- **`src/sentinel_ml/data/loaders.py`** — `_get_collection` väljer nu rätt databas per collection (`uploads` → `sentinel_upload`, övriga → `sentinel`)


- **`src/sentinel_ml/log_anomaly/`** — nytt paket för logganomalier enligt [r87-e/ais-grupp-logganomali](https://github.com/r87-e/ais-grupp-logganomali)-konventioner:
  - `tfidf_detector.py` — TF-IDF + IsolationForest på råa loggtexter; ger jämförbar ML-metod mot strukturerad detektor (VG-krav: algoritmjämförelse)
  - `detector.py` — IsolationForest på strukturerade Wazuh-tidsfeatures (portad från `ai-detection/`, anpassad till projektstil)
  - `generate_data.py` — syntetisk CSV-loggdata med `line`/`label`-kolumner (normal/attack); genereras automatiskt om `data/logs.csv` saknas
  - `train.py` — träningsentry för TF-IDF-detektorn; rapporterar precision/recall/F1
  - `alert_manager.py` — larmklassificering (critical/high/medium) baserad på z-score och IsolationForest-score
  - `response_playbook.py` — SOAR-playbook: IP-blockering via iptables, agent-isolering (Wazuh-stub), larmutskick
  - `summarize.py` — LLM-incidentsammanfattning via befintlig `OllamaClient`; faller tillbaka på regelbaserad text om Ollama ej är igång
  - `attack.py` — mimicry-attackdemonstration: kamuflerar attackloggar med godartade prefix/suffix för att undvika TF-IDF-detektion (VG-krav: robusthetstestning)
- **`POST /predict/log-anomaly`** — ny FastAPI-endpoint som tar en lista råa loggtexter och returnerar per-rad anomaliflagg och score; faller tillbaka på `model_version="none"` om ingen modell laddats
- **CLI-kommandon:**
  - `sentinel-ml train log-anomaly` — tränar TF-IDF-modellen
  - `sentinel-ml detect-anomalies <csv>` — kör detektion och skriver anomalier som JSON
  - `sentinel-ml attack-demo` — kör mimicry-attackdemon
- **`tests/test_log_anomaly.py`** — 18 tester för `generate_data`, `tfidf_detector`, `alert_manager`, `attack` och API-endpointen

### Ändrat
- `src/sentinel_ml/service/api.py` — laddar nu även `log_anomaly_tfidf.joblib` vid uppstart via lifespan
- `src/sentinel_ml/cli.py` — tre nya kommandon tillagda
- `pyproject.toml` — lade till `S311`-undantag i per-file-ignores för `generate_data.py` och `attack.py` (pseudo-slump för syntetisk data, ej kryptografisk)
- `src/sentinel_ml/data/schemas.py` — `MalwareSample` återinförd för att återställa reproducerbar malware-evaluering
- `docs/sentinel-ml-upload-api-integration-architecture.md` — uppdaterad endpoint-tabell och kontrakt för upload/ClamAV, text-ingest, CVE-relevans och liveflow
- `ROADMAP.md` — uppdaterad med avbockade levererade integrationssteg samt ärlig status för G/VG-projektkraven

---

## [0.1.0] — 2026-06-02

### Tillagt
- **`src/sentinel_ml/service/api.py`** — FastAPI-service med tre endpoints: `GET /health`, `POST /predict/threat`, `POST /predict/upload`
- Modeller laddas nu en gång vid uppstart via FastAPI `lifespan`-kontexthanterare istället för per-anrop
- `Prediction`-schemat konsoliderat som delat kontrakt för båda predict-endpoints

### Ändrat
- `src/sentinel_ml/data/schemas.py` — `Prediction` är nu det enda svarsformatskontraktet (bort med dubbla varianter)

---

## [0.0.2] — 2026-05-26

### Tillagt
- `ai-detection/` — Kristoffers AI-detektionskod uppladdad som startpunkt (ännu ej anpassad till projektstil):
  - `anomaly_detector.py` — Wazuh-logganalys med IsolationForest och z-score-baslinje
  - `alert_manager.py` — larmklassificering och JSON-utskrift
  - `response_playbook.py` — incidentrespons-playbook med iptables-integrering
  - `Soar.py` — SOAR-loggintegration
  - `run_ai_pipeline.sh` — skalskript för hela pipeline-körning

### Fixat
- CI: ruff-fel åtgärdade (StrEnum-import, B008, S311, S112)
- CI: pip-audit justerat till att bara misslyckas vid faktiska CVE:er (bort med `--strict`)
- deps: `pytest-asyncio` borttaget (inkompatibelt med pytest 9)
- deps: pytest bumpad till 9.0.3 (CVE-2025-71176)
- deps: fastapi pinnad `<0.136` (MAL-2026-4750)

---

## [0.0.1] — 2026-05-26

### Tillagt
- Initial repo-struktur med tre ML-spår:
  - **Spår A** — Threat report NLP: `ThreatClassifier` (TF-IDF + LogisticRegression), IOC-extraktion (IP, hash, domän, CVE)
  - **Spår B** — Upload risk ML: `UploadClassifier` (Random Forest), feature-extraktion från filmetadata
  - **Spår C** — Adversarial harness: evasion (ART), data poisoning, prompt injection
- `pyproject.toml` med pinnade beroenden och ruff/pytest-konfiguration
- CI-pipeline (GitHub Actions): ruff, pytest, pip-audit
- Dokumentation: `docs/architecture.md`, `docs/data-sources.md`, `docs/sentinel-ml-upload-api-integration-architecture.md`, `docs/adversarial-analysis-plan.md`
- `ROADMAP.md` med fas-indelning och rollfördelning
- Kursledare godkände scope (`bygga vidare på Sentinel`)

---

[Unreleased]: https://github.com/Sidestep-Error/sentinel-ml/compare/main...stoffes_feature
[0.1.0]: https://github.com/Sidestep-Error/sentinel-ml/compare/0.0.2...main
[0.0.2]: https://github.com/Sidestep-Error/sentinel-ml/compare/0.0.1...0.0.2
[0.0.1]: https://github.com/Sidestep-Error/sentinel-ml/releases/tag/0.0.1
