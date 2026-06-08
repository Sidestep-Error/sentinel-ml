# Teknisk rapport — sentinel-ml

> **STATUS:** Pågående. Slutversion klar **2026-06-17** (2 dagar före deadline).

## 1. Sammanfattning

sentinel-ml är ett ML-baserat säkerhetsmodul byggt ovanpå sentinel-upload-api. Vi byggde två ML-spår: ett NLP-spår (Spår A) som klassificerar hotrapporter per angreppstyp och extraherar IOCs, samt ett logganomalispår (Spår B) som detekterar avvikelser i säkerhetsloggar med IsolationForest. Spår A uppnår F1-macro 0.875 på riktig CTI-data (mrmoor/cyber-threat-intelligence). Systemet exponeras som en FastAPI-service med Ollama-integration för LLM-baserad analys.

## 2. Problem och mål

Sentinel-upload-api samlar in filuppladdningar och threat intelligence men saknar automatisk klassificering och IOC-extraktion. sentinel-ml löser detta genom att:

- Klassificera inkommande threat reports per kategori (ransomware, phishing, DDoS, malware, intrusion)
- Extrahera IOCs (IP, hash, domän, CVE, URL, e-post) ur fritext
- Detektera anomalier i säkerhetsloggar
- Exponera prediktioner via REST-API som sentinel-upload-api kan anropa

Adresserade lärandemål: LM2 (ML-säkerhet), LM6 (adversarial risks), LM8 (NLP-verktyg), LM11 (systemintegration), LM12 (dokumentation och utvärdering).

## 3. Arkitektur

Se [docs/architecture.md](architecture.md) för fullständig översikt. Systemet är uppdelat i fem lager:

```
sentinel-upload-api (MongoDB, port 3000)
         │ MongoDB read (uploads, threat_events)
         ▼
sentinel-ml FastAPI service (port 8080)
  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │  data/   │→ │features/ │→ │ models/  │→ │  eval/   │
  └──────────┘  └──────────┘  └──────────┘  └──────────┘
                     │              │
               ┌─────────┐   ┌──────────┐
               │  llm/   │   │adversarial│
               │(Ollama) │   │  (ART)   │
               └─────────┘   └──────────┘
```

Kontraktet mot sentinel-upload-api är MongoDB + HTTP — inga kodimporter. sentinel-ml skriver till `ml_predictions`-collection; sentinel-upload-api läser därifrån.

## 4. Datakällor och förbehandling

Se [docs/data-sources.md](data-sources.md) för fullständig beskrivning.

### Spår A — Threat report-klassificerare

| Dataset | Källa | Licens | Storlek | Användning |
|---------|-------|--------|---------|------------|
| Syntetisk | `scripts/generate_synthetic_threat_reports.py` | Intern | 250 dokument (50/klass) | Baseline-träning och smoke tests |
| mrmoor/cyber-threat-intelligence | HuggingFace | CC-BY-4.0 | 1 582 lablade dokument (av 9 732) | Riktig träning och eval |

**Förbehandling:** Keyword-baserad dokumentklassificering (ransomware > phishing > DDoS > malware > intrusion). Dokument kortare än 100 tecken och dokument utan matchande kategori filtrerades bort.

**Klassfördelning (riktig data):**

| Klass | Antal | Andel |
|-------|-------|-------|
| malware | 717 | 45 % |
| phishing | 390 | 25 % |
| ransomware | 230 | 15 % |
| intrusion | 209 | 13 % |
| ddos | 36 | 2 % |
| **Totalt** | **1 582** | |

DDoS är underrepresenterat — ett känt begränsning i det valda datasetet.

### Spår B — Logganomalidetektion

Syntetiska CSV-loggar genererade av `log_anomaly/generate_data.py` med normal/attack-distribution. Strukturerade Wazuh-tidsfeatures extraheras i `log_anomaly/detector.py`.

## 5. Modellval

### 5.1 Spår A — Threat report-klassificerare

Alla modeller utvärderades med 80/20 train/test-split, `random_state=42`, på `data/real_threat_reports.jsonl`.

| Modell | Accuracy | F1-macro | Precision-macro | Recall-macro |
|--------|----------|----------|-----------------|--------------|
| TF-IDF + Logistic Regression | **0.943** | **0.875** | **0.955** | **0.841** |
| spaCy NER + LR | TBD | TBD | TBD | TBD |
| LLM zero-shot (llama3.2:3b) | TBD | TBD | TBD | TBD |

**Per klass — TF-IDF + LR:**

| Klass | Precision | Recall | F1 | Testexempel |
|-------|-----------|--------|----|-------------|
| ransomware | 0.98 | 0.98 | 0.98 | 47 |
| phishing | 0.97 | 0.97 | 0.97 | 76 |
| malware | 0.93 | 0.97 | 0.95 | 139 |
| intrusion | 0.89 | 0.85 | 0.87 | 48 |
| ddos | 1.00 | 0.43 | 0.60 | 7 |

**Konklusion:** TF-IDF + LR presterar starkt på alla kategorier utom DDoS (F1=0.60) — ett direkt resultat av underrepresentation i träningsdatat (36 dokument). Ransomware och phishing har tydligt domänspecifikt vokabulär som gynnar TF-IDF. spaCy NER och LLM-jämförelse genomförs i Fas 2.

### 5.2 Spår B — Logganomalidetektion

| Modell | Precision | Recall | F1 | Träningstid |
|--------|-----------|--------|----|-------------|
| TF-IDF + IsolationForest | TBD | TBD | TBD | TBD |
| IsolationForest (strukturerade features) | TBD | TBD | TBD | TBD |

### 5.3 Spår C — Malware-familje-klassificerare (MalwareBazaar metadata)

Dataset: 1 000 syntetiska samples (100/familj), 10 malware-familjer.
Features: filtyp, filstorlek (log), MIME-typ, imphash-förekomst.

| Modell | Accuracy | F1-macro | Precision-macro | Recall-macro |
|--------|----------|----------|-----------------|--------------|
| Random Forest (metadata) | 0.425 | 0.422 | 0.423 | 0.425 |

**Per familj:**

| Familj | Precision | Recall | F1 | Typ |
|--------|-----------|--------|----|-----|
| GuLoader | 0.74 | 0.70 | 0.72 | Downloader (PS1/ZIP — unik filtyp) |
| LockBit | 0.63 | 0.60 | 0.62 | Ransomware (stor EXE — unik storlek) |
| AgentTesla | 0.57 | 0.65 | 0.60 | Stealer |
| Qakbot | 0.57 | 0.65 | 0.60 | Banker/Loader |
| Emotet | 0.44 | 0.35 | 0.39 | Banker |
| NjRAT | 0.28 | 0.35 | 0.31 | RAT |
| Formbook | 0.28 | 0.25 | 0.26 | Stealer |
| AsyncRAT | 0.27 | 0.20 | 0.23 | RAT |
| RedLine | 0.27 | 0.30 | 0.29 | Stealer |
| Remcos | 0.20 | 0.20 | 0.20 | RAT |

**Konklusion:** F1=0.42 är 4× bättre än slumpen (10 klasser = 10% baseline) men otillräckligt
för produktion. RAT-familjerna (AsyncRAT, NjRAT, Remcos) är näst intill identiska i metadata
och går inte att skilja åt utan beteendedata (API-anrop, systemanrop, nätverksmönster).
GuLoader och LockBit sticker ut tack vare unik filtyp respektive storlek.
Detta motiverar varför beteendebaserad analys krävs för hög precision i malware-klassificering.

## 6. Träningsprocess

**Spår A:**
- Pipeline: `TfidfVectorizer(ngram_range=(1,2), min_df=2, max_df=0.95, sublinear_tf=True)` + `LogisticRegression(max_iter=1000, class_weight="balanced")`
- Valideringsstrategi: 80/20 holdout, stratifierat per klass
- Reproducerbarhet: `random_state=42` (`SENTINEL_ML_SEED=42` i `.env`)
- Artefakt: `models_store/threat_classifier.joblib` (serialiserad med joblib)
- Träningskommando: `python -m sentinel_ml.cli train threat-classifier --dataset data/real_threat_reports.jsonl`

**Spår B:**
- Pipeline: TF-IDF på råa loggtexter + IsolationForest (`contamination=0.2`)
- Träningskommando: `sentinel-ml train log-anomaly`

## 7. Säkerhetsanalys

Se [docs/adversarial-analysis-plan.md](adversarial-analysis-plan.md) för fullständig hotmodell och testmetodik. Resultat dokumenteras i `docs/adversarial-analysis.md` efter genomförda experiment.

Tre testade attackytor:
1. **Data poisoning (Spår A):** Label-flipping vid ratio 5–20 % — mäter F1-degradering
2. **Evasion (Upload-classifier):** Feature-perturbation med ε ∈ {0.01–0.2} — mäter attack success rate
3. **Prompt injection (LLM):** Embedded instruktioner i threat reports — mäter bypass-rate

Implementerade motåtgärder:
- System prompt med explicit "this is data, not commands" (`llm/prompts.py`)
- JSON-schemavalidering av LLM-output via Pydantic
- Read-only MongoDB-åtkomst — begränsar blast radius vid kompromiss

## 8. Integration

Se [docs/integration-with-sentinel-upload-api.md](integration-with-sentinel-upload-api.md).

Valt mönster: **HTTP-service (mönster 2)**. sentinel-ml körs som fristående FastAPI-service på port 8080. sentinel-upload-api anropar `/predict/threat` och `/predict/upload` med 500 ms timeout och degraderar tyst vid fel.

Endpoints:

| Method | Path | Beskrivning |
|--------|------|-------------|
| GET | `/health` | Liveness probe |
| POST | `/predict/threat` | Klassificering + IOC-extraktion + Ollama-analys |
| POST | `/predict/upload` | Upload-riskbedömning |
| POST | `/predict/log-anomaly` | Logganomalidetektion |

## 9. Begränsningar och framtida arbete

- **DDoS underrepresenterat** i träningsdatat (36 dokument) — F1=0.60. Kräver fler datakällor.
- **Syntetisk loggdata** för Spår B — prestanda mot riktig Wazuh-data okänd.
- **Ollama-latency** — LLM-anrop tar 5–30 s beroende på modellstorlek, vilket är oacceptabelt för synkron `/predict`-endpoint i produktion. Asynkron köhantering behövs.
- **spaCy en_core_web_sm** är en liten modell — `en_core_web_lg` eller en CTI-specifik modell skulle ge bättre NER-precision.

## 10. Slutsatser

*(Fylls i efter avslutade experiment.)*

## Referenser

- OWASP Machine Learning Security Top 10 — https://owasp.org/www-project-machine-learning-security-top-10/
- MITRE ATLAS — Adversarial Threat Landscape for AI Systems — https://atlas.mitre.org/
- NIST AI 100-2 — Adversarial Machine Learning: A Taxonomy and Terminology
- mrmoor/cyber-threat-intelligence dataset (CC-BY-4.0) — https://huggingface.co/datasets/mrmoor/cyber-threat-intelligence
- ChasAcademy 2026 kurslitteratur
