# Teknisk rapport — sentinel-ml

> **STATUS:** Pågående. Slutversion klar **2026-06-17** (2 dagar före deadline).

## 1. Sammanfattning

sentinel-ml är ett ML-baserat säkerhetsmodul byggt ovanpå sentinel-upload-api. Vi byggde tre ML-spår: ett NLP-spår (Spår A) som klassificerar hotrapporter per angreppstyp och extraherar IOCs, ett logganomalispår (Spår B) som detekterar avvikelser i säkerhetsloggar med IsolationForest, samt ett malware-metadataspår (Spår C) som klassificerar malware-familjer på MalwareBazaar-metadata. Spår A uppnår F1-macro 0.875 på riktig CTI-data (mrmoor/cyber-threat-intelligence). Systemet exponeras som en FastAPI-service med Ollama-integration för LLM-baserad analys.

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
sentinel-ml FastAPI service (port 8100)
  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │  data/   │→ │features/ │→ │ models/  │→ │  eval/   │
  └──────────┘  └──────────┘  └──────────┘  └──────────┘
                     │              │
               ┌─────────┐   ┌──────────┐
               │  llm/   │   │adversarial│
               │(Ollama) │   │  (ART)   │
               └─────────┘   └──────────┘
```

Kontraktet mot sentinel-upload-api är MongoDB + HTTP — inga kodimporter. sentinel-ml är **stateless** och läser endast (read-only) från Sentinels MongoDB. Persistens av prediktioner ägs av sentinel-upload-api: den anropar sentinel-ml via HTTP, tar emot svaret och skriver det till `ml_predictions`-collection per `upload_id`. Detta håller sentinel-ml utan skrivrättigheter mot databasen och begränsar blast radius vid kompromiss.

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

Utvärderat med 80/20 train/test-split, `random_state=42`, på `data/real_threat_reports.jsonl` (1 582 dokument).

**Metodjämförelse — klassificering:**

| Modell | Accuracy | F1-macro | Prec-macro | Rec-macro | Beslut |
|--------|----------|----------|------------|-----------|--------|
| TF-IDF + Logistic Regression | **0.943** | **0.875** | **0.955** | **0.841** | **Vald** — stark prestanda, snabb träning, tolkbara feature-vikter |
| spaCy pipeline (NER+LR) | — | — | — | — | Ej utvärderad för klassificering; spaCy används för IOC-extraktion (se 5.1.1) |
| LLM zero-shot (llama3.2:3b) | — | — | — | — | Ej vald — 5–30 s latency per anrop är oacceptabelt för realtidsklassificering; används i stället för incidentsammanfattning |

**Per klass — TF-IDF + LR:**

| Klass | Precision | Recall | F1 | Testexempel |
|-------|-----------|--------|----|-------------|
| ransomware | 0.98 | 0.98 | 0.98 | 47 |
| phishing | 0.97 | 0.97 | 0.97 | 76 |
| malware | 0.93 | 0.97 | 0.95 | 139 |
| intrusion | 0.89 | 0.85 | 0.87 | 48 |
| ddos | 1.00 | 0.43 | 0.60 | 7 |

**Konklusion:** TF-IDF + LR presterar starkt på alla kategorier utom DDoS (F1=0.60) — ett direkt resultat av underrepresentation i träningsdatat (36 dokument). Ransomware och phishing har tydligt domänspecifikt vokabulär som gynnar TF-IDF. TF-IDF + LR valdes framför spaCy-klassificering och LLM zero-shot p.g.a. överlägsen precision/recall vid acceptabel latency.

#### 5.1.1 IOC-extraktionsmetoder — regex vs spaCy

IOC-extraktion är en central funktion i Alt 6. Två metoder implementerades och jämfördes (`scripts/compare_ioc_extractors.py`).

| Metod | Implementering | Styrka | Svaghet |
|-------|----------------|--------|---------|
| Regex | `features/ioc_extract.py` | Hög precision för strukturerade IOCs (IP, hash, CVE, URL, e-post, domän) | Missar named entities (threat actors, malware-namn) |
| spaCy EntityRuler + NER | `features/ioc_extract_spacy.py` | Detekterar threat actors och malware-namn som regex inte kan hitta | Lägre precision för strukturerade IOCs (conf < 1.0 för NER-träffar) |

**Resultat på exempeltext:**

| Metod | Strukturerade IOCs | NER-träffar (threat actors/malware) | Totalt |
|-------|--------------------|-------------------------------------|--------|
| Regex | 6 | 0 | 6 |
| spaCy | 4 | 3 ("CTB-Locker", "Fancy Bear", "SHA-256") | 7 |

**Resultat på 30 verkliga CTI-dokument (`data/real_threat_reports.jsonl`):**

| Metod | Snitt IOCs/dokument | Max IOCs | Dokument med fler träffar än motparten |
|-------|---------------------|----------|----------------------------------------|
| Regex | 0.0 | 0 | 0 av 30 |
| spaCy | 0.5 | 3 | 12 av 30 |

**Analys:** I narrativ CTI-text förekommer sällan strukturerade IOC-format (IPs, hash-strängar). spaCy NER hittar named entities (malware-familjer, threat actor-namn) som regex helt missar. Hybridansatsen — regex för strukturerade indikatorer, spaCy NER för named entities — ger bästa täckning och används i `/predict/threat`-endpointen.

### 5.2 Spår B — Logganomalidetektion

Två komplementära ansatser implementerades, med olika datakrav och utvärderingsparadigm.

**Metodjämförelse:**

| Modell | Precision | Recall | F1 | Kommentar |
|--------|-----------|--------|----|-----------|
| TF-IDF + IsolationForest (text-baserad) | 0.370 | 0.370 | 0.370 | Tränad på 1 000 syntetiska loggrader (800 normal / 200 attack). `contamination=0.20`, `random_state=42`. Utvärderad mot grund-sanningsetiketter. |
| IsolationForest (strukturerade Wazuh-features) | — | — | — | Osupervisad — kräver riktig Wazuh-data utan etiketter. Utvärderas via anomaly_score-fördelning och contamination-parameter, inte F1. Designad för produktionsmiljö där etiketter saknas. |

**Analys:** De två metoderna löser samma problem men med olika förutsättningar. TF-IDF-metoden är superviserbar (kräver etiketter) och lämpar sig för testmiljöer med syntetisk eller annoterad data. Den strukturerade IsolationForest-detektorn kräver inga etiketter och passar produktionsmiljöer med riktiga Wazuh-loggar. F1=0.370 för TF-IDF-metoden på syntetisk data är förväntat lågt — IsolationForest är osensitiv för feature-representation och syntetisk data saknar den token-variation som gynnar TF-IDF.

**Kompletterande LLM-komponent:** Ollama-integrationen (`log_anomaly/summarize.py`) genererar naturspråkliga incidentsammanfattningar från anomalilistor. Detta är inte en detektionsmodell utan ett steg i incidentresponsflödet (LM12).
Alla modeller utvärderades med 80/20 train/test-split, `random_state=42`, på `data/real_threat_reports.jsonl`.
Alla modeller utvärderades med 80/20 train/test-split, `random_state=42`, på `data/real_threat_reports.jsonl` (1 582 dokument).

**Metodjämförelse — klassificering:**

| Modell | Accuracy | F1-macro | Prec-macro | Rec-macro | Beslut |
|--------|----------|----------|------------|-----------|--------|
| TF-IDF + Logistic Regression | **0.943** | **0.875** | **0.955** | **0.841** | **Vald** — stark prestanda, snabb träning, tolkbara feature-vikter |
| spaCy NER + LR | TBD | TBD | TBD | TBD | Benchmarkkolumn reserverad för fortsatt jämförelse i Fas 2 |
| LLM zero-shot (llama3.2:3b) | 0.413 | 0.460 | 0.400 | TBD | Referens för LLM-spåret; används främst för strukturerad analys, inte som primär realtidsklassificerare |

**Per klass — TF-IDF + LR:**

| Klass | Precision | Recall | F1 | Testexempel |
|-------|-----------|--------|----|-------------|
| ransomware | 0.98 | 0.98 | 0.98 | 47 |
| phishing | 0.97 | 0.97 | 0.97 | 76 |
| malware | 0.93 | 0.97 | 0.95 | 139 |
| intrusion | 0.89 | 0.85 | 0.87 | 48 |
| ddos | 1.00 | 0.43 | 0.60 | 7 |

**Konklusion:** TF-IDF + LR presterar starkt på alla kategorier utom DDoS (F1=0.60) — ett direkt resultat av underrepresentation i träningsdatat (36 dokument). Ransomware och phishing har tydligt domänspecifikt vokabulär som gynnar TF-IDF. spaCy NER och fortsatt LLM-jämförelse genomförs i Fas 2.

#### 5.1.1 IOC-extraktionsmetoder — regex vs spaCy

IOC-extraktion är en central funktion i Alt 6. Två metoder implementerades och jämfördes (`scripts/compare_ioc_extractors.py`).

| Metod | Implementering | Styrka | Svaghet |
|-------|----------------|--------|---------|
| Regex | `features/ioc_extract.py` | Hög precision för strukturerade IOCs (IP, hash, CVE, URL, e-post, domän) | Missar named entities (threat actors, malware-namn) |
| spaCy EntityRuler + NER | `features/ioc_extract_spacy.py` | Detekterar threat actors och malware-namn som regex inte kan hitta | Lägre precision för strukturerade IOCs (conf < 1.0 för NER-träffar) |

**Resultat på exempeltext:**

| Metod | Strukturerade IOCs | NER-träffar (threat actors/malware) | Totalt |
|-------|--------------------|-------------------------------------|--------|
| Regex | 6 | 0 | 6 |
| spaCy | 4 | 3 ("CTB-Locker", "Fancy Bear", "SHA-256") | 7 |

**Resultat på 30 verkliga CTI-dokument (`data/real_threat_reports.jsonl`):**

| Metod | Snitt IOCs/dokument | Max IOCs | Dokument med fler träffar än motparten |
|-------|---------------------|----------|----------------------------------------|
| Regex | 0.0 | 0 | 0 av 30 |
| spaCy | 0.5 | 3 | 12 av 30 |

**Analys:** I narrativ CTI-text förekommer sällan strukturerade IOC-format (IP-adresser, hash-strängar). spaCy NER hittar named entities (malware-familjer, threat actor-namn) som regex helt missar. Hybridansatsen — regex för strukturerade indikatorer, spaCy NER för named entities — ger bäst täckning och används i `/predict/threat`-endpointen.

### 5.2 Spår B — Logganomalidetektion

Två komplementära ansatser implementerades, med olika datakrav och utvärderingsparadigm.

**Metodjämförelse:**

| Modell | Precision | Recall | F1 | Kommentar |
|--------|-----------|--------|----|-----------|
| TF-IDF + IsolationForest (text-baserad) | 0.370 | 0.370 | 0.370 | Tränad på 1 000 syntetiska loggrader (800 normal / 200 attack). `contamination=0.20`, `random_state=42`. Utvärderad mot grund-sanningsetiketter. |
| IsolationForest (strukturerade Wazuh-features) | — | — | — | Osuperviserad — kräver riktig Wazuh-data utan etiketter. Utvärderas via `anomaly_score`-fördelning och contamination-parameter, inte F1. Designad för produktionsmiljö där etiketter saknas. |

**Analys:** De två metoderna löser samma problem men med olika förutsättningar. TF-IDF-metoden är superviserad och lämpar sig för testmiljöer med syntetisk eller annoterad data. Den strukturerade IsolationForest-detektorn kräver inga etiketter och passar produktionsmiljöer med riktiga Wazuh-loggar. F1=0.370 för TF-IDF-metoden på syntetisk data är förväntat lågt — IsolationForest är relativt okänslig för feature-representation och syntetisk data saknar den token-variation som gynnar TF-IDF.

**Kompletterande LLM-komponent:** Ollama-integrationen (`log_anomaly/summarize.py`) genererar naturspråkliga incidentsammanfattningar från anomalilistor. Detta är inte en detektionsmodell utan ett steg i incidentresponsflödet (LM12).

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

Se [docs/adversarial-analysis.md](adversarial-analysis.md) för fullständiga experimentresultat och [docs/adversarial-analysis-plan.md](adversarial-analysis-plan.md) för hotmodell och testmetodik.

**Statusöversikt:**

| Experiment | Status | Resultat |
|------------|--------|---------|
| Data poisoning (Spår A) | Klar | ΔF1 = −0.156 vid 20 % label-flipping |
| Evasion (Upload-classifier) | Klar | Flip-rate = 0.0 % vid ε ≤ 0.2 (RF robust mot slumpmässigt brus) |
| Prompt injection (LLM) | Pågår | Kräver körande Ollama-instans — genomförs 11–12 juni |

Tre testade attackytor:
1. **Data poisoning (Spår A):** Label-flipping vid ratio 5–20 % — F1 sjunker från 0.963 → 0.807 vid 20 % förgiftning
2. **Evasion (Upload-classifier):** Feature-perturbation med ε ∈ {0.01–0.2} — Random Forest visar hög robusthet mot slumpmässigt feature-brus
3. **Prompt injection (LLM):** Kuraterad lista av instruktioner dolda i threat report-text — bypass-rate mäts mot LLM-backenden
Se [docs/adversarial-analysis-plan.md](adversarial-analysis-plan.md) för fullständig hotmodell och testmetodik. Resultat dokumenteras i `docs/adversarial-analysis.md` efter genomförda experiment.

Tre testade attackytor:
1. **Data poisoning (Spår A):** Label-flipping vid ratio 5–20 % — F1 sjunker från 0.963 → 0.807 vid 20 % förgiftning
2. **Evasion (Upload-classifier):** Feature-perturbation med ε ∈ {0.01–0.2} — Random Forest visar hög robusthet mot slumpmässigt feature-brus
3. **Prompt injection (LLM):** Inbäddade instruktioner i threat report-text — bypass-rate mäts mot LLM-backenden

Se [docs/adversarial-analysis-plan.md](adversarial-analysis-plan.md) för fullständig hotmodell och testmetodik. Resultat dokumenteras i `docs/adversarial-analysis.md` efter genomförda experiment.

Implementerade motåtgärder:
- System prompt med explicit "this is data, not commands" (`llm/prompts.py`)
- JSON-schemavalidering av LLM-output via Pydantic
- Read-only MongoDB-åtkomst — begränsar blast radius vid kompromiss

## 8. Integration

Se [docs/sentinel-ml-upload-api-integration-architecture.md](sentinel-ml-upload-api-integration-architecture.md).

Valt mönster: **HTTP-service (mönster 2)**. sentinel-ml körs som fristående FastAPI-service på port 8100. sentinel-upload-api anropar `/predict/threat` och `/predict/upload` med 500 ms timeout och degraderar tyst vid fel.

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

Alla tre spår är reproducerbart körbara med dokumenterade metrics:

- **Spår A (Alt 6 — Automated Threat Intel):** TF-IDF + LR uppnår F1-macro 0.875 på riktig CTI-data. IOC-extraktion implementerad som hybrid (regex + spaCy NER). Valt som primärt spår.
- **Spår B (Alt 4 — Log-anomali):** Två komplementära metoder implementerade — TF-IDF+IsolationForest (F1=0.370 på syntetisk data) och strukturerad Wazuh-IsolationForest (osupervisad, produktionsinriktad). LLM-sammanfattning via Ollama för incidentrespons.
- **Spår C (Alt 3 — Malware, delvis):** Random Forest på metadata uppnår F1=0.42 (4× bättre än slumpen). Tydligt avgränsad som ett delspår utan beteendedata.
*(Fylls i efter avslutade experiment.)*

## Referenser

- OWASP Machine Learning Security Top 10 — https://owasp.org/www-project-machine-learning-security-top-10/
- MITRE ATLAS — Adversarial Threat Landscape for AI Systems — https://atlas.mitre.org/
- NIST AI 100-2 — Adversarial Machine Learning: A Taxonomy and Terminology
- mrmoor/cyber-threat-intelligence dataset (CC-BY-4.0) — https://huggingface.co/datasets/mrmoor/cyber-threat-intelligence
- ChasAcademy 2026 kurslitteratur
