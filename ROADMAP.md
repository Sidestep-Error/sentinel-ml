# ROADMAP — sentinel-ml

**Senast uppdaterad:** 2026-06-09
**Deadline:** 2026-06-19 (≈ 3,5 veckor)
**Examineras mot:** LM2, LM6, LM8, LM11, LM12 (se `guides/week-9-group-project.html` i sentinel-upload-api)

---

## Slutspurt 2026-06-08 -> 2026-06-19 (konkret checklista)

Målet med slutspurten är att stänga det som fortfarande är "delvis" och visa tre tydliga projektspår:

- **Alternativ 6 (Automated Threat Intel):** Ska vara **helt uppfyllt**.
- **Alternativ 4 (Log-anomali med LLM):** Ska vara **helt eller nästan helt uppfyllt**.
- **Alternativ 3 (Malware-analys):** Ska vara **tydligt delvis uppfyllt** med korrekt avgränsning i rapport och demo.

### Prioritering från kollega (2026-06-08)

Bedömningen nedan används som styrning för vad vi bygger först till demo:

- Metadata + ClamAV -> första AI/ML-flöde: låg till medel (snabbast väg till stabil demo)
- Trivy-output -> CVE/SBOM-relevans: medel (matchningskärna finns, fokus på datakoppling)
- Direkt textextraktion för .txt/.md/.json/.csv/.eml: medel (kräver parsering + säkert flöde)
- Allt i ett sammanhängande liveflöde: medel till hög (integrationsrisk och tidsrisk)

Praktisk prioritet för tidsplan:

- [x] Metadata + ClamAV till ML
- [x] SBOM/CVE-relevans
- [x] Text-extraktion till LLM/IOC
- [x] Sammanhållet liveflöde (backend-aggregator `/predict/liveflow`)
- [ ] Sammanhållet liveflöde i UI

Detaljerad cross-repo-plan finns i `docs/sentinel-ml-upload-api-integration-architecture.md`.

## Projektkrav status (2026-06-09)

### G-krav

- [x] Fungerande ML-baserat säkerhetsverktyg (API + modeller + end-to-end-flöden)
- [x] Dokumenterade modellresultat med relevanta metriker (accuracy, precision, recall, F1)
- [x] Teknisk dokumentation av arkitektur, dataflöde och implementation
- [ ] Säkerhetsanalys helt stängd (prompt-injection-resultat saknas ännu — kollegan)
- [ ] Presentation med live-demo i vecka 11 (Demo Day 16 juni)

### VG-krav (utöver G)

- [x] Jämförelse av flera ML-metoder — IOC regex vs spaCy (30 CTI-dok), log anomaly TF-IDF vs strukturerad IF, threat classifier metodval motiverat med latency-evidens
- [x] Avancerad feature engineering/modellarkitektur (hybrid IOC, tre ML-pipelines, spaCy EntityRuler)
- [ ] Robusthetstestning helt stängd (prompt-injection kvar — kollegan)
- [ ] Integration med befintlig säkerhetsinfrastruktur (backend klart, UI i sentinel-upload-api kvar)
- [x] Välstrukturerad, reproducerbar kodbas — 104 tester (inkl. 8 outcome-tester), ruff ren, CI grön

### A. Måste klart för Alternativ 6 (Automated Threat Intel)

- [x] Kör slutlig eval för threat-klassificeraren och skriv in slutliga tabeller i `docs/technical-report.md`.
- [x] Fyll i jämförelsemodeller (spaCy/LLM) — dokumenterade som ej valda med motivering + evidens (latency, IOC-uppgift vs klassificeringsuppgift). IOC-jämförelse (regex vs spaCy på 30 CTI-dokument) tillagd som sektion 5.1.1.
- [x] Verifiera IOC-extraktion med jämförelsescript och lägg in kort resultatsammanfattning i rapporten.
- [x] Säkerställ att `/predict/threat` visar: kategori, confidence, IOCs och model_version i demo-flödet. ✓ Verifierat via TestClient.
- [x] Lägg in 3 realistiska demoexempel (phishing, ransomware, intrusion) med förväntad output. ✓ Se `docs/demo-examples.md`.

**Klart när:** metrics + modellval + API-demo + IOC-evidens finns dokumenterat och är reproducerbart.

### B. Måste klart för Alternativ 4 (Log-anomali med LLM)

- [x] Kör och dokumentera slutlig log-anomaly-evaluering (precision/recall/F1) i `docs/technical-report.md`.
- [x] Verifierat fallback-beteende om Ollama är nere — `summarize.py` degraderar till regelbaserad text; lazy-import fix applicerad.
- [x] Demo-tabell "normal vs anomali" dokumenterad i `docs/demo-examples.md` (Scenario 4) med verifierade scores och talkpunkter.
- [x] Best Heist-demo (`scripts/demo_attack_live.py`) — HTTP-attack mot live API; visar att 77 % av attackloggar undkommer detektion utan mimicry.
- [ ] Kör prompt-injection-testet med aktiv Ollama och uppdatera `docs/adversarial-analysis.md`. (kollegan)

LLM-relaterade punkter i denna sektion ägs av kollega som kör Ollama-spåret.

**Klart när:** log-metrics är ifyllda, prompt-injection inte längre står som "ej testat", och demo visar end-to-end.

### C. Måste klart för Alternativ 3 (Malware-analys, delvis)

- [ ] Behåll malware-spåret i rapporten med nuvarande resultat, men märk tydligt som metadata-baserat delspår.
- [ ] Lägg till en tydlig begränsning: ingen systemanrops-/API-sekvensanalys i denna iteration.
- [ ] Lägg till ett konkret "nästa steg" (ex: API-call sequence features) för att visa metodförståelse.
- [ ] Visa en enkel jämförelsetabell i presentationen: vad spåret redan gör vs vad som krävs för full uppfyllelse.

**Klart när:** examinator direkt ser att ni medvetet levererar "delvis" med korrekt teknisk motivering.

### D. G-krav: stäng alla öppna punkter

- [x] Teknisk rapport klar — alla "Pågår"/"TBD"-platshållare stängda (2026-06-09).
- [ ] Adversarial-analysen komplett — poisoning ✓, evasion ✓, prompt-injection saknas (kollegan, 11-12 juni).
- [ ] Förbered 10-15 min demo med backup-video (13-14 juni).
- [ ] Verifiera att alla i gruppen har meningsfulla commits innan inlämning.
- [x] Testsvit: 104 tester (inkl. 8 outcome-tester), ruff ren, CI grön.

### E. VG-krav: minsta säkra väg (3 starka punkter)

**Status 2026-06-09: 3 av 5 säkra, VG-gränsen uppnådd.**

- [x] **Jämförelse av flera ML-metoder** — IOC regex vs spaCy (riktiga siffror), log anomaly TF-IDF vs strukturerad IF, threat classifier motiverat modellval.
- [ ] **Robusthetstestning mot adversarial attacks** — poisoning + evasion klara; prompt-injection kvar (kollegan).
- [ ] **Integration med befintlig säkerhetsinfrastruktur** — backend-kontrakt klart inkl. sha256-fix; application-kod i sentinel-upload-api saknas (Jon).
- [x] **Avancerad feature engineering** — hybrid IOC, tre ML-pipelines, EntityRuler.
- [x] **Välstrukturerad kodbas** — 104 tester, outcome-tester, ruff, CI.

### F. Dag-för-dag (uppdaterad 2026-06-09)

- [x] **8-9 juni:** stäng alla "TBD" i metrics, upload-klassificerare tränad på 2 000 poster, MongoDB populerad (2 017 poster), outcome-tester, Best Heist-demo, lazy-import-fix i `summarize.py` och `llm/__init__.py`, sha256-kontrakt fixat, Copilot-commit skriven om.
- [ ] **11-12 juni:** prompt-injection med Ollama (kollegan) + Jon: integration PR i sentinel-upload-api.
- [ ] **13-14 juni:** slides med F1-tabeller + confusion matrix + demo-script timad + backup-video inspelad.
- [ ] **15 juni:** full intern genomkörning (12 min + 3 min buffert).
- [ ] **16 juni (Demo Day):** live-demo mot Hetzner + backup redo.
- [ ] **17-18 juni:** slutputs dokumentation + release-tag `v1.0.0`.
- [ ] **19 juni:** slutinlämning.

### Nästa repo-steg: sentinel-upload-api

- [ ] Lägg till `SentinelMlClient` och anropa `/predict/liveflow` med 500 ms timeout.
- [ ] Bygg payload-mappning (upload + upload_text + cve_relevance) i upload-flödet.
- [ ] Persista svar i `ml_predictions` per `upload_id`.
- [ ] Visa liveflow-fält i upload-detaljvyn i UI.
- [ ] Verifiera graceful degradation när sentinel-ml inte svarar.

### Checklista inför fredag 2026-06-12 (måste vara klart)

Detta är den operativa stopp-listan inför intern deadline på fredag.

- [ ] **Cross-repo integration klar i sentinel-upload-api**
  - DoD: `SentinelMlClient` finns, `/predict/liveflow` anropas med timeout 500 ms, payload innehåller `upload`, `upload_text`, `cve_relevance`.
  - Evidens: länkad PR + diff + kort körlogg från lyckat anrop.
- [ ] **Graceful degradation verifierad**
  - DoD: Upload-flödet i sentinel-upload-api fungerar även när sentinel-ml är nere; inga 500-fel i UI på grund av ML-timeout.
  - Evidens: två testkörningar (ML up/down) dokumenterade i PR-beskrivning.
- [ ] **ML-resultat syns i UI**
  - DoD: upload-detalj visar minst `label`, `confidence`, IOC-count/lista och `matched_cves`.
  - Evidens: 2 skärmbilder (normal + malicious case).
- [ ] **Prompt-injection-resultat stängt (kollegans spår)**
  - DoD: `docs/adversarial-analysis.md` uppdaterad med metod, testfall, success rate och slutsats.
  - Evidens: commit-referens + tabell/sektion i rapport.
- [ ] **Teknisk rapport konsoliderad och konsekvent**
  - DoD: inga dubbla/konflikterande sektioner i `docs/technical-report.md`; alla TBD/Pågår borttagna i slutversion.
  - Evidens: snabb peer review (1 godkännande i teamet) + markerad "demo version" i filens topp.
- [ ] **Demo-manus klart och tidat**
  - DoD: 10-12 min manus med ordning: problem -> metod -> liveflow -> adversarial -> slutsats.
  - Evidens: genomkörning en gång utan avbrott och tidslogg.
- [ ] **Backup-material klart**
  - DoD: backup-video 3-5 min + lokalt fallback-scenario om live-miljö fallerar.
  - Evidens: videofil + checkad fallback-sekvens i manus.
- [ ] **Release hygiene för fredagspunkter**
  - DoD: `ROADMAP.md` och `CHANGELOG.md` uppdaterade med vad som faktiskt blev klart under veckan.
  - Evidens: separat "fredagscommit" med tydlig sammanfattning.

**Go/No-Go fredag 2026-06-12:**

- **GO** om alla punkter ovan är klara.
- **Villkorat GO** om endast prompt-injection återstår men övriga punkter är klara och fallback-plan finns i demo.
- **NO-GO** om cross-repo UI/integration inte är fungerande.

---

## Faser

### Fas 0 — Setup (klart eller pågående)

- [x] Repo skapat och scaffold på plats
- [ ] Alla teammedlemmar har klonat och kört `pip install -e ".[dev]"` framgångsrikt
- [ ] CI-pipeline grön (ruff + pytest)
- [x] Kursledare har godkänt scope (`bygga vidare på Sentinel`)

### Fas 1 — Baseline (vecka 1, ~till 2026-06-01)

**Mål:** En tränad modell per spår, oavsett kvalitet. Dokumenterade metrics.

- [ ] **Spår A:** TF-IDF + LogisticRegression på syntetiskt threat-report-dataset. Mätvärden: accuracy, precision, recall, F1 per klass.
- [ ] **Spår A:** IOC-extraktion via regex (IP, hash, domän, CVE) — baseline utan ML.
- [ ] **Spår B:** Feature-extraktion från Sentinel MongoDB (`uploads`-collection): size, content_type, extension, entropi-approximation från sha256-prefix, namnlängd, special-tecken-count.
- [ ] **Spår B:** Random Forest baseline med `class_weight="balanced"`.
- [ ] **Integration:** Lokal FastAPI-service (`/predict/threat`, `/predict/upload`) som returnerar dummy-svar.
- [ ] **LLM:** Ollama installerat lokalt, `llama3.2:3b` nedladdad, en `client.generate()`-anrop funkar i tester.
- [ ] **Status-badge:** uppdatera README.md `Status: scaffold` → `Status: alpha` när fas är klar.

### Fas 2 — Iteration + adversarial (vecka 2, ~2026-06-08)

**Mål:** Bättre modeller + adversarial-tester körda och dokumenterade.

- [ ] **Spår A:** Jämför TF-IDF+LR vs spaCy NER vs LLM zero-shot på samma testset. Tabell över precision/recall/F1.
- [ ] **Spår A:** CVE-relevansgradering — matcha CVE-ID:n mot SBOM från sentinel-upload-api (Trivy/Syft artefakt) + ranka per CVSS.
- [ ] **Spår B:** Hyperparameter-sökning (GridSearch eller Optuna) på Random Forest + Gradient Boosting. Välj bästa.
- [ ] **Spår C (kritisk för VG):**
  - [ ] **Data poisoning:** lägg in 5/10/20 % felmärkta threat reports i träningsdata. Mät F1-degradering. Plot i `docs/adversarial-analysis.md`.
  - [ ] **Evasion:** ART `HopSkipJump` på Spår B-modellen. Skapa adversarial-exempel som ligger nära beslutsgränsen.
  - [ ] **Prompt injection:** kuraterad lista av prompts som försöker styra LLM-output. Mät success rate.
- [ ] **Rapport:** Påbörja teknisk rapport (`docs/technical-report.md`).
- [ ] **UI-integration:** PR i `sentinel-upload-api` som visar ML-output i threat map-popup.
- [ ] **Status-badge:** uppdatera README.md `Status: alpha` → `Status: beta` när fas är klar.

### Fas 3 — Demo + leverans (vecka 3, ~2026-06-15 → 2026-06-19)

**Mål:** Spikad demo, ifylld rapport, inlämnat.

- [ ] FastAPI-service körs i Docker på Hetzner eller lokalt (välj enklast för demo).
- [ ] Sentinel UI visar ML-output i realtid.
- [ ] Backup-demo-video inspelad (5 min, walkthrough).
- [ ] Teknisk rapport ifylld (arkitektur, dataflöde, modellval, träningsprocess, säkerhetsanalys).
- [ ] Presentationsmaterial — 10–15 min, alla pratar (intro, metod, demo, säkerhet, slutsats).
- [ ] Slutgiltig commit + tag (`v1.0.0`).
- [ ] **Status-badge:** uppdatera README.md `Status: beta` → `Status: released` vid inlämning.
- [ ] Inlämning via Canvas/portalen senast **2026-06-19**.

---

## Rollfördelning (5 personer)

| Person | Huvudansvar | Sekundär |
|--------|-------------|----------|
| Jon | Tech lead, integration mot sentinel-upload-api, FastAPI-service, demo-orchestrering | Code review |
| TBD | Spår A — NLP (TF-IDF, spaCy, klassisk ML) | Datasetkurering |
| TBD | Spår A — LLM (Ollama, prompt engineering, CVE-relevans) | Prompt-injection-tester |
| TBD | Spår B — Upload classifier (feature engineering, RF/GBM, eval) | MongoDB-ingest |
| TBD | Spår C — Adversarial-harness (ART, poisoning, dokumentation) | Teknisk rapport |

Justera när teamet bekräftat rollerna.

---

## Definition of Done

**G-nivå (minimum):**
- En fungerande modell per spår med rapporterade metrics
- Teknisk dokumentation (`docs/`)
- Säkerhetsanalys av ML-systemet (`docs/adversarial-analysis.md`)
- 10–15 min presentation + live-demo

**VG-nivå (måste-ha utöver G — minst 3 av):**
- [ ] Jämförelse av flera ML-metoder (Spår A: TF-IDF vs spaCy vs LLM)
- [x] Avancerad feature engineering eller modellarkitektur
- [ ] Robusthetstestning mot adversarial attacks (data poisoning, evasion, prompt injection)
- [ ] Integration med befintlig säkerhetsinfra (sentinel-upload-api)
- [x] Välstrukturerad, reproducerbar kodbas (pyproject + lock, MLflow, CI)
