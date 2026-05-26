# ROADMAP — sentinel-ml

**Senast uppdaterad:** 2026-05-26
**Deadline:** 2026-06-19 (≈ 3,5 veckor)
**Examineras mot:** LM2, LM6, LM8, LM11, LM12 (se `guides/week-9-group-project.html` i sentinel-upload-api)

---

## Faser

### Fas 0 — Setup (klart eller pågående)

- [x] Repo skapat och scaffold på plats
- [ ] Alla teammedlemmar har klonat och kört `pip install -e ".[dev]"` framgångsrikt
- [ ] CI-pipeline grön (ruff + pytest)
- [ ] Kursledare har godkänt scope (`bygga vidare på Sentinel`)

### Fas 1 — Baseline (vecka 1, ~till 2026-06-01)

**Mål:** En tränad modell per spår, oavsett kvalitet. Dokumenterade metrics.

- [ ] **Spår A:** TF-IDF + LogisticRegression på syntetiskt threat-report-dataset. Mätvärden: accuracy, precision, recall, F1 per klass.
- [ ] **Spår A:** IOC-extraktion via regex (IP, hash, domän, CVE) — baseline utan ML.
- [ ] **Spår B:** Feature-extraktion från Sentinel MongoDB (`uploads`-collection): size, content_type, extension, entropi-approximation från sha256-prefix, namnlängd, special-tecken-count.
- [ ] **Spår B:** Random Forest baseline med `class_weight="balanced"`.
- [ ] **Integration:** Lokal FastAPI-service (`/predict/threat`, `/predict/upload`) som returnerar dummy-svar.
- [ ] **LLM:** Ollama installerat lokalt, `llama3.2:3b` nedladdad, en `client.generate()`-anrop funkar i tester.

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

### Fas 3 — Demo + leverans (vecka 3, ~2026-06-15 → 2026-06-19)

**Mål:** Spikad demo, ifylld rapport, inlämnat.

- [ ] FastAPI-service körs i Docker på Hetzner eller lokalt (välj enklast för demo).
- [ ] Sentinel UI visar ML-output i realtid.
- [ ] Backup-demo-video inspelad (5 min, walkthrough).
- [ ] Teknisk rapport ifylld (arkitektur, dataflöde, modellval, träningsprocess, säkerhetsanalys).
- [ ] Presentationsmaterial — 10–15 min, alla pratar (intro, metod, demo, säkerhet, slutsats).
- [ ] Slutgiltig commit + tag (`v1.0.0`).
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
- [x] Jämförelse av flera ML-metoder (Spår A: TF-IDF vs spaCy vs LLM)
- [x] Avancerad feature engineering eller modellarkitektur
- [x] Robusthetstestning mot adversarial attacks (data poisoning, evasion, prompt injection)
- [x] Integration med befintlig säkerhetsinfra (sentinel-upload-api)
- [x] Välstrukturerad, reproducerbar kodbas (pyproject + lock, MLflow, CI)
