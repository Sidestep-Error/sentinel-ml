# Teknisk rapport — sentinel-ml

> **STATUS:** Skelett. Fylls i löpande under Fas 1–3.
> Slutversion ska vara klar **2026-06-17** (2 dagar före deadline).

## 1. Sammanfattning

*(En kort paragraf: vad byggde vi, vilka modeller, vilka resultat,
vilka slutsatser. Fyll i sist.)*

## 2. Problem och mål

*(Vilken säkerhetsfunktion löser detta? Vilka av kursens lärandemål
adresseras (LM2/6/8/11/12)? Vilken roll spelar verktyget i ett SOC-flöde?)*

## 3. Arkitektur

*(Hänvisa till `docs/architecture.md`. Inkludera ASCII-diagrammet här
eller en bild.)*

## 4. Datakällor och förbehandling

*(Vilka dataset, hur stora, hur städade, vilken klassfördelning. Hänvisa
till `docs/data-sources.md`.)*

## 5. Modellval

### 5.1 Spår A — Threat report-klassificerare

| Modell | F1-macro | Precision-macro | Recall-macro | Träningstid |
|--------|----------|------------------|---------------|-------------|
| TF-IDF + LR | 0.875 | 0.955 | 0.841 | TBD |
| spaCy NER + LR | TBD | TBD | TBD | TBD |
| LLM zero-shot (llama3.2:3b) | 0.413 | 0.460 | 0.400 | TBD |

*(Konklusion: vilken vann och varför. Trade-off vs. komplexitet.)*

### 5.2 Spår B — Upload-classifier

| Modell | F1 | Precision | Recall | Träningstid |
|--------|-----|-----------|---------|--------------|
| Logistic Regression | TBD | TBD | TBD | TBD |
| Random Forest | TBD | TBD | TBD | TBD |
| Gradient Boosting | TBD | TBD | TBD | TBD |

## 6. Träningsprocess

*(Hyperparameter-sökning, validation strategy, seeds, reproducerbarhet.)*

## 7. Säkerhetsanalys

*(Hänvisa till `docs/adversarial-analysis.md`. Sammanfatta resultaten:
poisoning-degradering, evasion-success-rate, prompt-injection-resultat.)*

## 8. Integration

*(Hänvisa till `docs/integration-with-sentinel-upload-api.md`. Vilket
mönster valdes? Vilken latency uppmättes?)*

## 9. Begränsningar och framtida arbete

*(Vad fungerar inte? Vad skulle vi göra med mer tid?)*

## 10. Slutsatser

*(Vad lärde vi oss? Hur skulle vi gjort om vi börjat om?)*

## Referenser

- OWASP Machine Learning Security Top 10
- MITRE ATLAS — Adversarial Threat Landscape for AI Systems
- NIST AI 100-2 — Adversarial Machine Learning Taxonomy
- ChasAcademy 2026 kurslitteratur
