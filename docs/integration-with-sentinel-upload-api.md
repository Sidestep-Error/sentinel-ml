# Integration med sentinel-upload-api

## Princip

`sentinel-ml` och `sentinel-upload-api` är **separata repos och separata
deploys**. Kontraktet mellan dem är data (MongoDB) och HTTP, inte
kodimport.

## Tre integrationsmönster

### 1. Off-line batch (enklast, börja här)

`sentinel-ml` kör periodiskt som ett cron-jobb eller manuellt:

1. Läser från `sentinel-upload-api`s MongoDB (`uploads`, `threat_events`).
2. Kör klassificering / IOC-extraktion / CVE-relevans.
3. Skriver resultat till `ml_predictions`-collection i samma databas.
4. `sentinel-upload-api`s UI läser från `ml_predictions` när threat-map
   eller upload-detalj visas.

**Fördel:** noll förändring i `sentinel-upload-api`-deploy. Endast ny
collection läses.

**Nackdel:** inte realtid.

### 2. HTTP-service (för live-demo i vecka 11)

`sentinel-ml` deployas som en FastAPI-service (port 8100). `sentinel-upload-api`
ringer `/predict/threat` och `/predict/upload` synkront eller asynkront.

**Endpoints exponerade av `sentinel-ml`:**

| Method | Path | Body | Response |
|--------|------|------|----------|
| GET | `/health` | – | `{status, version}` |
| POST | `/predict/threat` | `{text: str}` | `{category, confidence, iocs, model_version}` |
| POST | `/predict/upload` | `UploadRecord` JSON | `{label, confidence, explanation, model_version}` |

**Authentication:** För kursprojektets demo räcker ingen auth (intern K8s-service,
NetworkPolicy begränsar tillgång). I produktion: mTLS eller delad HMAC-secret.

**Tillgänglighet:** ML-tjänsten får ALDRIG ta ner upload-flödet. `sentinel-upload-api`
ringer med kort timeout (500 ms) och degraderar tyst om ML-tjänsten är nere.

### 3. Sidecar (om Hetzner-noden tillåter)

Kör `sentinel-ml`-containern som en sidecar i samma pod som `sentinel-upload-api`.
Snabbare nätverk, en deploy-enhet. Kräver dock att vi packar om Sentinel-deployen.

**Rekommendation:** Kör mönster 1 (batch) under Fas 1 + 2, lyft till mönster 2
(HTTP) i Fas 3 för demo. Hoppa över mönster 3 om vi inte hinner.

## Konkreta ändringar i `sentinel-upload-api`

**Minimum (för mönster 1):**

- Lägg till en ny collection `ml_predictions` i indexsetup (`app/db.py`).
- I `app/routers/threats.py`: när threat events returneras, gör en lookup
  i `ml_predictions` per event och inkludera fältet om det finns.
- I UI:t (`app/static/index.html`): visa ML-fältet i threat map-popup.

**För mönster 2 (HTTP):**

- Ny env-var: `SENTINEL_ML_URL=http://sentinel-ml.sentinel.svc.cluster.local:8100`.
- En `httpx.AsyncClient` med timeout 500 ms i `app/routers/threats.py`.
- Försämringsgraciös fallback: om timeout → returnera utan ML-fält, logga.

## Hur ML-output exponeras i UI:t

Förslag — i threat map-popup (`app/static/index.html`):

```
┌─────────────────────────────────────┐
│ IP: 8.8.8.8                         │
│ Source: Feodo Tracker               │
│ First seen: 2026-05-20              │
│ Confidence: 0.92                    │
│ ─────────── ML ─────────────        │
│ Category: ransomware (0.78)         │
│ Related CVEs: CVE-2024-12345 (high) │
└─────────────────────────────────────┘
```

För upload-detaljvyn — komplementera ClamAV-resultat med ML-bedömning:

```
Filename: report.pdf
ClamAV: clean
ML score: 0.34 (low risk)  ← ny rad
Final decision: accepted
```

## Roll-clarification

| Vad | sentinel-upload-api äger | sentinel-ml äger |
|-----|--------------------------|--------------------|
| Upload + scan + storage | ✓ | – |
| Threat-intel insamling | ✓ | – |
| ML-träning + lagring av modeller | – | ✓ |
| ML-inferens vid request | – | ✓ |
| `ml_predictions`-collection skrivning | – | ✓ |
| `ml_predictions`-collection läsning | ✓ | – |
| UI som visar ML-output | ✓ | – |
| Adversarial test-data | – | ✓ |
