# Arkitektur för integration mellan sentinel-ml och sentinel-upload-api

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
| POST | `/predict/upload-ingest` | Upload+ClamAV payload | `{upload_id, source, prediction, model_version, ...}` |
| POST | `/predict/cve-relevance` | SBOM/CVE payload | `{results, summary}` med relevansscore per CVE |
| POST | `/predict/cve-relevance-prediction` | SBOM/CVE payload | `{source, related_cves}` för serialiserbar deterministisk output |
| POST | `/predict/cve-relevance-trivy` | Trivy SBOM + vulnerability payload | `{source, related_cves}` via Trivy-adapter |
| POST | `/predict/upload-text-ingest` | Upload+text payload | `{upload_id, source, prediction, iocs, extracted_text, text_truncated, ...}` |
| POST | `/predict/liveflow` | Kombinerad payload | `{upload_result, upload_text_result, cve_relevance_result, summary}` |
| POST | `/predict/liveflow-document` | Kombinerad payload | `{upload_id, ml_provider, ml_liveflow, created_at}` |
| POST | `/predict/liveflow-writeback` | Kombinerad payload | `{persisted, collection, document}` |

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

## Kontraktsförslag för demo-flöde (2026-06-08)

För att minimera integrationsrisk används följande payload-kontrakt mellan
upload/scan, ML och LLM-delarna.

### 1) Upload + ClamAV -> ML/LLM ingress

```json
{
  "upload_id": "upload-123",
  "filename": "invoice.eml",
  "content_type": "message/rfc822",
  "size_bytes": 58213,
  "scan_status": "malicious",
  "scan_engine": "clamav",
  "scan_detail": "Phishing.Email.Generic",
  "risk_score": 78,
  "source": "upload"
}
```

Syfte:

- Första AI/ML-flöde med låg integrationskostnad.
- Kan användas direkt för metadata-baserad klassificering och prioritering.

### 2) Upload + extraherad text -> LLM/IOC

```json
{
  "upload_id": "upload-123",
  "filename": "invoice.eml",
  "content_type": "message/rfc822",
  "scan_status": "malicious",
  "scan_engine": "clamav",
  "scan_detail": "Phishing.Email.Generic",
  "extracted_text": "Please review the attached payroll update and log in here...",
  "source": "upload_text"
}
```

Syfte:

- Underlag för IOC-extraktion och LLM-analys i samma request-kontext.
- Kräver parsersteg för .txt/.md/.json/.csv/.eml innan anrop.

Implementerat API-stöd:

- `/predict/upload-text-ingest` accepterar antingen färdig `extracted_text` eller `raw_content`.
- Vid `raw_content` sker typstyrd extraktion för `.txt`, `.md`, `.json`, `.csv`, `.eml`.
- Säkerhetsräcken: kontrollteckensrensning, max inlängd och truncering (`text_truncated`).

### 3) SBOM/CVE -> CVE-relevans

```json
{
  "sbom_components": [
    {
      "name": "openssl",
      "version": "3.0.7",
      "ecosystem": "debian",
      "purl": "pkg:deb/debian/openssl@3.0.7",
      "cpe": "cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*"
    }
  ],
  "cves": [
    {
      "cve_id": "CVE-2024-12345",
      "summary": "OpenSSL vulnerability affecting versions before 3.0.8",
      "cvss_score": 8.8,
      "severity": "high",
      "affected_packages": [
        {
          "name": "openssl",
          "ecosystem": "debian",
          "fixed_version": "3.0.8"
        }
      ]
    }
  ]
}
```

Syfte:

- Knyta Trivy/SBOM-data till CVE-relevansgradering i threat-flödet.
- Låg modellrisk, hög nytta för operativ prioritering.

Förväntad respons från `/predict/cve-relevance`:

- `results[]`: en rad per CVE med `relevance_score`, `matched_components` och kort `reason`.
- `summary`: antal matchade CVE och antal high/critical som matchar er SBOM.

För serialiserbar output som är lätt att skriva vidare till `ml_predictions` finns också:

- `POST /predict/cve-relevance-prediction`

För Trivy-baserat upstream utan separat normalisering i upload-sidan finns:

- `POST /predict/cve-relevance-trivy`

Den endpointen använder befintliga adaptrar för:

- `Results[].Packages` i Trivy SBOM-liknande data
- `Results[].Vulnerabilities` i Trivy vulnerability-liknande data

### Rekommenderad implementationsordning

1. Upload + ClamAV -> ML
2. SBOM/CVE -> relevans
3. Upload text -> LLM/IOC
4. Slå ihop allt i ett enhetligt liveflöde i UI

Implementerat API-stöd för steg 4 (backend-aggregator):

- `/predict/liveflow` accepterar valfria delobjekt: `upload`, `upload_text`, `cve_relevance`.
- Returnerar delresultat per flöde + en `summary` med indikatorer (`has_*`) samt nyckeltal (`ioc_count`, `matched_cves`).
- Gör det enkelt för UI att rendera ett sammanhållet demoresultat från en enda request.
- `/predict/liveflow-document` returnerar samma innehåll inbäddat i ett write-back-färdigt dokument för `ml_predictions`.
- `/predict/liveflow-writeback` gör samma sak och skriver dessutom dokumentet direkt till `ml_predictions`.
