# Integration Playbook: sentinel-upload-api -> sentinel-ml

Denna guide beskriver hur ni kopplar in liveflow från sentinel-ml i repo `sentinel-upload-api`.

Målbild:

- `sentinel-upload-api` skickar ett enda anrop till `POST /predict/liveflow`.
- UI kan visa ett sammanhållet resultat med upload-risk, text/IOC och CVE-relevans.
- Upload-flödet degraderar tyst om ML-tjänsten är nere.

## 1. Miljövariabler i sentinel-upload-api

Lägg till i `.env`:

```env
SENTINEL_ML_URL=http://localhost:8100
SENTINEL_ML_TIMEOUT_MS=500
SENTINEL_ML_ENABLED=true
```

## 2. Minimal klient i sentinel-upload-api

Skapa en enkel klient (exempelvis `app/services/sentinel_ml_client.py`) som anropar liveflow-endpointen.

```python
from __future__ import annotations

import httpx


class SentinelMlClient:
    def __init__(self, base_url: str, timeout_ms: int = 500) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout_ms / 1000

    async def predict_liveflow(self, payload: dict) -> dict | None:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                res = await client.post(f"{self.base_url}/predict/liveflow", json=payload)
                res.raise_for_status()
                return res.json()
        except Exception:
            # Degradera tyst i upload-flödet
            return None
```

## 3. Payload-mappning från upload-api

Bygg payload med dessa tre delar när data finns:

1. `upload`: metadata + ClamAV
2. `upload_text`: extraherad text eller raw_content
3. `cve_relevance`: SBOM-komponenter + CVE-lista (från Trivy/Syft)

Exempel:

```json
{
  "upload": {
    "upload_id": "upload-123",
    "filename": "invoice.eml",
    "content_type": "message/rfc822",
    "size_bytes": 58213,
    "scan_status": "malicious",
    "scan_engine": "clamav",
    "scan_detail": "Phishing.Email.Generic",
    "risk_score": 78,
    "source": "upload"
  },
  "upload_text": {
    "upload_id": "upload-123",
    "filename": "invoice.eml",
    "content_type": "message/rfc822",
    "scan_status": "malicious",
    "scan_engine": "clamav",
    "scan_detail": "Phishing.Email.Generic",
    "extracted_text": "Please review and login at http://evil.example",
    "source": "upload_text"
  },
  "cve_relevance": {
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
}
```

## 4. Persistens i sentinel-upload-api

Spara ML-svar i `ml_predictions` med `upload_id` som nyckel:

```json
{
  "upload_id": "upload-123",
  "ml_provider": "sentinel-ml",
  "ml_liveflow": {"...": "..."},
  "created_at": "2026-06-08T12:00:00Z"
}
```

## 5. UI-koppling (minsta demo)

Visa dessa fält i upload-detalj:

- `upload_result.prediction.label`
- `upload_result.prediction.confidence`
- `upload_text_result.iocs` (antal + lista)
- `cve_relevance_result.summary.matched_cves`

## 6. Definition of Done för integration

- Ett upload-event skickar `liveflow`-anrop och får svar.
- Fallback fungerar när sentinel-ml är nere (ingen blockering av upload).
- `ml_predictions` fylls med liveflow-svar.
- UI visar minst fyra nyckelfält från liveflow.