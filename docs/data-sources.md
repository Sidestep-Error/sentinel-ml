# Datakällor

## Eget data (från sentinel-upload-api)

| Källa | Collection | Vad | Storlek (uppskattat) |
|-------|------------|-----|----------------------|
| MongoDB | `uploads` | Upload-metadata (hash, content-type, scan-resultat, risk score) | ~hundratals dokument |
| MongoDB | `threat_events` | GeoIP-anrikade hotevents från Feodo/URLhaus/ThreatFox | ~tusentals dokument |

**Anslutning:** `MONGODB_URI` i `.env`. Default i [config.py](../src/sentinel_ml/config.py) matchar upstream: `mongodb://localhost:27017/sentinel_upload`, database `sentinel_upload`. Använd **read-only**-användare i prod — ML-modulen ska aldrig kunna mutera produktionsdata.

### Verifierat Mongo-schema: `uploads`-collection

Verifierat 2026-06-02 mot upstream [sentinel-upload-api/app/models.py](https://github.com/Sidestep-Error/sentinel-upload-api/blob/main/app/models.py) efter merge av PR #68.

| Fält | Typ | Upstream-default | Anteckning |
|------|-----|------------------|------------|
| `_id` | ObjectId | (auto) | Injicerat av Mongo |
| `created_at` | datetime | `now(UTC)` | TTL-index, default 30 dagar |
| `filename` | str | — | Sanerat (path-traversal-skydd) |
| `sha256` | str | — | SHA256-hex, indexerat |
| `content_type` | str | — | Whitelisted (text/image/PDF/Office) |
| `size_bytes` | int (≥0) | — | Filstorlek i bytes. **Nytt fält per 2026-06-02 (upstream PR #68).** Äldre dokument saknar fältet. |
| `status` | str | `"accepted"` | `"accepted"` eller `"rejected"` |
| `decision` | str | `"accepted"` | `"accepted"` / `"review"` / `"rejected"` |
| `risk_score` | int (0-100) | `0` | Beräknas av upstream `compute_risk` |
| `risk_reasons` | list[str] | `[]` | Triggade riskregler |
| `scan_status` | str | `"clean"` | `"clean"` / `"malicious"` / `"error"` |
| `scan_engine` | str | `"mock"` | `"mock"` eller `"clamav"` |
| `scan_detail` | str | `"No signature matched"` | Scannerns rapport |
| `deduplicated` | bool | `false` | True om matchade tidigare sha256 |

[`UploadRecord` i schemas.py](../src/sentinel_ml/data/schemas.py) speglar dessa fält med optional-defaults så äldre dokument validerar utan krasch.

## Publika dataset

### Spår A (threat report-klassificering)

| Dataset | Storlek | Licens | Användning |
|---------|---------|--------|------------|
| [MITRE ATT&CK](https://attack.mitre.org/) | ~700 techniques | MIT-liknande | Labels + taxonomi |
| [AlienVault OTX](https://otx.alienvault.com/) | API-tillgång | Gratis konto | Threat reports i fritext |
| [PhishTank](https://www.phishtank.com/) | ~10k URLs/månad | Open-data | Phishing-corpus |
| [Nazario Phishing Corpus](https://monkey.org/~jose/phishing/) | ~20k emails | Forskningslicens | Phishing-textanalys |

### Spår B (upload-classifier)

| Dataset | Storlek | Licens | Användning |
|---------|---------|--------|------------|
| [EMBER 2018](https://github.com/elastic/ember) | 1.1M PE-filer (features only) | Apache 2.0 | Klassisk malware-classifier-benchmark |
| [MalwareBazaar](https://bazaar.abuse.ch/) | API-tillgång | CC0 | Metadata för verkliga samples |

## Hantering

- **Dataset committas inte.** `.gitignore` blockar `data/*` förutom `README.md`.
- **Nedladdning dokumenteras** här med exakt URL + förväntad sha256.
- **Stora dataset symlinkas** in från extern disk om de inte får plats i repo-mappen.
- **Sample-data** för CI ligger i `tests/fixtures/` (max 100 KB total).

## Nedladdningskommandon

```powershell
# MITRE ATT&CK JSON
curl -o data/enterprise-attack.json `
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

# EMBER 2018 (stort — ~10 GB komprimerat)
# Se README i https://github.com/elastic/ember för instruktioner.
```

## Datakvalitet

Innan ett dataset används för träning:

1. **Schema-validering** — varje rad parseras genom `data/schemas.py`-modeller. Trasiga rader hoppas över med räkneverk.
2. **Klassbalans-rapport** — `eval/metrics.py` skriver ut fördelning före träning.
3. **Dubblettkontroll** — sha256 på text/innehåll. Dubbletter tas bort.
4. **PII-scan** — kolla att inga e-postadresser, person-IDs eller liknande finns i fritext (utöver de som är legitima IOCs).
