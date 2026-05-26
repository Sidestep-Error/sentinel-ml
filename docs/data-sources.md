# Datakällor

## Eget data (från sentinel-upload-api)

| Källa | Collection | Vad | Storlek (uppskattat) |
|-------|------------|-----|----------------------|
| MongoDB | `uploads` | Upload-metadata (hash, content-type, scan-resultat, risk score) | ~hundratals dokument |
| MongoDB | `threat_events` | GeoIP-anrikade hotevents från Feodo/URLhaus/ThreatFox | ~tusentals dokument |

**Anslutning:** `MONGODB_URI` i `.env`. Använd **read-only**-användare där möjligt — ML-modulen ska aldrig kunna mutera produktionsdata.

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
