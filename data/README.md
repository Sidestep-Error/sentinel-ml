# data/

Datasets för träning och utvärdering. **Inget innehåll committas** —
.gitignore blockerar allt utom denna README + `.gitkeep`.

## Nedladdning

Se [docs/data-sources.md](../docs/data-sources.md) för alla källor.

Snabb-setup:

```powershell
# Sample threat reports (skapa själv eller hämta från publik källa)
# Vi börjar med syntetisk data — se notebooks/01-baseline.ipynb när den finns.

# MITRE ATT&CK
curl -L -o data/enterprise-attack.json `
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

## Förväntad filstruktur

```
data/
├── README.md                       # denna fil
├── enterprise-attack.json          # MITRE ATT&CK (~20 MB)
├── threat_reports_sample.jsonl     # syntetiska threat reports för baseline
├── uploads_export.jsonl            # dump från sentinel-upload-api MongoDB
└── phishing_corpus/                # publik corpus (gitignored)
    └── ...
```
