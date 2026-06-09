# LLM/CVE-översikt

Det här dokumentet är startpunkten för LLM/CVE-spåret i `sentinel-ml`.

## Syfte

Spåret täcker två områden:

1. **LLM**
   - lokal `Ollama`
   - zero-shot-klassificering
   - strikt JSON-validerad output
   - benchmark mot klassiska modeller

2. **CVE-relevans**
   - deterministisk matchning mellan `SBOM` och `CVE`
   - stöd för normaliserad JSON
   - stöd för `Trivy`-liknande input
   - serialiserbar output för vidare integration

## Viktigaste beslut

- `LLM` körs lokalt via `Ollama`
- `LLM` är inte primär live-klassificering
- första liveflödet är `metadata + ClamAV + klassisk modell`
- `LLM` används främst offline för benchmark, analys och rapport
- normaliserat JSON är låst som upstream-format
- `Trivy` stöds som adapterväg i CVE-spåret

## Status

Det som är byggt:

- `ollama_client.py`, `prompts.py`, `schemas.py`, `classifier.py`
- strikt JSON-parse och schema-validering för LLM-output
- zero-shot-benchmark för threat reports
- deterministisk CVE/SBOM-kärna
- API-endpoints för:
  - `POST /predict/liveflow-writeback`
  - `POST /predict/cve-relevance`
  - `POST /predict/cve-relevance-prediction`
  - `POST /predict/cve-relevance-trivy`

## Live och offline

### Live nu

- upload-metadata + `ClamAV`
- klassisk upload-modell
- write-back till `ml_predictions`
- deterministisk CVE-relevans via API

### Offline nu

- LLM zero-shot
- LLM-jämförelse mot `TF-IDF`
- vidare LLM-analys
- prompt-injection-underlag för adversarial-spåret

## Benchmarkläge

| Modell | Accuracy | F1-macro | Precision-macro | Recall-macro |
|---|---:|---:|---:|---:|
| `TF-IDF + Logistic Regression` | `0.943` | `0.875` | `0.955` | `0.841` |
| `LLM zero-shot (llama3.2:3b)` | `0.672` | `0.413` | `0.460` | `0.400` |

Övrigt:

- LLM-latens: cirka `462 ms`
- ogiltiga JSON-svar: `6` av `317`

Slutsats:

- klassisk modell är förstahandsval i liveflödet
- LLM behålls som benchmark- och analysspår

## Läs vidare

- [Teknisk LLM-dokumentation](/home/viktor/sentinel-ml/docs/llm-technical-reference.md)
- [LLM/CVE-integrationsguide](/home/viktor/sentinel-ml/docs/llm-cve-integration-guide.md)
