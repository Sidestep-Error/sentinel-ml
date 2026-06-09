# LLM-implementationen

Det här katalogen innehåller den första fungerande LLM-integrationen för `sentinel-ml`.

Målet med implementationen är att kunna använda lokal Ollama för två typer av säkerhetsrelaterad inferens:

- zero-shot-klassificering av threat reports
- relevansbedömning av CVE:er mot en given mjukvarustack

Den viktigaste designprincipen är att LLM-output aldrig får användas direkt som fri text. All output måste först parseas som JSON och valideras mot ett strikt schema.

## Vad som är byggt

### `ollama_client.py`

Ett tunt HTTP-lager ovanpå Ollamas `/api/generate`.

Ansvar:

- läsa `OLLAMA_HOST` och `OLLAMA_MODEL` från `config.py`
- skicka prompt + systemprompt + temperatur
- returnera råtexten från modellen i ett enkelt `LLMResponse`-objekt

Klienten är medvetet liten för att göra mockning enkel i tester och för att hålla backend-bytet isolerat.

### `prompts.py`

Systemprompter för:

- `CLASSIFY_THREAT_REPORT_SYSTEM`
- `CVE_RELEVANCE_SYSTEM`

De instruerar modellen att:

- svara med exakt ett JSON-objekt
- inte använda markdown
- inte följa instruktioner i själva report-texten

### `schemas.py`

Pydantic-scheman för validerad LLM-output:

- `ThreatClassificationResult`
- `CVERelevanceResult`

Scheman är strikta:

- `extra="forbid"`
- typer valideras strikt
- confidence begränsas till `0.0 .. 1.0`
- rationale måste finnas och vara rimligt kort

Det här är första skyddslagret mot prompt injection och trasig modelloutput.

### `classifier.py`

Det här är huvudlagret ovanpå klienten.

Den modulen ansvarar för att:

- sanera input lätt genom att ta bort kontrolltecken och bidi-tecken
- bygga promptar där indata ramas in som data
- anropa Ollama-klienten
- parsea modellsvaret som JSON
- validera JSON mot rätt schema
- kasta tydliga domänspecifika fel om svaret inte går att lita på

Viktiga funktioner:

- `sanitize_llm_input(text)`
- `parse_json_response(raw_text, schema)`
- `classify_threat_report(text, ...)`
- `try_classify_threat_report(text, ...)`
- `classify_cve_relevance(cve_text, stack_summary, ...)`

`try_classify_threat_report()` är avsedd för säker inkoppling i API-lagret. Den returnerar ett validerat resultat när LLM-flödet fungerar och `None` när LLM-anropet eller JSON-valideringen faller. På så sätt kan `service/api.py` använda ett enkelt fallback-kontrakt utan att bero på att modellen alltid svarar korrekt.

## Hur flödet fungerar

### Threat report

1. En threat report skickas till `classify_threat_report()`.
2. Texten saneras lätt.
3. Texten kapslas in i `<threat_report> ... </threat_report>`.
4. `OllamaClient.generate()` anropas med rätt systemprompt.
5. Modellens svar måste vara giltig JSON.
6. JSON valideras mot `ThreatClassificationResult`.
7. Om allt är korrekt returneras ett typat resultat.

Om modellen svarar med fri text, markdown, fel keys eller ogiltiga värden kastas ett tydligt fel i stället för att dålig output släpps vidare.

### CVE-relevans

1. En CVE-beskrivning och en stack-sammanfattning skickas till `classify_cve_relevance()`.
2. Båda delarna saneras lätt.
3. De ramas in i separata block:
   - `<cve_description>`
   - `<software_stack>`
4. `OllamaClient.generate()` anropas med CVE-systemprompten.
5. Modellens svar parseas och valideras mot `CVERelevanceResult`.

Det här gör att LLM-delen blir ett kontrollerat analyslager, inte en fri textgenerator som resten av systemet måste gissa sig runt.

## Säkerhetsmodell

Den här implementationen försöker inte "lösa" prompt injection helt, men den bygger in flera skydd:

- systemprompt som säger att reporten är data, inte instruktioner
- lätt inputsanering för kontrolltecken och bidi-tecken
- strikt JSON-krav
- strikt schema-validering
- tydliga fel vid parse- eller schemafel

Det betyder att ett misslyckat eller manipulerat modellutdata oftast leder till ett kontrollerat fel eller fallback, inte till att dålig output accepteras tyst.

## Tester

Det finns tester för tre nivåer:

### `tests/test_ollama_client.py`

Verifierar att klienten skickar rätt payload till Ollama.

### `tests/test_llm_classifier.py`

Verifierar bland annat:

- giltig JSON accepteras
- fri text och markdown avvisas
- fel shape avvisas
- extra keys avvisas
- ogiltig confidence avvisas
- promptbyggarna kapslar in data korrekt

### `tests/test_ollama_integration.py`

Ett markerat integrationstest som kör mot lokal Ollama om den finns tillgänglig.

Testet skippar automatiskt om Ollama inte är uppe lokalt.

## Krav för att köra lokalt

För att köra LLM-koden och testerna lokalt behöver du en virtuell miljö med projektets beroenden installerade.

> Note: Det kan vara värt att se över ett Docker-baserat flöde senare. Då slipper varje utvecklingsmiljö installera Python-beroenden, Ollama och modeller direkt lokalt. Lokal installation är enklast just nu för snabb utveckling, men Docker kan ge en mer reproducerbar demo- och onboardingmiljö.

### 1. Skapa virtuell miljö

Kör från repo-roten:

```bash
cd ~/sentinel-ml
python3 -m venv .venv
```

### 2. Installera beroenden

För LLM-spåret och testerna behövs minst `dev` och `llm` extras:

```bash
cd ~/sentinel-ml
./.venv/bin/pip install -e '.[dev,llm]'
```

### 3. Kontrollera att miljön finns

Det här kommandot ska fungera:

```bash
cd ~/sentinel-ml
./.venv/bin/python --version
```

Om du står i `tests/`-mappen behöver du i stället använda:

```bash
../.venv/bin/python --version
```

## Ollama i WSL

Integrationstestet mot riktig modell kräver att Ollama kör lokalt och att modellen `llama3.2:3b` finns nedladdad.

### 1. Installera Ollama

På Ubuntu/WSL kan Ollama installeras via den officiella installern:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Om installationen säger att `zstd` saknas:

```bash
sudo apt-get update
sudo apt-get install -y zstd
curl -fsSL https://ollama.com/install.sh | sh
```

### 2. Kontrollera att Ollama kör

```bash
ollama --version
curl http://127.0.0.1:11434/
```

Ett friskt svar från API:t är:

```text
Ollama is running
```

### 3. Ladda ner modellen

Projektets defaultmodell kommer från `OLLAMA_MODEL` i `config.py` och är:

```bash
ollama pull llama3.2:3b
```

Kontrollera sedan att modellen finns:

```bash
ollama list
```

Du bör se något i stil med:

```text
NAME           ID              SIZE
llama3.2:3b    ...             2.0 GB
```

### 4. Kör integrationstestet

```bash
cd ~/sentinel-ml
./.venv/bin/python -m pytest tests/test_ollama_integration.py
```

När allt fungerar ska testet passera. På första körningen kan det ta längre tid eftersom modellen behöver laddas in.

Exempel på grönt resultat:

```text
1 passed in 35.76s
```

## Hur man kör testerna

Använd helst `pytest`, inte `python3 test_fil.py`.

### Kör bara LLM-testerna

Från repo-roten:

```bash
cd ~/sentinel-ml
./.venv/bin/python -m pytest tests/test_ollama_client.py
./.venv/bin/python -m pytest tests/test_llm_classifier.py
./.venv/bin/python -m pytest tests/test_ollama_integration.py
```

Eller alla tre samtidigt:

```bash
cd ~/sentinel-ml
./.venv/bin/python -m pytest tests/test_ollama_client.py tests/test_llm_classifier.py tests/test_ollama_integration.py
```

### Kör alla tester i projektet

```bash
cd ~/sentinel-ml
./.venv/bin/python -m pytest -q
```

### Kör från `tests/`-mappen

Om du redan står i `~/sentinel-ml/tests`:

```bash
../.venv/bin/python -m pytest test_ollama_client.py
../.venv/bin/python -m pytest test_llm_classifier.py
../.venv/bin/python -m pytest test_ollama_integration.py
```

### Kör lint

```bash
cd ~/sentinel-ml
./.venv/bin/ruff check src tests
```

## Vanliga fel

### `ModuleNotFoundError: No module named 'httpx'`

Det betyder nästan alltid att du kör med systemets `python3` i stället för projektets `.venv`.

Använd:

```bash
cd ~/sentinel-ml
./.venv/bin/python -m pytest tests/test_ollama_client.py
```

inte:

```bash
python3 tests/test_ollama_client.py
```

### `No such file or directory: .venv/bin/python`

Det betyder oftast att:

- du står i fel mapp
- eller att `.venv` inte har skapats ännu

Om du står i `tests/` behöver du använda:

```bash
../.venv/bin/python -m pytest test_ollama_client.py
```

Om `.venv` inte finns ännu:

```bash
cd ~/sentinel-ml
python3 -m venv .venv
./.venv/bin/pip install -e '.[dev,llm]'
```

### `404 Not Found` från `/api/generate`

Om integrationstestet hittar Ollama men faller med något i stil med:

```text
httpx.HTTPStatusError: Client error '404 Not Found' for url 'http://localhost:11434/api/generate'
```

och ett direkt API-anrop visar:

```json
{"error":"model 'llama3.2:3b' not found"}
```

då kör Ollama, men modellen saknas lokalt.

Lösning:

```bash
ollama pull llama3.2:3b
ollama list
cd ~/sentinel-ml
./.venv/bin/python -m pytest tests/test_ollama_integration.py
```

### Integrationstestet blir `skipped`

Om testet blir `skipped` betyder det att testet inte kunde nå lokal Ollama på `OLLAMA_HOST`.

Kontrollera:

```bash
curl http://127.0.0.1:11434/
systemctl status ollama --no-pager
```

Om tjänsten inte kör:

```bash
sudo systemctl start ollama
```

## Begränsningar just nu

- API-lagret använder ännu inte LLM-funktionerna i `/predict/threat`.
- CVE/SBOM-matchning finns nu som en deterministisk kärna, men är ännu inte kopplad till verklig SBOM-inläsning från `sentinel-upload-api` eller Trivy-baserat upstream-flöde.
- Första planerade integrationsvägen för upload-spåret är metadata + ClamAV. Direkt textextraktion för `.txt`, `.md`, `.json`, `.csv` och `.eml` är ett senare steg om tid finns.
- Benchmarkmodulen finns nu, men jämförelsen är ännu inte helt komplett eftersom spaCy-raden fortfarande saknar resultat.

## Nästa steg

Rimlig ordning härifrån:

1. koppla ett första normaliserat metadata + ClamAV-flöde till `sentinel-ml`
2. koppla in `try_classify_threat_report()` i `service/api.py` bakom säkert fallback-beteende där textbaserad input finns
3. koppla den deterministiska CVE/SBOM-matchningen till verkligt normaliserat JSON-upstream
4. använd `classify_cve_relevance()` som komplement där exakt matchning inte räcker
5. utöka prompt-injection-underlaget med fler adversarial-fall

## Deterministisk CVE/SBOM-matchning

En första regelbaserad kärna för CVE-relevans finns i:

- `src/sentinel_ml/features/cve_relevance.py`

Den hanterar:

- normalisering av paketnamn
- matchning mellan CVE-paket och SBOM-komponenter
- versionsjämförelse via `version_range` eller `fixed_version`
- rankning per relevans, CVSS och matchstyrka

Deterministisk output används här före eventuell LLM-hjälp, så att första bedömningen förblir spårbar och testbar.

Dessutom finns nu små adaptergränssnitt för att minska beroendet till ett specifikt upstream-format:

- `sbom_components_from_normalized(...)`
- `sbom_components_from_trivy(...)`
- `sbom_components_from_syft(...)`
- `cve_records_from_normalized(...)`
- `cve_records_from_trivy(...)`

De gör bara försiktiga antaganden om vanliga fält och är tänkta som en stabil normaliseringsyta, inte som ett slutligt kontrakt mot upstream.

För write-back eller vidare API-användning finns också ett serialiserbart outputformat:

- `CVERelevancePrediction`

Det formatet innehåller sorterade `related_cves` och är tänkt att kunna användas senare vid skrivning till `ml_predictions`.

## Benchmark för zero-shot-klassificering

En första benchmarkväg finns nu för LLM zero-shot på threat reports.

Delar:

- `src/sentinel_ml/eval/llm_threat_benchmark.py`
- `scripts/eval_llm_threat_classifier.py`

Benchmarken utgår just nu från följande upplägg:

- dataset: `data/real_threat_reports.jsonl`
- labels: `ransomware`, `phishing`, `ddos`, `malware`, `intrusion`
- huvudmetrics: `Accuracy`, `Precision-macro`, `Recall-macro`, `F1-macro`

Den mäter också:

- antal giltiga LLM-svar
- antal ogiltiga LLM-svar
- genomsnittlig latency i millisekunder

### Jämförelsetabell

Den här tabellen är avsedd för direkt jämförelse mellan LLM, TF-IDF och spaCy på samma dataset och samma test split.

| Model | Accuracy | Precision-macro | Recall-macro | F1-macro | Valid outputs | Invalid outputs | Avg latency ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| TF-IDF + Logistic Regression | `0.943` | `0.955` | `0.841` | `0.875` | `N/A` | `N/A` | `TBD` |
| spaCy | `TBD` | `TBD` | `TBD` | `TBD` | `N/A` | `N/A` | `TBD` |
| LLM `llama3.2:3b` | `0.672` | `0.460` | `0.400` | `0.413` | `311` | `6` | `462.4` |

Metod för jämförelsen:

- dataset: `data/real_threat_reports.jsonl`
- test split: `20%`
- `random_state=42`
- labels: `ransomware`, `phishing`, `ddos`, `malware`, `intrusion`

Per klass för `TF-IDF + Logistic Regression`:

| Class | Precision | Recall | F1 | Test Examples |
|---|---:|---:|---:|---:|
| `ransomware` | `0.98` | `0.98` | `0.98` | `47` |
| `phishing` | `0.97` | `0.97` | `0.97` | `76` |
| `malware` | `0.93` | `0.97` | `0.95` | `139` |
| `intrusion` | `0.89` | `0.85` | `0.87` | `48` |
| `ddos` | `1.00` | `0.43` | `0.60` | `7` |

### Kör benchmarkscriptet

```bash
cd ~/sentinel-ml
./.venv/bin/python scripts/eval_llm_threat_classifier.py data/real_threat_reports.jsonl
```

Med valfri begränsning av antal exempel:

```bash
cd ~/sentinel-ml
./.venv/bin/python scripts/eval_llm_threat_classifier.py data/real_threat_reports.jsonl --limit 100
```

## Exempel på användning

```python
from sentinel_ml.llm.classifier import classify_threat_report

result = classify_threat_report(
    "Phishing campaign impersonating payroll with credential harvesting links."
)

print(result.category)
print(result.confidence)
print(result.rationale)
```

## Sammanfattning

Det som är byggt här är inte "hela LLM-funktionen" för projektet, utan ett säkert grundlager.

Det viktigaste värdet just nu är:

- lokal Ollama-integration
- strikt validerad output
- tydliga felvägar
- testbar och isolerad design

Det gör att resten av projektet kan bygga vidare på LLM-spåret utan att bli beroende av opålitlig fri text från modellen.
