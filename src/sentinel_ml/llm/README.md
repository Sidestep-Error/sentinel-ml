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
- `classify_cve_relevance(cve_text, stack_summary, ...)`

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

> Note: Det kan vara värt att se över ett Docker-baserat flöde för LLM-spåret senare. Då slipper varje teammedlem installera Python-beroenden, Ollama och modeller direkt på sin egen maskin. Lokal installation är enklast just nu för snabb utveckling, men Docker kan ge mer reproducerbar demo- och onboardingmiljö.

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
- CVE/SBOM-matchning är ännu inte byggd; här finns bara LLM-lagret för relevansbedömning.
- Det finns ännu ingen persistens eller benchmarkmodul för att jämföra LLM mot TF-IDF och spaCy.

## Nästa steg

Rimlig ordning härifrån:

1. koppla in `classify_threat_report()` bakom säkert fallback-beteende i `service/api.py`
2. lås gemensamt eval-format med Roll 2
3. bygg deterministisk CVE/SBOM-matchning
4. använd `classify_cve_relevance()` som komplement där exakt matchning inte räcker
5. utöka prompt-injection-underlaget till Roll 5

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
