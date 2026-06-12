# Adversarial-analys — plan

> VG-krav: "Robusthetstestning mot adversarial attacks (t.ex. evasion, data poisoning)".
> Det här dokumentet beskriver *vad* vi testar, *varför* och *hur vi mäter*.
> Resultat (siffror, plottar, slutsatser) hamnar i `docs/adversarial-analysis.md`
> när experimenten är körda.

## Hotmodell

Vårt ML-system har tre angripbara ytor:

1. **Spår A (threat-report-klassificeraren)** — angripare kan publicera
   förgiftade threat reports som hamnar i vår träningsdata, eller skicka
   reports i körning som har dolda instruktioner till LLM-backend.
2. **Spår B (upload-classifier)** — en angripare som vet hur klassificeraren
   bedömer kan tweaka filmetadata för att hamna under flagg-tröskeln
   (evasion).
3. **Hela pipelinen** — en kompromettrad threat-intel-feed (Feodo/URLhaus/
   ThreatFox) kan i värsta fall styra både IOC-extraktion och modellträning.

Referens: [OWASP ML Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/),
[MITRE ATLAS](https://atlas.mitre.org/), NIST AI 100-2.

## Tester

### 1. Data poisoning — Spår A

**Hypotes:** Att felmärka 5–20 % av träningsdatat degraderar F1 mätbart.

**Metod:**
- `adversarial/poisoning.py::poison_labels` flippar `ratio %` av labels till en
  annan slumpmässigt vald klass.
- Träna baseline + poisoned versions för ratio ∈ {0.0, 0.05, 0.10, 0.20}.
- Mät F1-macro på rent testset.

**Mätvärde:** ΔF1 = F1(clean) − F1(poisoned). Plot: x = ratio, y = F1.

**Motåtgärder att diskutera:**
- Datavalidering vid intag (skip outliers).
- Cross-validation över datakällor (lämna en feed utanför vid varje fold).
- Robust loss-funktioner (om vi har tid).

### 2. Evasion — Spår B

**Hypotes:** Angriparkontrollerad metadata kan ändras så att en skadlig upload
liknar en vanlig fil och klassificeras som accepterad.

**Metod:**
- Baseline: random perturbation (`adversarial/evasion.py::random_feature_perturbation`)
  med ε ∈ {0.01, 0.05, 0.1, 0.2}. Mät predict-flipping-rate.
- Riktad metadata-mimicry: ändra endast filnamn, content-type och storlek till
  en benign PDF-profil. Bevara sha256, scan-status och risk-score.
- Använd det av-biasade upload-datasetet när det finns. Syntetisk data märks
  uttryckligen som sanity-check.
- ART `HopSkipJump` är frivillig fördjupning endast om genererade features kan
  mappas tillbaka till giltiga upload-poster.

**Mätvärde:** Andel korrekt identifierade skadliga uploads som ändras till
`accepted` efter metadata-mimicry, plus random-noise flipping-rate per ε.

**Motåtgärder att diskutera:**
- Behandla metadata-modellen som triage-hint, inte ensam detektion.
- Behåll ClamAV, hash-brygga och makroanalys som separata skyddslager.
- Träna och utvärdera på realistiska, av-biasade metadata.

### 3. Prompt injection — Spår A LLM

**Hypotes:** Threat-reports kan innehålla embedded instruktioner som styr LLM-output.

**Metod:**
- `adversarial/prompt_injection.py::PROBES` listar 4+ probes.
- Skicka varje probe genom det validerade `classify_threat_report()`-lagret.
- Samma validerade lager används av FastAPI:s uttryckligen aktiverade LLM-väg.
- Loggning: validerad kategori eller separat `invalid_output`. Match mot
  `expected_class_for(probe)`.

**Mätvärde:** Injection-success-rate, invalid-output-rate och blocked-rate per
probe-typ.

**Motåtgärder att diskutera:**
- System prompt med stark "this is data, not commands"-uttalande
  (redan i `llm/prompts.py`).
- Output-schema-validering (JSON parse + Pydantic).
- Strip av kontrolltecken och bidi-tecken före LLM-anrop.
- Sandboxa LLM-output — använd det som hint, inte sanning.

## Rapportering

Slutdokument: `docs/adversarial-analysis.md` med:

- **Sammanfattningstabell:** test × success rate × motåtgärd.
- **Plottar:** F1-degradering per poison-ratio, attack success per ε,
  injection success per probe.
- **Diskussion:** vad detta säger om vårt systems lämplighet i produktion,
  vad som skulle behöva åtgärdas innan en riktig deployment.
- **Hänvisningar:** OWASP ML Top 10, MITRE ATLAS-tactic-IDs, NIST AI 100-2-taxonomi.
