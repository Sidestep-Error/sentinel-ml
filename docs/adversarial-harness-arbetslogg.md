# Arbetslogg — adversarial-harness

## Syfte

Den här filen dokumenterar arbetet med projektets adversarial-harness.
För varje genomfört arbetsmoment beskriver vi:

- **Vad** som har gjorts.
- **Varför** arbetet behövdes.
- **Resultat** från implementation och verifiering.
- **Nästa steg** när arbete återstår.

Arbetsloggen används för poisoning-, evasion- och prompt-injection-spåren
samt relaterade ändringar i projektets tekniska rapport och säkerhetsanalys.

---

## 2026-06-09 — Arbetsloggen skapades

### Vad

Skapade `docs/adversarial-harness-arbetslogg.md` som gemensam arbetslogg för
det fortsatta arbetet med adversarial-harnessen.

### Varför

Arbetet behöver ett samlat dokument som förklarar både genomförda ändringar
och motiveringen bakom dem. Det gör implementationen, experimenten och
resultaten enklare att följa, granska och använda i slutrapporten.

### Resultat

Arbetsloggen är skapad och redo att fyllas på löpande under projektets
fortsatta arbete.

### Nästa steg

Kartlägg och prioritera kvarvarande arbete för data poisoning, evasion med
ART HopSkipJump och prompt injection.

---

## 2026-06-09 — Omvärdering efter senaste GitHub-uppdateringen

### Vad

Hämtade senaste `main` från GitHub och granskade commit
`6bfbde0` (`LLM/CVE integration groundwork (#46)`).

Uppdateringen tillför bland annat:

- Ett modellagnostiskt LLM-klassificeringslager i
  `src/sentinel_ml/llm/classifier.py`.
- Sanering av kontrolltecken och bidi-tecken före LLM-anrop.
- Strikt JSON- och Pydantic-validering av LLM-output.
- En LLM-benchmark för threat report-klassificering.
- Ett integrationstest som körs mot lokal Ollama när tjänsten finns.
- En mer robust deterministisk CVE/SBOM-matchning med versionshantering.

Alla Python-filer kompilerades efter uppdateringen och Git-repot är synkat
med `origin/main`.

### Varför

Arbetsordningen behövde omvärderas eftersom den nya LLM-implementationen
ger adversarial-harnessen en stabil och testbar anropsyta. Prompt injection
kan nu testas modellagnostiskt med en stub-klient innan riktiga experiment
körs mot Ollama.

Roadmapen anger dessutom prompt-injection-testet som ett direkt nästa steg
för 11–12 juni, medan data poisoning redan har resultat och evasion redan
har en fungerande slumpbrus-baseline.

### Resultat

Första prioritet ändras från ART HopSkipJump till en reproducerbar
prompt-injection-harness.

Den nya harnessen bör:

1. Köra alla befintliga `PROBES` genom `classify_threat_report()`.
2. Mäta korrekt klassificering, lyckad injection och ogiltig output separat.
3. Testa sanering av bidi- och kontrolltecken.
4. Fungera med stub-klient i enhetstester och riktig Ollama vid experiment.
5. Generera resultat som kan skrivas direkt till adversarial-analysen.

En viktig upptäckt är att FastAPI-tjänstens äldre `_call_ollama()` fortfarande
anropar `OllamaClient` direkt och inte använder det nya validerade
klassificeringslagret. Harnessen bör därför först testa den nya avsedda
säkerhetsvägen och därefter användas för att verifiera API-integrationen när
den kopplas om.

### Nästa steg

Implementera den modellagnostiska prompt-injection-harnessen och dess
enhetstester. Därefter körs den mot lokal Ollama och resultaten dokumenteras.
ART HopSkipJump blir nästa större arbetspaket efter prompt injection.

---

## 2026-06-09 — Modellagnostisk prompt-injection-harness

### Vad

Implementerade en modellagnostisk harness i
`src/sentinel_ml/adversarial/prompt_injection.py` som kör enskilda eller
samtliga prompt-injection-prober genom det validerade LLM-klassificeringslagret.

Varje probe får nu ett av tre separata resultat:

- `blocked` när rätt hotklass returneras trots attacken.
- `injection_success` när attacken styr modellen till fel hotklass.
- `invalid_output` när modellens svar inte klarar JSON- eller schemavalidering.

Experiment-scriptet använder harnessen och rapporterar separata värden för
blocked-rate, injection-success-rate och invalid-output-rate. Fokuserade
enhetstester har lagts till för resultatklassificering, aggregerade mätvärden,
tomma probe-listor, bidi-sanering och transportfel.

### Varför

En felaktig hotklass och ett svar som inte kan parsas är två olika
säkerhetsutfall och behöver mätas separat. Den modellagnostiska klientytan gör
det också möjligt att testa beteendet deterministiskt med stubbar utan att
kräva en körande Ollama-instans, samtidigt som samma harness kan användas för
lokala experiment mot Ollama.

### Resultat

Python-källkod, script och tester klarar statisk kompilering med
`python3 -m compileall`. Ändringarna klarar även `git diff --check`.

Arbetet har synkroniserats ovanpå senaste `origin/main` på commit `cb06785`
utan konflikter. Den uppdateringen innehåller bland annat en import-säkerhetsfix
för produktion och en uppdaterad teknisk rapport.

Enhetstesterna har skapats men kunde inte köras i den aktuella miljön eftersom
`pytest` inte är installerat. Lintkontrollen kunde av samma skäl inte köras
eftersom `ruff` saknas. Ett verkligt prompt-injection-experiment mot lokal
Ollama har därför inte heller körts ännu.

### Nästa steg

Kör enhetstesterna i projektets utvecklingsmiljö och kör därefter
`scripts/run_adversarial_experiments.py` mot lokal Ollama. Dokumentera de
verkliga mätvärdena i adversarial-analysen innan arbetet fortsätter med ART
HopSkipJump.
