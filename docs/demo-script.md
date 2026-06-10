# Demo-manus — sentinel-ml | Demo Day 16 juni 2026

**Total tid:** 12 min + 3 min buffert för frågor  
**Format:** slides + live terminal-demo  
**Backup:** video 4 min (spela in 13–14 juni mot localhost)

---

## Rollfördelning (justera efter teamet)

| Del | Tid | Talare |
|-----|-----|--------|
| Intro + problemet | 1 min | Person 1 |
| Arkitektur | 1.5 min | Person 2 |
| Live-demo (Alt 6) | 3 min | Person 3 (kör terminal) + Person 2 (kommenterar) |
| ML-resultat + jämförelser | 2 min | Person 1 |
| Adversarial-analys + Best Heist | 2 min | Person 4 |
| Begränsningar + nästa steg | 1 min | Person 2 |
| Slutsats | 0.5 min | Person 1 |
| **Totalt** | **11 min** | |

---

## Slide 1 — Titel (0:00–0:30)

**Visar:** Titelsild

> "Vi heter [namn] och det här är sentinel-ml — ett ML-baserat säkerhetslager byggt
> ovanpå sentinel-upload-api. På 12 minuter ska vi visa er hur vi klassificerar hot,
> extraherar indikatorer och attackerar vår egen modell."

---

## Slide 2 — Problemet (0:30–1:30) · Person 1

**Visar:** Problemslide

> "sentinel-upload-api tar emot filuppladdningar och kör ClamAV-skanning. Men ClamAV
> är signaturbaserat — det fångar känd malware, inte ny. Och det säger ingenting om
> varför en fil ser misstänkt ut, vad den kommunicerar med eller vilken hotaktör som
> ligger bakom."
>
> "Vi löser det med tre ML-spår: hotklassificering på CTI-rapporter, logganomalidetektion
> och filmetadata-klassificering."

---

## Slide 3 — Arkitektur (1:30–3:00) · Person 2

**Visar:** Arkitekturslide med dataflödesdiagram

> "sentinel-ml är en fristående FastAPI-service på port 8100. sentinel-upload-api
> anropar oss via HTTP med 500 millisekunder timeout och degraderar tyst om vi inte svarar —
> det påverkar aldrig uppladdningsflödet."
>
> "Vi har sex endpoints. De tre viktigaste är: predict/threat för CTI-klassificering,
> predict/log-anomaly för logganalys och predict/liveflow som aggregerar allt i ett svar.
> Modellerna laddas en gång vid uppstart och artefakterna versionshanteras med ett
> 12-teckens sha256-prefix."

---

## Demo (3:00–6:00) · Person 3 kör terminal, Person 2 kommenterar

> *[Person 3 öppnar terminalen, visar att service svarar]*

**Steg 1 — Health check (15 sek)**
```
curl https://[hetzner-url]/health
```
> "Servicen körs på Hetzner. Grön."

**Steg 2 — Phishing-klassificering (45 sek)**

Klistra in Scenario 1 från docs/demo-examples.md via curl eller Swagger.

> *[Person 2 kommenterar medan svaret visas]*
> "label: phishing, confidence 0.70. Tre IOCs extraherade automatiskt — URL, avsändar-adress
> och rapport-kontakt. Det här är Alt 6: automated threat intel."

**Steg 3 — Ransomware (30 sek)**

Klistra in Scenario 2.

> "Conti-ransomware. SHA-256-hashen och Tor-betalportalen extraherades som IOCs.
> Confidence 0.53 — lägre för att ransomware och intrusion delar vokabulär i riktig CTI-data.
> Modellen har ändå rätt klass som toppkandidat."

**Steg 4 — Logganomalidetektion (45 sek)**

```bash
curl -X POST https://[hetzner-url]/predict/log-anomaly \
  -H "Content-Type: application/json" \
  -d '{"logs": ["sshd[9999]: Failed password for root from 185.220.101.42 port 44512 ssh2",
              "sshd[9999]: Failed password for root from 185.220.101.42 port 44513 ssh2",
              "systemd[1]: Started nginx.service",
              "cron[5678]: (ubuntu) CMD (/usr/local/bin/backup.sh)"]}'
```

> "SSH brute force mot root flaggas omedelbart. Normala loggar passerar.
> Modellen är tränad på syntetisk Wazuh-data och svarar i realtid."

---

## Slide 4 — ML-resultat (6:00–8:00) · Person 1

**Visar:** F1-tabellen + metodjämförelsestabellen

> "Tre modeller, tre spår:"
>
> "Alt 6 — Threat classifier: TF-IDF plus Logistic Regression på 1 582 riktiga
> CTI-rapporter från HuggingFace. F1-macro 0.875. Ransomware och phishing nära perfekt.
> DDoS har F1 0.60 för att vi hade 36 träningsexempel av 1 582 — ett känt dataproblem,
> inte ett modellproblem."
>
> "Alt 4 — Log anomaly: TF-IDF plus IsolationForest. F1 0.37 på syntetisk data.
> Vi jämförde två metoder — textbaserad och strukturerad Wazuh-features — och valde
> textbaserad för att den inte kräver etiketter i produktion."
>
> "Alt 3 — Malware metadata: Random Forest på MalwareBazaar-metadata. F1 0.42.
> Fyra gånger bättre än slumpen, men RAT-familjerna är omöjliga att skilja utan
> beteendedata. Det är en medveten avgränsning — metadata räcker inte för familje-klassificering."

---

## Slide 5 — Adversarial-analys (8:00–10:00) · Person 4

**Visar:** Adversarial-resultatslide + Best Heist demo

> "Vi analyserade vår egen modell som en attackyta. Tre experiment:"
>
> "Data poisoning: vi felmärkte 20 procent av träningsdatat. F1 sjönk från 0.963
> till 0.807. Degraderingen är gradvis och mätbar — utan löpande monitorering av
> labelfördelningen syns attacken inte förrän modellen redan är komprometterad."
>
> "Evasion på upload-klassificeraren: uniform brusinjicering i feature-rymden
> gav noll flippade prediktioner. Random Forest är robust mot slumpmässigt feature-brus."
>
> *[Person 4 kör Best Heist-demo om tid finns]*
>
> "Det här är det verkliga adversarial-problemet för log-detektorn:
> 77 procent av attackloggarna passerar utan modifiering. Reverse shell och path traversal
> är osynliga för modellen. En angripare behöver inte en mimicry-attack — de väljer bara
> rätt attacktyp. Motåtgärden är semantisk analys via LLM, vilket är exakt varför
> vi integrerat Ollama med fallback."

---

## Slide 6 — Begränsningar + nästa steg (10:00–11:00) · Person 2

**Visar:** Begränsningsslide

> "Tre ärliga begränsningar:"
>
> "Upload-klassificeraren är tränad på syntetisk data. Den lär sig att exe-filer
> är misstänkta och pdf-filer är ok. En förkledd fil — exe omdöpt till pdf —
> passar troligen igenom. Nästa steg är Shannon-entropiberäkning direkt på filinnehållet."
>
> "Log-anomalidetektorn missar attacktyper den inte sett under träning. Nästa steg
> är riktig Wazuh-data och ett regelbaserat komplement för känd attacksyntax."
>
> "LLM-integrationen kräver en körande Ollama-instans. Vi har automatisk fallback
> till regelbaserad sammanfattning men latency på 5 till 30 sekunder är oacceptabelt
> för synkrona endpoints i produktion. Asynkron köhantering är nästa steg."

---

## Slide 7 — Slutsats (11:00–11:30) · Person 1

**Visar:** Slutsatsslide

> "Vi har byggt ett ML-säkerhetslager som faktiskt körs i produktion på Hetzner,
> integrerat med sentinel-upload-api via Kubernetes NetworkPolicy och HTTP-kontrakt.
> 104 automatiserade tester varav 8 outcome-tester som fångar modellregressioner."
>
> "Det vi är mest nöjda med: vi vet exakt var modellerna är svaga och varför.
> Det är mer värt i ett säkerhetssystem än ett F1-värde på 0.99 ni inte kan förklara."
>
> "Tack. Vi tar frågor."

---

## Frågor att ha svar klara på

**"Varför inte neural network?"**
> "TF-IDF plus Logistic Regression ger F1 0.875 med tolkbara feature-vikter och
> tränas på sekunder. En neural modell skulle kräva tio gånger mer data för marginell
> förbättring. Feature engineering slår modellkomplexitet när data är begränsad."

**"Hur säker är systemet egentligen?"**
> "ClamAV är primärförsvaret och fångar känd malware med hög precision.
> Vår ML är ett komplement för okänd malware och beteendeanalys. Ingen enskild lager
> är tillräcklig — det är defense in depth."

**"Vad händer om sentinel-ml är nere?"**
> "sentinel-upload-api degraderar tyst. 500 millisekunder timeout och om vi inte
> svarar fortsätter uppladdningsflödet normalt. Vi är aldrig en single point of failure."

**"Varför är DDoS-recall bara 0.43?"**
> "36 träningsexempel av 1 582. Det är ett datavolymproblem, inte ett modellproblem.
> Med balanserat dataset förväntar vi oss F1 nära ransomware-nivån."
