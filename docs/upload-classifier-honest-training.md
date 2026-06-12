# Upload-classifier: ärlig träning och dess gränser

> Syfte: dokumentera *hur* vi tränar upload-classifiern, *varför* vi valde att
> medvetet sänka dess siffror, och vad den faktiskt kan och inte kan. Slutsatsen
> är att metadata-only är en **svag, gameable triage-signal — inte robust
> malware-detektion**, och att vi hellre redovisar det ärligt än visar en
> uppblåst metrik.

## TL;DR

| Datauppsättning | Accuracy | Recall (malware) | Medel-confidence | Vad siffran döljer/visar |
|---|---|---|---|---|
| Trivial syntetisk (clean=office, malware=exe) | 1.000 | ~1.00 | ~0.98 | Trivialt separerbart på filtyp — säger inget om verklig förmåga |
| Riktig MalwareBazaar + kalibrering | 0.995 | 0.995 | 0.994 | **Artefakt:** modellen fuskar på MalwareBazaar:s AV-omdöpta filnamn |
| **Av-bias:ad (realistiska malware-namn)** | **0.784** | **0.681** | **0.794** | **Ärlig:** missar ~1/3 av förklädd malware; signalen är size+ändelse |

Vi deployar/redovisar den **av-bias:ade, kalibrerade** modellen. De lägre
siffrorna är poängen: de är sanna.

## Bakgrund — vad upload-classifiern är (och inte är)

Upload-classifiern är tänkt som ett **komplement till ClamAV**: flagga
uppladdningar som ser statistiskt avvikande ut på *metadata*, även när ingen
virussignatur matchar. Den ser bara metadata:

`size_bytes`, `filename`, `content_type`, `extension`, `scan_status`, `risk_score`.

Den ser **aldrig filens innehåll**. Det är ett medvetet val (vi laddar inte ner
binärer — säkerhet och scope), men det sätter en hård gräns för vad som är möjligt.

## Resan — tre steg och vad vi lärde oss

### 1. Trivial syntetisk data → F1 = 1.00 (oärligt)
Första modellen tränades på syntetisk clean (pdf/office/bild) vs syntetisk
malware (exe/dll). De är trivialt separerbara på filtyp → F1 = 1.00 och
confidence 0.96–1.00 på allt. En sådan siffra säger ingenting om verklig
förmåga — den mäter bara hur olika vi gjorde de två syntetiska klasserna.

### 2. Riktig MalwareBazaar-data + kalibrering → fortfarande 0.995 (artefakt)
Vi hämtade **923 riktiga malware-samples** (metadata, CC0, inga binärer) från
MalwareBazaar — mest skadliga **Office-filer** (`.xlsx/.doc/.rtf/...`), vilket ger
en naturlig överlapp med clean office-filer. Vi la även till kalibrering
(`CalibratedClassifierCV`).

Resultatet blev ändå **0.995**. Feature importance avslöjade varför:

```
filename_digit_ratio   0.33
filename_length        0.31
extension_in_allowlist 0.29
size_bytes_log         0.05
scan_status_*          0.00   <- noll signal (båda klasser är ClamAV-"clean" by design)
risk_score             0.00
```

Modellen lärde sig **filnamns-artefakten**: MalwareBazaar döper om sina prover
med AV-prefix (`SecuriteInfo.com.W97M.Keylog…`), medan vår syntetiska clean-data
har prydliga namn (`budget_4821.xlsx`). Det är inte "skadlighet" — det är hur de
två datakällorna råkar namnge filer. En modell som "fuskar" så generaliserar inte.

### 3. Av-bias → ärliga 0.78 / recall 0.68
Vi neutraliserade artefakten (`generate_upload_training_data.py
--realistic-malware-names`): malware får ett vardagligt namn + sin *riktiga*
ändelse (t.ex. `report_8842.xlsx`). Det simulerar dessutom det realistiska hotet —
**en angripare som döper sin malware som en vanlig fil**.

Då blev resultatet ärligt:

```
              precision  recall  f1-score  support
  accepted      0.749    0.880    0.809      200
  rejected      0.840    0.681    0.752      185
  accuracy                        0.784      385
Brier (rejected): 0.144     Medel-confidence: 0.794
```

Modellen **missar ~32% av malware** (de förklädda Office-filerna, som nu är
metadata-omöjliga att skilja från clean office). Den fångar främst det uppenbara
(exe/elf med fel ändelse, ovanliga storlekar). Kvarvarande signal: `size_bytes`
(0.59) + `extension` (0.28) — **båda styr angriparen själv**.

## Varför vi väljer den lägre siffran

1. **Ärlighet över metrik.** 0.995 var en artefakt; 0.78 är sant. Att redovisa
   det sanna är hela poängen med en säkerhetsanalys.
2. **Kalibrerade sannolikheter.** Confidence är nu en ärlig sannolikhet (Brier
   0.14, spridd kring 0.79) i stället för 1.00 på allt — UI:t och ev. nedströms-
   beslut blir trovärdiga.
3. **Speglar det verkliga hotet.** Realistiska malware-namn = angriparen döper om
   filen. Modellen ska mätas mot det, inte mot en AV-prefix-artefakt.

## Den fundamentala gränsen — varför detta *inte* kan bli robust

Alla features är **angriparkontrollerade** (filnamn, ändelse, content-type,
storlek), och `scan_status`/`risk_score` bär noll signal (båda klasser är
ClamAV-clean per definition). Robust malware-detektion kräver filens *innehåll*
(signaturer, PE-struktur, entropi, imports, sandbox) — det gör **ClamAV**, och
det har vi medvetet inte i ML-lagret. Metadata-only är därför till sin natur en
**svag, gameable hint** — inte detektion.

## Var robustheten faktiskt finns

I systemets helhet kommer den robusta detektionen från:

- **ClamAV** — signaturbaserad analys av innehållet.
- **Hash-bryggan** — exakt `sha256`-match mot kända skadliga hashar. Ogameable
  (annat än genom att ändra filen, vilket ger en ny, icke-känd hash).

Upload-classifiern är den **mjuka komplementsignalen** ovanpå dessa: en
probabilistisk triage-hint, redovisad med ärlig konfidens och kända gränser.

## Reproducerbarhet

```bash
# 1. Riktig malware-metadata (körs i CI så API-nyckeln stannar i GitHub Secrets;
#    CC0, inga binärer). Lokalt: kräver MALWAREBAZAAR_API_KEY i .env.
#    Se .github/workflows/fetch-malware-data.yml -> ladda ner artifact till data/
# 2. Bygg av-bias:ad träningsdata (realistiska malware-namn):
python scripts/generate_upload_training_data.py --realistic-malware-names
# 3. Träna kalibrerat + ärlig utvärdering:
python scripts/train_upload_calibrated.py
```

Modellen är API-kompatibel (`predict_proba` + `classes_`, samma 9 features via
`build_feature_matrix`) och kan deployas som vanligt (se
`runbooks/sentinel-ml-load-models.md`).

## Koppling till rapporten

Det här är en stark VG-poäng: den visar förståelse för ML:ens gränser, för
adversarial gameability (knyter till Spår C), och för varför säkerhet byggs i
lager — ClamAV + hash-brygga + en *ärligt redovisad* ML-hint, inte en
övertroende svart låda.
