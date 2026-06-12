# Office-makroförsvaret — innehållsanalys som berikad metadata

> Underlag för rapport och demo. Dokumenterar varför metadata-ML inte kan
> fånga makro-malware, hur trelagersförsvaret är byggt, var innehålls-
> analysen sker (och varför just där), samt bedömningen av oletools som
> säkerhetskritiskt beroende.
>
> Kod: sentinel-ml PR #62 (`macro_risk`-regeln) + sentinel-upload-api PR #81
> (olevba-extraktionen). Relaterat: hash-bryggan (PR #59),
> [upload-classifier-honest-training.md](upload-classifier-honest-training.md).

---

## Bakgrund: incidenten som visade luckan

Ett känt malware-sampel från MalwareBazaar (.xls med makro-malware) laddades
upp i prod och passerade alla tre kontrollager:

| Lager | Resultat | Varför det missade |
|-------|----------|--------------------|
| ClamAV | "No signature matched" | Signaturbaserad — blind för sampel utan signatur |
| Threat intel (hash-bryggan) | "Ingen träff" | Hash-setet var tomt i prod (fixat i PR #59) |
| ML-score (upload-classifier) | accepted (0.78) | Modellen ser bara metadata — **smittade Office-filer har samma metadata som friska** |

Den sista raden är kärninsikten: en .xls med ett skadligt makro har samma
storlek, content-type och filnamnsform som en frisk .xls. Ingen modell
tränad på enbart metadata kan skilja dem åt — det är inte en svag modell,
det är en informationsteoretisk gräns. Ska makro-malware fångas måste någon
titta *i* filen.

## Grundprincip: features måste finnas vid prediktion, inte bara träning

En modell kan bara använda de signaler den får när den körs live — inte de
den såg under träning. Att träna en modell på innehålls-features medan
servern bara skickar metadata vid prediktion (s.k. *train/serve skew*) ger
en modell som aldrig kan använda det den lärt sig. Därför börjar
innehållsförsvaret inte i modellen utan i *dataflödet*: innehålls-features
måste extraheras vid uppladdning och följa med hela vägen.

## Var innehållsanalysen sker — och varför just där

**sentinel-upload-api läser redan filens bytes** — ClamAV scannar innehållet
och SHA-256 beräknas på det. Regeln "vi läser bara metadata" gäller
sentinel-ml, inte upload-API:t. Alltså:

- Extraktionen (oletools/olevba) körs i upload-API:t, på samma ställe som
  ClamAV-scannen.
- Resultatet — `has_macros` + räknare för autoexec-triggers, suspicious
  keywords och IOC:er — sparas som **berikad metadata** i `uploads` och
  skickas till sentinel-ml i ingest-anropet.
- **Filinnehåll passerar aldrig tjänstegränsen.** sentinel-ml får bara
  aggregerade räknare; makro-källkod loggas eller lagras aldrig någonstans.
  Säkerhetsgränsen från arkitekturen är intakt.

## Trelagersförsvaret

| Lager | Fångar | Karaktär |
|-------|--------|----------|
| 1. Hash-bryggan | **Känt** malware (exakt sha256-träff mot threat intel + MalwareBazaar) | Deterministisk, noll falsklarm, extern bevisning |
| 2. Makro-regeln | **Okänt** makro-malware på dess beteendeform | Deterministisk, transparent, citerbar motivering |
| 3. Metadata-ML | Statistiskt avvikande filer | Svag triage-hint (medvetet ärliga ~0.78) |

Makro-regeln (samma trösklar i upload-API:ts `compute_risk` och
sentinel-ml:s `macro_risk` — håll dem i synk):

- Autoexec-trigger (AutoOpen/Workbook_Open/...) **+** suspicious keyword
  (Shell, CreateObject, URLDownload...) ⇒ risk 75, **rejected**.
  Det är den klassiska makro-malware-formen: kod som kör vid öppning och
  når utanför dokumentet.
- ≥3 suspicious keywords utan trigger ⇒ 60, review.
- Enbart makron ⇒ 30, review.

## Designval: regel, inte tränad modell (än)

Vi valde medvetet en deterministisk regel i stället för att träna om
upload-classifiern med makro-kolumner:

1. **Vi har ingen ärlig träningsdata med innehålls-features.** Vi laddar
   aldrig ner binärer — bara MalwareBazaar-metadata, som inte innehåller
   makro-information. Att syntetisera makro-kolumner och träna på dem vore
   samma metrik-uppblåsning som
   [upload-classifier-honest-training.md](upload-classifier-honest-training.md)
   dokumenterar emot.
2. **Regeln är transparent och citerbar** — varje flaggning kommer med en
   motivering som kan försvaras i både UI och rapport.
3. **Vägen till en tränad modell är förberedd:** från och med PR #81
   ackumuleras riktiga makro-rader i `uploads`-collectionen. När tillräckligt
   med verklig data finns kan upload-classifiern tränas om med
   makro-kolumnerna tillagda i feature-kontraktet — på riktig data, inte
   syntetisk. Tills dess är modellens 9-feature-kontrakt orört.

## Beroendebedömning: oletools

oletools valdes för extraktionen. Senaste PyPI-release (0.60.2) är från
juli 2024, vilket väcker den rimliga frågan om beroendet är för gammalt för
ett säkerhetskritiskt syfte. Bedömningen (verifierad mot PyPI och GitHub
2026-06-12) är att det är acceptabelt, av fyra skäl:

1. **Långsam release-takt ≠ övergivet projekt.** Repot hade senaste push
   2026-02-14, och en commit i januari 2026 lade till detektering kopplad
   till CVE-2026-21509 — underhållaren följer aktivt nya Office-hot.
   En changelog för kommande 0.60.3 finns i master.
2. **Formaten som parsas är frysta.** OLE2/CFB-formatet är från 90-talet och
   VBA-projektformatet har inte ändrats på decennier; Microsoft blockerar
   dessutom internet-makron som standard sedan 2022. En parser för ett fryst
   format ruttnar inte som t.ex. ett TLS-bibliotek — det finns lite att
   releasa.
3. **Attackytan är liten.** oletools är ren Python — ingen native-kod,
   alltså ingen minneskorruptions-klass av sårbarheter vid parsning av
   fientliga filer. Biblioteket *kör* aldrig makron (ren statisk analys).
   Värsta fallet är parser-fel, som fångas och degraderar till "ingen
   makro-data" utan att uppladdningsflödet påverkas; indata är dessutom
   begränsad till 10 MB.
4. **Vakten är systematisk, inte en engångsbedömning.** `pip-audit` körs i
   CI på varje PR och push — publiceras en CVE mot oletools går bygget rött.
   Vi behöver inte själva bevaka beroendet manuellt.

Att pinna mot git master i stället för PyPI-releasen avfärdades: det skulle
byta reproducerbara builds mot ogranskade commits. Det enda som teoretiskt
åldras i releasen är nyckelords-listorna (detektionskvalitet, inte
säkerhetsrisk), och även de uppdateras aktivt i master.

## Fallgrop värd att dokumentera: olevbas Text-fallback

Vid implementationen upptäcktes att olevba faller tillbaka till "Text"-läge
för bytes den inte kan parsa som Office-container — och då behandlar **hela
innehållet som makro-källkod**, vilket rapporterar `has_macros=True` för
varje trasig eller förklädd fil. Utan hantering hade varje oparsebar
uppladdning felmärkts som makro-bärande. Extraktionen exkluderar därför
Text-läget (returnerar "ingen makro-data"), och ett regressionstest låser
beteendet. Ett bra exempel på varför empirisk verifiering av
tredjepartsbibliotek på fientlig indata hör till bygget, inte till
efterarbetet.
