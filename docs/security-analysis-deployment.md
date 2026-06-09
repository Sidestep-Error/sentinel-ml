# Säkerhetsanalys — sentinel-ml deploy

> Hot-modell, RBAC-resonemang och known follow-ups för sentinel-ml:s
> Hetzner k3s-deploy. Tänkt som referensmaterial för slutrapporten.

## Sammanfattning

sentinel-ml deployas som en **intern-only microservice** i `sentinel`-
namespacet. Ingen publik URL, ingen direkt internetåtkomst inåt. All
trafik filtreras via NetworkPolicy så att bara sentinel-upload-api:s
pods kan ringa servicen. Containern kör som non-root med read-only
filesystem och alla Linux-capabilities droppade.

## Hotmodell (STRIDE-snabbtitt)

| Hot | Yta | Mitigering |
|-----|-----|------------|
| **S — Spoofing** | Klient som låtsas vara upload-api | NetworkPolicy `podSelector` matchar bara label `app.kubernetes.io/name: sentinel-upload-api`. Pods utanför namespace eller utan rätt label blockeras. |
| **T — Tampering** | Modifierad container-image | Image hämtas från Docker Hub med `imagePullPolicy: Always`. CI taggar både `:main` och `:<sha>` så vi kan pinna en specifik commit vid behov. Trivy-scan i CI fångar HIGH/CRITICAL CVEs (PR B). Image signing med Cosign är planerad. |
| **R — Repudiation** | Glömma vem som deployade | CI deploys är auditbara via GitHub Actions-loggar. `ci-deploy`-SA-tokenen används bara av CI; manuell deploy kräver admin-kubeconfig. |
| **I — Information disclosure** | Mongo-credentials i klartext | `MONGODB_URI` lagras i `sentinel-ml-secrets` (Kubernetes Secret, namespace-scoped). Inte i ConfigMap. Värdet exponeras aldrig i Git eller CI-loggar. |
| **D — Denial of service** | Resurs-utmattning | `resources.limits` sätter hård gräns (`1Gi` memory, `1` CPU). OOM-killer skyddar noden från att gå ned. `livenessProbe` triggar omstart om servicen hänger. |
| **E — Elevation of privilege** | Container-escape | `runAsNonRoot: true`, `runAsUser: 10001`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`. Pod-Security Standards "restricted"-nivå uppfyllt. |

## Network exposure

```
internet
   │
   │ TLS 443 (cert-manager + Let's Encrypt)
   ▼
ingress-nginx
   │
   ▼
sentinel-upload-api:8000  ◄─── PUBLIK FRONT
   │
   │ HTTP 8100 (internal, NetworkPolicy-skyddad)
   ▼
sentinel-ml:80 → :8100   ◄─── INTERN-ONLY
   │
   │ TCP 27017 (egress, TLS i Atlas-fallet)
   ▼
MongoDB Atlas
```

**Egress-policy tillåter:**
- DNS (port 53, UDP+TCP) inom klustret
- Mongo (port 27017) till 0.0.0.0/0 — krävs för Atlas
- HTTPS (port 443) till 0.0.0.0/0 — för Atlas TLS-handshake och ev. ML-feeds

**Egress nekas:**
- All annan trafik. Container kan inte t.ex. ringa `evil.example.com:80`
  om någon lyckas injicera kod.

## RBAC

`ci-deploy` ServiceAccount (Terraform-skapad i sentinel-upload-api repot):

```
Role: ci-deploy-role
  apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch", "patch", "update"]
  namespace: sentinel
```

**Vad SA:n kan göra:**
- Trigga `kubectl rollout restart` på vilken deployment som helst i `sentinel`-ns
- Läsa deployment-status

**Vad SA:n inte kan göra:**
- Skapa eller ta bort deployments
- Läsa Secrets eller ConfigMaps
- Röra resurser i andra namespaces
- Skapa pods, services, ingresses

Detta är medvetet "blast radius = en rolling restart". Vid läckt token
kan en angripare bara orsaka tillfällig DoS via repeated restarts —
inte exfiltrera data eller köra egen kod.

## Container security posture

Alla OPA Gatekeeper-policies från sentinel-upload-api-klustret enforced:

- ✅ `k8sdisallowlatesttag` — deployment refererar `:main`, inte `:latest`
- ✅ `k8srequiredlabels` — `app.kubernetes.io/name` + `part-of` på alla resurser
- ✅ `k8srequirereadonlyrootfs` — `readOnlyRootFilesystem: true`
- ✅ `k8srequireresourcelimits` — requests + limits satta
- ✅ `k8srequirerunasnonroot` — `runAsNonRoot: true`, `runAsUser: 10001`

Pod-Security Standards-nivå: **restricted** (strängaste).

## Known follow-ups

### 1. Verifiera Mongo-användarens privilegier (medium prioritet)

sentinel-ml har **egna MongoDB-credentials** (separata från upload-api),
lagrade som GitHub Secret (`MONGODB_URI`) i sentinel-ml-repot och
applicerade via `k8s/base/secret.yaml` på Hetzner. Det ger redan
isolation: en kompromiss av sentinel-ml-pod:en kan inte använda
upload-api:s kreds (eller tvärtom).

**Att verifiera:** är användaren read-only mot `uploads`- och
`threat_events`-collections, plus `readWrite` på en separat
`ml_predictions`-collection? Om kredsen idag har bredare access —
strama åt. Då har vi minimum-privilegium även på Mongo-nivå
(utöver nätverks-nivå via NetworkPolicy).

### 2. Image signing med Cosign (låg prioritet)

upload-api har Cosign i sin roadmap (`cosign.pub` finns i repot). När
det implementeras där, replikera mönstret för sentinel-ml.

### 3. Secret rotation (låg prioritet)

`MONGODB_URI` byts manuellt idag. För kursprojekt tillräckligt. För
produktion: External Secrets Operator + Vault eller liknande.

### 4. ml_predictions-collection write-back (Fas 2)

När modellerna börjar producera predictions ska de skrivas till en
separat collection enligt [integration-doc](sentinel-ml-upload-api-integration-architecture.md).
Hot: race conditions, oavsiktlig skrivning till `uploads`-collection.
Mitigering: explicit collection-namn i loader-kod, integration-test som
verifierar att vi bara skriver till `ml_predictions`.

### 5. Adversarial test-data isolering (Fas 2)

Spår C kommer producera adversarial samples. Dessa **får inte** läcka
till `uploads`-collection eller orsaka feedback-loops om modellen
retraineras på Mongo-data. Mitigering: alla adversarial-skript läser
från lokal JSONL, skriver till `data/adversarial/`, aldrig till Mongo.

## Operationella lärdomar (incident-baserade)

### 1. NetworkPolicy-symmetri: båda sidor explicit

**Vad hände 2026-06-04:** Vid first-deploy av sentinel-ml fungerade pod + Service tekniskt, men `kubectl exec deployment/sentinel-upload-api -- curl http://sentinel-ml.../health` returnerade `connection refused` på 2 ms. Sentinel-ml-pod var Running, Service hade endpoints, alla OPA-policies passade. Verkade fungera från sentinel-ml-sidan.

**Rotorsak:** Sentinel-ml:s ingress-policy tillåter trafik från upload-api-pods — men upload-api:s **egress**-policy är default-deny med fyra specifika allow-regler (DNS, ClamAV, Mongo, HTTPS). Ingen matchade sentinel-ml på port 8100. Curl droppades av upload-api:s **egen** egress innan paketet ens lämnade upload-api-pod:en.

**Insight:** I default-deny NetworkPolicy-arkitektur måste **båda sidor** explicit allowlist:a en koppling:

- **Sender's `egress`** måste tillåta `to: <receiver-podSelector>` på rätt port
- **Receiver's `ingress`** måste tillåta `from: <sender-podSelector>` på rätt port

Det är inte intuitivt om man bara designar sin egen tjänst — man tänker på sin egen ingress och missar att andra sidan har egress-restriktioner.

**Checklista vid ny intern microservice:**

1. Designa receiver:ns ingress-policy
2. Identifiera alla pods som ska ringa receiver:n
3. För varje sender: kontrollera att dess egress-policy tillåter `to: receiver-podSelector` på rätt port — uppdatera vid behov
4. Verifiera med `kubectl exec sender-pod -- curl receiver:port/health` efter deploy

**Lösning:** [sentinel-upload-api PR #70](https://github.com/Sidestep-Error/sentinel-upload-api/pull/70) lade till egress-regel för sentinel-ml.

### 2. CI deploy är medvetet smal: manifest-ändringar är manuella

**Vad hände 2026-06-04:** Efter merge av upload-api:s PR #70 körde CI:s `deploy-hetzner`-jobb framgångsrikt (17s, grön status), men curl-testet failade fortfarande. Anledning: CI-jobbet kör bara `kubectl rollout restart deployment/sentinel-upload-api`. Det rullar nya pods (för image-uppdateringar), men **applicerar inte ändrade manifests** (NetworkPolicy, ConfigMap, Service).

**Insight:** CI:s smala scope är säkerhetsdesign — `ci-deploy`-SA har bara `patch/update`-rättigheter på `deployments`, inte på NetworkPolicies, Secrets eller andra resurser. En läckt CI-token kan max trigga en restart, inte ändra säkerhetspolicies. Blast radius = en rolling restart.

**Trade-off:** Manifest-ändringar blir manuella ops:

- **Image-byten (kod-ändringar):** hanteras automatiskt av CI vid main-push
- **Manifest-ändringar** (NetworkPolicy, ConfigMap, Service, Resources): kräver manuell `kubectl apply -k k8s/base/` på klustret efter merge till main

**Checklista vid PR som rör `k8s/base/`-filer:**

1. Mergea PR till main som vanligt
2. Vänta in CI:s automatiska rollout (image-delen)
3. SSH till klustret + `cd /srv/<repo>` + `git pull` + `kubectl apply -k k8s/base/`
4. Verifiera nytt manifest-state med `kubectl get <resource> -o yaml`

Detta gäller både sentinel-ml och sentinel-upload-api — samma deploy-mönster.

## Referenser

- [runbooks/sentinel-ml-deploy.md](../runbooks/sentinel-ml-deploy.md) — deploy-procedurer
- [docs/sentinel-ml-upload-api-integration-architecture.md](sentinel-ml-upload-api-integration-architecture.md) — kontrakt mellan tjänsterna
- [docs/adversarial-analysis-plan.md](adversarial-analysis-plan.md) — hotbild mot ML-modellen själv (Spår C)
- sentinel-upload-api `k8s/gatekeeper/` — OPA-constraints (deras repo)
- sentinel-upload-api `infra/terraform/hetzner/` — `ci-deploy`-SA definition
