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

### 1. Separat read-only Mongo-user (medium prioritet)

Idag delar sentinel-ml `MONGODB_URI` med upload-api (samma kreds).
Bättre: skapa en dedikerad MongoDB-användare med `read`-rättighet bara
på `uploads`- och `threat_events`-collections, plus `readWrite` på
`ml_predictions`-collection. Då kan en kompromitterad sentinel-ml-pod
inte mutera upload-data.

### 2. Image signing med Cosign (låg prioritet)

upload-api har Cosign i sin roadmap (`cosign.pub` finns i repot). När
det implementeras där, replikera mönstret för sentinel-ml.

### 3. Secret rotation (låg prioritet)

`MONGODB_URI` byts manuellt idag. För kursprojekt tillräckligt. För
produktion: External Secrets Operator + Vault eller liknande.

### 4. ml_predictions-collection write-back (Fas 2)

När modellerna börjar producera predictions ska de skrivas till en
separat collection enligt [integration-doc](integration-with-sentinel-upload-api.md).
Hot: race conditions, oavsiktlig skrivning till `uploads`-collection.
Mitigering: explicit collection-namn i loader-kod, integration-test som
verifierar att vi bara skriver till `ml_predictions`.

### 5. Adversarial test-data isolering (Fas 2)

Spår C kommer producera adversarial samples. Dessa **får inte** läcka
till `uploads`-collection eller orsaka feedback-loops om modellen
retraineras på Mongo-data. Mitigering: alla adversarial-skript läser
från lokal JSONL, skriver till `data/adversarial/`, aldrig till Mongo.

## Referenser

- [runbooks/sentinel-ml-deploy.md](../runbooks/sentinel-ml-deploy.md) — deploy-procedurer
- [docs/integration-with-sentinel-upload-api.md](integration-with-sentinel-upload-api.md) — kontrakt mellan tjänsterna
- [docs/adversarial-analysis-plan.md](adversarial-analysis-plan.md) — hotbild mot ML-modellen själv (Spår C)
- sentinel-upload-api `k8s/gatekeeper/` — OPA-constraints (deras repo)
- sentinel-upload-api `infra/terraform/hetzner/` — `ci-deploy`-SA definition
