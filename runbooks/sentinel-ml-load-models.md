# Runbook: ladda tränade modeller till sentinel-ml (live på Hetzner)

Modellerna (`.joblib`) är gitignorerade och bakas **inte** in i imagen. De ligger
på en **PersistentVolumeClaim** (`sentinel-ml-models`) så de överlever
pod-omstarter. Den här runbooken populerar volymen **en gång**.

> ## Läs detta först — så här ser miljön faktiskt ut
>
> - **Klustret kör på Hetzner-noden, inte i molnet.** Du administrerar det
>   genom att **SSH:a in på servern**, där `kubectl` pratar med k3s lokalt.
>   En lokal kubectl på din laptop når **inte** klustret (om du inte exporterat
>   k3s-kubeconfigen dit). Repot finns på servern i `/srv/sentinel-ml`.
> - **CI applicerar INTE manifest-ändringar.** `deploy`-jobbet gör bara
>   `kubectl rollout restart`. PVC:n och volym-ändringen måste appliceras
>   **manuellt** (steg 1). Se [sentinel-ml-deploy.md](sentinel-ml-deploy.md)
>   → "Manifest-ändringar kräver manuell apply".
> - **Shell-syntax:** kommandona nedan är **bash** (servern + WSL). Använd `\`
>   för radbrytning — **inte** PowerShell-backtick `` ` `` (då tolkar bash varje
>   rad som ett eget kommando).

Förutsättningar: SSH-åtkomst till Hetzner-noden, och de tränade
filerna lokalt i `models_store/`:
`threat_classifier.joblib`, `upload_classifier.joblib`, `log_anomaly_tfidf.joblib`.
(`malware_classifier.joblib` behövs inte — inget API-anrop använder den ännu.)

## 1. Applicera PVC + deployment-ändringen på klustret (på servern)

Eftersom CI inte applicerar manifest måste detta göras manuellt **en gång** efter
att PVC-PR:en mergats:

```bash
ssh <användare>@<hetzner-nod>
cd /srv/sentinel-ml
git pull --ff-only origin main
kubectl apply -f k8s/base/pvc.yaml
kubectl apply -f k8s/base/deployment.yaml
kubectl get pvc -n sentinel        # sentinel-ml-models ska bli "Bound"
```

(`deployment.yaml` kan appliceras ensamt — den refererar configmap/secret som
redan finns i klustret, så ingen lokal `secret.yaml` behövs.)

## 2. Kopiera upp modellerna till servern

`kubectl cp` läser källfilen där `kubectl` körs (= servern), så filerna måste
ligga där. Från din **lokala** maskin, i repo-roten (bash — en rad eller `\`):

```bash
scp models_store/threat_classifier.joblib models_store/upload_classifier.joblib models_store/log_anomaly_tfidf.joblib <användare>@<hetzner-nod>:~/
```

## 3. Starta loader-podden och kopiera in modellerna (på servern)

```bash
kubectl apply -f k8s/maintenance/models-loader.yaml
kubectl wait --for=condition=Ready pod/sentinel-ml-models-loader -n sentinel --timeout=90s
kubectl cp ~/threat_classifier.joblib sentinel/sentinel-ml-models-loader:/models/threat_classifier.joblib
kubectl cp ~/upload_classifier.joblib sentinel/sentinel-ml-models-loader:/models/upload_classifier.joblib
kubectl cp ~/log_anomaly_tfidf.joblib sentinel/sentinel-ml-models-loader:/models/log_anomaly_tfidf.joblib
kubectl exec -n sentinel sentinel-ml-models-loader -- ls -la /models   # ska visa 3 filer, ägda av 10001
```

## 4. Starta om app-podden så modellerna laddas

Modellerna läses in vid startup (lifespan), så app-podden måste startas om:

```bash
kubectl rollout restart deployment/sentinel-ml -n sentinel
kubectl rollout status  deployment/sentinel-ml -n sentinel --timeout=120s
```

## 5. Verifiera att riktiga modeller laddats

sentinel-ml har ingen publik ingress, så port-forwarda och curl:a lokalt på
servern:

```bash
kubectl port-forward -n sentinel deploy/sentinel-ml 8100:8100 >/tmp/pf.log 2>&1 &
sleep 2
curl -sS http://localhost:8100/health; echo
curl -sS -X POST http://localhost:8100/predict/upload \
  -H 'Content-Type: application/json' \
  -d "{\"filename\":\"x.pdf\",\"content_type\":\"application/pdf\",\"sha256\":\"$(printf 'a%.0s' {1..64})\",\"scan_status\":\"clean\"}"; echo
kill %1
```

Förväntat (= modellerna laddade):
- `/health` → `{"status":"ok","version":"0.1.0"}`
- `/predict/upload` → `model_version` är en **12-teckens hash** (inte `"none"`),
  och `prediction.label` är `accepted`/`rejected` (inte `unknown`).

## 6. Städa upp

```bash
kubectl delete pod sentinel-ml-models-loader -n sentinel
```

## 7. (Valfritt) Hash-bryggan live

För att kunna visa "MATCH – känd skadlig hash":

1. `scp` upp en threat-reports-JSONL till servern och `kubectl cp` in den i
   loader-podden (samma flöde som steg 2–3), t.ex.
   `/models/known_malicious_reports.jsonl` — seedad med `sha256` på den fil du
   tänker ladda upp i demon.
2. Sätt i `k8s/base/configmap.yaml`:
   `KNOWN_MALICIOUS_HASHES_PATH: "/app/models_store/known_malicious_reports.jsonl"`
   och **applicera manuellt**: `kubectl apply -f k8s/base/configmap.yaml`.
3. `kubectl rollout restart deployment/sentinel-ml -n sentinel`.

## Noter

- **Engång:** volymen är persistent, så detta behöver bara göras en gång.
  Vanliga rollouts (nya image-builds) behåller modellerna.
- **Omträning:** vid ny modell — kör om steg 2–4 (scp + cp + rollout restart).
- **RWO + single node:** loader- och app-podden mountar samma PVC på samma nod;
  det är tillåtet för ReadWriteOnce inom en nod.
