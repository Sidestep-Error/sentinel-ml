# Runbook: ladda tränade modeller till sentinel-ml (live på Hetzner)

Modellerna (`.joblib`) är gitignorerade och bakas inte in i imagen. De ligger
på en **PersistentVolumeClaim** (`sentinel-ml-models`) så de överlever
pod-omstarter. Den här runbooken populerar volymen **en gång** via en
kortlivad loader-pod.

> Förutsättning: `kubectl`-access mot `sentinel`-namespace, och de tränade
> filerna lokalt i `models_store/`:
> `threat_classifier.joblib`, `upload_classifier.joblib`, `log_anomaly_tfidf.joblib`.
> (`malware_classifier.joblib` behövs inte — inget API-anrop använder den ännu.)

## 0. Förutsättning: PVC + deployment deployad

PVC:n och deployment-ändringen (`emptyDir` → PVC) ingår i `k8s/base/` och
deployas via vanliga flödet (merge till main → CI `kubectl apply -k`). Verifiera:

```bash
kubectl get pvc -n sentinel sentinel-ml-models
# STATUS blir "Pending" tills första podden använder den (WaitForFirstConsumer) —
# det är väntat. Den binder när loader-podden eller app-podden schemaläggs.
```

## 1. Starta loader-podden

```bash
kubectl apply -f k8s/maintenance/models-loader.yaml
kubectl wait --for=condition=Ready pod/sentinel-ml-models-loader -n sentinel --timeout=60s
```

## 2. Kopiera in modellerna (engång)

Kör från repo-roten där `models_store/` finns:

```bash
kubectl cp models_store/threat_classifier.joblib  sentinel/sentinel-ml-models-loader:/models/threat_classifier.joblib
kubectl cp models_store/upload_classifier.joblib  sentinel/sentinel-ml-models-loader:/models/upload_classifier.joblib
kubectl cp models_store/log_anomaly_tfidf.joblib  sentinel/sentinel-ml-models-loader:/models/log_anomaly_tfidf.joblib
```

Verifiera:

```bash
kubectl exec -n sentinel sentinel-ml-models-loader -- ls -la /models
```

## 3. Starta om app-podden så modellerna laddas

Modellerna läses in vid startup (lifespan), så app-podden måste startas om
efter att volymen populerats:

```bash
kubectl rollout restart deployment/sentinel-ml -n sentinel
kubectl rollout status  deployment/sentinel-ml -n sentinel --timeout=120s
```

## 4. Verifiera att riktiga modeller laddats

```bash
# Health
kubectl exec -n sentinel deploy/sentinel-upload-api -- \
  curl -sS http://sentinel-ml.sentinel.svc.cluster.local/health

# Upload-prediktion ska ge model_version != "none" (alltså inte fallback)
kubectl exec -n sentinel deploy/sentinel-upload-api -- sh -c \
  'curl -sS -X POST http://sentinel-ml.sentinel.svc.cluster.local/predict/upload \
   -H "Content-Type: application/json" \
   -d "{\"filename\":\"x.pdf\",\"content_type\":\"application/pdf\",\"sha256\":\"'"$(printf a%.0s {1..64})"'\",\"scan_status\":\"clean\"}"'
```

Förväntat: `"model_version"` är en 12-teckens hash, inte `"none"`, och
`prediction.label` är `accepted`/`rejected` (inte `unknown`).

## 5. Städa upp

```bash
kubectl delete -f k8s/maintenance/models-loader.yaml
```

## 6. (Valfritt) Hash-bryggan live

För att kunna visa "MATCH – känd skadlig hash":

1. Lägg en threat-reports-JSONL i volymen (samma loader-flöde), t.ex.
   `kubectl cp data/known_malicious_reports.jsonl sentinel/sentinel-ml-models-loader:/models/known_malicious_reports.jsonl`
   — seedad med `sha256` på den fil du tänker ladda upp i demon.
2. Sätt i `k8s/base/configmap.yaml`:
   `KNOWN_MALICIOUS_HASHES_PATH: "/app/models_store/known_malicious_reports.jsonl"`
3. `kubectl rollout restart deployment/sentinel-ml -n sentinel`.

## Noter

- **Omstarter:** eftersom volymen är persistent behöver detta bara göras **en
  gång**. Vanliga rollouts (t.ex. nya image-builds) behåller modellerna.
- **Omträning:** vid ny modell — kör om steg 1–3 (cp + rollout restart).
- **RWO + single node:** loader- och app-podden mountar samma PVC på samma nod;
  det är tillåtet för ReadWriteOnce inom en nod.
