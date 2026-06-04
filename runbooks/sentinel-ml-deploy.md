# Runbook: sentinel-ml Hetzner k3s-deploy

## Översikt

sentinel-ml körs som en intern microservice i `sentinel`-namespacet på
samma k3s-kluster som sentinel-upload-api. Ingen publik URL — servicen
är bara nåbar via `http://sentinel-ml.sentinel.svc.cluster.local`
från upload-api:s pods.

## CI/CD-flödet

```
push till main
   ↓
test-and-build (ruff, pytest, pip-audit)
   ↓
dockerhub-push (build + push jonitsx/sentinel-ml:main, :latest, :<sha>)
   ↓
deploy-hetzner (kubectl rollout restart deployment/sentinel-ml -n sentinel)
```

GitHub Secrets som CI använder:

| Secret | Syfte |
|--------|-------|
| `DOCKER_IMAGE` | `jonitsx/sentinel-ml` |
| `DOCKER_USERNAME` | Docker Hub-användarnamn för push |
| `DOCKER_PASSWORD` | Personal access token för Docker Hub |
| `KUBECONFIG_HETZNER_B64` | Base64-kodad kubeconfig för `ci-deploy`-SA |

`ci-deploy`-SA:n är **delad** med upload-api — samma RBAC-roll täcker
alla deployments i `sentinel`-namespacet. Ingen ny Terraform behövs.

## Första-deploy (manuell setup)

Detta är en engångs-procedur — CI hanterar alla efterföljande rollouts.

```bash
# 1. Klona repot på maskin med kubectl-access mot Hetzner-klustret
git clone https://github.com/Sidestep-Error/sentinel-ml.git
cd sentinel-ml

# 2. Skapa secret.yaml med riktig MONGODB_URI
cp k8s/base/secret.example.yaml k8s/base/secret.yaml
$EDITOR k8s/base/secret.yaml   # fyll i Mongo connection string

# 3. Applicera alla manifests via Kustomize
kubectl apply -k k8s/base/

# 4. Verifiera att pod startar
kubectl rollout status deployment/sentinel-ml -n sentinel --timeout=120s
kubectl get pod -n sentinel -l app.kubernetes.io/name=sentinel-ml

# 5. Verifiera intern access från upload-api:s pod
kubectl exec -n sentinel deployment/sentinel-upload-api -- \
  curl -sS http://sentinel-ml.sentinel.svc.cluster.local/health

# Förväntat svar: {"status":"ok","version":"0.1.0"}

# 6. Radera lokal secret.yaml (klusterets kopia är källan)
rm k8s/base/secret.yaml
```

## Vanlig deploy (efter setup)

Sker automatiskt vid push till `main`. Inget manuellt steg.

För manuell trigger utan kod-ändring:
```bash
kubectl rollout restart deployment/sentinel-ml -n sentinel
kubectl rollout status deployment/sentinel-ml -n sentinel --timeout=120s
```

## Rollback

```bash
# Lista rollout-historik
kubectl rollout history deployment/sentinel-ml -n sentinel

# Rulla tillbaka till föregående revision
kubectl rollout undo deployment/sentinel-ml -n sentinel

# Eller till specifik revision
kubectl rollout undo deployment/sentinel-ml -n sentinel --to-revision=N

# Verifiera att rollback lyckades
kubectl rollout status deployment/sentinel-ml -n sentinel --timeout=120s
```

Om imagen i tidigare revision är borta från Docker Hub räcker inte
`rollout undo` — då måste man bygga om från en motsvarande commit och
trigga ny deploy.

## Felsökning

| Symptom | Trolig orsak | Åtgärd |
|---------|--------------|--------|
| Pod i `ImagePullBackOff` | Image inte pushad eller fel `:tag` i deployment.yaml | Kolla att CI:s dockerhub-push-jobb lyckades; verifiera `image:`-fältet i `k8s/base/deployment.yaml` |
| Pod i `CrashLoopBackOff` | App kraschar vid start | `kubectl logs -n sentinel <pod> --previous` — vanligaste orsak är saknad/felaktig `MONGODB_URI` i `sentinel-ml-secrets` |
| `/health` svarar 503 | Service uppe men kan inte nå Mongo | Kontrollera `MONGODB_URI` i secret; verifiera att NetworkPolicy tillåter egress till port 27017 |
| `forbidden: cannot patch deployments` i CI | SA-token rotated eller saknas | Regenera `KUBECONFIG_HETZNER_B64`-secret enligt sentinel-upload-api runbook |
| OPA-policyn blockerar apply | Manifest bryter mot constraint (latest-tag, missing labels, no resource limits, root user, rw-rootfs) | Läs error-meddelandet — alla policies dokumenterade i `sentinel-upload-api/k8s/gatekeeper/` |
| Pod startar men `models_store` är tomt | Förväntat i Fas 1 | Service returnerar fallback-svar (`label="unknown"`, `model_version="none"`). Fas 2 bakar in `.joblib` i image. |

## Säkerhetsanalys

Se [docs/security-analysis-deployment.md](../docs/security-analysis-deployment.md)
för hotmodell, RBAC-resonemang och known follow-ups (separat read-only
Mongo-user, secret rotation, image signing).

## Cleanup

Om sentinel-ml ska tas bort från klustret:

```bash
kubectl delete -k k8s/base/ -n sentinel
# Behöver inte ta bort namespace -- det delas med sentinel-upload-api
```
