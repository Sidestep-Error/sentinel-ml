# syntax=docker/dockerfile:1.7
#
# Multi-stage build for sentinel-ml FastAPI service.
#
# Stage 1 (builder): installerar Python-paketet i en venv som kopieras vidare.
# Stage 2 (runtime): minimal slim-image, non-root user, kör uvicorn på 8100.
#
# Modeller (.joblib) bakas INTE in i image:n. De mountas via volym i compose
# (./models_store -> /app/models_store) så de kan swappas in utan rebuild.
# Saknad modell -> service degraderar gracefully (se service/api.py).

# --- Stage 1: builder ---
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install .

# --- Stage 2: runtime ---
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Patcha OS-paket i basimagen (python:3.12-slim ligger ofta några dagar efter
# Debians säkerhetsuppdateringar). Drar in fixade openssl/libssl m.fl. så att
# Trivy-scannern (--severity HIGH,CRITICAL, fixable) inte blockerar bygget.
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Non-root user matchar sentinel-upload-api-konvention (UID 10001).
# K8s pod-spec sätter runAsUser: 10001 — UID måste finnas i image:n så
# att ägarskap på /app/models_store mappas till rätt process-identitet.
RUN groupadd --system --gid 10001 appuser && \
    useradd --system --uid 10001 --gid appuser --home /app --shell /usr/sbin/nologin appuser

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app

COPY --chown=appuser:appuser src/ ./src/
RUN mkdir -p /app/models_store && chown -R appuser:appuser /app/models_store

USER appuser

EXPOSE 8100

# Healthcheck via Python stdlib (urllib) så vi inte behöver curl i image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8100/health', timeout=3).read()" || exit 1

CMD ["uvicorn", "sentinel_ml.service.api:app", "--host", "0.0.0.0", "--port", "8100"]
