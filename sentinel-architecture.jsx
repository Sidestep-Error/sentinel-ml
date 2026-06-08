import { useState } from "react";

const MODULES = {
  "upload-api": {
    name: "sentinel-upload-api",
    tech: "FastAPI · Python 3.11/3.12 · MongoDB (Motor) · ClamAV",
    port: 8000,
    infra: "Hetzner k3s · Kubernetes · Kustomize · Gatekeeper OPA",
    modules: [
      {
        id: "main",
        name: "main.py",
        layer: "API",
        desc: "Huvudfilen. Hanterar /upload, /uploads, /metrics/summary, /external/threats/kev-summary. Implementerar rate limiting (per IP, sliding window), filnamnsvalidering (path-traversal-skydd), content-type-matchning mot extension, SHA256-deduplicering, riskpoäng-beräkning (0–100) med fail-closed policy. Hämtar CISA KEV-data med in-memory cache och TTL.",
        imports: ["db", "models", "scanner", "threats_router", "threat_intel"],
        endpoints: ["POST /upload", "GET /uploads", "GET /metrics/summary", "GET /external/threats/kev-summary", "GET /health"],
      },
      {
        id: "scanner",
        name: "scanner.py",
        layer: "Service",
        desc: "Filscanning med tre modes: mock (EICAR-signatur + filnamn), clamav (socket-baserad INSTREAM), auto (försök ClamAV, fallback till mock). Returnerar ScanResult(status, engine, detail). Fail-closed: scanner-fel → status='error' → risk_score=80.",
        imports: [],
        endpoints: [],
      },
      {
        id: "auth",
        name: "auth.py",
        layer: "Security",
        desc: "Firebase-autentisering. AUTH_MODE styr: 'off' → anonymous, 'firebase' → verifiera Bearer-token via firebase_admin. Stöder credentials via JSON-env eller fil. Cachad med lru_cache.",
        imports: [],
        endpoints: [],
      },
      {
        id: "db",
        name: "db.py",
        layer: "Data",
        desc: "Motor (async MongoDB-driver). Lazy client via lru_cache. Stöder databas-namn i URI eller fallback-env. Skapar TTL-index på created_at (konfigurerbara retentionsdagar) och SHA256-index.",
        imports: [],
        endpoints: [],
      },
      {
        id: "models",
        name: "models.py",
        layer: "Data",
        desc: "Pydantic BaseModel: UploadRecord med created_at, filename, sha256, content_type, size_bytes, status, decision, risk_score (0–100), risk_reasons, scan_status/engine/detail, deduplicated.",
        imports: [],
        endpoints: [],
      },
      {
        id: "threat_intel",
        name: "services/threat_intel.py",
        layer: "Service",
        desc: "Periodisk hotinsamling (APScheduler, var 15:e minut). Tre källor: Feodo Tracker (C2-servrar), URLhaus (malware-URLs), ThreatFox (IOCs). GeoIP-enrichment via MaxMind GeoLite2. Fingerprint-baserad dedup (SHA256 av source|ioc|day). Konfigurerbar min_confidence, max_events_per_run, allowed_sources.",
        imports: ["db"],
        endpoints: [],
      },
      {
        id: "threats_router",
        name: "routers/threats.py",
        layer: "API",
        desc: "APIRouter med prefix /api/v1/threats. GET / returnerar senaste threat events med geolokation. Paginering via limit-parameter (1–1000).",
        imports: ["threat_intel"],
        endpoints: ["GET /api/v1/threats/"],
      },
    ],
  },
  "ml": {
    name: "sentinel-ml",
    tech: "FastAPI · scikit-learn · Pydantic · Ollama (llama3.2) · Typer CLI",
    port: 8100,
    infra: "Docker Compose · valfri sidecar i k8s",
    modules: [
      {
        id: "data",
        name: "data/",
        layer: "Data",
        desc: "loaders.py: Läser från MongoDB (uploads) och JSONL-filer. Returnerar Pydantic-modeller. Read-only mot Sentinels DB. schemas.py: IOCType (IP, domain, URL, hashes, CVE, email), IOC, ThreatReport, UploadRecord (speglar upstream), Prediction.",
        imports: [],
        endpoints: [],
      },
      {
        id: "features",
        name: "features/",
        layer: "Feature eng.",
        desc: "ioc_extract.py: Regex-baserad IOC-extraktion (IPv4, domäner, MD5/SHA1/SHA256, CVE, URL, email). Dedupning, prioriterad ordning. upload_meta.py: 9 numeriska features från UploadRecord — size_bytes_log, filename_length, special_chars, digit_ratio, extension_match, risk_score_normalized, scan_status one-hot.",
        imports: ["data"],
        endpoints: [],
      },
      {
        id: "ml_models",
        name: "models/",
        layer: "ML",
        desc: "threat_classifier.py: TF-IDF(1-2gram, sublinear_tf) + LogisticRegression (balanced). train/save/load via joblib. upload_classifier.py: RandomForest (200 träd, balanced, n_jobs=-1). Båda följer sklearn API (fit/predict/predict_proba).",
        imports: ["features"],
        endpoints: [],
      },
      {
        id: "eval",
        name: "eval/",
        layer: "Evaluation",
        desc: "metrics.py: ClassificationMetrics(accuracy, precision_macro, recall_macro, f1_macro, per_class_report, confusion). Enda stället för rapporterade siffror — garanterar jämförbarhet mellan körningar.",
        imports: ["ml_models"],
        endpoints: [],
      },
      {
        id: "llm",
        name: "llm/",
        layer: "LLM",
        desc: "ollama_client.py: Tunn httpx-klient mot Ollama REST API. Synkron generate() med system-prompt, temperature. prompts.py: CLASSIFY_THREAT_REPORT_SYSTEM (klassificera → malware/phishing/ddos/ransomware/etc, JSON), CVE_RELEVANCE_SYSTEM (triage CVE mot vår stack).",
        imports: [],
        endpoints: [],
      },
      {
        id: "adversarial",
        name: "adversarial/",
        layer: "Security",
        desc: "poisoning.py: Flipp-labeling experiment — mät F1-degradering vid X% poisonade samples. evasion.py: Random feature-perturbation (ε-bounded noise). prompt_injection.py: 4 probes (direct_override, role_swap, hidden_unicode, output_format_hijack) som testar LLM-klassificerarens robusthet.",
        imports: ["ml_models", "llm"],
        endpoints: [],
      },
      {
        id: "service",
        name: "service/api.py",
        layer: "API",
        desc: "FastAPI-app. Laddar .joblib vid startup, degraderar gracefully om modell saknas. POST /predict/threat: klassificera text + extrahera IOCs. POST /predict/upload: klassificera UploadRecord. Artifact-versionering via SHA256-hash.",
        imports: ["features", "ml_models", "data"],
        endpoints: ["GET /health", "POST /predict/threat", "POST /predict/upload"],
      },
      {
        id: "cli",
        name: "cli.py",
        layer: "CLI",
        desc: "Typer-baserad CLI. Kommandon: version, extract-iocs <file>, train threat-classifier --dataset <jsonl>. Binder samman loaders, features och models för offline-körning.",
        imports: ["data", "features", "ml_models"],
        endpoints: [],
      },
    ],
  },
};

const INTEGRATION = {
  patterns: [
    { name: "Off-line batch", status: "Fas 1–2", desc: "sentinel-ml läser periodiskt från MongoDB, skriver till ml_predictions" },
    { name: "HTTP service", status: "Fas 3 (demo)", desc: "sentinel-upload-api anropar /predict med 500ms timeout, graceful fallback" },
    { name: "Sidecar", status: "Valfritt", desc: "sentinel-ml i samma pod, snabbare nätverkshopp" },
  ],
  shared: ["MongoDB (uploads, threat_events → ml_predictions)", "Pydantic UploadRecord-schema (speglad)", "Docker/K8s deploy-konventioner"],
};

const LAYER_COLORS = {
  API: "bg-blue-50 text-blue-800 border-blue-200",
  Service: "bg-teal-50 text-teal-800 border-teal-200",
  Security: "bg-pink-50 text-pink-800 border-pink-200",
  Data: "bg-amber-50 text-amber-800 border-amber-200",
  "Feature eng.": "bg-purple-50 text-purple-800 border-purple-200",
  ML: "bg-indigo-50 text-indigo-800 border-indigo-200",
  Evaluation: "bg-green-50 text-green-800 border-green-200",
  LLM: "bg-orange-50 text-orange-800 border-orange-200",
  CLI: "bg-gray-100 text-gray-700 border-gray-300",
};

export default function SentinelArchitecture() {
  const [activeRepo, setActiveRepo] = useState("upload-api");
  const [selectedModule, setSelectedModule] = useState(null);
  const [view, setView] = useState("modules");

  const repo = MODULES[activeRepo];
  const mod = selectedModule
    ? repo.modules.find((m) => m.id === selectedModule)
    : null;

  return (
    <div className="max-w-[680px] mx-auto font-sans">
      <div className="flex gap-2 mb-4">
        {Object.entries(MODULES).map(([key, r]) => (
          <button
            key={key}
            onClick={() => { setActiveRepo(key); setSelectedModule(null); }}
            className={`px-3 py-1.5 rounded-lg text-sm transition-all ${
              activeRepo === key
                ? "bg-gray-900 text-white"
                : "bg-gray-100 text-gray-600 hover:bg-gray-200"
            }`}
          >
            {r.name}
          </button>
        ))}
        <button
          onClick={() => setView(view === "modules" ? "integration" : "modules")}
          className="ml-auto px-3 py-1.5 rounded-lg text-sm bg-gray-100 text-gray-600 hover:bg-gray-200"
        >
          {view === "modules" ? "Integration" : "Moduler"}
        </button>
      </div>

      {view === "integration" ? (
        <div className="space-y-4">
          <p className="text-sm text-gray-500 mb-3">
            Tre integrationsmönster mellan repona — kontraktet är data (MongoDB) och HTTP, inte kodimport.
          </p>
          {INTEGRATION.patterns.map((p) => (
            <div key={p.name} className="border border-gray-200 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-1">
                <span className="font-medium text-sm">{p.name}</span>
                <span className="text-xs px-2 py-0.5 rounded-full bg-gray-100 text-gray-600">
                  {p.status}
                </span>
              </div>
              <p className="text-sm text-gray-500">{p.desc}</p>
            </div>
          ))}
          <div className="border border-gray-200 rounded-xl p-4 mt-4">
            <p className="font-medium text-sm mb-2">Delad infrastruktur</p>
            <ul className="space-y-1">
              {INTEGRATION.shared.map((s, i) => (
                <li key={i} className="text-sm text-gray-600 flex items-start gap-2">
                  <span className="text-gray-400 mt-0.5">→</span> {s}
                </li>
              ))}
            </ul>
          </div>
        </div>
      ) : (
        <>
          <div className="border border-gray-200 rounded-xl p-4 mb-4">
            <div className="flex items-baseline justify-between mb-1">
              <span className="font-medium">{repo.name}</span>
              <span className="text-xs text-gray-400">:{repo.port}</span>
            </div>
            <p className="text-xs text-gray-500 mb-1">{repo.tech}</p>
            <p className="text-xs text-gray-400">{repo.infra}</p>
          </div>

          <div className="grid grid-cols-2 gap-2 mb-4">
            {repo.modules.map((m) => (
              <button
                key={m.id}
                onClick={() => setSelectedModule(selectedModule === m.id ? null : m.id)}
                className={`text-left p-3 rounded-xl border transition-all ${
                  selectedModule === m.id
                    ? "border-gray-900 bg-gray-50 shadow-sm"
                    : "border-gray-200 hover:border-gray-300"
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-sm font-medium">{m.name}</span>
                </div>
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded border ${
                    LAYER_COLORS[m.layer] || "bg-gray-50 text-gray-600 border-gray-200"
                  }`}
                >
                  {m.layer}
                </span>
              </button>
            ))}
          </div>

          {mod && (
            <div className="border border-gray-900 rounded-xl p-4 animate-in fade-in">
              <div className="flex items-center justify-between mb-2">
                <span className="font-medium">{mod.name}</span>
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded border ${
                    LAYER_COLORS[mod.layer] || ""
                  }`}
                >
                  {mod.layer}
                </span>
              </div>
              <p className="text-sm text-gray-600 leading-relaxed mb-3">{mod.desc}</p>

              {mod.endpoints.length > 0 && (
                <div className="mb-3">
                  <p className="text-xs text-gray-400 uppercase tracking-wide mb-1">Endpoints</p>
                  <div className="flex flex-wrap gap-1">
                    {mod.endpoints.map((e) => (
                      <span key={e} className="text-xs font-mono px-2 py-0.5 rounded bg-gray-100 text-gray-700">
                        {e}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {mod.imports.length > 0 && (
                <div>
                  <p className="text-xs text-gray-400 uppercase tracking-wide mb-1">Beroenden</p>
                  <div className="flex flex-wrap gap-1">
                    {mod.imports.map((imp) => {
                      const target = repo.modules.find((m) => m.id === imp);
                      return (
                        <button
                          key={imp}
                          onClick={() => setSelectedModule(imp)}
                          className="text-xs px-2 py-0.5 rounded bg-blue-50 text-blue-700 hover:bg-blue-100 transition-colors"
                        >
                          {target?.name || imp}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
