# Adversarial-analys — sentinel-ml

        > Genererad: 2026-06-03 | Dataset: data\real_threat_reports.jsonl

        ## Sammanfattning

        | Experiment | Resultat |
        |------------|---------|
        | Data poisoning (20 %) | ΔF1 = -0.156 |
        | Evasion (ε=0.2) | Flip rate = 0.0% |
        | Prompt injection | Ej testat (Ollama ej tillgänglig) |

        ## Hotmodell

        Systemet har tre angripbara ytor:
        1. **Spår A (threat-classifier)** — förgiftad träningsdata eller instruktioner dolda i threat reports
        2. **Upload-classifier** — riktad feature-perturbation för att undvika flaggning
        3. **LLM-backend** — prompt injection via skadliga dokument

        ---

        ## Experiment

        ### 1. Data poisoning — Spår A (TF-IDF + LR)

        **Hypotes:** Att felmärka 5–20 % av träningsdatat degraderar F1 mätbart.

        **Metod:** `adversarial/poisoning.py::poison_labels` flippar `ratio` % av
        träningslabels till slumpmässig annan klass. Utvärderat på rent testset.

        | Poison-ratio | Förgiftade samples | Accuracy | F1-macro | ΔF1 |
        |-------------|-------------------|----------|----------|-----|
        | 0% | 0 | 0.962 | 0.963 | +0.000 |
| 5% | 63 | 0.956 | 0.930 | -0.033 |
| 10% | 126 | 0.934 | 0.866 | -0.097 |
| 20% | 253 | 0.886 | 0.807 | -0.156 |

        **Analys:**
        Vid 20 % förgiftning sjunker F1 från 0.963 till 0.807
        (ΔF1=-0.156). TF-IDF + LR visar sig
        känslig för poisoning — datavalidering vid intag är nödvändig.

        **Motåtgärder:**
        - Datavalidering vid intag (filtrera outliers per klass)
        - Cross-validation över datakällor
        - Övervaka träningsdatans labelfördelning löpande

        ---

        ### 2. Evasion — Upload-classifier (Random Forest)

        **Hypotes:** Bounded uniform noise i feature-rymden räcker för att flippa prediktioner.

        **Metod:** `adversarial/evasion.py::random_feature_perturbation` lägger till
        uniform brus ∈ [-ε, ε] på alla features. Mäter andel flippade prediktioner.

        | ε | Flippade | Flip-rate |
        |---|----------|-----------|
        | 0.01 | 0 / 60 | 0.0% |
| 0.05 | 0 / 60 | 0.0% |
| 0.1 | 0 / 60 | 0.0% |
| 0.2 | 0 / 60 | 0.0% |

        **Analys:**
        Random Forest är robust mot random feature noise — låg flip-rate även vid ε=0.2. En riktad ART-attack (HopSkipJump) skulle sannolikt prestera bättre.

        **Motåtgärder:**
        - Input-domain-validering (clampa size_bytes, risk_score till rimliga intervall)
        - Ensemble-votning med flera modeller
        - Adversarial training med ART

        ---

        ### 3. Prompt injection — Spår A LLM

**Status:** Ej genomfört — Ollama var inte tillgängligt vid testkörningen.
Kör `ollama serve` och kör scriptet igen för att genomföra testet.

        ---

        ## Slutsats

        sentinel-ml visar god robusthet mot baseline-attacker men systemet bör
        inte anses produktionsklart utan ytterligare härdning:

        1. **Datavalidering** bör implementeras i `data/loaders.py` vid MongoDB-intag
        2. **Input-range-validering** bör läggas till i upload-feature-pipeline
        3. **Prompt injection** kräver fortsatt testning mot en körande Ollama-instans
        4. **ART-baserade riktade attacker** (HopSkipJump, C&W) är nästa steg för VG

        Referens: [OWASP ML Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/),
        [MITRE ATLAS](https://atlas.mitre.org/), NIST AI 100-2.