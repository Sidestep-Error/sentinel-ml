"""
Modulens ansvar:
Denna modul implementerar en AI-stödd pipeline för anomalidetektering i loggdata.
Fokus ligger på att transformera råa Wazuh-alerts till tidsfönsterbaserade features,
kombinera modellbaserad detektion (Isolation Forest) med statistisk baslinje och
slutligen generera en rapport som är användbar i säkerhetsanalys.

Pipeline i korthet:
1. Ladda och normalisera JSON-alerts.
2. Extrahera aggregerade features per tidsfönster.
3. Kör anomalidetektering med Isolation Forest.
4. Kör kompletterande z-score-baslinje.
5. Spara resultat och skriv textbaserad sammanfattning.
"""

from __future__ import annotations

import json
from pathlib import Path
import warnings

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")


def load_alerts(file_path: str | Path) -> pd.DataFrame:
    """Läs in Wazuh-alerts från JSON och omvandla till analyserbar tabell.

    Funktionen plockar ut relevanta fält ur Wazuh-strukturen (`hits.hits._source`)
    och normaliserar datatyper för tid, nivå och port så att efterföljande steg
    får stabil indata.

    """
    file_path = Path(file_path)
    data = json.loads(file_path.read_text(encoding="utf-8"))

    if isinstance(data, dict) and "hits" in data:
        raw_hits = data.get("hits", {}).get("hits", [])
    elif isinstance(data, list):
        raw_hits = data
    else:
        raw_hits = []

    records = []
    for hit in raw_hits:
        source = hit.get("_source", hit) if isinstance(hit, dict) else {}
        rule = source.get("rule", {}) if isinstance(source, dict) else {}
        data_section = source.get("data", {}) if isinstance(source, dict) else {}
        agent = source.get("agent", {}) if isinstance(source, dict) else {}

        timestamp = (
            source.get("timestamp")
            or source.get("@timestamp")
            or hit.get("@timestamp")
            if isinstance(hit, dict)
            else None
        )

        records.append(
            {
                "timestamp": timestamp,
                "rule_id": rule.get("id", source.get("rule_id", "unknown")),
                "rule_level": rule.get("level", source.get("rule_level", 0)),
                "description": rule.get("description", source.get("description", "")),
                "src_ip": data_section.get("srcip", source.get("src_ip", "unknown")),
                "dst_port": data_section.get("dstport", source.get("dst_port", 0)),
                "agent_name": agent.get("name", source.get("agent_name", "unknown")),
            }
        )

    df = pd.DataFrame(records)
    if df.empty:
        return df

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["rule_level"] = pd.to_numeric(df["rule_level"], errors="coerce").fillna(0)
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce").fillna(0)
    return df.dropna(subset=["timestamp"])


def extract_features(df: pd.DataFrame, window: str = "1h") -> pd.DataFrame:
    """Skapa tidsfönsterbaserade features för modellering och baslinjeanalys.

    Funktionen resamplar logghändelser till ett valt tidsfönster och beräknar
    bland annat händelsevolym, variationsmått och aktivitetsmönster. Den bygger
    också derivat som rullande medelvärde/standardavvikelse samt z-score.

    Args:
        df: Normaliserad loggdata med tidsstämpelkolumn.
        window: Resamplingsfönster, exempelvis `1h`.

    Returns:
        Feature-DataFrame indexerad på tidsfönster.
    """
    if df.empty:
        return pd.DataFrame()

    indexed_df = df.set_index("timestamp").sort_index()

    features = indexed_df.resample(window).agg(
        event_count=("rule_id", "count"),
        unique_rules=("rule_id", "nunique"),
        avg_severity=("rule_level", "mean"),
        max_severity=("rule_level", "max"),
        unique_ips=("src_ip", "nunique"),
        unique_ports=("dst_port", "nunique"),
    ).fillna(0)

    features["hour"] = features.index.hour
    features["is_night"] = features["hour"].apply(lambda hour: 1 if hour < 6 or hour > 22 else 0)
    features["event_count_rolling_mean"] = features["event_count"].rolling(6, min_periods=1).mean()
    features["event_count_rolling_std"] = (
        features["event_count"].rolling(6, min_periods=1).std().fillna(0)
    )

    mean = features["event_count"].mean()
    std = features["event_count"].std()
    scale = std if pd.notna(std) and std > 0 else 1
    features["event_count_zscore"] = (features["event_count"] - mean) / scale
    return features


def detect_anomalies(features: pd.DataFrame, contamination: float = 0.1) -> pd.DataFrame:
    """Identifiera avvikande tidsfönster med Isolation Forest.

    Funktionen skalar featurematrisen för att minska påverkan av olika enheter
    och tränar sedan en osuperviserad modell som markerar avvikande observationer.
    Den kompletterar DataFrame med prediktion, score och boolesk anomaliindikator.

    Args:
        features: Extraherade features per tidsfönster.
        contamination: Antagen andel anomalier i datasetet.

    Returns:
        Samma DataFrame med tillagda kolumner: `anomaly`, `anomaly_score`, `is_anomaly`.
    """
    if features.empty:
        return features

    feature_cols = [
        "event_count",
        "unique_rules",
        "avg_severity",
        "max_severity",
        "unique_ips",
        "unique_ports",
        "is_night",
        "event_count_zscore",
    ]

    if len(features) < 2:
        features["anomaly"] = 1
        features["anomaly_score"] = 0.0
        features["is_anomaly"] = False
        return features

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(features[feature_cols].values)

    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
    )
    features["anomaly"] = model.fit_predict(X_scaled)
    features["anomaly_score"] = model.decision_function(X_scaled)
    features["is_anomaly"] = features["anomaly"] == -1
    return features


def statistical_baseline(features: pd.DataFrame, threshold_sigma: float = 2.0) -> pd.DataFrame:
    """Flagga avvikelser med enkel statistisk tröskel på z-score.

    Detta steg fungerar som en transparent referensmetod som kan jämföras mot
    AI-modellens beslut. Ett tidsfönster markeras när absolut z-score överstiger
    angiven sigma-tröskel.

    Args:
        features: Feature-DataFrame som innehåller `event_count_zscore`.
        threshold_sigma: Gränsvärde för avvikelse i standardavvikelser.

    Returns:
        DataFrame med tillagd kolumn `stat_anomaly`.
    """
    if features.empty:
        features["stat_anomaly"] = []
        return features

    features["stat_anomaly"] = features["event_count_zscore"].abs() > threshold_sigma
    return features


def generate_report(features: pd.DataFrame) -> str:
    """Bygg en textbaserad rapport för snabb tolkning av detektionsresultat.

    Rapporten innehåller period, antal analyserade fönster, antal anomalier från
    både Isolation Forest och statistisk baslinje samt detaljrader för markerade
    tidsfönster.

    Args:
        features: DataFrame med resultat från detektionsstegen.

    Returns:
        Formaterad rapporttext.
    """
    if features.empty:
        return "Ingen data kunde analyseras."

    anomalies = features[features["is_anomaly"]]
    stat_anomalies = features[features["stat_anomaly"]]

    report = []
    report.append("=" * 60)
    report.append("Anomalidetekteringsrapport")
    report.append("=" * 60)
    report.append(f"\nAnalyserad period: {features.index.min()} - {features.index.max()}")
    report.append(f"Antal tidsperioder analyserade: {len(features)}")
    report.append("\n--- Isolation Forest ---")
    report.append(f"Anomalier detekterade: {len(anomalies)}")
    report.append("\n--- Statistisk baslinje (z-score) ---")
    report.append(f"Statistiska anomalier: {len(stat_anomalies)}")

    if len(anomalies) > 0:
        report.append("\nDetaljer om detekterade anomalier:")
        for idx, row in anomalies.iterrows():
            report.append(
                f"{idx}: {int(row['event_count'])} händelser, "
                f"severity snitt {row['avg_severity']:.1f}, "
                f"{int(row['unique_ips'])} unika IP:n, "
                f"score {row['anomaly_score']:.3f}"
            )

    report.append("\n" + "=" * 60)
    return "\n".join(report)


def main() -> None:
    """Kör hela detektionspipen från filinläsning till rapport och export.

    Funktionen fungerar som modulens CLI-ingång: den väljer indatafil, kör alla
    analyssteg i ordning, skriver rapport till terminal och sparar artefakter på disk.
    """
    import sys

    script_dir = Path(__file__).resolve().parent
    filepath = Path(sys.argv[1]) if len(sys.argv) > 1 else script_dir / "baseline_alerts.json"

    if not filepath.exists():
        fallback = script_dir / filepath
        if fallback.exists():
            filepath = fallback

    print(f"Laddar data från: {filepath}...")

    df = load_alerts(filepath)
    print(f"Laddade: {len(df)} händelser")

    features = extract_features(df, window="1h")
    print(f"Extraherade funktioner för {len(features)} tidsperioder")

    features = detect_anomalies(features)
    features = statistical_baseline(features)

    report = generate_report(features)
    print(report)

    results_path = script_dir / "anomaly_detection_results.csv"
    report_path = script_dir / "anomaly_report.txt"
    features.to_csv(results_path)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"\nResultat sparade i {results_path.name} och {report_path.name}")


if __name__ == "__main__":
    main()
