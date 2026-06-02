"""
chas academy kurs 5 - Nätverks-, OT & AI-säkerhet
Grupp: Sidestep Error

Modulens ansvar:
Denna testmodul jämför två detektionsstrategier: regelbaserad logik och AI-baserad
anomalidetektering. Modulen skapar syntetiska angreppsscenarier, kör båda metoderna,
mäter exekveringstid och sammanställer resultat till terminal samt JSON-rapport.

Pedagogiskt syfte:
Att tydligt visa styrkor och svagheter i olika detektionsmodeller, exempelvis när
långsamma eller mönsterbaserade attacker passerar fasta tröskelvärden men ändå kan
fångas av en ML-baserad metod.
"""

import json
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))
from anomaly_detector import detect_anomalies, extract_features, statistical_baseline


# ---------------------------------------------------------------------------
# Scenariogeneratorer – skapar syntetisk Wazuh-alertdata
# ---------------------------------------------------------------------------

def generate_ssh_brute_force(n_attempts: int = 10) -> pd.DataFrame:
    """Skapa scenario med snabb SSH brute force under kort tidsintervall.

    Args:
        n_attempts: Antal misslyckade inloggningsförsök som genereras.

    Returns:
        DataFrame med attackhändelser plus bakgrundsbrus.
    """
    base = datetime(2026, 4, 30, 3, 0, 0)
    records = [
        {
            "timestamp": base + timedelta(seconds=i * 5),
            "rule_id": 5763,
            "rule_level": 5,
            "description": "sshd: Authentication failed.",
            "src_ip": "192.168.1.100",
            "dst_port": 22,
            "agent_name": "test-host",
        }
        for i in range(n_attempts)
    ]
    # Bakgrundsbrus under tidigare timmar
    records += [
        {
            "timestamp": base - timedelta(hours=i + 1),
            "rule_id": 1002,
            "rule_level": 2,
            "description": "Normal system event.",
            "src_ip": "10.0.0.1",
            "dst_port": 80,
            "agent_name": "test-host",
        }
        for i in range(6)
    ]
    return pd.DataFrame(records)


def generate_port_scan(n_ports: int = 1000) -> pd.DataFrame:
    """Skapa scenario för intensiv portskanning från en enskild källa.

    Args:
        n_ports: Antal destinationportar som skannas.

    Returns:
        DataFrame med skanningshändelser och normal trafikhistorik.
    """
    base = datetime(2026, 4, 30, 14, 0, 0)
    records = [
        {
            "timestamp": base + timedelta(seconds=i * 0.1),
            "rule_id": 1002,
            "rule_level": 3,
            "description": "Possible port scan.",
            "src_ip": "10.0.0.50",
            "dst_port": i + 1,
            "agent_name": "test-host",
        }
        for i in range(n_ports)
    ]
    records += [
        {
            "timestamp": base - timedelta(hours=i + 1),
            "rule_id": 1002,
            "rule_level": 2,
            "description": "Normal traffic.",
            "src_ip": f"10.0.0.{i + 10}",
            "dst_port": 80,
            "agent_name": "test-host",
        }
        for i in range(10)
    ]
    return pd.DataFrame(records)


def generate_file_change() -> pd.DataFrame:
    """Skapa scenario med kritisk filintegritetsavvikelse.

    Returns:
        DataFrame med en högkritisk filändringshändelse och historiskt brus.
    """
    base = datetime(2026, 4, 30, 2, 30, 0)
    records = [
        {
            "timestamp": base,
            "rule_id": 550,
            "rule_level": 7,
            "description": "Integrity checksum changed.",
            "src_ip": "unknown",
            "dst_port": 0,
            "agent_name": "test-host",
        }
    ]
    records += [
        {
            "timestamp": base - timedelta(hours=i + 2),
            "rule_id": 1002,
            "rule_level": 2,
            "description": "Normal event.",
            "src_ip": "10.0.0.1",
            "dst_port": 80,
            "agent_name": "test-host",
        }
        for i in range(6)
    ]
    return pd.DataFrame(records)


def generate_slow_brute_force(n_attempts: int = 36) -> pd.DataFrame:
    """Skapa scenario för lågintensiv, ihållande brute force.

    Attacken är avsiktligt utformad för att ofta passera fasta tröskelregler men
    samtidigt skapa ett långvarigt avvikande beteendemönster.

    Args:
        n_attempts: Antal misslyckade försök i hela scenariot.

    Returns:
        DataFrame med lågintensiva attackhändelser och bakgrundstrafik.
    """
    base = datetime(2026, 4, 30, 18, 0, 0)
    records: list[dict[str, object]] = [
        {
            "timestamp": base + timedelta(minutes=i * 10),
            "rule_id": 5763,
            "rule_level": 5,
            "description": "sshd: Authentication failed.",
            "src_ip": "172.16.0.200",
            "dst_port": 22,
            "agent_name": "test-host",
        }
        for i in range(n_attempts)
    ]
    # Bakgrundsbrus: 2–3 normala händelser per timme under 24h
    for i in range(48):
        records.append({
            "timestamp": base - timedelta(hours=i // 2, minutes=(i % 2) * 25),
            "rule_id": 1002,
            "rule_level": 2,
            "description": "Normal event.",
            "src_ip": f"10.0.0.{(i % 20) + 5}",
            "dst_port": 80,
            "agent_name": "test-host",
        })
    return pd.DataFrame(records)


# ---------------------------------------------------------------------------
# Detektionsmetoder
# ---------------------------------------------------------------------------

def rule_based_detection(df: pd.DataFrame, scenario: str) -> tuple[bool, float]:
    """Simulera regelbaserad detektering med statiska tröskelvärden.

    Funktionen representerar ett förenklat SIEM/Wazuh-upplägg där varje scenario
    har explicit logik med fasta gränser.

    Args:
        df: Händelsedata för aktuellt scenario.
        scenario: Scenarionyckel som styr regeluppsättning.

    Returns:
        Tuple med detektionsutfall och körtid i sekunder.
    """
    start = time.perf_counter()
    detected = False

    if scenario == "ssh_brute":
        ssh = df[df["rule_id"] == 5763].copy()
        if not ssh.empty:
            ssh = ssh.set_index("timestamp").sort_index()
            if ssh.resample("1min").size().max() >= 5:
                detected = True

    elif scenario == "port_scan":
        per_ip = df.groupby("src_ip")["dst_port"].nunique()
        if (per_ip > 100).any():
            detected = True

    elif scenario == "file_change":
        if not df[(df["rule_id"] == 550) & (df["rule_level"] >= 7)].empty:
            detected = True

    elif scenario == "slow_brute":
        ssh = df[df["rule_id"] == 5763].copy()
        if not ssh.empty:
            ssh = ssh.set_index("timestamp").sort_index()
            # Standardregel kräver ≥10 per timme; långsam attack når bara ~2/timme
            if ssh.resample("1h").size().max() >= 10:
                detected = True

    return detected, time.perf_counter() - start


def ai_detection(df: pd.DataFrame) -> tuple[bool, float]:
    """Kör AI-baserad detekteringskedja på scenario-data.

    Metoden extraherar features, tillämpar Isolation Forest och kompletterar med
    statistisk baslinje för att avgöra om scenariot innehåller anomalier.

    Args:
        df: Händelsedata för scenario.

    Returns:
        Tuple med detektionsutfall och körtid i sekunder.
    """
    start = time.perf_counter()

    features = extract_features(df, window="1h")
    if features.empty:
        return False, time.perf_counter() - start

    features = detect_anomalies(features, contamination=0.15)
    features = statistical_baseline(features, threshold_sigma=2.0)

    detected = bool(features["is_anomaly"].any() or features["stat_anomaly"].any())
    return detected, time.perf_counter() - start


# ---------------------------------------------------------------------------
# Testsvit
# ---------------------------------------------------------------------------

SCENARIOS = [
    ("SSH brute force (10 försök)",        "ssh_brute",   generate_ssh_brute_force),
    ("Portskanning (top 1000)",             "port_scan",   generate_port_scan),
    ("Kritisk filändring",                  "file_change", generate_file_change),
    ("Långsam brute force (1 försök/min)", "slow_brute",  generate_slow_brute_force),
]


def run_tests() -> dict:
    """Exekvera samtliga scenarier och sammanställ jämförelseresultat.

    Funktionen kör generator, regelbaserad detektering och AI-detektering för
    varje scenario. Resultatet returneras i ett serialiserbart dictionary-format.

    Returns:
        Struktur med metadata och mätvärden per scenario.
    """
    results = {
        "test_scenario": "SSH brute force + portskanning + filändring + långsam brute force",
        "measurement_date": datetime.now().isoformat(),
        "tests": [],
    }

    print("=" * 62)
    print("  Detekteringstest: regelbaserad vs AI")
    print("=" * 62)

    for name, key, generator in SCENARIOS:
        print(f"\n[SCENARIO] {name}")
        df = generator()

        rule_detected, rule_time = rule_based_detection(df, key)
        ai_detected,   ai_time   = ai_detection(df)

        improvement = None
        if rule_detected and ai_detected and rule_time > 0:
            improvement = (rule_time - ai_time) / rule_time * 100

        result = {
            "attack":                    name,
            "rule_based_detection_sec":  round(rule_time, 6),
            "ai_detection_sec":          round(ai_time, 6),
            "rule_based_detected":       rule_detected,
            "ai_detected":               ai_detected,
            "improvement_pct":           round(improvement, 1) if improvement is not None else None,
        }
        results["tests"].append(result)

        rb_label = "DETEKTERAD    " if rule_detected else "EJ DETEKTERAD "
        ai_label = "DETEKTERAD    " if ai_detected   else "EJ DETEKTERAD "
        print(f"  Regelbaserad : {rb_label} ({rule_time * 1000:7.2f} ms)")
        print(f"  AI           : {ai_label} ({ai_time  * 1000:7.2f} ms)")
        if improvement is not None:
            direction = "snabbare" if improvement > 0 else "långsammare"
            print(f"  Förbättring  : {improvement:+.1f}% ({direction})")
        else:
            missed = []
            if not rule_detected:
                missed.append("regelbaserad")
            if not ai_detected:
                missed.append("AI")
            print(f"  Förbättring  : N/A ({', '.join(missed)} missade attacken)")

    return results


def print_summary(results: dict) -> None:
    """Skriv en läsbar slutsammanfattning till terminalen.

    Sammanfattningen visar detektionsgrad per metod, medelförbättring i tid
    när båda metoderna detekterar, samt vilka scenarier som endast fångats av
    den ena metoden.

    Args:
        results: Resultatstruktur från `run_tests`.
    """
    tests = results["tests"]
    print("\n" + "=" * 62)
    print("  SAMMANFATTNING")
    print("=" * 62)

    rb_detected = sum(1 for t in tests if t["rule_based_detected"])
    ai_detected = sum(1 for t in tests if t["ai_detected"])
    total = len(tests)

    print(f"  Detektionsgrad regelbaserad : {rb_detected}/{total}")
    print(f"  Detektionsgrad AI           : {ai_detected}/{total}")

    improvements = [t["improvement_pct"] for t in tests if t["improvement_pct"] is not None]
    if improvements:
        avg = sum(improvements) / len(improvements)
        print(f"  Genomsnittlig förbättring   : {avg:+.1f}%")
        print(f"  (baserat på {len(improvements)} scenario(n) där båda detekterade)")
    else:
        print("  Genomsnittlig förbättring   : N/A")

    only_ai = [t["attack"] for t in tests if t["ai_detected"] and not t["rule_based_detected"]]
    if only_ai:
        print(f"\n  Attacker som bara AI hittade:")
        for a in only_ai:
            print(f"    - {a}")

    only_rule = [t["attack"] for t in tests if t["rule_based_detected"] and not t["ai_detected"]]
    if only_rule:
        print(f"\n  Attacker som bara regelbaserad hittade:")
        for a in only_rule:
            print(f"    - {a}")

    print("=" * 62)


def main() -> None:
    """Kör hela jämförelsetestet och spara resultat till JSON-fil."""
    results = run_tests()
    print_summary(results)

    out = Path(__file__).parent / "detection_comparison.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\nResultat sparade i {out.name}")


if __name__ == "__main__":
    main()
