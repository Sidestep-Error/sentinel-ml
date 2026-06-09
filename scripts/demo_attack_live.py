"""Best Heist-demo — mimicry-attack mot live sentinel-ml-service.

Visar att TF-IDF-detektorn kan luras av kamouflerade attackloggar.
Kör lokalt, anropar Hetzner (eller valfri URL) via HTTP.

Usage:
  python scripts/demo_attack_live.py
  python scripts/demo_attack_live.py --url https://sentinel-ml.ditt-kluster.example
  python scripts/demo_attack_live.py --url http://localhost:8080
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import typer

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from sentinel_ml.log_anomaly.attack import camouflage

def _get_attack_logs(n: int = 30, seed: int = 42) -> list[str]:
    """Generera varierade attackloggar lokalt — skickas till remote API."""
    from sentinel_ml.log_anomaly.generate_data import generate_logs
    records = generate_logs(n_normal=0, n_attack=n, seed=seed)
    return [r["line"] for r in records]


def _predict(url: str, logs: list[str]) -> list[dict]:
    resp = httpx.post(f"{url}/predict/log-anomaly", json={"logs": logs}, timeout=10.0)
    resp.raise_for_status()
    return resp.json()["predictions"]


def _print_results(predictions: list[dict], title: str) -> int:
    flagged = sum(1 for p in predictions if p["is_anomaly"])
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")
    for p in predictions:
        icon = "⚠  FLAGGAD" if p["is_anomaly"] else "   ok"
        print(f"  {icon}  score={p['score']:+.3f}  {p['line'][:65]}")
    print(f"\n  Detekterade: {flagged}/{len(predictions)}")
    return flagged


def main(
    url: str = typer.Option("http://localhost:8080", envvar="SENTINEL_ML_URL",
                            help="Base URL till sentinel-ml-service"),
) -> None:
    attack_logs = _get_attack_logs(n=30)

    print("=" * 60)
    print("  Best Heist Demo — Mimicry Attack mot sentinel-ml")
    print(f"  Target: {url}")
    print(f"  Attackloggar: {len(attack_logs)} (genererade lokalt, skickas till live API)")
    print("=" * 60)

    # Steg 1: Originala attackloggar
    print("\n[1/3] Skickar originala attackloggar till live service...")
    original_preds = _predict(url, attack_logs)
    detected_before = _print_results(original_preds, "ORIGINAL attackloggar")

    # Steg 2: Kamouflera loggarna
    camouflaged = [camouflage(line) for line in attack_logs]
    print(f"\n[2/3] Kamuflerar {len(attack_logs)} loggar med godartade prefix/suffix...")
    print("\n  Exempel på kamouflering:")
    print(f"  FÖR:   {attack_logs[0][:65]}")
    print(f"  EFTER: {camouflaged[0][:65]}")

    # Steg 3: Kamuflerade loggar mot samma service
    print("\n[3/3] Skickar kamuflerade loggar till SAMMA live service...")
    camouflaged_preds = _predict(url, camouflaged)
    detected_after = _print_results(camouflaged_preds, "KAMUFLERADE attackloggar")

    # Sammanfattning
    n = len(attack_logs)
    evaded = max(0, detected_before - detected_after)
    missed_base = n - detected_before

    print(f"\n{'═'*60}")
    print(f"  RESULTAT")
    print(f"{'═'*60}")
    print(f"  Attackloggar totalt:       {n}")
    print(f"  Detekterade (original):    {detected_before}/{n}  ({detected_before/n*100:.0f}%)")
    print(f"  Detekterade (kamuflerade): {detected_after}/{n}  ({detected_after/n*100:.0f}%)")
    print(f"  Undanmanövrerade av attack:{evaded} loggar")
    print(f"  Missades redan från start: {missed_base} loggar  ← redan ett problem")
    print()
    if evaded > 0:
        print("  ⚠  Mimicry-attack lyckades delvis — keyword-kamouflering fungerar.")
    else:
        print("  De starka attackmönstren (SSH brute force, AVC) klarar kamouflering.")
        print("  Men observera: {missed_base} loggar undkommer redan UTAN attack.".format(
            missed_base=missed_base))
        print("  Reverse shell och path traversal evade detection utan modifiering.")
    print()
    print("  Motåtgärd: semantisk analys (LLM) eller sekvensbaserad detektion.")
    print(f"{'═'*60}")


if __name__ == "__main__":
    typer.run(main)
