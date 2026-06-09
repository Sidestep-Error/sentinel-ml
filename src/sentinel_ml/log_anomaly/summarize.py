"""LLM-based incident summary generation via Ollama.

Uses the project's existing OllamaClient. Falls back to a rule-based summary
if Ollama is unavailable, so the rest of the pipeline always gets a string.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "Du är en SOC-analytiker som skriver korta incidentsammanfattningar på svenska. "
    "Givet en lista med säkerhetslogganomalier, skriv en 2-3 meningars sammanfattning "
    "som beskriver vad som hände, allvarlighetsgraden och rekommenderade åtgärder."
)


def _rule_based_summary(alerts: list[dict[str, Any]]) -> str:
    if not alerts:
        return "Inga anomalier detekterade."
    counts: dict[str, int] = {}
    for a in alerts:
        sev = str(a.get("severity", "unknown"))
        counts[sev] = counts.get(sev, 0) + 1
    parts = [f"{v} {k}" for k, v in sorted(counts.items())]
    return f"Detekterade {len(alerts)} larm: {', '.join(parts)}. Granska loggarna för detaljer."


def summarize_alerts(
    alerts: list[dict[str, Any]],
    *,
    client: Any | None = None,
) -> str:
    """Generate an LLM incident summary. Falls back to rule-based if Ollama fails."""
    if not alerts:
        return "Inga anomalier detekterade."

    alert_text = "\n".join(
        f"- [{str(a.get('severity', '?')).upper()}] {a.get('timestamp', '?')}: {a.get('details', {})}"
        for a in alerts
    )
    prompt = f"Säkerhetsanomalier:\n{alert_text}\n\nSkriv en incidentsammanfattning."

    try:
        from sentinel_ml.llm.ollama_client import OllamaClient  # noqa: PLC0415
        llm = client or OllamaClient()
        response = llm.generate(prompt, system=_SYSTEM_PROMPT)
        return response.text
    except Exception:  # noqa: BLE001
        logger.warning("Ollama unavailable — using rule-based summary")
        return _rule_based_summary(alerts)
