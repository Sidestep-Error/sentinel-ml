"""Thin Ollama HTTP client.

Why a custom client instead of `ollama` Python package: keeps dependency
graph small and makes mocking trivial (single `httpx.post` to stub).
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from sentinel_ml.config import get_settings


@dataclass
class LLMResponse:
    text: str
    model: str
    raw: dict


class OllamaClient:
    """Synchronous Ollama client. Async variant can be added when needed."""

    def __init__(self, host: str | None = None, model: str | None = None, timeout: float = 60.0):
        settings = get_settings()
        self.host = host or settings.ollama_host
        self.model = model or settings.ollama_model
        self.timeout = timeout

    def generate(self, prompt: str, *, system: str | None = None, temperature: float = 0.0) -> LLMResponse:
        """Single-turn generation. Returns the assistant text."""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if system:
            payload["system"] = system

        response = httpx.post(f"{self.host}/api/generate", json=payload, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        return LLMResponse(text=data.get("response", ""), model=self.model, raw=data)
