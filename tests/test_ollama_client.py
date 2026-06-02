from __future__ import annotations

import httpx

from sentinel_ml.llm.ollama_client import OllamaClient


class DummyResponse:
    def __init__(self, payload: dict):
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


def test_generate_posts_expected_payload(monkeypatch):
    captured: dict = {}

    def fake_post(url: str, *, json: dict, timeout: float) -> DummyResponse:
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        return DummyResponse({"response": '{"category":"phishing","confidence":0.8,"rationale":"x"}'})

    monkeypatch.setattr(httpx, "post", fake_post)

    client = OllamaClient(host="http://ollama.test", model="llama3.2:3b", timeout=12.5)
    response = client.generate("report text", system="system prompt", temperature=0.2)

    assert captured["url"] == "http://ollama.test/api/generate"
    assert captured["timeout"] == 12.5
    assert captured["json"] == {
        "model": "llama3.2:3b",
        "prompt": "report text",
        "stream": False,
        "options": {"temperature": 0.2},
        "system": "system prompt",
    }
    assert response.text == '{"category":"phishing","confidence":0.8,"rationale":"x"}'
    assert response.model == "llama3.2:3b"
