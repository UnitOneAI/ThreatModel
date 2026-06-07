"""LLM provider abstraction.

Three providers, selected from env, in priority order:
  - Anthropic            ANTHROPIC_API_KEY            (urllib, no SDK dependency)
  - OpenAI-compatible    OPENAI_BASE_URL + OPENAI_API_KEY  (local models, vLLM, etc.)
  - Scripted             always available; deterministic; zero network

The scripted provider is what makes the whole engine runnable offline and in CI.
It returns structured JSON keyed off the task so the loop produces a coherent,
deterministic model with no key — the same "demo mode" idea as upstream Synthesis.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any

DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-5-20250929"
WORKER_MODEL_ENV = "SYNTHESIS_WORKER_MODEL"  # cheap model for Phase-B fan-out


class LLM:
    name = "base"
    scripted = True

    def complete(self, system: str, user: str, *, json_out: bool = False) -> str:
        raise NotImplementedError

    def json(self, system: str, user: str) -> Any:
        raw = self.complete(system, user, json_out=True)
        return _safe_json(raw)


class AnthropicLLM(LLM):
    name = "anthropic"
    scripted = False

    def __init__(self, api_key: str, model: str | None = None):
        self.api_key = api_key
        self.model = model or os.environ.get("SYNTHESIS_MODEL", DEFAULT_ANTHROPIC_MODEL)

    def complete(self, system: str, user: str, *, json_out: bool = False) -> str:
        body = {
            "model": self.model,
            "max_tokens": 4096,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(body).encode(),
            headers={
                "content-type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
            data = json.loads(resp.read().decode())
        return "".join(b.get("text", "") for b in data.get("content", []))


class OpenAICompatibleLLM(LLM):
    name = "openai-compatible"
    scripted = False

    def __init__(self, base_url: str, api_key: str, model: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model or os.environ.get("SYNTHESIS_MODEL", "gpt-4o-mini")

    def complete(self, system: str, user: str, *, json_out: bool = False) -> str:
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if json_out:
            body["response_format"] = {"type": "json_object"}
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(body).encode(),
            headers={
                "content-type": "application/json",
                "authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
            data = json.loads(resp.read().decode())
        return data["choices"][0]["message"]["content"]


class TestLLM(LLM):
    """CI / test mode ONLY. Produces deterministic TEMPLATED output (fixtures), not a
    real analysis of the target. The loop branches on `.scripted` to use the template
    generators. Never selected unless explicitly enabled (allow_test / SYNTHESIS_TEST_MODE)
    so a real run can never silently emit fixture data."""

    name = "test"
    scripted = True

    def complete(self, system: str, user: str, *, json_out: bool = False) -> str:
        return "{}" if json_out else ""

    def json(self, system: str, user: str) -> Any:
        return {}


# back-compat alias
ScriptedLLM = TestLLM


class NoProviderError(RuntimeError):
    """Raised when no real LLM provider is configured and test mode isn't allowed."""


_NO_PROVIDER_MSG = (
    "No LLM provider configured. To run a real scan, do one of:\n"
    "  1. export ANTHROPIC_API_KEY=sk-ant-...            (hosted, best quality)\n"
    "  2. export OPENAI_BASE_URL=... OPENAI_API_KEY=...  (any OpenAI-compatible / local server)\n"
    "  3. pip install 'synthesis-engine[local]' && export SYNTHESIS_USE_LOCAL=1\n"
    "     (bundled local model: Foundation-Sec-8B, Apache-2.0, downloaded on first use)\n"
    "For CI/demo of the machinery only (TEMPLATED, not a real scan): pass --test "
    "or SYNTHESIS_TEST_MODE=1."
)


class BudgetExceeded(RuntimeError):
    """Raised when a run exceeds its configured LLM-call budget (arch review S3)."""


class BudgetedLLM(LLM):
    """Wraps a provider and caps the number of LLM calls per run, so a large design
    can't trigger unbounded fan-out / runaway spend."""

    def __init__(self, inner: LLM, max_calls: int):
        self.inner = inner
        self.max_calls = max_calls
        self.calls = 0
        self.name = inner.name
        self.scripted = inner.scripted

    def _tick(self) -> None:
        self.calls += 1
        if self.calls > self.max_calls:
            raise BudgetExceeded(
                f"LLM call budget exceeded ({self.max_calls}). Raise SYNTHESIS_MAX_LLM_CALLS "
                f"or narrow the input."
            )

    def complete(self, system: str, user: str, *, json_out: bool = False) -> str:
        self._tick()
        return self.inner.complete(system, user, json_out=json_out)

    def json(self, system: str, user: str) -> Any:
        self._tick()
        return self.inner.json(system, user)


def get_llm(prefer_worker: bool = False, allow_test: bool = False) -> LLM:
    """Provider ladder: Anthropic -> OpenAI-compatible -> bundled local model ->
    (only if explicitly allowed) test mode. Raises NoProviderError otherwise so a
    real run never silently falls back to fixtures."""
    from .config import get_config
    cfg = get_config()
    if cfg.anthropic_key:
        model = cfg.worker_model if prefer_worker else cfg.model
        return AnthropicLLM(cfg.anthropic_key, model=model)
    if cfg.openai_base and cfg.openai_key:
        return OpenAICompatibleLLM(cfg.openai_base, cfg.openai_key, model=cfg.model)

    # bundled local model: auto if installed + (opted in or already downloaded)
    from .local_llm import get_local_llm, is_model_cached, local_available
    if local_available() and (cfg.use_local or is_model_cached()):
        local = get_local_llm(download=cfg.use_local)
        if local is not None:
            return local

    if allow_test or cfg.test_mode:
        return TestLLM()
    raise NoProviderError(_NO_PROVIDER_MSG)


def _safe_json(raw: str) -> Any:
    raw = raw.strip()
    if not raw:
        return {}
    # tolerate ```json fences
    if raw.startswith("```"):
        raw = raw.split("```", 2)[1]
        if raw.startswith("json"):
            raw = raw[4:]
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # last-ditch: grab the outermost {...}
        a, b = raw.find("{"), raw.rfind("}")
        if a >= 0 and b > a:
            try:
                return json.loads(raw[a : b + 1])
            except json.JSONDecodeError:
                return {}
        return {}
