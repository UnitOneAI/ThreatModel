"""Central, typed configuration. All SYNTHESIS_* env vars are read HERE (one place),
validated, and consumed by the rest of the engine via get_config(). This replaces
ad-hoc os.environ reads scattered across modules (arch review D6).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

_HOME = os.path.expanduser("~")
_DEFAULT_DIR = os.path.join(_HOME, ".synthesis")


def _b(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _i(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _path(env: str, name: str) -> str:
    return os.environ.get(env, os.path.join(_DEFAULT_DIR, name))


@dataclass
class Config:
    # storage
    db: str = field(default_factory=lambda: _path("SYNTHESIS_DB", "intent_graph.db"))
    models_dir: str = field(default_factory=lambda: _path("SYNTHESIS_MODELS_DIR", "models"))
    audit_log: str = field(default_factory=lambda: _path("SYNTHESIS_AUDIT_LOG", "audit.log"))
    skills_dir: str | None = field(default_factory=lambda: os.environ.get("SYNTHESIS_SKILLS_DIR"))

    # providers
    anthropic_key: str | None = field(default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY"))
    openai_base: str | None = field(default_factory=lambda: os.environ.get("OPENAI_BASE_URL"))
    openai_key: str | None = field(default_factory=lambda: os.environ.get("OPENAI_API_KEY"))
    model: str | None = field(default_factory=lambda: os.environ.get("SYNTHESIS_MODEL"))
    worker_model: str | None = field(default_factory=lambda: os.environ.get("SYNTHESIS_WORKER_MODEL"))

    # local model
    use_local: bool = field(default_factory=lambda: _b("SYNTHESIS_USE_LOCAL"))
    local_model: str | None = field(default_factory=lambda: os.environ.get("SYNTHESIS_LOCAL_MODEL"))  # profile name
    local_repo: str | None = field(default_factory=lambda: os.environ.get("SYNTHESIS_LOCAL_REPO"))
    local_file: str | None = field(default_factory=lambda: os.environ.get("SYNTHESIS_LOCAL_FILE"))
    local_revision: str | None = field(default_factory=lambda: os.environ.get("SYNTHESIS_LOCAL_REVISION"))

    # safety / cost
    max_llm_calls: int = field(default_factory=lambda: _i("SYNTHESIS_MAX_LLM_CALLS", 200))
    max_workers: int = field(default_factory=lambda: _i("SYNTHESIS_MAX_WORKERS", 8))
    max_fixes: int = field(default_factory=lambda: _i("SYNTHESIS_MAX_FIXES", 5))

    # sandbox: 'off' (skip), 'docker' (rungs 1-3). 'auto' is intentionally NOT a
    # silent docker enable — docker access is opt-in (arch review S6).
    sandbox: str = field(default_factory=lambda: os.environ.get("SYNTHESIS_SANDBOX", "off"))

    # mcp transport auth (stdio is local-trust; sse/remote needs a token — S5)
    mcp_token: str | None = field(default_factory=lambda: os.environ.get("SYNTHESIS_MCP_TOKEN"))

    # test mode
    test_mode: bool = field(default_factory=lambda: _b("SYNTHESIS_TEST_MODE"))

    # logging
    log_level: str = field(default_factory=lambda: os.environ.get("SYNTHESIS_LOG_LEVEL", "INFO"))
    log_format: str = field(default_factory=lambda: os.environ.get("SYNTHESIS_LOG_FORMAT", "text"))  # text|json

    def validate(self) -> list[str]:
        warnings: list[str] = []
        if self.sandbox not in ("off", "docker"):
            warnings.append(f"SYNTHESIS_SANDBOX='{self.sandbox}' invalid; using 'off'")
            self.sandbox = "off"
        if self.log_format not in ("text", "json"):
            self.log_format = "text"
        if self.max_llm_calls < 1:
            self.max_llm_calls = 1
        return warnings


_cfg: Config | None = None


def get_config(refresh: bool = False) -> Config:
    """Process-wide config singleton. refresh=True re-reads env (used by tests)."""
    global _cfg
    if _cfg is None or refresh:
        _cfg = Config()
        _cfg.validate()
    return _cfg
