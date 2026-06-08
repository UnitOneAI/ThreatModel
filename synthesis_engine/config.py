"""Central, typed configuration. All SYNTHESIS_* env vars are read HERE (one place),
validated, and consumed by the rest of the engine via get_config(). This replaces
ad-hoc os.environ reads scattered across modules (arch review D6).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

_HOME = os.path.expanduser("~")
_DEFAULT_DIR = os.path.join(_HOME, ".synthesis")
def _settings_path() -> str:
    # read dynamically so env changes (and tests) are honored, not frozen at import
    return os.environ.get("SYNTHESIS_SETTINGS", os.path.join(_DEFAULT_DIR, "settings.json"))

# fields the Configure UI may persist (override env when set).
SETTINGS_KEYS = (
    "anthropic_key", "openai_base", "openai_key", "model", "worker_model",
    "github_token", "use_local", "local_model", "sandbox", "max_llm_calls",
)


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

    # github (private-repo fetch); settable from the Configure UI
    github_token: str | None = field(default_factory=lambda: os.environ.get("GITHUB_TOKEN"))

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


def load_settings() -> dict:
    """Persisted UI settings (plaintext JSON, like a .env). Empty if none."""
    try:
        with open(_settings_path(), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def save_settings(updates: dict) -> dict:
    """Merge updates into the settings file (only known keys), then take effect live.
    Empty-string values are ignored (so blank secret fields don't wipe existing ones)."""
    settings = load_settings()
    for k, v in updates.items():
        if k not in SETTINGS_KEYS:
            continue
        if isinstance(v, str) and v.strip() == "":
            continue
        settings[k] = v
    path = _settings_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(settings, fh, indent=2)
    try:
        os.chmod(path, 0o600)  # secrets — restrict perms
    except OSError:
        pass
    get_config(refresh=True)
    return settings


def _overlay_settings(cfg: Config) -> None:
    """UI-set settings override env (the Configure tab is the control plane)."""
    for k, v in load_settings().items():
        if k in SETTINGS_KEYS and v not in (None, ""):
            setattr(cfg, k, v)


_cfg: Config | None = None


def get_config(refresh: bool = False) -> Config:
    """Process-wide config singleton. refresh=True re-reads env + settings."""
    global _cfg
    if _cfg is None or refresh:
        _cfg = Config()
        _overlay_settings(_cfg)
        _cfg.validate()
    return _cfg
