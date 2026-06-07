"""Bundled local-model provider — the no-API-key path that still does REAL analysis.

Uses llama.cpp (via llama-cpp-python) to run a quantized GGUF model in-process. The
weights are NOT vendored in git (multi-GB); they are pulled from the Hugging Face Hub
on first use, at a **pinned revision** (arch review S2), and cached under
~/.synthesis/models/llm/.

Profiles (SYNTHESIS_LOCAL_MODEL=<name>), all repo_id/file/revision verified:

  qwen3-4b            (DEFAULT) Qwen3-4B-Instruct-2507, Apache-2.0, ~2.5GB, instruct.
                      Clean license -> safe default for an Apache repo.
  foundation-sec      Foundation-Sec-8B-Instruct (Cisco), security-domain, ~4.9GB.
                      License: "other" (Cisco) -> opt-in, not the default.
  foundation-sec-apache  Foundation-Sec-8B base, Apache-2.0, ~4.9GB (NOT instruct).

Full override: SYNTHESIS_LOCAL_REPO + SYNTHESIS_LOCAL_FILE + SYNTHESIS_LOCAL_REVISION.

Install:  pip install 'synthesis-engine[local]'
"""
from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from typing import Any

from .config import get_config
from .llm import LLM, _safe_json
from .logging_setup import get_logger

_log = get_logger("local_llm")


@dataclass(frozen=True)
class ModelProfile:
    repo_id: str
    filename: str
    revision: str  # pinned commit SHA (supply-chain integrity)
    license: str


# Verified against the HF API (repo_id, exact filename, current main SHA).
PROFILES: dict[str, ModelProfile] = {
    "qwen3-4b": ModelProfile(
        "unsloth/Qwen3-4B-Instruct-2507-GGUF",
        "Qwen3-4B-Instruct-2507-Q4_K_M.gguf",
        "a06e946bb6b655725eafa393f4a9745d460374c9",
        "apache-2.0",
    ),
    "foundation-sec": ModelProfile(
        "gabriellarson/Foundation-Sec-8B-Instruct-GGUF",
        "Foundation-Sec-8B-Instruct-Q4_K_M.gguf",
        "a50bbd0bbb46a333c6cda11e9e8d7717ced39777",
        "other (Cisco)",
    ),
    "foundation-sec-apache": ModelProfile(
        "fdtn-ai/Foundation-Sec-8B-Q4_K_M-GGUF",
        "foundation-sec-8b-q4_k_m.gguf",
        "0f21603d7793fdc62134345f018296d870714688",
        "apache-2.0",
    ),
}
DEFAULT_PROFILE = "qwen3-4b"

_CACHE_DIR = os.environ.get(
    "SYNTHESIS_LOCAL_CACHE",
    os.path.join(os.path.expanduser("~"), ".synthesis", "models", "llm"),
)

_LOADED: dict[str, Any] = {}  # process-level model cache (load once)


class LocalLLM(LLM):
    name = "local"
    scripted = False  # produces REAL analysis, not templates

    def __init__(self, model_path: str, n_ctx: int = 8192):
        from llama_cpp import Llama  # type: ignore

        self.model_path = model_path
        if model_path not in _LOADED:
            chat_format = os.environ.get("SYNTHESIS_LOCAL_CHAT_FORMAT")  # else auto from gguf
            _LOADED[model_path] = Llama(
                model_path=model_path,
                n_ctx=int(os.environ.get("SYNTHESIS_LOCAL_CTX", n_ctx)),
                n_gpu_layers=int(os.environ.get("SYNTHESIS_LOCAL_GPU_LAYERS", "0")),
                chat_format=chat_format,
                verbose=False,
            )
        self.llm = _LOADED[model_path]
        self.model = os.path.basename(model_path)

    def complete(self, system: str, user: str, *, json_out: bool = False) -> str:
        kwargs: dict[str, Any] = {"max_tokens": 4096, "temperature": 0.2}
        if json_out:
            kwargs["response_format"] = {"type": "json_object"}
        out = self.llm.create_chat_completion(
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user}],
            **kwargs,
        )
        return out["choices"][0]["message"]["content"]

    def json(self, system: str, user: str) -> Any:
        return _safe_json(self.complete(system, user, json_out=True))


def local_available() -> bool:
    """True if llama-cpp-python is importable (the [local] extra is installed)."""
    try:
        import llama_cpp  # noqa: F401
        return True
    except ImportError:
        return False


def is_model_cached() -> bool:
    """True if a GGUF is already on disk (so we won't trigger a multi-GB download)."""
    if not os.path.isdir(_CACHE_DIR):
        return False
    for _root, _d, files in os.walk(_CACHE_DIR):
        if any(f.endswith(".gguf") for f in files):
            return True
    return False


def _resolve_target() -> tuple[str, str, str | None] | None:
    """Return (repo_id, filename_or_glob, revision) from config/profile, or None."""
    cfg = get_config()
    if cfg.local_file and os.path.exists(cfg.local_file):
        return (None, cfg.local_file, None)  # explicit local path
    if cfg.local_repo:
        fname = cfg.local_file or "*Q4_K_M*.gguf"
        return (cfg.local_repo, fname, cfg.local_revision)
    prof = PROFILES.get(cfg.local_model or DEFAULT_PROFILE)
    if not prof:
        _log.warning("unknown SYNTHESIS_LOCAL_MODEL '%s'; using default", cfg.local_model)
        prof = PROFILES[DEFAULT_PROFILE]
    return (prof.repo_id, prof.filename, cfg.local_revision or prof.revision)


def ensure_model(download: bool = True) -> str | None:
    """Resolve a local GGUF path, downloading from HF Hub at a pinned revision on
    first use if allowed. Returns the model path, or None if unavailable."""
    if not local_available():
        return None
    target = _resolve_target()
    if not target:
        return None
    repo_id, fname, revision = target
    if repo_id is None:  # explicit local file
        return fname
    try:
        from huggingface_hub import hf_hub_download, list_repo_files  # type: ignore
    except ImportError:
        return None
    os.makedirs(_CACHE_DIR, exist_ok=True)
    try:
        # if fname is a glob, resolve it against the repo's file list
        if any(ch in fname for ch in "*?["):
            files = [f for f in list_repo_files(repo_id, revision=revision) if f.endswith(".gguf")]
            match = next((f for f in files if fnmatch.fnmatch(f, fname)), files[0] if files else None)
            if not match:
                return None
            fname = match
        if not download and not is_model_cached():
            return None
        _log.info("resolving local model %s/%s @ %s", repo_id, fname, revision or "latest")
        return hf_hub_download(repo_id=repo_id, filename=fname, revision=revision,
                               cache_dir=_CACHE_DIR)
    except Exception as e:
        _log.warning("local model resolution failed for %s: %s", repo_id, e)
        return None


def get_local_llm(download: bool = True) -> LocalLLM | None:
    path = ensure_model(download=download)
    if not path:
        return None
    return LocalLLM(path)
