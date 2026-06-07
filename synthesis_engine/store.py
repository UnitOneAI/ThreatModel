"""Tiny JSON model store so models survive between MCP/CLI calls."""
from __future__ import annotations

import json
import os
from typing import Any

from .config import get_config


def _dir(models_dir: str | None) -> str:
    return models_dir or get_config().models_dir


def save_model(model_dict: dict[str, Any], models_dir: str | None = None) -> str:
    models_dir = _dir(models_dir)
    os.makedirs(models_dir, exist_ok=True)
    path = os.path.join(models_dir, f"{model_dict['id']}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(model_dict, fh, indent=2)
    return path


def load_model(model_id: str, models_dir: str | None = None) -> dict[str, Any] | None:
    models_dir = _dir(models_dir)
    path = os.path.join(models_dir, f"{model_id}.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def list_models(models_dir: str | None = None) -> list[str]:
    models_dir = _dir(models_dir)
    if not os.path.isdir(models_dir):
        return []
    return sorted(f[:-5] for f in os.listdir(models_dir) if f.endswith(".json"))
