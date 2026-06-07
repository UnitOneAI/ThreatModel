"""Append-only audit log (arch review S9).

A security tool that proposes code changes and executes code must keep an immutable
record of what it did. Each event is one JSON line: scan start/finish, threats
emitted, fixes proposed, and sandbox executions. Append-only (open 'a'); rotate or
ship to a SIEM in production. No secrets are recorded.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any

from .config import get_config
from .logging_setup import get_logger

_log = get_logger("audit")


def record(event: str, **fields: Any) -> None:
    cfg = get_config()
    entry = {"ts": round(time.time(), 3), "event": event, **fields}
    try:
        path = cfg.audit_log
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception as e:  # never let auditing break a run, but do surface it
        _log.warning("audit write failed: %s", e)


def read_recent(limit: int = 100) -> list[dict[str, Any]]:
    cfg = get_config()
    if not os.path.exists(cfg.audit_log):
        return []
    with open(cfg.audit_log, encoding="utf-8") as fh:
        lines = fh.readlines()[-limit:]
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return out
