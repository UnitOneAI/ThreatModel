"""Structured logging (arch review D7). Text by default; JSON when
SYNTHESIS_LOG_FORMAT=json. Modules use `logging.getLogger("synthesis." + name)`.
Never logs secrets — providers read keys directly and never pass them here.
"""
from __future__ import annotations

import json
import logging
import sys

_CONFIGURED = False


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging(level: str = "INFO", fmt: str = "text") -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler(sys.stderr)
    if fmt == "json":
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s",
                                                datefmt="%H:%M:%S"))
    root = logging.getLogger("synthesis")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.propagate = False
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger("synthesis." + name)
