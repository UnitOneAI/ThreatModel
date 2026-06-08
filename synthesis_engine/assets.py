"""Packaged static assets (the UnitOne logo) as data URIs, so the UI and reports are
fully self-contained — no external image requests."""
from __future__ import annotations

import base64
import os
from functools import lru_cache

_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")


@lru_cache(maxsize=4)
def logo_data_uri() -> str:
    path = os.path.join(_DIR, "logo.png")
    try:
        with open(path, "rb") as fh:
            b64 = base64.b64encode(fh.read()).decode("ascii")
        return f"data:image/png;base64,{b64}"
    except OSError:
        return ""  # logo is cosmetic; never fail a render over it
