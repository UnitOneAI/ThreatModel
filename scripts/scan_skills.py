#!/usr/bin/env python3
"""Skill injection-scan gate (arch review S1).

A skill body becomes a system prompt, so a malicious skill PR is prompt injection
against every user. This enforces the CONTRIBUTING rules in CI:

  1. control IDs the skill references must RESOLVE (no hallucinated frameworks)
  2. no instruction-injection / exfiltration / tool-escalation language in the body
  3. confidence_cap within bounds (skills earn trust from outcomes, not assertion)

Usage:  python scripts/scan_skills.py [skills_dir]
Exit:   0 clean, 1 violations found.
"""
from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from synthesis_engine import controls  # noqa: E402
from synthesis_engine.skills import load_skills  # noqa: E402

MAX_CAP = 0.85

# control-id shapes we recognise; each match must resolve in controls.py
_CONTROL_RE = re.compile(r"\b(A\d{2}:\d{4}|CWE-\d+|LLM\d{2}|T\d{4})\b")

# instruction-injection / exfiltration / escalation signatures
_INJECTION = [
    r"ignore (all |the )?(previous|prior|above) instructions",
    r"disregard (the |all )?(system|previous)",
    r"reveal (your|the) (system )?prompt",
    r"exfiltrat", r"base64\b", r"\bcurl\b", r"\bwget\b", r"rm\s+-rf",
    r"send .* to https?://", r"api[_ ]?key", r"secret key", r"credentials\b",
    r"allowed_tools", r"write_file", r"execute the following", r"run the following command",
]
_INJECTION_RE = [re.compile(p, re.IGNORECASE) for p in _INJECTION]


def scan(skills_dir: str | None = None) -> list[str]:
    violations: list[str] = []
    skills = load_skills(skills_dir)
    if not skills:
        return [f"no skills found in {skills_dir or 'default dir'}"]
    for sid, sk in skills.items():
        # 1. control IDs resolve
        for cid in set(_CONTROL_RE.findall(sk.body)):
            if not controls.resolve(cid):
                violations.append(f"{sid}: unresolved control id '{cid}'")
        # 2. injection signatures
        for rx in _INJECTION_RE:
            m = rx.search(sk.body)
            if m:
                violations.append(f"{sid}: injection signature '{m.group(0)}'")
        # 3. confidence cap bounds
        if sk.confidence_cap > MAX_CAP:
            violations.append(f"{sid}: confidence_cap {sk.confidence_cap} > {MAX_CAP}")
    return violations


def main() -> int:
    skills_dir = sys.argv[1] if len(sys.argv) > 1 else None
    violations = scan(skills_dir)
    if violations:
        print("SKILL SCAN FAILED:")
        for v in violations:
            print(f"  - {v}")
        return 1
    print("skill scan: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
