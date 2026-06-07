"""Synthesis — open-source threat modeling + fixer engine, MCP-first.

A self-hostable agentic loop that turns repos + design docs into a STRIDE threat
model, then proposes and sandbox-validates fixes. Exposed as an MCP server so any
agent can call it.

Run modes (graceful degradation):
    quick    — one LLM pass (no infra beyond a key)
    agentic  — planner -> parallel skill reviewers -> critic
    fix      — + sandbox-validated remediation -> PR

Open-core: the loop, skills, fixer, and a *local* single-tenant Intent Graph are
Apache-2.0. The federated cross-customer graph and managed exploit-tier runtime are
the paid tier.
"""

__version__ = "0.1.0"

from .loop import run_fix, run_threat_model  # noqa: F401
from .types import (  # noqa: F401
    Component,
    DesignDoc,
    Dfd,
    Flow,
    Mitigation,
    RunTrace,
    Threat,
    ThreatModel,
)
