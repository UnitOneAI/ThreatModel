"""Phase D — CRITIQUE. An AppSec reviewer challenges the findings: it cuts noise
(downgrades threats whose element no attacker path reaches) and flags high-severity
threats that lack a mitigation. It also emits per-skill accept/reject decisions that
feed the local confidence-calibration flywheel (synthesis_engine/memory.py).
"""
from __future__ import annotations

from .types import Threat

_SEV_DOWN = {"critical": "high", "high": "medium", "medium": "low", "low": "low"}


def critique(threats: list[Threat], trace=None) -> tuple[list[Threat], list[tuple[str, bool]]]:
    decisions: list[tuple[str, bool]] = []  # (skill_id, accepted)
    notes: list[str] = []
    for t in threats:
        if t.reachability == "not_reachable":
            old = t.severity
            t.severity = _SEV_DOWN.get(t.severity, t.severity)
            t.status = "rejected"
            notes.append(f"{t.id}: no attacker path to {t.target_element}; "
                         f"{old}->{t.severity}, deprioritized")
            if t.skill_id:
                decisions.append((t.skill_id, False))
            continue
        if t.severity in ("critical", "high") and not (t.mitigation and t.mitigation.prose):
            notes.append(f"{t.id}: high severity with no mitigation — needs revision")
        if t.skill_id:
            decisions.append((t.skill_id, True))
    if trace:
        trace.mark("critique", reviewed=len(threats), notes=notes[:20],
                   accepted=sum(1 for _, a in decisions if a),
                   rejected=sum(1 for _, a in decisions if not a))
    return threats, decisions
