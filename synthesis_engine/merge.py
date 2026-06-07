"""Phase C — MERGE. Dedupe, validate every control id resolves, reconcile severity,
and run reachability (the noise-cut: a threat only ranks if an attacker-controlled
entry can actually reach its element across the DFD over a weakly-controlled path).
"""
from __future__ import annotations

from collections import deque

from .controls import validate_threat_controls
from .types import EXTERNAL_ENTITY, Dfd, Threat

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_RANK_SEV = {v: k for k, v in _SEV_RANK.items()}


def merge(dfd: Dfd, threats: list[Threat], trace=None) -> list[Threat]:
    # 1. drop threats whose target isn't in the DFD; null hallucinated control ids
    valid_targets = {c.id for c in dfd.components}
    cleaned: list[Threat] = []
    for t in threats:
        if t.target_element not in valid_targets:
            continue
        for bad in validate_threat_controls(t.owasp, t.cwe, t.mitre):
            t.owasp = None if t.owasp == bad else t.owasp
            t.cwe = None if t.cwe == bad else t.cwe
            t.mitre = None if t.mitre == bad else t.mitre
        cleaned.append(t)

    # 2. dedupe by (name, target); keep max severity
    by_key: dict[tuple, Threat] = {}
    for t in cleaned:
        key = (t.name, t.target_element)
        if key in by_key:
            if _SEV_RANK.get(t.severity, 2) > _SEV_RANK.get(by_key[key].severity, 2):
                by_key[key].severity = t.severity
        else:
            by_key[key] = t
    merged = list(by_key.values())

    # 3. reachability
    reach = _reachability(dfd)
    for t in merged:
        t.reachability = reach.get(t.target_element, "not_reachable")

    # 4. order: severity desc, exposed first
    merged.sort(key=lambda t: (_SEV_RANK.get(t.severity, 2),
                               1 if t.reachability == "exposed" else 0), reverse=True)
    if trace:
        trace.mark("merge", threats=len(merged),
                   exposed=sum(1 for t in merged if t.reachability == "exposed"))
    return merged


def _reachability(dfd: Dfd) -> dict[str, str]:
    """BFS from attacker entries; 'exposed' if reached via any none/partial crossing,
    'guarded' if only via all-strong paths, else not present (=> not_reachable)."""
    adj: dict[str, list] = {c.id: [] for c in dfd.components}
    for f in dfd.flows:
        if f.src in adj:
            adj[f.src].append(f)
    entries = [c.id for c in dfd.components if c.kind == EXTERNAL_ENTITY] or \
              [c.id for c in dfd.components if c.zone == "untrusted"]
    status: dict[str, str] = {}
    q: deque = deque()
    for e in entries:
        status[e] = "exposed"  # the entry itself is attacker-controlled
        q.append((e, True))
    while q:
        node, weak = q.popleft()
        for f in adj.get(node, []):
            new_weak = weak or f.control in ("none", "partial")
            new_status = "exposed" if new_weak else "guarded"
            cur = status.get(f.dst)
            if cur == "exposed":
                continue
            if cur is None or (cur == "guarded" and new_status == "exposed"):
                status[f.dst] = new_status
                q.append((f.dst, new_weak))
    return status
