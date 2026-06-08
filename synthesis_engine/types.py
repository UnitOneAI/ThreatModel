"""Core data model. Stdlib only so the engine runs offline with no deps.

The output shape mirrors what the Synthesis UI / `/spine` render, so the same
renderers work against either backend.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

# --- STRIDE ---------------------------------------------------------------
SPOOFING = "spoofing"
TAMPERING = "tampering"
REPUDIATION = "repudiation"
INFO_DISCLOSURE = "information_disclosure"
DOS = "denial_of_service"
ELEVATION = "elevation_of_privilege"
STRIDE = [SPOOFING, TAMPERING, REPUDIATION, INFO_DISCLOSURE, DOS, ELEVATION]

# Element kinds (Microsoft SDL DFD vocabulary)
EXTERNAL_ENTITY = "external_entity"
PROCESS = "process"
DATA_STORE = "data_store"
DATA_FLOW = "data_flow"
TRUST_BOUNDARY = "trust_boundary"

# STRIDE applicability per element kind (SDL rules) — drives the coverage matrix.
STRIDE_APPLICABILITY = {
    EXTERNAL_ENTITY: {SPOOFING, REPUDIATION},
    PROCESS: set(STRIDE),
    DATA_STORE: {TAMPERING, REPUDIATION, INFO_DISCLOSURE, DOS},
    DATA_FLOW: {TAMPERING, INFO_DISCLOSURE, DOS},
}

SEVERITIES = ["critical", "high", "medium", "low", "info"]

# actor -> (capability, motivation) for the spine 'Threat actors' panel.
ACTOR_PROFILES = {
    "External Attacker (Opportunistic)": ("low-medium", "financial gain, data theft"),
    "External Attacker (Targeted)": ("medium-high", "IP theft, espionage, disruption"),
    "Malicious Insider": ("high (privileged access)", "financial gain, sabotage"),
    "Automated Bot/Scraper": ("low", "resource abuse, credential stuffing"),
    "AI/LLM Threat Actor": ("medium-high", "prompt injection, data exfiltration, model abuse"),
    "Supply Chain Attacker": ("medium-high", "broad downstream compromise"),
}


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@dataclass
class Component:
    id: str
    name: str
    kind: str  # one of EXTERNAL_ENTITY / PROCESS / DATA_STORE
    zone: str = "untrusted"  # trust zone label
    source_refs: list[str] = field(default_factory=list)
    embedding: list[float] | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("embedding", None)
        return d


@dataclass
class Flow:
    id: str
    src: str  # component id
    dst: str  # component id
    label: str = ""
    crosses_boundary: bool = False
    control: str = "none"  # strong | partial | none

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Dfd:
    components: list[Component] = field(default_factory=list)
    flows: list[Flow] = field(default_factory=list)

    def component(self, cid: str) -> Component | None:
        return next((c for c in self.components if c.id == cid), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "components": [c.to_dict() for c in self.components],
            "flows": [f.to_dict() for f in self.flows],
        }


@dataclass
class Mitigation:
    prose: str = ""
    code_fix: str | None = None  # unified diff
    skill_id: str | None = None
    confidence: float = 0.0
    pr_url: str | None = None
    security_verified: bool = False
    behavior_verified: bool = False
    sandbox_rungs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Threat:
    id: str
    name: str
    stride: str
    target_element: str  # component id
    element_kind: str
    severity: str = "medium"
    likelihood: str = "medium"
    impact: str = "medium"
    owasp: str | None = None  # e.g. "A01:2021"
    cwe: str | None = None  # e.g. "CWE-287"
    mitre: str | None = None  # e.g. "T1190"
    actor: str | None = None
    evidence: str = ""
    reachability: str = "unknown"  # exposed | guarded | not_reachable | unknown
    status: str = "open"  # open | security_verified | mitigated | accepted | rejected
    skill_id: str | None = None
    mitigation: Mitigation | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["mitigation"] = self.mitigation.to_dict() if self.mitigation else None
        return d


@dataclass
class DesignDoc:
    """A single ingested system: N repos + N docs merged into one model."""
    sources: list[str] = field(default_factory=list)   # repo URLs
    docs: list[str] = field(default_factory=list)       # doc refs (paths / urls / "inline")
    doc_excerpt: str = ""                               # merged excerpt for display
    focus: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RunTrace:
    phases: list[dict[str, Any]] = field(default_factory=list)

    def mark(self, phase: str, **info: Any) -> None:
        self.phases.append({"phase": phase, "t": round(time.time(), 3), **info})

    def to_dict(self) -> dict[str, Any]:
        return {"phases": self.phases}


@dataclass
class ThreatModel:
    id: str
    design: DesignDoc
    dfd: Dfd
    threats: list[Threat] = field(default_factory=list)
    mode: str = "agentic"
    created: float = field(default_factory=lambda: round(time.time(), 3))
    trace: RunTrace = field(default_factory=RunTrace)

    # --- derived artifacts ------------------------------------------------
    def stride_matrix(self) -> dict[str, Any]:
        """element x STRIDE coverage: covered / gap / n_a."""
        rows = []
        covered = gaps = applicable = 0
        for c in self.dfd.components:
            applic = STRIDE_APPLICABILITY.get(c.kind, set())
            cells = {}
            for cat in STRIDE:
                if cat not in applic:
                    cells[cat] = "n_a"
                    continue
                applicable += 1
                hit = any(t.target_element == c.id and t.stride == cat for t in self.threats)
                cells[cat] = "covered" if hit else "gap"
                covered += 1 if hit else 0
                gaps += 0 if hit else 1
            rows.append({"component": c.id, "name": c.name, "kind": c.kind, "cells": cells})
        return {"rows": rows, "applicable": applicable, "covered": covered, "gaps": gaps}

    def owasp_coverage(self) -> dict[str, int]:
        cov: dict[str, int] = {}
        for t in self.threats:
            if t.owasp:
                cov[t.owasp] = cov.get(t.owasp, 0) + 1
        return cov

    def actors(self) -> list[str]:
        return sorted({t.actor for t in self.threats if t.actor})

    def trust_zones(self) -> list[str]:
        return sorted({c.zone for c in self.dfd.components if c.zone})

    def threat_actors_detail(self) -> list[dict[str, Any]]:
        """Actors with capability/motivation + how many threats reference each
        (spine 'Threat actors' panel shape)."""
        rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        agg: dict[str, dict[str, Any]] = {}
        for t in self.threats:
            if not t.actor:
                continue
            a = agg.setdefault(t.actor, {"name": t.actor, "count": 0, "max_severity": "low"})
            a["count"] += 1
            if rank.get(t.severity, 0) > rank.get(a["max_severity"], 0):
                a["max_severity"] = t.severity
        out = []
        for name, a in sorted(agg.items(), key=lambda kv: -kv[1]["count"]):
            cap, mot = ACTOR_PROFILES.get(name, ("medium", "opportunistic compromise"))
            out.append({**a, "capability": cap, "motivation": mot})
        return out

    def trust_boundaries(self) -> list[dict[str, Any]]:
        """Boundary crossings derived from the DFD (spine 'Trust boundaries' panel):
        from -> to, the control on the crossing, and the gap when it's weak."""
        by_id = {c.id: c for c in self.dfd.components}
        seen, out = set(), []
        for f in self.dfd.flows:
            if not f.crosses_boundary:
                continue
            src, dst = by_id.get(f.src), by_id.get(f.dst)
            if not src or not dst:
                continue
            key = (src.name, dst.name)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "from": f"{src.name} ({src.zone})", "to": f"{dst.name} ({dst.zone})",
                "control": f.control,
                "gap": None if f.control == "strong" else f"unauthenticated/weak crossing ({f.control})",
            })
        return out

    def mermaid(self) -> str:
        from .viz import dfd_to_mermaid
        return dfd_to_mermaid(self.dfd, self.threats)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "design": self.design.to_dict(),
            "dfd": self.dfd.to_dict(),
            "mermaid": self.mermaid(),
            "threats": [t.to_dict() for t in self.threats],
            "stride_matrix": self.stride_matrix(),
            "owasp_coverage": self.owasp_coverage(),
            "actors": self.actors(),
            "threat_actors": self.threat_actors_detail(),
            "trust_boundaries": self.trust_boundaries(),
            "trust_zones": self.trust_zones(),
            "mode": self.mode,
            "created": self.created,
            "trace": self.trace.to_dict(),
        }


def new_model_id() -> str:
    return _id("tm")


def new_threat_id() -> str:
    return _id("t")


# --- output-encoding contract (arch review S4) ----------------------------
# The engine returns model-generated text (threat names, evidence, mitigation prose,
# code-fix diffs) as DATA. It is the CONSUMER's responsibility to encode for its sink
# (HTML-escape before rendering in a browser, etc.). This helper is provided for
# consumers that render HTML; the engine itself never executes or renders this text.
def escape_html(text: str) -> str:
    import html
    return html.escape(text or "", quote=True)

