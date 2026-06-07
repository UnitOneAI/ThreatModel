"""Phase B — ANALYZE. One read-only reviewer per (component x skill), run in
parallel. LLM mode loads the skill body as the reviewer system prompt; offline a
deterministic, control-grounded template generator stands in so the engine always
produces a coherent model. Every emitted control id is validated.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from .controls import validate_threat_controls
from .llm import LLM
from .plan import Job
from .skills import Skill
from .types import (
    DATA_STORE,
    DOS,
    ELEVATION,
    EXTERNAL_ENTITY,
    INFO_DISCLOSURE,
    PROCESS,
    SPOOFING,
    STRIDE_APPLICABILITY,
    TAMPERING,
    Component,
    Dfd,
    Threat,
    new_threat_id,
)

# Deterministic, control-grounded templates for the offline reviewer.
# Each: (element_kind, stride, name, owasp, cwe, mitre, severity, actor, mitigation)
_TEMPLATES: dict[str, list[tuple]] = {
    "appsec/threat-modeling": [
        (PROCESS, SPOOFING, "Unauthenticated request accepted at {n}", "A07:2021", "CWE-306", "T1190", "high", "External Attacker (Opportunistic)", "Require authenticated, mutually-verified identity on all inbound calls."),
        (PROCESS, ELEVATION, "Privilege escalation via missing authorization at {n}", "A01:2021", "CWE-269", "T1078", "high", "Malicious Insider", "Enforce per-action authorization checks server-side."),
        (PROCESS, DOS, "Resource exhaustion at {n}", "A04:2021", "CWE-400", "T1499", "medium", "Automated Bot/Scraper", "Add rate limiting and request quotas."),
        (DATA_STORE, INFO_DISCLOSURE, "Sensitive data readable from {n}", "A02:2021", "CWE-311", None, "high", "External Attacker (Targeted)", "Encrypt at rest and restrict read scope by role."),
        (DATA_STORE, TAMPERING, "Unauthorized write to {n}", "A01:2021", "CWE-639", None, "high", "Malicious Insider", "Enforce object-level authorization on writes."),
        (EXTERNAL_ENTITY, SPOOFING, "Identity spoofing by {n}", "A07:2021", "CWE-287", "T1078", "medium", "External Attacker (Targeted)", "Strong authentication / certificate pinning."),
    ],
    "appsec/api-security": [
        (PROCESS, SPOOFING, "Broken authentication on API at {n}", "A07:2021", "CWE-287", "T1078", "high", "External Attacker (Opportunistic)", "Validate tokens on every request; short-lived, signed, audience-scoped."),
        (PROCESS, INFO_DISCLOSURE, "IDOR — broken object-level authorization at {n}", "A01:2021", "CWE-639", None, "high", "External Attacker (Targeted)", "Check ownership of every object id against the caller."),
        (PROCESS, INFO_DISCLOSURE, "SSRF via {n}", "A10:2021", "CWE-918", None, "high", "External Attacker (Targeted)", "Allowlist outbound hosts; block link-local/metadata ranges."),
        (PROCESS, DOS, "Missing rate limiting at {n}", "A04:2021", "CWE-400", "T1499", "medium", "Automated Bot/Scraper", "Per-client rate limits and concurrency caps."),
    ],
    "appsec/authentication": [
        (PROCESS, SPOOFING, "Weak token validation at {n}", "A07:2021", "CWE-287", "T1556", "high", "External Attacker (Targeted)", "Verify signature, issuer, audience and expiry; reject 'alg=none'."),
        (DATA_STORE, INFO_DISCLOSURE, "Credential store exposure at {n}", "A02:2021", "CWE-311", None, "high", "External Attacker (Targeted)", "Hash with a memory-hard KDF; encrypt the store; tight access."),
        (EXTERNAL_ENTITY, SPOOFING, "Credential stuffing against {n}", "A07:2021", "CWE-287", "T1078", "medium", "Automated Bot/Scraper", "Rate limit, MFA, and breached-password checks."),
    ],
    "appsec/secure-code-review": [
        (PROCESS, TAMPERING, "SQL injection at {n}", "A03:2021", "CWE-89", "T1190", "critical", "External Attacker (Opportunistic)", "Parameterize all queries; no string-built SQL."),
        (PROCESS, TAMPERING, "Insecure deserialization at {n}", "A08:2021", "CWE-502", "T1059", "high", "External Attacker (Targeted)", "Reject untrusted serialized input; use safe formats."),
        (PROCESS, INFO_DISCLOSURE, "Unrestricted file upload at {n}", "A04:2021", "CWE-20", None, "high", "External Attacker (Opportunistic)", "Validate type/size; store off web root; scan content."),
    ],
    "ai-security/llm-top-10": [
        (PROCESS, TAMPERING, "Prompt injection at {n}", "LLM01", "CWE-20", None, "high", "AI/LLM Threat Actor", "Instruction-hierarchy boundaries; treat retrieved data as untrusted."),
        (PROCESS, INFO_DISCLOSURE, "Sensitive information disclosure via {n}", "LLM02", "CWE-200", None, "high", "AI/LLM Threat Actor", "Redact secrets/PII from context; output filtering."),
        (PROCESS, ELEVATION, "Excessive agency / tool abuse at {n}", "LLM06", "CWE-269", None, "high", "AI/LLM Threat Actor", "Least-privilege tools; human approval on high-impact actions."),
        (PROCESS, DOS, "Unbounded consumption at {n}", "LLM10", "CWE-400", "T1499", "medium", "Automated Bot/Scraper", "Token/cost budgets and per-tenant quotas."),
    ],
}


def analyze(
    dfd: Dfd, jobs: list[Job], skills: dict[str, Skill], context: str, llm: LLM,
    max_workers: int = 8, trace=None,
) -> list[Threat]:
    comp_by_id = {c.id: c for c in dfd.components}

    def run_job(job: Job) -> list[Threat]:
        comp = comp_by_id.get(job.target)
        skill = skills.get(job.skill_id)
        if not comp or not skill:
            return []
        if llm.scripted:  # test mode only -> templated fixtures
            return _scripted_review(comp, job.skill_id)
        # real provider: NEVER fall back to templates (no fake findings in a real scan)
        return _llm_review(comp, skill, context, llm)

    threats: list[Threat] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for res in ex.map(run_job, jobs):
            threats.extend(res)
    if trace:
        trace.mark("analyze", jobs=len(jobs), raw_threats=len(threats), provider=llm.name)
    return threats


def _scripted_review(comp: Component, skill_id: str) -> list[Threat]:
    out: list[Threat] = []
    for (kind, stride, name, owasp, cwe, mitre, sev, actor, mit) in _TEMPLATES.get(skill_id, []):
        if kind != comp.kind:
            continue
        if stride not in STRIDE_APPLICABILITY.get(comp.kind, set()):
            continue
        from .types import Mitigation
        out.append(Threat(
            id=new_threat_id(), name=name.format(n=comp.name), stride=stride,
            target_element=comp.id, element_kind=comp.kind, severity=sev,
            owasp=owasp, cwe=cwe, mitre=mitre, actor=actor,
            evidence=f"{comp.kind} '{comp.name}' in zone '{comp.zone}'",
            skill_id=skill_id, mitigation=Mitigation(prose=mit, skill_id=skill_id),
        ))
    return out


def _llm_review(comp: Component, skill: Skill, context: str, llm: LLM) -> list[Threat]:
    from .types import Mitigation
    user = (
        f"Element: id={comp.id} name={comp.name} kind={comp.kind} zone={comp.zone}\n"
        f"System context (excerpt):\n{context[:3000]}\n\n"
        "Emit only threats applicable to this element's kind."
    )
    data = llm.json(skill.body, user)
    raw = data.get("threats", []) if isinstance(data, dict) else []
    out: list[Threat] = []
    applic = STRIDE_APPLICABILITY.get(comp.kind, set())
    for t in raw:
        stride = t.get("stride", "").lower().replace(" ", "_")
        if stride not in applic:
            continue
        owasp, cwe, mitre = t.get("owasp"), t.get("cwe"), t.get("mitre")
        for bad in validate_threat_controls(owasp, cwe, mitre):  # null hallucinated ids
            owasp = None if owasp == bad else owasp
            cwe = None if cwe == bad else cwe
            mitre = None if mitre == bad else mitre
        sev = t.get("severity", "medium").lower()
        out.append(Threat(
            id=new_threat_id(), name=t.get("name", "Unnamed threat"), stride=stride,
            target_element=comp.id, element_kind=comp.kind,
            severity=sev if sev in ("critical", "high", "medium", "low") else "medium",
            owasp=owasp, cwe=cwe, mitre=mitre, actor=t.get("actor"),
            evidence=t.get("evidence", ""), skill_id=skill.id,
            mitigation=Mitigation(prose=t.get("mitigation", ""), skill_id=skill.id),
        ))
    return out
