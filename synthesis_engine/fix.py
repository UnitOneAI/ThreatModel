"""Phase E — FIX. For high-severity, reachable threats: propose a code fix, validate
it in the sandbox, and open a PR. The honesty gate is the point: we own the security
regression (replay the PoC, assert it now fails, commit it as a permanent test); we
do NOT own functional regression (that needs the customer's suite). A fix that passes
security but has no functional coverage ships as "security-verified,
behavior-UNVERIFIED — human review required" rather than dressed up as fully tested.
"""
from __future__ import annotations

from . import audit
from .llm import LLM
from .sandbox import Sandbox, get_sandbox
from .types import Dfd, Mitigation, Threat


def fix_threats(
    dfd: Dfd, threats: list[Threat], llm: LLM, ecosystem: str = "node20",
    max_fixes: int = 5, max_rung: int = 4, trace=None,
) -> list[Threat]:
    sandbox = get_sandbox(ecosystem)
    comp_by_id = {c.id: c for c in dfd.components}
    fixed = 0
    for t in threats:
        if fixed >= max_fixes:
            break
        if t.severity not in ("critical", "high") or t.reachability != "exposed":
            continue
        comp = comp_by_id.get(t.target_element)
        if not comp:
            continue
        _fix_one(t, comp.name, llm, sandbox, max_rung)
        fixed += 1
    if trace:
        trace.mark("fix", attempted=fixed, sandbox=sandbox.driver,
                   security_verified=sum(1 for t in threats if t.mitigation and t.mitigation.security_verified))
    return threats


def _fix_one(t: Threat, comp_name: str, llm: LLM, sandbox: Sandbox, max_rung: int) -> None:
    diff = _generate_diff(t, comp_name, llm)
    results = sandbox.validate(diff, max_rung=max_rung)
    rungs = [r.to_dict() for r in results]
    audit.record("fix_proposed", threat_id=t.id, threat=t.name, skill_id=t.skill_id,
                 sandbox=sandbox.driver, rungs=[r["status"] for r in rungs])
    rung4 = next((r for r in results if r.rung == 4), None)
    security_verified = bool(rung4 and rung4.status == "passed")

    note = (
        "Security regression: " + ("PoC replayed and now fails (verified)."
        if security_verified else
        "PoC not yet replayed in this run — "
        + ("install Docker for rungs 1-3; managed tier for rung 4."
           if sandbox.driver == "local" else "rung 4 requires the managed runtime.")) +
        " Behavior preservation: UNVERIFIED — no customer functional suite is wired; "
        "human review required before merge."
    )
    base = (t.mitigation.prose if t.mitigation else "")
    t.mitigation = Mitigation(
        prose=(base + "\n\n" + note).strip(),
        code_fix=diff,
        skill_id=t.skill_id,
        confidence=0.6 if security_verified else 0.4,
        pr_url=f"synthetic-pr://{t.id}",  # real PR via GitHub App when configured
        security_verified=security_verified,
        behavior_verified=False,
        sandbox_rungs=[r["name"] for r in rungs if r["status"] == "passed"],
    )
    t.status = "security_verified" if security_verified else "open"


def _generate_diff(t: Threat, comp_name: str, llm: LLM) -> str:
    if not llm.scripted:
        system = ("You are a remediation agent. Output ONLY a unified diff that closes "
                  "the described threat against the named component. No prose.")
        user = (f"Threat: {t.name}\nSTRIDE: {t.stride}\nControl: {t.owasp} {t.cwe}\n"
                f"Mitigation intent: {t.mitigation.prose if t.mitigation else ''}\n"
                f"Component: {comp_name}")
        diff = llm.complete(system, user)
        if "@@" in diff or diff.lstrip().startswith(("diff", "---")):
            return diff
    # scripted stub: a placeholder patch + the characterization test we commit
    ctrl = t.owasp or t.cwe or "control"
    return (
        f"# synthetic patch for {t.id} ({t.name})\n"
        f"# applies the mitigation: {t.mitigation.prose if t.mitigation else ''}\n"
        f"# grounded in {ctrl}; replace with the real diff against {comp_name}.\n"
        f"+ // {ctrl}: enforce mitigation at {comp_name}\n"
        f"+ test('regression: {t.name} no longer reproduces', () => "
        f"expect(exploit_{t.id.replace('-', '_')}()).toBe(false));\n"
    )
