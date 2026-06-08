"""Phase A — PLAN. The new primitive: inventory components and SELECT which skills
apply, per component, from the live skill index. Output is a task graph the
orchestrator fans Phase B out from. Adding a skill file changes the plan with no
code change.
"""
from __future__ import annotations

from dataclasses import dataclass

from .llm import LLM
from .skills import Skill, select_skills
from .types import Dfd


@dataclass
class Job:
    skill_id: str
    target: str  # component id
    rationale: str = ""


def plan(
    dfd: Dfd, skills: dict[str, Skill], context: str, focus: str, llm: LLM,
    base_only: bool = False, trace=None,
) -> list[Job]:
    if base_only:
        base = next((s for s in skills if "threat-modeling" in s), next(iter(skills), None))
        jobs = [Job(base, c.id, "quick mode: base STRIDE skill") for c in dfd.components] if base else []
        if trace:
            trace.mark("plan", mode="quick", jobs=len(jobs))
        return jobs

    jobs: list[Job] = []
    if not llm.scripted:
        jobs = _llm_plan(dfd, skills, context, focus, llm)
    if not jobs:  # scripted or LLM fallback
        for c in dfd.components:
            for sid in select_skills(skills, [c.kind], context + " " + c.name):
                jobs.append(Job(sid, c.id, f"{c.kind} matched {sid} triggers"))
    if trace:
        trace.mark("plan", mode="agentic", jobs=len(jobs),
                   skills=sorted({j.skill_id for j in jobs}))
    return jobs


def _llm_plan(dfd, skills, context, focus, llm: LLM) -> list[Job]:
    index = [{"id": sk.id, "triggers": sk.triggers, "title": sk.title}
             for sk in skills.values()]
    system = (
        "You are a planning agent. Given a DFD and a skill index, assign which "
        "skills should review which components. Only use skill ids from the index "
        "and component ids from the DFD."
    )
    user = (
        f"DFD components: {[{'id': c.id, 'kind': c.kind, 'name': c.name} for c in dfd.components]}\n"
        f"Skill index: {index}\nFocus: {focus}\n\n"
        'Return JSON: {"jobs":[{"skill_id","target","rationale"}]}'
    )
    data = llm.json(system, user)
    valid_ids = set(skills)
    valid_targets = {c.id for c in dfd.components}
    out = []
    for j in (data.get("jobs", []) if isinstance(data, dict) else []):
        if j.get("skill_id") in valid_ids and j.get("target") in valid_targets:
            out.append(Job(j["skill_id"], j["target"], j.get("rationale", "")))
    return out
