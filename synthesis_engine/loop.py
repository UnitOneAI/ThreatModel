"""Orchestrator — the ProposerCriticLoop. Runs the phases per mode and ties in the
local Intent Graph (warm-start + write) and skill confidence calibration.

    quick    : ingest -> (base skill) analyze -> merge
    agentic  : ingest -> plan -> analyze -> merge -> critique
    fix      : agentic + Phase E fix
"""
from __future__ import annotations

from typing import Any

from . import audit, store
from .analyze import analyze
from .config import get_config
from .critique import critique
from .fix import fix_threats
from .ingest import ingest
from .llm import BudgetedLLM, BudgetExceeded, NoProviderError, get_llm
from .logging_setup import configure_logging, get_logger
from .memory import IntentGraph
from .merge import merge
from .plan import plan
from .skills import load_skills
from .types import RunTrace, ThreatModel, new_model_id

MODES = ("quick", "agentic", "fix")
_log = get_logger("loop")

_TEST_WARNING = ("TEST MODE — templated fixtures, NOT a real scan of the target. "
                 "Configure an LLM provider (ANTHROPIC_API_KEY, an OpenAI-compatible "
                 "endpoint, or the [local] model) for real analysis.")


def run_threat_model(
    repos: list[str] | None = None,
    docs: list[str] | None = None,
    doc: str = "",                       # back-compat: single doc string
    mode: str = "agentic",
    focus: str = "",
    skills_dir: str | None = None,
    db_path: str | None = None,
    persist: bool = True,
    allow_test: bool = False,
) -> dict[str, Any]:
    cfg = get_config()
    configure_logging(cfg.log_level, cfg.log_format)
    if mode not in MODES:
        mode = "agentic"
    repos = repos or []
    docs = list(docs or [])
    if doc:
        docs.append(doc)
    trace = RunTrace()
    try:
        llm = get_llm(allow_test=allow_test)
    except NoProviderError as e:
        return {"error": str(e)}
    if not llm.scripted:  # cap real LLM calls per run (cost guard, arch review S3)
        llm = BudgetedLLM(llm, cfg.max_llm_calls)

    audit.record("scan_start", mode=mode, repos=repos, docs=len(docs), provider=llm.name)
    try:
        md = _run_pipeline(repos, docs, mode, focus, skills_dir, db_path, persist, llm, cfg, trace)
    except BudgetExceeded as e:
        audit.record("scan_aborted", reason="budget", detail=str(e))
        return {"error": str(e)}
    audit.record("scan_finish", model_id=md["id"], threats=len(md["threats"]),
                 exposed=sum(1 for t in md["threats"] if t.get("reachability") == "exposed"))
    return md


def _run_pipeline(repos, docs, mode, focus, skills_dir, db_path, persist, llm, cfg, trace):
    skills = load_skills(skills_dir)
    graph = IntentGraph(db_path)

    # Phase 0 — ingest (N repos + N docs)
    design, dfd, context = ingest(repos, docs, focus, llm, trace)

    # warm-start (local tier; federated seam returns [] in OSS)
    priors = graph.warm_start(dfd.components) + graph.federated_warm_start(dfd.components)
    if priors:
        trace.mark("warm_start", priors=len(priors), source="local_intent_graph")
        context += "\n\nPRIOR ART (accepted threats on similar components): " + str(priors[:10])

    # Phase A — plan
    jobs = plan(dfd, skills, context, focus, llm, base_only=(mode == "quick"), trace=trace)

    # Phase B — analyze (parallel reviewers)
    threats = analyze(dfd, jobs, skills, context, llm, max_workers=cfg.max_workers, trace=trace)

    # Phase C — merge + reachability
    threats = merge(dfd, threats, trace=trace)

    # Phase D — critique (agentic/fix) + local calibration flywheel
    if mode in ("agentic", "fix"):
        threats, decisions = critique(threats, trace=trace)
        caps = {}
        for skill_id, accepted in decisions:
            caps[skill_id] = graph.calibrate(skill_id, accepted)
        if caps:
            trace.mark("calibrate", confidence_caps=caps)

    # Phase E — fix
    if mode == "fix":
        threats = fix_threats(dfd, threats, llm, ecosystem=_ecosystem(context),
                              max_fixes=cfg.max_fixes, trace=trace)

    model = ThreatModel(id=new_model_id(), design=design, dfd=dfd, threats=threats,
                        mode=mode, trace=trace)

    graph.write_model(model)
    graph.close()
    md = model.to_dict()
    md["provider"] = llm.name
    if llm.scripted:  # test mode — label loudly so it's never mistaken for a scan
        md["demo"] = True
        md["warning"] = _TEST_WARNING
    if persist:
        md["_path"] = store.save_model(md)
    return md


def run_fix(
    model_id: str, threat_id: str, db_path: str | None = None,
    models_dir: str | None = None,
) -> dict[str, Any]:
    """Re-run Phase E for a single threat in a stored model (e.g. from the MCP tool)."""
    md = store.load_model(model_id, models_dir)
    if not md:
        return {"error": f"model {model_id} not found"}
    model = _rehydrate(md)
    target = next((t for t in model.threats if t.id == threat_id), None)
    if not target:
        return {"error": f"threat {threat_id} not in model"}
    try:
        llm = get_llm()
    except NoProviderError as e:
        return {"error": str(e)}
    fix_threats(model.dfd, [target], llm, ecosystem=_ecosystem(md.get("design", {}).get("doc_excerpt", "")),
                max_fixes=1, trace=model.trace)
    out = model.to_dict()
    out["_path"] = store.save_model(out, models_dir)
    return out


def accept_threat(
    model_id: str, threat_id: str, accepted: bool,
    db_path: str | None = None, models_dir: str | None = None,
) -> dict[str, Any]:
    """Human verdict -> calibrate the firing skill (the explicit flywheel input)."""
    md = store.load_model(model_id, models_dir)
    if not md:
        return {"error": f"model {model_id} not found"}
    threat = next((t for t in md["threats"] if t["id"] == threat_id), None)
    if not threat:
        return {"error": f"threat {threat_id} not found"}
    threat["status"] = "accepted" if accepted else "rejected"
    graph = IntentGraph(db_path)
    cap = graph.calibrate(threat.get("skill_id") or "unknown", accepted)
    graph.close()
    store.save_model(md, models_dir)
    return {"model_id": model_id, "threat_id": threat_id,
            "skill_id": threat.get("skill_id"), "new_confidence_cap": cap}


# --- helpers --------------------------------------------------------------
def _ecosystem(context: str) -> str:
    c = (context or "").lower()
    if ".py" in c or "python" in c or "fastapi" in c or "django" in c:
        return "python311"
    if ".go" in c or "golang" in c:
        return "go122"
    return "node20"


def _rehydrate(md: dict[str, Any]) -> ThreatModel:
    from .types import Component, DesignDoc, Dfd, Flow, Mitigation, Threat
    dfd = Dfd(
        components=[Component(**c) for c in md["dfd"]["components"]],
        flows=[Flow(**f) for f in md["dfd"]["flows"]],
    )
    threats = []
    for t in md["threats"]:
        mit = t.get("mitigation")
        threats.append(Threat(
            id=t["id"], name=t["name"], stride=t["stride"],
            target_element=t["target_element"], element_kind=t["element_kind"],
            severity=t["severity"], likelihood=t.get("likelihood", "medium"),
            impact=t.get("impact", "medium"), owasp=t.get("owasp"), cwe=t.get("cwe"),
            mitre=t.get("mitre"), actor=t.get("actor"), evidence=t.get("evidence", ""),
            reachability=t.get("reachability", "unknown"), status=t.get("status", "open"),
            skill_id=t.get("skill_id"),
            mitigation=Mitigation(**mit) if mit else None,
        ))
    model = ThreatModel(
        id=md["id"], design=DesignDoc(**md["design"]), dfd=dfd, threats=threats,
        mode=md.get("mode", "agentic"),
    )
    return model
