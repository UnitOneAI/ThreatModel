"""Engine tests — all run offline (scripted provider), no network, no keys."""
import os
import tempfile

# isolate state to a temp dir before importing the package
_TMP = tempfile.mkdtemp(prefix="synthesis-test-")
os.environ["SYNTHESIS_DB"] = os.path.join(_TMP, "ig.db")
os.environ["SYNTHESIS_MODELS_DIR"] = os.path.join(_TMP, "models")
os.environ["SYNTHESIS_AUDIT_LOG"] = os.path.join(_TMP, "audit.log")
os.environ.pop("ANTHROPIC_API_KEY", None)
os.environ.pop("OPENAI_BASE_URL", None)
os.environ.pop("SYNTHESIS_TEST_MODE", None)
os.environ.pop("SYNTHESIS_USE_LOCAL", None)

from synthesis_engine import controls  # noqa: E402
from synthesis_engine.loop import run_threat_model  # noqa: E402
from synthesis_engine.memory import IntentGraph  # noqa: E402
from synthesis_engine.skills import load_skills, select_skills  # noqa: E402
from synthesis_engine.types import (  # noqa: E402
    PROCESS,
    Component,
    DesignDoc,
    Dfd,
    Mitigation,
    Threat,
    ThreatModel,
)

DOC = ("Web platform: a public REST API gateway authenticates users with JWT, "
       "calls an LLM agent service, and reads/writes a Postgres database. "
       "File upload is supported. SQL is used for queries.")


# --- skills ---------------------------------------------------------------
def test_skills_load_and_select():
    skills = load_skills()
    assert "appsec/threat-modeling" in skills
    assert skills["appsec/threat-modeling"].confidence_cap == 0.8
    assert skills["appsec/threat-modeling"].body  # body parsed
    sel = select_skills(skills, [PROCESS], "this has an llm agent and jwt auth")
    assert "ai-security/llm-top-10" in sel
    assert "appsec/authentication" in sel


# --- controls -------------------------------------------------------------
def test_control_validation():
    assert controls.resolve("A01:2021")
    assert controls.resolve("CWE-89")
    assert controls.resolve("LLM01")
    assert not controls.resolve("A99:2021")
    assert controls.validate_threat_controls("A01:2021", "CWE-89", "T1190") == []
    assert "A99:2021" in controls.validate_threat_controls("A99:2021", "CWE-89", None)


# --- end-to-end scripted --------------------------------------------------
def test_quick_mode():
    md = run_threat_model(doc=DOC, mode="quick", db_path=os.environ["SYNTHESIS_DB"], allow_test=True)
    assert len(md["dfd"]["components"]) > 0
    assert len(md["threats"]) > 0
    targets = {c["id"] for c in md["dfd"]["components"]}
    for t in md["threats"]:
        assert t["target_element"] in targets
        # no hallucinated control ids
        assert controls.validate_threat_controls(t["owasp"], t["cwe"], t["mitre"]) == []


def test_agentic_mode_phases_and_reachability():
    md = run_threat_model(doc=DOC, mode="agentic", focus="unauthenticated peer",
                          db_path=os.environ["SYNTHESIS_DB"], allow_test=True)
    phases = [p["phase"] for p in md["trace"]["phases"]]
    for expected in ("ingest", "plan", "analyze", "merge", "critique"):
        assert expected in phases
    assert any(t["reachability"] == "exposed" for t in md["threats"])
    sm = md["stride_matrix"]
    assert sm["applicable"] >= sm["covered"] > 0


def test_fix_mode_honesty_gate():
    md = run_threat_model(doc=DOC, mode="fix", db_path=os.environ["SYNTHESIS_DB"], allow_test=True)
    fixed = [t for t in md["threats"] if t.get("mitigation") and t["mitigation"].get("code_fix")]
    assert fixed, "fix mode should attach at least one code fix"
    m = fixed[0]["mitigation"]
    assert m["behavior_verified"] is False           # honesty gate
    assert "UNVERIFIED" in m["prose"]
    assert m["pr_url"].startswith("synthetic-pr://")


# --- memory: calibration + warm-start ------------------------------------
def test_confidence_calibration_moves():
    g = IntentGraph(":memory:")
    assert g.confidence("s1") == 0.7  # default before any outcomes
    for _ in range(5):
        up = g.calibrate("s1", True)
    for _ in range(5):
        down = g.calibrate("s2", False)
    assert up > down
    assert 0.3 <= down <= up <= 0.95
    g.close()


def test_warm_start_returns_accepted_priors():
    db = os.path.join(_TMP, "warm.db")
    g = IntentGraph(db)
    comp = Component(id="c-auth", name="Auth Service", kind=PROCESS, zone="app")
    threat = Threat(id="t-1", name="Weak token validation", stride="spoofing",
                    target_element="c-auth", element_kind=PROCESS, severity="high",
                    owasp="A07:2021", cwe="CWE-287", status="accepted",
                    skill_id="appsec/authentication",
                    mitigation=Mitigation(prose="verify sig", skill_id="appsec/authentication"))
    model = ThreatModel(id="tm-x", design=DesignDoc(sources=["x"]),
                        dfd=Dfd(components=[comp]), threats=[threat])
    g.write_model(model)
    priors = g.warm_start([Component(id="c-auth2", name="Auth Service", kind=PROCESS)])
    assert any("Weak token validation" == p["name"] for p in priors)
    g.close()


def test_federated_seam_is_empty_in_oss():
    g = IntentGraph(":memory:")
    assert g.federated_warm_start([Component(id="c", name="x", kind=PROCESS)]) == []
    g.close()


# --- provider gating: real runs must not silently emit fixtures --------------
def test_no_provider_is_an_error_not_fake_data():
    # no keys, no local opt-in, test mode NOT allowed -> explicit error, not a scan
    md = run_threat_model(doc=DOC, mode="quick", db_path=os.environ["SYNTHESIS_DB"])
    assert "error" in md
    assert "No LLM provider" in md["error"]
    assert "threats" not in md


def test_test_mode_is_labeled():
    md = run_threat_model(doc=DOC, mode="quick", db_path=os.environ["SYNTHESIS_DB"], allow_test=True)
    assert md["provider"] == "test"
    assert md["demo"] is True
    assert "not a real scan" in md["warning"].lower()


def test_get_llm_ladder():
    import pytest

    from synthesis_engine.llm import NoProviderError, TestLLM, get_llm
    with pytest.raises(NoProviderError):
        get_llm(allow_test=False)
    assert isinstance(get_llm(allow_test=True), TestLLM)


def test_local_provider_seam_is_safe_without_deps():
    # local model is optional; absence must not crash selection
    from synthesis_engine.local_llm import is_model_cached, local_available
    assert isinstance(local_available(), bool)
    assert isinstance(is_model_cached(), bool)
