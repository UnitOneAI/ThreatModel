"""MCP server — the front door.

This is the boundary the whole product is designed around: the engine is exposed as
MCP tools so ANY agent (Claude Code, Cursor, a customer orchestrator, our own Pi
backend) calls the same loop. Run with `synthesis serve` or `python -m
synthesis_engine.mcp_server`.

Tools:
  threat_model(repos, doc, mode, focus) -> a STRIDE threat model (+ DFD, matrix, fixes)
  fix(model_id, threat_id)              -> run the fixer on one threat
  get_model(model_id)                   -> fetch a stored model
  accept_threat(model_id, threat_id, accepted) -> human verdict (flywheel input)
  list_skills()                         -> the live skill index
  skill_stats()                         -> local confidence caps (the evolution state)
"""
from __future__ import annotations

from typing import Any

from . import store
from .loop import accept_threat as _accept
from .loop import run_fix as _run_fix
from .loop import run_threat_model as _run_tm
from .memory import IntentGraph
from .skills import load_skills


def build_server():
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as e:  # pragma: no cover
        raise SystemExit(
            "The MCP SDK is not installed. Install with:  pip install 'synthesis-engine[mcp]'\n"
            "(or: pip install mcp)"
        ) from e

    mcp = FastMCP("synthesis")

    @mcp.tool()
    def threat_model(repos: list[str] = [], docs: list[str] = [], doc: str = "",
                     mode: str = "agentic", focus: str = "", model: str = "",
                     test: bool = False) -> dict[str, Any]:
        """Generate a STRIDE threat model from repos and/or design docs (merged as one system).

        repos: GitHub URLs. docs: doc file paths, doc URLs, or pasted text (multiple).
        doc: single pasted doc (back-compat). mode: 'quick' | 'agentic' | 'fix'.
        focus: threat actors / attack vectors you care about.
        model: optional model id to run this scan on, e.g. 'claude-fable-5',
        'claude-mythos-5' (needs Project Glasswing access), or an OpenAI id like
        'gpt-4o' — the provider is inferred and the relevant key must be set in Configure.
        Omit to use the default from Configure.
        test: CI/demo only — TEMPLATED fixtures, NOT a real scan. Leave False for real
        analysis (requires a configured LLM provider; returns an error if none).
        """
        provider = ""
        if model:
            provider = ("anthropic" if model.startswith("claude")
                        else "openai" if model.startswith(("gpt", "o1", "o3", "o4")) else "")
        md = _run_tm(repos=repos, docs=docs, doc=doc, mode=mode, focus=focus,
                     allow_test=test, provider=(provider or None), model=(model or None))
        if "error" in md:
            return md
        return _summarize(md)

    @mcp.tool()
    def fix(model_id: str, threat_id: str) -> dict[str, Any]:
        """Run the fixer loop on one threat: propose a diff, sandbox-validate, attach
        a PR + characterization test. Returns the threat's mitigation + honesty gate."""
        out = _run_fix(model_id, threat_id)
        if "error" in out:
            return out
        t = next((x for x in out["threats"] if x["id"] == threat_id), None)
        return {"model_id": model_id, "threat": t}

    @mcp.tool()
    def get_model(model_id: str) -> dict[str, Any]:
        """Fetch a previously generated threat model by id."""
        md = store.load_model(model_id)
        return md or {"error": f"model {model_id} not found"}

    @mcp.tool()
    def accept_threat(model_id: str, threat_id: str, accepted: bool) -> dict[str, Any]:
        """Record a human verdict on a threat. Calibrates the firing skill's local
        confidence cap — the explicit input to the skill-evolution flywheel."""
        return _accept(model_id, threat_id, accepted)

    @mcp.tool()
    def list_skills() -> list[dict[str, Any]]:
        """The live skill index (built from skills/*.md frontmatter)."""
        return [s.to_dict() for s in load_skills().values()]

    @mcp.tool()
    def skill_stats() -> list[dict[str, Any]]:
        """Local confidence caps per skill — the current state of skill evolution."""
        g = IntentGraph()
        out = g.skill_stats()
        g.close()
        return out

    return mcp


def _summarize(md: dict[str, Any]) -> dict[str, Any]:
    """Trim the full model to a tool-friendly summary (full model via get_model)."""
    sm = md.get("stride_matrix", {})
    return {
        "id": md["id"],
        "mode": md["mode"],
        "provider": md.get("provider"),
        "model": md.get("model"),
        **({"demo": True, "warning": md["warning"]} if md.get("demo") else {}),
        "sources": md["design"]["sources"],
        "components": len(md["dfd"]["components"]),
        "threats": len(md["threats"]),
        "exposed": sum(1 for t in md["threats"] if t.get("reachability") == "exposed"),
        "stride_coverage": {"covered": sm.get("covered"), "gaps": sm.get("gaps"),
                            "applicable": sm.get("applicable")},
        "owasp_coverage": md.get("owasp_coverage", {}),
        "actors": md.get("actors", []),
        "top_threats": [
            {"id": t["id"], "name": t["name"], "stride": t["stride"],
             "severity": t["severity"], "reachability": t.get("reachability"),
             "owasp": t.get("owasp"), "cwe": t.get("cwe"),
             "security_verified": (t.get("mitigation") or {}).get("security_verified")}
            for t in md["threats"][:10]
        ],
        "hint": f"call get_model('{md['id']}') for the full DFD + matrix + diffs",
    }


def main() -> None:
    """Start the MCP server. stdio (default) is local-trust. A remote transport
    (SYNTHESIS_MCP_TRANSPORT=sse) REFUSES to start without SYNTHESIS_MCP_TOKEN, so
    the engine is never accidentally exposed unauthenticated (arch review S5)."""
    import os

    from .config import get_config
    from .logging_setup import configure_logging, get_logger

    cfg = get_config()
    configure_logging(cfg.log_level, cfg.log_format)
    log = get_logger("mcp")
    transport = os.environ.get("SYNTHESIS_MCP_TRANSPORT", "stdio")
    server = build_server()
    if transport == "sse":
        if not cfg.mcp_token:
            raise SystemExit(
                "Refusing to start the SSE (remote) transport without SYNTHESIS_MCP_TOKEN. "
                "Set a token (and front it with TLS), or use the default stdio transport."
            )
        log.info("starting MCP over SSE (token auth required at the proxy/transport)")
        server.run(transport="sse")
    else:
        server.run()


if __name__ == "__main__":
    main()
