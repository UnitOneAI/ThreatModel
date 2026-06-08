"""Synthesis CLI.

The one command you need:

    synthesis analyze <repo-or-doc> [<repo-or-doc> ...] [--mode quick|agentic|fix]

Inputs are auto-detected — mix GitHub repo URLs, local doc files, doc URLs, and
pasted text freely; they're merged into one threat model. Examples:

    synthesis analyze https://github.com/org/api https://github.com/org/worker design.md
    synthesis analyze ./architecture.md ./threats.md            # docs only
    echo "a public API with JWT + postgres" | synthesis analyze --doc -

Other commands:
    synthesis fix <model_id> <threat_id>
    synthesis accept <model_id> <threat_id> (--accept | --reject)
    synthesis skills | stats | audit | serve
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from urllib.parse import urlparse

from . import __version__, audit
from .config import get_config
from .logging_setup import configure_logging
from .loop import accept_threat, run_fix, run_threat_model
from .memory import IntentGraph
from .skills import load_skills


def _classify(inputs: list[str]) -> tuple[list[str], list[str]]:
    """Split mixed positional inputs into (repos, docs)."""
    repos, docs = [], []
    for item in inputs:
        host = (urlparse(item).netloc or "").lower() if "://" in item else ""
        if host in ("github.com", "www.github.com"):
            repos.append(item)
        else:
            docs.append(item)  # doc URL, file path, or inline text — ingest handles it
    return repos, docs


def main(argv: list[str] | None = None) -> int:
    cfg = get_config()
    configure_logging(cfg.log_level, cfg.log_format)

    p = argparse.ArgumentParser(prog="synthesis", description="Threat modeling + fixer (MCP-first).")
    p.add_argument("--version", action="version", version=f"synthesis {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="generate a threat model from repos and/or docs")
    a.add_argument("inputs", nargs="*", help="repo URLs, doc files, doc URLs, or text (auto-detected)")
    a.add_argument("--repo", action="append", default=[], help="explicit repo URL (repeatable)")
    a.add_argument("--doc", action="append", default=[], help="explicit doc file/URL, or - for stdin (repeatable)")
    a.add_argument("--mode", default="agentic", choices=["quick", "agentic", "fix"])
    a.add_argument("--focus", default="", help="threat actors / attack vectors you care about")
    a.add_argument("--json", action="store_true", help="print the full model JSON")
    a.add_argument("--html", metavar="PATH", help="also write a visual HTML report to PATH")
    a.add_argument("--test", action="store_true",
                   help="CI/demo of the machinery only — TEMPLATED fixtures, not a real scan")

    f = sub.add_parser("fix", help="run the fixer on one threat")
    f.add_argument("model_id")
    f.add_argument("threat_id")

    ac = sub.add_parser("accept", help="record a human verdict (flywheel input)")
    ac.add_argument("model_id")
    ac.add_argument("threat_id")
    g = ac.add_mutually_exclusive_group(required=True)
    g.add_argument("--accept", action="store_true")
    g.add_argument("--reject", action="store_true")

    rp = sub.add_parser("report", help="render a stored model as a visual HTML report")
    rp.add_argument("model_id")
    rp.add_argument("-o", "--out", help="output HTML path (default: <model_id>.html)")
    rp.add_argument("--open", action="store_true", help="open the report in a browser")

    up = sub.add_parser("ui", help="launch the local web UI (threat modeling + fixing)")
    up.add_argument("--host", default="127.0.0.1")
    up.add_argument("--port", type=int, default=8765)
    up.add_argument("--no-open", action="store_true", help="don't auto-open the browser")

    sub.add_parser("skills", help="list the live skill index")
    sub.add_parser("stats", help="show local skill confidence caps (evolution state)")
    sub.add_parser("audit", help="show recent audit-log entries")
    sub.add_parser("serve", help="start the MCP server (stdio)")

    args = p.parse_args(argv)

    if args.cmd == "analyze":
        repos, docs = _classify(args.inputs)
        repos += args.repo
        for d in args.doc:
            docs.append(sys.stdin.read() if d == "-" else d)
        if not repos and not docs:
            print("nothing to analyze. e.g.: synthesis analyze https://github.com/org/repo design.md",
                  file=sys.stderr)
            return 2
        md = run_threat_model(repos=repos, docs=docs, mode=args.mode,
                              focus=args.focus, allow_test=args.test)
        if md.get("error"):
            print(md["error"], file=sys.stderr)
            return 2
        if args.html:
            from .report import render_html
            with open(args.html, "w", encoding="utf-8") as fh:
                fh.write(render_html(md))
            print(f"HTML report → {args.html}")
        print(json.dumps(md, indent=2)) if args.json else _print_summary(md)
        return 0

    if args.cmd == "report":
        from . import store
        from .report import render_html
        md = store.load_model(args.model_id)
        if not md:
            print(f"model {args.model_id} not found", file=sys.stderr)
            return 2
        out = args.out or f"{args.model_id}.html"
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(render_html(md))
        print(f"HTML report → {out}")
        if args.open:
            import webbrowser
            webbrowser.open(f"file://{os.path.abspath(out)}")
        return 0

    if args.cmd == "ui":
        from .ui import serve
        serve(host=args.host, port=args.port, open_browser=not args.no_open)
        return 0

    if args.cmd == "fix":
        out = run_fix(args.model_id, args.threat_id)
        print(json.dumps(out.get("error") or _threat(out, args.threat_id), indent=2))
        return 0

    if args.cmd == "accept":
        out = accept_threat(args.model_id, args.threat_id, accepted=bool(args.accept))
        print(json.dumps(out, indent=2))
        return 0

    if args.cmd == "skills":
        for s in load_skills().values():
            print(f"{s.id:32}  cap={s.confidence_cap:<4}  triggers={','.join(s.triggers)}")
        return 0

    if args.cmd == "stats":
        gr = IntentGraph()
        rows = gr.skill_stats()
        gr.close()
        if not rows:
            print("no skill stats yet — run `synthesis analyze` first.")
        for r in rows:
            print(f"{r['skill_id']:32}  cap={r['confidence_cap']:<5}  "
                  f"accepted={r['accepted']} rejected={r['rejected']}")
        return 0

    if args.cmd == "audit":
        for e in audit.read_recent(50):
            print(json.dumps(e))
        return 0

    if args.cmd == "serve":
        from .mcp_server import main as serve_main
        serve_main()
        return 0
    return 1


def _threat(model: dict, tid: str) -> dict:
    return next((t for t in model.get("threats", []) if t["id"] == tid), {})


def _print_summary(md: dict) -> None:
    sm = md["stride_matrix"]
    if md.get("demo"):
        print("\n" + "!" * 72)
        print("  " + md.get("warning", "TEST MODE — templated fixtures, not a real scan."))
        print("!" * 72)
    print(f"\nmodel {md['id']}  (mode={md['mode']}, provider={md.get('provider', '?')})")
    print(f"repos: {', '.join(md['design']['sources']) or '(none)'}    "
          f"docs: {', '.join(md['design'].get('docs', [])) or '(none)'}")
    print(f"components: {len(md['dfd']['components'])}   threats: {len(md['threats'])}   "
          f"exposed: {sum(1 for t in md['threats'] if t['reachability']=='exposed')}")
    print(f"STRIDE coverage: {sm['covered']}/{sm['applicable']} cells   gaps: {sm['gaps']}")
    if md["owasp_coverage"]:
        print(f"OWASP: {md['owasp_coverage']}")
    print("\ntop threats:")
    for t in md["threats"][:10]:
        sv = (t.get("mitigation") or {}).get("security_verified")
        flag = " [sec-verified]" if sv else ""
        print(f"  {t['severity']:8} {t['reachability']:13} {t['stride']:22} "
              f"{t['name']}{flag}")
    print(f"\nfull JSON: add --json   |   fix: synthesis fix {md['id']} <threat_id>\n")


if __name__ == "__main__":
    raise SystemExit(main())
