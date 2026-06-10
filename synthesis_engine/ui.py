"""Local web app for threat modeling + fixing — stdlib only (http.server), styled to
the UnitOne spine. Left sidebar (logo + nav: Threat Models / Fix Queue / Learn·Skills),
persisted threat-model list, an "Add Threat Model Source" form (N repos + N docs), the
visual report, a fix queue (diffs, skills used, components touched), and the Learn
surface (skill auto-evolution + confidence caps). No framework, no build.

Run:  synthesis ui   →  http://127.0.0.1:8765   (localhost-bound; single-user tool)
"""
from __future__ import annotations

import time
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import store
from .assets import logo_data_uri
from .cli import _classify
from .config import get_config, save_settings
from .logging_setup import configure_logging, get_logger
from .loop import run_fix, run_threat_model
from .memory import IntentGraph
from .report import REPORT_CSS, colorize_diff, render_body
from .skills import load_skills

_log = get_logger("ui")

_NAV = [("models", "Threat Models", "/models"),
        ("fixes", "Fix Queue", "/fixes"),
        ("learn", "Learn · Skills", "/learn"),
        ("configure", "Configure", "/configure")]

_SHELL_CSS = """
.app{display:flex;min-height:100vh}
.side{width:230px;flex:none;background:var(--surface);border-right:1px solid var(--border);
  display:flex;flex-direction:column;position:sticky;top:0;height:100vh}
.side .top{display:flex;align-items:center;gap:10px;padding:18px 16px;border-bottom:1px solid var(--border)}
.side .logo{width:30px;height:30px;border-radius:7px}
.side .brand{font-family:ui-monospace,monospace;font-size:10px;letter-spacing:.22em;color:var(--teal);font-weight:700}
.side .sub{font-size:11px;color:var(--text-dim);margin-top:1px}
.nav{padding:12px 10px;display:flex;flex-direction:column;gap:2px}
.nav a{display:block;padding:10px 12px;border-radius:8px;color:var(--text-muted);font-size:13px;font-weight:600;text-decoration:none}
.nav a:hover{background:var(--surface-2);color:var(--text)}
.nav a.on{background:var(--surface-2);color:var(--teal)}
.side .foot{margin-top:auto;padding:14px 16px;border-top:1px solid var(--border);font-size:10px;color:var(--text-dim);font-family:ui-monospace,monospace}
.main{flex:1;min-width:0}
.bar{display:flex;align-items:center;gap:14px;padding:16px 28px;border-bottom:1px solid var(--border);background:var(--surface)}
.bar h1{font-size:16px;margin:0;font-weight:700} .bar .sp{flex:1}
.btn{background:var(--teal);color:#06251c;border:0;border-radius:8px;padding:9px 16px;font-size:12px;
  font-weight:700;cursor:pointer;text-transform:uppercase;letter-spacing:.06em;text-decoration:none;display:inline-block}
.btn:hover{filter:brightness(1.08)}
.btn.ghost{background:transparent;border:1px solid var(--border-strong);color:var(--text-muted)}
.list{padding:18px 28px;display:flex;flex-direction:column;gap:10px}
.row{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px;display:flex;align-items:center;gap:16px;text-decoration:none;color:inherit}
.row:hover{border-color:var(--border-strong)}
.row .id{font-family:ui-monospace,monospace;font-size:12px;color:var(--teal);min-width:130px}
.row .src{font-size:13px;flex:1;color:var(--text);white-space:normal}
.row .pill{font-size:11px;color:var(--text-muted);border:1px solid var(--border);border-radius:999px;padding:2px 10px}
.row .pill.exp{color:var(--coral);border-color:var(--coral)}
.empty{color:var(--text-dim);font-size:13px;padding:30px 28px;text-align:center}
form.scan{padding:18px 28px;max-width:820px} form.scan label{display:block;font-size:12px;color:var(--text-muted);margin:12px 0 5px;font-weight:600}
form.scan textarea,form.scan input,form.scan select{width:100%;padding:9px;border:1px solid var(--border);border-radius:8px;background:var(--bg);color:var(--text);font-size:14px;font-family:inherit}
form.cfg{padding:14px 0!important} form.cfg .card{margin:0 28px 14px}
form.scan textarea{min-height:84px} .frow{display:flex;gap:14px} .frow>div{flex:1}
.hint{font-size:12px;color:var(--text-dim);margin-top:8px}
.fixgroup{margin:0 28px 18px}
.grouphdr{display:flex;align-items:center;gap:12px;padding:10px 14px;background:var(--surface-2);border:1px solid var(--border);border-radius:10px 10px 0 0;text-decoration:none;color:inherit}
.grouphdr .id{font-family:ui-monospace,monospace;font-size:12px;color:var(--teal)}
.grouphdr .gsrc{flex:1;font-size:12px;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fixgroup .fixcard{margin:0;border-radius:0;border-top:0}
.fixgroup .fixcard:last-child{border-radius:0 0 10px 10px}
.fixcard{background:var(--surface);border:1px solid var(--border);border-radius:10px;margin:0 28px 12px;padding:14px 16px}
.fixcard .h{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.fixcard .tn{font-weight:600;flex:1} .tag{font-size:10px;border:1px solid var(--border);border-radius:5px;padding:2px 8px;color:var(--text-muted)}
.tag.skill{border-color:var(--violet);color:#c4b5fd} .tag.comp{border-color:var(--amber);color:var(--amber)}
.sev{color:#0b0f1a;border-radius:5px;padding:2px 8px;font-size:10px;font-weight:700;text-transform:uppercase}
.diff{background:#0b0f1a;color:#e2e8f0;padding:12px;border-radius:8px;overflow:auto;font-size:12px;white-space:pre-wrap;border:1px solid var(--border);margin-top:8px}
.skrow{display:grid;grid-template-columns:1fr 90px 90px 120px;gap:10px;align-items:center;padding:10px 16px;border-bottom:1px solid var(--border);font-size:13px}
.skrow .skid{font-family:ui-monospace,monospace;color:var(--text)} .bar2{height:6px;background:var(--surface-2);border-radius:3px;overflow:hidden}
.bar2 i{display:block;height:100%;background:var(--teal)}
"""


def _shell(active: str, title: str, content: str, actions: str = "") -> bytes:
    logo = logo_data_uri()
    logo_img = f'<img src="{logo}" class="logo" alt="UnitOne">' if logo else ""
    nav = "".join(f'<a href="{href}" class="{"on" if key == active else ""}">{escape(label)}</a>'
                  for key, label, href in _NAV)
    return (f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>UnitOne · Synthesis</title>
<style>{REPORT_CSS}{_SHELL_CSS}</style></head><body>
<div class="app">
  <aside class="side">
    <div class="top">{logo_img}<div><div class="brand">UNITONE</div><div class="sub">Synthesis</div></div></div>
    <nav class="nav">{nav}</nav>
    <div class="foot">threat modeling + fixer<br>local · Apache-2.0</div>
  </aside>
  <div class="main">
    <div class="bar"><h1>{escape(title)}</h1><div class="sp"></div>{actions}</div>
    {content}
  </div>
</div></body></html>""").encode()


def _models_page() -> bytes:
    ids = store.list_models()
    rows = []
    for mid in ids[::-1]:
        md = store.load_model(mid)
        if not md:
            continue
        d = md.get("design", {})
        src = ", ".join(d.get("sources", []) + d.get("docs", [])) or "(inline)"
        n = len(md.get("threats", []))
        exp = sum(1 for t in md.get("threats", []) if t.get("reachability") == "exposed")
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(md.get("created", 0)))
        rows.append(f"""<a class="row" href="/model/{escape(mid)}">
  <span class="id">{escape(mid)}</span>
  <span class="src">{escape(src)}<br><span class="dim">{when} · {escape(md.get('mode',''))} · {escape(md.get('provider',''))} · {escape(md.get('model') or '—')}</span></span>
  <span class="pill">{n} threats</span><span class="pill exp">{exp} exposed</span></a>""")
    body = f'<div class="list">{"".join(rows)}</div>' if rows else \
        '<div class="empty">No threat models yet. Click <b>+ Add Threat Model Source</b> to run your first scan.</div>'
    actions = '<a class="btn" href="/new">+ Add Threat Model Source</a>'
    return _shell("models", "Threat Models", body, actions)


def _new_page(msg: str = "") -> bytes:
    cfg = get_config()
    note = ("" if (cfg.anthropic_key or (cfg.openai_base and cfg.openai_key) or cfg.use_local)
            else "No LLM provider configured — a real scan will error. Pick 'test mode' below for a templated demo, "
                 "or set ANTHROPIC_API_KEY / a local model.")
    err = f'<div class="demo">{escape(msg)}</div>' if msg else ""
    form = f"""{err}<form class="scan" method="post" action="/scan">
  <label>GitHub repos — one per line (merged as one system)</label>
  <textarea name="repos" placeholder="https://github.com/org/api&#10;https://github.com/org/worker"></textarea>
  <label>Design docs — paste text, local file paths, or URLs (one per line)</label>
  <textarea name="docs" placeholder="Public REST API with JWT, calls an LLM agent, reads postgres. File upload supported."></textarea>
  <label>Customer focus — threat actors / attack vectors you care about</label>
  <input type="text" name="focus" placeholder="unauthenticated peer on the IT VLAN; ransomware IT→OT">
  <div class="frow">
    <div><label>Mode</label><select name="mode"><option value="fix" selected>fix (model + remediation)</option>
      <option value="agentic">agentic (model only)</option><option value="quick">quick (one pass)</option></select></div>
    <div><label>Model</label><select name="model_choice">
      <option value="">Default (from Configure)</option>
      <optgroup label="Claude (Anthropic)">
        <option value="anthropic:claude-fable-5">Claude Fable 5 — recommended for threat modeling</option>
        <option value="anthropic:claude-mythos-5">Claude Mythos 5 — cyber-class (Project Glasswing preview)</option>
        <option value="anthropic:claude-sonnet-4-6">Claude Sonnet 4.6</option>
        <option value="anthropic:claude-opus-4-6">Claude Opus 4.6</option>
        <option value="anthropic:claude-haiku-4-5-20251001">Claude Haiku 4.5</option></optgroup>
      <optgroup label="OpenAI">
        <option value="openai:gpt-4o">GPT-4o</option>
        <option value="openai:gpt-4o-mini">GPT-4o mini</option></optgroup>
      <optgroup label="Local (no key)">
        <option value="local:">Bundled local model</option></optgroup>
      <optgroup label="Demo">
        <option value="test:">Test mode — templated (no key)</option></optgroup>
    </select></div>
  </div>
  <div style="margin-top:16px"><button class="btn" type="submit">Run threat model</button>
    <a class="btn ghost" href="/models" style="margin-left:8px">Cancel</a></div>
  <div class="hint">{escape(note)}</div>
</form>"""
    return _shell("models", "Add Threat Model Source", form)


def _fixes_page() -> bytes:
    groups = []  # (model header html, [fix card html, ...])
    total = 0
    for mid in store.list_models()[::-1]:
        md = store.load_model(mid)
        if not md:
            continue
        comp_name = {c["id"]: c["name"] for c in md.get("dfd", {}).get("components", [])}
        cards = []
        for t in md.get("threats", []):
            mit = t.get("mitigation") or {}
            if not mit.get("code_fix"):
                continue
            total += 1
            sev = t.get("severity", "medium")
            sev_c = "var(--coral)" if sev in ("critical", "high") else "var(--amber)" if sev == "medium" else "var(--text-dim)"
            comp = comp_name.get(t.get("target_element"), t.get("target_element", "—"))
            ver = ('<span class="tag" style="border-color:var(--teal);color:var(--teal)">security-verified</span>'
                   if mit.get("security_verified") else '<span class="tag" style="border-color:var(--amber);color:var(--amber)">behavior UNVERIFIED</span>')
            cards.append(f"""<div class="fixcard">
  <div class="h"><span class="sev" style="background:{sev_c}">{escape(sev)}</span>
    <span class="tn">{escape(t.get('name'))}</span></div>
  <div class="h"><span class="tag skill">skill · {escape(mit.get('skill_id') or '—')}</span>
    <span class="tag comp">component · {escape(comp)}</span>
    <span class="tag">stride · {escape(t.get('stride',''))}</span>{ver}</div>
  <details><summary>▸ diff</summary>{colorize_diff(mit.get('code_fix',''))}</details>
</div>""")
        if cards:
            d = md.get("design", {})
            src = ", ".join(d.get("sources", []) + d.get("docs", [])) or "(inline)"
            header = (f'<a class="grouphdr" href="/model/{escape(mid)}">'
                      f'<span class="id">{escape(mid)}</span>'
                      f'<span class="gsrc">{escape(src)}</span>'
                      f'<span class="pill">{len(cards)} fixes</span>'
                      f'<span class="pill">{escape(md.get("provider") or "")} · {escape(md.get("model") or "—")}</span></a>')
            groups.append(header + "".join(cards))
    note = ('<div class="card" style="margin:14px 28px"><div class="lbl">How fixes get here</div>'
            '<div class="dim" style="font-size:13px;line-height:1.6">The fixer runs in <b>fix</b> mode on the '
            '<b>high-severity, attacker-reachable</b> threats of a model (and on any threat you click '
            '“Run fixer” on). Each fix below is grouped under the threat model it came from, and tagged with '
            'the skill that produced it and the component it touches.</div></div>')
    body = (note + "".join(f'<div class="fixgroup">{g}</div>' for g in groups)) if groups else \
        '<div class="empty">No fixes yet. Run a scan in <b>fix</b> mode, or open a model and click “Run fixer”.</div>'
    return _shell("fixes", f"Fix Queue · {total}", f'<div style="padding-top:8px">{body}</div>')


def _learn_page() -> bytes:
    skills = load_skills()
    g = IntentGraph()
    stats = {s["skill_id"]: s for s in g.skill_stats()}
    g.close()
    rows = []
    for sid, sk in sorted(skills.items()):
        st = stats.get(sid, {})
        cap = st.get("confidence_cap", sk.confidence_cap)
        acc, rej = st.get("accepted", 0), st.get("rejected", 0)
        rows.append(f"""<div class="skrow">
  <div><div class="skid">{escape(sid)}</div><div class="dim">{escape(', '.join(sk.triggers))}</div></div>
  <div class="dim">acc {acc} · rej {rej}</div>
  <div><div class="dim">cap {cap}</div><div class="bar2"><i style="width:{int(float(cap)*100)}%"></i></div></div>
  <div class="dim">{escape(sk.domain)}</div></div>""")
    intro = """<div class="card"><div class="lbl">Auto-evolution · the skill flywheel</div>
  <div class="dim" style="font-size:13px;line-height:1.6">Each completed model + fix outcome calibrates the firing
  skill's local <b>confidence cap</b> (accept ↑ / reject ↓), and accepted threats on similar components warm-start the
  next run. Confidence caps move automatically; skill <i>bodies</i> change only via human-reviewed PRs that pass the
  injection-scan gate. The federated (cross-customer) version is the paid tier.</div></div>"""
    head = '<div class="skrow" style="color:var(--text-dim);font-size:11px;text-transform:uppercase;letter-spacing:.1em"><div>skill · triggers</div><div>outcomes</div><div>confidence</div><div>domain</div></div>'
    body = f'<div style="padding:14px 0">{intro}<div class="card" style="padding:0">{head}{"".join(rows)}</div></div>'
    return _shell("learn", "Learn · Skills", body)


def _configure_page(saved: bool = False) -> bytes:
    from .local_llm import PROFILES
    cfg = get_config()
    ph = lambda v: "•••• configured (leave blank to keep)" if v else ""  # noqa: E731
    prov = ("Anthropic" if cfg.anthropic_key else "OpenAI-compatible" if (cfg.openai_base and cfg.openai_key)
            else "Local model" if cfg.use_local else "none (runs will require test mode)")
    opts = "".join(f'<option value="{escape(k)}"{" selected" if cfg.local_model == k else ""}>{escape(k)} · {escape(p.license)}</option>'
                   for k, p in PROFILES.items())
    note = '<div class="demo" style="background:rgba(16,163,127,.14);color:var(--teal);border-color:var(--teal)">Saved · takes effect immediately.</div>' if saved else ""
    body = f"""{note}<form class="scan cfg" method="post" action="/configure">
  <div class="card"><div class="lbl">Models · active provider: {escape(prov)}</div>
    <label>Anthropic API key</label>
    <input type="password" name="anthropic_key" placeholder="{ph(cfg.anthropic_key)}" autocomplete="off">
    <div class="frow"><div><label>OpenAI-compatible base URL</label>
      <input type="text" name="openai_base" value="{escape(cfg.openai_base or '')}" placeholder="http://localhost:11434/v1"></div>
      <div><label>OpenAI-compatible API key</label>
      <input type="password" name="openai_key" placeholder="{ph(cfg.openai_key)}" autocomplete="off"></div></div>
    <label>Default model id (optional)</label>
    <input type="text" name="model" value="{escape(cfg.model or '')}" placeholder="claude-sonnet-4-5 / gpt-4o-mini">
    <div class="frow"><div><label>Use bundled local model</label>
      <select name="use_local"><option value=""{" selected" if not cfg.use_local else ""}>no</option>
      <option value="1"{" selected" if cfg.use_local else ""}>yes (needs the [local] extra)</option></select></div>
      <div><label>Local model profile</label><select name="local_model">{opts}</select></div></div>
  </div>
  <div class="card"><div class="lbl">GitHub · private repositories</div>
    <label>GitHub token (used to fetch private repos you add as a source)</label>
    <input type="password" name="github_token" placeholder="{ph(cfg.github_token)}" autocomplete="off">
    <div class="hint">A fine-grained PAT with read access works. Stored locally in
      ~/.synthesis/settings.json (chmod 600); never sent anywhere except api.github.com.</div>
  </div>
  <div class="card"><div class="lbl">Safety</div>
    <div class="frow"><div><label>Sandbox (fix validation)</label>
      <select name="sandbox"><option value="off"{" selected" if cfg.sandbox != "docker" else ""}>off</option>
      <option value="docker"{" selected" if cfg.sandbox == "docker" else ""}>docker (rungs 1-3)</option></select></div>
      <div><label>Max LLM calls per run</label>
      <input type="text" name="max_llm_calls" value="{escape(str(cfg.max_llm_calls))}"></div></div>
  </div>
  <div style="padding:0 28px"><button class="btn" type="submit">Save settings</button></div>
</form>"""
    return _shell("configure", "Configure", body)


def _model_page(mid: str) -> bytes | None:
    md = store.load_model(mid)
    if not md:
        return None
    actions = '<a class="btn ghost" href="/models">← Threat Models</a>'
    return _shell("models", f"Threat Model · {mid}", render_body(md, fix_action=True), actions)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body: bytes, status: int = 200, ctype: str = "text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, loc: str):
        self.send_response(303)
        self.send_header("Location", loc)
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/models"):
            return self._send(_models_page())
        if path == "/new":
            return self._send(_new_page())
        if path == "/fixes":
            return self._send(_fixes_page())
        if path == "/learn":
            return self._send(_learn_page())
        if path == "/configure":
            return self._send(_configure_page(saved="saved" in urlparse(self.path).query))
        if path.startswith("/model/"):
            page = _model_page(path.rsplit("/", 1)[-1])
            return self._send(page or _shell("models", "Not found", '<div class="empty">Model not found.</div>'),
                              200 if page else 404)
        return self._send(_shell("models", "Not found", '<div class="empty">Not found.</div>'), 404)

    def _form(self) -> dict:
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n).decode("utf-8") if n else ""
        return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

    def do_POST(self):
        path = urlparse(self.path).path
        form = self._form()
        if path == "/scan":
            repo_lines = [x.strip() for x in form.get("repos", "").splitlines() if x.strip()]
            doc_lines = [x.strip() for x in form.get("docs", "").splitlines() if x.strip()]
            repos, more_docs = _classify(repo_lines)
            choice = form.get("model_choice", "")
            sel_provider, _, sel_model = choice.partition(":")
            allow_test = sel_provider == "test"
            provider = None if sel_provider in ("", "test") else sel_provider
            md = run_threat_model(repos=repos, docs=doc_lines + more_docs,
                                  mode=form.get("mode", "fix"), focus=form.get("focus", ""),
                                  allow_test=allow_test, provider=provider,
                                  model=(sel_model or None))
            if md.get("error"):
                return self._send(_new_page(md["error"]))
            return self._redirect(f"/model/{md['id']}")
        if path == "/configure":
            try:
                mlc = int(form.get("max_llm_calls", "") or 200)
            except ValueError:
                mlc = 200
            save_settings({
                "anthropic_key": form.get("anthropic_key", ""),
                "openai_base": form.get("openai_base", ""),
                "openai_key": form.get("openai_key", ""),
                "model": form.get("model", ""),
                "github_token": form.get("github_token", ""),
                "use_local": form.get("use_local") == "1",
                "local_model": form.get("local_model", ""),
                "sandbox": form.get("sandbox", "off"),
                "max_llm_calls": mlc,
            })
            return self._redirect("/configure?saved")
        if path == "/fix":
            mid, tid = form.get("model_id", ""), form.get("threat_id", "")
            run_fix(mid, tid)
            return self._redirect(f"/model/{mid}")
        return self._send(_shell("models", "Not found", '<div class="empty">Not found.</div>'), 404)


def serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    cfg = get_config()
    configure_logging(cfg.log_level, cfg.log_format)
    # bind, trying a few ports if the requested one is busy
    httpd = None
    for p in range(port, port + 10):
        try:
            httpd = ThreadingHTTPServer((host, p), _Handler)
            port = p
            break
        except OSError:
            continue
    if httpd is None:
        raise SystemExit(f"Could not bind a port in {port}..{port + 9}. "
                         f"Try: synthesis ui --port 9000")
    url = f"http://{host}:{port}"
    _log.info("Synthesis UI on %s", url)
    print(f"\n  UnitOne · Synthesis UI  →  {url}\n  (Ctrl-C to stop)\n")
    if open_browser:
        import threading
        import webbrowser
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
