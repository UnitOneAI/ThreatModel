"""Visual threat model — styled to the UnitOne spine (dark theme, mono micro-labels,
teal/coral/amber accents). Sections mirror the spine UI: data-flow diagram (Mermaid),
a 3-column threat-analysis overview (OWASP rating / threat actors / trust boundaries),
STRIDE per-element matrix, and a threat table with a per-threat fix drawer.

`render_body()` returns the inner sections (embedded in the UI app shell);
`render_html()` wraps them as a standalone file with a logo header. Mermaid is
rendered the spine way (UMD build, securityLevel:'loose', explicit render(), source
passed as JSON). Framework-free.
"""
from __future__ import annotations

import json
from html import escape
from typing import Any

from .assets import logo_data_uri

_STRIDE = [
    ("spoofing", "S", "Spoofing"),
    ("tampering", "T", "Tampering"),
    ("repudiation", "R", "Repudiation"),
    ("information_disclosure", "I", "Info Disclosure"),
    ("denial_of_service", "D", "Denial of Service"),
    ("elevation_of_privilege", "E", "Elevation of Priv"),
]
_SEV = {"critical": "var(--coral)", "high": "var(--coral)", "medium": "var(--amber)",
        "low": "var(--text-dim)", "info": "var(--text-dim)"}
_REACH = {"exposed": "var(--coral)", "guarded": "var(--teal)",
          "not_reachable": "var(--text-dim)", "unknown": "var(--text-dim)"}


def _e(s: Any) -> str:
    return escape(str(s if s is not None else ""))


def colorize_diff(diff: str) -> str:
    """Render a unified diff as a colored block (added=green, removed=red, hunk=blue)."""
    lines = []
    for ln in (diff or "").split("\n"):
        if ln.startswith("+") and not ln.startswith("+++"):
            cls = "add"
        elif ln.startswith("-") and not ln.startswith("---"):
            cls = "del"
        elif ln.startswith("@@"):
            cls = "hunk"
        elif ln.startswith(("diff ", "index ", "+++", "---")):
            cls = "meta"
        else:
            cls = "ctx"
        lines.append(f'<span class="dl {cls}">{_e(ln) or "&nbsp;"}</span>')
    return '<pre class="diff">' + "\n".join(lines) + "</pre>"


def render_body(md: dict[str, Any], fix_action: bool = False) -> str:
    """Inner report sections (no <html>/header) — used by the UI shell."""
    if "error" in md:
        return f'<section class="card"><div class="lbl">Error</div><pre class="src">{_e(md["error"])}</pre></section>'
    design = md.get("design", {})
    sm = md.get("stride_matrix", {})
    threats = md.get("threats", [])
    mermaid_src = md.get("mermaid", "")

    banner = (f'<div class="demo">⚠ {_e(md.get("warning", "TEST MODE — templated, not a real scan."))}</div>'
              if md.get("demo") else "")

    stats = f"""<section class="stats">
  {_stat(len(md.get('dfd', {}).get('components', [])), 'components')}
  {_stat(len(threats), 'threats')}
  {_stat(sum(1 for t in threats if t.get('reachability') == 'exposed'), 'exposed', 'var(--coral)')}
  {_stat(f"{sm.get('covered', 0)}/{sm.get('applicable', 0)}", 'stride covered', 'var(--teal)')}
  {_stat(sm.get('gaps', 0), 'coverage gaps', 'var(--amber)')}
</section>"""

    scope = f"""<section class="card"><div class="lbl">Scope · {_e(md.get('mode'))} · provider {_e(md.get('provider'))} · model {_e(md.get('model') or '—')}</div>
  <div class="kv"><span>repos</span><div>{_e(', '.join(design.get('sources', [])) or '—')}</div></div>
  <div class="kv"><span>docs</span><div>{_e(', '.join(design.get('docs', [])) or '—')}</div></div>
  <div class="kv"><span>focus</span><div>{_e(design.get('focus') or '—')}</div></div>
</section>"""

    dfd = f"""<section class="card"><div class="lbl">Data flow diagram · Mermaid</div>
  <div class="legend">
    <span class="lg" style="border-color:var(--coral)">attacker</span>
    <span class="lg" style="border-color:var(--violet)">process</span>
    <span class="lg" style="border-color:var(--amber)">data store</span>
    <span class="lg" style="border:1px dashed var(--coral)">exposed</span>
    <span class="dim">dashed edge = weak/none control on a boundary crossing</span>
  </div>
  <div class="mermaid-box"><div id="mmd"></div><div id="mmderr"></div>
    <details><summary>▸ Mermaid source</summary><pre class="src">{_e(mermaid_src)}</pre></details>
  </div>
</section>"""

    script = f"""
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<script>
const MERMAID_SRC = {json.dumps(mermaid_src)};
function tg(i){{var d=document.getElementById('d'+i);if(d)d.classList.toggle('open');}}
(function(){{
  function render(){{
    if(!window.mermaid){{var e=document.getElementById('mmderr');if(e)e.textContent='mermaid · CDN unavailable (offline?)';return;}}
    try{{
      mermaid.initialize({{startOnLoad:false, theme:'default', securityLevel:'loose', fontFamily:'ui-monospace, monospace'}});
      mermaid.render('mmd-svg', MERMAID_SRC).then(function(r){{var m=document.getElementById('mmd');if(m)m.innerHTML=r.svg;}})
        .catch(function(err){{var e=document.getElementById('mmderr');if(e)e.textContent='mermaid · '+err.message;}});
    }}catch(err){{var e=document.getElementById('mmderr');if(e)e.textContent='mermaid · '+err.message;}}
  }}
  if(window.mermaid){{render();}}
  else{{var s=document.querySelector('script[src*="mermaid"]');if(s)s.addEventListener('load',render);else render();}}
}})();
</script>"""

    return (banner + stats + scope + dfd + _overview(md)
            + _stride_matrix(sm) + _threats(threats, md.get("id"), fix_action) + script)


def render_html(md: dict[str, Any], fix_action: bool = False) -> str:
    """Standalone single-file report (logo header + body)."""
    logo = logo_data_uri()
    logo_img = f'<img src="{logo}" alt="UnitOne" class="logo">' if logo else ""
    head = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Threat Model · {_e(md.get('id'))}</title><style>{REPORT_CSS}</style></head><body>
<header class="topbar">{logo_img}<div><div class="brand">UNITONE · SYNTHESIS</div>
<div class="htitle">Threat Model</div></div>
<div class="meta">{_e(md.get('id'))}</div></header><main class="content">"""
    return head + render_body(md, fix_action) + "</main></body></html>"


def _stat(value: Any, label: str, color: str = "var(--text)") -> str:
    return (f'<div class="stat"><div class="num" style="color:{color}">{_e(value)}</div>'
            f'<div class="slbl">{_e(label)}</div></div>')


def _overview(md: dict[str, Any]) -> str:
    """Spine 'Threat analysis · before mitigation' — 3 columns."""
    owasp = md.get("owasp_coverage", {})
    actors = md.get("threat_actors", [])
    boundaries = md.get("trust_boundaries", [])
    if not (owasp or actors or boundaries):
        return ""
    owasp_chips = "".join(f'<span class="ochip">{_e(k)} · {_e(v)}</span>' for k, v in sorted(owasp.items())) or '<span class="dim">—</span>'
    actor_items = "".join(
        f'<li><span class="aname">{_e(a.get("name"))}</span> <span class="dim">· {_e(a.get("capability"))}</span>'
        f'<div class="dim">motivation: {_e(a.get("motivation"))} · {_e(a.get("count"))} threat(s)</div></li>'
        for a in actors) or '<li class="dim">—</li>'
    boundary_items = "".join(
        f'<li><span class="bflow">{_e(b.get("from"))} → {_e(b.get("to"))}</span>'
        f'<div class="dim">control: {_e(b.get("control"))}'
        + (f' <span class="gap">· gap: {_e(b.get("gap"))}</span>' if b.get("gap") else "")
        + '</div></li>'
        for b in boundaries) or '<li class="dim">—</li>'
    return f"""<section class="card"><div class="lbl">Threat analysis · before mitigation</div>
  <div class="cols3">
    <div class="ov"><div class="ovh">OWASP rating</div><div class="ochips">{owasp_chips}</div></div>
    <div class="ov"><div class="ovh">Threat actors</div><ul class="ovl">{actor_items}</ul></div>
    <div class="ov"><div class="ovh">Trust boundaries</div><ul class="ovl">{boundary_items}</ul></div>
  </div>
</section>"""


def _stride_matrix(sm: dict[str, Any]) -> str:
    rows = sm.get("rows", [])
    if not rows:
        return ""
    head = "".join(f'<th title="{_e(full)}">{_e(short)}</th>' for _k, short, full in _STRIDE)
    body = []
    for r in rows:
        cells = []
        for key, _short, _full in _STRIDE:
            v = r.get("cells", {}).get(key, "n_a")
            cls = {"covered": "cov", "gap": "gap", "n_a": "na"}.get(v, "na")
            mark = {"covered": "✓", "gap": "•", "n_a": "·"}.get(v, "")
            cells.append(f'<td class="{cls}" title="{_e(v)}">{mark}</td>')
        body.append(f'<tr><td class="rl">{_e(r.get("name"))} <span class="dim">{_e(r.get("kind"))}</span></td>{"".join(cells)}</tr>')
    return f"""<section class="card"><div class="lbl">STRIDE coverage matrix</div>
  <div class="legend"><span class="lg cov">✓ covered</span><span class="lg gap">• gap</span><span class="lg na">· n/a</span></div>
  <table class="matrix"><thead><tr><th class="rl">element</th>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>
</section>"""


def _threats(threats: list[dict[str, Any]], model_id: str = "", fix_action: bool = False) -> str:
    if not threats:
        return '<section class="card"><div class="lbl">Threats</div><p class="dim">No threats.</p></section>'
    rows = []
    for i, t in enumerate(threats):
        sev = t.get("severity", "medium")
        reach = t.get("reachability", "unknown")
        mit = t.get("mitigation") or {}
        ctrl = " · ".join(x for x in [t.get("owasp"), t.get("cwe"), t.get("mitre")] if x)
        inner = _fix_drawer(t, mit) if mit else '<div class="dim">No mitigation generated yet.</div>'
        if fix_action:
            inner += (f'<form method="post" action="/fix" class="fixform">'
                      f'<input type="hidden" name="model_id" value="{_e(model_id)}">'
                      f'<input type="hidden" name="threat_id" value="{_e(t.get("id"))}">'
                      f'<button type="submit">▶ Run fixer on this threat</button></form>')
        rows.append(f"""<div class="threat">
  <div class="trow" onclick="tg({i})">
    <span class="sev" style="background:{_SEV.get(sev, 'var(--text-dim)')}">{_e(sev)}</span>
    <span class="reach" style="color:{_REACH.get(reach, 'var(--text-dim)')}">{_e(reach)}</span>
    <span class="tn">{_e(t.get('name'))}</span>
    <span class="tstride">{_e(t.get('stride'))}</span>
    <span class="dim tctrl">{_e(ctrl)}</span>
  </div>
  <div class="tdrawer" id="d{i}">{inner}</div>
</div>""")
    return f'<section class="card"><div class="lbl">Threats · {len(threats)}</div>{"".join(rows)}</section>'


def _fix_drawer(t: dict, mit: dict) -> str:
    badges = []
    badges.append('<span class="badge ok">security-verified</span>' if mit.get("security_verified")
                  else '<span class="badge warn">security unverified</span>')
    badges.append('<span class="badge ok">behavior-verified</span>' if mit.get("behavior_verified")
                  else '<span class="badge warn">behavior UNVERIFIED</span>')
    if mit.get("skill_id"):
        badges.append(f'<span class="badge">skill · {_e(mit["skill_id"])}</span>')
    if mit.get("pr_url"):
        badges.append(f'<span class="badge">{_e(mit["pr_url"])}</span>')
    diff = (f'<div class="diffh">Proposed fix</div>{colorize_diff(mit["code_fix"])}'
            if mit.get("code_fix") else "")
    return f"""<div class="ev"><b>Evidence</b> · {_e(t.get('evidence') or '—')}</div>
  <div class="badges">{''.join(badges)}</div>
  <div class="mit"><b>Mitigation</b> · {_e(mit.get('prose') or '—')}</div>
  {diff}"""


# Shared design tokens + report styles (the UI shell imports this).
REPORT_CSS = """
:root{
  --bg:#f6f8fb; --surface:#ffffff; --surface-2:#f1f4f9;
  --border:rgba(15,23,42,.10); --border-strong:rgba(15,23,42,.18);
  --text:#0f172a; --text-muted:rgba(15,23,42,.68); --text-dim:rgba(15,23,42,.48);
  --teal:#10a37f; --coral:#e11d48; --amber:#d97706; --violet:#7c3aed;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}
.mono,.lbl,.slbl,.brand,.src,.diff,.ovh{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.topbar{display:flex;align-items:center;gap:14px;padding:14px 28px;border-bottom:1px solid var(--border);background:var(--surface)}
.logo{width:30px;height:30px;border-radius:7px}
.brand{font-size:10px;letter-spacing:.24em;color:var(--teal);font-weight:700}
.htitle{font-size:17px;font-weight:700;margin-top:1px} .topbar .meta{margin-left:auto;font-size:11px;color:var(--text-dim)}
.content{padding:6px 0 60px}
.demo{background:rgba(239,83,80,.16);color:var(--coral);border-bottom:1px solid var(--coral);padding:9px 28px;font-size:12px;font-weight:600}
.stats{display:flex;gap:12px;flex-wrap:wrap;padding:18px 28px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:12px 18px;min-width:118px}
.num{font-size:24px;font-weight:700}
.slbl{font-size:10px;text-transform:uppercase;letter-spacing:.14em;color:var(--text-dim);margin-top:4px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;margin:14px 28px;padding:18px 22px}
.lbl{font-size:10px;text-transform:uppercase;letter-spacing:.14em;color:var(--text-dim);margin-bottom:14px}
.kv{display:flex;gap:14px;padding:4px 0;font-size:14px}
.kv span{color:var(--text-dim);min-width:90px;font-size:12px}
.dim{color:var(--text-dim);font-size:12px}
.cols3{display:grid;gap:12px;grid-template-columns:repeat(3,1fr)}
@media(max-width:820px){.cols3{grid-template-columns:1fr}}
.ov{border:1px solid var(--border);background:var(--bg);border-radius:8px;padding:12px}
.ovh{font-size:10px;text-transform:uppercase;letter-spacing:.12em;color:var(--text-dim);margin-bottom:8px}
.ovl{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:8px;font-size:12px}
.aname{color:var(--text);font-weight:600} .bflow{font-family:ui-monospace,monospace;font-size:11px;color:var(--text)}
.gap{color:var(--coral)}
.ochips{display:flex;flex-wrap:wrap;gap:6px}
.ochip{border:1px solid var(--amber);color:var(--amber);border-radius:6px;padding:1px 7px;font-size:10px;font-family:ui-monospace,monospace}
.legend{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px;font-size:11px}
.lg{padding:2px 9px;border-radius:6px;border:1px solid var(--border-strong);color:var(--text-muted)}
.lg.cov{border-color:var(--teal);color:var(--teal)} .lg.gap{border-color:var(--amber);color:var(--amber)} .lg.na{color:var(--text-dim)}
.mermaid-box{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;overflow-x:auto}
#mmd svg{max-width:100%}
#mmderr{color:var(--coral);font-size:11px;font-family:ui-monospace,monospace;margin-top:8px}
details{margin-top:10px} summary{font-size:10px;text-transform:uppercase;letter-spacing:.14em;color:var(--text-dim);cursor:pointer}
summary:hover{color:var(--text-muted)}
.src{font-size:11px;background:var(--surface-2);border-radius:8px;padding:12px;overflow-x:auto;color:var(--text-muted);white-space:pre;margin-top:8px}
table.matrix{border-collapse:collapse;width:100%;font-size:13px}
.matrix th,.matrix td{border:1px solid var(--border);padding:7px 9px;text-align:center}
.matrix th{color:var(--text-dim);font-size:11px;font-weight:600}
.matrix th.rl,.matrix td.rl{text-align:left;min-width:240px}
.matrix td.cov{color:var(--teal);font-weight:700} .matrix td.gap{color:var(--amber)} .matrix td.na{color:var(--text-dim)}
.threat{border:1px solid var(--border);border-radius:8px;margin-bottom:8px;overflow:hidden;background:var(--surface)}
.trow{display:flex;gap:12px;align-items:center;padding:10px 12px;cursor:pointer}
.trow:hover{background:var(--surface-2)}
.sev{color:#0b0f1a;border-radius:5px;padding:2px 8px;font-size:10px;font-weight:700;text-transform:uppercase}
.reach{font-size:11px;font-weight:600;min-width:90px;text-transform:uppercase;letter-spacing:.06em}
.tn{font-weight:600;flex:1} .tstride{font-size:12px;color:var(--text-muted)} .tctrl{font-size:11px}
.tdrawer{display:none;padding:14px 16px;background:var(--surface-2);border-top:1px solid var(--border);font-size:13px}
.tdrawer.open{display:block}
.ev,.mit{margin-bottom:8px;color:var(--text-muted)} .ev b,.mit b{color:var(--text)}
.badges{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px}
.badge{font-size:10px;border-radius:5px;padding:2px 8px;background:var(--surface);border:1px solid var(--border);color:var(--text-muted)}
.badge.ok{border-color:var(--teal);color:var(--teal)} .badge.warn{border-color:var(--amber);color:var(--amber)}
.diffh{font-weight:600;margin:6px 0 4px}
.diff{background:#0b0f1a;color:#cbd5e1;padding:12px;border-radius:8px;overflow:auto;font-size:12px;white-space:pre-wrap;border:1px solid var(--border)}
.diff .dl{display:block;padding:0 4px;border-radius:2px}
.diff .add{color:#4ade80;background:rgba(74,222,128,.12)}
.diff .del{color:#f87171;background:rgba(248,113,113,.12)}
.diff .hunk{color:#38bdf8} .diff .meta{color:#94a3b8} .diff .ctx{color:#cbd5e1}
.fixform{margin-top:10px}
.fixform button{background:var(--teal);color:#06251c;border:0;border-radius:6px;padding:8px 14px;font-size:12px;font-weight:700;cursor:pointer;text-transform:uppercase;letter-spacing:.06em}
.fixform button:hover{filter:brightness(1.08)}
"""
_CSS = REPORT_CSS  # back-compat alias