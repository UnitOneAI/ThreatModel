# Synthesis

**Open-source threat modeling that doesn't stop at the report.** Point it at repos
and/or a design doc; it builds a STRIDE threat model (DFD, per-element coverage
matrix, OWASP/CWE/MITRE-grounded threats, reachability triage), then **proposes and
sandbox-validates fixes and opens a PR** — and the skills get sharper every time you
run it.

MCP-first: the engine is exposed as MCP tools, so any agent (Claude Code, Cursor,
your own orchestrator) calls the same loop. It also ships a CLI. A **real scan needs
a model** — a hosted key, an OpenAI-compatible endpoint, or the bundled local model.
If none is configured a real run **refuses rather than faking**; `--test` mode
produces templated fixtures for CI/UI demos only and is loudly labeled.

**The one command** (mix any number of repos and docs — they're merged into one model):

```bash
synthesis analyze <repo-or-doc> [<repo-or-doc> ...]
# e.g.
synthesis analyze https://github.com/org/api https://github.com/org/worker arch.md threats.md --mode fix
```

```
quick    one LLM pass                                   (≈ STRIDE-GPT / Threat Forge)
agentic  planner → parallel skill reviewers → critic    (the agentic loop)
fix      + sandbox-validated remediation → PR            ← nobody else does this for free
```

> Apache-2.0. The loop, skills, fixer, and a **local** Intent Graph are open. The
> **federated** cross-customer graph and the managed exploit-tier runtime are the
> paid tier — see [Open-core](#open-core).

---

## Quickstart

### pip
```bash
pip install 'synthesis-engine[mcp]'   # engine + MCP server
# pip install 'synthesis-engine[local]'   # + bundled local model (no API key needed)

export ANTHROPIC_API_KEY=sk-ant-...   # a real scan needs a model — pick one:
# or:  export OPENAI_BASE_URL=... OPENAI_API_KEY=...   (any OpenAI-compatible / local server)
# or:  pip install 'synthesis-engine[local]' && export SYNTHESIS_USE_LOCAL=1

synthesis analyze https://github.com/org/api https://github.com/org/worker \
  --doc design.md --mode fix --focus "unauthenticated peer; ransomware IT→OT"
```

### Docker
```bash
cp .env.example .env          # add a key, or set SYNTHESIS_USE_LOCAL=1 for the local model
docker compose run --rm synthesis analyze https://github.com/org/repo --mode fix
```

### Make (less typing)
```bash
make dev          # editable install + dev extras
make demo         # see the machinery in TEST mode (no key)
make test lint    # offline tests + ruff
make scan-skills  # the skill injection-scan gate
make build        # wheel (verifies skills are packaged)
make serve        # start the MCP server (stdio)
```

> **Storage note:** the local Intent Graph is SQLite — keep `SYNTHESIS_DB` on a real
> local disk, not a network/FUSE mount (file locking).

---

## Models / providers

The engine tries providers in this order; the first available wins:

| Order | Provider | How | Notes |
|---|---|---|---|
| 1 | **Anthropic** | `ANTHROPIC_API_KEY` | best quality |
| 2 | **OpenAI-compatible** | `OPENAI_BASE_URL` + `OPENAI_API_KEY` | vLLM, Ollama, LM Studio, local servers |
| 3 | **Bundled local model** | `pip install '.[local]'` + `SYNTHESIS_USE_LOCAL=1` | Default **Qwen3-4B-Instruct** (Apache-2.0, ~2.5GB), pulled from HF Hub at a pinned revision on first use and cached. Security-domain upgrade: `SYNTHESIS_LOCAL_MODEL=foundation-sec` (**Foundation-Sec-8B**, Cisco, ~4.9GB) or `foundation-sec-apache` (Apache base). Full override via `SYNTHESIS_LOCAL_REPO/FILE/REVISION`. |
| — | **Test mode** | `--test` / `SYNTHESIS_TEST_MODE=1` | **CI/UI demo only** — deterministic *templated fixtures*, not a real scan. Refuses to masquerade: every output is stamped `demo: true` + a warning. |

If none is configured, a real run returns an error telling you how to fix it — it
will **not** silently emit fixtures. The local model gives a genuine, free, fully
offline scan; test mode does not.

## Visual report & local UI

Threat modeling is visual. Every model renders as a self-contained HTML report —
data-flow diagram (Mermaid, with trust-zone subgraphs and attacker/asset/exposed
highlighting), STRIDE-per-element coverage matrix, threat actors, trust zones, OWASP
coverage, and a threat table with a per-threat fix drawer (mitigation, code diff,
honesty-gate badges).

```bash
synthesis analyze ./arch.md --html report.html     # write a report alongside a scan
synthesis report <model_id> --open                 # render a stored model + open it
synthesis ui                                       # local web app → http://127.0.0.1:8765
```

`synthesis ui` is a stdlib-only web app (no framework, localhost-bound), styled to the
UnitOne design system, with a left sidebar:

- **Threat Models** — list of every model you've run (persisted), and an **Add Threat
  Model Source** form to scan N repos + N docs together. Open one to see the full
  visual report (DFD, 3-column threat-analysis overview, STRIDE matrix, threats).
- **Fix Queue** — every generated fix across models: the diff, the skill that produced
  it, the component it touches, and security/behavior-verified badges.
- **Learn · Skills** — the skill auto-evolution surface: each skill's confidence cap
  and accept/reject history (the flywheel state).

## Use it from an agent (MCP)

Start the server: `synthesis serve` (stdio). Register it with your agent, e.g. for
Claude Code / Cursor:

```json
{
  "mcpServers": {
    "synthesis": { "command": "synthesis", "args": ["serve"] }
  }
}
```

Tools exposed:

| Tool | What it does |
|---|---|
| `threat_model(repos, doc, mode, focus)` | generate a model (DFD, STRIDE matrix, threats, fixes) |
| `fix(model_id, threat_id)` | run the fixer on one threat → diff + sandbox + PR |
| `get_model(model_id)` | fetch a stored model |
| `accept_threat(model_id, threat_id, accepted)` | human verdict → calibrates the skill (flywheel) |
| `list_skills()` / `skill_stats()` | the live skill index / current confidence caps |

---

## How it works

```
Phase 0  INGEST    N repos + doc → merged context + DFD seed
Phase A  PLAN      planner inventories components, SELECTS skills from the index
Phase B  ANALYZE   one read-only reviewer per (component × skill), in parallel,
                   emitting STRIDE entries with validated control IDs
Phase C  MERGE     dedupe, validate IDs resolve, reachability noise-cut
Phase D  CRITIQUE  challenge high-sev threats; downgrade unreachable ones
Phase E  FIX       propose diff → sandbox validate → PR + characterization test
```

**The honesty gate.** We own the *security* regression (replay the PoC, assert it now
fails, commit it as a permanent test). We do **not** own *functional* regression —
that needs your test suite. A fix that passes security but has no functional coverage
ships as *"security-verified, behavior-UNVERIFIED — human review required,"* never
dressed up as fully tested.

**Sandbox tiers.** Rungs 1–3 (build / lint+SAST / tests) run in a network-isolated
Docker container on your own code. Rung 4 (exploit no longer reproduces) and rung 5
(no behavioral regression) want hardware-grade isolation (gVisor / Firecracker per
invocation) to safely run untrusted, agent-generated exploit reproducers — that
hardened runtime is the managed tier. Same interface, swappable runtime.

---

## Skills & auto-evolution

Capabilities are **skills** — agentskills.io-style markdown in `skills/` with a
frontmatter header. Adding a `SKILL.md` adds a capability; the planner reads the live
index and selects skills per component (add an LLM component → `ai-security/llm-top-10`
fires, no code change).

After each run, outcomes calibrate each skill's local `confidence_cap`
(`synthesis stats` shows the state), and accepted threats on similar components
warm-start the next run. This is the flywheel — and it runs **locally**, so
"auto-evolving" is true for a self-hoster on day one.

```bash
synthesis skills      # the index
synthesis stats       # confidence caps move as you accept/reject findings
synthesis accept tm-abc123 t-def456 --reject   # feed a verdict back
```

---

## Open-core

| | Tier | Why |
|---|---|---|
| Loop, skills, fixer, **local** Intent Graph + calibration | **OSS (Apache-2.0)** | the tool genuinely improves on *your* codebase |
| **Federated** Intent Graph (every customer's outcomes improve every customer's planner) | **Paid** | the network effect — the actual moat |
| Managed gVisor/Firecracker exploit-tier (rungs 4–5 at scale) | **Paid** | safely running untrusted exploit code is an operational liability |
| Pre-warmed, signed skill releases | **Paid** | OSS starts cold; managed ships pre-trained |

The license protects nothing — the pooled memory does. `federated_warm_start()` in
`memory.py` is the seam a managed client overrides; the OSS build returns local-only.

---

## Status

v0.1 — engine, MCP server, CLI, skills, local Intent Graph, Docker sandbox (rungs
1–3), and the provider ladder (hosted / OpenAI-compatible / bundled local model /
test mode) all working; tests run offline with `pip install '.[dev]' && pytest` (no
key, no model). Real PRs need a GitHub App (synthetic PRs until configured); rung 4–5 need
the managed runtime. Built and maintained by [UnitOne](https://unitone.ai).
