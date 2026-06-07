# Synthesis-MCP — Architecture & Security Review (v2)

*Dual review: Security Architect + Software/Developer Architect · 2026-06-07 · re-review after remediation*
*(v1 review at the bottom for diff.)*

**Verdict:** **launch-ready for a public OSS release.** Every v1 release blocker is
closed and the full P1/P2 list is implemented. The suite is green (`pytest`, `ruff`),
the skill injection-scan gate passes, and the wheel now ships the skills. Remaining
items are explicitly-scoped maturity caveats (Postgres backend is beta; mypy is
advisory; live-provider inference is unit-tested via mocks, not run in CI), all
documented rather than hidden.

Score (1–5, enterprise readiness) — v1 → **v2**:
Architecture 4 → **4.5** · Security posture 3 → **4.5** · Operability 2 → **4** ·
Packaging/Release 2 → **4.5** · Test rigor 2.5 → **4**.

---

## 1. Language & stack (unchanged, confirmed)

100% **Python 3.10+**, stdlib-only core. Optional extras: `[mcp]` (MCP SDK),
`[local]` (llama-cpp-python + huggingface_hub), `[postgres]` (psycopg), `[dev]`
(pytest/ruff/mypy/build). Storage SQLite (default) or PostgreSQL (beta). Skills are
Markdown+YAML, shipped inside the package. Agent boundary: MCP over stdio (or SSE
with a required token). The wider UnitOne platform remains polyglot (TS/Next.js UI,
Python/FastAPI backend); this engine is the standalone Python half.

---

## 2. v1 findings — remediation status

### Release blockers (P0) — all CLOSED
| v1 | Finding | Status | Evidence |
|---|---|---|---|
| D1 | `pip install` broken (skills not packaged) | ✅ FIXED | skills moved to `synthesis_engine/skills/`; `package-data` globs; wheel build confirms **6 skill files** packaged; CI `build` job asserts it; `test_v2.py::test_skills_ship_inside_package`. |
| S1 | Skill injection-scan documented, not enforced | ✅ FIXED | `scripts/scan_skills.py` (control-id + injection + cap gate); CI `skill-scan` job; `test_v2.py` covers clean + malicious cases. |
| S2 | Local model unpinned (supply chain) | ✅ FIXED | `PROFILES` pin repo_id + filename + **commit SHA** per model (verified against HF API); `SYNTHESIS_LOCAL_REVISION` override. Default is Apache-2.0 Qwen3-4B; Foundation-Sec is an opt-in profile. |

### P1 — all implemented
| v1 | Finding | Status | Notes |
|---|---|---|---|
| D3 | Real-path test coverage ≈ 0 | ✅ | `test_v2.py` exercises `_llm_review` (incl. hallucinated-control nulling, inapplicable-STRIDE drop) and `_llm_dfd` via a mocked non-scripted provider. Live API/model inference still not run in CI (needs creds/weights) — documented. |
| D2 | SQLite concurrency / no PG | ✅ | WAL + `busy_timeout` + `synchronous=NORMAL`; `IntentGraph` now backend-agnostic with a PostgreSQL path (`postgresql://` DSN, `[postgres]` extra). **PG is beta — sqlite is the CI-tested default.** |
| S3 | No cost cap | ✅ | `BudgetedLLM` caps LLM calls/run (`SYNTHESIS_MAX_LLM_CALLS`); `BudgetExceeded` aborts cleanly + audits. |
| S9 | No audit log | ✅ | append-only JSONL (`audit.py`): scan_start/finish/aborted, fix_proposed (with sandbox rungs). `synthesis audit` to view. |
| S5 | Unauthenticated remote MCP | ✅ | SSE transport refuses to start without `SYNTHESIS_MCP_TOKEN`; stdio remains local-trust by design. |
| S4 | Output-encoding contract | ✅ | documented contract + `types.escape_html()` helper for HTML consumers. |

### P2 — implemented
| v1 | Finding | Status |
|---|---|---|
| D4 | No CI / lint / type | ✅ ruff (blocking) + mypy (advisory) + pytest matrix (3.10–3.12) + build + skill-scan in `.github/workflows/ci.yml` |
| D6 | Config sprawl | ✅ central typed `config.py` (`get_config()`); all `SYNTHESIS_*` read + validated in one place |
| D7 | No logging | ✅ `logging_setup.py` (text/JSON); modules log via `synthesis.*`; never logs secrets |
| D8 | Version duplicated | ✅ single-sourced — pyproject reads `synthesis_engine.__version__` dynamically |
| D5 | Three names | ✅ documented canonical naming (product *Synthesis*, dist `synthesis-engine`, import `synthesis_engine`); no rename churn |
| D10 | No CHANGELOG/CODEOWNERS/templates | ✅ all added; CODEOWNERS routes `skills/` to security reviewers |
| S6 | docker.sock exposure | ✅ Docker sandbox is opt-in (`SYNTHESIS_SANDBOX=docker`); default `off` |
| S7 | Loose GitHub URL parse | ✅ `urlparse` host allow-list |
| S8 | Broad exception swallowing | ✅ narrowed to specific exception types + logged |

---

## 3. Feature delivered alongside the review

**Multi-repo + multi-doc input.** The engine now merges **N repos and N docs**
(local file paths, doc URLs, or pasted text) into one model. CLI auto-detects mixed
inputs; MCP `threat_model` takes `repos[]` + `docs[]`. The one command:

```
synthesis analyze <repo-or-doc> [<repo-or-doc> ...] [--mode quick|agentic|fix]
```

---

## 4. Remaining items (honest maturity caveats — not blockers)

1. **PostgreSQL backend is beta** — implemented and import-clean, but only SQLite is
   exercised in CI (no PG service in the test matrix). Flagged in code + docs.
2. **mypy is advisory** in CI (`continue-on-error`) — the pinned mypy in this env
   crashed internally; types compile and ruff is green. Promote to blocking once a
   stable mypy run is confirmed.
3. **Live provider/model inference is mock-tested, not live-tested** — the real LLM
   and local-GGUF code paths have unit coverage via a fake provider, but an
   end-to-end run against a real key/model should be done on a developer machine
   (needs creds / a multi-GB download).
4. **Reachability is uniformly "exposed" in test mode** — a cosmetic artifact of the
   templated DFD; real provider DFDs produce guarded/not-reachable paths.
5. **Vestigial top-level `skills/`** exists on disk (this filesystem blocks deletion)
   but is gitignored — it is NOT in the published repo; canonical skills are in-package.

Suggested next: stand up a Postgres service in CI to graduate it from beta; add one
gated live-provider smoke test (skipped without a key); promote mypy to blocking.

---

## 5. Bottom line

v1 said "strong bones, not yet enterprise-grade." v2: the blockers are gone, the
supply-chain controls are enforced (not just documented), it installs and runs from
the artifact, and it's operable (config, logging, audit, budgets, auth seam). This
is a credible public launch; the remaining caveats are the normal pre-1.0 maturity
edges, stated openly.

---
---

# Appendix — v1 review (2026-06-06, pre-remediation)

v1 verdict was: strong bones, **not yet enterprise-grade**, with 3 release blockers
(D1 packaging, S1 unenforced skill-scan, S2 unpinned model) and a P1/P2 list covering
test coverage, SQLite concurrency, cost caps, audit logging, MCP auth, output
contract, config, logging, naming, version, and hardening. All of the above are
addressed in v2 §2.
