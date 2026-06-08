# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog]; this project uses [Semantic Versioning] (pre-1.0: minor =
breaking allowed).

## [Unreleased]

### Added
- **Visual threat model**: Mermaid data-flow diagram (trust-zone subgraphs,
  attacker/asset/exposed highlighting, control-labeled flows) + self-contained HTML
  report (STRIDE matrix, threat actors, trust zones, OWASP coverage, threat table with
  per-threat fix drawer). New `synthesis report`, `synthesis ui` (stdlib web app), and
  `analyze --html`. Mermaid string is included in the model output (`mermaid` field).
- **Multi-input threat modeling**: N GitHub repos + N design docs (file paths, URLs,
  or pasted text) merged into one model. CLI auto-detects inputs.
- **Bundled local model** provider (`[local]` extra): runs a pinned GGUF via
  llama.cpp, no API key. Default Qwen3-4B-Instruct (Apache-2.0); Foundation-Sec-8B
  profile available. Model revisions are pinned (supply-chain integrity).
- **Provider ladder** with refuse-don't-fake: Anthropic → OpenAI-compatible →
  local → (opt-in) test mode. A keyless real run errors instead of emitting fixtures.
- **Skill injection-scan gate** (`scripts/scan_skills.py`) enforced in CI.
- **Append-only audit log** of scans, proposed fixes, and sandbox executions.
- **LLM call budget** per run (cost guard).
- Central typed config, structured logging, PostgreSQL backend option (beta),
  SQLite WAL hardening, `Makefile`, GitHub Actions CI, lint/type config.
- Skills now ship inside the package (installable via `pip`).

### Security
- Docker sandbox is opt-in (`SYNTHESIS_SANDBOX=docker`).
- Remote MCP transport refuses to start without `SYNTHESIS_MCP_TOKEN`.
- GitHub URL host validation; narrowed exception handling with logging.

## [0.1.0] — initial
- Agentic STRIDE loop (ingest→plan→analyze→merge→critique→fix), MCP server, CLI,
  skills + local Intent Graph, Docker sandbox (rungs 1–3), honesty gate.

[Keep a Changelog]: https://keepachangelog.com/
[Semantic Versioning]: https://semver.org/
