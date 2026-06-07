# Security Policy

Synthesis is a security tool, so we hold it to the bar it enforces.

## Reporting a vulnerability

Email **security@unitone.ai** with details and a reproduction. Please do not open a
public issue for a vulnerability. We aim to acknowledge within 3 business days and to
ship or disclose a fix on a coordinated timeline.

## Threat model of the tool itself

The two highest-risk surfaces, and how we contain them:

- **Skill bodies are system prompts.** A malicious skill is prompt injection against
  every user. Mitigations: skills are human-reviewed (never auto-merged), CI
  injection-scans every skill PR, review skills are loaded **read-only** (no write /
  network / exec tools), and emitted control IDs must resolve against
  `controls.py` (no hallucinated frameworks). See `CONTRIBUTING.md`.

- **The fixer executes agent-generated code.** Remediation diffs and exploit
  reproducers are untrusted. Rungs 1–3 run in a network-isolated, read-only,
  non-root Docker container on your own code. Rungs 4–5 (running an exploit PoC)
  require hardware-grade isolation (gVisor / Firecracker per invocation) — do **not**
  run rung 4+ under plain Docker. The OSS build ships Docker-only and reports rung
  4–5 as `requires_managed` rather than executing exploits under soft isolation.

## Handling of your data

- LLM calls go directly to the provider you configure (Anthropic, an
  OpenAI-compatible endpoint, or the bundled local model which runs entirely on your
  machine). With no provider, a real run refuses rather than emitting fixtures; test
  mode (templated, clearly labeled) is opt-in for CI/UI only.
- The local Intent Graph (SQLite) stays on your disk. The OSS build never sends your
  designs or outcomes anywhere; `federated_warm_start()` is a no-op unless you opt
  into the managed tier.
- Keep `SYNTHESIS_DB` off shared/network mounts.

## Supported versions

v0.1.x receives security fixes. Pre-1.0 — pin a version.
