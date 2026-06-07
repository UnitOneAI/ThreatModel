# Contributing

Thanks for helping. Two contribution paths: **code** and **skills**. Skills have
extra rules because a skill body becomes a system prompt — a poisoned skill is a
supply-chain attack on everyone who runs Synthesis.

## Code

```bash
pip install -e '.[dev,mcp]'
pytest -q                     # all tests run offline; no key needed
```

- Keep the **core** path stdlib-only (no required deps) so the engine runs offline.
- Anything network/LLM/sandbox must degrade gracefully to the scripted/local path.
- New control IDs must be added to `controls.py` (and resolve) — the loop rejects
  any emitted ID that doesn't resolve. No hallucinated controls, ever.

## Skills (read this before opening a skill PR)

A skill is `skills/<domain>/<name>.md` with YAML frontmatter:

```yaml
---
id: appsec/my-skill
domain: appsec
title: My Skill
confidence_cap: 0.6          # new skills start LOW; the cap is earned via outcomes
triggers: [process, api]     # component kinds / keywords that select this skill
control_frameworks: [OWASP-2021]
---
<the reviewer instructions — this becomes the system prompt>
```

**Hard rules — a skill PR is rejected if it violates any:**

1. **Real control IDs only.** Every framework ID the skill instructs the model to
   emit must resolve in `controls.py`. PRs that add IDs must add them to the tables.
2. **Read-only.** Review skills observe; they never instruct file writes, network
   calls, or command execution. Only the downstream fixer writes, in the sandbox.
3. **No instruction-injection.** The body must not contain text that tries to
   override the host system, exfiltrate context, or escalate tool access. CI runs an
   **injection scan** on every skill PR; it must pass.
4. **Human-gated, never auto-merged.** Skill bodies change only via reviewed PR.
   (Confidence-cap calibration is automatic and *local* — it never edits the body.)
5. **Start low.** `confidence_cap ≤ 0.65` for new skills; the cap is earned from
   accepted outcomes, not asserted.

## The evolution loop (how skills improve)

Outcomes (accept/reject verdicts, critic disagreement, PoC results) calibrate each
skill's local confidence cap automatically. When a *new pattern* recurs, the right
move is a PR that adds an `examples/` case or a new skill — under the rules above.
We never auto-merge a skill change from a model's output.

## DCO

Sign off your commits: `git commit -s`. By contributing you agree to the Apache-2.0
license and the Developer Certificate of Origin.
