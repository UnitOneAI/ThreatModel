<!-- Thanks for contributing. -->

## What & why

## Checklist
- [ ] `make test` passes (offline)
- [ ] `make lint type` clean
- [ ] If I changed/added a **skill**: `make scan-skills` passes, control IDs resolve,
      body is read-only with no injection language, `confidence_cap ≤ 0.85`
      (new skills start ≤ 0.65). See `CONTRIBUTING.md`.
- [ ] Updated `CHANGELOG.md` if user-facing
- [ ] Commits signed off (`git commit -s`, DCO)
