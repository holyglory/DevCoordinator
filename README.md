# Holy Skills

Holy Skills is a local curation and development repository for Codex skills.
It is meant to hold reusable skills while they are being designed, tested,
reviewed, and prepared for installation into a Codex skills directory.

## Layout

- `skills/`: source-controlled skill directories.
- `skills/full-repo-audit/`: a repository-wide audit skill copied from the
  local Codex skills installation.
- `skills/full-repo-test-coverage-audit/`: a repository-wide test coverage
  audit skill that reports missing unit, integration, UI journey, visual, and
  edge-case coverage.
- `skills/ui-implementation-audit/`: a UI implementation audit skill that
  batches only interface source files while comparing rendered desktop/mobile
  UI against mockups, visual assets, and user journey requirements.
- `skills/user-journey-docs-audit/`: a product documentation audit skill that
  actively interviews the user and checks whether Markdown/docs describe the
  app idea, users, journeys, UI priorities, edge cases, and usability
  acceptance criteria well enough to build excellent apps.
- `full_repo_harness/`: shared Python harness code for repository discovery,
  batching, manifests, queue markers, and verifier helpers used by audit
  skills.
- `scripts/validate.py`: repo-level validation for both skills, the shared
  harness, vendored fallback copies, and standalone skill-copy execution.

Each skill directory should keep its own `SKILL.md`, README, scripts, agents,
fixtures, and tests together so the skill can be reviewed or installed as a
self-contained unit.

## Development Notes

When changing a skill:

1. Reproduce the issue or behavior you are changing before editing it.
2. Keep the skill contract in `SKILL.md` authoritative.
3. Test the changed path the same way it was reproduced.
4. Keep generated audit outputs, temporary runs, and local caches out of git.

Run the release gate before committing public skill changes:

```bash
python3 scripts/validate.py
```

The root `full_repo_harness/` package is the canonical shared source. Each
skill also carries a vendored fallback copy under `scripts/_vendor/` so a single
skill directory can still be copied and self-tested on its own; the validation
script fails if those copies drift.

This repository is public, so avoid committing private workspace paths,
secrets, customer data, or generated artifacts that include sensitive source
content.
