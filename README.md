# Holy Skills

Holy Skills is a local curation and development repository for Codex skills.
It is meant to hold reusable skills while they are being designed, tested,
reviewed, and prepared for installation into a Codex skills directory.

## Layout

- `skills/`: source-controlled skill directories.
- `skills/full-repo-audit/`: a repository-wide audit skill copied from the
  local Codex skills installation.

Each skill directory should keep its own `SKILL.md`, README, scripts, agents,
fixtures, and tests together so the skill can be reviewed or installed as a
self-contained unit.

## Development Notes

When changing a skill:

1. Reproduce the issue or behavior you are changing before editing it.
2. Keep the skill contract in `SKILL.md` authoritative.
3. Test the changed path the same way it was reproduced.
4. Keep generated audit outputs, temporary runs, and local caches out of git.

This repository is public, so avoid committing private workspace paths,
secrets, customer data, or generated artifacts that include sensitive source
content.
