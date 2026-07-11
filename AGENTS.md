# DevCoordinator Agent Instructions

These rules apply to Codex and Claude Code in this repository.

## Repository freshness

- Before a repository-wide audit, broad refactor, migration, history rewrite,
  or split, run `python3 scripts/check_repository_freshness.py --repo "$PWD" --json`
  and inspect fetched remote-default ancestry.
- `current` and `ahead` are safe ancestry states. Reconcile `behind`,
  `diverged`, and `dirty-on-stale-base` before implementation.
  `remote-unavailable` is unknown, not proof of freshness.
- Never reset, rebase, stash, clean, or overwrite valuable dirty work to make a
  checkout current. Preserve it and reconcile from an isolated remote-fresh
  clone with an evidence-backed three-way merge.

## Incident and detector work

- Reproduce a user-reported error through the original surface before fixing
  it when reproduction is reasonable. Trace user intent, requirements,
  implementation, tests, tooling, and the missed-detection path first.
- Update the nearest durable guardrail before the product fix when practical.
  Keep one-off incident narratives in `DecisionHistory.md`, not policy.
- Detector changes must prove realistic recall for every advertised class and
  include false-positive controls for common intentional patterns.
- Re-test the original reproduction, the guardrail, and adjacent failure paths
  before reporting completion.

## Canonical skill ownership

- This repository is the only writable source for exactly
  `codex-dev-coordinator` and `postgres-docker-backup`.
- Install them only through `scripts/manage_skill_links.py` as direct absolute
  symlinks to this checkout. Never hand-edit a Codex, Claude, Parall, or other
  installed copy.
- Before relying on an installed skill, verify both direct `readlink` and
  canonical `realpath`. Preserve drift in a private rollback transaction and
  port intentional unique work here before replacement.
- Keep `SKILL.md` authoritative and mirror enforceable safety behavior in the
  deterministic self-tests.

## Repository independence and public history

- DevCoordinator must not acquire a source, build, runtime, test, CI, or pinned
  dependency on holyskills. `DEVCOORDINATOR_ROOT` is the only repository-root
  override for these products.
- Preserve the legacy Board bundle identifier/settings lookup solely for
  application identity migration; do not use it to resolve source.
- Keep actual environment files, credentials, private keys, runtime state,
  backups, logs, and rollback transactions outside Git. Only `.env.example`
  and provenance-bound deterministic fixtures may be published.
- Do not add non-canonical screenshots to reachable history. Run
  `scripts/check_repository_boundaries.py` before release.
- Record architectural decisions and later contradictions in
  `DecisionHistory.md`, including expected behavioral consequences.

## macOS app workflow

- Load and use the Build macOS Apps plugin before building, testing,
  snapshotting, packaging, launching, debugging, or automating DevOps Board.
- Do not use direct `swift`, `swiftc`, `xcodebuild`, XCUI, `open`, ad-hoc mouse,
  or keyboard control as a substitute.
- If the plugin is unavailable, stop the native gate and report it as pending;
  continue only non-native work.

## Services, Docker, and databases

- Before starting, stopping, restarting, or replacing a service, Docker
  resource, or local database stack, set
  `PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"` and run
  `python3 skills/codex-dev-coordinator/scripts/dev_coordinator.py inventory --project "$PROJECT_ROOT"`.
- Every mutation must include `--agent "$USER"` and
  `--project "$PROJECT_ROOT"`. Lease ports; do not probe a default port and
  silently move after a collision.
- Register an already-running owned resource rather than creating a duplicate.
- Before destructive PostgreSQL-in-Docker work, create and verify a backup with
  `postgres-docker-backup` and bind every live operation to the expected
  immutable container ID.
