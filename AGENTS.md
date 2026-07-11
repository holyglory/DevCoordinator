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
- Deterministic tests must isolate every host-sensitive discovery channel they
  assert is absent: global Git identity/configuration, executable `PATH`,
  standard binary fallbacks, ignored/generated files, credentials, ports, and
  runtime state. A developer machine's installed tools or leftovers must not
  make a negative fixture pass or fail.
- A concurrency test must stub every capability check that precedes its
  intended blocking boundary, prove the worker reached that boundary, and
  include any worker error in a timeout failure. Do not mistake failure to
  satisfy a prerequisite for evidence about serialization or locking.
- Never launch a bare `python -m http.server` test fixture on macOS-capable
  paths. Its inherited `HTTPServer.server_bind` can block on reverse DNS after
  bind but before listen. Use the repository's fast-bind socketserver fixture,
  and keep the AST recall/control guard that rejects literal raw http.server
  argv in the coordinator self-test.
- When a deterministic test passes its own temporary paths into production
  code that rejects symlink components, canonicalize only the test-created
  temporary root before deriving fixture paths. Keep a separate must-catch
  case proving that an operator-supplied path component symlink is rejected;
  never weaken the production guard for a host-managed alias such as macOS
  `/var -> /private/var`. Canonicalize other test-owned temporary roots before
  asserting path identity, provenance, or persisted canonical paths.
- When a body operation and its cleanup, rollback, diagnostic collection, or
  restoration can both fail, the top-level redacted structured error must
  retain every operator-relevant failure. Tests must inject returned failures
  and invocation exceptions at each boundary; causes or exception notes that
  the CLI serializer does not expose are not sufficient evidence.

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
- During an existing-host Console cutover, preserve checksummed per-process
  evidence for repeated clean cgroup samples and recheck immediately before
  stop. Every copied mutation phase must enable fail-fast shell semantics.
  Never treat state copied while a writer is active as lossless; checkpoint
  only after verified shutdown and immediately before relocation, and bind
  rollback to durable phase markers. Parse Linux `/proc/PID/stat` around its
  final parenthesized `comm` delimiter and use pidfds for signaling so PID reuse
  cannot redirect a signal. After the legacy writers are stopped, normalize both external
  state trees to private modes and rerun production layout preflight before
  state migration, relocation, or new-unit start.
- Treat the writer-free post-stop checkpoint through successful relocation as
  an operator-exclusive coordinator mutation window. Do not run another API or
  coordinator CLI against that home until relocation is committed or rollback
  is complete.
