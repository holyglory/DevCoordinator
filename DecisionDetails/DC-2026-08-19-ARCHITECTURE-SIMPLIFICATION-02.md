# DC-2026-08-19-ARCHITECTURE-SIMPLIFICATION-02 — Retain control data, rebuild disposable execution state

## Confirmed scope

The user approved the complete follow-on simplification identified after
DC-2026-08-19-TEST-SIMPLIFICATION-01. DevCoordinator retains repository
registrations, routes, Console users, their grants, required Console settings,
and secret references. Repository source, project databases, credentials, and
recoverable database-backup artifacts remain outside destructive scope. Test
runs, cases, artifacts, timings, rollups, queues, plans, attempts, progress,
retry state, evidence reuse, compatibility history, and unfinished native test
work are disposable.

## Selected architecture

- A DevCoordinator or testd restart first imports any complete atomic result,
  then cancels unfinished tests and cleans their exact transient units. Callers
  rerun them. There is no recovery lease, cross-process attempt resurrection,
  legacy progress projection, or replayable result-chunk protocol.
- Testd keeps one execution slot per selected target and is the only semantic
  run authority. The root boundary persists and returns exact prepare, start,
  observe, stop, cgroup-empty, result-package, and collection facts; it never
  decides the test conclusion. Bounded aggregate statistics may be derived
  from retained terminal rows, but no second lifecycle or rollup authority is
  maintained.
- Preserve the stable public testing contract: `enqueue`, reviewed `submit`,
  `follow`, `queue-status`, cursor-bounded `failures` and `cases`, verified
  `artifact` and `artifact-export`, `cancel`, and manual failed-only `retry`.
  Retry creates a new immutable run. Advanced CLI and MCP commands are thin
  mappings over the same testd operations and never construct a local plan or
  independent conclusion.
- A repository test manifest continues to declare inputs, intents, current
  targets, no-shell commands, working directories, exact dependencies,
  timeouts, artifacts, explicit sharding/retry policy, and sealed fixture,
  credential, or typed state-handle references. Planning may inspect the live
  worktree, but every governed execution uses one immutable captured source.
- The completed pre-availability installation, legacy authority import,
  storage split, fleet adoption, temporary handoff listeners, and rollback to
  the pre-availability layout are unsupported and removed. Current releases
  use one immutable package, one fixed authority path, atomic activation,
  health verification, and rollback only to the immediately preceding
  current-format release.
- Root-owned atomic release state records the previous digest, candidate
  digest, and phase. Release content remains SHA-256 addressed. The transaction
  document has no self-hash, signature, or compatibility path binding.
- An incompatible authority schema exports only approved retained control
  collections, creates a fresh current database, imports those collections,
  invalidates prior operational handles through a new generation, and
  reobserves current host resources. Terminal operations, observations,
  tombstones, cleanup history, test data, and legacy migration records are not
  retained across that rebuild.
- The steady-state service boundary remains public edge, unprivileged
  Console/API application, root host authority, unprivileged test scheduler,
  and transient non-root repository/test units. One-time handoff and duplicate
  legacy broker services are removed. Further merging is allowed only when it
  does not mix public credentials, root host mutation, or repository execution.

## Supersession

This decision supersedes historical result-chunk replay, lease-based active-test
recovery, progress-schema compatibility, materialized fleet rollup authority,
legacy test journals, pre-availability cutover, legacy authority import, fleet
manifest adoption, and old-layout rollback portions of earlier decisions and
user-issue rows. It does not supersede reviewed release/handoff submission,
queue observability, complete cursor-bounded failures/cases, verified artifact
export, manual retry as a new run, change-based target selection, typed state
handles, or compatible same-schema reads. Exact resource identity, generation
and path checks, idempotent host mutation, public authorization, secret
transport, non-root repository execution, transient cgroup isolation, TTL
cleanup, bounded diagnostics, and repository-owned DevCoordinator delivery
remain.

## Alternatives and rationale

Keeping the current compatibility layers, simplifying only their
implementation, and rebuilding disposable state were considered. The first
two retain two test journals, eighteen historical Test Store tables, recovery
and chunk protocols, one hundred authority/broker table names, and a 36k-line
completed cutover product. Rebuilding disposable state follows the user's
retention boundary directly and makes failure recovery a rerun instead of a
second distributed state machine.

## Verification

Static contracts reject retired modules, binaries, units, operations, manifest
fields, tables, and documentation. Focused tests cover fresh-state launch,
dependency scheduling, timeout, cancellation, artifact validation, daemon
restart cleanup, retained-control export/import, current-format activation,
health, and rollback. Final readiness requires the complete repository-owned
software delivery workflow and installed browser/client acceptance.
