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

- A DevCoordinator or testd restart cancels unfinished tests and cleans their
  exact transient units. Callers rerun them. There is no recovery lease,
  cross-process attempt resurrection, legacy progress projection, or replayable
  result-chunk protocol.
- Testd keeps only current execution state and a bounded short-lived terminal
  result needed by `follow` and exact artifact retrieval. It publishes no
  historical statistics, fleet heatmaps, rollups, evidence-consumption state,
  or cross-run reuse decision.
- The public testing journey is run, follow, cancel, and artifact retrieval.
  Planning and launch validation remain implementation details of `run`.
  Manual retry is a new run.
- A repository test manifest declares current targets, no-shell command,
  working directory, dependencies, timeout, artifacts, and sealed fixture or
  credential references. It has no intent matrix, change-selection language,
  reuse policy, evidence policy, shard history, or retry policy.
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

This decision supersedes the test-history, cross-run reuse, retry, active-test
recovery, result-chunk replay, progress-schema compatibility, fleet analytics,
legacy test journal, pre-availability cutover, legacy authority import, fleet
manifest adoption, and old-layout rollback portions of earlier decisions and
user-issue rows. It narrows same-schema continuity to retained control data and
current-format release activation. Exact resource identity, generation and
path checks, idempotent host mutation, public authorization, secret transport,
non-root repository execution, transient cgroup isolation, TTL cleanup,
bounded diagnostics, and repository-owned DevCoordinator delivery remain.

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
