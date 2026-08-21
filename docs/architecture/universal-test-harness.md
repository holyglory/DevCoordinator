# Universal test harness

This document is the current DevCoordinator governed-test contract. Test Store
schema versions are fail-closed release discriminators, not compatibility
modes. Historical lease, spool, result-chunk, and in-run retry protocols are
not part of the current architecture.

## Scope

DevCoordinator coordinates attributed asynchronous tests across repositories
on one Linux/systemd server. A direct local test is narrow feedback only: one
invocation must be proven before launch to collect at most 20 cases, enforce at
most 10 seconds of execution, need no host-visible or shared state, and not be
one fragment of a larger suite. Unknown or larger scope and all durable,
handoff, or release evidence use one governed enqueue.

DevCoordinator never validates or installs itself through its installed
runtime or test plane. Its repository-owned command is:

```bash
python3 scripts/software_owned_delivery.py run --help
```

A DevCoordinator release or cutover changes DevCoordinator itself, never a
repository under test. Test data is disposable. Repository registrations,
routes, Console users and grants, settings, secret references, repository
source, project databases, and recoverable database-backup artifacts are not
test history and remain outside a Test Store reset.

## Service and state boundaries

- The authority resolves immutable repository identity and generation, seals
  protected capabilities, and exposes the kernel-attributed local broker.
- `devcoordinator-testd` and its private Test Store are the only semantic
  authority for plans, runs, exact dependency readiness, one execution slot
  per selected target, deadlines, terminal conclusions, cases, failures,
  artifacts, and bounded statistics derived from terminal rows.
- The root snapshot/runtime boundary performs generation-fenced,
  descriptor-bounded `prepare`, `start`, `observe`, `stop`, cgroup-empty proof,
  result-package access, and collection. It returns host facts and never
  chooses a test conclusion.
- A trusted runner executes repository commands as the recorded actual
  non-root caller in a transient systemd unit. Repository code never runs as
  root, testd, the authority, or a filesystem stat owner selected by inference.
- Public identity and route grants remain authorization boundaries. Local Unix
  identity supplies attribution and the execution UID under the confirmed
  single-developer trust model; it is not repository- or account-scoped local
  authorization.

High-volume test evidence never enters the authority database. The Test Store
contains only current disposable test state. It has no durable recovery spool,
lease or heartbeat-renewal authority, semantic result chunks, compatibility
progress projection, cross-run evidence cache, or independent rollup state
machine.

## One execution lifecycle

1. Protected planning validates `.codex/tests.json`, inspects current Git
   changes when required, expands exact declared dependencies, captures the
   selected source immutably, and registers one deterministic plan. For
   `change` and `checkpoint`, live worktree inspection is selection input only:
   execution still uses the exact immutable capture. A change between
   inspection and capture rejects planning and requires a fresh plan.
2. Submission is idempotent under the exact repository, plan, actor, and
   operation identities. It creates one run and one empty execution slot for
   each selected target. A replay of identical input returns the same result;
   conflicting input under the same operation ID fails.
3. Testd schedules only targets whose exact dependencies succeeded. A failed
   dependency cancels only its transitive dependents; independent branches
   continue. Admission uses current host-available memory and learned target
   memory. CPU is measured, not used as a rejection gate.
4. Before launch, testd and the root boundary revalidate the exact repository
   ID and generation, plan/run/target/execution identity, immutable source and
   launch fingerprints, caller execution UID, contained paths, target TTL, and
   lifecycle state. A stale generation, substituted identity, path escape, or
   conflicting replay fails before repository code runs.
5. The root boundary starts one transient systemd unit as the recorded non-root
   UID with a clean environment, hidden unrelated homes, private scratch,
   `KillMode=control-group`, an explicit positive TTL, and
   `kill_after_run=true`. Systemd owns TERM/KILL escalation and the cgroup
   `populated=0` cleanup proof.
6. The unit's cgroup is a required isolation, cancellation, accounting, and
   cleanup primitive. CPU, memory, I/O, and task accounting remain enabled, but
   the harness does not translate repository declarations into per-run
   `CPUQuota`, `MemoryHigh`, `MemoryMax`, or `TasksMax` policy. Cgroup isolation
   is therefore required even though per-run resource quotas are not.
7. The runner continuously drains bounded captures and parses driver-specific
   reports into normalized cases, failures, artifacts, timing, and outcome.
   After the repository process exits, it publishes exactly one deterministic
   uncompressed USTAR `result-package.tar` by atomic rename. The package
   manifest binds repository/run/target/execution generations, descriptor
   fingerprint, outcome, counts, member names, sizes, and SHA-256 digests.
8. Testd validates the complete package as one object, imports its normalized
   records transactionally, commits the terminal conclusion, and then requests
   exact privileged stop/collection. A partial, malformed, excessive,
   secret-bearing, identity-mismatched, or digest-mismatched package is never
   treated as measured test evidence.

There is no automatic retry inside a run. The public failed-only `retry`
command creates a new immutable plan/run with a dense exact dependency graph
and its own identities. A changed source is captured by a fresh plan; an old
live-source fingerprint is never replayed.

## Restart, cancellation, and cleanup

On testd, authority, or DevCoordinator release restart, recovery is deliberately
result-first and finite:

1. enumerate exact retained nonterminal execution identities;
2. import a complete, valid `result-package.tar` if one was atomically
   published;
3. otherwise stop the exact transient unit, require its original cgroup to be
   empty, mark the unfinished execution cancelled, and collect its private
   material; and
4. reopen admission only after that bounded reconciliation completes.

Callers rerun cancelled unfinished work. Restart never renews a lease,
resurrects an execution in another process, replays a result chunk stream, or
launches a replacement under the old execution identity.

Explicit cancellation follows the same ordering: preserve an already complete
package, otherwise stop the exact unit and terminalize only after stopped and
cgroup-empty proof. Repeated cancellation with the same operation ID is
idempotent.

## Source, manifest, and dependency contract

Manifest schema 4 is strict. It declares bounded inputs and intents, current
targets, driver/reporter, shell-free argv, contained cwd, exact dependencies,
target timeouts, artifacts, fixtures, credential aliases, network capability,
typed state handles, and bounded non-secret literal environment. It does not
declare CPU, memory, PID, worker quotas, recovery leases, result chunks, or an
automatic multi-attempt retry policy.

Selection fails toward more testing. Manifest, dependency-lock, build-system,
CI, global-input, unmapped, renamed, deleted, and unexpected untracked changes
select the complete required intent. Invalid graphs, unsafe paths, incomplete
source capture, or missing protected capability coverage block planning.

Immutable source includes tracked, staged, unstaged, and bounded non-ignored
untracked files plus manifest, dependency-lock, and toolchain identity.
Generated dependency trees are not copied as source. Coordinator may derive
only the target's standard lock-matched Python, Node, .NET/package-cache, or
narrow external toolchain mapping and expose it read-only at the expected
materialized location. Repositories cannot declare arbitrary host mounts or a
whole-home mapping.

A target may opt into a bounded named SQLite state handle. The root boundary
validates the real repository-contained directory and database entry, pins
their device/inode identities, revalidates them immediately before launch, and
binds the directory read-only at its fixed unit-private destination. Only the
declared non-secret environment path is added. The database is not copied into
source or artifacts and is unavailable to targets that did not request it.

## Network, fixtures, and secret transport

Network defaults to none. Private isolated loopback is ordinary local test
reachability. Host loopback, external access, sealed fixtures, and operational
credentials require their exact current protected capability. Fixture names
resolve only to sealed templates; manifests cannot provide images, mounts,
privileges, secrets, or Docker arguments.

Credential declarations contain opaque aliases only. The root boundary
resolves an administrator-sealed, generation-bound binding and delivers the
value through transient systemd `LoadCredential=` transport. Values and
private paths never enter a manifest, plan, launch argv, ordinary environment,
Test Store row, result package, artifact metadata, call journal, Console, or
model-facing result. Rotation and revocation prevent new delivery; cancelling
the exact active execution plus its TTL bounds a value already copied by the
kernel into a running unit.

## Agent and administrative surfaces

The installed stable agent surface is:

```text
devcoordinator test enqueue
devcoordinator test submit PLAN
devcoordinator test follow RUN
devcoordinator test queue-status
devcoordinator test failures RUN
devcoordinator test cases RUN
devcoordinator test artifact RUN ARTIFACT
devcoordinator test artifact-export RUN ARTIFACT --output NEW_FILE
devcoordinator test cancel RUN --reason TEXT
devcoordinator test retry RUN --failed-only
```

`enqueue` is the normal run command: it registers and submits routine intents.
`handoff` and `release` stop after registered immutable plan creation and
require explicit `submit`. There is no separate stable `test run`, `status`,
`summary`, or `wait` alias; `follow` owns immediate observation, bounded wait,
and summary. DevCoordinator's own repository delivery command named `run` is
the separate `software_owned_delivery.py run` workflow shown above.

The protected advanced interface additionally supports manifest management,
plan preview, exact status/summary/wait mappings, `policy check`, `catalog`, and
`stats`. These are thin testd operations, not a local planner, scheduler,
conclusion engine, or advisory evidence publisher.

Every continuation carries the canonical `--project` scope whenever repository
context is known, so it resolves the same immutable repository from another
working directory. Opaque plan, run, execution, and artifact handles are
references, not credentials and not substitutes for repository scope.

## Bounded evidence

Agent results have a fixed 8 KiB ceiling. `follow` returns one non-empty
decision with command success, current state, timeout truth, exact continuation,
and next command. Run conclusion is a separate field: `ok: true` can accompany
a failed test conclusion.

Failure and case reads return the largest ordered non-empty prefix that fits
the envelope. `next_cursor` is the final returned record whenever more rows
exist or size shortened the requested page; it becomes null only after complete
exhaustion. Every retained failed/error case has one bounded failure record.

`artifact` verifies exact run/artifact identity, size, and SHA-256 and may
return a bounded UTF-8 tail. `artifact-export` transfers a verified retained
blob in bounded byte pages, checks stable identity, contiguity, total size, and
the complete digest, then atomically creates a new mode-0600 local file without
overwrite. Those byte pages are an explicit export transport, not semantic
runner result chunks. Artifact bytes never enter agent JSON, call journals,
Console, or public HTTP.

## Replacement and release

Compatible read-only follow, queue, failure, case, and artifact requests may
cross a same-schema release digest change only when protocol, authority
generation, Test Store schema, result bounds, capability contract, repository,
and requested identity still match. Mutations retain exact release matching.

An incompatible Test Store release stops testd, performs result-first cleanup
of unfinished units, and activates an empty current store. It does not back up,
import, migrate, or reinterpret prior test rows. The operation is confined to
the testd-owned database and never opens the retained authority, profile,
inventory, Console, repository-source, project-database, credential, or backup
stores.

## Acceptance

Focused contracts cover manifest/source validation, exact dependency branches,
one execution slot per target, identity and generation drift, path escape,
idempotent replay, non-root UID, systemd cgroup/TTL cleanup, cancellation,
result-package validation and atomic publication, cursor completeness, artifact
export, restart result-first cleanup, secret exclusion, and fresh-store
activation.

Final readiness requires the complete repository-owned
`scripts/software_owned_delivery.py` cycle, including repository boundaries,
immutable package verification, installed agent access, current release
activation/rollback, and browser acceptance. Installed DevCoordinator test or
runtime commands are never self-hosted as its release evidence.
