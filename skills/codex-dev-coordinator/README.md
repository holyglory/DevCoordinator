# Codex Dev Coordinator

`codex-dev-coordinator` is a local, single-machine coordination layer for
development processes, port leases, declared project runtimes, and Docker
lifecycle commands used by multiple Codex or Claude Code sessions.

It is implemented by `scripts/dev_coordinator.py`. The skill contract in
`SKILL.md` is authoritative; this README describes what the implementation
honestly does and does not provide.

## What It Provides

- A locked, private, atomically written state file shared by cooperating local
  agent sessions.
- Port leasing with expiry and stale-lease reclamation.
- Atomic, exact-precondition transfer of a stopped server's durable port and
  reusable identity when an operator moves ownership to a new checkout.
- Structured-argv process launch, including atomic attachment of an existing
  manual lease by exact ID, plus adoption, status, logs, stop, and restart.
- Project-level status/start/restart/stop driven by
  `.codex/dev-runtime.json` declarations.
- Docker inventory, telemetry, logs, Compose lifecycle commands, and
  coordinator-side ownership metadata.
- Process and Docker resource summaries based on measured local state.
- A loopback-only bearer-token HTTP API for the same local operations.

The coordinator records provenance and operation evidence so a failed or
superseded action is not silently presented as successful.

## Concurrency Model

The cross-agent file lock is held only for state snapshots, reservations, and
commits. Process lifecycle work, health and ordinary listener checks, Docker
commands and inspection, project/inventory discovery, backup scans, and HTTP
response writes run after the lock is released. The rare `port relocate`
administrative transaction performs one bounded final positive-listener check
under that lock so listener-stop evidence and ownership transfer cannot race.
A pending lifecycle mutation blocks another
mutation for the same server, Docker target, or project; it does not block an
unrelated port lease or project. Project reservations form a hierarchy: they
exclude direct server/Docker mutations for that project, while only internal
synchronous child work with the exact parent-operation capability is admitted.
Exact manual-lease server start participates in that hierarchy: while its one
outer server operation is pending, the lease cannot be released and a
conflicting server or project mutation cannot interleave.
Process-instance lock identities distinguish a live long-running owner from a
dead or PID-reused owner, so elapsed time by itself cannot dissolve a valid
reservation. Direct server restart likewise owns one outer reservation across
its delegated stop/start children. Docker name and ID aliases are normalized to
the inspected immutable container ID before lifecycle reservation.

The exceptional `port relocate` administration path runs as one locked state
transaction after the old listener stops. It validates the exact old
assignment and captured lease identity, refuses live/pending/foreign or
ambiguous state, migrates the stopped server record, and retains attributed
history. It detects listeners from positive socket/PID/connect evidence rather
than a bind probe, so lack of permission to bind a free privileged port cannot
be mistaken for a live listener.

Registration never treats an arbitrary live `--pid` as listener ownership.
The exact PID must own a LISTEN socket for the declared port and have a
readable cwd within the canonical project. On Linux, inspecting a
capability-bearing listener can require the observer to hold the same narrow
capability even under the same UID. The production API clears its ambient and
inheritable sets at startup so that observer capability remains in the
coordinator process and does not become an inheritable, permitted, effective,
or ambient capability of ordinary managed executables. The coordinator leaves
the system manager's bounding ceiling unchanged: that ceiling is not active
capability state, and legitimate privileges attached to a child's own
executable remain available.

Status and inventory collect evidence from a consistent snapshot. Their health
and telemetry observations reserve monotonic per-server tickets and commit only
if both the newest ticket and lifecycle fingerprint are still current. A newer
observation or lifecycle change wins instead of being overwritten by stale
evidence. Project lifecycle operations retain a bounded journal entry and
compact result summary. This is local optimistic coordination, not distributed
consensus or a guarantee that an external process cannot change independently
between observation and commit.

Repository identity is resolved from local `.git` markers and HEAD metadata.
State-critical paths do not invoke the Git executable or credential helpers
while the coordinator lock is held.

An unprivileged CLI may be unable to re-open procfs evidence for a listener
whose capability was strictly proved by the production API. That observation
is returned as `unverified-listener` (`health.ok=null`,
`identity.observable=false`) and does not upgrade/downgrade the stored
lifecycle or release its lease. Authenticated inventory through the
capability-matched API is the strict current-ownership surface.
Server and whole-project start, stop, and restart also fail before any
operation record, signal, process launch, lease change, Docker action, or
sidecar metadata write when a target listener is unobservable. Unknown
ownership is never treated as evidence that the listener is stopped.

## What It Does Not Provide

- Remote orchestration, multi-host consensus, distributed locks, or a hosted
  control plane.
- An authorization system beyond the current operating-system user.
- Container isolation, secret management, deployment, or production service
  supervision.
- Automatic inference of a complete project topology. Undeclared or ambiguous
  runtimes report missing dependencies instead of inventing commands or ports.
- Mutation authority from Docker name similarity. Name-only container matches
  are read-only evidence; lifecycle actions require a runtime declaration,
  verified Compose working-directory ownership, or attributable coordinator
  sidecar registration for the canonical project.
- A shell. Legacy `--cmd` input is parsed into argv and shell operators are
  rejected.

The HTTP mode is a local capability endpoint. It accepts `localhost` or IPv4
loopback binds such as `127.0.0.1`, rejects IPv6 and non-loopback binds early,
and requires its private token for every `/v1/*` route; it should not be exposed
through a proxy or shared network. Token initialization is serialized and uses
exclusive creation, so concurrent first starts all reopen the same complete
credential. Token reads reject symlinks, non-regular files, unsafe modes, and
oversized content without following the caller-supplied final path.

## Minimal Workflow

```bash
PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
python3 scripts/dev_coordinator.py inventory --project "$PROJECT_ROOT"
python3 scripts/dev_coordinator.py project status --project "$PROJECT_ROOT"
```

For a declared project runtime:

```bash
python3 scripts/dev_coordinator.py project start \
  --agent "$USER" \
  --project "$PROJECT_ROOT"
```

Every mutating command must include the acting agent and canonical project
root. Port release additionally verifies that project owns the lease, and
destructive state reset records who cleared which prior state. See `SKILL.md`
for server, Docker, registration, and API examples.

If a workflow leases a port first, pass that active unbound manual lease to
`server start --lease-id ID --argv '[...]'`. The agent and canonical project
must match the lease. The coordinator preserves the exact ID and port and does
not allocate a second lease. Pre-launch failure restores the manual lease;
post-launch failure keeps it attached as cleanup/reconciliation evidence rather
than advertising the port as safely reusable.

## State And Privacy

The default state is under the current process's
`~/.codex/agent-coordinator/`. It is shared only by runtimes that resolve the
same OS-user home. Compare the `coordinator_home` field from each runtime's
`inventory` output before assuming shared leases. Same-user runtimes can set
one absolute `CODEX_AGENT_COORDINATOR_HOME`; different OS users, VMs, and
security boundaries must retain separate homes because the coordinator has no
multi-user access protocol. The directory is `0700`; state, token, lock, and
log files are private.

Inventory and logs can contain local project paths, process commands, and
service names. Treat generated state and screenshots as private runtime
artifacts; do not commit them to a public repository.

## Verification

Run the deterministic self-test without starting project services:

```bash
python3 scripts/self_test.py
```

The test uses isolated temporary coordinator homes, deliberately slow fake Git
and Docker executables, hanging loopback health endpoints, and short-lived
fixture processes. It covers state recovery, unique concurrent leases,
same-target lifecycle exclusion, unrelated-operation progress during slow
project/health/Docker work, durable operation evidence, exact manual-lease
attachment and rollback/interleaving behavior, structured launch, project
runtime classification, exact/atomic port relocation and listener false-
positive guards, Docker metadata/telemetry command paths, and API
authentication, concurrent token initialization, token-file safety, and
request boundaries.

The self-test is broad but not a production reliability proof. OS process
introspection, Docker availability, firewall behavior, and application-specific
readiness still require verification on the target machine.
