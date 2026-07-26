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
The same rule applies to every managed server and to non-Linux `lsof`
observation. A clean empty lsof selection is observable; permission or
execution diagnostics are unknown and cannot become wrong-owner proof.
Even a clean empty result cannot positively attribute a live managed PID to a
project, so lifecycle status remains unverified until a concrete cwd is found.
An unreaped zombie is terminated, not live: the coordinator checks process
state in addition to `kill(pid, 0)` so retained stopped-PID evidence cannot
block a legitimate restart.
Server and whole-project start, stop, and restart also fail before any
operation record, signal, process launch, lease change, Docker action, or
sidecar metadata write when a target listener is unobservable. Unknown
ownership is never treated as evidence that the listener is stopped.

## Brokered Compose Safety

The server-wide root broker accepts only enrolled, fingerprinted Compose
definitions. Enrollment holds the broker lifetime lock, renders the merged JSON
model from sealed inputs before changing authority, and requires its complete
service/profile scope to match the declaration. Hidden
dependencies cannot expand `up`; broker commands use `--no-deps`, disable
orphan removal, and cap Compose parallelism at four. Host-equivalent features
such as bind mounts, Docker sockets, external resources, published ports,
devices/GPUs, host/container namespaces, added capabilities, or privileged mode
require an explicit fingerprint-bound root approval. Unknown features fail
closed. Replica counts remain bounded regardless of approval, and each mutation
re-renders the model before invoking Compose.

Every mutation is followed by a fresh exhaustive observation. Unexpected
services or uncertain command outcomes remain fenced for administrator
reconciliation. A disabled definition retains its project name until a
root-only release command proves, with a strict new full-Docker ticket under
the service lifetime lock, that no container, network, volume, or unresolved
operation remains and then revokes the old definition's lifecycle ACLs. Exact commands and recovery modes are documented in
`SKILL.md`.

## Broker-Owned Ephemeral Containers

Short-lived containers must be declared by an administrator in the repository's
top-level `.codex/dev-runtime.json` `ephemeral_containers` list. Each template
pins an `image_ref` by `@sha256:`, bounds its TTL, memory, CPU, optional argv and
environment, and may publish one TCP port only through a declared loopback port
range. Enrollment stores the sealed definition privately and publishes only a
template name-to-opaque-ID mapping in the protected client profile.

The complete sealed shape is explicit; there are no hidden defaults for
resource admission or concurrency:

```json
{
  "ephemeral_containers": [
    {
      "name": "artifact-db",
      "image_ref": "postgres@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "argv": ["postgres", "-c", "fsync=off"],
      "env": {"POSTGRES_DB": "artifact_validation"},
      "secret_policy": "postgres_initdb_password_file_v1",
      "default_ttl_seconds": 900,
      "max_ttl_seconds": 3600,
      "container_tcp_port": 5432,
      "host_port_start": 55000,
      "host_port_end": 55010,
      "memory_bytes": 268435456,
      "cpu_millis": 500,
      "max_concurrent_runs": 4,
      "max_concurrent_runs_per_uid": 2,
      "repo_max_active_runs": 16,
      "repo_memory_budget_bytes": 8589934592,
      "repo_cpu_budget_millis": 16000
    }
  ]
}
```

`max_concurrent_runs` caps active runs of this template;
`max_concurrent_runs_per_uid` caps one authenticated OS account within that
template. The three `repo_*` values are shared repository-wide limits across
all its templates, so every template in one repository must declare the same
values. Admission serializes the count and the sum of each active run's sealed
memory/CPU limits before recording a new run.

Template `env` is non-secret configuration only. Its values are retained in the
repository manifest and the service database, so enrollment rejects
credential-looking variable names such as passwords, tokens, private keys, and
API keys. The optional, narrowly typed
`"secret_policy": "postgres_initdb_password_file_v1"` is the sole exception
to the lack of a general secret manager: it accepts no credential value, path,
token, or alternate policy from an agent, manifest, client, CLI, profile, or
broker request. After durable broker authorization, the root-owned broker
generates one PostgreSQL password under its private volatile runtime directory
and mounts that material directory read-only into only the admitted container.
It sets `POSTGRES_PASSWORD_FILE` to the fixed in-container filename; it never
places password bytes in Docker argv, ordinary environment variables, SQLite,
profiles, logs, or JSON replies. Public state retains only the policy name and
an opaque binding. Ordinary CLI and generic JSON calls cannot retrieve the
credential; the broker's internal runner path gets one read-only descriptor
over authenticated Unix `SCM_RIGHTS`, and ambiguous delivery retries fail
closed. Exact container-absence proof precedes material removal; a reboot that
loses volatile material leaves the run unavailable instead of regenerating it.

Agents can request lifecycle changes but cannot provide images, commands,
environment, mounts, privileges, devices, capabilities, networks, or arbitrary
Docker flags:

```bash
PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
python3 scripts/dev_coordinator.py ephemeral start --agent "$USER" --project "$PROJECT_ROOT" --template artifact-db --ttl-seconds 1800 --operation-id START_OPERATION_UUID
python3 scripts/dev_coordinator.py ephemeral status --project "$PROJECT_ROOT" --run-id RUN_ID
python3 scripts/dev_coordinator.py ephemeral renew --agent "$USER" --project "$PROJECT_ROOT" --run-id RUN_ID --ttl-seconds 1800 --operation-id RENEW_OPERATION_UUID
python3 scripts/dev_coordinator.py ephemeral finish --agent "$USER" --project "$PROJECT_ROOT" --run-id RUN_ID --reason "validation complete" --operation-id FINISH_OPERATION_UUID
```

Retain one operation UUID before every mutation. After a lost or uncertain
reply, retry with the exact same project, target, agent, TTL/reason, and
`--operation-id`. Omitting it creates a distinct operation; changing any input
while reusing it is rejected.

These commands fail closed without the root-provisioned broker profile. The
explicit project selects one exact enrollment even when different repositories
reuse a template name; status makes one read-only call in that same scope.
Mutation `--agent` is bounded diagnostic metadata stored with the durable
operation, while the kernel-authenticated UID and enrolled account remain the
authorization identity.

The broker records the run and an unguessable creation nonce before invoking
`docker create`, creates it stopped, records the returned immutable 64-hex
container ID, and only then starts it. If Docker created the container but its
reply was lost, recovery may record it afterward only when exactly one
container matches the precommitted run ID, creation nonce, repository ID,
template ID, and definition fingerprint. It then verifies the sealed safety
profile and persists the immutable ID before start or cleanup. A name match is
never recovery evidence.

An unrelated container that was started outside this protocol has no such
precommit and cannot be auto-claimed. After a full observation, an operator may
attach that exact immutable resource to the chosen repository with `resource
attach`, supplying the inventory row's resource ID, control binding, immutable
fingerprint, and ownership fingerprint. That explicit repair records ownership
without pretending the unsafe creation window never existed.

```bash
python3 scripts/dev_coordinator.py resource attach \
  --resource-kind container \
  --resource-id EXACT_RESOURCE_ID \
  --control-binding-id EXACT_BINDING_ID \
  --immutable-fingerprint sha256:EXACT_IMMUTABLE_FINGERPRINT \
  --ownership-fingerprint sha256:EXACT_OWNERSHIP_FINGERPRINT \
  --project "$PROJECT_ROOT" --agent "$USER" \
  --reason "Operator verified this existing container belongs to the repository"
```

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

In server-wide mode, API startup parses the exact protected client-profile
identity before binding. The long-lived process watches only that file's
publication metadata; after two stable observations of an atomic replacement,
it logs one `api.profile_changed` event, closes cleanly, and relies on the
production unit's `Restart=always` policy to reload the current strict reader.
This does not restart the broker or public Console and never logs profile
contents. A malformed replacement therefore fails the supervised startup gate
instead of leaving anonymous health green while every authenticated request
returns an opaque profile error.

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

For a server-wide authorization/schema upgrade, installer
`profile_database_enrollment_drift` is a hard pre-restart stop. Follow the
canonical `SKILL.md` authorization-upgrade workflow: verified private backup,
offline exact generation reconciliation when reported, protected-profile
enrollment backfill, idempotence, two-way installer plan/verify, then the full
UID/repository and Console registration checks. Never use normal enrollment as
a migration shortcut because it can rebuild observation-derived grants.

If a workflow leases a port first, pass that active unbound manual lease to
`server start --lease-id ID --argv '[...]'`. The agent and canonical project
must match the lease. The coordinator preserves the exact ID and port and does
not allocate a second lease. Pre-launch failure restores the manual lease;
post-launch failure keeps it attached as cleanup/reconciliation evidence rather
than advertising the port as safely reusable.

An enrolled runtime declaration may also define an exact server identity only
so automation can lease or pin a validation port. That definition is control
metadata, not proof that a process exists: it remains available in normalized
`resources.servers` and the Ports workflow, while Servers and project running
counts require a concrete running/stopping/stopped lifecycle observation. Use
the broker-owned `ephemeral` lifecycle for short-lived containers; a normal
managed process must be stopped explicitly because lease TTL does not terminate
it.

## State And Privacy

The default state is under the effective POSIX account's
`~/.codex/agent-coordinator/`. The coordinator resolves that home through
`getpwuid(geteuid())`; it does not trust runtime `HOME`, `CFFIXED_USER_HOME`, or
a desktop host's remapped user-domain root for the default. Two Codex or Parall
instances running as one effective UID therefore share one lock automatically.
Compare the `coordinator_home` field from each runtime's `inventory` output when
verifying that boundary.

One absolute `CODEX_AGENT_COORDINATOR_HOME` remains an authoritative same-UID
override. Deliberately different overrides are independent: they do not share a
lock and can both lease the same currently free host port. Never use one
override across effective OS users. The implementation verifies the effective
UID and exact private directory mode, while separate Linux users must use
disjoint port ranges or an authorized system broker when host-wide port
coordination is required. A source-aware UI may aggregate separate inventories
read-only, but mutations must stay bound to the originating home. Coordinator
directories are mode `0700`; state, token, lock, and log files are private.

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
fixture processes. It covers remapped same-user runtime convergence and
shared-lock serialization, the duplicate-port risk across deliberately
separate overrides, distinct effective-UID home resolution, foreign-UID home
rejection, state recovery, unique concurrent
leases, same-target lifecycle exclusion, unrelated-operation progress during
slow project/health/Docker work, durable operation evidence, exact manual-lease
attachment and rollback/interleaving behavior, structured launch, project
runtime classification, exact/atomic port relocation and listener false-
positive guards, Docker metadata/telemetry command paths, and API
authentication, concurrent token initialization, token-file safety, and
request boundaries.

The self-test is broad but not a production reliability proof. OS process
introspection, Docker availability, firewall behavior, and application-specific
readiness still require verification on the target machine.
