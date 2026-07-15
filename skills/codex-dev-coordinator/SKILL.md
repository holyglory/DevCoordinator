---
name: codex-dev-coordinator
description: Use when coding agents (Codex, Claude Code) in one or multiple apps or sessions need coordinated port leases, shared dev-server start/stop/restart/status/health control, or Docker/Docker Compose management through a single local coordinator CLI or HTTP endpoint.
---

# Codex Dev Coordinator

Use this skill before starting local dev servers, allocating ports, inspecting
running services, or managing Docker when multiple agent sessions or app
instances (Codex, Claude Code, or both) may be working on the same machine.

## Core Rule

Do not start dev/test servers, Docker Compose services, Docker containers, or
local database stacks directly with default ports. First run `inventory` to see
what is already running. When the user asks to run, start, restart, check, or
open a project's dev server, prefer the project-level runtime command:

```bash
PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
python3 scripts/dev_coordinator.py project start --agent "$USER" --project "$PROJECT_ROOT"
```

Use individual `server` and `docker` commands only for narrow operations on a
specific service after the project runtime status has made the dependency
picture clear.

Never do the pattern "try the default port, then try another one if busy." The
coordinator is the source of truth.

Every mutating coordinator command must identify the agent and canonical repo
path. Use `PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"`
before starting, stopping, restarting, registering, or changing dev servers,
Docker containers, Docker Compose services, local databases, port leases, or
destructive coordinator state. Port release is restricted to the lease-owning
project, and destructive state reset retains attributed prior-state evidence.

## Shared State

Server-wide authority is the product default. Every Codex, Claude Code, and
other enrolled agent account reads and mutates one service-owned WAL database:

```text
/var/lib/devcoordinator/coordinator.sqlite3
/run/devcoordinator/broker.sock
/etc/devcoordinator/client-profiles.json
```

Clients never open the database. The broker authenticates the kernel peer UID,
requires a current root-owned profile, and enforces exact repository/server
ACLs. `inventory` returns this host graph, so a server started by one UID is
immediately visible to the DevOps Console and every other enrolled UID. If the
profile, socket, or service is missing, system mode fails closed; it never
silently creates a second authority below an application-specific home.

The supervised authority broker runs as root because its enrollment database
is root-owned and it must prove or stop exact resources across UIDs. Its typed
protocol has no user-account host-process launch operation, and service
authority mode rejects all direct CLI server, project, Docker, port,
repository, resource, and API commands; host-process workloads remain children
of their enrolled non-root clients. Typed Docker lifecycle stays broker-owned.

Each client has a private execution/reconciliation journal at
`/var/lib/devcoordinator-clients/<uid>/`. That database may retain launch, log,
rollback, and broker-link evidence, but it is not inventory or reservation
authority. The installer creates it as the client UID with mode `0700`; normal
agent operations then require no sudo or repeated permission prompt.

`DEVCOORDINATOR_AUTHORITY=account` or an explicit
`CODEX_AGENT_COORDINATOR_HOME` without an authority setting is an isolated
compatibility/test scope. It must not be used as host-global evidence. The
legacy JSON implementation remains available only as
`legacy-json-test-only` for deterministic fixtures.

Never make the service SQLite file group-writable and never point multiple
users at it through a symlink. Symlinks are used only to install this canonical
repository skill into Codex/Claude roots so repository updates are picked up;
the installer gives the client group read/execute-only source ACLs, including
defaults for future files. Unix-socket peer authentication and ACLs provide
runtime access; neither mechanism grants database or repository write access.

SQLite foreign keys and uniqueness constraints own the normalized invariants.
Short `BEGIN IMMEDIATE` reservation/commit phases serialize conflicts while
WAL permits concurrent reads. Slow process launch/termination, health checks,
Docker, Git, backup scans, and filesystem observation run outside write
transactions and commit only against their captured fingerprints. Product
mutations use typed normalized services; the legacy JSON lock and callback
projection are isolated to explicit compatibility-test fixtures and fail closed
if selected by the default SQLite backend.

Same-target lifecycle mutations are rejected while an operation is active;
unrelated repositories continue independently. A pending project lifecycle
also excludes direct server and Docker mutations for that repository. Only
synchronous child work carrying the exact internal parent-operation capability
may run inside it; callers cannot supply that capability through CLI or HTTP.
Abandoned reservations release safe unlaunched leases. A live process whose
operation owner disappeared remains explicit orphan/reconciliation evidence,
and a reused PID cannot impersonate the reserving process.

`inventory` and authenticated inventory endpoints are pure snapshot reads.
They do not inspect Docker/processes, scan backups, prune data, advance a
revision, or write the database. `observe` performs the bounded host sampling
transaction. Concurrent same-scope observations join one database-backed
single-flight ticket; full-Docker, no-Docker, and different backup-directory
scopes are distinct so a cheaper observation cannot masquerade as complete.

The first normalized observation discovers eligible same-UID legacy homes as
migration inputs, privately backs them up, and imports them transactionally.
One canonical Git worktree root becomes one repository. Exact duplicates merge;
cross-repository claims and other unsafe differences remain explicit conflicts
or Unassigned Resources. Imported homes are no longer independently polled.
Later legacy writes are detected and surfaced rather than silently winning.

### Server-wide installation

Plan and apply the system identity, tmpfiles layout, systemd unit, client group
membership, private journals, and direct canonical Codex/Claude skill links.
Apply is transactional for configuration and skill links and does not start the
service before ACL enrollment:

```bash
python3 scripts/install_server_wide_coordinator.py plan \
  --client-user alice --client-user console

sudo python3 scripts/install_server_wide_coordinator.py apply \
  --client-user alice --client-user console \
  --transaction-dir /var/lib/devcoordinator-install/$(date +%Y%m%d-%H%M%S)
```

Enroll each UID/repository. Repeat `--server` to give that account control of
only those declared servers; omitting it grants no server control unless the
administrator supplies the explicit `--all-servers` override. Re-enrollment
atomically replaces the server allowlist and revokes omitted grants:

```bash
sudo python3 scripts/dev_coordinator.py broker enroll \
  --database /var/lib/devcoordinator/coordinator.sqlite3 \
  --socket /run/devcoordinator/broker.sock \
  --access-group devcoordinator-clients \
  --client-uid NUMERIC_CLIENT_UID \
  --account-id EXACT_CLIENT_ACCOUNT_ID \
  --project /absolute/path/to/repository \
  --agent "$USER" \
  --server web \
  --server worker \
  --port-range 3000-3999

sudo systemctl enable --now devcoordinator-broker.service
```

Enrollment performs a fresh full-Docker observation, grants only exact opaque
normalized IDs, writes the protected system client profile, and starts no
resource. To migrate an already-running listener, enroll its definition and
run `server register` as the owning UID; the service verifies the exact UID,
PID, repository cwd, port, and listener before publication. Preserve the old
account store until the shared inventory and Console show the migrated server.
Use the install transaction with the installer's `rollback` command if the
configuration or canonical links must be restored.

### Normalized store backup, restore, and corrupt recovery

Back up either an account or service authority to a private absolute directory
outside Git:

```bash
python3 scripts/dev_coordinator.py broker store-backup \
  --database /absolute/path/to/coordinator.sqlite3 \
  --store-role account \
  --output-root /private/backup/root

python3 scripts/dev_coordinator.py broker store-export \
  --database /absolute/path/to/coordinator.sqlite3 \
  --store-role account \
  --output-root /private/backup/root
```

For a readable current store, `store-restore` (verified binary, same database
generation) and `store-import` (verified logical export) first take a verified
safety backup and require `--manifest`, `--safety-root`, and `--confirm`. They
fail closed on corruption. A logical export is not corruption recovery.

If the store is unreadable, stop every service/client using it before invoking
the separate offline path:

```bash
python3 scripts/dev_coordinator.py broker store-recover \
  --database /absolute/path/to/coordinator.sqlite3 \
  --store-role account \
  --manifest /private/backup/root/VERIFIED_BINARY_MANIFEST.json \
  --forensic-root /private/forensic/root \
  --confirm-corrupt-recovery
```

Recovery accepts only a strongly verified binary backup for the same store
role. It cannot infer a generation from corrupt bytes, so it first captures
the exact database/WAL/shared-memory files and checksums, retains that forensic
evidence, verifies the replacement, and rolls back exact bytes on publication
failure. The command does not stop or supervise the service; the operator owns
that quiescent boundary.

## Quick Start

Resolve the script path relative to this skill directory:

```bash
PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
python3 scripts/dev_coordinator.py inventory --project "$PROJECT_ROOT"
python3 scripts/dev_coordinator.py observe \
  --agent "$USER" \
  --project "$PROJECT_ROOT" \
  --max-age-seconds 30
python3 scripts/dev_coordinator.py inventory --project "$PROJECT_ROOT"
```

```bash
python3 scripts/dev_coordinator.py port lease --agent "$USER" --project "$PROJECT_ROOT" --range 3000-3999
```

Start or verify a whole project runtime first. This uses the canonical project
path as the stable runtime identity, starts declared dependencies before web
processes, preserves fixed ports, and returns URLs, ports, service status,
dependency classifications, recent logs, and previous exit reasons:

```bash
python3 scripts/dev_coordinator.py project status --project "$PROJECT_ROOT"
python3 scripts/dev_coordinator.py project start --agent "$USER" --project "$PROJECT_ROOT"
python3 scripts/dev_coordinator.py project restart --agent "$USER" --project "$PROJECT_ROOT"
python3 scripts/dev_coordinator.py project stop --agent "$USER" --project "$PROJECT_ROOT"
```

## Remove, Reinstall, Attach, Or Retire

Do not hide a repository with a Board preference or delete its state rows.
Repository removal is a two-step, fingerprint-bound decommission:

```bash
python3 scripts/dev_coordinator.py repository plan-remove \
  --agent "$USER" \
  --project "$PROJECT_ROOT" \
  --reason "No longer used on this machine"

python3 scripts/dev_coordinator.py repository remove \
  --agent "$USER" \
  --project "$PROJECT_ROOT" \
  --plan-id EXACT_PLAN_ID \
  --plan-fingerprint EXACT_PLAN_FINGERPRINT
```

Planning forces a current full-Docker observation. Every container target must
have an observable immutable identity, one authoritative controller, an
available engine, and exactly one current Docker restart policy. Apply writes a
durable start fence before host work, captures and disables the exact automatic
start state, stops and verifies every target, deactivates leases/assignments,
and hides only after complete success. Any drift or partial failure retains the
fence and per-target evidence for idempotent continuation. Files, containers,
volumes, databases, backups, and history are never deleted by this journey.

Inspect retained removal records or explicitly reinstall:

```bash
python3 scripts/dev_coordinator.py repository list-removed
python3 scripts/dev_coordinator.py repository reinstall \
  --agent "$USER" \
  --project "$PROJECT_ROOT" \
  --reason "Needed again" \
  --explicit
```

Reinstall only clears the repository fence. It never starts retained resources.
The first later explicit Start restores only the exact pre-disable policy state
captured by removal; missing or changed capture fails closed.

Unassigned Resources are physical evidence without one proved repository
membership. Never infer ownership from a name. Use inventory's
`host_resource_id`, `immutable_fingerprint`, `control_binding_id`, and
`ownership_fingerprint` with `resource attach` after the operator chooses a
validated repository. If the resource is intentionally standalone, use
`resource plan-retire`, review the exact plan, and pass its identifier and
fingerprint to `resource retire`. Standalone retirement applies the same fresh
observation, policy-disable, exact-stop, verification, retained-data, and fence
rules as repository removal.

For a single managed process inside a project, start a server and let the
coordinator lease the port, keep the PID, store logs, and health-check it:

```bash
python3 scripts/dev_coordinator.py server start \
  --agent "$USER" \
  --project "$PROJECT_ROOT" \
  --name web \
  --cwd "$PROJECT_ROOT" \
  --cmd 'npm run dev -- --host 127.0.0.1 --port {port}' \
  --range 3000-3999 \
  --health-url 'http://127.0.0.1:{port}/'
```

### Durable port assignments (ports are fixed per repo server)

The first successful `server start` or `server register` for a
`(canonical project, server name)` identity durably pins that port to the
server. The normalized `port_assignments` row survives server stops, lease
expiry, and stopped-observation pruning, and is removed only by an explicit
unassign, repository decommission, or destructive state reset. Consequences
agents can rely on:

- Restarting a server — even weeks later, after its stopped record was pruned —
  lands on the same port, so tests and tooling can hard-code where a repo's
  servers live. Look the port up while the server is stopped:

```bash
python3 scripts/dev_coordinator.py port assignments --project "$PROJECT_ROOT"
```

- No other project can lease, start on, or register over a pinned port. Such
  attempts fail with an error naming the owner
  (`port N is durably assigned to server 'web' of /repo`); do not work around
  it — pick another port or ask the owner to unassign.
- Starting the owner without `--range` treats the pinned port as the only
  acceptable outcome: if a foreign process squats it, the start fails loudly
  instead of silently drifting to a new port.
- Passing an explicit `--preferred`/`--range` that lands the owner on a
  different port re-pins the assignment to the new port.
- Pin a port ahead of the first start, or release one:

```bash
python3 scripts/dev_coordinator.py port assign --agent "$USER" --project "$PROJECT_ROOT" --name web --port 3210
python3 scripts/dev_coordinator.py port unassign --agent "$USER" --project "$PROJECT_ROOT" --name web
```

`port unassign --port N --force` removes another project's pin (for example an
orphan left by a moved or renamed repo); without `--force` foreign pins are
protected. Legacy assignments are imported automatically. Exact duplicates
collapse; two repositories or two materially different definitions contesting
one port create an explicit blocking migration conflict. The importer never
picks a winner from timestamps or source order.

For an operator-approved checkout ownership migration, do not unassign and
race to re-create the pin. Capture the exact active lease ID from inventory,
stop and verify the old listener, privately back up the SQLite database and
its verified control-state manifest, then transfer the assignment and reusable
stopped server identity in one transaction:

```bash
python3 scripts/dev_coordinator.py port relocate \
  --agent "$USER" \
  --old-project /absolute/old/checkout \
  --new-project /absolute/new/checkout \
  --name devops-console \
  --port 443 \
  --lease-id EXACT_PRE_CUTOVER_LEASE_ID
```

`port relocate` is deliberately strict. It rejects a live listener, live
recorded PID, pending lease/operation, wrong or ambiguous assignment/server,
foreign active lease, destination collision, or a missing lease without exact
retained stale-release evidence. It uses positive listener evidence and never
tries to bind the port, because an unprivileged bind to a free port such as 443
can fail with `EACCES`. A successful relocation clears obsolete process/launch
fields, marks the migrated server stopped, records attributed history, and
allows the new listener's `server register` to reuse the same server ID.

`--cmd` is compatibility input. It is parsed into argv and is never evaluated
by a shell; shell control operators such as `;`, `&&`, pipes, redirects, and
newlines are rejected. Prefer structured argv when quoting would be ambiguous:

```bash
python3 scripts/dev_coordinator.py server start \
  --agent "$USER" \
  --project "$PROJECT_ROOT" \
  --name web \
  --cwd "$PROJECT_ROOT" \
  --argv '["npm","run","dev","--","--host","127.0.0.1","--port","{port}"]' \
  --range 3000-3999
```

When a preceding workflow already owns an active lease whose purpose is
`manual`, attach that exact lease instead of releasing it and racing to lease
the port again. Exact-lease start accepts structured argv only:

```bash
LEASE_ID="$({
  python3 scripts/dev_coordinator.py port lease \
    --agent "$USER" \
    --project "$PROJECT_ROOT" \
    --range 3000-3999 \
    --purpose manual
} | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"

python3 scripts/dev_coordinator.py server start \
  --agent "$USER" \
  --project "$PROJECT_ROOT" \
  --name web \
  --cwd "$PROJECT_ROOT" \
  --argv '["npm","run","dev","--","--host","127.0.0.1","--port","{port}"]' \
  --lease-id "$LEASE_ID" \
  --health-url 'http://127.0.0.1:{port}/'
```

The lease must still be active and unexpired, have purpose `manual`, be
unbound, and belong to the same agent and canonical project. The start reserves
the server lifecycle and exact lease in one outer operation, uses its exact ID
and port, and never allocates a replacement lease. Port release and direct
project/server lifecycle mutations that conflict with that attachment are
rejected until it completes. A failure before process launch restores the
manual lease as unbound. Once process launch has occurred, a failed health
check or uncertain outcome keeps the lease attached as explicit failure or
reconciliation evidence until an attributed stop or release clears it; it is
never silently returned to the manual pool.

Project runtime declarations may likewise provide `"argv": [...]` instead of
`"cmd"`. The persisted `LaunchSpec` contains argv, cwd, declared environment,
agent, project, and source provenance, so restart retains the explicitly
declared environment.

If a server is already running on the declared fixed port but is not registered,
adopt it instead of starting a duplicate. Adoption is allowed only when the
listener PID can be attributed to the canonical project root. If the occupied
port belongs to another repo, fix the stale coordinator metadata or register
the real owner instead of attaching that listener to the current project:

```bash
python3 scripts/dev_coordinator.py server register \
  --agent "$USER" \
  --project "$PROJECT_ROOT" \
  --name web \
  --port 3000 \
  --url 'http://127.0.0.1:3000'
```

An explicit `--pid` is proof input, not an ownership override. Registration
requires that PID to be alive, have a readable cwd inside the canonical
project, and own an exact TCP LISTEN socket inode for the declared port. A
same-project idle PID, foreign listener, dead PID, wrong port, or unreadable
process identity is rejected.

On Linux, same UID alone does not guarantee `/proc/<pid>/fd` or cwd visibility
when the target carries capabilities. A long-lived system service that adopts
such listeners must have the narrow matching observer capability. Before it
can exec managed children it must clear ambient and inheritable capabilities;
the children must receive empty inheritable, permitted, effective, and ambient
sets. The DevCoordinator production unit and capability integration test model
this boundary for the Console's `CAP_NET_BIND_SERVICE` listener. The
coordinator leaves the system manager's bounding ceiling unchanged; it is not
an active capability, and legitimate privileges attached to a child's own
executable remain available.

Check, restart, and stop:

```bash
python3 scripts/dev_coordinator.py server status --project "$PROJECT_ROOT" --name web
python3 scripts/dev_coordinator.py server restart --agent "$USER" --project "$PROJECT_ROOT" --name web
python3 scripts/dev_coordinator.py server stop --agent "$USER" --project "$PROJECT_ROOT" --name web
python3 scripts/dev_coordinator.py server logs --project "$PROJECT_ROOT" --name web --tail 200
```

Direct server restart holds one outer reservation across its delegated stop and
start children, so another stop/start/restart cannot interleave in the gap.

The coordinator keeps managed server log paths and stopped server records. When
a managed server stops or its PID exits, inventory exposes `stopped_at`,
`stopped_reason`, and `log_path`, and `server logs` returns the requested log
tail plus the stop metadata.

Inventory also exposes real per-server process CPU/RSS and project-level
resource rollups. For managed dev servers, the coordinator samples the launcher
PID plus its child process tree so Node/Next/Vite child processes are counted
under the correct canonical repo. Use `inventory --project "$PROJECT_ROOT"` or
project `status` evidence before assuming a server is healthy when it is slow,
GC-bound, or memory-heavy. The `project_usage` rollup lists CPU percent, memory
bytes, process counts, and hot PIDs by repo; it must be treated as diagnostic
evidence, not synthetic UI decoration. Each row also carries authoritative
membership (`usage_key`, `server_ids`, `container_names`) so UIs group
inventory rows without re-implementing repo-identity heuristics.

Display grouping and whole-project actions share one membership model: the
same attribution that places a container in a `project_usage` row decides
whether `project start|restart|stop` acts on it. Explicit attribution (Docker
Compose labels, then coordinator sidecar metadata) always wins; an
unattributed container is claimed by a known repo only when exactly one known
project path matches its name key; a container whose name key matches several
known repos stays in its own name-keyed group (`usage_key` `name:<key>`,
`project` null) and no whole-project action touches it. A UI grouped by
`project_usage` therefore shows exactly the blast radius of whole-project
actions.

Inventory must show one current row per logical server identity
(`canonical project path + server name`). Repeated starts, stops, restarts, or
adoptions of the same fixed-port service must not appear as multiple runnable
rows with the same URL or port. If stale state records exist from older runs,
inventory collapses them into the preferred current record and may expose
`duplicate_count` / `duplicate_server_ids` as diagnostic metadata.
Stopped or stale records whose ports are now reused by another project must not
be exposed as current URLs. Inventory marks those rows with
`url_is_current=false`, `port_reused=true`, and `port_reused_by` evidence so
agents and UI surfaces do not open the wrong app.

## HTTP Endpoint Mode

Run a single coordinator endpoint when agents prefer tool-style JSON calls:

```bash
python3 scripts/dev_coordinator.py api serve --host 127.0.0.1 --port 29876
```

The API is a local capability endpoint, not a remote administration service.
It supports `localhost` or IPv4 loopback binds such as `127.0.0.1`; wildcard,
non-loopback, and IPv6 binds are rejected before the server is created. At first start it creates
`~/.codex/agent-coordinator/api-token` with mode `0600` (override with
`CODEX_AGENT_COORDINATOR_TOKEN_FILE` or `--token-file`). Only `GET /healthz` is
anonymous. Every `/v1/*` request must send:

```text
Authorization: Bearer <contents of api-token>
```

The server validates loopback `Host`, same-origin browser requests, JSON
content type, and a 64 KiB body limit, and bounds concurrent request workers.
Do not print, commit, or put the token in a URL. A group/world-readable or
symlinked token file is rejected. Concurrent first starts converge on one
exclusively created token; every process reopens the winning credential rather
than replacing it with a different token.

Useful endpoints:

- `GET /v1/inventory`
- `GET /v1/inventory/no-docker` — the same observed coordinator graph with
  Docker discovery intentionally omitted (`available: null`, empty container
  and PostgreSQL rows); use only for authenticated service readiness where
  Docker availability must not control the unit start transaction.
- `GET /v1/state`
- `GET /v1/ports`
- `GET /v1/ports/assignments`
- `GET /v1/servers`
- `POST /v1/ports/lease`
- `POST /v1/ports/release`
- `POST /v1/ports/assign`
- `POST /v1/ports/unassign`
- `POST /v1/servers/start`
- `POST /v1/servers/register`
- `POST /v1/servers/stop`
- `POST /v1/servers/restart`
- `POST /v1/servers/status`
- `POST /v1/servers/logs`
- `POST /v1/projects/status`
- `POST /v1/projects/start`
- `POST /v1/projects/restart`
- `POST /v1/projects/stop`
- `POST /v1/docker/ps`
- `POST /v1/docker/stats`
- `POST /v1/docker/compose-up`
- `POST /v1/docker/compose-down`
- `POST /v1/docker/logs`
- `POST /v1/docker/register`
- `POST /v1/docker/start`
- `POST /v1/docker/stop`
- `POST /v1/docker/restart`

POST bodies are JSON and use the same option names as the CLI without leading
dashes. Prefer the `argv` array over a legacy `cmd` string, for example:

```json
{"agent":"codex-a","project":"/repo","name":"web","cwd":"/repo","argv":["npm","run","dev","--","--port","{port}"],"range":"3000-3999"}
```

To consume an existing manual lease through the API, include its exact
`"lease_id"` in the same `/v1/servers/start` payload. The same ownership,
expiry, source, binding, structured-argv, and rollback rules apply.

## Docker

Use Docker commands through the coordinator so agents have one visible control
surface:

```bash
python3 scripts/dev_coordinator.py docker ps
python3 scripts/dev_coordinator.py docker stats
python3 scripts/dev_coordinator.py docker ps --all
python3 scripts/dev_coordinator.py docker compose-up --agent "$USER" --project "$PROJECT_ROOT" --cwd "$PROJECT_ROOT" --file docker-compose.yml --detach
python3 scripts/dev_coordinator.py docker compose-down --agent "$USER" --project "$PROJECT_ROOT" --cwd "$PROJECT_ROOT" --file docker-compose.yml
python3 scripts/dev_coordinator.py docker logs --container my-container --tail 80
python3 scripts/dev_coordinator.py docker register --agent "$USER" --project "$PROJECT_ROOT" --container my-container --role web
python3 scripts/dev_coordinator.py docker start --agent "$USER" --project "$PROJECT_ROOT" --container my-container
python3 scripts/dev_coordinator.py docker restart --agent "$USER" --project "$PROJECT_ROOT" --container my-container
```

Use `--dry-run` when Docker may not be installed or when validating the command
shape without changing containers.

Docker execution does not assume an interactive-shell `PATH`. The coordinator
resolves `CODEX_DOCKER_CLI` when it names an absolute executable, then the
current `PATH`, then standard Homebrew, Docker Desktop, OrbStack, and per-user
installation locations. It preserves the discovered `docker` entry-point path
instead of canonicalizing a multicall symlink to a differently named target.
Real Docker calls are bounded by observation and lifecycle timeouts; dry-run
never requires a Docker installation.

Project start, restart, and stop preflight Docker before mutating any managed
process whenever the declaration includes Compose or an attributed container.
The bounded preflight verifies the Docker executable, daemon, and—when
declared—the Compose plugin. An unavailable capability returns a complete project report with
`ok=false`, `classification=missing_dependency`, `actions=[]`,
`partial=false`, and structured `action_errors[].capability` evidence instead
of partially changing the runtime or exposing a raw `FileNotFoundError`.
Failures after one or more successful actions return the same report shape with
`partial=true`, the completed `actions`, and structured `action_errors`.

Existing Docker labels cannot be rewritten for running containers. When Docker
does not provide Compose project labels, register coordinator-side metadata with
`docker register` or let `docker start/stop/restart` attach it automatically
from `--agent` and `--project`. Inventory merges real Docker Compose labels
first, then coordinator sidecar metadata for unlabeled containers.

When a declared dependency is also owned by declared Compose, keep the
dependency for health/readiness evidence and map its lifecycle explicitly with
`"service": "<compose-service>"` (preferred), or give it a `name` that exactly
matches an entry in `docker.services`. Compose then exclusively owns its
start/stop/restart lifecycle, while unrelated declared containers retain direct
container lifecycle management. Project restart safely uses `compose restart`
for observed running services and `compose up -d` for missing or stopped
services; recovery actions run before dependent restarts, and the coordinator
does not force-recreate containers or risk writable-layer data.

A container name or image that resembles a repository name is discovery
evidence only. Project start, restart, and stop may mutate a container only when
it is explicitly declared in the runtime, has a Compose working-directory label
for the canonical project, or has prior coordinator-side registration with
matching project and agent metadata. Name-only matches remain visible as
`read_only_evidence=true` and `mutation_authorized=false`; they must never be
auto-registered or passed to a Docker lifecycle command.

Docker lifecycle reservations normalize container names and short IDs through
`docker inspect` to the immutable full container ID before reserving state. Two
aliases for the same container therefore conflict as one mutation target. If
that immutable identity cannot be verified, lifecycle mutation and sidecar
registration fail closed.

When a project runtime declaration names an existing unlabeled container,
`project start` adopts that container into coordinator-side metadata before it
reports final status, and `project stop`/`project restart` record the same
sidecar attribution for the containers they act on. This keeps databases such
as `aerodb-pg` grouped under the repo that declared them instead of under a
name-derived pseudo-project.

The shared inventory includes stopped containers (`docker ps --all`) so agents
can see containers that are available to start instead of accidentally creating
duplicates.

After an explicit full-Docker `observe`, inventory includes the committed real
telemetry for running containers. The observer samples `docker stats
--no-stream` once per coalesced host scope, stores a bounded rolling
`stats_history` per immutable container, and exposes current CPU, memory,
network I/O, and block I/O values plus per-second network/block rates. Pure
inventory reads never resample Docker. Stopped containers remain visible but
do not receive live stats.

Machine consumers can reduce inventory transport cost without changing the
persisted telemetry window. `--compact-json` emits the same inventory as one
compact JSON line, while `--stats-history-limit` selects how many of the newest
stored samples are returned for each primary Docker container:

```bash
python3 scripts/dev_coordinator.py inventory --compact-json --stats-history-limit 30
```

Both controls are opt-in. Ordinary CLI and HTTP inventory responses retain the
full bounded 120-sample history, and ordinary CLI JSON stays pretty-printed.
Use a limit of `0` when only the last committed `stats` sample is needed; this
shapes the response only and never deletes persisted history. Values outside
`0..120` are rejected.

## Project Runtime Declarations

Project runtime declarations live at `.codex/dev-runtime.json` by default. Use
them when a repo needs a database, worker, Docker Compose service, fixed port,
or meaningful readiness check. A project-level `start` must not report success
only because the web process answers `/`; required dependencies and declared
readiness checks must also pass.
Default HTTP health accepts 2xx and 3xx responses. A 4xx response, including a
foreign app's 404 on the requested health path, is unhealthy unless the repo
declares a more specific readiness check that proves the app is actually ready.

Docker Compose mutation requires an explicit runtime declaration. If a repo has
`docker-compose.yml` but no `.codex/dev-runtime.json`, the coordinator may show
the file as discovered evidence, but `project start` must not run `docker
compose up` from that discovery. Add a declaration or register/adopt the
already-running containers instead of creating a duplicate stack.

Minimal example:

```json
{
  "name": "example-app",
  "docker": {
    "compose_files": ["docker-compose.yml"],
    "services": ["postgres", "worker"]
  },
  "servers": [
    {
      "name": "web",
      "role": "web",
      "port": 3000,
      "cmd": "npm run dev -- --host 127.0.0.1 --port {port}",
      "health_url": "http://127.0.0.1:{port}/"
    }
  ],
  "dependencies": [
    {
      "type": "docker",
      "name": "postgres",
      "container": "example-postgres",
      "ports": [{"host": "127.0.0.1", "port": 5432}]
    }
  ],
  "health_checks": [
    {
      "name": "app-ready",
      "url": "http://127.0.0.1:3000/api/health",
      "expect_status": 200,
      "expect_text": "ok"
    }
  ]
}
```

If there is no declaration, the coordinator may discover existing managed
servers, Docker Compose files, Compose working-directory labels, and matching
containers. Container discovery uses the same attribution as inventory's
`project_usage` grouping: a container explicitly attributed to another project
never joins this project's runtime, and a name match claims a container only
when this project is the single known claimant for its name key. If the
coordinator still cannot identify a complete runtime, it returns `ok=false`
with `classification=missing_dependency` instead of guessing ports or
reporting success.

## Agent Workflow

1. Set `PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"`, then
   run `inventory --project "$PROJECT_ROOT"` before starting, stopping, or replacing any
   local service. If the snapshot is absent or stale for the task, run one
   explicit `observe --agent "$USER" --project "$PROJECT_ROOT"` and read
   inventory again. Do not treat inventory itself as a refresh mutation.
2. For "run/start/restart/check the dev server", call `project status` or
   `project start` with the canonical repo path. Do not manually run package
   manager dev commands, Docker, database, worker, and web commands unless the
   project runtime report points to a specific service-level repair.
3. Treat `ok=false` as not ready even when a web URL exists. Report the
   coordinator's classification: `wrong_port`, `stopped_container`,
   `crashed_process`, `unhealthy_process`, `timeout`, `missing_dependency`, or
   `stale_coordinator_metadata`.
4. Keep project ports fixed. Add or update `.codex/dev-runtime.json` when a
   repo needs a fixed web, database, or worker port. Use `--allow-port-change`
   only when the user explicitly asks to change ports.
   `project start` may reclaim same-project fixed-port leases that were left by
   stopped, missing, or dead managed servers; do not manually switch to a new
   port to work around stale coordinator metadata.
   Durable port assignments back this policy automatically: every managed or
   registered server keeps its port across stops, restarts, and record pruning,
   and `port assignments --project "$PROJECT_ROOT"` answers "where does this
   repo's server live" even while it is stopped. If a start fails because the
   pinned port is unavailable, surface the error instead of moving the server.
5. When a dependency is stopped or unhealthy, preserve the evidence in the
   runtime report (`before`, recent logs, previous exit reasons), then recover
   through `project start` or `project restart`, and report both evidence and
   final status.
6. Use individual `server`, `docker`, and `port` commands for explicit
   service-level tasks only after the project runtime is understood.
7. If an already-running server or unlabeled Docker container belongs to the
   repo, register it. `project start` adopts healthy fixed-port servers
   automatically; use `server register` or `docker register` for explicit
   repairs.
8. Before trusting or stopping an adopted process, verify listener ownership
   through the process cwd/git root. If a registered server PID or port belongs
   to another project, treat it as `stale_coordinator_metadata`; do not report
   it as working and do not kill the foreign PID.

## Health, Status, And State Robustness

- `server status` re-checks health a few times with a short backoff before
  concluding a server is down, so a transient blip or a still-warming server is
  not misclassified after a single miss.
- A live, correctly-owned server that fails its health check within its startup
  grace window is reported as `starting`, not `unhealthy`, so a slow boot does
  not trigger needless restart churn. After the grace window it becomes
  `unhealthy`. `server_health` also returns a `classification` of `healthy`,
  `starting`, `unhealthy`, `wrong-listener`, `unverified-listener`, or
  `stopped`.
- A CLI process that lacks permission to inspect a previously proven
  capability-bearing listener reports `unverified-listener` with
  `health.ok=null` and `identity.observable=false`. It preserves the recorded
  running/unhealthy lifecycle and active lease; inability to observe is not
  evidence that another process owns the port. Use the capability-matched,
  authenticated production API inventory for a fresh strict ownership proof.
- Apply the same tri-state rule to managed servers without explicit
  registration evidence and to non-Linux lsof probes. lsof exit 1 with no
  output is a clean no-match; permission or execution diagnostics mean
  `observable=false`, never `wrong-listener`.
- Treat that clean no-match as negative probe evidence only. If a managed PID
  is still live but no concrete cwd was returned, project ownership remains
  unverified and every mutating lifecycle path must fail closed.
- Treat an unreaped zombie as terminated even though `kill(pid, 0)` succeeds;
  confirm non-zombie process state before applying the live-PID ownership gate.
- Server and project start, stop, and restart fail closed on that unknown
  identity before recording an operation, signaling or launching a process,
  changing a lease, acting on Docker, or writing sidecar metadata. Run the
  mutation through a capability-matched coordinator surface; do not retry it
  from an incapable CLI or infer that the port is safe to replace.
- Stopped observations and high-frequency telemetry are retained under bounded
  policies. Pruning never deletes the normalized server definition, durable
  assignment, removal record, operation evidence, or current ownership
  boundary merely because a status sample aged out.
- SQLite/database validation failures fail closed; the coordinator never
  replaces damaged normalized control state with an invented empty database.
  Preserve the database, WAL, and shared-memory files together for diagnosis
  and restore only from verified coordinator backup/export evidence.
- Managed server/project and Docker lifecycle calls reserve and commit in
  short transactions. Process spawn, health polling, termination, Docker
  execution/inspection, project discovery, and host sampling happen outside
  the SQLite writer transaction, so an unrelated lease is not blocked by slow
  host work. Captured generations and immutable fingerprints prevent the slow
  result from overwriting a newer lifecycle decision.
- `inventory` is read-only. `observe` owns server/process/Docker/database
  observation commits and their monotonic observation revision. An older or
  narrower in-flight sample cannot overwrite or satisfy a newer/different
  scope; Docker telemetry merges by sample identity and remains bounded.
- Repository roots, branches, and short commits are read from local `.git`
  metadata; state-critical paths do not invoke the Git executable or a Git
  credential/network helper while holding the coordinator lock.
- Failed process launches release their reserved leases and retain failed
  operation evidence for coordinator-allocated leases. Exact manual-lease
  starts instead restore the unbound manual lease only when no process was
  launched; after launch they quarantine the lease with explicit failure
  evidence until attributed cleanup. Generation checks keep a superseded
  operation from overwriting a newer server record.

## Safety Notes

- The coordinator does not grant permissions. It runs structured argv as the
  current OS user and invokes the local Docker CLI without a command shell.
- Use project-specific `--name` values. Avoid generic names like `server` when a
  repo has multiple services.
- Set `--ttl` for short-lived port leases that are not attached to a managed
  server. Expired leases are ignored during new allocation.
- Leases and assignments are different things: a lease says "this port is in
  use right now" and expires or is released on stop; a durable assignment says
  "this port belongs to this repo's server" and never expires. Manual
  `port lease` calls do not create assignments.
- Use `--json` on CLI commands when another script or agent will parse output.
