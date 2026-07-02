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
Docker containers, Docker Compose services, or local databases.

## Shared State

The bundled script stores leases and server metadata under:

```bash
~/.codex/agent-coordinator/
```

This default is intentionally shared by every runtime on the machine: Codex and
Claude Code sessions must use the same state directory so they see each other's
leases, servers, and containers. Do not point one runtime at a different state
home unless every agent on the machine moves with it.

For multiple OS users, Parallels VMs, or separate agent accounts that need one
shared memory, set the same writable path in every agent shell:

```bash
export CODEX_AGENT_COORDINATOR_HOME=/path/to/shared/codex-agent-coordinator
```

The script uses a lock file in that directory so concurrent agents cannot lease
the same port.

## Quick Start

Resolve the script path relative to this skill directory:

```bash
PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
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

Check, restart, and stop:

```bash
python3 scripts/dev_coordinator.py server status --project "$PROJECT_ROOT" --name web
python3 scripts/dev_coordinator.py server restart --agent "$USER" --project "$PROJECT_ROOT" --name web
python3 scripts/dev_coordinator.py server stop --agent "$USER" --project "$PROJECT_ROOT" --name web
python3 scripts/dev_coordinator.py server logs --project "$PROJECT_ROOT" --name web --tail 200
```

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
evidence, not synthetic UI decoration.

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

Useful endpoints:

- `GET /v1/inventory`
- `GET /v1/state`
- `GET /v1/ports`
- `GET /v1/servers`
- `POST /v1/ports/lease`
- `POST /v1/ports/release`
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
dashes, for example:

```json
{"agent":"codex-a","project":"/repo","name":"web","cwd":"/repo","cmd":"npm run dev -- --port {port}","range":"3000-3999"}
```

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

Existing Docker labels cannot be rewritten for running containers. When Docker
does not provide Compose project labels, register coordinator-side metadata with
`docker register` or let `docker start/stop/restart` attach it automatically
from `--agent` and `--project`. Inventory merges real Docker Compose labels
first, then coordinator sidecar metadata for unlabeled containers.

When a project runtime declaration names an existing unlabeled container,
`project start` adopts that container into coordinator-side metadata before it
reports final status. This keeps databases such as `aerodb-pg` grouped under
the repo that declared them instead of under a name-derived pseudo-project.

The shared inventory includes stopped containers (`docker ps --all`) so agents
can see containers that are available to start instead of accidentally creating
duplicates.

Inventory also includes real telemetry for running containers when Docker is
available. The coordinator samples `docker stats --no-stream`, stores a bounded
rolling `stats_history` per container, and exposes current CPU, memory, network
I/O, and block I/O values plus per-second network/block rates. Stopped
containers remain visible but do not receive live stats.

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
containers. If it still cannot identify a complete runtime, it returns
`ok=false` with `classification=missing_dependency` instead of guessing ports or
reporting success.

## Agent Workflow

1. Set `PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"`, then
   run `inventory --project "$PROJECT_ROOT"` before starting, stopping, or replacing any
   local service.
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
  `starting`, `unhealthy`, `wrong-listener`, or `stopped`.
- Stopped-server records are retained for evidence but pruned once they pass the
  retention window or exceed the per-home cap, so the shared state file does not
  grow without bound across months of start/stop cycles.
- A corrupt state file (for example a partial write after a crash) is backed up
  to `state.json.corrupt-<epoch>` and replaced with a fresh default state, so
  read-only commands like `inventory` recover instead of failing.

## Safety Notes

- The coordinator does not grant permissions. It runs commands as the current
  OS user and shells out to the local Docker CLI.
- Use project-specific `--name` values. Avoid generic names like `server` when a
  repo has multiple services.
- Set `--ttl` for short-lived port leases that are not attached to a managed
  server. Expired leases are ignored during new allocation.
- Use `--json` on CLI commands when another script or agent will parse output.
