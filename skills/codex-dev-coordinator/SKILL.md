---
name: codex-dev-coordinator
description: Use when Codex agents in one or multiple Codex apps need coordinated port leases, shared dev-server start/stop/restart/status/health control, or Docker/Docker Compose management through a single local coordinator CLI or HTTP endpoint.
---

# Codex Dev Coordinator

Use this skill before starting local dev servers, allocating ports, inspecting
running services, or managing Docker when multiple Codex agents or Codex app
instances may be working on the same machine.

## Core Rule

Do not start dev/test servers, Docker Compose services, Docker containers, or
local database stacks directly with default ports. First run `inventory` to see
what is already running. Then start/restart/stop through the coordinator, or
lease a port through the coordinator and pass that port to the command.

Never do the pattern "try the default port, then try another one if busy." The
coordinator is the source of truth.

## Shared State

The bundled script stores leases and server metadata under:

```bash
~/.codex/agent-coordinator/
```

For multiple OS users, Parallels VMs, or separate Codex accounts that need one
shared memory, set the same writable path in every agent shell:

```bash
export CODEX_AGENT_COORDINATOR_HOME=/path/to/shared/codex-agent-coordinator
```

The script uses a lock file in that directory so concurrent agents cannot lease
the same port.

## Quick Start

Resolve the script path relative to this skill directory:

```bash
python3 scripts/dev_coordinator.py inventory --project "$PWD"
```

```bash
python3 scripts/dev_coordinator.py port lease --agent "$USER" --project "$PWD" --range 3000-3999
```

Start a server and let the coordinator lease the port, keep the PID, store logs,
and health-check it:

```bash
python3 scripts/dev_coordinator.py server start \
  --agent "$USER" \
  --project "$PWD" \
  --name web \
  --cwd "$PWD" \
  --cmd 'npm run dev -- --host 127.0.0.1 --port {port}' \
  --range 3000-3999 \
  --health-url 'http://127.0.0.1:{port}/'
```

Check, restart, and stop:

```bash
python3 scripts/dev_coordinator.py server status --project "$PWD" --name web
python3 scripts/dev_coordinator.py server restart --project "$PWD" --name web
python3 scripts/dev_coordinator.py server stop --project "$PWD" --name web
```

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
- `POST /v1/servers/stop`
- `POST /v1/servers/restart`
- `POST /v1/servers/status`
- `POST /v1/docker/ps`
- `POST /v1/docker/compose-up`
- `POST /v1/docker/compose-down`
- `POST /v1/docker/logs`
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
python3 scripts/dev_coordinator.py docker compose-up --cwd "$PWD" --file docker-compose.yml --detach
python3 scripts/dev_coordinator.py docker compose-down --cwd "$PWD" --file docker-compose.yml
python3 scripts/dev_coordinator.py docker logs --container my-container --tail 80
python3 scripts/dev_coordinator.py docker restart --container my-container
```

Use `--dry-run` when Docker may not be installed or when validating the command
shape without changing containers.

## Agent Workflow

1. Run `inventory --project "$PWD"` before starting, stopping, or replacing any
   local service. Reuse healthy existing URLs when they match the task.
2. Identify the project path and a stable server name such as `web`, `api`, or
   `worker`.
3. Run `server status` first. If the existing healthy server matches the task,
   reuse its URL.
4. If no server exists, run `server start` with a command that accepts `{port}`.
5. If the server exists but is stale or unhealthy, run `server restart`.
6. When stopping work, run `server stop` only for servers you own or that the
   user asked you to stop.
7. For Docker, prefer `docker compose-*` commands through the coordinator and
   inspect status before stopping shared containers.

## Safety Notes

- The coordinator does not grant permissions. It runs commands as the current
  OS user and shells out to the local Docker CLI.
- Use project-specific `--name` values. Avoid generic names like `server` when a
  repo has multiple services.
- Set `--ttl` for short-lived port leases that are not attached to a managed
  server. Expired leases are ignored during new allocation.
- Use `--json` on CLI commands when another script or agent will parse output.
