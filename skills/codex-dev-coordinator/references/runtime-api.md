# Agent Runtime API

This reference ships inside the standalone `codex-dev-coordinator` skill.

The runtime API is the only agent-facing lifecycle entrypoint. It resolves
repository ownership, observes current state, performs one typed action, and
returns one compact report. Agents should not reproduce its preflights or
cleanup logic in shell commands.

## Current authority boundary

The product-default system client resolves enrolled paths locally, sends only
stored repository/resource IDs to the peer-authenticated broker, and supports
`status` after a fresh service-owned observation with live ACL, family-wide
classification, and exact-membership revalidation. Shared `start`, `stop`, and
`restart` are enabled for existing enrolled Docker and database-stack targets;
they use an exact underlying container ID, durable replay, fresh final
observation, and terminal state/readiness proof. Enrolled worker-role services
also support peer-UID status/start/stop/restart and structured,
generation-checked replacement through a fixed native runner. Other service
roles return `runtime_supervisor_required`. Start/restart with a TTL returns
`runtime_cleanup_owner_required` until the broker owns durable expiry cleanup.
An ambiguous restart remains `operation_outcome_uncertain` when observing the
container running cannot prove that the restart transition occurred. `run`,
client-authored port definitions, and Docker/database replacement are rejected.
Do not create a private shadow store to bypass that boundary. Explicit isolated
account authority retains the full source implementation; its detached TTL
lifecycle requires the long-lived authenticated `api serve` owner.

## Call

```bash
COORDINATOR="skills/codex-dev-coordinator/scripts/dev_coordinator.py"
python3 "$COORDINATOR" runtime status \
  --agent "$AGENT" --root-repo "$ROOT_REPO" --no-temporary-repo \
  --target-kind service --target-id "$RESOURCE_ID" --target-name web \
  --purpose development --no-ttl --kill-after-run false
python3 "$COORDINATOR" runtime --request-file /absolute/request.json
```

Use flags for ordinary existing-target actions. Use `--request-file` or
`--request-json` for structured definitions, replacement, and bounded `run`
requests. Both forms use the same validator. The default response is one JSON
line; use `--pretty` for inspection and `runtime --help` for the executable
contract.

## Request

Every request has this shape:

```json
{
  "schema_version": 1,
  "action": "status",
  "agent": "codex-session-id",
  "root_repo": "/absolute/original/worktree",
  "temporary_repo": null,
  "purpose": "development",
  "ttl_seconds": null,
  "kill_after_run": false,
  "target": {
    "kind": "service",
    "id": "normalized-immutable-id",
    "name": "web"
  }
}
```

Required context:

- `root_repo` is the canonical primary Git worktree.
- `temporary_repo` is always present. It is either `null` or the canonical
  linked worktree used by this run.
- `agent` identifies the requesting account/session.
- `target.id` is a normalized immutable identity. A service also carries its
  declared `name`, but that display/runtime name never grants ownership.

Actions are `status`, `start`, `stop`, `restart`, `replace`, `run`, and
`remove`. Target kinds are `service`, `docker`, and `database_stack`. The API
rejects combinations that cannot preserve identity or data. Service
replacement is rollback-capable; shared authority restricts it to an enrolled
worker, exact peer UID, repository-contained cwd, structured argv/environment,
and an expected definition generation. Docker and database-stack replacement
return `unsupported_safe_replace` before store or host access. Compose options
cannot enable it; the required recreate/rebind and verified PostgreSQL
backup/restore transaction remains in `CompletionLedger.md`.

`purpose` is `development`, `test`, or `temporary`. Every request includes an
explicit boolean `kill_after_run`; only `run` may set it true. Test and
temporary start, restart, replace, and run actions require a positive bounded
`ttl_seconds`. Read-only status requires null, and explicit stop may also use
null. A `run` request supplies structured `run_argv`; the API starts the
declared runtime, executes that command without a shell, and owns cleanup on
success, failure, interruption, and TTL expiry.

## Structured request examples

Request and option names are lower-case `snake_case`; `KillAfterRun` is the
top-level JSON boolean `kill_after_run`. The request and `options` objects are
closed schemas, so unknown keys fail validation. Command arrays are executed
without a shell, and `cwd` must be an absolute directory inside the effective
root or temporary repository.

### Define and start a new service

Omit `target.id` only when defining a service with `start` or `run`. After
proving the repository scope, the API derives the immutable ID from the
effective repository and service name and returns it in the result. This
definition form uses explicit account authority; shared system authority
requires an already-enrolled immutable target.

```json
{
  "schema_version": 1,
  "action": "start",
  "agent": "codex-session-id",
  "root_repo": "/workspace/example",
  "temporary_repo": null,
  "purpose": "development",
  "ttl_seconds": null,
  "kill_after_run": false,
  "target": {
    "kind": "service",
    "name": "web"
  },
  "options": {
    "argv": ["npm", "run", "dev", "--", "--host", "{host}", "--port", "{port}"],
    "cwd": "/workspace/example",
    "env": {"NODE_ENV": "development"},
    "host": "127.0.0.1",
    "preferred": 3000,
    "range": "3000-3999",
    "health_url": "http://{host}:{port}/health",
    "health_timeout": 15
  }
}
```

`options.argv` is required for a new service. `{host}` and `{port}` are
replaced in command arguments and `health_url` after the Coordinator reserves
the port. `cwd`, `env`, `host`, `preferred`, `range`, `health_url`, and
`health_timeout` are optional; `cwd` defaults to the effective repository and
`host` defaults to `127.0.0.1`. A new persistent supervised worker must first
be installed/enrolled so later worker actions can name its immutable ID.

### Replace one exact enrolled worker

```json
{
  "schema_version": 1,
  "action": "replace",
  "agent": "codex-session-id",
  "root_repo": "/workspace/example",
  "temporary_repo": null,
  "purpose": "development",
  "ttl_seconds": null,
  "kill_after_run": false,
  "target": {
    "kind": "service",
    "id": "immutable-worker-id",
    "name": "index-worker"
  },
  "options": {
    "argv": ["python3", "workers/index.py"],
    "cwd": "/workspace/example",
    "env": {"WORKER_MODE": "index"},
    "expected_definition_generation": 7,
    "keep_alive": true,
    "restart_limit": 10,
    "restart_window_seconds": 300,
    "rearm_crash_loop": false
  }
}
```

Shared authority requires all of `argv`, `cwd`, `env`, and
`expected_definition_generation`. Read the current generation from a fresh
status/inventory result; it is a compare-and-swap guard, not a guessed value.
The broker also proves that `cwd` belongs to the enrolled peer and is inside
the exact repository before mutation. Supervision fields are optional, apply
only to an installed persistent development worker, and restart limits require
`keep_alive: true`. Set `rearm_crash_loop: true` only after repairing a tripped
worker; successful replacement advances the definition generation.

### Start a temporary service, run a bounded test, then clean up

```json
{
  "schema_version": 1,
  "action": "run",
  "agent": "codex-session-id",
  "root_repo": "/workspace/example",
  "temporary_repo": "/workspace/example-worktrees/test-123",
  "purpose": "test",
  "ttl_seconds": 600,
  "kill_after_run": true,
  "target": {
    "kind": "service",
    "name": "test-web"
  },
  "options": {
    "argv": ["npm", "run", "dev", "--", "--host", "{host}", "--port", "{port}"],
    "cwd": "/workspace/example-worktrees/test-123",
    "env": {"NODE_ENV": "test"},
    "host": "127.0.0.1",
    "range": "3000-3999",
    "health_url": "http://{host}:{port}/health",
    "health_timeout": 15,
    "run_argv": ["npm", "test", "--", "--runInBand"],
    "run_env": {"CI": "true"},
    "run_timeout_seconds": 480
  }
}
```

`run` requires purpose `test` or `temporary`, a positive `ttl_seconds`, and
`options.run_argv`; a newly defined service also requires `options.argv`.
`run_env` affects only the test command, while `env` defines the service
environment. The command timeout defaults to and cannot exceed the required
TTL. With `kill_after_run: true`, the API
stops and cleans the exact session-owned resources after success, failure, or
interruption; the TTL is the crash fallback. A newly created service is removed
from active state, while a borrowed pre-existing resource is stopped as needed
but remains cataloged. Shared broker authority does not accept `run`; submit it
through explicit account authority.

## Repository families

One canonical Git worktree remains one repository/project. A repository family
adds presentation and execution context without collapsing identities:

```text
original/root repository
├── services owned by the root worktree
└── temporary linked worktree
    └── services owned by that worktree
```

Python proves the Git common-directory relationship. Names, remote URLs, path
prefixes, ports, container images, and UI state never establish it.

Repository proof also inspects the native ACL on every already-opened path
component while retaining owner, mode, type, and symlink checks. Non-owner
mutation grants fail closed. macOS extended ACLs and Linux POSIX ACLs are
supported; Linux NFS/SMB NFSv4 and rich-ACL repositories are rejected rather
than treated as mode-equivalent.

Inventory exposes `repository_trees`:

```json
[
  {
    "family_id": "family-id",
    "root_repository": {
      "repo_id": "root-id",
      "canonical_root": "/repo",
      "display_name": "repo"
    },
    "usage": {},
    "scopes": [
      {
        "repo_id": "root-id",
        "kind": "root",
        "canonical_root": "/repo",
        "display_name": "repo",
        "run_id": null,
        "expires_at": null,
        "kill_after_run": false,
        "usage": {},
        "server_ids": [],
        "container_resource_ids": [],
        "database_binding_ids": []
      }
    ]
  }
]
```

Board and Console render this tree. They may use the flat arrays only as
resource lookup tables; they do not recompute membership or parentage. Missing
or malformed `repository_trees` produces an explicit contract-unavailable
state and disables hierarchy-dependent lifecycle actions.

## Result

Successful and failed calls use the same envelope:

```json
{
  "ok": true,
  "classification": "ready",
  "ready": true,
  "action": "start",
  "run_id": "runtime-session-id",
  "repository": {},
  "resources": [],
  "totals": {},
  "stale_processes": {"count": 0, "items": [], "truncated": false},
  "crashes": {"count": 0, "items": [], "truncated": false},
  "artifacts": [],
  "target_log_evidence": null,
  "cleanup": {}
}
```

Resources report exact state, immutable identity, ports, URLs/domains, and
CPU/memory. Totals include service/process, Docker, and combined values for the
effective worktree and original root family. Crash and stale-process entries
carry concise classifications. Logs are size- and line-bounded artifact links
with an absolute `path` for agents/native UI and an authenticated relative
`href` for Console; the Console proxy never returns the host path. Explicit
account authority captures Docker/database attention and failure logs against
the normalized target plus exact full container ID, redacts secrets, and
publishes a private immutable typed artifact capped at 1 MiB and 2,000 lines.
An exact-ID capture remains available after container removal, while identity
replacement or missing Docker without a retained capture reports an explicit
`target_log_evidence.availability = "unavailable"` reason. Shared worker
supervision returns retained per-attempt crash artifacts. Shared
Docker/database mode still requires an ACL-checked ID-only capture operation
and never falls back to a client-local artifact authority.

For `status`, `ok=true` means the exact target was successfully observed and
classified. `ready` separately reports whether its current state is usable;
an honestly observed stopped or unhealthy target is not an API failure.

Treat `ok=false` as failure even if one URL answers. Unclassified active
resources in the requested family fail before mutation. The response preserves
the exact blocker, operation, cleanup state, and log artifacts.

## Worker supervision and removal

Persistent workers run only from a stored structured definition. Set
`keep_alive` explicitly on first start. When enabled, the fixed native runner
starts with the Coordinator and asks the broker before each child launch. Every
exit becomes an immutable attempt and typed log artifact before a restart is
allowed. The default breaker trips on the tenth unexpected crash in an
inclusive 300-second window and never clears itself; after repairing the
definition, an attributed start with `rearm_crash_loop=true` re-arms it.
Turning keep alive off changes restart policy but does not stop a running
worker.

`remove` accepts an existing immutable service ID and is deliberately staged:
plan/apply Archive, then plan/apply permanent cleanup. Apply fields are the
returned plan ID, fingerprint, and confirmation phrase. Permanent cleanup
proves stop, unregisters native startup, deletes active definition,
configuration, policy, membership, allocation, ACL, and UI projections, and
retains the tombstone, operations, attempts, and log links. The removed ID can
never be started or silently reenrolled. A deliberate
`broker enroll --explicit-reinstall` creates a new immutable incarnation and
preserves the old evidence.

## Temporary cleanup

Runtime sessions persist their expiry and exact resource fingerprints before a
mutation. `kill_after_run=true` performs synchronous cleanup when `run` ends;
the TTL reaper is the crash fallback. Cleanup is idempotent and exact-identity
bound. After exact stop, listener, lease, and assignment proof, one transaction
deletes a session-created service's active definition, command/environment,
observation, membership, controller, startup-policy, released lease, and
inactive assignment rows. Operations, events, and the immutable runtime session
resource snapshot remain audit evidence. An otherwise-empty temporary
repository is startup-fenced and omitted from active repository trees; its
proved Git-family scope identity is retained so explicit Coordinator reinstall
can safely reactivate it. Pre-existing services, Docker resources, and database
targets are borrowed: cleanup stops them when required but retains their
catalog, membership, and repository presentation. The current API cannot create
Docker/database targets and rejects a `removed` disposition for either kind.

## Lower-level and operator interfaces

Legacy `project`, `server`, `docker`, `port`, `broker`, archive, backup, and
recovery commands remain compatibility/operator interfaces. Agents should use
them only when a runtime report names a specific repair and `--help` confirms
the required authority. Server-wide installation and recovery are described in
[the coordinator skill README](../skills/codex-dev-coordinator/README.md), the
[Console operations documentation](../apps/DevOpsConsole/README.md), and each
script's generated help.
