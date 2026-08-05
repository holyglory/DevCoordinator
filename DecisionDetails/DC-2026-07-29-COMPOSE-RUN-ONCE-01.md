# Governed Compose run-once execution

## Context

Skydive.Live needs to invoke repository-owned ingestion/parsing work that is
already modeled as a Docker Compose service. Agent accounts must not regain
direct Docker authority, and the broker must not become an arbitrary command,
environment, mount, or path execution boundary. The result needs a small
machine-readable receipt while scraper output and diagnostics can contain
credentials, page content, or personal data.

## Selected contract

- Administrators declare `docker.run_once_services` separately from lifecycle
  `docker.services`. Each exact service policy seals a 600–3600 second maximum
  and a closed receipt schema of required/optional fields and primitive types.
- Enrollment grants each service name explicitly. The protected profile
  publishes only the granted name and timeout ceiling. A client sends exactly
  agent, service, timeout, and an idempotent operation UUID; it cannot send a
  command, environment, mount, Compose file, working directory, or Docker
  option.
- Enrollment proves the merged Compose model and an explicit image reference
  for every run-once service. Execution binds that reference to the current
  immutable image ID before creation, then creates one named, labeled, stopped
  container with `--no-deps`, `--no-TTY`, `--no-start`, `pull_policy: never`,
  the immutable image ID, a non-restarting/noninteractive configuration, and
  the repository cgroup/resource limits.
- The authority journals intent before image binding, creation, start, wait,
  timeout stop, evidence capture, and cleanup. Later phases use only the exact
  immutable container ID. A replay after an unbound create intent may recover
  only the exact fully labeled container; proved absence is reported
  categorically and is never recreated under that operation ID.
- The service must write exactly one UTF-8 JSON object to stdout. Duplicate
  keys, non-finite numbers, trailing data, missing/unexpected fields, wrong
  types, and output above 64 KiB fail closed. Only allowlisted typed fields and
  their canonical digest are public. Complete stdout/stderr are drained and
  retained only as private SHA-256 and byte-count evidence; raw bytes never
  enter the authority, profile, broker reply, or ordinary logs.
- The exact container and anonymous volumes are removed before the operation
  can commit its public result. A lost final reply replays the durable result
  without repeating host work.

## Alternatives considered

Direct Docker/Compose access was rejected because it restores arbitrary host
execution and loses broker attribution. Extending the general shared runtime
`run` contract was rejected because client-authored commands and environment
are intentionally outside system authority. A generic ephemeral-container
template was rejected because the ingestion workload already depends on a
repository-sealed Compose model and project networks. Capturing raw logs or
accepting free-form JSON was rejected because it can publish secrets,
unbounded content, or schema-confused data. Automatically recreating an absent
container after an uncertain create was rejected because it can duplicate
non-idempotent ingestion.

## Implementation evidence

- Policy and strict receipt validation:
  `skills/codex-dev-coordinator/scripts/devcoordinator/compose_run_once.py`
- Request, profile, enrollment, CLI, and runtime-manifest boundaries:
  `broker.py`, `broker_profile.py`, `broker_enrollment.py`, `broker_cli.py`,
  and `scripts/dev_coordinator.py`
- Durable phases, ACLs, immutable snapshots, and private evidence:
  `broker_persistence.py`
- Fixed host execution and stream hashing:
  `broker_host.py`
- Replay/resume state machine:
  `broker_backend.py`
- Authority-plane table ownership:
  `storage_split.py`

## Verification

`test_compose_run_once.py` covers closed policy/request schemas, duplicate and
non-finite JSON rejection, field/type enforcement, size/UTF-8 boundaries,
explicit grants, timeout ceilings, manifest separation, CLI defaults, durable
success and replay, private stream evidence, crash after create intent,
no-recreate ambiguity handling, fixed Compose argv, immutable image override,
exact labels/cgroup limits, and complete separate stdout/stderr hashing.
Existing Compose, host, profile migration, reenrollment, and storage-split
regressions are run alongside the focused suite in normal and optimized Python.

## Remaining activation evidence

Source completion is not live deployment. The immutable broker release and
authority schema must be activated through the existing server-wide upgrade
transaction. Skydive.Live must then declare the exact ingestion service and
receipt fields, receive an explicit root enrollment grant, and prove one real
run plus same-operation replay through the broker. Acceptance must verify the
database changes and multilingual parsed/translated records through the
application surface while confirming no raw scraper output is exposed.
