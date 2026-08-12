# DC-2026-08-10-CONTAINER-CLEANUP-01 — Agent-selected container removal is direct

## Context

A GlobalFinance agent identified nine obsolete historical topic-initializer
containers from current Compose source and live inventory. The storage planner
rejected them because mounted Compose containers were outside its reclaimable
subset. The generic lifecycle path then required archive before purge and an
administrator-provisioned exact resource grant. Those mechanical gates blocked
a clear semantic deletion decision and caused the agent to confuse eligibility
proof with obsolescence.

This server has one developer across its local accounts. The user explicitly
rejected repository ownership, cleanup ACL, archive, lifecycle-state, mount,
Compose-role, database-binding, fingerprint, plan, confirmation, and
revalidation gates for Docker container deletion. Named volumes remain a
separate data-retention decision.

## Decision

The stable client exposes one direct container-removal intent:

```text
devcoordinator storage remove container TARGET --reason REASON
```

The agent or user selects the target and owns the destructive decision. Python
resolves one current Coordinator catalog target to its full 64-character native
Docker container ID so it can issue a fixed command; that resolution is command
binding, not a project-ownership or authorization proof. One attributed broker
operation invokes only:

```text
docker rm -f <full-container-id>
```

There is no cleanup grant, repository ownership check, archive, retirement,
stopped/unmounted requirement, Compose or database classification, identity
fingerprint, durable plan, confirmation phrase, or second observation. Docker's
already-absent response is successful. The command never adds `-v`, invokes
Compose teardown, or prunes resources, so named and anonymous volumes are not
removed by this container intent.

Volume deletion keeps its existing exact plan/apply workflow because it is a
separate user data-retention decision. The container portion of
DC-2026-08-09-STORAGE-CLEANUP-01 and the generic archive-before-permanent-remove
constraint in DC-2026-07-25-RUNTIME-01 are superseded by this decision.

## Alternatives considered

- Keeping the exact storage planner, archive-first lifecycle, per-resource
  grants, fingerprints, and confirmation was rejected because those gates
  blocked routine single-developer cleanup after the semantic decision was
  already made.
- Using non-forced `docker rm` was rejected because it reintroduces a running
  state gate and requires separate stop choreography.
- Allowing arbitrary Docker argv or prune was rejected because the requested
  operation selects one container, and a fixed command is simpler than another
  command language.
- Removing volumes with the container was rejected because the user explicitly
  distinguished container cleanup from data retention.

## Verification

Regression coverage removes stopped, running, mounted, standalone, Compose
one-off, ordinary Compose, database-bound, cross-repository, and ACL-free
container fixtures through one installed-client call. It proves the only host
argv is `docker rm -f <64-char-id>` without `-v`, no plan/archive/grant or fresh
observation occurs, an already-absent result is truthful, and malformed or
unresolved selectors never invoke Docker. Existing named-volume plan/apply
coverage remains unchanged. Production acceptance removes disposable exact
containers only; it never uses project data volumes as fixtures.
