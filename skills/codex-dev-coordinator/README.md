# Codex DevCoordinator Runtime

This canonical skill guides attributed host-visible runtime work through the
server-wide DevCoordinator. Governed repository testing is documented by the
separate `codex-governed-tests` skill.

## Routine runtime

Run the installed client in the active worktree:

```bash
devcoordinator capabilities
devcoordinator targets web --kind service
devcoordinator runtime status web --kind service
devcoordinator runtime ensure web --kind service --desired ready
```

For a valid first-use repository, use one structured bounded service start:

```bash
devcoordinator runtime serve prototype --cwd . --port 4173 \
  --ttl-seconds 3600 --kill-after-run false --launch-timeout-seconds 30 -- \
  npm run dev -- --host 0.0.0.0 --port 4173 --strictPort
```

The cwd is contained, the port is exact, argv is shell-free, execution is
non-root, and systemd owns the cgroup and TTL cleanup. Direct sandbox binds,
manual enrollment, and local fallback are not substitutes.

Use `--project /absolute/worktree` only from another cwd. Reuse an operation ID
only for exact replay after an uncertain reply:

```bash
devcoordinator operation follow dc1:operation:OPERATION_UUID
```

## Authority

Python owns immutable target resolution, generation fencing, observation,
idempotent mutation, convergence, and cleanup. Local accounts are attribution
and execution domains, not mutually distrusting tenants. Credentials use the
separate sealed transport and never ordinary metadata or argv.

## Advanced work

```bash
python3 skills/codex-dev-coordinator/scripts/dev_coordinator.py runtime --help
devcoordinator-call-log --operation-id OPERATION_UUID --limit 20
```

Read [the stable client](references/agent-client.md),
[runtime API](references/runtime-api.md), or
[server administration](references/admin-operations.md) only as needed.

Install canonical links with `scripts/manage_skill_links.py`. DevCoordinator
itself is verified and delivered only by `scripts/software_owned_delivery.py`.
