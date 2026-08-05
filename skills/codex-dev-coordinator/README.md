# Codex DevCoordinator

DevCoordinator is the single attributed Python authority for host-visible local
runtimes and durable asynchronous tests across repositories, agents, and local
accounts.

## Routine agents

Run the immutable client in the active Git worktree:

```bash
devcoordinator capabilities
devcoordinator targets web --kind service
devcoordinator runtime status web --kind service
devcoordinator runtime ensure web --kind service --desired ready
devcoordinator test enqueue --intent change
```

For a development server in a valid repository that has never used the host
authority, discovery is pure and reports `repository.state=unenrolled`. The
first bounded start adopts and starts it in one broker-owned operation:

```bash
devcoordinator runtime serve prototype --cwd . --port 4173 \
  --ttl-seconds 3600 --kill-after-run false --launch-timeout-seconds 30 -- \
  npm run dev -- --host 0.0.0.0 --port 4173 --strictPort
```

The cwd is repository-relative, the port is exact, and argv is never a shell
string. Do not substitute a coding-sandbox bind, administrator enrollment, or
local fallback. Failures say whether validation or broker execution failed,
whether anything changed, whether retrying helps, and what to do next.

It derives root/temporary-worktree context and attribution, validates the one
active release/generation/protocol contract, resolves the exact target, creates
mutation operation IDs, and emits a bounded decision. Use command-scoped
`--project /absolute/worktree` only from arbitrary cwd. Supply an operation ID
only to replay the exact prior mutation after an uncertain reply.

```bash
devcoordinator operation follow dc1:operation:OPERATION_UUID
devcoordinator test follow dc1:run:RUN_ID --wait-seconds 30
```

Routine change/checkpoint/manual tests plan and submit in one call. Handoff and
release return an immutable plan for review and require a separate exact
`devcoordinator test submit dc1:plan:…` decision. `devcoordinator-mcp` stdio
tools expose the same contract and accept only MCP protocol `2025-11-25`.

See [the agent-client reference](references/agent-client.md) for call counts,
bounds, timing/token-proxy evidence, outcomes, MCP, and ownership.

## Authority

One service-owned SQLite/WAL authority behind a peer-authenticated Unix socket
owns repository/resource identity, runtime/test admission, lifecycle, replay,
cleanup, and evidence. One canonical worktree is one project; Python proves the
root → temporary → resource tree. Names, paths, ports, images, and UI heuristics
never establish ownership.

On the confirmed single-developer host, local accounts are attribution and
failure domains, not mutually distrusting principals. Exact identities,
generation fencing, bounds, containment, idempotent operation IDs, public
authorization, and separate secret transports remain enforced.

Python owns mechanical context/target resolution, validation, runtime no-op and
convergence, schema-3-only test planning/submission/follow, safe pre-launch
retry, supported durable cleanup/recovery/supersession, and
`scripts/software_owned_delivery.py`. The agent or user retains semantic goals,
material test choices/deadlines, attention remediation, destructive/data work,
handoff/release review, and publication.

## Advanced work

Lower-level commands are separate current capabilities for structured
definitions, replacement, bounded run, staged removal, manifest
authoring/doctoring, exact artifact drill-down, Compose run-once, ephemeral
containers, enrollment, migration, backup, and recovery:

```bash
python3 skills/codex-dev-coordinator/scripts/dev_coordinator.py runtime --help
devcoordinator-test --help
```

For correlated failures and source-side efficiency evidence:

```bash
devcoordinator-call-log --operation-id OPERATION_UUID --limit 20
python3 scripts/check_agent_client_efficiency.py
python3 scripts/self_test_agent_client_efficiency.py
```

See [the runtime API](references/runtime-api.md) and
[admin operations](references/admin-operations.md). Install source links with
`scripts/manage_skill_links.py`; deliver with `software_owned_delivery.py`.
