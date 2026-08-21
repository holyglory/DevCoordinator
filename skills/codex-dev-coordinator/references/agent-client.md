# Stable Runtime Client

`devcoordinator` is the bounded interface for routine host-runtime intents. It
composes broker/runtime contracts; it is not another authority or state store.

## Contents

- [Context and contract](#context-and-contract)
- [Stable commands](#stable-commands)
- [First-use diagnosis](#first-use-diagnosis)
- [Result bounds and typed outcomes](#result-bounds-and-typed-outcomes)
- [Optional MCP](#optional-mcp)
- [Ownership boundary](#ownership-boundary)

## Context and contract

Run inside the intended Git worktree. Each command:

1. resolves the canonical root or linked temporary worktree;
2. derives caller attribution and repository routing;
3. validates release, authority generation, broker protocol, result schema, and
   the 8 KiB result envelope;
4. resolves an exact ID or rejects an ambiguous display name; and
5. emits one compact JSON decision.

Use command-scoped `--project /absolute/worktree` from another cwd. Generated
continuations include the resolved canonical project and shell-quote paths with
spaces, so they remain executable from any directory.

## Stable commands

| Intent | Command |
| --- | --- |
| Validate contract | `devcoordinator capabilities` |
| Resolve a target | `devcoordinator targets [SELECTOR] [--kind KIND]` |
| Read state | `devcoordinator runtime status SELECTOR [--kind KIND]` |
| Converge state | `devcoordinator runtime ensure SELECTOR --desired ready\|stopped` |
| Start first-use service | `devcoordinator runtime serve NAME ... -- ARGV...` |
| Read bounded logs | `devcoordinator runtime capture_logs SELECTOR` |
| Exact lifecycle action | `devcoordinator runtime start\|stop\|restart SELECTOR` |
| Replace definition | `devcoordinator runtime replace SELECTOR --expected-generation N ...` |
| Recover mutation | `devcoordinator operation follow HANDLE` |
| Inspect storage | `devcoordinator storage inventory` |
| Remove one container | `devcoordinator storage remove container EXACT_ID --reason TEXT` |
| Plan/apply volume removal | `devcoordinator storage plan volume NAME ...`, then returned apply command |
| Database operation | `devcoordinator database backup\|retire SELECTOR ...` |
| Compose recreation | `devcoordinator compose recreate-service SERVICE ...` |
| Ephemeral image | `devcoordinator ephemeral image-status\|image-prefetch TEMPLATE` |

The selected agent or user owns destructive meaning. Python owns context,
identity, validation, exact host calls, replay, convergence, and cleanup.

Container removal is the confirmed single-developer exception: one selected
current target invokes only `docker rm -f FULL_ID` without `-v`. It may stop a
running container and discard its writable layer; it never deletes volumes.
Volume removal remains a separate confirmation-bound plan/apply operation.

## First-use diagnosis

A valid unknown Git root is `unenrolled`, not broken. Read-only discovery never
adopts it. `runtime serve` is the routine first-use mutation and requires a
lowercase name, repository-relative cwd, exact port, positive TTL, explicit
`kill-after-run`, bounded launch timeout, and shell-free argv.

| Evidence | Meaning | Recovery |
| --- | --- | --- |
| Direct bind failed; no Coordinator JSON or journal record | Coordinator was not invoked | Use `devcoordinator runtime serve --help` and one structured serve call |
| `broker_contacted=false`, `mutation_performed=false` | Client validation rejected the request | Correct the named field and resubmit |
| `broker_contacted=true`, `mutation_performed=false` | Broker rejected without mutation | Correct the typed cause; retain the exact port |
| `broker_contacted=true`, `mutation_performed=true` | Adoption committed before later rejection | Do not re-enroll; correct the launch cause |
| Contact or mutation is null with an operation handle | Outcome is uncertain | Run the returned project-scoped `operation follow` command |

“Local fallback is disabled” never authorizes fallback. A coding-sandbox
`EACCES` or `EPERM` host bind is caller misuse until a Coordinator call itself
returns a typed defect.

## Result bounds and typed outcomes

| Surface | Maximum compact JSON |
| --- | ---: |
| Absolute client envelope, including errors | 8 KiB |
| Capabilities | 3 KiB |
| Targets | 2 KiB |
| Runtime status or ensure | 2 KiB |
| Complete operation-follow result | 3 KiB |

A failure includes code, classification, phase, broker-contact truth, mutation
truth, retryability, and one next action or command. `false` is proven absence;
null is uncertainty. Never turn uncertainty into a fresh operation UUID.

Read-only results may cross a same-schema release digest change only when the
protocol, authority generation, schema, result bounds, capability contract, and
requested exact identity still match. Runtime and other mutations retain exact
release matching.

## Optional MCP

`devcoordinator-mcp` accepts protocol `2025-11-25` only. Runtime tools are
`capabilities`, `targets`, `runtime_status`, `runtime_ensure`, and
`operation_follow`. MCP maps arguments to the same stable parser and returns the
same bounded decision; it owns no target, lifecycle, retry, or cleanup meaning.

The independent `bug_report`, `bug_list`, and `bug_close` tools use the same
open-only registry as `devcoordinator-bug` and load no repository context,
profile, broker, API, authority, testd, or call journal.

## Ownership boundary

Use immutable IDs and generations. Repository association and local account are
non-authorizing routing and attribution on this single-developer host. Public
Console identities, route grants, and credentials remain separate authorization
boundaries. Secret values never enter ordinary metadata, argv, environment
descriptors, results, or logs.

The advanced Python CLI may expose structured definitions, replacement,
bounded run, commissioning, and recovery, but must remain a thin mapping to the
same broker operations. It must not introduce another lifecycle state machine.
