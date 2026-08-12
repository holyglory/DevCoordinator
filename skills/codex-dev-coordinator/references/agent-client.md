# Agent Intent Client

`devcoordinator` is the immutable, low-entropy interface for routine calling
agents. It composes existing broker/runtime/test contracts; it is not another
authority or state store.

## Current context and contract

Run the client inside the intended Git worktree. For each command, Python:

1. proves the current path as a canonical root or linked temporary worktree;
2. derives the root → temporary relationship and caller attribution;
3. loads the protected broker profile and active repository identity;
4. handshakes the broker protocol, authority generation, release digest, result
   schema, and required 8 KiB agent-result envelope; and
5. performs the requested exact-ID operation and emits one compact JSON line.

Use command-scoped `--project /absolute/worktree` when invoked from arbitrary
cwd. The current client has no caller-supplied root-repository,
temporary-repository, or attribution override; Python derives all three. An
installed immutable client rejects an active release mismatch. All clients
reject a broker protocol, authority generation, result-schema, or required
global-result-bound mismatch before dependent work. Source-checkout clients
have no immutable release digest and are development only. Per-surface client
projections independently enforce their local ceilings even though only the
global 8 KiB envelope is part of the contract fence.

The sole local test-actor form is `codex:<thread-or-task-id>`, with
`codex:uid:<effective-uid>` when neither identity exists. Python validates that
same contract at production and broker consumption. A normalized
`google:<email>` actor is a distinct public-Console identity and remains
accepted only from the protected Console API account. The broker never
interprets one namespace as the other, and the sole explicit wire field is
`actor`. The host profile may contain duplicate same-repository enrollments for
local routing. An enabled enrollment wins first, then repository generation,
the calling UID, repository owner, later validity bound, and lower UID decide
ties. Repository-scoped calls use the account ID on that selected enrollment,
not the profile's default account.

`capabilities` is useful for orientation and troubleshooting, but the calling
agent does not need a separate preflight before every action: every command
performs the current-contract handshake internally. Its `runtime.actions` and
`tests.actions` describe the underlying authority, not a promise that every
action is projected by the thin CLI or MCP catalog. Use the actual parser/tool
catalog and `approval_classes` for routine interface availability; replacement,
removal, artifact drill-down, and other admin surfaces remain lower-level.

## Stable CLI

| Intent | One caller command | Python-owned work |
| --- | --- | --- |
| Validate current contract | `devcoordinator capabilities` | Context, profile, release/generation/protocol validation |
| Find one target | `devcoordinator targets [SELECTOR] [--kind KIND]` | Inventory projection, exact-ID/unique-name resolution, ambiguity rejection |
| Read state | `devcoordinator runtime status SELECTOR [--kind KIND]` | Fresh exact observation and bounded state/attention projection |
| Converge state | `devcoordinator runtime ensure SELECTOR --desired ready\|stopped [--kind KIND]` | Observation, no-op or safe start/stop selection, durable mutation, terminal proof |
| Start a new bounded development service | `devcoordinator runtime serve NAME --cwd RELATIVE --port PORT --ttl-seconds N --kill-after-run BOOL --launch-timeout-seconds N -- ARGV...` | Pure context validation, atomic first-use adoption when needed, exact-port launch without a shell, supervision, expiry and control-group cleanup |
| Remove one selected Docker container | `devcoordinator storage remove container EXACT_RESOURCE_ID --reason REASON` | Resolve the current catalog target to its full native ID and invoke only `docker rm -f <id>` without `-v`, ownership, cleanup-grant, archive, state, fingerprint, plan, confirmation, or observation gates |
| Recover mutation | `devcoordinator operation follow HANDLE` | Exact operation lookup, certainty and next-transition projection |
| Governed test batches | `devcoordinator test enqueue --intent change\|checkpoint\|manual` | Manifest validation, policy plan, registration, submission, run handle |
| Reviewed tests | `devcoordinator test enqueue --intent handoff\|release` then returned `test submit` | Immutable plan first; submission only after semantic review |
| Read/wait for tests | `devcoordinator test follow RUN [--wait-seconds N]` | Broker polling, terminal summary, bounded failures and next action |

Each row requires one launcher invocation per stated command. Target discovery
does not need to be called separately when a runtime command already has an
exact ID or unique enrolled name; the runtime command resolves it internally.
A routine test enqueue plans and submits in one call. A handoff/release workflow
requires two calls by design because plan review is a semantic gate. Follow is
one call per immediate read or bounded wait.

### Local feedback versus governed batches

Direct local test execution is limited to one focused invocation whose selector
is proven before launch to collect at most 20 cases, whose runner enforces an
execution deadline of at most 10 seconds, and which needs no host-visible or
shared state. Unit-test isolation alone is not proof of local eligibility.
Static checks remain local and are not counted as test cases.

If the collected-case count or runtime bound is unknown, collection would
exceed 20 cases, execution may exceed 10 seconds, the deadline cannot be
enforced, or durable shared evidence is required, enqueue one governed batch.
Do not reproduce the batch by looping over test files, packages, or targets in
separate local commands. A repository without a valid `.codex/tests.json` may
run only a bounded focused subset locally; its broad suite remains a manifest
setup gap rather than an authorized local fallback.

### New repository first use

A valid canonical Git root may have zero commits and only untracked source.
`capabilities` and selector-free `targets` remain read-only: they return an
unenrolled repository state and `bootstrap_supported=true` without changing the
authority. A selector against that state returns `repository_unenrolled` and
the exact `runtime serve` recovery shape; it is not a broker outage.

`runtime serve` is the only routine first-use mutation. In the same caller
operation, the broker idempotently adopts the calling peer's canonical root and
starts a structured service definition. `--cwd` must remain within that root,
the requested port is exact, TTL is positive, `kill-after-run` is explicit, and
argv after `--` is an array. The broker never executes a shell, chooses a new
port, revives a disabled/tombstoned identity, or enables local fallback. Exact
replay uses the prior operation UUID and yields the same repository, service,
session and native-unit identities.

### First-use diagnosis and recovery

The coding sandbox and DevCoordinator are separate execution boundaries. A
direct framework command that fails with `EACCES`, `EPERM`, or “cannot bind”
inside the coding sandbox did not call Coordinator. Do not diagnose that as a
broken Vite/npm server, broker outage, or port collision, and do not retry it
with a different port. Submit the documented structured `runtime serve` call.

“Repository is not enrolled” is a normal first-use state for a valid Git root.
“Local fallback is disabled” is an intentional statement that host mutation
must use the installed broker; never enable fallback or request manual
enrollment as a workaround. The supported recovery is:

```bash
devcoordinator runtime serve --help
devcoordinator runtime serve NAME \
  --cwd RELATIVE --port PORT --ttl-seconds N \
  --kill-after-run false --launch-timeout-seconds 30 -- \
  EXECUTABLE ARG...
```

The error envelope distinguishes the cases without inference:

| Evidence | What happened | Exact recovery |
| --- | --- | --- |
| Direct host bind failed; no Coordinator JSON/call-journal record | Coordinator was not invoked | Stop the direct launch and use `devcoordinator runtime serve --help`, then one structured serve call |
| `repository_unenrolled`, `broker_contacted=false`, `mutation_performed=false` | Read-only discovery or an unsupported existing-target action found a valid first-use root | Use `devcoordinator runtime serve --help`, then one structured serve call; no administrator enrollment or fallback change |
| Invalid serve shape, `broker_contacted=false`, `mutation_performed=false` | Client validation rejected the call before adoption | Run the returned `devcoordinator runtime serve --help`, correct the named field, and resubmit |
| Typed broker rejection, `broker_contacted=true`, `mutation_performed=false` | Broker received the request and changed nothing | Correct the typed cause. For `port_in_use`, keep the exact port, stop or wait for its owner, then submit a fresh operation |
| Typed broker rejection, `broker_contacted=true`, `mutation_performed=true` | A durable first-use adoption occurred before the later launch rejection | Do not re-enroll. Correct the typed launch cause and submit the stated fresh operation |
| Contact or mutation is `null`; operation handle returned | The reply cannot prove the mutation outcome | Run the exact returned `devcoordinator operation follow dc1:operation:…` command; do not create another operation |

Malformed serve calls name the rejected field and return a bounded corrective
action. Required fields are a lowercase service name, repository-relative
working directory, exact port 1–65535, positive TTL, explicit boolean cleanup
policy, readiness timeout 1–300 seconds, and non-shell argv after `--`.

The client generates a mutation UUID before repository discovery or transport
and records it at the caller boundary. The returned `dc1:operation:…`,
`dc1:plan:…`, `dc1:run:…`, and `dc1:artifact:…` values are typed references,
not credentials. When a caller supplies `--operation-id`, it must be the exact
canonical UUID and exact request replay. Generate no replacement UUID after an
uncertain outcome; use `operation follow` first.

## Result and input bounds

Bounds are UTF-8 bytes of compact JSON, including all required evidence:

| Surface | Hard result ceiling |
| --- | ---: |
| Absolute CLI safety envelope, including errors | 8 KiB |
| Capabilities result | 3 KiB |
| Capability document inside the capabilities result | 2 KiB |
| Target list/resolution | 2 KiB |
| Runtime status or ensure | 2 KiB |
| Authority operation-follow projection | 2 KiB |
| Complete client operation-follow result | 3 KiB |
| Test enqueue, submit, or follow | 4 KiB |

The six representative intent surfaces checked by the repository have a
combined worst-case ceiling of 18 KiB. The gate reports a clearly labelled
UTF-8 byte-derived token proxy (bytes divided by two through six); it does not
claim provider-native token measurement. Error messages and next commands are
each at most 512 bytes. Selectors and continuation identities are bounded, and
test follow returns at most three representative failures before declaring
truncation. MCP requests and complete responses are each at most 32 KiB because
tool output includes paired structured and compact text forms.

Measure the source contract, including fresh-interpreter import/help medians,
one-launcher command shapes, fixtures, headroom, aggregate bounds, and token
proxies with:

```bash
python3 scripts/check_agent_client_efficiency.py
python3 scripts/self_test_agent_client_efficiency.py
```

The default timing gates are medians of five fresh Python processes: at most
2,000 ms for `devcoordinator --help` and 500 ms for importing the package.
Operating-system page-cache state is unspecified, so these are regression
contracts rather than cold-cache latency claims.

## Typed outcomes

Success and failure are decision envelopes, not raw broker documents. A failure
identifies its code, classification, phase, whether the broker was contacted,
certainty, retryability, whether mutation is known to have occurred, and one
exact next command or corrective action. `broker_contacted: false` proves a
client-side rejection; `null` means transport could not prove whether the
authority received it. `mutation_performed: null` and an uncertain or
attention-required outcome mean the agent must retain the operation handle and
follow evidence; they never authorize a blind retry.

`runtime ensure` intentionally returns attention, without host mutation, for an
unclassified family or unknown/unhealthy target. It proves whether a mutation
was performed and which terminal observation established the result. Already
ready/stopped is a successful no-op.

Test manifest schema 3 makes retry policy explicit per target. Python may retry
only `lease_expired_before_launch`, with `max_attempts` from 1 through 4. A
single-attempt policy has no retry events. Assertions, ordinary test failures,
timeouts, and post-launch losses are not silently rerun under this policy.
Operation/run stores own durable replay and supersession where their protocol
supports it; the agent follows the returned handle rather than reconstructing
state.

## Independent failure intake and advisory test fallback

A typed Coordinator infrastructure or tool failure is reported before the
agent continues dependent work. Use the standalone launcher when Coordinator
services may be unavailable; `devcoordinator bug report ...` is the equivalent
integrated action, with the same `report`, `list`, and `close` contract:

```bash
devcoordinator-bug report \
  --component test-harness \
  --summary "governed tests failed before any measured attempt" \
  --expected "enqueue starts the selected governed targets" \
  --actual "infrastructure_failure: snapshot service unavailable" \
  --step "Run from the affected repository root." \
  --step "Invoke the command once and follow the returned run." \
  --command-arg=devcoordinator --command-arg=test \
  --command-arg=enqueue --command-arg=--intent --command-arg=change \
  --classification infrastructure_failure --stage launch \
  --call-id CALL_ID --operation-id OPERATION_ID --run-id RUN_ID
```

`component`, `summary`, `expected`, `actual`, and at least one ordered `step`
are required. Repeat `--command-arg=ARG` in exact argv order, using the equals
form when `ARG` begins with `-`. Supply every available `--call-id`,
`--operation-id`, `--run-id`, and `--attempt-id`; correlations are optional
because a pre-admission failure may not have one. Optional `--reporter`,
`--surface`, `--operation`, `--classification`, `--code`, `--stage`,
`--repository`, `--release-digest`, and `--instance-id` add bounded diagnostic
context. Reports exclude raw logs, environment dumps, credentials, and secrets.

Reports are cross-server reproduction packets. Assume the receiving server
does not have the source checkout: replace private repository roots with
`$REPOSITORY`, state prerequisites and tool versions explicitly, and make the
ordered steps and structured argv sufficient after an equivalent checkout is
provided. Never make a report depend only on a local `/tmp` file, private log,
task link, or agent memory. The Console transfer bundle retains the originating
server, original bug ID, and original fingerprint. An imported report stays
marked remote and remains distinct if the receiving server observes the same
failure locally.

The failure channel is deliberately independent: reporting, listing, and
closing load no repository enrollment, profile, broker, API, authority, testd,
or call journal. Do not auto-message another Codex task or infer a task from a
repository name. Return the report ID and a copyable user notice.

Codex filesystem sandboxes use the already-approved actual-caller/host
execution path for this installed launcher. An `EACCES` or `EROFS` mentioning
`/var/lib/devcoordinator-bugs` identifies the wrong execution context, not a
reason to redirect the shared registry: retry the identical structured command
as the actual caller without asking the user again.

Only typed Coordinator tool or infrastructure behavior belongs in this
registry. An invalid caller argument rejected before Coordinator contact, or a
direct sandbox bind/probe with no Coordinator result, is caller misuse—not
automatically a Coordinator bug. Correct those calls; do not convert a failed
direct probe into an infrastructure report.

```bash
devcoordinator-bug list --limit 20
devcoordinator-bug list --component test-harness --limit 20
devcoordinator-bug close BUG_ID
```

The registry is open-only. `list` returns bounded current records; `close`
physically removes the exact report, with no closed table, archive, or
tombstone. Re-reporting the same failure after close creates a new identity.

If the failure is in the governed test harness, it blocks shared evidence but
not ordinary source development. After reporting it, the agent may run static
checks and only repository-native test invocations that still collect at most
20 cases, enforce at most 10 seconds of execution, and need no shared or
host-visible state. It must not split a larger suite into repeated bounded
local commands. Every result is labelled exactly
`local/advisory — non-governed; not Coordinator evidence`; it is not ingested
into Coordinator statistics, cannot establish handoff or release readiness,
and must be followed by a governed rerun after repair. The report can record
this with `--local-fallback-status not_run|passed|failed|incomplete`, repeated
`--local-test-command-arg=ARG`, and `--local-fallback-summary TEXT`.

No local fallback may run tests or runtime work requiring host listeners,
Docker/Compose, databases, shared processes, or host mutation. Such work
remains Coordinator-owned. A measured assertion or ordinary test failure from
an actually launched governed attempt is a project bug, not a Coordinator bug;
report Coordinator only when its tool, admission, scheduling, launch,
collection, or evidence behavior failed.

This contract implements
[DC-2026-08-04-BUG-INTAKE-01](../../../DecisionDetails/DC-2026-08-04-BUG-INTAKE-01.md)
under the confirmed
[single-developer security assumptions](../../../security-assumptions.md), and
is the agent-facing prevention for `UIL-DOCUMENTATION-002` and
`UIL-TESTING-006`.

## Optional MCP stdio

`devcoordinator-mcp` is a dependency-free stdio adapter over the same current
contract. It accepts MCP protocol `2025-11-25` only and rejects every other
requested protocol version during initialization; it never negotiates or
downgrades to an older contract. Standard output contains only newline-delimited
JSON-RPC messages.

The path-free runtime/test tool set is:

- read-only: `capabilities`, `targets`, `runtime_status`, `operation_follow`,
  and `test_follow`;
- mutating: `runtime_ensure`, `test_enqueue`, and `test_submit`.

The independent failure-intake tool set is:

- `bug_report`, which validates and atomically creates or updates one bounded
  structured open report;
- `bug_list`, which reads bounded current open reports; and
- `bug_close`, which physically removes one exact report and is destructive.

These three tools use the same filesystem implementation as
`devcoordinator-bug report|list|close`. They run without repository context,
profiles, broker, API, authority, testd, or call-journal availability.

`runtime_ensure` advertises the MCP idempotent hint. Test enqueue/submit do not
advertise that hint because the semantic action creates workflow state, even
though an explicit operation UUID still enables exact transport replay.

Tool annotations advertise read-only, destructive, idempotent, and closed-world
hints, while the broker remains the mutation and lifecycle coordinator. The
server uses its process cwd for repository context, so start it in the intended
worktree for runtime/test calls; bug tools are context-independent. MCP bounded
waits are capped at 300 seconds. Tool results use the same compact decision
object as both structured content and a compact text value.

## Ownership boundary

Python owns deterministic mechanical work:

- repository-family context, target resolution, generation fencing, and exact
  immutable identities;
- runtime observation, prerequisite validation, desired-state action selection,
  no-op detection, convergence, terminal proof, and supported cleanup/recovery;
- test manifest decoding, prerequisite/policy plan selection, routine plan
  registration/submission, polling, summary/failure projection, safe retry,
  durable uncertain-launch reconciliation, and supersession where supported;
- the repository-owned `software_owned_delivery.py` verification, immutable
  package, deployment, acceptance, evidence, and concise-report workflow.

The agent or user retains choices that require meaning or authority: the desired
product/runtime outcome, material test targets and deadlines, whether an
attention result is safe to remediate, destructive removal or data work,
handoff/release plan review, and publication approval. More Python ownership
reduces repeated discovery and transcription; it does not erase those gates.

## Advanced current capabilities

The lower-level Python CLI and `devcoordinator-test` are separate current
interfaces for capabilities intentionally outside the routine parser/tool
catalog: a new definition, generation-checked replacement, bounded `run`,
staged removal, manifest init/validate/doctor, exact failure/artifact
drill-down, or an administrator migration/recovery transaction. The authority
capability document may advertise these operations without projecting them into
the routine client. A release/generation/broker-protocol mismatch must not be
bypassed through another interface.

For advanced tests, `test plan` derives the enrolled repository from its
explicit root/temporary-repository context. Every submit, status, summary,
failure, artifact, cancel, retry, and wait continuation requires
`--repository-id` in addition to its opaque plan/run/artifact ID. The returned
identity never selects or implies repository scope.

Never hand-build routine JSON, infer ownership from names/paths/ports, or copy
discovery/cleanup/retry loops into shell. Read the focused runtime or admin
reference only for the advanced operation at hand.
