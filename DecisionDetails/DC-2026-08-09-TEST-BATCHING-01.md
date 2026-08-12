# DC-2026-08-09-TEST-BATCHING-01 — Broad tests use one governed batch

## Context

The agent skill and repository guidance classified tests mainly by isolation
and evidence needs. That made a thousand-case unit suite eligible for direct
local execution even though the governed test plane already provides
asynchronous dependency waves, supported sharding, durable artifacts, and
bounded summaries. The result consumed avoidable execution time and model
context while remaining textually compliant with the old guidance.

## Decision

A direct local test invocation is eligible only when all of these conditions
are established before launch:

- an explicit selector collects no more than 20 cases;
- the runner enforces an execution deadline of no more than 10 seconds;
- the invocation needs no host-visible or shared runtime, listener, container,
  database, or process; and
- it is a focused feedback check, not one fragment of a broad suite divided
  across repeated local commands.

If either quantitative bound is unknown, collection would exceed 20 cases,
execution may exceed 10 seconds, the runner cannot enforce the deadline, or
durable evidence is required, the agent submits one policy-derived Coordinator
batch and follows its run handle. Unit-test isolation does not establish local
eligibility. Static analysis and formatting remain local and are not test
cases.

When the test harness is unavailable, the agent first records the Coordinator
failure and may continue only static checks and test invocations that satisfy
the same local bounds. It does not split a larger suite into many locally
eligible fragments. A repository without a valid `.codex/tests.json` may run a
bounded focused subset, but broad execution remains a manifest setup gap rather
than an authorized local bypass.

## Alternatives considered

- Keep isolation as the boundary: simple, but permits arbitrarily large local
  unit suites and does not achieve the intended batching or context savings.
- Use only the 10-second deadline: misses very large fast suites and their
  output/context cost.
- Use only the 20-case limit: permits a small set of unusually slow tests to
  occupy the local agent for too long.
- Route every test through Coordinator: maximizes uniform evidence but adds
  avoidable latency to one-test development feedback.
- Add a second batch executor: duplicates the existing plan, enqueue, shard,
  follow, and bounded-summary authority without improving the routing rule.

## Verification

Static documentation contracts require the numerical bounds, unknown-scope
routing, one-batch rule, no split-local workaround, and bounded outage fallback
across the canonical skill, agent-client reference, repository guidance,
README, and agent metadata. Forward cases distinguish one explicit fast test
from 21 collected cases, an 11-second test, unknown scope, and a thousand-case
suite. The existing governed test plane remains the execution authority; no new
test executor is introduced by this decision.
