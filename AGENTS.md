# Global Agent Instructions

## Codex Implementation Mistake Protocol

When the user reports an implementation mistake likely made by Codex, handle it
as a prevention-first incident unless the evidence shows the user changed their
mind or the requested behavior changed after implementation.

1. Reproduce the reported error through the same surface the user saw whenever
   it is possible and reasonable. If it cannot be reproduced, record why and
   gather the closest concrete evidence available.
2. Check whether the failure is actually a changed requirement. Compare the
   original request, later clarifications, accepted plans, project docs, and
   delivered behavior before treating it as a Codex mistake.
3. If the request was not changed, trace why the mistake happened before
   changing product code. Inspect the user intent, how Codex perceived the
   request, requirements, journey docs, design handoff, implementation, tests,
   verifier rules, audit outputs, tool choices, policies, skills, context, and
   handoff assumptions.
4. Identify the nearest durable guardrail that allowed the mistake: local
   `AGENTS.md`, project documentation, acceptance criteria, tests, verifier,
   skill instructions, checklist, policy, or context source.
5. Fix that system guardrail first when practical. If a skill or audit missed
   the issue, update the skill or deterministic check and rerun it against the
   same evidence so it now catches the gap.
6. Audit the testing procedure that failed to catch the mistake. Look for other
   likely missed failures in adjacent journeys, edge cases, failure paths,
   integrations, generated artifacts, and user-visible acceptance criteria.
   Add or update tests for those risks, not only the one reported symptom.
7. Close the implementation gap only after the prevention layer is patched, or
   explicitly explain why the product fix had to be done first.
8. After the detected gap is closed, run comprehensive tests that prove the
   user gets the expected result. Include the original reproduction path, the
   new or updated guardrail/check, and the broader tests from the testing
   procedure audit before reporting done.

Keep one-off local mistakes separate from broad process changes, but bias
toward durable prevention when the same class of mistake could recur.

## Skill Development

- Before fixing errors, reproduce the issue or policy gap you are changing.
- Keep each skill's `SKILL.md` contract authoritative and mirror enforceable
  behavior in deterministic self-tests where possible.
- Test the changed path the same way it was reproduced.
- When a test or verifier missed a user-visible mistake, audit neighboring
  testing gaps and add comprehensive post-fix coverage before delivery.
- Never deliver static mocks, fake plumbing, no-op UI, synthetic data flows, or
  "wired later" implementations as completed work.

## Local Services, Docker, And Databases

- Before starting, stopping, restarting, or replacing any dev/test server,
  Docker Compose service, Docker container, or local database stack, use
  `$codex-dev-coordinator` and run its `inventory --project "$PWD"` command.
- Do not start services on default ports directly. Do not follow the pattern
  "try the default port, then try another one if busy." Lease ports or manage
  servers through the coordinator.
- Reuse a healthy coordinator-managed URL when it matches the task instead of
  launching a duplicate server.
- Before destructive PostgreSQL-in-Docker operations such as migrations, resets,
  imports, seed rewrites, `DROP`, or `TRUNCATE`, use `$postgres-docker-backup`
  to create and verify a backup.
