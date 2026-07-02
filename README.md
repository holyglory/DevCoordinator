# Holy Skills

Holy Skills is a local curation and development repository for Codex skills.
It is meant to hold reusable skills while they are being designed, tested,
reviewed, and prepared for installation into a Codex skills directory.

## Layout

- `skills/`: source-controlled skill directories.
- `skills/codex-dev-coordinator/`: a shared coordinator skill for leasing
  ports, starting/stopping/restarting dev servers, checking health, and routing
  Docker/Docker Compose commands through one local CLI or HTTP endpoint.
- `skills/formal-web-ui-verification/`: a browser-side formal UI verification
  skill that injects deterministic JavaScript through Playwright to catch
  clipped text, hidden controls, overlap, off-canvas elements, broken media,
  invisible text, horizontal overflow, and visible scrollbars across desktop
  and mobile web routes.
- `skills/full-repo-audit/`: a repository-wide audit skill for source,
  architecture, user journeys, UI elements, intended features, and tests.
- `skills/full-repo-test-coverage-audit/`: a repository-wide test coverage
  audit skill that reports missing unit, integration, UI journey, visual,
  feature, edge-case, and failure-path coverage.
- `skills/postgres-docker-backup/`: a Docker Postgres safety skill for
  discovering running Postgres containers, creating verified backups, writing
  manifests, and restoring with confirmation plus a default pre-restore backup.
- `skills/trace-fix-root-causes/`: a prevention skill for tracing recently
  fixed bugs, UI flaws, regressions, and audit misses back to their creation
  path, then recommending workflow guardrails.
- `skills/ui-implementation-audit/`: a UI implementation audit skill that
  batches only interface source files while comparing rendered desktop/mobile
  UI against mockups, visual assets, complete UI element requirements, and user
  journey requirements.
- `skills/user-journey-docs-audit/`: a product documentation audit skill that
  actively interviews the user and checks whether Markdown/docs describe the
  app idea, users, journeys, feature set, UI element set, implementation
  expectations, tests, edge cases, and usability acceptance criteria well enough
  to build excellent apps.
- `full_repo_harness/`: shared Python harness code for repository discovery,
  batching, manifests, queue markers, and verifier helpers used by audit
  skills.
- `apps/CodexOpsConsole/`: a native macOS SwiftUI utility for viewing and
  managing coordinator inventory, dev-server URLs, Docker containers, database
  backups, leases, and recent service events.
- `scripts/validate.py`: repo-level validation for all skills, the shared
  harness, vendored fallback copies, standalone skill-copy execution, and the
  Codex Ops Console Swift build.

Each skill directory should keep its own `SKILL.md`, README, scripts, agents,
fixtures, and tests together so the skill can be reviewed or installed as a
self-contained unit.

## Deployment Notes

Deploy skills into the Codex home used by the specific app/account that needs
them:

```bash
CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
rsync -a --delete skills/codex-dev-coordinator/ "$CODEX_HOME/skills/codex-dev-coordinator/"
rsync -a --delete skills/formal-web-ui-verification/ "$CODEX_HOME/skills/formal-web-ui-verification/"
```

Codex sessions load skill metadata at startup. After installing or updating a
skill, fully restart the Codex app/session that should see it. For Parallels,
Parall, VMs, or multiple OS users, verify the target app's `$HOME` and
`$CODEX_HOME`; installing into `/Users/holyglory/.codex/skills` on the host does
not make the skill available inside a separate guest, sandbox, or account unless
that environment points to the same Codex home.

## Local Service Policy

Agents must use `codex-dev-coordinator` before starting, stopping, restarting,
or replacing local dev/test servers, Docker services, Docker containers, or
database stacks. The first command should be:

```bash
python3 scripts/dev_coordinator.py inventory --project "$PWD"
```

Do not start on default ports and then hunt for another port after a collision.
Lease ports or manage servers through the coordinator. Before destructive
PostgreSQL-in-Docker work, use `postgres-docker-backup` to create and verify a
backup.

## Development Notes

When changing a skill:

1. Reproduce the issue or behavior you are changing before editing it.
2. Keep the skill contract in `SKILL.md` authoritative.
3. Test the changed path the same way it was reproduced.
4. Keep generated audit outputs, temporary runs, and local caches out of git.

Run the validation gate before committing public skill changes:

```bash
python3 scripts/validate.py
```

The root `full_repo_harness/` package is the canonical shared source. Each
skill also carries a vendored fallback copy under `scripts/_vendor/` so a single
skill directory can still be copied and self-tested on its own; the validation
script fails if those copies drift.

This repository is public, so avoid committing private workspace paths,
secrets, customer data, or generated artifacts that include sensitive source
content.
