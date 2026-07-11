# Holy Skills

Holy Skills is a local curation and development repository for agent skills.
The skills were originally built for Codex and remain Codex-compatible; they
are also installable into Claude Code. This repo holds reusable skills while
they are being designed, tested, reviewed, and prepared for installation into
a Codex or Claude Code skills directory.

## Layout

- `skills/`: source-controlled skill directories.
- `SKILL_AUDIT.md`: honest capability, improvement, and residual-boundary
  review for every canonical skill plus the pre-repair installation topology.
- `skills/codex-dev-coordinator/`: a local single-machine coordinator for
  leasing ports, managing attributed development processes and Docker
  resources, checking health, and exposing a protected local CLI/API boundary.
- `skills/formal-web-ui-verification/`: a deterministic browser-side heuristic
  verifier that injects JavaScript through Playwright to catch
  clipped text, hidden controls, overlap, off-canvas elements, broken media,
  invisible text, horizontal overflow, and visible scrollbars across desktop
  and mobile web routes.
- `skills/full-repo-audit/`: a manifest/batch/evidence framework for manual
  repository-wide source, architecture, journey, interface, and test review.
- `skills/full-repo-test-coverage-audit/`: a source-to-test traceability audit
  that distinguishes empirical coverage evidence from structural/manual review.
- `skills/postgres-docker-backup/`: a local Docker PostgreSQL logical backup,
  manifest, verification, and safety-gated restore tool; it is not encrypted,
  off-site, continuous, or point-in-time backup.
- `skills/trace-fix-root-causes/`: a prevention-first incident workflow and
  structured report verifier for implementation, factual, reasoning, tool,
  artifact, service, regression, and audit misses.
- `skills/ui-implementation-audit/`: a UI implementation audit skill that
  batches only interface source files while comparing rendered desktop/mobile
  UI against mockups, visual assets, complete UI element requirements, and user
  journey requirements.
- `skills/user-journey-docs-audit/`: a lexical/structural product-documentation
  inventory and report gate that actively interviews the user and checks whether docs describe the
  app idea, users, journeys, feature set, UI element set, implementation
  expectations, tests, edge cases, and usability acceptance criteria well enough
  to build excellent apps.
- `full_repo_harness/`: shared Python harness code for repository discovery,
  batching, manifests, queue markers, and verifier helpers used by audit
  skills.
- `apps/DevOpsBoard/`: a native macOS SwiftUI utility (formerly Codex Ops
  Console) for viewing and managing coordinator inventory, dev-server URLs,
  Docker containers, database backups, leases, retained action outcomes, and
  recent service events, with provenance-bound native evidence tooling.
- `apps/DevOpsConsole/`: a zero-dependency Node 20 web control center for the
  `vr.ae` VPS that terminates TLS for `*.vr.ae` (80→443 redirect), reverse-
  proxies `<slug>.vr.ae` to local dev-server ports (WebSocket/HMR included)
  behind Google sign-in with a per-route public/login toggle, and drives the
  coordinator HTTP API on loopback as its control engine.
- `scripts/validate.py`: repo-level validation for all skills, the shared
  harness, vendored fallback copies, standalone skill-copy execution, artifact
  and provenance checks, and, in full mode, DevOps Board native validation.

Each skill directory should keep its own `SKILL.md`, README, scripts, agents,
fixtures, and tests together so the skill can be reviewed or installed as a
self-contained unit.

## Deployment Notes

This repository is the only writable source for its eight skills. Install them
as direct links into every runtime home; never hand-edit an installed path.
First discover every runtime's actual config/skills directory, convert it to an
absolute path, and inspect all intended roots. Do not derive host and desktop
roots from the executing shell's `$HOME`: sandboxed desktop runtimes can report
a different home. `CLAUDE_CONFIG_DIR`, when configured, identifies Claude's
config root, but pass its resolved `skills` path explicitly to the manager.

```bash
REPO_ROOT="/absolute/path/to/holyskills"
CODEX_SKILLS_ROOT="/absolute/path/to/host-codex-home/skills"
CLAUDE_SKILLS_ROOT="/absolute/path/to/claude-config/skills"
PARALL_SKILLS_ROOT="/absolute/path/to/desktop-codex-home/skills"
python3 scripts/manage_skill_links.py plan \
  --repo-root "$REPO_ROOT" \
  --target-root "$CODEX_SKILLS_ROOT" \
  --target-root "$CLAUDE_SKILLS_ROOT" \
  --target-root "$PARALL_SKILLS_ROOT"
```

After reviewing divergent paths and preserving any unique changes in the repo,
apply with a new absolute transaction directory. `--allow-noncanonical` is
required when replacing divergent copies, broken/chained links, or unexpected
filesystem objects; a byte-for-byte copied match does not require it. Mutating
invocations serialize all named roots in deterministic order and replan only
after those locks are held. The transaction directory and every named target
root must be on the same filesystem so preserved objects can move atomically;
use one retained transaction per filesystem when runtime roots live on separate
volumes:

```bash
install -d -m 700 "$HOME/.local/state/holyskills/backups"
python3 scripts/manage_skill_links.py apply \
  --repo-root "$REPO_ROOT" \
  --target-root "$CODEX_SKILLS_ROOT" \
  --target-root "$CLAUDE_SKILLS_ROOT" \
  --target-root "$PARALL_SKILLS_ROOT" \
  --transaction-dir "$HOME/.local/state/holyskills/backups/$(date +%Y%m%d-%H%M%S)" \
  --allow-noncanonical
```

Codex sessions load skill metadata at startup. After installing or updating a
skill, fully restart the Codex app/session that should see it. For Parallels,
Parall, VMs, or multiple OS users, verify the target app's `$HOME` and
`$CODEX_HOME`; installing into the host account's `~/.codex/skills` does
not make the skill available inside a separate guest, sandbox, or account unless
that environment points to the same Codex home.

Run `manage_skill_links.py verify` with the same roots after migration and
restart Codex, Claude, and Parall because skill metadata is loaded at session
startup. Retain the transaction directory until fresh-session discovery and
the complete repository validation pass.

```bash
python3 scripts/manage_skill_links.py verify \
  --repo-root "$REPO_ROOT" \
  --target-root "$CODEX_SKILLS_ROOT" \
  --target-root "$CLAUDE_SKILLS_ROOT" \
  --target-root "$PARALL_SKILLS_ROOT"
```

Transaction journals and preserved pre-migration objects contain absolute
local paths and possibly divergent private source. Keep them mode-private and
outside the repository; they are rollback evidence, not publishable artifacts.
The installed links are absolute by design, so moving the canonical repository
requires a new reviewed link transaction.

Global (all-project) agent policy is maintained per runtime:
`~/.codex/AGENTS.md` for Codex (mirrored read-only at
`reference/codex-app-wide/AGENTS.md`) and `~/.claude/CLAUDE.md` for Claude
Code. When a generalized rule changes, port the applicable rule into both
runtimes and the curated public reference; runtime-specific instructions may
remain different.

The coordinator default is relative to the current process's resolved home, so
it is shared only when the runtimes execute as the same OS user with the same
home. Sandboxed desktop runtimes can have a separate coordinator home. Compare
the `coordinator_home` field returned by `inventory` in each runtime before
assuming shared state. To deliberately share state between runtimes of one OS
user, set the same absolute `CODEX_AGENT_COORDINATOR_HOME` in every runtime.
DevOps Board can also aggregate explicitly configured separate homes and
routes mutations through the resource's owning source.

## Local Service Policy

Agents must use `codex-dev-coordinator` before starting, stopping, restarting,
or replacing local dev/test servers, Docker services, Docker containers, or
database stacks. The first command should be:

```bash
PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
python3 skills/codex-dev-coordinator/scripts/dev_coordinator.py \
  inventory --project "$PROJECT_ROOT"
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

Agents can run the complete non-macOS portion of the repository gate without
invoking native tooling:

```bash
python3 scripts/validate.py --skip-macos-app
```

This mode runs the snapshot verifier's recall tests and structural pixel and
geometry checks, but explicitly skips canonical renderer-source freshness
because it cannot regenerate the native images. A passing non-macOS gate must
not be described as proof that the committed PNGs depict the current SwiftUI
source.

The full gate also builds and tests DevOps Board, compiles its native
geometry/menu snapshot targets, requires canonical provenance to bind the exact
current renderer inputs, verifies the artifacts, and exercises packaging.
Agents must run that native portion through the Build macOS Apps plugin; they
must not substitute direct Swift/Xcode commands or desktop control. If the
plugin is unavailable, report native validation and current-source snapshot
regeneration as pending rather than implying that the non-macOS gate covered
them.

The root `full_repo_harness/` package is the canonical shared source. Each
skill also carries a vendored fallback copy under `scripts/_vendor/` so a single
skill directory can still be copied and self-tested on its own; the validation
script fails if those copies drift.

This repository is public, so avoid committing private workspace paths,
secrets, customer data, or generated artifacts that include sensitive source
content.
