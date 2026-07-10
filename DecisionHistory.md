# Decision History

## 2026-07-10 - GUI runtime actions preflight dependencies and bind delivered binaries

Decision: Codex Ops Console constructs one deterministic subprocess environment
from inherited absolute PATH entries plus `/etc/paths` and `/etc/paths.d`.
Docker-backed project mutations require Docker capability, always refresh after
success or failure, and retain structured preflight/partial evidence. The
coordinator independently resolves Docker through an explicit absolute override,
PATH, and standard macOS locations while preserving the discovered `docker`
entry-point path (multicall tools such as OrbStack select behavior from
`argv[0]`); it bounds Docker calls, preflights the CLI, daemon, and Compose
plugin before touching managed processes, parses Compose global flags correctly,
and gives Compose sole lifecycle ownership when a dependency maps to a declared
service.

Why: the launchd Board process inherited only
`/usr/bin:/bin:/usr/sbin:/sbin`, while OrbStack exposed Docker under
`/usr/local/bin`. A benzovozka project stop therefore stopped four workers before
the first bare `docker` call raised `ENOENT`; the Board then kept stale inventory.
The running Board was also an older bare SwiftPM process, and packaging did not
bind executable bytes to the Swift inputs that produced them.

Result: realistic minimal-PATH, multicall-symlink, zero-mutation preflight,
partial-result, Compose-option/ownership/restart, timeout, and false-positive
fixtures protect the coordinator contract. Board source has injectable
PATH/capability/refresh regressions. Packaging records exact production
Swift/manifest hashes and the executable hash, rejects unprovenanced
`--skip-build`, and has a Python-only stale/tamper suite in the non-native
validation gate. The user explicitly requires Build macOS Apps for compilation,
XCTest, packaging, launch, and native acceptance; replacing the still-running
bare process remains pending until that plugin is exposed.

## 2026-07-10 - Canonical direct-link skill installation

Decision: This repository is the only writable source for its eight skills.
Codex, Claude, and desktop Codex runtimes install each repo-owned skill as a
direct absolute symlink to `skills/<name>`. Installation changes go through the
transactional `scripts/manage_skill_links.py` plan/apply/verify/rollback
workflow, which locks every explicit root, preserves replaced objects, records
private rollback evidence, and refuses unreviewed divergence.

Why: The previous topology used copied Codex and Claude directories, while the
desktop runtime linked to the Codex copies. Installed copies were edited after
deployment, including `trace-fix-root-causes`, so repo changes and runtime
behavior could move independently and a chained desktop link amplified that
drift.

Result: The historical 2026-07-02 “Known drift” note below is superseded. On
2026-07-10 the 16 divergent directories and eight chained links were preserved
under the private transaction
`$HOME/.local/state/holyskills/backups/20260710-182238`, replaced, and verified
as 24 direct links to this repository. The transaction remains retained until
fresh Codex, Claude, and desktop sessions reload their startup metadata. Links
are absolute and must be reinstalled if the repository moves; roots on separate
filesystems require separate transactions.

## 2026-07-10 - Truthful, fail-closed skill and Board contracts

Decision: The eight skills expose only claims their implementations and
deterministic evidence can support. Detector-style skills must bind real
evidence and prove realistic recall plus intentional-pattern precision. The
coordinator uses private atomic state, structured commands, short reservation/
commit locks, attributed operations, exact manual-lease attachment, immutable
Docker identity, and a protected IPv4-loopback API. PostgreSQL protection binds
live work to immutable container identity, separates database and cluster
scope, strongly verifies scratch restores, and refuses unsafe cluster restore.
Codex Ops Console preserves source identity, partial capability truth, retained
action evidence, exact port-lease values, and strong database evidence instead
of inventing status or treating a failed optional integration as total source
failure.

Why: The repo-wide audit found several contracts that were stronger than their
deterministic proof, security/concurrency gaps at local control boundaries, and
Board state that could lose provenance or block unrelated actions. Those gaps
could make a passing self-test or green UI imply guarantees the user did not
actually have.

Result: Safe Python/static validation passes for the link manager, public
artifact guard, snapshot-verifier self-tests, audit, coverage, journey, trace,
and PostgreSQL suites, standalone skill copies, vendored harnesses, syntax
checks, and Board static guardrails. The four canonical PNGs pass pixel and
geometry checks only when source freshness is explicitly skipped;
current-source canonical verification remains pending native regeneration.
Coordinator process/API and standalone suites also pass in isolated temporary
homes.
Environment-dependent native Board verification remains separate and pending
the required Build macOS Apps workflow; the non-native results do not claim to
cover it.

## 2026-07-10 - Approved Board hierarchy and structured exact-lease starts

Decision: The user approved the ImageGen Board review on 2026-07-10, authorizing
the confirmed SwiftUI hierarchy: compact source health, dominant resource
inventory, retained typed results, focused lease/database safety flows,
explicit bulk selection, and secondary source configuration. Starting a server
from an existing port lease now accepts a typed executable plus argument list,
JSON-encodes that vector, and sends it to the coordinator with `--argv` and the
exact `--lease-id`. It must never combine exact-lease start with `--cmd` or ask
the user to edit a raw command payload.

Why: The coordinator deliberately rejects `server start --lease-id` with
`--cmd`; the previous Board path therefore exposed a start action that could not
succeed. Structured argv also preserves spaces and quotes as argument
boundaries without shell interpretation. The approved hierarchy removes
overexposed global/destructive controls and keeps source ownership and real
operation evidence adjacent to the affected resource.

Result: The approved Board and menu-bar source implementation is present, and
the static interaction gate checks the structured exact-lease path and approved
surface contracts. Swift compilation, XCTest, native rendering, accessibility,
packaging, and launch evidence are not claimed for this source until the Build
macOS Apps workflow is available.

## 2026-07-10 - Production-view, source-bound snapshot evidence

Decision: Native snapshot tools render the production `BoardView` and
`MenuBarRuntimeView` with deterministic fixture inventory and live loading
disabled. Each canonical sidecar must name the exact portable renderer inputs
and bind their current bytes through `source_files` and `source_sha256`, in
addition to binding the PNG bytes, dimensions, fixture, and generator.

Why: A separate menu snapshot shell could drift from the product view, while
PNG hashes and dimensions alone could let an old image keep passing after the
SwiftUI source changed. A current visual claim requires both real production
view rendering and evidence that the image came from the current renderer
inputs.

Result: The verifier now has realistic must-catch coverage for a UI source edit
and missing source provenance, plus a current-source passing control. The four
committed PNGs still pass structural pixel/geometry checks, but their existing
sidecars lack the new source binding and the default verifier rejects all four.
They must be regenerated through Build macOS Apps before they can be claimed as
current redesign evidence.

## 2026-07-10 - Attributed lease lifecycle and target-wide action isolation

Decision: Board lease release sends the coordinator's required acting agent and
exact lease project, and direct Start/Release controls are available only for
active, unbound manual leases with the ownership fields required by the chosen
operation. Inventory models retain `server_id` and pending attachment state.
Project-scoped inventory absence is not treated as release evidence for a lease
owned by another project. Running actions conflict by stable target domains,
including cross-kind server lifecycle operations and database/container
operations, rather than only by identical action names.

Why: A static recheck reproduced that the Board's old Release call was rejected
by the coordinator because it omitted `--agent` and `--project`; its unit test
had encoded the malformed call. The same review found that dropping attachment
metadata could expose guaranteed-failing Start and unsafe Release actions, a
scope change could fabricate a Released state, and Stop/Restart or
backup/restore/container actions could overlap on one real target. Those are
safety and truthfulness failures, not presentation details.

Result: The release contract, lease lifecycle fields, scope-aware reconciliation,
source provenance, issue/result association, stable source identity, and
target-conflict rules now have static guard requirements and focused XCTest
regressions. The malformed CLI path was reproduced with exit 2 before the fix.
The XCTest/native execution of these regressions remains pending Build macOS
Apps; the non-native gate checks that the guard and test source stay present.

## 2026-07-10 - Build macOS Apps is mandatory for native validation

Decision: At the user's direction, coding agents must use the Build macOS Apps
plugin for Swift/macOS build, test, packaging, launch, debugging, snapshots,
and native UI automation. Agents must not take over the user's desktop or
substitute direct Swift/Xcode, `open`, XCUI, mouse, or keyboard control. If the
plugin is unavailable, native validation stays explicitly pending. A user-
confirmed ImageGen mockup is also required before consequential Board view
changes.

Why: Native validation should use the purpose-built workflow and must not
interfere with the user's computer. Separating the native gate also prevents a
partial static/non-Swift pass from being reported as a compiled, tested, or
run macOS app.

Result: The rule is recorded in active Codex and Claude policy, the curated
app-wide reference, this repo policy, Board documentation, and the repository
validation instructions. `scripts/validate.py --skip-macos-app` provides an
honest non-native gate; the complete gate remains reserved for Build macOS Apps.
The user subsequently approved the ImageGen Board review, so source
implementation proceeded while native validation and canonical regeneration
remained pending the unavailable plugin.

## 2026-07-03 - Functional hardening pass across all skills

Decision: A functional-only audit (security excluded per user) drove concrete
improvements. Landed: the interaction 10-label "hard reporting gate" is now
enforced by code (a shared `verify_common.interaction_checklist_missing` used by
the full-repo-audit and ui-implementation-audit verifiers) rather than SKILL.md
prose, and the ui-implementation SKILL Final Output list was reconciled from 6
labels back to the canonical 10. A new shared `full_repo_harness/merge_findings.py`
consolidates/ranks findings across hundreds of batch reports (wired into all
three audit skills' synthesis step). The coordinator gained health retry/backoff,
a `starting` vs `unhealthy` grace classification, bounded stopped-server
retention, and corrupt-state recovery (no more `SystemExit` on read). A
concurrency stress self-test now proves no double-lease. formal-web-ui added a
full-page scroll pass, `unmeasurable` contrast handling for gradient/image
backgrounds, shadow-DOM/iframe not-inspected reporting, and natural-position
occlusion. postgres-docker-backup added `verify --test-restore` (restore into a
throwaway scratch DB with guaranteed cleanup). The root-cause verifier now
recognizes `~/.claude/CLAUDE.md` as a valid global policy target (dual-runtime
parity), and journey-doc discovery covers `.rst`/`.adoc` and code-comment
journeys. CI (`.github/workflows/validate.yml`) now runs `scripts/validate.py`,
and validate.py gained a label-parity guard.

Why: The prior audit found the deterministic gates had honor-system joints
(the label gate was prose-only), synthesis did not scale, and several verifiers
produced false gates or crashed on edge states.

Result: `scripts/validate.py` passes end to end. Two audit claims were checked
against the code and found FALSE, so no change was made: the coordinator
port-lease is already serialized under `locked_state()` (no double-lease TOCTOU),
and source-backed audit checks already hard-fail (`source_text_errors` /
`verification_warnings` already force `ok=False`; SHA re-hash is on by default).
Excerpt-proof for non-interface files was descoped as disproportionate risk to
the 3.7k-line fixture suite; interface files already require real source quotes.

## 2026-07-02 - Dual-runtime skills and mirrored global policy (Codex + Claude Code)

Decision: Holy Skills now targets both Codex and Claude Code. Skill contracts
were made runtime-neutral (descriptions and actor wording say "agent (Codex,
Claude Code)"; `trace-fix-root-causes` names both global policy files;
`user-journey-docs-audit` maps `request_user_input` to `AskUserQuestion`).
All eight skills install into `~/.claude/skills/` in addition to
`~/.codex/skills/`, and global agent policy is maintained as a mirrored pair:
`~/.codex/AGENTS.md` (Codex) and `~/.claude/CLAUDE.md` (Claude Code). A repo
`CLAUDE.md` imports `AGENTS.md` so both runtimes read one repo policy.

Why: The same machine runs both agent runtimes against the same projects,
dev servers, Docker containers, and databases. Coordination only works if both
runtimes follow the same policies and share one coordinator state
(`~/.codex/agent-coordinator/`), and skill descriptions must trigger in both
apps.

Result: `scripts/validate.py` passes after the curation; all eight skills pass
self-tests from `~/.claude/skills/`; the installed coordinator reads the
shared machine-wide inventory. The `server_health` early-return fix for dead
PIDs (previously hand-applied only in `~/.codex/skills/`) was backported into
the repo. Known drift: `~/.codex/skills/trace-fix-root-causes/` carries a
later hand-edited revision (SKILL.md, README, openai.yaml, self_test,
verifier) that was never backported here, and `~/.codex/skills/`
`ui-implementation-audit` + `full-repo-audit` are stale deployments of commit
13b4f1e — reconcile and redeploy both directions.

## 2026-07-02 - Coordinator project resource telemetry

Decision: The Codex dev coordinator inventory emits real per-server process-tree CPU/RSS telemetry and project-level resource rollups, and CodexOpsConsole displays those rollups by repo.

Why: Managed dev servers often launch child processes that own the actual listener and resource usage. A launcher PID alone can hide runaway Next/Vite/node child processes, especially across multiple Codex/Parall coordinator homes.

Result: Inventory now includes `process_usage` per server and `project_usage` per repo. The console discovers coordinator homes, merges read-only inventory, shows project load, and flags high-load projects in the status bar.

## 2026-07-02 - Formal Web UI DOM verification

Decision: Holy Skills now includes `formal-web-ui-verification`, a Playwright-driven skill that injects deterministic JavaScript into rendered web pages to measure DOM geometry, computed styles, text fit, occlusion, media health, area-of-interest boundaries, document overflow, and visible scrollbars.

Why: UI implementation and audit workflows were still able to miss software-detectable defects such as cropped text, hidden controls, unintended overlap, off-canvas interactive elements, broken media, and invisible text. Screenshot review remains useful, but these failure classes need formal browser-side measurements that can fail delivery gates without relying on model vision.

Result: The verifier defaults to critical-only failure for low-noise delivery checks and warning-level reporting for softer risks. It supports explicit route configs, coordinator current-URL smoke checks, AOI/ignore/allow attributes, JSON/Markdown reports, and mandatory visible scrollbar inventory. Existing UI audit prompts now require the verifier whenever a safe web render path exists, and the app-wide Codex instructions require formal web UI verification after material web UI changes.

## 2026-07-03 - Formal web UI verifier recall rework

Decision: Reworked `formal-web-ui-verification` detection so it measures how real applications break, and made recall (must-catch fixtures) a permanent part of its self-test: text candidates now include any element that directly owns rendered text (div-based layouts), clipping detection covers ancestor `overflow` cuts (absolute children, negative offsets, nowrap spill) with containing-block and scroll-path awareness, occlusion reports partial coverage (≥60% critical, ≥2 points warning), broken media checks include images collapsed to ~0x0, complex-artifact exclusion is token-bounded (a `roadmap`/`sitemap` class no longer disables checks), and off-canvas rules cover left/top document-edge cuts and fixed-position viewport cuts. Intentional patterns stay non-critical: own/parent single-line ellipsis, line-clamp, carousel-context cuts, fully hidden closed-state content, skip links, app-shell inner scrollers. Coverage inventories (ellipsis truncations, hidden text-like counts, pending media, per-rule finding caps with a `findings-truncated` marker) keep gaps visible.

Why: User reported the skill "doesn't report problems now in most of the cases". Reproduction confirmed it: 10 of 11 realistic defect fixtures (div text cut by a parent card, absolutely positioned button cut by an overflow-hidden panel, negative-margin top cut, 60% badge/label overlap, collapsed broken image, invisible text in a `roadmap-section` and in a plain div, half-off-canvas button, fixed toolbar cut below the viewport, nowrap div text spilling into a clipping parent) produced zero findings, while only the synthetic self-overflow case was caught. Root cause: detection rules and self-test fixtures both mirrored the implementation (self-overflow on a fixed tag list, all-sample-points occlusion, substring artifact exclusion), so the self-test proved precision only and gave false confidence — a recall gap, not a regression from one bad edit.

Result: All 11 realistic defect fixtures now produce criticals; the prior contract fixtures still pass; the extended self-test fails against the pre-fix verifier at the first new fixture (fail-before/pass-after proven). Noise checks stay clean: a composite modern page (sticky header, ellipsis card titles inside overflow-hidden cards, line-clamp, scrollable table, FAB, sr-only link) yields zero findings at mobile and desktop — this page also caught and now guards a false positive where an element's own ellipsis was re-tested against its parent's clip — and real pages (example.com, news.ycombinator.com) yield zero criticals with plausible warnings only. `scripts/validate.py` passes. Guardrails updated: repo `AGENTS.md` skill-development recall rule, and the generalized detector-recall rule in `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`, and the curated mirror `reference/codex-app-wide/AGENTS.md`.
