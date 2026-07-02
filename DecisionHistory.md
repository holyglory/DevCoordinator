# Decision History

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
