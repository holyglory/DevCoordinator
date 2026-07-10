# Holy Skills Audit

Date: 2026-07-10

This audit covers every canonical skill under `skills/`. Descriptions below
state what the implementation and deterministic checks actually establish, not
what a skill name might imply. Passing a skill self-test proves its advertised
fixture classes and safety invariants; it does not prove that every future
repository, interface, incident, or environment will be understood correctly.

## Installation topology finding

The repository contains eight canonical skill directories. Before repair, the
Codex and Claude installations were real copied directories rather than links
(16 divergent directories total), while the desktop runtime's eight entries
were links to the Codex copies rather than direct links to this repository.
That topology explains why `trace-fix-root-causes` differed: changes had been
made in an installed copy, the repository was not updated at the same time, and
the desktop runtime followed the installed copy. It also meant a later repo
change could not update any runtime automatically.

`scripts/manage_skill_links.py` is now the only supported installation path. It
plans and verifies every explicit runtime root, refuses divergent/copy/broken/
chained paths without reviewed acceptance, installs exact absolute links to
`skills/<name>`, preserves every replaced object in a private transaction, and
can roll the whole transaction back. Unrelated third-party skills are outside
its managed set.

Repair result: the eight Codex entries, eight Claude entries, and eight desktop
Codex entries were migrated and verified as 24 direct canonical links. The 24
pre-repair objects remain in one private rollback transaction until fresh
sessions reload their skill metadata and the native validation gate completes.

Operational boundaries: the manager intentionally does not auto-discover
runtime homes; every absolute target root must be confirmed by the operator.
Absolute links must be reinstalled if this repository moves. Atomic preserved-
object moves require the transaction directory and named roots to share a
filesystem, so roots on separate volumes require separate transactions.

## Skill-by-skill findings

### `codex-dev-coordinator`

Honest description: a local, single-machine coordinator for attributed port
leases, managed development processes, declared project runtime actions,
Docker lifecycle commands, inventory, health evidence, and a loopback bearer-
authenticated HTTP API. It is not a remote orchestrator, container scheduler,
or production service manager.

Improvements made in this pass:

- removed shell execution and added structured argv with safe legacy parsing;
- made state, logs, locks, and API tokens private and state writes atomic;
- added durable operation/generation evidence and recovery for abandoned work;
- restricted the API to loopback with bearer auth, Host/Origin/content-type,
  body-size, timeout, and concurrency boundaries;
- moved slow direct and project-level lifecycle work out of the shared state
  lock and added concurrency regressions;
- bound mutable Docker operations to immutable labeled ownership rather than
  same-name discovery and guarded process state with instance identity;
- added exact manual-lease server start through CLI/API, with the same lease ID
  and port, structured argv, pre-launch rollback, post-launch quarantine, and
  conflicting-operation checks;
- made the implemented API bind contract explicitly IPv4 loopback/`localhost`;
- resolved Docker independently of launchd/GUI PATH, with explicit and standard
  macOS executable locations plus bounded observation/lifecycle execution;
- preflighted Docker daemon and Compose capability before project mutations,
  returning structured zero-mutation or partial-result evidence instead of raw
  `FileNotFoundError` failures;
- parsed Compose global options when classifying mutations and deduplicated
  Compose-owned dependency lifecycle while retaining dependency health evidence;
- expanded realistic tests for injection, rollback, restart provenance,
  parallel leases, abandoned operations, exact-lease interleavings, GUI-minimal
  PATH, missing/hung Docker, Compose restart ownership, and API boundary attacks.

What can still improve: Windows support would require replacing Unix process,
signal, and `flock` assumptions. The local bearer token protects the API
boundary but does not turn it into a safe remote network service. Project
runtime declarations remain explicit local configuration and cannot infer every
framework's dependency graph. Multi-resource lifecycle operations cannot be
made globally transactional across arbitrary OS processes and container
runtimes, so failures after a successful preflight can still be partial; those
outcomes are retained explicitly. Private `0700` state is a same-OS-user
design, not a secure multi-user or VM-shared coordination protocol.

### `formal-web-ui-verification`

Honest description: a Chromium/Playwright heuristic detector for rendered DOM
geometry, clipping, occlusion, off-canvas content, media health, contrast risks,
declared areas, target coverage, and visible scrollbars. It is deterministic
for the states it reaches, but it is not a mathematical proof or a replacement
for visual/design/accessibility review.

Improvements made in this pass:

- made explicit and discovered target coverage fail closed with a distinct exit
  code and reported exemptions;
- traversed discoverable open shadow roots and evaluated reachable iframes;
- added Playwright mobile device descriptors rather than equating narrow width
  with a mobile device;
- added bounded declarative interaction states without arbitrary JavaScript and
  kept entered values out of reports;
- retained realistic must-catch fixtures and intentional-layout false-positive
  guards for every advertised detection class.

What can still improve: closed shadow roots and undeclared states cannot be
discovered externally. Chromium results do not substitute for WebKit/Firefox
coverage. Gradients, images, animation, aesthetics, focus order, screen-reader
semantics, and product suitability still need their appropriate visual or
accessibility review.

### `full-repo-audit`

Honest description: a manifest-verified framework for repository-wide manual
source, architecture, journey, interface, and test review. Deterministic batches
and hashes prove the review queue and artifact identity; agents still perform
the semantic judgment.

Improvements made in this pass:

- labeled effort and worker capability as runtime-attested only when immutable
  evidence exists, otherwise ledger-recorded and unverified;
- required a direct lead-review ledger for every detected high-risk file;
- bound real screenshots/native snapshots/formal reports through a confined,
  hashed evidence manifest with route/state/viewport metadata;
- verified formal-report coverage and visible-scrollbar inventories;
- added must-catch fixtures for missing/tampered evidence, dishonest effort
  claims, and skipped high-risk review, with valid-evidence controls.

What can still improve: artifact hashes prove identity, not whether a screenshot
looks correct. The high-risk classifier is a review floor rather than a proof
that no other file is important. Repository semantics, generated code, external
services, and user intent can still require lead investigation beyond the
deterministic queue.

### `full-repo-test-coverage-audit`

Honest description: a manifest-verified test-assurance audit with deterministic
structural target discovery, exact `TESTED`/`UNTESTED`/`NOT_REASONABLE`
decisions, verified test references, and optional empirical coverage ingestion.
Without a supplied runtime report it is structural/manual assurance, not an
empirical coverage measurement.

Improvements made in this pass:

- added an exact per-unit target inventory and refused omitted deterministic
  targets;
- separated `EMPIRICAL`, `STRUCTURAL`, `MANUAL`, and `NONE` evidence;
- validated real test paths and named symbols rather than accepting prose;
- ingested LCOV, Cobertura XML, coverage.py JSON, and Istanbul JSON with hashes
  and measured/covered line evidence;
- added realistic omissions, invented-test, stale-evidence, and justified-
  exclusion fixtures.

What can still improve: deterministic symbol scanners cover a portable language
floor, not every metaprogrammed, generated, reflective, macro-created, or
framework-discovered behavior. Manual targets remain necessary. Line execution
does not prove assertions are meaningful, so scenario and mutation-quality
review remain separate concerns.

### `postgres-docker-backup`

Honest description: a safety-gated logical backup, verification, and database-
restore tool for explicitly selected PostgreSQL Docker containers. It supports
database custom/plain dumps and isolated whole-cluster dump verification. It is
not encrypted, off-site, continuous, replicated, or point-in-time recovery.

Improvements made in this pass:

- added private, staged, fsynced, collision-refusing artifact publication and
  versioned provenance manifests;
- removed password command-line arguments and used ephemeral private pgpass
  files transported through stdin with redacted errors;
- separated database and cluster scope and rejected cross-scope artifacts;
- compared restored catalog signatures in scratch databases and made cleanup
  failures fatal;
- made database restore transactional with incoming verification and a strongly
  verified safety backup;
- verified cluster dumps only in a distinct, no-network disposable container
  and refused unsafe in-place cluster restore;
- required an operator-supplied immutable full or unambiguous standard short
  container ID before every live-container backup, database verification, and
  database restore, with repeated full-ID checks around each protected phase;
- kept cluster artifact verification intentionally offline/disposable when no
  source identity check is requested, and rejected a silently ignored source
  hint;
- added deterministic failure fixtures and a real disposable PostgreSQL 16
  integration path.

What can still improve: production cluster replacement needs an explicitly
designed staged topology outside this skill. Logical catalog/restore verification
does not provide encryption, off-site durability, WAL/PITR, replication, or an
application-level semantic data audit.

### `trace-fix-root-causes`

Honest description: an evidence-structured, prevention-first workflow and
report verifier for implementation, UI, factual, reasoning, tool-use, artifact,
service, audit, and verification incidents. It guides investigation; it cannot
automatically prove a causal explanation is true.

Improvements made in this pass:

- merged the installed Codex/Claude variants back into one canonical source;
- separated `diagnose-only` from `authorized-fix` so a report does not imply
  mutation authority;
- required an exact incident class, structured evidence ledger, evidence-linked
  origin/immediate-defect/missed-detection chain, and confidence labels;
- added incident-specific evidence contracts and portable runtime policy paths;
- expanded realistic report-verifier fixtures across all incident classes and
  false-trigger cases.

What can still improve: evidence quality remains bounded by what was preserved.
The verifier proves report structure and references, not hidden reasoning or
causal truth. External state changes and unavailable logs must remain explicitly
unconfirmed rather than being filled with a plausible narrative.

### `ui-implementation-audit`

Honest description: an interface-source and rendered-evidence audit against
mockups and journey requirements. It checks visual/responsive/interaction gaps
and traces visible actions through handlers, backend/API, permissions,
persistence, and tests. It does not create design truth when requirements or
render evidence are missing.

Improvements made in this pass:

- rejected screenshot filenames that do not resolve to real evidence;
- verified confined hashed screenshots/native snapshots/formal reports with
  route/state/viewport metadata;
- required exact action-trace columns and real `path#symbol` references;
- required missing handler/backend/permission/persistence/test layers to produce
  findings instead of accepting invented plumbing;
- added tampering, missing-artifact, invented-symbol, and legitimate-not-
  applicable fixtures.

What can still improve: visual evidence identity does not prove semantic or
aesthetic quality. Native automation, accessibility, permissions, and external
integrations need runnable environments. When the journey or mockup is
unconfirmed, the audit must keep conclusions assumption-based.

### `user-journey-docs-audit`

Honest description: a lexical/structural documentation inventory, interview
workflow, and final-report gate for product purpose, users, journeys, decision
models, relevance, features, UI handoff, edge cases, implementation, tests, and
usability criteria. It detects missing documentation; it does not decide the
product on the user's behalf.

Improvements made in this pass:

- recognized SwiftUI, AppKit/UIKit, XAML/Avalonia, Compose, Flutter, Objective-C,
  and QML visible-interface hints;
- classified `AGENTS.md`, `CLAUDE.md`, and decision logs as policy/governance,
  never as confirmed product truth;
- added an exact final-report verifier for headings, interview status, journey
  status, unconfirmed propagation, and the interaction checklist;
- added realistic native-source, policy-only, missing-interaction, and
  confirmation-propagation fixtures;
- produced `apps/CodexOpsConsole/PRODUCT.md` as the confirmed Board journey and
  decision contract; the user subsequently approved the ImageGen layout and the
  Board source implementation now follows that confirmed hierarchy.

What can still improve: lexical evidence can locate likely omissions but cannot
infer a user's actual priorities. Product purpose, ambiguous journeys, and UI
assumptions still require interview/confirmation. Rich non-text artifacts may
need separate extraction before this skill can inventory them.

## Verification expectation

| Gate | Closeout status | Evidence/boundary |
| --- | --- | --- |
| Link topology | passed | 24/24 managed Codex, Claude, and desktop entries verified as direct links; rollback transaction retained |
| Link/privacy/shared-harness guards | passed | Manager recall/rollback suite, public guard over 116 publishable files, vendored sync, and merge checks |
| Snapshot detector and structural artifact checks | passed | Source-binding recall/precision self-tests pass; four canonical PNGs pass privacy, pixel, and geometry checks with source freshness explicitly skipped |
| Current-source canonical snapshots | pending | All four committed sidecars lack the new exact renderer-source binding, so the default verifier rejects them until Build macOS Apps regenerates the artifacts |
| Eight skill self-tests | passed | Repository copies passed; standalone copied-skill runs passed, including isolated coordinator process/API fixtures |
| Python/static source gates | passed | Compileall/py_compile, JSON/YAML parsing, diff hygiene, and Board static interaction assertions |
| Real PostgreSQL integration | passed | Unique labeled PostgreSQL 16 container; exact/wrong/short identity, backup, strong verify, restore, disposable cluster verification, and cleanup |
| Formal web runtime fixtures | passed | Current repository and standalone copied-skill Playwright fixture suites completed inside the consolidated non-native gate |
| Codex Ops Console native build/XCTest/package/run | pending | Must use Build macOS Apps; the plugin is not exposed in this session, so earlier pre-final Swift results are not claimed for the current source |
| Approved Board source/native accessibility acceptance | pending | The ImageGen review is approved and the source implementation is present; native compile, layout, and accessibility acceptance still require Build macOS Apps |

The repository's `scripts/validate.py --skip-macos-app` gate is the honest
non-native path. It explicitly skips canonical snapshot source freshness, so it
does not prove that committed PNGs depict the current SwiftUI source. The
complete default gate includes that current-source requirement and the native
Board checks, and must be run by an agent only through Build macOS Apps.
Environment-dependent checks must always remain labeled passed, skipped, or
pending rather than being implied by a structural pass.
