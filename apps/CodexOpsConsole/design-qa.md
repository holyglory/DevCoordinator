# Design QA

source visual truth path: `/Users/holyglory/.codex/generated_images/019e8760-bb84-7061-a3d5-dc3a3a8752f3/ig_0332395ad68d9ced016a2c505facbc8191b07701adb394bd59.png`

implementation screenshot paths:
- Dev Servers: `/Users/holyglory/src/holyskills/apps/CodexOpsConsole/design-qa-implementation.png`
- Docker: `/Users/holyglory/src/holyskills/apps/CodexOpsConsole/design-qa-docker.png`
- Databases: `/Users/holyglory/src/holyskills/apps/CodexOpsConsole/design-qa-databases.png`
- Narrow reproduction before fix: `/Users/holyglory/src/holyskills/apps/CodexOpsConsole/design-qa-narrow-before.png`
- Narrow verification after fix: `/Users/holyglory/src/holyskills/apps/CodexOpsConsole/design-qa-narrow-after.png`

viewport: 1440 x 1024 desktop macOS app

state: dark Command Center Board, global coordinator inventory, real Docker/Postgres inventory

commands:
- `python3 /Users/holyglory/.codex/skills/codex-dev-coordinator/scripts/dev_coordinator.py inventory --project "$PWD"` reproduced project-scoped empty dev-server state and Docker-only-running inventory before the coordinator fix.
- `python3 /Users/holyglory/.codex/skills/codex-dev-coordinator/scripts/dev_coordinator.py docker ps --all --dry-run` verified the app-facing coordinator command shape.
- `python3 /Users/holyglory/.codex/skills/codex-dev-coordinator/scripts/dev_coordinator.py inventory --project "$PWD"` verified all-container inventory after deployment to `~/.codex/skills`.
- `python3 /Users/holyglory/.codex/skills/codex-dev-coordinator/scripts/dev_coordinator.py server logs --server-id <id> --tail 5` verified the installed coordinator returns real managed-server log text and stop metadata.
- `swift build`
- `python3 skills/codex-dev-coordinator/scripts/self_test.py`
- `swiftc -parse-as-library -o .build/qa/CodexOpsConsoleSnapshot Sources/CodexOpsConsole/Models.swift Sources/CodexOpsConsole/OpsStore.swift Sources/CodexOpsConsole/Views.swift Tools/SnapshotMain.swift`
- `swiftc -parse-as-library -o .build/qa/SplitSizingTest Sources/CodexOpsConsole/Models.swift Sources/CodexOpsConsole/OpsStore.swift Sources/CodexOpsConsole/Views.swift Tools/SplitSizingTest.swift`
- `.build/qa/SplitSizingTest`
- `.build/qa/CodexOpsConsoleSnapshot /Users/holyglory/src/holyskills/apps/CodexOpsConsole/design-qa-implementation.png`
- `.build/qa/CodexOpsConsoleSnapshot /Users/holyglory/src/holyskills/apps/CodexOpsConsole/design-qa-docker.png docker`
- `.build/qa/CodexOpsConsoleSnapshot /Users/holyglory/src/holyskills/apps/CodexOpsConsole/design-qa-databases.png databases`
- `.build/qa/CodexOpsConsoleSnapshot /Users/holyglory/src/holyskills/apps/CodexOpsConsole/design-qa-narrow-before.png servers 1180 760` reproduced the narrow-window crop before the responsive layout fix.
- `.build/qa/CodexOpsConsoleSnapshot /Users/holyglory/src/holyskills/apps/CodexOpsConsole/design-qa-narrow-after.png servers 1180 760` verified the sidebar is left-anchored and uncropped after the fix.
- `python3 scripts/validate.py`
- `swift build && swiftc -parse-as-library -o .build/qa/SplitSizingTest Sources/CodexOpsConsole/Models.swift Sources/CodexOpsConsole/OpsStore.swift Sources/CodexOpsConsole/Views.swift Tools/SplitSizingTest.swift && .build/qa/SplitSizingTest` verified sidebar run/stop status decisions after the inline-control pass.

incident cause:
- Previous QA over-weighted static screenshot similarity and did not verify interaction affordances.
- The second splitter pass used local drag translation while the splitter handle itself moved during resizing. That made the right-pane drag susceptible to feedback jitter where pane width did not track the mouse.
- The left tree rendered chevrons and leaves without expandable state or selection actions.
- Fixed-width pane layout made the sidebar feel cropped and unresizable.
- Static SwiftUI grids provided no user-resizable columns.
- The first resizable-column pass used a narrow divider and local drag translation; the handle was hard to hit, gave no cursor affordance, and could behave like the earlier moving-pane splitter.
- Coordinator Docker inventory used `docker ps`, so stopped containers could not appear in the UI.
- The start-server sheet exposed only a range, not an exact custom port path.
- Coordinator `server stop` removed managed servers from state, so stopped dev servers lost their durable `log_path` and did not expose a stop reason for the app.
- The app window minimum width was smaller than the fixed pane total. At 1180 px the fixed 1440 px HStack overflowed and the sidebar was clipped from the left edge.
- Project grouping used the first two hyphenated name parts, so service suffixes such as `metrics-worker`, `minio`, `postgres`, `prod-copy-pg`, and `db` could become separate pseudo-projects.
- The service map used category rows (`Dev Servers`, `Docker`, `Databases`) as structural separators. Those rows consumed vertical space without adding a direct action target.
- Child nodes only had status dots and text, so users could not tell resource type at a glance and could not run, stop, or restart from the tree.
- The right panel mixed selected-resource details with synthetic queued recommendations and coordinator event history, making generated suggestions look like real running work.
- The Docker table displayed fake CPU and memory bars from deterministic name seeds, plus an inferred restart count, instead of real Docker metrics.
- The `Group by` control had no implementation behind it and did not change table grouping.

patches made in this pass:
- Added explicit draggable splitters for the sidebar and inspector panes.
- Enlarged the splitter grip to a visible 14 px resize target with cursor feedback after the first splitter was too hard to operate.
- Changed splitter resizing to use global gesture coordinates and extracted `resizedPaneWidth(...)` so the moving handle no longer feeds back into its own drag translation.
- Converted the service map into an expandable/collapsible, selectable navigation tree.
- Added resource tabs for Dev Servers, Docker, and Databases.
- Replaced static grids with resizable-column table components using draggable header dividers.
- Enlarged table column resize handles to 14 px, added left-right cursor feedback, and switched column drag math to global coordinates through `resizedColumnWidth(...)`.
- Made the tab content and table container fill the available center pane instead of sizing to the intrinsic table rows.
- Added Docker start actions for stopped containers and kept stop/restart/log actions for running containers.
- Updated coordinator inventory to include stopped containers via `docker ps --all`.
- Added `docker ps --all` self-test coverage and deployed the updated coordinator skill to `/Users/holyglory/.codex/skills/codex-dev-coordinator`.
- Added exact preferred port support to the start-server flow; entering a port sends a one-port range plus `--preferred`.
- Changed coordinator-managed dev servers to stay in inventory after stop, retain `stopped_at`, `stopped_reason`, and `log_path`, and expose log tails through `server logs`.
- Added Dev Server row and inspector log actions; the app opens a logs sheet with stop metadata and monospaced captured output.
- Adjusted the default Dev Server column widths so the fourth row action, Logs, is visible without horizontal scrolling at the QA viewport.
- Added responsive pane allocation through `consoleLayout(...)`; the sidebar keeps a readable left-anchored width, while the inspector and then the main pane collapse as needed when the window narrows.
- Made the service map vertical-scroll only and constrained rows to the sidebar width so labels truncate within the row instead of widening or clipping the tree.
- Added canonical project grouping through `projectKey(...)`, treating service role suffixes as child resources rather than project names.
- Removed repeated project prefixes from tree leaves, so grouped resources display as `web`, `metrics-worker`, `minio`, `postgres`, etc.
- Removed category rows from the left navigation tree.
- Added typed child icons: terminal for dev servers, shipping box for Docker containers, and database cylinder for databases.
- Added per-child inline actions in the tree: one play/stop toggle and one restart control.
- Added a real `Stop all` sidebar button that queues coordinator-backed stop commands for all currently running managed servers and Docker containers.
- Raised the sidebar minimum readable width to 280 px so the new inline controls do not get squeezed out by a narrow window or splitter.
- Removed the right-panel action queue and recent events feed; the right panel is now a details-only inspector.
- Removed generated `Inspect ...` and backup recommendation rows from `OpsStore`.
- Removed fake Docker CPU, memory, and restart columns; Docker now shows container, project, status, image, ports, and actions.
- Added real Docker telemetry from coordinator-managed `docker stats --no-stream`: CPU, memory, network I/O, block I/O, PIDs, timestamps, and rolling `stats_history`.
- Added Docker table sparklines for CPU, memory, network rate, and disk I/O rate, plus larger selected-container charts in the details inspector.
- Changed the app subprocess runner to write Python stdout/stderr to temp files before reading, preventing large inventory JSON from deadlocking on pipe buffers as telemetry history grows.
- Added a project-level coordinator runtime flow: `project status/start/restart/stop --project <canonical path>`.
- Project runtime reports now include dependency-aware readiness, URLs, fixed ports, service statuses, previous exit reasons, recent logs, and failure classifications such as `stopped_container`, `missing_dependency`, `wrong_port`, `unhealthy_process`, `timeout`, and `stale_coordinator_metadata`.
- Updated the coordinator skill contract so agents use the single project-runtime flow for "run/start/restart/check the dev server" instead of manually chaining Docker, database, worker, and web commands.
- Added project-level run/stop and restart controls to left navigation project rows, plus project runtime status/actions in the details inspector.
- Removed the unused `Group by` picker and state.
- Added `scripts/validate.py` source guardrails for splitter panes, tree selection, tabs, resizable columns, Docker start, exact preferred port, all-container inventory, and real Docker telemetry.
- Added `Tools/SplitSizingTest.swift`, compiled during validation, to verify left and right splitter width math, monotonic right-pane resizing, stable column-width resizing, 1180 px no-overflow layout, canonical project grouping, and sidebar play/stop state.
- Updated the snapshot helper to capture the Dev Servers, Docker, and Databases tabs directly.

**Interaction Checklist**
- [Passed] Left navigation has a visible splitter and adjustable width.
- [Passed] Splitter has a large enough hit target and left/right resize cursor feedback.
- [Passed] Splitter width math is stable in global coordinates; right-pane width grows monotonically when dragging left.
- [Passed] Project rows expand/collapse through clickable chevrons.
- [Passed] Tree leaves are selectable and switch to the relevant resource tab.
- [Passed] At the 1180 px narrow viewport, the service map remains uncropped from the left and right without a horizontal scrollbar.
- [Passed] GlobalNewsTracker web, Docker services, and Postgres are grouped under one `globalnewstracker` project node.
- [Passed] Category rows are gone from the service tree.
- [Passed] Child rows use type icons to distinguish dev servers, Docker containers, and databases.
- [Passed] Child rows expose play/stop and restart controls.
- [Passed] Stop all is available in the sidebar footer and disabled when nothing can be stopped.
- [Passed] Right inspector shows selected server, Docker container, database, or project details.
- [Passed] Right panel does not show action queue recommendations or recent event history.
- [Passed] Docker table does not show fake CPU, memory, or restart data.
- [Passed] Docker table shows real CPU, memory, network I/O, and disk I/O telemetry with small charts for running containers.
- [Passed] Selected Docker containers and databases show larger details-panel telemetry charts with current values and sample time.
- [Passed] Project runtime command reports Nevod as not ready when `nevod-postgres` is stopped, instead of treating a web process independently.
- [Passed] Left tree project rows expose project-level run/stop and restart controls without clipping at the narrow QA viewport.
- [Passed] The unused Group by control is gone.
- [Passed] Dev Servers, Docker, and Databases are split into separate tabs.
- [Passed] Table column headers include drag handles for resizing.
- [Passed] Column resize handles use a 14 px target, show a left-right resize cursor, and use global coordinates so the width follows the mouse.
- [Passed] Tables stretch to occupy the available tab page.
- [Passed] Docker inventory includes stopped containers.
- [Passed] Stopped Docker containers show a Start action.
- [Passed] Dev server start flow supports exact custom ports.
- [Passed] Dev server stop preserves the server record, stopped reason, and log path.
- [Passed] Dev server logs can be opened from the row action or selected server inspector.
- [Passed] The default Dev Servers screenshot shows all four row actions, including Logs, and the selected-server inspector shows View Logs.
- [Passed] Repo validation includes deterministic source checks for these affordances.

**Findings**
- [Closed] Left navigation tree was cropped and non-interactive.
  Evidence: `design-qa-implementation.png` shows a resizable left pane, expanded project groups, selectable leaves, and persistent coordinator footer.

- [Closed] Tree splitter existed but was not practically usable.
  Evidence: `design-qa-implementation.png` now shows a visible vertical grip between the service map and center pane; `scripts/validate.py` checks for the splitter and 14 px hit target.

- [Closed] Right inspector splitter jittered and did not follow the mouse.
  Evidence: splitter drag now uses `DragGesture(minimumDistance: 0, coordinateSpace: .global)` plus `resizedPaneWidth(...)`; `.build/qa/SplitSizingTest` verifies the right pane follows left/right cursor movement without sign reversal or non-monotonic width changes.

- [Closed] Resource tables were stacked instead of tabbed.
  Evidence: `design-qa-implementation.png`, `design-qa-docker.png`, and `design-qa-databases.png` show separate tabs for Dev Servers, Docker, and Databases.

- [Closed] Tables floated in the middle of empty tab pages.
  Evidence: all three QA screenshots show the table surface stretching vertically and horizontally across the center tab content area.

- [Closed] Columns were not user-resizable.
  Evidence: table headers now use `ResizableHeaderCell` drag handles with `NSCursor.resizeLeftRight`, a 14 px target, and global-coordinate `resizedColumnWidth(...)`; `.build/qa/SplitSizingTest` covers grow, clamp, and monotonic column resizing.

- [Closed] Dev server logs and stop reasons were not retained for stopped servers.
  Evidence: coordinator `server stop --reason ...` now leaves the server in inventory with `stopped_at`, `stopped_reason`, and `log_path`; `server logs` returns the log tail and metadata; `python3 skills/codex-dev-coordinator/scripts/self_test.py` covers stop reason, stopped inventory, and lookup by server id. `design-qa-implementation.png` shows the row Logs icon and selected-server View Logs action.

- [Closed] Narrow windows cropped the left navigation tree from both sides.
  Evidence: `design-qa-narrow-before.png` reproduced the crop at 1180 x 760; `design-qa-narrow-after.png` verifies the service map starts at the left window edge and remains readable. `Tools/SplitSizingTest.swift` now asserts the 1180 px layout exactly fits the available width.

- [Closed] Similar service resources were shown as separate projects.
  Evidence: `design-qa-implementation.png` and `design-qa-narrow-after.png` show `globalnewstracker` as one group with Dev Servers, Docker, and Databases children. `Tools/SplitSizingTest.swift` asserts `globalnewstracker-metrics-worker`, `globalnewstracker-minio`, and `globalnewstracker-postgres` all resolve to the same project key.

- [Closed] Category rows made the left tree too tall and non-actionable.
  Evidence: `design-qa-implementation.png` shows project children directly under each project, with no `Dev Servers`, `Docker`, or `Databases` rows. `scripts/validate.py` now fails if the old `MapCategory` component returns.

- [Closed] The left tree could not run, stop, or restart resources.
  Evidence: `design-qa-implementation.png` shows each child row with a resource type icon, a play/stop toggle, and a restart control. `OpsStore.toggle(...)`, `OpsStore.toggleDocker(...)`, and `OpsStore.stopAll()` call the coordinator-backed server and Docker actions.

- [Closed] Right panel showed synthetic recommendations as queued work.
  Evidence: `design-qa-implementation.png` shows only the `DETAILS` inspector in the right rail. `scripts/validate.py` now rejects `ACTION QUEUE`, `RECENT EVENTS`, `visibleQueueItems`, `Inspect ...`, and the old action item model.

- [Closed] Docker table included fake metrics.
  Evidence: `design-qa-docker.png` shows real Docker stats columns for CPU, Memory, Network, and Disk I/O with sparklines, plus non-telemetry columns for Container, Project, Status, Image, Ports, and Actions. `scripts/validate.py` now requires `DockerStats`, `MetricSparkCell`, and `DockerTelemetryPanel`, and still rejects the old Restarts, `UsageBar`, and `usageSeed` patterns.

- [Closed] Large coordinator inventory output could deadlock the Swift app.
  Evidence: parallel snapshots initially hung after telemetry made inventory JSON large enough to fill the stdout pipe. `runPython(...)` now sends subprocess stdout/stderr to temporary files before reading them after process exit; final screenshot generation and `python3 scripts/validate.py` both passed.

- [Closed] Coordinator could report a web server independently of required project dependencies.
  Evidence: `python3 /Users/holyglory/.codex/skills/codex-dev-coordinator/scripts/dev_coordinator.py project status --project /Users/holyglory/src/nevod` now returns `ok=false`; `nevod-postgres` is classified as `stopped_container`, and the missing web runtime is classified as `missing_dependency`. The coordinator self-test now verifies one-call fixed-port project start/status/stop with a declared readiness check.

- [Closed] Project rows could not start, stop, or restart all associated runtime services.
  Evidence: `design-qa-implementation.png` and `design-qa-narrow-after.png` show project-level play/stop and restart controls on left-tree project rows, while child service controls remain visible.

- [Closed] Group by was a no-op control.
  Evidence: `design-qa-implementation.png` shows only the status filter row above the tabs; `scripts/validate.py` now rejects the old `Group by` and `groupBy` patterns.

- [Closed] Stopped Docker containers were invisible and could not be started.
  Evidence: `design-qa-docker.png` shows stopped containers such as `xfoilfoam-cfd-api`, `nevod-telegram-worker`, and `nevod-postgres` with Start actions.

- [Closed] Dev server start did not support exact custom ports.
  Evidence: `StartServerDraft.preferredPort` and `OpsStore.startServer()` send `--range PORT-PORT --preferred PORT` when an exact port is entered.

**Residual Polish**
- Long real service names still truncate inside compact cells. The splitter and resizable columns provide the user-controlled path to inspect more text.
- Some wide database columns require horizontal scrolling at the default pane width; this is expected because columns are now resizable and preserve dense row height.

final result: passed
