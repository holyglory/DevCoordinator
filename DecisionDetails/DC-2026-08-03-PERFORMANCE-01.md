# DC-2026-08-03-PERFORMANCE-01 — Performance reconciles the whole server before drilling into projects

## Decision evidence

- On the audited production page, whole-host memory was about 81.4 GiB while the visible repository-family total was about 34.6 GiB. The figures came from different accounting bases: host `MemTotal - MemAvailable` versus managed process RSS and Docker working sets.
- The remainder was not proved to be one missing project. It includes unprojected control-plane and agent/test processes, unmanaged workloads, kernel/slab and shared-memory effects, plus sampling and RSS/cgroup accounting differences.
- A follow-up live host reading confirmed that the gap was materially dominated by non-project developer sessions rather than a small sampling error: host used was about 80.6 GiB, top-level `user.slice` working memory was about 49.1 GiB with about 32.1 GiB shared memory, and UID 1000 accounted for about 34.5 GiB working memory with about 24.8 GiB shared memory across two sessions. Gross slab was about 9.4 GiB. These readings overlap and therefore explain the residual without becoming additive stack segments.
- A bounded read-only attribution audit on 2026-08-03 measured 83.23 GiB host used and 49.76 GiB in developer-account sessions, including 32.46 GiB of shared memory. Two UID 1000 login scopes alone held 33.60 GiB and contained 91 Chrome renderers plus eight agent-browser processes. Over the same CPU sample, user sessions consumed only 0.15 core, while project workloads consumed 5.39 cores and one active test runner consumed 0.99 core. The practical efficiency problem was therefore browser lifecycle and attribution, not a CPU quota or a monolithic pool of “unclassified workers.”
- The old Performance view repeated a CPU and memory chart for every server and container. Its captured narrow state exceeded 23,000 pixels in height and made the global composition hard to scan.
- Product Design generated three grounded directions from fresh desktop and mobile production captures. The user selected displayed option 1 on 2026-08-03 with: “The first option looks great, go ahead.” The exact selected pixels and provenance live at `apps/DevOpsConsole/Artifacts/Design/performance-stacked-selected-reference.png`.

## Consequences

- Every displayed memory composition reconciles disjoint cgroup-v2 roots for project runtimes, Coordinator control, Coordinator background/scheduler, active test attempts and developer-account sessions, a truthful residual, and `MemAvailable` to physical memory. The inclusive `devcoordinator.slice` parent is never added beside its children.
- Repository-family, Agent-browser, child-cgroup, `system.slice`, and `/proc/meminfo` observations are bounded non-additive drilldowns. They preserve account/process, shared-memory, anonymous-memory and kernel evidence without nested-cgroup, browser, repository or host-counter double counting; cgroup working memory is labelled as `memory.current - inactive_file`, and unavailable PSS is not inferred.
- CPU is normalized to whole-host capacity before composition; incompatible or skewed samples expose coverage/skew rather than inventing precision.
- Repository families remain exact on-demand cross-checks over the one project-runtime root. Root, family and project-runtime values are never added together; a material mismatch is reported as an attribution gap.
- A compact legend is the project selector. Its native dialog shows current/peak usage, history, component counts, and top known contributors for only the selected repository.
- The memory residual is named `Estimated System & unattributed`, and its overlapping evidence stays in a local disclosure below the memory composition instead of a standalone warning-style accounting banner.
- Repository colors are assigned from a deliberately separated twelve-color palette with deterministic collision resolution. Hovering or focusing an additive legend row emphasizes its matching stack segment. A repository or Agent-browser row is non-additive, so it instead draws only that exact drilldown's retained observed-value history as an overlay on the same host scale; it never highlights the containing aggregate as if the aggregate were the selected series. A drilldown with no positive retained sample leaves the chart unchanged. None of these transient interactions opens the detail dialog.
- Background refresh retains visible content and the selected dialog/focus. Mobile keeps the stacked overview and moves detail into the dialog without horizontal document scrolling.

## Verification

- Unit fixtures cover disjoint-root reconciliation, repository/browser/system overlap, missing/stale samples, negative-residual prevention, family/root double-count prevention, cgroup CPU deltas, account labels, bounded child detail, and multicore CPU normalization.
- Browser verification covers legend activation, one-project dialog content, Escape/close focus restoration, refresh stability, and responsive geometry at 320, 390, 768, 981, and 1440 pixels.
- The populated browser fixture renders twelve repositories and verifies distinct legend/chart colors, exact-key observed-value overlays, distinct repository selections, current-zero/historical-peak Agent-browser geometry, no false emphasis for a 0/0 repository, hover and keyboard parity, overlapping pointer/focus state, touch suppression, refresh cleanup, and modal-state cleanup at the same five widths.
- Each chart exposes its exact time-series values in a compact disclosure/table for keyboard, touch, and assistive-technology access; mobile legend rows visibly distinguish current and peak values.
- Product Design QA compares the selected visual reference and same-state rendered implementation before delivery.
