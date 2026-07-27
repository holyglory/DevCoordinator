# DC-2026-07-27-BOARD-INCIDENTS-01 — Lifecycle incidents get a dedicated, stable workspace

## Decision

The DevOps Board center pane has two explicit workspaces:

- **Resources** keeps compact status, load, filter, resource-kind controls, and the active inventory table. Its table is the only vertical scroll owner.
- **Activity** keeps the operation list and selected incident explanation in one shared vertical scroll surface. It presents what happened, whether change was confirmed, the recommended next action, and selectable/copyable technical evidence.

The right inspector remains tied to the selected project or resource in both workspaces. A lifecycle confirmation sheet closes when execution starts. The operation becomes the selected Activity item immediately; failure remains visible there and never depends on keeping the sheet alive. Recovery context belongs to that exact Activity operation rather than one global target: a typed pre-mutation stale-plan rejection offers **Refresh & re-plan**, while a `needs_attention` result after partial mutation offers **Retry confirmed operation** with the original reviewed plan ID and fingerprint.

A standalone-retirement apply uses the exact refreshed target identity embedded in the reviewed durable plan. Python may accept an older caller ownership generation only after plan ID, plan fingerprint, immutable resource identity, stable control contract, repository attachment, and current observation prove the same semantic target. Real plan, controller, attachment, or resource drift returns a typed pre-mutation stale-plan failure with refresh-and-replan guidance.

## Why

The prior center pane could mount an outer dashboard scroll, an inner resource-table scroll, and an Activity drawer scroll at once. Expanded alerts and project load pushed inventory below the fold, two visible scrollbars made navigation ambiguous, raw evidence was difficult to select, and retirement failures appeared behind a modal that remained open. Its apply call also reused the UI identity captured before planning, even though the mandatory planning observation advanced the ownership generation and stored a newer exact identity in the reviewed plan.

Three interface structures were considered:

1. Keep the dashboard and bottom Activity drawer, but reduce heights. This preserves familiarity but retains competing scroll ownership and makes incident evidence secondary.
2. Put all lifecycle evidence in the right inspector. This removes the drawer but overloads the narrow resource inspector and makes comparing operations difficult.
3. Use dedicated Resources and Activity workspaces in the center while keeping the resource inspector stable. This gives each task enough space, makes one-scroll behavior enforceable, and keeps failures immediately actionable without displacing inventory during ordinary work.

For lifecycle identity, applying the pre-plan UI snapshot was rejected because a successful planning observation legitimately advances its generation. Ignoring identity changes was also rejected because it could act on a replaced controller or resource. Creating a new plan for a partially applied retirement was rejected because Python deliberately fences and resumes that durable operation. The selected contract executes or resumes the reviewed plan target, binds success back to its confirmed plan reference, compares stable semantic controller evidence across fresh observation, and preserves fail-closed rejection for material drift.

## Verification

Focused Python tests must reproduce planning-generation churn, accept only the unchanged semantic controller, reject real target/controller drift before host effects, and verify the typed non-mutating failure payload. Native tests must prove a failed apply closes the sheet, selects its retained Activity incident, uses planned identity arguments, scopes recovery to that incident, resumes partial application with the original plan, rejects mismatched success evidence, exposes selectable technical evidence, and has exactly one visible center-pane vertical scroll owner at supported compact and desktop widths. The deterministic visual state must load an authoritative multi-repository tree with a temporary child, retain the exact resource selection, and include the operation density and warning state promised by the selected concept; an empty hierarchy, empty inspector, or sparse history is not a valid comparison fixture. Compare that same-state native capture beside the selected Incident Workspace reference before delivery.
