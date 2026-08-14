# DC-2026-08-12-EFFICIENCY-PROJECTION-01

## Context

Each runtime account owns an independent delivery-efficiency recorder and cold ledger. The user wants repository-level statistics across those accounts in DevOps Console only where DevCoordinator is installed, without making recording depend on Coordinator or retaining source paths, prompts, or another unbounded event history.

## Options and rationale

- Centralize raw recorder events in Coordinator: rejected because it duplicates the authoritative ledger, expands private-data and schema surface, and grows indefinitely.
- Keep statistics recorder-only: rejected because it cannot provide the requested cross-account repository view.
- Publish replaceable cumulative per-account/repository snapshots: selected because each writer owns one bounded file, Coordinator can merge exact `known_sum` and coverage semantics, and the recorder remains standalone.

The CLI advertises schema-1 ingestion through `devcoordinator capabilities`. A terminal declaration checks that capability, derives its current configured repository locally, and publishes only an opaque repository summary. Failure or absence is best effort and never changes terminal recording. The Console projection is separately readable during a broker outage and hidden when its production root is not configured.

The accepted security basis is `security-assumptions.md`: one developer controls the local accounts; account boundaries are attribution and accounting domains rather than mutually distrusting tenants; nonsecret coordination metadata may be readable across accounts; repository association is display/accounting context, not authorization. Revisit the storage and access design if any of those assumptions changes.

## Verification contract

Strict schema fixtures reject extra/private fields, malformed or oversized snapshots, unsafe links, and invented zeroes. Merge tests prove partial coverage and account separation. Browser tests exercise repository-first display, detail, refresh, focus restoration, and wide/narrow geometry. The production page remains absent without the configured capability.
