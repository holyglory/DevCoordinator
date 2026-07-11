# Stale-Base Recovery Improvement Ledger

This ledger accounts for the intended work preserved at `55e64d2`, which was
implemented from the older `348aa9f` base and then semantically merged onto the
remote-first baseline beginning at `40a27b8`. `ported` means the local behavior
survived; `adapted` means it was rewritten for the newer architecture;
`already present remotely` and `superseded` mean no weaker duplicate was kept;
`rejected` records an intentional exclusion and its consequence.

| Local improvement group | Disposition | Merge evidence and consequence |
| --- | --- | --- |
| Repository freshness incident prevention | adapted | Added a fetched ancestry detector and eight-case real-Git recall/precision suite on the remote-first branch before merging. |
| Global/repository implementation-mistake policy | ported | Retained the stricter stale work's prevention-first, detector-recall, canonical-link, native-build, service, and database guardrails; combined them with remote-only guidance. |
| Shared repository audit harness evidence and target validation | ported | Kept evidence hashing, deterministic target validation, and queue hardening; synchronized the same sources into all vendored audit harnesses. |
| Full repository audit skill | ported | Kept honest capability/effort provenance, manifest verification, stronger result checks, realistic self-tests, and updated agent metadata. |
| Full repository test-coverage audit skill | ported | Kept exact TESTED/UNTESTED/NOT_REASONABLE target decisions, validated test symbols/paths, optional empirical coverage handling, and recall fixtures. |
| UI implementation audit skill | ported | Kept deterministic interface batches, bound visual evidence, source-backed action tracing, stronger checks, and recall fixtures. |
| User-journey documentation audit skill | ported | Kept product-truth boundaries, ambiguity escalation, inventory verification, result verification, and expanded self-tests. |
| Trace-fix-root-causes skill | ported | Kept structured evidence/causal-chain verification, authorization modes, prevention-first ordering, and realistic self-tests. |
| Formal web UI verifier | adapted | Retained remote coordinator integration while porting the stale work's area-of-interest, scrollbar, media/visibility, target-coverage, and realistic recall/false-positive protections. |
| Coordinator authentication, bounded execution, locking, Docker preflight, and state safety | adapted | The hardened local v2/auth implementation is the base; remote durable port assignments, project membership/usage fields, Linux listener support, fast bind, and real port-0 reporting are integrated without restoring shell execution or whole-request locks. |
| Coordinator remote Console contract | adapted | Server-side bearer authentication, anonymous `/healthz`, ownership-attributed lease release, semantic project-action errors, and safe Docker attribution are added while retaining every remote Console surface. |
| PostgreSQL backup/restore safety | ported | Kept P0 regressions, strong archive verification, disposable integration coverage, transaction-safe restore, provenance, and standalone documentation. |
| Native Board multi-source model, execution safety, database flows, actions, and tests | adapted | Local production behavior and its complete test corpus are renamed into `DevOpsBoard`; remote membership, idle-CPU, lifecycle, and rename contracts are ported into that richer architecture. Per-origin inventory/enrichment overlaps while indexed outcomes publish deterministically, and subprocess completion/output limits are event-driven with bounded cancellation, timeout, pipe drain, and SIGTERM-to-SIGKILL handling. |
| Native Board packaging and helper provenance | adapted | Local tamper tests and helper/source/executable provenance are retained under DevCoordinator naming while preserving the existing bundle identifier and settings identity. |
| Native Board historical screenshots | rejected | Removed unprovenanced intermediate images; consequence is no product behavior loss. Canonical artifacts require regeneration through Build macOS Apps after the merged source is available. |
| Native Board fake window dots and one-click global Stop all | rejected | The stale work's explicit-selection destructive flow remains; consequence is safer truthful control behavior, not feature loss. |
| Remote `apps/DevOpsConsole` application | already present remotely | Retained in full; it was absent only because the local work began before the remote feature landed. |
| Remote `apps/CodexOpsConsole` to `apps/DevOpsBoard` rename | already present remotely | Remote directory/module/product names are authoritative; local Board changes are adapted to them rather than recreating the old path. |
| Public artifact, snapshot provenance, and skill-link detectors | ported | Kept the artifact guard, snapshot verifier, realistic detector suites, transactional direct-link manager, drift backup, and rollback checks. |
| Root validation and CI hardening | adapted | Combined remote Board/Console checks with all stale skill, detector, link, provenance, packaging, and vendored-harness checks; native execution remains gated by Build macOS Apps. |
| Audit report and current documentation | adapted | `SKILL_AUDIT.md`, READMEs, installation guidance, counts, and DecisionHistory are retained where still current and updated again at the repository split boundary. |

No local test is intentionally dropped solely because a symbol or directory was
renamed. No remote-only application or coordinator feature is deleted solely
because it did not exist on the stale base.
