# DevOps Board inventory readiness incident

## Outcome
Status: fixed

## Cause
Class: service
Confidence: confirmed
Request: DevOps Board must run with its real coordinator source, keep ordinary refreshes efficient, expose working source details, and not remain in an updating or unavailable state.
Immediate cause: The Board's coordinator wrapper applied a 1,048,576-byte command-output ceiling to a valid 3,271,993-byte inventory, killed the helper at that boundary, discarded the snapshot, and then treated the source and its dependent capabilities as unavailable.
Why missed: The prior build-and-run verification checked only that a signed DevOpsBoard process existed after one second; 69 native tests supplied small fake coordinator results, and the repository validation path checked static source contracts rather than completing the bundled coordinator command against the live source.
Evidence: The pre-fix app PID 110 was alive from the provenance-bound bundle while its unified app log and user screenshot reported Inventory unavailable. Running the exact bundled coordinator command against `~/.codex/agent-coordinator` produced 3,271,993 bytes of valid JSON with Docker `available=true`, while the production command execution recorded truncation at 1,048,576 bytes. The post-change compact command produced 650,020 bytes in 2.86 seconds with 16 servers, 15 containers, seven PostgreSQL projections, and 450 history samples.

## Changes
Product: Fixed the Board by adding a 16 MiB inventory-only output budget, compact 30-sample inventory responses without shrinking persisted history, one off-main decode, a Docker warning that requires loaded-source evidence, and a real-source launch-readiness gate with executable/start identity and stabilization checks.
Prevention: Added realistic over-1-MiB transport regression coverage with an ordinary-command false-positive control; strengthened coordinator tests for compact output, current statistics, limits, history ordering, and invalid values; and implemented a tested launch detector that must catch failed sources, stale identities, split log writes, capture or app death, and failed-launch cleanup.

## Verification
Original path: After the fix, reran the signed app through `./script/build_and_run.sh --verify`; the original native Board path passed on two independent provenance-bound launches with `loaded=1 total=1`, then remained sustained on the same Board surface through four real inventory markers on PID 84736 and three on PID 95190 with no failure marker.
Checks: Post-fix checks passed: 74 Swift tests, 120 DevOps Console tests, repository and standalone coordinator/backup skill self-tests, package provenance tests, normal and optimized launch-detector tests, the full `scripts/validate.py --skip-macos-app` gate, strict code-signature verification, and live process sampling showing 0% idle CPU, a brief 17.3% refresh sample, and roughly 116-124 MiB RSS.
Residual risk: Visible interval mode intentionally polls after a full 30-second idle period and still performs a real Docker statistics observation; manual mode remains available, and an inventory that grows beyond the bounded 16 MiB allowance will fail closed with a concise limit diagnostic instead of being accepted without a bound.
