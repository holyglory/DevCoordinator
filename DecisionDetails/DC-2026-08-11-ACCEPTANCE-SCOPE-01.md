# DC-2026-08-11-ACCEPTANCE-SCOPE-01 — Completion excludes external-repository canaries

## Context

The Completion Ledger mixed DevCoordinator-owned acceptance with live canaries tied to particular external repositories and resources. Those canaries were useful while diagnosing integration defects, but keeping them open made DevCoordinator completion depend on another repository's application surface, credentials, resource inventory, and host availability.

The user explicitly directed that repository-specific acceptance items be removed.

## Decision

Completion remains gated by live acceptance of DevCoordinator-owned capabilities and interfaces. A named external repository, application, or resource may provide regression evidence, but it is not itself an unresolved DevCoordinator deliverable.

Accordingly:

- remove the PRTZN-specific authenticated Codex browser canary;
- remove the named `gnt-artifact-pg` attachment canary;
- describe universal-harness evidence without making GlobalFinance a continuing acceptance dependency;
- retain the generic broker admission, Telegram integration, cleanup lifecycle, DevOps Board, and signed native-app journeys because they exercise DevCoordinator-owned behavior.

This decision changes completion scope only. It does not weaken the implemented immutable-identity, authorization, secret-boundary, lifecycle, or browser-security controls, and it does not erase historical evidence in earlier decision records.

## Verification

The project-root Completion Ledger must contain no open item naming PRTZN, GlobalFinance, `gnt-artifact-pg`, or another external repository/resource as a required acceptance target. Remaining entries must name only DevCoordinator-owned behavior and the exact live surface still needed to verify it.
