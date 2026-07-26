# DC-2026-07-20-CONSOLE-RESILIENCE-01 — Listener availability and upgrades fail independently

## Durable decision

The public TLS Console, authenticated loopback API, and server-wide broker are
separate supervised availability boundaries. Units use soft ordering
dependencies: each consumer starts after and wants its control dependency, but
maintenance or failure of that dependency does not automatically stop an
already-running public listener. Unexpected failed or clean exits restart and
leave structured durable journal evidence; an explicit operator stop remains
authoritative.

Authorization or schema changes migrate and reconcile protected profiles and
the service database before restart. Startup, rollback, and deployment
readiness require bounded convergence of the exact MainPID/cgroup, listener,
health, authenticated API, Coordinator registration, assignment, and lease
graph. Process creation, a fixed delay, TLS reachability, or one lucky sample is
not readiness.

A long-lived loopback API validates the exact protected client-profile identity
before bind and watches only publication metadata. After a stable atomic
replacement it exits once so its existing supervisor reloads current code and
strict schema; it neither reads profile secrets for change detection nor
restarts the broker or public Console.

## Alternatives rejected

Hard service dependencies turned broker or API maintenance into a Console
outage and did not restart reverse dependents afterward. `Restart=always`
cannot override an explicit system manager stop. A permanent upholder would
fight intentional maintenance. Post-restart data migration risks stopping a
working deployment before authorization drift is discovered. Manual reload or
permissive unknown-field parsing leaves stale protected-profile readers broken
or weakens the authorization schema; restarting every listener broadens the
blast radius.

## Operational consequences

Deployment helpers and rollback paths share exact convergence probes and real
CLI contracts. Pre-stop work must preserve rollback evidence, and externally
visible activation or migration work remains unresolved in
`CompletionLedger.md` until exercised through the live deployed surfaces.
