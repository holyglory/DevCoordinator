# DC-2026-07-19-ENROLLMENT-01 — Authorization upgrades migrate before restart

## Supporting record

Decision: Treat the protected client profile and the service-owned enrollment
rows as one versioned authorization contract. A schema change that makes a new
authorization row mandatory must include an offline administrator migration
from the existing root-owned profile. The migration validates the database
generation, kernel UID/account principal, exact repository ID and canonical
root, repository generation and installed state, profile validity, and the
existing resource ACL evidence before it creates only a missing enrollment
row. It never reconstructs grants from display names, broadens server or
cleanup access, or revives a disabled or conflicting enrollment.

Arbitrary repository-generation drift remains a blocking conflict. A separate
offline reconciliation may advance one protected profile repository generation
only when the operator supplies the exact old and current generations and the
tool proves the same database generation, UID/account principal, repository ID
and canonical root, active installed and unfenced repository, and unchanged
enabled ACL digest. It must hold both the broker lifetime and protected-profile
publication locks, atomically rewrite only that one JSON scalar, and prove the
rest of the profile and database authority are unchanged. Normal enrollment is
not a migration substitute because it rebuilds observation-derived grants.

The server-wide installer must compare every current protected profile entry
with the service database before it allows a broker restart. Missing,
disabled, expired, cross-account, wrong-generation, or extra enabled authority
is `profile_database_enrollment_drift` and blocks the stop boundary. A rollout
is healthy only after the broker, authenticated loopback inventory, and the
Console's exact MainPID/listener/assignment/lease registration all converge.

Why: On 2026-07-19 the deployed code added
`broker_repository_enrollments` and immediately required a matching row for
every broker request, but it created the table empty and provided no migration
for profiles issued by the preceding version. At 20:08:34 UTC the broker
restart cleanly stopped the required loopback API and Console. The broker
returned, but the API's authenticated inventory failed with
`project_access_denied` through twenty start attempts, so the Console remained
inactive and public ports 80/443 refused connections. DNS and the host firewall
were healthy.

Before repair, the service store was captured with a verified WAL-consistent
backup under the private 20260719T232653Z Console-outage recovery transaction.
The exact `/home/DevCoordinator` enrollment for UID 1000, account
`holyglory`, server `devops-console`, and port 443 was restored without cleanup
capabilities. The public login and health paths then returned HTTP 200, and the
registered MainPID, active assignment, and lease converged without lifecycle
violations.

Options considered:

- Allowing missing rows was rejected because it removes the new least-
  privilege boundary.
- Inferring access from repository names, inventory visibility, or broad ACL
  residue was rejected because those are not exact administrator grants.
- Deleting unmatched profile entries was rejected because it silently revokes
  intended access and leaves other agents broken.
- Re-enrolling every repository from today's runtime manifests was rejected as
  the migration mechanism because manifests and server names may have changed
  since the trusted profile was issued, changing grants during recovery.
- Ignoring generation drift was rejected because a genuinely reinstalled
  repository must not inherit authority silently. The observed UID 0
  GlobalFinance row was instead eligible for the explicit scalar-only repair:
  its repository ID and root were unchanged, the installation remained active
  and unfenced, and generation 1 to 2 coincided with later account enrollment
  rather than repository reinstallation.
- An exact offline profile-backed migration plus a two-way installer gate was
  selected because it preserves the prior authorization scope and detects the
  same defect before any production dependency is stopped.

Required evidence: a legacy-store fixture with a current protected profile and
missing enrollment row must be caught before restart; exact migration must
preserve existing ACLs and pass afterward; disabled, expired, conflicting, and
wrong-generation controls must fail closed; the explicit generation-forward
repair must prove a one-scalar profile diff and unchanged ACL digest; and
production recovery must prove the broker, authenticated inventory, public TLS
health/login, and exact Console registration graph.

Completion evidence: the final focused authorization suite passed 41/41 and
the complete checkout-owner server-wide installer self-test passed. Before the
offline mutation, the installer reproduced
`profile_database_enrollment_drift` with 10 protected grants, three current
service rows, seven missing rows, and the UID 0 GlobalFinance generation 1/2
conflict. A new verified WAL-consistent service backup and manifest were
created under
`/var/lib/devcoordinator-install/20260720T000102Z-profile-enrollment-migration`.
With Console, API, and broker stopped and their listeners absent, the exact UID
0 row was reconciled from generation 1 to 2. The tool reported one profile
scalar change, zero database changes, no rebuilt grants, an unchanged
1,929-row enabled-ACL digest, and a private root-owned rollback profile. An
independent document comparison proved every other profile value unchanged.

The enrollment migration then checked all 10 grants, retained three exact
rows, and inserted only the seven missing `(uid, repo_id)` rows. Its immediate
second run checked 10/10, inserted zero rows, and mutated no table. Installer
plan and verify both then reported 10 protected and 10 database enrollments,
no issues, and no failure codes. After restart, project-scoped inventory passed
through the real UID 0, UID 1000, and UID 1001 peer contexts for every one of
the 10 profile grants with active installed repositories and no lifecycle
violations. The capability-matched production verifier proved Console MainPID
3894685, server `144ba3fb-9939-5a81-91b1-f1bb3a5db418`, assignment
`/home/DevCoordinator::devops-console`, active lease
`ed23f012-e5b8-49a7-9372-d8b34247b1ce`, and port 443 in one exact graph. Local
TLS health/login and public `34.118.75.147` health/login all returned success;
the original public login URL returned HTTP 200. No planned, running, or
partial coordinator operation remained.
