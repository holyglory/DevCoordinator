# Security assumptions

These are the user-confirmed assumptions for DevCoordinator's current production
deployment. They govern security-posture decisions; unknowns do not justify a
new gate.

## Users and operators

- One developer owns and operates this Linux server. Several Unix accounts and
  agent products are execution, attribution, accounting, and crash domains for
  that same developer; they are not mutually distrusting tenants.
- A few developers may use the product through its public Console interfaces,
  but that does not turn local Unix accounts on this host into separate security
  principals.

## Environment and ownership

- DevCoordinator runs on one Linux/systemd server. Its Coordinator, Console,
  project, and test processes are separated so crashes, cleanup, accounting,
  and stale operations do not interfere across projects.
- Public traffic, Google identities, Telegram users, and external upstreams are
  outside the trusted local-host boundary.

## Assets and sensitivity

- Test history, timing, rollups, and test-attempt state are disposable. Console
  user settings and authority/project configuration are retained.
- Credentials, external identity assertions, bot tokens, and fixture secrets
  remain secret and must use their dedicated server-owned transport. They must
  never be placed in a repository manifest or ordinary launch descriptor.
- Repository source and project databases may be valuable even though their
  exact sensitivity is not otherwise classified. This assumption does not
  authorize deleting or publicly exposing them.

## Credible failures and adversaries

- Accidental cross-project interference, stale agents, duplicate requests,
  malformed inputs, path escapes, runaway processes, crashes, and lost replies
  are credible and must remain bounded by immutable resource identity,
  generation fencing, idempotent operations, process isolation, TTLs, and
  cleanup.
- Another local Unix account is not a credible adversary in this deployment.
  Internet users and external identities remain untrusted unless authorized by
  the public product boundary.

## Required gates

- Public Google login, Console grants, domain authorization, Telegram
  ownership, and upstream credentials remain explicit authorization boundaries.
- Local protocols continue to validate message size and shape, known immutable
  repository/resource identity, generation, lifecycle state, path containment,
  and idempotent operation identity. These prevent mistakes and stale work; they
  do not authenticate one local account against another.
- Secret-bearing files and credential transports remain separate from ordinary
  non-secret local coordination metadata.
- A first-use repository mutation requires a non-root local caller using the
  typed protocol and a proven repository identity. Coordinator durably records
  that actual caller UID as the execution identity and may atomically create or
  refresh the corresponding routing/enrollment record. Filesystem stat owner is
  neither authorization nor an execution-identity selector, and repository code
  never runs as root, with elevated capabilities, or as the control plane. For
  a fresh launch, after the exact-port preflight succeeds and immediately before
  attributed execution, Coordinator may descriptor-walk only the exact resolved
  and validated working directory. It skips `.git`, does not follow symlinks,
  and adds only group-class `rwX` bits: directory traversal/read/write, regular
  file read/write, and execute only where the inode was already executable.
  With an extended POSIX ACL, those group-class bits update the ACL mask and can
  make existing named local-account entries effective; named ACL entries,
  bytes, UID, GID, world bits, and regular-file executable intent remain
  unchanged. Multiply linked regular files are silently skipped so an inode
  reachable through an external hard link is never mutated.
  This is execution compatibility inside the selected working tree, not broad
  source-root or world-access normalization. An occupied port causes no metadata
  mutation. Explicitly disabled Coordinator actions, enrollments, repositories,
  and lifecycle states are not silently revived.
- The root-owned authority service sets `ProtectHome=false` and retains
  `ProtectSystem=strict` with an explicit `ReadWritePaths=/home` exception so
  `/home` is writable in its systemd sandbox solely for this fixed,
  descriptor-bounded normalizer to update an
  enrolled repository belonging to any trusted local account. The authority
  code—not per-account home-path policy—enforces the exact working-tree scope;
  repository commands still run only after the actual-caller credential drop.

## Explicitly unnecessary gates

- UID, GID, file or directory owner, mode bits, POSIX ACLs, shared groups,
  socket ownership, link count, or writable-ancestor metadata are local
  attribution, routing, execution, or diagnostic evidence only. They are not
  local authorization gates, filesystem ownership does not choose which
  account executes repository code, and a repository created by one trusted
  local account need not retain that account's restrictive umask for execution
  by another.
- A transient repository service keeps the caller's ordinary umask. Coordinator
  does not set `UMask=0000`, make a source root world-writable, or pre-emptively
  normalize an entire repository when only a contained working directory will
  execute.
- Same-host communication needs no agent-authored bearer token, signature,
  encryption layer, or duplicate cryptographic handshake.
- Non-secret broker catalogs, retained inventory, and bounded launch
  descriptors may be readable by every local account. Root ownership may still
  make generated descriptors immutable to those accounts.
- Provisioning the actual non-root local caller's execution record during a
  valid first-use adoption is not a new tenant grant and does not need separate
  case-by-case approval. Repeated deployments of this already-confirmed behavior
  likewise do not require another security-posture decision.
- Per-account writable-home drop-ins are unnecessary for the authority. They
  made ordinary first use depend on installer inventory even though every
  local account belongs to the same developer.

## Accepted risk and review triggers

- The developer accepts that any local account can read non-secret coordination
  and launch metadata. The benefit is simpler, faster, and more reliable
  cross-account operation on a single-developer host.
- The developer explicitly authorizes Coordinator to observe and terminate
  abandoned explicit headless/automation browser trees across these local
  accounts. Interactive browsers remain outside that selection; exact process
  identity and project/test lifecycle ownership prevent accidental cleanup of
  unrelated work.
- The developer explicitly authorizes Coordinator to create or refresh the
  routing/execution record for the actual non-root local caller during a valid
  first-use adoption, restore only the group-class ACL mask/access bits inside
  the exact descriptor-validated working directory after a successful port
  preflight, and execute it only as that caller. The accepted risk is that an
  existing named ACL entry for another account belonging to the same developer
  can become effective for those files. No named entry or world permission is
  added. Repository paths remain behind the local-host boundary; this does not
  authorize a public identity, remote worker, secret disclosure, disabled
  action, or disabled/retired repository.
- The developer accepts the root authority's narrowly configured writable
  `/home` sandbox view (`ProtectHome=false`, `ProtectSystem=strict`, and the
  explicit `/home` write exception) as
  the simple host capability for that bounded normalizer. A defect in the
  root authority could already mutate host services; exact path validation,
  descriptor walking, `.git`/symlink/hardlink exclusions, and actual-caller
  execution remain the prevention and containment layers.
- Revisit these assumptions before hosting mutually distrusting people on the
  same server, adding remote test workers, placing secrets in ordinary launch
  metadata, introducing regulated data, or changing the server from one
  developer's trusted machine into a multi-tenant service.

## Recorded confirmations

- [Single-developer local trust](docs/architecture/single-developer-local-trust.md)
  records the confirmed local-account and public-boundary model.
- [Universal test harness](docs/architecture/universal-test-harness.md) records
  non-secret manifest data, separate credential transport, exact identities,
  idempotent attempts, and project/test isolation.
- [DC-2026-08-01-TEST-CAPACITY-01](DecisionDetails/DC-2026-08-01-TEST-CAPACITY-01.md)
  records the confirmed single-developer deployment, disposable test data, and
  throughput-first test policy.
- [DC-2026-08-03-BROWSER-LIFECYCLE-01](DecisionDetails/DC-2026-08-03-BROWSER-LIFECYCLE-01.md)
  records the approved cross-account headless-browser accounting and cleanup
  boundary.
- [DC-2026-08-04-FIRST-USE-TRUST-01](DecisionDetails/DC-2026-08-04-FIRST-USE-TRUST-01.md)
  records actual-caller execution, the superseded filesystem-owner local-auth
  model, and the no-repeat-approval rule.
- [DC-2026-08-04-BUG-INTAKE-01](DecisionDetails/DC-2026-08-04-BUG-INTAKE-01.md)
  records the authority-independent open-bug registry, local-account access to
  its non-secret bounded records, public Console close boundary, and the
  non-governed local-test fallback.
