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

- All repositories' test runs, cases, artifacts, timing, rollups, queues,
  attempt state, and Test Store compatibility history are disposable. An
  incompatible DevCoordinator release creates an empty current Test Store; it
  does not back up, import, or migrate prior test data.
- Repository registrations, routes, Console users and their grants, Console
  settings, and authority/project configuration are retained control data.
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
  resource identity, generation, lifecycle state, path containment, and
  idempotent operation identity except for the deliberately simplified
  developer-directed Docker container removal described below. These prevent
  mistakes and stale work; they are not permissions and do not authenticate one
  local account, repository, agent, resource, or controller against another.
- Secret-bearing files and credential transports remain separate from ordinary
  non-secret local coordination metadata.
- A first-use repository mutation requires a non-root local caller using the
  typed protocol and a proven repository identity. Coordinator durably records
  that actual caller UID as the execution identity and may atomically create or
  refresh the corresponding non-authorizing routing record. Filesystem stat owner is
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
  mutation. Explicitly disabled Coordinator actions, repositories, and lifecycle
  states are not silently revived.
- The root-owned authority service sets `ProtectHome=false` and retains
  `ProtectSystem=strict` with an explicit `ReadWritePaths=/home` exception so
  `/home` is writable in its systemd sandbox solely for this fixed,
  descriptor-bounded normalizer to update an
  enrolled repository belonging to any trusted local account. The authority
  code—not per-account home-path policy—enforces the exact working-tree scope;
  repository commands still run only after the actual-caller credential drop.

## Explicitly unnecessary gates

- There is no local repository-, account-, UID-, GID-, group-, action-,
  resource-, controller-, source-, or provisioning-scoped authorization. Any
  trusted local agent may issue any supported command for any current resource
  on this server, including a resource associated with another repository or
  local account. The physical caller remains attribution and may select the
  non-root execution identity for newly launched repository code; neither fact
  is an access gate.
- Repository association is optional inventory, display, routing, accounting,
  and cleanup context. It is not membership and is never consulted to allow or
  deny a local request. A command targets a globally unique current immutable
  resource ID; repository context may narrow discovery for convenience but
  cannot expand or restrict command authority.
- Controller/source provenance may remain observational evidence where useful,
  but there is no active-controller permission, authoritative-source state, or
  binding lookup in local command admission. Exact native identity and stale
  generation/fingerprint checks prevent accidental replacement targeting
  without creating a controller authorization model.
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
- A sealed first-use Compose declaration that publishes only to numeric
  loopback addresses (`127.0.0.0/8` or `::1`) does not need separate
  administrator approval. Loopback publication is ordinary local development
  reachability on this single-developer host. Missing, wildcard, malformed, or
  non-loopback host addresses and other host-equivalent Compose features remain
  behind the explicit approval boundary.
- Per-account writable-home drop-ins are unnecessary for the authority. They
  made ordinary first use depend on installer inventory even though every
  local account belongs to the same developer.
- Developer-directed Docker container removal needs no repository ownership,
  cleanup grant, archive, lifecycle-state or mount check, Compose-role or
  database-binding classification, fingerprint, durable plan, confirmation
  phrase, or post-removal revalidation. The agent or user owns the semantic
  deletion decision. Coordinator resolves the selected current catalog target
  to its full native container ID and invokes only `docker rm -f <id>` without
  `-v`; named-volume deletion remains a separate data-retention decision.

## Accepted risk and review triggers

- The developer accepts that any local account can read non-secret coordination
  and launch metadata and command any supported current resource, regardless of
  repository association or the account/agent that created it. The benefit is a
  substantially simpler, faster, and more reliable single-developer control
  plane without administrator provisioning or false cross-repository denials.
- Delivery-efficiency repository projections are non-secret coordination and
  accounting metadata under this same trust decision. They may be readable
  across these local accounts only as strict bounded aggregates with opaque
  source identity and explicit unknown-counter coverage; prompts, source
  content, paths, credentials, personal data, and raw recorder events remain
  outside Coordinator. Revisit this projection if local accounts become
  mutually distrusting or the data boundary expands.
- The developer explicitly accepts that any local agent can remove any selected
  Docker container on this server in one call, including a running, mounted,
  Compose-managed, database-bound, or differently attributed container. This
  can interrupt a service and discards the container writable layer. The direct
  command does not remove named or anonymous volumes; volume deletion retains
  its separate explicit workflow. Revisit this acceptance if local accounts
  become mutually distrusting or container writable layers become retained
  project data.
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
- The developer explicitly authorizes the root-owned Coordinator
  administrative release to commission only an exact project
  `deploy/systemd/<unit>.service` non-root one-shot and its optional exact
  sibling timer. The source must pass the fixed safety contract, plan and
  status are non-mutating, and every install, replacement, one-shot start, or
  timer state change is bound to a revalidated source/installed-state plan
  fingerprint and replayable operation UUID. The interface accepts no unit
  payload, arbitrary path, shell command, root service, sibling selector, or
  implicit activation. This confirmation approves implementing the capability;
  it does not authorize running a particular retention job or enabling its
  timer without a separate exact apply confirmation.
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
- [DC-2026-08-10-SYSTEMD-COMMISSIONING-01](DecisionDetails/DC-2026-08-10-SYSTEMD-COMMISSIONING-01.md)
  records the project-sealed, confirmation-bound non-root one-shot and timer
  commissioning authority and the explicit no-activation-without-confirmation
  boundary.
