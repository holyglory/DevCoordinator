# First-use actual-caller execution

## Confirmed assumptions

This decision applies the user-confirmed [security assumptions](../security-assumptions.md): one developer owns every local Unix account; those accounts are attribution, accounting, execution, and crash domains rather than mutually distrusting tenants; repository identity, generation, lifecycle, path containment, TTL, cleanup, and idempotency remain required; public Google/domain/Telegram/upstream identities and secrets remain outside this local trust boundary.

## Decision

A valid first-use repository adoption accepts a typed request from an actual
non-root local caller, proves the repository identity without making Unix
metadata an authorization gate, and atomically creates or refreshes that
caller's routing/execution record when needed. The actual peer UID is both the
durably recorded execution identity and audit attribution. Repository
filesystem stat owner never selects execution, and repository code never runs
as root or as the control-plane identity. Explicitly disabled Coordinator
actions, enrollments, repositories, and lifecycle states remain disabled.
Deploying this established behavior does not require another security-posture
approval each time.

A sealed effective Compose model may publish declared ports without separate
administrator approval only when every published host address is a numeric
loopback address (`127.0.0.0/8` or `::1`). The evidence still records the
published-port feature. An omitted, wildcard, malformed, or non-loopback host
address remains approval-required, as do privileged mode, host namespaces,
host bind mounts, devices, added capabilities, the Docker socket, and other
host-equivalent features. This keeps ordinary local previews fast without
turning first use into implicit public exposure.

Superseded in part by
[DC-2026-08-22-COMPOSE-DECLARED-HOST-CAPABILITIES-01](DC-2026-08-22-COMPOSE-DECLARED-HOST-CAPABILITIES-01.md):
service-level Compose bind mounts classified as `host_bind_mount`, local
volume-driver binds classified as `volume_driver_bind`, and `cap_add` classified
as `added_capabilities` remain complete risk evidence but no longer require
separate approval. Every other approval boundary in this record remains
unchanged. Later references below to requiring approval for every other
host-equivalent feature are historical for those three exempt categories.

A protected read-only control-plane client may use any one current installed
repository as its transport anchor and dynamically merge the broker-issued
route for a newer adopted repository. If that protected account has no row for
the target, the resolver may reuse another trusted local account's enabled
route for the same exact repository. Enrollment expiry remains diagnostic
evidence rather than a local permission boundary. The route account selects an
existing typed repository/resource/action policy; the kernel peer UID remains
the caller and attribution identity. If matching account rows exist but none
is enabled, that explicit account-level block never falls through to another
account. A revoked repository generation also remains blocked. This read path
cannot adopt, revive, start, or otherwise mutate a repository.
Enabled policy UIDs within one account form a union: disabling one UID row is
not an account-wide veto while another matching UID remains enabled. An
account-wide block disables every matching enrollment or uses the exact
repository/action/lifecycle revocation.

When the actual caller and live source tree belong to different local accounts,
the Coordinator first proves that the requested port is free, then performs a
descriptor-anchored walk of only the exact resolved and validated working
directory. It prunes `.git`, never follows symlinks, silently skips regular
files with more than one hard link, and adds only group-class `rwX` bits:
`rwX` on directories, `rw` on regular non-executables, and `rwx` only on
regular files that were already executable. It changes no bytes, UID, GID,
named ACL entry, world bit, or regular-file executable intent. On an extended
POSIX ACL, the group-class bits are the ACL mask, so the mask and the effective
access of existing named local-account entries may change. An occupied port
causes no normalization. This is a narrow fresh-launch compatibility step, not
whole-repository or world-access normalization.

The root-owned authority service sets `ProtectHome=false` while retaining
`ProtectSystem=strict` and the explicit `ReadWritePaths=/home` exception. This
makes its writable `/home` view effective so the fixed normalizer works for
present and future trusted local accounts without installer-maintained
per-home exceptions. This is a
host capability of the existing root lifecycle authority, not a capability
given to repository code. Exact working-tree containment remains enforced by
the descriptor-walking implementation before the actual-caller credential
drop.

The transient unit then keeps the caller UID and primary GID and may add
already-observed non-root filesystem GIDs along the resolved working-directory
chain as per-unit supplementary compatibility groups for ancestor traversal.
This creates no account membership or shared system group and does not
authorize the request or select its UID. The service retains the caller's
ordinary umask; Coordinator does not set `UMask=0000`.

Systemd starts one fixed Coordinator-owned `setpriv` shim from the universally
reachable filesystem root. The shim drops to the operation's durably recorded
actual caller UID, primary GID, and explicit per-unit supplementary groups;
only then does the Coordinator-trusted `env --chdir` exec boundary enter the
already resolved, repository-contained working directory and execute the
caller's structured argv. No repository-controlled command executes before the
credential drop. After listener and cgroup ownership are proven, the
Coordinator reads the stable systemd MainPID through `/proc` and requires all
four Linux UID fields to equal the actual caller before publishing the service
as ready. This avoids systemd's pre-exec `CHDIR` ordering without using a
shell, executing repository code as root, granting it capabilities, or changing
the validated cwd.

This decision explicitly supersedes the local-account authorization and
filesystem-owner execution-selection portions of
[DC-2026-07-15-HOST-01](DC-2026-07-15-HOST-01.md). Its single service-owned
authority, exact repository/resource identity, lifecycle fencing, scoped host
capabilities, and public/secret boundaries remain in force.

## Alternatives and rationale

- Manual administrator enrollment for each local account was rejected because it blocked normal first use and recreated a multi-tenant workflow on a single-developer host.
- Selecting the repository filesystem owner was rejected because stat metadata is neither caller intent nor authorization and caused cross-account permission failures before the broker could act.
- Running repository code as root or the control-plane identity was rejected because it loses the real caller's attribution and unnecessarily widens execution authority.
- Removing the durable execution record entirely was rejected because the actual non-root caller still needs stable accounting, cleanup, replay, and diagnostic evidence.
- Requiring agents or users to repair modes, ownership, ACLs, or shared groups
  was rejected because those are not authorization boundaries on this
  single-developer host. Bounded working-directory ACL-mask normalization is
  faster and keeps repository execution non-root.
- Setting `UMask=0000`, making a repository world-writable, or normalizing a
  whole source root was rejected because each changes more metadata than the
  selected service working directory requires.
- Maintaining an installer-generated writable-path exception for each local
  home was rejected because it reintroduced account enrollment as an execution
  prerequisite and caused the fixed normalizer to fail inside the authority's
  otherwise read-only home sandbox.
- Requiring administrator approval for a port explicitly bound only to
  loopback was rejected because it treated local development reachability like
  public host exposure and blocked valid first use. Silently approving an
  omitted, wildcard, malformed, or non-loopback address was rejected because
  that can expose a repository service beyond the trusted local-host boundary.

## Verification

The regression must use a non-root caller whose UID differs from the repository
filesystem stat owner and which has no repository routing/execution record. One
atomic first-use request must retain that real peer UID in operation evidence,
create or refresh only the caller's record, run the exact structured service as
that caller, prove the ready MainPID's real/effective/saved/filesystem UIDs all
equal that caller, and remain idempotent under replay. A mismatched or
unprovable UID must stop the exact transient unit before returning a typed
launch-infrastructure failure. It must not require client-side traversal,
manual chmod/chown/ACL repair, or account group membership. Seed the fixture
with a generated executable owned by a third local account at mode `0700`;
prove Coordinator restores only its group-class execute/mask bit while leaving
world bits, bytes, UID, GID, named ACL entries, and executable intent unchanged.
Also prove `.git` remains unchanged, an external symlink is not followed, a
multiply linked regular file is skipped, a regular non-executable does not gain
execute, and a pre-launch port conflict performs no normalization. Assert the
unit contains no `UMask=0000`, repository code receives no capability, and no
source root is broadly normalized. A per-unit filesystem compatibility group
must not replace or authorize the caller UID, and group 0 must never be added.
It must never execute the service as the filesystem owner, root, or a
control-plane account. Explicit disabled action/lifecycle state must still fail
with a typed, actionable error, and no local trust rule may weaken public
identity or secret handling.
Exercise both IPv4 and IPv6 loopback-only published ports without administrator
approval and require the retained evidence to report `published_host_ports`.
Then prove an absent host address, a wildcard, a non-loopback address, and every
other host-equivalent feature still fail without explicit approval.
Use a long-lived protected API identity with an anchor enrollment but no row
for a repository adopted later by another local account. Prove it resolves the
exact broker-issued repository and server IDs, captures logs through the other
enabled local route, and retains its physical peer UID. Then leave the matching
account with no enabled enrollment and disable the exact runtime status action;
each must remain denied instead of falling through to another local policy.
The topology verifier must also reject an authority unit whose writable paths
omit `/home` or whose `ProtectHome` setting would override that exception,
while continuing to keep unrelated protected home roots outside repository
execution.
