# Single-developer local trust

DevCoordinator is a multi-account product for one developer on one Linux
server. Unix accounts separate execution, attribution, accounting, and crash
domains; they are not security tenants.

## Local trust boundary

Local communication is authorized by the typed protocol and exact known
repository/resource identity. The system records a peer UID when available so
events remain attributable, but it never rejects a local client because of:

- UID or GID;
- file or directory owner;
- mode bits, POSIX ACLs, or shared-group membership;
- Unix-socket owner or mode;
- link count or a writable ancestor.

Local sockets are reachable by every account. The published broker catalog and
retained inventory are readable by every account. Client entries are routing
and attribution data, not an ACL. No agent-created token, signature, or local
cryptographic handshake is required.

The actual non-root local caller is the execution identity for repository code.
Coordinator records that UID durably for accounting, cleanup, and evidence; it
does not substitute the repository filesystem owner, root, or a control-plane
service account, and the repository command receives no elevated capability.
For a fresh launch, Coordinator first proves the exact port is free. It may then
descriptor-walk only the exact resolved, repository-contained working directory
and restore group-class `rwX` access there. The walk prunes `.git`, does not
follow symlinks, and silently skips multiply linked regular files. Directories
gain only group-class `rwX`; a regular file gains group-class `rw`, plus execute
only when it was already executable. Bytes, UID, GID, named ACL entries, world
bits, and regular-file executable intent do not change. With an extended POSIX
ACL, changing group-class bits changes its mask and may make an existing named
local-account entry effective. This fixed preparation never executes a
repository command. A port collision performs no metadata mutation.

The protocol still rejects malformed or oversized messages, unknown
repositories/resources, stale generations, disabled actions or lifecycle
states, invalid lifecycle transitions, ambiguous resource identity, path
escapes, symlinks at exact file boundaries, and replayed mutations with a
different operation identity. Those checks prevent accidental cross-project
interference rather than distrust another local user.

The service keeps the caller's ordinary umask. There is no `UMask=0000`, no
world-writable source-tree policy, and no broad normalization of a repository
root when only a contained working directory will execute.

The root lifecycle authority sets `ProtectHome=false` while keeping
`ProtectSystem=strict` and the explicit `ReadWritePaths=/home` exception. Its
own systemd sandbox can therefore perform that exact-cwd repair for any trusted
local account. This replaces brittle per-home installer exceptions. Repository
code does not inherit that view or root authority: it starts only after
`setpriv` drops to the recorded actual caller.

Public Google login, Console grants, domain authorization, Telegram ownership,
upstream identities, and secret-bearing credential transports remain product
authorization boundaries because they represent identities or sensitive data
outside the trusted local-account relationship.

## Isolation is not authorization

Dedicated systemd users, slices, cgroups, transient units, TTLs, and process
group cleanup remain for attribution, measurement, cancellation, crash
propagation, and cleanup scope. Ordinary tests have no per-account,
per-repository, or per-worker CPU, memory, PID, or job quota. Admission uses
current system `MemAvailable` and the learned target peak; CPU use is measured
but never gates execution. Protected control services retain their own host
reserve so a test cannot consume the memory needed to observe and recover the
system. Local accounts must never need shared-group membership or filesystem
metadata repair before using the product.

## Delivery behavior

Routine same-schema delivery is software-owned: one command runs focused source
checks, packages an immutable release, switches healthy services, exercises all
Console journeys, records every failure, and reports once. Test history is
disposable; user settings and project runtimes are retained. Full legacy
migration and metadata-security suites are manual diagnostics, not a gate for
ordinary releases.
