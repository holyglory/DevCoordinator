# DC-2026-07-29-REMOTE-INFRA-01 supporting record

## User intent

The operator is building a global, security-critical multi-domain platform and
asked to use the existing Windows Server 2022 Hyper-V host as the first
laboratory, verify the application there, and add those systems to the shared
Console. They also explicitly corrected the scope so unrelated
Khan/`SWITH VM` infrastructure is not treated as part of SPECTRE.

## Options evaluated

### Put the six VMs on the existing Servers page

This is superficially quick but false. Existing Server rows are local
Coordinator-managed processes or web-serving containers with local lifecycle
actions, logs, ports, routes, and repository ownership. A Hyper-V VM is a
different object and a VM name is not a local process identity. This option
would imply controls and failure independence that do not exist.

### Let the Console SSH or WinRM into the Hyper-V host on every page load

This avoids a new data model but makes UI reads execute privileged remote
administration, requires inbound management exposure or a permanent tunnel,
couples page availability to the remote host, and provides weak replay,
retention, and complete-roster semantics. It was excluded.

### Let the Windows observer write directly into the central database

This minimizes one hop but distributes database credentials and schema
authority to every managed host. Compromise of one observer would broaden into
control-plane database access, rotations become fleet-wide, and the broker
cannot consistently enforce identity, scope, replay, or audit invariants. It
was excluded.

### Add a file-backed Console-only snapshot importer

This is suitable only as an isolated fixture. It would create a second
writable authority beside the Coordinator, lose transactional enrollment and
replay state, and become a temporary bridge that is easy to mistake for the
production path. It was excluded from the release path.

### Enrolled outbound observer, dedicated mTLS/JWS ingress, broker authority

The Hyper-V host observes locally with SYSTEM read privileges and initiates an
outbound connection. A separate minimal ingress validates transport identity,
the signed versioned report, replay state, and exact enrollment, then submits
one narrow local operation to the Coordinator. Before acceptance, the broker
independently verifies and copies the exact compact JWS from a private staging
CAS into its own root-owned CAS; rows retain only the digest and opaque
locator. The broker commits current state, audit and signed-envelope evidence;
the Console reads a bounded projection. This costs a new service, schema, PKI
lifecycle, Windows observer, evidence retention and tests, but it preserves
least privilege, immutable identities, verifiable source evidence,
offline/stale behavior, future multi-host expansion, and one central
authority.

## Consequences and reversibility

The first release is read-only and cannot perform a remote Hyper-V mutation.
The dedicated page can be removed without altering existing local
Server/Docker/route behavior, while retained broker observations remain
auditable. A later remote-control plane is not a PATCH to this observation
endpoint: it requires its own command ledger, explicit grants, plan/approval,
idempotency, fencing, acknowledgement, and recovery decision.

The current single-host lab remains one failure domain. Multiple VMs increase
role separation and permit guest/process failure tests but do not survive loss
of the Windows host, shared storage, power, switch, or site. Global production
promotion also requires a separate HA control-plane store; the SPECTRE
operational database is not silently reused.

The source authority advances to schema v14 for real verification-key
identity. Each certificate generation binds exact PS256, canonical DER
RSA-3072-or-stronger
SubjectPublicKeyInfo and its SHA-256 digest in addition to its certificate
fingerprint and key ID. A dedicated ingress can retrieve only one exact public
verification context by fingerprint plus generation; it cannot enumerate
certificates, and ingest repeats the enrollment, key digest, revocation,
validity and scope checks. Matching `kid` text is therefore not sufficient to
substitute another key. The RSA modulus must be odd and 3,072–8,192 bits with
public exponent exactly 65,537. The SPKI digest is globally unique across all
agents and generations, so every new generation requires a newly generated
JWS key; cert-only renewal with the same signing key is not silently modeled
as a new generation.

Enrollment is deliberately local and offline rather than a new remote
administration plane. Effective UID 0 applies one closed JSON request while
holding the broker lifetime lock; the mutation and immutable request/result
receipt commit atomically. Exact replay is idempotent, conflicting request-ID
reuse fails, private key fields are outside the request schema, and
certificate rotation retains independently revocable overlapping generations.
The v1 cryptoperiod is at most 30 days and overlap between any unrevoked
generations of one agent is at most 72 hours. A seven-day period would reduce
key exposure but, without verified automatic issuance and rotation, would
create disproportionate manual-renewal and availability risk; a much longer
period would extend compromise exposure. The selected bound balances security
and operational continuity through the end of each cryptoperiod. Once
automatic rotation is proven, reducing the maximum to seven days requires a
separate recorded decision and boundary-test update.
Public-ingress UIDs are rejected if they have broader repository or runtime
authority, and that isolation is rechecked for ingest and verification-context
authorization. The laboratory Console/API UID may combine its existing
repository authority with the exact expiring non-mutating read grant; a
production reader bridge may be split to its own UID.

The separately supervised network ingress now exists in source. It uses one
dedicated non-login account, TLS 1.3 only, an exact private client root, a
fresh issuer-authenticated CRL rebuilt into each connection context, exact
Client Authentication EKU, actual leaf validity equal to the enrolled
maximum-30-day window, closed canonical PS256, strict single-request HTTP
framing, bounded time/concurrency/rates and broker replay as the only durable
authority. The ingress stages the exact JWS in a private CAS; the broker
reopens it without trusting a caller path, verifies owner/mode/type/link
count/size/digest and publishes its own mode-0400 copy before a row can claim
`evidence_available=true`. Safe unreferenced staging or broker CAS objects may
remain after rejection or lost replies; they are not current evidence and no
v1 garbage collector is authorized.

The ingress account receives exactly verification-context plus ingest through
one root-only broker-offline closed request. The request binds the fixed
system account, actual numeric non-root UID, fixed broker account and expiry;
the ACL mutation and immutable receipt commit atomically. A grant lasts no
more than 30 days, exact replay is idempotent, conflicting request-ID reuse
fails, and a separately receipted disable request removes both grants
immediately. Reusing the broader Console UID or an indefinite grant was
excluded because it would couple the public edge to unrelated authority or
leave access beyond the certificate renewal horizon.

Server authentication has a separate lifecycle from the 30-day observer
client/JWS generation. The Windows transport can require the exact DNS SAN,
server trust root and SPKI, but its reviewed path does not produce an online
server-revocation result. Treating those pins as revocation, using only the
platform hostname check, or permitting a wildcard/multi-SAN leaf was excluded.
The selected compensation binds an exact monotonically reviewed server-leaf
generation to its DER SHA-256 and exact validity seconds, limits that leaf to
seven days, and repeats the binding in the at-most-15-minute central readiness
receipt. The ingress startup independently compares the configured generation
facts to the actual leaf before bind. This adds rotation work but bounds a
revoked-yet-still-pinned server identity without shortening the independent
observer client/JWS generation to an operationally unproven seven-day cycle.

The central readiness exporter is root-only and read-only with respect to the
authority. Before it creates one canonical protected receipt, it reconciles
the immutable host, agent, certificate and ingress-access receipts with the
exact live schema-v14 rows; rechecks the dedicated ingress UID and two-operation
ACL; validates the config, broker socket, current client CA/CRL and public
client leaf; validates the actual server certificate/key pair through the
exact pinned root; and checks the promoted local listener. It accepts public
certificate material only, never a private observer or CA key. A mismatch or
expired dependency creates no receipt. The receipt is activation input, not
proof of a successful remote observation.

The ingress dependency closure is the exact hash-locked CPython 3.14/Linux
x86-64 set `cryptography==49.0.0`, `cffi==2.0.0` and `pycparser==2.22`.
Retaining the initially available `cryptography==46.0.5` was excluded after
upstream security releases corrected CVE-2026-34073 and CVE-2026-39892; exact
49.0.0 API and failure-shaped ingress tests pass in an isolated environment.
Deployment first binds only `127.0.0.1:9443` behind an explicit external deny,
so negative TLS/JWS/framing/replay tests cannot accidentally publish an
unqualified listener. External `0.0.0.0:9443` binding and its narrow
source-firewall allow are a later atomic promotion gate after loopback proof.

The shared authority runtime is not built or patched in place. A root-only
transaction hashes the approved offline wheel set, builds a candidate outside
the live path with the exact lock, removes symlinks, normalizes ownership, and
creates a manifest that binds the future live root. Static file-set, mode and
digest comparison completes before the candidate interpreter is allowed to
execute its contract or dependency probes. Activation stops both broker and
ingress consumers, retains the verified previous runtime/manifest pair,
renames and fsyncs each candidate object, verifies the active pair, and
restores the exact recorded service states. Any partial activation
automatically restores the retained pair; an explicit rollback additionally
refuses to overwrite an active generation that has drifted. Root maintenance
commands use a system-Python wrapper that verifies this manifest before
`execve` of the pinned interpreter. Direct live-path venv mutation, ambient
`python3`, and create-in-place manifest replacement were excluded because
they can execute a mixed or unauthenticated root dependency generation.

The Console reader has its own expiring immutable receipt and exactly one
`infrastructure.read` operation. Central readiness binds that exact receipt
and current OS UID in addition to the two-operation ingress receipt. The
Python HTTP adapter serializes the infrastructure result as compact canonical
UTF-8-compatible JSON. Broker pagination stops before either 100 hosts or a
12 MiB canonical projection, leaving headroom below the 16 MiB broker result
frame and returning an exact continuation cursor rather than truncating a
host.

The laboratory Console reveals Hyper-V management addresses, immutable host
identities, cell classification and security incidents only to configured
owners/access administrators. The server enforces that boundary before cursor
validation or any Coordinator read; hiding controls in the browser is not the
authorization mechanism. The owner-only Servers destination places the real
read-only Hyper-V collection first, while `#/infrastructure` provides its
detailed projection. A disabled cell or host enrollment remains
administratively inactive regardless of saved telemetry freshness. This
coarse owner boundary is intentionally limited to the laboratory and is not a
production multi-cell clearance model.

Source tests are not deployment evidence. `mtls_verified` is valid only after
the deployed listener has performed the checks above against the actual leaf
and current CRL. Live wrong-CA/EKU/time/revocation/signature/framing/overload/
restart tests and a real accepted artifact remain mandatory.

Schema v13 certificate rows cannot be upgraded by guessing public material.
An empty v13 certificate table upgrades additively; a populated one blocks v14
activation until an audited offline reenrollment provides the real SPKI. The
live schema-v4 authority remains untouched. The maintenance source now targets
v4-to-v14, and exact service-owner, UID-0 and UID-1000 clones have passed
read-only integrity, foreign-key, semantic, representative legacy and empty
infrastructure-projection verification. After both writer-free checkpoints,
the source transaction runs the guarded offline upgrader separately for the
root-owned service database and Console-UID-owned client database, retains
distinct create-new mode-0400 receipts, and only then runs protected-profile
backfill plus its idempotency pass. That removes the stale source-path blocker
but is not a live cutover: the approved maintenance transaction, rollback
artifacts, exact live-candidate readiness, service convergence and rollback
proof remain required.

## Acceptance source

The binding implementation and live gates are in
`docs/architecture/remote-infrastructure-observation.md`.
