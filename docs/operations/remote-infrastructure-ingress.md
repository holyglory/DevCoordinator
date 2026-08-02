# Remote-infrastructure ingress operations

Status: source and deployment contract only. Nothing in this document records
a live installation, an opened firewall, an issued production certificate, or
an accepted report. The laboratory is live-ready only after every gate below
has produced retained evidence.

## Boundary

`spectre.classified.guru:9443` is a dedicated TLS 1.3 listener for enrolled
observers. It is not a browser, Console, repository, SSH, WinRM, or generic API
endpoint. Each TCP connection must present one private-CA client certificate,
send exactly one bounded `POST /v1/infrastructure/observations`, receive one
bounded response, and close. A reverse proxy must not terminate client TLS.
If a load balancer is later approved, it must use L4 TCP pass-through and
preserve the actual source address; the first laboratory should connect
directly.

The service account is the fixed non-login user `devcoord-infra-ingress`. Its
broker account is `spectre-infrastructure-ingress`. The root-only offline
access command can grant exactly these two operations and no others:

- `infrastructure.verification_context`
- `infrastructure.ingest`

One grant expires within 30 days and must be replaced with a new receipted
request before expiry. `ingress.disable` immediately disables both grants.
The ingress never opens the Coordinator database.

## Required inputs

Do not begin a live deployment until all of these inputs are approved and
retained:

1. An exact reviewed source commit and a source-readiness test receipt.
2. The approved server-wide maintenance transaction, rollback artifact and
   schema-v14 readiness receipt. Clone rehearsal has passed, but live cutover
   remains a separate operation.
3. A dedicated, currently valid server certificate and private key for
   `spectre.classified.guru`; the leaf has exactly that DNS SAN, exactly the
   Server Authentication EKU, non-CA signing Key Usage, and is separate from
   the private observer CA. Give every replacement a monotonically reviewed
   positive generation and a validity window no longer than seven days.
   Preflight binds that generation to the exact leaf DER SHA-256 and exact
   `notBefore`/`notAfter` seconds before bind. The short, exact leaf generation
   is the Windows observer's fail-closed server-revocation compensation; a
   hostname match or SPKI pin alone is insufficient.
4. Exactly one self-signed private observer root certificate and exactly one
   issuer-signed current CRL. The CA private key stays offline and never
   appears on the ingress host.
5. A client leaf whose actual validity is at most 30 days, whose EKU set is
   exactly Client Authentication, and whose Key Usage permits digital
   signatures but not certificate or CRL signing.
6. A separate host-generated JWS RSA key and an owner-approved schema-v14
   enrollment receipt binding its canonical SPKI, digest, key ID, certificate
   fingerprint, generation, validity bounds, agent, host, cell and VM scope.
7. Approved host and provider firewall changes that expose only TCP 9443 to
   the intended observer source policy. The broker Unix socket and database
   remain local.
8. An offline, reviewed wheel set containing the exact hash-locked
   `PyYAML==6.0.3`, `cryptography==49.0.0`, `cffi==2.0.0` and
   `pycparser==2.22` CPython 3.14/Linux x86-64 artifacts from
   `skills/codex-dev-coordinator/requirements-infrastructure-ingress.txt`.
   Versions of cryptography
   46.0.5 and earlier are prohibited because later upstream releases corrected
   CVE-2026-34073 and CVE-2026-39892. Startup independently rejects any other
   cryptography version or missing API, while `pip check` proves its declared
   dependency closure.

## Files and ownership

Install the repository-owned deployment files without editing their installed
copies:

| Source | Installed destination | Required owner/mode |
| --- | --- | --- |
| `deploy/devcoordinator-infrastructure-ingress.sysusers.conf` | `/usr/lib/sysusers.d/devcoordinator-infrastructure-ingress.conf` | root:root 0644 |
| `deploy/devcoordinator-infrastructure-ingress.tmpfiles.conf` | `/usr/lib/tmpfiles.d/devcoordinator-infrastructure-ingress.conf` | root:root 0644 |
| `deploy/devcoordinator-infrastructure-ingress.service` | `/etc/systemd/system/devcoordinator-infrastructure-ingress.service` | root:root 0644 |
| reviewed config derived from `deploy/infrastructure-ingress-config.example.json` | `/etc/devcoordinator/infrastructure-ingress/config.json` | root:devcoord-infra-ingress 0640 |
| server full chain | `/etc/devcoordinator/infrastructure-ingress/server-fullchain.pem` | root:devcoord-infra-ingress 0640 |
| server private key | `/etc/devcoordinator/infrastructure-ingress/server-key.pem` | root:devcoord-infra-ingress 0640 |
| exact client root | `/etc/devcoordinator/infrastructure-ingress/client-ca.pem` | root:devcoord-infra-ingress 0640 |
| current client CRL | `/etc/devcoordinator/infrastructure-ingress/client-ca.crl.pem` | root:devcoord-infra-ingress 0640 |

Every trusted file must be one regular, single-link, non-symlink file. Every
path component must be non-symlink. systemd owns
`/var/lib/devcoordinator-infrastructure-ingress/envelopes` as the service UID
with mode 0700. The broker owns
`/var/lib/devcoordinator/infrastructure-envelope-artifacts` as root with mode
0700. Ingress can read neither the broker artifact store nor the database.

`/opt/devcoordinator-authority` is one root-owned shared authority virtual
environment for both the broker and ingress. This keeps broker-side PS256
reverification on the same reviewed cryptographic library as ingress and
prevents either service from falling back to distribution or user packages.
Never build or rewrite this live path in place. Prepare one separate,
root-owned, non-group/other-writable offline wheelhouse containing only the
reviewed wheels for the exact lock, retain its independently reviewed
manifest and hashes, and activate it through the repository transaction:

```text
/usr/bin/python3 -I -B \
  /home/DevCoordinator/scripts/install_authority_runtime.py apply \
  --wheelhouse /root/APPROVED_WHEELHOUSE \
  --transaction-dir /root/PRIVATE_TRANSACTION/authority-runtime
/usr/bin/python3 -I -B /home/DevCoordinator/scripts/verify_authority_runtime.py \
  verify
```

The placeholder wheelhouse is not an instruction to invent a path: replace it
with the reviewed artifact location. The transaction hashes the wheel set,
builds an isolated candidate with `--no-index --require-hashes`, removes venv
symlinks, normalizes root ownership, and creates a candidate manifest before
the candidate interpreter can execute. It then stops both authority-runtime
consumers, retains the verified previous generation, atomically renames and
fsyncs the candidate runtime and manifest, verifies the active pair, and
restores the exact prior active/inactive service states. A failure after either
rename automatically restores the retained pair and preserves the failed
generation for diagnosis.

The live create-new manifest is
`/etc/devcoordinator/authority-runtime-manifest.json`; it binds every runtime
file, the dependency-lock digest and the CPython 3.14/Linux x86-64 contract.
Both services independently verify it with the system interpreter before any
root process executes the authority interpreter. Any symlink, hard link,
non-root runtime byte, group/other-writable entry, hash drift, file-set drift
or interpreter drift fails closed. Never invoke the manifest `create` action
against a live runtime and never rewrite a live manifest in place.

Retain the transaction directory until the deployment is accepted. To reverse
one successfully applied generation, use its exact journal; rollback first
verifies that the active generation has not drifted, stops both consumers,
atomically restores the retained runtime and manifest, verifies them, and
restores the recorded service states:

```text
/usr/bin/python3 -I -B \
  /home/DevCoordinator/scripts/install_authority_runtime.py rollback \
  --transaction-dir /root/PRIVATE_TRANSACTION/authority-runtime
```

## Offline broker access receipt

This mutation belongs inside the approved broker-offline maintenance
transaction. The command refuses a running broker through the same exclusive
service lock and refuses any database whose current schema is not exactly 14.
It also resolves `devcoord-infra-ingress` through the operating system and
requires its real non-root UID to equal the root-owned request.

Copy `deploy/infrastructure-ingress-access-request.example.json` into the
private maintenance transaction directory. Replace its request ID with a new
canonical UUID, its UID with `id -u devcoord-infra-ingress`, and its expiry
with an exact future Unix second no more than 30 days away. Keep the request
root-owned, mode 0600 and single-link, then run:

```text
/usr/bin/python3 -I -B \
  /home/DevCoordinator/scripts/run_verified_authority.py -- \
  /home/DevCoordinator/skills/codex-dev-coordinator/scripts/dev_coordinator.py \
  broker infrastructure-ingress-access \
  --database /var/lib/devcoordinator/coordinator.sqlite3 \
  --request-file /root/PRIVATE_TRANSACTION/ingress-access.json
```

The result must have
`schema=spectre.infrastructure.ingress-access-receipt.v1`,
`replayed=false`, the exact UID/account, exactly the two operations above,
and `authority_schema_version=14`. Retain the request, canonical request and
result digests, and receipt. Put the returned canonical lowercase UUID
`authority_generation` into the ingress config without numeric conversion.
Repeating the exact request returns the same receipt with
`replayed=true`; reusing its request ID with different material fails.

For emergency removal, create a new root-owned request from
`deploy/infrastructure-ingress-disable-request.example.json` and run the same
command. The receipt must say `status=disabled` and `operations=[]`.

The Console/API reader is an independent, expiring grant. Copy
`deploy/infrastructure-reader-access-request.example.json`, bind
`service_account` to the real Console service account (currently
`holyglory`), bind `uid` to `id -u holyglory`, choose a dedicated broker
`account_id`, and set an expiry no more than 30 days away. Execute it inside
the same broker-offline boundary:

```text
/usr/bin/python3 -I -B \
  /home/DevCoordinator/scripts/run_verified_authority.py -- \
  /home/DevCoordinator/skills/codex-dev-coordinator/scripts/dev_coordinator.py \
  broker infrastructure-reader-access \
  --database /var/lib/devcoordinator/coordinator.sqlite3 \
  --request-file /root/PRIVATE_TRANSACTION/reader-access.json
```

The receipt must have
`schema=spectre.infrastructure.reader-access-receipt.v1`,
`role=infrastructure-reader`, and exactly
`operations=["infrastructure.read"]`. It grants no ingest or verification
authority. Retain the request and receipt. Revoke it with a new request based
on `deploy/infrastructure-reader-disable-request.example.json`; the resulting
receipt must have `status=disabled` and no operations.

## Configuration and PKI checks

Replace every placeholder in the example config:

- `broker.expected_socket_gid` is the exact GID of
  `devcoordinator-clients`;
- `broker.authority_generation` is the exact canonical lowercase UUID
  generation returned by the access receipt;
- all four `tls.server_certificate_*` values come from the actual first leaf
  in `server-fullchain.pem`: a positive monotonic generation, DER SHA-256,
  exact Unix `notBefore`, and exact Unix `notAfter`; the interval must be no
  more than 604800 seconds;
- `listen.host` remains `127.0.0.1` throughout local qualification; changing
  it to `0.0.0.0` is a separate external-listener promotion gate below;
- `listen.public_host` remains exactly
  `spectre.classified.guru:9443`;
- `artifact_root` remains the systemd-owned staging path.

The private observer root must be an exact current self-signed CA with critical
CA Basic Constraints, critical certificate/CRL-signing Key Usage and a Subject
Key Identifier. The CRL issuer and Authority Key Identifier must match that
root, its signature must verify, `lastUpdate` cannot be future or older than
the configured six-hour bound, and `nextUpdate` must be future. Missing,
unreadable, stale, expired, future or wrong-issuer CRLs fail every new
connection.

Rotate certificates and CRLs through a same-directory atomic replacement:
write a new root-owned file, set its final owner and mode, fsync the file,
rename over the stable path and fsync the directory. Never copy the observer
CA private key onto this host. A service restart is not required for a CRL
change because every connection rebuilds trust, but the new file must pass the
preflight before the rotation is considered successful.

The server leaf is different: replace the full chain, key and their exact
generation fields as one reviewed deployment transaction and restart the
ingress. Startup rejects a leaf whose DER digest or exact validity seconds
differ from configuration. Retain the superseded generation and deployment
receipt; never silently reuse a generation number.

## Windows-observer central readiness export

After schema 14, exact host/agent/certificate enrollment, ingress access,
externally promoted configuration, broker socket and both PKI chains are live,
root exports one canonical create-new receipt valid for at most 15 minutes:

```text
/usr/bin/python3 -I -B \
  /home/DevCoordinator/scripts/run_verified_authority.py -- \
  /home/DevCoordinator/skills/codex-dev-coordinator/scripts/dev_coordinator.py \
  broker infrastructure-observer-readiness \
  --database /var/lib/devcoordinator/coordinator.sqlite3 \
  --host-provision-receipt /root/PRIVATE_TRANSACTION/host-receipt.json \
  --agent-provision-receipt /root/PRIVATE_TRANSACTION/agent-receipt.json \
  --certificate-provision-receipt /root/PRIVATE_TRANSACTION/certificate-receipt.json \
  --ingress-access-receipt /root/PRIVATE_TRANSACTION/ingress-access-receipt.json \
  --reader-access-receipt /root/PRIVATE_TRANSACTION/reader-access-receipt.json \
  --ingress-configuration /etc/devcoordinator/infrastructure-ingress/config.json \
  --client-certificate /root/PRIVATE_TRANSACTION/observer-client-leaf.pem \
  --server-trust-root /root/PRIVATE_TRANSACTION/server-trust-root.pem \
  --output /root/PRIVATE_TRANSACTION/observer-central-readiness.json \
  --validity-seconds 900
```

The client input is the public leaf only; neither the Windows TLS private key,
the Windows JWS private key nor the client-CA private key may be copied here.
The exporter rechecks the immutable receipts against the live read-only
authority, exact two-operation ingress ACL and dedicated UID, exact
one-operation Console reader ACL, current CRL, actual certificate/key pair,
exact server root, exact leaf/SPKI generation, broker-socket identity and
local external-promoted listener. Any mismatch creates no receipt. This short
receipt enables only the separately reviewed disabled Windows task; it is not
evidence that an observation was accepted.

## Loopback qualification gates

Install an explicit host-firewall deny for external TCP 9443 before the first
service start and retain the rule evidence. With `listen.host` still exactly
`127.0.0.1`, run the service preflight under its real systemd identity:

```text
systemctl daemon-reload
systemctl start devcoordinator-infrastructure-ingress.service
systemctl status devcoordinator-infrastructure-ingress.service
```

These are live mutations and require the approved deployment window. The
unit's `ExecStartPre` checks the closed config, exact dependency version,
private files, current CA/CRL, server key pair, staging owner/mode and broker
identity expectations before binding. The actual Unix-socket owner, group,
mode and authority generation are independently checked on each broker call.

Do not promote the ingress beyond loopback until an isolated deployed test,
connecting to `127.0.0.1:9443` while using the exact
`spectre.classified.guru` TLS server name and HTTP Host, proves:

- valid private-CA mTLS plus valid canonical PS256 produces one broker-bound
  accepted artifact;
- wrong CA, wrong/missing EKU, future, expired, over-30-day and revoked leaves
  never call ingest;
- missing, future, stale, expired and wrong-issuer CRLs fail closed;
- wrong fingerprint, generation, key ID, SPKI, signature, scope and canonical
  payload fail;
- compression, chunked transfer, duplicate headers, oversized/slow/pipelined
  requests, connection reuse, per-IP/per-certificate limits and concurrency
  saturation fail within bounds;
- a lost response and ingress restart reuse the artifact-derived operation ID
  and do not create a second authority outcome;
- broker rejection leaves only a non-current safe CAS orphan;
- ingress restart, broker restart and CRL rotation recover without accepting
  unchecked state.

After every loopback check passes, atomically replace only `listen.host` with
`0.0.0.0`, preserving the protected file identity rules, then restart and
prove the listener identity while the external deny remains active. Only then
may the approved firewall policy replace that deny with a narrow TCP-9443
source allow. Test one real enrolled observer connection, restore the deny on
any failure, and never use a temporary allow-all interval. The public Console
must remain independently available throughout.

## Evidence and rollback

Logs contain only event, typed code, broker operation ID and artifact digest;
they must never contain the JWS, certificate, observation or key material.
Accepted evidence is the broker-owned mode-0400 CAS object plus its
digest-bound database row. Staging or broker CAS objects with no database
binding are retained orphans, not accepted evidence. No garbage collector is
approved in v1.

Rollback closes the external firewall, stops the ingress unit, applies a new
receipted `ingress.disable` request inside the broker-offline transaction,
revokes the exact client certificate generation, publishes a fresh CRL, and
retains logs, receipts, staging objects and broker evidence for audit. Do not
delete artifacts or reuse the service UID, certificate generation, request ID,
JWS key or operation ID as part of rollback.
