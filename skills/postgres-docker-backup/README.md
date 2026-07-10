# Postgres Docker Backup

`postgres-docker-backup` creates, verifies, and restores logical PostgreSQL
backups for explicitly selected Docker containers. `SKILL.md` is the
authoritative workflow and safety contract.

## What It Provides

- Database-scoped custom (`pg_dump -Fc`) and plain SQL backups.
- Whole-cluster `pg_dumpall` backups with an explicit, separate scope.
- Private `0700` backup directories and `0600` artifacts/manifests.
- Staged, fsynced, exclusive publication that does not truncate an existing
  backup and does not publish a failed partial dump.
- Versioned manifests containing checksum, source container/image identity,
  database or cluster scope, catalog provenance, and verification evidence.
- Immutable container preflights through `--expect-container-id`: exact full
  IDs and unambiguous standard 12-character short IDs are accepted, while
  weak/ambiguous prefixes and same-name replacement are rejected before the
  protected PostgreSQL phase. PostgreSQL commands use the inspected full ID.
- Lightweight checksum/archive parsing and strong scratch-database restore
  verification.
- Transactional database restore after strong incoming verification and a
  separately created, strongly verified safety backup.
- Strong `pg_dumpall` verification inside a new, labeled, no-network,
  disposable PostgreSQL container—not the source cluster.

Passwords are never accepted as a command-line value. The script reads the
selected container environment or `--password-file` / `--password-stdin`, sends
the secret to a temporary in-container pgpass file over stdin, redacts
diagnostics, and removes the credential file.

## What It Does Not Provide

- Encryption, off-site storage, retention management, WAL archiving,
  replication, or point-in-time recovery.
- A production whole-cluster cutover. Direct cluster restore is refused because
  safe replacement requires an externally declared staging, cutover, and
  rollback topology.
- Protection from loss of the host and its backup directory.
- Application-level correctness checks after restore.

A `pg_dumpall` artifact can contain role password hashes and remains sensitive
even though the tool does not persist a plaintext CLI password.

## Minimal Workflow

Run the coordinator inventory before any Docker or database-stack operation,
then select the intended PostgreSQL container:

```bash
python3 scripts/postgres_docker_backup.py list
python3 scripts/postgres_docker_backup.py backup \
  --container example-postgres \
  --expect-container-id 0123456789ab \
  --database appdb \
  --out-dir .codex-db-backups
python3 scripts/postgres_docker_backup.py verify \
  --container example-postgres \
  --expect-container-id 0123456789ab \
  --file .codex-db-backups/example-postgres-appdb-...dump \
  --test-restore
```

See `SKILL.md` before restore or whole-cluster work; those paths have additional
scope and confirmation requirements.

## Verification

The deterministic suite uses a fake Docker executable and realistic failure
fixtures:

```bash
python3 scripts/self_test.py
```

It proves recall for collision/truncation, partial publication, permissions,
secret exposure, scope confusion, cross-scope plain SQL, restore and cleanup
failures, same-name container recreation, weak/ambiguous immutable-ID prefixes,
replacement between restore phases, transactional custom/plain restores,
safety-backup verification, disposable cluster isolation, and unsafe
cluster-restore refusal. It also keeps false-positive guards for exact full and
unambiguous standard short IDs, valid fixture credentials, and ordinary
database dumps.

After coordinator inventory, a real integration is available when Docker and a
local compatible PostgreSQL image exist:

```bash
POSTGRES_BACKUP_INTEGRATION_INVENTORY_CHECKED=1 \
  python3 scripts/integration_test.py
```

The integration creates only uniquely named, labeled, network-isolated
disposable containers and checks that none remain. It never selects an existing
database automatically. CI also sets `POSTGRES_BACKUP_INTEGRATION_REQUIRED=1`
so missing Docker or a missing pre-pulled image fails instead of silently
skipping this gate.
