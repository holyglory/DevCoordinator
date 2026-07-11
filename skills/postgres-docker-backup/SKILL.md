---
name: postgres-docker-backup
description: Use when an agent (Codex, Claude Code) needs to protect, backup, strongly verify, or transactionally restore a PostgreSQL database running in Docker or Docker Compose, especially before migrations, destructive tests, resets, seed operations, or any work that risks local database data loss.
---

# Postgres Docker Backup

Use this skill before any operation that can destroy or overwrite PostgreSQL
data in Docker. Resolve `scripts/postgres_docker_backup.py` relative to this
skill directory.

## Core Rules

1. Before migrations, resets, destructive tests, imports, seed rewrites,
   `DROP`, `TRUNCATE`, or restore, create a database-scope backup. Do not rely
   on a Docker volume alone.
2. Before any Docker or database-stack operation, follow
   `$codex-dev-coordinator`: resolve the canonical project root and run its
   `inventory --project "$PROJECT_ROOT"` command. Never select or mutate an
   unrelated running container.
3. Treat database dumps and whole-cluster dumps as different scopes:
   `custom` and `plain` are `database`; `all` (`pg_dumpall`) is `cluster`.
   Scope/format mismatches are rejected.
4. Never pass a password on the command line. The script reads the selected
   container's `POSTGRES_PASSWORD` by default, or accepts `--password-file`
   (current-user-only mode `0600`) / `--password-stdin`. It sends credentials
   into the container over stdin as a temporary `0600` pgpass file and removes
   that file after the command. Passwords are redacted from diagnostics and
   manifest command metadata.
5. Resolve the selected container's immutable ID from coordinator/Docker
   inventory and pass `--expect-container-id` on every backup, every
   database-scope verification, and every database restore. These
   live-container paths fail before Docker selection when the expected ID is
   missing. The accepted forms are an exact 64-character hexadecimal ID or an
   unambiguous standard 12-character Docker short ID. Shorter and arbitrary
   prefixes are refused. The script reinspects the name immediately before
   each protected phase and executes PostgreSQL commands against the full ID,
   so recreating a container under the same name cannot redirect the work.
   Cluster artifact verification is the intentional exception: without
   `--expect-container-id` it verifies offline or in a newly created disposable
   container and does not inspect the live source. Supply both `--container`
   and `--expect-container-id` only when explicitly checking that the original
   cluster source still matches its recorded identity.

## Inventory

List running PostgreSQL candidates. If more than one candidate exists, every
command that selects a live source or target must identify the intended
`--container`. Offline/disposable cluster artifact verification is the explicit
exception and selects no live candidate.

```bash
python3 scripts/postgres_docker_backup.py list
```

## Database Backups

The default is one database in PostgreSQL custom format:

```bash
python3 scripts/postgres_docker_backup.py backup \
  --container my-postgres \
  --expect-container-id 0123456789ab \
  --database appdb \
  --user postgres \
  --out-dir .codex-db-backups
```

Plain SQL remains database-scoped:

```bash
python3 scripts/postgres_docker_backup.py backup \
  --container my-postgres \
  --expect-container-id 0123456789ab \
  --database appdb \
  --format plain \
  --scope database \
  --out-dir .codex-db-backups
```

Publication is fail-closed:

- the backup directory must be private (`0700`);
- dump and manifest files are `0600`;
- the dump is written and fsynced under a hidden staging name;
- final publication is atomic and exclusive, never truncating an existing
  artifact;
- a failed dump publishes neither final backup nor manifest;
- the manifest is written atomically and contains the artifact checksum.

If a pre-existing backup directory has broader permissions, the script refuses
and asks the operator to `chmod 700` rather than silently changing an arbitrary
directory.

## Database Verification

Lightweight verification checks the versioned manifest, byte size, SHA-256,
scope, format, and source provenance. For custom archives it also runs
`pg_restore --list`:

```bash
python3 scripts/postgres_docker_backup.py verify \
  --container my-postgres \
  --expect-container-id 0123456789ab \
  --file .codex-db-backups/my-postgres-appdb-...dump
```

Strong verification creates a uniquely named database from `template0` in the
selected PostgreSQL container, restores only into that scratch database, and
compares the restored catalog signature (tables, sequences, views, functions)
with the signature captured at backup time. It always force-drops the scratch
database. Restore failure, signature mismatch, or cleanup failure makes the
command fail:

```bash
python3 scripts/postgres_docker_backup.py verify \
  --container my-postgres \
  --expect-container-id 0123456789ab \
  --file .codex-db-backups/my-postgres-appdb-...dump \
  --test-restore
```

The successful verification record is atomically persisted in the manifest.
The scratch path never targets the real `--database`, but it does require a
role allowed to create and drop a temporary database.

## Transactional Database Restore

Database restore requires confirmation. Before the target is changed, the
script:

1. strongly test-restores the incoming artifact;
2. rechecks that the container name still resolves to the locked immutable ID;
3. creates a new custom-format safety backup of the current target under the
   same identity lock;
4. strongly test-restores that safety backup;
5. rechecks the immutable identity immediately before target mutation;
6. restores custom dumps using `pg_restore --single-transaction
   --exit-on-error`, or plain dumps using `psql --single-transaction` with
   `ON_ERROR_STOP=1`;
7. rechecks the target catalog signature.

```bash
python3 scripts/postgres_docker_backup.py restore \
  --container my-postgres \
  --expect-container-id 0123456789ab \
  --database appdb \
  --file .codex-db-backups/my-postgres-appdb-...dump \
  --confirm-restore
```

Restoring a backup into a differently named database additionally requires
`--allow-database-remap`. `--no-safety-backup` remains an explicit expert
override; do not use it unless the user deliberately accepts losing the
automatic rollback artifact.

Unmanifested legacy database dumps are rejected by default. A reviewed legacy
database dump may use `--allow-unmanifested` only together with explicit
`--scope database --format custom|plain`. Before a plain database dump is
parsed or restored, the script rejects cluster headers, `\\connect`/include or
shell meta-commands, database/role DDL, `ALTER SYSTEM`, and `COPY ... PROGRAM`.
This exception cannot turn a database dump into a cluster/control-plane script.

## Whole-Cluster Backup And Verification

Create a cluster-scoped `pg_dumpall --clean --if-exists` artifact explicitly:

```bash
python3 scripts/postgres_docker_backup.py backup \
  --container my-postgres \
  --expect-container-id 0123456789ab \
  --format all \
  --scope cluster \
  --out-dir .codex-db-backups
```

The v2 manifest records the source container identity/image plus the source
database, role, and per-database catalog inventory. Strong verification never
pipes cluster SQL back into the source container. It creates a uniquely named,
labeled Docker container from the source image (or `--verification-image`),
with no host ports and `--network none`, restores the dump there, compares the
complete catalog provenance, and always removes the disposable container:

```bash
python3 scripts/postgres_docker_backup.py verify \
  --file .codex-db-backups/my-postgres-cluster-...sql \
  --test-restore
```

That cluster verification intentionally omits both `--container` and
`--expect-container-id`: the manifest and artifact are checked without looking
up the original live source, and strong verification executes only in the new
disposable target. If the operator separately needs to prove the recorded
source still resolves to the expected immutable ID, request that check
explicitly:

```bash
python3 scripts/postgres_docker_backup.py verify \
  --file .codex-db-backups/my-postgres-cluster-...sql \
  --container my-postgres \
  --expect-container-id 0123456789ab
```

`--container` without `--expect-container-id` is rejected for cluster
verification so a source hint is never silently ignored.

Direct cluster restore is refused. A safe production cluster replacement needs
an externally declared staged replacement, cutover, and rollback topology; this
skill does not guess one and never pipes `pg_dumpall` into an existing cluster.

## Manifest V2

Every new artifact has a `.manifest.json` containing:

- schema and tool version;
- explicit `database` or `cluster` scope and dump format;
- source container name, immutable ID, image tag/ID;
- execution-time immutable identity-preflight evidence, including the expected
  ID, actual full ID, match mode, phase, and timestamp;
- source PostgreSQL user/database and catalog provenance;
- artifact path, size, SHA-256, creation time;
- redacted command metadata and non-secret authentication source;
- atomic/exclusive publication properties;
- the most recent successful verification mode, time, checksum, and catalog
  result.

Compatibility fields remain at the top level for existing inventory readers,
but `source.container` and `source.postgres` are authoritative.

## Tests

Run deterministic fake-Docker recall and false-positive coverage:

```bash
python3 scripts/self_test.py
```

The suite covers atomic collision/failure publication, permissions, manifest
provenance, secret redaction, database scope, strong scratch verification and
cleanup failures, transactional custom/plain restore, verified safety backups,
missing immutable-ID rejection before Docker selection for backup, database
verification, and restore, same-name container recreation, weak/ambiguous ID
prefixes, restore-phase identity replacement, cluster scope, disposable
cluster isolation/cleanup, final-server TCP application-database query
readiness after listener startup, and refusal of unsafe cluster restore. Exact full and unambiguous
standard short IDs, already-queryable application databases, plus
offline/disposable cluster verification without a source ID, are retained as
false-positive controls.

After coordinator inventory, optionally run the real disposable Docker test
when Docker and a local `postgres:16-alpine` image are available:

```bash
POSTGRES_BACKUP_INTEGRATION_INVENTORY_CHECKED=1 \
  python3 scripts/integration_test.py
```

It creates only uniquely named containers labeled
`com.devcoordinator.postgres-backup.disposable=true`, publishes no ports, uses
`--network none`, verifies database backup/restore and whole-cluster
test-restore, and checks that no disposable containers leaked.

## Boundaries

- These are logical backups, not off-site storage, encryption, continuous
  archiving, replication, or point-in-time recovery.
- A `pg_dumpall` artifact can contain role password hashes and must remain
  private even though no plaintext CLI password is persisted.
- Strong database verification requires scratch-database privileges.
- Strong cluster verification requires the source image (or a compatible
  explicit verification image) to exist locally and enough Docker resources to
  start one temporary PostgreSQL container.
- A successful backup must still be followed by the application's normal
  post-operation database smoke test.
