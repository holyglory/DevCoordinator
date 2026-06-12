---
name: postgres-docker-backup
description: Use when Codex needs to protect, backup, verify, or restore a PostgreSQL database running in Docker or Docker Compose, especially before migrations, destructive tests, resets, seed operations, or any work that risks local database data loss.
---

# Postgres Docker Backup

Use this skill before any operation that can destroy or overwrite data in a
PostgreSQL database running in Docker.

## Core Rule

Before migrations, resets, destructive tests, imports, seed rewrites, `prisma
migrate reset`, `DROP`, `TRUNCATE`, or restore operations, create a backup with
the bundled script. Do not rely on Docker volumes alone as the backup.

## Quick Start

Resolve the script path relative to this skill directory.

List candidate Postgres containers:

```bash
python3 scripts/postgres_docker_backup.py list
```

Create a backup from the only running Postgres container:

```bash
python3 scripts/postgres_docker_backup.py backup --out-dir .codex-db-backups
```

Create a backup for a specific container and database:

```bash
python3 scripts/postgres_docker_backup.py backup \
  --container my-postgres \
  --database appdb \
  --user postgres \
  --out-dir .codex-db-backups
```

Verify a custom-format backup:

```bash
python3 scripts/postgres_docker_backup.py verify \
  --container my-postgres \
  --file .codex-db-backups/my-postgres-appdb-20260602T120000Z.dump
```

Restore requires an explicit confirmation flag and creates a safety backup first
unless `--no-safety-backup` is passed:

```bash
python3 scripts/postgres_docker_backup.py restore \
  --container my-postgres \
  --database appdb \
  --file .codex-db-backups/my-postgres-appdb-20260602T120000Z.dump \
  --confirm-restore
```

## Agent Workflow

1. Run `list` and identify the target container. If more than one candidate is
   present, require or infer the correct `--container` from project context.
2. Run `backup` before destructive database work.
3. Run `verify` on the new backup when practical.
4. Proceed with the risky operation only after the backup and manifest exist.
5. For restore, inspect the target container/database, require
   `--confirm-restore`, and keep the automatic pre-restore safety backup unless
   the user explicitly says to skip it.
6. After restore, run the app's normal DB smoke check or test path.

## Output

Backups are written as PostgreSQL custom-format dumps by default (`pg_dump -Fc`)
with a `.manifest.json` file containing:

- container id/name/image
- database and user
- backup format
- timestamp
- size
- SHA-256 checksum
- command metadata

Plain SQL and `pg_dumpall` are supported with `--format plain` and
`--format all`.

## Safety Notes

- The script shells out to the local Docker CLI and runs PostgreSQL tools inside
  the selected container.
- It reads `POSTGRES_USER`, `POSTGRES_DB`, and `POSTGRES_PASSWORD` from the
  container environment when explicit flags are not supplied.
- If multiple Postgres containers are running, the script refuses to choose
  silently.
- Restore is intentionally gated by `--confirm-restore`.
- Default restore behavior runs a fresh safety backup first.
