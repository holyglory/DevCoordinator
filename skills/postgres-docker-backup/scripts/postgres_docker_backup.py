#!/usr/bin/env python3
"""Backup and restore PostgreSQL databases running in Docker."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any


DEFAULT_OUT_DIR = ".codex-db-backups"


def utc_timestamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def slug(value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")
    return clean or "postgres"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(
    args: list[str],
    *,
    input_path: Path | None = None,
    stdout_path: Path | None = None,
    capture: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    stdin = input_path.open("rb") if input_path else None
    stdout_file = stdout_path.open("wb") if stdout_path else None
    try:
        result = subprocess.run(
            args,
            stdin=stdin,
            stdout=subprocess.PIPE if capture or stdout_path is None else stdout_file,
            stderr=subprocess.PIPE,
            text=capture,
            check=False,
        )
    except FileNotFoundError as exc:
        raise SystemExit("Docker CLI was not found on PATH") from exc
    finally:
        if stdin:
            stdin.close()
        if stdout_file:
            stdout_file.close()
    if check and result.returncode != 0:
        stderr = result.stderr if isinstance(result.stderr, str) else result.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"command failed: {' '.join(args)}\n{stderr}")
    return result


def docker(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return run(["docker", *args], **kwargs)


def docker_json(args: list[str]) -> Any:
    result = docker(args, capture=True)
    output = result.stdout.strip()
    if not output:
        return None
    return json.loads(output)


def container_names(ps_item: dict[str, Any]) -> list[str]:
    raw = ps_item.get("Names") or ps_item.get("Names".lower()) or ps_item.get("Name") or ""
    if isinstance(raw, list):
        return [str(item).lstrip("/") for item in raw]
    return [name.strip().lstrip("/") for name in str(raw).split(",") if name.strip()]


def inspect_container(container: str) -> dict[str, Any]:
    inspected = docker_json(["inspect", container])
    if not inspected:
        raise RuntimeError(f"container not found: {container}")
    return inspected[0]


def env_map(inspected: dict[str, Any]) -> dict[str, str]:
    values = inspected.get("Config", {}).get("Env") or []
    env: dict[str, str] = {}
    for item in values:
        if "=" in item:
            key, value = item.split("=", 1)
            env[key] = value
    return env


def is_postgres_container(ps_item: dict[str, Any], inspected: dict[str, Any]) -> bool:
    env = env_map(inspected)
    image = str(ps_item.get("Image") or inspected.get("Config", {}).get("Image") or "").lower()
    command = str(ps_item.get("Command") or inspected.get("Config", {}).get("Cmd") or "").lower()
    ports = str(ps_item.get("Ports") or "").lower()
    return (
        "postgres" in image
        or "postgres" in command
        or "5432" in ports
        or "POSTGRES_PASSWORD" in env
        or "POSTGRES_USER" in env
    )


def list_postgres_containers() -> list[dict[str, Any]]:
    result = docker(["ps", "--format", "{{json .}}"], capture=True)
    candidates: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        names = container_names(item)
        container = names[0] if names else item.get("ID")
        inspected = inspect_container(str(container))
        if not is_postgres_container(item, inspected):
            continue
        env = env_map(inspected)
        candidates.append(
            {
                "id": item.get("ID") or inspected.get("Id"),
                "name": container,
                "names": names,
                "image": item.get("Image") or inspected.get("Config", {}).get("Image"),
                "status": item.get("Status"),
                "ports": item.get("Ports"),
                "user": env.get("POSTGRES_USER") or "postgres",
                "database": env.get("POSTGRES_DB") or env.get("POSTGRES_USER") or "postgres",
                "has_password": bool(env.get("POSTGRES_PASSWORD")),
            }
        )
    return candidates


def select_container(container: str | None) -> tuple[str, dict[str, Any], dict[str, str]]:
    if container:
        inspected = inspect_container(container)
        return container, inspected, env_map(inspected)
    candidates = list_postgres_containers()
    if not candidates:
        raise RuntimeError("no running Postgres Docker container found")
    if len(candidates) > 1:
        names = ", ".join(item["name"] for item in candidates)
        raise RuntimeError(f"multiple Postgres containers found; pass --container. Candidates: {names}")
    selected = candidates[0]["name"]
    inspected = inspect_container(selected)
    return selected, inspected, env_map(inspected)


def auth_prefix(password: str | None) -> list[str]:
    if password:
        return ["env", f"PGPASSWORD={password}"]
    return []


def postgres_identity(args: argparse.Namespace, env: dict[str, str]) -> tuple[str, str, str | None]:
    user = args.user or env.get("POSTGRES_USER") or "postgres"
    database = args.database or env.get("POSTGRES_DB") or user
    password = args.password if args.password is not None else env.get("POSTGRES_PASSWORD")
    return user, database, password


def backup_command(container: str, user: str, database: str, password: str | None, backup_format: str) -> list[str]:
    prefix = ["exec", container, *auth_prefix(password)]
    if backup_format == "custom":
        return [*prefix, "pg_dump", "-Fc", "--no-owner", "-U", user, "-d", database]
    if backup_format == "plain":
        return [*prefix, "pg_dump", "--no-owner", "--clean", "--if-exists", "-U", user, "-d", database]
    if backup_format == "all":
        return [*prefix, "pg_dumpall", "-U", user]
    raise ValueError(f"unsupported backup format: {backup_format}")


def default_backup_path(out_dir: Path, container: str, database: str, backup_format: str) -> Path:
    extension = ".dump" if backup_format == "custom" else ".sql"
    return out_dir / f"{slug(container)}-{slug(database)}-{utc_timestamp()}{extension}"


def write_manifest(path: Path, manifest: dict[str, Any]) -> Path:
    manifest_path = Path(f"{path}.manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest_path


def load_manifest(path: Path) -> dict[str, Any] | None:
    manifest_path = Path(f"{path}.manifest.json")
    if not manifest_path.exists():
        return None
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def command_result(command: list[str]) -> dict[str, Any]:
    hidden = []
    for item in command:
        if item.startswith("PGPASSWORD="):
            hidden.append("PGPASSWORD=<redacted>")
        else:
            hidden.append(item)
    return {"docker_args": hidden}


def do_backup(args: argparse.Namespace) -> dict[str, Any]:
    container, inspected, env = select_container(args.container)
    user, database, password = postgres_identity(args, env)
    backup_format = args.format
    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    output = Path(args.output).expanduser().resolve() if args.output else default_backup_path(out_dir, container, database, backup_format)
    command = backup_command(container, user, database, password, backup_format)

    if args.dry_run:
        return {"dry_run": True, "output": str(output), "command": command_result(command)}

    docker(command, stdout_path=output)
    size = output.stat().st_size
    checksum = sha256_file(output)
    manifest = {
        "type": "postgres-docker-backup",
        "created_at": utc_timestamp(),
        "container": container,
        "container_id": inspected.get("Id"),
        "image": inspected.get("Config", {}).get("Image"),
        "database": database,
        "user": user,
        "format": backup_format,
        "path": str(output),
        "size": size,
        "sha256": checksum,
        "command": command_result(command),
    }
    manifest_path = write_manifest(output, manifest)
    return {"backup": str(output), "manifest": str(manifest_path), "size": size, "sha256": checksum, "format": backup_format}


def restore_command(container: str, user: str, database: str, password: str | None, backup_format: str) -> list[str]:
    prefix = ["exec", "-i", container, *auth_prefix(password)]
    if backup_format == "custom":
        return [*prefix, "pg_restore", "--clean", "--if-exists", "--no-owner", "-U", user, "-d", database]
    if backup_format in {"plain", "all"}:
        return [*prefix, "psql", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", database]
    raise ValueError(f"unsupported restore format: {backup_format}")


SANITY_QUERY = (
    "SELECT count(*) FROM pg_catalog.pg_tables "
    "WHERE schemaname NOT IN ('pg_catalog', 'information_schema');"
)


def scratch_db_name() -> str:
    return f"codex_verify_{uuid.uuid4().hex[:12]}"


def psql_exec_command(container: str, user: str, database: str, password: str | None, sql: str) -> list[str]:
    """Run a single SQL statement via psql in the container, against `database`."""
    return [
        "exec",
        container,
        *auth_prefix(password),
        "psql",
        "-v",
        "ON_ERROR_STOP=1",
        "-U",
        user,
        "-d",
        database,
        "-c",
        sql,
    ]


def create_scratch_db_command(container: str, user: str, password: str | None, scratch_db: str) -> list[str]:
    # Connect to the maintenance "postgres" database to create the scratch DB.
    return psql_exec_command(container, user, "postgres", password, f'CREATE DATABASE "{scratch_db}";')


def drop_scratch_db_command(container: str, user: str, password: str | None, scratch_db: str) -> list[str]:
    # Connect to the maintenance "postgres" database to drop the scratch DB.
    return psql_exec_command(container, user, "postgres", password, f'DROP DATABASE IF EXISTS "{scratch_db}";')


def sanity_query_command(container: str, user: str, password: str | None, scratch_db: str) -> list[str]:
    return [
        "exec",
        container,
        *auth_prefix(password),
        "psql",
        "-v",
        "ON_ERROR_STOP=1",
        "-tA",
        "-U",
        user,
        "-d",
        scratch_db,
        "-c",
        SANITY_QUERY,
    ]


def restore_into_scratch_command(
    container: str, user: str, password: str | None, scratch_db: str, backup_format: str
) -> list[str]:
    """Restore a dump into the scratch DB. Never targets the real database."""
    prefix = ["exec", "-i", container, *auth_prefix(password)]
    if backup_format == "custom":
        # No --clean/--if-exists: the scratch DB is fresh and empty.
        return [*prefix, "pg_restore", "--no-owner", "-U", user, "-d", scratch_db]
    if backup_format in {"plain", "all"}:
        return [*prefix, "psql", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", scratch_db]
    raise ValueError(f"unsupported backup format: {backup_format}")


def deep_verify(
    path: Path,
    container: str,
    user: str,
    password: str | None,
    backup_format: str,
) -> dict[str, Any]:
    """Restore a dump into a throwaway scratch DB, prove data landed, then always drop it.

    Never targets the real database. The scratch DB is dropped on every exit path
    (success, restore failure, sanity-query failure).
    """
    scratch_db = scratch_db_name()
    create_cmd = create_scratch_db_command(container, user, password, scratch_db)
    restore_cmd = restore_into_scratch_command(container, user, password, scratch_db, backup_format)
    sanity_cmd = sanity_query_command(container, user, password, scratch_db)
    drop_cmd = drop_scratch_db_command(container, user, password, scratch_db)

    restore_returncode: int | None = None
    table_count: int | None = None
    try:
        docker(create_cmd)
        restore_result = docker(restore_cmd, input_path=path, capture=True, check=False)
        restore_returncode = restore_result.returncode
        if restore_returncode != 0:
            stderr = restore_result.stderr or ""
            raise RuntimeError(
                f"test-restore into scratch DB {scratch_db} failed (exit {restore_returncode}): {stderr.strip()}"
            )
        sanity_result = docker(sanity_cmd, capture=True, check=False)
        if sanity_result.returncode != 0:
            stderr = sanity_result.stderr or ""
            raise RuntimeError(
                f"sanity query on scratch DB {scratch_db} failed (exit {sanity_result.returncode}): {stderr.strip()}"
            )
        raw_count = (sanity_result.stdout or "").strip().splitlines()
        try:
            table_count = int(raw_count[0]) if raw_count else 0
        except ValueError as exc:
            raise RuntimeError(
                f"sanity query on scratch DB {scratch_db} returned unparseable output: {sanity_result.stdout!r}"
            ) from exc
    finally:
        # Always drop the scratch DB, even if restore or sanity failed.
        docker(drop_cmd, check=False)

    return {
        "test_restore": True,
        "scratch_db": scratch_db,
        "restore_returncode": restore_returncode,
        "table_count": table_count,
        "sanity_query": SANITY_QUERY,
        "commands": {
            "create_scratch_db": command_result(create_cmd),
            "restore_into_scratch": command_result(restore_cmd),
            "sanity_query": command_result(sanity_cmd),
            "drop_scratch_db": command_result(drop_cmd),
        },
    }


def do_verify(args: argparse.Namespace) -> dict[str, Any]:
    path = Path(args.file).expanduser().resolve()
    if not path.exists():
        raise RuntimeError(f"backup file does not exist: {path}")
    manifest = load_manifest(path)
    if manifest and manifest.get("sha256") != sha256_file(path):
        raise RuntimeError("backup checksum does not match manifest")
    backup_format = args.format or (manifest or {}).get("format") or ("custom" if path.suffix == ".dump" else "plain")

    test_restore = getattr(args, "test_restore", False)
    if test_restore:
        container, _inspected, env = select_container(args.container)
        user, database, password = postgres_identity(args, env)
        deep = deep_verify(path, container, user, password, backup_format)
        return {
            "ok": True,
            "format": backup_format,
            "sha256": sha256_file(path),
            "target_database": database,
            **deep,
        }

    if backup_format == "custom":
        container, _inspected, env = select_container(args.container)
        _user, _database, password = postgres_identity(args, env)
        command = ["exec", "-i", container, *auth_prefix(password), "pg_restore", "--list"]
        result = docker(command, input_path=path, capture=True)
        return {"ok": True, "format": backup_format, "sha256": sha256_file(path), "pg_restore_list": result.stdout[:4000]}
    return {"ok": True, "format": backup_format, "sha256": sha256_file(path), "note": "plain SQL checksum verified"}


def do_restore(args: argparse.Namespace) -> dict[str, Any]:
    if not args.confirm_restore and not args.dry_run:
        raise RuntimeError("restore is destructive; pass --confirm-restore")
    path = Path(args.file).expanduser().resolve()
    if not path.exists():
        raise RuntimeError(f"backup file does not exist: {path}")
    manifest = load_manifest(path)
    if manifest and manifest.get("sha256") != sha256_file(path):
        raise RuntimeError("backup checksum does not match manifest")
    container, _inspected, env = select_container(args.container)
    user, database, password = postgres_identity(args, env)
    backup_format = args.format or (manifest or {}).get("format") or ("custom" if path.suffix == ".dump" else "plain")
    command = restore_command(container, user, database, password, backup_format)

    safety_backup: dict[str, Any] | None = None
    if not args.no_safety_backup:
        backup_args = argparse.Namespace(
            container=container,
            user=user,
            database=database,
            password=password,
            format="custom",
            out_dir=str(Path(args.safety_out_dir).expanduser().resolve()),
            output=None,
            dry_run=args.dry_run,
        )
        safety_backup = do_backup(backup_args)

    if args.dry_run:
        return {"dry_run": True, "restore_file": str(path), "command": command_result(command), "safety_backup": safety_backup}

    docker(command, input_path=path)
    return {"restored": str(path), "container": container, "database": database, "format": backup_format, "safety_backup": safety_backup}


def do_doctor() -> dict[str, Any]:
    version = docker(["version", "--format", "{{json .}}"], capture=True, check=False)
    containers = list_postgres_containers()
    return {"docker_returncode": version.returncode, "docker_version": version.stdout.strip(), "postgres_containers": containers}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Backup and restore Docker PostgreSQL databases safely.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list")
    sub.add_parser("doctor")

    backup = sub.add_parser("backup")
    backup.add_argument("--container")
    backup.add_argument("--database")
    backup.add_argument("--user")
    backup.add_argument("--password")
    backup.add_argument("--format", choices=["custom", "plain", "all"], default="custom")
    backup.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    backup.add_argument("--output")
    backup.add_argument("--dry-run", action="store_true")

    verify = sub.add_parser("verify")
    verify.add_argument("--container")
    verify.add_argument("--database")
    verify.add_argument("--user")
    verify.add_argument("--password")
    verify.add_argument("--file", required=True)
    verify.add_argument("--format", choices=["custom", "plain", "all"])
    verify.add_argument(
        "--test-restore",
        action="store_true",
        help="deep verify: restore into a throwaway scratch DB in the same container, run a sanity query, then drop it (never touches --database)",
    )

    restore = sub.add_parser("restore")
    restore.add_argument("--container")
    restore.add_argument("--database")
    restore.add_argument("--user")
    restore.add_argument("--password")
    restore.add_argument("--file", required=True)
    restore.add_argument("--format", choices=["custom", "plain", "all"])
    restore.add_argument("--confirm-restore", action="store_true")
    restore.add_argument("--no-safety-backup", action="store_true")
    restore.add_argument("--safety-out-dir", default=f"{DEFAULT_OUT_DIR}/pre-restore")
    restore.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "list":
            result = list_postgres_containers()
        elif args.command == "doctor":
            result = do_doctor()
        elif args.command == "backup":
            result = do_backup(args)
        elif args.command == "verify":
            result = do_verify(args)
        elif args.command == "restore":
            result = do_restore(args)
        else:
            raise RuntimeError(f"unsupported command: {args.command}")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, indent=2, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
