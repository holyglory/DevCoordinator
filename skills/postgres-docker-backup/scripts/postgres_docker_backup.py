#!/usr/bin/env python3
"""Create, verify, and restore PostgreSQL backups without crossing scope boundaries."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any, BinaryIO


DEFAULT_OUT_DIR = ".codex-db-backups"
TOOL_NAME = "postgres-docker-backup"
TOOL_VERSION = "2.1.0"
MANIFEST_SCHEMA_VERSION = 2
DATABASE_SCOPE = "database"
CLUSTER_SCOPE = "cluster"
DISPOSABLE_LABEL = "com.devcoordinator.postgres-backup.disposable=true"
DOCKER_SHORT_ID_LENGTH = 12
DOCKER_FULL_ID_LENGTH = 64
DOCKER_ID_RE = re.compile(r"^[0-9a-fA-F]+$")

DATABASE_SIGNATURE_SQL = """
/* codex_catalog_signature */
SELECT
  (SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'
       AND c.relkind IN ('r', 'p'))::text || '|' ||
  (SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'
       AND c.relkind = 'S')::text || '|' ||
  (SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'
       AND c.relkind IN ('v', 'm'))::text || '|' ||
  (SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%')::text;
""".strip()

DATABASE_LIST_SQL = """
/* codex_database_list */
SELECT datname FROM pg_catalog.pg_database
WHERE datallowconn AND NOT datistemplate
ORDER BY datname;
""".strip()

ROLE_LIST_SQL = """
/* codex_role_list */
SELECT rolname FROM pg_catalog.pg_roles ORDER BY rolname;
""".strip()


def utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def filename_timestamp() -> str:
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


def redact_text(value: str, secrets: tuple[str, ...] | list[str]) -> str:
    redacted = value
    for secret in sorted({item for item in secrets if item}, key=len, reverse=True):
        redacted = redacted.replace(secret, "<redacted>")
    redacted = re.sub(r"PGPASSWORD=[^\s'\"]+", "PGPASSWORD=<redacted>", redacted)
    return redacted


def redacted_args(args: list[str], secrets: tuple[str, ...] | list[str] = ()) -> list[str]:
    hidden: list[str] = []
    redact_next = False
    for item in args:
        if redact_next:
            hidden.append("<redacted>")
            redact_next = False
        elif item in {"--password", "--password-file"}:
            hidden.append(item)
            redact_next = True
        elif item.startswith("PGPASSWORD="):
            hidden.append("PGPASSWORD=<redacted>")
        else:
            hidden.append(redact_text(item, secrets))
    return hidden


def surface_cleanup_failure(body_error: BaseException | None, message: str) -> None:
    """Raise one CLI-visible error that retains body and cleanup failures."""
    if body_error is None:
        raise RuntimeError(message)
    raise RuntimeError(f"{body_error}; additionally, {message}") from body_error


def run(
    args: list[str],
    *,
    input_path: Path | None = None,
    input_bytes: bytes | None = None,
    stdout_handle: BinaryIO | None = None,
    capture: bool = False,
    check: bool = True,
    secrets: tuple[str, ...] | list[str] = (),
) -> subprocess.CompletedProcess[str]:
    if input_path is not None and input_bytes is not None:
        raise ValueError("input_path and input_bytes are mutually exclusive")
    stdin = input_path.open("rb") if input_path else None
    try:
        result = subprocess.run(
            args,
            stdin=stdin,
            input=input_bytes,
            stdout=subprocess.PIPE if capture or stdout_handle is None else stdout_handle,
            stderr=subprocess.PIPE,
            text=False,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"executable was not found: {redacted_args(args, secrets)[0]}") from exc
    finally:
        if stdin:
            stdin.close()
    stdout = result.stdout.decode("utf-8", errors="replace") if isinstance(result.stdout, bytes) else ""
    stderr = result.stderr.decode("utf-8", errors="replace") if isinstance(result.stderr, bytes) else ""
    completed = subprocess.CompletedProcess(args, result.returncode, stdout, stderr)
    if check and completed.returncode != 0:
        command = " ".join(redacted_args(args, secrets))
        detail = redact_text(completed.stderr, secrets).strip()
        raise RuntimeError(f"command failed: {command}\n{detail}".rstrip())
    return completed


def docker(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return run(["docker", *args], **kwargs)


def docker_json(args: list[str]) -> Any:
    result = docker(args, capture=True)
    output = result.stdout.strip()
    if not output:
        return None
    return json.loads(output)


def container_names(ps_item: dict[str, Any]) -> list[str]:
    raw = ps_item.get("Names") or ps_item.get("names") or ps_item.get("Name") or ""
    if isinstance(raw, list):
        return [str(item).lstrip("/") for item in raw]
    return [name.strip().lstrip("/") for name in str(raw).split(",") if name.strip()]


def inspect_container(container: str) -> dict[str, Any]:
    inspected = docker_json(["inspect", container])
    if not inspected:
        raise RuntimeError(f"container not found: {container}")
    return inspected[0]


def normalize_expected_container_id(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) not in {DOCKER_SHORT_ID_LENGTH, DOCKER_FULL_ID_LENGTH} or not DOCKER_ID_RE.fullmatch(normalized):
        raise RuntimeError(
            "--expect-container-id must be exactly 12 (standard short ID) or 64 (full ID) hexadecimal characters; "
            "weak and arbitrary prefixes are refused"
        )
    return normalized


def require_expected_container_id(value: str | None, *, operation: str) -> str:
    if not value or not str(value).strip():
        raise RuntimeError(
            f"{operation} requires --expect-container-id from coordinator/Docker inventory before selecting a live container"
        )
    return normalize_expected_container_id(str(value))


def normalize_inspected_container_id(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if len(normalized) != DOCKER_FULL_ID_LENGTH or not DOCKER_ID_RE.fullmatch(normalized):
        raise RuntimeError("docker inspect did not return a standard 64-character hexadecimal container ID")
    return normalized


def container_identity_preflight(container: str, expected: str | None, *, phase: str) -> tuple[dict[str, Any], dict[str, str], dict[str, Any]]:
    """Inspect a name immediately before work and bind subsequent execs to its full ID."""
    requested = normalize_expected_container_id(expected) if expected else None
    inspected = inspect_container(container)
    actual = normalize_inspected_container_id(inspected.get("Id"))
    match = "observed_only"
    if requested:
        if len(requested) == DOCKER_FULL_ID_LENGTH:
            if requested != actual:
                raise RuntimeError(
                    f"container identity mismatch during {phase}: {container!r} is {actual}, expected {requested}; "
                    "refusing all PostgreSQL work"
                )
            match = "exact_full"
        else:
            if not actual.startswith(requested):
                raise RuntimeError(
                    f"container identity mismatch during {phase}: {container!r} is {actual}, expected standard short ID {requested}; "
                    "refusing all PostgreSQL work"
                )
            resolved = docker(
                ["inspect", "--type", "container", requested],
                capture=True,
                check=False,
            )
            if resolved.returncode != 0:
                raise RuntimeError(
                    f"expected standard short container ID {requested} did not resolve unambiguously during {phase}; "
                    "use the full 64-character ID"
                )
            try:
                matches = json.loads(resolved.stdout)
            except json.JSONDecodeError as exc:
                raise RuntimeError("docker returned invalid identity evidence for the expected short container ID") from exc
            if not isinstance(matches, list) or len(matches) != 1:
                raise RuntimeError(
                    f"expected standard short container ID {requested} did not resolve to exactly one container during {phase}"
                )
            resolved_id = normalize_inspected_container_id(matches[0].get("Id") if isinstance(matches[0], dict) else None)
            if resolved_id != actual:
                raise RuntimeError(
                    f"expected standard short container ID {requested} resolved to {resolved_id}, not selected container {actual}; "
                    "refusing all PostgreSQL work"
                )
            match = "unambiguous_standard_short"
    evidence = {
        "phase": phase,
        "container": container,
        "expected_id": requested,
        "actual_id": actual,
        "match": match,
        "checked_at": utc_timestamp(),
        "execution_target": "immutable_full_id",
    }
    return inspected, env_map(inspected), evidence


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


def validate_password(password: str | None) -> str | None:
    if password is None or password == "":
        return None
    if "\x00" in password or "\n" in password or "\r" in password:
        raise RuntimeError("PostgreSQL password must not contain NUL or newline characters")
    return password


def password_from_file(path_value: str) -> str:
    path = Path(path_value).expanduser().resolve()
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError("--password-file must name a regular file")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise RuntimeError("--password-file must be owned by the current user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError("--password-file must not be accessible by group or other users (use chmod 600)")
    return validate_password(path.read_text(encoding="utf-8").rstrip("\r\n")) or ""


def resolve_password(args: argparse.Namespace, env: dict[str, str]) -> tuple[str | None, str]:
    override = getattr(args, "_password_override", None)
    if override is not None:
        return validate_password(override), "internal"
    password_file = getattr(args, "password_file", None)
    password_stdin = bool(getattr(args, "password_stdin", False))
    if password_file and password_stdin:
        raise RuntimeError("--password-file and --password-stdin are mutually exclusive")
    if password_file:
        return validate_password(password_from_file(password_file)), "file"
    if password_stdin:
        return validate_password(sys.stdin.read().rstrip("\r\n")), "stdin"
    return validate_password(env.get("POSTGRES_PASSWORD")), "container_env" if env.get("POSTGRES_PASSWORD") else "none"


def postgres_identity(args: argparse.Namespace, env: dict[str, str], *, database_default: str | None = None) -> tuple[str, str, str | None, str]:
    user = args.user or env.get("POSTGRES_USER") or "postgres"
    database = args.database or database_default or env.get("POSTGRES_DB") or user
    password, password_source = resolve_password(args, env)
    return user, database, password, password_source


def pgpass_bytes(password: str) -> bytes:
    escaped = password.replace("\\", "\\\\").replace(":", "\\:")
    return f"*:*:*:*:{escaped}\n".encode("utf-8")


@contextlib.contextmanager
def postgres_auth(container: str, password: str | None) -> Iterator[list[str]]:
    if not password:
        yield []
        return
    secret_path = f"/tmp/.codex-pgpass-{uuid.uuid4().hex}"
    install = [
        "exec",
        "-i",
        container,
        "sh",
        "-c",
        'umask 077; cat > "$1"',
        "codex-pgpass",
        secret_path,
    ]
    cleanup = ["exec", container, "rm", "-f", "--", secret_path]
    body_error: BaseException | None = None
    attempted = False
    try:
        attempted = True
        docker(install, input_bytes=pgpass_bytes(password), secrets=(password,))
        yield ["env", f"PGPASSFILE={secret_path}"]
    except BaseException as exc:
        body_error = exc
        raise
    finally:
        if attempted:
            result = docker(cleanup, capture=True, check=False, secrets=(password,))
            if result.returncode != 0:
                message = f"failed to remove temporary PostgreSQL credential file from {container}: {redact_text(result.stderr, (password,)).strip()}"
                surface_cleanup_failure(body_error, message)


def psql_query_command(container: str, user: str, database: str, auth: list[str], sql: str) -> list[str]:
    return [
        "exec",
        container,
        *auth,
        "psql",
        "-X",
        "-v",
        "ON_ERROR_STOP=1",
        "-qAt",
        "-U",
        user,
        "-d",
        database,
        "-c",
        sql,
    ]


def query_lines(container: str, user: str, database: str, auth: list[str], sql: str, *, secrets: tuple[str, ...] = ()) -> list[str]:
    result = docker(psql_query_command(container, user, database, auth, sql), capture=True, secrets=secrets)
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def database_signature(container: str, user: str, database: str, auth: list[str], *, secrets: tuple[str, ...] = ()) -> dict[str, int]:
    lines = query_lines(container, user, database, auth, DATABASE_SIGNATURE_SQL, secrets=secrets)
    if len(lines) != 1:
        raise RuntimeError(f"could not read catalog signature from database {database}")
    parts = lines[0].split("|")
    if len(parts) != 4:
        raise RuntimeError(f"database {database} returned an invalid catalog signature")
    try:
        values = [int(item) for item in parts]
    except ValueError as exc:
        raise RuntimeError(f"database {database} returned a non-numeric catalog signature") from exc
    return dict(zip(("tables", "sequences", "views", "functions"), values))


def cluster_signature(
    container: str,
    user: str,
    auth: list[str],
    *,
    secrets: tuple[str, ...] = (),
    exclude_databases: set[str] | None = None,
    exclude_roles: set[str] | None = None,
) -> dict[str, Any]:
    databases = query_lines(container, user, "postgres", auth, DATABASE_LIST_SQL, secrets=secrets)
    roles = query_lines(container, user, "postgres", auth, ROLE_LIST_SQL, secrets=secrets)
    excluded_databases = exclude_databases or set()
    excluded_roles = exclude_roles or set()
    databases = [item for item in databases if item not in excluded_databases]
    roles = [item for item in roles if item not in excluded_roles]
    signatures = {
        database: database_signature(container, user, database, auth, secrets=secrets)
        for database in databases
    }
    return {"databases": databases, "roles": roles, "catalog_signatures": signatures}


def backup_scope(backup_format: str) -> str:
    return CLUSTER_SCOPE if backup_format == "all" else DATABASE_SCOPE


def validate_scope(scope: str | None, backup_format: str) -> str:
    inferred = backup_scope(backup_format)
    if scope and scope != inferred:
        raise RuntimeError(f"format {backup_format!r} has {inferred!r} scope, not {scope!r}")
    return inferred


def backup_command(container: str, user: str, database: str | None, auth: list[str], backup_format: str) -> list[str]:
    prefix = ["exec", container, *auth]
    if backup_format == "custom":
        if not database:
            raise RuntimeError("database-scope backup requires a database")
        return [*prefix, "pg_dump", "-Fc", "--no-owner", "-U", user, "-d", database]
    if backup_format == "plain":
        if not database:
            raise RuntimeError("database-scope backup requires a database")
        return [*prefix, "pg_dump", "--no-owner", "--clean", "--if-exists", "-U", user, "-d", database]
    if backup_format == "all":
        return [*prefix, "pg_dumpall", "--clean", "--if-exists", "-U", user]
    raise RuntimeError(f"unsupported backup format: {backup_format}")


def restore_command(container: str, user: str, database: str, auth: list[str], backup_format: str) -> list[str]:
    prefix = ["exec", "-i", container, *auth]
    if backup_format == "custom":
        return [
            *prefix,
            "pg_restore",
            "--clean",
            "--if-exists",
            "--no-owner",
            "--exit-on-error",
            "--single-transaction",
            "-U",
            user,
            "-d",
            database,
        ]
    if backup_format == "plain":
        return [
            *prefix,
            "psql",
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
            "--single-transaction",
            "-U",
            user,
            "-d",
            database,
        ]
    raise RuntimeError("cluster-scope dumps are never restored into an existing container")


def default_backup_path(out_dir: Path, container: str, database: str | None, backup_format: str) -> Path:
    extension = ".dump" if backup_format == "custom" else ".sql"
    target = database if backup_scope(backup_format) == DATABASE_SCOPE else "cluster"
    unique = uuid.uuid4().hex[:8]
    return out_dir / f"{slug(container)}-{slug(target or 'database')}-{filename_timestamp()}-{unique}{extension}"


def ensure_private_directory(path: Path) -> None:
    existed = path.exists()
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not path.is_dir():
        raise RuntimeError(f"backup parent is not a directory: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        if existed:
            raise RuntimeError(f"backup directory is accessible by group/other users: {path}; run chmod 700")
        path.chmod(0o700)
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise RuntimeError(f"backup directory must have mode 0700: {path}")


def fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_temp_file(directory: Path, prefix: str) -> tuple[int, Path]:
    fd, raw_path = tempfile.mkstemp(prefix=prefix, suffix=".partial", dir=directory)
    os.fchmod(fd, 0o600)
    return fd, Path(raw_path)


def atomic_json_write(path: Path, payload: dict[str, Any], *, exclusive: bool) -> None:
    ensure_private_directory(path.parent)
    fd, temporary = private_temp_file(path.parent, f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if exclusive:
            os.link(temporary, path)
            temporary.unlink()
        else:
            os.replace(temporary, path)
        path.chmod(0o600)
        fsync_directory(path.parent)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


def manifest_path_for(path: Path) -> Path:
    return Path(f"{path}.manifest.json")


def load_manifest(path: Path) -> dict[str, Any] | None:
    manifest_path = manifest_path_for(path)
    if not manifest_path.exists():
        return None
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def command_result(command: list[str], secrets: tuple[str, ...] | list[str] = ()) -> dict[str, Any]:
    return {"docker_args": redacted_args(command, secrets)}


def validate_database_dump_structure(path: Path, backup_format: str) -> None:
    """Reject a cluster/control-plane script before it can escape a scratch DB."""
    if backup_format == "custom":
        with path.open("rb") as handle:
            if handle.read(5) != b"PGDMP":
                raise RuntimeError("custom-format database backup is missing the PGDMP archive header")
        return
    if backup_format != "plain":
        raise RuntimeError("database dump structure accepts only custom or plain format")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError("plain database backup is not valid UTF-8 SQL") from exc
    forbidden = {
        "cluster dump header": r"(?im)^--\s*PostgreSQL database cluster dump",
        "database connection switch": r"(?im)^\s*\\(?:connect|c)(?:\s|$)",
        "psql shell/include command": r"(?im)^\s*\\(?:!|i|ir)(?:\s|$)",
        "database or role DDL": r"(?im)^\s*(?:CREATE|ALTER|DROP)\s+(?:DATABASE|ROLE|USER|GROUP)\b",
        "server-wide ALTER SYSTEM": r"(?im)^\s*ALTER\s+SYSTEM\b",
        "server-side COPY PROGRAM": r"(?im)^\s*COPY\b[^\n]*\bPROGRAM\b",
        "client-side copy program": r"(?im)^\s*\\copy\b[^\n]*\bPROGRAM\b",
    }
    for label, pattern in forbidden.items():
        if re.search(pattern, text):
            raise RuntimeError(f"plain database backup contains forbidden cross-scope operation: {label}")


def artifact_manifest(
    *,
    output: Path,
    container: str,
    inspected: dict[str, Any],
    user: str,
    database: str | None,
    backup_format: str,
    scope: str,
    size: int,
    checksum: str,
    command: list[str],
    provenance: dict[str, Any],
    password_source: str,
    secrets: tuple[str, ...],
    identity_preflight: dict[str, Any],
) -> dict[str, Any]:
    image = inspected.get("Config", {}).get("Image")
    source = {
        "container": {
            "name": container,
            "id": inspected.get("Id"),
            "image": image,
            "image_id": inspected.get("Image"),
        },
        "postgres": {
            "user": user,
            "database": database,
            "scope": scope,
            "catalog": provenance,
        },
    }
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "type": TOOL_NAME,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "created_at": utc_timestamp(),
        "scope": scope,
        "format": backup_format,
        "path": str(output),
        "size": size,
        "sha256": checksum,
        "source": source,
        "publication": {"atomic_artifact": True, "exclusive": True, "directory_mode": "0700", "file_mode": "0600"},
        "authentication": {"source": password_source, "secret_persisted": False},
        "container_identity_preflight": identity_preflight,
        "command": command_result(command, secrets),
        "verification": None,
        # Compatibility fields consumed by existing inventory clients.
        "container": container,
        "container_id": inspected.get("Id"),
        "image": image,
        "database": database,
        "user": user,
    }


def publish_artifact(staging: Path, output: Path, manifest: dict[str, Any]) -> Path:
    manifest_path = manifest_path_for(output)
    if os.path.lexists(output) or os.path.lexists(manifest_path):
        raise RuntimeError(f"refusing to overwrite existing backup or manifest: {output}")
    published = False
    try:
        os.link(staging, output)
        published = True
        output.chmod(0o600)
        atomic_json_write(manifest_path, manifest, exclusive=True)
        fsync_directory(output.parent)
        return manifest_path
    except FileExistsError as exc:
        raise RuntimeError(f"refusing to overwrite existing backup or manifest: {output}") from exc
    except Exception:
        if published:
            with contextlib.suppress(FileNotFoundError, OSError):
                if os.path.samefile(output, staging):
                    output.unlink()
        raise
    finally:
        with contextlib.suppress(FileNotFoundError):
            staging.unlink()


def do_backup(args: argparse.Namespace) -> dict[str, Any]:
    expected_container_id = require_expected_container_id(
        getattr(args, "expect_container_id", None),
        operation="backup",
    )
    container, _initial_inspected, _initial_env = select_container(args.container)
    inspected, env, initial_identity = container_identity_preflight(
        container,
        expected_container_id,
        phase="backup selection",
    )
    backup_format = args.format
    scope = validate_scope(getattr(args, "scope", None), backup_format)
    if scope == CLUSTER_SCOPE and args.database:
        raise RuntimeError("cluster-scope backup does not accept --database")
    user, database, password, password_source = postgres_identity(args, env)
    if scope == CLUSTER_SCOPE:
        database = None

    out_dir = Path(args.out_dir).expanduser().resolve()
    output = Path(args.output).expanduser().resolve() if args.output else default_backup_path(out_dir, container, database, backup_format)
    directory = output.parent
    ensure_private_directory(directory)
    if os.path.lexists(output) or os.path.lexists(manifest_path_for(output)):
        raise RuntimeError(f"refusing to overwrite existing backup or manifest: {output}")

    dry_auth = ["env", "PGPASSFILE=<ephemeral>"] if password else []
    immutable_target = initial_identity["actual_id"]
    dry_command = backup_command(immutable_target, user, database, dry_auth, backup_format)
    if args.dry_run:
        return {
            "dry_run": True,
            "output": str(output),
            "scope": scope,
            "format": backup_format,
            "command": command_result(dry_command),
            "container_identity_preflight": initial_identity,
        }

    fd, staging = private_temp_file(directory, f".{output.name}.")
    secrets = (password,) if password else ()
    try:
        with os.fdopen(fd, "wb") as output_handle:
            inspected, _current_env, identity_preflight = container_identity_preflight(
                container,
                immutable_target,
                phase="backup execution",
            )
            identity_preflight["requested_expected_id"] = initial_identity["expected_id"]
            identity_preflight["selection_match"] = initial_identity["match"]
            immutable_target = identity_preflight["actual_id"]
            with postgres_auth(immutable_target, password) as auth:
                if scope == DATABASE_SCOPE:
                    provenance = database_signature(immutable_target, user, database, auth, secrets=secrets)
                else:
                    provenance = cluster_signature(immutable_target, user, auth, secrets=secrets)
                command = backup_command(immutable_target, user, database, auth, backup_format)
                docker(command, stdout_handle=output_handle, secrets=secrets)
            output_handle.flush()
            os.fsync(output_handle.fileno())
        size = staging.stat().st_size
        if size <= 0:
            raise RuntimeError("backup command produced an empty artifact")
        checksum = sha256_file(staging)
        manifest = artifact_manifest(
            output=output,
            container=container,
            inspected=inspected,
            user=user,
            database=database,
            backup_format=backup_format,
            scope=scope,
            size=size,
            checksum=checksum,
            command=command,
            provenance=provenance,
            password_source=password_source,
            secrets=secrets,
            identity_preflight=identity_preflight,
        )
        manifest_path = publish_artifact(staging, output, manifest)
        return {
            "backup": str(output),
            "manifest": str(manifest_path),
            "size": size,
            "sha256": checksum,
            "format": backup_format,
            "scope": scope,
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "container_identity_preflight": identity_preflight,
        }
    finally:
        with contextlib.suppress(FileNotFoundError):
            staging.unlink()


def descriptor_for(args: argparse.Namespace, path: Path, *, require_manifest: bool) -> tuple[dict[str, Any] | None, str, str, str]:
    if not path.is_file():
        raise RuntimeError(f"backup file does not exist: {path}")
    manifest = load_manifest(path)
    if require_manifest and not manifest and not getattr(args, "allow_unmanifested", False):
        raise RuntimeError("backup manifest is required; pass --allow-unmanifested only for a reviewed legacy database dump")
    if not manifest and getattr(args, "allow_unmanifested", False):
        if getattr(args, "scope", None) != DATABASE_SCOPE or getattr(args, "format", None) not in {"custom", "plain"}:
            raise RuntimeError("--allow-unmanifested requires explicit --scope database and --format custom|plain")
    manifest_format = (manifest or {}).get("format")
    if args.format and manifest_format and args.format != manifest_format:
        raise RuntimeError(f"--format {args.format!r} conflicts with manifest format {manifest_format!r}")
    backup_format = args.format or manifest_format or ("custom" if path.suffix == ".dump" else "plain")
    scope = validate_scope(getattr(args, "scope", None), backup_format)
    manifest_scope = (manifest or {}).get("scope")
    if manifest_scope and manifest_scope != scope:
        raise RuntimeError(f"manifest scope {manifest_scope!r} conflicts with {scope!r} format scope")
    checksum = sha256_file(path)
    if manifest:
        if manifest.get("type") != TOOL_NAME:
            raise RuntimeError("backup manifest has an unexpected type")
        expected = manifest.get("sha256")
        if not expected:
            raise RuntimeError("backup manifest does not contain a SHA-256 checksum")
        if expected != checksum:
            raise RuntimeError("backup checksum does not match manifest")
        if manifest.get("size") is not None and int(manifest["size"]) != path.stat().st_size:
            raise RuntimeError("backup size does not match manifest")
        schema = manifest.get("schema_version")
        if schema is not None and schema != MANIFEST_SCHEMA_VERSION:
            raise RuntimeError(f"unsupported backup manifest schema version: {schema}")
        if schema == MANIFEST_SCHEMA_VERSION:
            source = manifest.get("source") or {}
            source_postgres = source.get("postgres") or {}
            if not (source.get("container") or {}).get("id") or source_postgres.get("scope") != scope:
                raise RuntimeError("v2 manifest is missing source provenance")
            if scope == DATABASE_SCOPE and not source_postgres.get("database"):
                raise RuntimeError("v2 database manifest is missing its source database")
            if scope == CLUSTER_SCOPE and source_postgres.get("database") is not None:
                raise RuntimeError("v2 cluster manifest must not claim one source database")
    if scope == CLUSTER_SCOPE and (not manifest or manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION):
        raise RuntimeError("cluster-scope verification requires a v2 manifest with explicit source provenance")
    if scope == DATABASE_SCOPE:
        validate_database_dump_structure(path, backup_format)
    return manifest, backup_format, scope, checksum


def scratch_db_name() -> str:
    return f"codex_verify_{uuid.uuid4().hex[:12]}"


def create_scratch_db_command(container: str, user: str, auth: list[str], scratch_db: str) -> list[str]:
    return ["exec", container, *auth, "createdb", "-U", user, "-T", "template0", scratch_db]


def drop_scratch_db_command(container: str, user: str, auth: list[str], scratch_db: str) -> list[str]:
    return ["exec", container, *auth, "dropdb", "--if-exists", "--force", "-U", user, scratch_db]


def restore_into_scratch_command(container: str, user: str, auth: list[str], scratch_db: str, backup_format: str) -> list[str]:
    prefix = ["exec", "-i", container, *auth]
    if backup_format == "custom":
        return [*prefix, "pg_restore", "--no-owner", "--exit-on-error", "-U", user, "-d", scratch_db]
    if backup_format == "plain":
        return [*prefix, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", scratch_db]
    raise RuntimeError("database scratch restore accepts only custom or plain database dumps")


def deep_verify_database(
    path: Path,
    container: str,
    user: str,
    password: str | None,
    backup_format: str,
    expected_signature: dict[str, Any] | None,
    *,
    expected_container_id: str | None,
    phase: str,
) -> dict[str, Any]:
    if backup_scope(backup_format) != DATABASE_SCOPE:
        raise RuntimeError("database verification cannot accept a cluster-scope dump")
    expected_container_id = require_expected_container_id(
        expected_container_id,
        operation=phase,
    )
    scratch = scratch_db_name()
    secrets = (password,) if password else ()
    body_error: BaseException | None = None
    created = False
    signature: dict[str, int] | None = None
    restore_returncode: int | None = None
    _inspected, _env, identity_preflight = container_identity_preflight(
        container,
        expected_container_id,
        phase=phase,
    )
    immutable_target = identity_preflight["actual_id"]
    with postgres_auth(immutable_target, password) as auth:
        create = create_scratch_db_command(immutable_target, user, auth, scratch)
        restore = restore_into_scratch_command(immutable_target, user, auth, scratch, backup_format)
        drop = drop_scratch_db_command(immutable_target, user, auth, scratch)
        try:
            docker(create, secrets=secrets)
            created = True
            result = docker(restore, input_path=path, capture=True, check=False, secrets=secrets)
            restore_returncode = result.returncode
            if result.returncode != 0:
                raise RuntimeError(
                    f"test restore into scratch database failed (exit {result.returncode}): {redact_text(result.stderr, secrets).strip()}"
                )
            signature = database_signature(immutable_target, user, scratch, auth, secrets=secrets)
            if expected_signature is not None and signature != expected_signature:
                raise RuntimeError(
                    f"restored catalog signature does not match source: expected {expected_signature}, got {signature}"
                )
        except BaseException as exc:
            body_error = exc
            raise
        finally:
            cleanup = docker(drop, capture=True, check=False, secrets=secrets)
            if cleanup.returncode != 0:
                message = f"failed to drop scratch database {scratch}: {redact_text(cleanup.stderr, secrets).strip()}"
                surface_cleanup_failure(body_error, message)
    return {
        "test_restore": True,
        "verification_target": "scratch_database",
        "scratch_db": scratch,
        "scratch_created": created,
        "restore_returncode": restore_returncode,
        "catalog_signature": signature,
        "table_count": (signature or {}).get("tables"),
        "container_identity_preflight": identity_preflight,
    }


def disposable_cluster_name() -> str:
    return f"codex-pg-verify-{uuid.uuid4().hex[:12]}"


def wait_for_disposable_cluster(container: str, user: str, database: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error = ""
    consecutive_ready = 0
    while time.monotonic() < deadline:
        result = docker(
            ["exec", container, "pg_isready", "-U", user, "-d", database],
            capture=True,
            check=False,
        )
        if result.returncode == 0:
            consecutive_ready += 1
            if consecutive_ready >= 3:
                return
        else:
            consecutive_ready = 0
            last_error = result.stderr.strip() or result.stdout.strip()
        # The official image briefly exposes its initialization server before
        # stopping it and launching the final server. Require sustained health
        # so verification cannot race that intentional handoff.
        time.sleep(0.5)
    raise RuntimeError(f"disposable verification cluster did not become ready within {timeout:g}s: {last_error}")


def disposable_cluster_diagnostics(container: str) -> str:
    state = docker(["inspect", "--format", "{{json .State}}", container], capture=True, check=False)
    logs = docker(["logs", "--tail", "80", container], capture=True, check=False)
    state_text = state.stdout.strip() or state.stderr.strip() or f"inspect exit {state.returncode}"
    log_text = logs.stdout.strip() or logs.stderr.strip() or f"logs exit {logs.returncode}"
    return f"state: {state_text[:2000]}\nlogs:\n{log_text[-6000:]}"


def cleanup_disposable_cluster(container: str) -> None:
    result = docker(["rm", "--force", container], capture=True, check=False)
    if result.returncode != 0 and "No such container" not in result.stderr:
        raise RuntimeError(f"failed to remove disposable verification cluster {container}: {result.stderr.strip()}")


def expected_cluster_catalog(manifest: dict[str, Any] | None) -> dict[str, Any]:
    catalog = (((manifest or {}).get("source") or {}).get("postgres") or {}).get("catalog")
    if not isinstance(catalog, dict) or not isinstance(catalog.get("databases"), list) or not isinstance(catalog.get("roles"), list):
        raise RuntimeError("cluster test restore requires a v2 manifest with source cluster provenance")
    return catalog


def deep_verify_cluster(
    path: Path,
    manifest: dict[str, Any] | None,
    *,
    verification_image: str | None,
    timeout: float,
) -> dict[str, Any]:
    expected = expected_cluster_catalog(manifest)
    source_container = (((manifest or {}).get("source") or {}).get("container") or {})
    image = verification_image or source_container.get("image")
    if not image:
        raise RuntimeError("cluster test restore requires --verification-image or a source image in the manifest")
    source_id = source_container.get("id")
    target = disposable_cluster_name()
    suffix = uuid.uuid4().hex[:10]
    admin = f"codex_verify_admin_{suffix}"
    control_db = f"codex_verify_control_{suffix}"
    run_command = [
        "run",
        "--detach",
        "--rm",
        "--name",
        target,
        "--label",
        DISPOSABLE_LABEL,
        "--network",
        "none",
        "-e",
        "POSTGRES_HOST_AUTH_METHOD=trust",
        "-e",
        f"POSTGRES_USER={admin}",
        "-e",
        f"POSTGRES_DB={control_db}",
        image,
    ]
    attempted = False
    body_error: BaseException | None = None
    target_id: str | None = None
    actual: dict[str, Any] | None = None
    try:
        attempted = True
        result = docker(run_command, capture=True)
        target_id = result.stdout.strip()
        inspected = inspect_container(target)
        target_id = inspected.get("Id") or target_id
        if source_id and target_id == source_id:
            raise RuntimeError("cluster verification target resolved to the source container")
        wait_for_disposable_cluster(target, admin, control_db, timeout)
        restore = [
            "exec",
            "-i",
            target,
            "psql",
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            admin,
            "-d",
            control_db,
        ]
        restored = docker(restore, input_path=path, capture=True, check=False)
        if restored.returncode != 0:
            raise RuntimeError(f"cluster test restore failed in disposable target: {restored.stderr.strip()}")
        actual = cluster_signature(
            target,
            admin,
            [],
            exclude_databases={control_db},
            exclude_roles={admin},
        )
        if actual != expected:
            raise RuntimeError(f"restored cluster catalog does not match source provenance: expected {expected}, got {actual}")
    except BaseException as exc:
        diagnostics = disposable_cluster_diagnostics(target) if attempted else "target creation was not attempted"
        wrapped = RuntimeError(f"{exc}\ndisposable verification diagnostics:\n{diagnostics}")
        body_error = wrapped
        raise wrapped from exc
    finally:
        if attempted:
            try:
                cleanup_disposable_cluster(target)
            except BaseException as cleanup_error:
                surface_cleanup_failure(body_error, str(cleanup_error))
    return {
        "test_restore": True,
        "verification_target": "disposable_cluster",
        "source_container_id": source_id,
        "verification_container_id": target_id,
        "verification_container": target,
        "verification_image": image,
        "network": "none",
        "catalog": actual,
        "cleaned_up": True,
    }


def verification_summary(result: dict[str, Any], scope: str, checksum: str) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "verified_at": utc_timestamp(),
        "mode": "test_restore" if result.get("test_restore") else "lightweight",
        "scope": scope,
        "sha256": checksum,
        "ok": True,
    }
    for key in (
        "verification_target",
        "catalog_signature",
        "catalog",
        "verification_image",
        "table_count",
        "container_identity_preflight",
    ):
        if key in result:
            summary[key] = result[key]
    return summary


def record_verification(path: Path, manifest: dict[str, Any] | None, result: dict[str, Any], scope: str, checksum: str) -> None:
    if not manifest:
        return
    manifest["verification"] = verification_summary(result, scope, checksum)
    atomic_json_write(manifest_path_for(path), manifest, exclusive=False)


def manifest_container_name(manifest: dict[str, Any] | None) -> str | None:
    return ((((manifest or {}).get("source") or {}).get("container") or {}).get("name") or (manifest or {}).get("container"))


def manifest_database_name(manifest: dict[str, Any] | None) -> str | None:
    return ((((manifest or {}).get("source") or {}).get("postgres") or {}).get("database") or (manifest or {}).get("database"))


def manifest_database_signature(manifest: dict[str, Any] | None) -> dict[str, Any] | None:
    catalog = (((manifest or {}).get("source") or {}).get("postgres") or {}).get("catalog")
    if isinstance(catalog, dict) and all(key in catalog for key in ("tables", "sequences", "views", "functions")):
        return catalog
    return None


def do_verify(args: argparse.Namespace) -> dict[str, Any]:
    path = Path(args.file).expanduser().resolve()
    manifest, backup_format, scope, checksum = descriptor_for(args, path, require_manifest=True)
    test_restore = bool(args.test_restore)
    requested_container_id = getattr(args, "expect_container_id", None)
    selection_identity: dict[str, Any] | None = None

    if scope == CLUSTER_SCOPE:
        identity_preflight: dict[str, Any] | None = None
        if args.container and not requested_container_id:
            raise RuntimeError(
                "cluster verification --container requires --expect-container-id for an explicit source-still-matches check; "
                "omit both options for offline/disposable artifact verification"
            )
        if requested_container_id:
            container_hint = args.container or manifest_container_name(manifest)
            if not container_hint:
                raise RuntimeError("--expect-container-id requires --container or manifest source container provenance")
            _inspected, _env, identity_preflight = container_identity_preflight(
                container_hint,
                requested_container_id,
                phase="cluster verification source check",
            )
            selection_identity = identity_preflight
        if test_restore:
            result = deep_verify_cluster(
                path,
                manifest,
                verification_image=args.verification_image,
                timeout=args.verification_timeout,
            )
        else:
            result = {
                "ok": True,
                "format": backup_format,
                "scope": scope,
                "sha256": checksum,
                "note": "cluster dump checksum and manifest verified; use --test-restore for disposable-cluster verification",
            }
        if identity_preflight is not None:
            result["container_identity_preflight"] = identity_preflight
    else:
        requested_container_id = require_expected_container_id(
            requested_container_id,
            operation="database verification",
        )
        container_hint = args.container or manifest_container_name(manifest)
        container, _initial_inspected, _initial_env = select_container(container_hint)
        _inspected, env, identity_preflight = container_identity_preflight(
            container,
            requested_container_id,
            phase="database verification selection",
        )
        selection_identity = identity_preflight
        immutable_target = identity_preflight["actual_id"]
        database_default = manifest_database_name(manifest)
        user, database, password, _password_source = postgres_identity(args, env, database_default=database_default)
        secrets = (password,) if password else ()
        if test_restore:
            result = deep_verify_database(
                path,
                container,
                user,
                password,
                backup_format,
                manifest_database_signature(manifest),
                expected_container_id=immutable_target,
                phase="database strong verification",
            )
            result.update({"ok": True, "format": backup_format, "scope": scope, "sha256": checksum, "target_database": database})
        elif backup_format == "custom":
            _inspected, _env, identity_preflight = container_identity_preflight(
                container,
                immutable_target,
                phase="database archive verification",
            )
            immutable_target = identity_preflight["actual_id"]
            with postgres_auth(immutable_target, password) as auth:
                command = ["exec", "-i", immutable_target, *auth, "pg_restore", "--list"]
                listed = docker(command, input_path=path, capture=True, secrets=secrets)
            result = {
                "ok": True,
                "format": backup_format,
                "scope": scope,
                "sha256": checksum,
                "pg_restore_list": listed.stdout[:4000],
                "container_identity_preflight": identity_preflight,
            }
        else:
            result = {
                "ok": True,
                "format": backup_format,
                "scope": scope,
                "sha256": checksum,
                "note": "plain SQL checksum and manifest verified; use --test-restore for strong verification",
                "container_identity_preflight": identity_preflight,
            }
    result.setdefault("ok", True)
    result.setdefault("format", backup_format)
    result.setdefault("scope", scope)
    result.setdefault("sha256", checksum)
    if requested_container_id and isinstance(result.get("container_identity_preflight"), dict):
        result["container_identity_preflight"]["requested_expected_id"] = normalize_expected_container_id(requested_container_id)
        if selection_identity is not None:
            result["container_identity_preflight"]["selection_match"] = selection_identity["match"]
    record_verification(path, manifest, result, scope, checksum)
    return result


def do_restore(args: argparse.Namespace) -> dict[str, Any]:
    if not args.confirm_restore and not args.dry_run:
        raise RuntimeError("restore is destructive; pass --confirm-restore")
    path = Path(args.file).expanduser().resolve()
    manifest, backup_format, scope, checksum = descriptor_for(args, path, require_manifest=True)
    if scope == CLUSTER_SCOPE:
        raise RuntimeError(
            "cluster-scope in-place restore is refused: no staged replacement and rollback topology was declared; "
            "verify with --test-restore in the disposable cluster, then perform a separately reviewed staged cutover"
        )

    expected_container_id = require_expected_container_id(
        getattr(args, "expect_container_id", None),
        operation="database restore",
    )

    container_hint = args.container or manifest_container_name(manifest)
    container, _initial_inspected, _initial_env = select_container(container_hint)
    _inspected, env, initial_identity = container_identity_preflight(
        container,
        expected_container_id,
        phase="restore selection",
    )
    immutable_target = initial_identity["actual_id"]
    source_database = manifest_database_name(manifest)
    if args.database and source_database and args.database != source_database and not args.allow_database_remap:
        raise RuntimeError(
            f"backup database {source_database!r} differs from target {args.database!r}; pass --allow-database-remap for an intentional clone"
        )
    user, database, password, _password_source = postgres_identity(args, env, database_default=source_database)
    secrets = (password,) if password else ()
    dry_auth = ["env", "PGPASSFILE=<ephemeral>"] if password else []
    command = restore_command(immutable_target, user, database, dry_auth, backup_format)

    if args.dry_run:
        return {
            "dry_run": True,
            "restore_file": str(path),
            "container": container,
            "database": database,
            "scope": scope,
            "format": backup_format,
            "sha256": checksum,
            "command": command_result(command),
            "safety_backup": None if args.no_safety_backup else {"planned": True, "out_dir": str(Path(args.safety_out_dir).expanduser().resolve())},
            "container_identity_preflight": initial_identity,
        }

    expected_signature = manifest_database_signature(manifest)
    incoming_verification = deep_verify_database(
        path,
        container,
        user,
        password,
        backup_format,
        expected_signature,
        expected_container_id=immutable_target,
        phase="restore incoming verification",
    )
    _inspected, _env, post_incoming_identity = container_identity_preflight(
        container,
        immutable_target,
        phase="restore post-incoming preflight",
    )

    safety_backup: dict[str, Any] | None = None
    safety_verification: dict[str, Any] | None = None
    if not args.no_safety_backup:
        backup_args = argparse.Namespace(
            container=container,
            user=user,
            database=database,
            _password_override=password,
            password_file=None,
            password_stdin=False,
            format="custom",
            scope=DATABASE_SCOPE,
            out_dir=str(Path(args.safety_out_dir).expanduser().resolve()),
            output=None,
            dry_run=False,
            expect_container_id=immutable_target,
        )
        safety_backup = do_backup(backup_args)
        safety_path = Path(safety_backup["backup"])
        safety_manifest = load_manifest(safety_path)
        safety_verification = deep_verify_database(
            safety_path,
            container,
            user,
            password,
            "custom",
            manifest_database_signature(safety_manifest),
            expected_container_id=immutable_target,
            phase="restore safety-backup verification",
        )
        record_verification(safety_path, safety_manifest, safety_verification, DATABASE_SCOPE, safety_backup["sha256"])

    _inspected, _env, final_identity = container_identity_preflight(
        container,
        immutable_target,
        phase="restore final mutation",
    )
    immutable_target = final_identity["actual_id"]
    with postgres_auth(immutable_target, password) as auth:
        command = restore_command(immutable_target, user, database, auth, backup_format)
        restored = docker(command, input_path=path, capture=True, check=False, secrets=secrets)
        if restored.returncode != 0:
            raise RuntimeError(
                f"transactional database restore failed and was rolled back (exit {restored.returncode}): "
                f"{redact_text(restored.stderr, secrets).strip()}"
            )
        restored_signature = database_signature(immutable_target, user, database, auth, secrets=secrets)
    if expected_signature is not None and restored_signature != expected_signature:
        raise RuntimeError(
            f"post-restore catalog signature does not match the verified source; safety backup retained at {(safety_backup or {}).get('backup', 'not created')}"
        )
    return {
        "restored": str(path),
        "container": container,
        "database": database,
        "format": backup_format,
        "scope": scope,
        "sha256": checksum,
        "transactional": True,
        "incoming_verification": incoming_verification,
        "safety_backup": safety_backup,
        "safety_verification": safety_verification,
        "restored_catalog_signature": restored_signature,
        "container_identity_preflights": [initial_identity, post_incoming_identity, final_identity],
    }


def do_doctor() -> dict[str, Any]:
    version = docker(["version", "--format", "{{json .}}"], capture=True, check=False)
    containers = list_postgres_containers()
    return {
        "tool_version": TOOL_VERSION,
        "docker_returncode": version.returncode,
        "docker_version": version.stdout.strip(),
        "postgres_containers": containers,
    }


def add_auth_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--user")
    parser.add_argument("--password-file", help="read the password from a current-user-only file (mode 0600)")
    parser.add_argument("--password-stdin", action="store_true", help="read the password from this process's stdin")


def add_container_identity_argument(parser: argparse.ArgumentParser, *, required: bool = False) -> None:
    parser.add_argument(
        "--expect-container-id",
        required=required,
        help=(
            "immutable 64-character or unambiguous standard 12-character Docker ID; required for backup, "
            "database-scope verification, and database restore; optional for an explicit cluster-source "
            "still-matches check"
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Backup and restore Docker PostgreSQL databases safely.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list")
    sub.add_parser("doctor")

    backup = sub.add_parser("backup")
    backup.add_argument("--container")
    add_container_identity_argument(backup, required=True)
    backup.add_argument("--database")
    add_auth_arguments(backup)
    backup.add_argument("--format", choices=["custom", "plain", "all"], default="custom")
    backup.add_argument("--scope", choices=[DATABASE_SCOPE, CLUSTER_SCOPE])
    backup.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    backup.add_argument("--output")
    backup.add_argument("--dry-run", action="store_true")

    verify = sub.add_parser("verify")
    verify.add_argument("--container")
    add_container_identity_argument(verify)
    verify.add_argument("--database")
    add_auth_arguments(verify)
    verify.add_argument("--file", required=True)
    verify.add_argument("--format", choices=["custom", "plain", "all"])
    verify.add_argument("--scope", choices=[DATABASE_SCOPE, CLUSTER_SCOPE])
    verify.add_argument("--allow-unmanifested", action="store_true")
    verify.add_argument("--test-restore", action="store_true")
    verify.add_argument("--verification-image", help="override the disposable cluster image for a cluster-scope test restore")
    verify.add_argument("--verification-timeout", type=float, default=60.0)

    restore = sub.add_parser("restore")
    restore.add_argument("--container")
    add_container_identity_argument(restore)
    restore.add_argument("--database")
    add_auth_arguments(restore)
    restore.add_argument("--file", required=True)
    restore.add_argument("--format", choices=["custom", "plain", "all"])
    restore.add_argument("--scope", choices=[DATABASE_SCOPE, CLUSTER_SCOPE])
    restore.add_argument("--allow-unmanifested", action="store_true")
    restore.add_argument("--allow-database-remap", action="store_true")
    restore.add_argument("--confirm-restore", action="store_true")
    restore.add_argument("--no-safety-backup", action="store_true")
    restore.add_argument("--safety-out-dir", default=f"{DEFAULT_OUT_DIR}/pre-restore")
    restore.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    previous_umask = os.umask(0o077)
    try:
        raw_argv = list(sys.argv[1:] if argv is None else argv)
        if any(item == "--password" or item.startswith("--password=") for item in raw_argv):
            print(
                json.dumps({"error": "--password is unsafe and unsupported; use --password-file or --password-stdin"}, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 2
        args = build_parser().parse_args(raw_argv)
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
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":
    raise SystemExit(main())
