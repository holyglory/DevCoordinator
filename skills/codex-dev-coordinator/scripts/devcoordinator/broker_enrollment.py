"""Administrative enrollment for the standard cross-UID broker workflow."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import stat
import time
from typing import Any, Callable, Iterable, Mapping, Sequence
import uuid

from .broker import BrokerOperation
from .broker_persistence import BrokerPersistence
from .broker_profile import PROFILE_VERSION
from .repository_lifecycle import LifecycleError, RepositoryLifecycle, ResourceKind
from .sqlite_lifecycle import SQLiteLifecyclePersistence
from .store import CoordinatorStore, deterministic_id, fingerprint, utc_timestamp


def enroll_repository(
    *,
    database_path: Path,
    socket_path: Path,
    socket_gid: int,
    client_uid: int,
    account_id: str,
    canonical_root: str,
    servers: Sequence[Mapping[str, Any]],
    port_start: int,
    port_end: int,
    profile_path: Path,
    compose: Mapping[str, Any] | None = None,
    observe_host: Callable[[CoordinatorStore], None] | None = None,
    explicit_reinstall: bool = False,
    validity_seconds: int = 30 * 24 * 60 * 60,
) -> dict[str, Any]:
    """Synchronize trusted definitions/ACLs and atomically install a profile.

    This is an administrator surface, not a broker wire operation. Paths and
    launch definitions are read locally by the service owner and remain in its
    private database; the emitted client profile contains opaque IDs only.
    """

    service_uid = os.geteuid()
    if service_uid != 0:
        raise PermissionError("broker enrollment must run as the root service administrator")
    if type(client_uid) is not int or client_uid < 0:
        raise ValueError("client_uid must be a non-negative integer")
    if type(socket_gid) is not int or socket_gid < 0:
        raise ValueError("socket_gid must be a non-negative integer")
    if not 1 <= port_start <= port_end <= 65535:
        raise ValueError("broker enrollment port range is invalid")
    if not 60 <= validity_seconds <= 365 * 24 * 60 * 60:
        raise ValueError("profile validity must be from one minute through one year")
    root = Path(canonical_root).resolve(strict=True)
    _require_real_git_root(root)
    if not socket_path.is_absolute():
        raise ValueError("broker socket path must be absolute")

    persistence = BrokerPersistence(database_path, expected_uid=service_uid)
    now = utc_timestamp()
    with CoordinatorStore.open(database_path, expected_uid=service_uid) as store:
        host_id = _ensure_host(store)
        repo_id = deterministic_id("repository", host_id, str(root))
        with store.immediate_transaction() as connection:
            existing = connection.execute(
                """
                SELECT repo_id, state, generation
                FROM repositories
                WHERE host_id = ? AND canonical_root = ?
                """,
                (host_id, str(root)),
            ).fetchone()
            if existing is not None and str(existing["repo_id"]) != repo_id:
                raise RuntimeError("canonical repository root resolves to a conflicting normalized ID")
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'active', 0, ?, ?)
                    """,
                    (repo_id, host_id, str(root), root.name or str(root), now, now),
                )
            else:
                if str(existing["state"]) != "active":
                    raise RuntimeError(
                        "repository identity is missing or relocated; observe and reconcile it before enrollment"
                    )
                connection.execute(
                    """
                    UPDATE repositories
                    SET display_name = ?, updated_at = ?
                    WHERE repo_id = ?
                    """,
                    (root.name or str(root), now, repo_id),
                )

        persistence_api = SQLiteLifecyclePersistence(store)
        lifecycle = RepositoryLifecycle(persistence_api, object())
        with store.read_transaction() as connection:
            installation = connection.execute(
                """
                SELECT status, startup_fenced
                FROM repository_installations WHERE repo_id = ?
                """,
                (repo_id,),
            ).fetchone()
        if installation is None:
            lifecycle.install_repository(
                repo_id,
                actor="broker-enrollment",
                reason="administrator enrollment",
                explicit=True,
            )
        elif str(installation["status"]) != "installed" or bool(
            installation["startup_fenced"]
        ):
            if not explicit_reinstall:
                raise RuntimeError(
                    "repository is disabled in the service authority; reinstall it explicitly through the Coordinator skill"
                )
            lifecycle.reinstall_repository(
                repo_id,
                actor="broker-enrollment",
                reason="explicit administrator reenrollment",
                explicit=True,
            )

        with store.immediate_transaction() as connection:
            server_ids: dict[str, str] = {}
            for raw in servers:
                name = str(raw.get("name") or "").strip()
                if not name or len(name) > 128:
                    raise ValueError("every enrolled server requires a bounded name")
                cwd = Path(str(raw.get("cwd") or root)).resolve(strict=True)
                if not _within(cwd, root):
                    raise ValueError(f"enrolled server cwd escapes canonical repository: {cwd}")
                server_id = deterministic_id("server-definition", repo_id, name)
                definition = {
                    "repo_id": repo_id,
                    "name": name,
                    "role": raw.get("role"),
                    "cwd": str(cwd),
                    "cmd": raw.get("cmd"),
                    "argv": raw.get("argv"),
                    "health_url": raw.get("health_url"),
                    "env": raw.get("env"),
                }
                connection.execute(
                    """
                    INSERT INTO server_definitions(
                        server_definition_id, repo_id, name, role, cwd,
                        health_url_template, definition_fingerprint, generation,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                    ON CONFLICT(server_definition_id) DO UPDATE SET
                        role = excluded.role,
                        cwd = excluded.cwd,
                        health_url_template = excluded.health_url_template,
                        definition_fingerprint = excluded.definition_fingerprint,
                        generation = server_definitions.generation + 1,
                        updated_at = excluded.updated_at
                    """,
                    (
                        server_id,
                        repo_id,
                        name,
                        raw.get("role"),
                        str(cwd),
                        raw.get("health_url"),
                        "sha256:" + fingerprint(definition),
                        now,
                        now,
                    ),
                )
                connection.execute(
                    "DELETE FROM server_command_arguments WHERE server_definition_id = ?",
                    (server_id,),
                )
                argv = raw.get("argv")
                if isinstance(argv, list) and argv and all(isinstance(item, str) for item in argv):
                    connection.executemany(
                        """
                        INSERT INTO server_command_arguments(
                            server_definition_id, ordinal, argument
                        ) VALUES (?, ?, ?)
                        """,
                        [(server_id, index, item) for index, item in enumerate(argv)],
                    )
                server_ids[name] = server_id
        database_generation = store.metadata.database_generation

        if observe_host is not None:
            observe_host(store)
        with store.read_transaction() as connection:
            repository_row = connection.execute(
                "SELECT generation FROM repositories WHERE repo_id = ?", (repo_id,)
            ).fetchone()
        if repository_row is None:
            raise RuntimeError("repository disappeared during enrollment")
        repository_generation = int(repository_row["generation"])

    persistence.provision_principal(uid=client_uid, account_id=account_id)
    persistence.grant_repository_read(
        uid=client_uid,
        repo_id=repo_id,
        operation=BrokerOperation.REPOSITORY_LIST_REMOVED,
    )
    for operation in (
        BrokerOperation.REPOSITORY_PLAN_REMOVE,
        BrokerOperation.REPOSITORY_REMOVE,
        BrokerOperation.REPOSITORY_REINSTALL,
        BrokerOperation.RESOURCE_ATTACH,
        BrokerOperation.RESOURCE_PLAN_RETIRE,
        BrokerOperation.RESOURCE_RETIRE,
    ):
        persistence.grant_lifecycle(
            uid=client_uid,
            repo_id=repo_id,
            operation=operation,
        )
    for server_id in server_ids.values():
        for operation in (
            BrokerOperation.PORT_LEASE,
            BrokerOperation.PORT_RELEASE,
            BrokerOperation.PORT_ASSIGN,
            BrokerOperation.PORT_UNASSIGN,
        ):
            persistence.grant_resource(
                uid=client_uid,
                repo_id=repo_id,
                resource_kind="server",
                resource_id=server_id,
                operation=operation,
            )
        persistence.grant_port_range(
            uid=client_uid,
            repo_id=repo_id,
            server_definition_id=server_id,
            start_port=port_start,
            end_port=port_end,
            protocol="tcp",
            max_ttl_seconds=7 * 24 * 60 * 60,
        )

    container_ids = _grant_observed_containers(
        persistence, repo_id=repo_id, client_uid=client_uid
    )
    _grant_observed_databases(
        persistence, repo_id=repo_id, client_uid=client_uid
    )
    _grant_observed_lifecycle_resources(
        persistence, repo_id=repo_id, client_uid=client_uid
    )
    compose_definition_id = _provision_compose(
        persistence,
        repo_id=repo_id,
        client_uid=client_uid,
        root=root,
        compose=compose,
    )
    profile = _merge_profile(
        profile_path=profile_path,
        service={
            "socket": str(socket_path),
            "uid": service_uid,
            "gid": socket_gid,
            "mode": "0660",
            "database_generation": database_generation,
        },
        client_uid=client_uid,
        account_id=account_id,
        repository={
            "canonical_root": str(root),
            "repo_id": repo_id,
            "generation": repository_generation,
            "servers": server_ids,
            "containers": container_ids,
            "compose_definition_id": compose_definition_id,
        },
        validity_seconds=validity_seconds,
    )
    return {
        "status": "enrolled",
        "client_uid": client_uid,
        "account_id": account_id,
        "repo_id": repo_id,
        "server_ids": server_ids,
        "container_ids": container_ids,
        "compose_definition_id": compose_definition_id,
        "database_generation": database_generation,
        "profile_path": str(profile_path),
        "valid_until_epoch": profile["clients"][str(client_uid)]["valid_until_epoch"],
        "starts_resources": False,
    }


def _ensure_host(store: CoordinatorStore) -> str:
    machine = f"{platform.system()}\x1f{platform.node()}\x1f{socket.gethostname()}"
    machine_fingerprint = hashlib.sha256(machine.encode("utf-8")).hexdigest()
    host_id = deterministic_id("host", machine_fingerprint)
    now = utc_timestamp()
    with store.immediate_transaction() as connection:
        connection.execute(
            """
            INSERT INTO hosts(
                host_id, machine_fingerprint, platform, hostname,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(host_id) DO UPDATE SET updated_at = excluded.updated_at
            """,
            (host_id, machine_fingerprint, platform.system(), socket.gethostname(), now, now),
        )
    return host_id


def _grant_observed_containers(
    persistence: BrokerPersistence, *, repo_id: str, client_uid: int
) -> dict[str, str]:
    result: dict[str, str] = {}
    with CoordinatorStore.open(
        persistence.database_path, expected_uid=persistence.expected_uid
    ) as store:
        with store.read_transaction() as connection:
            rows = list(
                connection.execute(
                    """
                    SELECT d.docker_resource_id, d.full_container_id, d.current_name
                    FROM repository_memberships m
                    JOIN docker_resources d
                      ON d.docker_resource_id = m.host_resource_id
                    JOIN control_bindings b
                      ON b.binding_id = m.control_binding_id
                    WHERE m.repo_id = ? AND m.resource_kind = 'container'
                      AND b.authority_state = 'authoritative'
                    ORDER BY d.current_name, d.full_container_id
                    """,
                    (repo_id,),
                )
            )
    for row in rows:
        resource_id = str(row["docker_resource_id"])
        for operation in (
            BrokerOperation.DOCKER_START,
            BrokerOperation.DOCKER_STOP,
            BrokerOperation.DOCKER_RESTART,
        ):
            persistence.grant_resource(
                uid=client_uid,
                repo_id=repo_id,
                resource_kind="container",
                resource_id=resource_id,
                operation=operation,
            )
        result[str(row["current_name"])] = resource_id
        result[str(row["full_container_id"])] = resource_id
    return result


def _grant_observed_databases(
    persistence: BrokerPersistence, *, repo_id: str, client_uid: int
) -> None:
    with CoordinatorStore.open(
        persistence.database_path, expected_uid=persistence.expected_uid
    ) as store:
        with store.read_transaction() as connection:
            binding_ids = tuple(
                str(row["database_binding_id"])
                for row in connection.execute(
                    """
                    SELECT db.database_binding_id
                    FROM database_bindings db
                    JOIN repository_memberships m
                      ON m.repo_id = db.repo_id
                     AND m.resource_kind = 'container'
                     AND m.host_resource_id = db.docker_resource_id
                    JOIN control_bindings c ON c.binding_id = m.control_binding_id
                    WHERE db.repo_id = ? AND db.engine_kind = 'postgresql'
                      AND c.authority_state = 'authoritative'
                    ORDER BY db.database_binding_id
                    """,
                    (repo_id,),
                )
            )
    for binding_id in binding_ids:
        for operation in (
            BrokerOperation.DATABASE_BACKUP,
            BrokerOperation.DATABASE_RESTORE,
        ):
            persistence.grant_database(
                uid=client_uid,
                repo_id=repo_id,
                database_binding_id=binding_id,
                operation=operation,
            )


def _grant_observed_lifecycle_resources(
    persistence: BrokerPersistence, *, repo_id: str, client_uid: int
) -> None:
    exact_resources = []
    with CoordinatorStore.open(
        persistence.database_path, expected_uid=persistence.expected_uid
    ) as store:
        lifecycle = SQLiteLifecyclePersistence(store)
        with store.read_transaction() as connection:
            candidates = tuple(
                (
                    str(row["resource_kind"]),
                    str(row["resource_id"]),
                    str(row["binding_id"]),
                )
                for row in connection.execute(
                    """
                    SELECT u.resource_kind, u.resource_id, b.binding_id
                    FROM unassigned_resources u
                    JOIN control_bindings b
                      ON b.resource_kind = u.resource_kind
                     AND b.resource_id = u.resource_id
                    JOIN coordinator_sources s ON s.source_id = b.source_id
                    WHERE u.status = 'active'
                      AND b.authority_state = 'authoritative'
                      AND s.effective_uid = ?
                    ORDER BY u.resource_kind, u.resource_id, b.binding_id
                    """,
                    (client_uid,),
                )
            )
        for resource_kind, resource_id, binding_id in candidates:
            try:
                exact_resources.append(
                    lifecycle.resolve_standalone_resource(
                        ResourceKind(resource_kind), resource_id, binding_id
                    )
                )
            except (LifecycleError, ValueError):
                # Incomplete or conflicted observations are intentionally not
                # converted into an authorization grant. A later administrator
                # enrollment after a clean observation can provision them.
                continue
    for exact in exact_resources:
        for operation in (
            BrokerOperation.RESOURCE_ATTACH,
            BrokerOperation.RESOURCE_PLAN_RETIRE,
            BrokerOperation.RESOURCE_RETIRE,
        ):
            persistence.grant_lifecycle_resource(
                uid=client_uid,
                repo_id=repo_id,
                resource_kind=exact.kind.value,
                resource_id=exact.resource_id,
                control_binding_id=exact.control_binding_id,
                immutable_fingerprint=exact.immutable_fingerprint,
                ownership_fingerprint=exact.ownership_fingerprint,
                operation=operation,
            )


def _provision_compose(
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    client_uid: int,
    root: Path,
    compose: Mapping[str, Any] | None,
) -> str | None:
    if not compose or not compose.get("declared"):
        return None
    files: list[str] = []
    for raw in compose.get("files") or []:
        path = Path(str(raw))
        if not path.is_absolute():
            path = root / path
        path = path.resolve(strict=True)
        if not _within(path, root) or not path.is_file() or path.is_symlink():
            raise ValueError(f"Compose file is not a real repository file: {path}")
        files.append(str(path))
    if not files:
        raise ValueError("declared Compose enrollment requires at least one exact file")
    compose_id = deterministic_id("compose-definition", repo_id, *files)
    provision = getattr(persistence, "provision_compose_definition", None)
    if provision is None:
        raise RuntimeError("installed broker service lacks Compose definition persistence")
    provision(
        repo_id=repo_id,
        compose_definition_id=compose_id,
        cwd=str(root),
        files=tuple(files),
        services=tuple(str(item) for item in compose.get("services") or []),
        project_name=(None if compose.get("project_name") is None else str(compose["project_name"])),
        enabled=True,
    )
    for operation in (BrokerOperation.COMPOSE_UP, BrokerOperation.COMPOSE_DOWN):
        persistence.grant_resource(
            uid=client_uid,
            repo_id=repo_id,
            resource_kind="compose",
            resource_id=compose_id,
            operation=operation,
            enabled=True,
        )
    return compose_id


def _merge_profile(
    *,
    profile_path: Path,
    service: dict[str, Any],
    client_uid: int,
    account_id: str,
    repository: dict[str, Any],
    validity_seconds: int,
) -> dict[str, Any]:
    path = profile_path
    if not path.is_absolute():
        raise ValueError("broker profile output must be absolute")
    _ensure_root_profile_parent(path.parent)
    if path.exists():
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise PermissionError("existing broker profile is not a protected root-owned file")
        document = json.loads(path.read_text(encoding="utf-8"))
        if document.get("version") != PROFILE_VERSION or document.get("service") != service:
            raise RuntimeError("existing broker profile belongs to another service authority")
    else:
        document = {"version": PROFILE_VERSION, "service": service, "clients": {}}
    clients = document.setdefault("clients", {})
    key = str(client_uid)
    current = clients.get(key) if isinstance(clients.get(key), dict) else {}
    repositories = [
        item
        for item in current.get("repositories", [])
        if isinstance(item, dict)
        and item.get("canonical_root") != repository["canonical_root"]
    ]
    repositories.append(repository)
    repositories.sort(key=lambda item: str(item["canonical_root"]))
    now_epoch = int(time.time())
    clients[key] = {
        "account_id": account_id,
        "issued_at": utc_timestamp(now_epoch),
        "valid_until_epoch": now_epoch + validity_seconds,
        "repositories": repositories,
    }
    _atomic_write_root_json(path, document)
    return document


def _ensure_root_profile_parent(path: Path) -> None:
    if os.geteuid() != 0:
        raise PermissionError("broker profile installation requires root")
    if not path.is_absolute() or ".." in path.parts:
        raise PermissionError("broker profile directory must be an absolute protected path")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        if not current.exists():
            current.mkdir(mode=0o755)
        metadata = current.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise PermissionError(
                "every broker profile directory ancestor must be protected and root-owned"
            )


def _atomic_write_root_json(path: Path, document: Mapping[str, Any]) -> None:
    payload = (
        json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o644)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, 0, 0)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _require_real_git_root(root: Path) -> None:
    marker = root / ".git"
    root_metadata = root.lstat()
    marker_metadata = marker.lstat()
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError("enrollment project root must be a real directory")
    if stat.S_ISLNK(marker_metadata.st_mode) or not (
        stat.S_ISDIR(marker_metadata.st_mode) or stat.S_ISREG(marker_metadata.st_mode)
    ):
        raise ValueError("enrollment project must be a real Git worktree")


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
