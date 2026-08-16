"""Administrative configuration for the trusted-local broker catalog."""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import socket
import sqlite3
import stat
import time
from typing import Any, Callable, Generator, Mapping, Sequence
import uuid

from .broker import BrokerError, BrokerOperation
from .broker_persistence import (
    BrokerPersistence,
    ComposeConfigurationContainerScope,
    _default_compose_project_name,
    _normalize_ephemeral_environment,
    _require_ephemeral_secret_policy_environment,
    _require_ephemeral_argument,
    _require_ephemeral_template_name,
    _require_pinned_ephemeral_image,
    _require_compose_profile_name,
    _require_compose_project_name,
    _require_compose_service_name,
)
from .broker_profile import (
    PROFILE_VERSION,
    REPOSITORY_PROFILE_FIELDS,
    host_profile_from_document,
)
from .ephemeral_secrets import (
    deterministic_secret_binding_id,
    normalize_ephemeral_secret_policy,
)
from .compose_contract import (
    require_effective_compose_model,
    require_sealable_compose_payload,
)
from .compose_run_once import normalize_compose_run_once_policies
from .observation_freshness import (
    FULL_DOCKER_OBSERVER_DOMAIN,
    ObservationFreshnessError,
    ObservationFreshnessFence,
    capture_observation_freshness_fence,
    require_exact_fresh_observation,
)
from .repository_lifecycle import LifecycleError, RepositoryLifecycle, ResourceKind
from .sqlite_lifecycle import SQLiteLifecyclePersistence
from .store import (
    AccountStore,
    CoordinatorStore,
    deterministic_id,
    fingerprint,
    utc_timestamp,
)
from .worker_artifacts import provision_worker_log_directory


_FULL_DOCKER_OBSERVER_DOMAIN = FULL_DOCKER_OBSERVER_DOMAIN
_SHA256_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}")
_BARE_SHA256 = re.compile(r"[0-9a-f]{64}")
_EXACT_CONTAINER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_MAX_SERVER_ENVIRONMENT_ENTRIES = 128
_MAX_SERVER_ENVIRONMENT_NAME_BYTES = 256
_MAX_SERVER_ENVIRONMENT_VALUE_BYTES = 8_192
_MAX_SERVER_ENVIRONMENT_BYTES = 32_768


class DeclaredComposeConfigurationError(RuntimeError):
    """One repository-owned first-use Compose contract could not be sealed."""


class DeclaredRuntimeConfigurationError(RuntimeError):
    """One repository-owned runtime manifest could not be cataloged."""


def _runtime_manifest_document(root: Path) -> Mapping[str, Any] | None:
    """Read the bounded runtime manifest without creating an access gate."""

    manifest = root / ".codex" / "dev-runtime.json"
    try:
        metadata = manifest.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise DeclaredRuntimeConfigurationError(
            f"could not read {manifest.name}: {error}"
        ) from error
    if not stat.S_ISREG(metadata.st_mode) or manifest.is_symlink():
        raise DeclaredRuntimeConfigurationError(
            ".codex/dev-runtime.json must be one regular repository file"
        )
    if metadata.st_size > 2 * 1024 * 1024:
        raise DeclaredRuntimeConfigurationError(
            ".codex/dev-runtime.json exceeds the 2 MiB contract limit"
        )
    try:
        document = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DeclaredRuntimeConfigurationError(
            f"could not parse .codex/dev-runtime.json: {error}"
        ) from error
    if not isinstance(document, Mapping):
        raise DeclaredRuntimeConfigurationError(
            ".codex/dev-runtime.json must contain one JSON object"
        )
    return document


def _manifest_environment(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return _bounded_server_environment(value)
    if not isinstance(value, list) or len(value) > _MAX_SERVER_ENVIRONMENT_ENTRIES:
        raise DeclaredRuntimeConfigurationError(
            "server env must be a bounded string map or KEY=VALUE array"
        )
    environment: dict[str, str] = {}
    for raw in value:
        if not isinstance(raw, str):
            raise DeclaredRuntimeConfigurationError(
                "server env entries must be KEY=VALUE strings"
            )
        name, separator, item = raw.partition("=")
        if not separator or not name or name in environment:
            raise DeclaredRuntimeConfigurationError(
                "server env entries must be unique KEY=VALUE strings"
            )
        environment[name] = item
    try:
        return _bounded_server_environment(environment)
    except ValueError as error:
        raise DeclaredRuntimeConfigurationError(str(error)) from error


def declared_servers_from_runtime_manifest(root: Path) -> tuple[dict[str, Any], ...]:
    """Return exact persistent service definitions declared by one repository."""

    document = _runtime_manifest_document(root)
    if document is None:
        return ()
    raw_servers = document.get("servers", [])
    if raw_servers is None:
        return ()
    if not isinstance(raw_servers, list) or len(raw_servers) > 128:
        raise DeclaredRuntimeConfigurationError(
            "servers must be a JSON array with at most 128 entries"
        )
    servers: list[dict[str, Any]] = []
    names: set[str] = set()
    for raw in raw_servers:
        if not isinstance(raw, Mapping):
            raise DeclaredRuntimeConfigurationError(
                "every server declaration must be a JSON object"
            )
        name = str(raw.get("name") or "").strip()
        if not name or len(name) > 128 or name in names:
            raise DeclaredRuntimeConfigurationError(
                "server names must be unique non-empty strings of at most 128 characters"
            )
        names.add(name)
        cwd_raw = str(raw.get("cwd") or ".")
        cwd = (root / cwd_raw).resolve(strict=True) if not Path(cwd_raw).is_absolute() else Path(cwd_raw).resolve(strict=True)
        if not _within(cwd, root):
            raise DeclaredRuntimeConfigurationError(
                f"server {name!r} cwd escapes the repository"
            )
        argv_raw = raw.get("argv")
        if argv_raw is None and isinstance(raw.get("cmd"), str):
            try:
                argv_raw = shlex.split(str(raw["cmd"]))
            except ValueError as error:
                raise DeclaredRuntimeConfigurationError(
                    f"server {name!r} command is invalid"
                ) from error
        if (
            not isinstance(argv_raw, list)
            or not argv_raw
            or len(argv_raw) > 256
            or any(
                not isinstance(argument, str)
                or not argument
                or "\x00" in argument
                or len(argument.encode("utf-8")) > 8192
                for argument in argv_raw
            )
        ):
            raise DeclaredRuntimeConfigurationError(
                f"server {name!r} requires bounded structured argv"
            )
        port = raw.get("port")
        if port is not None and (
            isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
        ):
            raise DeclaredRuntimeConfigurationError(
                f"server {name!r} port must be from 1 through 65535"
            )
        servers.append(
            {
                "name": name,
                "role": raw.get("role"),
                "cwd": str(cwd),
                "argv": list(argv_raw),
                "health_url": raw.get("health_url"),
                "env": _manifest_environment(raw.get("env")),
                "port": port,
            }
        )
    return tuple(servers)


def _runtime_manifest_strings(
    value: Any,
    *,
    field: str,
    maximum: int,
    required: bool = False,
) -> tuple[str, ...]:
    if value is None:
        values: tuple[Any, ...] = ()
    elif isinstance(value, list):
        values = tuple(value)
    else:
        raise DeclaredComposeConfigurationError(f"{field} must be a JSON array")
    if len(values) > maximum:
        raise DeclaredComposeConfigurationError(
            f"{field} must contain at most {maximum} entries"
        )
    normalized: list[str] = []
    for item in values:
        if not isinstance(item, str) or not item.strip():
            raise DeclaredComposeConfigurationError(
                f"{field} entries must be non-empty strings"
            )
        normalized.append(item)
    if required and not normalized:
        raise DeclaredComposeConfigurationError(
            f"{field} must declare at least one entry"
        )
    if len(set(normalized)) != len(normalized):
        raise DeclaredComposeConfigurationError(
            f"{field} must not contain duplicates"
        )
    return tuple(normalized)


def declared_compose_from_runtime_manifest(root: Path) -> Mapping[str, Any] | None:
    """Read one bounded repository-owned Compose declaration for first use.

    The authority, not the client, turns repository paths into a sealed Compose
    definition.  Missing manifests or manifests without explicit Compose files
    simply mean the repository has no first-use Compose contract.
    """

    try:
        document = _runtime_manifest_document(root)
    except DeclaredRuntimeConfigurationError as error:
        raise DeclaredComposeConfigurationError(str(error)) from error
    if document is None:
        return None
    docker = document.get("docker")
    if docker is None:
        return None
    if not isinstance(docker, Mapping):
        raise DeclaredComposeConfigurationError("docker must be a JSON object")
    files = _runtime_manifest_strings(
        docker.get("compose_files") or docker.get("files"),
        field="docker.compose_files",
        maximum=16,
    )
    if not files:
        return None
    services = _runtime_manifest_strings(
        docker.get("services"),
        field="docker.services",
        maximum=128,
        required=True,
    )
    env_files = _runtime_manifest_strings(
        docker.get("env_files") or docker.get("env_file"),
        field="docker.env_files",
        maximum=16,
    )
    profiles = _runtime_manifest_strings(
        docker.get("profiles") or docker.get("profile"),
        field="docker.profiles",
        maximum=64,
    )
    project_name = docker.get("project_name")
    if project_name is not None and (
        not isinstance(project_name, str) or not project_name.strip()
    ):
        raise DeclaredComposeConfigurationError(
            "docker.project_name must be a non-empty string"
        )
    try:
        run_once = normalize_compose_run_once_policies(
            docker.get("run_once_services", ())
        )
    except (TypeError, ValueError) as error:
        raise DeclaredComposeConfigurationError(str(error)) from error
    if set(services) & {policy.name for policy in run_once}:
        raise DeclaredComposeConfigurationError(
            "docker.services and docker.run_once_services must be disjoint"
        )
    return {
        "declared": True,
        "files": files,
        "env_files": env_files,
        "profiles": profiles,
        "services": services,
        "run_once_services": tuple(policy.to_document() for policy in run_once),
        "project_name": project_name,
    }


def configure_repository(
    *,
    database_path: Path,
    socket_path: Path,
    execution_uid: int,
    canonical_root: str,
    servers: Sequence[Mapping[str, Any]],
    port_start: int,
    port_end: int,
    profile_path: Path,
    ephemeral_containers: Sequence[Mapping[str, Any]] = (),
    compose: Mapping[str, Any] | None = None,
    compose_model_renderer: Callable[..., bytes] | None = None,
    approve_compose_host_access: bool = False,
    observe_host: Callable[[AccountStore], Mapping[str, Any] | None] | None = None,
    explicit_reinstall: bool = False,
) -> dict[str, Any]:
    """Synchronize repository routing metadata and install a connection profile.

    This is an administrator surface, not a broker wire operation. Paths and
    launch definitions are read locally by the service owner and remain in its
    private database; the emitted client profile contains opaque IDs only.
    """

    service_uid = os.geteuid()
    if type(execution_uid) is not int or execution_uid <= 0:
        raise ValueError("execution_uid must be a positive integer")
    if not 1 <= port_start <= port_end <= 65535:
        raise ValueError("broker configuration port range is invalid")
    if compose and compose.get("declared") and observe_host is None:
        raise RuntimeError(
            "Compose configuration requires a fresh service-owned full-Docker observation"
        )
    if type(approve_compose_host_access) is not bool:
        raise TypeError("approve_compose_host_access must be a boolean")
    normalized_ephemeral = _normalize_ephemeral_templates(ephemeral_containers)
    if type(explicit_reinstall) is not bool:
        raise TypeError("explicit_reinstall must be a boolean")
    if approve_compose_host_access and not (compose and compose.get("declared")):
        raise ValueError(
            "Compose host-access approval requires a declared Compose definition"
        )
    if compose and compose.get("declared") and compose_model_renderer is None:
        from .broker_host import render_compose_effective_model

        compose_model_renderer = render_compose_effective_model
    root = Path(canonical_root).resolve(strict=True)
    _require_real_git_root(root)
    if not socket_path.is_absolute():
        raise ValueError("broker socket path must be absolute")
    _preflight_compose_definition(
        root=root,
        compose=compose,
        compose_model_renderer=compose_model_renderer,
        host_access_approved=approve_compose_host_access,
    )
    # Provision the only writable runner artifact location before changing
    # configuration authority. A failed filesystem boundary must not leave a new
    # principal/grant set that cannot produce broker-verifiable crash evidence.
    worker_log_root = provision_worker_log_directory(execution_uid)

    persistence = BrokerPersistence(
        database_path,
        expected_uid=service_uid,
        compose_model_renderer=compose_model_renderer,
    )
    now = utc_timestamp()
    # Host observation and normalized inventory are intentionally implemented
    # by AccountStore for both account-owned and service-owned databases.  Use
    # that adapter here so the real configuration observer receives the same
    # contract exercised by the normalized coordinator paths.
    with AccountStore.open(database_path, expected_uid=service_uid) as store:
        host_id = _ensure_host(store)
        repo_id = deterministic_id("repository", host_id, str(root))
        with store.immediate_transaction() as connection:
            existing = connection.execute(
                """
                SELECT repository.repo_id, repository.state,
                       repository.generation
                FROM repositories repository
                WHERE host_id = ? AND canonical_root = ?
                """,
                (host_id, str(root)),
            ).fetchone()
            if existing is not None and str(existing["repo_id"]) != repo_id:
                raise RuntimeError(
                    "canonical repository root resolves to a conflicting normalized ID"
                )
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
                if str(existing["state"]) == "missing":
                    removed_generation = int(existing["generation"]) - 1
                    revocation = connection.execute(
                        """
                        SELECT 1 FROM broker_repository_revocations
                        WHERE repo_id = ? AND repository_generation = ?
                        """,
                        (repo_id, removed_generation),
                    ).fetchone()
                    if revocation is None:
                        raise RuntimeError(
                            "repository identity is missing or relocated; observe and reconcile it before configuration"
                        )
                    if not explicit_reinstall:
                        raise RuntimeError(
                            "repository generation was permanently removed; reinstall it explicitly through the Coordinator skill"
                        )
                    changed = connection.execute(
                        """
                        UPDATE repositories
                        SET state = 'active', generation = generation + 1,
                            display_name = ?, updated_at = ?
                        WHERE repo_id = ? AND state = 'missing'
                          AND generation = ?
                        """,
                        (
                            root.name or str(root),
                            now,
                            repo_id,
                            int(existing["generation"]),
                        ),
                    ).rowcount
                    if changed != 1:
                        raise RuntimeError(
                            "repository generation changed during explicit reinstall"
                        )
                elif str(existing["state"]) == "active":
                    connection.execute(
                        """
                        UPDATE repositories
                        SET display_name = ?, updated_at = ?
                        WHERE repo_id = ?
                        """,
                        (root.name or str(root), now, repo_id),
                    )
                else:
                    raise RuntimeError(
                        "repository identity is relocated; observe and reconcile it before configuration"
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
                actor="broker-configuration",
                reason="administrator configuration",
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
                actor="broker-configuration",
                reason="explicit administrator reconfiguration",
                explicit=True,
            )

        with store.immediate_transaction() as connection:
            server_ids = _synchronize_server_definitions(
                connection,
                repo_id=repo_id,
                root=root,
                servers=servers,
                now=now,
                explicit_reinstall=explicit_reinstall,
            )
        database_generation = store.metadata.database_generation

        configured_server_ids = dict(server_ids)

        configuration_snapshot_id: str | None = None
        if observe_host is not None:
            configuration_snapshot_id = _capture_new_configuration_observation(
                store,
                host_id=host_id,
                observe_host=observe_host,
                require_complete_compose_assets=bool(
                    compose and compose.get("declared")
                ),
            )
        with store.read_transaction() as connection:
            repository_row = connection.execute(
                "SELECT generation FROM repositories WHERE repo_id = ?", (repo_id,)
            ).fetchone()
        if repository_row is None:
            raise RuntimeError("repository disappeared during configuration")
        repository_generation = int(repository_row["generation"])

    compose_observed_scope = _compose_configuration_container_scope(
        persistence,
        repo_id=repo_id,
        root=root,
        compose=compose,
        configuration_snapshot_id=configuration_snapshot_id,
    )

    persistence.replace_server_port_ranges(
        repo_id=repo_id,
        server_definition_ids=configured_server_ids.values(),
        start_port=port_start,
        end_port=port_end,
        protocol="tcp",
        max_ttl_seconds=7 * 24 * 60 * 60,
    )

    container_ids: dict[str, str] = {}
    grant_snapshot_id: str | None = None
    if observe_host is not None:
        # One exact post-boundary host snapshot is sufficient for configuration,
        # grants, and Compose collision checks.  Recapturing the entire Docker
        # host here doubled configuration latency and could pair an incomplete
        # transient scan with a later complete one.  Reuse the already fenced
        # snapshot instead.
        grant_snapshot_id = configuration_snapshot_id
        if grant_snapshot_id is None:
            raise RuntimeError("repository observation disappeared before association")
        container_ids = _associate_observed_resources(
            persistence,
            repo_id=repo_id,
            snapshot_id=grant_snapshot_id,
            excluded_container_ids=(
                ()
                if compose_observed_scope is None
                else compose_observed_scope.non_lifecycle_container_ids
            ),
        )

    compose_run_once_services = _compose_run_once_mapping(compose=compose)
    compose_definition_id = _provision_compose(
        persistence,
        repo_id=repo_id,
        root=root,
        compose=compose,
        observation_snapshot_id=configuration_snapshot_id,
        host_access_approved=approve_compose_host_access,
    )
    compose_container_ids = _compose_owned_container_ids_for_profile(
        persistence,
        repo_id=repo_id,
        root=root,
        compose=compose,
        compose_definition_id=compose_definition_id,
        configuration_snapshot_id=configuration_snapshot_id,
        configured_container_ids=frozenset(container_ids.values()),
    )
    ephemeral_templates = _provision_ephemeral_templates(
        persistence,
        repo_id=repo_id,
        templates=normalized_ephemeral,
    )
    ephemeral_secret_policies = _ephemeral_secret_policy_profiles(
        repo_id=repo_id,
        template_ids=ephemeral_templates,
        templates=normalized_ephemeral,
    )
    _merge_profile(
        profile_path=profile_path,
        service={
            "socket": str(socket_path),
            "database_generation": database_generation,
        },
        repository={
            "canonical_root": str(root),
            "repo_id": repo_id,
            "generation": repository_generation,
            "servers": configured_server_ids,
            "containers": container_ids,
            "compose_definition_id": compose_definition_id,
            "compose_container_ids": list(compose_container_ids),
            "compose_run_once_services": compose_run_once_services,
            "ephemeral_templates": ephemeral_templates,
            "ephemeral_secret_policies": ephemeral_secret_policies,
        },
    )
    return {
        "status": "configured",
        "execution_uid": execution_uid,
        "repo_id": repo_id,
        "server_ids": configured_server_ids,
        "defined_server_ids": server_ids,
        "container_ids": container_ids,
        "compose_definition_id": compose_definition_id,
        "compose_container_ids": list(compose_container_ids),
        "compose_run_once_services": compose_run_once_services,
        "ephemeral_templates": ephemeral_templates,
        "ephemeral_secret_policies": ephemeral_secret_policies,
        "configuration_snapshot_id": configuration_snapshot_id,
        "association_snapshot_id": grant_snapshot_id,
        "database_generation": database_generation,
        "profile_path": str(profile_path),
        "starts_resources": False,
        "worker_log_root": str(worker_log_root),
        "observation_snapshot_id": configuration_snapshot_id,
    }


def _synchronize_server_definitions(
    connection: sqlite3.Connection,
    *,
    repo_id: str,
    root: Path,
    servers: Sequence[Mapping[str, Any]],
    now: str,
    explicit_reinstall: bool,
) -> dict[str, str]:
    """Persist exact worker definitions without reviving a purged identity."""

    specifications: list[dict[str, Any]] = []
    names: set[str] = set()
    for raw in servers:
        if not isinstance(raw, Mapping):
            raise TypeError("every configured server definition must be an object")
        name = str(raw.get("name") or "").strip()
        if not name or len(name) > 128:
            raise ValueError("every configured server requires a bounded name")
        if name in names:
            raise ValueError(f"duplicate configured server name: {name}")
        names.add(name)
        cwd = Path(str(raw.get("cwd") or root)).resolve(strict=True)
        if not _within(cwd, root):
            raise ValueError(
                f"configured server cwd escapes canonical repository: {cwd}"
            )
        environment = _bounded_server_environment(raw.get("env"))
        specifications.append(
            {
                "raw": raw,
                "name": name,
                "cwd": str(cwd),
                "environment": environment,
            }
        )

    active_ids = {
        str(row["name"]): str(row["server_definition_id"])
        for row in connection.execute(
            """
            SELECT name, server_definition_id
            FROM server_definitions
            WHERE repo_id = ?
            """,
            (repo_id,),
        )
    }
    missing_names = {item["name"] for item in specifications} - set(active_ids)
    tombstones = (
        _reinstall_server_tombstones_by_name(connection, repo_id=repo_id)
        if missing_names
        else {}
    )
    server_ids: dict[str, str] = {}
    for item in specifications:
        raw = item["raw"]
        name = str(item["name"])
        server_id = active_ids.get(name)
        tombstone = tombstones.get(name)
        if server_id is None and tombstone is not None:
            if not explicit_reinstall:
                raise RuntimeError(
                    f"server {name!r} was permanently removed; reinstall it explicitly through the Coordinator skill"
                )
            server_id = _reinstalled_server_id(
                repo_id=repo_id,
                name=name,
                tombstone=tombstone,
            )
        elif server_id is None:
            server_id = deterministic_id("server-definition", repo_id, name)

        conflicting = connection.execute(
            """
            SELECT repo_id, name
            FROM server_definitions
            WHERE server_definition_id = ?
              AND (repo_id != ? OR name != ?)
            """,
            (server_id, repo_id, name),
        ).fetchone()
        if conflicting is not None:
            raise RuntimeError(
                "derived server identity conflicts with another persisted definition"
            )
        definition = {
            "repo_id": repo_id,
            "name": name,
            "role": raw.get("role"),
            "cwd": item["cwd"],
            "cmd": raw.get("cmd"),
            "argv": raw.get("argv"),
            "health_url": raw.get("health_url"),
            "env": item["environment"],
        }
        definition_fingerprint = "sha256:" + fingerprint(definition)
        current = connection.execute(
            """
            SELECT definition_fingerprint
            FROM server_definitions
            WHERE repo_id = ? AND server_definition_id = ?
            """,
            (repo_id, server_id),
        ).fetchone()
        if (
            current is not None
            and str(current["definition_fingerprint"]) == definition_fingerprint
        ):
            server_ids[name] = server_id
            continue
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
                item["cwd"],
                raw.get("health_url"),
                definition_fingerprint,
                now,
                now,
            ),
        )
        connection.execute(
            "DELETE FROM server_command_arguments WHERE server_definition_id = ?",
            (server_id,),
        )
        argv = raw.get("argv")
        if (
            isinstance(argv, list)
            and argv
            and all(isinstance(argument, str) for argument in argv)
        ):
            connection.executemany(
                """
                INSERT INTO server_command_arguments(
                    server_definition_id, ordinal, argument
                ) VALUES (?, ?, ?)
                """,
                [
                    (server_id, index, argument)
                    for index, argument in enumerate(argv)
                ],
            )
        connection.execute(
            "DELETE FROM server_environment WHERE server_definition_id = ?",
            (server_id,),
        )
        if item["environment"]:
            connection.executemany(
                """
                INSERT INTO server_environment(
                    server_definition_id, name, value
                ) VALUES (?, ?, ?)
                """,
                [
                    (server_id, key, value)
                    for key, value in item["environment"].items()
                ],
            )
        server_ids[name] = server_id
    return server_ids


def _reinstall_server_tombstones_by_name(
    connection: sqlite3.Connection, *, repo_id: str
) -> dict[str, Mapping[str, Any]]:
    grouped: dict[str, dict[tuple[str, str, str], Mapping[str, Any]]] = {}
    rows = connection.execute(
        """
        SELECT target_id, immutable_fingerprint, operation_id,
               evidence_json, removed_at
        FROM cleanup_tombstones
        WHERE target_kind = 'server' AND repo_id = ?
        ORDER BY removed_at DESC, target_id DESC
        """,
        (repo_id,),
    )
    for row in rows:
        try:
            evidence = json.loads(str(row["evidence_json"]))
        except (json.JSONDecodeError, TypeError) as error:
            raise RuntimeError(
                "server cleanup evidence is unreadable; configuration cannot safely determine identity lineage"
            ) from error
        if not isinstance(evidence, dict):
            raise RuntimeError(
                "server cleanup evidence is invalid; configuration cannot safely determine identity lineage"
            )
        plan = evidence.get("plan")
        snapshot = evidence.get("snapshot")
        target = plan.get("target") if isinstance(plan, dict) else None
        if not isinstance(target, dict) and isinstance(snapshot, dict):
            target = snapshot.get("target")
        name = target.get("display_name") if isinstance(target, dict) else None
        if not isinstance(name, str) or not name:
            raise RuntimeError(
                "server cleanup evidence lacks its exact name; configuration cannot safely determine identity lineage"
            )
        normalized = dict(row)
        key = (
            str(normalized["target_id"]),
            str(normalized["immutable_fingerprint"]),
            str(normalized["operation_id"]),
        )
        grouped.setdefault(name, {})[key] = normalized
    for row in connection.execute(
        """
        SELECT server_definition_id AS target_id,
               immutable_fingerprint,
               cleanup_operation_id AS operation_id,
               server_name
        FROM broker_server_revocations
        WHERE repo_id = ?
        ORDER BY revoked_at DESC, server_definition_id DESC
        """,
        (repo_id,),
    ):
        normalized = dict(row)
        key = (
            str(normalized["target_id"]),
            str(normalized["immutable_fingerprint"]),
            str(normalized["operation_id"]),
        )
        grouped.setdefault(str(row["server_name"]), {})[key] = normalized
    result: dict[str, Mapping[str, Any]] = {}
    for name, grouped_candidates in grouped.items():
        candidates = list(grouped_candidates.values())
        tombstoned_ids = {str(row["target_id"]) for row in candidates}
        lineage_tips = [
            row
            for row in candidates
            if _reinstalled_server_id(
                repo_id=repo_id,
                name=name,
                tombstone=row,
            )
            not in tombstoned_ids
        ]
        if len(lineage_tips) != 1:
            raise RuntimeError(
                "server cleanup evidence has ambiguous identity lineage; configuration requires administrative reconciliation"
            )
        result[name] = lineage_tips[0]
    return result


def _reinstalled_server_id(
    *, repo_id: str, name: str, tombstone: Mapping[str, Any]
) -> str:
    return deterministic_id(
        "server-definition-incarnation",
        repo_id,
        name,
        str(tombstone["target_id"]),
        str(tombstone["immutable_fingerprint"]),
        str(tombstone["operation_id"]),
    )


def _bounded_server_environment(value: Any) -> dict[str, str]:
    if value is None or (isinstance(value, (list, tuple)) and not value):
        return {}
    if not isinstance(value, Mapping) or len(value) > _MAX_SERVER_ENVIRONMENT_ENTRIES:
        raise ValueError("server env must be a bounded NUL-free string map")
    environment: dict[str, str] = {}
    total_bytes = 0
    for name, item in value.items():
        if (
            not isinstance(name, str)
            or not name
            or "=" in name
            or "\x00" in name
            or len(name.encode("utf-8")) > _MAX_SERVER_ENVIRONMENT_NAME_BYTES
            or not isinstance(item, str)
            or "\x00" in item
            or len(item.encode("utf-8")) > _MAX_SERVER_ENVIRONMENT_VALUE_BYTES
        ):
            raise ValueError("server env must be a bounded NUL-free string map")
        total_bytes += len(name.encode("utf-8")) + len(item.encode("utf-8"))
        environment[name] = item
    if total_bytes > _MAX_SERVER_ENVIRONMENT_BYTES:
        raise ValueError("server env must be a bounded NUL-free string map")
    return dict(sorted(environment.items()))


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
            (
                host_id,
                machine_fingerprint,
                platform.system(),
                socket.gethostname(),
                now,
                now,
            ),
        )
    return host_id


def _require_configuration_snapshot(
    store: CoordinatorStore,
    *,
    observation: Mapping[str, Any],
    host_id: str,
) -> str:
    """Validate an explicitly supplied newest committed observation snapshot.

    New configuration uses the stricter per-call freshness fence below. This
    validator remains the compatibility boundary for callers that already
    captured a snapshot and must still prove its exact durable fingerprints.
    """

    if not isinstance(observation, Mapping):
        raise TypeError("configuration host observation returned non-mapping evidence")
    snapshot_id = str(observation.get("snapshot_id") or "")
    observer_domain = str(observation.get("observer_domain") or "")
    returned_host_id = str(observation.get("host_id") or "")
    material_fingerprint = str(observation.get("material_fingerprint") or "")
    capability_fingerprint = str(observation.get("capability_fingerprint") or "")
    completed_at = str(observation.get("completed_at") or "")
    if (
        not snapshot_id
        or returned_host_id != host_id
        or observer_domain != _FULL_DOCKER_OBSERVER_DOMAIN
        or observation.get("docker_available") is not True
        or not _BARE_SHA256.fullmatch(material_fingerprint)
        or not _SHA256_FINGERPRINT.fullmatch(capability_fingerprint)
        or not completed_at
    ):
        raise RuntimeError(
            "broker configuration observation lacks exact committed full-Docker evidence"
        )
    with store.read_transaction() as connection:
        row = connection.execute(
            """
            WITH latest AS (
                SELECT s.snapshot_id
                FROM observation_snapshots s
                JOIN observation_capabilities c USING(snapshot_id)
                WHERE s.host_id = ?
                  AND s.status = 'completed'
                  AND s.completed_at IS NOT NULL
                  AND s.observer_domain = c.observer_domain
                  AND c.docker_available = 1
                ORDER BY s.completed_at DESC, s.snapshot_id DESC
                LIMIT 1
            )
            SELECT s.snapshot_id, s.host_id, s.observer_domain,
                   s.material_fingerprint, s.completed_at,
                   c.capability_fingerprint, c.committed_at
            FROM latest
            JOIN observation_snapshots s USING(snapshot_id)
            JOIN observation_capabilities c USING(snapshot_id)
            WHERE s.snapshot_id = ?
            """,
            (host_id, snapshot_id),
        ).fetchone()
    if (
        row is None
        or str(row["host_id"]) != returned_host_id
        or str(row["observer_domain"]) != observer_domain
        or str(row["material_fingerprint"]) != material_fingerprint
        or str(row["capability_fingerprint"]) != capability_fingerprint
        or str(row["completed_at"]) != completed_at
    ):
        raise RuntimeError(
            "broker configuration observation is not the latest committed full-Docker snapshot"
        )
    capability_committed_at = observation.get("capability_committed_at")
    if capability_committed_at is not None and str(
        capability_committed_at
    ) != str(row["committed_at"]):
        raise RuntimeError(
            "broker configuration observation capability evidence changed before configuration"
        )
    return snapshot_id


def _associate_observed_resources(
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    snapshot_id: str,
    excluded_container_ids: Sequence[str] = (),
) -> dict[str, str]:
    """Persist observation-backed repository hints and return container aliases."""

    if isinstance(excluded_container_ids, (str, bytes, bytearray)):
        raise ValueError("excluded container IDs must be a sequence")
    excluded = frozenset(str(item) for item in excluded_container_ids)
    aliases: dict[str, str] = {}
    with CoordinatorStore.open(
        persistence.database_path, expected_uid=persistence.expected_uid
    ) as store:
        with store.immediate_transaction() as connection:
            _require_exact_observation_snapshot(
                connection, repo_id=repo_id, snapshot_id=snapshot_id
            )
            rows = list(
                connection.execute(
                    """
                    SELECT observed.docker_resource_id,
                           observed.full_container_id AS observed_full_container_id,
                           observed.association_state,
                           observed.associated_repo_id,
                           docker.full_container_id, docker.current_name
                    FROM broker_observed_compose_containers AS observed
                    JOIN docker_resources AS docker
                      ON docker.docker_resource_id = observed.docker_resource_id
                    WHERE observed.snapshot_id = ?
                      AND observed.association_state = 'exclusive'
                      AND observed.associated_repo_id = ?
                    ORDER BY docker.current_name, docker.full_container_id
                    """,
                    (snapshot_id, repo_id),
                )
            )
            for row in rows:
                resource_id = str(row["docker_resource_id"])
                if resource_id in excluded:
                    continue
                if str(row["observed_full_container_id"]) != str(
                    row["full_container_id"]
                ):
                    raise RuntimeError(
                        "observed container identity changed before association"
                    )
                connection.execute(
                    "UPDATE docker_resources SET repo_id = ?, updated_at = ? "
                    "WHERE docker_resource_id = ? AND full_container_id = ?",
                    (
                        repo_id,
                        utc_timestamp(),
                        resource_id,
                        str(row["full_container_id"]),
                    ),
                )
                aliases[str(row["current_name"])] = resource_id
                aliases[str(row["full_container_id"])] = resource_id
            connection.execute(
                """
                UPDATE database_bindings
                SET repo_id = ?, updated_at = ?
                WHERE docker_resource_id IN (
                    SELECT docker_resource_id FROM docker_resources WHERE repo_id = ?
                )
                """,
                (repo_id, utc_timestamp(), repo_id),
            )
    return aliases


def _require_exact_observation_snapshot(
    connection: sqlite3.Connection,
    *,
    repo_id: str,
    snapshot_id: str,
) -> None:
    evidence = connection.execute(
        """
        SELECT snapshot.status, snapshot.observer_domain,
               capability.docker_available
        FROM repositories repository
        JOIN observation_snapshots snapshot
          ON snapshot.host_id = repository.host_id
        JOIN observation_capabilities capability
          ON capability.snapshot_id = snapshot.snapshot_id
         AND capability.observer_domain = snapshot.observer_domain
        WHERE repository.repo_id = ? AND snapshot.snapshot_id = ?
        """,
        (repo_id, snapshot_id),
    ).fetchone()
    if (
        evidence is None
        or str(evidence["status"]) != "completed"
        or str(evidence["observer_domain"]) != _FULL_DOCKER_OBSERVER_DOMAIN
        or not bool(evidence["docker_available"])
    ):
        raise RuntimeError(
            "resource association requires its exact completed full-Docker snapshot"
        )


def _declared_container_names(
    runtime_file: Path,
    *,
    candidates: frozenset[str],
) -> tuple[str, ...]:
    """Read explicit Docker dependency names from one configured runtime manifest.

    Only the exact ``container`` field is authority. Dependency labels, images,
    repository names, and fuzzy container-name similarity are deliberately not
    considered. The observer calls this only while an exact currently
    unassigned container with the same name exists.
    """

    if not candidates:
        return ()
    try:
        metadata = runtime_file.lstat()
    except FileNotFoundError:
        return ()
    except OSError as error:
        raise ValueError("runtime manifest metadata cannot be read") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size < 2
        or metadata.st_size > 2 * 1024 * 1024
    ):
        raise ValueError("runtime manifest is not one bounded regular file")
    try:
        document = json.loads(runtime_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("runtime manifest cannot be decoded") from error
    if not isinstance(document, Mapping):
        raise ValueError("runtime manifest must be an object")
    docker = document.get("docker")
    sections: list[object] = [document.get("dependencies", [])]
    if isinstance(docker, Mapping):
        sections.append(docker.get("containers", []))
    declared: list[str] = []
    for section in sections:
        if section is None:
            continue
        if not isinstance(section, list):
            raise ValueError("runtime Docker dependencies must be lists")
        for raw in section:
            if not isinstance(raw, Mapping):
                raise ValueError("runtime Docker dependency must be an object")
            if str(raw.get("type") or "docker") != "docker":
                continue
            container = raw.get("container")
            if container is None:
                continue
            if (
                not isinstance(container, str)
                or _EXACT_CONTAINER_NAME.fullmatch(container) is None
            ):
                raise ValueError("runtime Docker dependency container is invalid")
            if container in candidates and container not in declared:
                declared.append(container)
    return tuple(declared)


def reconcile_configured_runtime_container_declarations(
    store: AccountStore,
    *,
    snapshot_id: str,
) -> dict[str, Any]:
    """Rebuild lost ownership from exact configured runtime declarations.

    Fresh-store adoption intentionally discards historical membership rows.
    This reconciliation makes the checked-in runtime manifest the durable
    reconstruction source without guessing from project or image names. It is
    bounded to exact containers that are both present in ``snapshot_id`` and
    currently unassigned for a repairable attribution reason.

    A dependency may be shared by several repositories. The first configured
    repository owns lifecycle control (``created_at``, then canonical root as a
    deterministic tie-break); later declarations are references only. An
    existing owner is never replaced.
    """

    if not isinstance(snapshot_id, str) or not snapshot_id:
        raise ValueError("declaration reconciliation requires a snapshot ID")
    with store.read_transaction() as connection:
        snapshot = connection.execute(
            """
            SELECT snapshot.host_id, snapshot.status, snapshot.observer_domain,
                   capability.docker_available
            FROM observation_snapshots snapshot
            JOIN observation_capabilities capability USING(snapshot_id)
            WHERE snapshot.snapshot_id = ?
            """,
            (snapshot_id,),
        ).fetchone()
        if (
            snapshot is None
            or str(snapshot["status"]) != "completed"
            or str(snapshot["observer_domain"]) != _FULL_DOCKER_OBSERVER_DOMAIN
            or not bool(snapshot["docker_available"])
        ):
            return {
                "checked": 0,
                "changed": 0,
                "bindings": [],
                "invalid_manifests": [],
                "skipped": "full_docker_snapshot_unavailable",
            }
        rows = list(
            connection.execute(
                """
                SELECT resource.docker_resource_id, resource.full_container_id,
                       resource.current_name,
                       resource.repo_id AS associated_repo_id
                FROM observation_snapshot_resources present
                JOIN docker_resources resource
                  ON resource.docker_resource_id = present.resource_id
                JOIN docker_engines engine USING(engine_id)
                WHERE present.snapshot_id = ?
                  AND present.resource_kind = 'container'
                  AND engine.host_id = ?
                ORDER BY resource.current_name, resource.full_container_id
                """,
                (snapshot_id, str(snapshot["host_id"])),
            )
        )
        repositories = list(
            connection.execute(
                """
                SELECT repository.repo_id, repository.canonical_root,
                       repository.created_at
                FROM repositories repository
                JOIN repository_installations installation USING(repo_id)
                WHERE repository.host_id = ?
                  AND repository.state = 'active'
                  AND installation.status = 'installed'
                  AND installation.startup_fenced = 0
                ORDER BY repository.created_at, repository.canonical_root,
                         repository.repo_id
                """,
                (str(snapshot["host_id"]),),
            )
        )
    if not rows:
        return {
            "checked": 0,
            "changed": 0,
            "bindings": [],
            "invalid_manifests": [],
        }

    by_name: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        by_name.setdefault(str(row["current_name"]), []).append(row)
    candidates = frozenset(by_name)
    declarations: dict[str, list[dict[str, str]]] = {}
    invalid_manifests: list[dict[str, str]] = []
    for repository in repositories:
        canonical_root = str(repository["canonical_root"])
        runtime_file = Path(canonical_root) / ".codex/dev-runtime.json"
        try:
            names = _declared_container_names(runtime_file, candidates=candidates)
        except ValueError as error:
            invalid_manifests.append(
                {
                    "repo_id": str(repository["repo_id"]),
                    "canonical_root": canonical_root,
                    "error": str(error),
                }
            )
            continue
        for name in names:
            declarations.setdefault(name, []).append(
                {
                    "repo_id": str(repository["repo_id"]),
                    "canonical_root": canonical_root,
                }
            )

    if invalid_manifests:
        # Primary ownership is ordered across every configured repository. If
        # even one manifest is temporarily unreadable or mid-edit, it may be
        # the earlier declaration for any candidate. Keep the observer healthy
        # but defer every adoption from this snapshot; otherwise a later shared
        # declaration could win permanently under the never-steal rule.
        return {
            "checked": len(rows),
            "changed": 0,
            "bindings": [
                {
                    "container": name,
                    "status": "reconciliation_deferred_invalid_manifest",
                    "declared_by": declarations.get(name, []),
                }
                for name in sorted(by_name)
            ],
            "invalid_manifests": invalid_manifests,
            "skipped": "configured_runtime_manifest_invalid",
        }

    bindings: list[dict[str, Any]] = []
    changed = 0
    for name in sorted(by_name):
        observed = by_name[name]
        declared_by = declarations.get(name, [])
        if not declared_by:
            continue
        if len(observed) != 1:
            bindings.append(
                {
                    "container": name,
                    "status": "ambiguous_observed_identity",
                    "observed_count": len(observed),
                    "declared_by": declared_by,
                }
            )
            continue
        row = observed[0]
        primary = declared_by[0]
        associated_repo_id = (
            None
            if row["associated_repo_id"] is None
            else str(row["associated_repo_id"])
        )
        if associated_repo_id not in {None, primary["repo_id"]}:
            bindings.append(
                {
                    "container": name,
                    "resource_id": str(row["docker_resource_id"]),
                    "status": "retained_existing_association",
                    "associated_repo_id": associated_repo_id,
                    "primary_declaration": primary,
                    "shared_references": declared_by[1:],
                }
            )
            continue
        with store.immediate_transaction() as connection:
            updated = connection.execute(
                """
                UPDATE docker_resources
                SET repo_id = ?, updated_at = ?
                WHERE docker_resource_id = ? AND full_container_id = ?
                  AND (repo_id IS NULL OR repo_id = ?)
                """,
                (
                    primary["repo_id"],
                    utc_timestamp(),
                    str(row["docker_resource_id"]),
                    str(row["full_container_id"]),
                    primary["repo_id"],
                ),
            ).rowcount
        if updated != 1:
            bindings.append(
                {
                    "container": name,
                    "resource_id": str(row["docker_resource_id"]),
                    "status": "reconciliation_deferred_identity_changed",
                    "primary_declaration": primary,
                    "shared_references": declared_by[1:],
                }
            )
            continue
        changed += int(associated_repo_id is None)
        bindings.append(
            {
                "container": name,
                "resource_id": str(row["docker_resource_id"]),
                "full_container_id": str(row["full_container_id"]),
                "status": "associated" if associated_repo_id is None else "already_associated",
                "associated_repo_id": primary["repo_id"],
                "associated_root": primary["canonical_root"],
                "shared_references": declared_by[1:],
            }
        )
    return {
        "checked": len(rows),
        "changed": changed,
        "bindings": bindings,
        "invalid_manifests": invalid_manifests,
    }


def _normalize_ephemeral_templates(
    value: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Validate the complete administrator-sealed ephemeral manifest section."""

    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError("ephemeral_containers must be a list of template objects")
    if len(value) > 64:
        raise ValueError("ephemeral_containers may contain at most 64 templates")
    required = {
        "name",
        "image_ref",
        "default_ttl_seconds",
        "max_ttl_seconds",
        "memory_bytes",
        "cpu_millis",
        "max_concurrent_runs",
        "max_concurrent_runs_per_uid",
        "repo_max_active_runs",
        "repo_memory_budget_bytes",
        "repo_cpu_budget_millis",
    }
    allowed = required | {
        "argv",
        "env",
        "secret_policy",
        "container_tcp_port",
        "host_port_start",
        "host_port_end",
    }
    normalized: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    repository_budget: tuple[int, int, int] | None = None
    for raw in value:
        if not isinstance(raw, Mapping) or set(raw) - allowed or required - set(raw):
            raise ValueError(
                "each ephemeral_containers entry requires exactly the sealed "
                "template fields"
            )
        name = _require_ephemeral_template_name(raw["name"])
        if name in seen_names:
            raise ValueError("ephemeral_containers names must be unique")
        seen_names.add(name)
        image_ref = _require_pinned_ephemeral_image(raw["image_ref"])
        if re.fullmatch(
            r"[a-z0-9][a-z0-9._/:+-]*@sha256:[0-9a-f]{64}", image_ref
        ) is None:
            raise ValueError(
                "ephemeral image_ref must use a lowercase option-safe image name"
            )
        argv = raw.get("argv", ())
        if not isinstance(argv, (list, tuple)) or len(argv) > 128:
            raise ValueError("ephemeral argv must be a list of at most 128 arguments")
        command = tuple(_require_ephemeral_argument(item) for item in argv)
        if sum(len(item.encode("utf-8")) for item in command) > 128 * 1024:
            raise ValueError("ephemeral argv exceeds its total size bound")
        environment = dict(
            _normalize_ephemeral_environment(raw.get("env", {}))
        )
        secret_policy = normalize_ephemeral_secret_policy(raw.get("secret_policy"))
        _require_ephemeral_secret_policy_environment(
            policy_kind=secret_policy,
            environment=tuple(sorted(environment.items())),
        )
        if any(
            "\r" in env_value
            or "\n" in env_value
            or len(env_value.encode("utf-8")) > 16 * 1024
            for env_value in environment.values()
        ) or sum(
            len(env_name.encode("utf-8"))
            + 1
            + len(env_value.encode("utf-8"))
            for env_name, env_value in environment.items()
        ) > 128 * 1024:
            raise ValueError(
                "ephemeral environment exceeds the sealed Docker input bounds"
            )
        default_ttl_seconds = raw["default_ttl_seconds"]
        max_ttl_seconds = raw["max_ttl_seconds"]
        if (
            type(default_ttl_seconds) is not int
            or type(max_ttl_seconds) is not int
            or not 60
            <= default_ttl_seconds
            <= max_ttl_seconds
            <= 7 * 24 * 60 * 60
        ):
            raise ValueError(
                "ephemeral TTLs must be ordered integers from one minute through seven days"
            )
        port_values = (
            raw.get("container_tcp_port"),
            raw.get("host_port_start"),
            raw.get("host_port_end"),
        )
        if all(item is None for item in port_values):
            container_tcp_port = host_port_start = host_port_end = None
        elif (
            any(type(item) is not int for item in port_values)
            or not 1 <= int(port_values[0]) <= 65535
            or not 1 <= int(port_values[1]) <= int(port_values[2]) <= 65535
        ):
            raise ValueError(
                "ephemeral TCP publication requires container_tcp_port and an "
                "ordered host_port_start/host_port_end range"
            )
        else:
            container_tcp_port, host_port_start, host_port_end = port_values
        memory_bytes = raw["memory_bytes"]
        if (
            type(memory_bytes) is not int
            or not 16 * 1024 * 1024 <= memory_bytes <= 1 << 50
        ):
            raise ValueError(
                "ephemeral memory_bytes must be from 16 MiB through one PiB"
            )
        cpu_millis = raw["cpu_millis"]
        if type(cpu_millis) is not int or not 10 <= cpu_millis <= 256_000:
            raise ValueError("ephemeral cpu_millis must be from 10 through 256000")
        max_concurrent_runs = raw["max_concurrent_runs"]
        max_concurrent_runs_per_uid = raw["max_concurrent_runs_per_uid"]
        repo_max_active_runs = raw["repo_max_active_runs"]
        repo_memory_budget_bytes = raw["repo_memory_budget_bytes"]
        repo_cpu_budget_millis = raw["repo_cpu_budget_millis"]
        if (
            type(max_concurrent_runs) is not int
            or type(max_concurrent_runs_per_uid) is not int
            or type(repo_max_active_runs) is not int
            or not 1
            <= max_concurrent_runs_per_uid
            <= max_concurrent_runs
            <= 32
            or not max_concurrent_runs <= repo_max_active_runs <= 64
        ):
            raise ValueError(
                "ephemeral concurrency limits must be ordered integers within the fixed host bounds"
            )
        if (
            type(repo_memory_budget_bytes) is not int
            or repo_memory_budget_bytes < memory_bytes
            or repo_memory_budget_bytes > 64 * (1 << 50)
            or type(repo_cpu_budget_millis) is not int
            or repo_cpu_budget_millis < cpu_millis
            or repo_cpu_budget_millis > 64 * 256_000
        ):
            raise ValueError(
                "ephemeral repository CPU and memory budgets must cover one sealed run and stay within the fixed repository bounds"
            )
        candidate_repository_budget = (
            repo_max_active_runs,
            repo_memory_budget_bytes,
            repo_cpu_budget_millis,
        )
        if repository_budget is None:
            repository_budget = candidate_repository_budget
        elif candidate_repository_budget != repository_budget:
            raise ValueError(
                "all ephemeral templates in one repository must declare the same repo_max_active_runs, repo_memory_budget_bytes, and repo_cpu_budget_millis"
            )
        normalized.append(
            {
                "name": name,
                "image_ref": image_ref,
                "command": command,
                "environment": environment,
                "secret_policy": secret_policy,
                "default_ttl_seconds": default_ttl_seconds,
                "max_ttl_seconds": max_ttl_seconds,
                "container_tcp_port": container_tcp_port,
                "host_port_start": host_port_start,
                "host_port_end": host_port_end,
                "memory_bytes": memory_bytes,
                "cpu_millis": cpu_millis,
                "max_concurrent_runs": max_concurrent_runs,
                "max_concurrent_runs_per_uid": max_concurrent_runs_per_uid,
                "repo_max_active_runs": repo_max_active_runs,
                "repo_memory_budget_bytes": repo_memory_budget_bytes,
                "repo_cpu_budget_millis": repo_cpu_budget_millis,
            }
        )
    return tuple(normalized)


def _provision_ephemeral_templates(
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    templates: Sequence[Mapping[str, Any]],
) -> dict[str, str]:
    """Replace one repository's exact template definitions."""
    template_ids: dict[str, str] = {}
    for template in templates:
        name = str(template["name"])
        template_id = deterministic_id("ephemeral-template", repo_id, name)
        secret_policy = template.get("secret_policy")
        secret_binding_id = (
            None
            if secret_policy is None
            else deterministic_secret_binding_id(
                repository_id=repo_id,
                template_id=template_id,
                policy=str(secret_policy),
            )
        )
        result = persistence.provision_ephemeral_template(
            template_id=template_id,
            repo_id=repo_id,
            name=name,
            image_ref=str(template["image_ref"]),
            command=tuple(template["command"]),
            environment=dict(template["environment"]),
            secret_policy_kind=(
                None if secret_policy is None else str(secret_policy)
            ),
            secret_binding_id=secret_binding_id,
            default_ttl_seconds=int(template["default_ttl_seconds"]),
            max_ttl_seconds=int(template["max_ttl_seconds"]),
            container_tcp_port=template.get("container_tcp_port"),
            host_port_start=template.get("host_port_start"),
            host_port_end=template.get("host_port_end"),
            memory_bytes=int(template["memory_bytes"]),
            cpu_millis=int(template["cpu_millis"]),
            max_concurrent_runs=int(template["max_concurrent_runs"]),
            max_concurrent_runs_per_uid=int(
                template["max_concurrent_runs_per_uid"]
            ),
            repo_max_active_runs=int(template["repo_max_active_runs"]),
            repo_memory_budget_bytes=int(template["repo_memory_budget_bytes"]),
            repo_cpu_budget_millis=int(template["repo_cpu_budget_millis"]),
            enabled=True,
        )
        if isinstance(result, Mapping) and result.get("template_id") != template_id:
            raise RuntimeError(
                "ephemeral template persistence substituted its immutable identity"
            )
        template_ids[name] = template_id
    persistence.disable_ephemeral_templates_except(
        repo_id=repo_id,
        template_ids=template_ids.values(),
    )
    return template_ids


def _ephemeral_secret_policy_profiles(
    *,
    repo_id: str,
    template_ids: Mapping[str, str],
    templates: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, str]]:
    """Publish public policy/binding metadata without any credential bytes."""

    result: dict[str, dict[str, str]] = {}
    for template in templates:
        name = str(template["name"])
        policy = template.get("secret_policy")
        if policy is None:
            continue
        template_id = template_ids.get(name)
        if template_id is None:
            raise RuntimeError("ephemeral template policy lost its immutable identity")
        result[name] = {
            "policy": str(policy),
            "binding_id": deterministic_secret_binding_id(
                repository_id=repo_id,
                template_id=template_id,
                policy=str(policy),
            ),
        }
    return result


def _provision_compose(
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    root: Path,
    compose: Mapping[str, Any] | None,
    observation_snapshot_id: str | None = None,
    host_access_approved: bool | None = False,
) -> str | None:
    if not compose or not compose.get("declared"):
        persistence.disable_repository_compose(repo_id=repo_id)
        return None
    run_once_policies = normalize_compose_run_once_policies(
        compose.get("run_once_services", ())
    )
    files: list[str] = []
    for raw in compose.get("files") or []:
        path = _canonical_repository_file(
            raw,
            root=root,
            field="Compose file",
        )
        files.append(str(path))
    if not files:
        raise ValueError("declared Compose configuration requires at least one exact file")
    services = tuple(str(item) for item in compose.get("services") or [])
    if not services:
        raise ValueError(
            "declared Compose configuration requires at least one exact service"
        )
    env_files: list[str] = []
    for raw in compose.get("env_files") or []:
        path = _canonical_repository_file(
            raw,
            root=root,
            field="Compose environment file",
        )
        env_files.append(str(path))
    existing_id = persistence.configured_compose_definition_id(repo_id=repo_id)
    compose_id = (
        existing_id
        if isinstance(existing_id, str)
        else deterministic_id("compose-definition", repo_id)
    )
    provision = getattr(persistence, "provision_compose_definition", None)
    if provision is None:
        raise RuntimeError(
            "installed broker service lacks Compose definition persistence"
        )
    provisioned = provision(
        repo_id=repo_id,
        compose_definition_id=compose_id,
        cwd=str(root),
        files=tuple(files),
        env_files=tuple(env_files),
        profiles=tuple(str(item) for item in compose.get("profiles") or []),
        services=services,
        run_once_services=tuple(
            policy.to_document() for policy in run_once_policies
        ),
        project_name=(
            None
            if compose.get("project_name") is None
            else str(compose["project_name"])
        ),
        observation_snapshot_id=observation_snapshot_id,
        host_access_approved=host_access_approved,
        enabled=True,
    )
    if isinstance(provisioned, Mapping):
        returned_id = provisioned.get("compose_definition_id")
        if isinstance(returned_id, str):
            compose_id = returned_id
    return compose_id


def reconcile_declared_compose_first_use(
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    root: Path,
) -> Mapping[str, Any]:
    """Seal one repository-declared Compose definition idempotently."""

    compose = declared_compose_from_runtime_manifest(root)
    if compose is None:
        return {
            "changed": False,
            "compose_definition_id": None,
            "compose_run_once_services": {},
        }
    before = {
        str(item["compose_definition_id"]): (
            str(item["definition_fingerprint"]),
            int(item["generation"]),
            bool(item["enabled"]),
        )
        for item in persistence.list_compose_definitions(repo_id=repo_id)
    }
    run_once_policies = normalize_compose_run_once_policies(
        compose.get("run_once_services", ())
    )
    try:
        compose_id = _provision_compose(
            persistence,
            repo_id=repo_id,
            root=root,
            compose=compose,
            observation_snapshot_id=None,
            host_access_approved=None,
        )
    except (BrokerError, OSError, RuntimeError, TypeError, ValueError) as error:
        raise DeclaredComposeConfigurationError(str(error)) from error
    if compose_id is None:
        raise DeclaredComposeConfigurationError(
            "declared Compose configuration did not produce an exact definition"
        )
    after = {
        str(item["compose_definition_id"]): (
            str(item["definition_fingerprint"]),
            int(item["generation"]),
            bool(item["enabled"]),
        )
        for item in persistence.list_compose_definitions(repo_id=repo_id)
    }
    return {
        "changed": before != after,
        "compose_definition_id": compose_id,
        "compose_run_once_services": {
            policy.name: policy.max_timeout_seconds
            for policy in run_once_policies
        },
    }


def reconcile_declared_servers_first_use(
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    root: Path,
    execution_uid: int,
) -> Mapping[str, Any]:
    """Catalog declared persistent services during ordinary first use.

    This is configuration discovery, not configuration: the live broker reads the
    repository manifest itself, records opaque service IDs, and selects the
    calling local account only as the execution identity for future launches.
    No offline administrator transaction or per-account grant is involved.
    """

    try:
        servers = declared_servers_from_runtime_manifest(root)
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        if isinstance(error, DeclaredRuntimeConfigurationError):
            raise
        raise DeclaredRuntimeConfigurationError(str(error)) from error
    if not servers:
        return {"changed": False, "servers": {}}
    provision_worker_log_directory(execution_uid)
    before: dict[str, tuple[str, int]] = {}
    with persistence._store() as store:
        with store.read_transaction() as connection:
            before = {
                str(row["server_definition_id"]): (
                    str(row["definition_fingerprint"]),
                    int(row["generation"]),
                )
                for row in connection.execute(
                    """
                    SELECT server_definition_id, definition_fingerprint, generation
                    FROM server_definitions WHERE repo_id = ?
                    ORDER BY server_definition_id
                    """,
                    (repo_id,),
                )
            }
        with store.immediate_transaction() as connection:
            server_ids = _synchronize_server_definitions(
                connection,
                repo_id=repo_id,
                root=root,
                servers=servers,
                now=utc_timestamp(),
                explicit_reinstall=False,
            )
    for server in servers:
        server_id = server_ids[str(server["name"])]
        port = server.get("port")
        if port is None:
            start_port, end_port = 3000, 3999
        else:
            start_port = end_port = int(port)
        persistence.set_server_port_range(
            repo_id=repo_id,
            server_definition_id=server_id,
            start_port=start_port,
            end_port=end_port,
            max_ttl_seconds=7 * 24 * 60 * 60,
        )
    with persistence._store() as store:
        with store.read_transaction() as connection:
            after = {
                str(row["server_definition_id"]): (
                    str(row["definition_fingerprint"]),
                    int(row["generation"]),
                )
                for row in connection.execute(
                    """
                    SELECT server_definition_id, definition_fingerprint, generation
                    FROM server_definitions WHERE repo_id = ?
                    ORDER BY server_definition_id
                    """,
                    (repo_id,),
                )
            }
    return {
        "changed": before != after,
        "servers": dict(server_ids),
    }


def _compose_configuration_container_scope(
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    root: Path,
    compose: Mapping[str, Any] | None,
    configuration_snapshot_id: str | None,
) -> ComposeConfigurationContainerScope | None:
    """Validate the complete same-project scope from the configuration snapshot."""

    if not compose or not compose.get("declared"):
        return None
    if configuration_snapshot_id is None:
        raise RuntimeError("declared Compose configuration lacks snapshot authority")
    services = tuple(
        _require_compose_service_name(str(item))
        for item in compose.get("services") or ()
    )
    if not services:
        raise RuntimeError("declared Compose configuration has no lifecycle services")
    run_once_services = tuple(
        policy.name
        for policy in normalize_compose_run_once_policies(
            compose.get("run_once_services", ())
        )
    )
    project_name = _require_compose_project_name(
        str(compose["project_name"])
        if compose.get("project_name") is not None
        else _default_compose_project_name(root.name)
    )
    return persistence.compose_configuration_container_scope(
        repo_id=repo_id,
        snapshot_id=configuration_snapshot_id,
        project_name=project_name,
        service_names=services,
        run_once_service_names=run_once_services,
    )


def _compose_owned_container_ids_for_profile(
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    root: Path,
    compose: Mapping[str, Any] | None,
    compose_definition_id: str | None,
    configuration_snapshot_id: str | None,
    configured_container_ids: frozenset[str],
) -> tuple[str, ...]:
    """Publish the exact existing container subset controlled by Compose."""

    if not compose or not compose.get("declared"):
        if compose_definition_id is not None:
            raise RuntimeError(
                "undeclared Compose configuration returned a contradictory definition"
            )
        return ()
    if compose_definition_id is None or configuration_snapshot_id is None:
        raise RuntimeError(
            "declared Compose configuration lacks definition or snapshot authority"
        )
    observed_scope = _compose_configuration_container_scope(
        persistence,
        repo_id=repo_id,
        root=root,
        compose=compose,
        configuration_snapshot_id=configuration_snapshot_id,
    )
    if observed_scope is None:
        raise RuntimeError("declared Compose configuration has no observed scope")
    resource_ids = observed_scope.lifecycle_container_ids
    if len(set(resource_ids)) != len(resource_ids):
        raise RuntimeError("Compose-owned configuration resource IDs are duplicated")
    if not set(resource_ids) <= configured_container_ids:
        raise RuntimeError(
            "Compose-owned configuration resource is absent from client container grants"
        )
    return tuple(sorted(resource_ids))


def _compose_run_once_mapping(
    *,
    compose: Mapping[str, Any] | None,
) -> dict[str, int]:
    """Publish every configured run-once service and its timeout ceiling."""

    if not compose or not compose.get("declared"):
        return {}
    policies = normalize_compose_run_once_policies(
        compose.get("run_once_services", ())
    )
    return {
        policy.name: policy.max_timeout_seconds for policy in policies
    }


def _preflight_compose_definition(
    *,
    root: Path,
    compose: Mapping[str, Any] | None,
    compose_model_renderer: Callable[..., bytes] | None,
    host_access_approved: bool,
) -> None:
    """Reject an invalid merged Compose model before authority mutation."""

    if not compose or not compose.get("declared"):
        return
    if compose_model_renderer is None:
        raise RuntimeError(
            "declared Compose configuration requires a merged-model renderer"
        )
    file_paths = tuple(
        _canonical_repository_file(raw, root=root, field="Compose file")
        for raw in compose.get("files") or ()
    )
    if not 1 <= len(file_paths) <= 16:
        raise ValueError(
            "declared Compose configuration requires from one through 16 exact files"
        )
    env_paths = tuple(
        _canonical_repository_file(raw, root=root, field="Compose environment file")
        for raw in compose.get("env_files") or ()
    )
    if len(env_paths) > 16:
        raise ValueError("Compose environment configuration accepts at most 16 files")
    compose_payloads: list[bytes] = []
    for path in file_paths:
        payload = path.read_bytes()
        if len(payload) > 8 * 1024 * 1024:
            raise ValueError("Compose file exceeds its bounded size limit")
        require_sealable_compose_payload(payload)
        compose_payloads.append(payload)
    env_payloads: list[bytes] = []
    for path in env_paths:
        payload = path.read_bytes()
        if len(payload) > 1024 * 1024:
            raise ValueError("Compose environment file exceeds its bounded size limit")
        env_payloads.append(payload)
    services = tuple(
        _require_compose_service_name(str(item))
        for item in compose.get("services") or ()
    )
    if not services or len(set(services)) != len(services):
        raise ValueError("declared Compose configuration requires unique exact services")
    run_once_policies = normalize_compose_run_once_policies(
        compose.get("run_once_services", ())
    )
    run_once_names = tuple(policy.name for policy in run_once_policies)
    if set(services) & set(run_once_names):
        raise ValueError(
            "Compose lifecycle and run-once service scopes must be disjoint"
        )
    model_services = tuple((*services, *run_once_names))
    profiles = tuple(
        _require_compose_profile_name(str(item))
        for item in compose.get("profiles") or ()
    )
    if len(set(profiles)) != len(profiles):
        raise ValueError("Compose configuration profiles must be unique")
    project_name = _require_compose_project_name(
        str(compose["project_name"])
        if compose.get("project_name") is not None
        else _default_compose_project_name(root.name)
    )
    rendered = compose_model_renderer(
        compose_payloads=tuple(compose_payloads),
        env_payloads=tuple(env_payloads),
        profiles=profiles,
        declared_services=model_services,
        project_name=project_name,
        pinned_cwd=str(root),
    )
    evidence = require_effective_compose_model(
        rendered,
        declared_services=model_services,
        declared_profiles=profiles,
        project_name=project_name,
        host_access_approved=host_access_approved,
    )
    missing_images = sorted(
        set(run_once_names) - set(dict(evidence.service_images))
    )
    if missing_images:
        raise ValueError(
            "Compose run-once services require explicit image references: "
            + ", ".join(missing_images)
        )


def revoke_server_from_protected_profile(
    *,
    profile_path: Path,
    repo_id: str,
    server_name: str,
    server_definition_id: str,
    cleanup_operation_id: str,
    expected_database_generation: str,
) -> dict[str, Any]:
    """Remove one permanently revoked server ID from every protected grant.

    SQLite revocation is committed first.  If publication fails, the broker
    remains safely fenced and cleanup retry can repeat this idempotently.
    """

    path = profile_path.expanduser()
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("broker profile path must be absolute without traversal")
    for value, label in (
        (repo_id, "repo_id"),
        (server_name, "server_name"),
        (server_definition_id, "server_definition_id"),
        (cleanup_operation_id, "cleanup_operation_id"),
        (expected_database_generation, "database_generation"),
    ):
        if not isinstance(value, str) or not value:
            raise ValueError(f"{label} must be a non-empty string")
    initial = _read_protected_profile_for_revocation(
        path, expected_database_generation=expected_database_generation
    )
    del initial
    _ensure_root_profile_parent(path.parent)
    with _locked_root_profile(path):
        document = _read_protected_profile_for_revocation(
            path, expected_database_generation=expected_database_generation
        )
        affected = _revoke_server_from_profile_document(
            document,
            repo_id=repo_id,
            server_name=server_name,
            server_definition_id=server_definition_id,
        )
        if affected:
            _atomic_write_root_json(path, document)
    return {
        "status": "revoked" if affected else "already_revoked",
        "repo_id": repo_id,
        "server_name": server_name,
        "server_definition_id": server_definition_id,
        "cleanup_operation_id": cleanup_operation_id,
        "affected_routes": affected,
        "profile_path": str(path),
    }


def revoke_repository_from_protected_profile(
    *,
    profile_path: Path,
    repo_id: str,
    repository_generation: int,
    cleanup_operation_id: str,
    expected_database_generation: str,
) -> dict[str, Any]:
    """Remove one permanently revoked repository generation from all clients."""

    path = profile_path.expanduser()
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("broker profile path must be absolute without traversal")
    for value, label in (
        (repo_id, "repo_id"),
        (cleanup_operation_id, "cleanup_operation_id"),
        (expected_database_generation, "database_generation"),
    ):
        if not isinstance(value, str) or not value:
            raise ValueError(f"{label} must be a non-empty string")
    if type(repository_generation) is not int or repository_generation < 0:
        raise ValueError("repository_generation must be a non-negative integer")
    initial = _read_protected_profile_for_revocation(
        path, expected_database_generation=expected_database_generation
    )
    del initial
    _ensure_root_profile_parent(path.parent)
    with _locked_root_profile(path):
        document = _read_protected_profile_for_revocation(
            path, expected_database_generation=expected_database_generation
        )
        affected = _revoke_repository_from_profile_document(
            document,
            repo_id=repo_id,
            repository_generation=repository_generation,
        )
        if affected:
            _atomic_write_root_json(path, document)
    return {
        "status": "revoked" if affected else "already_revoked",
        "repo_id": repo_id,
        "repository_generation": repository_generation,
        "cleanup_operation_id": cleanup_operation_id,
        "affected_routes": affected,
        "profile_path": str(path),
    }


def _read_protected_profile_for_revocation(
    path: Path, *, expected_database_generation: str
) -> dict[str, Any]:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
    ):
        raise PermissionError("broker profile revocation requires a regular file")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("protected broker profile cannot be decoded") from error
    after = path.lstat()
    if (metadata.st_dev, metadata.st_ino) != (after.st_dev, after.st_ino):
        raise RuntimeError("protected broker profile identity changed while read")
    if not isinstance(document, dict) or not isinstance(document.get("service"), dict):
        raise RuntimeError("protected broker profile structure is invalid")
    host_profile_from_document(document)
    service = document["service"]
    if str(service.get("database_generation") or "") != expected_database_generation:
        raise RuntimeError(
            "protected broker profile belongs to another database generation"
        )
    return document


def _revoke_server_from_profile_document(
    document: dict[str, Any],
    *,
    repo_id: str,
    server_name: str,
    server_definition_id: str,
) -> list[str]:
    """Pure exact-ID profile mutation used by publication and regression tests."""

    repositories = document.get("repositories")
    if not isinstance(repositories, list):
        raise RuntimeError("protected broker routing catalog is invalid")
    affected: list[str] = []
    for repository in repositories:
        if not isinstance(repository, dict):
            raise RuntimeError("protected broker repository route is invalid")
        if str(repository.get("repo_id") or "") != repo_id:
            continue
        servers = repository.get("servers")
        if not isinstance(servers, dict):
            raise RuntimeError("protected broker server mapping is invalid")
        aliases = [
            str(name)
            for name, resource_id in servers.items()
            if str(resource_id) == server_definition_id
        ]
        if any(name != server_name for name in aliases):
            raise RuntimeError(
                "protected profile maps the revoked server ID under a conflicting name"
            )
        if aliases:
            del servers[server_name]
            affected.append(str(repository.get("canonical_root") or ""))
    return sorted(affected)


def _revoke_repository_from_profile_document(
    document: dict[str, Any],
    *,
    repo_id: str,
    repository_generation: int,
) -> list[str]:
    """Remove only the exact revoked repository incarnation from each client."""

    repositories = document.get("repositories")
    if not isinstance(repositories, list):
        raise RuntimeError("protected broker routing catalog is invalid")
    affected = [
        str(repository.get("canonical_root") or "")
        for repository in repositories
        if isinstance(repository, dict)
        and str(repository.get("repo_id") or "") == repo_id
        and repository.get("generation") == repository_generation
    ]
    document["repositories"] = [
        repository
        for repository in repositories
        if not (
            isinstance(repository, dict)
            and str(repository.get("repo_id") or "") == repo_id
            and repository.get("generation") == repository_generation
        )
    ]
    return sorted(affected)


def _merge_profile(
    *,
    profile_path: Path,
    service: dict[str, Any],
    repository: dict[str, Any],
) -> dict[str, Any]:
    """Publish one host-wide repository and resource routing catalog."""

    path = profile_path
    if not path.is_absolute():
        raise ValueError("broker profile output must be absolute")
    _ensure_root_profile_parent(path.parent)
    with _locked_root_profile(path):
        if path.exists():
            metadata = path.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
            ):
                raise PermissionError("existing broker profile is not a regular file")
            document = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                raise RuntimeError(
                    "existing broker profile belongs to another coordinator service"
                )
            host_profile_from_document(document)
            existing_service = document.get("service")
            if not isinstance(existing_service, dict) or any(
                existing_service.get(field) != service.get(field)
                for field in ("socket", "database_generation")
            ):
                raise RuntimeError(
                    "existing broker profile belongs to another coordinator service"
                )
            if document.get("version") == PROFILE_VERSION:
                current_repositories = document.get("repositories")
                if not isinstance(current_repositories, list):
                    raise RuntimeError("broker routing repositories are invalid")
            else:
                raise RuntimeError("existing broker profile version is unsupported")
        else:
            current_repositories = []
        repositories: list[dict[str, Any]] = []
        for item in current_repositories:
            if not isinstance(item, dict) or not REPOSITORY_PROFILE_FIELDS <= set(item):
                raise RuntimeError(
                    "existing broker profile has an invalid repository route"
                )
            if item.get("canonical_root") == repository["canonical_root"]:
                continue
            preserved = {field: item[field] for field in REPOSITORY_PROFILE_FIELDS}
            repositories.append(preserved)
        configured_repository = dict(repository)
        if set(configured_repository) != REPOSITORY_PROFILE_FIELDS:
            raise RuntimeError(
                "new broker profile has an invalid repository route"
            )
        repositories.append(configured_repository)
        repositories.sort(key=lambda item: str(item["canonical_root"]))
        document = {
            "version": PROFILE_VERSION,
            "service": service,
            "repositories": repositories,
        }
        _atomic_write_root_json(path, document)
        return document


@contextmanager
def _locked_root_profile(
    path: Path,
) -> Generator[None, None, None]:
    """Serialize protected profile read-modify-replace across publishers."""

    lock_path = path.parent / f".{path.name}.lock"
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o640)
    try:
        metadata = os.fstat(descriptor)
        path_metadata = lock_path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise PermissionError("broker profile lock is not a stable regular file")
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o640)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _ensure_root_profile_parent(path: Path) -> None:
    if (
        not path.is_absolute()
        or ".." in path.parts
        or path == Path(path.anchor)
    ):
        raise PermissionError(
            "broker profile directory must be an absolute protected path"
        )
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        if not current.exists():
            try:
                current.mkdir(mode=0o755)
            except FileExistsError:
                pass
        metadata = current.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise PermissionError("broker profile directory ancestor is not a real directory")
    os.chown(path, 0, 0)
    os.chmod(path, 0o755)


def _atomic_write_root_json(
    path: Path,
    document: Mapping[str, Any],
) -> None:
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
        raise ValueError("configuration project root must be a real directory")
    if stat.S_ISLNK(marker_metadata.st_mode) or not (
        stat.S_ISDIR(marker_metadata.st_mode) or stat.S_ISREG(marker_metadata.st_mode)
    ):
        raise ValueError("configuration project must be a real Git worktree")


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _require_exact_configuration_observation(
    store: CoordinatorStore,
    *,
    evidence: Mapping[str, Any] | None,
    fence: ObservationFreshnessFence,
) -> str:
    try:
        committed = require_exact_fresh_observation(
            store,
            evidence=evidence,
            fence=fence,
            allow_joined_ticket=False,
        )
    except ObservationFreshnessError as exc:
        raise RuntimeError(
            "Configuration requires the exact fresh service-owned full-Docker snapshot"
        ) from exc
    return str(committed["snapshot_id"])


def _capture_new_configuration_observation(
    store: CoordinatorStore,
    *,
    host_id: str,
    observe_host: Callable[[CoordinatorStore], Mapping[str, Any] | None],
    require_complete_compose_assets: bool = False,
) -> str:
    """Capture evidence created strictly after the configuration boundary.

    A host observer may single-flight onto a ticket that was already running
    when configuration began.  Let that ticket finish, then fence and observe once
    more so authority is never derived from pre-boundary state.
    """

    if type(require_complete_compose_assets) is not bool:
        raise TypeError("require_complete_compose_assets must be a boolean")
    for attempt in range(3):
        fence = capture_observation_freshness_fence(store, host_id=host_id)
        evidence = observe_host(store)
        snapshot_id = (
            str(evidence["snapshot_id"])
            if isinstance(evidence, Mapping) and evidence.get("snapshot_id")
            else None
        )
        joined_pre_boundary_ticket = (
            snapshot_id is not None and snapshot_id in fence.joinable_snapshot_ids
        )
        try:
            accepted = _require_exact_configuration_observation(
                store,
                evidence=evidence,
                fence=fence,
            )
        except RuntimeError:
            if attempt < 2 and joined_pre_boundary_ticket:
                continue
            raise
        if require_complete_compose_assets:
            with store.read_transaction() as connection:
                compose_scope = connection.execute(
                    """
                    SELECT assets_complete
                    FROM broker_observation_compose_scope
                    WHERE snapshot_id = ?
                    """,
                    (accepted,),
                ).fetchone()
            if compose_scope is None or not bool(compose_scope["assets_complete"]):
                if attempt < 2:
                    continue
                raise RuntimeError(
                    "Compose configuration could not obtain a complete local Docker asset snapshot"
                )
        return accepted
    raise RuntimeError(
        "Configuration requires an observation created after its freshness boundary"
    )


def _canonical_repository_file(raw: object, *, root: Path, field: str) -> Path:
    path = Path(str(raw)).expanduser()
    if not path.is_absolute():
        path = root / path
    absolute = Path(os.path.abspath(path))
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{field} must be an existing repository file") from exc
    if absolute != resolved:
        raise ValueError(f"{field} must not contain symbolic-link components")
    if not _within(resolved, root) or not resolved.is_file():
        raise ValueError(f"{field} must be a regular file inside the repository")
    return resolved
