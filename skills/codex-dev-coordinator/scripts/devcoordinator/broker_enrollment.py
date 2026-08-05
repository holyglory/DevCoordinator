"""Administrative enrollment for the standard cross-UID broker workflow."""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import socket
import sqlite3
import stat
import time
from typing import Any, Callable, Generator, Mapping, Sequence
import uuid

from .broker import BrokerOperation
from .broker_persistence import (
    BrokerPersistence,
    ComposeEnrollmentContainerScope,
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
from .schema import (
    advance_repository_owner_generation,
    establish_repository_owner_authority,
)
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


def enroll_repository(
    *,
    database_path: Path,
    socket_path: Path,
    socket_gid: int,
    client_uid: int,
    repository_owner_uid: int,
    account_id: str,
    canonical_root: str,
    servers: Sequence[Mapping[str, Any]],
    allowed_server_names: Sequence[str] | None = None,
    port_start: int,
    port_end: int,
    profile_path: Path,
    ephemeral_containers: Sequence[Mapping[str, Any]] = (),
    grant_ephemeral_image_prefetch: bool = False,
    compose: Mapping[str, Any] | None = None,
    allowed_compose_run_once_services: Sequence[str] = (),
    compose_model_renderer: Callable[..., bytes] | None = None,
    approve_compose_host_access: bool = False,
    observe_host: Callable[[AccountStore], Mapping[str, Any] | None] | None = None,
    explicit_reinstall: bool = False,
    grant_cleanup_capabilities: bool = False,
    validity_seconds: int = 30 * 24 * 60 * 60,
    socket_mode: int = 0o666,
) -> dict[str, Any]:
    """Synchronize trusted definitions/ACLs and atomically install a profile.

    This is an administrator surface, not a broker wire operation. Paths and
    launch definitions are read locally by the service owner and remain in its
    private database; the emitted client profile contains opaque IDs only.
    """

    service_uid = os.geteuid()
    if type(client_uid) is not int or client_uid < 0:
        raise ValueError("client_uid must be a non-negative integer")
    if type(socket_gid) is not int or socket_gid < 0:
        raise ValueError("socket_gid must be a non-negative integer")
    if socket_mode != 0o666:
        raise ValueError("new broker profiles require universal local socket mode 0666")
    if not 1 <= port_start <= port_end <= 65535:
        raise ValueError("broker enrollment port range is invalid")
    if not 60 <= validity_seconds <= 365 * 24 * 60 * 60:
        raise ValueError("profile validity must be from one minute through one year")
    if compose and compose.get("declared") and observe_host is None:
        raise RuntimeError(
            "Compose enrollment requires a fresh service-owned full-Docker observation"
        )
    if type(approve_compose_host_access) is not bool:
        raise TypeError("approve_compose_host_access must be a boolean")
    if type(grant_cleanup_capabilities) is not bool:
        raise TypeError("grant_cleanup_capabilities must be a boolean")
    if type(grant_ephemeral_image_prefetch) is not bool:
        raise TypeError("grant_ephemeral_image_prefetch must be a boolean")
    normalized_ephemeral = _normalize_ephemeral_templates(ephemeral_containers)
    if type(explicit_reinstall) is not bool:
        raise TypeError("explicit_reinstall must be a boolean")
    if approve_compose_host_access and not (compose and compose.get("declared")):
        raise ValueError(
            "Compose host-access approval requires a declared Compose definition"
        )
    if grant_cleanup_capabilities and observe_host is None:
        raise RuntimeError(
            "Cleanup enrollment requires a fresh service-owned full-Docker observation"
        )
    if compose and compose.get("declared") and compose_model_renderer is None:
        from .broker_host import render_compose_effective_model

        compose_model_renderer = render_compose_effective_model
    if type(repository_owner_uid) is not int or repository_owner_uid <= 0:
        raise ValueError("repository owner UID must be a positive integer")
    issued_epoch = int(time.time())
    issued_at = utc_timestamp(issued_epoch)
    valid_until_epoch = issued_epoch + validity_seconds
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
    # enrollment authority. A failed filesystem boundary must not leave a new
    # principal/grant set that cannot produce broker-verifiable crash evidence.
    worker_log_root = provision_worker_log_directory(client_uid)

    persistence = BrokerPersistence(
        database_path,
        expected_uid=service_uid,
        compose_model_renderer=compose_model_renderer,
    )
    # Bind UID to account before mutating any repository definitions.  A
    # conflicting reenrollment must not leave even trusted catalog changes
    # behind while retaining the prior account's grants.
    persistence.provision_principal(uid=client_uid, account_id=account_id)
    now = utc_timestamp()
    owner_operation_id = str(uuid.uuid4())
    # Host observation and normalized inventory are intentionally implemented
    # by AccountStore for both account-owned and service-owned databases.  Use
    # that adapter here so the real enrollment observer receives the same
    # contract exercised by the normalized coordinator paths.
    with AccountStore.open(database_path, expected_uid=service_uid) as store:
        host_id = _ensure_host(store)
        repo_id = deterministic_id("repository", host_id, str(root))
        with store.immediate_transaction() as connection:
            existing = connection.execute(
                """
                SELECT repository.repo_id, repository.state,
                       repository.generation, owner.owner_uid,
                       owner.repository_generation
                FROM repositories repository
                LEFT JOIN repository_owners owner USING(repo_id)
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
                establish_repository_owner_authority(
                    connection,
                    repository_id=repo_id,
                    owner_uid=repository_owner_uid,
                    repository_generation=0,
                    operation_id=owner_operation_id,
                    actor=f"broker-enrollment:{account_id}",
                    reason="explicit repository enrollment owner authority",
                    timestamp=now,
                    evidence={
                        "kind": "broker-repository-owner-enrollment",
                        "repository_id": repo_id,
                        "canonical_root": str(root),
                        "repository_generation": 0,
                        "owner_uid": repository_owner_uid,
                        "authorized_client_uid": client_uid,
                        "account_id": account_id,
                    },
                )
            else:
                if (
                    existing["owner_uid"] is None
                    or int(existing["owner_uid"]) != repository_owner_uid
                    or int(existing["repository_generation"])
                    != int(existing["generation"])
                ):
                    raise RuntimeError(
                        "repository execution owner authority is missing, stale, or conflicts with the explicit enrollment owner"
                    )
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
                            "repository identity is missing or relocated; observe and reconcile it before enrollment"
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
                    advance_repository_owner_generation(
                        connection,
                        repository_id=repo_id,
                        owner_uid=repository_owner_uid,
                        prior_repository_generation=int(existing["generation"]),
                        repository_generation=int(existing["generation"]) + 1,
                        operation_id=owner_operation_id,
                        actor=f"broker-enrollment:{account_id}",
                        reason="explicit repository reinstall generation advance",
                        timestamp=now,
                        evidence={
                            "kind": "broker-repository-owner-reinstall",
                            "repository_id": repo_id,
                            "canonical_root": str(root),
                            "prior_repository_generation": int(existing["generation"]),
                            "repository_generation": int(existing["generation"]) + 1,
                            "owner_uid": repository_owner_uid,
                            "authorized_client_uid": client_uid,
                            "account_id": account_id,
                        },
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
                        "repository identity is relocated; observe and reconcile it before enrollment"
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
            server_ids = _synchronize_server_definitions(
                connection,
                repo_id=repo_id,
                root=root,
                servers=servers,
                now=now,
                explicit_reinstall=explicit_reinstall,
            )
        database_generation = store.metadata.database_generation

        if allowed_server_names is None:
            granted_server_ids = dict(server_ids)
        else:
            requested_names = tuple(
                dict.fromkeys(str(item).strip() for item in allowed_server_names)
            )
            if any(not name for name in requested_names):
                raise ValueError("allowed server names must be non-empty")
            unknown = sorted(set(requested_names) - set(server_ids))
            if unknown:
                raise ValueError(
                    "server access allowlist names are absent from the runtime manifest: "
                    + ", ".join(unknown)
                )
            granted_server_ids = {name: server_ids[name] for name in requested_names}

        enrollment_snapshot_id: str | None = None
        if observe_host is not None:
            enrollment_snapshot_id = _capture_new_enrollment_observation(
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
            raise RuntimeError("repository disappeared during enrollment")
        repository_generation = int(repository_row["generation"])

    compose_observed_scope = _compose_enrollment_container_scope(
        persistence,
        repo_id=repo_id,
        root=root,
        compose=compose,
        enrollment_snapshot_id=enrollment_snapshot_id,
    )

    persistence.grant_repository_read(
        uid=client_uid,
        repo_id=repo_id,
        operation=BrokerOperation.REPOSITORY_LIST_REMOVED,
    )
    persistence.grant_host_observation(uid=client_uid, repo_id=repo_id)
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
    persistence.replace_server_access(
        uid=client_uid,
        repo_id=repo_id,
        server_definition_ids=granted_server_ids.values(),
        start_port=port_start,
        end_port=port_end,
        protocol="tcp",
        max_ttl_seconds=7 * 24 * 60 * 60,
    )

    # Reenrollment commits one fail-closed revocation of every observation-
    # derived capability before an exact fresh snapshot may replace the set.
    persistence.revoke_observation_derived_access(
        uid=client_uid,
        repo_id=repo_id,
        containers=True,
        databases=True,
        lifecycle_resources=True,
        cleanup_resources=True,
    )
    container_ids: dict[str, str] = {}
    grant_snapshot_id: str | None = None
    if observe_host is not None:
        # One exact post-boundary host snapshot is sufficient for enrollment,
        # grants, and Compose collision checks.  Recapturing the entire Docker
        # host here doubled enrollment latency and could pair an incomplete
        # transient scan with a later complete one.  Reuse the already fenced
        # snapshot instead.
        grant_snapshot_id = enrollment_snapshot_id
        if grant_snapshot_id is None:
            raise RuntimeError("enrollment observation disappeared before grants")
        container_ids = _grant_all_observed_access(
            persistence,
            repo_id=repo_id,
            client_uid=client_uid,
            snapshot_id=grant_snapshot_id,
            include_cleanup=grant_cleanup_capabilities,
            excluded_container_ids=(
                ()
                if compose_observed_scope is None
                else compose_observed_scope.non_lifecycle_container_ids
            ),
        )

    for operation in (
        BrokerOperation.ARCHIVES_READ,
        BrokerOperation.CLEANUP_PLAN,
        BrokerOperation.CLEANUP_APPLY,
        BrokerOperation.LIFECYCLE_RESTORE,
        BrokerOperation.REPOSITORY_PLAN_REMOVE,
        BrokerOperation.REPOSITORY_REMOVE,
        BrokerOperation.REPOSITORY_REINSTALL,
        BrokerOperation.RESOURCE_PLAN_RETIRE,
        BrokerOperation.RESOURCE_RETIRE,
        BrokerOperation.RESOURCE_PLAN_ARCHIVE,
        BrokerOperation.RESOURCE_ARCHIVE,
        BrokerOperation.RESOURCE_RESTORE,
    ):
        persistence.grant_cleanup(
            uid=client_uid,
            repo_id=repo_id,
            operation=operation,
            enabled=grant_cleanup_capabilities,
        )
    compose_run_once_services = _compose_run_once_grant_mapping(
        compose=compose,
        allowed_run_once_services=allowed_compose_run_once_services,
    )
    compose_definition_id = _provision_compose(
        persistence,
        repo_id=repo_id,
        client_uid=client_uid,
        root=root,
        compose=compose,
        allowed_run_once_services=allowed_compose_run_once_services,
        observation_snapshot_id=enrollment_snapshot_id,
        host_access_approved=approve_compose_host_access,
    )
    compose_container_ids = _compose_owned_container_ids_for_profile(
        persistence,
        repo_id=repo_id,
        root=root,
        compose=compose,
        compose_definition_id=compose_definition_id,
        enrollment_snapshot_id=enrollment_snapshot_id,
        enrolled_container_ids=frozenset(container_ids.values()),
    )
    ephemeral_templates = _provision_ephemeral_templates(
        persistence,
        repo_id=repo_id,
        client_uid=client_uid,
        templates=normalized_ephemeral,
        grant_image_prefetch=grant_ephemeral_image_prefetch,
    )
    ephemeral_secret_policies = _ephemeral_secret_policy_profiles(
        repo_id=repo_id,
        template_ids=ephemeral_templates,
        templates=normalized_ephemeral,
    )
    persistence.provision_repository_enrollment(
        uid=client_uid,
        repo_id=repo_id,
        account_id=account_id,
        issued_at=issued_at,
        valid_until_epoch=valid_until_epoch,
        enrollment_snapshot_id=enrollment_snapshot_id,
        grant_snapshot_id=grant_snapshot_id,
    )
    _merge_profile(
        profile_path=profile_path,
        service={
            "socket": str(socket_path),
            "uid": service_uid,
            "gid": socket_gid,
            "mode": f"{socket_mode:04o}",
            "database_generation": database_generation,
        },
        client_uid=client_uid,
        account_id=account_id,
        repository={
            "canonical_root": str(root),
            "repo_id": repo_id,
            "generation": repository_generation,
            "owner_uid": repository_owner_uid,
            "servers": granted_server_ids,
            "containers": container_ids,
            "compose_definition_id": compose_definition_id,
            "compose_container_ids": list(compose_container_ids),
            "compose_run_once_services": compose_run_once_services,
            "ephemeral_templates": ephemeral_templates,
            "ephemeral_image_prefetch_templates": (
                sorted(ephemeral_templates.values())
                if grant_ephemeral_image_prefetch
                else []
            ),
            "ephemeral_secret_policies": ephemeral_secret_policies,
        },
        issued_at=issued_at,
        valid_until_epoch=valid_until_epoch,
    )
    return {
        "status": "enrolled",
        "client_uid": client_uid,
        "account_id": account_id,
        "repo_id": repo_id,
        "repository_owner_uid": repository_owner_uid,
        "server_ids": granted_server_ids,
        "defined_server_ids": server_ids,
        "container_ids": container_ids,
        "compose_definition_id": compose_definition_id,
        "compose_container_ids": list(compose_container_ids),
        "compose_run_once_services": compose_run_once_services,
        "ephemeral_templates": ephemeral_templates,
        "ephemeral_image_prefetch_templates": (
            sorted(ephemeral_templates.values())
            if grant_ephemeral_image_prefetch
            else []
        ),
        "ephemeral_secret_policies": ephemeral_secret_policies,
        "enrollment_snapshot_id": enrollment_snapshot_id,
        "grant_snapshot_id": grant_snapshot_id,
        "database_generation": database_generation,
        "profile_path": str(profile_path),
        "valid_until_epoch": valid_until_epoch,
        "starts_resources": False,
        "cleanup_capabilities": bool(grant_cleanup_capabilities),
        "worker_log_root": str(worker_log_root),
        "observation_snapshot_id": enrollment_snapshot_id,
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
            raise TypeError("every enrolled server definition must be an object")
        name = str(raw.get("name") or "").strip()
        if not name or len(name) > 128:
            raise ValueError("every enrolled server requires a bounded name")
        if name in names:
            raise ValueError(f"duplicate enrolled server name: {name}")
        names.add(name)
        cwd = Path(str(raw.get("cwd") or root)).resolve(strict=True)
        if not _within(cwd, root):
            raise ValueError(
                f"enrolled server cwd escapes canonical repository: {cwd}"
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
                "server cleanup evidence is unreadable; enrollment cannot safely determine identity lineage"
            ) from error
        if not isinstance(evidence, dict):
            raise RuntimeError(
                "server cleanup evidence is invalid; enrollment cannot safely determine identity lineage"
            )
        plan = evidence.get("plan")
        snapshot = evidence.get("snapshot")
        target = plan.get("target") if isinstance(plan, dict) else None
        if not isinstance(target, dict) and isinstance(snapshot, dict):
            target = snapshot.get("target")
        name = target.get("display_name") if isinstance(target, dict) else None
        if not isinstance(name, str) or not name:
            raise RuntimeError(
                "server cleanup evidence lacks its exact name; enrollment cannot safely determine identity lineage"
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
                "server cleanup evidence has ambiguous identity lineage; enrollment requires administrative reconciliation"
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


def _require_enrollment_snapshot(
    store: CoordinatorStore,
    *,
    observation: Mapping[str, Any],
    host_id: str,
) -> str:
    """Validate an explicitly supplied newest committed observation snapshot.

    New enrollment uses the stricter per-call freshness fence below. This
    validator remains the compatibility boundary for callers that already
    captured a snapshot and must still prove its exact durable fingerprints.
    """

    if not isinstance(observation, Mapping):
        raise TypeError("enrollment host observation returned non-mapping evidence")
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
            "broker enrollment observation lacks exact committed full-Docker evidence"
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
            "broker enrollment observation is not the latest committed full-Docker snapshot"
        )
    capability_committed_at = observation.get("capability_committed_at")
    if capability_committed_at is not None and str(
        capability_committed_at
    ) != str(row["committed_at"]):
        raise RuntimeError(
            "broker enrollment observation capability evidence changed before enrollment"
        )
    return snapshot_id


def _disable_observed_resource_grants(
    persistence: BrokerPersistence, *, repo_id: str, client_uid: int
) -> None:
    """Fail closed on stale observation-derived grants before reenrollment."""

    now = utc_timestamp()
    with CoordinatorStore.open(
        persistence.database_path, expected_uid=persistence.expected_uid
    ) as store:
        with store.immediate_transaction() as connection:
            connection.execute(
                """
                UPDATE broker_resource_acl SET enabled = 0, updated_at = ?
                WHERE uid = ? AND repo_id = ? AND resource_kind = 'container'
                """,
                (now, client_uid, repo_id),
            )
            for table in (
                "broker_database_acl",
                "broker_lifecycle_resource_acl",
                "broker_cleanup_resource_acl",
            ):
                connection.execute(
                    f"UPDATE {table} SET enabled = 0, updated_at = ? "
                    "WHERE uid = ? AND repo_id = ?",
                    (now, client_uid, repo_id),
                )


def _collect_observed_containers(
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    client_uid: int,
    snapshot_id: str,
    excluded_container_ids: Sequence[str] = (),
) -> tuple[
    dict[str, str],
    tuple[tuple[str, str, str, bool], ...],
    tuple[tuple[str, str, str], ...],
    tuple[tuple[str, str, BrokerOperation], ...],
]:
    result: dict[str, str] = {}
    if isinstance(excluded_container_ids, (str, bytes, bytearray)):
        raise ValueError("excluded container IDs must be a sequence")
    excluded_ids = frozenset(str(item) for item in excluded_container_ids)
    if any(not item for item in excluded_ids):
        raise ValueError("excluded container IDs must be non-empty")
    with CoordinatorStore.open(
        persistence.database_path, expected_uid=persistence.expected_uid
    ) as store:
        with store.read_transaction() as connection:
            _require_exact_grant_snapshot(
                connection,
                repo_id=repo_id,
                snapshot_id=snapshot_id,
            )
            rows = list(
                connection.execute(
                    """
                    SELECT observed.docker_resource_id,
                           observed.full_container_id AS observed_full_container_id,
                           observed.ownership_state,
                           observed.authoritative_owner_repo_id,
                           d.full_container_id, d.current_name,
                           1 AS compose_scoped
                    FROM broker_observed_compose_containers observed
                    JOIN docker_resources d
                      ON d.docker_resource_id = observed.docker_resource_id
                    WHERE observed.snapshot_id = ?
                      AND observed.authoritative_owner_repo_id = ?
                      AND NOT EXISTS (
                          SELECT 1
                          FROM repository_memberships membership
                          JOIN control_bindings binding
                            ON binding.binding_id = membership.control_binding_id
                          WHERE membership.repo_id = ?
                            AND membership.resource_kind = 'container'
                            AND membership.host_resource_id = observed.docker_resource_id
                            AND binding.authority_state = 'authoritative'
                            AND binding.provenance = 'coordinator_ephemeral'
                      )
                    ORDER BY d.current_name, d.full_container_id
                    """,
                    (snapshot_id, repo_id, repo_id),
                )
            )
            # Compose scope is exhaustive only for Compose-labelled resources.
            # An exact operator/runtime-manifest membership can deliberately
            # own a standalone container in the same full-Docker snapshot. It
            # needs the same runtime grants, but its identity proof must remain
            # snapshot-scoped rather than pretending it was Compose evidence.
            rows.extend(
                connection.execute(
                    """
                    SELECT d.docker_resource_id,
                           d.full_container_id AS observed_full_container_id,
                           'exclusive' AS ownership_state,
                           membership.repo_id AS authoritative_owner_repo_id,
                           d.full_container_id, d.current_name,
                           0 AS compose_scoped
                    FROM repository_memberships membership
                    JOIN control_bindings binding
                      ON binding.binding_id = membership.control_binding_id
                    JOIN docker_resources d
                      ON d.docker_resource_id = membership.host_resource_id
                    JOIN docker_engines engine USING(engine_id)
                    JOIN repositories repository
                      ON repository.repo_id = membership.repo_id
                     AND repository.host_id = engine.host_id
                    JOIN observation_snapshot_resources observed
                      ON observed.snapshot_id = ?
                     AND observed.resource_kind = 'container'
                     AND observed.resource_id = d.docker_resource_id
                    WHERE membership.repo_id = ?
                      AND membership.resource_kind = 'container'
                      AND binding.authority_state = 'authoritative'
                      AND binding.provenance != 'coordinator_ephemeral'
                      AND (
                          binding.provenance IN (
                              'operator_attach', 'runtime_manifest'
                          )
                          OR NOT EXISTS (
                              SELECT 1
                              FROM broker_observation_compose_scope scope
                              WHERE scope.snapshot_id = ?
                          )
                      )
                      AND NOT EXISTS (
                          SELECT 1
                          FROM broker_observed_compose_containers compose_observed
                          WHERE compose_observed.snapshot_id = ?
                            AND compose_observed.docker_resource_id =
                                d.docker_resource_id
                      )
                    ORDER BY d.current_name, d.full_container_id
                    """,
                    (snapshot_id, repo_id, snapshot_id, snapshot_id),
                )
            )
            rows.sort(
                key=lambda row: (
                    str(row["current_name"]),
                    str(row["full_container_id"]),
                )
            )
            rows = [
                row
                for row in rows
                if str(row["docker_resource_id"]) not in excluded_ids
            ]
            for row in rows:
                if (
                    str(row["ownership_state"]) != "exclusive"
                    or str(row["authoritative_owner_repo_id"] or "") != repo_id
                    or str(row["observed_full_container_id"])
                    != str(row["full_container_id"])
                ):
                    raise RuntimeError(
                        "exact enrollment container evidence no longer matches current identity"
                    )
                owner_rows = tuple(
                    str(owner["repo_id"])
                    for owner in connection.execute(
                        """
                        SELECT DISTINCT membership.repo_id
                        FROM repository_memberships membership
                        JOIN control_bindings binding
                          ON binding.binding_id = membership.control_binding_id
                        WHERE membership.resource_kind = 'container'
                          AND membership.host_resource_id = ?
                          AND binding.authority_state = 'authoritative'
                        ORDER BY membership.repo_id
                        """,
                        (row["docker_resource_id"],),
                    )
                )
                if owner_rows != (repo_id,):
                    raise RuntimeError(
                        "exact enrollment container membership is absent, stale, or conflicting"
                    )
    runtime_grants = tuple(
        ("docker", str(row["docker_resource_id"]), action)
        for row in rows
        for action in ("status", "start", "stop", "restart")
    )
    resource_grants = tuple(
        ("container", str(row["docker_resource_id"]), operation)
        for row in rows
        for operation in (
            BrokerOperation.DOCKER_START,
            BrokerOperation.DOCKER_STOP,
            BrokerOperation.DOCKER_RESTART,
        )
    )
    for row in rows:
        resource_id = str(row["docker_resource_id"])
        result[str(row["current_name"])] = resource_id
        result[str(row["full_container_id"])] = resource_id
    identity_grants = tuple(
        (
            snapshot_id,
            str(row["docker_resource_id"]),
            str(row["full_container_id"]),
            bool(row["compose_scoped"]),
        )
        for row in rows
    )
    return result, identity_grants, runtime_grants, resource_grants


def _grant_observed_containers(
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    client_uid: int,
    snapshot_id: str,
) -> dict[str, str]:
    (
        aliases,
        identity_grants,
        runtime_grants,
        resource_grants,
    ) = _collect_observed_containers(
        persistence,
        repo_id=repo_id,
        client_uid=client_uid,
        snapshot_id=snapshot_id,
    )
    persistence.grant_observation_derived_access_batch(
        uid=client_uid,
        repo_id=repo_id,
        container_identity_grants=identity_grants,
        runtime_grants=runtime_grants,
        resource_grants=resource_grants,
    )
    return aliases


def _collect_observed_databases(
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    client_uid: int,
    snapshot_id: str,
) -> tuple[
    tuple[tuple[str, str, str], ...],
    tuple[tuple[str, BrokerOperation], ...],
]:
    with CoordinatorStore.open(
        persistence.database_path, expected_uid=persistence.expected_uid
    ) as store:
        with store.read_transaction() as connection:
            _require_exact_grant_snapshot(
                connection,
                repo_id=repo_id,
                snapshot_id=snapshot_id,
            )
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
                    JOIN observation_snapshot_resources snapshot
                      ON snapshot.snapshot_id = ?
                     AND snapshot.resource_kind = 'container'
                     AND snapshot.resource_id = db.docker_resource_id
                    JOIN docker_observations observed
                      ON observed.docker_resource_id = db.docker_resource_id
                     AND observed.observation_fingerprint =
                         snapshot.observation_fingerprint
                    WHERE db.repo_id = ? AND db.engine_kind = 'postgresql'
                      AND c.authority_state = 'authoritative'
                    ORDER BY db.database_binding_id
                    """,
                    (snapshot_id, repo_id),
                )
            )
            compose_scope = connection.execute(
                "SELECT 1 FROM broker_observation_compose_scope WHERE snapshot_id = ?",
                (snapshot_id,),
            ).fetchone()
            if not binding_ids and compose_scope is None:
                binding_ids = tuple(
                    str(row["database_binding_id"])
                    for row in connection.execute(
                        """
                        SELECT db.database_binding_id
                        FROM database_bindings db
                        JOIN repository_memberships membership
                          ON membership.repo_id = db.repo_id
                         AND membership.resource_kind = 'container'
                         AND membership.host_resource_id = db.docker_resource_id
                        JOIN control_bindings binding
                          ON binding.binding_id = membership.control_binding_id
                        JOIN observation_snapshot_resources observed
                          ON observed.snapshot_id = ?
                         AND observed.resource_kind = 'container'
                         AND observed.resource_id = db.docker_resource_id
                        WHERE db.repo_id = ? AND db.engine_kind = 'postgresql'
                          AND binding.authority_state = 'authoritative'
                        ORDER BY db.database_binding_id
                        """,
                        (snapshot_id, repo_id),
                    )
                )
    return (
        tuple(
            ("database_stack", binding_id, action)
            for binding_id in binding_ids
            for action in ("status", "start", "stop", "restart")
        ),
        tuple(
            (binding_id, operation)
            for binding_id in binding_ids
            for operation in (
                BrokerOperation.DATABASE_BACKUP,
                BrokerOperation.DATABASE_RESTORE,
            )
        ),
    )


def _grant_observed_databases(
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    client_uid: int,
    snapshot_id: str,
) -> None:
    runtime_grants, database_grants = _collect_observed_databases(
        persistence,
        repo_id=repo_id,
        client_uid=client_uid,
        snapshot_id=snapshot_id,
    )
    persistence.grant_observation_derived_access_batch(
        uid=client_uid,
        repo_id=repo_id,
        runtime_grants=runtime_grants,
        database_grants=database_grants,
    )


def _collect_observed_lifecycle_resources(
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    client_uid: int,
    snapshot_id: str,
) -> tuple[tuple[str, str, str, str, str, BrokerOperation], ...]:
    exact_resources = []
    with CoordinatorStore.open(
        persistence.database_path, expected_uid=persistence.expected_uid
    ) as store:
        lifecycle = SQLiteLifecyclePersistence(store)
        with store.read_transaction() as connection:
            _require_exact_grant_snapshot(
                connection,
                repo_id=repo_id,
                snapshot_id=snapshot_id,
            )
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
                    JOIN observation_snapshot_resources snapshot
                      ON snapshot.snapshot_id = ?
                     AND snapshot.resource_kind = u.resource_kind
                     AND snapshot.resource_id = u.resource_id
                    WHERE u.status = 'active'
                      AND b.authority_state = 'authoritative'
                      AND s.effective_uid = ?
                      AND (
                          (
                              u.resource_kind = 'container'
                              AND EXISTS (
                                  SELECT 1 FROM docker_observations observed
                                  WHERE observed.docker_resource_id = u.resource_id
                                    AND observed.observation_fingerprint =
                                        snapshot.observation_fingerprint
                              )
                          )
                          OR
                          (
                              u.resource_kind = 'server'
                              AND EXISTS (
                                  SELECT 1 FROM server_observations observed
                                  WHERE observed.server_definition_id = u.resource_id
                                    AND observed.observation_fingerprint =
                                        snapshot.observation_fingerprint
                              )
                          )
                      )
                    ORDER BY u.resource_kind, u.resource_id, b.binding_id
                    """,
                    (snapshot_id, client_uid),
                )
            )
            compose_scope = connection.execute(
                "SELECT 1 FROM broker_observation_compose_scope WHERE snapshot_id = ?",
                (snapshot_id,),
            ).fetchone()
            if not candidates and compose_scope is None:
                candidates = tuple(
                    (
                        str(row["resource_kind"]),
                        str(row["resource_id"]),
                        str(row["binding_id"]),
                    )
                    for row in connection.execute(
                        """
                        SELECT unassigned.resource_kind,
                               unassigned.resource_id, binding.binding_id
                        FROM unassigned_resources unassigned
                        JOIN control_bindings binding
                          ON binding.resource_kind = unassigned.resource_kind
                         AND binding.resource_id = unassigned.resource_id
                        JOIN coordinator_sources source
                          ON source.source_id = binding.source_id
                        JOIN observation_snapshot_resources observed
                          ON observed.snapshot_id = ?
                         AND observed.resource_kind = unassigned.resource_kind
                         AND observed.resource_id = unassigned.resource_id
                        WHERE unassigned.status = 'active'
                          AND binding.authority_state = 'authoritative'
                          AND source.effective_uid = ?
                        ORDER BY unassigned.resource_kind,
                                 unassigned.resource_id, binding.binding_id
                        """,
                        (snapshot_id, client_uid),
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
    return tuple(
        (
            exact.kind.value,
            exact.resource_id,
            exact.control_binding_id,
            exact.immutable_fingerprint,
            exact.ownership_fingerprint,
            operation,
        )
        for exact in exact_resources
        for operation in (
            BrokerOperation.RESOURCE_ATTACH,
            BrokerOperation.RESOURCE_PLAN_RETIRE,
            BrokerOperation.RESOURCE_RETIRE,
        )
    )


def _grant_observed_lifecycle_resources(
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    client_uid: int,
    snapshot_id: str,
) -> None:
    grants = _collect_observed_lifecycle_resources(
        persistence,
        repo_id=repo_id,
        client_uid=client_uid,
        snapshot_id=snapshot_id,
    )
    persistence.grant_observation_derived_access_batch(
        uid=client_uid,
        repo_id=repo_id,
        lifecycle_resource_grants=grants,
    )


def _collect_observed_cleanup_resources(
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    client_uid: int,
    snapshot_id: str,
) -> tuple[tuple[str, str, str, str, str, BrokerOperation], ...]:
    with CoordinatorStore.open(
        persistence.database_path, expected_uid=persistence.expected_uid
    ) as store:
        with store.read_transaction() as connection:
            _require_exact_grant_snapshot(
                connection,
                repo_id=repo_id,
                snapshot_id=snapshot_id,
            )
            observed_resources = {
                (str(row["resource_kind"]), str(row["resource_id"]))
                for row in connection.execute(
                    """
                    SELECT resource_kind, resource_id
                    FROM observation_snapshot_resources observed
                    WHERE snapshot_id = ?
                      AND NOT EXISTS (
                          SELECT 1 FROM control_bindings binding
                          WHERE binding.resource_kind = observed.resource_kind
                            AND binding.resource_id = observed.resource_id
                            AND binding.provenance = 'coordinator_ephemeral'
                      )
                    """,
                    (snapshot_id,),
                )
            }
        snapshot = SQLiteLifecyclePersistence(store).repository_snapshot(repo_id)
        exact_resources = tuple(
            target
            for target in snapshot.targets
            if (target.kind.value, target.resource_id) in observed_resources
        )
    return tuple(
        (
            exact.kind.value,
            exact.resource_id,
            exact.control_binding_id,
            exact.immutable_fingerprint,
            (
                exact.control_contract_fingerprint
                if operation
                in {
                    BrokerOperation.CLEANUP_PLAN,
                    BrokerOperation.CLEANUP_APPLY,
                    BrokerOperation.RESOURCE_RESTORE,
                }
                else exact.ownership_fingerprint
            ),
            operation,
        )
        for exact in exact_resources
        for operation in (
            BrokerOperation.CLEANUP_PLAN,
            BrokerOperation.CLEANUP_APPLY,
            BrokerOperation.RESOURCE_PLAN_ARCHIVE,
            BrokerOperation.RESOURCE_ARCHIVE,
            BrokerOperation.RESOURCE_RESTORE,
        )
    )


def _grant_observed_cleanup_resources(
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    client_uid: int,
    snapshot_id: str,
) -> None:
    grants = _collect_observed_cleanup_resources(
        persistence,
        repo_id=repo_id,
        client_uid=client_uid,
        snapshot_id=snapshot_id,
    )
    persistence.grant_observation_derived_access_batch(
        uid=client_uid,
        repo_id=repo_id,
        cleanup_resource_grants=grants,
    )


def _grant_all_observed_access(
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    client_uid: int,
    snapshot_id: str,
    include_cleanup: bool,
    excluded_container_ids: Sequence[str] = (),
) -> dict[str, str]:
    """Derive one exact replacement set and publish it in one transaction."""

    aliases, container_identities, container_runtime, container_resources = (
        _collect_observed_containers(
            persistence,
            repo_id=repo_id,
            client_uid=client_uid,
            snapshot_id=snapshot_id,
            excluded_container_ids=excluded_container_ids,
        )
    )
    database_runtime, database_grants = _collect_observed_databases(
        persistence,
        repo_id=repo_id,
        client_uid=client_uid,
        snapshot_id=snapshot_id,
    )
    lifecycle_grants = _collect_observed_lifecycle_resources(
        persistence,
        repo_id=repo_id,
        client_uid=client_uid,
        snapshot_id=snapshot_id,
    )
    cleanup_grants = (
        _collect_observed_cleanup_resources(
            persistence,
            repo_id=repo_id,
            client_uid=client_uid,
            snapshot_id=snapshot_id,
        )
        if include_cleanup
        else ()
    )
    persistence.grant_observation_derived_access_batch(
        uid=client_uid,
        repo_id=repo_id,
        container_identity_grants=container_identities,
        runtime_grants=(*container_runtime, *database_runtime),
        resource_grants=container_resources,
        database_grants=database_grants,
        lifecycle_resource_grants=lifecycle_grants,
        cleanup_resource_grants=cleanup_grants,
    )
    return aliases


def _require_exact_grant_snapshot(
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
            "enrollment grant derivation requires its exact completed full-Docker snapshot"
        )


def _declared_container_names(
    runtime_file: Path,
    *,
    candidates: frozenset[str],
) -> tuple[str, ...]:
    """Read explicit Docker dependency names from one enrolled runtime manifest.

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


def reconcile_enrolled_runtime_container_declarations(
    store: AccountStore,
    *,
    snapshot_id: str,
) -> dict[str, Any]:
    """Rebuild lost ownership from exact enrolled runtime declarations.

    Fresh-store adoption intentionally discards historical membership rows.
    This reconciliation makes the checked-in runtime manifest the durable
    reconstruction source without guessing from project or image names. It is
    bounded to exact containers that are both present in ``snapshot_id`` and
    currently unassigned for a repairable attribution reason.

    A dependency may be shared by several repositories. The first enrolled
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
                       resource.current_name, binding.binding_id,
                       binding.authority_state, binding.provenance,
                       membership.repo_id AS attached_repo_id,
                       membership.control_binding_id AS membership_binding_id
                FROM observation_snapshot_resources present
                JOIN docker_resources resource
                  ON resource.docker_resource_id = present.resource_id
                JOIN docker_engines engine USING(engine_id)
                JOIN control_bindings binding
                  ON binding.binding_id = (
                      SELECT candidate.binding_id
                      FROM control_bindings candidate
                      WHERE candidate.resource_kind = 'container'
                        AND candidate.resource_id = resource.docker_resource_id
                      ORDER BY candidate.priority DESC, candidate.binding_id
                      LIMIT 1
                  )
                LEFT JOIN repository_memberships membership
                  ON membership.resource_kind = 'container'
                 AND membership.host_resource_id = resource.docker_resource_id
                WHERE present.snapshot_id = ?
                  AND present.resource_kind = 'container'
                  AND engine.host_id = ?
                  AND EXISTS (
                      SELECT 1 FROM unassigned_resources unassigned
                      WHERE unassigned.host_id = engine.host_id
                        AND unassigned.resource_kind = 'container'
                        AND unassigned.resource_id = resource.docker_resource_id
                        AND unassigned.status = 'active'
                        AND unassigned.reason_code IN (
                            'name_only', 'not_git', 'missing_repo'
                        )
                  )
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
        # Primary ownership is ordered across every enrolled repository. If
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
            "skipped": "enrolled_runtime_manifest_invalid",
        }

    lifecycle = SQLiteLifecyclePersistence(store)
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
        attached_repo_id = (
            None
            if row["attached_repo_id"] is None
            else str(row["attached_repo_id"])
        )
        if attached_repo_id not in {None, primary["repo_id"]}:
            bindings.append(
                {
                    "container": name,
                    "resource_id": str(row["docker_resource_id"]),
                    "status": "retained_existing_owner",
                    "owner_repo_id": attached_repo_id,
                    "primary_declaration": primary,
                    "shared_references": declared_by[1:],
                }
            )
            continue
        if (
            str(row["authority_state"]) != "authoritative"
            or not isinstance(row["binding_id"], str)
            or not row["binding_id"]
            or (
                attached_repo_id is not None
                and str(row["membership_binding_id"] or "")
                != str(row["binding_id"])
            )
        ):
            bindings.append(
                {
                    "container": name,
                    "resource_id": str(row["docker_resource_id"]),
                    "status": "control_binding_unavailable",
                    "primary_declaration": primary,
                    "shared_references": declared_by[1:],
                }
            )
            continue
        try:
            if attached_repo_id is None:
                exact = lifecycle.resolve_standalone_resource(
                    ResourceKind.CONTAINER,
                    str(row["docker_resource_id"]),
                    str(row["binding_id"]),
                )
            else:
                exact, resolved_repo_id = lifecycle.resolve_resource(
                    ResourceKind.CONTAINER,
                    str(row["docker_resource_id"]),
                    str(row["binding_id"]),
                )
                if resolved_repo_id != primary["repo_id"]:
                    raise LifecycleError(
                        "declared container owner changed during reconciliation"
                    )
            result = lifecycle.attach_resource(
                primary["repo_id"],
                exact,
                actor="runtime-manifest-reconciler",
                reason=(
                    "exact checked-in runtime dependency declaration"
                ),
                provenance="runtime_manifest",
                allow_existing=True,
            )
        except (LifecycleError, ValueError) as error:
            bindings.append(
                {
                    "container": name,
                    "resource_id": str(row["docker_resource_id"]),
                    "status": "reconciliation_deferred",
                    "error": str(error),
                    "primary_declaration": primary,
                    "shared_references": declared_by[1:],
                }
            )
            continue
        changed += int(result.attached)
        bindings.append(
            {
                "container": name,
                "resource_id": str(row["docker_resource_id"]),
                "full_container_id": str(row["full_container_id"]),
                "status": "attached" if result.attached else "already_attached",
                "owner_repo_id": primary["repo_id"],
                "owner_root": primary["canonical_root"],
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
    client_uid: int,
    templates: Sequence[Mapping[str, Any]],
    grant_image_prefetch: bool = False,
) -> dict[str, str]:
    """Replace one repository's exact template definitions and UID grants."""

    if type(grant_image_prefetch) is not bool:
        raise TypeError("grant_image_prefetch must be a boolean")
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
    persistence.replace_ephemeral_access(
        uid=client_uid,
        repo_id=repo_id,
        template_ids=template_ids.values(),
        prefetch_template_ids=(
            template_ids.values() if grant_image_prefetch else ()
        ),
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
    client_uid: int,
    root: Path,
    compose: Mapping[str, Any] | None,
    allowed_run_once_services: Sequence[str] = (),
    observation_snapshot_id: str | None = None,
    host_access_approved: bool = False,
) -> str | None:
    if not compose or not compose.get("declared"):
        persistence.disable_repository_compose(repo_id=repo_id)
        if allowed_run_once_services:
            raise ValueError(
                "Compose run-once grants require a declared Compose definition"
            )
        return None
    run_once_policies = normalize_compose_run_once_policies(
        compose.get("run_once_services", ())
    )
    granted_run_once_names = tuple(
        _compose_run_once_grant_mapping(
            compose=compose,
            allowed_run_once_services=allowed_run_once_services,
        )
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
        raise ValueError("declared Compose enrollment requires at least one exact file")
    services = tuple(str(item) for item in compose.get("services") or [])
    if not services:
        raise ValueError(
            "declared Compose enrollment requires at least one exact service"
        )
    env_files: list[str] = []
    for raw in compose.get("env_files") or []:
        path = _canonical_repository_file(
            raw,
            root=root,
            field="Compose environment file",
        )
        env_files.append(str(path))
    existing_id = persistence.enrolled_compose_definition_id(repo_id=repo_id)
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
    persistence.replace_compose_access(
        uid=client_uid,
        repo_id=repo_id,
        compose_definition_id=compose_id,
    )
    persistence.replace_compose_run_once_access(
        uid=client_uid,
        repo_id=repo_id,
        compose_definition_id=compose_id,
        service_names=granted_run_once_names,
    )
    return compose_id


def _compose_enrollment_container_scope(
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    root: Path,
    compose: Mapping[str, Any] | None,
    enrollment_snapshot_id: str | None,
) -> ComposeEnrollmentContainerScope | None:
    """Validate the complete same-project scope from the enrollment snapshot."""

    if not compose or not compose.get("declared"):
        return None
    if enrollment_snapshot_id is None:
        raise RuntimeError("declared Compose enrollment lacks snapshot authority")
    services = tuple(
        _require_compose_service_name(str(item))
        for item in compose.get("services") or ()
    )
    if not services:
        raise RuntimeError("declared Compose enrollment has no lifecycle services")
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
    return persistence.compose_enrollment_container_scope(
        repo_id=repo_id,
        snapshot_id=enrollment_snapshot_id,
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
    enrollment_snapshot_id: str | None,
    enrolled_container_ids: frozenset[str],
) -> tuple[str, ...]:
    """Publish the exact existing container subset controlled by Compose."""

    if not compose or not compose.get("declared"):
        if compose_definition_id is not None:
            raise RuntimeError(
                "undeclared Compose enrollment returned a contradictory definition"
            )
        return ()
    if compose_definition_id is None or enrollment_snapshot_id is None:
        raise RuntimeError(
            "declared Compose enrollment lacks definition or snapshot authority"
        )
    observed_scope = _compose_enrollment_container_scope(
        persistence,
        repo_id=repo_id,
        root=root,
        compose=compose,
        enrollment_snapshot_id=enrollment_snapshot_id,
    )
    if observed_scope is None:
        raise RuntimeError("declared Compose enrollment has no observed scope")
    resource_ids = observed_scope.lifecycle_container_ids
    if len(set(resource_ids)) != len(resource_ids):
        raise RuntimeError("Compose-owned enrollment resource IDs are duplicated")
    if not set(resource_ids) <= enrolled_container_ids:
        raise RuntimeError(
            "Compose-owned enrollment resource is absent from client container grants"
        )
    return tuple(sorted(resource_ids))


def _compose_run_once_grant_mapping(
    *,
    compose: Mapping[str, Any] | None,
    allowed_run_once_services: Sequence[str],
) -> dict[str, int]:
    """Validate an explicit enrollment grant and publish only timeout ceilings."""

    if isinstance(allowed_run_once_services, (str, bytes, bytearray)):
        raise ValueError(
            "allowed Compose run-once services must be a sequence of exact names"
        )
    supplied = tuple(allowed_run_once_services)
    if not compose or not compose.get("declared"):
        if supplied:
            raise ValueError(
                "Compose run-once grants require a declared Compose definition"
            )
        return {}
    policies = normalize_compose_run_once_policies(
        compose.get("run_once_services", ())
    )
    policy_by_name = {policy.name: policy for policy in policies}
    names: list[str] = []
    for item in supplied:
        if not isinstance(item, str) or not item:
            raise ValueError(
                "allowed Compose run-once service names must be non-empty strings"
            )
        if item not in names:
            names.append(item)
    unknown = sorted(set(names) - set(policy_by_name))
    if unknown:
        raise ValueError(
            "Compose run-once grant names are absent from the sealed manifest: "
            + ", ".join(unknown)
        )
    return {
        name: policy_by_name[name].max_timeout_seconds
        for name in names
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
            "declared Compose enrollment requires a merged-model renderer"
        )
    file_paths = tuple(
        _canonical_repository_file(raw, root=root, field="Compose file")
        for raw in compose.get("files") or ()
    )
    if not 1 <= len(file_paths) <= 16:
        raise ValueError(
            "declared Compose enrollment requires from one through 16 exact files"
        )
    env_paths = tuple(
        _canonical_repository_file(raw, root=root, field="Compose environment file")
        for raw in compose.get("env_files") or ()
    )
    if len(env_paths) > 16:
        raise ValueError("Compose environment enrollment accepts at most 16 files")
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
        raise ValueError("declared Compose enrollment requires unique exact services")
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
        raise ValueError("Compose enrollment profiles must be unique")
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
    initial, access_gid = _read_protected_profile_for_revocation(
        path, expected_database_generation=expected_database_generation
    )
    del initial
    _ensure_root_profile_parent(path.parent, access_gid=access_gid)
    with _locked_root_profile(path, access_gid=access_gid):
        document, locked_gid = _read_protected_profile_for_revocation(
            path, expected_database_generation=expected_database_generation
        )
        if locked_gid != access_gid:
            raise RuntimeError(
                "protected broker profile service identity changed before revocation"
            )
        affected = _revoke_server_from_profile_document(
            document,
            repo_id=repo_id,
            server_name=server_name,
            server_definition_id=server_definition_id,
        )
        if affected:
            _atomic_write_root_json(path, document, access_gid=access_gid)
    return {
        "status": "revoked" if affected else "already_revoked",
        "repo_id": repo_id,
        "server_name": server_name,
        "server_definition_id": server_definition_id,
        "cleanup_operation_id": cleanup_operation_id,
        "affected_client_uids": affected,
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
    initial, access_gid = _read_protected_profile_for_revocation(
        path, expected_database_generation=expected_database_generation
    )
    del initial
    _ensure_root_profile_parent(path.parent, access_gid=access_gid)
    with _locked_root_profile(path, access_gid=access_gid):
        document, locked_gid = _read_protected_profile_for_revocation(
            path, expected_database_generation=expected_database_generation
        )
        if locked_gid != access_gid:
            raise RuntimeError(
                "protected broker profile service identity changed before revocation"
            )
        affected = _revoke_repository_from_profile_document(
            document,
            repo_id=repo_id,
            repository_generation=repository_generation,
        )
        if affected:
            _atomic_write_root_json(path, document, access_gid=access_gid)
    return {
        "status": "revoked" if affected else "already_revoked",
        "repo_id": repo_id,
        "repository_generation": repository_generation,
        "cleanup_operation_id": cleanup_operation_id,
        "affected_client_uids": affected,
        "profile_path": str(path),
    }


def _read_protected_profile_for_revocation(
    path: Path, *, expected_database_generation: str
) -> tuple[dict[str, Any], int]:
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
    if (
        not isinstance(document, dict)
        or set(document) != {"version", "service", "clients"}
        or document.get("version") != PROFILE_VERSION
        or not isinstance(document.get("service"), dict)
        or not isinstance(document.get("clients"), dict)
    ):
        raise RuntimeError("protected broker profile structure is invalid")
    service = document["service"]
    if str(service.get("database_generation") or "") != expected_database_generation:
        raise RuntimeError(
            "protected broker profile belongs to another database generation"
        )
    access_gid = service.get("gid")
    if type(access_gid) is not int or access_gid < 0:
        raise RuntimeError("protected broker profile socket GID is invalid")
    return document, access_gid


def _revoke_server_from_profile_document(
    document: dict[str, Any],
    *,
    repo_id: str,
    server_name: str,
    server_definition_id: str,
) -> list[int]:
    """Pure exact-ID profile mutation used by publication and regression tests."""

    affected: list[int] = []
    clients = document.get("clients")
    if not isinstance(clients, dict):
        raise RuntimeError("protected broker profile clients are invalid")
    for uid_text, client in clients.items():
        if not isinstance(client, dict) or not isinstance(
            client.get("repositories"), list
        ):
            raise RuntimeError("protected broker profile client is invalid")
        try:
            uid = int(uid_text)
        except (TypeError, ValueError) as error:
            raise RuntimeError("protected broker profile UID is invalid") from error
        if uid < 0 or str(uid) != str(uid_text):
            raise RuntimeError("protected broker profile UID is invalid")
        changed = False
        for repository in client["repositories"]:
            if not isinstance(repository, dict):
                raise RuntimeError("protected broker repository profile is invalid")
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
                changed = True
        if changed:
            affected.append(uid)
    return sorted(affected)


def _revoke_repository_from_profile_document(
    document: dict[str, Any],
    *,
    repo_id: str,
    repository_generation: int,
) -> list[int]:
    """Remove only the exact revoked repository incarnation from each client."""

    affected: list[int] = []
    clients = document.get("clients")
    if not isinstance(clients, dict):
        raise RuntimeError("protected broker profile clients are invalid")
    for uid_text, client in clients.items():
        if not isinstance(client, dict) or not isinstance(
            client.get("repositories"), list
        ):
            raise RuntimeError("protected broker profile client is invalid")
        try:
            uid = int(uid_text)
        except (TypeError, ValueError) as error:
            raise RuntimeError("protected broker profile UID is invalid") from error
        if uid < 0 or str(uid) != str(uid_text):
            raise RuntimeError("protected broker profile UID is invalid")
        retained: list[dict[str, Any]] = []
        changed = False
        for repository in client["repositories"]:
            if not isinstance(repository, dict):
                raise RuntimeError("protected broker repository profile is invalid")
            if (
                str(repository.get("repo_id") or "") == repo_id
                and repository.get("generation") == repository_generation
            ):
                changed = True
                continue
            retained.append(repository)
        if changed:
            client["repositories"] = retained
            affected.append(uid)
    return sorted(affected)


def _merge_profile(
    *,
    profile_path: Path,
    service: dict[str, Any],
    client_uid: int,
    account_id: str,
    repository: dict[str, Any],
    issued_at: str,
    valid_until_epoch: int,
) -> dict[str, Any]:
    path = profile_path
    if not path.is_absolute():
        raise ValueError("broker profile output must be absolute")
    access_gid = int(service["gid"])
    _ensure_root_profile_parent(path.parent, access_gid=access_gid)
    with _locked_root_profile(path, access_gid=access_gid):
        if path.exists():
            metadata = path.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
            ):
                raise PermissionError("existing broker profile is not a regular file")
            document = json.loads(path.read_text(encoding="utf-8"))
            if (
                not isinstance(document, dict)
                or set(document) != {"version", "service", "clients"}
                or document.get("version") != PROFILE_VERSION
                or document.get("service") != service
            ):
                raise RuntimeError(
                    "existing broker profile belongs to another service authority"
                )
            host_profile_from_document(document, effective_uid=client_uid)
        else:
            document = {
                "version": PROFILE_VERSION,
                "service": service,
                "clients": {},
            }
        clients = document.setdefault("clients", {})
        if not isinstance(clients, dict):
            raise RuntimeError("existing broker profile has an invalid clients object")
        key = str(client_uid)
        if key in clients and not isinstance(clients[key], dict):
            raise RuntimeError(
                "existing broker profile has an invalid client enrollment"
            )
        current = clients.get(key) if isinstance(clients.get(key), dict) else {}
        current_account = current.get("account_id")
        if current and str(current_account or "") != account_id:
            raise RuntimeError(
                "authenticated UID already has a protected profile for a different account; implicit authority transfer is forbidden"
            )
        repositories: list[dict[str, Any]] = []
        current_repositories = current.get("repositories", [])
        if not isinstance(current_repositories, list):
            raise RuntimeError(
                "existing broker profile has an invalid repository enrollment list"
            )
        for item in current_repositories:
            if (
                not isinstance(item, dict)
                or set(item) != REPOSITORY_PROFILE_FIELDS
            ):
                raise RuntimeError(
                    "existing broker profile has an invalid repository enrollment"
                )
            if item.get("canonical_root") == repository["canonical_root"]:
                continue
            preserved = dict(item)
            if str(preserved["account_id"]) != account_id:
                raise RuntimeError(
                    "protected repository profile belongs to a different account"
                )
            repositories.append(preserved)
        enrolled_repository = dict(repository)
        enrolled_repository.update(
            {
                "account_id": account_id,
                "enabled": True,
                "issued_at": issued_at,
                "valid_until_epoch": valid_until_epoch,
            }
        )
        if set(enrolled_repository) != REPOSITORY_PROFILE_FIELDS:
            raise RuntimeError(
                "new broker profile has an invalid repository enrollment"
            )
        repositories.append(enrolled_repository)
        repositories.sort(key=lambda item: str(item["canonical_root"]))
        clients[key] = {
            "account_id": account_id,
            "issued_at": min(str(item["issued_at"]) for item in repositories),
            "valid_until_epoch": max(
                int(item["valid_until_epoch"]) for item in repositories
            ),
            "repositories": repositories,
        }
        _atomic_write_root_json(path, document, access_gid=access_gid)
        return document


@contextmanager
def _locked_root_profile(
    path: Path,
    *,
    access_gid: int,
) -> Generator[None, None, None]:
    """Serialize protected profile read-modify-replace across enroll processes."""

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
        os.fchown(descriptor, 0, access_gid)
        os.fchmod(descriptor, 0o640)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _ensure_root_profile_parent(path: Path, *, access_gid: int) -> None:
    if (
        not path.is_absolute()
        or ".." in path.parts
        or path == Path(path.anchor)
        or access_gid < 0
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
    os.chown(path, 0, access_gid)
    os.chmod(path, 0o755)


def _atomic_write_root_json(
    path: Path,
    document: Mapping[str, Any],
    *,
    access_gid: int,
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
        os.chown(temporary, 0, access_gid)
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


def _require_exact_enrollment_observation(
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
            "Enrollment requires the exact fresh service-owned full-Docker snapshot"
        ) from exc
    return str(committed["snapshot_id"])


def _capture_new_enrollment_observation(
    store: CoordinatorStore,
    *,
    host_id: str,
    observe_host: Callable[[CoordinatorStore], Mapping[str, Any] | None],
    require_complete_compose_assets: bool = False,
) -> str:
    """Capture evidence created strictly after the enrollment boundary.

    A host observer may single-flight onto a ticket that was already running
    when enrollment began.  Let that ticket finish, then fence and observe once
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
            accepted = _require_exact_enrollment_observation(
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
                    "Compose enrollment could not obtain a complete local Docker asset snapshot"
                )
        return accepted
    raise RuntimeError(
        "Enrollment requires an observation created after its freshness boundary"
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
