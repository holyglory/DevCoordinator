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
    _default_compose_project_name,
    _require_compose_profile_name,
    _require_compose_project_name,
    _require_compose_service_name,
)
from .broker_profile import PROFILE_VERSION
from .compose_contract import (
    require_effective_compose_model,
    require_sealable_compose_payload,
)
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


_FULL_DOCKER_OBSERVER_DOMAIN = FULL_DOCKER_OBSERVER_DOMAIN
_SHA256_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}")
_BARE_SHA256 = re.compile(r"[0-9a-f]{64}")


def enroll_repository(
    *,
    database_path: Path,
    socket_path: Path,
    socket_gid: int,
    client_uid: int,
    account_id: str,
    canonical_root: str,
    servers: Sequence[Mapping[str, Any]],
    allowed_server_names: Sequence[str] | None = None,
    port_start: int,
    port_end: int,
    profile_path: Path,
    compose: Mapping[str, Any] | None = None,
    compose_model_renderer: Callable[..., bytes] | None = None,
    approve_compose_host_access: bool = False,
    observe_host: Callable[[AccountStore], Mapping[str, Any] | None] | None = None,
    explicit_reinstall: bool = False,
    grant_cleanup_capabilities: bool = False,
    validity_seconds: int = 30 * 24 * 60 * 60,
) -> dict[str, Any]:
    """Synchronize trusted definitions/ACLs and atomically install a profile.

    This is an administrator surface, not a broker wire operation. Paths and
    launch definitions are read locally by the service owner and remain in its
    private database; the emitted client profile contains opaque IDs only.
    """

    service_uid = os.geteuid()
    if service_uid != 0:
        raise PermissionError(
            "broker enrollment must run as the root service administrator"
        )
    if type(client_uid) is not int or client_uid < 0:
        raise ValueError("client_uid must be a non-negative integer")
    if type(socket_gid) is not int or socket_gid < 0:
        raise ValueError("socket_gid must be a non-negative integer")
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
                SELECT repo_id, state, generation
                FROM repositories
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
                    raise ValueError(
                        f"enrolled server cwd escapes canonical repository: {cwd}"
                    )
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
                if (
                    isinstance(argv, list)
                    and argv
                    and all(isinstance(item, str) for item in argv)
                ):
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
            )
        with store.read_transaction() as connection:
            repository_row = connection.execute(
                "SELECT generation FROM repositories WHERE repo_id = ?", (repo_id,)
            ).fetchone()
        if repository_row is None:
            raise RuntimeError("repository disappeared during enrollment")
        repository_generation = int(repository_row["generation"])

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

    # Reenrollment must revoke every observation-derived capability before any
    # exact fresh snapshot is allowed to grant it again. Cleanup resources are
    # intentionally included in the older canonical ACL set as well.
    _disable_observed_resource_grants(
        persistence, repo_id=repo_id, client_uid=client_uid
    )
    persistence.revoke_observation_derived_access(
        uid=client_uid,
        repo_id=repo_id,
        containers=True,
        databases=True,
        lifecycle_resources=True,
    )
    container_ids = (
        _grant_observed_containers(
            persistence,
            repo_id=repo_id,
            client_uid=client_uid,
            snapshot_id=enrollment_snapshot_id,
        )
        if enrollment_snapshot_id is not None
        else {}
    )
    grant_snapshot_id: str | None = None
    if observe_host is not None:
        with AccountStore.open(database_path, expected_uid=service_uid) as grant_store:
            grant_host_id = persistence.repository_host_id(repo_id)
            grant_snapshot_id = _capture_new_enrollment_observation(
                grant_store,
                host_id=grant_host_id,
                observe_host=observe_host,
            )
        _grant_observed_databases(
            persistence,
            repo_id=repo_id,
            client_uid=client_uid,
            snapshot_id=grant_snapshot_id,
        )
        _grant_observed_lifecycle_resources(
            persistence,
            repo_id=repo_id,
            client_uid=client_uid,
            snapshot_id=grant_snapshot_id,
        )
        if grant_cleanup_capabilities:
            _grant_observed_cleanup_resources(
                persistence,
                repo_id=repo_id,
                client_uid=client_uid,
                snapshot_id=grant_snapshot_id,
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
    compose_definition_id = _provision_compose(
        persistence,
        repo_id=repo_id,
        client_uid=client_uid,
        root=root,
        compose=compose,
        observation_snapshot_id=enrollment_snapshot_id,
        host_access_approved=approve_compose_host_access,
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
            "mode": "0660",
            "database_generation": database_generation,
        },
        client_uid=client_uid,
        account_id=account_id,
        repository={
            "canonical_root": str(root),
            "repo_id": repo_id,
            "generation": repository_generation,
            "servers": granted_server_ids,
            "containers": container_ids,
            "compose_definition_id": compose_definition_id,
        },
        issued_at=issued_at,
        valid_until_epoch=valid_until_epoch,
    )
    return {
        "status": "enrolled",
        "client_uid": client_uid,
        "account_id": account_id,
        "repo_id": repo_id,
        "server_ids": granted_server_ids,
        "defined_server_ids": server_ids,
        "container_ids": container_ids,
        "compose_definition_id": compose_definition_id,
        "enrollment_snapshot_id": enrollment_snapshot_id,
        "grant_snapshot_id": grant_snapshot_id,
        "database_generation": database_generation,
        "profile_path": str(profile_path),
        "valid_until_epoch": valid_until_epoch,
        "starts_resources": False,
        "cleanup_capabilities": bool(grant_cleanup_capabilities),
        "observation_snapshot_id": enrollment_snapshot_id,
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


def _grant_observed_containers(
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    client_uid: int,
    snapshot_id: str,
) -> dict[str, str]:
    result: dict[str, str] = {}
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
                           d.full_container_id, d.current_name
                    FROM broker_observed_compose_containers observed
                    JOIN docker_resources d
                      ON d.docker_resource_id = observed.docker_resource_id
                    WHERE observed.snapshot_id = ?
                      AND observed.authoritative_owner_repo_id = ?
                    ORDER BY d.current_name, d.full_container_id
                    """,
                    (snapshot_id, repo_id),
                )
            )
            compose_scope = connection.execute(
                "SELECT 1 FROM broker_observation_compose_scope WHERE snapshot_id = ?",
                (snapshot_id,),
            ).fetchone()
            if not rows and compose_scope is None:
                # Compatibility for canonical full-Docker snapshots recorded
                # before exhaustive Compose-scope evidence existed. Never use
                # this path for a new Compose-scoped snapshot: those must carry
                # the stronger per-container ownership and full-ID proof above.
                rows = list(
                    connection.execute(
                        """
                        SELECT d.docker_resource_id,
                               d.full_container_id AS observed_full_container_id,
                               'exclusive' AS ownership_state,
                               membership.repo_id AS authoritative_owner_repo_id,
                               d.full_container_id, d.current_name
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
                        ORDER BY d.current_name, d.full_container_id
                        """,
                        (snapshot_id, repo_id),
                    )
                )
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
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    client_uid: int,
    snapshot_id: str,
) -> None:
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
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    client_uid: int,
    snapshot_id: str,
) -> None:
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


def _grant_observed_cleanup_resources(
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    client_uid: int,
    snapshot_id: str,
) -> None:
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
                    FROM observation_snapshot_resources
                    WHERE snapshot_id = ?
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
    for exact in exact_resources:
        for operation in (
            BrokerOperation.CLEANUP_PLAN,
            BrokerOperation.CLEANUP_APPLY,
            BrokerOperation.RESOURCE_PLAN_ARCHIVE,
            BrokerOperation.RESOURCE_ARCHIVE,
            BrokerOperation.RESOURCE_RESTORE,
        ):
            persistence.grant_cleanup_resource(
                uid=client_uid,
                repo_id=repo_id,
                resource_kind=exact.kind.value,
                resource_id=exact.resource_id,
                control_binding_id=exact.control_binding_id,
                immutable_fingerprint=exact.immutable_fingerprint,
                ownership_fingerprint=exact.ownership_fingerprint,
                operation=operation,
            )


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


def _provision_compose(
    persistence: BrokerPersistence,
    *,
    repo_id: str,
    client_uid: int,
    root: Path,
    compose: Mapping[str, Any] | None,
    observation_snapshot_id: str | None = None,
    host_access_approved: bool = False,
) -> str | None:
    if not compose or not compose.get("declared"):
        persistence.disable_repository_compose(repo_id=repo_id)
        return None
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
    return compose_id


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
        metadata = path.stat()
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("Compose environment file grants group or other access")
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
        declared_services=services,
        project_name=project_name,
        pinned_cwd=str(root),
    )
    require_effective_compose_model(
        rendered,
        declared_services=services,
        declared_profiles=profiles,
        project_name=project_name,
        host_access_approved=host_access_approved,
    )


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
                or metadata.st_uid != 0
                or stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                raise PermissionError(
                    "existing broker profile is not a protected root-owned file"
                )
            document = json.loads(path.read_text(encoding="utf-8"))
            if (
                document.get("version") != PROFILE_VERSION
                or document.get("service") != service
            ):
                raise RuntimeError(
                    "existing broker profile belongs to another service authority"
                )
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
        current_issued_at = str(current.get("issued_at") or issued_at)
        current_expiry = current.get("valid_until_epoch")
        legacy_expiry = (
            int(current_expiry)
            if type(current_expiry) is int and current_expiry > 0
            else valid_until_epoch
        )
        repositories: list[dict[str, Any]] = []
        current_repositories = current.get("repositories", [])
        if not isinstance(current_repositories, list):
            raise RuntimeError(
                "existing broker profile has an invalid repository enrollment list"
            )
        for item in current_repositories:
            if not isinstance(item, dict):
                raise RuntimeError(
                    "existing broker profile has an invalid repository enrollment"
                )
            if item.get("canonical_root") == repository["canonical_root"]:
                continue
            preserved = dict(item)
            preserved.setdefault("account_id", account_id)
            if str(preserved["account_id"]) != account_id:
                raise RuntimeError(
                    "protected repository profile belongs to a different account"
                )
            preserved.setdefault("enabled", True)
            preserved.setdefault("issued_at", current_issued_at)
            preserved.setdefault("valid_until_epoch", legacy_expiry)
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
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
            or (metadata.st_dev, metadata.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise PermissionError(
                "broker profile lock is not a protected root-owned regular file"
            )
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
    if os.geteuid() != 0:
        raise PermissionError("broker profile installation requires root")
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
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise PermissionError(
                "every broker profile directory ancestor must be protected and root-owned"
            )
    os.chown(path, 0, access_gid)
    os.chmod(path, 0o750)


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
    descriptor = os.open(temporary, flags, 0o640)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, 0, access_gid)
        os.chmod(temporary, 0o640)
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
) -> str:
    """Capture evidence created strictly after the enrollment boundary.

    A host observer may single-flight onto a ticket that was already running
    when enrollment began.  Let that ticket finish, then fence and observe once
    more so authority is never derived from pre-boundary state.
    """

    for attempt in range(2):
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
            return _require_exact_enrollment_observation(
                store,
                evidence=evidence,
                fence=fence,
            )
        except RuntimeError:
            if attempt == 0 and joined_pre_boundary_ticket:
                continue
            raise
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
