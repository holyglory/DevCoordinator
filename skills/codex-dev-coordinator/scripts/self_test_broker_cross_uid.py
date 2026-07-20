#!/usr/bin/env python3
"""Linux acceptance test for the real cross-UID broker boundary.

This suite deliberately requires a root parent so it can run one broker owned
by UID 0 and connect through the same Unix socket from three distinct numeric
UIDs.  The children drop supplementary groups, GID, and UID before creating
their clients; broker authorization therefore observes real Linux
``SO_PEERCRED`` data rather than test-injected credentials.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import socket
import stat
import struct
import sys
import threading
import time
import unittest
import uuid
from typing import Any, Mapping


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

from devcoordinator.broker import (  # noqa: E402
    BrokerClient,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
)
from devcoordinator.broker_backend import build_store_backed_broker_runtime  # noqa: E402
from devcoordinator.broker_enrollment import (  # noqa: E402
    _merge_profile,
    enroll_repository,
)
from devcoordinator.broker_host import LocalBrokerHostMutations  # noqa: E402
from devcoordinator.broker_persistence import BrokerPersistence  # noqa: E402
from devcoordinator.repository_lifecycle import (  # noqa: E402
    PolicyObservation,
    ResourceKind,
    ResourceObservation,
    RunningState,
)
from devcoordinator.sqlite_lifecycle import SQLiteLifecyclePersistence  # noqa: E402
from devcoordinator.store import AccountStore, CoordinatorStore, utc_timestamp  # noqa: E402

import dev_coordinator  # noqa: E402


SERVICE_UID = 0
ACCESS_GID = 62000
FIRST_UID = 62001
SECOND_UID = 62002
UNKNOWN_UID = 62003
HOST_ID = "cross-uid-host"
REPO_ID = "cross-uid-repo"
FIRST_SERVER_ID = "cross-uid-server-a"
SECOND_SERVER_ID = "cross-uid-server-b"
FIRST_ACCOUNT_ID = "cross-uid-account-a"
SECOND_ACCOUNT_ID = "cross-uid-account-b"
UNKNOWN_ACCOUNT_ID = "cross-uid-account-unknown"
SOURCE_ID = "cross-uid-source"
ENGINE_ID = "cross-uid-engine"
MAIN_CONTAINER_ID = "cross-uid-container-main"


def _rendered_compose_fixture(**arguments: object) -> bytes:
    services = tuple(str(item) for item in arguments["declared_services"])
    profiles = tuple(str(item) for item in arguments["profiles"])
    model = {name: {"image": f"example.invalid/{name}:test"} for name in services}
    if profiles:
        model[services[0]]["profiles"] = list(profiles)
    return json.dumps({"services": model}).encode("utf-8")


ORPHAN_CONTAINER_ID = "cross-uid-container-orphan"
MAIN_CONTROL_ID = "cross-uid-control-main"
ORPHAN_CONTROL_ID = "cross-uid-control-orphan"
MAIN_FULL_ID = "a" * 64
ORPHAN_FULL_ID = "b" * 64
OBSERVER_DOMAIN = "host-runtime-v2:full-docker"


def _free_tcp_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])
    finally:
        probe.close()


def _seed_service_database(database_path: Path, port: int) -> BrokerPersistence:
    persistence = BrokerPersistence(database_path, expected_uid=SERVICE_UID)
    now = utc_timestamp()
    with CoordinatorStore.open(database_path, expected_uid=SERVICE_UID) as store:
        with store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO hosts(
                    host_id, machine_fingerprint, platform, hostname,
                    created_at, updated_at
                ) VALUES (?, 'cross-uid-machine', 'linux', 'ci-host', ?, ?)
                """,
                (HOST_ID, now, now),
            )
            connection.execute(
                """
                INSERT INTO repositories(
                    repo_id, host_id, canonical_root, display_name, state,
                    generation, created_at, updated_at
                ) VALUES (?, ?, '/srv/cross-uid-repo', 'Cross UID',
                          'active', 0, ?, ?)
                """,
                (REPO_ID, HOST_ID, now, now),
            )
            connection.execute(
                """
                INSERT INTO repository_installations(
                    repo_id, status, startup_fenced, generation, actor, updated_at
                ) VALUES (?, 'installed', 0, 0, 'cross-uid-fixture', ?)
                """,
                (REPO_ID, now),
            )
            for server_id, name in (
                (FIRST_SERVER_ID, "server-a"),
                (SECOND_SERVER_ID, "server-b"),
            ):
                connection.execute(
                    """
                    INSERT INTO server_definitions(
                        server_definition_id, repo_id, name, cwd,
                        definition_fingerprint, generation, created_at, updated_at
                    ) VALUES (?, ?, ?, '/srv/cross-uid-repo', ?, 0, ?, ?)
                    """,
                    (server_id, REPO_ID, name, "definition-" + server_id, now, now),
                )

    for uid, account_id, server_id in (
        (FIRST_UID, FIRST_ACCOUNT_ID, FIRST_SERVER_ID),
        (SECOND_UID, SECOND_ACCOUNT_ID, SECOND_SERVER_ID),
    ):
        persistence.provision_principal(uid=uid, account_id=account_id)
        persistence.provision_repository_enrollment(
            uid=uid,
            repo_id=REPO_ID,
            account_id=account_id,
            issued_at=utc_timestamp(),
            valid_until_epoch=int(time.time()) + 3_600,
        )
        persistence.grant_resource(
            uid=uid,
            repo_id=REPO_ID,
            resource_kind="server",
            resource_id=server_id,
            operation=BrokerOperation.PORT_LEASE,
        )
        persistence.grant_port_range(
            uid=uid,
            repo_id=REPO_ID,
            server_definition_id=server_id,
            start_port=port,
            end_port=port,
            protocol="tcp",
            max_ttl_seconds=60,
        )
    return persistence


def _database_generation(database_path: Path) -> str:
    with CoordinatorStore.open(database_path, expected_uid=SERVICE_UID) as store:
        return store.metadata.database_generation


def _write_framed_result(file_descriptor: int, document: dict[str, object]) -> None:
    payload = json.dumps(document, sort_keys=True).encode("utf-8")
    os.write(file_descriptor, struct.pack("!I", len(payload)) + payload)


def _read_exact(file_descriptor: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(file_descriptor, remaining)
        if not chunk:
            raise RuntimeError("cross-UID child closed its result pipe early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_framed_result(file_descriptor: int) -> dict[str, object]:
    size = struct.unpack("!I", _read_exact(file_descriptor, 4))[0]
    if not 1 <= size <= 64 * 1024:
        raise RuntimeError("cross-UID child returned an invalid result size")
    document = json.loads(_read_exact(file_descriptor, size))
    if not isinstance(document, dict):
        raise RuntimeError("cross-UID child returned a non-object result")
    return document


def _spawn_client(
    *,
    socket_path: Path,
    uid: int,
    account_id: str,
    server_id: str,
    port: int,
    database_generation: str,
) -> tuple[int, int, int]:
    start_read, start_write = os.pipe()
    result_read, result_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(start_write)
            os.close(result_read)
            if _read_exact(start_read, 1) != b"1":
                raise RuntimeError("parent did not release the broker client")
            os.setgroups([ACCESS_GID])
            os.setgid(ACCESS_GID)
            os.setuid(uid)
            if os.geteuid() != uid or os.getegid() != ACCESS_GID:
                raise RuntimeError("credential drop did not take effect")
            request = BrokerRequest.create(
                account_id=account_id,
                project_id=REPO_ID,
                resource_id=server_id,
                operation=BrokerOperation.PORT_LEASE,
                arguments={
                    "requested_port": port,
                    "protocol": "tcp",
                    "ttl_seconds": 60,
                },
                authority_generation=database_generation,
            )
            client = BrokerClient(
                socket_path,
                expected_broker_uid=SERVICE_UID,
                expected_socket_gid=ACCESS_GID,
                expected_socket_mode=0o660,
            )
            try:
                reply = client.call(request)
                if not bool(reply.get("ok")):
                    error_payload = reply.get("error")
                    if not isinstance(error_payload, dict):
                        raise RuntimeError("broker returned an invalid failure payload")
                    document = {
                        "status": "broker_error",
                        "code": str(error_payload.get("code") or "invalid_reply"),
                        "uid": os.geteuid(),
                    }
                else:
                    result = reply.get("result")
                    if not isinstance(result, dict):
                        raise RuntimeError("broker returned an invalid success payload")
                    document = {
                        "status": "success",
                        "uid": os.geteuid(),
                        "result": result,
                    }
            except BrokerError as error:
                document: dict[str, object] = {
                    "status": "broker_error",
                    "code": error.code,
                    "uid": os.geteuid(),
                }
            _write_framed_result(result_write, document)
            os._exit(0)
        except BaseException as error:
            try:
                _write_framed_result(
                    result_write,
                    {
                        "status": "child_failure",
                        "type": type(error).__name__,
                        "message": str(error),
                    },
                )
            finally:
                os._exit(97)
    os.close(start_read)
    os.close(result_write)
    return pid, start_write, result_read


class CrossUIDRuntimeFixture:
    """Service-owned runtime truth shared by typed actions and observation."""

    def __init__(self) -> None:
        self.running = {
            MAIN_CONTAINER_ID: False,
            ORPHAN_CONTAINER_ID: True,
        }
        self.restart_policy = {
            MAIN_CONTAINER_ID: "always",
            ORPHAN_CONTAINER_ID: "always",
        }
        self.host_calls: list[tuple[str, str]] = []
        self.lifecycle_calls: list[tuple[str, str]] = []

    def observe(self, store: AccountStore) -> Mapping[str, Any]:
        """Commit one full-Docker snapshot and the fixture's exact resources."""

        if not isinstance(store, CoordinatorStore):
            raise RuntimeError(
                "service observation requires the normalized CoordinatorStore adapter"
            )
        if store.database_path != store.path:
            raise RuntimeError(
                "enrollment observation requires one canonical database path"
            )

        now = utc_timestamp()
        snapshot_id = "cross-uid-snapshot-" + uuid.uuid4().hex
        material_fingerprint = "3" * 64
        capability_fingerprint = "sha256:" + "4" * 64
        with store.immediate_transaction(revision_kind="observation") as connection:
            host = connection.execute(
                "SELECT host_id FROM hosts ORDER BY host_id LIMIT 1"
            ).fetchone()
            repository = connection.execute(
                "SELECT repo_id FROM repositories ORDER BY repo_id LIMIT 1"
            ).fetchone()
            if host is None or repository is None:
                raise RuntimeError(
                    "cross-UID observation lacks host/repository authority"
                )
            host_id = str(host["host_id"])
            repo_id = str(repository["repo_id"])
            connection.execute(
                """
                INSERT OR IGNORE INTO coordinator_sources(
                    source_id, host_id, canonical_home, state_path,
                    effective_uid, status, created_at, updated_at
                ) VALUES (?, ?, '/service/cross-uid',
                          '/service/cross-uid/coordinator.sqlite3', ?,
                          'imported', ?, ?)
                """,
                (SOURCE_ID, host_id, FIRST_UID, now, now),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO docker_engines(
                    engine_id, host_id, context_identity, daemon_identity,
                    capability_state, created_at, updated_at
                ) VALUES (?, ?, 'default', 'cross-uid-daemon',
                          'available', ?, ?)
                """,
                (ENGINE_ID, host_id, now, now),
            )
            for resource_id, full_id, name in (
                (MAIN_CONTAINER_ID, MAIN_FULL_ID, "cross-uid-main"),
                (ORPHAN_CONTAINER_ID, ORPHAN_FULL_ID, "cross-uid-orphan"),
            ):
                connection.execute(
                    """
                    INSERT OR IGNORE INTO docker_resources(
                        docker_resource_id, engine_id, full_container_id,
                        current_name, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (resource_id, ENGINE_ID, full_id, name, now, now),
                )
                lifecycle = "running" if self.running[resource_id] else "stopped"
                connection.execute(
                    """
                    INSERT INTO docker_observations(
                        docker_resource_id, lifecycle, restart_policy,
                        sampled_at, observation_fingerprint
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(docker_resource_id) DO UPDATE SET
                        lifecycle = excluded.lifecycle,
                        restart_policy = excluded.restart_policy,
                        sampled_at = excluded.sampled_at,
                        observation_fingerprint = excluded.observation_fingerprint
                    """,
                    (
                        resource_id,
                        lifecycle,
                        self.restart_policy[resource_id],
                        now,
                        f"cross-uid-{resource_id}-{lifecycle}",
                    ),
                )
            connection.execute(
                """
                INSERT OR IGNORE INTO control_bindings(
                    binding_id, repo_id, resource_kind, resource_id, source_id,
                    capability, provenance, authority_state, priority,
                    generation, created_at, updated_at
                ) VALUES (?, ?, 'container', ?, ?, 'lifecycle',
                          'cross-uid-fixture', 'authoritative', 100, 0, ?, ?)
                """,
                (MAIN_CONTROL_ID, repo_id, MAIN_CONTAINER_ID, SOURCE_ID, now, now),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO control_bindings(
                    binding_id, repo_id, resource_kind, resource_id, source_id,
                    capability, provenance, authority_state, priority,
                    generation, created_at, updated_at
                ) VALUES (?, NULL, 'container', ?, ?, 'lifecycle',
                          'cross-uid-fixture', 'authoritative', 100, 0, ?, ?)
                """,
                (ORPHAN_CONTROL_ID, ORPHAN_CONTAINER_ID, SOURCE_ID, now, now),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO repository_memberships(
                    membership_id, repo_id, resource_kind, host_resource_id,
                    immutable_fingerprint, control_binding_id, created_at
                ) VALUES ('cross-uid-membership-main', ?, 'container', ?,
                          ?, ?, ?)
                """,
                (
                    repo_id,
                    MAIN_CONTAINER_ID,
                    "sha256:" + "7" * 64,
                    MAIN_CONTROL_ID,
                    now,
                ),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO unassigned_resources(
                    unassigned_id, host_id, resource_kind, resource_id,
                    display_name, reason_code, status, created_at, updated_at
                ) VALUES ('cross-uid-unassigned-orphan', ?, 'container', ?,
                          'cross-uid-orphan', 'name_only', 'active', ?, ?)
                """,
                (host_id, ORPHAN_CONTAINER_ID, now, now),
            )
            for resource_id, repo_value, policy_id in (
                (MAIN_CONTAINER_ID, repo_id, "cross-uid-policy-main"),
                (ORPHAN_CONTAINER_ID, None, "cross-uid-policy-orphan"),
            ):
                connection.execute(
                    """
                    INSERT OR IGNORE INTO startup_policies(
                        policy_id, repo_id, resource_kind, resource_id,
                        policy_kind, current_value, desired_disabled_value,
                        immutable_fingerprint, generation, updated_at
                    ) VALUES (?, ?, 'container', ?, 'docker_restart',
                              'always', 'no', ?, 0, ?)
                    """,
                    (
                        policy_id,
                        repo_value,
                        resource_id,
                        "sha256:"
                        + ("5" if resource_id == MAIN_CONTAINER_ID else "6") * 64,
                        now,
                    ),
                )
            connection.execute(
                """
                INSERT INTO observation_snapshots(
                    snapshot_id, host_id, observer_domain, status,
                    material_fingerprint, started_at, completed_at
                ) VALUES (?, ?, ?, 'completed', ?, ?, ?)
                """,
                (
                    snapshot_id,
                    host_id,
                    OBSERVER_DOMAIN,
                    material_fingerprint,
                    now,
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO observation_capabilities(
                    snapshot_id, observer_domain, docker_available,
                    capability_fingerprint, committed_at
                ) VALUES (?, ?, 1, ?, ?)
                """,
                (
                    snapshot_id,
                    OBSERVER_DOMAIN,
                    capability_fingerprint,
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO broker_observation_compose_scope(
                    snapshot_id, assets_complete, observed_asset_count,
                    evidence_fingerprint, recorded_at
                ) VALUES (?, 1, 0, 'cross-uid-compose-scope', ?)
                """,
                (snapshot_id, now),
            )
            for resource_id in (MAIN_CONTAINER_ID, ORPHAN_CONTAINER_ID):
                lifecycle = "running" if self.running[resource_id] else "stopped"
                connection.execute(
                    """
                    INSERT INTO observation_snapshot_resources(
                        snapshot_id, resource_kind, resource_id,
                        observation_fingerprint
                    ) VALUES (?, 'container', ?, ?)
                    """,
                    (
                        snapshot_id,
                        resource_id,
                        f"cross-uid-{resource_id}-{lifecycle}",
                    ),
                )
            main_lifecycle = "running" if self.running[MAIN_CONTAINER_ID] else "stopped"
            connection.execute(
                """
                INSERT INTO broker_observed_compose_containers(
                    snapshot_id, docker_resource_id, full_container_id,
                    project_name, service_name, lifecycle, ownership_state,
                    authoritative_owner_repo_id, observation_fingerprint
                ) VALUES (?, ?, ?, 'crossuid', 'app', ?, 'exclusive', ?, ?)
                """,
                (
                    snapshot_id,
                    MAIN_CONTAINER_ID,
                    MAIN_FULL_ID,
                    main_lifecycle,
                    repo_id,
                    "sha256:" + "7" * 64,
                ),
            )
        return {
            "snapshot_id": snapshot_id,
            "host_id": host_id,
            "observer_domain": OBSERVER_DOMAIN,
            "joined": False,
            "docker_available": True,
            "capability_fingerprint": capability_fingerprint,
            "material_fingerprint": material_fingerprint,
            "completed_at": now,
        }

    def select_available_port(
        self, *, candidates: tuple[int, ...], protocol: str
    ) -> int | None:
        if protocol != "tcp":
            raise RuntimeError("cross-UID fixture received a non-TCP port request")
        return candidates[0] if candidates else None

    def verify_owned_tcp_listener(
        self, *, port: int, canonical_root: str
    ) -> Mapping[str, Any]:
        raise BrokerError(
            "listener_identity_unavailable",
            f"cross-UID fixture has no adopted listener on {port} for {canonical_root}",
        )

    def docker_start(self, target: Any) -> Mapping[str, Any]:
        self.running[target.docker_resource_id] = True
        self.host_calls.append(("docker.start", target.docker_resource_id))
        return {"status": "started", "resource_id": target.docker_resource_id}

    def docker_stop(self, target: Any) -> Mapping[str, Any]:
        self.running[target.docker_resource_id] = False
        self.host_calls.append(("docker.stop", target.docker_resource_id))
        return {"status": "stopped", "resource_id": target.docker_resource_id}

    def docker_restart(self, target: Any) -> Mapping[str, Any]:
        self.running[target.docker_resource_id] = True
        self.host_calls.append(("docker.restart", target.docker_resource_id))
        return {"status": "restarted", "resource_id": target.docker_resource_id}

    def compose_up(self, target: Any) -> Mapping[str, Any]:
        self.host_calls.append(("compose.up", target.compose_definition_id))
        return {
            "status": "started",
            "compose_definition_id": target.compose_definition_id,
        }

    def compose_stop(self, target: Any) -> Mapping[str, Any]:
        self.host_calls.append(("compose.stop", target.compose_definition_id))
        return {
            "status": "stopped",
            "compose_definition_id": target.compose_definition_id,
        }

    def compose_restart(self, target: Any) -> Mapping[str, Any]:
        self.host_calls.append(("compose.restart", target.compose_definition_id))
        return {
            "status": "restarted",
            "compose_definition_id": target.compose_definition_id,
        }

    def compose_down(self, target: Any) -> Mapping[str, Any]:
        self.host_calls.append(("compose.down", target.compose_definition_id))
        return {
            "status": "stopped",
            "compose_definition_id": target.compose_definition_id,
        }

    def postgres_backup(self, target: Any, *, output_root: str) -> Mapping[str, Any]:
        del target, output_root
        raise AssertionError(
            "cross-UID public routing unexpectedly requested PostgreSQL backup"
        )

    def postgres_restore(
        self, target: Any, backup: Any, *, safety_output_root: str
    ) -> Mapping[str, Any]:
        del target, backup, safety_output_root
        raise AssertionError(
            "cross-UID public routing unexpectedly requested PostgreSQL restore"
        )

    def observe_exact(self, target: Any) -> ResourceObservation:
        running = bool(self.running[target.resource_id])
        policies = {
            policy.policy_id: PolicyObservation(
                policy_id=policy.policy_id,
                immutable_fingerprint=policy.immutable_fingerprint,
                observable=True,
                disabled=self.restart_policy[target.resource_id]
                == policy.disabled_value,
                value=self.restart_policy[target.resource_id],
                docker_restart_policy=self.restart_policy[target.resource_id],
            )
            for policy in target.policies
        }
        return ResourceObservation(
            resource_id=target.resource_id,
            kind=target.kind,
            identity_observable=True,
            immutable_fingerprint=target.immutable_fingerprint,
            ownership_observable=True,
            ownership_fingerprint=target.ownership_fingerprint,
            running_state=RunningState.RUNNING if running else RunningState.STOPPED,
            container_running=running,
            policies=policies,
        )

    def disable_startup_policy(self, target: Any, policy: Any) -> Mapping[str, Any]:
        self.restart_policy[target.resource_id] = policy.disabled_value
        self.lifecycle_calls.append(("disable_policy", target.resource_id))
        return {"status": "disabled", "policy_id": policy.policy_id}

    def stop_exact(self, target: Any) -> Mapping[str, Any]:
        self.running[target.resource_id] = False
        self.lifecycle_calls.append(("stop", target.resource_id))
        return {"status": "stopped", "resource_id": target.resource_id}


def _initialize_cross_uid_account_store(account_home: Path) -> None:
    """Create a migration-ready account store without relying on passwd(5)."""

    with AccountStore.open_default(account_home) as store:
        store.ensure_local_host()
        now = utc_timestamp()
        with store.immediate_transaction() as connection:
            connection.execute(
                """
                UPDATE schema_metadata
                SET authority_mode = 'sqlite', migration_state = 'ready',
                    first_sqlite_mutation_at = COALESCE(first_sqlite_mutation_at, ?),
                    updated_at = ?
                WHERE singleton = 1
                """,
                (now, now),
            )


def _seed_local_retirement_mirror(
    account_home: Path,
    *,
    repo_id: str,
    exact: Mapping[str, str],
) -> None:
    """Materialize the exact pre-retirement client projection for reconciliation."""

    now = utc_timestamp()
    with AccountStore.open_default(account_home) as store:
        with store.read_transaction() as connection:
            host_id = str(
                connection.execute(
                    "SELECT host_id FROM hosts ORDER BY host_id LIMIT 1"
                ).fetchone()[0]
            )
        with store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO coordinator_sources(
                    source_id, host_id, canonical_home, state_path,
                    effective_uid, status, created_at, updated_at
                ) VALUES (?, ?, '/client/cross-uid',
                          '/client/cross-uid/coordinator.sqlite3', ?,
                          'imported', ?, ?)
                """,
                (SOURCE_ID, host_id, FIRST_UID, now, now),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO docker_engines(
                    engine_id, host_id, context_identity, daemon_identity,
                    capability_state, created_at, updated_at
                ) VALUES (?, ?, 'default', 'cross-uid-daemon',
                          'available', ?, ?)
                """,
                (ENGINE_ID, host_id, now, now),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO docker_resources(
                    docker_resource_id, engine_id, full_container_id,
                    current_name, created_at, updated_at
                ) VALUES (?, ?, ?, 'cross-uid-orphan', ?, ?)
                """,
                (ORPHAN_CONTAINER_ID, ENGINE_ID, ORPHAN_FULL_ID, now, now),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO docker_observations(
                    docker_resource_id, lifecycle, restart_policy, sampled_at,
                    observation_fingerprint
                ) VALUES (?, 'stopped', 'no', ?, 'cross-uid-client-mirror')
                """,
                (ORPHAN_CONTAINER_ID, now),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO control_bindings(
                    binding_id, repo_id, resource_kind, resource_id, source_id,
                    capability, provenance, authority_state, priority,
                    generation, created_at, updated_at
                ) VALUES (?, NULL, 'container', ?, ?, 'lifecycle',
                          'cross-uid-fixture', 'authoritative', 100, 0, ?, ?)
                """,
                (ORPHAN_CONTROL_ID, ORPHAN_CONTAINER_ID, SOURCE_ID, now, now),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO unassigned_resources(
                    unassigned_id, host_id, resource_kind, resource_id,
                    display_name, reason_code, status, created_at, updated_at
                ) VALUES ('cross-uid-unassigned-orphan', ?, 'container', ?,
                          'cross-uid-orphan', 'name_only', 'active', ?, ?)
                """,
                (host_id, ORPHAN_CONTAINER_ID, now, now),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO startup_policies(
                    policy_id, repo_id, resource_kind, resource_id, policy_kind,
                    current_value, desired_disabled_value, immutable_fingerprint,
                    generation, updated_at
                ) VALUES ('cross-uid-policy-orphan', NULL, 'container', ?,
                          'docker_restart', 'always', 'no', ?, 0, ?)
                """,
                (ORPHAN_CONTAINER_ID, "sha256:" + "6" * 64, now),
            )
        resolved = SQLiteLifecyclePersistence(store).resolve_standalone_resource(
            ResourceKind.CONTAINER,
            ORPHAN_CONTAINER_ID,
            ORPHAN_CONTROL_ID,
        )
        if (
            resolved.immutable_fingerprint != exact["immutable_fingerprint"]
            or resolved.ownership_fingerprint != exact["ownership_fingerprint"]
        ):
            raise RuntimeError(
                "client lifecycle mirror identity differs from service authority"
            )
        with store.read_transaction() as connection:
            repository = connection.execute(
                "SELECT repo_id FROM repositories WHERE repo_id = ?", (repo_id,)
            ).fetchone()
        if repository is None:
            raise RuntimeError("client lifecycle mirror lacks the enrolled repository")


def _run_public_cli(arguments: list[str]) -> Any:
    return dev_coordinator.handle_cli(
        dev_coordinator.build_parser().parse_args(arguments)
    )


def _spawn_public_journey(
    *,
    socket_path: Path,
    profile_path: Path,
    project_root: Path,
    account_home: Path,
    poison_directory: Path,
    poison_sentinel: Path,
    port: int,
    repo_id: str,
    exact: Mapping[str, str],
) -> tuple[int, int, int]:
    start_read, start_write = os.pipe()
    result_read, result_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(start_write)
            os.close(result_read)
            if _read_exact(start_read, 1) != b"1":
                raise RuntimeError("parent did not release the public broker journey")
            os.setgroups([ACCESS_GID])
            os.setgid(ACCESS_GID)
            os.setuid(FIRST_UID)
            os.environ.update(
                {
                    "CODEX_AGENT_COORDINATOR_HOME": str(account_home),
                    "DEVCOORDINATOR_AUTHORITY": "system",
                    "DEVCOORDINATOR_BROKER_PROFILE": str(profile_path),
                    "DEVCOORDINATOR_STATE_BACKEND": "sqlite",
                    "DEVCOORDINATOR_DOCKER_POISON_SENTINEL": str(poison_sentinel),
                    "PATH": f"{poison_directory}:/usr/bin:/bin",
                }
            )
            _initialize_cross_uid_account_store(account_home)
            client_database = account_home / "coordinator.sqlite3"
            client_store_before_observe = client_database.read_bytes()
            observed = _run_public_cli(
                [
                    "observe",
                    "--agent",
                    "cross-uid-client",
                    "--project",
                    str(project_root),
                ]
            )
            observed_inventory = _run_public_cli(
                ["inventory", "--project", str(project_root)]
            )
            client_store_after_observe = client_database.read_bytes()
            leased = _run_public_cli(
                [
                    "port",
                    "lease",
                    "--agent",
                    "cross-uid-client",
                    "--project",
                    str(project_root),
                    "--name",
                    "server-a",
                    "--preferred",
                    str(port),
                ]
            )
            docker = _run_public_cli(
                [
                    "docker",
                    "start",
                    "--container",
                    "cross-uid-main",
                    "--agent",
                    "cross-uid-client",
                    "--project",
                    str(project_root),
                ]
            )
            compose = _run_public_cli(
                [
                    "docker",
                    "compose-up",
                    "--cwd",
                    str(project_root),
                    "--agent",
                    "cross-uid-client",
                    "--project",
                    str(project_root),
                    "--detach",
                ]
            )
            broker_profile = dev_coordinator.load_broker_profile(required=True)
            if broker_profile is None:
                raise RuntimeError("required cross-UID broker profile was not loaded")
            broker_repository = broker_profile.repository(str(project_root))
            compose_lifecycle = [compose]
            for action in ("stop", "restart", "down"):
                compose_lifecycle.append(
                    dev_coordinator.coordinated_broker_compose_command(
                        profile=broker_profile,
                        repository=broker_repository,
                        command=["docker", "compose", action],
                        cwd=str(project_root),
                        project=str(project_root),
                        agent="cross-uid-client",
                    )
                )
            identity_arguments = [
                "--resource-kind",
                exact["resource_kind"],
                "--resource-id",
                ORPHAN_CONTAINER_ID,
                "--immutable-fingerprint",
                exact["immutable_fingerprint"],
                "--control-binding-id",
                ORPHAN_CONTROL_ID,
                "--ownership-fingerprint",
                exact["ownership_fingerprint"],
                "--request-project",
                str(project_root),
                "--agent",
                "cross-uid-client",
            ]
            retirement_plan = _run_public_cli(
                [
                    "resource",
                    "plan-retire",
                    *identity_arguments,
                    "--reason",
                    "cross-UID orphan retirement",
                ]
            )
            mirror_failure = None
            try:
                _run_public_cli(
                    [
                        "resource",
                        "retire",
                        *identity_arguments,
                        "--plan-id",
                        str(retirement_plan["plan_id"]),
                        "--plan-fingerprint",
                        str(retirement_plan["fingerprint"]),
                    ]
                )
            except RuntimeError as error:
                mirror_failure = str(error)
            if not mirror_failure or "requires reconciliation" not in mirror_failure:
                raise RuntimeError(
                    "completed service retirement did not expose the expected local mirror gap"
                )
            _seed_local_retirement_mirror(
                account_home,
                repo_id=repo_id,
                exact=exact,
            )
            reconciled = _run_public_cli(
                [
                    "broker",
                    "reconcile-links",
                    "--coordinator-home",
                    str(account_home),
                ]
            )
            removal_plan = _run_public_cli(
                [
                    "repository",
                    "plan-remove",
                    "--project",
                    str(project_root),
                    "--agent",
                    "cross-uid-client",
                    "--reason",
                    "cross-UID repository removal",
                ]
            )
            removed = _run_public_cli(
                [
                    "repository",
                    "remove",
                    "--project",
                    str(project_root),
                    "--agent",
                    "cross-uid-client",
                    "--plan-id",
                    str(removal_plan["plan_id"]),
                    "--plan-fingerprint",
                    str(removal_plan["fingerprint"]),
                ]
            )
            removed_rows = _run_public_cli(["repository", "list-removed"])
            final_reconcile = _run_public_cli(
                [
                    "broker",
                    "reconcile-links",
                    "--coordinator-home",
                    str(account_home),
                ]
            )
            with CoordinatorStore.open(
                account_home / "coordinator.sqlite3", expected_uid=FIRST_UID
            ) as store:
                with store.read_transaction() as connection:
                    local_installation = connection.execute(
                        """
                        SELECT status, startup_fenced
                        FROM repository_installations WHERE repo_id = ?
                        """,
                        (repo_id,),
                    ).fetchone()
                    local_retirement = connection.execute(
                        """
                        SELECT status FROM resource_retirements
                        WHERE host_resource_id = ?
                        """,
                        (ORPHAN_CONTAINER_ID,),
                    ).fetchone()
                    lifecycle_links = list(
                        connection.execute(
                            """
                            SELECT operation, status FROM broker_lifecycle_links
                            ORDER BY operation
                            """
                        )
                    )
            _write_framed_result(
                result_write,
                {
                    "status": "success",
                    "uid": os.geteuid(),
                    "observe_snapshot_id": observed["snapshot_id"],
                    "observe_revision": observed["observation_revision"],
                    "inventory_revision": observed_inventory["store"][
                        "observation_revision"
                    ],
                    "observe_client_store_unchanged": (
                        client_store_before_observe == client_store_after_observe
                    ),
                    "lease_port": leased["port"],
                    "docker_operation": docker["broker"]["operation"],
                    "compose_operations": [
                        row["operation"]
                        for lifecycle in compose_lifecycle
                        for row in lifecycle["broker"]["operations"]
                    ],
                    "mirror_failure": mirror_failure,
                    "reconciled": reconciled,
                    "removed_status": removed["status"],
                    "removed_ids": [row["repo_id"] for row in removed_rows],
                    "final_reconcile": final_reconcile,
                    "docker_poisoned": poison_sentinel.exists(),
                    "local_installation": [
                        local_installation["status"],
                        local_installation["startup_fenced"],
                    ],
                    "local_retirement": local_retirement["status"],
                    "lifecycle_links": [
                        [row["operation"], row["status"]] for row in lifecycle_links
                    ],
                },
            )
            os._exit(0)
        except BaseException as error:
            try:
                _write_framed_result(
                    result_write,
                    {
                        "status": "child_failure",
                        "type": type(error).__name__,
                        "message": str(error),
                    },
                )
            finally:
                os._exit(97)
    os.close(start_read)
    os.close(result_write)
    return pid, start_write, result_read


@unittest.skipUnless(
    sys.platform.startswith("linux") and os.geteuid() == SERVICE_UID,
    "real cross-UID broker acceptance requires Linux root",
)
class CrossUIDBrokerAcceptanceTests(unittest.TestCase):
    def test_concurrent_root_profile_publication_retains_both_uid_enrollments(
        self,
    ) -> None:
        root = Path("/run") / ("devcoordinator-profile-lock-" + uuid.uuid4().hex)
        profile_path = root / "profiles" / "client-profiles.json"
        try:
            root.mkdir(mode=0o750)
            os.chown(root, SERVICE_UID, ACCESS_GID)
            profile_path.parent.mkdir(mode=0o750)
            os.chown(profile_path.parent, SERVICE_UID, ACCESS_GID)
            barrier = threading.Barrier(2)
            failures: list[BaseException] = []
            service = {
                "socket": str(root / "broker.sock"),
                "uid": SERVICE_UID,
                "gid": ACCESS_GID,
                "mode": "0660",
                "database_generation": "cross-uid-profile-generation",
            }

            def publish(
                uid: int,
                account_id: str,
                repo_id: str,
                suffix: str,
            ) -> None:
                try:
                    barrier.wait(timeout=5.0)
                    _merge_profile(
                        profile_path=profile_path,
                        service=service,
                        client_uid=uid,
                        account_id=account_id,
                        repository={
                            "canonical_root": str(root / suffix),
                            "repo_id": repo_id,
                            "generation": 0,
                            "servers": {},
                            "containers": {},
                            "compose_definition_id": None,
                        },
                        issued_at=utc_timestamp(),
                        valid_until_epoch=int(time.time()) + 3_600,
                    )
                except BaseException as exc:
                    failures.append(exc)

            workers = (
                threading.Thread(
                    target=publish,
                    args=(FIRST_UID, FIRST_ACCOUNT_ID, "repo-first", "first"),
                ),
                threading.Thread(
                    target=publish,
                    args=(SECOND_UID, SECOND_ACCOUNT_ID, "repo-second", "second"),
                ),
            )
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=10.0)

            self.assertFalse(any(worker.is_alive() for worker in workers))
            self.assertEqual(failures, [])
            document = json.loads(profile_path.read_text(encoding="utf-8"))
            self.assertEqual(
                set(document["clients"]), {str(FIRST_UID), str(SECOND_UID)}
            )
            self.assertEqual(
                document["clients"][str(FIRST_UID)]["account_id"],
                FIRST_ACCOUNT_ID,
            )
            self.assertEqual(
                document["clients"][str(SECOND_UID)]["account_id"],
                SECOND_ACCOUNT_ID,
            )
            before = profile_path.read_bytes()
            with self.assertRaisesRegex(RuntimeError, "different account"):
                _merge_profile(
                    profile_path=profile_path,
                    service=service,
                    client_uid=FIRST_UID,
                    account_id="cross-uid-account-replacement",
                    repository={
                        "canonical_root": str(root / "replacement"),
                        "repo_id": "repo-replacement",
                        "generation": 0,
                        "servers": {},
                        "containers": {},
                        "compose_definition_id": None,
                    },
                    issued_at=utc_timestamp(),
                    valid_until_epoch=int(time.time()) + 7_200,
                )
            self.assertEqual(profile_path.read_bytes(), before)
            first_expiry = document["clients"][str(FIRST_UID)]["repositories"][0][
                "valid_until_epoch"
            ]
            later_expiry = int(time.time()) + 7_200
            _merge_profile(
                profile_path=profile_path,
                service=service,
                client_uid=FIRST_UID,
                account_id=FIRST_ACCOUNT_ID,
                repository={
                    "canonical_root": str(root / "first-second-repository"),
                    "repo_id": "repo-first-second",
                    "generation": 0,
                    "servers": {},
                    "containers": {},
                    "compose_definition_id": None,
                },
                issued_at=utc_timestamp(),
                valid_until_epoch=later_expiry,
            )
            updated = json.loads(profile_path.read_text(encoding="utf-8"))
            first_repositories = updated["clients"][str(FIRST_UID)]["repositories"]
            expiries = {
                item["repo_id"]: item["valid_until_epoch"]
                for item in first_repositories
            }
            self.assertEqual(expiries["repo-first"], first_expiry)
            self.assertEqual(expiries["repo-first-second"], later_expiry)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_root_enrollment_and_public_cross_uid_lifecycle_journey(self) -> None:
        root = Path("/run") / ("devcoordinator-public-crossuid-" + uuid.uuid4().hex)
        runtime_directory = root / "runtime"
        database_path = root / "private" / "coordinator.sqlite3"
        socket_path = runtime_directory / "broker.sock"
        profile_path = root / "profiles" / "client-profiles.json"
        project_root = root / "repository"
        account_home = root / "account"
        poison_directory = root / "poison-bin"
        poison_sentinel = account_home / "docker-was-invoked"
        runtime = None
        child: tuple[int, int, int] | None = None
        try:
            root.mkdir(mode=0o750)
            root.chmod(0o750)
            os.chown(root, SERVICE_UID, ACCESS_GID)
            runtime_directory.mkdir(mode=0o750)
            runtime_directory.chmod(0o750)
            os.chown(runtime_directory, SERVICE_UID, ACCESS_GID)
            database_path.parent.mkdir(mode=0o700)
            project_root.mkdir(mode=0o750)
            (project_root / ".git").mkdir(mode=0o750)
            compose_file = project_root / "compose.yaml"
            compose_file.write_text(
                "services:\n  app:\n    image: example.invalid/cross-uid:test\n",
                encoding="utf-8",
            )
            account_home.mkdir(mode=0o700)
            poison_directory.mkdir(mode=0o755)
            poison = poison_directory / "docker"
            poison.write_text(
                '#!/bin/sh\ntouch "$DEVCOORDINATOR_DOCKER_POISON_SENTINEL"\nexit 97\n',
                encoding="utf-8",
            )
            poison.chmod(0o755)
            for path in (project_root, project_root / ".git", compose_file):
                os.chown(path, FIRST_UID, ACCESS_GID)
            os.chown(account_home, FIRST_UID, ACCESS_GID)

            port = _free_tcp_port()
            fixture = CrossUIDRuntimeFixture()
            enrollment = enroll_repository(
                database_path=database_path,
                socket_path=socket_path,
                socket_gid=ACCESS_GID,
                client_uid=FIRST_UID,
                account_id=FIRST_ACCOUNT_ID,
                canonical_root=str(project_root),
                servers=(
                    {
                        "name": "server-a",
                        "cwd": str(project_root),
                        "argv": ["/usr/bin/false"],
                    },
                ),
                port_start=port,
                port_end=port,
                profile_path=profile_path,
                compose={
                    "declared": True,
                    "files": [str(compose_file)],
                    "services": ["app"],
                    "project_name": "crossuid",
                },
                compose_model_renderer=_rendered_compose_fixture,
                observe_host=fixture.observe,
                validity_seconds=3_600,
            )
            protected_profile_before = profile_path.read_bytes()
            with self.assertRaises(BrokerError) as account_conflict:
                enroll_repository(
                    database_path=database_path,
                    socket_path=socket_path,
                    socket_gid=ACCESS_GID,
                    client_uid=FIRST_UID,
                    account_id="cross-uid-account-replacement",
                    canonical_root=str(project_root),
                    servers=(
                        {
                            "name": "server-a",
                            "cwd": str(project_root),
                            "argv": ["/usr/bin/false"],
                        },
                    ),
                    port_start=port,
                    port_end=port,
                    profile_path=profile_path,
                    compose={
                        "declared": True,
                        "files": [str(compose_file)],
                        "services": ["app"],
                        "project_name": "crossuid",
                    },
                    compose_model_renderer=_rendered_compose_fixture,
                    observe_host=fixture.observe,
                    validity_seconds=3_600,
                )
            self.assertEqual(
                account_conflict.exception.code, "principal_account_conflict"
            )
            self.assertEqual(profile_path.read_bytes(), protected_profile_before)
            repo_id = str(enrollment["repo_id"])
            profile_parent = profile_path.parent.stat()
            profile_metadata = profile_path.stat()
            self.assertEqual(profile_parent.st_uid, SERVICE_UID)
            self.assertEqual(profile_parent.st_gid, ACCESS_GID)
            self.assertEqual(stat.S_IMODE(profile_parent.st_mode), 0o750)
            self.assertEqual(profile_metadata.st_uid, SERVICE_UID)
            self.assertEqual(profile_metadata.st_gid, ACCESS_GID)
            self.assertEqual(stat.S_IMODE(profile_metadata.st_mode), 0o640)
            self.assertEqual(
                enrollment["container_ids"]["cross-uid-main"], MAIN_CONTAINER_ID
            )
            self.assertNotIn("cross-uid-orphan", enrollment["container_ids"])
            self.assertIsNotNone(enrollment["compose_definition_id"])
            with CoordinatorStore.open(
                database_path, expected_uid=SERVICE_UID
            ) as store:
                exact_ref = SQLiteLifecyclePersistence(
                    store
                ).resolve_standalone_resource(
                    ResourceKind.CONTAINER,
                    ORPHAN_CONTAINER_ID,
                    ORPHAN_CONTROL_ID,
                )
            exact = {
                "resource_kind": exact_ref.kind.value,
                "immutable_fingerprint": exact_ref.immutable_fingerprint,
                "ownership_fingerprint": exact_ref.ownership_fingerprint,
            }

            child = _spawn_public_journey(
                socket_path=socket_path,
                profile_path=profile_path,
                project_root=project_root,
                account_home=account_home,
                poison_directory=poison_directory,
                poison_sentinel=poison_sentinel,
                port=port,
                repo_id=repo_id,
                exact=exact,
            )
            runtime = build_store_backed_broker_runtime(
                database_path=database_path,
                socket_path=socket_path,
                host_mutations=fixture,
                service_uid=SERVICE_UID,
                access_gid=ACCESS_GID,
                lifecycle_adapter=fixture,
                observe_before_lifecycle_plan=fixture.observe,
            )
            runtime.server.start()
            os.write(child[1], b"1")
            os.close(child[1])
            result = _read_framed_result(child[2])
            os.close(child[2])
            finished_pid, status = os.waitpid(child[0], 0)
            self.assertEqual(finished_pid, child[0])
            self.assertTrue(os.WIFEXITED(status), result)
            self.assertEqual(os.WEXITSTATUS(status), 0, result)
            child = None

            self.assertEqual(result["status"], "success", result)
            self.assertEqual(result["uid"], FIRST_UID)
            self.assertTrue(result["observe_snapshot_id"], result)
            self.assertEqual(
                result["inventory_revision"], result["observe_revision"], result
            )
            self.assertTrue(result["observe_client_store_unchanged"], result)
            self.assertEqual(result["lease_port"], port)
            self.assertEqual(result["docker_operation"], "docker.start")
            self.assertEqual(
                result["compose_operations"],
                [
                    "compose.up",
                    "compose.stop",
                    "compose.restart",
                    "compose.down",
                ],
            )
            self.assertEqual(result["reconciled"]["resolved"], 1)
            self.assertEqual(result["reconciled"]["pending"], 0)
            self.assertEqual(result["removed_status"], "succeeded")
            self.assertIn(repo_id, result["removed_ids"])
            self.assertEqual(result["final_reconcile"]["attempted"], 0)
            self.assertFalse(result["docker_poisoned"], result)
            self.assertFalse(poison_sentinel.exists())
            self.assertIn(("docker.start", MAIN_CONTAINER_ID), fixture.host_calls)
            self.assertIn(
                ("compose.up", str(enrollment["compose_definition_id"])),
                fixture.host_calls,
            )
            for operation in (
                "compose.stop",
                "compose.restart",
                "compose.down",
            ):
                self.assertIn(
                    (operation, str(enrollment["compose_definition_id"])),
                    fixture.host_calls,
                )
            self.assertEqual(
                fixture.lifecycle_calls,
                [
                    ("disable_policy", ORPHAN_CONTAINER_ID),
                    ("stop", ORPHAN_CONTAINER_ID),
                    ("disable_policy", MAIN_CONTAINER_ID),
                    ("stop", MAIN_CONTAINER_ID),
                ],
            )

            with CoordinatorStore.open(
                database_path, expected_uid=SERVICE_UID
            ) as store:
                with store.read_transaction() as connection:
                    installation = connection.execute(
                        """
                        SELECT status, startup_fenced
                        FROM repository_installations WHERE repo_id = ?
                        """,
                        (repo_id,),
                    ).fetchone()
                    retirement = connection.execute(
                        """
                        SELECT status FROM resource_retirements
                        WHERE host_resource_id = ?
                        """,
                        (ORPHAN_CONTAINER_ID,),
                    ).fetchone()
            self.assertEqual(
                (installation["status"], installation["startup_fenced"]),
                ("disabled", 1),
            )
            self.assertEqual(retirement["status"], "retired")

            self.assertEqual(
                result["local_installation"],
                ["disabled", 1],
            )
            self.assertEqual(result["local_retirement"], "retired")
            self.assertEqual(
                result["lifecycle_links"],
                [
                    ["repository.remove", "applied"],
                    ["resource.retire", "applied"],
                ],
            )
        finally:
            if runtime is not None:
                runtime.server.close()
            if child is not None:
                for descriptor in child[1:]:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                try:
                    os.kill(child[0], 9)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(child[0], 0)
                except ChildProcessError:
                    pass
            shutil.rmtree(root, ignore_errors=True)

    def test_real_peer_credentials_share_one_global_port_authority(self) -> None:
        root = Path("/run") / ("devcoordinator-crossuid-" + uuid.uuid4().hex)
        runtime_directory = root / "runtime"
        database_path = root / "private" / "coordinator.sqlite3"
        socket_path = runtime_directory / "broker.sock"
        runtime = None
        children: list[tuple[int, int, int]] = []
        try:
            runtime_directory.mkdir(parents=True, mode=0o750)
            database_path.parent.mkdir(parents=True, mode=0o700)
            os.chown(root, SERVICE_UID, ACCESS_GID)
            os.chmod(root, 0o750)
            os.chown(runtime_directory, SERVICE_UID, ACCESS_GID)
            os.chmod(runtime_directory, 0o750)
            port = _free_tcp_port()
            _seed_service_database(database_path, port)
            database_generation = _database_generation(database_path)

            children = [
                _spawn_client(
                    socket_path=socket_path,
                    uid=FIRST_UID,
                    account_id=FIRST_ACCOUNT_ID,
                    server_id=FIRST_SERVER_ID,
                    port=port,
                    database_generation=database_generation,
                ),
                _spawn_client(
                    socket_path=socket_path,
                    uid=SECOND_UID,
                    account_id=SECOND_ACCOUNT_ID,
                    server_id=SECOND_SERVER_ID,
                    port=port,
                    database_generation=database_generation,
                ),
                _spawn_client(
                    socket_path=socket_path,
                    uid=SECOND_UID,
                    account_id=FIRST_ACCOUNT_ID,
                    server_id=SECOND_SERVER_ID,
                    port=port,
                    database_generation=database_generation,
                ),
                _spawn_client(
                    socket_path=socket_path,
                    uid=UNKNOWN_UID,
                    account_id=UNKNOWN_ACCOUNT_ID,
                    server_id=FIRST_SERVER_ID,
                    port=port,
                    database_generation=database_generation,
                ),
            ]

            runtime = build_store_backed_broker_runtime(
                database_path=database_path,
                socket_path=socket_path,
                host_mutations=LocalBrokerHostMutations(),
                service_uid=SERVICE_UID,
                access_gid=ACCESS_GID,
            )
            runtime.server.start()

            def collect(index: int) -> dict[str, object]:
                pid, _start_write, result_read = children[index]
                result = _read_framed_result(result_read)
                os.close(result_read)
                finished_pid, status = os.waitpid(pid, 0)
                self.assertEqual(finished_pid, pid)
                self.assertTrue(os.WIFEXITED(status), result)
                self.assertEqual(os.WEXITSTATUS(status), 0, result)
                return result

            # Release both authorized clients before reading either result.
            # The broker must arbitrate the real two-UID race globally: which
            # account wins is intentionally unspecified, but two successes or
            # two failures are both defects.
            for index in (0, 1):
                os.write(children[index][1], b"1")
                os.close(children[index][1])
            authorized = [collect(0), collect(1)]
            successes = [item for item in authorized if item.get("status") == "success"]
            conflicts = [
                item
                for item in authorized
                if item.get("status") == "broker_error"
                and item.get("code") == "port_unavailable"
            ]
            self.assertEqual(len(successes), 1, authorized)
            self.assertEqual(len(conflicts), 1, authorized)
            winner = successes[0].get("result")
            self.assertIsInstance(winner, dict)
            self.assertEqual(winner.get("port"), port)
            self.assertEqual(winner.get("status"), "active")

            for index in (2, 3):
                os.write(children[index][1], b"1")
                os.close(children[index][1])
            spoofed = collect(2)
            unauthorized = collect(3)
            self.assertEqual(spoofed["status"], "broker_error", spoofed)
            self.assertEqual(
                spoofed.get("code"), "cross_account_access_denied", spoofed
            )
            self.assertEqual(unauthorized["status"], "broker_error", unauthorized)
            self.assertEqual(
                unauthorized.get("code"), "peer_not_authorized", unauthorized
            )

            with CoordinatorStore.open(
                database_path, expected_uid=SERVICE_UID
            ) as store:
                with store.read_transaction() as connection:
                    active = list(
                        connection.execute(
                            "SELECT lease_id, port, status FROM leases WHERE status = 'active'"
                        )
                    )
            self.assertEqual(len(active), 1)
            self.assertEqual(int(active[0]["port"]), port)
        finally:
            if runtime is not None:
                runtime.server.close()
            for pid, start_write, result_read in children:
                for descriptor in (start_write, result_read):
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                try:
                    os.kill(pid, 9)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    required = os.environ.get("DEVCOORDINATOR_BROKER_CROSS_UID_REQUIRED") == "1"
    capable = sys.platform.startswith("linux") and os.geteuid() == SERVICE_UID
    if required and not capable:
        raise SystemExit(
            "required cross-UID broker acceptance must run as root on Linux"
        )
    unittest.main()
