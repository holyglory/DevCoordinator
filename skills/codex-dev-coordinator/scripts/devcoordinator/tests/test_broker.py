"""Deterministic security and concurrency tests for the cross-UID broker."""

from __future__ import annotations

import json
import hashlib
import os
import pwd
import socket
import sqlite3
import stat
import struct
import sys
import tempfile
import threading
import time
import unittest
import uuid
from unittest import mock
from pathlib import Path
from typing import Any, Mapping, Optional


SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from devcoordinator.broker import (  # noqa: E402
    AccountAccessPolicy,
    AuthorizedBrokerRequest,
    BrokerClient,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    BrokerService,
    PeerCredentials,
    PortLeasePolicy,
    SerializedMutationWriter,
    StaticPeerAuthorizer,
    UnixBrokerServer,
    resolve_peer_credentials,
    validate_runtime_directory,
)
import devcoordinator.broker as broker_module  # noqa: E402
from devcoordinator.broker_backend import (  # noqa: E402
    StoreBackedMutationBackend,
    build_store_backed_broker_runtime,
)
from devcoordinator.broker_persistence import (  # noqa: E402
    BrokerPersistence,
    StoreBackedAuthorizer,
)
from devcoordinator.repository_lifecycle import (  # noqa: E402
    PolicyObservation,
    ResourceObservation,
    ResourceKind,
    RunningState,
)
from devcoordinator.sqlite_lifecycle import SQLiteLifecyclePersistence  # noqa: E402
from devcoordinator.store import CoordinatorStore, utc_timestamp  # noqa: E402


ACCOUNT_ID = "account-current"
PROJECT_ID = "repo-alpha"
CONTAINER_ID = "container-alpha"
SECOND_CONTAINER_ID = "container-beta"
STOP_ONLY_CONTAINER_ID = "container-stop-only"
SERVER_ID = "server-web"
LEASE_ID = "lease-web"
HOST_ID = "host-current"
SOURCE_ID = "source-current"
ENGINE_ID = "engine-current"
CONTROL_ID = "control-container-alpha"
SECOND_CONTROL_ID = "control-container-beta"
DATABASE_ID = "database-alpha"
DATABASE_NAME = "app"
CURRENT_AUTHORITY_GENERATION = "unbound-static-test"


class RecordingBackend:
    def __init__(
        self,
        *,
        entered: Optional[threading.Event] = None,
        release: Optional[threading.Event] = None,
    ) -> None:
        self._lock = threading.Lock()
        self.entered = entered
        self.release = release
        self.calls: list[AuthorizedBrokerRequest] = []
        self.active = 0
        self.max_active = 0
        self.wait_timed_out = False

    def execute(self, request: AuthorizedBrokerRequest) -> Mapping[str, Any]:
        with self._lock:
            self.calls.append(request)
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            if self.entered is not None:
                self.entered.set()
            if self.release is not None and not self.release.wait(timeout=3.0):
                self.wait_timed_out = True
                raise RuntimeError("test backend release boundary timed out")
            return {
                "status": "accepted",
                "operation": request.request.operation.value,
                "resource_id": request.request.resource_id,
            }
        finally:
            with self._lock:
                self.active -= 1


class RecordingTypedHostActions:
    def __init__(
        self,
        *,
        occupied_ports: Optional[set[int]] = None,
        listener_evidence: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.calls: list[tuple[str, str, str]] = []
        self.occupied_ports = set(occupied_ports or set())
        self.port_observations: list[tuple[tuple[int, ...], str]] = []
        self.listener_evidence = listener_evidence
        self.listener_observations: list[tuple[int, str, str]] = []

    def select_available_port(
        self, *, candidates: tuple[int, ...], protocol: str
    ) -> Optional[int]:
        self.port_observations.append((candidates, protocol))
        return next(
            (port for port in candidates if port not in self.occupied_ports), None
        )

    def verify_owned_tcp_listener(
        self, *, port: int, canonical_root: str
    ) -> Mapping[str, Any]:
        self.listener_observations.append((port, canonical_root, "tcp"))
        if self.listener_evidence is None:
            raise BrokerError(
                "listener_identity_unavailable",
                "The test host did not configure exact listener evidence.",
            )
        return dict(self.listener_evidence)

    def _record(self, action: str, target: Any) -> Mapping[str, Any]:
        self.calls.append(
            (action, target.docker_resource_id, target.full_container_id)
        )
        return {
            "status": "accepted",
            "action": action,
            "docker_resource_id": target.docker_resource_id,
        }

    def docker_start(self, target: Any) -> Mapping[str, Any]:
        return self._record("start", target)

    def docker_stop(self, target: Any) -> Mapping[str, Any]:
        return self._record("stop", target)

    def docker_restart(self, target: Any) -> Mapping[str, Any]:
        return self._record("restart", target)


def _publish_strong_postgres_backup(
    output_root: str | Path,
    *,
    full_container_id: str,
    database_name: str,
    marker: str,
) -> dict[str, Any]:
    root = Path(output_root)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    artifact = root / f"{marker}.dump"
    artifact.write_bytes((f"strong backup {marker}\n").encode("utf-8"))
    os.chmod(artifact, 0o600)
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    manifest = Path(f"{artifact}.manifest.json")
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "type": "postgres-docker-backup",
                "created_at": "2026-07-15T12:00:00Z",
                "scope": "database",
                "format": "custom",
                "path": str(artifact),
                "size": artifact.stat().st_size,
                "sha256": digest,
                "source": {
                    "container": {
                        "id": full_container_id,
                        "name": "postgres",
                    },
                    "postgres": {
                        "database": database_name,
                        "scope": "database",
                    },
                },
                "verification": {
                    "ok": True,
                    "mode": "test_restore",
                    "sha256": digest,
                    "verified_at": "2026-07-15T12:05:00Z",
                    "verification_target": "scratch_database",
                    "catalog_signature": {
                        "tables": 2,
                        "sequences": 1,
                        "views": 0,
                        "functions": 3,
                    },
                    "container_identity_preflight": {
                        "actual_id": full_container_id,
                        "match": "exact_full",
                    },
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    os.chmod(manifest, 0o600)
    return {"backup": str(artifact), "manifest": str(manifest), "sha256": digest}


class RecordingPostgresHostActions(RecordingTypedHostActions):
    def __init__(self, *, fail_backup: bool = False) -> None:
        super().__init__()
        self.postgres_calls: list[tuple[str, str, str]] = []
        self.fail_backup = fail_backup
        self._published = 0

    def postgres_backup(
        self, target: Any, *, output_root: str
    ) -> Mapping[str, Any]:
        self.postgres_calls.append(
            ("backup", target.full_container_id, target.database_name)
        )
        if self.fail_backup:
            raise RuntimeError("injected PostgreSQL host backup failure")
        self._published += 1
        return _publish_strong_postgres_backup(
            output_root,
            full_container_id=target.full_container_id,
            database_name=target.database_name,
            marker=f"broker-{self._published}",
        )

    def postgres_restore(
        self,
        target: Any,
        backup: Any,
        *,
        safety_output_root: str,
    ) -> Mapping[str, Any]:
        self.postgres_calls.append(
            ("restore", target.full_container_id, target.database_name)
        )
        self._published += 1
        safety = _publish_strong_postgres_backup(
            safety_output_root,
            full_container_id=target.full_container_id,
            database_name=target.database_name,
            marker=f"safety-{self._published}",
        )
        catalog = {"tables": 2, "sequences": 1, "views": 0, "functions": 3}
        return {
            "restored": backup.artifact_path,
            "database": target.database_name,
            "scope": "database",
            "sha256": backup.artifact_sha256,
            "transactional": True,
            "incoming_verification": {
                "test_restore": True,
                "verification_target": "scratch_database",
                "restore_returncode": 0,
                "scratch_created": True,
                "catalog_signature": catalog,
            },
            "restored_catalog_signature": catalog,
            "container_identity_preflights": [
                {"actual_id": target.full_container_id, "phase": phase}
                for phase in ("selection", "post-incoming", "final")
            ],
            "safety_backup": safety,
        }


class BlockingTypedHostActions(RecordingTypedHostActions):
    def __init__(self, entered: threading.Event, release: threading.Event) -> None:
        super().__init__()
        self.entered = entered
        self.release = release

    def _record(self, action: str, target: Any) -> Mapping[str, Any]:
        self.entered.set()
        if not self.release.wait(timeout=3.0):
            raise RuntimeError("typed host action release boundary timed out")
        return super()._record(action, target)


class ExactLifecycleAdapter:
    def __init__(self) -> None:
        self.running = True
        self.policy_disabled = False
        self.calls: list[str] = []

    def observe_exact(self, target: Any) -> ResourceObservation:
        policy = target.policies[0]
        return ResourceObservation(
            resource_id=target.resource_id,
            kind=target.kind,
            identity_observable=True,
            immutable_fingerprint=target.immutable_fingerprint,
            ownership_observable=True,
            ownership_fingerprint=target.ownership_fingerprint,
            running_state=(
                RunningState.RUNNING if self.running else RunningState.STOPPED
            ),
            container_running=self.running,
            policies={
                policy.policy_id: PolicyObservation(
                    policy_id=policy.policy_id,
                    immutable_fingerprint=policy.immutable_fingerprint,
                    observable=True,
                    disabled=self.policy_disabled,
                    value=(policy.disabled_value if self.policy_disabled else "always"),
                    docker_restart_policy=(
                        policy.disabled_value if self.policy_disabled else "always"
                    ),
                )
            },
        )

    def disable_startup_policy(self, _target: Any, _policy: Any) -> Mapping[str, Any]:
        self.calls.append("disable_policy")
        self.policy_disabled = True
        return {"status": "disabled"}

    def stop_exact(self, _target: Any) -> Mapping[str, Any]:
        self.calls.append("stop")
        self.running = False
        return {"status": "stopped"}


def policy_for(uid: int) -> Mapping[int, AccountAccessPolicy]:
    return {
        uid: AccountAccessPolicy(
            account_id=ACCOUNT_ID,
            grants={
                PROJECT_ID: {
                    CONTAINER_ID: frozenset(
                        {
                            BrokerOperation.DOCKER_START,
                            BrokerOperation.DOCKER_STOP,
                            BrokerOperation.DOCKER_RESTART,
                        }
                    ),
                    SECOND_CONTAINER_ID: frozenset(
                        {
                            BrokerOperation.DOCKER_START,
                            BrokerOperation.DOCKER_STOP,
                        }
                    ),
                    STOP_ONLY_CONTAINER_ID: frozenset(
                        {BrokerOperation.DOCKER_STOP}
                    ),
                    SERVER_ID: frozenset({BrokerOperation.PORT_LEASE}),
                    LEASE_ID: frozenset({BrokerOperation.PORT_RELEASE}),
                }
            },
            port_policies={
                PROJECT_ID: {
                    SERVER_ID: (
                        PortLeasePolicy(
                            start_port=3100,
                            end_port=3199,
                            protocol="tcp",
                            max_ttl_seconds=3_600,
                        ),
                    )
                }
            },
        )
    }


def request_for(
    operation: BrokerOperation = BrokerOperation.DOCKER_STOP,
    *,
    resource_id: str = CONTAINER_ID,
    arguments: Optional[Mapping[str, Any]] = None,
    operation_id: Optional[str] = None,
) -> BrokerRequest:
    return BrokerRequest.create(
        account_id=ACCOUNT_ID,
        project_id=PROJECT_ID,
        resource_id=resource_id,
        operation=operation,
        arguments=arguments,
        operation_id=operation_id,
        authority_generation=CURRENT_AUTHORITY_GENERATION,
    )


def service_for(
    backend: RecordingBackend,
    *,
    uid: Optional[int] = None,
) -> tuple[BrokerService, SerializedMutationWriter]:
    effective_uid = os.geteuid() if uid is None else uid
    writer = SerializedMutationWriter(backend)
    service = BrokerService(
        StaticPeerAuthorizer(policy_for(effective_uid)), writer
    )
    return service, writer


def peer_for(uid: Optional[int] = None) -> PeerCredentials:
    return PeerCredentials(
        uid=os.geteuid() if uid is None else uid,
        gid=os.getegid(),
        pid=os.getpid(),
    )


class CanonicalTemporaryDirectory:
    """Test-owned canonical root; avoids host aliases such as /var -> /private/var."""

    def __init__(self) -> None:
        # macOS Unix-domain socket paths are short (104 bytes), while the
        # per-user TMPDIR under /var/folders can already consume most of that.
        # A short, test-owned directory under the canonical checkout preserves
        # the production path guard and is removed at fixture teardown.
        canonical_tmp = Path(pwd.getpwuid(os.geteuid()).pw_dir).resolve()
        self._temporary = tempfile.TemporaryDirectory(
            prefix=".broker-test-", dir=str(canonical_tmp)
        )
        self.path = Path(self._temporary.name).resolve()

    def cleanup(self) -> None:
        self._temporary.cleanup()

    def __enter__(self) -> Path:
        return self.path

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.cleanup()


def seed_store_backed_broker(
    root: Path,
) -> tuple[BrokerPersistence, RecordingTypedHostActions]:
    database_path = root / "store" / "coordinator.sqlite3"
    global CURRENT_AUTHORITY_GENERATION
    persistence = BrokerPersistence(database_path, expected_uid=os.geteuid())
    with CoordinatorStore.open(database_path, expected_uid=os.geteuid()) as store:
        CURRENT_AUTHORITY_GENERATION = store.metadata.database_generation
    now = utc_timestamp()
    with CoordinatorStore.open(database_path, expected_uid=os.geteuid()) as store:
        with store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO hosts(host_id, machine_fingerprint, platform, hostname, created_at, updated_at)
                VALUES (?, 'machine-current', 'test', 'test-host', ?, ?)
                """,
                (HOST_ID, now, now),
            )
            connection.execute(
                """
                INSERT INTO coordinator_sources(
                    source_id, host_id, canonical_home, state_path, effective_uid,
                    status, created_at, updated_at
                ) VALUES (?, ?, '/service/source', '/service/source/state', ?, 'imported', ?, ?)
                """,
                (SOURCE_ID, HOST_ID, os.geteuid(), now, now),
            )
            connection.execute(
                """
                INSERT INTO repositories(
                    repo_id, host_id, canonical_root, display_name, state,
                    generation, created_at, updated_at
                ) VALUES (?, ?, '/repos/alpha', 'Alpha', 'active', 0, ?, ?)
                """,
                (PROJECT_ID, HOST_ID, now, now),
            )
            connection.execute(
                """
                INSERT INTO repository_installations(
                    repo_id, status, startup_fenced, generation, actor, updated_at
                ) VALUES (?, 'installed', 0, 0, 'fixture', ?)
                """,
                (PROJECT_ID, now),
            )
            connection.execute(
                """
                INSERT INTO server_definitions(
                    server_definition_id, repo_id, name, cwd,
                    definition_fingerprint, generation, created_at, updated_at
                ) VALUES (?, ?, 'web', '/repos/alpha', 'server-definition', 0, ?, ?)
                """,
                (SERVER_ID, PROJECT_ID, now, now),
            )
            connection.execute(
                """
                INSERT INTO docker_engines(
                    engine_id, host_id, context_identity, daemon_identity,
                    capability_state, created_at, updated_at
                ) VALUES (?, ?, 'default', 'daemon-current', 'available', ?, ?)
                """,
                (ENGINE_ID, HOST_ID, now, now),
            )
            for resource_id, full_id, name in (
                (CONTAINER_ID, "a" * 64, "alpha"),
                (SECOND_CONTAINER_ID, "b" * 64, "beta"),
            ):
                connection.execute(
                    """
                    INSERT INTO docker_resources(
                        docker_resource_id, engine_id, full_container_id,
                        current_name, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (resource_id, ENGINE_ID, full_id, name, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO docker_observations(
                        docker_resource_id, lifecycle, sampled_at, observation_fingerprint
                    ) VALUES (?, 'stopped', ?, ?)
                    """,
                    (resource_id, now, "observation-" + resource_id),
                )
            for resource_id, binding_id in (
                (CONTAINER_ID, CONTROL_ID),
                (SECOND_CONTAINER_ID, SECOND_CONTROL_ID),
            ):
                connection.execute(
                    """
                    INSERT INTO control_bindings(
                        binding_id, repo_id, resource_kind, resource_id, source_id,
                        capability, provenance, authority_state, priority,
                        generation, created_at, updated_at
                    ) VALUES (?, ?, 'container', ?, ?, 'lifecycle', 'fixture',
                              'authoritative', 100, 0, ?, ?)
                    """,
                    (binding_id, PROJECT_ID, resource_id, SOURCE_ID, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repository_memberships(
                        membership_id, repo_id, resource_kind, host_resource_id,
                        immutable_fingerprint, control_binding_id, created_at
                    ) VALUES (?, ?, 'container', ?, ?, ?, ?)
                    """,
                    (
                        "membership-" + resource_id,
                        PROJECT_ID,
                        resource_id,
                        "membership-fingerprint-" + resource_id,
                        binding_id,
                        now,
                    ),
                )
    persistence.provision_principal(uid=os.geteuid(), account_id=ACCOUNT_ID)
    for resource_id in (CONTAINER_ID, SECOND_CONTAINER_ID):
        for operation in (
            BrokerOperation.DOCKER_START,
            BrokerOperation.DOCKER_STOP,
            BrokerOperation.DOCKER_RESTART,
        ):
            persistence.grant_resource(
                uid=os.geteuid(),
                repo_id=PROJECT_ID,
                resource_kind="container",
                resource_id=resource_id,
                operation=operation,
            )
    for operation in (BrokerOperation.PORT_LEASE, BrokerOperation.PORT_RELEASE):
        persistence.grant_resource(
            uid=os.geteuid(),
            repo_id=PROJECT_ID,
            resource_kind="server",
            resource_id=SERVER_ID,
            operation=operation,
        )
    persistence.grant_port_range(
        uid=os.geteuid(),
        repo_id=PROJECT_ID,
        server_definition_id=SERVER_ID,
        start_port=3100,
        end_port=3199,
        protocol="tcp",
        max_ttl_seconds=3_600,
    )
    return persistence, RecordingTypedHostActions()


def seed_postgres_database(persistence: BrokerPersistence) -> None:
    now = utc_timestamp()
    with CoordinatorStore.open(
        persistence.database_path, expected_uid=os.geteuid()
    ) as store:
        with store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO database_bindings(
                    database_binding_id, docker_resource_id, repo_id,
                    database_name, engine_kind, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'postgresql', ?, ?)
                """,
                (
                    DATABASE_ID,
                    CONTAINER_ID,
                    PROJECT_ID,
                    DATABASE_NAME,
                    now,
                    now,
                ),
            )
    for operation in (
        BrokerOperation.DATABASE_BACKUP,
        BrokerOperation.DATABASE_RESTORE,
    ):
        persistence.grant_database(
            uid=os.geteuid(),
            repo_id=PROJECT_ID,
            database_binding_id=DATABASE_ID,
            operation=operation,
        )


class DatabaseTargetDriftPersistence(BrokerPersistence):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.inject_drift = True

    def database_target(self, authorized: AuthorizedBrokerRequest) -> Any:
        if self.inject_drift:
            self.inject_drift = False
            with CoordinatorStore.open(
                self.database_path, expected_uid=self.expected_uid
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        UPDATE docker_resources SET full_container_id = ?,
                            updated_at = ? WHERE docker_resource_id = ?
                        """,
                        ("d" * 64, utc_timestamp(), CONTAINER_ID),
                    )
        return super().database_target(authorized)


def store_backed_service(
    persistence: BrokerPersistence,
    actions: RecordingTypedHostActions,
    *,
    completed_cache_size: int = 1024,
) -> BrokerService:
    backend = StoreBackedMutationBackend(
        persistence,
        actions,
        observe_before_lifecycle_plan=_committed_available_observer,
    )
    return BrokerService(
        StoreBackedAuthorizer(persistence),
        SerializedMutationWriter(
            backend, completed_cache_size=completed_cache_size
        ),
    )


def _committed_available_observer(store: CoordinatorStore) -> Mapping[str, Any]:
    snapshot_id = str(uuid.uuid4())
    completed_at = utc_timestamp()
    material = "1" * 64
    capability = "sha256:" + "2" * 64
    with store.immediate_transaction(revision_kind="observation") as connection:
        host_id = str(
            connection.execute("SELECT host_id FROM hosts ORDER BY host_id LIMIT 1").fetchone()[0]
        )
        connection.execute(
            """
            INSERT INTO observation_snapshots(
                snapshot_id, host_id, observer_domain, status,
                material_fingerprint, started_at, completed_at
            ) VALUES (?, ?, 'host-runtime-v2:full-docker', 'completed', ?, ?, ?)
            """,
            (snapshot_id, host_id, material, completed_at, completed_at),
        )
        connection.execute(
            """
            INSERT INTO observation_capabilities(
                snapshot_id, observer_domain, docker_available,
                capability_fingerprint, committed_at
            ) VALUES (?, 'host-runtime-v2:full-docker', 1, ?, ?)
            """,
            (snapshot_id, capability, completed_at),
        )
        pending = connection.execute(
            """
            SELECT t.target_id, t.action
            FROM operation_targets t JOIN operations o USING(operation_id)
            WHERE o.status = 'running' AND t.action LIKE 'docker.%'
            ORDER BY o.created_at DESC LIMIT 1
            """
        ).fetchone()
        if pending is not None:
            lifecycle = (
                "stopped" if pending["action"] == "docker.stop" else "running"
            )
            connection.execute(
                """
                UPDATE docker_observations
                SET lifecycle = ?, sampled_at = ?, observation_fingerprint = ?
                WHERE docker_resource_id = ?
                """,
                (
                    lifecycle,
                    completed_at,
                    f"post-{pending['action']}",
                    pending["target_id"],
                ),
            )
    return {
        "snapshot_id": snapshot_id,
        "observer_domain": "host-runtime-v2:full-docker",
        "docker_available": True,
        "capability_fingerprint": capability,
        "material_fingerprint": material,
        "completed_at": completed_at,
    }


class PeerCredentialTests(unittest.TestCase):
    def test_kernel_peer_credentials_match_the_real_unix_peer(self) -> None:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            credentials = resolve_peer_credentials(left)
        finally:
            left.close()
            right.close()

        self.assertEqual(credentials.uid, os.geteuid())
        self.assertEqual(credentials.gid, os.getegid())
        if sys.platform.startswith("linux"):
            self.assertEqual(credentials.pid, os.getpid())
        else:
            self.assertIsNone(credentials.pid)

    def test_non_unix_socket_cannot_bypass_peer_authentication(self) -> None:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with self.assertRaises(BrokerError) as raised:
                resolve_peer_credentials(connection)
        finally:
            connection.close()
        self.assertEqual(raised.exception.code, "peer_credentials_unavailable")


class AuthorizationAndProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = RecordingBackend()
        self.service, self.writer = service_for(self.backend)
        self.peer = peer_for()

    def test_authorized_docker_and_port_operations_are_not_false_positives(self) -> None:
        requests = [
            request_for(BrokerOperation.DOCKER_STOP),
            request_for(
                BrokerOperation.PORT_LEASE,
                resource_id=SERVER_ID,
                arguments={
                    "requested_port": 3107,
                    "protocol": "tcp",
                    "ttl_seconds": 600,
                },
            ),
            request_for(BrokerOperation.PORT_RELEASE, resource_id=LEASE_ID),
        ]

        replies = [
            self.service.reply_for_document(self.peer, request.to_wire())
            for request in requests
        ]

        self.assertTrue(all(reply["ok"] for reply in replies), replies)
        self.assertEqual(
            [reply["operation_id"] for reply in replies],
            [request.operation_id for request in requests],
        )
        self.assertEqual(len(self.backend.calls), 3)

    def test_atomic_host_inventory_supports_a_bounded_multi_account_graph(self) -> None:
        class InventoryBackend:
            def __init__(self, payload_bytes: int) -> None:
                self.payload = "x" * payload_bytes

            def execute(self, _request: AuthorizedBrokerRequest) -> Mapping[str, Any]:
                return {"schema_version": 2, "graph_payload": self.payload}

        # The real six-repository host graph crossed the retired 2 MiB result
        # ceiling because normalized and v1 compatibility views coexist during
        # migration. Keep one atomic snapshot comfortably above that boundary.
        backend = InventoryBackend(3 * 1024 * 1024)
        inventory_policy = {
            os.geteuid(): AccountAccessPolicy(
                account_id=ACCOUNT_ID,
                grants={
                    PROJECT_ID: {
                        PROJECT_ID: frozenset({BrokerOperation.INVENTORY_READ})
                    }
                },
            )
        }
        writer = SerializedMutationWriter(backend)  # type: ignore[arg-type]
        service = BrokerService(StaticPeerAuthorizer(inventory_policy), writer)
        request = request_for(
            BrokerOperation.INVENTORY_READ, resource_id=PROJECT_ID
        )
        accepted = service.reply_for_document(self.peer, request.to_wire())

        self.assertTrue(accepted["ok"], accepted)
        self.assertEqual(len(accepted["result"]["graph_payload"]), 3 * 1024 * 1024)

        # The boundary remains explicit and fail-closed rather than becoming
        # an unbounded local-socket allocation.
        bounded_writer = SerializedMutationWriter(
            InventoryBackend(2048),  # type: ignore[arg-type]
            max_result_bytes=1024,
        )
        bounded_service = BrokerService(
            StaticPeerAuthorizer(inventory_policy), bounded_writer
        )
        rejected = bounded_service.reply_for_document(self.peer, request.to_wire())
        self.assertFalse(rejected["ok"], rejected)
        self.assertEqual(rejected["error"]["code"], "backend_result_too_large")

    def test_unknown_peer_and_cross_account_project_resource_operation_are_rejected(self) -> None:
        cases: list[tuple[str, PeerCredentials, dict[str, Any], str]] = []

        unknown_peer_request = request_for().to_wire()
        cases.append(
            (
                "unknown peer",
                peer_for(os.geteuid() + 10000),
                unknown_peer_request,
                "peer_not_authorized",
            )
        )

        cross_account = request_for().to_wire()
        cross_account["account_id"] = "account-other"
        cases.append(
            (
                "cross account",
                self.peer,
                cross_account,
                "cross_account_access_denied",
            )
        )

        cross_project = request_for().to_wire()
        cross_project["project_id"] = "repo-other"
        cases.append(
            (
                "cross project",
                self.peer,
                cross_project,
                "project_access_denied",
            )
        )

        cross_resource = request_for().to_wire()
        cross_resource["resource_id"] = "container-other"
        cases.append(
            (
                "cross resource",
                self.peer,
                cross_resource,
                "resource_access_denied",
            )
        )

        wrong_operation = request_for(
            BrokerOperation.DOCKER_START,
            resource_id=STOP_ONLY_CONTAINER_ID,
        ).to_wire()
        cases.append(
            (
                "operation outside grant",
                self.peer,
                wrong_operation,
                "operation_access_denied",
            )
        )

        for name, peer, document, expected_code in cases:
            with self.subTest(name=name):
                reply = self.service.reply_for_document(peer, document)
                self.assertFalse(reply["ok"], reply)
                self.assertEqual(reply["operation_id"], document["operation_id"])
                self.assertEqual(reply["error"]["code"], expected_code)

        self.assertEqual(self.backend.calls, [])

    def test_paths_commands_sql_and_untyped_arguments_are_rejected_before_backend(self) -> None:
        cases: list[tuple[str, dict[str, Any], str]] = []

        traversal = request_for().to_wire()
        traversal["project_id"] = "../../root"
        cases.append(("path traversal", traversal, "invalid_identifier"))

        socket_path = request_for().to_wire()
        socket_path["resource_id"] = "/var/run/docker.sock"
        cases.append(("resource path", socket_path, "invalid_identifier"))

        arbitrary_command = request_for().to_wire()
        arbitrary_command["operation"] = "exec"
        cases.append(("arbitrary operation", arbitrary_command, "unknown_operation"))

        argv = request_for().to_wire()
        argv["arguments"] = {"argv": ["docker", "rm", "--force"]}
        cases.append(("argv", argv, "invalid_arguments"))

        database_path = request_for(
            BrokerOperation.DATABASE_BACKUP,
            arguments={"database_name": DATABASE_NAME},
        ).to_wire()
        database_path["arguments"] = {
            "database_name": DATABASE_NAME,
            "output_root": "/tmp/client-selected",
        }
        cases.append(("database output path", database_path, "invalid_arguments"))

        restore_command = request_for(
            BrokerOperation.DATABASE_RESTORE,
            arguments={
                "database_name": DATABASE_NAME,
                "database_backup_id": "backup-id",
                "explicit": True,
            },
        ).to_wire()
        restore_command["arguments"] = {
            "database_name": DATABASE_NAME,
            "database_backup_id": "backup-id",
            "explicit": True,
            "command": "pg_restore --clean",
        }
        cases.append(("database restore command", restore_command, "invalid_arguments"))

        sql = request_for().to_wire()
        sql["sql"] = "DELETE FROM repositories"
        cases.append(("sql", sql, "invalid_request"))

        for name, document, expected_code in cases:
            with self.subTest(name=name):
                reply = self.service.reply_for_document(self.peer, document)
                self.assertFalse(reply["ok"], reply)
                self.assertEqual(reply["operation_id"], document["operation_id"])
                self.assertEqual(reply["error"]["code"], expected_code)

        self.assertEqual(self.backend.calls, [])

    def test_duplicate_json_keys_are_rejected_without_dispatch(self) -> None:
        operation_id = str(uuid.uuid4())
        payload = (
            '{"version":1,"operation_id":"'
            + operation_id
            + '","operation_id":"'
            + operation_id
            + '"}'
        ).encode("utf-8")

        reply = json.loads(self.service.reply_for_payload(self.peer, payload))

        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"]["code"], "invalid_json")
        self.assertIsNone(reply["operation_id"])
        self.assertEqual(self.backend.calls, [])

    def test_pathologically_nested_json_is_rejected_without_killing_worker(self) -> None:
        payload = ("[" * 1500 + "0" + "]" * 1500).encode("utf-8")

        reply = json.loads(self.service.reply_for_payload(self.peer, payload))

        self.assertFalse(reply["ok"])
        # Python 3.9 reaches its parser recursion guard; newer decoders can
        # construct this value iteratively and the request-shape guard rejects
        # the resulting array.  Both paths must remain structured and inert.
        self.assertIn(reply["error"]["code"], {"invalid_json", "invalid_request"})
        self.assertEqual(self.backend.calls, [])

    def test_same_operation_id_is_idempotent_and_conflicting_reuse_is_rejected(self) -> None:
        operation_id = str(uuid.uuid4())
        first = request_for(operation_id=operation_id)
        repeated = self.service.reply_for_document(self.peer, first.to_wire())
        second = self.service.reply_for_document(self.peer, first.to_wire())

        conflicting = request_for(
            resource_id=SECOND_CONTAINER_ID,
            operation_id=operation_id,
        )
        conflict_reply = self.service.reply_for_document(
            self.peer, conflicting.to_wire()
        )

        self.assertTrue(repeated["ok"])
        self.assertEqual(second, repeated)
        self.assertEqual(len(self.backend.calls), 1)
        self.assertFalse(conflict_reply["ok"])
        self.assertEqual(conflict_reply["operation_id"], operation_id)
        self.assertEqual(
            conflict_reply["error"]["code"], "operation_id_conflict"
        )


class SingleWriterConcurrencyTests(unittest.TestCase):
    def _run_reply(
        self,
        service: BrokerService,
        peer: PeerCredentials,
        request: BrokerRequest,
        replies: list[dict[str, Any]],
        failures: list[BaseException],
    ) -> None:
        try:
            replies.append(service.reply_for_document(peer, request.to_wire()))
        except BaseException as exc:  # retain worker failures in timeout assertions
            failures.append(exc)

    def test_unrelated_mutations_progress_concurrently(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        backend = RecordingBackend(entered=entered, release=release)
        service, writer = service_for(backend)
        peer = peer_for()
        replies: list[dict[str, Any]] = []
        failures: list[BaseException] = []

        first = threading.Thread(
            target=self._run_reply,
            args=(service, peer, request_for(), replies, failures),
        )
        second = threading.Thread(
            target=self._run_reply,
            args=(
                service,
                peer,
                request_for(resource_id=SECOND_CONTAINER_ID),
                replies,
                failures,
            ),
        )
        first.start()
        self.assertTrue(
            entered.wait(timeout=1.0),
            "first worker did not reach the blocking mutation backend",
        )
        second.start()
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline and backend.max_active < 2:
            time.sleep(0.01)
        if backend.max_active < 2:
            release.set()
            first.join(timeout=1.0)
            second.join(timeout=1.0)
            self.fail(
                "unrelated second worker did not reach its host-action boundary; "
                + f"worker failures={failures!r}"
            )

        self.assertTrue(writer.is_active)
        self.assertEqual(backend.max_active, 2)
        release.set()
        first.join(timeout=2.0)
        second.join(timeout=2.0)

        self.assertFalse(first.is_alive(), failures)
        self.assertFalse(second.is_alive(), failures)
        self.assertEqual(failures, [])
        self.assertFalse(backend.wait_timed_out)
        self.assertEqual(len(backend.calls), 2)
        self.assertEqual(backend.max_active, 2)
        self.assertEqual(len(replies), 2)
        self.assertTrue(all(reply["ok"] for reply in replies), replies)

    def test_concurrent_duplicate_operation_executes_backend_once(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        backend = RecordingBackend(entered=entered, release=release)
        service, writer = service_for(backend)
        peer = peer_for()
        request = request_for()
        replies: list[dict[str, Any]] = []
        failures: list[BaseException] = []

        threads = [
            threading.Thread(
                target=self._run_reply,
                args=(service, peer, request, replies, failures),
            )
            for _ in range(2)
        ]
        threads[0].start()
        self.assertTrue(
            entered.wait(timeout=1.0),
            "first duplicate did not reach the mutation backend",
        )
        threads[1].start()
        queued = writer.wait_for_queued(1, timeout=1.0)
        release.set()
        for thread in threads:
            thread.join(timeout=2.0)

        self.assertTrue(queued, f"worker failures={failures!r}")
        self.assertTrue(all(not thread.is_alive() for thread in threads), failures)
        self.assertEqual(failures, [])
        self.assertFalse(backend.wait_timed_out)
        self.assertEqual(len(backend.calls), 1)
        self.assertEqual(len(replies), 2)
        self.assertEqual(replies[0], replies[1])

    def test_different_operations_on_one_exact_resource_serialize(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        backend = RecordingBackend(entered=entered, release=release)
        service, writer = service_for(backend)
        peer = peer_for()
        replies: list[dict[str, Any]] = []
        failures: list[BaseException] = []
        first = threading.Thread(
            target=self._run_reply,
            args=(service, peer, request_for(BrokerOperation.DOCKER_STOP), replies, failures),
        )
        second = threading.Thread(
            target=self._run_reply,
            args=(service, peer, request_for(BrokerOperation.DOCKER_START), replies, failures),
        )
        first.start()
        self.assertTrue(entered.wait(timeout=1.0))
        second.start()
        queued = writer.wait_for_queued(1, timeout=1.0)
        self.assertTrue(queued, failures)
        self.assertEqual(backend.max_active, 1)
        release.set()
        first.join(timeout=2.0)
        second.join(timeout=2.0)
        self.assertEqual(failures, [])
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(backend.max_active, 1)


class RuntimeAndSocketIntegrationTests(unittest.TestCase):
    def test_runtime_directory_rejects_world_access_group_write_and_symlink(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o700)

            os.chmod(runtime, 0o755)
            with self.assertRaises(BrokerError) as world_access:
                validate_runtime_directory(runtime, expected_uid=os.geteuid())
            self.assertEqual(world_access.exception.code, "unsafe_runtime_directory")

            os.chmod(runtime, 0o770)
            with self.assertRaises(BrokerError) as group_write:
                validate_runtime_directory(runtime, expected_uid=os.geteuid())
            self.assertEqual(group_write.exception.code, "unsafe_runtime_directory")

            os.chmod(runtime, 0o750)
            validate_runtime_directory(runtime, expected_uid=os.geteuid())

            alias = root / "runtime-alias"
            alias.symlink_to(runtime, target_is_directory=True)
            with self.assertRaises(BrokerError) as symlink:
                validate_runtime_directory(alias, expected_uid=os.geteuid())
            self.assertEqual(symlink.exception.code, "unsafe_runtime_directory")

    def test_runtime_directory_rejects_replaceable_ancestor_and_missing_group_traversal(self) -> None:
        backend = RecordingBackend()
        service, _ = service_for(backend)
        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o750)
            os.chmod(runtime, 0o750)
            os.chmod(root, 0o777)
            try:
                with self.assertRaises(BrokerError) as ancestor:
                    validate_runtime_directory(runtime, expected_uid=os.geteuid())
                self.assertEqual(
                    ancestor.exception.code, "unsafe_runtime_directory"
                )
            finally:
                os.chmod(root, 0o700)

            os.chmod(runtime, 0o700)
            server = UnixBrokerServer(runtime / "broker.sock", service)
            with self.assertRaises(BrokerError) as traversal:
                server.start()
            self.assertEqual(traversal.exception.code, "unsafe_runtime_directory")

    def test_server_uses_real_peer_credentials_and_protected_socket(self) -> None:
        backend = RecordingBackend()
        service, _ = service_for(backend)
        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o750)
            os.chmod(runtime, 0o750)
            socket_path = runtime / "broker.sock"
            server = UnixBrokerServer(socket_path, service)
            try:
                server.start()
                request = request_for()
                reply = BrokerClient(
                    socket_path,
                    expected_broker_uid=os.geteuid(),
                    expected_socket_gid=os.getegid(),
                ).call(request)

                self.assertTrue(reply["ok"], reply)
                self.assertEqual(reply["operation_id"], request.operation_id)
                self.assertEqual(len(backend.calls), 1)
                self.assertEqual(backend.calls[0].peer.uid, os.geteuid())
                socket_info = os.lstat(socket_path)
                self.assertTrue(stat.S_ISSOCK(socket_info.st_mode))
                self.assertEqual(stat.S_IMODE(socket_info.st_mode), 0o660)
            finally:
                server.close()
            self.assertFalse(socket_path.exists())

    def test_client_rejects_wrong_broker_owner_and_socket_group(self) -> None:
        backend = RecordingBackend()
        service, _ = service_for(backend)
        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o750)
            os.chmod(runtime, 0o750)
            socket_path = runtime / "broker.sock"
            with UnixBrokerServer(socket_path, service):
                request = request_for()
                with self.assertRaises(BrokerError) as owner:
                    BrokerClient(
                        socket_path,
                        expected_broker_uid=os.geteuid() + 10_000,
                        expected_socket_gid=os.getegid(),
                    ).call(request)
                self.assertEqual(owner.exception.code, "unsafe_runtime_directory")

                with self.assertRaises(BrokerError) as group:
                    BrokerClient(
                        socket_path,
                        expected_broker_uid=os.geteuid(),
                        expected_socket_gid=os.getegid() + 10_000,
                    ).call(request)
                self.assertEqual(group.exception.code, "broker_identity_mismatch")
            self.assertEqual(backend.calls, [])

    def test_client_rejects_socket_inode_change_during_connect(self) -> None:
        backend = RecordingBackend()
        service, _ = service_for(backend)
        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o750)
            os.chmod(runtime, 0o750)
            socket_path = runtime / "broker.sock"
            with UnixBrokerServer(socket_path, service):
                real_validate = broker_module._validate_client_socket
                calls = 0

                def changed_identity(*args: Any, **kwargs: Any) -> os.stat_result:
                    nonlocal calls
                    calls += 1
                    info = real_validate(*args, **kwargs)
                    if calls == 1:
                        return info
                    values = list(info)
                    values[1] = int(info.st_ino) + 1
                    return os.stat_result(values)

                with mock.patch.object(
                    broker_module,
                    "_validate_client_socket",
                    side_effect=changed_identity,
                ):
                    with self.assertRaises(BrokerError) as changed:
                        BrokerClient(
                            socket_path,
                            expected_broker_uid=os.geteuid(),
                            expected_socket_gid=os.getegid(),
                        ).call(request_for())
                self.assertEqual(
                    changed.exception.code, "broker_identity_mismatch"
                )
            self.assertEqual(backend.calls, [])

    def test_capacity_overflow_is_bounded_and_shutdown_drains_slow_clients(self) -> None:
        backend = RecordingBackend()
        service, _ = service_for(backend)
        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o750)
            os.chmod(runtime, 0o750)
            socket_path = runtime / "broker.sock"
            server = UnixBrokerServer(
                socket_path,
                service,
                max_clients=1,
                request_timeout_seconds=30.0,
                shutdown_timeout_seconds=1.0,
            )
            server.start()
            first = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                first.connect(str(socket_path))
                deadline = time.monotonic() + 1.0
                while time.monotonic() < deadline:
                    with server._clients_lock:
                        if len(server._client_threads) == 1:
                            break
                    time.sleep(0.01)
                busy = BrokerClient(
                    socket_path,
                    expected_broker_uid=os.geteuid(),
                    expected_socket_gid=os.getegid(),
                    timeout_seconds=1.0,
                ).call(request_for())
                self.assertEqual(busy["error"]["code"], "server_busy")

                accept_thread = server._accept_thread
                started = time.monotonic()
                server.close()
                self.assertLess(time.monotonic() - started, 1.0)
                self.assertIsNotNone(accept_thread)
                self.assertFalse(accept_thread.is_alive())
                with server._clients_lock:
                    self.assertEqual(server._client_threads, set())
                    self.assertEqual(server._client_connections, set())
            finally:
                first.close()
                if server._socket_identity is not None:
                    server.close()
            self.assertEqual(backend.calls, [])

    def test_client_reads_authenticated_busy_reply_after_send_reports_broken_pipe(
        self,
    ) -> None:
        """A pre-request overload reply must survive the Unix close/send race."""

        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o750)
            os.chmod(runtime, 0o750)
            socket_path = runtime / "broker.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(socket_path))
            os.chmod(socket_path, 0o660)
            listener.listen(1)
            reply_sent = threading.Event()
            server_errors: list[BaseException] = []

            def reject_at_capacity() -> None:
                try:
                    connection, _ = listener.accept()
                    with connection:
                        payload = json.dumps(
                            {
                                "version": broker_module.PROTOCOL_VERSION,
                                "operation_id": None,
                                "ok": False,
                                "error": {
                                    "code": "server_busy",
                                    "message": "Broker capacity is exhausted.",
                                },
                            },
                            separators=(",", ":"),
                            sort_keys=True,
                        ).encode("utf-8")
                        connection.sendall(struct.pack("!I", len(payload)) + payload)
                except BaseException as exc:  # surfaced in the parent assertion
                    server_errors.append(exc)
                finally:
                    reply_sent.set()

            reject_thread = threading.Thread(target=reject_at_capacity)
            reject_thread.start()
            try:
                real_validate = broker_module._validate_client_socket
                validation_calls = 0

                def wait_for_rejection(*args: Any, **kwargs: Any) -> os.stat_result:
                    nonlocal validation_calls
                    info = real_validate(*args, **kwargs)
                    validation_calls += 1
                    if validation_calls == 2:
                        self.assertTrue(reply_sent.wait(timeout=1.0))
                    return info

                with mock.patch.object(
                    broker_module,
                    "_validate_client_socket",
                    side_effect=wait_for_rejection,
                ), mock.patch.object(
                    broker_module,
                    "_send_frame",
                    side_effect=BrokenPipeError("peer closed before request send"),
                ):
                    reply = BrokerClient(
                        socket_path,
                        expected_broker_uid=os.geteuid(),
                        expected_socket_gid=os.getegid(),
                    ).call(request_for())
                self.assertFalse(reply["ok"])
                self.assertEqual(reply["error"]["code"], "server_busy")
            finally:
                listener.close()
                reject_thread.join(timeout=1.0)
            self.assertFalse(reject_thread.is_alive())
            self.assertEqual(server_errors, [])

    def test_partial_frame_timeout_releases_capacity_for_valid_request(self) -> None:
        backend = RecordingBackend()
        service, _ = service_for(backend)
        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o750)
            os.chmod(runtime, 0o750)
            socket_path = runtime / "broker.sock"
            with UnixBrokerServer(
                socket_path,
                service,
                max_clients=1,
                request_timeout_seconds=0.1,
            ):
                slow = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                slow.connect(str(socket_path))
                slow.sendall(struct.pack("!I", 100) + b"{")
                time.sleep(0.25)
                slow.close()
                request = request_for()
                reply = BrokerClient(
                    socket_path,
                    expected_broker_uid=os.geteuid(),
                    expected_socket_gid=os.getegid(),
                ).call(request)
                self.assertTrue(reply["ok"], reply)
            self.assertEqual(len(backend.calls), 1)

    def test_oversized_declared_frame_is_rejected_without_body_or_dispatch(self) -> None:
        backend = RecordingBackend()
        service, _ = service_for(backend)
        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o750)
            os.chmod(runtime, 0o750)
            socket_path = runtime / "broker.sock"
            with UnixBrokerServer(
                socket_path, service, max_message_bytes=256
            ):
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.settimeout(1.0)
                client.connect(str(socket_path))
                client.sendall(struct.pack("!I", 257))
                header = _receive_exact_for_test(client, 4)
                size = struct.unpack("!I", header)[0]
                reply = json.loads(_receive_exact_for_test(client, size))
                client.close()
            self.assertEqual(reply["error"]["code"], "request_too_large")
            self.assertEqual(backend.calls, [])

    def test_real_unknown_peer_is_rejected_before_mutation(self) -> None:
        backend = RecordingBackend()
        configured_uid = os.geteuid() + 10000
        service, _ = service_for(backend, uid=configured_uid)
        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o750)
            os.chmod(runtime, 0o750)
            socket_path = runtime / "broker.sock"
            with UnixBrokerServer(socket_path, service):
                request = request_for()
                reply = BrokerClient(
                    socket_path,
                    expected_broker_uid=os.geteuid(),
                    expected_socket_gid=os.getegid(),
                ).call(request)

        self.assertFalse(reply["ok"])
        self.assertEqual(reply["operation_id"], request.operation_id)
        self.assertEqual(reply["error"]["code"], "peer_not_authorized")
        self.assertEqual(backend.calls, [])

    def test_server_never_replaces_an_existing_socket_path(self) -> None:
        backend = RecordingBackend()
        service, _ = service_for(backend)
        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o750)
            os.chmod(runtime, 0o750)
            socket_path = runtime / "broker.sock"
            socket_path.write_text("operator-owned sentinel", encoding="utf-8")
            server = UnixBrokerServer(socket_path, service)

            with self.assertRaises(BrokerError) as raised:
                server.start()

            self.assertEqual(raised.exception.code, "socket_path_exists")
            self.assertEqual(
                socket_path.read_text(encoding="utf-8"), "operator-owned sentinel"
            )

    def test_client_rejects_a_reply_bound_to_another_operation(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            socket_path = root / "malicious.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(socket_path))
            os.chmod(socket_path, 0o660)
            listener.listen(1)
            failures: list[BaseException] = []

            def fake_server() -> None:
                try:
                    connection, _ = listener.accept()
                    with connection:
                        header = _receive_exact_for_test(connection, 4)
                        request_size = struct.unpack("!I", header)[0]
                        _receive_exact_for_test(connection, request_size)
                        reply = json.dumps(
                            {
                                "version": 1,
                                "operation_id": str(uuid.uuid4()),
                                "ok": True,
                                "result": {},
                            },
                            separators=(",", ":"),
                        ).encode("utf-8")
                        connection.sendall(struct.pack("!I", len(reply)) + reply)
                except BaseException as exc:
                    failures.append(exc)
                finally:
                    listener.close()

            thread = threading.Thread(target=fake_server)
            thread.start()
            request = request_for()
            with self.assertRaises(BrokerError) as raised:
                BrokerClient(
                    socket_path,
                    expected_broker_uid=os.geteuid(),
                    expected_socket_gid=os.getegid(),
                ).call(request)
            thread.join(timeout=2.0)

            self.assertFalse(thread.is_alive(), failures)
            self.assertEqual(failures, [])
            self.assertEqual(raised.exception.code, "reply_operation_mismatch")
        self.assertEqual(raised.exception.operation_id, request.operation_id)


class StoreBackedBrokerTests(unittest.TestCase):
    def test_postgres_backup_restore_registers_strong_safety_evidence(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, _unused = seed_store_backed_broker(root)
            seed_postgres_database(persistence)
            actions = RecordingPostgresHostActions()
            service = store_backed_service(persistence, actions)

            backup = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.DATABASE_BACKUP,
                    arguments={"database_name": DATABASE_NAME},
                ).to_wire(),
            )
            self.assertTrue(backup["ok"], backup)
            self.assertEqual(backup["result"]["verification_status"], "strong")
            backup_id = backup["result"]["database_backup_id"]

            restore = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.DATABASE_RESTORE,
                    arguments={
                        "database_name": DATABASE_NAME,
                        "database_backup_id": backup_id,
                        "explicit": True,
                    },
                ).to_wire(),
            )
            self.assertTrue(restore["ok"], restore)
            self.assertTrue(restore["result"]["transactional"])
            self.assertEqual(restore["result"]["status"], "restored")
            self.assertEqual(
                actions.postgres_calls,
                [
                    ("backup", "a" * 64, DATABASE_NAME),
                    ("restore", "a" * 64, DATABASE_NAME),
                ],
            )
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    safety = connection.execute(
                        """
                        SELECT verification_status, source_container_id,
                               source_database_name, status
                        FROM database_backups WHERE database_backup_id = ?
                        """,
                        (restore["result"]["safety_database_backup_id"],),
                    ).fetchone()
                    event = connection.execute(
                        """
                        SELECT database_backup_id, safety_database_backup_id,
                               target_container_id, target_database_name
                        FROM database_restore_events WHERE restore_event_id = ?
                        """,
                        (restore["result"]["restore_event_id"],),
                    ).fetchone()
            self.assertEqual(
                (
                    safety["verification_status"],
                    safety["source_container_id"],
                    safety["source_database_name"],
                    safety["status"],
                ),
                ("strong", "a" * 64, DATABASE_NAME, "available"),
            )
            self.assertEqual(
                (
                    event["database_backup_id"],
                    event["safety_database_backup_id"],
                    event["target_container_id"],
                    event["target_database_name"],
                ),
                (
                    backup_id,
                    restore["result"]["safety_database_backup_id"],
                    "a" * 64,
                    DATABASE_NAME,
                ),
            )

    def test_postgres_authority_mismatches_and_fence_fail_before_runner(self) -> None:
        cases = ("uid", "repo", "resource", "database", "fence", "container-drift")
        for case in cases:
            with self.subTest(case=case), CanonicalTemporaryDirectory() as root:
                persistence, _unused = seed_store_backed_broker(root)
                seed_postgres_database(persistence)
                if case == "container-drift":
                    persistence = DatabaseTargetDriftPersistence(
                        persistence.database_path, expected_uid=os.geteuid()
                    )
                actions = RecordingPostgresHostActions()
                service = store_backed_service(persistence, actions)
                request = request_for(
                    BrokerOperation.DATABASE_BACKUP,
                    arguments={"database_name": DATABASE_NAME},
                )
                peer = peer_for()
                document = request.to_wire()
                if case == "uid":
                    peer = peer_for(os.geteuid() + 10_000)
                elif case == "repo":
                    document["project_id"] = "repo-foreign"
                elif case == "resource":
                    document["resource_id"] = SECOND_CONTAINER_ID
                elif case == "database":
                    document["arguments"] = {"database_name": "foreign"}
                elif case == "fence":
                    with CoordinatorStore.open(
                        persistence.database_path, expected_uid=os.geteuid()
                    ) as store:
                        with store.immediate_transaction() as connection:
                            connection.execute(
                                """
                                UPDATE repository_installations
                                SET status = 'disabled', startup_fenced = 1,
                                    updated_at = ? WHERE repo_id = ?
                                """,
                                (utc_timestamp(), PROJECT_ID),
                            )

                reply = service.reply_for_document(peer, document)

                self.assertFalse(reply["ok"], reply)
                self.assertEqual(actions.postgres_calls, [])

    def test_postgres_host_failure_is_durable_and_never_registers_backup(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, _unused = seed_store_backed_broker(root)
            seed_postgres_database(persistence)
            actions = RecordingPostgresHostActions(fail_backup=True)
            service = store_backed_service(persistence, actions)
            request = request_for(
                BrokerOperation.DATABASE_BACKUP,
                arguments={"database_name": DATABASE_NAME},
            )

            reply = service.reply_for_document(peer_for(), request.to_wire())

            self.assertFalse(reply["ok"], reply)
            self.assertEqual(reply["error"]["code"], "mutation_failed")
            self.assertEqual(len(actions.postgres_calls), 1)
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    operation = connection.execute(
                        "SELECT status FROM operations WHERE operation_id = ?",
                        (request.operation_id,),
                    ).fetchone()
                    backup_count = connection.execute(
                        "SELECT COUNT(*) FROM database_backups"
                    ).fetchone()[0]
            self.assertEqual(operation["status"], "failed")
            self.assertEqual(backup_count, 0)

    def test_postgres_registry_uncertainty_replays_journal_without_second_dump(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, _unused = seed_store_backed_broker(root)
            seed_postgres_database(persistence)
            actions = RecordingPostgresHostActions()
            original_register = persistence.register_database_backup_result
            attempts = 0

            def flaky_register(*args: Any, **kwargs: Any) -> dict[str, Any]:
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    raise sqlite3.OperationalError("injected registry commit failure")
                return original_register(*args, **kwargs)

            with mock.patch.object(
                persistence,
                "register_database_backup_result",
                side_effect=flaky_register,
            ):
                service = store_backed_service(persistence, actions)
                request = request_for(
                    BrokerOperation.DATABASE_BACKUP,
                    arguments={"database_name": DATABASE_NAME},
                )
                uncertain = service.reply_for_document(
                    peer_for(), request.to_wire()
                )
                replayed = service.reply_for_document(
                    peer_for(), request.to_wire()
                )

            self.assertFalse(uncertain["ok"], uncertain)
            self.assertEqual(
                uncertain["error"]["code"], "operation_outcome_uncertain"
            )
            self.assertTrue(replayed["ok"], replayed)
            self.assertEqual(attempts, 2)
            self.assertEqual(
                actions.postgres_calls,
                [("backup", "a" * 64, DATABASE_NAME)],
            )
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    operation = connection.execute(
                        "SELECT status FROM operations WHERE operation_id = ?",
                        (request.operation_id,),
                    ).fetchone()
                    journal_count = connection.execute(
                        """
                        SELECT COUNT(*) FROM broker_database_host_results
                        WHERE operation_id = ?
                        """,
                        (request.operation_id,),
                    ).fetchone()[0]
                    backup_count = connection.execute(
                        "SELECT COUNT(*) FROM database_backups"
                    ).fetchone()[0]
            self.assertEqual(operation["status"], "succeeded")
            self.assertEqual(journal_count, 1)
            self.assertEqual(backup_count, 1)

    def test_repository_removal_and_reinstall_execute_only_in_service_store(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        "DELETE FROM repository_memberships WHERE repo_id = ?",
                        (PROJECT_ID,),
                    )
            for operation in (
                BrokerOperation.REPOSITORY_PLAN_REMOVE,
                BrokerOperation.REPOSITORY_REMOVE,
                BrokerOperation.REPOSITORY_REINSTALL,
            ):
                persistence.grant_lifecycle(
                    uid=os.geteuid(), repo_id=PROJECT_ID, operation=operation
                )
            service = store_backed_service(persistence, actions)

            planned = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.REPOSITORY_PLAN_REMOVE,
                    resource_id=PROJECT_ID,
                    arguments={"reason": "retire this checkout"},
                ).to_wire(),
            )
            self.assertTrue(planned["ok"], planned)
            self.assertEqual(planned["result"]["repo_id"], PROJECT_ID)
            plan_observation = planned["result"]["broker_observation"]
            self.assertTrue(plan_observation["docker_available"])
            self.assertRegex(
                plan_observation["capability_fingerprint"], r"^sha256:[0-9a-f]{64}$"
            )
            self.assertRegex(
                plan_observation["material_fingerprint"], r"^[0-9a-f]{64}$"
            )
            removed = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.REPOSITORY_REMOVE,
                    resource_id=PROJECT_ID,
                    arguments={
                        "plan_id": planned["result"]["plan_id"],
                        "plan_fingerprint": planned["result"]["fingerprint"],
                    },
                ).to_wire(),
            )
            self.assertTrue(removed["ok"], removed)
            self.assertTrue(removed["result"]["hidden"])
            self.assertEqual(removed["result"]["fence"], "disabled")
            self.assertEqual(
                removed["result"]["broker_observation"]["plan_basis"],
                plan_observation,
            )
            self.assertNotEqual(
                removed["result"]["broker_observation"]["apply_time"]["snapshot_id"],
                plan_observation["snapshot_id"],
            )
            self.assertEqual(actions.calls, [])
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    installation = connection.execute(
                        """
                        SELECT status, startup_fenced
                        FROM repository_installations WHERE repo_id = ?
                        """,
                        (PROJECT_ID,),
                    ).fetchone()
            self.assertEqual(
                (installation["status"], installation["startup_fenced"]),
                ("disabled", 1),
            )

            reinstalled = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.REPOSITORY_REINSTALL,
                    resource_id=PROJECT_ID,
                    arguments={"reason": "explicit reinstall", "explicit": True},
                ).to_wire(),
            )
            self.assertTrue(reinstalled["ok"], reinstalled)
            self.assertEqual(reinstalled["result"]["status"], "installed")
            self.assertFalse(reinstalled["result"]["started"])

    def test_repository_remove_replans_generation_churn_and_retries_confirmed_id(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            now = utc_timestamp()
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        "UPDATE docker_observations SET restart_policy = 'always'"
                    )
                    resources = list(
                        connection.execute(
                            """
                            SELECT host_resource_id FROM repository_memberships
                            WHERE repo_id = ? AND resource_kind = 'container'
                            ORDER BY host_resource_id
                            """,
                            (PROJECT_ID,),
                        )
                    )
                    for index, row in enumerate(resources):
                        resource_id = str(row["host_resource_id"])
                        connection.execute(
                            """
                            INSERT INTO startup_policies(
                                policy_id, repo_id, resource_kind, resource_id,
                                policy_kind, current_value, desired_disabled_value,
                                immutable_fingerprint, generation, updated_at
                            ) VALUES (?, ?, 'container', ?, 'docker_restart',
                                      'always', 'no', ?, 0, ?)
                            """,
                            (
                                f"policy-generation-churn-{index}",
                                PROJECT_ID,
                                resource_id,
                                "sha256:" + "a" * 64,
                                now,
                            ),
                        )
            for operation in (
                BrokerOperation.REPOSITORY_PLAN_REMOVE,
                BrokerOperation.REPOSITORY_REMOVE,
            ):
                persistence.grant_lifecycle(
                    uid=os.geteuid(), repo_id=PROJECT_ID, operation=operation
                )
            observations = 0

            def observer(store: CoordinatorStore) -> Mapping[str, Any]:
                nonlocal observations
                observations += 1
                evidence = _committed_available_observer(store)
                if observations >= 2:
                    with store.immediate_transaction() as connection:
                        connection.execute(
                            """
                            UPDATE control_bindings
                            SET generation = generation + 1, updated_at = ?
                            WHERE repo_id = ?
                            """,
                            (utc_timestamp(), PROJECT_ID),
                        )
                return evidence

            adapter = ExactLifecycleAdapter()
            backend = StoreBackedMutationBackend(
                persistence,
                actions,
                lifecycle_adapter=adapter,
                observe_before_lifecycle_plan=observer,
            )
            service = BrokerService(
                StoreBackedAuthorizer(persistence), SerializedMutationWriter(backend)
            )
            planned = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.REPOSITORY_PLAN_REMOVE,
                    resource_id=PROJECT_ID,
                    arguments={"reason": "generation churn regression"},
                ).to_wire(),
            )
            self.assertTrue(planned["ok"], planned)
            arguments = {
                "plan_id": planned["result"]["plan_id"],
                "plan_fingerprint": planned["result"]["fingerprint"],
            }
            removed = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.REPOSITORY_REMOVE,
                    resource_id=PROJECT_ID,
                    arguments=arguments,
                ).to_wire(),
            )
            self.assertTrue(removed["ok"], removed)
            self.assertTrue(removed["result"]["hidden"])
            self.assertNotEqual(
                removed["result"]["plan_id"], planned["result"]["plan_id"]
            )
            effects = list(adapter.calls)

            repeated = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.REPOSITORY_REMOVE,
                    resource_id=PROJECT_ID,
                    arguments=arguments,
                ).to_wire(),
            )

            self.assertTrue(repeated["ok"], repeated)
            self.assertEqual(repeated["result"]["status"], "already_complete")
            self.assertEqual(
                repeated["result"]["plan_id"], removed["result"]["plan_id"]
            )
            self.assertEqual(adapter.calls, effects)

    def test_repository_remove_refreshes_and_rejects_new_attributed_container(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            now = utc_timestamp()
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        "UPDATE docker_observations SET restart_policy = 'always'"
                    )
                    for resource_id in (CONTAINER_ID, SECOND_CONTAINER_ID):
                        connection.execute(
                            """
                            INSERT INTO startup_policies(
                                policy_id, repo_id, resource_kind, resource_id,
                                policy_kind, current_value, desired_disabled_value,
                                immutable_fingerprint, generation, updated_at
                            ) VALUES (?, ?, 'container', ?, 'docker_restart',
                                      'always', 'no', ?, 0, ?)
                            """,
                            (
                                "policy-" + resource_id,
                                PROJECT_ID,
                                resource_id,
                                "sha256:" + "a" * 64,
                                now,
                            ),
                        )
            for operation in (
                BrokerOperation.REPOSITORY_PLAN_REMOVE,
                BrokerOperation.REPOSITORY_REMOVE,
            ):
                persistence.grant_lifecycle(
                    uid=os.geteuid(), repo_id=PROJECT_ID, operation=operation
                )

            observations = 0

            def observer(store: CoordinatorStore) -> Mapping[str, Any]:
                nonlocal observations
                observations += 1
                evidence = _committed_available_observer(store)
                if observations == 2:
                    timestamp = utc_timestamp()
                    with store.immediate_transaction() as connection:
                        connection.execute(
                            """
                            INSERT INTO docker_resources(
                                docker_resource_id, engine_id, full_container_id,
                                current_name, created_at, updated_at
                            ) VALUES ('container-after-plan', ?, ?,
                                      'after-plan', ?, ?)
                            """,
                            (ENGINE_ID, "c" * 64, timestamp, timestamp),
                        )
                        connection.execute(
                            """
                            INSERT INTO docker_observations(
                                docker_resource_id, lifecycle, restart_policy,
                                sampled_at, observation_fingerprint
                            ) VALUES ('container-after-plan', 'running', 'always',
                                      ?, 'after-plan-observation')
                            """,
                            (timestamp,),
                        )
                        connection.execute(
                            """
                            INSERT INTO control_bindings(
                                binding_id, repo_id, resource_kind, resource_id,
                                source_id, capability, provenance, authority_state,
                                priority, generation, created_at, updated_at
                            ) VALUES ('control-after-plan', ?, 'container',
                                      'container-after-plan', ?, 'lifecycle',
                                      'fixture', 'authoritative', 100, 0, ?, ?)
                            """,
                            (PROJECT_ID, SOURCE_ID, timestamp, timestamp),
                        )
                        connection.execute(
                            """
                            INSERT INTO repository_memberships(
                                membership_id, repo_id, resource_kind,
                                host_resource_id, immutable_fingerprint,
                                control_binding_id, created_at
                            ) VALUES ('membership-after-plan', ?, 'container',
                                      'container-after-plan', 'after-plan-immutable',
                                      'control-after-plan', ?)
                            """,
                            (PROJECT_ID, timestamp),
                        )
                        connection.execute(
                            """
                            INSERT INTO startup_policies(
                                policy_id, repo_id, resource_kind, resource_id,
                                policy_kind, current_value,
                                desired_disabled_value, immutable_fingerprint,
                                generation, updated_at
                            ) VALUES ('policy-after-plan', ?, 'container',
                                      'container-after-plan', 'docker_restart',
                                      'always', 'no', ?, 0, ?)
                            """,
                            (PROJECT_ID, "sha256:" + "b" * 64, timestamp),
                        )
                return evidence

            adapter = ExactLifecycleAdapter()
            backend = StoreBackedMutationBackend(
                persistence,
                actions,
                lifecycle_adapter=adapter,
                observe_before_lifecycle_plan=observer,
            )
            service = BrokerService(
                StoreBackedAuthorizer(persistence), SerializedMutationWriter(backend)
            )
            planned = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.REPOSITORY_PLAN_REMOVE,
                    resource_id=PROJECT_ID,
                    arguments={"reason": "fresh apply regression"},
                ).to_wire(),
            )
            self.assertTrue(planned["ok"], planned)

            removed = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.REPOSITORY_REMOVE,
                    resource_id=PROJECT_ID,
                    arguments={
                        "plan_id": planned["result"]["plan_id"],
                        "plan_fingerprint": planned["result"]["fingerprint"],
                    },
                ).to_wire(),
            )
            self.assertFalse(removed["ok"], removed)
            self.assertEqual(removed["error"]["code"], "lifecycle_rejected")
            self.assertRegex(
                removed["error"]["message"],
                "changed after the plan|resources changed during current observation",
            )
            self.assertEqual(observations, 2)
            self.assertEqual(adapter.calls, [])
            self.assertEqual(actions.calls, [])
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    installation = connection.execute(
                        """
                        SELECT status, startup_fenced
                        FROM repository_installations WHERE repo_id = ?
                        """,
                        (PROJECT_ID,),
                    ).fetchone()
            self.assertEqual(
                (installation["status"], installation["startup_fenced"]),
                ("installed", 0),
            )

    def test_repository_lifecycle_requires_exact_project_target_and_grant(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            service = store_backed_service(persistence, actions)
            request = request_for(
                BrokerOperation.REPOSITORY_PLAN_REMOVE,
                resource_id=CONTAINER_ID,
                arguments={"reason": "wrong target"},
            )
            denied = service.reply_for_document(peer_for(), request.to_wire())
            self.assertFalse(denied["ok"], denied)
            self.assertEqual(denied["error"]["code"], "resource_access_denied")
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    self.assertIsNone(
                        connection.execute(
                            "SELECT 1 FROM broker_operation_requests WHERE operation_id = ?",
                            (request.operation_id,),
                        ).fetchone()
                    )

    def test_lifecycle_plan_refuses_unavailable_timeout_and_malformed_observation(self) -> None:
        def unavailable(store: CoordinatorStore) -> Mapping[str, Any]:
            evidence = dict(_committed_available_observer(store))
            with store.immediate_transaction(revision_kind="observation") as connection:
                connection.execute(
                    "UPDATE observation_capabilities SET docker_available = 0 WHERE snapshot_id = ?",
                    (evidence["snapshot_id"],),
                )
            evidence["docker_available"] = False
            return evidence

        def callback_claims_available_but_database_is_unavailable(
            store: CoordinatorStore,
        ) -> Mapping[str, Any]:
            evidence = dict(_committed_available_observer(store))
            with store.immediate_transaction(revision_kind="observation") as connection:
                connection.execute(
                    "UPDATE observation_capabilities SET docker_available = 0 WHERE snapshot_id = ?",
                    (evidence["snapshot_id"],),
                )
            return evidence

        def malformed(store: CoordinatorStore) -> Mapping[str, Any]:
            evidence = dict(_committed_available_observer(store))
            evidence.pop("capability_fingerprint")
            return evidence

        def timed_out(_store: CoordinatorStore) -> Mapping[str, Any]:
            raise TimeoutError("injected bounded Docker observation timeout")

        for label, observer in (
            ("unavailable", unavailable),
            (
                "callback-database-capability-mismatch",
                callback_claims_available_but_database_is_unavailable,
            ),
            ("malformed", malformed),
            ("timeout", timed_out),
        ):
            with self.subTest(label=label), CanonicalTemporaryDirectory() as root:
                persistence, actions = seed_store_backed_broker(root)
                with CoordinatorStore.open(
                    persistence.database_path, expected_uid=os.geteuid()
                ) as store:
                    with store.immediate_transaction() as connection:
                        connection.execute(
                            "DELETE FROM repository_memberships WHERE repo_id = ?",
                            (PROJECT_ID,),
                        )
                persistence.grant_lifecycle(
                    uid=os.geteuid(),
                    repo_id=PROJECT_ID,
                    operation=BrokerOperation.REPOSITORY_PLAN_REMOVE,
                )
                backend = StoreBackedMutationBackend(
                    persistence,
                    actions,
                    observe_before_lifecycle_plan=observer,
                )
                service = BrokerService(
                    StoreBackedAuthorizer(persistence),
                    SerializedMutationWriter(backend),
                )
                reply = service.reply_for_document(
                    peer_for(),
                    request_for(
                        BrokerOperation.REPOSITORY_PLAN_REMOVE,
                        resource_id=PROJECT_ID,
                        arguments={"reason": "must observe"},
                    ).to_wire(),
                )
                self.assertFalse(reply["ok"], reply)
                with CoordinatorStore.open(
                    persistence.database_path, expected_uid=os.geteuid()
                ) as store:
                    with store.read_transaction() as connection:
                        plans = connection.execute(
                            "SELECT COUNT(*) FROM operations WHERE kind = 'repository_decommission'"
                        ).fetchone()[0]
                self.assertEqual(plans, 0, reply)

    def test_standalone_retirement_routes_exact_host_effects_through_service(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            now = utc_timestamp()
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        DELETE FROM repository_memberships
                        WHERE host_resource_id = ? AND resource_kind = 'container'
                        """,
                        (SECOND_CONTAINER_ID,),
                    )
                    connection.execute(
                        "UPDATE control_bindings SET repo_id = NULL WHERE binding_id = ?",
                        (SECOND_CONTROL_ID,),
                    )
                    connection.execute(
                        """
                        UPDATE docker_observations
                        SET lifecycle = 'running', restart_policy = 'always',
                            sampled_at = ?, observation_fingerprint = 'standalone-running'
                        WHERE docker_resource_id = ?
                        """,
                        (now, SECOND_CONTAINER_ID),
                    )
                    connection.execute(
                        """
                        INSERT INTO unassigned_resources(
                            unassigned_id, host_id, resource_kind, resource_id,
                            display_name, reason_code, status, created_at, updated_at
                        ) VALUES ('unassigned-beta', ?, 'container', ?, 'beta',
                                  'name_only', 'active', ?, ?)
                        """,
                        (HOST_ID, SECOND_CONTAINER_ID, now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO startup_policies(
                            policy_id, repo_id, resource_kind, resource_id,
                            policy_kind, current_value, desired_disabled_value,
                            immutable_fingerprint, generation, updated_at
                        ) VALUES ('policy-beta-restart', NULL, 'container', ?,
                                  'docker_restart', 'always', 'no',
                                  'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                                  0, ?)
                        """,
                        (SECOND_CONTAINER_ID, now),
                    )
                exact = SQLiteLifecyclePersistence(store).resolve_standalone_resource(
                    ResourceKind.CONTAINER,
                    SECOND_CONTAINER_ID,
                    SECOND_CONTROL_ID,
                )
            for operation in (
                BrokerOperation.RESOURCE_PLAN_RETIRE,
                BrokerOperation.RESOURCE_RETIRE,
            ):
                persistence.grant_lifecycle(
                    uid=os.geteuid(), repo_id=PROJECT_ID, operation=operation
                )
                persistence.grant_lifecycle_resource(
                    uid=os.geteuid(),
                    repo_id=PROJECT_ID,
                    resource_kind=exact.kind.value,
                    resource_id=exact.resource_id,
                    control_binding_id=exact.control_binding_id,
                    immutable_fingerprint=exact.immutable_fingerprint,
                    ownership_fingerprint=exact.ownership_fingerprint,
                    operation=operation,
                )
            lifecycle_adapter = ExactLifecycleAdapter()
            observations = 0

            def generation_churning_observer(
                store: CoordinatorStore,
            ) -> Mapping[str, Any]:
                nonlocal observations
                observations += 1
                evidence = _committed_available_observer(store)
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        UPDATE control_bindings
                        SET generation = generation + 1, updated_at = ?
                        WHERE binding_id = ?
                        """,
                        (utc_timestamp(), SECOND_CONTROL_ID),
                    )
                return evidence

            backend = StoreBackedMutationBackend(
                persistence,
                actions,
                lifecycle_adapter=lifecycle_adapter,
                observe_before_lifecycle_plan=generation_churning_observer,
            )
            service = BrokerService(
                StoreBackedAuthorizer(persistence), SerializedMutationWriter(backend)
            )
            identity = {
                "resource_kind": exact.kind.value,
                "control_binding_id": exact.control_binding_id,
                "immutable_fingerprint": exact.immutable_fingerprint,
                "ownership_fingerprint": exact.ownership_fingerprint,
            }
            planned = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.RESOURCE_PLAN_RETIRE,
                    resource_id=SECOND_CONTAINER_ID,
                    arguments={**identity, "reason": "remove orphaned database"},
                ).to_wire(),
            )
            self.assertTrue(planned["ok"], planned)
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    controller = connection.execute(
                        "SELECT capability FROM control_bindings WHERE binding_id = ?",
                        (SECOND_CONTROL_ID,),
                    ).fetchone()
                    original_capability = str(controller["capability"])
                    connection.execute(
                        """
                        UPDATE control_bindings
                        SET capability = ?, generation = generation + 1, updated_at = ?
                        WHERE binding_id = ?
                        """,
                        (
                            original_capability + ":changed-controller",
                            utc_timestamp(),
                            SECOND_CONTROL_ID,
                        ),
                    )
            rejected_controller_change = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.RESOURCE_RETIRE,
                    resource_id=SECOND_CONTAINER_ID,
                    arguments={
                        **identity,
                        "plan_id": planned["result"]["plan_id"],
                        "plan_fingerprint": planned["result"]["fingerprint"],
                    },
                ).to_wire(),
            )
            self.assertFalse(
                rejected_controller_change["ok"], rejected_controller_change
            )
            self.assertEqual(
                rejected_controller_change["error"]["code"], "lifecycle_rejected"
            )
            self.assertEqual(lifecycle_adapter.calls, [])
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        UPDATE control_bindings
                        SET capability = ?, generation = generation + 1, updated_at = ?
                        WHERE binding_id = ?
                        """,
                        (original_capability, utc_timestamp(), SECOND_CONTROL_ID),
                    )
            retired = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.RESOURCE_RETIRE,
                    resource_id=SECOND_CONTAINER_ID,
                    arguments={
                        **identity,
                        "plan_id": planned["result"]["plan_id"],
                        "plan_fingerprint": planned["result"]["fingerprint"],
                    },
                ).to_wire(),
            )
            self.assertTrue(retired["ok"], retired)
            self.assertTrue(retired["result"]["hidden"])
            self.assertNotEqual(
                retired["result"]["plan_id"], planned["result"]["plan_id"]
            )
            self.assertEqual(lifecycle_adapter.calls, ["disable_policy", "stop"])
            self.assertEqual(actions.calls, [])
            effects = list(lifecycle_adapter.calls)
            repeated = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.RESOURCE_RETIRE,
                    resource_id=SECOND_CONTAINER_ID,
                    arguments={
                        **identity,
                        "plan_id": planned["result"]["plan_id"],
                        "plan_fingerprint": planned["result"]["fingerprint"],
                    },
                ).to_wire(),
            )
            self.assertTrue(repeated["ok"], repeated)
            self.assertEqual(repeated["result"]["status"], "already_complete")
            self.assertEqual(
                repeated["result"]["plan_id"], retired["result"]["plan_id"]
            )
            self.assertEqual(lifecycle_adapter.calls, effects)
            rejected_new_plan = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.RESOURCE_PLAN_RETIRE,
                    resource_id=SECOND_CONTAINER_ID,
                    arguments={**identity, "reason": "try to plan inactive resource"},
                ).to_wire(),
            )
            self.assertFalse(rejected_new_plan["ok"], rejected_new_plan)
            self.assertEqual(
                rejected_new_plan["error"]["code"], "resource_access_denied"
            )
            for changed_resource_id, changed_binding_id in (
                (SECOND_CONTAINER_ID + "-other", exact.control_binding_id),
                (SECOND_CONTAINER_ID, exact.control_binding_id + "-other"),
            ):
                rejected_changed_target = service.reply_for_document(
                    peer_for(),
                    request_for(
                        BrokerOperation.RESOURCE_RETIRE,
                        resource_id=changed_resource_id,
                        arguments={
                            **identity,
                            "control_binding_id": changed_binding_id,
                            "plan_id": planned["result"]["plan_id"],
                            "plan_fingerprint": planned["result"]["fingerprint"],
                        },
                    ).to_wire(),
                )
                self.assertFalse(
                    rejected_changed_target["ok"], rejected_changed_target
                )
                self.assertEqual(
                    rejected_changed_target["error"]["code"],
                    "resource_access_denied",
                )
            rejected_wrong_plan = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.RESOURCE_RETIRE,
                    resource_id=SECOND_CONTAINER_ID,
                    arguments={
                        **identity,
                        "plan_id": planned["result"]["plan_id"],
                        "plan_fingerprint": "sha256:" + "f" * 64,
                    },
                ).to_wire(),
            )
            self.assertFalse(rejected_wrong_plan["ok"], rejected_wrong_plan)
            self.assertEqual(
                rejected_wrong_plan["error"]["code"], "resource_access_denied"
            )
            persistence.grant_lifecycle_resource(
                uid=os.geteuid(),
                repo_id=PROJECT_ID,
                resource_kind=exact.kind.value,
                resource_id=exact.resource_id,
                control_binding_id=exact.control_binding_id,
                immutable_fingerprint=exact.immutable_fingerprint,
                ownership_fingerprint=exact.ownership_fingerprint,
                operation=BrokerOperation.RESOURCE_RETIRE,
                enabled=False,
            )
            rejected_revoked_retry = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.RESOURCE_RETIRE,
                    resource_id=SECOND_CONTAINER_ID,
                    arguments={
                        **identity,
                        "plan_id": planned["result"]["plan_id"],
                        "plan_fingerprint": planned["result"]["fingerprint"],
                    },
                ).to_wire(),
            )
            self.assertFalse(rejected_revoked_retry["ok"], rejected_revoked_retry)
            self.assertEqual(
                rejected_revoked_retry["error"]["code"], "resource_access_denied"
            )
            self.assertEqual(lifecycle_adapter.calls, effects)
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    retirement = connection.execute(
                        """
                        SELECT status FROM resource_retirements
                        WHERE host_resource_id = ?
                        """,
                        (SECOND_CONTAINER_ID,),
                    ).fetchone()
                    unassigned = connection.execute(
                        "SELECT status FROM unassigned_resources WHERE unassigned_id='unassigned-beta'"
                    ).fetchone()
            self.assertEqual(retirement["status"], "retired")
            self.assertEqual(unassigned["status"], "retired")

    def test_stale_database_generation_is_rejected_before_reservation(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            service = store_backed_service(persistence, actions)
            stale = BrokerRequest.create(
                account_id=ACCOUNT_ID,
                project_id=PROJECT_ID,
                resource_id=CONTAINER_ID,
                operation=BrokerOperation.DOCKER_STOP,
                authority_generation="stale-generation",
            )

            reply = service.reply_for_document(peer_for(), stale.to_wire())

            self.assertFalse(reply["ok"], reply)
            self.assertEqual(
                reply["error"]["code"], "broker_generation_mismatch", reply
            )
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    reserved = connection.execute(
                        "SELECT 1 FROM broker_operation_requests WHERE operation_id = ?",
                        (stale.operation_id,),
                    ).fetchone()
            self.assertIsNone(reserved)

    def test_production_runtime_factory_uses_real_socket_and_private_store(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            runtime_directory = root / "runtime"
            runtime_directory.mkdir(mode=0o750)
            os.chmod(runtime_directory, 0o750)
            socket_path = runtime_directory / "broker.sock"
            runtime = build_store_backed_broker_runtime(
                database_path=persistence.database_path,
                socket_path=socket_path,
                host_mutations=actions,
                service_uid=os.geteuid(),
                access_gid=os.getegid(),
                observe_before_lifecycle_plan=_committed_available_observer,
            )
            with runtime.server:
                request = request_for(BrokerOperation.DOCKER_STOP)
                reply = BrokerClient(
                    socket_path,
                    expected_broker_uid=os.geteuid(),
                    expected_socket_gid=os.getegid(),
                ).call(request)
            self.assertTrue(reply["ok"], reply)
            self.assertEqual(actions.calls[0][0:2], ("stop", CONTAINER_ID))
            self.assertEqual(
                stat.S_IMODE(os.lstat(persistence.database_path).st_mode), 0o600
            )
            self.assertEqual(
                stat.S_IMODE(os.lstat(persistence.database_path.parent).st_mode),
                0o700,
            )

    def test_port_policy_denies_privileged_and_out_of_range_before_operation(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            service = store_backed_service(persistence, actions)
            for port in (22, 3099, 3200):
                with self.subTest(port=port):
                    request = request_for(
                        BrokerOperation.PORT_LEASE,
                        resource_id=SERVER_ID,
                        arguments={
                            "requested_port": port,
                            "protocol": "tcp",
                            "ttl_seconds": 600,
                        },
                    )
                    reply = service.reply_for_document(
                        peer_for(), request.to_wire()
                    )
                    self.assertFalse(reply["ok"], reply)
                    self.assertEqual(reply["error"]["code"], "port_policy_denied")
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    self.assertEqual(
                        connection.execute(
                            "SELECT count(*) FROM broker_operation_requests"
                        ).fetchone()[0],
                        0,
                    )

    def test_allowed_port_boundaries_and_dynamic_owned_release(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            service = store_backed_service(persistence, actions)
            leases: list[dict[str, Any]] = []
            for port in (3100, 3199):
                request = request_for(
                    BrokerOperation.PORT_LEASE,
                    resource_id=SERVER_ID,
                    arguments={
                        "requested_port": port,
                        "protocol": "tcp",
                        "ttl_seconds": 600,
                    },
                )
                reply = service.reply_for_document(peer_for(), request.to_wire())
                self.assertTrue(reply["ok"], reply)
                self.assertEqual(reply["result"]["port"], port)
                leases.append(reply["result"])

            release = request_for(
                BrokerOperation.PORT_RELEASE,
                resource_id=leases[0]["lease_id"],
            )
            released = service.reply_for_document(peer_for(), release.to_wire())
            self.assertTrue(released["ok"], released)
            self.assertEqual(released["result"]["status"], "released")
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    statuses = {
                        row["lease_id"]: row["status"]
                        for row in connection.execute(
                            "SELECT lease_id, status FROM leases"
                        )
                    }
            self.assertEqual(statuses[leases[0]["lease_id"]], "released")
            self.assertEqual(statuses[leases[1]["lease_id"]], "active")

    def test_server_can_lease_its_own_durable_pinned_port(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            now = utc_timestamp()
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        INSERT INTO port_assignments(
                            assignment_id, host_id, repo_id, server_name, port,
                            status, generation, created_at, updated_at
                        ) VALUES ('assignment-web', ?, ?, 'web', 3105,
                                  'active', 0, ?, ?)
                        """,
                        (HOST_ID, PROJECT_ID, now, now),
                    )
            service = store_backed_service(persistence, actions)
            request = request_for(
                BrokerOperation.PORT_LEASE,
                resource_id=SERVER_ID,
                arguments={"protocol": "tcp", "ttl_seconds": 600},
            )
            reply = service.reply_for_document(peer_for(), request.to_wire())
            self.assertTrue(reply["ok"], reply)
            self.assertEqual(reply["result"]["port"], 3105)

    def test_host_listener_observation_skips_occupied_port_and_blocks_exact_request(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, _ = seed_store_backed_broker(root)
            actions = RecordingTypedHostActions(occupied_ports={3100})
            service = store_backed_service(persistence, actions)
            automatic = request_for(
                BrokerOperation.PORT_LEASE,
                resource_id=SERVER_ID,
                arguments={"protocol": "tcp", "ttl_seconds": 600},
            )
            reply = service.reply_for_document(peer_for(), automatic.to_wire())
            self.assertTrue(reply["ok"], reply)
            self.assertEqual(reply["result"]["port"], 3101)
            self.assertEqual(actions.port_observations[0][1], "tcp")
            self.assertEqual(actions.port_observations[0][0][:2], (3100, 3101))

        with CanonicalTemporaryDirectory() as root:
            persistence, _ = seed_store_backed_broker(root)
            actions = RecordingTypedHostActions(occupied_ports={3100})
            service = store_backed_service(persistence, actions)
            exact = request_for(
                BrokerOperation.PORT_LEASE,
                resource_id=SERVER_ID,
                arguments={
                    "requested_port": 3100,
                    "protocol": "tcp",
                    "ttl_seconds": 600,
                },
            )
            blocked = service.reply_for_document(peer_for(), exact.to_wire())
            self.assertFalse(blocked["ok"], blocked)
            self.assertEqual(blocked["error"]["code"], "port_unavailable")
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    self.assertEqual(
                        connection.execute(
                            "SELECT count(*) FROM leases"
                        ).fetchone()[0],
                        0,
                    )

    def test_existing_listener_adoption_is_service_verified_and_identity_bound(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, _ = seed_store_backed_broker(root)
            evidence = {
                "pid": 12345,
                "process_start_time": "2026-07-15T12:00:00Z",
                "canonical_cwd": "/repos/alpha/apps/web",
                "listener_port": 3107,
                "protocol": "tcp",
            }
            actions = RecordingTypedHostActions(
                occupied_ports={3107}, listener_evidence=evidence
            )
            service = store_backed_service(persistence, actions)
            request = request_for(
                BrokerOperation.PORT_LEASE,
                resource_id=SERVER_ID,
                arguments={
                    "requested_port": 3107,
                    "protocol": "tcp",
                    "ttl_seconds": 600,
                    "adopt_existing_listener": True,
                },
            )

            reply = service.reply_for_document(peer_for(), request.to_wire())

            self.assertTrue(reply["ok"], reply)
            self.assertEqual(reply["result"]["listener_identity"], evidence)
            self.assertEqual(
                actions.listener_observations,
                [
                    (3107, "/repos/alpha", "tcp"),
                    (3107, "/repos/alpha", "tcp"),
                ],
            )
            self.assertEqual(actions.port_observations, [])
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    lease = connection.execute(
                        "SELECT port, process_fingerprint FROM leases"
                    ).fetchone()
            self.assertEqual(int(lease["port"]), 3107)
            self.assertTrue(str(lease["process_fingerprint"]).startswith("sha256:"))

            # A completed idempotent replay returns durable truth without
            # requiring the adopted listener to remain observable forever.
            actions.listener_evidence = None
            replay = service.reply_for_document(peer_for(), request.to_wire())
            self.assertTrue(replay["ok"], replay)
            self.assertEqual(replay["result"], reply["result"])
            self.assertEqual(len(actions.listener_observations), 2)

    def test_listener_adoption_reuses_exact_active_server_reservation(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            service = store_backed_service(persistence, actions)
            reserved = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.PORT_LEASE,
                    resource_id=SERVER_ID,
                    arguments={
                        "requested_port": 3107,
                        "protocol": "tcp",
                        "ttl_seconds": 600,
                    },
                ).to_wire(),
            )
            self.assertTrue(reserved["ok"], reserved)
            lease_id = str(reserved["result"]["lease_id"])

            evidence = {
                "pid": 12345,
                "owner_uid": os.geteuid(),
                "process_start_time": "2026-07-16T13:38:05Z",
                "canonical_cwd": "/repos/alpha/apps/web",
                "cwd": "/repos/alpha/apps/web",
                "canonical_root": "/repos/alpha",
                "listener_port": 3107,
                "port": 3107,
                "protocol": "tcp",
                "process_identity": "linux:12345:987654",
            }
            actions.occupied_ports.add(3107)
            actions.listener_evidence = evidence
            adopted = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.PORT_LEASE,
                    resource_id=SERVER_ID,
                    arguments={
                        "requested_port": 3107,
                        "protocol": "tcp",
                        "ttl_seconds": 600,
                        "adopt_existing_listener": True,
                    },
                ).to_wire(),
            )

            self.assertTrue(adopted["ok"], adopted)
            self.assertEqual(adopted["result"]["lease_id"], lease_id)
            self.assertTrue(adopted["result"]["reused"])
            self.assertEqual(adopted["result"]["listener_identity"], evidence)
            self.assertEqual(len(actions.listener_observations), 2)

            published = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.SERVER_PUBLISH,
                    resource_id=SERVER_ID,
                    arguments={
                        "lease_id": lease_id,
                        "lifecycle": "running",
                        "pid": 12345,
                        "listener_port": 3107,
                        "health_classification": "healthy",
                        "health_ok": True,
                    },
                ).to_wire(),
            )
            self.assertTrue(published["ok"], published)
            readopted = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.PORT_LEASE,
                    resource_id=SERVER_ID,
                    arguments={
                        "requested_port": 3107,
                        "protocol": "tcp",
                        "ttl_seconds": 600,
                        "adopt_existing_listener": True,
                    },
                ).to_wire(),
            )
            self.assertTrue(readopted["ok"], readopted)
            self.assertEqual(readopted["result"]["lease_id"], lease_id)
            self.assertTrue(readopted["result"]["reused"])
            self.assertEqual(len(actions.listener_observations), 5)
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    self.assertEqual(
                        connection.execute("SELECT count(*) FROM leases").fetchone()[0],
                        1,
                    )
                    self.assertEqual(
                        connection.execute(
                            "SELECT count(*) FROM broker_lease_owners"
                        ).fetchone()[0],
                        1,
                    )

            # Exact reuse is adoption-only. An ordinary second reservation on
            # the occupied port remains unavailable.
            ordinary = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.PORT_LEASE,
                    resource_id=SERVER_ID,
                    arguments={
                        "requested_port": 3107,
                        "protocol": "tcp",
                        "ttl_seconds": 600,
                    },
                ).to_wire(),
            )
            self.assertFalse(ordinary["ok"], ordinary)
            self.assertEqual(ordinary["error"]["code"], "port_unavailable")

    def test_unobservable_listener_adoption_writes_no_broker_operation(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, _unused = seed_store_backed_broker(root)
            actions = RecordingTypedHostActions(
                occupied_ports={3107}, listener_evidence=None
            )
            service = store_backed_service(persistence, actions)
            request = request_for(
                BrokerOperation.PORT_LEASE,
                resource_id=SERVER_ID,
                arguments={
                    "requested_port": 3107,
                    "protocol": "tcp",
                    "ttl_seconds": 600,
                    "adopt_existing_listener": True,
                },
            )

            reply = service.reply_for_document(peer_for(), request.to_wire())

            self.assertFalse(reply["ok"], reply)
            self.assertEqual(reply["error"]["code"], "listener_identity_unavailable")
            self.assertEqual(
                actions.listener_observations,
                [(3107, "/repos/alpha", "tcp")],
            )
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    self.assertIsNone(
                        connection.execute(
                            "SELECT status FROM operations WHERE operation_id = ?",
                            (request.operation_id,),
                        ).fetchone()
                    )
                    self.assertEqual(
                        connection.execute("SELECT count(*) FROM leases").fetchone()[0],
                        0,
                    )

    def test_existing_listener_adoption_requires_one_exact_requested_port(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            service = store_backed_service(persistence, actions)
            document = request_for(
                BrokerOperation.PORT_LEASE,
                resource_id=SERVER_ID,
                arguments={"protocol": "tcp", "ttl_seconds": 600},
            ).to_wire()
            document["arguments"]["adopt_existing_listener"] = True

            reply = service.reply_for_document(peer_for(), document)

            self.assertFalse(reply["ok"], reply)
            self.assertEqual(reply["error"]["code"], "invalid_arguments")
            self.assertEqual(actions.listener_observations, [])
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    self.assertEqual(
                        connection.execute("SELECT count(*) FROM leases").fetchone()[0],
                        0,
                    )

    def test_server_publication_is_peer_listener_bound_and_host_inventory_is_cross_uid(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            service = store_backed_service(persistence, actions)
            leased = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.PORT_LEASE,
                    resource_id=SERVER_ID,
                    arguments={
                        "requested_port": 3112,
                        "protocol": "tcp",
                        "ttl_seconds": 600,
                    },
                ).to_wire(),
            )
            self.assertTrue(leased["ok"], leased)
            lease_id = str(leased["result"]["lease_id"])
            actions.listener_evidence = {
                "pid": 12345,
                "owner_uid": os.geteuid(),
                "process_identity": "linux:12345:987654",
                "cwd": "/repos/alpha/apps/web",
                "canonical_root": "/repos/alpha",
                "port": 3112,
                "protocol": "tcp",
            }
            published = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.SERVER_PUBLISH,
                    resource_id=SERVER_ID,
                    arguments={
                        "lease_id": lease_id,
                        "lifecycle": "running",
                        "pid": 12345,
                        "listener_port": 3112,
                        "health_classification": "healthy",
                        "health_ok": True,
                    },
                ).to_wire(),
            )
            self.assertTrue(published["ok"], published)

            second_uid = os.geteuid() + 100_000
            unauthorized = service.reply_for_document(
                PeerCredentials(second_uid, os.getegid(), 54321),
                BrokerRequest.create(
                    account_id="account-console",
                    project_id=PROJECT_ID,
                    resource_id=PROJECT_ID,
                    operation=BrokerOperation.INVENTORY_READ,
                    authority_generation=CURRENT_AUTHORITY_GENERATION,
                ).to_wire(),
            )
            self.assertFalse(unauthorized["ok"], unauthorized)
            self.assertEqual(
                unauthorized["error"]["code"], "peer_not_authorized"
            )
            persistence.provision_principal(
                uid=second_uid, account_id="account-console"
            )
            inventory_request = BrokerRequest.create(
                account_id="account-console",
                project_id=PROJECT_ID,
                resource_id=PROJECT_ID,
                operation=BrokerOperation.INVENTORY_READ,
                authority_generation=CURRENT_AUTHORITY_GENERATION,
            )
            inventory = service.reply_for_document(
                PeerCredentials(second_uid, os.getegid(), 54321),
                inventory_request.to_wire(),
            )
            self.assertTrue(inventory["ok"], inventory)
            visible = inventory["result"]["v1_compatibility"]["servers"]
            self.assertEqual(len(visible), 1)
            self.assertEqual(visible[0]["name"], "web")
            self.assertEqual(visible[0]["status"], "running")
            self.assertEqual(visible[0]["pid"], 12345)
            self.assertEqual(visible[0]["port"], 3112)
            visible_leases = inventory["result"]["v1_compatibility"]["leases"]
            self.assertEqual(len(visible_leases), 1)
            self.assertEqual(visible_leases[0]["id"], lease_id)
            self.assertEqual(visible_leases[0]["purpose"], "server:web")
            self.assertEqual(visible_leases[0]["server_id"], SERVER_ID)
            self.assertEqual(visible_leases[0]["owner_pid"], 12345)
            self.assertEqual(
                visible_leases[0]["assignment_key"], "/repos/alpha::web"
            )

            stopped = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.SERVER_PUBLISH,
                    resource_id=SERVER_ID,
                    arguments={
                        "lease_id": lease_id,
                        "lifecycle": "stopped",
                        "listener_port": 3112,
                        "health_classification": "stopped",
                        "health_ok": False,
                        "stopped_reason": "Stopped by regression test",
                    },
                ).to_wire(),
            )
            self.assertTrue(stopped["ok"], stopped)
            self.assertEqual(
                actions.port_observations[-1], ((3112,), "tcp")
            )
            refreshed = service.reply_for_document(
                PeerCredentials(second_uid, os.getegid(), 54321),
                BrokerRequest.create(
                    account_id="account-console",
                    project_id=PROJECT_ID,
                    resource_id=PROJECT_ID,
                    operation=BrokerOperation.INVENTORY_READ,
                    authority_generation=CURRENT_AUTHORITY_GENERATION,
                ).to_wire(),
            )
            self.assertEqual(
                refreshed["result"]["v1_compatibility"]["servers"][0]["status"],
                "stopped",
            )

    def test_server_publication_rejects_foreign_uid_pid_and_bound_stop(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            service = store_backed_service(persistence, actions)
            lease = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.PORT_LEASE,
                    resource_id=SERVER_ID,
                    arguments={"requested_port": 3113, "ttl_seconds": 600},
                ).to_wire(),
            )["result"]
            actions.listener_evidence = {
                "pid": 12345,
                "owner_uid": os.geteuid() + 1,
                "process_identity": "linux:12345:987654",
                "cwd": "/repos/alpha",
                "canonical_root": "/repos/alpha",
                "port": 3113,
                "protocol": "tcp",
            }
            arguments = {
                "lease_id": lease["lease_id"],
                "lifecycle": "running",
                "pid": 12345,
                "listener_port": 3113,
                "health_classification": "healthy",
                "health_ok": True,
            }
            foreign_owner = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.SERVER_PUBLISH,
                    resource_id=SERVER_ID,
                    arguments=arguments,
                ).to_wire(),
            )
            self.assertFalse(foreign_owner["ok"], foreign_owner)
            self.assertEqual(
                foreign_owner["error"]["code"], "listener_peer_mismatch"
            )
            actions.listener_evidence = {
                **actions.listener_evidence,
                "owner_uid": os.geteuid(),
            }
            wrong_pid = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.SERVER_PUBLISH,
                    resource_id=SERVER_ID,
                    arguments={**arguments, "pid": 12346},
                ).to_wire(),
            )
            self.assertFalse(wrong_pid["ok"], wrong_pid)
            self.assertEqual(
                wrong_pid["error"]["code"], "listener_process_mismatch"
            )
            actions.occupied_ports.add(3113)
            bound_stop = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.SERVER_PUBLISH,
                    resource_id=SERVER_ID,
                    arguments={
                        "lease_id": lease["lease_id"],
                        "lifecycle": "stopped",
                        "listener_port": 3113,
                        "health_classification": "stopped",
                        "health_ok": False,
                        "stopped_reason": "must not commit",
                    },
                ).to_wire(),
            )
            self.assertFalse(bound_stop["ok"], bound_stop)
            self.assertEqual(bound_stop["error"]["code"], "listener_still_bound")

    def test_server_access_replacement_revokes_omitted_servers_atomically(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            persistence.replace_server_access(
                uid=os.geteuid(),
                repo_id=PROJECT_ID,
                server_definition_ids=(),
                start_port=3100,
                end_port=3199,
            )
            service = store_backed_service(persistence, actions)
            denied = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.PORT_LEASE,
                    resource_id=SERVER_ID,
                    arguments={"requested_port": 3115, "ttl_seconds": 600},
                ).to_wire(),
            )
            self.assertFalse(denied["ok"], denied)
            self.assertEqual(denied["error"]["code"], "operation_access_denied")

            persistence.replace_server_access(
                uid=os.geteuid(),
                repo_id=PROJECT_ID,
                server_definition_ids=(SERVER_ID,),
                start_port=3100,
                end_port=3199,
            )
            with self.assertRaises(BrokerError):
                persistence.replace_server_access(
                    uid=os.geteuid(),
                    repo_id=PROJECT_ID,
                    server_definition_ids=("server-foreign",),
                    start_port=3100,
                    end_port=3199,
                )
            allowed = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.PORT_LEASE,
                    resource_id=SERVER_ID,
                    arguments={"requested_port": 3115, "ttl_seconds": 600},
                ).to_wire(),
            )
            self.assertTrue(allowed["ok"], allowed)

    def test_foreign_dynamic_lease_release_is_rejected_without_mutation(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            service = store_backed_service(persistence, actions)
            lease_request = request_for(
                BrokerOperation.PORT_LEASE,
                resource_id=SERVER_ID,
                arguments={"requested_port": 3110, "ttl_seconds": 600},
            )
            lease = service.reply_for_document(peer_for(), lease_request.to_wire())[
                "result"
            ]
            foreign = request_for(
                BrokerOperation.PORT_RELEASE,
                resource_id=lease["lease_id"],
            ).to_wire()
            foreign["account_id"] = "account-other"
            reply = service.reply_for_document(peer_for(), foreign)
            self.assertFalse(reply["ok"], reply)
            self.assertEqual(reply["error"]["code"], "cross_account_access_denied")
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    status = connection.execute(
                        "SELECT status FROM leases WHERE lease_id = ?",
                        (lease["lease_id"],),
                    ).fetchone()[0]
            self.assertEqual(status, "active")

    def test_overlapping_port_policy_is_rejected_but_disjoint_policy_is_allowed(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, _ = seed_store_backed_broker(root)
            with self.assertRaises(BrokerError) as overlap:
                persistence.grant_port_range(
                    uid=os.geteuid(),
                    repo_id=PROJECT_ID,
                    server_definition_id=SERVER_ID,
                    start_port=3150,
                    end_port=3250,
                )
            self.assertEqual(overlap.exception.code, "overlapping_port_policy")
            persistence.grant_port_range(
                uid=os.geteuid(),
                repo_id=PROJECT_ID,
                server_definition_id=SERVER_ID,
                start_port=3200,
                end_port=3299,
            )

    def test_durable_idempotency_survives_cache_eviction_restart_and_gid_change(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            service = store_backed_service(
                persistence, actions, completed_cache_size=1
            )
            operation_id = str(uuid.uuid4())
            first = request_for(operation_id=operation_id)
            first_reply = service.reply_for_document(peer_for(), first.to_wire())
            self.assertTrue(first_reply["ok"], first_reply)

            eviction = request_for(
                BrokerOperation.DOCKER_START,
                resource_id=SECOND_CONTAINER_ID,
            )
            self.assertTrue(
                service.reply_for_document(peer_for(), eviction.to_wire())["ok"]
            )

            alternate_gid = os.getegid() + 10_000
            replay = service.reply_for_document(
                PeerCredentials(os.geteuid(), alternate_gid, os.getpid()),
                first.to_wire(),
            )
            self.assertEqual(replay, first_reply)
            self.assertEqual(
                [call[0:2] for call in actions.calls].count(
                    ("stop", CONTAINER_ID)
                ),
                1,
            )

            restarted_persistence = BrokerPersistence(
                persistence.database_path, expected_uid=os.geteuid()
            )
            restarted = store_backed_service(restarted_persistence, actions)
            after_restart = restarted.reply_for_document(
                peer_for(), first.to_wire()
            )
            self.assertEqual(after_restart, first_reply)
            self.assertEqual(
                [call[0:2] for call in actions.calls].count(
                    ("stop", CONTAINER_ID)
                ),
                1,
            )

    def test_pending_durable_operation_is_never_blindly_reexecuted(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            request = request_for()
            authorized = persistence.authorize(peer_for(), request)
            disposition = persistence.reserve_operation(authorized)
            self.assertEqual(disposition.state, "execute")

            restarted = store_backed_service(
                BrokerPersistence(
                    persistence.database_path, expected_uid=os.geteuid()
                ),
                actions,
            )
            reply = restarted.reply_for_document(peer_for(), request.to_wire())
            self.assertFalse(reply["ok"], reply)
            self.assertEqual(reply["error"]["code"], "operation_in_progress")
            self.assertEqual(actions.calls, [])

    def test_two_service_instances_dispatch_one_concurrent_operation_once(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, _ = seed_store_backed_broker(root)
            entered = threading.Event()
            release = threading.Event()
            actions = BlockingTypedHostActions(entered, release)
            first_service = store_backed_service(persistence, actions)
            second_service = store_backed_service(
                BrokerPersistence(
                    persistence.database_path, expected_uid=os.geteuid()
                ),
                actions,
            )
            request = request_for()
            first_replies: list[dict[str, Any]] = []

            def run_first() -> None:
                first_replies.append(
                    first_service.reply_for_document(peer_for(), request.to_wire())
                )

            worker = threading.Thread(target=run_first)
            worker.start()
            self.assertTrue(
                entered.wait(timeout=1.0),
                "first service did not reach the exact typed host action",
            )
            second = second_service.reply_for_document(peer_for(), request.to_wire())
            self.assertFalse(second["ok"], second)
            self.assertEqual(second["error"]["code"], "operation_in_progress")
            release.set()
            worker.join(timeout=2.0)
            self.assertFalse(worker.is_alive(), first_replies)
            self.assertTrue(first_replies[0]["ok"], first_replies)
            self.assertEqual(len(actions.calls), 1)
            completed = second_service.reply_for_document(
                peer_for(), request.to_wire()
            )
            self.assertTrue(completed["ok"], completed)
            self.assertEqual(len(actions.calls), 1)

    def test_decommission_fence_committed_after_reservation_blocks_start_action(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            original_reserve = persistence.reserve_operation

            def reserve_and_fence(authorized: Any) -> Any:
                disposition = original_reserve(authorized)
                if disposition.state == "execute":
                    with CoordinatorStore.open(
                        persistence.database_path, expected_uid=os.geteuid()
                    ) as store:
                        with store.immediate_transaction() as connection:
                            connection.execute(
                                """
                                UPDATE repository_installations
                                SET status = 'disabling', startup_fenced = 1,
                                    generation = generation + 1, updated_at = ?
                                WHERE repo_id = ?
                                """,
                                (utc_timestamp(), PROJECT_ID),
                            )
                return disposition

            persistence.reserve_operation = reserve_and_fence  # type: ignore[method-assign]
            service = store_backed_service(persistence, actions)
            request = request_for(BrokerOperation.DOCKER_START)
            reply = service.reply_for_document(peer_for(), request.to_wire())
            self.assertFalse(reply["ok"], reply)
            self.assertEqual(
                reply["error"]["code"], "repository_startup_fenced"
            )
            self.assertEqual(actions.calls, [])

    def test_live_acl_revocation_after_reservation_blocks_stop_action(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            original_reserve = persistence.reserve_operation

            def reserve_and_revoke(authorized: Any) -> Any:
                disposition = original_reserve(authorized)
                if disposition.state == "execute":
                    with CoordinatorStore.open(
                        persistence.database_path, expected_uid=os.geteuid()
                    ) as store:
                        with store.immediate_transaction() as connection:
                            connection.execute(
                                """
                                UPDATE broker_resource_acl SET enabled = 0, updated_at = ?
                                WHERE uid = ? AND repo_id = ? AND resource_id = ?
                                  AND operation = 'docker.stop'
                                """,
                                (
                                    utc_timestamp(),
                                    os.geteuid(),
                                    PROJECT_ID,
                                    CONTAINER_ID,
                                ),
                            )
                return disposition

            persistence.reserve_operation = reserve_and_revoke  # type: ignore[method-assign]
            service = store_backed_service(persistence, actions)
            request = request_for(BrokerOperation.DOCKER_STOP)
            reply = service.reply_for_document(peer_for(), request.to_wire())
            self.assertFalse(reply["ok"], reply)
            self.assertEqual(reply["error"]["code"], "operation_access_denied")
            self.assertEqual(actions.calls, [])


def _receive_exact_for_test(connection: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise AssertionError("fixture connection closed before frame completed")
        result.extend(chunk)
    return bytes(result)


if __name__ == "__main__":
    unittest.main()
