"""Deterministic security and concurrency tests for the cross-UID broker."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import pwd
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterator, Mapping, Optional
from unittest import mock

SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import dev_coordinator  # noqa: E402

import devcoordinator.broker as broker_module  # noqa: E402
import devcoordinator.broker_persistence as broker_persistence  # noqa: E402
import devcoordinator.repository_context as repository_context_module  # noqa: E402
from devcoordinator.broker import (  # noqa: E402
    AcceptedBrokerRequest,
    BrokerClient,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    BrokerService,
    PeerCredentials,
    SerializedMutationWriter,
    TrustedLocalRequestAcceptor,
    UnixBrokerServer,
    resolve_peer_credentials,
    validate_runtime_directory,
)
from devcoordinator.broker_backend import (  # noqa: E402
    StoreBackedBrokerRuntime,
    StoreBackedMutationBackend,
    build_store_backed_broker_runtime,
)
from devcoordinator.broker_cli import exclusive_broker_service_lock  # noqa: E402
from devcoordinator.broker_host import render_compose_effective_model  # noqa: E402
from devcoordinator.broker_persistence import (  # noqa: E402
    BrokerPersistence,
    StoreBackedRequestAcceptor,
)
from devcoordinator.ephemeral_containers import (  # noqa: E402
    EphemeralContainerCoordinator,
)
from devcoordinator.observer import SingleFlightObserver  # noqa: E402
from devcoordinator.repository_lifecycle import (  # noqa: E402
    PolicyObservation,
    ResourceKind,
    ResourceObservation,
    RunningState,
)
from devcoordinator.sqlite_lifecycle import SQLiteLifecyclePersistence  # noqa: E402
from devcoordinator.store import (  # noqa: E402
    AccountStore,
    CoordinatorStore,
    deterministic_id,
    utc_timestamp,
)

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
        self.calls: list[AcceptedBrokerRequest] = []
        self.active = 0
        self.max_active = 0
        self.wait_timed_out = False

    def execute(self, request: AcceptedBrokerRequest) -> Mapping[str, Any]:
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


class BlockingPostgresHostActions(RecordingPostgresHostActions):
    """Production-shaped database boundary with deterministic release/failure."""

    def __init__(
        self,
        entered: threading.Event,
        release: threading.Event,
        *,
        fail_after_release: bool = False,
    ) -> None:
        super().__init__()
        self.entered = entered
        self.release = release
        self.fail_after_release = fail_after_release

    def postgres_backup(
        self, target: Any, *, output_root: str
    ) -> Mapping[str, Any]:
        self.postgres_calls.append(
            ("backup", target.full_container_id, target.database_name)
        )
        self.entered.set()
        if not self.release.wait(timeout=5.0):
            raise RuntimeError("PostgreSQL shutdown-drain fixture timed out")
        if self.fail_after_release:
            raise RuntimeError("injected drained PostgreSQL backup failure")
        self._published += 1
        return _publish_strong_postgres_backup(
            output_root,
            full_container_id=target.full_container_id,
            database_name=target.database_name,
            marker=f"drained-{self._published}",
        )


class TimedOutPostgresHostActions(RecordingPostgresHostActions):
    def postgres_backup(
        self, target: Any, *, output_root: str
    ) -> Mapping[str, Any]:
        del output_root
        self.postgres_calls.append(
            ("backup", target.full_container_id, target.database_name)
        )
        raise BrokerError(
            "operation_outcome_uncertain",
            "injected bounded PostgreSQL helper timeout",
        )


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
        policies = {}
        if target.policies:
            policy = target.policies[0]
            policies[policy.policy_id] = PolicyObservation(
                policy_id=policy.policy_id,
                immutable_fingerprint=policy.immutable_fingerprint,
                observable=True,
                disabled=self.policy_disabled,
                value=(policy.disabled_value if self.policy_disabled else "always"),
                docker_restart_policy=(
                    policy.disabled_value if self.policy_disabled else "always"
                ),
            )
        return ResourceObservation(
            resource_id=target.resource_id,
            kind=target.kind,
            identity_observable=True,
            immutable_fingerprint=target.immutable_fingerprint,
            ownership_observable=True,
            observation_fingerprint=target.observation_fingerprint,
            running_state=(
                RunningState.RUNNING if self.running else RunningState.STOPPED
            ),
            container_running=(
                self.running if target.kind is ResourceKind.CONTAINER else None
            ),
            listener_active=(
                self.running if target.kind is ResourceKind.SERVER else None
            ),
            policies=policies,
        )

    def disable_startup_policy(self, _target: Any, _policy: Any) -> Mapping[str, Any]:
        self.calls.append("disable_policy")
        self.policy_disabled = True
        return {"status": "disabled"}

    def stop_exact(self, _target: Any) -> Mapping[str, Any]:
        self.calls.append("stop")
        self.running = False
        return {"status": "stopped"}


def request_for(
    operation: BrokerOperation = BrokerOperation.DOCKER_STOP,
    *,
    resource_id: Optional[str] = None,
    arguments: Optional[Mapping[str, Any]] = None,
    operation_id: Optional[str] = None,
) -> BrokerRequest:
    resolved_resource_id = resource_id
    if resolved_resource_id is None:
        resolved_resource_id = (
            DATABASE_ID
            if operation
            in {
                BrokerOperation.DATABASE_BACKUP,
                BrokerOperation.DATABASE_BACKUP_RETIRE,
                BrokerOperation.DATABASE_RESTORE,
            }
            else CONTAINER_ID
        )
    return BrokerRequest.create(
        account_id=ACCOUNT_ID,
        project_id=PROJECT_ID,
        resource_id=resolved_resource_id,
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
    del uid
    writer = SerializedMutationWriter(backend)
    service = BrokerService(TrustedLocalRequestAcceptor(), writer)
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
        canonical_tmp = Path(
            os.environ.get("DEVCOORDINATOR_TEST_TMP_ROOT")
            or pwd.getpwuid(os.geteuid()).pw_dir
        ).resolve()
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


def create_dead_unix_socket(
    socket_path: Path,
    *,
    mode: int = 0o660,
) -> tuple[int, int]:
    """Leave a service-owned AF_UNIX pathname with no listening process."""

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(socket_path))
        os.chmod(socket_path, mode)
        info = os.lstat(socket_path)
        return (info.st_dev, info.st_ino)
    finally:
        listener.close()


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
                "UPDATE schema_metadata SET migration_state = 'ready' WHERE singleton = 1"
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
                INSERT INTO broker_port_ranges(
                    repo_id, server_definition_id, protocol,
                    start_port, end_port, max_ttl_seconds, enabled, updated_at
                ) VALUES (?, ?, 'tcp', 3100, 3199, 604800, 1, ?)
                """,
                (PROJECT_ID, SERVER_ID, now),
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
                        docker_resource_id, engine_id, repo_id, full_container_id,
                        current_name, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (resource_id, ENGINE_ID, PROJECT_ID, full_id, name, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO docker_observations(
                        docker_resource_id, lifecycle, sampled_at, observation_fingerprint
                    ) VALUES (?, 'stopped', ?, ?)
                    """,
                    (resource_id, now, "observation-" + resource_id),
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


class DatabaseTargetDriftPersistence(BrokerPersistence):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.inject_drift = True

    def database_target(self, authorized: AcceptedBrokerRequest) -> Any:
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
        StoreBackedRequestAcceptor(persistence),
        SerializedMutationWriter(
            backend, completed_cache_size=completed_cache_size
        ),
    )


def _committed_observer(
    store: CoordinatorStore, *, docker_available: bool
) -> Mapping[str, Any]:
    snapshot_id = str(uuid.uuid4())
    completed_at = utc_timestamp()
    material = "1" * 64
    capability = "sha256:" + ("2" if docker_available else "3") * 64
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
            ) VALUES (?, 'host-runtime-v2:full-docker', ?, ?, ?)
            """,
            (snapshot_id, int(docker_available), capability, completed_at),
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
        "host_id": host_id,
        "observer_domain": "host-runtime-v2:full-docker",
        "docker_available": docker_available,
        "capability_fingerprint": capability,
        "material_fingerprint": material,
        "started_at": completed_at,
        "completed_at": completed_at,
    }


def _committed_available_observer(store: CoordinatorStore) -> Mapping[str, Any]:
    return _committed_observer(store, docker_available=True)


class PeerCredentialTests(unittest.TestCase):
    def test_client_identity_metadata_is_optional_compatibility_input(self) -> None:
        client = BrokerClient(Path("/tmp/devcoordinator-optional.sock"))
        compatibility = BrokerClient(
            Path("/tmp/devcoordinator-optional.sock"),
        )

        self.assertEqual(client.socket_path, compatibility.socket_path)

    def test_kernel_peer_credentials_match_the_real_unix_peer(self) -> None:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            credentials = resolve_peer_credentials(left)
        finally:
            left.close()
            right.close()

        if credentials.uid == broker_module.UNMAPPED_LOCAL_IDENTITY:
            self.assertEqual(credentials.gid, broker_module.UNMAPPED_LOCAL_IDENTITY)
            self.assertIsNone(credentials.pid)
        else:
            self.assertEqual(credentials.uid, os.geteuid())
            self.assertEqual(credentials.gid, os.getegid())
            if sys.platform.startswith("linux"):
                self.assertEqual(credentials.pid, os.getpid())
            else:
                self.assertIsNone(credentials.pid)

    def test_non_unix_socket_cannot_bypass_peer_authentication(self) -> None:
        connection = mock.Mock()
        connection.family = socket.AF_INET
        with self.assertRaises(BrokerError) as raised:
            resolve_peer_credentials(connection)
        self.assertEqual(raised.exception.code, "peer_credentials_unavailable")

    def test_unavailable_unix_peer_credentials_use_unmapped_attribution(self) -> None:
        connection = mock.Mock()
        connection.family = socket.AF_UNIX
        connection.getsockopt.side_effect = OSError("fixture unavailable")

        credentials = resolve_peer_credentials(connection)

        self.assertEqual(credentials.uid, broker_module.UNMAPPED_LOCAL_IDENTITY)
        self.assertEqual(credentials.gid, broker_module.UNMAPPED_LOCAL_IDENTITY)
        self.assertIsNone(credentials.pid)


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

            def execute(self, _request: AcceptedBrokerRequest) -> Mapping[str, Any]:
                return {"schema_version": 2, "graph_payload": self.payload}

        # The real six-repository host graph crossed the retired 2 MiB result
        # ceiling because normalized and v1 compatibility views coexist during
        # migration. Keep one atomic snapshot comfortably above that boundary.
        backend = InventoryBackend(3 * 1024 * 1024)
        writer = SerializedMutationWriter(backend)  # type: ignore[arg-type]
        service = BrokerService(TrustedLocalRequestAcceptor(), writer)
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
        bounded_service = BrokerService(TrustedLocalRequestAcceptor(), bounded_writer)
        rejected = bounded_service.reply_for_document(self.peer, request.to_wire())
        self.assertFalse(rejected["ok"], rejected)
        self.assertEqual(rejected["error"]["code"], "backend_result_too_large")

    def test_unexpected_read_failure_is_logged_and_returned_as_a_frame(self) -> None:
        class BrokenInventoryBackend:
            def execute(self, _request: AcceptedBrokerRequest) -> Mapping[str, Any]:
                raise OSError("fixture transport disappeared")

        service = BrokerService(
            TrustedLocalRequestAcceptor(),
            SerializedMutationWriter(BrokenInventoryBackend()),  # type: ignore[arg-type]
        )
        request = request_for(
            BrokerOperation.INVENTORY_READ, resource_id=PROJECT_ID
        )

        with self.assertLogs(broker_module._LOGGER, level="ERROR") as captured:
            reply = service.reply_for_document(self.peer, request.to_wire())

        self.assertFalse(reply["ok"], reply)
        self.assertEqual(reply["operation_id"], request.operation_id)
        self.assertEqual(reply["error"]["code"], "internal_error")
        self.assertNotIn("fixture transport disappeared", reply["error"]["message"])
        self.assertTrue(
            any("broker request failed unexpectedly" in line for line in captured.output)
        )

    def test_host_observe_reaches_database_single_flight_without_outer_repo_lock(self) -> None:
        release = threading.Event()
        backend = RecordingBackend(release=release)
        writer = SerializedMutationWriter(backend)
        service = BrokerService(TrustedLocalRequestAcceptor(), writer)
        requests = [
            request_for(BrokerOperation.HOST_OBSERVE, resource_id=PROJECT_ID),
            request_for(BrokerOperation.HOST_OBSERVE, resource_id=PROJECT_ID),
        ]
        replies: list[dict[str, Any]] = []
        failures: list[BaseException] = []

        def invoke(request: BrokerRequest) -> None:
            try:
                replies.append(
                    service.reply_for_document(self.peer, request.to_wire())
                )
            except BaseException as error:  # pragma: no cover - diagnostic path
                failures.append(error)

        workers = [threading.Thread(target=invoke, args=(request,)) for request in requests]
        for worker in workers:
            worker.start()
        deadline = time.monotonic() + 1.0
        reached_backend_together = False
        try:
            while time.monotonic() < deadline:
                if backend.max_active >= 2:
                    reached_backend_together = True
                    break
                time.sleep(0.01)
        finally:
            release.set()
            for worker in workers:
                worker.join(timeout=2.0)

        self.assertFalse(any(worker.is_alive() for worker in workers), failures)
        self.assertEqual(failures, [])
        self.assertTrue(
            reached_backend_together,
            "same-repository observations were serialized before the durable host-domain single-flight boundary",
        )
        self.assertEqual(len(replies), 2)
        self.assertTrue(all(reply["ok"] for reply in replies), replies)

    def test_peer_uid_and_account_are_attribution_not_local_authorization(self) -> None:
        unknown_peer_request = request_for()
        unknown_peer_reply = self.service.reply_for_document(
            peer_for(os.geteuid() + 10000), unknown_peer_request.to_wire()
        )
        self.assertTrue(unknown_peer_reply["ok"], unknown_peer_reply)
        self.assertEqual(self.backend.calls[-1].peer.uid, os.geteuid() + 10000)
        self.assertEqual(
            self.backend.calls[-1].attribution_uid, os.geteuid() + 10000
        )

        cross_account = request_for().to_wire()
        cross_account["account_id"] = "account-other"

        cross_project = request_for().to_wire()
        cross_project["project_id"] = "repo-other"

        cross_resource = request_for().to_wire()
        cross_resource["resource_id"] = "container-other"

        wrong_operation = request_for(
            BrokerOperation.DOCKER_START,
            resource_id=STOP_ONLY_CONTAINER_ID,
        ).to_wire()
        for name, document in (
            ("another attribution namespace", cross_account),
            ("another repository route", cross_project),
            ("another resource", cross_resource),
            ("another supported operation", wrong_operation),
        ):
            with self.subTest(name=name):
                reply = self.service.reply_for_document(self.peer, document)
                self.assertTrue(reply["ok"], reply)

        self.assertEqual(len(self.backend.calls), 5)

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

    def test_service_shutting_down_error_does_not_poison_operation_replay(self) -> None:
        class ShuttingDownOnceBackend:
            def __init__(self) -> None:
                self.calls = 0

            def execute(
                self, _request: AcceptedBrokerRequest
            ) -> Mapping[str, Any]:
                self.calls += 1
                if self.calls == 1:
                    raise BrokerError(
                        "service_shutting_down",
                        "The broker is shutting down; retry with its replacement.",
                    )
                return {"status": "stopped"}

        backend = ShuttingDownOnceBackend()
        writer = SerializedMutationWriter(backend)  # type: ignore[arg-type]
        service = BrokerService(TrustedLocalRequestAcceptor(), writer)
        request = request_for()

        first = service.reply_for_document(self.peer, request.to_wire())
        retried = service.reply_for_document(self.peer, request.to_wire())

        self.assertFalse(first["ok"], first)
        self.assertEqual(first["error"]["code"], "service_shutting_down")
        self.assertTrue(retried["ok"], retried)
        self.assertEqual(retried["result"]["status"], "stopped")
        self.assertEqual(backend.calls, 2)


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

    def test_worker_runner_callback_progresses_during_same_resource_runtime_action(self) -> None:
        runtime_entered = threading.Event()
        release_runtime = threading.Event()
        callback_entered = threading.Event()

        class RuntimeAndRunnerBackend:
            def execute(self, request: AcceptedBrokerRequest) -> Mapping[str, Any]:
                if request.request.operation is BrokerOperation.RUNTIME_REQUEST:
                    runtime_entered.set()
                    if not release_runtime.wait(timeout=3.0):
                        raise RuntimeError("runtime release boundary timed out")
                else:
                    callback_entered.set()
                return {"status": "accepted"}

        writer = SerializedMutationWriter(RuntimeAndRunnerBackend())
        peer = peer_for()

        def authorized(operation: BrokerOperation) -> AcceptedBrokerRequest:
            return AcceptedBrokerRequest(
                peer=peer,
                request=BrokerRequest(
                    operation_id=str(uuid.uuid4()),
                    authority_generation=CURRENT_AUTHORITY_GENERATION,
                    account_id=ACCOUNT_ID,
                    project_id=PROJECT_ID,
                    repository_generation=0,
                    resource_id=SERVER_ID,
                    operation=operation,
                    arguments={},
                ),
            )

        runtime_results: list[dict[str, Any]] = []
        callback_results: list[dict[str, Any]] = []
        failures: list[BaseException] = []

        def invoke(
            request: AcceptedBrokerRequest, results: list[dict[str, Any]]
        ) -> None:
            try:
                results.append(writer.execute(request))
            except BaseException as error:
                failures.append(error)

        runtime = threading.Thread(
            target=invoke,
            args=(authorized(BrokerOperation.RUNTIME_REQUEST), runtime_results),
        )
        callback = threading.Thread(
            target=invoke,
            args=(authorized(BrokerOperation.WORKER_LAUNCH_TICKET), callback_results),
        )
        runtime.start()
        self.assertTrue(
            runtime_entered.wait(timeout=1.0),
            "runtime action did not reach its lifecycle boundary",
        )
        callback.start()
        callback_progressed = callback_entered.wait(timeout=1.0)
        release_runtime.set()
        runtime.join(timeout=2.0)
        callback.join(timeout=2.0)

        self.assertTrue(
            callback_progressed,
            "worker callback was blocked behind its parent runtime resource lock",
        )
        self.assertFalse(runtime.is_alive(), failures)
        self.assertFalse(callback.is_alive(), failures)
        self.assertEqual(failures, [])
        self.assertEqual(runtime_results, [{"status": "accepted"}])
        self.assertEqual(callback_results, [{"status": "accepted"}])

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

    def test_shutdown_rejects_pre_fence_waiter_before_backend_admission(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        backend = RecordingBackend(entered=entered, release=release)
        service, writer = service_for(backend)
        peer = peer_for()
        replies: list[dict[str, Any]] = []
        failures: list[BaseException] = []
        first = threading.Thread(
            target=self._run_reply,
            args=(
                service,
                peer,
                request_for(BrokerOperation.DOCKER_STOP),
                replies,
                failures,
            ),
        )
        second = threading.Thread(
            target=self._run_reply,
            args=(
                service,
                peer,
                request_for(BrokerOperation.DOCKER_START),
                replies,
                failures,
            ),
        )
        first.start()
        self.assertTrue(
            entered.wait(timeout=1.0),
            f"first mutation missed backend boundary; failures={failures!r}",
        )
        second.start()
        self.assertTrue(
            writer.wait_for_queued(1, timeout=1.0),
            f"second mutation missed keyed wait boundary; failures={failures!r}",
        )
        self.assertEqual(writer.begin_shutdown(), 1)
        release.set()
        first.join(timeout=2.0)
        second.join(timeout=2.0)

        self.assertFalse(first.is_alive(), failures)
        self.assertFalse(second.is_alive(), failures)
        self.assertEqual(failures, [])
        self.assertEqual(len(backend.calls), 1)
        self.assertTrue(writer.wait_for_drain(0.1))
        self.assertEqual(len(replies), 2)
        accepted = [reply for reply in replies if reply["ok"]]
        rejected = [reply for reply in replies if not reply["ok"]]
        self.assertEqual(len(accepted), 1, replies)
        self.assertEqual(len(rejected), 1, replies)
        self.assertEqual(
            rejected[0]["error"]["code"], "service_shutting_down"
        )

    def test_busy_host_observation_does_not_poison_operation_replay(self) -> None:
        entered = threading.Event()
        release = threading.Event()

        class BlockingObservationBackend:
            def __init__(self) -> None:
                self._lock = threading.Lock()
                self.calls = 0

            def execute(
                self, _request: AcceptedBrokerRequest
            ) -> Mapping[str, Any]:
                with self._lock:
                    self.calls += 1
                    call_number = self.calls
                if call_number == 1:
                    entered.set()
                    if not release.wait(timeout=2.0):
                        raise RuntimeError("host observation fixture timed out")
                return {"observed": True}

        backend = BlockingObservationBackend()
        writer = SerializedMutationWriter(
            backend,  # type: ignore[arg-type]
            max_concurrent_host_observations=1,
        )

        def authorized_observation() -> AcceptedBrokerRequest:
            return AcceptedBrokerRequest(
                peer=peer_for(),
                request=request_for(
                    BrokerOperation.HOST_OBSERVE,
                    resource_id=PROJECT_ID,
                ),
            )

        first_failures: list[BaseException] = []

        def run_first() -> None:
            try:
                writer.execute(authorized_observation())
            except BaseException as error:
                first_failures.append(error)

        first = threading.Thread(target=run_first)
        first.start()
        self.assertTrue(entered.wait(timeout=1.0))
        retry_request = authorized_observation()

        with self.assertRaises(BrokerError) as busy:
            writer.execute(retry_request)
        self.assertEqual(busy.exception.code, "host_observation_busy")
        self.assertEqual(backend.calls, 1)

        release.set()
        first.join(timeout=2.0)
        self.assertFalse(first.is_alive(), first_failures)
        self.assertEqual(first_failures, [])

        retried = writer.execute(retry_request)
        self.assertEqual(retried, {"observed": True})
        self.assertEqual(backend.calls, 2)

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
    def test_client_classifies_executor_denied_unix_transport(self) -> None:
        request = request_for()
        socket_metadata = mock.Mock(st_dev=1, st_ino=2)
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.connect.side_effect = PermissionError(
            errno.EPERM,
            "sandbox denied Unix transport",
        )

        with (
            mock.patch.object(
                broker_module,
                "_validate_client_socket",
                return_value=socket_metadata,
            ),
            mock.patch.object(
                broker_module.socket,
                "socket",
                return_value=connection,
            ),
            mock.patch.object(BrokerClient, "_require_available", return_value=None),
        ):
            with self.assertRaises(BrokerError) as denied:
                BrokerClient(
                    Path("/run/devcoordinator-authority.sock"),
                ).call(request)

        self.assertEqual(denied.exception.code, "broker_transport_forbidden")
        self.assertEqual(denied.exception.operation_id, request.operation_id)

    def test_runtime_directory_ignores_local_modes_but_rejects_symlink(
        self,
    ) -> None:
        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o700)

            os.chmod(runtime, 0o755)
            validate_runtime_directory(runtime)

            os.chmod(runtime, 0o775)
            validate_runtime_directory(runtime)

            os.chmod(runtime, 0o757)
            validate_runtime_directory(runtime)

            os.chmod(runtime, 0o755)
            alias = root / "runtime-alias"
            alias.symlink_to(runtime, target_is_directory=True)
            with self.assertRaises(BrokerError) as symlink:
                validate_runtime_directory(alias)
            self.assertEqual(symlink.exception.code, "unsafe_runtime_directory")

    def test_runtime_directory_accepts_shared_ancestor_and_private_direct_start(self) -> None:
        backend = RecordingBackend()
        service, _ = service_for(backend)
        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o750)
            os.chmod(runtime, 0o750)
            os.chmod(root, 0o777)
            try:
                validate_runtime_directory(runtime)
            finally:
                os.chmod(root, 0o700)

            os.chmod(runtime, 0o700)
            with UnixBrokerServer(runtime / "broker.sock", service):
                pass

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

    def test_client_captures_peer_uid_but_does_not_authorize_with_it(self) -> None:
        backend = RecordingBackend()
        service, _ = service_for(backend)
        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o750)
            os.chmod(runtime, 0o750)
            socket_path = runtime / "broker.sock"
            with UnixBrokerServer(socket_path, service):
                request = request_for()
                owner = BrokerClient(
                    socket_path,
                ).call(request)
                self.assertTrue(owner["ok"], owner)

                group = BrokerClient(
                    socket_path,
                ).call(request)
                self.assertTrue(group["ok"], group)
                self.assertEqual(owner, group)
            # This is one idempotent operation replayed through different
            # deprecated metadata hints. Neither hint authorizes the call or
            # causes the backend to execute twice.
            self.assertEqual(len(backend.calls), 1)

    def test_system_socket_accepts_unmapped_root_identity(self) -> None:
        backend = RecordingBackend()
        service, _ = service_for(backend)
        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o750)
            os.chmod(runtime, 0o750)
            socket_path = runtime / "broker.sock"
            with UnixBrokerServer(socket_path, service):
                real_lstat = os.lstat
                real_peer_credentials = broker_module.resolve_peer_credentials

                def unmapped_identity(path: str) -> os.stat_result:
                    metadata = real_lstat(path)
                    fields = list(metadata)
                    fields[4] = 65534
                    fields[5] = 65534
                    return os.stat_result(fields)

                def unmapped_client_peer(
                    connection: socket.socket,
                ) -> PeerCredentials:
                    credentials = real_peer_credentials(connection)
                    if connection.getpeername() == str(socket_path):
                        return PeerCredentials(
                            uid=65534,
                            gid=65534,
                            pid=credentials.pid,
                        )
                    return credentials

                with mock.patch.object(
                    broker_module, "SYSTEM_BROKER_SOCKET_PATH", socket_path
                ), mock.patch.object(
                    os, "lstat", new=unmapped_identity
                ), mock.patch.object(
                    broker_module,
                    "resolve_peer_credentials",
                    new=unmapped_client_peer,
                ), mock.patch.object(
                    BrokerClient, "_require_available", return_value=None
                ):
                    reply = BrokerClient(
                        socket_path,
                    ).call(request_for())

                self.assertTrue(reply["ok"], reply)
                self.assertEqual(len(backend.calls), 1)

                with mock.patch.object(
                    os, "lstat", new=unmapped_identity
                ), mock.patch.object(
                    BrokerClient, "_require_available", return_value=None
                ):
                    custom_path = BrokerClient(
                        socket_path,
                    ).call(request_for())

                self.assertTrue(custom_path["ok"], custom_path)
                self.assertEqual(len(backend.calls), 2)

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
                request_timeout_seconds=0.1,
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

    def test_host_observation_saturation_preserves_socket_capacity_for_other_work(
        self,
    ) -> None:
        release = threading.Event()
        two_observers_entered = threading.Event()

        class HostBlockingBackend:
            def __init__(self) -> None:
                self.lock = threading.Lock()
                self.active_observers = 0
                self.operations: list[BrokerOperation] = []

            def execute(
                self, request: AcceptedBrokerRequest
            ) -> Mapping[str, Any]:
                operation = request.request.operation
                with self.lock:
                    self.operations.append(operation)
                    if operation == BrokerOperation.HOST_OBSERVE:
                        self.active_observers += 1
                        if self.active_observers == 2:
                            two_observers_entered.set()
                try:
                    if operation == BrokerOperation.HOST_OBSERVE:
                        if not release.wait(timeout=4.0):
                            raise RuntimeError(
                                "host observation capacity fixture timed out"
                            )
                    return {"operation": operation.value, "accepted": True}
                finally:
                    if operation == BrokerOperation.HOST_OBSERVE:
                        with self.lock:
                            self.active_observers -= 1

        backend = HostBlockingBackend()
        service = BrokerService(
            TrustedLocalRequestAcceptor(),
            SerializedMutationWriter(
                backend,  # type: ignore[arg-type]
                max_concurrent_host_observations=2,
            ),
        )

        with CanonicalTemporaryDirectory() as root:
            runtime_dir = root / "runtime"
            runtime_dir.mkdir(mode=0o750)
            os.chmod(runtime_dir, 0o750)
            socket_path = runtime_dir / "broker.sock"
            server = UnixBrokerServer(socket_path, service, max_clients=4)
            server.start()
            replies: list[dict[str, Any]] = []
            failures: list[BaseException] = []

            def call_observe() -> None:
                try:
                    replies.append(
                        BrokerClient(
                            socket_path,
                            timeout_seconds=5.0,
                        ).call(
                            request_for(
                                BrokerOperation.HOST_OBSERVE,
                                resource_id=PROJECT_ID,
                            )
                        )
                    )
                except BaseException as error:  # pragma: no cover - diagnostics
                    failures.append(error)

            workers = [threading.Thread(target=call_observe) for _ in range(2)]
            for worker in workers:
                worker.start()
            try:
                self.assertTrue(
                    two_observers_entered.wait(timeout=2.0),
                    "two long observations did not reach the backend boundary",
                )

                started = time.monotonic()
                excess = BrokerClient(
                    socket_path,
                    timeout_seconds=1.0,
                ).call(
                    request_for(
                        BrokerOperation.HOST_OBSERVE,
                        resource_id=PROJECT_ID,
                    )
                )
                self.assertLess(time.monotonic() - started, 1.0)
                self.assertFalse(excess["ok"], excess)
                self.assertEqual(
                    excess["error"]["code"], "host_observation_busy"
                )

                inventory = BrokerClient(
                    socket_path,
                    timeout_seconds=1.0,
                ).call(
                    request_for(
                        BrokerOperation.INVENTORY_READ,
                        resource_id=PROJECT_ID,
                    )
                )
                mutation = BrokerClient(
                    socket_path,
                    timeout_seconds=1.0,
                ).call(request_for(BrokerOperation.DOCKER_STOP))
                self.assertTrue(inventory["ok"], inventory)
                self.assertTrue(mutation["ok"], mutation)
            finally:
                release.set()
                for worker in workers:
                    worker.join(timeout=3.0)
                server.close()

        self.assertFalse(any(worker.is_alive() for worker in workers), failures)
        self.assertEqual(failures, [])
        self.assertEqual(len(replies), 2)
        self.assertTrue(all(reply["ok"] for reply in replies), replies)
        self.assertEqual(
            backend.operations.count(BrokerOperation.HOST_OBSERVE),
            2,
            "the rejected observation must not consume backend or single-flight work",
        )
        self.assertIn(BrokerOperation.INVENTORY_READ, backend.operations)
        self.assertIn(BrokerOperation.DOCKER_STOP, backend.operations)

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

    def test_real_unknown_peer_uses_configured_policy_union(self) -> None:
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
                ).call(request)

        self.assertTrue(reply["ok"], reply)
        self.assertEqual(reply["operation_id"], request.operation_id)
        self.assertEqual(len(backend.calls), 1)
        self.assertEqual(backend.calls[0].peer.uid, os.geteuid())

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

    def test_direct_start_never_reclaims_dead_socket_or_runtime_siblings(self) -> None:
        backend = RecordingBackend()
        service, _ = service_for(backend)
        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o750)
            os.chmod(runtime, 0o750)
            socket_path = runtime / "broker.sock"
            create_dead_unix_socket(socket_path)
            runtime_identity = (os.lstat(runtime).st_dev, os.lstat(runtime).st_ino)
            secrets = runtime / "ephemeral-secrets"
            secrets.mkdir(mode=0o700)
            sentinel = secrets / "untouched"
            sentinel.write_text("preserve sibling", encoding="utf-8")
            secrets_identity = (os.lstat(secrets).st_dev, os.lstat(secrets).st_ino)
            server = UnixBrokerServer(socket_path, service)

            with self.assertRaises(BrokerError) as raised:
                server.start()
            self.assertEqual(raised.exception.code, "socket_path_exists")
            current = os.lstat(socket_path)
            self.assertTrue(stat.S_ISSOCK(current.st_mode))
            self.assertEqual(
                runtime_identity,
                (os.lstat(runtime).st_dev, os.lstat(runtime).st_ino),
            )
            self.assertEqual(
                secrets_identity,
                (os.lstat(secrets).st_dev, os.lstat(secrets).st_ino),
            )
            self.assertEqual(
                sentinel.read_text(encoding="utf-8"),
                "preserve sibling",
            )
            os.unlink(socket_path)

    def test_stale_socket_without_service_lock_is_untouched(self) -> None:
        backend = RecordingBackend()
        service, _ = service_for(backend)
        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o750)
            os.chmod(runtime, 0o750)
            socket_path = runtime / "broker.sock"
            stale_identity = create_dead_unix_socket(socket_path)
            server = UnixBrokerServer(socket_path, service)

            with self.assertRaises(BrokerError) as raised:
                server.start()

            self.assertEqual(raised.exception.code, "socket_path_exists")
            current = os.lstat(socket_path)
            self.assertEqual(stale_identity, (current.st_dev, current.st_ino))
            os.unlink(socket_path)

    def test_stale_socket_has_no_issuer_construction_or_replay_surface(self) -> None:
        backend = RecordingBackend()
        service, _ = service_for(backend)
        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o750)
            os.chmod(runtime, 0o750)
            socket_path = runtime / "broker.sock"
            stale_identity = create_dead_unix_socket(socket_path)
            server = UnixBrokerServer(socket_path, service)

            with self.assertRaises(AttributeError):
                getattr(broker_module, "_issue_broker_service_lock_capability")()
            with self.assertRaises(AttributeError):
                getattr(broker_module, "_BrokerServiceLockCapability")()

            class MutableLookalike:
                pass

            synthetic = object()
            mutated = MutableLookalike()
            mutated._issuer = object()
            mutated._active = False
            mutated._active = True
            with exclusive_broker_service_lock(
                root / "coordinator.sqlite3"
            ) as captured_scope_value:
                self.assertIsNone(captured_scope_value)

            for label, candidate in (
                ("synthetic", synthetic),
                ("mutated_lookalike", mutated),
                ("replayed_scope_value", captured_scope_value),
            ):
                with self.subTest(label=label):
                    with self.assertRaises(TypeError):
                        server.start(stale_socket_recovery_capability=candidate)
                    current = os.lstat(socket_path)
                    self.assertEqual(stale_identity, (current.st_dev, current.st_ino))

            with self.assertRaises(BrokerError) as direct:
                server.start()
            self.assertEqual(direct.exception.code, "socket_path_exists")
            os.unlink(socket_path)

    def test_service_locked_start_keeps_live_socket_untouched(self) -> None:
        backend = RecordingBackend()
        service, _ = service_for(backend)
        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o750)
            os.chmod(runtime, 0o750)
            socket_path = runtime / "broker.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(socket_path))
            os.chmod(socket_path, 0o660)
            listener.listen(2)
            live_identity = (os.lstat(socket_path).st_dev, os.lstat(socket_path).st_ino)
            server = UnixBrokerServer(socket_path, service)
            try:
                with exclusive_broker_service_lock(
                    root / "coordinator.sqlite3"
                ):
                    with self.assertRaises(BrokerError) as raised:
                        server.start()
                self.assertEqual(raised.exception.code, "socket_path_exists")
                current = os.lstat(socket_path)
                self.assertEqual(live_identity, (current.st_dev, current.st_ino))
            finally:
                listener.close()
                os.unlink(socket_path)

    def test_service_locked_start_keeps_foreign_or_mismatched_paths_untouched(
        self,
    ) -> None:
        backend = RecordingBackend()
        service, _ = service_for(backend)
        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o750)
            os.chmod(runtime, 0o750)
            socket_path = runtime / "broker.sock"

            socket_path.write_text("operator-owned", encoding="utf-8")
            with exclusive_broker_service_lock(
                root / "coordinator.sqlite3"
            ):
                with self.assertRaises(BrokerError) as regular:
                    UnixBrokerServer(socket_path, service).start()
            self.assertEqual(regular.exception.code, "socket_path_exists")
            self.assertEqual(socket_path.read_text(encoding="utf-8"), "operator-owned")
            socket_path.unlink()

            target = runtime / "operator-target"
            target.write_text("symlink target", encoding="utf-8")
            socket_path.symlink_to(target)
            with exclusive_broker_service_lock(
                root / "coordinator.sqlite3"
            ):
                with self.assertRaises(BrokerError) as symlink:
                    UnixBrokerServer(socket_path, service).start()
            self.assertEqual(symlink.exception.code, "socket_path_exists")
            self.assertTrue(socket_path.is_symlink())
            self.assertEqual(target.read_text(encoding="utf-8"), "symlink target")
            socket_path.unlink()

            wrong_mode_identity = create_dead_unix_socket(socket_path, mode=0o600)
            with exclusive_broker_service_lock(
                root / "coordinator.sqlite3"
            ):
                with self.assertRaises(BrokerError) as wrong_mode:
                    UnixBrokerServer(socket_path, service).start()
            self.assertEqual(wrong_mode.exception.code, "socket_path_exists")
            current = os.lstat(socket_path)
            self.assertEqual(wrong_mode_identity, (current.st_dev, current.st_ino))
            os.unlink(socket_path)

            wrong_owner_identity = create_dead_unix_socket(socket_path)
            real_lstat = broker_module.os.lstat

            def wrong_owner(path: str) -> os.stat_result:
                info = real_lstat(path)
                if Path(path) == socket_path:
                    values = list(info)
                    values[4] = int(info.st_uid) + 1
                    return os.stat_result(values)
                return info

            with mock.patch.object(
                broker_module.os,
                "lstat",
                side_effect=wrong_owner,
            ):
                with exclusive_broker_service_lock(
                    root / "coordinator.sqlite3"
                ):
                    with self.assertRaises(BrokerError) as wrong_owner_error:
                        UnixBrokerServer(socket_path, service).start()
            self.assertEqual(wrong_owner_error.exception.code, "socket_path_exists")
            current = os.lstat(socket_path)
            self.assertEqual(wrong_owner_identity, (current.st_dev, current.st_ino))
            os.unlink(socket_path)

    def test_direct_start_does_not_probe_or_unlink_stale_socket(self) -> None:
        backend = RecordingBackend()
        service, _ = service_for(backend)
        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o750)
            os.chmod(runtime, 0o750)
            socket_path = runtime / "broker.sock"
            stale_identity = create_dead_unix_socket(socket_path)
            with mock.patch.object(
                broker_module.os,
                "unlink",
                side_effect=AssertionError("direct startup must not unlink"),
            ):
                with self.assertRaises(BrokerError) as raised:
                    UnixBrokerServer(socket_path, service).start()
            self.assertEqual(raised.exception.code, "socket_path_exists")
            current = os.lstat(socket_path)
            self.assertEqual(stale_identity, (current.st_dev, current.st_ino))
            os.unlink(socket_path)

    def test_service_locked_start_keeps_stale_socket_when_unlink_fails(self) -> None:
        backend = RecordingBackend()
        service, _ = service_for(backend)
        with CanonicalTemporaryDirectory() as root:
            runtime = root / "runtime"
            runtime.mkdir(mode=0o750)
            os.chmod(runtime, 0o750)
            socket_path = runtime / "broker.sock"
            stale_identity = create_dead_unix_socket(socket_path)
            real_unlink = broker_module.os.unlink

            def reject_socket_unlink(
                path: str,
                *args: object,
                **kwargs: object,
            ) -> None:
                if Path(path) == socket_path:
                    raise PermissionError("injected unlink denial")
                real_unlink(path, *args, **kwargs)

            with mock.patch.object(
                broker_module.os,
                "unlink",
                side_effect=reject_socket_unlink,
            ):
                with exclusive_broker_service_lock(
                    root / "coordinator.sqlite3"
                ):
                    with self.assertRaises(BrokerError) as raised:
                        UnixBrokerServer(socket_path, service).start()
            self.assertEqual(raised.exception.code, "socket_path_exists")
            current = os.lstat(socket_path)
            self.assertEqual(stale_identity, (current.st_dev, current.st_ino))
            os.unlink(socket_path)

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
                ).call(request)
            thread.join(timeout=2.0)

            self.assertFalse(thread.is_alive(), failures)
            self.assertEqual(failures, [])
            self.assertEqual(raised.exception.code, "reply_operation_mismatch")
        self.assertEqual(raised.exception.operation_id, request.operation_id)


class StoreBackedBrokerTests(unittest.TestCase):
    def test_broker_uses_the_store_contention_budget(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence = BrokerPersistence(root / "coordinator.sqlite3")
        self.assertEqual(persistence.busy_timeout_ms, 30_000)

    def test_production_runtime_wires_service_owned_compose_renderer(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            runtime = build_store_backed_broker_runtime(
                database_path=persistence.database_path,
                socket_path=root / "runtime/broker.sock",
                host_mutations=actions,
                service_uid=os.geteuid(),
            )

            self.assertIs(
                runtime.persistence.compose_model_renderer,
                render_compose_effective_model,
            )

    def test_host_observe_runtime_supplies_production_snapshot_store_contract(
        self,
    ) -> None:
        callback_store_types: list[type[CoordinatorStore]] = []

        def production_snapshot_observer(
            store: CoordinatorStore,
        ) -> Mapping[str, Any]:
            callback_store_types.append(type(store))
            return dev_coordinator.observe_broker_service_store_for_configuration(store)

        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            service = BrokerService(
                StoreBackedRequestAcceptor(persistence),
                SerializedMutationWriter(
                    StoreBackedMutationBackend(
                        persistence,
                        actions,
                        observe_before_lifecycle_plan=production_snapshot_observer,
                    )
                ),
            )

            with mock.patch.object(
                dev_coordinator,
                "build_inventory",
                return_value={
                    "servers": [],
                    "docker": {
                        "available": True,
                        "containers": [],
                        "postgres": [],
                    },
                    "postgres": [],
                },
            ):
                reply = service.reply_for_document(
                    peer_for(),
                    request_for(
                        BrokerOperation.HOST_OBSERVE, resource_id=PROJECT_ID
                    ).to_wire(),
                )

        self.assertTrue(reply["ok"], reply)
        self.assertEqual(callback_store_types, [AccountStore])
        self.assertEqual(reply["result"]["status"], "completed")

    def test_runtime_close_serializes_every_shutdown_failure_without_private_text(
        self,
    ) -> None:
        class FailingBackend:
            def __init__(self) -> None:
                self.calls = 0

            def request_ephemeral_reaper_stop(self) -> None:
                return None

            def wait_ephemeral_reaper_stopped(self, _timeout: float) -> None:
                raise RuntimeError("private reaper diagnostic")

            def begin_shutdown_host_observations(self) -> int:
                self.calls += 1
                raise RuntimeError(f"private cleanup diagnostic {self.calls}")

        class FailingServer:
            def close(self, *, timeout_seconds: float | None = None) -> None:
                del timeout_seconds
                raise BrokerError(
                    "shutdown_timeout",
                    "Broker clients did not drain before the shutdown deadline.",
                )

        class FailingWriter:
            def begin_shutdown(self) -> int:
                raise RuntimeError("private mutation-fence diagnostic")

            def wait_for_drain(self, _timeout: float) -> bool:
                raise RuntimeError("private mutation-drain diagnostic")

        backend = FailingBackend()
        runtime = StoreBackedBrokerRuntime(
            persistence=mock.Mock(),
            backend=backend,  # type: ignore[arg-type]
            writer=FailingWriter(),  # type: ignore[arg-type]
            service=mock.Mock(),
            server=FailingServer(),  # type: ignore[arg-type]
            shutdown_timeout_seconds=0.1,
        )

        with self.assertRaises(BrokerError) as raised:
            runtime.close()

        self.assertEqual(raised.exception.code, "broker_shutdown_failed")
        message = raised.exception.message
        self.assertIn("mutation admission fence: RuntimeError", message)
        self.assertIn("mutation drain: RuntimeError", message)
        self.assertIn("ephemeral reaper drain: RuntimeError", message)
        self.assertIn("initial observation cleanup: RuntimeError", message)
        self.assertIn("server drain: shutdown_timeout", message)
        self.assertIn("final observation cleanup: RuntimeError", message)
        self.assertNotIn("private cleanup diagnostic", message)
        self.assertNotIn("private reaper diagnostic", message)
        self.assertEqual(backend.calls, 2)

    def test_reaper_stop_request_does_not_join_a_blocked_host_call(self) -> None:
        entered_host = threading.Event()
        release_host = threading.Event()
        host_calls: list[str] = []

        class BlockingReaperHost:
            @staticmethod
            def reconcile_ephemeral_container(run_id: str) -> None:
                host_calls.append(run_id)
                if run_id == "run-a":
                    entered_host.set()
                    if not release_host.wait(timeout=3.0):
                        raise RuntimeError("blocked host-call fixture timed out")

        class Target:
            def __init__(self, run_id: str) -> None:
                self.run_id = run_id

        class HostCallingReaper(EphemeralContainerCoordinator):
            @staticmethod
            def _recovery_targets(*, due_before: int | None = None):
                del due_before
                return (Target("run-a"), Target("run-b"))

            def _recover_target(self, target: Target) -> None:
                self._host.reconcile_ephemeral_container(target.run_id)

        reaper = HostCallingReaper(
            mock.Mock(),
            BlockingReaperHost(),
            reaper_interval_seconds=3600,
        )
        reaper.start_reaper()
        self.assertTrue(
            entered_host.wait(timeout=1.0),
            "reaper did not reach the blocking host-call boundary",
        )
        try:
            reaper.request_reaper_stop()
            self.assertFalse(
                release_host.is_set(),
                "stop request unexpectedly controlled the host-call fixture",
            )
            with self.assertRaises(BrokerError) as raised:
                reaper.wait_reaper_stopped(0.0)
            self.assertEqual(
                raised.exception.code, "ephemeral_reaper_shutdown_timeout"
            )
        finally:
            release_host.set()
            reaper.wait_reaper_stopped(1.0)
        self.assertEqual(
            host_calls,
            ["run-a"],
            "shutdown must not begin another bounded host call in the same pass",
        )

        stopped_before_start = HostCallingReaper(
            mock.Mock(),
            BlockingReaperHost(),
            reaper_interval_seconds=3600,
        )
        stopped_before_start.request_reaper_stop()
        stopped_before_start.start_reaper()
        stopped_before_start.wait_reaper_stopped(0.0)
        self.assertEqual(
            host_calls,
            ["run-a"],
            "a signal-turn stop request must not be cleared by a late start",
        )

    def test_runtime_joins_reaper_after_transport_and_writer_drain(self) -> None:
        events: list[str] = []
        test_case = self

        class OrderedBackend:
            def request_ephemeral_reaper_stop(self) -> None:
                events.append("reaper-stop-requested")

            def wait_ephemeral_reaper_stopped(self, timeout: float) -> None:
                test_case.assertGreater(timeout, 0.5)
                test_case.assertLessEqual(timeout, 1.0)
                test_case.assertEqual(events[-1], "writer-drained")
                events.append("reaper-stopped")

            def begin_shutdown_host_observations(self) -> int:
                events.append("observations-cleaned")
                return 0

        class OrderedWriter:
            def begin_shutdown(self) -> int:
                events.append("mutation-fenced")
                return 0

            def wait_for_drain(self, timeout: float) -> bool:
                test_case.assertGreater(timeout, 0.0)
                events.append("writer-drained")
                return True

        class OrderedServer:
            @staticmethod
            def close(*, timeout_seconds: float | None = None) -> None:
                test_case.assertIsNotNone(timeout_seconds)
                events.append("server-drained")

        runtime = StoreBackedBrokerRuntime(
            persistence=mock.Mock(),
            backend=OrderedBackend(),  # type: ignore[arg-type]
            writer=OrderedWriter(),  # type: ignore[arg-type]
            service=mock.Mock(),
            server=OrderedServer(),  # type: ignore[arg-type]
            shutdown_timeout_seconds=1.0,
        )

        runtime.close()

        self.assertEqual(
            events,
            [
                "mutation-fenced",
                "reaper-stop-requested",
                "server-drained",
                "writer-drained",
                "reaper-stopped",
                "observations-cleaned",
                "observations-cleaned",
            ],
        )

    def test_shutdown_fences_late_database_mutation_and_drains_accepted_result(
        self,
    ) -> None:
        for fail_after_release in (False, True):
            with self.subTest(fail_after_release=fail_after_release), CanonicalTemporaryDirectory() as root:
                persistence, _unused = seed_store_backed_broker(root)
                seed_postgres_database(persistence)
                entered = threading.Event()
                release = threading.Event()
                actions = BlockingPostgresHostActions(
                    entered,
                    release,
                    fail_after_release=fail_after_release,
                )
                runtime = build_store_backed_broker_runtime(
                    database_path=persistence.database_path,
                    socket_path=root / "runtime/broker.sock",
                    host_mutations=actions,
                    service_uid=os.geteuid(),
                    shutdown_timeout_seconds=3.0,
                    observe_before_lifecycle_plan=_committed_available_observer,
                )
                first_request = request_for(
                    BrokerOperation.DATABASE_BACKUP,
                    arguments={"database_name": DATABASE_NAME},
                )
                late_request = request_for(
                    BrokerOperation.DATABASE_BACKUP,
                    arguments={"database_name": DATABASE_NAME},
                )
                first_replies: list[dict[str, Any]] = []
                first_failures: list[BaseException] = []

                def run_first() -> None:
                    try:
                        first_replies.append(
                            runtime.service.reply_for_document(
                                peer_for(), first_request.to_wire()
                            )
                        )
                    except BaseException as error:  # pragma: no cover - diagnostics
                        first_failures.append(error)

                first_worker = threading.Thread(target=run_first)
                first_worker.start()
                self.assertTrue(
                    entered.wait(timeout=2.0),
                    f"database mutation never reached host boundary; failures={first_failures!r}",
                )
                self.assertEqual(runtime.writer.admitted_mutation_count, 1)
                with CoordinatorStore.open(
                    persistence.database_path, expected_uid=os.geteuid()
                ) as store:
                    with store.read_transaction() as connection:
                        running = connection.execute(
                            "SELECT status, phase FROM operations WHERE operation_id = ?",
                            (first_request.operation_id,),
                        ).fetchone()
                self.assertIsNotNone(running)
                self.assertEqual(running["status"], "running")
                self.assertEqual(running["phase"], "host_backup")

                close_failures: list[BaseException] = []

                def close_runtime() -> None:
                    try:
                        runtime.close()
                    except BaseException as error:  # pragma: no cover - diagnostics
                        close_failures.append(error)

                closer = threading.Thread(target=close_runtime)
                closer.start()
                deadline = time.monotonic() + 2.0
                while runtime.writer.accepting_mutations and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertFalse(runtime.writer.accepting_mutations)

                late = runtime.service.reply_for_document(
                    peer_for(), late_request.to_wire()
                )
                self.assertFalse(late["ok"], late)
                self.assertEqual(late["error"]["code"], "service_shutting_down")
                with CoordinatorStore.open(
                    persistence.database_path, expected_uid=os.geteuid()
                ) as store:
                    with store.read_transaction() as connection:
                        late_operation = connection.execute(
                            "SELECT 1 FROM operations WHERE operation_id = ?",
                            (late_request.operation_id,),
                        ).fetchone()
                        late_reservation = connection.execute(
                            "SELECT 1 FROM broker_operation_requests WHERE operation_id = ?",
                            (late_request.operation_id,),
                        ).fetchone()
                self.assertIsNone(late_operation)
                self.assertIsNone(late_reservation)
                self.assertTrue(closer.is_alive(), close_failures)

                release.set()
                first_worker.join(timeout=3.0)
                closer.join(timeout=3.0)
                self.assertFalse(first_worker.is_alive(), first_failures)
                self.assertFalse(closer.is_alive(), close_failures)
                self.assertEqual(first_failures, [])
                self.assertEqual(close_failures, [])
                self.assertEqual(len(first_replies), 1)
                self.assertEqual(len(actions.postgres_calls), 1)
                with CoordinatorStore.open(
                    persistence.database_path, expected_uid=os.geteuid()
                ) as store:
                    with store.read_transaction() as connection:
                        retained_status = connection.execute(
                            "SELECT status FROM operations WHERE operation_id = ?",
                            (first_request.operation_id,),
                        ).fetchone()[0]
                        backup_count = connection.execute(
                            "SELECT COUNT(*) FROM database_backups"
                        ).fetchone()[0]
                if fail_after_release:
                    self.assertFalse(first_replies[0]["ok"], first_replies)
                    self.assertEqual(
                        first_replies[0]["error"]["code"], "mutation_failed"
                    )
                    self.assertEqual(retained_status, "failed")
                    self.assertEqual(backup_count, 0)
                else:
                    self.assertTrue(first_replies[0]["ok"], first_replies)
                    self.assertEqual(retained_status, "succeeded")
                    self.assertEqual(backup_count, 1)

                replacement_actions = RecordingPostgresHostActions()
                replacement = build_store_backed_broker_runtime(
                    database_path=persistence.database_path,
                    socket_path=root / "replacement/broker.sock",
                    host_mutations=replacement_actions,
                    service_uid=os.geteuid(),
                    shutdown_timeout_seconds=1.0,
                    observe_before_lifecycle_plan=_committed_available_observer,
                )
                try:
                    replayed = replacement.service.reply_for_document(
                        peer_for(), first_request.to_wire()
                    )
                finally:
                    replacement.close()
                self.assertEqual(replayed["ok"], not fail_after_release, replayed)
                if fail_after_release:
                    self.assertEqual(replayed["error"]["code"], "mutation_failed")
                else:
                    self.assertEqual(
                        replayed["result"], first_replies[0]["result"]
                    )
                self.assertEqual(replacement_actions.postgres_calls, [])

    def test_host_observe_commits_service_owned_snapshot_without_client_paths(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            service = store_backed_service(persistence, actions)
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                before = store.metadata.observation_revision

            request = request_for(
                BrokerOperation.HOST_OBSERVE,
                resource_id=PROJECT_ID,
                arguments={},
            )
            reply = service.reply_for_document(peer_for(), request.to_wire())

            self.assertTrue(reply["ok"], reply)
            self.assertEqual(
                reply["result"]["observer_domain"],
                "host-runtime-v2:full-docker",
            )
            self.assertEqual(reply["result"]["observation_revision"], before + 1)
            self.assertTrue(reply["result"]["observed"])
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    durable_mutation = connection.execute(
                        "SELECT 1 FROM operations WHERE operation_id = ?",
                        (request.operation_id,),
                    ).fetchone()
                    snapshot = connection.execute(
                        """
                        SELECT status, observer_domain FROM observation_snapshots
                        WHERE snapshot_id = ?
                        """,
                        (reply["result"]["snapshot_id"],),
                    ).fetchone()
            self.assertIsNone(durable_mutation)
            self.assertEqual(
                (snapshot["status"], snapshot["observer_domain"]),
                ("completed", "host-runtime-v2:full-docker"),
            )

            invalid = request.to_wire()
            invalid["operation_id"] = str(uuid.uuid4())
            invalid["arguments"] = {"path": "/client-controlled"}
            rejected = service.reply_for_document(peer_for(), invalid)
            self.assertFalse(rejected["ok"], rejected)
            self.assertEqual(rejected["error"]["code"], "invalid_arguments")

    def test_host_observe_reports_committed_docker_unavailable_evidence(self) -> None:
        def unavailable(store: CoordinatorStore) -> Mapping[str, Any]:
            return _committed_observer(store, docker_available=False)

        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            backend = StoreBackedMutationBackend(
                persistence,
                actions,
                observe_before_lifecycle_plan=unavailable,
            )
            service = BrokerService(
                StoreBackedRequestAcceptor(persistence), SerializedMutationWriter(backend)
            )
            reply = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.HOST_OBSERVE, resource_id=PROJECT_ID
                ).to_wire(),
            )

            self.assertTrue(reply["ok"], reply)
            self.assertTrue(reply["result"]["observed"])
            self.assertFalse(reply["result"]["docker_available"])
            self.assertEqual(reply["result"]["status"], "completed")

    def test_runtime_shutdown_drains_owned_ticket_and_replacement_is_prompt(
        self,
    ) -> None:
        sampler_entered = threading.Event()
        release_sampler = threading.Event()

        def observer_callback(*, block: bool) -> Any:
            def observe(store: CoordinatorStore) -> Mapping[str, Any]:
                def sample() -> Mapping[str, Any]:
                    if block:
                        sampler_entered.set()
                        if not release_sampler.wait(timeout=5.0):
                            raise RuntimeError(
                                "shutdown observation fixture timed out"
                            )
                    return {
                        "sampled_at": utc_timestamp(),
                        "inventory": {
                            "servers": [],
                            "docker": {
                                "available": True,
                                "containers": [],
                                "postgres": [],
                            },
                        },
                    }

                def commit(
                    connection: sqlite3.Connection,
                    snapshot_id: str,
                    measured: Mapping[str, Any],
                ) -> None:
                    committed_at = str(measured["sampled_at"])
                    connection.execute(
                        """
                        INSERT INTO observation_capabilities(
                            snapshot_id, observer_domain, docker_available,
                            capability_fingerprint, committed_at
                        ) VALUES (?, 'host-runtime-v2:full-docker', 1, ?, ?)
                        """,
                        (snapshot_id, "sha256:" + "6" * 64, committed_at),
                    )
                    connection.execute(
                        """
                        UPDATE schema_metadata
                        SET observation_revision = observation_revision + 1,
                            updated_at = ? WHERE singleton = 1
                        """,
                        (committed_at,),
                    )

                outcome = SingleFlightObserver(
                    store, join_timeout=1.0
                ).observe(
                    host_id=HOST_ID,
                    observer_domain="host-runtime-v2:full-docker",
                    sampler=sample,
                    commit=commit,
                )
                return {
                    "snapshot_id": outcome.snapshot_id,
                    "host_id": outcome.host_id,
                    "observer_domain": outcome.observer_domain,
                    "joined": outcome.joined,
                    "completed_at": outcome.completed_at,
                    "material_fingerprint": outcome.material_fingerprint,
                    "docker_available": True,
                    "capability_fingerprint": "sha256:" + "6" * 64,
                }

            return observe

        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            unowned_snapshot_id = str(uuid.uuid4())
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        INSERT INTO observation_snapshots(
                            snapshot_id, host_id, observer_domain, status, started_at
                        ) VALUES (?, ?, 'account-unowned-fixture', 'running', ?)
                        """,
                        (unowned_snapshot_id, HOST_ID, utc_timestamp()),
                    )

            runtime_dir = root / "runtime"
            runtime_dir.mkdir(mode=0o750)
            os.chmod(runtime_dir, 0o750)
            socket_path = runtime_dir / "broker.sock"
            runtime = build_store_backed_broker_runtime(
                database_path=persistence.database_path,
                socket_path=socket_path,
                host_mutations=actions,
                service_uid=os.geteuid(),
                max_clients=4,
                observe_before_lifecycle_plan=observer_callback(block=True),
            )
            runtime.server.start()
            request_failures: list[BaseException] = []
            request_replies: list[dict[str, Any]] = []

            def request_observation() -> None:
                try:
                    request_replies.append(
                        BrokerClient(
                            socket_path,
                            timeout_seconds=5.0,
                        ).call(
                            request_for(
                                BrokerOperation.HOST_OBSERVE,
                                resource_id=PROJECT_ID,
                            )
                        )
                    )
                except BaseException as error:
                    request_failures.append(error)

            request_worker = threading.Thread(target=request_observation)
            request_worker.start()
            self.assertTrue(sampler_entered.wait(timeout=2.0))
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    owned = connection.execute(
                        """
                        SELECT s.snapshot_id, o.broker_instance_id
                        FROM observation_snapshots s
                        JOIN broker_host_observation_sessions o USING(snapshot_id)
                        WHERE s.observer_domain = 'host-runtime-v2:full-docker'
                          AND s.status = 'running'
                        """
                    ).fetchone()
            self.assertIsNotNone(owned)
            old_snapshot_id = str(owned["snapshot_id"])
            self.assertTrue(str(owned["broker_instance_id"]).startswith("broker-"))

            close_failures: list[BaseException] = []

            def close_runtime() -> None:
                try:
                    runtime.close()
                except BaseException as error:  # pragma: no cover - diagnostics
                    close_failures.append(error)

            closer = threading.Thread(target=close_runtime)
            closer.start()
            deadline = time.monotonic() + 2.0
            while runtime.writer.accepting_mutations and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertFalse(runtime.writer.accepting_mutations)
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    old_status = connection.execute(
                        """
                        SELECT status, error_code FROM observation_snapshots
                        WHERE snapshot_id = ?
                        """,
                        (old_snapshot_id,),
                    ).fetchone()
            self.assertIsNotNone(old_status)
            self.assertEqual(old_status["status"], "running")
            self.assertIsNone(old_status["error_code"])

            late = runtime.service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.HOST_OBSERVE,
                    resource_id=PROJECT_ID,
                ).to_wire(),
            )
            self.assertFalse(late["ok"], late)
            self.assertEqual(late["error"]["code"], "service_shutting_down")

            release_sampler.set()
            request_worker.join(timeout=3.0)
            closer.join(timeout=3.0)
            self.assertFalse(request_worker.is_alive(), request_failures)
            self.assertFalse(closer.is_alive(), close_failures)
            self.assertEqual(request_failures, [])
            self.assertEqual(close_failures, [])
            self.assertEqual(len(request_replies), 1)
            self.assertTrue(request_replies[0]["ok"], request_replies)

            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    unowned_status = connection.execute(
                        "SELECT status FROM observation_snapshots WHERE snapshot_id = ?",
                        (unowned_snapshot_id,),
                    ).fetchone()[0]
                    running_owned = connection.execute(
                        """
                        SELECT COUNT(*) FROM observation_snapshots s
                        JOIN broker_host_observation_sessions o USING(snapshot_id)
                        WHERE s.status = 'running'
                        """
                    ).fetchone()[0]
                    completed = connection.execute(
                        "SELECT status FROM observation_snapshots WHERE snapshot_id = ?",
                        (old_snapshot_id,),
                    ).fetchone()[0]
            self.assertEqual(unowned_status, "running")
            self.assertEqual(running_owned, 0)
            self.assertEqual(completed, "completed")

            replacement = build_store_backed_broker_runtime(
                database_path=persistence.database_path,
                socket_path=socket_path,
                host_mutations=actions,
                service_uid=os.geteuid(),
                max_clients=4,
                observe_before_lifecycle_plan=observer_callback(block=False),
            )
            replacement.server.start()
            try:
                started = time.monotonic()
                refreshed = BrokerClient(
                    socket_path,
                    timeout_seconds=2.0,
                ).call(
                    request_for(
                        BrokerOperation.HOST_OBSERVE,
                        resource_id=PROJECT_ID,
                    )
                )
                self.assertLess(time.monotonic() - started, 2.0)
                self.assertTrue(refreshed["ok"], refreshed)
                self.assertNotEqual(
                    refreshed["result"]["snapshot_id"], old_snapshot_id
                )
            finally:
                replacement.close()

    def test_host_observe_sampler_exception_returns_redacted_broker_error(self) -> None:
        def failed_sampler(_store: CoordinatorStore) -> Mapping[str, Any]:
            raise RuntimeError("private sampler diagnostic")

        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            service = BrokerService(
                StoreBackedRequestAcceptor(persistence),
                SerializedMutationWriter(
                    StoreBackedMutationBackend(
                        persistence,
                        actions,
                        observe_before_lifecycle_plan=failed_sampler,
                    )
                ),
            )

            reply = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.HOST_OBSERVE, resource_id=PROJECT_ID
                ).to_wire(),
            )

            self.assertFalse(reply["ok"], reply)
            self.assertEqual(reply["error"]["code"], "mutation_failed")
            self.assertNotIn("private sampler diagnostic", reply["error"]["message"])

    def test_host_observe_rejects_callback_host_mismatch(self) -> None:
        def mismatched_host(store: CoordinatorStore) -> Mapping[str, Any]:
            evidence = dict(_committed_available_observer(store))
            evidence["host_id"] = "host-wrong"
            return evidence

        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            service = BrokerService(
                StoreBackedRequestAcceptor(persistence),
                SerializedMutationWriter(
                    StoreBackedMutationBackend(
                        persistence,
                        actions,
                        observe_before_lifecycle_plan=mismatched_host,
                    )
                ),
            )

            reply = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.HOST_OBSERVE, resource_id=PROJECT_ID
                ).to_wire(),
            )

            self.assertFalse(reply["ok"], reply)
            self.assertEqual(
                reply["error"]["code"], "lifecycle_observation_incomplete"
            )

    def test_concurrent_host_observe_requests_join_one_committed_snapshot(self) -> None:
        sampler_entered = threading.Event()
        release_sampler = threading.Event()
        sampler_lock = threading.Lock()
        observer_barrier = threading.Barrier(2)
        joiner_entered = threading.Event()
        sampler_calls = 0

        class InstrumentedObserver(SingleFlightObserver):
            def _join(self, ticket: Any) -> Any:
                joiner_entered.set()
                return super()._join(ticket)

        def observe(store: CoordinatorStore) -> Mapping[str, Any]:
            def sample() -> Mapping[str, Any]:
                nonlocal sampler_calls
                with sampler_lock:
                    sampler_calls += 1
                sampler_entered.set()
                if not release_sampler.wait(timeout=3.0):
                    raise RuntimeError("test sampler release boundary timed out")
                return {
                    "sampled_at": utc_timestamp(),
                    "inventory": {
                        "servers": [],
                        "docker": {
                            "available": True,
                            "containers": [],
                            "postgres": [],
                        },
                    },
                }

            observer_barrier.wait(timeout=2.0)
            def commit(
                connection: sqlite3.Connection,
                snapshot_id: str,
                measured: Mapping[str, Any],
            ) -> None:
                committed_at = str(measured["sampled_at"])
                connection.execute(
                    """
                    INSERT INTO observation_capabilities(
                        snapshot_id, observer_domain, docker_available,
                        capability_fingerprint, committed_at
                    ) VALUES (?, 'host-runtime-v2:full-docker', 1, ?, ?)
                    """,
                    (snapshot_id, "sha256:" + "4" * 64, committed_at),
                )

            outcome = InstrumentedObserver(store, join_timeout=3.0).observe(
                host_id=HOST_ID,
                observer_domain="host-runtime-v2:full-docker",
                sampler=sample,
                commit=commit,
            )
            with store.read_transaction() as connection:
                capability = connection.execute(
                    """
                    SELECT docker_available, capability_fingerprint
                    FROM observation_capabilities WHERE snapshot_id = ?
                    """,
                    (outcome.snapshot_id,),
                ).fetchone()
            return {
                "snapshot_id": outcome.snapshot_id,
                "host_id": outcome.host_id,
                "observer_domain": outcome.observer_domain,
                "joined": outcome.joined,
                "completed_at": outcome.completed_at,
                "material_fingerprint": outcome.material_fingerprint,
                "docker_available": bool(capability["docker_available"]),
                "capability_fingerprint": str(
                    capability["capability_fingerprint"]
                ),
            }

        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            service = BrokerService(
                StoreBackedRequestAcceptor(persistence),
                SerializedMutationWriter(
                    StoreBackedMutationBackend(
                        persistence,
                        actions,
                        observe_before_lifecycle_plan=observe,
                    )
                ),
            )
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                before = store.metadata.observation_revision
            replies: list[dict[str, Any]] = []
            failures: list[BaseException] = []

            def invoke() -> None:
                try:
                    replies.append(
                        service.reply_for_document(
                            peer_for(),
                            request_for(
                                BrokerOperation.HOST_OBSERVE,
                                resource_id=PROJECT_ID,
                            ).to_wire(),
                        )
                    )
                except BaseException as error:  # pragma: no cover - diagnostics
                    failures.append(error)

            workers = [threading.Thread(target=invoke) for _ in range(2)]
            for worker in workers:
                worker.start()
            self.assertTrue(sampler_entered.wait(timeout=1.0))
            self.assertTrue(
                joiner_entered.wait(timeout=1.0),
                "second request did not join the durable observation ticket",
            )
            release_sampler.set()
            for worker in workers:
                worker.join(timeout=3.0)
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                after = store.metadata.observation_revision

        self.assertFalse(any(worker.is_alive() for worker in workers), failures)
        self.assertEqual(failures, [])
        self.assertEqual(sampler_calls, 1)
        self.assertEqual(len(replies), 2)
        self.assertTrue(all(reply["ok"] for reply in replies), replies)
        self.assertEqual(
            {reply["result"]["snapshot_id"] for reply in replies},
            {replies[0]["result"]["snapshot_id"]},
        )
        self.assertEqual(
            sorted(reply["result"]["joined"] for reply in replies),
            [False, True],
        )
        self.assertEqual(after, before + 1)

    def test_host_observe_respects_lifecycle_fence_across_reopen(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        UPDATE repository_installations
                        SET status = 'disabled', startup_fenced = 1, updated_at = ?
                        WHERE repo_id = ?
                        """,
                        (utc_timestamp(), PROJECT_ID),
                    )

            migrated = BrokerPersistence(
                persistence.database_path, expected_uid=os.geteuid()
            )
            service = store_backed_service(migrated, actions)
            fenced = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.HOST_OBSERVE, resource_id=PROJECT_ID
                ).to_wire(),
            )
            self.assertFalse(fenced["ok"], fenced)
            self.assertEqual(
                fenced["error"]["code"], "repository_startup_fenced"
            )
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        UPDATE repository_installations
                        SET status = 'installed', startup_fenced = 0, updated_at = ?
                        WHERE repo_id = ?
                        """,
                        (utc_timestamp(), PROJECT_ID),
                    )
            allowed = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.HOST_OBSERVE, resource_id=PROJECT_ID
                ).to_wire(),
            )
            self.assertTrue(allowed["ok"], allowed)

            reopened = BrokerPersistence(
                persistence.database_path, expected_uid=os.geteuid()
            )
            reopened_reply = store_backed_service(reopened, actions).reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.HOST_OBSERVE, resource_id=PROJECT_ID
                ).to_wire(),
            )
            self.assertTrue(reopened_reply["ok"], reopened_reply)

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

    def test_postgres_backup_retirement_is_exact_confirmed_and_replay_safe(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, _unused = seed_store_backed_broker(root)
            seed_postgres_database(persistence)
            actions = RecordingPostgresHostActions()
            service = store_backed_service(persistence, actions)
            backup_request = request_for(
                BrokerOperation.DATABASE_BACKUP,
                arguments={"database_name": DATABASE_NAME},
            )
            backup = service.reply_for_document(
                peer_for(), backup_request.to_wire()
            )
            self.assertTrue(backup["ok"], backup)
            backup_id = str(backup["result"]["database_backup_id"])
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    row = connection.execute(
                        """
                        SELECT artifact_path, manifest_path FROM database_backups
                        WHERE database_backup_id = ?
                        """,
                        (backup_id,),
                    ).fetchone()
            artifact = Path(str(row["artifact_path"]))
            manifest = Path(str(row["manifest_path"]))
            self.assertTrue(artifact.is_file())
            self.assertTrue(manifest.is_file())
            retire_request = request_for(
                BrokerOperation.DATABASE_BACKUP_RETIRE,
                arguments={
                    "database_name": DATABASE_NAME,
                    "database_backup_id": backup_id,
                    "confirm_backup_id": backup_id,
                },
            )

            retired = service.reply_for_document(
                peer_for(), retire_request.to_wire()
            )
            replay = service.reply_for_document(
                peer_for(), retire_request.to_wire()
            )

            self.assertTrue(retired["ok"], retired)
            self.assertEqual(retired, replay)
            self.assertEqual(retired["result"]["status"], "retired")
            self.assertEqual(
                set(retired["result"]["removed"]), {"artifact", "manifest"}
            )
            self.assertFalse(artifact.exists())
            self.assertFalse(manifest.exists())
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    status = connection.execute(
                        "SELECT status FROM database_backups WHERE database_backup_id = ?",
                        (backup_id,),
                    ).fetchone()["status"]
            self.assertEqual(status, "retired")

            with self.assertRaises(BrokerError) as rejected:
                request_for(
                    BrokerOperation.DATABASE_BACKUP_RETIRE,
                    arguments={
                        "database_name": DATABASE_NAME,
                        "database_backup_id": backup_id,
                        "confirm_backup_id": "backup-wrong",
                    },
                )
            self.assertEqual(
                rejected.exception.code,
                "database_backup_confirmation_invalid",
            )

    def test_postgres_target_mismatches_fail_before_runner(self) -> None:
        cases = ("repo", "resource", "database", "container-drift")
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
                if case == "repo":
                    document["project_id"] = "repo-foreign"
                elif case == "resource":
                    document["resource_id"] = SECOND_CONTAINER_ID
                elif case == "database":
                    document["arguments"] = {"database_name": "foreign"}
                reply = service.reply_for_document(peer, document)

                self.assertFalse(reply["ok"], reply)
                self.assertEqual(actions.postgres_calls, [])

    def test_internal_testd_uid_is_attribution_not_authorization(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, _unused = seed_store_backed_broker(root)
            caller_uid = os.geteuid() + 20_000
            request = BrokerRequest.create(
                authority_generation=CURRENT_AUTHORITY_GENERATION,
                account_id="devcoordinator-testd",
                project_id=PROJECT_ID,
                repository_generation=0,
                resource_id=PROJECT_ID,
                operation=BrokerOperation.TEST_ATTEMPT_STATUS,
                arguments={"runtime_id": "runtime-alpha", "result_chunk_index": 0},
            )

            acceptor = StoreBackedRequestAcceptor(
                persistence,
                internal_testd_uid=-999,  # ignored legacy service metadata
            )
            accepted = acceptor.accept(peer_for(caller_uid), request)

            self.assertEqual(accepted.peer.uid, caller_uid)
            self.assertEqual(accepted.request.project_id, PROJECT_ID)

    def test_attempt_runtime_io_failure_is_typed_and_retriable(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            backend = StoreBackedMutationBackend(persistence, actions)

            class AttemptRuntime:
                available = False

                @staticmethod
                def runtime_descriptor(_runtime_id: str) -> object:
                    class Descriptor:
                        repository_id = PROJECT_ID
                        repository_generation = 0
                        attempt_id = PROJECT_ID

                    return Descriptor()

                def observe(
                    self, _runtime_id: str, *, result_chunk_index: int
                ) -> Mapping[str, object]:
                    self.last_chunk_index = result_chunk_index
                    if not self.available:
                        raise OSError(errno.EROFS, "read-only artifact store")
                    return {"state": "running"}

            runtime = AttemptRuntime()
            backend._test_attempts = runtime
            service = BrokerService(
                StoreBackedRequestAcceptor(persistence),
                SerializedMutationWriter(backend),
            )
            request = BrokerRequest.create(
                authority_generation=CURRENT_AUTHORITY_GENERATION,
                account_id="devcoordinator-testd",
                project_id=PROJECT_ID,
                repository_generation=0,
                resource_id=PROJECT_ID,
                operation=BrokerOperation.TEST_ATTEMPT_STATUS,
                arguments={
                    "runtime_id": "devcoordinator-test-runtime-io",
                    "result_chunk_index": 0,
                },
            )

            with self.assertNoLogs("devcoordinator.broker", level="ERROR"):
                unavailable = service.reply_for_document(
                    peer_for(), request.to_wire()
                )
            self.assertFalse(unavailable["ok"], unavailable)
            self.assertEqual(
                unavailable["error"]["code"],
                "test_attempt_runtime_unavailable",
            )

            runtime.available = True
            recovered = service.reply_for_document(peer_for(), request.to_wire())

            self.assertTrue(recovered["ok"], recovered)
            self.assertEqual(recovered["result"], {"state": "running"})
            self.assertEqual(runtime.last_chunk_index, 0)

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

    def test_postgres_backup_timeout_is_terminal_not_an_indefinite_fence(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, _unused = seed_store_backed_broker(root)
            seed_postgres_database(persistence)
            actions = TimedOutPostgresHostActions()
            service = store_backed_service(persistence, actions)
            request = request_for(
                BrokerOperation.DATABASE_BACKUP,
                arguments={"database_name": DATABASE_NAME},
            )

            first = service.reply_for_document(peer_for(), request.to_wire())
            replay = service.reply_for_document(peer_for(), request.to_wire())

            self.assertFalse(first["ok"], first)
            self.assertEqual(first["error"]["code"], "database_backup_timeout")
            self.assertFalse(replay["ok"], replay)
            self.assertEqual(replay["error"]["code"], "database_backup_timeout")
            self.assertEqual(
                actions.postgres_calls,
                [("backup", "a" * 64, DATABASE_NAME)],
            )

    def test_replacement_broker_settles_abandoned_database_backup(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, _unused = seed_store_backed_broker(root)
            seed_postgres_database(persistence)
            request = request_for(
                BrokerOperation.DATABASE_BACKUP,
                arguments={"database_name": DATABASE_NAME},
            )
            accepted = StoreBackedRequestAcceptor(persistence).accept(
                peer_for(), request
            )
            persistence.reserve_operation(accepted)
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        UPDATE operations SET process_fingerprint = 'departed-broker'
                        WHERE operation_id = ?
                        """,
                        (request.operation_id,),
                    )
            actions = RecordingPostgresHostActions()
            service = store_backed_service(persistence, actions)

            reply = service.reply_for_document(peer_for(), request.to_wire())

            self.assertFalse(reply["ok"], reply)
            self.assertEqual(
                reply["error"]["code"], "database_backup_interrupted"
            )
            self.assertEqual(actions.postgres_calls, [])
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    status = connection.execute(
                        "SELECT status FROM operations WHERE operation_id = ?",
                        (request.operation_id,),
                    ).fetchone()["status"]
            self.assertEqual(status, "failed")

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

    def test_postgres_restore_finish_uncertainty_registers_exactly_once(self) -> None:
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
            restore_request = request_for(
                BrokerOperation.DATABASE_RESTORE,
                arguments={
                    "database_name": DATABASE_NAME,
                    "database_backup_id": backup["result"]["database_backup_id"],
                    "explicit": True,
                },
            )
            original_finish = persistence.finish_operation
            failed_once = False

            def flaky_finish(
                operation_id: str, *args: Any, **kwargs: Any
            ) -> None:
                nonlocal failed_once
                if (
                    operation_id == restore_request.operation_id
                    and kwargs.get("result") is not None
                    and not failed_once
                ):
                    failed_once = True
                    raise sqlite3.OperationalError(
                        "injected post-registry operation finish failure"
                    )
                original_finish(operation_id, *args, **kwargs)

            with mock.patch.object(
                persistence, "finish_operation", side_effect=flaky_finish
            ):
                uncertain = service.reply_for_document(
                    peer_for(), restore_request.to_wire()
                )
                replayed = service.reply_for_document(
                    peer_for(), restore_request.to_wire()
                )

            self.assertFalse(uncertain["ok"], uncertain)
            self.assertEqual(
                uncertain["error"]["code"], "operation_outcome_uncertain"
            )
            self.assertTrue(replayed["ok"], replayed)
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
                    event_count = connection.execute(
                        "SELECT COUNT(*) FROM database_restore_events"
                    ).fetchone()[0]
                    restore_count = connection.execute(
                        """
                        SELECT restore_count FROM database_backups
                        WHERE database_backup_id = ?
                        """,
                        (backup["result"]["database_backup_id"],),
                    ).fetchone()[0]
            self.assertEqual(event_count, 1)
            self.assertEqual(restore_count, 1)

    def test_repository_lifecycle_requires_exact_project_target(self) -> None:
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
            self.assertEqual(denied["error"]["code"], "lifecycle_rejected")
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

    def test_request_loaded_before_generation_rotation_is_rejected_before_reservation(
        self,
    ) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            service = store_backed_service(persistence, actions)
            loaded_generation = persistence.database_generation()
            loaded_request = BrokerRequest.create(
                account_id=ACCOUNT_ID,
                project_id=PROJECT_ID,
                resource_id=CONTAINER_ID,
                operation=BrokerOperation.DOCKER_STOP,
                authority_generation=loaded_generation,
            )
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction(revision_kind=None) as connection:
                    changed = connection.execute(
                        """
                        UPDATE schema_metadata
                        SET database_generation = ?, state_revision = state_revision + 1,
                            updated_at = ?
                        WHERE singleton = 1 AND database_generation = ?
                        """,
                        (
                            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                            utc_timestamp(),
                            loaded_generation,
                        ),
                    ).rowcount
                    self.assertEqual(changed, 1)

            reply = service.reply_for_document(peer_for(), loaded_request.to_wire())

            self.assertFalse(reply["ok"], reply)
            self.assertEqual(reply["error"]["code"], "broker_generation_mismatch")
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    reserved = connection.execute(
                        "SELECT 1 FROM broker_operation_requests WHERE operation_id = ?",
                        (loaded_request.operation_id,),
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
                observe_before_lifecycle_plan=_committed_available_observer,
            )
            with runtime.server:
                request = request_for(BrokerOperation.DOCKER_STOP)
                reply = BrokerClient(
                    socket_path,
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
            repeated_release = service.reply_for_document(
                peer_for(),
                request_for(
                    BrokerOperation.PORT_RELEASE,
                    resource_id=leases[0]["lease_id"],
                ).to_wire(),
            )
            self.assertTrue(repeated_release["ok"], repeated_release)
            self.assertEqual(repeated_release["result"], released["result"])
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

    def test_server_publication_ignores_listener_uid_but_rejects_pid_and_bound_stop(self) -> None:
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
            self.assertTrue(foreign_owner["ok"], foreign_owner)
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

    def test_dynamic_lease_release_is_shared_across_local_callers(self) -> None:
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
            self.assertTrue(reply["ok"], reply)
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    status = connection.execute(
                        "SELECT status FROM leases WHERE lease_id = ?",
                        (lease["lease_id"],),
                    ).fetchone()[0]
            self.assertEqual(status, "released")

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
            authorized = persistence.accept(peer_for(), request)
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


class DirectDockerReconciliationTests(unittest.TestCase):
    @staticmethod
    def _snapshot(
        persistence: BrokerPersistence,
        *,
        present_resource_id: str | None,
        host_id: str = HOST_ID,
    ) -> dict[str, Any]:
        snapshot_id = "docker-reconcile-" + uuid.uuid4().hex
        completed_at = utc_timestamp()
        material = "sha256:" + "4" * 64
        capability = "sha256:" + "5" * 64
        with CoordinatorStore.open(
            persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction(revision_kind="observation") as connection:
                if host_id != HOST_ID:
                    connection.execute(
                        """
                        INSERT INTO hosts(
                            host_id, machine_fingerprint, platform, hostname,
                            created_at, updated_at
                        ) VALUES (?, ?, 'test', 'wrong-host', ?, ?)
                        """,
                        (
                            host_id,
                            "machine-" + host_id,
                            completed_at,
                            completed_at,
                        ),
                    )
                connection.execute(
                    """
                    INSERT INTO observation_snapshots(
                        snapshot_id, host_id, observer_domain, status,
                        material_fingerprint, started_at, completed_at
                    ) VALUES (?, ?, 'host-runtime-v2:full-docker', 'completed',
                              ?, ?, ?)
                    """,
                    (
                        snapshot_id,
                        host_id,
                        material,
                        completed_at,
                        completed_at,
                    ),
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
                if present_resource_id is not None:
                    connection.execute(
                        """
                        INSERT INTO observation_snapshot_resources(
                            snapshot_id, resource_kind, resource_id,
                            observation_fingerprint
                        ) VALUES (?, 'container', ?, ?)
                        """,
                        (
                            snapshot_id,
                            present_resource_id,
                            "sha256:" + "6" * 64,
                        ),
                    )
        return {
            "snapshot_id": snapshot_id,
            "host_id": host_id,
            "observer_domain": "host-runtime-v2:full-docker",
            "docker_available": True,
            "capability_fingerprint": capability,
            "material_fingerprint": material,
            "started_at": completed_at,
            "completed_at": completed_at,
        }

    @staticmethod
    @contextmanager
    def _root_contract(
        persistence: BrokerPersistence,
    ) -> Iterator[None]:
        effective_uid = os.geteuid()

        @contextmanager
        def open_owned_store() -> Iterator[CoordinatorStore]:
            with mock.patch.object(
                broker_persistence.os,
                "geteuid",
                return_value=effective_uid,
            ):
                with CoordinatorStore.open(
                    persistence.database_path,
                    expected_uid=effective_uid,
                ) as store:
                    yield store

        with (
            mock.patch.object(broker_persistence.os, "geteuid", return_value=0),
            mock.patch.object(persistence, "expected_uid", 0),
            mock.patch.object(persistence, "_store", side_effect=open_owned_store),
        ):
            yield

    def test_startup_recovery_fences_all_direct_docker_actions(self) -> None:
        for action in (
            BrokerOperation.DOCKER_START,
            BrokerOperation.DOCKER_STOP,
            BrokerOperation.DOCKER_RESTART,
        ):
            with self.subTest(action=action.value), CanonicalTemporaryDirectory() as root:
                persistence, _actions = seed_store_backed_broker(root)
                request = request_for(action)
                authorized = persistence.accept(peer_for(), request)
                self.assertEqual(
                    persistence.reserve_operation(authorized).state,
                    "execute",
                )
                recovered = persistence.recover_interrupted_docker_operations()
                self.assertEqual(recovered["operation_ids"], [request.operation_id])
                candidate = persistence.docker_reconciliation_candidate(
                    request.operation_id
                )
                self.assertEqual(candidate["action"], action.value.removeprefix("docker."))
                self.assertEqual(candidate["full_container_id"], "a" * 64)
                with CoordinatorStore.open(
                    persistence.database_path, expected_uid=os.geteuid()
                ) as store:
                    with store.read_transaction() as connection:
                        row = connection.execute(
                            "SELECT status, phase, error_code FROM operations "
                            "WHERE operation_id = ?",
                            (request.operation_id,),
                        ).fetchone()
                self.assertEqual(
                    dict(row),
                    {
                        "status": "needs_attention",
                        "phase": "reconciliation_required",
                        "error_code": "operation_outcome_uncertain",
                    },
                )

    def test_unresolved_container_blocks_only_the_same_exact_target(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, _actions = seed_store_backed_broker(root)
            first = request_for(BrokerOperation.DOCKER_STOP)
            persistence.reserve_operation(persistence.accept(peer_for(), first))

            same_target = request_for(
                BrokerOperation.DOCKER_START,
                operation_id=str(uuid.uuid4()),
            )
            with self.assertRaises(BrokerError) as blocked:
                persistence.reserve_operation(
                    persistence.accept(peer_for(), same_target)
                )
            self.assertEqual(blocked.exception.code, "docker_operation_pending")

            unrelated = request_for(
                BrokerOperation.DOCKER_START,
                resource_id=SECOND_CONTAINER_ID,
                operation_id=str(uuid.uuid4()),
            )
            self.assertEqual(
                persistence.reserve_operation(
                    persistence.accept(peer_for(), unrelated)
                ).state,
                "execute",
            )

    def test_reconciliation_records_present_and_absent_without_host_action(self) -> None:
        for present in (True, False):
            with self.subTest(present=present), CanonicalTemporaryDirectory() as root:
                persistence, actions = seed_store_backed_broker(root)
                request = request_for(BrokerOperation.DOCKER_RESTART)
                persistence.reserve_operation(
                    persistence.accept(peer_for(), request)
                )
                persistence.recover_interrupted_docker_operations()
                evidence = self._snapshot(
                    persistence,
                    present_resource_id=CONTAINER_ID if present else None,
                )
                with self._root_contract(persistence):
                    result = persistence.reconcile_docker_operation(
                        request.operation_id,
                        evidence=evidence,
                        confirm_container_id="a" * 64,
                    )
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["phase"], "reconciled")
                self.assertIs(result["current_container_present"], present)
                self.assertEqual(actions.calls, [])
                with CoordinatorStore.open(
                    persistence.database_path, expected_uid=os.geteuid()
                ) as store:
                    with store.read_transaction() as connection:
                        event_count = connection.execute(
                            "SELECT COUNT(*) FROM events WHERE operation_id = ? "
                            "AND event_kind = 'docker.reconciled'",
                            (request.operation_id,),
                        ).fetchone()[0]
                        target = connection.execute(
                            "SELECT status, phase FROM operation_targets "
                            "WHERE operation_id = ?",
                            (request.operation_id,),
                        ).fetchone()
                self.assertEqual(event_count, 1)
                self.assertEqual(
                    dict(target), {"status": "failed", "phase": "reconciled"}
                )

    def test_wrong_identity_or_host_snapshot_leaves_uncertain_state_unchanged(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            request = request_for(BrokerOperation.DOCKER_STOP)
            persistence.reserve_operation(persistence.accept(peer_for(), request))
            persistence.recover_interrupted_docker_operations()
            evidence = self._snapshot(
                persistence,
                present_resource_id=None,
                host_id="wrong-host",
            )
            with self._root_contract(persistence):
                with self.assertRaises(BrokerError) as wrong_identity:
                    persistence.reconcile_docker_operation(
                        request.operation_id,
                        evidence=evidence,
                        confirm_container_id="b" * 64,
                    )
                self.assertEqual(
                    wrong_identity.exception.code,
                    "docker_reconciliation_confirmation_required",
                )
                with self.assertRaises(BrokerError) as wrong_host:
                    persistence.reconcile_docker_operation(
                        request.operation_id,
                        evidence=evidence,
                        confirm_container_id="a" * 64,
                    )
                self.assertEqual(
                    wrong_host.exception.code,
                    "docker_reconciliation_observation_incomplete",
                )
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    row = connection.execute(
                        "SELECT status, phase FROM operations WHERE operation_id = ?",
                        (request.operation_id,),
                    ).fetchone()
                    event_count = connection.execute(
                        "SELECT COUNT(*) FROM events WHERE operation_id = ?",
                        (request.operation_id,),
                    ).fetchone()[0]
            self.assertEqual(
                dict(row),
                {"status": "needs_attention", "phase": "reconciliation_required"},
            )
            self.assertEqual(event_count, 0)
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
