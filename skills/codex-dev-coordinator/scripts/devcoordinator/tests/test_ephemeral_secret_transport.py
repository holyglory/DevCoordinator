"""Recall tests for the broker's FD-only ephemeral credential transport."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import pwd
import socket
import struct
import sys
import tempfile
import time
import threading
import unittest
import uuid
from typing import Any
from unittest import mock


SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))
import devcoordinator.broker as broker_module  # noqa: E402

from devcoordinator.broker import (  # noqa: E402
    AccountAccessPolicy,
    AuthorizedBrokerRequest,
    BrokerClient,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    BrokerService,
    EphemeralSecretFD,
    PeerCredentials,
    SerializedMutationWriter,
    StaticPeerAuthorizer,
    UnixBrokerServer,
    _receive_frame_rejecting_fds,
    _send_frame,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend  # noqa: E402
from devcoordinator.broker_persistence import (  # noqa: E402
    BrokerPersistence,
    StoreBackedAuthorizer,
)
from devcoordinator.broker_cli import _request_arguments  # noqa: E402
from devcoordinator.ephemeral_secrets import (  # noqa: E402
    POSTGRES_INITDB_PASSWORD_FILE_V1,
    VolatileRunSecretManager,
)
from devcoordinator.store import CoordinatorStore, utc_timestamp  # noqa: E402


ACCOUNT_ID = "account-secret"
PROJECT_ID = "repo-secret"
TEMPLATE_ID = "template-secret"
RUN_ID = str(uuid.uuid4())
AUTHORITY_GENERATION = "secret-test-generation"
SECRET = b"secret-must-never-appear-in-json-or-logs"
STORE_BACKED_SECRET = b"store-backed-secret-only-for-isolated-test"
STORE_BACKED_HOST = "host-store-secret"
STORE_BACKED_ACCOUNT = "account-store-secret"
STORE_BACKED_REPO = "repo-store-secret"
STORE_BACKED_TEMPLATE = "template-store-secret"
STORE_BACKED_IMAGE = "postgres@sha256:" + "a" * 64


class _UnusedWriterBackend:
    def __init__(self) -> None:
        self.calls = 0

    def execute(self, _request: AuthorizedBrokerRequest) -> dict[str, object]:
        self.calls += 1
        return {"unexpected": True}


@dataclass(frozen=True)
class _Material:
    value: bytes
    expires_at_epoch: int
    request_id: uuid.UUID


class _DeliveryLease:
    """Test-only closeable delivery with no secret-bearing representation."""

    def __init__(
        self,
        material: _Material,
        closed_request_ids: list[uuid.UUID],
    ) -> None:
        self.material = material
        self._closed_request_ids = closed_request_ids
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._closed_request_ids.append(self.material.request_id)


class _OneTimeSecretRetriever:
    def __init__(self, *, expired: bool = False) -> None:
        self.expired = expired
        self.calls: list[tuple[int, str, str, uuid.UUID]] = []
        self.closed_request_ids: list[uuid.UUID] = []
        self._consumed: set[uuid.UUID] = set()

    def acquire_ephemeral_secret_fd_delivery(
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        template_id: str,
        run_id: uuid.UUID,
        request_id: uuid.UUID,
    ) -> _DeliveryLease:
        self.calls.append(
            (authorized.peer.uid, template_id, str(run_id), request_id)
        )
        if template_id != TEMPLATE_ID or str(run_id) != RUN_ID:
            raise BrokerError("resource_access_denied", "Exact run binding was not proved.")
        if self.expired:
            raise BrokerError(
                "secret_grant_expired",
                "The one-time run credential has expired.",
            )
        if request_id in self._consumed:
            raise BrokerError(
                "secret_grant_replay",
                "The one-time credential request was already consumed.",
            )
        self._consumed.add(request_id)
        return _DeliveryLease(
            _Material(
                value=SECRET,
                expires_at_epoch=int(time.time()) + 60,
                request_id=request_id,
            ),
            self.closed_request_ids,
        )


class _SocketDirectory:
    """Test-owned canonical private socket directory."""

    def __enter__(self) -> Path:
        account_home = Path(pwd.getpwuid(os.geteuid()).pw_dir).resolve()
        self._temporary = tempfile.TemporaryDirectory(
            prefix=".dc-fd-", dir=str(account_home)
        )
        self.path = Path(self._temporary.name).resolve()
        # The production broker socket is group-readable/writable (0660), so
        # its immediate private parent must grant the configured group search
        # permission while all ancestors remain test-owned and non-replaceable.
        os.chmod(self.path, 0o750)
        return self.path

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self._temporary.cleanup()


class _StoreBackedEphemeralHost:
    """Typed no-Docker host double for the real store-backed broker proof."""

    full_container_id = "c" * 64

    def __init__(self) -> None:
        self.create_target: object | None = None
        self.start_target: object | None = None
        self.calls: list[str] = []
        self._container: dict[str, object] | None = None

    def docker_inspect_ephemeral_image(self, target: object) -> dict[str, object]:
        self.calls.append("inspect_image")
        assert getattr(target, "image_ref") == STORE_BACKED_IMAGE
        return {
            "cached": True,
            "image_ref": STORE_BACKED_IMAGE,
            "image_id": "sha256:" + "d" * 64,
            "repo_digest": STORE_BACKED_IMAGE,
            "os": "linux",
            "architecture": "amd64",
        }

    def docker_prefetch_ephemeral_image(self, target: object) -> dict[str, object]:
        self.calls.append("prefetch_image")
        return {
            **self.docker_inspect_ephemeral_image(target),
            "cache_origin": "already_present",
            "changed": False,
        }

    def docker_create_ephemeral(self, target: object) -> dict[str, object]:
        self.calls.append("create")
        self.create_target = target
        self._container = {
            "identity": getattr(target, "identity"),
            "running": False,
            "status": "created",
        }
        return {
            "full_container_id": self.full_container_id,
            "running": False,
            "status": "created",
        }

    def docker_start_ephemeral(self, target: object) -> dict[str, object]:
        self.calls.append("start")
        self.start_target = target
        assert self._container is not None
        self._container["running"] = True
        self._container["status"] = "running"
        return {
            "full_container_id": self.full_container_id,
            "running": True,
            "status": "running",
        }

    def docker_find_ephemeral(self, identity: object) -> dict[str, object]:
        self.calls.append("find")
        if self._container is None or self._container["identity"] != identity:
            return {"found": False}
        return {
            "found": True,
            "full_container_id": self.full_container_id,
            "running": self._container["running"],
            "status": self._container["status"],
        }

    def docker_inspect_ephemeral(self, target: object) -> dict[str, object]:
        self.calls.append("inspect")
        assert self._container is not None
        assert getattr(target, "full_container_id") == self.full_container_id
        return {
            "full_container_id": self.full_container_id,
            "running": self._container["running"],
            "status": self._container["status"],
        }

    def docker_stop_ephemeral(self, target: object) -> dict[str, object]:
        self.calls.append("stop")
        assert self._container is not None
        assert getattr(target, "full_container_id") == self.full_container_id
        self._container["running"] = False
        self._container["status"] = "exited"
        return {
            "full_container_id": self.full_container_id,
            "running": False,
            "status": "exited",
        }

    def docker_remove_ephemeral(self, target: object) -> dict[str, object]:
        self.calls.append("remove")
        assert self._container is not None
        assert self._container["running"] is False
        assert getattr(target, "full_container_id") == self.full_container_id
        self._container = None
        return {"full_container_id": self.full_container_id, "action": "remove"}


class _TrackingRLock:
    """Expose the second acquisition attempt without changing lock semantics."""

    def __init__(self, lock: object) -> None:
        self._lock = lock
        self._count_lock = threading.Lock()
        self._acquire_count = 0
        self.second_acquire_attempted = threading.Event()

    def acquire(self) -> bool:
        with self._count_lock:
            self._acquire_count += 1
            if self._acquire_count == 2:
                self.second_acquire_attempted.set()
        return bool(self._lock.acquire())

    def release(self) -> None:
        self._lock.release()

    def __enter__(self) -> "_TrackingRLock":
        self.acquire()
        return self

    def __exit__(
        self,
        _exc_type: object,
        _exc_value: object,
        _traceback: object,
    ) -> None:
        self.release()



class _StoreBackedFixture:
    """Fresh local authority with one typed secret-enabled ephemeral template."""

    def __init__(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(
            prefix="devcoordinator-store-secret-", dir=str(Path("/tmp").resolve())
        )
        self.root = Path(self._temporary.name)
        self.root.chmod(0o700)
        self.database = self.root / "coordinator.sqlite3"
        self.persistence = BrokerPersistence(self.database, expected_uid=os.geteuid())
        now = utc_timestamp()
        with CoordinatorStore.open(self.database, expected_uid=os.geteuid()) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO hosts(
                        host_id, machine_fingerprint, platform, hostname,
                        created_at, updated_at
                    ) VALUES (?, 'store-secret-machine', 'test', 'host', ?, ?)
                    """,
                    (STORE_BACKED_HOST, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (?, ?, ?, 'Store secret', 'active', 0, ?, ?)
                    """,
                    (STORE_BACKED_REPO, STORE_BACKED_HOST, str(self.root), now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation, actor, updated_at
                    ) VALUES (?, 'installed', 0, 0, 'test', ?)
                    """,
                    (STORE_BACKED_REPO, now),
                )
            self.generation = store.metadata.database_generation
        self.persistence.provision_principal(
            uid=os.geteuid(), account_id=STORE_BACKED_ACCOUNT
        )
        self.persistence.provision_repository_enrollment(
            uid=os.geteuid(),
            repo_id=STORE_BACKED_REPO,
            account_id=STORE_BACKED_ACCOUNT,
            issued_at=now,
            valid_until_epoch=int(time.time()) + 3600,
        )
        self.persistence.provision_ephemeral_template(
            template_id=STORE_BACKED_TEMPLATE,
            repo_id=STORE_BACKED_REPO,
            name="store-secret-postgres",
            image_ref=STORE_BACKED_IMAGE,
            command=("postgres",),
            environment={"POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256"},
            secret_policy_kind=POSTGRES_INITDB_PASSWORD_FILE_V1,
            secret_binding_id=str(uuid.uuid4()),
            default_ttl_seconds=600,
            max_ttl_seconds=3600,
            memory_bytes=256 * 1024 * 1024,
            cpu_millis=750,
        )
        self.persistence.replace_ephemeral_access(
            uid=os.geteuid(),
            repo_id=STORE_BACKED_REPO,
            template_ids=(STORE_BACKED_TEMPLATE,),
        )
        self.authorizer = StoreBackedAuthorizer(self.persistence)

    def authorize(
        self, operation: BrokerOperation, resource_id: str, *, arguments: dict[str, object]
    ) -> AuthorizedBrokerRequest:
        request = BrokerRequest.create(
            account_id=STORE_BACKED_ACCOUNT,
            project_id=STORE_BACKED_REPO,
            resource_id=resource_id,
            operation=operation,
            arguments=arguments,
            authority_generation=self.generation,
        )
        return self.authorizer.authorize(_peer(), request)

    def close(self) -> None:
        self._temporary.cleanup()


def _peer() -> PeerCredentials:
    return PeerCredentials(uid=os.geteuid(), gid=os.getegid(), pid=os.getpid())


def _request(request_id: uuid.UUID | None = None) -> BrokerRequest:
    return BrokerRequest.create(
        account_id=ACCOUNT_ID,
        project_id=PROJECT_ID,
        resource_id=RUN_ID,
        operation=BrokerOperation.EPHEMERAL_SECRET_FD,
        arguments={
            "template_id": TEMPLATE_ID,
            "run_id": RUN_ID,
            "request_id": str(request_id or uuid.uuid4()),
        },
        authority_generation=AUTHORITY_GENERATION,
    )


def _service(retriever: _OneTimeSecretRetriever) -> tuple[BrokerService, _UnusedWriterBackend]:
    backend = _UnusedWriterBackend()
    policy = AccountAccessPolicy(
        account_id=ACCOUNT_ID,
        grants={
            PROJECT_ID: {
                RUN_ID: frozenset({BrokerOperation.EPHEMERAL_SECRET_FD}),
            }
        },
    )
    return (
        BrokerService(
            StaticPeerAuthorizer({os.geteuid(): policy}),
            SerializedMutationWriter(backend),
            secret_fd_retriever=retriever,
        ),
        backend,
    )


def _client(path: Path) -> BrokerClient:
    return BrokerClient(
        path,
        expected_broker_uid=os.geteuid(),
        expected_socket_gid=os.getegid(),
    )


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise AssertionError("test broker connection closed before a full reply")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class EphemeralSecretTransportTests(unittest.TestCase):
    def test_generic_cli_rejects_fd_only_credential_retrieval(self) -> None:
        with self.assertRaisesRegex(ValueError, "in-process descriptor transport"):
            _request_arguments(
                argparse.Namespace(), BrokerOperation.EPHEMERAL_SECRET_FD
            )

    def test_mismatched_run_binding_and_unauthorized_peer_never_reach_retriever(self) -> None:
        retriever = _OneTimeSecretRetriever()
        service, _backend = _service(retriever)
        with self.assertRaises(BrokerError) as mismatched:
            BrokerRequest.create(
                account_id=ACCOUNT_ID,
                project_id=PROJECT_ID,
                resource_id=RUN_ID,
                operation=BrokerOperation.EPHEMERAL_SECRET_FD,
                arguments={
                    "template_id": TEMPLATE_ID,
                    "run_id": str(uuid.uuid4()),
                    "request_id": str(uuid.uuid4()),
                },
                authority_generation=AUTHORITY_GENERATION,
            )
        self.assertEqual(mismatched.exception.code, "invalid_arguments")

        request = _request()
        denied = service.transport_response_for_payload(
            PeerCredentials(
                uid=os.geteuid() + 100_000,
                gid=os.getegid(),
                pid=os.getpid(),
            ),
            json.dumps(request.to_wire(), sort_keys=True).encode("utf-8"),
        )
        self.assertIsNone(denied.secret_fd)
        reply = json.loads(denied.payload)
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"]["code"], "peer_not_authorized")
        self.assertEqual(retriever.calls, [])

    def test_success_is_fd_only_read_only_close_on_exec_and_never_writer_cached(self) -> None:
        retriever = _OneTimeSecretRetriever()
        service, backend = _service(retriever)
        request = _request()
        with _SocketDirectory() as runtime:
            socket_path = runtime / "broker.sock"
            with UnixBrokerServer(socket_path, service):
                with _client(socket_path).retrieve_ephemeral_secret_fd(request) as received:
                    self.assertIsInstance(received, EphemeralSecretFD)
                    self.assertFalse(os.get_inheritable(received.fd))
                    self.assertEqual(os.read(received.fd, 512), SECRET)
                    self.assertEqual(os.read(received.fd, 1), b"")
                    with self.assertRaises(OSError):
                        os.write(received.fd, b"x")
                    self.assertNotIn(SECRET.decode("ascii"), repr(received))
                    self.assertEqual(received.request_id, request.arguments["request_id"])
        self.assertEqual(backend.calls, 0)
        self.assertEqual(len(retriever.calls), 1)
        self.assertEqual(
            retriever.closed_request_ids,
            [uuid.UUID(str(request.arguments["request_id"]))],
        )

    def test_json_path_and_generic_client_refuse_the_secret_operation(self) -> None:
        retriever = _OneTimeSecretRetriever()
        service, backend = _service(retriever)
        request = _request()
        direct = service.reply_for_document(_peer(), request.to_wire())
        self.assertFalse(direct["ok"])
        self.assertEqual(direct["error"]["code"], "secret_fd_transport_required")
        self.assertNotIn(SECRET.decode("ascii"), json.dumps(direct, sort_keys=True))
        self.assertEqual(backend.calls, 0)
        self.assertEqual(retriever.calls, [])

        with _SocketDirectory() as runtime:
            socket_path = runtime / "broker.sock"
            with UnixBrokerServer(socket_path, service):
                with self.assertRaises(TypeError):
                    _client(socket_path).call(request)
        self.assertEqual(retriever.calls, [])

    def test_descriptor_transport_unavailable_preserves_one_time_material(self) -> None:
        retriever = _OneTimeSecretRetriever()
        service, _backend = _service(retriever)
        request = _request()
        with mock.patch(
            "devcoordinator.broker._descriptor_transport_available",
            return_value=False,
        ):
            unavailable = service.transport_response_for_payload(
                _peer(),
                json.dumps(request.to_wire(), sort_keys=True).encode("utf-8"),
            )
            with self.assertRaises(BrokerError) as client_unavailable:
                _client(Path("/not-used-when-fd-transport-is-unavailable")).retrieve_ephemeral_secret_fd(
                    request
                )
        reply = json.loads(unavailable.payload)
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"]["code"], "secret_fd_transport_unavailable")
        self.assertEqual(client_unavailable.exception.code, "secret_fd_transport_unavailable")
        self.assertIsNone(unavailable.secret_fd)
        self.assertEqual(retriever.calls, [])

    def test_normal_json_frame_falls_back_without_descriptor_support(self) -> None:
        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            _send_frame(sender, b"{}", max_message_bytes=1024)
            with mock.patch(
                "devcoordinator.broker._descriptor_transport_available",
                return_value=False,
            ):
                self.assertEqual(
                    _receive_frame_rejecting_fds(receiver, max_message_bytes=1024),
                    b"{}",
                )
        finally:
            sender.close()
            receiver.close()

    def test_store_backed_running_run_delivers_only_one_fd_through_real_socket(self) -> None:
        fixture = _StoreBackedFixture()
        try:
            host = _StoreBackedEphemeralHost()
            manager = VolatileRunSecretManager(
                runtime_root=fixture.root / "runtime",
                expected_uid=os.geteuid(),
                password_factory=lambda: STORE_BACKED_SECRET,
            )
            backend = StoreBackedMutationBackend(
                fixture.persistence,
                host,
                secret_manager=manager,
            )
            started = backend.execute(
                fixture.authorize(
                    BrokerOperation.EPHEMERAL_START,
                    STORE_BACKED_TEMPLATE,
                    arguments={"agent": "test-agent"},
                )
            )
            run_id = str(started["run_id"])
            self.assertEqual(started["status"], "running")
            self.assertIsNotNone(host.create_target)
            self.assertIsNotNone(host.start_target)

            request_id = uuid.uuid4()
            request = BrokerRequest.create(
                account_id=STORE_BACKED_ACCOUNT,
                project_id=STORE_BACKED_REPO,
                resource_id=run_id,
                operation=BrokerOperation.EPHEMERAL_SECRET_FD,
                arguments={
                    "template_id": STORE_BACKED_TEMPLATE,
                    "run_id": run_id,
                    "request_id": str(request_id),
                },
                authority_generation=fixture.generation,
            )
            service = BrokerService(
                fixture.authorizer,
                SerializedMutationWriter(backend),
                secret_fd_retriever=backend,
            )
            with _SocketDirectory() as runtime:
                socket_path = runtime / "broker.sock"
                with UnixBrokerServer(socket_path, service):
                    with _client(socket_path).retrieve_ephemeral_secret_fd(request) as received:
                        self.assertFalse(os.get_inheritable(received.fd))
                        self.assertEqual(os.read(received.fd, 512), STORE_BACKED_SECRET)
                        with self.assertRaises(OSError):
                            os.write(received.fd, b"x")
                    with self.assertRaises(BrokerError) as replay:
                        _client(socket_path).retrieve_ephemeral_secret_fd(request)
            self.assertEqual(replay.exception.code, "secret_delivery_replay")
            self.assertNotIn(STORE_BACKED_SECRET.decode("ascii"), str(replay.exception))
            self.assertNotIn(STORE_BACKED_SECRET, fixture.database.read_bytes())
        finally:
            fixture.close()

    def test_unresolved_renewal_blocks_secret_fd_without_consuming_material(
        self,
    ) -> None:
        fixture = _StoreBackedFixture()
        try:
            host = _StoreBackedEphemeralHost()
            manager = VolatileRunSecretManager(
                runtime_root=fixture.root / "runtime",
                expected_uid=os.geteuid(),
                password_factory=lambda: STORE_BACKED_SECRET,
            )
            backend = StoreBackedMutationBackend(
                fixture.persistence,
                host,
                secret_manager=manager,
            )
            started = backend.execute(
                fixture.authorize(
                    BrokerOperation.EPHEMERAL_START,
                    STORE_BACKED_TEMPLATE,
                    arguments={"agent": "test-agent"},
                )
            )
            run_id = str(started["run_id"])
            assert host.create_target is not None
            mount = getattr(host.create_target, "secret_mount")
            assert mount is not None
            state_path = mount.source_directory.parent / "state.json"
            before = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertIsNone(before.get("consumed_request_id"))

            with CoordinatorStore.open(
                fixture.database, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    row = connection.execute(
                        """
                        SELECT expires_at_epoch
                        FROM ephemeral_container_runs WHERE run_id = ?
                        """,
                        (run_id,),
                    ).fetchone()
                    assert row is not None
                    old_expiry = int(row["expires_at_epoch"])
                    connection.execute(
                        """
                        UPDATE ephemeral_container_runs
                        SET credential_renewal_phase = 'prepared',
                            credential_renewal_old_expires_at_epoch = ?,
                            credential_renewal_new_expires_at_epoch = ?,
                            credential_renewal_operation_id = ?
                        WHERE run_id = ?
                        """,
                        (
                            old_expiry,
                            old_expiry + 60,
                            str(uuid.uuid4()),
                            run_id,
                        ),
                    )

            request = BrokerRequest.create(
                account_id=STORE_BACKED_ACCOUNT,
                project_id=STORE_BACKED_REPO,
                resource_id=run_id,
                operation=BrokerOperation.EPHEMERAL_SECRET_FD,
                arguments={
                    "template_id": STORE_BACKED_TEMPLATE,
                    "run_id": run_id,
                    "request_id": str(uuid.uuid4()),
                },
                authority_generation=fixture.generation,
            )
            service = BrokerService(
                fixture.authorizer,
                SerializedMutationWriter(backend),
                secret_fd_retriever=backend,
            )
            with _SocketDirectory() as runtime:
                socket_path = runtime / "broker.sock"
                with UnixBrokerServer(socket_path, service):
                    with self.assertRaises(BrokerError) as denied:
                        _client(socket_path).retrieve_ephemeral_secret_fd(request)
            self.assertEqual(denied.exception.code, "resource_access_denied")
            after = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertIsNone(after.get("consumed_request_id"))
        finally:
            fixture.close()


    def test_finish_waits_for_fd_send_and_local_descriptor_close(self) -> None:
        fixture = _StoreBackedFixture()
        entered_send = threading.Event()
        release_send = threading.Event()
        entered_close = threading.Event()
        release_close = threading.Event()
        retrieve_thread: threading.Thread | None = None
        finish_thread: threading.Thread | None = None
        try:
            host = _StoreBackedEphemeralHost()
            manager = VolatileRunSecretManager(
                runtime_root=fixture.root / "runtime",
                expected_uid=os.geteuid(),
                password_factory=lambda: STORE_BACKED_SECRET,
            )
            backend = StoreBackedMutationBackend(
                fixture.persistence,
                host,
                secret_manager=manager,
            )
            started = backend.execute(
                fixture.authorize(
                    BrokerOperation.EPHEMERAL_START,
                    STORE_BACKED_TEMPLATE,
                    arguments={"agent": "test-agent"},
                )
            )
            run_id = str(started["run_id"])
            host.calls.clear()
            tracking_lock = _TrackingRLock(backend._ephemeral._mutation_lock)
            backend._ephemeral._mutation_lock = tracking_lock

            request = BrokerRequest.create(
                account_id=STORE_BACKED_ACCOUNT,
                project_id=STORE_BACKED_REPO,
                resource_id=run_id,
                operation=BrokerOperation.EPHEMERAL_SECRET_FD,
                arguments={
                    "template_id": STORE_BACKED_TEMPLATE,
                    "run_id": run_id,
                    "request_id": str(uuid.uuid4()),
                },
                authority_generation=fixture.generation,
            )
            finish = fixture.authorize(
                BrokerOperation.EPHEMERAL_FINISH,
                run_id,
                arguments={
                    "agent": "test-agent",
                    "reason": "race regression cleanup",
                },
            )
            service = BrokerService(
                fixture.authorizer,
                SerializedMutationWriter(backend),
                secret_fd_retriever=backend,
            )
            received: list[bytes] = []
            retrieve_errors: list[BaseException] = []
            finish_results: list[dict[str, object]] = []
            finish_errors: list[BaseException] = []
            sent_descriptors: list[int] = []
            original_send = broker_module._send_frame_with_fd
            original_close = broker_module._close_descriptor_quietly

            def blocked_send(*args: Any, **kwargs: Any) -> None:
                sent_descriptors.append(int(args[2]))
                entered_send.set()
                release_send.wait(5)
                original_send(*args, **kwargs)

            def blocked_close(descriptor: int) -> None:
                if sent_descriptors and descriptor == sent_descriptors[0]:
                    entered_close.set()
                    release_close.wait(5)
                original_close(descriptor)

            with _SocketDirectory() as runtime:
                socket_path = runtime / "broker.sock"
                with UnixBrokerServer(socket_path, service):
                    with mock.patch(
                        "devcoordinator.broker._send_frame_with_fd",
                        side_effect=blocked_send,
                    ), mock.patch(
                        "devcoordinator.broker._close_descriptor_quietly",
                        side_effect=blocked_close,
                    ):
                        try:
                            def retrieve() -> None:
                                try:
                                    with _client(
                                        socket_path
                                    ).retrieve_ephemeral_secret_fd(request) as secret:
                                        received.append(os.read(secret.fd, 512))
                                except BaseException as error:
                                    retrieve_errors.append(error)

                            def complete_finish() -> None:
                                try:
                                    finish_results.append(dict(backend.execute(finish)))
                                except BaseException as error:
                                    finish_errors.append(error)

                            retrieve_thread = threading.Thread(target=retrieve)
                            retrieve_thread.start()
                            self.assertTrue(
                                entered_send.wait(2),
                                "secret transport did not reach the controlled send boundary",
                            )

                            finish_thread = threading.Thread(target=complete_finish)
                            finish_thread.start()
                            self.assertTrue(
                                tracking_lock.second_acquire_attempted.wait(2),
                                "Finish did not attempt the coordinator mutation lock",
                            )
                            self.assertTrue(finish_thread.is_alive())
                            self.assertEqual(
                                backend._ephemeral._target(run_id).status,
                                "running",
                            )
                            self.assertNotIn("stop", host.calls)
                            self.assertNotIn("remove", host.calls)

                            release_send.set()
                            self.assertTrue(
                                entered_close.wait(2),
                                "server did not reach local descriptor close",
                            )
                            self.assertTrue(
                                finish_thread.is_alive(),
                                "Finish escaped before local descriptor closure",
                            )
                            self.assertNotIn("stop", host.calls)
                            self.assertNotIn("remove", host.calls)

                            release_close.set()
                        finally:
                            release_send.set()
                            release_close.set()
                            if retrieve_thread is not None:
                                retrieve_thread.join(5)
                            if finish_thread is not None:
                                finish_thread.join(5)

            self.assertIsNotNone(retrieve_thread)
            self.assertIsNotNone(finish_thread)
            assert retrieve_thread is not None
            assert finish_thread is not None
            self.assertFalse(retrieve_thread.is_alive())
            self.assertFalse(finish_thread.is_alive())
            self.assertFalse(retrieve_errors, "descriptor retrieval failed")
            self.assertFalse(finish_errors, "Finish failed")
            self.assertEqual(received, [STORE_BACKED_SECRET])
            self.assertEqual(len(finish_results), 1)
            self.assertEqual(finish_results[0]["status"], "cleaned")
            self.assertEqual(backend._ephemeral._target(run_id).status, "cleaned")
            self.assertIn("stop", host.calls)
            self.assertIn("remove", host.calls)
        finally:
            release_send.set()
            release_close.set()
            fixture.close()


    def test_replay_is_rejected_without_a_second_descriptor_or_secret_leak(self) -> None:
        retriever = _OneTimeSecretRetriever()
        service, _backend = _service(retriever)
        request_id = uuid.uuid4()
        request = _request(request_id)
        with _SocketDirectory() as runtime:
            socket_path = runtime / "broker.sock"
            with UnixBrokerServer(socket_path, service):
                with _client(socket_path).retrieve_ephemeral_secret_fd(request) as received:
                    self.assertEqual(os.read(received.fd, 512), SECRET)
                with self.assertRaises(BrokerError) as replay:
                    _client(socket_path).retrieve_ephemeral_secret_fd(request)
        self.assertEqual(replay.exception.code, "secret_grant_replay")
        self.assertNotIn(SECRET.decode("ascii"), str(replay.exception))
        self.assertEqual(len(retriever.calls), 2)

    def test_expired_grant_has_no_descriptor_and_no_secret_in_reply(self) -> None:
        retriever = _OneTimeSecretRetriever(expired=True)
        service, _backend = _service(retriever)
        request = _request()
        with _SocketDirectory() as runtime:
            socket_path = runtime / "broker.sock"
            with UnixBrokerServer(socket_path, service):
                with self.assertRaises(BrokerError) as expired:
                    _client(socket_path).retrieve_ephemeral_secret_fd(request)
        self.assertEqual(expired.exception.code, "secret_grant_expired")
        self.assertNotIn(SECRET.decode("ascii"), str(expired.exception))

    def test_ambiguous_transport_retry_fails_closed_as_replay(self) -> None:
        retriever = _OneTimeSecretRetriever()
        service, _backend = _service(retriever)
        request = _request(uuid.uuid4())
        with _SocketDirectory() as runtime:
            socket_path = runtime / "broker.sock"
            with UnixBrokerServer(socket_path, service):
                with mock.patch(
                    "devcoordinator.broker._send_frame_with_fd",
                    side_effect=OSError("simulated descriptor send failure"),
                ):
                    with self.assertRaises(BrokerError) as interrupted:
                        _client(socket_path).retrieve_ephemeral_secret_fd(request)
                self.assertIn(
                    interrupted.exception.code,
                    {"incomplete_reply", "incomplete_request"},
                )
                with self.assertRaises(BrokerError) as replay:
                    _client(socket_path).retrieve_ephemeral_secret_fd(request)
        self.assertEqual(replay.exception.code, "secret_grant_replay")
        self.assertNotIn(SECRET.decode("ascii"), str(interrupted.exception))
        self.assertNotIn(SECRET.decode("ascii"), str(replay.exception))

    def test_server_rejects_client_supplied_descriptor_before_authorization_or_retrieval(self) -> None:
        retriever = _OneTimeSecretRetriever()
        service, backend = _service(retriever)
        request = _request()
        payload = json.dumps(
            request.to_wire(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        with _SocketDirectory() as runtime:
            socket_path = runtime / "broker.sock"
            with UnixBrokerServer(socket_path, service):
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                    connection.connect(str(socket_path))
                    read_fd, write_fd = os.pipe()
                    try:
                        connection.sendmsg(
                            [len(payload).to_bytes(4, "big") + payload],
                            [
                                (
                                    socket.SOL_SOCKET,
                                    socket.SCM_RIGHTS,
                                    struct.pack("i", read_fd),
                                )
                            ],
                        )
                    finally:
                        os.close(read_fd)
                        os.close(write_fd)
                    header = _recv_exact(connection, 4)
                    self.assertEqual(len(header), 4)
                    reply = json.loads(
                        _recv_exact(connection, int.from_bytes(header, "big"))
                    )
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"]["code"], "unexpected_file_descriptor")
        self.assertEqual(retriever.calls, [])
        self.assertEqual(backend.calls, 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
