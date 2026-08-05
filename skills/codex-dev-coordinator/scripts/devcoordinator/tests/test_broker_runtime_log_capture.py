"""Focused exact-identity contracts for broker-owned runtime log capture."""

from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import sys
import time
import unittest
import uuid


SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from devcoordinator.broker import (  # noqa: E402
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    BrokerService,
    SerializedMutationWriter,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend  # noqa: E402
from devcoordinator.broker_host import LocalBrokerHostMutations  # noqa: E402
from devcoordinator.broker_persistence import (  # noqa: E402
    RuntimeDockerMutationTarget,
    RuntimeServiceLogTarget,
    StoreBackedAuthorizer,
)
from devcoordinator.schema import establish_repository_owner_authority  # noqa: E402
from devcoordinator.store import CoordinatorStore, utc_timestamp  # noqa: E402
from devcoordinator.runtime_artifacts import (  # noqa: E402
    RUNTIME_LOG_MAX_BYTES,
    RUNTIME_LOG_MAX_LINES,
)
from devcoordinator.tests.test_broker import (  # noqa: E402
    ACCOUNT_ID,
    CONTAINER_ID,
    HOST_ID,
    PROJECT_ID,
    SERVER_ID,
    CanonicalTemporaryDirectory,
    peer_for,
    request_for,
    seed_store_backed_broker,
)
from devcoordinator.tests.test_broker_runtime import runtime_arguments  # noqa: E402


_FULL_CONTAINER_ID = "a" * 64


def _runtime_target() -> RuntimeDockerMutationTarget:
    return RuntimeDockerMutationTarget(
        resource_kind="docker",
        resource_id=CONTAINER_ID,
        docker_resource_id=CONTAINER_ID,
        full_container_id=_FULL_CONTAINER_ID,
        database_binding_id=None,
        database_name=None,
        observation_revision=11,
        control_generation=7,
        immutable_fingerprint="sha256:" + "b" * 64,
    )


class BrokerHostRuntimeLogCaptureTests(unittest.TestCase):
    def test_capture_invokes_only_the_full_immutable_id_with_fixed_bounds(self) -> None:
        calls: list[tuple[tuple[str, ...], float, int]] = []

        def runner(
            command: tuple[str, ...], timeout: float, maximum_buffer: int
        ) -> tuple[bytes, int]:
            calls.append((command, timeout, maximum_buffer))
            return b"bounded log\n", 17

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker",
            docker_timeout_seconds=9,
            docker_log_runner=runner,
        )

        payload, discarded = host.docker_capture_logs(_runtime_target())

        self.assertEqual(payload, b"bounded log\n")
        self.assertEqual(discarded, 17)
        self.assertEqual(
            calls,
            [
                (
                    (
                        "/trusted/docker",
                        "logs",
                        "--tail",
                        str(RUNTIME_LOG_MAX_LINES),
                        "--timestamps",
                        _FULL_CONTAINER_ID,
                    ),
                    9.0,
                    RUNTIME_LOG_MAX_BYTES + 64 * 1024,
                )
            ],
        )

    def test_capture_rejects_a_name_or_short_id_before_host_invocation(self) -> None:
        called = False

        def runner(
            _command: tuple[str, ...], _timeout: float, _maximum_buffer: int
        ) -> tuple[bytes, int]:
            nonlocal called
            called = True
            return b"", 0

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker", docker_log_runner=runner
        )
        with self.assertRaises(BrokerError) as raised:
            host.docker_capture_logs(
                replace(_runtime_target(), full_container_id="friendly-name")
            )

        self.assertEqual(raised.exception.code, "runtime_log_identity_invalid")
        self.assertFalse(called)


class BrokerRuntimeLogCaptureTests(unittest.TestCase):
    def test_wire_allows_read_only_capture_for_exact_runtime_targets(self) -> None:
        arguments = runtime_arguments(action="capture_logs")
        request = request_for(
            BrokerOperation.RUNTIME_REQUEST,
            resource_id=CONTAINER_ID,
            arguments=arguments,
        )
        self.assertEqual(request.arguments, arguments)

        service = request_for(
            BrokerOperation.RUNTIME_REQUEST,
            resource_id=CONTAINER_ID,
            arguments=runtime_arguments(
                action="capture_logs", target_kind="service"
            ),
        )
        self.assertEqual(service.arguments["target_kind"], "service")
        with self.assertRaises(BrokerError):
            request_for(
                BrokerOperation.RUNTIME_REQUEST,
                resource_id=CONTAINER_ID,
                arguments=runtime_arguments(
                    action="capture_logs", ttl_seconds=1
                ),
            )

    def test_status_grant_authorizes_exact_capture_and_returns_verified_artifact(self) -> None:
        captures: list[RuntimeDockerMutationTarget] = []

        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            persistence.grant_runtime(
                uid=os.geteuid(),
                repo_id=PROJECT_ID,
                resource_kind="docker",
                resource_id=CONTAINER_ID,
                action="status",
            )

            def capture(
                target: RuntimeDockerMutationTarget,
            ) -> tuple[bytes, int]:
                captures.append(target)
                return b"exact immutable log line\n", 0

            actions.docker_capture_logs = capture  # type: ignore[attr-defined]
            service = BrokerService(
                StoreBackedAuthorizer(persistence),
                SerializedMutationWriter(
                    StoreBackedMutationBackend(persistence, actions)
                ),
            )
            request = request_for(
                BrokerOperation.RUNTIME_REQUEST,
                resource_id=CONTAINER_ID,
                arguments=runtime_arguments(action="capture_logs"),
            )

            reply = service.reply_for_document(peer_for(), request.to_wire())

        self.assertTrue(reply["ok"], reply)
        result = reply["result"]
        self.assertEqual(result["action"], "capture_logs")
        self.assertEqual(result["classification"], "available")
        self.assertEqual(result["target"], {"kind": "docker", "id": CONTAINER_ID})
        self.assertEqual(
            result["artifact_content"]["artifact_id"],
            result["artifact"]["artifact_id"],
        )
        self.assertEqual(
            result["artifact_content"]["text"], "exact immutable log line\n"
        )
        self.assertNotIn("path", result["artifact"])
        self.assertEqual(len(captures), 1)
        self.assertEqual(captures[0].resource_id, CONTAINER_ID)
        self.assertEqual(captures[0].full_container_id, _FULL_CONTAINER_ID)
        self.assertRegex(
            captures[0].immutable_fingerprint, r"^sha256:[0-9a-f]{64}$"
        )

    def test_protected_peer_captures_service_log_through_another_local_route(
        self,
    ) -> None:
        """Route reuse preserves physical attribution and every live veto."""

        protected_account_id = "account-protected-api"
        protected_uid = max(os.geteuid(), 1) + 120_000
        anchor_repo_id = "repo-protected-anchor"
        definition_fingerprint = "sha256:" + "c" * 64
        source_file_identity = "sha256:" + "d" * 64
        captures: list[RuntimeServiceLogTarget] = []

        with CanonicalTemporaryDirectory() as root:
            persistence, actions = seed_store_backed_broker(root)
            now = utc_timestamp()
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        INSERT INTO repositories(
                            repo_id, host_id, canonical_root, display_name,
                            state, generation, created_at, updated_at
                        ) VALUES (?, ?, '/repos/protected-anchor',
                                  'Protected anchor', 'active', 0, ?, ?)
                        """,
                        (anchor_repo_id, HOST_ID, now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO repository_installations(
                            repo_id, status, startup_fenced, generation,
                            actor, updated_at
                        ) VALUES (?, 'installed', 0, 0, 'fixture', ?)
                        """,
                        (anchor_repo_id, now),
                    )
                    establish_repository_owner_authority(
                        connection,
                        repository_id=anchor_repo_id,
                        owner_uid=protected_uid,
                        repository_generation=0,
                        operation_id=str(uuid.uuid4()),
                        actor="fixture",
                        reason="protected log reader transport anchor",
                        timestamp=now,
                        evidence={"kind": "protected-log-reader-anchor"},
                    )
                    connection.execute(
                        """
                        UPDATE server_definitions
                        SET log_path = ?, definition_fingerprint = ?, updated_at = ?
                        WHERE repo_id = ? AND server_definition_id = ?
                        """,
                        (
                            "/var/log/devcoordinator/server-web.log",
                            definition_fingerprint,
                            now,
                            PROJECT_ID,
                            SERVER_ID,
                        ),
                    )
            persistence.provision_principal(
                uid=protected_uid, account_id=protected_account_id
            )
            persistence.provision_repository_enrollment(
                uid=protected_uid,
                repo_id=anchor_repo_id,
                account_id=protected_account_id,
                issued_at=now,
                valid_until_epoch=int(time.time()) + 3_600,
            )
            persistence.grant_runtime(
                uid=os.geteuid(),
                repo_id=PROJECT_ID,
                resource_kind="service",
                resource_id=SERVER_ID,
                action="status",
            )

            def capture(
                target: RuntimeServiceLogTarget,
            ) -> tuple[bytes, int, str]:
                captures.append(target)
                return b"exact routed service log\n", 0, source_file_identity

            actions.service_capture_logs = capture  # type: ignore[attr-defined]
            service = BrokerService(
                StoreBackedAuthorizer(persistence),
                SerializedMutationWriter(
                    StoreBackedMutationBackend(persistence, actions)
                ),
            )
            authority_generation = persistence.database_generation()
            resolve_request = BrokerRequest.create(
                account_id=protected_account_id,
                project_id=anchor_repo_id,
                resource_id=anchor_repo_id,
                operation=BrokerOperation.REPOSITORY_RESOLVE,
                arguments={"canonical_root": "/repos/alpha"},
                authority_generation=authority_generation,
            )

            resolved = service.reply_for_document(
                peer_for(protected_uid), resolve_request.to_wire()
            )

            self.assertTrue(resolved["ok"], resolved)
            self.assertEqual(resolved["result"]["state"], "enrolled")
            repository = resolved["result"]["repository"]
            self.assertEqual(repository["repo_id"], PROJECT_ID)
            self.assertEqual(repository["generation"], 0)
            self.assertEqual(repository["account_id"], ACCOUNT_ID)
            self.assertEqual(repository["servers"], {"web": SERVER_ID})
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    protected_target_enrollments = connection.execute(
                        """
                        SELECT count(*) FROM broker_repository_enrollments
                        WHERE uid = ? AND repo_id = ?
                        """,
                        (protected_uid, PROJECT_ID),
                    ).fetchone()[0]
            self.assertEqual(protected_target_enrollments, 0)

            def capture_request() -> BrokerRequest:
                return BrokerRequest.create(
                    account_id=str(repository["account_id"]),
                    project_id=str(repository["repo_id"]),
                    repository_generation=int(repository["generation"]),
                    resource_id=SERVER_ID,
                    operation=BrokerOperation.RUNTIME_REQUEST,
                    arguments=runtime_arguments(
                        action="capture_logs", target_kind="service"
                    ),
                    authority_generation=authority_generation,
                )

            captured = service.reply_for_document(
                peer_for(protected_uid), capture_request().to_wire()
            )

            self.assertTrue(captured["ok"], captured)
            self.assertEqual(
                captured["result"]["target"],
                {"kind": "service", "id": SERVER_ID},
            )
            self.assertEqual(
                captured["result"]["artifact_content"]["text"],
                "exact routed service log\n",
            )
            self.assertEqual(len(captures), 1)
            self.assertEqual(captures[0].repo_id, PROJECT_ID)
            self.assertEqual(captures[0].server_definition_id, SERVER_ID)
            self.assertEqual(
                captures[0].definition_fingerprint, definition_fingerprint
            )

            persistence.grant_runtime(
                uid=os.geteuid(),
                repo_id=PROJECT_ID,
                resource_kind="service",
                resource_id=SERVER_ID,
                action="status",
                enabled=False,
            )
            captures.clear()
            disabled = service.reply_for_document(
                peer_for(protected_uid), capture_request().to_wire()
            )
            self.assertFalse(disabled["ok"], disabled)
            self.assertEqual(disabled["error"]["code"], "operation_access_denied")
            self.assertEqual(captures, [])

            persistence.grant_runtime(
                uid=os.geteuid(),
                repo_id=PROJECT_ID,
                resource_kind="service",
                resource_id=SERVER_ID,
                action="status",
            )
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        INSERT INTO broker_repository_revocations(
                            repo_id, repository_generation,
                            cleanup_operation_id, immutable_fingerprint,
                            canonical_root, actor, revoked_at
                        ) VALUES (?, 0, ?, ?, '/repos/alpha', 'fixture', ?)
                        """,
                        (
                            PROJECT_ID,
                            "cleanup-protected-log-reader",
                            "sha256:" + "e" * 64,
                            utc_timestamp(),
                        ),
                    )
            captures.clear()
            revoked = service.reply_for_document(
                peer_for(protected_uid), capture_request().to_wire()
            )
            self.assertFalse(revoked["ok"], revoked)
            self.assertEqual(revoked["error"]["code"], "project_permanently_removed")
            self.assertEqual(captures, [])


if __name__ == "__main__":
    unittest.main()
