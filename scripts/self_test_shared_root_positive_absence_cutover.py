#!/usr/bin/env python3
"""Focused production-wrapper tests for the shared-root positive-absence cutover."""

from __future__ import annotations

from contextlib import contextmanager, redirect_stdout
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid


SCRIPT_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_ROOT.parent
MODULE_ROOT = REPOSITORY_ROOT / "skills/codex-dev-coordinator/scripts"
for candidate in (SCRIPT_ROOT, MODULE_ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

import orchestrate_availability_cutover as cutover  # noqa: E402
from devcoordinator.shared_root_positive_absence import (  # noqa: E402
    EXPECTED_ABSENT_DATABASE_BINDING_COUNT,
    EXPECTED_DATABASE_BINDING_COUNT,
    EXPECTED_PRESENT_DATABASE_BINDING_COUNT,
)
from devcoordinator.tests.test_shared_root_positive_absence import (  # noqa: E402
    REPOSITORY_ID,
    SharedRootPositiveAbsenceFixture,
)


class SharedRootPositiveAbsenceCutoverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.release = self.root / "release"
        self.release.mkdir()
        self.database = self.root / "authority.sqlite3"
        self.broker_socket = self.root / "broker.sock"
        self.canary_project = Path("/fixtures/project")
        self.canary_user = "holyglory"
        self.canary_uid = 1000
        self.canary_repository_id = "globalfinance-repository"
        self.canary_repository_generation = 9
        self._create_database()
        self.plan_path = self.root / "plan.json"
        self.attestation = self.root / "result.json"
        self.transaction_journal = self.root / "transaction.json"
        self.transaction_attestation = self.root / "terminal.json"
        self.operation_id = str(uuid.uuid4())
        self.deployment_id = str(uuid.uuid4())
        self.events: list[str] = []
        self.maintenance_reads = 0
        self.marker: object | None = None
        self.service: dict[str, object] = self._healthy_service(4100, "1" * 32)
        self.service_commands: list[str] = []
        self.readiness_calls: list[str] = []

    def _create_database(self) -> None:
        fixture = SharedRootPositiveAbsenceFixture()
        try:
            target = sqlite3.connect(self.database)
            try:
                fixture.connection.backup(target)
            finally:
                target.close()
        finally:
            fixture.close()
        self.database.chmod(0o600)

    @staticmethod
    def _healthy_service(pid: int, invocation_id: str) -> dict[str, object]:
        return {
            "loaded": True,
            "enabled": True,
            "active_state": "active",
            "sub_state": "running",
            "main_pid": pid,
            "invocation_id": invocation_id,
            "socket_present": True,
        }

    @staticmethod
    def _stopped_service(invocation_id: str) -> dict[str, object]:
        return {
            "loaded": True,
            "enabled": True,
            "active_state": "inactive",
            "sub_state": "dead",
            "main_pid": 0,
            "invocation_id": invocation_id,
            "socket_present": False,
        }

    def _reset_lifecycle(self) -> None:
        for path in (
            self.plan_path,
            self.attestation,
            self.transaction_journal,
            self.transaction_attestation,
            self.database,
        ):
            path.unlink(missing_ok=True)
        self._create_database()
        self.operation_id = str(uuid.uuid4())
        self.deployment_id = str(uuid.uuid4())
        self.events.clear()
        self.maintenance_reads = 0
        self.marker = None
        self.service = self._healthy_service(4100, "1" * 32)
        self.service_commands.clear()
        self.readiness_calls.clear()
        self._plan()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _identity(path: Path, *, uid: int) -> dict[str, int]:
        del uid
        info = path.stat()
        return {
            "device": int(info.st_dev),
            "inode": int(info.st_ino),
            "size": int(info.st_size),
        }

    @staticmethod
    def _read(path: Path, *, uid: int) -> dict[str, object]:
        del uid
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise AssertionError("test evidence is not an object")
        return value

    @staticmethod
    def _publish(path: Path, document: object, *, uid: int) -> None:
        del uid
        payload = json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ) + "\n"
        if path.exists():
            if path.read_text(encoding="utf-8") != payload:
                raise AssertionError("test evidence changed")
            return
        path.write_text(payload, encoding="utf-8")
        path.chmod(0o600)

    def _maintenance(self, **kwargs: object) -> object:
        del kwargs
        self.maintenance_reads += 1
        self.events.append("maintenance-read")
        return SimpleNamespace(
            deployment_id=self.deployment_id,
            message=cutover.PUBLIC_MAINTENANCE_MESSAGE,
        )

    def _read_outer_marker(self, **kwargs: object) -> object | None:
        del kwargs
        self.events.append("outer-maintenance-read")
        return self.marker

    def _activate_outer_marker(self, **kwargs: object) -> object:
        self.assertEqual(kwargs["deployment_id"], self.deployment_id)
        self.assertEqual(
            kwargs["scope"], cutover.CONTROL_PLANE_MAINTENANCE_SCOPE
        )
        self.events.append("maintenance-activate")
        state = SimpleNamespace(
            deployment_id=self.deployment_id,
            message=cutover.PUBLIC_MAINTENANCE_MESSAGE,
            retry_after_seconds=5,
            started_at=str(kwargs["started_at"]),
        )
        if self.marker is not None and self.marker != state:
            raise AssertionError("test maintenance marker changed")
        self.marker = state
        return state

    def _clear_outer_marker(self, **kwargs: object) -> bool:
        self.assertEqual(kwargs["deployment_id"], self.deployment_id)
        self.events.append("maintenance-clear")
        if self.marker is None:
            return False
        self.marker = None
        return True

    def _service_state(self, unit: str) -> dict[str, object]:
        self.assertEqual(unit, "devcoordinator-broker.service")
        return dict(self.service)

    def _service_command(self, argv: list[str]) -> int:
        self.assertEqual(argv[:2], ["/usr/bin/systemctl", argv[1]])
        self.assertEqual(argv[-1], "devcoordinator-broker.service")
        action = argv[1]
        self.service_commands.append(action)
        if action == "stop":
            self.service = self._stopped_service(str(self.service["invocation_id"]))
        elif action == "start":
            self.service = self._healthy_service(4200, "2" * 32)
        else:
            raise AssertionError(f"unexpected systemctl action: {action}")
        return 0

    @staticmethod
    def _release_verifier(path: Path) -> dict[str, object]:
        del path
        return {
            "release_digest": "c" * 64,
            "capabilities": {"cutover": True},
        }

    def _readiness(self, **kwargs: object) -> dict[str, object]:
        phase = str(kwargs["phase"])
        binding = kwargs["binding"]
        self.readiness_calls.append(phase)
        canary = None
        if phase == "authenticated":
            canary = {
                "user": self.canary_user,
                "uid": self.canary_uid,
                "project": str(self.canary_project),
                "repository_id": self.canary_repository_id,
                "repository_generation": self.canary_repository_generation,
                "inventory_sha256": "d" * 64,
            }
        return {
            "phase": phase,
            "broker_socket": str(self.broker_socket),
            "socket_identity": {
                "device": 1,
                "inode": 2,
                "uid": 0,
                "gid": 0,
                "mode": 0o660,
            },
            "socket_peer": {
                "pid": int(self.service["main_pid"]),
                "uid": 0,
                "gid": 0,
            },
            "authority_generation": kwargs["authority_generation"],
            "canary": canary,
            "invariants": {
                "contract": "schema12-pre-owner-authority-complete-v1",
                "schema_version": 12,
                "database_generation": kwargs["authority_generation"],
                "state_revision": 42,
                "quick_check": "ok",
                "semantic_violation_count": 0,
                "database_identity": self._identity(self.database, uid=0),
            },
            "verified_at": "2026-07-30T08:00:00Z",
        }

    def _execute(self, **overrides: object) -> dict[str, object]:
        plan = self._read(self.plan_path, uid=0)
        options = {
            "effective_uid_reader": lambda: 0,
            "database_identity_reader": self._identity,
            "evidence_reader": self._read,
            "evidence_publisher": self._publish,
            "maintenance_state_reader": self._read_outer_marker,
            "maintenance_lock_factory": self._maintenance_lock,
            "broker_lock_factory": self._broker_lock,
        }
        arguments: dict[str, object] = {
            "release": self.release,
            "authority_database": self.database,
            "plan_path": self.plan_path,
            "plan_document_sha256": str(plan["document_sha256"]),
            "attestation": self.attestation,
            "transaction_journal": self.transaction_journal,
            "transaction_attestation": self.transaction_attestation,
            "maintenance_root": self.root,
            "maintenance_gid": 0,
            "maintenance_deployment_id": self.deployment_id,
            "broker_socket": self.broker_socket,
            "canary_user": self.canary_user,
            "canary_uid": self.canary_uid,
            "canary_project": self.canary_project,
            "canary_repository_id": self.canary_repository_id,
            "canary_repository_generation": self.canary_repository_generation,
            "readiness_wait_seconds": 1,
            "authority_uid": 0,
            "release_verifier": self._release_verifier,
            "command_status": self._service_command,
            "effective_uid_reader": lambda: 0,
            "maintenance_activator": self._activate_outer_marker,
            "maintenance_clearer": self._clear_outer_marker,
            "maintenance_state_reader": self._read_outer_marker,
            "evidence_reader": self._read,
            "evidence_publisher": self._publish,
            "now_reader": lambda: "2026-07-30T08:00:00Z",
            "applier_options": options,
            "service_state_reader": self._service_state,
            "service_readiness_verifier": self._readiness,
        }
        arguments.update(overrides)
        return cutover.execute_authority_shared_root_positive_absence(**arguments)

    @contextmanager
    def _broker_lock(self, database: Path):
        self.assertEqual(database, self.database)
        self.events.append("broker-enter")
        try:
            yield
        finally:
            self.events.append("broker-exit")

    @contextmanager
    def _maintenance_lock(self, **kwargs: object):
        self.assertEqual(kwargs["maintenance_root"], self.root)
        self.assertEqual(kwargs["expected_uid"], 0)
        self.events.append("maintenance-enter")
        try:
            yield
        finally:
            self.events.append("maintenance-exit")

    def _plan(self) -> dict[str, object]:
        return cutover.plan_authority_shared_root_positive_absence(
            authority_database=self.database,
            repository_id=REPOSITORY_ID,
            operation_id=self.operation_id,
            plan_path=self.plan_path,
            authority_uid=0,
            effective_uid_reader=lambda: 0,
            database_identity_reader=self._identity,
            evidence_publisher=self._publish,
        )

    def _apply(self, **overrides: object) -> dict[str, object]:
        plan = self._read(self.plan_path, uid=0)
        arguments: dict[str, object] = {
            "authority_database": self.database,
            "plan_path": self.plan_path,
            "plan_document_sha256": str(plan["document_sha256"]),
            "attestation": self.attestation,
            "maintenance_root": self.root,
            "maintenance_gid": 0,
            "maintenance_deployment_id": self.deployment_id,
            "authority_uid": 0,
            "effective_uid_reader": lambda: 0,
            "database_identity_reader": self._identity,
            "evidence_reader": self._read,
            "evidence_publisher": self._publish,
            "maintenance_state_reader": self._maintenance,
            "maintenance_lock_factory": self._maintenance_lock,
            "broker_lock_factory": self._broker_lock,
        }
        arguments.update(overrides)
        return cutover.apply_authority_shared_root_positive_absence(**arguments)

    def test_plan_apply_and_replay_are_sealed_locked_and_database_only(self) -> None:
        with mock.patch.object(
            cutover.subprocess,
            "run",
            side_effect=AssertionError("positive-absence wrapper invoked a native tool"),
        ):
            planned = self._plan()
            self.assertFalse(planned["writes_performed"])
            self.assertEqual(
                planned["database_binding_count"], EXPECTED_DATABASE_BINDING_COUNT
            )
            first = self._apply()
            replay = self._apply()

        self.assertTrue(first["writes_performed"])
        self.assertFalse(replay["writes_performed"])
        self.assertEqual(first["document_sha256"], replay["document_sha256"])
        self.assertEqual(EXPECTED_PRESENT_DATABASE_BINDING_COUNT, 135)
        self.assertEqual(EXPECTED_ABSENT_DATABASE_BINDING_COUNT, 4)
        self.assertLess(
            self.events.index("broker-enter"), self.events.index("maintenance-enter")
        )
        self.assertGreaterEqual(self.maintenance_reads, 6)

        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        try:
            repository = connection.execute(
                "SELECT state FROM repositories WHERE repo_id = ?",
                (REPOSITORY_ID,),
            ).fetchone()
            self.assertEqual(repository["state"], "missing")
            present = connection.execute(
                """
                SELECT policy.repo_id, policy.current_value,
                       observation.restart_policy
                FROM startup_policies policy
                JOIN docker_observations observation
                  ON observation.docker_resource_id = policy.resource_id
                WHERE policy.resource_id = 'container-23'
                """
            ).fetchone()
            self.assertEqual(
                (present["repo_id"], present["current_value"], present["restart_policy"]),
                (None, "no", "no"),
            )
        finally:
            connection.close()

    def test_lost_maintenance_before_commit_rolls_back(self) -> None:
        self._plan()

        def expiring_maintenance(**kwargs: object) -> object | None:
            del kwargs
            self.maintenance_reads += 1
            if self.maintenance_reads >= 3:
                return None
            return SimpleNamespace(
                deployment_id=self.deployment_id,
                message=cutover.PUBLIC_MAINTENANCE_MESSAGE,
            )

        with self.assertRaisesRegex(cutover.CutoverError, "maintenance fence"):
            self._apply(maintenance_state_reader=expiring_maintenance)
        self.assertFalse(self.attestation.exists())
        connection = sqlite3.connect(self.database)
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM repositories WHERE repo_id = ?",
                    (REPOSITORY_ID,),
                ).fetchone()[0],
                "active",
            )
        finally:
            connection.close()

    def test_execute_restores_broker_runs_canary_and_terminal_replays(self) -> None:
        self._plan()
        result = self._execute()
        self.assertTrue(result["writes_performed"])
        self.assertFalse(result["replayed"])
        self.assertIsNone(self.marker)
        self.assertEqual(self.service_commands, ["stop", "start"])
        self.assertEqual(self.readiness_calls, ["preclear", "authenticated"])
        self.assertLess(
            self.events.index("maintenance-activate"), self.events.index("broker-enter")
        )
        self.assertLess(
            self.events.index("broker-exit"), self.events.index("maintenance-clear")
        )

        commands_before = list(self.service_commands)
        changes_before = sqlite3.connect(self.database).total_changes
        replay = self._execute()
        self.assertTrue(replay["replayed"])
        self.assertFalse(replay["writes_performed"])
        self.assertEqual(self.service_commands, commands_before)
        self.assertEqual(sqlite3.connect(self.database).total_changes, changes_before)
        self.assertEqual(self.readiness_calls[-1], "authenticated")

    def test_execute_accepts_broker_revision_churn_and_replays_original_result(self) -> None:
        self._plan()

        def churning_service_command(argv: list[str]) -> int:
            status = self._service_command(argv)
            revision_delta, updated_at = (
                (5, "2099-07-30T08:01:00Z")
                if argv[1] == "stop"
                else (3, "2099-07-30T08:02:00Z")
            )
            connection = sqlite3.connect(self.database)
            try:
                connection.execute(
                    """
                    UPDATE schema_metadata
                    SET state_revision = state_revision + ?, updated_at = ?
                    WHERE singleton = 1
                    """,
                    (revision_delta, updated_at),
                )
                connection.commit()
            finally:
                connection.close()
            return status

        first = self._execute(command_status=churning_service_command)
        retained = self._read(self.attestation, uid=0)
        self.assertEqual(retained["state_revision_before"], 46)
        self.assertEqual(retained["state_revision_after"], 47)
        self.assertTrue(first["writes_performed"])
        self.assertEqual(self.service_commands, ["stop", "start"])

        replay = self._execute(command_status=churning_service_command)
        self.assertTrue(replay["replayed"])
        self.assertFalse(replay["writes_performed"])
        self.assertEqual(self.service_commands, ["stop", "start"])
        self.assertEqual(self._read(self.attestation, uid=0), retained)

    def test_execute_rejects_retained_result_when_database_target_drifted(self) -> None:
        self._plan()
        self._execute()
        commands_before = list(self.service_commands)
        connection = sqlite3.connect(self.database)
        try:
            connection.execute(
                "UPDATE repositories SET state = 'active' WHERE repo_id = ?",
                (REPOSITORY_ID,),
            )
            connection.execute(
                """
                UPDATE schema_metadata
                SET state_revision = state_revision + 1,
                    updated_at = '2099-07-30T08:03:00Z'
                WHERE singleton = 1
                """
            )
            connection.commit()
        finally:
            connection.close()

        with self.assertRaisesRegex(
            cutover.CutoverError, "retained authority state is invalid"
        ):
            self._execute()
        self.assertEqual(self.service_commands, commands_before)

    def test_execute_binds_the_exact_preexisting_maintenance_marker(self) -> None:
        self._plan()
        retained_started_at = "2026-07-30T07:59:00Z"
        self.marker = SimpleNamespace(
            deployment_id=self.deployment_id,
            message=cutover.PUBLIC_MAINTENANCE_MESSAGE,
            retry_after_seconds=5,
            started_at=retained_started_at,
        )
        result = self._execute()
        transaction = self._read(self.transaction_journal, uid=0)
        self.assertEqual(
            transaction["maintenance"]["started_at"], retained_started_at
        )
        self.assertNotIn("maintenance-activate", self.events)
        self.assertTrue(result["maintenance_cleared"])
        self.assertIsNone(self.marker)

    def test_execute_failpoints_retain_marker_and_replay(self) -> None:
        for target in (
            "after-stop",
            "after-apply",
            "after-restart",
            "after-preclear",
            "after-clear",
        ):
            with self.subTest(target=target):
                self._reset_lifecycle()
                raised = False

                def failpoint(phase: str) -> None:
                    nonlocal raised
                    if phase == target and not raised:
                        raised = True
                        raise RuntimeError(f"failpoint:{phase}")

                with self.assertRaisesRegex(RuntimeError, f"failpoint:{target}"):
                    self._execute(phase_hook=failpoint)
                self.assertIsNotNone(self.marker)
                self.assertTrue(cutover._shared_root_broker_is_healthy(self.service))
                had_result = self.attestation.exists()
                replay = self._execute()
                self.assertIsNone(self.marker)
                self.assertTrue(replay["maintenance_cleared"])
                if had_result:
                    self.assertFalse(replay["writes_performed"])

    def test_execute_applier_failure_restores_broker_and_retains_marker(self) -> None:
        self._plan()
        with self.assertRaisesRegex(RuntimeError, "apply failed"):
            self._execute(applier=mock.Mock(side_effect=RuntimeError("apply failed")))
        self.assertEqual(self.service_commands, ["stop", "start"])
        self.assertTrue(cutover._shared_root_broker_is_healthy(self.service))
        self.assertIsNotNone(self.marker)
        self.assertFalse(self.attestation.exists())

    def test_execute_rejects_marker_mismatch_and_transitional_service(self) -> None:
        self._plan()
        self.marker = SimpleNamespace(
            deployment_id=str(uuid.uuid4()),
            message=cutover.PUBLIC_MAINTENANCE_MESSAGE,
            retry_after_seconds=5,
            started_at="2026-07-30T08:00:00Z",
        )
        with self.assertRaises(cutover.CutoverError):
            self._execute()
        self.assertEqual(self.service_commands, [])

        self.marker = None
        self.service = {
            **self._healthy_service(4100, "1" * 32),
            "active_state": "deactivating",
            "sub_state": "stop-sigterm",
        }
        with self.assertRaisesRegex(cutover.CutoverError, "healthy broker baseline"):
            self._execute()
        self.assertIsNone(self.marker)

    def test_stopped_service_requires_pid_zero_and_socket_absence(self) -> None:
        stopped = self._stopped_service("1" * 32)
        self.assertTrue(cutover._shared_root_broker_is_stopped(stopped))
        self.assertFalse(
            cutover._shared_root_broker_is_stopped({**stopped, "main_pid": 41})
        )
        self.assertFalse(
            cutover._shared_root_broker_is_stopped(
                {**stopped, "socket_present": True}
            )
        )

    def test_cli_contract_and_dispatch_are_exact(self) -> None:
        plan_arguments = [
            "plan-authority-shared-root-positive-absence",
            "--authority-database",
            str(self.database),
            "--repository-id",
            REPOSITORY_ID,
            "--operation-id",
            self.operation_id,
            "--plan",
            str(self.plan_path),
        ]
        with mock.patch.object(
            cutover,
            "plan_authority_shared_root_positive_absence",
            return_value={"ok": True},
        ) as planner, redirect_stdout(io.StringIO()):
            self.assertEqual(cutover.main(plan_arguments), 0)
        planner.assert_called_once_with(
            authority_database=self.database,
            repository_id=REPOSITORY_ID,
            operation_id=self.operation_id,
            plan_path=self.plan_path,
            authority_uid=0,
        )

        apply_arguments = [
            "apply-authority-shared-root-positive-absence",
            "--authority-database",
            str(self.database),
            "--plan",
            str(self.plan_path),
            "--plan-document-sha256",
            "a" * 64,
            "--attestation",
            str(self.attestation),
            "--maintenance-root",
            str(self.root),
            "--maintenance-gid",
            "0",
            "--maintenance-deployment-id",
            self.deployment_id,
        ]
        with mock.patch.object(
            cutover,
            "apply_authority_shared_root_positive_absence",
            return_value={"ok": True},
        ) as applier, redirect_stdout(io.StringIO()):
            self.assertEqual(cutover.main(apply_arguments), 0)
        applier.assert_called_once_with(
            authority_database=self.database,
            plan_path=self.plan_path,
            plan_document_sha256="a" * 64,
            attestation=self.attestation,
            maintenance_root=self.root,
            maintenance_gid=0,
            maintenance_deployment_id=self.deployment_id,
            authority_uid=0,
        )

        execute_arguments = [
            "execute-authority-shared-root-positive-absence",
            *apply_arguments[1:],
            "--release",
            str(self.release),
            "--transaction-journal",
            str(self.transaction_journal),
            "--transaction-attestation",
            str(self.transaction_attestation),
            "--broker-socket",
            str(self.broker_socket),
            "--canary-user",
            self.canary_user,
            "--canary-uid",
            str(self.canary_uid),
            "--canary-project",
            str(self.canary_project),
            "--canary-repository-id",
            self.canary_repository_id,
            "--canary-repository-generation",
            str(self.canary_repository_generation),
        ]
        with mock.patch.object(
            cutover,
            "execute_authority_shared_root_positive_absence",
            return_value={"ok": True},
        ) as executor, redirect_stdout(io.StringIO()):
            self.assertEqual(cutover.main(execute_arguments), 0)
        executor.assert_called_once_with(
            release=self.release,
            authority_database=self.database,
            plan_path=self.plan_path,
            plan_document_sha256="a" * 64,
            attestation=self.attestation,
            transaction_journal=self.transaction_journal,
            transaction_attestation=self.transaction_attestation,
            maintenance_root=self.root,
            maintenance_gid=0,
            maintenance_deployment_id=self.deployment_id,
            broker_socket=self.broker_socket,
            canary_user=self.canary_user,
            canary_uid=self.canary_uid,
            canary_project=self.canary_project,
            canary_repository_id=self.canary_repository_id,
            canary_repository_generation=self.canary_repository_generation,
            readiness_wait_seconds=30,
            authority_uid=0,
        )

    def test_non_root_authority_owner_is_rejected(self) -> None:
        with self.assertRaisesRegex(cutover.CutoverError, "root authority owner"):
            cutover.plan_authority_shared_root_positive_absence(
                authority_database=self.database,
                repository_id=REPOSITORY_ID,
                operation_id=self.operation_id,
                plan_path=self.plan_path,
                authority_uid=os.geteuid(),
                effective_uid_reader=os.geteuid,
                database_identity_reader=self._identity,
                evidence_publisher=self._publish,
            )


if __name__ == "__main__":
    unittest.main()
