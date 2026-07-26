"""Permanent worker-removal and explicit broker reenrollment regressions."""

from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import tempfile
import unittest
from unittest import mock

from devcoordinator import broker_enrollment
from devcoordinator.broker import (
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    PeerCredentials,
)
from devcoordinator.broker_persistence import BrokerPersistence
from devcoordinator.cleanup_lifecycle import CleanupLifecycle
from devcoordinator.store import (
    AccountStore,
    CoordinatorStore,
    deterministic_id,
    utc_timestamp,
)


UID = os.geteuid()


class CanonicalTemporaryDirectory:
    def __init__(self) -> None:
        home = Path(pwd.getpwuid(UID).pw_dir).resolve()
        self._temporary = tempfile.TemporaryDirectory(
            prefix="devcoordinator-enrollment-reinstall-",
            dir=str(home),
        )
        self.path = Path(self._temporary.name).resolve()

    def cleanup(self) -> None:
        self._temporary.cleanup()


class BrokerEnrollmentReinstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = CanonicalTemporaryDirectory()
        self.root = self.temporary.path / "repository"
        self.root.mkdir()
        (self.root / ".git").mkdir()
        self.database = self.temporary.path / "broker.sqlite3"
        self.profile = self.temporary.path / "profile.json"
        self.socket = self.temporary.path / "broker.sock"
        self.profile_publications: list[dict[str, object]] = []
        self.real_account_open = AccountStore.open
        self.real_persistence = BrokerPersistence

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _enroll(
        self,
        *,
        explicit_reinstall: bool = False,
        environment: object = None,
    ) -> dict[str, object]:
        class RootEnrollmentOS:
            def geteuid(self) -> int:
                return 0

            def __getattr__(self, name: str) -> object:
                return getattr(os, name)

        def open_account_store(
            path: Path, *, expected_uid: int, **kwargs: object
        ) -> AccountStore:
            del expected_uid
            return self.real_account_open(path, expected_uid=UID, **kwargs)

        def persistence_factory(
            database_path: Path,
            *,
            expected_uid: int,
            compose_model_renderer: object = None,
            **kwargs: object,
        ) -> BrokerPersistence:
            del expected_uid
            return self.real_persistence(
                database_path,
                expected_uid=UID,
                compose_model_renderer=compose_model_renderer,
                **kwargs,
            )

        def publish_profile(**arguments: object) -> dict[str, object]:
            self.profile_publications.append(arguments)
            return {}

        server = {
            "name": "worker",
            "cwd": str(self.root),
            "role": "test-worker",
            "argv": ["/usr/bin/true"],
            "env": {"MODE": "test"} if environment is None else environment,
            "health_url": "http://127.0.0.1:{port}/health",
        }
        with (
            mock.patch.object(broker_enrollment, "os", RootEnrollmentOS()),
            mock.patch.object(
                broker_enrollment.AccountStore,
                "open",
                side_effect=open_account_store,
            ),
            mock.patch.object(
                broker_enrollment,
                "BrokerPersistence",
                side_effect=persistence_factory,
            ),
            mock.patch.object(
                broker_enrollment,
                "provision_worker_log_directory",
                return_value=self.temporary.path / "worker-logs",
            ),
            mock.patch.object(
                broker_enrollment,
                "_merge_profile",
                side_effect=publish_profile,
            ),
        ):
            return broker_enrollment.enroll_repository(
                database_path=self.database,
                socket_path=self.socket,
                socket_gid=os.getgid(),
                client_uid=UID,
                account_id="account-test",
                canonical_root=str(self.root),
                servers=(server,),
                allowed_server_names=("worker",),
                port_start=43_200,
                port_end=43_210,
                profile_path=self.profile,
                explicit_reinstall=explicit_reinstall,
            )

    def _purge_worker(
        self, *, repo_id: str, server_id: str, sequence: str = "old"
    ) -> str:
        operation_id = f"operation-purge-worker-{sequence}"
        definition_fingerprint = f"definition-{sequence}"
        timestamp = utc_timestamp()
        evidence = {
            "plan": {
                "plan_id": operation_id,
                "target": {
                    "target_kind": "server",
                    "target_id": server_id,
                    "display_name": "worker",
                },
            },
            "snapshot": {
                "target": {
                    "target_kind": "server",
                    "target_id": server_id,
                    "display_name": "worker",
                }
            },
            "retained_log_path": str(self.temporary.path / "worker.log"),
        }
        with CoordinatorStore.open(
            self.database, expected_uid=UID
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO operations(
                        operation_id, repo_id, kind, status, phase,
                        request_fingerprint, owner_uid, actor,
                        created_at, updated_at
                    ) VALUES (?, ?, 'cleanup.apply', 'succeeded', 'complete',
                              'purge-request', ?, 'test-admin', ?, ?)
                    """,
                    (operation_id, repo_id, UID, timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO resource_lifecycle_history(
                        history_id, repo_id, resource_kind, resource_id,
                        immutable_fingerprint, action, operation_id, actor,
                        reason, evidence_json, occurred_at
                    ) VALUES (?, ?, 'server', ?, ?, 'purged', ?, 'test-admin',
                              'permanent test removal', ?, ?)
                    """,
                    (
                        f"history-purge-worker-{sequence}",
                        repo_id,
                        server_id,
                        definition_fingerprint,
                        operation_id,
                        json.dumps(evidence),
                        timestamp,
                    ),
                )
                for statement in (
                    "DELETE FROM broker_runtime_acl WHERE repo_id = ? AND resource_kind = 'service' AND resource_id = ?",
                    "DELETE FROM broker_resource_acl WHERE repo_id = ? AND resource_kind = 'server' AND resource_id = ?",
                    "DELETE FROM broker_assignment_acl WHERE repo_id = ? AND server_definition_id = ?",
                    "DELETE FROM broker_port_policies WHERE repo_id = ? AND server_definition_id = ?",
                ):
                    connection.execute(statement, (repo_id, server_id))
                connection.execute(
                    "DELETE FROM server_definitions WHERE repo_id = ? AND server_definition_id = ?",
                    (repo_id, server_id),
                )
                connection.execute(
                    """
                    INSERT INTO cleanup_tombstones(
                        target_kind, target_id, repo_id, immutable_fingerprint,
                        operation_id, actor, reason, evidence_json, removed_at
                    ) VALUES ('server', ?, ?, ?, ?, 'test-admin',
                              'permanent test removal', ?, ?)
                    """,
                    (
                        server_id,
                        repo_id,
                        definition_fingerprint,
                        operation_id,
                        json.dumps(evidence),
                        timestamp,
                    ),
                )
        return operation_id

    def test_purged_worker_requires_explicit_reinstall_and_gets_new_replay_safe_identity(
        self,
    ) -> None:
        initial = self._enroll(environment={"MODE": "initial", "EMPTY": ""})
        repo_id = str(initial["repo_id"])
        old_id = str(initial["defined_server_ids"]["worker"])
        repeated = self._enroll(environment={"MODE": "updated"})
        self.assertEqual(repeated["defined_server_ids"]["worker"], old_id)
        self.assertEqual(
            old_id,
            deterministic_id("server-definition", repo_id, "worker"),
        )

        purge_operation_id = self._purge_worker(repo_id=repo_id, server_id=old_id)
        publications_before_rejected_enrollment = len(self.profile_publications)
        with self.assertRaisesRegex(RuntimeError, "permanently removed"):
            self._enroll(environment={"MODE": "must-not-return"})
        self.assertEqual(
            len(self.profile_publications),
            publications_before_rejected_enrollment,
        )
        with CoordinatorStore.open(
            self.database, expected_uid=UID
        ) as store:
            with store.read_transaction() as connection:
                self.assertIsNone(
                    connection.execute(
                        "SELECT 1 FROM server_definitions WHERE name = 'worker'"
                    ).fetchone()
                )

        reinstalled = self._enroll(
            explicit_reinstall=True,
            environment={"MODE": "reinstalled", "EMPTY": ""},
        )
        new_id = str(reinstalled["defined_server_ids"]["worker"])
        expected_new_id = deterministic_id(
            "server-definition-incarnation",
            repo_id,
            "worker",
            old_id,
            "definition-old",
            purge_operation_id,
        )
        self.assertEqual(new_id, expected_new_id)
        self.assertNotEqual(new_id, old_id)
        self.assertEqual(
            self.profile_publications[-1]["repository"]["servers"],
            {"worker": new_id},
        )
        with CoordinatorStore.open(
            self.database, expected_uid=UID
        ) as store:
            with store.read_transaction() as connection:
                reinstalled_environment = dict(
                    connection.execute(
                        """
                        SELECT name, value FROM server_environment
                        WHERE server_definition_id = ?
                        """,
                        (new_id,),
                    )
                )
        self.assertEqual(
            reinstalled_environment,
            {"EMPTY": "", "MODE": "reinstalled"},
        )

        replay = self._enroll(
            explicit_reinstall=True,
            environment={"MODE": "reinstalled", "EMPTY": ""},
        )
        ordinary_replay = self._enroll(environment={"MODE": "ordinary-replay"})
        self.assertEqual(replay["defined_server_ids"]["worker"], new_id)
        self.assertEqual(ordinary_replay["defined_server_ids"]["worker"], new_id)

        with CoordinatorStore.open(
            self.database, expected_uid=UID
        ) as store:
            with store.read_transaction() as connection:
                definitions = list(
                    connection.execute(
                        """
                        SELECT server_definition_id
                        FROM server_definitions
                        WHERE repo_id = ? AND name = 'worker'
                        """,
                        (repo_id,),
                    )
                )
                environment = dict(
                    connection.execute(
                        """
                        SELECT name, value FROM server_environment
                        WHERE server_definition_id = ?
                        """,
                        (new_id,),
                    )
                )
                old_definition = connection.execute(
                    "SELECT 1 FROM server_definitions WHERE server_definition_id = ?",
                    (old_id,),
                ).fetchone()
                tombstone = connection.execute(
                    """
                    SELECT operation_id, evidence_json FROM cleanup_tombstones
                    WHERE target_kind = 'server' AND target_id = ?
                    """,
                    (old_id,),
                ).fetchone()
                history = connection.execute(
                    """
                    SELECT operation_id FROM resource_lifecycle_history
                    WHERE history_id = 'history-purge-worker-old'
                    """
                ).fetchone()
                new_worker_grants = int(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM broker_worker_acl
                        WHERE uid = ? AND repo_id = ?
                          AND server_definition_id = ? AND enabled = 1
                        """,
                        (UID, repo_id, new_id),
                    ).fetchone()[0]
                )
                old_runtime_grants = int(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM broker_runtime_acl
                        WHERE uid = ? AND repo_id = ?
                          AND resource_kind = 'service' AND resource_id = ?
                          AND enabled = 1
                        """,
                        (UID, repo_id, old_id),
                    ).fetchone()[0]
                )
        self.assertEqual(
            [str(row["server_definition_id"]) for row in definitions],
            [new_id],
        )
        self.assertEqual(environment, {"MODE": "ordinary-replay"})
        self.assertIsNone(old_definition)
        self.assertEqual(str(tombstone["operation_id"]), purge_operation_id)
        self.assertIn("retained_log_path", str(tombstone["evidence_json"]))
        self.assertEqual(str(history["operation_id"]), purge_operation_id)
        self.assertGreater(new_worker_grants, 0)
        self.assertEqual(old_runtime_grants, 0)

        second_purge_operation_id = self._purge_worker(
            repo_id=repo_id,
            server_id=new_id,
            sequence="new",
        )
        with self.assertRaisesRegex(RuntimeError, "permanently removed"):
            self._enroll()
        second_reinstall = self._enroll(explicit_reinstall=True)
        second_id = str(second_reinstall["defined_server_ids"]["worker"])
        self.assertEqual(
            second_id,
            deterministic_id(
                "server-definition-incarnation",
                repo_id,
                "worker",
                new_id,
                "definition-new",
                second_purge_operation_id,
            ),
        )
        self.assertNotIn(second_id, {old_id, new_id})

    def test_removed_project_generation_requires_explicit_reinstall(self) -> None:
        initial = self._enroll(environment={"MODE": "initial"})
        repo_id = str(initial["repo_id"])
        old_server_id = str(initial["defined_server_ids"]["worker"])
        persistence = self.real_persistence(self.database, expected_uid=UID)

        def purge_current_project(reason: str) -> tuple[object, dict[str, object]]:
            with CoordinatorStore.open(self.database, expected_uid=UID) as store:
                now = utc_timestamp()
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        UPDATE repository_installations
                        SET status = 'disabled', startup_fenced = 1,
                            generation = generation + 1,
                            disabled_at = ?, updated_at = ?
                        WHERE repo_id = ?
                        """,
                        (now, now, repo_id),
                    )

                def prepare(plan: object, actor: str) -> dict[str, object]:
                    identity = plan.snapshot["identity"]
                    service = persistence.revoke_repository_for_permanent_cleanup(
                        repo_id=repo_id,
                        repository_generation=int(identity["generation"]),
                        cleanup_operation_id=str(plan.plan_id),
                        immutable_fingerprint=str(plan.target_fingerprint),
                        actor=actor,
                    )
                    projections = (
                        persistence.remove_revoked_repository_server_definitions(
                            repo_id=repo_id,
                            repository_generation=int(identity["generation"]),
                            cleanup_operation_id=str(plan.plan_id),
                        )
                    )
                    return {
                        "status": "project_generation_revoked",
                        "repository_revocation": {"service": service},
                        "server_projections": projections,
                    }

                lifecycle = CleanupLifecycle(store, prepare_apply=prepare)
                plan = lifecycle.plan(
                    target_kind="project",
                    target_id=repo_id,
                    actor="test-admin",
                    reason=reason,
                )
                result = lifecycle.apply(
                    plan_id=plan.plan_id,
                    plan_fingerprint=plan.plan_fingerprint,
                    confirmation_phrase=plan.confirmation_phrase,
                    actor="test-admin",
                )
                self.assertTrue(result["ok"], result)
                return plan, result

        first_plan, first_result = purge_current_project("first project removal")
        revoked = first_result["pre_apply"]["repository_revocation"]["service"]
        self.assertEqual(
            revoked["server_revocations"][0]["server_definition_id"],
            old_server_id,
        )
        stale_request = BrokerRequest.create(
            account_id="account-test",
            project_id=repo_id,
            repository_generation=0,
            resource_id=repo_id,
            operation=BrokerOperation.INVENTORY_READ,
            authority_generation=persistence.database_generation(),
        )
        with self.assertRaises(BrokerError) as denied:
            persistence.authorize(
                PeerCredentials(uid=UID, gid=os.getgid(), pid=os.getpid()),
                stale_request,
            )
        self.assertEqual(denied.exception.code, "project_permanently_removed")

        with self.assertRaisesRegex(RuntimeError, "explicitly"):
            self._enroll(environment={"MODE": "stale"})
        reinstalled = self._enroll(
            explicit_reinstall=True,
            environment={"MODE": "reinstalled"},
        )
        new_server_id = str(reinstalled["defined_server_ids"]["worker"])
        self.assertNotEqual(new_server_id, old_server_id)
        self.assertEqual(
            self.profile_publications[-1]["repository"]["generation"], 2
        )
        second_plan, _second_result = purge_current_project(
            "second project removal"
        )
        with CoordinatorStore.open(self.database, expected_uid=UID) as store:
            with store.read_transaction() as connection:
                tombstones = [
                    tuple(row)
                    for row in connection.execute(
                        """
                        SELECT target_generation, operation_id
                        FROM cleanup_tombstones
                        WHERE target_kind = 'project' AND target_id = ?
                        ORDER BY target_generation
                        """,
                        (repo_id,),
                    )
                ]
                repository = connection.execute(
                    "SELECT state, generation FROM repositories WHERE repo_id = ?",
                    (repo_id,),
                ).fetchone()
        self.assertEqual(
            tombstones,
            [(0, first_plan.plan_id), (2, second_plan.plan_id)],
        )
        self.assertEqual(
            dict(repository), {"state": "missing", "generation": 3}
        )

    def test_server_environment_rejects_unstructured_or_unbounded_values(self) -> None:
        invalid = (
            [],
            {"": "value"},
            {"BAD=NAME": "value"},
            {"BAD\x00NAME": "value"},
            {"NAME": "bad\x00value"},
            {"NAME": 1},
            {f"KEY{index}": "value" for index in range(129)},
            {"N" * 257: "value"},
            {"NAME": "x" * 8_193},
            {f"KEY{index}": "x" * 7_000 for index in range(5)},
        )
        for environment in invalid:
            with self.subTest(environment_type=type(environment).__name__):
                with self.assertRaisesRegex(ValueError, "bounded NUL-free"):
                    broker_enrollment._bounded_server_environment(environment)

    def test_profile_revocation_removes_only_exact_old_incarnation_for_all_clients(
        self,
    ) -> None:
        document = {
            "clients": {
                "501": {
                    "repositories": [
                        {
                            "repo_id": "repo-alpha",
                            "servers": {
                                "worker": "worker-old",
                                "web": "web-current",
                            },
                        }
                    ]
                },
                "502": {
                    "repositories": [
                        {
                            "repo_id": "repo-alpha",
                            "servers": {"worker": "worker-old"},
                        },
                        {
                            "repo_id": "repo-other",
                            "servers": {"worker": "worker-old"},
                        },
                    ]
                },
                "503": {
                    "repositories": [
                        {
                            "repo_id": "repo-alpha",
                            "servers": {"worker": "worker-new"},
                        }
                    ]
                },
            }
        }
        affected = broker_enrollment._revoke_server_from_profile_document(
            document,
            repo_id="repo-alpha",
            server_name="worker",
            server_definition_id="worker-old",
        )
        self.assertEqual(affected, [501, 502])
        self.assertEqual(
            document["clients"]["501"]["repositories"][0]["servers"],
            {"web": "web-current"},
        )
        self.assertEqual(
            document["clients"]["502"]["repositories"][1]["servers"],
            {"worker": "worker-old"},
        )
        self.assertEqual(
            document["clients"]["503"]["repositories"][0]["servers"],
            {"worker": "worker-new"},
        )
        self.assertEqual(
            broker_enrollment._revoke_server_from_profile_document(
                document,
                repo_id="repo-alpha",
                server_name="worker",
                server_definition_id="worker-old",
            ),
            [],
        )

    def test_service_revocation_is_plan_bound_and_cannot_be_regranted(self) -> None:
        initial = self._enroll()
        repo_id = str(initial["repo_id"])
        server_id = str(initial["defined_server_ids"]["worker"])
        plan_id = "cleanup-worker-revocation"
        target_fingerprint = "sha256:" + "a" * 64
        plan_fingerprint = "sha256:" + "b" * 64
        timestamp = utc_timestamp()
        with CoordinatorStore.open(self.database, expected_uid=UID) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO operations(
                        operation_id, repo_id, kind, status, phase,
                        request_fingerprint, owner_uid, actor,
                        created_at, updated_at
                    ) VALUES (?, ?, 'cleanup.apply', 'planned', 'planned',
                              ?, ?, 'test-admin', ?, ?)
                    """,
                    (plan_id, repo_id, plan_fingerprint, UID, timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO cleanup_plans(
                        plan_id, repo_id, target_kind, target_id, action,
                        target_fingerprint, plan_fingerprint,
                        confirmation_phrase, snapshot_json, status, phase,
                        actor, reason, created_at, updated_at
                    ) VALUES (?, ?, 'server', ?, 'purge', ?, ?,
                              'REMOVE worker', '{}', 'planned', 'planned',
                              'test-admin', 'obsolete', ?, ?)
                    """,
                    (
                        plan_id,
                        repo_id,
                        server_id,
                        target_fingerprint,
                        plan_fingerprint,
                        timestamp,
                        timestamp,
                    ),
                )
        persistence = BrokerPersistence(self.database, expected_uid=UID)
        self.assertEqual(
            persistence.database_generation(), str(initial["database_generation"])
        )
        with self.assertRaises(BrokerError) as drifted:
            persistence.revoke_server_for_permanent_cleanup(
                repo_id=repo_id,
                server_definition_id=server_id,
                cleanup_operation_id=plan_id,
                immutable_fingerprint="sha256:" + "c" * 64,
                actor="test-admin",
            )
        self.assertEqual(drifted.exception.code, "cleanup_plan_drift")
        with CoordinatorStore.open(self.database, expected_uid=UID) as store:
            with store.read_transaction() as connection:
                self.assertIsNone(
                    connection.execute(
                        "SELECT 1 FROM broker_server_revocations WHERE repo_id = ? AND server_definition_id = ?",
                        (repo_id, server_id),
                    ).fetchone()
                )
                self.assertGreater(
                    int(
                        connection.execute(
                            "SELECT COUNT(*) FROM broker_worker_acl WHERE repo_id = ? AND server_definition_id = ? AND enabled = 1",
                            (repo_id, server_id),
                        ).fetchone()[0]
                    ),
                    0,
                )
        revoked = persistence.revoke_server_for_permanent_cleanup(
            repo_id=repo_id,
            server_definition_id=server_id,
            cleanup_operation_id=plan_id,
            immutable_fingerprint=target_fingerprint,
            actor="test-admin",
        )
        self.assertFalse(revoked["already_revoked"], revoked)
        self.assertTrue(revoked["profile_update_required"], revoked)
        replay = persistence.revoke_server_for_permanent_cleanup(
            repo_id=repo_id,
            server_definition_id=server_id,
            cleanup_operation_id=plan_id,
            immutable_fingerprint=target_fingerprint,
            actor="test-admin",
        )
        self.assertTrue(replay["already_revoked"], replay)
        with self.assertRaises(BrokerError) as blocked:
            persistence.replace_server_access(
                uid=UID,
                repo_id=repo_id,
                server_definition_ids=(server_id,),
                start_port=43_200,
                end_port=43_210,
            )
        self.assertEqual(blocked.exception.code, "resource_permanently_removed")
        with CoordinatorStore.open(self.database, expected_uid=UID) as store:
            with store.read_transaction() as connection:
                enabled = {
                    table: int(
                        connection.execute(
                            f"SELECT COUNT(*) FROM {table} WHERE repo_id = ? AND enabled = 1",
                            (repo_id,),
                        ).fetchone()[0]
                    )
                    for table in (
                        "broker_resource_acl",
                        "broker_runtime_acl",
                        "broker_assignment_acl",
                        "broker_port_policies",
                    )
                }
                worker_grants = {
                    str(row["operation"]): bool(row["enabled"])
                    for row in connection.execute(
                        """
                        SELECT operation, enabled FROM broker_worker_acl
                        WHERE repo_id = ? AND server_definition_id = ?
                        """,
                        (repo_id, server_id),
                    )
                }
                retained = connection.execute(
                    """
                    SELECT cleanup_operation_id
                    FROM broker_server_revocations
                    WHERE repo_id = ? AND server_definition_id = ?
                    """,
                    (repo_id, server_id),
                ).fetchone()
        self.assertEqual(enabled, {key: 0 for key in enabled})
        self.assertFalse(worker_grants["worker.launch_ticket"])
        self.assertFalse(worker_grants["worker.policy_read"])
        self.assertTrue(worker_grants["worker.launched"])
        self.assertTrue(worker_grants["worker.exit"])
        self.assertTrue(worker_grants["worker.attempt_read"])
        self.assertEqual(str(retained["cleanup_operation_id"]), plan_id)

    def test_enrollment_guards_do_not_depend_on_assert_statements(self) -> None:
        source = Path(broker_enrollment.__file__).read_text(encoding="utf-8")
        self.assertNotIn("assert ", source)
        self.assertNotIn("__debug__", source)


if __name__ == "__main__":
    unittest.main()
