from __future__ import annotations

from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
import uuid
from unittest import mock

from devcoordinator import agent_cli, broker_backend, broker_configuration
from devcoordinator.broker import (
    AcceptedBrokerRequest,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    BrokerService,
    PeerCredentials,
    SerializedMutationWriter,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend
from devcoordinator.broker_persistence import BrokerPersistence
from devcoordinator.call_journal import RollingCallJournal, read_call_records
from devcoordinator.store import CoordinatorStore, StoreInvariantError, utc_timestamp


class _Acceptor:
    def accept(
        self, peer: PeerCredentials, request: BrokerRequest
    ) -> AcceptedBrokerRequest:
        return AcceptedBrokerRequest(peer=peer, request=request)


class _FailingPersistence:
    def __init__(self, error: BaseException) -> None:
        self.error = error
        self.finished: list[tuple[str, str | None, str | None]] = []

    def ensure_repository_catalog_entry(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        context: object,
        reconcile_repository: object = None,
    ) -> dict[str, object]:
        del accepted, context, reconcile_repository
        raise self.error

    def finish_operation(
        self,
        operation_id: str,
        *,
        result: object = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> None:
        del result
        self.finished.append((operation_id, error_code, error_message))


class _ComposePersistence:
    def __init__(self) -> None:
        self.definition: dict[str, object] | None = None
        self.pending_operation_id: str | None = None
        self.reconciliations: list[tuple[str, dict[str, object]]] = []

    def list_compose_definitions(self, *, repo_id: str) -> list[dict[str, object]]:
        if self.definition is None or self.definition["repo_id"] != repo_id:
            return []
        return [dict(self.definition)]

    def configured_compose_definition_id(self, *, repo_id: str) -> str | None:
        if self.definition is None or self.definition["repo_id"] != repo_id:
            return None
        return str(self.definition["compose_definition_id"])

    def reconcilable_compose_operation_for_definition(
        self, *, repo_id: str, compose_definition_id: str
    ) -> str | None:
        if (
            self.definition is None
            or self.definition["repo_id"] != repo_id
            or self.definition["compose_definition_id"] != compose_definition_id
        ):
            return None
        return self.pending_operation_id

    def compose_reconciliation_candidate(
        self, operation_id: str
    ) -> dict[str, object]:
        if operation_id != self.pending_operation_id or self.definition is None:
            raise AssertionError("unexpected Compose reconciliation candidate")
        return {
            "repo_id": self.definition["repo_id"],
            "compose_definition_id": self.definition["compose_definition_id"],
        }

    def reconcile_compose_operation(
        self, operation_id: str, *, evidence: dict[str, object]
    ) -> None:
        if operation_id != self.pending_operation_id:
            raise AssertionError("unexpected Compose reconciliation operation")
        self.reconciliations.append((operation_id, dict(evidence)))
        self.pending_operation_id = None

    def provision_compose_definition(self, **arguments: object) -> dict[str, object]:
        compose_id = str(arguments["compose_definition_id"])
        repo_id = str(arguments["repo_id"])
        fingerprint = "sha256:" + ("1" * 64)
        generation = 0
        if self.definition is not None:
            generation = int(self.definition["generation"])
        self.definition = {
            "compose_definition_id": compose_id,
            "repo_id": repo_id,
            "definition_fingerprint": fingerprint,
            "generation": generation,
            "enabled": True,
        }
        self.provision_arguments = dict(arguments)
        return dict(self.definition)

class RepositoryEnsureDiagnosticsTests(unittest.TestCase):
    def _request(self) -> BrokerRequest:
        return BrokerRequest.create(
            account_id="developer",
            project_id="anchor-repository",
            resource_id="anchor-repository",
            operation=BrokerOperation.REPOSITORY_ENSURE,
            operation_id=str(uuid.uuid4()),
            arguments={
                "agent": "codex:task:repository-adoption",
                "canonical_root": "/workspace/new-repository",
                "project_kind": "primary",
                "reconcile_scope": "runtime",
            },
        )

    def _reply(
        self, error: BaseException
    ) -> tuple[BrokerRequest, dict[str, object], _FailingPersistence, list[dict[str, object]]]:
        request = self._request()
        persistence = _FailingPersistence(error)
        backend = object.__new__(StoreBackedMutationBackend)
        backend._persistence = persistence  # type: ignore[attr-defined]
        peer = PeerCredentials(uid=1000, gid=1000, pid=12345)
        with tempfile.TemporaryDirectory(
            prefix="repository-ensure-diagnostic-"
        ) as temporary:
            journal_path = Path(temporary) / "calls.jsonl"
            service = BrokerService(
                _Acceptor(),
                SerializedMutationWriter(backend),
                call_journal=RollingCallJournal(
                    journal_path,
                    max_bytes=16 * 1024,
                    backups=1,
                ),
            )
            with mock.patch(
                "devcoordinator.repository_context.resolve_effective_repository_context",
                return_value=object(),
            ):
                reply = service.reply_for_document(peer, request.to_wire())
            records = list(read_call_records(journal_path, backups=1))
        return request, reply, persistence, records

    def test_constraint_failure_retains_concrete_bounded_cause_and_recovery(self) -> None:
        request, reply, persistence, records = self._reply(
            sqlite3.IntegrityError(
                "UNIQUE constraint failed: repositories.host_id, "
                "repositories.canonical_root"
            )
        )

        self.assertFalse(reply["ok"])
        error = reply["error"]
        self.assertEqual(error["code"], "repository_adoption_constraint_failed")
        self.assertIn("UNIQUE constraint failed", error["message"])
        self.assertIn("fresh operation ID", error["message"])
        self.assertNotIn("inspect", error["message"].lower())
        self.assertLessEqual(len(error["message"]), 512)
        self.assertEqual(
            persistence.finished,
            [(request.operation_id, error["code"], error["message"])],
        )
        terminal = records[-1]
        self.assertEqual(terminal["code"], error["code"])
        self.assertEqual(terminal["message"], error["message"])

        client = agent_cli._failure(
            BrokerError(
                error["code"],
                error["message"],
                operation_id=request.operation_id,
            ),
            mutation_attempted=True,
            operation_id_hint=request.operation_id,
            broker_contacted=True,
            observed_mutation=False,
        )
        self.assertEqual(client["classification"], "repository_bootstrap_failed")
        self.assertEqual(client["message"], error["message"])
        self.assertEqual(client["operation_id"], request.operation_id)
        self.assertEqual(
            client["next_command"], "devcoordinator runtime serve --help"
        )
        self.assertIn("specific catalog conflict", client["next_action"])
        self.assertNotIn("inspect logs", client["next_action"].lower())

    def test_store_invariant_failure_is_typed_instead_of_mutation_failed(self) -> None:
        violation = SimpleNamespace(
            code="repository_generation_mismatch",
            detail="repository generation does not match the accepted request",
        )
        _request, reply, _persistence, _records = self._reply(
            StoreInvariantError([violation])
        )

        error = reply["error"]
        self.assertEqual(error["code"], "repository_adoption_invariant_failed")
        self.assertIn("repository_generation_mismatch", error["message"])
        self.assertIn("Correct the conflicting catalog state", error["message"])
        self.assertLessEqual(len(error["message"]), 512)

    def test_unexpected_exception_is_operation_specific_redacted_and_bounded(self) -> None:
        secret = "never-expose-this-value"
        path = "/home/private/developer/repository.sqlite3"
        with self.assertLogs("devcoordinator.broker_backend", level="ERROR"):
            request, reply, persistence, records = self._reply(
                KeyError(f"password={secret} at {path} " + ("x" * 4096))
            )

        error = reply["error"]
        self.assertEqual(error["code"], "repository_adoption_internal_error")
        self.assertIn("failed unexpectedly", error["message"])
        self.assertIn("report this operation ID", error["message"])
        self.assertNotIn(secret, error["message"])
        self.assertNotIn(path, error["message"])
        self.assertNotIn("inspect logs", error["message"].lower())
        self.assertLessEqual(len(error["message"]), 512)
        self.assertEqual(
            persistence.finished,
            [(request.operation_id, error["code"], error["message"])],
        )
        self.assertEqual(records[-1]["code"], error["code"])
        self.assertNotIn(secret, str(records[-1]))
        self.assertNotIn(path, str(records[-1]))

    def test_first_use_compose_contract_is_sealed_idempotently(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="repository-first-use-compose-"
        ) as temporary:
            root = Path(temporary)
            (root / ".codex").mkdir()
            (root / "compose.yaml").write_text(
                "services:\n  postgres:\n    image: postgres:17\n",
                encoding="utf-8",
            )
            (root / ".codex" / "dev-runtime.json").write_text(
                '{"docker":{"project_name":"example","compose_files":'
                '["compose.yaml"],"services":["postgres"]}}',
                encoding="utf-8",
            )
            persistence = _ComposePersistence()

            first = broker_configuration.reconcile_declared_compose_first_use(
                persistence,  # type: ignore[arg-type]
                repo_id="repo-1",
                root=root,
            )
            second = broker_configuration.reconcile_declared_compose_first_use(
                persistence,  # type: ignore[arg-type]
                repo_id="repo-1",
                root=root,
            )

        self.assertTrue(first["changed"])
        self.assertFalse(second["changed"])
        self.assertEqual(
            first["compose_definition_id"], second["compose_definition_id"]
        )
        self.assertEqual(
            persistence.provision_arguments["services"], ("postgres",)
        )

    def test_repository_ensure_reconciles_prior_uncertain_compose_before_reseal(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="repository-first-use-compose-reconcile-"
        ) as temporary:
            root = Path(temporary)
            (root / ".codex").mkdir()
            (root / "compose.yaml").write_text(
                "services:\n  postgres:\n    image: postgres:17\n",
                encoding="utf-8",
            )
            (root / ".codex" / "dev-runtime.json").write_text(
                '{"docker":{"project_name":"example","compose_files":'
                '["compose.yaml"],"services":["postgres"]}}',
                encoding="utf-8",
            )
            persistence = _ComposePersistence()
            persistence.definition = {
                "compose_definition_id": "compose-1",
                "repo_id": "repo-1",
                "definition_fingerprint": "sha256:" + ("0" * 64),
                "generation": 0,
                "enabled": True,
            }
            prior_operation_id = str(uuid.uuid4())
            persistence.pending_operation_id = prior_operation_id
            backend = object.__new__(StoreBackedMutationBackend)
            backend._persistence = persistence  # type: ignore[attr-defined]
            observation = {
                "snapshot_id": "snapshot-1",
                "material_fingerprint": "sha256:" + ("2" * 64),
            }
            backend._observe_fresh_full_docker = mock.Mock(  # type: ignore[method-assign]
                return_value=observation
            )
            request = self._request()

            with mock.patch.object(
                broker_backend,
                "reconcile_declared_ephemeral_templates_first_use",
                return_value={
                    "changed": False,
                    "ephemeral_templates": {},
                    "ephemeral_secret_policies": {},
                },
            ):
                result = backend._reconcile_repository_runtime_contract(
                    request=request,
                    repo_id="repo-1",
                    root=str(root),
                    execution_uid=1000,
                )

        self.assertEqual(
            persistence.reconciliations,
            [(prior_operation_id, observation)],
        )
        self.assertIsNone(persistence.pending_operation_id)
        self.assertEqual(result["compose_definition_id"], "compose-1")
        backend._observe_fresh_full_docker.assert_called_once_with(  # type: ignore[attr-defined]
            request.operation_id,
            project_id="repo-1",
        )

    def test_test_scope_reconciles_fixtures_without_runtime_catalogs(self) -> None:
        persistence = mock.Mock()
        backend = object.__new__(StoreBackedMutationBackend)
        backend._persistence = persistence  # type: ignore[attr-defined]
        ephemeral = {
            "changed": True,
            "ephemeral_templates": {"artifact-postgres": "template-1"},
            "ephemeral_secret_policies": {},
        }
        with (
            mock.patch.object(
                broker_backend,
                "reconcile_declared_compose_first_use",
            ) as compose,
            mock.patch.object(
                broker_backend,
                "reconcile_declared_servers_first_use",
            ) as servers,
            mock.patch.object(
                broker_backend,
                "reconcile_declared_ephemeral_templates_first_use",
                return_value=ephemeral,
            ) as fixtures,
        ):
            result = backend._reconcile_repository_runtime_contract(
                request=self._request(),
                repo_id="repo-1",
                root="/repository",
                execution_uid=1000,
                reconcile_scope="test",
            )

        persistence.configured_compose_definition_id.assert_not_called()
        compose.assert_not_called()
        servers.assert_not_called()
        fixtures.assert_called_once_with(
            persistence,
            repo_id="repo-1",
            root=Path("/repository"),
        )
        self.assertEqual(result["ephemeral_templates"], {"artifact-postgres": "template-1"})
        self.assertTrue(result["changed"])

    def test_first_use_catalogs_declared_persistent_services_without_offline_setup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="repository-first-use-services-"
        ) as temporary:
            root = Path(temporary).resolve()
            (root / ".codex").mkdir()
            (root / "web").mkdir()
            (root / ".codex" / "dev-runtime.json").write_text(
                """{
                  "servers": [{
                    "name": "web",
                    "role": "web",
                    "port": 4185,
                    "cwd": "web",
                    "argv": ["/usr/bin/node", "server.mjs", "--port", "{port}"],
                    "health_url": "http://127.0.0.1:{port}/ready",
                    "env": ["NODE_ENV=development"]
                  }]
                }""",
                encoding="utf-8",
            )
            persistence = BrokerPersistence(
                root / "coordinator.sqlite3",
                expected_uid=Path(root).stat().st_uid,
            )
            now = utc_timestamp()
            with CoordinatorStore.open(
                persistence.database_path,
                expected_uid=Path(root).stat().st_uid,
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        INSERT INTO hosts(
                            host_id, machine_fingerprint, platform, hostname,
                            created_at, updated_at
                        ) VALUES ('host-1', 'machine-1', 'test', 'test', ?, ?)
                        """,
                        (now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO repositories(
                            repo_id, host_id, canonical_root, display_name,
                            state, generation, created_at, updated_at
                        ) VALUES ('repo-1', 'host-1', ?, 'Example',
                                  'active', 0, ?, ?)
                        """,
                        (str(root), now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO repository_installations(
                            repo_id, status, startup_fenced, generation,
                            actor, updated_at
                        ) VALUES ('repo-1', 'installed', 0, 0, 'fixture', ?)
                        """,
                        (now,),
                    )
            with mock.patch.object(
                broker_configuration,
                "provision_worker_log_directory",
                return_value=root / "logs",
            ):
                first = broker_configuration.reconcile_declared_servers_first_use(
                    persistence,
                    repo_id="repo-1",
                    root=root,
                    execution_uid=1000,
                )
                second = broker_configuration.reconcile_declared_servers_first_use(
                    persistence,
                    repo_id="repo-1",
                    root=root,
                    execution_uid=1000,
                )
                manifest = root / ".codex" / "dev-runtime.json"
                manifest.write_text(
                    manifest.read_text(encoding="utf-8").replace(
                        '"port": 4185', '"port": 4186'
                    ),
                    encoding="utf-8",
                )
                third = broker_configuration.reconcile_declared_servers_first_use(
                    persistence,
                    repo_id="repo-1",
                    root=root,
                    execution_uid=1000,
                )
            with CoordinatorStore.open(
                persistence.database_path,
                expected_uid=Path(root).stat().st_uid,
            ) as store:
                with store.read_transaction() as connection:
                    definition = connection.execute(
                        """
                        SELECT server_definition_id, cwd, generation
                        FROM server_definitions
                        WHERE repo_id = 'repo-1' AND name = 'web'
                        """
                    ).fetchone()
                    arguments = [
                        str(row[0])
                        for row in connection.execute(
                            """
                            SELECT argument FROM server_command_arguments
                            WHERE server_definition_id = ? ORDER BY ordinal
                            """,
                            (definition["server_definition_id"],),
                        )
                    ]
                    environment = dict(
                        connection.execute(
                            """
                            SELECT name, value FROM server_environment
                            WHERE server_definition_id = ?
                            """,
                            (definition["server_definition_id"],),
                        )
                    )
                    port_range = connection.execute(
                        """
                        SELECT start_port, end_port, enabled
                        FROM broker_port_ranges
                        WHERE repo_id = 'repo-1' AND server_definition_id = ?
                          AND start_port = 4185 AND end_port = 4185
                        """,
                        (definition["server_definition_id"],),
                    ).fetchone()
                    active_port_ranges = [
                        tuple(row)
                        for row in connection.execute(
                            """
                            SELECT start_port, end_port
                            FROM broker_port_ranges
                            WHERE repo_id = 'repo-1'
                              AND server_definition_id = ? AND enabled = 1
                            ORDER BY start_port, end_port
                            """,
                            (definition["server_definition_id"],),
                        )
                    ]

        self.assertTrue(first["changed"])
        self.assertFalse(second["changed"])
        self.assertTrue(third["changed"])
        self.assertEqual(first["servers"], second["servers"])
        self.assertEqual(definition["cwd"], str(root / "web"))
        self.assertEqual(definition["generation"], 0)
        self.assertEqual(arguments[-2:], ["--port", "{port}"])
        self.assertEqual(environment, {"NODE_ENV": "development"})
        self.assertEqual(tuple(port_range), (4185, 4185, 0))
        self.assertEqual(active_port_ranges, [(4186, 4186)])

    def test_first_use_catalogs_declared_ephemeral_fixture_without_offline_setup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="repository-first-use-fixtures-"
        ) as temporary:
            root = Path(temporary).resolve()
            (root / ".codex").mkdir()
            (root / ".codex" / "dev-runtime.json").write_text(
                """{
                  "ephemeral_containers": [{
                    "name": "artifact-postgres",
                    "image_ref": "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777",
                    "argv": ["postgres", "-c", "fsync=off"],
                    "env": {"POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256"},
                    "secret_policy": "postgres_initdb_password_file_v1",
                    "default_ttl_seconds": 600,
                    "max_ttl_seconds": 3600,
                    "container_tcp_port": 5432,
                    "host_port_start": 55600,
                    "host_port_end": 55631,
                    "memory_bytes": 536870912,
                    "cpu_millis": 1000,
                    "max_concurrent_runs": 2,
                    "max_concurrent_runs_per_uid": 1,
                    "repo_max_active_runs": 4,
                    "repo_memory_budget_bytes": 2147483648,
                    "repo_cpu_budget_millis": 4000
                  }]
                }""",
                encoding="utf-8",
            )
            persistence = BrokerPersistence(
                root / "coordinator.sqlite3",
                expected_uid=Path(root).stat().st_uid,
            )
            now = utc_timestamp()
            with CoordinatorStore.open(
                persistence.database_path,
                expected_uid=Path(root).stat().st_uid,
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        INSERT INTO hosts(
                            host_id, machine_fingerprint, platform, hostname,
                            created_at, updated_at
                        ) VALUES ('host-1', 'machine-1', 'test', 'test', ?, ?)
                        """,
                        (now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO repositories(
                            repo_id, host_id, canonical_root, display_name,
                            state, generation, created_at, updated_at
                        ) VALUES ('repo-1', 'host-1', ?, 'Example',
                                  'active', 0, ?, ?)
                        """,
                        (str(root), now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO repository_installations(
                            repo_id, status, startup_fenced, generation,
                            actor, updated_at
                        ) VALUES ('repo-1', 'installed', 0, 0, 'fixture', ?)
                        """,
                        (now,),
                    )

            first = (
                broker_configuration.reconcile_declared_ephemeral_templates_first_use(
                    persistence,
                    repo_id="repo-1",
                    root=root,
                )
            )
            second = (
                broker_configuration.reconcile_declared_ephemeral_templates_first_use(
                    persistence,
                    repo_id="repo-1",
                    root=root,
                )
            )
            template_id = first["ephemeral_templates"]["artifact-postgres"]
            with CoordinatorStore.open(
                persistence.database_path,
                expected_uid=Path(root).stat().st_uid,
            ) as store:
                with store.read_transaction() as connection:
                    sealed = connection.execute(
                        """
                        SELECT template_id, image_ref, container_tcp_port, enabled
                        FROM ephemeral_container_templates
                        WHERE repo_id = 'repo-1' AND name = 'artifact-postgres'
                        """
                    ).fetchone()

        self.assertTrue(first["changed"])
        self.assertFalse(second["changed"])
        self.assertEqual(first["ephemeral_templates"], second["ephemeral_templates"])
        self.assertEqual(sealed["template_id"], template_id)
        self.assertEqual(sealed["image_ref"].split("@", 1)[0], "postgres")
        self.assertEqual(sealed["container_tcp_port"], 5432)
        self.assertTrue(sealed["enabled"])
        self.assertEqual(
            first["ephemeral_secret_policies"]["artifact-postgres"]["policy"],
            "postgres_initdb_password_file_v1",
        )


if __name__ == "__main__":
    unittest.main()
