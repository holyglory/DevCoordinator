from __future__ import annotations

from pathlib import Path
import sqlite3
import tempfile
import unittest

from devcoordinator.broker import (
    BrokerError,
    BrokerOperation,
    _validate_arguments,
)
from devcoordinator.broker_configuration import (
    _bounded_server_environment,
    _require_nonsecret_server_descriptor as require_config_descriptor,
    _synchronize_server_definitions,
)
from devcoordinator.broker_persistence import BROKER_SCHEMA
from devcoordinator.normalized_server_lifecycle import (
    NormalizedServerLifecycle,
    ServerStartRequest,
    _require_nonsecret_server_environment,
)
from devcoordinator.schema import initialize_schema
from devcoordinator.server_credentials import server_credential_id
from devcoordinator.store import deterministic_id, fingerprint


class ServerCredentialConfigurationTests(unittest.TestCase):
    def test_repository_server_configuration_rejects_literal_credentials(self) -> None:
        secret = "fixture-secret-cl016"
        for environment in (
            {"API_TOKEN": secret},
            {"DATABASE_URL": f"postgresql://worker:{secret}@localhost/app"},
            {"DATABASE_URL": f"postgresql://localhost/app?password={secret}"},
        ):
            with self.subTest(environment=tuple(environment)):
                with self.assertRaisesRegex(ValueError, "dedicated sealed credential") as raised:
                    _bounded_server_environment(environment)
                self.assertNotIn(secret, str(raised.exception))

    def test_credential_free_database_endpoint_remains_ordinary_configuration(self) -> None:
        environment = {
            "DATABASE_URL": "postgresql://localhost/app",
            "OAUTH_AUTHORIZATION_URL": "https://identity.invalid/authorize",
            "PUBLIC_API_KEY": "publishable-fixture-key",
        }
        self.assertEqual(_bounded_server_environment(environment), environment)

    def test_runtime_replacement_rejects_literal_credentials(self) -> None:
        secret = "fixture-secret-cl016"
        arguments = {
            "action": "replace",
            "agent": "codex:test",
            "root_repo_id": "repo-tests",
            "temporary_repo_id": None,
            "target_kind": "service",
            "purpose": "development",
            "ttl_seconds": None,
            "kill_after_run": False,
            "expected_definition_generation": 3,
            "argv": ["/usr/bin/true"],
            "cwd": "/srv/repository",
            "environment": {
                "DATABASE_URL": f"postgresql://worker:{secret}@localhost/app"
            },
        }
        with self.assertRaises(BrokerError) as raised:
            _validate_arguments(
                BrokerOperation.RUNTIME_REQUEST,
                arguments,
                operation_id="00000000-0000-4000-8000-000000000016",
            )
        self.assertEqual(raised.exception.code, "invalid_arguments")
        self.assertIn("dedicated sealed credential", raised.exception.message)
        self.assertNotIn(secret, raised.exception.message)

        arguments["environment"] = {}
        arguments["argv"] = ["/usr/bin/server", "--password", secret]
        with self.assertRaises(BrokerError) as argv_raised:
            _validate_arguments(
                BrokerOperation.RUNTIME_REQUEST,
                arguments,
                operation_id="00000000-0000-4000-8000-000000000017",
            )
        self.assertEqual(argv_raised.exception.code, "invalid_arguments")
        self.assertNotIn(secret, argv_raised.exception.message)

    def test_direct_normalized_lifecycle_rejects_literal_credentials(self) -> None:
        secret = "fixture-secret-cl016"
        with self.assertRaisesRegex(ValueError, "dedicated sealed credential") as raised:
            _require_nonsecret_server_environment(
                {"DATABASE_URL": f"postgresql://worker:{secret}@localhost/app"}
            )
        self.assertNotIn(secret, str(raised.exception))

    def test_server_descriptor_rejects_argv_and_health_url_credentials(self) -> None:
        secret = "fixture-secret-cl016"
        cases = (
            (("/usr/bin/server", "--password", secret), None),
            (
                ("/usr/bin/server",),
                f"https://worker:{secret}@health.invalid/status",
            ),
            (
                ("/usr/bin/server",),
                f"https://health.invalid/status?client_secret={secret}",
            ),
        )
        for argv, health_url in cases:
            with self.subTest(argv=argv[:-1], health=health_url is not None):
                with self.assertRaises(ValueError) as raised:
                    require_config_descriptor(argv, health_url)
                self.assertNotIn(secret, str(raised.exception))
        require_config_descriptor(
            ("/usr/bin/server", "--config", "/etc/example/config.json"),
            "https://health.invalid/status?mode=ready",
        )

    def test_repository_sync_fingerprint_retains_ordered_credential_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            connection = sqlite3.connect(":memory:")
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            initialize_schema(
                connection,
                database_generation="generation-tests",
                timestamp="2026-08-21T00:00:00.000Z",
            )
            connection.executescript(BROKER_SCHEMA)
            connection.execute(
                "INSERT INTO hosts VALUES (?,?,?,?,?,?)",
                ("host-tests", "machine-tests", "linux", "host", "created", "updated"),
            )
            connection.execute(
                "INSERT INTO repositories VALUES (?,?,?,?,?,?,?,?)",
                ("repo-tests", "host-tests", str(root), "Repo", "active", 1, "created", "updated"),
            )
            servers = [
                {
                    "name": "worker",
                    "role": "worker",
                    "cwd": str(root),
                    "argv": ["/usr/bin/server", "--config", "/etc/example.json"],
                    "health_url": "https://health.invalid/status",
                    "env": {"MODE": "development"},
                }
            ]
            server_id = _synchronize_server_definitions(
                connection,
                repo_id="repo-tests",
                root=root,
                servers=servers,
                now="first",
                explicit_reinstall=False,
            )["worker"]
            credential_id = server_credential_id(server_id, "DATABASE_URL")
            connection.execute(
                "INSERT INTO server_environment_credentials VALUES (?,?,?,?,?)",
                (server_id, "DATABASE_URL", credential_id, "created", "updated"),
            )
            connection.execute(
                "INSERT INTO startup_policies VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    deterministic_id("startup-policy", "server", server_id, "coordinator"),
                    "repo-tests",
                    "server",
                    server_id,
                    "coordinator",
                    "enabled",
                    "disabled",
                    "old-fingerprint",
                    0,
                    "created",
                ),
            )
            expected = "sha256:" + fingerprint(
                {
                    "name": "worker",
                    "role": "worker",
                    "cwd": str(root),
                    "argv": ["/usr/bin/server", "--config", "/etc/example.json"],
                    "environment": {"MODE": "development"},
                    "credential_bindings": [
                        {"name": "DATABASE_URL", "credential_id": credential_id}
                    ],
                    "health_url": "https://health.invalid/status",
                }
            )
            connection.execute(
                "UPDATE server_definitions SET definition_fingerprint=? "
                "WHERE server_definition_id=?",
                (expected, server_id),
            )
            connection.execute(
                "UPDATE startup_policies SET immutable_fingerprint=? WHERE resource_id=?",
                (expected, server_id),
            )
            _synchronize_server_definitions(
                connection,
                repo_id="repo-tests",
                root=root,
                servers=servers,
                now="second",
                explicit_reinstall=False,
            )
            row = connection.execute(
                "SELECT definition_fingerprint,generation FROM server_definitions "
                "WHERE server_definition_id=?",
                (server_id,),
            ).fetchone()
            policy = connection.execute(
                "SELECT immutable_fingerprint,generation FROM startup_policies "
                "WHERE resource_id=?",
                (server_id,),
            ).fetchone()
            self.assertEqual(tuple(row), (expected, 0))
            self.assertEqual(tuple(policy), (expected, 0))

            token_id = server_credential_id(server_id, "SERVICE_TOKEN")
            connection.execute(
                "INSERT INTO server_environment_credentials VALUES (?,?,?,?,?)",
                (server_id, "SERVICE_TOKEN", token_id, "created", "updated"),
            )
            _synchronize_server_definitions(
                connection,
                repo_id="repo-tests",
                root=root,
                servers=servers,
                now="third",
                explicit_reinstall=False,
            )
            changed = connection.execute(
                "SELECT definition_fingerprint,generation FROM server_definitions "
                "WHERE server_definition_id=?",
                (server_id,),
            ).fetchone()
            changed_policy = connection.execute(
                "SELECT immutable_fingerprint,generation FROM startup_policies "
                "WHERE resource_id=?",
                (server_id,),
            ).fetchone()
            self.assertNotEqual(changed[0], expected)
            self.assertEqual(changed[1], 1)
            self.assertEqual(tuple(changed_policy), (changed[0], 1))

            _synchronize_server_definitions(
                connection,
                repo_id="repo-tests",
                root=root,
                servers=servers,
                now="fourth",
                explicit_reinstall=False,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT generation FROM server_definitions WHERE server_definition_id=?",
                    (server_id,),
                ).fetchone()[0],
                1,
            )
            connection.close()

    def test_normalized_fingerprint_payload_includes_credential_bindings(self) -> None:
        request = ServerStartRequest(
            agent="codex:test",
            canonical_project="/srv/repository",
            name="worker",
            cwd="/srv/repository",
            argv=("/usr/bin/server",),
            environment={"MODE": "development"},
            host="127.0.0.1",
            health_url="https://health.invalid/status",
            role="worker",
            port_start=31000,
            port_end=31000,
            preferred=31000,
            ttl_seconds=0,
        )
        binding = {
            "name": "DATABASE_URL",
            "credential_id": server_credential_id("server-tests", "DATABASE_URL"),
        }
        payload = NormalizedServerLifecycle._definition_payload(
            request, 31000, credential_bindings=[binding]
        )
        self.assertEqual(payload["credential_bindings"], [binding])


if __name__ == "__main__":
    unittest.main()
