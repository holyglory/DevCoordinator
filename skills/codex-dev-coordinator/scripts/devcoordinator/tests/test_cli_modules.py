from __future__ import annotations

import argparse
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from devcoordinator.broker import BrokerOperation
from devcoordinator.broker_cli import add_broker_parser, handle_broker_cli
from devcoordinator.lifecycle_cli import add_lifecycle_parsers
import dev_coordinator


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    subparsers = value.add_subparsers(dest="group", required=True)
    add_lifecycle_parsers(subparsers)
    add_broker_parser(subparsers)
    return value


class LifecycleParserContractTests(unittest.TestCase):
    def test_production_cli_registers_lifecycle_and_broker_dispatch_groups(self) -> None:
        value = dev_coordinator.build_parser()
        commands = (
            ["repository", "list-removed", "--compact-json"],
            [
                "resource",
                "plan-retire",
                "--resource-kind",
                "container",
                "--resource-id",
                "resource-id",
                "--immutable-fingerprint",
                "sha256:immutable",
                "--control-binding-id",
                "binding-id",
                "--ownership-fingerprint",
                "sha256:owner",
                "--request-project",
                "/repo",
                "--agent",
                "codex",
                "--reason",
                "retire",
            ],
            [
                "broker",
                "serve",
                "--database",
                "/private/coordinator.sqlite3",
                "--socket",
                "/run/devcoordinator/broker.sock",
            ],
        )
        parsed = [value.parse_args(command) for command in commands]
        self.assertEqual(
            [(item.group, item.action) for item in parsed],
            [
                ("repository", "list-removed"),
                ("resource", "plan-retire"),
                ("broker", "serve"),
            ],
        )

    def test_board_repository_commands_parse_exactly(self) -> None:
        value = parser()
        planned = value.parse_args(
            [
                "repository",
                "plan-remove",
                "--project",
                "/repo",
                "--agent",
                "codex",
                "--reason",
                "Remove from Board",
            ]
        )
        self.assertEqual((planned.group, planned.action), ("repository", "plan-remove"))
        applied = value.parse_args(
            [
                "repository",
                "remove",
                "--project",
                "/repo",
                "--agent",
                "codex",
                "--plan-id",
                "plan-1",
                "--plan-fingerprint",
                "sha256:plan",
            ]
        )
        self.assertEqual(applied.plan_fingerprint, "sha256:plan")
        restored = value.parse_args(
            [
                "repository",
                "reinstall",
                "--project",
                "/repo",
                "--agent",
                "codex",
                "--reason",
                "explicit",
                "--explicit",
            ]
        )
        self.assertTrue(restored.explicit)

    def test_board_resource_commands_require_every_exact_identity_field(self) -> None:
        identity = [
            "--resource-kind",
            "container",
            "--resource-id",
            "docker-id",
            "--immutable-fingerprint",
            "sha256:immutable",
            "--control-binding-id",
            "binding-id",
            "--ownership-fingerprint",
            "sha256:owner",
        ]
        value = parser()
        attached = value.parse_args(
            ["resource", "attach", *identity, "--project", "/repo", "--agent", "codex", "--reason", "attach"]
        )
        self.assertEqual(attached.control_binding_id, "binding-id")
        planned = value.parse_args(
            [
                "resource",
                "plan-retire",
                *identity,
                "--request-project",
                "/coordinator",
                "--agent",
                "codex",
                "--reason",
                "retire",
            ]
        )
        self.assertEqual(planned.request_project, "/coordinator")
        with self.assertRaises(SystemExit):
            value.parse_args(
                [
                    "resource",
                    "plan-retire",
                    *identity[:-2],
                    "--request-project",
                    "/coordinator",
                    "--agent",
                    "codex",
                    "--reason",
                    "retire",
                ]
            )

    def test_public_enrollment_accepts_compose_only_repository(self) -> None:
        args = dev_coordinator.build_parser().parse_args(
            [
                "broker", "enroll",
                "--database", "/service/coordinator.sqlite3",
                "--socket", "/run/devcoordinator/broker.sock",
                "--access-gid", "62000",
                "--client-uid", "501",
                "--account-id", "account-a",
                "--project", "/repo",
                "--agent", "codex-test",
                "--profile-output", "/etc/devcoordinator/profile.json",
            ]
        )
        compose = {
            "declared": True,
            "cwd": "/repo",
            "files": ["/repo/compose.yaml"],
            "services": [],
        }
        with (
            mock.patch.object(
                dev_coordinator, "canonical_project", return_value="/repo"
            ),
            mock.patch.object(
                dev_coordinator,
                "build_project_runtime_spec",
                return_value={
                    "servers": [],
                    "compose": compose,
                    "runtime_file": "/repo/.codex/dev-runtime.json",
                },
            ),
            mock.patch.object(
                dev_coordinator,
                "enroll_repository",
                return_value={"status": "enrolled", "starts_resources": False},
            ) as enroll,
        ):
            result = dev_coordinator.handle_cli(args)

        self.assertEqual(result["status"], "enrolled")
        self.assertFalse(result["starts_resources"])
        call = enroll.call_args.kwargs
        self.assertEqual(call["servers"], [])
        self.assertEqual(call["compose"], compose)
        self.assertIs(call["observe_host"], dev_coordinator.observe_broker_service_store_for_enrollment)


class BrokerCLIContractTests(unittest.TestCase):
    def test_client_wire_accepts_only_opaque_ids_and_typed_arguments(self) -> None:
        value = parser()
        args = value.parse_args(
            [
                "broker",
                "call",
                "--socket",
                "/run/devcoordinator/broker.sock",
                "--expected-broker-uid",
                "123",
                "--account-id",
                "account-a",
                "--database-generation",
                "generation-a",
                "--project-id",
                "repo-id",
                "--resource-id",
                "server-id",
                "--operation",
                "port.lease",
                "--requested-port",
                "3200",
                "--ttl-seconds",
                "60",
            ]
        )
        calls: list[object] = []

        class FakeClient:
            def __init__(self, *_args: object, **_kwargs: object) -> None:
                pass

            def call(self, request: object) -> dict[str, object]:
                calls.append(request)
                return {
                    "version": 1,
                    "operation_id": request.operation_id,
                    "ok": True,
                    "result": {
                        "lease_id": "lease-id",
                        "port": 3200,
                        "status": "active",
                    },
                }

        with mock.patch("devcoordinator.broker_cli.BrokerClient", FakeClient):
            result = handle_broker_cli(args)
        request = calls[0]
        self.assertEqual(request.project_id, "repo-id")
        self.assertEqual(request.resource_id, "server-id")
        self.assertEqual(
            request.arguments,
            {"requested_port": 3200, "protocol": "tcp", "ttl_seconds": 60},
        )
        self.assertEqual(result["result"]["lease_id"], "lease-id")
        with self.assertRaises(SystemExit):
            value.parse_args(
                [
                    "broker",
                    "call",
                    "--socket",
                    "/run/devcoordinator/broker.sock",
                    "--expected-broker-uid",
                    "123",
                    "--account-id",
                    "account-a",
                    "--database-generation",
                    "generation-a",
                    "--project-id",
                    "repo-id",
                    "--resource-id",
                    "server-id",
                    "--operation",
                    "port.lease",
                    "--project-path",
                    "/repo",
                ]
            )

    def test_docker_and_port_argument_families_do_not_cross(self) -> None:
        value = parser()
        docker = value.parse_args(
            [
                "broker",
                "call",
                "--socket",
                "/run/devcoordinator/broker.sock",
                "--expected-broker-uid",
                "123",
                "--account-id",
                "account-a",
                "--database-generation",
                "generation-a",
                "--project-id",
                "repo-id",
                "--resource-id",
                "container-id",
                "--operation",
                "docker.start",
                "--expected-observation-revision",
                "4",
            ]
        )

        class FakeClient:
            def __init__(self, *_args: object, **_kwargs: object) -> None:
                pass

            def call(self, request: object) -> dict[str, object]:
                self.request = request
                return {
                    "version": 1,
                    "operation_id": request.operation_id,
                    "ok": True,
                    "result": {"action": "start"},
                }

        with mock.patch("devcoordinator.broker_cli.BrokerClient", FakeClient):
            result = handle_broker_cli(docker)
        self.assertEqual(result["operation"], BrokerOperation.DOCKER_START.value)
        docker.requested_port = 3200
        with self.assertRaisesRegex(ValueError, "do not accept port"):
            handle_broker_cli(docker)

    def test_admin_provisioning_names_the_service_owned_database_precondition(self) -> None:
        value = parser()
        with tempfile.TemporaryDirectory() as raw:
            database = str(Path(raw) / "coordinator.sqlite3")
            args = value.parse_args(
                [
                    "broker",
                    "grant-resource",
                    "--database",
                    database,
                    "--uid",
                    "501",
                    "--repo-id",
                    "repo-id",
                    "--resource-kind",
                    "container",
                    "--resource-id",
                    "container-id",
                    "--operation",
                    "docker.stop",
                ]
            )
            persistence = mock.Mock()
            with mock.patch(
                "devcoordinator.broker_cli.BrokerPersistence", return_value=persistence
            ):
                result = handle_broker_cli(args)
            persistence.grant_resource.assert_called_once()
            self.assertEqual(result["repo_id"], "repo-id")

    def test_store_artifact_admin_commands_cover_account_and_service_roles(self) -> None:
        value = parser()
        commands = [
            (
                [
                    "broker", "store-backup", "--database", "/stores/account.sqlite3",
                    "--store-role", "account", "--output-root", "/backups/account",
                ],
                "create_store_backup",
                ("/stores/account.sqlite3", "/backups/account"),
                {"store_role": "account"},
            ),
            (
                [
                    "broker", "store-export", "--database", "/stores/service.sqlite3",
                    "--store-role", "service", "--output-root", "/backups/service",
                ],
                "create_store_export",
                ("/stores/service.sqlite3", "/backups/service"),
                {"store_role": "service"},
            ),
            (
                [
                    "broker", "store-restore", "--database", "/stores/service.sqlite3",
                    "--store-role", "service", "--manifest", "/backups/manifest.json",
                    "--safety-root", "/backups/safety", "--timeout-seconds", "9", "--confirm",
                ],
                "restore_store_backup",
                (
                    "/stores/service.sqlite3",
                    "/backups/manifest.json",
                    "/backups/safety",
                ),
                {"store_role": "service", "confirm": True, "timeout_seconds": 9.0},
            ),
            (
                [
                    "broker", "store-import", "--database", "/stores/account.sqlite3",
                    "--store-role", "account", "--manifest", "/backups/export-manifest.json",
                    "--safety-root", "/backups/safety", "--confirm",
                ],
                "restore_store_export",
                (
                    "/stores/account.sqlite3",
                    "/backups/export-manifest.json",
                    "/backups/safety",
                ),
                {"store_role": "account", "confirm": True, "timeout_seconds": 5.0},
            ),
            (
                [
                    "broker", "store-recover", "--database", "/stores/service.sqlite3",
                    "--store-role", "service", "--manifest", "/backups/manifest.json",
                    "--forensic-root", "/backups/forensic",
                    "--confirm-corrupt-recovery",
                ],
                "recover_corrupt_store_backup",
                (
                    "/stores/service.sqlite3",
                    "/backups/manifest.json",
                    "/backups/forensic",
                ),
                {"store_role": "service", "confirm": True, "timeout_seconds": 5.0},
            ),
        ]
        for raw, function_name, positional, keywords in commands:
            with self.subTest(action=raw[1]), mock.patch(
                f"devcoordinator.broker_cli.{function_name}",
                return_value={"status": "verified"},
            ) as operation:
                self.assertEqual(handle_broker_cli(value.parse_args(raw))["status"], "verified")
                operation.assert_called_once_with(*positional, **keywords)


if __name__ == "__main__":
    unittest.main()
