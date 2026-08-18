from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import dev_coordinator

import devcoordinator.broker_cli as broker_cli_module
from devcoordinator import broker_configuration
from devcoordinator.broker import BrokerError, BrokerOperation, UnixBrokerServer
from devcoordinator.broker_cli import add_broker_parser, handle_broker_cli, serve_broker
from devcoordinator.lifecycle_cli import _handle_broker_cleanup, add_lifecycle_parsers
from devcoordinator.store import CoordinatorStore, utc_timestamp
from devcoordinator.tests.test_broker import CanonicalTemporaryDirectory


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    subparsers = value.add_subparsers(dest="group", required=True)
    add_lifecycle_parsers(subparsers)
    add_broker_parser(subparsers)
    return value


class LifecycleParserContractTests(unittest.TestCase):
    def test_archive_listing_is_server_wide_through_one_transport_anchor(self) -> None:
        first = mock.Mock(repo_id="repo-a", canonical_root="/a")
        second = mock.Mock(repo_id="repo-b", canonical_root="/b")
        profile = mock.Mock()
        profile.repositories = {"b": second, "a": first}
        profile.repository.side_effect = lambda root: {
            "/a": first,
            "/b": second,
        }[root]
        profile.call.return_value = (
            "archive-read-operation",
            {
                "archives": [
                    {
                        "target_kind": "project",
                        "target_id": "repo-b",
                        "project_id": "repo-b",
                        "display_name": "Project B",
                        "archived_at": "2026-08-18T02:00:00Z",
                    },
                    {
                        "target_kind": "project",
                        "target_id": "repo-a",
                        "project_id": "repo-a",
                        "display_name": "Project A",
                        "archived_at": "2026-08-18T01:00:00Z",
                    },
                ]
            },
        )

        result = _handle_broker_cleanup(
            argparse.Namespace(group="archives"), profile=profile
        )

        self.assertEqual(
            [item["target_id"] for item in result["archives"]],
            ["repo-b", "repo-a"],
        )
        profile.call.assert_called_once_with(
            repository=first,
            resource_id="repo-a",
            operation=BrokerOperation.ARCHIVES_READ,
            arguments={},
        )

    def test_archive_listing_rejects_conflicting_duplicate_identity(self) -> None:
        repository = mock.Mock(repo_id="repo-a", canonical_root="/a")
        profile = mock.Mock()
        profile.repositories = {"a": repository}
        profile.repository.return_value = repository
        profile.call.return_value = (
            "archive-read-operation",
            {
                "archives": [
                    {"target_kind": "project", "target_id": "repo-a"},
                    {
                        "target_kind": "project",
                        "target_id": "repo-a",
                        "status": "removed",
                    },
                ]
            },
        )

        with self.assertRaisesRegex(RuntimeError, "conflicting duplicate"):
            _handle_broker_cleanup(
                argparse.Namespace(group="archives"), profile=profile
            )

    def test_cleanup_plan_uses_anchor_for_target_absent_from_active_profile(self) -> None:
        anchor = mock.Mock(repo_id="repo-active", canonical_root="/active")
        profile = mock.Mock()
        profile.repositories = {"active": anchor}
        profile.repository.return_value = anchor
        profile.call.return_value = (
            "cleanup-plan-operation",
            {
                "status": "planned",
                "target": {
                    "target_kind": "project",
                    "target_id": "repo-archived",
                },
            },
        )

        result = _handle_broker_cleanup(
            argparse.Namespace(
                group="cleanup",
                action="plan",
                lifecycle_action="purge",
                target_kind="project",
                target_id="repo-archived",
                reason="remove archived fixture",
            ),
            profile=profile,
        )

        self.assertEqual(result["status"], "planned")
        profile.inventory.assert_not_called()
        profile.call.assert_called_once_with(
            repository=anchor,
            resource_id="repo-archived",
            operation=BrokerOperation.CLEANUP_PLAN,
            arguments={
                "action": "purge",
                "target_kind": "project",
                "target_id": "repo-archived",
                "reason": "remove archived fixture",
            },
        )

    def test_universal_test_planning_error_is_not_process_health_failure(self) -> None:
        error = dev_coordinator.UniversalTestCliError(
            "explicit changes are incomplete",
            code="test_plan_changes_mismatch",
            classification="repository_source_invalid",
            action_required="Omit --change and replan.",
        )

        payload = dev_coordinator.coordinator_exception_payload(error)

        self.assertEqual(payload["code"], "test_plan_changes_mismatch")
        self.assertEqual(payload["classification"], "repository_source_invalid")
        self.assertFalse(payload["mutation_performed"])
        self.assertEqual(payload["action_required"], "Omit --change and replan.")

    def test_legacy_absolute_project_route_does_not_require_local_stat(self) -> None:
        route = Path("/another-account/private/repository")
        dev_coordinator._PROJECT_ROOT_CACHE.pop(str(route), None)
        with (
            mock.patch.object(Path, "resolve", return_value=route),
            mock.patch.object(
                dev_coordinator,
                "resolve_immutable_repository_binding",
                return_value=None,
            ),
            mock.patch.object(
                Path,
                "is_dir",
                side_effect=PermissionError(13, "permission denied"),
            ),
        ):
            self.assertEqual(
                dev_coordinator.canonical_project(str(route), refresh=True),
                str(route),
            )

    def test_legacy_project_resolution_uses_immutable_snapshot_route(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            snapshot = Path(raw) / "snapshot" / "root"
            snapshot.mkdir(parents=True)
            binding = mock.Mock(original_root="/source/repository")
            with mock.patch.object(
                dev_coordinator,
                "resolve_immutable_repository_binding",
                return_value=binding,
            ) as resolve_binding:
                self.assertEqual(
                    dev_coordinator.canonical_project(str(snapshot), refresh=True),
                    "/source/repository",
                )
            resolve_binding.assert_called_once_with(snapshot.resolve())

    def test_services_only_runtime_cannot_resurrect_discovered_legacy_compose(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".compose-runtime-no-resurrection-",
            dir=str(Path.home().resolve()),
        ) as raw_root:
            root = Path(raw_root).resolve()
            runtime_dir = root / ".codex"
            runtime_dir.mkdir()
            (root / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            (runtime_dir / "dev-runtime.json").write_text(
                json.dumps({"docker": {"services": ["legacy"]}}),
                encoding="utf-8",
            )
            with (
                mock.patch.object(
                    dev_coordinator,
                    "docker_ps_inventory",
                    return_value={
                        "available": True,
                        "containers": [],
                        "postgres": [],
                    },
                ),
                self.assertRaisesRegex(ValueError, "explicit docker.compose_files"),
            ):
                dev_coordinator.build_project_runtime_spec(
                    {"servers": {}},
                    project=str(root),
                )

    def test_container_inspect_failure_preserves_listing_but_blocks_compose_evidence(
        self,
    ) -> None:
        full_id = "a" * 64

        def command(arguments: list[str]) -> dict[str, object]:
            if arguments[0] == "ps":
                return {
                    "ok": True,
                    "stdout": json.dumps(
                        {
                            "ID": full_id,
                            "Names": "app",
                            "Image": "example/app",
                            "Status": "Up",
                            "Ports": "",
                        }
                    )
                    + "\n",
                }
            if arguments[0] == "inspect":
                return {"ok": False, "error": "denied"}
            raise AssertionError(arguments)

        with (
            mock.patch.object(
                dev_coordinator,
                "docker_available_command",
                side_effect=command,
            ),
            mock.patch.object(
                dev_coordinator,
                "docker_compose_asset_inventory",
                return_value={
                    "available": True,
                    "assets": [
                        {
                            "kind": "network",
                            "id": "b" * 64,
                            "project_name": "foreign-compose-project",
                            "working_dir": "/srv/foreign-compose-project",
                        }
                    ],
                },
            ),
        ):
            observed = dev_coordinator.docker_ps_inventory()
        self.assertTrue(observed["available"])
        self.assertFalse(observed["container_inspection_available"])
        self.assertEqual(observed["containers"][0]["full_id"], full_id)
        self.assertFalse(observed["containers"][0]["inspection_observable"])
        self.assertTrue(observed["containers"][0]["running"])
        self.assertFalse(observed["compose_assets_available"])
        self.assertEqual(observed["compose_assets"], [])

    def test_complete_container_inspect_preserves_compose_asset_evidence(self) -> None:
        full_id = "a" * 64
        asset = {
            "kind": "network",
            "id": "b" * 64,
            "project_name": "foreign-compose-project",
            "working_dir": "/srv/foreign-compose-project",
        }

        def command(arguments: list[str]) -> dict[str, object]:
            if arguments[0] == "ps":
                return {
                    "ok": True,
                    "stdout": json.dumps(
                        {
                            "ID": full_id,
                            "Names": "app",
                            "Image": "example/app",
                            "Status": "Up",
                            "Ports": "",
                        }
                    )
                    + "\n",
                }
            if arguments[0] == "inspect":
                return {
                    "ok": True,
                    "stdout": json.dumps(
                        {
                            "Id": full_id,
                            "State": {"Running": True},
                            "Config": {"Labels": {}},
                            "HostConfig": {"RestartPolicy": {}},
                            "NetworkSettings": {"Ports": {}},
                        }
                    )
                    + "\n",
                }
            raise AssertionError(arguments)

        with (
            mock.patch.object(
                dev_coordinator,
                "docker_available_command",
                side_effect=command,
            ),
            mock.patch.object(
                dev_coordinator,
                "docker_compose_asset_inventory",
                return_value={"available": True, "assets": [asset]},
            ),
        ):
            observed = dev_coordinator.docker_ps_inventory()

        self.assertTrue(observed["container_inspection_available"])
        self.assertTrue(observed["compose_assets_available"])
        self.assertEqual(observed["compose_assets"], [asset])

    def test_malformed_container_listing_fails_closed(self) -> None:
        with mock.patch.object(
            dev_coordinator,
            "docker_available_command",
            return_value={"ok": True, "stdout": "{not-json}\n"},
        ):
            observed = dev_coordinator.docker_ps_inventory()
        self.assertFalse(observed["available"])
        self.assertIn("malformed", observed["error"])

    def test_container_listing_rejects_non_hex_and_out_of_bounds_identities(
        self,
    ) -> None:
        for listed_id in ("abc", "a" * 12, "g" * 12, "A" * 12, "a" * 65):
            with self.subTest(listed_id=listed_id):
                with mock.patch.object(
                    dev_coordinator,
                    "docker_available_command",
                    return_value={
                        "ok": True,
                        "stdout": json.dumps(
                            {
                                "ID": listed_id,
                                "Names": "app",
                                "Image": "example/app",
                                "Status": "Up",
                                "Ports": "",
                            }
                        )
                        + "\n",
                    },
                ):
                    observed = dev_coordinator.docker_ps_inventory()
                self.assertFalse(observed["available"])
                self.assertIn("malformed identity", observed["error"])

    def test_container_inventory_accepts_only_full_hex_identities(self) -> None:
        first_full_id = "a" * 64
        listed_full_id = "c" * 64
        listed = [
            {
                "ID": first_full_id,
                "Names": "first",
                "Image": "example/first",
                "Status": "Up",
                "Ports": "",
            },
            {
                "ID": listed_full_id,
                "Names": "full",
                "Image": "example/full",
                "Status": "Up",
                "Ports": "",
            },
        ]

        def command(arguments: list[str]) -> dict[str, object]:
            if arguments[0] == "ps":
                return {
                    "ok": True,
                    "stdout": "\n".join(json.dumps(item) for item in listed) + "\n",
                }
            if arguments[0] == "inspect":
                return {
                    "ok": True,
                    "stdout": "\n".join(
                        json.dumps(
                            {
                                "Id": identity,
                                "State": {"Running": True},
                                "Config": {},
                            }
                        )
                        for identity in (first_full_id, listed_full_id)
                    )
                    + "\n",
                }
            raise AssertionError(arguments)

        with (
            mock.patch.object(
                dev_coordinator,
                "docker_available_command",
                side_effect=command,
            ),
            mock.patch.object(
                dev_coordinator,
                "docker_compose_asset_inventory",
                return_value={"available": True, "assets": []},
            ),
        ):
            observed = dev_coordinator.docker_ps_inventory()
        self.assertTrue(observed["available"])
        self.assertEqual(
            [item["full_id"] for item in observed["containers"]],
            [first_full_id, listed_full_id],
        )

    def test_container_lifecycle_comes_only_from_exact_inspection(self) -> None:
        full_id = "a" * 64

        def observe(state: object) -> dict[str, object]:
            def command(arguments: list[str]) -> dict[str, object]:
                if arguments[0] == "ps":
                    return {
                        "ok": True,
                        "stdout": json.dumps(
                            {
                                "ID": full_id,
                                "Names": "app",
                                "Image": "example/app",
                                "Status": "Up 10 minutes",
                                "Ports": "",
                            }
                        )
                        + "\n",
                    }
                if arguments[0] == "inspect":
                    return {
                        "ok": True,
                        "stdout": json.dumps(
                            {"Id": full_id, "State": state, "Config": {}}
                        )
                        + "\n",
                    }
                raise AssertionError(arguments)

            with (
                mock.patch.object(
                    dev_coordinator,
                    "docker_available_command",
                    side_effect=command,
                ),
                mock.patch.object(
                    dev_coordinator,
                    "docker_compose_asset_inventory",
                    return_value={"available": True, "assets": []},
                ),
            ):
                return dev_coordinator.docker_ps_inventory()

        stopped = observe({"Running": False})
        self.assertTrue(stopped["available"])
        self.assertIs(stopped["containers"][0]["running"], False)
        for malformed in ({}, {"Running": 1}, {"Running": "false"}, None):
            with self.subTest(state=malformed):
                result = observe(malformed)
                self.assertFalse(result["available"])
                self.assertIn("lifecycle", result["error"])

    def test_container_inspection_rejects_malformed_substituted_and_duplicate_ids(
        self,
    ) -> None:
        listed_id = "a" * 64
        listed = (
            json.dumps(
                {
                    "ID": listed_id,
                    "Names": "app",
                    "Image": "example/app",
                    "Status": "Up",
                    "Ports": "",
                }
            )
            + "\n"
        )
        valid_row = (
            json.dumps(
                {
                    "Id": listed_id,
                    "State": {"Running": True},
                    "Config": {},
                }
            )
            + "\n"
        )
        cases = {
            "malformed": json.dumps({"Id": "a" * 63}) + "\n",
            "substituted": json.dumps({"Id": "b" * 64}) + "\n",
            "duplicate": valid_row + valid_row,
        }
        for case, inspection in cases.items():
            with self.subTest(case=case):

                def command(arguments: list[str]) -> dict[str, object]:
                    if arguments[0] == "ps":
                        return {"ok": True, "stdout": listed}
                    if arguments[0] == "inspect":
                        return {"ok": True, "stdout": inspection}
                    raise AssertionError(arguments)

                with mock.patch.object(
                    dev_coordinator,
                    "docker_available_command",
                    side_effect=command,
                ):
                    observed = dev_coordinator.docker_ps_inventory()
                self.assertFalse(observed["available"])
                self.assertEqual(observed["containers"], [])

    def test_missing_container_inspect_identity_fails_closed(self) -> None:
        first_id = "a" * 64
        second_id = "b" * 64
        listed = [
            {
                "ID": first_id,
                "Names": "one",
                "Image": "example/one",
                "Status": "Up",
                "Ports": "",
            },
            {
                "ID": second_id,
                "Names": "two",
                "Image": "example/two",
                "Status": "Up",
                "Ports": "",
            },
        ]

        def command(arguments: list[str]) -> dict[str, object]:
            if arguments[0] == "ps":
                return {
                    "ok": True,
                    "stdout": "\n".join(json.dumps(item) for item in listed) + "\n",
                }
            if arguments[0] == "inspect":
                return {
                    "ok": True,
                    "stdout": json.dumps(
                        {
                            "Id": first_id,
                            "State": {"Running": True},
                            "Config": {},
                        }
                    )
                    + "\n",
                }
            raise AssertionError(arguments)

        with mock.patch.object(
            dev_coordinator,
            "docker_available_command",
            side_effect=command,
        ):
            observed = dev_coordinator.docker_ps_inventory()
        self.assertFalse(observed["available"])
        self.assertIn("omitted", observed["error"])

    def test_compose_asset_inventory_collects_labeled_networks_and_volumes(
        self,
    ) -> None:
        short_network_id = "a" * 12
        short_network_full_id = short_network_id + "b" * 52
        full_network_id = "c" * 64
        responses = {
            ("network", "ls"): {
                "ok": True,
                "stdout": f"{short_network_id}\n{full_network_id}\n",
            },
            ("network", "inspect"): {
                "ok": True,
                "stdout": "\n".join(
                    json.dumps(
                        {
                            "Id": identity,
                            "Labels": {
                                "com.docker.compose.project": project_name,
                            },
                        }
                    )
                    for identity, project_name in (
                        (short_network_full_id, "alpha-stack"),
                        (full_network_id, "beta-stack"),
                    )
                )
                + "\n",
            },
            ("volume", "ls"): {"ok": True, "stdout": "alpha-data\n"},
            ("volume", "inspect"): {
                "ok": True,
                "stdout": json.dumps(
                    {
                        "Name": "alpha-data",
                        "Labels": {
                            "com.docker.compose.project": "alpha-stack",
                        },
                    }
                )
                + "\n",
            },
        }

        def command(arguments: list[str]) -> dict[str, object]:
            return responses[(arguments[0], arguments[1])]

        with mock.patch.object(
            dev_coordinator,
            "docker_available_command",
            side_effect=command,
        ):
            observed = dev_coordinator.docker_compose_asset_inventory()
        self.assertTrue(observed["available"])
        self.assertEqual(
            observed["assets"],
            [
                {
                    "kind": "network",
                    "id": short_network_full_id,
                    "project_name": "alpha-stack",
                    "working_dir": None,
                },
                {
                    "kind": "network",
                    "id": full_network_id,
                    "project_name": "beta-stack",
                    "working_dir": None,
                },
                {
                    "kind": "volume",
                    "id": "alpha-data",
                    "project_name": "alpha-stack",
                    "working_dir": None,
                },
            ],
        )

    def test_compose_asset_inventory_fails_closed_on_partial_scope(self) -> None:
        def command(arguments: list[str]) -> dict[str, object]:
            if arguments[:2] == ["network", "ls"]:
                return {"ok": True, "stdout": ""}
            if arguments[:2] == ["volume", "ls"]:
                return {"ok": False, "error": "denied"}
            raise AssertionError(arguments)

        with mock.patch.object(
            dev_coordinator,
            "docker_available_command",
            side_effect=command,
        ):
            observed = dev_coordinator.docker_compose_asset_inventory()
        self.assertFalse(observed["available"])
        self.assertEqual(observed["assets"], [])

    def test_compose_network_inspection_rejects_unbound_rows(self) -> None:
        listed_id = "a" * 12
        full_id = listed_id + "b" * 52
        labels = {"com.docker.compose.project": "alpha-stack"}
        valid_row = json.dumps({"Id": full_id, "Labels": labels}) + "\n"
        cases = {
            "non_mapping": json.dumps([{"Id": full_id}]) + "\n",
            "malformed": json.dumps({"Id": listed_id + "b" * 51, "Labels": labels})
            + "\n",
            "substituted": json.dumps({"Id": "c" * 64, "Labels": labels}) + "\n",
            "duplicate": valid_row + valid_row,
            "missing": "",
        }
        for case, inspection in cases.items():
            with self.subTest(case=case):

                def command(arguments: list[str]) -> dict[str, object]:
                    if arguments[:2] == ["network", "ls"]:
                        return {"ok": True, "stdout": listed_id + "\n"}
                    if arguments[:2] == ["network", "inspect"]:
                        return {"ok": True, "stdout": inspection}
                    raise AssertionError(arguments)

                with mock.patch.object(
                    dev_coordinator,
                    "docker_available_command",
                    side_effect=command,
                ):
                    observed = dev_coordinator.docker_compose_asset_inventory()
                self.assertFalse(observed["available"])
                self.assertEqual(observed["assets"], [])

    def test_compose_asset_inventory_rejects_duplicate_list_identity(self) -> None:
        listed_id = "a" * 12

        def command(arguments: list[str]) -> dict[str, object]:
            if arguments[:2] == ["network", "ls"]:
                return {"ok": True, "stdout": f"{listed_id}\n{listed_id}\n"}
            raise AssertionError(arguments)

        with mock.patch.object(
            dev_coordinator,
            "docker_available_command",
            side_effect=command,
        ):
            observed = dev_coordinator.docker_compose_asset_inventory()
        self.assertFalse(observed["available"])
        self.assertIn("duplicate", observed["error"])

    def test_compose_volume_inspection_requires_exact_listed_name(self) -> None:
        def command(arguments: list[str]) -> dict[str, object]:
            if arguments[:2] == ["network", "ls"]:
                return {"ok": True, "stdout": ""}
            if arguments[:2] == ["volume", "ls"]:
                return {"ok": True, "stdout": "alpha-data\n"}
            if arguments[:2] == ["volume", "inspect"]:
                return {
                    "ok": True,
                    "stdout": json.dumps(
                        {
                            "Name": "beta-data",
                            "Labels": {
                                "com.docker.compose.project": "alpha-stack",
                            },
                        }
                    )
                    + "\n",
                }
            raise AssertionError(arguments)

        with mock.patch.object(
            dev_coordinator,
            "docker_available_command",
            side_effect=command,
        ):
            observed = dev_coordinator.docker_compose_asset_inventory()
        self.assertFalse(observed["available"])
        self.assertIn("substituted", observed["error"])

    def test_declared_compose_runtime_requires_exact_nonempty_services(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".compose-runtime-services-", dir=str(Path.home().resolve())
        ) as raw_root:
            root = Path(raw_root).resolve()
            runtime_dir = root / ".codex"
            runtime_dir.mkdir()
            compose_file = root / "docker-compose.yml"
            compose_file.write_text("services: {}\n", encoding="utf-8")
            (runtime_dir / "dev-runtime.json").write_text(
                json.dumps(
                    {
                        "docker": {
                            "compose_files": [str(compose_file)],
                            "services": [],
                        }
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "at least one exact"):
                dev_coordinator.build_project_runtime_spec(
                    {"servers": {}},
                    project=str(root),
                )

    def test_runtime_compose_rejects_symlinked_env_file_before_provenance_is_lost(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".compose-runtime-symlink-", dir=str(Path.home().resolve())
        ) as raw_root:
            root = Path(raw_root).resolve()
            runtime_dir = root / ".codex"
            runtime_dir.mkdir()
            compose_file = root / "docker-compose.yml"
            compose_file.write_text("services: {}\n", encoding="utf-8")
            real_env = root / "real.env"
            real_env.write_text("PRIVATE=value\n", encoding="utf-8")
            real_env.chmod(0o600)
            linked_env = root / "linked.env"
            linked_env.symlink_to(real_env)
            (runtime_dir / "dev-runtime.json").write_text(
                json.dumps(
                    {
                        "docker": {
                            "compose_files": [str(compose_file)],
                            "env_files": [str(linked_env)],
                            "services": ["app"],
                        }
                    }
                ),
                encoding="utf-8",
            )
            with (
                mock.patch.object(
                    dev_coordinator,
                    "docker_ps_inventory",
                    return_value={
                        "available": True,
                        "containers": [],
                        "postgres": [],
                    },
                ),
                self.assertRaisesRegex(ValueError, "symbolic|symlink"),
            ):
                dev_coordinator.build_project_runtime_spec(
                    {"servers": {}},
                    project=str(root),
                )

    def test_runtime_compose_env_files_and_profiles_preserve_declared_order(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".compose-runtime-inputs-", dir=str(Path.home().resolve())
        ) as raw_root:
            root = Path(raw_root).resolve()
            runtime_dir = root / ".codex"
            runtime_dir.mkdir()
            compose_file = root / "docker-compose.yml"
            compose_file.write_text("services: {}\n", encoding="utf-8")
            first_env = root / "first.env"
            second_env = root / "second.env"
            first_env.write_text("FIRST=value\n", encoding="utf-8")
            second_env.write_text("SECOND=value\n", encoding="utf-8")
            first_env.chmod(0o600)
            second_env.chmod(0o600)
            (runtime_dir / "dev-runtime.json").write_text(
                json.dumps(
                    {
                        "docker": {
                            "compose_files": [str(compose_file)],
                            "env_files": [str(first_env), str(second_env)],
                            "profiles": ["capture", "display"],
                            "services": ["collector", "api"],
                            "project_name": "ordered-stack",
                        }
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(
                dev_coordinator,
                "docker_ps_inventory",
                return_value={"available": True, "containers": [], "postgres": []},
            ):
                specification = dev_coordinator.build_project_runtime_spec(
                    {"servers": {}},
                    project=str(root),
                )

        compose = specification["compose"]
        self.assertEqual(compose["env_files"], [str(first_env), str(second_env)])
        self.assertEqual(compose["profiles"], ["capture", "display"])
        self.assertEqual(compose["services"], ["collector", "api"])

    def test_runtime_compose_project_name_reaches_broker_configuration(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".compose-project-name-", dir=str(Path.home().resolve())
        ) as raw_root:
            root = Path(raw_root).resolve()
            runtime_dir = root / ".codex"
            runtime_dir.mkdir()
            (root / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            (runtime_dir / "dev-runtime.json").write_text(
                """{
  "docker": {
    "compose_files": ["docker-compose.yml"],
    "services": ["app"],
    "project_name": "existing_stack"
  }
}
""",
                encoding="utf-8",
            )
            with mock.patch.object(
                dev_coordinator,
                "docker_ps_inventory",
                return_value={"available": True, "containers": [], "postgres": []},
            ):
                specification = dev_coordinator.build_project_runtime_spec(
                    {"servers": {}},
                    project=str(root),
                )

        self.assertEqual(
            specification["compose"]["project_name"],
            "existing_stack",
        )

    def test_broker_configuration_materializes_legacy_cmd_into_fixed_worker_argv(
        self,
    ) -> None:
        args = argparse.Namespace(
            project="/repository",
            port_range="3000-3010",
            profile_output="/tmp/profile.json",
            runtime_file=None,
            access_group=None,
            all_servers=True,
            server=[],
            database="/tmp/coordinator.sqlite3",
            socket="/tmp/broker.sock",
            execution_uid=501,
            approve_compose_host_access=False,
            explicit_reinstall=False,
            agent="test-agent",
        )
        server = {
            "name": "web",
            "role": "worker",
            "cwd": "/repository/apps/web",
            "cmd": "npm run dev -- --hostname {host} --port {port}",
            "argv": None,
            "port": 3003,
            "host": "127.0.0.1",
            "health_url": "http://127.0.0.1:{port}/dashboard",
            "env": {},
        }
        configured = mock.Mock(return_value={})
        with (
            mock.patch.object(dev_coordinator, "canonical_project", return_value="/repository"),
            mock.patch.object(dev_coordinator, "parse_range", return_value=(3000, 3010)),
            mock.patch.object(
                dev_coordinator,
                "build_project_runtime_spec",
                return_value={"servers": [server], "compose": None},
            ),
            mock.patch.object(
                dev_coordinator,
                "exclusive_broker_service_lock",
                return_value=mock.MagicMock(),
            ),
            mock.patch.object(dev_coordinator, "configure_repository", configured),
        ):
            dev_coordinator.coordinated_broker_configure(args)

        self.assertEqual(
            configured.call_args.kwargs["servers"],
            [
                {
                    **server,
                    "argv": [
                        "npm",
                        "run",
                        "dev",
                        "--",
                        "--hostname",
                        "127.0.0.1",
                        "--port",
                        "3003",
                    ],
                }
            ],
        )

    def test_broker_configuration_rejects_unresolved_port_placeholder(self) -> None:
        with self.assertRaisesRegex(ValueError, "web.*no declared port"):
            dev_coordinator.materialize_configured_servers(
                [
                    {
                        "name": "web",
                        "cmd": "npm run dev -- --port {port}",
                        "port": None,
                        "host": "127.0.0.1",
                    }
                ]
            )

    def test_runtime_server_normalizes_legacy_environment_list(self) -> None:
        server = dev_coordinator.normalize_server_definition(
            {
                "name": "web",
                "cwd": ".",
                "env": ["CI=true", "API_URL=http://127.0.0.1:4000"],
            },
            "/repository",
        )
        self.assertEqual(
            server["env"],
            {"CI": "true", "API_URL": "http://127.0.0.1:4000"},
        )
        with self.assertRaisesRegex(ValueError, "unique"):
            dev_coordinator.normalize_server_definition(
                {"name": "web", "env": ["CI=true", "CI=false"]},
                "/repository",
            )

    def test_configuration_rejects_symlinked_compose_inputs_before_canonicalization(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".compose-configuration-symlink-", dir=str(Path.home().resolve())
        ) as raw_root:
            root = Path(raw_root).resolve()
            real_compose = root / "compose.yml"
            real_compose.write_text("services: {}\n", encoding="utf-8")
            linked_compose = root / "linked-compose.yml"
            linked_compose.symlink_to(real_compose)
            env_file = root / "runtime.env"
            env_file.write_text("PRIVATE=value\n", encoding="utf-8")
            env_file.chmod(0o600)

            with self.assertRaisesRegex(ValueError, "symbolic-link"):
                broker_configuration._provision_compose(
                    mock.Mock(),
                    repo_id="repo-alpha",
                    root=root,
                    compose={
                        "declared": True,
                        "files": [str(linked_compose)],
                        "env_files": [str(env_file)],
                        "services": ["api"],
                    },
                )

    def test_configuration_never_falls_back_to_an_older_available_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".compose-configuration-observation-", dir=str(Path.home().resolve())
        ) as raw_root:
            database = Path(raw_root) / "coordinator.sqlite3"
            now = utc_timestamp()
            with CoordinatorStore.open(
                database,
                expected_uid=os.geteuid(),
            ) as store:
                with store.immediate_transaction(
                    revision_kind="observation"
                ) as connection:
                    connection.execute(
                        """
                        INSERT INTO hosts(
                            host_id, machine_fingerprint, platform, hostname,
                            created_at, updated_at
                        ) VALUES ('host-alpha', 'machine-alpha', 'test',
                                  'test-host', ?, ?)
                        """,
                        (now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO observation_snapshots(
                            snapshot_id, host_id, observer_domain, status,
                            material_fingerprint, started_at, completed_at
                        ) VALUES ('old-available', 'host-alpha',
                                  'host-runtime-v2:full-docker', 'completed',
                                  'old-material', ?, ?)
                        """,
                        (now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO observation_capabilities(
                            snapshot_id, observer_domain, docker_available,
                            capability_fingerprint, committed_at
                        ) VALUES ('old-available',
                                  'host-runtime-v2:full-docker', 1,
                                  'old-capability', ?)
                        """,
                        (now,),
                    )
                unavailable_fence = (
                    broker_configuration.capture_observation_freshness_fence(
                        store,
                        host_id="host-alpha",
                    )
                )
                with store.immediate_transaction(
                    revision_kind="observation"
                ) as connection:
                    connection.execute(
                        """
                        INSERT INTO observation_snapshots(
                            snapshot_id, host_id, observer_domain, status,
                            material_fingerprint, started_at, completed_at
                        ) VALUES ('fresh-unavailable', 'host-alpha',
                                  'host-runtime-v2:full-docker', 'completed',
                                  'fresh-material', ?, ?)
                        """,
                        (now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO observation_capabilities(
                            snapshot_id, observer_domain, docker_available,
                            capability_fingerprint, committed_at
                        ) VALUES ('fresh-unavailable',
                                  'host-runtime-v2:full-docker', 0,
                                  'fresh-capability', ?)
                        """,
                        (now,),
                    )
                with self.assertRaisesRegex(RuntimeError, "exact fresh"):
                    broker_configuration._require_exact_configuration_observation(
                        store,
                        evidence={
                            "snapshot_id": "fresh-unavailable",
                            "observer_domain": "host-runtime-v2:full-docker",
                            "docker_available": False,
                            "capability_fingerprint": "fresh-capability",
                            "material_fingerprint": "fresh-material",
                            "completed_at": now,
                        },
                        fence=unavailable_fence,
                    )

                available_fence = broker_configuration.capture_observation_freshness_fence(
                    store,
                    host_id="host-alpha",
                )
                with store.immediate_transaction(
                    revision_kind="observation"
                ) as connection:
                    connection.execute(
                        """
                        INSERT INTO observation_snapshots(
                            snapshot_id, host_id, observer_domain, status,
                            material_fingerprint, started_at, completed_at
                        ) VALUES ('fresh-available', 'host-alpha',
                                  'host-runtime-v2:full-docker', 'completed',
                                  'valid-material', ?, ?)
                        """,
                        (now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO observation_capabilities(
                            snapshot_id, observer_domain, docker_available,
                            capability_fingerprint, committed_at
                        ) VALUES ('fresh-available',
                                  'host-runtime-v2:full-docker', 1,
                                  'valid-capability', ?)
                        """,
                        (now,),
                    )
                accepted = broker_configuration._require_exact_configuration_observation(
                    store,
                    evidence={
                        "snapshot_id": "fresh-available",
                        "observer_domain": "host-runtime-v2:full-docker",
                        "docker_available": True,
                        "capability_fingerprint": "valid-capability",
                        "material_fingerprint": "valid-material",
                        "completed_at": now,
                    },
                    fence=available_fence,
                )
        self.assertEqual(accepted, "fresh-available")

    def test_configuration_waits_out_joined_ticket_then_requires_new_snapshot(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".compose-configuration-joined-ticket-",
            dir=str(Path.home().resolve()),
        ) as raw_root:
            database = Path(raw_root) / "coordinator.sqlite3"
            now = utc_timestamp()
            calls: list[str] = []
            with CoordinatorStore.open(database, expected_uid=os.geteuid()) as store:
                with store.immediate_transaction(
                    revision_kind="observation"
                ) as connection:
                    connection.execute(
                        """
                        INSERT INTO hosts(
                            host_id, machine_fingerprint, platform, hostname,
                            created_at, updated_at
                        ) VALUES ('host-alpha', 'machine-alpha', 'test',
                                  'test-host', ?, ?)
                        """,
                        (now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO observation_snapshots(
                            snapshot_id, host_id, observer_domain, status,
                            started_at
                        ) VALUES ('joined-ticket', 'host-alpha',
                                  'host-runtime-v2:full-docker', 'running', ?)
                        """,
                        (now,),
                    )

                def observe(
                    current_store: CoordinatorStore,
                ) -> dict[str, object]:
                    snapshot_id = "joined-ticket" if not calls else "new-ticket"
                    calls.append(snapshot_id)
                    with current_store.immediate_transaction(
                        revision_kind="observation"
                    ) as connection:
                        if snapshot_id == "joined-ticket":
                            connection.execute(
                                """
                                UPDATE observation_snapshots
                                SET status = 'completed',
                                    material_fingerprint = 'joined-material',
                                    completed_at = ?
                                WHERE snapshot_id = 'joined-ticket'
                                """,
                                (now,),
                            )
                        else:
                            connection.execute(
                                """
                                INSERT INTO observation_snapshots(
                                    snapshot_id, host_id, observer_domain,
                                    status, material_fingerprint, started_at,
                                    completed_at
                                ) VALUES ('new-ticket', 'host-alpha',
                                          'host-runtime-v2:full-docker',
                                          'completed', 'new-material', ?, ?)
                                """,
                                (now, now),
                            )
                        material = (
                            "joined-material"
                            if snapshot_id == "joined-ticket"
                            else "new-material"
                        )
                        capability = (
                            "joined-capability"
                            if snapshot_id == "joined-ticket"
                            else "new-capability"
                        )
                        connection.execute(
                            """
                            INSERT INTO observation_capabilities(
                                snapshot_id, observer_domain, docker_available,
                                capability_fingerprint, committed_at
                            ) VALUES (?, 'host-runtime-v2:full-docker', 1, ?, ?)
                            """,
                            (snapshot_id, capability, now),
                        )
                    return {
                        "snapshot_id": snapshot_id,
                        "observer_domain": "host-runtime-v2:full-docker",
                        "docker_available": True,
                        "capability_fingerprint": capability,
                        "material_fingerprint": material,
                        "completed_at": now,
                    }

                accepted = broker_configuration._capture_new_configuration_observation(
                    store,
                    host_id="host-alpha",
                    observe_host=observe,
                )

        self.assertEqual(accepted, "new-ticket")
        self.assertEqual(calls, ["joined-ticket", "new-ticket"])

    def test_compose_configuration_retries_an_incomplete_local_asset_scan(self) -> None:
        store = mock.Mock()
        connection = mock.Mock()
        scopes = iter(({"assets_complete": 0}, {"assets_complete": 1}))
        connection.execute.side_effect = lambda *_args, **_kwargs: mock.Mock(
            fetchone=lambda: next(scopes)
        )

        def read_transaction() -> mock.MagicMock:
            transaction = mock.MagicMock()
            transaction.__enter__.return_value = connection
            return transaction

        store.read_transaction.side_effect = read_transaction
        observed: list[str] = []

        def observe(_store: object) -> dict[str, str]:
            snapshot_id = f"snapshot-{len(observed) + 1}"
            observed.append(snapshot_id)
            return {"snapshot_id": snapshot_id}

        with (
            mock.patch.object(
                broker_configuration,
                "capture_observation_freshness_fence",
                return_value=mock.Mock(joinable_snapshot_ids=frozenset()),
            ),
            mock.patch.object(
                broker_configuration,
                "_require_exact_configuration_observation",
                side_effect=lambda _store, *, evidence, fence: evidence["snapshot_id"],
            ),
        ):
            accepted = broker_configuration._capture_new_configuration_observation(
                store,
                host_id="host-alpha",
                observe_host=observe,
                require_complete_compose_assets=True,
            )

        self.assertEqual(accepted, "snapshot-2")
        self.assertEqual(observed, ["snapshot-1", "snapshot-2"])

    def test_configuration_rejects_old_ticket_after_unrelated_revision_advance(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".compose-configuration-stale-ticket-",
            dir=str(Path.home().resolve()),
        ) as raw_root:
            database = Path(raw_root) / "coordinator.sqlite3"
            now = utc_timestamp()
            with CoordinatorStore.open(database, expected_uid=os.geteuid()) as store:
                with store.immediate_transaction(
                    revision_kind="observation"
                ) as connection:
                    connection.execute(
                        """
                        INSERT INTO hosts(
                            host_id, machine_fingerprint, platform, hostname,
                            created_at, updated_at
                        ) VALUES ('host-alpha', 'machine-alpha', 'test',
                                  'test-host', ?, ?)
                        """,
                        (now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO observation_snapshots(
                            snapshot_id, host_id, observer_domain, status,
                            material_fingerprint, started_at, completed_at
                        ) VALUES ('old-ticket', 'host-alpha',
                                  'host-runtime-v2:full-docker', 'completed',
                                  'old-material', ?, ?)
                        """,
                        (now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO observation_capabilities(
                            snapshot_id, observer_domain, docker_available,
                            capability_fingerprint, committed_at
                        ) VALUES ('old-ticket',
                                  'host-runtime-v2:full-docker', 1,
                                  'old-capability', ?)
                        """,
                        (now,),
                    )
                fence = broker_configuration.capture_observation_freshness_fence(
                    store,
                    host_id="host-alpha",
                )
                with store.immediate_transaction(
                    revision_kind="observation"
                ) as connection:
                    connection.execute(
                        """
                        INSERT INTO observation_snapshots(
                            snapshot_id, host_id, observer_domain, status,
                            material_fingerprint, started_at, completed_at
                        ) VALUES ('unrelated-ticket', 'host-alpha',
                                  'another-domain', 'completed',
                                  'unrelated-material', ?, ?)
                        """,
                        (now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO observation_capabilities(
                            snapshot_id, observer_domain, docker_available,
                            capability_fingerprint, committed_at
                        ) VALUES ('unrelated-ticket', 'another-domain', 0,
                                  'unrelated-capability', ?)
                        """,
                        (now,),
                    )
                with self.assertRaisesRegex(RuntimeError, "exact fresh"):
                    broker_configuration._require_exact_configuration_observation(
                        store,
                        evidence={
                            "snapshot_id": "old-ticket",
                            "observer_domain": "host-runtime-v2:full-docker",
                            "docker_available": True,
                            "capability_fingerprint": "old-capability",
                            "material_fingerprint": "old-material",
                            "completed_at": now,
                        },
                        fence=fence,
                    )

    def test_system_client_journal_never_imports_legacy_account_authority(self) -> None:
        with (
            mock.patch.object(dev_coordinator, "authority_mode", return_value="system"),
            mock.patch.object(
                dev_coordinator,
                "bootstrap_legacy_import",
                side_effect=AssertionError("system journal imported account authority"),
            ) as legacy_import,
        ):
            dev_coordinator._require_normalized_bootstrap_before_mutation(object())
        legacy_import.assert_not_called()

    def test_service_authority_rejects_user_workload_commands(self) -> None:
        args = dev_coordinator.build_parser().parse_args(["server", "list"])
        with (
            mock.patch.dict(
                os.environ,
                {dev_coordinator.AUTHORITY_ENV: "service"},
                clear=False,
            ),
            self.assertRaisesRegex(PermissionError, "must never use client workload"),
        ):
            dev_coordinator.handle_cli(args)

    def test_legacy_inventory_cli_projects_current_graph_through_v2_envelope(self) -> None:
        args = dev_coordinator.build_parser().parse_args(
            ["inventory", "--project", "/repository", "--compact-json"]
        )
        current = {
            "schema_version": dev_coordinator.INVENTORY_SCHEMA_VERSION,
            "repositories": [{"repo_id": "repo-alpha"}],
            "v1_compatibility": {"servers": []},
        }
        with mock.patch.object(
            dev_coordinator,
            "coordinated_build_inventory",
            return_value=current,
        ) as inventory:
            result = dev_coordinator.handle_cli(args)

        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["repositories"], [{"repo_id": "repo-alpha"}])
        self.assertEqual(result["v1_compatibility"], {"servers": []})
        self.assertEqual(result["memberships"], [])
        self.assertNotIn("memberships", current)
        inventory.assert_called_once_with(
            project="/repository",
            include_docker=True,
            backup_dirs=None,
            stats_history_limit=dev_coordinator.DOCKER_STATS_HISTORY_LIMIT,
        )

    def test_legacy_inventory_projects_immutable_effective_route_without_membership_state(
        self,
    ) -> None:
        current = {
            "schema_version": dev_coordinator.INVENTORY_SCHEMA_VERSION,
            "project": "/source/repository",
            "repositories": [
                {
                    "canonical_root": "/source/repository",
                    "repo_id": "repo-alpha",
                }
            ],
            "v1_compatibility": {"project": "/source/repository"},
        }
        binding = mock.Mock(
            materialized_root="/snapshots/snapshot-one/root",
            original_root="/source/repository",
            repository_id="repo-alpha",
        )
        with (
            mock.patch.object(
                dev_coordinator,
                "coordinated_build_inventory",
                return_value=current,
            ),
            mock.patch.object(
                dev_coordinator,
                "resolve_immutable_repository_binding",
                return_value=binding,
            ),
        ):
            result = dev_coordinator.legacy_cli_inventory(
                project="/snapshots/snapshot-one/root",
            )

        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["memberships"], [])
        self.assertEqual(result["project"], binding.materialized_root)
        self.assertEqual(
            result["v1_compatibility"]["project"], binding.materialized_root
        )
        self.assertEqual(
            result["repositories"],
            [
                {
                    "authority_canonical_root": binding.original_root,
                    "canonical_root": binding.materialized_root,
                    "repo_id": binding.repository_id,
                }
            ],
        )
        self.assertEqual(
            current["schema_version"], dev_coordinator.INVENTORY_SCHEMA_VERSION
        )
        self.assertNotIn("memberships", current)

    def test_production_cli_registers_lifecycle_and_broker_dispatch_groups(
        self,
    ) -> None:
        value = dev_coordinator.build_parser()
        commands = (
            ["repository", "list-removed", "--compact-json"],
            [
                "cleanup",
                "plan-remove",
                "--target-kind",
                "server",
                "--target-id",
                "server-id",
                "--agent",
                "codex",
                "--reason",
                "obsolete",
            ],
            [
                "cleanup",
                "remove",
                "--plan-id",
                "cleanup-plan",
                "--plan-fingerprint",
                "sha256:cleanup-plan",
                "--confirm",
                "REMOVE server server-id",
                "--agent",
                "codex",
            ],
            [
                "resource",
                "plan-retire",
                "--resource-kind",
                "container",
                "--resource-id",
                "resource-id",
                "--immutable-fingerprint",
                "sha256:immutable",
                "--observation-fingerprint",
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
                "/run/devcoordinator-authority.sock",
            ],
        )
        parsed = [value.parse_args(command) for command in commands]
        self.assertEqual(
            [(item.group, item.action) for item in parsed],
            [
                ("repository", "list-removed"),
                ("cleanup", "plan-remove"),
                ("cleanup", "remove"),
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

    def test_resource_commands_require_every_exact_identity_field(self) -> None:
        identity = [
            "--resource-kind",
            "container",
            "--resource-id",
            "docker-id",
            "--immutable-fingerprint",
            "sha256:immutable",
            "--observation-fingerprint",
            "sha256:owner",
        ]
        value = parser()
        attached = value.parse_args(
            [
                "resource",
                "attach",
                *identity,
                "--project",
                "/repo",
                "--agent",
                "codex",
                "--reason",
                "attach",
            ]
        )
        self.assertEqual(attached.resource_id, "docker-id")
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

    def test_compose_project_name_release_parser_is_exact(self) -> None:
        args = dev_coordinator.build_parser().parse_args(
            [
                "broker",
                "release-compose-project-name",
                "--database",
                "/service/coordinator.sqlite3",
                "--compose-definition-id",
                "compose-alpha",
            ]
        )
        self.assertEqual(args.action, "release-compose-project-name")
        self.assertEqual(args.compose_definition_id, "compose-alpha")

    def test_project_name_release_uses_lock_and_strict_new_observation(self) -> None:
        args = argparse.Namespace(
            database="/service/coordinator.sqlite3",
            compose_definition_id="compose-alpha",
        )
        persistence = mock.Mock()
        persistence.compose_project_name_release_candidate.return_value = {
            "enabled": False,
            "claimed": True,
            "host_id": "host-a",
        }
        persistence.release_compose_project_name.return_value = {"status": "released"}
        store = mock.Mock()
        store_context = mock.MagicMock()
        store_context.__enter__.return_value = store
        store_context.__exit__.return_value = False
        lock = mock.MagicMock()
        fresh = {
            "snapshot_id": "snapshot-new",
            "observer_domain": "host-runtime-v2:full-docker",
            "docker_available": True,
            "material_fingerprint": "material",
            "capability_fingerprint": "capability",
            "completed_at": "2026-07-19T00:00:00Z",
        }
        with (
            mock.patch.object(dev_coordinator.os, "geteuid", return_value=0),
            mock.patch.object(
                dev_coordinator,
                "exclusive_broker_service_lock",
                return_value=lock,
            ) as service_lock,
            mock.patch.object(
                dev_coordinator, "BrokerPersistence", return_value=persistence
            ),
            mock.patch.object(
                dev_coordinator.AccountStore, "open", return_value=store_context
            ),
            mock.patch.object(
                dev_coordinator,
                "capture_observation_freshness_fence",
                return_value=object(),
            ),
            mock.patch.object(
                dev_coordinator,
                "observe_broker_service_store_for_configuration",
                return_value={**fresh, "joined": False},
            ),
            mock.patch.object(
                dev_coordinator,
                "require_exact_fresh_observation",
                return_value=fresh,
            ) as require_fresh,
        ):
            result = dev_coordinator.coordinated_broker_compose_project_name_release(
                args
            )
        self.assertEqual(result["administrator_uid"], 0)
        service_lock.assert_called_once()
        require_fresh.assert_called_once()
        self.assertFalse(require_fresh.call_args.kwargs["allow_joined_ticket"])
        persistence.release_compose_project_name.assert_called_once_with(
            compose_definition_id="compose-alpha",
            observation_evidence=fresh,
            actor_uid=0,
        )

    def test_project_name_release_rejects_nonroot_and_stale_ticket(self) -> None:
        args = argparse.Namespace(
            database="/service/coordinator.sqlite3",
            compose_definition_id="compose-alpha",
        )
        with (
            mock.patch.object(dev_coordinator.os, "geteuid", return_value=1001),
            self.assertRaisesRegex(PermissionError, "root service administrator"),
        ):
            dev_coordinator.coordinated_broker_compose_project_name_release(args)

        persistence = mock.Mock()
        persistence.compose_project_name_release_candidate.return_value = {
            "enabled": False,
            "claimed": True,
            "host_id": "host-a",
        }
        store_context = mock.MagicMock()
        store_context.__enter__.return_value = mock.Mock()
        store_context.__exit__.return_value = False
        with (
            mock.patch.object(dev_coordinator.os, "geteuid", return_value=0),
            mock.patch.object(
                dev_coordinator,
                "exclusive_broker_service_lock",
                return_value=mock.MagicMock(),
            ),
            mock.patch.object(
                dev_coordinator, "BrokerPersistence", return_value=persistence
            ),
            mock.patch.object(
                dev_coordinator.AccountStore, "open", return_value=store_context
            ),
            mock.patch.object(
                dev_coordinator,
                "capture_observation_freshness_fence",
                return_value=object(),
            ),
            mock.patch.object(
                dev_coordinator,
                "observe_broker_service_store_for_configuration",
                return_value={"snapshot_id": "old", "joined": False},
            ),
            mock.patch.object(
                dev_coordinator,
                "require_exact_fresh_observation",
                side_effect=dev_coordinator.ObservationFreshnessError("stale"),
            ),
            self.assertRaises(dev_coordinator.ObservationFreshnessError),
        ):
            dev_coordinator.coordinated_broker_compose_project_name_release(args)
        persistence.release_compose_project_name.assert_not_called()

    def test_broker_runtime_status_uses_authoritative_docker_inventory(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".broker-runtime-observation-", dir=str(Path.home().resolve())
        ) as raw_root:
            root = Path(raw_root).resolve()
            runtime_dir = root / ".codex"
            runtime_dir.mkdir()
            (root / "compose.yml").write_text("services: {}\n", encoding="utf-8")
            (runtime_dir / "dev-runtime.json").write_text(
                json.dumps(
                    {
                        "docker": {
                            "compose_files": ["compose.yml"],
                            "services": ["postgres"],
                        },
                        "dependencies": [
                            {
                                "type": "docker",
                                "name": "postgres",
                                "service": "postgres",
                                "container": "globalnewstracker-postgres",
                                "ports": [{"host": "127.0.0.1", "port": 54330}],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            broker_docker = {
                "available": True,
                "containers": [
                    {
                        "name": "globalnewstracker-postgres",
                        "status": "running",
                        "project": str(root),
                        "metadata_source": "docker_labels",
                    },
                    {
                        "name": "globalnewstracker-migrations",
                        "status": "stopped",
                        "project": str(root),
                        "metadata_source": "docker_labels",
                    }
                ],
                "postgres": [],
            }
            baseline = {
                "servers": {},
                "leases": {},
                "port_assignments": {},
                "docker": {"available": None, "containers": [], "postgres": []},
            }
            with (
                mock.patch.object(
                    dev_coordinator,
                    "configured_broker_context",
                    return_value=(object(), object()),
                ),
                mock.patch.object(
                    dev_coordinator,
                    "broker_authority_inventory",
                    return_value={"docker": broker_docker},
                ),
                mock.patch.object(
                    dev_coordinator,
                    "snapshot_runtime_observation",
                    return_value=baseline,
                ),
                mock.patch.object(
                    dev_coordinator,
                    "docker_ps_inventory",
                    side_effect=AssertionError("broker runtime status used local Docker ps"),
                ),
                mock.patch.object(
                    dev_coordinator,
                    "docker_inspect_state",
                    side_effect=AssertionError("broker runtime status used local Docker inspect"),
                ),
                mock.patch.object(
                    dev_coordinator,
                    "docker_log_tail",
                    side_effect=AssertionError("broker runtime status used local Docker logs"),
                ),
                mock.patch.object(dev_coordinator, "port_open", return_value=True),
                mock.patch.object(dev_coordinator, "commit_runtime_observations"),
            ):
                spec, report = dev_coordinator.observe_project_runtime(
                    {"project": str(root)}, action="status"
                )

        self.assertEqual(spec["docker_observation_authority"], "host_broker")
        self.assertTrue(report["ok"])
        self.assertEqual(report["docker_observation"]["status"], "broker_inventory")
        postgres = next(
            service for service in report["services"] if service["name"] == "postgres"
        )
        self.assertEqual(postgres["status"], "running")
        self.assertTrue(postgres["ok"])
        migrations = next(
            service
            for service in report["services"]
            if service["name"] == "globalnewstracker-migrations"
        )
        self.assertFalse(migrations["required"])

    def test_project_start_skips_compose_when_broker_inventory_is_healthy(self) -> None:
        spec = {
            "project": "/repo",
            "compose": {
                "name": "docker-compose",
                "declared": True,
                "autostart": True,
                "cwd": "/repo",
                "files": ["/repo/compose.yml"],
                "services": ["postgres"],
            },
            "docker": {
                "containers": [
                    {
                        "name": "globalnewstracker-postgres",
                        "status": "running",
                        "metadata_source": "docker_labels",
                    }
                ]
            },
            "docker_observation_authority": "host_broker",
            "docker_dependencies": [
                {
                    "name": "postgres",
                    "service": "postgres",
                    "container": "globalnewstracker-postgres",
                    "ports": [{"host": "127.0.0.1", "port": 54330}],
                    "lifecycle_managed": True,
                }
            ],
            "servers": [],
        }
        after = {"action": "start", "ok": True, "classifications": []}
        with (
            mock.patch.object(
                dev_coordinator,
                "configured_broker_context",
                return_value=(object(), object()),
            ),
            mock.patch.object(dev_coordinator, "port_open", return_value=True),
            mock.patch.object(
                dev_coordinator,
                "docker_inspect_state",
                side_effect=AssertionError("healthy broker runtime used local Docker inspect"),
            ),
            mock.patch.object(
                dev_coordinator,
                "coordinated_run_docker",
            ) as docker_action,
            mock.patch.object(
                dev_coordinator,
                "observe_project_runtime",
                return_value=(spec, after),
            ),
        ):
            result = dev_coordinator.execute_project_start(
                {"project": "/repo", "agent": "codex-test"},
                spec,
                {"action": "pre-start", "ok": True, "classifications": []},
            )

        docker_action.assert_not_called()
        self.assertEqual(result["actions"], [])
        self.assertEqual(result["action_errors"], [])

    def test_system_project_restart_uses_only_configured_broker_resources(self) -> None:
        repository_root = str(Path("/").joinpath("home", "private", "repository"))
        repository = dev_coordinator.BrokerRepositoryProfile(
            canonical_root=repository_root,
            repo_id="repo-a",
            generation=3,
            server_ids={"worker": "server-a"},
            container_ids={"database": "container-a"},
            compose_definition_id="compose-a",
            compose_container_ids=frozenset({"container-a"}),
            compose_run_once_services={},
            ephemeral_templates={},
            ephemeral_secret_policies={},
        )
        profile = mock.Mock()
        profile.repository.return_value = repository
        profile.call.side_effect = lambda **arguments: (
            arguments["operation_id"],
            (
                {"compose_observation": {"desired_state_observed": True}}
                if arguments["operation"] is BrokerOperation.COMPOSE_RESTART
                else {"status": "running"}
            ),
        )
        inventory = {
            "schema_version": 2,
            "resources": {
                "servers": [
                    {
                        "server_definition_id": "server-a",
                        "repo_id": "repo-a",
                        "role": "worker",
                    }
                ],
                "docker": [
                    {"docker_resource_id": "container-a", "repo_id": "repo-a"}
                ],
            },
            "observations": {
                "servers": [
                    {"server_definition_id": "server-a", "lifecycle": "running"}
                ],
                "docker": [
                    {"docker_resource_id": "container-a", "lifecycle": "running"}
                ],
            },
            "v1_compatibility": {
                "servers": [{"id": "server-a", "name": "worker", "status": "running"}],
                "docker": {
                    "containers": [
                        {
                            "host_resource_id": "container-a",
                            "name": "database",
                            "status": "running",
                        }
                    ]
                },
            },
        }
        profile.inventory.side_effect = [inventory, inventory]
        with (
            mock.patch.object(dev_coordinator, "authority_mode", return_value="system"),
            mock.patch.object(
                dev_coordinator, "configured_broker_profile", return_value=profile
            ),
            mock.patch.object(
                dev_coordinator,
                "_open_normalized_action_store",
                side_effect=AssertionError("system project action opened client store"),
            ),
        ):
            result = dev_coordinator.coordinated_project_runtime_restart(
                {
                    "agent": "devops-console:user@example.com",
                    "project": repository_root,
                }
            )

        self.assertTrue(result["ok"])
        self.assertEqual(
            [call.kwargs["operation"] for call in profile.call.call_args_list],
            [BrokerOperation.COMPOSE_RESTART, BrokerOperation.RUNTIME_REQUEST],
        )
        self.assertEqual(
            profile.call.call_args_list[1].kwargs["arguments"]["action"], "restart"
        )
        self.assertEqual(profile.inventory.call_count, 2)
        profile.inventory.assert_called_with(canonical_root=repository_root)

    def test_project_action_error_retains_broker_reconciliation_id(self) -> None:
        error = dev_coordinator.project_action_error_from_exception(
            dev_coordinator.BrokerError(
                "operation_outcome_uncertain",
                "Compose outcome needs reconciliation.",
                operation_id="4c6507a0-7f32-4cfd-bf5c-a196322687b3",
            )
        )

        self.assertEqual(
            error["operation_id"], "4c6507a0-7f32-4cfd-bf5c-a196322687b3"
        )
        self.assertIn("Coordinator skill", error["action_required"])

    def test_maintenance_error_returns_typed_wait_and_retry_response(self) -> None:
        payload = dev_coordinator.coordinator_exception_payload(
            dev_coordinator.BrokerError(
                "maintenance_in_progress",
                "Coordinator upgrade in progress; please wait.",
                operation_id="4c6507a0-7f32-4cfd-bf5c-a196322687b3",
                retry_after_seconds=30,
            )
        )

        self.assertEqual(payload["classification"], "maintenance")
        self.assertEqual(payload["code"], "maintenance_in_progress")
        self.assertEqual(payload["retry_after_seconds"], 30)
        self.assertIn("Wait", payload["action_required"])

    def test_non_maintenance_broker_error_preserves_only_bounded_retry_response(
        self,
    ) -> None:
        payload = dev_coordinator.coordinator_exception_payload(
            dev_coordinator.BrokerError(
                "test_scheduler_unavailable",
                "The asynchronous test scheduler is unavailable; retry shortly.",
                retry_after_seconds=2,
            )
        )

        self.assertEqual(payload["classification"], "broker_mutation_failed")
        self.assertEqual(payload["retry_after_seconds"], 2)
        for invalid in (True, 0, -1, 3601, 1.5, "2"):
            invalid_payload = dev_coordinator.coordinator_exception_payload(
                dev_coordinator.BrokerError(
                    "test_scheduler_unavailable",
                    "The asynchronous test scheduler is unavailable; retry shortly.",
                    retry_after_seconds=invalid,  # type: ignore[arg-type]
                )
            )
            self.assertNotIn("retry_after_seconds", invalid_payload)

    def test_systemd_plan_contract_failure_is_typed_repository_configuration(self) -> None:
        payload = dev_coordinator.coordinator_exception_payload(
            dev_coordinator.SystemdCommissioningError(
                "commissioned service requires UMask=0077"
            )
        )

        self.assertEqual(payload["code"], "systemd_unit_contract_invalid")
        self.assertEqual(
            payload["classification"], "repository_configuration_invalid"
        )
        self.assertFalse(payload["mutation_performed"])
        self.assertIn("repository-declared unit", payload["action_required"])

    def test_active_maintenance_masks_transient_profile_contract_skew(self) -> None:
        maintenance = mock.Mock(
            message="Coordinator control-plane maintenance is in progress; live controls will reconnect automatically.",
            retry_after_seconds=45,
        )
        with mock.patch.object(
            dev_coordinator,
            "load_maintenance_state",
            return_value=maintenance,
        ) as load:
            payload = dev_coordinator.coordinator_exception_payload(
                dev_coordinator.BrokerProfileError(
                    "broker repository profile fields are invalid"
                )
            )

        load.assert_called_once_with()
        self.assertEqual(payload["classification"], "maintenance")
        self.assertEqual(payload["code"], "maintenance_in_progress")
        self.assertEqual(payload["retry_after_seconds"], 45)
        self.assertNotIn("broker_profile_invalid", json.dumps(payload))

    def test_unverifiable_maintenance_fails_closed_during_profile_skew(self) -> None:
        with mock.patch.object(
            dev_coordinator,
            "load_maintenance_state",
            side_effect=dev_coordinator.MaintenanceMarkerError(
                "Coordinator maintenance marker has an unsafe identity"
            ),
        ) as load:
            payload = dev_coordinator.coordinator_exception_payload(
                dev_coordinator.BrokerProfileError(
                    "broker repository profile fields are invalid"
                )
            )

        load.assert_called_once_with()
        self.assertEqual(payload["classification"], "maintenance")
        self.assertEqual(payload["code"], "maintenance_state_invalid")
        self.assertEqual(payload["retry_after_seconds"], 60)
        self.assertIn("wait", payload["error"].lower())
        self.assertNotIn("broker_profile_invalid", json.dumps(payload))

    def test_trusted_maintenance_absence_preserves_profile_error(self) -> None:
        with mock.patch.object(
            dev_coordinator,
            "load_maintenance_state",
            return_value=None,
        ) as load:
            payload = dev_coordinator.coordinator_exception_payload(
                dev_coordinator.BrokerProfileError(
                    "broker repository profile fields are invalid"
                )
            )

        load.assert_called_once_with()
        self.assertEqual(payload["classification"], "broker_configuration_required")
        self.assertEqual(payload["code"], "broker_profile_invalid")
        self.assertNotIn("maintenance_state_invalid", json.dumps(payload))

    def test_source_fingerprint_health_check_matches_build_algorithm_and_detects_stale_runtime(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".runtime-provenance-", dir=str(Path.home().resolve())
        ) as raw_root:
            root = Path(raw_root).resolve()
            worker = root / "worker"
            worker.mkdir()
            (worker / "Program.cs").write_text("current source\n", encoding="utf-8")
            (worker / "bin").mkdir()
            (worker / "bin" / "ignored.dll").write_text("ignored", encoding="utf-8")

            check = dev_coordinator.normalize_health_check(
                {
                    "name": "worker-source-provenance",
                    "url": "http://127.0.0.1:5080/healthz",
                    "source_fingerprint": {
                        "root": "worker",
                        "exclude_directories": ["bin", "obj"],
                    },
                },
                project=str(root),
            )
            specification = check["source_fingerprint"]
            self.assertIsInstance(specification, dict)
            expected_file = hashlib.sha256(b"current source\n").hexdigest()
            expected = hashlib.sha256(
                f"{expected_file}  ./Program.cs\n".encode("utf-8")
            ).hexdigest()
            self.assertEqual(dev_coordinator.source_tree_fingerprint(specification), expected)

            verified = dev_coordinator.source_fingerprint_health_result(
                specification,
                json.dumps({"status": "ok", "build": {"sourceFingerprint": expected}}),
            )
            self.assertTrue(verified["ok"])
            self.assertEqual(verified["provenance_status"], "verified")

            stale = dev_coordinator.source_fingerprint_health_result(
                specification,
                json.dumps(
                    {
                        "status": "ok",
                        "build": {"sourceFingerprint": "a" * 64},
                    }
                ),
            )
            self.assertFalse(stale["ok"])
            self.assertEqual(stale["classification"], "source_stale")

            unavailable = dev_coordinator.source_fingerprint_health_result(
                specification,
                json.dumps({"status": "ok"}),
            )
            self.assertFalse(unavailable["ok"])
            self.assertEqual(
                unavailable["classification"], "runtime_provenance_unavailable"
            )

    def test_runtime_provenance_requires_a_confined_source_root(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".runtime-provenance-root-", dir=str(Path.home().resolve())
        ) as raw_root:
            root = Path(raw_root).resolve()
            with self.assertRaisesRegex(ValueError, "source_fingerprint.root"):
                dev_coordinator.normalize_health_check(
                    {
                        "url": "http://127.0.0.1:5080/healthz",
                        "source_fingerprint": {"root": "missing"},
                    },
                    project=str(root),
                )


class BrokerCLIContractTests(unittest.TestCase):
    def test_image_publication_requires_active_maintenance_marker(self) -> None:
        with (
            mock.patch.object(
                dev_coordinator.grp,
                "getgrnam",
                return_value=mock.Mock(gr_gid=986),
            ),
            mock.patch.object(
                dev_coordinator,
                "load_maintenance_state",
                return_value=None,
            ),
            mock.patch.object(dev_coordinator.subprocess, "run") as run,
            self.assertRaisesRegex(RuntimeError, "requires active server-wide"),
        ):
            dev_coordinator._require_live_image_publication_maintenance_boundary()
        run.assert_not_called()

    def test_image_publication_keeps_loopback_api_available(self) -> None:
        with (
            mock.patch.object(
                dev_coordinator.grp,
                "getgrnam",
                return_value=mock.Mock(gr_gid=986),
            ),
            mock.patch.object(
                dev_coordinator,
                "load_maintenance_state",
                return_value=object(),
            ),
            mock.patch.object(
                dev_coordinator.subprocess,
                "run",
                return_value=mock.Mock(returncode=3),
            ) as run,
            self.assertRaisesRegex(RuntimeError, "instead of ECONNREFUSED"),
        ):
            dev_coordinator._require_live_image_publication_maintenance_boundary()
        run.assert_called_once_with(
            [
                "systemctl",
                "is-active",
                "--quiet",
                "devcoordinator-authority.service",
            ],
            check=False,
            stdin=dev_coordinator.subprocess.DEVNULL,
            stdout=dev_coordinator.subprocess.DEVNULL,
            stderr=dev_coordinator.subprocess.DEVNULL,
            timeout=5.0,
        )

    def test_image_publication_accepts_preserved_control_plane(self) -> None:
        with (
            mock.patch.object(
                dev_coordinator.grp,
                "getgrnam",
                return_value=mock.Mock(gr_gid=986),
            ),
            mock.patch.object(
                dev_coordinator,
                "load_maintenance_state",
                return_value=object(),
            ),
            mock.patch.object(
                dev_coordinator.subprocess,
                "run",
                return_value=mock.Mock(returncode=0),
            ) as run,
        ):
            dev_coordinator._require_live_image_publication_maintenance_boundary()
        self.assertEqual(
            [call.args[0][-1] for call in run.call_args_list],
            [
                "devcoordinator-authority.service",
                "devcoordinator-api.service",
            ],
        )

    def test_sigterm_fences_mutations_before_serve_loop_poll(self) -> None:
        events: list[str] = []
        handlers: dict[int, object] = {}

        class FakeServer:
            def __init__(self, socket_path: Path | None = None) -> None:
                self.socket_path = socket_path
                self._expected_uid = os.geteuid()
                self._expected_gid = os.getegid()
                self._socket_mode = 0o660

            def start(self) -> None:
                self.assert_startup_recovery_complete()
                events.append("server-started")
                handlers[broker_cli_module.signal.SIGTERM](
                    broker_cli_module.signal.SIGTERM, None
                )

            @staticmethod
            def assert_startup_recovery_complete() -> None:
                self.assertEqual(
                    runtime.persistence.method_calls[:2],
                    [
                        mock.call.recover_interrupted_docker_operations(),
                        mock.call.recover_interrupted_compose_operations(),
                    ],
                )

        class FakeRuntime:
            def __init__(self, socket_path: Path | None = None) -> None:
                self.server = FakeServer(socket_path)
                self.persistence = mock.Mock()
                self.backend = mock.Mock()
                self.fenced = False
                self.begin_shutdown_calls = 0

            def fence_workers_on_startup(self) -> dict[str, object]:
                events.append("workers-fenced")
                return {
                    "ok": True,
                    "supervisor_epoch": "epoch-a",
                    "fenced_old_runners": [],
                    "started": [],
                    "errors": [],
                }

            def begin_shutdown(self) -> int:
                self.begin_shutdown_calls += 1
                self.fenced = True
                events.append("mutation-fenced")
                return 1

            def close(self) -> None:
                if not self.fenced:
                    raise AssertionError("runtime closed before mutation fence")
                events.append("runtime-closed")

        def install_handler(signum: int, handler: object) -> None:
            handlers[signum] = handler

        temporary = tempfile.TemporaryDirectory(
            prefix="devcoordinator-broker-signal-fence-"
        )
        self.addCleanup(temporary.cleanup)
        args = argparse.Namespace(
            access_group=None,
            database=str(Path(temporary.name) / "coordinator.sqlite3"),
            socket="/run/devcoordinator-authority.sock",
            max_clients=4,
        )
        runtime = FakeRuntime()
        with (
            mock.patch.object(
                broker_cli_module,
                "build_store_backed_broker_runtime",
                return_value=runtime,
            ),
            mock.patch.object(
                broker_cli_module.signal,
                "getsignal",
                return_value=broker_cli_module.signal.SIG_DFL,
            ),
            mock.patch.object(
                broker_cli_module.signal,
                "signal",
                side_effect=install_handler,
            ),
            mock.patch("builtins.print"),
        ):
            serve_broker(args, host_mutations_factory=mock.Mock)

        self.assertEqual(
            events,
            [
                "workers-fenced",
                "server-started",
                "mutation-fenced",
                "runtime-closed",
            ],
        )
        self.assertEqual(runtime.begin_shutdown_calls, 1)
        (
            runtime.persistence.recover_interrupted_compose_operations
        ).assert_called_once_with()
        (
            runtime.persistence.recover_interrupted_docker_operations
        ).assert_called_once_with()
        runtime.backend.recover_ephemeral_runs.assert_called_once_with()
        runtime.backend.start_ephemeral_reaper.assert_called_once_with()

    def test_repeated_signal_during_shutdown_does_not_reenter_fence(self) -> None:
        events: list[str] = []
        handlers: dict[int, object] = {}
        admission_lock = threading.Lock()

        class FakeServer:
            def start(self) -> None:
                events.append("server-started")
                handlers[broker_cli_module.signal.SIGTERM](
                    broker_cli_module.signal.SIGTERM, None
                )

        class FakeRuntime:
            def __init__(self) -> None:
                self.server = FakeServer()
                self.persistence = mock.Mock()
                self.backend = mock.Mock()
                self.begin_shutdown_calls = 0

            def fence_workers_on_startup(self) -> dict[str, object]:
                events.append("workers-fenced")
                return {
                    "ok": True,
                    "supervisor_epoch": "epoch-a",
                    "fenced_old_runners": [],
                    "started": [],
                    "errors": [],
                }

            def begin_shutdown(self) -> int:
                if not admission_lock.acquire(blocking=False):
                    raise AssertionError(
                        "signal handler reentered a non-reentrant admission fence"
                    )
                try:
                    self.begin_shutdown_calls += 1
                    events.append("mutation-fenced")
                    return 1
                finally:
                    admission_lock.release()

            def close(self) -> None:
                if not admission_lock.acquire(blocking=False):
                    raise AssertionError("shutdown drain could not acquire admission lock")
                try:
                    events.append("drain-started")
                    # Model SIGINT arriving while runtime.close() is inside the
                    # same admission condition used by begin_shutdown(). A
                    # second begin_shutdown call would deadlock on a plain
                    # Condition lock; this bounded fixture raises instead.
                    handlers[broker_cli_module.signal.SIGINT](
                        broker_cli_module.signal.SIGINT, None
                    )
                    events.append("drain-finished")
                finally:
                    admission_lock.release()

        runtime = FakeRuntime()

        def install_handler(signum: int, handler: object) -> None:
            handlers[signum] = handler

        temporary = tempfile.TemporaryDirectory(
            prefix="devcoordinator-broker-repeat-signal-"
        )
        self.addCleanup(temporary.cleanup)
        args = argparse.Namespace(
            access_group=None,
            database=str(Path(temporary.name) / "coordinator.sqlite3"),
            socket="/run/devcoordinator-authority.sock",
            max_clients=4,
        )
        with (
            mock.patch.object(
                broker_cli_module,
                "build_store_backed_broker_runtime",
                return_value=runtime,
            ),
            mock.patch.object(
                broker_cli_module.signal,
                "getsignal",
                return_value=broker_cli_module.signal.SIG_DFL,
            ),
            mock.patch.object(
                broker_cli_module.signal,
                "signal",
                side_effect=install_handler,
            ),
            mock.patch("builtins.print"),
        ):
            serve_broker(args, host_mutations_factory=mock.Mock)

        self.assertEqual(runtime.begin_shutdown_calls, 1)
        (
            runtime.persistence.recover_interrupted_compose_operations
        ).assert_called_once_with()
        (
            runtime.persistence.recover_interrupted_docker_operations
        ).assert_called_once_with()
        runtime.backend.recover_ephemeral_runs.assert_called_once_with()
        runtime.backend.start_ephemeral_reaper.assert_called_once_with()
        self.assertEqual(
            events,
            [
                "workers-fenced",
                "server-started",
                "mutation-fenced",
                "drain-started",
                "drain-finished",
            ],
        )

    def test_worker_autostart_begins_only_after_server_admission(self) -> None:
        events: list[str] = []
        handlers: dict[int, object] = {}

        class FakeServer:
            @staticmethod
            def start() -> None:
                events.append("server-started")

        class FakeRuntime:
            def __init__(self) -> None:
                self.server = FakeServer()
                self.persistence = mock.Mock()
                self.backend = mock.Mock()

            @staticmethod
            def fence_workers_on_startup() -> dict[str, object]:
                events.append("workers-fenced")
                return {
                    "ok": True,
                    "supervisor_epoch": "epoch-after-admission",
                    "fenced_old_runners": ["worker-old"],
                    "started": [],
                    "errors": [],
                }

            @staticmethod
            def autostart_workers_after_admission(
                *, fenced: object
            ) -> dict[str, object]:
                if events != ["workers-fenced", "server-started"]:
                    raise AssertionError("worker autostart ran before broker admission")
                events.append("workers-autostarted")
                handlers[broker_cli_module.signal.SIGTERM](
                    broker_cli_module.signal.SIGTERM, None
                )
                return {
                    **dict(fenced),
                    "started": [{"worker_id": "worker-old"}],
                }

            @staticmethod
            def begin_shutdown() -> int:
                events.append("mutation-fenced")
                return 1

            @staticmethod
            def close() -> None:
                events.append("runtime-closed")

        def install_handler(signum: int, handler: object) -> None:
            handlers[signum] = handler

        temporary = tempfile.TemporaryDirectory(
            prefix="devcoordinator-broker-worker-order-"
        )
        self.addCleanup(temporary.cleanup)
        args = argparse.Namespace(
            access_group=None,
            database=str(Path(temporary.name) / "coordinator.sqlite3"),
            socket="/run/devcoordinator-authority.sock",
            max_clients=4,
        )
        runtime = FakeRuntime()
        with (
            mock.patch.object(
                broker_cli_module,
                "build_store_backed_broker_runtime",
                return_value=runtime,
            ),
            mock.patch.object(
                broker_cli_module.signal,
                "getsignal",
                return_value=broker_cli_module.signal.SIG_DFL,
            ),
            mock.patch.object(
                broker_cli_module.signal,
                "signal",
                side_effect=install_handler,
            ),
            mock.patch("builtins.print"),
        ):
            serve_broker(args, host_mutations_factory=mock.Mock)

        self.assertEqual(
            events,
            [
                "workers-fenced",
                "server-started",
                "workers-autostarted",
                "mutation-fenced",
                "runtime-closed",
            ],
        )

    def test_serve_reclaims_only_proven_dead_socket_under_real_service_lock(self) -> None:
        events: list[str] = []
        handlers: dict[int, object] = {}
        with CanonicalTemporaryDirectory() as root:
            runtime_directory = root / "runtime"
            runtime_directory.mkdir(mode=0o750)
            os.chmod(runtime_directory, 0o750)
            socket_path = runtime_directory / "broker.sock"
            sibling = runtime_directory / "ephemeral-secrets"
            sibling.mkdir(mode=0o700)
            sentinel = sibling / "untouched"
            sentinel.write_text("preserve sibling", encoding="utf-8")
            runtime_identity = (
                os.lstat(runtime_directory).st_dev,
                os.lstat(runtime_directory).st_ino,
            )
            sibling_identity = (os.lstat(sibling).st_dev, os.lstat(sibling).st_ino)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(str(socket_path))
                os.chmod(socket_path, 0o660)
            finally:
                listener.close()

            server = UnixBrokerServer(socket_path, mock.Mock())
            real_start = server.start
            started_calls: list[None] = []

            def started() -> None:
                self.assertFalse(
                    socket_path.exists(),
                    "lexical recovery must remove only the proven dead pathname",
                )
                real_start()
                started_calls.append(None)
                events.append("server-started")
                handlers[broker_cli_module.signal.SIGTERM](
                    broker_cli_module.signal.SIGTERM, None
                )

            server.start = mock.Mock(side_effect=started)

            class FakeRuntime:
                def __init__(self) -> None:
                    self.server = server
                    self.persistence = mock.Mock()
                    self.backend = mock.Mock()
                    self.begin_shutdown_calls = 0

                @staticmethod
                def fence_workers_on_startup() -> dict[str, object]:
                    return {
                        "ok": True,
                        "supervisor_epoch": "socket-reclaim-test",
                        "fenced_old_runners": [],
                        "started": [],
                        "errors": [],
                    }

                def begin_shutdown(self) -> int:
                    self.begin_shutdown_calls += 1
                    events.append("mutation-fenced")
                    return 1

                def close(self) -> None:
                    server.close()
                    events.append("runtime-closed")

            runtime = FakeRuntime()

            def install_handler(signum: int, handler: object) -> None:
                handlers[signum] = handler

            args = argparse.Namespace(
                access_group=None,
                database=str(root / "coordinator.sqlite3"),
                socket=str(socket_path),
                max_clients=4,
            )
            with (
                mock.patch.object(
                    broker_cli_module,
                    "build_store_backed_broker_runtime",
                    return_value=runtime,
                ),
                mock.patch.object(
                    broker_cli_module.signal,
                    "getsignal",
                    return_value=broker_cli_module.signal.SIG_DFL,
                ),
                mock.patch.object(
                    broker_cli_module.signal,
                    "signal",
                    side_effect=install_handler,
                ),
                mock.patch("builtins.print"),
            ):
                serve_broker(args, host_mutations_factory=mock.Mock)

            self.assertEqual(events, ["server-started", "mutation-fenced", "runtime-closed"])
            self.assertEqual(started_calls, [None])
            self.assertFalse(socket_path.exists())
            self.assertEqual(
                runtime_identity,
                (os.lstat(runtime_directory).st_dev, os.lstat(runtime_directory).st_ino),
            )
            self.assertEqual(
                sibling_identity,
                (os.lstat(sibling).st_dev, os.lstat(sibling).st_ino),
            )
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve sibling")

    def test_serve_lexical_recovery_failure_guards_leave_paths_untouched(self) -> None:
        with CanonicalTemporaryDirectory() as root:
            runtime_directory = root / "runtime"
            runtime_directory.mkdir(mode=0o750)
            os.chmod(runtime_directory, 0o750)

            def dead_socket(path: Path) -> None:
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    listener.bind(str(path))
                    os.chmod(path, 0o660)
                finally:
                    listener.close()

            def serve(path: Path, started: list[None]) -> None:
                handlers: dict[int, object] = {}
                server = UnixBrokerServer(path, mock.Mock())
                real_start = server.start

                def start_and_stop() -> None:
                    real_start()
                    started.append(None)
                    handlers[broker_cli_module.signal.SIGTERM](
                        broker_cli_module.signal.SIGTERM, None
                    )

                server.start = start_and_stop

                class Runtime:
                    def __init__(self) -> None:
                        self.server = server
                        self.persistence = mock.Mock()
                        self.backend = mock.Mock()

                    @staticmethod
                    def fence_workers_on_startup() -> dict[str, object]:
                        return {
                            "ok": True,
                            "supervisor_epoch": "socket-guard-test",
                            "fenced_old_runners": [],
                            "started": [],
                            "errors": [],
                        }

                    def begin_shutdown(self) -> int:
                        return 1

                    def close(self) -> None:
                        server.close()

                def install_handler(signum: int, handler: object) -> None:
                    handlers[signum] = handler

                args = argparse.Namespace(
                    access_group=None,
                    database=str(root / "coordinator.sqlite3"),
                    socket=str(path),
                    max_clients=4,
                )
                runtime = Runtime()
                with (
                    mock.patch.object(
                        broker_cli_module,
                        "build_store_backed_broker_runtime",
                        return_value=runtime,
                    ),
                    mock.patch.object(
                        broker_cli_module.signal,
                        "getsignal",
                        return_value=broker_cli_module.signal.SIG_DFL,
                    ),
                    mock.patch.object(
                        broker_cli_module.signal,
                        "signal",
                        side_effect=install_handler,
                    ),
                    mock.patch("builtins.print"),
                ):
                    serve_broker(args, host_mutations_factory=mock.Mock)

            live_path = runtime_directory / "live.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(str(live_path))
                os.chmod(live_path, 0o660)
                listener.listen(1)
                started: list[None] = []
                with self.assertRaises(BrokerError) as live:
                    serve(live_path, started)
                self.assertEqual(live.exception.code, "socket_path_exists")
                self.assertEqual(started, [])
                self.assertTrue(live_path.exists())
            finally:
                listener.close()
                os.unlink(live_path)

            wrong_type_path = runtime_directory / "operator-owned"
            wrong_type_path.write_text("operator-owned", encoding="utf-8")
            started = []
            with self.assertRaises(BrokerError) as wrong_type:
                serve(wrong_type_path, started)
            self.assertEqual(wrong_type.exception.code, "unsafe_socket_path")
            self.assertEqual(started, [])
            self.assertEqual(wrong_type_path.read_text(encoding="utf-8"), "operator-owned")

            race_path = runtime_directory / "race.sock"
            dead_socket(race_path)
            real_lstat = broker_cli_module.os.lstat
            socket_lstat_calls = 0

            def replace_before_recheck(path: str) -> os.stat_result:
                nonlocal socket_lstat_calls
                if Path(path) != race_path:
                    return real_lstat(path)
                socket_lstat_calls += 1
                if socket_lstat_calls != 2:
                    return real_lstat(path)
                os.unlink(race_path)
                dead_socket(race_path)
                replacement = real_lstat(race_path)
                values = list(replacement)
                values[1] = int(replacement.st_ino) + 1
                return os.stat_result(values)

            started = []
            with (
                mock.patch.object(
                    broker_cli_module.os,
                    "lstat",
                    side_effect=replace_before_recheck,
                ),
                self.assertRaises(BrokerError) as race,
            ):
                serve(race_path, started)
            self.assertEqual(race.exception.code, "socket_path_reclaim_unproven")
            self.assertEqual(started, [])
            self.assertTrue(race_path.exists())
            os.unlink(race_path)
    def test_compose_reconciliation_plan_is_read_only(self) -> None:
        args = argparse.Namespace(
            database="/service/coordinator.sqlite3",
            operation_id="operation-a",
            plan=True,
            abandon_as_failed=False,
            confirm_definition_fingerprint=None,
        )
        candidate = {
            "operation_id": "operation-a",
            "scope_recoverable": True,
            "target_fingerprint": "sha256:target",
        }
        with (
            mock.patch.object(dev_coordinator.os, "geteuid", return_value=0),
            mock.patch.object(
                dev_coordinator.BrokerPersistence,
                "inspect_compose_reconciliation_candidate",
                return_value=candidate,
            ) as inspect,
            mock.patch.object(
                dev_coordinator,
                "exclusive_broker_service_lock",
                side_effect=AssertionError("plan must not acquire service lock"),
            ),
        ):
            result = dev_coordinator.coordinated_broker_compose_reconcile(args)
        self.assertEqual(result["status"], "reconciliation_plan")
        self.assertFalse(result["mutated"])
        inspect.assert_called_once()

    def test_compose_reconciliation_evidence_and_offline_abandonment_are_distinct(
        self,
    ) -> None:
        base = {
            "database": "/service/coordinator.sqlite3",
            "operation_id": "operation-a",
            "plan": False,
        }
        persistence = mock.Mock()
        persistence.compose_reconciliation_candidate.return_value = {
            "host_id": "host-a",
            "scope_recoverable": True,
            "target_fingerprint": "sha256:target",
        }
        persistence.reconcile_compose_operation.return_value = {"status": "reconciled"}
        store_context = mock.MagicMock()
        store_context.__enter__.return_value = mock.Mock()
        store_context.__exit__.return_value = False
        evidence = {"snapshot_id": "new-snapshot"}
        with (
            mock.patch.object(dev_coordinator.os, "geteuid", return_value=0),
            mock.patch.object(
                dev_coordinator,
                "exclusive_broker_service_lock",
                return_value=mock.MagicMock(),
            ) as service_lock,
            mock.patch.object(
                dev_coordinator, "BrokerPersistence", return_value=persistence
            ),
            mock.patch.object(
                dev_coordinator.AccountStore, "open", return_value=store_context
            ),
            mock.patch.object(
                dev_coordinator,
                "capture_observation_freshness_fence",
                return_value=object(),
            ),
            mock.patch.object(
                dev_coordinator,
                "observe_broker_service_store_for_configuration",
                return_value={"snapshot_id": "new-snapshot", "joined": False},
            ),
            mock.patch.object(
                dev_coordinator,
                "require_exact_fresh_observation",
                return_value=evidence,
            ) as require_fresh,
        ):
            result = dev_coordinator.coordinated_broker_compose_reconcile(
                argparse.Namespace(
                    **base,
                    abandon_as_failed=False,
                    confirm_definition_fingerprint=None,
                )
            )
        self.assertEqual(result["administrator_uid"], 0)
        service_lock.assert_called_once()
        require_fresh.assert_called_once()
        persistence.reconcile_compose_operation.assert_called_once_with(
            "operation-a",
            evidence=evidence,
            abandon_as_failed=False,
            confirm_definition_fingerprint=None,
        )

        persistence.reset_mock()
        persistence.compose_reconciliation_candidate.return_value = {
            "host_id": "host-a",
            "scope_recoverable": False,
            "target_fingerprint": "sha256:target",
        }
        persistence.reconcile_compose_operation.return_value = {"status": "abandoned"}
        with (
            mock.patch.object(dev_coordinator.os, "geteuid", return_value=0),
            mock.patch.object(
                dev_coordinator,
                "exclusive_broker_service_lock",
                return_value=mock.MagicMock(),
            ),
            mock.patch.object(
                dev_coordinator, "BrokerPersistence", return_value=persistence
            ),
            mock.patch.object(
                dev_coordinator.AccountStore,
                "open",
                side_effect=AssertionError(
                    "offline abandonment must not observe Docker"
                ),
            ),
        ):
            dev_coordinator.coordinated_broker_compose_reconcile(
                argparse.Namespace(
                    **base,
                    abandon_as_failed=True,
                    confirm_definition_fingerprint="sha256:target",
                )
            )
        persistence.reconcile_compose_operation.assert_called_once_with(
            "operation-a",
            evidence=None,
            abandon_as_failed=True,
            confirm_definition_fingerprint="sha256:target",
        )

    def test_compose_abandonment_requires_exact_confirmation_argument(self) -> None:
        with (
            mock.patch.object(dev_coordinator.os, "geteuid", return_value=0),
            self.assertRaisesRegex(ValueError, "requires --confirm"),
        ):
            dev_coordinator.coordinated_broker_compose_reconcile(
                argparse.Namespace(
                    database="/service/coordinator.sqlite3",
                    operation_id="operation-a",
                    plan=False,
                    abandon_as_failed=True,
                    confirm_definition_fingerprint=None,
                )
            )

    def test_docker_reconciliation_parser_excludes_caller_supplied_evidence(
        self,
    ) -> None:
        value = parser()
        planned = value.parse_args(
            [
                "broker",
                "reconcile-docker",
                "--database",
                "/service/coordinator.sqlite3",
                "--operation-id",
                "operation-a",
                "--plan",
            ]
        )
        self.assertTrue(planned.plan)
        applied = value.parse_args(
            [
                "broker",
                "reconcile-docker",
                "--database",
                "/service/coordinator.sqlite3",
                "--operation-id",
                "operation-a",
                "--confirm-container-id",
                "a" * 64,
            ]
        )
        self.assertFalse(applied.plan)
        self.assertEqual(applied.confirm_container_id, "a" * 64)
        with self.assertRaises(SystemExit):
            value.parse_args(
                [
                    "broker",
                    "reconcile-docker",
                    "--database",
                    "/service/coordinator.sqlite3",
                    "--operation-id",
                    "operation-a",
                    "--observation-snapshot-id",
                    "caller-selected",
                ]
            )

    def test_docker_reconciliation_dispatches_only_to_offline_admin_path(
        self,
    ) -> None:
        args = dev_coordinator.build_parser().parse_args(
            [
                "broker",
                "reconcile-docker",
                "--database",
                "/service/coordinator.sqlite3",
                "--operation-id",
                "operation-a",
                "--plan",
            ]
        )
        expected = {"status": "reconciliation_plan", "mutated": False}
        with mock.patch.object(
            dev_coordinator,
            "coordinated_broker_docker_reconcile",
            return_value=expected,
        ) as reconcile:
            result = dev_coordinator.handle_cli(args)
        self.assertEqual(result, expected)
        reconcile.assert_called_once_with(args)

    def test_docker_reconciliation_plan_is_root_only_lock_free_and_read_only(
        self,
    ) -> None:
        args = argparse.Namespace(
            database="/service/coordinator.sqlite3",
            operation_id="operation-a",
            plan=True,
            confirm_container_id=None,
        )
        candidate = {
            "operation_id": "operation-a",
            "host_id": "host-a",
            "full_container_id": "a" * 64,
        }
        with (
            mock.patch.object(dev_coordinator.os, "geteuid", return_value=0),
            mock.patch.object(
                dev_coordinator.BrokerPersistence,
                "inspect_docker_reconciliation_candidate",
                return_value=candidate,
            ) as inspect,
            mock.patch.object(
                dev_coordinator,
                "exclusive_broker_service_lock",
                side_effect=AssertionError("plan must not acquire service lock"),
            ),
            mock.patch.object(
                dev_coordinator,
                "observe_broker_service_store_for_configuration",
                side_effect=AssertionError("plan must not observe Docker"),
            ),
        ):
            result = dev_coordinator.coordinated_broker_docker_reconcile(args)
        self.assertEqual(result["status"], "reconciliation_plan")
        self.assertFalse(result["mutated"])
        self.assertEqual(result["full_container_id"], "a" * 64)
        inspect.assert_called_once_with(
            Path("/service/coordinator.sqlite3"),
            operation_id="operation-a",
            expected_uid=0,
        )

    def test_docker_reconciliation_apply_uses_lock_and_new_exact_observation(
        self,
    ) -> None:
        container_id = "a" * 64
        args = argparse.Namespace(
            database="/service/coordinator.sqlite3",
            operation_id="operation-a",
            plan=False,
            confirm_container_id=container_id,
        )
        persistence = mock.Mock()
        persistence.docker_reconciliation_candidate.return_value = {
            "host_id": "host-a",
            "full_container_id": container_id,
        }
        persistence.reconcile_docker_operation.return_value = {
            "status": "reconciled"
        }
        store = mock.Mock()
        store_context = mock.MagicMock()
        store_context.__enter__.return_value = store
        store_context.__exit__.return_value = False
        fence = object()
        observed = {"snapshot_id": "snapshot-new", "joined": False}
        evidence = {
            "snapshot_id": "snapshot-new",
            "observer_domain": "host-runtime-v2:full-docker",
        }
        with (
            mock.patch.object(dev_coordinator.os, "geteuid", return_value=0),
            mock.patch.object(
                dev_coordinator,
                "exclusive_broker_service_lock",
                return_value=mock.MagicMock(),
            ) as service_lock,
            mock.patch.object(
                dev_coordinator, "BrokerPersistence", return_value=persistence
            ),
            mock.patch.object(
                dev_coordinator.AccountStore, "open", return_value=store_context
            ),
            mock.patch.object(
                dev_coordinator,
                "capture_observation_freshness_fence",
                return_value=fence,
            ) as capture_fence,
            mock.patch.object(
                dev_coordinator,
                "observe_broker_service_store_for_configuration",
                return_value=observed,
            ) as observe,
            mock.patch.object(
                dev_coordinator,
                "require_exact_fresh_observation",
                return_value=evidence,
            ) as require_fresh,
        ):
            result = dev_coordinator.coordinated_broker_docker_reconcile(args)
        self.assertEqual(result["status"], "reconciled")
        self.assertEqual(result["administrator_uid"], 0)
        service_lock.assert_called_once_with(Path("/service/coordinator.sqlite3"))
        persistence.docker_reconciliation_candidate.assert_called_once_with(
            "operation-a"
        )
        capture_fence.assert_called_once_with(store, host_id="host-a")
        observe.assert_called_once_with(store)
        require_fresh.assert_called_once_with(
            store,
            evidence=observed,
            fence=fence,
            allow_joined_ticket=False,
        )
        persistence.reconcile_docker_operation.assert_called_once_with(
            "operation-a",
            evidence=evidence,
            confirm_container_id=container_id,
        )

    def test_docker_reconciliation_rejects_nonroot_and_ambiguous_mode(self) -> None:
        base = {
            "database": "/service/coordinator.sqlite3",
            "operation_id": "operation-a",
        }
        with (
            mock.patch.object(dev_coordinator.os, "geteuid", return_value=1001),
            self.assertRaisesRegex(PermissionError, "root service administrator"),
        ):
            dev_coordinator.coordinated_broker_docker_reconcile(
                argparse.Namespace(
                    **base,
                    plan=True,
                    confirm_container_id=None,
                )
            )
        with (
            mock.patch.object(dev_coordinator.os, "geteuid", return_value=0),
            self.assertRaisesRegex(ValueError, "requires --confirm-container-id"),
        ):
            dev_coordinator.coordinated_broker_docker_reconcile(
                argparse.Namespace(
                    **base,
                    plan=False,
                    confirm_container_id=None,
                )
            )
        with (
            mock.patch.object(dev_coordinator.os, "geteuid", return_value=0),
            self.assertRaisesRegex(ValueError, "valid only when applying"),
        ):
            dev_coordinator.coordinated_broker_docker_reconcile(
                argparse.Namespace(
                    **base,
                    plan=True,
                    confirm_container_id="a" * 64,
                )
            )

    def test_client_wire_accepts_only_opaque_ids_and_typed_arguments(self) -> None:
        value = parser()
        args = value.parse_args(
            [
                "broker",
                "call",
                "--socket",
                "/run/devcoordinator-authority.sock",
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
        client_options: list[dict[str, object]] = []

        class FakeClient:
            def __init__(self, *_args: object, **kwargs: object) -> None:
                client_options.append(kwargs)

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
        self.assertEqual(client_options[0], {"timeout_seconds": 10.0})
        with self.assertRaises(SystemExit):
            value.parse_args(
                [
                    "broker",
                    "call",
                    "--socket",
                    "/run/devcoordinator-authority.sock",
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

    def test_low_level_ephemeral_call_requires_and_forwards_agent(self) -> None:
        value = parser()
        common = [
            "broker",
            "call",
            "--socket",
            "/run/devcoordinator-authority.sock",
            "--database-generation",
            "generation-a",
            "--project-id",
            "repo-id",
            "--resource-id",
            "template-id",
            "--operation",
            "ephemeral.start",
        ]
        missing_agent = value.parse_args(common)
        with self.assertRaisesRegex(ValueError, "require --agent"):
            handle_broker_cli(missing_agent)

        args = value.parse_args(
            [*common, "--agent", "codex-a", "--ttl-seconds", "900"]
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
                    "result": {"status": "running"},
                }

        with mock.patch("devcoordinator.broker_cli.BrokerClient", FakeClient):
            handle_broker_cli(args)
        self.assertEqual(
            calls[0].arguments,
            {"agent": "codex-a", "ttl_seconds": 900},
        )

    def test_docker_and_port_argument_families_do_not_cross(self) -> None:
        value = parser()
        docker = value.parse_args(
            [
                "broker",
                "call",
                "--socket",
                "/run/devcoordinator-authority.sock",
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

    def test_store_artifact_admin_commands_cover_account_and_service_roles(
        self,
    ) -> None:
        value = parser()
        commands = [
            (
                [
                    "broker",
                    "store-backup",
                    "--database",
                    "/stores/account.sqlite3",
                    "--store-role",
                    "account",
                    "--output-root",
                    "/backups/account",
                ],
                "create_store_backup",
                ("/stores/account.sqlite3", "/backups/account"),
                {"store_role": "account"},
            ),
            (
                [
                    "broker",
                    "store-export",
                    "--database",
                    "/stores/service.sqlite3",
                    "--store-role",
                    "service",
                    "--output-root",
                    "/backups/service",
                ],
                "create_store_export",
                ("/stores/service.sqlite3", "/backups/service"),
                {"store_role": "service"},
            ),
            (
                [
                    "broker",
                    "store-restore",
                    "--database",
                    "/stores/service.sqlite3",
                    "--store-role",
                    "service",
                    "--manifest",
                    "/backups/manifest.json",
                    "--safety-root",
                    "/backups/safety",
                    "--timeout-seconds",
                    "9",
                    "--confirm",
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
                    "broker",
                    "store-import",
                    "--database",
                    "/stores/account.sqlite3",
                    "--store-role",
                    "account",
                    "--manifest",
                    "/backups/export-manifest.json",
                    "--safety-root",
                    "/backups/safety",
                    "--confirm",
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
                    "broker",
                    "store-recover",
                    "--database",
                    "/stores/service.sqlite3",
                    "--store-role",
                    "service",
                    "--manifest",
                    "/backups/manifest.json",
                    "--forensic-root",
                    "/backups/forensic",
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
            with (
                self.subTest(action=raw[1]),
                mock.patch(
                    f"devcoordinator.broker_cli.{function_name}",
                    return_value={"status": "verified"},
                ) as operation,
            ):
                self.assertEqual(
                    handle_broker_cli(value.parse_args(raw))["status"], "verified"
                )
                operation.assert_called_once_with(*positional, **keywords)


if __name__ == "__main__":
    unittest.main()
