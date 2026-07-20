from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

from devcoordinator import broker_enrollment
from devcoordinator.broker import BrokerOperation
from devcoordinator.broker_cli import add_broker_parser, handle_broker_cli, serve_broker
import devcoordinator.broker_cli as broker_cli_module
from devcoordinator.lifecycle_cli import add_lifecycle_parsers
from devcoordinator.store import CoordinatorStore, utc_timestamp
import dev_coordinator


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    subparsers = value.add_subparsers(dest="group", required=True)
    add_lifecycle_parsers(subparsers)
    add_broker_parser(subparsers)
    return value


class LifecycleParserContractTests(unittest.TestCase):
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
                return_value={"available": True, "assets": []},
            ),
        ):
            observed = dev_coordinator.docker_ps_inventory()
        self.assertTrue(observed["available"])
        self.assertFalse(observed["container_inspection_available"])
        self.assertEqual(observed["containers"][0]["full_id"], full_id)
        self.assertFalse(observed["containers"][0]["inspection_observable"])

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

    def test_runtime_compose_project_name_reaches_broker_enrollment(self) -> None:
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

    def test_enrollment_preserves_env_profiles_and_grants_each_typed_compose_action(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".compose-enrollment-fields-", dir=str(Path.home().resolve())
        ) as raw_root:
            root = Path(raw_root).resolve()
            compose_file = root / "compose.yml"
            compose_file.write_text("services: {}\n", encoding="utf-8")
            env_file = root / "runtime.env"
            env_file.write_text("PRIVATE=value\n", encoding="utf-8")
            env_file.chmod(0o600)
            persistence = mock.Mock()

            compose_id = broker_enrollment._provision_compose(
                persistence,
                repo_id="repo-alpha",
                client_uid=501,
                root=root,
                compose={
                    "declared": True,
                    "files": [str(compose_file)],
                    "env_files": [str(env_file)],
                    "profiles": ["capture", "display"],
                    "services": ["collector", "api"],
                    "project_name": "alpha-stack",
                },
                observation_snapshot_id="snapshot-alpha",
            )

        self.assertIsNotNone(compose_id)
        provisioned = persistence.provision_compose_definition.call_args.kwargs
        self.assertEqual(provisioned["env_files"], (str(env_file),))
        self.assertEqual(provisioned["profiles"], ("capture", "display"))
        self.assertEqual(provisioned["services"], ("collector", "api"))
        self.assertEqual(provisioned["observation_snapshot_id"], "snapshot-alpha")
        persistence.replace_compose_access.assert_called_once_with(
            uid=501,
            repo_id="repo-alpha",
            compose_definition_id=compose_id,
        )
        persistence.grant_resource.assert_not_called()

    def test_enrollment_rejects_symlinked_compose_inputs_before_canonicalization(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".compose-enrollment-symlink-", dir=str(Path.home().resolve())
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
                broker_enrollment._provision_compose(
                    mock.Mock(),
                    repo_id="repo-alpha",
                    client_uid=501,
                    root=root,
                    compose={
                        "declared": True,
                        "files": [str(linked_compose)],
                        "env_files": [str(env_file)],
                        "services": ["api"],
                    },
                )

    def test_enrollment_never_falls_back_to_an_older_available_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".compose-enrollment-observation-", dir=str(Path.home().resolve())
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
                    broker_enrollment.capture_observation_freshness_fence(
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
                    broker_enrollment._require_exact_enrollment_observation(
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

                available_fence = broker_enrollment.capture_observation_freshness_fence(
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
                accepted = broker_enrollment._require_exact_enrollment_observation(
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

    def test_enrollment_waits_out_joined_ticket_then_requires_new_snapshot(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".compose-enrollment-joined-ticket-",
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

                accepted = broker_enrollment._capture_new_enrollment_observation(
                    store,
                    host_id="host-alpha",
                    observe_host=observe,
                )

        self.assertEqual(accepted, "new-ticket")
        self.assertEqual(calls, ["joined-ticket", "new-ticket"])

    def test_enrollment_rejects_old_ticket_after_unrelated_revision_advance(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".compose-enrollment-stale-ticket-",
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
                fence = broker_enrollment.capture_observation_freshness_fence(
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
                    broker_enrollment._require_exact_enrollment_observation(
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

    def test_production_cli_registers_lifecycle_and_broker_dispatch_groups(
        self,
    ) -> None:
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
                "broker",
                "enroll",
                "--database",
                "/service/coordinator.sqlite3",
                "--socket",
                "/run/devcoordinator/broker.sock",
                "--access-gid",
                "62000",
                "--client-uid",
                "501",
                "--account-id",
                "account-a",
                "--project",
                "/repo",
                "--agent",
                "codex-test",
                "--profile-output",
                "/etc/devcoordinator/profile.json",
            ]
        )
        compose = {
            "declared": True,
            "cwd": "/repo",
            "files": ["/repo/compose.yaml"],
            "env_files": ["/repo/runtime.env"],
            "profiles": ["capture"],
            "services": ["app"],
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
            mock.patch.object(
                dev_coordinator,
                "exclusive_broker_service_lock",
                return_value=mock.MagicMock(),
            ) as service_lock,
        ):
            result = dev_coordinator.handle_cli(args)

        self.assertEqual(result["status"], "enrolled")
        self.assertFalse(result["starts_resources"])
        call = enroll.call_args.kwargs
        self.assertEqual(call["servers"], [])
        self.assertEqual(call["allowed_server_names"], ())
        self.assertEqual(call["compose"], compose)
        self.assertFalse(call["approve_compose_host_access"])
        self.assertIs(
            call["observe_host"],
            dev_coordinator.observe_broker_service_store_for_enrollment,
        )
        service_lock.assert_called_once_with(Path("/service/coordinator.sqlite3"))

    def test_public_enrollment_refuses_a_live_broker_lifetime_lock(self) -> None:
        args = dev_coordinator.build_parser().parse_args(
            [
                "broker",
                "enroll",
                "--database",
                "/service/coordinator.sqlite3",
                "--socket",
                "/run/devcoordinator/broker.sock",
                "--access-gid",
                "62000",
                "--client-uid",
                "501",
                "--account-id",
                "account-a",
                "--project",
                "/repo",
                "--agent",
                "codex-test",
                "--profile-output",
                "/etc/devcoordinator/profile.json",
            ]
        )
        with (
            mock.patch.object(
                dev_coordinator, "canonical_project", return_value="/repo"
            ),
            mock.patch.object(
                dev_coordinator,
                "build_project_runtime_spec",
                return_value={"servers": [], "compose": None},
            ),
            mock.patch.object(
                dev_coordinator,
                "exclusive_broker_service_lock",
                side_effect=RuntimeError("broker service already holds lifetime lock"),
            ),
            mock.patch.object(dev_coordinator, "enroll_repository") as enroll,
            self.assertRaisesRegex(RuntimeError, "lifetime lock"),
        ):
            dev_coordinator.handle_cli(args)
        enroll.assert_not_called()

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
                "observe_broker_service_store_for_enrollment",
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
                "observe_broker_service_store_for_enrollment",
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


class BrokerCLIContractTests(unittest.TestCase):
    def test_sigterm_fences_mutations_before_serve_loop_poll(self) -> None:
        events: list[str] = []
        handlers: dict[int, object] = {}

        class FakeServer:
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
            def __init__(self) -> None:
                self.server = FakeServer()
                self.persistence = mock.Mock()
                self.fenced = False
                self.begin_shutdown_calls = 0

            def begin_shutdown(self) -> int:
                self.begin_shutdown_calls += 1
                self.fenced = True
                events.append("mutation-fenced")
                return 1

            def close(self) -> None:
                if not self.fenced:
                    raise AssertionError("runtime closed before mutation fence")
                events.append("runtime-closed")

        runtime = FakeRuntime()

        def install_handler(signum: int, handler: object) -> None:
            handlers[signum] = handler

        temporary = tempfile.TemporaryDirectory(
            prefix="devcoordinator-broker-signal-fence-"
        )
        self.addCleanup(temporary.cleanup)
        args = argparse.Namespace(
            access_group=None,
            access_gid=os.getegid(),
            database=str(Path(temporary.name) / "coordinator.sqlite3"),
            socket="/run/devcoordinator/broker.sock",
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

        self.assertEqual(
            events,
            ["server-started", "mutation-fenced", "runtime-closed"],
        )
        self.assertEqual(runtime.begin_shutdown_calls, 1)
        (
            runtime.persistence.recover_interrupted_compose_operations
        ).assert_called_once_with()
        (
            runtime.persistence.recover_interrupted_docker_operations
        ).assert_called_once_with()

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
                self.begin_shutdown_calls = 0

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
            access_gid=os.getegid(),
            database=str(Path(temporary.name) / "coordinator.sqlite3"),
            socket="/run/devcoordinator/broker.sock",
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
        self.assertEqual(
            events,
            [
                "server-started",
                "mutation-fenced",
                "drain-started",
                "drain-finished",
            ],
        )

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
                "observe_broker_service_store_for_enrollment",
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
                "observe_broker_service_store_for_enrollment",
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
                "observe_broker_service_store_for_enrollment",
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

    def test_admin_provisioning_names_the_service_owned_database_precondition(
        self,
    ) -> None:
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
