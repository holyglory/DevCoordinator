#!/usr/bin/env python3
"""Focused tests for the bounded clean-adoption helper.

These tests intentionally exercise only disposable offline state.  They do not
invoke systemd, a live broker, project processes, Docker, or project databases.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import clean_adopt_availability as subject


_AUTHORITY_SCHEMA_VERSION = 15
_TEST_STORE_SCHEMA_VERSION = 6
_INVENTORY_STORE_SCHEMA_VERSION = 1


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


class CleanAdoptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="clean-adoption-")
        self.root = Path(self.temporary.name).resolve()
        self.uid = os.geteuid()
        self.gid = os.getegid()
        self._fixture_index = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def manifest(self) -> dict[str, object]:
        self._fixture_index += 1
        fixture = self.root / f"fixture-{self._fixture_index}"
        repository = fixture / "repositories" / "console"
        repository.mkdir(parents=True)
        runtime_file = repository / ".codex" / "dev-runtime.json"
        _write_json(runtime_file, {"version": 1, "servers": {}})

        legacy_state = fixture / "legacy-console"
        for name in subject.CONSOLE_STATE_FILES:
            _write_json(legacy_state / name, {"source": name})

        state = fixture / "fresh-state"
        state.mkdir(mode=0o700)
        destinations = {
            name: str(state / f"{index:02d}-{name}")
            for index, name in enumerate(sorted(subject.DESTINATION_FIELDS))
        }
        return {
            "schema_version": subject.MANIFEST_VERSION,
            "kind": subject.MANIFEST_KIND,
            "release": "/opt/devcoordinator/releases/" + "a" * 64,
            "rendered_units": str(fixture / "rendered-units"),
            "candidate_slot_source": str(fixture / "console-slot"),
            "legacy_console_env": str(fixture / "console.env"),
            "legacy_console_state": str(legacy_state),
            "legacy_console_uid": max(self.uid, 1),
            "legacy_console_gid": max(self.gid, 1),
            "legacy_console_home": str(fixture / "console-home"),
            "background_project_root": str(repository),
            "console_state_files": list(subject.CONSOLE_STATE_FILES),
            "destinations": destinations,
            "ports": {
                "console_outer": 41001,
                "console_inner": 41002,
                "handoff_http": 41003,
                "handoff_https": 41004,
                "handoff_api": 41005,
            },
            "repositories": [
                {
                    "canonical_root": str(repository),
                    "runtime_file": str(runtime_file),
                    "port_range": "3100-3199",
                    "fixed_ports": [{"name": "web", "port": 3150}],
                    "approve_compose_host_access": True,
                    "compose_run_once_services": ["seed"],
                }
            ],
        }

    def validated(self) -> dict[str, object]:
        return subject.validate_manifest(
            self.manifest(), expected_uid=self.uid, current_uid=self.uid
        )

    def test_contract_names_exactly_four_retained_console_files(self) -> None:
        self.assertEqual(
            subject.CONSOLE_STATE_FILES,
            (
                "routes.json",
                "upstream-auth.json",
                "access-control.json",
                "telegram-control.json",
            ),
        )

    def test_valid_manifest_normalizes_host_wide_repository_routes(
        self,
    ) -> None:
        document = self.manifest()
        validated = subject.validate_manifest(
            document, expected_uid=self.uid, current_uid=self.uid
        )
        repository = validated["repositories"][0]
        self.assertEqual(
            repository["runtime_file"],
            str(Path(repository["canonical_root"]) / ".codex/dev-runtime.json"),
        )
        self.assertEqual(
            validated["ports"],
            {
                "console_inner": 41002,
                "console_outer": 41001,
                "handoff_api": 41005,
                "handoff_http": 41003,
                "handoff_https": 41004,
            },
        )
        self.assertEqual(repository["fixed_ports"], [{"name": "web", "port": 3150}])
        self.assertNotIn("clients", repository)
        self.assertNotIn("owner_uid", repository)

    def test_manifest_requires_exact_console_file_list_and_destination_set(self) -> None:
        mutations = (
            lambda document: document["console_state_files"].pop(),
            lambda document: document["console_state_files"].reverse(),
            lambda document: document["destinations"].pop("profile"),
            lambda document: document["destinations"].__setitem__(
                "unknown", str(self.root / "unknown")
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                document = self.manifest()
                mutation(document)
                with self.assertRaises(subject.CleanAdoptionError):
                    subject.validate_manifest(
                        document, expected_uid=self.uid, current_uid=self.uid
                    )

    def test_manifest_rejects_runtime_manifest_outside_repository(self) -> None:
        document = self.manifest()
        escaped = self.root / "outside-runtime.json"
        _write_json(escaped, {"version": 1, "servers": {}})
        document["repositories"][0]["runtime_file"] = str(escaped)
        with self.assertRaises(subject.CleanAdoptionError):
            subject.validate_manifest(
                document, expected_uid=self.uid, current_uid=self.uid
            )

    def test_manifest_rejects_duplicate_repository(self) -> None:
        def duplicate_repository(document: dict[str, object]) -> None:
            document["repositories"].append(copy.deepcopy(document["repositories"][0]))

        for mutation in (duplicate_repository,):
            with self.subTest(mutation=mutation.__name__):
                document = self.manifest()
                mutation(document)
                with self.assertRaises(subject.CleanAdoptionError):
                    subject.validate_manifest(
                        document, expected_uid=self.uid, current_uid=self.uid
                    )

    def test_legacy_reader_accepts_modes_without_a_permission_policy(self) -> None:
        for mode in (0o660, 0o640, 0o644, 0o400):
            with self.subTest(mode=oct(mode)):
                path = self.root / f"legacy-{mode:o}.json"
                path.write_bytes(b'{"retained":true}\n')
                path.chmod(mode)
                payload, evidence = subject._read_legacy_regular(
                    path,
                    expected_uid=self.uid + 100,
                    expected_gid=self.gid + 100,
                    maximum=1024,
                )
                self.assertEqual(payload, b'{"retained":true}\n')
                self.assertEqual(evidence["mode"], f"{mode:04o}")
                self.assertEqual(evidence["owner_uid"], self.uid)
                self.assertEqual(evidence["owner_gid"], self.gid)

    def test_fixed_ports_require_sorted_unique_assignments(self) -> None:
        mutations = (
            lambda repo: repo["fixed_ports"].append({"name": "api", "port": 3151}),
            lambda repo: repo["fixed_ports"].append({"name": "web2", "port": 3150}),
            lambda repo: repo["fixed_ports"].__setitem__(0, {"name": "web", "port": 9999}),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                document = self.manifest()
                mutation(document["repositories"][0])
                with self.assertRaises(subject.CleanAdoptionError):
                    subject.validate_manifest(
                        document, expected_uid=self.uid, current_uid=self.uid
                    )

    def test_static_console_instance_is_stopped_without_enabled_state_gate(self) -> None:
        class Runner:
            def __init__(self) -> None:
                self.status_calls = []

            def text(self, argv) -> str:
                self.asserted_argv = list(argv)
                return "loaded\n"

            def status(self, argv) -> int:
                command = list(argv)
                self.status_calls.append(command)
                if command[1] == "stop":
                    return 0
                if command[1:3] == ["is-active", "--quiet"]:
                    return 3
                raise AssertionError(f"unexpected systemctl call: {command}")

        runner = Runner()
        result = subject._stop_loaded_unit(
            runner,
            "devcoordinator-console@release.service",
            label="clean-adoption control-plane writer",
        )
        self.assertEqual(
            result,
            {
                "unit": "devcoordinator-console@release.service",
                "loaded": True,
                "stopped": True,
            },
        )
        self.assertEqual(
            runner.status_calls,
            [
                [
                    "/usr/bin/systemctl",
                    "stop",
                    "devcoordinator-console@release.service",
                ],
                [
                    "/usr/bin/systemctl",
                    "is-active",
                    "--quiet",
                    "devcoordinator-console@release.service",
                ],
            ],
        )

    def test_loaded_console_instances_are_discovered_across_release_retries(self) -> None:
        first = "a" * 64
        second = "b" * 64

        class Runner:
            def text(self, argv) -> str:
                self.argv = list(argv)
                return (
                    f"devcoordinator-console@{second}.service loaded inactive dead Console\n"
                    f"devcoordinator-console@{first}.service loaded active running Console\n"
                )

        runner = Runner()
        self.assertEqual(
            subject._loaded_console_units(runner),
            (
                f"devcoordinator-console@{first}.service",
                f"devcoordinator-console@{second}.service",
            ),
        )
        self.assertEqual(
            runner.argv,
            [
                "/usr/bin/systemctl",
                "list-units",
                "--all",
                "--type=service",
                "--plain",
                "--no-legend",
                "--full",
                "--no-pager",
                "devcoordinator-console@*.service",
            ],
        )

    def test_loaded_console_instance_discovery_rejects_unsealed_names(self) -> None:
        class Runner:
            def text(self, argv) -> str:
                return "devcoordinator-console@current.service loaded active running Console\n"

        with self.assertRaisesRegex(
            subject.CleanAdoptionError,
            "invalid immutable identity",
        ):
            subject._loaded_console_units(Runner())

    def test_control_plane_graph_is_disabled_before_one_batched_stop(self) -> None:
        service = "devcoordinator-edge.service"
        socket = "devcoordinator-edge-http.socket"
        console = f"devcoordinator-console@{'a' * 64}.service"

        class Runner:
            def __init__(self) -> None:
                self.disabled = []
                self.stop_calls = []

            def text(self, argv) -> str:
                return "loaded\n"

            def status(self, argv) -> int:
                command = list(argv)
                action = command[1]
                if action == "disable":
                    self.disabled.append(command[2])
                    return 0
                if action == "stop":
                    if set(self.disabled) != {service, socket}:
                        raise AssertionError("graph was stopped before every ordinary unit was disabled")
                    self.stop_calls.append(command[2:])
                    return 0
                if action == "is-active":
                    return 3
                if action == "is-enabled":
                    return 1
                raise AssertionError(f"unexpected systemctl call: {command}")

        runner = Runner()
        result = subject._stop_loaded_units(
            runner,
            (service, socket, console),
            label="clean-adoption control-plane writer",
        )
        self.assertEqual(runner.disabled, [service, socket])
        self.assertEqual(runner.stop_calls, [[service, socket, console]])
        self.assertEqual(
            result,
            [
                {"unit": service, "loaded": True, "stopped": True},
                {"unit": socket, "loaded": True, "stopped": True},
                {"unit": console, "loaded": True, "stopped": True},
            ],
        )

    def test_disposable_rotation_moves_test_store_and_attempt_spool_together(self) -> None:
        manifest = self.validated()
        test_database = Path(manifest["destinations"]["test_database"])
        test_database.write_bytes(b"disposable-test-store")
        test_database.chmod(0o600)
        wal = Path(f"{test_database}-wal")
        wal.write_bytes(b"disposable-wal")
        wal.chmod(0o600)
        spool = test_database.parent / "spool"
        active = spool / "active"
        active.mkdir(parents=True, mode=0o700)
        stale_attempt = active / ("a" * 64 + ".json")
        stale_attempt.write_text("stale-attempt\n", encoding="utf-8")
        stale_attempt.chmod(0o600)

        result = subject._rotate_disposable_state(
            manifest,
            transaction_root=self.root / "rotation-transaction",
        )

        moved = result["moved"]
        self.assertEqual(
            set(moved),
            {str(test_database), str(wal), str(spool)},
        )
        self.assertFalse(test_database.exists())
        self.assertFalse(wal.exists())
        self.assertFalse(spool.exists())
        self.assertEqual(
            Path(moved[str(test_database)]).read_bytes(), b"disposable-test-store"
        )
        self.assertEqual(Path(moved[str(wal)]).read_bytes(), b"disposable-wal")
        self.assertEqual(
            (Path(moved[str(spool)]) / "active" / stale_attempt.name).read_text(
                encoding="utf-8"
            ),
            "stale-attempt\n",
        )
        self.assertFalse(result["project_storage_mutated"])

    def test_initialize_fresh_stores_refuses_existing_or_symlinked_output(self) -> None:
        for name in (
            "authority_database",
            "test_database",
            "inventory_database",
            "inventory_publication",
        ):
            with self.subTest(name=name, kind="file"):
                validated = self.validated()
                plan = subject.fresh_store_plan(validated)
                Path(plan[name]).write_bytes(b"occupied")
                with self.assertRaises(subject.CleanAdoptionError):
                    subject.initialize_fresh_stores(
                        plan, current_uid=self.uid, expected_uid=self.uid
                    )
            with self.subTest(name=name, kind="symlink"):
                validated = self.validated()
                plan = subject.fresh_store_plan(validated)
                Path(plan[name]).symlink_to(self.root / "missing-target")
                with self.assertRaises(subject.CleanAdoptionError):
                    subject.initialize_fresh_stores(
                        plan, current_uid=self.uid, expected_uid=self.uid
                    )

    def test_initialize_fresh_stores_creates_only_current_private_schemas(self) -> None:
        validated = self.validated()
        plan = subject.fresh_store_plan(validated)
        result = subject.initialize_fresh_stores(
            plan, current_uid=self.uid, expected_uid=self.uid
        )
        self.assertEqual(result["ok"], True)
        self.assertEqual(result["authority_schema_version"], _AUTHORITY_SCHEMA_VERSION)
        self.assertEqual(result["test_schema_version"], _TEST_STORE_SCHEMA_VERSION)
        self.assertEqual(result["inventory_generation"], 1)

        for name in (
            "authority_database",
            "test_database",
            "inventory_database",
            "inventory_publication",
        ):
            path = Path(plan[name])
            metadata = path.lstat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
            self.assertEqual(metadata.st_uid, self.uid)

        with sqlite3.connect(plan["authority_database"]) as connection:
            version, migration_state = connection.execute(
                "SELECT schema_version,migration_state FROM schema_metadata WHERE singleton = 1"
            ).fetchone()
            self.assertEqual(version, _AUTHORITY_SCHEMA_VERSION)
            self.assertEqual(migration_state, "ready")
        with sqlite3.connect(plan["test_database"]) as connection:
            version = connection.execute(
                "SELECT schema_version FROM test_store_metadata WHERE singleton = 1"
            ).fetchone()[0]
            self.assertEqual(version, _TEST_STORE_SCHEMA_VERSION)
        with sqlite3.connect(plan["inventory_database"]) as connection:
            version = connection.execute(
                "SELECT schema_version FROM inventory_store_metadata WHERE singleton = 1"
            ).fetchone()[0]
            self.assertEqual(version, _INVENTORY_STORE_SCHEMA_VERSION)

    def test_initialize_rejects_uid_mismatch_before_writing(self) -> None:
        validated = self.validated()
        plan = subject.fresh_store_plan(validated)
        with self.assertRaises(subject.CleanAdoptionError):
            subject.initialize_fresh_stores(
                plan, current_uid=self.uid + 1, expected_uid=self.uid
            )
        for name in (
            "authority_database",
            "test_database",
            "inventory_database",
            "inventory_publication",
        ):
            self.assertFalse(Path(plan[name]).exists())

    def test_final_health_gate_requires_inventory_and_store_contracts(self) -> None:
        manifest = self.validated()
        repository = manifest["repositories"][0]
        repo_id = "repo-clean-adoption"
        test_database = Path(manifest["destinations"]["test_database"])
        test_database.parent.mkdir(parents=True, exist_ok=True)
        test_database.write_bytes(b"test-store")
        test_database.chmod(0o600)
        env = self.root / "staged-console.env"
        env.write_text("DOMAIN=vr.ae\n", encoding="utf-8")
        env.chmod(0o600)

        class Runner:
            commands: list[list[str]] = []

            def status(self, _argv: list[str]) -> int:
                return 0

            def text(self, argv: list[str]) -> str:
                self.commands.append(argv)
                return json.dumps(
                    {
                        "schema_version": 2,
                        "repositories": [
                            {
                                "canonical_root": repository["canonical_root"],
                                "repo_id": repo_id,
                            }
                        ],
                    }
                )

        authority_connection = mock.Mock()
        authority_connection.execute.return_value.fetchone.return_value = (15, "ready")
        authority_store = mock.Mock(connection=authority_connection)
        runner = Runner()
        test_plane_result = {
            "status": "ready",
            "schema_version": 1,
            "test_store_schema_version": 6,
            "store_generation": "store-generation",
            "repository_count": 1,
            "setup_repository_id": repo_id,
            "setup_retained": True,
        }
        with (
            mock.patch.object(subject.AccountStore, "open", return_value=authority_store),
            mock.patch.object(
                subject,
                "verify_inventory_store",
                return_value={"generation": 1},
            ),
            mock.patch.object(
                subject,
                "_test_plane_application_canary",
                return_value=test_plane_result,
            ) as test_plane_canary,
            mock.patch.object(subject.activation, "_probe_local_api", return_value=200),
            mock.patch.object(subject.activation, "_probe_url", return_value=(200, False)),
            mock.patch.object(subject, "_console_domain", return_value="vr.ae"),
        ):
            result = subject._final_health_gate(
                manifest,
                staged_legacy_env=env,
                maintenance_deployment_id="8060e625-ae47-432e-be09-5b01f449cdd8",
                expected_repository_ids={repository["canonical_root"]: repo_id},
                observer_uid=self.uid,
                testd_uid=self.uid,
                canary_uid=max(self.uid, 1),
                canary_gid=max(self.gid, 1),
                runner=runner,
            )
        self.assertEqual(result["inventory_canaries"][0]["repo_id"], repo_id)
        self.assertEqual(
            {item["caller_uid"] for item in result["inventory_canaries"]},
            {max(self.uid, 1)},
        )
        self.assertEqual(result["test_catalog"]["repository_count"], 1)
        self.assertEqual(result["test_catalog"]["status"], "pending-maintenance-clear")
        self.assertEqual(result["test_plane"], test_plane_result)
        test_plane_canary.assert_called_once_with(
            {repository["canonical_root"]: repo_id},
            setup_repository_id=repo_id,
            setup_execution_uid=max(self.uid, 1),
        )
        canary = runner.commands[0]
        self.assertIn(
            "DEVCOORDINATOR_MAINTENANCE_DEPLOYMENT_ID="
            "8060e625-ae47-432e-be09-5b01f449cdd8",
            canary,
        )
        self.assertEqual(canary[-5:], ["inventory", "--project", repository["canonical_root"], "--no-docker", "--compact-json"])
        self.assertEqual(len(runner.commands), 1)

    def test_test_plane_application_canary_proves_setup_write_and_retention(self) -> None:
        repository_ids = {
            "/home/example/one": "repo-one",
            "/home/example/two": "repo-two",
        }

        class Plane:
            def __init__(self) -> None:
                self.setup_arguments = None
                self.catalog_arguments = None

            def health(self):
                return {
                    "schema_version": 1,
                    "status": "ok",
                    "test_store_schema_version": 6,
                    "store_generation": "fresh-store-generation",
                }

            def setup(self, **arguments):
                self.setup_arguments = arguments
                return {
                    "schema_version": 1,
                    "repository_id": "repo-one",
                    "status": "ready",
                    "ok": True,
                }

            def repository_catalog(self, **arguments):
                self.catalog_arguments = arguments
                return {
                    "schema_version": 1,
                    "repositories": [
                        {
                            "repository_id": "repo-one",
                            "setup_status": "ready",
                            "retained": True,
                        },
                        {
                            "repository_id": "repo-two",
                            "setup_status": "missing",
                            "retained": False,
                        },
                    ],
                }

        plane = Plane()
        socket_path = self.root / "testd.sock"
        with mock.patch.object(
            subject,
            "UnixTestPlaneClient",
            return_value=plane,
        ) as client:
            result = subject._test_plane_application_canary(
                repository_ids,
                setup_repository_id="repo-one",
                setup_execution_uid=max(self.uid, 1),
                socket_path=socket_path,
            )
        client.assert_called_once_with(
            socket_path,
            expected_server_uid=subject.TEST_PLANE_SOCKET_OWNER_UID,
            timeout_seconds=30,
        )
        self.assertEqual(
            plane.setup_arguments,
            {"repository_id": "repo-one", "owner_uid": max(self.uid, 1)},
        )
        self.assertEqual(
            plane.catalog_arguments,
            {"repository_ids": ("repo-one", "repo-two")},
        )
        self.assertEqual(result["status"], "ready")
        self.assertTrue(result["setup_retained"])

    def test_test_plane_application_canary_rejects_scheduler_setup_failure(self) -> None:
        class Plane:
            def health(self):
                return {
                    "schema_version": 1,
                    "status": "ok",
                    "test_store_schema_version": 6,
                    "store_generation": "fresh-store-generation",
                }

            def setup(self, **_arguments):
                raise subject.TestPlaneTransportError(
                    "invalid_request", "unable to open database file"
                )

        with (
            mock.patch.object(
                subject,
                "UnixTestPlaneClient",
                return_value=Plane(),
            ),
            self.assertRaisesRegex(
                subject.CleanAdoptionError,
                "test-plane application canary failed: invalid_request",
            ),
        ):
            subject._test_plane_application_canary(
                {"/home/example": "repo-one"},
                setup_repository_id="repo-one",
                setup_execution_uid=max(self.uid, 1),
                socket_path=self.root / "testd.sock",
            )

    def test_tests_catalog_api_canary_runs_after_maintenance_contract(self) -> None:
        repository_id = "repo-catalog-ready"

        class Response:
            def __init__(self, payload: dict[str, object], *, status: int = 200) -> None:
                self.status = status
                self.payload = payload

            def read(self, _maximum: int) -> bytes:
                return json.dumps(self.payload).encode("utf-8")

        class Connection:
            def __init__(self, response: Response) -> None:
                self.response = response

            def request(self, method, path, *, headers) -> None:
                self.request_value = (method, path, headers)

            def getresponse(self) -> Response:
                return self.response

            def close(self) -> None:
                self.closed = True

        catalog_connection = Connection(
            Response(
                {
                    "schema_version": 1,
                    "repositories": [
                        {
                            "repo_id": repository_id,
                            "setup_status": "missing",
                        }
                    ],
                }
            )
        )
        setup_connection = Connection(
            Response(
                {
                    "schema_version": 1,
                    "repository_id": repository_id,
                    "status": "ready",
                    "ok": True,
                }
            )
        )
        retained_catalog_connection = Connection(
            Response(
                {
                    "schema_version": 1,
                    "repositories": [
                        {
                            "repo_id": repository_id,
                            "setup_status": "ready",
                            "setup_retained": True,
                        }
                    ],
                }
            )
        )
        with mock.patch.object(
            subject.http.client,
            "HTTPConnection",
            side_effect=[
                catalog_connection,
                setup_connection,
                retained_catalog_connection,
            ],
        ):
            result = subject._tests_catalog_api_canary(
                {"/home/example": repository_id},
                setup_repository_id=repository_id,
            )
        self.assertEqual(
            result,
            {
                "status": 200,
                "repository_count": 1,
                "schema_version": 1,
                "setup": {
                    "attempts": 1,
                    "ok": True,
                    "repository_id": repository_id,
                    "retained": True,
                    "schema_version": 1,
                    "status": "ready",
                },
            },
        )
        self.assertEqual(
            catalog_connection.request_value,
            ("GET", "/v1/test-repositories", {"Host": "127.0.0.1"}),
        )
        self.assertEqual(
            setup_connection.request_value,
            (
                "GET",
                f"/v1/test-repositories/{repository_id}/setup",
                {"Host": "127.0.0.1"},
            ),
        )
        self.assertTrue(catalog_connection.closed)
        self.assertTrue(setup_connection.closed)
        self.assertEqual(
            retained_catalog_connection.request_value,
            ("GET", "/v1/test-repositories", {"Host": "127.0.0.1"}),
        )
        self.assertTrue(retained_catalog_connection.closed)

    def test_tests_catalog_api_canary_retries_only_typed_setup_cold_start(self) -> None:
        repository_id = "repo-catalog-ready"

        class Response:
            def __init__(self, status: int, payload: dict[str, object]) -> None:
                self.status = status
                self.payload = payload

            def read(self, _maximum: int) -> bytes:
                return json.dumps(self.payload).encode("utf-8")

        class Connection:
            def __init__(self, response: Response) -> None:
                self.response = response

            def request(self, method, path, *, headers) -> None:
                self.request_value = (method, path, headers)

            def getresponse(self) -> Response:
                return self.response

            def close(self) -> None:
                self.closed = True

        connections = [
            Connection(
                Response(
                    200,
                    {
                        "schema_version": 1,
                        "repositories": [
                            {
                                "repo_id": repository_id,
                                "setup_status": "missing",
                            }
                        ],
                    },
                )
            ),
            Connection(
                Response(
                    502,
                    {
                        "code": "test_repository_setup_unavailable",
                        "retry_after_seconds": 2,
                    },
                )
            ),
            Connection(
                Response(
                    200,
                    {
                        "schema_version": 1,
                        "repository_id": repository_id,
                        "status": "ready",
                        "ok": True,
                    },
                )
            ),
            Connection(
                Response(
                    200,
                    {
                        "schema_version": 1,
                        "repositories": [
                            {
                                "repo_id": repository_id,
                                "setup_status": "ready",
                                "setup_retained": True,
                            }
                        ],
                    },
                )
            ),
        ]
        with (
            mock.patch.object(
                subject.http.client,
                "HTTPConnection",
                side_effect=connections,
            ),
            mock.patch.object(subject.time, "sleep") as sleep,
        ):
            result = subject._tests_catalog_api_canary(
                {"/home/example": repository_id},
                setup_repository_id=repository_id,
            )
        self.assertEqual(result["setup"]["attempts"], 2)
        self.assertEqual(
            [call.args for call in sleep.call_args_list],
            [(2,)],
        )
        self.assertTrue(all(connection.closed for connection in connections))

    def test_tests_catalog_api_canary_does_not_retry_scheduler_unavailable(self) -> None:
        repository_id = "repo-catalog-ready"

        class Response:
            def __init__(self, status: int, payload: dict[str, object]) -> None:
                self.status = status
                self.payload = payload

            def read(self, _maximum: int) -> bytes:
                return json.dumps(self.payload).encode("utf-8")

        class Connection:
            def __init__(self, response: Response) -> None:
                self.response = response

            def request(self, method, path, *, headers) -> None:
                self.request_value = (method, path, headers)

            def getresponse(self) -> Response:
                return self.response

            def close(self) -> None:
                self.closed = True

        connections = [
            Connection(
                Response(
                    200,
                    {
                        "schema_version": 1,
                        "repositories": [
                            {
                                "repo_id": repository_id,
                                "setup_status": "missing",
                            }
                        ],
                    },
                )
            ),
            Connection(
                Response(
                    503,
                    {
                        "code": "test_scheduler_unavailable",
                        "retry_after_seconds": 2,
                    },
                )
            ),
        ]
        with (
            mock.patch.object(
                subject.http.client,
                "HTTPConnection",
                side_effect=connections,
            ) as connection_factory,
            mock.patch.object(subject.time, "sleep") as sleep,
            self.assertRaisesRegex(
                subject.CleanAdoptionError,
                "Tests repository setup API canary failed",
            ),
        ):
            subject._tests_catalog_api_canary(
                {"/home/example": repository_id},
                setup_repository_id=repository_id,
            )
        self.assertEqual(connection_factory.call_count, 2)
        sleep.assert_not_called()
        self.assertTrue(all(connection.closed for connection in connections))

    def test_tests_catalog_api_canary_covers_one_minute_cold_start(self) -> None:
        repository_id = "repo-catalog-cold"

        class Response:
            def __init__(self, status: int, payload: dict[str, object]) -> None:
                self.status = status
                self.payload = payload

            def read(self, _maximum: int) -> bytes:
                return json.dumps(self.payload).encode("utf-8")

        class Connection:
            def __init__(self, response: Response) -> None:
                self.response = response

            def request(self, method, path, *, headers) -> None:
                self.request_value = (method, path, headers)

            def getresponse(self) -> Response:
                return self.response

            def close(self) -> None:
                self.closed = True

        catalog = {
            "schema_version": 1,
            "repositories": [
                {"repo_id": repository_id, "setup_status": "missing"}
            ],
        }
        retained = {
            "schema_version": 1,
            "repositories": [
                {
                    "repo_id": repository_id,
                    "setup_status": "ready",
                    "setup_retained": True,
                }
            ],
        }
        connections = [Connection(Response(200, catalog))]
        connections.extend(
            Connection(
                Response(503, {"code": "test_repository_setup_unavailable"})
            )
            for _ in range(subject.TEST_SETUP_CANARY_ATTEMPTS - 1)
        )
        connections.extend(
            [
                Connection(
                    Response(
                        200,
                        {
                            "schema_version": 1,
                            "repository_id": repository_id,
                            "status": "ready",
                            "ok": True,
                        },
                    )
                ),
                Connection(Response(200, retained)),
            ]
        )
        with (
            mock.patch.object(
                subject.http.client,
                "HTTPConnection",
                side_effect=connections,
            ),
            mock.patch.object(subject.time, "sleep") as sleep,
        ):
            result = subject._tests_catalog_api_canary(
                {"/home/example": repository_id},
                setup_repository_id=repository_id,
            )
        self.assertEqual(
            result["setup"]["attempts"],
            subject.TEST_SETUP_CANARY_ATTEMPTS,
        )
        self.assertGreaterEqual(
            sum(call.args[0] for call in sleep.call_args_list),
            60,
        )

    def test_completed_apply_replay_does_not_reopen_rotated_sources(self) -> None:
        document = self.manifest()
        normalized = subject.validate_manifest(document, current_uid=0)
        manifest_sha = subject.hashlib.sha256(
            subject._canonical(normalized)
        ).hexdigest()
        completed = {
            "manifest_sha256": manifest_sha,
            "phase": "complete",
        }
        transaction_root = self.root / "completed-transaction"
        journal = transaction_root / "journal.json"
        with (
            mock.patch.object(subject.os, "geteuid", return_value=0),
            mock.patch.object(
                Path,
                "lstat",
                return_value=SimpleNamespace(st_uid=0),
            ),
            mock.patch.object(subject, "_read_journal", return_value=completed),
            mock.patch.object(subject, "plan_adoption") as plan,
            mock.patch.object(subject.installer, "verify_release") as verify_release,
        ):
            self.assertIs(
                subject.apply_adoption(
                    document,
                    transaction_root=transaction_root,
                    journal_file=journal,
                    expected_uid=0,
                ),
                completed,
            )
        plan.assert_not_called()
        verify_release.assert_called_once_with(Path(document["release"]))

    def test_tests_catalog_api_canary_does_not_retry_untyped_setup_failure(self) -> None:
        repository_id = "repo-catalog-ready"

        class Response:
            def __init__(self, status: int, payload: dict[str, object]) -> None:
                self.status = status
                self.payload = payload

            def read(self, _maximum: int) -> bytes:
                return json.dumps(self.payload).encode("utf-8")

        class Connection:
            def __init__(self, response: Response) -> None:
                self.response = response

            def request(self, method, path, *, headers) -> None:
                self.request_value = (method, path, headers)

            def getresponse(self) -> Response:
                return self.response

            def close(self) -> None:
                self.closed = True

        connections = [
            Connection(
                Response(
                    200,
                    {
                        "schema_version": 1,
                        "repositories": [
                            {
                                "repo_id": repository_id,
                                "setup_status": "missing",
                            }
                        ],
                    },
                )
            ),
            Connection(Response(503, {"code": "unrelated_failure"})),
        ]
        with (
            mock.patch.object(
                subject.http.client,
                "HTTPConnection",
                side_effect=connections,
            ) as connection_factory,
            mock.patch.object(subject.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(
                subject.CleanAdoptionError,
                "Tests repository setup API canary failed",
            ):
                subject._tests_catalog_api_canary(
                    {"/home/example": repository_id},
                    setup_repository_id=repository_id,
                )
        self.assertEqual(connection_factory.call_count, 2)
        sleep.assert_not_called()

    def test_maintenance_boundary_allows_exact_post_clear_resume(self) -> None:
        deployment_id = "8060e625-ae47-432e-be09-5b01f449cdd8"
        current = {
            "phase": "post_maintenance_api_ready",
            "steps": {
                "health_verified": {"ok": True},
                "maintenance_cleared": {
                    "active": False,
                    "deployment_id": deployment_id,
                    "cleared": True,
                },
                "post_maintenance_api_ready": {"status": 200},
            },
        }
        self.assertIsNone(
            subject._maintenance_boundary_recovery(
                current,
                maintenance_record={"deployment_id": deployment_id},
                active_maintenance=None,
            )
        )
        with self.assertRaisesRegex(
            subject.CleanAdoptionError,
            "maintenance clear record changed",
        ):
            subject._maintenance_boundary_recovery(
                current,
                maintenance_record={"deployment_id": deployment_id},
                active_maintenance=SimpleNamespace(deployment_id=deployment_id),
            )

    def test_maintenance_boundary_recovers_only_the_post_health_clear_crash(self) -> None:
        deployment_id = "8060e625-ae47-432e-be09-5b01f449cdd8"
        recovered = subject._maintenance_boundary_recovery(
            {
                "phase": "health_verified",
                "steps": {"health_verified": {"ok": True}},
            },
            maintenance_record={"deployment_id": deployment_id},
            active_maintenance=None,
        )
        self.assertEqual(
            recovered,
            {
                "active": False,
                "deployment_id": deployment_id,
                "cleared": False,
                "recovered_absence": True,
            },
        )
        self.assertIsNone(
            subject._maintenance_boundary_recovery(
                {
                    "phase": "maintenance_cleared",
                    "steps": {
                        "health_verified": {"ok": True},
                        "maintenance_cleared": recovered,
                    },
                },
                maintenance_record={"deployment_id": deployment_id},
                active_maintenance=None,
            )
        )
        for phase, steps in (
            ("maintenance", {"maintenance": {"active": True}}),
            ("public_ready", {"public_ready": {"ok": True}}),
        ):
            with self.subTest(phase=phase):
                with self.assertRaisesRegex(
                    subject.CleanAdoptionError,
                    "maintenance fence changed",
                ):
                    subject._maintenance_boundary_recovery(
                        {"phase": phase, "steps": steps},
                        maintenance_record={"deployment_id": deployment_id},
                        active_maintenance=None,
                    )

    def test_apply_orders_offline_fixed_ports_before_authority_start(self) -> None:
        source = Path(subject.__file__).read_text(encoding="utf-8")
        fixed = source.index('if not done("fixed_ports"):', source.index("def apply_adoption"))
        authority = source.index('if not done("authority_ready"):', fixed)
        self.assertLess(fixed, authority)
        segment = source[fixed:authority]
        self.assertIn("replay_fixed_ports_offline", segment)
        self.assertNotIn("command.run_json", segment)
        route = source.index('if not done("route_resolution"):', authority)
        readiness = source[authority:route]
        self.assertLess(
            readiness.index("_start_units"),
            readiness.index("_wait_for_authority_application"),
        )
        self.assertLess(
            readiness.index("_wait_for_authority_application"),
            readiness.index('advance(\n                "authority_ready"'),
        )
        maintenance_cleared = source.index(
            'if not done("maintenance_cleared"):', route
        )
        post_maintenance = source.index(
            'if not done("post_maintenance_api_ready"):', maintenance_cleared
        )
        complete = source.index('if not done("complete"):', post_maintenance)
        self.assertLess(maintenance_cleared, post_maintenance)
        self.assertLess(post_maintenance, complete)

    def test_apply_uses_root_maintenance_identity_without_shared_group(self) -> None:
        source = Path(subject.__file__).read_text(encoding="utf-8")
        start = source.index("def apply_adoption(")
        end = source.index("\ndef _parser(", start)
        apply_source = source[start:end]
        self.assertIn("maintenance_gid = 0", apply_source)
        self.assertIn("expected_gid=maintenance_gid", apply_source)
        self.assertNotIn("clients_gid", apply_source)
        self.assertNotIn("devcoordinator-clients", apply_source)
        self.assertNotIn('groups["devcoordinator-clients"]', apply_source)

    def test_clean_adoption_normalizes_the_legacy_maintenance_directory(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            maintenance = root / "maintenance"
            maintenance.mkdir(mode=0o750)
            marker = maintenance / "maintenance.json"
            marker.write_text("{}\n", encoding="utf-8")
            marker.chmod(0o640)

            result = subject._normalize_maintenance_root(
                maintenance,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
            )

            self.assertEqual(stat.S_IMODE(maintenance.lstat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(marker.lstat().st_mode), 0o644)
            self.assertEqual(result["mode"], "0755")
            self.assertEqual(result["marker_mode"], "0644")
            self.assertFalse(result["created"])

            marker.unlink()
            maintenance.rmdir()
            maintenance.symlink_to(root)
            with self.assertRaisesRegex(
                subject.CleanAdoptionError, "owned real directory"
            ):
                subject._normalize_maintenance_root(
                    maintenance,
                    expected_uid=os.geteuid(),
                    expected_gid=os.getegid(),
                )

    def test_route_state_parents_are_bootstrapped_privately(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = {
                "destinations": {
                    "route_resolution": str(root / "routing" / "route-resolution.json"),
                    "publication_input": str(root / "routing" / "publication-input.json"),
                }
            }

            result = subject._prepare_route_state_parents(
                manifest, expected_uid=os.geteuid()
            )

            parent = root / "routing"
            self.assertEqual(result, {"private_parents": [str(parent)]})
            self.assertTrue(parent.is_dir())
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o700)

    def test_authority_readiness_requires_trusted_local_application_response(self) -> None:
        manifest = self.validated()
        repository = manifest["repositories"][0]
        repository_id = "repo-application-ready"

        class Runner:
            def __init__(self) -> None:
                self.status_calls = 0
                self.text_calls = 0
                self.command: list[str] | None = None

            def status(self, argv: list[str]) -> int:
                self.status_calls += 1
                self.asserted_status = list(argv)
                return 0

            def text(self, argv: list[str]) -> str:
                self.text_calls += 1
                self.command = list(argv)
                if self.text_calls < 3:
                    raise subject.activation.ActivationError(
                        "authority accepted a systemd start but is not serving"
                    )
                return json.dumps(
                    {
                        "schema_version": 2,
                        "repositories": [
                            {
                                "canonical_root": repository["canonical_root"],
                                "repo_id": repository_id,
                            }
                        ],
                    }
                )

        runner = Runner()
        sleeps: list[float] = []
        result = subject._wait_for_authority_application(
            manifest,
            maintenance_deployment_id=(
                "8060e625-ae47-432e-be09-5b01f449cdd8"
            ),
            expected_repository_ids={
                repository["canonical_root"]: repository_id
            },
            runner=runner,
            max_attempts=4,
            poll_interval_seconds=0.125,
            sleeper=sleeps.append,
        )
        self.assertEqual(result["attempts"], 3)
        self.assertEqual(result["repo_id"], repository_id)
        self.assertEqual(runner.text_calls, 3)
        self.assertEqual(runner.status_calls, 4)
        self.assertEqual(sleeps, [0.125, 0.125])
        self.assertEqual(
            runner.command[:4],
            ["/usr/bin/timeout", "--signal=KILL", "5", "/usr/bin/env"],
        )
        self.assertIn(
            "DEVCOORDINATOR_MAINTENANCE_DEPLOYMENT_ID="
            "8060e625-ae47-432e-be09-5b01f449cdd8",
            runner.command,
        )
        self.assertEqual(
            runner.command[-5:],
            [
                "inventory",
                "--project",
                repository["canonical_root"],
                "--no-docker",
                "--compact-json",
            ],
        )

    def test_authority_readiness_is_bounded_when_systemd_stays_active(self) -> None:
        manifest = self.validated()
        repository = manifest["repositories"][0]

        class Runner:
            def __init__(self) -> None:
                self.text_calls = 0

            def status(self, _argv: list[str]) -> int:
                return 0

            def text(self, _argv: list[str]) -> str:
                self.text_calls += 1
                raise subject.activation.ActivationError(
                    "systemd active before application readiness"
                )

        runner = Runner()
        sleeps: list[float] = []
        with self.assertRaisesRegex(
            subject.CleanAdoptionError,
            "trusted-local application readiness",
        ):
            subject._wait_for_authority_application(
                manifest,
                maintenance_deployment_id=(
                    "8060e625-ae47-432e-be09-5b01f449cdd8"
                ),
                expected_repository_ids={
                    repository["canonical_root"]: "repo-never-ready"
                },
                runner=runner,
                max_attempts=2,
                poll_interval_seconds=0.25,
                sleeper=sleeps.append,
            )
        self.assertEqual(runner.text_calls, 2)
        self.assertEqual(sleeps, [0.25])

    def test_exact_unit_start_clears_a_prior_start_limit(self) -> None:
        class Runner:
            def __init__(self) -> None:
                self.commands: list[list[str]] = []

            def status(self, command: list[str]) -> int:
                self.commands.append(command)
                return 0

        runner = Runner()
        result = subject.activation._start_exact_units(
            runner,
            ("devcoordinator-authority.socket", "devcoordinator-authority.service"),
        )
        self.assertEqual(
            runner.commands,
            [
                [
                    "/usr/bin/systemctl",
                    "reset-failed",
                    "devcoordinator-authority.socket",
                ],
                [
                    "/usr/bin/systemctl",
                    "enable",
                    "devcoordinator-authority.socket",
                ],
                [
                    "/usr/bin/systemctl",
                    "restart",
                    "devcoordinator-authority.socket",
                ],
                [
                    "/usr/bin/systemctl",
                    "reset-failed",
                    "devcoordinator-authority.service",
                ],
                [
                    "/usr/bin/systemctl",
                    "enable",
                    "--now",
                    "devcoordinator-authority.service",
                ],
            ],
        )
        self.assertEqual(
            result,
            {
                "devcoordinator-authority.socket": True,
                "devcoordinator-authority.service": True,
            },
        )

    def test_exact_unit_start_ignores_reset_failed_noop(self) -> None:
        class Runner:
            def __init__(self) -> None:
                self.commands: list[list[str]] = []

            def status(self, command: list[str]) -> int:
                self.commands.append(command)
                return 1 if command[1] == "reset-failed" else 0

        runner = Runner()
        result = subject.activation._start_exact_units(
            runner, ("devcoordinator-api.socket",)
        )

        self.assertEqual(result, {"devcoordinator-api.socket": True})
        self.assertEqual(
            runner.commands,
            [
                [
                    "/usr/bin/systemctl",
                    "reset-failed",
                    "devcoordinator-api.socket",
                ],
                [
                    "/usr/bin/systemctl",
                    "enable",
                    "devcoordinator-api.socket",
                ],
                [
                    "/usr/bin/systemctl",
                    "restart",
                    "devcoordinator-api.socket",
                ],
            ],
        )


if __name__ == "__main__":
    unittest.main()
