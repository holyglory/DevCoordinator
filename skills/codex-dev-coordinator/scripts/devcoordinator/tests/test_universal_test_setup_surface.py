from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import uuid

from devcoordinator.universal_test_service import (
    StoreTestPlaneAdapter,
    TestRepositorySetupUnavailable,
    decode_repository_setup_document,
)
from devcoordinator.universal_test_snapshot_service import (
    RootSnapshotService,
    UnixSnapshotServiceClient,
    UnixSnapshotServiceServer,
)
from devcoordinator.universal_test_store import (
    TestStoreContractError,
    UniversalTestStore,
)
from devcoordinator.universal_test_transport import (
    TEST_REPOSITORY_SETUP,
    TestPlaneDispatcher,
    UnixTestPlaneClient,
)
from devcoordinator import universal_test_uid_helper as uid_helper
from devcoordinator.universal_test_uid_helper import execute


def manifest_document() -> dict[str, object]:
    return {
        "schema_version": 3,
        "defaults": {
            "timeout_seconds": 300,
            "network": "none",
            "environment": {"CONFIG": "must-not-leak"},
        },
        "global_inputs": [".codex/tests.json", "pyproject.toml"],
        "intents": {
            "handoff": {"source_mode": "immutable", "allow_reuse": True}
        },
        "fixtures": {
            "postgres": {"template": "postgres-template", "network": "loopback"}
        },
        "targets": {
            "lint": {
                "driver": "automation",
                "reporter": "automation-events",
                "argv": ["./scripts/lint"],
                "cwd": ".",
                "inputs": ["src/**"],
                "depends_on": [],
                "intents": ["handoff"],
                "retry": {
                    "max_attempts": 2,
                    "retry_on": ["lease_expired_before_launch"],
                },
            },
            "unit": {
                "driver": "pytest",
                "reporter": "pytest-events",
                "argv": ["{python}", "-m", "pytest", "tests"],
                "cwd": ".",
                "inputs": ["src/**", "tests/**"],
                "depends_on": ["lint"],
                "intents": ["handoff"],
                "network": "loopback",
                "fixtures": ["postgres"],
                "retry": {
                    "max_attempts": 2,
                    "retry_on": ["lease_expired_before_launch"],
                },
            },
        },
        "evidence_policies": {
            "handoff-proof": {
                "intent": "handoff",
                "required_targets": ["unit"],
                "max_age_seconds": 3_600,
                "allow_reuse": True,
            }
        },
    }


class FakePreviewer:
    def __init__(self, setup: dict[str, object]) -> None:
        self.setup = setup
        self.calls: list[dict[str, object]] = []

    def setup_as_owner(self, **arguments):
        self.calls.append(dict(arguments))
        return self.setup

    def preview_as_owner(self, **_arguments):
        raise AssertionError("preview is outside this setup test")


class FakeAuthority:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls: list[str] = []

    def repository(self, *, repository_id: str):
        self.calls.append(repository_id)
        return {
            "repository_id": repository_id,
            "canonical_root": str(self.root),
            "generation": 7,
        }


class FakeHelper:
    def __init__(self, result: dict[str, object]) -> None:
        self.result = result
        self.calls: list[tuple[str, int, dict[str, object]]] = []

    def call(self, operation, *, owner_uid, arguments):
        self.calls.append((operation, owner_uid, dict(arguments)))
        return self.result


class RepositorySetupSurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repo"
        (self.root / ".codex").mkdir(parents=True)
        (self.root / ".codex" / "tests.json").write_text(
            json.dumps(manifest_document(), sort_keys=True), encoding="utf-8"
        )
        self.owner_uid = os.geteuid()

    def helper_setup(self, root: Path | None = None) -> dict[str, object]:
        result = execute(
            {
                "operation": "setup",
                "owner_uid": self.owner_uid,
                "arguments": {"repository_root": str(root or self.root)},
            }
        )
        return dict(result)

    def full_setup(self) -> dict[str, object]:
        return {"repository_id": "repo-setup", **self.helper_setup()}

    def test_uid_helper_returns_ready_sanitized_manifest_projection(self) -> None:
        with mock.patch(
            "devcoordinator.universal_test_uid_helper._repository_input_paths",
            return_value=(
                ".codex/tests.json",
                "pyproject.toml",
                "src/example.py",
                "tests/test_example.py",
            ),
        ):
            result = self.helper_setup()
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["target_graph"], {"lint": [], "unit": ["lint"]})
        self.assertEqual(result["input_coverage"], {
            "global_input_count": 2,
            "target_input_count": 3,
            "targets_with_inputs": 2,
        })
        self.assertEqual(result["evidence_policies"], ["handoff-proof"])
        self.assertEqual(result["fixtures"], ["postgres"])
        targets = {target["name"]: target for target in result["targets"]}
        self.assertEqual(targets["lint"]["fixtures"], [])
        self.assertEqual(targets["unit"]["fixtures"], ["postgres"])
        self.assertEqual(result["network_requirements"], ["none", "loopback"])
        self.assertEqual(
            result["isolation"],
            {
                "network": "loopback",
                "cpu_millis": 1_000,
                "memory_mib": 512,
                "pids": 256,
                "private_scratch": True,
                "kill_after_run": True,
            },
        )
        self.assertEqual(result["input_coverage_gaps"], [])
        encoded = json.dumps(result, sort_keys=True)
        for forbidden in (
            str(self.root),
            ".codex/tests.json",
            "src/**",
            "./scripts/lint",
            "postgres-template",
            "must-not-leak",
            "environment",
        ):
            self.assertNotIn(forbidden, encoded)

    def test_uid_helper_reports_truthful_unmapped_repository_paths(self) -> None:
        with mock.patch(
            "devcoordinator.universal_test_uid_helper._repository_input_paths",
            return_value=(
                ".codex/tests.json",
                "README.md",
                "docs/operations.md",
                "pyproject.toml",
                "src/example.py",
                "tests/test_example.py",
            ),
        ):
            result = self.helper_setup()

        self.assertEqual(
            result["input_coverage_gaps"],
            [
                {
                    "code": "unmapped_repository_path",
                    "message": "repository path is not mapped by global inputs or target inputs",
                    "path": "README.md",
                    "detail": "changes to this path select the complete required intent",
                },
                {
                    "code": "unmapped_repository_path",
                    "message": "repository path is not mapped by global inputs or target inputs",
                    "path": "docs/operations.md",
                    "detail": "changes to this path select the complete required intent",
                },
            ],
        )
        decoded = decode_repository_setup_document(
            {"repository_id": "repo-setup", **result},
            expected_repository_id="repo-setup",
        )
        self.assertEqual(decoded["input_coverage_gaps"], result["input_coverage_gaps"])

    def test_uid_helper_marks_incomplete_repository_inspection_fail_closed(self) -> None:
        with mock.patch(
            "devcoordinator.universal_test_uid_helper._repository_input_paths",
            side_effect=RuntimeError("private repository detail must not leak"),
        ):
            result = self.helper_setup()

        self.assertEqual(
            result["input_coverage_gaps"],
            [
                {
                    "code": "input_coverage_inspection_incomplete",
                    "message": "repository input coverage could not be fully inspected",
                    "detail": (
                        "unmapped paths may exist; uncertain changes still select "
                        "the complete required intent"
                    ),
                }
            ],
        )
        self.assertNotIn("private repository detail", json.dumps(result, sort_keys=True))

    def test_repository_input_paths_include_baseline_and_nonignored_untracked(self) -> None:
        root = Path(self.temporary.name) / "path-state"
        root.mkdir()
        (root / "README.md").write_text("tracked then deleted\n", encoding="utf-8")
        (root / ".gitignore").write_text("ignored/\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(
            ["git", "-C", str(root), "config", "user.email", "setup@example.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(root), "config", "user.name", "Setup test"],
            check=True,
        )
        subprocess.run(["git", "-C", str(root), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(root), "commit", "-q", "-m", "fixture"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(root), "rm", "-q", "README.md"], check=True
        )
        (root / "notes.txt").write_text("non-ignored\n", encoding="utf-8")
        (root / "ignored").mkdir()
        (root / "ignored" / "cache.bin").write_bytes(b"ignored")

        self.assertEqual(
            uid_helper._repository_input_paths(root),
            (".gitignore", "README.md", "notes.txt"),
        )

    def test_input_coverage_gap_projection_is_bounded_and_fail_closed(self) -> None:
        unmapped = tuple(f"extra/{index:03d}.txt" for index in range(130))
        with mock.patch(
            "devcoordinator.universal_test_uid_helper._repository_input_paths",
            return_value=(".codex/tests.json", *unmapped),
        ):
            result = self.helper_setup()

        gaps = result["input_coverage_gaps"]
        self.assertEqual(len(gaps), 129)
        self.assertEqual(gaps[0]["path"], "extra/000.txt")
        self.assertEqual(gaps[-2]["path"], "extra/127.txt")
        self.assertEqual(gaps[-1]["code"], "unmapped_repository_paths_omitted")
        decoded = decode_repository_setup_document(
            {"repository_id": "repo-setup", **result},
            expected_repository_id="repo-setup",
        )
        self.assertEqual(decoded["input_coverage_gaps"], gaps)

        forged = {"repository_id": "repo-setup", **result}
        forged["input_coverage_gaps"] = [dict(item) for item in gaps]
        forged["input_coverage_gaps"][0]["path"] = "/private/path"
        with self.assertRaisesRegex(TestStoreContractError, "gap path"):
            decode_repository_setup_document(
                forged, expected_repository_id="repo-setup"
            )

    def test_uid_helper_projects_host_loopback_as_distinct_requirement(self) -> None:
        document = manifest_document()
        document["intents"]["manual"] = {  # type: ignore[index]
            "source_mode": "immutable",
            "allow_reuse": False,
        }
        document["targets"]["host-health"] = {  # type: ignore[index]
            "driver": "automation",
            "reporter": "automation-events",
            "argv": ["./scripts/host-health"],
            "cwd": ".",
            "inputs": ["scripts/host-health"],
            "depends_on": [],
            "intents": ["manual"],
            "network": "host-loopback",
            "retry": {
                "max_attempts": 2,
                "retry_on": ["lease_expired_before_launch"],
            },
        }
        document["targets"]["external-health"] = {  # type: ignore[index]
            "driver": "automation",
            "reporter": "automation-events",
            "argv": ["./scripts/external-health"],
            "cwd": ".",
            "inputs": ["scripts/external-health"],
            "depends_on": [],
            "intents": ["manual"],
            "network": "external",
            "retry": {
                "max_attempts": 2,
                "retry_on": ["lease_expired_before_launch"],
            },
        }
        (self.root / ".codex" / "tests.json").write_text(
            json.dumps(document, sort_keys=True), encoding="utf-8"
        )

        result = self.helper_setup()

        self.assertEqual(
            result["network_requirements"],
            ["none", "loopback", "host-loopback", "external"],
        )
        self.assertEqual(result["isolation"]["network"], "external")
        decoded = decode_repository_setup_document(
            {"repository_id": "repo-setup", **result},
            expected_repository_id="repo-setup",
        )
        self.assertEqual(
            decoded["network_requirements"],
            ["none", "loopback", "host-loopback", "external"],
        )

    def test_uid_helper_distinguishes_missing_and_invalid_without_leaking_detail(self) -> None:
        missing_root = Path(self.temporary.name) / "missing"
        missing_root.mkdir()
        missing = self.helper_setup(missing_root)
        self.assertEqual(missing["status"], "missing")
        self.assertEqual(missing["issues"][0]["code"], "manifest_missing")

        invalid_root = Path(self.temporary.name) / "invalid"
        (invalid_root / ".codex").mkdir(parents=True)
        (invalid_root / ".codex" / "tests.json").write_text(
            json.dumps(
                {"secret": "must-not-leak", "path": "/private/must-not-leak"}
            ),
            encoding="utf-8",
        )
        invalid = self.helper_setup(invalid_root)
        self.assertEqual(invalid["status"], "invalid")
        self.assertEqual(invalid["issues"][0]["code"], "manifest_invalid")
        self.assertNotIn("must-not-leak", json.dumps(invalid, sort_keys=True))

    def test_adapter_revalidates_identity_shape_and_secret_free_fields(self) -> None:
        path = Path(self.temporary.name) / "test-plane.sqlite3"
        previewer = FakePreviewer(self.full_setup())
        adapter = StoreTestPlaneAdapter(
            UniversalTestStore.create(path), previewer=previewer
        )
        result = adapter.setup(repository_id="repo-setup", owner_uid=self.owner_uid)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(previewer.calls, [
            {"repository_id": "repo-setup", "owner_uid": self.owner_uid}
        ])
        catalog = adapter.repository_catalog(repository_ids=("repo-setup",))
        self.assertEqual(catalog["repositories"][0]["setup_status"], "ready")
        self.assertTrue(catalog["repositories"][0]["retained"])
        self.assertEqual(len(previewer.calls), 1, "catalog reads must not rescan the worktree")

        poisoned = self.full_setup()
        poisoned["repository_root"] = "/private/must-not-leak"
        with self.assertRaisesRegex(TestStoreContractError, "fields"):
            StoreTestPlaneAdapter(
                UniversalTestStore.open(path), previewer=FakePreviewer(poisoned)
            ).setup(repository_id="repo-setup", owner_uid=self.owner_uid)

    def test_adapter_reports_typed_unavailable_without_uid_boundary(self) -> None:
        path = Path(self.temporary.name) / "unavailable.sqlite3"
        with self.assertRaises(TestRepositorySetupUnavailable):
            StoreTestPlaneAdapter(UniversalTestStore.create(path)).setup(
                repository_id="repo-setup", owner_uid=self.owner_uid
            )

    def test_root_snapshot_setup_resolves_catalog_then_calls_uid_helper(self) -> None:
        helper_result = self.helper_setup()
        authority = FakeAuthority(self.root)
        helper = FakeHelper(helper_result)
        service = object.__new__(RootSnapshotService)
        service.authority = authority
        service.helper = helper
        result = service.setup(
            {"repository_id": "repo-setup", "owner_uid": self.owner_uid}
        )
        self.assertEqual(result["repository_id"], "repo-setup")
        self.assertEqual(authority.calls, ["repo-setup"])
        self.assertEqual(helper.calls, [
            (
                "setup",
                self.owner_uid,
                {"repository_root": str(self.root)},
            )
        ])

    def test_snapshot_preview_socket_uses_only_transport_margin(self) -> None:
        request_id = uuid.UUID("11111111-1111-4111-8111-111111111111")
        connection = mock.MagicMock()
        client = object.__new__(UnixSnapshotServiceClient)
        client.socket_path = Path("/run/devcoordinator/snapshot.sock")
        client.last_peer_uid = None
        response = {
            "request_id": str(request_id),
            "ok": True,
            "result": {},
        }
        with (
            mock.patch(
                "devcoordinator.universal_test_snapshot_service.uuid.uuid4",
                return_value=request_id,
            ),
            mock.patch(
                "devcoordinator.universal_test_snapshot_service.socket.socket",
                return_value=connection,
            ),
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._peer_uid",
                return_value=0,
            ),
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._send"
            ),
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._receive",
                side_effect=[response, response],
            ),
        ):
            self.assertEqual(
                client._call("preview", {"launch_timeout_seconds": 987}), {}
            )
            self.assertEqual(client._call("setup", {}), {})

        self.assertEqual(
            connection.settimeout.call_args_list,
            [mock.call(1017.0), mock.call(180.0)],
        )

    def test_snapshot_client_and_server_route_only_setup_arguments(self) -> None:
        result = self.full_setup()
        client = object.__new__(UnixSnapshotServiceClient)
        client._call = mock.Mock(return_value=result)
        self.assertEqual(
            client.setup_as_owner(
                repository_id="repo-setup", owner_uid=self.owner_uid
            ),
            result,
        )
        client._call.assert_called_once_with(
            "setup", {"repository_id": "repo-setup", "owner_uid": self.owner_uid}
        )

        class Service:
            def __init__(self):
                self.arguments = None

            def setup(self, arguments):
                self.arguments = arguments
                return result

        snapshot_service = Service()
        server = UnixSnapshotServiceServer(
            mock.Mock(), snapshot_service, allowed_peer_uid=self.owner_uid
        )
        sent = mock.Mock()
        with (
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._peer_uid",
                return_value=self.owner_uid,
            ),
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._receive",
                return_value={
                    "schema_version": 1,
                    "request_id": "request-1",
                    "operation": "setup",
                    "arguments": {
                        "repository_id": "repo-setup",
                        "owner_uid": self.owner_uid,
                    },
                },
            ),
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._send", sent
            ),
        ):
            server.serve_connection(mock.Mock())
        self.assertEqual(snapshot_service.arguments, {
            "repository_id": "repo-setup",
            "owner_uid": self.owner_uid,
        })
        self.assertTrue(sent.call_args.args[1]["ok"])

    def test_snapshot_server_accepts_root_first_adoption_policy_reader(self) -> None:
        result = self.full_setup()
        service = mock.Mock()
        service.setup.return_value = result
        server = UnixSnapshotServiceServer(
            mock.Mock(), service, allowed_peer_uid=self.owner_uid
        )
        sent = mock.Mock()
        with (
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._peer_uid",
                return_value=0,
            ),
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._receive",
                return_value={
                    "schema_version": 1,
                    "request_id": "first-adoption-policy",
                    "operation": "setup",
                    "arguments": {
                        "repository_id": "repo-setup",
                        "owner_uid": self.owner_uid,
                    },
                },
            ),
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._send", sent
            ),
        ):
            server.serve_connection(mock.Mock())
        service.setup.assert_called_once_with(
            {"repository_id": "repo-setup", "owner_uid": self.owner_uid}
        )
        self.assertEqual(sent.call_args.args[1]["request_id"], "first-adoption-policy")
        self.assertTrue(sent.call_args.args[1]["ok"])

    def test_snapshot_server_send_disconnect_does_not_poison_later_requests(self) -> None:
        result = self.full_setup()
        request = {
            "schema_version": 1,
            "operation": "setup",
            "arguments": {
                "repository_id": "repo-setup",
                "owner_uid": self.owner_uid,
            },
        }
        for disconnect_error in (BrokenPipeError, ConnectionResetError):
            with self.subTest(disconnect_error=disconnect_error.__name__):
                service = mock.Mock()
                service.setup.return_value = result
                server = UnixSnapshotServiceServer(
                    mock.Mock(), service, allowed_peer_uid=self.owner_uid
                )
                sent: list[dict[str, object]] = []

                def send(_connection, response):
                    sent.append(response)
                    if len(sent) == 1:
                        raise disconnect_error("fixture client disconnected")

                with (
                    mock.patch(
                        "devcoordinator.universal_test_snapshot_service._peer_uid",
                        return_value=self.owner_uid,
                    ),
                    mock.patch(
                        "devcoordinator.universal_test_snapshot_service._receive",
                        side_effect=[
                            {**request, "request_id": "abandoned-request"},
                            {**request, "request_id": "later-request"},
                        ],
                    ),
                    mock.patch(
                        "devcoordinator.universal_test_snapshot_service._send",
                        side_effect=send,
                    ),
                ):
                    self.assertIsNone(server.serve_connection(mock.Mock()))
                    self.assertIsNone(server.serve_connection(mock.Mock()))

                self.assertEqual(service.setup.call_count, 2)
                self.assertEqual(
                    [response["request_id"] for response in sent],
                    ["abandoned-request", "later-request"],
                )
                self.assertTrue(sent[1]["ok"])

    def test_test_plane_transport_routes_setup_and_rejects_extra_arguments(self) -> None:
        path = Path(self.temporary.name) / "transport.sqlite3"
        previewer = FakePreviewer(self.full_setup())
        service = StoreTestPlaneAdapter(
            UniversalTestStore.create(path), previewer=previewer
        )
        dispatcher = TestPlaneDispatcher(service)

        def dispatch(arguments):
            return dispatcher.dispatch(
                json.dumps(
                    {
                        "schema_version": 1,
                        "request_id": str(uuid.uuid4()),
                        "operation": TEST_REPOSITORY_SETUP,
                        "arguments": arguments,
                    },
                    separators=(",", ":"),
                ).encode("utf-8"),
                peer_uid=self.owner_uid,
            )

        accepted = dispatch(
            {"repository_id": "repo-setup", "owner_uid": self.owner_uid}
        )
        self.assertTrue(accepted["ok"])
        self.assertEqual(accepted["result"]["status"], "ready")
        refused = dispatch(
            {
                "repository_id": "repo-setup",
                "owner_uid": self.owner_uid,
                "repository_root": "/private/must-not-leak",
            }
        )
        self.assertFalse(refused["ok"])
        self.assertEqual(refused["error"]["code"], "invalid_request")

        client = object.__new__(UnixTestPlaneClient)
        client._call = mock.Mock(return_value=accepted["result"])
        self.assertEqual(
            client.setup(repository_id="repo-setup", owner_uid=self.owner_uid)[
                "status"
            ],
            "ready",
        )
        client._call.assert_called_once_with(
            TEST_REPOSITORY_SETUP,
            {"repository_id": "repo-setup", "owner_uid": self.owner_uid},
        )

    def test_setup_decoder_rejects_contradictory_repository_identity(self) -> None:
        with self.assertRaisesRegex(TestStoreContractError, "identity"):
            decode_repository_setup_document(
                self.full_setup(), expected_repository_id="repo-other"
            )


if __name__ == "__main__":
    unittest.main()
