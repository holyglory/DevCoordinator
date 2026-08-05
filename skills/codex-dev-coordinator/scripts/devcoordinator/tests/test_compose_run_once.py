"""Governed Docker Compose run-once policy, receipt, and replay tests."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest import mock

import dev_coordinator
from devcoordinator import broker_enrollment, broker_host
from devcoordinator.broker import (
    BrokerBackendError,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend
from devcoordinator.broker_host import (
    ComposeRunOnceOutputEvidence,
    LocalBrokerHostMutations,
)
from devcoordinator.broker_profile import (
    BrokerProfileError,
    BrokerRepositoryProfile,
    _compose_run_once_service_mapping,
)
from devcoordinator.compose_run_once import (
    MAX_COMPOSE_RUN_ONCE_RECEIPT_BYTES,
    ComposeRunOncePolicy,
    ComposeRunOnceReceiptContract,
    normalize_compose_run_once_policies,
    validate_published_receipt,
)
from devcoordinator.store import CoordinatorStore
from devcoordinator.tests.test_broker_assignment_compose import (
    COMPOSE_ALPHA,
    ExtendedBrokerFixture,
)


def _policy_document() -> dict[str, object]:
    return {
        "name": "ingestion-once",
        "max_timeout_seconds": 900,
        "receipt": {
            "required": {
                "imported": "integer",
                "ok": "boolean",
            },
            "optional": {
                "language": "string_or_null",
                "warnings": "string_array",
            },
        },
    }


class ComposeRunOnceReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = ComposeRunOnceReceiptContract.from_document(
            _policy_document()["receipt"]
        )

    def test_valid_receipt_publishes_only_declared_typed_fields(self) -> None:
        receipt = validate_published_receipt(
            b'{"warnings":["one"],"ok":true,"imported":7,"language":null}',
            contract=self.contract,
        )

        self.assertEqual(receipt.status, "valid")
        self.assertEqual(
            dict(receipt.receipt or {}),
            {
                "imported": 7,
                "language": None,
                "ok": True,
                "warnings": ["one"],
            },
        )
        canonical = json.dumps(
            dict(receipt.receipt or {}),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertEqual(
            receipt.receipt_sha256,
            "sha256:" + hashlib.sha256(canonical).hexdigest(),
        )

    def test_duplicate_key_trailing_data_and_non_finite_number_fail_closed(
        self,
    ) -> None:
        cases = (
            b'{"imported":1,"imported":2,"ok":true}',
            b'{"imported":1,"ok":true} trailing',
            b'{"imported":NaN,"ok":true}',
        )

        for payload in cases:
            with self.subTest(payload=payload):
                result = validate_published_receipt(
                    payload,
                    contract=self.contract,
                )
                self.assertEqual(result.status, "invalid_json")
                self.assertIsNone(result.receipt)
                self.assertIsNone(result.receipt_sha256)

    def test_missing_unexpected_and_wrong_type_fields_are_rejected(self) -> None:
        cases = (
            (b'{"imported":1}', "invalid_fields"),
            (
                b'{"imported":1,"ok":true,"private":"must-not-publish"}',
                "invalid_fields",
            ),
            (b'{"imported":true,"ok":true}', "invalid_types"),
            (b'{"imported":1,"ok":1}', "invalid_types"),
        )

        for payload, status in cases:
            with self.subTest(payload=payload):
                result = validate_published_receipt(
                    payload,
                    contract=self.contract,
                )
                self.assertEqual(result.status, status)
                self.assertIsNone(result.receipt)

    def test_oversize_invalid_utf8_and_empty_receipts_are_categorical(self) -> None:
        cases = (
            (b"", False, "empty"),
            (b"\xff", False, "invalid_utf8"),
            (
                b"x" * (MAX_COMPOSE_RUN_ONCE_RECEIPT_BYTES + 1),
                False,
                "too_large",
            ),
            (b'{"imported":1,"ok":true}', True, "too_large"),
        )

        for payload, truncated, status in cases:
            with self.subTest(status=status):
                result = validate_published_receipt(
                    payload,
                    contract=self.contract,
                    truncated=truncated,
                )
                self.assertEqual(result.status, status)
                self.assertIsNotNone(result.error_code)

    def test_policy_normalization_is_sorted_bounded_and_duplicate_safe(self) -> None:
        second = {
            **_policy_document(),
            "name": "z-last",
            "max_timeout_seconds": 600,
        }
        policies = normalize_compose_run_once_policies(
            [second, _policy_document()]
        )
        self.assertEqual(
            tuple(policy.name for policy in policies),
            ("ingestion-once", "z-last"),
        )
        self.assertTrue(
            all(isinstance(policy, ComposeRunOncePolicy) for policy in policies)
        )
        with self.assertRaisesRegex(ValueError, "duplicate"):
            normalize_compose_run_once_policies(
                [_policy_document(), _policy_document()]
            )
        with self.assertRaisesRegex(ValueError, "600 through 3600"):
            ComposeRunOncePolicy.from_document(
                {**_policy_document(), "max_timeout_seconds": 599}
            )
        with self.assertRaisesRegex(ValueError, "service name is invalid"):
            ComposeRunOncePolicy.from_document(
                {**_policy_document(), "name": 7}
            )


class ComposeRunOnceRequestTests(unittest.TestCase):
    def _request(self, arguments: dict[str, object]) -> BrokerRequest:
        return BrokerRequest.create(
            account_id="account-alpha",
            project_id="repo-alpha",
            resource_id="compose-alpha",
            operation=BrokerOperation.COMPOSE_RUN_ONCE,
            arguments=arguments,
        )

    def test_wire_accepts_only_agent_service_and_timeout(self) -> None:
        request = self._request(
            {
                "agent": "codex",
                "service": "ingestion-once",
                "timeout_seconds": 600,
            }
        )
        self.assertEqual(request.arguments["service"], "ingestion-once")

        forbidden = (
            {"command": ["sh"]},
            {"environment": {"SECRET": "value"}},
            {"mounts": ["/:/host"]},
            {"compose_file": "/tmp/override.yml"},
        )
        for addition in forbidden:
            with self.subTest(addition=addition):
                with self.assertRaisesRegex(BrokerError, "accepts exactly"):
                    self._request(
                        {
                            "agent": "codex",
                            "service": "ingestion-once",
                            "timeout_seconds": 600,
                            **addition,
                        }
                    )

    def test_wire_timeout_is_strictly_bounded(self) -> None:
        for value in (0, 3_601, True, 1.5):
            with self.subTest(value=value):
                with self.assertRaisesRegex(BrokerError, "one through 3600"):
                    self._request(
                        {
                            "agent": "codex",
                            "service": "ingestion-once",
                            "timeout_seconds": value,
                        }
                    )


class ComposeRunOnceManifestProfileAndCliTests(unittest.TestCase):
    def test_runtime_manifest_separates_lifecycle_and_run_once_services(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="devcoordinator-run-once-manifest-",
            dir="/tmp",
        ) as raw_root:
            root = Path(raw_root)
            (root / "compose.yml").write_text(
                "services:\n"
                "  app:\n"
                "    image: example.invalid/app:test\n"
                "  ingestion-once:\n"
                "    image: example.invalid/ingestion:test\n",
                encoding="utf-8",
            )
            config_dir = root / ".codex"
            config_dir.mkdir()
            runtime_file = config_dir / "dev-runtime.json"
            runtime_file.write_text(
                json.dumps(
                    {
                        "docker": {
                            "compose_files": ["compose.yml"],
                            "services": ["app"],
                            "run_once_services": [_policy_document()],
                        }
                    }
                ),
                encoding="utf-8",
            )

            specification = dev_coordinator.build_project_runtime_spec(
                {},
                project=str(root),
                runtime_file=str(runtime_file),
                include_docker=False,
            )

            compose = specification["compose"]
            self.assertEqual(compose["services"], ["app"])
            self.assertEqual(
                compose["run_once_services"],
                [_policy_document()],
            )
            self.assertTrue(compose["declared"])

            document = json.loads(runtime_file.read_text(encoding="utf-8"))
            document["docker"]["services"] = ["app", "ingestion-once"]
            runtime_file.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must be disjoint"):
                dev_coordinator.build_project_runtime_spec(
                    {},
                    project=str(root),
                    runtime_file=str(runtime_file),
                    include_docker=False,
                )

    def test_profile_requires_exact_service_and_policy_timeout(self) -> None:
        profile = BrokerRepositoryProfile(
            canonical_root="/tmp/repo",
            repo_id="repo-alpha",
            generation=0,
            owner_uid=max(1, os.geteuid()),
            server_ids={},
            container_ids={},
            compose_definition_id="compose-alpha",
            compose_container_ids=frozenset(),
            compose_run_once_services={"ingestion-once": 900},
            ephemeral_templates={},
            ephemeral_image_prefetch_template_ids=frozenset(),
            ephemeral_secret_policies={},
            account_id="account-alpha",
            enabled=True,
            issued_at="2026-08-03T00:00:00Z",
            valid_until_epoch=4_102_444_800,
        )
        self.assertEqual(
            profile.compose_run_once_timeout(
                "ingestion-once",
                timeout_seconds=600,
            ),
            600,
        )
        with self.assertRaisesRegex(BrokerProfileError, "not explicitly enrolled"):
            profile.compose_run_once_timeout(
                "another-service",
                timeout_seconds=600,
            )
        with self.assertRaisesRegex(BrokerProfileError, "one through 900"):
            profile.compose_run_once_timeout(
                "ingestion-once",
                timeout_seconds=901,
            )
        with self.assertRaisesRegex(BrokerProfileError, "policy is invalid"):
            _compose_run_once_service_mapping({"ingestion@once": 900})

    def test_enrollment_grant_map_is_explicit_and_timeout_only(self) -> None:
        compose = {
            "declared": True,
            "run_once_services": [_policy_document()],
        }
        self.assertEqual(
            broker_enrollment._compose_run_once_grant_mapping(
                compose=compose,
                allowed_run_once_services=("ingestion-once",),
            ),
            {"ingestion-once": 900},
        )
        self.assertEqual(
            broker_enrollment._compose_run_once_grant_mapping(
                compose=compose,
                allowed_run_once_services=(),
            ),
            {},
        )
        with self.assertRaisesRegex(ValueError, "absent from the sealed manifest"):
            broker_enrollment._compose_run_once_grant_mapping(
                compose=compose,
                allowed_run_once_services=("another-service",),
            )

    def test_cli_default_is_ten_minutes_and_accepts_operation_replay_id(
        self,
    ) -> None:
        operation_id = str(uuid.uuid4())
        arguments = dev_coordinator.build_parser().parse_args(
            [
                "docker",
                "compose-run-once",
                "--agent",
                "codex",
                "--project",
                "/tmp/repo",
                "--service",
                "ingestion-once",
                "--operation-id",
                operation_id,
            ]
        )
        self.assertEqual(arguments.timeout_seconds, 600)
        self.assertEqual(arguments.operation_id, operation_id)
        self.assertFalse(hasattr(arguments, "command"))
        self.assertFalse(hasattr(arguments, "environment"))
        self.assertFalse(hasattr(arguments, "mount"))


class ComposeRunOnceLogCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = ComposeRunOnceReceiptContract.from_document(
            _policy_document()["receipt"]
        )

    def test_capture_hashes_complete_separate_streams_and_publishes_receipt(
        self,
    ) -> None:
        stdout = b'{"imported":3,"ok":true}'
        stderr = b"private stderr detail"
        script = (
            "import os;"
            f"os.write(1,{stdout!r});"
            f"os.write(2,{stderr!r})"
        )

        evidence = broker_host._capture_compose_run_once_logs(
            (sys.executable, "-c", script),
            timeout_seconds=10,
            contract=self.contract,
            environment={},
        )

        self.assertEqual(
            dict(evidence.published_receipt.receipt or {}),
            {"imported": 3, "ok": True},
        )
        self.assertEqual(
            evidence.stdout_sha256,
            "sha256:" + hashlib.sha256(stdout).hexdigest(),
        )
        self.assertEqual(
            evidence.stderr_sha256,
            "sha256:" + hashlib.sha256(stderr).hexdigest(),
        )
        self.assertEqual(evidence.stdout_byte_size, len(stdout))
        self.assertEqual(evidence.stderr_byte_size, len(stderr))

    def test_oversize_stdout_is_fully_hashed_but_never_published(self) -> None:
        stdout = b"x" * (MAX_COMPOSE_RUN_ONCE_RECEIPT_BYTES + 17)
        script = f"import os;os.write(1,{stdout!r})"

        evidence = broker_host._capture_compose_run_once_logs(
            (sys.executable, "-c", script),
            timeout_seconds=10,
            contract=self.contract,
            environment={},
        )

        self.assertEqual(evidence.published_receipt.status, "too_large")
        self.assertIsNone(evidence.published_receipt.receipt)
        self.assertEqual(evidence.stdout_byte_size, len(stdout))
        self.assertEqual(
            evidence.stdout_sha256,
            "sha256:" + hashlib.sha256(stdout).hexdigest(),
        )


class _SuccessfulRunOnceHost:
    image_id = "sha256:" + "a" * 64
    container_id = "b" * 64

    def __init__(self) -> None:
        self.calls: list[str] = []

    def compose_run_once_bind_image(self, target):
        self.calls.append("bind_image")
        return {"image_ref": target.service_image_ref, "image_id": self.image_id}

    def compose_run_once_find_container(self, _target):
        self.calls.append("find_container")
        return None

    def compose_run_once_create_container(self, _target):
        self.calls.append("create_container")
        return {
            "full_container_id": self.container_id,
            "image_id": self.image_id,
            "status": "created",
            "exit_code": 0,
        }

    def compose_run_once_start_container(self, _target):
        self.calls.append("start_container")
        return {
            "full_container_id": self.container_id,
            "image_id": self.image_id,
            "status": "running",
            "exit_code": 0,
        }

    def compose_run_once_wait_container(self, _target, *, timeout_seconds):
        self.calls.append("wait_container")
        if not 0 < timeout_seconds <= 600:
            raise AssertionError("backend wait escaped the sealed timeout")
        return {
            "full_container_id": self.container_id,
            "image_id": self.image_id,
            "status": "exited",
            "exit_code": 0,
            "timed_out": False,
        }

    def compose_run_once_capture_evidence(self, target):
        self.calls.append("capture_evidence")
        stdout = b'{"language":"en","ok":true,"imported":7}'
        stderr = b"private diagnostic must not be published"
        return ComposeRunOnceOutputEvidence(
            published_receipt=validate_published_receipt(
                stdout,
                contract=target.receipt_contract,
            ),
            stdout_sha256="sha256:" + hashlib.sha256(stdout).hexdigest(),
            stdout_byte_size=len(stdout),
            stderr_sha256="sha256:" + hashlib.sha256(stderr).hexdigest(),
            stderr_byte_size=len(stderr),
        )

    def compose_run_once_remove_container(self, _target):
        self.calls.append("remove_container")
        return {"removed": True, "full_container_id": self.container_id}


class _CrashAfterCreateIntentHost(_SuccessfulRunOnceHost):
    def compose_run_once_create_container(self, _target):
        self.calls.append("create_container")
        raise KeyboardInterrupt("simulated broker death after durable create intent")


class _AbsentReplayHost(_SuccessfulRunOnceHost):
    def compose_run_once_create_container(self, _target):
        raise AssertionError("ambiguous replay must never recreate a container")


class ComposeRunOncePersistenceAndBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self._home = tempfile.TemporaryDirectory(
            prefix="devcoordinator-run-once-home-",
            dir="/tmp",
        )
        Path(self._home.name).chmod(0o700)
        current = pwd.getpwuid(os.geteuid())
        values = list(current)
        values[5] = self._home.name
        replacement = pwd.struct_passwd(tuple(values))
        original = pwd.getpwuid
        self._pwd_patch = mock.patch.object(
            pwd,
            "getpwuid",
            side_effect=lambda uid: (
                replacement if uid == os.geteuid() else original(uid)
            ),
        )
        self._pwd_patch.start()
        self.fixture = ExtendedBrokerFixture()
        self.manifest = {
            "declared": True,
            "files": [str(self.fixture.compose_one)],
            "services": ["db", "web"],
            "project_name": "alpha-stack",
            "run_once_services": [_policy_document()],
        }
        compose_id = broker_enrollment._provision_compose(
            self.fixture.persistence,
            repo_id="repo-alpha",
            client_uid=os.geteuid(),
            root=self.fixture.alpha_root,
            compose=self.manifest,
            allowed_run_once_services=("ingestion-once",),
        )
        self.assertEqual(compose_id, COMPOSE_ALPHA)

    def tearDown(self) -> None:
        self.fixture.close()
        self._pwd_patch.stop()
        self._home.cleanup()

    def _request(self, *, operation_id: str | None = None) -> BrokerRequest:
        return self.fixture.request(
            BrokerOperation.COMPOSE_RUN_ONCE,
            resource_id=COMPOSE_ALPHA,
            arguments={
                "agent": "codex",
                "service": "ingestion-once",
                "timeout_seconds": 600,
            },
            operation_id=operation_id,
        )

    def _backend(self, host) -> StoreBackedMutationBackend:
        return StoreBackedMutationBackend(
            self.fixture.persistence,
            host,
            observe_before_lifecycle_plan=self.fixture.observe_full_docker,
        )

    def _reserved_create_target(self):
        request = self._request()
        authorized = self.fixture.persistence.authorize(
            self.fixture.peer(),
            request,
        )
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            preflight = self.fixture.observe_full_docker(store)
        self.fixture.persistence.require_compose_mutation_safe(
            authorized,
            snapshot_id=str(preflight["snapshot_id"]),
        )
        self.fixture.persistence.reserve_operation(
            authorized,
            compose_preflight=preflight,
        )
        self.fixture.persistence.mark_compose_run_once_image_bind_intent(
            authorized
        )
        self.fixture.persistence.bind_compose_run_once_image(
            authorized,
            image_id=_SuccessfulRunOnceHost.image_id,
        )
        self.fixture.persistence.mark_compose_run_once_create_intent(
            authorized
        )
        return (
            authorized,
            self.fixture.persistence.compose_run_once_target(authorized),
        )

    def test_exact_grant_required_and_policy_timeout_enforced(self) -> None:
        request = self._request()
        authorized = self.fixture.persistence.authorize(
            self.fixture.peer(),
            request,
        )
        self.assertEqual(authorized.request.arguments["service"], "ingestion-once")

        too_long = self.fixture.request(
            BrokerOperation.COMPOSE_RUN_ONCE,
            resource_id=COMPOSE_ALPHA,
            arguments={
                "agent": "codex",
                "service": "ingestion-once",
                "timeout_seconds": 901,
            },
        )
        with self.assertRaisesRegex(BrokerError, "not authorized"):
            self.fixture.persistence.authorize(self.fixture.peer(), too_long)

        self.fixture.persistence.replace_compose_run_once_access(
            uid=os.geteuid(),
            repo_id="repo-alpha",
            compose_definition_id=COMPOSE_ALPHA,
            service_names=(),
        )
        with self.assertRaisesRegex(BrokerError, "not authorized"):
            self.fixture.persistence.authorize(self.fixture.peer(), request)

    def test_success_is_durable_idempotent_and_raw_streams_stay_private(self) -> None:
        host = _SuccessfulRunOnceHost()
        request = self._request()
        authorized = self.fixture.persistence.authorize(
            self.fixture.peer(),
            request,
        )
        result = dict(self._backend(host).execute(authorized))

        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(
            result["receipt"],
            {"imported": 7, "language": "en", "ok": True},
        )
        self.assertTrue(result["output_suppressed"])
        self.assertNotIn("stdout_sha256", result)
        self.assertNotIn("stderr_sha256", result)
        self.assertNotIn("stdout", result)
        self.assertNotIn("stderr", result)
        calls_after_first = tuple(host.calls)

        replay = dict(self._backend(host).execute(authorized))
        self.assertEqual(replay, result)
        self.assertEqual(tuple(host.calls), calls_after_first)

        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.read_transaction() as connection:
                row = connection.execute(
                    """
                    SELECT stdout_sha256, stdout_byte_size,
                           stderr_sha256, stderr_byte_size, receipt_json
                    FROM broker_compose_run_once_attempts
                    WHERE operation_id = ?
                    """,
                    (request.operation_id,),
                ).fetchone()
        self.assertIsNotNone(row)
        self.assertRegex(str(row["stdout_sha256"]), r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(str(row["stderr_sha256"]), r"^sha256:[0-9a-f]{64}$")
        self.assertGreater(int(row["stdout_byte_size"]), 0)
        self.assertGreater(int(row["stderr_byte_size"]), 0)
        self.assertNotIn("private diagnostic", str(row["receipt_json"]))

    def test_replay_after_ambiguous_create_intent_never_recreates(self) -> None:
        operation_id = str(uuid.uuid4())
        request = self._request(operation_id=operation_id)
        authorized = self.fixture.persistence.authorize(
            self.fixture.peer(),
            request,
        )
        crash_host = _CrashAfterCreateIntentHost()
        with self.assertRaises(KeyboardInterrupt):
            self._backend(crash_host).execute(authorized)

        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.read_transaction() as connection:
                phase = connection.execute(
                    """
                    SELECT phase FROM broker_compose_run_once_attempts
                    WHERE operation_id = ?
                    """,
                    (operation_id,),
                ).fetchone()[0]
        self.assertEqual(phase, "create_intent")

        replay_host = _AbsentReplayHost()
        result = dict(self._backend(replay_host).execute(authorized))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(
            result["error_code"],
            "compose_run_once_creation_ambiguous",
        )
        self.assertEqual(result["cleanup_status"], "not_created")
        self.assertNotIn("create_container", replay_host.calls)

    def test_host_create_uses_fixed_argv_labels_and_immutable_image_override(
        self,
    ) -> None:
        _authorized, target = self._reserved_create_target()
        captured: dict[str, object] = {}

        def runner(command, cwd, timeout_seconds, environment):
            captured["command"] = tuple(command)
            captured["cwd"] = cwd
            captured["timeout_seconds"] = timeout_seconds
            captured["environment"] = dict(environment)
            paths = [
                command[index + 1]
                for index, token in enumerate(command)
                if token == "--file"
            ]
            captured["compose_payloads"] = tuple(
                Path(path).read_bytes() for path in paths
            )
            return subprocess.CompletedProcess(command, 0, "", "")

        @contextmanager
        def pinned_material():
            yield ((b"services: {}\n",), (), "/proc/self/fd/test-cwd")

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker",
            compose_runner=runner,
            compose_model_renderer=lambda **_arguments: b"{}",
        )
        host.compose_run_once_find_container = mock.Mock(
            side_effect=(
                None,
                {
                    "full_container_id": _SuccessfulRunOnceHost.container_id,
                    "image_id": _SuccessfulRunOnceHost.image_id,
                    "status": "created",
                    "exit_code": 0,
                },
            )
        )
        host._require_current_compose_model = mock.Mock()
        host._inspect_compose_run_once_image = mock.Mock(
            return_value=_SuccessfulRunOnceHost.image_id
        )
        with mock.patch.object(
            broker_host,
            "_validated_compose_target",
            return_value=pinned_material(),
        ):
            created = host.compose_run_once_create_container(target)

        self.assertEqual(
            created["full_container_id"],
            _SuccessfulRunOnceHost.container_id,
        )
        command = tuple(captured["command"])
        run_index = command.index("run")
        self.assertEqual(
            command[run_index : run_index + 6],
            (
                "run",
                "--no-deps",
                "--no-TTY",
                "--no-start",
                "--name",
                target.container_name,
            ),
        )
        self.assertEqual(command[-1], "ingestion-once")
        label_values = tuple(
            command[index + 1]
            for index, token in enumerate(command)
            if token == "--label"
        )
        self.assertEqual(
            label_values,
            tuple(
                f"{name}={value}"
                for name, value in broker_host._compose_run_once_labels(target)
            ),
        )
        override = json.loads(tuple(captured["compose_payloads"])[-1])
        self.assertEqual(set(override["services"]), {"ingestion-once"})
        service = override["services"]["ingestion-once"]
        self.assertEqual(service["image"], _SuccessfulRunOnceHost.image_id)
        self.assertEqual(service["pull_policy"], "never")
        self.assertEqual(service["mem_limit"], "20g")
        self.assertEqual(service["cpus"], "8.0")
        self.assertEqual(service["pids_limit"], 4096)
        self.assertEqual(service["restart"], "no")
        self.assertIs(service["stdin_open"], False)
        self.assertIs(service["tty"], False)
        self.assertNotIn("--env", command)
        self.assertNotIn("--volume", command)

    def test_host_inspection_requires_exact_identity_labels_and_limits(self) -> None:
        _authorized, target = self._reserved_create_target()
        labels = broker_host._compose_run_once_labels(target)

        def inspect_output(*, wrong_label: bool = False) -> str:
            values = [value for _name, value in labels]
            if wrong_label:
                values[3] = "another-service"
            return "\n".join(
                (
                    _SuccessfulRunOnceHost.container_id,
                    "/" + target.container_name,
                    _SuccessfulRunOnceHost.image_id,
                    "created",
                    "0",
                    broker_host._project_slice(
                        owner_uid=target.compose.owner_uid,
                        repository_id=target.compose.repo_id,
                    ),
                    str(20 * 1024 * 1024 * 1024),
                    "8000000000",
                    "4096",
                    "no",
                    "false",
                    "false",
                    *values,
                )
            )

        observed_output = inspect_output()

        def docker_runner(_command, _timeout):
            return subprocess.CompletedProcess(
                (),
                0,
                observed_output,
                "",
            )

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker",
            docker_runner=docker_runner,
        )
        observed = host.compose_run_once_inspect_container(
            target,
            full_container_id=_SuccessfulRunOnceHost.container_id,
        )
        self.assertEqual(observed["status"], "created")

        observed_output = inspect_output(wrong_label=True)
        with self.assertRaisesRegex(
            BrokerBackendError,
            "sealed identity",
        ):
            host.compose_run_once_inspect_container(
                target,
                full_container_id=_SuccessfulRunOnceHost.container_id,
            )

    def test_cleanup_replay_accepts_proved_absence_without_second_remove(
        self,
    ) -> None:
        _authorized, create_target = self._reserved_create_target()
        target = replace(
            create_target,
            phase="cleanup_intent",
            full_container_id=_SuccessfulRunOnceHost.container_id,
        )
        commands: list[tuple[str, ...]] = []

        def docker_runner(command, _timeout):
            commands.append(tuple(command))
            return subprocess.CompletedProcess(command, 0, "", "")

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker",
            docker_runner=docker_runner,
        )
        result = host.compose_run_once_remove_container(target)

        self.assertEqual(
            result,
            {
                "removed": True,
                "full_container_id": _SuccessfulRunOnceHost.container_id,
            },
        )
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][1:4], ("container", "ls", "--all"))


if __name__ == "__main__":
    unittest.main()
