from __future__ import annotations

from dataclasses import replace
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import textwrap
from types import SimpleNamespace
import time
import unittest
from unittest import mock

from devcoordinator.universal_test_runner import (
    DotnetProbeResult,
    _capture,
    _dotnet_readiness,
    _dotnet_restore_project,
    _dotnet_restore_semantic_options,
    _jsonl_cases,
    _load,
    _run_dotnet_probe,
    _trx_cases,
    adapt_driver_invocation,
    run,
)
from devcoordinator.universal_test_result_package import (
    RESULT_PACKAGE_FILE_NAME,
    copy_result_package_artifact,
    iter_result_package_records,
    validate_result_package,
)
from devcoordinator.universal_test_runtime import (
    SystemdTestAttemptManager,
    TestAttemptDescriptor,
)
from devcoordinator.universal_test_store import (
    TestStoreConflict,
    TestStoreContractError,
)


class UniversalTestRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repo"
        self.output = Path(self.temporary.name) / "output"
        self.root.mkdir(mode=0o700)
        self.output.mkdir(mode=0o700)

    def descriptor(self, argv: tuple[str, ...]) -> TestAttemptDescriptor:
        return TestAttemptDescriptor(
            execution_id="execution-runner-evidence",
            target_id="target-runner-evidence",
            run_id="run-runner-evidence",
            repository_id="repo-runner-evidence",
            repository_generation=1,
            owner_uid=os.geteuid(),
            generation=1,
            source_mode="live",
            snapshot_id=None,
            original_root=str(self.root),
            temporary_root=None,
            execution_root=str(self.root),
            worktree_key=str(self.root),
            target_name="automation",
            shard_index=0,
            shard_count=1,
            argv=argv,
            cwd=".",
            environment={},
            driver="automation",
            reporter="automation-events",
            artifacts=(),
            fixtures=(),
            network="none",
            ttl_seconds=30,
        )

    def test_jsonl_reporter_accepts_blank_zero_case_stream(self) -> None:
        report = self.output / "reporter.events.jsonl"
        report.write_text("\n  \n", encoding="utf-8")
        self.assertEqual(_jsonl_cases(report), ([], []))
        report.write_text(
            "\n" + json.dumps({"id": "case-1", "status": "passed"}) + "\n\n",
            encoding="utf-8",
        )
        cases, failures = _jsonl_cases(report)
        self.assertEqual([item["case_id"] for item in cases], ["case-1"])
        self.assertEqual(failures, [])
        report.write_text("\nnot-json\n", encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            _jsonl_cases(report)

    def result_cases(self, result_path: Path) -> list[dict[str, object]]:
        return list(
            iter_result_package_records(
                validate_result_package(result_path), "cases"
            )
        )

    def result_package_content(self, result_path: Path) -> dict[str, object]:
        package = validate_result_package(result_path)
        return {
            "cases": list(iter_result_package_records(package, "cases")),
            "failures": list(
                iter_result_package_records(package, "failures")
            ),
            "artifacts": list(package.manifest["artifacts"]),
            "reporter_complete": package.manifest["outcome"][
                "reporter_complete"
            ],
        }

    def result_failures(self, result_path: Path) -> list[dict[str, object]]:
        return list(self.result_package_content(result_path)["failures"])

    def result_document(self, result_path: Path) -> dict[str, object]:
        package = validate_result_package(result_path)
        manifest = package.manifest
        return {
            "schema_version": manifest["schema_version"],
            **dict(manifest["identity"]),
            **dict(manifest["outcome"]),
            **dict(manifest["resource_usage"]),
            "counts": dict(manifest["counts"]),
            "captures": dict(manifest["captures"]),
            "artifacts": list(manifest["artifacts"]),
            "package_sha256": package.evidence.sha256,
        }

    def result_artifact_bytes(self, result_path: Path, artifact_id: str) -> bytes:
        package = validate_result_package(result_path)
        destination = io.BytesIO()
        copy_result_package_artifact(package, artifact_id, destination)
        return destination.getvalue()

    def fake_dotnet(self, source: str) -> Path:
        executable = self.root / "fake-dotnet"
        executable.write_text(
            "#!/usr/bin/python3\n" + textwrap.dedent(source),
            encoding="utf-8",
        )
        executable.chmod(0o700)
        return executable

    def immutable_dotnet_descriptor(
        self, argv: tuple[str, ...], *, cwd: str = "."
    ) -> TestAttemptDescriptor:
        account_home = Path(self.temporary.name) / "dotnet-account"
        package_cache = account_home / ".nuget" / "packages"
        package_cache.mkdir(parents=True, mode=0o700)
        mounted_source = (
            self.root / ".devcoordinator-dependencies" / "nuget-source"
        )
        mounted_package = mounted_source / "demo.package" / "1.0.0"
        mounted_package.mkdir(parents=True, mode=0o700)
        (mounted_package / "demo.package.1.0.0.nupkg").write_bytes(
            b"sealed-local-feed-package"
        )
        cache_identity = package_cache.stat()
        dependency_lock = "a" * 64
        binding = {
            "kind": "dotnet-packages",
            "source_root": str(package_cache),
            "source_device": cache_identity.st_dev,
            "source_inode": cache_identity.st_ino,
            "destination": ".devcoordinator-dependencies/nuget-source",
            "locks": {"packages.lock.json": dependency_lock},
            "marker_path": None,
            "marker_sha256": None,
            "executable": None,
            "installation_kind": "nuget-package-source",
            "installation_sha256": "b" * 64,
            "installation_files": 2,
            "installation_bytes": 2,
            "toolchain": None,
        }
        account = SimpleNamespace(
            pw_uid=os.geteuid(),
            pw_dir=str(account_home),
        )
        with mock.patch(
            "devcoordinator.universal_test_runtime.pwd.getpwall",
            return_value=[account],
        ):
            return replace(
                self.descriptor(argv),
                source_mode="immutable",
                snapshot_id="snapshot-runner-dotnet-immutable",
                driver="dotnet",
                reporter="trx",
                target_name="dotnet-immutable",
                cwd=cwd,
                environment={
                    "DEVCOORDINATOR_NUGET_SOURCE": str(mounted_source)
                },
                source_provenance={
                    "complete": True,
                    "content_fingerprint": "c" * 64,
                    "manifest_fingerprint": "d" * 64,
                    "dependency_locks": {
                        "packages.lock.json": dependency_lock,
                    },
                    "toolchain": {},
                },
                dependency_bindings=(binding,),
            )

    def result_diagnostic(
        self, descriptor: TestAttemptDescriptor, result_path: Path
    ) -> str:
        paths = (
            self.output / f"{descriptor.execution_id}-stdout.log",
            self.output / f"{descriptor.execution_id}-stderr.log",
        )
        values: dict[str, str] = {}
        for path in paths:
            if path.is_file():
                values[path.name] = path.read_text(
                    encoding="utf-8", errors="replace"
                )[-8000:]
        if result_path.is_file():
            package = validate_result_package(result_path)
            values["manifest.json"] = json.dumps(
                package.manifest, sort_keys=True, default=dict
            )[-8000:]
            values["failures.ndjson"] = json.dumps(
                list(iter_result_package_records(package, "failures")),
                sort_keys=True,
            )[-8000:]
        return json.dumps(values, indent=2, sort_keys=True)

    def test_systemd_manager_ticketed_launch_loads_exact_runner_contract(self) -> None:
        descriptor = self.descriptor(("/usr/bin/python3", "-c", "pass"))
        attempt_root = Path(self.temporary.name) / "attempts"
        state = attempt_root / "devcoordinator-test-ticketed-launch"
        state.mkdir(parents=True, mode=0o700)
        manager = SystemdTestAttemptManager(
            attempt_root=attempt_root,
            artifact_root=Path(self.temporary.name) / "artifacts",
        )

        launch_path, expected_result_path = manager._publish_runner_launch(
            descriptor,
            state=state,
            execution_root=self.root,
            owner_gid=os.getegid(),
            launch_ticket_id="test-ticket-runner-contract",
        )

        published = json.loads(launch_path.read_text(encoding="utf-8"))
        self.assertEqual(
            set(published),
            {
                "schema_version",
                "descriptor",
                "descriptor_fingerprint",
                "output_root",
                "result_path",
                "launch_ticket_id",
            },
        )
        self.assertEqual(published["schema_version"], 2)
        self.assertEqual(
            published["launch_ticket_id"], "test-ticket-runner-contract"
        )

        loaded_descriptor, loaded_output, loaded_result = _load(launch_path)
        self.assertEqual(loaded_descriptor, descriptor)
        self.assertEqual(loaded_output, state / "output")
        self.assertEqual(loaded_result, expected_result_path)

    def test_fixture_launch_preserves_typed_provider_cause_without_raw_secrets(
        self,
    ) -> None:
        class TypedFailure(RuntimeError):
            code = "fixture_image_unavailable"
            message = "sealed fixture image is not cached"

        class Provider:
            def provision(self, _descriptor, *, runtime_id):
                del runtime_id
                raise TypedFailure("credential=must-not-leak")

            def cleanup(self, *, runtime_id, descriptor_fingerprint, reason):
                del runtime_id, descriptor_fingerprint, reason

        descriptor = replace(
            self.descriptor(("/usr/bin/python3", "-c", "pass")),
            fixtures=("postgres",),
            fixture_bindings=(
                {
                    "name": "postgres",
                    "template": "artifact-postgres",
                    "network": "loopback",
                },
            ),
        )
        manager = SystemdTestAttemptManager(
            attempt_root=Path(self.temporary.name) / "fixture-attempts",
            artifact_root=Path(self.temporary.name) / "fixture-artifacts",
            fixture_provider=Provider(),
        )

        with self.assertRaisesRegex(
            TestStoreConflict,
            "fixture_image_unavailable: sealed fixture image is not cached",
        ) as raised:
            manager._provision_fixture_descriptor(
                descriptor, runtime_id="devcoordinator-test-fixture-cause"
            )
        self.assertNotIn("must-not-leak", str(raised.exception))

    def test_runner_load_accepts_legacy_launch_and_rejects_invalid_ticket_shape(self) -> None:
        descriptor = self.descriptor(("/usr/bin/python3", "-c", "pass"))
        attempt_root = Path(self.temporary.name) / "legacy-attempts"
        state = attempt_root / "devcoordinator-test-legacy-launch"
        state.mkdir(parents=True, mode=0o700)
        manager = SystemdTestAttemptManager(
            attempt_root=attempt_root,
            artifact_root=Path(self.temporary.name) / "legacy-artifacts",
        )
        launch_path, expected_result_path = manager._publish_runner_launch(
            descriptor,
            state=state,
            execution_root=self.root,
            owner_gid=os.getegid(),
        )

        loaded_descriptor, loaded_output, loaded_result = _load(launch_path)
        self.assertEqual(loaded_descriptor, descriptor)
        self.assertEqual(loaded_output, state / "output")
        self.assertEqual(loaded_result, expected_result_path)

        invalid = json.loads(launch_path.read_text(encoding="utf-8"))
        invalid["schema_version"] = 2
        invalid["launch_ticket_id"] = "ticket-without-required-prefix"
        invalid_path = state / "invalid-launch.json"
        invalid_path.write_text(
            json.dumps(invalid, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            TestStoreContractError, "runner launch descriptor fields are invalid"
        ):
            _load(invalid_path)

    def test_process_captures_are_verified_artifacts_and_nonzero_has_failure(self) -> None:
        descriptor = self.descriptor(
            (
                "/usr/bin/python3",
                "-c",
                "import sys;sys.stdout.write('out');sys.stderr.write('err');sys.exit(7)",
            )
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME

        self.assertEqual(run(descriptor, self.output, result_path), 1)

        result = self.result_document(result_path)
        self.assertEqual(result["schema_version"], 1)
        self.assertIsInstance(result["peak_memory_bytes"], int)
        self.assertGreater(result["peak_memory_bytes"], 0)
        self.assertIsInstance(result["cpu_seconds"], float)
        self.assertGreaterEqual(result["cpu_seconds"], 0.0)
        artifacts = result["artifacts"]
        self.assertEqual({item["kind"] for item in artifacts}, {"log", "trace"})
        self.assertEqual(len(artifacts), 3)
        self.assertTrue(
            all(
                item["storage_handle"].startswith(
                    f"test-artifact://{item['artifact_id']}/"
                )
                for item in artifacts
            )
        )
        self.assertTrue(
            all("/tmp/" not in item["storage_handle"] for item in artifacts)
        )
        stdout = result["captures"]["stdout"]
        stderr = result["captures"]["stderr"]
        self.assertEqual(stdout["retained_sha256"], hashlib.sha256(b"out").hexdigest())
        self.assertEqual(stderr["retained_sha256"], hashlib.sha256(b"err").hexdigest())
        failure = next(
            item
            for item in self.result_failures(result_path)
            if item["classification"] == "test_failure"
        )
        self.assertIn("status 7", failure["message"])
        self.assertEqual(failure["artifact_id"], stderr["artifact_id"])
        self.assertTrue(
            any(item["artifact_id"] == failure["artifact_id"] for item in artifacts)
        )
        provenance = json.loads(
            (self.output / "execution-provenance.json").read_text(encoding="utf-8")
        )
        self.assertEqual(provenance["repository_id"], descriptor.repository_id)
        self.assertEqual(provenance["source"], {"mode": "live", "snapshot_id": None})
        self.assertEqual(provenance["target"]["shard_count"], 1)
        self.assertEqual(len(provenance["executable"]["sha256"]), 64)
        self.assertNotIn(str(self.root), json.dumps(provenance))

        for item in artifacts:
            payload = self.result_artifact_bytes(result_path, item["artifact_id"])
            self.assertEqual(hashlib.sha256(payload).hexdigest(), item["sha256"])
            self.assertEqual(len(payload), item["size_bytes"])

    def test_capture_progress_advances_after_retained_artifact_cap(self) -> None:
        destination = self.output / "bounded.log"
        state: dict[str, object] = {}
        payload = b"x" * 192

        with mock.patch(
            "devcoordinator.universal_test_runner.MAX_CAPTURE_BYTES", 64
        ):
            _capture(io.BytesIO(payload), destination, state)

        progress = json.loads(
            destination.with_name(destination.name + ".progress.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(destination.stat().st_size, 64)
        self.assertEqual(progress["observed_bytes"], len(payload))
        self.assertEqual(progress["retained_bytes"], 64)
        self.assertTrue(progress["truncated"])
        self.assertIsInstance(progress["last_output_at"], float)
        self.assertEqual(state["observed_bytes"], len(payload))
        self.assertTrue(state["truncated"])

    def test_failed_automation_links_declared_directory_text_diagnostic(self) -> None:
        descriptor = replace(
            self.descriptor(
                (
                    "/usr/bin/python3",
                    "-c",
                    "import pathlib,sys; d=pathlib.Path('diagnostics'); d.mkdir(); "
                    f"(d/'database.log').write_text('connection refused at {self.root}/data\\n'); "
                    "(d/'image.bin').write_bytes(b'\\x00\\x01'); "
                    "sys.stderr.write('build warning\\n'); sys.exit(1)",
                )
            ),
            driver="automation",
            reporter="automation-events",
            artifacts=(
                {
                    "name": "diagnostics",
                    "path": "diagnostics",
                    "kind": "directory",
                    "required": True,
                    "max_bytes": 1024 * 1024,
                },
            ),
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME

        self.assertEqual(run(descriptor, self.output, result_path), 1)

        result = self.result_document(result_path)
        artifacts = result["artifacts"]
        failures = self.result_failures(result_path)
        failure = next(
            item
            for item in failures
            if item["classification"] == "test_failure"
        )
        diagnostic = next(
            item for item in artifacts if item["artifact_id"] == failure["artifact_id"]
        )
        self.assertEqual(diagnostic["kind"], "log")
        payload = self.result_artifact_bytes(
            result_path, diagnostic["artifact_id"]
        ).decode("utf-8")
        self.assertIn("== database.log ==", payload)
        self.assertIn("connection refused", payload)
        self.assertIn("<repository>/data", payload)
        self.assertNotIn("image.bin", payload)
        self.assertNotIn(str(self.root), payload)

    def test_missing_declared_executable_publishes_bounded_infrastructure_result(self) -> None:
        missing = self.root / ".venv-v2" / "bin" / "python"
        descriptor = self.descriptor((str(missing.relative_to(self.root)), "-V"))
        result_path = self.output / RESULT_PACKAGE_FILE_NAME

        self.assertEqual(run(descriptor, self.output, result_path), 1)

        result = self.result_document(result_path)
        failures = self.result_failures(result_path)
        failure = self.assert_single_infrastructure_failure(failures)
        self.assertEqual(failure["location"], "runner/bootstrap")
        self.assertIsInstance(failure["artifact_id"], str)
        self.assertIn("could not be started", failure["message"])
        self.assertFalse(any(item["classification"] == "test_failure" for item in failures))
        self.assertEqual(result["returncode"], 127)
        self.assertTrue(result["incomplete_reporting"])
        stderr = (self.output / f"{descriptor.execution_id}-stderr.log").read_text(
            encoding="utf-8"
        )
        self.assertIn("FileNotFoundError", stderr)
        self.assertLessEqual(len(stderr.encode("utf-8")), 4096)

    def assert_single_infrastructure_failure(
        self, failures: list[dict[str, object]]
    ) -> dict[str, object]:
        infrastructure = [
            item
            for item in failures
            if item["classification"] == "infrastructure_failure"
        ]
        self.assertEqual(len(infrastructure), 1)
        return infrastructure[0]

    def test_declared_artifact_with_secret_material_is_never_published(self) -> None:
        secret = "github_pat_" + "Z" * 30
        artifact = self.root / "trace.log"
        artifact.write_text(f"trace {secret}\n", encoding="utf-8")
        descriptor = replace(
            self.descriptor(
                (
                    "/usr/bin/python3",
                    "-c",
                    "import os,pathlib; value=os.environ['CREDENTIALS_DIRECTORY']; "
                    "assert pathlib.Path(value).is_absolute(); "
                    "assert value==os.environ['DEVCOORDINATOR_FIXTURE_DIRECTORY']",
                )
            ),
            artifacts=(
                {
                    "name": "trace",
                    "path": "trace.log",
                    "kind": "trace",
                    "required": True,
                    "max_bytes": 4096,
                },
            ),
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME
        self.assertEqual(run(descriptor, self.output, result_path), 1)
        result = self.result_document(result_path)
        self.assertNotIn(secret, json.dumps(result))
        self.assertFalse(any(item["sha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest() for item in result["artifacts"]))
        self.assertTrue(
            any(
                "suspected secret material" in failure["message"]
                for failure in self.result_failures(result_path)
            )
        )

    def test_collected_unit_uses_durable_runner_resource_measurements(self) -> None:
        descriptor = self.descriptor(("/usr/bin/python3", "-c", "pass"))
        result_path = self.output / RESULT_PACKAGE_FILE_NAME
        self.assertEqual(run(descriptor, self.output, result_path), 0)
        expected = self.result_document(result_path)

        runtime_id = "devcoordinator-test-collected-usage"
        attempt_root = Path(self.temporary.name) / "collected-attempts"
        state_root = attempt_root / runtime_id
        state_root.mkdir(parents=True)
        shutil.copytree(self.output, state_root / "output", copy_function=shutil.copy2)
        (state_root / "launch.json").write_text(
            json.dumps({"descriptor": descriptor.to_document()}),
            encoding="utf-8",
        )

        def collected(_argv, **_kwargs):
            return subprocess.CompletedProcess(_argv, 1, "", "unit collected")

        manager = SystemdTestAttemptManager(
            attempt_root=attempt_root,
            artifact_root=Path(self.temporary.name) / "collected-artifacts",
            runner=collected,
        )
        observed = manager.status(runtime_id)

        self.assertEqual(observed.state, "collected")
        self.assertEqual(
            observed.peak_memory_bytes,
            expected["peak_memory_bytes"],
        )
        self.assertEqual(observed.cpu_seconds, expected["cpu_seconds"])

    def test_successful_not_found_observation_drains_durable_result(self) -> None:
        descriptor = self.descriptor(("/usr/bin/python3", "-c", "pass"))
        result_path = self.output / RESULT_PACKAGE_FILE_NAME
        self.assertEqual(run(descriptor, self.output, result_path), 0)
        expected = self.result_document(result_path)

        runtime_id = "devcoordinator-test-collected-not-found"
        attempt_root = Path(self.temporary.name) / "not-found-attempts"
        state_root = attempt_root / runtime_id
        state_root.mkdir(parents=True)
        shutil.copytree(self.output, state_root / "output", copy_function=shutil.copy2)
        (state_root / "launch.json").write_text(
            json.dumps({"descriptor": descriptor.to_document()}),
            encoding="utf-8",
        )

        def collected(_argv, **_kwargs):
            stdout = "\n".join((
                "LoadState=not-found",
                "ActiveState=inactive",
                "SubState=dead",
                "Result=success",
                "ExecMainCode=0",
                "ExecMainStatus=0",
                "OOMKilled=no",
            ))
            return subprocess.CompletedProcess(_argv, 0, stdout, "")

        manager = SystemdTestAttemptManager(
            attempt_root=attempt_root,
            artifact_root=Path(self.temporary.name) / "not-found-artifacts",
            runner=collected,
        )
        observed = manager.status(runtime_id)

        self.assertEqual(observed.state, "collected")
        self.assertEqual(observed.exit_status, expected["returncode"])
        self.assertEqual(observed.result_document, expected)
        self.assertEqual(observed.termination_reason, "success")

    def test_loaded_unit_prefers_cgroup_usage_over_runner_fallback(self) -> None:
        descriptor = self.descriptor(("/usr/bin/python3", "-c", "pass"))
        result_path = self.output / RESULT_PACKAGE_FILE_NAME
        self.assertEqual(run(descriptor, self.output, result_path), 0)

        runtime_id = "devcoordinator-test-cgroup-usage"
        attempt_root = Path(self.temporary.name) / "cgroup-attempts"
        state_root = attempt_root / runtime_id
        state_root.mkdir(parents=True)
        shutil.copytree(self.output, state_root / "output", copy_function=shutil.copy2)
        (state_root / "launch.json").write_text(
            json.dumps({"descriptor": descriptor.to_document()}),
            encoding="utf-8",
        )

        def observed(_argv, **_kwargs):
            stdout = "\n".join((
                "LoadState=loaded",
                "ActiveState=inactive",
                "SubState=dead",
                "Result=success",
                "ExecMainCode=1",
                "ExecMainStatus=0",
                "OOMKilled=no",
                "CPUUsageNSec=3500000000",
                "MemoryPeak=234881024",
                "MemoryCurrent=0",
            ))
            return subprocess.CompletedProcess(_argv, 0, stdout, "")

        manager = SystemdTestAttemptManager(
            attempt_root=attempt_root,
            artifact_root=Path(self.temporary.name) / "cgroup-artifacts",
            runner=observed,
        )
        state = manager.status(runtime_id)

        self.assertEqual(state.peak_memory_bytes, 224 * 1024 * 1024)
        self.assertEqual(state.cpu_seconds, 3.5)
        self.assertIsNone(state.current_memory_bytes)

    def test_active_unit_exposes_atomic_runner_result_for_terminal_convergence(self) -> None:
        descriptor = self.descriptor(("/usr/bin/python3", "-c", "pass"))
        result_path = self.output / RESULT_PACKAGE_FILE_NAME
        self.assertEqual(run(descriptor, self.output, result_path), 0)
        expected = self.result_document(result_path)
        runtime_id = "devcoordinator-test-active-result"
        attempt_root = Path(self.temporary.name) / "active-result-attempts"
        state_root = attempt_root / runtime_id
        state_root.mkdir(parents=True)
        shutil.copytree(self.output, state_root / "output", copy_function=shutil.copy2)
        (state_root / "launch.json").write_text(
            json.dumps({"descriptor": descriptor.to_document()}),
            encoding="utf-8",
        )

        def active(_argv, **_kwargs):
            stdout = "\n".join((
                "LoadState=loaded",
                "ActiveState=deactivating",
                "SubState=stop-sigterm",
                "Result=success",
                "ExecMainCode=0",
                "ExecMainStatus=0",
                "OOMKilled=no",
                "CPUUsageNSec=3500000000",
                "MemoryPeak=234881024",
                "MemoryCurrent=1048576",
            ))
            return subprocess.CompletedProcess(_argv, 0, stdout, "")

        manager = SystemdTestAttemptManager(
            attempt_root=attempt_root,
            artifact_root=Path(self.temporary.name) / "active-result-artifacts",
            runner=active,
        )

        observed = manager.status(runtime_id)

        self.assertTrue(observed.active)
        self.assertEqual(observed.result_document, expected)
        self.assertEqual(observed.current_memory_bytes, 1024 * 1024)

    def test_active_unit_recovers_nonextending_start_from_legacy_launch_time(self) -> None:
        descriptor = self.descriptor(("/usr/bin/python3", "-c", "pass"))
        runtime_id = "devcoordinator-test-recovered-start"
        attempt_root = Path(self.temporary.name) / "recovered-start-attempts"
        state_root = attempt_root / runtime_id
        state_root.mkdir(parents=True)
        launch_path = state_root / "launch.json"
        launch_path.write_text(
            json.dumps({"descriptor": descriptor.to_document()}),
            encoding="utf-8",
        )
        os.utime(launch_path, (12.5, 12.5))
        manager = SystemdTestAttemptManager(
            attempt_root=attempt_root,
            artifact_root=Path(self.temporary.name) / "recovered-start-artifacts",
        )

        self.assertEqual(manager._attempt_started_at(runtime_id), 12.5)
        self.assertEqual(manager._started[runtime_id], 12.5)

    def test_active_unit_exposes_bounded_output_growth_without_content(self) -> None:
        descriptor = self.descriptor(("/usr/bin/python3", "-c", "pass"))
        runtime_id = "devcoordinator-test-active-progress"
        attempt_root = Path(self.temporary.name) / "active-progress-attempts"
        state_root = attempt_root / runtime_id
        output = state_root / "output"
        output.mkdir(parents=True)
        (state_root / "launch.json").write_text(
            json.dumps({"descriptor": descriptor.to_document()}),
            encoding="utf-8",
        )
        (output / f"{descriptor.execution_id}-stdout.log").write_bytes(b"progress\n")
        (output / f"{descriptor.execution_id}-stderr.log").write_bytes(b"warn\n")

        def active(_argv, **_kwargs):
            stdout = "\n".join((
                "LoadState=loaded",
                "ActiveState=active",
                "SubState=running",
                "Result=",
                "ExecMainCode=0",
                "ExecMainStatus=0",
                "OOMKilled=no",
                "CPUUsageNSec=1000000",
                "MemoryPeak=1048576",
                "MemoryCurrent=524288",
            ))
            return subprocess.CompletedProcess(_argv, 0, stdout, "")

        manager = SystemdTestAttemptManager(
            attempt_root=attempt_root,
            artifact_root=Path(self.temporary.name) / "active-progress-artifacts",
            runner=active,
        )

        observed = manager.status(runtime_id)

        self.assertEqual(observed.output_progress["stdout_bytes"], 9)
        self.assertEqual(observed.output_progress["stderr_bytes"], 5)
        self.assertEqual(observed.output_progress["stdout_retained_bytes"], 9)
        self.assertFalse(observed.output_progress["stdout_truncated"])
        self.assertNotIn("progress", json.dumps(observed.output_progress))

        stdout_progress = output / (
            f"{descriptor.execution_id}-stdout.log.progress.json"
        )
        stdout_progress.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "observed_bytes": 5 * 1024 * 1024,
                    "retained_bytes": 9,
                    "truncated": True,
                    "last_output_at": time.time(),
                }
            ),
            encoding="utf-8",
        )
        capped = manager.status(runtime_id)
        self.assertEqual(capped.output_progress["stdout_bytes"], 5 * 1024 * 1024)
        self.assertEqual(capped.output_progress["stdout_retained_bytes"], 9)
        self.assertTrue(capped.output_progress["stdout_truncated"])

    def test_source_toolchain_and_fixture_provenance_are_exact_and_nonsecret(self) -> None:
        credentials = Path(self.temporary.name) / "credentials"
        credentials.mkdir(mode=0o700)
        (credentials / "fixtures.json").write_text(
            '[{"host":"127.0.0.1","name":"postgres","port":5432,'
            '"secret_credential":"fixture-secret-postgres"}]',
            encoding="utf-8",
        )
        secret = b"fixture-secret-not-for-provenance"
        (credentials / "fixture-secret-postgres").write_bytes(secret)
        fixture_provenance = [
            {
                "name": "postgres",
                "template_id": "artifact-postgres",
                "template_fingerprint": "sha256:" + "a" * 64,
                "image_ref": "postgres@sha256:" + "b" * 64,
                "full_container_id": "c" * 64,
                "network": "private-loopback",
                "secret_delivery": True,
            }
        ]
        (credentials / "fixture-provenance.json").write_text(
            json.dumps(fixture_provenance, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        descriptor = replace(
            self.descriptor(("/usr/bin/python3", "-c", "pass")),
            fixtures=("postgres",),
            fixture_bindings=(
                {
                    "name": "postgres",
                    "template": "artifact-postgres",
                    "network": "loopback",
                },
            ),
            source_provenance={
                "complete": True,
                "content_fingerprint": "d" * 64,
                "manifest_fingerprint": "e" * 64,
                "dependency_locks": {"requirements.lock": "f" * 64},
                "toolchain": {"python": "3.13"},
            },
        )
        with mock.patch.dict(
            os.environ, {"CREDENTIALS_DIRECTORY": str(credentials)}
        ):
            self.assertEqual(
                run(descriptor, self.output, self.output / RESULT_PACKAGE_FILE_NAME),
                0,
            )
        provenance = json.loads(
            (self.output / "execution-provenance.json").read_text(encoding="utf-8")
        )
        self.assertEqual(provenance["fixtures"], fixture_provenance)
        self.assertEqual(
            provenance["toolchain"]["source"], descriptor.source_provenance
        )
        self.assertEqual(len(provenance["executable"]["sha256"]), 64)
        self.assertNotIn(secret.decode("utf-8"), json.dumps(provenance))

    def test_declared_hardlink_artifact_is_published_by_exact_digest(self) -> None:
        unrelated = Path(self.temporary.name) / "unrelated-account-evidence"
        unrelated.write_text("must remain private\n", encoding="utf-8")
        artifact = self.root / "trace.log"
        os.link(unrelated, artifact)
        descriptor = replace(
            self.descriptor(("/usr/bin/python3", "-c", "pass")),
            artifacts=(
                {
                    "name": "trace",
                    "path": "trace.log",
                    "kind": "trace",
                    "required": True,
                    "max_bytes": 4096,
                },
            ),
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME

        self.assertEqual(run(descriptor, self.output, result_path), 0)

        result = self.result_document(result_path)
        expected_digest = hashlib.sha256(b"must remain private\n").hexdigest()
        trace = next(
            item
            for item in result["artifacts"]
            if item["kind"] == "trace" and item["sha256"] == expected_digest
        )
        self.assertEqual(
            self.result_artifact_bytes(result_path, trace["artifact_id"]),
            b"must remain private\n",
        )
        self.assertEqual(unrelated.read_text(encoding="utf-8"), "must remain private\n")

    def test_directory_artifact_is_deterministic_and_embedded(self) -> None:
        directory = self.root / "reports"
        (directory / "nested").mkdir(parents=True)
        (directory / "z.txt").write_text("zeta\n", encoding="utf-8")
        (directory / "nested" / "a.txt").write_text("alpha\n", encoding="utf-8")
        descriptor = replace(
            self.descriptor(("/usr/bin/python3", "-c", "pass")),
            artifacts=(
                {
                    "name": "reports",
                    "path": "reports",
                    "kind": "directory",
                    "required": True,
                    "max_bytes": 1024 * 1024,
                },
            ),
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME
        outcome = run(descriptor, self.output, result_path)
        self.assertEqual(
            outcome,
            0,
            self.result_diagnostic(descriptor, result_path),
        )
        result = self.result_document(result_path)
        directory_source = next(
            item for item in result["artifacts"] if item["kind"] == "directory"
        )
        original_archive = self.result_artifact_bytes(
            result_path, directory_source["artifact_id"]
        )
        self.assertEqual(hashlib.sha256(original_archive).hexdigest(), directory_source["sha256"])

        second = Path(self.temporary.name) / "second-output"
        second.mkdir(mode=0o700)
        self.assertEqual(run(descriptor, second, second / RESULT_PACKAGE_FILE_NAME), 0)
        second_result = validate_result_package(second / RESULT_PACKAGE_FILE_NAME).manifest
        second_source = next(
            item
            for item in second_result["artifacts"]
            if item["kind"] == "directory"
        )
        self.assertEqual(directory_source["sha256"], second_source["sha256"])
        self.assertEqual(directory_source["size_bytes"], second_source["size_bytes"])

    def test_directory_artifact_rejects_links_and_secret_material(self) -> None:
        directory = self.root / "reports"
        directory.mkdir()
        outside = self.root / "outside.txt"
        outside.write_text("not public\n", encoding="utf-8")
        (directory / "link").symlink_to(outside)
        descriptor = replace(
            self.descriptor(("/usr/bin/python3", "-c", "pass")),
            artifacts=(
                {
                    "name": "reports",
                    "path": "reports",
                    "kind": "directory",
                    "required": True,
                    "max_bytes": 1024 * 1024,
                },
            ),
        )
        self.assertEqual(
            run(descriptor, self.output, self.output / RESULT_PACKAGE_FILE_NAME), 1
        )
        result = validate_result_package(
            self.output / RESULT_PACKAGE_FILE_NAME
        ).manifest
        self.assertFalse(any(item["kind"] == "directory" for item in result["artifacts"]))

        (directory / "link").unlink()
        (directory / "secret.txt").write_text(
            "github_pat_" + "Q" * 30, encoding="utf-8"
        )
        second = Path(self.temporary.name) / "secret-output"
        second.mkdir(mode=0o700)
        self.assertEqual(run(descriptor, second, second / RESULT_PACKAGE_FILE_NAME), 1)
        second_result = validate_result_package(second / RESULT_PACKAGE_FILE_NAME).manifest
        self.assertFalse(
            any(item["kind"] == "directory" for item in second_result["artifacts"])
        )

    def test_runner_retains_failure_details_beyond_legacy_sample_cap(self) -> None:
        executable = self.root / "many-failures"
        executable.write_text(
            """#!/usr/bin/python3
from pathlib import Path
import sys

destination = Path(sys.argv[sys.argv.index('--junitxml') + 1])
results = ''.join(
    f'<testcase name="case-{index}"><failure>failure {index}</failure></testcase>'
    for index in range(130)
)
destination.write_text(f'<testsuite>{results}</testsuite>', encoding='utf-8')
raise SystemExit(1)
""",
            encoding="utf-8",
        )
        executable.chmod(0o755)
        descriptor = replace(
            self.descriptor((str(executable),)),
            driver="pytest",
            reporter="pytest-events",
            target_name="many-failures",
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME

        self.assertEqual(run(descriptor, self.output, result_path), 1)

        failures = self.result_failures(result_path)
        cases = self.result_cases(result_path)
        self.assertEqual(len(cases), 130)
        self.assertEqual(len(failures), 130)
        self.assertEqual(
            {failure["case_id"] for failure in failures},
            {case["case_id"] for case in cases},
        )
        self.assertEqual(
            self.result_package_content(result_path)["failures"], failures
        )
        self.assertEqual(self.result_document(result_path)["counts"]["failures"], 130)

    def test_typed_drivers_receive_fixed_reporter_adapters(self) -> None:
        base = self.descriptor(("/usr/bin/python3", "-m", "pytest", "tests"))
        pytest_argv, _, pytest_reporter, pytest_kind = adapt_driver_invocation(
            replace(base, driver="pytest", reporter="pytest-events"), self.output
        )
        self.assertEqual(pytest_argv[-2], "--junitxml")
        self.assertEqual(pytest_argv[-1], str(pytest_reporter))
        self.assertEqual(pytest_kind, "junit")

        node = replace(
            base,
            argv=("/usr/bin/node", "--test"),
            driver="node",
            reporter="jsonl",
        )
        node_argv, node_environment, node_reporter, node_kind = adapt_driver_invocation(
            node, self.output
        )
        self.assertNotIn("DEVCOORDINATOR_TEST_EVENTS", node_environment)
        self.assertIn("--test-reporter=junit", node_argv)
        self.assertIn(
            f"--test-reporter-destination={node_reporter}", node_argv
        )
        self.assertEqual(node_kind, "junit")

        dotnet = replace(
            base,
            argv=("/usr/bin/dotnet", "test"),
            driver="dotnet",
            reporter="trx",
        )
        dotnet_argv, dotnet_environment, dotnet_reporter, dotnet_kind = adapt_driver_invocation(
            dotnet, self.output
        )
        self.assertIn("--results-directory", dotnet_argv)
        self.assertEqual(dotnet_reporter.suffix, ".trx")
        self.assertEqual(dotnet_kind, "trx")
        self.assertEqual(
            dotnet_environment["DOTNET_CLI_HOME"],
            str(self.output / "dotnet-cli-home"),
        )
        self.assertEqual(dotnet_environment["DOTNET_CLI_TELEMETRY_OPTOUT"], "1")
        self.assertEqual(dotnet_environment["DOTNET_NOLOGO"], "1")
        self.assertEqual(dotnet_environment["DOTNET_SKIP_FIRST_TIME_EXPERIENCE"], "1")
        self.assertEqual(
            dotnet_environment["DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE"], "1"
        )

        dotnet_build = replace(
            base,
            argv=("/usr/bin/dotnet", "build", "App.slnx", "--no-restore"),
            driver="automation",
            reporter="automation-events",
        )
        build_argv, build_environment, _, build_kind = adapt_driver_invocation(
            dotnet_build, self.output
        )
        self.assertEqual(build_argv, dotnet_build.argv)
        self.assertEqual(build_kind, "jsonl")
        self.assertEqual(
            build_environment["DOTNET_CLI_HOME"],
            str(self.output / "dotnet-cli-home"),
        )

    def test_dotnet_clean_attempt_home_is_ready_before_project_execution(self) -> None:
        observed = self.root / "dotnet-observed.json"
        executable = self.fake_dotnet(
            f"""\
            import json
            import os
            from pathlib import Path
            import sys

            expected = {{
                "HOME": {str(self.output / "home")!r},
                "DEVCOORDINATOR_TEST_TMP_ROOT": "/tmp",
                "DOTNET_CLI_HOME": {str(self.output / "dotnet-cli-home")!r},
                "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
                "DOTNET_NOLOGO": "1",
                "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
                "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE": "1",
            }}
            actual = {{name: os.environ.get(name) for name in expected}}
            if actual != expected:
                print(json.dumps({{"expected": expected, "actual": actual}}, sort_keys=True), file=sys.stderr)
                raise SystemExit(70)
            if not Path(expected["HOME"]).is_dir() or not Path(expected["DOTNET_CLI_HOME"]).is_dir():
                print("runner-owned dotnet directories are missing", file=sys.stderr)
                raise SystemExit(71)
            if sys.argv[1:] in (["--version"], ["workload", "list"]):
                marker = Path({str(observed)!r})
                payload = json.loads(marker.read_text()) if marker.exists() else {{}}
                payload.setdefault("readiness", []).append({{"argv": sys.argv[1:], "environment": actual}})
                marker.write_text(json.dumps(payload, sort_keys=True))
                raise SystemExit(0)
            payload = json.loads(Path({str(observed)!r}).read_text())
            payload["execution"] = actual
            Path({str(observed)!r}).write_text(json.dumps(payload, sort_keys=True))
            args = sys.argv[1:]
            results = Path(args[args.index("--results-directory") + 1])
            (results / "reporter.trx").write_text(
                '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">'
                '<Results><UnitTestResult testId="clean-home" testName="clean home" '
                'outcome="Passed" duration="00:00:00.0100000" /></Results></TestRun>'
            )
            """
        )
        descriptor = replace(
            self.descriptor((str(executable), "test")),
            driver="dotnet",
            reporter="trx",
            target_name="dotnet-clean-home",
            environment={
                "DOTNET_CLI_HOME": "/repository-controlled/dotnet-home",
                "DOTNET_CLI_TELEMETRY_OPTOUT": "0",
                "DOTNET_NOLOGO": "0",
                "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "0",
                "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE": "0",
            },
            ttl_seconds=300,
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME
        self.assertFalse((self.output / "home").exists())
        self.assertFalse((self.output / "dotnet-cli-home").exists())

        with mock.patch(
            "devcoordinator.universal_test_runner._dotnet_readiness",
            wraps=_dotnet_readiness,
        ) as readiness:
            self.assertEqual(
                run(descriptor, self.output, result_path),
                0,
                self.result_diagnostic(descriptor, result_path),
            )
        self.assertEqual(readiness.call_args.kwargs["timeout_seconds"], 300)

        observed_environment = json.loads(observed.read_text(encoding="utf-8"))
        self.assertEqual(
            [item["argv"] for item in observed_environment["readiness"]],
            [["--version"]],
        )
        self.assertTrue(
            all(
                item["environment"] == observed_environment["execution"]
                for item in observed_environment["readiness"]
            )
        )
        result = self.result_document(result_path)
        self.assertFalse(result["incomplete_reporting"])
        self.assertEqual(result["terminal_outcome"], "succeeded")
        self.assertEqual(self.result_cases(result_path)[0]["status"], "passed")
        self.assertTrue(
            self.result_package_content(result_path)["reporter_complete"]
        )

    def test_immutable_dotnet_restores_offline_before_no_restore_test(self) -> None:
        (self.root / "global.json").write_text(
            json.dumps({"sdk": {"version": "10.0.100"}}),
            encoding="utf-8",
        )
        project = self.root / "src" / "tests" / "App.Tests.csproj"
        project.parent.mkdir(parents=True)
        project.write_text("<Project />", encoding="utf-8")
        observed = self.root / "dotnet-offline-observed.json"
        executable = self.fake_dotnet(
            f"""\
            import json
            import os
            from pathlib import Path
            import sys

            marker = Path({str(observed)!r})
            payload = json.loads(marker.read_text()) if marker.exists() else {{"calls": []}}
            payload["calls"].append({{
                "argv": sys.argv[1:],
                "nuget_packages": os.environ.get("NUGET_PACKAGES"),
                "nuget_source": os.environ.get("DEVCOORDINATOR_NUGET_SOURCE"),
            }})
            marker.write_text(json.dumps(payload, sort_keys=True))
            args = sys.argv[1:]
            if args in (["--version"], ["workload", "list"]):
                raise SystemExit(0)
            if args and args[0] == "restore":
                required = {{"--locked-mode", "--force", "--no-http-cache", "--disable-build-servers", "-p:NuGetAudit=false", "--verbosity", "minimal"}}
                source = Path(args[args.index("--source") + 1])
                packages = Path(args[args.index("--packages") + 1])
                config = Path(args[args.index("--configfile") + 1])
                if args[1] != {str(project.resolve())!r} or not required.issubset(args):
                    print("trusted offline restore flags are incomplete", file=sys.stderr)
                    raise SystemExit(74)
                if "-p:Configuration=Release" not in args:
                    print("restore lost the test graph configuration", file=sys.stderr)
                    raise SystemExit(79)
                if "--configuration" in args or "--framework" in args:
                    print("restore received an unsupported test-only graph switch", file=sys.stderr)
                    raise SystemExit(80)
                archives = list(source.glob("*/*/*.nupkg"))
                if len(archives) != 1 or packages != Path(os.environ["NUGET_PACKAGES"]):
                    print("restore did not use the sealed package roots", file=sys.stderr)
                    raise SystemExit(77)
                if "<clear />" not in config.read_text() or "http" in config.read_text().lower():
                    print("restore configuration retained a network feed", file=sys.stderr)
                    raise SystemExit(83)
                if any(packages.iterdir()):
                    print("restore cache was not attempt-local and empty", file=sys.stderr)
                    raise SystemExit(81)
                extracted = packages / "demo.package" / "1.0.0"
                extracted.mkdir(parents=True)
                (extracted / "restored.txt").write_text("restored")
                if Path.cwd() != Path({str(project.parent)!r}):
                    print("relative project restore used the wrong cwd", file=sys.stderr)
                    raise SystemExit(78)
                if "--results-directory" in args or "--no-restore" in args:
                    print("test-only flags leaked into restore", file=sys.stderr)
                    raise SystemExit(75)
                raise SystemExit(0)
            if not args or args[0] != "test" or "--no-restore" not in args:
                print("project execution repeated restore", file=sys.stderr)
                raise SystemExit(76)
            if not (Path(os.environ["NUGET_PACKAGES"]) / "demo.package" / "1.0.0" / "restored.txt").is_file():
                print("test did not receive the restored attempt-local cache", file=sys.stderr)
                raise SystemExit(82)
            results = Path(args[args.index("--results-directory") + 1])
            (results / "reporter.trx").write_text(
                '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">'
                '<Results><UnitTestResult testId="offline" testName="offline restore" '
                'outcome="Passed" duration="00:00:00.0100000" /></Results></TestRun>'
            )
            """
        )
        descriptor = self.immutable_dotnet_descriptor(
            (
                str(executable),
                "test",
                "--configuration",
                "Release",
                "App.Tests.csproj",
                "--no-build",
                "--",
                "--filter",
                "Smoke",
            ),
            cwd="src/tests",
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME

        self.assertEqual(
            run(descriptor, self.output, result_path),
            0,
            self.result_diagnostic(descriptor, result_path),
        )

        evidence = json.loads(observed.read_text(encoding="utf-8"))
        self.assertEqual(
            [item["argv"][:2] for item in evidence["calls"][:3]],
            [["--version"], ["restore", str(project.resolve())], ["test", "--configuration"]],
        )
        self.assertIn("--no-restore", evidence["calls"][2]["argv"])
        self.assertNotIn("--no-build", evidence["calls"][2]["argv"])
        self.assertLess(
            evidence["calls"][2]["argv"].index("--no-restore"),
            evidence["calls"][2]["argv"].index("--"),
        )
        self.assertLess(
            evidence["calls"][2]["argv"].index("--logger"),
            evidence["calls"][2]["argv"].index("--"),
        )
        self.assertLess(
            evidence["calls"][2]["argv"].index("--results-directory"),
            evidence["calls"][2]["argv"].index("--"),
        )
        expected_packages = str(self.output / "nuget-packages")
        self.assertTrue(
            all(item["nuget_packages"] == expected_packages for item in evidence["calls"][:3])
        )
        self.assertTrue(
            all(
                item["nuget_source"]
                == descriptor.environment["DEVCOORDINATOR_NUGET_SOURCE"]
                for item in evidence["calls"][:3]
            )
        )
        result = self.result_document(result_path)
        self.assertFalse(result["incomplete_reporting"])
        self.assertEqual(self.result_cases(result_path)[0]["status"], "passed")

    def test_immutable_automation_dotnet_build_restores_before_execution(self) -> None:
        project = self.root / "EngineeringRegistry.slnx"
        project.write_text("<Solution />", encoding="utf-8")
        observed = self.root / "dotnet-build-observed.json"
        executable = self.fake_dotnet(
            f"""\
            import json
            import os
            from pathlib import Path
            import sys

            marker = Path({str(observed)!r})
            payload = json.loads(marker.read_text()) if marker.exists() else {{"calls": []}}
            payload["calls"].append(sys.argv[1:])
            marker.write_text(json.dumps(payload, sort_keys=True))
            args = sys.argv[1:]
            if args == ["--version"]:
                raise SystemExit(0)
            if args and args[0] == "restore":
                packages = Path(args[args.index("--packages") + 1])
                restored = packages / "demo.package" / "1.0.0"
                restored.mkdir(parents=True)
                (restored / "restored.txt").write_text("restored")
                raise SystemExit(0)
            if not args or args[0] != "build" or "--no-restore" not in args:
                raise SystemExit(76)
            if not (Path(os.environ["NUGET_PACKAGES"]) / "demo.package" / "1.0.0" / "restored.txt").is_file():
                raise SystemExit(82)
            event = {{
                "case_id": "dotnet-automation-build",
                "name": "dotnet automation build",
                "status": "passed",
                "duration_seconds": 0.01,
                "location": "EngineeringRegistry.slnx",
            }}
            Path(os.environ["DEVCOORDINATOR_TEST_EVENTS"]).write_text(
                json.dumps(event, sort_keys=True) + "\\n"
            )
            """
        )
        dotnet_executable = self.root / "dotnet"
        executable.rename(dotnet_executable)
        executable = dotnet_executable
        typed_descriptor = self.immutable_dotnet_descriptor(
            (str(executable), "build", project.name, "--no-restore")
        )
        package_root = Path(typed_descriptor.dependency_bindings[0]["source_root"])
        account = SimpleNamespace(
            pw_uid=os.geteuid(),
            pw_dir=str(package_root.parents[1]),
        )
        with mock.patch(
            "devcoordinator.universal_test_runtime.pwd.getpwall",
            return_value=[account],
        ):
            descriptor = replace(
                typed_descriptor,
                driver="automation",
                reporter="automation-events",
                target_name="dotnet-automation-build",
            )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME

        self.assertEqual(
            run(descriptor, self.output, result_path),
            0,
            self.result_diagnostic(descriptor, result_path),
        )
        evidence = json.loads(observed.read_text(encoding="utf-8"))
        self.assertEqual(
            [call[0] for call in evidence["calls"]],
            ["--version", "restore", "build"],
        )
        self.assertEqual(self.result_cases(result_path)[0]["status"], "passed")

    def test_dotnet_locked_restore_requires_one_stable_snapshot_project(self) -> None:
        first = self.root / "First.csproj"
        second = self.root / "Second.slnx"
        first.write_text("<Project />", encoding="utf-8")
        second.write_text("<Solution />", encoding="utf-8")

        with self.assertRaisesRegex(
            TestStoreContractError, "exactly one project or solution"
        ):
            _dotnet_restore_project(
                ("/usr/bin/dotnet", "test", "--configuration", "Release"),
                cwd=self.root,
                execution_root=self.root,
            )
        with self.assertRaisesRegex(
            TestStoreContractError, "exactly one project or solution"
        ):
            _dotnet_restore_project(
                ("/usr/bin/dotnet", "test", first.name, second.name),
                cwd=self.root,
                execution_root=self.root,
            )
        escaped = self.root / "Escaped.csproj"
        escaped.symlink_to(Path(self.temporary.name) / "outside.csproj")
        (Path(self.temporary.name) / "outside.csproj").write_text(
            "<Project />", encoding="utf-8"
        )
        with self.assertRaisesRegex(TestStoreContractError, "unsafe"):
            _dotnet_restore_project(
                ("/usr/bin/dotnet", "test", escaped.name),
                cwd=self.root,
                execution_root=self.root,
            )
        self.assertEqual(
            _dotnet_restore_semantic_options(
                (
                    "/usr/bin/dotnet",
                    "test",
                    "--configuration",
                    "Release",
                    "--framework=net10.0",
                    "-p:RestoreLockedMode=true",
                    "-p:Platform=x64",
                    first.name,
                )
            ),
            (
                "-p:Configuration=Release",
                "-p:TargetFramework=net10.0",
                "-p:Platform=x64",
            ),
        )
        self.assertEqual(
            _dotnet_restore_semantic_options(
                (
                    "/usr/bin/dotnet",
                    "test",
                    "cacheworker/GfCache.slnx",
                    "--configuration",
                    "Release",
                    "-p:RestoreLockedMode=true",
                )
            ),
            ("-p:Configuration=Release",),
        )
        for property_argument in (
            "-p:UseSharedCompilation=false",
            "/p:UseSharedCompilation=0",
            "--property:UseSharedCompilation=true",
        ):
            self.assertEqual(
                _dotnet_restore_semantic_options(
                    (
                        "/usr/bin/dotnet",
                        "test",
                        first.name,
                        property_argument,
                    )
                ),
                (),
            )
        for property_argument in (
            "-p:UseSharedCompilation",
            "-p:UseSharedCompilation=maybe",
        ):
            with self.assertRaisesRegex(
                TestStoreContractError, "requires a boolean value"
            ):
                _dotnet_restore_semantic_options(
                    (
                        "/usr/bin/dotnet",
                        "test",
                        first.name,
                        property_argument,
                    )
                )
        self.assertEqual(
            _dotnet_restore_project(
                ("/usr/bin/dotnet", "build", second.name, "--no-restore"),
                cwd=self.root,
                execution_root=self.root,
            ),
            second,
        )
        with self.assertRaisesRegex(TestStoreContractError, "missing its value"):
            _dotnet_restore_semantic_options(
                (
                    "/usr/bin/dotnet",
                    "test",
                    first.name,
                    "--configuration",
                    "--source",
                    "https://example.invalid/v3/index.json",
                )
            )
        with self.assertRaisesRegex(TestStoreContractError, "runner-owned"):
            _dotnet_restore_semantic_options(
                (
                    "/usr/bin/dotnet",
                    "test",
                    first.name,
                    "--source=https://example.invalid/v3/index.json",
                )
            )
        with self.assertRaisesRegex(TestStoreContractError, "graph selector"):
            _dotnet_restore_semantic_options(
                (
                    "/usr/bin/dotnet",
                    "test",
                    first.name,
                    "-p:RestoreSources=https://example.invalid/v3/index.json",
                )
            )

    def test_immutable_dotnet_restore_failure_is_bootstrap_evidence_only(self) -> None:
        project = self.root / "src" / "App.Tests.csproj"
        project.parent.mkdir()
        project.write_text("<Project />", encoding="utf-8")
        project_started = self.root / "dotnet-project-started"
        executable = self.fake_dotnet(
            f"""\
            from pathlib import Path
            import sys

            args = sys.argv[1:]
            if args == ["--version"]:
                raise SystemExit(0)
            if args and args[0] == "restore":
                print("NU1301: Unable to load the service index for source https://example.invalid/v3/index.json", file=sys.stderr)
                raise SystemExit(42)
            Path({str(project_started)!r}).touch()
            raise SystemExit(0)
            """
        )
        descriptor = self.immutable_dotnet_descriptor(
            (str(executable), "test", "src/App.Tests.csproj")
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME

        self.assertEqual(run(descriptor, self.output, result_path), 1)

        self.assertFalse(project_started.exists())
        result = self.result_document(result_path)
        self.assertEqual(result["returncode"], 42)
        self.assertFalse(result["incomplete_reporting"])
        self.assertEqual(result["terminal_outcome"], "infrastructure_failed")
        failures = self.result_failures(result_path)
        failure = self.assert_single_infrastructure_failure(failures)
        self.assertEqual(failure["location"], "runner/dotnet-bootstrap")
        self.assertIn("offline locked dotnet restore failed", failure["message"])
        self.assertIsInstance(failure["artifact_id"], str)
        self.assertFalse(
            any(item["classification"] == "test_failure" for item in failures)
        )
        self.assertFalse(
            any(
                item["classification"] == "incomplete_reporting"
                for item in failures
            )
        )
        stderr = (self.output / f"{descriptor.execution_id}-stderr.log").read_text(
            encoding="utf-8"
        )
        self.assertIn("NU1301", stderr)

    def test_immutable_dotnet_lock_mismatch_is_project_setup_evidence(self) -> None:
        project = self.root / "src" / "App.Tests.csproj"
        project.parent.mkdir()
        project.write_text("<Project />", encoding="utf-8")
        project_started = self.root / "dotnet-project-started"
        executable = self.fake_dotnet(
            f"""\
            from pathlib import Path
            import sys

            args = sys.argv[1:]
            if args == ["--version"]:
                raise SystemExit(0)
            if args and args[0] == "restore":
                print("NU1004: The package references have changed since packages.lock.json was created.", file=sys.stderr)
                raise SystemExit(1)
            Path({str(project_started)!r}).touch()
            raise SystemExit(0)
            """
        )
        descriptor = self.immutable_dotnet_descriptor(
            (str(executable), "test", "src/App.Tests.csproj")
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME

        self.assertEqual(run(descriptor, self.output, result_path), 1)

        self.assertFalse(project_started.exists())
        result = self.result_document(result_path)
        self.assertFalse(result["incomplete_reporting"])
        self.assertEqual(result["terminal_outcome"], "test_failed")
        failures = self.result_failures(result_path)
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["classification"], "test_failure")
        self.assertEqual(failures[0]["location"], "setup/dotnet-lock")
        self.assertIn("locked restore contract", failures[0]["message"])

    def test_immutable_dotnet_bootstrap_timeout_is_timeout_evidence(self) -> None:
        project = self.root / "src" / "App.Tests.csproj"
        project.parent.mkdir()
        project.write_text("<Project />", encoding="utf-8")
        executable = self.fake_dotnet("raise SystemExit(0)\n")
        descriptor = self.immutable_dotnet_descriptor(
            (str(executable), "test", "src/App.Tests.csproj")
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME
        probes = (
            DotnetProbeResult(0, b"10.0.100\n", b"", False),
            DotnetProbeResult(124, b"", b"restore timed out\n", True),
        )

        with mock.patch(
            "devcoordinator.universal_test_runner._run_dotnet_probe",
            side_effect=probes,
        ):
            self.assertEqual(run(descriptor, self.output, result_path), 1)

        result = self.result_document(result_path)
        self.assertFalse(result["incomplete_reporting"])
        self.assertEqual(result["terminal_outcome"], "timed_out")
        failures = self.result_failures(result_path)
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["classification"], "timeout")
        self.assertEqual(failures[0]["location"], "runner/dotnet-bootstrap")
        self.assertIn("timed out", failures[0]["message"])

    def test_dotnet_readiness_uses_caller_timeout_without_waiting(self) -> None:
        timed_out = DotnetProbeResult(
            returncode=124,
            stdout=b"bounded stdout",
            stderr=b"bounded stderr",
            timed_out=True,
        )
        with mock.patch(
            "devcoordinator.universal_test_runner.time.monotonic",
            side_effect=(100.0, 100.0),
        ), mock.patch(
            "devcoordinator.universal_test_runner._run_dotnet_probe",
            return_value=timed_out,
        ) as probe:
            failure = _dotnet_readiness(
                ("/usr/bin/dotnet", "test"),
                cwd=self.root,
                execution_root=self.root,
                environment={},
                timeout_seconds=3_600,
            )

        self.assertIsNotNone(failure)
        self.assertEqual(failure.returncode, 124)
        self.assertEqual(failure.stage, "sdk")
        self.assertIn("3600s execution timeout", failure.stderr.decode("utf-8"))
        self.assertEqual(probe.call_args.kwargs["timeout_seconds"], 3_600)

    def test_dotnet_probe_drains_and_bounds_both_streams(self) -> None:
        class UnclosedBytesIO(io.BytesIO):
            def close(self) -> None:
                self.runner_closed = True

        stdout = UnclosedBytesIO(b"x" * 300)
        stderr = UnclosedBytesIO(b"y" * 200)
        process = mock.Mock()
        process.pid = 987_654
        process.stdout = stdout
        process.stderr = stderr
        process.wait.return_value = 0
        with mock.patch(
            "devcoordinator.universal_test_runner.MAX_DOTNET_READINESS_STREAM_BYTES",
            64,
        ), mock.patch(
            "devcoordinator.universal_test_runner.subprocess.Popen",
            return_value=process,
        ), mock.patch("devcoordinator.universal_test_runner.os.killpg"):
            result = _run_dotnet_probe(
                ("/usr/bin/dotnet", "--version"),
                cwd=self.root,
                environment={},
                timeout_seconds=3_600,
            )

        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.timed_out)
        self.assertLessEqual(len(result.stdout), 64)
        self.assertLessEqual(len(result.stderr), 64)
        self.assertIn(b"truncated", result.stdout)
        self.assertIn(b"truncated", result.stderr)
        self.assertEqual(stdout.tell(), 300)
        self.assertEqual(stderr.tell(), 200)
        process.wait.assert_called_once_with(timeout=3_600)

    def test_dotnet_probe_timeout_kills_the_entire_process_group(self) -> None:
        process = mock.Mock()
        process.pid = 987_655
        process.stdout = io.BytesIO(b"partial stdout")
        process.stderr = io.BytesIO(b"partial stderr")
        process.wait.side_effect = (
            subprocess.TimeoutExpired(("dotnet", "restore"), 1),
            -signal.SIGKILL,
        )
        with mock.patch(
            "devcoordinator.universal_test_runner.subprocess.Popen",
            return_value=process,
        ), mock.patch(
            "devcoordinator.universal_test_runner.os.killpg"
        ) as killpg:
            result = _run_dotnet_probe(
                ("/usr/bin/dotnet", "restore", "App.Tests.csproj"),
                cwd=self.root,
                environment={},
                timeout_seconds=1,
            )

        self.assertEqual(result.returncode, 124)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.stdout, b"partial stdout")
        self.assertEqual(result.stderr, b"partial stderr")
        killpg.assert_called_once_with(process.pid, signal.SIGKILL)
        self.assertEqual(
            process.wait.call_args_list,
            [mock.call(timeout=1), mock.call()],
        )

    def test_dotnet_project_execution_uses_the_remaining_caller_deadline(self) -> None:
        executable = self.fake_dotnet(
            """\
            import sys
            import time

            if sys.argv[1:] == ["--version"]:
                raise SystemExit(0)
            time.sleep(5)
            """
        )
        descriptor = replace(
            self.descriptor((str(executable), "test")),
            driver="dotnet",
            reporter="trx",
            target_name="dotnet-shared-deadline",
            ttl_seconds=1,
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME
        started = time.monotonic()

        self.assertEqual(run(descriptor, self.output, result_path), 1)

        self.assertLess(time.monotonic() - started, 3.0)
        result = self.result_document(result_path)
        self.assertEqual(result["returncode"], 124)
        self.assertFalse(result["incomplete_reporting"])
        self.assertEqual(result["terminal_outcome"], "timed_out")
        failures = self.result_failures(result_path)
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["classification"], "timeout")
        self.assertEqual(failures[0]["location"], "runner/execution")

    def test_dotnet_sdk_readiness_failure_is_infrastructure_only(self) -> None:
        project_started = self.root / "project-started"
        executable = self.fake_dotnet(
            f"""\
            from pathlib import Path
            import sys

            if sys.argv[1:] == ["--version"]:
                print("The selected SDK could not be initialized.", file=sys.stderr)
                raise SystemExit(42)
            Path({str(project_started)!r}).touch()
            raise SystemExit(0)
            """
        )
        descriptor = replace(
            self.descriptor((str(executable), "test")),
            driver="dotnet",
            reporter="trx",
            target_name="dotnet-sdk-readiness",
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME

        self.assertEqual(run(descriptor, self.output, result_path), 1)

        self.assertFalse(project_started.exists())
        result = self.result_document(result_path)
        self.assertEqual(result["returncode"], 42)
        self.assertFalse(result["incomplete_reporting"])
        self.assertEqual(result["terminal_outcome"], "infrastructure_failed")
        failures = self.result_failures(result_path)
        failure = self.assert_single_infrastructure_failure(failures)
        self.assertEqual(failure["location"], "runner/dotnet-readiness")
        self.assertIsInstance(failure["artifact_id"], str)
        self.assertFalse(
            any(item["classification"] == "test_failure" for item in failures)
        )
        self.assertFalse(
            any(item["classification"] == "incomplete_reporting" for item in failures)
        )
        stderr = (self.output / f"{descriptor.execution_id}-stderr.log").read_text(
            encoding="utf-8"
        )
        self.assertIn("selected SDK could not be initialized", stderr)

    def test_dotnet_readiness_uses_the_project_global_json_sdk(self) -> None:
        project = self.root / "cacheworker" / "GfCache.slnx"
        project.parent.mkdir()
        project.write_text("<Solution />", encoding="utf-8")
        (project.parent / "global.json").write_text(
            json.dumps(
                {"sdk": {"version": "10.0.301", "rollForward": "disable"}}
            ),
            encoding="utf-8",
        )
        project_started = self.root / "project-started"
        executable = self.fake_dotnet(
            f"""\
            import json
            from pathlib import Path
            import sys

            if sys.argv[1:] == ["--version"]:
                config = json.loads(Path("global.json").read_text())
                print("A compatible .NET SDK was not found.", file=sys.stderr)
                print("Requested SDK version: " + config["sdk"]["version"], file=sys.stderr)
                raise SystemExit(155)
            if sys.argv[1:] == ["workload", "list"]:
                raise SystemExit(72)
            Path({str(project_started)!r}).touch()
            raise SystemExit(0)
            """
        )
        descriptor = replace(
            self.descriptor(
                (str(executable), "test", "cacheworker/GfCache.slnx")
            ),
            driver="dotnet",
            reporter="trx",
            target_name="dotnet-global-json",
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME

        self.assertEqual(run(descriptor, self.output, result_path), 1)

        self.assertFalse(project_started.exists())
        failures = self.result_failures(result_path)
        failure = self.assert_single_infrastructure_failure(failures)
        self.assertIn("requested dotnet SDK 10.0.301", failure["message"])
        self.assertIn("cacheworker/global.json", failure["message"])
        stderr = (self.output / f"{descriptor.execution_id}-stderr.log").read_text(
            encoding="utf-8"
        )
        self.assertIn("Requested SDK version: 10.0.301", stderr)

    def test_dotnet_project_exit_without_trx_is_actionable_and_incomplete(self) -> None:
        executable = self.fake_dotnet(
            """\
            import sys

            if sys.argv[1:] in (["--version"], ["workload", "list"]):
                raise SystemExit(0)
            print("project build failed before test execution", file=sys.stderr)
            raise SystemExit(23)
            """
        )
        descriptor = replace(
            self.descriptor((str(executable), "test")),
            driver="dotnet",
            reporter="trx",
            target_name="dotnet-missing-trx",
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME

        self.assertEqual(run(descriptor, self.output, result_path), 1)

        result = self.result_document(result_path)
        self.assertEqual(result["returncode"], 23)
        self.assertTrue(result["incomplete_reporting"])
        failures = self.result_failures(result_path)
        self.assertEqual(
            {item["classification"] for item in failures},
            {"incomplete_reporting", "test_failure"},
        )
        test_failure = next(
            item for item in failures if item["classification"] == "test_failure"
        )
        self.assertIsInstance(test_failure["artifact_id"], str)
        self.assertIn("status 23", test_failure["message"])

    def test_dotnet_failing_trx_is_complete_project_failure(self) -> None:
        executable = self.fake_dotnet(
            """\
            from pathlib import Path
            import sys

            if sys.argv[1:] in (["--version"], ["workload", "list"]):
                raise SystemExit(0)
            args = sys.argv[1:]
            results = Path(args[args.index("--results-directory") + 1])
            (results / "reporter.trx").write_text(
                '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">'
                '<Results><UnitTestResult testId="real-failure" testName="real failure" '
                'outcome="Failed" duration="00:00:00.0200000" /></Results></TestRun>'
            )
            raise SystemExit(1)
            """
        )
        descriptor = replace(
            self.descriptor((str(executable), "test")),
            driver="dotnet",
            reporter="trx",
            target_name="dotnet-real-failure",
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME

        self.assertEqual(run(descriptor, self.output, result_path), 1)

        result = self.result_document(result_path)
        self.assertFalse(result["incomplete_reporting"])
        failures = self.result_failures(result_path)
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["classification"], "test_failure")
        self.assertEqual(failures[0]["case_id"], "real-failure")
        self.assertEqual(self.result_cases(result_path)[0]["status"], "failed")
        self.assertTrue(
            self.result_package_content(result_path)["reporter_complete"]
        )

    def test_dotnet_solution_retains_every_trx_and_assertion_cause(self) -> None:
        executable = self.fake_dotnet(
            """\
            from pathlib import Path
            import sys

            if sys.argv[1:] in (["--version"], ["workload", "list"]):
                raise SystemExit(0)
            args = sys.argv[1:]
            results = Path(args[args.index("--results-directory") + 1])
            results.joinpath("reporter_alpha.trx").write_text(
                '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">'
                '<Results><UnitTestResult testId="shared" testName="alpha failure" '
                'outcome="Failed" duration="00:00:00.0200000"><Output><ErrorInfo>'
                '<Message>Expected 2 but found 1</Message>'
                '<StackTrace>at Alpha.Tests.Case() in Alpha.cs:line 42</StackTrace>'
                '</ErrorInfo></Output></UnitTestResult></Results></TestRun>'
            )
            results.joinpath("reporter_beta.trx").write_text(
                '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">'
                '<Results><UnitTestResult testId="shared" testName="beta passes" '
                'outcome="Passed" duration="00:00:00.0100000" /></Results></TestRun>'
            )
            raise SystemExit(1)
            """
        )
        descriptor = replace(
            self.descriptor((str(executable), "test", "AllTests.sln")),
            driver="dotnet",
            reporter="trx",
            target_name="dotnet-solution-failure",
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME

        self.assertEqual(run(descriptor, self.output, result_path), 1)

        cases = self.result_cases(result_path)
        failures = self.result_failures(result_path)
        self.assertEqual(len(cases), 2)
        self.assertEqual(len({case["case_id"] for case in cases}), 2)
        self.assertEqual(len(failures), 1)
        self.assertIn("Expected 2 but found 1", failures[0]["message"])
        self.assertIn("Alpha.cs:line 42", failures[0]["location"])
        self.assertIsInstance(failures[0]["artifact_id"], str)
        result = self.result_document(result_path)
        reporter_artifacts = [
            artifact
            for artifact in result["artifacts"]
            if artifact["kind"] == "trx"
        ]
        self.assertEqual(len(reporter_artifacts), 2)

    def test_dotnet_oversized_trx_streams_bounded_failure_projection(self) -> None:
        executable = self.fake_dotnet(
            """\
            from pathlib import Path
            import sys

            if sys.argv[1:] in (["--version"], ["workload", "list"]):
                raise SystemExit(0)
            args = sys.argv[1:]
            results = Path(args[args.index("--results-directory") + 1])
            oversized = (
                '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">'
                '<Results><UnitTestResult testId="large-failure" '
                'testName="oversized assertion" outcome="Failed" '
                'duration="00:00:00.0200000"><Output><ErrorInfo>'
                '<Message>Expected durable cause</Message>'
                '<StackTrace>at Large.Tests.Case() in /private/source/Large.cs:line 9</StackTrace>'
                '</ErrorInfo><StdOut>'
                + ("bounded diagnostic filler\\n" * 1_400_000)
                + '</StdOut></Output></UnitTestResult></Results></TestRun>'
            )
            results.joinpath("reporter_alpha.trx").write_text(oversized)
            results.joinpath("reporter_beta.trx").write_text(
                '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">'
                '<Results><UnitTestResult testId="small-pass" testName="small pass" '
                'outcome="Passed" duration="00:00:00.0100000" /></Results></TestRun>'
            )
            raise SystemExit(1)
            """
        )
        descriptor = replace(
            self.descriptor((str(executable), "test", "AllTests.sln")),
            driver="dotnet",
            reporter="trx",
            target_name="dotnet-oversized-trx",
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME

        self.assertEqual(run(descriptor, self.output, result_path), 1)

        result = self.result_document(result_path)
        self.assertFalse(result["incomplete_reporting"])
        cases = self.result_cases(result_path)
        failures = self.result_failures(result_path)
        self.assertEqual({case["status"] for case in cases}, {"failed", "passed"})
        self.assertEqual(len(failures), 1)
        self.assertIn("Expected durable cause", failures[0]["message"])
        self.assertIn("Large.cs:line 9", failures[0]["location"])
        self.assertIsInstance(failures[0]["artifact_id"], str)
        reporter_artifacts = [
            artifact
            for artifact in result["artifacts"]
            if artifact["kind"] in {"trace", "trx"}
        ]
        self.assertEqual({artifact["kind"] for artifact in reporter_artifacts}, {"trace", "trx"})
        self.assertIn(failures[0]["artifact_id"], {item["artifact_id"] for item in reporter_artifacts})

    def test_dotnet_invalid_trx_does_not_suppress_independent_report(self) -> None:
        executable = self.fake_dotnet(
            """\
            from pathlib import Path
            import sys

            if sys.argv[1:] in (["--version"], ["workload", "list"]):
                raise SystemExit(0)
            args = sys.argv[1:]
            results = Path(args[args.index("--results-directory") + 1])
            results.joinpath("reporter_alpha.trx").write_text("<invalid")
            results.joinpath("reporter_beta.trx").write_text(
                '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">'
                '<Results><UnitTestResult testId="safe-pass" testName="safe pass" '
                'outcome="Passed" duration="00:00:00.0100000" /></Results></TestRun>'
            )
            raise SystemExit(0)
            """
        )
        descriptor = replace(
            self.descriptor((str(executable), "test", "AllTests.sln")),
            driver="dotnet",
            reporter="trx",
            target_name="dotnet-invalid-trx",
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME

        self.assertEqual(run(descriptor, self.output, result_path), 1)

        result = self.result_document(result_path)
        self.assertTrue(result["incomplete_reporting"])
        self.assertEqual(
            [case["display_name"] for case in self.result_cases(result_path)],
            ["safe pass"],
        )
        self.assertTrue(
            any(
                failure["classification"] == "incomplete_reporting"
                for failure in self.result_failures(result_path)
            )
        )

    def test_python_unittest_executes_through_trusted_jsonl_reporter(self) -> None:
        script = self.root / "python_framework_suite.py"
        script.write_text(
            textwrap.dedent(
                """\
                import json
                import os
                import unittest


                class FrameworkSuite(unittest.TestCase):
                    def test_runner_contract(self):
                        self.assertEqual(6 * 7, 42)


                suite = unittest.defaultTestLoader.loadTestsFromTestCase(FrameworkSuite)
                result = unittest.TextTestRunner(verbosity=0).run(suite)
                event = {
                    "case_id": "python-unittest-runner-contract",
                    "name": "python unittest runner contract",
                    "status": "passed" if result.wasSuccessful() else "failed",
                    "duration_seconds": 0.001,
                    "location": "python_framework_suite.py",
                }
                with open(os.environ["DEVCOORDINATOR_TEST_EVENTS"], "w", encoding="utf-8") as stream:
                    stream.write(json.dumps(event, sort_keys=True) + "\\n")
                raise SystemExit(0 if result.wasSuccessful() else 1)
                """
            ),
            encoding="utf-8",
        )
        descriptor = replace(
            self.descriptor(("/usr/bin/python3", str(script))),
            driver="automation",
            reporter="automation-events",
            target_name="python-unittest-integration",
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME

        outcome = run(descriptor, self.output, result_path)
        self.assertEqual(
            outcome, 0, self.result_diagnostic(descriptor, result_path)
        )

        cases = self.result_cases(result_path)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["case_id"], "python-unittest-runner-contract")
        self.assertEqual(cases[0]["status"], "passed")

    @unittest.skipUnless(shutil.which("node"), "Node.js is unavailable")
    def test_node_test_executes_through_trusted_junit_reporter(self) -> None:
        script = self.root / "node-framework.test.mjs"
        script.write_text(
            textwrap.dedent(
                """\
                import assert from 'node:assert/strict';
                import test from 'node:test';

                test('node test runner contract', () => {
                  assert.equal(6 * 7, 42);
                });
                """
            ),
            encoding="utf-8",
        )
        descriptor = replace(
            self.descriptor(("/usr/bin/node", "--test", str(script))),
            driver="node",
            reporter="jsonl",
            target_name="node-test-integration",
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME

        outcome = run(descriptor, self.output, result_path)
        self.assertEqual(
            outcome, 0, self.result_diagnostic(descriptor, result_path)
        )

        cases = self.result_cases(result_path)
        self.assertTrue(cases)
        self.assertTrue(
            any(
                case["status"] == "passed"
                and (
                    "node test runner contract" in str(case["display_name"])
                    or "node-framework.test.mjs" in str(case["display_name"])
                )
                for case in cases
            ),
            json.dumps(cases, indent=2, sort_keys=True),
        )

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_dotnet_xunit_executes_through_trusted_trx_reporter(self) -> None:
        package_root = Path.home() / ".nuget" / "packages"
        required_packages = {
            "microsoft.net.test.sdk": "18.7.0",
            "xunit": "2.9.3",
            "xunit.runner.visualstudio": "3.1.5",
        }
        if any(
            not (package_root / name / version).is_dir()
            for name, version in required_packages.items()
        ):
            self.skipTest("the pinned offline .NET test packages are unavailable")
        project = self.root / "DotnetFramework.Tests.csproj"
        project.write_text(
            textwrap.dedent(
                """\
                <Project Sdk="Microsoft.NET.Sdk">
                  <PropertyGroup>
                    <TargetFramework>net10.0</TargetFramework>
                    <IsPackable>false</IsPackable>
                    <IsTestProject>true</IsTestProject>
                  </PropertyGroup>
                  <ItemGroup>
                    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="18.7.0" />
                    <PackageReference Include="xunit" Version="2.9.3" />
                    <PackageReference Include="xunit.runner.visualstudio" Version="3.1.5" />
                  </ItemGroup>
                </Project>
                """
            ),
            encoding="utf-8",
        )
        (self.root / "RunnerContractTests.cs").write_text(
            textwrap.dedent(
                """\
                using Xunit;

                public sealed class RunnerContractTests
                {
                    [Fact]
                    public void Dotnet_runner_contract() => Assert.Equal(42, 6 * 7);
                }
                """
            ),
            encoding="utf-8",
        )
        restore_home = Path(self.temporary.name) / "dotnet-restore-home"
        restore_home.mkdir(mode=0o700)
        restore_environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(restore_home),
            "NUGET_PACKAGES": str(package_root),
            "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
            "DOTNET_NOLOGO": "1",
        }
        restored = subprocess.run(
            [
                "/usr/bin/dotnet",
                "restore",
                str(project),
                "--packages",
                str(package_root),
                "--ignore-failed-sources",
            ],
            cwd=self.root,
            env=restore_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            check=False,
        )
        self.assertEqual(
            restored.returncode,
            0,
            (restored.stdout + "\n" + restored.stderr)[-4000:],
        )
        descriptor = replace(
            self.descriptor(
                (
                    "/usr/bin/dotnet",
                    "test",
                    str(project),
                    "--no-restore",
                    "--no-build",
                )
            ),
            driver="dotnet",
            reporter="trx",
            target_name="dotnet-xunit-integration",
            environment={
                "NUGET_PACKAGES": str(package_root),
                "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
                "DOTNET_NOLOGO": "1",
            },
        )
        build_environment = dict(restore_environment)
        built = subprocess.run(
            [
                "/usr/bin/dotnet",
                "build",
                str(project),
                "--no-restore",
                "--nologo",
            ],
            cwd=self.root,
            env=build_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            check=False,
        )
        self.assertEqual(
            built.returncode,
            0,
            (built.stdout + "\n" + built.stderr)[-4000:],
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME

        outcome = run(descriptor, self.output, result_path)
        self.assertEqual(
            outcome, 0, self.result_diagnostic(descriptor, result_path)
        )

        cases = self.result_cases(result_path)
        self.assertTrue(cases)
        self.assertTrue(
            any(
                case["status"] == "passed"
                and "Dotnet_runner_contract" in str(case["display_name"])
                for case in cases
            ),
            json.dumps(cases, indent=2, sort_keys=True),
        )

    def test_history_shards_receive_distinct_trusted_driver_selectors(self) -> None:
        pytest_descriptor = replace(
            self.descriptor(("/usr/bin/python3", "-m", "pytest", "tests")),
            driver="pytest",
            reporter="pytest-events",
            shard_index=1,
            shard_count=3,
        )
        pytest_argv, pytest_environment, _, _ = adapt_driver_invocation(
            pytest_descriptor, self.output
        )
        self.assertIn("devcoordinator_pytest_shard", pytest_argv)
        self.assertEqual(pytest_environment["DEVCOORDINATOR_TEST_SHARD_INDEX"], "1")
        self.assertEqual(pytest_environment["DEVCOORDINATOR_TEST_SHARD_COUNT"], "3")
        self.assertTrue(
            (self.output / "devcoordinator_pytest_shard.py").is_file()
        )

        node_descriptor = replace(
            pytest_descriptor,
            argv=("/usr/bin/node", "--test", "tests"),
            driver="node",
            reporter="jsonl",
        )
        node_argv, _, _, _ = adapt_driver_invocation(
            node_descriptor, self.output
        )
        self.assertIn("--test-shard=2/3", node_argv)

        with self.assertRaisesRegex(
            TestStoreContractError, "no trusted distinct shard selector"
        ):
            replace(
                self.descriptor(("/usr/bin/python3", "script.py")),
                shard_index=0,
                shard_count=2,
            )

    def test_pytest_history_partition_is_stable_disjoint_and_complete(self) -> None:
        descriptor = replace(
            self.descriptor(("/usr/bin/python3", "-m", "pytest", "tests")),
            driver="pytest",
            reporter="pytest-events",
            shard_index=0,
            shard_count=4,
        )
        adapt_driver_invocation(descriptor, self.output)
        plugin_path = self.output / "devcoordinator_pytest_shard.py"
        spec = importlib.util.spec_from_file_location(
            "generated_devcoordinator_pytest_shard", plugin_path
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin)

        class Item:
            def __init__(self, nodeid):
                self.nodeid = nodeid

        class Hook:
            def pytest_deselected(self, *, items):
                self.deselected = [item.nodeid for item in items]

        class Config:
            def __init__(self):
                self.hook = Hook()

        nodeids = [f"tests/test_suite.py::test_case[{index}]" for index in range(257)]

        def partitions():
            observed = []
            before_index = os.environ.get("DEVCOORDINATOR_TEST_SHARD_INDEX")
            before_count = os.environ.get("DEVCOORDINATOR_TEST_SHARD_COUNT")
            try:
                for index in range(4):
                    os.environ["DEVCOORDINATOR_TEST_SHARD_INDEX"] = str(index)
                    os.environ["DEVCOORDINATOR_TEST_SHARD_COUNT"] = "4"
                    items = [Item(nodeid) for nodeid in nodeids]
                    plugin.pytest_collection_modifyitems(Config(), items)
                    observed.append([item.nodeid for item in items])
            finally:
                if before_index is None:
                    os.environ.pop("DEVCOORDINATOR_TEST_SHARD_INDEX", None)
                else:
                    os.environ["DEVCOORDINATOR_TEST_SHARD_INDEX"] = before_index
                if before_count is None:
                    os.environ.pop("DEVCOORDINATOR_TEST_SHARD_COUNT", None)
                else:
                    os.environ["DEVCOORDINATOR_TEST_SHARD_COUNT"] = before_count
            return observed

        first = partitions()
        second = partitions()
        self.assertEqual(first, second)
        self.assertEqual(
            set().union(*(set(values) for values in first)), set(nodeids)
        )
        self.assertEqual(sum(len(values) for values in first), len(nodeids))
        for values in first:
            positions = [nodeids.index(value) for value in values]
            self.assertEqual(positions, sorted(positions))

    def test_capture_secret_marker_is_redacted_before_artifact_publication(self) -> None:
        secret = "sk-" + "A" * 32
        descriptor = self.descriptor(
            ("/usr/bin/python3", "-c", f"print({secret!r})")
        )
        result_path = self.output / RESULT_PACKAGE_FILE_NAME
        self.assertEqual(run(descriptor, self.output, result_path), 1)
        payload = result_path.read_bytes()
        capture = (self.output / f"{descriptor.execution_id}-stdout.log").read_text(
            encoding="utf-8"
        )
        self.assertNotIn(secret.encode("utf-8"), payload)
        self.assertNotIn(secret, capture)
        self.assertIn("redacted", capture)
        self.assertFalse(
            (
                self.output
                / f"{descriptor.execution_id}-stdout.log.progress.json"
            ).exists()
        )
        result = self.result_document(result_path)
        self.assertTrue(result["captures"]["stdout"]["secret_redacted"])
        self.assertTrue(result["incomplete_reporting"])

    def test_trx_duration_is_preserved(self) -> None:
        path = self.output / "sample.trx"
        path.write_text(
            """<TestRun xmlns=\"http://microsoft.com/schemas/VisualStudio/TeamTest/2010\"><Results><UnitTestResult testId=\"id-1\" testName=\"works\" outcome=\"Passed\" duration=\"00:01:02.5000000\" /></Results></TestRun>""",
            encoding="utf-8",
        )
        cases, failures = _trx_cases(path)
        self.assertEqual(failures, [])
        self.assertAlmostEqual(cases[0]["duration_seconds"], 62.5)


if __name__ == "__main__":
    unittest.main()
