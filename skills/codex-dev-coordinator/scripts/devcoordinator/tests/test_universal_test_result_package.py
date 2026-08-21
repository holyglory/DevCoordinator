from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

from devcoordinator.universal_test_result_package import (
    RESULT_PACKAGE_FILE_NAME,
    ResultPackageArtifact,
    ResultPackageError,
    copy_result_package_artifact,
    iter_result_package_records,
    publish_result_package,
    validate_result_package,
)


class UniversalTestResultPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.output = self.root / "output"
        self.output.mkdir(mode=0o700)
        self.stdout = self.output / "stdout.log"
        self.stderr = self.output / "stderr.log"
        self.stdout.write_bytes(b"stdout evidence\n")
        self.stderr.write_bytes(b"stderr evidence\n")

    @staticmethod
    def identity() -> dict[str, object]:
        return {
            "execution_id": "execution-package",
            "target_id": "target-package",
            "run_id": "run-package",
            "repository_id": "repo-package",
            "repository_generation": 7,
            "generation": 3,
            "descriptor_sha256": "a" * 64,
        }

    @staticmethod
    def artifact(path: Path, index: int) -> ResultPackageArtifact:
        payload = path.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        artifact_id = f"artifact-{index:032x}"
        return ResultPackageArtifact(
            artifact_id=artifact_id,
            kind="log",
            storage_handle=f"test-artifact://{artifact_id}/{digest}",
            sha256=digest,
            size_bytes=len(payload),
            source_path=path,
        )

    def inputs(self) -> dict[str, object]:
        stdout = self.artifact(self.stdout, 1)
        stderr = self.artifact(self.stderr, 2)
        return {
            "identity": self.identity(),
            "outcome": {
                "returncode": 1,
                "duration_seconds": 1.25,
                "incomplete_reporting": False,
                "reporter_complete": True,
                "terminal_outcome": "test_failed",
            },
            "resource_usage": {
                "peak_memory_bytes": 1024,
                "cpu_seconds": 0.5,
            },
            "captures": {
                "stdout": {
                    "artifact_id": stdout.artifact_id,
                    "sha256": stdout.sha256,
                    "retained_sha256": stdout.sha256,
                    "size_bytes": stdout.size_bytes,
                    "observed_bytes": stdout.size_bytes,
                    "truncated": False,
                    "secret_redacted": False,
                },
                "stderr": {
                    "artifact_id": stderr.artifact_id,
                    "sha256": stderr.sha256,
                    "retained_sha256": stderr.sha256,
                    "size_bytes": stderr.size_bytes,
                    "observed_bytes": stderr.size_bytes,
                    "truncated": False,
                    "secret_redacted": False,
                },
            },
            "cases": [
                {
                    "case_id": "case-one",
                    "display_name": "one",
                    "status": "failed",
                    "duration_seconds": 1.0,
                    "location": "tests/test_one.py:1",
                }
            ],
            "failures": [
                {
                    "failure_id": "failure-one",
                    "classification": "test_failure",
                    "message": "expected true",
                    "case_id": "case-one",
                    "location": "tests/test_one.py:1",
                    "artifact_id": stderr.artifact_id,
                }
            ],
            "artifacts": [stdout, stderr],
        }

    def publish(self, directory: Path | None = None, **overrides: object):
        directory = self.output if directory is None else directory
        values = self.inputs()
        values.update(overrides)
        destination = directory / RESULT_PACKAGE_FILE_NAME
        evidence = publish_result_package(destination, **values)
        return destination, evidence

    def test_atomic_deterministic_package_round_trips_records_and_artifacts(self) -> None:
        first_path, first_evidence = self.publish()
        second_output = self.root / "second"
        second_output.mkdir(mode=0o700)
        second_stdout = second_output / "stdout.log"
        second_stderr = second_output / "stderr.log"
        second_stdout.write_bytes(self.stdout.read_bytes())
        second_stderr.write_bytes(self.stderr.read_bytes())
        values = self.inputs()
        values["artifacts"] = [
            self.artifact(second_stdout, 1),
            self.artifact(second_stderr, 2),
        ]
        second_path = second_output / RESULT_PACKAGE_FILE_NAME
        second_evidence = publish_result_package(second_path, **values)

        self.assertEqual(first_path.read_bytes(), second_path.read_bytes())
        self.assertEqual(first_evidence.sha256, second_evidence.sha256)
        package = validate_result_package(
            first_path, expected_identity=self.identity()
        )
        self.assertEqual(
            list(iter_result_package_records(package, "cases"))[0]["case_id"],
            "case-one",
        )
        self.assertEqual(
            list(iter_result_package_records(package, "failures"))[0][
                "failure_id"
            ],
            "failure-one",
        )
        copied = io.BytesIO()
        digest, size = copy_result_package_artifact(
            package, "artifact-" + f"{1:032x}", copied
        )
        self.assertEqual(copied.getvalue(), self.stdout.read_bytes())
        self.assertEqual(digest, hashlib.sha256(copied.getvalue()).hexdigest())
        self.assertEqual(size, len(copied.getvalue()))
        with tarfile.open(first_path, mode="r:") as archive:
            self.assertEqual(
                [member.name for member in archive],
                [
                    "manifest.json",
                    "cases.ndjson",
                    "failures.ndjson",
                    "artifacts/artifact-00000000000000000000000000000001.blob",
                    "artifacts/artifact-00000000000000000000000000000002.blob",
                ],
            )

    def test_matching_publication_is_idempotent_and_conflict_is_not_overwritten(self) -> None:
        path, first = self.publish()
        _same_path, replay = self.publish()
        self.assertEqual(first, replay)
        original = path.read_bytes()
        changed = self.inputs()["outcome"]
        assert isinstance(changed, dict)
        changed["duration_seconds"] = 2.0
        with self.assertRaisesRegex(ResultPackageError, "digest is contradictory"):
            self.publish(outcome=changed)
        self.assertEqual(path.read_bytes(), original)

    def test_failed_publication_leaves_no_visible_or_temporary_package(self) -> None:
        values = self.inputs()
        artifacts = list(values["artifacts"])
        first = artifacts[0]
        artifacts[0] = ResultPackageArtifact(
            **{**first.__dict__, "sha256": "0" * 64}
        )
        with self.assertRaises(ResultPackageError):
            self.publish(artifacts=artifacts)
        self.assertFalse((self.output / RESULT_PACKAGE_FILE_NAME).exists())
        self.assertEqual(
            [path.name for path in self.output.iterdir() if path.name.startswith(".result-package")],
            [],
        )

    def test_validator_rejects_tamper_symlink_and_undeclared_member(self) -> None:
        path, _evidence = self.publish()
        tampered = self.output / "tampered.tar"
        payload = bytearray(path.read_bytes())
        payload[600] ^= 1
        tampered.write_bytes(payload)
        with self.assertRaises(ResultPackageError):
            validate_result_package(tampered)

        linked = self.output / "linked.tar"
        linked.symlink_to(path)
        with self.assertRaisesRegex(ResultPackageError, "unavailable"):
            validate_result_package(linked)

        excessive = self.output / "excessive.tar"
        with tarfile.open(path, mode="r:") as source, tarfile.open(
            excessive, mode="w", format=tarfile.USTAR_FORMAT
        ) as destination:
            for member in source:
                content = source.extractfile(member)
                destination.addfile(member, content)
            extra = tarfile.TarInfo("../escape")
            extra.uid = extra.gid = 0
            extra.uname = extra.gname = ""
            extra.mtime = 0
            extra.mode = 0o400
            extra.size = 1
            destination.addfile(extra, io.BytesIO(b"x"))
        with self.assertRaises(ResultPackageError):
            validate_result_package(excessive)

    def test_secret_artifact_and_private_metadata_are_rejected(self) -> None:
        self.stdout.write_bytes(b"sk-" + b"S" * 30)
        with self.assertRaisesRegex(ResultPackageError, "protected material"):
            self.publish()
        self.stdout.write_bytes(b"stdout evidence\n")
        values = self.inputs()
        failures = list(values["failures"])
        failures[0] = {**failures[0], "message": "failed in /private/repository"}
        with self.assertRaisesRegex(ResultPackageError, "protected material"):
            self.publish(
                failures=failures,
                prohibited_metadata_sequences=(b"/private/repository",),
            )

    def test_complete_failure_detail_is_retained_beyond_legacy_sample_cap(self) -> None:
        values = self.inputs()
        cases = []
        failures = []
        for index in range(70):
            case_id = f"case-{index}"
            cases.append(
                {
                    "case_id": case_id,
                    "display_name": case_id,
                    "status": "failed",
                    "duration_seconds": 0.01,
                    "location": f"tests/test_many.py:{index + 1}",
                }
            )
            failures.append(
                {
                    "failure_id": f"failure-{index}",
                    "classification": "test_failure",
                    "message": f"failure detail {index}",
                    "case_id": case_id,
                    "location": f"tests/test_many.py:{index + 1}",
                    "artifact_id": None,
                }
            )
        path, evidence = self.publish(cases=cases, failures=failures)
        package = validate_result_package(path)
        self.assertEqual(evidence.counts["failures"], 70)
        self.assertEqual(
            len(list(iter_result_package_records(package, "failures"))), 70
        )

    def test_failed_case_without_detail_and_stale_identity_fail_closed(self) -> None:
        values = self.inputs()
        with self.assertRaisesRegex(ResultPackageError, "detail is incomplete"):
            self.publish(failures=[])
        path, _evidence = self.publish()
        stale = self.identity()
        stale["generation"] = 4
        with self.assertRaisesRegex(ResultPackageError, "identity is contradictory"):
            validate_result_package(path, expected_identity=stale)


if __name__ == "__main__":
    unittest.main()
