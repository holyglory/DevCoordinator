"""Focused contract tests for the root-only image publication boundary."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest import mock

from devcoordinator import image_publication as publication
from devcoordinator.compose_contract import require_effective_compose_model


IMAGE_ID = "sha256:" + "1" * 64
SOURCE_FINGERPRINT = "2" * 64


def rendered_model(**_kwargs: object) -> bytes:
    return json.dumps(
        {
            "name": "demo",
            "services": {
                "migrate": {"image": "postgres:17-alpine"},
                "worker": {"image": "example/worker:local"},
                "helper": {"image": "example/worker:local"},
            },
        }
    ).encode("utf-8")


class ImagePublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.project = self.root / "project"
        self.project.mkdir(mode=0o700)
        (self.project / ".dockerignore").write_text("**/bin\n**/obj\n", encoding="utf-8")
        source = self.project / "services/worker/src/App"
        source.mkdir(parents=True)
        (source / "App.csproj").write_text("<Project />\n", encoding="utf-8")
        (source / "packages.lock.json").write_text("{}\n", encoding="utf-8")
        (source / "Program.cs").write_text("class Program {}\n", encoding="utf-8")
        dockerfile = self.project / "services/worker/Dockerfile"
        dockerfile.parent.mkdir(exist_ok=True)
        dockerfile.write_text(
            "ARG SDK_IMAGE=example/sdk@sha256:" + "a" * 64 + "\n"
            "FROM ${SDK_IMAGE}\n"
            "COPY services/worker/src/App/ services/worker/src/App/\n",
            encoding="utf-8",
        )
        (self.project / "compose.yml").write_text(
            "services:\n  migrate:\n    image: postgres:17-alpine\n  worker:\n    image: example/worker:local\n  helper:\n    image: example/worker:local\n",
            encoding="utf-8",
        )
        environment = self.project / ".env"
        environment.write_text("TOKEN=fixture-not-recorded\n", encoding="utf-8")
        os.chmod(environment, 0o600)
        self.config = {
            "docker": {
                "compose_files": ["compose.yml"],
                "env_files": [".env"],
                "project_name": "demo",
                "services": ["migrate", "worker", "helper"],
            },
            "image_publications": [
                {
                    "name": "worker",
                    "image": "example/worker:local",
                    "dockerfile": "services/worker/Dockerfile",
                    "context_paths": [
                        ".dockerignore",
                        "services/worker/Dockerfile",
                        "services/worker/src/App",
                    ],
                    "source_fingerprint": {
                        "root": "services/worker/src/App",
                        "exclude_directories": ["bin", "obj"],
                    },
                    "rollout_services": ["migrate", "worker", "helper"],
                    "migration_service": "migrate",
                    "workload_service": "worker",
                    "workload_container": "demo-worker",
                    "ready_url": "http://127.0.0.1:5080/readyz",
                    "health_url": "http://127.0.0.1:5080/healthz",
                    "health_timeout_seconds": 10,
                }
            ],
        }
        self.specification = publication.normalize_publication_spec(
            project=self.project, runtime_config=self.config, name="worker"
        )
        self.artifacts = self.root / "artifacts"
        self.broker_database = self.root / "broker.sqlite"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_plan_freezes_context_and_omits_environment_payload(self) -> None:
        with mock.patch.object(publication, "docker_image_id", return_value=IMAGE_ID):
            result = publication.plan_publication(
                specification=self.specification,
                artifact_root=self.artifacts,
                operation_id="11111111-1111-4111-8111-111111111111",
                service_uid=os.geteuid(),
                broker_database_path=self.broker_database,
                compose_renderer=rendered_model,
                compose_enrollment_verifier=self._enrollment_verifier,
            )

        directory, manifest = publication.load_manifest(
            artifact_root=self.artifacts,
            operation_id=result["operation_id"],
            expected_uid=os.geteuid(),
        )
        self.assertEqual(manifest["status"], "planned")
        self.assertEqual(manifest["previous_image_id"], IMAGE_ID)
        self.assertNotIn("TOKEN=fixture-not-recorded", json.dumps(manifest))
        snapshot_source = directory / "context/services/worker/src/App/Program.cs"
        self.assertEqual(snapshot_source.read_text(encoding="utf-8"), "class Program {}\n")
        self.assertEqual(
            manifest["source"]["fingerprint"],
            publication.source_tree_fingerprint(
                directory / "context/services/worker/src/App", ("bin", "obj")
            ),
        )

    def test_plan_rejects_symlinked_context_input(self) -> None:
        target = self.project / "outside.cs"
        target.write_text("outside\n", encoding="utf-8")
        (self.project / "services/worker/src/App/linked.cs").symlink_to(target)
        with mock.patch.object(publication, "docker_image_id", return_value=None):
            with self.assertRaisesRegex(publication.ImagePublicationError, "symbolic links"):
                publication.plan_publication(
                    specification=self.specification,
                    artifact_root=self.artifacts,
                    operation_id="22222222-2222-4222-8222-222222222222",
                    service_uid=os.geteuid(),
                    broker_database_path=self.broker_database,
                    compose_renderer=rendered_model,
                    compose_enrollment_verifier=self._enrollment_verifier,
                )
        self.assertFalse((self.artifacts / "22222222-2222-4222-8222-222222222222").exists())

    def test_planned_snapshot_passes_apply_integrity_check(self) -> None:
        with mock.patch.object(publication, "docker_image_id", return_value=IMAGE_ID):
            plan = publication.plan_publication(
                specification=self.specification,
                artifact_root=self.artifacts,
                operation_id="24242424-2424-4242-8242-242424242424",
                service_uid=os.geteuid(),
                broker_database_path=self.broker_database,
                compose_renderer=rendered_model,
                compose_enrollment_verifier=self._enrollment_verifier,
            )
        directory, manifest = publication.load_manifest(
            artifact_root=self.artifacts,
            operation_id=plan["operation_id"],
            expected_uid=os.geteuid(),
        )

        publication._require_snapshot_integrity(
            manifest,
            directory / "context",
            self.specification,
        )

    def test_build_argv_is_fixed_and_carries_snapshot_labels(self) -> None:
        manifest = {
            "source": {"fingerprint": "a" * 64},
            "snapshot": {"input_manifest_sha256": "b" * 64},
        }
        command = publication.build_command_for(
            manifest, self.root / "snapshot", self.specification
        )
        self.assertEqual(command[:3], ("docker", "build", "--pull=false"))
        self.assertIn("--file", command)
        self.assertIn("--tag", command)
        self.assertIn("io.devcoordinator.source-fingerprint=" + "a" * 64, command)
        self.assertIn("--build-arg", command)
        self.assertIn("DEVCOORDINATOR_SOURCE_FINGERPRINT=" + "a" * 64, command)
        self.assertNotIn("--network", command)

    def test_compose_capture_rejects_input_drift_before_returning_material(self) -> None:
        original_hashes = publication._file_hashes
        calls = 0

        def drifting_hashes(root: Path, paths: tuple[str, ...]) -> list[dict[str, str]]:
            nonlocal calls
            calls += 1
            result = original_hashes(root, paths)
            if calls == 3:
                return [{"path": "drift", "sha256": "0" * 64}]
            return result

        with mock.patch.object(publication, "_file_hashes", side_effect=drifting_hashes):
            with self.assertRaisesRegex(publication.ImagePublicationError, "changed while publication evidence"):
                publication.capture_compose_material(
                    self.specification,
                    renderer=rendered_model,
                    broker_database_path=self.broker_database,
                    enrollment_verifier=self._enrollment_verifier,
                )

    def test_compose_capture_uses_the_enrollment_model_canonicalization(self) -> None:
        observed: dict[str, object] = {}

        def verify(
            _specification: publication.PublicationSpec,
            evidence: dict[str, object],
            effective: object,
            _database: Path,
        ) -> dict[str, object]:
            observed["model_sha256"] = evidence["model_sha256"]
            observed["effective_model_sha256"] = getattr(effective, "model_sha256")
            return self._enrollment_verifier(
                _specification, evidence, effective, _database
            )

        publication.capture_compose_material(
            self.specification,
            renderer=rendered_model,
            broker_database_path=self.broker_database,
            enrollment_verifier=verify,
        )

        self.assertEqual(observed["model_sha256"], observed["effective_model_sha256"])

    def test_enrollment_reader_accepts_the_canonical_capture_digest(self) -> None:
        material = publication.capture_compose_material(
            self.specification,
            renderer=rendered_model,
            broker_database_path=self.broker_database,
            enrollment_verifier=self._enrollment_verifier,
        )
        effective = require_effective_compose_model(
            rendered_model(),
            declared_services=self.specification.compose_services,
            declared_profiles=self.specification.compose_profiles,
            project_name=self.specification.compose_project_name,
            host_access_approved=True,
        )
        definition_id = "00000000-0000-4000-8000-000000000000"
        definition_fingerprint = "sha256:" + "c" * 64
        with sqlite3.connect(self.broker_database) as database:
            database.executescript(
                """
                CREATE TABLE repositories (repo_id TEXT, canonical_root TEXT);
                CREATE TABLE broker_compose_definitions (
                    compose_definition_id TEXT,
                    repo_id TEXT,
                    cwd TEXT,
                    project_name TEXT,
                    definition_fingerprint TEXT,
                    enabled INTEGER
                );
                CREATE TABLE broker_compose_effective_model_evidence (
                    compose_definition_id TEXT,
                    definition_fingerprint TEXT,
                    model_sha256 TEXT,
                    services_json TEXT,
                    profiles_json TEXT,
                    host_access_risks_json TEXT,
                    host_access_approved INTEGER,
                    approved_by_uid INTEGER,
                    approved_at TEXT
                );
                CREATE TABLE broker_compose_file_evidence (
                    compose_definition_id TEXT,
                    ordinal INTEGER,
                    content_sha256 TEXT
                );
                CREATE TABLE broker_compose_env_file_evidence (
                    compose_definition_id TEXT,
                    ordinal INTEGER,
                    content_sha256 TEXT
                );
                """
            )
            database.execute(
                "INSERT INTO repositories VALUES (?, ?)",
                ("repo", str(self.project)),
            )
            database.execute(
                "INSERT INTO broker_compose_definitions VALUES (?, ?, ?, ?, ?, 1)",
                (
                    definition_id,
                    "repo",
                    str(self.project),
                    self.specification.compose_project_name,
                    definition_fingerprint,
                ),
            )
            database.execute(
                "INSERT INTO broker_compose_effective_model_evidence VALUES (?, ?, ?, ?, ?, ?, 1, 0, ?)",
                (
                    definition_id,
                    definition_fingerprint,
                    effective.model_sha256,
                    json.dumps(sorted(self.specification.compose_services)),
                    json.dumps(list(effective.profiles)),
                    json.dumps(list(effective.host_access_risks)),
                    "2026-07-23T00:00:00Z",
                ),
            )
            database.executemany(
                "INSERT INTO broker_compose_file_evidence VALUES (?, ?, ?)",
                [
                    (definition_id, index, item["sha256"])
                    for index, item in enumerate(material.evidence["compose_files"])
                ],
            )
            database.executemany(
                "INSERT INTO broker_compose_env_file_evidence VALUES (?, ?, ?)",
                [
                    (definition_id, index, item["sha256"])
                    for index, item in enumerate(material.evidence["env_files"])
                ],
            )
        database.close()

        with mock.patch.object(
            publication,
            "_require_private_regular_file",
            return_value=self.broker_database.stat(),
        ):
            enrollment = publication.require_enrolled_compose_approval(
                self.specification,
                material.evidence,
                effective,
                self.broker_database,
            )

        self.assertEqual(enrollment["model_sha256"], effective.model_sha256)

    def test_runtime_verification_requires_built_image_and_source_fingerprint(self) -> None:
        def runner(command: tuple[str, ...], _timeout: float, _environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
            self.assertEqual(command[:3], ("docker", "inspect", "--format"))
            return subprocess.CompletedProcess(command, 0, stdout=IMAGE_ID + "\n", stderr="")

        responses = {
            self.specification.ready_url: (200, "{}"),
            self.specification.health_url: (
                200,
                json.dumps({"build": {"sourceFingerprint": SOURCE_FINGERPRINT}}),
            ),
        }
        result = publication.verify_published_runtime(
            self.specification,
            expected_image_id=IMAGE_ID,
            expected_source_fingerprint=SOURCE_FINGERPRINT,
            run_docker=runner,
            environment={},
            fetcher=lambda url, _timeout: responses[url],
            now=lambda: 100.0,
        )
        self.assertEqual(result["image_id"], IMAGE_ID)
        self.assertEqual(result["source_fingerprint"], SOURCE_FINGERPRINT)

    def test_runtime_verification_rejects_legacy_health_payload(self) -> None:
        with self.assertRaisesRegex(publication.ImagePublicationError, "source fingerprint"):
            publication.verify_published_runtime(
                self.specification,
                expected_image_id=IMAGE_ID,
                expected_source_fingerprint=SOURCE_FINGERPRINT,
                run_docker=lambda command, _timeout, _environment: subprocess.CompletedProcess(
                    command, 0, stdout=IMAGE_ID + "\n", stderr=""
                ),
                environment={},
                fetcher=lambda url, _timeout: (200, "{}"),
                now=lambda: 100.0,
            )

    def test_apply_refuses_source_drift_before_any_docker_mutation(self) -> None:
        with mock.patch.object(publication, "docker_image_id", return_value=IMAGE_ID):
            plan = publication.plan_publication(
                specification=self.specification,
                artifact_root=self.artifacts,
                operation_id="33333333-3333-4333-8333-333333333333",
                service_uid=os.geteuid(),
                broker_database_path=self.broker_database,
                compose_renderer=rendered_model,
                compose_enrollment_verifier=self._enrollment_verifier,
            )
            (self.project / "services/worker/src/App/Program.cs").write_text(
                "class Program { static int Changed = 1; }\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(publication.ImagePublicationError, "source changed"):
                publication.apply_publication(
                    specification=self.specification,
                    artifact_root=self.artifacts,
                    operation_id=plan["operation_id"],
                    confirmation_fingerprint=plan["plan_fingerprint"],
                    service_uid=os.geteuid(),
                    broker_database_path=self.broker_database,
                    compose_renderer=rendered_model,
                    compose_enrollment_verifier=self._enrollment_verifier,
                    docker_runner=lambda *_args: self.fail("Docker must not run after source drift"),
                )

    def test_failed_build_records_bounded_redacted_diagnostic(self) -> None:
        with mock.patch.object(publication, "docker_image_id", return_value=IMAGE_ID), mock.patch.object(
            publication, "_docker_environment", return_value={}
        ):
            plan = publication.plan_publication(
                specification=self.specification,
                artifact_root=self.artifacts,
                operation_id="34343434-3434-4343-8343-343434343434",
                service_uid=os.geteuid(),
                broker_database_path=self.broker_database,
                compose_renderer=rendered_model,
                compose_enrollment_verifier=self._enrollment_verifier,
            )
            with self.assertRaisesRegex(publication.ImagePublicationError, "image build failed"):
                publication.apply_publication(
                    specification=self.specification,
                    artifact_root=self.artifacts,
                    operation_id=plan["operation_id"],
                    confirmation_fingerprint=plan["plan_fingerprint"],
                    service_uid=os.geteuid(),
                    broker_database_path=self.broker_database,
                    compose_renderer=rendered_model,
                    compose_enrollment_verifier=self._enrollment_verifier,
                    docker_runner=lambda command, _timeout, _environment: subprocess.CompletedProcess(
                        command,
                        1,
                        stdout="restore TOKEN=do-not-leak-diagnostic\n" + "x" * 5000,
                        stderr="Authorization: " + "Bearer " + "do-not-leak-bearer\n",
                    ),
                )
        _directory, manifest = publication.load_manifest(
            artifact_root=self.artifacts,
            operation_id=plan["operation_id"],
            expected_uid=os.geteuid(),
        )
        diagnostic = manifest["build_diagnostic"]
        self.assertNotIn("do-not-leak-diagnostic", json.dumps(diagnostic))
        self.assertNotIn("do-not-leak-bearer", json.dumps(diagnostic))
        self.assertLessEqual(len(diagnostic["stdout_tail"]), publication.BUILD_DIAGNOSTIC_LIMIT + 3)

    def test_apply_persists_failed_rollout_diagnostic(self) -> None:
        with mock.patch.object(publication, "docker_image_id", return_value=IMAGE_ID), mock.patch.object(
            publication, "_docker_environment", return_value={}
        ):
            plan = publication.plan_publication(
                specification=self.specification,
                artifact_root=self.artifacts,
                operation_id="35353535-3535-4353-8353-353535353535",
                service_uid=os.geteuid(),
                broker_database_path=self.broker_database,
                compose_renderer=rendered_model,
                compose_enrollment_verifier=self._enrollment_verifier,
            )
            _directory, planned = publication.load_manifest(
                artifact_root=self.artifacts,
                operation_id=plan["operation_id"],
                expected_uid=os.geteuid(),
            )
            image = {
                "image_id": IMAGE_ID,
                "repo_digests": [],
                "labels": {
                    "io.devcoordinator.publication": self.specification.name,
                    "io.devcoordinator.source-fingerprint": planned["source"]["fingerprint"],
                    "io.devcoordinator.input-fingerprint": planned["snapshot"]["input_manifest_sha256"],
                },
            }
            failed = publication.ComposeRolloutError(
                completed_phases=[],
                failed_services=("migrate",),
                result=subprocess.CompletedProcess(
                    ("docker", "compose"),
                    1,
                    stdout="TOKEN=do-not-leak-diagnostic\n",
                    stderr="Authorization: " + "Bearer " + "do-not-leak-bearer\n",
                ),
            )
            with mock.patch.object(publication, "docker_image_evidence", return_value=image), mock.patch.object(
                publication, "installed_package_identity", return_value="libgssapi-krb5-2=1.0:amd64"
            ), mock.patch.object(publication, "run_compose_rollout", side_effect=failed):
                with self.assertRaisesRegex(publication.ImagePublicationError, "pending reconciliation"):
                    publication.apply_publication(
                        specification=self.specification,
                        artifact_root=self.artifacts,
                        operation_id=plan["operation_id"],
                        confirmation_fingerprint=plan["plan_fingerprint"],
                        service_uid=os.geteuid(),
                        broker_database_path=self.broker_database,
                        compose_renderer=rendered_model,
                        compose_enrollment_verifier=self._enrollment_verifier,
                        docker_runner=lambda command, _timeout, _environment: subprocess.CompletedProcess(
                            command, 0, stdout="ok", stderr=""
                        ),
                    )
        _directory, manifest = publication.load_manifest(
            artifact_root=self.artifacts,
            operation_id=plan["operation_id"],
            expected_uid=os.geteuid(),
        )
        diagnostic = manifest["rollout_diagnostic"]
        self.assertEqual(manifest["status"], "rollout_pending")
        self.assertEqual(diagnostic["failed_services"], ["migrate"])
        self.assertNotIn("do-not-leak-diagnostic", json.dumps(diagnostic))
        self.assertNotIn("do-not-leak-bearer", json.dumps(diagnostic))

    def test_rollout_uses_only_sealed_no_build_force_recreate_commands(self) -> None:
        commands: list[tuple[str, ...]] = []

        def fake_compose(
            command: tuple[str, ...], _cwd: str, _timeout: float, _environment: dict[str, str]
        ) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

        material = publication.ComposeMaterial(
            compose_payloads=(
                b"services:\n  migrate:\n    image: postgres:17-alpine\n  worker:\n    image: example/worker:local\n  helper:\n    image: example/worker:local\n",
            ),
            env_payloads=(b"TOKEN=fixture-sealed\n",),
            evidence={},
        )
        with mock.patch.object(publication, "_resolve_docker_executable", return_value="/usr/bin/docker"), mock.patch.object(
            publication, "_run_compose_command", side_effect=fake_compose
        ):
            result = publication.run_compose_rollout(
                self.specification,
                run_docker=lambda *_args: self.fail("rollout must use the sealed compose runner"),
                material=material,
            )
        self.assertEqual(
            [(item["action"], item["services"]) for item in result["phases"]],
            [
                ("clean-cutover", ["migrate", "worker", "helper"]),
                ("up", ["migrate"]),
                ("up", ["worker", "helper"]),
            ],
        )
        self.assertEqual(len(commands), 3)
        cleanup = commands[0]
        self.assertIn("rm", cleanup)
        self.assertIn("--force", cleanup)
        self.assertIn("--stop", cleanup)
        self.assertNotIn("--volumes", cleanup)
        for command in commands[1:]:
            self.assertIn("--no-build", command)
            self.assertIn("--force-recreate", command)
            self.assertNotIn("build", command)
            self.assertIn("--env-file", command)
            self.assertIn("--file", command)

    def test_rollout_failure_preserves_its_failed_phase_evidence(self) -> None:
        material = publication.ComposeMaterial(
            compose_payloads=(
                b"services:\n  migrate:\n    image: postgres:17-alpine\n  worker:\n    image: example/worker:local\n",
            ),
            env_payloads=(b"TOKEN=fixture-sealed\n",),
            evidence={},
        )
        with mock.patch.object(publication, "_resolve_docker_executable", return_value="/usr/bin/docker"), mock.patch.object(
            publication,
            "_run_compose_command",
            side_effect=[
                subprocess.CompletedProcess(
                    ("docker", "compose"), 0, stdout="removed", stderr=""
                ),
                subprocess.CompletedProcess(
                    ("docker", "compose"),
                    1,
                    stdout="TOKEN=do-not-leak-diagnostic\n",
                    stderr="Authorization: " + "Bearer " + "do-not-leak-bearer\n",
                ),
            ],
        ):
            with self.assertRaises(publication.ComposeRolloutError) as raised:
                publication.run_compose_rollout(
                    self.specification,
                    run_docker=lambda *_args: self.fail("rollout must use the sealed compose runner"),
                    material=material,
                )
        self.assertEqual(raised.exception.evidence["failed_services"], ["migrate"])
        self.assertNotIn("do-not-leak-diagnostic", json.dumps(raised.exception.evidence))
        self.assertNotIn("do-not-leak-bearer", json.dumps(raised.exception.evidence))

    @staticmethod
    def _enrollment_verifier(
        _specification: publication.PublicationSpec,
        _evidence: dict[str, object],
        _effective: object,
        _database: Path,
    ) -> dict[str, object]:
        return {
            "compose_definition_id": "00000000-0000-4000-8000-000000000000",
            "definition_fingerprint": "sha256:" + "c" * 64,
            "model_sha256": "sha256:" + "d" * 64,
            "host_access_approved": True,
            "approved_by_uid": 0,
            "approved_at": "2026-07-23T00:00:00Z",
        }


if __name__ == "__main__":
    unittest.main()
