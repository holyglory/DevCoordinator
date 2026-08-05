from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import threading
import unittest

from devcoordinator.runtime_artifacts import (
    RUNTIME_LOG_MAX_BYTES,
    RUNTIME_LOG_MAX_LINES,
    load_latest_runtime_log_artifact,
    load_runtime_log_artifact,
    persist_runtime_log_artifact,
)


class RuntimeArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="devcoordinator-runtime-artifacts-"
        )
        self.root = Path(self.temporary.name).resolve() / "logs"
        self.root.mkdir(mode=0o700)
        self.target = "11111111-1111-4111-8111-111111111111"
        self.docker_resource = "22222222-2222-4222-8222-222222222222"
        self.container = "a" * 64

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def persist(self, raw: bytes, **changes):
        values = {
            "root": self.root,
            "artifact_kind": "docker",
            "target_resource_id": self.target,
            "docker_resource_id": self.docker_resource,
            "full_container_id": self.container,
            "raw": raw,
            "request": {
                "options": {"env": {"PASSWORD": "fixture-secret-value"}}
            },
        }
        values.update(changes)
        return persist_runtime_log_artifact(**values)

    def test_capture_is_secret_redacted_line_and_byte_bounded(self) -> None:
        raw = (
            b"Authorization: Bearer bearer-secret\n"
            b"password=fixture-secret-value\n"
            + b"x" * (RUNTIME_LOG_MAX_BYTES + 128 * 1024)
            + b"\n"
            + b"tail\n" * (RUNTIME_LOG_MAX_LINES + 10)
        )
        result = self.persist(raw, input_discarded_bytes=99)
        manifest, path = load_runtime_log_artifact(
            root=self.root,
            artifact_kind="docker",
            artifact_id=result["artifact_id"],
        )
        payload = path.read_bytes()
        self.assertLessEqual(len(payload), RUNTIME_LOG_MAX_BYTES)
        self.assertLessEqual(len(payload.decode("utf-8").splitlines()), RUNTIME_LOG_MAX_LINES)
        self.assertNotIn(b"bearer-secret", payload)
        self.assertNotIn(b"fixture-secret-value", payload)
        self.assertTrue(result["truncated"])
        self.assertEqual(manifest["input_discarded_bytes"], 99)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_typed_artifact_cannot_cross_resource_kind_or_accept_tampering(self) -> None:
        result = self.persist(b"crash line\n")
        with self.assertRaises(OSError):
            load_runtime_log_artifact(
                root=self.root,
                artifact_kind="database_stack",
                artifact_id=result["artifact_id"],
            )
        path = Path(result["path"])
        path.write_text("replacement data", encoding="utf-8")
        path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "manifest"):
            load_runtime_log_artifact(
                root=self.root,
                artifact_kind="docker",
                artifact_id=result["artifact_id"],
            )

    def test_latest_capture_is_exact_identity_bound_across_concurrent_writers(self) -> None:
        results = []
        errors = []

        def writer(index: int) -> None:
            try:
                results.append(self.persist(f"capture-{index}\n".encode()))
            except BaseException as error:  # pragma: no cover - assertion below
                errors.append(error)

        threads = [threading.Thread(target=writer, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 8)
        latest = load_latest_runtime_log_artifact(
            root=self.root,
            artifact_kind="docker",
            target_resource_id=self.target,
            docker_resource_id=self.docker_resource,
            full_container_id=self.container,
        )
        self.assertIsNotNone(latest)
        self.assertIn(latest["artifact_id"], {item["artifact_id"] for item in results})
        self.assertIsNone(
            load_latest_runtime_log_artifact(
                root=self.root,
                artifact_kind="docker",
                target_resource_id=self.target,
                docker_resource_id=self.docker_resource,
                full_container_id="b" * 64,
            ),
            "a replaced container must not inherit the old artifact pointer",
        )

    def test_manifest_never_contains_an_absolute_host_path(self) -> None:
        result = self.persist(b"stopped\n")
        manifest_path = self.root / f"runtime-docker-{result['artifact_id']}.json"
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertFalse(Path(document["filename"]).is_absolute())
        self.assertNotIn(str(self.root), json.dumps(document, sort_keys=True))

    def test_local_metadata_is_not_authorization_but_symlink_root_is_rejected(self) -> None:
        result = self.persist(b"metadata independent\n")
        self.root.chmod(0o777)
        Path(result["path"]).chmod(0o666)
        manifest, path = load_runtime_log_artifact(
            root=self.root,
            artifact_kind="docker",
            artifact_id=result["artifact_id"],
        )
        self.assertEqual(path.read_bytes(), b"metadata independent\n")
        alias = self.root.parent / "logs-link"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            load_runtime_log_artifact(
                root=alias,
                artifact_kind="docker",
                artifact_id=result["artifact_id"],
            )


if __name__ == "__main__":
    unittest.main()
