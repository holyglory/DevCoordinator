from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest

import devcoordinator.universal_test_preflight as preflight
from devcoordinator.universal_test_preflight import (
    PREFLIGHT_ATTESTATION_KIND,
    RELEASE_SCRIPT_RELATIVE,
    TestPlanePreflightError,
    production_test_plane_preflight,
)


class UniversalTestPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cgroup = self.root / "cgroup"
        self.runtime = self.root / "systemd"
        self.cgroup.mkdir()
        self.runtime.mkdir()
        (self.cgroup / "cgroup.controllers").write_text("cpu memory pids\n")
        self.boot_id = self.root / "boot-id"
        self.boot_id.write_text("12345678-1234-4567-89ab-123456789abc\n")
        self.release_digest = "a" * 64
        self.release_root = self.root / "releases"
        self.script = self.release_root / self.release_digest / RELEASE_SCRIPT_RELATIVE
        self.script.parent.mkdir(parents=True)
        self.script.write_bytes(Path(preflight.__file__).read_bytes())
        self.script.chmod(0o444)
        self.calls: list[tuple[str, ...]] = []

    def arguments(self) -> dict[str, object]:
        return {
            "release_root": self.release_root,
            "release_digest": self.release_digest,
            "script": self.script,
            "boot_id_path": self.boot_id,
            "host_nonloopback_address": "192.0.2.10",
        }

    def runner(self, argv, **_kwargs):
        values = tuple(argv)
        self.calls.append(values)
        stdout = "systemd 255 (255.4)\n" if values[-1] == "--version" else ""
        return subprocess.CompletedProcess(values, 0, stdout=stdout, stderr="")

    def test_live_probe_is_blocking_and_exercises_credentials_and_namespaces(self) -> None:
        document = production_test_plane_preflight(
            **self.arguments(),
            runner=self.runner,
            effective_uid=0,
            cgroup_root=self.cgroup,
            systemd_runtime=self.runtime,
            credential_root=self.root,
        )
        self.assertTrue(document["ok"])
        self.assertTrue(document["blocking"])
        self.assertEqual(document["kind"], PREFLIGHT_ATTESTATION_KIND)
        self.assertEqual(document["release_root"], str(self.release_root))
        self.assertEqual(document["release_digest"], self.release_digest)
        self.assertEqual(document["executor"], "/usr/bin/python3")
        self.assertEqual(document["script"], str(self.script))
        self.assertEqual(document["host_boot_id"], self.boot_id.read_text().strip())
        self.assertEqual(len(document["executor_sha256"]), 64)
        self.assertEqual(len(document["script_sha256"]), 64)
        self.assertNotIn("evidence_sha256", document)
        unsigned = {
            key: value for key, value in document.items() if key != "document_sha256"
        }
        self.assertEqual(
            document["document_sha256"],
            hashlib.sha256(
                json.dumps(
                    unsigned,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("utf-8")
            ).hexdigest(),
        )
        self.assertEqual(
            set(document),
            {
                "schema_version",
                "kind",
                "ok",
                "blocking",
                "release_root",
                "release_digest",
                "executor",
                "executor_sha256",
                "script",
                "script_sha256",
                "observed_at",
                "host_boot_id",
                "systemd_version",
                "checks",
                "document_sha256",
            },
        )
        flattened = "\n".join(" ".join(call) for call in self.calls)
        self.assertIn("PrivateNetwork=yes", flattened)
        self.assertIn("IPAddressDeny=any", flattened)
        self.assertIn("IPAddressAllow=localhost", flattened)
        self.assertIn("LoadCredential=fixture-proof:", flattened)
        self.assertIn("NetworkNamespacePath=/proc/1/ns/net", flattened)
        self.assertNotIn("MemoryMax=", flattened)
        self.assertNotIn("TasksMax=", flattened)
        self.assertNotIn("CPUQuota=", flattened)
        self.assertEqual(flattened.count("LoadCredential=fixture-proof:"), 2)
        checks = {item["id"] for item in document["checks"]}
        self.assertTrue(
            {
                "host-loopback-host-127",
                "host-loopback-nonloopback-denied",
                "private-loopback-host-denied",
            }.issubset(checks)
        )
        host_call = next(
            call
            for call in self.calls
            if any(item.endswith("-host-loopback") for item in call)
        )
        host_properties = "\n".join(host_call)
        self.assertNotIn("PrivateNetwork=", host_properties)
        self.assertNotIn("NetworkNamespacePath=", host_properties)
        self.assertIn("IPAddressDeny=any", host_properties)
        self.assertIn("IPAddressAllow=localhost", host_properties)
        private_host_call = next(
            call
            for call in self.calls
            if any(item.endswith("-private-host-denied") for item in call)
        )
        self.assertIn("PrivateNetwork=yes", "\n".join(private_host_call))

    def test_non_root_or_missing_cgroup_blocks_activation_before_probe(self) -> None:
        with self.assertRaisesRegex(TestPlanePreflightError, "root authority"):
            production_test_plane_preflight(
                **self.arguments(),
                runner=self.runner,
                effective_uid=1000,
                cgroup_root=self.cgroup,
                systemd_runtime=self.runtime,
                credential_root=self.root,
            )
        (self.cgroup / "cgroup.controllers").unlink()
        with self.assertRaisesRegex(TestPlanePreflightError, "cgroup v2"):
            production_test_plane_preflight(
                **self.arguments(),
                runner=self.runner,
                effective_uid=0,
                cgroup_root=self.cgroup,
                systemd_runtime=self.runtime,
                credential_root=self.root,
            )
        self.assertEqual(self.calls, [])

    def test_failed_live_probe_blocks_activation(self) -> None:
        def failing(argv, **_kwargs):
            values = tuple(argv)
            if values[-1] == "--version":
                return subprocess.CompletedProcess(values, 0, stdout="systemd 255\n", stderr="")
            return subprocess.CompletedProcess(values, 1, stdout="", stderr="denied")

        with self.assertRaisesRegex(TestPlanePreflightError, "private loopback"):
            production_test_plane_preflight(
                **self.arguments(),
                runner=failing,
                effective_uid=0,
                cgroup_root=self.cgroup,
                systemd_runtime=self.runtime,
                credential_root=self.root,
            )

    def test_failed_host_loopback_probe_blocks_activation(self) -> None:
        def failing_host_loopback(argv, **_kwargs):
            values = tuple(argv)
            if values[-1] == "--version":
                return subprocess.CompletedProcess(
                    values, 0, stdout="systemd 255\n", stderr=""
                )
            if any(item.endswith("-host-loopback") for item in values):
                return subprocess.CompletedProcess(
                    values, 73, stdout="", stderr="non-loopback allowed"
                )
            return subprocess.CompletedProcess(values, 0, stdout="", stderr="")

        with self.assertRaisesRegex(TestPlanePreflightError, "host 127"):
            production_test_plane_preflight(
                **self.arguments(),
                runner=failing_host_loopback,
                effective_uid=0,
                cgroup_root=self.cgroup,
                systemd_runtime=self.runtime,
                credential_root=self.root,
            )

    def test_release_binding_rejects_writable_or_stale_script_before_probe(self) -> None:
        self.script.chmod(0o644)
        with self.assertRaisesRegex(TestPlanePreflightError, "script binding"):
            production_test_plane_preflight(
                **self.arguments(),
                runner=self.runner,
                effective_uid=0,
                cgroup_root=self.cgroup,
                systemd_runtime=self.runtime,
                credential_root=self.root,
            )
        self.script.chmod(0o444)
        arguments = self.arguments()
        arguments["release_digest"] = "b" * 64
        with self.assertRaisesRegex(TestPlanePreflightError, "script is unavailable"):
            production_test_plane_preflight(
                **arguments,
                runner=self.runner,
                effective_uid=0,
                cgroup_root=self.cgroup,
                systemd_runtime=self.runtime,
                credential_root=self.root,
            )
        self.assertEqual(self.calls, [])

    def test_invalid_boot_identity_blocks_activation_before_live_probe(self) -> None:
        self.boot_id.write_text("not-a-boot-id\n")
        with self.assertRaisesRegex(TestPlanePreflightError, "boot identity"):
            production_test_plane_preflight(
                **self.arguments(),
                runner=self.runner,
                effective_uid=0,
                cgroup_root=self.cgroup,
                systemd_runtime=self.runtime,
                credential_root=self.root,
            )
        self.assertEqual(self.calls, [])

    @unittest.skipUnless(
        os.environ.get("DEVCOORDINATOR_RUN_LIVE_SYSTEMD_TESTS") == "1"
        and os.geteuid() == 0
        and Path("/run/systemd/system").is_dir(),
        "requires explicit root live-systemd harness opt-in",
    )
    def test_live_systemd_host_loopback_isolation_harness(self) -> None:
        arguments = self.arguments()
        arguments.pop("host_nonloopback_address")
        document = production_test_plane_preflight(
            **arguments,
            effective_uid=0,
            credential_root=self.root,
        )
        checks = {item["id"]: item["ok"] for item in document["checks"]}
        for identifier in (
            "host-loopback-host-127",
            "host-loopback-nonloopback-denied",
            "private-loopback-host-denied",
        ):
            self.assertIs(checks[identifier], True)


if __name__ == "__main__":
    unittest.main()
