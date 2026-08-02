"""Root-owned authority-runtime manifest and drift controls."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
SCRIPT = REPOSITORY_ROOT / "scripts" / "verify_authority_runtime.py"
if not SCRIPT.is_file():
    raise unittest.SkipTest(
        "repository-level authority runtime verifier is not part of the standalone skill package"
    )
SPEC = importlib.util.spec_from_file_location("authority_runtime", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load authority runtime verifier")
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)

WRAPPER_SCRIPT = REPOSITORY_ROOT / "scripts" / "run_verified_authority.py"
WRAPPER_SPEC = importlib.util.spec_from_file_location(
    "run_verified_authority",
    WRAPPER_SCRIPT,
)
if WRAPPER_SPEC is None or WRAPPER_SPEC.loader is None:
    raise RuntimeError("cannot load verified authority wrapper")
WRAPPER = importlib.util.module_from_spec(WRAPPER_SPEC)
WRAPPER_SPEC.loader.exec_module(WRAPPER)


class AuthorityRuntimePreExecutionOrderingTests(unittest.TestCase):
    """These ordering proofs stay active on non-root CI hosts."""

    def test_static_manifest_mismatch_rejects_before_interpreter_probe(self) -> None:
        approved_static = {
            "schema": VERIFIER.SCHEMA,
            "runtime_root": "/opt/devcoordinator-authority",
            "requirements": {
                "path": "/requirements.txt",
                "sha256": "a" * 64,
                "size": 1,
            },
            "files": [],
        }
        approved = {
            **approved_static,
            "interpreter": dict(VERIFIER.APPROVED_INTERPRETER),
        }
        drifted = {**approved_static, "runtime_root": "/unexpected-runtime"}
        with (
            mock.patch.object(
                VERIFIER,
                "_trusted_manifest",
                return_value=approved,
            ),
            mock.patch.object(
                VERIFIER,
                "_build_static_manifest",
                return_value=drifted,
            ),
            mock.patch.object(VERIFIER, "_interpreter_contract") as probe,
            self.assertRaisesRegex(
                VERIFIER.RuntimeVerificationError,
                "does not match",
            ),
        ):
            VERIFIER.verify_manifest(
                Path("/candidate"),
                Path("/requirements.txt"),
                Path("/manifest.json"),
            )
        probe.assert_not_called()

    def test_interpreter_probe_occurs_only_after_exact_static_match(self) -> None:
        approved_static = {
            "schema": VERIFIER.SCHEMA,
            "runtime_root": "/opt/devcoordinator-authority",
            "requirements": {
                "path": "/requirements.txt",
                "sha256": "b" * 64,
                "size": 2,
            },
            "files": [
                {
                    "path": "bin/python",
                    "sha256": "c" * 64,
                    "size": 3,
                    "mode": "0755",
                }
            ],
        }
        approved = {
            **approved_static,
            "interpreter": dict(VERIFIER.APPROVED_INTERPRETER),
        }
        with (
            mock.patch.object(
                VERIFIER,
                "_trusted_manifest",
                return_value=approved,
            ),
            mock.patch.object(
                VERIFIER,
                "_build_static_manifest",
                return_value=approved_static,
            ),
            mock.patch.object(
                VERIFIER,
                "_interpreter_contract",
                return_value=dict(VERIFIER.APPROVED_INTERPRETER),
            ) as probe,
        ):
            VERIFIER.verify_manifest(
                Path("/opt/devcoordinator-authority"),
                Path("/requirements.txt"),
                Path("/manifest.json"),
            )
        probe.assert_called_once_with(
            Path("/opt/devcoordinator-authority/bin/python")
        )

    def test_wrapper_never_executes_authority_after_manifest_failure(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="authority-wrapper-failure-"
        ) as raw:
            verifier = Path(raw) / "verify.py"
            verifier.write_text("# fixture\n", encoding="utf-8")
            with (
                mock.patch.object(WRAPPER.os, "geteuid", return_value=0),
                mock.patch.object(WRAPPER, "VERIFIER", verifier),
                mock.patch.object(
                    WRAPPER.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess(
                        args=[],
                        returncode=1,
                        stdout='{"ok":false}\n',
                        stderr="",
                    ),
                ) as verify,
                mock.patch.object(WRAPPER.os, "execve") as execute,
            ):
                self.assertEqual(
                    WRAPPER.main(["--", "/reviewed/authority.py"]),
                    1,
                )
            verify.assert_called_once()
            execute.assert_not_called()

    def test_wrapper_executes_only_after_system_verifier_passes(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="authority-wrapper-success-"
        ) as raw:
            verifier = Path(raw) / "verify.py"
            verifier.write_text("# fixture\n", encoding="utf-8")
            with (
                mock.patch.object(WRAPPER.os, "geteuid", return_value=0),
                mock.patch.object(WRAPPER, "VERIFIER", verifier),
                mock.patch.object(
                    WRAPPER.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess(
                        args=[],
                        returncode=0,
                        stdout='{"ok":true}\n',
                        stderr="",
                    ),
                ) as verify,
                mock.patch.object(
                    WRAPPER.os,
                    "execve",
                    return_value=None,
                ) as execute,
                self.assertRaisesRegex(
                    AssertionError,
                    "unexpectedly returned",
                ),
            ):
                WRAPPER.main(
                    [
                        "--",
                        "/reviewed/authority.py",
                        "broker",
                        "read",
                    ]
                )
            verify.assert_called_once_with(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    str(verifier),
                    "verify",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60,
                check=False,
                env={
                    "PATH": "/usr/bin:/bin",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
            )
            execute.assert_called_once_with(
                str(WRAPPER.SYSTEM_PYTHON),
                [
                    str(WRAPPER.SYSTEM_PYTHON),
                    "-I",
                    "-B",
                    "/reviewed/authority.py",
                    "broker",
                    "read",
                ],
                dict(WRAPPER.SAFE_ENVIRONMENT),
            )


@unittest.skipUnless(
    os.geteuid() == 0 and Path("/usr/bin/python3.14").is_file(),
    "real authority-runtime proof requires root and CPython 3.14",
)
class AuthorityRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".authority-runtime-test-",
            dir="/root",
        )
        self.root = Path(self.temporary.name)
        self.runtime = self.root / "runtime"
        subprocess.run(
            [
                "/usr/bin/python3.14",
                "-m",
                "venv",
                "--copies",
                str(self.runtime),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=True,
        )
        lib64 = self.runtime / "lib64"
        self.assertTrue(lib64.is_symlink())
        lib64.unlink()
        for path in [self.root, *self.runtime.rglob("*")]:
            if path.is_symlink():
                continue
            os.chown(path, 0, 0)
            os.chmod(path, stat.S_IMODE(path.stat().st_mode) & ~0o022)
        self.requirements = self.root / "requirements.txt"
        self.requirements.write_text(
            "PyYAML==6.0.3 --hash=sha256:" + "a" * 64 + "\n",
            encoding="utf-8",
        )
        os.chmod(self.requirements, 0o600)
        self.manifest = self.root / "manifest.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create(self) -> None:
        VERIFIER.create_manifest(
            self.runtime,
            self.requirements,
            self.manifest,
        )

    def verify(self) -> None:
        VERIFIER.verify_manifest(
            self.runtime,
            self.requirements,
            self.manifest,
        )

    def test_real_copied_venv_create_and_verify(self) -> None:
        self.create()
        self.verify()

    def test_candidate_manifest_can_bind_the_atomic_live_root(self) -> None:
        live = self.root / "live-runtime"
        VERIFIER.create_manifest(
            self.runtime,
            self.requirements,
            self.manifest,
            recorded_runtime_root=live,
        )
        self.runtime.rename(live)
        VERIFIER.verify_manifest(live, self.requirements, self.manifest)

    def test_create_persists_manifest_before_first_candidate_execution(
        self,
    ) -> None:
        marker_before = self.root / "executed-before-manifest"
        marker_after = self.root / "executed-after-manifest"
        interpreter = self.runtime / "bin" / "python"
        interpreter.write_text(
            "#!/bin/sh\n"
            f"if [ ! -f '{self.manifest}' ]; then "
            f"/usr/bin/touch '{marker_before}'; fi\n"
            f"/usr/bin/touch '{marker_after}'\n"
            "printf '%s\\n' "
            "'{\"implementation\":\"cpython\",\"machine\":\"x86_64\","
            "\"major\":3,\"minor\":14,\"platform\":\"linux\"}'\n",
            encoding="utf-8",
        )
        interpreter.chmod(0o755)
        VERIFIER.create_manifest(
            self.runtime,
            self.requirements,
            self.manifest,
        )
        self.assertTrue(
            marker_after.exists(),
            "the post-manifest interpreter contract probe did not execute",
        )
        self.assertFalse(
            marker_before.exists(),
            "candidate interpreter executed before its create-new manifest",
        )
        self.assertEqual(
            stat.S_IMODE(self.manifest.stat().st_mode),
            0o400,
        )

    def test_hash_mode_and_file_set_drift_fail_closed(self) -> None:
        self.create()
        target = self.runtime / "pyvenv.cfg"
        original = target.read_bytes()
        target.write_bytes(original + b"\n")
        with self.assertRaisesRegex(
            VERIFIER.RuntimeVerificationError,
            "does not match",
        ):
            self.verify()
        target.write_bytes(original)
        os.chmod(target, 0o662)
        with self.assertRaisesRegex(
            VERIFIER.RuntimeVerificationError,
            "writable or linked",
        ):
            self.verify()
        os.chmod(target, 0o644)
        (self.runtime / "unexpected").write_text("drift", encoding="utf-8")
        with self.assertRaisesRegex(
            VERIFIER.RuntimeVerificationError,
            "does not match",
        ):
            self.verify()

    def test_symlink_and_manifest_replacement_fail_closed(self) -> None:
        (self.runtime / "unexpected-link").symlink_to("pyvenv.cfg")
        with self.assertRaisesRegex(
            VERIFIER.RuntimeVerificationError,
            "writable or linked",
        ):
            VERIFIER.build_manifest(self.runtime, self.requirements)
        (self.runtime / "unexpected-link").unlink()
        self.create()
        os.chmod(self.manifest, 0o600)
        with self.assertRaisesRegex(
            VERIFIER.RuntimeVerificationError,
            "manifest is untrusted",
        ):
            self.verify()

    def test_drifted_interpreter_is_rejected_before_it_can_execute(self) -> None:
        self.create()
        marker = self.root / "sentinel-executed"
        interpreter = self.runtime / "bin" / "python"
        interpreter.write_text(
            "#!/bin/sh\n"
            f"/usr/bin/touch {marker}\n"
            "exit 0\n",
            encoding="utf-8",
        )
        interpreter.chmod(0o755)
        with self.assertRaisesRegex(
            VERIFIER.RuntimeVerificationError,
            "does not match",
        ):
            self.verify()
        self.assertFalse(
            marker.exists(),
            "the drifted authority interpreter executed before hash proof",
        )


if __name__ == "__main__":
    unittest.main()
