"""Failure-shaped tests for authority-runtime atomic activation and rollback."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
SCRIPT = REPOSITORY_ROOT / "scripts" / "install_authority_runtime.py"
if not SCRIPT.is_file():
    raise unittest.SkipTest(
        "repository-level authority runtime installer is not part of the standalone skill package"
    )
SPEC = importlib.util.spec_from_file_location(
    "authority_runtime_transaction",
    SCRIPT,
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load authority runtime transaction")
TRANSACTION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRANSACTION)


@unittest.skipUnless(os.geteuid() == 0, "transaction ownership proof requires root")
class AuthorityRuntimeTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".authority-runtime-transaction-",
            dir="/root",
        )
        self.root = Path(self.temporary.name)
        self.opt = self.root / "opt"
        self.etc = self.root / "etc"
        self.opt.mkdir(mode=0o700)
        self.etc.mkdir(mode=0o700)
        self.runtime = self.opt / "runtime"
        self.manifest = self.etc / "manifest.json"
        self.requirements = self.root / "requirements.txt"
        self.requirements.write_text("locked\n", encoding="utf-8")
        self.requirements.chmod(0o600)
        self.wheelhouse = self.root / "wheels"
        self.wheelhouse.mkdir(mode=0o700)
        self.transaction = self.root / "transaction"
        self.runtime.mkdir(mode=0o700)
        (self.runtime / "generation").write_text("previous", encoding="utf-8")
        self.manifest.write_text("previous-manifest", encoding="utf-8")
        self.manifest.chmod(0o400)
        self.restore_calls: list[dict] = []

        self.constants = mock.patch.multiple(
            TRANSACTION,
            RUNTIME_ROOT=self.runtime,
            MANIFEST=self.manifest,
            REQUIREMENTS=self.requirements,
        )
        self.constants.start()

    def tearDown(self) -> None:
        self.constants.stop()
        self.temporary.cleanup()

    def fake_build(self, **values):
        candidate = values["candidate"]
        candidate_manifest = values["candidate_manifest"]
        candidate.mkdir(mode=0o700)
        (candidate / "generation").write_text("target", encoding="utf-8")
        candidate_manifest.write_text("target-manifest", encoding="utf-8")
        candidate_manifest.chmod(0o400)
        return {
            "manifest": {"sha256": "a" * 64, "size": 15},
            "dependency": {"ok": True},
        }

    def patches(self):
        states = {
            unit: {
                "load_state": "loaded",
                "active_state": "active",
                "sub_state": "running",
                "unit_file_state": "enabled",
            }
            for unit in TRANSACTION.CONSUMER_UNITS
        }
        return (
            mock.patch.object(
                TRANSACTION,
                "_wheelhouse_evidence",
                return_value={"path": str(self.wheelhouse), "files": []},
            ),
            mock.patch.object(
                TRANSACTION,
                "_capture_services",
                return_value=states,
            ),
            mock.patch.object(TRANSACTION, "_stop_consumers"),
            mock.patch.object(
                TRANSACTION,
                "_restore_services",
                side_effect=lambda value: self.restore_calls.append(value),
            ),
            mock.patch.object(TRANSACTION, "_build_candidate", side_effect=self.fake_build),
            mock.patch.object(TRANSACTION, "_live_pair_state", return_value="verified"),
            mock.patch.object(
                TRANSACTION,
                "_verify_live",
                return_value={
                    "manifest": {"sha256": "b" * 64, "size": 16},
                    "dependency": {"ok": True},
                },
            ),
            mock.patch.object(TRANSACTION.VERIFIER, "verify_manifest"),
        )

    def test_apply_and_explicit_rollback_restore_exact_previous_generation(
        self,
    ) -> None:
        patches = self.patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7]:
            applied = TRANSACTION.apply_runtime(
                wheelhouse=self.wheelhouse,
                transaction_path=self.transaction,
            )
            self.assertEqual(applied["status"], "applied")
            self.assertEqual(
                (self.runtime / "generation").read_text(encoding="utf-8"),
                "target",
            )
            self.assertEqual(
                self.manifest.read_text(encoding="utf-8"),
                "target-manifest",
            )
            rolled_back = TRANSACTION.rollback_runtime(self.transaction)
        self.assertEqual(rolled_back["status"], "rolled-back")
        self.assertEqual(
            (self.runtime / "generation").read_text(encoding="utf-8"),
            "previous",
        )
        self.assertEqual(
            self.manifest.read_text(encoding="utf-8"),
            "previous-manifest",
        )
        self.assertEqual(len(self.restore_calls), 2)

    def test_manifest_activation_failure_rolls_back_partial_runtime_swap(
        self,
    ) -> None:
        patches = self.patches()
        real_rename = TRANSACTION._rename

        def fail_manifest(source: Path, destination: Path) -> None:
            if destination == self.manifest and "candidate" in source.name:
                raise OSError("injected manifest activation failure")
            real_rename(source, destination)

        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            patches[7],
            mock.patch.object(
                TRANSACTION,
                "_rename",
                side_effect=fail_manifest,
            ),
            self.assertRaisesRegex(OSError, "injected"),
        ):
            TRANSACTION.apply_runtime(
                wheelhouse=self.wheelhouse,
                transaction_path=self.transaction,
            )
        self.assertEqual(
            (self.runtime / "generation").read_text(encoding="utf-8"),
            "previous",
        )
        self.assertEqual(
            self.manifest.read_text(encoding="utf-8"),
            "previous-manifest",
        )
        journal = TRANSACTION._read_journal(self.transaction)
        self.assertEqual(journal["status"], "failed-rolled-back")
        self.assertEqual(len(self.restore_calls), 1)


if __name__ == "__main__":
    unittest.main()
