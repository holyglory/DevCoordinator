#!/usr/bin/env python3
"""Offline immutable browser runtime installer tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import install_browser_lcp_runtime as installer


class BrowserRuntimeInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.uid = os.getuid()
        self.gid = os.getgid()
        self.package = self.root / "package"
        (self.package / "node_modules/playwright").mkdir(parents=True)
        (self.package / "node_modules/playwright-core").mkdir(parents=True)
        (self.package / "package.json").write_text(
            json.dumps({"dependencies": {"playwright": "1.50.0"}}),
            encoding="utf-8",
        )
        (self.package / "package-lock.json").write_text(
            json.dumps(
                {
                    "packages": {
                        "": {"dependencies": {"playwright": "1.50.0"}},
                        "node_modules/playwright": {"version": "1.50.0"},
                        "node_modules/playwright-core": {"version": "1.50.0"},
                    }
                }
            ),
            encoding="utf-8",
        )
        (self.package / "node_modules/playwright/index.mjs").write_text(
            "export const chromium = {};\n", encoding="utf-8"
        )
        (self.package / "node_modules/playwright-core/index.js").write_text(
            "module.exports = {};\n", encoding="utf-8"
        )
        self.node = self.root / "node"
        self.node.write_text("#!/bin/sh\nprintf 'v22.1.0\\n'\n", encoding="utf-8")
        self.node.chmod(0o755)
        self.browser_root = self.root / "browser-bundle"
        (self.browser_root / "locales").mkdir(parents=True)
        self.browser = self.browser_root / "chrome"
        self.browser.write_text(
            "#!/bin/sh\nprintf 'Chromium 131.0.0.0\\n'\n", encoding="utf-8"
        )
        self.browser.chmod(0o755)
        (self.browser_root / "icudtl.dat").write_bytes(b"browser-data\n")
        (self.browser_root / "locales/en-US.pak").write_bytes(b"locale-data\n")
        self.runtime_root = self.root / "runtimes"
        self.evidence = self.root / "evidence"
        self.evidence.mkdir(mode=0o700)
        self.original_runtime_root = installer.DEFAULT_RUNTIME_ROOT
        self.original_uid = installer.AUTHORITY_UID
        self.original_gid = installer.AUTHORITY_GID
        installer.DEFAULT_RUNTIME_ROOT = self.runtime_root
        installer.AUTHORITY_UID = self.uid
        installer.AUTHORITY_GID = self.gid

    def tearDown(self) -> None:
        installer.DEFAULT_RUNTIME_ROOT = self.original_runtime_root
        installer.AUTHORITY_UID = self.original_uid
        installer.AUTHORITY_GID = self.original_gid
        self.temporary.cleanup()

    def _plan(self):
        return installer.build_plan(
            package_root=self.package,
            node=self.node,
            browser_root=self.browser_root,
            browser_executable_relative=Path("chrome"),
        )

    def test_plan_stage_verify_is_content_addressed_and_idempotent(self) -> None:
        plan = self._plan()
        runtime_lock = self.evidence / "runtime-lock.json"
        attestation = self.evidence / "stage.json"
        staged = installer.stage(
            plan=plan,
            runtime_lock=runtime_lock,
            attestation=attestation,
        )
        replay = installer.stage(
            plan=plan,
            runtime_lock=runtime_lock,
            attestation=attestation,
        )
        verified = installer.verify(
            plan=plan,
            runtime_lock=runtime_lock,
            attestation=attestation,
        )
        self.assertEqual(staged, replay)
        self.assertEqual(verified["runtime_digest"], plan["runtime_digest"])
        runtime = Path(str(plan["runtime"]))
        self.assertEqual(runtime.name, plan["runtime_digest"])
        self.assertEqual(runtime.stat().st_mode & 0o777, 0o555)
        self.assertEqual((runtime / "bin/node").stat().st_mode & 0o777, 0o555)
        self.assertEqual(
            (runtime / "browser/locales/en-US.pak").read_bytes(), b"locale-data\n"
        )
        self.assertEqual(
            (runtime / "playwright/package.json").stat().st_mode & 0o777,
            0o444,
        )

    def test_stage_rejects_source_drift_before_copy(self) -> None:
        plan = self._plan()
        (self.package / "node_modules/playwright/index.mjs").write_text(
            "export const chromium = {changed: true};\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            installer.BrowserRuntimeInstallError, "changed after planning"
        ):
            installer.stage(
                plan=plan,
                runtime_lock=self.evidence / "runtime-lock.json",
                attestation=self.evidence / "stage.json",
            )

    def test_verify_rejects_runtime_tampering(self) -> None:
        plan = self._plan()
        runtime_lock = self.evidence / "runtime-lock.json"
        attestation = self.evidence / "stage.json"
        installer.stage(
            plan=plan,
            runtime_lock=runtime_lock,
            attestation=attestation,
        )
        target = Path(str(plan["runtime"])) / "playwright/package.json"
        target.chmod(0o644)
        target.write_text("{}\n", encoding="utf-8")
        target.chmod(0o444)
        with self.assertRaisesRegex(
            installer.BrowserRuntimeInstallError, "file changed"
        ):
            installer.verify(
                plan=plan,
                runtime_lock=runtime_lock,
                attestation=attestation,
            )

    def test_cli_refuses_non_root_before_mutation(self) -> None:
        with mock.patch.object(installer.os, "geteuid", return_value=1234):
            result = installer.main(
                [
                    "plan",
                    "--package-root",
                    str(self.package),
                    "--node",
                    str(self.node),
                    "--browser-root",
                    str(self.browser_root),
                    "--browser-executable-relative",
                    "chrome",
                    "--output",
                    str(self.evidence / "plan.json"),
                ]
            )
        self.assertEqual(result, 1)
        self.assertFalse((self.evidence / "plan.json").exists())

    def test_plan_binds_complete_browser_bundle_and_total_bytes(self) -> None:
        plan = self._plan()
        browser_entries = [
            item for item in plan["files"] if str(item["path"]).startswith("browser/")
        ]
        self.assertEqual(
            {item["path"] for item in browser_entries},
            {"browser/chrome", "browser/icudtl.dat", "browser/locales/en-US.pak"},
        )
        self.assertEqual(
            plan["package_contract"]["browser_file_count"], len(browser_entries)
        )
        self.assertEqual(
            plan["total_bytes"], sum(int(item["size"]) for item in plan["files"])
        )
        malformed = {
            key: value
            for key, value in plan.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        malformed["total_bytes"] += 1
        malformed = installer.browser_lcp._seal_digest(
            installer.PLAN_KIND, malformed
        )
        with self.assertRaisesRegex(
            installer.BrowserRuntimeInstallError, "total planned bytes"
        ):
            installer.verify_plan(malformed)

    def test_stage_rejects_browser_bundle_inventory_drift(self) -> None:
        plan = self._plan()
        (self.browser_root / "new-library.so").write_bytes(b"late addition")
        with self.assertRaisesRegex(
            installer.BrowserRuntimeInstallError, "source directory changed"
        ):
            installer.stage(
                plan=plan,
                runtime_lock=self.evidence / "runtime-lock.json",
                attestation=self.evidence / "stage.json",
            )

    def test_fd_copy_rejects_path_swap_after_open(self) -> None:
        plan = self._plan()
        item = next(
            entry for entry in plan["files"] if entry["path"] == "browser/icudtl.dat"
        )
        temporary = self.root / "private-partial"
        temporary.mkdir(mode=0o700)
        replacement = self.root / "replacement"
        replacement.write_bytes(b"replacement-data\n")
        real_open = installer.os.open
        swapped = False

        def racing_open(path, flags, *args, **kwargs):
            nonlocal swapped
            descriptor = real_open(path, flags, *args, **kwargs)
            if not swapped and Path(path) == Path(str(item["source"])):
                os.replace(replacement, path)
                swapped = True
            return descriptor

        with mock.patch.object(installer.os, "open", side_effect=racing_open):
            with self.assertRaisesRegex(
                installer.BrowserRuntimeInstallError, "source changed after planning"
            ):
                installer._copy_planned_file(item, temporary=temporary)
        self.assertFalse((temporary / "browser/icudtl.dat").exists())

    def test_stage_repairs_only_safe_stale_private_partial(self) -> None:
        plan = self._plan()
        self.runtime_root.mkdir(mode=0o755)
        self.runtime_root.chmod(0o755)
        stale = self.runtime_root / f".{plan['runtime_digest']}.{'a' * 32}.partial"
        stale.mkdir(mode=0o700)
        (stale / "orphan").write_bytes(b"orphan")
        installer.stage(
            plan=plan,
            runtime_lock=self.evidence / "runtime-lock.json",
            attestation=self.evidence / "stage.json",
        )
        self.assertFalse(stale.exists())

    def test_stage_rejects_corrupt_published_digest_without_removing_it(self) -> None:
        plan = self._plan()
        self.runtime_root.mkdir(mode=0o755)
        self.runtime_root.chmod(0o755)
        published = Path(str(plan["runtime"]))
        published.mkdir(mode=0o555)
        with self.assertRaisesRegex(
            installer.BrowserRuntimeInstallError,
            "published browser runtime digest is corrupt",
        ):
            installer.stage(
                plan=plan,
                runtime_lock=self.evidence / "runtime-lock.json",
                attestation=self.evidence / "stage.json",
            )
        self.assertTrue(published.is_dir())

    def test_stage_rejects_unsafe_stale_partial(self) -> None:
        plan = self._plan()
        self.runtime_root.mkdir(mode=0o755)
        self.runtime_root.chmod(0o755)
        outside = self.root / "outside"
        outside.mkdir()
        stale = self.runtime_root / f".{plan['runtime_digest']}.{'b' * 32}.partial"
        stale.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(
            installer.BrowserRuntimeInstallError, "partial identity is unsafe"
        ):
            installer.stage(
                plan=plan,
                runtime_lock=self.evidence / "runtime-lock.json",
                attestation=self.evidence / "stage.json",
            )
        self.assertTrue(stale.is_symlink())

    def test_plan_parser_has_no_gid_or_destination_override(self) -> None:
        base = [
            "plan",
            "--package-root",
            str(self.package),
            "--node",
            str(self.node),
            "--browser-root",
            str(self.browser_root),
            "--browser-executable-relative",
            "chrome",
            "--output",
            str(self.evidence / "plan.json"),
        ]
        with self.assertRaises(SystemExit):
            installer._parser().parse_args([*base, "--authority-gid", "100"])
        with self.assertRaises(SystemExit):
            installer._parser().parse_args(
                [*base, "--runtime-root", str(self.root / "other")]
            )


if __name__ == "__main__":
    unittest.main()
