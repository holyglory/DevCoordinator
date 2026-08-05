#!/usr/bin/env python3
"""Focused regressions for socket-preserving edge TLS credential refresh."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import refresh_edge_tls_credential as refresh  # noqa: E402
import activate_availability_release as activation  # noqa: E402


class FakeRunner:
    def __init__(self, *, key_matches: bool = True, restart_ok: bool = True) -> None:
        self.key_matches = key_matches
        self.restart_ok = restart_ok
        self.commands: list[tuple[str, ...]] = []

    def status(self, argv):
        command = tuple(argv)
        self.commands.append(command)
        if "restart" in command and not self.restart_ok:
            return 1
        return 0

    def run(self, argv, *, binary=False):
        command = tuple(argv)
        self.commands.append(command)
        if "-outform" in command:
            return b"leaf-der"
        if Path(argv[1]).name == "pkey" and not self.key_matches:
            return b"another-public-key"
        return b"one-public-key"


class HookRunner:
    def __init__(self, *, valid: bool = True) -> None:
        self.valid = valid

    def run_json(self, argv):
        return {
            "ok": self.valid,
            "checked": self.valid,
            "leaf_sha256": "a" * 64,
            "public_key_sha256": "b" * 64,
        }

    def status(self, _argv):
        return 0


class RefreshTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="edge-tls-refresh-")
        self.root = Path(self.temporary.name)
        self.archive = self.root / "archive"
        self.lineage = self.root / "live"
        self.archive.mkdir()
        self.lineage.mkdir()
        cert = self.archive / "fullchain1.pem"
        key = self.archive / "privkey1.pem"
        cert.write_bytes(b"certificate")
        key.write_bytes(b"private-key")
        cert.chmod(0o644)
        key.chmod(0o600)
        (self.lineage / "fullchain.pem").symlink_to(cert)
        (self.lineage / "privkey.pem").symlink_to(key)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_refresh_preserves_socket_and_proves_served_leaf(self) -> None:
        digest = hashlib.sha256(b"leaf-der").hexdigest()
        runner = FakeRunner()
        result = refresh.refresh(
            lineage=self.lineage,
            domain="vr.ae",
            runner=runner,
            inode_reader=lambda _port: 8123,
            peer_reader=lambda _host, _port: digest,
            expected_uid=os.geteuid(),
        )
        self.assertTrue(result["restarted"])
        self.assertEqual(result["listener_inode_before"], result["listener_inode_after"])
        self.assertTrue(any("restart" in command for command in runner.commands))

    def test_invalid_pair_blocks_restart(self) -> None:
        runner = FakeRunner(key_matches=False)
        with self.assertRaisesRegex(refresh.RefreshError, "do not match"):
            refresh.refresh(
                lineage=self.lineage,
                domain="vr.ae",
                runner=runner,
                inode_reader=lambda _port: 1,
                peer_reader=lambda _host, _port: "0" * 64,
                expected_uid=os.geteuid(),
            )
        self.assertFalse(any("restart" in command for command in runner.commands))

    def test_listener_or_certificate_mismatch_fails_closed(self) -> None:
        calls = iter((11, 12))
        with self.assertRaisesRegex(refresh.RefreshError, "listener identity changed"):
            refresh.refresh(
                lineage=self.lineage,
                domain="vr.ae",
                runner=FakeRunner(),
                inode_reader=lambda _port: next(calls),
                peer_reader=lambda _host, _port: "0" * 64,
                expected_uid=os.geteuid(),
            )

    def test_certbot_hook_replaces_and_restores_legacy_hook(self) -> None:
        release_root = self.root / "releases"
        release = release_root / ("d" * 64)
        helper = release / "bin/devcoordinator-edge-cert-refresh"
        helper.parent.mkdir(parents=True)
        helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        helper.chmod(0o555)
        hooks = self.root / "hooks"
        hooks.mkdir(mode=0o755)
        legacy = hooks / "devops-console"
        legacy.write_text("#!/bin/sh\nsystemctl reload devops-console\n", encoding="utf-8")
        legacy.chmod(0o700)
        rollback = self.root / "rollback"
        rollback.mkdir(mode=0o700)
        with mock.patch.object(activation, "IMMUTABLE_RELEASE_ROOT", release_root):
            evidence = activation.install_edge_certbot_hook(
                release=release,
                rollback_directory=rollback,
                expected_uid=os.geteuid(),
                hook_root=hooks,
                runner=HookRunner(),
            )
            installed = hooks / "devcoordinator-edge"
            self.assertTrue(installed.is_file())
            self.assertFalse(legacy.exists())
            self.assertIn(str(helper), installed.read_text(encoding="utf-8"))
            self.assertEqual(installed.stat().st_mode & 0o777, 0o700)
            activation._restore_prepared_graph(
                {"prior_units": {}, "prior_files": evidence["prior_files"]},
                runner=HookRunner(),
                expected_uid=os.geteuid(),
            )
        self.assertFalse(installed.exists())
        self.assertIn("reload devops-console", legacy.read_text(encoding="utf-8"))
        with self.assertRaisesRegex(refresh.RefreshError, "did not serve"):
            refresh.refresh(
                lineage=self.lineage,
                domain="vr.ae",
                runner=FakeRunner(),
                inode_reader=lambda _port: 11,
                peer_reader=lambda _host, _port: "0" * 64,
                expected_uid=os.geteuid(),
            )


if __name__ == "__main__":
    unittest.main()
