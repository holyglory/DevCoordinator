#!/usr/bin/env python3
"""Focused regressions for socket-preserving edge TLS credential refresh."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import refresh_edge_tls_credential as refresh  # noqa: E402
import switch_same_schema_release as release_switch  # noqa: E402


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

    def test_current_hook_uses_stable_refresh_launcher_and_exact_lineage(self) -> None:
        payload = release_switch.certbot_hook_payload().decode("utf-8")
        self.assertIn(str(release_switch.EDGE_CERT_REFRESH_LAUNCHER), payload)
        self.assertIn("RENEWED_LINEAGE", payload)
        self.assertIn("/etc/letsencrypt/live/vr.ae", payload)
        self.assertNotIn("/opt/devcoordinator/releases/", payload)


if __name__ == "__main__":
    unittest.main()
