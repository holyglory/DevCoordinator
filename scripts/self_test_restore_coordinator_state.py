#!/usr/bin/env python3
"""Behavioral tests for lock-aware coordinator-state rollback."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


SCRIPT = Path(__file__).with_name("restore_coordinator_state.py")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def private_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def private_file(path: Path, payload: bytes) -> Path:
    path.write_bytes(payload)
    path.chmod(0o600)
    return path


def command(snapshot: Path, checksum: Path, home: Path) -> list[str]:
    return [
        sys.executable,
        str(SCRIPT),
        "--snapshot",
        str(snapshot),
        "--checksum",
        str(checksum),
        "--coordinator-home",
        str(home),
    ]


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="restore-coordinator-state-") as raw:
        root = private_directory(Path(raw))
        home = private_directory(root / "coordinator")
        old_payload = b'{"revision":1,"leases":{},"servers":{},"history":[],"port_assignments":{"old":{}}}\n'
        restored_payload = b'{"revision":2,"leases":{},"servers":{},"history":[],"port_assignments":{"restored":{}}}\n'
        state = private_file(home / "state.json", old_payload)
        snapshot = private_file(root / "snapshot.json", restored_payload)
        digest = hashlib.sha256(restored_payload).hexdigest()
        checksum = private_file(root / "snapshot.sha256", f"{digest}  {snapshot}\n".encode())

        lock_fd = os.open(home / "state.lock", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        process = subprocess.Popen(
            command(snapshot, checksum, home),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.1)
        if process.poll() is not None:
            early_stdout, early_stderr = process.communicate(timeout=5)
            raise AssertionError(
                "restore did not wait for the coordinator state lock: "
                f"stdout={early_stdout!r} stderr={early_stderr!r}"
            )
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
        stdout, stderr = process.communicate(timeout=10)
        require(process.returncode == 0, f"verified restore failed: {stderr}")
        report = json.loads(stdout)
        require(report["ok"] is True, "restore report did not confirm success")
        require(state.read_bytes() == restored_payload, "restore did not install the exact snapshot bytes")
        require(state.stat().st_mode & 0o077 == 0, "restored state is not private")

        private_file(state, old_payload)
        bad_checksum = private_file(root / "bad.sha256", f"{'0' * 64}  {snapshot}\n".encode())
        failed = subprocess.run(
            command(snapshot, bad_checksum, home),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        require(failed.returncode != 0, "wrong-checksum restore unexpectedly succeeded")
        require("checksum mismatch" in failed.stderr, f"wrong checksum failure was unclear: {failed.stderr}")
        require(state.read_bytes() == old_payload, "wrong-checksum restore changed current state")

        symlink = root / "snapshot-link.json"
        symlink.symlink_to(snapshot)
        linked = subprocess.run(
            command(symlink, checksum, home),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        require(linked.returncode != 0, "symlink snapshot unexpectedly succeeded")
        require(state.read_bytes() == old_payload, "symlink snapshot changed current state")

        wrong_shape_payload = b'{"revision":3,"leases":[],"servers":{},"history":[]}\n'
        wrong_shape = private_file(root / "wrong-shape.json", wrong_shape_payload)
        wrong_shape_digest = hashlib.sha256(wrong_shape_payload).hexdigest()
        wrong_shape_checksum = private_file(
            root / "wrong-shape.sha256",
            f"{wrong_shape_digest}  {wrong_shape}\n".encode(),
        )
        shaped = subprocess.run(
            command(wrong_shape, wrong_shape_checksum, home),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        require(shaped.returncode != 0, "checksummed wrong-shape snapshot unexpectedly succeeded")
        require("leases" in shaped.stderr, f"wrong-shape failure was unclear: {shaped.stderr}")
        require(state.read_bytes() == old_payload, "wrong-shape snapshot changed current state")

    print("coordinator state restore self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
