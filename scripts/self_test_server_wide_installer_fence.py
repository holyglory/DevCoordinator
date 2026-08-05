#!/usr/bin/env python3
"""Focused normal/optimized checks for the durable installer fence."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import tempfile
import uuid

import server_wide_installer_fence as fence


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def expect_error(call, text: str) -> None:
    try:
        call()
    except fence.InstallerFenceError as error:
        expect(text in str(error), f"unexpected fence error: {error}")
    else:
        raise RuntimeError(f"expected installer fence error containing {text!r}")


def acquire_transaction(
    lock: Path,
    claim: Path,
    transaction: Path,
    terminal: Path,
    operation_id: str,
    action: str,
):
    return fence.acquire_transaction_fence(
        owner_kind="self-test-cutover",
        operation_id=operation_id,
        transaction=transaction,
        terminal=terminal,
        action=action,
        expected_uid=os.geteuid(),
        expected_gid=os.getegid(),
        lock_path=lock,
        claim_path=claim,
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="installer-fence-") as raw:
        root = Path(raw)
        root.chmod(0o700)
        lock = root / "installer.lock"
        claim_root = root / "claims"
        claim_root.mkdir(mode=0o700)
        claim = claim_root / "durable-claim.json"
        transaction = root / "transaction.json"
        terminal = root / "terminal.json"
        operation_id = str(uuid.uuid4())

        ordinary = fence.acquire_installer_mutex(
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
            lock_path=lock,
            claim_path=claim,
        )
        info = lock.lstat()
        expect(stat.S_ISREG(info.st_mode), "installer lock is not regular")
        expect(info.st_nlink == 1, "installer lock is not single-link")
        expect(stat.S_IMODE(info.st_mode) == 0o600, "installer lock mode changed")
        ordinary.close(command_succeeded=True)

        outer = acquire_transaction(
            lock, claim, transaction, terminal, operation_id, "prepare"
        )
        inner = fence.acquire_installer_mutex(
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
            lock_path=lock,
            claim_path=claim,
        )
        expect(inner is outer and outer.depth == 2, "nested helper did not reuse outer FD")
        fence.release_nested_installer_fence(inner)
        expect(outer.depth == 1, "nested helper did not release its level")
        transaction.write_text("sealed transaction placeholder\n", encoding="utf-8")
        outer.close(command_succeeded=True)

        expect_error(
            lambda: fence.acquire_installer_mutex(
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
                lock_path=lock,
                claim_path=claim,
            ),
            "owns the installer fence",
        )
        os.environ["DEVCOORDINATOR_INSTALLER_FENCE_OPERATION_ID"] = operation_id
        expect_error(
            lambda: acquire_transaction(
                lock,
                claim,
                transaction,
                terminal,
                str(uuid.uuid4()),
                "finalize",
            ),
            "another server-wide cutover transaction",
        )
        resumed = acquire_transaction(
            lock, claim, transaction, terminal, operation_id, "finalize"
        )
        terminal.write_text("sealed terminal placeholder\n", encoding="utf-8")
        terminal.chmod(0o600)
        resumed.mark_complete()
        real_fsync = fence.os.fsync
        fsynced_paths: list[str] = []

        def tracked_fsync(descriptor: int) -> None:
            try:
                fsynced_paths.append(os.readlink(f"/proc/self/fd/{descriptor}"))
            except OSError:
                fsynced_paths.append("unresolved")
            real_fsync(descriptor)

        fence.os.fsync = tracked_fsync
        try:
            resumed.close(command_succeeded=True)
        finally:
            fence.os.fsync = real_fsync
        expect(
            str(terminal) in fsynced_paths
            and str(root) in fsynced_paths
            and str(claim_root) in fsynced_paths
            and fsynced_paths.index(str(terminal)) < fsynced_paths.index(str(root))
            < fsynced_paths.index(str(claim_root)),
            "terminal file and parent were not durable before claim removal",
        )
        expect(not claim.exists(), "completed owner claim was not cleared")

        handoff_operation = str(uuid.uuid4())
        handoff_transaction = root / "handoff-predecessor.json"
        handoff_terminal = root / "handoff-predecessor-terminal.json"
        predecessor = acquire_transaction(
            lock,
            claim,
            handoff_transaction,
            handoff_terminal,
            handoff_operation,
            "prepare",
        )
        handoff_transaction.write_text("predecessor journal\n", encoding="utf-8")
        handoff_transaction.chmod(0o600)
        predecessor_claim = dict(predecessor.owner or {})
        successor_transaction = root / "handoff-successor.json"
        successor_terminal = root / "handoff-successor-terminal.json"
        successor_payload = b"sealed predecessor result for successor\n"
        successor_transaction.write_bytes(successor_payload)
        successor_transaction.chmod(0o600)
        successor_digest = hashlib.sha256(successor_payload).hexdigest()
        expect_error(
            lambda: fence.transfer_transaction_fence(
                predecessor,
                successor_owner_kind="self-test-successor",
                successor_operation_id=handoff_operation,
                successor_transaction=successor_transaction,
                successor_terminal=successor_terminal,
                successor_transaction_sha256="0" * 64,
            ),
            "changed before handoff",
        )
        expect(
            fence._read_claim(
                claim,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
            )
            == predecessor_claim,
            "failed handoff changed or removed the predecessor claim",
        )
        unsafe_successor = root / "unsafe-successor.json"
        unsafe_successor.write_text("unsafe\n", encoding="utf-8")
        unsafe_successor.chmod(0o644)
        expect_error(
            lambda: fence.transfer_transaction_fence(
                predecessor,
                successor_owner_kind="self-test-successor",
                successor_operation_id=handoff_operation,
                successor_transaction=unsafe_successor,
                successor_terminal=successor_terminal,
                successor_transaction_sha256=hashlib.sha256(b"unsafe\n").hexdigest(),
            ),
            "evidence is unsafe",
        )
        successor_claim = fence.transfer_transaction_fence(
            predecessor,
            successor_owner_kind="self-test-successor",
            successor_operation_id=handoff_operation,
            successor_transaction=successor_transaction,
            successor_terminal=successor_terminal,
            successor_transaction_sha256=successor_digest,
        )
        expect(
            predecessor.owner == successor_claim
            and predecessor.transaction_path == successor_transaction
            and predecessor.terminal_path == successor_terminal
            and not predecessor.created_claim,
            "held handle did not adopt the exact successor claim",
        )
        expect(
            fence._read_claim(
                claim,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
            )
            == successor_claim,
            "handoff did not leave one exact successor claim",
        )
        predecessor.close(command_succeeded=True)
        expect(claim.exists(), "successful handoff close removed successor ownership")
        expect_error(
            lambda: acquire_transaction(
                lock,
                claim,
                handoff_transaction,
                handoff_terminal,
                handoff_operation,
                "recover",
            ),
            "another server-wide cutover transaction",
        )
        expect_error(
            lambda: fence.acquire_installer_mutex(
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
                lock_path=lock,
                claim_path=claim,
            ),
            "owns the installer fence",
        )
        successor = fence.acquire_transaction_fence(
            owner_kind="self-test-successor",
            operation_id=handoff_operation,
            transaction=successor_transaction,
            terminal=successor_terminal,
            action="recover",
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
            lock_path=lock,
            claim_path=claim,
        )
        successor_terminal.write_text("successor complete\n", encoding="utf-8")
        successor_terminal.chmod(0o600)
        successor.mark_complete()
        successor.close(command_succeeded=True)
        expect(not claim.exists(), "successor terminal did not clear the durable claim")

        provisional_transaction = root / "provisional.json"
        provisional_terminal = root / "provisional-terminal.json"
        provisional = acquire_transaction(
            lock,
            claim,
            provisional_transaction,
            provisional_terminal,
            str(uuid.uuid4()),
            "prepare",
        )
        provisional.close(command_succeeded=False)
        expect(not claim.exists(), "pre-journal failure retained a claim")

        retained_operation = str(uuid.uuid4())
        retained_transaction = root / "retained.json"
        retained_terminal = root / "retained-terminal.json"
        retained = acquire_transaction(
            lock,
            claim,
            retained_transaction,
            retained_terminal,
            retained_operation,
            "prepare",
        )
        retained_transaction.write_text("durable\n", encoding="utf-8")
        retained.close(command_succeeded=False)
        expect(claim.stat().st_size > 0, "post-journal failure lost its durable claim")
        recovered = acquire_transaction(
            lock,
            claim,
            retained_transaction,
            retained_terminal,
            retained_operation,
            "abort",
        )
        retained_terminal.write_text("aborted\n", encoding="utf-8")
        retained_terminal.chmod(0o600)
        recovered.mark_complete()
        recovered.close(command_succeeded=True)

        alias = root / "installer-hardlink"
        os.link(lock, alias)
        expect_error(
            lambda: fence.acquire_installer_mutex(
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
                lock_path=lock,
                claim_path=claim,
            ),
            "single-link regular file",
        )
        alias.unlink()

        crash_claim = root / "crash-claim.json"
        probe = fence.acquire_installer_mutex(
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
            lock_path=lock,
            claim_path=crash_claim,
        )
        crash_document = fence._seal(
            {
                "owner_kind": "self-test-crash-prefix",
                "operation_id": str(uuid.uuid4()),
                "transaction": str(root / "crash-transaction.json"),
                "terminal": str(root / "crash-terminal.json"),
                "lock_identity": dict(probe.identity),
                "created_at_epoch": 1,
            }
        )
        expect_error(
            lambda: fence._publish_claim(
                crash_claim,
                crash_document,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
                failpoint=lambda stage: (_ for _ in ()).throw(
                    fence.InstallerFenceError("simulated temp crash")
                )
                if stage == "after-temp-fsync"
                else None,
            ),
            "simulated temp crash",
        )
        expect(not crash_claim.exists(), "pre-publication crash exposed a partial claim")
        expect_error(
            lambda: fence._publish_claim(
                crash_claim,
                crash_document,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
                failpoint=lambda stage: (_ for _ in ()).throw(
                    fence.InstallerFenceError("simulated linked crash")
                )
                if stage == "after-link"
                else None,
            ),
            "simulated linked crash",
        )
        expect(
            fence._read_claim(
                crash_claim,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
            )
            == crash_document,
            "post-link crash did not retain one complete claim",
        )
        fence._remove_claim(
            crash_claim,
            expected=crash_document,
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
        )
        probe.close(command_succeeded=True)

        reboot_operation = str(uuid.uuid4())
        reboot_transaction = root / "reboot-transaction.json"
        reboot_terminal = root / "reboot-terminal.json"
        before_reboot = acquire_transaction(
            lock,
            claim,
            reboot_transaction,
            reboot_terminal,
            reboot_operation,
            "prepare",
        )
        reboot_transaction.write_text("durable reboot journal\n", encoding="utf-8")
        reboot_transaction.chmod(0o600)
        old_inode = before_reboot.identity["inode"]
        before_reboot.close(command_succeeded=True)
        retired_lock = root / "retired-installer.lock"
        os.link(lock, retired_lock)
        lock.unlink()
        expect_error(
            lambda: fence.acquire_installer_mutex(
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
                lock_path=lock,
                claim_path=claim,
            ),
            "owns the installer fence",
        )
        after_reboot = acquire_transaction(
            lock,
            claim,
            reboot_transaction,
            reboot_terminal,
            reboot_operation,
            "recover",
        )
        expect(
            after_reboot.identity["inode"] != old_inode
            and after_reboot.owner["lock_identity"] == after_reboot.identity,
            "reboot recovery did not atomically rebind the durable claim",
        )
        reboot_terminal.write_text("recovered\n", encoding="utf-8")
        reboot_terminal.chmod(0o600)
        after_reboot.mark_complete()
        after_reboot.close(command_succeeded=True)
        retired_lock.unlink()

    print("server-wide installer fence self-test: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
