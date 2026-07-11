#!/usr/bin/env python3
"""Terminate only an exact process instance recorded in legacy cutover evidence."""

from __future__ import annotations

import argparse
import json
import os
import select
import signal
import sys
from pathlib import Path
from typing import Callable

from linux_proc_identity import ProcIdentityError, read_stable_process_identity
from secure_cutover_io import SecureIOError, read_private_regular


class TerminationError(RuntimeError):
    pass


def read_identity(proc_root: Path, pid: int) -> tuple[str, list[str]] | None:
    process = proc_root / str(pid)
    try:
        return read_stable_process_identity(process)
    except (FileNotFoundError, ProcessLookupError):
        return None
    except ProcIdentityError as error:
        raise TerminationError(f"invalid process stat for {pid}: {error}") from error


def open_pidfd(pid: int) -> int:
    opener = getattr(os, "pidfd_open", None)
    sender = getattr(signal, "pidfd_send_signal", None)
    if opener is None or sender is None or not hasattr(select, "poll"):
        raise TerminationError("Linux pidfd support is required for race-free process termination")
    return opener(pid, 0)


def send_pidfd(pidfd: int, sent: int) -> None:
    signal.pidfd_send_signal(pidfd, sent, None, 0)


def wait_pidfd(pidfd: int, timeout_seconds: float) -> bool:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    return bool(poller.poll(round(timeout_seconds * 1000)))


def terminate_captured(
    *,
    evidence_path: Path,
    role: str,
    proc_root: Path = Path("/proc"),
    timeout_seconds: float = 5.0,
    open_handle_fn: Callable[[int], int] = open_pidfd,
    send_handle_fn: Callable[[int, int], None] = send_pidfd,
    wait_handle_fn: Callable[[int, float], bool] = wait_pidfd,
    close_handle_fn: Callable[[int], None] = os.close,
) -> dict[str, object]:
    if timeout_seconds < 0 or timeout_seconds > 60:
        raise TerminationError("timeout must be between 0 and 60 seconds")
    try:
        payload = read_private_regular(evidence_path, label="captured process evidence")
        item = json.loads(payload)[role]
        pid = item["pid"]
        expected_start = item["start_ticks"]
        expected_command = item["command"]
        if not isinstance(pid, int) or pid <= 1:
            raise ValueError("PID must be an integer greater than one")
        if not isinstance(expected_start, str) or not expected_start:
            raise ValueError("start_ticks must be a non-empty string")
        if not isinstance(expected_command, list) or not expected_command:
            raise ValueError("command must be a non-empty argv list")
    except (SecureIOError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise TerminationError(f"invalid captured process evidence: {error}") from error

    current = read_identity(proc_root, pid)
    if current is None:
        return {"ok": True, "pid": pid, "role": role, "result": "already-stopped"}
    if current[0] != expected_start or current[1] != expected_command:
        raise TerminationError(f"captured {role} PID was reused or changed identity; refusing to signal {pid}")

    try:
        pidfd = open_handle_fn(pid)
    except ProcessLookupError:
        return {"ok": True, "pid": pid, "role": role, "result": "already-stopped"}
    try:
        # Re-read after opening the immutable kernel process handle. If the PID
        # was reused during open, refuse; every subsequent signal targets only
        # the process instance bound to this pidfd.
        bound = read_identity(proc_root, pid)
        if bound is None:
            return {"ok": True, "pid": pid, "role": role, "result": "already-stopped"}
        if bound[0] != expected_start or bound[1] != expected_command:
            raise TerminationError(
                f"captured {role} PID changed while binding pidfd; refusing to signal {pid}"
            )
        try:
            send_handle_fn(pidfd, signal.SIGTERM)
        except ProcessLookupError:
            return {"ok": True, "pid": pid, "role": role, "result": "terminated"}
        if wait_handle_fn(pidfd, timeout_seconds):
            return {"ok": True, "pid": pid, "role": role, "result": "terminated"}
        try:
            send_handle_fn(pidfd, signal.SIGKILL)
        except ProcessLookupError:
            return {"ok": True, "pid": pid, "role": role, "result": "terminated"}
        if not wait_handle_fn(pidfd, max(timeout_seconds, 1.0)):
            raise TerminationError(f"captured {role} did not exit after pidfd SIGKILL: {pid}")
        return {"ok": True, "pid": pid, "role": role, "result": "killed-after-timeout"}
    finally:
        close_handle_fn(pidfd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--role", choices=("console", "coordinator"), default="coordinator")
    parser.add_argument("--timeout-seconds", type=float, default=5.0)
    parser.add_argument("--proc-root", default="/proc", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        report = terminate_captured(
            evidence_path=Path(args.evidence),
            role=args.role,
            proc_root=Path(args.proc_root),
            timeout_seconds=args.timeout_seconds,
        )
    except (TerminationError, OSError) as error:
        print(f"guarded legacy termination failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
