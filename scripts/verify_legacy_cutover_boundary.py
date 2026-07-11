#!/usr/bin/env python3
"""Sample and preserve the exact legacy Console cgroup cutover boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from linux_proc_identity import ProcIdentityError, read_stable_process_identity
from secure_cutover_io import SecureIOError, open_private_parent, read_at, read_private_regular


class BoundaryError(RuntimeError):
    """The live cgroup no longer matches the captured legacy boundary."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_process(proc_root: Path, pid: int) -> dict[str, object]:
    record: dict[str, object] = {"pid": pid}
    try:
        start_ticks, command = read_stable_process_identity(proc_root / str(pid))
        record.update(
            {
                "start_ticks": start_ticks,
                "command": command,
                "status": "captured",
            }
        )
    except (FileNotFoundError, PermissionError, ProcessLookupError, ProcIdentityError, OSError) as error:
        record.update({"status": "unavailable", "error": f"{type(error).__name__}: {error}"})
    return record


class LedgerWriter:
    def __init__(self, path: Path) -> None:
        self.parent, self.path, self.name = open_private_parent(path)
        self.checksum_name = f"{self.name}.sha256"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            ledger_reservation = os.open(self.name, flags, 0o600, dir_fd=self.parent)
        except FileExistsError as error:
            os.close(self.parent)
            raise BoundaryError(f"cutover evidence path already exists: {self.path}") from error
        os.close(ledger_reservation)
        try:
            checksum_reservation = os.open(self.checksum_name, flags, 0o600, dir_fd=self.parent)
        except BaseException:
            os.unlink(self.name, dir_fd=self.parent)
            os.fsync(self.parent)
            os.close(self.parent)
            raise
        os.close(checksum_reservation)
        os.fsync(self.parent)

    def close(self) -> None:
        if self.parent >= 0:
            os.close(self.parent)
            self.parent = -1

    def _replace(self, name: str, payload: bytes) -> None:
        temporary = f".{name}.{os.getpid()}.{secrets.token_hex(8)}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600, dir_fd=self.parent)
        try:
            handle = os.fdopen(descriptor, "wb")
            descriptor = -1
            with handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(
                temporary,
                name,
                src_dir_fd=self.parent,
                dst_dir_fd=self.parent,
            )
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=self.parent)
            except FileNotFoundError:
                pass

    def write(self, ledger: dict[str, object]) -> None:
        payload = (json.dumps(ledger, indent=2, sort_keys=True) + "\n").encode("utf-8")
        digest = hashlib.sha256(payload).hexdigest()
        checksum = f"{digest}  {self.name}\n".encode("ascii")
        self._replace(self.name, payload)
        self._replace(self.checksum_name, checksum)
        os.fsync(self.parent)
        actual_payload = read_at(self.parent, self.name, label="cutover sample ledger")
        actual_checksum = read_at(self.parent, self.checksum_name, label="cutover sample checksum")
        if actual_payload != payload or actual_checksum != checksum:
            raise BoundaryError("cutover sample ledger/checksum verification failed after durable write")


def verify_ledger_pair(path: Path) -> None:
    payload = read_private_regular(path, label="cutover sample ledger")
    checksum = read_private_regular(Path(f"{path}.sha256"), label="cutover sample checksum")
    expected = f"{hashlib.sha256(payload).hexdigest()}  {path.name}\n".encode("ascii")
    if checksum != expected:
        raise BoundaryError(f"cutover sample ledger checksum mismatch: {path}")


def _load_evidence(path: Path) -> tuple[dict[str, object], bytes]:
    try:
        payload = read_private_regular(path, label="captured process evidence")
    except SecureIOError as error:
        raise BoundaryError(str(error)) from error
    try:
        evidence = json.loads(payload)
        console = evidence["console"]
        coordinator = evidence["coordinator"]
        cgroup = evidence["cgroup"]
        for item in (console, coordinator):
            if not isinstance(item["pid"], int) or item["pid"] <= 1:
                raise ValueError("captured PID must be an integer greater than one")
            if not isinstance(item["start_ticks"], str) or not item["start_ticks"]:
                raise ValueError("captured start_ticks must be a non-empty string")
            if not isinstance(item["command"], list) or not item["command"]:
                raise ValueError("captured command must be a non-empty argv list")
        if console["pid"] == coordinator["pid"]:
            raise ValueError("captured Console and coordinator PIDs must be distinct")
        if not isinstance(cgroup, str) or not cgroup.startswith("/") or ".." in Path(cgroup).parts:
            raise ValueError("captured cgroup must be an absolute cgroup path")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise BoundaryError(f"invalid captured process evidence: {error}") from error
    return evidence, payload


def sample_boundary(
    *,
    evidence_path: Path,
    ledger_path: Path,
    cgroup_root: Path = Path("/sys/fs/cgroup"),
    proc_root: Path = Path("/proc"),
    sample_count: int = 5,
    interval_seconds: float = 1.0,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    if sample_count < 1 or sample_count > 60:
        raise BoundaryError("sample count must be between 1 and 60")
    if interval_seconds < 0 or interval_seconds > 10:
        raise BoundaryError("sample interval must be between 0 and 10 seconds")
    evidence, evidence_payload = _load_evidence(evidence_path)
    cgroup = str(evidence["cgroup"])
    members_path = cgroup_root / cgroup.lstrip("/") / "cgroup.procs"
    expected_items = [evidence["console"], evidence["coordinator"]]
    expected_pids = {int(item["pid"]) for item in expected_items}
    ledger: dict[str, object] = {
        "schema_version": 1,
        "ok": False,
        "started_at": utc_now(),
        "completed_at": None,
        "captured_evidence": str(evidence_path),
        "captured_evidence_sha256": hashlib.sha256(evidence_payload).hexdigest(),
        "cgroup": cgroup,
        "expected_pids": sorted(expected_pids),
        "requested_samples": sample_count,
        "interval_seconds": interval_seconds,
        "samples": [],
    }

    try:
        writer = LedgerWriter(ledger_path)
    except (SecureIOError, OSError) as error:
        raise BoundaryError(str(error)) from error
    try:
        for index in range(sample_count):
            problems: list[str] = []
            try:
                current = {
                    int(value)
                    for value in members_path.read_text(encoding="utf-8").splitlines()
                    if value.strip()
                }
            except (FileNotFoundError, PermissionError, OSError, ValueError) as error:
                current = set()
                problems.append(f"cgroup process list unavailable: {type(error).__name__}: {error}")
            records = [_read_process(proc_root, pid) for pid in sorted(current)]
            by_pid = {int(item["pid"]): item for item in records}
            if current != expected_pids:
                problems.append(
                    f"cgroup members differ: expected {sorted(expected_pids)}, found {sorted(current)}"
                )
            for expected in expected_items:
                pid = int(expected["pid"])
                actual = by_pid.get(pid)
                if actual is None or actual.get("status") != "captured":
                    problems.append(f"captured legacy PID is unavailable: {pid}")
                    continue
                if actual.get("start_ticks") != expected["start_ticks"]:
                    problems.append(f"captured legacy PID start time changed: {pid}")
                if actual.get("command") != expected["command"]:
                    problems.append(f"captured legacy PID command changed: {pid}")
            sample = {
                "number": index + 1,
                "timestamp": utc_now(),
                "members": sorted(current),
                "processes": records,
                "problems": problems,
            }
            ledger["samples"].append(sample)  # type: ignore[union-attr]
            if problems:
                ledger["completed_at"] = utc_now()
                ledger["failure"] = problems
                writer.write(ledger)
                raise BoundaryError("; ".join(problems))
            writer.write(ledger)
            if index + 1 < sample_count:
                sleep_fn(interval_seconds)

        ledger["ok"] = True
        ledger["completed_at"] = utc_now()
        writer.write(ledger)
    finally:
        writer.close()
    verify_ledger_pair(ledger_path)
    return ledger


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, help="captured legacy-processes.json")
    parser.add_argument("--ledger", required=True, help="new private JSON evidence ledger")
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--interval-seconds", type=float, default=1.0)
    parser.add_argument("--cgroup-root", default="/sys/fs/cgroup", help=argparse.SUPPRESS)
    parser.add_argument("--proc-root", default="/proc", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        report = sample_boundary(
            evidence_path=Path(args.evidence),
            ledger_path=Path(args.ledger),
            cgroup_root=Path(args.cgroup_root),
            proc_root=Path(args.proc_root),
            sample_count=args.samples,
            interval_seconds=args.interval_seconds,
        )
    except (BoundaryError, OSError) as error:
        print(f"legacy cutover boundary failed: {error}", file=sys.stderr)
        return 1
    print(
        f"legacy cutover boundary ok ({len(report['samples'])} samples; "
        f"ledger {args.ledger})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
