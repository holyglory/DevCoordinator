#!/usr/bin/env python3
"""Observe and preserve the exact legacy Console cgroup cutover boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import secrets
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from linux_proc_identity import ProcIdentityError, read_stable_process_identity
from secure_cutover_io import SecureIOError, open_private_parent, read_at, read_private_regular


class BoundaryError(RuntimeError):
    """The live cgroup no longer matches the captured legacy boundary."""


class BoundaryInterrupted(BoundaryError):
    """A handled process signal interrupted boundary observation."""


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


def _observe_boundary(
    *,
    members_path: Path,
    proc_root: Path,
    expected_items: list[dict[str, object]],
    expected_pids: set[int],
    after_first_members_read: Callable[[], None] | None = None,
    after_first_identity_read: Callable[[], None] | None = None,
) -> tuple[dict[str, object], list[str]]:
    problems: list[str] = []
    fatal_problems: list[str] = []
    try:
        current = {
            int(value)
            for value in members_path.read_text(encoding="utf-8").splitlines()
            if value.strip()
        }
    except (FileNotFoundError, PermissionError, OSError, ValueError) as error:
        current = set()
        message = f"cgroup process list unavailable: {type(error).__name__}: {error}"
        problems.append(message)
        fatal_problems.append(message)
    first_current = set(current)
    if after_first_members_read is not None:
        after_first_members_read()
    first_records = [_read_process(proc_root, pid) for pid in sorted(first_current)]
    if after_first_identity_read is not None:
        after_first_identity_read()
    try:
        confirmed_current = {
            int(value)
            for value in members_path.read_text(encoding="utf-8").splitlines()
            if value.strip()
        }
    except (FileNotFoundError, PermissionError, OSError, ValueError) as error:
        confirmed_current = set(first_current)
        message = f"second cgroup process read unavailable: {type(error).__name__}: {error}"
        problems.append(message)
        fatal_problems.append(message)
    if confirmed_current != first_current:
        problems.append(
            "cgroup members changed during observation: "
            f"first {sorted(first_current)}, second {sorted(confirmed_current)}"
        )
    confirmed_records = [_read_process(proc_root, pid) for pid in sorted(confirmed_current)]
    first_by_pid = {int(item["pid"]): item for item in first_records}
    confirmed_by_pid = {int(item["pid"]): item for item in confirmed_records}
    identity_changed = False
    for pid in sorted(first_current & confirmed_current):
        first_identity = first_by_pid[pid]
        confirmed_identity = confirmed_by_pid[pid]
        if first_identity != confirmed_identity:
            identity_changed = True
            message = f"process identity changed during observation: {pid}"
            problems.append(message)
            if pid in expected_pids:
                fatal_problems.append(message)
    current = confirmed_current
    records = list(confirmed_records)
    records.extend(
        dict(item, membership_read="first_only")
        for pid, item in sorted(first_by_pid.items())
        if pid not in confirmed_current
    )
    by_pid = confirmed_by_pid
    if current != expected_pids:
        problems.append(
            f"cgroup members differ: expected {sorted(expected_pids)}, found {sorted(current)}"
        )
    missing_expected = expected_pids - current
    if missing_expected:
        fatal_problems.append(
            f"captured legacy PIDs left the cgroup: {sorted(missing_expected)}"
        )
    for expected in expected_items:
        pid = int(expected["pid"])
        actual = by_pid.get(pid)
        if actual is None or actual.get("status") != "captured":
            message = f"captured legacy PID is unavailable: {pid}"
            problems.append(message)
            fatal_problems.append(message)
            continue
        if actual.get("start_ticks") != expected["start_ticks"]:
            message = f"captured legacy PID start time changed: {pid}"
            problems.append(message)
            fatal_problems.append(message)
        if actual.get("command") != expected["command"]:
            message = f"captured legacy PID command changed: {pid}"
            problems.append(message)
            fatal_problems.append(message)
    observation = {
        "timestamp": utc_now(),
        "members": sorted(current),
        "processes": records,
        "problems": problems,
    }
    if first_current != current or identity_changed:
        observation["members_first_read"] = sorted(first_current)
        observation["processes_first_read"] = first_records
    return observation, fatal_problems


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
    if not math.isfinite(interval_seconds) or interval_seconds < 0 or interval_seconds > 10:
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
            sample, _fatal_problems = _observe_boundary(
                members_path=members_path,
                proc_root=proc_root,
                expected_items=expected_items,
                expected_pids=expected_pids,
            )
            sample["number"] = index + 1
            ledger["samples"].append(sample)  # type: ignore[union-attr]
            if sample["problems"]:
                ledger["completed_at"] = utc_now()
                ledger["failure"] = sample["problems"]
                writer.write(ledger)
                raise BoundaryError("; ".join(str(item) for item in sample["problems"]))
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


def wait_for_clean_boundary(
    *,
    evidence_path: Path,
    ledger_path: Path,
    cgroup_root: Path = Path("/sys/fs/cgroup"),
    proc_root: Path = Path("/proc"),
    clean_window_seconds: float = 5.0,
    wait_timeout_seconds: float = 30.0,
    poll_interval_seconds: float = 0.02,
    max_observation_gap_seconds: float | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    monotonic_fn: Callable[[], float] = time.monotonic,
    after_first_members_read: Callable[[], None] | None = None,
    after_first_identity_read: Callable[[], None] | None = None,
) -> dict[str, object]:
    """Wait for a bounded-polling exact boundary and preserve every transition.

    This is a user-space observed-clean window, not a kernel event subscription.
    Extra children reset the candidate window. Missing/reused captured processes,
    unreadable identity, observation stalls, interruption, and timeout fail closed.
    """

    if (
        not math.isfinite(clean_window_seconds)
        or clean_window_seconds <= 0
        or clean_window_seconds > 60
    ):
        raise BoundaryError("continuous clean window must be greater than 0 and at most 60 seconds")
    if (
        not math.isfinite(wait_timeout_seconds)
        or wait_timeout_seconds <= clean_window_seconds
        or wait_timeout_seconds > 600
    ):
        raise BoundaryError("wait timeout must be greater than the clean window and at most 600 seconds")
    if (
        not math.isfinite(poll_interval_seconds)
        or poll_interval_seconds <= 0
        or poll_interval_seconds > 1
    ):
        raise BoundaryError("poll interval must be greater than 0 and at most 1 second")
    if max_observation_gap_seconds is None:
        max_observation_gap_seconds = poll_interval_seconds * 5
    if (
        not math.isfinite(max_observation_gap_seconds)
        or max_observation_gap_seconds <= poll_interval_seconds
        or max_observation_gap_seconds >= clean_window_seconds
    ):
        raise BoundaryError(
            "maximum observation gap must be greater than the poll interval "
            "and strictly less than the clean window"
        )

    evidence, evidence_payload = _load_evidence(evidence_path)
    cgroup = str(evidence["cgroup"])
    members_path = cgroup_root / cgroup.lstrip("/") / "cgroup.procs"
    expected_items = [evidence["console"], evidence["coordinator"]]
    expected_pids = {int(item["pid"]) for item in expected_items}
    started_monotonic = monotonic_fn()
    if not math.isfinite(started_monotonic):
        raise BoundaryError("monotonic clock returned a non-finite start time")
    deadline = started_monotonic + wait_timeout_seconds
    if not math.isfinite(deadline):
        raise BoundaryError("monotonic deadline is non-finite")
    ledger: dict[str, object] = {
        "schema_version": 2,
        "mode": "continuous_observed_clean_window",
        "ok": False,
        "status": "running",
        "code": None,
        "started_at": utc_now(),
        "completed_at": None,
        "captured_evidence": str(evidence_path),
        "captured_evidence_sha256": hashlib.sha256(evidence_payload).hexdigest(),
        "cgroup": cgroup,
        "expected_pids": sorted(expected_pids),
        "clean_window_seconds": clean_window_seconds,
        "wait_timeout_seconds": wait_timeout_seconds,
        "poll_interval_seconds": poll_interval_seconds,
        "max_observation_gap_seconds": max_observation_gap_seconds,
        "observation_count": 0,
        "membership_transitions": [],
        "clean_checkpoints": [],
        "clean_window_resets": 0,
        "sampling_gap_resets": 0,
        "sampling_gaps": [],
        "max_observed_gap_seconds": 0.0,
        "max_scan_duration_seconds": 0.0,
        "longest_clean_window_seconds": 0.0,
    }
    try:
        writer = LedgerWriter(ledger_path)
    except (SecureIOError, OSError) as error:
        raise BoundaryError(str(error)) from error

    clean_started: float | None = None
    clean_observations = 0
    last_signature: str | None = None
    last_checkpoint = started_monotonic
    previous_observed: float | None = None
    try:
        writer.write(ledger)
        while True:
            scan_started = monotonic_fn()
            observation, fatal_problems = _observe_boundary(
                members_path=members_path,
                proc_root=proc_root,
                expected_items=expected_items,
                expected_pids=expected_pids,
                after_first_members_read=after_first_members_read,
                after_first_identity_read=after_first_identity_read,
            )
            observed_monotonic = monotonic_fn()
            if not math.isfinite(scan_started):
                fatal_problems.append("monotonic clock returned a non-finite scan start time")
            if not math.isfinite(observed_monotonic):
                fatal_problems.append("monotonic clock returned a non-finite observation time")
            elif math.isfinite(scan_started) and observed_monotonic < scan_started:
                fatal_problems.append("monotonic clock moved backwards during boundary scan")
            elif previous_observed is not None and observed_monotonic < previous_observed:
                fatal_problems.append("monotonic clock moved backwards during boundary observation")
            scan_duration = (
                max(0.0, observed_monotonic - scan_started)
                if math.isfinite(scan_started) and math.isfinite(observed_monotonic)
                else None
            )
            observation_gap = (
                None
                if previous_observed is None or not math.isfinite(observed_monotonic)
                else max(0.0, observed_monotonic - previous_observed)
            )
            sampling_gap = bool(
                (observation_gap is not None and observation_gap >= max_observation_gap_seconds)
                or (scan_duration is not None and scan_duration >= max_observation_gap_seconds)
            )
            observation["scan_started_after_seconds"] = (
                max(0.0, scan_started - started_monotonic) if math.isfinite(scan_started) else None
            )
            observation["scan_completed_after_seconds"] = (
                max(0.0, observed_monotonic - started_monotonic)
                if math.isfinite(observed_monotonic)
                else None
            )
            observation["scan_duration_seconds"] = scan_duration
            observation["gap_since_previous_observation_seconds"] = observation_gap
            if observation_gap is not None:
                ledger["max_observed_gap_seconds"] = max(
                    float(ledger["max_observed_gap_seconds"]), observation_gap
                )
            if scan_duration is not None:
                ledger["max_scan_duration_seconds"] = max(
                    float(ledger["max_scan_duration_seconds"]), scan_duration
                )
            if sampling_gap:
                ledger["sampling_gap_resets"] = int(ledger["sampling_gap_resets"]) + 1
                ledger["sampling_gaps"].append(  # type: ignore[union-attr]
                    {
                        "observation": int(ledger["observation_count"]) + 1,
                        "gap_seconds": observation_gap,
                        "scan_duration_seconds": scan_duration,
                        "timestamp": observation["timestamp"],
                    }
                )
            if math.isfinite(observed_monotonic):
                previous_observed = observed_monotonic
            ledger["observation_count"] = int(ledger["observation_count"]) + 1
            signature = json.dumps(
                {
                    "members": observation["members"],
                    "members_first_read": observation.get("members_first_read"),
                    "processes": observation["processes"],
                    "problems": observation["problems"],
                },
                sort_keys=True,
            )
            if signature != last_signature:
                transition = dict(observation)
                transition["observation"] = ledger["observation_count"]
                ledger["membership_transitions"].append(transition)  # type: ignore[union-attr]
                last_signature = signature
                writer.write(ledger)

            if fatal_problems:
                ledger["status"] = "unsafe"
                ledger["code"] = "captured_boundary_unsafe"
                ledger["completed_at"] = utc_now()
                ledger["failure"] = fatal_problems
                ledger["last_observation"] = observation
                writer.write(ledger)
                raise BoundaryError("; ".join(fatal_problems))

            exact = not observation["problems"]
            if exact:
                if clean_started is None or sampling_gap:
                    if clean_started is not None:
                        ledger["clean_window_resets"] = int(ledger["clean_window_resets"]) + 1
                    clean_started = observed_monotonic
                    clean_observations = 1
                    last_checkpoint = observed_monotonic
                else:
                    clean_observations += 1
                clean_duration = max(0.0, observed_monotonic - clean_started)
                ledger["longest_clean_window_seconds"] = max(
                    float(ledger["longest_clean_window_seconds"]), clean_duration
                )
                if observed_monotonic - last_checkpoint >= 1.0:
                    checkpoint = dict(observation)
                    checkpoint["clean_duration_seconds"] = clean_duration
                    checkpoint["observation"] = ledger["observation_count"]
                    ledger["clean_checkpoints"].append(checkpoint)  # type: ignore[union-attr]
                    last_checkpoint = observed_monotonic
                    writer.write(ledger)
                if clean_duration >= clean_window_seconds and observed_monotonic <= deadline:
                    ledger["ok"] = True
                    ledger["status"] = "succeeded"
                    ledger["code"] = "observed_clean_window"
                    ledger["completed_at"] = utc_now()
                    ledger["clean_window"] = {
                        "duration_seconds": clean_duration,
                        "observations": clean_observations,
                        "started_after_seconds": max(0.0, clean_started - started_monotonic),
                        "completed_after_seconds": max(
                            0.0, observed_monotonic - started_monotonic
                        ),
                    }
                    ledger["last_observation"] = observation
                    writer.write(ledger)
                    break
            else:
                if clean_started is not None:
                    ledger["clean_window_resets"] = int(ledger["clean_window_resets"]) + 1
                clean_started = None
                clean_observations = 0

            if observed_monotonic >= deadline:
                ledger["status"] = "timed_out"
                ledger["code"] = "clean_window_timeout"
                ledger["completed_at"] = utc_now()
                ledger["failure"] = [
                    f"no continuous {clean_window_seconds:g}-second exact cgroup window "
                    f"within {wait_timeout_seconds:g} seconds"
                ]
                ledger["last_observation"] = observation
                writer.write(ledger)
                raise BoundaryError(str(ledger["failure"][0]))
            if sampling_gap:
                writer.write(ledger)
            sleep_fn(poll_interval_seconds)
    except BoundaryInterrupted as error:
        ledger["ok"] = False
        ledger["status"] = "interrupted"
        ledger["code"] = "observation_interrupted"
        ledger["completed_at"] = utc_now()
        ledger["failure"] = [str(error)]
        writer.write(ledger)
        raise
    finally:
        writer.close()
    verify_ledger_pair(ledger_path)
    return ledger


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, help="captured legacy-processes.json")
    parser.add_argument("--ledger", required=True, help="new private JSON evidence ledger")
    parser.add_argument("--continuous-clean-seconds", type=float, required=True)
    parser.add_argument("--wait-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--poll-interval-seconds", type=float, default=0.02)
    parser.add_argument("--max-observation-gap-seconds", type=float, required=True)
    parser.add_argument("--cgroup-root", default="/sys/fs/cgroup", help=argparse.SUPPRESS)
    parser.add_argument("--proc-root", default="/proc", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    handled_signals = [signal.SIGINT, signal.SIGTERM]
    if hasattr(signal, "SIGHUP"):
        handled_signals.append(signal.SIGHUP)
    previous_handlers: dict[signal.Signals, object] = {}

    def interrupt(signum: int, _frame: object) -> None:
        raise BoundaryInterrupted(
            f"boundary observation interrupted by {signal.Signals(signum).name}"
        )

    try:
        for handled_signal in handled_signals:
            previous_handlers[handled_signal] = signal.signal(handled_signal, interrupt)
        report = wait_for_clean_boundary(
            evidence_path=Path(args.evidence),
            ledger_path=Path(args.ledger),
            cgroup_root=Path(args.cgroup_root),
            proc_root=Path(args.proc_root),
            clean_window_seconds=args.continuous_clean_seconds,
            wait_timeout_seconds=args.wait_timeout_seconds,
            poll_interval_seconds=args.poll_interval_seconds,
            max_observation_gap_seconds=args.max_observation_gap_seconds,
        )
    except (BoundaryError, OSError) as error:
        print(f"legacy cutover boundary failed: {error}", file=sys.stderr)
        return 1
    finally:
        for handled_signal, previous_handler in previous_handlers.items():
            signal.signal(handled_signal, previous_handler)
    clean_window = report.get("clean_window") or {}
    print(
        "legacy cutover boundary ok "
        f"({float(clean_window.get('duration_seconds') or 0):.3f}s observed clean window; "
        f"{report.get('observation_count')} observations; ledger {args.ledger})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
