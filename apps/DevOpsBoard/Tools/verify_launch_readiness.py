#!/usr/bin/env python3
"""Wait for a fresh DevOps Board inventory-readiness telemetry marker."""

from __future__ import annotations

import argparse
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


MARKER_PATTERN = re.compile(
    r"(?<!\S)Inventory refresh (?P<outcome>completed|failed) "
    r"pid=(?P<pid>[1-9][0-9]*) loaded=(?P<loaded>[0-9]+) "
    r"total=(?P<total>[0-9]+)\s*$"
)
MAX_PARTIAL_LINE_CHARS = 65_536


class LaunchReadinessError(RuntimeError):
    """The newly launched app did not prove usable inventory readiness."""


@dataclass(frozen=True)
class InventoryMarker:
    outcome: str
    pid: int
    loaded: int
    total: int


@dataclass(frozen=True)
class ReadinessResult:
    pid: int
    loaded: int
    total: int


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    executable: str
    start: str


def parse_inventory_marker(line: str) -> InventoryMarker | None:
    """Parse only the exact marker emitted at the end of a unified-log line."""

    match = MARKER_PATTERN.search(line)
    if match is None:
        return None
    return InventoryMarker(
        outcome=match.group("outcome"),
        pid=int(match.group("pid")),
        loaded=int(match.group("loaded")),
        total=int(match.group("total")),
    )


def evaluate_inventory_marker(marker: InventoryMarker, *, expected_pid: int) -> ReadinessResult | None:
    """Ignore stale PIDs and classify a marker from the newly launched app."""

    if marker.pid != expected_pid:
        return None
    if marker.outcome == "failed":
        if marker.loaded != 0:
            raise LaunchReadinessError(
                f"inventory failure marker for PID {expected_pid} reported loaded={marker.loaded}; expected 0"
            )
        raise LaunchReadinessError(
            f"inventory refresh failed for PID {expected_pid}: loaded=0 total={marker.total}"
        )
    if marker.loaded < 1:
        raise LaunchReadinessError(
            f"inventory refresh completed for PID {expected_pid} without a loaded source"
        )
    if marker.total < marker.loaded:
        raise LaunchReadinessError(
            f"inventory readiness marker for PID {expected_pid} is inconsistent: "
            f"loaded={marker.loaded} total={marker.total}"
        )
    return ReadinessResult(pid=expected_pid, loaded=marker.loaded, total=marker.total)


def process_state_is_alive(state: str) -> bool:
    normalized = state.strip()
    return bool(normalized) and not normalized.startswith("Z")


def _ps_field(pid: int, field: str) -> str | None:
    result = subprocess.run(
        ["/bin/ps", "-ww", "-p", str(pid), "-o", f"{field}="],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def normalize_start_identity(value: str) -> str:
    return " ".join(value.split())


def normalize_executable(value: str) -> str:
    return os.path.realpath(value)


def process_identity(pid: int) -> ProcessIdentity | None:
    """Read one stable, non-zombie executable/start identity for a PID."""

    state_before = _ps_field(pid, "stat")
    start_before = _ps_field(pid, "lstart")
    executable = _ps_field(pid, "comm")
    start_after = _ps_field(pid, "lstart")
    state_after = _ps_field(pid, "stat")
    if (
        state_before is None
        or start_before is None
        or executable is None
        or start_after is None
        or state_after is None
        or not process_state_is_alive(state_before)
        or not process_state_is_alive(state_after)
    ):
        return None
    normalized_before = normalize_start_identity(start_before)
    normalized_after = normalize_start_identity(start_after)
    if normalized_before != normalized_after:
        return None
    return ProcessIdentity(
        pid=pid,
        executable=normalize_executable(executable),
        start=normalized_before,
    )


def process_is_alive(pid: int) -> bool:
    state = _ps_field(pid, "stat")
    return state is not None and process_state_is_alive(state)


def require_process_identity(
    expected: ProcessIdentity,
    *,
    identity_reader: Callable[[int], ProcessIdentity | None],
    phase: str,
) -> None:
    current = identity_reader(expected.pid)
    if current is None:
        raise LaunchReadinessError(
            f"DevOpsBoard PID {expected.pid} exited or became unobservable {phase}"
        )
    if current != expected:
        raise LaunchReadinessError(
            f"DevOpsBoard PID {expected.pid} changed identity {phase}; "
            "refusing stale-process readiness"
        )


def wait_for_stable_identity(
    *,
    expected: ProcessIdentity,
    capture_pid: int | None,
    duration: float,
    poll_interval: float,
    identity_reader: Callable[[int], ProcessIdentity | None],
    is_alive: Callable[[int], bool],
    monotonic: Callable[[], float],
    sleep: Callable[[float], None],
) -> None:
    deadline = monotonic() + duration
    while True:
        require_process_identity(
            expected,
            identity_reader=identity_reader,
            phase="during launch stabilization",
        )
        if capture_pid is not None and not is_alive(capture_pid):
            raise LaunchReadinessError(
                "unified-log capture exited during launch stabilization"
            )
        now = monotonic()
        if now >= deadline:
            return
        sleep(min(poll_interval, deadline - now))


def wait_for_inventory_readiness(
    *,
    log_path: Path,
    expected_identity: ProcessIdentity,
    timeout: float,
    poll_interval: float = 0.05,
    stabilization: float = 1.5,
    capture_pid: int | None = None,
    identity_reader: Callable[[int], ProcessIdentity | None] = process_identity,
    is_alive: Callable[[int], bool] = process_is_alive,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> ReadinessResult:
    """Tail one fresh capture until the expected PID proves inventory readiness."""

    if expected_identity.pid < 1:
        raise ValueError("expected PID must be positive")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if poll_interval <= 0:
        raise ValueError("poll_interval must be positive")
    if stabilization <= 0:
        raise ValueError("stabilization must be positive")

    deadline = monotonic() + timeout
    offset = 0
    partial = ""

    def inspect(line: str) -> ReadinessResult | None:
        marker = parse_inventory_marker(line)
        if marker is None:
            return None
        result = evaluate_inventory_marker(marker, expected_pid=expected_identity.pid)
        if result is not None:
            require_process_identity(
                expected_identity,
                identity_reader=identity_reader,
                phase="after reporting inventory readiness",
            )
        return result

    while True:
        require_process_identity(
            expected_identity,
            identity_reader=identity_reader,
            phase="before inventory readiness",
        )
        if capture_pid is not None and not is_alive(capture_pid):
            raise LaunchReadinessError("unified-log capture exited before inventory readiness")

        try:
            current_size = log_path.stat().st_size
        except FileNotFoundError:
            current_size = 0
        if current_size < offset:
            offset = 0
            partial = ""
        if current_size > offset:
            with log_path.open("r", encoding="utf-8", errors="replace") as stream:
                stream.seek(offset)
                partial += stream.read()
                offset = stream.tell()
            while "\n" in partial:
                line, partial = partial.split("\n", 1)
                result = inspect(line)
                if result is not None:
                    wait_for_stable_identity(
                        expected=expected_identity,
                        capture_pid=capture_pid,
                        duration=stabilization,
                        poll_interval=poll_interval,
                        identity_reader=identity_reader,
                        is_alive=is_alive,
                        monotonic=monotonic,
                        sleep=sleep,
                    )
                    return result
            if len(partial) > MAX_PARTIAL_LINE_CHARS:
                partial = partial[-MAX_PARTIAL_LINE_CHARS:]

        now = monotonic()
        if now >= deadline:
            if partial:
                result = inspect(partial)
                if result is not None:
                    wait_for_stable_identity(
                        expected=expected_identity,
                        capture_pid=capture_pid,
                        duration=stabilization,
                        poll_interval=poll_interval,
                        identity_reader=identity_reader,
                        is_alive=is_alive,
                        monotonic=monotonic,
                        sleep=sleep,
                    )
                    return result
            raise LaunchReadinessError(
                f"timed out waiting for inventory readiness from DevOpsBoard PID {expected_identity.pid}"
            )
        sleep(min(poll_interval, deadline - now))


def terminate_exact_process(
    expected: ProcessIdentity,
    *,
    grace: float = 2.0,
    poll_interval: float = 0.05,
    identity_reader: Callable[[int], ProcessIdentity | None] = process_identity,
    send_signal: Callable[[int, int], None] = os.kill,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Boundedly terminate only the process that still has the captured identity."""

    if grace <= 0:
        raise ValueError("grace must be positive")
    current = identity_reader(expected.pid)
    if current is None or current != expected:
        return False
    try:
        send_signal(expected.pid, signal.SIGTERM)
    except ProcessLookupError:
        return False
    deadline = monotonic() + grace
    while monotonic() < deadline:
        current = identity_reader(expected.pid)
        if current is None or current != expected:
            return True
        sleep(max(0.0, min(poll_interval, deadline - monotonic())))
    current = identity_reader(expected.pid)
    if current is None or current != expected:
        return True
    try:
        send_signal(expected.pid, signal.SIGKILL)
    except ProcessLookupError:
        return True
    kill_deadline = monotonic() + grace
    while monotonic() < kill_deadline:
        current = identity_reader(expected.pid)
        if current is None or current != expected:
            return True
        sleep(max(0.0, min(poll_interval, kill_deadline - monotonic())))
    current = identity_reader(expected.pid)
    if current is not None and current == expected:
        raise LaunchReadinessError(
            f"DevOpsBoard PID {expected.pid} retained its exact identity after SIGKILL"
        )
    return True


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inspect, verify, or safely terminate one DevOps Board launch identity."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    inspect = commands.add_parser("inspect")
    inspect.add_argument("--pid", type=int, required=True)
    inspect.add_argument("--expected-executable", required=True)

    wait = commands.add_parser("wait")
    wait.add_argument("--log-file", type=Path, required=True)
    wait.add_argument("--pid", type=int, required=True)
    wait.add_argument("--expected-executable", required=True)
    wait.add_argument("--expected-start", required=True)
    wait.add_argument("--capture-pid", type=int)
    wait.add_argument("--timeout", type=float, default=30.0)
    wait.add_argument("--poll-interval", type=float, default=0.05)
    wait.add_argument("--stabilization", type=float, default=1.5)

    terminate = commands.add_parser("terminate")
    terminate.add_argument("--pid", type=int, required=True)
    terminate.add_argument("--expected-executable", required=True)
    terminate.add_argument("--expected-start", required=True)
    terminate.add_argument("--grace", type=float, default=2.0)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "inspect":
            identity = process_identity(args.pid)
            if identity is None:
                raise LaunchReadinessError(
                    f"DevOpsBoard PID {args.pid} exited or became unobservable during identity capture"
                )
            expected_executable = normalize_executable(args.expected_executable)
            if identity.executable != expected_executable:
                raise LaunchReadinessError(
                    f"PID {args.pid} executable does not match the packaged DevOpsBoard binary"
                )
            print(identity.start)
            return 0

        expected_identity = ProcessIdentity(
            pid=args.pid,
            executable=normalize_executable(args.expected_executable),
            start=normalize_start_identity(args.expected_start),
        )
        if args.command == "terminate":
            terminated = terminate_exact_process(expected_identity, grace=args.grace)
            print(
                f"DevOps Board cleanup: pid={args.pid} "
                f"status={'terminated' if terminated else 'already-exited-or-identity-changed'}"
            )
            return 0

        result = wait_for_inventory_readiness(
            log_path=args.log_file,
            expected_identity=expected_identity,
            timeout=args.timeout,
            poll_interval=args.poll_interval,
            stabilization=args.stabilization,
            capture_pid=args.capture_pid,
        )
    except (LaunchReadinessError, OSError, ValueError) as error:
        print(f"DevOps Board launch verification failed: {error}", file=sys.stderr)
        return 1
    print(
        f"DevOps Board ready: pid={result.pid} loaded={result.loaded} total={result.total}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
