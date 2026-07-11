#!/usr/bin/env python3
"""Fail closed until the captured legacy cgroup, processes, and listeners are gone."""

from __future__ import annotations

import argparse
import json
import math
import socket
import sys
import time
from pathlib import Path
from typing import Callable

from linux_proc_identity import ProcIdentityError, read_stable_process_identity
from secure_cutover_io import SecureIOError, read_private_regular


class StoppedBoundaryError(RuntimeError):
    pass


class RetryableStoppedBoundaryError(StoppedBoundaryError):
    """A still-live boundary that may converge before the finite deadline."""


MAX_WAIT_TIMEOUT_SECONDS = 60.0
MAX_POLL_INTERVAL_SECONDS = 1.0


def default_port_probe(port: int) -> bool:
    with socket.socket() as probe:
        probe.settimeout(0.3)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def load_evidence(path: Path) -> dict[str, object]:
    try:
        evidence = json.loads(read_private_regular(path, label="captured process evidence"))
        cgroup = evidence["cgroup"]
        console = evidence["console"]
        coordinator = evidence["coordinator"]
        if not isinstance(cgroup, str) or not cgroup.startswith("/") or ".." in Path(cgroup).parts:
            raise ValueError("captured cgroup must be an absolute cgroup path")
        for item in (console, coordinator):
            if not isinstance(item["pid"], int) or item["pid"] <= 1:
                raise ValueError("captured PID must be an integer greater than one")
            if not isinstance(item["start_ticks"], str) or not isinstance(item["command"], list):
                raise ValueError("captured process identity is incomplete")
    except (SecureIOError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        raise StoppedBoundaryError(f"invalid captured process evidence: {error}") from error
    return evidence


def _check_stopped_once(
    *,
    evidence: dict[str, object],
    observed_cgroup_identities: set[tuple[int, str]],
    cgroup_root: Path = Path("/sys/fs/cgroup"),
    proc_root: Path = Path("/proc"),
    ports: tuple[int, ...] = (80, 443, 29876),
    port_probe: Callable[[int], bool] = default_port_probe,
) -> dict[str, object]:
    members_path = cgroup_root / str(evidence["cgroup"]).lstrip("/") / "cgroup.procs"
    try:
        members = {
            int(value)
            for value in members_path.read_text(encoding="utf-8").splitlines()
            if value.strip()
        }
    except FileNotFoundError:
        members = set()
    except (PermissionError, OSError, ValueError) as error:
        raise StoppedBoundaryError(f"legacy cgroup process list cannot be verified: {error}") from error
    if members:
        records: list[dict[str, object]] = []
        for pid in sorted(members):
            try:
                start, _command = read_stable_process_identity(proc_root / str(pid))
                observed_cgroup_identities.add((pid, start))
                records.append({"pid": pid, "start_ticks": start, "identity": "captured"})
            except (FileNotFoundError, ProcessLookupError) as error:
                records.append({"pid": pid, "identity_error": f"{type(error).__name__}: {error}"})
            except (PermissionError, ProcIdentityError, OSError) as error:
                raise StoppedBoundaryError(
                    f"cannot capture legacy cgroup member {pid} identity: {error}"
                ) from error
        raise RetryableStoppedBoundaryError(
            "legacy cgroup still has managed processes: " + json.dumps(records, sort_keys=True)
        )

    escaped_records: list[dict[str, object]] = []
    for pid, start_ticks in sorted(observed_cgroup_identities):
        try:
            actual = read_stable_process_identity(proc_root / str(pid))
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (PermissionError, ProcIdentityError, OSError) as error:
            raise StoppedBoundaryError(
                f"cannot verify observed legacy cgroup member {pid} exit: {error}"
            ) from error
        if actual[0] == start_ticks:
            escaped_records.append({"pid": pid, "start_ticks": start_ticks})
    if escaped_records:
        raise RetryableStoppedBoundaryError(
            "observed legacy cgroup processes are still alive outside the cgroup: "
            + json.dumps(escaped_records, sort_keys=True)
        )

    for role in ("console", "coordinator"):
        item = evidence[role]
        try:
            actual = read_stable_process_identity(proc_root / str(item["pid"]))
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (PermissionError, ProcIdentityError, OSError) as error:
            raise StoppedBoundaryError(f"cannot verify captured {role} process exit: {error}") from error
        if actual[0] == item["start_ticks"]:
            raise RetryableStoppedBoundaryError(
                f"captured legacy process is still alive: {item['pid']}"
            )

    open_ports = [port for port in ports if port_probe(port)]
    if open_ports:
        raise RetryableStoppedBoundaryError(
            f"legacy listener still accepts connections on ports: {open_ports}"
        )
    return {
        "ok": True,
        "cgroup": evidence["cgroup"],
        "cgroup_members": [],
        "closed_ports": list(ports),
    }


def check_stopped(
    *,
    evidence_path: Path,
    cgroup_root: Path = Path("/sys/fs/cgroup"),
    proc_root: Path = Path("/proc"),
    ports: tuple[int, ...] = (80, 443, 29876),
    port_probe: Callable[[int], bool] = default_port_probe,
    wait_timeout_seconds: float = 0.0,
    poll_interval_seconds: float = 0.1,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    """Verify the stopped boundary once, or until a finite deadline.

    A zero timeout preserves the original fail-fast, one-shot behavior.  A
    positive timeout permits only the same exact cgroup, PID-identity, and
    listener checks to converge; it does not weaken or omit any boundary.
    """

    if (
        not math.isfinite(wait_timeout_seconds)
        or wait_timeout_seconds < 0
        or wait_timeout_seconds > MAX_WAIT_TIMEOUT_SECONDS
    ):
        raise StoppedBoundaryError(
            f"wait timeout must be finite and between 0 and {MAX_WAIT_TIMEOUT_SECONDS:g} seconds"
        )
    if (
        not math.isfinite(poll_interval_seconds)
        or poll_interval_seconds <= 0
        or poll_interval_seconds > MAX_POLL_INTERVAL_SECONDS
    ):
        raise StoppedBoundaryError(
            "poll interval must be finite, greater than zero, and at most "
            f"{MAX_POLL_INTERVAL_SECONDS:g} second"
        )

    evidence = load_evidence(evidence_path)
    observed_cgroup_identities: set[tuple[int, str]] = set()

    # Keep the original call and output contract exact when no wait was
    # requested: one check, no clock dependency, and no timing metadata.
    if wait_timeout_seconds == 0:
        return _check_stopped_once(
            evidence=evidence,
            observed_cgroup_identities=observed_cgroup_identities,
            cgroup_root=cgroup_root,
            proc_root=proc_root,
            ports=ports,
            port_probe=port_probe,
        )

    started = monotonic()
    if not math.isfinite(started):
        raise StoppedBoundaryError("monotonic clock returned a non-finite start time")
    deadline = started + wait_timeout_seconds
    if not math.isfinite(deadline) or deadline < started:
        raise StoppedBoundaryError("monotonic deadline is invalid")
    last_clock_reading = started
    attempts = 0
    last_retryable_error: RetryableStoppedBoundaryError | None = None
    while True:
        attempts += 1
        try:
            report = _check_stopped_once(
                evidence=evidence,
                observed_cgroup_identities=observed_cgroup_identities,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                ports=ports,
                port_probe=port_probe,
            )
        except RetryableStoppedBoundaryError as error:
            last_retryable_error = error
            now = monotonic()
            if not math.isfinite(now):
                raise StoppedBoundaryError(
                    "monotonic clock returned a non-finite boundary time"
                ) from error
            if now < last_clock_reading:
                raise StoppedBoundaryError(
                    "monotonic clock moved backwards during stopped-boundary validation"
                ) from error
            last_clock_reading = now
            remaining = deadline - now
            if remaining <= 0:
                elapsed = max(0.0, now - started)
                raise StoppedBoundaryError(
                    "stopped boundary did not converge "
                    f"after {attempts} attempts in {elapsed:.3f}s: {error}"
                ) from error
            sleeper(min(poll_interval_seconds, remaining))
            after_sleep = monotonic()
            if not math.isfinite(after_sleep):
                raise StoppedBoundaryError(
                    "monotonic clock returned a non-finite post-sleep time"
                ) from error
            if after_sleep <= last_clock_reading:
                raise StoppedBoundaryError(
                    "monotonic clock did not advance during stopped-boundary wait"
                ) from error
            if after_sleep >= deadline:
                elapsed = max(0.0, after_sleep - started)
                raise StoppedBoundaryError(
                    "stopped boundary did not converge "
                    f"after {attempts} attempts in {elapsed:.3f}s: {error}"
                ) from error
            last_clock_reading = after_sleep
            continue

        completed = monotonic()
        if not math.isfinite(completed):
            raise StoppedBoundaryError("monotonic clock returned a non-finite completion time")
        if completed < last_clock_reading:
            raise StoppedBoundaryError(
                "monotonic clock moved backwards during stopped-boundary completion"
            )
        elapsed = max(0.0, completed - started)
        if completed >= deadline:
            latest = (
                f": last boundary failure was {last_retryable_error}"
                if last_retryable_error is not None
                else ""
            )
            raise StoppedBoundaryError(
                "stopped boundary clean observation reached or exceeded its deadline "
                f"after {attempts} attempts in {elapsed:.3f}s{latest}"
            )
        report["attempts"] = attempts
        report["elapsed_seconds"] = round(elapsed, 6)
        report["observed_cgroup_processes"] = [
            {"pid": pid, "start_ticks": start_ticks, "status": "exited-or-reused"}
            for pid, start_ticks in sorted(observed_cgroup_identities)
        ]
        return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--cgroup-root", default="/sys/fs/cgroup", help=argparse.SUPPRESS)
    parser.add_argument("--proc-root", default="/proc", help=argparse.SUPPRESS)
    parser.add_argument("--ports", nargs="+", type=int, default=[80, 443, 29876])
    parser.add_argument(
        "--wait-timeout-seconds",
        type=float,
        default=0.0,
        help="bounded time to wait for the exact stopped boundary (default: one shot)",
    )
    parser.add_argument(
        "--poll-interval-seconds",
        type=float,
        default=0.1,
        help="poll interval while waiting for the stopped boundary",
    )
    args = parser.parse_args(argv)
    if any(port < 1 or port > 65535 for port in args.ports):
        parser.error("ports must be between 1 and 65535")
    if (
        not math.isfinite(args.wait_timeout_seconds)
        or args.wait_timeout_seconds < 0
        or args.wait_timeout_seconds > MAX_WAIT_TIMEOUT_SECONDS
    ):
        parser.error(
            f"wait timeout must be finite and between 0 and {MAX_WAIT_TIMEOUT_SECONDS:g} seconds"
        )
    if (
        not math.isfinite(args.poll_interval_seconds)
        or args.poll_interval_seconds <= 0
        or args.poll_interval_seconds > MAX_POLL_INTERVAL_SECONDS
    ):
        parser.error(
            "poll interval must be finite, greater than zero, and at most "
            f"{MAX_POLL_INTERVAL_SECONDS:g} second"
        )
    try:
        report = check_stopped(
            evidence_path=Path(args.evidence),
            cgroup_root=Path(args.cgroup_root),
            proc_root=Path(args.proc_root),
            ports=tuple(args.ports),
            wait_timeout_seconds=args.wait_timeout_seconds,
            poll_interval_seconds=args.poll_interval_seconds,
        )
    except (StoppedBoundaryError, OSError) as error:
        print(f"legacy stopped-boundary failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
