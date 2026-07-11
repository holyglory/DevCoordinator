#!/usr/bin/env python3
"""Recall tests for the post-stop legacy cgroup/process/listener boundary."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Callable

from check_legacy_cutover_stopped import StoppedBoundaryError, check_stopped


def write_process(proc_root: Path, pid: int, start: str, command: list[str]) -> None:
    process = proc_root / str(pid)
    process.mkdir(parents=True, exist_ok=True)
    after_comm = ["S", *("0" for _ in range(18)), start]
    (process / "stat").write_text(
        f"{pid} (fixture worker) {' '.join(after_comm)}\n",
        encoding="utf-8",
    )
    (process / "cmdline").write_bytes(b"\0".join(part.encode() for part in command) + b"\0")


class FixtureClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        if seconds <= 0:
            raise AssertionError("bounded wait requested a non-positive sleep")
        self.now += seconds


class SequenceClock:
    def __init__(self, readings: list[float]) -> None:
        self.readings = iter(readings)

    def monotonic(self) -> float:
        return next(self.readings)


def forbidden_sleep(message: str) -> Callable[[float], None]:
    def sleeper(_seconds: float) -> None:
        raise AssertionError(message)

    return sleeper


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="legacy-stopped-boundary-") as raw:
        root = Path(raw).resolve(strict=True)
        cgroup_root = root / "cgroup"
        proc_root = root / "proc"
        members = cgroup_root / "system.slice/devops-console.service/cgroup.procs"
        members.parent.mkdir(parents=True)
        members.write_text("", encoding="utf-8")
        console = ["/usr/bin/node", "/srv/fixture/console.mjs"]
        coordinator = ["/usr/bin/python3", "/srv/fixture/coordinator.py", "api", "serve"]
        evidence = root / "legacy-processes.json"
        evidence.write_text(
            json.dumps(
                {
                    "cgroup": "/system.slice/devops-console.service",
                    "console": {"pid": 101, "start_ticks": "11001", "command": console},
                    "coordinator": {"pid": 202, "start_ticks": "22002", "command": coordinator},
                }
            ),
            encoding="utf-8",
        )
        os.chmod(evidence, 0o600)
        clean_clock = FixtureClock()
        report = check_stopped(
            evidence_path=evidence,
            cgroup_root=cgroup_root,
            proc_root=proc_root,
            port_probe=lambda _port: False,
            monotonic=clean_clock.monotonic,
            sleeper=clean_clock.sleep,
        )
        if report["ok"] is not True:
            raise AssertionError("empty stopped boundary did not pass")
        expected_one_shot = {
            "ok": True,
            "cgroup": "/system.slice/devops-console.service",
            "cgroup_members": [],
            "closed_ports": [80, 443, 29876],
        }
        if report != expected_one_shot:
            raise AssertionError(f"clean one-shot contract changed: {report}")

        invalid_waits = (
            (float("nan"), 0.02),
            (float("inf"), 0.02),
            (-0.01, 0.02),
            (1.0, float("nan")),
            (1.0, 0.0),
            (1.0, -0.01),
            (60.01, 0.02),
            (1.0, 1.01),
        )
        for timeout, interval in invalid_waits:
            try:
                check_stopped(
                    evidence_path=evidence,
                    cgroup_root=cgroup_root,
                    proc_root=proc_root,
                    port_probe=lambda _port: False,
                    wait_timeout_seconds=timeout,
                    poll_interval_seconds=interval,
                )
            except StoppedBoundaryError:
                pass
            else:
                raise AssertionError("non-finite bounded-wait input was accepted")

        invalid_evidence = root / "invalid-process-evidence.json"
        invalid_evidence.write_text("{not-json\n", encoding="utf-8")
        os.chmod(invalid_evidence, 0o600)
        try:
            check_stopped(
                evidence_path=invalid_evidence,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                port_probe=lambda _port: False,
                wait_timeout_seconds=1.0,
                poll_interval_seconds=0.02,
                sleeper=forbidden_sleep("invalid evidence was retried"),
            )
        except StoppedBoundaryError as error:
            if (
                "invalid captured process evidence" not in str(error)
                or "did not converge" in str(error)
            ):
                raise
        else:
            raise AssertionError("invalid evidence was treated as retryable")

        broken_cgroup_root = root / "broken-cgroup"
        broken_members = (
            broken_cgroup_root / "system.slice/devops-console.service/cgroup.procs"
        )
        broken_members.mkdir(parents=True)
        try:
            check_stopped(
                evidence_path=evidence,
                cgroup_root=broken_cgroup_root,
                proc_root=proc_root,
                port_probe=lambda _port: False,
                wait_timeout_seconds=1.0,
                poll_interval_seconds=0.02,
                sleeper=forbidden_sleep("unreadable cgroup evidence was retried"),
            )
        except StoppedBoundaryError as error:
            if (
                "process list cannot be verified" not in str(error)
                or "did not converge" in str(error)
            ):
                raise
        else:
            raise AssertionError("unreadable cgroup evidence was treated as retryable")

        slow_success_clock = FixtureClock()

        def slow_closed_port(_port: int) -> bool:
            slow_success_clock.now = 1.01
            return False

        try:
            check_stopped(
                evidence_path=evidence,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                port_probe=slow_closed_port,
                wait_timeout_seconds=1.0,
                poll_interval_seconds=0.02,
                monotonic=slow_success_clock.monotonic,
                sleeper=forbidden_sleep("slow clean observation unexpectedly retried"),
            )
        except StoppedBoundaryError as error:
            message = str(error)
            if (
                "clean observation reached or exceeded its deadline" not in message
                or "after 1 attempts in 1.010s" not in message
            ):
                raise
        else:
            raise AssertionError("clean observation that completed after deadline passed")

        # A real service stop can leave a short-lived child in the cgroup.
        # The bounded mode must retry the unchanged exact check and report the
        # convergence evidence without adding a wall-clock delay to this test.
        write_process(proc_root, 303, "33003", ["/usr/bin/git", "status", "--porcelain"])
        members.write_text("303\n", encoding="utf-8")
        transient_clock = FixtureClock()

        def finish_transient_cgroup(seconds: float) -> None:
            transient_clock.sleep(seconds)
            members.write_text("", encoding="utf-8")
            shutil.rmtree(proc_root / "303")

        report = check_stopped(
            evidence_path=evidence,
            cgroup_root=cgroup_root,
            proc_root=proc_root,
            port_probe=lambda _port: False,
            wait_timeout_seconds=1.0,
            poll_interval_seconds=0.02,
            monotonic=transient_clock.monotonic,
            sleeper=finish_transient_cgroup,
        )
        if report["attempts"] != 2 or report["elapsed_seconds"] != 0.02:
            raise AssertionError(f"transient cgroup convergence was not reported: {report}")
        if report["observed_cgroup_processes"] != [
            {"pid": 303, "start_ticks": "33003", "status": "exited-or-reused"}
        ]:
            raise AssertionError(f"transient child identity was not retained: {report}")

        # Must catch an unattributed process with no listener that survives in
        # the old cgroup—the exact rollback gap found during review.
        write_process(proc_root, 303, "33003", ["/usr/bin/git", "status", "--porcelain"])
        members.write_text("303\n", encoding="utf-8")
        try:
            check_stopped(
                evidence_path=evidence,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                port_probe=lambda _port: False,
            )
        except StoppedBoundaryError as error:
            expected = (
                "legacy cgroup still has managed processes: "
                '[{"identity": "captured", "pid": 303, "start_ticks": "33003"}]'
            )
            if str(error) != expected:
                raise AssertionError(f"one-shot failure contract changed: {error}") from error
        else:
            raise AssertionError("surviving cgroup process was not detected")

        oversleep_clock = FixtureClock()

        def reach_deadline_before_retry(_seconds: float) -> None:
            # Model a scheduler wakeup that overshoots the budget rather than
            # mirroring the exact `>= deadline` implementation branch.
            oversleep_clock.now = 0.08

        try:
            check_stopped(
                evidence_path=evidence,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                port_probe=lambda _port: False,
                wait_timeout_seconds=0.05,
                poll_interval_seconds=0.02,
                monotonic=oversleep_clock.monotonic,
                sleeper=reach_deadline_before_retry,
            )
        except StoppedBoundaryError as error:
            message = str(error)
            if (
                "did not converge after 1 attempts in 0.080s" not in message
                or "cgroup still has managed processes" not in message
            ):
                raise
        else:
            raise AssertionError("sleep that reached the deadline began another check")

        for label, readings in (
            ("non-finite", [0.0, float("nan")]),
            ("backward", [1.0, 0.5]),
        ):
            clock = SequenceClock(readings)
            try:
                check_stopped(
                    evidence_path=evidence,
                    cgroup_root=cgroup_root,
                    proc_root=proc_root,
                    port_probe=lambda _port: False,
                    wait_timeout_seconds=1.0,
                    poll_interval_seconds=0.02,
                    monotonic=clock.monotonic,
                    sleeper=forbidden_sleep("invalid clock reached sleep"),
                )
            except StoppedBoundaryError as error:
                if "monotonic clock" not in str(error):
                    raise
            else:
                raise AssertionError(f"{label} monotonic clock was accepted")

        stalled_clock = FixtureClock()
        try:
            check_stopped(
                evidence_path=evidence,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                port_probe=lambda _port: False,
                wait_timeout_seconds=1.0,
                poll_interval_seconds=0.02,
                monotonic=stalled_clock.monotonic,
                sleeper=lambda _seconds: None,
            )
        except StoppedBoundaryError as error:
            if "did not advance" not in str(error):
                raise
        else:
            raise AssertionError("stalled monotonic clock was accepted")

        escaped_clock = FixtureClock()

        def escape_cgroup_without_exiting(seconds: float) -> None:
            escaped_clock.sleep(seconds)
            members.write_text("", encoding="utf-8")

        try:
            check_stopped(
                evidence_path=evidence,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                port_probe=lambda _port: False,
                wait_timeout_seconds=0.03,
                poll_interval_seconds=0.02,
                monotonic=escaped_clock.monotonic,
                sleeper=escape_cgroup_without_exiting,
            )
        except StoppedBoundaryError as error:
            message = str(error)
            if (
                "did not converge after 2 attempts in 0.030s" not in message
                or "still alive outside the cgroup" not in message
                or '"pid": 303' not in message
                or '"start_ticks": "33003"' not in message
            ):
                raise
        else:
            raise AssertionError("cgroup member that escaped without exiting was missed")

        members.write_text("303\n", encoding="utf-8")
        persistent_clock = FixtureClock()
        try:
            check_stopped(
                evidence_path=evidence,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                port_probe=lambda _port: False,
                wait_timeout_seconds=0.05,
                poll_interval_seconds=0.02,
                monotonic=persistent_clock.monotonic,
                sleeper=persistent_clock.sleep,
            )
        except StoppedBoundaryError as error:
            message = str(error)
            if (
                "did not converge after 3 attempts in 0.050s" not in message
                or "cgroup still has managed processes" not in message
            ):
                raise
        else:
            raise AssertionError("persistent cgroup process did not time out")

        members.write_text("", encoding="utf-8")
        write_process(proc_root, 202, "22002", coordinator)
        try:
            check_stopped(
                evidence_path=evidence,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                port_probe=lambda _port: False,
            )
        except StoppedBoundaryError as error:
            if "still alive" not in str(error):
                raise
        else:
            raise AssertionError("captured process outside cgroup was not detected")

        write_process(proc_root, 202, "22002", ["/usr/bin/python3", "changed-title.py"])
        try:
            check_stopped(
                evidence_path=evidence,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                port_probe=lambda _port: False,
            )
        except StoppedBoundaryError as error:
            if "still alive" not in str(error):
                raise
        else:
            raise AssertionError("same process with changed argv was misclassified as stopped")

        # PID reuse by another instance is not a false positive.
        write_process(proc_root, 202, "99999", ["/usr/bin/python3", "unrelated.py"])
        report = check_stopped(
            evidence_path=evidence,
            cgroup_root=cgroup_root,
            proc_root=proc_root,
            port_probe=lambda _port: False,
        )
        if report["ok"] is not True:
            raise AssertionError("reused numeric PID was misclassified as the captured process")

        try:
            check_stopped(
                evidence_path=evidence,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                port_probe=lambda port: port == 29876,
            )
        except StoppedBoundaryError as error:
            if "29876" not in str(error):
                raise
        else:
            raise AssertionError("live legacy listener was not detected")

        # The final timeout must preserve the latest failure, not an earlier
        # transient cgroup observation from the same convergence window.
        members.write_text("303\n", encoding="utf-8")
        listener_clock = FixtureClock()

        def progress_from_cgroup_to_listener(seconds: float) -> None:
            listener_clock.sleep(seconds)
            members.write_text("", encoding="utf-8")
            shutil.rmtree(proc_root / "303", ignore_errors=True)

        try:
            check_stopped(
                evidence_path=evidence,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                port_probe=lambda port: port == 29876,
                wait_timeout_seconds=0.03,
                poll_interval_seconds=0.02,
                monotonic=listener_clock.monotonic,
                sleeper=progress_from_cgroup_to_listener,
            )
        except StoppedBoundaryError as error:
            message = str(error)
            if (
                "did not converge after 2 attempts in 0.030s" not in message
                or "29876" not in message
                or "cgroup still has managed processes" in message
            ):
                raise
        else:
            raise AssertionError("live legacy listener did not time out")

    print(
        "legacy stopped-boundary self-test ok "
        "(clean, transient, persistent cgroup, escaped process, listener recall)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
