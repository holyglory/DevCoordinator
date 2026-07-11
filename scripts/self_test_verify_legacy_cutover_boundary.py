#!/usr/bin/env python3
"""Recall and false-positive tests for the legacy cutover boundary sampler."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from pathlib import Path

from linux_proc_identity import ProcIdentityError, read_stable_process_identity
from verify_legacy_cutover_boundary import (
    BoundaryError,
    BoundaryInterrupted,
    sample_boundary,
    verify_ledger_pair,
    wait_for_clean_boundary,
)


def write_process(
    proc_root: Path,
    pid: int,
    start_ticks: str,
    command: list[str],
    *,
    comm: str = "fixture worker ) helper",
) -> None:
    process = proc_root / str(pid)
    process.mkdir(parents=True, exist_ok=True)
    after_comm = ["S", *("0" for _ in range(18)), start_ticks]
    (process / "stat").write_text(
        f"{pid} ({comm}) {' '.join(after_comm)}\n",
        encoding="utf-8",
    )
    (process / "cmdline").write_bytes(b"\0".join(value.encode("utf-8") for value in command) + b"\0")


def fixture(root: Path) -> tuple[Path, Path, Path]:
    proc_root = root / "proc"
    cgroup_root = root / "cgroup"
    members = cgroup_root / "system.slice/devops-console.service/cgroup.procs"
    members.parent.mkdir(parents=True)
    members.write_text("202\n101\n202\n", encoding="utf-8")
    console = ["/usr/bin/node", "/srv/fixture/legacy/apps/DevOpsConsole/bin/devops-console.mjs"]
    coordinator = [
        "/usr/bin/python3",
        "/srv/fixture/legacy/skills/codex-dev-coordinator/scripts/dev_coordinator.py",
        "api",
        "serve",
    ]
    write_process(proc_root, 101, "11001", console)
    write_process(proc_root, 202, "22002", coordinator)
    evidence = root / "legacy-processes.json"
    evidence.write_text(
        json.dumps(
            {
                "cgroup": "/system.slice/devops-console.service",
                "console": {"pid": 101, "start_ticks": "11001", "command": console},
                "coordinator": {"pid": 202, "start_ticks": "22002", "command": coordinator},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    os.chmod(evidence, 0o600)
    return evidence, cgroup_root, proc_root


def assert_checksum(ledger: Path) -> None:
    expected, name = Path(f"{ledger}.sha256").read_text(encoding="ascii").strip().split("  ", 1)
    assert name == ledger.name
    assert hashlib.sha256(ledger.read_bytes()).hexdigest() == expected


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cutover-boundary-") as raw:
        root = Path(raw).resolve(strict=True)
        evidence, cgroup_root, proc_root = fixture(root)
        # Must reject PID reuse exactly between stat and cmdline, even when the
        # replacement retains the expected argv (the hybrid-identity race).
        race_process = proc_root / "202"
        original_stat = (race_process / "stat").read_text(encoding="utf-8")
        def reuse_between_reads() -> None:
            (race_process / "stat").write_text(
                original_stat.replace("22002", "99999"),
                encoding="utf-8",
            )
        try:
            read_stable_process_identity(race_process, after_first_stat=reuse_between_reads)
        except ProcIdentityError as error:
            assert "changed while reading" in str(error)
        else:
            raise AssertionError("hybrid stat/cmdline PID identity was accepted")
        (race_process / "stat").write_text(original_stat, encoding="utf-8")

        sleeps: list[float] = []
        ledger = root / "healthy.json"
        report = sample_boundary(
            evidence_path=evidence,
            ledger_path=ledger,
            cgroup_root=cgroup_root,
            proc_root=proc_root,
            sample_count=5,
            interval_seconds=1,
            sleep_fn=sleeps.append,
        )
        assert report["ok"] is True
        assert len(report["samples"]) == 5
        assert sleeps == [1, 1, 1, 1], "five samples must retain four one-second gaps"
        assert all(sample["members"] == [101, 202] for sample in report["samples"])
        assert_checksum(ledger)
        ledger.write_text(ledger.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")
        try:
            verify_ledger_pair(ledger)
        except BoundaryError as error:
            assert "checksum mismatch" in str(error)
        else:
            raise AssertionError("tampered ledger passed checksum verification")

        # Must catch a real-world child that arrives between clean samples and
        # retain enough command/start evidence to attribute it after refusal.
        write_process(proc_root, 303, "33003", ["/usr/bin/node", "worker.mjs", "--drain"])
        members = cgroup_root / "system.slice/devops-console.service/cgroup.procs"
        members.write_text("202\n101\n", encoding="utf-8")
        mismatch = root / "extra-process.json"
        def add_transient_child(_delay: float) -> None:
            members.write_text("101\n303\n202\n", encoding="utf-8")
        try:
            sample_boundary(
                evidence_path=evidence,
                ledger_path=mismatch,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                sample_count=5,
                interval_seconds=1,
                sleep_fn=add_transient_child,
            )
        except BoundaryError as error:
            assert "members differ" in str(error)
        else:
            raise AssertionError("additional cgroup member was not detected")
        mismatch_report = json.loads(mismatch.read_text(encoding="utf-8"))
        assert mismatch_report["ok"] is False
        assert [sample["members"] for sample in mismatch_report["samples"]] == [
            [101, 202],
            [101, 202, 303],
        ]
        extra = next(item for item in mismatch_report["samples"][1]["processes"] if item["pid"] == 303)
        assert extra["command"] == ["/usr/bin/node", "worker.mjs", "--drain"]
        assert extra["start_ticks"] == "33003"
        assert_checksum(mismatch)

        # A real inventory burst can contain clean internal gaps that are too
        # short for cutover, followed by one true inter-cycle window. Preserve
        # every extra-child transition, reset the candidate window, and return
        # only at the end of five continuously exact seconds.
        coordinator_command = json.loads(evidence.read_text(encoding="utf-8"))["coordinator"]["command"]
        write_process(proc_root, 202, "22002", coordinator_command)
        members.write_text("101\n202\n303\n", encoding="utf-8")
        clean_clock = [0.0]
        def burst_then_quiet(delay: float) -> None:
            clean_clock[0] += delay
            now = clean_clock[0]
            if now < 0.2 or 3.4 <= now < 3.6:
                members.write_text("101\n202\n303\n", encoding="utf-8")
            else:
                members.write_text("101\n202\n", encoding="utf-8")
        continuous = root / "continuous-clean.json"
        continuous_report = wait_for_clean_boundary(
            evidence_path=evidence,
            ledger_path=continuous,
            cgroup_root=cgroup_root,
            proc_root=proc_root,
            clean_window_seconds=5,
            wait_timeout_seconds=12,
            poll_interval_seconds=0.1,
            sleep_fn=burst_then_quiet,
            monotonic_fn=lambda: clean_clock[0],
        )
        assert continuous_report["ok"] is True
        assert clean_clock[0] >= 8.6, "the short internal clean gap was accepted as the cutover window"
        assert continuous_report["clean_window_resets"] == 1
        assert float(continuous_report["clean_window"]["duration_seconds"]) >= 5
        assert any(
            transition["members"] == [101, 202, 303]
            and next(item for item in transition["processes"] if item["pid"] == 303)["command"]
            == ["/usr/bin/node", "worker.mjs", "--drain"]
            for transition in continuous_report["membership_transitions"]
        ), "continuous ledger lost the attributed transient child"
        assert_checksum(continuous)

        # Periodic children that keep every exact interval below the required
        # duration must time out rather than being allowlisted or point-sampled
        # as clean.
        timeout_clock = [0.0]
        members.write_text("101\n202\n303\n", encoding="utf-8")
        def repeating_burst(delay: float) -> None:
            timeout_clock[0] += delay
            if timeout_clock[0] % 2.5 < 0.2:
                members.write_text("101\n202\n303\n", encoding="utf-8")
            else:
                members.write_text("101\n202\n", encoding="utf-8")
        timed_out = root / "continuous-timeout.json"
        try:
            wait_for_clean_boundary(
                evidence_path=evidence,
                ledger_path=timed_out,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                clean_window_seconds=5,
                wait_timeout_seconds=8,
                poll_interval_seconds=0.1,
                sleep_fn=repeating_burst,
                monotonic_fn=lambda: timeout_clock[0],
            )
        except BoundaryError as error:
            assert "no continuous 5-second exact cgroup window" in str(error)
        else:
            raise AssertionError("periodic transient children were accepted without a clean window")
        timeout_report = json.loads(timed_out.read_text(encoding="utf-8"))
        assert timeout_report["ok"] is False
        assert float(timeout_report["longest_clean_window_seconds"]) < 5
        assert any(item["members"] == [101, 202, 303] for item in timeout_report["membership_transitions"])
        assert_checksum(timed_out)

        # A delayed scheduler wakeup is an unobserved interval, not evidence
        # that the cgroup stayed exact. Reset the candidate window, retain the
        # gap in the ledger, and require a new full clean window afterward.
        members.write_text("101\n202\n", encoding="utf-8")
        stall_clock = [0.0]
        first_stall = [True]
        def scheduler_stall(delay: float) -> None:
            if first_stall[0]:
                first_stall[0] = False
                stall_clock[0] += 2.0
            else:
                stall_clock[0] += delay
        stalled = root / "continuous-scheduler-stall.json"
        stalled_report = wait_for_clean_boundary(
            evidence_path=evidence,
            ledger_path=stalled,
            cgroup_root=cgroup_root,
            proc_root=proc_root,
            clean_window_seconds=1,
            wait_timeout_seconds=5,
            poll_interval_seconds=0.1,
            max_observation_gap_seconds=0.5,
            sleep_fn=scheduler_stall,
            monotonic_fn=lambda: stall_clock[0],
        )
        assert stalled_report["ok"] is True
        assert stalled_report["sampling_gap_resets"] == 1
        assert stalled_report["clean_window_resets"] == 1
        assert stalled_report["sampling_gaps"][0]["gap_seconds"] == 2.0
        assert float(stalled_report["clean_window"]["started_after_seconds"]) >= 2.0
        assert float(stalled_report["clean_window"]["completed_after_seconds"]) >= 3.0
        assert stalled_report["clean_window"]["observations"] > 2
        assert_checksum(stalled)

        # The deadline is inclusive only when a complete observed-clean window
        # ends exactly at it. Crossing the deadline by even one observation
        # must time out instead of converting the overrun into success.
        members.write_text("101\n202\n303\n", encoding="utf-8")
        deadline_clock = [0.0]
        def reach_exact_deadline(delay: float) -> None:
            deadline_clock[0] += delay
            members.write_text("101\n202\n", encoding="utf-8")
        exact_deadline = root / "continuous-exact-deadline.json"
        exact_deadline_report = wait_for_clean_boundary(
            evidence_path=evidence,
            ledger_path=exact_deadline,
            cgroup_root=cgroup_root,
            proc_root=proc_root,
            clean_window_seconds=1.5,
            wait_timeout_seconds=2,
            poll_interval_seconds=0.5,
            max_observation_gap_seconds=0.75,
            sleep_fn=reach_exact_deadline,
            monotonic_fn=lambda: deadline_clock[0],
        )
        assert exact_deadline_report["status"] == "succeeded"
        assert float(exact_deadline_report["clean_window"]["completed_after_seconds"]) == 2.0
        assert_checksum(exact_deadline)

        members.write_text("101\n202\n303\n", encoding="utf-8")
        overrun_clock = [0.0]
        overrun_sleeps = [0]
        def cross_deadline(delay: float) -> None:
            overrun_sleeps[0] += 1
            overrun_clock[0] += 0.51 if overrun_sleeps[0] == 4 else delay
            members.write_text("101\n202\n", encoding="utf-8")
        overrun = root / "continuous-deadline-overrun.json"
        try:
            wait_for_clean_boundary(
                evidence_path=evidence,
                ledger_path=overrun,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                clean_window_seconds=1.5,
                wait_timeout_seconds=2,
                poll_interval_seconds=0.5,
                max_observation_gap_seconds=0.75,
                sleep_fn=cross_deadline,
                monotonic_fn=lambda: overrun_clock[0],
            )
        except BoundaryError as error:
            assert "no continuous 1.5-second exact cgroup window" in str(error)
        else:
            raise AssertionError("a clean window ending after its deadline was accepted")
        overrun_report = json.loads(overrun.read_text(encoding="utf-8"))
        assert overrun_report["status"] == "timed_out"
        assert overrun_report["code"] == "clean_window_timeout"
        assert overrun_report["ok"] is False
        assert float(overrun_report["last_observation"]["scan_completed_after_seconds"]) > 2.0
        assert_checksum(overrun)

        # NaN and infinity must be rejected at every duration boundary. They
        # must never reach arithmetic that could make the comparison fail open.
        valid_timing = {
            "clean_window_seconds": 1.0,
            "wait_timeout_seconds": 2.0,
            "poll_interval_seconds": 0.1,
            "max_observation_gap_seconds": 0.5,
        }
        invalid_timing = [
            ("clean-nan", "clean_window_seconds", float("nan")),
            ("clean-inf", "clean_window_seconds", float("inf")),
            ("timeout-nan", "wait_timeout_seconds", float("nan")),
            ("timeout-inf", "wait_timeout_seconds", float("inf")),
            ("poll-nan", "poll_interval_seconds", float("nan")),
            ("poll-inf", "poll_interval_seconds", float("inf")),
            ("gap-nan", "max_observation_gap_seconds", float("nan")),
            ("gap-inf", "max_observation_gap_seconds", float("inf")),
        ]
        members.write_text("101\n202\n", encoding="utf-8")
        for label, field, invalid_value in invalid_timing:
            timing = dict(valid_timing)
            timing[field] = invalid_value
            invalid_ledger = root / f"continuous-invalid-{label}.json"
            try:
                wait_for_clean_boundary(
                    evidence_path=evidence,
                    ledger_path=invalid_ledger,
                    cgroup_root=cgroup_root,
                    proc_root=proc_root,
                    **timing,
                )
            except BoundaryError:
                pass
            else:
                raise AssertionError(f"non-finite timing was accepted: {label}")
            assert not invalid_ledger.exists()

        for label, non_finite_clock in (("nan", float("nan")), ("inf", float("inf"))):
            invalid_clock_ledger = root / f"continuous-invalid-start-clock-{label}.json"
            try:
                wait_for_clean_boundary(
                    evidence_path=evidence,
                    ledger_path=invalid_clock_ledger,
                    cgroup_root=cgroup_root,
                    proc_root=proc_root,
                    monotonic_fn=lambda value=non_finite_clock: value,
                    **valid_timing,
                )
            except BoundaryError as error:
                assert "non-finite start time" in str(error)
            else:
                raise AssertionError(f"non-finite start clock was accepted: {label}")
            assert not invalid_clock_ledger.exists()

        for label, non_finite_clock in (("nan", float("nan")), ("inf", float("inf"))):
            clock_values = iter((0.0, 0.0, non_finite_clock))
            invalid_runtime_clock = root / f"continuous-invalid-runtime-clock-{label}.json"
            try:
                wait_for_clean_boundary(
                    evidence_path=evidence,
                    ledger_path=invalid_runtime_clock,
                    cgroup_root=cgroup_root,
                    proc_root=proc_root,
                    monotonic_fn=lambda values=clock_values: next(values),
                    **valid_timing,
                )
            except BoundaryError as error:
                assert "non-finite observation time" in str(error)
            else:
                raise AssertionError(f"non-finite runtime clock was accepted: {label}")
            invalid_clock_report = json.loads(
                invalid_runtime_clock.read_text(encoding="utf-8")
            )
            assert invalid_clock_report["status"] == "unsafe"
            assert invalid_clock_report["code"] == "captured_boundary_unsafe"
            assert_checksum(invalid_runtime_clock)

        # A child arriving between the first and second cgroup.procs read is a
        # real scan race. The observation must carry both membership images and
        # reset the window even if the child is gone at the next poll.
        members.write_text("101\n202\n", encoding="utf-8")
        scan_race_clock = [0.0]
        inject_scan_child = [True]
        def race_between_membership_reads() -> None:
            if inject_scan_child[0]:
                inject_scan_child[0] = False
                members.write_text("101\n202\n303\n", encoding="utf-8")
        def end_scan_race(delay: float) -> None:
            scan_race_clock[0] += delay
            members.write_text("202\n101\n", encoding="utf-8")
        scan_race = root / "continuous-membership-scan-race.json"
        scan_race_report = wait_for_clean_boundary(
            evidence_path=evidence,
            ledger_path=scan_race,
            cgroup_root=cgroup_root,
            proc_root=proc_root,
            clean_window_seconds=0.5,
            wait_timeout_seconds=2,
            poll_interval_seconds=0.1,
            max_observation_gap_seconds=0.25,
            sleep_fn=end_scan_race,
            monotonic_fn=lambda: scan_race_clock[0],
            after_first_members_read=race_between_membership_reads,
        )
        raced_transition = next(
            item
            for item in scan_race_report["membership_transitions"]
            if item.get("members_first_read") == [101, 202]
        )
        assert raced_transition["members"] == [101, 202, 303]
        assert any("changed during observation" in problem for problem in raced_transition["problems"])
        assert any(item["pid"] == 303 for item in raced_transition["processes"])
        assert float(scan_race_report["clean_window"]["started_after_seconds"]) >= 0.1
        assert_checksum(scan_race)

        # A captured PID can be reused after the first identity pass while the
        # cgroup membership itself remains exact. Inject that replacement on
        # the observation that would otherwise complete the clean window: the
        # second identity pass must make the terminal decision unsafe, retain
        # both identities, and never emit success-shaped evidence.
        members.write_text("101\n202\n", encoding="utf-8")
        write_process(proc_root, 202, "22002", coordinator_command)
        final_race_clock = [0.0]
        final_race_injected = [False]
        def reuse_expected_pid_on_final_observation() -> None:
            if final_race_clock[0] >= 0.3 and not final_race_injected[0]:
                final_race_injected[0] = True
                stat = proc_root / "202/stat"
                stat.write_text(
                    stat.read_text(encoding="utf-8").replace("22002", "99999"),
                    encoding="utf-8",
                )
        final_identity_race = root / "continuous-final-identity-race.json"
        try:
            wait_for_clean_boundary(
                evidence_path=evidence,
                ledger_path=final_identity_race,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                clean_window_seconds=0.3,
                wait_timeout_seconds=2,
                poll_interval_seconds=0.1,
                max_observation_gap_seconds=0.25,
                sleep_fn=lambda delay: final_race_clock.__setitem__(
                    0, final_race_clock[0] + delay
                ),
                monotonic_fn=lambda: final_race_clock[0],
                after_first_identity_read=reuse_expected_pid_on_final_observation,
            )
        except BoundaryError as error:
            assert "process identity changed during observation: 202" in str(error)
        else:
            raise AssertionError("final-observation PID reuse was certified clean")
        assert final_race_injected[0] is True
        final_race_report = json.loads(final_identity_race.read_text(encoding="utf-8"))
        assert final_race_report["ok"] is False
        assert final_race_report["status"] == "unsafe"
        assert final_race_report["code"] == "captured_boundary_unsafe"
        assert "clean_window" not in final_race_report
        final_race_observation = final_race_report["last_observation"]
        assert final_race_observation["members"] == [101, 202]
        assert final_race_observation["members_first_read"] == [101, 202]
        assert next(
            item
            for item in final_race_observation["processes_first_read"]
            if item["pid"] == 202
        )["start_ticks"] == "22002"
        assert next(
            item for item in final_race_observation["processes"] if item["pid"] == 202
        )["start_ticks"] == "99999"
        assert_checksum(final_identity_race)
        write_process(proc_root, 202, "22002", coordinator_command)

        # Losing either captured process is not a transient child burst. Fail
        # immediately in wait mode and preserve the terminal unsafe decision.
        members.write_text("101\n", encoding="utf-8")
        loss_clock = [0.0]
        loss_sleeps: list[float] = []
        lost_expected = root / "continuous-expected-process-loss.json"
        try:
            wait_for_clean_boundary(
                evidence_path=evidence,
                ledger_path=lost_expected,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                clean_window_seconds=1,
                wait_timeout_seconds=2,
                poll_interval_seconds=0.1,
                max_observation_gap_seconds=0.5,
                sleep_fn=loss_sleeps.append,
                monotonic_fn=lambda: loss_clock[0],
            )
        except BoundaryError as error:
            assert "captured legacy PIDs left the cgroup" in str(error)
        else:
            raise AssertionError("wait mode treated an expected-process loss as transient")
        loss_report = json.loads(lost_expected.read_text(encoding="utf-8"))
        assert loss_report["status"] == "unsafe"
        assert loss_report["code"] == "captured_boundary_unsafe"
        assert loss_sleeps == []
        assert loss_report["observation_count"] == 1
        assert_checksum(lost_expected)

        # A handled signal raised while sleeping must terminally commit an
        # interrupted decision and its checksum, never leave success-shaped
        # evidence or a running ledger.
        members.write_text("101\n202\n", encoding="utf-8")
        interrupted_clock = [0.0]
        interrupted = root / "continuous-interrupted.json"
        def interrupt_sleep(_delay: float) -> None:
            raise BoundaryInterrupted("fixture SIGTERM")
        try:
            wait_for_clean_boundary(
                evidence_path=evidence,
                ledger_path=interrupted,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                clean_window_seconds=1,
                wait_timeout_seconds=2,
                poll_interval_seconds=0.1,
                max_observation_gap_seconds=0.5,
                sleep_fn=interrupt_sleep,
                monotonic_fn=lambda: interrupted_clock[0],
            )
        except BoundaryInterrupted as error:
            assert "SIGTERM" in str(error)
        else:
            raise AssertionError("handled boundary interruption did not propagate")
        interrupted_report = json.loads(interrupted.read_text(encoding="utf-8"))
        assert interrupted_report["ok"] is False
        assert interrupted_report["status"] == "interrupted"
        assert interrupted_report["code"] == "observation_interrupted"
        assert interrupted_report["completed_at"] is not None
        assert interrupted_report["failure"] == ["fixture SIGTERM"]
        assert_checksum(interrupted)

        # Exercise the deployed CLI/signal surface, not only an injected Python
        # exception. Wait for a durable, checksum-valid running ledger before
        # sending the real process SIGTERM, then require a terminal interrupted
        # decision and exit status rather than a signal-shaped partial write.
        members.write_text("101\n202\n", encoding="utf-8")
        subprocess_ledger = root / "continuous-subprocess-sigterm.json"
        verifier_cli = Path(__file__).with_name(
            "verify_legacy_cutover_boundary.py"
        ).resolve(strict=True)
        process = subprocess.Popen(
            [
                sys.executable,
                str(verifier_cli),
                "--evidence",
                str(evidence),
                "--ledger",
                str(subprocess_ledger),
                "--continuous-clean-seconds",
                "30",
                "--wait-timeout-seconds",
                "60",
                "--poll-interval-seconds",
                "0.05",
                "--max-observation-gap-seconds",
                "0.25",
                "--cgroup-root",
                str(cgroup_root),
                "--proc-root",
                str(proc_root),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        subprocess_stdout = ""
        subprocess_stderr = ""
        try:
            ready_deadline = time.monotonic() + 5
            running_seen = False
            last_poll_error: Exception | None = None
            while time.monotonic() < ready_deadline:
                if process.poll() is not None:
                    break
                if subprocess_ledger.exists() and Path(f"{subprocess_ledger}.sha256").exists():
                    try:
                        verify_ledger_pair(subprocess_ledger)
                        running_report = json.loads(
                            subprocess_ledger.read_text(encoding="utf-8")
                        )
                        if running_report.get("status") == "running":
                            running_seen = True
                            break
                    except (BoundaryError, OSError, json.JSONDecodeError) as error:
                        # Ledger and checksum are replaced separately but
                        # atomically; retry during that bounded update window.
                        last_poll_error = error
                time.sleep(0.01)
            if not running_seen:
                detail = f"; last ledger error: {last_poll_error}" if last_poll_error else ""
                raise AssertionError(
                    "verifier CLI did not publish a checksum-valid running ledger "
                    f"before the readiness deadline{detail}"
                )
            process.send_signal(signal.SIGTERM)
            try:
                subprocess_stdout, subprocess_stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired as error:
                raise AssertionError("verifier CLI did not terminate after SIGTERM") from error
            assert process.returncode == 1
            assert subprocess_stdout == ""
            assert "interrupted by SIGTERM" in subprocess_stderr
            assert "legacy cutover boundary failed" in subprocess_stderr
        finally:
            if process.poll() is None:
                process.kill()
                subprocess_stdout, subprocess_stderr = process.communicate(timeout=5)
        verify_ledger_pair(subprocess_ledger)
        subprocess_report = json.loads(subprocess_ledger.read_text(encoding="utf-8"))
        assert subprocess_report["ok"] is False
        assert subprocess_report["status"] == "interrupted"
        assert subprocess_report["code"] == "observation_interrupted"
        assert subprocess_report["completed_at"] is not None
        assert any("SIGTERM" in item for item in subprocess_report["failure"])
        assert_checksum(subprocess_ledger)

        # Ordering and duplicate lines in cgroup.procs are semantically
        # irrelevant. Keep this common kernel/read-race representation as a
        # false-positive guard for an otherwise exact observed window.
        members.write_text("202\n101\n202\n101\n", encoding="utf-8")
        duplicate_clock = [0.0]
        reordered = root / "continuous-reordered-duplicate-members.json"
        reordered_report = wait_for_clean_boundary(
            evidence_path=evidence,
            ledger_path=reordered,
            cgroup_root=cgroup_root,
            proc_root=proc_root,
            clean_window_seconds=0.3,
            wait_timeout_seconds=2,
            poll_interval_seconds=0.1,
            max_observation_gap_seconds=0.25,
            sleep_fn=lambda delay: duplicate_clock.__setitem__(0, duplicate_clock[0] + delay),
            monotonic_fn=lambda: duplicate_clock[0],
        )
        assert reordered_report["ok"] is True
        assert reordered_report["clean_window_resets"] == 0
        assert reordered_report["sampling_gap_resets"] == 0
        assert reordered_report["membership_transitions"][0]["members"] == [101, 202]
        assert reordered_report["membership_transitions"][0]["problems"] == []
        assert_checksum(reordered)

        # A one-second poll cannot silently derive a five-second maximum gap
        # for a five-second clean window. Both the derived and explicit equal
        # boundary must be rejected because neither can prove bounded coverage.
        for label, explicit_gap in (("derived", None), ("explicit", 5.0)):
            loophole = root / f"continuous-max-gap-loophole-{label}.json"
            try:
                wait_for_clean_boundary(
                    evidence_path=evidence,
                    ledger_path=loophole,
                    cgroup_root=cgroup_root,
                    proc_root=proc_root,
                    clean_window_seconds=5,
                    wait_timeout_seconds=6,
                    poll_interval_seconds=1,
                    max_observation_gap_seconds=explicit_gap,
                )
            except BoundaryError as error:
                assert "maximum observation gap" in str(error)
            else:
                raise AssertionError(f"unsafe max-gap contract was accepted: {label}")
            assert not loophole.exists()

        # Continuous waiting must still fail immediately on captured PID reuse;
        # that fatal identity change is not a transient to wait through.
        members.write_text("101\n202\n", encoding="utf-8")
        (proc_root / "202/stat").write_text(
            (proc_root / "202/stat").read_text(encoding="utf-8").replace("22002", "99999"),
            encoding="utf-8",
        )
        fatal_clock = [0.0]
        fatal_continuous = root / "continuous-pid-reuse.json"
        try:
            wait_for_clean_boundary(
                evidence_path=evidence,
                ledger_path=fatal_continuous,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                clean_window_seconds=1,
                wait_timeout_seconds=2,
                poll_interval_seconds=0.1,
                sleep_fn=lambda delay: fatal_clock.__setitem__(0, fatal_clock[0] + delay),
                monotonic_fn=lambda: fatal_clock[0],
            )
        except BoundaryError as error:
            assert "start time changed" in str(error)
        else:
            raise AssertionError("continuous window waited through captured PID reuse")
        assert fatal_clock[0] == 0
        assert_checksum(fatal_continuous)
        write_process(proc_root, 202, "22002", coordinator_command)

        # Exact membership with changed argv must also fail on the next sample.
        members.write_text("101\n202\n", encoding="utf-8")
        write_process(proc_root, 202, "22002", coordinator_command)
        changed_argv = root / "changed-argv.json"
        def change_argv(_delay: float) -> None:
            (proc_root / "202/cmdline").write_bytes(b"/usr/bin/python3\0unrelated.py\0")
        try:
            sample_boundary(
                evidence_path=evidence,
                ledger_path=changed_argv,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                sample_count=2,
                interval_seconds=1,
                sleep_fn=change_argv,
            )
        except BoundaryError as error:
            assert "command changed" in str(error)
        else:
            raise AssertionError("changed argv was not detected")
        assert_checksum(changed_argv)

        # Must catch PID reuse even when cgroup membership itself still looks
        # exact and Linux comm contains spaces (the field-shift regression).
        members.write_text("202\n101\n", encoding="utf-8")
        (proc_root / "202/stat").write_text(
            (proc_root / "202/stat").read_text(encoding="utf-8").replace("22002", "99999"),
            encoding="utf-8",
        )
        reused = root / "pid-reuse.json"
        try:
            sample_boundary(
                evidence_path=evidence,
                ledger_path=reused,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                sample_count=1,
                interval_seconds=0,
            )
        except BoundaryError as error:
            assert "start time changed" in str(error)
        else:
            raise AssertionError("PID reuse was not detected")
        assert_checksum(reused)

        # Missing /proc evidence for an expected member must fail and be kept.
        write_process(proc_root, 202, "22002", coordinator_command)
        stat_path = proc_root / "202/stat"
        saved_stat = stat_path.read_bytes()
        stat_path.unlink()
        unavailable = root / "unavailable-process.json"
        try:
            sample_boundary(
                evidence_path=evidence,
                ledger_path=unavailable,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                sample_count=1,
                interval_seconds=0,
            )
        except BoundaryError as error:
            assert "PID is unavailable" in str(error)
        else:
            raise AssertionError("missing expected /proc evidence was not detected")
        unavailable_report = json.loads(unavailable.read_text(encoding="utf-8"))
        assert next(item for item in unavailable_report["samples"][0]["processes"] if item["pid"] == 202)["status"] == "unavailable"
        stat_path.write_bytes(saved_stat)

        # One PID cannot satisfy both the Console and coordinator roles.
        duplicate_roles = root / "duplicate-roles.json"
        duplicate = json.loads(evidence.read_text(encoding="utf-8"))
        duplicate["coordinator"] = dict(duplicate["console"])
        duplicate_roles.write_text(json.dumps(duplicate), encoding="utf-8")
        os.chmod(duplicate_roles, 0o600)
        try:
            sample_boundary(
                evidence_path=duplicate_roles,
                ledger_path=root / "duplicate-roles-ledger.json",
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                sample_count=1,
                interval_seconds=0,
            )
        except BoundaryError as error:
            assert "must be distinct" in str(error)
        else:
            raise AssertionError("duplicate role PIDs were accepted")

        evidence_link = root / "legacy-processes-link.json"
        evidence_link.symlink_to(evidence)
        try:
            sample_boundary(
                evidence_path=evidence_link,
                ledger_path=root / "symlink-evidence-ledger.json",
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                sample_count=1,
                interval_seconds=0,
            )
        except BoundaryError as error:
            assert "direct regular file" in str(error)
        else:
            raise AssertionError("symlinked process evidence was accepted")

        # A symlinked ledger parent must never redirect private evidence.
        real_parent = root / "real-ledgers"
        real_parent.mkdir(mode=0o700)
        linked_parent = root / "linked-ledgers"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        try:
            sample_boundary(
                evidence_path=evidence,
                ledger_path=linked_parent / "redirected.json",
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                sample_count=1,
                interval_seconds=0,
            )
        except BoundaryError as error:
            assert "contains a symlink" in str(error)
        else:
            raise AssertionError("symlinked ledger parent was accepted")

        # Atomic O_EXCL reservation allows exactly one concurrent writer.
        members.write_text("202\n101\n202\n", encoding="utf-8")
        write_process(proc_root, 202, "22002", coordinator_command)
        concurrent = root / "concurrent.json"
        barrier = Barrier(2)
        def contender() -> str:
            barrier.wait()
            try:
                sample_boundary(
                    evidence_path=evidence,
                    ledger_path=concurrent,
                    cgroup_root=cgroup_root,
                    proc_root=proc_root,
                    sample_count=1,
                    interval_seconds=0,
                )
                return "won"
            except BoundaryError as error:
                assert "already exists" in str(error)
                return "refused"
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = sorted(pool.map(lambda _value: contender(), range(2)))
        assert outcomes == ["refused", "won"]
        assert_checksum(concurrent)

    print(
        "legacy cutover boundary self-test ok "
        "(continuous-window, identity, transient, path, and concurrency recall)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
