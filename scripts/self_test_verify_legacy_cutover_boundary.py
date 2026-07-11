#!/usr/bin/env python3
"""Recall and false-positive tests for the legacy cutover boundary sampler."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from pathlib import Path

from linux_proc_identity import ProcIdentityError, read_stable_process_identity
from verify_legacy_cutover_boundary import BoundaryError, sample_boundary, verify_ledger_pair


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

        # Exact membership with changed argv must also fail on the next sample.
        coordinator_command = json.loads(evidence.read_text(encoding="utf-8"))["coordinator"]["command"]
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

    print("legacy cutover boundary self-test ok (identity, transient, path, and concurrency recall)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
