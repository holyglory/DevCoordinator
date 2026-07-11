#!/usr/bin/env python3
"""Recall tests for the post-stop legacy cgroup/process/listener boundary."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

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
        report = check_stopped(
            evidence_path=evidence,
            cgroup_root=cgroup_root,
            proc_root=proc_root,
            port_probe=lambda _port: False,
        )
        if report["ok"] is not True:
            raise AssertionError("empty stopped boundary did not pass")

        # Must catch an unattributed process with no listener that survives in
        # the old cgroup—the exact rollback gap found during review.
        write_process(proc_root, 303, "33003", ["/usr/bin/node", "worker.mjs"])
        members.write_text("303\n", encoding="utf-8")
        try:
            check_stopped(
                evidence_path=evidence,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
                port_probe=lambda _port: False,
            )
        except StoppedBoundaryError as error:
            if "cgroup still has managed processes" not in str(error):
                raise
        else:
            raise AssertionError("surviving cgroup process was not detected")

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

    print("legacy stopped-boundary self-test ok (cgroup, escaped process, listener recall)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
