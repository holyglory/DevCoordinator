#!/usr/bin/env python3
"""Identity-reuse and bounded-escalation tests for guarded legacy termination."""

from __future__ import annotations

import json
import os
import signal
import tempfile
from pathlib import Path

from terminate_captured_legacy_process import TerminationError, terminate_captured


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
    with tempfile.TemporaryDirectory(prefix="guarded-legacy-stop-") as raw:
        root = Path(raw).resolve(strict=True)
        proc_root = root / "proc"
        evidence = root / "legacy-processes.json"
        command = ["/usr/bin/python3", "/srv/fixture/dev_coordinator.py", "api", "serve"]
        evidence.write_text(
            json.dumps({"coordinator": {"pid": 202, "start_ticks": "22002", "command": command}}),
            encoding="utf-8",
        )
        os.chmod(evidence, 0o600)

        # Exact instance exits on TERM; KILL must not be sent.
        write_process(proc_root, 202, "22002", command)
        signals: list[int] = []
        closed: list[int] = []
        def exits_on_term(_handle: int, sent: int) -> None:
            signals.append(sent)
        report = terminate_captured(
            evidence_path=evidence,
            role="coordinator",
            proc_root=proc_root,
            open_handle_fn=lambda pid: pid + 1000,
            send_handle_fn=exits_on_term,
            wait_handle_fn=lambda _handle, _timeout: True,
            close_handle_fn=closed.append,
        )
        assert report["result"] == "terminated"
        assert signals == [signal.SIGTERM]
        assert closed == [1202]

        # Must refuse a PID reused by a different command without signaling it.
        write_process(proc_root, 202, "22002", ["/usr/bin/python3", "unrelated.py"])
        signals.clear()
        try:
            terminate_captured(
                evidence_path=evidence,
                role="coordinator",
                proc_root=proc_root,
                open_handle_fn=lambda pid: pid + 1000,
                send_handle_fn=lambda _handle, sent: signals.append(sent),
                wait_handle_fn=lambda _handle, _timeout: False,
                close_handle_fn=lambda _handle: None,
                timeout_seconds=0,
            )
        except TerminationError as error:
            assert "reused or changed identity" in str(error)
        else:
            raise AssertionError("changed command was not refused")
        assert signals == []

        # A stubborn exact instance receives bounded TERM then KILL.
        write_process(proc_root, 202, "22002", command)
        signals.clear()
        waits = iter((False, True))
        report = terminate_captured(
            evidence_path=evidence,
            role="coordinator",
            proc_root=proc_root,
            timeout_seconds=0.5,
            open_handle_fn=lambda pid: pid + 1000,
            send_handle_fn=lambda _handle, sent: signals.append(sent),
            wait_handle_fn=lambda _handle, _timeout: next(waits),
            close_handle_fn=lambda _handle: None,
        )
        assert report["result"] == "killed-after-timeout"
        assert signals == [signal.SIGTERM, signal.SIGKILL]

        signals.clear()
        try:
            terminate_captured(
                evidence_path=evidence,
                role="coordinator",
                proc_root=proc_root,
                timeout_seconds=0,
                open_handle_fn=lambda pid: pid + 1000,
                send_handle_fn=lambda _handle, sent: signals.append(sent),
                wait_handle_fn=lambda _handle, _timeout: False,
                close_handle_fn=lambda _handle: None,
            )
        except TerminationError as error:
            assert "did not exit after pidfd SIGKILL" in str(error)
        else:
            raise AssertionError("an unconfirmed SIGKILL was reported as stopped")
        assert signals == [signal.SIGTERM, signal.SIGKILL]

        # Must catch reuse between the first identity read and pidfd binding;
        # the race fixture mutates /proc from inside the handle-open step.
        signals.clear()
        write_process(proc_root, 202, "22002", command)
        def reuse_during_open(pid: int) -> int:
            write_process(proc_root, pid, "99999", ["/usr/bin/python3", "unrelated.py"])
            return pid + 1000
        try:
            terminate_captured(
                evidence_path=evidence,
                role="coordinator",
                proc_root=proc_root,
                open_handle_fn=reuse_during_open,
                send_handle_fn=lambda _handle, sent: signals.append(sent),
                wait_handle_fn=lambda _handle, _timeout: False,
                close_handle_fn=lambda _handle: None,
            )
        except TerminationError as error:
            assert "binding pidfd" in str(error)
        else:
            raise AssertionError("PID reuse during handle binding was not refused")
        assert signals == []

    print("guarded legacy termination self-test ok (identity refusal and bounded escalation)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
