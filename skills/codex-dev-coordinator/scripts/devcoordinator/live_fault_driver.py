#!/usr/bin/env python3
"""Trusted fixed-behavior driver for live fault-isolation acceptance.

The driver accepts only one enumerated scenario.  Bounds are compiled into the
immutable release; repository content cannot supply a command, port, process
count, payload size, or duration.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import threading
import time
from urllib.request import urlopen


SCENARIOS = (
    "bounded_fork_pressure",
    "cgroup_oom",
    "crash_loop_breaker",
    "malformed_runner_output",
    "slow_project_upstream",
    "bounded_request_burst",
)


def _events_path() -> Path:
    raw = os.environ.get("DEVCOORDINATOR_TEST_EVENTS")
    if not raw or not Path(raw).is_absolute():
        raise RuntimeError("Coordinator reporter path is unavailable")
    return Path(raw)


def _event(scenario: str, *, status: str = "passed", name: str | None = None) -> None:
    payload = {
        "case_id": "fault-acceptance:" + scenario,
        "name": name or scenario.replace("_", " "),
        "status": status,
        "duration_seconds": 0,
    }
    _events_path().write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _bounded_fork_pressure() -> None:
    children: list[int] = []
    blocked = False
    try:
        for _ in range(256):
            try:
                child = os.fork()
            except OSError:
                blocked = True
                break
            if child == 0:
                time.sleep(0.25)
                os._exit(0)
            children.append(child)
    finally:
        for child in children:
            try:
                os.waitpid(child, 0)
            except ChildProcessError:
                pass
    if not blocked:
        _event("bounded_fork_pressure", status="failed", name="PID clamp did not stop fork pressure")
        raise SystemExit(41)
    _event("bounded_fork_pressure", name="PID clamp contained fork pressure")


def _cgroup_oom() -> None:
    # The unit's fixed 96 MiB MemoryMax is intentionally lower than this
    # bounded allocation.  Holding distinct mutable pages prevents sharing.
    pages: list[bytearray] = []
    for _ in range(192):
        value = bytearray(1024 * 1024)
        value[0] = 1
        value[-1] = 1
        pages.append(value)
    _event("cgroup_oom", status="failed", name="MemoryMax did not classify the OOM")
    raise SystemExit(42)


def _crash_loop_breaker() -> None:
    crashes = 0
    breaker_limit = 5
    for _ in range(breaker_limit):
        child = os.fork()
        if child == 0:
            os._exit(73)
        _, status = os.waitpid(child, 0)
        if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 73:
            crashes += 1
    if crashes != breaker_limit:
        _event("crash_loop_breaker", status="failed", name="Crash outcomes were not exact")
        raise SystemExit(43)
    _event("crash_loop_breaker", name="Crash loop stopped at the fixed breaker limit")


def _malformed_runner_output() -> None:
    _events_path().write_bytes(b'{"case_id":"broken"\nnot-json\n')


class _Handler(BaseHTTPRequestHandler):
    delay = 0.0

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        time.sleep(self.delay)
        self.send_response(200)
        self.send_header("content-length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, _format: str, *_args: object) -> None:
        return


def _serve_requests(*, count: int, delay: float) -> None:
    class Handler(_Handler):
        pass

    Handler.delay = delay
    server = HTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/"
        for _ in range(count):
            with urlopen(url, timeout=3) as response:
                if response.status != 200 or response.read(2) != b"ok":
                    raise RuntimeError("loopback fault upstream returned invalid evidence")
    finally:
        server.shutdown()
        worker.join(timeout=2)
        server.server_close()
    if worker.is_alive():
        raise RuntimeError("loopback fault upstream did not stop")


def _slow_project_upstream() -> None:
    _serve_requests(count=1, delay=0.5)
    _event("slow_project_upstream", name="Slow project upstream remained isolated")


def _bounded_request_burst() -> None:
    _serve_requests(count=32, delay=0.0)
    _event("bounded_request_burst", name="Bounded request burst completed")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=SCENARIOS, required=True)
    arguments = parser.parse_args(argv)
    operation = os.environ.get("DEVCOORDINATOR_FAULT_OPERATION_ID", "")
    resource = os.environ.get("DEVCOORDINATOR_FAULT_RESOURCE_ID", "")
    if not operation or not resource or any(character in operation + resource for character in "\x00\r\n"):
        raise RuntimeError("fault acceptance identity is unavailable")
    actions = {
        "bounded_fork_pressure": _bounded_fork_pressure,
        "cgroup_oom": _cgroup_oom,
        "crash_loop_breaker": _crash_loop_breaker,
        "malformed_runner_output": _malformed_runner_output,
        "slow_project_upstream": _slow_project_upstream,
        "bounded_request_burst": _bounded_request_burst,
    }
    actions[arguments.scenario]()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
