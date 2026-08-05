#!/usr/bin/env python3
"""Optimized-Python-safe tests for the trusted-loopback API preflight."""

from __future__ import annotations

import http.client
import http.server
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from check_coordinator_auth_boundary import (
    AuthBoundaryError,
    check_boundary,
    fetch_local_inventory,
    write_private_inventory,
)


SCRIPT = Path(__file__).with_name("check_coordinator_auth_boundary.py")
COORDINATOR = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "codex-dev-coordinator"
    / "scripts"
    / "dev_coordinator.py"
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def unused_loopback_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def run_checker(
    port: int,
    *,
    wait_seconds: float,
    request_timeout: float = 0.2,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--timeout",
            str(request_timeout),
            "--wait-seconds",
            str(wait_seconds),
            "--poll-interval-seconds",
            "0.05",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=max(8.0, wait_seconds + 5.0),
        check=False,
    )


def status_for_boundary(
    path: str,
    headers: dict[str, str] | None,
    *,
    health: int = 200,
    ready: int = 200,
) -> int:
    headers = headers or {}
    if path == "/healthz":
        return health
    if headers.get("Host") == "external.example":
        return 400
    if headers.get("Origin") == "https://external.example":
        return 403
    return ready


def main() -> int:
    calls: list[tuple[str, dict[str, str] | None]] = []

    def healthy(
        _host: str,
        _port: int,
        _timeout: float,
        path: str,
        headers: dict[str, str] | None,
    ) -> int:
        calls.append((path, headers))
        return status_for_boundary(path, headers)

    observed = check_boundary(status_fn=healthy)
    require(
        observed
        == {
            "local_health": 200,
            "local_ready": 200,
            "foreign_host_ready": 400,
            "foreign_origin_ready": 403,
        },
        "trusted-loopback status contract drifted",
    )
    require(len(calls) == 4, "boundary preflight did not issue exactly four probes")
    require(
        all("Authorization" not in (headers or {}) for _path, headers in calls),
        "boundary preflight sent an application credential",
    )

    # A Type=simple unit may exist briefly before its listener accepts. Retry
    # a transient transport failure, then prove the complete boundary again.
    delayed_calls = 0
    delayed_clock = [0.0]

    def delayed_start(
        host: str,
        port: int,
        timeout: float,
        path: str,
        headers: dict[str, str] | None,
    ) -> int:
        nonlocal delayed_calls
        delayed_calls += 1
        if delayed_calls == 1:
            raise ConnectionRefusedError(111, "Connection refused")
        return healthy(host, port, timeout, path, headers)

    delayed = check_boundary(
        status_fn=delayed_start,
        wait_seconds=1,
        poll_interval_seconds=0.1,
        monotonic_fn=lambda: delayed_clock[0],
        sleep_fn=lambda duration: delayed_clock.__setitem__(0, delayed_clock[0] + duration),
    )
    require(delayed == observed, "delayed coordinator did not converge")
    require(delayed_calls == 5, "startup refusal did not restart the full boundary probe")

    # The HTTP listener can exist before its local readiness backend opens.
    # Only exact local readiness 5xx with every locality guard intact retries.
    warming_clock = [0.0]
    warming_calls = 0
    warming_statuses = iter((503, 502, 200))

    def warming(
        _host: str,
        _port: int,
        _timeout: float,
        path: str,
        headers: dict[str, str] | None,
    ) -> int:
        nonlocal warming_calls
        warming_calls += 1
        if path == "/v1/ready" and not headers:
            return next(warming_statuses)
        return status_for_boundary(path, headers)

    warmed = check_boundary(
        status_fn=warming,
        wait_seconds=1,
        poll_interval_seconds=0.1,
        monotonic_fn=lambda: warming_clock[0],
        sleep_fn=lambda duration: warming_clock.__setitem__(0, warming_clock[0] + duration),
    )
    require(warmed == observed, "local readiness warmup did not converge")
    require(warming_calls == 12, "local readiness 5xx did not rerun every boundary probe")
    require(warming_clock[0] == 0.2, "local readiness retry ignored the poll interval")

    stalled_clock = [0.0]
    stalled_calls = 0

    def stalled(
        _host: str,
        _port: int,
        _timeout: float,
        path: str,
        headers: dict[str, str] | None,
    ) -> int:
        nonlocal stalled_calls
        stalled_calls += 1
        if path == "/v1/ready" and not headers:
            return 503
        return status_for_boundary(path, headers)

    try:
        check_boundary(
            status_fn=stalled,
            wait_seconds=0.25,
            poll_interval_seconds=0.1,
            monotonic_fn=lambda: stalled_clock[0],
            sleep_fn=lambda duration: stalled_clock.__setitem__(0, stalled_clock[0] + duration),
        )
    except AuthBoundaryError as error:
        require("readiness deadline" in str(error), "persistent readiness 5xx had the wrong failure")
        require("HTTP 503" in str(error), "persistent readiness 5xx lost status evidence")
        require(stalled_calls == 12, "persistent readiness exceeded its global retry bound")
    else:
        raise AssertionError("persistent readiness 5xx was accepted")

    for wrong_ready in (204, 403):
        mismatch_calls = 0
        mismatch_sleeps: list[float] = []

        def mismatch(
            _host: str,
            _port: int,
            _timeout: float,
            path: str,
            headers: dict[str, str] | None,
        ) -> int:
            nonlocal mismatch_calls
            mismatch_calls += 1
            if path == "/v1/ready" and not headers:
                return wrong_ready
            return status_for_boundary(path, headers)

        try:
            check_boundary(status_fn=mismatch, wait_seconds=1, sleep_fn=mismatch_sleeps.append)
        except AuthBoundaryError as error:
            require("boundary mismatch" in str(error), "readiness mismatch had the wrong failure")
            require(mismatch_calls == 4, "non-5xx readiness mismatch was retried")
            require(mismatch_sleeps == [], "readiness mismatch entered polling")
        else:
            raise AssertionError(f"local readiness HTTP {wrong_ready} was accepted")

    broken_calls = 0
    broken_sleeps: list[float] = []

    def broken_locality(
        _host: str,
        _port: int,
        _timeout: float,
        path: str,
        headers: dict[str, str] | None,
    ) -> int:
        nonlocal broken_calls
        broken_calls += 1
        if path == "/v1/ready" and not headers:
            return 503
        if (headers or {}).get("Host") == "external.example":
            return 200
        return status_for_boundary(path, headers)

    try:
        check_boundary(status_fn=broken_locality, wait_seconds=1, sleep_fn=broken_sleeps.append)
    except AuthBoundaryError as error:
        require("boundary mismatch" in str(error), "foreign-Host regression had the wrong failure")
        require(broken_calls == 4, "broken locality plus readiness 5xx was retried")
        require(broken_sleeps == [], "broken locality entered readiness polling")
    else:
        raise AssertionError("foreign Host access plus readiness 5xx was accepted")

    with tempfile.TemporaryDirectory(prefix="coordinator-loopback-boundary-") as raw:
        root = Path(raw).resolve(strict=True)
        real_port = unused_loopback_port()
        real_home = root / "real-coordinator-home"
        real_home.mkdir(mode=0o700)
        wrapper = (
            "import os,sys,time; time.sleep(float(sys.argv[1])); "
            "os.execv(sys.executable, [sys.executable, *sys.argv[2:]])"
        )
        environment = os.environ.copy()
        environment["CODEX_AGENT_COORDINATOR_HOME"] = str(real_home)
        environment["PATH"] = "/usr/bin:/bin"
        coordinator = subprocess.Popen(
            [
                sys.executable,
                "-c",
                wrapper,
                "0.3",
                str(COORDINATOR),
                "api",
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                str(real_port),
            ],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        started = time.monotonic()
        try:
            real_result = run_checker(real_port, wait_seconds=5, request_timeout=4)
            require(real_result.returncode == 0, f"real delayed coordinator was rejected: {real_result.stderr}")
            require(time.monotonic() - started >= 0.2, "delayed bind fixture did not exercise startup absence")
            require('"foreign_origin_ready": 403' in real_result.stdout, "real CLI did not prove locality")
        finally:
            coordinator.terminate()
            try:
                coordinator.wait(timeout=3)
            except subprocess.TimeoutExpired:
                coordinator.kill()
                coordinator.wait(timeout=3)

        absent_port = unused_loopback_port()
        absent_started = time.monotonic()
        absent_result = run_checker(absent_port, wait_seconds=0.25)
        require(absent_result.returncode == 1, "absent real listener was accepted")
        require("readiness deadline" in absent_result.stderr, "absent listener had the wrong failure")
        require(0.2 <= time.monotonic() - absent_started < 2, "absent listener deadline was not bounded")

        class WrongBoundary(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                body = b"{}\n"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format: str, *_args: object) -> None:
                return

        wrong_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), WrongBoundary)
        wrong_thread = threading.Thread(target=wrong_server.serve_forever, daemon=True)
        wrong_thread.start()
        wrong_started = time.monotonic()
        try:
            wrong_result = run_checker(int(wrong_server.server_address[1]), wait_seconds=2)
        finally:
            wrong_server.shutdown()
            wrong_server.server_close()
            wrong_thread.join(timeout=2)
        require(wrong_result.returncode == 1, "reachable foreign-Host leak was accepted")
        require("boundary mismatch" in wrong_result.stderr, "wrong real boundary had the wrong failure")
        require(time.monotonic() - wrong_started < 1.5, "semantic boundary failure was retried")

        inventory_calls = 0

        def inventory_fetch(_host: str, _port: int, _timeout: float) -> tuple[int, bytes]:
            nonlocal inventory_calls
            inventory_calls += 1
            return 200, b'{"servers":[],"leases":[],"port_assignments":[]}\n'

        inventory = fetch_local_inventory(fetch_fn=inventory_fetch)
        require(inventory["servers"] == [], "trusted-loopback inventory body was not preserved")
        require(inventory_calls == 1, "inventory fetch was not called exactly once")
        inventory_output = root / "post-cutover-inventory.json"
        write_private_inventory(inventory_output, inventory)
        require((inventory_output.stat().st_mode & 0o777) == 0o600, "inventory evidence is not mode 0600")
        try:
            write_private_inventory(inventory_output, inventory)
        except FileExistsError:
            pass
        else:
            raise AssertionError("inventory evidence writer overwrote an existing checkpoint")

        try:
            fetch_local_inventory(fetch_fn=lambda *_args: (200, b"[]"))
        except AuthBoundaryError as error:
            require("root must be an object" in str(error), "wrong inventory shape failure")
        else:
            raise AssertionError("non-object trusted-loopback inventory was accepted")

    corrupt_calls = 0

    def corrupt_protocol(*_args: object) -> int:
        nonlocal corrupt_calls
        corrupt_calls += 1
        if corrupt_calls == 1:
            raise http.client.BadStatusLine("not HTTP")
        return 200

    try:
        check_boundary(status_fn=corrupt_protocol)
    except AuthBoundaryError as error:
        require("non-transient" in str(error), "protocol corruption had the wrong failure")
        require(corrupt_calls == 1, "protocol corruption was retried")
    else:
        raise AssertionError("protocol-corrupt listener was accepted")

    slow_clock = [0.0]

    def slow_but_correct(
        _host: str,
        _port: int,
        _timeout: float,
        path: str,
        headers: dict[str, str] | None,
    ) -> int:
        slow_clock[0] += 0.26
        return status_for_boundary(path, headers)

    try:
        check_boundary(
            status_fn=slow_but_correct,
            wait_seconds=1,
            monotonic_fn=lambda: slow_clock[0],
            sleep_fn=lambda duration: slow_clock.__setitem__(0, slow_clock[0] + duration),
        )
    except AuthBoundaryError as error:
        require("readiness deadline" in str(error), "cross-request deadline had the wrong failure")
    else:
        raise AssertionError("four requests exceeded one readiness deadline")

    unavailable_clock = [0.0]
    unavailable_calls = 0

    def unavailable(*_args: object) -> int:
        nonlocal unavailable_calls
        unavailable_calls += 1
        raise ConnectionRefusedError(111, "Connection refused")

    try:
        check_boundary(
            status_fn=unavailable,
            wait_seconds=0.3,
            poll_interval_seconds=0.1,
            monotonic_fn=lambda: unavailable_clock[0],
            sleep_fn=lambda duration: unavailable_clock.__setitem__(0, unavailable_clock[0] + duration),
        )
    except AuthBoundaryError as error:
        require("readiness deadline" in str(error), "unreachable coordinator had the wrong failure")
        require(unavailable_calls >= 3, "readiness deadline was not exercised")
    else:
        raise AssertionError("permanently unreachable coordinator was accepted")

    try:
        check_boundary(host="0.0.0.0", status_fn=healthy)
    except AuthBoundaryError as error:
        require("restricted to loopback" in str(error), "non-loopback host had the wrong failure")
    else:
        raise AssertionError("non-loopback preflight host was accepted")

    print("coordinator trusted-loopback boundary self-test ok (works with Python optimization)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
