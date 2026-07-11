#!/usr/bin/env python3
"""Optimized-Python-safe tests for the coordinator auth boundary preflight."""

from __future__ import annotations

import http.client
import http.server
import os
import signal
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
    fetch_authenticated_inventory,
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
    token_file: Path,
    port: int,
    *,
    wait_seconds: float,
    request_timeout: float = 0.2,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--token-file",
            str(token_file),
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


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="coordinator-auth-boundary-") as raw:
        root = Path(raw).resolve(strict=True)
        token_file = root / "api-token"
        token_file.write_text("fixture-secret-token\n", encoding="utf-8")
        os.chmod(token_file, 0o600)
        calls: list[tuple[str, str | None]] = []

        def healthy(_host: str, _port: int, _timeout: float, path: str, bearer: str | None) -> int:
            calls.append((path, bearer))
            if path == "/healthz" and bearer is None:
                return 200
            if path == "/v1/inventory" and bearer is None:
                return 401
            if path == "/v1/inventory" and bearer == "fixture-secret-token":
                return 200
            return 500

        observed = check_boundary(token_file=token_file, status_fn=healthy)
        require(observed["anonymous_inventory"] == 401, "anonymous inventory was not proved closed")
        require(calls[-1] == ("/v1/inventory", "fixture-secret-token"), "token was not server-side only")

        # Reproduce the production Type=simple startup race: systemd reports
        # the unit active before the Python listener accepts its first
        # connection. A transient refusal must be retried, while the complete
        # anonymous/authenticated contract is still checked after readiness.
        delayed_calls = 0
        clock = [0.0]

        def delayed_start(_host: str, _port: int, _timeout: float, path: str, bearer: str | None) -> int:
            nonlocal delayed_calls
            delayed_calls += 1
            if delayed_calls == 1:
                raise ConnectionRefusedError(111, "Connection refused")
            return healthy(_host, _port, _timeout, path, bearer)

        delayed = check_boundary(
            token_file=token_file,
            status_fn=delayed_start,
            wait_seconds=1,
            poll_interval_seconds=0.1,
            monotonic_fn=lambda: clock[0],
            sleep_fn=lambda duration: clock.__setitem__(0, clock[0] + duration),
        )
        require(delayed == {"anonymous_health": 200, "anonymous_inventory": 401, "authenticated_inventory": 200}, "delayed coordinator did not converge")
        require(delayed_calls == 4, "startup refusal did not restart the full boundary probe")

        # Real-socket/CLI recall fixture for the production failure: invoke the
        # actual coordinator only after a 300 ms delay, while the checker is
        # already receiving kernel-level ECONNREFUSED on the final port.
        real_port = unused_loopback_port()
        real_home = root / "real-coordinator-home"
        real_home.mkdir(mode=0o700)
        real_token = root / "real-api-token"
        real_token.write_text("real-fixture-secret-token-value-0000000001\n", encoding="utf-8")
        real_token.chmod(0o600)
        wrapper = (
            "import os,sys,time; time.sleep(float(sys.argv[1])); "
            "os.execv(sys.executable, [sys.executable, *sys.argv[2:]])"
        )
        environment = os.environ.copy()
        environment["CODEX_AGENT_COORDINATOR_HOME"] = str(real_home)
        # Keep the readiness fixture independent of a developer's Docker
        # daemon latency; Docker inventory is not the behavior under test.
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
                "--token-file",
                str(real_token),
            ],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        started = time.monotonic()
        try:
            real_result = run_checker(real_token, real_port, wait_seconds=5, request_timeout=4)
            require(real_result.returncode == 0, f"real delayed coordinator was rejected: {real_result.stderr}")
            require(time.monotonic() - started >= 0.2, "real delayed-bind fixture did not exercise startup absence")
            require('"anonymous_inventory": 401' in real_result.stdout, "real CLI did not prove auth closure")
        finally:
            coordinator.terminate()
            try:
                coordinator.wait(timeout=3)
            except subprocess.TimeoutExpired:
                coordinator.kill()
                coordinator.wait(timeout=3)

        # A real absent listener remains bounded and fails closed.
        absent_port = unused_loopback_port()
        absent_started = time.monotonic()
        absent_result = run_checker(token_file, absent_port, wait_seconds=0.25)
        absent_elapsed = time.monotonic() - absent_started
        require(absent_result.returncode == 1, "absent real listener was accepted")
        require("readiness deadline" in absent_result.stderr, "absent listener had the wrong CLI failure")
        require(0.2 <= absent_elapsed < 2, "absent listener deadline was not bounded")

        # A reachable real HTTP endpoint with the wrong anonymous contract is
        # unsafe, not unready, and must fail immediately without retrying.
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
            wrong_result = run_checker(token_file, int(wrong_server.server_address[1]), wait_seconds=2)
        finally:
            wrong_server.shutdown()
            wrong_server.server_close()
            wrong_thread.join(timeout=2)
        require(wrong_result.returncode == 1, "reachable anonymous inventory leak was accepted")
        require("boundary mismatch" in wrong_result.stderr, "wrong real boundary had the wrong failure")
        require(time.monotonic() - wrong_started < 1.5, "semantic boundary failure was retried")

        # Protocol corruption is likewise reachable-but-invalid and must not
        # be reclassified as a transient startup race.
        corrupt_calls = 0

        def corrupt_protocol(*_args: object) -> int:
            nonlocal corrupt_calls
            corrupt_calls += 1
            if corrupt_calls == 1:
                raise http.client.BadStatusLine("not HTTP")
            return 200

        try:
            check_boundary(token_file=token_file, status_fn=corrupt_protocol)
        except AuthBoundaryError as error:
            require("non-transient" in str(error), "protocol corruption had the wrong failure")
            require(corrupt_calls == 1, "protocol corruption was retried")
        else:
            raise AssertionError("protocol-corrupt listener was accepted")

        # The deadline covers all three semantic requests, not three separate
        # timeout budgets.
        slow_clock = [0.0]

        def slow_but_correct(_host: str, _port: int, _timeout: float, path: str, bearer: str | None) -> int:
            # Every request begins inside the one-second budget, but the final
            # correct response completes just after it. Success must still be
            # rejected rather than treating the request-start time as enough.
            slow_clock[0] += 0.34
            return 200 if path == "/healthz" or bearer else 401

        try:
            check_boundary(
                token_file=token_file,
                status_fn=slow_but_correct,
                wait_seconds=1,
                monotonic_fn=lambda: slow_clock[0],
                sleep_fn=lambda duration: slow_clock.__setitem__(0, slow_clock[0] + duration),
            )
        except AuthBoundaryError as error:
            require("readiness deadline" in str(error), "cross-request deadline had the wrong failure")
        else:
            raise AssertionError("three requests exceeded one readiness deadline")

        # A genuinely absent final token is also a fresh-host startup race.
        # The coordinator publishes it atomically, so only ENOENT is retried.
        missing_token = root / "late-api-token"
        missing_clock = [0.0]

        def publish_token(duration: float) -> None:
            missing_clock[0] += duration
            missing_token.write_text("late-fixture-secret-token-value-0001\n", encoding="utf-8")
            missing_token.chmod(0o600)

        after_token_publish = check_boundary(
            token_file=missing_token,
            status_fn=lambda _host, _port, _timeout, path, bearer: (
                200 if path == "/healthz" or bearer == "late-fixture-secret-token-value-0001" else 401
            ),
            wait_seconds=1,
            poll_interval_seconds=0.1,
            monotonic_fn=lambda: missing_clock[0],
            sleep_fn=publish_token,
        )
        require(after_token_publish["authenticated_inventory"] == 200, "late token was not retried")

        # A permanently unreachable listener must still fail closed at a
        # bounded deadline and must not leak the private bearer value.
        unavailable_clock = [0.0]
        unavailable_calls = 0

        def unavailable(*_args: object) -> int:
            nonlocal unavailable_calls
            unavailable_calls += 1
            raise ConnectionRefusedError(111, "Connection refused")

        try:
            check_boundary(
                token_file=token_file,
                status_fn=unavailable,
                wait_seconds=0.3,
                poll_interval_seconds=0.1,
                monotonic_fn=lambda: unavailable_clock[0],
                sleep_fn=lambda duration: unavailable_clock.__setitem__(0, unavailable_clock[0] + duration),
            )
        except AuthBoundaryError as error:
            require("readiness deadline" in str(error), "unreachable coordinator had the wrong failure")
            require("fixture-secret-token" not in str(error), "token leaked in readiness failure")
            require(unavailable_calls >= 3, "readiness deadline was not exercised")
        else:
            raise AssertionError("permanently unreachable coordinator was accepted")

        fetch_calls: list[str] = []

        def inventory_fetch(_host: str, _port: int, _timeout: float, bearer: str) -> tuple[int, bytes]:
            fetch_calls.append(bearer)
            return 200, b'{"servers":[],"leases":[],"port_assignments":[]}\n'

        inventory = fetch_authenticated_inventory(token_file=token_file, fetch_fn=inventory_fetch)
        require(inventory["servers"] == [], "authenticated inventory body was not preserved")
        require(fetch_calls == ["fixture-secret-token"], "inventory fetch did not use the private token once")
        inventory_output = root / "post-cutover-inventory.json"
        write_private_inventory(inventory_output, inventory)
        require((inventory_output.stat().st_mode & 0o777) == 0o600, "inventory evidence is not mode 0600")
        require("fixture-secret-token" not in inventory_output.read_text(encoding="utf-8"), "token leaked to inventory evidence")
        try:
            write_private_inventory(inventory_output, inventory)
        except FileExistsError:
            pass
        else:
            raise AssertionError("inventory evidence writer overwrote an existing checkpoint")

        try:
            fetch_authenticated_inventory(
                token_file=token_file,
                fetch_fn=lambda *_args: (200, b'[]'),
            )
        except AuthBoundaryError as error:
            require("root must be an object" in str(error), "wrong inventory shape failure")
        else:
            raise AssertionError("non-object authenticated inventory was accepted")

        # Must catch a coordinator that accidentally leaves /v1 anonymous.
        def anonymous_leak(_host: str, _port: int, _timeout: float, path: str, bearer: str | None) -> int:
            if path == "/healthz":
                return 200
            if path == "/v1/inventory" and bearer is None:
                return 200
            return 200
        try:
            check_boundary(token_file=token_file, status_fn=anonymous_leak)
        except AuthBoundaryError as error:
            require("boundary mismatch" in str(error), "wrong auth failure classification")
            require("fixture-secret-token" not in str(error), "token leaked in auth failure")
        else:
            raise AssertionError("anonymous /v1 access was not detected")

        fifo = root / "token-fifo"
        os.mkfifo(fifo, 0o600)
        previous_handler = signal.signal(
            signal.SIGALRM,
            lambda _signum, _frame: (_ for _ in ()).throw(TimeoutError("FIFO open blocked")),
        )
        signal.alarm(2)
        try:
            try:
                check_boundary(token_file=fifo, status_fn=healthy)
            except AuthBoundaryError as error:
                require("regular file" in str(error), "FIFO had the wrong credential failure")
            else:
                raise AssertionError("FIFO credential path was accepted")
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous_handler)

    print("coordinator auth boundary self-test ok (works with Python optimization)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
