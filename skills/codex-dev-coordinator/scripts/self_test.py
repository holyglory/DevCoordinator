#!/usr/bin/env python3
"""Self-tests for codex-dev-coordinator."""

from __future__ import annotations

import ast
import copy
import http.client
import http.server
import socketserver
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from shutil import rmtree, which as _which


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "dev_coordinator.py"
SKILL = ROOT / "SKILL.md"

# macOS CI runners black-hole reverse DNS lookups, which hangs
# `python3 -m http.server` inside HTTPServer.server_bind (socket.getfqdn)
# between bind() and listen() — the process sits alive with a bound,
# never-listening socket. This fixture serves the same directory listing
# through plain socketserver.TCPServer, which never resolves names.
HTTP_FIXTURE_CODE = (
    "import socketserver, http.server, sys; "
    "socketserver.TCPServer.allow_reuse_address = True; "
    'socketserver.TCPServer(("127.0.0.1", int(sys.argv[1])), '
    "http.server.SimpleHTTPRequestHandler).serve_forever()"
)


class _FastBindThreadingHTTPServer(http.server.ThreadingHTTPServer):
    # Same macOS getfqdn hazard as HTTP_FIXTURE_CODE above, for in-process
    # fixtures: skip HTTPServer.server_bind's reverse-DNS lookup.
    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)


_ISSUED_PORTS: set[int] = set()


def free_port() -> int:
    # Never hand out a port an earlier fixture already used: durable port
    # assignments persist in the shared test home for the whole run, so a
    # kernel-recycled ephemeral port could otherwise collide with an earlier
    # block's pin and flake a later single-port fixture.
    for _ in range(100):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
        if port not in _ISSUED_PORTS:
            _ISSUED_PORTS.add(port)
            return port
    raise AssertionError("could not allocate a fresh fixture port after 100 attempts")


def run(args: list[str], *, env: dict[str, str]) -> dict:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=20,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"command failed: {' '.join(args)}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return json.loads(result.stdout)


def run_fail(args: list[str], *, env: dict[str, str], expected: str) -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=20,
    )
    if result.returncode == 0:
        raise AssertionError(f"command unexpectedly succeeded: {' '.join(args)}\nstdout:\n{result.stdout}")
    haystack = f"{result.stdout}\n{result.stderr}"
    if expected not in haystack:
        raise AssertionError(f"failure did not mention {expected!r}: {' '.join(args)}\n{haystack}")


def request_http(
    port: int,
    method: str,
    path: str,
    *,
    payload: dict | None = None,
    token: str | None = None,
    headers: dict[str, str] | None = None,
    expected_status: int = 200,
) -> tuple[dict[str, str], bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    body = json.dumps(payload) if payload is not None else None
    request_headers = dict(headers or {})
    if payload is not None:
        request_headers.setdefault("Content-Type", "application/json")
    if token:
        request_headers["Authorization"] = f"Bearer {token}"
    conn.request(method, path, body=body, headers=request_headers)
    response = conn.getresponse()
    response_headers = {name.lower(): value for name, value in response.getheaders()}
    response_body = response.read()
    conn.close()
    if response.status != expected_status:
        raise AssertionError(
            f"{method} {path} returned {response.status}, expected {expected_status}: "
            f"{response_body.decode('utf-8', errors='replace')}"
        )
    return response_headers, response_body


def request_json(
    port: int,
    method: str,
    path: str,
    *,
    payload: dict | None = None,
    token: str | None = None,
    headers: dict[str, str] | None = None,
    expected_status: int = 200,
) -> dict | list:
    _, response_body = request_http(
        port,
        method,
        path,
        payload=payload,
        token=token,
        headers=headers,
        expected_status=expected_status,
    )
    data = json.loads(response_body.decode("utf-8"))
    return data


def post_json(port: int, path: str, payload: dict, *, token: str | None = None) -> dict:
    result = request_json(port, "POST", path, payload=payload, token=token)
    check(isinstance(result, dict), f"POST {path} should return an object")
    return result


def get_json(port: int, path: str, *, token: str | None = None) -> dict | list:
    return request_json(port, "GET", path, token=token)


def wait_for_api(process: subprocess.Popen[str], port: int) -> None:
    # Cold CI runners need real headroom for interpreter start + state load.
    deadline = time.time() + 30
    while time.time() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"api exited early: {process.returncode}")
        try:
            get_json(port, "/healthz")
            return
        except OSError:
            time.sleep(0.1)
    raise AssertionError("api did not become ready")


def wait_for_http(port: int) -> None:
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            conn.request("GET", "/")
            conn.getresponse().read()
            conn.close()
            return
        except OSError:
            time.sleep(0.1)
    raise AssertionError(f"HTTP fixture on {port} did not become ready")


def wait_for_tcp(port: int) -> None:
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise AssertionError(f"TCP fixture on {port} did not become ready")


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def literal_raw_http_server_argv_lines(source: str) -> list[int]:
    findings: list[int] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, (ast.List, ast.Tuple)):
            continue
        values = [
            element.value if isinstance(element, ast.Constant) and isinstance(element.value, str) else None
            for element in node.elts
        ]
        if any(
            values[index] == "-m" and values[index + 1] == "http.server"
            for index in range(len(values) - 1)
        ):
            findings.append(int(node.lineno))
    return sorted(set(findings))


def check_http_fixture_policy() -> None:
    realistic_raw_fixture = "argv = ['python3', '-m', 'http.server', '{port}', '--bind', '127.0.0.1']\n"
    safe_fast_bind_fixture = (
        "argv = ['python3', '-c', "
        "'import socketserver, http.server; socketserver.TCPServer((\\\"127.0.0.1\\\", 0), "
        "http.server.SimpleHTTPRequestHandler).serve_forever()']\n"
    )
    check(
        literal_raw_http_server_argv_lines(realistic_raw_fixture) == [1],
        "raw http.server argv detector missed a realistic macOS-hanging fixture",
    )
    check(
        literal_raw_http_server_argv_lines(safe_fast_bind_fixture) == [],
        "raw http.server argv detector rejected the fast-bind socketserver control",
    )
    current_findings = literal_raw_http_server_argv_lines(Path(__file__).read_text(encoding="utf-8"))
    check(
        current_findings == [],
        f"bare python -m http.server fixtures are forbidden; use HTTP_FIXTURE_CODE: {current_findings}",
    )


def _load_module():
    import importlib.util

    spec = importlib.util.spec_from_file_location("dev_coordinator_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    # Python 3.9 dataclasses resolve postponed annotations through
    # sys.modules while the class decorator runs.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def check_atomic_write_cleanup_preserves_primary(module: object, tmp: Path) -> None:
    target = tmp / "atomic-write-cleanup" / "state.json"
    target.parent.mkdir()
    target.write_text("original state\n", encoding="utf-8")
    target.chmod(0o600)
    original_replace = module.os.replace
    path_type = type(target)
    original_unlink = path_type.unlink
    publication_failure = "simulated private-state write failure"
    cleanup_failure = "simulated private-state temp cleanup failure"

    def fail_state_replace(source: object, destination: object) -> None:
        if Path(destination) == target:
            raise OSError(publication_failure)
        original_replace(source, destination)

    def fail_temp_unlink(path: Path, *args: object, **kwargs: object) -> None:
        candidate = Path(path)
        if candidate.parent == target.parent and candidate.name.startswith(f".{target.name}.tmp-"):
            raise OSError(cleanup_failure)
        original_unlink(path, *args, **kwargs)

    module.os.replace = fail_state_replace
    path_type.unlink = fail_temp_unlink
    try:
        try:
            module.atomic_write_private(target, "replacement state\n")
        except module.PrivateStateWriteCleanupError as error:
            check(
                publication_failure in str(error) and cleanup_failure in str(error),
                f"top-level private-state error did not retain both failures: {error!r}",
            )
            check(
                isinstance(error.__cause__, OSError) and publication_failure in str(error.__cause__),
                f"private-state write failure was not retained as the cause: {error.__cause__!r}",
            )
            serialized = json.dumps(module.coordinator_exception_payload(error), sort_keys=True)
            check(
                publication_failure in serialized and cleanup_failure in serialized,
                f"coordinator JSON surface omitted write or cleanup evidence: {serialized}",
            )
        else:
            raise AssertionError("fault-injected private-state write unexpectedly succeeded")
    finally:
        module.os.replace = original_replace
        path_type.unlink = original_unlink

    check(
        target.read_text(encoding="utf-8") == "original state\n",
        "failed private-state write changed the existing state",
    )
    leftovers = sorted(target.parent.glob(f".{target.name}.tmp-*"))
    check(len(leftovers) == 1, "failed temp cleanup did not retain exact recovery evidence")
    original_unlink(leftovers[0])


def check_listener_and_health_helpers() -> None:
    """Directly exercise the two host-portability paths that a CLI register
    depends on: resolving the PID that owns a listening port, and probing an
    HTTPS liveness endpoint on loopback.

    These guard against regressions to (a) the pure-stdlib /proc PID resolver
    that lets `server register`/adoption work on Linux hosts without `lsof`,
    and (b) the loopback-relaxed TLS verification that lets an HTTPS dev server
    (serving a public-hostname cert that can never match 127.0.0.1) report
    healthy.
    """
    module = _load_module()

    # (a) PID resolution for a known listener, via whatever path the host
    # supports (pure-stdlib /proc on Linux; lsof elsewhere).
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listen_port = int(listener.getsockname()[1])
        resolved = module.listening_pid_for_port(listen_port)
        check(
            resolved == os.getpid(),
            f"listening_pid_for_port({listen_port}) should resolve this process "
            f"pid {os.getpid()} without lsof, got {resolved}",
        )
        check(
            module.listening_pid_for_port(free_port()) is None,
            "listening_pid_for_port should return None for a port with no listener",
        )
    finally:
        listener.close()

    # (b) HTTPS loopback health check against a self-signed cert.
    import ssl as _ssl

    if not _which("openssl"):
        return  # cert generation needs openssl; skip gracefully where absent
    cert_dir = Path(tempfile.mkdtemp(prefix="coordinator-health-tls-")).resolve(strict=True)
    try:
        cert = cert_dir / "cert.pem"
        key = cert_dir / "key.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "1",
                "-subj", "/CN=console.example",
                "-addext", "subjectAltName=DNS:console.example",
            ],
            check=True,
            capture_output=True,
            timeout=20,
        )
        httpd = _FastBindThreadingHTTPServer(("127.0.0.1", 0), _HealthzHandler)
        context = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        tls_port = int(httpd.server_address[1])
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            result = module.http_health(f"https://127.0.0.1:{tls_port}/healthz")
            check(
                result.get("ok") is True and result.get("status") == 200,
                f"http_health should accept a self-signed HTTPS loopback endpoint, got {result}",
            )
        finally:
            httpd.shutdown()
            thread.join(timeout=5)
    finally:
        rmtree(cert_dir, ignore_errors=True)


def check_registration_pid_guards() -> None:
    """Prove explicit registration binds the exact process, project and port."""

    module = _load_module()
    root = Path(tempfile.mkdtemp(prefix="coordinator-register-pid-")).resolve(strict=True)
    project = root / "project"
    foreign_project = root / "foreign"
    project.mkdir()
    foreign_project.mkdir()
    processes: list[subprocess.Popen[str]] = []

    # Cross-version guard: Python 3.9 Path.resolve() can turn an unreadable
    # procfs symlink into a pseudo-path containing the readlink error. Direct
    # proc observation must instead preserve permission denial as unknown.
    original_readlink = module.os.readlink
    synthetic_proc_cwd = "/proc/424242/cwd"
    try:
        def denied_proc_readlink(path: object) -> str:
            if str(path) == synthetic_proc_cwd:
                raise PermissionError("denied")
            return original_readlink(path)

        module.os.readlink = denied_proc_readlink
        check(
            module.process_cwd_from_proc(424242) is None,
            "unreadable proc cwd must not become a synthetic foreign path",
        )
        module.os.readlink = lambda path: (
            str(project) if str(path) == synthetic_proc_cwd else original_readlink(path)
        )
        check(
            module.process_cwd_from_proc(424242) == str(project.resolve()),
            "readable proc cwd should resolve to the concrete project path",
        )
    finally:
        module.os.readlink = original_readlink

    def spawn_listener(cwd: Path, *, nondumpable: bool = False) -> tuple[subprocess.Popen[str], int]:
        port = free_port()
        code = HTTP_FIXTURE_CODE
        if nondumpable:
            code = (
                "import ctypes\n"
                "libc=ctypes.CDLL(None,use_errno=True)\n"
                "assert libc.prctl(4,0,0,0,0)==0\n"
                + HTTP_FIXTURE_CODE
            )
        process = subprocess.Popen(
            [sys.executable, "-c", code, str(port)],
            cwd=cwd,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        processes.append(process)
        wait_for_http(port)
        return process, port

    def must_reject(pid: int, port: int, expected: str | None, *, host: str = "127.0.0.1") -> None:
        try:
            module.registration_pid_identity(pid=pid, host=host, port=port, project=str(project))
        except RuntimeError as exc:
            if expected is not None:
                check(expected in str(exc), f"registration PID rejection should mention {expected!r}: {exc}")
            return
        raise AssertionError(f"registration accepted invalid PID {pid} for port {port}: {expected}")

    try:
        listener, port = spawn_listener(project)
        identity = module.registration_pid_identity(
            pid=listener.pid, host="127.0.0.1", port=port, project=str(project)
        )
        check(
            identity["pid"] == listener.pid and identity["port"] == port and identity["cwd"] == str(project),
            f"exact owning PID should validate: {identity}",
        )
        resolved_pid, resolved_identity = module.resolve_registration_pid(
            {}, host="127.0.0.1", port=port, project=str(project)
        )
        check(
            resolved_pid == listener.pid and (resolved_identity or {}).get("pid") == listener.pid,
            "normal omitted-PID adoption should retain verified listener discovery",
        )

        assignment_key = module.server_key(str(project), "lease-owner-change")
        owner_state = module.default_state()
        owner_state["port_assignments"][assignment_key] = {
            "key": assignment_key,
            "project": str(project),
            "name": "lease-owner-change",
            "port": port,
        }
        owner_state["servers"]["owner-change-server"] = {
            "id": "owner-change-server",
            "key": assignment_key,
            "project": str(project),
            "name": "lease-owner-change",
            "port": port,
            "pid": os.getpid(),
            "status": "running",
        }
        owner_state["leases"]["old-owner-lease"] = {
            "id": "old-owner-lease",
            "project": str(project),
            "port": port,
            "purpose": "server:lease-owner-change",
            "server_id": "owner-change-server",
            "owner_pid": os.getpid(),
            "status": "active",
        }
        replacement = module.lease_existing_server_port(
            owner_state,
            agent="registration-test",
            project=str(project),
            port=port,
            purpose="server:lease-owner-change",
            server_id="owner-change-server",
            owner_pid=listener.pid,
            assignment_key=assignment_key,
        )
        check(
            replacement["id"] != "old-owner-lease"
            and replacement["owner_pid"] == listener.pid
            and replacement["assignment_key"] == assignment_key
            and "old-owner-lease" not in owner_state["leases"],
            f"changed listener owner must receive a replacement lease: {replacement}",
        )

        idle = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            cwd=project,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        processes.append(idle)
        must_reject(idle.pid, port, "does not own")
        must_reject(listener.pid, port, None, host="127.0.0.2")

        foreign, foreign_port = spawn_listener(foreign_project)
        must_reject(foreign.pid, foreign_port, "outside registered project")
        must_reject(
            listener.pid,
            free_port(),
            "no TCP LISTEN socket" if sys.platform.startswith("linux") else "does not own",
        )

        dead = subprocess.Popen(
            [sys.executable, "-c", "pass"],
            cwd=project,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        dead.wait(timeout=5)
        must_reject(dead.pid, port, "is not alive")

        empty_pid, empty_identity = module.resolve_registration_pid(
            {}, host="127.0.0.1", port=free_port(), project=str(project)
        )
        check(empty_pid is None and empty_identity is None, "an intentionally stopped endpoint may remain unleased")

        if sys.platform.startswith("linux"):
            opaque, opaque_port = spawn_listener(project, nondumpable=True)
            must_reject(opaque.pid, opaque_port, "working directory is not observable")
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
        rmtree(root, ignore_errors=True)
    check(True, "loopback HTTPS health checks should pass against self-signed certs")


def check_port_relocation_guards(module: object, tmp: Path, base_env: dict[str, str]) -> None:
    """Prove exact, atomic checkout ownership transfer and listener recall."""

    root = tmp / "port-relocation"
    old_project = root / "old-checkout"
    new_project = root / "new-checkout"
    foreign_project = root / "foreign-checkout"
    for project in (old_project, new_project, foreign_project):
        project.mkdir(parents=True)

    name = "devops-console"
    lease_id = "relocation-lease-exact"
    server_id = "relocation-server-exact"

    def fixture(port: int) -> dict:
        state = module.default_state()
        old_key = module.server_key(str(old_project), name)
        state["port_assignments"] = {
            old_key: {
                "key": old_key,
                "project": str(old_project.resolve()),
                "name": name,
                "port": port,
                "agent": "old-agent",
                "source": "server_register",
                "created_at": module.iso_timestamp(),
                "updated_at": module.iso_timestamp(),
            }
        }
        state["servers"] = {
            server_id: {
                "id": server_id,
                "key": old_key,
                "project": str(old_project.resolve()),
                "name": name,
                "cwd": str(old_project / "apps" / "DevOpsConsole"),
                "port": port,
                "pid": 999_999_999,
                "lease_id": lease_id,
                "status": "stopped",
                "cmd": f"node {old_project}/apps/DevOpsConsole/bin/devops-console.mjs",
                "cmd_template": f"node {old_project}/apps/DevOpsConsole/bin/devops-console.mjs",
                "health": {"ok": False, "pid_alive": False},
                "created_at": module.iso_timestamp(),
                "updated_at": module.iso_timestamp(),
                "stopped_at": module.iso_timestamp(),
                "stopped_ts": module.now(),
            }
        }
        state["leases"] = {
            lease_id: {
                "id": lease_id,
                "agent": "devops-console",
                "project": str(old_project.resolve()),
                "port": port,
                "status": "active",
                "purpose": f"server:{name}",
                "server_id": server_id,
                "created_at": module.iso_timestamp(),
                "expires_at": module.now() + 3600,
            }
        }
        return state

    def prepare(case: str, state: dict) -> tuple[dict[str, str], Path]:
        home = root / f"state-{case}"
        home.mkdir(mode=0o700)
        state_file = home / "state.json"
        state_file.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        state_file.chmod(0o600)
        case_env = base_env.copy()
        case_env["CODEX_AGENT_COORDINATOR_HOME"] = str(home)
        return case_env, state_file

    def relocate_args(port: int, *, expected_lease: str = lease_id) -> list[str]:
        return [
            "port",
            "relocate",
            "--agent",
            "cutover-agent",
            "--old-project",
            str(old_project),
            "--new-project",
            str(new_project),
            "--name",
            name,
            "--port",
            str(port),
            "--lease-id",
            expected_lease,
        ]

    happy_port = free_port()
    happy_env, happy_file = prepare("happy", fixture(happy_port))
    result = run(relocate_args(happy_port), env=happy_env)
    happy_state = json.loads(happy_file.read_text(encoding="utf-8"))
    new_key = module.server_key(str(new_project), name)
    check(result.get("ok") is True, f"port relocation should succeed: {result}")
    check(
        list(happy_state["port_assignments"]) == [new_key]
        and happy_state["port_assignments"][new_key]["port"] == happy_port,
        f"relocation should move exactly one durable assignment: {happy_state['port_assignments']}",
    )
    migrated = happy_state["servers"][server_id]
    check(
        migrated["project"] == str(new_project.resolve())
        and migrated["key"] == new_key
        and migrated["cwd"] == str(new_project / "apps" / "DevOpsConsole")
        and migrated["status"] == "stopped"
        and migrated["pid"] is None
        and migrated["lease_id"] is None
        and migrated["cmd"] is None,
        f"relocation should preserve one reusable stopped record without stale process paths: {migrated}",
    )
    check(
        not any(
            item.get("status") == "active" and item.get("project") == str(old_project.resolve())
            for item in happy_state["leases"].values()
        ),
        "relocation must leave no active lease pointing at the retired checkout",
    )
    check(
        happy_state["history"][-1]["type"] == "port.relocated"
        and happy_state["history"][-1]["payload"]["agent"] == "cutover-agent",
        "relocation should retain attributed history",
    )
    relocated_listener = subprocess.Popen(
        [sys.executable, "-c", HTTP_FIXTURE_CODE, str(happy_port)],
        cwd=new_project,
        env=happy_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_for_http(happy_port)
        registered = run(
            [
                "server",
                "register",
                "--agent",
                "devops-console",
                "--project",
                str(new_project),
                "--name",
                name,
                "--cwd",
                str(new_project),
                "--port",
                str(happy_port),
                "--url",
                f"http://127.0.0.1:{happy_port}",
                "--health-url",
                f"http://127.0.0.1:{happy_port}/",
            ],
            env=happy_env,
        )
        check(
            registered.get("id") == server_id and registered.get("project") == str(new_project.resolve()),
            f"new listener registration should reuse the relocated server id: {registered}",
        )
        registered_state = json.loads(happy_file.read_text(encoding="utf-8"))
        current_server = registered_state["servers"][server_id]
        active_leases = [
            lease
            for lease in registered_state["leases"].values()
            if lease.get("status") == "active"
            and lease.get("project") == str(new_project.resolve())
            and int(lease.get("port") or 0) == happy_port
        ]
        check(
            current_server.get("status") == "running"
            and (current_server.get("health") or {}).get("ok") is True
            and current_server.get("pid") == relocated_listener.pid,
            f"relocated server must become the exact healthy listener: {current_server}",
        )
        check(len(active_leases) == 1, f"registration must create one replacement lease: {active_leases}")
        replacement_lease = active_leases[0]
        check(
            replacement_lease.get("id") != lease_id
            and current_server.get("lease_id") == replacement_lease.get("id")
            and replacement_lease.get("server_id") == server_id
            and replacement_lease.get("owner_pid") == relocated_listener.pid
            and replacement_lease.get("purpose") == f"server:{name}"
            and replacement_lease.get("assignment_key") == new_key,
            f"replacement lease must link server, PID, purpose, and assignment in both directions: {replacement_lease}",
        )
        check(
            not any(
                assignment.get("project") == str(old_project.resolve())
                for assignment in registered_state["port_assignments"].values()
            )
            and not any(
                server.get("project") == str(old_project.resolve()) and server.get("name") == name
                for server in registered_state["servers"].values()
            )
            and not any(
                lease.get("status") == "active" and lease.get("project") == str(old_project.resolve())
                for lease in registered_state["leases"].values()
            ),
            "assignment, server, and active lease state must no longer point at the retired checkout",
        )
    finally:
        if relocated_listener.poll() is None:
            relocated_listener.terminate()
            try:
                relocated_listener.wait(timeout=5)
            except subprocess.TimeoutExpired:
                relocated_listener.kill()

    def expect_unchanged(case: str, state: dict, args: list[str], expected: str) -> None:
        case_env, state_file = prepare(case, state)
        before = state_file.read_bytes()
        run_fail(args, env=case_env, expected=expected)
        check(state_file.read_bytes() == before, f"failed relocation {case} must not write coordinator state")

    wrong_owner_port = free_port()
    wrong_owner = fixture(wrong_owner_port)
    old_key = module.server_key(str(old_project), name)
    wrong_owner["port_assignments"][old_key]["project"] = str(foreign_project.resolve())
    expect_unchanged("wrong-owner", wrong_owner, relocate_args(wrong_owner_port), "exact project/name/port")

    wrong_lease_port = free_port()
    expect_unchanged(
        "wrong-lease",
        fixture(wrong_lease_port),
        relocate_args(wrong_lease_port, expected_lease="not-the-captured-lease"),
        "missing without stale-release evidence",
    )

    foreign_lease_port = free_port()
    foreign_lease = fixture(foreign_lease_port)
    foreign_lease["leases"]["foreign-active-lease"] = {
        "id": "foreign-active-lease",
        "agent": "foreign-agent",
        "project": str(foreign_project.resolve()),
        "port": foreign_lease_port,
        "status": "active",
        "purpose": "manual",
        "created_at": module.iso_timestamp(),
        "expires_at": module.now() + 3600,
    }
    expect_unchanged(
        "foreign-lease",
        foreign_lease,
        relocate_args(foreign_lease_port),
        "foreign active lease",
    )

    pending_lease_port = free_port()
    pending_lease = fixture(pending_lease_port)
    pending_lease["leases"][lease_id]["pending_operation_id"] = "pending-lease-operation"
    expect_unchanged(
        "pending-lease",
        pending_lease,
        relocate_args(pending_lease_port),
        "has pending operation",
    )

    pending_operation_port = free_port()
    pending_operation = fixture(pending_operation_port)
    pending_operation["operations"]["pending-server-operation"] = {
        "id": "pending-server-operation",
        "action": "server.stop",
        "target": f"server:{module.server_key(str(old_project), name)}",
        "agent": "old-agent",
        "project": str(old_project.resolve()),
        "generation": 1,
        "status": "pending",
        "phase": "reserved",
        "owner_pid": os.getpid(),
        "owner_thread": threading.get_ident(),
        "created_at": module.iso_timestamp(),
        "created_ts": module.now(),
        "updated_at": module.iso_timestamp(),
    }
    expect_unchanged(
        "pending-operation",
        pending_operation,
        relocate_args(pending_operation_port),
        "pending coordinator operation",
    )

    live_pid_port = free_port()
    live_pid = fixture(live_pid_port)
    live_pid["servers"][server_id]["pid"] = os.getpid()
    expect_unchanged(
        "live-recorded-pid",
        live_pid,
        relocate_args(live_pid_port),
        "is still alive",
    )

    ambiguous_port = free_port()
    ambiguous = fixture(ambiguous_port)
    ambiguous["servers"]["ambiguous-old-record"] = {
        **ambiguous["servers"][server_id],
        "id": "ambiguous-old-record",
        "port": free_port(),
    }
    expect_unchanged(
        "ambiguous-server",
        ambiguous,
        relocate_args(ambiguous_port),
        "ambiguous old server identity",
    )

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        live_port = int(listener.getsockname()[1])
        expect_unchanged("live-listener", fixture(live_port), relocate_args(live_port), "live listener")
    finally:
        listener.close()

    # Bind-based availability checks falsely reject a free privileged port
    # when an unprivileged process gets EACCES. Prove relocation uses only
    # positive listener evidence by making the legacy bind probe explode.
    privileged_home = root / "state-privileged-eacces"
    privileged_home.mkdir(mode=0o700)
    (privileged_home / "state.json").write_text(
        json.dumps(fixture(443), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (privileged_home / "state.json").chmod(0o600)
    original_home = os.environ.get("CODEX_AGENT_COORDINATOR_HOME")
    original_listener_evidence = module.listener_evidence_for_port
    original_port_available = module.port_available
    os.environ["CODEX_AGENT_COORDINATOR_HOME"] = str(privileged_home)
    module.listener_evidence_for_port = lambda port: {
        "present": False,
        "port": port,
        "pid": None,
        "proc_listen_socket_count": 0,
        "loopback_reachable": False,
    }
    module.port_available = lambda *args, **kwargs: (_ for _ in ()).throw(
        PermissionError(13, "simulated EACCES from privileged bind probe")
    )
    try:
        with module.locked_state() as state:
            low_result = module.relocate_port_assignment(
                state,
                agent="cutover-agent",
                old_project=str(old_project),
                new_project=str(new_project),
                name=name,
                port=443,
                lease_id=lease_id,
            )
        check(low_result.get("ok") is True, "free privileged port must not be rejected by a bind EACCES")
    finally:
        module.listener_evidence_for_port = original_listener_evidence
        module.port_available = original_port_available
        if original_home is None:
            os.environ.pop("CODEX_AGENT_COORDINATOR_HOME", None)
        else:
            os.environ["CODEX_AGENT_COORDINATOR_HOME"] = original_home


class _HealthzHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


def check_unobservable_listener_lifecycle_guards(module: object, tmp: Path) -> None:
    """Prove unknown listener identity is never treated as stopped or replaceable."""

    project = tmp / "unobservable-listener-lifecycle"
    (project / ".codex").mkdir(parents=True)
    port = free_port()
    server_id = "unobservable-server"
    lease_id = "unobservable-lease"
    key = f"{project.resolve()}::web"
    (project / ".codex" / "dev-runtime.json").write_text(
        json.dumps(
            {
                "name": "unobservable-runtime",
                "servers": [
                    {
                        "name": "web",
                        "role": "web",
                        "port": port,
                        "cwd": ".",
                        "argv": [sys.executable, "-c", "pass"],
                    }
                ],
                "dependencies": [
                    {"type": "docker", "name": "database", "container": "unobservable-db"}
                ],
            }
        ),
        encoding="utf-8",
    )

    server = {
        "id": server_id,
        "key": key,
        "name": "web",
        "project": str(project.resolve()),
        "cwd": str(project.resolve()),
        "port": port,
        "host": "127.0.0.1",
        "pid": os.getpid(),
        "lease_id": lease_id,
        "status": "running",
        "argv_template": [sys.executable, "-c", "pass"],
        "cmd_template": None,
        "env": {},
        "health_url": None,
        "created_at": "fixture-created",
        "generation": 7,
        "registration_identity": {"pid": os.getpid()},
    }
    lease = {
        "id": lease_id,
        "port": port,
        "agent": "fixture-agent",
        "project": str(project.resolve()),
        "purpose": "server:web",
        "server_id": server_id,
        "status": "active",
        "owner_pid": os.getpid(),
        "assignment_key": key,
        "expires_at": None,
    }
    assignment = {
        "key": key,
        "project": str(project.resolve()),
        "name": "web",
        "port": port,
        "agent": "fixture-agent",
        "source": "fixture",
        "created_at": "fixture-created",
        "updated_at": "fixture-created",
    }
    unknown = {
        "ok": None,
        "pid_alive": True,
        "check": {"ok": True},
        "identity": {
            "ok": None,
            "observable": False,
            "reason": "listener fd table is outside this observer's capability",
        },
        "classification": "unverified-listener",
    }

    def fixture_state() -> dict:
        state = module.default_state()
        state["servers"] = {server_id: copy.deepcopy(server)}
        state["leases"] = {lease_id: copy.deepcopy(lease)}
        state["port_assignments"] = {key: copy.deepcopy(assignment)}
        return state

    def lifecycle(state: dict) -> dict:
        row = state["servers"][server_id]
        return {
            "status": row.get("status"),
            "pid": row.get("pid"),
            "lease_id": row.get("lease_id"),
            "generation": row.get("generation"),
            "operation_id": row.get("operation_id"),
            "lease": copy.deepcopy(state["leases"].get(lease_id)),
        }

    def expect_unknown(call, label: str) -> None:
        try:
            call()
        except module.ListenerIdentityUnobservable as exc:
            check("unobservable" in str(exc), f"{label} should explain listener identity: {exc}")
            return
        raise AssertionError(f"{label} accepted an unobservable listener identity")

    original_health = module.server_health
    original_stop = module.stop_pid
    original_start = module.start_process
    original_docker_inventory = module.docker_ps_inventory
    original_run_docker = module.run_docker
    original_register_docker = module.register_docker_metadata
    original_coordinated_docker = module.coordinated_run_docker
    original_coordinated_register = module.coordinated_register_docker_metadata
    original_project_identity_guard = module.require_project_server_identities_observable
    original_home = os.environ.get("CODEX_AGENT_COORDINATOR_HOME")
    signals: list[int] = []
    launches: list[dict] = []
    docker_mutations: list[list[str]] = []
    docker_registrations: list[str] = []
    try:
        module.server_health = lambda *_args, **_kwargs: copy.deepcopy(unknown)
        module.stop_pid = lambda pid: signals.append(int(pid))
        module.start_process = lambda **kwargs: (
            launches.append(dict(kwargs)) or (987_654_321, str(project / "unexpected.log"))
        )
        module.docker_ps_inventory = lambda **_kwargs: {
            "available": True,
            "containers": [
                {
                    "id": "unobservable-db-id",
                    "name": "unobservable-db",
                    "status": "Exited (0)",
                    "ports": "",
                    "metadata_source": "none",
                }
            ],
            "postgres": [],
        }
        module.run_docker = lambda _state, command, **_kwargs: (
            docker_mutations.append(list(command)) or {"command": list(command)}
        )
        module.register_docker_metadata = lambda _state, options: (
            docker_registrations.append(str(options["container"])) or dict(options)
        )
        module.coordinated_run_docker = lambda command, **_kwargs: (
            docker_mutations.append(list(command)) or {"command": list(command)}
        )
        module.coordinated_register_docker_metadata = lambda options: (
            docker_registrations.append(str(options["container"])) or dict(options)
        )

        status_state = fixture_state()
        before = lifecycle(status_state)
        status = module.status_server(
            status_state,
            {"server_id": server_id, "project": str(project.resolve()), "name": "web"},
        )
        check(
            status.get("status") == "running"
            and (status.get("health") or {}).get("ok") is None
            and lifecycle(status_state) == before,
            f"read-only status must preserve the recorded lifecycle: {status}",
        )
        inventory_state = fixture_state()
        before = lifecycle(inventory_state)
        inventory = module.build_inventory(
            inventory_state,
            project=str(project.resolve()),
            include_docker=False,
        )
        inventory_server = next(item for item in inventory["servers"] if item["id"] == server_id)
        check(
            inventory_server.get("status") == "running"
            and (inventory_server.get("health") or {}).get("classification") == "unverified-listener"
            and lifecycle(inventory_state) == before,
            "read-only inventory must preserve lifecycle and lease state",
        )

        sync_actions = {
            "stop": lambda state: module.stop_server(
                state,
                {"agent": "guard-test", "project": str(project.resolve()), "name": "web"},
            ),
            "start": lambda state: module.start_server(
                state,
                {
                    "agent": "guard-test",
                    "project": str(project.resolve()),
                    "name": "web",
                    "cwd": str(project.resolve()),
                    "argv": [sys.executable, "-c", "pass"],
                    "range": f"{port}-{port}",
                    "preferred": port,
                },
            ),
            "restart": lambda state: module.restart_server(
                state,
                {"agent": "guard-test", "project": str(project.resolve()), "name": "web"},
            ),
        }
        for action, call in sync_actions.items():
            state = fixture_state()
            before = lifecycle(state)
            expect_unknown(lambda call=call, state=state: call(state), f"synchronous {action}")
            check(lifecycle(state) == before, f"synchronous {action} changed lifecycle or lease")
        for action in ("start", "restart", "stop"):
            state = fixture_state()
            before = lifecycle(state)
            docker_mutations.clear()
            docker_registrations.clear()
            expect_unknown(
                lambda action=action, state=state: getattr(module, f"project_runtime_{action}")(
                    state,
                    {"agent": "guard-test", "project": str(project.resolve())},
                ),
                f"synchronous project {action}",
            )
            check(
                lifecycle(state) == before and not docker_mutations and not docker_registrations,
                f"synchronous project {action} partially mutated before identity proof",
            )

        # The project preflight covers every registered row owned by the
        # project, including a server omitted from the runtime declaration.
        undeclared_state = fixture_state()
        undeclared = copy.deepcopy(server)
        undeclared.update(
            {
                "id": "undeclared-unobservable-server",
                "key": f"{project.resolve()}::undeclared-worker",
                "name": "undeclared-worker",
                "lease_id": None,
            }
        )
        undeclared_state["servers"][undeclared["id"]] = undeclared
        healthy = {
            "ok": True,
            "pid_alive": True,
            "check": {"ok": True},
            "identity": {"ok": True, "observable": True},
            "classification": "healthy",
        }
        module.server_health = lambda candidate, **_kwargs: copy.deepcopy(
            unknown if candidate.get("name") == "undeclared-worker" else healthy
        )
        undeclared_spec = module.build_project_runtime_spec(
            undeclared_state,
            project=str(project.resolve()),
        )
        expect_unknown(
            lambda: module.require_project_server_identities_observable(
                undeclared_state,
                undeclared_spec,
                action="stop",
            ),
            "undeclared registered project server preflight",
        )
        module.server_health = lambda *_args, **_kwargs: copy.deepcopy(unknown)

        coordinated_home = tmp / "unobservable-coordinated-state"
        os.environ["CODEX_AGENT_COORDINATOR_HOME"] = str(coordinated_home)

        def reset_coordinated() -> None:
            with module.locked_state() as state:
                fresh = fixture_state()
                state.clear()
                state.update(fresh)

        reset_coordinated()
        before = lifecycle(module.snapshot_coordinator_state())
        coordinated_status = module.coordinated_status_server(
            {"project": str(project.resolve()), "name": "web"}
        )
        after = lifecycle(module.snapshot_coordinator_state())
        check(
            coordinated_status.get("status") == "running"
            and (coordinated_status.get("health") or {}).get("ok") is None
            and after == before,
            "coordinated status must preserve lifecycle and lease state",
        )
        for action in ("stop", "start", "restart"):
            reset_coordinated()
            before_state = module.snapshot_coordinator_state()
            before = lifecycle(before_state)
            signals.clear()
            launches.clear()
            options = {"agent": "guard-test", "project": str(project.resolve()), "name": "web"}
            if action == "start":
                options.update(
                    {
                        "cwd": str(project.resolve()),
                        "argv": [sys.executable, "-c", "pass"],
                        "range": f"{port}-{port}",
                        "preferred": port,
                    }
                )
            expect_unknown(
                lambda action=action, options=options: getattr(
                    module, f"coordinated_{action}_server"
                )(options),
                f"coordinated {action}",
            )
            after_state = module.snapshot_coordinator_state()
            check(
                lifecycle(after_state) == before
                and len(after_state.get("operations", {})) == len(before_state.get("operations", {}))
                and not signals
                and not launches,
                f"coordinated {action} signalled, launched, or changed lifecycle state",
            )
        for action in ("start", "restart", "stop"):
            reset_coordinated()
            before_state = module.snapshot_coordinator_state()
            before = lifecycle(before_state)
            docker_mutations.clear()
            docker_registrations.clear()
            expect_unknown(
                lambda action=action: getattr(module, f"coordinated_project_runtime_{action}")(
                    {"agent": "guard-test", "project": str(project.resolve())}
                ),
                f"coordinated project {action}",
            )
            after_state = module.snapshot_coordinator_state()
            check(
                lifecycle(after_state) == before
                and len(after_state.get("operations", {})) == len(before_state.get("operations", {}))
                and not docker_mutations
                and not docker_registrations,
                f"coordinated project {action} partially mutated before identity proof",
            )

        # Revalidate all relevant lifecycle fingerprints under the same lock
        # that creates the project operation. This fixture changes generation
        # after observation and must fail before an operation record exists.
        reset_coordinated()
        module.server_health = lambda *_args, **_kwargs: copy.deepcopy(healthy)
        before_operation_ids = set(module.snapshot_coordinator_state().get("operations", {}))

        def race_project_preflight(state: dict, spec: dict, *, action: str) -> dict:
            fingerprints = original_project_identity_guard(state, spec, action=action)
            with module.locked_state() as current:
                current["servers"][server_id]["generation"] += 1
            return fingerprints

        module.require_project_server_identities_observable = race_project_preflight
        try:
            module.begin_project_operation(
                {"agent": "guard-test", "project": str(project.resolve())},
                "stop",
            )
        except RuntimeError as exc:
            check(
                "changed during listener identity preflight" in str(exc),
                f"project TOCTOU should have an exact retry failure: {exc}",
            )
        else:
            raise AssertionError("project operation ignored a post-observation lifecycle change")
        finally:
            module.require_project_server_identities_observable = original_project_identity_guard
        after_operation_ids = set(module.snapshot_coordinator_state().get("operations", {}))
        check(
            after_operation_ids == before_operation_ids,
            "project TOCTOU rejection must happen before operation-state mutation",
        )

        # False-positive guard: positive identity proof retains the authorized
        # lifecycle path instead of turning every registered listener immutable.
        module.server_health = lambda *_args, **_kwargs: {
            "ok": True,
            "pid_alive": True,
            "check": {"ok": True},
            "identity": {"ok": True, "observable": True},
            "classification": "healthy",
        }
        capable_state = fixture_state()
        signals.clear()
        stopped = module.stop_server(
            capable_state,
            {"agent": "guard-test", "project": str(project.resolve()), "name": "web"},
        )
        check(
            signals == [os.getpid()]
            and stopped.get("status") == "stopped"
            and lease_id not in capable_state["leases"],
            "positive listener identity proof must retain authorized stop behavior",
        )
    finally:
        module.server_health = original_health
        module.stop_pid = original_stop
        module.start_process = original_start
        module.docker_ps_inventory = original_docker_inventory
        module.run_docker = original_run_docker
        module.register_docker_metadata = original_register_docker
        module.coordinated_run_docker = original_coordinated_docker
        module.coordinated_register_docker_metadata = original_coordinated_register
        module.require_project_server_identities_observable = original_project_identity_guard
        if original_home is None:
            os.environ.pop("CODEX_AGENT_COORDINATOR_HOME", None)
        else:
            os.environ["CODEX_AGENT_COORDINATOR_HOME"] = original_home


def main() -> int:
    check_http_fixture_policy()
    check_listener_and_health_helpers()
    check_registration_pid_guards()
    tmp = Path(tempfile.mkdtemp(prefix="codex-dev-coordinator-self-test-")).resolve(strict=True)
    env = os.environ.copy()
    env["CODEX_AGENT_COORDINATOR_HOME"] = str(tmp / "state")
    # Project-runtime tests must never inherit a real local Docker Desktop
    # daemon. Dedicated Docker command-path tests install their richer fake
    # below; every other fixture sees a deterministic unavailable CLI.
    base_fake_bin = tmp / "base-fake-bin"
    base_fake_bin.mkdir()
    base_fake_docker = base_fake_bin / "docker"
    base_fake_docker.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    base_fake_docker.chmod(0o755)
    env["PATH"] = f"{base_fake_bin}:{env.get('PATH', '')}"
    original_coordinator_home = os.environ.get("CODEX_AGENT_COORDINATOR_HOME")
    os.environ["CODEX_AGENT_COORDINATOR_HOME"] = env["CODEX_AGENT_COORDINATOR_HOME"]
    api_process: subprocess.Popen[str] | None = None
    external_processes: list[subprocess.Popen[str]] = []
    try:
        skill_text = SKILL.read_text(encoding="utf-8")
        for needle in (
            "PROJECT_ROOT=",
            "server register",
            "docker register",
            "Do not start dev/test servers",
            "try the default port",
            "--argv",
            "Authorization: Bearer",
            "non-loopback",
            "outside the cross-agent lock",
        ):
            check(needle in skill_text, f"SKILL.md should retain policy text: {needle}")

        if str(ROOT / "scripts") not in sys.path:
            sys.path.insert(0, str(ROOT / "scripts"))
        import dev_coordinator as dc

        check_atomic_write_cleanup_preserves_primary(dc, tmp)
        check_port_relocation_guards(dc, tmp, env)
        check_unobservable_listener_lifecycle_guards(dc, tmp)

        # A GUI-launched process commonly receives launchd's minimal PATH.  A
        # Linux validation host may legitimately install Docker in /usr/bin,
        # so an absence fixture must not reuse real system directories.  Keep
        # every discovery channel controlled while proving the same missing-
        # PATH and missing-standard-location contract.
        isolated_launchd_path = tmp / "isolated-launchd-path"
        isolated_launchd_path.mkdir()
        launchd_environment = {"PATH": str(isolated_launchd_path)}
        missing_standard_docker = tmp / "missing-standard-location" / "docker"
        try:
            dc.resolve_docker_executable(
                environment=launchd_environment,
                standard_locations=[str(missing_standard_docker)],
            )
        except dc.DockerCapabilityError as exc:
            missing_docker_payload = dc.coordinator_exception_payload(exc)
        else:
            raise AssertionError("launchd-minimal PATH without Docker must fail capability preflight")
        check(
            missing_docker_payload.get("code") == "docker_cli_unavailable"
            and missing_docker_payload.get("classification") == "missing_dependency"
            and (missing_docker_payload.get("capability") or {}).get("name") == "docker_cli",
            f"missing Docker must retain structured capability evidence: {missing_docker_payload}",
        )

        standard_docker = tmp / "standard-location" / "docker"
        standard_docker.parent.mkdir()
        standard_docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        standard_docker.chmod(0o755)
        check(
            dc.resolve_docker_executable(
                environment=launchd_environment,
                standard_locations=[str(standard_docker)],
            )
            == str(standard_docker.resolve()),
            "Docker resolution should fall back to an executable standard absolute location",
        )
        normal_path_bin = tmp / "normal-path-bin"
        normal_path_bin.mkdir()
        normal_path_docker = normal_path_bin / "docker"
        normal_path_docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        normal_path_docker.chmod(0o755)
        check(
            dc.resolve_docker_executable(
                environment={"PATH": str(normal_path_bin)},
                standard_locations=[],
            )
            == str(normal_path_docker.resolve()),
            "normal PATH Docker discovery must remain supported",
        )

        # OrbStack exposes Docker as a multicall entry-point symlink. Resolving
        # that symlink to `docker-tools` changes argv[0], so the target rejects
        # an otherwise valid Docker command. Preserve the discovered `docker`
        # entry-point path while still validating its executable target.
        multicall_bin = tmp / "multicall-bin"
        multicall_bin.mkdir()
        multicall_target = multicall_bin / "docker-tools"
        multicall_target.write_text(
            """#!/bin/sh
if [ "$(basename "$0")" != "docker" ]; then
  echo "unsupported argv0 $(basename "$0")" >&2
  exit 127
fi
echo docker-entrypoint-ok
""",
            encoding="utf-8",
        )
        multicall_target.chmod(0o755)
        multicall_entrypoint = multicall_bin / "docker"
        multicall_entrypoint.symlink_to(multicall_target.name)
        resolved_multicall = dc.resolve_docker_executable(
            environment={"PATH": str(multicall_bin)},
            standard_locations=[],
        )
        check(
            resolved_multicall == str(multicall_entrypoint.absolute()),
            f"Docker multicall resolution must preserve the docker entry-point path: {resolved_multicall}",
        )
        original_docker_override = os.environ.get("CODEX_DOCKER_CLI")
        os.environ["CODEX_DOCKER_CLI"] = str(multicall_entrypoint.absolute())
        try:
            multicall_probe = dc.docker_available_command(["info"])
        finally:
            if original_docker_override is None:
                os.environ.pop("CODEX_DOCKER_CLI", None)
            else:
                os.environ["CODEX_DOCKER_CLI"] = original_docker_override
        check(
            multicall_probe.get("ok") is True
            and "docker-entrypoint-ok" in str(multicall_probe.get("stdout") or ""),
            f"Docker multicall execution must retain argv0=docker: {multicall_probe}",
        )

        # Compose global flags precede the lifecycle verb in real commands.
        # This was the exact classification gap for `compose -f ... stop`.
        check(
            dc.docker_command_is_mutating(
                ["docker", "compose", "-f", "compose.yml", "stop", "postgres"]
            ),
            "Compose lifecycle classification must skip -f and its value",
        )
        check(
            not dc.docker_command_is_mutating(["docker", "compose", "-f", "compose.yml", "ps"]),
            "read-only Compose commands must not become false-positive mutations",
        )

        # Dry-run remains useful on machines without Docker and therefore must
        # not invoke capability discovery even for a mutating Compose command.
        original_resolve_docker = dc.resolve_docker_executable
        dc.resolve_docker_executable = lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("Docker resolution must not run during dry-run")
        )
        try:
            compose_dry_run = dc.coordinated_run_docker(
                ["docker", "compose", "-f", "compose.yml", "stop"],
                cwd=str(tmp),
                dry_run=True,
                project=str(tmp),
                agent="dry-run-agent",
            )
        finally:
            dc.resolve_docker_executable = original_resolve_docker
        check(
            compose_dry_run.get("dry_run") is True,
            f"Compose dry-run should remain executable without Docker: {compose_dry_run}",
        )

        # A project with both a managed process and declared Compose runtime
        # must preflight Docker before stopping that process.  This reproduces
        # the Board incident without touching a real server or Docker daemon.
        mixed_project = tmp / "launchd-mixed-runtime"
        mixed_project.mkdir()
        mixed_spec = {
            "project": str(mixed_project.resolve()),
            "servers": [{"name": "worker", "project": str(mixed_project.resolve())}],
            "compose": {
                "name": "docker-compose",
                "autostart": True,
                "declared": True,
                "cwd": str(mixed_project.resolve()),
                "files": ["compose.yml"],
                "services": ["postgres"],
            },
            "docker": {"available": False, "containers": []},
            "docker_dependencies": [],
        }
        mixed_before = {
            "action": "pre-stop",
            "project": str(mixed_project.resolve()),
            "runtime_id": str(mixed_project.resolve()),
            "ok": False,
            "classification": "missing_dependency",
            "classifications": ["missing_dependency"],
            "services": [{"type": "server", "name": "worker", "status": "running"}],
            "urls": [],
            "health_checks": [],
        }
        original_observe_project_runtime = dc.observe_project_runtime
        original_stop_server = dc.coordinated_stop_server
        original_standard_locations = dc.DOCKER_STANDARD_LOCATIONS
        original_process_path = os.environ.get("PATH")
        stopped_mixed_servers: list[dict] = []
        dc.observe_project_runtime = lambda options, action: (copy.deepcopy(mixed_spec), copy.deepcopy(mixed_before))
        dc.coordinated_stop_server = lambda options: stopped_mixed_servers.append(dict(options)) or {"status": "stopped"}
        dc.DOCKER_STANDARD_LOCATIONS = (str(missing_standard_docker),)
        os.environ["PATH"] = launchd_environment["PATH"]
        try:
            mixed_stop = dc.coordinated_project_runtime_stop(
                {"agent": "launchd-agent", "project": str(mixed_project)}
            )
        finally:
            dc.observe_project_runtime = original_observe_project_runtime
            dc.coordinated_stop_server = original_stop_server
            dc.DOCKER_STANDARD_LOCATIONS = original_standard_locations
            if original_process_path is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = original_process_path
        check(not stopped_mixed_servers, "failed Docker preflight must cause zero server mutations")
        check(
            mixed_stop.get("ok") is False
            and mixed_stop.get("classification") == "missing_dependency"
            and mixed_stop.get("actions") == []
            and mixed_stop.get("partial") is False,
            f"project preflight failure must be a complete non-partial report: {mixed_stop}",
        )
        mixed_capability = ((mixed_stop.get("action_errors") or [{}])[0].get("capability") or {})
        check(
            mixed_capability.get("code") == "docker_cli_unavailable",
            f"project preflight report must expose Docker capability detail: {mixed_stop}",
        )

        # Finding an executable is insufficient: a GUI can see the Docker CLI
        # while its daemon is unavailable, and the Compose plugin can be absent
        # independently.  Both failures must be detected before server stop.
        unavailable_docker = tmp / "unavailable-docker"
        unavailable_docker.write_text(
            """#!/bin/sh
if [ "$1" = "info" ]; then
  echo 'Cannot connect to the Docker daemon' >&2
  exit 1
fi
if [ "$1" = "compose" ] && [ "$2" = "version" ]; then
  exit 0
fi
exit 0
""",
            encoding="utf-8",
        )
        unavailable_docker.chmod(0o755)
        missing_compose_docker = tmp / "missing-compose-docker"
        missing_compose_docker.write_text(
            """#!/bin/sh
if [ "$1" = "info" ]; then
  exit 0
fi
if [ "$1" = "compose" ] && [ "$2" = "version" ]; then
  echo 'docker: compose is not a docker command' >&2
  exit 1
fi
exit 0
""",
            encoding="utf-8",
        )
        missing_compose_docker.chmod(0o755)
        original_observe_project_runtime = dc.observe_project_runtime
        original_stop_server = dc.coordinated_stop_server
        original_docker_override = os.environ.get("CODEX_DOCKER_CLI")
        stopped_probe_servers: list[dict] = []
        dc.observe_project_runtime = lambda options, action: (copy.deepcopy(mixed_spec), copy.deepcopy(mixed_before))
        dc.coordinated_stop_server = lambda options: stopped_probe_servers.append(dict(options)) or {"status": "stopped"}
        probe_results: list[dict] = []
        try:
            for executable in (unavailable_docker, missing_compose_docker):
                os.environ["CODEX_DOCKER_CLI"] = str(executable.resolve())
                probe_results.append(
                    dc.coordinated_project_runtime_stop(
                        {"agent": "probe-agent", "project": str(mixed_project)}
                    )
                )
        finally:
            dc.observe_project_runtime = original_observe_project_runtime
            dc.coordinated_stop_server = original_stop_server
            if original_docker_override is None:
                os.environ.pop("CODEX_DOCKER_CLI", None)
            else:
                os.environ["CODEX_DOCKER_CLI"] = original_docker_override
        check(not stopped_probe_servers, "daemon/Compose capability probes must precede every server mutation")
        probe_codes = [
            (((item.get("action_errors") or [{}])[0].get("capability") or {}).get("code"))
            for item in probe_results
        ]
        check(
            probe_codes == ["docker_daemon_unavailable", "docker_compose_unavailable"]
            and all(item.get("actions") == [] and item.get("partial") is False for item in probe_results),
            f"daemon and Compose failures must be structured zero-mutation reports: {probe_results}",
        )

        # A dependency may remain in readiness/status evidence while Compose
        # exclusively owns lifecycle mutation.  An unrelated explicitly
        # declared container must remain a direct lifecycle target.
        compose_owned_spec = {
            "compose": {"autostart": True, "declared": True, "services": ["postgres"]},
            "docker_dependencies": [
                {
                    "type": "docker",
                    "name": "database",
                    "service": "postgres",
                    "container": "fixture-postgres",
                    "mutation_authorized": True,
                },
                {
                    "type": "docker",
                    "name": "cache",
                    "container": "fixture-cache",
                    "mutation_authorized": True,
                },
            ],
        }
        lifecycle_dependencies = dc.mutable_runtime_docker_dependencies(
            compose_owned_spec,
            exclude_compose_owned=True,
        )
        check(
            [item.get("name") for item in lifecycle_dependencies] == ["cache"],
            f"Compose-owned dependency should retain evidence but not duplicate lifecycle: {lifecycle_dependencies}",
        )
        check(
            len(compose_owned_spec["docker_dependencies"]) == 2,
            "lifecycle dedupe must not remove dependency status evidence",
        )

        # Project restart must still restart a Compose-owned dependency.  It
        # should do that exactly once through Compose—not with both a direct
        # container restart and a redundant idempotent `compose up`.
        compose_restart_project = tmp / "compose-owned-restart"
        compose_restart_project.mkdir()
        compose_restart_spec = {
            "project": str(compose_restart_project.resolve()),
            "servers": [],
            "compose": {
                "name": "docker-compose",
                "autostart": True,
                "declared": True,
                "cwd": str(compose_restart_project.resolve()),
                "files": ["compose.yml"],
                "services": ["postgres"],
            },
            "docker": {
                "available": True,
                "containers": [
                    {
                        "name": "fixture-postgres",
                        "status": "Up 1 minute",
                        "metadata_source": "docker_labels",
                    }
                ],
            },
            "docker_dependencies": [
                {
                    "type": "docker",
                    "name": "database",
                    "service": "postgres",
                    "container": "fixture-postgres",
                    "mutation_authorized": True,
                }
            ],
        }
        compose_restart_report = {
            "action": "status",
            "project": str(compose_restart_project.resolve()),
            "runtime_id": str(compose_restart_project.resolve()),
            "ok": True,
            "classification": None,
            "classifications": [],
            "services": [
                {"type": "docker", "name": "database", "status": "Up 1 minute", "ok": True}
            ],
            "urls": [],
            "health_checks": [],
        }
        original_observe_project_runtime = dc.observe_project_runtime
        original_coordinated_docker = dc.coordinated_run_docker
        original_resolve_docker = dc.resolve_docker_executable
        original_metadata_coordinated = dc.ensure_runtime_docker_metadata_coordinated
        compose_restart_commands: list[list[str]] = []
        dc.observe_project_runtime = lambda options, action: (
            copy.deepcopy(compose_restart_spec),
            {**copy.deepcopy(compose_restart_report), "action": action},
        )
        dc.coordinated_run_docker = lambda command, **kwargs: (
            compose_restart_commands.append(list(command))
            or {"command": list(command), "returncode": 0}
        )
        dc.ensure_runtime_docker_metadata_coordinated = lambda spec, options: []
        dc.resolve_docker_executable = lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("project restart dry-run must not resolve or probe Docker")
        )
        try:
            dc.coordinated_project_runtime_restart(
                {
                    "agent": "compose-agent",
                    "project": str(compose_restart_project),
                    "dry_run": True,
                }
            )
        finally:
            dc.resolve_docker_executable = original_resolve_docker
        effective_compose_restart = [
            "docker", "compose", "-f", "compose.yml", "restart", "postgres"
        ]
        check(
            compose_restart_commands == [effective_compose_restart],
            f"restart dry-run should expose one semantic Compose action without Docker: {compose_restart_commands}",
        )
        compose_restart_commands.clear()
        dc.resolve_docker_executable = lambda **kwargs: str(standard_docker.resolve())
        try:
            compose_restart_result = dc.coordinated_project_runtime_restart(
                {"agent": "compose-agent", "project": str(compose_restart_project)}
            )
        finally:
            dc.observe_project_runtime = original_observe_project_runtime
            dc.coordinated_run_docker = original_coordinated_docker
            dc.resolve_docker_executable = original_resolve_docker
            dc.ensure_runtime_docker_metadata_coordinated = original_metadata_coordinated
        check(
            compose_restart_commands == [effective_compose_restart],
            "Compose-owned project restart must issue one effective Compose restart without "
            f"direct-container or redundant-up lifecycle: {compose_restart_commands}",
        )
        check(
            any(item.get("name") == "database" for item in compose_restart_result.get("services", [])),
            "Compose lifecycle dedupe must retain dependency status evidence in the project report",
        )
        missing_compose_restart_spec = copy.deepcopy(compose_restart_spec)
        missing_compose_restart_spec["docker"]["containers"] = []
        missing_compose_restart_report = copy.deepcopy(compose_restart_report)
        missing_compose_restart_report["ok"] = False
        missing_compose_restart_report["classification"] = "missing_dependency"
        missing_compose_restart_report["classifications"] = ["missing_dependency"]
        missing_compose_restart_report["services"][0].update(
            {"status": "missing", "ok": False, "classification": "missing_dependency"}
        )
        compose_restart_commands.clear()
        dc.observe_project_runtime = lambda options, action: (
            copy.deepcopy(missing_compose_restart_spec),
            {**copy.deepcopy(missing_compose_restart_report), "action": action},
        )
        dc.coordinated_run_docker = lambda command, **kwargs: (
            compose_restart_commands.append(list(command))
            or {"command": list(command), "returncode": 0}
        )
        dc.resolve_docker_executable = lambda **kwargs: str(standard_docker.resolve())
        dc.ensure_runtime_docker_metadata_coordinated = lambda spec, options: []
        try:
            dc.coordinated_project_runtime_restart(
                {"agent": "compose-agent", "project": str(compose_restart_project)}
            )
        finally:
            dc.observe_project_runtime = original_observe_project_runtime
            dc.coordinated_run_docker = original_coordinated_docker
            dc.resolve_docker_executable = original_resolve_docker
            dc.ensure_runtime_docker_metadata_coordinated = original_metadata_coordinated
        check(
            compose_restart_commands == [
                ["docker", "compose", "-f", "compose.yml", "up", "-d", "postgres"]
            ],
            "Compose restart must create a missing declared service through the same single "
            f"effective lifecycle action: {compose_restart_commands}",
        )
        check(
            all("--force-recreate" not in command for command in compose_restart_commands),
            "project restart must not replace containers or risk writable-layer data",
        )

        # Recover missing/stopped services before restarting running dependents.
        mixed_compose_restart_spec = copy.deepcopy(compose_restart_spec)
        mixed_compose_restart_spec["compose"]["services"] = ["postgres", "worker"]
        mixed_compose_restart_spec["docker_dependencies"].append(
            {
                "type": "docker",
                "name": "worker",
                "service": "worker",
                "container": "fixture-worker",
                "mutation_authorized": True,
            }
        )
        mixed_compose_restart_spec["docker"]["containers"] = [
            {
                "name": "fixture-worker",
                "status": "Up 1 minute",
                "metadata_source": "docker_labels",
            }
        ]
        compose_restart_commands.clear()
        dc.observe_project_runtime = lambda options, action: (
            copy.deepcopy(mixed_compose_restart_spec),
            {**copy.deepcopy(compose_restart_report), "action": action},
        )
        dc.coordinated_run_docker = lambda command, **kwargs: (
            compose_restart_commands.append(list(command))
            or {"command": list(command), "returncode": 0}
        )
        dc.resolve_docker_executable = lambda **kwargs: str(standard_docker.resolve())
        dc.ensure_runtime_docker_metadata_coordinated = lambda spec, options: []
        try:
            dc.coordinated_project_runtime_restart(
                {"agent": "compose-agent", "project": str(compose_restart_project)}
            )
        finally:
            dc.observe_project_runtime = original_observe_project_runtime
            dc.coordinated_run_docker = original_coordinated_docker
            dc.resolve_docker_executable = original_resolve_docker
            dc.ensure_runtime_docker_metadata_coordinated = original_metadata_coordinated
        check(
            compose_restart_commands
            == [
                ["docker", "compose", "-f", "compose.yml", "up", "-d", "postgres"],
                ["docker", "compose", "-f", "compose.yml", "restart", "worker"],
            ],
            "mixed Compose restart must recover missing dependencies before restarting running services: "
            f"{compose_restart_commands}",
        )

        # Every real Docker execution is bounded.  A timeout must be structured
        # in both the direct exception and the durable Docker command journal.
        original_subprocess_run = dc.subprocess.run
        original_resolve_docker = dc.resolve_docker_executable
        timeout_values: list[float] = []

        def timeout_docker_run(command: list[str], **kwargs: object) -> object:
            timeout_values.append(float(kwargs.get("timeout") or 0))
            raise subprocess.TimeoutExpired(command, timeout=kwargs.get("timeout"))

        dc.resolve_docker_executable = lambda **kwargs: str(standard_docker.resolve())
        dc.subprocess.run = timeout_docker_run
        timeout_project = tmp / "docker-timeout-project"
        timeout_project.mkdir()
        try:
            try:
                dc.coordinated_run_docker(
                    ["docker", "compose", "-f", "compose.yml", "stop"],
                    cwd=str(timeout_project),
                    project=str(timeout_project),
                    agent="timeout-agent",
                )
            except Exception as exc:
                timeout_payload = dc.coordinator_exception_payload(exc)
            else:
                raise AssertionError("a timed-out Docker lifecycle must not report success")
        finally:
            dc.subprocess.run = original_subprocess_run
            dc.resolve_docker_executable = original_resolve_docker
        check(
            timeout_values
            and 0 < timeout_values[0] <= dc.DOCKER_LIFECYCLE_TIMEOUT_SECONDS
            and timeout_payload.get("code") == "docker_command_timeout"
            and timeout_payload.get("classification") == "timeout",
            f"Docker lifecycle timeout must be bounded and structured: values={timeout_values}, payload={timeout_payload}",
        )
        timeout_state = dc.snapshot_coordinator_state()
        timeout_history = timeout_state.get("docker", {}).get("last_commands", [])
        check(
            timeout_history
            and (timeout_history[-1].get("result") or {}).get("code") == "docker_command_timeout",
            f"Docker timeout evidence must be durable in command history: {timeout_history[-1:]}",
        )

        # A legacy command string is compatibility input, not shell source.
        # This fixture is deliberately shaped like a realistic command-injection
        # payload: the managed process itself is harmless, while a shell would
        # interpret the trailing separator and create an unrelated file.
        injection_marker = tmp / "shell-injection-ran"
        injection_port = free_port()
        run_fail(
            [
                "server",
                "start",
                "--agent",
                "attacker",
                "--project",
                str(tmp),
                "--name",
                "unsafe-command",
                "--cwd",
                str(tmp),
                "--cmd",
                f"{shlex_join([sys.executable, '-c', 'pass'])}; touch {injection_marker}",
                "--range",
                f"{injection_port}-{injection_port}",
                "--health-timeout",
                "0.1",
            ],
            env=env,
            expected="unsafe shell syntax",
        )
        check(not injection_marker.exists(), "legacy command parsing must never execute shell separators")

        failed_launch_port = free_port()
        failure_env = env.copy()
        failure_env["CODEX_AGENT_COORDINATOR_HOME"] = str(tmp / "failure-state")
        run_fail(
            [
                "server",
                "start",
                "--agent",
                "agent-a",
                "--project",
                str(tmp),
                "--name",
                "missing-executable",
                "--cwd",
                str(tmp),
                "--argv",
                json.dumps([str(tmp / "does-not-exist")]),
                "--range",
                f"{failed_launch_port}-{failed_launch_port}",
            ],
            env=failure_env,
            expected="No such file",
        )
        failed_launch_state = run(["state", "show"], env=failure_env)
        check(
            all(
                lease.get("port") != failed_launch_port or lease.get("status") != "active"
                for lease in failed_launch_state["leases"].values()
            ),
            "failed process launch must roll back its reserved port",
        )
        check(
            any(
                operation.get("action") == "server.start" and operation.get("status") == "failed"
                for operation in failed_launch_state.get("operations", {}).values()
            ),
            "failed process launch must leave durable failure evidence",
        )

        run_fail(["docker", "restart", "--container", "fixture-postgres", "--dry-run"], env=env, expected="--agent")
        run_fail(["server", "stop", "--project", str(tmp), "--name", "fixture-web"], env=env, expected="--agent")

        port_a = free_port()
        port_b = free_port()
        low, high = sorted((port_a, port_b))

        first = run(
            [
                "port",
                "lease",
                "--agent",
                "agent-a",
                "--project",
                str(tmp),
                "--range",
                f"{low}-{high}",
                "--preferred",
                str(low),
            ],
            env=env,
        )
        second = run(
            [
                "port",
                "lease",
                "--agent",
                "agent-b",
                "--project",
                str(tmp),
                "--range",
                f"{low}-{high}",
                "--preferred",
                str(low),
            ],
            env=env,
        )
        check(first["port"] == low, "first lease should use preferred port")
        check(second["port"] != first["port"], "second lease should avoid active lease")
        coordinator_state_home = Path(env["CODEX_AGENT_COORDINATOR_HOME"])
        check(stat.S_IMODE(coordinator_state_home.stat().st_mode) == 0o700, "coordinator state home must be mode 0700")
        check(stat.S_IMODE((coordinator_state_home / "state.json").stat().st_mode) == 0o600, "state file must be mode 0600")
        check(stat.S_IMODE((coordinator_state_home / "state.lock").stat().st_mode) == 0o600, "state lock must be mode 0600")

        run_fail(
            ["port", "release", "--lease-id", first["id"]],
            env=env,
            expected="--agent",
        )
        wrong_release_project = tmp / "wrong-release-project"
        wrong_release_project.mkdir()
        run_fail(
            [
                "port",
                "release",
                "--lease-id",
                first["id"],
                "--agent",
                "agent-a",
                "--project",
                str(wrong_release_project),
            ],
            env=env,
            expected="does not match",
        )
        released = run(
            [
                "port",
                "release",
                "--lease-id",
                first["id"],
                "--agent",
                "agent-a",
                "--project",
                str(tmp),
            ],
            env=env,
        )
        check(released["status"] == "released", "release should report released status")
        check(
            (released.get("released_by") or {}).get("agent") == "agent-a",
            "port release evidence should retain the acting agent",
        )

        reset_env = env.copy()
        reset_env["CODEX_AGENT_COORDINATOR_HOME"] = str(tmp / "reset-state")
        reset_port = free_port()
        run(
            [
                "port",
                "lease",
                "--agent",
                "reset-agent",
                "--project",
                str(tmp),
                "--range",
                f"{reset_port}-{reset_port}",
            ],
            env=reset_env,
        )
        run_fail(
            ["state", "reset", "--force"],
            env=reset_env,
            expected="--agent",
        )
        reset_state = run(
            [
                "state",
                "reset",
                "--force",
                "--agent",
                "reset-agent",
                "--project",
                str(tmp),
            ],
            env=reset_env,
        )
        check(not reset_state["leases"] and not reset_state["servers"], "state reset should clear runtime state")
        reset_event = next(item for item in reset_state["history"] if item["type"] == "state.reset")
        check(
            reset_event["payload"]["agent"] == "reset-agent"
            and reset_event["payload"]["prior"]["lease_count"] == 1,
            f"state reset should retain attributed prior-state evidence: {reset_event}",
        )

        # An exact manual lease can be consumed by structured server start
        # without release/reacquire or a second lease. All provenance and
        # rollback boundaries are checked through the public CLI.
        exact_lease_port = free_port()
        exact_lease = run(
            [
                "port",
                "lease",
                "--agent",
                "lease-agent",
                "--project",
                str(tmp),
                "--range",
                f"{exact_lease_port}-{exact_lease_port}",
                "--purpose",
                "manual",
            ],
            env=env,
        )
        lease_count_before_start = len(run(["port", "list"], env=env))
        exact_lease_server = run(
            [
                "server",
                "start",
                "--agent",
                "lease-agent",
                "--project",
                str(tmp),
                "--name",
                "lease-web",
                "--cwd",
                str(tmp),
                "--argv",
                json.dumps(
                    [
                        sys.executable,
                        "-c",
                        HTTP_FIXTURE_CODE,
                        "{port}",
                    ]
                ),
                "--lease-id",
                exact_lease["id"],
                "--health-url",
                "http://127.0.0.1:{port}/",
            ],
            env=env,
        )
        check(
            exact_lease_server["port"] == exact_lease_port
            and exact_lease_server["lease_id"] == exact_lease["id"]
            and exact_lease_server.get("lease_source") == "manual",
            f"server start should preserve the exact manual lease identity: {exact_lease_server}",
        )
        leases_after_exact_start = run(["port", "list"], env=env)
        attached_exact_lease = next(item for item in leases_after_exact_start if item["id"] == exact_lease["id"])
        check(
            len(leases_after_exact_start) == lease_count_before_start
            and attached_exact_lease["port"] == exact_lease_port
            and attached_exact_lease["server_id"] == exact_lease_server["id"]
            and attached_exact_lease["attachment_status"] == "attached"
            and attached_exact_lease["original_purpose"] == "manual",
            f"exact lease attachment must not allocate a second lease: {leases_after_exact_start}",
        )
        run_fail(
            [
                "server",
                "start",
                "--agent",
                "lease-agent",
                "--project",
                str(tmp),
                "--name",
                "lease-web-duplicate",
                "--cwd",
                str(tmp),
                "--argv",
                json.dumps([sys.executable, "-c", "pass"]),
                "--lease-id",
                exact_lease["id"],
            ],
            env=env,
            expected="already bound",
        )

        wrong_agent_port = free_port()
        wrong_agent_lease = run(
            [
                "port",
                "lease",
                "--agent",
                "lease-owner",
                "--project",
                str(tmp),
                "--range",
                f"{wrong_agent_port}-{wrong_agent_port}",
            ],
            env=env,
        )
        run_fail(
            [
                "server",
                "start",
                "--agent",
                "different-agent",
                "--project",
                str(tmp),
                "--name",
                "wrong-agent-web",
                "--cwd",
                str(tmp),
                "--argv",
                json.dumps([sys.executable, "-c", "pass"]),
                "--lease-id",
                wrong_agent_lease["id"],
            ],
            env=env,
            expected="agent does not match",
        )
        wrong_lease_project = tmp / "wrong-lease-project"
        wrong_lease_project.mkdir()
        run_fail(
            [
                "server",
                "start",
                "--agent",
                "lease-owner",
                "--project",
                str(wrong_lease_project),
                "--name",
                "wrong-project-web",
                "--cwd",
                str(wrong_lease_project),
                "--argv",
                json.dumps([sys.executable, "-c", "pass"]),
                "--lease-id",
                wrong_agent_lease["id"],
            ],
            env=env,
            expected="project does not match",
        )

        wrong_source_port = free_port()
        wrong_source_lease = run(
            [
                "port",
                "lease",
                "--agent",
                "lease-agent",
                "--project",
                str(tmp),
                "--range",
                f"{wrong_source_port}-{wrong_source_port}",
                "--purpose",
                "database-reservation",
            ],
            env=env,
        )
        run_fail(
            [
                "server",
                "start",
                "--agent",
                "lease-agent",
                "--project",
                str(tmp),
                "--name",
                "wrong-source-web",
                "--cwd",
                str(tmp),
                "--argv",
                json.dumps([sys.executable, "-c", "pass"]),
                "--lease-id",
                wrong_source_lease["id"],
            ],
            env=env,
            expected="manual lease",
        )

        expired_port = free_port()
        expired_lease = run(
            [
                "port",
                "lease",
                "--agent",
                "lease-agent",
                "--project",
                str(tmp),
                "--range",
                f"{expired_port}-{expired_port}",
                "--ttl",
                "1",
            ],
            env=env,
        )
        time.sleep(1.1)
        run_fail(
            [
                "server",
                "start",
                "--agent",
                "lease-agent",
                "--project",
                str(tmp),
                "--name",
                "expired-lease-web",
                "--cwd",
                str(tmp),
                "--argv",
                json.dumps([sys.executable, "-c", "pass"]),
                "--lease-id",
                expired_lease["id"],
            ],
            env=env,
            expected="expired",
        )

        occupied_lease_port = free_port()
        occupied_lease = run(
            [
                "port",
                "lease",
                "--agent",
                "lease-agent",
                "--project",
                str(tmp),
                "--range",
                f"{occupied_lease_port}-{occupied_lease_port}",
            ],
            env=env,
        )
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied_listener:
            occupied_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            occupied_listener.bind(("127.0.0.1", occupied_lease_port))
            occupied_listener.listen(1)
            run_fail(
                [
                    "server",
                    "start",
                    "--agent",
                    "lease-agent",
                    "--project",
                    str(tmp),
                    "--name",
                    "occupied-lease-web",
                    "--cwd",
                    str(tmp),
                    "--argv",
                    json.dumps([sys.executable, "-c", "pass"]),
                    "--lease-id",
                    occupied_lease["id"],
                ],
                env=env,
                expected="port is no longer available",
            )
        occupied_state = run(["state", "show"], env=env)
        retained_occupied_lease = occupied_state["leases"][occupied_lease["id"]]
        check(
            retained_occupied_lease["status"] == "active"
            and retained_occupied_lease["purpose"] == "manual"
            and not retained_occupied_lease.get("server_id")
            and not retained_occupied_lease.get("pending_operation_id"),
            f"pre-launch port conflict should retain the manual lease unbound: {retained_occupied_lease}",
        )

        launch_failure_port = free_port()
        launch_failure_lease = run(
            [
                "port",
                "lease",
                "--agent",
                "lease-agent",
                "--project",
                str(tmp),
                "--range",
                f"{launch_failure_port}-{launch_failure_port}",
            ],
            env=env,
        )
        run_fail(
            [
                "server",
                "start",
                "--agent",
                "lease-agent",
                "--project",
                str(tmp),
                "--name",
                "launch-failure-web",
                "--cwd",
                str(tmp),
                "--argv",
                json.dumps([str(tmp / "missing-server-executable")]),
                "--lease-id",
                launch_failure_lease["id"],
            ],
            env=env,
            expected="launch failed",
        )
        launch_failure_state = run(["state", "show"], env=env)
        retained_launch_failure_lease = launch_failure_state["leases"][launch_failure_lease["id"]]
        check(
            retained_launch_failure_lease["purpose"] == "manual"
            and not retained_launch_failure_lease.get("server_id")
            and retained_launch_failure_lease["last_attachment_failure"]["process_launched"] is False,
            f"pre-launch failure should retain the exact manual lease: {retained_launch_failure_lease}",
        )

        timeout_lease_port = free_port()
        timeout_lease = run(
            [
                "port",
                "lease",
                "--agent",
                "lease-agent",
                "--project",
                str(tmp),
                "--range",
                f"{timeout_lease_port}-{timeout_lease_port}",
            ],
            env=env,
        )
        run_fail(
            [
                "server",
                "start",
                "--agent",
                "lease-agent",
                "--project",
                str(tmp),
                "--name",
                "timeout-lease-web",
                "--cwd",
                str(tmp),
                "--argv",
                json.dumps([sys.executable, "-c", "import time; time.sleep(30)"]),
                "--lease-id",
                timeout_lease["id"],
                "--health-timeout",
                "0.3",
            ],
            env=env,
            expected="failed health check",
        )
        timeout_state = run(["state", "show"], env=env)
        retained_timeout_lease = timeout_state["leases"][timeout_lease["id"]]
        check(
            retained_timeout_lease["server_id"]
            and retained_timeout_lease["purpose"].startswith("server:")
            and retained_timeout_lease["attachment_status"].startswith("failed_after_launch")
            and retained_timeout_lease["last_attachment_failure"]["process_launched"] is True,
            f"post-launch timeout must not silently return the lease to the manual pool: {retained_timeout_lease}",
        )

        structured_only_port = free_port()
        structured_only_lease = run(
            [
                "port",
                "lease",
                "--agent",
                "lease-agent",
                "--project",
                str(tmp),
                "--range",
                f"{structured_only_port}-{structured_only_port}",
            ],
            env=env,
        )
        run_fail(
            [
                "server",
                "start",
                "--agent",
                "lease-agent",
                "--project",
                str(tmp),
                "--name",
                "legacy-command-lease-web",
                "--cwd",
                str(tmp),
                "--cmd",
                f"{sys.executable} -c pass",
                "--lease-id",
                structured_only_lease["id"],
            ],
            env=env,
            expected="structured --argv",
        )

        stopped_exact_lease_server = run(
            [
                "server",
                "stop",
                "--agent",
                "lease-agent",
                "--project",
                str(tmp),
                "--name",
                "lease-web",
            ],
            env=env,
        )
        check(stopped_exact_lease_server["status"] == "stopped", "exact-lease fixture should stop cleanly")

        server_port = free_port()
        server = run(
            [
                "server",
                "start",
                "--agent",
                "agent-a",
                "--project",
                str(tmp),
                "--name",
                "fixture-web",
                "--cwd",
                str(tmp),
                "--cmd",
                f"{shlex_join([sys.executable, '-c', HTTP_FIXTURE_CODE, '{port}'])}",
                "--range",
                f"{server_port}-{server_port}",
                "--health-url",
                "http://127.0.0.1:{port}/",
            ],
            env=env,
        )
        check(server["health"]["ok"], "managed server should become healthy")
        inventory = run(["inventory", "--project", str(tmp), "--no-docker"], env=env)
        fixture_inventory_server = next(item for item in inventory["servers"] if item["id"] == server["id"])
        check(
            any(item["url"] == server["url"] for item in inventory["urls"]),
            "inventory should expose managed server URL",
        )
        check(fixture_inventory_server["status"] == "running", "inventory should health-check managed server")
        usage = fixture_inventory_server.get("process_usage") or {}
        check(usage.get("process_count", 0) >= 1, "inventory should expose managed server process usage")
        check(usage.get("memory_bytes", 0) > 0, "managed server process usage should include RSS memory")
        project_usage = inventory.get("project_usage") or []
        check(project_usage, "inventory should expose project usage rollups")
        check(project_usage[0].get("process_count", 0) >= 1, "project usage should count managed processes")
        check(project_usage[0].get("memory_bytes", 0) > 0, "project usage should include managed process memory")
        check(
            server["id"] in (project_usage[0].get("server_ids") or []),
            "project usage rows must list member server ids for authoritative grouping",
        )
        check(isinstance(project_usage[0].get("container_names"), list), "project usage rows must carry container membership")
        # The usage_key FORMAT is a persisted contract: the console stores it
        # in ui-prefs hidden.projects, so a format change silently unhides.
        check(
            project_usage[0].get("usage_key") == f"path:{Path(str(tmp)).resolve()}",
            "project usage usage_key must keep the 'path:<resolved project>' format",
        )
        status = run(["server", "status", "--project", str(tmp), "--name", "fixture-web"], env=env)
        check(status["status"] == "running", "server status should be running")
        stopped = run(["server", "stop", "--agent", "agent-a", "--project", str(tmp), "--name", "fixture-web", "--reason", "test stop"], env=env)
        check(stopped["status"] == "stopped", "server stop should return stopped server")
        check(stopped["stopped_reason"] == "test stop", "server stop should retain explicit stopped reason")
        stopped_inventory = run(["inventory", "--project", str(tmp), "--no-docker"], env=env)
        stopped_fixture_inventory = next(
            item for item in stopped_inventory["servers"] if item["id"] == stopped["id"]
        )
        check(stopped_fixture_inventory["status"] == "stopped", "stopped server should remain in inventory")
        check(stopped_fixture_inventory["stopped_reason"] == "test stop", "inventory should expose stopped reason")
        logs = run(["server", "logs", "--project", str(tmp), "--name", "fixture-web", "--tail", "20"], env=env)
        check(logs["server"]["stopped_reason"] == "test stop", "server logs should expose stopped reason")
        check(logs["server"]["log_path"], "server logs should expose log path")
        logs_by_id = run(["server", "logs", "--server-id", stopped["id"], "--tail", "20"], env=env)
        check(logs_by_id["server"]["id"] == stopped["id"], "server logs should support exact server id")
        restarted_same_service = run(
            [
                "server",
                "start",
                "--agent",
                "agent-a",
                "--project",
                str(tmp),
                "--name",
                "fixture-web",
                "--cwd",
                str(tmp),
                "--cmd",
                f"{shlex_join([sys.executable, '-c', HTTP_FIXTURE_CODE, '{port}'])}",
                "--range",
                f"{server_port}-{server_port}",
                "--health-url",
                "http://127.0.0.1:{port}/",
                "--env",
                "PERSIST_ACROSS_RESTART=verified",
            ],
            env=env,
        )
        check(restarted_same_service["id"] == stopped["id"], "restarting a logical server should reuse its state record")
        explicit_restart = run(
            ["server", "restart", "--agent", "agent-a", "--project", str(tmp), "--name", "fixture-web"],
            env=env,
        )
        check(explicit_restart["id"] == stopped["id"], "explicit restart should preserve logical server identity")
        check(
            explicit_restart.get("env", {}).get("PERSIST_ACROSS_RESTART") == "verified",
            "restart must preserve explicitly declared process environment",
        )
        check(
            explicit_restart.get("launch_spec", {}).get("env", {}).get("PERSIST_ACROSS_RESTART") == "verified",
            "persisted LaunchSpec must retain restart environment provenance",
        )
        deduped_inventory = run(["inventory", "--project", str(tmp), "--no-docker"], env=env)
        logical_fixture_rows = [item for item in deduped_inventory["servers"] if item["name"] == "fixture-web"]
        check(len(logical_fixture_rows) == 1, "inventory should expose one row per logical server")
        logical_fixture_urls = [item for item in deduped_inventory["urls"] if item["name"] == "fixture-web"]
        check(len(logical_fixture_urls) == 1, "inventory URLs should not duplicate stale logical servers")
        stopped_again = run(["server", "stop", "--agent", "agent-a", "--project", str(tmp), "--name", "fixture-web", "--reason", "test stop again"], env=env)
        check(stopped_again["status"] == "stopped", "deduped restarted server should stop cleanly")

        adopted_port = free_port()
        adopted_process = subprocess.Popen(
            [sys.executable, "-c", HTTP_FIXTURE_CODE, str(adopted_port)],
            cwd=tmp,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        external_processes.append(adopted_process)
        wait_for_http(adopted_port)
        adopted = run(
            [
                "server",
                "register",
                "--agent",
                "agent-a",
                "--project",
                str(tmp),
                "--name",
                "adopted-web",
                "--port",
                str(adopted_port),
                "--url",
                f"http://127.0.0.1:{adopted_port}",
            ],
            env=env,
        )
        check(adopted["adopted"], "server register should mark adopted servers")
        check(adopted["missing_command"], "server register without --cmd should expose missing_command")
        check(adopted.get("lease_id"), "server register should lease an already-running adopted server port")
        adopted_inventory = run(["inventory", "--project", str(tmp), "--no-docker"], env=env)
        check(any(item["name"] == "adopted-web" for item in adopted_inventory["servers"]), "inventory should include adopted server")
        check(
            any(
                item["name"] == "adopted-web" and item["port"] == adopted["port"]
                for item in adopted_inventory.get("port_assignments", [])
            ),
            "server register should durably pin the adopted server's port",
        )
        bad_health_project = tmp / "bad-health-project"
        bad_health_project.mkdir()
        bad_health_port = free_port()
        bad_health_process = subprocess.Popen(
            [sys.executable, "-c", HTTP_FIXTURE_CODE, str(bad_health_port)],
            cwd=bad_health_project,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        external_processes.append(bad_health_process)
        wait_for_http(bad_health_port)
        bad_health = run(
            [
                "server",
                "register",
                "--agent",
                "agent-a",
                "--project",
                str(bad_health_project),
                "--name",
                "bad-health-web",
                "--port",
                str(bad_health_port),
                "--url",
                f"http://127.0.0.1:{bad_health_port}",
                "--health-url",
                f"http://127.0.0.1:{bad_health_port}/missing-health",
            ],
            env=env,
        )
        check(bad_health["status"] == "unhealthy", "HTTP 404 health checks should not be treated as healthy")
        hanging_health_project = tmp / "hanging-health-project"
        hanging_health_project.mkdir()
        hanging_health_port = free_port()
        hanging_health_code = (
            "import socket, time\n"
            "srv = socket.socket()\n"
            "srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            f"srv.bind(('127.0.0.1', {hanging_health_port}))\n"
            "srv.listen(5)\n"
            "while True:\n"
            "    conn, _ = srv.accept()\n"
            "    time.sleep(30)\n"
        )
        hanging_health_process = subprocess.Popen(
            [sys.executable, "-c", hanging_health_code],
            cwd=hanging_health_project,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        external_processes.append(hanging_health_process)
        wait_for_tcp(hanging_health_port)
        before = time.monotonic()
        hanging_register = subprocess.Popen(
            [
                sys.executable,
                str(SCRIPT),
                "server",
                "register",
                "--agent",
                "agent-a",
                "--project",
                str(hanging_health_project),
                "--name",
                "hanging-health-web",
                "--port",
                str(hanging_health_port),
                "--url",
                f"http://127.0.0.1:{hanging_health_port}",
                "--health-url",
                f"http://127.0.0.1:{hanging_health_port}/",
                "--health-timeout",
                "1",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        time.sleep(0.25)
        register_independent_port = free_port()
        register_lease_started = time.monotonic()
        register_independent_lease = run(
            [
                "port",
                "lease",
                "--agent",
                "register-independent",
                "--project",
                str(tmp),
                "--range",
                f"{register_independent_port}-{register_independent_port}",
            ],
            env=env,
        )
        register_lease_elapsed = time.monotonic() - register_lease_started
        hanging_register_stdout, hanging_register_stderr = hanging_register.communicate(timeout=10)
        check(
            hanging_register.returncode == 0,
            f"hanging register fixture should complete: {hanging_register_stdout}\n{hanging_register_stderr}",
        )
        hanging_health = json.loads(hanging_register_stdout)
        check(time.monotonic() - before < 6, "hanging HTTP health checks should be bounded")
        check(
            register_independent_lease["port"] == register_independent_port,
            "independent lease should succeed while server registration health-checks",
        )
        check(
            register_lease_elapsed < 0.75,
            f"slow server registration held the state lock for {register_lease_elapsed:.2f}s",
        )
        check(hanging_health["status"] == "unhealthy", "hanging HTTP health checks should report unhealthy")
        hanging_inventory = run(["inventory", "--project", str(hanging_health_project), "--no-docker"], env=env)
        hanging_server = next(item for item in hanging_inventory["servers"] if item["name"] == "hanging-health-web")
        check(
            (hanging_server.get("health") or {}).get("check", {}).get("classification") == "timeout",
            "hanging HTTP inventory health should classify timeout",
        )
        # A realistic hanging health endpoint must not turn inventory/status
        # observation into a global coordinator lock. The observer remains slow
        # (and truthful), while an unrelated lease must complete immediately.
        hanging_inventory_process = subprocess.Popen(
            [
                sys.executable,
                str(SCRIPT),
                "inventory",
                "--project",
                str(hanging_health_project),
                "--no-docker",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        time.sleep(0.25)
        hanging_independent_port = free_port()
        hanging_lease_started = time.monotonic()
        hanging_independent_lease = run(
            [
                "port",
                "lease",
                "--agent",
                "hanging-health-independent",
                "--project",
                str(tmp),
                "--range",
                f"{hanging_independent_port}-{hanging_independent_port}",
            ],
            env=env,
        )
        hanging_lease_elapsed = time.monotonic() - hanging_lease_started
        hanging_stdout, hanging_stderr = hanging_inventory_process.communicate(timeout=10)
        check(
            hanging_inventory_process.returncode == 0,
            f"slow inventory fixture should complete: {hanging_stdout}\n{hanging_stderr}",
        )
        check(
            hanging_independent_lease["port"] == hanging_independent_port,
            "independent lease should succeed while inventory observes a hanging endpoint",
        )
        check(
            hanging_lease_elapsed < 0.75,
            f"slow inventory health observation held the state lock for {hanging_lease_elapsed:.2f}s",
        )
        hanging_status_process = subprocess.Popen(
            [
                sys.executable,
                str(SCRIPT),
                "server",
                "status",
                "--project",
                str(hanging_health_project),
                "--name",
                "hanging-health-web",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        time.sleep(0.25)
        status_independent_port = free_port()
        status_lease_started = time.monotonic()
        status_independent_lease = run(
            [
                "port",
                "lease",
                "--agent",
                "status-independent",
                "--project",
                str(tmp),
                "--range",
                f"{status_independent_port}-{status_independent_port}",
            ],
            env=env,
        )
        status_lease_elapsed = time.monotonic() - status_lease_started
        status_stdout, status_stderr = hanging_status_process.communicate(timeout=15)
        check(
            hanging_status_process.returncode == 0,
            f"slow server status fixture should complete: {status_stdout}\n{status_stderr}",
        )
        check(
            status_independent_lease["port"] == status_independent_port,
            "independent lease should succeed while server status health-checks",
        )
        check(
            status_lease_elapsed < 0.75,
            f"slow server status held the state lock for {status_lease_elapsed:.2f}s",
        )
        # Optimistic observation commits must not resurrect a server after a
        # newer lifecycle generation stops it. The slow status starts from an
        # older snapshot; stop wins even if that observation completes later.
        stale_status_process = subprocess.Popen(
            [
                sys.executable,
                str(SCRIPT),
                "server",
                "status",
                "--project",
                str(hanging_health_project),
                "--name",
                "hanging-health-web",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        time.sleep(0.25)
        stopped_during_observation = run(
            [
                "server",
                "stop",
                "--agent",
                "observation-race-stop",
                "--project",
                str(hanging_health_project),
                "--name",
                "hanging-health-web",
                "--reason",
                "stopped during slow observation",
            ],
            env=env,
        )
        stale_status_stdout, stale_status_stderr = stale_status_process.communicate(timeout=15)
        check(
            stale_status_process.returncode == 0,
            f"stale status fixture should still return its snapshot: {stale_status_stdout}\n{stale_status_stderr}",
        )
        observation_race_state = run(["state", "show"], env=env)
        observation_race_server = next(
            server
            for server in observation_race_state["servers"].values()
            if server.get("project") == str(hanging_health_project.resolve())
            and server.get("name") == "hanging-health-web"
        )
        check(
            observation_race_server.get("status") == "stopped"
            and observation_race_server.get("stopped_reason") == "stopped during slow observation",
            f"stale observation must not overwrite the newer stop: {observation_race_server}",
        )
        check(
            observation_race_server.get("generation") == stopped_during_observation.get("generation"),
            "optimistic observation commit must preserve the winning lifecycle generation",
        )
        wrong_owner_project = tmp / "wrong-owner-project"
        wrong_owner_project.mkdir()
        wrong_runtime_dir = wrong_owner_project / ".codex"
        wrong_runtime_dir.mkdir()
        (wrong_runtime_dir / "dev-runtime.json").write_text(
            json.dumps(
                {
                    "name": "wrong-owner-runtime",
                    "servers": [
                        {
                            "name": "web",
                            "role": "web",
                            "port": adopted_port,
                            "cwd": ".",
                            "cmd": shlex_join([sys.executable, "-c", HTTP_FIXTURE_CODE, "{port}"]),
                            "health_url": "http://127.0.0.1:{port}/",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        run_fail(
            [
                "server",
                "register",
                "--agent",
                "agent-a",
                "--project",
                str(wrong_owner_project),
                "--name",
                "wrong-web",
                "--port",
                str(adopted_port),
                "--url",
                f"http://127.0.0.1:{adopted_port}",
            ],
            env=env,
            expected="outside registered project",
        )
        check(True, "server register should reject a listener owned by another project")
        wrong_owner_start = run(["project", "start", "--agent", "agent-a", "--project", str(wrong_owner_project)], env=env)
        check(not wrong_owner_start["ok"], "wrong-project adoption should not report success")
        wrong_owner_report = json.dumps(wrong_owner_start)
        check(
            "refusing to adopt" in wrong_owner_report and "outside project" in wrong_owner_report,
            "wrong-project adoption should report stale coordinator metadata",
        )

        reuse_port = free_port()
        reuse_old_project = tmp / "reuse-old-project"
        reuse_new_project = tmp / "reuse-new-project"
        reuse_old_project.mkdir()
        reuse_new_project.mkdir()
        old_reused = run(
            [
                "server",
                "start",
                "--agent",
                "agent-a",
                "--project",
                str(reuse_old_project),
                "--name",
                "web",
                "--cwd",
                str(reuse_old_project),
                "--cmd",
                shlex_join([sys.executable, "-c", HTTP_FIXTURE_CODE, "{port}"]),
                "--range",
                f"{reuse_port}-{reuse_port}",
                "--health-url",
                "http://127.0.0.1:{port}/",
            ],
            env=env,
        )
        run(["server", "stop", "--agent", "agent-a", "--project", str(reuse_old_project), "--name", "web", "--reason", "historical row"], env=env)
        # The stopped server keeps a durable port assignment, so another
        # project must be refused until the pin is explicitly removed.
        run_fail(
            [
                "server",
                "start",
                "--agent",
                "agent-a",
                "--project",
                str(reuse_new_project),
                "--name",
                "web",
                "--cwd",
                str(reuse_new_project),
                "--cmd",
                shlex_join([sys.executable, "-c", HTTP_FIXTURE_CODE, "{port}"]),
                "--range",
                f"{reuse_port}-{reuse_port}",
                "--health-url",
                "http://127.0.0.1:{port}/",
            ],
            env=env,
            expected="no free port available",
        )
        check(True, "a stopped server's assigned port must be refused to other projects")
        run(
            ["port", "unassign", "--agent", "agent-a", "--project", str(reuse_old_project), "--name", "web"],
            env=env,
        )
        new_reused = run(
            [
                "server",
                "start",
                "--agent",
                "agent-a",
                "--project",
                str(reuse_new_project),
                "--name",
                "web",
                "--cwd",
                str(reuse_new_project),
                "--cmd",
                shlex_join([sys.executable, "-c", HTTP_FIXTURE_CODE, "{port}"]),
                "--range",
                f"{reuse_port}-{reuse_port}",
                "--health-url",
                "http://127.0.0.1:{port}/",
            ],
            env=env,
        )
        reuse_inventory = run(["inventory", "--no-docker"], env=env)
        old_reused_row = next(item for item in reuse_inventory["servers"] if item["id"] == old_reused["id"])
        check(old_reused_row.get("url_is_current") is False, "stopped historical URL should be marked non-current when another project reuses its port")
        check(old_reused_row.get("port_reused") is True, "stopped historical row should expose port_reused")
        check(
            old_reused_row.get("port_reused_by", {}).get("project") == str(reuse_new_project.resolve()),
            "stopped historical row should identify the current port owner",
        )
        check(
            not any(item.get("project") == str(reuse_old_project.resolve()) and item.get("url") == old_reused["url"] for item in reuse_inventory["urls"]),
            "inventory URL list should not expose stale historical URLs",
        )
        run(["server", "stop", "--agent", "agent-a", "--project", str(reuse_new_project), "--name", "web", "--reason", "reuse cleanup"], env=env)

        # --- Durable port assignments: a server's port is pinned to (project, name) ---
        pin_project = tmp / "pin-project"
        pin_project.mkdir()
        pinned = run(
            [
                "server",
                "start",
                "--agent",
                "agent-a",
                "--project",
                str(pin_project),
                "--name",
                "web",
                "--cwd",
                str(pin_project),
                "--cmd",
                shlex_join([sys.executable, "-c", HTTP_FIXTURE_CODE, "{port}"]),
                "--health-url",
                "http://127.0.0.1:{port}/",
            ],
            env=env,
        )
        pin_port = int(pinned["port"])
        pin_assignments = run(["port", "assignments", "--project", str(pin_project)], env=env)
        check(
            any(item["name"] == "web" and item["port"] == pin_port for item in pin_assignments),
            "server start should create a durable port assignment",
        )
        run(["server", "stop", "--agent", "agent-a", "--project", str(pin_project), "--name", "web", "--reason", "pin test"], env=env)
        active_after_stop = run(["port", "list"], env=env)
        check(
            not any(int(item.get("port") or 0) == pin_port and item.get("status") == "active" for item in active_after_stop),
            "stopping the server should release its lease",
        )
        pin_assignments = run(["port", "assignments", "--project", str(pin_project)], env=env)
        check(
            any(item["name"] == "web" and item["port"] == pin_port for item in pin_assignments),
            "assignment must survive server stop and stopped-record pruning",
        )
        run_fail(
            ["port", "lease", "--agent", "agent-b", "--project", str(tmp), "--preferred", str(pin_port), "--range", f"{pin_port}-{pin_port}"],
            env=env,
            expected="is durably assigned to",
        )
        check(True, "a foreign lease on an assigned port must be refused with the owner named")

        # Restart after the stopped record is pruned: age the record past the
        # retention window (the way pruning really happens), prune, and start
        # again — the durable assignment must bring the same port back.
        pin_state_file = Path(env["CODEX_AGENT_COORDINATOR_HOME"]) / "state.json"
        pin_state = json.loads(pin_state_file.read_text(encoding="utf-8"))
        for record in pin_state["servers"].values():
            if record.get("project") == str(pin_project.resolve()) and record.get("name") == "web":
                record["stopped_ts"] = record["created_ts"] - 30 * 24 * 3600
        pin_state_file.write_text(json.dumps(pin_state), encoding="utf-8")
        pruned_view = run(["state", "show"], env=env)
        check(
            not any(
                record.get("project") == str(pin_project.resolve()) and record.get("name") == "web"
                for record in pruned_view["servers"].values()
            ),
            "aged stopped record should be pruned before the pinned restart",
        )
        repinned = run(
            [
                "server",
                "start",
                "--agent",
                "agent-a",
                "--project",
                str(pin_project),
                "--name",
                "web",
                "--cwd",
                str(pin_project),
                "--cmd",
                shlex_join([sys.executable, "-c", HTTP_FIXTURE_CODE, "{port}"]),
                "--health-url",
                "http://127.0.0.1:{port}/",
            ],
            env=env,
        )
        check(
            int(repinned["port"]) == pin_port,
            "server start after record pruning must land on the durably assigned port",
        )

        # Explicit different preferred port re-pins the assignment.
        run(["server", "stop", "--agent", "agent-a", "--project", str(pin_project), "--name", "web", "--reason", "re-pin test"], env=env)
        repin_port = free_port()
        repin = run(
            [
                "server",
                "start",
                "--agent",
                "agent-a",
                "--project",
                str(pin_project),
                "--name",
                "web",
                "--cwd",
                str(pin_project),
                "--cmd",
                shlex_join([sys.executable, "-c", HTTP_FIXTURE_CODE, "{port}"]),
                "--range",
                f"{repin_port}-{repin_port}",
                "--preferred",
                str(repin_port),
                "--health-url",
                "http://127.0.0.1:{port}/",
            ],
            env=env,
        )
        check(int(repin["port"]) == repin_port, "explicit preferred port should win over the assignment")
        pin_assignments = run(["port", "assignments", "--project", str(pin_project)], env=env)
        check(
            [item["port"] for item in pin_assignments if item["name"] == "web"] == [repin_port],
            "an explicit different port should re-pin the assignment",
        )
        run(["server", "stop", "--agent", "agent-a", "--project", str(pin_project), "--name", "web", "--reason", "re-pin cleanup"], env=env)

        # A foreign process squatting the pinned port must fail the owner's
        # start loudly instead of silently drifting to a different port.
        squatter = subprocess.Popen(
            [sys.executable, "-c", HTTP_FIXTURE_CODE, str(repin_port)],
            cwd=str(tmp),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.time() + 10
            while time.time() < deadline:
                probe = socket.socket()
                try:
                    probe.connect(("127.0.0.1", repin_port))
                    probe.close()
                    break
                except OSError:
                    probe.close()
                    time.sleep(0.1)
            run_fail(
                [
                    "server",
                    "start",
                    "--agent",
                    "agent-a",
                    "--project",
                    str(pin_project),
                    "--name",
                    "web",
                    "--cwd",
                    str(pin_project),
                    "--cmd",
                    shlex_join([sys.executable, "-c", HTTP_FIXTURE_CODE, "{port}"]),
                ],
                env=env,
                expected="pinned to port",
            )
            check(True, "owner start must fail loudly when a squatter occupies the pinned port")
        finally:
            squatter.terminate()
            squatter.wait(timeout=10)

        # register must refuse a port pinned to another project even when the
        # listener legitimately belongs to the registering project.
        register_guard_port = free_port()
        run(
            ["port", "assign", "--agent", "agent-b", "--project", str(tmp), "--name", "blocker", "--port", str(register_guard_port)],
            env=env,
        )
        register_victim = subprocess.Popen(
            [sys.executable, "-c", HTTP_FIXTURE_CODE, str(register_guard_port)],
            cwd=str(pin_project),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.time() + 10
            while time.time() < deadline:
                probe = socket.socket()
                try:
                    probe.connect(("127.0.0.1", register_guard_port))
                    probe.close()
                    break
                except OSError:
                    probe.close()
                    time.sleep(0.1)
            run_fail(
                [
                    "server",
                    "register",
                    "--agent",
                    "agent-a",
                    "--project",
                    str(pin_project),
                    "--name",
                    "web2",
                    "--port",
                    str(register_guard_port),
                    "--url",
                    f"http://127.0.0.1:{register_guard_port}",
                ],
                env=env,
                expected="is durably assigned to",
            )
            check(True, "server register must refuse a port durably assigned to another project")
        finally:
            register_victim.terminate()
            register_victim.wait(timeout=10)
        run(
            ["port", "unassign", "--agent", "agent-b", "--project", str(tmp), "--name", "blocker"],
            env=env,
        )

        # Unassign contract: attribution required, foreign unassign needs --force,
        # and an unassigned port returns to the shared pool.
        run_fail(
            ["port", "unassign", "--project", str(pin_project), "--name", "web"],
            env=env,
            expected="the following arguments are required: --agent",
        )
        check(True, "port unassign without agent attribution must be rejected")
        run_fail(
            ["port", "unassign", "--agent", "agent-b", "--project", str(tmp), "--port", str(repin_port)],
            env=env,
            expected="pass --force",
        )
        check(True, "unassigning another project's port must require --force")
        removed_assignment = run(
            ["port", "unassign", "--agent", "agent-b", "--project", str(tmp), "--port", str(repin_port), "--force"],
            env=env,
        )
        check(removed_assignment.get("status") == "unassigned", "force unassign should remove another project's pin")
        check(removed_assignment.get("name") == "web", "force unassign should return the removed assignment")
        freed_lease = run(
            ["port", "lease", "--agent", "agent-b", "--project", str(tmp), "--preferred", str(repin_port), "--range", f"{repin_port}-{repin_port}", "--ttl", "60"],
            env=env,
        )
        check(int(freed_lease["port"]) == repin_port, "an unassigned port must be leasable again")
        run(
            [
                "port",
                "release",
                "--lease-id",
                freed_lease["id"],
                "--agent",
                "agent-b",
                "--project",
                str(tmp),
            ],
            env=env,
        )

        # Manual leases must NOT create durable assignments.
        manual_probe = run(["port", "assignments"], env=env)
        check(
            not any(int(item.get("port") or 0) == repin_port for item in manual_probe),
            "manual port leases must not create durable assignments",
        )

        # Moving a pin while the server is stopped: `server restart` must land
        # on the NEW pin, not the stale record port.
        moved_pin_port = free_port()
        run(
            ["port", "assign", "--agent", "agent-a", "--project", str(pin_project), "--name", "web", "--port", str(moved_pin_port)],
            env=env,
        )
        moved_restart = run(
            ["server", "restart", "--agent", "agent-a", "--project", str(pin_project), "--name", "web"],
            env=env,
        )
        check(
            int(moved_restart["port"]) == moved_pin_port,
            "server restart must follow a moved pin instead of the stale record port",
        )

        # Healthy-existing short-circuit heals a MISSING pin (and only that):
        # unassign while running, idempotent start recreates the pin in place.
        run(
            ["port", "unassign", "--agent", "agent-a", "--project", str(pin_project), "--name", "web"],
            env=env,
        )
        healed = run(
            [
                "server",
                "start",
                "--agent",
                "agent-a",
                "--project",
                str(pin_project),
                "--name",
                "web",
                "--cwd",
                str(pin_project),
                "--cmd",
                shlex_join([sys.executable, "-c", HTTP_FIXTURE_CODE, "{port}"]),
                "--health-url",
                "http://127.0.0.1:{port}/",
            ],
            env=env,
        )
        check(int(healed["port"]) == moved_pin_port, "idempotent start of a healthy server must not move it")
        healed_assignments = run(["port", "assignments", "--project", str(pin_project)], env=env)
        check(
            any(item["name"] == "web" and item["port"] == moved_pin_port for item in healed_assignments),
            "idempotent start of a healthy server must heal a missing pin at the current port",
        )
        run(["server", "stop", "--agent", "agent-a", "--project", str(pin_project), "--name", "web", "--reason", "pin fixtures done"], env=env)

        # project start must prefer a moved pin over the stale record port
        # (same precedence as server restart: declared port > pin > record).
        pin_runtime_project = tmp / "pin-runtime-project"
        pin_runtime_dir = pin_runtime_project / ".codex"
        pin_runtime_dir.mkdir(parents=True)
        pin_runtime_port = free_port()

        def write_pin_runtime(port_value):
            server_def = {
                "name": "web",
                "role": "web",
                "cwd": ".",
                "cmd": shlex_join([sys.executable, "-c", HTTP_FIXTURE_CODE, "{port}"]),
                "health_url": "http://127.0.0.1:{port}/",
            }
            if port_value is not None:
                server_def["port"] = port_value
            (pin_runtime_dir / "dev-runtime.json").write_text(
                json.dumps({"name": "pin-runtime", "servers": [server_def]}),
                encoding="utf-8",
            )

        write_pin_runtime(pin_runtime_port)
        first_runtime = run(["project", "start", "--agent", "agent-a", "--project", str(pin_runtime_project)], env=env)
        check(first_runtime["ok"], f"pin-runtime project should start: {first_runtime}")
        run(["project", "stop", "--agent", "agent-a", "--project", str(pin_runtime_project)], env=env)
        # Drop the declared port so the pin (not the stale record) must decide.
        write_pin_runtime(None)
        pin_runtime_moved = free_port()
        run(
            ["port", "assign", "--agent", "agent-a", "--project", str(pin_runtime_project), "--name", "web", "--port", str(pin_runtime_moved)],
            env=env,
        )
        second_runtime = run(["project", "start", "--agent", "agent-a", "--project", str(pin_runtime_project)], env=env)
        check(second_runtime["ok"], f"pin-runtime project should restart: {second_runtime}")
        check(
            any(str(pin_runtime_moved) in str(item.get("url")) for item in second_runtime.get("urls", [])),
            "project start must follow a moved pin instead of the stale record port",
        )
        run(["project", "stop", "--agent", "agent-a", "--project", str(pin_runtime_project)], env=env)

        # Migration seeding: a pre-assignment state file pins existing records;
        # on a contested port the most recently stopped record wins.
        seed_home = tmp / "seed-home"
        seed_home.mkdir()
        seed_env = dict(env)
        seed_env["CODEX_AGENT_COORDINATOR_HOME"] = str(seed_home)
        seed_now = time.time()
        seed_state = {
            "version": 1,
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-01-01T00:00:00Z",
            "leases": {},
            "servers": {
                "old-loser": {
                    "id": "old-loser",
                    "key": "/repo-a::web",
                    "name": "web",
                    "project": "/repo-a",
                    "port": 4000,
                    "status": "stopped",
                    "created_ts": seed_now - 7200,
                    "stopped_ts": seed_now - 3600,
                },
                "new-winner": {
                    "id": "new-winner",
                    "key": "/repo-b::web",
                    "name": "web",
                    "project": "/repo-b",
                    "port": 4000,
                    "status": "stopped",
                    "created_ts": seed_now - 1800,
                    "stopped_ts": seed_now - 900,
                },
                "solo": {
                    "id": "solo",
                    "key": "/repo-c::api",
                    "name": "api",
                    "project": "/repo-c",
                    "port": 4100,
                    "status": "stopped",
                    "created_ts": seed_now - 600,
                    "stopped_ts": seed_now - 300,
                },
                # Port 4200 contested between a RUNNING record that is much
                # older and a freshly stopped one: running must win anyway.
                "old-runner": {
                    "id": "old-runner",
                    "key": "/repo-d::web",
                    "name": "web",
                    "project": "/repo-d",
                    "port": 4200,
                    "status": "running",
                    "created_ts": seed_now - 90_000,
                },
                "fresh-stopped": {
                    "id": "fresh-stopped",
                    "key": "/repo-e::web",
                    "name": "web",
                    "project": "/repo-e",
                    "port": 4200,
                    "status": "stopped",
                    "created_ts": seed_now - 120,
                    "stopped_ts": seed_now - 60,
                },
            },
            "history": [],
            "docker": {"last_commands": [], "stats_history": {}, "metadata": {}},
        }
        (seed_home / "state.json").write_text(json.dumps(seed_state), encoding="utf-8")
        seeded = run(["port", "assignments"], env=seed_env)
        seeded_by_key = {item["key"]: item for item in seeded}
        check(
            seeded_by_key.get("/repo-b::web", {}).get("port") == 4000
            and seeded_by_key.get("/repo-b::web", {}).get("source") == "seed_existing_servers",
            "migration seeding should pin the most recently stopped record on a contested port",
        )
        check("/repo-a::web" not in seeded_by_key, "the older contested record must stay unpinned after seeding")
        check(seeded_by_key.get("/repo-c::api", {}).get("port") == 4100, "uncontested records should seed their ports")
        check(
            seeded_by_key.get("/repo-d::web", {}).get("port") == 4200,
            "a running record must win a contested port during seeding even against a newer stopped record",
        )
        check("/repo-e::web" not in seeded_by_key, "the stopped loser of a running-contested port must stay unpinned")

        adopt_project = tmp / "adopt-project"
        adopt_project.mkdir()
        adopt_runtime_dir = adopt_project / ".codex"
        adopt_runtime_dir.mkdir()
        adopt_runtime_port = free_port()
        (adopt_runtime_dir / "dev-runtime.json").write_text(
            json.dumps(
                {
                    "name": "adopt-runtime",
                    "servers": [
                        {
                            "name": "web",
                            "role": "web",
                            "port": adopt_runtime_port,
                            "cwd": ".",
                            "cmd": shlex_join([sys.executable, "-c", HTTP_FIXTURE_CODE, "{port}"]),
                            "health_url": "http://127.0.0.1:{port}/",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        runtime_adopt_process = subprocess.Popen(
            [sys.executable, "-c", HTTP_FIXTURE_CODE, str(adopt_runtime_port)],
            cwd=adopt_project,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        external_processes.append(runtime_adopt_process)
        wait_for_http(adopt_runtime_port)
        runtime_adopted = run(["project", "start", "--agent", "agent-a", "--project", str(adopt_project)], env=env)
        check(runtime_adopted["ok"], f"project start should adopt healthy fixed-port server: {runtime_adopted}")
        adopted_services = [item for item in runtime_adopted["services"] if item.get("name") == "web"]
        check(adopted_services and adopted_services[0].get("adopted"), "project start should report adopted server service")
        restarted_adopted = run(["server", "restart", "--agent", "agent-a", "--project", str(adopt_project), "--name", "web"], env=env)
        check(restarted_adopted["status"] == "running", f"adopted fixed-port server restart should recover cleanly: {restarted_adopted}")
        check(not restarted_adopted.get("adopted"), "restarted adopted server should become coordinator-managed")
        stopped_restarted_adopted = run(["server", "stop", "--agent", "agent-a", "--project", str(adopt_project), "--name", "web"], env=env)
        check(stopped_restarted_adopted["status"] == "stopped", "restarted adopted server should stop cleanly")

        runtime_port = free_port()
        runtime_config_dir = tmp / ".codex"
        runtime_config_dir.mkdir()
        (runtime_config_dir / "dev-runtime.json").write_text(
            json.dumps(
                {
                    "name": "fixture-runtime",
                    "servers": [
                        {
                            "name": "runtime-web",
                            "role": "web",
                            "port": runtime_port,
                            "cwd": ".",
                            "cmd": shlex_join([sys.executable, "-c", HTTP_FIXTURE_CODE, "{port}"]),
                            "health_url": "http://127.0.0.1:{port}/",
                        }
                    ],
                    "health_checks": [
                        {
                            "name": "runtime-web-ready",
                            "url": f"http://127.0.0.1:{runtime_port}/",
                            "expect_status": 200,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        runtime_start = run(["project", "start", "--agent", "agent-a", "--project", str(tmp)], env=env)
        check(runtime_start["ok"], f"project start should verify full runtime: {runtime_start}")
        check(runtime_start["urls"][0]["url"] == f"http://127.0.0.1:{runtime_port}", "project start should preserve fixed URL/port")
        check(runtime_start["services"][0]["type"] == "server", "project runtime should report server service status")
        runtime_status = run(["project", "status", "--project", str(tmp)], env=env)
        check(runtime_status["ok"], "project status should be healthy after project start")
        check(runtime_status["health_checks"][0]["ok"], "project status should run declared readiness checks")
        runtime_stop = run(["project", "stop", "--agent", "agent-a", "--project", str(tmp)], env=env)
        check(runtime_stop["ok"], "project stop should report successful stop operation")
        runtime_stopped_status = run(["project", "status", "--project", str(tmp)], env=env)
        check(runtime_stopped_status["classification"] == "crashed_process", "stopped project status should not report working")

        stale_lease_project = tmp / "stale-lease-project"
        stale_lease_project.mkdir()
        stale_lease_runtime_dir = stale_lease_project / ".codex"
        stale_lease_runtime_dir.mkdir()
        stale_lease_port = free_port()
        (stale_lease_runtime_dir / "dev-runtime.json").write_text(
            json.dumps(
                {
                    "name": "stale-lease-runtime",
                    "servers": [
                        {
                            "name": "web",
                            "role": "web",
                            "port": stale_lease_port,
                            "cwd": ".",
                            "cmd": shlex_join([sys.executable, "-c", HTTP_FIXTURE_CODE, "{port}"]),
                            "health_url": "http://127.0.0.1:{port}/",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        stale_lease = run(
            [
                "port",
                "lease",
                "--agent",
                "agent-a",
                "--project",
                str(stale_lease_project),
                "--range",
                f"{stale_lease_port}-{stale_lease_port}",
                "--preferred",
                str(stale_lease_port),
                "--purpose",
                "server:web",
            ],
            env=env,
        )
        stale_start = run(["project", "start", "--agent", "agent-a", "--project", str(stale_lease_project)], env=env)
        check(stale_start["ok"], f"project start should reclaim same-project stale fixed-port leases: {stale_start}")
        stale_inventory = run(["inventory", "--project", str(stale_lease_project), "--no-docker"], env=env)
        check(
            all(item["id"] != stale_lease["id"] for item in stale_inventory["leases"]),
            "stale fixed-port lease should not remain active after project start",
        )
        stale_stop = run(["project", "stop", "--agent", "agent-a", "--project", str(stale_lease_project)], env=env)
        check(stale_stop["ok"], "stale lease project should stop cleanly after reclamation")

        docker = run(
            [
                "docker",
                "compose-up",
                "--agent",
                "agent-a",
                "--project",
                str(tmp),
                "--cwd",
                str(tmp),
                "--file",
                "compose.yml",
                "--detach",
                "--dry-run",
            ],
            env=env,
        )
        check(docker["dry_run"], "docker dry-run should not execute docker")
        check(docker["command"] == ["docker", "compose", "-f", "compose.yml", "up", "-d"], "docker command shape drifted")
        docker_restart = run(
            ["docker", "restart", "--agent", "agent-a", "--project", str(tmp), "--container", "fixture-postgres", "--role", "postgres", "--dry-run"],
            env=env,
        )
        check(docker_restart["command"] == ["docker", "restart", "fixture-postgres"], "docker restart command shape drifted")
        check(docker_restart["metadata"]["project"] == str(tmp.resolve()), "docker action should attach sidecar project metadata")
        docker_ps_all = run(["docker", "ps", "--all", "--dry-run"], env=env)
        check(docker_ps_all["command"] == ["docker", "ps", "--all"], "docker ps --all command shape drifted")
        docker_stats = run(["docker", "stats", "--dry-run"], env=env)
        check(
            docker_stats["command"] == ["docker", "stats", "--no-stream", "--format", "{{json .}}"],
            "docker stats command shape drifted",
        )

        fake_bin = tmp / "fake-bin"
        fake_bin.mkdir()
        compose_owner = tmp / "compose-owner"
        leak_owner = tmp / "leak-owner"
        fake_docker = fake_bin / "docker"
        leak_labels = {
            "com.docker.compose.project.working_dir": str(leak_owner),
            "com.docker.compose.project": "leak-owner",
        }
        fake_containers = {
            "abc123def456": {"Id": "abc123def4567890", "Name": "/fixture-postgres", "Config": {"Labels": {}}},
            "fixture-postgres": {"Id": "abc123def4567890", "Name": "/fixture-postgres", "Config": {"Labels": {}}},
            "fed789abc012": {"Id": "fed789abc0123456", "Name": "/runtime-db", "Config": {"Labels": {}}},
            "runtime-db": {"Id": "fed789abc0123456", "Name": "/runtime-db", "Config": {"Labels": {}}},
            "def456abc123": {
                "Id": "def456abc1237890",
                "Name": "/fixture-compose-db",
                "Config": {
                    "Labels": {
                        "com.docker.compose.project.working_dir": str(compose_owner),
                        "com.docker.compose.project": "fixture-compose",
                    }
                },
            },
            "fixture-compose-db": {
                "Id": "def456abc1237890",
                "Name": "/fixture-compose-db",
                "Config": {
                    "Labels": {
                        "com.docker.compose.project.working_dir": str(compose_owner),
                        "com.docker.compose.project": "fixture-compose",
                    }
                },
            },
            # Membership fixtures (unified display/action attribution):
            # an unattributed container named after a real repo, a labeled
            # container whose name also matches a different repo, and an
            # unattributed container whose name matches two repos.
            "11aa22bb33cc": {"Id": "11aa22bb33cc4455", "Name": "/grouprepo-db", "Config": {"Labels": {}}},
            "grouprepo-db": {"Id": "11aa22bb33cc4455", "Name": "/grouprepo-db", "Config": {"Labels": {}}},
            "22bb33cc44dd": {"Id": "22bb33cc44dd5566", "Name": "/leakrepo-db", "Config": {"Labels": leak_labels}},
            "leakrepo-db": {"Id": "22bb33cc44dd5566", "Name": "/leakrepo-db", "Config": {"Labels": leak_labels}},
            "33cc44dd55ee": {"Id": "33cc44dd55ee6677", "Name": "/duporepo-db", "Config": {"Labels": {}}},
            "duporepo-db": {"Id": "33cc44dd55ee6677", "Name": "/duporepo-db", "Config": {"Labels": {}}},
        }
        fake_ps = [
            {"ID": "abc123def456", "Names": "fixture-postgres", "Image": "postgres:16", "Status": "Up 1 second", "Ports": "0.0.0.0:5544->5432/tcp"},
            {"ID": "fed789abc012", "Names": "runtime-db", "Image": "postgres:16", "Status": "Up 1 second", "Ports": "5432/tcp"},
            {"ID": "def456abc123", "Names": "fixture-compose-db", "Image": "postgres:16", "Status": "Up 1 second", "Ports": "5432/tcp"},
            {"ID": "11aa22bb33cc", "Names": "grouprepo-db", "Image": "postgres:16", "Status": "Up 1 second", "Ports": "5432/tcp"},
            {"ID": "22bb33cc44dd", "Names": "leakrepo-db", "Image": "postgres:16", "Status": "Up 1 second", "Ports": "5432/tcp"},
            {"ID": "33cc44dd55ee", "Names": "duporepo-db", "Image": "postgres:16", "Status": "Up 1 second", "Ports": "5432/tcp"},
        ]
        fake_docker.write_text(
            f"""#!/usr/bin/env python3
import json
import os
import sys
import time
args = sys.argv[1:]
delay = float(os.environ.get("CODEX_COORDINATOR_FAKE_DOCKER_DELAY", "0"))
if delay:
    time.sleep(delay)
containers = json.loads({json.dumps(json.dumps(fake_containers))})
ps_rows = json.loads({json.dumps(json.dumps(fake_ps))})
if args[:1] == ["info"]:
    print(json.dumps("fixture-engine"))
elif args[:2] == ["compose", "version"]:
    print("v2.fixture")
elif args[:1] == ["ps"]:
    for row in ps_rows:
        print(json.dumps(row))
elif args[:3] == ["inspect", "--format", "{{{{json .}}}}"]:
    for key in args[3:]:
        print(json.dumps(containers[key]))
elif args[:1] in (["stats"], ["stop"], ["start"], ["restart"]):
    pass
else:
    sys.exit(1)
""",
            encoding="utf-8",
        )
        fake_docker.chmod(0o755)
        fake_env = env.copy()
        fake_env["PATH"] = f"{fake_bin}:{fake_env.get('PATH', '')}"
        undeclared_compose_project = tmp / "undeclared-compose-project"
        undeclared_compose_project.mkdir()
        (undeclared_compose_project / "docker-compose.yml").write_text(
            "services:\n  db:\n    image: postgres:16\n    ports:\n      - '5544:5432'\n",
            encoding="utf-8",
        )
        undeclared_start = run(
            ["project", "start", "--agent", "agent-a", "--project", str(undeclared_compose_project), "--dry-run"],
            env=fake_env,
        )
        check(not undeclared_start["ok"], "undeclared Compose-only project start should not report success")
        check(
            not any(action.get("command", [])[:3] == ["docker", "compose", "up"] for action in undeclared_start.get("actions", [])),
            "project start must not run docker compose up from discovered files without a runtime declaration",
        )
        check(
            any(item.get("type") == "compose" and item.get("discovered") for item in undeclared_start.get("services", [])),
            "undeclared Compose files should be reported as discovered evidence",
        )

        registered_container = run(
            ["docker", "register", "--agent", "agent-a", "--project", str(tmp), "--container", "fixture-postgres", "--role", "postgres"],
            env=fake_env,
        )
        check(registered_container["metadata_source"] == "coordinator_sidecar", "docker register should create sidecar metadata for unlabeled containers")
        docker_inventory = run(["inventory", "--project", str(tmp)], env=fake_env)
        fixture_pg = next(item for item in docker_inventory["docker"]["containers"] if item["name"] == "fixture-postgres")
        check(fixture_pg["project"] == str(tmp.resolve()), "inventory should merge sidecar project metadata")
        check(fixture_pg["metadata_source"] == "coordinator_sidecar", "inventory should expose sidecar metadata source")
        docker_usage_row = next(
            (row for row in docker_inventory.get("project_usage", []) if row.get("usage_key") == f"path:{tmp.resolve()}"),
            None,
        )
        check(docker_usage_row is not None, "project usage should include the docker-attributed project row")
        check(
            "fixture-postgres" in (docker_usage_row.get("container_names") or []),
            "project usage container_names must list the attributed container",
        )
        compose_register = run(
            ["docker", "register", "--agent", "agent-a", "--project", str(tmp), "--container", "fixture-compose-db", "--role", "postgres"],
            env=fake_env,
        )
        check(compose_register["metadata_source"] == "docker_labels" and compose_register["skipped"], "compose labels should win over sidecar registration")
        docker_inventory = run(["inventory", "--project", str(tmp)], env=fake_env)
        fixture_compose = next(item for item in docker_inventory["docker"]["containers"] if item["name"] == "fixture-compose-db")
        check(fixture_compose["project"] == str(compose_owner.resolve()), "inventory should preserve Compose working-dir project metadata")

        # Docker inspection/statistics are external subprocesses. A deliberately
        # slow Docker executable must not serialize an unrelated state mutation.
        slow_docker_env = fake_env.copy()
        slow_docker_env["CODEX_COORDINATOR_FAKE_DOCKER_DELAY"] = "2"
        slow_stats = subprocess.Popen(
            [sys.executable, str(SCRIPT), "docker", "stats"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=slow_docker_env,
        )
        time.sleep(0.25)
        docker_independent_port = free_port()
        docker_lease_started = time.monotonic()
        docker_independent_lease = run(
            [
                "port",
                "lease",
                "--agent",
                "docker-independent",
                "--project",
                str(tmp),
                "--range",
                f"{docker_independent_port}-{docker_independent_port}",
            ],
            env=env,
        )
        docker_lease_elapsed = time.monotonic() - docker_lease_started
        stats_stdout, stats_stderr = slow_stats.communicate(timeout=10)
        check(slow_stats.returncode == 0, f"slow Docker stats fixture should complete: {stats_stdout}\n{stats_stderr}")
        check(
            docker_independent_lease["port"] == docker_independent_port,
            "independent lease should succeed while Docker stats waits",
        )
        check(
            docker_lease_elapsed < 0.75,
            f"slow Docker stats held the state lock for {docker_lease_elapsed:.2f}s",
        )
        slow_docker_register = subprocess.Popen(
            [
                sys.executable,
                str(SCRIPT),
                "docker",
                "register",
                "--agent",
                "slow-docker-register",
                "--project",
                str(tmp),
                "--container",
                "fixture-postgres",
                "--role",
                "postgres",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=slow_docker_env,
        )
        time.sleep(0.25)
        docker_register_parallel_started = time.monotonic()
        docker_register_parallel = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "docker",
                "register",
                "--agent",
                "conflicting-docker-register",
                "--project",
                str(tmp),
                "--container",
                "fixture-postgres",
                "--role",
                "postgres",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=fake_env,
            timeout=5,
        )
        docker_register_parallel_elapsed = time.monotonic() - docker_register_parallel_started
        check(
            docker_register_parallel.returncode == 0,
            "a fast metadata registration may complete while another caller is still doing read-only Docker inspection",
        )
        check(
            docker_register_parallel_elapsed < 0.75,
            f"read-only Docker identity inspection should not hold a mutation reservation, took {docker_register_parallel_elapsed:.2f}s",
        )
        docker_register_independent_port = free_port()
        docker_register_lease_started = time.monotonic()
        docker_register_independent_lease = run(
            [
                "port",
                "lease",
                "--agent",
                "docker-register-independent",
                "--project",
                str(tmp),
                "--range",
                f"{docker_register_independent_port}-{docker_register_independent_port}",
            ],
            env=env,
        )
        docker_register_lease_elapsed = time.monotonic() - docker_register_lease_started
        docker_register_stdout, docker_register_stderr = slow_docker_register.communicate(timeout=10)
        check(
            slow_docker_register.returncode == 0,
            f"slow Docker register fixture should complete: {docker_register_stdout}\n{docker_register_stderr}",
        )
        check(
            docker_register_independent_lease["port"] == docker_register_independent_port,
            "independent lease should succeed while Docker register inspects a container",
        )
        check(
            docker_register_lease_elapsed < 0.75,
            f"slow Docker registration held the state lock for {docker_register_lease_elapsed:.2f}s",
        )

        declared_docker_project = tmp / "declared-docker-project"
        declared_docker_project.mkdir()
        declared_docker_runtime_dir = declared_docker_project / ".codex"
        declared_docker_runtime_dir.mkdir()
        (declared_docker_runtime_dir / "dev-runtime.json").write_text(
            json.dumps(
                {
                    "name": "declared-docker-runtime",
                    "dependencies": [
                        {"type": "docker", "name": "database", "container": "runtime-db", "required": True}
                    ],
                }
            ),
            encoding="utf-8",
        )
        declared_docker_start = run(["project", "start", "--agent", "agent-a", "--project", str(declared_docker_project)], env=fake_env)
        check(declared_docker_start["ok"], f"declared running Docker dependency should make project start healthy: {declared_docker_start}")
        docker_inventory = run(["inventory", "--project", str(declared_docker_project)], env=fake_env)
        runtime_db = next(item for item in docker_inventory["docker"]["containers"] if item["name"] == "runtime-db")
        check(runtime_db["project"] == str(declared_docker_project.resolve()), "project start should attach sidecar metadata to declared unlabeled containers")
        check(runtime_db["metadata_source"] == "coordinator_sidecar", "declared unlabeled containers should expose coordinator sidecar metadata")

        # --- Unified container membership: explicit provenance owns project
        # membership. A unique name resemblance remains visible as read-only
        # evidence and must not authorize a whole-project action.
        grouprepo = tmp / "grouprepo"
        grouprepo.mkdir()
        leakrepo = tmp / "leakrepo"
        leakrepo.mkdir()
        duporepo = tmp / "duporepo"
        duporepo.mkdir()
        duporepo_twin = tmp / "twin" / "duporepo"
        duporepo_twin.mkdir(parents=True)
        for repo in (grouprepo, leakrepo, duporepo, duporepo_twin):
            run(
                ["port", "assign", "--agent", "agent-a", "--project", str(repo), "--name", "web", "--port", str(free_port())],
                env=fake_env,
            )

        def usage_rows() -> tuple[dict[str, dict], dict]:
            inventory = run(["inventory"], env=fake_env)
            return {row["usage_key"]: row for row in inventory.get("project_usage", [])}, inventory

        def stop_targets(project: Path) -> list[str]:
            report = run(
                ["project", "stop", "--agent", "agent-a", "--project", str(project), "--dry-run"],
                env=fake_env,
            )
            return [
                action["command"][2]
                for action in report.get("actions", [])
                if action.get("command", [])[:2] == ["docker", "stop"]
            ]

        rows, _ = usage_rows()
        group_row = rows.get("name:grouprepo")
        check(group_row is not None, "name-only container must remain in a read-only name-keyed row")
        check(
            "grouprepo-db" in (group_row or {}).get("container_names", []),
            "must-catch: unattributed grouprepo-db must remain visible as read-only evidence",
        )
        check(
            "grouprepo-db" not in (rows.get(f"path:{grouprepo.resolve()}") or {}).get("container_names", []),
            "must-catch: name similarity must not claim a container for a repo-owned group",
        )
        check(
            "grouprepo-db" not in stop_targets(grouprepo),
            "project stop must not act on a name-only container",
        )

        leak_row = rows.get(f"path:{leak_owner.resolve()}")
        check(
            leak_row is not None and "leakrepo-db" in leak_row.get("container_names", []),
            "labeled container must display under its label owner",
        )
        check(
            "leakrepo-db" not in (rows.get(f"path:{leakrepo.resolve()}") or {}).get("container_names", []),
            "labeled container must not display under a name-matched repo",
        )
        check(
            "leakrepo-db" not in stop_targets(leakrepo),
            "must-catch: project stop on a name-matched repo must not stop a container attributed to another project",
        )

        dupo_row = rows.get("name:duporepo")
        check(
            dupo_row is not None and "duporepo-db" in dupo_row.get("container_names", []),
            "ambiguous name match (two repos share the key) must stay in its own name-keyed group",
        )
        check(
            "duporepo-db" not in (rows.get(f"path:{duporepo.resolve()}") or {}).get("container_names", []),
            "ambiguous name match must not be claimed by either repo row",
        )
        check(
            "duporepo-db" not in stop_targets(duporepo),
            "project stop must not act on a container whose name matches several repos",
        )

        member_stop = run(["project", "stop", "--agent", "agent-a", "--project", str(grouprepo)], env=fake_env)
        check(member_stop["ok"], f"project stop with read-only evidence should remain a calm no-op: {member_stop}")
        rows, converged_inventory = usage_rows()
        converged = next(item for item in converged_inventory["docker"]["containers"] if item["name"] == "grouprepo-db")
        check(
            converged["metadata_source"] == "none" and not converged.get("project"),
            "a no-op project stop must not manufacture sidecar ownership",
        )
        check(
            "grouprepo-db" in (rows.get("name:grouprepo") or {}).get("container_names", []),
            "read-only name evidence must remain in its non-actionable group",
        )

        api_port = free_port()
        api_process = subprocess.Popen(
            [sys.executable, str(SCRIPT), "api", "serve", "--host", "127.0.0.1", "--port", str(api_port)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=fake_env,
        )
        wait_for_api(api_process, api_port)
        token_file = Path(fake_env["CODEX_AGENT_COORDINATOR_HOME"]) / "api-token"
        check(token_file.exists(), "API startup must create a local bearer-token file")
        api_token = token_file.read_text(encoding="utf-8").strip()
        check(len(api_token) >= 32, "API bearer token must have sufficient entropy")
        check(stat.S_IMODE(token_file.stat().st_mode) == 0o600, "API token file must be mode 0600")
        health = get_json(api_port, "/healthz")
        check(set(health) == {"ok", "service", "version"}, "anonymous health must not disclose coordinator state")
        health_get_headers, health_get_body = request_http(api_port, "GET", "/healthz")
        health_head_headers, health_head_body = request_http(api_port, "HEAD", "/healthz")
        check(not health_head_body, "HEAD /healthz must return headers only")
        check(
            health_head_headers.get("content-length") == health_get_headers.get("content-length")
            == str(len(health_get_body)),
            "HEAD /healthz must advertise the same representation length as GET without sending a body",
        )

        # Authentication is a route boundary, not an accident of the two
        # methods with product handlers. Real clients, scanners, and mistaken
        # integrations send other standard methods; BaseHTTPRequestHandler's
        # inherited 501 path must never run before /v1 authorization.
        protected_method_matrix = (
            ("POST", "/v1/state", "GET"),
            ("GET", "/v1/projects/status", "POST"),
            ("HEAD", "/v1/state", "GET"),
            ("PUT", "/v1/state", "GET"),
            ("DELETE", "/v1/projects/status", "POST"),
            ("PATCH", "/v1/ports/lease", "POST"),
            ("OPTIONS", "/v1/state", "GET"),
            ("PROPFIND", "/v1/state", "GET"),
        )
        for method, path, allowed_method in protected_method_matrix:
            anonymous_headers, anonymous_body = request_http(
                api_port,
                method,
                path,
                expected_status=401,
            )
            check(
                anonymous_headers.get("www-authenticate") == 'Bearer realm="codex-dev-coordinator"',
                f"anonymous {method} {path} must receive the bearer challenge",
            )
            if method == "HEAD":
                check(not anonymous_body, "HEAD responses must not include a body")
            else:
                check(
                    json.loads(anonymous_body.decode("utf-8")).get("error") == "unauthorized",
                    f"anonymous {method} {path} must fail at the auth boundary",
                )

            authenticated_headers, authenticated_body = request_http(
                api_port,
                method,
                path,
                token=api_token,
                expected_status=405,
            )
            check(
                authenticated_headers.get("allow") == allowed_method,
                f"authenticated {method} {path} must advertise {allowed_method} as the allowed method",
            )
            if method == "HEAD":
                check(not authenticated_body, "authenticated HEAD error responses must not include a body")
                check(
                    int(authenticated_headers.get("content-length") or 0) > 0,
                    "authenticated HEAD 405 must describe the body a non-HEAD request would receive",
                )
            else:
                check(
                    json.loads(authenticated_body.decode("utf-8")).get("error") == "method not allowed",
                    f"authenticated {method} {path} must receive a JSON 405",
                )

        health_put_headers, health_put_body = request_http(
            api_port,
            "PUT",
            "/healthz",
            expected_status=405,
        )
        check(
            health_put_headers.get("allow") == "GET, HEAD"
            and json.loads(health_put_body.decode("utf-8")).get("error") == "method not allowed",
            "anonymous health must allow only GET and HEAD",
        )
        outside_headers, outside_body = request_http(
            api_port,
            "DELETE",
            "/not-an-api-route",
            expected_status=404,
        )
        check(
            "www-authenticate" not in outside_headers
            and json.loads(outside_body.decode("utf-8")).get("error") == "not found",
            "non-v1 unsupported requests must fail as JSON 404 without an auth challenge",
        )
        _, outside_head_body = request_http(
            api_port,
            "HEAD",
            "/not-an-api-route",
            expected_status=404,
        )
        check(not outside_head_body, "non-v1 HEAD 404 must not include a body")
        unauthorized = request_json(api_port, "GET", "/v1/state", expected_status=401)
        check(unauthorized.get("error") == "unauthorized", "protected API state must reject missing bearer credentials")
        wrong_token = request_json(api_port, "GET", "/v1/state", token="definitely-not-the-token", expected_status=401)
        check(wrong_token.get("error") == "unauthorized", "protected API state must reject incorrect bearer credentials")
        invalid_host = request_json(
            api_port,
            "GET",
            "/v1/state",
            token=api_token,
            headers={"Host": "attacker.example"},
            expected_status=400,
        )
        check("Host" in str(invalid_host.get("error")), "API must reject non-loopback Host headers")
        forbidden_origin = request_json(
            api_port,
            "GET",
            "/v1/state",
            token=api_token,
            headers={"Origin": "https://attacker.example"},
            expected_status=403,
        )
        check("cross-origin" in str(forbidden_origin.get("error")), "API must reject cross-origin browser requests")
        wrong_content_type = request_json(
            api_port,
            "POST",
            "/v1/projects/status",
            payload={"project": str(tmp)},
            token=api_token,
            headers={"Content-Type": "text/plain"},
            expected_status=415,
        )
        check("application/json" in str(wrong_content_type.get("error")), "API must require JSON content type")
        oversized = request_json(
            api_port,
            "POST",
            "/v1/projects/status",
            payload={"project": str(tmp), "padding": "x" * (70 * 1024)},
            token=api_token,
            expected_status=413,
        )
        check("exceeds" in str(oversized.get("error")), "API must reject oversized bodies before parsing")
        api_lease = post_json(
            api_port,
            "/v1/ports/lease",
            {"agent": "api-agent", "project": str(tmp), "range": f"{low}-{high}", "ttl": 60},
            token=api_token,
        )
        check("port" in api_lease, "API lease should return a port")
        ports = get_json(api_port, "/v1/ports", token=api_token)
        check(any(item["id"] == api_lease["id"] for item in ports), "API lease should appear in port list")
        missing_release_identity = request_json(
            api_port,
            "POST",
            "/v1/ports/release",
            payload={"lease_id": api_lease["id"]},
            token=api_token,
            expected_status=400,
        )
        check(
            "agent" in str(missing_release_identity.get("error")),
            "API port release should require acting-agent attribution",
        )
        api_released = post_json(
            api_port,
            "/v1/ports/release",
            {
                "lease_id": api_lease["id"],
                "agent": "api-agent",
                "project": str(tmp),
            },
            token=api_token,
        )
        check(
            api_released["status"] == "released"
            and (api_released.get("released_by") or {}).get("agent") == "api-agent",
            f"API port release should be attributed: {api_released}",
        )
        api_exact_port = free_port()
        api_exact_lease = post_json(
            api_port,
            "/v1/ports/lease",
            {
                "agent": "api-lease-agent",
                "project": str(tmp),
                "range": f"{api_exact_port}-{api_exact_port}",
                "purpose": "manual",
            },
            token=api_token,
        )
        api_exact_server = post_json(
            api_port,
            "/v1/servers/start",
            {
                "agent": "api-lease-agent",
                "project": str(tmp),
                "name": "api-exact-lease-web",
                "cwd": str(tmp),
                "argv": [
                    sys.executable,
                    "-c",
                    HTTP_FIXTURE_CODE,
                    "{port}",
                ],
                "lease_id": api_exact_lease["id"],
                "health_url": "http://127.0.0.1:{port}/",
                "health_timeout": 5,
            },
            token=api_token,
        )
        check(
            api_exact_server["lease_id"] == api_exact_lease["id"]
            and api_exact_server["port"] == api_exact_port
            and api_exact_server.get("lease_source") == "manual",
            f"API exact-lease start should preserve lease identity: {api_exact_server}",
        )
        api_exact_stopped = post_json(
            api_port,
            "/v1/servers/stop",
            {
                "agent": "api-lease-agent",
                "project": str(tmp),
                "name": "api-exact-lease-web",
            },
            token=api_token,
        )
        check(api_exact_stopped["status"] == "stopped", "API exact-lease fixture should stop cleanly")
        api_inventory = get_json(api_port, "/v1/inventory", token=api_token)
        check("urls" in api_inventory and "docker" in api_inventory, "API inventory should expose URLs and Docker summary")
        api_runtime = post_json(api_port, "/v1/projects/status", {"project": str(tmp)}, token=api_token)
        check("services" in api_runtime and "ok" in api_runtime, "API project status should expose runtime report")
        api_stats = post_json(api_port, "/v1/docker/stats", {"dry_run": True}, token=api_token)
        check(api_stats["command"] == ["docker", "stats", "--no-stream", "--format", "{{json .}}"], "API docker stats should use real stats command")
        api_assign_port = free_port()
        api_assigned = post_json(
            api_port,
            "/v1/ports/assign",
            {"agent": "api-agent", "project": str(tmp), "name": "api-pinned", "port": api_assign_port},
            token=api_token,
        )
        check(api_assigned.get("port") == api_assign_port, "API port assign should pin the requested port")
        api_assignments = get_json(api_port, "/v1/ports/assignments", token=api_token)
        check(
            any(item.get("name") == "api-pinned" and item.get("port") == api_assign_port for item in api_assignments),
            "API assignments listing should include the new pin",
        )
        api_unassigned = post_json(
            api_port,
            "/v1/ports/unassign",
            {"agent": "api-agent", "project": str(tmp), "name": "api-pinned"},
            token=api_token,
        )
        check(api_unassigned.get("status") == "unassigned", "API port unassign should remove the pin")
        state = get_json(api_port, "/v1/state", token=api_token)
        history_types = {item["type"] for item in state["history"]}
        check("port.leased" in history_types and "server.stopped" in history_types, "state should retain action history")

        remote_port = free_port()
        remote_api = subprocess.run(
            [sys.executable, str(SCRIPT), "api", "serve", "--host", "0.0.0.0", "--port", str(remote_port)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=fake_env,
            timeout=5,
        )
        check(remote_api.returncode != 0, "API must refuse wildcard/non-loopback bind addresses")
        check("non-loopback" in remote_api.stderr, f"remote bind refusal should explain the boundary: {remote_api.stderr}")
        ipv6_api = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "api",
                "serve",
                "--host",
                "::1",
                "--port",
                str(free_port()),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=fake_env,
            timeout=5,
        )
        check(ipv6_api.returncode != 0, "API must fail before bind when explicit IPv6 is unsupported")
        check(
            "IPv4 loopback only" in ipv6_api.stderr and "127.0.0.1" in ipv6_api.stderr,
            f"IPv6 refusal should accurately name the supported bind surface: {ipv6_api.stderr}",
        )
        unsafe_token_file = tmp / "unsafe-api-token"
        unsafe_token_file.write_text("x" * 64, encoding="utf-8")
        unsafe_token_file.chmod(0o644)
        unsafe_token_api = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "api",
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                str(free_port()),
                "--token-file",
                str(unsafe_token_file),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=fake_env,
            timeout=5,
        )
        check(unsafe_token_api.returncode != 0, "API must reject a group/world-readable token file")
        check("group or others" in unsafe_token_api.stderr, "unsafe token refusal should explain required permissions")

        oversized_token_file = tmp / "oversized-api-token"
        oversized_token_file.write_text("x" * (dc.API_TOKEN_MAX_BYTES + 1), encoding="utf-8")
        oversized_token_file.chmod(0o600)
        oversized_token_api = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "api",
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                str(free_port()),
                "--token-file",
                str(oversized_token_file),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=fake_env,
            timeout=5,
        )
        check(oversized_token_api.returncode != 0, "API must reject an oversized private token file")
        check("exceeds" in oversized_token_api.stderr, "oversized token refusal should explain the bound")

        fifo_token_file = tmp / "fifo-api-token"
        os.mkfifo(fifo_token_file, 0o600)
        fifo_token_api = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "api",
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                str(free_port()),
                "--token-file",
                str(fifo_token_file),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=fake_env,
            timeout=5,
        )
        check(fifo_token_api.returncode != 0, "API must reject a FIFO token path without blocking")
        check("regular file" in fifo_token_api.stderr, "FIFO token refusal should require a regular file")

        # Concurrent first startup must converge on exactly one persisted
        # credential. Pause the winner after it exclusively creates the final
        # path but before it writes. A check-then-open loser observes an empty
        # file and fails; a serialized creator waits, then reads the complete
        # winning credential.
        concurrent_token_file = tmp / "concurrent-api-token"
        token_results: list[str] = []
        token_errors: list[str] = []
        token_results_lock = threading.Lock()
        writer_has_created = threading.Event()
        release_writer = threading.Event()
        original_fdopen = dc.os.fdopen

        def paused_token_writer(fd: int, mode: str = "r", *args: object, **kwargs: object):
            if str(mode).startswith("w") and not writer_has_created.is_set():
                writer_has_created.set()
                release_writer.wait(timeout=15)
            return original_fdopen(fd, mode, *args, **kwargs)

        def initialize_token() -> None:
            try:
                value = dc.load_or_create_api_token(concurrent_token_file)
                with token_results_lock:
                    token_results.append(value)
            except Exception as exc:  # pragma: no cover - failure is asserted below
                with token_results_lock:
                    token_errors.append(repr(exc))

        dc.os.fdopen = paused_token_writer
        token_threads: list[threading.Thread] = []
        loser_waited_for_winner = False
        try:
            winner = threading.Thread(target=initialize_token)
            winner.start()
            token_threads.append(winner)
            check(
                writer_has_created.wait(timeout=15),
                "token winner should reach the pre-write fixture gate; "
                f"results={token_results} errors={token_errors}",
            )
            loser = threading.Thread(target=initialize_token)
            loser.start()
            token_threads.append(loser)
            time.sleep(0.2)
            loser_waited_for_winner = loser.is_alive() and not token_errors and not token_results
        finally:
            release_writer.set()
            for thread in token_threads:
                thread.join(timeout=15)
            dc.os.fdopen = original_fdopen
        token_threads_alive = [thread.name for thread in token_threads if thread.is_alive()]
        check(
            not token_threads_alive,
            f"concurrent token workers did not terminate: {token_threads_alive}; errors={token_errors}",
        )
        check(loser_waited_for_winner, "a concurrent token loser must wait while the winner's file is incomplete")
        check(not token_errors, f"concurrent token initialization should not fail: {token_errors}")
        check(len(token_results) == 2, f"both concurrent token callers should return: {token_results}")
        check(
            len(set(token_results)) == 1
            and token_results[0] == concurrent_token_file.read_text(encoding="utf-8").strip(),
            "concurrent first token creation must return the single credential persisted on disk",
        )
        check(
            dc.load_or_create_api_token(concurrent_token_file) == token_results[0],
            "a legitimate existing private token must remain reusable",
        )

        # Both token path entry points must inspect the path the caller named,
        # not resolve a symlink first and then inspect the regular-file target.
        symlink_target = tmp / "symlink-token-target"
        symlink_target.write_text("s" * 64, encoding="utf-8")
        symlink_target.chmod(0o600)
        explicit_symlink = tmp / "explicit-api-token-link"
        explicit_symlink.symlink_to(symlink_target)
        explicit_symlink_api = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "api",
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                str(free_port()),
                "--token-file",
                str(explicit_symlink),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=fake_env,
            timeout=5,
        )
        check(explicit_symlink_api.returncode != 0, "--token-file must reject a symbolic link")
        check("symbolic link" in explicit_symlink_api.stderr, "explicit symlink refusal should explain the boundary")

        default_symlink_home = tmp / "default-symlink-home"
        default_symlink_home.mkdir(mode=0o700)
        (default_symlink_home / "api-token").symlink_to(symlink_target)
        default_symlink_env = fake_env.copy()
        default_symlink_env["CODEX_AGENT_COORDINATOR_HOME"] = str(default_symlink_home)
        default_symlink_env.pop("CODEX_AGENT_COORDINATOR_TOKEN_FILE", None)
        default_symlink_api = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "api",
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                str(free_port()),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=default_symlink_env,
            timeout=5,
        )
        check(default_symlink_api.returncode != 0, "the default/environment token path must reject a symbolic link")
        check("symbolic link" in default_symlink_api.stderr, "default symlink refusal should explain the boundary")

        # --- Concurrency: parallel port leases must never double-assign a port ---
        # lease_port runs inside locked_state (one flock across read-modify-write),
        # so concurrent leasers must serialize and receive distinct ports.
        concurrency_range = "38000-38999"
        lease_results: list[dict] = []
        lease_errors: list[str] = []
        lease_lock = threading.Lock()

        def lease_worker(agent_name: str) -> None:
            try:
                leased = run(
                    ["port", "lease", "--agent", agent_name, "--project", str(tmp), "--range", concurrency_range, "--ttl", "120"],
                    env=env,
                )
            except AssertionError as exc:
                with lease_lock:
                    lease_errors.append(str(exc))
                return
            with lease_lock:
                lease_results.append(leased)

        lease_threads = [threading.Thread(target=lease_worker, args=(f"conc-agent-{index}",)) for index in range(6)]
        for thread in lease_threads:
            thread.start()
        for thread in lease_threads:
            thread.join()
        check(not lease_errors, f"concurrent port leases should all succeed: {lease_errors}")
        concurrency_ports = [item["port"] for item in lease_results]
        check(len(concurrency_ports) == 6, f"all concurrent leases should return a port: {concurrency_ports}")
        check(
            len(set(concurrency_ports)) == len(concurrency_ports),
            f"concurrent leases must not double-assign a port: {sorted(concurrency_ports)}",
        )
        concurrency_state = run(["state", "show"], env=env)
        active_lease_ports = [
            lease["port"] for lease in concurrency_state["leases"].values() if lease.get("status") == "active"
        ]
        check(
            len(active_lease_ports) == len(set(active_lease_ports)),
            "coordinator state must never hold two active leases on the same port",
        )

        # State identity must not shell out to Git while leasing. A fake Git
        # binary that sleeps represents a credential helper, networked
        # worktree, or wedged executable; the lease path should never invoke it.
        slow_git_bin = tmp / "slow-git-bin"
        slow_git_bin.mkdir()
        slow_git = slow_git_bin / "git"
        slow_git.write_text(
            "#!/usr/bin/env python3\nimport time\ntime.sleep(2)\nraise SystemExit(1)\n",
            encoding="utf-8",
        )
        slow_git.chmod(0o755)
        slow_git_env = env.copy()
        slow_git_env["PATH"] = f"{slow_git_bin}:{slow_git_env.get('PATH', '')}"
        slow_git_port = free_port()
        slow_git_started = time.monotonic()
        slow_git_lease = run(
            [
                "port",
                "lease",
                "--agent",
                "slow-git-guard",
                "--project",
                str(tmp),
                "--range",
                f"{slow_git_port}-{slow_git_port}",
            ],
            env=slow_git_env,
        )
        slow_git_elapsed = time.monotonic() - slow_git_started
        check(slow_git_lease["port"] == slow_git_port, "lease should work without invoking Git")
        check(
            slow_git_elapsed < 0.75,
            f"port lease invoked slow Git discovery or held the lock for {slow_git_elapsed:.2f}s",
        )

        # --- Slow process startup must not monopolize the cross-agent state lock ---
        slow_port = free_port()
        independent_port = free_port()
        slow_start = subprocess.Popen(
            [
                sys.executable,
                str(SCRIPT),
                "server",
                "start",
                "--agent",
                "slow-agent",
                "--project",
                str(tmp),
                "--name",
                "slow-start",
                "--cwd",
                str(tmp),
                "--argv",
                json.dumps([sys.executable, "-c", "import time; time.sleep(2)"]),
                "--range",
                f"{slow_port}-{slow_port}",
                "--health-timeout",
                "1.5",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        time.sleep(0.25)
        lease_started = time.monotonic()
        independent_lease = run(
            [
                "port",
                "lease",
                "--agent",
                "independent-agent",
                "--project",
                str(tmp),
                "--range",
                f"{independent_port}-{independent_port}",
            ],
            env=env,
        )
        lease_elapsed = time.monotonic() - lease_started
        slow_stdout, slow_stderr = slow_start.communicate(timeout=10)
        check(slow_start.returncode == 0, f"slow start fixture should complete: {slow_stdout}\n{slow_stderr}")
        check(independent_lease["port"] == independent_port, "independent lease should succeed during startup")
        check(lease_elapsed < 0.75, f"slow server startup held the state lock for {lease_elapsed:.2f}s")

        # The project-level convenience path must obey the same lock boundary.
        # This realistic runtime declaration used to call the legacy start and
        # health routines while holding `state.lock`, blocking every other agent.
        slow_project = tmp / "slow-project-start"
        (slow_project / ".codex").mkdir(parents=True)
        slow_project_port = free_port()
        slow_project_independent_port = free_port()
        (slow_project / ".codex" / "dev-runtime.json").write_text(
            json.dumps(
                {
                    "name": "slow-project",
                    "servers": [
                        {
                            "name": "slow-worker",
                            "role": "worker",
                            "port": slow_project_port,
                            "cwd": ".",
                            "argv": [sys.executable, "-c", "import time; time.sleep(2)"],
                            "health_timeout": 1.25,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        no_docker_bin = tmp / "slow-project-no-docker-bin"
        no_docker_bin.mkdir()
        no_docker_cli = no_docker_bin / "docker"
        no_docker_cli.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        no_docker_cli.chmod(0o755)
        slow_project_env = env.copy()
        slow_project_env["PATH"] = f"{no_docker_bin}:{slow_project_env.get('PATH', '')}"
        slow_project_started_at = time.monotonic()
        slow_project_start = subprocess.Popen(
            [
                sys.executable,
                str(SCRIPT),
                "project",
                "start",
                "--agent",
                "slow-project-agent",
                "--project",
                str(slow_project),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=slow_project_env,
        )
        conflict_ready_deadline = time.monotonic() + 3
        while time.monotonic() < conflict_ready_deadline:
            if slow_project_start.poll() is not None:
                stdout, stderr = slow_project_start.communicate()
                raise AssertionError(
                    "slow project fixture exited before reserving its operation: "
                    f"{stdout}\n{stderr}"
                )
            conflict_state = run(["state", "show"], env=slow_project_env)
            if any(
                operation.get("status") == "pending"
                and operation.get("action") == "project.start"
                and operation.get("project") == str(slow_project.resolve())
                for operation in conflict_state.get("operations", {}).values()
            ):
                break
            time.sleep(0.02)
        else:
            raise AssertionError("slow project fixture did not reserve its operation in time")
        conflicting_project_started = time.monotonic()
        conflicting_project = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "project",
                "stop",
                "--agent",
                "conflicting-project-agent",
                "--project",
                str(slow_project),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=slow_project_env,
            timeout=5,
        )
        conflicting_project_elapsed = time.monotonic() - conflicting_project_started
        check(
            conflicting_project.returncode != 0,
            "a second lifecycle mutation for the same project must not overlap the reserved operation",
        )
        check(
            "operation already in progress" in f"{conflicting_project.stdout}\n{conflicting_project.stderr}",
            "same-project lifecycle conflict should explain the active operation; "
            f"stdout={conflicting_project.stdout!r} stderr={conflicting_project.stderr!r}",
        )
        check(
            conflicting_project_elapsed < 0.75,
            f"same-project conflict detection should be a short atomic check, took {conflicting_project_elapsed:.2f}s",
        )
        project_lease_started = time.monotonic()
        project_independent_lease = run(
            [
                "port",
                "lease",
                "--agent",
                "project-independent-agent",
                "--project",
                str(tmp),
                "--range",
                f"{slow_project_independent_port}-{slow_project_independent_port}",
            ],
            env=env,
        )
        project_lease_elapsed = time.monotonic() - project_lease_started
        project_stdout, project_stderr = slow_project_start.communicate(timeout=20)
        slow_project_total_elapsed = time.monotonic() - slow_project_started_at
        check(
            slow_project_start.returncode == 0,
            f"slow project fixture should finish with a report: {project_stdout}\n{project_stderr}",
        )
        check(
            project_independent_lease["port"] == slow_project_independent_port,
            "independent lease should succeed during project startup",
        )
        check(
            project_lease_elapsed < 0.75,
            f"slow project startup held the state lock for {project_lease_elapsed:.2f}s",
        )
        check(
            slow_project_total_elapsed < 12,
            f"slow project fixture exceeded its finite non-deadlock budget: {slow_project_total_elapsed:.2f}s",
        )
        slow_project_state = run(["state", "show"], env=env)
        slow_project_operations = [
            operation
            for operation in slow_project_state.get("operations", {}).values()
            if operation.get("action") == "project.start"
            and operation.get("project") == str(slow_project.resolve())
        ]
        check(slow_project_operations, "project start should leave durable operation evidence")
        check(
            slow_project_operations[-1].get("status") == "completed",
            f"project operation should commit after the slow work: {slow_project_operations[-1]}",
        )
        check(
            (slow_project_operations[-1].get("result") or {}).get("action") == "start",
            "project operation evidence should include its committed result summary",
        )
        check(
            not any(
                operation.get("target") == f"project:{slow_project.resolve()}"
                and operation.get("status") == "pending"
                for operation in slow_project_state.get("operations", {}).values()
            ),
            "completed project lifecycle work must not leave a pending reservation",
        )
        slow_project_servers = [
            server
            for server in slow_project_state.get("servers", {}).values()
            if server.get("project") == str(slow_project.resolve()) and server.get("name") == "slow-worker"
        ]
        check(
            len(slow_project_servers) == 1,
            f"same-project conflict guard must prevent duplicate logical servers: {slow_project_servers}",
        )

        # --- A process crash between reservation and launch is reconciled ---
        abandoned_port = free_port()
        abandoned_lease = run(
            [
                "port",
                "lease",
                "--agent",
                "crashed-agent",
                "--project",
                str(tmp),
                "--range",
                f"{abandoned_port}-{abandoned_port}",
            ],
            env=env,
        )
        state_file = Path(env["CODEX_AGENT_COORDINATOR_HOME"]) / "state.json"
        abandoned_state = json.loads(state_file.read_text(encoding="utf-8"))
        abandoned_server_id = "abandoned-server"
        abandoned_operation_id = "abandoned-operation"
        abandoned_state["leases"][abandoned_lease["id"]]["server_id"] = abandoned_server_id
        abandoned_state["servers"][abandoned_server_id] = {
            "id": abandoned_server_id,
            "key": f"{tmp.resolve()}::abandoned",
            "name": "abandoned",
            "project": str(tmp.resolve()),
            "status": "starting",
            "pid": None,
            "lease_id": abandoned_lease["id"],
            "operation_id": abandoned_operation_id,
        }
        abandoned_state.setdefault("operations", {})[abandoned_operation_id] = {
            "id": abandoned_operation_id,
            "action": "server.start",
            "target": f"server:{tmp.resolve()}::abandoned",
            "agent": "crashed-agent",
            "project": str(tmp.resolve()),
            "generation": 1,
            "status": "pending",
            "phase": "reserved",
            "owner_pid": 2_147_483_647,
            "lease_id": abandoned_lease["id"],
            "server_id": abandoned_server_id,
            "created_at": "2020-01-01T00:00:00Z",
        }
        state_file.write_text(json.dumps(abandoned_state), encoding="utf-8")
        reconciled_state = run(["state", "show"], env=env)
        check(
            abandoned_lease["id"] not in reconciled_state["leases"],
            "abandoned pre-launch reservation must release its lease",
        )
        check(
            reconciled_state["operations"][abandoned_operation_id]["status"] == "failed",
            "abandoned operation must be marked failed during reconciliation",
        )
        check(
            reconciled_state["servers"][abandoned_server_id]["status"] == "stopped",
            "abandoned pre-launch server record must become stopped evidence",
        )

        # Exact manual-lease reconciliation has a different ownership boundary
        # from a coordinator-allocated start. Before launch, it restores the
        # same manual lease; once launch may have begun, it quarantines that
        # exact lease instead of making the port look reusable.
        def abandoned_manual_attachment(phase: str) -> tuple[dict, str, str, str]:
            attachment_state = dc.default_state()
            lease_id = f"manual-{phase}-lease"
            server_id = f"manual-{phase}-server"
            operation_id = f"manual-{phase}-operation"
            attachment_state["leases"][lease_id] = {
                "id": lease_id,
                "port": free_port(),
                "agent": "manual-crashed-agent",
                "project": str(tmp.resolve()),
                "purpose": "manual",
                "original_purpose": "manual",
                "server_id": None,
                "pending_operation_id": operation_id,
                "pending_server_id": server_id,
                "status": "active",
                "expires_at": dc.now() + 60,
            }
            attachment_state["servers"][server_id] = {
                "id": server_id,
                "key": f"{tmp.resolve()}::{server_id}",
                "name": server_id,
                "project": str(tmp.resolve()),
                "status": "starting",
                "pid": None,
                "lease_id": lease_id,
                "operation_id": operation_id,
            }
            attachment_state["operations"][operation_id] = {
                "id": operation_id,
                "action": "server.start",
                "target": f"server:{tmp.resolve()}::{server_id}",
                "agent": "manual-crashed-agent",
                "project": str(tmp.resolve()),
                "generation": 1,
                "status": "pending",
                "phase": phase,
                "lease_source": "manual",
                "owner_pid": 2_147_483_647,
                "owner_thread": 0,
                "lease_id": lease_id,
                "server_id": server_id,
                "created_at": "2020-01-01T00:00:00Z",
                "created_ts": dc.now(),
            }
            dc.reconcile_operations(attachment_state)
            dc.prune_expired_leases(attachment_state)
            return attachment_state, lease_id, server_id, operation_id

        manual_reserved_state, manual_reserved_lease_id, manual_reserved_server_id, _ = (
            abandoned_manual_attachment("reserved")
        )
        manual_reserved_lease = manual_reserved_state["leases"][manual_reserved_lease_id]
        check(
            manual_reserved_lease["purpose"] == "manual"
            and not manual_reserved_lease.get("server_id")
            and manual_reserved_lease["attachment_status"] == "rolled_back_before_launch"
            and manual_reserved_state["servers"][manual_reserved_server_id]["status"] == "stopped",
            f"abandoned pre-launch manual attachment should restore its exact lease: {manual_reserved_state}",
        )
        manual_launching_state, manual_launching_lease_id, manual_launching_server_id, _ = (
            abandoned_manual_attachment("launching")
        )
        manual_launching_lease = manual_launching_state["leases"][manual_launching_lease_id]
        check(
            manual_launching_lease["server_id"] == manual_launching_server_id
            and manual_launching_lease["purpose"].startswith("server:")
            and manual_launching_lease["attachment_status"] == "launch_outcome_unknown"
            and manual_launching_lease["reconciliation_required"] is True
            and manual_launching_state["servers"][manual_launching_server_id]["status"] == "orphaned",
            f"abandoned post-launch-boundary attachment should quarantine its exact lease: {manual_launching_state}",
        )

        # --- Stopped-server records past retention are pruned so state does not grow unbounded ---
        crafted_state = {
            "version": 1,
            "created_at": "2020-01-01T00:00:00Z",
            "updated_at": "2020-01-01T00:00:00Z",
            "leases": {},
            "servers": {
                "old-stopped": {
                    "id": "old-stopped",
                    "name": "old",
                    "project": str(tmp),
                    "status": "stopped",
                    "stopped_at": "2020-01-01T00:00:00Z",
                    "stopped_ts": time.time() - (30 * 24 * 60 * 60),
                },
                "fresh-stopped": {
                    "id": "fresh-stopped",
                    "name": "fresh",
                    "project": str(tmp),
                    "status": "stopped",
                    "stopped_at": "2020-01-01T00:00:00Z",
                    "stopped_ts": time.time(),
                },
            },
            "history": [],
            "docker": {"last_commands": [], "stats_history": {}, "metadata": {}},
        }
        state_file.write_text(json.dumps(crafted_state), encoding="utf-8")
        pruned_state = run(["state", "show"], env=env)
        check("old-stopped" not in pruned_state["servers"], "stopped servers past retention should be pruned from state")
        check("fresh-stopped" in pruned_state["servers"], "recent stopped servers should be retained in state")

        # --- A corrupt state file must recover instead of crashing read-only commands ---
        state_file.write_text("{ this is not valid json", encoding="utf-8")
        recovered = run(["inventory", "--project", str(tmp), "--no-docker"], env=env)
        check("servers" in recovered, "inventory should recover from a corrupt state file instead of crashing")
        corrupt_backups = list(state_file.parent.glob("state.json.corrupt-*"))
        check(bool(corrupt_backups), "corrupt state file should be backed up for forensics")

        # --- server_health classification: fresh+unreachable -> starting, aged -> unhealthy ---
        original_identity = dc.server_listener_identity
        original_pid_alive = dc.pid_alive
        try:
            dc.server_listener_identity = lambda server: {"ok": True}
            dc.pid_alive = lambda pid: True
            closed_port = free_port()
            starting_health = dc.server_health({"pid": 1, "port": closed_port, "created_ts": dc.now()})
            check(starting_health["classification"] == "starting", f"fresh unreachable server should be 'starting': {starting_health}")
            aged_health = dc.server_health({"pid": 1, "port": closed_port, "created_ts": dc.now() - 600})
            check(aged_health["classification"] == "unhealthy", f"aged unreachable server should be 'unhealthy': {aged_health}")
            retried_health = dc.server_health({"pid": 1, "port": closed_port, "created_ts": dc.now()}, attempts=3)
            check(retried_health.get("attempts") == 3, "server_health should honor the retry attempts count")
        finally:
            dc.server_listener_identity = original_identity
            dc.pid_alive = original_pid_alive

        # A project lifecycle reservation owns its server/Docker mutation
        # boundary. Direct child work is rejected in both directions, while an
        # explicitly delegated child records the parent operation id.
        hierarchy_project = str((tmp / "hierarchy-owner").resolve())
        hierarchy_other_project = str((tmp / "hierarchy-other").resolve())
        hierarchy_state = dc.default_state()
        parent_operation = dc.begin_operation(
            hierarchy_state,
            action="project.start",
            target=f"project:{hierarchy_project}",
            agent="project-agent",
            project=hierarchy_project,
            generation=1,
        )
        for child_target in (
            f"server:{hierarchy_project}::web",
            "docker:hierarchy-owner-postgres",
            "docker-metadata:hierarchy-owner-postgres",
        ):
            try:
                dc.begin_operation(
                    hierarchy_state,
                    action="child.direct",
                    target=child_target,
                    agent="direct-agent",
                    project=hierarchy_project,
                    generation=2,
                )
            except RuntimeError as exc:
                check("operation already in progress" in str(exc), f"child conflict should be explicit: {exc}")
            else:
                raise AssertionError(f"pending project operation must block direct child mutation {child_target}")
        with dc.delegated_project_operation(parent_operation):
            delegated_child = dc.begin_operation(
                hierarchy_state,
                action="server.start",
                target=f"server:{hierarchy_project}::web",
                agent="project-agent",
                project=hierarchy_project,
                generation=2,
            )
        check(
            delegated_child.get("parent_operation_id") == parent_operation["id"],
            f"delegated child should retain its exact parent capability: {delegated_child}",
        )
        dc.finish_operation(
            hierarchy_state,
            delegated_child["id"],
            status="completed",
            phase="committed",
        )
        dc.finish_operation(
            hierarchy_state,
            parent_operation["id"],
            status="completed",
            phase="committed",
        )

        pending_child = dc.begin_operation(
            hierarchy_state,
            action="server.stop",
            target=f"server:{hierarchy_project}::web",
            agent="direct-agent",
            project=hierarchy_project,
            generation=3,
        )
        try:
            dc.begin_operation(
                hierarchy_state,
                action="project.restart",
                target=f"project:{hierarchy_project}",
                agent="project-agent",
                project=hierarchy_project,
                generation=4,
            )
        except RuntimeError as exc:
            check("operation already in progress" in str(exc), f"project conflict should be explicit: {exc}")
        else:
            raise AssertionError("a pending child mutation must block a project lifecycle reservation")
        unrelated_child = dc.begin_operation(
            hierarchy_state,
            action="server.start",
            target=f"server:{hierarchy_project}::worker",
            agent="other-agent",
            project=hierarchy_project,
            generation=1,
        )
        other_project_operation = dc.begin_operation(
            hierarchy_state,
            action="project.start",
            target=f"project:{hierarchy_other_project}",
            agent="other-agent",
            project=hierarchy_other_project,
            generation=1,
        )
        check(
            unrelated_child["status"] == "pending" and other_project_operation["status"] == "pending",
            "unrelated child and other-project mutations should not be over-serialized",
        )
        dc.finish_operation(hierarchy_state, pending_child["id"], status="completed", phase="committed")
        dc.finish_operation(hierarchy_state, unrelated_child["id"], status="completed", phase="committed")
        dc.finish_operation(
            hierarchy_state,
            other_project_operation["id"],
            status="completed",
            phase="committed",
        )

        restart_parent = dc.begin_operation(
            hierarchy_state,
            action="server.restart",
            target=f"server:{hierarchy_project}::api",
            agent="restart-agent",
            project=hierarchy_project,
            generation=1,
        )
        try:
            dc.begin_operation(
                hierarchy_state,
                action="server.stop",
                target=f"server:{hierarchy_project}::api",
                agent="interleaving-agent",
                project=hierarchy_project,
                generation=2,
            )
        except RuntimeError as exc:
            check("operation already in progress" in str(exc), f"restart conflict should be explicit: {exc}")
        else:
            raise AssertionError("a direct stop must not interleave with a reserved direct restart")
        with dc.delegated_server_restart_operation(restart_parent):
            restart_stop_child = dc.begin_operation(
                hierarchy_state,
                action="server.stop",
                target=f"server:{hierarchy_project}::api",
                agent="restart-agent",
                project=hierarchy_project,
                generation=2,
            )
        check(
            restart_stop_child.get("parent_operation_id") == restart_parent["id"],
            "restart stop child should carry the exact outer restart capability",
        )
        dc.finish_operation(
            hierarchy_state,
            restart_stop_child["id"],
            status="completed",
            phase="committed",
        )
        with dc.delegated_server_restart_operation(restart_parent):
            restart_start_child = dc.begin_operation(
                hierarchy_state,
                action="server.start",
                target=f"server:{hierarchy_project}::api",
                agent="restart-agent",
                project=hierarchy_project,
                generation=3,
            )
        check(
            restart_start_child.get("parent_operation_id") == restart_parent["id"],
            "restart start child should carry the exact outer restart capability",
        )
        dc.finish_operation(
            hierarchy_state,
            restart_start_child["id"],
            status="completed",
            phase="committed",
        )
        dc.finish_operation(
            hierarchy_state,
            restart_parent["id"],
            status="completed",
            phase="committed",
        )

        # Age alone must never retire a positively live process instance.
        live_owner_state = dc.default_state()
        live_old_operation = dc.begin_operation(
            live_owner_state,
            action="project.start",
            target=f"project:{hierarchy_project}",
            agent="live-agent",
            project=hierarchy_project,
            generation=1,
        )
        live_old_operation["created_ts"] = dc.now() - dc.OPERATION_STALE_SECONDS - 60
        dc.reconcile_operations(live_owner_state)
        check(
            live_owner_state["operations"][live_old_operation["id"]]["status"] == "pending",
            "an old operation with a verified live owner instance must remain pending",
        )
        dc.finish_operation(
            live_owner_state,
            live_old_operation["id"],
            status="completed",
            phase="committed",
        )

        # The same numeric PID with a different, unlocked instance marker is a
        # reused PID, not proof that the original operation owner survived.
        reused_pid_state = dc.default_state()
        reused_operation_id = "reused-pid-operation"
        reused_pid_state["operations"][reused_operation_id] = {
            "id": reused_operation_id,
            "action": "project.start",
            "target": f"project:{hierarchy_project}",
            "agent": "old-agent",
            "project": hierarchy_project,
            "generation": 1,
            "status": "pending",
            "phase": "reserved",
            "owner_pid": os.getpid(),
            "owner_thread": threading.get_ident(),
            "owner_instance_id": "f" * 32,
            "created_ts": dc.now(),
            "created_at": dc.iso_timestamp(),
        }
        dc.reconcile_operations(reused_pid_state)
        check(
            reused_pid_state["operations"][reused_operation_id]["status"] == "failed",
            "a reused PID without the original process-instance lock must be reconciled",
        )

        dead_owner_state = dc.default_state()
        dead_operation_id = "dead-owner-operation"
        dead_owner_state["operations"][dead_operation_id] = {
            "id": dead_operation_id,
            "action": "project.start",
            "target": f"project:{hierarchy_project}",
            "agent": "dead-agent",
            "project": hierarchy_project,
            "generation": 1,
            "status": "pending",
            "phase": "reserved",
            "owner_pid": 2_147_483_647,
            "owner_thread": 0,
            "created_ts": dc.now(),
            "created_at": dc.iso_timestamp(),
        }
        dc.reconcile_operations(dead_owner_state)
        check(
            dead_owner_state["operations"][dead_operation_id]["status"] == "failed",
            "a genuinely dead legacy owner must still reconcile normally",
        )

        # Read-only observations reserve per-server tickets. A later-started
        # observation must win regardless of which health check finishes first.
        observation_project = tmp / "observation-owner"
        observation_project.mkdir()
        observation_server_id = "observation-server"
        with dc.locked_state() as coordinator_state:
            coordinator_state["servers"][observation_server_id] = {
                "id": observation_server_id,
                "key": f"{observation_project.resolve()}::web",
                "project": str(observation_project.resolve()),
                "name": "web",
                "generation": 7,
                "operation_id": "completed-start",
                "pid": 4242,
                "lease_id": None,
                "port": free_port(),
                "host": "127.0.0.1",
                "created_at": "fixed",
                "status": "starting",
                "health": {"ok": False},
                "updated_at": "baseline",
            }
        stale_baseline = dc.snapshot_runtime_observation(project=str(observation_project.resolve()))
        stale_observed = copy.deepcopy(stale_baseline)
        stale_observed["servers"][observation_server_id].update(
            {"status": "unhealthy", "health": {"ok": False, "error": "old timeout"}}
        )
        current_baseline = dc.snapshot_runtime_observation(project=str(observation_project.resolve()))
        current_observed = copy.deepcopy(current_baseline)
        current_observed["servers"][observation_server_id].update(
            {"status": "running", "health": {"ok": True}}
        )
        dc.commit_runtime_observations(current_baseline, current_observed)
        dc.commit_runtime_observations(stale_baseline, stale_observed)
        observation_winner = dc.snapshot_coordinator_state()["servers"][observation_server_id]
        check(
            observation_winner["status"] == "running" and observation_winner["health"]["ok"],
            f"an older observation must not overwrite the newer ticket: {observation_winner}",
        )

        # The no-contention path still commits normally.
        uncontended_baseline = dc.snapshot_runtime_observation(project=str(observation_project.resolve()))
        uncontended_observed = copy.deepcopy(uncontended_baseline)
        uncontended_observed["servers"][observation_server_id].update(
            {"status": "unhealthy", "health": {"ok": False, "error": "current failure"}}
        )
        dc.commit_runtime_observations(uncontended_baseline, uncontended_observed)
        uncontended_result = dc.snapshot_coordinator_state()["servers"][observation_server_id]
        check(
            uncontended_result["status"] == "unhealthy"
            and uncontended_result["health"].get("error") == "current failure",
            f"an uncontended observation should commit: {uncontended_result}",
        )

        # Idempotent start performs health outside the lock. If a newer stop
        # wins during that check, the old healthy result must be rejected.
        original_server_health = dc.server_health
        start_health_entered = threading.Event()
        release_start_health = threading.Event()
        start_race_result: dict[str, object] = {}

        def delayed_existing_health(server: dict) -> dict:
            start_health_entered.set()
            release_start_health.wait(timeout=15)
            return {"ok": True, "classification": "healthy"}

        def idempotent_start_worker() -> None:
            try:
                start_race_result["value"] = dc.coordinated_start_server(
                    {
                        "agent": "review-agent",
                        "project": str(observation_project),
                        "name": "web",
                        "argv": [sys.executable, "-c", "pass"],
                    }
                )
            except Exception as exc:  # expected conflict
                start_race_result["error"] = str(exc)

        with dc.locked_state() as coordinator_state:
            race_server = coordinator_state["servers"][observation_server_id]
            race_server.update(
                {"generation": 10, "operation_id": "old-start", "status": "running", "health": {"ok": True}}
            )
        dc.server_health = delayed_existing_health
        start_race_thread = threading.Thread(target=idempotent_start_worker)
        start_race_thread_started = False
        start_race_thread_alive = False
        try:
            start_race_thread.start()
            start_race_thread_started = True
            check(
                start_health_entered.wait(timeout=15),
                "idempotent start should reach its delayed health check; "
                f"worker evidence: {start_race_result}",
            )
            with dc.locked_state() as coordinator_state:
                stopped_server = coordinator_state["servers"][observation_server_id]
                stopped_server.update(
                    {
                        "generation": 11,
                        "operation_id": "new-stop",
                        "status": "stopped",
                        "health": {"ok": False, "classification": "stopped"},
                    }
                )
            release_start_health.set()
        finally:
            release_start_health.set()
            if start_race_thread_started:
                start_race_thread.join(timeout=15)
                start_race_thread_alive = start_race_thread.is_alive()
            dc.server_health = original_server_health
        check(
            not start_race_thread_alive,
            f"idempotent-start worker did not terminate: {start_race_result}",
        )
        raced_server = dc.snapshot_coordinator_state()["servers"][observation_server_id]
        check(
            "changed while" in str(start_race_result.get("error") or "")
            and raced_server["generation"] == 11
            and raced_server["status"] == "stopped",
            f"a stale idempotent start must not overwrite a newer stop: result={start_race_result} state={raced_server}",
        )

        # With no concurrent lifecycle mutation, the idempotent healthy-start
        # path remains a successful no-op.
        with dc.locked_state() as coordinator_state:
            healthy_server = coordinator_state["servers"][observation_server_id]
            healthy_server.update(
                {"generation": 12, "operation_id": "healthy-start", "status": "running", "health": {"ok": True}}
            )
        dc.server_health = lambda server: {"ok": True, "classification": "healthy"}
        try:
            idempotent_success = dc.coordinated_start_server(
                {
                    "agent": "review-agent",
                    "project": str(observation_project),
                    "name": "web",
                    "argv": [sys.executable, "-c", "pass"],
                }
            )
        finally:
            dc.server_health = original_server_health
        check(
            idempotent_success["status"] == "running" and idempotent_success["generation"] == 12,
            f"an uncontended healthy idempotent start should still succeed: {idempotent_success}",
        )

        # Exercise the real direct restart wrapper at its historical stop/start
        # gap. The outer reservation must reject a direct stop until the
        # delegated start child commits.
        restart_project = tmp / "restart-atomic-owner"
        restart_project.mkdir()
        restart_server_id = "restart-atomic-server"
        restart_server_name = "api"
        with dc.locked_state() as coordinator_state:
            coordinator_state["servers"][restart_server_id] = {
                "id": restart_server_id,
                "key": f"{restart_project.resolve()}::{restart_server_name}",
                "project": str(restart_project.resolve()),
                "name": restart_server_name,
                "cwd": str(restart_project.resolve()),
                "argv_template": [sys.executable, "-c", "pass"],
                "cmd_template": None,
                "env": {},
                "generation": 1,
                "operation_id": "initial-start",
                "pid": 2_147_483_647,
                "lease_id": None,
                "port": free_port(),
                "host": "127.0.0.1",
                "created_at": "fixed",
                "status": "running",
                "health": {"ok": True},
            }
        original_start_server = dc.coordinated_start_server
        original_server_health = dc.server_health
        restart_gap_entered = threading.Event()
        release_restart_gap = threading.Event()
        restart_thread_result: dict[str, object] = {}

        def delegated_gap_start(options: dict) -> dict:
            restart_gap_entered.set()
            release_restart_gap.wait(timeout=15)
            with dc.locked_state() as coordinator_state:
                current = coordinator_state["servers"][restart_server_id]
                child_generation = int(current.get("generation") or 0) + 1
                child = dc.begin_operation(
                    coordinator_state,
                    action="server.start",
                    target=f"server:{restart_project.resolve()}::{restart_server_name}",
                    agent=str(options["agent"]),
                    project=str(restart_project),
                    generation=child_generation,
                    server_id=restart_server_id,
                )
                current.update(
                    {
                        "generation": child_generation,
                        "operation_id": child["id"],
                        "status": "running",
                        "health": {"ok": True},
                    }
                )
                dc.finish_operation(
                    coordinator_state,
                    child["id"],
                    status="completed",
                    phase="committed",
                )
                return copy.deepcopy(current)

        def atomic_restart_worker() -> None:
            try:
                restart_thread_result["value"] = dc.coordinated_restart_server(
                    {
                        "agent": "restart-agent",
                        "project": str(restart_project),
                        "name": restart_server_name,
                    }
                )
            except Exception as exc:
                restart_thread_result["error"] = str(exc)

        dc.server_health = lambda server: {
            "ok": False,
            "identity": {"ok": False},
            "classification": "wrong-listener",
            "pid_alive": False,
        }
        dc.coordinated_start_server = delegated_gap_start
        restart_thread = threading.Thread(target=atomic_restart_worker)
        restart_thread_started = False
        restart_thread_alive = False
        try:
            restart_thread.start()
            restart_thread_started = True
            check(
                restart_gap_entered.wait(timeout=15),
                "restart should reach the delegated stop/start gap; "
                f"worker evidence: {restart_thread_result}",
            )
            try:
                dc.coordinated_stop_server(
                    {
                        "agent": "interleaving-agent",
                        "project": str(restart_project),
                        "name": restart_server_name,
                    }
                )
            except RuntimeError as exc:
                check(
                    "operation already in progress" in str(exc),
                    f"interleaving stop should see the outer restart reservation: {exc}",
                )
            else:
                raise AssertionError("a direct stop must not interleave between restart stop/start children")
        finally:
            release_restart_gap.set()
            if restart_thread_started:
                restart_thread.join(timeout=15)
                restart_thread_alive = restart_thread.is_alive()
            dc.coordinated_start_server = original_start_server
            dc.server_health = original_server_health
        check(
            not restart_thread_alive,
            f"delegated-restart worker did not terminate: {restart_thread_result}",
        )
        check(
            not restart_thread_result.get("error")
            and (restart_thread_result.get("value") or {}).get("status") == "running",
            f"the delegated direct restart should complete after the gap: {restart_thread_result}",
        )
        restart_atomic_state = dc.snapshot_coordinator_state()
        check(
            any(
                operation.get("action") == "server.restart"
                and operation.get("server_id") == restart_server_id
                and operation.get("status") == "completed"
                for operation in restart_atomic_state.get("operations", {}).values()
            ),
            "direct restart should retain completed outer operation evidence",
        )

        # Exact-lease attachment reserves both the server target and lease
        # before checking the OS port. Port release and project lifecycle work
        # must not interleave through that external-check window.
        lease_interleave_project = tmp / "lease-interleave-owner"
        lease_interleave_project.mkdir()
        lease_interleave_port = free_port()
        with dc.locked_state() as coordinator_state:
            lease_interleave = dc.lease_port(
                coordinator_state,
                agent="lease-interleave-agent",
                project=str(lease_interleave_project),
                port_range=f"{lease_interleave_port}-{lease_interleave_port}",
                purpose="manual",
            )
        original_port_available = dc.port_available
        lease_port_check_entered = threading.Event()
        release_lease_port_check = threading.Event()
        lease_interleave_result: dict[str, object] = {}

        def delayed_lease_port_available(port: int, host: str = "127.0.0.1") -> bool:
            if int(port) == lease_interleave_port:
                lease_port_check_entered.set()
                release_lease_port_check.wait(timeout=15)
                return True
            return original_port_available(port, host)

        def lease_interleave_worker() -> None:
            try:
                lease_interleave_result["value"] = dc.coordinated_start_server(
                    {
                        "agent": "lease-interleave-agent",
                        "project": str(lease_interleave_project),
                        "name": "web",
                        "cwd": str(lease_interleave_project),
                        "argv": [str(lease_interleave_project / "missing-executable")],
                        "lease_id": lease_interleave["id"],
                    }
                )
            except Exception as exc:
                lease_interleave_result["error"] = str(exc)

        dc.port_available = delayed_lease_port_available
        lease_interleave_thread = threading.Thread(target=lease_interleave_worker)
        lease_interleave_thread_started = False
        lease_interleave_thread_alive = False
        pending_operation_id = ""
        try:
            lease_interleave_thread.start()
            lease_interleave_thread_started = True
            check(
                lease_port_check_entered.wait(timeout=15),
                "exact-lease start should reserve state before its external port check; "
                f"worker evidence: {lease_interleave_result}",
            )
            with dc.locked_state() as coordinator_state:
                pending_lease = coordinator_state["leases"][lease_interleave["id"]]
                check(
                    pending_lease.get("pending_operation_id"),
                    f"lease should expose its pending attachment operation: {pending_lease}",
                )
                try:
                    dc.release_port_for_identity(
                        coordinator_state,
                        agent="lease-interleave-agent",
                        project=str(lease_interleave_project),
                        lease_id=lease_interleave["id"],
                    )
                except RuntimeError as exc:
                    check("attachment operation" in str(exc), f"lease release conflict should be explicit: {exc}")
                else:
                    raise AssertionError("port release must not interleave with exact-lease attachment")
                try:
                    dc.begin_operation(
                        coordinator_state,
                        action="project.stop",
                        target=f"project:{lease_interleave_project.resolve()}",
                        agent="project-agent",
                        project=str(lease_interleave_project),
                        generation=1,
                    )
                except RuntimeError as exc:
                    check("operation already in progress" in str(exc), f"project conflict should be explicit: {exc}")
                else:
                    raise AssertionError("project lifecycle must not interleave with exact-lease server start")
                pending_operation_id = str(pending_lease["pending_operation_id"])
                pending_lease.pop("pending_operation_id", None)
                pending_lease.pop("pending_server_id", None)
        finally:
            release_lease_port_check.set()
            if lease_interleave_thread_started:
                lease_interleave_thread.join(timeout=15)
                lease_interleave_thread_alive = lease_interleave_thread.is_alive()
            dc.port_available = original_port_available
        check(
            not lease_interleave_thread_alive,
            f"exact-lease worker did not terminate: {lease_interleave_result}",
        )
        check(
            "reservation changed before process launch" in str(lease_interleave_result.get("error") or ""),
            f"changed pre-launch reservation should fail deterministically: {lease_interleave_result}",
        )
        lease_interleave_state = dc.snapshot_coordinator_state()
        rolled_back_interleave_lease = lease_interleave_state["leases"][lease_interleave["id"]]
        check(
            rolled_back_interleave_lease["purpose"] == "manual"
            and not rolled_back_interleave_lease.get("server_id")
            and not rolled_back_interleave_lease.get("pending_operation_id")
            and lease_interleave_state["operations"][pending_operation_id]["status"] == "failed",
            f"pre-launch interleaving fixture should roll back to its manual lease: {rolled_back_interleave_lease}",
        )

        # The same exact-lease core remains usable by an authorized synchronous
        # child of a project lifecycle; the internal capability is recorded and
        # cannot be supplied by a CLI/API caller.
        delegated_lease_project = tmp / "delegated-lease-owner"
        delegated_lease_project.mkdir()
        delegated_lease_port = free_port()
        with dc.locked_state() as coordinator_state:
            delegated_lease = dc.lease_port(
                coordinator_state,
                agent="delegated-lease-agent",
                project=str(delegated_lease_project),
                port_range=f"{delegated_lease_port}-{delegated_lease_port}",
                purpose="manual",
            )
            delegated_lease_parent = dc.begin_operation(
                coordinator_state,
                action="project.start",
                target=f"project:{delegated_lease_project.resolve()}",
                agent="delegated-lease-agent",
                project=str(delegated_lease_project),
                generation=1,
            )
        try:
            with dc.delegated_project_operation(delegated_lease_parent):
                dc.coordinated_start_server(
                    {
                        "agent": "delegated-lease-agent",
                        "project": str(delegated_lease_project),
                        "name": "web",
                        "cwd": str(delegated_lease_project),
                        "argv": [str(delegated_lease_project / "missing-executable")],
                        "lease_id": delegated_lease["id"],
                    }
                )
        except RuntimeError as exc:
            check("launch failed" in str(exc), f"delegated exact-lease child should reach launch: {exc}")
        else:
            raise AssertionError("delegated exact-lease fixture should take its planned launch failure")
        with dc.locked_state() as coordinator_state:
            delegated_children = [
                operation
                for operation in coordinator_state["operations"].values()
                if operation.get("parent_operation_id") == delegated_lease_parent["id"]
                and operation.get("action") == "server.start"
            ]
            check(
                len(delegated_children) == 1 and delegated_children[0]["status"] == "failed",
                f"delegated exact-lease child should retain its parent capability evidence: {delegated_children}",
            )
            dc.finish_operation(
                coordinator_state,
                delegated_lease_parent["id"],
                status="failed",
                phase="child-failed",
                error="planned child launch failure",
            )

        # Name similarity is useful read-only inventory evidence, never enough
        # authority to start, restart, stop, or sidecar-register a container.
        original_docker_inventory = dc.docker_ps_inventory
        original_docker_inspect_state = dc.docker_inspect_state
        original_docker_log_tail = dc.docker_log_tail
        original_coordinated_docker = dc.coordinated_run_docker
        original_coordinated_register = dc.coordinated_register_docker_metadata
        original_resolve_docker = dc.resolve_docker_executable
        original_docker_available_command = dc.docker_available_command
        current_container: dict = {}
        docker_mutations: list[list[str]] = []
        docker_registrations: list[str] = []
        try:
            dc.docker_ps_inventory = lambda **kwargs: {
                "available": True,
                "containers": [dict(current_container)] if current_container else [],
                "postgres": [dict(current_container)] if current_container else [],
            }
            dc.docker_inspect_state = lambda container: None
            dc.docker_log_tail = lambda container, tail=40: ""
            dc.coordinated_run_docker = lambda command, **kwargs: (
                docker_mutations.append(list(command))
                or {"command": list(command), "returncode": 0}
            )
            dc.coordinated_register_docker_metadata = lambda options: (
                docker_registrations.append(str(options["container"]))
                or {"container": options["container"], "metadata_source": "coordinator_sidecar"}
            )
            dc.resolve_docker_executable = lambda **kwargs: str(standard_docker.resolve())
            dc.docker_available_command = lambda args: {
                "ok": True,
                "command": ["docker", *args],
                "docker_executable": str(standard_docker.resolve()),
                "timeout_seconds": dc.DOCKER_OBSERVATION_TIMEOUT_SECONDS,
            }

            heuristic_project = tmp / "heuristic-owner"
            heuristic_project.mkdir()
            current_container = {
                "id": "heuristic123",
                "name": "heuristic-owner-postgres",
                "image": "postgres:16",
                "status": "Exited (0) 1 second ago",
                "ports": "",
                "metadata_source": "none",
            }
            for project_action in ("start", "restart", "stop"):
                docker_mutations.clear()
                docker_registrations.clear()
                report = getattr(dc, f"coordinated_project_runtime_{project_action}")(
                    {"agent": "review-agent", "project": str(heuristic_project)}
                )
                check(
                    not docker_mutations and not docker_registrations,
                    f"project {project_action} must not mutate a same-name unlabeled container: "
                    f"mutations={docker_mutations} registrations={docker_registrations}",
                )
                check(
                    any(
                        item.get("name") == "heuristic-owner-postgres"
                        and item.get("read_only_evidence")
                        and item.get("mutation_authorized") is False
                        for item in report.get("services", [])
                    ),
                    f"project {project_action} should retain same-name Docker evidence as read-only",
                )

            # An explicit runtime declaration is sufficient authority.
            explicit_project = tmp / "explicit-owner"
            (explicit_project / ".codex").mkdir(parents=True)
            (explicit_project / ".codex" / "dev-runtime.json").write_text(
                json.dumps(
                    {
                        "dependencies": [
                            {
                                "type": "docker",
                                "name": "database",
                                "container": "explicit-owner-postgres",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            current_container = {
                "id": "explicit123",
                "name": "explicit-owner-postgres",
                "image": "postgres:16",
                "status": "Exited (0) 1 second ago",
                "ports": "",
                "metadata_source": "none",
            }
            docker_mutations.clear()
            dc.coordinated_project_runtime_start(
                {"agent": "review-agent", "project": str(explicit_project)}
            )
            check(
                ["docker", "start", "explicit-owner-postgres"] in docker_mutations,
                "an explicitly declared container should remain a valid project mutation target",
            )

            # Verified Compose working-directory labels are sufficient authority.
            compose_project = tmp / "verified-compose-owner"
            compose_project.mkdir()
            current_container = {
                "id": "compose123",
                "name": "verified-compose-owner-postgres",
                "image": "postgres:16",
                "status": "Up 1 second",
                "ports": "",
                "project": str(compose_project.resolve()),
                "metadata_source": "docker_labels",
            }
            docker_mutations.clear()
            dc.coordinated_project_runtime_restart(
                {"agent": "review-agent", "project": str(compose_project)}
            )
            check(
                ["docker", "restart", "verified-compose-owner-postgres"] in docker_mutations,
                "verified Compose project provenance should remain a valid mutation authority",
            )

            # Prior sidecar registration is sufficient only with matching
            # project and attributable agent metadata.
            sidecar_project = tmp / "verified-sidecar-owner"
            sidecar_project.mkdir()
            current_container = {
                "id": "sidecar123",
                "name": "verified-sidecar-owner-postgres",
                "image": "postgres:16",
                "status": "Up 1 second",
                "ports": "",
                "project": str(sidecar_project.resolve()),
                "agent": "prior-agent",
                "metadata_source": "coordinator_sidecar",
                "agent_metadata": {
                    "agent": "prior-agent",
                    "project": str(sidecar_project.resolve()),
                },
            }
            docker_mutations.clear()
            dc.coordinated_project_runtime_restart(
                {"agent": "review-agent", "project": str(sidecar_project)}
            )
            check(
                ["docker", "restart", "verified-sidecar-owner-postgres"] in docker_mutations,
                "verified coordinator sidecar provenance should remain a valid mutation authority",
            )
        finally:
            dc.docker_ps_inventory = original_docker_inventory
            dc.docker_inspect_state = original_docker_inspect_state
            dc.docker_log_tail = original_docker_log_tail
            dc.coordinated_run_docker = original_coordinated_docker
            dc.coordinated_register_docker_metadata = original_coordinated_register
            dc.resolve_docker_executable = original_resolve_docker
            dc.docker_available_command = original_docker_available_command

        # Docker name and short/full-id aliases must serialize on the immutable
        # inspected container id, not on the caller's spelling.
        original_inspect_container = dc.inspect_docker_container
        original_resolve_docker = dc.resolve_docker_executable
        original_subprocess_run = dc.subprocess.run
        alias_project = tmp / "docker-alias-owner"
        alias_project.mkdir()
        immutable_container_id = "a" * 64
        docker_command_entered = threading.Event()
        release_docker_command = threading.Event()
        docker_command_calls: list[list[str]] = []
        docker_resolver_calls: list[str] = []
        first_docker_call = True

        class FakeDockerCompleted:
            returncode = 0
            stdout = ""
            stderr = ""

        def blocking_docker_run(command: list[str], **kwargs: object) -> FakeDockerCompleted:
            nonlocal first_docker_call
            docker_command_calls.append(list(command))
            if first_docker_call:
                first_docker_call = False
                docker_command_entered.set()
                release_docker_command.wait(timeout=15)
            return FakeDockerCompleted()

        def fixture_docker_resolver() -> str:
            docker_resolver_calls.append("resolved")
            return "/fixture/docker"

        dc.inspect_docker_container = lambda container: {
            "Id": immutable_container_id,
            "Name": "/alias-db",
            "Config": {"Labels": {}},
        }
        dc.resolve_docker_executable = fixture_docker_resolver
        dc.subprocess.run = blocking_docker_run
        first_alias_result: dict[str, object] = {}

        def first_alias_worker() -> None:
            try:
                first_alias_result["value"] = dc.coordinated_run_docker(
                    ["docker", "restart", "alias-db"],
                    project=str(alias_project),
                    agent="alias-agent",
                    container="alias-db",
                )
            except Exception as exc:
                first_alias_result["error"] = str(exc)

        first_alias_thread = threading.Thread(target=first_alias_worker)
        first_alias_thread_started = False
        first_alias_thread_alive = False
        try:
            first_alias_thread.start()
            first_alias_thread_started = True
            check(
                docker_command_entered.wait(timeout=15),
                "first Docker alias should reach the external command; "
                f"worker evidence: {first_alias_result}",
            )
            try:
                dc.coordinated_run_docker(
                    ["docker", "stop", immutable_container_id[:12]],
                    project=str(alias_project),
                    agent="alias-agent-2",
                    container=immutable_container_id[:12],
                )
            except RuntimeError as exc:
                check(
                    "operation already in progress" in str(exc),
                    f"Docker alias conflict should be explicit: {exc}",
                )
            else:
                raise AssertionError("name and id aliases of one container must not mutate concurrently")
        finally:
            release_docker_command.set()
            if first_alias_thread_started:
                first_alias_thread.join(timeout=15)
                first_alias_thread_alive = first_alias_thread.is_alive()
            dc.inspect_docker_container = original_inspect_container
            dc.resolve_docker_executable = original_resolve_docker
            dc.subprocess.run = original_subprocess_run
        check(
            not first_alias_thread_alive,
            f"Docker alias worker did not terminate: {first_alias_result}",
        )
        check(not first_alias_result.get("error"), f"winning Docker alias should complete: {first_alias_result}")
        check(
            len(docker_command_calls) == 1,
            f"the conflicting alias must be rejected before a second Docker command: {docker_command_calls}",
        )
        check(
            docker_resolver_calls and docker_command_calls[0][0] == "/fixture/docker",
            "Docker alias serialization fixture must isolate executable discovery "
            f"before testing the immutable-id lock: resolvers={docker_resolver_calls}, "
            f"commands={docker_command_calls}",
        )
        alias_state = dc.snapshot_coordinator_state()
        check(
            any(
                operation.get("target") == f"docker:container-id:{immutable_container_id}"
                and operation.get("status") == "completed"
                for operation in alias_state.get("operations", {}).values()
            ),
            "Docker lifecycle evidence should use the immutable inspected container id",
        )
        dc.inspect_docker_container = lambda container: None
        dc.resolve_docker_executable = fixture_docker_resolver
        dc.subprocess.run = lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("Docker mutation must not execute without immutable identity")
        )
        try:
            try:
                dc.coordinated_run_docker(
                    ["docker", "start", "unverified-db"],
                    project=str(alias_project),
                    agent="alias-agent",
                    container="unverified-db",
                )
            except RuntimeError as exc:
                check(
                    "immutable container identity was not verified" in str(exc),
                    f"unverified Docker mutation should fail closed explicitly: {exc}",
                )
            else:
                raise AssertionError("Docker mutation must fail closed when inspect cannot verify identity")
        finally:
            dc.inspect_docker_container = original_inspect_container
            dc.resolve_docker_executable = original_resolve_docker
            dc.subprocess.run = original_subprocess_run

        print("self-test ok")
        return 0
    finally:
        if original_coordinator_home is None:
            os.environ.pop("CODEX_AGENT_COORDINATOR_HOME", None)
        else:
            os.environ["CODEX_AGENT_COORDINATOR_HOME"] = original_coordinator_home
        if api_process and api_process.poll() is None:
            api_process.terminate()
            try:
                api_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                api_process.kill()
        for process in external_processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
        rmtree(tmp, ignore_errors=True)


def shlex_join(parts: list[str]) -> str:
    return " ".join("'" + part.replace("'", "'\"'\"'") + "'" for part in parts)


if __name__ == "__main__":
    raise SystemExit(main())
