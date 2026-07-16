#!/usr/bin/env python3
"""Recall, precision, and convergence tests for Console registration readiness."""

from __future__ import annotations

import ast
import copy
import http.client
import importlib.util
import json
import os
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


READY = load("check_console_registration_ready", ROOT / "check_console_registration_ready.py")
FIXTURES = load("post_cutover_fixture", ROOT / "self_test_post_cutover_registration.py")

FAST_HTTP_SERVER_CODE = r"""
import socketserver
import sys

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(2)
        while True:
            line = self.rfile.readline()
            if not line or line in {b"\r\n", b"\n"}:
                break
        self.wfile.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
        )

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

server = Server(("127.0.0.1", int(sys.argv[1])), Handler)
print(server.server_address[1], flush=True)
server.serve_forever()
"""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def start_fast_http_listener(*, cwd: Path, port: int = 0) -> tuple[subprocess.Popen, int]:
    listener = subprocess.Popen(
        [sys.executable, "-u", "-c", FAST_HTTP_SERVER_CODE, str(port)],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    deadline = time.monotonic() + 5
    try:
        while time.monotonic() < deadline:
            if listener.poll() is not None:
                raise AssertionError(
                    f"fast HTTP listener exited before bind: {listener.returncode}"
                )
            if listener.stdout is not None:
                readable, _, _ = select.select([listener.stdout], [], [], 0.1)
                if readable:
                    line = listener.stdout.readline().strip()
                    if line.isdigit() and 1 <= int(line) <= 65535:
                        return listener, int(line)
                    raise AssertionError(f"fast HTTP listener emitted invalid port: {line!r}")
        raise AssertionError("fast HTTP listener did not report its bound port")
    except BaseException:
        stop_fast_http_listener(listener)
        raise


def stop_fast_http_listener(listener) -> None:
    if listener is None or listener.poll() is not None:
        return
    listener.terminate()
    try:
        listener.wait(timeout=5)
    except subprocess.TimeoutExpired:
        listener.kill()
        listener.wait(timeout=5)


def ready_fixture(*, project: str = FIXTURES.PROJECT, port: int = FIXTURES.PORT, pid: int = FIXTURES.MAIN_PID) -> dict:
    value = copy.deepcopy(FIXTURES.fixture())
    old_key = FIXTURES.ASSIGNMENT_KEY
    new_key = f"{project}::{FIXTURES.NAME}"
    assignment = value["port_assignments"][0]
    assignment.update({"key": new_key, "project": project, "port": port})
    server = value["servers"][0]
    server.update({"key": new_key, "project": project, "port": port, "pid": pid})
    server["registration_identity"].update(
        {"pid": pid, "cwd": f"{project}/apps/DevOpsConsole", "project": project, "port": port}
    )
    server["health"]["identity"].update(
        {"pid": pid, "cwd": f"{project}/apps/DevOpsConsole", "project": project, "port": port}
    )
    lease = value["leases"][0]
    lease.update({"project": project, "port": port, "owner_pid": pid, "assignment_key": new_key})
    for row in value["port_assignments"][1:]:
        require(row.get("key") != old_key, "unrelated fixture unexpectedly shares target key")
    return value


def schema_v2_fixture(value: dict) -> dict:
    compatibility = copy.deepcopy(value)
    compatibility.setdefault("docker", {"available": None, "containers": [], "postgres": []})
    return {
        **copy.deepcopy(compatibility),
        "schema_version": 2,
        "leases": [
            {
                "lease_id": "normalized-lease",
                "repo_id": "normalized-repository",
                "server_definition_id": "normalized-server",
                "port": FIXTURES.PORT,
                "status": "active",
            }
        ],
        "port_assignments": [
            {
                "assignment_id": "normalized-assignment",
                "repo_id": "normalized-repository",
                "server_name": FIXTURES.NAME,
                "port": FIXTURES.PORT,
                "status": "active",
            }
        ],
        "v1_compatibility": compatibility,
    }


def pending_current_main_pid_fixture() -> dict:
    """Mirror the brief local-commit/fresh-listener-proof startup boundary."""

    value = ready_fixture()
    value["port_assignments"][0]["status"] = "active"
    server = value["servers"][0]
    server.pop("registration_identity")
    server["host"] = "127.0.0.1"
    server["cwd"] = f"{FIXTURES.PROJECT}/apps/DevOpsConsole"
    server["url_is_current"] = False
    server["health"] = {
        "attempts": 1,
        "check": {"ok": False, "error": "[Errno 111] Connection refused"},
        "classification": "unverified-listener",
        "identity": {
            "cwd": f"{FIXTURES.PROJECT}/apps/DevOpsConsole",
            "observable": False,
            "ok": None,
            "pid": FIXTURES.MAIN_PID,
            "project": FIXTURES.PROJECT,
            "reason": "registration PID fd table is not observable yet",
        },
        "ok": None,
        "pid_alive": True,
    }
    return value


def stopped_server(*, project: str = FIXTURES.PROJECT, port: int = FIXTURES.PORT, pid=27001, lease_id=None) -> dict:
    server = copy.deepcopy(FIXTURES.fixture()["servers"][0])
    server.update(
        {
            "key": f"{project}::{FIXTURES.NAME}",
            "project": project,
            "port": port,
            "pid": pid,
            "status": "stopped",
            "lease_id": lease_id,
            "health": {"ok": False, "pid_alive": False, "classification": "stopped"},
        }
    )
    return server


def pending_assignment(*, project: str = FIXTURES.PROJECT, port: int = FIXTURES.PORT) -> dict:
    return {
        "key": f"{project}::{FIXTURES.NAME}",
        "project": project,
        "name": FIXTURES.NAME,
        "port": port,
        "server_status": "stopped",
    }


def enrolled_unobserved_server(*, project: str = FIXTURES.PROJECT) -> dict:
    """Mirror the broker projection created by server-wide enrollment."""

    return {
        "argv": [],
        "attribution": None,
        "cwd": f"{project}/apps/DevOpsConsole",
        "health": {
            "classification": "unobserved",
            "ok": None,
            "pid_alive": None,
        },
        "health_url": "http://127.0.0.1:{port}/healthz",
        "host": "127.0.0.1",
        "id": FIXTURES.SERVER_ID,
        "identity_observable": None,
        "key": f"{project}::{FIXTURES.NAME}",
        # Enrollment briefly leases the durable port and retains the released
        # lease id as history; the v1 projection intentionally hides that
        # inactive lease row.
        "lease_id": "released-enrollment-lease",
        "log_path": None,
        "metadata_source": "normalized-sqlite",
        "name": FIXTURES.NAME,
        "pid": None,
        "port": None,
        "process_fingerprint": None,
        "process_start_time": None,
        "project": project,
        "role": "web",
        "status": "unobserved",
        "stopped_at": None,
        "stopped_reason": None,
        "url": None,
        "url_is_current": False,
    }


def classify(value: dict, *, project: str = FIXTURES.PROJECT, port: int = FIXTURES.PORT, pid: int = FIXTURES.MAIN_PID):
    return READY.classify_registration_snapshot(
        value,
        project=project,
        name=FIXTURES.NAME,
        port=port,
        main_pid=pid,
    )


def must_fail(value: dict, contains: str, label: str) -> None:
    try:
        classify(value)
    except READY.ConsoleRegistrationError as error:
        require(contains.lower() in str(error).lower(), f"{label}: wrong error: {error}")
        return
    raise AssertionError(f"readiness guard missed unsafe state: {label}")


class FakeClock:
    def __init__(self) -> None:
        self.value = 10.0

    def __call__(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


def wait_with_snapshots(snapshots: list[object]) -> dict:
    clock = FakeClock()
    state = {"active_state": "activating", "main_pid": FIXTURES.MAIN_PID, "cgroup": "/system.slice/devops-console.service"}
    identity = {
        "start_ticks": "123456",
        "argv": ["/usr/bin/node", "bin/devops-console.mjs", "--env-file", "/private/console.env"],
        "cwd": "/home/DevCoordinator/apps/DevOpsConsole",
        "cgroups": {state["cgroup"]},
    }
    queue = list(snapshots)

    def observe(_remaining: float) -> dict:
        value = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(value, BaseException):
            raise value
        return copy.deepcopy(value)

    return READY.wait_for_console_registration(
        unit="devops-console.service",
        main_pid=FIXTURES.MAIN_PID,
        project=FIXTURES.PROJECT,
        name=FIXTURES.NAME,
        port=FIXTURES.PORT,
        token="x" * 64,
        host="127.0.0.1",
        coordinator_port=29876,
        expected_argv=identity["argv"],
        expected_working_directory=identity["cwd"],
        wait_seconds=5,
        poll_interval_seconds=0.1,
        unit_probe_fn=lambda: copy.deepcopy(state),
        process_probe_fn=lambda: copy.deepcopy(identity),
        inventory_probe_fn=observe,
        clock=clock,
        sleeper=clock.sleep,
    )


def real_listener_delayed_registration_test() -> None:
    if not sys.platform.startswith("linux") or not Path("/proc/self").exists():
        return
    with tempfile.TemporaryDirectory(prefix="console-registration-listener-") as raw:
        project = Path(raw).resolve()
        listener, reported_port = start_fast_http_listener(cwd=project)
        try:
            deadline = time.monotonic() + 5
            port = None
            while time.monotonic() < deadline:
                # The port is deliberately discovered from the real listener's
                # socket inode through /proc, not invented as registration evidence.
                try:
                    links = [Path(entry).readlink() for entry in (Path("/proc") / str(listener.pid) / "fd").iterdir()]
                except OSError:
                    links = []
                inodes = {str(link)[8:-1] for link in links if str(link).startswith("socket:[")}
                if inodes:
                    tcp = Path("/proc/net/tcp").read_text(encoding="utf-8").splitlines()[1:]
                    for line in tcp:
                        fields = line.split()
                        if len(fields) > 9 and fields[9] in inodes and fields[3] == "0A":
                            port = int(fields[1].rsplit(":", 1)[1], 16)
                            break
                if port:
                    break
                time.sleep(0.02)
            require(port is not None, "real listener did not expose a bound port")
            require(port == reported_port, "procfs listener port disagreed with bound port")
            identity = READY.process_identity_probe(listener.pid)
            cgroup = sorted(identity["cgroups"])[0]
            blank = {"port_assignments": [], "servers": [], "leases": []}
            final = ready_fixture(project=str(project), port=port, pid=listener.pid)
            sequence = [blank, blank, final]
            clock = FakeClock()

            def inventory(_remaining: float) -> dict:
                return copy.deepcopy(sequence.pop(0) if len(sequence) > 1 else sequence[0])

            report = READY.wait_for_console_registration(
                unit="fixture.service",
                main_pid=listener.pid,
                project=str(project),
                name=FIXTURES.NAME,
                port=port,
                token="x" * 64,
                host="127.0.0.1",
                coordinator_port=29876,
                expected_argv=identity["argv"],
                expected_working_directory=str(project),
                wait_seconds=5,
                poll_interval_seconds=0.1,
                unit_probe_fn=lambda: {"active_state": "activating", "main_pid": listener.pid, "cgroup": cgroup},
                process_probe_fn=lambda: READY.process_identity_probe(listener.pid),
                inventory_probe_fn=inventory,
                clock=clock,
                sleeper=clock.sleep,
            )
            require(report["attempts"] == 3, "real listener delayed registration did not retry exactly")
        finally:
            stop_fast_http_listener(listener)


def actual_api_delayed_registration_test() -> None:
    if not sys.platform.startswith("linux") or not Path("/proc/self").exists():
        return
    coordinator_script = ROOT.parent / "skills" / "codex-dev-coordinator" / "scripts" / "dev_coordinator.py"
    with tempfile.TemporaryDirectory(prefix="console-registration-api-") as raw:
        root = Path(raw).resolve()
        old_project = root / "legacy-project"
        project = root / "current-project"
        git_environment = {
            **os.environ,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
        }
        for repository in (old_project, project):
            subprocess.run(
                ["git", "init", "-q", "--initial-branch=main", str(repository)],
                check=True,
                env=git_environment,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        home = root / "coordinator-home"
        home.mkdir(mode=0o700)
        old_listener, listener_port = start_fast_http_listener(cwd=old_project)
        listener = None
        original_home = os.environ.get("CODEX_AGENT_COORDINATOR_HOME")
        original_backend = os.environ.get("DEVCOORDINATOR_STATE_BACKEND")
        os.environ["CODEX_AGENT_COORDINATOR_HOME"] = str(home)
        os.environ["DEVCOORDINATOR_STATE_BACKEND"] = "sqlite"
        api = None
        try:
            dc = load("actual_registration_coordinator", coordinator_script)
            # A developer's other coordinator homes or system broker profile
            # must not influence this isolated normalized fixture.
            dc.discover_same_uid_legacy_homes = lambda **_kwargs: []
            dc.load_broker_profile = lambda **_kwargs: None

            with dc.AccountStore.open_default(home) as store:
                host_id = store.ensure_local_host()
                timestamp = dc.utc_timestamp()
                with store.immediate_transaction() as connection:
                    for repository in (old_project, project):
                        repo_id = dc.deterministic_id(
                            "repository", host_id, str(repository)
                        )
                        connection.execute(
                            """
                            INSERT INTO repositories(
                                repo_id, host_id, canonical_root, display_name,
                                state, generation, created_at, updated_at
                            ) VALUES (?, ?, ?, ?, 'active', 0, ?, ?)
                            """,
                            (
                                repo_id,
                                host_id,
                                str(repository),
                                repository.name,
                                timestamp,
                                timestamp,
                            ),
                        )
                        connection.execute(
                            """
                            INSERT INTO repository_installations(
                                repo_id, status, startup_fenced, generation,
                                actor, updated_at
                            ) VALUES (?, 'installed', 0, 0, 'readiness-test', ?)
                            """,
                            (repo_id, timestamp),
                        )
                    connection.execute(
                        """
                        UPDATE schema_metadata
                        SET authority_mode = 'sqlite', migration_state = 'ready',
                            first_sqlite_mutation_at = ?, updated_at = ?
                        WHERE singleton = 1
                        """,
                        (timestamp, timestamp),
                    )
                stale = dc.NormalizedServerLifecycle(store).commit_registration(
                    dc.ServerRegistrationRequest(
                        agent="readiness-test",
                        canonical_project=str(old_project),
                        name=FIXTURES.NAME,
                        cwd=str(old_project),
                        argv=(),
                        environment={},
                        host="127.0.0.1",
                        port=listener_port,
                        health_url=f"http://127.0.0.1:{listener_port}/",
                        role=None,
                        pid=2_147_483_647,
                        process_start_time="dead-fixture-process",
                        process_fingerprint="sha256:dead-fixture-process",
                        health={
                            "ok": True,
                            "pid_alive": True,
                            "classification": "healthy",
                            "check": {"ok": True, "status": 200},
                            "identity": {"ok": True, "observable": True},
                        },
                        ttl_seconds=600,
                        log_path=None,
                    )
                )
                require(store.check_invariants() == (), "restart fixture violates SQLite invariants")
                with store.read_transaction() as connection:
                    before_read = tuple(
                        connection.execute(
                            """
                            SELECT state_revision, observation_revision
                            FROM schema_metadata WHERE singleton = 1
                            """
                        ).fetchone()
                    )
            old_server_id = str(stale["id"])
            old_lease_id = str(stale["lease_id"])
            token = "a" * 64
            api = dc.BoundedThreadingHTTPServer(("127.0.0.1", 0), dc.ApiHandler, token=token)
            api_port = int(api.server_address[1])
            api_thread = threading.Thread(target=api.serve_forever, daemon=True)
            api_thread.start()
            restart_inventory = READY.inventory_probe(
                host="127.0.0.1",
                port=api_port,
                token=token,
                timeout=3,
                project=str(old_project),
                name=FIXTURES.NAME,
                server_port=listener_port,
            )
            restart_state, _restart_report = READY.classify_registration_snapshot(
                restart_inventory,
                project=str(old_project),
                name=FIXTURES.NAME,
                port=listener_port,
                main_pid=old_listener.pid,
            )
            require(
                restart_state == "pending-stopped-baseline",
                "actual no-Docker restart baseline was not retryable",
            )
            normalized_restart = next(
                row for row in restart_inventory["servers"] if row.get("id") == old_server_id
            )
            require(
                normalized_restart.get("status") == "stopped"
                and normalized_restart.get("health", {}).get("pid_alive") is False
                and not any(row.get("id") == old_lease_id for row in restart_inventory["leases"]),
                "actual no-Docker view did not normalize dead state and hide its stale active lease",
            )
            require(
                normalized_restart.get("port_reused_by", {}).get("type") == "process"
                and normalized_restart.get("port_reused_by", {}).get("pid") == old_listener.pid,
                "actual restart observation did not bind the raw listener to the gate MainPID",
            )
            with dc.AccountStore.open_default(home) as store:
                with store.read_transaction() as connection:
                    after_read = tuple(
                        connection.execute(
                            """
                            SELECT state_revision, observation_revision
                            FROM schema_metadata WHERE singleton = 1
                            """
                        ).fetchone()
                    )
                    stored_lifecycle = connection.execute(
                        """
                        SELECT lifecycle FROM server_observations
                        WHERE server_definition_id = ?
                        """,
                        (old_server_id,),
                    ).fetchone()[0]
                    stored_lease = connection.execute(
                        "SELECT status FROM leases WHERE lease_id = ?",
                        (old_lease_id,),
                    ).fetchone()[0]
                require(before_read == after_read, "readiness inventory mutated SQLite revisions")
                require(
                    stored_lifecycle == "running" and stored_lease == "active",
                    "readiness inventory persisted its in-memory stale normalization",
                )

            stop_fast_http_listener(old_listener)
            old_listener = None
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and dc.port_open(
                "127.0.0.1", listener_port
            ):
                time.sleep(0.02)
            require(
                not dc.port_open("127.0.0.1", listener_port),
                "old listener remained present before relocation",
            )
            with dc.AccountStore.open_default(home) as store:
                relocated = dc.NormalizedServerLifecycle(store).relocate(
                    agent="readiness-test",
                    old_project=str(old_project),
                    new_project=str(project),
                    name=FIXTURES.NAME,
                    port=listener_port,
                    lease_id=old_lease_id,
                    listener_present=False,
                    process_alive=False,
                )
                require(relocated["project"] == str(project), "normalized relocation used wrong project")
                require(store.check_invariants() == (), "relocation fixture violates SQLite invariants")

            listener, rebound_port = start_fast_http_listener(
                cwd=project, port=listener_port
            )
            require(rebound_port == listener_port, "relocated listener changed its durable port")
            relocated_inventory = READY.inventory_probe(
                host="127.0.0.1",
                port=api_port,
                token=token,
                timeout=3,
                project=str(project),
                name=FIXTURES.NAME,
                server_port=listener_port,
            )
            relocated_row = next(
                row for row in relocated_inventory["servers"] if row.get("id") == old_server_id
            )
            require(
                relocated_row.get("health", {}).get("pid_alive") is None,
                "actual relocated observation did not reproduce pid_alive=None",
            )
            require(
                relocated_row.get("port_reused_by", {}).get("type") == "process"
                and relocated_row.get("port_reused_by", {}).get("pid") == listener.pid,
                "actual relocated observation did not bind the raw listener to the gate MainPID",
            )
            relocated_state, _relocated_report = READY.classify_registration_snapshot(
                relocated_inventory,
                project=str(project),
                name=FIXTURES.NAME,
                port=listener_port,
                main_pid=listener.pid,
            )
            require(
                relocated_state == "pending-stopped-baseline",
                "actual answering-listener relocation baseline was not retryable",
            )
            registration: dict[str, object] = {}
            first_pending_poll = threading.Event()

            def register_later() -> None:
                if not first_pending_poll.wait(timeout=5):
                    registration["error"] = "readiness never completed its first pending poll"
                    return
                connection = http.client.HTTPConnection("127.0.0.1", api_port, timeout=5)
                try:
                    payload = {
                        "agent": "readiness-test",
                        "project": str(project),
                        "name": FIXTURES.NAME,
                        "cwd": str(project),
                        "pid": listener.pid,
                        "port": listener_port,
                        "url": f"http://127.0.0.1:{listener_port}",
                        "health_url": f"http://127.0.0.1:{listener_port}/",
                    }
                    connection.request(
                        "POST",
                        "/v1/servers/register",
                        body=json.dumps(payload),
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Content-Type": "application/json",
                            "Host": f"127.0.0.1:{api_port}",
                        },
                    )
                    response = connection.getresponse()
                    registration["status"] = response.status
                    registration["body"] = response.read().decode("utf-8", errors="replace")
                except BaseException as error:  # test thread evidence
                    registration["error"] = repr(error)
                finally:
                    connection.close()

            register_thread = threading.Thread(target=register_later, daemon=True)
            register_thread.start()
            identity = READY.process_identity_probe(listener.pid)
            cgroup = sorted(identity["cgroups"])[0]

            def registration_inventory_probe(remaining: float) -> dict:
                inventory = READY.inventory_probe(
                    host="127.0.0.1",
                    port=api_port,
                    token=token,
                    timeout=remaining,
                    project=str(project),
                    name=FIXTURES.NAME,
                    server_port=listener_port,
                )
                first_pending_poll.set()
                return inventory

            report = READY.wait_for_console_registration(
                unit="fixture.service",
                main_pid=listener.pid,
                project=str(project),
                name=FIXTURES.NAME,
                port=listener_port,
                token=token,
                host="127.0.0.1",
                coordinator_port=api_port,
                expected_argv=identity["argv"],
                expected_working_directory=str(project),
                wait_seconds=8,
                poll_interval_seconds=0.05,
                unit_probe_fn=lambda: {"active_state": "activating", "main_pid": listener.pid, "cgroup": cgroup},
                process_probe_fn=lambda: READY.process_identity_probe(listener.pid),
                inventory_probe_fn=registration_inventory_probe,
            )
            register_thread.join(timeout=5)
            require(not register_thread.is_alive(), "actual registration request did not finish")
            require(registration.get("status") == 200, f"actual registration failed: {registration}")
            require(report["server_pid"] == listener.pid and report["attempts"] >= 2, "actual API registration was not observed after delay")
        finally:
            if api is not None:
                api.shutdown()
                api.server_close()
            stop_fast_http_listener(listener)
            stop_fast_http_listener(old_listener)
            if original_home is None:
                os.environ.pop("CODEX_AGENT_COORDINATOR_HOME", None)
            else:
                os.environ["CODEX_AGENT_COORDINATOR_HOME"] = original_home
            if original_backend is None:
                os.environ.pop("DEVCOORDINATOR_STATE_BACKEND", None)
            else:
                os.environ["DEVCOORDINATOR_STATE_BACKEND"] = original_backend


def normalized_fixture_source_guard_test() -> None:
    source = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden = {
        "locked_state",
        "load_legacy_state_projection",
        "replace_legacy_state_projection",
    }
    used = sorted(
        {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and node.attr in forbidden
        }
    )
    require(
        used == [],
        f"Console readiness fixture reached retired state projection APIs: {used}",
    )
    require(
        ("http" + ".server") not in source,
        "Console readiness fixture uses the reverse-DNS-prone HTTPServer path",
    )


def normalized_producer_contract_test() -> None:
    coordinator_script = (
        ROOT.parent
        / "skills"
        / "codex-dev-coordinator"
        / "scripts"
        / "dev_coordinator.py"
    )
    with tempfile.TemporaryDirectory(prefix="console-registration-producer-") as raw:
        root = Path(raw).resolve()
        project = root / "project"
        project.mkdir()
        home = root / "coordinator-home"
        home.mkdir(mode=0o700)
        original_home = os.environ.get("CODEX_AGENT_COORDINATOR_HOME")
        original_backend = os.environ.get("DEVCOORDINATOR_STATE_BACKEND")
        os.environ["CODEX_AGENT_COORDINATOR_HOME"] = str(home)
        os.environ["DEVCOORDINATOR_STATE_BACKEND"] = "sqlite"
        try:
            dc = load("producer_contract_coordinator", coordinator_script)
            with dc.AccountStore.open_default(home) as store:
                host_id = store.ensure_local_host()
                timestamp = dc.utc_timestamp()
                repo_id = dc.deterministic_id("repository", host_id, str(project))
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        INSERT INTO repositories(
                            repo_id, host_id, canonical_root, display_name,
                            state, generation, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, 'active', 0, ?, ?)
                        """,
                        (
                            repo_id,
                            host_id,
                            str(project),
                            project.name,
                            timestamp,
                            timestamp,
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO repository_installations(
                            repo_id, status, startup_fenced, generation,
                            actor, updated_at
                        ) VALUES (?, 'installed', 0, 0, 'readiness-test', ?)
                        """,
                        (repo_id, timestamp),
                    )
                    connection.execute(
                        """
                        UPDATE schema_metadata
                        SET authority_mode = 'sqlite', migration_state = 'ready',
                            first_sqlite_mutation_at = ?, updated_at = ?
                        WHERE singleton = 1
                        """,
                        (timestamp, timestamp),
                    )
                registered = dc.NormalizedServerLifecycle(store).commit_registration(
                    dc.ServerRegistrationRequest(
                        agent="readiness-test",
                        canonical_project=str(project),
                        name=FIXTURES.NAME,
                        cwd=str(project),
                        argv=(),
                        environment={},
                        host="127.0.0.1",
                        port=FIXTURES.PORT,
                        health_url=f"http://127.0.0.1:{FIXTURES.PORT}/healthz",
                        role=None,
                        pid=FIXTURES.MAIN_PID,
                        process_start_time="fixture-start",
                        process_fingerprint="sha256:fixture-process",
                        health={
                            "ok": True,
                            "pid_alive": True,
                            "classification": "healthy",
                            "check": {"ok": True, "status": 200},
                            "identity": {"ok": True, "observable": True},
                        },
                        ttl_seconds=600,
                        log_path=None,
                    )
                )
                dc.NormalizedServerLifecycle(store).commit_registration(
                    dc.ServerRegistrationRequest(
                        agent="readiness-test",
                        canonical_project=str(project),
                        name="unrelated-slow-service",
                        cwd=str(project),
                        argv=(),
                        environment={},
                        host="127.0.0.1",
                        port=FIXTURES.PORT + 1,
                        health_url="http://127.0.0.1:1/would-block-if-sampled",
                        role=None,
                        pid=FIXTURES.MAIN_PID + 1,
                        process_start_time="unrelated-fixture-start",
                        process_fingerprint="sha256:unrelated-fixture-process",
                        health={
                            "ok": True,
                            "pid_alive": True,
                            "classification": "healthy",
                            "check": {"ok": True, "status": 200},
                            "identity": {"ok": True, "observable": True},
                        },
                        ttl_seconds=600,
                        log_path=None,
                    )
                )
                require(store.check_invariants() == (), "producer fixture violates SQLite invariants")
            before_read = None

            exact_identity = {
                "ok": True,
                "observable": True,
                "pid": FIXTURES.MAIN_PID,
                "cwd": str(project / "apps" / "DevOpsConsole"),
                "project": str(project),
                "host": "127.0.0.1",
                "port": FIXTURES.PORT,
                "listener_inodes": ["123456"],
                "source": "proc_pid_fd",
            }
            original_health = dc.server_health
            original_process_usage = dc.annotate_server_process_usage
            original_backup_inventory = dc.backup_inventory
            health_calls: list[str] = []

            def exact_health(server: dict, **_kwargs) -> dict:
                health_calls.append(str(server.get("name")))
                require(
                    server.get("name") == FIXTURES.NAME,
                    "targeted readiness sampled an unrelated server",
                )
                require(
                    server.get("_require_exact_listener_identity") is True,
                    "active target did not request fresh strict listener proof",
                )
                return {
                    "ok": True,
                    "pid_alive": True,
                    "classification": "healthy",
                    "check": {"ok": True, "status": 200},
                    "identity": copy.deepcopy(exact_identity),
                }

            def forbidden_expensive_probe(*_args, **_kwargs):
                raise AssertionError(
                    "targeted readiness invoked process-usage or backup discovery"
                )

            dc.server_health = exact_health
            dc.annotate_server_process_usage = forbidden_expensive_probe
            dc.backup_inventory = forbidden_expensive_probe
            try:
                for persisted_observable in (None, False, True):
                    with dc.AccountStore.open_default(home) as store:
                        with store.immediate_transaction() as connection:
                            connection.execute(
                                """
                                UPDATE server_observations
                                SET listener_observable = ?
                                WHERE server_definition_id = ?
                                """,
                                (
                                    None
                                    if persisted_observable is None
                                    else int(persisted_observable),
                                    registered["id"],
                                ),
                            )
                    with dc.AccountStore.open_default_read_only(home) as store:
                        before_read = (
                            store.metadata.state_revision,
                            store.metadata.observation_revision,
                        )
                    health_calls.clear()
                    inventory = dc.coordinated_build_registration_inventory(
                        project=str(project),
                        name=FIXTURES.NAME,
                        port=FIXTURES.PORT,
                    )
                    require(
                        health_calls == [FIXTURES.NAME],
                        f"targeted readiness sampled wrong servers: {health_calls}",
                    )
                    state, report = READY.classify_registration_snapshot(
                        inventory,
                        project=str(project),
                        name=FIXTURES.NAME,
                        port=FIXTURES.PORT,
                        main_pid=FIXTURES.MAIN_PID,
                    )
                    require(
                        state == "ready" and report["server_id"] == registered["id"],
                        "fresh strict proof did not supersede stale observability metadata",
                    )
                    with dc.AccountStore.open_default_read_only(home) as store:
                        after_targeted_read = (
                            store.metadata.state_revision,
                            store.metadata.observation_revision,
                        )
                    require(
                        before_read == after_targeted_read,
                        "targeted producer mutated SQLite revisions",
                    )

                def generic_health(server: dict, **_kwargs) -> dict:
                    require(
                        server.get("_require_exact_listener_identity") is True,
                        "generic-proof control did not request strict identity",
                    )
                    return {
                        "ok": True,
                        "pid_alive": True,
                        "classification": "healthy",
                        "check": {"ok": True, "status": 200},
                        "identity": {
                            "ok": True,
                            "pid": FIXTURES.MAIN_PID,
                            "cwd": str(project),
                            "project": str(project),
                        },
                    }

                dc.server_health = generic_health
                generic_inventory = dc.coordinated_build_registration_inventory(
                    project=str(project),
                    name=FIXTURES.NAME,
                    port=FIXTURES.PORT,
                )
                generic_server = next(
                    row
                    for row in generic_inventory["v1_compatibility"]["servers"]
                    if row["id"] == registered["id"]
                )
                require(
                    "registration_identity" not in generic_server,
                    "generic cwd identity was mislabeled as registration proof",
                )

                def unobservable_health(server: dict, **_kwargs) -> dict:
                    require(
                        server.get("_require_exact_listener_identity") is True,
                        "unobservable control did not request strict identity",
                    )
                    return {
                        "ok": None,
                        "pid_alive": True,
                        "classification": "unverified-listener",
                        "check": {"ok": True, "status": 200},
                        "identity": {
                            "ok": None,
                            "observable": False,
                            "reason": "injected capability boundary",
                        },
                    }

                dc.server_health = unobservable_health
                unobservable_inventory = dc.coordinated_build_registration_inventory(
                    project=str(project),
                    name=FIXTURES.NAME,
                    port=FIXTURES.PORT,
                )
                unobservable_server = next(
                    row
                    for row in unobservable_inventory["v1_compatibility"]["servers"]
                    if row["id"] == registered["id"]
                )
                require(
                    unobservable_server["status"] == "running"
                    and "registration_identity" not in unobservable_server,
                    "unobservable strict proof changed lifecycle or invented identity",
                )
                try:
                    READY.classify_registration_snapshot(
                        unobservable_inventory,
                        project=str(project),
                        name=FIXTURES.NAME,
                        port=FIXTURES.PORT,
                        main_pid=FIXTURES.MAIN_PID,
                    )
                except READY.ConsoleRegistrationError:
                    pass
                else:
                    raise AssertionError("unobservable listener identity was accepted as ready")

                dc.server_health = exact_health
                inventory = dc.coordinated_build_registration_inventory(
                    project=str(project),
                    name=FIXTURES.NAME,
                    port=FIXTURES.PORT,
                )
            finally:
                dc.server_health = original_health
                dc.annotate_server_process_usage = original_process_usage
                dc.backup_inventory = original_backup_inventory

            state, report = READY.classify_registration_snapshot(
                inventory,
                project=str(project),
                name=FIXTURES.NAME,
                port=FIXTURES.PORT,
                main_pid=FIXTURES.MAIN_PID,
            )
            require(
                state == "ready" and report["server_id"] == registered["id"],
                "normalized producer did not satisfy the current readiness contract",
            )
            require(
                all("lease_id" in row and "id" not in row for row in inventory["leases"]),
                "registration view replaced normalized top-level leases",
            )
            require(
                "_require_exact_listener_identity" not in json.dumps(inventory),
                "private live-proof marker leaked into the public inventory",
            )
            with dc.AccountStore.open_default_read_only(home) as store:
                after_read = (
                    store.metadata.state_revision,
                    store.metadata.observation_revision,
                )
            require(
                before_read is not None and before_read == after_read,
                "producer readiness view mutated SQLite",
            )
        finally:
            if original_home is None:
                os.environ.pop("CODEX_AGENT_COORDINATOR_HOME", None)
            else:
                os.environ["CODEX_AGENT_COORDINATOR_HOME"] = original_home
            if original_backend is None:
                os.environ.pop("DEVCOORDINATOR_STATE_BACKEND", None)
            else:
                os.environ["DEVCOORDINATOR_STATE_BACKEND"] = original_backend


def identity_and_deadline_tests() -> None:
    state = {"active_state": "activating", "main_pid": FIXTURES.MAIN_PID, "cgroup": "/fixture.service"}
    identity = {
        "start_ticks": "123",
        "argv": ["/usr/bin/node", "bin/devops-console.mjs", "--env-file", "/private/console.env"],
        "cwd": "/home/DevCoordinator/apps/DevOpsConsole",
        "cgroups": {state["cgroup"]},
    }
    base = dict(
        unit="devops-console.service",
        main_pid=FIXTURES.MAIN_PID,
        project=FIXTURES.PROJECT,
        name=FIXTURES.NAME,
        port=FIXTURES.PORT,
        token="x" * 64,
        host="127.0.0.1",
        coordinator_port=29876,
        expected_argv=identity["argv"],
        expected_working_directory=identity["cwd"],
        wait_seconds=5,
        poll_interval_seconds=0.1,
        process_probe_fn=lambda: copy.deepcopy(identity),
        inventory_probe_fn=lambda _remaining: ready_fixture(),
    )
    try:
        READY.wait_for_console_registration(
            **{**base, "expected_argv": ["/tmp/wrong-node"]},
            unit_probe_fn=lambda: copy.deepcopy(state),
        )
    except READY.ConsoleRegistrationError as error:
        require("argv" in str(error), f"wrong runtime argv had wrong error: {error}")
    else:
        raise AssertionError("wrong runtime argv was accepted")

    calls = 0

    def drifting_unit() -> dict:
        nonlocal calls
        calls += 1
        value = copy.deepcopy(state)
        if calls >= 2:
            value["main_pid"] += 1
        return value

    try:
        READY.wait_for_console_registration(**base, unit_probe_fn=drifting_unit)
    except READY.ConsoleRegistrationError as error:
        require("MainPID changed" in str(error), f"unit PID drift had wrong error: {error}")
    else:
        raise AssertionError("systemd MainPID drift was accepted")

    clock = FakeClock()

    def late_ready(_remaining: float) -> dict:
        clock.value += 6
        return ready_fixture()

    try:
        READY.wait_for_console_registration(
            **{
                **base,
                "unit_probe_fn": lambda: copy.deepcopy(state),
                "inventory_probe_fn": late_ready,
                "clock": clock,
                "sleeper": clock.sleep,
            }
        )
    except READY.ConsoleRegistrationTimeout as error:
        require("crossed" in str(error), f"deadline overrun had wrong error: {error}")
    else:
        raise AssertionError("ready observation crossing the global deadline was accepted")


def main() -> int:
    normalized_fixture_source_guard_test()
    normalized_producer_contract_test()
    state, report = classify(ready_fixture())
    require(state == "ready" and report["server_pid"] == FIXTURES.MAIN_PID, "valid graph must pass")

    current_pending = pending_current_main_pid_fixture()
    require(
        classify(current_pending)[0] == "pending-current-main-pid-proof",
        "exact current MainPID awaiting fresh listener proof must retry",
    )
    pending_wrong_pid = copy.deepcopy(current_pending)
    pending_wrong_pid["servers"][0]["pid"] = FIXTURES.MAIN_PID + 1
    must_fail(pending_wrong_pid, "MainPID", "pending current row names another PID")
    pending_foreign_cwd = copy.deepcopy(current_pending)
    pending_foreign_cwd["servers"][0]["cwd"] = "/srv/foreign/apps/DevOpsConsole"
    must_fail(pending_foreign_cwd, "cwd", "pending current row names another checkout")
    pending_wrong_owner = copy.deepcopy(current_pending)
    pending_wrong_owner["leases"][0]["owner_pid"] = FIXTURES.MAIN_PID + 1
    must_fail(pending_wrong_owner, "owner_pid", "pending current lease names another PID")
    pending_wrong_listener = copy.deepcopy(current_pending)
    pending_wrong_listener["servers"][0]["health"]["identity"]["ok"] = False
    must_fail(pending_wrong_listener, "wrong listener", "negative listener proof was retried")

    schema_v2_ready = schema_v2_fixture(ready_fixture())
    schema_v2_before = copy.deepcopy(schema_v2_ready)
    state, report = classify(schema_v2_ready)
    require(state == "ready" and report["server_pid"] == FIXTURES.MAIN_PID, "schema-v2 graph must pass")
    require(schema_v2_ready == schema_v2_before, "readiness classification mutated schema-v2 input")

    missing_compatibility = schema_v2_fixture(ready_fixture())
    missing_compatibility.pop("v1_compatibility")
    must_fail(missing_compatibility, "compatibility", "schema-v2 inventory omitted v1 compatibility")

    malformed_compatibility = schema_v2_fixture(ready_fixture())
    malformed_compatibility["v1_compatibility"]["leases"] = {}
    must_fail(
        malformed_compatibility,
        "leases",
        "schema-v2 inventory supplied malformed v1 compatibility rows",
    )

    unrelated_history = {
        "port_assignments": [],
        "servers": [{"project": "/retired", "name": "old", "port": FIXTURES.PORT, "status": "stopped"}],
        "leases": [{"id": "old", "project": "/retired", "port": FIXTURES.PORT, "status": "stale_released"}],
    }
    require(classify(unrelated_history)[0] == "pending-clean-absence", "inactive history is not current ownership")

    relocated = copy.deepcopy(unrelated_history)
    relocated["port_assignments"] = [pending_assignment()]
    relocated_server = stopped_server(pid=None, lease_id=None)
    relocated_server.update(
        {
            "metadata_source": "port_relocate",
            "relocated_from": "/srv/legacy/holyskills",
            "relocated_at": "2026-07-11T00:00:00Z",
            "stopped_reason": "Checkout ownership relocated; awaiting exact listener registration",
            # The real no-Docker observation recomputes this from the already
            # answering new listener even though the relocated row stays stopped.
            "health": {"ok": True, "pid_alive": None, "classification": "healthy"},
        }
    )
    relocated["servers"].append(relocated_server)
    require(classify(relocated)[0] == "pending-stopped-baseline", "relocated null-lease baseline must retry")
    observed_listener = copy.deepcopy(relocated)
    observed_listener["servers"][-1].update(
        {
            "port_reused": True,
            "url_is_current": False,
            "port_reused_by": {
                "type": "process",
                "pid": FIXTURES.MAIN_PID,
                "cwd": f"{FIXTURES.PROJECT}/apps/DevOpsConsole",
                "project": FIXTURES.PROJECT,
            },
        }
    )
    require(classify(observed_listener)[0] == "pending-stopped-baseline", "exact MainPID raw listener must retry")
    foreign_listener = copy.deepcopy(observed_listener)
    foreign_listener["servers"][-1]["port_reused_by"]["pid"] = FIXTURES.MAIN_PID + 1
    must_fail(foreign_listener, "raw port listener", "foreign unregistered listener occupies Console port")

    assignment_only = {"port_assignments": [pending_assignment()], "servers": [], "leases": []}
    assignment_only["port_assignments"][0]["server_status"] = "unregistered"
    require(classify(assignment_only)[0] == "pending-stopped-baseline", "unregistered exact assignment must retry")

    enrolled = {
        "port_assignments": [],
        "servers": [enrolled_unobserved_server()],
        "leases": [],
    }
    require(
        classify(enrolled)[0] == "pending-enrolled-unobserved-baseline",
        "exact server-wide enrollment baseline must retry",
    )
    enrolled_with_pid = copy.deepcopy(enrolled)
    enrolled_with_pid["servers"][0]["pid"] = FIXTURES.MAIN_PID
    must_fail(enrolled_with_pid, "unobserved", "enrollment baseline retains a PID")
    enrolled_with_port = copy.deepcopy(enrolled)
    enrolled_with_port["servers"][0]["port"] = FIXTURES.PORT
    must_fail(enrolled_with_port, "Console port", "enrollment baseline retains a current port")
    enrolled_with_lease = copy.deepcopy(enrolled)
    enrolled_with_lease["leases"] = [
        {
            "agent": "console-startup",
            "assignment_key": FIXTURES.ASSIGNMENT_KEY,
            "deactivated_at": None,
            "id": "released-enrollment-lease",
            "owner": "uid:1000",
            "owner_pid": None,
            "status": "active",
            "port": FIXTURES.PORT,
            "process_fingerprint": "sha256:" + ("a" * 64),
            "project": FIXTURES.PROJECT,
            "purpose": "broker",
            "server_id": FIXTURES.SERVER_ID,
        }
    ]
    require(
        classify(enrolled_with_lease)[0] == "pending-enrolled-reservation-baseline",
        "exact pre-listener broker reservation must retry",
    )
    reservation_with_pid = copy.deepcopy(enrolled_with_lease)
    reservation_with_pid["leases"][0]["owner_pid"] = FIXTURES.MAIN_PID
    must_fail(reservation_with_pid, "owner_pid", "reservation already names a process")
    reservation_for_other_server = copy.deepcopy(enrolled_with_lease)
    reservation_for_other_server["leases"][0]["server_id"] = "other-server"
    must_fail(
        reservation_for_other_server,
        "server_id",
        "reservation belongs to another server",
    )
    reservation_for_other_port = copy.deepcopy(enrolled_with_lease)
    reservation_for_other_port["leases"][0]["port"] = FIXTURES.PORT + 1
    must_fail(
        reservation_for_other_port,
        "port",
        "referenced reservation belongs to another port",
    )
    unlinked_active_lease = copy.deepcopy(enrolled_with_lease)
    unlinked_active_lease["servers"][0]["lease_id"] = None
    must_fail(unlinked_active_lease, "active lease", "active reservation is not linked")
    enrolled_foreign_cwd = copy.deepcopy(enrolled)
    enrolled_foreign_cwd["servers"][0]["cwd"] = "/srv/foreign/apps/DevOpsConsole"
    must_fail(enrolled_foreign_cwd, "cwd", "enrollment baseline names a foreign checkout")

    contradictory_assignment = copy.deepcopy(assignment_only)
    contradictory_assignment["port_assignments"][0]["server_status"] = "stopped"
    must_fail(contradictory_assignment, "expected 'unregistered'", "assignment says stopped without server")
    contradictory_server = copy.deepcopy(relocated)
    contradictory_server["port_assignments"][0]["server_status"] = "unregistered"
    must_fail(contradictory_server, "expected 'stopped'", "assignment says unregistered with stopped server")

    restart_lease = {
        "id": "prior-restart-lease",
        "project": FIXTURES.PROJECT,
        "port": FIXTURES.PORT,
        "status": "stale_released",
        "purpose": f"server:{FIXTURES.NAME}",
        "server_id": FIXTURES.SERVER_ID,
        "owner_pid": 27001,
        "assignment_key": FIXTURES.ASSIGNMENT_KEY,
    }
    restart = {
        "port_assignments": [pending_assignment()],
        "servers": [stopped_server(lease_id=restart_lease["id"])],
        "leases": [],
    }
    require(classify(restart)[0] == "pending-stopped-baseline", "ordinary restart stale linkage must retry")

    foreign_live = copy.deepcopy(unrelated_history)
    foreign_live["servers"][0]["status"] = "running"
    must_fail(foreign_live, "non-stopped server", "foreign current port owner")
    active = copy.deepcopy(restart)
    active["leases"] = [{**restart_lease, "status": "active"}]
    must_fail(active, "active lease", "stale lease was not normalized before retry")
    wrong_pid = copy.deepcopy(restart)
    wrong_pid["servers"][0]["pid"] = FIXTURES.MAIN_PID
    must_fail(wrong_pid, "MainPID", "stopped row names current MainPID")
    live_health = copy.deepcopy(restart)
    live_health["servers"][0]["health"]["pid_alive"] = True
    must_fail(live_health, "process-dead", "stopped metadata retains a live process")
    detached = copy.deepcopy(restart)
    detached["leases"] = [{**restart_lease, "server_id": "other"}]
    must_fail(detached, "server_id", "referenced inactive lease belongs to another server")

    converged = wait_with_snapshots([
        {"port_assignments": [], "servers": [], "leases": []},
        restart,
        ready_fixture(),
    ])
    require(converged["attempts"] == 3, "clean absence and exact stopped baseline should retry")
    transported = wait_with_snapshots([
        READY.InventoryTransportPending("connection refused"),
        ready_fixture(),
    ])
    require(transported["attempts"] == 2, "explicit startup transport should retry")
    try:
        wait_with_snapshots([foreign_live])
    except READY.ConsoleRegistrationError:
        pass
    else:
        raise AssertionError("unsafe current ownership was retried")

    identity_and_deadline_tests()
    real_listener_delayed_registration_test()
    actual_api_delayed_registration_test()
    print("Console registration readiness self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
