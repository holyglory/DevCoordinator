#!/usr/bin/env python3
"""Exercise production cutover helper argv through their real CLI boundaries.

The private cutover script is intentionally not a repository artifact.  This
test instead pins every repository helper interface that script consumes.  All
fixtures are isolated from systemd, production state, and production network
resources.  A helper may fail after parsing on a platform that cannot expose
Linux procfs, but argparse/usage exit 2 is never accepted as contract evidence.
"""

from __future__ import annotations

import copy
import http.client
import http.server
import importlib.util
import json
import os
import shutil
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qs, urlencode, urlparse


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
DEAD_PID = 2_147_483_647
FIXTURE_CREDENTIAL = "cutover-cli-contract-" + "a" * 40


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def private_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def private_file(path: Path, payload: str | bytes) -> Path:
    private_directory(path.parent)
    if isinstance(payload, bytes):
        path.write_bytes(payload)
    else:
        path.write_text(payload, encoding="utf-8")
    path.chmod(0o600)
    return path


def executable_file(path: Path, payload: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    path.chmod(0o755)
    return path


def helper_command(script: str, arguments: list[str]) -> list[str]:
    command = [sys.executable]
    # Running this self-test with ``python -O`` must also cross every helper
    # boundary under optimized Python, rather than optimizing only the driver.
    if sys.flags.optimize > 0:
        command.append("-O")
    return [*command, str(SCRIPTS / script), *arguments]


def run_helper(
    script: str,
    arguments: list[str],
    *,
    environment: dict[str, str] | None = None,
    timeout: float = 20.0,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        helper_command(script, arguments),
        cwd=ROOT,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    combined = f"{completed.stdout}\n{completed.stderr}".lower()
    require(
        completed.returncode != 2,
        f"{script} rejected the candidate argv at argparse: {combined}",
    )
    require(
        "usage:" not in combined,
        f"{script} emitted argparse usage for the candidate argv: {combined}",
    )
    return completed


def require_success(completed: subprocess.CompletedProcess[str], label: str) -> None:
    require(
        completed.returncode == 0,
        f"{label} failed\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
    )


class FastThreadingServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """TCPServer avoids HTTPServer's hostname lookup during fixture bind."""

    allow_reuse_address = True
    daemon_threads = True


class CoordinatorFixtureHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, _format: str, *_arguments: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        server = self.server
        token = getattr(server, "fixture_token")
        inventory = getattr(server, "fixture_inventory")
        authorization = self.headers.get("Authorization")
        if self.path == "/healthz":
            self._reply(200, {"ok": True})
            return
        if self.path == "/v1/inventory":
            if authorization != f"Bearer {token}":
                self._reply(401, {"error": "unauthorized"})
                return
            self._reply(200, inventory)
            return
        parsed = urlparse(self.path)
        if parsed.path == "/v1/inventory/no-docker":
            if authorization != f"Bearer {token}":
                self._reply(401, {"error": "unauthorized"})
                return
            expected_query = getattr(server, "fixture_registration_query", None)
            if expected_query is not None:
                try:
                    values = parse_qs(
                        parsed.query,
                        keep_blank_values=True,
                        strict_parsing=True,
                        max_num_fields=3,
                    )
                except ValueError:
                    self._reply(400, {"error": "invalid registration query"})
                    return
                observed_query = {
                    key: rows[0] if len(rows) == 1 else None
                    for key, rows in values.items()
                }
                if observed_query != expected_query:
                    self._reply(400, {"error": "wrong registration query"})
                    return
            elif parsed.query:
                self._reply(404, {"error": "not found"})
                return
            self._reply(200, inventory)
            return
        self._reply(404, {"error": "not found"})

    def _reply(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextmanager
def coordinator_fixture(
    inventory: dict[str, Any],
    *,
    registration_query: dict[str, str] | None = None,
) -> Iterator[FastThreadingServer]:
    server = FastThreadingServer(("127.0.0.1", 0), CoordinatorFixtureHandler)
    server.fixture_token = FIXTURE_CREDENTIAL  # type: ignore[attr-defined]
    server.fixture_inventory = inventory  # type: ignore[attr-defined]
    server.fixture_registration_query = registration_query  # type: ignore[attr-defined]
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def fixture_request_status(
    server: FastThreadingServer,
    target: str,
    *,
    authenticated: bool = True,
) -> int:
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        int(server.server_address[1]),
        timeout=5,
    )
    try:
        connection.request(
            "GET",
            target,
            headers=(
                {"Authorization": f"Bearer {FIXTURE_CREDENTIAL}"}
                if authenticated
                else {}
            ),
        )
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def fixture_inventory_status(
    server: FastThreadingServer,
    query: dict[str, str] | None,
) -> int:
    target = "/v1/inventory/no-docker"
    if query is not None:
        target = f"{target}?{urlencode(query)}"
    return fixture_request_status(server, target)


def test_scoped_inventory_fixture() -> None:
    expected = {
        "project": "/tmp/project with spaces",
        "name": "devops-console",
        "port": "29876",
    }
    with coordinator_fixture({"servers": []}, registration_query=expected) as server:
        require(
            fixture_inventory_status(server, expected) == 200,
            "coordinator fixture rejected the exact scoped readiness query",
        )
        require(
            fixture_inventory_status(server, None) == 400,
            "coordinator fixture accepted a missing readiness scope",
        )
        require(
            fixture_inventory_status(server, {**expected, "port": "29877"}) == 400,
            "coordinator fixture accepted the wrong readiness scope",
        )
        require(
            fixture_request_status(
                server,
                "/healthz?unexpected=1",
                authenticated=False,
            )
            == 404,
            "coordinator fixture weakened the exact health-probe path contract",
        )
        require(
            fixture_request_status(server, "/v1/inventory?unexpected=1") == 404,
            "coordinator fixture weakened the exact authenticated inventory path contract",
        )


def captured_process_evidence() -> dict[str, Any]:
    return {
        "cgroup": "/system.slice/devops-console-cli-contract-dead.service",
        "console": {
            "pid": DEAD_PID - 1,
            "start_ticks": "111111",
            "command": ["/usr/bin/node", "bin/devops-console.mjs"],
        },
        "coordinator": {
            "pid": DEAD_PID,
            "start_ticks": "222222",
            "command": ["/usr/bin/python3", "dev_coordinator.py", "api", "serve"],
        },
    }


def test_production_layout(root: Path) -> None:
    case = private_directory(root / "production-layout")
    repo = private_directory(case / "repo")
    private_directory(repo / "apps" / "DevOpsConsole")
    home = private_directory(case / "home")
    environment = private_file(
        case / "external" / "console.env",
        "SESSION_SECRET=${SESSION_SECRET}\n",
    )
    state = private_directory(case / "external" / "state")
    acme = private_directory(state / "acme")
    coordinator = private_directory(case / "external" / "coordinator")
    token = private_file(coordinator / "api-token", FIXTURE_CREDENTIAL + "\n")

    completed = run_helper(
        "check_production_layout.py",
        [
            "--repo-root",
            str(repo),
            "--home",
            str(home),
            "--env-file",
            str(environment),
            "--state-dir",
            str(state),
            "--acme-webroot",
            str(acme),
            "--coordinator-home",
            str(coordinator),
            "--token-file",
            str(token),
            "--require-token",
            "--wait-token-seconds",
            "10",
        ],
    )
    require_success(completed, "token-required production layout CLI")
    require(
        completed.stdout.strip() == "production layout preflight ok",
        "production layout CLI did not reach its successful post-parse contract",
    )


def test_state_only_migration(root: Path) -> None:
    case = private_directory(root / "state-only-migration")
    checkout = private_directory(case / "repo")
    legacy_state = private_directory(case / "legacy-state")
    private_file(legacy_state / "routes.json", '{"routes":{}}\n')
    private_file(legacy_state / "ui-prefs.json", '{"hidden":{}}\n')
    external = private_directory(case / "external")
    environment = external / "console.env"
    state = external / "state"
    coordinator = external / "coordinator"
    backup = external / "migration-backup"

    completed = run_helper(
        "migrate_legacy_console_runtime.py",
        [
            "--legacy-env",
            str(case / "unused-legacy.env"),
            "--legacy-state",
            str(legacy_state),
            "--env-file",
            str(environment),
            "--state-dir",
            str(state),
            "--coordinator-home",
            str(coordinator),
            "--devcoordinator-root",
            str(checkout),
            "--backup-dir",
            str(backup),
            "--sync-state-only",
        ],
    )
    require_success(completed, "writer-free state-only migration CLI")
    require(
        completed.stdout.strip() == "legacy Console runtime migration ok",
        "state-only migration did not reach its successful post-parse contract",
    )
    require(
        (state / "routes.json").read_bytes() == (legacy_state / "routes.json").read_bytes(),
        "state-only migration did not copy the realistic route state",
    )
    manifest = json.loads((backup / "migration-manifest.json").read_text(encoding="utf-8"))
    require(manifest.get("sync_state_only") is True, "migration manifest lost the state-only phase")
    require(not environment.exists(), "state-only phase unexpectedly created an environment file")


def test_captured_process_termination(root: Path) -> Path:
    case = private_directory(root / "captured-processes")
    evidence = private_file(
        case / "legacy-processes.json",
        json.dumps(captured_process_evidence(), indent=2, sort_keys=True) + "\n",
    )
    completed = run_helper(
        "terminate_captured_legacy_process.py",
        [
            "--evidence",
            str(evidence),
            "--role",
            "coordinator",
            "--timeout-seconds",
            "5",
        ],
    )
    require_success(completed, "captured coordinator termination CLI")
    report = json.loads(completed.stdout)
    require(report.get("role") == "coordinator", "termination CLI selected the wrong role")
    require(report.get("pid") == DEAD_PID, "termination CLI did not consume captured coordinator evidence")
    require(report.get("result") == "already-stopped", "dead captured PID was not safely classified")
    return evidence


def test_stopped_boundary(root: Path, evidence: Path) -> None:
    case = private_directory(root / "stopped-boundary")
    shim = private_directory(case / "python-shim")
    probe_log = case / "probed-ports.jsonl"
    # Isolate the exact production ports from the developer host.  The helper
    # still executes as a real CLI; only its socket discovery channel is a
    # deterministic closed-listener fixture.
    (shim / "socket.py").write_text(
        """import json, os
class socket:
    def __enter__(self):
        return self
    def __exit__(self, *_args):
        return False
    def settimeout(self, _seconds):
        return None
    def connect_ex(self, address):
        with open(os.environ['CUTOVER_SOCKET_PROBE_LOG'], 'a', encoding='utf-8') as output:
            output.write(json.dumps(list(address)) + '\\n')
        return 111
""",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["CUTOVER_SOCKET_PROBE_LOG"] = str(probe_log)
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = str(shim) + (os.pathsep + existing if existing else "")
    completed = run_helper(
        "check_legacy_cutover_stopped.py",
        [
            "--evidence",
            str(evidence),
            "--ports",
            "80",
            "443",
            "29876",
            "--wait-timeout-seconds",
            "10",
            "--poll-interval-seconds",
            "0.02",
        ],
        environment=environment,
    )
    require_success(completed, "legacy stopped-boundary CLI")
    report = json.loads(completed.stdout)
    require(report.get("closed_ports") == [80, 443, 29876], "stopped boundary lost exact production ports")
    require(report.get("attempts") == 1, "clean stopped boundary unexpectedly retried")
    require(
        isinstance(report.get("elapsed_seconds"), (int, float)),
        "stopped boundary omitted elapsed-time evidence",
    )
    probes = [json.loads(line) for line in probe_log.read_text(encoding="utf-8").splitlines()]
    require(
        probes == [["127.0.0.1", 80], ["127.0.0.1", 443], ["127.0.0.1", 29876]],
        f"stopped boundary did not probe the exact candidate port sequence: {probes}",
    )


def test_auth_inventory_capture(root: Path) -> None:
    case = private_directory(root / "auth-boundary")
    token = private_file(case / "api-token", FIXTURE_CREDENTIAL + "\n")
    evidence = case / "post-cutover-inventory.json"
    inventory = {
        "port_assignments": [],
        "servers": [],
        "leases": [],
        "fixture": "authenticated-cutover-inventory",
    }
    with coordinator_fixture(inventory) as server:
        port = int(server.server_address[1])
        completed = run_helper(
            "check_coordinator_auth_boundary.py",
            [
                "--token-file",
                str(token),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--inventory-output",
                str(evidence),
            ],
        )
    require_success(completed, "authenticated inventory capture CLI")
    report = json.loads(completed.stdout)
    require(
        report.get("statuses")
        == {
            "anonymous_health": 200,
            "anonymous_inventory": 401,
            "authenticated_inventory": 200,
        },
        "auth boundary did not prove the exact three-response contract",
    )
    require(json.loads(evidence.read_text(encoding="utf-8")) == inventory, "inventory evidence differs from API")
    require(stat.S_IMODE(evidence.stat().st_mode) == 0o600, "inventory evidence is not private")


def unused_loopback_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_for_file(path: Path, process: subprocess.Popen[str], timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            return
        if process.poll() is not None:
            _stdout, stderr = process.communicate()
            raise AssertionError(f"listener fixture exited before readiness: {stderr}")
        time.sleep(0.02)
    raise AssertionError("listener fixture did not become ready")


def process_cgroups(pid: int) -> list[str]:
    cgroups: list[str] = []
    for line in (Path("/proc") / str(pid) / "cgroup").read_text(encoding="utf-8").splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[2].startswith("/"):
            cgroups.append(parts[2])
    return cgroups


def process_socket_inodes(pid: int) -> list[str]:
    values: list[str] = []
    for descriptor in (Path("/proc") / str(pid) / "fd").iterdir():
        try:
            target = os.readlink(descriptor)
        except OSError:
            continue
        if target.startswith("socket:[") and target.endswith("]"):
            inode = target[8:-1]
            if inode.isdigit():
                values.append(inode)
    return sorted(set(values))


def current_registration_inventory(
    *, project: Path, working: Path, pid: int, port: int, listener_inode: str
) -> dict[str, Any]:
    name = "devops-console"
    key = f"{project}::{name}"
    server_id = "cli-contract-console-server"
    lease_id = "cli-contract-console-lease"
    identity = {
        "ok": True,
        "pid": pid,
        "cwd": str(working),
        "project": str(project),
        "host": "127.0.0.1",
        "port": port,
        "listener_inodes": [listener_inode],
        "source": "proc_pid_fd",
    }
    compatibility = {
        "port_assignments": [
            {
                "key": key,
                "project": str(project),
                "name": name,
                "port": port,
                "server_status": "running",
            }
        ],
        "servers": [
            {
                "id": server_id,
                "key": key,
                "project": str(project),
                "name": name,
                "port": port,
                "pid": pid,
                "status": "running",
                "lease_id": lease_id,
                "registration_identity": identity,
                "health": {
                    "ok": True,
                    "pid_alive": True,
                    "classification": "healthy",
                    "check": {"ok": True, "status": 200},
                    "identity": identity,
                },
            }
        ],
        "leases": [
            {
                "id": lease_id,
                "project": str(project),
                "port": port,
                "status": "active",
                "purpose": f"server:{name}",
                "server_id": server_id,
                "owner_pid": pid,
                "assignment_key": key,
            }
        ],
        "docker": {"available": None, "containers": [], "postgres": []},
    }
    return {
        **copy.deepcopy(compatibility),
        "schema_version": 2,
        "leases": [
            {
                "lease_id": "normalized-cli-contract-lease",
                "repo_id": "normalized-cli-contract-repository",
                "server_definition_id": "normalized-cli-contract-server",
                "port": port,
                "status": "active",
            }
        ],
        "port_assignments": [
            {
                "assignment_id": "normalized-cli-contract-assignment",
                "repo_id": "normalized-cli-contract-repository",
                "server_name": name,
                "port": port,
                "status": "active",
            }
        ],
        "v1_compatibility": compatibility,
    }


def test_console_registration_cli(root: Path) -> None:
    case = private_directory(root / "console-registration")
    project = private_directory(case / "repo")
    working = private_directory(project / "apps" / "DevOpsConsole")
    bin_directory = private_directory(working / "bin")
    listener_script = bin_directory / "devops-console.mjs"
    listener_script.write_text(
        """import os, socket, time
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(('127.0.0.1', int(os.environ['FIXTURE_CONSOLE_PORT'])))
listener.listen(8)
with open(os.environ['FIXTURE_READY_FILE'], 'w', encoding='utf-8') as output:
    output.write('ready\\n')
while True:
    time.sleep(1)
""",
        encoding="utf-8",
    )
    environment_file = private_file(
        case / "console.env", "SESSION_SECRET=${SESSION_SECRET}\n"
    )
    token_file = private_file(case / "api-token", FIXTURE_CREDENTIAL + "\n")
    ready_file = case / "listener.ready"
    console_port = unused_loopback_port()
    child_environment = os.environ.copy()
    child_environment.update(
        {
            "FIXTURE_CONSOLE_PORT": str(console_port),
            "FIXTURE_READY_FILE": str(ready_file),
        }
    )
    child = subprocess.Popen(
        [sys.executable, "bin/devops-console.mjs", "--env-file", str(environment_file)],
        cwd=working,
        env=child_environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        wait_for_file(ready_file, child)
        linux_proc = sys.platform.startswith("linux") and (Path("/proc") / str(child.pid)).is_dir()
        if linux_proc:
            cgroups = process_cgroups(child.pid)
            inodes = process_socket_inodes(child.pid)
            require(bool(cgroups), "real Console fixture exposed no process cgroup")
            require(bool(inodes), "real Console fixture exposed no listener socket inode")
            cgroup = cgroups[0]
            listener_inode = inodes[0]
        else:
            cgroup = "/system.slice/devops-console-cli-contract.service"
            listener_inode = "123456"
        fake_systemctl = executable_file(
            case / "fake-systemctl",
            f"#!{sys.executable}\n"
            "import sys\n"
            f"sys.stdout.write('ActiveState=active\\nMainPID={child.pid}\\nControlGroup={cgroup}\\n')\n",
        )
        inventory = current_registration_inventory(
            project=project,
            working=working,
            pid=child.pid,
            port=console_port,
            listener_inode=listener_inode,
        )
        with coordinator_fixture(
            inventory,
            registration_query={
                "project": str(project),
                "name": "devops-console",
                "port": str(console_port),
            },
        ) as coordinator:
            coordinator_port = int(coordinator.server_address[1])
            completed = run_helper(
                "check_console_registration_ready.py",
                [
                    "--unit",
                    "devops-console.service",
                    "--main-pid",
                    str(child.pid),
                    "--token-file",
                    str(token_file),
                    "--project",
                    str(project),
                    "--name",
                    "devops-console",
                    "--port",
                    str(console_port),
                    "--host",
                    "127.0.0.1",
                    "--coordinator-port",
                    str(coordinator_port),
                    "--expected-executable",
                    sys.executable,
                    "--expected-script",
                    "bin/devops-console.mjs",
                    "--env-file",
                    str(environment_file),
                    "--expected-working-directory",
                    str(working),
                    "--wait-seconds",
                    "80",
                    "--poll-interval-seconds",
                    "0.1",
                    "--systemctl",
                    str(fake_systemctl),
                ],
            )
        if linux_proc:
            require_success(completed, "Console production registration CLI")
            report = json.loads(completed.stdout)
            require(report.get("server_pid") == child.pid, "registration CLI lost systemd MainPID")
            require(report.get("port") == console_port, "registration CLI lost Console port")
        else:
            require(
                completed.returncode == 1
                and "cannot observe Console process identity" in completed.stderr,
                "non-Linux registration CLI did not reach its procfs-specific post-parse outcome",
            )
    finally:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)


def load_loaded_unit_module() -> Any:
    path = SCRIPTS / "check_loaded_systemd_paths.py"
    spec = importlib.util.spec_from_file_location("cutover_cli_loaded_systemd", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot import loaded-unit helper for fixture declarations")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def loaded_unit_fixtures(module: Any, bounding_names: str) -> tuple[str, str]:
    command = lambda value: (  # noqa: E731 - compact systemd serialization fixture
        f"{{ path={value.partition(' ')[0]} ; argv[]={value} ; ignore_errors=no ; start_time=[n/a] ; }}"
    )
    coordinator = "\n".join(
        [
            "Type=simple",
            "FragmentPath=/etc/systemd/system/dev-coordinator.service",
            "DropInPaths=",
            "User=holyglory",
            "Group=holyglory",
            "WorkingDirectory=/home/DevCoordinator",
            "Environment=DEVCOORDINATOR_AUTHORITY=system "
            f"CODEX_AGENT_COORDINATOR_HOME={module.COORDINATOR_JOURNAL}",
            "EnvironmentFiles=",
            "ExecStartPre=",
            f"ExecStart={command(module.COORDINATOR_ARGV)}",
            f"ExecStartPost={command(module.COORDINATOR_POSTSTART_ARGV)}",
            "TimeoutStartUSec=20s",
            "ReadWritePaths=",
            "AmbientCapabilities=cap_net_bind_service",
            f"CapabilityBoundingSet={bounding_names}",
            "",
        ]
    )
    console = "\n".join(
        [
            "Type=simple",
            "FragmentPath=/etc/systemd/system/devops-console.service",
            "DropInPaths=",
            "User=holyglory",
            "Group=holyglory",
            "WorkingDirectory=/home/DevCoordinator/apps/DevOpsConsole",
            "Environment=",
            f"EnvironmentFiles={module.CONSOLE_ENV} (ignore_errors=no)",
            f"ExecStartPre={command(module.CONSOLE_PREFLIGHT_ARGV)}",
            f"ExecStart={command(module.CONSOLE_ARGV)}",
            f"ExecStartPost={command(module.CONSOLE_POSTSTART_ARGV)}",
            "TimeoutStartUSec=1min 30s",
            f"ReadWritePaths={module.CONSOLE_STATE}",
            "AmbientCapabilities=cap_net_bind_service",
            "CapabilityBoundingSet=cap_net_bind_service",
            "",
        ]
    )
    return coordinator, console


def test_loaded_unit_evidence(root: Path) -> None:
    case = private_directory(root / "loaded-unit-evidence")
    module = load_loaded_unit_module()
    manager_available = True
    try:
        manager_mask = module.manager_capability_bounding_mask()
    except module.LoadedUnitPathError:
        manager_available = False
        manager_mask = module.CAPABILITY_BITS["cap_net_bind_service"]
    bounding_names = " ".join(
        name for name in module.LINUX_CAPABILITIES if manager_mask & module.CAPABILITY_BITS[name]
    )
    coordinator_raw, console_raw = loaded_unit_fixtures(module, bounding_names)
    coordinator_file = private_file(case / "coordinator.show", coordinator_raw)
    console_file = private_file(case / "console.show", console_raw)
    bin_directory = private_directory(case / "bin")
    executable_file(
        bin_directory / "systemctl",
        f"#!{sys.executable}\n"
        "import os, pathlib, sys\n"
        "unit = sys.argv[-1]\n"
        "key = 'FAKE_COORDINATOR_SHOW' if unit == 'dev-coordinator.service' else 'FAKE_CONSOLE_SHOW'\n"
        "sys.stdout.write(pathlib.Path(os.environ[key]).read_text(encoding='utf-8'))\n",
    )
    environment = os.environ.copy()
    environment["PATH"] = str(bin_directory) + os.pathsep + environment.get("PATH", "")
    environment["FAKE_COORDINATOR_SHOW"] = str(coordinator_file)
    environment["FAKE_CONSOLE_SHOW"] = str(console_file)
    evidence = case / "resolved-unit-paths.json"
    completed = run_helper(
        "check_loaded_systemd_paths.py",
        ["--evidence", str(evidence)],
        environment=environment,
    )
    if manager_available:
        require_success(completed, "loaded systemd evidence CLI")
        require(
            completed.stdout.strip() == "loaded systemd path preflight ok",
            "loaded-unit CLI did not reach its successful post-parse contract",
        )
        report = json.loads(evidence.read_text(encoding="utf-8"))
        require(report.get("ok") is True, "loaded-unit evidence does not record success")
        require(
            set(report.get("units", {}))
            == {"dev-coordinator.service", "devops-console.service"},
            "loaded-unit evidence omitted a production unit",
        )
        require(stat.S_IMODE(evidence.stat().st_mode) == 0o600, "loaded-unit evidence is not private")
    else:
        require(
            completed.returncode == 1
            and "loaded systemd path preflight failed:" in completed.stderr,
            "host without a compatible Linux manager did not reach a helper-specific post-parse outcome",
        )


def main() -> int:
    raw = tempfile.mkdtemp(prefix="devcoordinator-cutover-cli-contracts-")
    root = Path(raw).resolve(strict=True)
    root.chmod(0o700)
    try:
        test_scoped_inventory_fixture()
        test_production_layout(root)
        test_state_only_migration(root)
        evidence = test_captured_process_termination(root)
        test_stopped_boundary(root, evidence)
        test_auth_inventory_capture(root)
        test_console_registration_cli(root)
        test_loaded_unit_evidence(root)
        mode = "optimized" if sys.flags.optimize > 0 else "normal"
        print(f"cutover helper CLI contract self-test ok ({mode})")
        return 0
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
