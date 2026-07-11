#!/usr/bin/env python3
"""Linux integration for capability-matched production listener registration."""

from __future__ import annotations

import argparse
import grp
import http.client
import http.server
import json
import os
import pwd
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import time
from pathlib import Path


SCRIPT = Path(__file__).with_name("dev_coordinator.py").resolve()
CAPABILITY = "net_bind_service"


class FastHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        payload = b'{"ok":true}\n'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class FastServer(socketserver.TCPServer):
    allow_reuse_address = True

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)


def listener_main(port: int, pid_file: Path | None) -> int:
    if pid_file is not None:
        pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")
    with FastServer(("127.0.0.1", port), FastHandler) as server:
        server.serve_forever()
    return 0


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_health(port: int, process: subprocess.Popen[str], *, timeout: float = 20) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError(f"process exited before health: {process.returncode}\n{stdout}\n{stderr}")
        try:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            connection.request("GET", "/healthz")
            response = connection.getresponse()
            response.read()
            connection.close()
            if response.status == 200:
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise AssertionError(f"listener on {port} did not become healthy")


def api_request(
    port: int,
    method: str,
    path: str,
    *,
    token: str | None = None,
    payload: dict[str, object] | None = None,
    expected_status: int = 200,
) -> dict[str, object]:
    headers: dict[str, str] = {}
    body = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload)
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    raw = response.read()
    connection.close()
    if response.status != expected_status:
        raise AssertionError(
            f"{method} {path} returned {response.status}, expected {expected_status}: "
            f"{raw.decode('utf-8', errors='replace')}"
        )
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError(f"{method} {path} did not return an object")
    return parsed


def setpriv_prefix() -> list[str]:
    executable = shutil.which("setpriv")
    if not executable:
        raise RuntimeError("setpriv is required for the capability integration")
    account = pwd.getpwuid(os.getuid()).pw_name
    group = grp.getgrgid(os.getgid()).gr_name
    return [
        "sudo",
        "-n",
        executable,
        f"--reuid={account}",
        f"--regid={group}",
        "--init-groups",
        f"--inh-caps=+{CAPABILITY}",
        f"--ambient-caps=+{CAPABILITY}",
        "--",
    ]


def current_capability_sets() -> dict[str, str]:
    selected = {"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"}
    result: dict[str, str] = {}
    for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition(":")
        if separator and key in selected:
            result[key] = value.strip()
    if set(result) != selected:
        raise RuntimeError(f"cannot capture process capability sets: {result}")
    return result


def exec_with_capability_snapshot(path: Path, command: list[str]) -> int:
    if not command:
        raise ValueError("capability snapshot execution requires a command")
    path.write_text(json.dumps(current_capability_sets(), sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    os.execv(command[0], command)
    raise AssertionError("os.execv returned")


def write_relocation_fixture(home: Path, *, old_project: Path, new_project: Path, port: int) -> tuple[str, str]:
    server_id = "capability-cutover-server"
    lease_id = "capability-cutover-old-lease"
    old_key = f"{old_project}::devops-console"
    now = time.time()
    state = {
        "version": 2,
        "revision": 0,
        "updated_at": "fixture",
        "leases": {
            lease_id: {
                "id": lease_id,
                "agent": "legacy-console",
                "project": str(old_project),
                "port": port,
                "purpose": "server:devops-console",
                "server_id": server_id,
                "status": "active",
                "created_at": "fixture",
                "created_ts": now,
                "expires_at": now + 3600,
            }
        },
        "servers": {
            server_id: {
                "id": server_id,
                "key": old_key,
                "name": "devops-console",
                "agent": "legacy-console",
                "project": str(old_project),
                "cwd": str(old_project),
                "port": port,
                "pid": 999999999,
                "lease_id": lease_id,
                "status": "stopped",
                "health": {"ok": False},
                "created_at": "fixture",
                "updated_at": "fixture",
                "stopped_at": "fixture",
                "stopped_ts": now,
            }
        },
        "port_assignments": {
            old_key: {
                "key": old_key,
                "project": str(old_project),
                "name": "devops-console",
                "port": port,
                "agent": "legacy-console",
                "source": "server_register",
                "created_at": "fixture",
                "updated_at": "fixture",
            }
        },
        "history": [],
        "operations": {},
        "docker": {"last_commands": [], "stats_history": {}, "metadata": {}},
    }
    home.mkdir(mode=0o700)
    state_file = home / "state.json"
    state_file.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    state_file.chmod(0o600)
    return server_id, lease_id


def run_integration() -> int:
    if not sys.platform.startswith("linux"):
        if os.environ.get("COORDINATOR_CAPABILITY_INTEGRATION_REQUIRED") == "1":
            raise RuntimeError("capability integration requires Linux")
        print("capability integration skipped (non-Linux)")
        return 0
    if os.environ.get("COORDINATOR_CAPABILITY_INTEGRATION_INVENTORY_CHECKED") != "1":
        raise RuntimeError("run coordinator inventory before capability integration")
    if os.geteuid() == 0:
        raise RuntimeError("run as the target non-root service user, with passwordless sudo available")
    subprocess.run(["sudo", "-n", "true"], check=True, stdout=subprocess.DEVNULL)
    host_default_bounding = int(current_capability_sets()["CapBnd"], 16)

    root = Path(tempfile.mkdtemp(prefix="coordinator-capability-integration-")).resolve(strict=True)
    old_project = root / "legacy"
    project = root / "DevCoordinator"
    old_project.mkdir()
    project.mkdir()
    home = root / "state"
    processes: list[subprocess.Popen[str]] = []
    try:
        edge_port = free_port()
        server_id, old_lease_id = write_relocation_fixture(
            home, old_project=old_project, new_project=project, port=edge_port
        )
        env = os.environ.copy()
        env["CODEX_AGENT_COORDINATOR_HOME"] = str(home)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        relocated = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "port",
                "relocate",
                "--agent",
                "capability-integration",
                "--old-project",
                str(old_project),
                "--new-project",
                str(project),
                "--name",
                "devops-console",
                "--port",
                str(edge_port),
                "--lease-id",
                old_lease_id,
            ],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if relocated.returncode != 0:
            raise AssertionError(f"relocation fixture failed: {relocated.stdout}\n{relocated.stderr}")

        listener_pid_file = root / "edge-listener.pid"
        listener = subprocess.Popen(
            setpriv_prefix()
            + [
                "/usr/bin/env",
                "PYTHONDONTWRITEBYTECODE=1",
                sys.executable,
                str(Path(__file__).resolve()),
                "--listener",
                str(edge_port),
                "--pid-file",
                str(listener_pid_file),
            ],
            cwd=project,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        processes.append(listener)
        wait_health(edge_port, listener)
        listener_pid = int(listener_pid_file.read_text(encoding="utf-8").strip())

        no_cap_port = free_port()
        no_cap_api = subprocess.Popen(
            [
                sys.executable,
                str(SCRIPT),
                "api",
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                str(no_cap_port),
            ],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        processes.append(no_cap_api)
        wait_health(no_cap_port, no_cap_api)
        token = (home / "api-token").read_text(encoding="utf-8").strip()
        failure = api_request(
            no_cap_port,
            "POST",
            "/v1/servers/register",
            token=token,
            payload={
                "agent": "devops-console",
                "project": str(project),
                "name": "devops-console",
                "cwd": str(project),
                "pid": listener_pid,
                "port": edge_port,
                "url": f"http://127.0.0.1:{edge_port}",
                "health_url": f"http://127.0.0.1:{edge_port}/healthz",
            },
            expected_status=400,
        )
        if "working directory is not observable" not in str(failure.get("error")):
            raise AssertionError(f"no-cap coordinator did not reproduce listener invisibility: {failure}")
        no_cap_api.terminate()
        no_cap_api.wait(timeout=10)

        cap_api_port = free_port()
        cap_api_caps_file = root / "cap-api-capabilities.json"
        cap_api = subprocess.Popen(
            setpriv_prefix()
            + [
                sys.executable,
                str(Path(__file__).resolve()),
                "--exec-capability-snapshot",
                str(cap_api_caps_file),
                "--",
                "/usr/bin/env",
                f"CODEX_AGENT_COORDINATOR_HOME={home}",
                "PYTHONDONTWRITEBYTECODE=1",
                sys.executable,
                str(SCRIPT),
                "api",
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                str(cap_api_port),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        processes.append(cap_api)
        wait_health(cap_api_port, cap_api)
        cap_api_capabilities = json.loads(cap_api_caps_file.read_text(encoding="utf-8"))
        expected_child_bounding = int(str(cap_api_capabilities["CapBnd"]), 16)
        if expected_child_bounding != host_default_bounding:
            raise AssertionError(
                "capability API narrowed the host's preexisting bounding ceiling: "
                f"host={host_default_bounding:x} api={expected_child_bounding:x}"
            )
        if not expected_child_bounding & (1 << 10):
            raise AssertionError("host capability ceiling cannot supply CAP_NET_BIND_SERVICE")
        registered = api_request(
            cap_api_port,
            "POST",
            "/v1/servers/register",
            token=token,
            payload={
                "agent": "devops-console",
                "project": str(project),
                "name": "devops-console",
                "cwd": str(project),
                "pid": listener_pid,
                "port": edge_port,
                "url": f"http://127.0.0.1:{edge_port}",
                "health_url": f"http://127.0.0.1:{edge_port}/healthz",
                "argv": [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--listener",
                    "{port}",
                ],
            },
        )
        if (
            registered.get("id") != server_id
            or not registered.get("lease_id")
            or registered.get("lease_id") == old_lease_id
        ):
            raise AssertionError(
                "capability-matched registration did not reuse the server identity with a replacement lease: "
                f"{registered}"
            )

        state = api_request(cap_api_port, "GET", "/v1/state", token=token)
        lease = (state.get("leases") or {}).get(str(registered["lease_id"]))
        server = (state.get("servers") or {}).get(server_id)
        assignment = (state.get("port_assignments") or {}).get(f"{project}::devops-console")
        if not (
            isinstance(server, dict)
            and server.get("status") == "running"
            and server.get("pid") == listener_pid
            and (server.get("registration_identity") or {}).get("pid") == listener_pid
            and (server.get("registration_identity") or {}).get("host") == "127.0.0.1"
            and bool((server.get("registration_identity") or {}).get("listener_inodes"))
            and isinstance(lease, dict)
            and lease.get("server_id") == server_id
            and lease.get("owner_pid") == listener_pid
            and lease.get("purpose") == "server:devops-console"
            and lease.get("assignment_key") == f"{project}::devops-console"
            and isinstance(assignment, dict)
            and assignment.get("port") == edge_port
        ):
            raise AssertionError("relocated server, replacement lease, and assignment are not fully linked")

        unobservable_home = root / "unobservable-baseline-state"
        unobservable_home.mkdir(mode=0o700)
        unobservable_state = json.loads(json.dumps(state))
        unobservable_state["servers"][server_id]["status"] = "unhealthy"
        unobservable_state["servers"][server_id]["health"] = {
            "ok": False,
            "classification": "unhealthy",
            "pid_alive": True,
        }
        unobservable_state_file = unobservable_home / "state.json"
        unobservable_state_file.write_text(
            json.dumps(unobservable_state, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        unobservable_state_file.chmod(0o600)
        unobservable_env = {**env, "CODEX_AGENT_COORDINATOR_HOME": str(unobservable_home)}
        preserved = subprocess.run(
            [sys.executable, str(SCRIPT), "inventory", "--project", str(project), "--no-docker"],
            env=unobservable_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if preserved.returncode != 0:
            raise AssertionError(f"unobservable baseline inventory failed: {preserved.stderr}")
        preserved_payload = json.loads(preserved.stdout)
        preserved_server = next(item for item in preserved_payload["servers"] if item.get("id") == server_id)
        preserved_lease = next(item for item in preserved_payload["leases"] if item.get("id") == registered["lease_id"])
        if not (
            preserved_server.get("status") == "unhealthy"
            and (preserved_server.get("health") or {}).get("classification") == "unverified-listener"
            and (preserved_server.get("health") or {}).get("ok") is None
            and preserved_lease.get("status") == "active"
        ):
            raise AssertionError("unobservable inventory upgraded an unhealthy baseline or detached its lease")

        plain_inventory = subprocess.run(
            [sys.executable, str(SCRIPT), "inventory", "--project", str(project), "--no-docker"],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if plain_inventory.returncode != 0:
            raise AssertionError(
                f"plain CLI inventory could not preserve an unobservable capable listener: "
                f"{plain_inventory.stdout}\n{plain_inventory.stderr}"
            )
        plain_payload = json.loads(plain_inventory.stdout)
        plain_server = next(item for item in plain_payload["servers"] if item.get("id") == server_id)
        plain_lease = next(item for item in plain_payload["leases"] if item.get("id") == registered["lease_id"])
        if not (
            plain_server.get("status") == "running"
            and (plain_server.get("health") or {}).get("ok") is None
            and (plain_server.get("health") or {}).get("classification") == "unverified-listener"
            and ((plain_server.get("health") or {}).get("identity") or {}).get("observable") is False
            and plain_lease.get("status") == "active"
        ):
            raise AssertionError(
                "an incapable CLI inventory corrupted or misrepresented the registered listener graph"
            )

        # Real plain-CLI lifecycle commands run without the API's ambient
        # observation capability. They must report unknown identity and leave
        # the exact registered process/lease graph untouched.
        runtime_dir = project / ".codex"
        runtime_dir.mkdir()
        (runtime_dir / "dev-runtime.json").write_text(
            json.dumps(
                {
                    "name": "capability-edge",
                    "servers": [
                        {
                            "name": "devops-console",
                            "role": "web",
                            "port": edge_port,
                            "cwd": ".",
                            "argv": [
                                sys.executable,
                                str(Path(__file__).resolve()),
                                "--listener",
                                "{port}",
                            ],
                            "health_url": f"http://127.0.0.1:{edge_port}/healthz",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        def edge_signature() -> dict[str, object]:
            current = api_request(cap_api_port, "GET", "/v1/state", token=token)
            current_server = (current.get("servers") or {}).get(server_id)
            if not isinstance(current_server, dict):
                raise AssertionError("edge server disappeared while checking incapable lifecycle")
            current_lease = (current.get("leases") or {}).get(str(registered["lease_id"]))
            return {
                "server_ids": sorted((current.get("servers") or {}).keys()),
                "lease_ids": sorted((current.get("leases") or {}).keys()),
                "operation_ids": sorted((current.get("operations") or {}).keys()),
                "status": current_server.get("status"),
                "pid": current_server.get("pid"),
                "lease_id": current_server.get("lease_id"),
                "generation": current_server.get("generation"),
                "operation_id": current_server.get("operation_id"),
                "lease": current_lease,
            }

        def plain_cli(arguments: list[str], *, succeeds: bool) -> subprocess.CompletedProcess[str]:
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), *arguments],
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
            )
            if succeeds != (completed.returncode == 0):
                raise AssertionError(
                    f"plain CLI {' '.join(arguments)} returned {completed.returncode}: "
                    f"{completed.stdout}\n{completed.stderr}"
                )
            return completed

        before_incapable = edge_signature()
        plain_status = plain_cli(
            ["server", "status", "--project", str(project), "--name", "devops-console"],
            succeeds=True,
        )
        plain_status_payload = json.loads(plain_status.stdout)
        if not (
            plain_status_payload.get("status") == "running"
            and (plain_status_payload.get("health") or {}).get("ok") is None
            and (plain_status_payload.get("health") or {}).get("classification")
            == "unverified-listener"
            and edge_signature() == before_incapable
        ):
            raise AssertionError("incapable plain status changed lifecycle/lease state or hid uncertainty")

        lifecycle_commands = {
            "start": [
                "server",
                "start",
                "--agent",
                "incapable-cli",
                "--project",
                str(project),
                "--name",
                "devops-console",
                "--cwd",
                str(project),
                "--argv",
                json.dumps([sys.executable, str(Path(__file__).resolve()), "--listener", "{port}"]),
                "--range",
                f"{edge_port}-{edge_port}",
                "--preferred",
                str(edge_port),
            ],
            "stop": [
                "server",
                "stop",
                "--agent",
                "incapable-cli",
                "--project",
                str(project),
                "--name",
                "devops-console",
            ],
            "restart": [
                "server",
                "restart",
                "--agent",
                "incapable-cli",
                "--project",
                str(project),
                "--name",
                "devops-console",
            ],
        }
        for action, command in lifecycle_commands.items():
            failed = plain_cli(command, succeeds=False)
            if "listener identity is unobservable" not in failed.stderr:
                raise AssertionError(f"incapable plain {action} had the wrong failure: {failed.stderr}")
            if listener.poll() is not None or edge_signature() != before_incapable:
                raise AssertionError(
                    f"incapable plain {action} signalled, launched, or changed the registration graph"
                )

        for action in ("start", "restart", "stop"):
            failed = plain_cli(
                [
                    "project",
                    action,
                    "--agent",
                    "incapable-cli",
                    "--project",
                    str(project),
                ],
                succeeds=False,
            )
            if "listener identity is unobservable" not in failed.stderr:
                raise AssertionError(
                    f"incapable project {action} did not fail at identity preflight: {failed.stderr}"
                )
            if listener.poll() is not None or edge_signature() != before_incapable:
                raise AssertionError(
                    f"incapable project {action} partially mutated before identity proof"
                )

        capable_inventory = api_request(cap_api_port, "GET", "/v1/inventory", token=token)
        capable_server = next(item for item in capable_inventory["servers"] if item.get("id") == server_id)
        if not (
            capable_server.get("status") == "running"
            and (((capable_server.get("health") or {}).get("identity") or {}).get("ok") is True)
        ):
            raise AssertionError("capability-matched API did not restore strict listener proof after CLI inventory")
        capable_status = api_request(
            cap_api_port,
            "POST",
            "/v1/servers/status",
            token=token,
            payload={"project": str(project), "name": "devops-console"},
        )
        if not (
            capable_status.get("status") == "running"
            and ((capable_status.get("health") or {}).get("identity") or {}).get("ok") is True
        ):
            raise AssertionError("capability-matched API status lost authorized listener proof")

        child_port = free_port()
        child_caps = root / "managed-child-capabilities.json"
        child_code = (
            "import http.server,json,pathlib,socketserver,sys\n"
            "caps={}\n"
            "for line in open('/proc/self/status'):\n"
            " key,sep,value=line.partition(':')\n"
            " if sep and key in {'CapInh','CapPrm','CapEff','CapBnd','CapAmb'}: caps[key]=value.strip()\n"
            "pathlib.Path(sys.argv[2]).write_text(json.dumps(caps))\n"
            "class S(socketserver.TCPServer): allow_reuse_address=True\n"
            "class H(http.server.BaseHTTPRequestHandler):\n"
            " def log_message(self,*args): pass\n"
            " def do_GET(self): self.send_response(200); self.end_headers(); self.wfile.write(b'ok')\n"
            "S(('127.0.0.1',int(sys.argv[1])),H).serve_forever()\n"
        )
        child = api_request(
            cap_api_port,
            "POST",
            "/v1/servers/start",
            token=token,
            payload={
                "agent": "capability-integration",
                "project": str(project),
                "name": "capability-child",
                "cwd": str(project),
                "argv": [sys.executable, "-c", child_code, "{port}", str(child_caps)],
                "range": f"{child_port}-{child_port}",
                "preferred": child_port,
                "health_url": f"http://127.0.0.1:{child_port}/",
                "health_timeout": 10,
            },
        )
        if child.get("status") != "running":
            raise AssertionError(f"managed capability child did not start: {child}")
        caps = json.loads(child_caps.read_text(encoding="utf-8"))
        for name in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
            if int(caps.get(name, "1"), 16) != 0:
                raise AssertionError(f"managed child inherited active capability {name}={caps.get(name)}")
        if int(caps.get("CapBnd", "0"), 16) != expected_child_bounding:
            raise AssertionError(
                "managed child capability ceiling did not inherit the API's default ceiling: "
                f"api={cap_api_capabilities.get('CapBnd')} child={caps.get('CapBnd')}"
            )
        api_request(
            cap_api_port,
            "POST",
            "/v1/servers/stop",
            token=token,
            payload={
                "agent": "capability-integration",
                "project": str(project),
                "name": "capability-child",
            },
        )
        print(
            "capability integration ok (asymmetric recall, fail-closed lifecycle, "
            "relocation lease, child active-cap non-propagation, inherited bounding ceiling)"
        )
        return 0
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
        shutil.rmtree(root, ignore_errors=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listener", type=int)
    parser.add_argument("--pid-file", type=Path)
    parser.add_argument("--exec-capability-snapshot", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.listener is not None:
        return listener_main(args.listener, args.pid_file)
    if args.exec_capability_snapshot is not None:
        command = list(args.command)
        if command and command[0] == "--":
            command.pop(0)
        return exec_with_capability_snapshot(args.exec_capability_snapshot, command)
    return run_integration()


if __name__ == "__main__":
    raise SystemExit(main())
