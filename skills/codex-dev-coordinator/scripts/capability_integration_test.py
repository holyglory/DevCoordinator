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
import select
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlencode


SCRIPT = Path(__file__).with_name("dev_coordinator.py").resolve()
CAPABILITY = "net_bind_service"


def canonical_test_temp_base() -> Path:
    """Return a writable canonical base outside any host/user Git marker."""

    candidates = (
        os.environ.get("DEVCOORDINATOR_TEST_TMP_ROOT"),
        pwd.getpwuid(os.geteuid()).pw_dir,
        tempfile.gettempdir(),
    )
    for raw in dict.fromkeys(value for value in candidates if value):
        base = Path(str(raw)).resolve()
        if not base.is_dir() or not os.access(base, os.W_OK | os.X_OK):
            continue
        cursor = base
        while not ((cursor / ".git").exists() or (cursor / ".git").is_symlink()):
            if cursor.parent == cursor:
                return base
            cursor = cursor.parent
    raise RuntimeError("no writable test temp root exists outside every Git worktree")


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


def terminate_test_process(process: subprocess.Popen[str]) -> None:
    """Terminate one isolated test-owned process group."""

    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)


def linux_pid_active(pid: int | None) -> bool:
    """Return whether one Linux PID still names a non-zombie process."""

    if not pid:
        return False
    try:
        stat_text = (Path("/proc") / str(int(pid)) / "stat").read_text(
            encoding="utf-8"
        )
    except (FileNotFoundError, ProcessLookupError):
        return False
    except OSError:
        return True
    _prefix, separator, suffix = stat_text.rpartition(") ")
    return bool(separator and suffix and suffix[0] not in {"Z", "X"})


def wait_pid_inactive(pid: int, *, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not linux_pid_active(pid):
            return True
        time.sleep(0.05)
    return not linux_pid_active(pid)


def _marked_process_identity(
    process: Path,
    *,
    marker_bytes: bytes,
    expected_cwd: Path,
) -> tuple[str, tuple[bytes, ...], str] | None:
    try:
        stat_text = (process / "stat").read_text(encoding="utf-8")
        _prefix, separator, suffix = stat_text.rpartition(") ")
        fields = suffix.split() if separator else []
        command = tuple((process / "cmdline").read_bytes().split(b"\0"))
        process_cwd = (process / "cwd").resolve(strict=True)
    except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
        return None
    if len(fields) <= 19 or marker_bytes not in command:
        return None
    if not (
        process_cwd == expected_cwd or expected_cwd in process_cwd.parents
    ):
        return None
    return fields[19], command, str(process_cwd)


def _wait_pidfd(pidfd: int, *, timeout: float) -> bool:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    return bool(poller.poll(round(timeout * 1000)))


def _terminate_marked_pidfd(
    pid: int,
    *,
    expected_identity: tuple[str, tuple[bytes, ...], str],
    marker_bytes: bytes,
    expected_cwd: Path,
) -> str | None:
    opener = getattr(os, "pidfd_open", None)
    sender = getattr(signal, "pidfd_send_signal", None)
    if opener is None or sender is None or not hasattr(select, "poll"):
        return "Linux pidfd support is required for race-free fixture cleanup"
    try:
        pidfd = opener(pid, 0)
    except ProcessLookupError:
        return None
    try:
        bound_identity = _marked_process_identity(
            Path("/proc") / str(pid),
            marker_bytes=marker_bytes,
            expected_cwd=expected_cwd,
        )
        if bound_identity is None:
            if _wait_pidfd(pidfd, timeout=0.0):
                return None
            return "process marker or cwd changed while binding pidfd; refusing to signal"
        if bound_identity != expected_identity:
            return "process identity changed while binding pidfd; refusing to signal"
        try:
            sender(pidfd, signal.SIGTERM, None, 0)
        except ProcessLookupError:
            return None
        if _wait_pidfd(pidfd, timeout=5.0):
            return None
        try:
            sender(pidfd, signal.SIGKILL, None, 0)
        except ProcessLookupError:
            return None
        if not _wait_pidfd(pidfd, timeout=5.0):
            return "process did not exit after pidfd SIGKILL"
        return None
    finally:
        os.close(pidfd)


def terminate_marked_test_processes(marker: Path, *, cwd: Path) -> tuple[list[int], list[str]]:
    """Race-safely terminate marked children and prove a stable clean sweep."""

    marker_bytes = os.fsencode(str(marker))
    expected_cwd = cwd.resolve()
    matched: set[int] = set()
    failures_by_pid: dict[int, str] = {}
    deadline = time.monotonic() + 6.0
    stable_since: float | None = None
    while time.monotonic() < deadline:
        observed: list[tuple[int, tuple[str, tuple[bytes, ...], str]]] = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            identity = _marked_process_identity(
                entry,
                marker_bytes=marker_bytes,
                expected_cwd=expected_cwd,
            )
            if identity is not None:
                observed.append((int(entry.name), identity))
        if not observed:
            if stable_since is None:
                stable_since = time.monotonic()
            elif time.monotonic() - stable_since >= 0.5:
                return sorted(matched), [
                    f"marked managed child PID {pid}: {message}"
                    for pid, message in sorted(failures_by_pid.items())
                ]
            time.sleep(0.05)
            continue
        stable_since = None
        for pid, identity in observed:
            matched.add(pid)
            failure = _terminate_marked_pidfd(
                pid,
                expected_identity=identity,
                marker_bytes=marker_bytes,
                expected_cwd=expected_cwd,
            )
            if failure is not None:
                failures_by_pid[pid] = failure
        time.sleep(0.05)
    remaining = sorted(
        int(entry.name)
        for entry in Path("/proc").iterdir()
        if entry.name.isdigit()
        and _marked_process_identity(
            entry,
            marker_bytes=marker_bytes,
            expected_cwd=expected_cwd,
        )
        is not None
    )
    if remaining:
        failures_by_pid[-1] = f"stable no-match sweep timed out; remaining PIDs={remaining}"
    return sorted(matched), [
        f"marked managed child PID {pid}: {message}"
        for pid, message in sorted(failures_by_pid.items())
    ]


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


def run_coordinator_json(
    env: dict[str, str], arguments: list[str], *, context: str
) -> dict[str, object]:
    try:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), *arguments],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(f"{context} timed out after 30 seconds") from exc
    if completed.returncode != 0:
        raise AssertionError(
            f"{context} failed ({completed.returncode}): "
            f"{completed.stdout}\n{completed.stderr}"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"{context} returned invalid JSON: {completed.stdout}\n{completed.stderr}"
        ) from exc
    if not isinstance(payload, dict):
        raise AssertionError(f"{context} did not return an object: {payload!r}")
    return payload


def control_graph_signature(state: dict[str, object]) -> dict[str, object]:
    """Select lifecycle fields that an incapable observation must not change."""

    servers = state.get("servers") or {}
    leases = state.get("leases") or {}
    assignments = state.get("port_assignments") or {}
    operations = state.get("operations") or {}
    if not all(
        isinstance(value, dict)
        for value in (servers, leases, assignments, operations)
    ):
        raise AssertionError("control state does not contain object lifecycle collections")
    return {
        "servers": {
            str(server_id): {
                key: server.get(key)
                for key in ("status", "pid", "lease_id", "generation", "operation_id")
            }
            for server_id, server in servers.items()
            if isinstance(server, dict)
        },
        "leases": {
            str(lease_id): {
                key: lease.get(key)
                for key in ("status", "server_id", "owner_pid", "assignment_key")
            }
            for lease_id, lease in leases.items()
            if isinstance(lease, dict)
        },
        "assignments": {
            str(key): {
                field: assignment.get(field)
                for field in ("project", "name", "port", "status")
            }
            for key, assignment in assignments.items()
            if isinstance(assignment, dict)
        },
        "operation_ids": sorted(str(key) for key in operations),
    }


def normalized_inventory_lease(
    inventory: dict[str, object], lease_id: str
) -> dict[str, object]:
    """Return one exact v2 lease without accepting the legacy `id` shape."""

    leases = inventory.get("leases")
    if not isinstance(leases, list):
        raise AssertionError("normalized inventory leases are not a list")
    matches = [
        item
        for item in leases
        if isinstance(item, dict) and item.get("lease_id") == lease_id
    ]
    if len(matches) != 1:
        observed_ids = [
            item.get("lease_id") for item in leases if isinstance(item, dict)
        ]
        raise AssertionError(
            f"normalized inventory did not contain lease {lease_id!r} exactly once; "
            f"observed lease_ids={observed_ids}"
        )
    return matches[0]


def bootstrap_normalized_fixture(
    *, root: Path, project: Path, env: dict[str, str]
) -> None:
    """Create isolated SQLite authority without discovering account state."""

    legacy_home = root / "empty-legacy-source"
    legacy_home.mkdir(mode=0o700)
    legacy_state = {
        "version": 2,
        "revision": 0,
        "created_at": "2026-07-15T00:00:00Z",
        "updated_at": "2026-07-15T00:00:00Z",
        "leases": {},
        "servers": {},
        "port_assignments": {},
        "history": [],
        "operations": {},
        "docker": {"last_commands": [], "stats_history": {}, "metadata": {}},
    }
    legacy_state_file = legacy_home / "state.json"
    legacy_state_file.write_text(
        json.dumps(legacy_state, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    legacy_state_file.chmod(0o600)
    backup_root = root / "legacy-import-backups"
    observed = run_coordinator_json(
        env,
        [
            "observe",
            "--agent",
            "capability-integration",
            "--project",
            str(project),
            "--no-docker",
            "--legacy-home",
            str(legacy_home),
            "--legacy-backup-root",
            str(backup_root),
        ],
        context="normalized fixture bootstrap",
    )
    imported = observed.get("imported")
    if not (
        isinstance(imported, dict)
        and imported.get("source_count") == 1
        and imported.get("repository_count") == 0
        and imported.get("conflict_count") == 0
        and imported.get("blocking_conflict_count") == 0
    ):
        raise AssertionError(
            "normalized fixture bootstrap did not import exactly the isolated "
            f"empty source: {observed}"
        )
    inventory = run_coordinator_json(
        env,
        ["inventory", "--no-docker"],
        context="normalized fixture inventory",
    )
    source_homes = {
        str(item.get("canonical_home"))
        for item in inventory.get("coordinator_sources", [])
        if isinstance(item, dict)
    }
    expected_homes = {
        str(legacy_home),
        str(Path(env["CODEX_AGENT_COORDINATOR_HOME"]) / "coordinator.sqlite3"),
    }
    if source_homes != expected_homes:
        raise AssertionError(
            "normalized fixture imported coordinator state outside its private source: "
            f"homes={sorted(source_homes)} "
            f"sources={inventory.get('coordinator_sources')}"
        )


def prepare_relocation_fixture(
    *,
    root: Path,
    old_project: Path,
    new_project: Path,
    port: int,
    env: dict[str, str],
    processes: list[subprocess.Popen[str]],
) -> tuple[str, str]:
    """Build the stopped relocation graph through public normalized actions."""

    fixture_pid_file = root / "relocation-listener.pid"
    listener = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--listener",
            str(port),
            "--pid-file",
            str(fixture_pid_file),
        ],
        cwd=old_project,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    processes.append(listener)
    wait_health(port, listener)
    listener_pid = int(fixture_pid_file.read_text(encoding="utf-8").strip())
    registered = run_coordinator_json(
        env,
        [
            "server",
            "register",
            "--agent",
            "capability-integration",
            "--project",
            str(old_project),
            "--name",
            "devops-console",
            "--cwd",
            str(old_project),
            "--argv",
            json.dumps(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--listener",
                    "{port}",
                ]
            ),
            "--pid",
            str(listener_pid),
            "--port",
            str(port),
            "--url",
            f"http://127.0.0.1:{port}",
            "--health-url",
            f"http://127.0.0.1:{port}/healthz",
        ],
        context="normalized relocation registration",
    )
    server_id = str(registered.get("id") or "")
    lease_id = str(registered.get("lease_id") or "")
    if not server_id or not lease_id or registered.get("status") != "running":
        raise AssertionError(
            f"normalized relocation registration was incomplete: {registered}"
        )
    stopped = run_coordinator_json(
        env,
        [
            "server",
            "stop",
            "--agent",
            "capability-integration",
            "--project",
            str(old_project),
            "--name",
            "devops-console",
            "--reason",
            "Prepared normalized relocation fixture",
        ],
        context="normalized relocation stop",
    )
    if stopped.get("status") != "stopped" or str(stopped.get("lease_id") or "") != lease_id:
        raise AssertionError(f"normalized relocation stop lost its exact lease: {stopped}")
    listener.wait(timeout=10)
    relocated = run_coordinator_json(
        env,
        [
            "port",
            "relocate",
            "--agent",
            "capability-integration",
            "--old-project",
            str(old_project),
            "--new-project",
            str(new_project),
            "--name",
            "devops-console",
            "--port",
            str(port),
            "--lease-id",
            lease_id,
        ],
        context="normalized relocation",
    )
    if not (
        relocated.get("id") == server_id
        and relocated.get("project") == str(new_project)
        and relocated.get("lease_id") == lease_id
        and relocated.get("lease_status") == "stale"
    ):
        raise AssertionError(f"normalized relocation changed server identity: {relocated}")
    return server_id, lease_id


def run_normalized_relocation_preflight() -> int:
    """Exercise the platform-neutral half of the Linux cutover fixture."""

    root = Path(
        tempfile.mkdtemp(
            prefix="coordinator-relocation-preflight-",
            dir=canonical_test_temp_base(),
        )
    ).resolve(strict=True)
    old_project = root / "legacy"
    new_project = root / "DevCoordinator"
    for repository in (old_project, new_project):
        repository.mkdir()
        (repository / ".git").mkdir()
    home = root / "state"
    env = os.environ.copy()
    env["CODEX_AGENT_COORDINATOR_HOME"] = str(home)
    env["DEVCOORDINATOR_STATE_BACKEND"] = "sqlite"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    processes: list[subprocess.Popen[str]] = []
    try:
        bootstrap_normalized_fixture(root=root, project=old_project, env=env)
        port = free_port()
        server_id, lease_id = prepare_relocation_fixture(
            root=root,
            old_project=old_project,
            new_project=new_project,
            port=port,
            env=env,
            processes=processes,
        )
        state = run_coordinator_json(
            env,
            ["state", "show"],
            context="relocation preflight state",
        )
        inventory = run_coordinator_json(
            env,
            ["inventory", "--project", str(new_project), "--no-docker"],
            context="relocation preflight inventory",
        )
        lease = normalized_inventory_lease(inventory, lease_id)
        server = (state.get("servers") or {}).get(server_id)
        assignment = (state.get("port_assignments") or {}).get(
            f"{new_project}::devops-console"
        )
        if not (
            isinstance(server, dict)
            and server.get("project") == str(new_project)
            and server.get("status") == "stopped"
            and isinstance(assignment, dict)
            and assignment.get("project") == str(new_project)
            and assignment.get("port") == port
            and lease.get("status") == "stale"
        ):
            raise AssertionError(
                "public normalized relocation preflight did not preserve its exact graph: "
                f"server={server} assignment={assignment} lease={lease}"
            )
        print("normalized relocation preflight ok")
        return 0
    finally:
        primary_error = sys.exc_info()[1]
        cleanup_failures: list[str] = []
        for process in reversed(processes):
            try:
                terminate_test_process(process)
            except BaseException as cleanup_error:
                cleanup_failures.append(
                    "tracked process group "
                    f"{process.pid}: {type(cleanup_error).__name__}: {cleanup_error}"
                )
        shutil.rmtree(root, ignore_errors=True)
        if cleanup_failures:
            cleanup_summary = "; ".join(cleanup_failures)
            if primary_error is not None:
                raise RuntimeError(
                    "normalized relocation preflight failed and cleanup also failed; "
                    f"primary={type(primary_error).__name__}: {primary_error}; "
                    f"cleanup={cleanup_summary}"
                ) from primary_error
            raise AssertionError(
                "normalized relocation preflight cleanup failed: " + cleanup_summary
            )


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
    subprocess.run(
        ["sudo", "-n", "true"],
        check=True,
        stdout=subprocess.DEVNULL,
        timeout=10,
    )
    host_default_bounding = int(current_capability_sets()["CapBnd"], 16)

    root = Path(
        tempfile.mkdtemp(
            prefix="coordinator-capability-integration-",
            dir=canonical_test_temp_base(),
        )
    ).resolve(strict=True)
    old_project = root / "legacy"
    project = root / "DevCoordinator"
    for repository in (old_project, project):
        repository.mkdir()
        (repository / ".git").mkdir()
    home = root / "state"
    processes: list[subprocess.Popen[str]] = []
    cap_api: subprocess.Popen[str] | None = None
    cap_api_port: int | None = None
    token: str | None = None
    edge_registered = False
    child_registered = False
    edge_start_attempted = False
    child_start_attempted = False
    edge_pid: int | None = None
    child_pid: int | None = None
    child_marker = root / "managed-child-capabilities.json"
    try:
        env = os.environ.copy()
        env["CODEX_AGENT_COORDINATOR_HOME"] = str(home)
        env["DEVCOORDINATOR_STATE_BACKEND"] = "sqlite"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        bootstrap_normalized_fixture(root=root, project=old_project, env=env)
        edge_port = free_port()
        server_id, old_lease_id = prepare_relocation_fixture(
            root=root,
            old_project=old_project,
            new_project=project,
            port=edge_port,
            env=env,
            processes=processes,
        )

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
            start_new_session=True,
        )
        processes.append(listener)
        wait_health(edge_port, listener)
        listener_pid = int(listener_pid_file.read_text(encoding="utf-8").strip())
        edge_pid = listener_pid

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
            start_new_session=True,
        )
        processes.append(no_cap_api)
        wait_health(no_cap_port, no_cap_api)
        token = (home / "api-token").read_text(encoding="utf-8").strip()
        before_no_cap_registration = control_graph_signature(
            run_coordinator_json(
                env,
                ["state", "show"],
                context="pre-registration control state",
            )
        )
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
        after_no_cap_registration = control_graph_signature(
            run_coordinator_json(
                env,
                ["state", "show"],
                context="post-registration control state",
            )
        )
        if after_no_cap_registration != before_no_cap_registration:
            raise AssertionError(
                "no-cap registration wrote lifecycle or operation state before "
                "listener identity proof"
            )
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
                "DEVCOORDINATOR_STATE_BACKEND=sqlite",
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
            start_new_session=True,
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
        for capability_set in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
            if not int(str(cap_api_capabilities.get(capability_set, "0")), 16) & (1 << 10):
                raise AssertionError(
                    "capability API did not receive CAP_NET_BIND_SERVICE in "
                    f"{capability_set}: {cap_api_capabilities}"
                )
        edge_start_attempted = True
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
        edge_registered = True
        if (
            registered.get("id") != server_id
            or not registered.get("lease_id")
            or registered.get("lease_id") == old_lease_id
            or (registered.get("registration_identity") or {}).get("pid") != listener_pid
            or (registered.get("registration_identity") or {}).get("host") != "127.0.0.1"
            or not (registered.get("registration_identity") or {}).get("listener_inodes")
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
            and bool(server.get("process_start_time"))
            and bool(server.get("process_fingerprint"))
            and server.get("identity_observable") is True
            and (server.get("health") or {}).get("ok") is True
            and isinstance(lease, dict)
            and lease.get("server_id") == server_id
            and lease.get("owner_pid") == listener_pid
            and lease.get("purpose") == "server:devops-console"
            and lease.get("assignment_key") == f"{project}::devops-console"
            and isinstance(assignment, dict)
            and assignment.get("port") == edge_port
        ):
            raise AssertionError("relocated server, replacement lease, and assignment are not fully linked")

        plain_inventory = subprocess.run(
            [sys.executable, str(SCRIPT), "inventory", "--project", str(project), "--no-docker"],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        if plain_inventory.returncode != 0:
            raise AssertionError(
                f"plain CLI inventory could not preserve an unobservable capable listener: "
                f"{plain_inventory.stdout}\n{plain_inventory.stderr}"
            )
        plain_payload = json.loads(plain_inventory.stdout)
        plain_server = next(item for item in plain_payload["servers"] if item.get("id") == server_id)
        plain_lease = normalized_inventory_lease(
            plain_payload, str(registered["lease_id"])
        )
        if not (
            plain_server.get("status") == "running"
            and (plain_server.get("health") or {}).get("ok") is True
            and (plain_server.get("health") or {}).get("classification") == "healthy"
            and plain_server.get("identity_observable") is True
            and plain_lease.get("status") == "active"
        ):
            raise AssertionError(
                "pure CLI inventory did not preserve the last committed capable observation"
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
            and plain_status_payload.get("identity_observable") is False
            and edge_signature() == before_incapable
        ):
            raise AssertionError("incapable plain status changed lifecycle/lease state or hid uncertainty")

        cached_inventory = api_request(cap_api_port, "GET", "/v1/inventory", token=token)
        cached_server = next(
            item for item in cached_inventory["servers"] if item.get("id") == server_id
        )
        cached_lease = normalized_inventory_lease(
            cached_inventory, str(registered["lease_id"])
        )
        if not (
            cached_server.get("status") == "running"
            and (cached_server.get("health") or {}).get("ok") is None
            and (cached_server.get("health") or {}).get("classification")
            == "unverified-listener"
            and cached_server.get("identity_observable") is False
            and cached_lease.get("status") == "active"
        ):
            raise AssertionError(
                "pure API inventory did not preserve the cached unknown observation and active lease"
            )

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

        readiness_query = urlencode(
            {
                "project": str(project),
                "name": "devops-console",
                "port": edge_port,
            }
        )
        capable_inventory = api_request(
            cap_api_port,
            "GET",
            f"/v1/inventory/no-docker?{readiness_query}",
            token=token,
        )
        capable_server = next(
            item
            for item in capable_inventory["v1_compatibility"]["servers"]
            if item.get("id") == server_id
        )
        if not (
            capable_server.get("status") == "running"
            and (capable_server.get("registration_identity") or {}).get("ok") is True
            and (capable_server.get("registration_identity") or {}).get("pid") == listener_pid
            and (capable_server.get("registration_identity") or {}).get("host") == "127.0.0.1"
            and bool(
                (capable_server.get("registration_identity") or {}).get(
                    "listener_inodes"
                )
            )
        ):
            raise AssertionError(
                "target-scoped capable inventory did not provide strict current listener proof"
            )
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
        restored_inventory = api_request(
            cap_api_port, "GET", "/v1/inventory", token=token
        )
        restored_server = next(
            item for item in restored_inventory["servers"] if item.get("id") == server_id
        )
        if not (
            restored_server.get("status") == "running"
            and (restored_server.get("health") or {}).get("ok") is True
            and (restored_server.get("health") or {}).get("classification") == "healthy"
            and restored_server.get("identity_observable") is True
        ):
            raise AssertionError(
                "capable status did not persist restored healthy listener evidence"
            )

        child_port = free_port()
        child_caps = child_marker
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
        child_start_attempted = True
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
        child_registered = True
        child_pid = int(child.get("pid") or 0) or None
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
        child_registered = False
        api_request(
            cap_api_port,
            "POST",
            "/v1/servers/stop",
            token=token,
            payload={
                "agent": "capability-integration",
                "project": str(project),
                "name": "devops-console",
            },
        )
        edge_registered = False
        listener.wait(timeout=10)
        print(
            "capability integration ok (asymmetric recall, fail-closed lifecycle, "
            "relocation lease, child active-cap non-propagation, inherited bounding ceiling)"
        )
        return 0
    finally:
        primary_error = sys.exc_info()[1]
        cleanup_failures: list[str] = []
        if (
            cap_api is not None
            and cap_api.poll() is None
            and cap_api_port is not None
            and token
        ):
            cleanup_state: dict[str, object] | None = None
            try:
                cleanup_state = api_request(
                    cap_api_port, "GET", "/v1/state", token=token
                )
            except BaseException as cleanup_error:
                cleanup_failures.append(
                    "state reconciliation: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
            if cleanup_state is not None:
                state_servers = cleanup_state.get("servers") or {}
                if not isinstance(state_servers, dict):
                    cleanup_failures.append("state reconciliation returned invalid servers")
                    state_servers = {}
                for attempted, name in (
                    (child_start_attempted or child_registered, "capability-child"),
                    (edge_start_attempted or edge_registered, "devops-console"),
                ):
                    if not attempted:
                        continue
                    matching = next(
                        (
                            value
                            for value in state_servers.values()
                            if isinstance(value, dict)
                            and value.get("project") == str(project)
                            and value.get("name") == name
                        ),
                        None,
                    )
                    if matching is None:
                        continue
                    retained_pid = int(matching.get("pid") or 0) or None
                    if name == "capability-child" and retained_pid is not None:
                        child_pid = retained_pid
                    if name == "devops-console" and retained_pid is not None:
                        edge_pid = retained_pid
                    if matching.get("status") == "stopped" and retained_pid is None:
                        continue
                    try:
                        api_request(
                            cap_api_port,
                            "POST",
                            "/v1/servers/stop",
                            token=token,
                            payload={
                                "agent": "capability-integration-cleanup",
                                "project": str(project),
                                "name": name,
                            },
                        )
                    except BaseException as cleanup_error:
                        cleanup_failures.append(
                            f"{name}: {type(cleanup_error).__name__}: {cleanup_error}"
                        )
        for process in reversed(processes):
            try:
                terminate_test_process(process)
            except BaseException as cleanup_error:
                cleanup_failures.append(
                    "tracked process group "
                    f"{process.pid}: {type(cleanup_error).__name__}: {cleanup_error}"
                )
        try:
            _marked_pids, marker_failures = terminate_marked_test_processes(
                child_marker, cwd=project
            )
        except BaseException as cleanup_error:
            cleanup_failures.append(
                "marked process sweep: "
                f"{type(cleanup_error).__name__}: {cleanup_error}"
            )
        else:
            cleanup_failures.extend(marker_failures)
        for label, pid in (("managed child", child_pid), ("edge listener", edge_pid)):
            if pid is not None and not wait_pid_inactive(pid):
                cleanup_failures.append(f"{label} PID {pid} remained active after cleanup")
        shutil.rmtree(root, ignore_errors=True)
        if cleanup_failures:
            cleanup_summary = "; ".join(cleanup_failures)
            if primary_error is not None:
                raise RuntimeError(
                    "capability integration failed and cleanup also failed; "
                    f"primary={type(primary_error).__name__}: {primary_error}; "
                    f"cleanup={cleanup_summary}"
                ) from primary_error
            raise AssertionError(
                "capability integration cleanup failed: " + cleanup_summary
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listener", type=int)
    parser.add_argument("--pid-file", type=Path)
    parser.add_argument("--exec-capability-snapshot", type=Path)
    parser.add_argument("--normalized-relocation-preflight", action="store_true")
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
    if args.normalized_relocation_preflight:
        return run_normalized_relocation_preflight()
    return run_integration()


if __name__ == "__main__":
    raise SystemExit(main())
