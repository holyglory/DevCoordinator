#!/usr/bin/env python3
"""Deterministic multi-runtime and OS-user boundary tests."""

from __future__ import annotations

import concurrent.futures
import json
import os
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from shutil import rmtree


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "dev_coordinator.py"

WRAPPER_SOURCE = """\
import os
from pathlib import Path
import pwd
import runpy
import sys
import time

target = os.environ.pop("COORDINATOR_TEST_SCRIPT")
account_home = os.environ.pop("COORDINATOR_TEST_ACCOUNT_HOME")
account_uid = int(os.environ.pop("COORDINATOR_TEST_ACCOUNT_UID"))
real_getpwuid = pwd.getpwuid

class AccountRecord:
    pw_dir = account_home

def fixture_getpwuid(uid):
    if int(uid) == account_uid:
        return AccountRecord()
    return real_getpwuid(uid)

pwd.getpwuid = fixture_getpwuid
barrier_raw = os.environ.pop("COORDINATOR_TEST_START_BARRIER", "")
barrier_count = int(os.environ.pop("COORDINATOR_TEST_START_BARRIER_COUNT", "0") or 0)
if barrier_raw:
    barrier = Path(barrier_raw)
    barrier.mkdir(parents=True, exist_ok=True)
    (barrier / f"ready-{os.getpid()}").write_text("ready", encoding="utf-8")
    deadline = time.monotonic() + 5.0
    while len(list(barrier.glob("ready-*"))) < barrier_count:
        if time.monotonic() >= deadline:
            raise RuntimeError("multi-runtime start barrier timed out")
        time.sleep(0.005)
sys.argv = [target, *sys.argv[1:]]
runpy.run_path(target, run_name="__main__")
"""

SERVER_SOURCE = """\
import json
import os
import signal
import socket
import sys
import time

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", int(sys.argv[1])))
listener.listen(8)
listener.settimeout(0.05)
print(json.dumps({"pid": os.getpid(), "port": listener.getsockname()[1]}), flush=True)

def stop(_signal, _frame):
    listener.close()
    raise SystemExit(0)

signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
while True:
    try:
        connection, _address = listener.accept()
    except socket.timeout:
        continue
    with connection:
        connection.settimeout(0.5)
        try:
            connection.recv(4096)
            connection.sendall(
                b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\n"
                b"Connection: close\\r\\n\\r\\nOK"
            )
        except (BrokenPipeError, ConnectionError, socket.timeout):
            pass
"""


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run(
    wrapper: Path,
    args: list[str],
    *,
    env: dict[str, str],
) -> dict:
    result = subprocess.run(
        [sys.executable, str(wrapper), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=20,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"command failed: {' '.join(args)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return json.loads(result.stdout)


def fresh_port(excluded: set[int]) -> int:
    for _ in range(100):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            candidate = int(listener.getsockname()[1])
        if candidate not in excluded:
            excluded.add(candidate)
            return candidate
    raise AssertionError("could not allocate a fresh multi-runtime fixture port")


def inventory(
    wrapper: Path,
    project: Path,
    env: dict[str, str],
) -> dict:
    return run(
        wrapper,
        [
            "inventory",
            "--project",
            str(project),
            "--no-docker",
            "--compact-json",
            "--stats-history-limit",
            "0",
        ],
        env=env,
    )


def lease(
    wrapper: Path,
    project: Path,
    env: dict[str, str],
    *,
    agent: str,
    port_range: str,
    preferred: int,
) -> dict:
    return run(
        wrapper,
        [
            "port",
            "lease",
            "--agent",
            agent,
            "--project",
            str(project),
            "--range",
            port_range,
            "--preferred",
            str(preferred),
            "--ttl",
            "120",
        ],
        env=env,
    )


def parallel_leases(
    wrapper: Path,
    project: Path,
    cases: list[tuple[dict[str, str], str, str, int]],
) -> list[dict]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(cases)) as pool:
        futures = [
            pool.submit(
                lease,
                wrapper,
                project,
                environment,
                agent=agent,
                port_range=port_range,
                preferred=preferred,
            )
            for environment, agent, port_range, preferred in cases
        ]
        return [future.result(timeout=25) for future in futures]


def main() -> int:
    root = Path(tempfile.mkdtemp(prefix="coordinator-multi-runtime-test-")).resolve(strict=True)
    try:
        project = root / "project"
        project.mkdir()
        (project / ".git").mkdir()
        empty_path = root / "empty-path"
        empty_path.mkdir()
        wrapper = root / "coordinator-wrapper.py"
        wrapper.write_text(WRAPPER_SOURCE, encoding="utf-8")
        wrapper.chmod(0o700)
        account_home = root / "posix-account-home"
        account_home.mkdir()
        effective_uid = os.geteuid()

        base_environment = os.environ.copy()
        for key in (
            "CODEX_AGENT_COORDINATOR_HOME",
            "CODEX_AGENT_COORDINATOR_TOKEN_FILE",
            "COORDINATOR_TEST_START_BARRIER",
            "COORDINATOR_TEST_START_BARRIER_COUNT",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
        ):
            base_environment.pop(key, None)
        base_environment.update(
            {
                "PATH": str(empty_path),
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                # This fixture exercises the explicit isolated-account
                # compatibility topology. Product default is server-wide.
                "DEVCOORDINATOR_AUTHORITY": "account",
                "COORDINATOR_TEST_SCRIPT": str(SCRIPT),
                "COORDINATOR_TEST_ACCOUNT_HOME": str(account_home),
                "COORDINATOR_TEST_ACCOUNT_UID": str(effective_uid),
            }
        )

        runtime_environments: list[dict[str, str]] = []
        expected_home = account_home / ".codex" / "agent-coordinator"
        for index in range(2):
            runtime_home = root / f"runtime-{index}" / "home"
            runtime_home.mkdir(parents=True)
            environment = {
                **base_environment,
                "HOME": str(runtime_home),
                # This is the real Parall-shaped split: both variables differ
                # even though the processes retain one effective POSIX UID.
                "CFFIXED_USER_HOME": str(runtime_home),
                "USER": f"runtime-label-{index}",
                "LOGNAME": f"runtime-label-{index}",
            }
            runtime_environments.append(environment)

        # Same-UID app instances in explicit account mode without a home
        # override must share one SQLite WAL authority. The process barrier makes both commands reach
        # their first store open before either may proceed, so this catches WAL
        # setup races instead of merely hoping the subprocesses overlap.
        issued_ports: set[int] = set()
        preferred = fresh_port(issued_ports)
        alternate = fresh_port(issued_ports)
        low, high = sorted((preferred, alternate))
        first_open_barrier = root / "first-open-barrier"
        shared_parallel = parallel_leases(
            wrapper,
            project,
            [
                (
                    {
                        **runtime_environments[index],
                        "COORDINATOR_TEST_START_BARRIER": str(first_open_barrier),
                        "COORDINATOR_TEST_START_BARRIER_COUNT": "2",
                    },
                    f"default-shared-runtime-{index}",
                    f"{low}-{high}",
                    low,
                )
                for index in range(2)
            ],
        )
        shared_ports = [item["port"] for item in shared_parallel]
        check(
            len(set(shared_ports)) == 2,
            f"same-UID default homes must serialize parallel leases: {shared_ports}",
        )
        observed_state_paths: set[str] = set()
        observed_generations: set[str] = set()
        for environment in runtime_environments:
            observed = inventory(wrapper, project, environment)
            observed_state_paths.add(str(observed.get("state_path") or ""))
            observed_generations.add(
                str((observed.get("store") or {}).get("database_generation") or "")
            )
            check(
                Path(observed["coordinator_home"]) == expected_home
                and {item.get("agent") for item in observed["leases"]}
                == {"default-shared-runtime-0", "default-shared-runtime-1"},
                "both remapped same-UID runtimes must converge on the POSIX account "
                "coordinator and observe the complete shared "
                f"lease set: {observed}",
            )
        database_path = expected_home / "coordinator.sqlite3"
        check(
            observed_state_paths == {str(database_path)},
            "same-UID runtimes must expose one exact normalized state path: "
            f"{observed_state_paths}",
        )
        check(
            len(observed_generations) == 1 and "" not in observed_generations,
            "same-UID runtimes must expose one non-empty database generation: "
            f"{observed_generations}",
        )
        with sqlite3.connect(f"file:{database_path}?mode=ro", uri=True) as connection:
            journal_mode = str(
                connection.execute("PRAGMA journal_mode").fetchone()[0]
            ).lower()
            stored_generation = str(
                connection.execute(
                    "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
                ).fetchone()[0]
            )
        check(journal_mode == "wal", f"normalized account store is not WAL: {journal_mode}")
        check(
            observed_generations == {stored_generation},
            "runtime inventory generation must match the exact SQLite authority: "
            f"{observed_generations} vs {stored_generation}",
        )
        check(
            stat.S_IMODE(expected_home.stat().st_mode) == 0o700
            and stat.S_ISREG(database_path.stat().st_mode)
            and database_path.stat().st_uid == effective_uid
            and stat.S_IMODE(database_path.stat().st_mode) == 0o600,
            "the account coordinator home and SQLite authority must remain private",
        )
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{database_path}{suffix}")
            if sidecar.exists():
                check(
                    stat.S_ISREG(sidecar.stat().st_mode)
                    and sidecar.stat().st_uid == effective_uid
                    and stat.S_IMODE(sidecar.stat().st_mode) == 0o600,
                    f"SQLite sidecar must remain a private regular file: {sidecar}",
                )
        legacy_lock = expected_home / "state.lock"
        check(
            not legacy_lock.exists(),
            "the default SQLite runtime must not create the legacy state.lock",
        )

        # Poison the old lock path with a directory. A default operation must
        # still succeed because SQLite/WAL, not the compatibility file lock,
        # owns cross-runtime concurrency.
        legacy_lock.mkdir()
        legacy_lock.chmod(0)
        poison_port = fresh_port(issued_ports)
        try:
            poisoned_result = lease(
                wrapper,
                project,
                runtime_environments[0],
                agent="default-with-legacy-lock-poisoned",
                port_range=str(poison_port),
                preferred=poison_port,
            )
        finally:
            legacy_lock.chmod(0o700)
            legacy_lock.rmdir()
        check(
            poisoned_result["port"] == poison_port,
            "default lease must ignore a poisoned legacy lock path",
        )
        check(
            not legacy_lock.exists(),
            "the default runtime must leave no legacy lock after the poison control",
        )

        # A real test-owned listener proves that server status and an explicit
        # normalized host observation can overlap across the two app runtimes
        # without projection, lock files, duplicate state, or a lost server.
        fixture_script = project / "multi-runtime-listener.py"
        fixture_script.write_text(SERVER_SOURCE, encoding="utf-8")
        fixture_script.chmod(0o700)
        server_port = fresh_port(issued_ports)
        server_process = subprocess.Popen(
            [sys.executable, str(fixture_script), str(server_port)],
            cwd=str(project),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            ready_line = server_process.stdout.readline() if server_process.stdout else ""
            if not ready_line:
                diagnostic = (
                    server_process.stderr.read() if server_process.stderr else ""
                )
                raise AssertionError(
                    f"test listener did not report readiness: {diagnostic}"
                )
            ready = json.loads(ready_line)
            check(
                int(ready["pid"]) == int(server_process.pid)
                and int(ready["port"]) == server_port,
                f"test listener readiness identity changed: {ready}",
            )
            registered = run(
                wrapper,
                [
                    "server",
                    "register",
                    "--agent",
                    "default-shared-runtime-0",
                    "--project",
                    str(project),
                    "--name",
                    "multi-runtime-listener",
                    "--argv",
                    json.dumps(
                        [sys.executable, str(fixture_script), str(server_port)]
                    ),
                    "--port",
                    str(server_port),
                    "--pid",
                    str(server_process.pid),
                    "--health-timeout",
                    "2",
                ],
                env=runtime_environments[0],
            )
            check(
                registered.get("status") == "running"
                and int(registered.get("port") or 0) == server_port,
                f"real listener registration failed: {registered}",
            )

            overlap_barrier = root / "server-observe-barrier"
            overlap_environments = [
                {
                    **runtime_environments[index],
                    "COORDINATOR_TEST_START_BARRIER": str(overlap_barrier),
                    "COORDINATOR_TEST_START_BARRIER_COUNT": "2",
                }
                for index in range(2)
            ]
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                status_future = pool.submit(
                    run,
                    wrapper,
                    [
                        "server",
                        "status",
                        "--project",
                        str(project),
                        "--name",
                        "multi-runtime-listener",
                    ],
                    env=overlap_environments[0],
                )
                observe_future = pool.submit(
                    run,
                    wrapper,
                    [
                        "observe",
                        "--agent",
                        "default-shared-runtime-1",
                        "--project",
                        str(project),
                        "--no-docker",
                        "--legacy-home",
                        str(root / "missing-legacy-home"),
                    ],
                    env=overlap_environments[1],
                )
                status_result = status_future.result(timeout=25)
                observe_result = observe_future.result(timeout=25)
            check(
                status_result.get("status") == "running",
                f"concurrent server status lost the listener: {status_result}",
            )
            check(
                observe_result.get("status") == "completed"
                and observe_result.get("observed") is True,
                f"concurrent explicit observation failed: {observe_result}",
            )
            post_overlap = inventory(wrapper, project, runtime_environments[1])
            check(
                any(
                    item.get("name") == "multi-runtime-listener"
                    and item.get("status") == "running"
                    for item in post_overlap.get("servers") or []
                ),
                "concurrent status/observe must retain one running server record: "
                f"{post_overlap.get('servers')}",
            )
            # Reap the test-owned child in this parent before asking the other
            # runtime to classify it. On platforms without procfs, an
            # unreaped child can remain visible to kill(2) even though it has
            # exited, which is deliberately not accepted as stopped proof.
            server_process.terminate()
            server_process.wait(timeout=5)
            stopped = run(
                wrapper,
                [
                    "server",
                    "status",
                    "--project",
                    str(project),
                    "--name",
                    "multi-runtime-listener",
                ],
                env=runtime_environments[0],
            )
            check(
                stopped.get("status") == "stopped",
                f"the second runtime did not observe the reaped listener stop: {stopped}",
            )
        finally:
            if server_process.poll() is None:
                server_process.terminate()
                try:
                    server_process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    server_process.kill()
                    server_process.wait(timeout=3)

        # Positive control for operator intent: an explicit absolute override
        # remains authoritative. Two deliberately different overrides are
        # independent and can duplicate a free port, so the docs must keep the
        # warning for this non-default topology.
        isolated_environments = []
        for index, environment in enumerate(runtime_environments):
            explicit_home = root / f"explicit-coordinator-{index}"
            explicit_environment = {
                **environment,
                "CODEX_AGENT_COORDINATOR_HOME": str(explicit_home),
            }
            observed = inventory(wrapper, project, explicit_environment)
            check(
                Path(observed["coordinator_home"]) == explicit_home,
                f"explicit coordinator override must remain authoritative: {observed}",
            )
            isolated_environments.append(explicit_environment)
        duplicate_port = fresh_port(issued_ports)
        isolated_duplicate = [
            lease(
                wrapper,
                project,
                isolated_environments[index],
                agent=f"explicit-isolated-{index}",
                port_range=str(duplicate_port),
                preferred=duplicate_port,
            )
            for index in range(2)
        ]
        check(
            [item["port"] for item in isolated_duplicate]
            == [duplicate_port, duplicate_port],
            "two deliberately separate explicit homes must not be mislabeled as "
            f"one coordination domain: {isolated_duplicate}",
        )

        if str(ROOT / "scripts") not in sys.path:
            sys.path.insert(0, str(ROOT / "scripts"))
        import dev_coordinator as coordinator

        # The explicit override must not depend on POSIX account lookup. This
        # false-positive guard keeps deliberate recovery/configuration usable
        # even if NSS/account discovery is temporarily unavailable.
        explicit_control = root / "explicit-authoritative-control"
        original_explicit_home = os.environ.get("CODEX_AGENT_COORDINATOR_HOME")
        original_getpwuid = coordinator.pwd.getpwuid
        os.environ["CODEX_AGENT_COORDINATOR_HOME"] = str(explicit_control)
        coordinator.pwd.getpwuid = lambda _uid: (_ for _ in ()).throw(
            AssertionError("explicit override must bypass account lookup")
        )
        try:
            check(
                coordinator.coordinator_home() == explicit_control.resolve(),
                "explicit coordinator home should remain authoritative",
            )
        finally:
            coordinator.pwd.getpwuid = original_getpwuid
            if original_explicit_home is None:
                os.environ.pop("CODEX_AGENT_COORDINATOR_HOME", None)
            else:
                os.environ["CODEX_AGENT_COORDINATOR_HOME"] = original_explicit_home

        class AccountRecord:
            def __init__(self, home: str) -> None:
                self.pw_dir = home

        account_records = {
            20001: AccountRecord("/home/coordinator-user-a"),
            20002: AccountRecord("/home/coordinator-user-b"),
        }

        def account_lookup(uid: int) -> AccountRecord:
            return account_records[int(uid)]

        first_user_home = coordinator.posix_account_home(
            effective_uid=20001,
            account_lookup=account_lookup,
        )
        second_user_home = coordinator.posix_account_home(
            effective_uid=20002,
            account_lookup=account_lookup,
        )
        check(
            first_user_home.name == "coordinator-user-a"
            and second_user_home.name == "coordinator-user-b"
            and first_user_home != second_user_home,
            "different effective POSIX UIDs must resolve distinct account homes: "
            f"{first_user_home}, {second_user_home}",
        )

        # Cross-OS-user sharing is forbidden even when a caller explicitly
        # names a reachable foreign path. Injecting another effective UID into
        # the production operation exercises fail-closed rejection before state
        # mutation without requiring root or modifying the host account DB.
        coordinator.validate_private_directory(expected_home, effective_uid=effective_uid)
        unsafe_mode_home = root / "unsafe-mode-coordinator"
        unsafe_mode_home.mkdir(mode=0o755)
        unsafe_mode_home.chmod(0o755)
        try:
            coordinator.validate_private_directory(
                unsafe_mode_home,
                effective_uid=effective_uid,
            )
        except PermissionError as error:
            check(
                "must be mode 0700" in str(error),
                f"unsafe-mode rejection should identify the boundary: {error}",
            )
        else:
            raise AssertionError(
                "a group/world-accessible coordinator directory must be rejected"
            )

        state_path = expected_home / "coordinator.sqlite3"
        state_before = state_path.read_bytes()
        original_coordinator_home = os.environ.get("CODEX_AGENT_COORDINATOR_HOME")
        original_geteuid = coordinator.os.geteuid
        os.environ["CODEX_AGENT_COORDINATOR_HOME"] = str(expected_home)
        coordinator.os.geteuid = lambda: effective_uid + 1
        try:
            coordinator.normalized_control_snapshot()
        except PermissionError as error:
            check(
                "owned by uid" in str(error),
                f"foreign-owner rejection should identify the boundary: {error}",
            )
        else:
            raise AssertionError(
                "a different effective OS user must not reuse another user's "
                "coordinator home"
            )
        finally:
            coordinator.os.geteuid = original_geteuid
            if original_coordinator_home is None:
                os.environ.pop("CODEX_AGENT_COORDINATOR_HOME", None)
            else:
                os.environ["CODEX_AGENT_COORDINATOR_HOME"] = original_coordinator_home
        check(
            state_path.read_bytes() == state_before,
            "foreign-UID rejection must happen before coordinator state mutation",
        )

        print("multi-runtime self-test ok")
        return 0
    finally:
        rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
