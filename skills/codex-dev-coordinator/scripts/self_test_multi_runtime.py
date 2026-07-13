#!/usr/bin/env python3
"""Deterministic multi-runtime and OS-user boundary tests."""

from __future__ import annotations

import concurrent.futures
import json
import os
import socket
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
import pwd
import runpy
import sys

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
sys.argv = [target, *sys.argv[1:]]
runpy.run_path(target, run_name="__main__")
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
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
        ):
            base_environment.pop(key, None)
        base_environment.update(
            {
                "PATH": str(empty_path),
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
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
            first_inventory = inventory(wrapper, project, environment)
            check(
                Path(first_inventory["coordinator_home"]) == expected_home,
                "same-effective-UID runtimes must ignore remapped HOME values and "
                f"converge on the POSIX account coordinator: {first_inventory}",
            )
            runtime_environments.append(environment)

        # Same-UID app instances without an explicit override must share one
        # real lock. Parallel requests that prefer one port therefore receive
        # distinct ports, and both inventories expose both agents.
        issued_ports: set[int] = set()
        preferred = fresh_port(issued_ports)
        alternate = fresh_port(issued_ports)
        low, high = sorted((preferred, alternate))
        shared_parallel = parallel_leases(
            wrapper,
            project,
            [
                (
                    runtime_environments[index],
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
        for environment in runtime_environments:
            observed = inventory(wrapper, project, environment)
            check(
                Path(observed["coordinator_home"]) == expected_home
                and {item.get("agent") for item in observed["leases"]}
                == {"default-shared-runtime-0", "default-shared-runtime-1"},
                "both remapped same-UID runtimes must observe the complete shared "
                f"lease set: {observed}",
            )
        check(
            stat.S_IMODE(expected_home.stat().st_mode) == 0o700
            and stat.S_IMODE((expected_home / "state.json").stat().st_mode) == 0o600
            and stat.S_IMODE((expected_home / "state.lock").stat().st_mode) == 0o600,
            "the account coordinator home, state, and lock must remain private",
        )

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

        state_path = expected_home / "state.json"
        state_before = state_path.read_bytes()
        original_coordinator_home = os.environ.get("CODEX_AGENT_COORDINATOR_HOME")
        original_geteuid = coordinator.os.geteuid
        os.environ["CODEX_AGENT_COORDINATOR_HOME"] = str(expected_home)
        coordinator.os.geteuid = lambda: effective_uid + 1
        try:
            coordinator.snapshot_coordinator_state()
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
