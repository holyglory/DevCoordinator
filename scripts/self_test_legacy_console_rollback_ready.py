#!/usr/bin/env python3
"""Realistic readiness/recall tests for legacy Console rollback."""

from __future__ import annotations

import copy
import hashlib
import http.server
import json
import os
import signal
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable

import verify_legacy_console_rollback_ready as rollback_ready
from verify_legacy_console_rollback_ready import (
    RollbackReadinessError,
    RollbackReadinessTimeout,
    credential_free_inventory_probe,
    wait_for_legacy_console_rollback,
)


SCRIPT = Path(__file__).with_name("verify_legacy_console_rollback_ready.py")
UNIT = "devops-console.service"
CGROUP = "/system.slice/devops-console.service"
MAIN_PID = 101
COORDINATOR_PID = 202
EXTRA_PID = 303
OLD_COORDINATOR = "/srv/legacy/skills/codex-dev-coordinator/scripts/dev_coordinator.py"
PROJECT = "/srv/legacy"
NAME = "devops-console"
PORT = 443
SERVER_ID = "legacy-console-server-id"
LEASE_ID = "legacy-console-active-lease"
CAPTURED_LEASE_ID = "legacy-console-pre-cutover-lease"
SECRET_SENTINEL = "must-never-appear-in-rollback-evidence"
MAIN_COMMAND = ["/usr/bin/node", "bin/devops-console.mjs"]
COORDINATOR_COMMAND = [
    "/usr/bin/python3",
    OLD_COORDINATOR,
    "api",
    "serve",
    "--host",
    "127.0.0.1",
    "--port",
    "29876",
]


def ready_inventory() -> dict[str, object]:
    key = f"{PROJECT}::{NAME}"
    return {
        "private_future_field": SECRET_SENTINEL,
        "port_assignments": [
            {
                "key": key,
                "project": PROJECT,
                "name": NAME,
                "port": PORT,
                "server_status": "running",
            }
        ],
        "servers": [
            {
                "id": SERVER_ID,
                "key": key,
                "project": PROJECT,
                "name": NAME,
                "cwd": f"{PROJECT}/apps/DevOpsConsole",
                "port": PORT,
                "pid": MAIN_PID,
                "status": "running",
                "lease_id": LEASE_ID,
                "health": {
                    "ok": True,
                    "pid_alive": True,
                    "classification": "healthy",
                    "check": {"ok": True, "status": 200},
                    "identity": {
                        "ok": True,
                        "pid": MAIN_PID,
                        "project": PROJECT,
                        "cwd": f"{PROJECT}/apps/DevOpsConsole",
                    },
                },
            },
            {
                "id": "unrelated-stopped-history",
                "key": "/srv/history::console",
                "project": "/srv/history",
                "name": "console",
                "cwd": "/srv/history",
                "port": PORT,
                "pid": 909,
                "status": "stopped",
                "lease_id": "unrelated-inactive-history",
                "health": {
                    "ok": False,
                    "pid_alive": False,
                    "classification": "stopped",
                },
            },
        ],
        "leases": [
            {
                "id": LEASE_ID,
                "project": PROJECT,
                "port": PORT,
                "status": "active",
                "purpose": f"server:{NAME}",
                "server_id": SERVER_ID,
                "owner_pid": MAIN_PID,
            },
            {
                "id": "unrelated-inactive-history",
                "project": "/srv/history",
                "port": PORT,
                "status": "released",
                "purpose": "server:console",
                "server_id": "unrelated-stopped-history",
                "owner_pid": 909,
            },
        ],
    }


def absent_inventory() -> dict[str, object]:
    return {
        "private_future_field": SECRET_SENTINEL,
        "port_assignments": [
            {
                "key": f"{PROJECT}::api",
                "project": PROJECT,
                "name": "api",
                "port": 8443,
                "server_status": "running",
            }
        ],
        "servers": [
            {
                "id": "unrelated-current-server",
                "key": f"{PROJECT}::api",
                "project": PROJECT,
                "name": "api",
                "cwd": f"{PROJECT}/services/api",
                "port": 8443,
                "pid": 707,
                "status": "running",
                "lease_id": "unrelated-current-lease",
            }
        ],
        "leases": [
            {
                "id": "unrelated-current-lease",
                "project": PROJECT,
                "port": 8443,
                "status": "active",
                "purpose": "server:api",
                "server_id": "unrelated-current-server",
                "owner_pid": 707,
            }
        ],
    }


def stopped_inventory() -> dict[str, object]:
    key = f"{PROJECT}::{NAME}"
    return {
        "private_future_field": SECRET_SENTINEL,
        "port_assignments": [
            {
                "key": key,
                "project": PROJECT,
                "name": NAME,
                "port": PORT,
                "server_status": "stopped",
            }
        ],
        "servers": [
            {
                "id": SERVER_ID,
                "key": key,
                "project": PROJECT,
                "name": NAME,
                "cwd": f"{PROJECT}/apps/DevOpsConsole",
                "port": PORT,
                "pid": 909,
                "status": "stopped",
                "lease_id": CAPTURED_LEASE_ID,
                "health": {
                    "ok": False,
                    "pid_alive": False,
                    "classification": "stopped",
                    "check": {
                        "ok": False,
                        "skipped": "recorded process is not alive",
                    },
                    "identity": {
                        "ok": True,
                        "skipped": "not checked because recorded process is not alive",
                    },
                },
            }
        ],
        # locked_state prunes the dead PID's active lease before
        # build_inventory normalizes the server, so server.lease_id is the
        # exact captured dangling identity and no lease row remains.
        "leases": [],
    }


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


def write_process(proc_root: Path, pid: int, start: str, command: list[str]) -> None:
    process = proc_root / str(pid)
    process.mkdir(parents=True, exist_ok=True)
    after_comm = ["S", *("0" for _ in range(18)), start]
    (process / "stat").write_text(
        f"{pid} (fixture worker) {' '.join(after_comm)}\n",
        encoding="utf-8",
    )
    (process / "cmdline").write_bytes(
        b"\0".join(item.encode("utf-8") for item in command) + b"\0"
    )


class RuntimeFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.proc_root = root / "proc"
        self.cgroup_root = root / "cgroup"
        self.members = self.cgroup_root / CGROUP.lstrip("/") / "cgroup.procs"
        self.members.parent.mkdir(parents=True)
        write_process(self.proc_root, MAIN_PID, "11001", MAIN_COMMAND)
        write_process(self.proc_root, COORDINATOR_PID, "22002", COORDINATOR_COMMAND)
        write_process(self.proc_root, EXTRA_PID, "33003", ["/usr/bin/docker", "inspect", "fixture"])
        self.set_members([MAIN_PID, COORDINATOR_PID])

    def set_members(self, pids: list[int]) -> None:
        self.members.write_text("".join(f"{pid}\n" for pid in pids), encoding="utf-8")

    def unit_state(self, *, main_pid: int = MAIN_PID, cgroup: str = CGROUP) -> dict[str, object]:
        return {"active_state": "active", "main_pid": main_pid, "cgroup": cgroup}


def listener_snapshot(
    *,
    main_pid: int = MAIN_PID,
    coordinator_pid: int = COORDINATOR_PID,
    include: tuple[int, ...] = (80, 443, 29876),
) -> str:
    owners = {80: main_pid, 443: main_pid, 29876: coordinator_pid}
    rows = []
    for port in include:
        process = "node" if port in {80, 443} else "python3"
        rows.append(
            f'LISTEN 0 511 *:{port} *:* users:(("{process}",pid={owners[port]},fd=20))'
        )
    return "\n".join(rows) + ("\n" if rows else "")


def healthy(_url: str, _timeout: float) -> dict[str, object]:
    return {
        "transport": "ok",
        "retryable": False,
        "status": 200,
        "tls_verify_result": 0,
        "remote_ip": "127.0.0.1",
    }


def call_wait(
    fixture: RuntimeFixture,
    evidence: Path,
    *,
    clock: FakeClock,
    unit_probe: Callable[[], dict[str, object]] | None = None,
    listener_probe: Callable[[tuple[int, ...]], str] | None = None,
    health_probe: Callable[[str, float], dict[str, object]] = healthy,
    inventory_probe: Callable[[str, float], dict[str, object]] | None = None,
    inventory_url: str = "http://127.0.0.1:29876/v1/inventory",
    expected_server_id: str = SERVER_ID,
    expected_lease_id: str = CAPTURED_LEASE_ID,
    timeout: float = 3.0,
    poll: float = 0.1,
) -> dict[str, object]:
    selected_unit_probe = unit_probe or fixture.unit_state
    selected_listener_probe = listener_probe or (lambda _ports: listener_snapshot())
    selected_inventory_probe = inventory_probe or (
        lambda _url, _timeout: copy.deepcopy(ready_inventory())
    )
    return wait_for_legacy_console_rollback(
        unit=UNIT,
        expected_main_pid=MAIN_PID,
        expected_cgroup=CGROUP,
        old_coordinator_script=OLD_COORDINATOR,
        health_url="https://console.example.test/healthz",
        inventory_url=inventory_url,
        expected_server_id=expected_server_id,
        expected_lease_id=expected_lease_id,
        registration_project=PROJECT,
        registration_name=NAME,
        registration_port=PORT,
        evidence_path=evidence,
        timeout_seconds=timeout,
        poll_interval_seconds=poll,
        cgroup_root=fixture.cgroup_root,
        proc_root=fixture.proc_root,
        unit_probe=lambda _timeout: selected_unit_probe(),
        listener_probe=lambda ports, _timeout: selected_listener_probe(ports),
        health_probe=health_probe,
        inventory_probe=selected_inventory_probe,
        clock=clock,
        sleep=clock.sleep,
    )


def expect_failure(
    action: Callable[[], object],
    *,
    contains: str,
    error_type: type[BaseException] = RollbackReadinessError,
) -> None:
    try:
        action()
    except error_type as error:
        require(contains in str(error), f"wrong failure for {contains!r}: {error}")
    else:
        raise AssertionError(f"missing expected failure containing {contains!r}")


def read_ledger(path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    expected_checksum = f"{hashlib.sha256(payload).hexdigest()}  {path.name}\n"
    require(Path(f"{path}.sha256").read_text(encoding="ascii") == expected_checksum, "ledger checksum mismatch")
    require((path.stat().st_mode & 0o777) == 0o600, "ledger is not mode 0600")
    require((Path(f"{path}.sha256").stat().st_mode & 0o777) == 0o600, "ledger checksum is not mode 0600")
    return json.loads(payload)


def write_executable(path: Path, payload: str) -> None:
    path.write_text(payload, encoding="utf-8")
    os.chmod(path, 0o700)


class FastThreadingServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class LoopbackInventoryServer:
    def __init__(
        self,
        *,
        body: bytes,
        status: int = 200,
        content_type: str = "application/json",
    ) -> None:
        self.requests: list[dict[str, object]] = []
        requests = self.requests

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
                requests.append(
                    {
                        "path": self.path,
                        "authorization": self.headers.get("Authorization"),
                        "cookie": self.headers.get("Cookie"),
                    }
                )
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format: str, *_args: object) -> None:
                return

        # HTTPServer.server_bind performs reverse DNS through getfqdn, which
        # can hang deterministic macOS tests. TCPServer preserves the real
        # HTTP handler semantics without that hostname lookup.
        self.server = FastThreadingServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1/inventory"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="legacy-rollback-ready-") as raw:
        root = Path(raw).resolve(strict=True)

        # A handled signal may arrive immediately after the first durable
        # running ledger becomes visible. Reproduce that exact boundary
        # deterministically: the valid running pair must be replaced by
        # checksum-valid terminal interruption evidence.
        interrupted_boundary_root = root / "interrupted-after-running-write"
        interrupted_boundary_root.mkdir(mode=0o700)
        interrupted_boundary_fixture = RuntimeFixture(interrupted_boundary_root)
        interrupted_boundary_evidence = (
            interrupted_boundary_root / "rollback-readiness.json"
        )
        original_writer = rollback_ready.LedgerWriter

        class InterruptAfterRunningWrite(original_writer):
            def __init__(self, path: Path) -> None:
                super().__init__(path)
                self.interrupted = False

            def write(self, ledger: dict[str, object]) -> None:
                super().write(ledger)
                if ledger.get("status") == "running" and not self.interrupted:
                    self.interrupted = True
                    raise rollback_ready.RollbackReadinessInterrupted(
                        "fixture interruption after durable running evidence"
                    )

        rollback_ready.LedgerWriter = InterruptAfterRunningWrite
        try:
            expect_failure(
                lambda: call_wait(
                    interrupted_boundary_fixture,
                    interrupted_boundary_evidence,
                    clock=FakeClock(),
                ),
                contains="after durable running evidence",
                error_type=rollback_ready.RollbackReadinessInterrupted,
            )
        finally:
            rollback_ready.LedgerWriter = original_writer
        require(
            read_ledger(interrupted_boundary_evidence)["status"] == "interrupted",
            "post-running-write interruption left running evidence",
        )

        # Reproduce the production timing: Type=simple is active, the child
        # coordinator appears first, a legitimate transient Docker helper
        # exits, 29876 binds, then 80/443 bind, then public TLS answers.
        delayed_root = root / "delayed"
        delayed_root.mkdir(mode=0o700)
        delayed = RuntimeFixture(delayed_root)
        delayed_clock = FakeClock()

        def delayed_unit() -> dict[str, object]:
            now = delayed_clock()
            if now < 0.2:
                delayed.set_members([MAIN_PID])
            elif now < 0.5:
                delayed.set_members([MAIN_PID, COORDINATOR_PID, EXTRA_PID])
            else:
                delayed.set_members([MAIN_PID, COORDINATOR_PID])
            return delayed.unit_state()

        def delayed_listeners(_ports: tuple[int, ...]) -> str:
            if delayed_clock() < 0.2:
                return ""
            if delayed_clock() < 0.8:
                return listener_snapshot(include=(29876,))
            return listener_snapshot()

        def delayed_health(_url: str, _timeout: float) -> dict[str, object]:
            if delayed_clock() < 1.0:
                return {
                    "transport": "unavailable",
                    "retryable": True,
                    "curl_code": 7,
                    "error": "connection refused",
                }
            return healthy(_url, _timeout)

        delayed_evidence = delayed_root / "rollback-readiness.json"
        result = call_wait(
            delayed,
            delayed_evidence,
            clock=delayed_clock,
            unit_probe=delayed_unit,
            listener_probe=delayed_listeners,
            health_probe=delayed_health,
        )
        require(result["main_pid"] == MAIN_PID, "delayed readiness returned the wrong main PID")
        delayed_ledger = read_ledger(delayed_evidence)
        classifications = [item["classification"] for item in delayed_ledger["observations"]]
        for expected in (
            "waiting_for_coordinator",
            "transient_extra_cgroup_members",
            "waiting_for_listeners",
            "waiting_for_tls_transport",
            "ready",
        ):
            require(expected in classifications, f"delayed fixture never recorded {expected}")
        require(delayed_clock() >= 1.0, "delayed fixture passed before TLS readiness")

        # Reproduce the real 40a rollback boundary: locked_state has pruned the
        # old active lease, build_inventory preserves the captured stopped
        # server with its dangling captured lease ID, and registration later
        # restores the same server ID with a replacement active lease.
        registration_root = root / "delayed-registration"
        registration_root.mkdir(mode=0o700)
        registration_fixture = RuntimeFixture(registration_root)
        registration_clock = FakeClock()
        registration_snapshots = [
            stopped_inventory(),
            ready_inventory(),
        ]
        registration_calls = [0]

        def delayed_registration(
            _url: str, _timeout: float
        ) -> dict[str, object]:
            index = min(registration_calls[0], len(registration_snapshots) - 1)
            registration_calls[0] += 1
            return copy.deepcopy(registration_snapshots[index])

        registration_evidence = registration_root / "rollback-readiness.json"
        registration_result = call_wait(
            registration_fixture,
            registration_evidence,
            clock=registration_clock,
            inventory_probe=delayed_registration,
        )
        require(
            registration_result["registration"]["server_id"] == SERVER_ID,
            "registration readiness lost the captured server identity",
        )
        registration_ledger = read_ledger(registration_evidence)
        registration_classifications = [
            item["classification"] for item in registration_ledger["observations"]
        ]
        require(
            "waiting_for_registration_stopped-baseline" in registration_classifications,
            "exact stopped registration was not retried",
        )
        stopped_observation = next(
            item
            for item in registration_ledger["observations"]
            if item["classification"] == "waiting_for_registration_stopped-baseline"
        )
        require(
            stopped_observation["registration"]["captured_lease_id"]
            == CAPTURED_LEASE_ID
            and stopped_observation["registration"]["dangling_captured_lease"]
            is True,
            "production-shaped stopped graph lost its dangling captured lease identity",
        )
        require(registration_classifications[-1] == "ready", "registration never converged")
        require(registration_calls[0] == 2, "rollback passed before the ready graph")
        require(registration_clock() >= 0.1, "registration convergence incurred no polling")
        require(
            SECRET_SENTINEL not in registration_evidence.read_text(encoding="utf-8"),
            "raw inventory content leaked into rollback evidence",
        )

        registration_timeout_root = root / "registration-timeout"
        registration_timeout_root.mkdir(mode=0o700)
        registration_timeout_fixture = RuntimeFixture(registration_timeout_root)
        registration_timeout_clock = FakeClock()
        expect_failure(
            lambda: call_wait(
                registration_timeout_fixture,
                registration_timeout_root / "rollback-readiness.json",
                clock=registration_timeout_clock,
                inventory_probe=lambda _url, _timeout: stopped_inventory(),
                timeout=0.3,
            ),
            contains="did not become ready",
            error_type=RollbackReadinessTimeout,
        )
        timeout_ledger = read_ledger(
            registration_timeout_root / "rollback-readiness.json"
        )
        require(timeout_ledger["status"] == "timeout", "stopped registration did not time out")
        require(
            timeout_ledger["observations"][-1]["classification"]
            == "waiting_for_registration_stopped-baseline",
            "stopped registration timeout lost its last safe pending state",
        )

        identity_loss_inventories = {
            "clean-absence": absent_inventory(),
            "assignment-only-unregistered": {
                "port_assignments": [
                    {
                        "key": f"{PROJECT}::{NAME}",
                        "project": PROJECT,
                        "name": NAME,
                        "port": PORT,
                        "server_status": "unregistered",
                    }
                ],
                "servers": [],
                "leases": [],
            },
        }
        for label, identity_loss in identity_loss_inventories.items():
            case_root = root / f"identity-loss-{label}"
            case_root.mkdir(mode=0o700)
            case_fixture = RuntimeFixture(case_root)
            case_clock = FakeClock()
            evidence = case_root / "rollback-readiness.json"
            expect_failure(
                lambda identity_loss=identity_loss: call_wait(
                    case_fixture,
                    evidence,
                    clock=case_clock,
                    inventory_probe=lambda _url, _timeout: copy.deepcopy(
                        identity_loss
                    ),
                ),
                contains="captured server identity",
            )
            require(case_clock() == 0.0, f"{label} identity loss was retried")
            require(
                read_ledger(evidence)["status"] == "failed",
                f"{label} identity loss was not terminal",
            )

        stopped_precursor_failures: list[
            tuple[str, Callable[[dict[str, object]], None]]
        ] = [
            (
                "wrong-captured-lease-id",
                lambda value: value["servers"][0].update(
                    {"lease_id": "different-captured-lease"}
                ),
            ),
            (
                "unpruned-active-lease",
                lambda value: value["leases"].append(
                    {
                        "id": CAPTURED_LEASE_ID,
                        "project": PROJECT,
                        "port": PORT,
                        "status": "active",
                        "purpose": f"server:{NAME}",
                        "server_id": SERVER_ID,
                        "owner_pid": 909,
                    }
                ),
            ),
            (
                "rollback-main-pid-still-stopped",
                lambda value: value["servers"][0].update({"pid": MAIN_PID}),
            ),
            (
                "health-ok",
                lambda value: value["servers"][0]["health"].update({"ok": True}),
            ),
            (
                "health-classification",
                lambda value: value["servers"][0]["health"].update(
                    {"classification": "unhealthy_process"}
                ),
            ),
            (
                "health-check",
                lambda value: value["servers"][0]["health"]["check"].update(
                    {"skipped": "different reason"}
                ),
            ),
            (
                "health-identity",
                lambda value: value["servers"][0]["health"]["identity"].update(
                    {"ok": False}
                ),
            ),
        ]
        for label, mutate in stopped_precursor_failures:
            case_root = root / f"stopped-precursor-{label}"
            case_root.mkdir(mode=0o700)
            case_fixture = RuntimeFixture(case_root)
            case_clock = FakeClock()
            broken = copy.deepcopy(stopped_inventory())
            mutate(broken)
            evidence = case_root / "rollback-readiness.json"
            expect_failure(
                lambda broken=broken: call_wait(
                    case_fixture,
                    evidence,
                    clock=case_clock,
                    inventory_probe=lambda _url, _timeout: copy.deepcopy(broken),
                ),
                contains="unsafe legacy registration graph",
            )
            require(case_clock() == 0.0, f"{label} was retried")
            require(
                read_ledger(evidence)["status"] == "failed",
                f"{label} did not fail terminally",
            )

        wrong_lease_identity_root = root / "wrong-expected-lease-identity"
        wrong_lease_identity_root.mkdir(mode=0o700)
        wrong_lease_identity_fixture = RuntimeFixture(wrong_lease_identity_root)
        wrong_lease_identity_clock = FakeClock()
        expect_failure(
            lambda: call_wait(
                wrong_lease_identity_fixture,
                wrong_lease_identity_root / "rollback-readiness.json",
                clock=wrong_lease_identity_clock,
                inventory_probe=lambda _url, _timeout: stopped_inventory(),
                expected_lease_id="different-pre-cutover-lease",
            ),
            contains="captured lease identity",
        )
        require(
            wrong_lease_identity_clock() == 0.0,
            "wrong captured lease identity was retried",
        )

        # Every current or foreign claim is an atomic conflict. None may be
        # retried as startup convergence after TLS/listener readiness.
        graph_failures: list[tuple[str, Callable[[dict[str, object]], None]]] = [
            (
                "wrong-server-id",
                lambda value: value["servers"][0].update({"id": "wrong-server-id"}),
            ),
            (
                "wrong-main-pid",
                lambda value: value["servers"][0].update({"pid": 999}),
            ),
            (
                "wrong-health-identity",
                lambda value: value["servers"][0]["health"]["identity"].update(
                    {"pid": 999}
                ),
            ),
            (
                "wrong-lease-link",
                lambda value: value["servers"][0].update({"lease_id": "detached-lease"}),
            ),
            (
                "wrong-lease-owner",
                lambda value: value["leases"][0].update({"owner_pid": 999}),
            ),
            (
                "reused-captured-lease",
                lambda value: (
                    value["servers"][0].update(
                        {"lease_id": CAPTURED_LEASE_ID}
                    ),
                    value["leases"][0].update({"id": CAPTURED_LEASE_ID}),
                ),
            ),
            (
                "retained-captured-lease-history",
                lambda value: value["leases"].append(
                    {
                        "id": CAPTURED_LEASE_ID,
                        "project": PROJECT,
                        "port": PORT,
                        "status": "released",
                        "purpose": f"server:{NAME}",
                        "server_id": SERVER_ID,
                        "owner_pid": 909,
                    }
                ),
            ),
            (
                "wrong-assignment",
                lambda value: value["port_assignments"][0].update(
                    {"key": "/srv/foreign::devops-console"}
                ),
            ),
            (
                "foreign-current-server",
                lambda value: value["servers"][0].update(
                    {
                        "key": "/srv/foreign::console",
                        "project": "/srv/foreign",
                        "name": "console",
                        "cwd": "/srv/foreign",
                    }
                ),
            ),
        ]
        for label, mutate in graph_failures:
            case_root = root / f"registration-{label}"
            case_root.mkdir(mode=0o700)
            case_fixture = RuntimeFixture(case_root)
            case_clock = FakeClock()
            broken = copy.deepcopy(ready_inventory())
            mutate(broken)
            evidence = case_root / "rollback-readiness.json"
            expect_failure(
                lambda broken=broken: call_wait(
                    case_fixture,
                    evidence,
                    clock=case_clock,
                    inventory_probe=lambda _url, _timeout: copy.deepcopy(broken),
                ),
                contains="unsafe legacy registration graph",
            )
            require(case_clock() == 0.0, f"{label} was retried")
            require(read_ledger(evidence)["status"] == "failed", f"{label} was not terminal")

        wrong_expected_root = root / "registration-wrong-captured-id"
        wrong_expected_root.mkdir(mode=0o700)
        wrong_expected_fixture = RuntimeFixture(wrong_expected_root)
        wrong_expected_clock = FakeClock()
        expect_failure(
            lambda: call_wait(
                wrong_expected_fixture,
                wrong_expected_root / "rollback-readiness.json",
                clock=wrong_expected_clock,
                expected_server_id="different-captured-server-id",
            ),
            contains="unsafe legacy registration graph",
        )
        require(wrong_expected_clock() == 0.0, "wrong captured server id was retried")

        # An accepting coordinator listener must not hide permanently missing
        # public listeners—the exact false-negative surface from production.
        missing_root = root / "missing-port"
        missing_root.mkdir(mode=0o700)
        missing = RuntimeFixture(missing_root)
        missing_clock = FakeClock()
        missing_evidence = missing_root / "rollback-readiness.json"
        expect_failure(
            lambda: call_wait(
                missing,
                missing_evidence,
                clock=missing_clock,
                listener_probe=lambda _ports: listener_snapshot(include=(29876,)),
                timeout=0.3,
            ),
            contains="did not become ready",
            error_type=RollbackReadinessTimeout,
        )
        missing_ledger = read_ledger(missing_evidence)
        require(missing_ledger["status"] == "timeout", "missing listener did not persist timeout evidence")

        slow_root = root / "slow-probe"
        slow_root.mkdir(mode=0o700)
        slow = RuntimeFixture(slow_root)
        slow_clock = FakeClock()

        def slow_unit_probe() -> dict[str, object]:
            slow_clock.sleep(0.5)
            return slow.unit_state()

        expect_failure(
            lambda: call_wait(
                slow,
                slow_root / "rollback-readiness.json",
                clock=slow_clock,
                unit_probe=slow_unit_probe,
                timeout=0.3,
            ),
            contains="did not become ready",
            error_type=RollbackReadinessTimeout,
        )
        require(read_ledger(slow_root / "rollback-readiness.json")["status"] == "timeout", "slow probe passed after deadline")

        false_coordinator_root = root / "false-coordinator"
        false_coordinator_root.mkdir(mode=0o700)
        false_coordinator = RuntimeFixture(false_coordinator_root)
        write_process(
            false_coordinator.proc_root,
            COORDINATOR_PID,
            "22002",
            [
                "/tmp/not-python",
                "--claim",
                OLD_COORDINATOR,
                "api",
                "serve",
                "--port",
                "9999",
            ],
        )
        false_coordinator_clock = FakeClock()
        expect_failure(
            lambda: call_wait(
                false_coordinator,
                false_coordinator_root / "rollback-readiness.json",
                clock=false_coordinator_clock,
                timeout=0.3,
            ),
            contains="not the exact legacy coordinator",
        )
        require(false_coordinator_clock() == 0.0, "wrong 29876 owner was retried")

        pre_coordinator_owner_root = root / "wrong-public-owner-before-coordinator"
        pre_coordinator_owner_root.mkdir(mode=0o700)
        pre_coordinator_owner = RuntimeFixture(pre_coordinator_owner_root)
        pre_coordinator_owner.set_members([MAIN_PID])
        pre_coordinator_clock = FakeClock()
        expect_failure(
            lambda: call_wait(
                pre_coordinator_owner,
                pre_coordinator_owner_root / "rollback-readiness.json",
                clock=pre_coordinator_clock,
                listener_probe=lambda _ports: listener_snapshot(
                    main_pid=999,
                    include=(80,),
                ),
            ),
            contains="listener ownership on port 80",
        )
        require(pre_coordinator_clock() == 0.0, "wrong public owner waited for a coordinator")

        concurrent_root = root / "concurrent-coordinator-arrival"
        concurrent_root.mkdir(mode=0o700)
        concurrent = RuntimeFixture(concurrent_root)
        concurrent_clock = FakeClock()
        concurrent_unit_calls = [0]
        concurrent_listener_calls = [0]

        def concurrent_unit() -> dict[str, object]:
            concurrent_unit_calls[0] += 1
            if concurrent_unit_calls[0] == 1:
                concurrent.set_members([MAIN_PID])
            return concurrent.unit_state()

        def concurrent_listener(_ports: tuple[int, ...]) -> str:
            concurrent_listener_calls[0] += 1
            if concurrent_listener_calls[0] == 1:
                concurrent.set_members([MAIN_PID, COORDINATOR_PID])
                return listener_snapshot(include=(29876,))
            return listener_snapshot()

        call_wait(
            concurrent,
            concurrent_root / "rollback-readiness.json",
            clock=concurrent_clock,
            unit_probe=concurrent_unit,
            listener_probe=concurrent_listener,
        )
        concurrent_ledger = read_ledger(concurrent_root / "rollback-readiness.json")
        require(
            concurrent_ledger["observations"][0]["classification"]
            == "coordinator_appeared_during_listener_probe",
            "legitimate coordinator arrival between cgroup and ss was rejected",
        )

        # Listener ownership is a hard boundary: wrong, ambiguous, and
        # privileged-but-unparseable observations all fail immediately.
        unsafe_snapshots = {
            "wrong": listener_snapshot(main_pid=999),
            "ambiguous": listener_snapshot().replace(
                'pid=101,fd=20))', 'pid=101,fd=20),("foreign",pid=999,fd=21))', 1
            ),
            "unparseable": listener_snapshot().replace(
                'users:(("node",pid=101,fd=20))', ""
            ),
        }
        for name, snapshot in unsafe_snapshots.items():
            unsafe_root = root / f"unsafe-{name}"
            unsafe_root.mkdir(mode=0o700)
            unsafe = RuntimeFixture(unsafe_root)
            unsafe_clock = FakeClock()
            evidence = unsafe_root / "rollback-readiness.json"
            expect_failure(
                lambda snapshot=snapshot: call_wait(
                    unsafe,
                    evidence,
                    clock=unsafe_clock,
                    listener_probe=lambda _ports: snapshot,
                ),
                contains="listener ownership",
            )
            require(unsafe_clock() == 0.0, f"{name} ownership was retried instead of failing immediately")
            require(read_ledger(evidence)["status"] == "failed", f"{name} failure evidence was not terminal")

        # Fixed systemd and process identities cannot drift while readiness is
        # pending. Each case changes exactly one advertised identity class.
        identity_cases: list[tuple[str, Callable[[RuntimeFixture], Callable[[], dict[str, object]]], str]] = [
            (
                "main-pid",
                lambda fixture: lambda: fixture.unit_state(main_pid=404),
                "MainPID changed",
            ),
            (
                "cgroup",
                lambda fixture: lambda: fixture.unit_state(cgroup="/system.slice/replaced.service"),
                "cgroup changed",
            ),
            (
                "start-ticks",
                lambda fixture: lambda: (
                    write_process(fixture.proc_root, MAIN_PID, "99999", MAIN_COMMAND),
                    fixture.unit_state(),
                )[1],
                "identity changed",
            ),
            (
                "argv",
                lambda fixture: lambda: (
                    write_process(fixture.proc_root, MAIN_PID, "11001", ["/usr/bin/node", "other.mjs"]),
                    fixture.unit_state(),
                )[1],
                "identity changed",
            ),
        ]
        for name, make_probe, message in identity_cases:
            case_root = root / f"identity-{name}"
            case_root.mkdir(mode=0o700)
            fixture = RuntimeFixture(case_root)
            case_clock = FakeClock()
            evidence = case_root / "rollback-readiness.json"
            expect_failure(
                lambda: call_wait(
                    fixture,
                    evidence,
                    clock=case_clock,
                    unit_probe=make_probe(fixture),
                ),
                contains=message,
            )
            require(case_clock() == 0.0, f"{name} identity change was retried")

        wrong_main_root = root / "wrong-main-command"
        wrong_main_root.mkdir(mode=0o700)
        wrong_main = RuntimeFixture(wrong_main_root)
        write_process(wrong_main.proc_root, MAIN_PID, "11001", ["/usr/bin/python3", "pretender.py"])
        wrong_main_clock = FakeClock()
        expect_failure(
            lambda: call_wait(
                wrong_main,
                wrong_main_root / "rollback-readiness.json",
                clock=wrong_main_clock,
            ),
            contains="not the legacy Node DevOps Console",
        )

        tls_root = root / "tls-invalid"
        tls_root.mkdir(mode=0o700)
        tls_fixture = RuntimeFixture(tls_root)
        tls_clock = FakeClock()
        expect_failure(
            lambda: call_wait(
                tls_fixture,
                tls_root / "rollback-readiness.json",
                clock=tls_clock,
                health_probe=lambda _url, _timeout: {
                    "transport": "ok",
                    "retryable": False,
                    "status": 200,
                    "tls_verify_result": 60,
                    "remote_ip": "127.0.0.1",
                },
            ),
            contains="certificate verification failed",
        )
        require(tls_clock() == 0.0, "invalid certificate was treated as startup transport delay")

        http_root = root / "http-wrong"
        http_root.mkdir(mode=0o700)
        http_fixture = RuntimeFixture(http_root)
        http_clock = FakeClock()
        expect_failure(
            lambda: call_wait(
                http_fixture,
                http_root / "rollback-readiness.json",
                clock=http_clock,
                health_probe=lambda _url, _timeout: {
                    "transport": "ok",
                    "retryable": False,
                    "status": 302,
                    "tls_verify_result": 0,
                    "remote_ip": "127.0.0.1",
                },
            ),
            contains="HTTP 302",
        )
        require(http_clock() == 0.0, "semantic HTTP failure was treated as startup delay")

        remote_root = root / "wrong-health-remote"
        remote_root.mkdir(mode=0o700)
        remote_fixture = RuntimeFixture(remote_root)
        remote_clock = FakeClock()
        expect_failure(
            lambda: call_wait(
                remote_fixture,
                remote_root / "rollback-readiness.json",
                clock=remote_clock,
                health_probe=lambda _url, _timeout: {
                    "transport": "ok",
                    "retryable": False,
                    "status": 200,
                    "tls_verify_result": 0,
                    "remote_ip": "203.0.113.10",
                },
            ),
            contains="expected local 127.0.0.1",
        )

        # A healthy response is not the terminal boundary by itself. Recheck
        # the same systemd/process identities afterward and bind the final
        # listener evidence between two exact topology confirmations.
        post_health_root = root / "post-health-identity-change"
        post_health_root.mkdir(mode=0o700)
        post_health_fixture = RuntimeFixture(post_health_root)
        post_health_clock = FakeClock()

        def identity_changing_health(url: str, timeout: float) -> dict[str, object]:
            write_process(post_health_fixture.proc_root, MAIN_PID, "99999", MAIN_COMMAND)
            return healthy(url, timeout)

        expect_failure(
            lambda: call_wait(
                post_health_fixture,
                post_health_root / "rollback-readiness.json",
                clock=post_health_clock,
                health_probe=identity_changing_health,
            ),
            contains="identity changed",
        )
        require(post_health_clock() == 0.0, "post-health identity change was retried")
        post_health_ledger = read_ledger(post_health_root / "rollback-readiness.json")
        post_health_records = post_health_ledger["observations"][-1]["post_health_topology"]["processes"]
        require(
            any(item.get("pid") == MAIN_PID and item.get("start_ticks") == "99999" for item in post_health_records),
            "terminal evidence omitted the post-health identity mutation",
        )

        final_owner_root = root / "final-listener-owner-change"
        final_owner_root.mkdir(mode=0o700)
        final_owner_fixture = RuntimeFixture(final_owner_root)
        final_owner_clock = FakeClock()
        listener_calls = [0]

        def owner_changing_listener(_ports: tuple[int, ...]) -> str:
            listener_calls[0] += 1
            return listener_snapshot() if listener_calls[0] < 3 else listener_snapshot(main_pid=999)

        expect_failure(
            lambda: call_wait(
                final_owner_fixture,
                final_owner_root / "rollback-readiness.json",
                clock=final_owner_clock,
                listener_probe=owner_changing_listener,
            ),
            contains="listener ownership",
        )
        require(listener_calls[0] == 3, "final listener ownership was not re-observed after health")
        require(final_owner_clock() == 0.0, "post-health wrong listener owner was retried")
        final_owner_ledger = read_ledger(final_owner_root / "rollback-readiness.json")
        require(
            any("pid=999" in line for line in final_owner_ledger["observations"][-1]["final_listener_snapshot"]),
            "terminal evidence omitted the post-health listener-owner swap",
        )

        # Inventory may take long enough for port ownership to change while
        # the same PIDs remain in the same cgroup. The final evidence must come
        # from a fresh listener probe made after the graph response.
        post_inventory_snapshots = {
            "wrong": listener_snapshot(main_pid=999),
            "ambiguous": listener_snapshot().replace(
                'pid=101,fd=20))',
                'pid=101,fd=20),("foreign",pid=999,fd=21))',
                1,
            ),
        }
        for label, changed_snapshot in post_inventory_snapshots.items():
            case_root = root / f"post-inventory-listener-{label}"
            case_root.mkdir(mode=0o700)
            case_fixture = RuntimeFixture(case_root)
            case_clock = FakeClock()
            inventory_returned = [False]
            listener_calls_after_graph = [0]

            def mark_inventory_returned(
                _url: str, _timeout: float
            ) -> dict[str, object]:
                inventory_returned[0] = True
                return copy.deepcopy(ready_inventory())

            def change_after_inventory(_ports: tuple[int, ...]) -> str:
                listener_calls_after_graph[0] += 1
                return changed_snapshot if inventory_returned[0] else listener_snapshot()

            evidence = case_root / "rollback-readiness.json"
            expect_failure(
                lambda: call_wait(
                    case_fixture,
                    evidence,
                    clock=case_clock,
                    listener_probe=change_after_inventory,
                    inventory_probe=mark_inventory_returned,
                ),
                contains="listener ownership",
            )
            require(inventory_returned[0], f"{label} fixture changed before inventory")
            require(
                listener_calls_after_graph[0] == 4,
                f"{label} fixture did not reach the post-registration listener probe",
            )
            require(case_clock() == 0.0, f"post-inventory {label} owner was retried")
            post_inventory_ledger = read_ledger(evidence)
            require(
                any(
                    "pid=999" in line
                    for line in post_inventory_ledger["observations"][-1][
                        "post_registration_listener_snapshot"
                    ]
                ),
                f"post-inventory {label} evidence omitted the changed owner",
            )

        terminal_extra_root = root / "post-health-transient-extra"
        terminal_extra_root.mkdir(mode=0o700)
        terminal_extra_fixture = RuntimeFixture(terminal_extra_root)
        terminal_extra_clock = FakeClock()
        health_calls = [0]

        def clear_terminal_extra() -> dict[str, object]:
            if terminal_extra_clock() > 0:
                terminal_extra_fixture.set_members([MAIN_PID, COORDINATOR_PID])
            return terminal_extra_fixture.unit_state()

        def add_one_terminal_extra(url: str, timeout: float) -> dict[str, object]:
            health_calls[0] += 1
            if health_calls[0] == 1:
                terminal_extra_fixture.set_members([MAIN_PID, COORDINATOR_PID, EXTRA_PID])
            return healthy(url, timeout)

        call_wait(
            terminal_extra_fixture,
            terminal_extra_root / "rollback-readiness.json",
            clock=terminal_extra_clock,
            unit_probe=clear_terminal_extra,
            health_probe=add_one_terminal_extra,
        )
        terminal_extra_ledger = read_ledger(terminal_extra_root / "rollback-readiness.json")
        terminal_classifications = [
            item["classification"] for item in terminal_extra_ledger["observations"]
        ]
        require(
            "post_health_transient_cgroup_members" in terminal_classifications,
            "post-health transient child was not retried",
        )
        require(terminal_classifications[-1] == "ready", "terminal transient child never converged")

        ready_root = root / "already-ready"
        ready_root.mkdir(mode=0o700)
        ready_fixture = RuntimeFixture(ready_root)
        ready_clock = FakeClock()
        call_wait(
            ready_fixture,
            ready_root / "rollback-readiness.json",
            clock=ready_clock,
        )
        require(ready_clock() == 0.0, "already-ready control incurred a fixed sleep")

        invalid_number_root = root / "invalid-number"
        invalid_number_root.mkdir(mode=0o700)
        invalid_number_fixture = RuntimeFixture(invalid_number_root)
        invalid_clock = FakeClock()
        expect_failure(
            lambda: call_wait(
                invalid_number_fixture,
                invalid_number_root / "nan-timeout.json",
                clock=invalid_clock,
                timeout=float("nan"),
            ),
            contains="timeout must be",
        )
        expect_failure(
            lambda: call_wait(
                invalid_number_fixture,
                invalid_number_root / "nan-poll.json",
                clock=invalid_clock,
                poll=float("nan"),
            ),
            contains="poll interval must be",
        )
        require(
            not (invalid_number_root / "nan-timeout.json").exists()
            and not (invalid_number_root / "nan-poll.json").exists(),
            "invalid numeric input created success-shaped evidence",
        )

        valid_http = LoopbackInventoryServer(
            body=json.dumps(ready_inventory()).encode("utf-8")
        )
        try:
            fetched = credential_free_inventory_probe(valid_http.url, 2.0)
            require(
                fetched["private_future_field"] == SECRET_SENTINEL,
                "real HTTP inventory body was not decoded",
            )
            require(len(valid_http.requests) == 1, "inventory endpoint was queried unexpectedly")
            require(
                valid_http.requests[0]
                == {
                    "path": "/v1/inventory",
                    "authorization": None,
                    "cookie": None,
                },
                "credential-free legacy request sent credentials or used the wrong path",
            )
        finally:
            valid_http.close()

        for label, status, content_type, body, message in (
            ("http", 503, "application/json", b"{}", "HTTP 503"),
            ("content-type", 200, "text/plain", b"{}", "Content-Type"),
            ("json", 200, "application/json", b"{broken", "JSON is invalid"),
            ("root", 200, "application/json", b"[]", "root must be an object"),
        ):
            bad_server = LoopbackInventoryServer(
                body=body,
                status=status,
                content_type=content_type,
            )
            try:
                expect_failure(
                    lambda bad_server=bad_server: credential_free_inventory_probe(
                        bad_server.url, 2.0
                    ),
                    contains=message,
                )
            finally:
                bad_server.close()

        for unsafe_url in (
            "https://127.0.0.1:29876/v1/inventory",
            "http://user@127.0.0.1:29876/v1/inventory",
            "http://localhost:29876/v1/inventory",
            "http://127.0.0.1:29876/v1/inventory?token=secret",
            "http://127.0.0.1:29876/v1/inventory/no-docker",
        ):
            expect_failure(
                lambda unsafe_url=unsafe_url: credential_free_inventory_probe(
                    unsafe_url, 2.0
                ),
                contains="credential-free IPv4 loopback",
            )

        # Exercise the exact subprocess CLI with isolated fake systemd, sudo,
        # ss, and curl executables; no host PATH or listener can affect it.
        cli_root = root / "cli"
        cli_root.mkdir(mode=0o700)
        cli_inventory_server = LoopbackInventoryServer(
            body=json.dumps(ready_inventory()).encode("utf-8")
        )
        cli_fixture = RuntimeFixture(cli_root)
        write_process(
            cli_fixture.proc_root,
            COORDINATOR_PID,
            "22002",
            [
                "/usr/bin/python3",
                OLD_COORDINATOR,
                "api",
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                str(cli_inventory_server.port),
            ],
        )
        bin_root = cli_root / "bin"
        bin_root.mkdir(mode=0o700)
        systemctl = bin_root / "systemctl"
        sudo = bin_root / "sudo"
        ss = bin_root / "ss"
        curl = bin_root / "curl"
        write_executable(
            systemctl,
            "#!/bin/sh\nprintf '%s\\n' 'ActiveState=active' 'MainPID=101' "
            "'ControlGroup=/system.slice/devops-console.service'\n",
        )
        write_executable(sudo, "#!/bin/sh\ntest \"$1\" = -n\nshift\nexec \"$@\"\n")
        write_executable(
            ss,
            "#!/bin/sh\nprintf '%s\\n' "
            "'LISTEN 0 511 *:80 *:* users:((\"node\",pid=101,fd=20))' "
            "'LISTEN 0 511 *:443 *:* users:((\"node\",pid=101,fd=21))' "
            f"'LISTEN 0 511 127.0.0.1:{cli_inventory_server.port} 0.0.0.0:* "
            "users:((\"python3\",pid=202,fd=3))'\n",
        )
        write_executable(
            curl,
            "#!/bin/sh\n"
            "test \"$1\" = '--disable' || exit 90\n"
            "seen_noproxy=0\nseen_resolve=0\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "  case \"$1\" in\n"
            "    --noproxy) shift; test \"$1\" = '*' || exit 91; seen_noproxy=1 ;;\n"
            "    --resolve) shift; test \"$1\" = 'console.example.test:443:127.0.0.1' || exit 92; seen_resolve=1 ;;\n"
            "  esac\n"
            "  shift\n"
            "done\n"
            "test \"$seen_noproxy\" -eq 1 || exit 93\n"
            "test \"$seen_resolve\" -eq 1 || exit 94\n"
            "if [ ! -e \"$0.state\" ]; then : > \"$0.state\"; exit 7; fi\n"
            "printf 'status=200 tls=0 remote=127.0.0.1\\n'\n",
        )
        expected_identities = cli_root / "pre-cutover-identities.json"
        expected_identities.write_text(
            json.dumps(
                {"server_id": SERVER_ID, "lease_id": CAPTURED_LEASE_ID}
            )
            + "\n",
            encoding="utf-8",
        )
        os.chmod(expected_identities, 0o600)

        def cli_arguments(
            evidence: Path,
            *,
            systemctl_path: Path = systemctl,
            curl_path: Path = curl,
            timeout: str = "5",
            poll: str = "0.01",
            optimized: bool = False,
        ) -> list[str]:
            prefix = [sys.executable, "-O", str(SCRIPT)] if optimized else [sys.executable, str(SCRIPT)]
            return [
                *prefix,
                "--unit",
                UNIT,
                "--main-pid",
                str(MAIN_PID),
                "--cgroup",
                CGROUP,
                "--old-coordinator-script",
                OLD_COORDINATOR,
                "--health-url",
                "https://console.example.test/healthz",
                "--inventory-url",
                cli_inventory_server.url,
                "--expected-identities",
                str(expected_identities),
                "--project",
                PROJECT,
                "--name",
                NAME,
                "--port",
                str(PORT),
                "--evidence",
                str(evidence),
                "--timeout-seconds",
                timeout,
                "--poll-interval-seconds",
                poll,
                "--cgroup-root",
                str(cli_fixture.cgroup_root),
                "--proc-root",
                str(cli_fixture.proc_root),
                "--systemctl",
                str(systemctl_path),
                "--sudo",
                str(sudo),
                "--ss",
                str(ss),
                "--curl",
                str(curl_path),
            ]

        isolated_env = {"PATH": "/nonexistent", "PYTHONHASHSEED": "0"}
        for optimized in (False, True):
            suffix = "optimized" if optimized else "normal"
            cli_evidence = cli_root / f"rollback-readiness-{suffix}.json"
            completed = subprocess.run(
                cli_arguments(cli_evidence, optimized=optimized),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=isolated_env,
                timeout=10,
            )
            require(
                completed.returncode == 0,
                f"rollback readiness CLI ({suffix}) failed: {completed.stderr}",
            )
            require(
                json.loads(completed.stdout)["ok"] is True,
                f"rollback readiness CLI ({suffix}) output was not successful",
            )
            cli_ledger = read_ledger(cli_evidence)
            require(
                cli_ledger["status"] == "success",
                f"CLI ({suffix}) evidence was not terminal success",
            )
            if not optimized:
                require(
                    any(
                        item.get("classification") == "waiting_for_tls_transport"
                        for item in cli_ledger["observations"]
                    ),
                    "real curl exit 7 was not retried before CLI success",
                )
            require(
                SECRET_SENTINEL not in cli_evidence.read_text(encoding="utf-8"),
                f"CLI ({suffix}) persisted raw inventory content",
            )

        bad_tls_curl = bin_root / "curl-bad-tls"
        write_executable(bad_tls_curl, "#!/bin/sh\nexit 60\n")
        bad_tls_evidence = cli_root / "bad-tls-readiness.json"
        bad_tls = subprocess.run(
            cli_arguments(bad_tls_evidence, curl_path=bad_tls_curl),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=isolated_env,
            timeout=10,
        )
        require(bad_tls.returncode == 1, "real curl certificate failure was accepted")
        require(read_ledger(bad_tls_evidence)["status"] == "failed", "TLS failure was not terminal evidence")

        unavailable_curl = bin_root / "curl-unavailable"
        write_executable(unavailable_curl, "#!/bin/sh\nexit 7\n")
        unavailable_evidence = cli_root / "unavailable-readiness.json"
        unavailable = subprocess.run(
            cli_arguments(unavailable_evidence, curl_path=unavailable_curl, timeout="0.2"),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=isolated_env,
            timeout=5,
        )
        require(unavailable.returncode == 1, "permanent curl transport failure was accepted")
        require(read_ledger(unavailable_evidence)["status"] == "timeout", "transport timeout was not terminal evidence")

        for option in ("--timeout-seconds", "--poll-interval-seconds"):
            invalid_cli_evidence = cli_root / f"invalid-{option.removeprefix('--')}.json"
            invalid_arguments = cli_arguments(invalid_cli_evidence)
            invalid_arguments[invalid_arguments.index(option) + 1] = "nan"
            invalid_cli = subprocess.run(
                invalid_arguments,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=isolated_env,
                timeout=5,
            )
            require(invalid_cli.returncode == 1, f"CLI accepted NaN for {option}")
            require(not invalid_cli_evidence.exists(), f"NaN {option} created evidence")

        blocking_systemctl = bin_root / "systemctl-blocking"
        write_executable(blocking_systemctl, "#!/bin/sh\nexec /bin/sleep 30\n")
        interrupted_evidence = cli_root / "interrupted-readiness.json"
        interrupted = subprocess.Popen(
            cli_arguments(interrupted_evidence, systemctl_path=blocking_systemctl, timeout="30"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=isolated_env,
        )
        interrupted_stdout = ""
        interrupted_stderr = ""
        try:
            ready_deadline = time.monotonic() + 5
            running_seen = False
            while time.monotonic() < ready_deadline:
                if interrupted.poll() is not None:
                    break
                if interrupted_evidence.exists() and Path(f"{interrupted_evidence}.sha256").exists():
                    try:
                        if read_ledger(interrupted_evidence).get("status") == "running":
                            running_seen = True
                            break
                    except (OSError, ValueError, AssertionError):
                        pass
                time.sleep(0.01)
            require(running_seen, "signal fixture never published a checksum-valid running ledger")
            interrupted.send_signal(signal.SIGTERM)
            interrupted_stdout, interrupted_stderr = interrupted.communicate(timeout=5)
        finally:
            if interrupted.poll() is None:
                interrupted.kill()
                interrupted_stdout, interrupted_stderr = interrupted.communicate(timeout=5)
        require(interrupted.returncode == 1, "SIGTERM did not produce a handled CLI failure")
        require(interrupted_stdout == "", "interrupted CLI emitted success output")
        require("SIGTERM" in interrupted_stderr, "interrupted CLI omitted its signal")
        require(read_ledger(interrupted_evidence)["status"] == "interrupted", "SIGTERM left running evidence")
        cli_inventory_server.close()

    print(
        "legacy rollback readiness self-test ok "
        "(delayed startup/registration, exact owners/graph, HTTP/JSON, timeout, CLI normal/-O)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
