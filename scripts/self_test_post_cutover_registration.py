#!/usr/bin/env python3
"""Recall and false-positive tests for the post-cutover registration guard."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable


SCRIPT = Path(__file__).with_name("verify_post_cutover_registration.py")
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("verify_post_cutover_registration", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import post-cutover registration verifier")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

PROJECT = "/home/DevCoordinator"
OLD_PROJECT = "/srv/legacy/holyskills"
NAME = "devops-console"
PORT = 443
MAIN_PID = 2854526
SERVER_ID = "d5b814b0-73fa-4eba-ac42-0d36aa2fcb36"
OLD_LEASE_ID = "pre-cutover-console-lease"
NEW_LEASE_ID = "post-cutover-console-lease"
ASSIGNMENT_KEY = f"{PROJECT}::{NAME}"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def fixture() -> dict:
    return {
        "port_assignments": [
            {
                "key": ASSIGNMENT_KEY,
                "project": PROJECT,
                "name": NAME,
                "port": PORT,
                "server_status": "running",
            },
            {
                "key": "/srv/worker::api",
                "project": "/srv/worker",
                "name": "api",
                "port": 8443,
                "server_status": "running",
            },
        ],
        "servers": [
            {
                "id": SERVER_ID,
                "key": ASSIGNMENT_KEY,
                "project": PROJECT,
                "name": NAME,
                "port": PORT,
                "pid": MAIN_PID,
                "status": "running",
                "lease_id": NEW_LEASE_ID,
                "registration_identity": {
                    "ok": True,
                    "pid": MAIN_PID,
                    "cwd": f"{PROJECT}/apps/DevOpsConsole",
                    "project": PROJECT,
                    "host": "127.0.0.1",
                    "port": PORT,
                    "listener_inodes": ["123456"],
                    "source": "proc_pid_fd",
                },
                "health": {
                    "ok": True,
                    "pid_alive": True,
                    "classification": "healthy",
                    "check": {"ok": True, "status": 200},
                    "identity": {
                        "ok": True,
                        "pid": MAIN_PID,
                        "cwd": f"{PROJECT}/apps/DevOpsConsole",
                        "project": PROJECT,
                        "host": "127.0.0.1",
                        "port": PORT,
                        "listener_inodes": ["123456"],
                        "source": "proc_pid_fd",
                    },
                },
            },
            {
                "id": "unrelated-live-server",
                "key": "/srv/worker::api",
                "project": "/srv/worker",
                "name": "api",
                "port": 8443,
                "pid": 48111,
                "status": "running",
                "lease_id": "unrelated-live-lease",
                "health": {
                    "ok": True,
                    "pid_alive": True,
                    "classification": "healthy",
                    "check": {"ok": True},
                    "identity": {"ok": True},
                },
            },
            {
                "id": "retired-stopped-history",
                "key": f"{OLD_PROJECT}::{NAME}",
                "project": OLD_PROJECT,
                "name": NAME,
                "port": PORT,
                "pid": None,
                "status": "stopped",
                "lease_id": None,
                "health": {"ok": False, "pid_alive": False},
            },
        ],
        "leases": [
            {
                "id": NEW_LEASE_ID,
                "project": PROJECT,
                "port": PORT,
                "status": "active",
                "purpose": f"server:{NAME}",
                "server_id": SERVER_ID,
                "owner_pid": MAIN_PID,
                "assignment_key": ASSIGNMENT_KEY,
            },
            {
                "id": "unrelated-live-lease",
                "project": "/srv/worker",
                "port": 8443,
                "status": "active",
                "purpose": "server:api",
                "server_id": "unrelated-live-server",
                "owner_pid": 48111,
                "assignment_key": "/srv/worker::api",
            },
            {
                "id": OLD_LEASE_ID,
                "project": OLD_PROJECT,
                "port": PORT,
                "status": "released",
                "purpose": f"server:{NAME}",
                "server_id": "retired-stopped-history",
                "owner_pid": 27001,
                "assignment_key": f"{OLD_PROJECT}::{NAME}",
            },
        ],
    }


def verify(inventory: dict, identities: dict | None = None) -> dict:
    return MODULE.verify_registration_graph(
        inventory,
        identities or {"server_id": SERVER_ID, "lease_id": OLD_LEASE_ID},
        project=PROJECT,
        old_project=OLD_PROJECT,
        name=NAME,
        port=PORT,
        main_pid=MAIN_PID,
    )


def must_fail(change: Callable[[dict], None], contains: str, label: str) -> None:
    inventory = copy.deepcopy(fixture())
    change(inventory)
    try:
        verify(inventory)
    except MODULE.RegistrationGraphError as error:
        require(
            contains.lower() in str(error).lower(),
            f"{label}: expected {contains!r} in {str(error)!r}",
        )
        return
    raise AssertionError(f"verifier missed realistic failure: {label}")


def main() -> int:
    report = verify(fixture())
    require(report["ok"] is True, "valid registration graph should pass")
    require(report["replacement_lease"] is True, "valid graph should prove lease replacement")

    must_fail(
        lambda value: value.update({"port_assignments": [], "servers": [], "leases": []}),
        "target durable assignment",
        "self-registration produced no coordinator rows",
    )

    def unrelated(value: dict) -> None:
        value["port_assignments"][0].update(
            {"key": "/srv/other::other-console", "project": "/srv/other", "name": "other-console"}
        )
        value["servers"][0].update(
            {"id": "unrelated", "key": "/srv/other::other-console", "project": "/srv/other", "name": "other-console"}
        )
        value["leases"][0].update(
            {"project": "/srv/other", "server_id": "unrelated", "assignment_key": "/srv/other::other-console"}
        )

    must_fail(unrelated, "target durable assignment", "port 443 is represented only by unrelated rows")
    must_fail(
        lambda value: value["servers"][0].update({"id": "new-accidental-server-id"}),
        "server id mismatch",
        "cutover failed to reuse the captured logical server identity",
    )

    duplicate_id = copy.deepcopy(fixture())
    duplicate_id["servers"].append(
        {
            **copy.deepcopy(duplicate_id["servers"][1]),
            "id": SERVER_ID,
            "port": 8555,
        }
    )
    try:
        verify(duplicate_id)
    except MODULE.RegistrationGraphError as error:
        require("captured id" in str(error), f"duplicate id had wrong failure: {error}")
    else:
        raise AssertionError("verifier accepted two rows with the captured immutable server id")
    must_fail(
        lambda value: value["port_assignments"][0].update({"key": f"{PROJECT}::wrong-name"}),
        "assignment key mismatch",
        "durable assignment points at the wrong logical key",
    )
    must_fail(
        lambda value: value["servers"][0].update({"status": "stopped"}),
        "current server on port",
        "Console listener exists but coordinator row remained stopped",
    )

    def port_collision(value: dict) -> None:
        value["servers"].append(
            {
                **copy.deepcopy(value["servers"][1]),
                "id": "unrelated-stale-port-owner",
                "port": PORT,
            }
        )

    must_fail(
        port_collision,
        "current server on port",
        "unrelated current server row also claims the Console port",
    )

    def unhealthy(value: dict) -> None:
        value["servers"][0]["status"] = "unhealthy"
        value["servers"][0]["health"].update(
            {"ok": False, "classification": "unhealthy", "check": {"ok": False}}
        )
        value["port_assignments"][0]["server_status"] = "unhealthy"

    must_fail(unhealthy, "server_status mismatch", "running process failed the health check")

    def inconsistent_health(value: dict) -> None:
        value["servers"][0]["health"].update(
            {"ok": False, "classification": "unhealthy", "check": {"ok": False}}
        )

    must_fail(
        inconsistent_health,
        "health ok mismatch",
        "row says running while its concrete health evidence failed",
    )
    must_fail(
        lambda value: value["servers"][0]["health"]["check"].update({"status": 302}),
        "status mismatch",
        "health endpoint redirected instead of returning its exact success response",
    )
    must_fail(
        lambda value: value["servers"][0].update({"pid": MAIN_PID + 1}),
        "pid mismatch",
        "coordinator registered a PID other than systemd MainPID",
    )
    must_fail(
        lambda value: value["servers"][0].pop("registration_identity"),
        "registration identity evidence is missing",
        "server row omitted the exact PID/socket proof",
    )
    must_fail(
        lambda value: value["servers"][0]["registration_identity"].update({"listener_inodes": []}),
        "no exact LISTEN socket inode",
        "registration proof did not bind the MainPID to a concrete listener",
    )
    must_fail(
        lambda value: value["servers"][0]["registration_identity"].update({"host": "127.0.0.2"}),
        "host mismatch",
        "registration proof named another same-port address",
    )
    must_fail(
        lambda value: value["servers"][0]["health"]["identity"].update({"listener_inodes": []}),
        "current health identity has no exact LISTEN socket inode",
        "authenticated inventory did not freshly prove the current listener",
    )
    must_fail(
        lambda value: value["leases"][0].update({"owner_pid": MAIN_PID + 1}),
        "owner_pid mismatch",
        "lease owner PID drifted from systemd MainPID",
    )
    must_fail(
        lambda value: value["leases"][0].update({"purpose": "manual"}),
        "purpose mismatch",
        "Console port remained a manual rather than server-bound lease",
    )
    must_fail(
        lambda value: value["servers"][0].update({"lease_id": "detached-lease"}),
        "lease_id mismatch",
        "server points to a different lease",
    )
    must_fail(
        lambda value: value["leases"][0].update({"server_id": "detached-server"}),
        "active target Console lease",
        "lease points to a different server",
    )
    must_fail(
        lambda value: value["leases"][0].update({"assignment_key": "/tmp/wrong::devops-console"}),
        "assignment_key mismatch",
        "lease is detached from the durable assignment",
    )

    duplicate_lease_id = copy.deepcopy(fixture())
    duplicate_lease_id["leases"].append(
        {
            **copy.deepcopy(duplicate_lease_id["leases"][2]),
            "id": NEW_LEASE_ID,
        }
    )
    try:
        verify(duplicate_lease_id)
    except MODULE.RegistrationGraphError as error:
        require("replacement id" in str(error), f"duplicate lease id had wrong failure: {error}")
    else:
        raise AssertionError("verifier accepted two rows with the replacement lease id")
    must_fail(
        lambda value: value["leases"][0].update({"id": OLD_LEASE_ID}),
        "reused the retired",
        "cutover reused rather than replaced the old lease",
    )

    def old_assignment(value: dict) -> None:
        value["port_assignments"].append(
            {
                "key": f"{OLD_PROJECT}::retired-helper",
                "project": OLD_PROJECT,
                "name": "retired-helper",
                "port": 9443,
                "server_status": "running",
            }
        )

    must_fail(old_assignment, "retired project", "retired checkout retains a current assignment")

    def old_server(value: dict) -> None:
        value["servers"][2]["status"] = "unhealthy"

    must_fail(old_server, "retired project", "retired checkout retains a current server row")

    def old_lease(value: dict) -> None:
        value["leases"][2]["status"] = "active"

    must_fail(old_lease, "retired project", "retired checkout retains an active lease")

    # Exercise the actual standalone command and its private no-follow input
    # path, not only the importable validator used by the focused mutations.
    root = Path(tempfile.mkdtemp(prefix="post-cutover-registration-")).resolve(strict=True)
    try:
        os.chmod(root, 0o700)
        inventory_file = root / "post-cutover-inventory.json"
        identities_file = root / "pre-cutover-identities.json"
        inventory_file.write_text(json.dumps(fixture()) + "\n", encoding="utf-8")
        identities_file.write_text(
            json.dumps({"server_id": SERVER_ID, "lease_id": OLD_LEASE_ID}) + "\n",
            encoding="utf-8",
        )
        os.chmod(inventory_file, 0o600)
        os.chmod(identities_file, 0o600)
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--inventory",
                str(inventory_file),
                "--expected-identities",
                str(identities_file),
                "--project",
                PROJECT,
                "--old-project",
                OLD_PROJECT,
                "--name",
                NAME,
                "--port",
                str(PORT),
                "--main-pid",
                str(MAIN_PID),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        require(completed.returncode == 0, f"standalone command failed: {completed.stderr}")
        require(json.loads(completed.stdout)["server_id"] == SERVER_ID, "standalone report lost id")
    finally:
        for child in root.iterdir():
            child.unlink()
        root.rmdir()

    print(
        "post-cutover registration self-test ok "
        "(assignment, identity, health, PID, lease, old-project recall and valid controls)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
