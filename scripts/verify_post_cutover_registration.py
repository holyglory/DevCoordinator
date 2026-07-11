#!/usr/bin/env python3
"""Verify the production Console's complete post-cutover registration graph.

This guard consumes a coordinator inventory snapshot, the private identity
capture made before cutover, and the Console systemd ``MainPID``.  It does not
query or mutate the coordinator, systemd, or any production process.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from secure_cutover_io import SecureIOError, read_private_regular


class RegistrationGraphError(RuntimeError):
    pass


def _rows(inventory: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = inventory.get(key)
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise RegistrationGraphError(f"inventory {key!r} must be a list of objects")
    return value


def _integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _one(rows: list[dict[str, Any]], *, label: str) -> dict[str, Any]:
    if len(rows) != 1:
        raise RegistrationGraphError(f"expected exactly one {label}, found {len(rows)}")
    return rows[0]


def _require_equal(row: dict[str, Any], key: str, expected: Any, *, label: str) -> None:
    actual = row.get(key)
    if actual != expected:
        raise RegistrationGraphError(
            f"{label} {key} mismatch: expected {expected!r}, got {actual!r}"
        )


def _is_current_server(row: dict[str, Any]) -> bool:
    return row.get("status") != "stopped"


def verify_current_registration_graph(
    inventory: dict[str, Any],
    *,
    project: str,
    name: str,
    port: int,
    main_pid: int,
    expected_server_id: str | None = None,
) -> dict[str, Any]:
    """Require the exact current assignment/server/lease graph.

    This is the reusable production-readiness contract.  Historical cutover
    assertions (retired checkout ownership and replacement lease identity) are
    deliberately layered on top by :func:`verify_registration_graph`.
    """

    if not isinstance(inventory, dict):
        raise RegistrationGraphError("inventory JSON root must be an object")
    if not project:
        raise RegistrationGraphError("project path must be non-empty")
    if not name:
        raise RegistrationGraphError("server name must be non-empty")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise RegistrationGraphError("port must be an integer between 1 and 65535")
    if not isinstance(main_pid, int) or isinstance(main_pid, bool) or main_pid <= 1:
        raise RegistrationGraphError("systemd MainPID must be an integer greater than one")

    if expected_server_id is not None and (
        not isinstance(expected_server_id, str) or not expected_server_id.strip()
    ):
        raise RegistrationGraphError("expected server id must be non-empty when supplied")

    assignments = _rows(inventory, "port_assignments")
    servers = _rows(inventory, "servers")
    leases = _rows(inventory, "leases")
    expected_key = f"{project}::{name}"

    target_assignments = [
        row
        for row in assignments
        if row.get("project") == project and row.get("name") == name
    ]
    port_assignments = [row for row in assignments if _integer(row.get("port")) == port]
    assignment = _one(target_assignments, label="target durable assignment")
    port_assignment = _one(port_assignments, label=f"durable assignment on port {port}")
    if assignment is not port_assignment:
        raise RegistrationGraphError(
            "target durable assignment and the unique port assignment are different rows"
        )
    _require_equal(assignment, "key", expected_key, label="durable assignment")
    _require_equal(assignment, "project", project, label="durable assignment")
    _require_equal(assignment, "name", name, label="durable assignment")
    _require_equal(assignment, "port", port, label="durable assignment")
    _require_equal(assignment, "server_status", "running", label="durable assignment")

    target_servers = [
        row for row in servers if row.get("project") == project and row.get("name") == name
    ]
    server = _one(target_servers, label="target Console server")
    current_servers_on_port = [
        row
        for row in servers
        if _integer(row.get("port")) == port and _is_current_server(row)
    ]
    current_server = _one(current_servers_on_port, label=f"current server on port {port}")
    if server is not current_server:
        raise RegistrationGraphError(
            "target Console server and the unique current server on its port are different rows"
        )
    server_id = server.get("id")
    if not isinstance(server_id, str) or not server_id.strip():
        raise RegistrationGraphError("Console server has no non-empty id")
    if expected_server_id is not None:
        _require_equal(server, "id", expected_server_id, label="Console server")
    _require_equal(server, "key", expected_key, label="Console server")
    _require_equal(server, "project", project, label="Console server")
    _require_equal(server, "name", name, label="Console server")
    _require_equal(server, "port", port, label="Console server")
    _require_equal(server, "pid", main_pid, label="Console server")
    _require_equal(server, "status", "running", label="Console server")
    server_id_rows = [row for row in servers if row.get("id") == server_id]
    identity_label = "captured id" if expected_server_id is not None else "current id"
    if _one(server_id_rows, label=f"server row with the {identity_label}") is not server:
        raise RegistrationGraphError(
            f"{identity_label} resolves to a different inventory row"
        )

    registration_identity = server.get("registration_identity")
    if not isinstance(registration_identity, dict):
        raise RegistrationGraphError("Console server registration identity evidence is missing")
    _require_equal(registration_identity, "ok", True, label="registration identity")
    _require_equal(registration_identity, "pid", main_pid, label="registration identity")
    _require_equal(registration_identity, "project", project, label="registration identity")
    _require_equal(registration_identity, "host", "127.0.0.1", label="registration identity")
    _require_equal(registration_identity, "port", port, label="registration identity")
    _require_equal(registration_identity, "source", "proc_pid_fd", label="registration identity")
    identity_cwd = registration_identity.get("cwd")
    project_prefix = project.rstrip("/") + "/"
    if not isinstance(identity_cwd, str) or not (
        identity_cwd == project or identity_cwd.startswith(project_prefix)
    ):
        raise RegistrationGraphError(
            f"registration identity cwd is outside project: {identity_cwd!r}"
        )
    listener_inodes = registration_identity.get("listener_inodes")
    if (
        not isinstance(listener_inodes, list)
        or not listener_inodes
        or any(not isinstance(value, str) or not value.isdigit() for value in listener_inodes)
    ):
        raise RegistrationGraphError("registration identity has no exact LISTEN socket inode evidence")

    health = server.get("health")
    if not isinstance(health, dict):
        raise RegistrationGraphError("Console server health evidence is missing")
    _require_equal(health, "ok", True, label="Console server health")
    _require_equal(health, "pid_alive", True, label="Console server health")
    _require_equal(health, "classification", "healthy", label="Console server health")
    for key in ("check", "identity"):
        evidence = health.get(key)
        if not isinstance(evidence, dict) or evidence.get("ok") is not True:
            raise RegistrationGraphError(f"Console server health {key} evidence is not successful")
    _require_equal(health["check"], "status", 200, label="Console server health check")
    current_identity = health["identity"]
    _require_equal(current_identity, "pid", main_pid, label="current health identity")
    _require_equal(current_identity, "project", project, label="current health identity")
    _require_equal(current_identity, "host", "127.0.0.1", label="current health identity")
    _require_equal(current_identity, "port", port, label="current health identity")
    _require_equal(current_identity, "source", "proc_pid_fd", label="current health identity")
    current_cwd = current_identity.get("cwd")
    if not isinstance(current_cwd, str) or not (
        current_cwd == project or current_cwd.startswith(project_prefix)
    ):
        raise RegistrationGraphError(f"current health identity cwd is outside project: {current_cwd!r}")
    current_inodes = current_identity.get("listener_inodes")
    if (
        not isinstance(current_inodes, list)
        or not current_inodes
        or any(not isinstance(value, str) or not value.isdigit() for value in current_inodes)
    ):
        raise RegistrationGraphError("current health identity has no exact LISTEN socket inode evidence")

    active_leases = [row for row in leases if row.get("status") == "active"]
    active_on_port = [row for row in active_leases if _integer(row.get("port")) == port]
    lease = _one(active_on_port, label=f"active replacement lease on port {port}")
    target_active_leases = [
        row
        for row in active_leases
        if row.get("project") == project and row.get("server_id") == server_id
    ]
    target_lease = _one(target_active_leases, label="active target Console lease")
    if lease is not target_lease:
        raise RegistrationGraphError(
            "target Console lease and the unique active lease on its port are different rows"
        )

    lease_id = lease.get("id")
    if not isinstance(lease_id, str) or not lease_id.strip():
        raise RegistrationGraphError("active replacement lease has no non-empty id")
    _require_equal(lease, "project", project, label="active Console lease")
    _require_equal(lease, "port", port, label="active Console lease")
    _require_equal(lease, "status", "active", label="active Console lease")
    _require_equal(lease, "purpose", f"server:{name}", label="active Console lease")
    _require_equal(lease, "server_id", server_id, label="active Console lease")
    _require_equal(lease, "owner_pid", main_pid, label="active Console lease")
    _require_equal(lease, "assignment_key", expected_key, label="active Console lease")
    lease_id_rows = [row for row in leases if row.get("id") == lease_id]
    if _one(lease_id_rows, label="lease row with the replacement id") is not lease:
        raise RegistrationGraphError("replacement lease id resolves to a different inventory row")

    _require_equal(server, "lease_id", lease_id, label="Console server")
    _require_equal(lease, "server_id", server.get("id"), label="active Console lease")

    return {
        "ok": True,
        "project": project,
        "name": name,
        "port": port,
        "assignment_key": expected_key,
        "server_id": server_id,
        "server_pid": main_pid,
        "lease_id": lease_id,
    }


def verify_registration_graph(
    inventory: dict[str, Any],
    identities: dict[str, Any],
    *,
    project: str,
    old_project: str,
    name: str,
    port: int,
    main_pid: int,
) -> dict[str, Any]:
    """Require the current graph plus the cutover-specific history contract."""

    if not isinstance(inventory, dict):
        raise RegistrationGraphError("inventory JSON root must be an object")
    if not isinstance(identities, dict):
        raise RegistrationGraphError("captured identities JSON root must be an object")
    if not project or not old_project or project == old_project:
        raise RegistrationGraphError("new and old project paths must be non-empty and distinct")
    expected_server_id = identities.get("server_id")
    if not isinstance(expected_server_id, str) or not expected_server_id.strip():
        raise RegistrationGraphError("captured identities must contain a non-empty server_id")
    old_lease_id = identities.get("lease_id")
    if not isinstance(old_lease_id, str) or not old_lease_id.strip():
        raise RegistrationGraphError(
            "captured identities must contain a non-empty pre-cutover lease_id"
        )

    assignments = _rows(inventory, "port_assignments")
    servers = _rows(inventory, "servers")
    leases = _rows(inventory, "leases")
    # A stopped server and an inactive lease are useful history. Assignments,
    # non-stopped servers, and active leases are current ownership claims and
    # must not retain the checkout retired by this cutover.
    old_assignments = [row for row in assignments if row.get("project") == old_project]
    old_servers = [
        row
        for row in servers
        if row.get("project") == old_project and _is_current_server(row)
    ]
    old_leases = [
        row
        for row in leases
        if row.get("project") == old_project and row.get("status") == "active"
    ]
    if old_assignments or old_servers or old_leases:
        raise RegistrationGraphError(
            "retired project still owns current coordinator rows "
            f"(assignments={len(old_assignments)}, servers={len(old_servers)}, "
            f"active_leases={len(old_leases)})"
        )

    active_target_old_lease = [
        row
        for row in leases
        if row.get("id") == old_lease_id
        and row.get("status") == "active"
        and row.get("project") == project
        and _integer(row.get("port")) == port
    ]
    if active_target_old_lease:
        raise RegistrationGraphError("active Console lease reused the retired pre-cutover lease id")

    report = verify_current_registration_graph(
        inventory,
        project=project,
        name=name,
        port=port,
        main_pid=main_pid,
        expected_server_id=expected_server_id,
    )
    if report["lease_id"] == old_lease_id:
        raise RegistrationGraphError("active Console lease reused the retired pre-cutover lease id")
    report.update(
        {
            "replacement_lease": True,
            "old_project_current_rows": 0,
        }
    )
    return report


def _read_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        raw = read_private_regular(path, label=label)
        value = json.loads(raw.decode("utf-8"))
    except (SecureIOError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RegistrationGraphError(f"cannot read {label}: {error}") from error
    if not isinstance(value, dict):
        raise RegistrationGraphError(f"{label} JSON root must be an object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, help="private post-cutover inventory JSON")
    parser.add_argument(
        "--expected-identities",
        required=True,
        help="private pre-cutover identity capture containing server_id and lease_id",
    )
    parser.add_argument("--project", required=True, help="exact new canonical project path")
    parser.add_argument("--old-project", required=True, help="exact retired canonical project path")
    parser.add_argument("--name", required=True, help="exact Console server name")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--main-pid", required=True, type=int, help="systemd MainPID for Console")
    args = parser.parse_args(argv)
    try:
        report = verify_registration_graph(
            _read_json(Path(args.inventory), label="post-cutover inventory"),
            _read_json(Path(args.expected_identities), label="pre-cutover identities"),
            project=args.project,
            old_project=args.old_project,
            name=args.name,
            port=args.port,
            main_pid=args.main_pid,
        )
    except RegistrationGraphError as error:
        print(f"post-cutover registration graph failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
