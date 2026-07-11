#!/usr/bin/env python3
"""Plan and atomically remove reviewed durable assignments from a retired checkout."""

from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

from secure_cutover_io import SecureIOError, open_private_parent, read_private_regular


SCHEMA_VERSION = 1
ROW_KEYS = {
    "disposition",
    "key",
    "name",
    "port",
    "source",
    "server_id",
    "pid",
    "cwd",
    "cmd",
    "lease_id",
}


class RetiredAssignmentError(RuntimeError):
    pass


def canonical_path(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RetiredAssignmentError("project path must be non-empty")
    return str(Path(value).expanduser().resolve())


def inside(path: Any, project: str) -> bool:
    if not isinstance(path, str) or not path:
        return False
    resolved = canonical_path(path)
    return resolved == project or resolved.startswith(project.rstrip("/") + "/")


def integer(value: Any, *, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise RetiredAssignmentError(f"{label} must be an integer")
    return value


def json_object(payload: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RetiredAssignmentError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise RetiredAssignmentError(f"{label} root must be an object")
    return value


def private_json(path: Path, *, label: str) -> tuple[dict[str, Any], str]:
    payload = read_private_regular(path, label=label)
    return json_object(payload, label=label), hashlib.sha256(payload).hexdigest()


def write_private_exclusive(path: Path, value: dict[str, Any]) -> None:
    parent_fd, _absolute, name = open_private_parent(path)
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=parent_fd,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.fsync(parent_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def rows(document: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = document.get(key)
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise RetiredAssignmentError(f"inventory {key} must be a list of objects")
    return value


def exact_one(items: list[dict[str, Any]], *, label: str) -> dict[str, Any]:
    if len(items) != 1:
        raise RetiredAssignmentError(f"expected exactly one {label}, found {len(items)}")
    return items[0]


def normalized_review_row(value: Any, *, disposition: str, old_project: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != ROW_KEYS:
        raise RetiredAssignmentError(
            f"{disposition} allowlist row must contain exactly the reviewed fields"
        )
    row = dict(value)
    if row.get("disposition") != disposition:
        raise RetiredAssignmentError(f"allowlist row disposition must be {disposition!r}")
    name = row.get("name")
    if not isinstance(name, str) or not name:
        raise RetiredAssignmentError("allowlist row name must be non-empty")
    port = integer(row.get("port"), label=f"{name} port")
    if not 1 <= port <= 65535:
        raise RetiredAssignmentError(f"{name} port is outside 1-65535")
    if row.get("key") != f"{old_project}::{name}":
        raise RetiredAssignmentError(f"{name} allowlist key does not match the retiring project")
    for key in ("source", "server_id", "lease_id"):
        if not isinstance(row.get(key), str) or not row[key]:
            raise RetiredAssignmentError(f"{name} allowlist {key} must be non-empty")
    pid = integer(row.get("pid"), label=f"{name} pid")
    if pid <= 1:
        raise RetiredAssignmentError(f"{name} allowlist pid must be greater than one")
    if not inside(row.get("cwd"), old_project):
        raise RetiredAssignmentError(f"{name} allowlist cwd is outside the retiring project")
    if row.get("cmd") is not None and not isinstance(row.get("cmd"), str):
        raise RetiredAssignmentError(f"{name} allowlist cmd must be a string or null")
    return row


def parse_allowlist(
    document: dict[str, Any], *, old_project: str, new_project: str
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if set(document) != {"schema_version", "old_project", "new_project", "target", "cleanup"}:
        raise RetiredAssignmentError("allowlist contains missing or unknown top-level fields")
    if document.get("schema_version") != SCHEMA_VERSION:
        raise RetiredAssignmentError("allowlist schema version is unsupported")
    if canonical_path(document.get("old_project")) != old_project:
        raise RetiredAssignmentError("allowlist old project does not match the CLI")
    if canonical_path(document.get("new_project")) != new_project:
        raise RetiredAssignmentError("allowlist new project does not match the CLI")
    target = normalized_review_row(document.get("target"), disposition="relocate", old_project=old_project)
    cleanup_value = document.get("cleanup")
    if not isinstance(cleanup_value, list):
        raise RetiredAssignmentError("allowlist cleanup must be a list")
    cleanup = [
        normalized_review_row(item, disposition="unassign", old_project=old_project)
        for item in cleanup_value
    ]
    identities = [(item["key"], item["port"], item["server_id"]) for item in [target, *cleanup]]
    if len(identities) != len(set(identities)):
        raise RetiredAssignmentError("allowlist contains duplicate assignment identities")
    if len({item["key"] for item in [target, *cleanup]}) != len([target, *cleanup]):
        raise RetiredAssignmentError("allowlist contains duplicate keys")
    if len({item["port"] for item in [target, *cleanup]}) != len([target, *cleanup]):
        raise RetiredAssignmentError("allowlist contains duplicate ports")
    return target, cleanup


def process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def listening_ports(proc_tables: list[Path]) -> set[int]:
    if len(proc_tables) < 2:
        raise RetiredAssignmentError("both IPv4 and IPv6 proc TCP tables are required")
    found: set[int] = set()
    for table in proc_tables:
        try:
            lines = table.read_text(encoding="utf-8").splitlines()
        except OSError as error:
            raise RetiredAssignmentError(f"TCP listener table is unavailable: {table}") from error
        for line in lines[1:]:
            fields = line.split()
            if len(fields) < 4:
                continue
            try:
                port = int(fields[1].rsplit(":", 1)[1], 16)
            except (IndexError, ValueError):
                raise RetiredAssignmentError(f"TCP listener table is malformed: {table}")
            if fields[3] == "0A":
                found.add(port)
    return found


def compare_assignment(row: dict[str, Any], reviewed: dict[str, Any], *, stopped: bool) -> None:
    label = reviewed["name"]
    for key in ("key", "name", "port", "source"):
        if row.get(key) != reviewed.get(key):
            raise RetiredAssignmentError(f"{label} assignment {key} drifted")
    expected_status = "stopped" if stopped else "running"
    if row.get("server_status") != expected_status:
        raise RetiredAssignmentError(f"{label} assignment is not {expected_status}")


def compare_server(row: dict[str, Any], reviewed: dict[str, Any], *, stopped: bool) -> None:
    label = reviewed["name"]
    expected = {
        "id": reviewed["server_id"],
        "key": reviewed["key"],
        "name": reviewed["name"],
        "port": reviewed["port"],
        "pid": reviewed["pid"],
        "cwd": reviewed["cwd"],
        "cmd": reviewed["cmd"],
        "lease_id": reviewed["lease_id"],
    }
    for key, value in expected.items():
        if row.get(key) != value:
            raise RetiredAssignmentError(f"{label} server {key} drifted")
    if row.get("project") != reviewed["key"].rsplit("::", 1)[0]:
        raise RetiredAssignmentError(f"{label} server project drifted")
    if stopped:
        if row.get("status") != "stopped":
            raise RetiredAssignmentError(f"{label} server is not stopped")
        health = row.get("health")
        if not isinstance(health, dict) or health.get("pid_alive") is not False:
            raise RetiredAssignmentError(f"{label} stopped health does not prove a dead PID")
        if process_alive(reviewed["pid"]):
            raise RetiredAssignmentError(f"{label} recorded PID is alive or reused")
    elif row.get("status") != "running":
        raise RetiredAssignmentError(f"{label} relocation target is not running")


def lease_conflicts(leases: list[dict[str, Any]], reviewed: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        lease
        for lease in leases
        if lease.get("status") == "active"
        and (
            lease.get("port") == reviewed["port"]
            or lease.get("server_id") == reviewed["server_id"]
            or lease.get("assignment_key") == reviewed["key"]
            or lease.get("id") == reviewed["lease_id"]
        )
    ]


def build_plan(
    inventory: dict[str, Any],
    allowlist: dict[str, Any],
    *,
    old_project: str,
    new_project: str,
    target_name: str,
    target_port: int,
    listener_ports: set[int],
    inventory_sha256: str,
    allowlist_sha256: str,
) -> dict[str, Any]:
    if inventory.get("project") is not None:
        raise RetiredAssignmentError("pre-cutover inventory must be global, not project-filtered")
    target, cleanup = parse_allowlist(allowlist, old_project=old_project, new_project=new_project)
    if target["name"] != target_name or target["port"] != target_port:
        raise RetiredAssignmentError("allowlist relocation target does not match the CLI")
    assignments = rows(inventory, "port_assignments")
    servers = rows(inventory, "servers")
    leases = rows(inventory, "leases")
    old_assignments = [item for item in assignments if item.get("project") == old_project]
    reviewed_keys = {item["key"] for item in [target, *cleanup]}
    actual_keys = {item.get("key") for item in old_assignments}
    if actual_keys != reviewed_keys or len(old_assignments) != len(reviewed_keys):
        raise RetiredAssignmentError("retiring-project assignment set differs from the reviewed allowlist")

    target_assignment = exact_one(
        [item for item in old_assignments if item.get("key") == target["key"]],
        label="relocation target assignment",
    )
    compare_assignment(target_assignment, target, stopped=False)
    target_server = exact_one(
        [item for item in servers if item.get("key") == target["key"]],
        label="relocation target server",
    )
    compare_server(target_server, target, stopped=False)
    target_health = target_server.get("health")
    if not isinstance(target_health, dict) or target_health.get("pid_alive") is not True:
        raise RetiredAssignmentError("relocation target health does not prove a live PID")
    if not process_alive(target["pid"]):
        raise RetiredAssignmentError("relocation target PID is not live before the stop boundary")
    target_lease = exact_one(
        [item for item in leases if item.get("id") == target["lease_id"]],
        label="relocation target lease",
    )
    if not (
        target_lease.get("status") == "active"
        and target_lease.get("project") == old_project
        and target_lease.get("port") == target_port
        and target_lease.get("server_id") == target["server_id"]
        and target_lease.get("purpose") == f"server:{target_name}"
    ):
        raise RetiredAssignmentError("relocation target lease graph drifted")
    target_active = [item for item in leases if item.get("status") == "active" and item.get("port") == target_port]
    if len(target_active) != 1 or target_active[0].get("id") != target["lease_id"]:
        raise RetiredAssignmentError("relocation target port has an ambiguous active lease")

    for reviewed in cleanup:
        assignment = exact_one(
            [item for item in old_assignments if item.get("key") == reviewed["key"]],
            label=f"{reviewed['name']} assignment",
        )
        compare_assignment(assignment, reviewed, stopped=True)
        server = exact_one(
            [item for item in servers if item.get("key") == reviewed["key"]],
            label=f"{reviewed['name']} server",
        )
        compare_server(server, reviewed, stopped=True)
        if lease_conflicts(leases, reviewed):
            raise RetiredAssignmentError(f"{reviewed['name']} has a matching active lease")
        if reviewed["port"] in listener_ports:
            raise RetiredAssignmentError(f"{reviewed['name']} port has a TCP listener")

    return {
        "schema_version": SCHEMA_VERSION,
        "old_project": old_project,
        "new_project": new_project,
        "target": target,
        "cleanup": cleanup,
        "inventory_sha256": inventory_sha256,
        "allowlist_sha256": allowlist_sha256,
    }


def load_coordinator(path: Path, *, expected_root: str) -> Any:
    expected = Path(expected_root) / "skills" / "codex-dev-coordinator" / "scripts" / "dev_coordinator.py"
    if path.resolve(strict=True) != expected.resolve(strict=True):
        raise RetiredAssignmentError("coordinator script is not the reviewed DevCoordinator copy")
    specification = importlib.util.spec_from_file_location("retired_assignment_coordinator", path)
    if specification is None or specification.loader is None:
        raise RetiredAssignmentError("coordinator module cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def read_state_nofollow(home: Path) -> dict[str, Any]:
    descriptor = os.open(home / "state.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise RetiredAssignmentError("coordinator state must be a private user-owned regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    return json_object(b"".join(chunks), label="coordinator state")


def state_rows(state: dict[str, Any], key: str) -> dict[str, dict[str, Any]]:
    value = state.get(key)
    if not isinstance(value, dict) or any(not isinstance(item, dict) for item in value.values()):
        raise RetiredAssignmentError(f"coordinator state {key} must be an object of objects")
    return value


def compare_raw_assignment(row: dict[str, Any], reviewed: dict[str, Any]) -> None:
    for key in ("key", "name", "port", "source"):
        if row.get(key) != reviewed.get(key):
            raise RetiredAssignmentError(f"{reviewed['name']} live assignment {key} drifted")
    if row.get("project") != reviewed["key"].rsplit("::", 1)[0]:
        raise RetiredAssignmentError(f"{reviewed['name']} live assignment project drifted")


def pending_conflict(operation: dict[str, Any], reviewed: dict[str, Any], old_project: str) -> bool:
    if operation.get("status") != "pending":
        return False
    return (
        operation.get("project") == old_project
        or operation.get("target") in {
            f"project:{old_project}",
            f"server:{reviewed['key']}",
            f"port:{reviewed['port']}",
        }
        or operation.get("server_id") == reviewed["server_id"]
        or operation.get("lease_id") == reviewed["lease_id"]
    )


def validate_apply_state(state: dict[str, Any], plan: dict[str, Any], module: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    old_project = plan["old_project"]
    target = plan["target"]
    cleanup = plan["cleanup"]
    assignments = state_rows(state, "port_assignments")
    servers = state_rows(state, "servers")
    leases = state_rows(state, "leases")
    operations = state_rows(state, "operations")
    old_assignments = {key: value for key, value in assignments.items() if value.get("project") == old_project}
    expected_keys = {target["key"], *(item["key"] for item in cleanup)}
    if set(old_assignments) != expected_keys:
        raise RetiredAssignmentError("live retiring-project assignment set drifted after planning")
    compare_raw_assignment(old_assignments[target["key"]], target)
    target_servers = [item for item in servers.values() if item.get("key") == target["key"]]
    target_server = exact_one(target_servers, label="live relocation target server")
    compare_server(target_server, target, stopped=False)
    if module.pid_alive(target["pid"]):
        raise RetiredAssignmentError("relocation target PID is still alive at the cleanup boundary")
    target_lease = leases.get(target["lease_id"])
    if not isinstance(target_lease, dict) or not (
        target_lease.get("status") == "active"
        and target_lease.get("project") == old_project
        and target_lease.get("port") == target["port"]
        and target_lease.get("server_id") == target["server_id"]
    ):
        raise RetiredAssignmentError("live relocation target lease graph drifted")
    if module.listener_evidence_for_port(target["port"]).get("present"):
        raise RetiredAssignmentError("relocation target still has a live listener")

    live_leases = list(leases.values())
    for reviewed in cleanup:
        assignment = old_assignments.get(reviewed["key"])
        if not isinstance(assignment, dict):
            raise RetiredAssignmentError(f"{reviewed['name']} live assignment is missing")
        compare_raw_assignment(assignment, reviewed)
        server = exact_one(
            [item for item in servers.values() if item.get("key") == reviewed["key"]],
            label=f"live {reviewed['name']} server",
        )
        compare_server(server, reviewed, stopped=True)
        if lease_conflicts(live_leases, reviewed):
            raise RetiredAssignmentError(f"{reviewed['name']} gained a matching active lease")
        if any(pending_conflict(item, reviewed, old_project) for item in operations.values()):
            raise RetiredAssignmentError(f"{reviewed['name']} has a pending coordinator operation")
        if module.listener_evidence_for_port(reviewed["port"]).get("present"):
            raise RetiredAssignmentError(f"{reviewed['name']} gained a live listener")
    unrelated = {key: copy.deepcopy(value) for key, value in assignments.items() if key not in expected_keys}
    return unrelated, cleanup


def build_atomic_cleanup_state(
    state: dict[str, Any], plan: dict[str, Any], module: Any, *, agent: str
) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    """Validate every row, then mutate only a detached copy of state."""

    unrelated_before, reviewed_cleanup = validate_apply_state(state, plan, module)
    target = plan["target"]
    old_project = plan["old_project"]
    working = copy.deepcopy(state)
    removed: list[dict[str, Any]] = []
    for reviewed in reviewed_cleanup:
        removed.append(
            module.unassign_port(
                working,
                agent=agent,
                project=old_project,
                name=reviewed["name"],
                port=reviewed["port"],
                force=False,
            )
        )
    assignments_after = state_rows(working, "port_assignments")
    cleanup_keys = {item["key"] for item in reviewed_cleanup}
    unrelated_after = {
        key: value
        for key, value in assignments_after.items()
        if key != target["key"] and key not in cleanup_keys
    }
    if unrelated_after != unrelated_before:
        raise RetiredAssignmentError("cleanup changed an unrelated durable assignment")
    if set(
        key for key, value in assignments_after.items() if value.get("project") == old_project
    ) != {target["key"]}:
        raise RetiredAssignmentError("cleanup did not leave exactly the relocation target")
    digest = hashlib.sha256(
        json.dumps(unrelated_before, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return working, removed, digest


def apply_plan(
    plan: dict[str, Any], *, coordinator_script: Path, coordinator_home: Path, agent: str
) -> dict[str, Any]:
    if set(plan) != {
        "schema_version",
        "old_project",
        "new_project",
        "target",
        "cleanup",
        "inventory_sha256",
        "allowlist_sha256",
    }:
        raise RetiredAssignmentError("cleanup plan contains missing or unknown fields")
    old_project = canonical_path(plan.get("old_project"))
    new_project = canonical_path(plan.get("new_project"))
    target, cleanup = parse_allowlist(
        {
            "schema_version": plan.get("schema_version"),
            "old_project": old_project,
            "new_project": new_project,
            "target": plan.get("target"),
            "cleanup": plan.get("cleanup"),
        },
        old_project=old_project,
        new_project=new_project,
    )
    for key in ("inventory_sha256", "allowlist_sha256"):
        digest = plan.get(key)
        if not isinstance(digest, str) or len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise RetiredAssignmentError(f"cleanup plan {key} is not a SHA-256 digest")
    if not agent:
        raise RetiredAssignmentError("agent attribution is required")
    home = coordinator_home.resolve(strict=True)
    if coordinator_home.is_symlink() or home != coordinator_home:
        raise RetiredAssignmentError("coordinator home must be a direct canonical directory")
    metadata = home.stat()
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise RetiredAssignmentError("coordinator home must be private to the current user")
    os.environ["CODEX_AGENT_COORDINATOR_HOME"] = str(home)
    module = load_coordinator(coordinator_script, expected_root=new_project)
    lock_fd = os.open(home / "state.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    lock_metadata = os.fstat(lock_fd)
    if (
        not stat.S_ISREG(lock_metadata.st_mode)
        or lock_metadata.st_uid != os.getuid()
        or stat.S_IMODE(lock_metadata.st_mode) & 0o077
    ):
        os.close(lock_fd)
        raise RetiredAssignmentError("coordinator state lock must be a private user-owned regular file")
    removed: list[dict[str, Any]] = []
    unrelated_digest = ""
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        state = read_state_nofollow(home)
        working, removed, unrelated_digest = build_atomic_cleanup_state(
            state, plan, module, agent=agent
        )
        module.write_state(working)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
    return {
        "ok": True,
        "old_project": old_project,
        "new_project": new_project,
        "target_key": target["key"],
        "removed": removed,
        "unrelated_assignments_sha256_before": unrelated_digest,
        "unrelated_assignments_sha256_after": unrelated_digest,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    plan = subparsers.add_parser("plan")
    plan.add_argument("--inventory", type=Path, required=True)
    plan.add_argument("--allowlist", type=Path, required=True)
    plan.add_argument("--output", type=Path, required=True)
    plan.add_argument("--old-project", required=True)
    plan.add_argument("--new-project", required=True)
    plan.add_argument("--target-name", required=True)
    plan.add_argument("--target-port", type=int, required=True)
    plan.add_argument("--proc-tcp-table", type=Path, action="append")
    apply = subparsers.add_parser("apply")
    apply.add_argument("--plan", type=Path, required=True)
    apply.add_argument("--coordinator-script", type=Path, required=True)
    apply.add_argument("--coordinator-home", type=Path, required=True)
    apply.add_argument("--agent", required=True)
    apply.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.action == "plan":
            old_project = canonical_path(args.old_project)
            new_project = canonical_path(args.new_project)
            inventory, inventory_digest = private_json(args.inventory, label="pre-cutover inventory")
            allowlist, allowlist_digest = private_json(args.allowlist, label="retired assignment allowlist")
            tables = args.proc_tcp_table or [Path("/proc/net/tcp"), Path("/proc/net/tcp6")]
            result = build_plan(
                inventory,
                allowlist,
                old_project=old_project,
                new_project=new_project,
                target_name=args.target_name,
                target_port=args.target_port,
                listener_ports=listening_ports(tables),
                inventory_sha256=inventory_digest,
                allowlist_sha256=allowlist_digest,
            )
        else:
            plan, _digest = private_json(args.plan, label="retired assignment cleanup plan")
            result = apply_plan(
                plan,
                coordinator_script=args.coordinator_script,
                coordinator_home=args.coordinator_home,
                agent=args.agent.strip(),
            )
        write_private_exclusive(args.output, result)
        print(json.dumps({"ok": True, "action": args.action}, sort_keys=True))
        return 0
    except (RetiredAssignmentError, SecureIOError, OSError, ValueError) as error:
        print(json.dumps({"error": str(error), "type": type(error).__name__}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
