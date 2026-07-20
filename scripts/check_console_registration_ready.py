#!/usr/bin/env python3
"""Wait for the systemd Console MainPID's exact coordinator registration graph."""

from __future__ import annotations

import argparse
import errno
import hashlib
import http.client
import json
import math
import os
import pwd
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlencode

from linux_proc_identity import (
    ProcIdentityError,
    parse_start_ticks,
    read_stable_process_identity,
)
from secure_cutover_io import SecureIOError, read_private_regular
from verify_post_cutover_registration import (
    RegistrationGraphError,
    current_registration_inventory_view,
    verify_current_registration_graph,
)


class ConsoleRegistrationError(RuntimeError):
    """The observed startup state is unsafe or unobservable."""


class ConsoleRegistrationTimeout(ConsoleRegistrationError):
    """Only explicitly retryable states were observed until the deadline."""


class InventoryTransportPending(ConsoleRegistrationError):
    """The loopback API transport is in one explicitly temporary state."""


IN_FLIGHT_LEASE_FRESHNESS_SECONDS = 120.0
MAX_BROKER_LEASE_TTL_SECONDS = 7 * 24 * 60 * 60
TIMESTAMP_FUTURE_SKEW_SECONDS = 1.0
BROKER_IDENTIFIER_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:@-"
)


def _rows(inventory: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = inventory.get(key)
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ConsoleRegistrationError(f"inventory {key!r} must be a list of objects")
    return value


def _integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _timestamp_epoch(value: Any) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    result = parsed.timestamp()
    return result if math.isfinite(result) else None


def console_account_identity(
    uid: int,
    *,
    account_lookup: Callable[[int], Any] = pwd.getpwuid,
) -> str:
    """Resolve the stable MainPID UID through the host's authoritative NSS map."""

    if _integer(uid) is None or uid < 0:
        raise ConsoleRegistrationError("Console MainPID UID is invalid")
    try:
        record = account_lookup(uid)
    except (KeyError, OSError) as error:
        raise ConsoleRegistrationError(
            f"Console MainPID UID {uid} has no authoritative NSS account mapping"
        ) from error
    account_id = getattr(record, "pw_name", None)
    record_uid = getattr(record, "pw_uid", None)
    if (
        record_uid != uid
        or not isinstance(account_id, str)
        or not account_id
        or any(character not in BROKER_IDENTIFIER_CHARS for character in account_id)
    ):
        raise ConsoleRegistrationError(
            "Console MainPID NSS account mapping is invalid or mismatched"
        )
    return account_id


def _broker_listener_fingerprint(
    *,
    main_pid: int,
    main_uid: int,
    main_start_ticks: str,
    main_cwd: str,
    project: str,
    port: int,
) -> str:
    """Reproduce the broker's exact Linux listener-evidence fingerprint."""

    evidence = {
        "pid": main_pid,
        "owner_uid": main_uid,
        "process_identity": f"linux:{main_pid}:{main_start_ticks}",
        "cwd": main_cwd,
        "canonical_root": project,
        "port": port,
        "protocol": "tcp",
    }
    return "sha256:" + hashlib.sha256(
        json.dumps(
            evidence,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _require_broker_stopped_baseline(
    raw: dict[str, Any],
    *,
    server: dict[str, Any],
    assignment: dict[str, Any],
    project: str,
    name: str,
    port: int,
    main_pid: int,
    main_uid: int | None,
    main_account_id: str | None,
    main_start_ticks: str | None,
    main_cwd: str | None,
    observed_at_epoch: float | None,
) -> str | None:
    """Require service-authority evidence for a process-free stopped row."""

    def reject(detail: str) -> None:
        raise ConsoleRegistrationError(
            "unsafe registration baseline: null PID stopped row lacks exact "
            f"broker/server-wide proof ({detail})"
        )

    def rows(container: Any, key: str, label: str) -> list[dict[str, Any]]:
        if not isinstance(container, dict):
            reject(f"{label} is not an object")
        value = container.get(key)
        if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
            reject(f"{label}.{key} is not a list of objects")
        return value

    authority = raw.get("authority")
    store = raw.get("store")
    if raw.get("schema_version") != 2 or not isinstance(authority, dict) or not isinstance(store, dict):
        reject("normalized authority envelope is missing")
    if (
        authority.get("scope") != "server-wide"
        or authority.get("transport") != "authenticated-unix-socket"
        or not isinstance(authority.get("socket"), str)
        or not Path(authority["socket"]).is_absolute()
        or _integer(authority.get("service_uid")) is None
        or _integer(authority.get("service_uid")) < 0
    ):
        reject("authority is not the authenticated system broker")
    generation = authority.get("database_generation")
    if not isinstance(generation, str) or not generation or store.get("database_generation") != generation:
        reject("broker profile is not bound to the projected database generation")

    server_id = server.get("id")
    if not isinstance(server_id, str) or not server_id.strip():
        reject("compatibility server id is missing")
    repositories = [
        row for row in rows(raw, "repositories", "inventory")
        if row.get("canonical_root") == project
    ]
    if len(repositories) != 1:
        reject("canonical repository is missing or ambiguous")
    repository = repositories[0]
    repo_id = repository.get("repo_id")
    if (
        not isinstance(repo_id, str)
        or not repo_id
        or repository.get("state") != "active"
        or repository.get("installation_status") == "disabled"
    ):
        reject("canonical repository is not one active installed broker resource")

    resources = raw.get("resources")
    definitions = [
        row for row in rows(resources, "servers", "resources")
        if row.get("server_definition_id") == server_id
    ]
    if len(definitions) != 1:
        reject("normalized server definition is missing or ambiguous")
    definition = definitions[0]
    if (
        definition.get("repo_id") != repo_id
        or definition.get("name") != name
        or not isinstance(definition.get("cwd"), str)
        or not (
            definition["cwd"] == project
            or definition["cwd"].startswith(project.rstrip("/") + "/")
        )
    ):
        reject("normalized server definition does not bind the exact repository target")

    observations = raw.get("observations")
    stopped = [
        row for row in rows(observations, "servers", "observations")
        if row.get("server_definition_id") == server_id
    ]
    if len(stopped) != 1:
        reject("normalized stopped observation is missing or ambiguous")
    observation = stopped[0]
    fingerprint = observation.get("observation_fingerprint")
    if (
        observation.get("lifecycle") != "stopped"
        or "pid" not in observation
        or observation.get("pid") is not None
        or observation.get("process_start_time") is not None
        or observation.get("process_fingerprint") is not None
        or observation.get("listener_host") != "127.0.0.1"
        or _integer(observation.get("listener_port")) != port
        or observation.get("listener_observable") not in {True, 1}
        or observation.get("health_classification") not in {"stopped", "unhealthy"}
        or observation.get("health_ok") not in {False, 0}
        or not isinstance(observation.get("stopped_at"), str)
        or not observation.get("stopped_at")
        or not isinstance(observation.get("stopped_reason"), str)
        or not observation.get("stopped_reason")
        or not isinstance(fingerprint, str)
        or len(fingerprint) != 64
        or any(character not in "0123456789abcdef" for character in fingerprint)
    ):
        reject("normalized observation is not an exact broker-published stop")

    normalized_assignments = [
        row for row in rows(raw, "port_assignments", "inventory")
        if _integer(row.get("port")) == port
        or (row.get("repo_id") == repo_id and row.get("server_name") == name)
    ]
    if len(normalized_assignments) != 1:
        reject("normalized durable assignment is missing or ambiguous")
    normalized_assignment = normalized_assignments[0]
    expected_normalized_assignment = {
        "repo_id": repo_id,
        "server_name": name,
        "port": port,
        "status": "active",
    }
    mismatched_normalized_assignment = [
        f"{key}={normalized_assignment.get(key)!r} (expected {expected!r})"
        for key, expected in expected_normalized_assignment.items()
        if normalized_assignment.get(key) != expected
    ]
    if mismatched_normalized_assignment:
        reject(
            "normalized assignment mismatch: "
            + ", ".join(mismatched_normalized_assignment)
        )
    normalized_assignment_id = normalized_assignment.get("assignment_id")
    if (
        not isinstance(normalized_assignment_id, str)
        or not normalized_assignment_id
        or assignment.get("id") != normalized_assignment_id
        or assignment.get("status") != "active"
    ):
        reject(
            "compatibility assignment is not the exact active normalized assignment"
        )

    all_normalized_leases = rows(raw, "leases", "inventory")
    relevant_normalized_leases = [
        row for row in all_normalized_leases
        if _integer(row.get("port")) == port
        or row.get("server_definition_id") == server_id
    ]
    compatibility = raw.get("v1_compatibility")
    all_compatibility_leases = rows(
        compatibility,
        "leases",
        "inventory.v1_compatibility",
    )
    relevant_compatibility_leases = [
        row for row in all_compatibility_leases
        if _integer(row.get("port")) == port
        or row.get("server_id") == server_id
        or row.get("assignment_key") == f"{project}::{name}"
    ]
    active_normalized_leases = [
        row for row in relevant_normalized_leases if row.get("status") == "active"
    ]
    active_compatibility_leases = [
        row for row in relevant_compatibility_leases if row.get("status") == "active"
    ]
    active_registration_lease_id: str | None = None
    if active_normalized_leases or active_compatibility_leases:
        if (
            len(active_normalized_leases) != 1
            or len(active_compatibility_leases) != 1
            or len(relevant_compatibility_leases) != 1
        ):
            reject("active lease mapping is missing or ambiguous")
        normalized_lease = active_normalized_leases[0]
        compatibility_lease = active_compatibility_leases[0]
        lease_id = normalized_lease.get("lease_id")
        fingerprint = normalized_lease.get("process_fingerprint")
        owner = normalized_lease.get("owner")
        agent = normalized_lease.get("agent")
        created_at_epoch = _timestamp_epoch(normalized_lease.get("created_at"))
        updated_at_epoch = _timestamp_epoch(normalized_lease.get("updated_at"))
        expires_at_epoch = _timestamp_epoch(normalized_lease.get("expires_at"))
        if (
            _integer(main_uid) is None
            or main_uid < 0
            or not isinstance(main_account_id, str)
            or not main_account_id
            or not isinstance(main_start_ticks, str)
            or not main_start_ticks.isdigit()
            or not isinstance(main_cwd, str)
            or not (
                main_cwd == project
                or main_cwd.startswith(project.rstrip("/") + "/")
            )
            or not isinstance(observed_at_epoch, (int, float))
            or isinstance(observed_at_epoch, bool)
            or not math.isfinite(float(observed_at_epoch))
        ):
            reject("stable systemd MainPID identity is incomplete")
        expected_fingerprint = _broker_listener_fingerprint(
            main_pid=main_pid,
            main_uid=main_uid,
            main_start_ticks=main_start_ticks,
            main_cwd=main_cwd,
            project=project,
            port=port,
        )
        observed_at = float(observed_at_epoch)
        if (
            not isinstance(lease_id, str)
            or not lease_id
            or normalized_lease.get("repo_id") != repo_id
            or normalized_lease.get("server_definition_id") != server_id
            or _integer(normalized_lease.get("port")) != port
            or normalized_lease.get("purpose") != "broker"
            or normalized_lease.get("status") != "active"
            or normalized_lease.get("deactivated_at") is not None
            or owner != f"uid:{main_uid}"
            or agent != main_account_id
            or fingerprint != expected_fingerprint
            or created_at_epoch is None
            or updated_at_epoch is None
            or expires_at_epoch is None
            or created_at_epoch > updated_at_epoch
            or updated_at_epoch > observed_at + TIMESTAMP_FUTURE_SKEW_SECONDS
            or observed_at - updated_at_epoch > IN_FLIGHT_LEASE_FRESHNESS_SECONDS
            or expires_at_epoch <= observed_at
            or expires_at_epoch <= updated_at_epoch
            or expires_at_epoch - updated_at_epoch > MAX_BROKER_LEASE_TTL_SECONDS
        ):
            reject("active lease is not the exact broker registration reservation")
        expected_compatibility_lease = {
            "id": lease_id,
            "project": project,
            "port": port,
            "owner": owner,
            "agent": agent,
            "purpose": "broker",
            "status": "active",
            "expires_at": normalized_lease.get("expires_at"),
            "process_fingerprint": fingerprint,
            "deactivated_at": None,
            "created_at": normalized_lease.get("created_at"),
            "updated_at": normalized_lease.get("updated_at"),
            "server_id": server_id,
            "owner_pid": None,
            "assignment_key": f"{project}::{name}",
        }
        mismatched_compatibility_lease = [
            f"{key}={compatibility_lease.get(key)!r} (expected {expected!r})"
            for key, expected in expected_compatibility_lease.items()
            if compatibility_lease.get(key) != expected
        ]
        if mismatched_compatibility_lease:
            reject(
                "active lease compatibility mapping mismatch: "
                + ", ".join(mismatched_compatibility_lease)
            )
        reused_by = server.get("port_reused_by")
        if (
            server.get("lease_id") != lease_id
            or server.get("port_reused") is not True
            or server.get("url_is_current") is not False
            or not isinstance(reused_by, dict)
            or reused_by.get("type") != "process"
            or _integer(reused_by.get("pid")) != main_pid
            or reused_by.get("project") != project
            or not isinstance(reused_by.get("cwd"), str)
            or not (
                reused_by["cwd"] == project
                or reused_by["cwd"].startswith(project.rstrip("/") + "/")
            )
        ):
            reject("active lease lacks the exact current systemd MainPID listener claim")
        active_registration_lease_id = lease_id

    target_normalized_leases = [
        row for row in all_normalized_leases
        if row.get("server_definition_id") == server_id
    ]
    lease_id = server.get("lease_id")
    if active_registration_lease_id is not None:
        if lease_id != active_registration_lease_id:
            reject("compatibility server does not reference the active broker lease")
    elif lease_id is None:
        if target_normalized_leases:
            reject("pruned compatibility lease conflicts with retained normalized history")
    else:
        exact = [row for row in target_normalized_leases if row.get("lease_id") == lease_id]
        if len(exact) != 1:
            reject("released compatibility lease is missing or ambiguous")
        lease = exact[0]
        if (
            lease.get("repo_id") != repo_id
            or lease.get("server_definition_id") != server_id
            or _integer(lease.get("port")) != port
            or lease.get("status") not in {"released", "stale_released"}
            or not isinstance(lease.get("deactivated_at"), str)
            or not lease.get("deactivated_at")
        ):
            reject("normalized lease is not the exact inactive broker lease")

    health = server.get("health")
    if (
        server.get("metadata_source") != "normalized-sqlite"
        or server.get("identity_observable") is not True
        or server.get("process_start_time") is not None
        or server.get("process_fingerprint") is not None
        or server.get("stopped_at") != observation.get("stopped_at")
        or server.get("stopped_reason") != observation.get("stopped_reason")
        or server.get("url_is_current") is not False
        or "registration_identity" in server
        or not isinstance(health, dict)
        or health.get("classification") != observation.get("health_classification")
        or health.get("ok") is not False
        or health.get("pid_alive") is not None
    ):
        reject("compatibility stopped row is not exact")
    return active_registration_lease_id


def classify_registration_snapshot(
    inventory: dict[str, Any],
    *,
    project: str,
    name: str,
    port: int,
    main_pid: int,
    main_uid: int | None = None,
    main_account_id: str | None = None,
    main_start_ticks: str | None = None,
    main_cwd: str | None = None,
    observed_at_epoch: float | None = None,
) -> tuple[str, dict[str, Any]]:
    """Return ``ready`` or an exact retryable baseline; reject everything else."""

    raw_inventory = inventory
    try:
        inventory = current_registration_inventory_view(inventory)
    except RegistrationGraphError as error:
        raise ConsoleRegistrationError(str(error)) from error

    try:
        report = verify_current_registration_graph(
            inventory,
            project=project,
            name=name,
            port=port,
            main_pid=main_pid,
        )
    except RegistrationGraphError:
        pass
    else:
        return "ready", report

    assignments = _rows(inventory, "port_assignments")
    servers = _rows(inventory, "servers")
    leases = _rows(inventory, "leases")
    expected_key = f"{project}::{name}"
    relevant_assignments = [
        row
        for row in assignments
        if _integer(row.get("port")) == port
        or (row.get("project") == project and row.get("name") == name)
    ]
    target_servers = [
        row
        for row in servers
        if row.get("project") == project and row.get("name") == name
    ]
    current_port_servers = [
        row
        for row in servers
        if _integer(row.get("port")) == port and row.get("status") != "stopped"
    ]
    active_port_leases = [
        row for row in leases if _integer(row.get("port")) == port and row.get("status") == "active"
    ]
    active_target_leases = [
        row
        for row in leases
        if row.get("status") == "active"
        and row.get("project") == project
        and row.get("purpose") == f"server:{name}"
    ]
    active_claim_present = bool(active_port_leases or active_target_leases)

    if current_port_servers:
        if len(current_port_servers) != 1 or len(target_servers) != 1:
            raise ConsoleRegistrationError(
                "unsafe registration baseline: a non-stopped server claims the Console port "
                f"(current_port_count={len(current_port_servers)}, "
                f"target_count={len(target_servers)}, "
                f"current_statuses={[row.get('status') for row in current_port_servers]!r})"
            )
        current = current_port_servers[0]
        if target_servers[0] is not current:
            raise ConsoleRegistrationError(
                "unsafe current MainPID proof: target and port server rows differ"
            )
        if current.get("status") != "running":
            raise ConsoleRegistrationError(
                "unsafe registration baseline: a non-stopped server claims the Console port "
                f"(status={current.get('status')!r}, pid={current.get('pid')!r})"
            )
        for key, expected in {
            "key": expected_key,
            "project": project,
            "name": name,
            "host": "127.0.0.1",
            "port": port,
            "pid": main_pid,
            "status": "running",
        }.items():
            if current.get(key) != expected:
                raise ConsoleRegistrationError(
                    "unsafe current MainPID proof: "
                    f"server {key} is {current.get(key)!r}, expected {expected!r}"
                )
        cwd = current.get("cwd")
        if not isinstance(cwd, str) or not (
            cwd == project or cwd.startswith(project.rstrip("/") + "/")
        ):
            raise ConsoleRegistrationError(
                "unsafe current MainPID proof: server cwd is outside project"
            )
        if "registration_identity" in current:
            raise ConsoleRegistrationError(
                "unsafe current MainPID proof: incomplete registration identity is present"
            )
        health = current.get("health")
        if not isinstance(health, dict):
            raise ConsoleRegistrationError(
                "unsafe current MainPID proof: server health is missing"
            )
        identity = health.get("identity")
        if isinstance(identity, dict) and identity.get("ok") is False:
            raise ConsoleRegistrationError(
                "unsafe current MainPID proof: fresh observation proved a wrong listener"
            )
        if (
            health.get("ok") is not None
            or health.get("pid_alive") is not True
            or health.get("classification") != "unverified-listener"
            or not isinstance(identity, dict)
            or identity.get("ok") is not None
            or identity.get("observable") is not False
            or identity.get("pid") != main_pid
            or identity.get("project") != project
        ):
            raise ConsoleRegistrationError(
                "unsafe current MainPID proof: listener state is not explicitly unverified"
            )
        identity_cwd = identity.get("cwd")
        if not isinstance(identity_cwd, str) or not (
            identity_cwd == project
            or identity_cwd.startswith(project.rstrip("/") + "/")
        ):
            raise ConsoleRegistrationError(
                "unsafe current MainPID proof: identity cwd is outside project"
            )
        if len(relevant_assignments) != 1:
            raise ConsoleRegistrationError(
                "unsafe current MainPID proof: durable assignment is missing or ambiguous"
            )
        assignment = relevant_assignments[0]
        for key, expected in {
            "key": expected_key,
            "project": project,
            "name": name,
            "port": port,
            "status": "active",
            "server_status": "running",
        }.items():
            if assignment.get(key) != expected:
                raise ConsoleRegistrationError(
                    "unsafe current MainPID proof: "
                    f"assignment {key} is {assignment.get(key)!r}, expected {expected!r}"
                )
        if len(active_port_leases) != 1 or len(active_target_leases) != 1:
            raise ConsoleRegistrationError(
                "unsafe current MainPID proof: active lease is missing or ambiguous"
            )
        lease = active_port_leases[0]
        if active_target_leases[0] is not lease:
            raise ConsoleRegistrationError(
                "unsafe current MainPID proof: target and port leases differ"
            )
        server_id = current.get("id")
        lease_id = lease.get("id")
        if not isinstance(server_id, str) or not server_id.strip():
            raise ConsoleRegistrationError(
                "unsafe current MainPID proof: server has no id"
            )
        if not isinstance(lease_id, str) or not lease_id.strip():
            raise ConsoleRegistrationError(
                "unsafe current MainPID proof: lease has no id"
            )
        for key, expected in {
            "project": project,
            "port": port,
            "status": "active",
            "purpose": f"server:{name}",
            "server_id": server_id,
            "owner_pid": main_pid,
            "assignment_key": expected_key,
        }.items():
            if lease.get(key) != expected:
                raise ConsoleRegistrationError(
                    "unsafe current MainPID proof: "
                    f"lease {key} is {lease.get(key)!r}, expected {expected!r}"
                )
        if current.get("lease_id") != lease_id:
            raise ConsoleRegistrationError(
                "unsafe current MainPID proof: server and lease identities differ"
            )
        return "pending-current-main-pid-proof", {
            "reason": "exact current systemd MainPID awaits fresh listener proof",
            "server_id": server_id,
            "lease_id": lease_id,
        }

    # Server-wide installation enrolls every declared server before it has
    # ever been observed.  The normalized broker projects that durable
    # definition without an assignment, PID, or current port.  Before opening
    # listeners, the Console then reserves its durable port through one linked
    # broker lease whose owner_pid remains null until registration.  These are
    # safe retry states because the surrounding readiness loop independently
    # pins the new systemd MainPID, argv, cwd, and cgroup on every observation.
    if not relevant_assignments and len(target_servers) == 1:
        enrolled = target_servers[0]
        if enrolled.get("status") == "unobserved":
            for key, expected in {
                "key": expected_key,
                "project": project,
                "name": name,
                "host": "127.0.0.1",
                "port": None,
                "pid": None,
                "process_start_time": None,
                "process_fingerprint": None,
                "status": "unobserved",
                "metadata_source": "normalized-sqlite",
                "identity_observable": None,
                "attribution": None,
                "url": None,
                "url_is_current": False,
                "stopped_at": None,
                "stopped_reason": None,
            }.items():
                if enrolled.get(key) != expected:
                    raise ConsoleRegistrationError(
                        "unsafe unobserved enrollment baseline: "
                        f"server {key} is {enrolled.get(key)!r}, expected {expected!r}"
                    )
            server_id = enrolled.get("id")
            if not isinstance(server_id, str) or not server_id.strip():
                raise ConsoleRegistrationError(
                    "unsafe unobserved enrollment baseline: server has no id"
                )
            cwd = enrolled.get("cwd")
            if not isinstance(cwd, str) or not (
                cwd == project or cwd.startswith(project.rstrip("/") + "/")
            ):
                raise ConsoleRegistrationError(
                    "unsafe unobserved enrollment baseline: server cwd is outside project"
                )
            if enrolled.get("argv") != [] or "registration_identity" in enrolled:
                raise ConsoleRegistrationError(
                    "unsafe unobserved enrollment baseline: process identity evidence is present"
                )
            health = enrolled.get("health")
            if not isinstance(health, dict) or any(
                health.get(key) != expected
                for key, expected in {
                    "classification": "unobserved",
                    "ok": None,
                    "pid_alive": None,
                }.items()
            ):
                raise ConsoleRegistrationError(
                    "unsafe unobserved enrollment baseline: health is not wholly unobserved"
                )
            if enrolled.get("port_reused") is True or enrolled.get("port_reused_by") is not None:
                raise ConsoleRegistrationError(
                    "unsafe unobserved enrollment baseline: a raw listener claim is present"
                )
            lease_id = enrolled.get("lease_id")
            if lease_id is not None and (
                not isinstance(lease_id, str) or not lease_id.strip()
            ):
                raise ConsoleRegistrationError(
                    "unsafe unobserved enrollment baseline: historical lease id is invalid"
                )
            referenced = [
                row
                for row in leases
                if lease_id is not None
                and (row.get("id") == lease_id or row.get("lease_id") == lease_id)
            ]
            if len(referenced) > 1:
                raise ConsoleRegistrationError(
                    "unsafe unobserved enrollment baseline: referenced lease is ambiguous"
                )
            if referenced:
                lease = referenced[0]
                for key, expected in {
                    "id": lease_id,
                    "status": "active",
                    "project": project,
                    "port": port,
                    "purpose": "broker",
                    "assignment_key": expected_key,
                    "server_id": server_id,
                    "owner_pid": None,
                    "deactivated_at": None,
                }.items():
                    if lease.get(key) != expected:
                        raise ConsoleRegistrationError(
                            "unsafe unobserved enrollment reservation: "
                            f"lease {key} is {lease.get(key)!r}, expected {expected!r}"
                        )
                owner = lease.get("owner")
                if not isinstance(owner, str) or not (
                    owner.startswith("uid:") and owner[4:].isdigit()
                ):
                    raise ConsoleRegistrationError(
                        "unsafe unobserved enrollment reservation: lease owner is invalid"
                    )
                agent = lease.get("agent")
                if not isinstance(agent, str) or not agent.strip():
                    raise ConsoleRegistrationError(
                        "unsafe unobserved enrollment reservation: lease agent is invalid"
                    )
                fingerprint = lease.get("process_fingerprint")
                if not isinstance(fingerprint, str) or not (
                    fingerprint.startswith("sha256:")
                    and len(fingerprint) == len("sha256:") + 64
                    and all(character in "0123456789abcdef" for character in fingerprint[7:])
                ):
                    raise ConsoleRegistrationError(
                        "unsafe unobserved enrollment reservation: lease fingerprint is invalid"
                    )
                if (
                    len(active_port_leases) != 1
                    or active_port_leases[0] is not lease
                    or active_target_leases
                ):
                    raise ConsoleRegistrationError(
                        "unsafe unobserved enrollment reservation: active lease ownership is ambiguous"
                    )
                return "pending-enrolled-reservation-baseline", {
                    "reason": "exact pre-listener broker reservation",
                    "server_id": server_id,
                    "active_reservation_lease_id": lease_id,
                    "inactive_lease_count": 0,
                    "active_stale_lease_count": 0,
                }
            if active_port_leases or active_target_leases:
                raise ConsoleRegistrationError(
                    "unsafe registration baseline: an active lease is not linked to enrollment"
                )
            return "pending-enrolled-unobserved-baseline", {
                "reason": "exact process-free server-wide enrollment baseline",
                "server_id": server_id,
                "inactive_lease_count": 0,
                "active_stale_lease_count": 0,
            }

    if not relevant_assignments and not target_servers:
        if active_claim_present:
            raise ConsoleRegistrationError(
                "unsafe registration baseline: an active lease still claims the Console port"
            )
        return "pending-clean-absence", {"reason": "registration graph is cleanly absent"}

    if len(relevant_assignments) != 1:
        raise ConsoleRegistrationError(
            f"unsafe registration baseline: expected one relevant assignment, found {len(relevant_assignments)}"
        )
    assignment = relevant_assignments[0]
    for key, expected in {
        "key": expected_key,
        "project": project,
        "name": name,
        "port": port,
    }.items():
        if assignment.get(key) != expected:
            raise ConsoleRegistrationError(
                f"unsafe registration baseline: assignment {key} is {assignment.get(key)!r}, expected {expected!r}"
            )
    expected_assignment_status = "stopped" if target_servers else "unregistered"
    if assignment.get("server_status") != expected_assignment_status:
        raise ConsoleRegistrationError(
            "unsafe registration baseline: assignment status is "
            f"{assignment.get('server_status')!r}, expected {expected_assignment_status!r}"
        )
    if not target_servers and active_claim_present:
        raise ConsoleRegistrationError(
            "unsafe registration baseline: an active lease still claims the Console port"
        )

    server: dict[str, Any] | None = None
    active_registration_lease_id: str | None = None
    if target_servers:
        if len(target_servers) != 1:
            raise ConsoleRegistrationError(
                f"unsafe registration baseline: expected at most one target server, found {len(target_servers)}"
            )
        server = target_servers[0]
        for key, expected in {
            "key": expected_key,
            "project": project,
            "name": name,
            "port": port,
            "status": "stopped",
        }.items():
            if server.get(key) != expected:
                raise ConsoleRegistrationError(
                    f"unsafe registration baseline: stopped server {key} is {server.get(key)!r}, expected {expected!r}"
                )
        server_id = server.get("id")
        if not isinstance(server_id, str) or not server_id.strip():
            raise ConsoleRegistrationError("unsafe registration baseline: stopped server has no id")
        reused_by = server.get("port_reused_by")
        if server.get("port_reused") is True or reused_by is not None:
            if (
                server.get("port_reused") is not True
                or server.get("url_is_current") is not False
                or not isinstance(reused_by, dict)
                or reused_by.get("type") != "process"
                or _integer(reused_by.get("pid")) != main_pid
                or reused_by.get("project") != project
                or not isinstance(reused_by.get("cwd"), str)
                or not (
                    reused_by["cwd"] == project
                    or reused_by["cwd"].startswith(project.rstrip("/") + "/")
                )
            ):
                raise ConsoleRegistrationError(
                    "unsafe registration baseline: raw port listener is not the systemd MainPID"
                )
        process_free = server.get("pid") is None
        relocated = process_free and server.get("lease_id") is None and server.get("metadata_source") == "port_relocate"
        if relocated:
            if active_claim_present:
                raise ConsoleRegistrationError(
                    "unsafe registration baseline: an active lease still claims the Console port"
                )
            if (
                "pid" not in server
                or "lease_id" not in server
                or server.get("metadata_source") != "port_relocate"
                or not isinstance(server.get("relocated_from"), str)
                or not server.get("relocated_from")
                or server.get("relocated_from") == project
                or not isinstance(server.get("relocated_at"), str)
                or not server.get("relocated_at")
                or server.get("stopped_reason")
                != "Checkout ownership relocated; awaiting exact listener registration"
            ):
                raise ConsoleRegistrationError(
                    "unsafe registration baseline: null PID/lease row is not exact relocation evidence"
                )
        elif process_free:
            active_registration_lease_id = _require_broker_stopped_baseline(
                raw_inventory,
                server=server,
                assignment=assignment,
                project=project,
                name=name,
                port=port,
                main_pid=main_pid,
                main_uid=main_uid,
                main_account_id=main_account_id,
                main_start_ticks=main_start_ticks,
                main_cwd=main_cwd,
                observed_at_epoch=observed_at_epoch,
            )
        else:
            if active_claim_present:
                raise ConsoleRegistrationError(
                    "unsafe registration baseline: an active lease still claims the Console port"
                )
            health = server.get("health")
            if (
                not isinstance(health, dict)
                or health.get("pid_alive") is not False
                or health.get("classification")
                not in {"stopped", "unhealthy_process", "crashed_process", "stale_coordinator_metadata"}
            ):
                raise ConsoleRegistrationError(
                    "unsafe registration baseline: stopped server is not proven process-dead"
                )
            recorded_pid = _integer(server.get("pid"))
            if recorded_pid is None or recorded_pid <= 1:
                raise ConsoleRegistrationError(
                    "unsafe registration baseline: stopped server PID history is invalid"
                )
            if recorded_pid == main_pid:
                raise ConsoleRegistrationError(
                    "unsafe registration baseline: systemd MainPID is still recorded as stopped"
                )
    else:
        server_id = None

    referenced: list[dict[str, Any]] = []
    if (
        server is not None
        and server.get("lease_id") is not None
        and active_registration_lease_id is None
    ):
        referenced = [row for row in leases if row.get("id") == server.get("lease_id")]
        if len(referenced) > 1:
            raise ConsoleRegistrationError(
                "unsafe registration baseline: stopped server lease reference is ambiguous"
            )
        # Stale-lease pruning removes the inactive row while intentionally
        # retaining server.lease_id as historical evidence. A missing row is
        # therefore the normal observed restart baseline, not an unproved
        # active claim. If retained history exists, it must link exactly.
        if referenced:
            lease = referenced[0]
            if lease.get("status") not in {"released", "stale_released"}:
                raise ConsoleRegistrationError(
                    "unsafe registration baseline: stopped server references a current lease"
                )
            for key, expected in {
                "project": project,
                "port": port,
                "purpose": f"server:{name}",
                "assignment_key": expected_key,
                "server_id": server_id,
            }.items():
                if lease.get(key) != expected:
                    raise ConsoleRegistrationError(
                        f"unsafe registration baseline: referenced lease {key} is {lease.get(key)!r}, expected {expected!r}"
                    )

    report = {
        "reason": "exact relocated or stale stopped registration baseline",
        "server_id": server_id,
        "inactive_lease_count": len(referenced),
        "active_stale_lease_count": 0,
    }
    if active_registration_lease_id is not None:
        report.update(
            {
                "reason": "exact in-flight broker registration reservation",
                "active_registration_lease_id": active_registration_lease_id,
            }
        )
    return "pending-stopped-baseline", report


def systemd_unit_probe(unit: str, *, systemctl: str, timeout: float) -> dict[str, Any]:
    completed = subprocess.run(
        [
            systemctl,
            "show",
            "--no-pager",
            "--property=ActiveState",
            "--property=MainPID",
            "--property=ControlGroup",
            unit,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=max(0.1, min(timeout, 3.0)),
    )
    if completed.returncode != 0:
        raise ConsoleRegistrationError(
            f"cannot observe Console systemd identity: {completed.stderr.strip() or completed.returncode}"
        )
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    try:
        main_pid = int(values["MainPID"])
        active_state = values["ActiveState"]
        cgroup = values["ControlGroup"]
    except (KeyError, ValueError) as error:
        raise ConsoleRegistrationError("Console systemd identity output is incomplete") from error
    return {"main_pid": main_pid, "active_state": active_state, "cgroup": cgroup}


def _process_cgroups(path: Path) -> set[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ConsoleRegistrationError(f"cannot observe Console process cgroup: {error}") from error
    result = {line.split(":", 2)[2] for line in lines if line.count(":") >= 2}
    if not result:
        raise ConsoleRegistrationError("Console process cgroup membership is empty")
    return result


def _process_uid(path: Path) -> int:
    try:
        uid_rows = [
            line.split()[1:]
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.startswith("Uid:")
        ]
    except OSError as error:
        raise ConsoleRegistrationError(
            f"cannot observe Console process UID: {error}"
        ) from error
    if (
        len(uid_rows) != 1
        or len(uid_rows[0]) != 4
        or any(not value.isdigit() for value in uid_rows[0])
    ):
        raise ConsoleRegistrationError("Console process UID evidence is malformed")
    values = {int(value) for value in uid_rows[0]}
    if len(values) != 1:
        raise ConsoleRegistrationError(
            "Console process real/effective/saved/filesystem UIDs differ"
        )
    return values.pop()


def process_identity_probe(pid: int, *, proc_root: Path = Path("/proc")) -> dict[str, Any]:
    process = proc_root / str(pid)
    try:
        start_ticks, argv = read_stable_process_identity(process)
    except (OSError, ProcIdentityError) as error:
        raise ConsoleRegistrationError(f"cannot observe Console process identity: {error}") from error
    if not argv:
        raise ConsoleRegistrationError("Console process argv is empty")
    try:
        cwd = os.readlink(process / "cwd")
    except OSError as error:
        raise ConsoleRegistrationError(f"cannot observe Console process cwd: {error}") from error
    uid = _process_uid(process / "status")
    try:
        proc_owner_uid = int(os.stat(process, follow_symlinks=False).st_uid)
    except OSError as error:
        raise ConsoleRegistrationError(
            f"cannot observe Console process directory owner: {error}"
        ) from error
    if proc_owner_uid != uid:
        raise ConsoleRegistrationError(
            "Console process directory owner differs from its stable UID evidence"
        )
    cgroups = _process_cgroups(process / "cgroup")
    try:
        final_start_ticks = parse_start_ticks(
            (process / "stat").read_text(encoding="utf-8")
        )
    except (OSError, ProcIdentityError) as error:
        raise ConsoleRegistrationError(
            f"cannot revalidate Console process identity: {error}"
        ) from error
    if final_start_ticks != start_ticks:
        raise ConsoleRegistrationError(
            "Console process identity changed while reading UID/cwd/cgroup evidence"
        )
    return {
        "start_ticks": start_ticks,
        "uid": uid,
        "argv": argv,
        "cwd": cwd,
        "cgroups": cgroups,
    }


def inventory_probe(
    *,
    host: str,
    port: int,
    token: str,
    timeout: float,
    project: str,
    name: str,
    server_port: int,
) -> dict[str, Any]:
    connection = http.client.HTTPConnection(host, port, timeout=max(0.1, min(timeout, 3.0)))
    try:
        query = urlencode(
            {
                "project": project,
                "name": name,
                "port": int(server_port),
            }
        )
        connection.request(
            "GET",
            f"/v1/inventory/no-docker?{query}",
            headers={"Authorization": f"Bearer {token}", "Host": f"{host}:{port}"},
        )
        response = connection.getresponse()
        content_type = (response.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
        body = response.read(8 * 1024 * 1024 + 1)
    except http.client.RemoteDisconnected as error:
        raise InventoryTransportPending(
            "authenticated no-Docker inventory transport closed during startup"
        ) from error
    except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError, TimeoutError) as error:
        raise InventoryTransportPending(
            f"authenticated no-Docker inventory transport is starting: {type(error).__name__}"
        ) from error
    except OSError as error:
        if error.errno in {errno.ECONNREFUSED, errno.ECONNRESET, errno.ECONNABORTED, errno.ETIMEDOUT}:
            raise InventoryTransportPending(
                f"authenticated no-Docker inventory transport is starting: {type(error).__name__}"
            ) from error
        raise ConsoleRegistrationError(
            f"authenticated no-Docker inventory transport failed unsafely: {type(error).__name__}"
        ) from error
    except http.client.HTTPException as error:
        raise ConsoleRegistrationError(
            f"authenticated no-Docker inventory protocol failed: {type(error).__name__}"
        ) from error
    finally:
        connection.close()
    if response.status != 200:
        raise ConsoleRegistrationError(
            f"authenticated no-Docker inventory returned HTTP {response.status}"
        )
    if content_type != "application/json" or len(body) > 8 * 1024 * 1024:
        raise ConsoleRegistrationError("authenticated no-Docker inventory response is invalid")
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConsoleRegistrationError(f"authenticated no-Docker inventory JSON is invalid: {error}") from error
    if not isinstance(value, dict):
        raise ConsoleRegistrationError("authenticated no-Docker inventory root is not an object")
    try:
        projected = current_registration_inventory_view(value)
    except RegistrationGraphError as error:
        raise ConsoleRegistrationError(str(error)) from error
    docker = projected.get("docker")
    if docker != {"available": None, "containers": [], "postgres": []}:
        raise ConsoleRegistrationError("inventory endpoint did not prove the no-Docker contract")
    # Keep the authoritative schema-v2 envelope intact. The classifier needs
    # both its normalized rows and its explicit v1 compatibility projection;
    # returning only the projected aliases while retaining schema_version=2
    # makes compatibility assignments masquerade as normalized assignments.
    return value


def _require_unit(state: dict[str, Any], *, main_pid: int, cgroup: str | None = None) -> str:
    if state.get("active_state") not in {"activating", "active"}:
        raise ConsoleRegistrationError(
            f"Console unit left startup state: {state.get('active_state')!r}"
        )
    if state.get("main_pid") != main_pid:
        raise ConsoleRegistrationError(
            f"Console systemd MainPID changed: {state.get('main_pid')!r} != {main_pid}"
        )
    observed = state.get("cgroup")
    if not isinstance(observed, str) or not observed.startswith("/"):
        raise ConsoleRegistrationError("Console systemd cgroup is invalid")
    if cgroup is not None and observed != cgroup:
        raise ConsoleRegistrationError("Console systemd cgroup changed during readiness")
    return observed


def _require_process(
    identity: dict[str, Any],
    *,
    baseline: dict[str, Any],
    cgroup: str,
    expected_argv: list[str],
    expected_working_directory: str,
) -> None:
    uid = _integer(identity.get("uid"))
    if uid is None or uid < 0:
        raise ConsoleRegistrationError("Console MainPID UID is invalid")
    if identity.get("uid") != baseline.get("uid"):
        raise ConsoleRegistrationError("Console process UID changed during readiness")
    if identity.get("start_ticks") != baseline.get("start_ticks"):
        raise ConsoleRegistrationError("Console process start identity changed during readiness")
    if identity.get("argv") != baseline.get("argv"):
        raise ConsoleRegistrationError("Console process argv changed during readiness")
    if identity.get("argv") != expected_argv:
        raise ConsoleRegistrationError("Console MainPID argv does not match the production contract")
    if identity.get("cwd") != expected_working_directory:
        raise ConsoleRegistrationError("Console MainPID cwd does not match the production contract")
    if cgroup not in identity.get("cgroups", set()):
        raise ConsoleRegistrationError("Console MainPID is outside its systemd cgroup")


def _require_account(
    probe: Callable[[int], str],
    *,
    uid: int,
    baseline: str | None = None,
) -> str:
    try:
        observed = probe(uid)
    except ConsoleRegistrationError:
        raise
    except BaseException as error:
        raise ConsoleRegistrationError(
            f"cannot resolve Console MainPID broker account: {type(error).__name__}"
        ) from error
    if (
        not isinstance(observed, str)
        or not observed
        or any(character not in BROKER_IDENTIFIER_CHARS for character in observed)
    ):
        raise ConsoleRegistrationError("Console MainPID broker account is invalid")
    if baseline is not None and observed != baseline:
        raise ConsoleRegistrationError(
            "Console MainPID broker account mapping changed during readiness"
        )
    return observed


def wait_for_console_registration(
    *,
    unit: str,
    main_pid: int,
    project: str,
    name: str,
    port: int,
    token: str,
    host: str,
    coordinator_port: int,
    expected_argv: list[str],
    expected_working_directory: str,
    wait_seconds: float,
    poll_interval_seconds: float,
    systemctl: str = "/usr/bin/systemctl",
    proc_root: Path = Path("/proc"),
    unit_probe_fn: Callable[[], dict[str, Any]] | None = None,
    process_probe_fn: Callable[[], dict[str, Any]] | None = None,
    inventory_probe_fn: Callable[[float], dict[str, Any]] | None = None,
    account_probe_fn: Callable[[int], str] | None = None,
    clock: Callable[[], float] = time.monotonic,
    wall_clock: Callable[[], float] = time.time,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    if main_pid <= 1:
        raise ConsoleRegistrationError("--main-pid must be greater than one")
    if not (0 < wait_seconds <= 120) or not (0 < poll_interval_seconds <= 1):
        raise ConsoleRegistrationError("readiness wait/poll bounds are invalid")
    deadline = clock() + wait_seconds
    unit_probe_fn = unit_probe_fn or (
        lambda: systemd_unit_probe(
            unit, systemctl=systemctl, timeout=max(0.1, deadline - clock())
        )
    )
    process_probe_fn = process_probe_fn or (
        lambda: process_identity_probe(main_pid, proc_root=proc_root)
    )
    inventory_probe_fn = inventory_probe_fn or (
        lambda remaining: inventory_probe(
            host=host,
            port=coordinator_port,
            token=token,
            timeout=remaining,
            project=project,
            name=name,
            server_port=port,
        )
    )
    account_probe_fn = account_probe_fn or console_account_identity
    first_unit = unit_probe_fn()
    cgroup = _require_unit(first_unit, main_pid=main_pid)
    baseline = process_probe_fn()
    _require_process(
        baseline,
        baseline=baseline,
        cgroup=cgroup,
        expected_argv=expected_argv,
        expected_working_directory=expected_working_directory,
    )
    main_uid = _integer(baseline.get("uid"))
    if main_uid is None or main_uid < 0:
        raise ConsoleRegistrationError("Console MainPID UID is invalid")
    main_account_id = _require_account(account_probe_fn, uid=main_uid)
    last_pending = "none"
    attempts = 0
    while True:
        remaining = deadline - clock()
        if remaining <= 0:
            raise ConsoleRegistrationTimeout(
                f"Console registration did not converge before deadline; last state={last_pending}"
            )
        attempts += 1
        _require_unit(unit_probe_fn(), main_pid=main_pid, cgroup=cgroup)
        _require_process(
            process_probe_fn(),
            baseline=baseline,
            cgroup=cgroup,
            expected_argv=expected_argv,
            expected_working_directory=expected_working_directory,
        )
        _require_account(
            account_probe_fn,
            uid=main_uid,
            baseline=main_account_id,
        )
        try:
            snapshot = inventory_probe_fn(remaining)
        except InventoryTransportPending:
            _require_unit(unit_probe_fn(), main_pid=main_pid, cgroup=cgroup)
            _require_process(
                process_probe_fn(),
                baseline=baseline,
                cgroup=cgroup,
                expected_argv=expected_argv,
                expected_working_directory=expected_working_directory,
            )
            _require_account(
                account_probe_fn,
                uid=main_uid,
                baseline=main_account_id,
            )
            last_pending = "pending-api-transport"
            remaining = deadline - clock()
            if remaining > 0:
                sleeper(min(poll_interval_seconds, remaining))
            continue
        _require_unit(unit_probe_fn(), main_pid=main_pid, cgroup=cgroup)
        _require_process(
            process_probe_fn(),
            baseline=baseline,
            cgroup=cgroup,
            expected_argv=expected_argv,
            expected_working_directory=expected_working_directory,
        )
        _require_account(
            account_probe_fn,
            uid=main_uid,
            baseline=main_account_id,
        )
        if clock() >= deadline:
            raise ConsoleRegistrationTimeout(
                "Console registration observation crossed the readiness deadline"
            )
        state, report = classify_registration_snapshot(
            snapshot,
            project=project,
            name=name,
            port=port,
            main_pid=main_pid,
            main_uid=main_uid,
            main_account_id=main_account_id,
            main_start_ticks=str(baseline["start_ticks"]),
            main_cwd=str(baseline["cwd"]),
            observed_at_epoch=wall_clock(),
        )
        if state == "ready":
            return {**report, "attempts": attempts, "unit": unit}
        last_pending = state
        remaining = deadline - clock()
        if remaining <= 0:
            continue
        sleeper(min(poll_interval_seconds, remaining))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--main-pid", required=True, type=int)
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--project", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--coordinator-port", default=29876, type=int)
    parser.add_argument("--expected-executable", required=True)
    parser.add_argument("--expected-script", required=True)
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--expected-working-directory", required=True)
    parser.add_argument("--wait-seconds", default=80.0, type=float)
    parser.add_argument("--poll-interval-seconds", default=0.1, type=float)
    parser.add_argument("--systemctl", default="/usr/bin/systemctl")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.host != "127.0.0.1":
            raise ConsoleRegistrationError("coordinator host must be exact IPv4 loopback")
        token = read_private_regular(args.token_file, label="coordinator token").decode("utf-8").strip()
        if len(token) < 32 or any(character.isspace() for character in token):
            raise ConsoleRegistrationError("coordinator token is invalid")
        report = wait_for_console_registration(
            unit=args.unit,
            main_pid=args.main_pid,
            project=args.project,
            name=args.name,
            port=args.port,
            token=token,
            host=args.host,
            coordinator_port=args.coordinator_port,
            expected_argv=[
                args.expected_executable,
                args.expected_script,
                "--env-file",
                args.env_file,
            ],
            expected_working_directory=args.expected_working_directory,
            wait_seconds=args.wait_seconds,
            poll_interval_seconds=args.poll_interval_seconds,
            systemctl=args.systemctl,
        )
    except (ConsoleRegistrationError, SecureIOError, UnicodeDecodeError) as error:
        print(f"Console registration readiness failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
