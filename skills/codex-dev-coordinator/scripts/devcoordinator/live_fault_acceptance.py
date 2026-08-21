"""Sealed live fault/load isolation acceptance for one immutable release.

The acceptance plane deliberately reuses the broker-owned universal-test
transient launcher.  Repository-controlled commands, shell wrappers, Docker
operations, and direct service lifecycle calls are not part of this module.
Each fixed scenario is generation-fenced, TTL bounded, and
collected before a root-private attestation can be published.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from typing import Any, Callable, Mapping, Protocol, runtime_checkable
import uuid

from .universal_test_runtime import (
    BrokerTestAttemptCoordinator,
    NativeTestAttemptManager,
    NativeTestAttemptState,
    SystemdTestAttemptManager,
    TestAttemptDescriptor,
)
from .universal_test_store import TestStoreContractError
from .worker_native import project_repository_slice


REQUEST_KIND = "devcoordinator-live-fault-isolation-request"
ATTESTATION_KIND = "devcoordinator-live-fault-isolation-attestation"
CONTRACT_VERSION = 2
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_ATTESTATION_AGE_SECONDS = 15 * 60
SCENARIO_IDS = (
    "bounded_fork_pressure",
    "cgroup_oom",
    "crash_loop_breaker",
    "malformed_runner_output",
    "slow_project_upstream",
    "bounded_request_burst",
)
CONTROL_CGROUP_NAMES = frozenset(
    {
        "edge",
        "api",
        "authority",
        "console",
        "console-standby",
    }
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")

# Fixed values make different cutovers comparable and prevent a request from
# weakening the fault while claiming to have exercised the same scenario.
SCENARIO_POLICIES: Mapping[str, Mapping[str, object]] = {
    "bounded_fork_pressure": {
        "unit_scope": "test",
        "ttl_seconds": 20,
        "expected_terminal": "success",
    },
    "cgroup_oom": {
        "unit_scope": "test",
        "ttl_seconds": 20,
        "expected_terminal": "oom_kill",
    },
    "crash_loop_breaker": {
        "unit_scope": "test",
        "ttl_seconds": 20,
        "expected_terminal": "success",
    },
    "malformed_runner_output": {
        "unit_scope": "test",
        "ttl_seconds": 20,
        "expected_terminal": "incomplete_reporting",
    },
    "slow_project_upstream": {
        "unit_scope": "project",
        "ttl_seconds": 20,
        "expected_terminal": "success",
    },
    "bounded_request_burst": {
        "unit_scope": "test",
        "ttl_seconds": 20,
        "expected_terminal": "success",
    },
}


class FaultAcceptanceError(RuntimeError):
    """Fail-closed fault acceptance contract error."""

    def __init__(self, message: str, *, code: str = "fault_acceptance_failed"):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise FaultAcceptanceError("fault acceptance evidence is not bounded JSON") from error
    if len(payload) > MAX_DOCUMENT_BYTES:
        raise FaultAcceptanceError("fault acceptance evidence exceeds its byte bound")
    return payload


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _seal(kind: str, values: Mapping[str, object]) -> dict[str, object]:
    document = {
        "schema_version": CONTRACT_VERSION,
        "kind": kind,
        **dict(values),
    }
    document["document_sha256"] = _sha256(document)
    return document


def _verify_seal(
    value: object, *, kind: str, fields: set[str]
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise FaultAcceptanceError("fault acceptance document must be an object")
    document = dict(value)
    expected = {"schema_version", "kind", "document_sha256", *fields}
    if set(document) != expected:
        raise FaultAcceptanceError("fault acceptance document fields are invalid")
    supplied = document.pop("document_sha256")
    if (
        document.get("schema_version") != CONTRACT_VERSION
        or document.get("kind") != kind
        or not isinstance(supplied, str)
        or _SHA256.fullmatch(supplied) is None
        or _sha256(document) != supplied
    ):
        raise FaultAcceptanceError("fault acceptance document seal is invalid")
    return {**document, "document_sha256": supplied}


def _timestamp(value: datetime | None = None) -> str:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise FaultAcceptanceError("fault acceptance timestamp must be timezone-aware")
    return current.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not 20 <= len(value) <= 40:
        raise FaultAcceptanceError(f"{field} timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise FaultAcceptanceError(f"{field} timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise FaultAcceptanceError(f"{field} timestamp lacks a timezone")
    return parsed.astimezone(timezone.utc)


def _uuid(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise FaultAcceptanceError(f"{field} must be a canonical UUID")
    try:
        parsed = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError) as error:
        raise FaultAcceptanceError(f"{field} must be a canonical UUID") from error
    if parsed != value:
        raise FaultAcceptanceError(f"{field} must be a canonical UUID")
    return value


def _safe_id(value: object, field: str) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise FaultAcceptanceError(f"{field} is invalid")
    return value


def _absolute(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise FaultAcceptanceError(f"{field} must be an absolute path")
    path = Path(value)
    if not path.is_absolute() or str(path) != (value.rstrip("/") or "/"):
        raise FaultAcceptanceError(f"{field} must be one normalized absolute path")
    if any(part in {".", ".."} for part in path.parts):
        raise FaultAcceptanceError(f"{field} must be one normalized absolute path")
    return value


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise FaultAcceptanceError(f"{field} digest is invalid")
    return value


def _https_url(value: object, field: str, *, websocket: bool = False) -> str:
    from urllib.parse import urlparse

    if not isinstance(value, str) or len(value) > 4096:
        raise FaultAcceptanceError(f"{field} URL is invalid")
    parsed = urlparse(value)
    expected = "wss" if websocket else "https"
    if (
        parsed.scheme != expected
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise FaultAcceptanceError(f"{field} must be one {expected.upper()} URL")
    return value


REQUEST_FIELDS = {
    "operation_id",
    "cutover",
    "release",
    "authority",
    "repository",
    "inventory",
    "control_cgroups",
    "probe_targets",
    "scenarios",
    "created_at",
    "valid_until",
}


def build_request(
    *,
    operation_id: str,
    cutover: Mapping[str, object],
    release: Mapping[str, object],
    authority: Mapping[str, object],
    repository: Mapping[str, object],
    inventory: Mapping[str, object],
    control_cgroups: Mapping[str, object],
    probe_targets: Mapping[str, object],
    created_at: datetime | None = None,
) -> dict[str, object]:
    """Build the fixed fault campaign from trusted, already-resolved bindings."""

    _uuid(operation_id, "operation_id")
    generation = repository.get("generation")
    repository_id = repository.get("repository_id")
    if type(generation) is not int or generation < 1:
        raise FaultAcceptanceError("repository.generation is invalid")
    _safe_id(repository_id, "repository.repository_id")
    namespace = uuid.UUID(operation_id)
    scenarios: list[dict[str, object]] = []
    for scenario_id in SCENARIO_IDS:
        policy = SCENARIO_POLICIES[scenario_id]
        identity_digest = hashlib.sha256(
            f"{repository_id}\0{generation}\0{scenario_id}".encode("utf-8")
        ).hexdigest()[:24]
        scenarios.append(
            {
                "scenario_id": scenario_id,
                "resource_id": f"fault-{identity_digest}",
                "resource_generation": generation,
                "operation_id": str(
                    uuid.uuid5(namespace, f"live-fault:{scenario_id}")
                ),
                "unit_scope": policy["unit_scope"],
                "ttl_seconds": policy["ttl_seconds"],
                "kill_after_run": True,
                "expected_terminal": policy["expected_terminal"],
            }
        )
    created = (created_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    document = _seal(
        REQUEST_KIND,
        {
            "operation_id": operation_id,
            "cutover": dict(cutover),
            "release": dict(release),
            "authority": dict(authority),
            "repository": dict(repository),
            "inventory": dict(inventory),
            "control_cgroups": dict(control_cgroups),
            "probe_targets": {
                str(key): list(value) if isinstance(value, list) else value
                for key, value in probe_targets.items()
            },
            "scenarios": scenarios,
            "created_at": _timestamp(created),
            "valid_until": _timestamp(created + timedelta(minutes=15)),
        },
    )
    return validate_request(document, now=created)


def validate_request(value: object, *, now: datetime | None = None) -> dict[str, object]:
    document = _verify_seal(value, kind=REQUEST_KIND, fields=REQUEST_FIELDS)
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    _uuid(document["operation_id"], "operation_id")

    cutover = document["cutover"]
    if not isinstance(cutover, Mapping) or set(cutover) != {
        "cutover_id",
        "activation_sha256",
        "live_rollback_rehearsal_sha256",
    }:
        raise FaultAcceptanceError("cutover binding fields are invalid")
    _safe_id(cutover["cutover_id"], "cutover.cutover_id")
    _digest(cutover["activation_sha256"], "cutover.activation")
    _digest(
        cutover["live_rollback_rehearsal_sha256"],
        "cutover.live_rollback_rehearsal",
    )
    if cutover["activation_sha256"] == cutover["live_rollback_rehearsal_sha256"]:
        raise FaultAcceptanceError("cutover evidence digests must be distinct")

    release = document["release"]
    if not isinstance(release, Mapping) or set(release) != {
        "root",
        "digest",
        "executor",
        "executor_sha256",
        "fault_helper",
        "fault_helper_sha256",
        "runner",
        "runner_sha256",
    }:
        raise FaultAcceptanceError("release binding fields are invalid")
    release_root = Path(_absolute(release["root"], "release.root"))
    release_digest = _digest(release["digest"], "release")
    if release_root.name != release_digest or release_root.parent != Path("/opt/devcoordinator/releases"):
        raise FaultAcceptanceError("fault acceptance requires one immutable release root")
    for name in ("executor", "fault_helper", "runner"):
        path = Path(_absolute(release[name], f"release.{name}"))
        if release_root not in path.parents:
            raise FaultAcceptanceError(f"release.{name} escapes the immutable release")
        _digest(release[f"{name}_sha256"], f"release.{name}")

    authority = document["authority"]
    if not isinstance(authority, Mapping) or set(authority) != {
        "host_id",
        "host_boot_id",
        "database_generation",
        "state_revision",
    }:
        raise FaultAcceptanceError("authority binding fields are invalid")
    _safe_id(authority["host_id"], "authority.host_id")
    _uuid(authority["host_boot_id"], "authority.host_boot_id")
    _safe_id(authority["database_generation"], "authority.database_generation")
    if type(authority["state_revision"]) is not int or authority["state_revision"] < 0:
        raise FaultAcceptanceError("authority.state_revision is invalid")

    repository = document["repository"]
    if not isinstance(repository, Mapping) or set(repository) != {
        "repository_id",
        "generation",
        "owner_uid",
        "root",
        "unrelated_repository_ids",
    }:
        raise FaultAcceptanceError("repository binding fields are invalid")
    _safe_id(repository["repository_id"], "repository.repository_id")
    if type(repository["generation"]) is not int or repository["generation"] < 1:
        raise FaultAcceptanceError("repository.generation is invalid")
    if type(repository["owner_uid"]) is not int or not 1 <= repository["owner_uid"] < 2**31:
        raise FaultAcceptanceError("repository.owner_uid is invalid")
    _absolute(repository["root"], "repository.root")
    unrelated = repository["unrelated_repository_ids"]
    if (
        not isinstance(unrelated, list)
        or not unrelated
        or len(unrelated) > 10_000
        or unrelated != sorted(unrelated)
        or len(set(unrelated)) != len(unrelated)
        or repository["repository_id"] in unrelated
    ):
        raise FaultAcceptanceError("unrelated repository identities are invalid")
    for item in unrelated:
        _safe_id(item, "unrelated repository ID")

    inventory = document["inventory"]
    if not isinstance(inventory, Mapping) or set(inventory) != {
        "publication",
        "expected_owner_uid",
    }:
        raise FaultAcceptanceError("inventory binding fields are invalid")
    _absolute(inventory["publication"], "inventory.publication")
    if type(inventory["expected_owner_uid"]) is not int or inventory["expected_owner_uid"] < 0:
        raise FaultAcceptanceError("inventory.expected_owner_uid is invalid")

    cgroups = document["control_cgroups"]
    if (
        not isinstance(cgroups, Mapping)
        or not cgroups
        or not {"edge", "api", "authority", "console"} <= set(cgroups)
        or not set(cgroups) <= CONTROL_CGROUP_NAMES
    ):
        raise FaultAcceptanceError("control cgroup identities are incomplete")
    for name, raw in cgroups.items():
        path = Path(_absolute(raw, f"control_cgroups.{name}"))
        if (
            path.name != "cgroup.procs"
            or Path("/sys/fs/cgroup/devcoordinator-control.slice") not in path.parents
        ):
            raise FaultAcceptanceError("control cgroup path is outside the protected slice")

    targets = document["probe_targets"]
    if not isinstance(targets, Mapping) or set(targets) != {"http", "websocket"}:
        raise FaultAcceptanceError("probe target fields are invalid")
    http_targets = targets["http"]
    ws_targets = targets["websocket"]
    if not isinstance(http_targets, list) or not isinstance(ws_targets, list):
        raise FaultAcceptanceError("probe targets must be lists")
    if not 1 <= len(ws_targets) <= 4:
        raise FaultAcceptanceError("WebSocket probe target count is outside the fixed bound")
    categories = set()
    identities: list[str] = []
    for raw in http_targets:
        if not isinstance(raw, Mapping) or set(raw) != {"target_id", "category", "url"}:
            raise FaultAcceptanceError("HTTP probe target fields are invalid")
        target_id = _safe_id(raw["target_id"], "HTTP target ID")
        if raw["category"] not in {"console", "board", "api", "project"}:
            raise FaultAcceptanceError("HTTP probe target category is invalid")
        _https_url(raw["url"], f"HTTP target {target_id}")
        categories.add(raw["category"])
        identities.append("http:" + target_id)
    if categories != {"console", "board", "api", "project"}:
        code = "board_continuity_unsupported" if "board" not in categories else "fault_acceptance_failed"
        raise FaultAcceptanceError(
            "stable Console, Board, API, and project HTTP probes are all required",
            code=code,
        )
    if len(http_targets) != 4:
        raise FaultAcceptanceError("HTTP probe target count is outside the fixed bound")
    for raw in ws_targets:
        if not isinstance(raw, Mapping) or set(raw) != {"target_id", "category", "url"}:
            raise FaultAcceptanceError("WebSocket probe target fields are invalid")
        target_id = _safe_id(raw["target_id"], "WebSocket target ID")
        if raw["category"] not in {"console", "board", "api", "project"}:
            raise FaultAcceptanceError("WebSocket probe target category is invalid")
        _https_url(raw["url"], f"WebSocket target {target_id}", websocket=True)
        identities.append("websocket:" + target_id)
    if not ws_targets:
        raise FaultAcceptanceError("at least one stable WebSocket probe is required")
    if identities != sorted(identities) or len(identities) != len(set(identities)):
        raise FaultAcceptanceError("probe targets are not canonical and unique")

    scenarios = document["scenarios"]
    if not isinstance(scenarios, list) or len(scenarios) != len(SCENARIO_IDS):
        raise FaultAcceptanceError("fault scenario set is incomplete")
    normalized_ids = []
    for raw in scenarios:
        if not isinstance(raw, Mapping) or set(raw) != {
            "scenario_id",
            "resource_id",
            "resource_generation",
            "operation_id",
            "unit_scope",
            "ttl_seconds",
            "kill_after_run",
            "expected_terminal",
        }:
            raise FaultAcceptanceError("fault scenario fields are invalid")
        scenario_id = _safe_id(raw["scenario_id"], "scenario_id")
        normalized_ids.append(scenario_id)
        if scenario_id not in SCENARIO_POLICIES:
            raise FaultAcceptanceError("fault scenario identity is unsupported")
        _safe_id(raw["resource_id"], "scenario.resource_id")
        _uuid(raw["operation_id"], "scenario.operation_id")
        if raw["operation_id"] == document["operation_id"]:
            raise FaultAcceptanceError("scenario operation ID must be independently unique")
        if raw["resource_generation"] != repository["generation"]:
            raise FaultAcceptanceError("scenario resource generation is stale")
        policy = SCENARIO_POLICIES[scenario_id]
        if (
            raw["unit_scope"] != policy["unit_scope"]
            or raw["ttl_seconds"] != policy["ttl_seconds"]
            or raw["kill_after_run"] is not True
            or raw["expected_terminal"] != policy["expected_terminal"]
        ):
            raise FaultAcceptanceError("scenario safety policy was weakened or changed")
    if normalized_ids != list(SCENARIO_IDS):
        raise FaultAcceptanceError("fault scenarios are not in canonical order")
    if len({raw["resource_id"] for raw in scenarios}) != len(scenarios):
        raise FaultAcceptanceError("fault scenario resource IDs are not unique")
    if len({raw["operation_id"] for raw in scenarios}) != len(scenarios):
        raise FaultAcceptanceError("fault scenario operation IDs are not unique")

    created = _parse_timestamp(document["created_at"], "created_at")
    valid_until = _parse_timestamp(document["valid_until"], "valid_until")
    if not created <= current <= valid_until or valid_until - created > timedelta(minutes=15):
        raise FaultAcceptanceError("fault acceptance request is stale or excessively long-lived")
    return document


@runtime_checkable
class FaultRuntime(Protocol):
    def launch(self, scenario: Mapping[str, object]) -> Mapping[str, object]: ...

    def status(self, handle: Mapping[str, object]) -> Mapping[str, object]: ...

    def cleanup(self, handle: Mapping[str, object]) -> Mapping[str, object]: ...


@runtime_checkable
class FaultObserver(Protocol):
    def capture(self, phase: str) -> Mapping[str, object]: ...


class FaultAcceptanceAttemptManager(SystemdTestAttemptManager):
    """Use the standard broker-owned launcher with one fixed project-slice case."""

    @staticmethod
    def _repository_slice(descriptor: TestAttemptDescriptor) -> str:
        if descriptor.target_name == "fault-acceptance:slow_project_upstream":
            return project_repository_slice(
                uid=descriptor.owner_uid,
                repository_id=descriptor.repository_id,
            )
        return SystemdTestAttemptManager._repository_slice(descriptor)


@dataclass
class NativeFaultRuntime:
    """Translate fixed scenarios into generation-fenced broker test tickets."""

    request: Mapping[str, object]
    manager: NativeTestAttemptManager
    clock: Callable[[], float] = time.time
    sleeper: Callable[[float], None] = time.sleep

    def __post_init__(self) -> None:
        if not isinstance(self.manager, NativeTestAttemptManager):
            raise FaultAcceptanceError("native fault runtime manager is invalid")
        self._broker = BrokerTestAttemptCoordinator(self.manager, clock=self.clock)
        self._descriptors: dict[str, TestAttemptDescriptor] = {}

    def _descriptor(self, scenario: Mapping[str, object]) -> TestAttemptDescriptor:
        repository = self.request["repository"]
        release = self.request["release"]
        if not isinstance(repository, Mapping) or not isinstance(release, Mapping):
            raise FaultAcceptanceError("fault runtime request binding is invalid")
        scenario_id = str(scenario["scenario_id"])
        operation = str(scenario["operation_id"])
        return TestAttemptDescriptor(
            attempt_id="fault-attempt-" + operation.replace("-", ""),
            target_id=str(scenario["resource_id"]),
            run_id="fault-run-" + str(self.request["operation_id"]).replace("-", ""),
            repository_id=str(repository["repository_id"]),
            repository_generation=int(repository["generation"]),
            owner_uid=int(repository["owner_uid"]),
            generation=int(scenario["resource_generation"]),
            source_mode="live",
            snapshot_id=None,
            original_root=str(repository["root"]),
            temporary_root=None,
            execution_root=str(repository["root"]),
            worktree_key=str(repository["root"]),
            target_name="fault-acceptance:" + scenario_id,
            shard_index=0,
            shard_count=1,
            argv=(
                "/usr/bin/python3",
                "-I",
                str(release["fault_helper"]),
                "--scenario",
                scenario_id,
            ),
            cwd=".",
            environment={
                "DEVCOORDINATOR_FAULT_OPERATION_ID": operation,
                "DEVCOORDINATOR_FAULT_RESOURCE_ID": str(scenario["resource_id"]),
            },
            driver="automation",
            reporter="automation-events",
            artifacts=(),
            fixtures=(),
            network="loopback",
            ttl_seconds=int(scenario["ttl_seconds"]),
        )

    def launch(self, scenario: Mapping[str, object]) -> Mapping[str, object]:
        descriptor = self._descriptor(scenario)
        ticket = self._broker.issue(descriptor)
        ticket_fingerprint = _sha256(ticket)
        launched = self._broker.launch(
            ticket_id=str(ticket["ticket_id"]),
            attempt_id=descriptor.attempt_id,
            generation=descriptor.generation,
        )
        runtime_id = str(launched["runtime_id"])
        self._descriptors[runtime_id] = descriptor
        return {
            "scenario_id": scenario["scenario_id"],
            "runtime_id": runtime_id,
            "resource_id": scenario["resource_id"],
            "resource_generation": scenario["resource_generation"],
            "operation_id": scenario["operation_id"],
            "ticket_fingerprint": ticket_fingerprint,
            "launch_ack_id": launched["launch_ack_id"],
            "descriptor_sha256": descriptor.fingerprint,
            "unit_scope": scenario["unit_scope"],
            "ttl_seconds": scenario["ttl_seconds"],
            "kill_after_run": True,
        }

    def status(self, handle: Mapping[str, object]) -> Mapping[str, object]:
        runtime_id = str(handle["runtime_id"])
        descriptor = self._descriptors.get(runtime_id)
        if descriptor is None:
            raise FaultAcceptanceError("fault runtime handle is unknown")
        deadline = self.clock() + descriptor.ttl_seconds + 5
        while True:
            state = self.manager.status(runtime_id)
            if not state.active:
                break
            if self.clock() >= deadline:
                state = self.manager.cancel(runtime_id)
                break
            self.sleeper(0.05)
        result = state.result_package
        package = (
            None
            if result is None
            else self.manager.resolve_result_package(str(result["storage_handle"]))
        )
        outcome = None if package is None else package.manifest["outcome"]
        incomplete = bool(
            isinstance(outcome, Mapping)
            and outcome.get("incomplete_reporting") is True
        )
        terminal = "incomplete_reporting" if incomplete else state.termination_reason
        return {
            "scenario_id": handle["scenario_id"],
            "runtime_id": runtime_id,
            "active": state.active,
            "loaded": state.loaded,
            "terminal": terminal,
            "exit_status": state.exit_status,
            "systemd_result": state.systemd_result,
            "oom_killed": state.oom_killed,
            "result_package_sha256": None if result is None else result["sha256"],
            "reporter_complete": bool(
                isinstance(outcome, Mapping)
                and outcome.get("reporter_complete") is True
            ),
        }

    def cleanup(self, handle: Mapping[str, object]) -> Mapping[str, object]:
        runtime_id = str(handle["runtime_id"])
        self.manager.collect(runtime_id)
        state = self.manager.status(runtime_id)
        converged = not state.loaded and not state.active and state.state == "not-found"
        self._descriptors.pop(runtime_id, None)
        return {
            "runtime_id": runtime_id,
            "converged": converged,
            "loaded": state.loaded,
            "active": state.active,
            "state": state.state,
        }


PROBE_FIELDS = {
    "phase",
    "captured_at",
    "http_sample_count",
    "websocket_sample_count",
    "connection_refused_count",
    "project_route_failures",
    "failed_sample_count",
    "control_processes_sha256",
    "socket_inodes_sha256",
    "unrelated_project_state_sha256",
    "global_attention_state_sha256",
    "passed",
}


def _validate_probe(value: object, *, phase: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != PROBE_FIELDS:
        raise FaultAcceptanceError("fault probe fields are invalid")
    result = dict(value)
    if result["phase"] != phase:
        raise FaultAcceptanceError("fault probe phase is contradictory")
    _parse_timestamp(result["captured_at"], f"probe.{phase}")
    for name in (
        "http_sample_count",
        "websocket_sample_count",
        "connection_refused_count",
        "project_route_failures",
        "failed_sample_count",
    ):
        if type(result[name]) is not int or result[name] < 0:
            raise FaultAcceptanceError("fault probe counters are invalid")
    for name in (
        "control_processes_sha256",
        "socket_inodes_sha256",
        "unrelated_project_state_sha256",
        "global_attention_state_sha256",
    ):
        _digest(result[name], f"probe.{name}")
    if (
        result["http_sample_count"] < 4
        or result["websocket_sample_count"] < 1
        or result["connection_refused_count"] != 0
        or result["project_route_failures"] != 0
        or result["failed_sample_count"] != 0
        or result["passed"] is not True
    ):
        raise FaultAcceptanceError("fault probe observed a continuity failure")
    return result


def _validate_runtime_result(
    scenario: Mapping[str, object],
    launch: object,
    result: object,
    cleanup: object,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    if not isinstance(launch, Mapping) or set(launch) != {
        "scenario_id",
        "runtime_id",
        "resource_id",
        "resource_generation",
        "operation_id",
        "ticket_fingerprint",
        "launch_ack_id",
        "descriptor_sha256",
        "unit_scope",
        "ttl_seconds",
        "kill_after_run",
    }:
        raise FaultAcceptanceError("fault runtime launch evidence is invalid")
    launch = dict(launch)
    for name in ("runtime_id", "launch_ack_id"):
        _safe_id(launch[name], f"launch.{name}")
    _digest(launch["ticket_fingerprint"], "launch.ticket_fingerprint")
    _digest(launch["descriptor_sha256"], "launch.descriptor_sha256")
    for field in (
        "scenario_id",
        "resource_id",
        "resource_generation",
        "operation_id",
        "unit_scope",
        "ttl_seconds",
        "kill_after_run",
    ):
        if launch[field] != scenario[field]:
            raise FaultAcceptanceError("fault runtime launch changed scenario identity")

    if not isinstance(result, Mapping) or set(result) != {
        "scenario_id",
        "runtime_id",
        "active",
        "loaded",
        "terminal",
        "exit_status",
        "systemd_result",
        "oom_killed",
        "result_package_sha256",
        "reporter_complete",
    }:
        raise FaultAcceptanceError("fault runtime terminal evidence is invalid")
    result = dict(result)
    if (
        result["scenario_id"] != scenario["scenario_id"]
        or result["runtime_id"] != launch["runtime_id"]
        or result["active"] is not False
        or type(result["loaded"]) is not bool
        or result["terminal"] != scenario["expected_terminal"]
        or (
            result["exit_status"] is not None
            and type(result["exit_status"]) is not int
        )
        or (
            result["systemd_result"] is not None
            and not isinstance(result["systemd_result"], str)
        )
        or type(result["oom_killed"]) is not bool
        or type(result["reporter_complete"]) is not bool
    ):
        raise FaultAcceptanceError("fault runtime did not reach its expected terminal state")
    if scenario["scenario_id"] == "cgroup_oom":
        if (
            result["oom_killed"] is not True
            or result["systemd_result"] != "oom-kill"
            or result["result_package_sha256"] is not None
            or result["reporter_complete"] is not False
        ):
            raise FaultAcceptanceError("OOM scenario was not classified by cgroup evidence")
    elif result["oom_killed"] is not False:
        raise FaultAcceptanceError("non-OOM scenario reported contradictory OOM evidence")
    if result["result_package_sha256"] is not None:
        _digest(result["result_package_sha256"], "result.result_package")
    if scenario["scenario_id"] == "malformed_runner_output":
        if (
            result["reporter_complete"] is not False
            or result["exit_status"] != 1
            or result["systemd_result"] != "exit-code"
            or result["result_package_sha256"] is None
        ):
            raise FaultAcceptanceError("malformed reporter scenario was not contained")
    elif scenario["scenario_id"] != "cgroup_oom":
        if (
            result["reporter_complete"] is not True
            or result["exit_status"] != 0
            or result["systemd_result"] != "success"
            or result["result_package_sha256"] is None
        ):
            raise FaultAcceptanceError("fault scenario omitted complete structured evidence")

    if not isinstance(cleanup, Mapping) or set(cleanup) != {
        "runtime_id",
        "converged",
        "loaded",
        "active",
        "state",
    }:
        raise FaultAcceptanceError("fault runtime cleanup evidence is invalid")
    cleanup = dict(cleanup)
    if (
        cleanup["runtime_id"] != launch["runtime_id"]
        or cleanup["converged"] is not True
        or cleanup["loaded"] is not False
        or cleanup["active"] is not False
        or cleanup["state"] != "not-found"
    ):
        raise FaultAcceptanceError("fault runtime cleanup did not converge")
    return launch, result, cleanup


ATTESTATION_FIELDS = {
    "operation_id",
    "cutover",
    "request_sha256",
    "config_sha256",
    "release",
    "authority",
    "repository",
    "probe_targets_sha256",
    "started_at",
    "completed_at",
    "valid_until",
    "scenarios",
    "aggregate",
}


def validate_attestation(
    value: object,
    *,
    request: Mapping[str, object],
    now: datetime | None = None,
    require_fresh: bool = False,
) -> dict[str, object]:
    request = validate_request(request, now=now)
    document = _verify_seal(value, kind=ATTESTATION_KIND, fields=ATTESTATION_FIELDS)
    if (
        document["operation_id"] != request["operation_id"]
        or document["cutover"] != request["cutover"]
        or document["request_sha256"] != request["document_sha256"]
        or document["config_sha256"] != request["document_sha256"]
        or document["release"] != request["release"]
        or document["authority"] != request["authority"]
        or document["repository"] != request["repository"]
        or document["probe_targets_sha256"] != _sha256(request["probe_targets"])
    ):
        raise FaultAcceptanceError("fault attestation is bound to another request or release")
    started = _parse_timestamp(document["started_at"], "attestation.started_at")
    completed = _parse_timestamp(document["completed_at"], "attestation.completed_at")
    valid_until = _parse_timestamp(document["valid_until"], "attestation.valid_until")
    if not started <= completed <= valid_until or valid_until - completed > timedelta(minutes=15):
        raise FaultAcceptanceError("fault attestation lifetime is invalid")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if require_fresh and not completed <= current <= valid_until:
        raise FaultAcceptanceError("fault attestation is stale")

    scenarios = document["scenarios"]
    if not isinstance(scenarios, list) or len(scenarios) != len(SCENARIO_IDS):
        raise FaultAcceptanceError("fault attestation scenario evidence is incomplete")
    total_probes = 0
    campaign_state: dict[str, object] | None = None
    stable_fields = (
        "control_processes_sha256",
        "socket_inodes_sha256",
        "unrelated_project_state_sha256",
        "global_attention_state_sha256",
    )
    for expected, evidence in zip(request["scenarios"], scenarios):
        if not isinstance(expected, Mapping) or not isinstance(evidence, Mapping) or set(evidence) != {
            "scenario_id",
            "resource_id",
            "resource_generation",
            "operation_id",
            "unit_scope",
            "ttl_seconds",
            "kill_after_run",
            "expected_terminal",
            "launch",
            "result",
            "cleanup",
            "probes",
            "state_preserved",
            "passed",
        }:
            raise FaultAcceptanceError("fault attestation scenario fields are invalid")
        for field in (
            "scenario_id",
            "resource_id",
            "resource_generation",
            "operation_id",
            "unit_scope",
            "ttl_seconds",
            "kill_after_run",
            "expected_terminal",
        ):
            if evidence[field] != expected[field]:
                raise FaultAcceptanceError("fault attestation changed scenario policy")
        _validate_runtime_result(expected, evidence["launch"], evidence["result"], evidence["cleanup"])
        probes = evidence["probes"]
        if not isinstance(probes, Mapping) or set(probes) != {"pre", "during", "post"}:
            raise FaultAcceptanceError("fault attestation probe phases are incomplete")
        checked = {phase: _validate_probe(probes[phase], phase=phase) for phase in ("pre", "during", "post")}
        total_probes += 3
        if any(
            len({checked[phase][field] for phase in checked}) != 1
            for field in stable_fields
        ):
            raise FaultAcceptanceError("fault scenario changed control or unrelated project state")
        for phase in ("pre", "during", "post"):
            state = {field: checked[phase][field] for field in stable_fields}
            if campaign_state is None:
                campaign_state = state
            elif state != campaign_state:
                raise FaultAcceptanceError(
                    "fault campaign changed control or unrelated project state"
                )
        if evidence["state_preserved"] is not True or evidence["passed"] is not True:
            raise FaultAcceptanceError("fault scenario did not preserve isolation")

    aggregate = document["aggregate"]
    if not isinstance(aggregate, Mapping) or set(aggregate) != {
        "scenario_count",
        "probe_phase_count",
        "connection_refused_count",
        "project_route_failures",
        "failed_probe_count",
        "control_restart_count",
        "cleanup_failure_count",
        "unrelated_project_change_count",
        "global_banner_change_count",
        "passed",
    }:
        raise FaultAcceptanceError("fault attestation aggregate fields are invalid")
    if aggregate != {
        "scenario_count": len(SCENARIO_IDS),
        "probe_phase_count": total_probes,
        "connection_refused_count": 0,
        "project_route_failures": 0,
        "failed_probe_count": 0,
        "control_restart_count": 0,
        "cleanup_failure_count": 0,
        "unrelated_project_change_count": 0,
        "global_banner_change_count": 0,
        "passed": True,
    }:
        raise FaultAcceptanceError("fault attestation aggregate did not pass exactly")
    return document


def run_acceptance(
    request: Mapping[str, object],
    *,
    runtime: FaultRuntime,
    observer: FaultObserver,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    request = validate_request(request, now=now())
    if not isinstance(runtime, FaultRuntime) or not isinstance(observer, FaultObserver):
        raise FaultAcceptanceError("fault acceptance runtime or observer is invalid")
    started_at = _timestamp(now())
    evidence_rows: list[dict[str, object]] = []
    campaign_state: dict[str, object] | None = None
    stable_fields = (
        "control_processes_sha256",
        "socket_inodes_sha256",
        "unrelated_project_state_sha256",
        "global_attention_state_sha256",
    )
    for scenario in request["scenarios"]:
        if not isinstance(scenario, Mapping):
            raise FaultAcceptanceError("fault scenario is invalid")
        pre = _validate_probe(observer.capture("pre"), phase="pre")
        handle: Mapping[str, object] | None = None
        try:
            handle = runtime.launch(scenario)
            during = _validate_probe(observer.capture("during"), phase="during")
            terminal = runtime.status(handle)
        finally:
            if handle is None:
                raise FaultAcceptanceError("fault runtime failed before returning cleanup identity")
            cleanup = runtime.cleanup(handle)
        post = _validate_probe(observer.capture("post"), phase="post")
        launch, terminal, cleanup = _validate_runtime_result(
            scenario, handle, terminal, cleanup
        )
        state_preserved = all(
            len({pre[field], during[field], post[field]}) == 1
            for field in stable_fields
        )
        if not state_preserved:
            raise FaultAcceptanceError(
                "fault scenario changed control, unrelated-project, or global-attention state"
            )
        for observation in (pre, during, post):
            state = {field: observation[field] for field in stable_fields}
            if campaign_state is None:
                campaign_state = state
            elif state != campaign_state:
                raise FaultAcceptanceError(
                    "fault campaign changed control, unrelated-project, or global-attention state"
                )
        evidence_rows.append(
            {
                **{key: scenario[key] for key in (
                    "scenario_id",
                    "resource_id",
                    "resource_generation",
                    "operation_id",
                    "unit_scope",
                    "ttl_seconds",
                    "kill_after_run",
                    "expected_terminal",
                )},
                "launch": launch,
                "result": terminal,
                "cleanup": cleanup,
                "probes": {"pre": pre, "during": during, "post": post},
                "state_preserved": True,
                "passed": True,
            }
        )
    completed = now()
    attestation = _seal(
        ATTESTATION_KIND,
        {
            "operation_id": request["operation_id"],
            "cutover": request["cutover"],
            "request_sha256": request["document_sha256"],
            "config_sha256": request["document_sha256"],
            "release": request["release"],
            "authority": request["authority"],
            "repository": request["repository"],
            "probe_targets_sha256": _sha256(request["probe_targets"]),
            "started_at": started_at,
            "completed_at": _timestamp(completed),
            "valid_until": _timestamp(completed + timedelta(minutes=15)),
            "scenarios": evidence_rows,
            "aggregate": {
                "scenario_count": len(evidence_rows),
                "probe_phase_count": len(evidence_rows) * 3,
                "connection_refused_count": 0,
                "project_route_failures": 0,
                "failed_probe_count": 0,
                "control_restart_count": 0,
                "cleanup_failure_count": 0,
                "unrelated_project_change_count": 0,
                "global_banner_change_count": 0,
                "passed": True,
            },
        },
    )
    return validate_attestation(attestation, request=request, now=completed, require_fresh=True)


def read_private_json(path: Path, *, expected_uid: int) -> dict[str, object]:
    absolute = path.expanduser().absolute()
    info = absolute.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != expected_uid
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
        or not 1 <= info.st_size <= MAX_DOCUMENT_BYTES
    ):
        raise FaultAcceptanceError("fault acceptance private document is unsafe")
    descriptor = os.open(
        absolute,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        payload = os.read(descriptor, MAX_DOCUMENT_BYTES + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(payload) > MAX_DOCUMENT_BYTES or (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
    ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise FaultAcceptanceError("fault acceptance private document changed while read")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FaultAcceptanceError("fault acceptance private document is invalid JSON") from error
    if not isinstance(value, dict):
        raise FaultAcceptanceError("fault acceptance private document must be an object")
    return value


def write_private_json(path: Path, value: Mapping[str, object], *, expected_uid: int) -> None:
    absolute = path.expanduser().absolute()
    parent = absolute.parent
    parent_info = parent.lstat()
    if (
        stat.S_ISLNK(parent_info.st_mode)
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != expected_uid
        or stat.S_IMODE(parent_info.st_mode) & 0o077
    ):
        raise FaultAcceptanceError("fault acceptance output parent is not root-private")
    if absolute.exists() or absolute.is_symlink():
        raise FaultAcceptanceError("fault acceptance output already exists")
    payload = json.dumps(value, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    if len(payload) > MAX_DOCUMENT_BYTES:
        raise FaultAcceptanceError("fault acceptance output exceeds its byte bound")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{absolute.name}.", dir=parent)
    temporary = Path(temporary_name)
    linked = False
    published = False
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        info = temporary.lstat()
        if info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o600:
            raise FaultAcceptanceError("fault acceptance temporary output is unsafe")
        os.link(temporary, absolute, follow_symlinks=False)
        linked = True
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        published = True
    finally:
        temporary.unlink(missing_ok=True)
        if linked and not published:
            absolute.unlink(missing_ok=True)
        if linked:
            directory = os.open(
                parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)


__all__ = [
    "ATTESTATION_KIND",
    "CONTRACT_VERSION",
    "FaultAcceptanceAttemptManager",
    "FaultAcceptanceError",
    "FaultObserver",
    "FaultRuntime",
    "NativeFaultRuntime",
    "REQUEST_KIND",
    "SCENARIO_IDS",
    "SCENARIO_POLICIES",
    "build_request",
    "read_private_json",
    "run_acceptance",
    "validate_attestation",
    "validate_request",
    "write_private_json",
]
