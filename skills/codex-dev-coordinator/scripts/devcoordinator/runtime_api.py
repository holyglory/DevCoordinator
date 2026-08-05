"""Strict unified lifecycle request boundary for agents and local UIs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Callable

from .repository_context import (
    PersistedRepositoryContext,
    RepositoryScopeIdentity,
    persist_repository_context,
    resolve_repository_context,
)
from .runtime_report import build_runtime_report
from .runtime_redaction import redact_runtime_value
from .runtime_sessions import (
    cleanup_runtime_session,
    create_runtime_session,
    finish_runtime_session,
    link_runtime_resource,
    mark_runtime_session_started,
    reap_expired_runtime_sessions,
)
from .store import deterministic_id, refuse_symlink_components, utc_timestamp


RUNTIME_ACTIONS = frozenset(
    {
        "status",
        "capture_logs",
        "start",
        "stop",
        "restart",
        "replace",
        "run",
        "remove",
    }
)
RUNTIME_TARGET_KINDS = frozenset({"service", "docker", "database_stack"})
RUNTIME_PURPOSES = frozenset({"development", "test", "temporary"})
RUNTIME_REQUEST_KEYS = frozenset(
    {
        "schema_version",
        "action",
        "agent",
        "root_repo",
        "temporary_repo",
        "target",
        "purpose",
        "ttl_seconds",
        "kill_after_run",
        "options",
    }
)
RUNTIME_REQUIRED_KEYS = RUNTIME_REQUEST_KEYS - {"options"}
RUNTIME_OPTION_KEYS = frozenset(
    {
        "argv",
        "cwd",
        "env",
        "preferred",
        "range",
        "host",
        "health_url",
        "health_timeout",
        "reason",
        "role",
        "compose_files",
        "compose_service",
        "run_argv",
        "run_env",
        "run_timeout_seconds",
        "dry_run",
        "keep_alive",
        "restart_limit",
        "restart_window_seconds",
        "rearm_crash_loop",
        "expected_definition_generation",
        "remove_plan_id",
        "remove_plan_fingerprint",
        "remove_confirmation_phrase",
    }
)
MAX_RUNTIME_REQUEST_BYTES = 64 * 1024
MAX_RUNTIME_TTL_SECONDS = 7 * 24 * 60 * 60


class RuntimeRequestError(ValueError):
    """The strict lifecycle request contract was violated."""

    def __init__(
        self,
        message: str,
        *,
        request_context: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.request_context = (
            None if request_context is None else dict(request_context)
        )


def runtime_request_error_context(payload: Any) -> dict[str, Any]:
    """Project only bounded, non-command request identity for error reports."""

    request = payload if isinstance(payload, Mapping) else {}

    def text(value: Any, *, maximum: int) -> str | None:
        if not isinstance(value, str):
            return None
        candidate = value.strip()
        if not candidate or "\x00" in candidate or len(candidate) > maximum:
            return None
        return candidate

    raw_target = request.get("target")
    target: dict[str, Any] = {}
    if isinstance(raw_target, Mapping):
        for key, maximum in (("kind", 40), ("id", 300), ("name", 200)):
            value = text(raw_target.get(key), maximum=maximum)
            if value is not None:
                target[key] = value
    temporary = request.get("temporary_repo")
    return {
        "action": text(request.get("action"), maximum=20),
        "root_repo": text(request.get("root_repo"), maximum=4096),
        "temporary_repo": (
            None
            if temporary is None
            else text(temporary, maximum=4096)
        ),
        "target": target or None,
    }


class UnclassifiedRuntimeResource(RuntimeError):
    """A scoped resource does not have one exact repository membership."""


class RuntimeObservationUnavailable(RuntimeError):
    """The mandatory pre-action host observation could not be completed."""

    def __init__(self, error: BaseException) -> None:
        super().__init__(f"runtime host observation is unavailable: {error}")
        self.payload = {
            "classification": "observation_unavailable",
            "error_type": type(error).__name__,
            "error": str(error),
        }


class RuntimeCleanupOwnerRequired(RuntimeError):
    """A leased runtime would outlive a one-shot caller without a reaper."""

    def __init__(self) -> None:
        super().__init__(
            "this leased runtime requires a live coordinator cleanup owner"
        )
        self.payload = {
            "code": "runtime_cleanup_owner_required",
            "classification": "cleanup_owner_required",
            "action_required": (
                "Submit the request to the long-lived authenticated account API, "
                "or use action=run with kill_after_run=true."
            ),
        }


class RuntimeSafeReplaceUnavailable(RuntimeError):
    """Replacement cannot preserve exact identity and state with current primitives."""

    def __init__(self, *, resource_kind: str, resource_id: str) -> None:
        super().__init__(
            f"safe {resource_kind} replacement is not implemented; no resource was inspected or changed"
        )
        if resource_kind == "database_stack":
            action_required = (
                "Use stop/start for the existing immutable target. Replacement remains "
                "disabled until verified backup, restore, rebind, rollback, and replay "
                "are one durable transaction."
            )
        else:
            action_required = (
                "Use stop/start for the existing immutable target. Replacement remains "
                "disabled until stored Compose recreation, exact identity rebind, rollback, "
                "and replay are one durable transaction."
            )
        self.payload = {
            "code": "runtime_safe_replace_unavailable",
            "classification": "unsupported_safe_replace",
            "resource_kind": resource_kind,
            "resource_id": resource_id,
            "mutation_performed": False,
            "action_required": action_required,
        }


class RuntimeExecutionCleanupError(RuntimeError):
    """Execution and mandatory cleanup both failed."""

    def __init__(self, execution_error: BaseException, cleanup_error: BaseException):
        super().__init__(
            "runtime execution failed and mandatory cleanup also failed: "
            f"{type(execution_error).__name__}: {execution_error}; cleanup: "
            f"{type(cleanup_error).__name__}: {cleanup_error}"
        )
        self.execution_error = execution_error
        self.cleanup_error = cleanup_error


@dataclass(frozen=True)
class RuntimeCallbacks:
    ensure_repository: Callable[[Any, RepositoryScopeIdentity], str]
    dispatch: Callable[
        [
            dict[str, Any],
            str,
            str | None,
            Callable[[dict[str, Any]], None],
        ],
        dict[str, Any],
    ]
    cleanup: Callable[
        [dict[str, Any], list[dict[str, Any]]], dict[str, Any]
    ]
    observe: Callable[[str], dict[str, Any]]
    inventory: Callable[[], dict[str, Any]]
    capture_logs: Callable[
        [dict[str, Any], str], dict[str, Any]
    ] = lambda _request, _project: {
        "availability": "unavailable",
        "reason_code": "authoritative_log_capture_unavailable",
    }
    cleanup_owner_available: Callable[[], bool] = lambda: False


def _nonempty_string(value: Any, *, field: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuntimeRequestError(f"{field} must be a non-empty string")
    result = value.strip()
    if "\x00" in result:
        raise RuntimeRequestError(f"{field} must not contain NUL")
    if len(result) > maximum:
        raise RuntimeRequestError(f"{field} is too long")
    return result


def _argv(value: Any, *, field: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 256
        or not all(
            isinstance(item, str)
            and item
            and "\x00" not in item
            and len(item.encode("utf-8")) <= 8192
            for item in value
        )
        or sum(len(item.encode("utf-8")) for item in value) > 32768
    ):
        raise RuntimeRequestError(
            f"{field} must be a bounded non-empty array of NUL-free strings"
        )
    return list(value)


def validate_runtime_request(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RuntimeRequestError("runtime request must be a JSON object")
    try:
        encoded_size = len(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
        )
    except (TypeError, ValueError) as error:
        raise RuntimeRequestError("runtime request must be JSON-serializable") from error
    if encoded_size > MAX_RUNTIME_REQUEST_BYTES:
        raise RuntimeRequestError("runtime request exceeds 65536 bytes")
    keys = set(payload)
    missing = sorted(RUNTIME_REQUIRED_KEYS - keys)
    extra = sorted(keys - RUNTIME_REQUEST_KEYS)
    if missing or extra:
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unknown " + ", ".join(extra))
        raise RuntimeRequestError("runtime request fields are invalid: " + "; ".join(details))
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        raise RuntimeRequestError("schema_version must be integer 1")
    action = _nonempty_string(payload["action"], field="action", maximum=20)
    if action not in RUNTIME_ACTIONS:
        raise RuntimeRequestError(
            "action must be status, capture_logs, start, stop, restart, replace, run, or remove"
        )
    purpose = _nonempty_string(payload["purpose"], field="purpose", maximum=20)
    if purpose not in RUNTIME_PURPOSES:
        raise RuntimeRequestError("purpose must be development, test, or temporary")
    agent = _nonempty_string(payload["agent"], field="agent", maximum=200)
    root_repo = _nonempty_string(payload["root_repo"], field="root_repo")
    temporary_repo = payload["temporary_repo"]
    if temporary_repo is not None:
        temporary_repo = _nonempty_string(temporary_repo, field="temporary_repo")
    if type(payload["kill_after_run"]) is not bool:
        raise RuntimeRequestError("kill_after_run must be a JSON boolean")
    if payload["kill_after_run"] and action != "run":
        raise RuntimeRequestError("kill_after_run=true is valid only for action run")
    ttl_seconds = payload["ttl_seconds"]
    if ttl_seconds is not None and (
        type(ttl_seconds) is not int
        or not 1 <= ttl_seconds <= MAX_RUNTIME_TTL_SECONDS
    ):
        raise RuntimeRequestError(
            f"ttl_seconds must be null or an integer from 1 through {MAX_RUNTIME_TTL_SECONDS}"
        )
    if (
        purpose in {"test", "temporary"}
        and action in {"start", "restart", "replace", "run"}
        and ttl_seconds is None
    ):
        raise RuntimeRequestError(
            "test and temporary runtime requests require ttl_seconds"
        )
    if action in {"status", "capture_logs"} and ttl_seconds is not None:
        raise RuntimeRequestError(
            f"{action} is read-only and requires ttl_seconds=null"
        )
    if action == "run" and purpose not in {"test", "temporary"}:
        raise RuntimeRequestError("run requires purpose test or temporary")
    if action == "remove" and (purpose != "development" or ttl_seconds is not None):
        raise RuntimeRequestError(
            "remove requires purpose development and ttl_seconds=null"
        )

    target = payload["target"]
    if not isinstance(target, dict) or not set(target) <= {"kind", "id", "name"}:
        raise RuntimeRequestError("target accepts exactly kind and optional id/name")
    kind = _nonempty_string(target.get("kind"), field="target.kind", maximum=40)
    if kind not in RUNTIME_TARGET_KINDS:
        raise RuntimeRequestError("target.kind must be service, docker, or database_stack")
    target_id = target.get("id")
    target_name = target.get("name")
    if target_id is not None:
        target_id = _nonempty_string(target_id, field="target.id", maximum=300)
    if target_name is not None:
        target_name = _nonempty_string(target_name, field="target.name", maximum=200)
    if kind == "service" and target_name is None:
        raise RuntimeRequestError("service target requires name")
    if (
        kind == "service"
        and target_id is None
        and action not in {"start", "run"}
    ):
        raise RuntimeRequestError(
            "existing service targets require normalized immutable id"
        )
    if kind in {"docker", "database_stack"} and target_id is None:
        raise RuntimeRequestError(f"{kind} target requires immutable id")
    if action == "capture_logs" and kind not in {
        "service",
        "docker",
        "database_stack",
    }:
        raise RuntimeRequestError(
            "capture_logs requires a service, docker, or database_stack target"
        )
    if action == "remove" and (kind != "service" or target_id is None):
        raise RuntimeRequestError(
            "remove currently requires an existing immutable service target"
        )

    raw_options = payload.get("options") or {}
    if not isinstance(raw_options, dict):
        raise RuntimeRequestError("options must be an object")
    option_extra = sorted(set(raw_options) - RUNTIME_OPTION_KEYS)
    if option_extra:
        raise RuntimeRequestError("unknown runtime options: " + ", ".join(option_extra))
    options = dict(raw_options)
    if action == "capture_logs" and options:
        raise RuntimeRequestError("capture_logs accepts no runtime options")
    if "argv" in options:
        options["argv"] = _argv(options["argv"], field="options.argv")
    if "run_argv" in options:
        options["run_argv"] = _argv(options["run_argv"], field="options.run_argv")
    for env_field in ("env", "run_env"):
        if env_field in options and (
            not isinstance(options[env_field], dict)
            or len(options[env_field]) > 128
            or not all(
                isinstance(key, str)
                and key
                and "=" not in key
                and "\x00" not in key
                and len(key.encode("utf-8")) <= 256
                and isinstance(value, str)
                and "\x00" not in value
                and len(value.encode("utf-8")) <= 8192
                for key, value in options[env_field].items()
            )
            or sum(
                len(key.encode("utf-8")) + len(value.encode("utf-8"))
                for key, value in options[env_field].items()
            )
            > 32768
        ):
            raise RuntimeRequestError(
                f"options.{env_field} must be a bounded NUL-free environment map"
            )
    if "dry_run" in options and type(options["dry_run"]) is not bool:
        raise RuntimeRequestError("options.dry_run must be a JSON boolean")
    for boolean_field in ("keep_alive", "rearm_crash_loop"):
        if boolean_field in options and type(options[boolean_field]) is not bool:
            raise RuntimeRequestError(
                f"options.{boolean_field} must be a JSON boolean"
            )
    for integer_field, maximum in (
        ("restart_limit", 1000),
        ("restart_window_seconds", MAX_RUNTIME_TTL_SECONDS),
    ):
        if integer_field in options and (
            type(options[integer_field]) is not int
            or not 1 <= options[integer_field] <= maximum
        ):
            raise RuntimeRequestError(
                f"options.{integer_field} must be an integer from 1 through {maximum}"
            )
    if "expected_definition_generation" in options and (
        type(options["expected_definition_generation"]) is not int
        or not 0 <= options["expected_definition_generation"] <= 2**63 - 1
    ):
        raise RuntimeRequestError(
            "options.expected_definition_generation must be a non-negative integer"
        )
    for numeric_field, maximum in (
        ("health_timeout", 300.0),
        ("run_timeout_seconds", float(MAX_RUNTIME_TTL_SECONDS)),
    ):
        if numeric_field in options:
            value = options[numeric_field]
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or not 0 < float(value) <= maximum
            ):
                raise RuntimeRequestError(
                    f"options.{numeric_field} must be a finite positive number no greater than {maximum:g}"
                )
    if "preferred" in options and (
        type(options["preferred"]) is not int
        or not 1 <= options["preferred"] <= 65535
    ):
        raise RuntimeRequestError(
            "options.preferred must be an integer from 1 through 65535"
        )
    for string_field, maximum in (
        ("cwd", 4096),
        ("range", 32),
        ("host", 255),
        ("health_url", 4096),
        ("reason", 1000),
        ("role", 200),
        ("compose_service", 200),
        ("remove_plan_id", 64),
        ("remove_plan_fingerprint", 80),
    ):
        if string_field in options:
            options[string_field] = _nonempty_string(
                options[string_field],
                field=f"options.{string_field}",
                maximum=maximum,
            )
    if "remove_confirmation_phrase" in options:
        phrase = options["remove_confirmation_phrase"]
        if (
            not isinstance(phrase, str)
            or "\x00" in phrase
            or len(phrase) > 500
        ):
            raise RuntimeRequestError(
                "options.remove_confirmation_phrase must be a bounded NUL-free string"
            )
    if "cwd" in options and not Path(options["cwd"]).expanduser().is_absolute():
        raise RuntimeRequestError("options.cwd must be an absolute path")
    if "range" in options:
        match = re.fullmatch(r"([0-9]{1,5})-([0-9]{1,5})", options["range"])
        if (
            match is None
            or not 1 <= int(match.group(1)) <= int(match.group(2)) <= 65535
        ):
            raise RuntimeRequestError("options.range must be a valid PORT-PORT range")
    if action == "run" and "run_argv" not in options:
        raise RuntimeRequestError("run requires options.run_argv")
    supervision_fields = {
        "keep_alive",
        "restart_limit",
        "restart_window_seconds",
        "rearm_crash_loop",
    }
    supplied_supervision = supervision_fields & set(options)
    if supplied_supervision and (
        kind != "service" or action not in {"start", "restart", "replace"}
    ):
        raise RuntimeRequestError(
            "worker supervision options apply only to service start, restart, or replace"
        )
    if supplied_supervision and target_id is None:
        raise RuntimeRequestError(
            "worker supervision requires an installed immutable service target ID"
        )
    if supplied_supervision and purpose != "development":
        raise RuntimeRequestError(
            "worker supervision options are valid only for persistent development workers"
        )
    if {"restart_limit", "restart_window_seconds"} & set(options) and options.get(
        "keep_alive"
    ) is not True:
        raise RuntimeRequestError(
            "restart limits require options.keep_alive=true"
        )
    if options.get("rearm_crash_loop") is True and target_id is None:
        raise RuntimeRequestError(
            "rearming a crash loop requires an existing immutable service target"
        )
    if "expected_definition_generation" in options and not (
        kind == "service" and action == "replace" and target_id is not None
    ):
        raise RuntimeRequestError(
            "options.expected_definition_generation applies only to exact service replacement"
        )
    remove_fields = {
        "remove_plan_id",
        "remove_plan_fingerprint",
        "remove_confirmation_phrase",
    }
    supplied_remove = remove_fields & set(options)
    if action == "remove":
        if supplied_remove and supplied_remove != remove_fields:
            raise RuntimeRequestError(
                "remove apply requires plan id, fingerprint, and confirmation phrase together"
            )
        if not supplied_remove and "reason" not in options:
            raise RuntimeRequestError("remove planning requires options.reason")
        forbidden = set(options) - remove_fields - {"reason"}
        if forbidden:
            raise RuntimeRequestError(
                "remove accepts only reason and optional complete plan/apply fields"
            )
    elif supplied_remove:
        raise RuntimeRequestError(
            "remove plan/apply fields are valid only for action remove"
        )
    if (
        kind == "service"
        and (
            action == "replace"
            or (action in {"start", "run"} and target_id is None)
        )
        and "argv" not in options
    ):
        raise RuntimeRequestError(
            f"service {action} requires options.argv when defining a service"
        )
    if kind in {"docker", "database_stack"} and action == "replace":
        files = options.get("compose_files")
        if files is not None and (
            not isinstance(files, list)
            or not all(isinstance(item, str) and item for item in files)
        ):
            raise RuntimeRequestError("options.compose_files must be an array of paths")
        if files is not None:
            normalized_files = []
            for index, item in enumerate(files):
                value = _nonempty_string(
                    item,
                    field=f"options.compose_files[{index}]",
                    maximum=4096,
                )
                if not Path(value).expanduser().is_absolute():
                    raise RuntimeRequestError(
                        "options.compose_files entries must be absolute paths"
                    )
                normalized_files.append(value)
            options["compose_files"] = normalized_files

    if options.get("dry_run") is True:
        raise RuntimeRequestError(
            "options.dry_run=true is not supported by the lifecycle API"
        )

    return {
        "schema_version": 1,
        "action": action,
        "agent": agent,
        "root_repo": root_repo,
        "temporary_repo": temporary_repo,
        "target": {key: value for key, value in {"kind": kind, "id": target_id, "name": target_name}.items() if value is not None},
        "purpose": purpose,
        "ttl_seconds": ttl_seconds,
        "kill_after_run": payload["kill_after_run"],
        "options": options,
    }


def reject_unsupported_safe_replace(request: Mapping[str, Any]) -> None:
    """Fail before repository resolution, store access, observation, or mutation."""

    target = request.get("target")
    target = target if isinstance(target, Mapping) else {}
    kind = str(target.get("kind") or "")
    if request.get("action") == "replace" and kind in {
        "docker",
        "database_stack",
    }:
        raise RuntimeSafeReplaceUnavailable(
            resource_kind=kind,
            resource_id=str(target.get("id") or ""),
        )


def load_runtime_request(
    *, request_json: str | None, request_file: str | None
) -> dict[str, Any]:
    if bool(request_json) == bool(request_file):
        raise RuntimeRequestError(
            "provide exactly one of --request-json or --request-file"
        )
    if request_file is not None:
        candidate = Path(request_file).expanduser()
        if not candidate.is_absolute():
            raise RuntimeRequestError("--request-file must be an absolute path")
        try:
            metadata = candidate.lstat()
        except OSError as error:
            raise RuntimeRequestError(f"request file is unavailable: {error}") from error
        if candidate.is_symlink() or not candidate.is_file():
            raise RuntimeRequestError("request file must be a regular non-symlink file")
        if metadata.st_size > MAX_RUNTIME_REQUEST_BYTES:
            raise RuntimeRequestError("runtime request exceeds 65536 bytes")
        try:
            raw = candidate.read_text(encoding="utf-8")
        except OSError as error:
            raise RuntimeRequestError(f"request file could not be read: {error}") from error
    else:
        raw = str(request_json)
        if len(raw.encode("utf-8")) > MAX_RUNTIME_REQUEST_BYTES:
            raise RuntimeRequestError("runtime request exceeds 65536 bytes")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeRequestError(f"invalid runtime request JSON: {error}") from error
    try:
        return validate_runtime_request(payload)
    except RuntimeRequestError as error:
        if error.request_context is None:
            error.request_context = runtime_request_error_context(payload)
        raise


_UNASSIGNED_PATH_SCOPED_REASONS = frozenset(
    {"not_git", "missing_repo", "stale_observation"}
)

_FULL_DOCKER_OBSERVER_DOMAIN = "host-runtime-v2:full-docker"
_SERVICE_READY_STATES = frozenset({"running"})
_SERVICE_STOPPED_STATES = frozenset({"stopped"})
_TERMINAL_STATE_MATRIX = {
    "docker": {
        "status": frozenset({"running"}),
        "start": frozenset({"running"}),
        "stop": frozenset({"stopped", "absent"}),
        "restart": frozenset({"running"}),
        "replace": frozenset(),
        "run": frozenset({"running"}),
    },
    "database_stack": {
        "status": frozenset({"running"}),
        "start": frozenset({"running"}),
        "stop": frozenset({"stopped", "absent"}),
        "restart": frozenset({"running"}),
        "replace": frozenset(),
        "run": frozenset({"running"}),
    },
}


def _service_action_result(
    action_result: Mapping[str, Any], *, action: str
) -> Mapping[str, Any] | None:
    if action == "replace":
        # Legacy unsupervised replacement returns {stopped, started}; the
        # atomic worker controller returns the final worker payload directly.
        value = action_result.get("started", action_result)
    elif action == "run":
        value = action_result.get("start")
    else:
        value = action_result
    return value if isinstance(value, Mapping) else None


def _service_terminal_state(
    *,
    request: Mapping[str, Any],
    action_result: Mapping[str, Any],
    inventory: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind a service result to the final normalized identity and endpoint."""

    target = request["target"]
    resource_id = str(target["id"])
    action = str(request["action"])
    observed = _observed_lifecycle(
        inventory, kind="service", resource_id=resource_id
    )
    evidence = {
        "action": action,
        "resource_kind": "service",
        "resource_id": resource_id,
        "proof": "post_observation_inventory",
        **observed["evidence"],
    }
    if observed.get("ok") is not True:
        return _terminal_failure(
            action_result,
            classification=str(observed["classification"]),
            error=str(observed["error"]),
            evidence=evidence,
        )

    state = str(observed["state"])
    expected_result = _service_action_result(action_result, action=action)
    if expected_result is None:
        return _terminal_failure(
            action_result,
            classification="terminal_state_unavailable",
            error="service lifecycle result omitted the exact observed server",
            evidence=evidence,
        )
    expected_id = str(expected_result.get("id") or "")
    if expected_id != resource_id:
        return _terminal_failure(
            action_result,
            classification="lifecycle_target_identity_changed",
            error="service lifecycle result changed immutable identity",
            evidence={**evidence, "result_resource_id": expected_id},
        )

    resource = observed.get("resource")
    observation = observed.get("observation")
    if not isinstance(resource, Mapping) or not isinstance(observation, Mapping):
        return _terminal_failure(
            action_result,
            classification="terminal_state_unavailable",
            error="service lifecycle identity evidence is unavailable",
            evidence=evidence,
        )

    result_generation = expected_result.get("generation")
    observed_generation = resource.get("generation")
    evidence["result_generation"] = result_generation
    evidence["observed_generation"] = observed_generation
    if (
        type(result_generation) is not int
        or type(observed_generation) is not int
        or result_generation != observed_generation
    ):
        return _terminal_failure(
            action_result,
            classification="lifecycle_target_identity_changed",
            error="service definition generation does not match final inventory",
            evidence=evidence,
        )

    leases = inventory.get("leases")
    assignments = inventory.get("port_assignments")
    if not isinstance(leases, list) or not isinstance(assignments, list):
        return _terminal_failure(
            action_result,
            classification="terminal_state_unavailable",
            error="service lease or port-assignment evidence is unavailable",
            evidence=evidence,
        )
    active_leases = [
        item
        for item in leases
        if isinstance(item, Mapping)
        and str(item.get("server_definition_id") or "") == resource_id
        and str(item.get("status") or "") == "active"
    ]
    active_assignments = [
        item
        for item in assignments
        if isinstance(item, Mapping)
        and str(item.get("repo_id") or "") == str(resource.get("repo_id") or "")
        and str(item.get("server_name") or "") == str(resource.get("name") or "")
        and str(item.get("status") or "") == "active"
    ]
    evidence["active_lease_count"] = len(active_leases)
    evidence["active_assignment_count"] = len(active_assignments)
    evidence["observed_state"] = state

    status_request = action == "status"
    status_ready = bool(
        status_request
        and state in _SERVICE_READY_STATES
        and observation.get("health_ok") in {True, 1}
    )
    required_states = (
        frozenset({"running", "starting", "unhealthy", "stopped"})
        if status_request
        else _SERVICE_STOPPED_STATES
        if action == "stop"
        else _SERVICE_READY_STATES
    )
    evidence["required_states"] = sorted(required_states)
    if state not in required_states:
        return _terminal_failure(
            action_result,
            classification="lifecycle_target_not_ready",
            error="service did not reach the requested terminal state",
            evidence=evidence,
        )

    supervision = resource.get("supervision")
    if isinstance(supervision, Mapping):
        current_attempt = supervision.get("current_attempt")
        current_attempt = (
            current_attempt if isinstance(current_attempt, Mapping) else None
        )
        supervisor_state = str(supervision.get("state") or "")
        desired_state = str(supervision.get("desired_state") or "")
        evidence.update(
            {
                "proof": "worker_supervisor_attempt",
                "supervisor_state": supervisor_state,
                "desired_state": desired_state,
                "current_attempt_id": supervision.get("current_attempt_id"),
                "current_attempt_pid": (
                    None if current_attempt is None else current_attempt.get("pid")
                ),
                "current_attempt_process_fingerprint": (
                    None
                    if current_attempt is None
                    else current_attempt.get("process_fingerprint")
                ),
            }
        )
        if active_leases:
            return _terminal_failure(
                action_result,
                classification="terminal_state_ambiguous",
                error=(
                    "supervised worker retains a legacy active lease; stop and "
                    "reinstall its worker definition before starting it"
                ),
                evidence=evidence,
            )
        if action == "stop" or (status_request and state == "stopped"):
            if (
                current_attempt is not None
                or observation.get("pid") is not None
                or (action == "stop" and desired_state != "stopped")
                or (action == "stop" and supervisor_state != "stopped")
            ):
                return _terminal_failure(
                    action_result,
                    classification="lifecycle_target_not_ready",
                    error="supervised worker has not reached its durable stopped boundary",
                    evidence=evidence,
                )
            result = _terminal_success(action_result, evidence=evidence)
            if status_request:
                result["ready"] = False
                result["state"] = state
                result["classification"] = "observed_not_ready"
            return result

        result_pid = expected_result.get("pid")
        result_fingerprint = str(expected_result.get("process_fingerprint") or "")
        attempt_pid = None if current_attempt is None else current_attempt.get("pid")
        attempt_fingerprint = str(
            ""
            if current_attempt is None
            else current_attempt.get("process_fingerprint") or ""
        )
        observed_fingerprint = str(observation.get("process_fingerprint") or "")
        evidence.update(
            {
                "result_pid": result_pid,
                "result_process_fingerprint": result_fingerprint,
                "observed_process_fingerprint": observed_fingerprint,
            }
        )
        if (
            supervisor_state != "running"
            or desired_state != "running"
            or current_attempt is None
            or str(current_attempt.get("state") or "") != "running"
            or type(result_pid) is not int
            or type(attempt_pid) is not int
            or result_pid != attempt_pid
            or observation.get("pid") != attempt_pid
            or not result_fingerprint
            or result_fingerprint != attempt_fingerprint
            or result_fingerprint != observed_fingerprint
            or observation.get("health_ok") not in {True, 1}
        ):
            return _terminal_failure(
                action_result,
                classification="lifecycle_target_identity_changed",
                error=(
                    "worker result, durable supervisor attempt, and process "
                    "observation do not identify one final runtime"
                ),
                evidence=evidence,
            )
        result = _terminal_success(action_result, evidence=evidence)
        if status_request:
            result["ready"] = True
            result["state"] = state
            result["classification"] = "ready"
        return result

    if action == "stop" or (status_request and state == "stopped"):
        if active_leases or active_assignments:
            return _terminal_failure(
                action_result,
                classification="lifecycle_target_not_ready",
                error="stopped service retains an active lease or port assignment",
                evidence=evidence,
            )
        result = _terminal_success(action_result, evidence=evidence)
        if status_request:
            result["ready"] = False
            result["state"] = state
            result["classification"] = "observed_not_ready"
        return result

    result_lease_id = str(expected_result.get("lease_id") or "")
    result_port = expected_result.get("port")
    result_fingerprint = str(expected_result.get("process_fingerprint") or "")
    observed_fingerprint = str(observation.get("process_fingerprint") or "")
    listener_port = observation.get("listener_port")
    evidence.update(
        {
            "result_lease_id": result_lease_id,
            "result_port": result_port,
            "result_process_fingerprint": result_fingerprint,
            "observed_process_fingerprint": observed_fingerprint,
            "listener_port": listener_port,
            "listener_observable": observation.get("listener_observable"),
        }
    )
    if len(active_leases) != 1 or len(active_assignments) != 1:
        return _terminal_failure(
            action_result,
            classification="terminal_state_ambiguous",
            error="running service does not have one exact active lease and assignment",
            evidence=evidence,
        )
    lease = active_leases[0]
    assignment = active_assignments[0]
    if (
        not result_lease_id
        or str(lease.get("lease_id") or "") != result_lease_id
        or type(result_port) is not int
        or type(listener_port) is not int
        or int(result_port) != int(listener_port)
        or int(result_port) != int(lease.get("port") or 0)
        or int(result_port) != int(assignment.get("port") or 0)
        or observation.get("listener_observable") not in {True, 1}
        or not result_fingerprint
        or result_fingerprint != observed_fingerprint
        or str(lease.get("process_fingerprint") or "") != result_fingerprint
    ):
        return _terminal_failure(
            action_result,
            classification="lifecycle_target_identity_changed",
            error=(
                "service result, process, listener, lease, and assignment do not "
                "identify one final runtime"
            ),
            evidence=evidence,
        )
    result = _terminal_success(action_result, evidence=evidence)
    if status_request:
        result["ready"] = status_ready
        result["state"] = state
        result["classification"] = (
            "ready" if status_ready else "observed_not_ready"
        )
    return result


def _terminal_failure(
    action_result: Mapping[str, Any],
    *,
    classification: str,
    error: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    result = dict(action_result)
    result["ok"] = False
    result.pop("terminal_state_pending", None)
    result["classification"] = classification
    result["error"] = error
    result["terminal_state"] = evidence
    return result


def _terminal_success(
    action_result: Mapping[str, Any], *, evidence: dict[str, Any]
) -> dict[str, Any]:
    result = dict(action_result)
    if result.get("classification") == "terminal_state_pending":
        result.pop("classification", None)
        result.pop("error", None)
    result.pop("terminal_state_pending", None)
    result["ok"] = True
    result["terminal_state"] = evidence
    return result


def _inventory_collection(
    inventory: Mapping[str, Any], section: str, collection: str
) -> list[Mapping[str, Any]] | None:
    parent = inventory.get(section)
    if not isinstance(parent, Mapping):
        return None
    rows = parent.get(collection)
    if not isinstance(rows, list) or not all(
        isinstance(item, Mapping) for item in rows
    ):
        return None
    return rows


def _exact_inventory_row(
    inventory: Mapping[str, Any],
    *,
    section: str,
    collection: str,
    id_key: str,
    resource_id: str,
) -> tuple[Mapping[str, Any] | None, int | None]:
    rows = _inventory_collection(inventory, section, collection)
    if rows is None:
        return None, None
    matches = [item for item in rows if str(item.get(id_key) or "") == resource_id]
    return (matches[0] if len(matches) == 1 else None), len(matches)


def _observed_lifecycle(
    inventory: Mapping[str, Any], *, kind: str, resource_id: str
) -> dict[str, Any]:
    if kind == "service":
        collection = "servers"
        id_key = "server_definition_id"
    elif kind == "docker":
        collection = "docker"
        id_key = "docker_resource_id"
    else:  # pragma: no cover - internal boundary
        raise ValueError(f"unsupported lifecycle observation kind {kind}")
    resource, resource_count = _exact_inventory_row(
        inventory,
        section="resources",
        collection=collection,
        id_key=id_key,
        resource_id=resource_id,
    )
    observation, observation_count = _exact_inventory_row(
        inventory,
        section="observations",
        collection=collection,
        id_key=id_key,
        resource_id=resource_id,
    )
    evidence: dict[str, Any] = {
        "resource_kind": kind,
        "resource_id": resource_id,
        "resource_count": resource_count,
        "observation_count": observation_count,
    }
    if resource_count is None or observation_count is None:
        return {
            "ok": False,
            "classification": "terminal_state_unavailable",
            "error": "normalized lifecycle resource or observation collection is unavailable",
            "evidence": evidence,
        }
    if resource_count > 1 or observation_count > 1:
        return {
            "ok": False,
            "classification": "terminal_state_ambiguous",
            "error": "exact lifecycle target resolves more than once",
            "evidence": evidence,
        }
    if resource_count == 0:
        if observation_count != 0:
            return {
                "ok": False,
                "classification": "terminal_state_ambiguous",
                "error": "absent lifecycle target retains an inconsistent observation",
                "evidence": evidence,
            }
        evidence["observed_state"] = "absent"
        return {"ok": True, "state": "absent", "evidence": evidence}
    if observation_count != 1 or observation is None or resource is None:
        return {
            "ok": False,
            "classification": "terminal_state_unavailable",
            "error": "exact lifecycle target has no current normalized observation",
            "evidence": evidence,
        }
    state = str(observation.get("lifecycle") or "").strip().lower()
    if not state:
        return {
            "ok": False,
            "classification": "terminal_state_unavailable",
            "error": "exact lifecycle target observation has no state",
            "evidence": evidence,
        }
    evidence["observed_state"] = state
    evidence["sampled_at"] = observation.get("sampled_at")
    return {
        "ok": True,
        "state": state,
        "resource": resource,
        "observation": observation,
        "evidence": evidence,
    }


def _full_docker_observation_proof(
    observation: Mapping[str, Any], inventory: Mapping[str, Any]
) -> tuple[bool, dict[str, Any]]:
    store = inventory.get("store")
    store = store if isinstance(store, Mapping) else {}
    state_revision = observation.get("state_revision")
    observation_revision = observation.get("observation_revision")
    evidence = {
        "observer_domain": observation.get("observer_domain"),
        "snapshot_id": observation.get("snapshot_id"),
        "docker_available": observation.get("docker_available"),
        "state_revision": state_revision,
        "observation_revision": observation_revision,
        "inventory_state_revision": store.get("state_revision"),
        "inventory_observation_revision": store.get("observation_revision"),
    }
    capability_fingerprint = observation.get("capability_fingerprint")
    valid = (
        observation.get("status") == "completed"
        and observation.get("observed") is True
        and observation.get("observer_domain") == _FULL_DOCKER_OBSERVER_DOMAIN
        and observation.get("docker_available") is True
        and isinstance(observation.get("snapshot_id"), str)
        and bool(str(observation.get("snapshot_id") or ""))
        and isinstance(capability_fingerprint, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", capability_fingerprint) is not None
        and type(state_revision) is int
        and type(observation_revision) is int
        and type(store.get("state_revision")) is int
        and type(store.get("observation_revision")) is int
        and state_revision == store.get("state_revision")
        and observation_revision == store.get("observation_revision")
    )
    return valid, evidence


def _validate_runtime_terminal_state(
    *,
    request: Mapping[str, Any],
    action_result: Mapping[str, Any],
    observation: Mapping[str, Any],
    inventory: Mapping[str, Any],
    pre_inventory: Mapping[str, Any],
) -> dict[str, Any]:
    """Promote a dispatched action to success only from exact observed state."""

    if not (
        action_result.get("ok") is True
        or action_result.get("terminal_state_pending") is True
    ):
        return dict(action_result)
    target = request["target"]
    kind = str(target["kind"])
    action = str(request["action"])
    resource_id = str(target["id"])
    if kind == "service":
        return _service_terminal_state(
            request=request,
            action_result=action_result,
            inventory=inventory,
        )
    required = _TERMINAL_STATE_MATRIX[kind][action]
    base_evidence: dict[str, Any] = {
        "action": action,
        "resource_kind": kind,
        "resource_id": resource_id,
        "required_states": sorted(required),
        "proof": "post_observation_inventory",
    }
    if not required:
        return _terminal_failure(
            action_result,
            classification="unsupported_safe_replace",
            error="Docker/database replacement has no safe terminal-state contract",
            evidence=base_evidence,
        )

    if kind in {"docker", "database_stack"}:
        docker_proved, docker_proof = _full_docker_observation_proof(
            observation, inventory
        )
        base_evidence["observation_proof"] = docker_proof
        if not docker_proved:
            return _terminal_failure(
                action_result,
                classification="terminal_state_unavailable",
                error=(
                    "fresh full-Docker observation does not match the final "
                    "authoritative inventory"
                ),
                evidence=base_evidence,
            )

    if kind == "docker":
        observed = _observed_lifecycle(
            inventory, kind=kind, resource_id=resource_id
        )
        evidence = {**base_evidence, **observed["evidence"]}
        if observed.get("ok") is not True:
            return _terminal_failure(
                action_result,
                classification=str(observed["classification"]),
                error=str(observed["error"]),
                evidence=evidence,
            )
        if action == "status":
            ready = observed["state"] == "running"
            result = _terminal_success(action_result, evidence=evidence)
            result["ready"] = ready
            result["state"] = observed["state"]
            result["classification"] = "ready" if ready else "observed_not_ready"
            return result
        if observed["state"] not in required:
            return _terminal_failure(
                action_result,
                classification="lifecycle_target_not_ready",
                error="exact lifecycle target did not reach the requested terminal state",
                evidence=evidence,
            )
        return _terminal_success(action_result, evidence=evidence)

    database, database_count = _exact_inventory_row(
        inventory,
        section="resources",
        collection="databases",
        id_key="database_binding_id",
        resource_id=resource_id,
    )
    previous_database, previous_count = _exact_inventory_row(
        pre_inventory,
        section="resources",
        collection="databases",
        id_key="database_binding_id",
        resource_id=resource_id,
    )
    if database_count is None or previous_count is None:
        return _terminal_failure(
            action_result,
            classification="terminal_state_unavailable",
            error="normalized database resource collection is unavailable",
            evidence=base_evidence,
        )
    if database_count > 1 or previous_count > 1:
        return _terminal_failure(
            action_result,
            classification="terminal_state_ambiguous",
            error="exact database target resolves more than once",
            evidence={
                **base_evidence,
                "resource_count": database_count,
                "previous_resource_count": previous_count,
            },
        )
    identity_source = database or previous_database
    docker_resource_id = str(
        (identity_source or {}).get("docker_resource_id") or ""
    )
    if not docker_resource_id:
        return _terminal_failure(
            action_result,
            classification="terminal_state_unavailable",
            error="database target has no exact underlying Docker identity",
            evidence=base_evidence,
        )
    if (
        database is not None
        and previous_database is not None
        and str(database.get("docker_resource_id") or "")
        != str(previous_database.get("docker_resource_id") or "")
    ):
        return _terminal_failure(
            action_result,
            classification="lifecycle_target_identity_changed",
            error="database target changed underlying Docker identity",
            evidence={**base_evidence, "docker_resource_id": docker_resource_id},
        )
    container = _observed_lifecycle(
        inventory, kind="docker", resource_id=docker_resource_id
    )
    evidence = {
        **base_evidence,
        "docker_resource_id": docker_resource_id,
        "database_resource_count": database_count,
        **container["evidence"],
    }
    # The database binding is the requested identity; restore it after merging
    # the underlying container evidence.
    evidence["resource_kind"] = kind
    evidence["resource_id"] = resource_id
    evidence["container_observed_state"] = container["evidence"].get(
        "observed_state"
    )
    evidence["observed_state"] = container["evidence"].get("observed_state")
    if container.get("ok") is not True:
        return _terminal_failure(
            action_result,
            classification=str(container["classification"]),
            error=str(container["error"]),
            evidence=evidence,
        )
    if action != "status" and container["state"] not in required:
        return _terminal_failure(
            action_result,
            classification="lifecycle_target_not_ready",
            error="database container did not reach the requested terminal state",
            evidence=evidence,
        )
    database_observation, database_observation_count = _exact_inventory_row(
        inventory,
        section="observations",
        collection="databases",
        id_key="database_binding_id",
        resource_id=resource_id,
    )
    evidence["database_observation_count"] = database_observation_count
    if database_observation_count is None or database_observation_count > 1:
        return _terminal_failure(
            action_result,
            classification=(
                "terminal_state_ambiguous"
                if database_observation_count and database_observation_count > 1
                else "database_readiness_unavailable"
            ),
            error="database readiness observation is unavailable or ambiguous",
            evidence=evidence,
        )
    raw_available = (
        None
        if database_observation is None
        else database_observation.get("available")
    )
    if type(raw_available) is bool:
        available: bool | None = raw_available
    elif type(raw_available) is int and raw_available in {0, 1}:
        available = bool(raw_available)
    else:
        available = None
    evidence["database_available"] = available
    if database_observation is not None:
        evidence["database_sampled_at"] = database_observation.get("sampled_at")
        evidence["database_error_code"] = database_observation.get("error_code")
    if action == "status":
        if database is None or database_observation is None or available is None:
            return _terminal_failure(
                action_result,
                classification="database_readiness_unavailable",
                error="database readiness has no current authoritative observation",
                evidence=evidence,
            )
        ready = container["state"] == "running" and available is True
        result = _terminal_success(action_result, evidence=evidence)
        result["ready"] = ready
        result["state"] = "available" if ready else "unavailable"
        result["classification"] = "ready" if ready else "observed_not_ready"
        return result
    if action == "stop":
        if available is True:
            return _terminal_failure(
                action_result,
                classification="lifecycle_target_not_ready",
                error="stopped database container still reports the database available",
                evidence=evidence,
            )
        return _terminal_success(action_result, evidence=evidence)
    if database is None or database_observation is None or available is None:
        return _terminal_failure(
            action_result,
            classification="database_readiness_unavailable",
            error="database readiness has no current authoritative observation",
            evidence=evidence,
        )
    if available is not True:
        return _terminal_failure(
            action_result,
            classification="database_not_ready",
            error="database container is running but the database is not ready",
            evidence=evidence,
        )
    return _terminal_success(action_result, evidence=evidence)


def validate_runtime_terminal_state(
    *,
    request: Mapping[str, Any],
    action_result: Mapping[str, Any],
    observation: Mapping[str, Any],
    inventory: Mapping[str, Any],
    pre_inventory: Mapping[str, Any],
) -> dict[str, Any]:
    """Public in-process boundary used before a runtime test command executes."""

    return _validate_runtime_terminal_state(
        request=request,
        action_result=action_result,
        observation=observation,
        inventory=inventory,
        pre_inventory=pre_inventory,
    )


def _normalized_absolute_path(value: Any) -> Path | None:
    if not isinstance(value, str) or not value or "\x00" in value:
        return None
    candidate = Path(value)
    if not candidate.is_absolute():
        return None
    return Path(os.path.realpath(os.path.normpath(value)))


def _unassigned_is_plausibly_in_family(
    item: dict[str, Any], *, family_roots: tuple[Path, ...]
) -> bool:
    """Keep unknown attribution fail-closed while excluding proved other paths."""

    reason = str(item.get("reason_code") or "")
    if reason not in _UNASSIGNED_PATH_SCOPED_REASONS:
        return True
    suggested_root = _normalized_absolute_path(item.get("suggested_root"))
    if suggested_root is None:
        return True
    return any(
        suggested_root == root or root in suggested_root.parents
        for root in family_roots
    )


def _classification_evidence(
    store: Any,
    *,
    request: dict[str, Any],
    context: PersistedRepositoryContext,
    inventory: dict[str, Any],
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    target = request["target"]
    with store.read_transaction() as connection:
        family_scopes = list(
            connection.execute(
                """
                SELECT scope.repo_id, repository.canonical_root,
                       repository.host_id
                FROM repository_scopes scope
                JOIN repositories repository USING(repo_id)
                WHERE scope.family_id = ?
                ORDER BY scope.project_kind, repository.canonical_root
                """,
                (context.family_id,),
            )
        )
        family_repo_ids = {
            str(row["repo_id"]) for row in family_scopes
        }
        family_host_ids = {str(row["host_id"]) for row in family_scopes}
        if len(family_host_ids) != 1:
            raise RuntimeError(
                "runtime repository family does not resolve to one host authority"
            )
        family_host_id = next(iter(family_host_ids))
        family_roots = tuple(
            path
            for row in family_scopes
            if (
                path := _normalized_absolute_path(row["canonical_root"])
            ) is not None
        )
        if len(family_roots) != len(family_scopes):
            raise RuntimeError(
                "runtime repository family contains a non-absolute canonical root"
            )
        active_unassigned = [
            dict(row)
            for row in connection.execute(
                """
                SELECT unassigned.resource_kind, unassigned.resource_id,
                       unassigned.display_name, unassigned.reason_code,
                       unassigned.suggested_root
                FROM unassigned_resources unassigned
                LEFT JOIN docker_observations observed_docker
                  ON unassigned.resource_kind = 'container'
                 AND observed_docker.docker_resource_id = unassigned.resource_id
                WHERE unassigned.status = 'active'
                  AND unassigned.host_id = ?
                  AND (
                    unassigned.resource_kind <> 'container'
                    OR observed_docker.lifecycle IS NULL
                    OR observed_docker.lifecycle <> 'stopped'
                  )
                ORDER BY unassigned.resource_kind, unassigned.resource_id
                """,
                (family_host_id,),
            )
        ]
        evidence.extend(
            {"classification": "unclassified_resource", **item}
            for item in active_unassigned
            if _unassigned_is_plausibly_in_family(
                item, family_roots=family_roots
            )
        )

        kind = target["kind"]
        if kind == "service":
            row = connection.execute(
                """
                SELECT server_definition_id, repo_id FROM server_definitions
                WHERE name = ? AND repo_id = ?
                """,
                (target["name"], context.effective_repo_id),
            ).fetchone()
            expected_id = (
                str(row["server_definition_id"])
                if row is not None
                else deterministic_id(
                    "server-definition",
                    context.effective_repo_id,
                    target["name"],
                )
            )
            supplied_id = target.get("id")
            if supplied_id is None and request["action"] in {"start", "run"}:
                target["id"] = expected_id
            elif str(supplied_id or "") != expected_id:
                evidence.append(
                    {
                        "classification": "unclassified_resource",
                        "resource_kind": "service",
                        "resource_id": supplied_id,
                        "expected_resource_id": expected_id,
                        "display_name": target["name"],
                        "reason_code": "identity_mismatch",
                    }
                )
            if row is None and request["action"] not in {"start", "run"}:
                evidence.append(
                    {
                        "classification": "unclassified_resource",
                        "resource_kind": "service",
                        "resource_id": target.get("id"),
                        "display_name": target["name"],
                        "reason_code": "missing_membership",
                    }
                )
            elif (
                row is None
                and request["action"] in {"start", "run"}
                and "argv" not in request["options"]
            ):
                evidence.append(
                    {
                        "classification": "unclassified_resource",
                        "resource_kind": "service",
                        "resource_id": target.get("id"),
                        "display_name": target["name"],
                        "reason_code": "missing_service_definition",
                    }
                )
        elif kind == "docker":
            row = connection.execute(
                """
                SELECT d.docker_resource_id, m.repo_id
                FROM docker_resources d
                LEFT JOIN repository_memberships m
                  ON m.resource_kind = 'container'
                 AND m.host_resource_id = d.docker_resource_id
                WHERE d.docker_resource_id = ?
                """,
                (target["id"],),
            ).fetchone()
            if row is None or str(row["repo_id"] or "") != context.effective_repo_id:
                evidence.append(
                    {
                        "classification": "unclassified_resource",
                        "resource_kind": "docker",
                        "resource_id": target["id"],
                        "reason_code": "missing_membership",
                    }
                )
        else:
            row = connection.execute(
                """
                SELECT b.database_binding_id, b.repo_id, m.repo_id AS container_repo_id
                FROM database_bindings b
                LEFT JOIN repository_memberships m
                  ON m.resource_kind = 'container'
                 AND m.host_resource_id = b.docker_resource_id
                WHERE b.database_binding_id = ?
                """,
                (target["id"],),
            ).fetchone()
            if (
                row is None
                or str(row["repo_id"] or "") != context.effective_repo_id
                or str(row["container_repo_id"] or "") != context.effective_repo_id
            ):
                evidence.append(
                    {
                        "classification": "unclassified_resource",
                        "resource_kind": "database_stack",
                        "resource_id": target["id"],
                        "reason_code": "missing_membership",
                    }
                )
    evidence.extend(
        {
            "classification": "lifecycle_violation",
            **item,
        }
        for item in inventory.get("lifecycle_violations") or []
        if str(item.get("repo_id") or "") in family_repo_ids
    )
    return evidence


def _validate_runtime_paths_in_scope(
    request: dict[str, Any], *, effective_root: str
) -> None:
    root = Path(effective_root)
    candidates: list[tuple[str, str, bool]] = []
    if request["options"].get("cwd"):
        candidates.append(("options.cwd", request["options"]["cwd"], True))
    for index, path in enumerate(request["options"].get("compose_files") or []):
        candidates.append((f"options.compose_files[{index}]", path, False))
    for field, raw, expect_directory in candidates:
        candidate = Path(raw).expanduser()
        try:
            refuse_symlink_components(candidate)
            candidate.lstat()
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise RuntimeRequestError(f"{field} is unavailable: {error}") from error
        if candidate.is_symlink() or (resolved != root and root not in resolved.parents):
            raise RuntimeRequestError(
                f"{field} must be a non-symlink path inside the effective repository"
            )
        if expect_directory and not resolved.is_dir():
            raise RuntimeRequestError(f"{field} must be a directory")
        if not expect_directory and not resolved.is_file():
            raise RuntimeRequestError(f"{field} must be a regular file")


def _runtime_target_needs_log_capture(
    *,
    request: Mapping[str, Any],
    action_result: Mapping[str, Any],
    inventory: Mapping[str, Any],
) -> bool:
    target = request.get("target")
    target = target if isinstance(target, Mapping) else {}
    kind = str(target.get("kind") or "")
    resource_id = str(target.get("id") or "")
    if kind not in {"docker", "database_stack"} or not resource_id:
        return False
    if action_result.get("ok") is not True or request.get("action") == "stop":
        return True
    if kind == "docker":
        observed = _observed_lifecycle(
            inventory, kind="docker", resource_id=resource_id
        )
        return str(observed.get("state") or "") in {
            "dead",
            "exited",
            "failed",
            "stopped",
            "unavailable",
            "unhealthy",
        }
    database, count = _exact_inventory_row(
        inventory,
        section="observations",
        collection="databases",
        id_key="database_binding_id",
        resource_id=resource_id,
    )
    return count == 1 and database is not None and database.get("available") in {
        False,
        0,
    }


def _attach_authoritative_log_capture(
    *,
    callbacks: RuntimeCallbacks,
    request: dict[str, Any],
    project: str,
    action_result: dict[str, Any],
    inventory: Mapping[str, Any],
) -> None:
    if not _runtime_target_needs_log_capture(
        request=request,
        action_result=action_result,
        inventory=inventory,
    ):
        return
    try:
        capture = callbacks.capture_logs(request, project)
        if not isinstance(capture, dict):
            raise RuntimeError("runtime log capture returned a non-object")
    except BaseException as error:
        capture = {
            "availability": "unavailable",
            "reason_code": "authoritative_log_capture_failed",
            "error": str(error),
            "error_type": type(error).__name__,
        }
    action_result["_runtime_log_capture"] = capture


def execute_runtime_request(
    request_payload: Any,
    *,
    store: Any,
    callbacks: RuntimeCallbacks,
) -> dict[str, Any]:
    request = validate_runtime_request(request_payload)
    reject_unsupported_safe_replace(request)
    reaped: list[dict[str, Any]] = []
    if request["action"] != "status":
        reaped = reap_expired_runtime_sessions(store, cleanup=callbacks.cleanup)
    repository_context = resolve_repository_context(
        root_repo=request["root_repo"],
        temporary_repo=request["temporary_repo"],
    )
    _validate_runtime_paths_in_scope(
        request, effective_root=repository_context.effective.canonical_root
    )
    root_repo_id = callbacks.ensure_repository(store, repository_context.root)
    effective_repo_id = callbacks.ensure_repository(store, repository_context.effective)
    persisted = persist_repository_context(
        store,
        repository_context,
        root_repo_id=root_repo_id,
        effective_repo_id=effective_repo_id,
        timestamp=utc_timestamp(),
    )
    try:
        pre_observation = callbacks.observe(
            repository_context.effective.canonical_root
        )
    except BaseException as error:
        raise RuntimeObservationUnavailable(error) from error
    classification_inventory = callbacks.inventory()
    classification_evidence = _classification_evidence(
        store,
        request=request,
        context=persisted,
        inventory=classification_inventory,
    )

    def report(
        *,
        session_id: str | None,
        action_result: dict[str, Any],
        inventory: dict[str, Any],
        cleanup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        value = build_runtime_report(
            request=request,
            session_id=session_id,
            family_id=persisted.family_id,
            root_repo_id=persisted.root_repo_id,
            effective_repo_id=persisted.effective_repo_id,
            project_kind=persisted.project_kind,
            inventory=inventory,
            action_result=action_result,
            reaped_sessions=reaped,
            cleanup=cleanup,
        )
        redacted = redact_runtime_value(value, request=request)
        if not isinstance(redacted, dict):  # pragma: no cover - report is an object
            raise RuntimeError("runtime report redaction returned a non-object")
        return redacted

    if request["action"] == "capture_logs":
        if classification_evidence:
            capture_result: dict[str, Any] = {
                "ok": False,
                "classification": "unclassified_resource",
                "error": (
                    "repository scope contains unclassified or "
                    "lifecycle-violating resources"
                ),
                "evidence": classification_evidence,
            }
        else:
            capture = callbacks.capture_logs(
                request, repository_context.effective.canonical_root
            )
            if not isinstance(capture, dict):
                raise RuntimeError("runtime log capture returned a non-object")
            capture_result = {
                "ok": capture.get("availability") == "available",
                "classification": (
                    "available"
                    if capture.get("availability") == "available"
                    else str(capture.get("reason_code") or "log_capture_unavailable")
                ),
                "_runtime_log_capture": capture,
            }
            if capture_result["ok"] is not True:
                capture_result["error"] = str(
                    capture.get("message") or "runtime log capture is unavailable"
                )
        return report(
            session_id=None,
            action_result=capture_result,
            inventory=classification_inventory,
        )

    if request["action"] == "status":
        if classification_evidence:
            status_result: dict[str, Any] = {
                "ok": False,
                "classification": "unclassified_resource",
                "error": (
                    "repository scope contains unclassified or "
                    "lifecycle-violating resources"
                ),
                "evidence": classification_evidence,
            }
        else:
            def reject_status_link(_resource: dict[str, Any]) -> None:
                raise RuntimeError("read-only status attempted to link a runtime resource")

            try:
                status_result = callbacks.dispatch(
                    request,
                    repository_context.effective.canonical_root,
                    None,
                    reject_status_link,
                )
                if not isinstance(status_result, dict):
                    raise RuntimeError(
                        "runtime lifecycle dispatcher returned a non-object"
                    )
            except BaseException as error:
                status_result = {
                    "ok": False,
                    "classification": str(
                        getattr(error, "payload", {}).get(
                            "classification", "runtime_execution_failed"
                        )
                    ),
                    "error": str(error),
                    "error_type": type(error).__name__,
                }
                structured = getattr(error, "payload", None)
                if isinstance(structured, dict):
                    status_result["evidence"] = structured
        status_result = _validate_runtime_terminal_state(
            request=request,
            action_result=status_result,
            observation=pre_observation,
            inventory=classification_inventory,
            pre_inventory=classification_inventory,
        )
        _attach_authoritative_log_capture(
            callbacks=callbacks,
            request=request,
            project=repository_context.effective.canonical_root,
            action_result=status_result,
            inventory=classification_inventory,
        )
        status_result["observation"] = {"sample": pre_observation}
        return report(
            session_id=None,
            action_result=status_result,
            inventory=classification_inventory,
        )

    needs_cleanup_owner = bool(
        request["ttl_seconds"] is not None
        and request["action"] in {"start", "restart", "replace", "run"}
        and not (
            request["action"] == "run" and request["kill_after_run"] is True
        )
    )
    if needs_cleanup_owner and callbacks.cleanup_owner_available() is not True:
        raise RuntimeCleanupOwnerRequired()

    session_id = create_runtime_session(
        store,
        family_id=persisted.family_id,
        root_repo_id=persisted.root_repo_id,
        repo_id=persisted.effective_repo_id,
        request=request,
    )
    mark_runtime_session_started(store, session_id)
    if classification_evidence:
        action_result = {
            "ok": False,
            "classification": "unclassified_resource",
            "error": "repository scope contains unclassified or lifecycle-violating resources",
            "evidence": classification_evidence,
            "observation": {"before": pre_observation},
        }
        finish_runtime_session(
            store,
            session_id,
            succeeded=False,
            result=action_result,
            keep_running_until_ttl=False,
            redaction_source=request,
        )
        return report(
            session_id=session_id,
            action_result=action_result,
            inventory=classification_inventory,
        )

    cleanup_result: dict[str, Any] | None = None

    def link_resource(resource: dict[str, Any]) -> None:
        if not isinstance(resource, dict):
            raise RuntimeError("runtime lifecycle resource link is not an object")
        link_runtime_resource(
            store,
            session_id=session_id,
            resource_kind=str(resource["kind"]),
            resource_id=str(resource["id"]),
            cleanup_disposition=str(resource["cleanup_disposition"]),
            identity=(
                dict(resource["identity"])
                if isinstance(resource.get("identity"), dict)
                else None
            ),
            immutable_fingerprint=resource.get("immutable_fingerprint"),
        )

    mutation_result: dict[str, Any] | None = None
    post_observation: dict[str, Any] | None = None
    reporting_error: BaseException | None = None
    final_inventory = classification_inventory
    try:
        mutation_result = callbacks.dispatch(
            request,
            repository_context.effective.canonical_root,
            session_id,
            link_resource,
        )
        if not isinstance(mutation_result, dict):
            raise RuntimeError("runtime lifecycle dispatcher returned a non-object")
        resource = mutation_result.pop("_runtime_resource", None)
        if resource is not None:
            link_resource(resource)
        for linked in mutation_result.pop("_runtime_resources", []):
            link_resource(linked)
        try:
            post_observation = callbacks.observe(
                repository_context.effective.canonical_root
            )
            final_inventory = callbacks.inventory()
        except BaseException as error:
            reporting_error = error
            raise
        action_result = _validate_runtime_terminal_state(
            request=request,
            action_result=mutation_result,
            observation=post_observation,
            inventory=final_inventory,
            pre_inventory=classification_inventory,
        )
        _attach_authoritative_log_capture(
            callbacks=callbacks,
            request=request,
            project=repository_context.effective.canonical_root,
            action_result=action_result,
            inventory=final_inventory,
        )
        action_result["observation"] = {
            "before": pre_observation,
            "after": post_observation,
        }
        succeeded = action_result.get("ok") is True
        with store.read_transaction() as connection:
            has_cleanup_resources = (
                connection.execute(
                    """
                    SELECT 1 FROM runtime_session_resources
                    WHERE session_id = ? LIMIT 1
                    """,
                    (session_id,),
                ).fetchone()
                is not None
            )
        keep_running = bool(
            succeeded
            and has_cleanup_resources
            and request["ttl_seconds"] is not None
            and request["action"] in {"start", "restart", "replace", "run"}
        )
        finish_runtime_session(
            store,
            session_id,
            succeeded=succeeded,
            result=action_result,
            keep_running_until_ttl=keep_running,
            redaction_source=request,
        )
        if not succeeded and has_cleanup_resources:
            try:
                cleanup_result = cleanup_runtime_session(
                    store,
                    session_id,
                    cleanup=callbacks.cleanup,
                    expired=False,
                    allow_unexpired=True,
                )
            except BaseException as cleanup_error:
                action_result["cleanup_error"] = {
                    "error": str(cleanup_error),
                    "error_type": type(cleanup_error).__name__,
                }
        if (
            succeeded
            and request["action"] == "run"
            and request["kill_after_run"]
        ):
            cleanup_result = cleanup_runtime_session(
                store,
                session_id,
                cleanup=callbacks.cleanup,
                expired=False,
                allow_unexpired=True,
            )
    except BaseException as execution_error:
        mutation_succeeded = bool(
            mutation_result is not None
            and (
                mutation_result.get("ok") is True
                or mutation_result.get("terminal_state_pending") is True
            )
        )
        if mutation_succeeded:
            action_result = {
                "ok": False,
                "classification": "reconciliation_required",
                "error": (
                    "lifecycle mutation succeeded but post-action "
                    "reconciliation failed"
                ),
                "mutation": mutation_result,
                "reporting_errors": [
                    {
                        "stage": (
                            "post_action_observation_or_inventory"
                            if reporting_error is not None
                            else "post_dispatch_processing"
                        ),
                        "error": str(execution_error),
                        "error_type": type(execution_error).__name__,
                    }
                ],
            }
        else:
            action_result = {
                "ok": False,
                "classification": str(
                    getattr(execution_error, "payload", {}).get(
                        "classification", "runtime_execution_failed"
                    )
                ),
                "error": str(execution_error),
                "error_type": type(execution_error).__name__,
            }
            if mutation_result is not None:
                action_result["mutation"] = mutation_result
            structured = getattr(execution_error, "payload", None)
            if isinstance(structured, dict):
                action_result["evidence"] = structured
        action_result["observation"] = {"before": pre_observation}
        if post_observation is not None:
            action_result["observation"]["after"] = post_observation
        elif reporting_error is not None:
            action_result["observation"]["after_error"] = {
                "error": str(reporting_error),
                "error_type": type(reporting_error).__name__,
            }
        finish_runtime_session(
            store,
            session_id,
            succeeded=False,
            result=action_result,
            keep_running_until_ttl=False,
            redaction_source=request,
        )
        with store.read_transaction() as connection:
            has_cleanup_resources = (
                connection.execute(
                    "SELECT 1 FROM runtime_session_resources WHERE session_id = ? LIMIT 1",
                    (session_id,),
                ).fetchone()
                is not None
            )
        if has_cleanup_resources:
            try:
                cleanup_result = cleanup_runtime_session(
                    store,
                    session_id,
                    cleanup=callbacks.cleanup,
                    expired=False,
                    allow_unexpired=True,
                )
            except BaseException as cleanup_error:
                action_result["cleanup_error"] = {
                    "error": str(cleanup_error),
                    "error_type": type(cleanup_error).__name__,
                }
                finish_runtime_session(
                    store,
                    session_id,
                    succeeded=False,
                    result=action_result,
                    keep_running_until_ttl=False,
                    redaction_source=request,
                )
        try:
            failure_inventory = callbacks.inventory()
        except BaseException as inventory_error:
            failure_inventory = classification_inventory
            action_result["inventory_error"] = {
                "error": str(inventory_error),
                "error_type": type(inventory_error).__name__,
            }
        _attach_authoritative_log_capture(
            callbacks=callbacks,
            request=request,
            project=repository_context.effective.canonical_root,
            action_result=action_result,
            inventory=failure_inventory,
        )
        return report(
            session_id=session_id,
            inventory=failure_inventory,
            action_result=action_result,
            cleanup=cleanup_result,
        )

    try:
        projected = report(
            session_id=session_id,
            inventory=final_inventory,
            action_result=action_result,
            cleanup=cleanup_result,
        )
        if action_result.get("ok") is True and projected.get("ok") is not True:
            raise RuntimeError(
                "successful lifecycle mutation was rejected by the authoritative "
                f"runtime projection: {projected.get('classification') or 'unknown'}"
            )
        return projected
    except BaseException as report_error:
        reconciliation = {
            "ok": False,
            "classification": "reconciliation_required",
            "error": "lifecycle mutation succeeded but report projection failed",
            "mutation": action_result,
            "reporting_errors": [
                {
                    "stage": "report_projection",
                    "error": str(report_error),
                    "error_type": type(report_error).__name__,
                }
            ],
        }
        if cleanup_result is None:
            finish_runtime_session(
                store,
                session_id,
                succeeded=False,
                result=reconciliation,
                keep_running_until_ttl=False,
                redaction_source=request,
            )
        with store.read_transaction() as connection:
            report_failure_has_resources = (
                connection.execute(
                    "SELECT 1 FROM runtime_session_resources WHERE session_id = ? LIMIT 1",
                    (session_id,),
                ).fetchone()
                is not None
            )
        report_failure_cleanup: dict[str, Any] | None = None
        if report_failure_has_resources:
            try:
                report_failure_cleanup = cleanup_runtime_session(
                    store,
                    session_id,
                    cleanup=callbacks.cleanup,
                    expired=False,
                    allow_unexpired=True,
                )
            except BaseException as cleanup_error:
                reconciliation["cleanup_error"] = {
                    "error": str(cleanup_error),
                    "error_type": type(cleanup_error).__name__,
                }
                finish_runtime_session(
                    store,
                    session_id,
                    succeeded=False,
                    result=reconciliation,
                    keep_running_until_ttl=False,
                    redaction_source=request,
                )
        fallback = {
            "schema_version": 1,
            "ok": False,
            "action": request["action"],
            "run_id": session_id,
            "classification": "reconciliation_required",
            "repository": {
                "family_id": persisted.family_id,
                "root_repo_id": persisted.root_repo_id,
                "effective_repo_id": persisted.effective_repo_id,
                "kind": persisted.project_kind,
                "root_repo": request["root_repo"],
                "temporary_repo": request["temporary_repo"],
            },
            "target": request["target"],
            "result": reconciliation,
            "cleanup": report_failure_cleanup,
            "error": reconciliation["error"],
        }
        redacted = redact_runtime_value(fallback, request=request)
        if not isinstance(redacted, dict):  # pragma: no cover
            raise RuntimeError("runtime fallback redaction returned a non-object")
        return redacted
