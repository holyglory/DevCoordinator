"""Python-owned composite test intents and compact run projections."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import math
from typing import Any
import uuid

from .agent_contract import (
    AgentContractError,
    bounded_text,
    canonical_json_bytes,
    continuation_handle,
    require_agent_result,
)


MAX_TEST_RESULT_BYTES = 4 * 1024
TEST_INTENTS = frozenset({"change", "checkpoint", "handoff", "release", "manual"})
TERMINAL_STATES = frozenset(
    {
        "succeeded",
        "failed",
        "timed_out",
        "cancelled",
        "incomplete",
    }
)


class AgentTestError(AgentContractError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def child_operation_id(workflow_operation_id: str, stage: str) -> str:
    """Derive one stable child mutation identity from a caller-visible root."""

    try:
        root = uuid.UUID(workflow_operation_id)
    except (ValueError, AttributeError) as error:
        raise AgentTestError(
            "operation_id_invalid", "test workflow operation ID is not a UUID"
        ) from error
    if str(root) != workflow_operation_id:
        raise AgentTestError(
            "operation_id_invalid", "test workflow operation ID is not canonical"
        )
    if stage not in {"submit"}:
        raise AgentTestError("workflow_stage_invalid", "test workflow stage is invalid")
    return str(uuid.uuid5(root, f"devcoordinator:test:{stage}:v1"))


def _opaque(value: object, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 256
        or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:@-" for character in value)
        or value[0] in "_.:@-"
    ):
        raise AgentTestError("test_reply_invalid", f"test reply {field} is invalid")
    return value


def _compact_plan(plan: Any) -> dict[str, Any]:
    selection = getattr(plan, "selection", None)
    if not isinstance(selection, Mapping):
        raise AgentTestError("test_reply_invalid", "test plan selection is malformed")
    targets = sorted(str(item) for item in selection)[:16]
    source = getattr(plan, "source", None)
    source_mode = getattr(getattr(source, "mode", None), "value", None)
    return {
        "id": _opaque(getattr(plan, "plan_id", None), field="plan_id"),
        "intent": str(getattr(plan, "intent", "")),
        "fingerprint": str(getattr(plan, "fingerprint", "")),
        "source": {
            "mode": source_mode,
            "snapshot_id": getattr(source, "snapshot_id", None),
        },
        "selection": {
            "count": len(selection),
            "targets": targets,
            "truncated": len(selection) > len(targets),
        },
    }


def enqueue_test(
    *,
    profile: Any,
    repository: Any,
    temporary_repository: Any | None,
    intent: str,
    requested_targets: Sequence[str],
    execution_timeout_seconds: int | None,
    launch_timeout_seconds: int,
    actor: str,
    operation_id: str,
) -> dict[str, Any]:
    """Register and, for routine intents, submit one replay-safe test plan."""

    if intent not in TEST_INTENTS:
        raise AgentTestError("test_intent_invalid", "test intent is unsupported")
    if requested_targets and intent != "manual":
        raise AgentTestError(
            "test_targets_forbidden", "explicit targets are supported only for manual intent"
        )
    if len(requested_targets) > 256 or len(set(requested_targets)) != len(requested_targets):
        raise AgentTestError(
            "test_targets_invalid", "test targets must be unique and no more than 256"
        )

    preview = profile.preview_test_plan(
        repository=repository.repo_id,
        intent=intent,
        temporary_root=(
            temporary_repository.canonical_root
            if temporary_repository is not None
            else None
        ),
        requested_targets=tuple(requested_targets),
        execution_timeout_seconds=execution_timeout_seconds,
        launch_timeout_seconds=launch_timeout_seconds,
        operation_id=operation_id,
    )
    if not isinstance(preview, Mapping):
        raise AgentTestError("test_reply_invalid", "test preview reply is not an object")
    if preview.get("operation_id") != operation_id:
        raise AgentTestError(
            "test_reply_invalid", "test preview contradicted its operation identity"
        )
    plan_id = _opaque(preview.get("plan_id"), field="plan_id")
    plan_document = preview.get("plan")
    if isinstance(plan_document, Mapping):
        # The producer-owned decoder verifies the complete plan, including
        # source, manifest, selection, timeouts, and fingerprints. Only its
        # compact projection crosses the caller boundary.
        from .universal_test_service import decode_test_plan_document

        plan = decode_test_plan_document(plan_document)
        if (
            plan.repository_id != repository.repo_id
            or plan.intent != intent
            or plan.timeouts.execution_seconds != execution_timeout_seconds
            or plan.timeouts.launch_seconds != launch_timeout_seconds
            or plan.source.original_root != repository.canonical_root
            or plan.source.temporary_root
            != (
                temporary_repository.canonical_root
                if temporary_repository is not None
                else None
            )
            or plan_id != plan.plan_id
        ):
            raise AgentTestError(
                "test_reply_invalid",
                "test preview contradicted repository, intent, or timeout",
            )
        plan_projection = _compact_plan(plan)
    elif preview.get("classification") == "test_plan_preview_completed":
        fingerprint = preview.get("plan_fingerprint")
        source_mode = preview.get("source_mode")
        selected_count = preview.get("selected_target_count")
        selected_targets = preview.get("selected_targets")
        selected_truncated = preview.get("selected_targets_truncated")
        if (
            preview.get("repository_id") != repository.repo_id
            or preview.get("intent") != intent
            or preview.get("operation_id") != operation_id
            or not isinstance(fingerprint, str)
            or len(fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in fingerprint)
            or source_mode not in {"live", "immutable"}
            or (intent in {"handoff", "release"} and source_mode != "immutable")
            or type(selected_count) is not int
            or selected_count < 0
            or not isinstance(selected_targets, list)
            or not all(isinstance(item, str) and item for item in selected_targets)
            or len(selected_targets) > 16
            or type(selected_truncated) is not bool
            or selected_truncated != (selected_count > len(selected_targets))
        ):
            raise AgentTestError(
                "test_reply_invalid", "durable test preview replay is contradictory"
            )
        plan_projection = {
            "id": plan_id,
            "intent": intent,
            "fingerprint": fingerprint,
            "source": {
                "mode": source_mode,
                "snapshot_id": preview.get("snapshot_id"),
            },
            "selection": {
                "count": selected_count,
                "targets": list(selected_targets),
                "truncated": selected_truncated,
            },
            "replayed": True,
        }
    else:
        raise AgentTestError("test_reply_invalid", "test preview omitted its plan")

    if intent in {"handoff", "release"}:
        plan_handle = continuation_handle("plan", plan_id)
        return require_agent_result(
            {
                "schema_version": 1,
                "ok": True,
                "classification": "test_plan_ready",
                "repository_id": repository.repo_id,
                "operation_id": operation_id,
                "continuation": plan_handle,
                "plan": plan_projection,
                "submission_performed": False,
                "next_command": f"devcoordinator test submit {plan_handle}",
            },
            surface="test enqueue",
            maximum_bytes=MAX_TEST_RESULT_BYTES,
        )

    submit_operation_id = child_operation_id(operation_id, "submit")
    submitted = profile.submit_test_plan(
        repository=repository.repo_id,
        plan_id=plan_id,
        operation_id=submit_operation_id,
        actor=actor,
    )
    if not isinstance(submitted, Mapping):
        raise AgentTestError("test_reply_invalid", "test submission reply is not an object")
    run_id = _opaque(submitted.get("run_id"), field="run_id")
    if submitted.get("repository_id") != repository.repo_id:
        raise AgentTestError(
            "test_reply_invalid", "test submission contradicted repository identity"
        )
    if submitted.get("operation_id") not in {None, submit_operation_id}:
        raise AgentTestError(
            "test_reply_invalid", "test submission contradicted operation identity"
        )
    state = bounded_text(submitted.get("state", "queued"), maximum_bytes=64)
    run_handle = continuation_handle("run", run_id)
    return require_agent_result(
        {
            "schema_version": 1,
            "ok": True,
            "classification": "test_enqueued",
            "repository_id": repository.repo_id,
            "operation_id": operation_id,
            "submission_operation_id": submit_operation_id,
            "continuation": run_handle,
            "plan": plan_projection,
            "run": {"id": run_id, "state": state},
            "submission_performed": True,
            "next_command": f"devcoordinator test follow {run_handle}",
        },
        surface="test enqueue",
        maximum_bytes=MAX_TEST_RESULT_BYTES,
    )


def submit_test_plan(
    *,
    profile: Any,
    repository: Any,
    plan_id: str,
    actor: str,
    operation_id: str,
) -> dict[str, Any]:
    submitted = profile.submit_test_plan(
        repository=repository.repo_id,
        plan_id=_opaque(plan_id, field="plan_id"),
        operation_id=operation_id,
        actor=actor,
    )
    if not isinstance(submitted, Mapping):
        raise AgentTestError("test_reply_invalid", "test submission reply is not an object")
    run_id = _opaque(submitted.get("run_id"), field="run_id")
    if submitted.get("repository_id") != repository.repo_id:
        raise AgentTestError(
            "test_reply_invalid", "test submission contradicted repository identity"
        )
    run_handle = continuation_handle("run", run_id)
    return require_agent_result(
        {
            "schema_version": 1,
            "ok": True,
            "classification": "test_enqueued",
            "repository_id": repository.repo_id,
            "operation_id": operation_id,
            "continuation": run_handle,
            "plan_id": plan_id,
            "run": {
                "id": run_id,
                "state": bounded_text(submitted.get("state", "queued"), maximum_bytes=64),
            },
            "submission_performed": True,
            "next_command": f"devcoordinator test follow {run_handle}",
        },
        surface="reviewed test submission",
        maximum_bytes=MAX_TEST_RESULT_BYTES,
    )


def project_queue_status(
    status: Mapping[str, Any], *, repository_id: str
) -> dict[str, Any]:
    """Validate and bound repository queue evidence for agent callers."""

    if status.get("repository_id") != repository_id:
        raise AgentTestError(
            "test_reply_invalid", "queue status contradicted repository identity"
        )
    result = {
        "schema_version": 1,
        "ok": True,
        "classification": "test_queue_status",
        "repository_id": repository_id,
        "sampled_at": status.get("sampled_at"),
        "phase": bounded_text(status.get("phase", "unknown"), maximum_bytes=64),
        "global_targets": _small_mapping(status.get("global_targets"), limit=4),
        "repository_targets": _small_mapping(
            status.get("repository_targets"), limit=4
        ),
        "repository_runnable_targets": status.get("repository_runnable_targets"),
        "approximate_first_position": status.get("approximate_first_position"),
        "position_population_truncated": bool(
            status.get("position_population_truncated")
        ),
        "blockers": [
            {
                "code": bounded_text(item.get("code", "unknown"), maximum_bytes=64),
                "target_count": item.get("target_count"),
            }
            for item in status.get("blockers", [])[:16]
            if isinstance(item, Mapping)
        ],
        "representative_targets": [
            {
                "run_id": _opaque(item.get("run_id"), field="run_id"),
                "target_name": _opaque(
                    item.get("target_name"), field="target_name"
                ),
                "state": bounded_text(
                    item.get("state", "unknown"), maximum_bytes=64
                ),
                "execution_id": (
                    None
                    if item.get("execution_id") is None
                    else _opaque(item.get("execution_id"), field="execution_id")
                ),
                "wait_code": (
                    None
                    if item.get("wait_code") is None
                    else bounded_text(item.get("wait_code"), maximum_bytes=64)
                ),
            }
            for item in status.get("representative_targets", [])[:16]
            if isinstance(item, Mapping)
        ],
        "worker_capacity": {
            "model": bounded_text(
                (
                    status.get("worker_capacity", {}).get("model", "unknown")
                    if isinstance(status.get("worker_capacity"), Mapping)
                    else "unknown"
                ),
                maximum_bytes=64,
            ),
            "limit": (
                status.get("worker_capacity", {}).get("limit")
                if isinstance(status.get("worker_capacity"), Mapping)
                else None
            ),
            "available": (
                status.get("worker_capacity", {}).get("available")
                if isinstance(status.get("worker_capacity"), Mapping)
                else None
            ),
        },
    }
    return require_agent_result(
        result,
        surface="test queue status",
        maximum_bytes=MAX_TEST_RESULT_BYTES,
    )


def _small_mapping(value: object, *, limit: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, Any] = {}
    for key in sorted(value)[:limit]:
        item = value[key]
        if isinstance(item, bool) or isinstance(item, int):
            result[bounded_text(key, maximum_bytes=64)] = item
        elif isinstance(item, float) and item == item and abs(item) != float("inf"):
            result[bounded_text(key, maximum_bytes=64)] = item
    return result


def _scheduler_wait_projection(status: Mapping[str, Any]) -> dict[str, Any]:
    """Expose bounded typed admission evidence for a pending exact run."""

    waits: list[dict[str, Any]] = []
    total = 0
    targets = status.get("targets")
    if isinstance(targets, list):
        for raw_target in targets:
            if not isinstance(raw_target, Mapping):
                continue
            raw_wait = raw_target.get("wait")
            if not isinstance(raw_wait, Mapping) or raw_wait.get("code") is None:
                continue
            total += 1
            if len(waits) >= 3:
                continue
            wait: dict[str, Any] = {
                "target": bounded_text(
                    raw_target.get("target_name") or raw_target.get("target_id") or "unknown",
                    maximum_bytes=128,
                ),
                "code": bounded_text(raw_wait.get("code"), maximum_bytes=64),
            }
            for key in ("since", "required_mib", "available_mib", "reserve_mib"):
                value = raw_wait.get(key)
                if isinstance(value, bool):
                    continue
                if isinstance(value, (int, float)) and value == value and abs(value) != float("inf"):
                    wait[key] = value
            waits.append(wait)
    return {
        "target_count": total,
        "targets": waits,
        "truncated": total > len(waits),
    }


def project_test_follow(
    status: Mapping[str, Any],
    *,
    run_id: str,
    summary: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return only the current decision surface for one exact run."""

    if not isinstance(status, Mapping) or status.get("run_id") != run_id:
        raise AgentTestError("test_reply_invalid", "test status contradicted run identity")
    source = summary if isinstance(summary, Mapping) else status
    if source.get("run_id") not in {None, run_id}:
        raise AgentTestError("test_reply_invalid", "test summary contradicted run identity")
    state = bounded_text(
        status.get("state") or status.get("status") or source.get("conclusion") or "unknown",
        maximum_bytes=64,
    )
    terminal = state in TERMINAL_STATES or str(source.get("conclusion") or "") in TERMINAL_STATES
    run_handle = continuation_handle("run", run_id)
    failures: list[dict[str, Any]] = []
    raw_failures = source.get("failures")
    if isinstance(raw_failures, list):
        for raw in raw_failures[:3]:
            if not isinstance(raw, Mapping):
                continue
            failure = {
                key: bounded_text(raw[key], maximum_bytes=256)
                for key in ("target", "message", "location", "artifact_id", "classification")
                if raw.get(key) is not None
            }
            failures.append(failure)
    counts = _small_mapping(source.get("counts"), limit=16)
    declared_failure_records = (
        source.get("failure_count")
        if type(source.get("failure_count")) is int
        else len(raw_failures)
        if isinstance(raw_failures, list)
        else len(failures)
    )
    failed_cases = (
        counts.get("failed")
        if type(counts.get("failed")) is int
        else declared_failure_records
    )
    source_failure_count = max(declared_failure_records, len(failures))
    active_executions: list[dict[str, Any]] = []
    raw_targets = status.get("targets")
    if isinstance(raw_targets, list):
        for raw_target in raw_targets:
            if not isinstance(raw_target, Mapping):
                continue
            raw_execution = raw_target.get("execution")
            if not isinstance(raw_execution, Mapping):
                continue
            execution_id = raw_execution.get("execution_id")
            execution_state = raw_execution.get("state")
            generation = raw_execution.get("generation")
            systemd_unit = raw_execution.get("systemd_unit")
            launch_confirmed = raw_execution.get("launch_confirmed")
            target_name = raw_target.get("target_name")
            if not all(
                isinstance(value, str) and value
                for value in (execution_id, execution_state, target_name)
            ):
                continue
            if execution_state not in {"starting", "running", "stopping"}:
                continue
            if (
                type(generation) is not int
                or generation <= 0
                or not isinstance(systemd_unit, str)
                or not systemd_unit
                or type(launch_confirmed) is not bool
            ):
                continue
            active = {
                "execution_id": bounded_text(execution_id, maximum_bytes=128),
                "target": bounded_text(target_name, maximum_bytes=128),
                "state": bounded_text(execution_state, maximum_bytes=64),
                "generation": generation,
                "systemd_unit": bounded_text(systemd_unit, maximum_bytes=256),
                "launch_confirmed": launch_confirmed,
                "output_progress": None,
            }
            for key in (
                "started_at",
                "last_observed_at",
                "launch_deadline_at",
                "execution_deadline_at",
            ):
                value = raw_execution.get(key)
                if value is None:
                    active[key] = None
                    continue
                if (
                    not isinstance(value, bool)
                    and isinstance(value, (int, float))
                    and math.isfinite(float(value))
                    and float(value) >= 0
                ):
                    active[key] = float(value)
            sampled_at = status.get("sampled_at")
            started_at = raw_execution.get("started_at")
            if (
                not isinstance(sampled_at, bool)
                and isinstance(sampled_at, (int, float))
                and not isinstance(started_at, bool)
                and isinstance(started_at, (int, float))
            ):
                active["elapsed_seconds"] = max(
                    0.0, float(sampled_at) - float(started_at)
                )
            raw_progress = raw_execution.get("output_progress")
            if isinstance(raw_progress, Mapping):
                stdout_bytes = raw_progress.get("stdout_bytes")
                stderr_bytes = raw_progress.get("stderr_bytes")
                stdout_retained_bytes = raw_progress.get(
                    "stdout_retained_bytes"
                )
                stderr_retained_bytes = raw_progress.get(
                    "stderr_retained_bytes"
                )
                stdout_truncated = raw_progress.get("stdout_truncated")
                stderr_truncated = raw_progress.get("stderr_truncated")
                current_memory_bytes = raw_progress.get("current_memory_bytes")
                observed_at = raw_progress.get("observed_at")
                last_output_at = raw_progress.get("last_output_at")
                if (
                    type(stdout_bytes) is int
                    and type(stderr_bytes) is int
                    and type(stdout_retained_bytes) is int
                    and type(stderr_retained_bytes) is int
                    and type(stdout_truncated) is bool
                    and type(stderr_truncated) is bool
                    and (
                        current_memory_bytes is None
                        or type(current_memory_bytes) is int
                    )
                    and not isinstance(observed_at, bool)
                    and isinstance(observed_at, (int, float))
                    and (
                        last_output_at is None
                        or (
                            not isinstance(last_output_at, bool)
                            and isinstance(last_output_at, (int, float))
                        )
                    )
                ):
                    active["output_progress"] = {
                        "stdout_bytes": stdout_bytes,
                        "stderr_bytes": stderr_bytes,
                        "stdout_retained_bytes": stdout_retained_bytes,
                        "stderr_retained_bytes": stderr_retained_bytes,
                        "stdout_truncated": stdout_truncated,
                        "stderr_truncated": stderr_truncated,
                        "current_memory_bytes": current_memory_bytes,
                        "last_output_at": (
                            None
                            if last_output_at is None
                            else float(last_output_at)
                        ),
                        "observed_at": float(observed_at),
                    }
            active_executions.append(active)
    document: dict[str, Any] = {
        "schema_version": 1,
        "ok": True,
        "classification": "test_terminal" if terminal else "test_pending",
        "continuation": run_handle,
        "run": {
            "id": run_id,
            "state": state,
            "terminal": terminal,
            "conclusion": source.get("conclusion"),
            "wait_timed_out": status.get("wait_timed_out") is True,
        },
        "progress": _small_mapping(source.get("progress"), limit=12),
        "counts": counts,
        "timing": _small_mapping(source.get("timing"), limit=12),
        "scheduler_wait": _scheduler_wait_projection(status),
        "active_executions": active_executions[:4],
        "active_executions_truncated": len(active_executions) > 4,
        "failures": failures,
        # ``counts.failed`` counts failed test cases, while the summary's
        # ``failure_count`` counts independently retained failure records.
        # Keep both dimensions explicit and make the long-standing public
        # ``failure_count`` agree with the case counts callers compare it to.
        "failure_count": failed_cases,
        "failure_record_count": source_failure_count,
        "next_command": (
            f"devcoordinator test failures {run_handle}"
            if terminal and source_failure_count > 0
            else None
            if terminal
            else f"devcoordinator test follow {run_handle} --wait-seconds 30"
        ),
    }
    for visible_failures in range(len(failures), -1, -1):
        candidate = dict(document)
        candidate["failures"] = failures[:visible_failures]
        candidate["failures_truncated"] = (
            visible_failures < source_failure_count
        )
        if len(canonical_json_bytes(candidate)) <= MAX_TEST_RESULT_BYTES:
            return require_agent_result(
                candidate,
                surface="test follow",
                maximum_bytes=MAX_TEST_RESULT_BYTES,
            )
    raise AgentTestError(
        "test_projection_too_large", "mandatory test status exceeds its result bound"
    )


__all__ = [
    "AgentTestError",
    "MAX_TEST_RESULT_BYTES",
    "TERMINAL_STATES",
    "TEST_INTENTS",
    "child_operation_id",
    "enqueue_test",
    "project_queue_status",
    "project_test_follow",
    "submit_test_plan",
]
