"""Python-owned composite test intents and compact run projections."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
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
REVIEW_INTENTS = frozenset({"handoff", "release"})
TERMINAL_STATES = frozenset(
    {
        "succeeded",
        "failed",
        "test_failed",
        "infrastructure_failed",
        "timed_out",
        "cancelled",
        "incomplete",
        "abandoned",
        "superseded",
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
    plan_document = preview.get("plan")
    if not isinstance(plan_document, Mapping):
        raise AgentTestError("test_reply_invalid", "test preview omitted its plan")

    # The producer-owned decoder verifies the complete plan, including source,
    # manifest, selection, timeouts, and fingerprints.  Only its compact
    # projection crosses the caller boundary.
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
    ):
        raise AgentTestError(
            "test_reply_invalid", "test preview contradicted repository, intent, or timeout"
        )
    plan_id = _opaque(preview.get("plan_id"), field="plan_id")
    if plan_id != plan.plan_id:
        raise AgentTestError(
            "test_reply_invalid", "registered plan identity is contradictory"
        )
    plan_projection = _compact_plan(plan)

    if intent in REVIEW_INTENTS:
        return require_agent_result(
            {
                "schema_version": 1,
                "ok": True,
                "classification": "review_required",
                "review_required": True,
                "repository_id": repository.repo_id,
                "operation_id": operation_id,
                "continuation": continuation_handle("operation", operation_id),
                "plan": plan_projection,
                "plan_handle": continuation_handle("plan", plan_id),
                "submission_performed": False,
                "next_command": (
                    f"devcoordinator test submit {continuation_handle('plan', plan_id)}"
                ),
            },
            surface="test review",
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
            "review_required": False,
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


def submit_reviewed_plan(
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
        "counts": _small_mapping(source.get("counts"), limit=16),
        "timing": _small_mapping(source.get("timing"), limit=12),
        "failures": failures,
        "failure_count": (
            source.get("failure_count")
            if type(source.get("failure_count")) is int
            else len(failures)
        ),
        "next_command": (
            None
            if terminal
            else f"devcoordinator test follow {run_handle} --wait-seconds 30"
        ),
    }
    for visible_failures in range(len(failures), -1, -1):
        candidate = dict(document)
        candidate["failures"] = failures[:visible_failures]
        candidate["failures_truncated"] = visible_failures < len(failures)
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
    "REVIEW_INTENTS",
    "TERMINAL_STATES",
    "TEST_INTENTS",
    "child_operation_id",
    "enqueue_test",
    "project_test_follow",
    "submit_reviewed_plan",
]
