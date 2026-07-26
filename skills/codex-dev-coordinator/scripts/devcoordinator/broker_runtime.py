"""ID-only broker boundary for the unified runtime API.

The broker resolves only enrolled repository/resource identity.  Service
process lifecycle remains fenced until peer-UID supervision exists; existing
Docker identities may use the broker's typed lifecycle boundary.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .broker import AuthorizedBrokerRequest, BrokerBackendError, BrokerOperation
from .runtime_redaction import redact_runtime_value
from .runtime_report import build_runtime_report


_READY_STATES = {
    "service": frozenset({"running"}),
    "docker": frozenset({"running"}),
    "database_stack": frozenset({"available"}),
}


@dataclass(frozen=True)
class BrokerRuntimeSnapshot:
    context: dict[str, Any]
    inventory: dict[str, Any]
    classification_evidence: list[dict[str, Any]]
    runtime_request: dict[str, Any]
    matching_resources: tuple[dict[str, Any], ...]


def load_broker_runtime_snapshot(
    authorized: AuthorizedBrokerRequest,
    *,
    persistence: Any,
) -> BrokerRuntimeSnapshot:
    """Load one live-authorized repository-family projection."""

    request = authorized.request
    context, inventory, classification_evidence = persistence.runtime_snapshot(
        authorized
    )
    target_kind = str(request.arguments["target_kind"])
    runtime_request = {
        "schema_version": 1,
        "action": str(request.arguments["action"]),
        "agent": str(request.arguments["agent"]),
        "root_repo": context["root_repo"],
        "temporary_repo": context["temporary_repo"],
        "target": {"kind": target_kind, "id": request.resource_id},
        "purpose": str(request.arguments["purpose"]),
        "ttl_seconds": request.arguments["ttl_seconds"],
        "kill_after_run": False,
        "options": {
            key: request.arguments[key]
            for key in (
                "keep_alive",
                "rearm_crash_loop",
                "restart_limit",
                "restart_window_seconds",
            )
            if request.arguments.get(key) is not None
            and not (
                key == "rearm_crash_loop"
                and request.arguments.get(key) is False
            )
        },
    }
    provisional = build_runtime_report(
        request=runtime_request,
        session_id=None,
        family_id=str(context["family_id"]),
        root_repo_id=str(context["root_repo_id"]),
        effective_repo_id=str(context["effective_repo_id"]),
        project_kind=str(context["project_kind"]),
        inventory=inventory,
        action_result={
            "ok": False,
            "classification": "runtime_snapshot",
            "authority": "broker",
            "operation_id": request.operation_id,
        },
    )
    matches = tuple(
        dict(item)
        for item in provisional.get("resources") or []
        if isinstance(item, dict)
        and str(item.get("kind") or "") == target_kind
        and str(item.get("id") or "") == request.resource_id
        and str(item.get("repo_id") or "") == request.project_id
    )
    return BrokerRuntimeSnapshot(
        context=dict(context),
        inventory=dict(inventory),
        classification_evidence=[dict(item) for item in classification_evidence],
        runtime_request=runtime_request,
        matching_resources=matches,
    )


def build_broker_runtime_snapshot_report(
    authorized: AuthorizedBrokerRequest,
    *,
    snapshot: BrokerRuntimeSnapshot,
    action_result: Mapping[str, Any],
) -> dict[str, Any]:
    """Build and redact one broker-authoritative runtime report."""

    context = snapshot.context
    report = build_runtime_report(
        request=snapshot.runtime_request,
        session_id=None,
        family_id=str(context["family_id"]),
        root_repo_id=str(context["root_repo_id"]),
        effective_repo_id=str(context["effective_repo_id"]),
        project_kind=str(context["project_kind"]),
        inventory=snapshot.inventory,
        action_result=dict(action_result),
    )
    redacted = redact_runtime_value(report, request=snapshot.runtime_request)
    if not isinstance(redacted, dict):
        raise RuntimeError("broker runtime report redaction returned a non-object")
    return redacted


def unclassified_broker_runtime_report(
    authorized: AuthorizedBrokerRequest,
    *,
    snapshot: BrokerRuntimeSnapshot,
    observation: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Return a fail-closed report when family/target classification is unsafe."""

    request = authorized.request
    target_kind = str(request.arguments["target_kind"])
    if snapshot.classification_evidence:
        action_result: dict[str, Any] = {
            "ok": False,
            "classification": "unclassified_resource",
            "error": (
                "The repository family contains unclassified or "
                "lifecycle-violating active resources."
            ),
            "authority": "broker",
            "operation_id": request.operation_id,
            "observation": dict(observation),
            "evidence": snapshot.classification_evidence,
        }
    elif len(snapshot.matching_resources) != 1:
        action_result = {
            "ok": False,
            "classification": "unclassified_resource",
            "error": "The broker runtime target is not one exact resource in the effective repository tree.",
            "authority": "broker",
            "operation_id": request.operation_id,
            "observation": dict(observation),
            "evidence": {
                "resource_kind": target_kind,
                "resource_id": request.resource_id,
                "matching_resource_count": len(snapshot.matching_resources),
            },
        }
    else:
        return None
    return build_broker_runtime_snapshot_report(
        authorized,
        snapshot=snapshot,
        action_result=action_result,
    )


def execute_broker_runtime_request(
    authorized: AuthorizedBrokerRequest,
    *,
    persistence: Any,
    observation: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Execute one already-authorized runtime request inside broker authority."""

    request = authorized.request
    if request.operation is not BrokerOperation.RUNTIME_REQUEST:
        raise ValueError("request is not a broker runtime request")
    action = str(request.arguments["action"])
    if action != "status":
        raise BrokerBackendError(
            "runtime_supervisor_required",
            "Service lifecycle requires a broker-owned peer-UID supervisor.",
            operation_id=request.operation_id,
        )

    if observation is None or observation.get("snapshot_id") is None:
        raise BrokerBackendError(
            "lifecycle_observation_incomplete",
            "Runtime status requires one committed service-owned host observation.",
            operation_id=request.operation_id,
        )

    snapshot = load_broker_runtime_snapshot(authorized, persistence=persistence)
    context = snapshot.context
    inventory = snapshot.inventory
    classification_evidence = snapshot.classification_evidence
    target_kind = str(request.arguments["target_kind"])
    matches = snapshot.matching_resources
    if classification_evidence:
        action_result: dict[str, Any] = {
            "ok": False,
            "classification": "unclassified_resource",
            "error": (
                "The repository family contains unclassified or "
                "lifecycle-violating active resources."
            ),
            "authority": "broker",
            "operation_id": request.operation_id,
            "observation": dict(observation),
            "evidence": classification_evidence,
        }
    elif len(matches) != 1:
        action_result = {
            "ok": False,
            "classification": "unclassified_resource",
            "error": "The broker status target is not one exact resource in the effective repository tree.",
            "authority": "broker",
            "operation_id": request.operation_id,
            "observation": dict(observation),
            "evidence": {
                "resource_kind": target_kind,
                "resource_id": request.resource_id,
                "matching_resource_count": len(matches),
            },
        }
    else:
        state = str(matches[0].get("state") or "unobserved").lower()
        ready = state in _READY_STATES[target_kind]
        action_result = {
            # Status succeeded when the exact target was freshly and
            # authoritatively observed.  Readiness is a property of that
            # result, not a transport/API failure.
            "ok": True,
            "classification": "ready" if ready else "observed_not_ready",
            "ready": ready,
            "authority": "broker",
            "operation_id": request.operation_id,
            "observation": dict(observation),
            "state": state,
            "resource_id": request.resource_id,
        }
        if not ready:
            action_result["message"] = (
                f"The exact {target_kind} target is {state}, not ready."
            )
    return build_broker_runtime_snapshot_report(
        authorized,
        snapshot=snapshot,
        action_result=action_result,
    )
