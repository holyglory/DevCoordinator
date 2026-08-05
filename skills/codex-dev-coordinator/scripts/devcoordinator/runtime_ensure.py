"""Compact desired-state decisions and evidence for broker runtime ensure."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Mapping


RUNTIME_ENSURE_RESULT_MAX_BYTES = 2_048
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}")
_DESIRED_STATES = frozenset({"ready", "stopped"})
_RESOURCE_KINDS = frozenset({"service", "docker", "database_stack"})
_UNHEALTHY = frozenset(
    {
        "crash",
        "crashed",
        "dead",
        "exited",
        "failed",
        "failure",
        "tripped",
        "unavailable",
        "unhealthy",
    }
)


@dataclass(frozen=True)
class RuntimeEnsureDecision:
    """One fail-closed action selected from fresh exact runtime evidence."""

    desired_state: str
    observed_state: str
    action: str | None
    classification: str
    reason: str | None

    @property
    def attention_required(self) -> bool:
        return self.classification == "attention_required"

    @property
    def already_desired(self) -> bool:
        return self.classification.startswith("already_")


def _identifier(value: object, *, fallback: str = "unknown") -> str:
    if isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None:
        return value
    return fallback


def _lower(value: object) -> str:
    return str(value or "").strip().lower()


def observed_runtime_state(observation: Mapping[str, Any]) -> str:
    """Normalize exact host evidence to ready/stopped/unhealthy/unknown."""

    kind = _lower(observation.get("resource_kind"))
    lifecycle = _lower(observation.get("lifecycle"))
    health = _lower(observation.get("health"))
    if observation.get("exact") is not True or kind not in _RESOURCE_KINDS:
        return "unknown"

    if kind == "service":
        health_classification = _lower(observation.get("health_classification"))
        breaker_state = _lower(observation.get("breaker_state"))
        if breaker_state == "tripped" or health_classification in _UNHEALTHY:
            return "unhealthy"
        if lifecycle == "stopped":
            return "stopped"
        if lifecycle == "running":
            return "ready" if observation.get("health_ok") is True else "unhealthy"
        if lifecycle in _UNHEALTHY:
            return "unhealthy"
        return "unknown"

    if kind == "docker":
        if lifecycle == "stopped":
            return "stopped"
        if lifecycle == "running" and health not in _UNHEALTHY | {"starting"}:
            return "ready"
        if lifecycle in _UNHEALTHY or health in _UNHEALTHY:
            return "unhealthy"
        return "unknown"

    docker_lifecycle = _lower(observation.get("docker_lifecycle")) or lifecycle
    if docker_lifecycle == "stopped":
        return "stopped"
    if docker_lifecycle in _UNHEALTHY:
        return "unhealthy"
    if docker_lifecycle != "running":
        return "unknown"
    available = observation.get("database_available")
    if available is True:
        return "ready"
    if available is False:
        return "unhealthy"
    return "unknown"


def decide_runtime_ensure(
    observation: Mapping[str, Any],
    *,
    desired_state: str,
    family_classified: bool,
) -> RuntimeEnsureDecision:
    """Select only a no-op, start, stop, or explicit attention outcome."""

    if desired_state not in _DESIRED_STATES:
        raise ValueError("runtime ensure desired state is invalid")
    if not family_classified:
        return RuntimeEnsureDecision(
            desired_state,
            "unclassified",
            None,
            "attention_required",
            "repository_family_unclassified",
        )
    observed = observed_runtime_state(observation)
    if observed in {"unknown", "unhealthy"}:
        return RuntimeEnsureDecision(
            desired_state,
            observed,
            None,
            "attention_required",
            "target_" + observed,
        )
    if observed == desired_state:
        return RuntimeEnsureDecision(
            desired_state,
            observed,
            None,
            "already_" + desired_state,
            None,
        )
    return RuntimeEnsureDecision(
        desired_state,
        observed,
        "start" if desired_state == "ready" else "stop",
        "mutation_required",
        None,
    )


def worker_result_observation(
    *, resource_id: str, controlled: Mapping[str, Any]
) -> dict[str, Any]:
    """Project a worker controller result back into the ensure state contract."""

    health = controlled.get("health")
    supervision = controlled.get("supervision")
    return {
        "exact": True,
        "resource_kind": "service",
        "resource_id": resource_id,
        "lifecycle": controlled.get("status"),
        "health_ok": health.get("ok") if isinstance(health, Mapping) else None,
        "health_classification": (
            health.get("classification") if isinstance(health, Mapping) else None
        ),
        "breaker_state": (
            supervision.get("breaker_state")
            if isinstance(supervision, Mapping)
            else None
        ),
    }


def build_runtime_ensure_result(
    *,
    operation_id: str,
    repository_id: str,
    repository_generation: int,
    resource_kind: str,
    resource_id: str,
    desired_state: str,
    decision: RuntimeEnsureDecision,
    mutation_performed: bool,
    terminal_observation: Mapping[str, Any],
    snapshot_id: str | None,
    proof_source: str,
    certain: bool = True,
    family_classified: bool = True,
) -> dict[str, Any]:
    """Build one path-free result and enforce its complete two-KiB ceiling.

    ``mutation_performed`` means the broker invoked the selected typed mutation;
    a false value proves that no start/stop call crossed the host boundary.
    """

    if type(repository_generation) is not int or repository_generation < 0:
        raise ValueError("runtime ensure repository generation is invalid")
    if (
        type(mutation_performed) is not bool
        or type(certain) is not bool
        or type(family_classified) is not bool
    ):
        raise TypeError("runtime ensure proof flags must be booleans")
    final_state = observed_runtime_state(terminal_observation)
    final_decision = decide_runtime_ensure(
        terminal_observation,
        desired_state=desired_state,
        family_classified=family_classified and final_state != "unknown",
    )
    classification = decision.classification
    reason = decision.reason
    ok = decision.already_desired
    if (
        mutation_performed
        and certain
        and family_classified
        and final_state == desired_state
    ):
        classification = "ensured_" + desired_state
        reason = None
        ok = True
    elif mutation_performed and not certain:
        classification = "attention_required"
        reason = "mutation_outcome_uncertain"
        ok = False
    elif mutation_performed and not family_classified:
        classification = "attention_required"
        reason = "repository_family_unclassified"
        ok = False
    elif mutation_performed and final_state != desired_state:
        classification = "attention_required"
        reason = final_decision.reason or "desired_state_not_reached"
        ok = False
    elif decision.attention_required:
        ok = False

    proof = {
        "certain": certain,
        "source": _identifier(proof_source),
        "snapshot_id": (
            None if snapshot_id is None else _identifier(snapshot_id)
        ),
        "observed_state": final_state,
    }
    health = _lower(
        terminal_observation.get("health_classification")
        or terminal_observation.get("health")
    )
    if health:
        proof["health"] = _identifier(health)
    result: dict[str, Any] = {
        "schema_version": 1,
        "ok": ok,
        "classification": classification,
        "operation_id": _identifier(operation_id),
        "repository_id": _identifier(repository_id),
        "repository_generation": repository_generation,
        "resource": {
            "kind": _identifier(resource_kind),
            "id": _identifier(resource_id),
        },
        "desired_state": desired_state,
        "observed_state_before": decision.observed_state,
        "mutation_performed": mutation_performed,
        "action": decision.action,
        "terminal_proof": proof,
    }
    if reason is not None:
        result["attention_reason"] = _identifier(reason)
    return validate_runtime_ensure_result(
        result, expected_operation_id=operation_id
    )


def validate_runtime_ensure_result(
    value: Mapping[str, Any],
    *,
    expected_operation_id: str | None = None,
) -> dict[str, Any]:
    """Validate the exact bounded public/durable result contract."""

    required = {
        "schema_version",
        "ok",
        "classification",
        "operation_id",
        "repository_id",
        "repository_generation",
        "resource",
        "desired_state",
        "observed_state_before",
        "mutation_performed",
        "action",
        "terminal_proof",
    }
    allowed = required | {"attention_reason"}
    document = dict(value)
    if not required <= set(document) or not set(document) <= allowed:
        raise ValueError("runtime ensure result fields are invalid")
    resource = document.get("resource")
    proof = document.get("terminal_proof")
    if not isinstance(resource, Mapping) or set(resource) != {"kind", "id"}:
        raise ValueError("runtime ensure resource proof is invalid")
    if not isinstance(proof, Mapping) or not set(proof) <= {
        "certain",
        "source",
        "snapshot_id",
        "observed_state",
        "health",
    } or not {"certain", "source", "snapshot_id", "observed_state"} <= set(
        proof
    ):
        raise ValueError("runtime ensure terminal proof is invalid")
    identifiers = (
        document.get("operation_id"),
        document.get("repository_id"),
        resource.get("kind"),
        resource.get("id"),
        proof.get("source"),
    )
    if any(
        not isinstance(item, str) or _IDENTIFIER.fullmatch(item) is None
        for item in identifiers
    ):
        raise ValueError("runtime ensure result identity is invalid")
    snapshot_id = proof.get("snapshot_id")
    health = proof.get("health")
    if snapshot_id is not None and (
        not isinstance(snapshot_id, str)
        or _IDENTIFIER.fullmatch(snapshot_id) is None
    ):
        raise ValueError("runtime ensure snapshot identity is invalid")
    if health is not None and (
        not isinstance(health, str) or _IDENTIFIER.fullmatch(health) is None
    ):
        raise ValueError("runtime ensure health proof is invalid")
    if (
        document.get("schema_version") != 1
        or type(document.get("ok")) is not bool
        or type(document.get("repository_generation")) is not int
        or document["repository_generation"] < 0
        or resource.get("kind") not in _RESOURCE_KINDS
        or document.get("desired_state") not in _DESIRED_STATES
        or document.get("observed_state_before")
        not in {"ready", "stopped", "unhealthy", "unknown", "unclassified"}
        or type(document.get("mutation_performed")) is not bool
        or document.get("action") not in {None, "start", "stop"}
        or type(proof.get("certain")) is not bool
        or proof.get("observed_state")
        not in {"ready", "stopped", "unhealthy", "unknown"}
    ):
        raise ValueError("runtime ensure result values are invalid")
    classification = document.get("classification")
    successful = {
        "already_ready",
        "already_stopped",
        "ensured_ready",
        "ensured_stopped",
    }
    if classification not in successful | {"attention_required"}:
        raise ValueError("runtime ensure classification is invalid")
    if document["ok"] is not (classification in successful):
        raise ValueError("runtime ensure status contradicts classification")
    if classification.startswith("already_") and (
        document["mutation_performed"]
        or proof["observed_state"] != document["desired_state"]
    ):
        raise ValueError("runtime ensure no-op proof is contradictory")
    if classification.startswith("ensured_") and (
        not document["mutation_performed"]
        or proof["certain"] is not True
        or proof["observed_state"] != document["desired_state"]
    ):
        raise ValueError("runtime ensure mutation proof is contradictory")
    if proof["certain"] is False and not document["mutation_performed"]:
        raise ValueError("runtime ensure uncertainty requires an invocation")
    if classification == "attention_required":
        reason = document.get("attention_reason")
        if not isinstance(reason, str) or _IDENTIFIER.fullmatch(reason) is None:
            raise ValueError("runtime ensure attention reason is invalid")
    elif "attention_reason" in document:
        raise ValueError("successful runtime ensure cannot retain attention reason")
    if document["mutation_performed"] != (document["action"] is not None):
        raise ValueError("runtime ensure action contradicts mutation proof")
    expected_action = (
        "start" if document["desired_state"] == "ready" else "stop"
    )
    if document["action"] is not None and document["action"] != expected_action:
        raise ValueError("runtime ensure action contradicts desired state")
    if (
        expected_operation_id is not None
        and document["operation_id"] != expected_operation_id
    ):
        raise ValueError("runtime ensure result operation identity changed")
    encoded = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > RUNTIME_ENSURE_RESULT_MAX_BYTES:
        raise ValueError("runtime ensure result exceeds its fixed byte ceiling")
    return {
        **document,
        "resource": dict(resource),
        "terminal_proof": dict(proof),
    }


__all__ = [
    "RUNTIME_ENSURE_RESULT_MAX_BYTES",
    "RuntimeEnsureDecision",
    "build_runtime_ensure_result",
    "decide_runtime_ensure",
    "observed_runtime_state",
    "validate_runtime_ensure_result",
    "worker_result_observation",
]
