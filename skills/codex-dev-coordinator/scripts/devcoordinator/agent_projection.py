"""Compact, fail-closed projections for calling agents.

Full normalized inventory and runtime reports remain the evidence authority.
These helpers select only exact repository-tree members and never synthesize
ownership from a name, path, image, port, or observation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .agent_contract import (
    AgentContractError,
    bounded_text,
    canonical_json_bytes,
    require_agent_result,
)


MAX_TARGET_RESULT_BYTES = 2 * 1024
MAX_STATUS_RESULT_BYTES = 2 * 1024
DEFAULT_TARGET_LIMIT = 4


class AgentProjectionError(AgentContractError):
    """Authoritative input cannot produce one safe compact projection."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        candidates: Sequence[Mapping[str, Any]] = (),
    ) -> None:
        super().__init__(message)
        self.code = code
        self.candidates = tuple(dict(item) for item in candidates[:4])


def _rows(value: Any, *, field: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise AgentProjectionError(
            "inventory_contract_invalid", f"{field} is missing or malformed"
        )
    return list(value)


def _index(
    value: Any,
    *,
    field: str,
    id_key: str,
) -> dict[str, Mapping[str, Any]]:
    indexed: dict[str, Mapping[str, Any]] = {}
    for row in _rows(value, field=field):
        identity = row.get(id_key)
        if not isinstance(identity, str) or not identity or identity in indexed:
            raise AgentProjectionError(
                "inventory_contract_invalid",
                f"{field} contains a missing or duplicated immutable ID",
            )
        indexed[identity] = row
    return indexed


def _scope_for_root(
    inventory: Mapping[str, Any], effective_root: str
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    matches: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for family in _rows(inventory.get("repository_trees"), field="repository_trees"):
        for scope in _rows(family.get("scopes"), field="repository_trees.scopes"):
            if scope.get("canonical_root") == effective_root:
                matches.append((family, scope))
    if len(matches) != 1:
        raise AgentProjectionError(
            "repository_scope_ambiguous",
            "effective repository is not exactly one authoritative inventory scope",
        )
    return matches[0]


def _observation_state(
    kind: str,
    resource: Mapping[str, Any],
    observation: Mapping[str, Any] | None,
) -> tuple[str, bool]:
    observed = observation or {}
    if kind == "database_stack":
        available = observed.get("available")
        if available in {True, 1}:
            return "available", True
        if available in {False, 0}:
            return "unavailable", False
        state = resource.get("state") or resource.get("status") or "unobserved"
        return bounded_text(state, maximum_bytes=64), False
    state = (
        observed.get("lifecycle")
        or observed.get("state")
        or resource.get("status")
        or resource.get("state")
        or "unobserved"
    )
    normalized = bounded_text(state, maximum_bytes=64).lower()
    return normalized, normalized in {"running", "ready", "healthy"}


def _target_rows(
    inventory: Mapping[str, Any], *, effective_root: str
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    family, scope = _scope_for_root(inventory, effective_root)
    resources = inventory.get("resources")
    observations = inventory.get("observations")
    if not isinstance(resources, Mapping) or not isinstance(observations, Mapping):
        raise AgentProjectionError(
            "inventory_contract_invalid", "normalized resources or observations are absent"
        )
    definitions = {
        "service": (
            "server_ids",
            _index(resources.get("servers"), field="resources.servers", id_key="server_definition_id"),
            _index(observations.get("servers"), field="observations.servers", id_key="server_definition_id"),
            ("name", "display_name"),
        ),
        "docker": (
            "container_resource_ids",
            _index(resources.get("docker"), field="resources.docker", id_key="docker_resource_id"),
            _index(observations.get("docker"), field="observations.docker", id_key="docker_resource_id"),
            ("current_name", "display_name"),
        ),
        "database_stack": (
            "database_binding_ids",
            _index(resources.get("databases"), field="resources.databases", id_key="database_binding_id"),
            _index(observations.get("databases"), field="observations.databases", id_key="database_binding_id"),
            ("database_name", "display_name"),
        ),
    }
    result: list[dict[str, Any]] = []
    for kind, (scope_key, resource_index, observation_index, name_keys) in definitions.items():
        identities = scope.get(scope_key)
        if (
            not isinstance(identities, list)
            or any(not isinstance(item, str) or not item for item in identities)
            or len(set(identities)) != len(identities)
        ):
            raise AgentProjectionError(
                "inventory_contract_invalid",
                f"repository scope {scope_key} is malformed",
            )
        for identity in identities:
            resource = resource_index.get(identity)
            if resource is None:
                raise AgentProjectionError(
                    "inventory_contract_invalid",
                    "repository scope references an absent normalized resource",
                )
            state, ready = _observation_state(
                kind, resource, observation_index.get(identity)
            )
            raw_name = next(
                (
                    resource.get(key)
                    for key in name_keys
                    if isinstance(resource.get(key), str) and resource.get(key)
                ),
                None,
            )
            row: dict[str, Any] = {
                "kind": kind,
                "id": identity,
                "state": state,
                "ready": ready,
            }
            if raw_name is not None:
                row["name"] = bounded_text(raw_name, maximum_bytes=96)
            result.append(row)
    result.sort(key=lambda item: (str(item["kind"]), str(item["id"])))
    repository = {
        "family_id": family.get("family_id"),
        "repo_id": scope.get("repo_id"),
        "kind": scope.get("kind"),
    }
    if any(not isinstance(value, str) or not value for value in repository.values()):
        raise AgentProjectionError(
            "inventory_contract_invalid", "repository scope identity is incomplete"
        )
    return repository, result


def resolve_target(
    targets: Sequence[Mapping[str, Any]],
    *,
    selector: str,
    kind: str | None = None,
) -> dict[str, Any]:
    """Bind an ID or unique display selector to one immutable target."""

    eligible = [
        dict(item)
        for item in targets
        if kind is None or str(item.get("kind") or "") == kind
    ]
    exact = [item for item in eligible if item.get("id") == selector]
    matches = exact or [item for item in eligible if item.get("name") == selector]
    if len(matches) != 1:
        raise AgentProjectionError(
            "target_not_found" if not matches else "target_ambiguous",
            (
                "target selector matched no authoritative resource"
                if not matches
                else "target selector matched multiple authoritative resources"
            ),
            candidates=matches or eligible,
        )
    return matches[0]


def project_targets(
    inventory: Mapping[str, Any],
    *,
    effective_root: str,
    selector: str | None = None,
    kind: str | None = None,
    limit: int = DEFAULT_TARGET_LIMIT,
) -> dict[str, Any]:
    """Return a byte-bounded target lookup for one exact repository scope."""

    if type(limit) is not int or not 1 <= limit <= 16:
        raise AgentProjectionError("invalid_limit", "target limit must be from 1 through 16")
    repository, targets = _target_rows(inventory, effective_root=effective_root)
    selected = (
        None
        if selector is None
        else resolve_target(targets, selector=selector, kind=kind)
    )
    visible_source = [selected] if selected is not None else targets
    for visible_count in range(min(limit, len(visible_source)), -1, -1):
        visible = visible_source[:visible_count]
        document: dict[str, Any] = {
            "schema_version": 1,
            "ok": True,
            "repository": repository,
            "target_count": len(visible_source),
            "targets": visible,
            "truncated": len(visible) < len(visible_source),
        }
        if selected is not None:
            document["selected"] = selected
        if len(canonical_json_bytes(document)) <= MAX_TARGET_RESULT_BYTES:
            return require_agent_result(
                document,
                surface="target projection",
                maximum_bytes=MAX_TARGET_RESULT_BYTES,
            )
    raise AgentProjectionError(
        "target_projection_too_large",
        "mandatory target identity exceeds the compact result contract",
    )


def project_runtime_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce one complete runtime report to its caller decision surface."""

    if not isinstance(report, Mapping):
        raise AgentProjectionError("runtime_result_invalid", "runtime report is not an object")
    target = report.get("target") if isinstance(report.get("target"), Mapping) else {}
    result = report.get("result") if isinstance(report.get("result"), Mapping) else {}
    matching = [
        item
        for item in (report.get("resources") or [])
        if isinstance(item, Mapping)
        and item.get("kind") == target.get("kind")
        and item.get("id") == target.get("id")
    ]
    resource: dict[str, Any] | None = None
    if len(matching) == 1:
        raw = matching[0]
        resource = {
            key: raw[key]
            for key in ("kind", "id", "name", "state", "ready", "repo_id")
            if key in raw
        }
    operation_id = result.get("operation_id") or report.get("operation_id")
    document: dict[str, Any] = {
        "schema_version": 1,
        "ok": report.get("ok") is True,
        "action": report.get("action"),
        "classification": bounded_text(
            report.get("classification", "runtime_result_unproven"),
            maximum_bytes=96,
        ),
        "ready": report.get("ready") if type(report.get("ready")) is bool else None,
        "target": dict(target),
        "resource": resource,
        "operation_id": operation_id if isinstance(operation_id, str) else None,
        "mutation_performed": bool(
            report.get("action") not in {"status", "capture_logs"}
            and result.get("mutation_performed", report.get("ok") is True)
        ),
        "outcome": (
            "uncertain"
            if "uncertain" in str(report.get("classification") or "")
            else (
                "attention_required"
                if report.get("ok") is not True
                else "certain"
            )
        ),
    }
    error = report.get("error") or result.get("error") or result.get("message")
    if error is not None:
        document["message"] = bounded_text(error)
    terminal = result.get("terminal_state")
    if isinstance(terminal, Mapping):
        document["terminal_state"] = {
            key: terminal[key]
            for key in (
                "proof",
                "resource_kind",
                "resource_id",
                "observed_state",
            )
            if key in terminal
        }
    for key in ("name", "url", "expires_at", "session_id"):
        value = result.get(key)
        if isinstance(value, str) and value:
            document[key] = bounded_text(value, maximum_bytes=256)
    cleanup = result.get("cleanup")
    if isinstance(cleanup, Mapping):
        document["cleanup"] = {
            key: cleanup[key]
            for key in (
                "owner",
                "kill_mode",
                "ttl_seconds",
                "kill_after_run",
            )
            if key in cleanup
        }
    return require_agent_result(
        document,
        surface="runtime status projection",
        maximum_bytes=MAX_STATUS_RESULT_BYTES,
    )


__all__ = [
    "AgentProjectionError",
    "DEFAULT_TARGET_LIMIT",
    "MAX_STATUS_RESULT_BYTES",
    "MAX_TARGET_RESULT_BYTES",
    "project_runtime_report",
    "project_targets",
    "resolve_target",
]
