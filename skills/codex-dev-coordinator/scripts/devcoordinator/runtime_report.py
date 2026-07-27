"""Compact, fail-closed lifecycle API response projection.

Repository-tree IDs are the only membership authority in this module.  Flat
inventory arrays are lookup tables; compatibility paths and display names
never decide which resources belong in a report.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import copy
from pathlib import Path
import re
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit
import uuid


MAX_EVIDENCE_ITEMS = 20
MAX_RESULT_ITEMS = 50
MAX_RESULT_DEPTH = 6
MAX_TEXT_CHARS = 1_024
RUNTIME_ARTIFACT_MAX_BYTES = 1_048_576
RUNTIME_ARTIFACT_MAX_LINES = 2_000

_DOCKER_ATTENTION_STATES = frozenset(
    {"dead", "exited", "failed", "stopped", "unavailable", "unhealthy"}
)

_SENSITIVE_KEY = re.compile(
    r"(?:authorization|cookie|credential|password|passwd|secret|token|api[_-]?key)",
    re.IGNORECASE,
)
_INLINE_LOG_KEYS = frozenset(
    {"stdout", "stderr", "text", "log", "logs", "log_text", "log_contents"}
)
_BEARER = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]+")
_URL = re.compile(r"(?i)\b(?:https?|wss?)://[^\s]+")
_CLI_SECRET = re.compile(
    r"(?i)(--(?:authorization|password|passwd|secret|token|api[_-]?key)"
    r"(?:=|\s+))(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_ASSIGNMENT_SECRET = re.compile(
    r"(?i)\b(authorization|cookie|password|passwd|secret|token|api[_-]?key)"
    r"\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)


def _text(value: Any, *, maximum: int = MAX_TEXT_CHARS) -> str:
    rendered = str(value)
    rendered = _URL.sub(
        lambda match: _safe_url(match.group(0)) or "[redacted-url]", rendered
    )
    rendered = _BEARER.sub(r"\1[REDACTED]", rendered)
    rendered = _CLI_SECRET.sub(r"\1[REDACTED]", rendered)
    rendered = _ASSIGNMENT_SECRET.sub(r"\1=[REDACTED]", rendered)
    if len(rendered) > maximum:
        return rendered[:maximum] + "…"
    return rendered


def _safe_url(value: Any) -> str | None:
    """Return a non-credentialed endpoint URL or ``None``.

    Query strings and fragments are intentionally omitted.  Runtime URLs are
    navigation/health evidence, not a transport for credentials.
    """

    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = urlsplit(value.strip())
        if parsed.scheme not in {"http", "https", "ws", "wss"} or not parsed.hostname:
            return None
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = host + (f":{parsed.port}" if parsed.port is not None else "")
        return urlunsplit(SplitResult(parsed.scheme, netloc, "", "", ""))
    except (TypeError, ValueError):
        return None


def _safe_action_value(value: Any, *, key: str = "", depth: int = 0) -> Any:
    """Bound and redact action evidence without inventing success.

    Lifecycle implementations return heterogeneous dictionaries.  Keeping a
    compact, redacted copy preserves operation/failure evidence when the final
    inventory cannot observe the target, while logs stay behind artifact URLs.
    """

    if _SENSITIVE_KEY.search(key):
        return "[redacted]"
    if depth >= MAX_RESULT_DEPTH:
        return {"omitted": True, "reason": "depth_limit"}
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        items = list(value.items())
        for raw_key, item in items[:MAX_RESULT_ITEMS]:
            item_key = str(raw_key)
            if item_key == "_runtime_log_capture":
                continue
            if item_key.lower() in _INLINE_LOG_KEYS:
                byte_count = len(item.encode("utf-8", errors="replace")) if isinstance(item, str) else None
                result[item_key] = {
                    "inline": False,
                    "bytes": byte_count,
                    "artifact_required": True,
                }
            elif item_key.lower() in {"env", "environment", "run_env"} and isinstance(item, Mapping):
                result[item_key] = {
                    "redacted": True,
                    "names": sorted(_text(name, maximum=200) for name in item)[:MAX_RESULT_ITEMS],
                }
            else:
                result[item_key] = _safe_action_value(
                    item, key=item_key, depth=depth + 1
                )
        if len(items) > MAX_RESULT_ITEMS:
            result["_omitted_field_count"] = len(items) - MAX_RESULT_ITEMS
        return result
    if isinstance(value, (list, tuple)):
        items = list(value)
        if key.lower() in {"argv", "run_argv", "command"}:
            executable = Path(str(items[0])).name if items else None
            return {
                "redacted": True,
                "executable": executable,
                "argument_count": max(0, len(items) - 1),
            }
        projected = [
            _safe_action_value(item, key=key, depth=depth + 1)
            for item in items[:MAX_RESULT_ITEMS]
        ]
        if len(items) > MAX_RESULT_ITEMS:
            projected.append({"omitted_item_count": len(items) - MAX_RESULT_ITEMS})
        return projected
    if isinstance(value, str):
        return _text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _text(value)


def _family_and_scope(
    inventory: dict[str, Any], *, family_id: str, repo_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    trees = inventory.get("repository_trees")
    if not isinstance(trees, list):
        raise RuntimeError("authoritative repository_trees are absent from inventory")
    family = next(
        (
            item
            for item in trees
            if isinstance(item, dict) and str(item.get("family_id")) == family_id
        ),
        None,
    )
    if family is None:
        raise RuntimeError(f"repository family {family_id} is absent from inventory")
    scope = next(
        (
            item
            for item in family.get("scopes") or []
            if isinstance(item, dict) and str(item.get("repo_id")) == repo_id
        ),
        None,
    )
    if scope is None:
        raise RuntimeError(f"repository scope {repo_id} is absent from inventory")
    return family, scope


def _usage(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, Mapping) else {}

    def part(name: str) -> dict[str, Any]:
        item = source.get(name)
        material = item if isinstance(item, Mapping) else {}
        return {
            "resource_count": int(material.get("resource_count") or 0),
            "process_count": int(material.get("process_count") or 0),
            "cpu_percent": (
                None
                if material.get("cpu_percent") is None
                else float(material["cpu_percent"])
            ),
            "memory_bytes": (
                None
                if material.get("memory_bytes") is None
                else int(material["memory_bytes"])
            ),
        }

    return {
        "cpu_percent": (
            None if source.get("cpu_percent") is None else float(source["cpu_percent"])
        ),
        "memory_bytes": (
            None if source.get("memory_bytes") is None else int(source["memory_bytes"])
        ),
        "process_count": int(source.get("process_count") or 0),
        "server": part("server"),
        "docker": part("docker"),
    }


def _observation_index(
    inventory: dict[str, Any], collection: str, id_key: str
) -> dict[str, dict[str, Any]]:
    observations = inventory.get("observations")
    rows = observations.get(collection) if isinstance(observations, Mapping) else []
    result: dict[str, dict[str, Any]] = {}
    for item in rows or []:
        if not isinstance(item, Mapping) or item.get(id_key) is None:
            continue
        resource_id = str(item[id_key])
        if resource_id in result:
            raise RuntimeError(
                f"duplicate {collection} observation for resource {resource_id}"
            )
        result[resource_id] = dict(item)
    return result


def _resource_usage(sample: Any, *, source: str) -> dict[str, Any]:
    """Project one store-filtered compatibility sample, never raw history.

    ``inventory_v2`` already binds service ``process_usage`` and container
    ``stats`` to their current lifecycle lineage.  The raw telemetry history is
    intentionally unsuitable here: choosing its newest timestamp can select a
    stale run or a future/corrupt sample that the inventory totals excluded.
    """

    sample = sample if isinstance(sample, Mapping) else {}
    memory = sample.get("memory_bytes")
    if memory is None:
        memory = sample.get("memory_usage_bytes", sample.get("rss_bytes"))
    cpu = sample.get("cpu_percent")
    sampled_at = sample.get("sampled_at") or sample.get("timestamp")
    present = sum(value is not None for value in (cpu, memory, sampled_at))
    return {
        "coverage": (
            "complete" if present == 3 else "partial" if present else "unavailable"
        ),
        "source": source if present else None,
        "cpu_percent": None if cpu is None else float(cpu),
        "memory_bytes": None if memory is None else int(memory),
        "sampled_at": sampled_at,
    }


def _port(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if 1 <= parsed <= 65_535 else None


def _service_resource(
    row: Mapping[str, Any],
    *,
    scope: Mapping[str, Any],
    effective_repo_id: str,
    observation: Mapping[str, Any] | None,
    compatibility: Mapping[str, Any] | None,
    assigned_ports: Iterable[int],
) -> dict[str, Any]:
    resource_id = str(row["server_definition_id"])
    observation = observation or {}
    compatibility = compatibility or {}
    ports = {item for item in assigned_ports if item is not None}
    listener_port = _port(observation.get("listener_port"))
    if listener_port is not None:
        ports.add(listener_port)
    compatible_port = _port(compatibility.get("port"))
    if compatible_port is not None:
        ports.add(compatible_port)
    urls: set[str] = set()
    for candidate in (
        compatibility.get("url") if compatibility.get("url_is_current", True) else None,
        compatibility.get("health_url"),
        row.get("health_url_template"),
    ):
        safe = _safe_url(candidate)
        if safe:
            urls.add(safe)
    if listener_port is not None and str(observation.get("lifecycle") or "") in {
        "running",
        "starting",
        "unhealthy",
    }:
        host = str(observation.get("listener_host") or "127.0.0.1")
        bracketed = f"[{host}]" if ":" in host and not host.startswith("[") else host
        safe = _safe_url(f"http://{bracketed}:{listener_port}")
        if safe:
            urls.add(safe)
    domains = sorted(
        {urlsplit(candidate).hostname for candidate in urls if urlsplit(candidate).hostname}
    )
    return {
        "kind": "service",
        "id": resource_id,
        "repo_id": str(scope["repo_id"]),
        "repository_kind": str(scope.get("kind") or "root"),
        "effective": str(scope["repo_id"]) == effective_repo_id,
        "name": row.get("name"),
        "state": observation.get("lifecycle") or compatibility.get("status") or "unobserved",
        "ports": sorted(ports),
        "urls": sorted(urls),
        "domains": domains,
        "usage": _resource_usage(
            compatibility.get("process_usage"),
            source="lineage_filtered_process_usage",
        ),
        "supervision": (
            row.get("supervision")
            if isinstance(row.get("supervision"), Mapping)
            else compatibility.get("supervision")
            if isinstance(compatibility.get("supervision"), Mapping)
            else None
        ),
        "source": "inventory",
    }


def _docker_resource(
    row: Mapping[str, Any],
    *,
    scope: Mapping[str, Any],
    effective_repo_id: str,
    observation: Mapping[str, Any] | None,
    compatibility: Mapping[str, Any] | None,
    ports: Iterable[int],
) -> dict[str, Any]:
    resource_id = str(row["docker_resource_id"])
    observation = observation or {}
    compatibility = compatibility or {}
    urls = {
        safe
        for candidate in (compatibility.get("url"), compatibility.get("health_url"))
        if (safe := _safe_url(candidate)) is not None
    }
    return {
        "kind": "docker",
        "id": resource_id,
        "repo_id": str(scope["repo_id"]),
        "repository_kind": str(scope.get("kind") or "root"),
        "effective": str(scope["repo_id"]) == effective_repo_id,
        "name": row.get("current_name") or compatibility.get("name"),
        "state": observation.get("lifecycle") or compatibility.get("status") or "unobserved",
        "ports": sorted(set(ports)),
        "urls": sorted(urls),
        "domains": sorted(
            {urlsplit(candidate).hostname for candidate in urls if urlsplit(candidate).hostname}
        ),
        "usage": _resource_usage(
            compatibility.get("stats"),
            source="lineage_filtered_container_stats",
        ),
        "source": "inventory",
    }


def _database_resource(
    row: Mapping[str, Any],
    *,
    scope: Mapping[str, Any],
    effective_repo_id: str,
    observation: Mapping[str, Any] | None,
    ports: Iterable[int],
) -> dict[str, Any]:
    resource_id = str(row["database_binding_id"])
    observation = observation or {}
    available = observation.get("available")
    state = "unobserved" if available is None else "available" if bool(available) else "unavailable"
    return {
        "kind": "database_stack",
        "id": resource_id,
        "repo_id": str(scope["repo_id"]),
        "repository_kind": str(scope.get("kind") or "root"),
        "effective": str(scope["repo_id"]) == effective_repo_id,
        "name": row.get("database_name"),
        "state": state,
        "container_resource_id": row.get("docker_resource_id"),
        "ports": sorted(set(ports)),
        "urls": [],
        "domains": [],
        "usage": _resource_usage(None, source="unavailable"),
        "source": "inventory",
    }


_TREE_RESOURCE_SPECS = (
    ("service", "server_ids", "servers", "server_definition_id"),
    ("docker", "container_resource_ids", "docker", "docker_resource_id"),
    (
        "database_stack",
        "database_binding_ids",
        "databases",
        "database_binding_id",
    ),
)


def _unique_resource_index(
    rows: Any, *, kind: str, id_key: str
) -> dict[str, Mapping[str, Any]]:
    if not isinstance(rows, list):
        raise RuntimeError(f"normalized {kind} resource collection is absent")
    result: dict[str, Mapping[str, Any]] = {}
    for ordinal, item in enumerate(rows):
        if not isinstance(item, Mapping) or not str(item.get(id_key) or ""):
            raise RuntimeError(
                f"normalized {kind} resource row {ordinal} has no stable identity"
            )
        resource_id = str(item[id_key])
        if resource_id in result:
            raise RuntimeError(
                f"normalized {kind} resource {resource_id} resolves more than once"
            )
        result[resource_id] = item
    return result


def _validate_repository_tree_integrity(
    inventory: dict[str, Any],
) -> dict[str, dict[str, Mapping[str, Any]]]:
    """Validate the complete tree before selecting a requested family.

    A response is unsafe if any tree claim is missing, ambiguous, or shared by
    scopes/families.  Validate the full graph so selecting one healthy-looking
    family cannot conceal corruption elsewhere in the same inventory.
    """

    normalized = inventory.get("resources")
    if not isinstance(normalized, Mapping):
        raise RuntimeError("normalized resource lookup is absent from inventory")
    indexes = {
        kind: _unique_resource_index(
            normalized.get(collection), kind=kind, id_key=id_key
        )
        for kind, _tree_key, collection, id_key in _TREE_RESOURCE_SPECS
    }
    trees = inventory.get("repository_trees")
    if not isinstance(trees, list):
        raise RuntimeError("authoritative repository_trees are absent from inventory")

    family_ids: set[str] = set()
    scope_claims: dict[str, str] = {}
    resource_claims: dict[tuple[str, str], tuple[str, str]] = {}
    for family_ordinal, family in enumerate(trees):
        if not isinstance(family, Mapping) or not str(family.get("family_id") or ""):
            raise RuntimeError(
                f"repository family row {family_ordinal} has no stable identity"
            )
        family_id = str(family["family_id"])
        if family_id in family_ids:
            raise RuntimeError(f"repository family {family_id} resolves more than once")
        family_ids.add(family_id)
        scopes = family.get("scopes")
        if not isinstance(scopes, list):
            raise RuntimeError(f"repository family {family_id} has no scope collection")
        for scope_ordinal, scope in enumerate(scopes):
            if not isinstance(scope, Mapping) or not str(scope.get("repo_id") or ""):
                raise RuntimeError(
                    f"repository family {family_id} scope {scope_ordinal} has no stable identity"
                )
            repo_id = str(scope["repo_id"])
            prior_family = scope_claims.get(repo_id)
            if prior_family is not None:
                raise RuntimeError(
                    f"repository scope {repo_id} is claimed more than once "
                    f"({prior_family}, {family_id})"
                )
            scope_claims[repo_id] = family_id
            for kind, tree_key, _collection, _id_key in _TREE_RESOURCE_SPECS:
                resource_ids = scope.get(tree_key)
                if not isinstance(resource_ids, list):
                    raise RuntimeError(
                        f"repository scope {repo_id} has no {tree_key} collection"
                    )
                for raw_id in resource_ids:
                    resource_id = str(raw_id or "")
                    if not resource_id or resource_id not in indexes[kind]:
                        raise RuntimeError(
                            f"tree {kind} resource {resource_id or '<empty>'} does not "
                            "resolve exactly once in the normalized lookup"
                        )
                    claim_key = (kind, resource_id)
                    prior_claim = resource_claims.get(claim_key)
                    if prior_claim is not None:
                        raise RuntimeError(
                            f"tree {kind} resource {resource_id} is claimed more than "
                            f"once ({prior_claim[0]}/{prior_claim[1]}, "
                            f"{family_id}/{repo_id})"
                        )
                    resource_claims[claim_key] = (family_id, repo_id)
    return indexes


def _family_resources(
    inventory: dict[str, Any],
    *,
    family: dict[str, Any],
    effective_repo_id: str,
    normalized_indexes: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    normalized = inventory.get("resources")
    normalized = normalized if isinstance(normalized, Mapping) else {}
    servers = normalized_indexes["service"]
    docker = normalized_indexes["docker"]
    databases = normalized_indexes["database_stack"]
    docker_ports: dict[str, set[int]] = {}
    for item in normalized.get("docker_ports") or []:
        if not isinstance(item, Mapping):
            continue
        port = _port(item.get("host_port"))
        if port is not None:
            docker_ports.setdefault(str(item.get("docker_resource_id") or ""), set()).add(port)

    compatibility = inventory.get("v1_compatibility")
    compatibility = compatibility if isinstance(compatibility, Mapping) else {}
    compatibility_servers = {
        str(item["id"]): item
        for item in compatibility.get("servers") or []
        if isinstance(item, Mapping) and item.get("id") is not None
    }
    docker_compat = compatibility.get("docker")
    docker_compat = docker_compat if isinstance(docker_compat, Mapping) else {}
    compatibility_docker = {
        str(item.get("host_resource_id") or ""): item
        for item in docker_compat.get("containers") or []
        if isinstance(item, Mapping) and item.get("host_resource_id") is not None
    }

    server_observations = _observation_index(
        inventory, "servers", "server_definition_id"
    )
    docker_observations = _observation_index(
        inventory, "docker", "docker_resource_id"
    )
    database_observations = _observation_index(
        inventory, "databases", "database_binding_id"
    )
    server_ports: dict[str, set[int]] = {}
    for item in inventory.get("leases") or []:
        if not isinstance(item, Mapping) or str(item.get("status") or "") != "active":
            continue
        resource_id = str(item.get("server_definition_id") or "")
        port = _port(item.get("port"))
        if resource_id and port is not None:
            server_ports.setdefault(resource_id, set()).add(port)
    for scope in family.get("scopes") or []:
        if not isinstance(scope, Mapping):
            continue
        repo_id = str(scope.get("repo_id") or "")
        names_to_ids = {
            str(servers[resource_id].get("name") or ""): resource_id
            for resource_id in scope.get("server_ids") or []
            if str(resource_id) in servers
        }
        for item in inventory.get("port_assignments") or []:
            if (
                not isinstance(item, Mapping)
                or str(item.get("repo_id") or "") != repo_id
                or str(item.get("status") or "") != "active"
            ):
                continue
            resource_id = names_to_ids.get(str(item.get("server_name") or ""))
            port = _port(item.get("port"))
            if resource_id and port is not None:
                server_ports.setdefault(resource_id, set()).add(port)

    projected: list[dict[str, Any]] = []
    for scope in family.get("scopes") or []:
        if not isinstance(scope, Mapping):
            continue
        for raw_id in scope.get("server_ids") or []:
            resource_id = str(raw_id)
            row = servers.get(resource_id)
            if row is None:
                raise RuntimeError(
                    f"tree service resource {resource_id} lost normalized resolution"
                )
            projected.append(
                _service_resource(
                    row,
                    scope=scope,
                    effective_repo_id=effective_repo_id,
                    observation=server_observations.get(resource_id),
                    compatibility=compatibility_servers.get(resource_id),
                    assigned_ports=server_ports.get(resource_id, set()),
                )
            )
        for raw_id in scope.get("container_resource_ids") or []:
            resource_id = str(raw_id)
            row = docker.get(resource_id)
            if row is None:
                raise RuntimeError(
                    f"tree docker resource {resource_id} lost normalized resolution"
                )
            projected.append(
                _docker_resource(
                    row,
                    scope=scope,
                    effective_repo_id=effective_repo_id,
                    observation=docker_observations.get(resource_id),
                    compatibility=compatibility_docker.get(resource_id),
                    ports=docker_ports.get(resource_id, set()),
                )
            )
        for raw_id in scope.get("database_binding_ids") or []:
            resource_id = str(raw_id)
            row = databases.get(resource_id)
            if row is None:
                raise RuntimeError(
                    f"tree database_stack resource {resource_id} lost normalized resolution"
                )
            projected.append(
                _database_resource(
                    row,
                    scope=scope,
                    effective_repo_id=effective_repo_id,
                    observation=database_observations.get(resource_id),
                    ports=docker_ports.get(str(row.get("docker_resource_id") or ""), set()),
                )
            )
    return projected


def _walk_action_nodes(value: Any, *, depth: int = 0) -> Iterable[Mapping[str, Any]]:
    if depth > 4 or not isinstance(value, Mapping):
        return
    yield value
    for key in ("started", "start", "server", "container", "result", "evidence"):
        child = value.get(key)
        if isinstance(child, Mapping):
            yield from _walk_action_nodes(child, depth=depth + 1)


def _artifact_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    path = Path(value).expanduser()
    return str(path) if path.is_absolute() else None


def _find_log_path(action_result: dict[str, Any]) -> str | None:
    run = action_result.get("run")
    if isinstance(run, Mapping):
        path = _artifact_path(run.get("log_path"))
        if path:
            return path
    for item in _walk_action_nodes(action_result):
        path = _artifact_path(item.get("log_path"))
        if path:
            return path
    return None


def _session_artifact_path(
    value: Any, *, artifact_kind: str, session_id: str | None
) -> str | None:
    """Accept only the exact filename created for this runtime session.

    An arbitrary absolute ``log_path`` is not evidence that the coordinator
    artifact endpoint can serve it.  The endpoint independently confines and
    verifies the file under its private log root; this producer-side filename
    check prevents reports from advertising a plausible but invented link.
    """

    path = _artifact_path(value)
    if path is None or session_id is None:
        return None
    expected = f"runtime-{artifact_kind}-{session_id}.log"
    return path if Path(path).name == expected else None


def _artifact_descriptor(
    *,
    resource_kind: str,
    resource_id: str,
    path: str,
    source: str,
) -> dict[str, Any]:
    return {
        "kind": "log",
        "resource_kind": resource_kind,
        "resource_id": resource_id,
        # Account-authority agents and the native Board may open this local
        # path.  DevOps Console never serializes it to the browser: it follows
        # only the authenticated href and returns the bounded text body.
        "path": path,
        "href": f"/api/runtime/artifacts/{resource_kind}/{resource_id}",
        "source": source,
        "bounds": {
            "tail_lines": RUNTIME_ARTIFACT_MAX_LINES,
            "max_bytes": RUNTIME_ARTIFACT_MAX_BYTES,
        },
    }


def _log_artifacts(
    *,
    inventory: dict[str, Any],
    resources: list[dict[str, Any]],
    request: dict[str, Any],
    action_result: dict[str, Any],
    session_id: str | None,
) -> list[dict[str, Any]]:
    normalized = inventory.get("resources")
    normalized = normalized if isinstance(normalized, Mapping) else {}
    server_rows = {
        str(item["server_definition_id"]): item
        for item in normalized.get("servers") or []
        if isinstance(item, Mapping) and item.get("server_definition_id") is not None
    }
    selected_service_ids = {
        str(item["id"]) for item in resources if item.get("kind") == "service"
    }
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for resource_id in sorted(selected_service_ids):
        row = server_rows.get(resource_id) or {}
        path = _artifact_path(row.get("log_path"))
        if path is None:
            continue
        key = ("service", resource_id)
        seen.add(key)
        result.append(
            _artifact_descriptor(
                resource_kind="service",
                resource_id=resource_id,
                path=path,
                source="managed_service_log",
            )
        )
        supervision = row.get("supervision")
        if not isinstance(supervision, Mapping):
            continue
        for crash in supervision.get("recent_crashes") or []:
            if not isinstance(crash, Mapping):
                continue
            log = crash.get("log")
            if not isinstance(log, Mapping):
                continue
            try:
                artifact_id = str(uuid.UUID(str(log.get("artifact_id") or "")))
            except ValueError:
                continue
            crash_path = _artifact_path(log.get("path"))
            if crash_path is None:
                continue
            key = ("worker_attempt", artifact_id)
            if key in seen:
                continue
            seen.add(key)
            descriptor = _artifact_descriptor(
                resource_kind="worker_attempt",
                resource_id=artifact_id,
                path=crash_path,
                source="worker_attempt_log",
            )
            descriptor["target_resource_id"] = resource_id
            descriptor["attempt_id"] = crash.get("attempt_id")
            descriptor["captured_at"] = crash.get("exited_at")
            result.append(descriptor)

    capture = action_result.get("_runtime_log_capture")
    capture = capture if isinstance(capture, Mapping) else {}
    target = request.get("target") if isinstance(request.get("target"), Mapping) else {}
    if capture.get("availability") == "available":
        try:
            artifact_id = str(uuid.UUID(str(capture.get("artifact_id") or "")))
        except ValueError:
            artifact_id = ""
        capture_kind = str(capture.get("resource_kind") or "")
        capture_target = str(capture.get("target_resource_id") or "")
        capture_path = _artifact_path(capture.get("path"))
        expected_name = f"runtime-{capture_kind}-{artifact_id}.log"
        if (
            artifact_id
            and capture_kind in {"docker", "database_stack"}
            and capture_kind == str(target.get("kind") or "")
            and capture_target == str(target.get("id") or "")
            and capture_path is not None
            and Path(capture_path).name == expected_name
        ):
            descriptor = _artifact_descriptor(
                resource_kind=capture_kind,
                resource_id=artifact_id,
                path=capture_path,
                source=str(capture.get("source") or "docker_logs_exact_container"),
            )
            descriptor["target_resource_id"] = capture_target
            descriptor["captured_at"] = capture.get("captured_at")
            descriptor["truncated"] = bool(capture.get("truncated"))
            result.append(descriptor)

    action_path = _find_log_path(action_result)
    run_path = _session_artifact_path(
        action_path, artifact_kind="run", session_id=session_id
    )
    diagnostic_path = _session_artifact_path(
        action_path, artifact_kind="diagnostic", session_id=session_id
    )
    if run_path and request.get("action") == "run" and session_id is not None:
        key = ("run", session_id)
        if key not in seen:
            result.append(
                _artifact_descriptor(
                    resource_kind="run",
                    resource_id=session_id,
                    path=run_path,
                    source="runtime_command_capture",
                )
            )
    if (
        diagnostic_path
        and session_id is not None
        and target.get("kind") in {"docker", "database_stack"}
        and action_result.get("ok") is not True
    ):
        result.append(
            _artifact_descriptor(
                resource_kind="diagnostic",
                resource_id=session_id,
                path=diagnostic_path,
                source="runtime_failure_diagnostic",
            )
        )
    return result


def _available_log_evidence(artifact: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "availability": "available",
        "source": artifact.get("source"),
        "artifact": dict(artifact),
    }


def _unavailable_log_evidence(resource_kind: str) -> dict[str, Any]:
    if resource_kind == "database_stack":
        noun = "database-stack"
        reason = "authoritative_database_log_capture_unavailable"
    else:
        noun = "container"
        reason = "authoritative_docker_log_capture_unavailable"
    return {
        "availability": "unavailable",
        "reason_code": reason,
        "message": (
            f"No immutable, bounded {noun} log artifact is attached to this "
            "observation."
        ),
        "action_required": (
            "Retry through the runtime API after restoring Docker observation; "
            "do not substitute a name- or path-derived log."
        ),
    }


def _capture_unavailable_evidence(action_result: Mapping[str, Any]) -> dict[str, Any] | None:
    capture = action_result.get("_runtime_log_capture")
    if not isinstance(capture, Mapping) or capture.get("availability") != "unavailable":
        return None
    return {
        "availability": "unavailable",
        "reason_code": str(
            capture.get("reason_code") or "authoritative_log_capture_unavailable"
        ),
        "message": _text(
            capture.get("message")
            or capture.get("error")
            or "The exact runtime log could not be captured."
        ),
        "action_required": (
            "Restore the reported Docker capability or exact resource identity, "
            "then retry through the runtime API."
        ),
    }


def _attach_log_evidence(
    *,
    resources: list[dict[str, Any]],
    request: Mapping[str, Any],
    action_result: Mapping[str, Any],
    artifacts: list[dict[str, Any]],
    effective_repo_id: str,
) -> tuple[dict[str, Any] | None, dict[tuple[str, str], dict[str, Any]]]:
    """Bind one real session-owned failure artifact to one exact target only.

    Only exact target-bound captures or this request's diagnostic can attach.
    """

    target = request.get("target")
    target = target if isinstance(target, Mapping) else {}
    target_kind = str(target.get("kind") or "")
    target_id = str(target.get("id") or "")
    exact_target = next(
        (
            item
            for item in resources
            if str(item.get("kind") or "") == target_kind
            and str(item.get("id") or "") == target_id
            and str(item.get("repo_id") or "") == effective_repo_id
        ),
        None,
    )
    diagnostic = next(
        (
            item
            for item in artifacts
            if item.get("resource_kind") == "diagnostic"
        ),
        None,
    )
    runtime_capture = next(
        (item for item in artifacts if item.get("resource_kind") == "run"),
        None,
    )
    target_capture = next(
        (
            item
            for item in artifacts
            if item.get("resource_kind") == target_kind
            and item.get("target_resource_id") == target_id
        ),
        None,
    )
    operation_evidence = target_capture or diagnostic or runtime_capture
    capture_unavailable = _capture_unavailable_evidence(action_result)
    service_artifacts = {
        str(item.get("resource_id") or ""): item
        for item in artifacts
        if item.get("resource_kind") == "service"
    }
    evidence_by_resource: dict[tuple[str, str], dict[str, Any]] = {}

    for resource in resources:
        kind = str(resource.get("kind") or "")
        resource_id = str(resource.get("id") or "")
        state = str(resource.get("state") or "").lower()
        needs_evidence = (
            kind == "docker" and state in _DOCKER_ATTENTION_STATES
        ) or (kind == "database_stack" and state == "unavailable") or (
            exact_target is resource
            and action_result.get("ok") is not True
            and kind in {"docker", "database_stack"}
        )
        if not needs_evidence:
            continue
        if (
            operation_evidence is not None
            and action_result.get("ok") is not True
            and exact_target is resource
            and kind in {"docker", "database_stack"}
        ):
            evidence = _available_log_evidence(operation_evidence)
        else:
            evidence = capture_unavailable or _unavailable_log_evidence(kind)
        resource["log_evidence"] = evidence
        evidence_by_resource[(kind, resource_id)] = evidence

    target_log: dict[str, Any] | None = None
    if exact_target is not None and target_kind == "service":
        artifact = service_artifacts.get(target_id)
        if artifact is not None:
            target_log = _available_log_evidence(artifact)
    elif target_kind in {"docker", "database_stack"} and (
        action_result.get("ok") is not True
        or (
            exact_target is not None
            and (
                str(exact_target.get("state") or "").lower()
                in _DOCKER_ATTENTION_STATES
                if target_kind == "docker"
                else str(exact_target.get("state") or "").lower() == "unavailable"
            )
        )
    ):
        if target_capture is not None:
            target_log = _available_log_evidence(target_capture)
        elif operation_evidence is not None and exact_target is not None:
            target_log = _available_log_evidence(operation_evidence)
        elif exact_target is None:
            target_log = {
                "availability": "unavailable",
                "reason_code": "target_not_authoritatively_classified",
                "message": (
                    "The runtime diagnostic cannot be attached to a resource "
                    "that is absent from the effective repository tree."
                ),
            }
        else:
            target_log = capture_unavailable or _unavailable_log_evidence(target_kind)
    return target_log, evidence_by_resource


def _resource_id_sets(family: Mapping[str, Any]) -> dict[str, set[str]]:
    result = {"server": set(), "container": set(), "database": set()}
    for scope in family.get("scopes") or []:
        if not isinstance(scope, Mapping):
            continue
        result["server"].update(str(value) for value in scope.get("server_ids") or [])
        result["container"].update(
            str(value) for value in scope.get("container_resource_ids") or []
        )
        result["database"].update(
            str(value) for value in scope.get("database_binding_ids") or []
        )
    return result


def _evidence_item(item: Mapping[str, Any]) -> dict[str, Any]:
    allowed = (
        "classification",
        "resource_kind",
        "resource_id",
        "display_name",
        "attempt_id",
        "exit_kind",
        "exit_code",
        "exit_signal",
        "crash_event_id",
        "reason_code",
        "repo_id",
        "event_id",
        "event_kind",
        "code",
        "message",
        "occurred_at",
        "sampled_at",
        "pid",
        "lifecycle",
        "state",
        "detected_at",
        "updated_at",
    )
    result = {
        key: _safe_action_value(item[key], key=key)
        for key in allowed
        if item.get(key) is not None
    }
    for key in ("process_fingerprint", "immutable_fingerprint"):
        if item.get(key) is not None:
            fingerprint = _text(item[key], maximum=80)
            result[key] = fingerprint[:24] + ("…" if len(fingerprint) > 24 else "")
    if isinstance(item.get("log_evidence"), Mapping):
        result["log_evidence"] = _safe_action_value(item["log_evidence"])
    return result


def _bounded_evidence(
    items: list[dict[str, Any]], *, source_truncated: bool = False
) -> dict[str, Any]:
    return {
        "count": len(items),
        "items": [_evidence_item(item) for item in items[:MAX_EVIDENCE_ITEMS]],
        "truncated": source_truncated or len(items) > MAX_EVIDENCE_ITEMS,
    }


def _stale_and_crashes(
    inventory: dict[str, Any],
    *,
    family: dict[str, Any],
    log_evidence_by_resource: Mapping[tuple[str, str], Mapping[str, Any]],
    artifacts: Iterable[Mapping[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    repo_ids = {
        str(item.get("repo_id"))
        for item in family.get("scopes") or []
        if isinstance(item, Mapping) and item.get("repo_id") is not None
    }
    ids = _resource_id_sets(family)

    stale: list[dict[str, Any]] = []
    for item in inventory.get("unassigned_resources") or []:
        if not isinstance(item, Mapping) or item.get("reason_code") != "stale_observation":
            continue
        kind = str(item.get("resource_kind") or "")
        if str(item.get("resource_id") or "") in ids.get(kind, set()):
            stale.append(dict(item))
    for item in inventory.get("lifecycle_violations") or []:
        if not isinstance(item, Mapping) or str(item.get("repo_id") or "") not in repo_ids:
            continue
        if (
            str(item.get("resource_kind") or "") == "server"
            and (
                str(item.get("reason_code") or "") == "stale_observation"
                or str(item.get("code") or "")
                in {"stale_observation", "stale_process", "stale_server"}
            )
        ):
            stale.append(dict(item))

    crashes = [
        dict(item)
        for item in inventory.get("events") or []
        if isinstance(item, Mapping)
        and str(item.get("repo_id") or "") in repo_ids
        and str(item.get("code") or "")
        in {"server_crashed", "docker_crashed"}
    ]
    for item in crashes:
        raw_kind = str(item.get("resource_kind") or "")
        resource_kind = {
            "container": "docker",
            "docker": "docker",
            "database": "database_stack",
            "database_stack": "database_stack",
            "server": "service",
            "service": "service",
        }.get(raw_kind, raw_kind)
        resource_id = str(item.get("resource_id") or "")
        evidence = log_evidence_by_resource.get((resource_kind, resource_id))
        if evidence is not None:
            item["log_evidence"] = dict(evidence)
        elif str(item.get("code") or "") == "docker_crashed":
            item["log_evidence"] = (
                _unavailable_log_evidence("docker")
                if resource_id
                else {
                    "availability": "unavailable",
                    "reason_code": "crash_resource_identity_unavailable",
                    "message": (
                        "The crash event has no immutable container identity, so "
                        "no log artifact can be attached."
                    ),
                }
            )

    worker_artifacts = {
        (
            str(item.get("target_resource_id") or ""),
            str(item.get("attempt_id") or ""),
        ): dict(item)
        for item in artifacts
        if item.get("resource_kind") == "worker_attempt"
        and item.get("target_resource_id")
        and item.get("attempt_id")
    }
    normalized = inventory.get("resources")
    server_rows = normalized.get("servers") if isinstance(normalized, Mapping) else []
    worker_source_truncated = False
    for row in server_rows or []:
        if not isinstance(row, Mapping):
            continue
        resource_id = str(row.get("server_definition_id") or "")
        if resource_id not in ids["server"]:
            continue
        supervision = row.get("supervision")
        if not isinstance(supervision, Mapping):
            continue
        worker_source_truncated = worker_source_truncated or bool(
            supervision.get("recent_crashes_truncated")
        )
        for crash in supervision.get("recent_crashes") or []:
            if not isinstance(crash, Mapping):
                continue
            attempt_id = str(crash.get("attempt_id") or "")
            artifact = worker_artifacts.get((resource_id, attempt_id))
            log_evidence = (
                _available_log_evidence(artifact)
                if artifact is not None
                else {
                    "availability": "unavailable",
                    "reason_code": "worker_attempt_log_unavailable",
                    "message": (
                        "The retained worker crash has no verified bounded log artifact."
                    ),
                }
            )
            crashes.append(
                {
                    "classification": crash.get("classification") or "crash",
                    "resource_kind": "service",
                    "resource_id": resource_id,
                    "display_name": row.get("name"),
                    "repo_id": row.get("repo_id"),
                    "attempt_id": attempt_id,
                    "exit_kind": crash.get("exit_kind"),
                    "exit_code": crash.get("exit_code"),
                    "exit_signal": crash.get("exit_signal"),
                    "crash_event_id": crash.get("crash_event_id"),
                    "event_id": crash.get("crash_event_id"),
                    "event_kind": "worker.crashed",
                    "code": "worker_crashed",
                    "message": "Worker exited unexpectedly",
                    "occurred_at": crash.get("exited_at"),
                    "log_evidence": log_evidence,
                }
            )
    crashes.sort(
        key=lambda item: str(item.get("occurred_at") or ""), reverse=True
    )
    return _bounded_evidence(stale), _bounded_evidence(
        crashes, source_truncated=worker_source_truncated
    )


def _endpoint_summary(
    resources: list[dict[str, Any]], *, effective_repo_id: str, root_repo_id: str
) -> tuple[dict[str, list[int]], dict[str, list[str]]]:
    family_ports: set[int] = set()
    effective_ports: set[int] = set()
    root_ports: set[int] = set()
    family_domains: set[str] = set()
    effective_domains: set[str] = set()
    root_domains: set[str] = set()
    for resource in resources:
        ports = {_port(value) for value in resource.get("ports") or []}
        ports.discard(None)
        domains = {str(value) for value in resource.get("domains") or [] if value}
        family_ports.update(int(value) for value in ports if value is not None)
        family_domains.update(domains)
        if str(resource.get("repo_id") or "") == effective_repo_id:
            effective_ports.update(int(value) for value in ports if value is not None)
            effective_domains.update(domains)
        if str(resource.get("repo_id") or "") == root_repo_id:
            root_ports.update(int(value) for value in ports if value is not None)
            root_domains.update(domains)
    return (
        {
            "effective_repo": sorted(effective_ports),
            "root_repo": sorted(root_ports),
            "root_family": sorted(family_ports),
        },
        {
            "effective_repo": sorted(effective_domains),
            "root_repo": sorted(root_domains),
            "root_family": sorted(family_domains),
        },
    )


def _validate_resource_usage_consistency(
    *, family: Mapping[str, Any], resources: list[dict[str, Any]]
) -> None:
    """Reject a complete per-resource sample set that contradicts its scope total."""

    for scope in family.get("scopes") or []:
        if not isinstance(scope, Mapping):
            continue
        aggregate = scope.get("usage")
        if not isinstance(aggregate, Mapping):
            continue
        repo_id = str(scope.get("repo_id") or "")
        candidates = [
            item
            for item in resources
            if str(item.get("repo_id") or "") == repo_id
            and item.get("kind") in {"service", "docker"}
        ]
        server = aggregate.get("server")
        docker = aggregate.get("docker")
        expected_count = sum(
            int(item.get("resource_count") or 0)
            for item in (server, docker)
            if isinstance(item, Mapping)
        )
        if expected_count != len(candidates) or not candidates:
            continue
        usage_rows = [item.get("usage") for item in candidates]
        if not all(isinstance(item, Mapping) for item in usage_rows):
            continue
        cpu_values = [item.get("cpu_percent") for item in usage_rows]
        memory_values = [item.get("memory_bytes") for item in usage_rows]
        if aggregate.get("cpu_percent") is not None and all(
            value is not None for value in cpu_values
        ):
            observed_cpu = sum(float(value) for value in cpu_values)
            if abs(observed_cpu - float(aggregate["cpu_percent"])) > 0.01:
                raise RuntimeError(
                    f"resource CPU samples contradict repository scope total {repo_id}"
                )
        if aggregate.get("memory_bytes") is not None and all(
            value is not None for value in memory_values
        ):
            observed_memory = sum(int(value) for value in memory_values)
            if observed_memory != int(aggregate["memory_bytes"]):
                raise RuntimeError(
                    f"resource memory samples contradict repository scope total {repo_id}"
                )


def _retain_removed_temporary_scope_context(
    inventory: dict[str, Any],
    *,
    pre_action_inventory: dict[str, Any] | None,
    request: Mapping[str, Any],
    action_result: Mapping[str, Any],
    family_id: str,
    root_repo_id: str,
    effective_repo_id: str,
    project_kind: str,
) -> dict[str, Any]:
    """Retain an empty, already-validated temporary scope after its last worker.

    Permanent cleanup may intentionally remove the final active projection that
    kept a temporary repository visible.  The post-action inventory remains the
    authority for resources and utilization, while the immutable pre-action
    tree supplies only the request context needed to report that successful
    absence.  No resource IDs or pre-action usage are carried forward.
    """

    if pre_action_inventory is None:
        return inventory
    terminal_state = action_result.get("terminal_state")
    terminal_state = (
        terminal_state if isinstance(terminal_state, Mapping) else {}
    )
    may_remove_scope = bool(
        request.get("action") == "remove"
        and action_result.get("ok") is True
        and project_kind == "temporary"
        and effective_repo_id != root_repo_id
        and terminal_state.get("proof")
        in {"cleanup_archive", "cleanup_tombstone"}
    )
    if not may_remove_scope:
        return inventory

    # Both snapshots must be internally sound.  A stale or corrupt pre-action
    # tree is never accepted merely to make a successful mutation reportable.
    _validate_repository_tree_integrity(pre_action_inventory)
    _validate_repository_tree_integrity(inventory)
    pre_family, pre_scope = _family_and_scope(
        pre_action_inventory, family_id=family_id, repo_id=effective_repo_id
    )
    _pre_root_family, pre_root_scope = _family_and_scope(
        pre_action_inventory, family_id=family_id, repo_id=root_repo_id
    )
    if str(pre_scope.get("kind") or "") != "temporary":
        raise RuntimeError(
            "pre-action effective repository is not an authoritative temporary scope"
        )

    post_trees = inventory.get("repository_trees")
    post_family = next(
        (
            item
            for item in post_trees or []
            if isinstance(item, Mapping)
            and str(item.get("family_id") or "") == family_id
        ),
        None,
    )
    if post_family is None:
        raise RuntimeError(
            "post-action inventory lost the authoritative root repository family"
        )
    post_root = post_family.get("root_repository")
    pre_root = pre_family.get("root_repository")
    if (
        not isinstance(post_root, Mapping)
        or not isinstance(pre_root, Mapping)
        or str(post_root.get("repo_id") or "") != root_repo_id
        or str(pre_root.get("repo_id") or "") != root_repo_id
        or str(pre_root_scope.get("repo_id") or "") != root_repo_id
    ):
        raise RuntimeError("repository family root identity changed during removal")
    if any(
        isinstance(scope, Mapping)
        and str(scope.get("repo_id") or "") == effective_repo_id
        for scope in post_family.get("scopes") or []
    ):
        return inventory

    merged = copy.deepcopy(inventory)
    merged_family = next(
        item
        for item in merged["repository_trees"]
        if str(item.get("family_id") or "") == family_id
    )
    context_scope = copy.deepcopy(dict(pre_scope))
    for _kind, tree_key, _collection, _id_key in _TREE_RESOURCE_SPECS:
        context_scope[tree_key] = []
    context_scope["usage"] = {}
    merged_family["scopes"].append(context_scope)
    _validate_repository_tree_integrity(merged)
    return merged


def build_runtime_report(
    *,
    request: dict[str, Any],
    session_id: str | None,
    family_id: str,
    root_repo_id: str,
    effective_repo_id: str,
    project_kind: str,
    inventory: dict[str, Any],
    action_result: dict[str, Any],
    pre_action_inventory: dict[str, Any] | None = None,
    reaped_sessions: list[dict[str, Any]] | None = None,
    cleanup: dict[str, Any] | None = None,
) -> dict[str, Any]:
    inventory = _retain_removed_temporary_scope_context(
        inventory,
        pre_action_inventory=pre_action_inventory,
        request=request,
        action_result=action_result,
        family_id=family_id,
        root_repo_id=root_repo_id,
        effective_repo_id=effective_repo_id,
        project_kind=project_kind,
    )
    normalized_indexes = _validate_repository_tree_integrity(inventory)
    family, scope = _family_and_scope(
        inventory, family_id=family_id, repo_id=effective_repo_id
    )
    resources = _family_resources(
        inventory,
        family=family,
        effective_repo_id=effective_repo_id,
        normalized_indexes=normalized_indexes,
    )
    target_id = str((request.get("target") or {}).get("id") or "")
    target_kind = str((request.get("target") or {}).get("kind") or "")
    target_matches = [
        item
        for item in resources
        if str(item.get("id") or "") == target_id
        and str(item.get("kind") or "") == target_kind
    ]
    terminal_state = action_result.get("terminal_state")
    terminal_state = terminal_state if isinstance(terminal_state, Mapping) else {}
    observation_proof = terminal_state.get("observation_proof")
    observation_proof = (
        observation_proof if isinstance(observation_proof, Mapping) else {}
    )
    stop_state_is_terminal_absence = bool(
        terminal_state.get("observed_state") == "absent"
        or (
            target_kind == "database_stack"
            and terminal_state.get("observed_state") == "stopped"
            and terminal_state.get("database_available") is not True
            and terminal_state.get("database_resource_count") == 0
        )
    )
    proved_absent_stop = bool(
        request.get("action") == "stop"
        and target_kind in {"docker", "database_stack"}
        and not target_matches
        and terminal_state.get("proof") == "post_observation_inventory"
        and str(terminal_state.get("resource_kind") or "") == target_kind
        and str(terminal_state.get("resource_id") or "") == target_id
        and stop_state_is_terminal_absence
        and observation_proof.get("observer_domain")
        == "host-runtime-v2:full-docker"
        and observation_proof.get("docker_available") is True
    )
    proved_worker_removal = bool(
        request.get("action") == "remove"
        and target_kind == "service"
        and not target_matches
        and terminal_state.get("proof")
        in {"cleanup_plan_snapshot", "cleanup_archive", "cleanup_tombstone"}
        and str(terminal_state.get("resource_kind") or "") == "service"
        and str(terminal_state.get("resource_id") or "") == target_id
    )
    target_is_exact = bool(
        not target_id
        or proved_absent_stop
        or proved_worker_removal
        or (
            len(target_matches) == 1
            and str(target_matches[0].get("repo_id") or "")
            == effective_repo_id
        )
    )
    if action_result.get("ok") is True and not target_is_exact:
        action_result = {
            "ok": False,
            "classification": "unclassified_resource",
            "error": (
                "successful lifecycle result is not backed by one exact target "
                "in the effective repository tree"
            ),
            "mutation": action_result,
            "evidence": {
                "classification": "unclassified_resource",
                "resource_kind": target_kind,
                "resource_id": target_id,
                "reason_code": (
                    "duplicate_or_cross_scope_claim"
                    if target_matches
                    else "missing_authoritative_resource"
                ),
                "matching_tree_resource_count": len(target_matches),
            },
        }
    elif target_id and not any(
        str(item.get("id") or "") == target_id
        and str(item.get("kind") or "") == target_kind
        for item in resources
    ):
        # Failed operations may legitimately leave no target behind. Preserve
        # their evidence, but never publish action-result data as membership.
        pass
    _validate_resource_usage_consistency(family=family, resources=resources)
    ports, domains = _endpoint_summary(
        resources,
        effective_repo_id=effective_repo_id,
        root_repo_id=root_repo_id,
    )
    artifacts = _log_artifacts(
        inventory=inventory,
        resources=resources,
        request=request,
        action_result=action_result,
        session_id=session_id,
    )
    target_log_evidence, log_evidence_by_resource = _attach_log_evidence(
        resources=resources,
        request=request,
        action_result=action_result,
        artifacts=artifacts,
        effective_repo_id=effective_repo_id,
    )
    stale, crashes = _stale_and_crashes(
        inventory,
        family=family,
        log_evidence_by_resource=log_evidence_by_resource,
        artifacts=artifacts,
    )
    ok = action_result.get("ok") is True
    classification = action_result.get("classification")
    if not isinstance(classification, str) or not classification:
        classification = "ready" if ok else "runtime_result_unproven"

    root_scope = next(
        (
            item
            for item in family.get("scopes") or []
            if isinstance(item, Mapping) and str(item.get("repo_id") or "") == root_repo_id
        ),
        None,
    )
    if root_scope is None:
        raise RuntimeError(f"root repository scope {root_repo_id} is absent from inventory")

    report: dict[str, Any] = {
        "schema_version": 1,
        "ok": ok,
        "action": request.get("action"),
        "run_id": session_id,
        "classification": classification,
        "repository": {
            "family_id": family_id,
            "root_repo_id": root_repo_id,
            "effective_repo_id": effective_repo_id,
            "kind": "temporary" if project_kind == "temporary" else "root",
            "root_repo": request.get("root_repo"),
            "temporary_repo": request.get("temporary_repo"),
        },
        "target": _safe_action_value(request.get("target") or {}),
        "result": _safe_action_value(action_result),
        "resources": resources,
        "ports": ports,
        "domains": domains,
        "totals": {
            "effective_repo": _usage(scope.get("usage")),
            "root_repo": _usage(root_scope.get("usage")),
            "root_family": _usage(family.get("usage")),
        },
        "stale_processes": stale,
        "crashes": crashes,
        "artifacts": artifacts,
        "target_log_evidence": target_log_evidence,
        "cleanup": None if cleanup is None else _safe_action_value(cleanup),
        "reaped_sessions": _safe_action_value(
            (reaped_sessions or [])[:MAX_EVIDENCE_ITEMS]
        ),
        "reaped_session_count": len(reaped_sessions or []),
    }
    if action_result.get("error") is not None:
        report["error"] = _text(action_result["error"])
    if action_result.get("evidence") is not None:
        report["evidence"] = _safe_action_value(action_result["evidence"])
    if request.get("action") == "status" and type(action_result.get("ready")) is bool:
        report["ready"] = action_result["ready"]
    return report
