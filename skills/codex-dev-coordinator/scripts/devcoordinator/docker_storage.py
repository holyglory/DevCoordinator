"""Cached, project-attributed Docker storage evidence.

The authority process owns this observer.  Agent clients consume its bounded
inventory projection and never invoke Docker directly.  The host total comes
from Docker's own system summary.  Project writable layers, logs, and named
volumes are measured directly; project image sizes are explicitly logical and
may share layers.  Container rootfs size is retained only as diagnostic
evidence because it overlaps the image plus writable layer.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from typing import Any, Callable, Mapping, Sequence

from .store import canonical_json, fingerprint, utc_timestamp


_CACHE_SECONDS = 60.0
_CACHE_LOCK = threading.Lock()
_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_REFRESHING: set[str] = set()
_FULL_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_NATIVE_BATCH_SIZE = 32


class DockerStorageError(RuntimeError):
    """The bounded storage observer could not produce trustworthy evidence."""


CommandRunner = Callable[[Sequence[str], float], subprocess.CompletedProcess[str]]


def _native_batches(values: Sequence[str]) -> list[list[str]]:
    ordered = list(values)
    return [
        ordered[offset : offset + _NATIVE_BATCH_SIZE]
        for offset in range(0, len(ordered), _NATIVE_BATCH_SIZE)
    ]


def _run(argv: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv),
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/var/lib/devcoordinator",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        },
    )


def _json_lines(
    result: subprocess.CompletedProcess[str], *, label: str
) -> list[dict[str, Any]]:
    if result.returncode != 0:
        raise DockerStorageError(f"{label} failed")
    rows: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as error:
            raise DockerStorageError(f"{label} returned malformed JSON") from error
        if not isinstance(item, dict):
            raise DockerStorageError(f"{label} returned a non-object row")
        rows.append(item)
    return rows


def _non_negative_bytes(value: Any) -> int:
    if type(value) is int and value >= 0:
        return value
    if isinstance(value, float) and value >= 0 and value.is_integer():
        return int(value)
    if not isinstance(value, str):
        return 0
    text = value.strip().replace(" ", "")
    if text.isdigit():
        return int(text)
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([kmgtpe]?i?b)", text, re.I)
    if match is None:
        return 0
    magnitude = float(match.group(1))
    unit = match.group(2).lower()
    powers = {
        "b": 0,
        "kb": 1,
        "kib": 1,
        "mb": 2,
        "mib": 2,
        "gb": 3,
        "gib": 3,
        "tb": 4,
        "tib": 4,
        "pb": 5,
        "pib": 5,
        "eb": 6,
        "eib": 6,
    }
    base = 1024 if "i" in unit else 1000
    return int(magnitude * (base ** powers[unit]))


def _owners(graph: Mapping[str, Any]) -> tuple[dict[str, set[str]], dict[str, dict[str, str]]]:
    owners: dict[str, set[str]] = {}
    repositories: dict[str, dict[str, str]] = {}
    for tree in graph.get("repository_trees") or []:
        if not isinstance(tree, Mapping):
            continue
        root = tree.get("root_repository")
        if not isinstance(root, Mapping):
            continue
        root_id = str(root.get("repo_id") or "")
        if not root_id:
            continue
        repositories[root_id] = {
            "repo_id": root_id,
            "display_name": str(root.get("display_name") or root_id),
            "canonical_root": str(root.get("canonical_root") or ""),
        }
        for scope in tree.get("scopes") or []:
            if not isinstance(scope, Mapping):
                continue
            for resource_id in scope.get("container_resource_ids") or []:
                owners.setdefault(str(resource_id), set()).add(root_id)
    return owners, repositories


def _directory_sizes(
    mountpoints: Sequence[str], runner: CommandRunner
) -> dict[str, int]:
    unique = sorted({value for value in mountpoints if value.startswith("/")})
    if not unique:
        return {}
    result = runner(["/usr/bin/du", "-sb", "--", *unique], 20.0)
    if result.returncode != 0:
        raise DockerStorageError("Docker volume size inspection failed")
    sizes: dict[str, int] = {}
    for line in result.stdout.splitlines():
        raw_size, separator, raw_path = line.partition("\t")
        if separator and raw_size.isdigit() and raw_path in unique:
            sizes[raw_path] = int(raw_size)
    if set(sizes) != set(unique):
        raise DockerStorageError("Docker volume size inspection was incomplete")
    return sizes


def _cache_key(
    graph: Mapping[str, Any],
    compose_project_owners: Mapping[str, Sequence[str]],
) -> str:
    resources = graph.get("resources")
    raw_docker = resources.get("docker") if isinstance(resources, Mapping) else []
    docker = [
        {
            "docker_resource_id": row.get("docker_resource_id"),
            "full_container_id": row.get("full_container_id"),
            "current_name": row.get("current_name"),
        }
        for row in (raw_docker or [])
        if isinstance(row, Mapping)
    ]
    ownership = [
        {
            "repo": tree.get("root_repository"),
            "scopes": [
                {
                    "repo_id": scope.get("repo_id"),
                    "container_resource_ids": scope.get("container_resource_ids"),
                }
                for scope in tree.get("scopes") or []
                if isinstance(scope, Mapping)
            ],
        }
        for tree in graph.get("repository_trees") or []
        if isinstance(tree, Mapping)
    ]
    compose_ownership = {
        str(project_name): sorted({str(repo_id) for repo_id in repo_ids})
        for project_name, repo_ids in sorted(compose_project_owners.items())
    }
    return fingerprint(
        {
            "docker": docker,
            "ownership": ownership,
            "compose_project_owners": compose_ownership,
        }
    )


def project_docker_storage_inventory(
    graph: Mapping[str, Any],
    *,
    compose_project_owners: Mapping[str, Sequence[str]] | None = None,
    runner: CommandRunner = _run,
) -> dict[str, Any]:
    """Measure one Docker storage snapshot and attribute known owners."""

    owners_by_resource, repositories = _owners(graph)
    normalized_compose_owners = {
        str(project_name): {
            str(repo_id)
            for repo_id in repo_ids
            if str(repo_id) in repositories
        }
        for project_name, repo_ids in (compose_project_owners or {}).items()
        if str(project_name)
    }
    resources = graph.get("resources")
    docker_rows = resources.get("docker") if isinstance(resources, Mapping) else []
    normalized = [row for row in (docker_rows or []) if isinstance(row, Mapping)]
    by_full_id: dict[str, Mapping[str, Any]] = {}
    for row in normalized:
        full_id = str(row.get("full_container_id") or "").lower()
        if _FULL_CONTAINER_ID.fullmatch(full_id):
            by_full_id[full_id] = row

    inspected: list[dict[str, Any]] = []
    for batch in _native_batches(sorted(by_full_id)):
        inspected.extend(
            _json_lines(
                runner(
                    [
                        "/usr/bin/docker",
                        "inspect",
                        "--size",
                        "--format",
                        "{{json .}}",
                        *batch,
                    ],
                    20.0,
                ),
                label="Docker container storage inspection",
            )
        )
    container_records: list[dict[str, Any]] = []
    referenced_images: dict[str, set[str]] = {}
    volume_owners: dict[str, set[str]] = {}
    volume_mountpoints: dict[str, str] = {}
    for item in inspected:
        full_id = str(item.get("Id") or "").lower()
        source = by_full_id.get(full_id)
        if source is None:
            raise DockerStorageError("Docker storage inspection returned an unknown container")
        resource_id = str(source.get("docker_resource_id") or "")
        project_ids = sorted(owners_by_resource.get(resource_id, set()))
        state = item.get("State") if isinstance(item.get("State"), Mapping) else {}
        config = item.get("Config") if isinstance(item.get("Config"), Mapping) else {}
        labels = config.get("Labels") if isinstance(config.get("Labels"), Mapping) else {}
        compose_owned = any(str(key).startswith("com.docker.compose.") for key in labels)
        compose_oneoff = (
            str(labels.get("com.docker.compose.oneoff") or "").lower() == "true"
        )
        log_path = str(item.get("LogPath") or "")
        try:
            log_bytes = max(0, os.stat(log_path, follow_symlinks=False).st_size) if log_path else 0
        except OSError:
            log_bytes = 0
        image_id = str(item.get("Image") or "")
        if _IMAGE_ID.fullmatch(image_id):
            referenced_images.setdefault(image_id, set()).update(project_ids)
        mounts: list[dict[str, Any]] = []
        for mount in item.get("Mounts") or []:
            if not isinstance(mount, Mapping):
                continue
            name = str(mount.get("Name") or "")
            mountpoint = str(mount.get("Source") or "")
            if str(mount.get("Type") or "") == "volume" and name:
                volume_owners.setdefault(name, set()).update(project_ids)
                if mountpoint:
                    volume_mountpoints[name] = mountpoint
            mounts.append({"type": str(mount.get("Type") or ""), "name": name})
        writable = _non_negative_bytes(item.get("SizeRw"))
        rootfs = _non_negative_bytes(item.get("SizeRootFs"))
        container_records.append(
            {
                "docker_resource_id": resource_id,
                "full_container_id": full_id,
                "name": str(source.get("current_name") or full_id[:12]),
                "project_ids": project_ids,
                "running": bool(state.get("Running")),
                "compose_owned": compose_owned,
                "compose_oneoff": compose_oneoff,
                "writable_layer_bytes": writable,
                "rootfs_diagnostic_bytes": rootfs,
                "log_bytes": log_bytes,
                "reclaimable_bytes": writable + log_bytes,
                "mounts": mounts,
                "image_id": image_id if _IMAGE_ID.fullmatch(image_id) else None,
            }
        )

    image_ids = {
        str(row.get("ID") or row.get("Id") or "")
        for row in _json_lines(
            runner(
                [
                    "/usr/bin/docker",
                    "image",
                    "ls",
                    "--no-trunc",
                    "--format",
                    "{{json .}}",
                ],
                15.0,
            ),
            label="Docker image listing",
        )
    }
    image_ids = {value for value in image_ids if _IMAGE_ID.fullmatch(value)}
    image_records: list[dict[str, Any]] = []
    if image_ids:
        image_inspect: list[dict[str, Any]] = []
        for batch in _native_batches(sorted(image_ids)):
            image_inspect.extend(
                _json_lines(
                    runner(
                        [
                            "/usr/bin/docker",
                            "image",
                            "inspect",
                            "--format",
                            "{{json .}}",
                            *batch,
                        ],
                        20.0,
                    ),
                    label="Docker image storage inspection",
                )
            )
        for item in image_inspect:
            image_id = str(item.get("Id") or "")
            if image_id not in image_ids:
                raise DockerStorageError("Docker image inspection returned an unknown image")
            repo_tags = sorted(
                value for value in (item.get("RepoTags") or []) if isinstance(value, str)
            )
            project_ids = sorted(referenced_images.get(image_id, set()))
            image_records.append(
                {
                    "image_id": image_id,
                    "repo_tags": repo_tags,
                    "project_ids": project_ids,
                    "physical_bytes": _non_negative_bytes(item.get("Size")),
                    "referenced": image_id in referenced_images,
                }
            )

    volume_listing = runner(["/usr/bin/docker", "volume", "ls", "-q"], 15.0)
    if volume_listing.returncode != 0:
        raise DockerStorageError("Docker volume listing failed")
    volume_names = sorted(
        line.strip()
        for line in volume_listing.stdout.splitlines()
        if line.strip()
    )
    volume_records: list[dict[str, Any]] = []
    if volume_names:
        volume_inspect: list[dict[str, Any]] = []
        for batch in _native_batches(volume_names):
            volume_inspect.extend(
                _json_lines(
                    runner(
                        [
                            "/usr/bin/docker",
                            "volume",
                            "inspect",
                            "--format",
                            "{{json .}}",
                            *batch,
                        ],
                        20.0,
                    ),
                    label="Docker volume inspection",
                )
            )
        inspected_volumes: dict[str, Mapping[str, Any]] = {}
        for item in volume_inspect:
            name = str(item.get("Name") or "")
            if name not in volume_names:
                raise DockerStorageError("Docker volume inspection returned an unknown volume")
            inspected_volumes[name] = item
            mountpoint = str(item.get("Mountpoint") or volume_mountpoints.get(name) or "")
            volume_mountpoints[name] = mountpoint
        sizes = _directory_sizes(list(volume_mountpoints.values()), runner)
        for name in volume_names:
            item = inspected_volumes.get(name)
            if item is None:
                raise DockerStorageError("Docker volume inspection was incomplete")
            labels = item.get("Labels") if isinstance(item.get("Labels"), Mapping) else {}
            options = item.get("Options") if isinstance(item.get("Options"), Mapping) else {}
            compose_project = str(labels.get("com.docker.compose.project") or "")
            compose_volume = str(labels.get("com.docker.compose.volume") or "")
            project_owners = set(volume_owners.get(name, set()))
            project_owners.update(normalized_compose_owners.get(compose_project, set()))
            project_ids = sorted(project_owners)
            identity_material = {
                "volume_name": name,
                "created_at": str(item.get("CreatedAt") or ""),
                "driver": str(item.get("Driver") or ""),
                "scope": str(item.get("Scope") or ""),
                "labels_fingerprint": "sha256:" + fingerprint(dict(labels)),
                "options_fingerprint": "sha256:" + fingerprint(dict(options)),
                "compose_project": compose_project,
                "compose_volume": compose_volume,
            }
            volume_records.append(
                {
                    "volume_name": name,
                    "project_ids": project_ids,
                    "physical_bytes": sizes.get(volume_mountpoints.get(name, ""), 0),
                    "referenced": name in volume_owners,
                    "compose_owned": bool(compose_project and compose_volume),
                    "compose_project": compose_project or None,
                    "identity_fingerprint": "sha256:" + fingerprint(identity_material),
                    "identity_complete": bool(
                        identity_material["created_at"]
                        and identity_material["driver"]
                        and identity_material["scope"]
                    ),
                }
            )

    build_cache_records: list[dict[str, Any]] = []
    cache_result = runner(
        ["/usr/bin/docker", "builder", "du", "--verbose", "--format", "{{json .}}"],
        20.0,
    )
    if cache_result.returncode == 0:
        for item in _json_lines(cache_result, label="Docker build-cache inspection"):
            cache_id = str(item.get("ID") or item.get("Id") or "")
            if not cache_id:
                continue
            build_cache_records.append(
                {
                    "cache_id": cache_id,
                    "project_ids": [],
                    "physical_bytes": _non_negative_bytes(item.get("Size")),
                    "reclaimable": bool(item.get("Reclaimable")),
                    "usage_count": int(item.get("UsageCount") or 0),
                    "last_used_at": item.get("LastUsedAt"),
                    "attribution": "unclassified_by_docker",
                }
            )

    docker_totals = _json_lines(
        runner(
            ["/usr/bin/docker", "system", "df", "--format", "json"],
            15.0,
        ),
        label="Docker physical-storage summary",
    )
    physical_total = sum(
        _non_negative_bytes(row.get("Size")) for row in docker_totals
    )

    project_totals: dict[str, dict[str, int]] = {
        repo_id: {
            "container_writable_bytes": 0,
            "container_log_bytes": 0,
            "exclusive_image_bytes": 0,
            "shared_image_bytes": 0,
            "exclusive_volume_bytes": 0,
            "shared_volume_bytes": 0,
        }
        for repo_id in repositories
    }

    def project_components(repo_id: str) -> dict[str, int]:
        return project_totals.setdefault(
            repo_id,
            {
                "container_writable_bytes": 0,
                "container_log_bytes": 0,
                "exclusive_image_bytes": 0,
                "shared_image_bytes": 0,
                "exclusive_volume_bytes": 0,
                "shared_volume_bytes": 0,
            },
        )

    for row in container_records:
        for repo_id in row["project_ids"]:
            components = project_components(repo_id)
            components["container_writable_bytes"] += row["writable_layer_bytes"]
            components["container_log_bytes"] += row["log_bytes"]
    for field, rows in (("image", image_records), ("volume", volume_records)):
        for row in rows:
            project_ids = row["project_ids"]
            target = (
                f"exclusive_{field}_bytes"
                if len(project_ids) == 1
                else f"shared_{field}_bytes"
            )
            for repo_id in project_ids:
                project_components(repo_id)[target] += row["physical_bytes"]

    projects: list[dict[str, Any]] = []
    for repo_id, identity in sorted(
        repositories.items(), key=lambda item: item[1]["display_name"].casefold()
    ):
        components = project_totals.get(repo_id, {})
        exclusive = sum(
            value
            for key, value in components.items()
            if key.startswith("exclusive_") or key.startswith("container_")
        )
        shared = sum(
            value for key, value in components.items() if key.startswith("shared_")
        )
        projects.append(
            {
                **identity,
                "exclusive_attributed_bytes": exclusive,
                "referenced_shared_bytes": shared,
                "components": components,
                "measurement": {
                    "container_writable_logs_and_volumes": "physical_apparent_bytes",
                    "images": "docker_logical_bytes_may_share_layers",
                },
            }
        )

    cleanup_plans: list[dict[str, Any]] = []
    for row in container_records:
        if (
            not row["running"]
            and not row["mounts"]
            and (not row["compose_owned"] or row["compose_oneoff"])
        ):
            proof = ["stopped", "unmounted", "exact_identity"]
            if row["compose_oneoff"]:
                proof.append("compose_oneoff")
            cleanup_plans.append(
                {
                    "target_kind": "container",
                    "target_id": row["docker_resource_id"],
                    "native_id": row["full_container_id"],
                    "project_ids": row["project_ids"],
                    "reclaimable_bytes": row["reclaimable_bytes"],
                    "proof": proof,
                    "apply_supported": True,
                }
            )
    for row in image_records:
        if not row["referenced"]:
            cleanup_plans.append(
                {
                    "target_kind": "image",
                    "target_id": row["image_id"],
                    "project_ids": [],
                    "reclaimable_bytes": row["physical_bytes"],
                    "proof": ["unreferenced_by_any_container", "exact_identity"],
                    "apply_supported": False,
                }
            )
    for row in volume_records:
        if not row["referenced"]:
            apply_supported = bool(
                row["compose_owned"]
                and row["identity_complete"]
                and len(row["project_ids"]) == 1
            )
            proof = ["unreferenced_by_any_container", "exact_identity"]
            if row["compose_owned"]:
                proof.append("compose_owned")
            if len(row["project_ids"]) == 1:
                proof.append("exclusive_project_ownership")
            cleanup_plans.append(
                {
                    "target_kind": "volume",
                    "target_id": row["volume_name"],
                    "project_ids": row["project_ids"],
                    "reclaimable_bytes": row["physical_bytes"],
                    "proof": proof,
                    "identity_fingerprint": row["identity_fingerprint"],
                    "apply_supported": apply_supported,
                }
            )
    for row in build_cache_records:
        if row["reclaimable"] and row["usage_count"] == 0:
            cleanup_plans.append(
                {
                    "target_kind": "build_cache",
                    "target_id": row["cache_id"],
                    "project_ids": [],
                    "reclaimable_bytes": row["physical_bytes"],
                    "proof": ["docker_reclaimable", "zero_usage", "exact_identity"],
                    "apply_supported": False,
                }
            )

    document = {
        "schema_version": 1,
        "available": True,
        "sampled_at": utc_timestamp(),
        "physical_total_bytes": physical_total,
        "projects": projects,
        "containers": container_records,
        "images": image_records,
        "volumes": volume_records,
        "build_cache": build_cache_records,
        "cleanup_plans": cleanup_plans,
        "accounting": {
            "container_rootfs_is_diagnostic_only": True,
            "physical_total_source": "docker_system_df",
            "project_image_sizes_are_logical": True,
            "project_image_layers_may_overlap": True,
            "build_cache_attribution": "unclassified_by_docker",
        },
    }
    document["evidence_fingerprint"] = "sha256:" + fingerprint(document)
    return document


def cached_project_docker_storage_inventory(
    graph: Mapping[str, Any],
    *,
    compose_project_owners: Mapping[str, Sequence[str]] | None = None,
) -> dict[str, Any]:
    normalized_compose_owners = compose_project_owners or {}
    key = _cache_key(graph, normalized_compose_owners)
    now = time.monotonic()
    with _CACHE_LOCK:
        cached = _CACHE.get(key)
        if cached is not None and now - cached[0] < _CACHE_SECONDS:
            return json.loads(canonical_json(cached[1]))
        should_refresh = key not in _REFRESHING
        if should_refresh:
            _REFRESHING.add(key)
    if should_refresh:
        frozen_graph = json.loads(canonical_json(graph))
        frozen_compose_owners = json.loads(canonical_json(normalized_compose_owners))

        def refresh() -> None:
            result: dict[str, Any] = {
                "schema_version": 1,
                "available": False,
                "status": "unavailable",
                "sampled_at": utc_timestamp(),
                "error": "storage observer terminated unexpectedly",
                "projects": [],
                "cleanup_plans": [],
            }
            try:
                result = project_docker_storage_inventory(
                    frozen_graph,
                    compose_project_owners=frozen_compose_owners,
                )
            except (
                DockerStorageError,
                OSError,
                subprocess.SubprocessError,
                ValueError,
            ) as error:
                result = {
                    "schema_version": 1,
                    "available": False,
                    "status": "unavailable",
                    "sampled_at": utc_timestamp(),
                    "error": str(error)[:512],
                    "projects": [],
                    "cleanup_plans": [],
                }
            except Exception as error:  # defensive: observer failures cannot wedge refresh
                result = {
                    "schema_version": 1,
                    "available": False,
                    "status": "unavailable",
                    "sampled_at": utc_timestamp(),
                    "error": f"unexpected storage observer failure: {error}"[:512],
                    "projects": [],
                    "cleanup_plans": [],
                }
            finally:
                with _CACHE_LOCK:
                    _CACHE.clear()
                    _CACHE[key] = (time.monotonic(), result)
                    _REFRESHING.discard(key)

        threading.Thread(
            target=refresh,
            name="devcoordinator-docker-storage",
            daemon=True,
        ).start()
    if cached is not None:
        stale = json.loads(canonical_json(cached[1]))
        stale["stale"] = True
        return stale
    return {
        "schema_version": 1,
        "available": False,
        "status": "collecting",
        "sampled_at": utc_timestamp(),
        "projects": [],
        "cleanup_plans": [],
    }
