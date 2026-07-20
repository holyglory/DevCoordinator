"""Normalize one explicitly sampled host inventory into the account store."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Mapping

from .database_backups import reconcile_inventory_backups
from .events import append_observation_transition
from .store import canonical_json, deterministic_id, fingerprint, utc_timestamp


def _boolean(value: Any) -> int | None:
    if value is True or value == 1:
        return 1
    if value is False or value == 0:
        return 0
    return None


def _server_sample_unknown(
    *, lifecycle: str, health: Mapping[str, Any]
) -> bool:
    identity = health.get("identity")
    identity = identity if isinstance(identity, Mapping) else {}
    classification = str(health.get("classification") or "")
    if (
        classification in {"unobserved", "unverified-listener"}
        or identity.get("observable") is False
        or ("ok" in health and health.get("ok") is None)
        or ("ok" in identity and identity.get("ok") is None)
    ):
        # A dead PID or positively wrong listener remains a strict negative
        # observation even though no current listener owner can be returned.
        if (
            lifecycle == "stopped"
            and (
                health.get("pid_alive") is False
                or identity.get("ok") is False
                or classification in {"stopped", "wrong-listener"}
            )
        ):
            return False
        return True
    return False


def _stored_server_sample_unknown(row: sqlite3.Row) -> bool:
    classification = str(row["health_classification"] or "")
    if classification in {"unobserved", "unverified-listener"}:
        return True
    return row["listener_observable"] == 0


def _server_signal(
    *,
    lifecycle: str,
    health_classification: str | None,
    health_ok: Any,
    unknown: bool,
) -> str | None:
    if lifecycle == "stopped":
        return "stopped"
    if unknown or lifecycle in {"", "unobserved"}:
        return None
    classification = str(health_classification or "")
    if (
        lifecycle == "unhealthy"
        or health_ok is False
        or classification
        in {
            "unhealthy",
            "wrong-listener",
            "timeout",
            "stop-outcome-uncertain",
        }
    ):
        return "failed"
    if lifecycle in {"running", "starting", "stopping"}:
        return "active"
    return None


def _pending_server_stop(
    connection: sqlite3.Connection,
    *,
    definition_id: str,
) -> str | None:
    """Return the exact active stop intent for a managed server, if any.

    The normalized server lifecycle owns the user-visible ``server.stopped``
    event for an intentional stop.  Host observation can prove that the
    process reached the stopped boundary before that lifecycle transaction
    commits, so it must not emit a second event or relabel the requested stop
    as a crash.
    """

    row = connection.execute(
        """
        SELECT o.operation_id
        FROM operations o
        JOIN operation_targets t USING(operation_id)
        WHERE o.status = 'running'
          AND o.kind = 'server.stop'
          AND t.target_kind = 'server'
          AND t.target_id = ?
          AND t.action = 'stop'
        ORDER BY o.created_at DESC, o.operation_id
        LIMIT 1
        """,
        (definition_id,),
    ).fetchone()
    return None if row is None else str(row["operation_id"])


def _record_server_transition(
    connection: sqlite3.Connection,
    *,
    snapshot_id: str,
    definition_id: str,
    repo_id: str,
    name: str,
    previous: sqlite3.Row | None,
    lifecycle: str,
    health: Mapping[str, Any],
    timestamp: str,
    stopped_reason: Any,
) -> None:
    if previous is None:
        return
    previous_lifecycle = str(previous["lifecycle"] or "unobserved")
    current_unknown = _server_sample_unknown(lifecycle=lifecycle, health=health)
    if current_unknown:
        return
    previous_unknown = _stored_server_sample_unknown(previous)
    previous_signal = _server_signal(
        lifecycle=previous_lifecycle,
        health_classification=previous["health_classification"],
        health_ok=(
            None
            if previous["health_ok"] is None
            else bool(previous["health_ok"])
        ),
        unknown=previous_unknown,
    )
    current_signal = _server_signal(
        lifecycle=lifecycle,
        health_classification=str(health.get("classification") or ""),
        health_ok=health.get("ok"),
        unknown=False,
    )
    lifecycle_changed = (
        previous_lifecycle not in {"", "unobserved"}
        and previous_lifecycle != lifecycle
    )
    if not lifecycle_changed:
        if previous_unknown or previous_signal is None or previous_signal == current_signal:
            return
    if current_signal is None or previous_signal == current_signal:
        return

    if current_signal == "stopped" and _pending_server_stop(
        connection, definition_id=definition_id
    ) is not None:
        # commit_stop emits the authoritative server.stopped/server_stopped
        # event for this operation.  Suppress the observation-derived event so
        # Telegram/feed consumers receive one intentional stop, never a crash
        # followed by a duplicate stop.
        return

    if current_signal == "stopped":
        event_kind = "server.stopped"
        code = "server_crashed"
        message = f"Server {name} stopped unexpectedly"
    elif current_signal == "failed":
        event_kind = "server.failed"
        code = "server_observed_unhealthy"
        message = f"Server {name} became unhealthy"
    elif previous_signal == "stopped":
        event_kind = "server.started"
        code = "server_observed_started"
        message = f"Server {name} started"
    else:
        event_kind = "server.recovered"
        code = "server_observed_recovered"
        message = f"Server {name} recovered"
    append_observation_transition(
        connection,
        snapshot_id=snapshot_id,
        repo_id=repo_id,
        operation_id=None,
        resource_kind="server",
        resource_id=definition_id,
        event_kind=event_kind,
        code=code,
        message=message,
        diagnostic={
            "server_definition_id": definition_id,
            "name": name,
            "from": {
                "lifecycle": previous_lifecycle,
                "health_classification": previous["health_classification"],
            },
            "to": {
                "lifecycle": lifecycle,
                "health_classification": health.get("classification"),
            },
            "stopped_reason": stopped_reason,
            "observation_snapshot_id": snapshot_id,
        },
        occurred_at=timestamp,
    )


def _pending_docker_intent(
    connection: sqlite3.Connection,
    *,
    resource_id: str,
    repo_id: str | None,
) -> tuple[str | None, str | None]:
    row = connection.execute(
        """
        SELECT o.operation_id, t.action
        FROM operations o
        JOIN operation_targets t USING(operation_id)
        WHERE o.status = 'running'
          AND (
                (t.target_kind = 'container' AND t.target_id = ?
                 AND t.action IN ('docker.start', 'docker.stop', 'docker.restart'))
             OR (? IS NOT NULL AND o.repo_id = ? AND t.target_kind = 'compose'
                 AND t.action IN ('compose.up', 'compose.down'))
          )
        ORDER BY CASE WHEN t.target_kind = 'container' THEN 0 ELSE 1 END,
                 o.created_at DESC, o.operation_id
        LIMIT 1
        """,
        (resource_id, repo_id, repo_id),
    ).fetchone()
    if row is None:
        return None, None
    return str(row["operation_id"]), str(row["action"])


def _docker_signal(lifecycle: str, health: Any) -> str | None:
    if lifecycle == "stopped":
        return "stopped"
    if lifecycle != "running":
        return None
    if str(health or "").lower() == "unhealthy":
        return "failed"
    return "active"


def _record_docker_transition(
    connection: sqlite3.Connection,
    *,
    snapshot_id: str,
    resource_id: str,
    repo_id: str | None,
    name: str,
    previous: sqlite3.Row | None,
    lifecycle: str,
    health: Any,
    timestamp: str,
    absent: bool = False,
) -> None:
    if previous is None:
        return
    previous_lifecycle = str(previous["lifecycle"] or "")
    previous_signal = _docker_signal(previous_lifecycle, previous["health"])
    current_signal = _docker_signal(lifecycle, health)
    if previous_signal is None or current_signal is None or previous_signal == current_signal:
        return
    operation_id, intent = _pending_docker_intent(
        connection, resource_id=resource_id, repo_id=repo_id
    )
    intentional_stop = intent in {"docker.stop", "compose.down"}
    if current_signal == "stopped":
        event_kind = "docker.stopped"
        code = "docker_stopped" if intentional_stop else "docker_crashed"
        message = (
            f"Docker container {name} stopped"
            if intentional_stop
            else f"Docker container {name} stopped unexpectedly"
        )
    elif current_signal == "failed":
        event_kind = "docker.failed"
        code = "docker_observed_unhealthy"
        message = f"Docker container {name} became unhealthy"
    elif previous_signal == "stopped":
        event_kind = "docker.started"
        code = "docker_started"
        message = f"Docker container {name} started"
    else:
        event_kind = "docker.recovered"
        code = "docker_observed_recovered"
        message = f"Docker container {name} recovered"
    append_observation_transition(
        connection,
        snapshot_id=snapshot_id,
        repo_id=repo_id,
        operation_id=operation_id,
        resource_kind="container",
        resource_id=resource_id,
        event_kind=event_kind,
        code=code,
        message=message,
        diagnostic={
            "docker_resource_id": resource_id,
            "name": name,
            "from": {
                "lifecycle": previous_lifecycle,
                "health": previous["health"],
            },
            "to": {"lifecycle": lifecycle, "health": health},
            "absent": absent,
            "intent": intent,
            "observation_snapshot_id": snapshot_id,
        },
        occurred_at=timestamp,
    )


def _repository_resolution(
    connection: sqlite3.Connection,
    host_id: str,
    project: Any,
) -> tuple[str | None, str | None, str]:
    """Resolve observed path evidence to the nearest canonical Git worktree.

    Docker Compose records its invocation directory, which is commonly a
    deploy/infra child of the repository. Walking upward to the first .git
    marker maps that explicit path evidence to the canonical worktree without
    guessing from the container name. The nearest marker also preserves a
    genuinely nested worktree as a distinct repository.
    """

    if not project:
        return None, None, "name_only"
    observed = Path(str(project)).expanduser().resolve()
    candidate = observed if observed.is_dir() else observed.parent
    registered: list[tuple[Path, str]] = []
    for row in connection.execute(
        "SELECT repo_id, canonical_root FROM repositories WHERE host_id = ?",
        (host_id,),
    ):
        registered_root = Path(str(row["canonical_root"]))
        try:
            observed.relative_to(registered_root)
        except ValueError:
            continue
        registered.append((registered_root, str(row["repo_id"])))
    registered.sort(key=lambda item: len(item[0].parts), reverse=True)

    root_path: Path | None = None
    if registered:
        registered_root, registered_id = registered[0]
        # A .git marker below the deepest enrolled ancestor is positive
        # evidence of a distinct nested worktree. Do not silently collapse it
        # into the outer repository.
        for directory in (candidate, *candidate.parents):
            if directory == registered_root:
                break
            if (directory / ".git").exists():
                root_path = directory
                break
        if root_path is None:
            return registered_id, str(registered_root), ""
    elif (observed / ".git").exists():
        # Preserve the existing exact-root discovery behavior, but never claim
        # an arbitrary directory merely because some unregistered ancestor
        # happens to contain a .git marker.
        root_path = observed
    else:
        reason = "not_git" if observed.exists() else "missing_repo"
        return None, str(observed), reason

    root = str(root_path)
    row = connection.execute(
        "SELECT repo_id FROM repositories WHERE host_id = ? AND canonical_root = ?",
        (host_id, root),
    ).fetchone()
    if row is not None:
        return str(row[0]), root, ""
    # Observation may register a newly installed repository only from the
    # proved nearest Git root. Resource-name similarity is never sufficient.
    timestamp = utc_timestamp()
    repo_id = deterministic_id("repository", host_id, root)
    connection.execute(
        """
        INSERT INTO repositories(
            repo_id, host_id, canonical_root, display_name, state,
            generation, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'active', 0, ?, ?)
        """,
        (repo_id, host_id, root, Path(root).name or root, timestamp, timestamp),
    )
    connection.execute(
        """
        INSERT INTO repository_installations(
            repo_id, status, startup_fenced, generation, actor, updated_at
        ) VALUES (?, 'installed', 0, 0, 'host-observer', ?)
        """,
        (repo_id, timestamp),
    )
    return repo_id, root, ""


def _repository_id(connection: sqlite3.Connection, host_id: str, project: Any) -> str | None:
    return _repository_resolution(connection, host_id, project)[0]


def _normalized_source(
    connection: sqlite3.Connection,
    *,
    host_id: str,
    coordinator_home: str,
    effective_uid: int,
) -> str:
    timestamp = utc_timestamp()
    database_path = str(Path(coordinator_home) / "coordinator.sqlite3")
    source_id = deterministic_id("normalized-account-source", host_id, coordinator_home)
    # coordinator_sources.canonical_home is a unique source locator, not the
    # user-facing coordinator_home field. The SQLite authority uses its exact
    # database endpoint so an imported legacy state.json source can retain the
    # same containing directory as its canonical home without an identity
    # collision. Inventory's top-level coordinator_home remains the directory.
    connection.execute(
        """
        INSERT INTO coordinator_sources(
            source_id, host_id, canonical_home, state_path, effective_uid,
            status, imported_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 'imported', ?, ?, ?)
        ON CONFLICT(source_id) DO UPDATE SET
            status = 'imported', updated_at = excluded.updated_at
        """,
        (
            source_id,
            host_id,
            database_path,
            database_path,
            int(effective_uid),
            timestamp,
            timestamp,
            timestamp,
        ),
    )
    return source_id


def _ports_text(connection: sqlite3.Connection, resource_id: str) -> str | None:
    rows = connection.execute(
        """
        SELECT host_address, host_port, container_port, protocol
        FROM docker_ports WHERE docker_resource_id = ? ORDER BY ordinal
        """,
        (resource_id,),
    ).fetchall()
    if not rows:
        return None
    values: list[str] = []
    for row in rows:
        destination = f"{row['container_port']}/{row['protocol']}"
        if row["host_port"] is None:
            values.append(destination)
        else:
            address = str(row["host_address"] or "0.0.0.0")
            values.append(f"{address}:{row['host_port']}->{destination}")
    return ", ".join(values)


def commit_host_inventory_observation(
    connection: sqlite3.Connection,
    snapshot_id: str,
    sample: Mapping[str, Any],
    *,
    host_id: str,
    coordinator_home: str,
    effective_uid: int | None = None,
) -> None:
    """Commit only measured facts from one single-flight host sample.

    Repository creation requires an exact Git root. Containers without that
    evidence remain explicit unassigned resources; their names are never used
    as repository identity.
    """

    inventory = sample.get("inventory")
    if not isinstance(inventory, Mapping):
        raise TypeError("host observation sample lacks an inventory mapping")
    docker = inventory.get("docker")
    docker = docker if isinstance(docker, Mapping) else {}
    docker_available = docker.get("available") is True
    capability_material = {
        "observer_domain": connection.execute(
            "SELECT observer_domain FROM observation_snapshots WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchone(),
        "docker_available": docker_available,
        "docker_error": docker.get("error"),
    }
    domain_row = capability_material.pop("observer_domain")
    if domain_row is None:
        raise RuntimeError("host observation capability lost its snapshot ticket")
    observer_domain = str(domain_row[0])
    connection.execute(
        """
        INSERT INTO observation_capabilities(
            snapshot_id, observer_domain, docker_available,
            capability_fingerprint, committed_at
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (
            snapshot_id,
            observer_domain,
            int(docker_available),
            "sha256:"
            + fingerprint(
                {"observer_domain": observer_domain, **capability_material}
            ),
            str(sample.get("sampled_at") or utc_timestamp()),
        ),
    )
    uid = os.geteuid() if effective_uid is None else int(effective_uid)
    timestamp = str(sample.get("sampled_at") or utc_timestamp())
    source_id = _normalized_source(
        connection,
        host_id=host_id,
        coordinator_home=coordinator_home,
        effective_uid=uid,
    )

    compose_scope_table = connection.execute(
        """
        SELECT 1 FROM sqlite_master
        WHERE type = 'table' AND name = 'broker_observation_compose_scope'
        """
    ).fetchone()
    compose_container_table = connection.execute(
        """
        SELECT 1 FROM sqlite_master
        WHERE type = 'table'
          AND name = 'broker_observed_compose_containers'
        """
    ).fetchone()
    if compose_scope_table is not None:
        raw_assets = docker.get("compose_assets")
        assets_complete = (
            docker.get("container_inspection_available") is True
            and docker.get("compose_assets_available") is True
        )
        if raw_assets is None:
            raw_assets = []
        if not isinstance(raw_assets, list):
            raise TypeError("Docker Compose asset observation must be a list")
        normalized_assets: list[dict[str, str | None]] = []
        if assets_complete:
            for raw_asset in raw_assets:
                if not isinstance(raw_asset, Mapping):
                    raise TypeError("Docker Compose asset evidence must be a mapping")
                asset_kind = str(raw_asset.get("kind") or "")
                asset_id = str(raw_asset.get("id") or "")
                project_name = str(raw_asset.get("project_name") or "")
                working_dir_raw = raw_asset.get("working_dir")
                working_dir = (
                    None
                    if working_dir_raw in {None, ""}
                    else str(Path(str(working_dir_raw)).expanduser().resolve())
                )
                if (
                    asset_kind not in {"network", "volume"}
                    or not 1 <= len(asset_id) <= 512
                    or not 1 <= len(project_name) <= 128
                ):
                    raise ValueError("Docker Compose asset evidence is invalid")
                normalized_assets.append(
                    {
                        "kind": asset_kind,
                        "id": asset_id,
                        "project_name": project_name,
                        "working_dir": working_dir,
                    }
                )
        elif raw_assets:
            raise ValueError(
                "incomplete Docker Compose asset observation must not claim assets"
            )
        scope_evidence = {
            "assets_complete": assets_complete,
            "assets": normalized_assets,
        }
        connection.execute(
            """
            INSERT INTO broker_observation_compose_scope(
                snapshot_id, assets_complete, observed_asset_count,
                evidence_fingerprint, recorded_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                snapshot_id,
                int(assets_complete),
                len(normalized_assets),
                "sha256:" + fingerprint(scope_evidence),
                timestamp,
            ),
        )
        for asset in normalized_assets:
            observation_fingerprint = "sha256:" + fingerprint(asset)
            connection.execute(
                """
                INSERT INTO broker_observed_compose_assets(
                    snapshot_id, asset_kind, asset_id, project_name,
                    working_dir, observation_fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    asset["kind"],
                    asset["id"],
                    asset["project_name"],
                    asset["working_dir"],
                    observation_fingerprint,
                ),
            )
            connection.execute(
                """
                INSERT OR REPLACE INTO observation_snapshot_resources(
                    snapshot_id, resource_kind, resource_id,
                    observation_fingerprint
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    asset["kind"],
                    asset["id"],
                    observation_fingerprint,
                ),
            )

    # Server definitions are authoritative catalog rows. Observation updates
    # their measured lifecycle only; it does not rewrite launch definitions.
    for server in inventory.get("servers") or []:
        if not isinstance(server, Mapping):
            continue
        repo_id = _repository_id(connection, host_id, server.get("project"))
        definition = None
        if repo_id is not None and server.get("name"):
            definition = connection.execute(
                """
                SELECT server_definition_id, repo_id, name FROM server_definitions
                WHERE repo_id = ? AND name = ?
                """,
                (repo_id, str(server["name"])),
            ).fetchone()
        if definition is None and server.get("id"):
            definition = connection.execute(
                """
                SELECT d.server_definition_id, d.repo_id, d.name
                FROM server_source_records ss
                JOIN source_resources sr USING(source_resource_id)
                JOIN server_definitions d USING(server_definition_id)
                WHERE sr.native_id = ? AND sr.resource_kind = 'server'
                ORDER BY ss.server_definition_id LIMIT 1
                """,
                (str(server["id"]),),
            ).fetchone()
        if definition is None:
            continue
        definition_id = str(definition["server_definition_id"])
        health = server.get("health") if isinstance(server.get("health"), Mapping) else {}
        identity = health.get("identity") if isinstance(health.get("identity"), Mapping) else {}
        lifecycle = str(server.get("status") or "unobserved")
        previous_observation = connection.execute(
            """
            SELECT lifecycle, listener_observable, health_classification,
                   health_ok, stopped_reason
            FROM server_observations WHERE server_definition_id = ?
            """,
            (definition_id,),
        ).fetchone()
        payload = {
            "lifecycle": lifecycle,
            "pid": server.get("pid"),
            "process_start_time": server.get("process_start_time") or server.get("pid_start_time"),
            "process_fingerprint": server.get("process_fingerprint") or server.get("process_instance_id"),
            "listener_host": server.get("host") or "127.0.0.1",
            "listener_port": server.get("port"),
            "listener_observable": identity.get("observable", server.get("identity_observable")),
            "health_classification": health.get("classification") or server.get("health_classification"),
            "health_ok": health.get("ok", server.get("health_ok")),
            "stopped_at": server.get("stopped_at"),
            "stopped_reason": server.get("stopped_reason"),
            "sampled_at": timestamp,
        }
        _record_server_transition(
            connection,
            snapshot_id=snapshot_id,
            definition_id=definition_id,
            repo_id=str(definition["repo_id"]),
            name=str(definition["name"]),
            previous=previous_observation,
            lifecycle=lifecycle,
            health=health,
            timestamp=timestamp,
            stopped_reason=payload["stopped_reason"],
        )
        connection.execute(
            """
            INSERT INTO server_observations(
                server_definition_id, lifecycle, pid, process_start_time,
                process_fingerprint, listener_host, listener_port,
                listener_observable, health_classification, health_ok,
                stopped_at, stopped_reason, sampled_at, observation_fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(server_definition_id) DO UPDATE SET
                lifecycle = excluded.lifecycle,
                pid = excluded.pid,
                process_start_time = excluded.process_start_time,
                process_fingerprint = excluded.process_fingerprint,
                listener_host = excluded.listener_host,
                listener_port = excluded.listener_port,
                listener_observable = excluded.listener_observable,
                health_classification = excluded.health_classification,
                health_ok = excluded.health_ok,
                stopped_at = excluded.stopped_at,
                stopped_reason = excluded.stopped_reason,
                sampled_at = excluded.sampled_at,
                observation_fingerprint = excluded.observation_fingerprint
            """,
            (
                definition_id,
                lifecycle,
                payload["pid"],
                payload["process_start_time"],
                payload["process_fingerprint"],
                payload["listener_host"],
                payload["listener_port"],
                _boolean(payload["listener_observable"]),
                payload["health_classification"],
                _boolean(payload["health_ok"]),
                payload["stopped_at"],
                payload["stopped_reason"],
                timestamp,
                fingerprint(payload),
            ),
        )
        connection.execute(
            """
            INSERT OR REPLACE INTO observation_snapshot_resources(
                snapshot_id, resource_kind, resource_id, observation_fingerprint
            ) VALUES (?, 'server', ?, ?)
            """,
            (snapshot_id, definition_id, fingerprint(payload)),
        )
        usage = (
            server.get("process_usage")
            if isinstance(server.get("process_usage"), Mapping)
            else None
        )
        if usage is not None:
            usage_sampled_at = str(usage.get("sampled_at") or timestamp)
            connection.execute(
                """
                INSERT OR IGNORE INTO telemetry_samples(
                    sample_id, host_resource_kind, host_resource_id, sampled_at,
                    cpu_percent, memory_bytes, network_rx_bytes, network_tx_bytes,
                    block_read_bytes, block_write_bytes
                ) VALUES (?, 'server', ?, ?, ?, ?, NULL, NULL, NULL, NULL)
                """,
                (
                    deterministic_id(
                        "telemetry", "server", definition_id, usage_sampled_at
                    ),
                    definition_id,
                    usage_sampled_at,
                    usage.get("cpu_percent"),
                    usage.get("memory_bytes", usage.get("rss_bytes")),
                ),
            )

    docker = inventory.get("docker") if isinstance(inventory.get("docker"), Mapping) else {}
    capability = "available" if docker.get("available") is True else "unavailable"
    engine_id = deterministic_id("docker-engine", host_id, "default")
    connection.execute(
        """
        INSERT INTO docker_engines(
            engine_id, host_id, context_identity, capability_state, created_at, updated_at
        ) VALUES (?, ?, 'default', ?, ?, ?)
        ON CONFLICT(engine_id) DO UPDATE SET
            capability_state = excluded.capability_state,
            updated_at = excluded.updated_at
        """,
        (engine_id, host_id, capability, timestamp, timestamp),
    )
    observed_resource_ids: set[str] = set()
    compose_containers: list[dict[str, str | None]] = []
    for container in docker.get("containers") or []:
        if not isinstance(container, Mapping):
            continue
        full_id = str(container.get("full_id") or container.get("id") or "").strip()
        if not full_id:
            continue
        resource_id = deterministic_id("docker-resource", engine_id, full_id)
        observed_resource_ids.add(resource_id)
        name = str(container.get("name") or full_id[:12])
        connection.execute(
            """
            INSERT INTO docker_resources(
                docker_resource_id, engine_id, full_container_id, current_name,
                image, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(docker_resource_id) DO UPDATE SET
                current_name = excluded.current_name,
                image = excluded.image,
                updated_at = excluded.updated_at
            """,
            (resource_id, engine_id, full_id, name, container.get("image"), timestamp, timestamp),
        )
        if type(container.get("running")) is not bool:
            raise ValueError(
                "Docker container observation lacks exact inspected lifecycle evidence"
            )
        running = bool(container["running"])
        lifecycle = "running" if running else "stopped"
        inspection_observable = (
            container.get("inspection_observable") is not False
            and str(container.get("metadata_source") or "") != "inspection_unavailable"
        )
        ownership_observable = (
            str(container.get("metadata_source") or "") != "inspection_unavailable"
        )
        labels = container.get("labels") if isinstance(container.get("labels"), Mapping) else {}
        compose_project_name = str(
            labels.get("com.docker.compose.project") or ""
        ).strip()
        compose_service_name = str(
            labels.get("com.docker.compose.service") or ""
        ).strip()
        port_bindings = container.get("port_bindings") if isinstance(container.get("port_bindings"), list) else []
        previous_observation = connection.execute(
            """
            SELECT o.lifecycle, o.health, o.restart_policy,
                   o.ports_fingerprint, o.labels_fingerprint,
                   (
                       SELECT m.repo_id FROM repository_memberships m
                       WHERE m.resource_kind = 'container'
                         AND m.host_resource_id = o.docker_resource_id
                       LIMIT 1
                   ) AS repo_id
            FROM docker_observations o WHERE o.docker_resource_id = ?
            """,
            (resource_id,),
        ).fetchone()
        if inspection_observable:
            health = container.get("container_health")
            restart_policy = container.get("restart_policy")
            ports_fingerprint = fingerprint(port_bindings)
            labels_fingerprint = fingerprint(labels)
            observation_payload = {
                "lifecycle": lifecycle,
                "health": health,
                "restart_policy": restart_policy,
                "ports": port_bindings,
                "labels": labels,
                "sampled_at": timestamp,
            }
        else:
            # `docker ps` still proves name and lifecycle while inspect is
            # unavailable. It does not prove that previously observed ports,
            # labels, health, or restart policy disappeared, so retain that
            # enrichment until another successful inspect replaces it.
            health = previous_observation["health"] if previous_observation is not None else None
            restart_policy = (
                previous_observation["restart_policy"]
                if previous_observation is not None
                else None
            )
            ports_fingerprint = (
                previous_observation["ports_fingerprint"]
                if previous_observation is not None
                else None
            )
            labels_fingerprint = (
                previous_observation["labels_fingerprint"]
                if previous_observation is not None
                else None
            )
            observation_payload = {
                "lifecycle": lifecycle,
                "health": health,
                "restart_policy": restart_policy,
                "ports_fingerprint": ports_fingerprint,
                "labels_fingerprint": labels_fingerprint,
                "inspection_observable": False,
                "sampled_at": timestamp,
            }
        observation_fingerprint = fingerprint(observation_payload)
        if compose_project_name and compose_container_table is not None:
            normalized_full_id = full_id.lower()
            if (
                len(normalized_full_id) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in normalized_full_id
                )
                or len(compose_project_name) > 512
                or len(compose_service_name) > 512
            ):
                raise ValueError(
                    "Docker Compose container identity evidence is invalid"
                )
            compose_containers.append(
                {
                    "docker_resource_id": resource_id,
                    "full_container_id": normalized_full_id,
                    "project_name": compose_project_name,
                    "service_name": compose_service_name or None,
                    "lifecycle": lifecycle,
                    "observation_fingerprint": observation_fingerprint,
                }
            )
        connection.execute(
            """
            INSERT INTO docker_observations(
                docker_resource_id, lifecycle, health, restart_policy,
                ports_fingerprint, labels_fingerprint, sampled_at,
                observation_fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(docker_resource_id) DO UPDATE SET
                lifecycle = excluded.lifecycle,
                health = excluded.health,
                restart_policy = excluded.restart_policy,
                ports_fingerprint = excluded.ports_fingerprint,
                labels_fingerprint = excluded.labels_fingerprint,
                sampled_at = excluded.sampled_at,
                observation_fingerprint = excluded.observation_fingerprint
            """,
            (
                resource_id,
                lifecycle,
                health,
                restart_policy,
                ports_fingerprint,
                labels_fingerprint,
                timestamp,
                observation_fingerprint,
            ),
        )
        if inspection_observable:
            connection.execute("DELETE FROM docker_ports WHERE docker_resource_id = ?", (resource_id,))
            for ordinal, binding in enumerate(port_bindings):
                if not isinstance(binding, Mapping) or not binding.get("container_port"):
                    continue
                connection.execute(
                    """
                    INSERT INTO docker_ports(
                        docker_resource_id, ordinal, host_address, host_port,
                        container_port, protocol
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        resource_id,
                        ordinal,
                        binding.get("host_address"),
                        binding.get("host_port"),
                        int(binding["container_port"]),
                        str(binding.get("protocol") or "tcp"),
                    ),
                )
            connection.execute("DELETE FROM docker_labels WHERE docker_resource_id = ?", (resource_id,))
            for label, value in sorted(labels.items()):
                connection.execute(
                    "INSERT INTO docker_labels(docker_resource_id, name, value) VALUES (?, ?, ?)",
                    (resource_id, str(label), str(value)),
                )

        retirement = connection.execute(
            """
            SELECT status FROM resource_retirements
            WHERE resource_kind = 'container' AND host_resource_id = ?
            """,
            (resource_id,),
        ).fetchone()
        retirement_status = str(retirement[0]) if retirement is not None else None
        if retirement_status in {"disabling", "retired"}:
            # Observation remains truthful after a standalone fence, but it may
            # never turn retained evidence back into an attachable resource.
            # A running retired container is projected separately as a
            # start_fence_violated attention item.
            connection.execute(
                """
                UPDATE control_bindings
                SET authority_state = 'retired', generation = generation + 1,
                    updated_at = ?
                WHERE resource_kind = 'container' AND resource_id = ?
                  AND authority_state != 'retired'
                """,
                (timestamp, resource_id),
            )
            connection.execute(
                """
                UPDATE unassigned_resources SET status = 'retired', updated_at = ?
                WHERE host_id = ? AND resource_kind = 'container'
                  AND resource_id = ? AND status = 'active'
                """,
                (timestamp, host_id, resource_id),
            )
            repo_id = None
            effective_repo_id = None
            ownership_conflict = False
        else:
            repo_id, suggested_root, unresolved_reason = _repository_resolution(
                connection,
                host_id,
                container.get("project"),
            )
            binding_id = deterministic_id("control-binding", "container", resource_id)
            existing_binding = connection.execute(
                """
                SELECT authority_state, provenance FROM control_bindings
                WHERE binding_id = ?
                """,
                (binding_id,),
            ).fetchone()
            existing_membership = connection.execute(
                """
                SELECT m.repo_id, m.control_binding_id, b.provenance
                FROM repository_memberships m
                LEFT JOIN control_bindings b ON b.binding_id = m.control_binding_id
                WHERE m.resource_kind = 'container' AND m.host_resource_id = ?
                """,
                (resource_id,),
            ).fetchone()
            ownership_conflict = bool(
                (
                    repo_id is not None
                    and existing_membership is not None
                    and str(existing_membership["repo_id"]) != repo_id
                )
                or (
                    repo_id is None
                    and existing_membership is None
                    and existing_binding is not None
                    and str(existing_binding["authority_state"]) == "conflicting"
                    and str(existing_binding["provenance"]) == "conflicting_exact_claim"
                )
            )
            if ownership_conflict:
                # Only a contradictory exact Git-root claim can invalidate an
                # existing membership. A pathless observation is absence of new
                # attribution evidence and must preserve an explicit attach.
                connection.execute(
                    """
                    DELETE FROM repository_memberships
                    WHERE resource_kind = 'container' AND host_resource_id = ?
                    """,
                    (resource_id,),
                )
                effective_repo_id = None
            elif repo_id is not None:
                effective_repo_id = repo_id
            elif existing_membership is not None:
                effective_repo_id = str(existing_membership["repo_id"])
            else:
                effective_repo_id = None
        event_repo_id = effective_repo_id
        if event_repo_id is None and previous_observation is not None:
            event_repo_id = (
                str(previous_observation["repo_id"])
                if previous_observation["repo_id"] is not None
                else None
            )
        _record_docker_transition(
            connection,
            snapshot_id=snapshot_id,
            resource_id=resource_id,
            repo_id=event_repo_id,
            name=name,
            previous=previous_observation,
            lifecycle=lifecycle,
            health=health,
            timestamp=timestamp,
        )
        source_resource_id = deterministic_id("source-resource", source_id, "container", full_id)
        if retirement_status not in {"disabling", "retired"}:
            source_repo_id = repo_id if ownership_observable else effective_repo_id
            connection.execute(
                """
                INSERT INTO source_resources(
                    source_resource_id, source_id, resource_kind, native_id,
                    repo_id, payload_sha256, provenance_json, created_at
                ) VALUES (?, ?, 'container', ?, ?, ?, ?, ?)
                ON CONFLICT(source_id, resource_kind, native_id) DO UPDATE SET
                    repo_id = excluded.repo_id,
                    payload_sha256 = excluded.payload_sha256,
                    provenance_json = excluded.provenance_json
                """,
                (
                    source_resource_id,
                    source_id,
                    full_id,
                    source_repo_id,
                    fingerprint(container),
                    canonical_json(
                        {
                            "metadata_source": container.get("metadata_source") or "none",
                            "observed_name": name,
                        }
                    ),
                    timestamp,
                ),
            )
            # Repository attribution and controller authority are separate
            # facts. Contradictory exact roots are deliberately non-actionable;
            # pathless observations retain an existing explicit membership.
            authority_state = "conflicting" if ownership_conflict else "authoritative"
            binding_provenance = (
                "conflicting_exact_claim"
                if ownership_conflict
                else str(container.get("metadata_source") or "observer")
            )
            connection.execute(
                """
                INSERT INTO control_bindings(
                    binding_id, repo_id, source_resource_id, resource_kind,
                    resource_id, source_id, capability, provenance,
                    authority_state, priority, generation, created_at, updated_at
                ) VALUES (?, ?, ?, 'container', ?, ?, 'lifecycle', ?, ?, ?, 0, ?, ?)
                ON CONFLICT(binding_id) DO UPDATE SET
                    repo_id = excluded.repo_id,
                    source_resource_id = excluded.source_resource_id,
                    provenance = CASE
                        WHEN control_bindings.provenance = 'operator_attach'
                         AND excluded.authority_state = 'authoritative'
                        THEN control_bindings.provenance
                        WHEN excluded.provenance = 'inspection_unavailable'
                         AND control_bindings.authority_state = 'authoritative'
                        THEN control_bindings.provenance
                        ELSE excluded.provenance
                    END,
                    authority_state = excluded.authority_state,
                    priority = excluded.priority,
                    generation = control_bindings.generation + 1,
                    updated_at = excluded.updated_at
                """,
                (
                    binding_id,
                    effective_repo_id,
                    source_resource_id,
                    resource_id,
                    source_id,
                    binding_provenance,
                    authority_state,
                    100,
                    timestamp,
                    timestamp,
                ),
            )
            if ownership_conflict:
                connection.execute(
                    """
                    UPDATE startup_policies SET repo_id = NULL,
                        generation = generation + 1, updated_at = ?
                    WHERE resource_kind = 'container' AND resource_id = ?
                      AND repo_id IS NOT NULL
                    """,
                    (timestamp, resource_id),
                )
            elif repo_id is not None:
                connection.execute(
                    """
                    INSERT INTO repository_memberships(
                        membership_id, repo_id, resource_kind, host_resource_id,
                        immutable_fingerprint, control_binding_id, created_at
                    ) VALUES (?, ?, 'container', ?, ?, ?, ?)
                    ON CONFLICT(resource_kind, host_resource_id) DO UPDATE SET
                        immutable_fingerprint = excluded.immutable_fingerprint,
                        control_binding_id = excluded.control_binding_id
                    """,
                    (
                        deterministic_id("membership", repo_id, "container", resource_id),
                        repo_id,
                        resource_id,
                        "sha256:"
                        + fingerprint(
                            {"engine_id": engine_id, "container_id": full_id}
                        ),
                        binding_id,
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    UPDATE unassigned_resources SET status = 'attached', updated_at = ?
                    WHERE host_id = ? AND resource_kind = 'container' AND resource_id = ?
                    """,
                    (timestamp, host_id, resource_id),
                )

            if effective_repo_id is None:
                existing_unassigned = connection.execute(
                    """
                    SELECT reason_code FROM unassigned_resources
                    WHERE host_id = ? AND resource_kind = 'container'
                      AND resource_id = ? AND status = 'active'
                    ORDER BY updated_at DESC LIMIT 1
                    """,
                    (host_id, resource_id),
                ).fetchone()
                # An inspect race is absence of new ownership evidence. Keep a
                # prior exact/unassigned classification instead of replacing
                # it with a weaker name-only observation.
                if not ownership_observable and existing_unassigned is not None:
                    reason = str(existing_unassigned["reason_code"])
                    preserve_unassigned = True
                else:
                    reason = (
                        "conflicting_claims"
                        if ownership_conflict
                        else "stale_observation"
                        if not ownership_observable
                        else unresolved_reason
                    )
                    preserve_unassigned = False
                if preserve_unassigned:
                    reason = str(existing_unassigned["reason_code"])
                else:
                    connection.execute(
                        """
                        UPDATE unassigned_resources SET status = 'attached', updated_at = ?
                        WHERE host_id = ? AND resource_kind = 'container'
                          AND resource_id = ? AND status = 'active' AND reason_code != ?
                        """,
                        (timestamp, host_id, resource_id, reason),
                    )
                    connection.execute(
                        """
                        INSERT INTO unassigned_resources(
                            unassigned_id, host_id, source_resource_id, resource_kind,
                            resource_id, display_name, reason_code, suggested_root,
                            status, created_at, updated_at
                        ) VALUES (?, ?, ?, 'container', ?, ?, ?, ?, 'active', ?, ?)
                        ON CONFLICT(host_id, resource_kind, resource_id, reason_code) DO UPDATE SET
                            source_resource_id = excluded.source_resource_id,
                            display_name = excluded.display_name,
                            suggested_root = excluded.suggested_root,
                            status = 'active',
                            updated_at = excluded.updated_at
                        """,
                        (
                            deterministic_id(
                                "unassigned", host_id, "container", resource_id, reason
                            ),
                            host_id,
                            source_resource_id,
                            resource_id,
                            name,
                            reason,
                            suggested_root,
                            timestamp,
                            timestamp,
                        ),
                    )

            restart_policy = container.get("restart_policy")
            if restart_policy is not None:
                installation = None
                if effective_repo_id is not None:
                    installation = connection.execute(
                        "SELECT status FROM repository_installations WHERE repo_id = ?",
                        (effective_repo_id,),
                    ).fetchone()
                repository_fenced = bool(
                    installation is not None
                    and str(installation[0]) in {"disabling", "disabled"}
                )
                if not repository_fenced:
                    policy_id = deterministic_id(
                        "startup-policy", "container", resource_id, "docker_restart"
                    )
                    policy_fingerprint = "sha256:" + fingerprint(
                        {
                            "engine_id": engine_id,
                            "full_container_id": full_id.lower(),
                            "policy_kind": "docker_restart",
                        }
                    )
                    connection.execute(
                        """
                        INSERT INTO startup_policies(
                            policy_id, repo_id, resource_kind, resource_id,
                            policy_kind, current_value, desired_disabled_value,
                            immutable_fingerprint, generation, updated_at
                        ) VALUES (?, ?, 'container', ?, 'docker_restart', ?, 'no', ?, 0, ?)
                        ON CONFLICT(resource_kind, resource_id, policy_kind) DO UPDATE SET
                            repo_id = excluded.repo_id,
                            current_value = excluded.current_value,
                            immutable_fingerprint = excluded.immutable_fingerprint,
                            generation = CASE
                                WHEN startup_policies.repo_id IS NOT excluded.repo_id
                                  OR startup_policies.current_value != excluded.current_value
                                  OR startup_policies.immutable_fingerprint
                                     != excluded.immutable_fingerprint
                                THEN startup_policies.generation + 1
                                ELSE startup_policies.generation
                            END,
                            updated_at = excluded.updated_at
                        """,
                        (
                            policy_id,
                            effective_repo_id,
                            resource_id,
                            str(restart_policy),
                            policy_fingerprint,
                            timestamp,
                        ),
                    )

        observed_database_names: set[str] = set()
        for database in container.get("databases") or []:
            if not isinstance(database, Mapping) or not database.get("name"):
                continue
            database_name = str(database["name"])
            observed_database_names.add(database_name)
            database_binding_id = deterministic_id(
                "database-binding", resource_id, database_name
            )
            connection.execute(
                """
                INSERT INTO database_bindings(
                    database_binding_id, docker_resource_id, repo_id,
                    database_name, engine_kind, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'postgresql', ?, ?)
                ON CONFLICT(docker_resource_id, database_name) DO UPDATE SET
                    repo_id = excluded.repo_id,
                    updated_at = excluded.updated_at
                """,
                (
                    database_binding_id,
                    resource_id,
                    effective_repo_id,
                    database_name,
                    timestamp,
                    timestamp,
                ),
            )
            raw_size = database.get("size_bytes")
            size_bytes = (
                int(raw_size)
                if type(raw_size) is int and int(raw_size) >= 0
                else None
            )
            database_observation = {
                "database_binding_id": database_binding_id,
                "docker_resource_id": resource_id,
                "available": True,
                "size_bytes": size_bytes,
                "sampled_at": timestamp,
            }
            connection.execute(
                """
                INSERT INTO database_observations(
                    database_binding_id, docker_resource_id, available,
                    size_bytes, error_code, error_message, sampled_at,
                    observation_fingerprint
                ) VALUES (?, ?, 1, ?, NULL, NULL, ?, ?)
                ON CONFLICT(database_binding_id) DO UPDATE SET
                    docker_resource_id = excluded.docker_resource_id,
                    available = 1,
                    size_bytes = excluded.size_bytes,
                    error_code = NULL,
                    error_message = NULL,
                    sampled_at = excluded.sampled_at,
                    observation_fingerprint = excluded.observation_fingerprint
                """,
                (
                    database_binding_id,
                    resource_id,
                    size_bytes,
                    timestamp,
                    fingerprint(database_observation),
                ),
            )

        database_error = container.get("database_discovery_error")
        previous_bindings = connection.execute(
            """
            SELECT database_binding_id, database_name
            FROM database_bindings WHERE docker_resource_id = ?
            ORDER BY database_binding_id
            """,
            (resource_id,),
        ).fetchall()
        for binding in previous_bindings:
            database_name = str(binding["database_name"])
            if database_name in observed_database_names:
                continue
            error_code = (
                "database_discovery_failed"
                if database_error
                else "database_absent"
            )
            error_message = (
                str(database_error)
                if database_error
                else "The database was absent from the latest successful PostgreSQL catalog observation."
            )
            database_observation = {
                "database_binding_id": str(binding["database_binding_id"]),
                "docker_resource_id": resource_id,
                "available": False,
                "size_bytes": None,
                "error_code": error_code,
                "error_message": error_message,
                "sampled_at": timestamp,
            }
            connection.execute(
                """
                INSERT INTO database_observations(
                    database_binding_id, docker_resource_id, available,
                    size_bytes, error_code, error_message, sampled_at,
                    observation_fingerprint
                ) VALUES (?, ?, 0, NULL, ?, ?, ?, ?)
                ON CONFLICT(database_binding_id) DO UPDATE SET
                    docker_resource_id = excluded.docker_resource_id,
                    available = 0,
                    size_bytes = NULL,
                    error_code = excluded.error_code,
                    error_message = excluded.error_message,
                    sampled_at = excluded.sampled_at,
                    observation_fingerprint = excluded.observation_fingerprint
                """,
                (
                    binding["database_binding_id"],
                    resource_id,
                    error_code,
                    error_message,
                    timestamp,
                    fingerprint(database_observation),
                ),
            )

        connection.execute(
            """
            INSERT OR REPLACE INTO observation_snapshot_resources(
                snapshot_id, resource_kind, resource_id, observation_fingerprint
            ) VALUES (?, 'container', ?, ?)
            """,
            (snapshot_id, resource_id, observation_fingerprint),
        )

        stats = container.get("stats") if isinstance(container.get("stats"), Mapping) else None
        if stats is not None and stats.get("timestamp"):
            connection.execute(
                """
                INSERT OR IGNORE INTO telemetry_samples(
                    sample_id, host_resource_kind, host_resource_id, sampled_at,
                    cpu_percent, memory_bytes, network_rx_bytes, network_tx_bytes,
                    block_read_bytes, block_write_bytes
                ) VALUES (?, 'docker', ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    deterministic_id("telemetry", "docker", resource_id, stats["timestamp"]),
                    resource_id,
                    str(stats["timestamp"]),
                    stats.get("cpu_percent"),
                    stats.get("memory_usage_bytes"),
                    stats.get("network_rx_bytes"),
                    stats.get("network_tx_bytes"),
                    stats.get("block_read_bytes"),
                    stats.get("block_write_bytes"),
                ),
            )

    if compose_container_table is not None:
        for container in compose_containers:
            owner_rows = list(
                connection.execute(
                    """
                    SELECT DISTINCT membership.repo_id
                    FROM repository_memberships membership
                    JOIN control_bindings binding
                      ON binding.binding_id = membership.control_binding_id
                    WHERE membership.resource_kind = 'container'
                      AND membership.host_resource_id = ?
                      AND binding.authority_state = 'authoritative'
                    ORDER BY membership.repo_id
                    """,
                    (container["docker_resource_id"],),
                )
            )
            owner_ids = tuple(str(row["repo_id"]) for row in owner_rows)
            ownership_state = (
                "exclusive"
                if len(owner_ids) == 1
                else ("missing" if not owner_ids else "conflicting")
            )
            evidence = {
                **container,
                "ownership_state": ownership_state,
                "authoritative_owner_repo_id": (
                    owner_ids[0] if ownership_state == "exclusive" else None
                ),
            }
            connection.execute(
                """
                INSERT INTO broker_observed_compose_containers(
                    snapshot_id, docker_resource_id, full_container_id,
                    project_name, service_name, lifecycle, ownership_state,
                    authoritative_owner_repo_id, observation_fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    evidence["docker_resource_id"],
                    evidence["full_container_id"],
                    evidence["project_name"],
                    evidence["service_name"],
                    evidence["lifecycle"],
                    evidence["ownership_state"],
                    evidence["authoritative_owner_repo_id"],
                    "sha256:" + fingerprint(evidence),
                ),
            )

    # A completed snapshot is authoritative absence evidence for the engine.
    # Keep durable resource identity/history, but mark resources not present in
    # this sample stopped instead of deleting them.
    if docker.get("available") is True:
        rows = connection.execute(
            """
            SELECT d.docker_resource_id, d.current_name, o.lifecycle, o.health,
                   (
                       SELECT m.repo_id FROM repository_memberships m
                       WHERE m.resource_kind = 'container'
                         AND m.host_resource_id = d.docker_resource_id
                       LIMIT 1
                   ) AS repo_id
            FROM docker_resources d
            JOIN docker_observations o USING(docker_resource_id)
            WHERE d.engine_id = ?
            """,
            (engine_id,),
        ).fetchall()
        for row in rows:
            resource_id = str(row["docker_resource_id"])
            if resource_id in observed_resource_ids:
                continue
            payload = {"lifecycle": "stopped", "sampled_at": timestamp, "absent": True}
            _record_docker_transition(
                connection,
                snapshot_id=snapshot_id,
                resource_id=resource_id,
                repo_id=(str(row["repo_id"]) if row["repo_id"] is not None else None),
                name=str(row["current_name"] or resource_id),
                previous=row,
                lifecycle="stopped",
                health=row["health"],
                timestamp=timestamp,
                absent=True,
            )
            connection.execute(
                """
                UPDATE docker_observations SET lifecycle = 'stopped', sampled_at = ?,
                    observation_fingerprint = ? WHERE docker_resource_id = ?
                """,
                (timestamp, fingerprint(payload), resource_id),
            )

    reconcile_inventory_backups(connection, inventory)

    connection.execute(
        """
        UPDATE schema_metadata
        SET authority_mode = 'sqlite',
            first_sqlite_mutation_at = COALESCE(first_sqlite_mutation_at, ?),
            updated_at = ?
        WHERE singleton = 1
        """,
        (timestamp, timestamp),
    )
