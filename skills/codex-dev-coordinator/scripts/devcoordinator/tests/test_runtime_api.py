from __future__ import annotations

import copy
import http.client
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from unittest import mock

import dev_coordinator
import devcoordinator.runtime_api as runtime_api_module
import devcoordinator.runtime_sessions as runtime_sessions_module

from devcoordinator.repository_context import (
    RepositoryScopeIdentity,
    find_repository_id_by_filesystem_identity,
    persist_repository_context,
    resolve_repository_context,
)
from devcoordinator.runtime_api import (
    RuntimeCallbacks,
    RuntimeCleanupOwnerRequired,
    RuntimeRequestError,
    RuntimeSafeReplaceUnavailable,
    execute_runtime_request,
    validate_runtime_request,
)
from devcoordinator.runtime_sessions import (
    cleanup_runtime_session,
    create_runtime_session,
    finish_runtime_session,
    link_runtime_resource,
    mark_runtime_session_started,
    next_runtime_cleanup_at,
    reap_expired_runtime_sessions,
)
from devcoordinator.schema import SCHEMA_VERSION
from devcoordinator.schema import invariant_violations
from devcoordinator.sqlite_lifecycle import SQLiteLifecyclePersistence
from devcoordinator.store import (
    AccountStore,
    StoreInvariantError,
    deterministic_id,
    utc_timestamp,
)
from devcoordinator.worker_control import WorkerReplaceError
from devcoordinator.worker_supervision import WorkerSupervision


class RuntimeApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="devcoordinator-runtime-api-", dir=Path.home()
        )
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "coordinator"
        self.repository = self.root / "repository"
        self.repository.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repository)], check=True)
        subprocess.run(
            ["git", "-C", str(self.repository), "config", "user.email", "test@example.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.repository), "config", "user.name", "Test"],
            check=True,
        )
        (self.repository / "tracked.txt").write_text("tracked\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(self.repository), "add", "tracked.txt"], check=True
        )
        subprocess.run(
            ["git", "-C", str(self.repository), "commit", "-qm", "fixture"],
            check=True,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_inventory_keeps_only_current_observation_snapshot_evidence(self) -> None:
        with AccountStore.open_default(
            self.home, effective_uid=os.geteuid()
        ) as store:
            host_id = store.ensure_local_host()
            with store.immediate_transaction(revision_kind="observation") as connection:
                connection.executemany(
                    """
                    INSERT INTO observation_snapshots(
                        snapshot_id, host_id, observer_domain, status,
                        started_at, completed_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            "domain-a-old-completed",
                            host_id,
                            "observer:domain-a",
                            "completed",
                            "2026-01-01T00:00:00Z",
                            "2026-01-01T00:00:01Z",
                        ),
                        (
                            "domain-a-current-completed",
                            host_id,
                            "observer:domain-a",
                            "completed",
                            "2026-01-02T00:00:00Z",
                            "2026-01-02T00:00:01Z",
                        ),
                        (
                            "domain-a-running",
                            host_id,
                            "observer:domain-a",
                            "running",
                            "2026-01-03T00:00:00Z",
                            None,
                        ),
                        (
                            "domain-b-current-completed",
                            host_id,
                            "observer:domain-b",
                            "completed",
                            "2026-01-04T00:00:00Z",
                            "2026-01-04T00:00:01Z",
                        ),
                    ],
                )
            snapshots = store.inventory_v2()["observations"]["snapshots"]

        self.assertEqual(
            {row["snapshot_id"] for row in snapshots},
            {
                "domain-a-current-completed",
                "domain-a-running",
                "domain-b-current-completed",
            },
        )
        self.assertTrue(
            all(
                "latest_ordinal" not in row and "status_ordinal" not in row
                for row in snapshots
            )
        )

    def request(self, **changes: object) -> dict[str, object]:
        value: dict[str, object] = {
            "schema_version": 1,
            "action": "start",
            "agent": "test-agent",
            "root_repo": str(self.repository),
            "temporary_repo": None,
            "target": {"kind": "service", "name": "web"},
            "purpose": "development",
            "ttl_seconds": None,
            "kill_after_run": False,
            "options": {"argv": ["/usr/bin/true"]},
        }
        value.update(changes)
        return value

    def _insert_repository(self, store: AccountStore) -> tuple[str, str]:
        host_id = store.ensure_local_host()
        repo_id = deterministic_id("repository", host_id, str(self.repository))
        timestamp = utc_timestamp()
        with store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO repositories(
                    repo_id, host_id, canonical_root, display_name, state,
                    generation, created_at, updated_at
                ) VALUES (?, ?, ?, 'repository', 'active', 0, ?, ?)
                """,
                (repo_id, host_id, str(self.repository), timestamp, timestamp),
            )
            connection.execute(
                """
                INSERT INTO repository_installations(
                    repo_id, status, startup_fenced, generation, actor, updated_at
                ) VALUES (?, 'installed', 0, 0, 'test', ?)
                """,
                (repo_id, timestamp),
            )
        return host_id, repo_id

    def _insert_running_service(
        self, store: AccountStore, *, repo_id: str, host_id: str
    ) -> str:
        server_id = deterministic_id("server-definition", repo_id, "web")
        timestamp = "2026-01-01T00:00:00Z"
        with store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO server_definitions(
                    server_definition_id, repo_id, name, cwd,
                    definition_fingerprint, generation, created_at, updated_at
                ) VALUES (?, ?, 'web', ?, ?, 0, ?, ?)
                """,
                (
                    server_id,
                    repo_id,
                    str(self.repository),
                    "definition",
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute(
                """
                INSERT INTO server_observations(
                    server_definition_id, lifecycle, pid, process_start_time,
                    process_fingerprint, listener_host, listener_port,
                    listener_observable, health_classification, health_ok,
                    sampled_at, observation_fingerprint
                ) VALUES (?, 'running', ?, 'fixture-start',
                          'fixture-process', '127.0.0.1', 3210, 1,
                          'ready', 1, ?, 'observation')
                """,
                (server_id, os.getpid(), timestamp),
            )
            connection.execute(
                """
                INSERT INTO port_assignments(
                    assignment_id, host_id, repo_id, server_name, port,
                    status, generation, created_at, updated_at
                ) VALUES (?, ?, ?, 'web', 3210, 'active', 0, ?, ?)
                """,
                (
                    deterministic_id("assignment", repo_id, "web"),
                    host_id,
                    repo_id,
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute(
                """
                INSERT INTO leases(
                    lease_id, host_id, repo_id, server_definition_id,
                    port, owner, agent, purpose, status,
                    process_fingerprint, generation, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 3210, ?, 'test-agent', 'development',
                          'active', 'fixture-process', 0, ?, ?)
                """,
                (
                    deterministic_id("lease", server_id),
                    host_id,
                    repo_id,
                    server_id,
                    str(os.getpid()),
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute(
                """
                INSERT INTO repository_memberships(
                    membership_id, repo_id, resource_kind, host_resource_id,
                    immutable_fingerprint, created_at
                ) VALUES (?, ?, 'server', ?, ?, ?)
                """,
                (
                    deterministic_id("membership", repo_id, server_id),
                    repo_id,
                    server_id,
                    "sha256:" + "1" * 64,
                    timestamp,
                ),
            )
        return server_id

    def _running_service_result(
        self, server_id: str, *, generation: int = 0
    ) -> dict[str, object]:
        return {
            "ok": True,
            "id": server_id,
            "status": "running",
            "state": "running",
            "generation": generation,
            "lease_id": deterministic_id("lease", server_id),
            "port": 3210,
            "process_fingerprint": "fixture-process",
            "health": {"ok": True},
        }

    def _set_running_service(
        self,
        store: AccountStore,
        *,
        server_id: str,
        generation: int,
        process_fingerprint: str = "fixture-process",
    ) -> dict[str, object]:
        timestamp = "2026-01-01T00:00:02Z"
        lease_id = deterministic_id("lease", server_id)
        with store.immediate_transaction() as connection:
            connection.execute(
                "UPDATE server_definitions SET generation = ?, updated_at = ? "
                "WHERE server_definition_id = ?",
                (generation, timestamp, server_id),
            )
            connection.execute(
                """
                UPDATE server_observations
                SET lifecycle = 'running', pid = ?,
                    process_start_time = 'fixture-start-new',
                    process_fingerprint = ?, listener_host = '127.0.0.1',
                    listener_port = 3210, listener_observable = 1,
                    health_classification = 'ready', health_ok = 1,
                    stopped_at = NULL, stopped_reason = NULL,
                    sampled_at = ?, observation_fingerprint = 'running-new'
                WHERE server_definition_id = ?
                """,
                (os.getpid(), process_fingerprint, timestamp, server_id),
            )
            connection.execute(
                """
                UPDATE port_assignments
                SET status = 'active', deactivated_at = NULL, updated_at = ?
                WHERE repo_id = (
                    SELECT repo_id FROM server_definitions
                    WHERE server_definition_id = ?
                ) AND server_name = 'web'
                """,
                (timestamp, server_id),
            )
            connection.execute(
                """
                UPDATE leases
                SET status = 'active', deactivated_at = NULL,
                    process_fingerprint = ?, generation = ?, updated_at = ?
                WHERE lease_id = ?
                """,
                (process_fingerprint, generation, timestamp, lease_id),
            )
        result = self._running_service_result(server_id, generation=generation)
        result["process_fingerprint"] = process_fingerprint
        return result

    @staticmethod
    def _stopped_service_result(
        server_id: str, *, generation: int = 0
    ) -> dict[str, object]:
        return {
            "ok": True,
            "id": server_id,
            "status": "stopped",
            "state": "stopped",
            "generation": generation,
            "lease_id": None,
            "port": None,
            "process_fingerprint": None,
            "health": {"ok": False, "classification": "stopped"},
        }

    def _prove_stopped_service(
        self, store: AccountStore, *, server_id: str
    ) -> dict[str, object]:
        timestamp = "2026-01-01T00:00:01Z"
        with store.immediate_transaction() as connection:
            connection.execute(
                """
                UPDATE server_observations
                SET lifecycle = 'stopped', pid = NULL,
                    process_start_time = NULL, process_fingerprint = NULL,
                    listener_observable = 1,
                    health_classification = 'stopped', health_ok = NULL,
                    stopped_at = ?, stopped_reason = 'runtime test cleanup',
                    sampled_at = ?, observation_fingerprint = 'stopped-observation'
                WHERE server_definition_id = ?
                """,
                (timestamp, timestamp, server_id),
            )
            connection.execute(
                """
                UPDATE port_assignments
                SET status = 'inactive', deactivated_at = ?, updated_at = ?
                WHERE server_name = 'web' AND status = 'active'
                """,
                (timestamp, timestamp),
            )
            connection.execute(
                """
                UPDATE leases
                SET status = 'released', deactivated_at = ?, updated_at = ?
                WHERE server_definition_id = ? AND status = 'active'
                """,
                (timestamp, timestamp, server_id),
            )
        return {
            "ok": True,
            "state": "removed",
            "server": {
                "id": server_id,
                "status": "stopped",
                "identity_observable": True,
            },
        }

    def _insert_created_service_catalog(
        self,
        store: AccountStore,
        *,
        repo_id: str,
        host_id: str,
        repository: Path,
    ) -> str:
        server_id = deterministic_id("server-definition", repo_id, "web")
        timestamp = "2026-01-01T00:00:00Z"
        source_id = deterministic_id("runtime-test-source", host_id, repo_id)
        binding_id = deterministic_id("control-binding", "server", server_id)
        with store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO coordinator_sources(
                    source_id, host_id, canonical_home, state_path,
                    effective_uid, status, imported_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'imported', ?, ?, ?)
                """,
                (
                    source_id,
                    host_id,
                    str(self.home),
                    str(self.home / "coordinator.sqlite3"),
                    os.geteuid(),
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute(
                """
                INSERT INTO server_definitions(
                    server_definition_id, repo_id, name, cwd,
                    definition_fingerprint, generation, created_at, updated_at
                ) VALUES (?, ?, 'web', ?, 'definition', 0, ?, ?)
                """,
                (server_id, repo_id, str(repository), timestamp, timestamp),
            )
            connection.execute(
                "INSERT INTO server_command_arguments VALUES (?, 0, '/usr/bin/true')",
                (server_id,),
            )
            connection.execute(
                "INSERT INTO server_environment VALUES (?, 'RUNTIME_TEST', '1')",
                (server_id,),
            )
            connection.execute(
                """
                INSERT INTO server_observations(
                    server_definition_id, lifecycle, pid, listener_observable,
                    health_classification, stopped_at, stopped_reason,
                    sampled_at, observation_fingerprint
                ) VALUES (?, 'stopped', NULL, 1, 'stopped', ?,
                          'runtime test cleanup', ?, 'stopped-observation')
                """,
                (server_id, timestamp, timestamp),
            )
            connection.execute(
                """
                INSERT INTO control_bindings(
                    binding_id, repo_id, resource_kind, resource_id, source_id,
                    capability, provenance, authority_state, priority,
                    generation, created_at, updated_at
                ) VALUES (?, ?, 'server', ?, ?, 'lifecycle',
                          'normalized_direct_control', 'authoritative', 100,
                          0, ?, ?)
                """,
                (binding_id, repo_id, server_id, source_id, timestamp, timestamp),
            )
            connection.execute(
                """
                INSERT INTO repository_memberships(
                    membership_id, repo_id, resource_kind, host_resource_id,
                    immutable_fingerprint, control_binding_id, created_at
                ) VALUES (?, ?, 'server', ?, ?, ?, ?)
                """,
                (
                    deterministic_id("membership", repo_id, "server", server_id),
                    repo_id,
                    server_id,
                    "sha256:" + "1" * 64,
                    binding_id,
                    timestamp,
                ),
            )
            connection.execute(
                """
                INSERT INTO startup_policies(
                    policy_id, repo_id, resource_kind, resource_id, policy_kind,
                    current_value, desired_disabled_value,
                    immutable_fingerprint, generation, updated_at
                ) VALUES (?, ?, 'server', ?, 'coordinator', 'enabled',
                          'disabled', ?, 0, ?)
                """,
                (
                    deterministic_id(
                        "startup-policy", "server", server_id, "coordinator"
                    ),
                    repo_id,
                    server_id,
                    "sha256:" + "1" * 64,
                    timestamp,
                ),
            )
            connection.execute(
                """
                INSERT INTO port_assignments(
                    assignment_id, host_id, repo_id, server_name, port,
                    status, generation, deactivated_at, created_at, updated_at
                ) VALUES (?, ?, ?, 'web', 43123, 'inactive', 1, ?, ?, ?)
                """,
                (
                    deterministic_id("port-assignment", repo_id, "web"),
                    host_id,
                    repo_id,
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute(
                """
                INSERT INTO leases(
                    lease_id, host_id, repo_id, server_definition_id, port,
                    agent, purpose, status, generation, deactivated_at,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, 43123, 'test-agent', 'server:web',
                          'released', 1, ?, ?, ?)
                """,
                (
                    deterministic_id("lease", repo_id, server_id),
                    host_id,
                    repo_id,
                    server_id,
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )
        return server_id

    def _insert_docker_database(
        self,
        store: AccountStore,
        *,
        repo_id: str,
        host_id: str,
        lifecycle: str = "stopped",
        database_available: bool | None = False,
    ) -> tuple[str, str]:
        timestamp = "2026-01-01T00:00:00Z"
        engine_id = deterministic_id("docker-engine", host_id, "runtime-test")
        full_container_id = "d" * 64
        docker_id = deterministic_id(
            "docker-resource", engine_id, full_container_id
        )
        database_id = deterministic_id("database-binding", docker_id, "app")
        with store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO docker_engines(
                    engine_id, host_id, context_identity, capability_state,
                    created_at, updated_at
                ) VALUES (?, ?, 'runtime-test', 'available', ?, ?)
                """,
                (engine_id, host_id, timestamp, timestamp),
            )
            connection.execute(
                """
                INSERT INTO docker_resources(
                    docker_resource_id, engine_id, full_container_id,
                    current_name, created_at, updated_at
                ) VALUES (?, ?, ?, 'runtime-db', ?, ?)
                """,
                (docker_id, engine_id, full_container_id, timestamp, timestamp),
            )
            connection.execute(
                """
                INSERT INTO docker_observations(
                    docker_resource_id, lifecycle, sampled_at,
                    observation_fingerprint
                ) VALUES (?, ?, ?, 'runtime-docker-observation')
                """,
                (docker_id, lifecycle, timestamp),
            )
            connection.execute(
                """
                INSERT INTO repository_memberships(
                    membership_id, repo_id, resource_kind, host_resource_id,
                    immutable_fingerprint, created_at
                ) VALUES (?, ?, 'container', ?, ?, ?)
                """,
                (
                    deterministic_id("membership", repo_id, docker_id),
                    repo_id,
                    docker_id,
                    "sha256:" + "d" * 64,
                    timestamp,
                ),
            )
            connection.execute(
                """
                INSERT INTO database_bindings(
                    database_binding_id, docker_resource_id, repo_id,
                    database_name, engine_kind, created_at, updated_at
                ) VALUES (?, ?, ?, 'app', 'postgresql', ?, ?)
                """,
                (database_id, docker_id, repo_id, timestamp, timestamp),
            )
            if database_available is not None:
                connection.execute(
                    """
                    INSERT INTO database_observations(
                        database_binding_id, docker_resource_id, available,
                        error_code, error_message, sampled_at,
                        observation_fingerprint
                    ) VALUES (?, ?, ?, ?, ?, ?, 'runtime-database-observation')
                    """,
                    (
                        database_id,
                        docker_id,
                        int(database_available),
                        None if database_available else "database_stopped",
                        None if database_available else "database is not ready",
                        timestamp,
                    ),
                )
        return docker_id, database_id

    def _full_docker_observation(self, store: AccountStore) -> dict[str, object]:
        host_id = store.ensure_local_host()
        metadata = store.inventory_v2()["store"]
        return {
            "schema_version": 2,
            "status": "completed",
            "observed": True,
            "joined": False,
            "snapshot_id": "runtime-test-snapshot",
            "host_id": host_id,
            "observer_domain": "host-runtime-v2:full-docker",
            "docker_available": True,
            "capability_fingerprint": "sha256:" + "c" * 64,
            "material_fingerprint": "m" * 64,
            "completed_at": "2026-01-01T00:00:00Z",
            "state_revision": metadata["state_revision"],
            "observation_revision": metadata["observation_revision"],
        }

    def _callbacks(
        self,
        store: AccountStore,
        *,
        dispatch: object,
        cleanup: object | None = None,
        observe: object | None = None,
        inventory: object | None = None,
        cleanup_owner_available: bool = False,
    ) -> RuntimeCallbacks:
        def ensure_repository(
            target_store: AccountStore, scope: RepositoryScopeIdentity
        ) -> str:
            root = scope.canonical_root
            host_id = target_store.ensure_local_host()
            repo_id = deterministic_id("repository", host_id, root)
            timestamp = utc_timestamp()
            with target_store.immediate_transaction() as connection:
                identity_match = find_repository_id_by_filesystem_identity(
                    connection,
                    host_id=host_id,
                    scope=scope,
                )
                if identity_match is not None:
                    return identity_match
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'active', 0, ?, ?)
                    ON CONFLICT(repo_id) DO UPDATE SET updated_at = excluded.updated_at
                    """,
                    (
                        repo_id,
                        host_id,
                        root,
                        Path(root).name,
                        timestamp,
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation, actor, updated_at
                    ) VALUES (?, 'installed', 0, 0, 'test', ?)
                    ON CONFLICT(repo_id) DO UPDATE SET updated_at = excluded.updated_at
                    """,
                    (repo_id, timestamp),
                )
            return repo_id

        cleanup_callback = cleanup or (
            lambda _request, _resources: {
                "ok": True,
                "state": "removed",
                "reservation_outcome": "not_created",
            }
        )
        observe_callback = observe or (lambda _project: {"ok": True})
        inventory_callback = inventory or store.inventory_v2
        return RuntimeCallbacks(
            ensure_repository=ensure_repository,
            dispatch=dispatch,  # type: ignore[arg-type]
            cleanup=cleanup_callback,  # type: ignore[arg-type]
            observe=observe_callback,  # type: ignore[arg-type]
            inventory=inventory_callback,  # type: ignore[arg-type]
            cleanup_owner_available=lambda: cleanup_owner_available,
        )

    def test_strict_request_requires_explicit_context_and_temporary_lifetime(self) -> None:
        valid = validate_runtime_request(self.request())
        self.assertIsNone(valid["temporary_repo"])
        missing = self.request()
        missing.pop("temporary_repo")
        with self.assertRaisesRegex(RuntimeRequestError, "missing temporary_repo"):
            validate_runtime_request(missing)
        with self.assertRaisesRegex(RuntimeRequestError, "require ttl_seconds"):
            validate_runtime_request(self.request(purpose="test"))
        with self.assertRaisesRegex(RuntimeRequestError, "JSON boolean"):
            validate_runtime_request(self.request(kill_after_run=1))
        with self.assertRaisesRegex(RuntimeRequestError, "only for action run"):
            validate_runtime_request(self.request(kill_after_run=True))

    def test_strict_options_reject_coercions_nul_and_unbounded_values(self) -> None:
        invalid_options = (
            {"argv": ["/usr/bin/true"], "dry_run": "false"},
            {"argv": ["/usr/bin/true"], "health_timeout": True},
            {"argv": ["/usr/bin/true"], "preferred": False},
            {"argv": ["/usr/bin/true"], "range": "70000-70001"},
            {"argv": ["bad\x00argument"]},
            {"argv": ["/usr/bin/true"], "env": {"BAD=KEY": "value"}},
            {"argv": ["/usr/bin/true"], "cwd": "relative/path"},
        )
        for options in invalid_options:
            with self.subTest(options=options), self.assertRaises(RuntimeRequestError):
                validate_runtime_request(self.request(options=options))
        with self.assertRaisesRegex(RuntimeRequestError, "dry_run=true"):
            validate_runtime_request(
                self.request(
                    options={"argv": ["/usr/bin/true"], "dry_run": True}
                )
            )

    def test_worker_supervision_and_removal_request_contracts_fail_closed(self) -> None:
        existing = {"kind": "service", "id": "service-id", "name": "web"}
        keep_alive = validate_runtime_request(
            self.request(
                target=existing,
                options={
                    "keep_alive": True,
                    "restart_limit": 10,
                    "restart_window_seconds": 300,
                    "rearm_crash_loop": True,
                },
            )
        )
        self.assertTrue(keep_alive["options"]["keep_alive"])
        self.assertEqual(keep_alive["options"]["restart_limit"], 10)
        replacement = validate_runtime_request(
            self.request(
                action="replace",
                target=existing,
                options={
                    "argv": ["/usr/bin/python3", "worker.py"],
                    "cwd": str(self.repository),
                    "env": {},
                    "expected_definition_generation": 0,
                    "keep_alive": True,
                },
            )
        )
        self.assertEqual(
            replacement["options"]["expected_definition_generation"], 0
        )
        for options in (
            {"keep_alive": 1},
            {"keep_alive": False, "restart_limit": 10},
            {"keep_alive": True, "restart_window_seconds": 0},
        ):
            with self.subTest(options=options), self.assertRaises(RuntimeRequestError):
                validate_runtime_request(self.request(target=existing, options=options))
        with self.assertRaisesRegex(RuntimeRequestError, "persistent development"):
            validate_runtime_request(
                self.request(
                    target=existing,
                    purpose="temporary",
                    ttl_seconds=60,
                    options={"keep_alive": True},
                )
            )
        for invalid in (-1, True, 2**63):
            with self.subTest(expected_definition_generation=invalid), self.assertRaises(
                RuntimeRequestError
            ):
                validate_runtime_request(
                    self.request(
                        action="replace",
                        target=existing,
                        options={
                            "argv": ["/usr/bin/true"],
                            "expected_definition_generation": invalid,
                        },
                    )
                )
        with self.assertRaisesRegex(RuntimeRequestError, "exact service replacement"):
            validate_runtime_request(
                self.request(options={"expected_definition_generation": 0})
            )

        remove_plan = validate_runtime_request(
            self.request(
                action="remove",
                target=existing,
                options={"reason": "obsolete"},
            )
        )
        self.assertEqual(remove_plan["action"], "remove")
        with self.assertRaisesRegex(RuntimeRequestError, "planning requires"):
            validate_runtime_request(
                self.request(action="remove", target=existing, options={})
            )
        remove_apply = validate_runtime_request(
            self.request(
                action="remove",
                target=existing,
                options={
                    "remove_plan_id": "11111111-1111-4111-8111-111111111111",
                    "remove_plan_fingerprint": "sha256:" + "a" * 64,
                    "remove_confirmation_phrase": "PURGE SERVER web",
                },
            )
        )
        self.assertEqual(
            remove_apply["options"]["remove_confirmation_phrase"],
            "PURGE SERVER web",
        )
        archive_apply = validate_runtime_request(
            self.request(
                action="remove",
                target=existing,
                options={
                    "remove_plan_id": "11111111-1111-4111-8111-111111111111",
                    "remove_plan_fingerprint": "sha256:" + "a" * 64,
                    "remove_confirmation_phrase": "",
                },
            )
        )
        self.assertEqual(
            archive_apply["options"]["remove_confirmation_phrase"], ""
        )
        with self.assertRaisesRegex(RuntimeRequestError, "together"):
            validate_runtime_request(
                self.request(
                    action="remove",
                    target=existing,
                    options={
                        "reason": "obsolete",
                        "remove_plan_id": "11111111-1111-4111-8111-111111111111",
                    },
                )
            )
        with self.assertRaisesRegex(RuntimeRequestError, "service target"):
            validate_runtime_request(
                self.request(
                    action="remove",
                    target={"kind": "docker", "id": "docker-id"},
                    options={"reason": "obsolete"},
                )
            )

    def test_runtime_remove_facade_returns_exact_plan_and_apply_evidence(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_running_service(
                store, repo_id=repo_id, host_id=host_id
            )
            inventory = store.inventory_v2()
        request = validate_runtime_request(
            self.request(
                action="remove",
                target={"kind": "service", "id": server_id, "name": "web"},
                options={"reason": "obsolete"},
            )
        )
        plan = {
            "plan_id": "11111111-1111-4111-8111-111111111111",
            "plan_fingerprint": "sha256:" + "a" * 64,
            "confirmation_phrase": "",
            "action": "archive",
            "target": {"target_kind": "server", "target_id": server_id},
            "blockers": [],
            "status": "planned",
        }
        with (
            mock.patch.object(
                dev_coordinator, "coordinated_list_archives", return_value={"archives": []}
            ),
            mock.patch.object(
                dev_coordinator, "coordinated_lifecycle_plan", return_value=plan
            ) as planned,
            mock.patch.object(
                dev_coordinator, "coordinated_build_inventory", return_value=inventory
            ),
        ):
            result = dev_coordinator.coordinated_runtime_remove(request)
        self.assertTrue(result["ok"])
        self.assertEqual(result["classification"], "worker_remove_plan_ready")
        self.assertEqual(result["result"]["stage"], "archive")
        planned.assert_called_once_with(
            {
                "action": "archive",
                "target_kind": "server",
                "target_id": server_id,
                "reason": "obsolete",
            }
        )

        apply_request = validate_runtime_request(
            self.request(
                action="remove",
                target={"kind": "service", "id": server_id, "name": "web"},
                options={
                    "remove_plan_id": plan["plan_id"],
                    "remove_plan_fingerprint": plan["plan_fingerprint"],
                    "remove_confirmation_phrase": "",
                },
            )
        )
        with (
            mock.patch.object(
                dev_coordinator,
                "coordinated_lifecycle_apply",
                return_value={"ok": True, "action": "purge", "status": "succeeded"},
            ) as applied,
            mock.patch.object(
                dev_coordinator, "coordinated_build_inventory", return_value=inventory
            ),
        ):
            applied_result = dev_coordinator.coordinated_runtime_remove(apply_request)
        self.assertTrue(applied_result["ok"])
        self.assertEqual(applied_result["classification"], "worker_removed")
        self.assertEqual(
            applied_result["result"]["terminal_state"]["proof"],
            "cleanup_tombstone",
        )
        applied.assert_called_once_with(
            {
                "plan_id": plan["plan_id"],
                "plan_fingerprint": plan["plan_fingerprint"],
                "confirmation_phrase": "",
            }
        )

    def test_runtime_remove_reports_last_worker_after_temporary_scope_disappears(self) -> None:
        linked = self.root / "remove-last-worker"
        subprocess.run(
            [
                "git",
                "-C",
                str(self.repository),
                "worktree",
                "add",
                "-qb",
                "runtime-remove-last-worker",
                str(linked),
            ],
            check=True,
        )
        context = resolve_repository_context(
            root_repo=str(self.repository), temporary_repo=str(linked)
        )
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, root_repo_id = self._insert_repository(store)
            temporary_repo_id = deterministic_id(
                "repository", host_id, str(linked.resolve())
            )
            timestamp = "2026-01-01T00:00:00Z"
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (?, ?, ?, 'remove-last-worker', 'active', 0, ?, ?)
                    """,
                    (
                        temporary_repo_id,
                        host_id,
                        str(linked.resolve()),
                        timestamp,
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation, actor, updated_at
                    ) VALUES (?, 'installed', 0, 0, 'test', ?)
                    """,
                    (temporary_repo_id, timestamp),
                )
            persist_repository_context(
                store,
                context,
                root_repo_id=root_repo_id,
                effective_repo_id=temporary_repo_id,
                timestamp=timestamp,
            )
            server_id = self._insert_created_service_catalog(
                store,
                repo_id=temporary_repo_id,
                host_id=host_id,
                repository=linked.resolve(),
            )
            before = store.inventory_v2()

        after = copy.deepcopy(before)
        family = next(
            item
            for item in after["repository_trees"]
            if item["family_id"] == root_repo_id
        )
        family["scopes"] = [
            scope
            for scope in family["scopes"]
            if scope["repo_id"] != temporary_repo_id
        ]
        family["usage"] = {}
        after["repositories"] = [
            item
            for item in after["repositories"]
            if item["repo_id"] != temporary_repo_id
        ]
        after["resources"]["servers"] = [
            item
            for item in after["resources"]["servers"]
            if item["server_definition_id"] != server_id
        ]
        after["observations"]["servers"] = [
            item
            for item in after["observations"]["servers"]
            if item["server_definition_id"] != server_id
        ]
        after["v1_compatibility"]["servers"] = [
            item
            for item in after["v1_compatibility"]["servers"]
            if item["id"] != server_id
        ]
        request = validate_runtime_request(
            self.request(
                action="remove",
                root_repo=str(self.repository),
                temporary_repo=str(linked.resolve()),
                target={"kind": "service", "id": server_id, "name": "web"},
                options={
                    "reason": "obsolete test worker",
                    "remove_plan_id": "11111111-1111-4111-8111-111111111111",
                    "remove_plan_fingerprint": "sha256:" + "a" * 64,
                    "remove_confirmation_phrase": "PURGE SERVER web",
                },
            )
        )
        with (
            mock.patch.object(
                dev_coordinator,
                "coordinated_lifecycle_apply",
                return_value={"ok": True, "action": "purge", "status": "succeeded"},
            ),
            mock.patch.object(
                dev_coordinator,
                "coordinated_build_inventory",
                side_effect=[before, after],
            ) as inventory_calls,
        ):
            result = dev_coordinator.coordinated_runtime_remove(request)

        self.assertTrue(result["ok"], result)
        self.assertEqual(result["classification"], "worker_removed")
        self.assertEqual(result["repository"]["root_repo_id"], root_repo_id)
        self.assertEqual(
            result["repository"]["effective_repo_id"], temporary_repo_id
        )
        self.assertEqual(result["repository"]["kind"], "temporary")
        self.assertEqual(result["resources"], [])
        self.assertEqual(inventory_calls.call_count, 2)

    def test_permanent_worker_apply_mirrors_old_id_fence_into_account_store(self) -> None:
        repository = dev_coordinator.BrokerRepositoryProfile(
            canonical_root=str(self.repository),
            repo_id="repo-id",
            generation=3,
            server_ids={"worker": "old-worker-id"},
            container_ids={},
            compose_definition_id=None,
            account_id="account-id",
        )
        profile = dev_coordinator.BrokerClientProfile(
            service=dev_coordinator.BrokerServiceProfile(
                socket_path=self.root / "broker.sock",
                service_uid=0,
                socket_gid=os.getgid(),
                socket_mode=0o660,
                database_generation="generation",
            ),
            client_uid=os.geteuid(),
            account_id="account-id",
            issued_at="2026-01-01T00:00:00Z",
            valid_until_epoch=int(time.time()) + 3600,
            repositories={str(self.repository): repository},
        )
        fingerprint = "sha256:" + "a" * 64
        service_revocation = {
            "repo_id": repository.repo_id,
            "server_definition_id": "old-worker-id",
            "server_name": "worker",
            "cleanup_operation_id": "cleanup-plan-id",
            "immutable_fingerprint": fingerprint,
        }
        result = {
            "action": "purge",
            "status": "succeeded",
            "pre_apply": {
                "workers": [
                    {
                        "worker_id": "old-worker-id",
                        "revocation": {
                            "service": service_revocation,
                            "protected_profile": {
                                **service_revocation,
                                "status": "revoked",
                            },
                        },
                    }
                ]
            },
        }
        store_context = mock.MagicMock()
        store_context.__enter__.return_value = mock.Mock()
        links = mock.Mock()
        links.revoke_server_materialization.return_value = {
            "status": "revoked",
            "server_definition_id": "old-worker-id",
        }
        with (
            mock.patch.object(
                dev_coordinator.AccountStore,
                "open_default",
                return_value=store_context,
            ),
            mock.patch.object(
                dev_coordinator, "BrokerLinkStore", return_value=links
            ),
        ):
            dev_coordinator._mirror_permanent_worker_revocations(profile, result)

        links.revoke_server_materialization.assert_called_once_with(
            profile=profile,
            repository=repository,
            server_name="worker",
            server_definition_id="old-worker-id",
            broker_operation_id="cleanup-plan-id",
            immutable_fingerprint=fingerprint,
        )
        self.assertEqual(
            result["client_materialization_revocations"][0]["status"],
            "revoked",
        )

    def test_existing_service_start_may_reuse_enrolled_definition(self) -> None:
        existing_id = "service-id"
        validated = validate_runtime_request(
            self.request(
                target={"kind": "service", "id": existing_id, "name": "web"},
                options={},
            )
        )
        self.assertEqual(validated["target"]["id"], existing_id)
        with self.assertRaisesRegex(RuntimeRequestError, "requires options.argv"):
            validate_runtime_request(
                self.request(
                    action="replace",
                    target={"kind": "service", "id": existing_id, "name": "web"},
                    options={},
                )
            )

    def test_status_rejects_ttl_and_test_stop_does_not_require_one(self) -> None:
        with self.assertRaisesRegex(RuntimeRequestError, "read-only"):
            validate_runtime_request(
                self.request(
                    action="status",
                    ttl_seconds=1,
                    target={"kind": "service", "id": "service-id", "name": "web"},
                    options={},
                )
            )
        stopped = validate_runtime_request(
            self.request(
                action="stop",
                purpose="temporary",
                ttl_seconds=None,
                target={"kind": "service", "id": "service-id", "name": "web"},
                options={},
            )
        )
        self.assertIsNone(stopped["ttl_seconds"])

    def test_interior_symlink_runtime_path_is_rejected(self) -> None:
        real = self.repository / "real"
        real.mkdir()
        linked = self.repository / "linked"
        linked.symlink_to(real, target_is_directory=True)
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            callbacks = self._callbacks(
                store,
                dispatch=lambda *_args: {"ok": True},
            )
            with self.assertRaisesRegex(RuntimeRequestError, "unavailable"):
                execute_runtime_request(
                    self.request(
                        options={
                            "argv": ["/usr/bin/true"],
                            "cwd": str(linked),
                        }
                    ),
                    store=store,
                    callbacks=callbacks,
                )

    def test_existing_service_requires_exact_id_but_new_start_derives_it_later(self) -> None:
        validate_runtime_request(self.request())
        with self.assertRaisesRegex(RuntimeRequestError, "immutable id"):
            validate_runtime_request(
                self.request(action="status", options={}, target={"kind": "service", "name": "web"})
            )

    def test_primary_and_linked_worktree_context_is_proved(self) -> None:
        linked = self.root / "linked"
        subprocess.run(
            [
                "git",
                "-C",
                str(self.repository),
                "worktree",
                "add",
                "-qb",
                "fixture-linked",
                str(linked),
            ],
            check=True,
        )
        context = resolve_repository_context(
            root_repo=str(self.repository), temporary_repo=str(linked)
        )
        self.assertEqual(context.project_kind, "temporary")
        self.assertEqual(
            context.root.git_common_dir, context.temporary.git_common_dir
        )
        with self.assertRaisesRegex(ValueError, "primary Git worktree"):
            resolve_repository_context(root_repo=str(linked), temporary_repo=None)

    def test_case_alias_runtime_request_reuses_one_repository(self) -> None:
        alias = self.repository.with_name(self.repository.name.upper())
        if alias == self.repository or not alias.exists() or not os.path.samefile(
            alias, self.repository
        ):
            self.skipTest("test filesystem is case-sensitive")
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_running_service(
                store, repo_id=repo_id, host_id=host_id
            )
            callbacks = self._callbacks(
                store,
                dispatch=lambda *_args: {
                    "ok": True,
                    "id": server_id,
                    "status": "running",
                    "health": {"ok": True},
                },
            )
            request = self.request(
                action="status",
                target={"kind": "service", "id": server_id, "name": "web"},
                options={},
            )
            execute_runtime_request(request, store=store, callbacks=callbacks)
            request["root_repo"] = str(alias)
            execute_runtime_request(request, store=store, callbacks=callbacks)
            with store.read_transaction() as connection:
                repository_count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM repositories WHERE host_id = ?",
                        (host_id,),
                    ).fetchone()[0]
                )
                scope = connection.execute(
                    """
                    SELECT root_device, root_inode
                    FROM repository_scopes WHERE repo_id = ?
                    """,
                    (repo_id,),
                ).fetchone()
        self.assertEqual(repository_count, 1)
        self.assertIsNotNone(scope["root_device"])
        self.assertIsNotNone(scope["root_inode"])

    def test_v4_backfill_is_deterministic_and_lossless(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            _host_id, repo_id = self._insert_repository(store)
        database = self.home / "coordinator.sqlite3"
        connection = sqlite3.connect(database)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("DELETE FROM repository_scopes")
        connection.execute("DELETE FROM repository_families")
        connection.execute(
            "UPDATE schema_metadata SET schema_version = 4 WHERE singleton = 1"
        )
        connection.commit()
        connection.close()

        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            with store.read_transaction() as connection:
                metadata = connection.execute(
                    "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
                ).fetchone()
                family = connection.execute(
                    """
                    SELECT f.family_id, f.root_repo_id, s.project_kind
                    FROM repository_families f JOIN repository_scopes s USING(family_id)
                    WHERE s.repo_id = ?
                    """,
                    (repo_id,),
                ).fetchone()
        self.assertEqual(int(metadata[0]), SCHEMA_VERSION)
        self.assertEqual(dict(family), {"family_id": repo_id, "root_repo_id": repo_id, "project_kind": "primary"})

    def test_tree_shape_and_successful_reap_remove_only_active_projection(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_running_service(
                store, repo_id=repo_id, host_id=host_id
            )
            before = store.inventory_v2()
            tree = before["repository_trees"][0]
            self.assertEqual(
                set(tree), {"family_id", "root_repository", "usage", "scopes"}
            )
            self.assertEqual(tree["scopes"][0]["kind"], "root")
            self.assertIn(server_id, tree["scopes"][0]["server_ids"])

            request = validate_runtime_request(
                self.request(
                    purpose="test",
                    ttl_seconds=1,
                    kill_after_run=False,
                    target={"kind": "service", "id": server_id, "name": "web"},
                )
            )
            session_id = create_runtime_session(
                store,
                family_id=repo_id,
                root_repo_id=repo_id,
                repo_id=repo_id,
                request=request,
                timestamp="2026-01-01T00:00:00Z",
            )
            mark_runtime_session_started(
                store, session_id, timestamp="2026-01-01T00:00:00Z"
            )
            link_runtime_resource(
                store,
                session_id=session_id,
                resource_kind="service",
                resource_id=server_id,
                cleanup_disposition="removed",
                identity={"generation": 0},
                timestamp="2026-01-01T00:00:00Z",
            )
            cleanup_result = self._prove_stopped_service(
                store, server_id=server_id
            )
            finish_runtime_session(
                store,
                session_id,
                succeeded=True,
                result={"ok": True},
                keep_running_until_ttl=True,
                timestamp="2026-01-01T00:00:00Z",
            )
            calls: list[str] = []
            reaped = reap_expired_runtime_sessions(
                store,
                timestamp="2026-01-01T00:00:02Z",
                cleanup=lambda _request, _resources: calls.append(session_id)
                or cleanup_result,
            )
            second = reap_expired_runtime_sessions(
                store,
                timestamp="2026-01-01T00:00:03Z",
                cleanup=lambda _request, _resources: calls.append("duplicate")
                or {"ok": True, "state": "removed"},
            )
            after = store.inventory_v2()
            with store.read_transaction() as connection:
                state = connection.execute(
                    "SELECT status FROM runtime_sessions WHERE session_id = ?",
                    (session_id,),
                ).fetchone()[0]
        self.assertEqual(calls, [session_id])
        self.assertEqual(reaped[0]["status"], "expired")
        self.assertEqual(second, [])
        self.assertEqual(state, "expired")
        self.assertNotIn(
            server_id, after["repository_trees"][0]["scopes"][0]["server_ids"]
        )

    def test_expired_created_service_deletes_catalog_hides_empty_temporary_scope_and_reinstalls(self) -> None:
        linked = self.root / "temporary-worktree"
        subprocess.run(
            [
                "git",
                "-C",
                str(self.repository),
                "worktree",
                "add",
                "-qb",
                "runtime-catalog-cleanup",
                str(linked),
            ],
            check=True,
        )
        context = resolve_repository_context(
            root_repo=str(self.repository), temporary_repo=str(linked)
        )
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, root_repo_id = self._insert_repository(store)
            temporary_repo_id = deterministic_id(
                "repository", host_id, str(linked.resolve())
            )
            timestamp = "2026-01-01T00:00:00Z"
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (?, ?, ?, 'temporary-worktree', 'active', 0, ?, ?)
                    """,
                    (
                        temporary_repo_id,
                        host_id,
                        str(linked.resolve()),
                        timestamp,
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation, actor, updated_at
                    ) VALUES (?, 'installed', 0, 0, 'test', ?)
                    """,
                    (temporary_repo_id, timestamp),
                )
            persist_repository_context(
                store,
                context,
                root_repo_id=root_repo_id,
                effective_repo_id=temporary_repo_id,
                timestamp=timestamp,
            )
            server_id = self._insert_created_service_catalog(
                store,
                repo_id=temporary_repo_id,
                host_id=host_id,
                repository=linked.resolve(),
            )
            request = validate_runtime_request(
                self.request(
                    purpose="temporary",
                    ttl_seconds=1,
                    root_repo=str(self.repository),
                    temporary_repo=str(linked.resolve()),
                    target={"kind": "service", "id": server_id, "name": "web"},
                )
            )
            session_id = create_runtime_session(
                store,
                family_id=root_repo_id,
                root_repo_id=root_repo_id,
                repo_id=temporary_repo_id,
                request=request,
                timestamp=timestamp,
            )
            mark_runtime_session_started(store, session_id, timestamp=timestamp)
            link_runtime_resource(
                store,
                session_id=session_id,
                resource_kind="service",
                resource_id=server_id,
                cleanup_disposition="removed",
                identity={"generation": 0},
                timestamp=timestamp,
            )
            finish_runtime_session(
                store,
                session_id,
                succeeded=True,
                result={"ok": True},
                keep_running_until_ttl=True,
                timestamp=timestamp,
            )
            reaped = reap_expired_runtime_sessions(
                store,
                timestamp="2026-01-01T00:00:02Z",
                cleanup=lambda _request, _resources: {
                    "ok": True,
                    "state": "removed",
                    "server": {
                        "id": server_id,
                        "status": "stopped",
                        "identity_observable": True,
                    },
                },
            )
            inventory = store.inventory_v2()
            with store.read_transaction() as connection:
                active_counts = {
                    table: connection.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE " + predicate,
                        parameters,
                    ).fetchone()[0]
                    for table, predicate, parameters in (
                        ("server_definitions", "server_definition_id = ?", (server_id,)),
                        ("repository_memberships", "host_resource_id = ?", (server_id,)),
                        ("control_bindings", "resource_id = ?", (server_id,)),
                        ("startup_policies", "resource_id = ?", (server_id,)),
                        ("port_assignments", "repo_id = ?", (temporary_repo_id,)),
                        ("leases", "repo_id = ?", (temporary_repo_id,)),
                    )
                }
                session_evidence = connection.execute(
                    """
                    SELECT s.status, s.result_json, r.cleanup_state
                    FROM runtime_sessions s
                    JOIN runtime_session_resources r USING(session_id)
                    WHERE s.session_id = ?
                    """,
                    (session_id,),
                ).fetchone()
                installation = connection.execute(
                    """
                    SELECT status, startup_fenced FROM repository_installations
                    WHERE repo_id = ?
                    """,
                    (temporary_repo_id,),
                ).fetchone()
                scope_count = connection.execute(
                    "SELECT COUNT(*) FROM repository_scopes WHERE repo_id = ?",
                    (temporary_repo_id,),
                ).fetchone()[0]
            self.assertEqual(reaped[0]["status"], "expired")
            self.assertEqual(set(active_counts.values()), {0})
            self.assertEqual(session_evidence["status"], "expired")
            self.assertEqual(session_evidence["cleanup_state"], "removed")
            self.assertTrue(
                json.loads(session_evidence["result_json"])["catalog_cleanup"][
                    "temporary_scope"
                ]["removed"]
            )
            self.assertEqual(dict(installation), {"status": "disabled", "startup_fenced": 1})
            # The active presentation is gone, while the exact Git-family
            # relationship remains as the minimal identity needed by the
            # explicit Coordinator reinstall journey.
            self.assertEqual(scope_count, 1)

            repository_ids = {item["repo_id"] for item in inventory["repositories"]}
            tree_scope_ids = {
                scope["repo_id"]
                for tree in inventory["repository_trees"]
                for scope in tree["scopes"]
            }
            self.assertEqual(repository_ids, tree_scope_ids)
            self.assertEqual(repository_ids, {root_repo_id})

            SQLiteLifecyclePersistence(store).reinstall_repository(
                temporary_repo_id,
                actor="test-agent",
                reason="new Coordinator runtime installation",
            )
            persist_repository_context(
                store,
                context,
                root_repo_id=root_repo_id,
                effective_repo_id=temporary_repo_id,
                timestamp="2026-01-01T00:00:03Z",
            )
            recreated_id = self._insert_created_service_catalog(
                store,
                repo_id=temporary_repo_id,
                host_id=host_id,
                repository=linked.resolve(),
            )
            self.assertEqual(recreated_id, server_id)
            replacement_session = create_runtime_session(
                store,
                family_id=root_repo_id,
                root_repo_id=root_repo_id,
                repo_id=temporary_repo_id,
                request=request,
                timestamp="2026-01-01T00:00:03Z",
            )
            mark_runtime_session_started(
                store, replacement_session, timestamp="2026-01-01T00:00:03Z"
            )
            link_runtime_resource(
                store,
                session_id=replacement_session,
                resource_kind="service",
                resource_id=server_id,
                cleanup_disposition="removed",
                identity={"generation": 0},
                timestamp="2026-01-01T00:00:03Z",
            )
            finish_runtime_session(
                store,
                replacement_session,
                succeeded=True,
                result={"ok": True},
                keep_running_until_ttl=True,
                timestamp="2026-01-01T00:00:03Z",
            )
            reinstalled = store.inventory_v2()
        temporary_scope = next(
            scope
            for tree in reinstalled["repository_trees"]
            for scope in tree["scopes"]
            if scope["repo_id"] == temporary_repo_id
        )
        self.assertIn(server_id, temporary_scope["server_ids"])

    def test_borrowed_service_docker_and_database_catalog_rows_are_retained(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_running_service(
                store, repo_id=repo_id, host_id=host_id
            )
            docker_id, database_id = self._insert_docker_database(
                store, repo_id=repo_id, host_id=host_id
            )
            service_request = validate_runtime_request(
                self.request(
                    purpose="temporary",
                    ttl_seconds=30,
                    target={"kind": "service", "id": server_id, "name": "web"},
                )
            )
            service_session = create_runtime_session(
                store,
                family_id=repo_id,
                root_repo_id=repo_id,
                repo_id=repo_id,
                request=service_request,
            )
            mark_runtime_session_started(store, service_session)
            link_runtime_resource(
                store,
                session_id=service_session,
                resource_kind="service",
                resource_id=server_id,
                cleanup_disposition="retained",
                identity={"generation": 0},
            )
            finish_runtime_session(
                store,
                service_session,
                succeeded=True,
                result={"ok": True},
                keep_running_until_ttl=True,
            )
            service_cleanup = cleanup_runtime_session(
                store,
                service_session,
                cleanup=lambda _request, _resources: {"ok": True, "state": "stopped"},
                expired=False,
                allow_unexpired=True,
            )

            database_request = validate_runtime_request(
                self.request(
                    purpose="temporary",
                    ttl_seconds=30,
                    target={"kind": "database_stack", "id": database_id},
                    options={},
                )
            )
            database_session = create_runtime_session(
                store,
                family_id=repo_id,
                root_repo_id=repo_id,
                repo_id=repo_id,
                request=database_request,
            )
            mark_runtime_session_started(store, database_session)
            for kind, resource_id in (
                ("database_stack", database_id),
                ("docker", docker_id),
            ):
                link_runtime_resource(
                    store,
                    session_id=database_session,
                    resource_kind=kind,
                    resource_id=resource_id,
                    cleanup_disposition="retained",
                    identity={"kind": kind},
                    immutable_fingerprint="sha256:" + "d" * 64,
                )
            finish_runtime_session(
                store,
                database_session,
                succeeded=True,
                result={"ok": True},
                keep_running_until_ttl=True,
            )
            database_cleanup = cleanup_runtime_session(
                store,
                database_session,
                cleanup=lambda _request, _resources: {"ok": True, "state": "stopped"},
                expired=False,
                allow_unexpired=True,
            )
            with self.assertRaisesRegex(ValueError, "pre-existing Docker/database"):
                link_runtime_resource(
                    store,
                    session_id=database_session,
                    resource_kind="docker",
                    resource_id=docker_id,
                    cleanup_disposition="removed",
                )
            with store.read_transaction() as connection:
                self.assertIsNotNone(
                    connection.execute(
                        "SELECT 1 FROM server_definitions WHERE server_definition_id = ?",
                        (server_id,),
                    ).fetchone()
                )
                self.assertIsNotNone(
                    connection.execute(
                        "SELECT 1 FROM docker_resources WHERE docker_resource_id = ?",
                        (docker_id,),
                    ).fetchone()
                )
                self.assertIsNotNone(
                    connection.execute(
                        "SELECT 1 FROM database_bindings WHERE database_binding_id = ?",
                        (database_id,),
                    ).fetchone()
                )
        self.assertTrue(
            all(
                item["ownership"] == "borrowed"
                for item in service_cleanup["result"]["catalog_cleanup"]["resources"]
                + database_cleanup["result"]["catalog_cleanup"]["resources"]
            )
        )

    def test_created_service_catalog_cleanup_failure_is_atomic_and_retryable(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_created_service_catalog(
                store,
                repo_id=repo_id,
                host_id=host_id,
                repository=self.repository,
            )
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE server_observations SET listener_observable = 0
                    WHERE server_definition_id = ?
                    """,
                    (server_id,),
                )
            request = validate_runtime_request(
                self.request(
                    purpose="temporary",
                    ttl_seconds=30,
                    target={"kind": "service", "id": server_id, "name": "web"},
                )
            )
            session_id = create_runtime_session(
                store,
                family_id=repo_id,
                root_repo_id=repo_id,
                repo_id=repo_id,
                request=request,
            )
            mark_runtime_session_started(store, session_id)
            link_runtime_resource(
                store,
                session_id=session_id,
                resource_kind="service",
                resource_id=server_id,
                cleanup_disposition="removed",
                identity={"generation": 0},
            )
            finish_runtime_session(
                store,
                session_id,
                succeeded=True,
                result={"ok": True},
                keep_running_until_ttl=True,
            )
            proof = {
                "ok": True,
                "state": "removed",
                "server": {
                    "id": server_id,
                    "status": "stopped",
                    "identity_observable": True,
                },
            }
            with self.assertRaisesRegex(
                RuntimeError, "no exact stopped listener boundary"
            ):
                cleanup_runtime_session(
                    store,
                    session_id,
                    cleanup=lambda _request, _resources: proof,
                    expired=False,
                    allow_unexpired=True,
                )
            with store.read_transaction() as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT status FROM runtime_sessions WHERE session_id = ?",
                        (session_id,),
                    ).fetchone()[0],
                    "cleanup_pending",
                )
                self.assertIsNotNone(
                    connection.execute(
                        "SELECT 1 FROM server_definitions WHERE server_definition_id = ?",
                        (server_id,),
                    ).fetchone()
                )
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE server_observations SET listener_observable = 1
                    WHERE server_definition_id = ?
                    """,
                    (server_id,),
                )
            retried = cleanup_runtime_session(
                store,
                session_id,
                cleanup=lambda _request, _resources: proof,
                expired=False,
                allow_unexpired=True,
            )
            with store.read_transaction() as connection:
                remaining = connection.execute(
                    "SELECT COUNT(*) FROM server_definitions WHERE server_definition_id = ?",
                    (server_id,),
                ).fetchone()[0]
        self.assertEqual(retried["status"], "cleaned")
        self.assertEqual(remaining, 0)

    def test_failed_cleanup_retains_resource_and_retryable_state(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_running_service(
                store, repo_id=repo_id, host_id=host_id
            )
            request = validate_runtime_request(
                self.request(purpose="temporary", ttl_seconds=1)
            )
            session_id = create_runtime_session(
                store,
                family_id=repo_id,
                root_repo_id=repo_id,
                repo_id=repo_id,
                request=request,
                timestamp="2026-01-01T00:00:00Z",
            )
            mark_runtime_session_started(store, session_id, timestamp="2026-01-01T00:00:00Z")
            link_runtime_resource(
                store,
                session_id=session_id,
                resource_kind="service",
                resource_id=server_id,
                cleanup_disposition="removed",
                timestamp="2026-01-01T00:00:00Z",
            )
            finish_runtime_session(
                store,
                session_id,
                succeeded=True,
                result={"ok": True},
                keep_running_until_ttl=True,
                timestamp="2026-01-01T00:00:00Z",
            )

            def fail(
                _request: dict[str, object],
                _resources: list[dict[str, object]],
            ) -> dict[str, object]:
                raise RuntimeError("injected stop failure")

            reaped = reap_expired_runtime_sessions(
                store,
                timestamp="2026-01-01T00:00:02Z",
                cleanup=fail,
            )
            inventory = store.inventory_v2()
            with store.read_transaction() as connection:
                state = connection.execute(
                    "SELECT status FROM runtime_sessions WHERE session_id = ?",
                    (session_id,),
                ).fetchone()[0]
        self.assertEqual(state, "cleanup_pending")
        self.assertEqual(reaped[0]["status"], "cleanup_pending")
        self.assertIn(
            server_id,
            inventory["repository_trees"][0]["scopes"][0]["server_ids"],
        )

    def test_cleanup_ok_false_is_not_a_terminal_tombstone(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_running_service(
                store, repo_id=repo_id, host_id=host_id
            )
            request = validate_runtime_request(
                self.request(purpose="test", ttl_seconds=1)
            )
            session_id = create_runtime_session(
                store,
                family_id=repo_id,
                root_repo_id=repo_id,
                repo_id=repo_id,
                request=request,
                timestamp="2026-01-01T00:00:00Z",
            )
            mark_runtime_session_started(
                store, session_id, timestamp="2026-01-01T00:00:00Z"
            )
            link_runtime_resource(
                store,
                session_id=session_id,
                resource_kind="service",
                resource_id=server_id,
                cleanup_disposition="removed",
                timestamp="2026-01-01T00:00:00Z",
            )
            finish_runtime_session(
                store,
                session_id,
                succeeded=True,
                result={"ok": True},
                keep_running_until_ttl=True,
                timestamp="2026-01-01T00:00:00Z",
            )
            result = reap_expired_runtime_sessions(
                store,
                timestamp="2026-01-01T00:00:02Z",
                cleanup=lambda _request, _resources: {
                    "ok": False,
                    "state": "running",
                },
            )
            inventory = store.inventory_v2()
        self.assertEqual(result[0]["status"], "cleanup_pending")
        self.assertIn(
            server_id,
            inventory["repository_trees"][0]["scopes"][0]["server_ids"],
        )

    def test_live_execution_claim_blocks_expired_cleanup(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_running_service(
                store, repo_id=repo_id, host_id=host_id
            )
            request = validate_runtime_request(
                self.request(purpose="test", ttl_seconds=1)
            )
            session_id = create_runtime_session(
                store,
                family_id=repo_id,
                root_repo_id=repo_id,
                repo_id=repo_id,
                request=request,
                timestamp="2026-01-01T00:00:00Z",
            )
            mark_runtime_session_started(
                store, session_id, timestamp="2026-01-01T00:00:00Z"
            )
            link_runtime_resource(
                store,
                session_id=session_id,
                resource_kind="service",
                resource_id=server_id,
                cleanup_disposition="retained",
                timestamp="2026-01-01T00:00:00Z",
            )
            calls: list[str] = []
            result = reap_expired_runtime_sessions(
                store,
                timestamp="2026-01-01T00:02:00Z",
                cleanup=lambda _request, _resources: calls.append("cleanup")
                or {"ok": True, "state": "stopped"},
            )
        self.assertEqual(result, [])
        self.assertEqual(calls, [])

    def test_newer_session_supersedes_old_cleanup_without_stopping(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_running_service(
                store, repo_id=repo_id, host_id=host_id
            )
            sessions = []
            for index, ttl in enumerate((1, 100)):
                request = validate_runtime_request(
                    self.request(purpose="test", ttl_seconds=ttl)
                )
                session_id = create_runtime_session(
                    store,
                    family_id=repo_id,
                    root_repo_id=repo_id,
                    repo_id=repo_id,
                    request=request,
                    timestamp=f"2026-01-01T00:00:0{index}Z",
                )
                mark_runtime_session_started(
                    store,
                    session_id,
                    timestamp=f"2026-01-01T00:00:0{index}Z",
                )
                link_runtime_resource(
                    store,
                    session_id=session_id,
                    resource_kind="service",
                    resource_id=server_id,
                    cleanup_disposition="retained",
                    timestamp=f"2026-01-01T00:00:0{index}Z",
                )
                finish_runtime_session(
                    store,
                    session_id,
                    succeeded=True,
                    result={"ok": True},
                    keep_running_until_ttl=True,
                    timestamp=f"2026-01-01T00:00:0{index}Z",
                )
                sessions.append(session_id)
            calls: list[str] = []
            result = reap_expired_runtime_sessions(
                store,
                timestamp="2026-01-01T00:00:02Z",
                cleanup=lambda _request, _resources: calls.append("cleanup")
                or {"ok": True, "state": "stopped"},
            )
            with store.read_transaction() as connection:
                old_state = connection.execute(
                    """
                    SELECT cleanup_state FROM runtime_session_resources
                    WHERE session_id = ?
                    """,
                    (sessions[0],),
                ).fetchone()[0]
        self.assertEqual(result[0]["status"], "expired")
        self.assertEqual(calls, [])
        self.assertEqual(old_state, "retained")

    def test_live_cleanup_owner_cannot_be_stolen_after_elapsed_threshold(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        calls: list[str] = []
        worker_errors: list[BaseException] = []
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_running_service(
                store, repo_id=repo_id, host_id=host_id
            )
            request = validate_runtime_request(
                self.request(purpose="temporary", ttl_seconds=1)
            )
            session_id = create_runtime_session(
                store,
                family_id=repo_id,
                root_repo_id=repo_id,
                repo_id=repo_id,
                request=request,
                timestamp="2026-01-01T00:00:00Z",
            )
            mark_runtime_session_started(
                store, session_id, timestamp="2026-01-01T00:00:00Z"
            )
            link_runtime_resource(
                store,
                session_id=session_id,
                resource_kind="service",
                resource_id=server_id,
                cleanup_disposition="retained",
                timestamp="2026-01-01T00:00:00Z",
            )
            finish_runtime_session(
                store,
                session_id,
                succeeded=True,
                result={"ok": True},
                keep_running_until_ttl=True,
                timestamp="2026-01-01T00:00:00Z",
            )

            def blocking_cleanup(_request, _resources):
                calls.append("first")
                entered.set()
                if not release.wait(5):
                    raise RuntimeError("cleanup test release timed out")
                return {"ok": True, "state": "stopped"}

            def worker() -> None:
                try:
                    with AccountStore.open_default(
                        self.home, effective_uid=os.geteuid()
                    ) as worker_store:
                        cleanup_runtime_session(
                            worker_store,
                            session_id,
                            cleanup=blocking_cleanup,
                            expired=True,
                            timestamp="2026-01-01T00:00:02Z",
                        )
                except BaseException as error:
                    worker_errors.append(error)

            thread = threading.Thread(target=worker)
            thread.start()
            self.assertTrue(
                entered.wait(5),
                f"cleanup callback did not reach boundary: {worker_errors}",
            )
            stolen = cleanup_runtime_session(
                store,
                session_id,
                cleanup=lambda _request, _resources: calls.append("stolen")
                or {"ok": True, "state": "stopped"},
                expired=True,
                timestamp="2026-01-01T00:02:02Z",
            )
            release.set()
            thread.join(5)
            self.assertFalse(thread.is_alive(), "cleanup worker did not finish")
        self.assertIsNone(stolen)
        self.assertEqual(calls, ["first"])
        self.assertEqual(worker_errors, [])

    def test_dead_cleanup_owner_is_recoverable(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_running_service(
                store, repo_id=repo_id, host_id=host_id
            )
            request = validate_runtime_request(
                self.request(purpose="temporary", ttl_seconds=1)
            )
            session_id = create_runtime_session(
                store,
                family_id=repo_id,
                root_repo_id=repo_id,
                repo_id=repo_id,
                request=request,
                timestamp="2026-01-01T00:00:00Z",
            )
            mark_runtime_session_started(
                store, session_id, timestamp="2026-01-01T00:00:00Z"
            )
            link_runtime_resource(
                store,
                session_id=session_id,
                resource_kind="service",
                resource_id=server_id,
                cleanup_disposition="retained",
                timestamp="2026-01-01T00:00:00Z",
            )
            finish_runtime_session(
                store,
                session_id,
                succeeded=True,
                result={"ok": True},
                keep_running_until_ttl=True,
                timestamp="2026-01-01T00:00:00Z",
            )
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE runtime_sessions
                    SET status = 'cleaning', cleanup_claim_id = 'dead-claim',
                        cleanup_started_at = '2026-01-01T00:00:02Z',
                        cleanup_owner_pid = 2147483647,
                        cleanup_owner_identity = 'dead-owner'
                    WHERE session_id = ?
                    """,
                    (session_id,),
                )
                connection.execute(
                    """
                    UPDATE runtime_session_resources SET cleanup_state = 'cleaning'
                    WHERE session_id = ?
                    """,
                    (session_id,),
                )
            recovered = cleanup_runtime_session(
                store,
                session_id,
                cleanup=lambda _request, _resources: {
                    "ok": True,
                    "state": "stopped",
                },
                expired=True,
                timestamp="2026-01-01T00:02:03Z",
            )
        self.assertEqual(recovered["status"], "expired")

    def test_non_linux_zombie_is_not_a_live_process_identity(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Z    Fri Jul 25 10:00:00 2026\n", stderr=""
        )
        with (
            mock.patch.object(runtime_sessions_module.sys, "platform", "darwin"),
            mock.patch.object(
                runtime_sessions_module.subprocess,
                "run",
                return_value=completed,
            ),
        ):
            self.assertIsNone(runtime_sessions_module._process_identity(1234))
        completed.stdout = "S    Fri Jul 25 10:00:00 2026\n"
        with (
            mock.patch.object(runtime_sessions_module.sys, "platform", "darwin"),
            mock.patch.object(
                runtime_sessions_module.subprocess,
                "run",
                return_value=completed,
            ),
        ):
            self.assertEqual(
                runtime_sessions_module._process_identity(1234),
                "ps-start:Fri Jul 25 10:00:00 2026",
            )

    def test_tree_never_makes_retained_docker_alias_or_unassigned_resource_actionable(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            timestamp = "2026-01-01T00:00:00Z"
            engine_id = deterministic_id("docker-engine", host_id, "default")
            full_native_id = "a" * 64
            alias_native_id = "a" * 12
            unassigned_native_id = "b" * 64
            full_resource_id = deterministic_id("docker-resource", engine_id, full_native_id)
            alias_resource_id = deterministic_id("docker-resource", engine_id, alias_native_id)
            unassigned_resource_id = deterministic_id(
                "docker-resource", engine_id, unassigned_native_id
            )
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO docker_engines(
                        engine_id, host_id, context_identity, capability_state,
                        created_at, updated_at
                    ) VALUES (?, ?, 'default', 'available', ?, ?)
                    """,
                    (engine_id, host_id, timestamp, timestamp),
                )
                for resource_id, native_id, name in (
                    (full_resource_id, full_native_id, "canonical"),
                    (alias_resource_id, alias_native_id, "alias"),
                    (unassigned_resource_id, unassigned_native_id, "unassigned"),
                ):
                    connection.execute(
                        """
                        INSERT INTO docker_resources(
                            docker_resource_id, engine_id, full_container_id,
                            current_name, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (resource_id, engine_id, native_id, name, timestamp, timestamp),
                    )
                    connection.execute(
                        """
                        INSERT INTO docker_observations(
                            docker_resource_id, lifecycle, ports_fingerprint,
                            labels_fingerprint, sampled_at, observation_fingerprint
                        ) VALUES (?, 'running', 'ports', 'labels', ?, ?)
                        """,
                        (resource_id, timestamp, f"observation-{resource_id}"),
                    )
                for resource_id in (full_resource_id, alias_resource_id):
                    connection.execute(
                        """
                        INSERT INTO repository_memberships(
                            membership_id, repo_id, resource_kind,
                            host_resource_id, immutable_fingerprint, created_at
                        ) VALUES (?, ?, 'container', ?, ?, ?)
                        """,
                        (
                            deterministic_id("membership", repo_id, resource_id),
                            repo_id,
                            resource_id,
                            "sha256:" + ("2" if resource_id == full_resource_id else "3") * 64,
                            timestamp,
                        ),
                    )
                connection.execute(
                    """
                    INSERT INTO unassigned_resources(
                        unassigned_id, host_id, resource_kind, resource_id,
                        display_name, reason_code, status, created_at, updated_at
                    ) VALUES (?, ?, 'container', ?, 'unassigned', 'name_only',
                              'active', ?, ?)
                    """,
                    (
                        deterministic_id("unassigned", host_id, unassigned_resource_id),
                        host_id,
                        unassigned_resource_id,
                        timestamp,
                        timestamp,
                    ),
                )
            inventory = store.inventory_v2()
        scope_ids = set(
            inventory["repository_trees"][0]["scopes"][0][
                "container_resource_ids"
            ]
        )
        normalized_ids = {
            item["docker_resource_id"]
            for item in inventory["resources"]["docker"]
        }
        self.assertIn(full_resource_id, scope_ids)
        self.assertNotIn(alias_resource_id, scope_ids)
        self.assertNotIn(unassigned_resource_id, scope_ids)
        self.assertTrue(scope_ids <= normalized_ids)

    def test_repeated_status_is_one_observation_and_creates_no_sessions_or_events(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_running_service(
                store, repo_id=repo_id, host_id=host_id
            )
            observations: list[str] = []
            cleanups: list[str] = []
            callbacks = self._callbacks(
                store,
                dispatch=lambda _request, _project, session_id, _link: {
                    **self._running_service_result(server_id),
                    "session_id_seen": session_id,
                },
                cleanup=lambda _request, _resources: cleanups.append("cleanup")
                or {"ok": True, "state": "removed"},
                observe=lambda project: observations.append(project)
                or {"ok": True, "project": project},
            )
            request = self.request(
                action="status",
                target={"kind": "service", "id": server_id, "name": "web"},
                options={},
            )
            first = execute_runtime_request(request, store=store, callbacks=callbacks)
            with store.read_transaction() as connection:
                after_first = {
                    "sessions": connection.execute(
                        "SELECT COUNT(*) FROM runtime_sessions"
                    ).fetchone()[0],
                    "events": connection.execute(
                        "SELECT COUNT(*) FROM events"
                    ).fetchone()[0],
                }
            second = execute_runtime_request(request, store=store, callbacks=callbacks)
            with store.read_transaction() as connection:
                after_second = {
                    "sessions": connection.execute(
                        "SELECT COUNT(*) FROM runtime_sessions"
                    ).fetchone()[0],
                    "events": connection.execute(
                        "SELECT COUNT(*) FROM events"
                    ).fetchone()[0],
                }
        self.assertIsNone(first["run_id"])
        self.assertIsNone(second["run_id"])
        self.assertEqual(after_first, after_second)
        self.assertEqual(after_second["sessions"], 0)
        self.assertEqual(len(observations), 2)
        self.assertEqual(cleanups, [])
        self.assertIsNone(first["result"]["session_id_seen"])

    def test_one_shot_ttl_requires_cleanup_owner_before_dispatch(self) -> None:
        dispatched: list[str] = []
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            callbacks = self._callbacks(
                store,
                dispatch=lambda *_args: dispatched.append("dispatch")
                or {"ok": True},
                cleanup_owner_available=False,
            )
            with self.assertRaises(RuntimeCleanupOwnerRequired):
                execute_runtime_request(
                    self.request(purpose="temporary", ttl_seconds=60),
                    store=store,
                    callbacks=callbacks,
                )
            with store.read_transaction() as connection:
                session_count = connection.execute(
                    "SELECT COUNT(*) FROM runtime_sessions"
                ).fetchone()[0]
        self.assertEqual(dispatched, [])
        self.assertEqual(session_count, 0)

    def test_successful_mutation_preserves_evidence_when_post_observation_fails(self) -> None:
        observations = 0

        def observe(_project: str) -> dict[str, object]:
            nonlocal observations
            observations += 1
            if observations == 2:
                raise RuntimeError("injected post-observation failure")
            return {"ok": True, "sample": observations}

        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            callbacks = self._callbacks(
                store,
                dispatch=lambda _request, _project, _session_id, _link: {
                    "ok": True,
                    "mutation_marker": "started-exact-service",
                },
                observe=observe,
            )
            result = execute_runtime_request(
                self.request(), store=store, callbacks=callbacks
            )
            with store.read_transaction() as connection:
                persisted = json.loads(
                    connection.execute(
                        "SELECT result_json FROM runtime_sessions"
                    ).fetchone()[0]
                )
        self.assertFalse(result["ok"])
        self.assertEqual(result["classification"], "reconciliation_required")
        self.assertEqual(
            result["result"]["mutation"]["mutation_marker"],
            "started-exact-service",
        )
        self.assertEqual(persisted["classification"], "reconciliation_required")
        self.assertEqual(observations, 2)

    def test_report_projection_failure_synchronously_cleans_linked_resource(self) -> None:
        cleanups: list[list[dict[str, object]]] = []
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_running_service(
                store, repo_id=repo_id, host_id=host_id
            )

            def dispatch(_request, _project, _session_id, link):
                link(
                    {
                        "kind": "service",
                        "id": server_id,
                        "cleanup_disposition": "retained",
                        "identity": {"generation": 0},
                    }
                )
                return self._running_service_result(server_id)

            callbacks = self._callbacks(
                store,
                dispatch=dispatch,
                cleanup=lambda _request, resources: cleanups.append(resources)
                or {"ok": True, "state": "stopped"},
            )
            request = self.request(
                target={"kind": "service", "id": server_id, "name": "web"},
                options={},
            )
            with mock.patch(
                "devcoordinator.runtime_api.build_runtime_report",
                side_effect=RuntimeError("injected report projection failure"),
            ):
                result = execute_runtime_request(
                    request, store=store, callbacks=callbacks
                )
            with store.read_transaction() as connection:
                state = connection.execute(
                    "SELECT status FROM runtime_sessions"
                ).fetchone()[0]
        self.assertEqual(result["classification"], "reconciliation_required")
        self.assertEqual(len(cleanups), 1)
        self.assertEqual(cleanups[0][0]["resource_id"], server_id)
        self.assertEqual(state, "cleaned")

    def test_success_without_authoritative_target_is_rejected_and_cleaned(self) -> None:
        cleanups: list[list[dict[str, object]]] = []
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            def dispatch(request, _project, _session_id, link):
                target_id = request["target"]["id"]
                link(
                    {
                        "kind": "service",
                        "id": target_id,
                        "cleanup_disposition": "removed",
                        "identity": {
                            "state": "reserved",
                            "expected_generation": 0,
                            "prior": None,
                        },
                    }
                )
                return {
                    "ok": True,
                    "id": target_id,
                    "status": "running",
                    "health": {"ok": True},
                }

            result = execute_runtime_request(
                self.request(),
                store=store,
                callbacks=self._callbacks(
                    store,
                    dispatch=dispatch,
                    cleanup=lambda _request, resources: cleanups.append(resources)
                    or {
                        "ok": True,
                        "state": "removed",
                        "reservation_outcome": "not_created",
                    },
                ),
            )
            with store.read_transaction() as connection:
                session = connection.execute(
                    "SELECT status FROM runtime_sessions"
                ).fetchone()[0]
                cleanup_state = connection.execute(
                    "SELECT cleanup_state FROM runtime_session_resources"
                ).fetchone()[0]
            inventory = store.inventory_v2()
        self.assertFalse(result["ok"])
        self.assertEqual(result["classification"], "terminal_state_unavailable")
        self.assertEqual(len(cleanups), 1)
        self.assertEqual(session, "cleaned")
        self.assertEqual(cleanup_state, "removed")
        self.assertFalse(
            any(
                scope["server_ids"]
                for tree in inventory["repository_trees"]
                for scope in tree["scopes"]
            )
        )

    def test_runtime_secrets_never_cross_persistence_response_or_diagnostic(self) -> None:
        secret = "unique-low-entropy-secret"
        credential_url = f"https://agent:{secret}@example.test/health?token={secret}"
        request = self.request(
            options={
                "argv": ["/usr/bin/true", secret],
                "env": {"PASSWORD": secret},
                "health_url": credential_url,
            }
        )
        with mock.patch.dict(
            os.environ,
            {"CODEX_AGENT_COORDINATOR_HOME": str(self.home)},
        ):
            with AccountStore.open_default(
                self.home, effective_uid=os.geteuid()
            ) as store:
                callbacks = self._callbacks(
                    store,
                    dispatch=lambda _request, _project, _session_id, _link: {
                        "ok": False,
                        "error": f"token={secret} at {credential_url}",
                        "argv": ["/usr/bin/true", secret],
                        "env": {"PASSWORD": secret},
                    },
                )
                result = execute_runtime_request(
                    request, store=store, callbacks=callbacks
                )
                with store.read_transaction() as connection:
                    row = connection.execute(
                        "SELECT session_id, request_json, result_json FROM runtime_sessions"
                    ).fetchone()
                session_id = str(row["session_id"])
                persisted = str(row["request_json"]) + str(row["result_json"])
                path = dev_coordinator._runtime_write_diagnostic(
                    session_id=session_id,
                    payload={"error": f"token={secret}", "url": credential_url},
                    request=request,
                )
                artifact = dev_coordinator.coordinated_runtime_artifact(
                    resource_kind="diagnostic", resource_id=session_id
                )
                Path(path).chmod(0o644)
                with self.assertRaises(KeyError):
                    dev_coordinator.coordinated_runtime_artifact(
                        resource_kind="diagnostic", resource_id=session_id
                    )
                Path(path).chmod(0o600)
        rendered = json.dumps(result, sort_keys=True)
        self.assertNotIn(secret, persisted)
        self.assertNotIn(secret, rendered)
        self.assertNotIn("agent:", persisted)
        self.assertNotIn("?token=", persisted)
        self.assertNotIn(secret, Path(path).read_text(encoding="utf-8"))
        self.assertNotIn(secret, artifact["text"])
        self.assertEqual(
            json.loads(row["request_json"])["options"]["env"],
            {"redacted": True, "names": ["PASSWORD"], "count": 1},
        )

    def test_runtime_artifact_is_fd_bound_root_confined_and_limited_to_one_mib(
        self,
    ) -> None:
        with mock.patch.dict(
            os.environ,
            {"CODEX_AGENT_COORDINATOR_HOME": str(self.home)},
        ):
            with AccountStore.open_default(
                self.home, effective_uid=os.geteuid()
            ) as store:
                host_id, repo_id = self._insert_repository(store)
                server_id = self._insert_running_service(
                    store, repo_id=repo_id, host_id=host_id
                )
                outside = self.root / "outside.log"
                outside.write_text("outside", encoding="utf-8")
                outside.chmod(0o600)
                with store.immediate_transaction() as connection:
                    connection.execute(
                        "UPDATE server_definitions SET log_path = ? "
                        "WHERE server_definition_id = ?",
                        (str(outside), server_id),
                    )
                with self.assertRaises(KeyError):
                    dev_coordinator.coordinated_runtime_artifact(
                        resource_kind="service", resource_id=server_id
                    )

                result = execute_runtime_request(
                    self.request(),
                    store=store,
                    callbacks=self._callbacks(
                        store,
                        dispatch=lambda *_arguments: {
                            "ok": False,
                            "classification": "fixture",
                        },
                    ),
                )
                self.assertFalse(result["ok"])
                with store.read_transaction() as connection:
                    session_id = str(
                        connection.execute(
                            "SELECT session_id FROM runtime_sessions "
                            "ORDER BY created_at DESC LIMIT 1"
                        ).fetchone()[0]
                    )
                artifact_path = Path(
                    dev_coordinator._runtime_write_diagnostic(
                        session_id=session_id,
                        payload={"classification": "fixture"},
                        request=self.request(),
                    )
                )
                artifact_path.write_bytes(
                    b"x" * (dev_coordinator.RUNTIME_ARTIFACT_MAX_BYTES + 1)
                )
                artifact_path.chmod(0o600)
                artifact = dev_coordinator.coordinated_runtime_artifact(
                    resource_kind="diagnostic", resource_id=session_id
                )
                self.assertEqual(
                    len(artifact["text"].encode("utf-8")),
                    dev_coordinator.RUNTIME_ARTIFACT_MAX_BYTES,
                )

                artifact_path.unlink()
                artifact_path.symlink_to(outside)
                with self.assertRaises(KeyError):
                    dev_coordinator.coordinated_runtime_artifact(
                        resource_kind="diagnostic", resource_id=session_id
                    )

            log_root = dev_coordinator.logs_dir()
            real_log_root = self.home / "logs-real"
            log_root.rename(real_log_root)
            log_root.symlink_to(real_log_root, target_is_directory=True)
            with self.assertRaises(KeyError):
                dev_coordinator.coordinated_runtime_artifact(
                    resource_kind="diagnostic", resource_id=session_id
                )

    def test_service_start_reuses_enrolled_runtime_configuration(self) -> None:
        server_id = "existing-service-id"
        request = validate_runtime_request(
            self.request(
                target={"kind": "service", "id": server_id, "name": "web"},
                options={},
            )
        )
        previous = {
            "id": server_id,
            "status": "stopped",
            "generation": 4,
            "health": {"ok": False},
        }
        started = {
            "id": server_id,
            "status": "running",
            "generation": 5,
            "lease_id": "lease-id",
            "process_fingerprint": "process",
            "health": {"ok": True},
        }
        stored_options = {
            "agent": "test-agent",
            "project": str(self.repository),
            "name": "web",
            "cwd": str(self.repository),
            "argv": ["/stored/executable", "--stored"],
            "health_timeout": 10,
        }
        links: list[dict[str, object]] = []
        with (
            mock.patch.object(
                dev_coordinator,
                "coordinated_status_server",
                return_value=previous,
            ),
            mock.patch.object(
                dev_coordinator,
                "_runtime_existing_service_start_options",
                return_value=stored_options,
            ) as existing,
            mock.patch.object(
                dev_coordinator,
                "coordinated_start_server",
                return_value=started,
            ) as start,
        ):
            result = dev_coordinator.coordinated_runtime_dispatch(
                request, str(self.repository), str(uuid.uuid4()), links.append
            )
        existing.assert_called_once()
        start.assert_called_once_with(stored_options)
        self.assertTrue(result["ok"])
        self.assertEqual(links, [])

    def test_proved_stopped_service_status_is_successful_but_not_ready(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_running_service(
                store, repo_id=repo_id, host_id=host_id
            )
            self._prove_stopped_service(store, server_id=server_id)
            result = execute_runtime_request(
                self.request(
                    action="status",
                    target={"kind": "service", "id": server_id, "name": "web"},
                    options={},
                ),
                store=store,
                callbacks=self._callbacks(
                    store,
                    dispatch=lambda *_args: self._stopped_service_result(server_id),
                ),
            )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["classification"], "observed_not_ready")
        self.assertFalse(result["result"]["ready"])
        self.assertEqual(result["result"]["state"], "stopped")

    def test_service_terminal_proof_binds_generation_listener_lease_and_process(
        self,
    ) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_running_service(
                store, repo_id=repo_id, host_id=host_id
            )
            inventory = store.inventory_v2()
        request = validate_runtime_request(
            self.request(
                target={"kind": "service", "id": server_id, "name": "web"},
                options={},
            )
        )
        baseline = self._running_service_result(server_id)
        proved = runtime_api_module.validate_runtime_terminal_state(
            request=request,
            action_result=baseline,
            observation={"ok": True},
            inventory=inventory,
            pre_inventory=inventory,
        )
        self.assertTrue(proved["ok"], proved)

        cases = {
            "immutable_id": {**baseline, "id": "different-service"},
            "generation": {**baseline, "generation": 7},
            "lease": {**baseline, "lease_id": "different-lease"},
            "listener": {**baseline, "port": 3211},
            "process": {**baseline, "process_fingerprint": "different-process"},
        }
        for label, action_result in cases.items():
            with self.subTest(label=label):
                rejected = runtime_api_module.validate_runtime_terminal_state(
                    request=request,
                    action_result=action_result,
                    observation={"ok": True},
                    inventory=inventory,
                    pre_inventory=inventory,
                )
                self.assertFalse(rejected["ok"], rejected)
                self.assertEqual(
                    rejected["classification"],
                    "lifecycle_target_identity_changed",
                )

    def test_supervised_worker_terminal_proof_uses_attempt_not_listener_lease(self) -> None:
        server_id = str(uuid.uuid4())
        request = validate_runtime_request(
            self.request(
                target={"kind": "service", "id": server_id, "name": "worker"},
                options={"keep_alive": True},
            )
        )
        fingerprint_value = "sha256:" + "7" * 64
        action_result = {
            "ok": True,
            "id": server_id,
            "name": "worker",
            "generation": 2,
            "status": "running",
            "pid": 43210,
            "process_fingerprint": fingerprint_value,
            "health": {"ok": True},
        }
        supervision = {
            "keep_alive": True,
            "desired_state": "running",
            "state": "running",
            "current_attempt_id": "attempt-1",
            "current_attempt": {
                "attempt_id": "attempt-1",
                "state": "running",
                "pid": 43210,
                "process_fingerprint": fingerprint_value,
            },
        }
        inventory = {
            "resources": {
                "servers": [
                    {
                        "server_definition_id": server_id,
                        "repo_id": "repo-1",
                        "name": "worker",
                        "generation": 2,
                        "supervision": supervision,
                    }
                ]
            },
            "observations": {
                "servers": [
                    {
                        "server_definition_id": server_id,
                        "lifecycle": "running",
                        "pid": 43210,
                        "process_fingerprint": fingerprint_value,
                        "health_ok": True,
                    }
                ]
            },
            "leases": [],
            "port_assignments": [],
        }
        proved = runtime_api_module.validate_runtime_terminal_state(
            request=request,
            action_result=action_result,
            observation={"ok": True},
            inventory=inventory,
            pre_inventory=inventory,
        )
        self.assertTrue(proved["ok"], proved)
        self.assertEqual(proved["terminal_state"]["proof"], "worker_supervisor_attempt")

        changed = json.loads(json.dumps(inventory))
        changed["observations"]["servers"][0]["process_fingerprint"] = (
            "sha256:" + "8" * 64
        )
        rejected = runtime_api_module.validate_runtime_terminal_state(
            request=request,
            action_result=action_result,
            observation={"ok": True},
            inventory=changed,
            pre_inventory=changed,
        )
        self.assertFalse(rejected["ok"])
        self.assertEqual(
            rejected["classification"], "lifecycle_target_identity_changed"
        )

    def test_account_supervised_worker_replace_uses_atomic_controller_and_preserves_failure(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_running_service(
                store, repo_id=repo_id, host_id=host_id
            )
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE server_definitions SET role = 'worker' WHERE server_definition_id = ?",
                    (server_id,),
                )
            WorkerSupervision(store).configure_policy(
                server_definition_id=server_id,
                actor="fixture",
                execution_uid=os.geteuid(),
                keep_alive=True,
            )
            request = validate_runtime_request(
                self.request(
                    action="replace",
                    target={"kind": "service", "id": server_id, "name": "web"},
                    options={
                        "argv": ["/usr/bin/python3", "worker.py"],
                        "cwd": str(self.repository),
                        "env": {"MODE": "worker-v2"},
                        "expected_definition_generation": 0,
                        "keep_alive": True,
                    },
                )
            )
            calls: list[dict[str, object]] = []
            repository_path = str(self.repository)

            class FakeController:
                def __init__(self, received_store, **_kwargs):
                    self.store = received_store

                def replace(self, **kwargs):
                    calls.append(kwargs)
                    return {
                        "id": server_id,
                        "name": "web",
                        "project": repository_path,
                        "generation": 1,
                        "status": "running",
                        "health": {"ok": True},
                        "replacement": {"generation": 1},
                    }

            with mock.patch.object(
                dev_coordinator, "WorkerController", FakeController
            ):
                result = dev_coordinator.coordinated_runtime_dispatch(
                    request,
                    str(self.repository),
                    None,
                    lambda _resource: None,
                    runtime_store=store,
                )

        self.assertTrue(result["ok"], result)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["expected_generation"], 0)
        self.assertEqual(calls[0]["environment"], {"MODE": "worker-v2"})

        failure = WorkerReplaceError(
            "replacement rolled back",
            payload={
                "classification": "replacement_failed_rolled_back",
                "rollback": {"ok": True},
            },
        )
        envelope = dev_coordinator._runtime_error_envelope(request, failure)
        self.assertEqual(
            envelope["classification"], "replacement_failed_rolled_back"
        )
        self.assertEqual(envelope["evidence"]["rollback"], {"ok": True})

    def test_service_replace_success_and_both_rollback_outcomes(self) -> None:
        server_id = "replace-service-id"
        request = validate_runtime_request(
            self.request(
                action="replace",
                target={"kind": "service", "id": server_id, "name": "web"},
                options={"argv": ["/replacement", "--serve"]},
            )
        )
        previous = self._running_service_result(server_id)
        stopped = self._stopped_service_result(server_id)
        replaced = self._running_service_result(server_id, generation=1)
        rollback = {
            "agent": "test-agent",
            "project": str(self.repository),
            "name": "web",
            "cwd": str(self.repository),
            "argv": ["/previous", "--serve"],
        }

        with (
            mock.patch.object(
                dev_coordinator, "coordinated_status_server", return_value=previous
            ),
            mock.patch.object(
                dev_coordinator,
                "_runtime_existing_service_start_options",
                return_value=rollback,
            ),
            mock.patch.object(
                dev_coordinator, "coordinated_stop_server", return_value=stopped
            ) as stop,
            mock.patch.object(
                dev_coordinator, "coordinated_start_server", return_value=replaced
            ) as start,
        ):
            result = dev_coordinator.coordinated_runtime_dispatch(
                request, str(self.repository), str(uuid.uuid4()), lambda _item: None
            )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["started"]["generation"], 1)
        stop.assert_called_once()
        start.assert_called_once()

        primary = RuntimeError("replacement failed")
        with (
            mock.patch.object(
                dev_coordinator, "coordinated_status_server", return_value=previous
            ),
            mock.patch.object(
                dev_coordinator,
                "_runtime_existing_service_start_options",
                return_value=rollback,
            ),
            mock.patch.object(
                dev_coordinator, "coordinated_stop_server", return_value=stopped
            ),
            mock.patch.object(
                dev_coordinator,
                "coordinated_start_server",
                side_effect=[primary, previous],
            ) as rollback_start,
        ):
            with self.assertRaisesRegex(RuntimeError, "replacement failed"):
                dev_coordinator.coordinated_runtime_dispatch(
                    request,
                    str(self.repository),
                    str(uuid.uuid4()),
                    lambda _item: None,
                )
        self.assertEqual(rollback_start.call_count, 2)
        self.assertEqual(rollback_start.call_args_list[1].args[0], rollback)

        with (
            mock.patch.object(
                dev_coordinator, "coordinated_status_server", return_value=previous
            ),
            mock.patch.object(
                dev_coordinator,
                "_runtime_existing_service_start_options",
                return_value=rollback,
            ),
            mock.patch.object(
                dev_coordinator, "coordinated_stop_server", return_value=stopped
            ),
            mock.patch.object(
                dev_coordinator,
                "coordinated_start_server",
                side_effect=[RuntimeError("replacement failed"), RuntimeError("rollback failed")],
            ),
        ):
            with self.assertRaises(dev_coordinator.StructuredCoordinatorError) as raised:
                dev_coordinator.coordinated_runtime_dispatch(
                    request,
                    str(self.repository),
                    str(uuid.uuid4()),
                    lambda _item: None,
                )
        self.assertEqual(
            raised.exception.payload["classification"], "reconciliation_required"
        )
        self.assertIn("replacement failed", raised.exception.payload["replace_error"]["error"])
        self.assertIn("rollback failed", raised.exception.payload["rollback_error"]["error"])

    def test_service_replace_post_observation_and_ttl_cleanup(self) -> None:
        cleaned: list[list[dict[str, object]]] = []
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_running_service(
                store, repo_id=repo_id, host_id=host_id
            )
            self._prove_stopped_service(store, server_id=server_id)
            stopped = self._stopped_service_result(server_id)

            def start_replacement(_options: dict[str, object]) -> dict[str, object]:
                return self._set_running_service(
                    store, server_id=server_id, generation=1
                )

            def cleanup(_request, resources):
                cleaned.append(resources)
                self._prove_stopped_service(store, server_id=server_id)
                return {
                    "ok": True,
                    "state": "stopped",
                    "server": self._stopped_service_result(
                        server_id, generation=1
                    ),
                }

            with (
                mock.patch.object(
                    dev_coordinator,
                    "coordinated_status_server",
                    return_value=stopped,
                ),
                mock.patch.object(
                    dev_coordinator,
                    "_runtime_existing_service_start_options",
                    return_value={
                        "agent": "test-agent",
                        "project": str(self.repository),
                        "name": "web",
                        "cwd": str(self.repository),
                        "argv": ["/previous"],
                    },
                ),
                mock.patch.object(
                    dev_coordinator,
                    "coordinated_stop_server",
                    return_value=stopped,
                ),
                mock.patch.object(
                    dev_coordinator,
                    "coordinated_start_server",
                    side_effect=start_replacement,
                ),
            ):
                result = execute_runtime_request(
                    self.request(
                        action="replace",
                        ttl_seconds=1,
                        target={
                            "kind": "service",
                            "id": server_id,
                            "name": "web",
                        },
                        options={"argv": ["/replacement"]},
                    ),
                    store=store,
                    callbacks=self._callbacks(
                        store,
                        dispatch=dev_coordinator.coordinated_runtime_dispatch,
                        cleanup=cleanup,
                        cleanup_owner_available=True,
                    ),
                )
            self.assertTrue(result["ok"], result)
            with store.read_transaction() as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT status FROM runtime_sessions WHERE session_id = ?",
                        (result["run_id"],),
                    ).fetchone()[0],
                    "running",
                )
            reaped = reap_expired_runtime_sessions(
                store,
                timestamp="2099-01-01T00:00:00Z",
                cleanup=cleanup,
            )
            inventory = store.inventory_v2()
        self.assertEqual(reaped[0]["status"], "expired")
        self.assertEqual(len(cleaned), 1)
        self.assertEqual(cleaned[0][0]["cleanup_disposition"], "retained")
        self.assertIn(
            server_id,
            inventory["repository_trees"][0]["scopes"][0]["server_ids"],
        )

    def test_service_replace_final_identity_drift_is_not_reported_successful(self) -> None:
        cleaned: list[list[dict[str, object]]] = []
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_running_service(
                store, repo_id=repo_id, host_id=host_id
            )
            self._prove_stopped_service(store, server_id=server_id)
            stopped = self._stopped_service_result(server_id)
            with (
                mock.patch.object(
                    dev_coordinator,
                    "coordinated_status_server",
                    return_value=stopped,
                ),
                mock.patch.object(
                    dev_coordinator,
                    "_runtime_existing_service_start_options",
                    return_value={"argv": ["/previous"]},
                ),
                mock.patch.object(
                    dev_coordinator,
                    "coordinated_stop_server",
                    return_value=stopped,
                ),
                mock.patch.object(
                    dev_coordinator,
                    "coordinated_start_server",
                    return_value=self._running_service_result(
                        server_id, generation=1
                    ),
                ),
            ):
                result = execute_runtime_request(
                    self.request(
                        action="replace",
                        target={
                            "kind": "service",
                            "id": server_id,
                            "name": "web",
                        },
                        options={"argv": ["/replacement"]},
                    ),
                    store=store,
                    callbacks=self._callbacks(
                        store,
                        dispatch=dev_coordinator.coordinated_runtime_dispatch,
                        cleanup=lambda _request, resources: cleaned.append(resources)
                        or {"ok": True, "state": "stopped"},
                    ),
                )
        self.assertFalse(result["ok"])
        self.assertIn(
            result["classification"],
            {"lifecycle_target_not_ready", "lifecycle_target_identity_changed"},
        )
        self.assertEqual(len(cleaned), 0)

    def test_run_never_executes_command_until_start_is_exactly_proved(self) -> None:
        server_id = "run-service-id"
        request = validate_runtime_request(
            self.request(
                action="run",
                purpose="test",
                ttl_seconds=30,
                kill_after_run=True,
                target={"kind": "service", "id": server_id, "name": "web"},
                options={
                    "argv": ["/service"],
                    "run_argv": ["/usr/bin/true"],
                },
            )
        )
        stopped = self._stopped_service_result(server_id)
        with (
            mock.patch.object(
                dev_coordinator, "coordinated_build_inventory", return_value={}
            ),
            mock.patch.object(
                dev_coordinator, "coordinated_status_server", return_value=stopped
            ),
            mock.patch.object(
                dev_coordinator,
                "coordinated_start_server",
                return_value={
                    "ok": False,
                    "id": server_id,
                    "status": "stopped",
                    "classification": "fixture_start_failed",
                },
            ),
            mock.patch.object(dev_coordinator, "_runtime_run_command") as run_command,
        ):
            with self.assertRaises(dev_coordinator.StructuredCoordinatorError) as raised:
                dev_coordinator.coordinated_runtime_dispatch(
                    request, str(self.repository), str(uuid.uuid4()), lambda _item: None
                )
        self.assertEqual(
            raised.exception.payload["code"], "runtime_test_start_failed"
        )
        run_command.assert_not_called()

    def test_run_rejects_claimed_start_when_final_inventory_does_not_match(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_running_service(
                store, repo_id=repo_id, host_id=host_id
            )
            self._prove_stopped_service(store, server_id=server_id)
            stopped_inventory = store.inventory_v2()
        request = validate_runtime_request(
            self.request(
                action="run",
                purpose="test",
                ttl_seconds=30,
                kill_after_run=True,
                target={"kind": "service", "id": server_id, "name": "web"},
                options={
                    "argv": ["/service"],
                    "run_argv": ["/usr/bin/true"],
                },
            )
        )
        stopped = self._stopped_service_result(server_id)
        with (
            mock.patch.object(
                dev_coordinator,
                "coordinated_build_inventory",
                side_effect=[stopped_inventory, stopped_inventory],
            ),
            mock.patch.object(
                dev_coordinator,
                "coordinated_observe_host",
                return_value={"ok": True, "observed": True},
            ),
            mock.patch.object(
                dev_coordinator, "coordinated_status_server", return_value=stopped
            ),
            mock.patch.object(
                dev_coordinator,
                "coordinated_start_server",
                return_value=self._running_service_result(server_id, generation=1),
            ),
            mock.patch.object(dev_coordinator, "_runtime_run_command") as run_command,
        ):
            with self.assertRaises(dev_coordinator.StructuredCoordinatorError) as raised:
                dev_coordinator.coordinated_runtime_dispatch(
                    request, str(self.repository), str(uuid.uuid4()), lambda _item: None
                )
        self.assertEqual(
            raised.exception.payload["code"], "runtime_test_start_unproven"
        )
        run_command.assert_not_called()

    def test_temporary_service_is_reserved_before_external_start(self) -> None:
        server_id = "temporary-service-id"
        request = validate_runtime_request(
            self.request(
                purpose="temporary",
                ttl_seconds=60,
                target={"kind": "service", "id": server_id, "name": "web"},
            )
        )
        links: list[dict[str, object]] = []

        def fail_after_reservation(_options):
            self.assertEqual(len(links), 1)
            self.assertEqual(links[0]["identity"]["state"], "reserved")
            raise RuntimeError("injected launch failure")

        with (
            mock.patch.object(
                dev_coordinator,
                "coordinated_status_server",
                side_effect=KeyError("not found"),
            ),
            mock.patch.object(
                dev_coordinator,
                "coordinated_start_server",
                side_effect=fail_after_reservation,
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "injected launch failure"):
                dev_coordinator.coordinated_runtime_dispatch(
                    request,
                    str(self.repository),
                    str(uuid.uuid4()),
                    links.append,
                )
        self.assertEqual(links[0]["cleanup_disposition"], "removed")

    def test_development_service_without_ttl_creates_no_runtime_link(self) -> None:
        server_id = "persistent-service-id"
        request = validate_runtime_request(
            self.request(
                target={"kind": "service", "id": server_id, "name": "web"}
            )
        )
        started = {
            "id": server_id,
            "status": "running",
            "generation": 0,
            "health": {"ok": True},
        }
        links: list[dict[str, object]] = []
        with (
            mock.patch.object(
                dev_coordinator,
                "coordinated_status_server",
                side_effect=KeyError("not found"),
            ),
            mock.patch.object(
                dev_coordinator,
                "coordinated_start_server",
                return_value=started,
            ),
        ):
            result = dev_coordinator.coordinated_runtime_dispatch(
                request, str(self.repository), str(uuid.uuid4()), links.append
            )
        self.assertEqual(links, [])
        self.assertEqual(result["runtime_ownership"], "persistent_created")

    def test_docker_command_exit_zero_remains_pending_until_observed(self) -> None:
        result = dev_coordinator._runtime_result_with_status(
            action="start",
            kind="docker",
            result={"returncode": 0, "command": ["docker", "start", "exact-id"]},
        )
        self.assertIsNot(result.get("ok"), True)
        self.assertTrue(result["terminal_state_pending"])
        self.assertEqual(result["classification"], "terminal_state_pending")

    def test_stopped_docker_and_database_status_are_observed_not_failures(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            docker_id, database_id = self._insert_docker_database(
                store,
                repo_id=repo_id,
                host_id=host_id,
                lifecycle="stopped",
                database_available=False,
            )
            for kind, resource_id in (
                ("docker", docker_id),
                ("database_stack", database_id),
            ):
                with self.subTest(kind=kind):
                    result = execute_runtime_request(
                        self.request(
                            action="status",
                            target={"kind": kind, "id": resource_id},
                            options={},
                        ),
                        store=store,
                        callbacks=self._callbacks(
                            store,
                            dispatch=lambda *_args: {
                                "ok": True,
                                "status": "stopped",
                                "state": "stopped",
                            },
                            observe=lambda _project: self._full_docker_observation(
                                store
                            ),
                        ),
                    )
                    self.assertTrue(result["ok"], result)
                    self.assertEqual(
                        result["classification"], "observed_not_ready"
                    )
                    self.assertFalse(result["result"]["ready"])

    def test_full_docker_proof_rejects_cached_and_revision_drift(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            inventory = store.inventory_v2()
            baseline = self._full_docker_observation(store)
            inventory = store.inventory_v2()
            cases = {
                "observed_false": {**baseline, "observed": False},
                "cached_fresh": {**baseline, "status": "fresh"},
                "revision_drift": {
                    **baseline,
                    "observation_revision": int(
                        baseline["observation_revision"]
                    )
                    + 1,
                },
            }
            for label, observation in cases.items():
                with self.subTest(label=label):
                    proved, _evidence = (
                        runtime_api_module._full_docker_observation_proof(
                            observation, inventory
                        )
                    )
                    self.assertFalse(proved)

    def test_account_observation_returns_revision_bound_docker_capability(self) -> None:
        snapshot_id = "runtime-account-observation"
        timestamp = "2026-01-01T00:00:00Z"
        with mock.patch.dict(
            os.environ,
            {
                "CODEX_AGENT_COORDINATOR_HOME": str(self.home),
                "DEVCOORDINATOR_AUTHORITY": "account",
            },
        ):
            with AccountStore.open_default(
                self.home, effective_uid=os.geteuid()
            ) as store:
                host_id = dev_coordinator.ensure_observation_host(store)
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        INSERT INTO observation_snapshots(
                            snapshot_id, host_id, observer_domain, status,
                            material_fingerprint, started_at, completed_at
                        ) VALUES (?, ?, 'host-runtime-v2:full-docker',
                                  'completed', ?, ?, ?)
                        """,
                        (snapshot_id, host_id, "f" * 64, timestamp, timestamp),
                    )
                    connection.execute(
                        """
                        INSERT INTO observation_capabilities(
                            snapshot_id, observer_domain, docker_available,
                            capability_fingerprint, committed_at
                        ) VALUES (?, 'host-runtime-v2:full-docker', 1, ?, ?)
                        """,
                        (snapshot_id, "sha256:" + "c" * 64, timestamp),
                    )
            outcome = mock.Mock(
                snapshot_id=snapshot_id,
                host_id=host_id,
                observer_domain="host-runtime-v2:full-docker",
                joined=False,
                material_fingerprint="f" * 64,
                completed_at=timestamp,
            )
            with (
                mock.patch.object(
                    dev_coordinator, "bootstrap_legacy_import", return_value={}
                ),
                mock.patch.object(
                    dev_coordinator.SingleFlightObserver,
                    "observe",
                    return_value=outcome,
                ),
            ):
                result = dev_coordinator.coordinated_observe_host(
                    {
                        "agent": "test-agent",
                        "project": str(self.repository),
                        "max_age_seconds": 0,
                        "no_docker": False,
                        "backup_dir": None,
                        "legacy_home": [],
                        "legacy_backup_root": None,
                    }
                )
            with AccountStore.open_default(
                self.home, effective_uid=os.geteuid()
            ) as store:
                inventory = store.inventory_v2()
        self.assertTrue(result["docker_available"])
        self.assertRegex(
            str(result["capability_fingerprint"]), r"^sha256:[0-9a-f]{64}$"
        )
        proved, _evidence = runtime_api_module._full_docker_observation_proof(
            result, inventory
        )
        self.assertTrue(proved)

    def test_docker_start_exit_zero_does_not_override_stopped_observation(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            docker_id, _database_id = self._insert_docker_database(
                store, repo_id=repo_id, host_id=host_id
            )
            result = execute_runtime_request(
                self.request(
                    target={"kind": "docker", "id": docker_id}, options={}
                ),
                store=store,
                callbacks=self._callbacks(
                    store,
                    dispatch=lambda *_args: {
                        "ok": False,
                        "terminal_state_pending": True,
                        "classification": "terminal_state_pending",
                        "returncode": 0,
                    },
                    observe=lambda _project: self._full_docker_observation(store),
                ),
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["classification"], "lifecycle_target_not_ready")
        self.assertEqual(result["result"]["terminal_state"]["observed_state"], "stopped")

    def test_docker_start_requires_fresh_full_docker_observation(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            docker_id, _database_id = self._insert_docker_database(
                store, repo_id=repo_id, host_id=host_id
            )

            def dispatch(*_args):
                with store.immediate_transaction() as connection:
                    connection.execute(
                        "UPDATE docker_observations SET lifecycle = 'running' "
                        "WHERE docker_resource_id = ?",
                        (docker_id,),
                    )
                return {
                    "ok": False,
                    "terminal_state_pending": True,
                    "classification": "terminal_state_pending",
                    "returncode": 0,
                }

            def cached_observation(_project: str) -> dict[str, object]:
                observation = self._full_docker_observation(store)
                observation["observed"] = False
                return observation

            result = execute_runtime_request(
                self.request(
                    target={"kind": "docker", "id": docker_id}, options={}
                ),
                store=store,
                callbacks=self._callbacks(
                    store,
                    dispatch=dispatch,
                    observe=cached_observation,
                ),
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["classification"], "terminal_state_unavailable")

    def test_docker_start_is_promoted_after_exact_running_observation(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            docker_id, _database_id = self._insert_docker_database(
                store, repo_id=repo_id, host_id=host_id
            )

            def dispatch(*_args):
                with store.immediate_transaction() as connection:
                    connection.execute(
                        "UPDATE docker_observations SET lifecycle = 'running' "
                        "WHERE docker_resource_id = ?",
                        (docker_id,),
                    )
                return {
                    "ok": False,
                    "terminal_state_pending": True,
                    "classification": "terminal_state_pending",
                    "returncode": 0,
                }

            result = execute_runtime_request(
                self.request(
                    target={"kind": "docker", "id": docker_id}, options={}
                ),
                store=store,
                callbacks=self._callbacks(
                    store,
                    dispatch=dispatch,
                    observe=lambda _project: self._full_docker_observation(store),
                ),
            )
        self.assertTrue(result["ok"])
        self.assertEqual(result["result"]["terminal_state"]["observed_state"], "running")

    def test_docker_stop_accepts_freshly_proved_absence(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            docker_id, database_id = self._insert_docker_database(
                store, repo_id=repo_id, host_id=host_id, lifecycle="running"
            )

            def dispatch(*_args):
                with store.immediate_transaction() as connection:
                    connection.execute(
                        "DELETE FROM database_observations WHERE database_binding_id = ?",
                        (database_id,),
                    )
                    connection.execute(
                        "DELETE FROM database_bindings WHERE database_binding_id = ?",
                        (database_id,),
                    )
                    connection.execute(
                        "DELETE FROM repository_memberships "
                        "WHERE resource_kind = 'container' AND host_resource_id = ?",
                        (docker_id,),
                    )
                    connection.execute(
                        "DELETE FROM docker_observations WHERE docker_resource_id = ?",
                        (docker_id,),
                    )
                    connection.execute(
                        "DELETE FROM docker_resources WHERE docker_resource_id = ?",
                        (docker_id,),
                    )
                return {
                    "ok": False,
                    "terminal_state_pending": True,
                    "classification": "terminal_state_pending",
                    "returncode": 0,
                }

            result = execute_runtime_request(
                self.request(
                    action="stop",
                    target={"kind": "docker", "id": docker_id},
                    options={},
                ),
                store=store,
                callbacks=self._callbacks(
                    store,
                    dispatch=dispatch,
                    observe=lambda _project: self._full_docker_observation(store),
                ),
            )
        self.assertTrue(result["ok"])
        self.assertEqual(result["result"]["terminal_state"]["observed_state"], "absent")

    def test_database_restart_requires_database_readiness(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            docker_id, database_id = self._insert_docker_database(
                store, repo_id=repo_id, host_id=host_id
            )

            def dispatch(*_args):
                with store.immediate_transaction() as connection:
                    connection.execute(
                        "UPDATE docker_observations SET lifecycle = 'running' "
                        "WHERE docker_resource_id = ?",
                        (docker_id,),
                    )
                return {
                    "ok": False,
                    "terminal_state_pending": True,
                    "classification": "terminal_state_pending",
                    "returncode": 0,
                }

            result = execute_runtime_request(
                self.request(
                    action="restart",
                    target={"kind": "database_stack", "id": database_id},
                    options={},
                ),
                store=store,
                callbacks=self._callbacks(
                    store,
                    dispatch=dispatch,
                    observe=lambda _project: self._full_docker_observation(store),
                ),
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["classification"], "database_not_ready")
        self.assertFalse(result["result"]["terminal_state"]["database_available"])

    def test_database_restart_is_promoted_after_readiness_observation(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            docker_id, database_id = self._insert_docker_database(
                store, repo_id=repo_id, host_id=host_id
            )

            def dispatch(*_args):
                with store.immediate_transaction() as connection:
                    connection.execute(
                        "UPDATE docker_observations SET lifecycle = 'running' "
                        "WHERE docker_resource_id = ?",
                        (docker_id,),
                    )
                    connection.execute(
                        """
                        UPDATE database_observations
                        SET available = 1, error_code = NULL, error_message = NULL
                        WHERE database_binding_id = ?
                        """,
                        (database_id,),
                    )
                return {
                    "ok": False,
                    "terminal_state_pending": True,
                    "classification": "terminal_state_pending",
                    "returncode": 0,
                }

            result = execute_runtime_request(
                self.request(
                    action="restart",
                    target={"kind": "database_stack", "id": database_id},
                    options={},
                ),
                store=store,
                callbacks=self._callbacks(
                    store,
                    dispatch=dispatch,
                    observe=lambda _project: self._full_docker_observation(store),
                ),
            )
        self.assertTrue(result["ok"])
        self.assertTrue(result["result"]["terminal_state"]["database_available"])

    def test_database_status_reports_missing_readiness_as_unavailable(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            _docker_id, database_id = self._insert_docker_database(
                store,
                repo_id=repo_id,
                host_id=host_id,
                lifecycle="running",
                database_available=None,
            )
            result = execute_runtime_request(
                self.request(
                    action="status",
                    target={"kind": "database_stack", "id": database_id},
                    options={},
                ),
                store=store,
                callbacks=self._callbacks(
                    store,
                    dispatch=lambda *_args: {"ok": True, "status": "running"},
                    observe=lambda _project: self._full_docker_observation(store),
                ),
            )
        self.assertFalse(result["ok"])
        self.assertEqual(
            result["classification"], "database_readiness_unavailable"
        )

    def test_database_stop_requires_and_reports_stopped_terminal_state(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            docker_id, database_id = self._insert_docker_database(
                store,
                repo_id=repo_id,
                host_id=host_id,
                lifecycle="running",
                database_available=True,
            )

            def dispatch(*_args):
                with store.immediate_transaction() as connection:
                    connection.execute(
                        "UPDATE docker_observations SET lifecycle = 'stopped' "
                        "WHERE docker_resource_id = ?",
                        (docker_id,),
                    )
                    connection.execute(
                        """
                        UPDATE database_observations
                        SET available = 0, error_code = 'database_stopped',
                            error_message = 'database is stopped'
                        WHERE database_binding_id = ?
                        """,
                        (database_id,),
                    )
                return {
                    "ok": False,
                    "terminal_state_pending": True,
                    "classification": "terminal_state_pending",
                    "returncode": 0,
                }

            result = execute_runtime_request(
                self.request(
                    action="stop",
                    target={"kind": "database_stack", "id": database_id},
                    options={},
                ),
                store=store,
                callbacks=self._callbacks(
                    store,
                    dispatch=dispatch,
                    observe=lambda _project: self._full_docker_observation(store),
                ),
            )
        self.assertTrue(result["ok"])
        self.assertEqual(result["classification"], "ready")
        self.assertEqual(result["result"]["terminal_state"]["observed_state"], "stopped")
        self.assertFalse(result["result"]["terminal_state"]["database_available"])

    def test_docker_replace_fails_before_resource_observation_or_mutation(self) -> None:
        for kind in ("docker", "database_stack"):
            with self.subTest(kind=kind):
                request = validate_runtime_request(
                    self.request(
                        action="replace",
                        target={"kind": kind, "id": "immutable-resource-id"},
                        options={},
                    )
                )
                with mock.patch.object(
                    dev_coordinator, "_runtime_docker_identity"
                ) as identity:
                    with self.assertRaises(
                        dev_coordinator.StructuredCoordinatorError
                    ) as raised:
                        dev_coordinator.coordinated_runtime_dispatch(
                            request,
                            str(self.repository),
                            str(uuid.uuid4()),
                            lambda _resource: self.fail(
                                "unsupported replace linked a resource"
                            ),
                        )
                identity.assert_not_called()
                self.assertEqual(
                    raised.exception.payload["classification"],
                    "unsupported_safe_replace",
                )

    def test_docker_replace_is_rejected_before_account_store_or_host_access(self) -> None:
        for kind in ("docker", "database_stack"):
            with (
                self.subTest(kind=kind),
                mock.patch.object(dev_coordinator, "state_backend", return_value="sqlite"),
                mock.patch.object(dev_coordinator, "authority_mode", return_value="account"),
                mock.patch.object(
                    dev_coordinator.AccountStore,
                    "open_default",
                    side_effect=AssertionError("replace opened the account store"),
                ) as open_store,
                mock.patch.object(
                    dev_coordinator,
                    "resolve_repository_context",
                    side_effect=AssertionError("replace inspected the repository"),
                ) as resolve_repository,
                mock.patch.object(
                    dev_coordinator,
                    "coordinated_observe_host",
                    side_effect=AssertionError("replace observed the host"),
                ) as observe_host,
                mock.patch.object(
                    dev_coordinator,
                    "coordinated_run_docker",
                    side_effect=AssertionError("replace mutated Docker"),
                ) as run_docker,
            ):
                result = dev_coordinator.coordinated_runtime_request(
                    self.request(
                        action="replace",
                        target={"kind": kind, "id": "immutable-resource-id"},
                        options={
                            "compose_service": "db",
                            "compose_files": [
                                str(self.repository / "compose.yaml")
                            ],
                        },
                    )
                )
            self.assertFalse(result["ok"])
            self.assertEqual(result["classification"], "unsupported_safe_replace")
            self.assertEqual(result["evidence"]["resource_kind"], kind)
            self.assertEqual(
                result["evidence"]["resource_id"], "immutable-resource-id"
            )
            open_store.assert_not_called()
            resolve_repository.assert_not_called()
            observe_host.assert_not_called()
            run_docker.assert_not_called()

    def test_direct_replace_rejection_does_not_touch_store_or_callbacks(self) -> None:
        def forbidden(*_args, **_kwargs):
            self.fail("unsupported replacement crossed the admission boundary")

        callbacks = RuntimeCallbacks(
            ensure_repository=forbidden,
            dispatch=forbidden,
            cleanup=forbidden,
            observe=forbidden,
            inventory=forbidden,
        )
        for kind in ("docker", "database_stack"):
            with self.subTest(kind=kind), self.assertRaises(
                RuntimeSafeReplaceUnavailable
            ) as raised:
                execute_runtime_request(
                    self.request(
                        action="replace",
                        target={"kind": kind, "id": "immutable-resource-id"},
                        options={},
                    ),
                    store=object(),
                    callbacks=callbacks,
                )
            self.assertEqual(
                raised.exception.payload["classification"],
                "unsupported_safe_replace",
            )

    def test_dispatch_failure_after_reservation_is_cleaned_synchronously(self) -> None:
        cleaned: list[list[dict[str, object]]] = []
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            def dispatch(_request, _project, _session_id, link):
                link(
                    {
                        "kind": "service",
                        "id": deterministic_id(
                            "server-definition",
                            deterministic_id(
                                "repository",
                                store.ensure_local_host(),
                                str(self.repository),
                            ),
                            "web",
                        ),
                        "cleanup_disposition": "removed",
                        "identity": {
                            "state": "reserved",
                            "expected_generation": 0,
                            "prior": None,
                        },
                    }
                )
                raise RuntimeError("injected failure after durable reservation")

            callbacks = self._callbacks(
                store,
                dispatch=dispatch,
                cleanup=lambda _request, resources: cleaned.append(resources)
                or {
                    "ok": True,
                    "state": "removed",
                    "reservation_outcome": "not_created",
                },
                cleanup_owner_available=True,
            )
            result = execute_runtime_request(
                self.request(purpose="temporary", ttl_seconds=30),
                store=store,
                callbacks=callbacks,
            )
            with store.read_transaction() as connection:
                state = connection.execute(
                    "SELECT status FROM runtime_sessions"
                ).fetchone()[0]
        self.assertFalse(result["ok"])
        self.assertEqual(len(cleaned), 1)
        self.assertEqual(cleaned[0][0]["cleanup_state"], "active")
        self.assertEqual(state, "cleaned")

    def test_unknown_active_unassigned_resource_blocks_mutation(self) -> None:
        dispatched: list[str] = []
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id = store.ensure_local_host()
            timestamp = utc_timestamp()
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO unassigned_resources(
                        unassigned_id, host_id, resource_kind, resource_id,
                        display_name, reason_code, status, created_at, updated_at
                    ) VALUES (?, ?, 'process', 'unknown-process', 'unknown',
                              'not_git', 'active', ?, ?)
                    """,
                    (
                        deterministic_id("unassigned", host_id, "unknown-process"),
                        host_id,
                        timestamp,
                        timestamp,
                    ),
                )
            result = execute_runtime_request(
                self.request(),
                store=store,
                callbacks=self._callbacks(
                    store,
                    dispatch=lambda *_args: dispatched.append("dispatch")
                    or {"ok": True},
                ),
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["classification"], "unclassified_resource")
        self.assertEqual(dispatched, [])

    def test_explicit_unrelated_unassigned_resource_does_not_block_family(self) -> None:
        dispatched: list[str] = []
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_running_service(
                store, repo_id=repo_id, host_id=host_id
            )
            timestamp = utc_timestamp()
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO unassigned_resources(
                        unassigned_id, host_id, resource_kind, resource_id,
                        display_name, reason_code, suggested_root, status,
                        created_at, updated_at
                    ) VALUES (?, ?, 'process', 'unrelated-process', 'unrelated',
                              'not_git', ?, 'active', ?, ?)
                    """,
                    (
                        deterministic_id(
                            "unassigned", host_id, "unrelated-process"
                        ),
                        host_id,
                        str(self.root / "unrelated-project"),
                        timestamp,
                        timestamp,
                    ),
                )
            request = self.request(
                action="status",
                target={"kind": "service", "id": server_id, "name": "web"},
                options={},
            )
            result = execute_runtime_request(
                request,
                store=store,
                callbacks=self._callbacks(
                    store,
                    dispatch=lambda *_args: dispatched.append("dispatch")
                    or self._running_service_result(server_id),
                ),
            )
        self.assertTrue(result["ok"])
        self.assertEqual(dispatched, ["dispatch"])
        self.assertNotIn("evidence", result)

    def test_unknown_unassigned_resource_on_another_host_does_not_block(self) -> None:
        dispatched: list[str] = []
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_running_service(
                store, repo_id=repo_id, host_id=host_id
            )
            timestamp = utc_timestamp()
            foreign_host_id = deterministic_id("host", "foreign-runtime-host")
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO hosts(
                        host_id, machine_fingerprint, platform, hostname,
                        created_at, updated_at
                    ) VALUES (?, 'foreign-runtime-machine', 'linux', 'foreign', ?, ?)
                    """,
                    (foreign_host_id, timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO unassigned_resources(
                        unassigned_id, host_id, resource_kind, resource_id,
                        display_name, reason_code, status, created_at, updated_at
                    ) VALUES (?, ?, 'process', 'foreign-process', 'foreign',
                              'name_only', 'active', ?, ?)
                    """,
                    (
                        deterministic_id(
                            "unassigned", foreign_host_id, "foreign-process"
                        ),
                        foreign_host_id,
                        timestamp,
                        timestamp,
                    ),
                )
            result = execute_runtime_request(
                self.request(
                    action="status",
                    target={"kind": "service", "id": server_id, "name": "web"},
                    options={},
                ),
                store=store,
                callbacks=self._callbacks(
                    store,
                    dispatch=lambda *_args: dispatched.append("dispatch")
                    or self._running_service_result(server_id),
                ),
            )
        self.assertTrue(result["ok"])
        self.assertEqual(dispatched, ["dispatch"])
        self.assertNotIn("evidence", result)

    def test_unassigned_resource_inside_family_still_blocks_mutation(self) -> None:
        dispatched: list[str] = []
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id, repo_id = self._insert_repository(store)
            server_id = self._insert_running_service(
                store, repo_id=repo_id, host_id=host_id
            )
            timestamp = utc_timestamp()
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO unassigned_resources(
                        unassigned_id, host_id, resource_kind, resource_id,
                        display_name, reason_code, suggested_root, status,
                        created_at, updated_at
                    ) VALUES (?, ?, 'process', 'family-process', 'family',
                              'missing_repo', ?, 'active', ?, ?)
                    """,
                    (
                        deterministic_id("unassigned", host_id, "family-process"),
                        host_id,
                        str(self.repository / "removed-worktree-child"),
                        timestamp,
                        timestamp,
                    ),
                )
            result = execute_runtime_request(
                self.request(
                    action="status",
                    target={"kind": "service", "id": server_id, "name": "web"},
                    options={},
                ),
                store=store,
                callbacks=self._callbacks(
                    store,
                    dispatch=lambda *_args: dispatched.append("dispatch")
                    or {"ok": True},
                ),
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["classification"], "unclassified_resource")
        self.assertEqual(dispatched, [])
        self.assertEqual(result["evidence"][0]["resource_id"], "family-process")

    def test_docker_cleanup_reports_retained_and_removed_states_truthfully(self) -> None:
        identity = {
            "docker_resource_id": "docker-id",
            "full_container_id": "a" * 64,
            "immutable_fingerprint": "sha256:" + "1" * 64,
        }
        request = validate_runtime_request(
            self.request(
                action="stop",
                target={"kind": "docker", "id": "docker-id"},
                options={"cwd": "/tmp/client-controlled", "role": "client-role"},
            )
        )

        def resource(disposition: str) -> dict[str, object]:
            return {
                "resource_kind": "docker",
                "resource_id": "docker-id",
                "immutable_fingerprint": identity["immutable_fingerprint"],
                "cleanup_disposition": disposition,
                "identity_json": json.dumps(identity),
            }

        with (
            mock.patch.object(
                dev_coordinator, "_runtime_docker_identity", return_value=identity
            ),
            mock.patch.object(
                dev_coordinator,
                "_runtime_inspect_container_state",
                side_effect=["running", "exited"],
            ),
            mock.patch.object(
                dev_coordinator,
                "coordinated_run_docker",
                return_value={"returncode": 0},
            ) as run_docker,
        ):
            retained = dev_coordinator.coordinated_runtime_cleanup(
                request, [resource("retained")]
            )
        self.assertTrue(retained["ok"])
        self.assertEqual(retained["state"], "stopped")
        run_docker.assert_called_once_with(
            ["docker", "stop", identity["full_container_id"]],
            cwd=str(self.repository),
            project=str(self.repository),
            agent=dev_coordinator.RUNTIME_CLEANUP_AGENT,
            container=identity["full_container_id"],
            role=None,
        )
        with (
            mock.patch.object(
                dev_coordinator, "_runtime_docker_identity", return_value=identity
            ),
            mock.patch.object(
                dev_coordinator,
                "_runtime_inspect_container_state",
                side_effect=["running", "exited"],
            ),
            mock.patch.object(
                dev_coordinator,
                "coordinated_run_docker",
                return_value={"returncode": 0},
            ),
        ):
            not_removed = dev_coordinator.coordinated_runtime_cleanup(
                request, [resource("removed")]
            )
        self.assertFalse(not_removed["ok"])
        self.assertEqual(not_removed["state"], "exited")
        with (
            mock.patch.object(
                dev_coordinator, "_runtime_docker_identity", return_value=identity
            ),
            mock.patch.object(
                dev_coordinator,
                "_runtime_inspect_container_state",
                side_effect=["absent", "absent"],
            ),
        ):
            removed = dev_coordinator.coordinated_runtime_cleanup(
                request, [resource("removed")]
            )
        self.assertTrue(removed["ok"])
        self.assertEqual(removed["state"], "removed")

    def test_runtime_command_bounds_output_redacts_secrets_and_kills_timeout_group(self) -> None:
        secret = "runner-secret-value"
        log_root = self.root / "runtime-logs"
        request = validate_runtime_request(
            self.request(
                action="run",
                purpose="test",
                ttl_seconds=10,
                kill_after_run=True,
                target={"kind": "service", "id": "service-id", "name": "web"},
                options={
                    "argv": ["/usr/bin/true"],
                    "run_argv": [
                        sys.executable,
                        "-c",
                        (
                            "import os,sys; "
                            "sys.stdout.buffer.write(os.environ['SECRET'].encode()+b'X'*(9*1024*1024))"
                        ),
                    ],
                    "run_env": {"SECRET": secret},
                    "run_timeout_seconds": 5,
                },
            )
        )
        with mock.patch.object(dev_coordinator, "logs_dir", return_value=log_root):
            result = dev_coordinator._runtime_run_command(
                request, str(self.repository), str(uuid.uuid4())
            )
            log = Path(result["log_path"]).read_bytes()
            self.assertNotIn(secret.encode(), log)
            self.assertLessEqual(result["log_bytes"], 8 * 1024 * 1024)
            self.assertGreater(result["discarded_log_bytes"], 0)

            timeout_request = validate_runtime_request(
                self.request(
                    action="run",
                    purpose="test",
                    ttl_seconds=10,
                    kill_after_run=True,
                    target={"kind": "service", "id": "service-id", "name": "web"},
                    options={
                        "argv": ["/usr/bin/true"],
                        "run_argv": [
                            sys.executable,
                            "-c",
                            "import time; time.sleep(30)",
                        ],
                        "run_timeout_seconds": 0.2,
                    },
                )
            )
            with self.assertRaises(
                dev_coordinator.StructuredCoordinatorError
            ) as timed_out:
                dev_coordinator._runtime_run_command(
                    timeout_request, str(self.repository), str(uuid.uuid4())
                )
        classification = timed_out.exception.payload["classification"]
        self.assertIn(classification, {"timeout", "reconciliation_required"})
        if classification == "timeout":
            self.assertTrue(
                timed_out.exception.payload["process_group_cleanup"]["signals_sent"]
            )
        else:
            self.assertEqual(
                timed_out.exception.payload["code"],
                "runtime_test_cleanup_failed",
            )
            self.assertTrue(
                timed_out.exception.payload["direct_process_cleanup"],
                timed_out.exception.payload,
            )

    def test_runtime_cli_failure_is_compact_and_nonzero_with_and_without_optimization(self) -> None:
        script = (
            "from unittest import mock\n"
            "import dev_coordinator\n"
            "with mock.patch.object(dev_coordinator, 'handle_cli', return_value={'ok':False,'classification':'fixture'}):\n"
            " raise SystemExit(dev_coordinator.main(['runtime','--request-json','{}']))\n"
        )
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(Path(dev_coordinator.__file__).parent)
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend(["-c", script])
            completed = subprocess.run(
                command,
                cwd=str(self.repository),
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(completed.returncode, 1, completed.stderr)
            self.assertEqual(
                completed.stdout.strip(),
                '{"classification":"fixture","ok":false}',
            )

    def test_runtime_cli_invalid_request_uses_compact_typed_envelope(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(Path(dev_coordinator.__file__).parent)
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend(
                [
                    str(Path(dev_coordinator.__file__)),
                    "runtime",
                    "--request-json",
                    "{}",
                ]
            )
            completed = subprocess.run(
                command,
                cwd=str(self.repository),
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(completed.returncode, 1, completed.stderr)
            self.assertEqual(completed.stderr, "")
            envelope = json.loads(completed.stdout)
            self.assertEqual(envelope["classification"], "invalid_request")
            self.assertFalse(envelope["ok"])
            self.assertEqual(envelope["error_type"], "RuntimeRequestError")
            self.assertIsNone(envelope["action"])
            self.assertIsNone(envelope["target"])
            self.assertEqual(
                envelope["repository"],
                {"root_repo": None, "temporary_repo": None},
            )
            self.assertNotIn("\n", completed.stdout.strip())

    def test_polymorphic_runtime_links_must_match_session_repository(self) -> None:
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            _host_id, repo_id = self._insert_repository(store)
            other = self.root / "other-repository"
            other.mkdir()
            timestamp = "2026-01-01T00:00:00Z"
            host_id = store.ensure_local_host()
            other_id = deterministic_id("repository", host_id, str(other))
            server_id = deterministic_id("server-definition", other_id, "foreign")
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (?, ?, ?, 'other', 'active', 0, ?, ?)
                    """,
                    (other_id, host_id, str(other), timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO server_definitions(
                        server_definition_id, repo_id, name, cwd,
                        definition_fingerprint, generation, created_at, updated_at
                    ) VALUES (?, ?, 'foreign', ?, 'definition', 0, ?, ?)
                    """,
                    (server_id, other_id, str(other), timestamp, timestamp),
                )
            session_id = create_runtime_session(
                store,
                family_id=repo_id,
                root_repo_id=repo_id,
                repo_id=repo_id,
                request=validate_runtime_request(self.request()),
                timestamp=timestamp,
            )
            with self.assertRaises(StoreInvariantError) as rejected:
                link_runtime_resource(
                    store,
                    session_id=session_id,
                    resource_kind="service",
                    resource_id=server_id,
                    cleanup_disposition="retained",
                    identity={"generation": 0},
                    timestamp=timestamp,
                )
            codes = {item.code for item in rejected.exception.violations}
            link_runtime_resource(
                store,
                session_id=session_id,
                resource_kind="service",
                resource_id=server_id,
                cleanup_disposition="retained",
                identity={"state": "reserved", "expected_generation": 0},
                timestamp=timestamp,
            )
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE runtime_session_resources
                    SET identity_json = '{"generation":0}',
                        cleanup_state = 'removed'
                    WHERE session_id = ?
                    """,
                    (session_id,),
                )
            with store.read_transaction() as connection:
                control_codes = {
                    item.code for item in invariant_violations(connection)
                }
        self.assertIn("runtime_service_resource_scope_mismatch", codes)
        self.assertNotIn(
            "runtime_service_resource_scope_mismatch", control_codes
        )

    def test_exact_docker_and_database_captures_survive_removed_targets(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"CODEX_AGENT_COORDINATOR_HOME": str(self.home)},
        ):
            with AccountStore.open_default(
                self.home, effective_uid=os.geteuid()
            ) as store:
                host_id, repo_id = self._insert_repository(store)
                docker_id, database_id = self._insert_docker_database(
                    store,
                    repo_id=repo_id,
                    host_id=host_id,
                    lifecycle="stopped",
                    database_available=False,
                )
            for kind, resource_id in (
                ("docker", docker_id),
                ("database_stack", database_id),
            ):
                request = validate_runtime_request(
                    self.request(
                        action="status",
                        target={"kind": kind, "id": resource_id},
                        options={},
                    )
                )
                with mock.patch.object(
                    dev_coordinator,
                    "_runtime_read_exact_docker_logs",
                    return_value=(
                        b"worker crashed password=fixture-secret\n",
                        0,
                    ),
                ):
                    capture = dev_coordinator.coordinated_runtime_capture_logs(
                        request, str(self.repository)
                    )
                self.assertEqual(capture["availability"], "available")
                artifact = dev_coordinator.coordinated_runtime_artifact(
                    resource_kind=kind,
                    resource_id=capture["artifact_id"],
                )
                self.assertNotIn("fixture-secret", artifact["text"])
                self.assertIn("password=[REDACTED]", artifact["text"])

                removed = dev_coordinator.StructuredCoordinatorError(
                    "exact Docker log target is no longer available",
                    {
                        "code": "runtime_log_target_removed",
                        "classification": "resource_removed",
                    },
                )
                with mock.patch.object(
                    dev_coordinator,
                    "_runtime_read_exact_docker_logs",
                    side_effect=removed,
                ):
                    retained = dev_coordinator.coordinated_runtime_capture_logs(
                        request, str(self.repository)
                    )
                self.assertEqual(retained["artifact_id"], capture["artifact_id"])
                self.assertTrue(retained["retained"])

    def test_capture_missing_docker_and_identity_change_fail_without_artifact(self) -> None:
        identity = {
            "docker_resource_id": "docker-resource",
            "full_container_id": "a" * 64,
            "immutable_fingerprint": "sha256:" + "1" * 64,
        }
        request = validate_runtime_request(
            self.request(
                action="status",
                target={
                    "kind": "docker",
                    "id": "11111111-1111-4111-8111-111111111111",
                },
                options={},
            )
        )
        self.home.mkdir(mode=0o700)
        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_AGENT_COORDINATOR_HOME": str(self.home)},
            ),
            mock.patch.object(
                dev_coordinator, "_runtime_docker_identity", return_value=identity
            ),
            mock.patch.object(
                dev_coordinator,
                "_runtime_read_exact_docker_logs",
                side_effect=dev_coordinator.DockerCapabilityError(
                    "Docker CLI unavailable",
                    {
                        "code": "docker_cli_unavailable",
                        "classification": "missing_dependency",
                    },
                ),
            ),
        ):
            unavailable = dev_coordinator.coordinated_runtime_capture_logs(
                request, str(self.repository)
            )
        self.assertEqual(unavailable["availability"], "unavailable")
        self.assertEqual(unavailable["reason_code"], "docker_cli_unavailable")

        changed = {**identity, "full_container_id": "b" * 64}
        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_AGENT_COORDINATOR_HOME": str(self.home)},
            ),
            mock.patch.object(
                dev_coordinator,
                "_runtime_docker_identity",
                side_effect=[identity, changed],
            ),
            mock.patch.object(
                dev_coordinator,
                "_runtime_read_exact_docker_logs",
                return_value=(b"must-not-publish\n", 0),
            ),
        ):
            mismatch = dev_coordinator.coordinated_runtime_capture_logs(
                request, str(self.repository)
            )
        self.assertEqual(mismatch["availability"], "unavailable")
        self.assertEqual(
            mismatch["reason_code"], "runtime_resource_identity_changed"
        )

    def test_runtime_and_artifact_routes_share_the_bearer_boundary(self) -> None:
        server = dev_coordinator.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0), dev_coordinator.ApiHandler, token="runtime-token"
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = int(server.server_address[1])

        def request(
            method: str,
            path: str,
            *,
            token: str | None,
            payload: dict[str, object] | None = None,
        ) -> tuple[int, object]:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            body = None if payload is None else json.dumps(payload)
            headers: dict[str, str] = {}
            if token is not None:
                headers["Authorization"] = f"Bearer {token}"
            if body is not None:
                headers["Content-Type"] = "application/json"
            try:
                connection.request(method, path, body=body, headers=headers)
                response = connection.getresponse()
                raw = response.read()
                if (response.getheader("Content-Type") or "").startswith(
                    "application/json"
                ):
                    decoded: object = json.loads(raw.decode("utf-8"))
                else:
                    decoded = raw.decode("utf-8")
                return response.status, decoded
            finally:
                connection.close()

        try:
            server.runtime_cleanup_owner_available = True
            with (
                mock.patch.object(
                    dev_coordinator,
                    "coordinated_runtime_request",
                    return_value={
                        "schema_version": 1,
                        "ok": False,
                        "classification": "unclassified_resource",
                        "error": "fixture",
                    },
                ) as runtime_request,
                mock.patch.object(
                    dev_coordinator,
                    "coordinated_runtime_artifact",
                    return_value={"path": "/private/fixture.log", "text": "fixture"},
                ),
            ):
                status, _body = request(
                    "POST", "/v1/runtime", token=None, payload={}
                )
                self.assertEqual(status, 401)
                status, body = request(
                    "POST", "/v1/runtime", token="runtime-token", payload={}
                )
                self.assertEqual(status, 409)
                self.assertIsInstance(body, dict)
                self.assertFalse(body["ok"])
                self.assertTrue(
                    runtime_request.call_args.kwargs["cleanup_owner_available"]
                )
                status, body = request(
                    "GET",
                    "/v1/runtime/artifacts/service/fixture-id",
                    token="runtime-token",
                )
                self.assertEqual(status, 200)
                self.assertEqual(body, "fixture")
                status, body = request(
                    "GET",
                    "/v1/runtime/artifacts/docker/11111111-1111-4111-8111-111111111111",
                    token="runtime-token",
                )
                self.assertEqual(status, 200)
                self.assertEqual(body, "fixture")
                status, _body = request(
                    "GET",
                    "/v1/runtime/artifacts/diagnostic/fixture-id",
                    token=None,
                )
                self.assertEqual(status, 401)
                status, _body = request(
                    "POST",
                    "/v1/runtime/artifacts/diagnostic/fixture-id",
                    token="runtime-token",
                    payload={},
                )
                self.assertEqual(status, 405)
                status, _body = request(
                    "GET",
                    "/v1/runtime/artifacts/diagnostic",
                    token="runtime-token",
                )
                self.assertEqual(status, 400)
            with mock.patch.object(
                dev_coordinator,
                "coordinated_runtime_artifact",
                side_effect=KeyError("missing artifact"),
            ):
                status, _body = request(
                    "GET",
                    "/v1/runtime/artifacts/diagnostic/00000000-0000-0000-0000-000000000000",
                    token="runtime-token",
                )
                self.assertEqual(status, 404)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
