from __future__ import annotations

import ast
import http.client
import inspect
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock

import dev_coordinator
from devcoordinator import store as store_module

from devcoordinator.normalized_server_lifecycle import (
    NormalizedLifecycleConflict,
    NormalizedPortLifecycle,
    NormalizedServerLifecycle,
    PortLeaseRequest,
    ServerStartRequest,
)
from devcoordinator.store import AccountStore, deterministic_id, utc_timestamp


class NormalizedPortLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "coordinator"
        self.project = self.root / "project-a"
        self.project.mkdir()
        (self.project / ".git").mkdir()
        self.project_b = self.root / "project-b"
        self.project_b.mkdir()
        (self.project_b / ".git").mkdir()
        self.open_stores: list[AccountStore] = []
        with AccountStore.open_default(self.home, effective_uid=os.geteuid()) as store:
            host_id = store.ensure_local_host()
            self._insert_repository(store, host_id, self.project)
            self._insert_repository(store, host_id, self.project_b)
            timestamp = utc_timestamp()
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE schema_metadata
                    SET authority_mode = 'sqlite', migration_state = 'ready',
                        first_sqlite_mutation_at = ?, updated_at = ?
                    WHERE singleton = 1
                    """,
                    (timestamp, timestamp),
                )

    def tearDown(self) -> None:
        for store in reversed(self.open_stores):
            store.close()
        self.temporary.cleanup()

    @staticmethod
    def _insert_repository(store: AccountStore, host_id: str, root: Path) -> None:
        timestamp = utc_timestamp()
        repo_id = deterministic_id("repository", host_id, str(root))
        with store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO repositories(
                    repo_id, host_id, canonical_root, display_name, state,
                    generation, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'active', 0, ?, ?)
                """,
                (repo_id, host_id, str(root), root.name, timestamp, timestamp),
            )
            connection.execute(
                """
                INSERT INTO repository_installations(
                    repo_id, status, startup_fenced, generation, actor, updated_at
                ) VALUES (?, 'installed', 0, 0, 'test', ?)
                """,
                (repo_id, timestamp),
            )

    def service(self) -> NormalizedPortLifecycle:
        store = AccountStore.open_default(self.home, effective_uid=os.geteuid())
        self.open_stores.append(store)
        return NormalizedPortLifecycle(store)

    def server_service(self) -> NormalizedServerLifecycle:
        store = AccountStore.open_default(self.home, effective_uid=os.geteuid())
        self.open_stores.append(store)
        return NormalizedServerLifecycle(store)

    def start_request(
        self,
        *,
        name: str,
        port_start: int,
        port_end: int,
        preferred: int | None = None,
        explicit_range: bool = False,
    ) -> ServerStartRequest:
        return ServerStartRequest(
            agent="codex-a",
            canonical_project=str(self.project),
            name=name,
            cwd=str(self.project),
            argv=("python3", "-m", "fixture", "--port", "{port}"),
            environment={},
            host="127.0.0.1",
            health_url=None,
            role=None,
            port_start=port_start,
            port_end=port_end,
            preferred=preferred,
            ttl_seconds=60,
            explicit_range=explicit_range,
        )

    def running_server(self, *, name: str, port: int) -> dict[str, object]:
        service = self.server_service()
        reservation = service.reserve_start(
            self.start_request(
                name=name,
                port_start=port,
                port_end=port,
                preferred=port,
                explicit_range=True,
            ),
            observed_available_ports=[port],
        )
        reservation = service.finalize_reserved_start_definition(
            operation_id=str(reservation["operation_id"]),
            server_definition_id=str(reservation["id"]),
            definition_generation=int(reservation["_definition_generation"]),
            argv=("python3", "fixture.py", "--port", str(port)),
            environment={"PORT": str(port), "HOST": "127.0.0.1"},
            health_url=None,
        )
        launched = service.mark_start_launched(
            operation_id=str(reservation["operation_id"]),
            server_definition_id=str(reservation["id"]),
            definition_generation=int(reservation["_definition_generation"]),
            pid=44001,
            log_path=str(self.home / f"{name}.log"),
            process_start_time="fixture-start",
            process_fingerprint=f"sha256:{name}-process",
        )
        return service.commit_start_health(
            operation_id=str(launched["operation_id"]),
            server_definition_id=str(launched["id"]),
            definition_generation=int(launched["_definition_generation"]),
            health={
                "ok": True,
                "pid_alive": True,
                "identity": {"ok": True, "observable": True},
                "classification": "healthy",
            },
        )

    def test_direct_assignment_and_lease_lifecycle_retains_history(self) -> None:
        service = self.service()
        assignment = service.assign(
            agent="codex-a",
            canonical_project=str(self.project),
            name="web",
            port=3210,
        )
        self.assertEqual(assignment["port"], 3210)
        self.assertEqual(service.list_assignments(), [assignment])

        lease = service.lease(
            PortLeaseRequest(
                agent="codex-a",
                canonical_project=str(self.project),
                port_start=3211,
                port_end=3211,
                preferred=3211,
                ttl_seconds=60,
                purpose="manual",
            ),
            port_available=lambda port: port == 3211,
        )
        self.assertEqual(lease["status"], "active")
        self.assertEqual(service.list_leases(), [lease])
        released = service.release(
            agent="codex-a",
            canonical_project=str(self.project),
            lease_id=lease["id"],
        )
        self.assertEqual(released["status"], "released")
        self.assertEqual(service.list_leases(), [])
        released_graph = service.store.inventory_v2()
        self.assertEqual(
            [(row["lease_id"], row["status"]) for row in released_graph["leases"]],
            [(lease["id"], "released")],
        )
        self.assertEqual(released_graph["v1_compatibility"]["leases"], [])

        removed = service.unassign(
            agent="codex-a",
            canonical_project=str(self.project),
            name="web",
        )
        self.assertEqual(removed["status"], "unassigned")
        self.assertEqual(service.list_assignments(), [])
        unassigned_graph = service.store.inventory_v2()
        self.assertEqual(
            [
                (row["assignment_id"], row["status"])
                for row in unassigned_graph["port_assignments"]
            ],
            [(assignment["id"], "inactive")],
        )
        self.assertEqual(
            unassigned_graph["v1_compatibility"]["port_assignments"],
            [],
        )
        with service.store.read_transaction() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT status FROM leases WHERE lease_id = ?", (lease["id"],)
                ).fetchone()[0],
                "released",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT status FROM port_assignments WHERE assignment_id = ?",
                    (assignment["id"],),
                ).fetchone()[0],
                "inactive",
            )

    def test_assignment_projection_tracks_running_and_stopped_server_lifecycle(self) -> None:
        running = self.running_server(name="status-web", port=3212)
        ports = self.service()
        assignment = next(
            item for item in ports.list_assignments() if item["name"] == "status-web"
        )
        self.assertEqual(assignment["server_status"], "running")

        servers = self.server_service()
        reserved = servers.reserve_stop(
            agent="codex-a",
            server_definition_id=str(running["id"]),
            expected_definition_generation=int(running["generation"]),
            expected_observation_fingerprint=running.get("_observation_fingerprint"),
        )
        servers.commit_stop(
            operation_id=str(reserved["operation_id"]),
            server_definition_id=str(running["id"]),
            agent="codex-a",
            reason="projection regression fixture",
            release_port=True,
            stale_lease=False,
            final_health={
                "ok": False,
                "pid_alive": False,
                "identity": {"ok": False, "observable": True},
                "classification": "stopped",
            },
        )
        assignment = next(
            item for item in ports.list_assignments() if item["name"] == "status-web"
        )
        self.assertEqual(assignment["server_status"], "stopped")
        graph_assignment = next(
            item
            for item in ports.store.inventory_v2()["v1_compatibility"]["port_assignments"]
            if item["name"] == "status-web"
        )
        self.assertEqual(graph_assignment["server_status"], "stopped")

    def test_compatibility_usage_projects_only_current_running_samples(self) -> None:
        running = self.running_server(name="metrics-web", port=3213)
        ports = self.service()
        with ports.store.immediate_transaction() as connection:
            definition = connection.execute(
                """
                SELECT d.repo_id, r.host_id, d.updated_at
                FROM server_definitions d JOIN repositories r USING(repo_id)
                WHERE d.server_definition_id = ?
                """,
                (running["id"],),
            ).fetchone()
            self.assertIsNotNone(definition)
            repo_id = str(definition["repo_id"])
            host_id = str(definition["host_id"])
            current_run_boundary = str(definition["updated_at"])

            connection.execute(
                """
                INSERT INTO telemetry_samples(
                    sample_id, host_resource_kind, host_resource_id, sampled_at,
                    cpu_percent, memory_bytes, network_rx_bytes, network_tx_bytes,
                    block_read_bytes, block_write_bytes
                ) VALUES (?, 'server', ?, '2000-01-01T00:00:00Z', 99.0, 99000,
                          NULL, NULL, NULL, NULL)
                """,
                (
                    deterministic_id("telemetry", "stale-server", running["id"]),
                    running["id"],
                ),
            )

        graph = ports.store.inventory_v2()["v1_compatibility"]
        projected_server = next(
            item for item in graph["servers"] if item["id"] == running["id"]
        )
        self.assertNotIn(
            "process_usage",
            projected_server,
            "a running definition must not inherit telemetry from an older run",
        )
        project_usage = next(
            item for item in graph["project_usage"] if item["project"] == str(self.project)
        )
        self.assertIsNone(project_usage["cpu_percent"])
        self.assertIsNone(project_usage["memory_bytes"])

        docker_resource_id = deterministic_id("docker-resource", host_id, "metrics-db")
        with ports.store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO telemetry_samples(
                    sample_id, host_resource_kind, host_resource_id, sampled_at,
                    cpu_percent, memory_bytes, network_rx_bytes, network_tx_bytes,
                    block_read_bytes, block_write_bytes
                ) VALUES (?, 'server', ?, ?, 2.5, 1000, NULL, NULL, NULL, NULL)
                """,
                (
                    deterministic_id("telemetry", "current-server", running["id"]),
                    running["id"],
                    current_run_boundary,
                ),
            )
            engine_id = deterministic_id("docker-engine", host_id, "test")
            connection.execute(
                """
                INSERT INTO docker_engines(
                    engine_id, host_id, context_identity, capability_state,
                    created_at, updated_at
                ) VALUES (?, ?, 'test', 'available', ?, ?)
                """,
                (engine_id, host_id, current_run_boundary, current_run_boundary),
            )
            connection.execute(
                """
                INSERT INTO docker_resources(
                    docker_resource_id, engine_id, full_container_id, current_name,
                    image, created_at, updated_at
                ) VALUES (?, ?, ?, 'metrics-db', 'postgres:test', ?, ?)
                """,
                (
                    docker_resource_id,
                    engine_id,
                    "a" * 64,
                    current_run_boundary,
                    current_run_boundary,
                ),
            )
            connection.execute(
                """
                INSERT INTO docker_observations(
                    docker_resource_id, lifecycle, health, restart_policy,
                    ports_fingerprint, labels_fingerprint, sampled_at,
                    observation_fingerprint
                ) VALUES (?, 'running', 'healthy', 'no', 'ports', 'labels', ?, 'observation')
                """,
                (docker_resource_id, current_run_boundary),
            )
            connection.execute(
                """
                INSERT INTO repository_memberships(
                    membership_id, repo_id, resource_kind, host_resource_id,
                    immutable_fingerprint, control_binding_id, created_at
                ) VALUES (?, ?, 'container', ?, 'container-identity', NULL, ?)
                """,
                (
                    deterministic_id("membership", repo_id, docker_resource_id),
                    repo_id,
                    docker_resource_id,
                    current_run_boundary,
                ),
            )
            connection.execute(
                """
                INSERT INTO telemetry_samples(
                    sample_id, host_resource_kind, host_resource_id, sampled_at,
                    cpu_percent, memory_bytes, network_rx_bytes, network_tx_bytes,
                    block_read_bytes, block_write_bytes
                ) VALUES (?, 'docker', ?, ?, 1.25, 500, NULL, NULL, NULL, NULL)
                """,
                (
                    deterministic_id("telemetry", "docker", docker_resource_id),
                    docker_resource_id,
                    current_run_boundary,
                ),
            )

        graph = ports.store.inventory_v2()["v1_compatibility"]
        projected_server = next(
            item for item in graph["servers"] if item["id"] == running["id"]
        )
        self.assertEqual(
            projected_server["process_usage"],
            {
                "source": "normalized_observation",
                "sampled_at": current_run_boundary,
                "cpu_percent": 2.5,
                "memory_bytes": 1000,
                "rss_bytes": 1000,
            },
        )
        project_usage = next(
            item for item in graph["project_usage"] if item["project"] == str(self.project)
        )
        self.assertEqual(project_usage["cpu_percent"], 3.75)
        self.assertEqual(project_usage["memory_bytes"], 1500)
        self.assertIsNone(project_usage["process_count"])

        with ports.store.immediate_transaction() as connection:
            connection.execute(
                """
                UPDATE server_definitions
                SET generation = generation + 1, updated_at = '9999-01-01T00:00:00Z'
                WHERE server_definition_id = ?
                """,
                (running["id"],),
            )
        graph = ports.store.inventory_v2()["v1_compatibility"]
        projected_server = next(
            item for item in graph["servers"] if item["id"] == running["id"]
        )
        self.assertNotIn(
            "process_usage",
            projected_server,
            "advancing the definition generation must fence the prior run sample",
        )
        project_usage = next(
            item for item in graph["project_usage"] if item["project"] == str(self.project)
        )
        self.assertEqual(project_usage["cpu_percent"], 1.25)
        self.assertEqual(project_usage["memory_bytes"], 500)

    def test_compatibility_docker_capability_ignores_legacy_import_placeholder(self) -> None:
        ports = self.service()
        timestamp = "2026-07-15T12:00:00Z"
        with ports.store.immediate_transaction() as connection:
            host_id = str(
                connection.execute("SELECT host_id FROM hosts LIMIT 1").fetchone()[0]
            )
            # Legacy import records an explicitly unobserved placeholder.  A
            # fresh normalized observation can land in the same whole-second
            # timestamp, so insertion order must not let that placeholder
            # override the measured default engine capability.
            connection.execute(
                """
                INSERT INTO docker_engines(
                    engine_id, host_id, context_identity, capability_state,
                    created_at, updated_at
                ) VALUES ('legacy-placeholder', ?, 'legacy-default', 'unobserved', ?, ?)
                """,
                (host_id, timestamp, timestamp),
            )
            connection.execute(
                """
                INSERT INTO docker_engines(
                    engine_id, host_id, context_identity, capability_state,
                    created_at, updated_at
                ) VALUES ('measured-default', ?, 'default', 'available', ?, ?)
                """,
                (host_id, timestamp, timestamp),
            )

        self.assertIs(
            ports.store.inventory_v2()["v1_compatibility"]["docker"]["available"],
            True,
            "a same-timestamp legacy placeholder must not mask fresh Docker evidence",
        )

        with ports.store.immediate_transaction() as connection:
            connection.execute("DELETE FROM docker_engines WHERE context_identity = 'default'")
        self.assertIsNone(
            ports.store.inventory_v2()["v1_compatibility"]["docker"]["available"],
            "legacy metadata alone is unobserved, not proof that Docker is unavailable",
        )

        with ports.store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO docker_engines(
                    engine_id, host_id, context_identity, capability_state,
                    created_at, updated_at
                ) VALUES ('measured-default', ?, 'default', 'unavailable', ?, ?)
                """,
                (host_id, timestamp, timestamp),
            )
        self.assertIs(
            ports.store.inventory_v2()["v1_compatibility"]["docker"]["available"],
            False,
            "a measured unavailable default engine must remain an unavailable state",
        )

    def test_foreign_assignment_and_release_are_rejected_without_mutation(self) -> None:
        service = self.service()
        assignment = service.assign(
            agent="codex-a",
            canonical_project=str(self.project),
            name="web",
            port=3220,
        )
        with self.assertRaisesRegex(NormalizedLifecycleConflict, "durably assigned"):
            service.assign(
                agent="codex-b",
                canonical_project=str(self.project_b),
                name="api",
                port=3220,
            )
        lease = service.lease(
            PortLeaseRequest(
                agent="codex-a",
                canonical_project=str(self.project),
                port_start=3221,
                port_end=3221,
                preferred=3221,
                ttl_seconds=60,
                purpose="manual",
            ),
            port_available=lambda _port: True,
        )
        with self.assertRaises(PermissionError):
            service.release(
                agent="codex-b",
                canonical_project=str(self.project_b),
                lease_id=lease["id"],
            )
        self.assertEqual(service.list_assignments(), [assignment])
        self.assertEqual(service.list_leases(), [lease])

    def test_concurrent_exact_port_lease_has_one_winner(self) -> None:
        reached_probe = threading.Barrier(2)
        results: list[dict[str, object]] = []
        errors: list[BaseException] = []
        lock = threading.Lock()

        def worker(agent: str) -> None:
            try:
                with AccountStore.open_default(
                    self.home, effective_uid=os.geteuid()
                ) as store:
                    service = NormalizedPortLifecycle(store)

                    def available(_port: int) -> bool:
                        reached_probe.wait(timeout=5)
                        return True

                    result = service.lease(
                        PortLeaseRequest(
                            agent=agent,
                            canonical_project=str(self.project),
                            port_start=3230,
                            port_end=3230,
                            preferred=3230,
                            ttl_seconds=60,
                            purpose="manual",
                        ),
                        port_available=available,
                    )
                with lock:
                    results.append(result)
            except BaseException as error:  # retained for diagnostic timeout/failure output
                with lock:
                    errors.append(error)

        threads = [threading.Thread(target=worker, args=(name,)) for name in ("a", "b")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertTrue(all(not thread.is_alive() for thread in threads), errors)
        self.assertEqual(len(results), 1, errors)
        self.assertEqual(len(errors), 1)
        self.assertRegex(str(errors[0]), "no free port available")
        self.assertEqual(results[0]["port"], 3230)

    def test_default_public_port_commands_never_load_legacy_projection(self) -> None:
        def command(*arguments: str) -> object:
            return dev_coordinator.handle_cli(
                dev_coordinator.build_parser().parse_args(list(arguments))
            )

        environment = {
            "CODEX_AGENT_COORDINATOR_HOME": str(self.home),
            "DEVCOORDINATOR_STATE_BACKEND": "sqlite",
        }

        def poisoned_locked_state() -> object:
            raise AssertionError("default port command reached locked_state")

        with (
            mock.patch.dict(os.environ, environment),
            mock.patch.object(
                dev_coordinator, "configured_broker_context", return_value=None
            ),
            mock.patch.object(dev_coordinator, "port_available", return_value=True),
            mock.patch.object(
                dev_coordinator, "locked_state", side_effect=poisoned_locked_state
            ),
        ):
            assignment = command(
                "port",
                "assign",
                "--agent",
                "codex-a",
                "--project",
                str(self.project),
                "--name",
                "web",
                "--port",
                "3240",
            )
            self.assertEqual(assignment["port"], 3240)
            self.assertEqual(command("port", "assignments"), [assignment])

            lease = command(
                "port",
                "lease",
                "--agent",
                "codex-a",
                "--project",
                str(self.project),
                "--range",
                "3241-3241",
                "--preferred",
                "3241",
            )
            self.assertEqual(command("port", "list"), [lease])
            self.assertIn(lease["id"], command("state", "show")["leases"])

            released = command(
                "port",
                "release",
                "--agent",
                "codex-a",
                "--project",
                str(self.project),
                "--lease-id",
                lease["id"],
            )
            self.assertEqual(released["status"], "released")
            removed = command(
                "port",
                "unassign",
                "--agent",
                "codex-a",
                "--project",
                str(self.project),
                "--name",
                "web",
            )
            self.assertEqual(removed["status"], "unassigned")
            self.assertEqual(command("port", "list"), [])
            self.assertEqual(command("port", "assignments"), [])

            foreign = command(
                "port",
                "assign",
                "--agent",
                "codex-a",
                "--project",
                str(self.project),
                "--name",
                "foreign-web",
                "--port",
                "3242",
            )
            with self.assertRaisesRegex(PermissionError, "--force"):
                command(
                    "port",
                    "unassign",
                    "--agent",
                    "codex-b",
                    "--project",
                    str(self.project_b),
                    "--port",
                    str(foreign["port"]),
                )
            forced = command(
                "port",
                "unassign",
                "--agent",
                "codex-b",
                "--project",
                str(self.project_b),
                "--port",
                str(foreign["port"]),
                "--force",
            )
            self.assertEqual(forced["status"], "unassigned")

    def test_locked_state_is_legacy_only_and_has_no_sqlite_projection(self) -> None:
        source = inspect.getsource(dev_coordinator.locked_state)
        self.assertNotIn("load_legacy_state_projection", source)
        self.assertNotIn("replace_legacy_state_projection", source)

        with mock.patch.dict(
            os.environ,
            {
                "CODEX_AGENT_COORDINATOR_HOME": str(self.home),
                "DEVCOORDINATOR_STATE_BACKEND": "sqlite",
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "disabled for the SQLite"):
                with dev_coordinator.locked_state():
                    self.fail("SQLite must never yield a legacy state projection")
            self.assertFalse(
                (self.home / "state.lock").exists(),
                "the SQLite backend must not create the legacy state lock",
            )

        legacy_home = self.root / "legacy-only"
        with mock.patch.dict(
            os.environ,
            {
                "CODEX_AGENT_COORDINATOR_HOME": str(legacy_home),
                "DEVCOORDINATOR_STATE_BACKEND": dev_coordinator.LEGACY_JSON_BACKEND,
            },
        ):
            with dev_coordinator.locked_state() as state:
                self.assertEqual(state["version"], dev_coordinator.VERSION)
            self.assertTrue((legacy_home / "state.lock").is_file())

    def test_default_runtime_source_has_no_legacy_projection_calls(self) -> None:
        source_path = Path(dev_coordinator.__file__).resolve()
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent

        def enclosing_function(node: ast.AST) -> str:
            current = node
            while current in parents:
                current = parents[current]
                if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return current.name
            return "<module>"

        forbidden = []
        legacy_gateway_calls: dict[str, dict[str, int]] = {
            "locked_state": {},
            "read_state": {},
            "write_state": {},
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            if isinstance(function, ast.Attribute) and function.attr in {
                "load_legacy_state_projection",
                "replace_legacy_state_projection",
            }:
                forbidden.append((node.lineno, function.attr))
            if isinstance(function, ast.Name) and function.id in legacy_gateway_calls:
                owner = enclosing_function(node)
                calls = legacy_gateway_calls[function.id]
                calls[owner] = calls.get(owner, 0) + 1
        self.assertEqual(
            forbidden,
            [],
            "the product dispatcher must not invoke the migration-only projection",
        )
        # This exact inventory is intentionally strict. A new compatibility
        # lock/read/write call must fail review until its public route is added
        # to the poisoned CLI/API matrices below or the call is removed. It
        # prevents a new default fallback from hiding inside an existing large
        # dispatcher while preserving the explicit legacy-json test bridge.
        self.assertEqual(
            legacy_gateway_calls,
            {
                "locked_state": {
                    "_coordinated_register_server_local": 3,
                    "_coordinated_start_server_local": 6,
                    "begin_project_operation": 1,
                    "commit_runtime_observations": 1,
                    "coordinated_assign_port": 3,
                    "coordinated_lease_port": 3,
                    "coordinated_reclaim_runtime_port": 1,
                    "coordinated_register_docker_metadata": 3,
                    "coordinated_register_server": 1,
                    "coordinated_release_port": 2,
                    "coordinated_relocate_port_assignment": 1,
                    "coordinated_restart_server": 4,
                    "coordinated_run_docker": 6,
                    "coordinated_sample_docker_stats": 1,
                    "coordinated_start_server": 2,
                    "coordinated_start_server_with_lease": 4,
                    "coordinated_stop_server": 5,
                    "coordinated_unassign_port": 2,
                    "finalize_manual_lease_start_failure": 1,
                    "finish_project_operation": 1,
                    "handle_cli": 2,
                    "record_project_status_evidence": 1,
                    "snapshot_coordinator_state": 1,
                    "snapshot_runtime_observation": 1,
                },
                "read_state": {"locked_state": 1},
                "write_state": {"locked_state": 1},
            },
            "legacy compatibility gateway inventory changed; prove the affected "
            "default CLI/API route still fails before reaching it",
        )
        sampler_source = inspect.getsource(
            dev_coordinator.sample_host_inventory_for_normalized_store
        )
        self.assertNotIn("legacy_state_projection", sampler_source)

        expected_post_routes = {
            "/v1/servers/start",
            "/v1/servers/stop",
            "/v1/servers/restart",
            "/v1/servers/register",
            "/v1/servers/status",
            "/v1/servers/logs",
            "/v1/projects/status",
            "/v1/projects/start",
            "/v1/projects/restart",
            "/v1/projects/stop",
            "/v1/docker/stats",
            "/v1/docker/register",
            "/v1/docker/ps",
            "/v1/docker/compose-up",
            "/v1/docker/compose-down",
            "/v1/docker/logs",
            "/v1/docker/start",
            "/v1/docker/stop",
            "/v1/docker/restart",
            "/v1/ports/lease",
            "/v1/ports/release",
            "/v1/ports/assign",
            "/v1/ports/unassign",
            "/v1/ports/relocate",
        }
        self.assertEqual(
            set(dev_coordinator.API_GET_ROUTES),
            {
                "/v1/inventory",
                "/v1/inventory/no-docker",
                "/v1/state",
                "/v1/ports",
                "/v1/ports/assignments",
                "/v1/servers",
            },
        )
        self.assertEqual(set(dev_coordinator.API_POST_ROUTES), expected_post_routes)

        parser = dev_coordinator.build_parser()
        group_action = next(
            action for action in parser._actions if action.dest == "group"
        )
        group_choices = group_action.choices

        def cli_actions(group: str) -> set[str]:
            action = next(
                item
                for item in group_choices[group]._actions
                if item.dest == "action"
            )
            return set(action.choices)

        # Keep the poisoned command matrices exhaustive. Adding a direct
        # product subcommand must update both this inventory and the exercised
        # route matrix, rather than silently reintroducing a compatibility
        # fallback through an untested dispatcher branch.
        self.assertEqual(cli_actions("state"), {"show", "reset"})
        self.assertEqual(
            cli_actions("port"),
            {"lease", "release", "list", "assign", "relocate", "unassign", "assignments"},
        )
        self.assertEqual(
            cli_actions("server"),
            {"start", "register", "stop", "restart", "status", "logs", "list"},
        )
        self.assertEqual(
            cli_actions("project"), {"status", "start", "restart", "stop"}
        )
        self.assertEqual(
            cli_actions("docker"),
            {
                "stats",
                "ps",
                "compose-up",
                "compose-down",
                "logs",
                "start",
                "stop",
                "restart",
                "register",
            },
        )

    def test_default_observe_project_and_docker_cli_matrix_is_projection_free(
        self,
    ) -> None:
        def command(*arguments: str) -> object:
            return dev_coordinator.handle_cli(
                dev_coordinator.build_parser().parse_args(list(arguments))
            )

        def poisoned_legacy(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("default dispatcher reached legacy state")

        def docker_probe(
            arguments: list[str], *, cwd: str | None = None
        ) -> dict[str, object]:
            if arguments and arguments[0] == "stats":
                return {
                    "ok": True,
                    "returncode": 0,
                    "stdout": json.dumps(
                        {
                            "ID": "abcdef123456",
                            "Container": "abcdef123456",
                            "Name": "fixture",
                            "CPUPerc": "1.0%",
                            "MemUsage": "1MiB / 2MiB",
                            "MemPerc": "50%",
                            "NetIO": "1kB / 2kB",
                            "BlockIO": "3kB / 4kB",
                            "PIDs": "1",
                        }
                    ),
                    "stderr": "",
                    "cwd": cwd,
                }
            return {"ok": False, "error": "fixture Docker unavailable", "cwd": cwd}

        environment = {
            "CODEX_AGENT_COORDINATOR_HOME": str(self.home),
            "DEVCOORDINATOR_STATE_BACKEND": "sqlite",
        }
        with (
            mock.patch.dict(os.environ, environment),
            mock.patch.object(
                dev_coordinator, "configured_broker_context", return_value=None
            ),
            mock.patch.object(
                dev_coordinator, "locked_state", side_effect=poisoned_legacy
            ),
            mock.patch.object(
                AccountStore,
                "load_legacy_state_projection",
                side_effect=poisoned_legacy,
            ),
            mock.patch.object(
                AccountStore,
                "replace_legacy_state_projection",
                side_effect=poisoned_legacy,
            ),
            mock.patch.object(
                dev_coordinator, "docker_available_command", side_effect=docker_probe
            ),
        ):
            observed = command(
                "observe",
                "--agent",
                "codex-a",
                "--project",
                str(self.project),
                "--no-docker",
                "--legacy-home",
                str(self.root / "missing-legacy-home"),
            )
            self.assertEqual(observed["status"], "completed")
            self.assertTrue(observed["observed"])

            inventory = command(
                "inventory", "--project", str(self.project), "--no-docker"
            )
            self.assertEqual(inventory["store"]["authority_mode"], "sqlite")
            self.assertIn("servers", command("state", "show"))

            status = command(
                "project", "status", "--project", str(self.project)
            )
            self.assertEqual(status["project"], str(self.project))
            for action in ("start", "restart", "stop"):
                report = command(
                    "project",
                    action,
                    "--agent",
                    "codex-a",
                    "--project",
                    str(self.project),
                    "--dry-run",
                )
                self.assertEqual(report["project"], str(self.project))

            self.assertTrue(command("docker", "ps", "--dry-run")["dry_run"])
            stats = command("docker", "stats")
            self.assertTrue(stats["available"])
            self.assertEqual(stats["persisted_samples"], 0)
            registration = command(
                "docker",
                "register",
                "--container",
                "fixture",
                "--agent",
                "codex-a",
                "--project",
                str(self.project),
                "--dry-run",
            )
            self.assertEqual(
                registration["metadata_source"],
                "planned_normalized_observation",
            )
            for action in ("start", "stop", "restart"):
                result = command(
                    "docker",
                    action,
                    "--container",
                    "fixture",
                    "--agent",
                    "codex-a",
                    "--project",
                    str(self.project),
                    "--dry-run",
                )
                self.assertTrue(result["dry_run"])
            for action in ("compose-up", "compose-down"):
                result = command(
                    "docker",
                    action,
                    "--cwd",
                    str(self.project),
                    "--agent",
                    "codex-a",
                    "--project",
                    str(self.project),
                    "--dry-run",
                )
                self.assertTrue(result["dry_run"])
            self.assertTrue(
                command(
                    "docker",
                    "logs",
                    "--container",
                    "fixture",
                    "--dry-run",
                )["dry_run"]
            )
            with self.assertRaisesRegex(RuntimeError, "legacy-json-test-only"):
                command(
                    "state",
                    "reset",
                    "--force",
                    "--agent",
                    "codex-a",
                    "--project",
                    str(self.project),
                )

    def test_sqlite_first_open_retries_only_busy_failures(self) -> None:
        attempts = 0

        def locked_once() -> str:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise sqlite3.OperationalError("database is locked")
            return "wal"

        self.assertEqual(
            store_module._retry_sqlite_busy(locked_once, timeout_ms=100),
            "wal",
        )
        self.assertEqual(attempts, 2)

        nonbusy_attempts = 0

        def unrelated_failure() -> None:
            nonlocal nonbusy_attempts
            nonbusy_attempts += 1
            raise sqlite3.OperationalError("malformed database schema")

        with self.assertRaisesRegex(sqlite3.OperationalError, "malformed"):
            store_module._retry_sqlite_busy(unrelated_failure, timeout_ms=100)
        self.assertEqual(nonbusy_attempts, 1)

        exhausted_attempts = 0

        def always_locked() -> None:
            nonlocal exhausted_attempts
            exhausted_attempts += 1
            raise sqlite3.OperationalError("database is locked")

        with (
            mock.patch.object(
                store_module.time,
                "monotonic",
                side_effect=(0.0, 0.0, 0.101),
            ),
            mock.patch.object(store_module.time, "sleep") as sleep,
            self.assertRaisesRegex(sqlite3.OperationalError, "locked"),
        ):
            store_module._retry_sqlite_busy(always_locked, timeout_ms=100)
        self.assertEqual(exhausted_attempts, 2)
        sleep.assert_called_once_with(0.01)

    def test_server_start_uses_existing_assignment_when_omitted(self) -> None:
        ports = self.service()
        ports.assign(
            agent="codex-a",
            canonical_project=str(self.project),
            name="web",
            port=3250,
        )
        reservation = self.server_service().reserve_start(
            self.start_request(
                name="web", port_start=3000, port_end=3999
            ),
            observed_available_ports=[3251, 3250],
        )
        self.assertEqual(reservation["port"], 3250)
        self.assertEqual(reservation["assigned_port"], 3250)

    def test_server_start_rejects_squatted_fixed_assignment(self) -> None:
        self.service().assign(
            agent="codex-a",
            canonical_project=str(self.project),
            name="web",
            port=3260,
        )
        with self.assertRaisesRegex(NormalizedLifecycleConflict, "pinned to port 3260"):
            self.server_service().reserve_start(
                self.start_request(
                    name="web", port_start=3000, port_end=3999
                ),
                observed_available_ports=[3261],
            )

    def test_server_start_explicit_range_may_repin(self) -> None:
        ports = self.service()
        ports.assign(
            agent="codex-a",
            canonical_project=str(self.project),
            name="web",
            port=3270,
        )
        reservation = self.server_service().reserve_start(
            self.start_request(
                name="web",
                port_start=3271,
                port_end=3272,
                preferred=3271,
                explicit_range=True,
            ),
            observed_available_ports=[3271, 3272],
        )
        self.assertEqual(reservation["port"], 3271)
        assignment = next(
            item
            for item in ports.list_assignments()
            if item["name"] == "web"
        )
        self.assertEqual(assignment["port"], 3271)

    def test_server_start_without_assignment_uses_first_available_candidate(self) -> None:
        reservation = self.server_service().reserve_start(
            self.start_request(
                name="api",
                port_start=3280,
                port_end=3282,
                preferred=3281,
            ),
            observed_available_ports=[3281, 3280, 3282],
        )
        self.assertEqual(reservation["port"], 3281)

    def test_default_public_server_lifecycle_and_relocation_never_load_legacy_projection(
        self,
    ) -> None:
        def command(*arguments: str) -> object:
            return dev_coordinator.handle_cli(
                dev_coordinator.build_parser().parse_args(list(arguments))
            )

        runtime = {"stopped": False, "pid": 43000}

        def healthy(
            _server: object, *_args: object, **_kwargs: object
        ) -> dict[str, object]:
            if runtime["stopped"]:
                return {
                    "ok": False,
                    "pid_alive": False,
                    "identity": {"ok": True, "observable": True},
                    "check": {"ok": False},
                    "classification": "stopped",
                }
            return {
                "ok": True,
                "pid_alive": True,
                "identity": {"ok": True, "observable": True},
                "check": {"ok": True},
                "classification": "healthy",
            }

        def launch(**_kwargs: object) -> tuple[int, str]:
            runtime["pid"] += 1
            runtime["stopped"] = False
            return int(runtime["pid"]), str(self.home / "server.log")

        def stop(_pid: int) -> None:
            runtime["stopped"] = True

        def poisoned_locked_state() -> object:
            raise AssertionError("default server command reached locked_state")

        environment = {
            "CODEX_AGENT_COORDINATOR_HOME": str(self.home),
            "DEVCOORDINATOR_STATE_BACKEND": "sqlite",
        }
        with (
            mock.patch.dict(os.environ, environment),
            mock.patch.object(
                dev_coordinator, "configured_broker_context", return_value=None
            ),
            mock.patch.object(
                dev_coordinator, "broker_lease_link_for_local", return_value=None
            ),
            mock.patch.object(dev_coordinator, "port_available", return_value=True),
            mock.patch.object(dev_coordinator, "start_process", side_effect=launch),
            mock.patch.object(dev_coordinator, "stop_pid", side_effect=stop),
            mock.patch.object(dev_coordinator, "server_health", side_effect=healthy),
            mock.patch.object(dev_coordinator, "wait_for_health", side_effect=healthy),
            mock.patch.object(
                dev_coordinator,
                "normalized_process_instance_evidence",
                side_effect=lambda **kwargs: (
                    "fixture-start",
                    f"sha256:fixture-{kwargs['pid']}",
                ),
            ),
            mock.patch.object(
                dev_coordinator, "locked_state", side_effect=poisoned_locked_state
            ),
        ):
            started = command(
                "server",
                "start",
                "--agent",
                "codex-a",
                "--project",
                str(self.project),
                "--name",
                "web",
                "--argv",
                '["python3","fixture.py","--port","{port}"]',
                "--range",
                "3290-3290",
                "--preferred",
                "3290",
            )
            self.assertEqual(started["status"], "running")
            self.assertEqual(started["port"], 3290)
            self.assertEqual(command("server", "list")[0]["name"], "web")
            status = command(
                "server",
                "status",
                "--project",
                str(self.project),
                "--name",
                "web",
            )
            self.assertEqual(status["status"], "running")
            logs = command(
                "server",
                "logs",
                "--project",
                str(self.project),
                "--name",
                "web",
            )
            self.assertEqual(logs["server"]["name"], "web")

            restarted = command(
                "server",
                "restart",
                "--agent",
                "codex-a",
                "--project",
                str(self.project),
                "--name",
                "web",
            )
            self.assertEqual(restarted["status"], "running")
            self.assertEqual(restarted["port"], 3290)
            stopped = command(
                "server",
                "stop",
                "--agent",
                "codex-a",
                "--project",
                str(self.project),
                "--name",
                "web",
            )
            self.assertEqual(stopped["status"], "stopped")
            lease_id = str(stopped["lease_id"])

            with mock.patch.object(
                dev_coordinator,
                "listener_evidence_for_port",
                return_value={
                    "present": False,
                    "port": 3290,
                    "pid": None,
                    "proc_listen_socket_count": 0,
                    "loopback_reachable": False,
                },
            ):
                relocated = command(
                    "port",
                    "relocate",
                    "--agent",
                    "codex-a",
                    "--old-project",
                    str(self.project),
                    "--new-project",
                    str(self.project_b),
                    "--name",
                    "web",
                    "--port",
                    "3290",
                    "--lease-id",
                    lease_id,
                )
            self.assertEqual(relocated["new_project"], str(self.project_b))
            self.assertEqual(relocated["project"], str(self.project_b))

            runtime["stopped"] = False
            with (
                mock.patch.object(
                    dev_coordinator,
                    "resolve_registration_pid",
                    return_value=(43050, {"ok": True, "observable": True}),
                ),
                mock.patch.object(
                    dev_coordinator,
                    "registration_pid_identity",
                    return_value={"ok": True, "observable": True},
                ),
            ):
                registered = command(
                    "server",
                    "register",
                    "--agent",
                    "codex-a",
                    "--project",
                    str(self.project),
                    "--name",
                    "adopted",
                    "--port",
                    "3291",
                    "--pid",
                    "43050",
                )
            self.assertEqual(registered["status"], "running")
            self.assertEqual(registered["port"], 3291)

    def test_unobservable_status_preserves_running_lifecycle_and_active_lease(self) -> None:
        running = self.running_server(name="web", port=3300)
        service = self.server_service()
        observed = service.commit_status(
            server_definition_id=str(running["id"]),
            expected_definition_generation=int(running["generation"]),
            expected_observation_fingerprint=running.get(
                "_observation_fingerprint"
            ),
            health={
                "ok": None,
                "pid_alive": True,
                "identity": {
                    "ok": None,
                    "observable": False,
                    "reason": "permission denied",
                },
                "classification": "unverified-listener",
            },
            stopped_reason=None,
        )
        self.assertEqual(observed["status"], "running")
        self.assertEqual(observed["lease_status"], "active")
        self.assertEqual(observed["identity_observable"], False)

    def test_public_status_retries_a_concurrent_observation_cas(self) -> None:
        self.running_server(name="web", port=3305)
        healthy = {
            "ok": True,
            "pid_alive": True,
            "identity": {"ok": True, "observable": True},
            "classification": "healthy",
        }
        original = NormalizedServerLifecycle.commit_status
        calls = 0

        def concurrent_commit(service: NormalizedServerLifecycle, **kwargs: object):
            nonlocal calls
            calls += 1
            if calls == 1:
                changed = dict(kwargs)
                changed["health"] = {
                    "ok": False,
                    "pid_alive": True,
                    "identity": {"ok": True, "observable": True},
                    "classification": "starting",
                }
                original(service, **changed)
            return original(service, **kwargs)

        with (
            mock.patch.dict(
                os.environ,
                {
                    "CODEX_AGENT_COORDINATOR_HOME": str(self.home),
                    "DEVCOORDINATOR_STATE_BACKEND": "sqlite",
                },
            ),
            mock.patch.object(dev_coordinator, "server_health", return_value=healthy),
            mock.patch.object(
                NormalizedServerLifecycle,
                "commit_status",
                autospec=True,
                side_effect=concurrent_commit,
            ),
        ):
            observed = dev_coordinator._coordinated_status_server_normalized(
                {"project": str(self.project), "name": "web"}
            )

        self.assertEqual(calls, 2)
        self.assertEqual(observed["status"], "running")

    def test_unobservable_stop_refuses_before_operation_or_mutation(self) -> None:
        running = self.running_server(name="web", port=3304)
        with AccountStore.open_default(
            self.home, effective_uid=os.geteuid()
        ) as store:
            before_operation_count = int(
                store.connection.execute(
                    "SELECT COUNT(*) FROM operations WHERE kind = 'server.stop'"
                ).fetchone()[0]
            )

        health = {
            "ok": None,
            "pid_alive": True,
            "identity": {
                "ok": None,
                "observable": False,
                "reason": "permission denied",
            },
            "classification": "unverified-listener",
        }
        with (
            mock.patch.dict(
                os.environ,
                {
                    "CODEX_AGENT_COORDINATOR_HOME": str(self.home),
                    "DEVCOORDINATOR_STATE_BACKEND": "sqlite",
                },
            ),
            mock.patch.object(dev_coordinator, "server_health", return_value=health),
            mock.patch.object(dev_coordinator, "prime_git_head_identity"),
            self.assertRaises(dev_coordinator.ListenerIdentityUnobservable),
        ):
            dev_coordinator.coordinated_stop_server(
                {
                    "agent": "codex-a",
                    "project": str(self.project),
                    "name": "web",
                    "release_port": True,
                }
            )

        with AccountStore.open_default(
            self.home, effective_uid=os.geteuid()
        ) as store:
            after_operation_count = int(
                store.connection.execute(
                    "SELECT COUNT(*) FROM operations WHERE kind = 'server.stop'"
                ).fetchone()[0]
            )
            retained = NormalizedServerLifecycle(store).server(
                server_definition_id=str(running["id"])
            )
        self.assertEqual(after_operation_count, before_operation_count)
        self.assertEqual(retained["status"], "running")
        self.assertEqual(retained["lease_status"], "active")
        self.assertEqual(retained["generation"], running["generation"])

    def test_wrong_listener_status_stops_server_and_stales_lease(self) -> None:
        running = self.running_server(name="web", port=3301)
        observed = self.server_service().commit_status(
            server_definition_id=str(running["id"]),
            expected_definition_generation=int(running["generation"]),
            expected_observation_fingerprint=running.get(
                "_observation_fingerprint"
            ),
            health={
                "ok": False,
                "pid_alive": True,
                "identity": {
                    "ok": False,
                    "observable": True,
                    "reason": "listener belongs to another repository",
                },
                "classification": "wrong-listener",
            },
            stopped_reason="listener belongs to another repository",
        )
        self.assertEqual(observed["status"], "stopped")
        self.assertEqual(observed["lease_status"], "stale")
        self.assertIsNone(observed["pid"])

    def test_manual_lease_that_reaches_launch_is_quarantined_after_failure(self) -> None:
        ports = self.service()
        lease = ports.lease(
            PortLeaseRequest(
                agent="codex-a",
                canonical_project=str(self.project),
                port_start=3302,
                port_end=3302,
                preferred=3302,
                ttl_seconds=60,
                purpose="manual",
            ),
            port_available=lambda _port: True,
        )
        service = self.server_service()
        request = self.start_request(
            name="web",
            port_start=3302,
            port_end=3302,
            preferred=3302,
            explicit_range=True,
        )
        request = ServerStartRequest(
            **{
                **request.__dict__,
                "manual_lease_id": lease["id"],
            }
        )
        reservation = service.reserve_start(
            request, observed_available_ports=[3302]
        )
        reservation = service.finalize_reserved_start_definition(
            operation_id=str(reservation["operation_id"]),
            server_definition_id=str(reservation["id"]),
            definition_generation=int(reservation["_definition_generation"]),
            argv=("python3", "fixture.py"),
            environment={"PORT": "3302"},
            health_url=None,
        )
        service.mark_start_launched(
            operation_id=str(reservation["operation_id"]),
            server_definition_id=str(reservation["id"]),
            definition_generation=int(reservation["_definition_generation"]),
            pid=44002,
            log_path=str(self.home / "manual.log"),
            process_start_time="fixture-start",
            process_fingerprint="sha256:manual-process",
        )
        failed = service.fail_start(
            operation_id=str(reservation["operation_id"]),
            server_definition_id=str(reservation["id"]),
            error="health check failed",
            process_launched=True,
            process_active=False,
            manual_lease=True,
            pid=44002,
        )
        self.assertEqual(failed["status"], "stopped")
        retained = next(
            item for item in ports.list_leases() if item["id"] == lease["id"]
        )
        self.assertEqual(retained["status"], "active")
        self.assertEqual(retained["server_id"], reservation["id"])

    def test_stop_failure_retains_lease_and_records_needs_attention(self) -> None:
        running = self.running_server(name="web", port=3303)
        service = self.server_service()
        reservation = service.reserve_stop(
            agent="codex-a",
            server_definition_id=str(running["id"]),
            expected_definition_generation=int(running["generation"]),
            expected_observation_fingerprint=running.get(
                "_observation_fingerprint"
            ),
        )
        failed = service.fail_stop(
            operation_id=str(reservation["operation_id"]),
            server_definition_id=str(running["id"]),
            error="signal failed",
            cleanup_errors=["observer failed"],
        )
        self.assertTrue(failed["reconciliation_required"])
        self.assertEqual(failed["lease_status"], "active")
        with service.store.read_transaction() as connection:
            operation = connection.execute(
                "SELECT status, error_code FROM operations WHERE operation_id = ?",
                (reservation["operation_id"],),
            ).fetchone()
        self.assertEqual(operation["status"], "needs_attention")
        self.assertEqual(operation["error_code"], "server_stop_outcome_uncertain")

    def test_normalized_project_preflight_rejects_real_definition_drift(self) -> None:
        self.running_server(name="web", port=3304)
        original = dev_coordinator.require_project_server_identities_observable

        def race_after_identity_proof(
            state: dict[str, object],
            spec: dict[str, object],
            *,
            action: str,
        ) -> dict[str, tuple[object, ...]]:
            fingerprints = original(state, spec, action=action)
            with AccountStore.open_default(
                self.home, effective_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        "UPDATE server_definitions SET generation = generation + 1 "
                        "WHERE repo_id = (SELECT repo_id FROM repositories "
                        "WHERE canonical_root = ?)",
                        (str(self.project),),
                    )
            return fingerprints

        healthy = {
            "ok": True,
            "pid_alive": True,
            "identity": {"ok": True, "observable": True},
            "check": {"ok": True},
            "classification": "healthy",
        }
        environment = {
            "CODEX_AGENT_COORDINATOR_HOME": str(self.home),
            "DEVCOORDINATOR_STATE_BACKEND": "sqlite",
        }
        with (
            mock.patch.dict(os.environ, environment),
            mock.patch.object(dev_coordinator, "server_health", return_value=healthy),
            mock.patch.object(
                dev_coordinator,
                "require_project_server_identities_observable",
                side_effect=race_after_identity_proof,
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "changed during listener identity preflight",
            ):
                with dev_coordinator.normalized_repository_action_guard(
                    project=str(self.project),
                    agent="codex-a",
                    action=dev_coordinator.RepositoryAction.STOP,
                ):
                    dev_coordinator.begin_project_operation(
                        {"agent": "codex-a", "project": str(self.project)},
                        "stop",
                    )

        with AccountStore.open_default(
            self.home, effective_uid=os.geteuid()
        ) as store:
            with store.read_transaction() as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM operations WHERE kind = 'project.stop'"
                    ).fetchone()[0],
                    0,
                )

    def test_default_http_server_and_port_matrix_never_loads_legacy_projection(
        self,
    ) -> None:
        runtime = {"stopped": False, "pid": 45000}

        def health(
            _server: object, *_args: object, **_kwargs: object
        ) -> dict[str, object]:
            if runtime["stopped"]:
                return {
                    "ok": False,
                    "pid_alive": False,
                    "identity": {"ok": True, "observable": True},
                    "check": {"ok": False},
                    "classification": "stopped",
                }
            return {
                "ok": True,
                "pid_alive": True,
                "identity": {"ok": True, "observable": True},
                "check": {"ok": True},
                "classification": "healthy",
            }

        def launch(**_kwargs: object) -> tuple[int, str]:
            runtime["pid"] += 1
            runtime["stopped"] = False
            return int(runtime["pid"]), str(self.home / "http-server.log")

        def stop(_pid: int) -> None:
            runtime["stopped"] = True

        def poisoned_locked_state() -> object:
            raise AssertionError("default HTTP route reached locked_state")

        environment = {
            "CODEX_AGENT_COORDINATOR_HOME": str(self.home),
            "DEVCOORDINATOR_STATE_BACKEND": "sqlite",
        }
        server = None
        thread = None
        with (
            mock.patch.dict(os.environ, environment),
            mock.patch.object(
                dev_coordinator, "configured_broker_context", return_value=None
            ),
            mock.patch.object(
                dev_coordinator, "broker_lease_link_for_local", return_value=None
            ),
            mock.patch.object(dev_coordinator, "port_available", return_value=True),
            mock.patch.object(dev_coordinator, "start_process", side_effect=launch),
            mock.patch.object(dev_coordinator, "stop_pid", side_effect=stop),
            mock.patch.object(dev_coordinator, "server_health", side_effect=health),
            mock.patch.object(dev_coordinator, "wait_for_health", side_effect=health),
            mock.patch.object(
                dev_coordinator,
                "normalized_process_instance_evidence",
                side_effect=lambda **kwargs: (
                    "fixture-start",
                    f"sha256:http-{kwargs['pid']}",
                ),
            ),
            mock.patch.object(
                dev_coordinator,
                "resolve_registration_pid",
                return_value=(45050, {"ok": True, "observable": True}),
            ),
            mock.patch.object(
                dev_coordinator,
                "registration_pid_identity",
                return_value={"ok": True, "observable": True},
            ),
            mock.patch.object(
                dev_coordinator,
                "listener_evidence_for_port",
                return_value={
                    "present": False,
                    "port": 3310,
                    "pid": None,
                    "proc_listen_socket_count": 0,
                    "loopback_reachable": False,
                },
            ),
            mock.patch.object(
                dev_coordinator, "locked_state", side_effect=poisoned_locked_state
            ),
            mock.patch.object(
                AccountStore,
                "load_legacy_state_projection",
                side_effect=poisoned_locked_state,
            ),
            mock.patch.object(
                AccountStore,
                "replace_legacy_state_projection",
                side_effect=poisoned_locked_state,
            ),
            mock.patch.object(
                dev_coordinator,
                "docker_available_command",
                return_value={"ok": False, "error": "fixture Docker unavailable"},
            ),
        ):
            server = dev_coordinator.BoundedThreadingHTTPServer(
                ("127.0.0.1", 0), dev_coordinator.ApiHandler, token="test-token"
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = int(server.server_address[1])

            def request(
                method: str, path: str, payload: dict[str, object] | None = None
            ) -> object:
                connection = http.client.HTTPConnection(
                    "127.0.0.1", port, timeout=5
                )
                body = None if payload is None else json.dumps(payload)
                headers = {"Authorization": "Bearer test-token"}
                if body is not None:
                    headers["Content-Type"] = "application/json"
                try:
                    connection.request(method, path, body=body, headers=headers)
                    response = connection.getresponse()
                    raw = response.read()
                finally:
                    connection.close()
                decoded = json.loads(raw.decode("utf-8")) if raw else None
                self.assertEqual(response.status, 200, decoded)
                return decoded

            try:
                self.assertEqual(
                    request("GET", "/v1/inventory")["store"]["authority_mode"],
                    "sqlite",
                )
                self.assertEqual(
                    request("GET", "/v1/inventory/no-docker")["docker"][
                        "available"
                    ],
                    None,
                )
                assignment = request(
                    "POST",
                    "/v1/ports/assign",
                    {
                        "agent": "codex-a",
                        "project": str(self.project),
                        "name": "temporary",
                        "port": 3311,
                    },
                )
                self.assertEqual(assignment["port"], 3311)
                self.assertEqual(
                    request("GET", "/v1/ports/assignments")[0]["name"],
                    "temporary",
                )
                request(
                    "POST",
                    "/v1/ports/unassign",
                    {
                        "agent": "codex-a",
                        "project": str(self.project),
                        "name": "temporary",
                    },
                )
                lease = request(
                    "POST",
                    "/v1/ports/lease",
                    {
                        "agent": "codex-a",
                        "project": str(self.project),
                        "range": "3311-3311",
                        "preferred": 3311,
                    },
                )
                self.assertEqual(request("GET", "/v1/ports")[0]["id"], lease["id"])
                request(
                    "POST",
                    "/v1/ports/release",
                    {
                        "agent": "codex-a",
                        "project": str(self.project),
                        "lease_id": lease["id"],
                    },
                )

                started = request(
                    "POST",
                    "/v1/servers/start",
                    {
                        "agent": "codex-a",
                        "project": str(self.project),
                        "name": "web",
                        "argv": ["python3", "fixture.py", "--port", "{port}"],
                        "range": "3310-3310",
                        "preferred": 3310,
                    },
                )
                self.assertEqual(started["status"], "running")
                self.assertEqual(request("GET", "/v1/servers")[0]["name"], "web")
                self.assertEqual(request("GET", "/v1/state")["servers"][started["id"]]["name"], "web")
                request(
                    "POST",
                    "/v1/servers/status",
                    {"project": str(self.project), "name": "web"},
                )
                request(
                    "POST",
                    "/v1/servers/logs",
                    {"project": str(self.project), "name": "web"},
                )
                restarted = request(
                    "POST",
                    "/v1/servers/restart",
                    {
                        "agent": "codex-a",
                        "project": str(self.project),
                        "name": "web",
                    },
                )
                self.assertEqual(restarted["status"], "running")
                stopped = request(
                    "POST",
                    "/v1/servers/stop",
                    {
                        "agent": "codex-a",
                        "project": str(self.project),
                        "name": "web",
                    },
                )
                self.assertEqual(stopped["status"], "stopped")
                relocated = request(
                    "POST",
                    "/v1/ports/relocate",
                    {
                        "agent": "codex-a",
                        "old_project": str(self.project),
                        "new_project": str(self.project_b),
                        "name": "web",
                        "port": 3310,
                        "lease_id": stopped["lease_id"],
                    },
                )
                self.assertEqual(relocated["project"], str(self.project_b))

                runtime["stopped"] = False
                registered = request(
                    "POST",
                    "/v1/servers/register",
                    {
                        "agent": "codex-a",
                        "project": str(self.project),
                        "name": "adopted",
                        "port": 3312,
                        "pid": 45050,
                    },
                )
                self.assertEqual(registered["status"], "running")

                # A non-dry-run project action must compare one authoritative
                # normalized lifecycle shape on both sides of its slow
                # listener-identity preflight.  The v1 compatibility
                # projection intentionally omits private CAS fields and must
                # never be compared with the direct lifecycle row: doing so
                # makes a stable registered server look like a TOCTOU race.
                stopped_project = request(
                    "POST",
                    "/v1/projects/stop",
                    {
                        "project": str(self.project),
                        "agent": "codex-a",
                    },
                )
                self.assertTrue(stopped_project["ok"])
                self.assertEqual(
                    request("GET", "/v1/servers")[0]["status"],
                    "stopped",
                )

                project_payload = {"project": str(self.project), "dry_run": True}
                project_status = request(
                    "POST",
                    "/v1/projects/status",
                    {"project": str(self.project)},
                )
                self.assertEqual(project_status["project"], str(self.project))
                for path in (
                    "/v1/projects/start",
                    "/v1/projects/restart",
                    "/v1/projects/stop",
                ):
                    project_result = request(
                        "POST",
                        path,
                        {**project_payload, "agent": "codex-a"},
                    )
                    self.assertEqual(project_result["project"], str(self.project))

                self.assertTrue(
                    request("POST", "/v1/docker/ps", {"dry_run": True})[
                        "dry_run"
                    ]
                )
                self.assertTrue(
                    request("POST", "/v1/docker/stats", {"dry_run": True})[
                        "dry_run"
                    ]
                )
                docker_identity = {
                    "container": "fixture",
                    "agent": "codex-a",
                    "project": str(self.project),
                    "dry_run": True,
                }
                self.assertTrue(
                    request(
                        "POST", "/v1/docker/register", docker_identity
                    )["dry_run"]
                )
                for path in (
                    "/v1/docker/start",
                    "/v1/docker/stop",
                    "/v1/docker/restart",
                ):
                    self.assertTrue(
                        request("POST", path, docker_identity)["dry_run"]
                    )
                for path in (
                    "/v1/docker/compose-up",
                    "/v1/docker/compose-down",
                ):
                    self.assertTrue(
                        request(
                            "POST",
                            path,
                            {
                                "cwd": str(self.project),
                                "project": str(self.project),
                                "agent": "codex-a",
                                "dry_run": True,
                            },
                        )["dry_run"]
                    )
                self.assertTrue(
                    request(
                        "POST",
                        "/v1/docker/logs",
                        {"container": "fixture", "dry_run": True},
                    )["dry_run"]
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
