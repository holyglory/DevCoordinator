from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

import dev_coordinator
from devcoordinator.broker_configuration import (
    reconcile_configured_runtime_container_declarations,
)
from devcoordinator.broker_host import EPHEMERAL_DOCKER_LABELS
from devcoordinator.host_observation import commit_host_inventory_observation
from devcoordinator.inventory_projection import envelope as inventory_envelope
from devcoordinator.observer import ObservationOutcome, SingleFlightObserver
from devcoordinator.store import AccountStore, deterministic_id, utc_timestamp


class DockerInventoryIdentityTests(unittest.TestCase):
    def test_host_observation_deadline_caps_and_then_refuses_docker_calls(self) -> None:
        completed = mock.Mock(returncode=0, stdout="", stderr="")
        with (
            mock.patch.object(dev_coordinator, "HOST_OBSERVATION_BUDGET_SECONDS", 5.0),
            mock.patch.object(
                dev_coordinator.time, "monotonic", side_effect=[100.0, 102.0]
            ),
            mock.patch.object(
                dev_coordinator,
                "resolve_docker_executable",
                return_value="/usr/bin/docker",
            ),
            mock.patch.object(
                dev_coordinator, "configured_docker_timeout", return_value=600.0
            ),
            mock.patch.object(
                dev_coordinator.subprocess, "run", return_value=completed
            ) as run,
        ):
            with dev_coordinator.bounded_host_observation():
                dev_coordinator.execute_docker_subprocess(["docker", "info"])
        self.assertEqual(run.call_args.kwargs["timeout"], 3.0)

        with (
            mock.patch.object(dev_coordinator, "HOST_OBSERVATION_BUDGET_SECONDS", 5.0),
            mock.patch.object(
                dev_coordinator.time, "monotonic", side_effect=[100.0, 106.0]
            ),
            mock.patch.object(
                dev_coordinator,
                "resolve_docker_executable",
                return_value="/usr/bin/docker",
            ),
            mock.patch.object(dev_coordinator.subprocess, "run") as run,
        ):
            with self.assertRaises(dev_coordinator.DockerCommandTimeoutError):
                with dev_coordinator.bounded_host_observation():
                    dev_coordinator.execute_docker_subprocess(["docker", "info"])
        run.assert_not_called()

    def test_docker_stats_requests_and_keys_full_immutable_ids(self) -> None:
        full_id = "e" * 64

        def docker_command(args: list[str], *, cwd: str | None = None) -> dict:
            del cwd
            self.assertEqual(args[:2], ["stats", "--no-stream"])
            self.assertIn(
                "--no-trunc",
                args,
                "must-catch: telemetry IDs must stay joinable to full inventory identities",
            )
            return {
                "ok": True,
                "stdout": json.dumps(
                    {
                        "ID": full_id,
                        "Container": full_id,
                        "Name": "fixture-web",
                        "CPUPerc": "1.5%",
                        "MemPerc": "2.5%",
                        "MemUsage": "10MiB / 1GiB",
                        "NetIO": "1kB / 2kB",
                        "BlockIO": "3kB / 4kB",
                        "PIDs": "2",
                    }
                ),
            }

        state: dict = {}
        with mock.patch.object(
            dev_coordinator,
            "docker_available_command",
            side_effect=docker_command,
        ):
            sampled = dev_coordinator.sample_docker_stats(state)
        self.assertEqual(sampled["stats"][0]["id"], full_id)
        self.assertIn(full_id, state["docker"]["stats_history"])

    def test_fractional_humanized_docker_sizes_become_integral_byte_counts(self) -> None:
        sample = dev_coordinator.normalize_docker_stats(
            {
                "ID": "e" * 64,
                "Container": "e" * 64,
                "Name": "fixture-web",
                "CPUPerc": "1.5%",
                "MemPerc": "2.5%",
                "MemUsage": "4.093GiB / 8GiB",
                "NetIO": "1.25kB / 2.5kB",
                "BlockIO": "3.001MiB / 4.999MiB",
                "PIDs": "2",
            },
            timestamp=1_785_000_000.0,
        )

        expected = {
            "memory_usage_bytes": 4_394_825_286,
            "memory_limit_bytes": 8_589_934_592,
            "network_rx_bytes": 1_250,
            "network_tx_bytes": 2_500,
            "block_read_bytes": 3_146_777,
            "block_write_bytes": 5_241_831,
        }
        for field, value in expected.items():
            self.assertEqual(sample[field], value)
            self.assertIs(type(sample[field]), int, f"{field} must remain an integer")

    def test_bulk_inspect_failure_keeps_full_ps_identity_and_sidecar_attribution(self) -> None:
        full_id = "a" * 64
        name = "fixture-web"
        project = "/repo/fixture"
        state = {
            "docker": {
                "metadata": {
                    name: {
                        "container": name,
                        "project": project,
                        "agent": "fixture-agent",
                        "metadata_source": "coordinator_sidecar",
                    }
                },
                "stats_history": {},
            }
        }

        def docker_command(args: list[str], *, cwd: str | None = None) -> dict:
            del cwd
            if args[:1] == ["ps"]:
                self.assertIn(
                    "--no-trunc",
                    args,
                    "must-catch: Docker ps must supply immutable full IDs independently of inspect",
                )
                return {
                    "ok": True,
                    "stdout": json.dumps(
                        {
                            "ID": full_id,
                            "Names": name,
                            "Image": "fixture/web:latest",
                            "Status": "Up 1 minute",
                            "Ports": "127.0.0.1:3000->3000/tcp",
                        }
                    ),
                }
            if args[:1] == ["inspect"]:
                return {"ok": False, "stderr": "one raced container disappeared"}
            if args[:2] in (["network", "ls"], ["volume", "ls"]):
                return {"ok": True, "stdout": ""}
            self.fail(f"unexpected Docker command: {args}")

        with (
            mock.patch.object(dev_coordinator, "docker_available_command", side_effect=docker_command),
            mock.patch.object(
                dev_coordinator,
                "sample_docker_stats",
                return_value={"available": True, "stats": []},
            ),
        ):
            inventory = dev_coordinator.docker_ps_inventory(state=state)

        self.assertTrue(inventory["available"])
        self.assertEqual(len(inventory["containers"]), 1)
        container = inventory["containers"][0]
        self.assertEqual(container["id"], full_id)
        self.assertEqual(container["full_id"], full_id)
        self.assertEqual(container["project"], project)
        self.assertEqual(container["metadata_source"], "coordinator_sidecar")
        self.assertFalse(container["inspection_observable"])
        self.assertIn("inspect", inventory["inspection_error"].lower())

    def test_intermediate_length_ps_id_is_not_accepted_as_an_immutable_identity(self) -> None:
        intermediate_id = "a" * 16

        def docker_command(args: list[str], *, cwd: str | None = None) -> dict:
            del cwd
            if args[:1] == ["ps"]:
                self.assertIn("--no-trunc", args)
                return {
                    "ok": True,
                    "stdout": json.dumps(
                        {
                            "ID": intermediate_id,
                            "Names": "malformed-id",
                            "Image": "fixture/web:latest",
                            "Status": "Up 1 minute",
                            "Ports": "",
                        }
                    ),
                }
            if args[:1] == ["inspect"]:
                return {"ok": False, "stderr": "inspection unavailable"}
            self.fail(f"unexpected Docker command: {args}")

        with (
            mock.patch.object(dev_coordinator, "docker_available_command", side_effect=docker_command),
            mock.patch.object(
                dev_coordinator,
                "sample_docker_stats",
                return_value={"available": True, "stats": []},
            ),
        ):
            inventory = dev_coordinator.docker_ps_inventory(state={})

        self.assertFalse(
            inventory["available"],
            "must-catch: only an exact 64-hex Docker ID is an immutable identity",
        )
        self.assertEqual(inventory["containers"], [])
        self.assertIn("identity unavailable", inventory["error"].lower())

    def test_compose_working_dir_maps_to_deepest_git_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            outer = root / "GlobalFinance"
            deploy = outer / "deploy"
            nested = deploy / "nested-worktree"
            nested_deploy = nested / "deploy"
            for repository in (outer, nested):
                repository.mkdir(parents=True)
                (repository / ".git").mkdir()
            nested_deploy.mkdir()

            outer_inspection = {
                "Config": {
                    "Labels": {
                        "com.docker.compose.project.working_dir": str(deploy),
                    }
                }
            }
            nested_inspection = {
                "Config": {
                    "Labels": {
                        "com.docker.compose.project.working_dir": str(nested_deploy),
                    }
                }
            }
            self.assertEqual(
                dev_coordinator.compose_project_from_inspection(outer_inspection),
                str(outer),
            )
            self.assertEqual(
                dev_coordinator.compose_project_from_inspection(nested_inspection),
                str(nested),
                "a distinct nested worktree must not be collapsed into its outer repository",
            )

    def test_compose_working_dir_refreshes_after_nested_worktree_is_created(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            outer = root / "outer"
            nested = outer / "services" / "nested"
            nested_deploy = nested / "deploy"
            nested_deploy.mkdir(parents=True)
            (outer / ".git").mkdir()
            inspection = {
                "Config": {
                    "Labels": {
                        "com.docker.compose.project.working_dir": str(nested_deploy),
                    }
                }
            }

            self.assertEqual(
                dev_coordinator.compose_project_from_inspection(inspection),
                str(outer),
            )
            (nested / ".git").write_text("gitdir: /fixture/worktrees/nested\n")
            self.assertEqual(
                dev_coordinator.compose_project_from_inspection(inspection),
                str(nested),
                "must-catch: a process-lifetime cache must not hide a nested "
                "worktree created between sequential Docker observations",
            )


class NormalizedDockerGroupingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "coordinator"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _insert_repository(store: AccountStore, host_id: str, root: Path) -> str:
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
        return repo_id

    def _observe(
        self,
        store: AccountStore,
        host_id: str,
        containers: list[dict],
        *,
        docker_available: bool = True,
        observer_domain: str = "fixture-docker",
    ) -> ObservationOutcome:
        sample = {
            "sampled_at": utc_timestamp(),
            "inventory": {
                "servers": [],
                "docker": {
                    "available": docker_available,
                    "containers": containers,
                    "postgres": [],
                },
            },
        }
        return SingleFlightObserver(store).observe(
            host_id=host_id,
            observer_domain=observer_domain,
            sampler=lambda: sample,
            commit=lambda connection, snapshot_id, observed: commit_host_inventory_observation(
                connection,
                snapshot_id,
                observed,
                host_id=host_id,
                coordinator_home=str(self.home),
                effective_uid=os.geteuid(),
            ),
        )

    def _write_runtime_container_declaration(
        self, repository: Path, container_name: str
    ) -> None:
        runtime = repository / ".codex"
        runtime.mkdir(exist_ok=True)
        (runtime / "dev-runtime.json").write_text(
            json.dumps(
                {
                    "dependencies": [
                        {"type": "docker", "container": container_name}
                    ]
                }
            ),
            encoding="utf-8",
        )

    def test_current_declared_container_reconciliation_is_read_only(self) -> None:
        repository = self.root / "current-declaration"
        repository.mkdir()
        (repository / ".git").mkdir()
        container_name = "current-declaration-api-1"
        self._write_runtime_container_declaration(repository, container_name)
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            repo_id = self._insert_repository(store, host_id, repository)
            outcome = self._observe(
                store,
                host_id,
                [self._container("d" * 64, container_name, project=repository)],
                observer_domain=dev_coordinator.OBSERVER_DOMAIN_FULL_DOCKER,
            )
            before = store.metadata.state_revision
            result = reconcile_configured_runtime_container_declarations(
                store, snapshot_id=outcome.snapshot_id
            )
            after = store.metadata.state_revision

        self.assertEqual(before, after)
        self.assertEqual(result["changed"], 0)
        self.assertEqual(result["bindings"][0]["status"], "already_associated")
        self.assertEqual(result["bindings"][0]["associated_repo_id"], repo_id)

    def test_concurrent_first_declaration_associates_exactly_once(self) -> None:
        repository = self.root / "concurrent-declaration"
        repository.mkdir()
        (repository / ".git").mkdir()
        container_name = "concurrent-declaration-api-1"
        self._write_runtime_container_declaration(repository, container_name)
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            repo_id = self._insert_repository(store, host_id, repository)
            outcome = self._observe(
                store,
                host_id,
                [self._container("e" * 64, container_name)],
                observer_domain=dev_coordinator.OBSERVER_DOMAIN_FULL_DOCKER,
            )
            before = store.metadata.state_revision

        barrier = threading.Barrier(8)
        results: list[dict] = []
        failures: list[BaseException] = []

        def reconcile() -> None:
            try:
                with AccountStore.open_default(self.home) as worker_store:
                    barrier.wait(timeout=2.0)
                    results.append(
                        reconcile_configured_runtime_container_declarations(
                            worker_store, snapshot_id=outcome.snapshot_id
                        )
                    )
            except BaseException as error:  # pragma: no cover - diagnostics
                failures.append(error)

        workers = [threading.Thread(target=reconcile) for _ in range(8)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=5.0)

        with AccountStore.open_default(self.home) as store:
            after = store.metadata.state_revision
            with store.read_transaction() as connection:
                associated_repo_id = connection.execute(
                    """
                    SELECT repo_id FROM docker_resources
                    WHERE full_container_id = ?
                    """,
                    ("e" * 64,),
                ).fetchone()[0]

        self.assertFalse(any(worker.is_alive() for worker in workers), failures)
        self.assertEqual(failures, [])
        self.assertEqual(len(results), 8)
        self.assertEqual(sum(int(result["changed"]) for result in results), 1)
        self.assertEqual(after, before + 1)
        self.assertEqual(associated_repo_id, repo_id)
        self.assertEqual(
            sorted(result["bindings"][0]["status"] for result in results),
            ["already_associated"] * 7 + ["associated"],
        )

    def _observe_at(
        self,
        store: AccountStore,
        host_id: str,
        containers: list[dict],
        *,
        started_at: str,
        sampled_at: str,
        completed_at: str,
    ) -> None:
        """Commit one Docker snapshot with a deterministic sampling window."""

        sample = {
            "sampled_at": sampled_at,
            "inventory": {
                "servers": [],
                "docker": {
                    "available": True,
                    "containers": containers,
                    "postgres": [],
                },
            },
        }
        clock_values = iter(
            [
                datetime.fromisoformat(started_at.replace("Z", "+00:00")),
                datetime.fromisoformat(started_at.replace("Z", "+00:00")),
                datetime.fromisoformat(completed_at.replace("Z", "+00:00")),
            ]
        )
        SingleFlightObserver(
            store,
            clock=lambda: next(clock_values).astimezone(timezone.utc),
        ).observe(
            host_id=host_id,
            observer_domain="fixture-docker",
            sampler=lambda: sample,
            commit=lambda connection, snapshot_id, observed: commit_host_inventory_observation(
                connection,
                snapshot_id,
                observed,
                host_id=host_id,
                coordinator_home=str(self.home),
                effective_uid=os.geteuid(),
            ),
        )

    @staticmethod
    def _container(
        full_id: str,
        name: str,
        *,
        project: Path | None = None,
        status: str = "Up 1 minute",
    ) -> dict:
        container = {
            "id": full_id,
            "full_id": full_id,
            "name": name,
            "image": "fixture/web:latest",
            "status": status,
            # The normalized observer accepts lifecycle only from an exact
            # inspect-backed boolean, never by reparsing Docker's display text.
            "running": status.startswith("Up "),
            "inspection_observable": True,
            "restart_policy": "unless-stopped",
            "labels": {},
            "port_bindings": [],
            "databases": [],
        }
        if project is not None:
            container["project"] = str(project)
            container["metadata_source"] = "docker_labels"
        return container

    @staticmethod
    def _insert_ephemeral_run(
        store: AccountStore,
        *,
        repo_id: str,
        run_id: str,
        creation_nonce: str,
        template_id: str,
        definition_fingerprint: str,
        container_name: str,
        full_container_id: str | None = None,
        docker_resource_id: str | None = None,
    ) -> dict[str, str]:
        timestamp = utc_timestamp()
        with store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO operations(
                    operation_id, repo_id, kind, status, phase, generation,
                    request_fingerprint, owner_uid, actor, created_at, updated_at
                ) VALUES (?, ?, 'broker.ephemeral.start', 'running',
                          'write_ahead_committed', 0, 'fixture-request', ?,
                          'fixture', ?, ?)
                """,
                (run_id, repo_id, os.geteuid(), timestamp, timestamp),
            )
            connection.execute(
                """
                INSERT INTO ephemeral_container_templates(
                    template_id, repo_id, name, image_ref,
                    definition_fingerprint, default_ttl_seconds,
                    max_ttl_seconds, max_concurrent_runs,
                    max_concurrent_runs_per_uid, repo_max_active_runs,
                    repo_memory_budget_bytes, repo_cpu_budget_millis,
                    enabled, generation, created_at, updated_at
                ) VALUES (?, ?, 'artifact-postgres', 'fixture:latest', ?,
                          600, 3600, 4, 2, 16, 8589934592, 16000,
                          1, 0, ?, ?)
                """,
                (template_id, repo_id, definition_fingerprint, timestamp, timestamp),
            )
            connection.execute(
                """
                INSERT INTO ephemeral_container_runs(
                    run_id, template_id, repo_id, owner_uid, account_id,
                    creation_nonce, container_name, full_container_id,
                    docker_resource_id, image_ref, template_fingerprint,
                    status, phase, max_ttl_seconds, expires_at_epoch,
                    next_reconcile_at_epoch, recovery_failures,
                    create_absence_observations, cleanup_requested, generation,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'fixture-account', ?, ?, ?, ?,
                          'fixture:latest', ?, 'creating',
                          'docker_create_outcome_unknown', 3600, 4102444800,
                          0, 0, 0, 0, 0, ?, ?)
                """,
                (
                    run_id,
                    template_id,
                    repo_id,
                    os.geteuid(),
                    creation_nonce,
                    container_name,
                    full_container_id,
                    docker_resource_id,
                    definition_fingerprint,
                    timestamp,
                    timestamp,
                ),
            )
        return dict(
            zip(
                EPHEMERAL_DOCKER_LABELS,
                (
                    run_id,
                    creation_nonce,
                    repo_id,
                    template_id,
                    definition_fingerprint,
                ),
            )
        )

    def test_testcontainers_dependencies_do_not_publish_ownership_or_crash_incidents(self) -> None:
        """Normal Testcontainers setup/teardown is not a Console incident."""

        full_id = "9" * 64
        container = self._container(full_id, "testcontainers-ryuk-fixture")
        container["labels"] = {
            "org.testcontainers": "true",
            "org.testcontainers.session-id": "fixture-session",
        }
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            self._observe(store, host_id, [container])
            stopped = dict(container)
            stopped["status"] = "Exited (0)"
            stopped["running"] = False
            self._observe(store, host_id, [stopped])
            graph = store.inventory_v2()
            with store.read_transaction() as connection:
                event_codes = [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT code FROM events ORDER BY occurred_at, event_id"
                    )
                ]

        self.assertEqual(graph["resources"]["docker"], [])
        self.assertEqual(graph["unassigned_resources"], [])
        self.assertEqual(graph["v1_compatibility"]["docker"]["containers"], [])
        self.assertNotIn("docker_unassigned_discovered", event_codes)
        self.assertNotIn("docker_crashed", event_codes)
        inventory_envelope(
            generation=1,
            inventory=graph,
            published_at="2026-07-31T00:00:00Z",
        )

    def test_uninspectable_test_setup_row_never_becomes_an_incident_or_database_group(self) -> None:
        """A ps/inspect race must not briefly pollute the Console inventory."""

        full_id = "8" * 64
        container = self._container(full_id, "naughty_haibt")
        container.update(
            {
                "inspection_observable": False,
                "metadata_source": "inspection_unavailable",
                "labels": {},
                "databases": [{"name": "skydive_fixture", "size_bytes": 42}],
            }
        )
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            self._observe(store, host_id, [container])
            graph = store.inventory_v2()
            with store.read_transaction() as connection:
                event_codes = [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT code FROM events ORDER BY occurred_at, event_id"
                    )
                ]
                database_binding_count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM database_bindings"
                    ).fetchone()[0]
                )

        self.assertEqual(graph["resources"]["docker"], [])
        self.assertEqual(graph["resources"]["databases"], [])
        self.assertEqual(graph["unassigned_resources"], [])
        self.assertEqual(graph["v1_compatibility"]["docker"]["containers"], [])
        self.assertEqual(database_binding_count, 0)
        self.assertNotIn("docker_unassigned_discovered", event_codes)
        self.assertNotIn("docker_crashed", event_codes)
        inventory_envelope(
            generation=1,
            inventory=graph,
            published_at="2026-07-31T00:00:00Z",
        )

    def test_compatibility_container_stats_belong_to_latest_available_snapshot(self) -> None:
        first_time = "2026-07-21T00:00:05Z"
        second_time = "2026-07-21T00:01:05Z"
        stale_id = "a" * 64
        stopped_id = "b" * 64
        current_id = "c" * 64
        repository = self.root / "metrics-project"
        repository.mkdir()
        (repository / ".git").mkdir()

        stale_running = self._container(
            stale_id,
            "stale-running",
            project=repository,
        )
        stale_running["stats"] = {
            "timestamp": first_time,
            "cpu_percent": 91.0,
            "memory_usage_bytes": 9_100,
            "network_rx_bytes": 910,
            "network_tx_bytes": 911,
            "block_read_bytes": 912,
            "block_write_bytes": 913,
        }
        previously_running = self._container(
            stopped_id,
            "stopped-history",
            project=repository,
        )
        previously_running["stats"] = {
            "timestamp": first_time,
            "cpu_percent": 82.0,
            "memory_usage_bytes": 8_200,
        }

        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            repo_id = self._insert_repository(store, host_id, repository)
            self._observe_at(
                store,
                host_id,
                [stale_running, previously_running],
                started_at="2026-07-21T00:00:00Z",
                sampled_at=first_time,
                completed_at="2026-07-21T00:00:10Z",
            )

            current_running = self._container(
                current_id,
                "current-running",
                project=repository,
            )
            current_running["stats"] = {
                "timestamp": second_time,
                "cpu_percent": 3.25,
                "memory_usage_bytes": 32_500,
                "network_rx_bytes": 3_210,
                "network_tx_bytes": 3_211,
                "block_read_bytes": 3_212,
                "block_write_bytes": 3_213,
            }
            self._observe_at(
                store,
                host_id,
                [
                    self._container(
                        stale_id,
                        "stale-running",
                        project=repository,
                    ),
                    self._container(
                        stopped_id,
                        "stopped-history",
                        project=repository,
                        status="Exited (0) 1 minute ago",
                    ),
                    current_running,
                ],
                started_at="2026-07-21T00:01:00Z",
                sampled_at=second_time,
                completed_at="2026-07-21T00:01:10Z",
            )
            graph = store.inventory_v2()
            with store.read_transaction() as connection:
                retained_samples = connection.execute(
                    "SELECT COUNT(*) FROM telemetry_samples WHERE host_resource_kind = 'docker'"
                ).fetchone()[0]

        containers = {
            item["name"]: item
            for item in graph["v1_compatibility"]["docker"]["containers"]
        }
        self.assertEqual(
            containers["current-running"]["stats"],
            {
                "source": "normalized_observation",
                "id": current_id,
                "container_id": current_id,
                "name": "current-running",
                "timestamp": second_time,
                "live": True,
                "cpu_percent": 3.25,
                "memory_usage_bytes": 32_500,
                "network_rx_bytes": 3_210,
                "network_tx_bytes": 3_211,
                "block_read_bytes": 3_212,
                "block_write_bytes": 3_213,
            },
            "a running exact resource must expose telemetry measured in the current snapshot",
        )
        self.assertNotIn(
            "stats",
            containers["stale-running"],
            "must-catch: a newer available snapshot without stats cannot reuse an older sample",
        )
        self.assertNotIn(
            "stats",
            containers["stopped-history"],
            "stopped containers must not present retained telemetry as live utilization",
        )
        self.assertEqual(
            retained_samples,
            3,
            "projection freshness must not delete retained telemetry history",
        )
        project_usage = next(
            item
            for item in graph["v1_compatibility"]["project_usage"]
            if item["project"] == str(repository)
        )
        self.assertEqual(project_usage["cpu_percent"], 3.25)
        self.assertEqual(project_usage["memory_bytes"], 32_500)

    def test_fractional_telemetry_is_stored_and_projected_as_integral_bytes(self) -> None:
        repository = self.root / "fractional-telemetry"
        repository.mkdir()
        (repository / ".git").mkdir()
        full_id = "d" * 64
        container = self._container(full_id, "fractional-web", project=repository)
        container["stats"] = {
            "timestamp": "2026-07-28T00:00:01Z",
            "cpu_percent": 1.25,
            "memory_usage_bytes": 4_394_825_285.632,
            "network_rx_bytes": 1_250.4,
            "network_tx_bytes": 2_500.5,
            "block_read_bytes": 8_460_000_000.000001,
            "block_write_bytes": 5_241_830.6,
        }

        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            self._insert_repository(store, host_id, repository)
            self._observe_at(
                store,
                host_id,
                [container],
                started_at="2026-07-28T00:00:00Z",
                sampled_at="2026-07-28T00:00:02Z",
                completed_at="2026-07-28T00:00:10Z",
            )
            with store.read_transaction() as connection:
                stored = connection.execute(
                    """
                    SELECT typeof(memory_bytes) AS memory_type,
                           typeof(network_rx_bytes) AS rx_type,
                           typeof(network_tx_bytes) AS tx_type,
                           typeof(block_read_bytes) AS read_type,
                           typeof(block_write_bytes) AS write_type
                    FROM telemetry_samples
                    WHERE host_resource_kind = 'docker'
                    """
                ).fetchone()
            graph = store.inventory_v2()

        self.assertEqual(
            dict(stored),
            {
                "memory_type": "integer",
                "rx_type": "integer",
                "tx_type": "integer",
                "read_type": "integer",
                "write_type": "integer",
            },
        )
        telemetry = graph["observations"]["telemetry"]
        self.assertEqual(len(telemetry), 1)
        expected = {
            "memory_bytes": 4_394_825_286,
            "network_rx_bytes": 1_250,
            "network_tx_bytes": 2_501,
            "block_read_bytes": 8_460_000_000,
            "block_write_bytes": 5_241_831,
        }
        for field, value in expected.items():
            self.assertEqual(telemetry[0][field], value)
            self.assertIs(type(telemetry[0][field]), int)

    def test_inventory_normalizes_preexisting_real_telemetry_rows(self) -> None:
        repository = self.root / "legacy-fractional-telemetry"
        repository.mkdir()
        (repository / ".git").mkdir()
        full_id = "f" * 64
        container = self._container(full_id, "legacy-fractional-web", project=repository)
        container["stats"] = {
            "timestamp": "2026-07-28T00:00:02Z",
            "cpu_percent": 2.5,
            "memory_usage_bytes": 1,
            "network_rx_bytes": 2,
            "network_tx_bytes": 3,
            "block_read_bytes": 4,
            "block_write_bytes": 5,
        }

        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            self._insert_repository(store, host_id, repository)
            self._observe_at(
                store,
                host_id,
                [container],
                started_at="2026-07-28T00:00:00Z",
                sampled_at="2026-07-28T00:00:02Z",
                completed_at="2026-07-28T00:00:10Z",
            )
            with store.immediate_transaction(revision_kind="observation") as connection:
                connection.execute(
                    """
                    UPDATE telemetry_samples
                    SET memory_bytes = 4394825285.632,
                        network_rx_bytes = 1250.4,
                        network_tx_bytes = 2500.5,
                        block_read_bytes = 8460000000.000001,
                        block_write_bytes = 5241830.6
                    WHERE host_resource_kind = 'docker'
                    """
                )
                storage_types = connection.execute(
                    """
                    SELECT typeof(memory_bytes), typeof(network_rx_bytes),
                           typeof(network_tx_bytes), typeof(block_read_bytes),
                           typeof(block_write_bytes)
                    FROM telemetry_samples
                    WHERE host_resource_kind = 'docker'
                    """
                ).fetchone()
            graph = store.inventory_v2()

        self.assertEqual(tuple(storage_types), ("real", "real", "real", "real", "real"))
        telemetry = graph["observations"]["telemetry"]
        self.assertEqual(len(telemetry), 1)
        for field in (
            "memory_bytes",
            "network_rx_bytes",
            "network_tx_bytes",
            "block_read_bytes",
            "block_write_bytes",
        ):
            self.assertIs(
                type(telemetry[0][field]),
                int,
                f"legacy {field} must be normalized before JSON transport",
            )
        compatibility = next(
            item
            for item in graph["v1_compatibility"]["docker"]["containers"]
            if item["name"] == "legacy-fractional-web"
        )
        for field in (
            "memory_usage_bytes",
            "network_rx_bytes",
            "network_tx_bytes",
            "block_read_bytes",
            "block_write_bytes",
        ):
            self.assertIs(type(compatibility["stats"][field]), int)

    def test_nested_compose_path_records_configured_repository_association(self) -> None:
        repository = self.root / "GlobalFinance"
        deploy = repository / "deploy"
        repository.mkdir()
        (repository / ".git").mkdir()
        deploy.mkdir()
        full_id = "b" * 64

        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            repo_id = self._insert_repository(store, host_id, repository)
            self._observe(
                store,
                host_id,
                [self._container(full_id, "gf-v2-dev-api-1", project=deploy)],
            )
            graph = store.inventory_v2()

        resource_id = deterministic_id(
            "docker-resource",
            deterministic_id("docker-engine", host_id, "default"),
            full_id,
        )
        resource = next(
            item
            for item in graph["resources"]["docker"]
            if item["docker_resource_id"] == resource_id
        )
        self.assertEqual(resource["repo_id"], repo_id)
        usage = next(
            item
            for item in graph["v1_compatibility"]["project_usage"]
            if item["project"] == str(repository)
        )
        self.assertEqual(usage["container_names"], ["gf-v2-dev-api-1"])
        self.assertEqual(usage["container_resource_ids"], [resource_id])

    def test_ownership_problem_telemetry_is_excluded_from_repository_usage(self) -> None:
        repository = self.root / "ownership-problem-usage"
        repository.mkdir()
        (repository / ".git").mkdir()
        full_id = "e" * 64
        container = self._container(
            full_id,
            "ownership-problem-worker",
            project=repository,
        )
        container["stats"] = {
            "timestamp": "2026-08-03T00:00:01Z",
            "cpu_percent": 24.0,
            "memory_usage_bytes": 3 * 1024**3,
        }

        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            repo_id = self._insert_repository(store, host_id, repository)
            self._observe(store, host_id, [container])
            resource_id = deterministic_id(
                "docker-resource",
                deterministic_id("docker-engine", host_id, "default"),
                full_id,
            )
            timestamp = utc_timestamp()
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO unassigned_resources(
                        unassigned_id, host_id, resource_kind, resource_id,
                        display_name, reason_code, status, created_at, updated_at
                    ) VALUES (?, ?, 'container', ?, ?, 'stale_observation',
                              'active', ?, ?)
                    """,
                    (
                        "problem-usage-container",
                        host_id,
                        resource_id,
                        "ownership-problem-worker",
                        timestamp,
                        timestamp,
                    ),
                )
            graph = store.inventory_v2()

        problem_ids = {
            item["resource_id"] for item in graph["unassigned_resources"]
        }
        self.assertIn(resource_id, problem_ids)
        usage = next(
            item
            for item in graph["v1_compatibility"]["project_usage"]
            if item["project"] == str(repository)
        )
        self.assertEqual(usage["container_resource_ids"], [])
        self.assertEqual(usage["container_names"], [])
        self.assertEqual(usage["process_count"], 0)
        self.assertIsNone(usage["cpu_percent"])
        self.assertIsNone(usage["memory_bytes"])
        tree = next(
            item
            for item in graph["repository_trees"]
            if item["root_repository"]["repo_id"] == repo_id
        )
        self.assertEqual(tree["usage"]["process_count"], 0)
        self.assertIsNone(tree["usage"]["cpu_percent"])
        self.assertIsNone(tree["usage"]["memory_bytes"])
        self.assertNotIn(
            resource_id,
            {
                container_id
                for scope in tree["scopes"]
                for container_id in scope["container_resource_ids"]
            },
            "an association-problem resource must not contribute aggregate usage to its former family",
        )

    def test_stopped_but_present_container_remains_visible(self) -> None:
        repository = self.root / "stopped-owner"
        repository.mkdir()
        (repository / ".git").mkdir()
        full_id = "3" * 64

        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            repo_id = self._insert_repository(store, host_id, repository)
            self._observe(
                store,
                host_id,
                [
                    self._container(
                        full_id,
                        "stopped-owner-web",
                        project=repository,
                        status="Exited (0) 1 minute ago",
                    )
                ],
            )
            graph = store.inventory_v2()

        resource_id = deterministic_id(
            "docker-resource",
            deterministic_id("docker-engine", host_id, "default"),
            full_id,
        )
        projected = next(
            item
            for item in graph["v1_compatibility"]["docker"]["containers"]
            if item["host_resource_id"] == resource_id
        )
        self.assertEqual(projected["status"], "stopped")
        normalized = next(
            item
            for item in graph["resources"]["docker"]
            if item["docker_resource_id"] == resource_id
        )
        self.assertEqual(normalized["repo_id"], repo_id)
        usage = next(
            item
            for item in graph["v1_compatibility"]["project_usage"]
            if item["project"] == str(repository)
        )
        self.assertEqual(usage["container_resource_ids"], [resource_id])

    def test_only_observed_server_instances_enter_compatibility_server_collections(self) -> None:
        repository = self.root / "server-owner"
        repository.mkdir()
        (repository / ".git").mkdir()
        expired_id = "server-expired-orphan"
        managed_id = "server-managed-current"
        running_id = "server-running-current"
        timestamp = "2026-07-18T00:00:00Z"

        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            repo_id = self._insert_repository(store, host_id, repository)
            with store.immediate_transaction() as connection:
                for server_id, name in (
                    (expired_id, "expired-orphan"),
                    (managed_id, "managed-current"),
                    (running_id, "running-current"),
                ):
                    connection.execute(
                        """
                        INSERT INTO server_definitions(
                            server_definition_id, repo_id, name, role, cwd,
                            definition_fingerprint, generation, created_at, updated_at
                        ) VALUES (?, ?, ?, 'worker', ?, ?, 0, ?, ?)
                        """,
                        (
                            server_id,
                            repo_id,
                            name,
                            str(repository),
                            f"definition-{server_id}",
                            timestamp,
                            timestamp,
                        ),
                    )
                    lifecycle = "running" if server_id == running_id else "unobserved"
                    connection.execute(
                        """
                        INSERT INTO server_observations(
                            server_definition_id, lifecycle, pid, listener_host,
                            listener_port, sampled_at, observation_fingerprint
                        ) VALUES (?, ?, ?, '127.0.0.1', ?, ?, ?)
                        """,
                        (
                            server_id,
                            lifecycle,
                            4242 if server_id == running_id else None,
                            4242 if server_id == running_id else None,
                            timestamp,
                            f"observation-{server_id}",
                        ),
                    )
                connection.execute(
                    """
                    INSERT INTO leases(
                        lease_id, host_id, repo_id, server_definition_id, port,
                        owner, agent, purpose, status, expires_at, generation,
                        created_at, updated_at
                    ) VALUES (
                        'lease-expired-orphan', ?, ?, ?, 4241,
                        'fixture', 'fixture', 'validation', 'active',
                        '2000-01-01T00:00:00Z', 0, ?, ?
                    )
                    """,
                    (host_id, repo_id, expired_id, timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO port_assignments(
                        assignment_id, host_id, repo_id, server_name, port,
                        status, generation, created_at, updated_at
                    ) VALUES (
                        'assignment-managed-current', ?, ?, 'managed-current',
                        4243, 'active', 0, ?, ?
                    )
                    """,
                    (host_id, repo_id, timestamp, timestamp),
                )
            graph = store.inventory_v2()
            with store.read_transaction() as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT status FROM leases WHERE lease_id = 'lease-expired-orphan'"
                    ).fetchone()[0],
                    "active",
                    "pure inventory must not reconcile or mutate the expired durable row",
                )

        visible_server_ids = {
            item["id"] for item in graph["v1_compatibility"]["servers"]
        }
        self.assertNotIn(
            expired_id,
            visible_server_ids,
            "must-catch: an unobserved orphan with only an expired lease is history",
        )
        self.assertEqual(visible_server_ids, {running_id})
        self.assertEqual(graph["v1_compatibility"]["leases"], [])
        self.assertEqual(
            {
                item["server_definition_id"]
                for item in graph["resources"]["servers"]
            },
            {managed_id, running_id},
            "port-assignment control definitions remain available to normalized lease consumers",
        )
        usage = next(
            item
            for item in graph["v1_compatibility"]["project_usage"]
            if item["project"] == str(repository)
        )
        self.assertEqual(set(usage["server_ids"]), {running_id})

    def test_unavailable_snapshot_preserves_last_proved_presence(self) -> None:
        full_id = "4" * 64
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            self._observe(
                store,
                host_id,
                [self._container(full_id, "last-proved-present")],
            )
            self._observe(
                store,
                host_id,
                [],
                docker_available=False,
            )
            graph = store.inventory_v2()

        resource_id = deterministic_id(
            "docker-resource",
            deterministic_id("docker-engine", host_id, "default"),
            full_id,
        )
        self.assertFalse(graph["v1_compatibility"]["docker"]["available"])
        self.assertIn(
            resource_id,
            {
                item["host_resource_id"]
                for item in graph["v1_compatibility"]["docker"]["containers"]
            },
            "observer failure is not evidence that a previously present container disappeared",
        )
        self.assertIn(
            resource_id,
            {item["resource_id"] for item in graph["unassigned_resources"]},
        )

    def test_reappearing_container_returns_to_active_projection(self) -> None:
        full_id = "5" * 64
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            container = self._container(full_id, "returns-after-absence")
            self._observe(store, host_id, [container])
            self._observe(store, host_id, [])
            hidden = store.inventory_v2()
            self._observe(store, host_id, [container])
            restored = store.inventory_v2()

        resource_id = deterministic_id(
            "docker-resource",
            deterministic_id("docker-engine", host_id, "default"),
            full_id,
        )
        self.assertNotIn(
            resource_id,
            {
                item["host_resource_id"]
                for item in hidden["v1_compatibility"]["docker"]["containers"]
            },
        )
        self.assertIn(
            resource_id,
            {
                item["host_resource_id"]
                for item in restored["v1_compatibility"]["docker"]["containers"]
            },
        )
        self.assertIn(
            resource_id,
            {item["resource_id"] for item in restored["unassigned_resources"]},
        )

    def test_database_deadline_error_never_turns_prior_binding_into_absence(self) -> None:
        repository = self.root / "database-owner"
        repository.mkdir()
        (repository / ".git").mkdir()
        full_id = "d" * 64
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            self._insert_repository(store, host_id, repository)
            observed = self._container(full_id, "database-postgres", project=repository)
            observed["databases"] = [{"name": "app", "size_bytes": 1024}]
            self._observe(store, host_id, [observed])

            timed_out = self._container(full_id, "database-postgres", project=repository)
            timed_out["database_discovery_error"] = (
                "bounded host observation deadline expired before PostgreSQL discovery"
            )
            self._observe(store, host_id, [timed_out])
            graph = store.inventory_v2()
            with store.read_transaction() as connection:
                latest = connection.execute(
                    """
                    SELECT database_binding_id, available, error_code, error_message
                    FROM database_observations o
                    JOIN database_bindings b USING(database_binding_id)
                    WHERE b.database_name = 'app'
                    """
                ).fetchone()

        self.assertEqual(latest["available"], 0)
        self.assertEqual(latest["error_code"], "database_discovery_failed")
        self.assertIn("deadline", latest["error_message"])
        binding_id = str(latest["database_binding_id"])
        self.assertIn(
            binding_id,
            {
                item["database_binding_id"]
                for item in graph["resources"]["databases"]
            },
            "an observer failure is unknown presence, not positive absence",
        )
        self.assertIn(
            binding_id,
            {
                value
                for tree in graph["repository_trees"]
                for scope in tree["scopes"]
                for value in scope["database_binding_ids"]
            },
        )

    def test_positive_database_absence_is_history_not_a_current_tree_resource(
        self,
    ) -> None:
        repository = self.root / "database-absence-owner"
        repository.mkdir()
        (repository / ".git").mkdir()
        full_id = "e" * 64
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            self._insert_repository(store, host_id, repository)
            present = self._container(full_id, "database-absence", project=repository)
            present["databases"] = [{"name": "removed_app", "size_bytes": 2048}]
            self._observe(store, host_id, [present])
            with store.read_transaction() as connection:
                binding_id = str(
                    connection.execute(
                        """
                        SELECT database_binding_id FROM database_bindings
                        WHERE database_name = 'removed_app'
                        """
                    ).fetchone()[0]
                )

            absent = self._container(full_id, "database-absence", project=repository)
            absent["databases"] = []
            self._observe(store, host_id, [absent])
            graph = store.inventory_v2()
            with store.read_transaction() as connection:
                durable = connection.execute(
                    """
                    SELECT available, error_code FROM database_observations
                    WHERE database_binding_id = ?
                    """,
                    (binding_id,),
                ).fetchone()

        self.assertEqual(
            (durable["available"], durable["error_code"]),
            (0, "database_absent"),
        )
        self.assertNotIn(
            binding_id,
            {
                item["database_binding_id"]
                for item in graph["resources"]["databases"]
            },
        )
        self.assertNotIn(
            binding_id,
            {
                item["database_binding_id"]
                for item in graph["observations"]["databases"]
            },
        )
        self.assertNotIn(
            binding_id,
            {
                value
                for tree in graph["repository_trees"]
                for scope in tree["scopes"]
                for value in scope["database_binding_ids"]
            },
            "positive absence stays durable history without becoming a current project resource",
        )

    def test_unconfigured_nested_git_worktree_is_unassigned_not_given_inferred_owner(self) -> None:
        outer = self.root / "outer"
        nested = outer / "services" / "nested"
        nested_deploy = nested / "deploy"
        outer.mkdir()
        (outer / ".git").mkdir()
        nested.mkdir(parents=True)
        (nested / ".git").mkdir()
        nested_deploy.mkdir()
        full_id = "9" * 64

        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            outer_repo_id = self._insert_repository(store, host_id, outer)
            self._observe(
                store,
                host_id,
                [self._container(full_id, "nested-web", project=nested_deploy)],
            )
            graph = store.inventory_v2()

        resource_id = deterministic_id(
            "docker-resource",
            deterministic_id("docker-engine", host_id, "default"),
            full_id,
        )
        resource = next(
            item
            for item in graph["resources"]["docker"]
            if item["docker_resource_id"] == resource_id
        )
        self.assertIsNone(resource["repo_id"])
        self.assertEqual(
            {item["repo_id"] for item in graph["repositories"]}, {outer_repo_id}
        )
        unassigned = next(
            item
            for item in graph["unassigned_resources"]
            if item["host_resource_id"] == resource_id
        )
        self.assertEqual(unassigned["reason_code"], "missing_repo")

    def test_existing_non_git_path_is_not_mislabeled_as_a_conflicting_claim(self) -> None:
        non_repository = self.root / "plain-directory"
        non_repository.mkdir()
        full_id = "c" * 64
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            self._observe(
                store,
                host_id,
                [self._container(full_id, "plain-container", project=non_repository)],
            )
            graph = store.inventory_v2()
        unassigned = next(
            item for item in graph["unassigned_resources"] if item["display_name"] == "plain-container"
        )
        self.assertEqual(unassigned["reason_code"], "not_git")

    def test_symlinked_git_marker_is_not_positive_ownership_evidence(self) -> None:
        repository = self.root / "symlinked-marker"
        git_target = self.root / "git-target"
        repository.mkdir()
        git_target.mkdir()
        (repository / ".git").symlink_to(git_target, target_is_directory=True)
        full_id = "4" * 64
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            self._insert_repository(store, host_id, repository)
            self._observe(
                store,
                host_id,
                [self._container(full_id, "symlinked-marker-web", project=repository)],
            )
            graph = store.inventory_v2()

        resource_id = deterministic_id(
            "docker-resource",
            deterministic_id("docker-engine", host_id, "default"),
            full_id,
        )
        resource = next(
            item
            for item in graph["resources"]["docker"]
            if item["docker_resource_id"] == resource_id
        )
        self.assertIsNone(resource["repo_id"])
        unassigned = next(
            item
            for item in graph["unassigned_resources"]
            if item["host_resource_id"] == resource_id
        )
        self.assertEqual(unassigned["reason_code"], "not_git")
        self.assertEqual(unassigned["suggested_root"], str(repository))

    def test_regular_file_git_marker_remains_valid_worktree_evidence(self) -> None:
        repository = self.root / "linked-worktree"
        repository.mkdir()
        (repository / ".git").write_text(
            "gitdir: /fixture/worktrees/linked\n", encoding="utf-8"
        )
        full_id = "5" * 64
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            repo_id = self._insert_repository(store, host_id, repository)
            self._observe(
                store,
                host_id,
                [self._container(full_id, "linked-worktree-web", project=repository)],
            )
            graph = store.inventory_v2()

        resource_id = deterministic_id(
            "docker-resource",
            deterministic_id("docker-engine", host_id, "default"),
            full_id,
        )
        resource = next(
            item
            for item in graph["resources"]["docker"]
            if item["docker_resource_id"] == resource_id
        )
        self.assertEqual(resource["repo_id"], repo_id)

    def test_unique_short_alias_is_suppressed_but_ambiguous_prefixes_remain(self) -> None:
        prefix = "d" * 12
        full_id = prefix + "1" * 52
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            self._observe(store, host_id, [self._container(prefix, "fixture-one")])
            self._observe(
                store,
                host_id,
                [
                    self._container(prefix, "fixture-one"),
                    self._container(full_id, "fixture-one"),
                ],
            )
            graph = store.inventory_v2()
        retained = [
            item for item in graph["resources"]["docker"] if item["current_name"] == "fixture-one"
        ]
        projected = [
            item
            for item in graph["v1_compatibility"]["docker"]["containers"]
            if item["name"] == "fixture-one"
        ]
        self.assertEqual(len(retained), 2, "suppression must not delete retained history")
        self.assertEqual([item["id"] for item in projected], [full_id])

        ambiguous_home = self.root / "ambiguous-coordinator"
        full_a = prefix + "2" * 52
        full_b = prefix + "3" * 52
        with AccountStore.open_default(ambiguous_home) as store:
            host_id = store.ensure_local_host()
            self.home = ambiguous_home
            self._observe(store, host_id, [self._container(prefix, "ambiguous")])
            self._observe(
                store,
                host_id,
                [
                    self._container(prefix, "ambiguous"),
                    self._container(full_a, "ambiguous-a"),
                    self._container(full_b, "ambiguous-b"),
                ],
            )
            graph = store.inventory_v2()
        ids = {
            item["id"]
            for item in graph["v1_compatibility"]["docker"]["containers"]
            if item["id"] in {prefix, full_a, full_b}
        }
        self.assertEqual(ids, {prefix, full_a, full_b})

    def test_intermediate_length_id_is_not_a_canonical_alias_candidate(self) -> None:
        prefix = "7" * 12
        intermediate = prefix + "8" * 4
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            self._observe(store, host_id, [self._container(prefix, "legacy-short")])
            self._observe(
                store,
                host_id,
                [
                    self._container(prefix, "legacy-short"),
                    self._container(intermediate, "malformed-intermediate"),
                ],
            )
            graph = store.inventory_v2()
        projected_ids = {
            item["id"]
            for item in graph["v1_compatibility"]["docker"]["containers"]
            if item["id"] in {prefix, intermediate}
        }
        self.assertEqual(
            projected_ids,
            {prefix, intermediate},
            "must-catch: only a unique exact 64-hex expansion can suppress a 12-char alias",
        )


if __name__ == "__main__":
    unittest.main()
