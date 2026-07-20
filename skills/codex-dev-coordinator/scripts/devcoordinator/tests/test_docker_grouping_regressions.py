from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import dev_coordinator
from devcoordinator.host_observation import commit_host_inventory_observation
from devcoordinator.observer import SingleFlightObserver
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
    ) -> None:
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
        SingleFlightObserver(store).observe(
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

    def test_nested_compose_path_joins_enrolled_root_with_exact_resource_membership(self) -> None:
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
        membership = next(
            item for item in graph["memberships"] if item["host_resource_id"] == resource_id
        )
        self.assertEqual(membership["repo_id"], repo_id)
        usage = next(
            item
            for item in graph["v1_compatibility"]["project_usage"]
            if item["project"] == str(repository)
        )
        self.assertEqual(usage["container_names"], ["gf-v2-dev-api-1"])
        self.assertEqual(usage["container_resource_ids"], [resource_id])

    def test_available_empty_snapshot_hides_retained_resources_from_active_views(self) -> None:
        repository = self.root / "current-owner"
        repository.mkdir()
        (repository / ".git").mkdir()
        attributed_id = "1" * 64
        unassigned_id = "2" * 64

        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            repo_id = self._insert_repository(store, host_id, repository)
            attributed = self._container(
                attributed_id,
                "current-owner-web",
                project=repository,
            )
            attributed["stats"] = {
                "timestamp": "2026-07-18T00:00:00Z",
                "cpu_percent": 7.5,
                "memory_usage_bytes": 750,
            }
            self._observe(
                store,
                host_id,
                [
                    attributed,
                    self._container(unassigned_id, "historical-unassigned"),
                ],
            )
            engine_id = deterministic_id("docker-engine", host_id, "default")
            attributed_resource_id = deterministic_id(
                "docker-resource", engine_id, attributed_id
            )
            unassigned_resource_id = deterministic_id(
                "docker-resource", engine_id, unassigned_id
            )

            self._observe(store, host_id, [])
            # Prove the presence set, not a coincidental stopped lifecycle
            # filter, owns both membership and telemetry projection.
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE docker_observations SET lifecycle = 'running' "
                    "WHERE docker_resource_id = ?",
                    (attributed_resource_id,),
                )
            graph = store.inventory_v2()
            with store.read_transaction() as connection:
                retained_rows = {
                    "resources": connection.execute(
                        "SELECT COUNT(*) FROM docker_resources WHERE docker_resource_id IN (?, ?)",
                        (attributed_resource_id, unassigned_resource_id),
                    ).fetchone()[0],
                    "memberships": connection.execute(
                        "SELECT COUNT(*) FROM repository_memberships "
                        "WHERE resource_kind = 'container' AND host_resource_id = ?",
                        (attributed_resource_id,),
                    ).fetchone()[0],
                    "bindings": connection.execute(
                        "SELECT COUNT(*) FROM control_bindings "
                        "WHERE resource_kind = 'container' AND resource_id IN (?, ?)",
                        (attributed_resource_id, unassigned_resource_id),
                    ).fetchone()[0],
                }

        self.assertEqual(
            retained_rows,
            {"resources": 2, "memberships": 1, "bindings": 2},
            "current inventory filtering must not delete durable identity/history",
        )
        self.assertFalse(
            {attributed_resource_id, unassigned_resource_id}
            & {
                item["docker_resource_id"]
                for item in graph["resources"]["docker"]
            },
            "must-catch: absent retained identities are not current normalized resources",
        )
        self.assertNotIn(
            attributed_resource_id,
            {item["host_resource_id"] for item in graph["memberships"]},
            "must-catch: retained ownership history is not current membership",
        )
        self.assertFalse(
            {attributed_resource_id, unassigned_resource_id}
            & {item["resource_id"] for item in graph["control_bindings"]},
            "must-catch: an absent container cannot retain current action authority",
        )
        self.assertFalse(
            {attributed_resource_id, unassigned_resource_id}
            & {
                item["docker_resource_id"]
                for item in graph["observations"]["docker"]
            },
            "must-catch: latest-row history is not a current observation projection",
        )
        projected_ids = {
            item["host_resource_id"]
            for item in graph["v1_compatibility"]["docker"]["containers"]
        }
        self.assertNotIn(attributed_resource_id, projected_ids)
        self.assertNotIn(unassigned_resource_id, projected_ids)
        self.assertNotIn(
            unassigned_resource_id,
            {item["resource_id"] for item in graph["unassigned_resources"]},
            "an absent identity is not an active attach/retire target",
        )
        usage = next(
            item
            for item in graph["v1_compatibility"]["project_usage"]
            if item["project"] == str(repository)
        )
        self.assertEqual(usage["container_names"], [])
        self.assertEqual(usage["container_resource_ids"], [])
        self.assertIsNone(usage["cpu_percent"])
        self.assertIsNone(usage["memory_bytes"])
        self.assertEqual(
            next(
                item
                for item in graph["repositories"]
                if item["repo_id"] == repo_id
            )["canonical_root"],
            str(repository),
        )

    def test_stopped_but_present_container_remains_visible(self) -> None:
        repository = self.root / "stopped-owner"
        repository.mkdir()
        (repository / ".git").mkdir()
        full_id = "3" * 64

        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            self._insert_repository(store, host_id, repository)
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
        self.assertIn(
            resource_id,
            {item["docker_resource_id"] for item in graph["resources"]["docker"]},
            "false-positive guard: a stopped container physically present in the "
            "latest complete snapshot remains current",
        )
        self.assertIn(
            resource_id,
            {item["host_resource_id"] for item in graph["memberships"]},
        )
        self.assertIn(
            resource_id,
            {item["resource_id"] for item in graph["control_bindings"]},
        )
        usage = next(
            item
            for item in graph["v1_compatibility"]["project_usage"]
            if item["project"] == str(repository)
        )
        self.assertEqual(usage["container_resource_ids"], [resource_id])

    def test_archived_stopped_resources_leave_active_views_but_running_violations_remain(self) -> None:
        repository = self.root / "archived-resources"
        repository.mkdir()
        (repository / ".git").mkdir()
        stopped_container_full_id = "6" * 64
        running_container_full_id = "7" * 64
        stopped_server_id = "server-archived-stopped"
        running_server_id = "server-archived-running"
        timestamp = utc_timestamp()

        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            repo_id = self._insert_repository(store, host_id, repository)
            self._observe(
                store,
                host_id,
                [
                    self._container(
                        stopped_container_full_id,
                        "archived-stopped-container",
                        project=repository,
                        status="Exited (0) 1 minute ago",
                    ),
                    self._container(
                        running_container_full_id,
                        "archived-running-container",
                        project=repository,
                    ),
                ],
            )
            engine_id = deterministic_id("docker-engine", host_id, "default")
            stopped_container_id = deterministic_id(
                "docker-resource", engine_id, stopped_container_full_id
            )
            running_container_id = deterministic_id(
                "docker-resource", engine_id, running_container_full_id
            )
            with store.immediate_transaction() as connection:
                source_id = str(
                    connection.execute(
                        "SELECT source_id FROM coordinator_sources ORDER BY source_id LIMIT 1"
                    ).fetchone()[0]
                )
                for server_id, name, lifecycle in (
                    (stopped_server_id, "archived-stopped-server", "stopped"),
                    (running_server_id, "archived-running-server", "running"),
                ):
                    binding_id = "binding-" + server_id
                    connection.execute(
                        """
                        INSERT INTO server_definitions(
                            server_definition_id, repo_id, name, role, cwd,
                            definition_fingerprint, generation,
                            created_at, updated_at
                        ) VALUES (?, ?, ?, 'worker', ?, ?, 0, ?, ?)
                        """,
                        (
                            server_id,
                            repo_id,
                            name,
                            str(repository),
                            "definition-" + server_id,
                            timestamp,
                            timestamp,
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO server_observations(
                            server_definition_id, lifecycle, pid,
                            listener_host, listener_port,
                            sampled_at, observation_fingerprint
                        ) VALUES (?, ?, ?, '127.0.0.1', ?, ?, ?)
                        """,
                        (
                            server_id,
                            lifecycle,
                            4747 if lifecycle == "running" else None,
                            4747 if lifecycle == "running" else None,
                            timestamp,
                            "observation-" + server_id,
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO control_bindings(
                            binding_id, repo_id, resource_kind, resource_id,
                            source_id, capability, provenance, authority_state,
                            priority, generation, created_at, updated_at
                        ) VALUES (?, ?, 'server', ?, ?, 'lifecycle',
                                  'operator', 'authoritative', 100, 0, ?, ?)
                        """,
                        (
                            binding_id,
                            repo_id,
                            server_id,
                            source_id,
                            timestamp,
                            timestamp,
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO repository_memberships(
                            membership_id, repo_id, resource_kind,
                            host_resource_id, immutable_fingerprint,
                            control_binding_id, created_at
                        ) VALUES (?, ?, 'server', ?, ?, ?, ?)
                        """,
                        (
                            "membership-" + server_id,
                            repo_id,
                            server_id,
                            "sha256:" + ("a" * 64),
                            binding_id,
                            timestamp,
                        ),
                    )
                for resource_kind, resource_id in (
                    ("container", stopped_container_id),
                    ("container", running_container_id),
                    ("server", stopped_server_id),
                    ("server", running_server_id),
                ):
                    connection.execute(
                        """
                        INSERT INTO resource_retirements(
                            host_resource_id, resource_kind,
                            immutable_fingerprint, status, reason, actor,
                            started_at, retired_at, updated_at
                        ) VALUES (?, ?, ?, 'retired', 'fixture archive',
                                  'fixture', ?, ?, ?)
                        """,
                        (
                            resource_id,
                            resource_kind,
                            "sha256:" + ("b" * 64),
                            timestamp,
                            timestamp,
                            timestamp,
                        ),
                    )
            graph = store.inventory_v2()
            with store.read_transaction() as connection:
                durable = {
                    "retirements": connection.execute(
                        "SELECT COUNT(*) FROM resource_retirements WHERE host_resource_id IN (?, ?, ?, ?)",
                        (
                            stopped_container_id,
                            running_container_id,
                            stopped_server_id,
                            running_server_id,
                        ),
                    ).fetchone()[0],
                    "memberships": connection.execute(
                        "SELECT COUNT(*) FROM repository_memberships WHERE host_resource_id IN (?, ?, ?, ?)",
                        (
                            stopped_container_id,
                            running_container_id,
                            stopped_server_id,
                            running_server_id,
                        ),
                    ).fetchone()[0],
                }

        self.assertEqual(durable, {"retirements": 4, "memberships": 4})
        membership_ids = {item["host_resource_id"] for item in graph["memberships"]}
        binding_ids = {item["resource_id"] for item in graph["control_bindings"]}
        docker_resource_ids = {
            item["docker_resource_id"] for item in graph["resources"]["docker"]
        }
        server_resource_ids = {
            item["server_definition_id"] for item in graph["resources"]["servers"]
        }
        docker_observation_ids = {
            item["docker_resource_id"] for item in graph["observations"]["docker"]
        }
        server_observation_ids = {
            item["server_definition_id"] for item in graph["observations"]["servers"]
        }
        usage = next(
            item
            for item in graph["v1_compatibility"]["project_usage"]
            if item["project"] == str(repository)
        )

        for stopped_id, resources, observations in (
            (stopped_container_id, docker_resource_ids, docker_observation_ids),
            (stopped_server_id, server_resource_ids, server_observation_ids),
        ):
            self.assertNotIn(stopped_id, membership_ids)
            self.assertNotIn(stopped_id, binding_ids)
            self.assertNotIn(stopped_id, resources)
            self.assertNotIn(stopped_id, observations)
        self.assertNotIn(running_container_id, membership_ids)
        self.assertNotIn(running_server_id, membership_ids)
        self.assertIn(running_container_id, binding_ids)
        self.assertIn(running_server_id, binding_ids)
        self.assertIn(running_container_id, docker_resource_ids)
        self.assertIn(running_server_id, server_resource_ids)
        self.assertIn(running_container_id, docker_observation_ids)
        self.assertIn(running_server_id, server_observation_ids)
        self.assertEqual(usage["container_resource_ids"], [])
        self.assertEqual(usage["server_ids"], [])
        self.assertTrue(
            {running_container_id, running_server_id}.issubset(
                {item["resource_id"] for item in graph["lifecycle_violations"]}
            ),
            "false-positive guard: physically running archived resources remain visible as fence violations",
        )

    def test_expired_orphan_server_is_not_current_but_managed_and_running_rows_are(self) -> None:
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
        self.assertEqual(
            visible_server_ids,
            {managed_id, running_id},
            "false-positive guards retain desired managed and physically running servers",
        )
        self.assertEqual(graph["v1_compatibility"]["leases"], [])
        self.assertEqual(
            {
                item["server_definition_id"]
                for item in graph["resources"]["servers"]
            },
            {managed_id, running_id},
        )
        usage = next(
            item
            for item in graph["v1_compatibility"]["project_usage"]
            if item["project"] == str(repository)
        )
        self.assertEqual(set(usage["server_ids"]), {managed_id, running_id})

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
            with store.read_transaction() as connection:
                latest = connection.execute(
                    """
                    SELECT available, error_code, error_message
                    FROM database_observations o
                    JOIN database_bindings b USING(database_binding_id)
                    WHERE b.database_name = 'app'
                    """
                ).fetchone()

        self.assertEqual(latest["available"], 0)
        self.assertEqual(latest["error_code"], "database_discovery_failed")
        self.assertIn("deadline", latest["error_message"])

    def test_nested_git_worktree_is_not_collapsed_into_enrolled_outer_repository(self) -> None:
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
        membership = next(
            item for item in graph["memberships"] if item["host_resource_id"] == resource_id
        )
        nested_repo_id = deterministic_id("repository", host_id, str(nested))
        self.assertEqual(membership["repo_id"], nested_repo_id)
        self.assertNotEqual(membership["repo_id"], outer_repo_id)
        self.assertIn(
            str(nested),
            {item["canonical_root"] for item in graph["repositories"]},
        )

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

    def test_unobservable_inspect_preserves_prior_compose_membership_and_provenance(self) -> None:
        repository = self.root / "compose-owner"
        repository.mkdir()
        (repository / ".git").mkdir()
        full_id = "f" * 64
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            repo_id = self._insert_repository(store, host_id, repository)
            attributed = self._container(full_id, "compose-web", project=repository)
            attributed["container_health"] = "healthy"
            attributed["restart_policy"] = "always"
            attributed["labels"] = {
                "com.docker.compose.project.working_dir": str(repository),
                "fixture.label": "must-survive",
            }
            attributed["port_bindings"] = [
                {
                    "host_address": "127.0.0.1",
                    "host_port": 3000,
                    "container_port": 3000,
                    "protocol": "tcp",
                }
            ]
            self._observe(
                store,
                host_id,
                [attributed],
            )
            resource_id = deterministic_id(
                "docker-resource",
                deterministic_id("docker-engine", host_id, "default"),
                full_id,
            )
            with store.read_transaction() as connection:
                prior_observation = dict(
                    connection.execute(
                        "SELECT * FROM docker_observations WHERE docker_resource_id = ?",
                        (resource_id,),
                    ).fetchone()
                )
            degraded = self._container(full_id, "compose-web")
            degraded["inspection_observable"] = False
            degraded["metadata_source"] = "inspection_unavailable"
            self._observe(store, host_id, [degraded])
            with store.read_transaction() as connection:
                degraded_observation = dict(
                    connection.execute(
                        "SELECT * FROM docker_observations WHERE docker_resource_id = ?",
                        (resource_id,),
                    ).fetchone()
                )
                retained_ports = [
                    dict(row)
                    for row in connection.execute(
                        "SELECT * FROM docker_ports WHERE docker_resource_id = ? ORDER BY ordinal",
                        (resource_id,),
                    )
                ]
                retained_labels = {
                    str(row["name"]): str(row["value"])
                    for row in connection.execute(
                        "SELECT name, value FROM docker_labels WHERE docker_resource_id = ?",
                        (resource_id,),
                    )
                }
            graph = store.inventory_v2()

        membership = next(
            item for item in graph["memberships"] if item["host_resource_id"] == resource_id
        )
        binding = next(
            item for item in graph["control_bindings"] if item["resource_id"] == resource_id
        )
        self.assertEqual(membership["repo_id"], repo_id)
        self.assertEqual(binding["repo_id"], repo_id)
        self.assertEqual(binding["provenance"], "docker_labels")
        self.assertEqual(
            degraded_observation["ports_fingerprint"],
            prior_observation["ports_fingerprint"],
            "must-catch: an inspect failure is not evidence that published ports disappeared",
        )
        self.assertEqual(
            degraded_observation["labels_fingerprint"],
            prior_observation["labels_fingerprint"],
            "must-catch: an inspect failure is not evidence that Compose labels disappeared",
        )
        self.assertEqual(degraded_observation["health"], "healthy")
        self.assertEqual(degraded_observation["restart_policy"], "always")
        self.assertEqual(len(retained_ports), 1)
        self.assertEqual(retained_ports[0]["host_port"], 3000)
        self.assertEqual(retained_labels["fixture.label"], "must-survive")
        compatibility = next(
            item
            for item in graph["v1_compatibility"]["docker"]["containers"]
            if item["host_resource_id"] == resource_id
        )
        self.assertEqual(compatibility["ports"], "127.0.0.1:3000->3000/tcp")
        self.assertNotIn(
            resource_id,
            {
                item["resource_id"]
                for item in graph["unassigned_resources"]
                if item["status"] == "active"
            },
        )

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
