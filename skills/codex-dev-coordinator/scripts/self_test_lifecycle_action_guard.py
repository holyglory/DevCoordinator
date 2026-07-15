#!/usr/bin/env python3
"""Recall tests for normalized repository action fencing at public surfaces."""

from __future__ import annotations

import contextlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("dev_coordinator.py")
SPEC = importlib.util.spec_from_file_location("dev_coordinator_action_guard", SCRIPT)
assert SPEC and SPEC.loader
coordinator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = coordinator
SPEC.loader.exec_module(coordinator)

from devcoordinator.repository_lifecycle import ActionFencedError, RepositoryAction
from devcoordinator.store import AccountStore


def private_directory(path: Path) -> Path:
    path.mkdir(parents=True, mode=0o700)
    path.chmod(0o700)
    return path


def git_repository(path: Path) -> Path:
    private_directory(path)
    (path / ".git").mkdir(mode=0o700)
    return path.resolve()


def legacy_state(repository: Path, *, revision: int = 1) -> dict:
    return {
        "version": 2,
        "revision": revision,
        "created_at": "2026-07-14T09:00:00Z",
        "updated_at": "2026-07-14T10:00:00Z",
        "servers": {
            "legacy-web": {
                "id": "legacy-web",
                "name": "web",
                "project": str(repository),
                "cwd": str(repository),
                "argv": ["python3", "-c", "print('fixture')"],
                "port": 43100,
                "status": "stopped",
                "stopped_at": "2026-07-14T10:00:00Z",
            }
        },
        "leases": {},
        "port_assignments": {
            f"{repository}::web": {
                "project": str(repository),
                "name": "web",
                "port": 43100,
            }
        },
        "operations": {},
        "history": [],
        "docker": {"metadata": {}, "stats_history": {}, "last_commands": []},
    }


class LifecycleActionGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "coordinator"
        self.repository = git_repository(self.root / "repo")
        runtime_directory = private_directory(self.repository / ".codex")
        (runtime_directory / "dev-runtime.json").write_text(
            json.dumps(
                {
                    "servers": [
                        {
                            "name": "web",
                            "port": 43101,
                            "argv": ["python3", "-c", "print('dry-run')"],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        self.environment = mock.patch.dict(
            os.environ,
            {
                "CODEX_AGENT_COORDINATOR_HOME": str(self.home),
                "DEVCOORDINATOR_STATE_BACKEND": "sqlite",
            },
            clear=False,
        )
        self.environment.start()
        self.discovery = mock.patch.object(
            coordinator, "discover_same_uid_legacy_homes", return_value=[]
        )
        self.discovery.start()

    def tearDown(self) -> None:
        self.discovery.stop()
        self.environment.stop()
        self.temporary.cleanup()

    def install_repository(self) -> str:
        with coordinator.normalized_repository_action_guard(
            project=str(self.repository),
            agent="guard-test",
            action=RepositoryAction.LEASE,
        ) as repo_id:
            self.assertIsInstance(repo_id, str)
        return str(repo_id)

    def set_installation_status(self, status: str) -> tuple[str, int, int]:
        repo_id = self.install_repository()
        with AccountStore.open_default(self.home) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE repository_installations
                    SET status = ?, startup_fenced = 1, generation = generation + 1
                    WHERE repo_id = ?
                    """,
                    (status, repo_id),
                )
            with store.read_transaction() as connection:
                revision = int(
                    connection.execute(
                        "SELECT state_revision FROM schema_metadata WHERE singleton = 1"
                    ).fetchone()[0]
                )
                operation_count = int(
                    connection.execute("SELECT count(*) FROM operations").fetchone()[0]
                )
        return repo_id, revision, operation_count

    def assert_store_unchanged(self, revision: int, operation_count: int) -> None:
        with AccountStore.open_default(self.home) as store:
            with store.read_transaction() as connection:
                self.assertEqual(
                    int(
                        connection.execute(
                            "SELECT state_revision FROM schema_metadata WHERE singleton = 1"
                        ).fetchone()[0]
                    ),
                    revision,
                )
                self.assertEqual(
                    int(connection.execute("SELECT count(*) FROM operations").fetchone()[0]),
                    operation_count,
                )

    def mutation_calls(self):
        base = {"agent": "guard-test", "project": str(self.repository)}
        return {
            "project_start": lambda: coordinator.coordinated_project_runtime_start(
                {**base, "dry_run": True}
            ),
            "project_restart": lambda: coordinator.coordinated_project_runtime_restart(
                {**base, "dry_run": True}
            ),
            "server_start": lambda: coordinator.coordinated_start_server(
                {
                    **base,
                    "name": "web",
                    "argv": ["python3", "-c", "print('blocked')"],
                }
            ),
            "server_register": lambda: coordinator.coordinated_register_server(
                {**base, "name": "web", "port": 43101}
            ),
            "server_restart": lambda: coordinator.coordinated_restart_server(
                {**base, "name": "web"}
            ),
            "docker_start": lambda: coordinator.coordinated_run_docker(
                ["docker", "start", "fixture"],
                project=str(self.repository),
                agent="guard-test",
                container="fixture",
            ),
            "docker_restart": lambda: coordinator.coordinated_run_docker(
                ["docker", "restart", "fixture"],
                project=str(self.repository),
                agent="guard-test",
                container="fixture",
            ),
            "compose_up": lambda: coordinator.coordinated_run_docker(
                ["docker", "compose", "up", "-d"],
                cwd=str(self.repository),
                project=str(self.repository),
                agent="guard-test",
            ),
            "docker_register": lambda: coordinator.coordinated_register_docker_metadata(
                {**base, "container": "fixture"}
            ),
            "port_lease": lambda: coordinator.coordinated_lease_port(
                {**base, "range": "43110-43110"}
            ),
            "port_assign": lambda: coordinator.coordinated_assign_port(
                {**base, "name": "web", "port": 43110}
            ),
            "port_relocate": lambda: coordinator.coordinated_relocate_port_assignment(
                {
                    "agent": "guard-test",
                    "old_project": str(self.repository),
                    "new_project": str(self.repository),
                    "name": "web",
                    "port": 43101,
                    "lease_id": "fixture-lease",
                }
            ),
        }

    def test_disabling_and_disabled_block_every_start_like_family_before_old_state_or_host(self) -> None:
        for status in ("disabling", "disabled"):
            with self.subTest(status=status):
                _repo_id, revision, operation_count = self.set_installation_status(status)

                @contextlib.contextmanager
                def forbidden_locked_state():
                    self.fail("disabled action reached the legacy compatibility lock")
                    yield {}

                def forbidden_external(*_args, **_kwargs):
                    self.fail("disabled action reached a host-side operation")

                patches = (
                    mock.patch.object(coordinator, "locked_state", forbidden_locked_state),
                    mock.patch.object(coordinator, "resolve_docker_executable", forbidden_external),
                    mock.patch.object(coordinator, "inspect_docker_container", forbidden_external),
                    mock.patch.object(coordinator, "docker_container_operation_identity", forbidden_external),
                    mock.patch.object(coordinator, "execute_docker_subprocess", forbidden_external),
                    mock.patch.object(coordinator, "start_process", forbidden_external),
                )
                with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
                    for family, invoke in self.mutation_calls().items():
                        with self.subTest(status=status, family=family):
                            with self.assertRaisesRegex(ActionFencedError, "fence"):
                                invoke()
                            self.assert_store_unchanged(revision, operation_count)

            # Each status needs a fresh store because a disabled installation
            # can only be restored by the explicit reinstall journey.
            if status == "disabling":
                self.home = self.root / "coordinator-disabled"
                os.environ["CODEX_AGENT_COORDINATOR_HOME"] = str(self.home)

    def test_fresh_first_use_installs_exactly_one_repo_and_actual_lease_assignment(self) -> None:
        with mock.patch.object(coordinator, "port_available", return_value=True):
            lease = coordinator.coordinated_lease_port(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                    "range": "43110-43110",
                }
            )
            assignment = coordinator.coordinated_assign_port(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                    "name": "api",
                    "port": 43111,
                }
            )
        self.assertEqual(lease["port"], 43110)
        self.assertEqual(assignment["port"], 43111)
        with AccountStore.open_default(self.home) as store:
            with store.read_transaction() as connection:
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM repositories").fetchone()[0], 1
                )
                installation = connection.execute(
                    "SELECT status, startup_fenced FROM repository_installations"
                ).fetchone()
                self.assertEqual(tuple(installation), ("installed", 0))
                self.assertEqual(
                    connection.execute(
                        "SELECT count(*) FROM operations WHERE kind LIKE 'guard:%' AND status = 'running'"
                    ).fetchone()[0],
                    0,
                )

    def test_guard_operation_coexists_with_actual_project_start_and_register_journals(self) -> None:
        project_result = coordinator.coordinated_project_runtime_start(
            {
                "agent": "guard-test",
                "project": str(self.repository),
                "dry_run": True,
            }
        )
        self.assertEqual(project_result["action"], "start")
        healthy = {
            "ok": True,
            "classification": "healthy",
            "identity": {"observable": True, "matches": True},
        }
        with mock.patch.object(
            coordinator, "resolve_registration_pid", return_value=(None, None)
        ), mock.patch.object(coordinator, "wait_for_health", return_value=healthy):
            registered = coordinator.coordinated_register_server(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                    "name": "registered",
                    "port": 43112,
                    "url": "http://127.0.0.1:43112",
                }
            )
        self.assertEqual(registered["name"], "registered")
        with AccountStore.open_default(self.home) as store:
            with store.read_transaction() as connection:
                rows = list(
                    connection.execute(
                        "SELECT kind, status FROM operations ORDER BY created_at, operation_id"
                    )
                )
        self.assertTrue(any(row["kind"] == "project.start" for row in rows))
        self.assertTrue(any(row["kind"] == "server.register" for row in rows))
        self.assertFalse(any(row["status"] == "running" for row in rows))

    def test_start_policy_restore_failure_releases_permit_before_legacy_or_host_start(self) -> None:
        @contextlib.contextmanager
        def forbidden_locked_state():
            self.fail("failed startup-policy restoration reached compatibility state")
            yield {}

        with mock.patch.object(
            coordinator.RepositoryLifecycle,
            "restore_startup_policies_for_start",
            side_effect=RuntimeError("fixture restoration failed"),
        ) as restore, mock.patch.object(
            coordinator, "locked_state", forbidden_locked_state
        ), mock.patch.object(
            coordinator, "start_process", side_effect=AssertionError("host start reached")
        ):
            with self.assertRaisesRegex(RuntimeError, "fixture restoration failed"):
                coordinator.coordinated_project_runtime_start(
                    {
                        "agent": "guard-test",
                        "project": str(self.repository),
                        "dry_run": True,
                    }
                )
        restore.assert_called_once()
        with AccountStore.open_default(self.home) as store:
            with store.read_transaction() as connection:
                operations = list(
                    connection.execute(
                        "SELECT kind, status FROM operations ORDER BY created_at, operation_id"
                    )
                )
        self.assertEqual(
            [(row["kind"], row["status"]) for row in operations],
            [("guard:start", "failed")],
        )

    def test_direct_lease_before_observe_imports_legacy_truth_first(self) -> None:
        source = private_directory(self.root / "legacy-source")
        state_path = source / "state.json"
        state_path.write_text(json.dumps(legacy_state(self.repository)), encoding="utf-8")
        state_path.chmod(0o600)
        with mock.patch.object(
            coordinator, "discover_same_uid_legacy_homes", return_value=[source]
        ), mock.patch.object(coordinator, "port_available", return_value=True):
            lease = coordinator.coordinated_lease_port(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                    "range": "43110-43110",
                }
            )
        self.assertEqual(lease["port"], 43110)
        with AccountStore.open_default(self.home) as store:
            with store.read_transaction() as connection:
                imported = connection.execute(
                    """
                    SELECT count(*) FROM coordinator_sources
                    WHERE canonical_home = ? AND captured_sha256 IS NOT NULL
                    """,
                    (str(source),),
                ).fetchone()[0]
                definitions = connection.execute(
                    "SELECT count(*) FROM server_definitions WHERE name = 'web'"
                ).fetchone()[0]
        self.assertEqual(imported, 1)
        self.assertEqual(definitions, 1)

    def test_bootstrap_keeps_existing_live_blocker_when_importing_pending_clean_source(self) -> None:
        live_source = private_directory(self.root / "legacy-live")
        clean_source = private_directory(self.root / "legacy-clean")
        other = git_repository(self.root / "other")
        live = legacy_state(self.repository)
        live["servers"]["legacy-web"].update(
            {
                "status": "running",
                "pid": 42001,
                "updated_at": "2026-07-14T11:00:00Z",
                "stopped_at": None,
            }
        )
        live["servers"]["legacy-web-conflict"] = {
            "id": "legacy-web-conflict",
            "name": "web",
            "project": str(self.repository),
            "cwd": str(self.repository),
            "argv": ["python3", "-c", "print('contradictory live fixture')"],
            "port": 43100,
            "status": "running",
            "pid": 42002,
            "updated_at": "2026-07-14T11:01:00Z",
        }
        clean = legacy_state(other, revision=2)
        clean["servers"]["legacy-web"]["port"] = 43120
        clean["port_assignments"] = {
            f"{other}::web": {
                "project": str(other),
                "name": "web",
                "port": 43120,
            }
        }
        for home, state in ((live_source, live), (clean_source, clean)):
            path = home / "state.json"
            path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
            path.chmod(0o600)

        with AccountStore.open_default(self.home) as store:
            initial = store.import_legacy_homes(
                [live_source], private_directory(self.root / "initial-backup")
            )
            self.assertEqual(
                {
                    item.kind: item.severity for item in initial.conflicts
                }["server_definition_conflict"],
                "blocking",
            )
            self.assertEqual(store.metadata.migration_state, "conflicted")
            with mock.patch.object(
                coordinator,
                "discover_same_uid_legacy_homes",
                return_value=[live_source, clean_source],
            ):
                report = coordinator.bootstrap_legacy_import(
                    store,
                    explicit_homes=[live_source, clean_source],
                    backup_root=str(private_directory(self.root / "pending-backup")),
                )
            self.assertTrue(report["attempted"])
            self.assertTrue(report["committed"])
            self.assertEqual(report["source_count"], 2, report)
            self.assertEqual(report["blocking_conflict_count"], 1)
            self.assertIn("server_definition_conflict", report["conflict_kinds"])
            self.assertEqual(report["reclassified_conflict_count"], 1)
            self.assertEqual(store.metadata.migration_state, "conflicted")
            self.assertEqual(
                store.connection.execute(
                    "SELECT COUNT(*) FROM legacy_imports"
                ).fetchone()[0],
                2,
            )

    def test_explicit_observe_reconciles_old_stopped_definition_fence(self) -> None:
        source = private_directory(self.root / "legacy-historical")
        state = legacy_state(self.repository)
        state["servers"]["legacy-web"].update(
            {
                "argv": ["python3", "-c", "print('old stopped fixture')"],
                "updated_at": "2026-07-14T10:00:00Z",
                "stopped_at": "2026-07-14T10:00:00Z",
            }
        )
        state["servers"]["legacy-web-new"] = {
            "id": "legacy-web-new",
            "name": "web",
            "project": str(self.repository),
            "cwd": str(self.repository),
            "argv": ["python3", "-c", "print('new stopped fixture')"],
            "port": 43100,
            "status": "stopped",
            "updated_at": "2026-07-14T11:00:00Z",
            "stopped_at": "2026-07-14T11:00:00Z",
        }
        state_path = source / "state.json"
        state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
        state_path.chmod(0o600)
        with AccountStore.open_default(self.home) as store:
            imported = store.import_legacy_homes(
                [source], private_directory(self.root / "historical-backup")
            )
            self.assertEqual(
                {
                    item.kind: item.severity for item in imported.conflicts
                }["server_definition_conflict"],
                "warning",
            )
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE migration_conflicts
                    SET severity='blocking', evidence_json='{"classifier_version":1}'
                    WHERE conflict_kind='server_definition_conflict'
                    """
                )
                connection.execute(
                    """
                    UPDATE control_bindings
                    SET authority_state='conflicting', provenance='legacy_conflict',
                        priority=0
                    WHERE resource_kind='server'
                    """
                )
                connection.execute(
                    "UPDATE schema_metadata SET migration_state='conflicted' WHERE singleton=1"
                )

        empty_sample = {
            "sampled_at": "2026-07-15T12:00:00Z",
            "inventory": {
                "servers": [],
                "docker": {"available": None, "containers": [], "postgres": []},
                "postgres": [],
                "backups": [],
            },
        }
        with mock.patch.object(
            coordinator,
            "discover_same_uid_legacy_homes",
            return_value=[source],
        ), mock.patch.object(
            coordinator,
            "sample_host_inventory_for_normalized_store",
            return_value=empty_sample,
        ):
            result = coordinator.coordinated_observe_host(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                    "legacy_home": [str(source)],
                    "max_age_seconds": 0,
                    "no_docker": True,
                }
            )
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["imported"]["reclassified_conflict_count"], 1)
        self.assertEqual(result["imported"]["blocking_conflict_count"], 0)
        with AccountStore.open_default(self.home) as store:
            self.assertEqual(store.metadata.migration_state, "ready")
            self.assertEqual(
                {
                    tuple(row)
                    for row in store.connection.execute(
                        """
                        SELECT authority_state, provenance FROM control_bindings
                        WHERE resource_kind='server'
                        """
                    )
                },
                {("authoritative", "normalized_historical_import")},
            )

    def test_project_start_before_observe_blocks_on_uncommitted_legacy_bootstrap(self) -> None:
        report = {
            "attempted": True,
            "committed": False,
            "blocking_conflict_count": 1,
            "late_writer_sources": [],
        }

        @contextlib.contextmanager
        def forbidden_locked_state():
            self.fail("project start reached compatibility state before legacy bootstrap")
            yield {}

        with mock.patch.object(
            coordinator, "bootstrap_legacy_import", return_value=report
        ), mock.patch.object(coordinator, "locked_state", forbidden_locked_state):
            with self.assertRaisesRegex(ActionFencedError, "blocking migration conflicts"):
                coordinator.coordinated_project_runtime_start(
                    {
                        "agent": "guard-test",
                        "project": str(self.repository),
                        "dry_run": True,
                    }
                )
        with AccountStore.open_default(self.home) as store:
            with store.read_transaction() as connection:
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM repositories").fetchone()[0], 0
                )
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM operations").fetchone()[0], 0
                )

    def test_late_legacy_writer_is_caught_before_next_mutation_with_clean_control(self) -> None:
        source = private_directory(self.root / "legacy-source")
        state_path = source / "state.json"
        state_path.write_text(json.dumps(legacy_state(self.repository)), encoding="utf-8")
        state_path.chmod(0o600)
        with mock.patch.object(
            coordinator, "discover_same_uid_legacy_homes", return_value=[source]
        ), mock.patch.object(coordinator, "port_available", return_value=True):
            coordinator.coordinated_lease_port(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                    "range": "43110-43110",
                }
            )
            control = coordinator.coordinated_assign_port(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                    "name": "control",
                    "port": 43111,
                }
            )
        self.assertEqual(control["port"], 43111)
        state_path.write_text(
            json.dumps(legacy_state(self.repository, revision=2)), encoding="utf-8"
        )
        state_path.chmod(0o600)

        @contextlib.contextmanager
        def forbidden_locked_state():
            self.fail("late-writer action reached compatibility state mutation")
            yield {}

        with mock.patch.object(coordinator, "locked_state", forbidden_locked_state):
            with self.assertRaisesRegex(ActionFencedError, "retired legacy coordinator"):
                coordinator.coordinated_assign_port(
                    {
                        "agent": "guard-test",
                        "project": str(self.repository),
                        "name": "must-not-exist",
                        "port": 43112,
                    }
                )
        with AccountStore.open_default(self.home) as store:
            with store.read_transaction() as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT count(*) FROM port_assignments WHERE server_name = 'must-not-exist'"
                    ).fetchone()[0],
                    0,
                )

    def test_later_observation_surfaces_a_start_fence_violation_after_the_preflight_window(self) -> None:
        source = private_directory(self.root / "legacy-source")
        state_path = source / "state.json"
        state_path.write_text(json.dumps(legacy_state(self.repository)), encoding="utf-8")
        state_path.chmod(0o600)
        with mock.patch.object(
            coordinator, "discover_same_uid_legacy_homes", return_value=[source]
        ):
            permitted = coordinator.coordinated_project_runtime_start(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                    "dry_run": True,
                }
            )
        self.assertEqual(permitted["action"], "start")

        # The normalized preflight is deliberately point-in-time: the action does
        # not hold the coordinator state lock while host work runs. Model the
        # residual race by completing the repository fence, then receiving a
        # later running observation for the exact server that crossed it.
        with AccountStore.open_default(self.home) as store:
            with store.immediate_transaction(revision_kind="observation") as connection:
                timestamp = coordinator.utc_timestamp()
                connection.execute(
                    """
                    UPDATE port_assignments
                    SET status = 'inactive', deactivated_at = ?, updated_at = ?
                    """,
                    (timestamp, timestamp),
                )
                connection.execute(
                    """
                    UPDATE startup_policies
                    SET current_value = desired_disabled_value,
                        generation = generation + 1, updated_at = ?
                    """,
                    (timestamp,),
                )
                connection.execute(
                    """
                    UPDATE repository_installations
                    SET status = 'disabled', startup_fenced = 1,
                        generation = generation + 1, disabled_at = ?
                    """,
                    (timestamp,),
                )
                connection.execute(
                    """
                    UPDATE server_observations
                    SET lifecycle = 'running', pid = 98765,
                        process_start_time = 'fixture-start',
                        process_fingerprint = 'fixture-process',
                        listener_host = '127.0.0.1', listener_port = 43100,
                        listener_observable = 1, sampled_at = ?
                    """,
                    (timestamp,),
                )
            inventory = store.inventory_v2()

        self.assertFalse(inventory["repositories"])
        self.assertEqual(len(inventory["lifecycle_violations"]), 1)
        violation = inventory["lifecycle_violations"][0]
        self.assertEqual(violation["resource_kind"], "server")
        self.assertEqual(violation["reason_code"], "start_fence_violated")
        self.assertTrue(violation["lifecycle_violation"])
        self.assertFalse(violation["can_attach"])
        self.assertFalse(violation["can_retire"])
        self.assertEqual(violation["corrective_action"], "repository_decommission")
        self.assertIn("Run repository removal again", violation["recommended_next_step"])

    def test_explicit_legacy_test_bridge_does_not_require_normalized_installation(self) -> None:
        os.environ["DEVCOORDINATOR_STATE_BACKEND"] = coordinator.LEGACY_JSON_BACKEND
        with coordinator.normalized_repository_action_guard(
            project=str(self.root / "not-a-git-repository"),
            agent="guard-test",
            action=RepositoryAction.START,
        ) as repo_id:
            self.assertIsNone(repo_id)
        self.assertFalse((self.home / "coordinator.sqlite3").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
