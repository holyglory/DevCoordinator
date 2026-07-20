#!/usr/bin/env python3
"""Deterministic integration tests for archive cleanup and tombstone safety.

These tests deliberately keep every host-facing boundary fake except for the
linked-worktree test.  That test creates its own Git repository, disables
system/global Git configuration, fixes the Git executable, and stubs procfs
and mount discovery so developer-machine state cannot decide the result.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Iterator, Mapping
import unittest
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import devcoordinator.cleanup_lifecycle as cleanup  # noqa: E402
from devcoordinator.cleanup_lifecycle import (  # noqa: E402
    CleanupBlocked,
    CleanupError,
    CleanupLifecycle,
    DockerCleanupBackend,
    PlanDriftError,
)
from devcoordinator.repository_lifecycle import (  # noqa: E402
    ExactResourceRef,
    ResourceKind,
    ResourceObservation,
    RunningState,
)
from devcoordinator.store import AccountStore, utc_timestamp  # noqa: E402


HOST_ID = "cleanup-host"
SOURCE_ID = "cleanup-source"
REPO_ID = "cleanup-project"
SERVER_ID = "cleanup-server"
CONTAINER_RESOURCE_ID = "cleanup-container"
CONTAINER_ID = "a" * 64
FIXED_GIT = "/usr/bin/git"
_OPEN_TEST_STORES: list[AccountStore] = []


class SimulatedCrash(BaseException):
    """Model process death after an external effect but before phase commit."""


class ExactStoppedAdapter:
    def __init__(self) -> None:
        self.running_state = RunningState.STOPPED
        self.listener_active: bool | None = False
        self.identity_observable = True
        self.ownership_observable = True

    def observe_exact(self, target: ExactResourceRef) -> ResourceObservation:
        return ResourceObservation(
            resource_id=target.resource_id,
            kind=target.kind,
            identity_observable=self.identity_observable,
            immutable_fingerprint=target.immutable_fingerprint,
            ownership_observable=self.ownership_observable,
            ownership_fingerprint=target.ownership_fingerprint,
            running_state=self.running_state,
            listener_active=(
                self.listener_active if target.kind is ResourceKind.SERVER else None
            ),
            container_running=(
                self.running_state is RunningState.RUNNING
                if target.kind is ResourceKind.CONTAINER
                else None
            ),
            policies={},
        )


class FakeDockerBackend:
    def __init__(self) -> None:
        self.present = True
        self.running = False
        self.status = "exited"
        self.mounts: list[dict[str, Any]] = []
        self.labels: dict[str, str] = {}
        self.crash_after_remove_effect = False
        self.inspect_calls: list[str] = []
        self.remove_calls: list[str] = []

    def inspect(self, full_container_id: str) -> Mapping[str, Any] | None:
        self.inspect_calls.append(full_container_id)
        if full_container_id != CONTAINER_ID:
            raise AssertionError("cleanup inspected a non-exact Docker identity")
        if not self.present:
            return None
        return {
            "full_container_id": CONTAINER_ID,
            "running": self.running,
            "status": self.status,
            "mounts": list(self.mounts),
            "labels": dict(self.labels),
        }

    def remove(self, full_container_id: str) -> Mapping[str, Any]:
        self.remove_calls.append(full_container_id)
        if full_container_id != CONTAINER_ID:
            raise AssertionError("cleanup removed a non-exact Docker identity")
        self.present = False
        if self.crash_after_remove_effect:
            self.crash_after_remove_effect = False
            raise SimulatedCrash("after docker rm, before durable phase success")
        return {"full_container_id": full_container_id, "already_absent": False}


def _blocker_codes(plan: Any) -> set[str]:
    return {str(item.get("code")) for item in plan.blockers}


@contextmanager
def _temporary_root(prefix: str) -> Iterator[Path]:
    # The repository path guard rejects operator-supplied symlink components.
    # Canonicalize only this test-created root, then derive every fixture path.
    with tempfile.TemporaryDirectory(prefix=prefix, dir=Path.home()) as raw:
        root = Path(raw).resolve(strict=True)
        try:
            yield root
        finally:
            for store in tuple(_OPEN_TEST_STORES):
                try:
                    store.path.relative_to(root)
                except ValueError:
                    continue
                store.close()
                _OPEN_TEST_STORES.remove(store)


def _open_store(root: Path) -> AccountStore:
    state = root / "state"
    state.mkdir(mode=0o700, parents=True)
    store = AccountStore.open(state / "coordinator.sqlite3")
    _OPEN_TEST_STORES.append(store)
    return store


def _seed_project(
    store: AccountStore,
    project_root: Path,
    *,
    repo_id: str = REPO_ID,
    display_name: str = "Cleanup Project",
    archived: bool,
) -> None:
    now = utc_timestamp()
    with store.immediate_transaction() as connection:
        if connection.execute("SELECT 1 FROM hosts WHERE host_id = ?", (HOST_ID,)).fetchone() is None:
            connection.execute(
                "INSERT INTO hosts VALUES (?, ?, 'linux', 'localhost', ?, ?)",
                (HOST_ID, "cleanup-machine", now, now),
            )
            connection.execute(
                """
                INSERT INTO coordinator_sources(
                    source_id, host_id, canonical_home, state_path,
                    effective_uid, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'imported', ?, ?)
                """,
                (
                    SOURCE_ID,
                    HOST_ID,
                    str(root := project_root.parent / "source"),
                    str(root / "state.json"),
                    os.geteuid(),
                    now,
                    now,
                ),
            )
        connection.execute(
            """
            INSERT INTO repositories(
                repo_id, host_id, canonical_root, display_name, state,
                generation, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'active', 0, ?, ?)
            """,
            (repo_id, HOST_ID, str(project_root), display_name, now, now),
        )
        connection.execute(
            """
            INSERT INTO repository_installations(
                repo_id, status, startup_fenced, generation, operation_id,
                disabled_at, reason, actor, updated_at
            ) VALUES (?, ?, ?, 1, NULL, ?, ?, 'archive-operator', ?)
            """,
            (
                repo_id,
                "disabled" if archived else "installed",
                1 if archived else 0,
                now if archived else None,
                "test archive" if archived else None,
                now,
            ),
        )


def _insert_archive_operation(
    connection: Any,
    *,
    operation_id: str,
    repo_id: str,
) -> None:
    now = utc_timestamp()
    connection.execute(
        """
        INSERT INTO operations(
            operation_id, repo_id, kind, status, phase, generation,
            request_fingerprint, owner_uid, actor, created_at, updated_at
        ) VALUES (?, ?, 'resource_retire', 'succeeded', 'complete', 0,
                  ?, ?, 'archive-operator', ?, ?)
        """,
        (operation_id, repo_id, f"request:{operation_id}", os.geteuid(), now, now),
    )


def _seed_server(store: AccountStore, project_root: Path) -> None:
    _seed_project(store, project_root, archived=False)
    now = utc_timestamp()
    archive_operation = "archive-server-operation"
    source_resource = "source-server"
    binding = "binding-server"
    with store.immediate_transaction() as connection:
        connection.execute(
            """
            INSERT INTO source_resources(
                source_resource_id, source_id, resource_kind, native_id,
                repo_id, payload_sha256, created_at
            ) VALUES (?, ?, 'server', ?, ?, 'payload:server', ?)
            """,
            (source_resource, SOURCE_ID, SERVER_ID, REPO_ID, now),
        )
        connection.execute(
            """
            INSERT INTO server_definitions(
                server_definition_id, repo_id, name, role, cwd, log_path,
                definition_fingerprint, generation, created_at, updated_at
            ) VALUES (?, ?, 'api-server', 'web', ?, ?, 'definition:server', 0, ?, ?)
            """,
            (
                SERVER_ID,
                REPO_ID,
                str(project_root),
                str(project_root / "server.log"),
                now,
                now,
            ),
        )
        connection.execute(
            "INSERT INTO server_command_arguments VALUES (?, 0, 'python3')",
            (SERVER_ID,),
        )
        connection.execute(
            "INSERT INTO server_environment VALUES (?, 'SECRET_NAME', 'redacted-fixture')",
            (SERVER_ID,),
        )
        connection.execute(
            """
            INSERT INTO server_observations(
                server_definition_id, source_resource_id, lifecycle, pid,
                listener_observable, stopped_at, stopped_reason, sampled_at,
                observation_fingerprint
            ) VALUES (?, ?, 'stopped', NULL, 1, ?, 'archived', ?, 'observation:server')
            """,
            (SERVER_ID, source_resource, now, now),
        )
        connection.execute(
            """
            INSERT INTO control_bindings(
                binding_id, repo_id, source_resource_id, resource_kind,
                resource_id, source_id, capability, provenance,
                authority_state, priority, generation, created_at, updated_at
            ) VALUES (?, ?, ?, 'server', ?, ?, 'process', 'test',
                      'authoritative', 10, 0, ?, ?)
            """,
            (binding, REPO_ID, source_resource, SERVER_ID, SOURCE_ID, now, now),
        )
        connection.execute(
            """
            INSERT INTO repository_memberships(
                membership_id, repo_id, resource_kind, host_resource_id,
                immutable_fingerprint, control_binding_id, created_at
            ) VALUES ('membership-server', ?, 'server', ?, 'immutable:server', ?, ?)
            """,
            (REPO_ID, SERVER_ID, binding, now),
        )
        connection.execute(
            """
            INSERT INTO leases(
                lease_id, host_id, repo_id, server_definition_id, port,
                owner, agent, purpose, status, generation, created_at, updated_at
            ) VALUES ('lease-server', ?, ?, ?, 43111, 'tester', 'tester',
                      'server', 'active', 0, ?, ?)
            """,
            (HOST_ID, REPO_ID, SERVER_ID, now, now),
        )
        connection.execute(
            """
            INSERT INTO port_assignments(
                assignment_id, host_id, repo_id, server_name, port, status,
                generation, created_at, updated_at
            ) VALUES ('assignment-server', ?, ?, 'api-server', 43111,
                      'active', 0, ?, ?)
            """,
            (HOST_ID, REPO_ID, now, now),
        )
        _insert_archive_operation(
            connection, operation_id=archive_operation, repo_id=REPO_ID
        )
        connection.execute(
            """
            INSERT INTO resource_retirements(
                host_resource_id, resource_kind, immutable_fingerprint,
                status, operation_id, reason, actor, started_at, retired_at, updated_at
            ) VALUES (?, 'server', 'immutable:server', 'retired', ?,
                      'archive server', 'archive-operator', ?, ?, ?)
            """,
            (SERVER_ID, archive_operation, now, now, now),
        )


def _seed_container(store: AccountStore, project_root: Path) -> None:
    _seed_project(store, project_root, archived=False)
    now = utc_timestamp()
    source_resource = "source-container"
    binding = "binding-container"
    archive_operation = "archive-container-operation"
    with store.immediate_transaction() as connection:
        connection.execute(
            """
            INSERT INTO docker_engines(
                engine_id, host_id, context_identity, daemon_identity,
                capability_state, created_at, updated_at
            ) VALUES ('cleanup-engine', ?, 'default', 'daemon', 'available', ?, ?)
            """,
            (HOST_ID, now, now),
        )
        connection.execute(
            """
            INSERT INTO source_resources(
                source_resource_id, source_id, resource_kind, native_id,
                repo_id, payload_sha256, created_at
            ) VALUES (?, ?, 'container', ?, ?, 'payload:container', ?)
            """,
            (source_resource, SOURCE_ID, CONTAINER_ID, REPO_ID, now),
        )
        connection.execute(
            """
            INSERT INTO docker_resources(
                docker_resource_id, engine_id, full_container_id, current_name,
                image, created_at, updated_at
            ) VALUES (?, 'cleanup-engine', ?, 'api-container', 'example:1', ?, ?)
            """,
            (CONTAINER_RESOURCE_ID, CONTAINER_ID, now, now),
        )
        connection.execute(
            """
            INSERT INTO docker_observations(
                docker_resource_id, lifecycle, restart_policy, sampled_at,
                observation_fingerprint
            ) VALUES (?, 'exited', 'no', ?, 'observation:container')
            """,
            (CONTAINER_RESOURCE_ID, now),
        )
        connection.execute(
            """
            INSERT INTO control_bindings(
                binding_id, repo_id, source_resource_id, resource_kind,
                resource_id, source_id, capability, provenance,
                authority_state, priority, generation, created_at, updated_at
            ) VALUES (?, ?, ?, 'container', ?, ?, 'docker', 'test',
                      'authoritative', 10, 0, ?, ?)
            """,
            (
                binding,
                REPO_ID,
                source_resource,
                CONTAINER_RESOURCE_ID,
                SOURCE_ID,
                now,
                now,
            ),
        )
        connection.execute(
            """
            INSERT INTO startup_policies(
                policy_id, repo_id, resource_kind, resource_id, policy_kind,
                current_value, desired_disabled_value, immutable_fingerprint,
                generation, updated_at
            ) VALUES ('policy-container', ?, 'container', ?, 'docker_restart',
                      'no', 'no', 'policy:container', 0, ?)
            """,
            (REPO_ID, CONTAINER_RESOURCE_ID, now),
        )
        connection.execute(
            """
            INSERT INTO repository_memberships(
                membership_id, repo_id, resource_kind, host_resource_id,
                immutable_fingerprint, control_binding_id, created_at
            ) VALUES ('membership-container', ?, 'container', ?,
                      'immutable:container', ?, ?)
            """,
            (REPO_ID, CONTAINER_RESOURCE_ID, binding, now),
        )
        _insert_archive_operation(
            connection, operation_id=archive_operation, repo_id=REPO_ID
        )
        connection.execute(
            """
            INSERT INTO resource_retirements(
                host_resource_id, resource_kind, immutable_fingerprint,
                status, operation_id, reason, actor, started_at, retired_at, updated_at
            ) VALUES (?, 'container', 'immutable:container', 'retired', ?,
                      'archive container', 'archive-operator', ?, ?, ?)
            """,
            (CONTAINER_RESOURCE_ID, archive_operation, now, now, now),
        )


def _lifecycle(
    store: AccountStore,
    *,
    adapter: ExactStoppedAdapter | None = None,
    docker: FakeDockerBackend | None = None,
    calls: list[tuple[str, str, str, str]] | None = None,
) -> CleanupLifecycle:
    def authorize(capability: str, kind: str, target: str, actor: str) -> None:
        if calls is not None:
            calls.append((capability, kind, target, actor))

    return CleanupLifecycle(
        store,
        lifecycle_adapter=adapter or ExactStoppedAdapter(),
        docker_backend=docker or FakeDockerBackend(),
        authorize=authorize,
    )


def _apply(service: CleanupLifecycle, plan: Any, *, actor: str = "apply-operator") -> dict[str, Any]:
    return service.apply(
        plan_id=plan.plan_id,
        plan_fingerprint=plan.plan_fingerprint,
        confirmation_phrase=plan.confirmation_phrase,
        actor=actor,
    )


def _git_env(home: Path) -> dict[str, str]:
    home.mkdir(mode=0o700, exist_ok=True)
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }


def _git(cwd: Path, env: Mapping[str, str], *arguments: str) -> str:
    if not Path(FIXED_GIT).is_file():
        raise RuntimeError(f"deterministic Git fixture executable is missing: {FIXED_GIT}")
    result = subprocess.run(
        [FIXED_GIT, "-C", str(cwd), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
        env=dict(env),
    )
    if result.returncode != 0:
        raise AssertionError(
            f"Git fixture failed ({' '.join(arguments)}): {result.stderr.strip()}"
        )
    return result.stdout


def _create_linked_worktree(root: Path) -> tuple[Path, Path, Mapping[str, str]]:
    primary = root / "primary"
    secondary = root / "secondary"
    primary.mkdir(mode=0o700)
    env = _git_env(root / "git-home")
    _git(primary, env, "init", "--initial-branch=main")
    (primary / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    _git(primary, env, "add", "tracked.txt")
    _git(
        primary,
        env,
        "-c",
        "user.name=Cleanup Test",
        "-c",
        "user.email=cleanup@example.invalid",
        "commit",
        "-m",
        "fixture",
    )
    _git(primary, env, "worktree", "add", "-b", "cleanup-secondary", str(secondary))
    return primary.resolve(strict=True), secondary.resolve(strict=True), env


@contextmanager
def _isolated_worktree_observation() -> Iterator[None]:
    with mock.patch.object(cleanup, "_process_cwds", return_value=((), 0)), mock.patch.object(
        cleanup, "_process_fds", return_value=((), 0)
    ), mock.patch.object(cleanup, "_mountpoints", return_value=((), 0)), mock.patch.object(
        cleanup, "_resolve_executable", side_effect=lambda name: FIXED_GIT
    ):
        yield


class CleanupLifecycleTests(unittest.TestCase):
    def test_non_container_cleanup_does_not_require_docker_executable(self) -> None:
        with _temporary_root(".cleanup-no-docker-") as root:
            project = root / "checkout"
            project.mkdir(mode=0o700)
            store = _open_store(root)
            self.addCleanup(store.close)
            _seed_project(store, project, archived=True)
            resolutions: list[str] = []

            def resolve(name: str) -> str:
                resolutions.append(name)
                if name == "docker":
                    raise AssertionError("non-container cleanup resolved Docker")
                return FIXED_GIT

            with mock.patch.object(cleanup, "_resolve_executable", side_effect=resolve):
                service = CleanupLifecycle(
                    store,
                    lifecycle_adapter=ExactStoppedAdapter(),
                )
                archives = service.list_archives(actor="reader")["archives"]
                self.assertTrue(
                    any(item["target_kind"] == "project" for item in archives)
                )
                plan = service.plan(
                    target_kind="project",
                    target_id=REPO_ID,
                    actor="planner",
                    reason="catalog cleanup without Docker",
                )
                self.assertTrue(_apply(service, plan)["ok"])

            self.assertNotIn("docker", resolutions)

    def test_project_plan_binds_actor_reason_and_retains_catalog_files(self) -> None:
        with _temporary_root(".cleanup-project-") as root:
            project = root / "checkout"
            project.mkdir(mode=0o700)
            sentinel = project / "must-remain.txt"
            sentinel.write_text("retained\n", encoding="utf-8")
            store = _open_store(root)
            self.addCleanup(store.close)
            _seed_project(store, project, archived=True)
            authorization: list[tuple[str, str, str, str]] = []
            service = _lifecycle(store, calls=authorization)

            first = service.plan(
                target_kind="repository",
                target_id=REPO_ID,
                actor="planner-one",
                reason="first approved reason",
            )
            second = service.plan(
                target_kind="project",
                target_id=REPO_ID,
                actor="planner-two",
                reason="different approved reason",
            )
            self.assertEqual(first.target_kind, "project")
            self.assertNotEqual(first.plan_id, second.plan_id)
            self.assertNotEqual(first.plan_fingerprint, second.plan_fingerprint)
            self.assertEqual(first.confirmation_phrase, "PURGE PROJECT Cleanup Project")
            self.assertNotIn(REPO_ID, first.confirmation_phrase)
            with self.assertRaisesRegex(CleanupError, "exact cleanup confirmation"):
                service.apply(
                    plan_id=first.plan_id,
                    plan_fingerprint=first.plan_fingerprint,
                    confirmation_phrase="PURGE PROJECT something else",
                    actor="separate-applier",
                )
            result = _apply(service, first, actor="separate-applier")
            self.assertTrue(result["ok"])
            self.assertTrue(sentinel.is_file(), "project cleanup deleted checkout content")

            with store.read_transaction() as connection:
                repository = connection.execute(
                    "SELECT state FROM repositories WHERE repo_id = ?", (REPO_ID,)
                ).fetchone()
                tombstone = connection.execute(
                    "SELECT actor, reason, evidence_json FROM cleanup_tombstones WHERE target_kind='project' AND target_id=?",
                    (REPO_ID,),
                ).fetchone()
                operation = connection.execute(
                    "SELECT actor FROM operations WHERE operation_id = ?", (first.plan_id,)
                ).fetchone()
                apply_evidence = connection.execute(
                    "SELECT evidence_json FROM cleanup_phase_evidence WHERE plan_id=? AND phase='apply_authorized'",
                    (first.plan_id,),
                ).fetchone()
            self.assertEqual(repository["state"], "missing")
            self.assertEqual(tombstone["actor"], "planner-one")
            self.assertEqual(tombstone["reason"], "first approved reason")
            self.assertEqual(operation["actor"], "planner-one")
            self.assertEqual(json.loads(apply_evidence["evidence_json"])["applier"], "separate-applier")
            self.assertEqual(json.loads(tombstone["evidence_json"])["applied_by"], "separate-applier")
            self.assertIn(("cleanup.apply", "project", REPO_ID, "separate-applier"), authorization)

            archives = service.list_archives(actor="reader")["archives"]
            removed = [
                item
                for item in archives
                if item["target_kind"] == "project" and item["target_id"] == REPO_ID
            ]
            self.assertEqual(len(removed), 1)
            self.assertEqual(removed[0]["status"], "removed")
            self.assertFalse(removed[0]["restorable"])
            self.assertFalse(removed[0]["removable"])
            with self.assertRaisesRegex(CleanupError, "already removed"):
                service.plan(
                    target_kind="project",
                    target_id=REPO_ID,
                    actor="planner-one",
                    reason="must not resurrect",
                )

            # Model stale discovery attempting to revive the catalogue row.
            # A cleanup tombstone is the durable no-resurrection boundary.
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE repositories SET state='active' WHERE repo_id=?", (REPO_ID,)
                )
                connection.execute(
                    "UPDATE repository_installations SET status='installed', startup_fenced=0 WHERE repo_id=?",
                    (REPO_ID,),
                )
            active_ids = {
                item["repo_id"] for item in store.inventory_v2()["repositories"]
            }
            self.assertNotIn(REPO_ID, active_ids, "tombstoned project resurrected in active inventory")

    def test_container_blockers_exact_command_and_successful_purge(self) -> None:
        with _temporary_root(".cleanup-container-") as root:
            project = root / "checkout"
            project.mkdir(mode=0o700)
            store = _open_store(root)
            self.addCleanup(store.close)
            _seed_container(store, project)
            docker = FakeDockerBackend()
            adapter = ExactStoppedAdapter()
            service = _lifecycle(store, adapter=adapter, docker=docker)

            docker.running = True
            docker.status = "running"
            live = service.plan(
                target_kind="container",
                target_id=CONTAINER_RESOURCE_ID,
                actor="planner",
                reason="live refusal",
            )
            self.assertIn("container_not_stopped", _blocker_codes(live))

            docker.running = False
            docker.status = "exited"
            docker.mounts = [
                {
                    "type": "volume",
                    "name": "data",
                    "source": "/volume/data",
                    "destination": "/data",
                    "rw": True,
                }
            ]
            mounted = service.plan(
                target_kind="container",
                target_id=CONTAINER_RESOURCE_ID,
                actor="planner",
                reason="mount refusal",
            )
            self.assertIn("mounted_container", _blocker_codes(mounted))

            docker.mounts = []
            docker.labels = {"com.docker.compose.project": "fixture"}
            compose = service.plan(
                target_kind="container",
                target_id=CONTAINER_RESOURCE_ID,
                actor="planner",
                reason="compose refusal",
            )
            self.assertIn("compose_owned", _blocker_codes(compose))

            docker.labels = {}
            with store.immediate_transaction() as connection:
                now = utc_timestamp()
                connection.execute(
                    """
                    INSERT INTO database_bindings(
                        database_binding_id, docker_resource_id, repo_id,
                        database_name, engine_kind, created_at, updated_at
                    ) VALUES ('database-container', ?, ?, 'app', 'postgres', ?, ?)
                    """,
                    (CONTAINER_RESOURCE_ID, REPO_ID, now, now),
                )
            database = service.plan(
                target_kind="container",
                target_id=CONTAINER_RESOURCE_ID,
                actor="planner",
                reason="database refusal",
            )
            self.assertIn("database_container", _blocker_codes(database))
            with store.immediate_transaction() as connection:
                connection.execute(
                    "DELETE FROM database_bindings WHERE database_binding_id='database-container'"
                )

            clean = service.plan(
                target_kind="container",
                target_id=CONTAINER_RESOURCE_ID,
                actor="planner",
                reason="exact stopped purge",
            )
            self.assertFalse(clean.blockers)
            result = _apply(service, clean)
            self.assertTrue(result["ok"])
            self.assertEqual(docker.remove_calls, [CONTAINER_ID])
            self.assertTrue(all(value == CONTAINER_ID for value in docker.inspect_calls))
            with store.read_transaction() as connection:
                self.assertIsNone(
                    connection.execute(
                        "SELECT 1 FROM docker_resources WHERE docker_resource_id=?",
                        (CONTAINER_RESOURCE_ID,),
                    ).fetchone()
                )
                tombstone = connection.execute(
                    "SELECT 1 FROM cleanup_tombstones WHERE target_kind='container' AND target_id=?",
                    (CONTAINER_RESOURCE_ID,),
                ).fetchone()
            self.assertIsNotNone(tombstone)

            backend = object.__new__(DockerCleanupBackend)
            backend.timeout = 1.0
            backend.executable = "/fixed/docker"
            responses = [
                subprocess.CompletedProcess([], 0, stdout=CONTAINER_ID + "\n", stderr=""),
                subprocess.CompletedProcess([], 1, stdout="", stderr="No such object"),
            ]
            with mock.patch.object(cleanup.subprocess, "run", side_effect=responses) as run:
                command_result = backend.remove(CONTAINER_ID)
            self.assertFalse(command_result["already_absent"])
            first_argv = run.call_args_list[0].args[0]
            self.assertEqual(first_argv, ["/fixed/docker", "rm", CONTAINER_ID])
            self.assertNotIn("-f", first_argv)
            self.assertNotIn("-v", first_argv)
            with self.assertRaisesRegex(CleanupError, "64-hex"):
                backend.remove("short-id")

    def test_interrupted_container_host_remove_reconciles_from_running_phase(self) -> None:
        with _temporary_root(".cleanup-crash-") as root:
            project = root / "checkout"
            project.mkdir(mode=0o700)
            store = _open_store(root)
            self.addCleanup(store.close)
            _seed_container(store, project)
            docker = FakeDockerBackend()
            docker.crash_after_remove_effect = True
            adapter = ExactStoppedAdapter()
            service = _lifecycle(store, adapter=adapter, docker=docker)
            plan = service.plan(
                target_kind="container",
                target_id=CONTAINER_RESOURCE_ID,
                actor="planner",
                reason="crash recovery",
            )
            with self.assertRaisesRegex(SimulatedCrash, "after docker rm"):
                _apply(service, plan, actor="first-applier")
            with store.read_transaction() as connection:
                phase = connection.execute(
                    "SELECT status FROM cleanup_phase_evidence WHERE plan_id=? AND phase='host_remove'",
                    (plan.plan_id,),
                ).fetchone()
            self.assertEqual(phase["status"], "running")
            self.assertEqual(docker.remove_calls, [CONTAINER_ID])

            # A new service instance models restart after process death.  The
            # absent exact target plus the durable running boundary is enough
            # to reconcile; it must not invoke Docker rm twice.
            resumed = _lifecycle(store, adapter=adapter, docker=docker)
            result = _apply(resumed, plan, actor="recovery-applier")
            self.assertTrue(result["ok"])
            self.assertEqual(docker.remove_calls, [CONTAINER_ID])
            with store.read_transaction() as connection:
                phase = connection.execute(
                    "SELECT status, evidence_json FROM cleanup_phase_evidence WHERE plan_id=? AND phase='host_remove'",
                    (plan.plan_id,),
                ).fetchone()
                tombstone = connection.execute(
                    "SELECT 1 FROM cleanup_tombstones WHERE target_kind='container' AND target_id=?",
                    (CONTAINER_RESOURCE_ID,),
                ).fetchone()
            self.assertEqual(phase["status"], "succeeded")
            self.assertTrue(json.loads(phase["evidence_json"])["recovered_after_interruption"])
            self.assertIsNotNone(tombstone)

    def test_server_requires_stopped_listener_and_does_not_resurrect(self) -> None:
        with _temporary_root(".cleanup-server-") as root:
            project = root / "checkout"
            project.mkdir(mode=0o700)
            log = project / "server.log"
            log.write_text("retained log\n", encoding="utf-8")
            store = _open_store(root)
            self.addCleanup(store.close)
            _seed_server(store, project)
            adapter = ExactStoppedAdapter()
            adapter.listener_active = None
            service = _lifecycle(store, adapter=adapter)
            unknown = service.plan(
                target_kind="server",
                target_id=SERVER_ID,
                actor="planner",
                reason="unknown listener refusal",
            )
            self.assertIn("listener_not_absent", _blocker_codes(unknown))

            adapter.listener_active = True
            listening = service.plan(
                target_kind="server",
                target_id=SERVER_ID,
                actor="planner",
                reason="active listener refusal",
            )
            self.assertIn("listener_not_absent", _blocker_codes(listening))

            adapter.listener_active = False
            clean = service.plan(
                target_kind="server",
                target_id=SERVER_ID,
                actor="planner",
                reason="stopped server purge",
            )
            self.assertFalse(clean.blockers)
            self.assertTrue(_apply(service, clean)["ok"])
            self.assertTrue(log.is_file())
            with store.read_transaction() as connection:
                definition = connection.execute(
                    "SELECT 1 FROM server_definitions WHERE server_definition_id=?",
                    (SERVER_ID,),
                ).fetchone()
                arguments = connection.execute(
                    "SELECT COUNT(*) FROM server_command_arguments WHERE server_definition_id=?",
                    (SERVER_ID,),
                ).fetchone()[0]
                environment = connection.execute(
                    "SELECT COUNT(*) FROM server_environment WHERE server_definition_id=?",
                    (SERVER_ID,),
                ).fetchone()[0]
                lease = connection.execute(
                    "SELECT status FROM leases WHERE lease_id='lease-server'"
                ).fetchone()
                assignment = connection.execute(
                    "SELECT status FROM port_assignments WHERE assignment_id='assignment-server'"
                ).fetchone()
                binding = connection.execute(
                    "SELECT authority_state FROM control_bindings WHERE binding_id='binding-server'"
                ).fetchone()
            self.assertIsNotNone(definition, "server audit definition should be retained")
            self.assertEqual(arguments, 0)
            self.assertEqual(environment, 0)
            self.assertEqual(lease["status"], "released")
            self.assertEqual(assignment["status"], "inactive")
            self.assertEqual(binding["authority_state"], "retired")
            server_ids = {item["id"] for item in store.inventory_v2()["servers"]}
            self.assertNotIn(SERVER_ID, server_ids, "purged server resurrected in active inventory")
            archived = service.list_archives(actor="reader")["archives"]
            removed = [
                item
                for item in archived
                if item["target_kind"] == "server" and item["target_id"] == SERVER_ID
            ]
            self.assertEqual(len(removed), 1)
            self.assertEqual(removed[0]["status"], "removed")

    def test_project_purge_retains_secondary_worktree_until_exact_removal(self) -> None:
        with _temporary_root(".cleanup-worktree-") as root:
            primary, secondary, _env = _create_linked_worktree(root)
            store = _open_store(root)
            self.addCleanup(store.close)
            _seed_project(store, secondary, archived=True)
            service = _lifecycle(store)
            with _isolated_worktree_observation():
                premature = service.plan(
                    target_kind="worktree",
                    target_id=REPO_ID,
                    actor="planner",
                    reason="must not orphan a restorable project",
                )
                self.assertIn("project_catalog_retained", _blocker_codes(premature))
                with self.assertRaises(CleanupBlocked):
                    _apply(service, premature)
                before = service.list_archives(actor="reader")["archives"]
                before_worktree = [
                    item
                    for item in before
                    if item["target_kind"] == "worktree"
                    and item["target_id"] == REPO_ID
                ]
                self.assertEqual(len(before_worktree), 1)
                self.assertFalse(before_worktree[0]["removable"])

                project_plan = service.plan(
                    target_kind="project",
                    target_id=REPO_ID,
                    actor="planner",
                    reason="catalog only",
                )
                self.assertTrue(_apply(service, project_plan)["ok"])
                self.assertTrue(secondary.is_dir(), "project purge removed checkout files")
                self.assertTrue(primary.is_dir(), "project purge touched the primary worktree")
                archived = service.list_archives(actor="reader")["archives"]
                retained = [
                    item
                    for item in archived
                    if item["target_kind"] == "worktree" and item["target_id"] == REPO_ID
                ]
                self.assertEqual(len(retained), 1)
                self.assertEqual(retained[0]["status"], "archived")
                self.assertTrue(retained[0]["removable"])

                worktree_plan = service.plan(
                    target_kind="worktree",
                    target_id=REPO_ID,
                    actor="planner",
                    reason="remove exact secondary",
                )
                self.assertFalse(worktree_plan.blockers)
                identity = worktree_plan.snapshot["identity"]
                self.assertEqual(identity["branch"], "refs/heads/cleanup-secondary")
                self.assertRegex(identity["head_oid"], r"^[0-9a-f]{40,64}$")
                for field in (
                    "git_dir_device",
                    "git_dir_inode",
                    "common_dir_device",
                    "common_dir_inode",
                    "root_device",
                    "root_inode",
                    "marker_device",
                    "marker_inode",
                ):
                    self.assertGreaterEqual(identity[field], 0, field)
                self.assertTrue(_apply(service, worktree_plan)["ok"])
                self.assertFalse(secondary.exists())
                self.assertTrue(primary.is_dir())
                listing = _git(primary, _git_env(root / "verify-home"), "worktree", "list", "--porcelain")
                self.assertNotIn(str(secondary), listing)
                with store.read_transaction() as connection:
                    tombstone = connection.execute(
                        "SELECT 1 FROM cleanup_tombstones WHERE target_kind='worktree' AND target_id=?",
                        (REPO_ID,),
                    ).fetchone()
                self.assertIsNotNone(tombstone)

    def test_worktree_branch_drift_after_plan_is_refused(self) -> None:
        with _temporary_root(".cleanup-worktree-drift-") as root:
            primary, secondary, env = _create_linked_worktree(root)
            store = _open_store(root)
            self.addCleanup(store.close)
            _seed_project(store, secondary, archived=True)
            service = _lifecycle(store)
            with _isolated_worktree_observation():
                project_plan = service.plan(
                    target_kind="project",
                    target_id=REPO_ID,
                    actor="planner",
                    reason="remove catalog before worktree",
                )
                self.assertTrue(_apply(service, project_plan)["ok"])
                plan = service.plan(
                    target_kind="worktree",
                    target_id=REPO_ID,
                    actor="planner",
                    reason="bind branch before removal",
                )
                self.assertFalse(plan.blockers)
                _git(secondary, env, "switch", "-c", "cleanup-drift")
                with self.assertRaises(PlanDriftError):
                    _apply(service, plan)

            self.assertTrue(secondary.is_dir(), "drifted worktree was removed")
            listing = _git(primary, env, "worktree", "list", "--porcelain")
            self.assertIn(str(secondary), listing)

    def test_worktree_observation_boundaries_fail_closed(self) -> None:
        with _temporary_root(".cleanup-worktree-observation-") as root:
            _primary, secondary, _env = _create_linked_worktree(root)
            store = _open_store(root)
            self.addCleanup(store.close)
            _seed_project(store, secondary, archived=True)
            service = _lifecycle(store)
            with _isolated_worktree_observation():
                project_plan = service.plan(
                    target_kind="project",
                    target_id=REPO_ID,
                    actor="planner",
                    reason="remove catalog before worktree",
                )
                self.assertTrue(_apply(service, project_plan)["ok"])

            with mock.patch.object(
                cleanup, "_process_cwds", return_value=((), 1)
            ), mock.patch.object(
                cleanup, "_process_fds", return_value=((), 1)
            ), mock.patch.object(
                cleanup, "_mountpoints", return_value=((), 1)
            ), mock.patch.object(
                cleanup, "_resolve_executable", side_effect=lambda name: FIXED_GIT
            ):
                plan = service.plan(
                    target_kind="worktree",
                    target_id=REPO_ID,
                    actor="planner",
                    reason="unobservable host refusal",
                )
                self.assertTrue(
                    {
                        "mount_observation_unavailable",
                        "process_cwd_unobservable",
                        "process_fd_unobservable",
                    }.issubset(_blocker_codes(plan))
                )
                with self.assertRaises(CleanupBlocked):
                    _apply(service, plan)

            self.assertTrue(secondary.is_dir(), "unobservable worktree was removed")

            with mock.patch.object(cleanup.Path, "is_dir", return_value=False):
                self.assertEqual(cleanup._process_cwds(), ((), 1))
                self.assertEqual(cleanup._process_fds(), ((), 1))
            with mock.patch.object(
                cleanup.Path, "read_text", side_effect=PermissionError("denied")
            ):
                self.assertEqual(cleanup._mountpoints(), ((), 1))

    def test_primary_dirty_and_root_owned_worktrees_are_refused(self) -> None:
        with _temporary_root(".cleanup-worktree-refuse-") as root:
            primary, secondary, _env = _create_linked_worktree(root)
            (secondary / "untracked.txt").write_text("must not delete\n", encoding="utf-8")

            dirty_store = _open_store(root / "dirty-state-root")
            self.addCleanup(dirty_store.close)
            _seed_project(dirty_store, secondary, archived=True)
            with _isolated_worktree_observation():
                dirty = _lifecycle(dirty_store).plan(
                    target_kind="worktree",
                    target_id=REPO_ID,
                    actor="planner",
                    reason="dirty refusal",
                )
            self.assertIn("dirty_worktree", _blocker_codes(dirty))
            self.assertTrue(secondary.is_dir())

            primary_store = _open_store(root / "primary-state-root")
            self.addCleanup(primary_store.close)
            _seed_project(primary_store, primary, archived=True)
            with _isolated_worktree_observation():
                primary_plan = _lifecycle(primary_store).plan(
                    target_kind="worktree",
                    target_id=REPO_ID,
                    actor="planner",
                    reason="primary refusal",
                )
            self.assertIn("primary_worktree", _blocker_codes(primary_plan))
            self.assertTrue(primary.is_dir())

            with self.assertRaises(CleanupBlocked) as caught:
                cleanup._owner_preexec(0, 0)
            self.assertIn("root_owned_worktree", {item["code"] for item in caught.exception.blockers})


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CleanupLifecycleTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    print("cleanup-lifecycle self-test ok")
