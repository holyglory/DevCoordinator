#!/usr/bin/env python3
"""Recall tests for normalized repository action fencing at public surfaces."""

from __future__ import annotations

import contextlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import subprocess
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


def test_temp_base() -> Path:
    """Select a writable canonical base outside host/user Git worktrees."""

    candidates = (
        os.environ.get("DEVCOORDINATOR_TEST_TMP_ROOT"),
        pwd.getpwuid(os.geteuid()).pw_dir,
        tempfile.gettempdir(),
    )
    for raw in dict.fromkeys(value for value in candidates if value):
        base = Path(str(raw)).resolve()
        if not base.is_dir() or not os.access(base, os.W_OK | os.X_OK):
            continue
        cursor = base
        inside_git = False
        while True:
            if (cursor / ".git").exists() or (cursor / ".git").is_symlink():
                inside_git = True
                break
            if cursor.parent == cursor:
                break
            cursor = cursor.parent
        if not inside_git:
            return base
    raise RuntimeError("no writable test temp root exists outside every Git worktree")


def git_repository(path: Path) -> Path:
    private_directory(path)
    git = "/usr/bin/git" if Path("/usr/bin/git").is_file() else "/bin/git"
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(path.parent),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    subprocess.run(
        [git, "init", "-q", str(path)],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        timeout=10,
    )
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
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".lifecycle-action-guard-", dir=test_temp_base()
        )
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

    def tearDown(self) -> None:
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

    def operation_ids(self) -> list[str]:
        with AccountStore.open_default(self.home) as store:
            with store.read_transaction() as connection:
                return [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT operation_id FROM operations ORDER BY operation_id"
                    )
                ]

    def store_revision(self) -> int:
        with AccountStore.open_default(self.home) as store:
            with store.read_transaction() as connection:
                return int(
                    connection.execute(
                        "SELECT state_revision FROM schema_metadata WHERE singleton = 1"
                    ).fetchone()[0]
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

    def test_linked_worktree_lease_persists_root_and_temporary_family(self) -> None:
        fixture = self.repository / "fixture.txt"
        fixture.write_text("fixture\n", encoding="utf-8")
        git = "/usr/bin/git" if Path("/usr/bin/git").is_file() else "/bin/git"
        environment = {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": str(self.root),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        }
        subprocess.run(
            [git, "-C", str(self.repository), "add", "fixture.txt"],
            env=environment,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        subprocess.run(
            [
                git,
                "-C",
                str(self.repository),
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "-qm",
                "fixture",
            ],
            env=environment,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        linked = self.root / "repo-linked"
        subprocess.run(
            [
                git,
                "-C",
                str(self.repository),
                "worktree",
                "add",
                "-q",
                "-b",
                "fixture-linked",
                str(linked),
            ],
            env=environment,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )

        with mock.patch.object(coordinator, "port_available", return_value=True):
            lease = coordinator.coordinated_lease_port(
                {
                    "agent": "guard-test",
                    "project": str(linked),
                    "range": "43110-43110",
                }
            )

        self.assertEqual(lease["project"], str(linked))
        with AccountStore.open_default(self.home) as store:
            with store.read_transaction() as connection:
                scopes = [
                    tuple(row)
                    for row in connection.execute(
                        """
                        SELECT repository.canonical_root, scope.project_kind
                        FROM repository_scopes scope
                        JOIN repositories repository USING(repo_id)
                        ORDER BY scope.project_kind, repository.canonical_root
                        """
                    )
                ]
                self.assertEqual(
                    connection.execute(
                        "SELECT count(*) FROM repository_families"
                    ).fetchone()[0],
                    1,
                )
        self.assertEqual(
            scopes,
            [(str(self.repository), "primary"), (str(linked), "temporary")],
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

    def test_unobservable_listener_fails_before_any_guard_or_lifecycle_operation(self) -> None:
        identity = {
            "ok": True,
            "observable": True,
            "pid": 43051,
            "host": "127.0.0.1",
            "port": 43101,
            "project": str(self.repository),
            "cwd": str(self.repository),
            "source": "fixture",
            "listener_inodes": ["43101"],
        }
        healthy = {
            "ok": True,
            "pid_alive": True,
            "classification": "healthy",
            "identity": identity,
        }
        with (
            mock.patch.object(coordinator, "configured_broker_context", return_value=None),
            mock.patch.object(
                coordinator,
                "resolve_registration_pid",
                return_value=(43051, identity),
            ),
            mock.patch.object(coordinator, "wait_for_health", return_value=healthy),
            mock.patch.object(
                coordinator,
                "registration_pid_identity",
                return_value=identity,
            ),
            mock.patch.object(
                coordinator,
                "normalized_process_instance_evidence",
                return_value=("fixture-start", "sha256:fixture-process"),
            ),
        ):
            registered = coordinator.coordinated_register_server(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                    "name": "web",
                    "cwd": str(self.repository),
                    "port": 43101,
                    "pid": 43051,
                    "url": "http://127.0.0.1:43101",
                    "argv": ["python3", "-c", "print('fixture')"],
                }
            )
        self.assertEqual(registered["status"], "running")

        def operation_ids() -> list[str]:
            with AccountStore.open_default(self.home) as store:
                with store.read_transaction() as connection:
                    return [
                        str(row[0])
                        for row in connection.execute(
                            "SELECT operation_id FROM operations ORDER BY operation_id"
                        )
                    ]

        before = operation_ids()
        unobservable = {
            "ok": None,
            "pid_alive": True,
            "classification": "unverified-listener",
            "identity": {
                "ok": None,
                "observable": False,
                "reason": "injected capability boundary",
            },
        }
        calls = {
            "server start": lambda: coordinator.coordinated_start_server(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                    "name": "web",
                    "cwd": str(self.repository),
                    "argv": ["python3", "-c", "print('must not launch')"],
                }
            ),
            "server restart": lambda: coordinator.coordinated_restart_server(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                    "name": "web",
                }
            ),
            "project start": lambda: coordinator.coordinated_project_runtime_start(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                }
            ),
            "project restart": lambda: coordinator.coordinated_project_runtime_restart(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                }
            ),
            "project stop": lambda: coordinator.coordinated_project_runtime_stop(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                }
            ),
        }
        with (
            mock.patch.object(coordinator, "server_health", return_value=unobservable),
            mock.patch.object(
                coordinator,
                "start_process",
                side_effect=AssertionError("unobservable preflight launched a process"),
            ),
            mock.patch.object(
                coordinator,
                "stop_pid",
                side_effect=AssertionError("unobservable preflight signalled a process"),
            ),
        ):
            for label, invoke in calls.items():
                with self.subTest(label=label):
                    with self.assertRaisesRegex(
                        coordinator.ListenerIdentityUnobservable,
                        "listener identity is unobservable",
                    ):
                        invoke()
                    self.assertEqual(operation_ids(), before)

        with (
            mock.patch.object(coordinator, "configured_broker_context", return_value=None),
            mock.patch.object(
                coordinator,
                "resolve_registration_pid",
                side_effect=coordinator.ListenerIdentityUnobservable(
                    "working directory is not observable"
                ),
            ),
            self.assertRaisesRegex(
                coordinator.ListenerIdentityUnobservable,
                "working directory is not observable",
            ),
        ):
            coordinator.coordinated_register_server(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                    "name": "web",
                    "cwd": str(self.repository),
                    "port": 43101,
                    "pid": 43051,
                }
            )
        self.assertEqual(operation_ids(), before)

    def test_absent_server_on_exact_unknown_port_fails_before_guard_reservation(self) -> None:
        self.install_repository()
        before_operations = self.operation_ids()
        before_revision = self.store_revision()
        unknown_owner = {
            "observable": False,
            "reason": "injected capability boundary",
        }
        with (
            mock.patch.object(coordinator, "port_open", return_value=True),
            mock.patch.object(
                coordinator,
                "listener_belongs_to_project",
                return_value=(False, unknown_owner),
            ),
            mock.patch.object(
                coordinator.RepositoryLifecycle,
                "restore_startup_policies_for_start",
                side_effect=AssertionError("listener preflight reached startup restoration"),
            ),
            mock.patch.object(
                coordinator,
                "start_process",
                side_effect=AssertionError("listener preflight launched a process"),
            ),
            self.assertRaisesRegex(
                coordinator.ListenerIdentityUnobservable,
                "injected capability boundary",
            ),
        ):
            coordinator.coordinated_start_server(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                    "name": "absent",
                    "cwd": str(self.repository),
                    "argv": ["python3", "-c", "print('must not launch')"],
                    "range": "43101-43101",
                    "preferred": 43101,
                }
            )
        self.assertEqual(self.operation_ids(), before_operations)
        self.assertEqual(self.store_revision(), before_revision)
        with AccountStore.open_default(self.home) as store:
            with store.read_transaction() as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT count(*) FROM server_definitions WHERE name = 'absent'"
                    ).fetchone()[0],
                    0,
                )

    def test_broker_registration_proves_listener_before_local_guard(self) -> None:
        with (
            mock.patch.object(
                coordinator,
                "configured_broker_context",
                return_value=(object(), object()),
            ),
            mock.patch.object(
                coordinator,
                "acquire_broker_lease_link",
                side_effect=coordinator.ListenerIdentityUnobservable(
                    "broker listener identity is unobservable"
                ),
            ) as broker_acquire,
            self.assertRaisesRegex(
                coordinator.ListenerIdentityUnobservable,
                "broker listener identity is unobservable",
            ),
        ):
            coordinator.coordinated_register_server(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                    "name": "web",
                    "cwd": str(self.repository),
                    "port": 43101,
                }
            )
        broker_acquire.assert_called_once()
        self.assertFalse((self.home / "coordinator.sqlite3").exists())

    def test_stale_dead_pid_on_assigned_unknown_port_fails_before_guard_reservation(self) -> None:
        identity = {
            "ok": True,
            "observable": True,
            "pid": 43052,
            "host": "127.0.0.1",
            "port": 43101,
            "project": str(self.repository),
            "cwd": str(self.repository),
            "source": "fixture",
            "listener_inodes": ["43101"],
        }
        healthy = {
            "ok": True,
            "pid_alive": True,
            "classification": "healthy",
            "identity": identity,
        }
        with (
            mock.patch.object(coordinator, "configured_broker_context", return_value=None),
            mock.patch.object(
                coordinator,
                "resolve_registration_pid",
                return_value=(43052, identity),
            ),
            mock.patch.object(coordinator, "wait_for_health", return_value=healthy),
            mock.patch.object(
                coordinator,
                "registration_pid_identity",
                return_value=identity,
            ),
            mock.patch.object(
                coordinator,
                "normalized_process_instance_evidence",
                return_value=("fixture-start", "sha256:fixture-process"),
            ),
        ):
            coordinator.coordinated_register_server(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                    "name": "stale",
                    "cwd": str(self.repository),
                    "port": 43101,
                    "pid": 43052,
                    "url": "http://127.0.0.1:43101",
                    "argv": ["python3", "-c", "print('fixture')"],
                }
            )
        with AccountStore.open_default(self.home) as store:
            with store.immediate_transaction(revision_kind="observation") as connection:
                connection.execute(
                    """
                    UPDATE server_observations
                    SET lifecycle = 'running', pid = 987654,
                        listener_host = '127.0.0.1', listener_port = 43101,
                        listener_observable = 1, sampled_at = ?
                    WHERE server_definition_id = (
                        SELECT server_definition_id FROM server_definitions
                        WHERE name = 'stale'
                    )
                    """,
                    (coordinator.utc_timestamp(),),
                )
        before_operations = self.operation_ids()
        before_revision = self.store_revision()
        unknown_owner = {
            "observable": False,
            "reason": "stale listener cannot be attributed",
        }
        calls = {
            "start": lambda: coordinator.coordinated_start_server(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                    "name": "stale",
                    "cwd": str(self.repository),
                    "argv": ["python3", "-c", "print('must not launch')"],
                }
            ),
            "restart": lambda: coordinator.coordinated_restart_server(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                    "name": "stale",
                }
            ),
        }
        with (
            mock.patch.object(coordinator, "pid_alive", return_value=False),
            mock.patch.object(coordinator, "port_open", return_value=True),
            mock.patch.object(
                coordinator,
                "listener_belongs_to_project",
                return_value=(False, unknown_owner),
            ),
            mock.patch.object(
                coordinator.RepositoryLifecycle,
                "restore_startup_policies_for_start",
                side_effect=AssertionError("listener preflight reached startup restoration"),
            ),
            mock.patch.object(
                coordinator,
                "start_process",
                side_effect=AssertionError("listener preflight launched a process"),
            ),
        ):
            for label, invoke in calls.items():
                with self.subTest(label=label):
                    with self.assertRaisesRegex(
                        coordinator.ListenerIdentityUnobservable,
                        "stale listener cannot be attributed",
                    ):
                        invoke()
                    self.assertEqual(self.operation_ids(), before_operations)
                    self.assertEqual(self.store_revision(), before_revision)

    def test_existing_conflict_precedes_listener_identity_sampling(self) -> None:
        repo_id = self.install_repository()
        timestamp = coordinator.utc_timestamp()
        with AccountStore.open_default(self.home) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO operations(
                        operation_id, repo_id, source_id, kind, status, phase,
                        generation, request_fingerprint, owner_uid, actor,
                        process_fingerprint, error_code, error_message,
                        result_json, created_at, updated_at
                    ) VALUES (
                        'fixture-conflict', ?, NULL, 'guard:start', 'running',
                        'reserved', 0, 'fixture-request', ?, 'other-agent',
                        NULL, NULL, NULL, '{}', ?, ?
                    )
                    """,
                    (repo_id, os.geteuid(), timestamp, timestamp),
                )
        before = self.operation_ids()
        with (
            mock.patch.object(
                coordinator,
                "resolve_registration_pid",
                side_effect=AssertionError("conflict path sampled listener identity"),
            ) as identity_probe,
            self.assertRaisesRegex(
                coordinator.ConcurrentLifecycleError,
                "already active",
            ),
        ):
            coordinator.coordinated_register_server(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                    "name": "web",
                    "cwd": str(self.repository),
                    "port": 43101,
                }
            )
        identity_probe.assert_not_called()
        self.assertEqual(self.operation_ids(), before)
        with AccountStore.open_default(self.home) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE operations SET kind = 'guard:lease' "
                    "WHERE operation_id = 'fixture-conflict'"
                )
            self.assertEqual(
                coordinator._precheck_normalized_repository_action(
                    store,
                    project=str(self.repository),
                    action=RepositoryAction.LEASE,
                ),
                repo_id,
            )

    def test_guard_uses_local_installation_when_foreign_same_root_exists(self) -> None:
        local_repo_id = self.install_repository()
        timestamp = coordinator.utc_timestamp()
        with AccountStore.open_default(self.home) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO hosts(
                        host_id, machine_fingerprint, platform, hostname,
                        created_at, updated_at
                    ) VALUES (
                        'foreign-host', 'foreign-fingerprint', 'Linux',
                        'foreign', ?, ?
                    )
                    """,
                    (timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (
                        'foreign-repo', 'foreign-host', ?, 'repo', 'active',
                        0, ?, ?
                    )
                    """,
                    (str(self.repository), timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation, reason,
                        actor, updated_at
                    ) VALUES (
                        'foreign-repo', 'disabled', 1, 0, 'foreign fixture',
                        'guard-test', ?
                    )
                    """,
                    (timestamp,),
                )

        options = {
            "agent": "guard-test",
            "project": str(self.repository),
            "name": "web",
            "cwd": str(self.repository),
            "port": 43101,
        }
        with mock.patch.object(
            coordinator,
            "resolve_registration_pid",
            return_value=(None, None),
        ):
            with coordinator.normalized_repository_action_guard(
                project=str(self.repository),
                agent="guard-test",
                action=RepositoryAction.REGISTER,
                preflight=lambda store: coordinator.preflight_normalized_listener_identity(
                    options, command="server register", store=store
                ),
            ) as guarded_repo_id:
                self.assertEqual(guarded_repo_id, local_repo_id)

        with AccountStore.open_default(self.home) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE repository_installations
                    SET status = 'disabled', startup_fenced = 1,
                        reason = 'local fixture', updated_at = ?
                    WHERE repo_id = ?
                    """,
                    (coordinator.utc_timestamp(), local_repo_id),
                )
                connection.execute(
                    """
                    UPDATE repository_installations
                    SET status = 'installed', startup_fenced = 0,
                        reason = 'foreign fixture', updated_at = ?
                    WHERE repo_id = 'foreign-repo'
                    """,
                    (coordinator.utc_timestamp(),),
                )
        before = self.operation_ids()
        with (
            mock.patch.object(
                coordinator,
                "resolve_registration_pid",
                side_effect=AssertionError("local fence sampled listener identity"),
            ) as identity_probe,
            self.assertRaisesRegex(ActionFencedError, "start fence is active"),
        ):
            with coordinator.normalized_repository_action_guard(
                project=str(self.repository),
                agent="guard-test",
                action=RepositoryAction.REGISTER,
                preflight=lambda store: coordinator.preflight_normalized_listener_identity(
                    options, command="server register", store=store
                ),
            ):
                self.fail("disabled local repository received a permit")
        identity_probe.assert_not_called()
        self.assertEqual(self.operation_ids(), before)

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

    def test_explicit_start_owns_loading_after_policy_restore_preflight(self) -> None:
        self.install_repository()
        events: list[str] = []

        def record_restore(*_args: object, **_kwargs: object) -> None:
            events.append("policy-restore")

        def record_explicit_start(*_args: object, **_kwargs: object) -> dict[str, object]:
            events.append("explicit-start")
            return {"action": "start", "ok": True}

        with mock.patch.object(
            coordinator.RepositoryLifecycle,
            "restore_startup_policies_for_start",
            side_effect=record_restore,
        ) as restore, mock.patch.object(
            coordinator,
            "execute_project_start",
            side_effect=record_explicit_start,
        ) as explicit_start:
            result = coordinator.coordinated_project_runtime_start(
                {
                    "agent": "guard-test",
                    "project": str(self.repository),
                    "dry_run": True,
                }
            )

        self.assertEqual(result["action"], "start")
        self.assertEqual(events, ["policy-restore", "explicit-start"])
        restore.assert_called_once()
        explicit_start.assert_called_once()

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
