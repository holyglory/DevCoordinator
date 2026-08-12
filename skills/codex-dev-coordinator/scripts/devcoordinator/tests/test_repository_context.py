from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import stat
import sqlite3
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from devcoordinator import repository_context as repository_context_module
from devcoordinator.repository_context import (
    RepositoryContextError,
    find_repository_id_by_filesystem_identity,
    persist_repository_context,
    resolve_effective_repository_context,
    resolve_repository_context,
)
from devcoordinator.runtime_sessions import (
    create_runtime_session,
    finish_runtime_session,
    link_runtime_resource,
    mark_runtime_session_started,
)
from devcoordinator.schema import invariant_violations
from devcoordinator.store import AccountStore, deterministic_id, utc_timestamp


GIT = "/usr/bin/git" if Path("/usr/bin/git").is_file() else "/bin/git"


def git_environment(*, home: Path) -> dict[str, str]:
    return {
        "GIT_ALLOW_PROTOCOL": "file",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


class RepositoryContextTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch_root = Path(
            os.environ.get("DEVCOORDINATOR_TEST_TMP_ROOT", Path.home())
        )
        self.temporary = tempfile.TemporaryDirectory(
            prefix="devcoordinator-repository-context-", dir=scratch_root
        )
        self.test_root = Path(self.temporary.name).resolve()
        self.git_home = self.test_root / "git-home"
        self.git_home.mkdir(mode=0o700)
        self.repository = self.test_root / "repository"
        self._initialize_repository(self.repository)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        directory_arguments = ["-C", str(cwd)] if cwd is not None else []
        return subprocess.run(
            [GIT, *directory_arguments, *arguments],
            env=git_environment(home=self.git_home),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            timeout=10,
        )

    def _initialize_repository(self, path: Path) -> None:
        path.mkdir(mode=0o700)
        self._git("init", "-q", str(path))
        self._git("config", "user.email", "fixture@example.invalid", cwd=path)
        self._git("config", "user.name", "Fixture", cwd=path)
        (path / "tracked.txt").write_text("tracked\n", encoding="utf-8")
        self._git("add", "tracked.txt", cwd=path)
        self._git("commit", "-qm", "fixture", cwd=path)

    def _linked(self, name: str = "linked") -> Path:
        linked = self.test_root / name
        self._git(
            "worktree",
            "add",
            "-qb",
            f"fixture-{name}",
            str(linked),
            cwd=self.repository,
        )
        return linked

    def _insert_repository(self, store: AccountStore, path: Path) -> str:
        host_id = store.ensure_local_host()
        repo_id = deterministic_id("repository", host_id, str(path))
        timestamp = utc_timestamp()
        with store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO repositories(
                    repo_id, host_id, canonical_root, display_name, state,
                    generation, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'active', 0, ?, ?)
                """,
                (repo_id, host_id, str(path), path.name, timestamp, timestamp),
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

    def test_exact_primary_and_linked_identity_contains_filesystem_and_git_material(self) -> None:
        linked = self._linked()
        context = resolve_repository_context(
            root_repo=str(self.repository), temporary_repo=str(linked)
        )
        self.assertEqual(context.project_kind, "temporary")
        self.assertEqual(context.root.root_owner_uid, os.geteuid())
        self.assertEqual(context.root.root_device, self.repository.stat().st_dev)
        self.assertEqual(context.root.root_inode, self.repository.stat().st_ino)
        self.assertEqual(
            context.root.git_common_dir, context.temporary.git_common_dir
        )
        self.assertNotEqual(context.root.git_dir, context.temporary.git_dir)
        self.assertNotEqual(
            context.root.identity_fingerprint,
            context.temporary.identity_fingerprint,
        )
        self.assertRegex(context.root.git_identity_fingerprint, r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(
            context.root.identity_fingerprint,
            r"^repository-scope-v2:sha256:[0-9a-f]{64}$",
        )
        with self.assertRaisesRegex(RepositoryContextError, "primary Git worktree"):
            resolve_repository_context(root_repo=str(linked), temporary_repo=None)

    @unittest.skipUnless(getattr(os, "O_PATH", 0), "O_PATH is Linux-specific")
    def test_exact_repository_below_execute_only_ancestor_is_inspectable(self) -> None:
        exact_parent = self.test_root / "exact-only"
        exact_parent.mkdir(mode=0o700)
        repository = exact_parent / "repository"
        self._initialize_repository(repository)
        exact_parent.chmod(0o111)
        try:
            context = resolve_repository_context(
                root_repo=str(repository), temporary_repo=None
            )
        finally:
            exact_parent.chmod(0o700)

        self.assertEqual(context.root.canonical_root, str(repository))

    def test_effective_worktree_discovery_returns_explicit_root_and_temporary_scope(self) -> None:
        linked = self._linked()
        primary = resolve_effective_repository_context(project=str(self.repository))
        temporary = resolve_effective_repository_context(project=str(linked))

        self.assertEqual(primary.root.canonical_root, str(self.repository))
        self.assertIsNone(primary.temporary)
        self.assertEqual(temporary.root.canonical_root, str(self.repository))
        self.assertEqual(temporary.effective.canonical_root, str(linked))
        self.assertEqual(temporary.temporary.canonical_root, str(linked))
        self.assertEqual(temporary.project_kind, "temporary")

    def test_foreign_repository_and_linked_worktree_admin_mismatch_are_rejected(self) -> None:
        foreign = self.test_root / "foreign"
        self._initialize_repository(foreign)
        with self.assertRaisesRegex(RepositoryContextError, "common directory"):
            resolve_repository_context(
                root_repo=str(self.repository), temporary_repo=str(foreign)
            )

        first = self._linked("first")
        second = self._linked("second")
        first_marker = first / ".git"
        second_marker = second / ".git"
        first_marker.write_bytes(second_marker.read_bytes())
        with self.assertRaisesRegex(
            RepositoryContextError,
            "exact Git top-level|administrative identity|active linked worktree|worktree backlink",
        ):
            resolve_repository_context(
                root_repo=str(self.repository), temporary_repo=str(first)
            )

    def test_symlink_is_rejected_but_shared_writable_ancestor_is_allowed(self) -> None:
        alias = self.test_root / "repository-alias"
        alias.symlink_to(self.repository, target_is_directory=True)
        with self.assertRaisesRegex(RepositoryContextError, "symbolic-link"):
            resolve_repository_context(root_repo=str(alias), temporary_repo=None)

        unsafe_parent = self.test_root / "replaceable"
        unsafe_parent.mkdir(mode=0o777)
        unsafe = unsafe_parent / "unsafe-repository"
        self._initialize_repository(unsafe)
        unsafe_parent.chmod(0o777)
        shared = resolve_repository_context(
            root_repo=str(unsafe), temporary_repo=None
        )
        self.assertEqual(shared.root.canonical_root, str(unsafe))

    def test_ambient_repository_redirection_and_local_config_include_are_rejected(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"GIT_DIR": str(self.repository / ".git")},
            clear=False,
        ):
            with self.assertRaisesRegex(RepositoryContextError, "GIT_DIR"):
                resolve_repository_context(
                    root_repo=str(self.repository), temporary_repo=None
                )

        include = self.test_root / "malicious.gitconfig"
        include.write_text("[core]\n\tworktree = /foreign\n", encoding="utf-8")
        with (self.repository / ".git" / "config").open("a", encoding="utf-8") as stream:
            stream.write(f"\n[include]\n\tpath = {include}\n")
        with self.assertRaisesRegex(RepositoryContextError, "includes are not allowed"):
            resolve_repository_context(root_repo=str(self.repository), temporary_repo=None)

    def test_global_config_and_path_cannot_select_git_or_change_identity(self) -> None:
        malicious_home = self.test_root / "malicious-home"
        malicious_home.mkdir(mode=0o700)
        sentinel = self.test_root / "fake-git-ran"
        fake_bin = self.test_root / "fake-bin"
        fake_bin.mkdir(mode=0o700)
        fake_git = fake_bin / "git"
        fake_git.write_text(
            "#!/bin/sh\nprintf ran > \"$FAKE_GIT_SENTINEL\"\nexit 90\n",
            encoding="utf-8",
        )
        fake_git.chmod(0o700)
        (malicious_home / ".gitconfig").write_text(
            "[include]\n\tpath = /definitely/foreign\n", encoding="utf-8"
        )
        with mock.patch.dict(
            os.environ,
            {
                "HOME": str(malicious_home),
                "PATH": str(fake_bin),
                "FAKE_GIT_SENTINEL": str(sentinel),
            },
            clear=False,
        ):
            context = resolve_repository_context(
                root_repo=str(self.repository), temporary_repo=None
            )
        self.assertEqual(context.root.canonical_root, str(self.repository))
        self.assertFalse(sentinel.exists())

    def test_path_and_git_admin_replacement_are_detected_before_persistence(self) -> None:
        home = self.test_root / "coordinator"
        with AccountStore.open_default(home, effective_uid=os.geteuid()) as store:
            repo_id = self._insert_repository(store, self.repository)
            context = resolve_repository_context(
                root_repo=str(self.repository), temporary_repo=None
            )
            persist_repository_context(
                store,
                context,
                root_repo_id=repo_id,
                effective_repo_id=repo_id,
                timestamp="2026-01-01T00:00:00Z",
            )

            old_git = self.repository / ".git-old"
            (self.repository / ".git").rename(old_git)
            self._git("init", "-q", str(self.repository))
            replacement = resolve_repository_context(
                root_repo=str(self.repository), temporary_repo=None
            )
            self.assertNotEqual(
                replacement.root.git_dir_inode, context.root.git_dir_inode
            )
            self.assertNotEqual(
                replacement.root.identity_fingerprint,
                context.root.identity_fingerprint,
            )
            with self.assertRaisesRegex(RepositoryContextError, "changed since configuration"):
                persist_repository_context(
                    store,
                    replacement,
                    root_repo_id=repo_id,
                    effective_repo_id=repo_id,
                    timestamp="2026-01-01T00:00:01Z",
                )
            with self.assertRaisesRegex(RepositoryContextError, "between request proof"):
                persist_repository_context(
                    store,
                    context,
                    root_repo_id=repo_id,
                    effective_repo_id=repo_id,
                    timestamp="2026-01-01T00:00:02Z",
                )

            replaced_worktree = self.test_root / "replaced-worktree"
            self.repository.rename(replaced_worktree)
            self._initialize_repository(self.repository)
            second_replacement = resolve_repository_context(
                root_repo=str(self.repository), temporary_repo=None
            )
            self.assertNotEqual(
                second_replacement.root.root_inode,
                replacement.root.root_inode,
            )
            with self.assertRaisesRegex(RepositoryContextError, "between request proof"):
                persist_repository_context(
                    store,
                    replacement,
                    root_repo_id=repo_id,
                    effective_repo_id=repo_id,
                    timestamp="2026-01-01T00:00:03Z",
                )

    def test_repeated_exact_persistence_does_not_change_rows_or_state_revision(self) -> None:
        home = self.test_root / "coordinator-idempotent"
        with AccountStore.open_default(home, effective_uid=os.geteuid()) as store:
            repo_id = self._insert_repository(store, self.repository)
            context = resolve_repository_context(
                root_repo=str(self.repository), temporary_repo=None
            )
            persist_repository_context(
                store,
                context,
                root_repo_id=repo_id,
                effective_repo_id=repo_id,
                timestamp="2026-01-01T00:00:00Z",
            )
            with store.read_transaction() as connection:
                before = dict(
                    connection.execute(
                        """
                        SELECT m.state_revision,
                               f.updated_at AS family_updated_at,
                               s.updated_at AS scope_updated_at
                        FROM schema_metadata m
                        JOIN repository_families f ON f.family_id = ?
                        JOIN repository_scopes s ON s.repo_id = ?
                        WHERE m.singleton = 1
                        """,
                        (repo_id, repo_id),
                    ).fetchone()
                )
            changes_before = store.connection.total_changes
            persist_repository_context(
                store,
                context,
                root_repo_id=repo_id,
                effective_repo_id=repo_id,
                timestamp="2026-01-02T00:00:00Z",
            )
            with store.read_transaction() as connection:
                after = dict(
                    connection.execute(
                        """
                        SELECT m.state_revision,
                               f.updated_at AS family_updated_at,
                               s.updated_at AS scope_updated_at
                        FROM schema_metadata m
                        JOIN repository_families f ON f.family_id = ?
                        JOIN repository_scopes s ON s.repo_id = ?
                        WHERE m.singleton = 1
                        """,
                        (repo_id, repo_id),
                    ).fetchone()
                )
            self.assertEqual(store.connection.total_changes, changes_before)
        self.assertEqual(after, before)

    def test_linked_proof_uses_bounded_git_reads_and_persistence_uses_none(self) -> None:
        linked = self._linked()
        home = self.test_root / "coordinator-bounded-git"
        with mock.patch.object(
            repository_context_module,
            "_git",
            wraps=repository_context_module._git,
        ) as git_call:
            context = resolve_repository_context(
                root_repo=str(self.repository), temporary_repo=str(linked)
            )
            proof_git_reads = git_call.call_count
            self.assertGreaterEqual(proof_git_reads, 3)
            self.assertLessEqual(proof_git_reads, 5)
            with AccountStore.open_default(home, effective_uid=os.geteuid()) as store:
                root_id = self._insert_repository(store, self.repository)
                linked_id = self._insert_repository(store, linked)
                persist_repository_context(
                    store,
                    context,
                    root_repo_id=root_id,
                    effective_repo_id=linked_id,
                    timestamp="2026-01-01T00:00:00Z",
                )
                persist_repository_context(
                    store,
                    context,
                    root_repo_id=root_id,
                    effective_repo_id=linked_id,
                    timestamp="2026-01-02T00:00:00Z",
                )
            self.assertEqual(git_call.call_count, proof_git_reads)

    def test_singleton_runtime_session_moves_before_temporary_family_deletion(self) -> None:
        linked = self._linked()
        home = self.test_root / "coordinator-session"
        context = resolve_repository_context(
            root_repo=str(self.repository), temporary_repo=str(linked)
        )
        with AccountStore.open_default(home, effective_uid=os.geteuid()) as store:
            root_id = self._insert_repository(store, self.repository)
            linked_id = self._insert_repository(store, linked)
            session_id = create_runtime_session(
                store,
                family_id=linked_id,
                root_repo_id=linked_id,
                repo_id=linked_id,
                request={
                    "action": "status",
                    "purpose": "development",
                    "ttl_seconds": None,
                    "kill_after_run": False,
                    "agent": "fixture",
                },
                timestamp="2026-01-01T00:00:00Z",
            )
            mark_runtime_session_started(
                store, session_id, timestamp="2026-01-01T00:00:00Z"
            )
            finish_runtime_session(
                store,
                session_id,
                succeeded=True,
                result={"ok": True},
                keep_running_until_ttl=True,
                timestamp="2026-01-01T00:00:00Z",
            )
            link_runtime_resource(
                store,
                session_id=session_id,
                resource_kind="service",
                resource_id="reserved-service",
                cleanup_disposition="removed",
                identity={"state": "reserved", "repo_id": linked_id},
                timestamp="2026-01-01T00:00:00Z",
            )
            persist_repository_context(
                store,
                context,
                root_repo_id=root_id,
                effective_repo_id=linked_id,
                timestamp="2026-01-01T00:00:01Z",
            )
            with store.read_transaction() as connection:
                session = dict(
                    connection.execute(
                        """
                        SELECT family_id, root_repo_id, repo_id, status,
                               execution_owner_pid, execution_owner_identity
                        FROM runtime_sessions WHERE session_id = ?
                        """,
                        (session_id,),
                    ).fetchone()
                )
                old_family = connection.execute(
                    "SELECT 1 FROM repository_families WHERE family_id = ?",
                    (linked_id,),
                ).fetchone()
                resource = dict(
                    connection.execute(
                        """
                        SELECT session_id, resource_kind, resource_id,
                               cleanup_state
                        FROM runtime_session_resources
                        WHERE session_id = ?
                        """,
                        (session_id,),
                    ).fetchone()
                )
                revision_before_repeat = connection.execute(
                    "SELECT state_revision FROM schema_metadata WHERE singleton = 1"
                ).fetchone()[0]
            changes_before_repeat = store.connection.total_changes
            persist_repository_context(
                store,
                context,
                root_repo_id=root_id,
                effective_repo_id=linked_id,
                timestamp="2026-01-02T00:00:00Z",
            )
            with store.read_transaction() as connection:
                revision_after_repeat = connection.execute(
                    "SELECT state_revision FROM schema_metadata WHERE singleton = 1"
                ).fetchone()[0]
            self.assertEqual(store.connection.total_changes, changes_before_repeat)
        self.assertEqual(
            {
                "family_id": session["family_id"],
                "root_repo_id": session["root_repo_id"],
                "repo_id": session["repo_id"],
                "status": session["status"],
            },
            {
                "family_id": root_id,
                "root_repo_id": root_id,
                "repo_id": linked_id,
                "status": "running",
            },
        )
        self.assertEqual(session["execution_owner_pid"], os.getpid())
        self.assertTrue(session["execution_owner_identity"])
        self.assertEqual(
            resource,
            {
                "session_id": session_id,
                "resource_kind": "service",
                "resource_id": "reserved-service",
                "cleanup_state": "active",
            },
        )
        self.assertIsNone(old_family)
        self.assertEqual(revision_after_repeat, revision_before_repeat)

    def test_versioned_identity_is_stable_across_normal_repository_activity(self) -> None:
        before = resolve_repository_context(
            root_repo=str(self.repository), temporary_repo=None
        )
        (self.repository / "second.txt").write_text("second\n", encoding="utf-8")
        self._git("add", "second.txt", cwd=self.repository)
        self._git("commit", "-qm", "second", cwd=self.repository)
        self._git("config", "fixture.identity-test", "changed", cwd=self.repository)
        self.repository.chmod(0o750)
        (self.repository / ".git").chmod(0o750)

        after = resolve_repository_context(
            root_repo=str(self.repository), temporary_repo=None
        )
        self.assertEqual(after.root.identity_fingerprint, before.root.identity_fingerprint)
        self.assertNotEqual(
            after.root.legacy_identity_fingerprint,
            before.root.legacy_identity_fingerprint,
        )

    def test_legacy_identity_is_transactionally_upgraded_once(self) -> None:
        home = self.test_root / "coordinator-fingerprint-upgrade"
        context = resolve_repository_context(
            root_repo=str(self.repository), temporary_repo=None
        )
        with AccountStore.open_default(home, effective_uid=os.geteuid()) as store:
            repo_id = self._insert_repository(store, self.repository)
            persist_repository_context(
                store,
                context,
                root_repo_id=repo_id,
                effective_repo_id=repo_id,
                timestamp="2026-01-01T00:00:00Z",
            )
            with store.immediate_transaction(revision_kind=None) as connection:
                connection.execute(
                    """
                    UPDATE repository_families
                    SET identity_fingerprint = ? WHERE family_id = ?
                    """,
                    (context.root.legacy_identity_fingerprint, repo_id),
                )
                connection.execute(
                    """
                    UPDATE repository_scopes
                    SET identity_fingerprint = ?, root_device = NULL,
                        root_inode = NULL
                    WHERE repo_id = ?
                    """,
                    (context.root.legacy_identity_fingerprint, repo_id),
                )
                revision_before = connection.execute(
                    "SELECT state_revision FROM schema_metadata WHERE singleton = 1"
                ).fetchone()[0]
            persist_repository_context(
                store,
                context,
                root_repo_id=repo_id,
                effective_repo_id=repo_id,
                timestamp="2026-01-02T00:00:00Z",
            )
            with store.read_transaction() as connection:
                row = connection.execute(
                    """
                    SELECT family.identity_fingerprint AS family_fingerprint,
                           scope.identity_fingerprint AS scope_fingerprint,
                           scope.root_device, scope.root_inode,
                           metadata.state_revision
                    FROM repository_families family
                    JOIN repository_scopes scope ON scope.repo_id = ?
                    JOIN schema_metadata metadata ON metadata.singleton = 1
                    WHERE family.family_id = ?
                    """,
                    (repo_id, repo_id),
                ).fetchone()
            self.assertEqual(row["family_fingerprint"], context.root.identity_fingerprint)
            self.assertEqual(row["scope_fingerprint"], context.root.identity_fingerprint)
            self.assertEqual(row["root_device"], context.root.root_device)
            self.assertEqual(row["root_inode"], context.root.root_inode)
            self.assertEqual(row["state_revision"], revision_before + 1)

            changes_before = store.connection.total_changes
            persist_repository_context(
                store,
                context,
                root_repo_id=repo_id,
                effective_repo_id=repo_id,
                timestamp="2026-01-03T00:00:00Z",
            )
            self.assertEqual(store.connection.total_changes, changes_before)

    def test_schema_v7_requires_explicit_offline_migration_without_writes(self) -> None:
        home = self.test_root / "coordinator-schema-v7"
        with AccountStore.open_default(home, effective_uid=os.geteuid()) as store:
            with store.immediate_transaction(
                revision_kind=None, check_invariants=False
            ) as connection:
                connection.execute("ALTER TABLE repository_scopes DROP COLUMN root_device")
                connection.execute("ALTER TABLE repository_scopes DROP COLUMN root_inode")
                connection.execute(
                    "UPDATE schema_metadata SET schema_version = 7 WHERE singleton = 1"
                )
        database = home / "coordinator.sqlite3"
        before = database.read_bytes()
        with self.assertRaisesRegex(
            RuntimeError, "unsupported coordinator database schema 7"
        ):
            AccountStore.open_default(home, effective_uid=os.geteuid())
        self.assertEqual(database.read_bytes(), before)
        with sqlite3.connect(database) as connection:
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(repository_scopes)")
            }
            version = int(
                connection.execute(
                    "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
                ).fetchone()[0]
            )
        self.assertNotIn("root_device", columns)
        self.assertNotIn("root_inode", columns)
        self.assertEqual(version, 7)

    def test_unicode_path_legacy_digest_matches_pre_version_algorithm(self) -> None:
        repository = self.test_root / "репозиторій"
        self._initialize_repository(repository)
        context = resolve_repository_context(
            root_repo=str(repository), temporary_repo=None
        )
        root_identity = repository_context_module._path_identity(repository.stat())
        admin = repository_context_module._admin_snapshot(repository)
        git_identity = {
            "object_format": "sha1",
            "inside_worktree": "true",
            "bare": "false",
        }
        material = {
            "canonical_root": str(repository),
            "root": root_identity.legacy_material(),
            "git_dir": {
                "path": admin.git_dir,
                **admin.git_dir_identity.legacy_material(),
            },
            "git_common_dir": {
                "path": admin.git_common_dir,
                **admin.git_common_dir_identity.legacy_material(),
            },
            "git_marker_kind": admin.marker_kind,
            "git_marker_fingerprint": admin.marker_digest,
            "git_identity": git_identity,
        }
        encoded = json.dumps(
            material,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        expected = "sha256:" + hashlib.sha256(encoded).hexdigest()
        self.assertEqual(context.root.legacy_identity_fingerprint, expected)

    def test_filesystem_identity_lookup_deduplicates_aliases_and_fails_on_corruption(self) -> None:
        home = self.test_root / "coordinator-alias"
        context = resolve_repository_context(
            root_repo=str(self.repository), temporary_repo=None
        )
        with AccountStore.open_default(home, effective_uid=os.geteuid()) as store:
            repo_id = self._insert_repository(store, self.repository)
            host_id = store.ensure_local_host()
            persist_repository_context(
                store,
                context,
                root_repo_id=repo_id,
                effective_repo_id=repo_id,
                timestamp="2026-01-01T00:00:00Z",
            )
            spelling_alias = replace(
                context.root,
                canonical_root=str(self.repository).swapcase(),
                git_dir=str(self.repository / ".git").swapcase(),
            )
            with store.immediate_transaction(revision_kind=None) as connection:
                self.assertEqual(
                    find_repository_id_by_filesystem_identity(
                        connection,
                        host_id=host_id,
                        scope=spelling_alias,
                    ),
                    repo_id,
                )

            duplicate = self.test_root / "duplicate-row"
            self._initialize_repository(duplicate)
            duplicate_id = self._insert_repository(store, duplicate)
            with store.immediate_transaction(
                revision_kind=None, check_invariants=False
            ) as connection:
                connection.execute(
                    """
                    UPDATE repository_scopes
                    SET root_device = ?, root_inode = ?
                    WHERE repo_id = ?
                    """,
                    (
                        context.root.root_device,
                        context.root.root_inode,
                        duplicate_id,
                    ),
                )
            with store.read_transaction() as connection:
                violations = invariant_violations(connection)
                self.assertIn(
                    "repository_scope_duplicate_filesystem_identity",
                    {violation.code for violation in violations},
                )
            with store.immediate_transaction(
                revision_kind=None, check_invariants=False
            ) as connection:
                with self.assertRaisesRegex(
                    RepositoryContextError, "multiple repository rows"
                ):
                    find_repository_id_by_filesystem_identity(
                        connection,
                        host_id=host_id,
                        scope=context.root,
                    )

    def test_untrusted_unrelated_legacy_repository_is_not_an_identity_match(self) -> None:
        context = resolve_repository_context(
            root_repo=str(self.repository), temporary_repo=None
        )
        error = RepositoryContextError("unrelated repository was replaced")

        with mock.patch.object(
            repository_context_module,
            "_canonical_existing_directory",
            side_effect=error,
        ):
            self.assertFalse(
                repository_context_module._repository_path_matches_scope(
                    "/unrelated/legacy/repository",
                    context.root,
                )
            )

    def test_case_alias_resolves_to_same_identity_when_filesystem_supports_it(self) -> None:
        alias = self.repository.with_name(self.repository.name.upper())
        if alias == self.repository or not alias.exists() or not os.path.samefile(
            alias, self.repository
        ):
            self.skipTest("test filesystem is case-sensitive")
        canonical = resolve_repository_context(
            root_repo=str(self.repository), temporary_repo=None
        )
        aliased = resolve_repository_context(root_repo=str(alias), temporary_repo=None)
        self.assertEqual(
            aliased.root.identity_fingerprint,
            canonical.root.identity_fingerprint,
        )
        self.assertEqual(aliased.root.root_inode, canonical.root.root_inode)

    def test_git_output_limit_is_enforced_while_streaming(self) -> None:
        with mock.patch.object(repository_context_module, "_MAX_GIT_OUTPUT", 16):
            with self.assertRaisesRegex(
                RepositoryContextError, "stdout exceeded 16 bytes"
            ):
                repository_context_module._git(
                    self.repository, "worktree", "list", "--porcelain", "-z"
                )

    def test_git_command_admits_only_the_exact_canonical_worktree(self) -> None:
        command = repository_context_module._git_command(
            self.repository, "rev-parse", "--show-toplevel"
        )

        self.assertIn(f"safe.directory={self.repository}", command)
        self.assertEqual(command[command.index("-C") + 1], str(self.repository))
        self.assertNotIn("--global", command)
        self.assertNotIn("safe.directory=*", command)
        self.assertFalse(
            any(
                argument.startswith("safe.directory=") and argument.endswith("/*")
                for argument in command
            )
        )

        alias = self.test_root / "repository-alias"
        alias.symlink_to(self.repository, target_is_directory=True)
        with self.assertRaisesRegex(
            RepositoryContextError, "symbolic-link|canonical non-symlink"
        ):
            repository_context_module._git_command(
                alias, "rev-parse", "--show-toplevel"
            )

    def test_git_inspection_handles_different_owner_without_global_config(self) -> None:
        environment = repository_context_module._git_environment()
        forced_home = self.test_root / "different-owner-home"
        forced_home.mkdir(mode=0o700)
        environment.update(
            {
                "GIT_TEST_ASSUME_DIFFERENT_OWNER": "1",
                "HOME": str(forced_home),
            }
        )

        with mock.patch.object(
            repository_context_module,
            "_git_environment",
            return_value=environment,
        ):
            raw = repository_context_module._git(
                self.repository, "rev-parse", "--show-toplevel"
            )

        self.assertEqual(
            raw.decode("utf-8", errors="surrogateescape").strip(),
            str(self.repository),
        )
        self.assertFalse((forced_home / ".gitconfig").exists())

    def test_trusted_git_accepts_any_executable_regular_system_candidate(self) -> None:
        real_metadata = Path(GIT).lstat()
        unsafe_modes = (
            real_metadata.st_mode | stat.S_IWGRP,
            real_metadata.st_mode | stat.S_IWOTH,
            real_metadata.st_mode | stat.S_ISUID,
        )
        for unsafe_mode in unsafe_modes:
            with self.subTest(mode=oct(unsafe_mode)):
                unsafe = SimpleNamespace(st_mode=unsafe_mode, st_uid=99_999)
                with mock.patch.object(Path, "lstat", return_value=unsafe), mock.patch.object(
                    os, "access", return_value=True
                ):
                    self.assertEqual(
                        repository_context_module._trusted_git_executable(),
                        "/usr/bin/git",
                    )

    def test_nul_is_normalized_and_non_utf8_repository_path_is_supported(self) -> None:
        with self.assertRaisesRegex(RepositoryContextError, "NUL"):
            resolve_repository_context(
                root_repo=str(self.repository) + "\0suffix", temporary_repo=None
            )

        raw_path = os.fsencode(self.test_root) + b"/repository-\xff"
        non_utf8 = Path(os.fsdecode(raw_path))
        try:
            self._initialize_repository(non_utf8)
        except OSError:
            if sys.platform != "darwin":
                raise
            # APFS rejects non-UTF-8 names. Exercise the serialization boundary
            # directly while Linux covers the real filesystem path below.
            self.assertRegex(
                repository_context_module._fingerprint({"path": "\udcff"}),
                r"^sha256:[0-9a-f]{64}$",
            )
            return
        context = resolve_repository_context(
            root_repo=os.fsdecode(raw_path), temporary_repo=None
        )
        self.assertRegex(
            context.root.identity_fingerprint,
            r"^repository-scope-v2:sha256:[0-9a-f]{64}$",
        )

    def test_final_reproof_detects_replacement_during_worktree_enumeration(self) -> None:
        original = repository_context_module._listed_worktrees

        def replace_after_list(path: Path) -> tuple[str, ...]:
            worktrees = original(path)
            (self.repository / ".git").rename(self.repository / ".git-before-race")
            self._git("init", "-q", str(self.repository))
            return worktrees

        with mock.patch.object(
            repository_context_module,
            "_listed_worktrees",
            side_effect=replace_after_list,
        ):
            with self.assertRaisesRegex(
                RepositoryContextError, "changed between request proof|changed during"
            ):
                resolve_repository_context(
                    root_repo=str(self.repository), temporary_repo=None
                )

    def test_concurrent_exact_persistence_serializes_to_one_revision(self) -> None:
        home = self.test_root / "coordinator-concurrent"
        linked = self._linked("concurrent-linked")
        context = resolve_repository_context(
            root_repo=str(self.repository), temporary_repo=str(linked)
        )
        with AccountStore.open_default(home, effective_uid=os.geteuid()) as store:
            root_id = self._insert_repository(store, self.repository)
            linked_id = self._insert_repository(store, linked)
            with store.read_transaction() as connection:
                revision_before = connection.execute(
                    "SELECT state_revision FROM schema_metadata WHERE singleton = 1"
                ).fetchone()[0]

        barrier = threading.Barrier(2)

        def persist() -> str:
            with AccountStore.open_default(home, effective_uid=os.geteuid()) as store:
                barrier.wait(timeout=10)
                result = persist_repository_context(
                    store,
                    context,
                    root_repo_id=root_id,
                    effective_repo_id=linked_id,
                    timestamp="2026-01-01T00:00:00Z",
                )
                return result.family_id

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = (pool.submit(persist), pool.submit(persist))
            results = [future.result(timeout=20) for future in futures]
        self.assertEqual(results, [root_id, root_id])
        with AccountStore.open_default(home, effective_uid=os.geteuid()) as store:
            with store.read_transaction() as connection:
                revision_after = connection.execute(
                    "SELECT state_revision FROM schema_metadata WHERE singleton = 1"
                ).fetchone()[0]
                linked_scope = dict(
                    connection.execute(
                        """
                        SELECT family_id, project_kind
                        FROM repository_scopes WHERE repo_id = ?
                        """,
                        (linked_id,),
                    ).fetchone()
                )
                old_family = connection.execute(
                    "SELECT 1 FROM repository_families WHERE family_id = ?",
                    (linked_id,),
                ).fetchone()
        self.assertEqual(revision_after, revision_before + 1)
        self.assertEqual(
            linked_scope, {"family_id": root_id, "project_kind": "temporary"}
        )
        self.assertIsNone(old_family)

    def test_optimized_python_keeps_linked_worktree_boundary(self) -> None:
        linked = self._linked()
        foreign = self.test_root / "optimized-foreign"
        self._initialize_repository(foreign)
        scripts_root = Path(__file__).resolve().parents[2]
        script = """
import sys
from devcoordinator.repository_context import RepositoryContextError, resolve_repository_context
good = resolve_repository_context(root_repo=sys.argv[1], temporary_repo=sys.argv[2])
if good.project_kind != 'temporary':
    raise SystemExit(10)
try:
    resolve_repository_context(root_repo=sys.argv[1], temporary_repo=sys.argv[3])
except RepositoryContextError:
    print('optimized-boundary-ok')
else:
    raise SystemExit(11)
"""
        environment = git_environment(home=self.git_home)
        environment.pop("GIT_CONFIG_GLOBAL", None)
        environment.pop("GIT_CONFIG_NOSYSTEM", None)
        environment.pop("GIT_CONFIG_SYSTEM", None)
        environment["PYTHONPATH"] = str(scripts_root)
        completed = subprocess.run(
            [
                sys.executable,
                "-O",
                "-c",
                script,
                str(self.repository),
                str(linked),
                str(foreign),
            ],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "optimized-boundary-ok")


if __name__ == "__main__":
    unittest.main()
