"""Project-incarnation revocation and stale protected-profile regressions."""

from __future__ import annotations

import os
from pathlib import Path
import pwd
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from devcoordinator import broker_backend as broker_backend_module
from devcoordinator import broker_enrollment
from devcoordinator.broker import BrokerOperation
from devcoordinator.broker_backend import StoreBackedMutationBackend
from devcoordinator.broker_links import BrokerLinkStore
from devcoordinator.broker_profile import (
    BrokerClientProfile,
    BrokerRepositoryProfile,
    BrokerServiceProfile,
)
from devcoordinator.store import AccountStore


UID = os.geteuid()


class CanonicalTemporaryDirectory:
    def __init__(self) -> None:
        home = Path(pwd.getpwuid(UID).pw_dir).resolve()
        self._temporary = tempfile.TemporaryDirectory(
            prefix="devcoordinator-project-revocation-",
            dir=str(home),
        )
        self.path = Path(self._temporary.name).resolve()

    def cleanup(self) -> None:
        self._temporary.cleanup()


def repository_profile(root: Path, *, generation: int) -> BrokerRepositoryProfile:
    return BrokerRepositoryProfile(
        canonical_root=str(root),
        repo_id="repo-project",
        generation=generation,
        owner_uid=1000,
        server_ids={"worker": f"worker-generation-{generation}"},
        container_ids={"postgres": "container-old"},
        compose_definition_id=None,
        compose_container_ids=frozenset(),
        compose_run_once_services={},
        ephemeral_templates={},
        ephemeral_image_prefetch_template_ids=frozenset(),
        ephemeral_secret_policies={},
        account_id="account-project",
        enabled=True,
        issued_at="2026-07-26T00:00:00Z",
        valid_until_epoch=int(time.time()) + 3600,
    )


def client_profile(repository: BrokerRepositoryProfile) -> BrokerClientProfile:
    return BrokerClientProfile(
        service=BrokerServiceProfile(
            socket_path=Path("/run/devcoordinator-authority.sock"),
            service_uid=0,
            socket_gid=62000,
            socket_mode=0o660,
            database_generation="database-generation",
        ),
        client_uid=UID,
        account_id="account-project",
        issued_at="2026-07-26T00:00:00Z",
        valid_until_epoch=int(time.time()) + 3600,
        repositories={repository.canonical_root: repository},
    )


def profile_document(root: Path) -> dict[str, object]:
    repository = {
        "canonical_root": str(root),
        "repo_id": "repo-project",
        "generation": 7,
        "owner_uid": 1000,
        "servers": {"worker": "worker-old"},
        "containers": {"postgres": "container-old"},
        "compose_definition_id": None,
        "compose_container_ids": [],
        "compose_run_once_services": {},
        "ephemeral_templates": {},
        "ephemeral_image_prefetch_templates": [],
        "ephemeral_secret_policies": {},
        "account_id": "account-project",
        "enabled": True,
        "issued_at": "2026-07-26T00:00:00Z",
        "valid_until_epoch": int(time.time()) + 3600,
    }
    return {
        "version": 1,
        "service": {
            "socket": "/run/devcoordinator-authority.sock",
            "uid": 0,
            "gid": 62000,
            "mode": "0660",
            "database_generation": "database-generation",
        },
        "clients": {
            "501": {
                "account_id": "account-project",
                "issued_at": "2026-07-26T00:00:00Z",
                "valid_until_epoch": int(time.time()) + 3600,
                "repositories": [dict(repository)],
            },
            "502": {
                "account_id": "account-project-two",
                "issued_at": "2026-07-26T00:00:00Z",
                "valid_until_epoch": int(time.time()) + 3600,
                "repositories": [
                    {**repository, "account_id": "account-project-two"}
                ],
            },
            "503": {
                "account_id": "unrelated",
                "issued_at": "2026-07-26T00:00:00Z",
                "valid_until_epoch": int(time.time()) + 3600,
                "repositories": [
                    {
                        **repository,
                        "canonical_root": str(root.parent / "other"),
                        "repo_id": "repo-other",
                        "account_id": "unrelated",
                    }
                ],
            },
        },
    }


class ProjectProfileRevocationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = CanonicalTemporaryDirectory()
        self.root = self.temporary.path / "repository"
        self.root.mkdir()
        (self.root / ".git").mkdir()
        self.database = self.temporary.path / "account.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_protected_profile_removes_exact_project_generation_for_every_client(
        self,
    ) -> None:
        document = profile_document(self.root)
        affected = broker_enrollment._revoke_repository_from_profile_document(
            document,
            repo_id="repo-project",
            repository_generation=7,
        )
        self.assertEqual(affected, [501, 502])
        self.assertEqual(document["clients"]["501"]["repositories"], [])
        self.assertEqual(document["clients"]["502"]["repositories"], [])
        self.assertEqual(
            document["clients"]["503"]["repositories"][0]["repo_id"],
            "repo-other",
        )

        replay = broker_enrollment._revoke_repository_from_profile_document(
            document,
            repo_id="repo-project",
            repository_generation=7,
        )
        self.assertEqual(replay, [])

    def test_profile_call_binds_repository_generation_to_broker_request(self) -> None:
        repository = repository_profile(self.root, generation=7)
        profile = client_profile(repository)
        with mock.patch(
            "devcoordinator.broker_profile.call_broker",
            return_value=("operation", {"status": "ok"}),
        ) as call:
            profile.call(
                repository=repository,
                resource_id=repository.repo_id,
                operation=BrokerOperation.INVENTORY_READ,
                arguments={},
            )
        self.assertEqual(call.call_args.kwargs["repository_generation"], 7)

    def test_account_journal_fences_stale_generation_and_accepts_new_profile_generation(
        self,
    ) -> None:
        old_repository = repository_profile(self.root, generation=7)
        old_profile = client_profile(old_repository)
        with AccountStore.open(self.database, expected_uid=UID) as store:
            links = BrokerLinkStore(store)
            links._ensure_server(
                old_repository,
                "worker",
                "worker-generation-7",
            )
            revoked = links.revoke_repository_materialization(
                profile=old_profile,
                repository=old_repository,
                broker_operation_id="project-cleanup-operation",
                immutable_fingerprint="sha256:" + "a" * 64,
            )
            self.assertTrue(revoked["active_projection_removed"], revoked)

            with self.assertRaisesRegex(RuntimeError, "permanently removed"):
                links._ensure_server(
                    old_repository,
                    "worker",
                    "worker-generation-7",
                )

            with store.read_transaction() as connection:
                old_project = connection.execute(
                    """
                    SELECT state, generation FROM repositories
                    WHERE repo_id = 'repo-project'
                    """
                ).fetchone()
                old_worker = connection.execute(
                    """
                    SELECT 1 FROM server_definitions
                    WHERE server_definition_id = 'worker-generation-7'
                    """
                ).fetchone()
            self.assertEqual(dict(old_project), {"state": "missing", "generation": 8})
            self.assertIsNone(old_worker)

            new_repository = repository_profile(self.root, generation=9)
            links._ensure_server(
                new_repository,
                "worker",
                "worker-generation-9",
            )
            with store.read_transaction() as connection:
                current = connection.execute(
                    """
                    SELECT state, generation FROM repositories
                    WHERE repo_id = 'repo-project'
                    """
                ).fetchone()
                fences = int(
                    connection.execute(
                        """
                        SELECT COUNT(*)
                        FROM broker_repository_materialization_revocations
                        WHERE repo_id = 'repo-project'
                          AND repository_generation = 7
                        """
                    ).fetchone()[0]
                )
            self.assertEqual(dict(current), {"state": "active", "generation": 9})
            self.assertEqual(fences, 1)

    def test_project_revocation_guards_do_not_depend_on_assert_statements(self) -> None:
        for source in (
            Path(broker_enrollment.__file__),
            Path(__file__).parents[1] / "broker_links.py",
        ):
            text = source.read_text(encoding="utf-8")
            self.assertNotIn("assert ", text)
            self.assertNotIn("__debug__", text)

    def test_project_cleanup_prepares_service_profile_and_account_evidence(
        self,
    ) -> None:
        calls: list[str] = []
        persistence = mock.MagicMock()
        persistence.revoke_repository_for_permanent_cleanup.side_effect = (
            lambda **_kwargs: calls.append("service")
            or {
                "repo_id": "repo-project",
                "repository_generation": 7,
                "cleanup_operation_id": "cleanup-project",
                "immutable_fingerprint": "sha256:" + "a" * 64,
            }
        )
        persistence.remove_revoked_repository_server_definitions.side_effect = (
            lambda **_kwargs: calls.append("projections")
            or {"status": "removed"}
        )
        persistence.database_generation.return_value = "database-generation"
        backend = object.__new__(StoreBackedMutationBackend)
        backend._persistence = persistence
        plan = SimpleNamespace(
            action="forget",
            target_kind="project",
            target_id="repo-project",
            repo_id="repo-project",
            plan_id="cleanup-project",
            target_fingerprint="sha256:" + "a" * 64,
            snapshot={"identity": {"generation": 7}},
        )
        authorized = SimpleNamespace(peer=SimpleNamespace(uid=UID))
        with (
            mock.patch.object(
                broker_backend_module,
                "unregister_workers_for_plan",
                side_effect=lambda *_args, **_kwargs: calls.append("workers")
                or {"workers": []},
            ),
            mock.patch.object(
                broker_backend_module,
                "configured_profile_path",
                return_value=Path("/protected/profile.json"),
            ),
            mock.patch.object(
                broker_backend_module,
                "revoke_repository_from_protected_profile",
                side_effect=lambda **_kwargs: calls.append("profile")
                or {
                    "repo_id": "repo-project",
                    "repository_generation": 7,
                    "cleanup_operation_id": "cleanup-project",
                },
            ),
        ):
            result = backend._prepare_worker_lifecycle_apply(
                authorized,
                store=mock.MagicMock(),
                plan=plan,
                actor="test-actor",
            )

        self.assertEqual(calls, ["service", "workers", "projections", "profile"])
        self.assertEqual(
            result["repository_revocation"]["service"]["repository_generation"],
            7,
        )


if __name__ == "__main__":
    unittest.main()
