"""Recall tests for broker-generated ephemeral PostgreSQL credentials."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
import uuid
from unittest import mock

from devcoordinator import broker_enrollment
from devcoordinator.broker_persistence import BrokerPersistence
from devcoordinator.broker_profile import BrokerProfileError, profile_from_document
from devcoordinator.ephemeral_secrets import (
    EphemeralSecretPolicy,
    SecretGrantDenied,
    SecretGrantExpired,
    SecretGrantReplay,
    VolatileRunSecretManager,
)
from devcoordinator.schema import initialize_schema
from devcoordinator.store import deterministic_id


_POLICY = "postgres_initdb_password_file_v1"
_IMAGE = "postgres@sha256:" + "a" * 64
_QUOTAS = {
    "max_concurrent_runs": 4,
    "max_concurrent_runs_per_uid": 2,
    "repo_max_active_runs": 16,
    "repo_memory_budget_bytes": 8 * 1024 * 1024 * 1024,
    "repo_cpu_budget_millis": 16_000,
}


class _Clock:
    def __init__(self, value: int = 10_000) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class VolatileSecretManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="devcoordinator-ephemeral-secret-", dir=str(Path("/tmp").resolve())
        )
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.clock = _Clock()
        self.manager = VolatileRunSecretManager(
            runtime_root=self.root / "runtime",
            expected_uid=os.geteuid(),
            clock=self.clock,
            password_factory=lambda: b"p" * 64,
        )
        self.run_id = uuid.uuid4()
        self.policy = EphemeralSecretPolicy(_POLICY, str(uuid.uuid4()))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _provision(self) -> None:
        self.manager.provision_for_start(
            peer_uid=os.geteuid(),
            account_id="account-test",
            repository_id="repo-test",
            template_id="template-test",
            run_id=self.run_id,
            policy=self.policy,
            expires_at_epoch=self.clock.value + 600,
        )

    def test_generated_material_is_private_nonpersistent_and_one_time(self) -> None:
        mount = self.manager.provision_for_start(
            peer_uid=os.geteuid(),
            account_id="account-test",
            repository_id="repo-test",
            template_id="template-test",
            run_id=self.run_id,
            policy=self.policy,
            expires_at_epoch=self.clock.value + 600,
        )
        password = mount.source_directory / mount.filename
        state_path = mount.source_directory.parent / "state.json"
        self.assertEqual(stat.S_IMODE(password.stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(state_path.stat().st_mode), 0o600)
        state = state_path.read_text(encoding="utf-8")
        self.assertNotIn("p" * 64, state)
        self.assertEqual(
            set(json.loads(state)),
            {
                "account_id",
                "binding_id",
                "consumed_request_id",
                "expires_at_epoch",
                "peer_uid",
                "policy",
                "repository_id",
                "run_id",
                "template_id",
                "version",
            },
        )
        restarted = VolatileRunSecretManager(
            runtime_root=self.root / "runtime",
            expected_uid=os.geteuid(),
            clock=self.clock,
        )
        request_id = uuid.uuid4()
        material = restarted.consume_run_secret(
            peer_uid=os.geteuid(),
            account_id="account-test",
            repository_id="repo-test",
            template_id="template-test",
            run_id=self.run_id,
            request_id=request_id,
        )
        self.assertEqual(material.value, b"p" * 64)
        self.assertNotIn("p" * 64, repr(material))
        with self.assertRaises(SecretGrantReplay):
            restarted.consume_run_secret(
                peer_uid=os.geteuid(),
                account_id="account-test",
                repository_id="repo-test",
                template_id="template-test",
                run_id=self.run_id,
                request_id=uuid.uuid4(),
            )
        restarted.release_run_secret(run_id=self.run_id)
        self.assertFalse((self.root / "runtime" / str(self.run_id)).exists())

    def test_rejects_wrong_owner_and_expired_material(self) -> None:
        self._provision()
        with self.assertRaises(SecretGrantDenied):
            self.manager.consume_run_secret(
                peer_uid=os.geteuid() + 1,
                account_id="account-test",
                repository_id="repo-test",
                template_id="template-test",
                run_id=self.run_id,
                request_id=uuid.uuid4(),
            )
        self.clock.value += 601
        with self.assertRaises(SecretGrantExpired):
            self.manager.consume_run_secret(
                peer_uid=os.geteuid(),
                account_id="account-test",
                repository_id="repo-test",
                template_id="template-test",
                run_id=self.run_id,
                request_id=uuid.uuid4(),
            )

    def test_trusted_0750_runtime_parent_creates_private_nested_root(self) -> None:
        """The service RuntimeDirectory may be group-readable but never writable."""

        parent = self.root / "service-runtime"
        parent.mkdir(mode=0o750)
        parent.chmod(0o750)
        manager = VolatileRunSecretManager(
            runtime_root=parent / "ephemeral-secrets",
            expected_uid=os.geteuid(),
            clock=self.clock,
            password_factory=lambda: b"q" * 64,
        )

        mount = manager.provision_for_start(
            peer_uid=os.geteuid(),
            account_id="account-test",
            repository_id="repo-test",
            template_id="template-test",
            run_id=self.run_id,
            policy=self.policy,
            expires_at_epoch=self.clock.value + 600,
        )

        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE(manager.runtime_root.stat().st_mode), 0o700)
        self.assertEqual(mount.source_directory.parent, manager.runtime_root / str(self.run_id))

    def test_rejects_symlink_but_accepts_local_parent_metadata(self) -> None:
        """Path type is enforced; UID and mode are not local authorization."""

        trusted = self.root / "trusted-runtime"
        trusted.mkdir(mode=0o700)
        linked = self.root / "linked-runtime"
        linked.symlink_to(trusted, target_is_directory=True)
        manager = VolatileRunSecretManager(
            runtime_root=linked / "ephemeral-secrets",
            expected_uid=os.geteuid(),
            clock=self.clock,
            password_factory=lambda: b"r" * 64,
        )
        with self.assertRaises(SecretGrantDenied):
            manager.provision_for_start(
                peer_uid=os.geteuid(),
                account_id="account-test",
                repository_id="repo-test",
                template_id="template-test",
                run_id=self.run_id,
                policy=self.policy,
                expires_at_epoch=self.clock.value + 600,
            )

        for index, (label, mode) in enumerate((("group-writable", 0o770), ("world-writable", 0o707))):
            with self.subTest(label=label):
                parent = self.root / label
                parent.mkdir(mode=mode)
                parent.chmod(mode)
                manager = VolatileRunSecretManager(
                    runtime_root=parent / "ephemeral-secrets",
                    expected_uid=os.geteuid(),
                    clock=self.clock,
                    password_factory=lambda: b"s" * 64,
                )
                run_id = uuid.UUID(int=self.run_id.int + index + 1)
                mount = manager.provision_for_start(
                    peer_uid=os.geteuid(),
                    account_id="account-test",
                    repository_id="repo-test",
                    template_id="template-test",
                    run_id=run_id,
                    policy=self.policy,
                    expires_at_epoch=self.clock.value + 600,
                )
                self.assertTrue(mount.source_directory.is_dir())


class SecretPolicyEnrollmentTests(unittest.TestCase):
    def test_manifest_accepts_only_typed_nonsecret_policy(self) -> None:
        template = {
            "name": "artifact-db",
            "image_ref": _IMAGE,
            "default_ttl_seconds": 900,
            "max_ttl_seconds": 3600,
            "memory_bytes": 256 * 1024 * 1024,
            "cpu_millis": 500,
            "env": {"POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256"},
            "secret_policy": _POLICY,
            **_QUOTAS,
        }
        normalized = broker_enrollment._normalize_ephemeral_templates([template])
        self.assertEqual(normalized[0]["secret_policy"], _POLICY)
        with self.assertRaises(ValueError):
            broker_enrollment._normalize_ephemeral_templates(
                [{**template, "secret_policy": "plaintext_password_v1"}]
            )
        with self.assertRaises(ValueError):
            broker_enrollment._normalize_ephemeral_templates(
                [{**template, "password": "must-never-be-accepted"}]
            )
        for environment, label in (
            ({}, "missing initdb configuration"),
            (
                {
                    "POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256",
                    "POSTGRES_HOST_AUTH_METHOD": "trust",
                },
                "trust override",
            ),
            ({"POSTGRES_INITDB_ARGS": "--auth-host=trust"}, "non-SCRAM initdb"),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, "SCRAM|auth method"):
                    broker_enrollment._normalize_ephemeral_templates(
                        [{**template, "env": environment}]
                    )

    def test_enrollment_persists_policy_and_opaque_binding_only(self) -> None:
        template = {
            "name": "artifact-db",
            "image_ref": _IMAGE,
            "default_ttl_seconds": 900,
            "max_ttl_seconds": 3600,
            "memory_bytes": 256 * 1024 * 1024,
            "cpu_millis": 500,
            "env": {"POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256"},
            "secret_policy": _POLICY,
            **_QUOTAS,
        }
        normalized = broker_enrollment._normalize_ephemeral_templates([template])
        persistence = mock.Mock()
        template_id = deterministic_id("ephemeral-template", "repo-test", "artifact-db")
        persistence.provision_ephemeral_template.return_value = {"template_id": template_id}
        result = broker_enrollment._provision_ephemeral_templates(
            persistence,
            repo_id="repo-test",
            client_uid=os.geteuid(),
            templates=normalized,
        )
        profile = broker_enrollment._ephemeral_secret_policy_profiles(
            repo_id="repo-test", template_ids=result, templates=normalized
        )
        provisioned = persistence.provision_ephemeral_template.call_args.kwargs
        self.assertEqual(provisioned["secret_policy_kind"], _POLICY)
        self.assertRegex(provisioned["secret_binding_id"], r"^[0-9a-f-]{36}$")
        self.assertEqual(
            profile,
            {
                "artifact-db": {
                    "policy": _POLICY,
                    "binding_id": provisioned["secret_binding_id"],
                }
            },
        )
        # The policy name describes the allowed password-file mechanism; it is
        # not credential material.  The published object must contain only
        # the allowlisted policy and its opaque binding.
        self.assertEqual(set(profile["artifact-db"]), {"policy", "binding_id"})
        self.assertNotIn("secret_value", json.dumps(profile))
        self.assertNotIn('"value"', json.dumps(profile))

    def test_profile_exposes_only_policy_and_binding(self) -> None:
        root = "/tmp/profile-secret-policy-repository"
        binding_id = str(uuid.uuid4())
        document = {
            "version": 1,
            "service": {
                "socket": "/run/devcoordinator-authority.sock",
                "uid": 0,
                "gid": 100,
                "mode": "0660",
                "database_generation": "generation-test",
            },
            "clients": {
                str(os.geteuid()): {
                    "account_id": "account-test",
                    "issued_at": "2026-07-24T00:00:00Z",
                    "valid_until_epoch": 9_999_999_999,
                    "repositories": [
                        {
                            "canonical_root": root,
                            "repo_id": "repo-test",
                            "generation": 0,
                            "owner_uid": os.geteuid(),
                            "servers": {},
                            "containers": {},
                            "compose_definition_id": None,
                            "compose_container_ids": [],
                            "compose_run_once_services": {},
                            "ephemeral_templates": {"artifact-db": "template-test"},
                            "ephemeral_image_prefetch_templates": [],
                            "ephemeral_secret_policies": {
                                "artifact-db": {
                                    "policy": _POLICY,
                                    "binding_id": binding_id,
                                }
                            },
                            "account_id": "account-test",
                            "enabled": True,
                            "issued_at": "2026-07-24T00:00:00Z",
                            "valid_until_epoch": 9_999_999_999,
                        }
                    ],
                }
            },
        }
        profile = profile_from_document(document, effective_uid=os.geteuid())
        policy = profile.repository(root).ephemeral_secret_policy("artifact-db")
        self.assertIsNotNone(policy)
        self.assertEqual(policy.policy if policy else None, _POLICY)
        malformed = json.loads(json.dumps(document))
        malformed["clients"][str(os.geteuid())]["repositories"][0][
            "ephemeral_secret_policies"
        ]["artifact-db"]["value"] = "must-never-appear"
        with self.assertRaises(BrokerProfileError):
            profile_from_document(malformed, effective_uid=os.geteuid())

    def test_fresh_schema_has_no_secret_value_column(self) -> None:
        import sqlite3

        connection = sqlite3.connect(":memory:")
        try:
            initialize_schema(
                connection,
                database_generation="generation-secret-test",
                timestamp="2026-07-24T00:00:00Z",
            )
            for table in (
                "ephemeral_container_templates",
                "ephemeral_container_runs",
            ):
                columns = {
                    row[1] for row in connection.execute(f"PRAGMA table_info({table})")
                }
                self.assertIn("secret_policy_kind", columns)
                self.assertIn("secret_binding_id", columns)
                self.assertNotIn("secret_value", columns)
                self.assertNotIn("password", columns)
        finally:
            connection.close()

    def test_legacy_ephemeral_acl_is_upgraded_for_descriptor_authorization(
        self,
    ) -> None:
        """Existing service stores gain the typed operation without a reset."""

        with tempfile.TemporaryDirectory(
            prefix="devcoordinator-secret-acl-migration-",
            dir=str(Path("/tmp").resolve()),
        ) as temporary:
            database = Path(temporary) / "coordinator.sqlite3"
            persistence = BrokerPersistence(database, expected_uid=os.geteuid())
            with persistence._store() as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        "ALTER TABLE broker_ephemeral_acl RENAME TO broker_ephemeral_acl_current"
                    )
                    connection.execute(
                        """
                        CREATE TABLE broker_ephemeral_acl (
                            uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE CASCADE,
                            repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
                            template_id TEXT NOT NULL
                                REFERENCES ephemeral_container_templates(template_id) ON DELETE CASCADE,
                            operation TEXT NOT NULL CHECK(operation IN (
                                'ephemeral.start', 'ephemeral.status',
                                'ephemeral.renew', 'ephemeral.finish'
                            )),
                            enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
                            updated_at TEXT NOT NULL,
                            PRIMARY KEY(uid, repo_id, template_id, operation)
                        )
                        """
                    )
                    connection.execute("DROP TABLE broker_ephemeral_acl_current")

            persistence.initialize()
            with persistence._store() as store:
                with store.read_transaction() as connection:
                    table_sql = str(
                        connection.execute(
                            """
                            SELECT sql FROM sqlite_master
                            WHERE type = 'table' AND name = 'broker_ephemeral_acl'
                            """
                        ).fetchone()[0]
                    )
                    lookup_index = connection.execute(
                        """
                        SELECT 1 FROM sqlite_master
                        WHERE type = 'index' AND name = 'broker_ephemeral_acl_lookup'
                        """
                    ).fetchone()
            self.assertIn("ephemeral.secret_fd", table_sql)
            self.assertIsNotNone(lookup_index)


if __name__ == "__main__":
    unittest.main()
