from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

from devcoordinator import retained_control, server_credentials
from devcoordinator.broker_persistence import BROKER_SCHEMA
from devcoordinator.compose_run_once import (
    ComposeRunOncePolicy,
    ComposeRunOnceReceiptContract,
)
from devcoordinator.schema import initialize_schema, invariant_violations


STAMP = "2026-08-21T00:00:00.000Z"


class RetainedControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "source.sqlite3"
        self.profile = self.root / "client-profiles.json"
        self.console = self.root / "console"
        self.console.mkdir(mode=0o700)
        self._seed_authority()
        self.profile.write_text('{"source":"profile"}\n', encoding="utf-8")
        (self.console / "routes.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "routes": {
                        "demo": {
                            "slug": "demo",
                            "kind": "port",
                            "auth": "google",
                            "instanceId": "12345678-1234-4234-8234-123456789abc",
                            "createdAt": STAMP,
                            "updatedAt": STAMP,
                            "port": 31000,
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        (self.console / "access-control.json").write_text(
            json.dumps(
                {
                    "version": 3,
                    "users": {"owner@example.com": {"grants": ["console", "route:demo"]}},
                    "requests": {"history": {"status": "approved"}},
                }
            ),
            encoding="utf-8",
        )
        (self.console / "ui-prefs.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "hidden": {"servers": ["repo::web"], "docker": [], "projects": []},
                }
            ),
            encoding="utf-8",
        )
        (self.console / "upstream-auth.json").write_text(
            '{"version":1,"routes":{"demo":{"authorization":"secret"}}}\n',
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _seed_authority(self) -> None:
        artifact = self.root / "backup.dump"
        artifact.write_bytes(b"database-backup")
        manifest = self.root / "backup.json"
        manifest.write_bytes(b"verified-manifest")
        connection = sqlite3.connect(self.database)
        try:
            run_once_policy = ComposeRunOncePolicy(
                name="migrate",
                max_timeout_seconds=900,
                receipt=ComposeRunOnceReceiptContract(required=(("migration", "string"),)),
            )
            compose_fingerprint = retained_control._compose_definition_fingerprint(
                repo_id="repo-1",
                canonical_root="/srv/repo",
                root_identity={"device": 1, "inode": 2},
                cwd="/srv/repo",
                cwd_identity={"device": 1, "inode": 3},
                compose_files=("/srv/repo/compose.yml",),
                compose_file_evidence=({"content_sha256": "a" * 64, "byte_size": 100},),
                env_files=(),
                env_file_evidence=(),
                profiles=(),
                services=("web",),
                run_once_services=(run_once_policy,),
                project_name="repo",
            )
            connection.execute("PRAGMA foreign_keys=ON")
            initialize_schema(connection, database_generation="source-generation", timestamp=STAMP)
            retained_control._execute_script(connection, BROKER_SCHEMA)
            connection.execute("DROP TABLE server_environment_credentials")
            connection.execute(
                "UPDATE schema_metadata SET schema_version=15,authority_mode='sqlite',migration_state='ready'"
            )
            connection.execute(
                "INSERT INTO hosts VALUES (?,?,?,?,?,?)",
                ("host-1", "machine-1", "linux", "host", STAMP, STAMP),
            )
            connection.execute(
                "INSERT INTO repositories VALUES (?,?,?,?,?,?,?,?)",
                ("repo-1", "host-1", "/srv/repo", "Repo", "active", 7, STAMP, STAMP),
            )
            connection.execute(
                "INSERT INTO repository_installations(repo_id,status,startup_fenced,generation,operation_id,actor,updated_at) "
                "VALUES (?,?,?,?,?,?,?)",
                ("repo-1", "installed", 0, 2, None, "owner", STAMP),
            )
            connection.execute(
                """
                INSERT INTO operations(
                    operation_id,repo_id,kind,status,phase,generation,
                    request_fingerprint,actor,created_at,updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                ("operation-1", "repo-1", "status", "succeeded", "complete", 0, "request", "owner", STAMP, STAMP),
            )
            connection.execute(
                "INSERT INTO events(event_id,repo_id,operation_id,event_kind,message,occurred_at) "
                "VALUES (?,?,?,?,?,?)",
                ("event-1", "repo-1", "operation-1", "operation", "history", STAMP),
            )
            connection.execute(
                """
                INSERT INTO observation_snapshots(
                    snapshot_id,host_id,observer_domain,status,material_fingerprint,
                    started_at,completed_at
                ) VALUES (?,?,?,?,?,?,?)
                """,
                ("snapshot-1", "host-1", "host", "completed", "material", STAMP, STAMP),
            )
            for table in sorted(retained_control.SCHEMA_15_DISPOSABLE_TEST_COLLECTIONS):
                connection.execute(f'CREATE TABLE "{table}"(row_id TEXT PRIMARY KEY)')
                connection.execute(f'INSERT INTO "{table}" VALUES (?)', (f"history-{table}",))
            connection.execute(
                """
                CREATE TABLE broker_acl_principals(
                    uid INTEGER PRIMARY KEY CHECK(uid >= 0),
                    account_id TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE UNIQUE INDEX broker_principal_uid_account_identity "
                "ON broker_acl_principals(uid, account_id)"
            )
            connection.execute(
                """
                CREATE TABLE broker_repository_enrollments(
                    uid INTEGER NOT NULL,
                    repo_id TEXT NOT NULL
                        REFERENCES repositories(repo_id) ON DELETE CASCADE,
                    account_id TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
                    issued_at TEXT NOT NULL,
                    valid_until_epoch INTEGER NOT NULL CHECK(valid_until_epoch > 0),
                    enrollment_snapshot_id TEXT
                        REFERENCES observation_snapshots(snapshot_id) ON DELETE RESTRICT,
                    grant_snapshot_id TEXT
                        REFERENCES observation_snapshots(snapshot_id) ON DELETE RESTRICT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(uid, repo_id),
                    FOREIGN KEY(uid, account_id)
                        REFERENCES broker_acl_principals(uid, account_id) ON DELETE CASCADE,
                    CHECK(
                        (enrollment_snapshot_id IS NULL AND grant_snapshot_id IS NULL)
                        OR
                        (enrollment_snapshot_id IS NOT NULL AND grant_snapshot_id IS NOT NULL)
                    )
                )
                """
            )
            connection.execute(
                "CREATE INDEX broker_repository_enrollments_by_repo "
                "ON broker_repository_enrollments(repo_id, enabled, valid_until_epoch)"
            )
            connection.execute(
                "INSERT INTO broker_acl_principals VALUES (?,?,?,?)",
                (1000, "legacy-local-account", 1, STAMP),
            )
            connection.execute(
                "INSERT INTO broker_repository_enrollments VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    1000,
                    "repo-1",
                    "legacy-local-account",
                    1,
                    STAMP,
                    4_102_444_800,
                    None,
                    None,
                    STAMP,
                ),
            )
            connection.execute("CREATE TABLE migration_conflicts(conflict_id TEXT PRIMARY KEY)")
            connection.execute("INSERT INTO migration_conflicts VALUES ('legacy-history')")
            connection.execute(
                "INSERT INTO server_definitions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                ("server-1", "repo-1", "web", "web", "/srv/repo", None, None, "fingerprint", 3, STAMP, STAMP),
            )
            connection.execute(
                "INSERT INTO server_command_arguments VALUES (?,?,?)",
                ("server-1", 0, "python3"),
            )
            connection.execute(
                "INSERT INTO server_definitions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                ("server-2", "repo-1", "worker", "worker", "/srv/repo", None, None, "fingerprint-2", 1, STAMP, STAMP),
            )
            connection.execute(
                "INSERT INTO server_environment VALUES (?,?,?)",
                ("server-1", "LOG_LEVEL", "info"),
            )
            connection.execute(
                """
                INSERT INTO startup_policies(
                    policy_id,repo_id,resource_kind,resource_id,policy_kind,
                    current_value,desired_disabled_value,immutable_fingerprint,
                    generation,updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    "startup-1", "repo-1", "server", "server-1", "coordinator",
                    "enabled", "disabled", "fingerprint", 9, STAMP,
                ),
            )
            connection.execute(
                """
                INSERT INTO worker_policies(
                    server_definition_id,repo_id,execution_uid,keep_alive,desired_state,
                    breaker_state,crash_limit,crash_window_seconds,generation,requested_by,
                    last_tripped_at,last_trip_reason,last_trip_attempt_id,last_trip_event_id,
                    created_at,updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    "server-1", "repo-1", 1000, 1, "running", "tripped", 5, 60,
                    4, "owner", STAMP, "crash-loop", "attempt-1", "event-1", STAMP, STAMP,
                ),
            )
            connection.execute(
                """
                INSERT INTO worker_policies(
                    server_definition_id,repo_id,execution_uid,keep_alive,desired_state,
                    breaker_state,crash_limit,crash_window_seconds,generation,requested_by,
                    created_at,updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                ("server-2", "repo-1", 1000, 1, "running", "armed", 5, 60, 2, "owner", STAMP, STAMP),
            )
            connection.execute(
                "INSERT INTO broker_compose_definitions VALUES (?,?,?,?,?,?,?,?,?)",
                ("compose-1", "repo-1", "/srv/repo", "repo", compose_fingerprint, 1, 5, STAMP, STAMP),
            )
            connection.execute(
                "INSERT INTO broker_compose_project_claims VALUES (?,?,?,?,?,?)",
                ("compose-1", "repo", 1, None, None, STAMP),
            )
            connection.execute(
                "INSERT INTO broker_compose_directory_identity VALUES (?,?,?,?,?,?)",
                ("compose-1", 1, 2, 1, 3, STAMP),
            )
            connection.execute(
                "INSERT INTO broker_compose_files VALUES (?,?,?)",
                ("compose-1", 0, "/srv/repo/compose.yml"),
            )
            connection.execute(
                "INSERT INTO broker_compose_file_evidence VALUES (?,?,?,?)",
                ("compose-1", 0, "a" * 64, 100),
            )
            connection.execute(
                "INSERT INTO broker_compose_services VALUES (?,?,?)",
                ("compose-1", 0, "web"),
            )
            connection.execute(
                "INSERT INTO broker_compose_run_once_services VALUES (?,?,?,?,?,?)",
                (
                    "compose-1",
                    0,
                    "migrate",
                    900,
                    json.dumps(run_once_policy.receipt.to_document(), sort_keys=True, separators=(",", ":")),
                    run_once_policy.fingerprint,
                ),
            )
            connection.execute(
                """
                INSERT INTO broker_compose_effective_model_evidence(
                    compose_definition_id,definition_fingerprint,model_sha256,
                    services_json,service_replicas_json,model_services_json,
                    model_service_replicas_json,service_images_json,profiles_json,
                    host_access_risks_json,host_access_approved,approved_by_uid,
                    approved_at,replica_budget,validated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    "compose-1", compose_fingerprint, "sha256:" + "b" * 64,
                    '["web"]', '{"web":1}', '["migrate","web"]',
                    '{"migrate":1,"web":1}',
                    '{"migrate":"repo/migrate@sha256:' + "c" * 64 + '","web":"repo/web@sha256:' + "d" * 64 + '"}',
                    "[]", "[]", 0, None, None, 2, STAMP,
                ),
            )
            connection.execute(
                """
                INSERT INTO ephemeral_container_templates(
                    template_id,repo_id,name,image_ref,secret_policy_kind,secret_binding_id,
                    definition_fingerprint,default_ttl_seconds,max_ttl_seconds,
                    max_concurrent_runs,max_concurrent_runs_per_uid,repo_max_active_runs,
                    repo_memory_budget_bytes,repo_cpu_budget_millis,enabled,generation,
                    created_at,updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    "template-1", "repo-1", "postgres", "postgres@sha256:" + "a" * 64,
                    "postgres_initdb_password_file_v1", "12345678-1234-4234-8234-123456789abc", "template-fingerprint",
                    60, 3600, 2, 1, 4, 64 * 1024 * 1024, 1000, 1, 6, STAMP, STAMP,
                ),
            )
            connection.execute(
                """
                INSERT INTO database_backups(
                    database_backup_id,repo_id,scope,source_container_id,source_database_name,
                    source_identity_fingerprint,artifact_path,artifact_size_bytes,artifact_sha256,
                    manifest_path,manifest_sha256,backup_format,verification_status,
                    verification_mode,created_at,verified_at,status,restore_count,updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    "backup-1", "repo-1", "database", "container-1", "app", "identity",
                    str(artifact), artifact.stat().st_size, retained_control._digest_file(artifact),
                    str(manifest), retained_control._digest_file(manifest), "custom", "strong",
                    "restore", STAMP, STAMP, "available", 0, STAMP,
                ),
            )
            connection.commit()
        finally:
            connection.close()

    def _prepare(self, name: str = "out") -> dict[str, object]:
        output = self.root / name
        output.mkdir(mode=0o700, exist_ok=True)
        return retained_control.prepare_rebaseline(
            source_database=self.database,
            source_profile=self.profile,
            console_state_root=self.console,
            output_root=output,
            database_generation="target-generation",
            timestamp=STAMP,
        )

    def test_rebaseline_retains_only_controls_and_advances_generations(self) -> None:
        source_before = self.database.read_bytes()
        profile_before = self.profile.read_bytes()
        source_identity = self.database.stat().st_ino
        profile_identity = self.profile.stat().st_ino
        result = self._prepare()
        target = sqlite3.connect(result["target"]["database"]["path"])
        try:
            metadata = target.execute(
                "SELECT schema_version,database_generation,state_revision,observation_revision,migration_state "
                "FROM schema_metadata"
            ).fetchone()
            self.assertEqual(metadata, (16, "target-generation", 0, 0, "ready"))
            self.assertEqual(target.execute("SELECT generation FROM repositories").fetchone()[0], 8)
            self.assertEqual(target.execute("SELECT generation FROM server_definitions").fetchone()[0], 4)
            self.assertEqual(
                target.execute(
                    "SELECT immutable_fingerprint,generation FROM startup_policies "
                    "WHERE policy_id='startup-1'"
                ).fetchone(),
                ("fingerprint", 10),
            )
            self.assertEqual(
                target.execute("SELECT COUNT(*) FROM server_environment_credentials").fetchone()[0],
                0,
            )
            self.assertEqual(target.execute("SELECT generation FROM broker_compose_definitions").fetchone()[0], 6)
            self.assertEqual(target.execute("SELECT generation FROM ephemeral_container_templates").fetchone()[0], 7)
            self.assertEqual(
                target.execute(
                    "SELECT desired_state,breaker_state,generation,last_trip_reason "
                    "FROM worker_policies WHERE server_definition_id='server-1'"
                ).fetchone(),
                ("stopped", "tripped", 5, None),
            )
            self.assertEqual(
                target.execute(
                    "SELECT desired_state,breaker_state,generation,last_trip_reason "
                    "FROM worker_policies WHERE server_definition_id='server-2'"
                ).fetchone(),
                ("running", "armed", 3, None),
            )
            self.assertEqual(
                target.execute(
                    "SELECT server_definition_id,state,supervisor_epoch,current_attempt_id "
                    "FROM worker_supervisor_states ORDER BY server_definition_id"
                ).fetchall(),
                [
                    ("server-1", "tripped", None, None),
                    ("server-2", "idle", None, None),
                ],
            )
            self.assertEqual(
                target.execute(
                    "SELECT policy.server_definition_id FROM worker_policies policy "
                    "JOIN worker_supervisor_states supervisor USING(server_definition_id) "
                    "WHERE policy.keep_alive=1 AND policy.desired_state='running' "
                    "AND policy.breaker_state='armed'"
                ).fetchall(),
                [("server-2",)],
            )
            self.assertEqual(
                target.execute("SELECT COUNT(*) FROM broker_compose_project_claims").fetchone()[0],
                1,
            )
            self.assertEqual(
                target.execute("SELECT COUNT(*) FROM broker_compose_effective_model_evidence").fetchone()[0],
                1,
            )
            self.assertEqual(target.execute("SELECT COUNT(*) FROM operations").fetchone()[0], 0)
            self.assertEqual(target.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)
            self.assertEqual(target.execute("SELECT COUNT(*) FROM observation_snapshots").fetchone()[0], 0)
            self.assertEqual(target.execute("SELECT COUNT(*) FROM worker_attempts").fetchone()[0], 0)
            self.assertEqual(target.execute("SELECT COUNT(*) FROM database_backups").fetchone()[0], 1)
            self.assertIsNone(
                target.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='test_runs'"
                ).fetchone()
            )
            for table in retained_control.SCHEMA_15_DISPOSABLE_TEST_COLLECTIONS:
                self.assertIsNone(
                    target.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                        (table,),
                    ).fetchone(),
                    table,
                )
            self.assertIsNone(
                target.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='migration_conflicts'"
                ).fetchone()
            )
            self.assertIsNone(
                target.execute(
                    "SELECT 1 FROM sqlite_master "
                    "WHERE type='table' AND name='broker_repository_enrollments'"
                ).fetchone()
            )
            self.assertIsNone(
                target.execute(
                    "SELECT 1 FROM sqlite_master "
                    "WHERE type='table' AND name='broker_acl_principals'"
                ).fetchone()
            )
        finally:
            target.close()
        access = json.loads((self.root / "out/console/access-control.json").read_text())
        self.assertEqual(access["requests"], {})
        self.assertEqual(result["server_credentials"], [])
        self.assertFalse((self.root / "out/server-credentials").exists())
        self.assertEqual(result["console_counts"], {"routes": 1, "users": 1, "grants": 2, "settings": 1})
        self.assertEqual(
            result["redacted_secret_references"][0]["binding_sha256"],
            retained_control._digest_bytes(b"12345678-1234-4234-8234-123456789abc"),
        )
        self.assertNotIn(
            "12345678-1234-4234-8234-123456789abc",
            json.dumps(result["redacted_secret_references"]),
        )
        self.assertFalse((self.root / "out/console/upstream-auth.json").exists())
        self.assertEqual(self.database.read_bytes(), source_before)
        self.assertEqual(self.profile.read_bytes(), profile_before)
        self.assertEqual(self.database.stat().st_ino, source_identity)
        self.assertEqual(self.profile.stat().st_ino, profile_identity)
        self.assertIn("test_runs", result["rejected_collections"])
        self.assertIn("migration_conflicts", result["rejected_collections"])
        self.assertIn("broker_repository_enrollments", result["rejected_collections"])
        self.assertNotIn("broker_repository_enrollments", result["retained_collections"])
        self.assertIn("operations", result["rejected_collections"])
        self.assertIn("events", result["rejected_collections"])
        self.assertIn("observation_snapshots", result["rejected_collections"])
        self.assertEqual(result["source"]["schema_version"], 15)
        self.assertEqual(result["source"]["database"]["path"], str(self.database))
        self.assertEqual(result["source"]["profile"]["path"], str(self.profile))
        self.assertTrue(result["console_sources"]["routes.json"]["present"])

    def test_secret_shaped_ephemeral_template_environment_is_rejected(self) -> None:
        connection = sqlite3.connect(self.database)
        connection.execute(
            "INSERT INTO ephemeral_template_environment VALUES (?,?,?)",
            ("template-1", "API_TOKEN", "synthetic-secret-sentinel"),
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(
            retained_control.RetainedControlError,
            "ephemeral_template_environment contains secret-shaped",
        ) as raised:
            self._prepare("ephemeral-secret-out")
        self.assertNotIn("synthetic-secret-sentinel", str(raised.exception))

    def test_credential_free_database_url_remains_a_literal(self) -> None:
        value = "postgresql://127.0.0.1/app"
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE server_environment SET name='DATABASE_URL',value=?",
            (value,),
        )
        connection.commit()
        connection.close()

        result = self._prepare("safe-database-url-out")
        target = sqlite3.connect(result["target"]["database"]["path"])
        try:
            self.assertEqual(
                target.execute(
                    "SELECT name,value FROM server_environment "
                    "WHERE server_definition_id='server-1'"
                ).fetchone(),
                ("DATABASE_URL", value),
            )
            self.assertEqual(
                target.execute("SELECT COUNT(*) FROM server_environment_credentials").fetchone()[0],
                0,
            )
        finally:
            target.close()
        self.assertEqual(result["server_credentials"], [])
        self.assertEqual(result["retained_collections"]["server_environment"], 1)
        self.assertEqual(
            result["retained_collections"]["server_environment_credentials"], 0
        )

    def test_credential_database_url_is_externalized_without_secret_echo(self) -> None:
        sentinel = "credential-sentinel-94d70d47"
        value = f"postgresql://app:{sentinel}@127.0.0.1/app"
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE server_environment SET name='DATABASE_URL',value=?",
            (value,),
        )
        connection.commit()
        connection.close()
        source_before = self.database.read_bytes()

        result = self._prepare("credential-out")
        expected_id = server_credentials.server_credential_id("server-1", "DATABASE_URL")
        self.assertEqual(len(result["server_credentials"]), 1)
        credential = result["server_credentials"][0]
        self.assertEqual(
            {key: credential[key] for key in ("server_definition_id", "name", "credential_id")},
            {
                "server_definition_id": "server-1",
                "name": "DATABASE_URL",
                "credential_id": expected_id,
            },
        )
        material_path = Path(credential["material"]["path"])
        self.assertEqual(
            material_path,
            server_credentials.staged_material_path(
                self.root / "credential-out/server-credentials", expected_id
            ),
        )
        self.assertEqual(material_path.read_bytes(), value.encode("utf-8"))
        self.assertEqual(material_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(
            sorted(self.root.joinpath("credential-out/server-credentials").iterdir()),
            [material_path],
        )

        target = sqlite3.connect(result["target"]["database"]["path"])
        try:
            self.assertEqual(
                target.execute("SELECT COUNT(*) FROM server_environment").fetchone()[0],
                0,
            )
            self.assertEqual(
                target.execute(
                    "SELECT server_definition_id,name,credential_id,created_at,updated_at "
                    "FROM server_environment_credentials"
                ).fetchone(),
                ("server-1", "DATABASE_URL", expected_id, STAMP, STAMP),
            )
            fingerprint, generation = target.execute(
                "SELECT definition_fingerprint,generation FROM server_definitions "
                "WHERE server_definition_id='server-1'"
            ).fetchone()
            self.assertRegex(fingerprint, r"^sha256:[0-9a-f]{64}$")
            self.assertNotEqual(fingerprint, "fingerprint")
            self.assertEqual(generation, 4)
            self.assertEqual(
                target.execute(
                    "SELECT immutable_fingerprint,generation FROM startup_policies "
                    "WHERE policy_id='startup-1'"
                ).fetchone(),
                (fingerprint, 10),
            )
        finally:
            target.close()

        self.assertEqual(result["retained_collections"]["server_environment"], 0)
        self.assertEqual(
            result["retained_collections"]["server_environment_credentials"], 1
        )
        self.assertEqual(self.database.read_bytes(), source_before)
        self.assertNotIn(sentinel, json.dumps(result, sort_keys=True))
        for path in sorted((self.root / "credential-out").rglob("*")):
            if path.is_file() and path != material_path:
                self.assertNotIn(sentinel.encode("utf-8"), path.read_bytes(), str(path))

        identity_before = credential["material"]
        replay = self._prepare("credential-out")
        self.assertEqual(replay, result)
        self.assertEqual(replay["server_credentials"][0]["material"], identity_before)

    def test_changed_or_unknown_server_credential_evidence_is_rejected(self) -> None:
        sentinel = "credential-sentinel-no-echo-1038"
        value = f"postgresql://app:{sentinel}@127.0.0.1/app"
        for scenario in ("changed-binding", "unknown-material"):
            with self.subTest(scenario=scenario):
                self.tearDown()
                self.setUp()
                connection = sqlite3.connect(self.database)
                connection.execute(
                    "UPDATE server_environment SET name='DATABASE_URL',value=?",
                    (value,),
                )
                connection.commit()
                connection.close()
                result = self._prepare(f"credential-{scenario}")
                output = self.root / f"credential-{scenario}"
                if scenario == "changed-binding":
                    manifest_path = output / "retained-control.json"
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    manifest.pop("document_sha256")
                    manifest["server_credentials"][0]["credential_id"] = str(uuid.uuid4())
                    manifest["document_sha256"] = retained_control._digest_bytes(
                        retained_control._canonical(manifest)
                    )
                    manifest_path.write_text(
                        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    message = "binding is invalid"
                else:
                    unknown_id = str(uuid.uuid4())
                    unknown_path = server_credentials.staged_material_path(
                        output / "server-credentials", unknown_id
                    )
                    unknown_path.write_text("unknown", encoding="utf-8")
                    unknown_path.chmod(0o600)
                    message = "unknown material"
                with self.assertRaisesRegex(
                    retained_control.RetainedControlError, message
                ) as raised:
                    self._prepare(f"credential-{scenario}")
                self.assertNotIn(sentinel, str(raised.exception))
                self.assertNotIn(sentinel, json.dumps(result, sort_keys=True))

    def test_current_schema_credential_bindings_are_unique_exact_and_unambiguous(self) -> None:
        result = self._prepare("credential-schema-out")
        target = sqlite3.connect(result["target"]["database"]["path"])
        target.execute("PRAGMA foreign_keys=ON")
        try:
            credential_id = server_credentials.server_credential_id(
                "server-1", "API_TOKEN"
            )
            target.execute(
                "INSERT INTO server_environment_credentials VALUES (?,?,?,?,?)",
                ("server-1", "API_TOKEN", credential_id, STAMP, STAMP),
            )
            with self.assertRaises(sqlite3.IntegrityError):
                target.execute(
                    "INSERT INTO server_environment_credentials VALUES (?,?,?,?,?)",
                    ("server-2", "OTHER_TOKEN", credential_id, STAMP, STAMP),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                target.execute(
                    "INSERT INTO server_environment_credentials VALUES (?,?,?,?,?)",
                    (
                        "server-2",
                        "OTHER_TOKEN",
                        server_credentials.server_credential_id(
                            "server-2", "OTHER_TOKEN"
                        ).upper(),
                        STAMP,
                        STAMP,
                    ),
                )

            wrong_id = str(uuid.uuid4())
            target.execute(
                "INSERT INTO server_environment_credentials VALUES (?,?,?,?,?)",
                ("server-2", "OTHER_TOKEN", wrong_id, STAMP, STAMP),
            )
            target.execute(
                "INSERT INTO server_environment_credentials VALUES (?,?,?,?,?)",
                (
                    "server-1",
                    "LOG_LEVEL",
                    server_credentials.server_credential_id("server-1", "LOG_LEVEL"),
                    STAMP,
                    STAMP,
                ),
            )
            codes = {
                violation.code
                for violation in invariant_violations(
                    target, include_foreign_keys=False
                )
            }
            self.assertIn("server_environment_credential_binding_invalid", codes)
            self.assertIn("server_environment_transport_conflict", codes)
        finally:
            target.close()

    def test_unknown_source_collection_is_rejected(self) -> None:
        connection = sqlite3.connect(self.database)
        connection.execute("CREATE TABLE invented_control(value TEXT)")
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(retained_control.RetainedControlError, "unknown collections"):
            self._prepare("unknown-out")

    def test_schema_15_source_with_unknown_credential_bindings_is_rejected(self) -> None:
        connection = sqlite3.connect(self.database)
        connection.execute(
            """
            CREATE TABLE server_environment_credentials(
                server_definition_id TEXT,
                name TEXT,
                credential_id TEXT,
                created_at TEXT,
                updated_at TEXT
            )
            """
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(
            retained_control.RetainedControlError,
            "schema-15 authority contains unknown server credential bindings",
        ):
            self._prepare("unknown-credential-bindings-out")

    def test_changed_retired_enrollment_shape_is_rejected(self) -> None:
        connection = sqlite3.connect(self.database)
        connection.execute(
            "ALTER TABLE broker_repository_enrollments ADD COLUMN invented_control TEXT"
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(
            retained_control.RetainedControlError,
            "retired broker_repository_enrollments columns differ from frozen schema 15",
        ):
            self._prepare("changed-retired-out")

    def test_changed_verified_backup_is_rejected(self) -> None:
        (self.root / "backup.dump").write_bytes(b"changed")
        with self.assertRaisesRegex(retained_control.RetainedControlError, "backup (size|digest) changed"):
            self._prepare("backup-out")

    def test_enabled_compose_without_effective_control_evidence_is_rejected(self) -> None:
        connection = sqlite3.connect(self.database)
        connection.execute("DELETE FROM broker_compose_effective_model_evidence")
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(retained_control.RetainedControlError, "lacks its active claim.*effective model"):
            self._prepare("compose-out")

    def test_enabled_compose_requires_an_active_claim(self) -> None:
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE broker_compose_project_claims "
            "SET claimed=0,release_snapshot_id='snapshot-1',released_at=?",
            (STAMP,),
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(retained_control.RetainedControlError, "lacks its active claim"):
            self._prepare("compose-claim-out")

    def test_enabled_compose_requires_exact_persisted_evidence(self) -> None:
        mutations = (
            ("DELETE FROM broker_compose_directory_identity", "directory identity"),
            ("DELETE FROM broker_compose_file_evidence", "file evidence"),
            (
                "UPDATE broker_compose_definitions SET definition_fingerprint='bad'; "
                "UPDATE broker_compose_effective_model_evidence SET definition_fingerprint='bad'",
                "fingerprint",
            ),
            (
                "UPDATE broker_compose_effective_model_evidence "
                "SET service_images_json='{\"web\":\"repo/web@sha256:" + "d" * 64 + "\"}'",
                "run-once service",
            ),
        )
        for index, (script, message) in enumerate(mutations):
            with self.subTest(message=message):
                self.tearDown()
                self.setUp()
                connection = sqlite3.connect(self.database)
                connection.executescript(script)
                connection.commit()
                connection.close()
                with self.assertRaisesRegex(retained_control.RetainedControlError, message):
                    self._prepare(f"compose-evidence-{index}")

    def test_disabled_released_compose_control_is_retained_without_effective_evidence(self) -> None:
        connection = sqlite3.connect(self.database)
        connection.execute("UPDATE broker_compose_definitions SET enabled=0")
        connection.execute(
            "UPDATE broker_compose_project_claims SET claimed=0,release_snapshot_id='snapshot-1',released_at=?",
            (STAMP,),
        )
        connection.execute("DELETE FROM broker_compose_effective_model_evidence")
        connection.execute("DELETE FROM broker_compose_directory_identity")
        connection.commit()
        connection.close()
        result = self._prepare("disabled-compose-out")
        target = sqlite3.connect(result["target"]["database"]["path"])
        try:
            self.assertEqual(
                target.execute(
                    "SELECT enabled,claimed FROM broker_compose_definitions "
                    "JOIN broker_compose_project_claims USING(compose_definition_id)"
                ).fetchone(),
                (0, 0),
            )
        finally:
            target.close()

    def test_schema_15_retained_columns_are_exact(self) -> None:
        connection = sqlite3.connect(self.database)
        connection.execute("ALTER TABLE repositories ADD COLUMN unreviewed_control TEXT")
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(retained_control.RetainedControlError, "frozen schema 15"):
            self._prepare("column-out")

    def test_already_current_authority_is_not_rebaselined(self) -> None:
        connection = sqlite3.connect(self.database)
        connection.execute("UPDATE schema_metadata SET schema_version=16")
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(retained_control.RetainedControlError, "exactly authority schema 15"):
            self._prepare("current-out")

    def test_inflight_repository_disable_is_rejected(self) -> None:
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE repository_installations SET status='disabling',startup_fenced=1,operation_id='operation-1'"
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(retained_control.RetainedControlError, "disable operations to finish"):
            self._prepare("disabling-out")

    def test_prepared_replay_and_known_partial_staging_are_idempotent(self) -> None:
        first = self._prepare("replay-out")
        replay = retained_control.prepare_rebaseline(
            source_database=self.database,
            source_profile=self.profile,
            console_state_root=self.console,
            output_root=self.root / "replay-out",
            database_generation="ignored-on-replay",
            timestamp="2099-01-01T00:00:00.000Z",
        )
        self.assertEqual(replay, first)

        partial = self.root / "partial-out"
        partial.mkdir(mode=0o700)
        (partial / "authority.sqlite3").write_bytes(b"interrupted")
        (partial / "console").mkdir(mode=0o700)
        (partial / "console/routes.json").write_text("partial", encoding="utf-8")
        recovered = retained_control.prepare_rebaseline(
            source_database=self.database,
            source_profile=self.profile,
            console_state_root=self.console,
            output_root=partial,
            database_generation="recovered-generation",
            timestamp=STAMP,
        )
        self.assertEqual(recovered["target"]["database_generation"], "recovered-generation")
        self.assertTrue((partial / "retained-control.json").is_file())

    def test_public_result_excludes_private_credential_evidence(self) -> None:
        private = {
            "source": {"schema_version": 15, "database": {"sha256": "a" * 64}},
            "target": {
                "schema_version": 16,
                "database_generation": "target-generation",
                "database": {"path": "/private/authority.sqlite3"},
            },
            "retained_collections": {"repositories": 1},
            "console_counts": {"routes": 1},
            "server_credentials": [
                {
                    "credential_id": str(uuid.uuid4()),
                    "material": {
                        "path": "/private/credential",
                        "sha256": "f" * 64,
                    },
                }
            ],
            "document_sha256": "e" * 64,
        }
        public = retained_control.public_rebaseline_result(private)
        encoded = json.dumps(public, sort_keys=True)
        self.assertEqual(public["server_credential_count"], 1)
        for forbidden in ("/private", "sha256", "credential_id", "material"):
            self.assertNotIn(forbidden, encoded)

    def test_server_descriptor_literal_credentials_are_rejected_without_echo(self) -> None:
        secret = "synthetic-descriptor-secret"
        mutations = (
            (
                "INSERT INTO server_command_arguments VALUES ('server-2',0,'--password'); "
                "INSERT INTO server_command_arguments VALUES ('server-2',1,'"
                + secret
                + "')",
                "command contains literal credential",
            ),
            (
                "UPDATE server_definitions SET health_url_template="
                "'https://worker:"
                + secret
                + "@health.invalid/status' WHERE server_definition_id='server-2'",
                "health URL contains literal credential",
            ),
        )
        for index, (script, message) in enumerate(mutations):
            with self.subTest(message=message):
                self.tearDown()
                self.setUp()
                connection = sqlite3.connect(self.database)
                connection.executescript(script)
                connection.commit()
                connection.close()
                with self.assertRaisesRegex(
                    retained_control.RetainedControlError, message
                ) as raised:
                    self._prepare(f"descriptor-secret-{index}")
                self.assertNotIn(secret, str(raised.exception))

        self.tearDown()
        self.setUp()
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE server_definitions SET health_url_template=? "
            "WHERE server_definition_id='server-2'",
            ("https://health.invalid/status?mode=ready",),
        )
        connection.commit()
        connection.close()
        self.assertEqual(self._prepare("safe-descriptor")["server_credentials"], [])


if __name__ == "__main__":
    unittest.main()
