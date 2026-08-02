#!/usr/bin/env python3
"""Focused guards for the offline deployment transaction."""

from __future__ import annotations

import importlib.util
import inspect
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
from types import SimpleNamespace


SCRIPT = Path(__file__).with_name("deploy_server_wide_maintenance.py")
SPEC = importlib.util.spec_from_file_location("deploy_server_wide_maintenance", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import maintenance deployment driver")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def driver_for(root: Path) -> object:
    driver = object.__new__(MODULE.Driver)
    driver.raw_checkpoint = root / "writer-free-database"
    driver.client_database = root / "client" / "coordinator.sqlite3"
    driver.client_checkpoint = root / "writer-free-client-database"
    driver.deployment_id = "11111111-1111-4111-8111-111111111111"
    driver.database_captured = False
    driver.client_database_captured = False
    driver.journal = lambda **_extra: None
    return driver


def initialize_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE schema_metadata(
                singleton INTEGER PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                database_generation TEXT NOT NULL
            );
            INSERT INTO schema_metadata VALUES (1, 4, 'generation-a');
            CREATE TABLE operations(
                operation_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                status TEXT NOT NULL
            );
            """
        )
        connection.commit()
    finally:
        connection.close()
    path.chmod(0o600)


class InventoryResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.status = 200

    def __enter__(self) -> "InventoryResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, limit: int = -1) -> bytes:
        return self.payload if limit < 0 else self.payload[:limit]


def main() -> int:
    parser_probe = MODULE.parse_args(
        [
            "--target-commit",
            "a" * 40,
            "--rollback-ref",
            "b" * 40,
            "--transaction-dir",
            "/tmp/devcoordinator-parser-probe",
            "--deployment-id",
            "00000000-0000-4000-8000-000000000001",
            "--client-user",
            "probe",
            "--public-url",
            "https://console.example.invalid/",
            "--token-file",
            "/tmp/token",
            "--console-env-file",
            "/tmp/console.env",
            "--console-state-dir",
            "/tmp/console-state",
        ]
    )
    expect(
        parser_probe.repository == "/home/DevCoordinator",
        "deployment CLI parser lost its canonical repository default",
    )

    with tempfile.TemporaryDirectory(prefix="maintenance-deploy-test-") as raw:
        root = Path(raw).resolve()
        database = root / "coordinator.sqlite3"
        initialize_database(database)
        previous = MODULE.DATABASE
        MODULE.DATABASE = database
        try:
            driver = driver_for(root)
            evidence = driver.schema_evidence(expected=4)
            expect(evidence["schema_version"] == 4, "schema preflight lost its version")

            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "INSERT INTO operations VALUES ('operation-a', 'test', 'planned')"
                )
                connection.commit()
            finally:
                connection.close()
            try:
                driver.schema_evidence(expected=4)
            except MODULE.DeploymentError as error:
                expect(
                    "non-terminal operations" in str(error),
                    "pending-operation guard returned the wrong failure",
                )
            else:
                raise AssertionError("planned operation was accepted as quiescent")

            connection = sqlite3.connect(database)
            try:
                connection.execute("DELETE FROM operations")
                connection.commit()
            finally:
                connection.close()
            before = database.read_bytes()
            driver.capture_database()
            manifest = json.loads(
                (driver.raw_checkpoint / "manifest.json").read_text(encoding="utf-8")
            )
            expect(
                manifest[database.name]["sha256"]
                == MODULE.hashlib.sha256(before).hexdigest(),
                "writer-free checkpoint did not bind the source checksum",
            )
            database.write_bytes(b"not a sqlite database")
            database.chmod(0o600)
            Path(f"{database}-wal").write_bytes(b"unexpected wal")
            Path(f"{database}-wal").chmod(0o600)
            driver.restore_database()
            expect(database.read_bytes() == before, "rollback did not restore exact bytes")
            expect(
                not Path(f"{database}-wal").exists(),
                "rollback retained a sidecar that was absent at checkpoint",
            )

            database.write_bytes(b"second damaged database")
            previous_replace = MODULE.os.replace

            def racing_replace(source: object, target: object) -> None:
                if Path(target) == database:
                    database.write_bytes(b"concurrent empty database")
                previous_replace(source, target)

            MODULE.os.replace = racing_replace
            try:
                driver.restore_database()
            finally:
                MODULE.os.replace = previous_replace
            expect(
                database.read_bytes() == before,
                "atomic rollback did not replace a concurrently recreated database",
            )

            driver.client_database.parent.mkdir(mode=0o700)
            initialize_database(driver.client_database)
            client_before = driver.client_database.read_bytes()
            driver.capture_client_database()
            driver.client_database.write_bytes(b"migrated client database")
            driver.client_database.chmod(0o600)
            driver.restore_client_database()
            expect(
                driver.client_database.read_bytes() == client_before,
                "rollback did not restore the exact client database",
            )
            expect(
                driver.client_schema_evidence(expected=4)["schema_version"] == 4,
                "restored client database lost its schema evidence",
            )
        finally:
            MODULE.DATABASE = previous

    with tempfile.TemporaryDirectory(prefix="maintenance-console-state-test-") as raw:
        root = Path(raw).resolve()
        assertion = root / "identity-assertion-public.json"
        assertion.write_text("{}\n", encoding="utf-8")
        assertion.chmod(0o644)
        driver = object.__new__(MODULE.Driver)
        driver.console_uid = os.getuid()
        driver.console_identity_assertion = assertion
        evidence = driver.normalize_console_private_state()
        expect(evidence["previous_mode"] == 0o644, "legacy state mode was not recorded")
        expect(
            assertion.stat().st_mode & 0o777 == 0o600,
            "legacy Console identity assertion was not made private",
        )

    with tempfile.TemporaryDirectory(prefix="maintenance-inventory-test-") as raw:
        root = Path(raw).resolve()
        token_file = root / "api-token"
        token_file.write_text("fixture-token\n", encoding="utf-8")
        token_file.chmod(0o600)
        driver = object.__new__(MODULE.Driver)
        driver.token_file = token_file
        driver.transaction = root
        driver.repository = Path("/home/DevCoordinator")
        padding = "x" * (8 * 1024 * 1024)
        response_payload = json.dumps({"padding": padding}).encode("utf-8")
        previous_urlopen = MODULE.urllib.request.urlopen
        MODULE.urllib.request.urlopen = lambda *_args, **_kwargs: InventoryResponse(
            response_payload
        )
        try:
            inventory = driver.inventory("large-inventory.json")
        finally:
            MODULE.urllib.request.urlopen = previous_urlopen
        expect(
            inventory == {"padding": padding},
            "authenticated inventory larger than the former 8 MiB ceiling was truncated",
        )

        previous_limit = MODULE.MAX_INVENTORY_RESPONSE_BYTES
        MODULE.MAX_INVENTORY_RESPONSE_BYTES = 1024
        MODULE.urllib.request.urlopen = lambda *_args, **_kwargs: InventoryResponse(
            json.dumps({"padding": "x" * 2048}).encode("utf-8")
        )
        try:
            try:
                driver.inventory("oversized-inventory.json")
            except MODULE.DeploymentError as error:
                expect(
                    "exceeds the bounded 1024-byte" in str(error),
                    "oversized authenticated inventory returned the wrong failure",
                )
            else:
                raise AssertionError("oversized authenticated inventory was accepted")
        finally:
            MODULE.urllib.request.urlopen = previous_urlopen
            MODULE.MAX_INVENTORY_RESPONSE_BYTES = previous_limit

    with tempfile.TemporaryDirectory(prefix="maintenance-readiness-test-") as raw:
        root = Path(raw)
        driver = object.__new__(MODULE.Driver)
        driver.repository = root
        driver.transaction = root
        driver.schema_after = 14
        commands: list[list[str]] = []
        readiness = {
            "ok": True,
            "schema": {"schema_version": 14},
            "checks": {
                "foreign_key_check": "ok",
                "integrity_check": "ok",
                "nonterminal_operations": 0,
                "semantic_invariants": "ok",
            },
            "legacy_projection_counts": {
                "repositories": 1,
                "server_definitions": 1,
                "leases": 1,
                "operations": 1,
                "events": 1,
            },
            "infrastructure_projection": {
                "schema": "spectre.infrastructure.projection.v1",
                "host_count": 0,
                "has_more": False,
            },
        }

        def readiness_run(
            arguments: list[str], *, timeout: float, check: bool = True
        ) -> object:
            commands.append(arguments)
            return SimpleNamespace(stdout=json.dumps(readiness), stderr="", returncode=0)

        driver.run = readiness_run
        root_result = driver.target_schema_readiness(
            root / "service.sqlite3",
            expected_uid=0,
            evidence_name="service-readiness.json",
        )
        expect(root_result == readiness, "root readiness result changed")
        expect(
            commands[-1][:2] == ["/usr/bin/python3", "-I"],
            "root readiness unexpectedly crosses a user boundary",
        )
        previous_getpwuid = MODULE.pwd.getpwuid
        MODULE.pwd.getpwuid = lambda uid: SimpleNamespace(
            pw_name="fixture-client", pw_uid=uid
        )
        try:
            driver.target_schema_readiness(
                root / "client.sqlite3",
                expected_uid=1234,
                evidence_name="client-readiness.json",
            )
        finally:
            MODULE.pwd.getpwuid = previous_getpwuid
        expect(
            commands[-1][:5]
            == [
                "/usr/sbin/runuser",
                "--user",
                "fixture-client",
                "--",
                "/usr/bin/python3",
            ],
            "client readiness does not run as the exact database owner",
        )
        readiness["checks"]["semantic_invariants"] = "failed"
        try:
            driver.target_schema_readiness(
                root / "service.sqlite3",
                expected_uid=0,
                evidence_name="invalid-readiness.json",
            )
        except MODULE.DeploymentError as error:
            expect(
                "complete readiness contract" in str(error),
                "incomplete readiness returned the wrong failure",
            )
        else:
            raise AssertionError("incomplete target readiness was accepted")

        driver.schema_before = 4
        driver.deployment_id = "11111111-1111-4111-8111-111111111111"
        driver.database_captured = False
        driver.client_database_captured = False
        driver.console_uid = 1234
        driver.client_database = root / "client.sqlite3"

        def upgrade_run(
            arguments: list[str], *, timeout: float, check: bool = True
        ) -> object:
            commands.append(arguments)
            database = arguments[arguments.index("--database") + 1]
            expected_uid = int(arguments[arguments.index("--expected-uid") + 1])
            timestamp = arguments[arguments.index("--timestamp") + 1]
            upgrade = {
                "ok": True,
                "receipt_contract": "devcoordinator.offline-schema-upgrade.v1",
                "database": database,
                "database_owner_uid": expected_uid,
                "migration_timestamp": timestamp,
                "schema_before": 4,
                "schema_after": 14,
                "checks": {
                    "foreign_keys_after": "ok",
                    "foreign_keys_before": "ok",
                    "integrity_after": "ok",
                    "integrity_before": "ok",
                    "nonterminal_operations": 0,
                    "semantic_invariants_after": "ok",
                    "wal_checkpoint": "ok",
                },
            }
            return SimpleNamespace(
                stdout=json.dumps(upgrade), stderr="", returncode=0
            )

        driver.run = upgrade_run
        command_count = len(commands)
        try:
            driver.upgrade_database_schema_offline(
                root / "service.sqlite3",
                expected_uid=0,
                database_role="service_authority",
                receipt_name=MODULE.SERVICE_SCHEMA_UPGRADE_RECEIPT_NAME,
            )
        except MODULE.DeploymentError as error:
            expect(
                "both writer-free database checkpoints" in str(error),
                "pre-checkpoint upgrade returned the wrong failure",
            )
        else:
            raise AssertionError("offline upgrade ran before both checkpoints")
        expect(
            len(commands) == command_count,
            "pre-checkpoint guard ran the offline upgrader",
        )
        driver.database_captured = True
        driver.client_database_captured = True
        service_database = root / "service.sqlite3"
        production_database = MODULE.DATABASE
        MODULE.DATABASE = service_database
        command_count = len(commands)
        try:
            driver.upgrade_database_schema_offline(
                driver.client_database,
                expected_uid=0,
                database_role="service_authority",
                receipt_name=MODULE.SERVICE_SCHEMA_UPGRADE_RECEIPT_NAME,
            )
        except MODULE.DeploymentError as error:
            expect(
                "fixed role contract" in str(error),
                "cross-role database target returned the wrong failure",
            )
        else:
            raise AssertionError("cross-role database target reached the upgrader")
        expect(
            len(commands) == command_count,
            "cross-role database rejection ran the upgrader",
        )
        service_upgrade = driver.upgrade_database_schema_offline(
            service_database,
            expected_uid=0,
            database_role="service_authority",
            receipt_name=MODULE.SERVICE_SCHEMA_UPGRADE_RECEIPT_NAME,
        )
        expect(
            commands[-1][:2] == ["/usr/bin/python3", "-I"],
            "root service upgrade unexpectedly crosses a user boundary",
        )
        service_receipt = root / MODULE.SERVICE_SCHEMA_UPGRADE_RECEIPT_NAME
        expect(
            service_upgrade["receipt"]["database_role"] == "service_authority"
            and service_upgrade["receipt"]["database"] == str(service_database)
            and service_upgrade["receipt"]["database_owner_uid"] == 0
            and stat.S_IMODE(service_receipt.lstat().st_mode) == 0o400
            and service_receipt.lstat().st_nlink == 1,
            "root service upgrade receipt is not exact, private, and create-new",
        )
        previous_getpwuid = MODULE.pwd.getpwuid
        MODULE.pwd.getpwuid = lambda uid: SimpleNamespace(
            pw_name="fixture-client", pw_uid=uid
        )
        try:
            client_upgrade = driver.upgrade_database_schema_offline(
                driver.client_database,
                expected_uid=1234,
                database_role="console_client_journal",
                receipt_name=MODULE.CLIENT_SCHEMA_UPGRADE_RECEIPT_NAME,
            )
        finally:
            MODULE.pwd.getpwuid = previous_getpwuid
        expect(
            commands[-1][:5]
            == [
                "/usr/sbin/runuser",
                "--user",
                "fixture-client",
                "--",
                "/usr/bin/python3",
            ]
            and "upgrade_coordinator_schema_offline.py"
            in " ".join(commands[-1]),
            "offline client upgrade does not run target code as the database owner",
        )
        client_receipt = root / MODULE.CLIENT_SCHEMA_UPGRADE_RECEIPT_NAME
        expect(
            client_upgrade["receipt"]["database_role"]
            == "console_client_journal"
            and client_upgrade["receipt"]["database"] == str(driver.client_database)
            and client_upgrade["receipt"]["database_owner_uid"] == 1234
            and service_upgrade["artifact"]["path"]
            != client_upgrade["artifact"]["path"]
            and stat.S_IMODE(client_receipt.lstat().st_mode) == 0o400
            and client_receipt.lstat().st_nlink == 1,
            "client upgrade receipt is not separate, exact, and private",
        )
        driver.require_schema_upgrade_receipt(
            service_upgrade,
            receipt_name=MODULE.SERVICE_SCHEMA_UPGRADE_RECEIPT_NAME,
            database_role="service_authority",
            database=service_database,
            expected_uid=0,
        )
        driver.require_schema_upgrade_receipt(
            client_upgrade,
            receipt_name=MODULE.CLIENT_SCHEMA_UPGRADE_RECEIPT_NAME,
            database_role="console_client_journal",
            database=driver.client_database,
            expected_uid=1234,
        )
        before_receipt = service_receipt.read_bytes()
        command_count = len(commands)
        try:
            driver.upgrade_database_schema_offline(
                service_database,
                expected_uid=0,
                database_role="service_authority",
                receipt_name=MODULE.SERVICE_SCHEMA_UPGRADE_RECEIPT_NAME,
            )
        except MODULE.DeploymentError as error:
            expect(
                "already exists and blocks upgrade" in str(error),
                "existing receipt returned the wrong failure",
            )
        else:
            raise AssertionError("existing immutable receipt was replaced")
        expect(
            len(commands) == command_count
            and service_receipt.read_bytes() == before_receipt,
            "receipt collision ran the upgrader or changed retained evidence",
        )
        previous_profile = MODULE.PROFILE
        MODULE.PROFILE = root / "client-profiles.json"
        schema_checks: list[tuple[str, int]] = []
        driver.schema_evidence = lambda *, expected: (
            schema_checks.append(("service", expected))
            or {"schema_version": expected}
        )
        driver.client_schema_evidence = lambda *, expected: (
            schema_checks.append(("client", expected))
            or {"schema_version": expected}
        )
        profile_results = [
            {
                "status": "migrated",
                "profile": str(MODULE.PROFILE),
                "database": str(MODULE.DATABASE),
                "database_generation": "generation-a",
                "checked": 2,
                "inserted": 1,
                "already_current": 1,
            },
            {
                "status": "migrated",
                "profile": str(MODULE.PROFILE),
                "database": str(MODULE.DATABASE),
                "database_generation": "generation-a",
                "checked": 2,
                "inserted": 0,
                "already_current": 2,
            },
        ]
        profile_commands: list[list[str]] = []

        def profile_run(
            arguments: list[str], *, timeout: float, check: bool = True
        ) -> object:
            profile_commands.append(arguments)
            return SimpleNamespace(
                stdout=json.dumps(profile_results[len(profile_commands) - 1]),
                stderr="",
                returncode=0,
            )

        driver.run = profile_run
        try:
            profile_evidence = driver.migrate(
                service_schema_upgrade=service_upgrade,
                client_schema_upgrade=client_upgrade,
            )
        finally:
            MODULE.DATABASE = production_database
            MODULE.PROFILE = previous_profile
        expect(
            profile_evidence["contract"]
            == "devcoordinator.post-upgrade-profile-backfill.v1"
            and profile_evidence["backfill"]["inserted"] == 1
            and profile_evidence["idempotency"]["inserted"] == 0
            and schema_checks == [("service", 14), ("client", 14)]
            and len(profile_commands) == 2,
            "post-upgrade profile backfill lost schema, migration, or idempotency proof",
        )

    source = SCRIPT.read_text(encoding="utf-8")
    capture_source = inspect.getsource(MODULE.Driver._capture_database_files)
    expect(
        "O_NOFOLLOW" in capture_source
        and "os.fstat(source_descriptor)" in capture_source
        and "source.read_bytes()" not in capture_source,
        "writer-free checkpoint is not descriptor-anchored and streaming",
    )
    expect('self.checkout("main")' in source, "target checkout is not explicit")
    expect("--force" not in source, "deployment can discard a dirty checkout")
    expect("self.rollback(error)" in source, "foreground failure handler is missing")
    expect(
        "clear maintenance marker after rollback" in source,
        "rollback does not retain the wait fence through health verification",
    )
    expect(
        "devcoordinator-sqlite-backup" in source,
        "deployment does not verify the canonical backup artifact type",
    )
    expect(
        '"/usr/sbin/runuser",\n                "--user",\n                "holyglory"'
        in source,
        "root deployment still runs private auth evidence as the wrong user",
    )
    expect(
        source.count(
            '"/usr/sbin/runuser",\n                "--user",\n                "holyglory"'
        )
        == 1,
        "deployment does not isolate the unprivileged auth check from root process evidence",
    )
    expect(
        '"--token-owner-uid",\n                str(self.console_uid)' in source,
        "root Console process verification does not bind the private token owner UID",
    )
    expect(
        '"project": str(self.repository)' in source
        and '"name": "devops-console"' in source
        and '"port": "443"' in source,
        "deployment evidence still requests the complete server-wide inventory",
    )
    deploy_source = inspect.getsource(MODULE.Driver.deploy)
    expect(
        "same-schema release must start from the approved target checkout" in deploy_source,
        "same-schema release does not bind the checked-out target commit",
    )
    expect(
        "same-schema rollback ref must be a distinct ancestor of target" in deploy_source,
        "same-schema release does not retain a historical rollback source",
    )
    expect(
        "if not self.args.same_schema_release:" in deploy_source,
        "same-schema release still runs the one-time schema migration",
    )
    expect(
        deploy_source.index("self.capture_client_database()")
        < deploy_source.index(
            "service_schema_upgrade = self.upgrade_database_schema_offline("
        )
        < deploy_source.index(
            "client_schema_upgrade = self.upgrade_database_schema_offline("
        )
        < deploy_source.index(
            "profile_enrollment_backfill = self.migrate("
        )
        < deploy_source.index(
            "migrated_client = self.client_schema_evidence("
        ),
        "dual offline upgrades and post-upgrade profile backfill are misordered",
    )
    expect(
        deploy_source.count("service_schema_upgrade=service_schema_upgrade") >= 4
        and deploy_source.count("client_schema_upgrade=client_schema_upgrade") >= 4
        and deploy_source.count(
            "profile_enrollment_backfill=profile_enrollment_backfill"
        )
        >= 3,
        "deployment journal/result flow omits upgrade or profile-backfill evidence",
    )
    journal_source = inspect.getsource(MODULE.Driver.journal)
    expect(
        "self.service_schema_upgrade_evidence" in journal_source
        and "self.client_schema_upgrade_evidence" in journal_source
        and "self.profile_enrollment_backfill_evidence" in journal_source,
        "failure journals can lose retained upgrade/backfill evidence references",
    )
    receipt_writer_source = inspect.getsource(MODULE._immutable_json_receipt)
    expect(
        "os.O_EXCL" in receipt_writer_source
        and '"O_NOFOLLOW"' in receipt_writer_source
        and "os.fchmod(descriptor, 0o400)" in receipt_writer_source
        and "os.replace" not in receipt_writer_source,
        "offline schema receipts are replaceable or insufficiently private",
    )
    migration_source = inspect.getsource(MODULE.Driver.migrate)
    expect(
        migration_source.index("require_schema_upgrade_receipt(")
        < migration_source.index("migrate-profile-enrollments")
        and migration_source.count("self.run(arguments, timeout=120)") == 2
        and "devcoordinator.post-upgrade-profile-backfill.v1"
        in migration_source,
        "profile backfill does not require both receipts and prove idempotency",
    )
    expect(
        deploy_source.index("self.installer(\"verify\")")
        < deploy_source.index("target_service_database = self.target_schema_readiness(")
        < deploy_source.index("target_client_database = self.target_schema_readiness(")
        < deploy_source.index('["/usr/bin/systemctl", "start", BROKER_UNIT]'),
        "target service/client database readiness is not proved before startup",
    )
    readiness_source = inspect.getsource(MODULE.Driver.target_schema_readiness)
    expect(
        "verify_coordinator_schema_readiness.py" in readiness_source
        and '"--expected-schema"' in readiness_source
        and '"/usr/sbin/runuser"' in readiness_source,
        "target readiness does not bind target source, schema, and database-owner UID",
    )
    expect(
        all(
            unit in deploy_source
            for unit in ("CONSOLE_UNIT", "API_UNIT", "BROKER_UNIT")
        ),
        "writer-free checkpoint does not stop every production writer",
    )
    expect(
        deploy_source.index("clear_maintenance(")
        < deploy_source.index('"restart", API_UNIT'),
        "target API is started while its own maintenance fence blocks readiness",
    )
    expect(
        "recovery-maintenance-active" in deploy_source,
        "post-clear target failure does not reactivate maintenance before rollback",
    )
    expect(
        deploy_source.index("activate_maintenance(")
        < deploy_source.index("self.wait_for_operation_quiescence()")
        < deploy_source.index("pre_schema = self.schema_evidence"),
        "deployment still admits a new operation between quiescence proof and maintenance",
    )
    expect(
        deploy_source.index("self.wait_for_operation_quiescence()")
        < deploy_source.index("backup_manifest = self.online_backup()"),
        "online backup starts before fenced operations have drained",
    )
    expect(
        'if not self.args.same_schema_release:\n            self.inventory("pre-inventory.json")'
        in deploy_source,
        "same-schema deployment still depends on the old process's inventory path",
    )
    quiescence_source = inspect.getsource(MODULE.Driver.wait_for_operation_quiescence)
    expect(
        quiescence_source.index("The fence prevents new admissions")
        < quiescence_source.index('["/usr/bin/systemctl", "restart", BROKER_UNIT]')
        < quiescence_source.index("recovery_deadline"),
        "orphaned pre-fence operations cannot be recovered by a controlled broker restart",
    )
    recovery_source = inspect.getsource(
        MODULE.Driver.require_or_recover_preflight_services
    )
    expect(
        recovery_source.index("self.require_active(API_UNIT)")
        < recovery_source.index('["/usr/bin/systemctl", "start", BROKER_UNIT]')
        and recovery_source.index("self.require_active(CONSOLE_UNIT)")
        < recovery_source.index('["/usr/bin/systemctl", "start", BROKER_UNIT]'),
        "preflight broker recovery does not first prove the API and Console shape",
    )
    expect(
        recovery_source.index("load_maintenance_state(")
        < recovery_source.index('["/usr/bin/systemctl", "start", BROKER_UNIT]'),
        "preflight broker recovery can race an active maintenance transaction",
    )
    expect(
        source.count("wait_broker_ready") == 4,
        "broker readiness is not required after preflight, target, and rollback starts",
    )
    expect(
        inspect.signature(MODULE.Driver.wait_broker_ready).parameters["timeout"].default
        >= 120,
        "deployment does not tolerate the broker's bounded post-stop lock handoff",
    )
    expect(
        MODULE.ONLINE_BACKUP_TIMEOUT_SECONDS >= 10 * 60,
        "multi-GiB verified backup still inherits the incident-causing short deadline",
    )
    failed_recovery_source = inspect.getsource(
        MODULE.Driver.recover_prior_failed_deployment
    )
    expect(
        failed_recovery_source.index("load_maintenance_state(")
        < failed_recovery_source.index('["/usr/bin/systemctl", "stop", CONSOLE_UNIT]')
        < failed_recovery_source.index('["/usr/bin/systemctl", "restart", API_UNIT]')
        < failed_recovery_source.index("clear_maintenance(")
        < failed_recovery_source.index('["/usr/bin/systemctl", "restart", CONSOLE_UNIT]')
        < failed_recovery_source.index("self.verify_services(")
        < failed_recovery_source.index("activate_maintenance("),
        "rollback-failed recovery is not fenced, ordered, and verified before reopening",
    )
    expect(
        deploy_source.index("os.chown(self.transaction, 0, 0)")
        < deploy_source.index("self.journal()"),
        "deployment artifacts can inherit a group owner that blocks installer rollback",
    )
    rollback_source = inspect.getsource(MODULE.Driver.rollback)
    expect(
        rollback_source.index('attempt("restore client database"')
        < rollback_source.index('"checkout compatibility source"'),
        "rollback starts compatibility code before restoring its client database",
    )
    expect(
        rollback_source.count("normalize_console_private_state") == 2,
        "rollback does not protect legacy Console state before and after startup",
    )
    print(
        "maintenance deployment self-test ok "
        "(quiescence, dual checkpoints, receipted dual upgrades, post-upgrade "
        "profile idempotency, bounded inventory, auth identity, privacy, rollback guard)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
