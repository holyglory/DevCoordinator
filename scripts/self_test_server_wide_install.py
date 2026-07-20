#!/usr/bin/env python3
"""Deterministic plan and deployment-contract tests for system installation."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import pwd
import sqlite3
import stat
import tempfile
from unittest import mock


SCRIPT = Path(__file__).with_name("install_server_wide_coordinator.py")
SPEC = importlib.util.spec_from_file_location("server_wide_install", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load server-wide installer")
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


def expect(condition: bool, label: str) -> None:
    if not condition:
        raise AssertionError(label)


def must_reject(action: object, label: str) -> None:
    try:
        action()  # type: ignore[operator]
    except INSTALLER.InstallError:
        return
    raise AssertionError(f"missed unsafe installer condition: {label}")


def private_directory(path: Path) -> None:
    path.mkdir()
    path.chmod(0o700)


def exercise_broker_unit_source_controls() -> None:
    source = (INSTALLER.ROOT / "deploy/devcoordinator-broker.service").read_text(
        encoding="utf-8"
    )
    with tempfile.TemporaryDirectory(prefix="devcoordinator-broker-unit-") as raw:
        fixture = Path(raw).resolve(strict=True) / "broker.service"

        def check_rejected(value: str, label: str) -> None:
            fixture.write_text(value, encoding="utf-8")
            try:
                INSTALLER.validate_broker_unit_source(fixture)
            except INSTALLER.InstallError:
                return
            raise AssertionError(f"installer accepted unsafe broker unit: {label}")

        fixture.write_text(source, encoding="utf-8")
        INSTALLER.validate_broker_unit_source(fixture)
        check_rejected(
            source.replace(
                "ReadWritePaths=/var/lib/devcoordinator /run/devcoordinator",
                "ReadWritePaths=/var/lib/devcoordinator /run/devcoordinator /etc",
            ),
            "extra writable path",
        )
        check_rejected(
            source.replace(
                "ReadWritePaths=/var/lib/devcoordinator /run/devcoordinator",
                "ReadWritePaths=/home /var/lib/devcoordinator /run/devcoordinator",
            ),
            "ineffective broad home exception",
        )
        check_rejected(
            source.replace("ProtectHome=read-only", "ProtectHome=false"),
            "writable home baseline",
        )
        check_rejected(
            source.replace("ProtectSystem=strict", "ProtectSystem=full"),
            "weakened system protection",
        )
        check_rejected(
            source + "\nAmbientCapabilities=CAP_SYS_ADMIN\n",
            "ambient capability",
        )
        check_rejected(
            source + "\nCapabilityBoundingSet=CAP_SYS_ADMIN\n",
            "changed capability ceiling",
        )
        check_rejected(
            source + "\nBindPaths=/home:/run/devcoordinator/home\n",
            "writable bind alias",
        )
        writable = "ReadWritePaths=/var/lib/devcoordinator /run/devcoordinator"
        check_rejected(
            source.replace(f"{writable}\n", "", 1) + f"\n{writable}\n",
            "writable path directive outside Service",
        )


def exercise_enrolled_home_dropin_transaction() -> None:
    alice = Path("/home/alice")
    bob = Path("/home/bob")
    old = INSTALLER.render_enrolled_home_dropin([Path("/home/legacy")])
    first = INSTALLER.render_enrolled_home_dropin([alice, bob])
    second = INSTALLER.render_enrolled_home_dropin([alice])
    for paths, label in (
        ([bob, alice], "unsorted homes"),
        ([alice, alice], "duplicate homes"),
        ([Path("/home")], "home root"),
        ([Path("/srv/alice")], "non-home root"),
        ([Path("/home/bad name")], "unit-token whitespace"),
    ):
        must_reject(
            lambda paths=paths: INSTALLER.render_enrolled_home_dropin(paths),
            label,
        )

    original_uid = INSTALLER.SYSTEM_OWNER_UID
    original_gid = INSTALLER.SYSTEM_OWNER_GID
    with tempfile.TemporaryDirectory(prefix="devcoordinator-home-dropin-") as raw:
        root = Path(raw).resolve(strict=True)
        dropin = root / "systemd" / "broker.service.d" / "80-homes.conf"
        dropin.parent.mkdir(parents=True)
        dropin.parent.chmod(0o755)
        dropin.write_bytes(old)
        dropin.chmod(0o640)
        first_transaction = root / "transaction-first"
        second_transaction = root / "transaction-second"
        absent_transaction = root / "transaction-absent"
        for transaction in (
            first_transaction,
            second_transaction,
            absent_transaction,
        ):
            private_directory(transaction)
        try:
            INSTALLER.SYSTEM_OWNER_UID = os.getuid()
            INSTALLER.SYSTEM_OWNER_GID = os.getgid()
            first_entry = INSTALLER.install_payload(
                first,
                dropin,
                first_transaction,
                source_label=INSTALLER.ENROLLED_HOME_DROPIN_SOURCE,
            )
            expect(dropin.read_bytes() == first, "first client set was not installed")
            second_entry = INSTALLER.install_payload(
                second,
                dropin,
                second_transaction,
                source_label=INSTALLER.ENROLLED_HOME_DROPIN_SOURCE,
            )
            expect(
                dropin.read_bytes() == second and b"/home/bob" not in dropin.read_bytes(),
                "reapply accumulated a removed client's writable home",
            )
            INSTALLER.restore_installed_system_file(second_entry)
            expect(
                dropin.read_bytes() == first,
                "second transaction rollback did not restore the prior complete set",
            )
            INSTALLER.restore_installed_system_file(first_entry)
            expect(
                dropin.read_bytes() == old
                and stat.S_IMODE(dropin.lstat().st_mode) == 0o640,
                "first transaction rollback did not restore exact prior bytes and mode",
            )

            absent = root / "systemd" / "broker.service.d" / "80-new.conf"
            absent_entry = INSTALLER.install_payload(
                second,
                absent,
                absent_transaction,
                source_label=INSTALLER.ENROLLED_HOME_DROPIN_SOURCE,
            )
            expect(absent.read_bytes() == second, "absent drop-in was not installed")
            INSTALLER.restore_installed_system_file(absent_entry)
            expect(not absent.exists(), "rollback retained a newly created drop-in")

            drift_transaction = root / "transaction-drift"
            private_directory(drift_transaction)
            drift_entry = INSTALLER.install_payload(
                first,
                dropin,
                drift_transaction,
                source_label=INSTALLER.ENROLLED_HOME_DROPIN_SOURCE,
            )
            dropin.write_bytes(second)
            must_reject(
                lambda: INSTALLER.restore_installed_system_file(drift_entry),
                "post-install drop-in drift",
            )

            unsafe_parent = root / "unsafe-parent" / "homes.conf"
            unsafe_parent.parent.mkdir(parents=True)
            unsafe_parent.parent.chmod(0o775)
            unsafe_parent_transaction = root / "transaction-unsafe-parent"
            private_directory(unsafe_parent_transaction)
            must_reject(
                lambda: INSTALLER.install_payload(
                    first,
                    unsafe_parent,
                    unsafe_parent_transaction,
                    source_label=INSTALLER.ENROLLED_HOME_DROPIN_SOURCE,
                ),
                "group-writable generated-drop-in parent",
            )

            unsafe_file = root / "unsafe-file" / "homes.conf"
            unsafe_file.parent.mkdir(parents=True)
            unsafe_file.parent.chmod(0o755)
            unsafe_file.write_bytes(old)
            unsafe_file.chmod(0o666)
            unsafe_file_transaction = root / "transaction-unsafe-file"
            private_directory(unsafe_file_transaction)
            must_reject(
                lambda: INSTALLER.install_payload(
                    first,
                    unsafe_file,
                    unsafe_file_transaction,
                    source_label=INSTALLER.ENROLLED_HOME_DROPIN_SOURCE,
                ),
                "group-writable generated drop-in",
            )
        finally:
            INSTALLER.SYSTEM_OWNER_UID = original_uid
            INSTALLER.SYSTEM_OWNER_GID = original_gid


def exercise_legacy_docker_dropin_transaction() -> None:
    original_dropin = INSTALLER.LEGACY_DOCKER_DROPIN
    original_run = INSTALLER.run
    original_command = INSTALLER.command
    original_geteuid = INSTALLER.os.geteuid
    original_owner_uid = INSTALLER.SYSTEM_OWNER_UID
    original_owner_gid = INSTALLER.SYSTEM_OWNER_GID
    with tempfile.TemporaryDirectory(prefix="devcoordinator-dropin-") as raw:
        root = Path(raw).resolve(strict=True)
        systemd = root / "systemd"
        dropin_parent = systemd / "devcoordinator-broker.service.d"
        dropin_parent.mkdir(parents=True)
        systemd.chmod(0o755)
        dropin_parent.chmod(0o755)
        dropin = dropin_parent / "90-docker-config.conf"
        unrelated = dropin_parent / "operator-owned.conf"
        unrelated.write_text("[Service]\nNice=5\n", encoding="utf-8")
        transaction = root / "transaction"
        private_directory(transaction)
        dropin.write_bytes(INSTALLER.LEGACY_DOCKER_DROPIN_CONTENT)
        dropin.chmod(0o640)
        try:
            INSTALLER.SYSTEM_OWNER_UID = os.getuid()
            INSTALLER.SYSTEM_OWNER_GID = os.getgid()
            INSTALLER.LEGACY_DOCKER_DROPIN = dropin
            entry = INSTALLER.prepare_legacy_docker_dropin_removal(transaction)
            expect(entry is not None, "known legacy drop-in was not prepared")
            backup = Path(str(entry["backup"]))
            expect(
                backup.read_bytes() == INSTALLER.LEGACY_DOCKER_DROPIN_CONTENT,
                "legacy drop-in backup content changed",
            )
            expect(
                stat.S_IMODE(backup.lstat().st_mode) == 0o600,
                "legacy drop-in backup is not private",
            )
            journal = {
                "version": 1,
                "status": "applied",
                "repo_root": str(INSTALLER.ROOT),
                "system_files": [],
                "link_transactions": [],
                "group_members_added": [],
                "client_journals": [],
                "legacy_docker_dropin": entry,
                "legacy_docker_dropin_removed": True,
            }
            INSTALLER.atomic_json(transaction / INSTALLER.JOURNAL_NAME, journal)
            INSTALLER.remove_prepared_legacy_docker_dropin(entry, transaction)
            expect(
                not INSTALLER.path_lexists(dropin),
                "proved legacy drop-in was not removed",
            )
            expect(dropin_parent.is_dir(), "drop-in directory was removed")
            expect(
                unrelated.read_text(encoding="utf-8") == "[Service]\nNice=5\n",
                "unrelated drop-in was changed",
            )

            calls: list[tuple[str, ...]] = []
            INSTALLER.run = lambda *arguments: calls.append(tuple(arguments))
            INSTALLER.command = lambda name: name
            INSTALLER.os.geteuid = lambda: 0
            result = INSTALLER.rollback_install(transaction)
            expect(result["status"] == "rolled_back", "rollback status was not durable")
            expect(
                dropin.read_bytes() == INSTALLER.LEGACY_DOCKER_DROPIN_CONTENT,
                "rollback did not restore exact legacy bytes",
            )
            expect(
                stat.S_IMODE(dropin.lstat().st_mode) == 0o640,
                "rollback did not restore the exact legacy mode",
            )
            expect(
                unrelated.read_text(encoding="utf-8") == "[Service]\nNice=5\n",
                "rollback changed an unrelated drop-in",
            )
            expect(
                calls == [("systemctl", "daemon-reload")],
                f"rollback invoked unexpected commands: {calls}",
            )
            persisted = json.loads(
                (transaction / INSTALLER.JOURNAL_NAME).read_text(encoding="utf-8")
            )
            expect(
                persisted["status"] == "rolled_back",
                "rollback journal status was not persisted",
            )
            # An exact already-restored target is an idempotent success, not
            # external drift or a reason to rewrite the directory.
            INSTALLER.restore_legacy_docker_dropin(entry, transaction)
            expect(unrelated.exists(), "idempotent restore removed unrelated content")
        finally:
            INSTALLER.LEGACY_DOCKER_DROPIN = original_dropin
            INSTALLER.run = original_run
            INSTALLER.command = original_command
            INSTALLER.os.geteuid = original_geteuid
            INSTALLER.SYSTEM_OWNER_UID = original_owner_uid
            INSTALLER.SYSTEM_OWNER_GID = original_owner_gid


def exercise_legacy_docker_dropin_controls() -> None:
    original_dropin = INSTALLER.LEGACY_DOCKER_DROPIN
    original_owner_uid = INSTALLER.SYSTEM_OWNER_UID
    original_owner_gid = INSTALLER.SYSTEM_OWNER_GID
    with tempfile.TemporaryDirectory(prefix="devcoordinator-dropin-controls-") as raw:
        root = Path(raw).resolve(strict=True)
        systemd = root / "systemd"
        systemd.mkdir()
        systemd.chmod(0o755)

        def fresh(label: str) -> tuple[Path, Path]:
            parent = systemd / f"{label}.service.d"
            parent.mkdir()
            parent.chmod(0o755)
            transaction = root / f"transaction-{label}"
            private_directory(transaction)
            return parent / "90-docker-config.conf", transaction

        try:
            INSTALLER.SYSTEM_OWNER_UID = os.getuid()
            INSTALLER.SYSTEM_OWNER_GID = os.getgid()
            absent, absent_transaction = fresh("absent")
            INSTALLER.LEGACY_DOCKER_DROPIN = absent
            expect(
                INSTALLER.prepare_legacy_docker_dropin_removal(absent_transaction)
                is None,
                "absent legacy drop-in was treated as present",
            )
            expect(absent.parent.is_dir(), "absent control removed the drop-in directory")

            owner_drift, owner_drift_transaction = fresh("owner-drift")
            owner_drift.write_bytes(INSTALLER.LEGACY_DOCKER_DROPIN_CONTENT)
            INSTALLER.LEGACY_DOCKER_DROPIN = owner_drift
            INSTALLER.SYSTEM_OWNER_UID = os.getuid() + 100_000
            must_reject(
                lambda: INSTALLER.prepare_legacy_docker_dropin_removal(
                    owner_drift_transaction
                ),
                "transaction owner drift",
            )
            must_reject(
                lambda: INSTALLER.inspect_legacy_docker_dropin(),
                "systemd parent owner drift",
            )
            INSTALLER.SYSTEM_OWNER_UID = os.getuid()
            expect(owner_drift.exists(), "owner-drift rejection removed the source")

            owner_artifact = root / "owner-artifact.json"
            owner_artifact.write_text("{}\n", encoding="utf-8")
            owner_artifact.chmod(0o600)
            INSTALLER.SYSTEM_OWNER_UID = os.getuid() + 100_000
            must_reject(
                lambda: INSTALLER.require_private_regular(
                    owner_artifact, label="test journal or backup"
                ),
                "journal or backup owner drift",
            )
            INSTALLER.SYSTEM_OWNER_UID = os.getuid()

            unsafe_parent, unsafe_parent_transaction = fresh("unsafe-parent")
            unsafe_parent.write_bytes(INSTALLER.LEGACY_DOCKER_DROPIN_CONTENT)
            unsafe_parent.parent.chmod(0o775)
            INSTALLER.LEGACY_DOCKER_DROPIN = unsafe_parent
            must_reject(
                lambda: INSTALLER.prepare_legacy_docker_dropin_removal(
                    unsafe_parent_transaction
                ),
                "group-writable drop-in parent",
            )
            unsafe_parent.parent.chmod(0o755)
            expect(unsafe_parent.exists(), "unsafe-parent rejection removed the source")

            unsafe_file, unsafe_file_transaction = fresh("unsafe-file")
            unsafe_file.write_bytes(INSTALLER.LEGACY_DOCKER_DROPIN_CONTENT)
            unsafe_file.chmod(0o666)
            INSTALLER.LEGACY_DOCKER_DROPIN = unsafe_file
            must_reject(
                lambda: INSTALLER.prepare_legacy_docker_dropin_removal(
                    unsafe_file_transaction
                ),
                "group/world-writable drop-in file",
            )
            expect(unsafe_file.exists(), "unsafe-file rejection removed the source")

            drift, drift_transaction = fresh("drift")
            drift.write_text(
                "[Service]\nEnvironment=DOCKER_CONFIG=/tmp/docker\n",
                encoding="utf-8",
            )
            INSTALLER.LEGACY_DOCKER_DROPIN = drift
            must_reject(
                lambda: INSTALLER.prepare_legacy_docker_dropin_removal(
                    drift_transaction
                ),
                "changed Docker path",
            )
            expect(drift.exists(), "content-drift rejection removed the source")

            extra, extra_transaction = fresh("extra")
            extra.write_bytes(
                INSTALLER.LEGACY_DOCKER_DROPIN_CONTENT + b"ExecStop=/usr/bin/false\n"
            )
            INSTALLER.LEGACY_DOCKER_DROPIN = extra
            must_reject(
                lambda: INSTALLER.prepare_legacy_docker_dropin_removal(
                    extra_transaction
                ),
                "extra directive",
            )
            expect(extra.exists(), "extra-directive rejection removed the source")

            symlink, symlink_transaction = fresh("symlink")
            symlink_source = root / "symlink-source.conf"
            symlink_source.write_bytes(INSTALLER.LEGACY_DOCKER_DROPIN_CONTENT)
            symlink.symlink_to(symlink_source)
            INSTALLER.LEGACY_DOCKER_DROPIN = symlink
            must_reject(
                lambda: INSTALLER.prepare_legacy_docker_dropin_removal(
                    symlink_transaction
                ),
                "symlink file",
            )
            expect(symlink.is_symlink(), "symlink rejection changed the source")

            real_parent = systemd / "real-parent"
            real_parent.mkdir()
            real_parent.chmod(0o755)
            (real_parent / "90-docker-config.conf").write_bytes(
                INSTALLER.LEGACY_DOCKER_DROPIN_CONTENT
            )
            parent_link = systemd / "parent-link.service.d"
            parent_link.symlink_to(real_parent, target_is_directory=True)
            parent_link_transaction = root / "transaction-parent-link"
            private_directory(parent_link_transaction)
            INSTALLER.LEGACY_DOCKER_DROPIN = (
                parent_link / "90-docker-config.conf"
            )
            must_reject(
                lambda: INSTALLER.prepare_legacy_docker_dropin_removal(
                    parent_link_transaction
                ),
                "symlink parent",
            )
            expect(parent_link.is_symlink(), "symlink-parent rejection changed the source")

            nonregular, nonregular_transaction = fresh("nonregular")
            nonregular.mkdir()
            INSTALLER.LEGACY_DOCKER_DROPIN = nonregular
            must_reject(
                lambda: INSTALLER.prepare_legacy_docker_dropin_removal(
                    nonregular_transaction
                ),
                "non-regular target",
            )
            expect(nonregular.is_dir(), "nonregular rejection changed the source")

            changed, changed_transaction = fresh("changed-after-backup")
            changed.write_bytes(INSTALLER.LEGACY_DOCKER_DROPIN_CONTENT)
            changed.chmod(0o640)
            INSTALLER.LEGACY_DOCKER_DROPIN = changed
            changed_entry = INSTALLER.prepare_legacy_docker_dropin_removal(
                changed_transaction
            )
            expect(changed_entry is not None, "changed-after-backup fixture was not prepared")
            changed.write_bytes(
                INSTALLER.LEGACY_DOCKER_DROPIN_CONTENT + b"# external drift\n"
            )
            must_reject(
                lambda: INSTALLER.remove_prepared_legacy_docker_dropin(
                    changed_entry, changed_transaction
                ),
                "changed after backup",
            )
            expect(changed.exists(), "post-backup drift rejection removed the source")

            bad_journal, bad_journal_transaction = fresh("bad-journal")
            bad_journal.write_bytes(INSTALLER.LEGACY_DOCKER_DROPIN_CONTENT)
            bad_journal.chmod(0o640)
            INSTALLER.LEGACY_DOCKER_DROPIN = bad_journal
            bad_entry = INSTALLER.prepare_legacy_docker_dropin_removal(
                bad_journal_transaction
            )
            expect(bad_entry is not None, "bad-journal fixture was not prepared")
            altered_entry = dict(bad_entry)
            altered_entry["destination"] = str(root / "foreign.conf")
            must_reject(
                lambda: INSTALLER.remove_prepared_legacy_docker_dropin(
                    altered_entry, bad_journal_transaction
                ),
                "journal destination",
            )
            expect(bad_journal.exists(), "bad-journal rejection removed the source")

            bad_backup, bad_backup_transaction = fresh("bad-backup")
            bad_backup.write_bytes(INSTALLER.LEGACY_DOCKER_DROPIN_CONTENT)
            bad_backup.chmod(0o640)
            INSTALLER.LEGACY_DOCKER_DROPIN = bad_backup
            bad_backup_entry = INSTALLER.prepare_legacy_docker_dropin_removal(
                bad_backup_transaction
            )
            expect(bad_backup_entry is not None, "bad-backup fixture was not prepared")
            INSTALLER.remove_prepared_legacy_docker_dropin(
                bad_backup_entry, bad_backup_transaction
            )
            backup_path = Path(str(bad_backup_entry["backup"]))
            backup_path.unlink()
            backup_path.symlink_to(symlink_source)
            must_reject(
                lambda: INSTALLER.restore_legacy_docker_dropin(
                    bad_backup_entry, bad_backup_transaction
                ),
                "symlink backup",
            )
            expect(
                not INSTALLER.path_lexists(bad_backup),
                "unsafe backup rejection recreated the destination",
            )
            expect(
                bad_backup.parent.is_dir(),
                "unsafe backup rejection removed the drop-in directory",
            )
        finally:
            INSTALLER.LEGACY_DOCKER_DROPIN = original_dropin
            INSTALLER.SYSTEM_OWNER_UID = original_owner_uid
            INSTALLER.SYSTEM_OWNER_GID = original_owner_gid


def exercise_source_acl_transaction() -> None:
    original_root = INSTALLER.ROOT
    original_source = INSTALLER.SKILL_SOURCE
    original_group = INSTALLER.ACCESS_GROUP
    with tempfile.TemporaryDirectory(prefix="devcoordinator-install-acl-") as raw:
        repository = Path(raw) / "repository"
        source = repository / "skills/codex-dev-coordinator"
        transaction = Path(raw) / "transaction"
        source.mkdir(parents=True)
        transaction.mkdir()
        skill = source / "SKILL.md"
        script = source / "scripts/dev_coordinator.py"
        script.parent.mkdir()
        skill.write_text("canonical\n", encoding="utf-8")
        script.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        script.chmod(0o700)
        try:
            INSTALLER.ROOT = repository
            INSTALLER.SKILL_SOURCE = source
            INSTALLER.ACCESS_GROUP = "root"
            before = INSTALLER.capture(
                INSTALLER.command("getfacl"),
                "--absolute-names",
                "--recursive",
                str(repository),
            )
            backup = INSTALLER.capture_source_acl(transaction)
            INSTALLER.grant_source_acl()
            skill_acl = INSTALLER.capture(
                INSTALLER.command("getfacl"), "--omit-header", str(skill)
            ).decode("utf-8")
            script_acl = INSTALLER.capture(
                INSTALLER.command("getfacl"), "--omit-header", str(script)
            ).decode("utf-8")
            expect("group:root:r--" in skill_acl, "skill ACL did not grant read access")
            expect("group:root:r-x" in script_acl, "script ACL did not grant execute access")
            inherited = source / "future-update.txt"
            inherited.write_text("future\n", encoding="utf-8")
            inherited_acl = INSTALLER.capture(
                INSTALLER.command("getfacl"), "--omit-header", str(inherited)
            ).decode("utf-8")
            expect("group:root:r-x" in inherited_acl, "default ACL was not inherited")
            expect("#effective:r--" in inherited_acl, "inherited file ACL was not read-only")
            inherited.unlink()
            INSTALLER.restore_source_acl(backup)
            after = INSTALLER.capture(
                INSTALLER.command("getfacl"),
                "--absolute-names",
                "--recursive",
                str(repository),
            )
            expect(after == before, "ACL rollback did not restore exact source ACLs")
        finally:
            INSTALLER.ROOT = original_root
            INSTALLER.SKILL_SOURCE = original_source
            INSTALLER.ACCESS_GROUP = original_group


def exercise_profile_database_enrollment_guard() -> None:
    now = 2_000_000_000
    uid = 1234
    account_id = "account-alice"
    repo_id = "repo-alpha"
    canonical_root = "/srv/repositories/alpha"
    database_generation = "database-generation-alpha"
    issued_at = "2033-05-18T03:23:20Z"
    original_owner_uid = INSTALLER.SYSTEM_OWNER_UID
    original_owner_gid = INSTALLER.SYSTEM_OWNER_GID
    with tempfile.TemporaryDirectory(prefix="devcoordinator-enrollment-guard-") as raw:
        root = Path(raw).resolve(strict=True)
        root.chmod(0o700)
        profile = root / "client-profiles.json"
        database = root / "coordinator.sqlite3"

        def write_profile(
            *,
            enabled: bool = True,
            expires_at: int = now + 600,
            profile_issued_at: str = issued_at,
        ) -> None:
            profile.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "service": {
                            "socket": "/run/devcoordinator/broker.sock",
                            "uid": 0,
                            "gid": 99,
                            "mode": "0660",
                            "database_generation": database_generation,
                        },
                        "clients": {
                            str(uid): {
                                "account_id": account_id,
                                "issued_at": profile_issued_at,
                                "valid_until_epoch": now + 1200,
                                "repositories": [
                                    {
                                        "canonical_root": canonical_root,
                                        "repo_id": repo_id,
                                        "generation": 7,
                                        "servers": {},
                                        "containers": {},
                                        "compose_definition_id": None,
                                        "account_id": account_id,
                                        "enabled": enabled,
                                        "issued_at": profile_issued_at,
                                        "valid_until_epoch": expires_at,
                                    }
                                ],
                            }
                        },
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            profile.chmod(0o640)

        connection = sqlite3.connect(database)
        connection.executescript(
            """
            CREATE TABLE schema_metadata(
                singleton INTEGER PRIMARY KEY,
                database_generation TEXT NOT NULL
            );
            CREATE TABLE broker_acl_principals(
                uid INTEGER PRIMARY KEY,
                account_id TEXT NOT NULL,
                enabled INTEGER NOT NULL
            );
            CREATE TABLE repositories(
                repo_id TEXT PRIMARY KEY,
                canonical_root TEXT NOT NULL,
                state TEXT NOT NULL,
                generation INTEGER NOT NULL
            );
            CREATE TABLE repository_installations(
                repo_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                startup_fenced INTEGER NOT NULL
            );
            CREATE TABLE broker_repository_enrollments(
                uid INTEGER NOT NULL,
                repo_id TEXT NOT NULL,
                account_id TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                issued_at TEXT NOT NULL,
                valid_until_epoch INTEGER NOT NULL,
                PRIMARY KEY(uid, repo_id)
            );
            """
        )
        connection.execute(
            "INSERT INTO schema_metadata VALUES(1, ?)", (database_generation,)
        )
        connection.execute(
            "INSERT INTO broker_acl_principals VALUES(?, ?, 1)", (uid, account_id)
        )
        connection.execute(
            "INSERT INTO repositories VALUES(?, ?, 'active', 7)",
            (repo_id, canonical_root),
        )
        connection.execute(
            "INSERT INTO repository_installations VALUES(?, 'installed', 0)",
            (repo_id,),
        )
        connection.commit()
        connection.close()
        database.chmod(0o600)
        write_profile()
        try:
            INSTALLER.SYSTEM_OWNER_UID = os.getuid()
            INSTALLER.SYSTEM_OWNER_GID = os.getgid()

            missing = INSTALLER.profile_database_enrollment_check(
                profile_path=profile,
                database_path=database,
                now_epoch=now,
            )
            expect(
                missing["ok"] is False
                and missing["code"]
                == INSTALLER.PROFILE_DATABASE_ENROLLMENT_DRIFT
                and {issue["reason"] for issue in missing["issues"]}
                == {"enrollment_missing"},
                "a current protected profile with no service enrollment did not block restart",
            )

            connection = sqlite3.connect(database)
            connection.execute(
                "INSERT INTO broker_repository_enrollments VALUES(?, ?, ?, 1, ?, ?)",
                (uid, repo_id, account_id, issued_at, now + 600),
            )
            connection.commit()
            connection.close()
            exact = INSTALLER.profile_database_enrollment_check(
                profile_path=profile,
                database_path=database,
                now_epoch=now,
            )
            expect(
                exact["ok"] is True
                and exact["status"] == "matched"
                and exact["checked_current_enrollments"] == 1,
                f"an exact profile/database enrollment did not pass: {exact}",
            )

            for sql, expected_reason in (
                (
                    "UPDATE broker_repository_enrollments SET enabled = 0",
                    "enrollment_disabled",
                ),
                (
                    f"UPDATE broker_repository_enrollments SET valid_until_epoch = {now}",
                    "enrollment_expired",
                ),
                (
                    "UPDATE broker_repository_enrollments SET account_id = 'account-bob'",
                    "enrollment_account_mismatch",
                ),
                (
                    "UPDATE broker_repository_enrollments SET issued_at = '2033-05-18T03:24:20Z'",
                    "enrollment_issued_at_mismatch",
                ),
                (
                    f"UPDATE broker_repository_enrollments SET valid_until_epoch = {now + 900}",
                    "enrollment_expiry_mismatch",
                ),
                (
                    f"UPDATE broker_repository_enrollments SET valid_until_epoch = {now + 300}",
                    "enrollment_expiry_mismatch",
                ),
                (
                    "UPDATE broker_acl_principals SET enabled = 0",
                    "principal_disabled",
                ),
                (
                    "UPDATE broker_acl_principals SET account_id = 'account-bob'",
                    "principal_account_mismatch",
                ),
                (
                    "UPDATE schema_metadata SET database_generation = 'database-generation-beta'",
                    "database_generation_mismatch",
                ),
                (
                    "UPDATE repositories SET generation = 8",
                    "repository_generation_mismatch",
                ),
                (
                    "UPDATE repositories SET canonical_root = '/srv/repositories/beta'",
                    "repository_root_mismatch",
                ),
                (
                    "UPDATE repository_installations SET startup_fenced = 1",
                    "repository_installation_inactive",
                ),
            ):
                connection = sqlite3.connect(database)
                connection.execute(
                    "UPDATE broker_repository_enrollments "
                    "SET account_id = ?, enabled = 1, issued_at = ?, "
                    "valid_until_epoch = ?",
                    (account_id, issued_at, now + 600),
                )
                connection.execute(
                    "UPDATE broker_acl_principals SET account_id = ?, enabled = 1",
                    (account_id,),
                )
                connection.execute(
                    "UPDATE schema_metadata SET database_generation = ?",
                    (database_generation,),
                )
                connection.execute(
                    "UPDATE repositories SET canonical_root = ?, generation = 7, state = 'active'",
                    (canonical_root,),
                )
                connection.execute(
                    "UPDATE repository_installations "
                    "SET status = 'installed', startup_fenced = 0"
                )
                connection.execute(sql)
                connection.commit()
                connection.close()
                rejected = INSTALLER.profile_database_enrollment_check(
                    profile_path=profile,
                    database_path=database,
                    now_epoch=now,
                )
                expect(
                    rejected["ok"] is False
                    and expected_reason
                    in {issue["reason"] for issue in rejected["issues"]},
                    f"guard missed {expected_reason}: {rejected}",
                )

            connection = sqlite3.connect(database)
            connection.execute(
                "UPDATE broker_repository_enrollments "
                "SET account_id = ?, enabled = 1, issued_at = ?, "
                "valid_until_epoch = ?",
                (account_id, issued_at, now + 600),
            )
            connection.execute(
                "UPDATE broker_acl_principals SET account_id = ?, enabled = 1",
                (account_id,),
            )
            connection.execute(
                "UPDATE schema_metadata SET database_generation = ?",
                (database_generation,),
            )
            connection.execute(
                "UPDATE repositories SET canonical_root = ?, generation = 7, state = 'active'",
                (canonical_root,),
            )
            connection.execute(
                "UPDATE repository_installations "
                "SET status = 'installed', startup_fenced = 0"
            )
            connection.commit()
            connection.close()
            write_profile(enabled=False)
            reverse_drift = INSTALLER.profile_database_enrollment_check(
                profile_path=profile,
                database_path=database,
                now_epoch=now,
            )
            expect(
                reverse_drift["ok"] is False
                and "profile_enrollment_missing"
                in {issue["reason"] for issue in reverse_drift["issues"]},
                "an enabled current database enrollment absent from the current "
                "profile did not block restart",
            )
            profile.unlink()
            absent_profile = INSTALLER.profile_database_enrollment_check(
                profile_path=profile,
                database_path=database,
                now_epoch=now,
            )
            expect(
                absent_profile["ok"] is False
                and "profile_enrollment_missing"
                in {issue["reason"] for issue in absent_profile["issues"]},
                "a current database enrollment with no protected profile did not "
                "block restart",
            )

            connection = sqlite3.connect(database)
            connection.execute(
                "UPDATE broker_repository_enrollments SET enabled = 0"
            )
            connection.commit()
            connection.close()
            write_profile(enabled=False)
            inactive = INSTALLER.profile_database_enrollment_check(
                profile_path=profile,
                database_path=database,
                now_epoch=now,
            )
            expect(
                inactive["ok"] is True
                and inactive["status"] == "no_current_profile_enrollments"
                and inactive["ignored_inactive_profile_enrollments"] == 1,
                "intentionally disabled profile/database entries caused a false "
                f"positive: {inactive}",
            )

            write_profile(expires_at=now)
            connection = sqlite3.connect(database)
            connection.execute(
                "UPDATE broker_repository_enrollments "
                "SET enabled = 1, valid_until_epoch = ?",
                (now,),
            )
            connection.commit()
            connection.close()
            expired = INSTALLER.profile_database_enrollment_check(
                profile_path=profile,
                database_path=database,
                now_epoch=now,
            )
            expect(
                expired["ok"] is True
                and expired["status"] == "no_current_profile_enrollments"
                and expired["ignored_inactive_profile_enrollments"] == 1,
                "intentionally expired profile/database entries caused a false "
                f"positive: {expired}",
            )

            drift_result = {
                "ok": False,
                "code": INSTALLER.PROFILE_DATABASE_ENROLLMENT_DRIFT,
                "issues": [
                    {"reason": "repository_generation_mismatch"},
                    {"reason": "enrollment_missing"},
                ],
            }
            with (
                mock.patch.object(INSTALLER, "validate_broker_unit_source"),
                mock.patch.object(
                    INSTALLER,
                    "profile_database_enrollment_check",
                    return_value=drift_result,
                ),
            ):
                plan = INSTALLER.desired_plan([pwd.getpwuid(os.geteuid()).pw_name])
            expect(
                plan["restart_allowed"] is False
                and INSTALLER.PROFILE_DATABASE_ENROLLMENT_DRIFT in plan["next_step"]
                and "Do not restart" in plan["next_step"],
                "plan still recommended restart after enrollment drift",
            )
            generation_step = "exact offline profile-generation reconciliation"
            backfill_step = "explicit offline profile-enrollment backfill"
            verify_step = "rerun plan and verify"
            expect(
                generation_step in plan["next_step"]
                and backfill_step in plan["next_step"]
                and verify_step in plan["next_step"]
                and plan["next_step"].index(generation_step)
                < plan["next_step"].index(backfill_step)
                < plan["next_step"].index(verify_step),
                "plan sent a generation mismatch directly to incapable enrollment backfill",
            )
            expect(
                "start devcoordinator-broker.service"
                not in plan["migration"]["steps"]
                and any(
                    "stop before service restart" in step
                    for step in plan["migration"]["steps"]
                ),
                "migration steps bypassed the restart enrollment precondition",
            )
            blocked_migration_step = next(
                step
                for step in plan["migration"]["steps"]
                if "stop before service restart" in step
            )
            expect(
                generation_step in blocked_migration_step
                and blocked_migration_step.index(generation_step)
                < blocked_migration_step.index(backfill_step),
                "migration sent a generation mismatch directly to incapable backfill",
            )

            verify_dropin = root / "80-enrolled-home-write-paths.conf"
            verify_dropin.write_bytes(
                INSTALLER.render_enrolled_home_dropin([Path("/home/alice")])
            )
            verify_dropin.chmod(0o644)
            verify_plan = {
                "restart_precondition": drift_result,
                "system_files": [{"home_write_paths": ["/home/alice"]}],
                "clients": [],
            }
            with (
                mock.patch.object(INSTALLER, "desired_plan", return_value=verify_plan),
                mock.patch.object(INSTALLER, "SYSTEM_FILES", {}),
                mock.patch.object(INSTALLER, "ENROLLED_HOME_DROPIN", verify_dropin),
                mock.patch.object(
                    INSTALLER,
                    "CLIENT_PROFILE_PATH",
                    root / "absent-profile" / "client-profiles.json",
                ),
                mock.patch.object(
                    INSTALLER, "runtime_dependency_evidence", return_value={"ok": True}
                ),
                mock.patch.object(
                    INSTALLER, "runtime_dependency_failure", return_value=None
                ),
                mock.patch.object(
                    INSTALLER.subprocess,
                    "run",
                    return_value=INSTALLER.subprocess.CompletedProcess(
                        args=[], returncode=0, stdout="", stderr=""
                    ),
                ),
                mock.patch.object(
                    INSTALLER, "inspect_legacy_docker_dropin", return_value=None
                ),
                mock.patch.object(INSTALLER.grp, "getgrnam", side_effect=KeyError),
            ):
                verified = INSTALLER.verify_install(
                    [pwd.getpwuid(os.geteuid()).pw_name]
                )
            expect(
                INSTALLER.PROFILE_DATABASE_ENROLLMENT_DRIFT
                in verified["failure_codes"]
                and any(
                    INSTALLER.PROFILE_DATABASE_ENROLLMENT_DRIFT in failure
                    for failure in verified["failures"]
                ),
                "verify omitted the exact enrollment-drift failure code",
            )

            transaction = root / "must-not-exist"
            with (
                mock.patch.object(INSTALLER.os, "geteuid", return_value=0),
                mock.patch.object(INSTALLER, "validate_broker_unit_source"),
                mock.patch.object(
                    INSTALLER,
                    "require_profile_database_enrollment_consistency",
                    side_effect=INSTALLER.ProfileDatabaseEnrollmentDrift(
                        INSTALLER.PROFILE_DATABASE_ENROLLMENT_DRIFT
                    ),
                ),
            ):
                must_reject(
                    lambda: INSTALLER.apply_install(
                        [pwd.getpwuid(os.geteuid()).pw_name],
                        str(transaction),
                        False,
                    ),
                    "apply enrollment drift precondition",
                )
            expect(
                not transaction.exists(),
                "apply mutated the host transaction boundary before rejecting enrollment drift",
            )
        finally:
            INSTALLER.SYSTEM_OWNER_UID = original_owner_uid
            INSTALLER.SYSTEM_OWNER_GID = original_owner_gid


def main() -> int:
    user = pwd.getpwuid(os.geteuid()).pw_name
    plan = INSTALLER.desired_plan([user])
    expect(
        plan["authority"]["database"] == "/var/lib/devcoordinator/coordinator.sqlite3",
        "plan selected the wrong authority database",
    )
    expect(
        plan["authority"]["socket"] == "/run/devcoordinator/broker.sock",
        "plan selected the wrong broker socket",
    )
    expect(plan["starts_service"] is False, "installer plan unexpectedly starts the service")
    expect(
        plan["requires_service_restart_for_sandbox_changes"] is True,
        "installer plan hides the mount-namespace restart requirement",
    )
    expect(
        plan["restart_allowed"] is plan["restart_precondition"]["ok"],
        "installer plan restart recommendation bypasses its enrollment precondition",
    )
    expect(
        plan["migration"]["legacy_authorities_preserved"] is True,
        "installer plan does not preserve legacy authority",
    )
    expect(
        any("owning non-root UID" in step for step in plan["migration"]["steps"]),
        "installer plan omits exact listener ownership",
    )
    expect(
        any("90-docker-config.conf" in step for step in plan["migration"]["steps"]),
        "installer plan omits the exact legacy drop-in migration",
    )
    expect(
        plan["clients"][0]["journal"]
        == f"/var/lib/devcoordinator-clients/{os.geteuid()}",
        "installer plan selected the wrong client journal",
    )
    expect(
        len(plan["clients"][0]["skill_roots"]) == 2,
        "installer plan omitted an agent skill root",
    )
    expect(
        plan["system_files"][-1]["source"]
        == INSTALLER.ENROLLED_HOME_DROPIN_SOURCE
        and plan["system_files"][-1]["destination"]
        == str(INSTALLER.ENROLLED_HOME_DROPIN)
        and plan["system_files"][-1]["home_write_paths"]
        == [pwd.getpwuid(os.geteuid()).pw_dir],
        "installer plan does not bind the generated drop-in to the complete client set",
    )
    assert plan["runtime_requirements"]["python"] == "/usr/bin/python3"
    assert plan["runtime_requirements"]["pyyaml"] == "6.x"
    assert (
        plan["runtime_requirements"]["docker_compose"]
        == "stable >=2.17,<3 or >=5,<6"
    )
    assert "config --format json" in plan["runtime_requirements"][
        "compose_capabilities"
    ]
    assert (
        plan["runtime_requirements"]["evidence_contract"]
        == "devcoordinator-broker-runtime-v1"
    )

    unit = (INSTALLER.ROOT / "deploy/devcoordinator-broker.service").read_text(
        encoding="utf-8"
    )
    expect("User=root" in unit, "broker unit does not use the system authority")
    expect("Group=devcoordinator-clients" in unit, "broker unit has the wrong access group")
    expect("DEVCOORDINATOR_AUTHORITY=service" in unit, "broker unit omits service authority")
    expect(
        unit.splitlines().count(
            "Environment=DOCKER_CONFIG=/var/lib/devcoordinator/docker"
        )
        == 1,
        "broker unit does not pin exactly one canonical Docker configuration",
    )
    expect(
        "/var/lib/devcoordinator/coordinator.sqlite3" in unit,
        "broker unit selected the wrong database",
    )
    expect("/run/devcoordinator/broker.sock" in unit, "broker unit selected the wrong socket")
    expect("%h" not in unit, "system unit uses manager-home expansion")
    for key, directive in INSTALLER.BROKER_UNIT_REQUIRED_SANDBOX.items():
        expect(
            [line for line in unit.splitlines() if line.startswith(f"{key}=")]
            == [directive],
            f"broker unit does not pin the exact {key} sandbox directive",
        )
    expect(
        not any(
            line.startswith(("AmbientCapabilities=", "CapabilityBoundingSet="))
            for line in unit.splitlines()
        ),
        "broker unit changes the manager capability ceiling or ambient set",
    )
    for directive in (
        "KillMode=mixed",
        "KillSignal=SIGTERM",
        "RestartKillSignal=SIGTERM",
        "FinalKillSignal=SIGKILL",
        "SendSIGKILL=yes",
        "SurviveFinalKillSignal=no",
        "TimeoutStopSec=65min",
        "TimeoutStopFailureMode=terminate",
    ):
        expect(
            unit.splitlines().count(directive) == 1,
            f"broker unit does not contain exactly one {directive}",
        )
    expect(
        not any(
            line.startswith(("ExecStop=", "ExecStopPost="))
            for line in unit.splitlines()
        ),
        "broker unit contains an external stop hook",
    )
    expect("KillMode=control-group" not in unit, "broker unit retained the old kill mode")
    expect("TimeoutStopSec=15" not in unit, "broker unit retained the old stop timeout")
    assert "ExecStartPre=/usr/bin/python3 -I " in unit
    assert "validate_runtime_dependencies.py" in unit
    assert "ExecStart=/usr/bin/python3 -I " in unit

    tmpfiles = (INSTALLER.ROOT / "deploy/devcoordinator.tmpfiles.conf").read_text(
        encoding="utf-8"
    )
    expect(
        "d /var/lib/devcoordinator 0700 root root" in tmpfiles,
        "tmpfiles omits the private authority directory",
    )
    expect(
        "d /var/lib/devcoordinator-clients 0711 root root" in tmpfiles,
        "tmpfiles omits the client journal parent",
    )
    expect(
        "d /etc/devcoordinator 0750 root devcoordinator-clients" in tmpfiles,
        "tmpfiles omits the shared profile directory",
    )

    installer_source = SCRIPT.read_text(encoding="utf-8")
    expect('f"g:{ACCESS_GROUP}:rX"' in installer_source, "installer omits source ACL access")
    expect(
        'f"d:g:{ACCESS_GROUP}:rX"' in installer_source,
        "installer omits default source ACL access",
    )
    expect('f"--restore={backup}"' in installer_source, "installer omits ACL rollback")
    expect(
        'stat.S_IMODE(metadata.st_mode) != 0o640' in installer_source,
        "installer omits profile mode verification",
    )
    expect("shutil.rmtree" not in installer_source, "installer can remove a directory tree")
    expect(".rmdir(" not in installer_source, "installer can remove a drop-in directory")
    exercise_broker_unit_source_controls()
    exercise_enrolled_home_dropin_transaction()
    exercise_legacy_docker_dropin_transaction()
    exercise_legacy_docker_dropin_controls()
    success_evidence = {
        "ok": True,
        "contract": "devcoordinator-broker-runtime-v1",
        "requirements": {
            "pyyaml": "6.x",
            "docker_compose": "stable >=2.17,<3 or >=5,<6",
        },
        "pyyaml": {"detected_major": "6"},
        "docker_compose": {
            "docker_cli": "/usr/bin/docker",
            "version": "2.17.0-desktop.1",
            "config_json": True,
            "multiple_explicit_env_files": True,
            "second_env_file_override": True,
            "implicit_dotenv_suppressed": True,
        },
    }
    with (
        mock.patch.object(
            INSTALLER.subprocess,
            "run",
            return_value=INSTALLER.subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(success_evidence),
                stderr="",
            ),
        ) as run,
        mock.patch.dict(
            INSTALLER.os.environ,
            {
                "CODEX_DOCKER_CLI": "/caller-controlled/docker",
                "DOCKER_CONFIG": "/caller-controlled/config",
            },
        ),
    ):
        assert INSTALLER.runtime_dependency_failure() is None
        assert run.call_args.args[0] == [
            "/usr/bin/python3",
            "-I",
            str(INSTALLER.RUNTIME_DEPENDENCY_CHECK),
        ]
        assert run.call_args.kwargs["env"] == {
            "DEVCOORDINATOR_AUTHORITY": "service",
            "DOCKER_CONFIG": "/var/lib/devcoordinator/docker",
            "HOME": "/root",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        }
        assert run.call_args.kwargs["timeout"] == 35
    failure_cases = (
        (
            {"ok": False, "code": "pyyaml_missing"},
            "PyYAML 6.x",
        ),
        (
            {"ok": False, "code": "compose_version_prerelease"},
            "stable >=2.17,<3 or >=5,<6",
        ),
        (
            {"ok": False, "code": "compose_implicit_dotenv_not_suppressed"},
            "implicit .env suppression",
        ),
    )
    for evidence, expected in failure_cases:
        with mock.patch.object(
            INSTALLER.subprocess,
            "run",
            return_value=INSTALLER.subprocess.CompletedProcess(
                args=[],
                returncode=1,
                stdout=json.dumps(evidence),
                stderr="preflight failed",
            ),
        ):
            assert expected in str(INSTALLER.runtime_dependency_failure())
    invalid_success = dict(success_evidence)
    invalid_success["docker_compose"] = {
        **success_evidence["docker_compose"],
        "config_json": False,
    }
    with mock.patch.object(
        INSTALLER.subprocess,
        "run",
        return_value=INSTALLER.subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(invalid_success),
            stderr="",
        ),
    ):
        assert "invalid success evidence" in str(
            INSTALLER.runtime_dependency_failure()
        )
    exercise_profile_database_enrollment_guard()
    exercise_source_acl_transaction()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
