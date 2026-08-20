#!/usr/bin/env python3
"""Deterministic plan and deployment-contract tests for system installation."""

from __future__ import annotations

import importlib.util
import json
import os
from contextlib import ExitStack
from pathlib import Path
import pwd
import shutil
import sqlite3
import stat
import sys
import tempfile
from types import SimpleNamespace
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
        writable = INSTALLER.BROKER_UNIT_REQUIRED_SANDBOX["ReadWritePaths"]
        check_rejected(
            source.replace(
                writable,
                f"{writable} /etc",
            ),
            "extra writable path",
        )
        check_rejected(
            source.replace(
                writable,
                f"ReadWritePaths=/home {INSTALLER.BASE_READ_WRITE_PATHS}",
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
        check_rejected(
            source.replace(f"{writable}\n", "", 1) + f"\n{writable}\n",
            "writable path directive outside Service",
        )


def exercise_worker_runner_script_guard() -> None:
    with tempfile.TemporaryDirectory(prefix="devcoordinator-runner-script-") as raw:
        script = Path(raw).resolve(strict=True) / "dev_coordinator.py"
        script.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        script.chmod(0o755)
        expect(
            INSTALLER.worker_runner_script_failure(script) is None,
            "trusted worker runner script was rejected",
        )
        script.chmod(0o775)
        expect(
            "group/world writable"
            in str(INSTALLER.worker_runner_script_failure(script)),
            "installer verifier missed a group-writable worker runner script",
        )
        script.unlink()
        script.symlink_to("target.py")
        expect(
            "regular non-symlink"
            in str(INSTALLER.worker_runner_script_failure(script)),
            "installer verifier accepted a symlink worker runner script",
        )


def exercise_systemd_unit_activity_states() -> None:
    classifications = {
        "inactive": False,
        "active": True,
        "failed": True,
        "activating": True,
        "deactivating": True,
        "reloading": True,
        "maintenance": True,
    }
    for state, expected in classifications.items():
        with mock.patch.object(
            INSTALLER,
            "_systemd_unit_property",
            return_value=state,
        ) as property_read:
            actual = INSTALLER._systemd_unit_active()
        expect(
            actual is expected,
            f"systemd ActiveState={state!r} was misclassified as {actual!r}",
        )
        expect(
            property_read.call_args_list == [mock.call("ActiveState")],
            f"systemd ActiveState={state!r} used an unexpected property read",
        )

    with mock.patch.object(
        INSTALLER,
        "_systemd_unit_property",
        return_value="unknown-future-state",
    ):
        must_reject(
            INSTALLER._systemd_unit_active,
            "unknown systemd active state",
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
                "group_members_added": ["legacy-client"],
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
            with mock.patch.object(
                INSTALLER, "_systemd_unit_active", return_value=False
            ):
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
                calls
                == [
                    ("gpasswd", "-d", "legacy-client", "devcoordinator-clients"),
                    ("systemctl", "daemon-reload"),
                ],
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


def _activation_transaction(
    root: Path,
    *,
    clients: tuple[str, ...] = ("agent-alpha", "agent-beta"),
    status: str = "applied",
    repo_root: str | None = None,
    restart_precondition: dict[str, object] | None = None,
) -> tuple[Path, dict[str, object]]:
    transaction = root / "activation-transaction"
    private_directory(transaction)
    precondition = (
        {
            "ok": True,
            "code": "profile_database_enrollment_consistent",
            "profile_enrollments": 2,
            "database_enrollments": 2,
        }
        if restart_precondition is None
        else restart_precondition
    )
    journal: dict[str, object] = {
        "version": 1,
        "status": status,
        "repo_root": str(INSTALLER.ROOT) if repo_root is None else repo_root,
        "system_files": [],
        "link_transactions": [],
        "skill_link_evidence": [
            {
                "user": name,
                "uid": 4100 + index,
                "verification": {"ok": True},
            }
            for index, name in enumerate(clients)
        ],
        "skill_root_directories": [],
        "group_members_added": [],
        "client_journals": [],
        "legacy_docker_dropin": None,
        "legacy_docker_dropin_removed": False,
        "restart_precondition": precondition,
        "starts_service": False,
        "requires_service_restart_for_sandbox_changes": True,
    }
    INSTALLER.atomic_json(transaction / INSTALLER.JOURNAL_NAME, journal)
    return transaction, journal


def _activation_patches(
    *,
    verify_result: dict[str, object],
    current_precondition: dict[str, object],
    state: dict[str, bool],
    calls: list[tuple[str, ...]],
    wait_calls: list[int],
    wait_error: BaseException | None = None,
    client_readiness: list[dict[str, object]] | BaseException | None = None,
    journal_path: Path | None = None,
    verification_calls: list[tuple[str, object]] | None = None,
    client_readiness_calls: list[list[str]] | None = None,
    authority_contract: dict[str, object] | BaseException | None = None,
) -> tuple[object, ...]:
    def run(*arguments: str) -> None:
        call = tuple(arguments)
        calls.append(call)
        if len(call) >= 2 and call[0] == "systemctl":
            if call[1] in {"enable", "start"} and journal_path is not None:
                persisted = json.loads(journal_path.read_text(encoding="utf-8"))
                activation = persisted.get("activation")
                if (
                    not isinstance(activation, dict)
                    or activation.get("phase") != "starting"
                ):
                    raise AssertionError(
                        "broker lifecycle ran before the activation journal was durable"
                    )
            if call[1] == "enable":
                state["enabled"] = True
            elif call[1] == "disable":
                state["enabled"] = False
            elif call[1] == "start":
                state["active"] = True
            elif call[1] == "stop":
                state["active"] = False

    def wait(wait_seconds: int) -> None:
        wait_calls.append(wait_seconds)
        if wait_error is not None:
            raise wait_error
        if not state["active"]:
            raise AssertionError("readiness wait ran before the broker was started")

    def verify(names: list[str]) -> dict[str, object]:
        if verification_calls is not None:
            verification_calls.append(("install", list(names)))
        return verify_result

    def current() -> dict[str, object]:
        if verification_calls is not None:
            verification_calls.append(("restart_precondition", None))
        return current_precondition

    def records(names: list[str]) -> list[tuple[SimpleNamespace, Path]]:
        return [
            (
                SimpleNamespace(
                    pw_name=name,
                    pw_uid=4100 + index,
                    pw_gid=5100 + index,
                ),
                Path(f"/home/{name}"),
            )
            for index, name in enumerate(names)
        ]

    def verify_client_readiness(names: list[str]) -> list[dict[str, object]]:
        expected = ["agent-alpha", "agent-beta"]
        if names != expected:
            raise AssertionError(f"client readiness received the wrong client set: {names}")
        if client_readiness_calls is not None:
            client_readiness_calls.append(list(names))
        if isinstance(client_readiness, BaseException):
            raise client_readiness
        if client_readiness is not None:
            return client_readiness
        return [
            {
                "user": name,
                "uid": 4100 + index,
                "canary": "broker_profile_inventory",
            }
            for index, name in enumerate(names)
        ]

    def verify_authority_contract() -> dict[str, object]:
        if isinstance(authority_contract, BaseException):
            raise authority_contract
        if authority_contract is not None:
            return authority_contract
        return {
            "ok": True,
            "code": "activation_authority_contract_ready",
            "target_broker_schema": 13,
            "authority_database_schema": 13,
            "checked_profile_clients": [4100, 4101],
            "checked_profile_repositories": 2,
            "issues": [],
        }

    return (
        mock.patch.object(INSTALLER.os, "geteuid", return_value=0),
        mock.patch.object(INSTALLER, "client_records", side_effect=records),
        mock.patch.object(INSTALLER, "verify_install", side_effect=verify),
        mock.patch.object(
            INSTALLER,
            "require_profile_database_enrollment_consistency",
            side_effect=current,
        ),
        mock.patch.object(
            INSTALLER,
            "activation_authority_contract_check",
            side_effect=verify_authority_contract,
        ),
        mock.patch.object(
            INSTALLER,
            "_systemd_unit_active",
            side_effect=lambda: state["active"],
        ),
        mock.patch.object(
            INSTALLER,
            "_systemd_unit_enabled",
            side_effect=lambda: state["enabled"],
        ),
        mock.patch.object(
            INSTALLER,
            "_broker_socket_ready",
            side_effect=lambda: state["active"],
        ),
        mock.patch.object(INSTALLER, "_wait_for_broker_ready", side_effect=wait),
        mock.patch.object(
            INSTALLER,
            "_verify_broker_client_readiness",
            side_effect=verify_client_readiness,
        ),
        mock.patch.object(
            INSTALLER,
            "_broker_start_failure_evidence",
            return_value={
                "captured_at_epoch": 1,
                "unit": {"ActiveState": "failed"},
                "property_errors": {},
                "journal": {"returncode": 0, "tail": "fixture", "stderr": ""},
            },
        ),
        mock.patch.object(INSTALLER, "command", side_effect=lambda name: name),
        mock.patch.object(INSTALLER, "run", side_effect=run),
    )


def _activation_profile_document(*, include_second_owner: bool = True) -> dict[str, object]:
    repositories: dict[str, list[dict[str, object]]] = {}
    for index, uid in enumerate((4100, 4101)):
        repository: dict[str, object] = {
            "canonical_root": f"/home/agent-{index}/project",
            "repo_id": f"repository-{index}",
            "generation": index,
            "owner_uid": uid,
            "servers": {},
            "containers": {},
            "compose_definition_id": None,
            "compose_container_ids": [],
            "compose_run_once_services": {},
            "ephemeral_templates": {},
            "ephemeral_image_prefetch_templates": [],
            "ephemeral_secret_policies": {},
            "account_id": f"account-{uid}",
            "enabled": True,
            "issued_at": "2026-07-29T00:00:00Z",
            "valid_until_epoch": 4_102_444_800,
        }
        if uid == 4101 and not include_second_owner:
            repository.pop("owner_uid")
        repositories[str(uid)] = [repository]
    return {
        "version": 1,
        "service": {
            "socket": "/run/devcoordinator-authority.sock",
            "uid": 0,
            "gid": 0,
            "mode": "0666",
            "database_generation": "activation-database-generation",
        },
        "clients": {
            str(uid): {
                "account_id": f"account-{uid}",
                "issued_at": "2026-07-29T00:00:00Z",
                "valid_until_epoch": 4_102_444_800,
                "repositories": repositories[str(uid)],
            }
            for uid in (4100, 4101)
        },
    }


def exercise_activation_authority_contract_guard() -> None:
    original_owner_uid = INSTALLER.SYSTEM_OWNER_UID
    original_owner_gid = INSTALLER.SYSTEM_OWNER_GID
    with tempfile.TemporaryDirectory(prefix="devcoordinator-activation-contract-") as raw:
        root = Path(raw).resolve(strict=True)
        database = root / "coordinator.sqlite3"
        profile = root / "client-profiles.json"
        try:
            INSTALLER.SYSTEM_OWNER_UID = os.getuid()
            INSTALLER.SYSTEM_OWNER_GID = os.getgid()
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    """
                    CREATE TABLE schema_metadata(
                        singleton INTEGER PRIMARY KEY,
                        schema_version INTEGER NOT NULL
                    )
                    """
                )
                connection.execute("INSERT INTO schema_metadata VALUES(1, 13)")
                connection.commit()
            finally:
                connection.close()
            database.chmod(0o600)
            profile.write_text(
                json.dumps(_activation_profile_document(), sort_keys=True),
                encoding="utf-8",
            )
            profile.chmod(0o644)

            ready = INSTALLER.activation_authority_contract_check(
                database_path=database,
                profile_path=profile,
            )
            expect(
                ready.get("ok") is True
                and ready.get("target_broker_schema") == 13
                and ready.get("authority_database_schema") == 13
                and ready.get("checked_profile_clients") == [4100, 4101]
                and ready.get("checked_profile_repositories") == 2,
                f"compatible schema/profile activation contract was rejected: {ready}",
            )

            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "UPDATE schema_metadata SET schema_version = 12 WHERE singleton = 1"
                )
                connection.commit()
            finally:
                connection.close()
            before_profile = profile.read_bytes()
            try:
                INSTALLER.activation_authority_contract_check(
                    database_path=database,
                    profile_path=profile,
                )
            except INSTALLER.AuthoritySchemaCutoverRequired as error:
                mismatch = error.evidence
                expect(
                    error.code == INSTALLER.AUTHORITY_SCHEMA_CUTOVER_REQUIRED
                    and error.classification == "cutover_required"
                    and "sealed offline repository-owner authority migration"
                    in error.action_required
                    and mismatch.get("authority_database_schema") == 12
                    and mismatch.get("target_broker_schema") == 13
                    and mismatch.get("checked_profile_clients") == [4100, 4101]
                    and any(
                        issue.get("reason") == "authority_schema_mismatch"
                        for issue in mismatch.get("issues", [])
                    ),
                    f"schema-12/target-13 refusal was not typed and actionable: {mismatch}",
                )
            else:
                raise AssertionError("activation accepted a schema-12 authority for schema 13")
            expect(
                profile.read_bytes() == before_profile,
                "schema activation preflight mutated the protected profile",
            )

            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "UPDATE schema_metadata SET schema_version = 13 WHERE singleton = 1"
                )
                connection.commit()
            finally:
                connection.close()
            incomplete_profile = _activation_profile_document(
                include_second_owner=False
            )
            profile.write_text(json.dumps(incomplete_profile, sort_keys=True), encoding="utf-8")
            profile.chmod(0o644)
            generation, repositories, _ignored, profile_issues = (
                INSTALLER._current_profile_repository_enrollments(
                    incomplete_profile,
                    now_epoch=1_800_000_000,
                )
            )
            expect(
                generation == "activation-database-generation"
                and len(repositories) == 1
                and any(
                    issue.get("reason") == "profile_repository_fields_invalid"
                    and issue.get("uid") == 4101
                    for issue in profile_issues
                ),
                "installer verifier did not reject the incomplete repository contract",
            )
            try:
                INSTALLER.activation_authority_contract_check(
                    database_path=database,
                    profile_path=profile,
                )
            except INSTALLER.AuthoritySchemaCutoverRequired as error:
                invalid_profile = error.evidence
                expect(
                    invalid_profile.get("checked_profile_clients") == []
                    and any(
                        issue.get("reason") == "profile_target_contract_invalid"
                        and issue.get("uid") == 4100
                        for issue in invalid_profile.get("issues", [])
                    )
                    and any(
                        issue.get("reason")
                        == "profile_repository_owner_uid_missing"
                        and issue.get("uid") == 4101
                        and issue.get("repository_indexes") == [0]
                        for issue in invalid_profile.get("issues", [])
                    ),
                    "target parser did not reject every profile entry missing owner_uid",
                )
            else:
                raise AssertionError("activation accepted a profile without owner_uid")

            transaction, journal = _activation_transaction(root)
            precondition = journal["restart_precondition"]
            assert isinstance(precondition, dict)
            verify_result: dict[str, object] = {
                "ok": True,
                "restart_precondition": precondition,
                "failures": [],
            }
            state = {"active": False, "enabled": False}
            calls: list[tuple[str, ...]] = []
            waits: list[int] = []
            before_journal = (transaction / INSTALLER.JOURNAL_NAME).read_bytes()
            cutover_error = INSTALLER.AuthoritySchemaCutoverRequired(
                {
                    "ok": False,
                    "code": INSTALLER.AUTHORITY_SCHEMA_CUTOVER_REQUIRED,
                    "target_broker_schema": 13,
                    "authority_database_schema": 12,
                    "issues": [{"reason": "authority_schema_mismatch"}],
                }
            )
            patches = _activation_patches(
                verify_result=verify_result,
                current_precondition=precondition,
                state=state,
                calls=calls,
                wait_calls=waits,
                authority_contract=cutover_error,
            )
            with ExitStack() as stack:
                for patch in patches:
                    stack.enter_context(patch)
                try:
                    INSTALLER.activate_install(
                        ["agent-alpha", "agent-beta"],
                        transaction,
                        "1170c4a3-44aa-4331-8ca2-f178db70a1be",
                        5,
                    )
                except INSTALLER.AuthoritySchemaCutoverRequired as error:
                    expect(
                        error.code == INSTALLER.AUTHORITY_SCHEMA_CUTOVER_REQUIRED,
                        "activate lost the typed cutover refusal",
                    )
                else:
                    raise AssertionError("activate ignored its authority contract refusal")
            expect(
                calls == []
                and waits == []
                and state == {"active": False, "enabled": False}
                and (transaction / INSTALLER.JOURNAL_NAME).read_bytes() == before_journal
                and "activation" not in json.loads(before_journal),
                "cutover-required activation touched systemd or journaled a start attempt",
            )
        finally:
            INSTALLER.SYSTEM_OWNER_UID = original_owner_uid
            INSTALLER.SYSTEM_OWNER_GID = original_owner_gid


def exercise_installer_activation_transaction() -> None:
    operation_id = "52c36442-f8fb-4613-94a4-c54eac6eab70"
    clients = ["agent-alpha", "agent-beta"]
    parsed = INSTALLER.parse_args(
        [
            "activate",
            "--client-user",
            clients[0],
            "--client-user",
            clients[1],
            "--transaction-dir",
            "/var/lib/devcoordinator-installs/fixture",
            "--operation-id",
            operation_id,
            "--wait-seconds",
            "7",
        ]
    )
    expect(
        parsed.action == "activate"
        and parsed.client_user == clients
        and parsed.transaction_dir
        == "/var/lib/devcoordinator-installs/fixture"
        and parsed.operation_id == operation_id
        and parsed.wait_seconds == 7,
        "activate CLI did not preserve exact client/transaction/operation/readiness inputs",
    )
    original_owner_uid = INSTALLER.SYSTEM_OWNER_UID
    original_owner_gid = INSTALLER.SYSTEM_OWNER_GID
    with tempfile.TemporaryDirectory(prefix="devcoordinator-activate-") as raw:
        root = Path(raw).resolve(strict=True)
        try:
            INSTALLER.SYSTEM_OWNER_UID = os.getuid()
            INSTALLER.SYSTEM_OWNER_GID = os.getgid()
            transaction, journal = _activation_transaction(root)
            precondition = journal["restart_precondition"]
            assert isinstance(precondition, dict)
            verify_result: dict[str, object] = {
                "ok": True,
                "restart_precondition": precondition,
                "failures": [],
            }
            state = {"active": False, "enabled": False}
            calls: list[tuple[str, ...]] = []
            wait_calls: list[int] = []
            verification_calls: list[tuple[str, object]] = []
            client_readiness_calls: list[list[str]] = []
            original_atomic_json = INSTALLER.atomic_json
            snapshots: list[dict[str, object]] = []

            def persist(path: Path, value: dict[str, object]) -> None:
                snapshots.append(json.loads(json.dumps(value)))
                original_atomic_json(path, value)

            patches = _activation_patches(
                verify_result=verify_result,
                current_precondition=precondition,
                state=state,
                calls=calls,
                wait_calls=wait_calls,
                journal_path=transaction / INSTALLER.JOURNAL_NAME,
                verification_calls=verification_calls,
                client_readiness_calls=client_readiness_calls,
            )
            with ExitStack() as stack:
                for patch in patches:
                    stack.enter_context(patch)
                stack.enter_context(
                    mock.patch.object(INSTALLER, "atomic_json", side_effect=persist)
                )
                result = INSTALLER.activate_install(
                    clients,
                    transaction,
                    operation_id,
                    7,
                )

            activation = result.get("activation")
            expect(
                result.get("status") == "activated" and isinstance(activation, dict),
                f"successful activation was not durable: {result}",
            )
            assert isinstance(activation, dict)
            expect(
                activation.get("operation_id") == operation_id
                and activation.get("clients") == clients
                and activation.get("initial_active") is False
                and activation.get("initial_enabled") is False
                and activation.get("phase") == "ready",
                f"activation journal omitted exact operation/client/baseline evidence: {activation}",
            )
            expect(
                activation.get("client_readiness")
                == [
                    {
                        "user": name,
                        "uid": 4100 + index,
                        "canary": "broker_profile_inventory",
                    }
                    for index, name in enumerate(clients)
                ],
                f"activation omitted the broker client-readiness canary: {activation}",
            )
            expect(
                wait_calls == [7],
                f"activation did not use its exact bounded readiness interval: {wait_calls}",
            )
            expect(
                verification_calls
                == [("install", clients), ("restart_precondition", None)]
                and client_readiness_calls == [clients],
                "activation skipped current install, enrollment, or client-readiness verification",
            )
            lifecycle = [call[1] for call in calls if call and call[0] == "systemctl"]
            expect(
                lifecycle == ["enable", "start"],
                f"activation did not enable then start from a disabled baseline: {calls}",
            )
            starting = [
                snapshot
                for snapshot in snapshots
                if isinstance(snapshot.get("activation"), dict)
                and snapshot["activation"].get("phase") == "starting"  # type: ignore[union-attr]
            ]
            expect(starting, "activation did not journal starting before lifecycle mutation")
            first_lifecycle_index = next(
                index
                for index, call in enumerate(calls)
                if call and call[0] == "systemctl"
            )
            # The persisted file, rather than an in-memory event ordering claim,
            # is the crash-recovery boundary that must exist before systemd runs.
            persisted = json.loads(
                (transaction / INSTALLER.JOURNAL_NAME).read_text(encoding="utf-8")
            )
            expect(
                first_lifecycle_index == 0
                and persisted["status"] == "activated"
                and persisted["activation"]["phase"] == "ready",
                "activation did not finish from a durable starting journal",
            )

            calls_before_replay = list(calls)
            replay_patches = _activation_patches(
                verify_result=verify_result,
                current_precondition=precondition,
                state=state,
                calls=calls,
                wait_calls=wait_calls,
                verification_calls=verification_calls,
                client_readiness_calls=client_readiness_calls,
            )
            with ExitStack() as stack:
                for patch in replay_patches:
                    stack.enter_context(patch)
                replay = INSTALLER.activate_install(
                    clients,
                    transaction,
                    operation_id,
                    7,
                )
                must_reject(
                    lambda: INSTALLER.activate_install(
                        clients,
                        transaction,
                        "3e48de75-d434-4ae0-8a21-d409264a028d",
                        7,
                    ),
                    "different activation operation replay",
                )
                must_reject(
                    lambda: INSTALLER.activate_install(
                        ["agent-alpha"],
                        transaction,
                        operation_id,
                        7,
                    ),
                    "different activation client replay",
                )
            expect(
                replay.get("status") == "activated"
                and replay.get("activation", {}).get("operation_id") == operation_id,
                f"same-operation activation replay did not converge: {replay}",
            )
            expect(
                calls == calls_before_replay and wait_calls == [7],
                "activation replay changed lifecycle state or repeated startup waiting: "
                f"calls={calls}, before={calls_before_replay}, waits={wait_calls}",
            )
            expect(
                verification_calls
                == [
                    ("install", clients),
                    ("restart_precondition", None),
                    ("install", clients),
                    ("restart_precondition", None),
                ]
                and client_readiness_calls == [clients, clients],
                "same-operation replay skipped current install or client-readiness verification",
            )
        finally:
            INSTALLER.SYSTEM_OWNER_UID = original_owner_uid
            INSTALLER.SYSTEM_OWNER_GID = original_owner_gid


def exercise_installer_activation_refusals() -> None:
    operation_id = "ccb740c1-8c62-44e8-8d1a-544671d07e2a"
    clients = ["agent-alpha", "agent-beta"]
    original_owner_uid = INSTALLER.SYSTEM_OWNER_UID
    original_owner_gid = INSTALLER.SYSTEM_OWNER_GID
    with tempfile.TemporaryDirectory(prefix="devcoordinator-activate-refuse-") as raw:
        root = Path(raw).resolve(strict=True)
        try:
            INSTALLER.SYSTEM_OWNER_UID = os.getuid()
            INSTALLER.SYSTEM_OWNER_GID = os.getgid()
            transaction, journal = _activation_transaction(root)
            precondition = journal["restart_precondition"]
            assert isinstance(precondition, dict)
            verify_result: dict[str, object] = {
                "ok": True,
                "restart_precondition": precondition,
                "failures": [],
            }

            def invoke(
                *,
                names: list[str] = clients,
                active: bool = False,
                verified: dict[str, object] = verify_result,
                current: dict[str, object] = precondition,
            ) -> tuple[list[tuple[str, ...]], list[int]]:
                calls: list[tuple[str, ...]] = []
                waits: list[int] = []
                state = {"active": active, "enabled": True}
                patches = _activation_patches(
                    verify_result=verified,
                    current_precondition=current,
                    state=state,
                    calls=calls,
                    wait_calls=waits,
                )
                with ExitStack() as stack:
                    for patch in patches:
                        stack.enter_context(patch)
                    must_reject(
                        lambda: INSTALLER.activate_install(
                            names,
                            transaction,
                            operation_id,
                            5,
                        ),
                        "installer activation refusal",
                    )
                return calls, waits

            before = (transaction / INSTALLER.JOURNAL_NAME).read_bytes()
            calls, waits = invoke(names=["agent-alpha"])
            expect(
                calls == [] and waits == []
                and (transaction / INSTALLER.JOURNAL_NAME).read_bytes() == before,
                "client-mismatched activation changed the journal or service",
            )

            failing_verify = {
                "ok": False,
                "restart_precondition": precondition,
                "failures": ["installed unit drift"],
            }
            calls, waits = invoke(verified=failing_verify)
            expect(calls == [] and waits == [], "failed install verification reached systemd")

            drifted = {**precondition, "database_enrollments": 1}
            calls, waits = invoke(current=drifted)
            expect(calls == [] and waits == [], "restart-precondition drift reached systemd")

            calls, waits = invoke(active=True)
            expect(
                calls == [] and waits == [],
                "unexpected active broker was accepted for first activation",
            )

            stale_document = json.loads(before)
            stale_document["status"] = "applying"
            INSTALLER.atomic_json(transaction / INSTALLER.JOURNAL_NAME, stale_document)
            calls, waits = invoke()
            expect(calls == [] and waits == [], "non-applied transaction reached systemd")

            stale_document["status"] = "applied"
            stale_document["repo_root"] = "/srv/another-coordinator"
            INSTALLER.atomic_json(transaction / INSTALLER.JOURNAL_NAME, stale_document)
            calls, waits = invoke()
            expect(calls == [] and waits == [], "foreign transaction reached systemd")
        finally:
            INSTALLER.SYSTEM_OWNER_UID = original_owner_uid
            INSTALLER.SYSTEM_OWNER_GID = original_owner_gid


def exercise_installer_activation_timeout_and_rollback() -> None:
    operation_id = "98b3ac41-1eb8-40cb-ad58-24f6cf2576b9"
    clients = ["agent-alpha", "agent-beta"]
    original_owner_uid = INSTALLER.SYSTEM_OWNER_UID
    original_owner_gid = INSTALLER.SYSTEM_OWNER_GID
    with tempfile.TemporaryDirectory(prefix="devcoordinator-activate-timeout-") as raw:
        root = Path(raw).resolve(strict=True)
        try:
            INSTALLER.SYSTEM_OWNER_UID = os.getuid()
            INSTALLER.SYSTEM_OWNER_GID = os.getgid()
            transaction, journal = _activation_transaction(root)
            precondition = journal["restart_precondition"]
            assert isinstance(precondition, dict)
            verify_result: dict[str, object] = {
                "ok": True,
                "restart_precondition": precondition,
                "failures": [],
            }
            state = {"active": False, "enabled": False}
            calls: list[tuple[str, ...]] = []
            waits: list[int] = []
            patches = _activation_patches(
                verify_result=verify_result,
                current_precondition=precondition,
                state=state,
                calls=calls,
                wait_calls=waits,
                wait_error=INSTALLER.InstallError("bounded readiness expired"),
            )
            with ExitStack() as stack:
                for patch in patches:
                    stack.enter_context(patch)
                must_reject(
                    lambda: INSTALLER.activate_install(
                        clients,
                        transaction,
                        operation_id,
                        3,
                    ),
                    "broker readiness timeout",
                )
            failed = json.loads(
                (transaction / INSTALLER.JOURNAL_NAME).read_text(encoding="utf-8")
            )
            expect(
                waits == [3]
                and state == {"active": False, "enabled": False}
                and failed["status"] == "applied"
                and failed["activation"]["operation_id"] == operation_id
                and failed["activation"]["phase"] == "failed",
                f"failed activation did not durably restore its baseline: {failed}; calls={calls}",
            )
            lifecycle = [call[1] for call in calls if call and call[0] == "systemctl"]
            expect(
                lifecycle == ["enable", "start", "stop", "disable"],
                f"timeout cleanup did not exactly restore a disabled/inactive baseline: {calls}",
            )

            # A systemd restart racing after the failed cleanup can be
            # reconciled only by the same journaled activation operation.  It
            # must stop the owned unit without rolling back installed files.
            state["active"] = True
            calls.clear()
            reconcile_patches = _activation_patches(
                verify_result=verify_result,
                current_precondition=precondition,
                state=state,
                calls=calls,
                wait_calls=waits,
            )
            with ExitStack() as stack:
                for patch in reconcile_patches:
                    stack.enter_context(patch)
                reconciled = INSTALLER.restore_activation_baseline(
                    transaction,
                    operation_id,
                )
            expect(
                reconciled.get("status") == "applied"
                and reconciled.get("activation", {}).get("phase") == "failed"
                and state == {"active": False, "enabled": False},
                "owned post-failure restart was not reconciled to its baseline",
            )
            expect(
                [call[1] for call in calls if call and call[0] == "systemctl"]
                == ["stop"],
                f"activation baseline reconciliation changed unrelated state: {calls}",
            )

            calls.clear()
            waits.clear()
            canary_failure_patches = _activation_patches(
                verify_result=verify_result,
                current_precondition=precondition,
                state=state,
                calls=calls,
                wait_calls=waits,
                client_readiness=INSTALLER.InstallError(
                    "installed broker profile canary failed"
                ),
            )
            with ExitStack() as stack:
                for patch in canary_failure_patches:
                    stack.enter_context(patch)
                must_reject(
                    lambda: INSTALLER.activate_install(
                        clients,
                        transaction,
                        operation_id,
                        3,
                    ),
                    "broker client-readiness canary",
                )
            canary_failed = json.loads(
                (transaction / INSTALLER.JOURNAL_NAME).read_text(encoding="utf-8")
            )
            expect(
                waits == [3]
                and state == {"active": False, "enabled": False}
                and canary_failed["status"] == "applied"
                and canary_failed["activation"]["phase"] == "failed",
                "client-readiness failure did not restore the service baseline",
            )
            expect(
                [call[1] for call in calls if call and call[0] == "systemctl"]
                == ["enable", "start", "stop", "disable"],
                f"client-readiness cleanup changed the exact baseline: {calls}",
            )

            # A later successful exact replay transitions the same operation to
            # activated; rollback must restore the pre-activation unit baseline
            # before touching installed files.
            calls.clear()
            waits.clear()
            success_patches = _activation_patches(
                verify_result=verify_result,
                current_precondition=precondition,
                state=state,
                calls=calls,
                wait_calls=waits,
            )
            with ExitStack() as stack:
                for patch in success_patches:
                    stack.enter_context(patch)
                activated = INSTALLER.activate_install(
                    clients,
                    transaction,
                    operation_id,
                    3,
                )
            expect(activated.get("status") == "activated", "failed activation was not retryable")
            calls.clear()
            rollback_patches = (
                mock.patch.object(INSTALLER.os, "geteuid", return_value=0),
                mock.patch.object(
                    INSTALLER,
                    "_systemd_unit_active",
                    side_effect=lambda: state["active"],
                ),
                mock.patch.object(
                    INSTALLER,
                    "_systemd_unit_enabled",
                    side_effect=lambda: state["enabled"],
                ),
                mock.patch.object(INSTALLER, "command", side_effect=lambda name: name),
                mock.patch.object(
                    INSTALLER,
                    "run",
                    side_effect=lambda *arguments: (
                        calls.append(tuple(arguments)),
                        state.__setitem__("active", False)
                        if len(arguments) > 1 and arguments[1] == "stop"
                        else None,
                        state.__setitem__("enabled", False)
                        if len(arguments) > 1 and arguments[1] == "disable"
                        else None,
                    ),
                ),
            )
            with ExitStack() as stack:
                for patch in rollback_patches:
                    stack.enter_context(patch)
                rolled_back = INSTALLER.rollback_install(transaction)
            expect(
                rolled_back.get("status") == "rolled_back"
                and state == {"active": False, "enabled": False},
                f"activated transaction rollback did not restore service baseline: {rolled_back}",
            )
            rollback_lifecycle = [
                call[1] for call in calls if call and call[0] == "systemctl"
            ]
            expect(
                rollback_lifecycle[:2] == ["stop", "disable"]
                and rollback_lifecycle[-1:] == ["daemon-reload"],
                f"rollback did not restore runtime before installed files: {calls}",
            )
        finally:
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


def exercise_installed_source_readability_transaction() -> None:
    # The installed source readability transaction is Linux-only. macOS does
    # not provide getfacl/setfacl, so retain the source-contract assertions in
    # main() and run the executable round trip only where both tools exist.
    if shutil.which("getfacl") is None or shutil.which("setfacl") is None:
        return
    original_root = INSTALLER.ROOT
    original_source = INSTALLER.SKILL_SOURCE
    with tempfile.TemporaryDirectory(prefix="devcoordinator-install-acl-") as raw:
        repository = Path(raw) / "repository"
        source = repository / "skills/codex-dev-coordinator"
        backup_source = repository / "skills/postgres-docker-backup"
        transaction = Path(raw) / "transaction"
        source.mkdir(parents=True)
        backup_source.mkdir()
        transaction.mkdir()
        skill = source / "SKILL.md"
        backup_skill = backup_source / "SKILL.md"
        script = source / "scripts/dev_coordinator.py"
        script.parent.mkdir()
        skill.write_text("canonical\n", encoding="utf-8")
        backup_skill.write_text("canonical backup\n", encoding="utf-8")
        script.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        script.chmod(0o700)
        try:
            INSTALLER.ROOT = repository
            INSTALLER.SKILL_SOURCE = source
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
            backup_skill_acl = INSTALLER.capture(
                INSTALLER.command("getfacl"), "--omit-header", str(backup_skill)
            ).decode("utf-8")
            script_acl = INSTALLER.capture(
                INSTALLER.command("getfacl"), "--omit-header", str(script)
            ).decode("utf-8")
            expect(
                "other::r--" in skill_acl,
                "skill ACL did not grant read access",
            )
            expect(
                "other::r--" in backup_skill_acl,
                "backup skill ACL did not grant read access",
            )
            expect(
                "other::r-x" in script_acl,
                "script ACL did not grant execute access",
            )
            inherited = source / "future-update.txt"
            inherited.write_text("future\n", encoding="utf-8")
            inherited_acl = INSTALLER.capture(
                INSTALLER.command("getfacl"), "--omit-header", str(inherited)
            ).decode("utf-8")
            expect(
                "other::r--" in inherited_acl,
                "default ACL was not inherited",
            )
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


def exercise_managed_docker_source_policy() -> None:
    with tempfile.TemporaryDirectory(prefix="devcoordinator-docker-source-policy-") as raw:
        skill = Path(raw).resolve(strict=True) / "codex-dev-coordinator"
        scripts = skill / "scripts"
        agents = skill / "agents"
        scripts.mkdir(parents=True)
        agents.mkdir()
        (skill / "SKILL.md").write_text(
            "Use the coordinator. Prose may explain why docker compose up is forbidden.\n",
            encoding="utf-8",
        )
        (skill / "README.md").write_text(
            "```bash\npython3 scripts/dev_coordinator.py docker compose-up\n```\n",
            encoding="utf-8",
        )
        (agents / "openai.yaml").write_text(
            "interface:\n  display_name: Coordinator\n",
            encoding="utf-8",
        )
        policy_script = scripts / "validate_runtime_dependencies.py"
        policy_script.write_text(
            "import subprocess\n"
            "subprocess.run(['docker', 'compose', 'config'])\n",
            encoding="utf-8",
        )
        (scripts / "dev_coordinator.py").write_text(
            "import subprocess\nsubprocess.run(['docker', 'run', 'internal'])\n",
            encoding="utf-8",
        )
        (scripts / "self_test.py").write_text(
            "fixture = ['docker', 'compose', 'up']\n",
            encoding="utf-8",
        )

        safe = INSTALLER.managed_docker_source_policy_evidence(skill_root=skill)
        expect(safe["ok"], f"safe typed coordinator source was rejected: {safe}")
        expect(
            "scripts/dev_coordinator.py" not in safe["checked_files"]
            and "scripts/self_test.py" not in safe["checked_files"],
            "coordinator internals or explicit fixtures were not excluded",
        )

        must_catch = (
            (
                "import subprocess\nsubprocess.run(['docker', 'run', '--rm', 'image'])\n",
                "docker run",
            ),
            (
                "import subprocess\nsubprocess.run(['docker', 'create', 'image'])\n",
                "docker create",
            ),
            (
                "import subprocess\n"
                "docker_cli = '/usr/bin/docker'\n"
                "subprocess.run([docker_cli, '--context', 'host', 'compose', "
                "'-f', 'compose.yml', 'up', '-d'])\n",
                "docker compose up",
            ),
        )
        for source, operation in must_catch:
            policy_script.write_text(source, encoding="utf-8")
            evidence = INSTALLER.managed_docker_source_policy_evidence(
                skill_root=skill
            )
            expect(
                not evidence["ok"]
                and any(
                    item["operation"] == operation for item in evidence["findings"]
                ),
                f"managed source guard missed {operation}: {evidence}",
            )

        policy_script.write_text("SAFE = True\n", encoding="utf-8")
        shell_helper = scripts / "agent_helper.sh"
        shell_helper.write_text(
            "#!/bin/sh\nDOCKER_HOST=unix:///run/docker.sock docker create image\n",
            encoding="utf-8",
        )
        shell_evidence = INSTALLER.managed_docker_source_policy_evidence(
            skill_root=skill
        )
        expect(
            not shell_evidence["ok"]
            and any(
                item["operation"] == "docker create"
                for item in shell_evidence["findings"]
            ),
            f"managed shell guard missed raw Docker creation: {shell_evidence}",
        )
        shell_helper.unlink()
        (skill / "README.md").write_text(
            "```console\n$ sudo docker compose --env-file fixture.env down\n```\n",
            encoding="utf-8",
        )
        markdown = INSTALLER.managed_docker_source_policy_evidence(skill_root=skill)
        expect(
            not markdown["ok"]
            and markdown["findings"][0]["operation"] == "docker compose down",
            f"managed guidance guard missed executable fenced Docker mutation: {markdown}",
        )
        (skill / "README.md").unlink()
        must_reject(
            lambda: INSTALLER.managed_docker_source_policy_evidence(skill_root=skill),
            "missing canonical managed-source surface",
        )


def exercise_docker_socket_admission_evidence() -> None:
    parsed = INSTALLER._parse_posix_acl(
        "user::rw-\n"
        "user:1234:rw-\n"
        "group::---\n"
        "mask::r--\n"
        "other::---\n"
    )
    metadata = SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFSOCK | 0o640)
    expect(
        INSTALLER._acl_permissions(parsed, metadata, uid=1234, gids={1234})
        == frozenset({"r"}),
        "ACL mask was not applied to a named-user Docker socket grant",
    )

    with tempfile.TemporaryDirectory(prefix="devcoordinator-missing-listxattr-") as raw:
        owned = Path(raw).resolve(strict=True)
        owned.chmod(0o700)
        with mock.patch.object(INSTALLER, "_read_posix_acl", return_value=(None, "getfacl_unavailable")), mock.patch.object(
            INSTALLER.os, "listxattr", new=None, create=True
        ):
            owner = INSTALLER._identity_path_permission(
                owned, uid=os.getuid(), gids={os.getgid()}, required="x"
            )
            foreign = INSTALLER._identity_path_permission(
                owned, uid=os.getuid() + 10_000, gids=set(), required="x"
            )
        expect(
            owner["allowed"] is True and owner["source"] == "owner_mode",
            f"missing listxattr rejected a directly owned path: {owner}",
        )
        expect(
            foreign["allowed"] is None
            and foreign["source"] == "getfacl_unavailable",
            f"missing listxattr trusted a non-owner mode approximation: {foreign}",
        )

    with tempfile.TemporaryDirectory(prefix="devcoordinator-docker-socket-") as raw:
        root = Path(raw).resolve(strict=True)
        root.chmod(0o755)
        socket_path = root / "docker.sock"
        alias_path = root / "docker-alias.sock"
        socket_path.write_text("fixture inode\n", encoding="utf-8")
        socket_path.chmod(0o600)
        alias_path.symlink_to(socket_path)
        record = SimpleNamespace(
            pw_name="fixture-client",
            pw_uid=os.getuid(),
            pw_gid=os.getgid(),
            pw_dir=str(root),
        )
        # The sandbox may forbid creating AF_UNIX filesystem sockets. Patch
        # only the type predicate; real inode, alias, ACL, mode, and traversal
        # evidence still exercise the full read-only admission path.
        with mock.patch.object(INSTALLER.stat, "S_ISSOCK", return_value=True), mock.patch.object(
            INSTALLER.os, "listxattr", return_value=[], create=True
        ):
            evidence = INSTALLER.docker_socket_admission_evidence(
                [(record, root)], socket_candidates=[socket_path, alias_path]
            )
        expect(
            len(evidence["sockets"]) == 1
            and set(evidence["sockets"][0]["aliases"])
            == {str(socket_path), str(alias_path)},
            f"socket aliases were not deduplicated by immutable inode: {evidence}",
        )
        expect(
            evidence["clients"][0]["direct_socket_access"] is True
            and evidence["activation_blockers"][0]["code"]
            == INSTALLER.DIRECT_DOCKER_SOCKET_ACCESS,
            f"direct owner access was not reported as an activation blocker: {evidence}",
        )
        expect(
            evidence["stage"] == "observe_only"
            and evidence["enforcement_enabled"] is False
            and evidence["exclusive_admission_ready"] is False
            and evidence["automatic_group_or_acl_mutation"] is False,
            "staged admission evidence falsely claimed enforcement or mutation",
        )
        warnings, warning_codes = INSTALLER._docker_admission_warning_summary(evidence)
        expect(
            warning_codes == [INSTALLER.DIRECT_DOCKER_SOCKET_ACCESS]
            and warnings == [evidence["activation_blockers"][0]["message"]],
            "verify warning projection lost the staged Docker activation blocker",
        )


def exercise_two_account_skill_plan_matrix() -> None:
    records = [
        pwd.struct_passwd(
            (
                name,
                "x",
                4100 + index,
                5100 + index,
                "",
                f"/home/{name}",
                "/bin/sh",
            )
        )
        for index, name in enumerate(("agent-alpha", "agent-beta"))
    ]
    clients = [(record, Path(record.pw_dir)) for record in records]
    with (
        mock.patch.object(INSTALLER, "client_records", return_value=clients),
        mock.patch.object(
            INSTALLER,
            "enrolled_home_write_paths",
            return_value=[home for _record, home in clients],
        ),
        mock.patch.object(
            INSTALLER,
            "docker_socket_admission_evidence",
            return_value={"activation_blockers": []},
        ),
    ):
        plan = INSTALLER.desired_plan([record.pw_name for record in records])
    links = [link for client in plan["clients"] for link in client["skill_links"]]
    expect(
        [entry["name"] for entry in plan["managed_skills"]]
        == list(INSTALLER.MANAGED_SKILLS),
        "installer plan did not expose the exact canonical skill set",
    )
    expect(
        len(links) == 8,
        f"two-account Codex/Claude plan did not expose eight exact links: {links}",
    )
    expect(
        {
            (link["uid"], link["runtime"], link["skill"])
            for link in links
        }
        == {
            (record.pw_uid, runtime, skill)
            for record in records
            for runtime in ("codex", "claude")
            for skill in INSTALLER.MANAGED_SKILLS
        },
        "installer plan duplicated or omitted a per-account/runtime/skill link",
    )


def _skill_fixture_repository(root: Path) -> Path:
    repository = root / "repository"
    scripts = repository / "scripts"
    scripts.mkdir(parents=True)
    shutil.copyfile(
        SCRIPT.with_name("manage_skill_links.py"),
        scripts / "manage_skill_links.py",
    )
    for name in INSTALLER.MANAGED_SKILLS:
        skill = repository / "skills" / name
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: fixture\n---\n",
            encoding="utf-8",
        )
    return repository


def _apply_fixture_links(roots: list[Path], transaction: Path) -> dict[str, object]:
    _returncode, result = INSTALLER.run_json_command(
        *INSTALLER.skill_manager_arguments(
            "apply",
            roots,
            transaction=transaction,
        )
    )
    return result


def _rollback_fixture_links(transaction: Path) -> None:
    INSTALLER.run_json_command(
        sys.executable,
        str(INSTALLER.ROOT / "scripts/manage_skill_links.py"),
        "rollback",
        "--transaction-dir",
        str(transaction),
        "--json",
    )


def exercise_skill_root_and_link_transactions() -> None:
    original_root = INSTALLER.ROOT
    original_source = INSTALLER.SKILL_SOURCE
    with tempfile.TemporaryDirectory(prefix="devcoordinator-skill-install-") as raw:
        fixture = Path(raw).resolve(strict=True)
        repository = _skill_fixture_repository(fixture)
        home = fixture / "home" / "agent"
        home.mkdir(parents=True)
        record = pwd.struct_passwd(
            (
                "agent",
                "x",
                os.getuid(),
                os.getgid(),
                "",
                str(home),
                "/bin/sh",
            )
        )
        try:
            INSTALLER.ROOT = repository
            INSTALLER.SKILL_SOURCE = repository / "skills/codex-dev-coordinator"

            missing_journal: dict[str, object] = {"skill_root_directories": []}
            persisted: list[int] = []
            roots = INSTALLER.install_client_skill_roots(
                record,
                home,
                journal=missing_journal,
                persist=lambda: persisted.append(1),
            )
            expect(
                len(roots) == 2
                and all(root.is_dir() and stat.S_IMODE(root.stat().st_mode) == 0o700 for root in roots),
                "missing explicit Codex/Claude roots were not created securely",
            )
            first_transaction = fixture / "link-transaction-missing"
            _apply_fixture_links(roots, first_transaction)
            verified = INSTALLER.verify_skill_links(roots)
            expect(
                verified["ok"] and len(verified["entries"]) == 4,
                f"two-skill link publication did not verify exactly: {verified}",
            )
            _rollback_fixture_links(first_transaction)
            INSTALLER.rollback_skill_root_directories(
                missing_journal["skill_root_directories"]
            )
            expect(
                all(not root.exists() for root in roots)
                and not (home / ".codex").exists()
                and not (home / ".claude").exists(),
                "rollback retained directories created by the installer transaction",
            )
            expect(persisted, "skill-root directory mutations were not journaled")

            for relative, root_mode, parent_mode in (
                (Path(".codex/skills"), 0o775, 0o755),
                (Path(".claude/skills"), 0o750, 0o711),
            ):
                parent = home / relative.parent
                root = home / relative
                parent.mkdir(mode=parent_mode)
                parent.chmod(parent_mode)
                root.mkdir(mode=root_mode)
                root.chmod(root_mode)
                (root / "unrelated-skill").mkdir()
                (root / "unrelated-skill" / "SKILL.md").write_text(
                    "unrelated\n", encoding="utf-8"
                )
            existing_journal: dict[str, object] = {"skill_root_directories": []}
            existing_roots = INSTALLER.install_client_skill_roots(
                record,
                home,
                journal=existing_journal,
                persist=lambda: None,
            )
            transaction = fixture / "link-transaction-existing"
            _apply_fixture_links(existing_roots, transaction)
            replay_transaction = fixture / "link-transaction-replay"
            replay = _apply_fixture_links(existing_roots, replay_transaction)
            expect(
                replay.get("status") == "applied"
                and replay.get("entries") == [],
                f"canonical replay was not an idempotent no-op: {replay}",
            )
            _rollback_fixture_links(replay_transaction)
            expect(
                INSTALLER.verify_skill_links(existing_roots)["ok"],
                "replay rollback changed canonical links",
            )
            _rollback_fixture_links(transaction)
            INSTALLER.rollback_skill_root_directories(
                existing_journal["skill_root_directories"]
            )
            restored_modes = {
                relative: stat.S_IMODE((home / relative).stat().st_mode)
                for relative in (
                    ".codex",
                    ".codex/skills",
                    ".claude",
                    ".claude/skills",
                )
            }
            expect(
                restored_modes
                == {
                    ".codex": 0o755,
                    ".codex/skills": 0o775,
                    ".claude": 0o711,
                    ".claude/skills": 0o750,
                },
                "rollback did not restore exact pre-existing skill-root metadata: "
                f"{restored_modes}; journal={existing_journal['skill_root_directories']}",
            )
            expect(
                all(
                    (root / "unrelated-skill/SKILL.md").read_text(encoding="utf-8")
                    == "unrelated\n"
                    for root in existing_roots
                ),
                "canonical apply/replay/rollback changed an unrelated skill",
            )
        finally:
            INSTALLER.ROOT = original_root
            INSTALLER.SKILL_SOURCE = original_source


def exercise_noncanonical_skill_refusal() -> None:
    original_root = INSTALLER.ROOT
    original_source = INSTALLER.SKILL_SOURCE
    with tempfile.TemporaryDirectory(prefix="devcoordinator-skill-refusal-") as raw:
        fixture = Path(raw).resolve(strict=True)
        repository = _skill_fixture_repository(fixture)
        roots = [fixture / "codex-skills", fixture / "claude-skills"]
        for root in roots:
            root.mkdir()
        divergent = roots[0] / "codex-dev-coordinator"
        divergent.mkdir()
        (divergent / "SKILL.md").write_text("operator copy\n", encoding="utf-8")
        unrelated = roots[1] / "unrelated-skill"
        unrelated.mkdir()
        try:
            INSTALLER.ROOT = repository
            INSTALLER.SKILL_SOURCE = repository / "skills/codex-dev-coordinator"
            transaction = fixture / "must-not-exist"
            try:
                _apply_fixture_links(roots, transaction)
            except INSTALLER.InstallError:
                pass
            else:
                raise AssertionError("installer accepted a noncanonical skill without approval")
            expect(
                not transaction.exists()
                and (divergent / "SKILL.md").read_text(encoding="utf-8")
                == "operator copy\n"
                and unrelated.is_dir(),
                "noncanonical refusal changed installed or unrelated skill state",
            )
        finally:
            INSTALLER.ROOT = original_root
            INSTALLER.SKILL_SOURCE = original_source


def main() -> int:
    user = "devcoordinator-fixture"
    fixture_home = Path("/home/devcoordinator-fixture")
    fixture_record = pwd.struct_passwd(
        (user, "x", os.geteuid(), os.getegid(), "", str(fixture_home), "/bin/sh")
    )
    # The production installer deliberately accepts only direct /home children.
    # Keep this plan fixture independent of the developer host's account layout
    # (for example macOS /Users) while the focused home-path tests exercise the
    # real validation function separately.
    with (
        mock.patch.object(
            INSTALLER,
            "client_records",
            return_value=[(fixture_record, fixture_home)],
        ),
        mock.patch.object(
            INSTALLER,
            "enrolled_home_write_paths",
            return_value=[fixture_home],
        ),
    ):
        plan = INSTALLER.desired_plan([user])
    expect(
        plan["authority"]["database"] == "/var/lib/devcoordinator/coordinator.sqlite3",
        "plan selected the wrong authority database",
    )
    expect(
        plan["authority"]["socket"] == "/run/devcoordinator-authority.sock",
        "plan selected the wrong broker socket",
    )
    expect(
        plan["authority"]["socket_gid"] == 0
        and plan["authority"]["socket_mode"] == "0666",
        "plan retained a group-authorized broker socket",
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
        plan["docker_admission"]["contract"]
        == INSTALLER.DOCKER_ADMISSION_CONTRACT
        and plan["docker_admission"]["stage"] == "observe_only"
        and plan["docker_admission"]["enforcement_enabled"] is False
        and plan["docker_admission"]["exclusive_admission_ready"] is False
        and plan["docker_admission"]["automatic_group_or_acl_mutation"] is False,
        "installer plan does not truthfully report staged Docker admission",
    )
    expect(
        plan["managed_docker_source_policy"]["ok"] is True
        and plan["managed_docker_source_policy"]["contract"]
        == INSTALLER.DOCKER_SOURCE_POLICY_CONTRACT,
        "installer plan omitted the canonical managed-source policy guard",
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
        [item["name"] for item in plan["managed_skills"]]
        == list(INSTALLER.MANAGED_SKILLS)
        and len(plan["clients"][0]["skill_links"])
        == len(INSTALLER.AGENT_SKILL_ROOTS) * len(INSTALLER.MANAGED_SKILLS),
        "installer plan omitted exact per-skill/per-root link evidence",
    )
    expect(
        plan["system_files"][-1]["source"]
        == INSTALLER.ENROLLED_HOME_DROPIN_SOURCE
        and plan["system_files"][-1]["destination"]
        == str(INSTALLER.ENROLLED_HOME_DROPIN)
        and plan["system_files"][-1]["home_write_paths"]
        == [str(fixture_home)],
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
    expect("Group=root" in unit, "broker unit does not use the root authority group")
    expect(
        "Group=devcoordinator-clients" not in unit,
        "broker unit still treats the shared client group as an authority gate",
    )
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
    expect("/run/devcoordinator-authority.sock" in unit, "broker unit selected the wrong socket")
    expect("%h" not in unit, "system unit uses manager-home expansion")
    expect(
        not any(line.startswith("RuntimeDirectory") for line in unit.splitlines()),
        "direct socket-activated broker must not own an obsolete runtime directory",
    )
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

    sysusers = (INSTALLER.ROOT / "deploy/devcoordinator.sysusers.conf").read_text(
        encoding="utf-8"
    )
    expect(
        'u devcoordinator-testd - "DevCoordinator test scheduler" '
        "/nonexistent /usr/sbin/nologin" in sysusers,
        "legacy bootstrap omits the broker's required test-plane identity",
    )
    expect(
        "devcoordinator-clients" not in sysusers,
        "legacy bootstrap still creates a broad client access group",
    )

    tmpfiles = (INSTALLER.ROOT / "deploy/devcoordinator.tmpfiles.conf").read_text(
        encoding="utf-8"
    )
    expect(
        "d /var/lib/devcoordinator 0711 root root" in tmpfiles,
        "tmpfiles omits the traverse-only authority state parent",
    )
    expect(
        "d /var/lib/devcoordinator-clients 0711 root root" in tmpfiles,
        "tmpfiles omits the client journal parent",
    )
    expect(
        "d /run/devcoordinator-maintenance 0755 root root"
        in tmpfiles,
        "tmpfiles omits the broker-independent maintenance directory",
    )
    expect(
        "d /run/devcoordinator 0755 root root" in tmpfiles,
        "tmpfiles omits the trusted-local runtime directory",
    )
    expect(
        "d /etc/devcoordinator 0755 root root" in tmpfiles,
        "tmpfiles omits the shared profile directory",
    )

    installer_source = SCRIPT.read_text(encoding="utf-8")
    expect('"o::rX"' in installer_source, "installer omits trusted-local source ACL access")
    expect(
        '"d:o::rX"' in installer_source,
        "installer omits default source ACL access",
    )
    expect('f"--restore={backup}"' in installer_source, "installer omits ACL rollback")
    expect(
        'stat.S_IMODE(metadata.st_mode) != 0o644' in installer_source,
        "installer omits profile mode verification",
    )
    expect(
        'run(command("usermod")' not in installer_source,
        "installer still mutates human account groups",
    )
    expect(
        "client is not in the broker access group" not in installer_source,
        "installer still verifies a human group authorization gate",
    )
    expect(
        'run(command("gpasswd"), "-d", str(user), LEGACY_ACCESS_GROUP)'
        in installer_source,
        "installer no longer understands legacy group rollback evidence",
    )
    expect("shutil.rmtree" not in installer_source, "installer can remove a directory tree")
    expect(
        installer_source.count("os.rmdir(path)") == 1,
        "installer may remove directories outside the exact skill-root rollback helper",
    )
    exercise_broker_unit_source_controls()
    exercise_worker_runner_script_guard()
    exercise_systemd_unit_activity_states()
    exercise_two_account_skill_plan_matrix()
    exercise_skill_root_and_link_transactions()
    exercise_noncanonical_skill_refusal()
    exercise_enrolled_home_dropin_transaction()
    exercise_legacy_docker_dropin_transaction()
    exercise_activation_authority_contract_guard()
    exercise_installer_activation_transaction()
    exercise_installer_activation_refusals()
    exercise_installer_activation_timeout_and_rollback()
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
    exercise_installed_source_readability_transaction()
    exercise_managed_docker_source_policy()
    exercise_docker_socket_admission_evidence()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
