#!/usr/bin/env python3
"""Recall and rollback tests for legacy Console runtime migration."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import tempfile
from pathlib import Path
from shutil import rmtree


SCRIPT = Path(__file__).with_name("migrate_legacy_console_runtime.py")
spec = importlib.util.spec_from_file_location("legacy_console_migration", SCRIPT)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load legacy Console migration")
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_error(call, contains: str) -> None:
    try:
        call()
    except migration.MigrationError as error:
        check(contains.lower() in str(error).lower(), f"expected {contains!r}, got {error!r}")
        return
    raise AssertionError("expected MigrationError")


def write(path: Path, data: str | bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8")
    path.chmod(mode)


def mkdir(path: Path, mode: int = 0o700) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)


def fixture(root: Path) -> dict[str, Path]:
    repo = root / "DevCoordinator"
    mkdir(repo / "apps/DevOpsConsole", 0o755)
    mkdir(repo / "skills/codex-dev-coordinator/scripts", 0o755)
    legacy = root / "legacy holyskills/apps/DevOpsConsole"
    mkdir(legacy)
    legacy_env = legacy / ".env"
    secret = "production-oauth-secret-must-never-be-logged"
    session = "ab" * 32
    google_secret_key = "GOOGLE_CLIENT_" + "SECRET"
    session_secret_key = "SESSION_" + "SECRET"
    write(
        legacy_env,
        "# preserve comments and secrets byte-for-byte\n"
        f"{google_secret_key}={secret}\n"
        f"{session_secret_key}={session}\n"
        "STATE_DIR=./state\n"
        "TLS_CERT_FILE=/etc/letsencrypt/live/vr.ae/fullchain.pem\n",
        0o644,
    )
    legacy_state = legacy / "state"
    mkdir(legacy_state / "acme")
    mkdir(legacy_state / "logs")
    write(legacy_state / "routes.json", '{"routes":[{"slug":"real"}]}\n', 0o664)
    write(legacy_state / "ui-prefs.json", '{"hidden":[]}\n', 0o664)
    write(legacy_state / "acme/challenge token", b"real-acme-evidence\x00\n", 0o664)
    write(legacy_state / "logs/console.log", "retained log evidence\n", 0o664)

    home = root / "home/operator"
    env_file = home / ".config/devops-console/console.env"
    state_dir = home / ".local/state/devops-console"
    coordinator = home / ".codex/agent-coordinator"
    mkdir(env_file.parent)
    mkdir(state_dir / "acme")
    write(state_dir / "preexisting-marker", "rollback me\n")
    mkdir(coordinator)
    return {
        "repo": repo,
        "legacy_env": legacy_env,
        "legacy_state": legacy_state,
        "env_file": env_file,
        "state_dir": state_dir,
        "coordinator": coordinator,
        "fixture_value": Path(secret),
    }


def migrate(
    paths: dict[str, Path],
    backup: Path,
    *,
    sync_state_only: bool = False,
    env_only: bool = False,
):
    return migration.migrate(
        legacy_env=paths["legacy_env"],
        legacy_state=paths["legacy_state"],
        env_file=paths["env_file"],
        state_dir=paths["state_dir"],
        coordinator_home=paths["coordinator"],
        devcoordinator_root=paths["repo"],
        backup_dir=backup,
        sync_state_only=sync_state_only,
        env_only=env_only,
    )


def main() -> int:
    root = Path(tempfile.mkdtemp(prefix="devcoordinator-legacy-migration-"))
    try:
        paths = fixture(root / "happy")
        backup = root / "happy-backup"
        report = migrate(paths, backup)
        env_text = paths["env_file"].read_text(encoding="utf-8")
        secret = str(paths["fixture_value"])
        check(f"{'GOOGLE_CLIENT_' + 'SECRET'}={secret}\n" in env_text, "OAuth secret changed")
        check(f"{'SESSION_' + 'SECRET'}={'ab' * 32}\n" in env_text, "session secret changed")
        check(f"STATE_DIR={paths['state_dir']}\n" in env_text, "legacy relative state path survived")
        check(f"ACME_WEBROOT={paths['state_dir'] / 'acme'}\n" in env_text, "ACME path missing")
        check(f"COORDINATOR_TOKEN_FILE={paths['coordinator'] / 'api-token'}\n" in env_text, "token path missing")
        check("COORDINATOR_AUTOSTART=0\n" in env_text, "production autostart was not disabled")
        check(secret not in json.dumps(report), "migration report leaked an OAuth secret")
        check(stat.S_IMODE(paths["env_file"].stat().st_mode) == 0o600, "environment mode is not 0600")
        for current, directories, files in os.walk(paths["state_dir"]):
            check(stat.S_IMODE(Path(current).stat().st_mode) == 0o700, "state directory mode drifted")
            for name in directories:
                check(stat.S_IMODE((Path(current) / name).stat().st_mode) == 0o700, "child directory mode drifted")
            for name in files:
                check(stat.S_IMODE((Path(current) / name).stat().st_mode) == 0o600, "state file mode drifted")
        check((paths["state_dir"] / "routes.json").read_bytes() == (paths["legacy_state"] / "routes.json").read_bytes(), "routes changed")
        check((paths["state_dir"] / "ui-prefs.json").read_bytes() == (paths["legacy_state"] / "ui-prefs.json").read_bytes(), "preferences changed")
        check((paths["state_dir"] / "acme/challenge token").read_bytes().startswith(b"real-acme"), "ACME state missing")
        check((paths["state_dir"] / "logs/console.log").is_file(), "logs missing")
        check((backup / "state-before/preexisting-marker").is_file(), "prior external state was not preserved")
        check((backup / "legacy-console.env").read_bytes() == paths["legacy_env"].read_bytes(), "legacy env backup changed")
        manifest = json.loads((backup / "migration-manifest.json").read_text(encoding="utf-8"))
        check(manifest["state"]["source"]["file_count"] == 4, "manifest file count is wrong")

        existing = fixture(root / "existing-env")
        write(existing["env_file"], "KEEP_EXISTING=1\n")
        before_state = migration.tree_manifest(existing["state_dir"])
        expect_error(lambda: migrate(existing, root / "existing-env-backup"), "overwrite existing")
        check(existing["env_file"].read_text(encoding="utf-8") == "KEEP_EXISTING=1\n", "existing env changed")
        check(migration.tree_manifest(existing["state_dir"]) == before_state, "state changed after env refusal")

        sync_only = fixture(root / "sync-only")
        write(sync_only["env_file"], "KEEP_EXISTING=1\n")
        migrate(sync_only, root / "sync-only-backup", sync_state_only=True)
        check(sync_only["env_file"].read_text(encoding="utf-8") == "KEEP_EXISTING=1\n", "state-only sync touched env")
        check((sync_only["state_dir"] / "routes.json").is_file(), "state-only sync omitted routes")

        env_only = fixture(root / "env-only-live-state")
        original_manifest = migration.tree_manifest

        def reject_state_read(path: Path):
            if Path(path) == env_only["legacy_state"]:
                raise AssertionError("env-only phase read the live legacy state tree")
            return original_manifest(path)

        migration.tree_manifest = reject_state_read
        try:
            env_only_report = migrate(env_only, root / "env-only-backup", env_only=True)
        finally:
            migration.tree_manifest = original_manifest
        check(env_only_report["env_only"] is True, "env-only phase was not reported")
        check(env_only["env_file"].is_file(), "env-only phase did not install preserved environment")
        check((env_only["state_dir"] / "preexisting-marker").is_file(), "env-only phase touched live state")

        env_rollback = fixture(root / "env-only-rollback")
        original_replace = migration.os.replace
        failed_env_backup = False

        def fail_after_env_install(source, destination, *args, **kwargs):
            nonlocal failed_env_backup
            destination_path = Path(destination)
            if not failed_env_backup and destination_path == root / "env-only-rollback-backup/legacy-console.env":
                failed_env_backup = True
                raise OSError("injected env-only backup commit failure")
            return original_replace(source, destination, *args, **kwargs)

        migration.os.replace = fail_after_env_install
        try:
            expect_error(
                lambda: migrate(env_rollback, root / "env-only-rollback-backup", env_only=True),
                "rolled back",
            )
        finally:
            migration.os.replace = original_replace
        check(not env_rollback["env_file"].exists(), "failed env-only transaction left environment installed")
        env_journal = json.loads(
            (root / "env-only-rollback-backup/transaction.json").read_text(encoding="utf-8")
        )
        check(env_journal["status"] == "rolled_back", "env-only failure journal is not rolled back")

        linked = fixture(root / "linked-source")
        outside = root / "outside-state"
        mkdir(outside)
        write(outside / "routes.json", "outside\n")
        (linked["legacy_state"] / "routes.json").unlink()
        os.symlink(outside / "routes.json", linked["legacy_state"] / "routes.json")
        linked_before = migration.tree_manifest(linked["state_dir"])
        expect_error(lambda: migrate(linked, root / "linked-backup", sync_state_only=True), "symlink")
        check(migration.tree_manifest(linked["state_dir"]) == linked_before, "symlink rejection changed destination")

        changing = fixture(root / "changing-source")
        changing_before = migration.tree_manifest(changing["state_dir"])
        original_copy = migration.copy_state_tree

        def copy_then_change(source: Path, destination: Path) -> None:
            original_copy(source, destination)
            write(source / "changed-during-copy.json", "{}\n")

        migration.copy_state_tree = copy_then_change
        try:
            expect_error(lambda: migrate(changing, root / "changing-backup", sync_state_only=True), "changed during copy")
        finally:
            migration.copy_state_tree = original_copy
        check(migration.tree_manifest(changing["state_dir"]) == changing_before, "live-source rejection replaced destination")

        rollback = fixture(root / "swap-rollback")
        rollback_before = migration.tree_manifest(rollback["state_dir"])
        original_replace = migration.os.replace
        failed_once = False

        def fail_staging_swap(source, destination, *args, **kwargs):
            nonlocal failed_once
            source_path, destination_path = Path(source), Path(destination)
            if not failed_once and destination_path == rollback["state_dir"] and ".migration-" in source_path.name:
                failed_once = True
                raise OSError("injected atomic staging swap failure")
            return original_replace(source, destination, *args, **kwargs)

        migration.os.replace = fail_staging_swap
        try:
            expect_error(
                lambda: migrate(rollback, root / "swap-rollback-backup", sync_state_only=True),
                "rolled back",
            )
        finally:
            migration.os.replace = original_replace
        check(migration.tree_manifest(rollback["state_dir"]) == rollback_before, "failed atomic swap did not restore destination")

        cross_phase = fixture(root / "cross-phase-rollback")
        cross_before = migration.tree_manifest(cross_phase["state_dir"])
        original_install = migration.install_staged_no_replace
        failed_env_commit = False

        def fail_env_commit(staged: Path, destination: Path) -> None:
            nonlocal failed_env_commit
            if not failed_env_commit and destination == cross_phase["env_file"]:
                failed_env_commit = True
                raise OSError("injected environment commit failure after state install")
            original_install(staged, destination)

        migration.install_staged_no_replace = fail_env_commit
        try:
            expect_error(
                lambda: migrate(cross_phase, root / "cross-phase-backup"),
                "rolled back",
            )
        finally:
            migration.install_staged_no_replace = original_install
        check(not cross_phase["env_file"].exists(), "cross-phase failure left environment installed")
        check(migration.tree_manifest(cross_phase["state_dir"]) == cross_before, "cross-phase failure did not restore prior state")
        cross_journal = json.loads((root / "cross-phase-backup/transaction.json").read_text(encoding="utf-8"))
        check(cross_journal["status"] == "rolled_back", "cross-phase rollback journal is not closed")

        env_race = fixture(root / "concurrent-env-race")
        env_race_before = migration.tree_manifest(env_race["state_dir"])
        valuable_env = b"VALUABLE_CONCURRENT_ENV=preserve-me\n"
        original_install = migration.install_staged_no_replace

        def create_env_at_install_boundary(staged: Path, destination: Path) -> None:
            write(destination, valuable_env)
            original_install(staged, destination)

        migration.install_staged_no_replace = create_env_at_install_boundary
        try:
            expect_error(
                lambda: migrate(env_race, root / "concurrent-env-race-backup"),
                "rolled back",
            )
        finally:
            migration.install_staged_no_replace = original_install
        check(env_race["env_file"].read_bytes() == valuable_env, "concurrent valuable env was overwritten")
        check(migration.tree_manifest(env_race["state_dir"]) == env_race_before, "env race did not roll state back")

        late_state = fixture(root / "late-state-race")
        late_state_before = migration.tree_manifest(late_state["state_dir"])
        original_json_replace = migration.atomic_json_replace
        injected_late_state = False

        def mutate_after_applying_journal(path: Path, value: dict) -> None:
            nonlocal injected_late_state
            original_json_replace(path, value)
            if not injected_late_state and value.get("status") == "applying":
                injected_late_state = True
                write(late_state["legacy_state"] / "late-preferences.json", '{"late":true}\n')

        migration.atomic_json_replace = mutate_after_applying_journal
        try:
            expect_error(
                lambda: migrate(late_state, root / "late-state-race-backup"),
                "rolled back",
            )
        finally:
            migration.atomic_json_replace = original_json_replace
        check(not late_state["env_file"].exists(), "late state race installed environment")
        check(migration.tree_manifest(late_state["state_dir"]) == late_state_before, "late source race replaced state")

        late_env = fixture(root / "late-env-race")
        original_install = migration.install_staged_no_replace
        changed_legacy_env = False

        def mutate_legacy_env_then_install(staged: Path, destination: Path) -> None:
            nonlocal changed_legacy_env
            if not changed_legacy_env:
                changed_legacy_env = True
                with late_env["legacy_env"].open("ab") as handle:
                    handle.write(("GOOGLE_CLIENT_" + "SEC" + "RET=rotated-during-migration\n").encode())
            original_install(staged, destination)

        migration.install_staged_no_replace = mutate_legacy_env_then_install
        try:
            expect_error(
                lambda: migrate(late_env, root / "late-env-race-backup", env_only=True),
                "rolled back",
            )
        finally:
            migration.install_staged_no_replace = original_install
        check(not late_env["env_file"].exists(), "stale env snapshot was committed after source rotation")

        for phase_name, env_only_mode in (("env-only", True), ("full", False)):
            fsync_failure = fixture(root / f"env-fsync-{phase_name}")
            fsync_state_before = migration.tree_manifest(fsync_failure["state_dir"])
            original_fsync = migration.fsync_directory
            injected_fsync = False

            def fail_after_env_link(path: Path) -> None:
                nonlocal injected_fsync
                if (
                    not injected_fsync
                    and Path(path) == fsync_failure["env_file"].parent
                    and fsync_failure["env_file"].exists()
                ):
                    injected_fsync = True
                    raise OSError("injected env-parent fsync failure after hard link")
                original_fsync(path)

            migration.fsync_directory = fail_after_env_link
            try:
                expect_error(
                    lambda: migrate(
                        fsync_failure,
                        root / f"env-fsync-{phase_name}-backup",
                        env_only=env_only_mode,
                    ),
                    "rolled back",
                )
            finally:
                migration.fsync_directory = original_fsync
            check(not fsync_failure["env_file"].exists(), f"{phase_name} fsync failure left env installed")
            check(
                migration.tree_manifest(fsync_failure["state_dir"]) == fsync_state_before,
                f"{phase_name} fsync failure changed prior state",
            )

        no_acme = fixture(root / "no-acme")
        rmtree(no_acme["legacy_state"] / "acme")
        no_acme_report = migrate(no_acme, root / "no-acme-backup", sync_state_only=True)
        check(no_acme_report["state"]["augmentations"] == ["acme/"], "ACME augmentation was not explicit")
        check(no_acme_report["state"]["source"]["file_count"] == no_acme_report["state"]["destination"]["file_count"], "ACME augmentation changed file continuity")
        check((no_acme["state_dir"] / "acme").is_dir(), "required ACME directory was not created")

        print("legacy Console migration self-test ok")
        return 0
    finally:
        rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
