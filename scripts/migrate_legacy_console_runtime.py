#!/usr/bin/env python3
"""Transactionally migrate legacy DevOps Console secrets and mutable state."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any


class MigrationError(RuntimeError):
    pass


class EnvironmentAppearedError(MigrationError):
    pass


class EnvironmentPublicationRollbackError(MigrationError):
    pass


PATH_VALUES = {
    "STATE_DIR": lambda state, coordinator, root: str(state),
    "ACME_WEBROOT": lambda state, coordinator, root: str(state / "acme"),
    "CODEX_AGENT_COORDINATOR_HOME": lambda state, coordinator, root: str(coordinator),
    "COORDINATOR_TOKEN_FILE": lambda state, coordinator, root: str(coordinator / "api-token"),
    "DEVCOORDINATOR_ROOT": lambda state, coordinator, root: str(root),
    "COORDINATOR_SCRIPT": lambda state, coordinator, root: str(
        root / "skills/codex-dev-coordinator/scripts/dev_coordinator.py"
    ),
    "COORDINATOR_AUTOSTART": lambda state, coordinator, root: "0",
    "COORDINATOR_URL": lambda state, coordinator, root: "http://127.0.0.1:29876",
}
ASSIGNMENT = re.compile(r"^(?P<prefix>\s*(?:export\s+)?)(?P<key>[A-Z][A-Z0-9_]*)(?P<separator>\s*=\s*).*$")


def no_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            raise MigrationError(f"path contains a symlink component: {current}")


def absolute_path(raw: str | Path, label: str) -> Path:
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise MigrationError(f"{label} must be an absolute path: {path}")
    return Path(os.path.abspath(os.fspath(path)))


def within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def require_regular(path: Path, label: str) -> Path:
    no_symlink_components(path)
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as error:
        raise MigrationError(f"{label} is missing: {path}") from error
    if not stat.S_ISREG(mode):
        raise MigrationError(f"{label} must be a regular non-symlink file: {path}")
    return path


def require_directory(path: Path, label: str) -> Path:
    no_symlink_components(path)
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as error:
        raise MigrationError(f"{label} is missing: {path}") from error
    if not stat.S_ISDIR(mode):
        raise MigrationError(f"{label} must be a real directory: {path}")
    return path


def ensure_private_directory(path: Path) -> Path:
    no_symlink_components(path.parent)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    no_symlink_components(path)
    mode = path.lstat().st_mode
    if not stat.S_ISDIR(mode):
        raise MigrationError(f"private path must be a real directory: {path}")
    path.chmod(0o700)
    return path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_snapshot(path: Path, label: str) -> dict[str, Any]:
    path = require_regular(path, label)
    metadata = path.lstat()
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "size": metadata.st_size,
        "sha256": sha256_file(path),
    }


def require_file_snapshot(path: Path, expected: dict[str, Any], label: str) -> None:
    if file_snapshot(path, label) != expected:
        raise MigrationError(f"{label} changed during migration; destination was not committed")


def tree_manifest(root: Path) -> dict[str, Any]:
    require_directory(root, "state directory")
    entries: list[dict[str, Any]] = []
    total_bytes = 0
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories.sort()
        files.sort()
        for name in [*directories, *files]:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise MigrationError(f"legacy state contains a symlink: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                entries.append({"path": relative, "type": "directory"})
            elif stat.S_ISREG(metadata.st_mode):
                size = metadata.st_size
                total_bytes += size
                entries.append(
                    {
                        "path": relative,
                        "type": "file",
                        "size": size,
                        "sha256": sha256_file(path),
                    }
                )
            else:
                raise MigrationError(f"legacy state contains a special filesystem object: {relative}")
    encoded = json.dumps(entries, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return {
        "entries": entries,
        "directory_count": sum(item["type"] == "directory" for item in entries),
        "file_count": sum(item["type"] == "file" for item in entries),
        "total_bytes": total_bytes,
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def copy_state_tree(source: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700, exist_ok=True)
    for current, directories, files in os.walk(source, topdown=True, followlinks=False):
        current_path = Path(current)
        relative = current_path.relative_to(source)
        target_current = destination / relative
        target_current.mkdir(parents=True, exist_ok=True, mode=0o700)
        target_current.chmod(0o700)
        directories.sort()
        files.sort()
        for name in directories:
            source_child = current_path / name
            if source_child.is_symlink() or not stat.S_ISDIR(source_child.lstat().st_mode):
                raise MigrationError(f"legacy state directory is unsafe: {source_child}")
            target_child = target_current / name
            target_child.mkdir(mode=0o700)
            target_child.chmod(0o700)
        for name in files:
            source_file = current_path / name
            metadata = source_file.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise MigrationError(f"legacy state file is unsafe: {source_file}")
            target_file = target_current / name
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            source_descriptor = os.open(source_file, flags)
            try:
                opened = os.fstat(source_descriptor)
                if not stat.S_ISREG(opened.st_mode) or (
                    opened.st_dev,
                    opened.st_ino,
                ) != (metadata.st_dev, metadata.st_ino):
                    raise MigrationError(f"legacy state file changed identity during copy: {source_file}")
                target_descriptor = os.open(
                    target_file,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                try:
                    while True:
                        chunk = os.read(source_descriptor, 1024 * 1024)
                        if not chunk:
                            break
                        view = memoryview(chunk)
                        while view:
                            written = os.write(target_descriptor, view)
                            view = view[written:]
                    os.fchmod(target_descriptor, 0o600)
                    os.fsync(target_descriptor)
                finally:
                    os.close(target_descriptor)
            finally:
                os.close(source_descriptor)
        fsync_directory(target_current)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_private(path: Path, data: bytes) -> None:
    ensure_private_directory(path.parent)
    if os.path.lexists(path):
        raise MigrationError(f"refusing to overwrite existing file: {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
        fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if os.path.lexists(temporary):
            temporary.unlink()


def migrated_environment(
    legacy: bytes,
    *,
    state_dir: Path,
    coordinator_home: Path,
    devcoordinator_root: Path,
) -> bytes:
    try:
        text = legacy.decode("utf-8")
    except UnicodeDecodeError as error:
        raise MigrationError("legacy environment is not valid UTF-8") from error
    replacements = {
        key: resolver(state_dir, coordinator_home, devcoordinator_root)
        for key, resolver in PATH_VALUES.items()
    }
    seen: set[str] = set()
    output: list[str] = []
    for line in text.splitlines(keepends=True):
        ending = "\n" if line.endswith("\n") else ""
        body = line[:-1] if ending else line
        if body.endswith("\r"):
            body = body[:-1]
            ending = "\r\n" if ending else "\r"
        match = ASSIGNMENT.match(body)
        key = match.group("key") if match else None
        if key in replacements:
            output.append(
                f"{match.group('prefix')}{key}{match.group('separator')}{replacements[key]}{ending}"
            )
            seen.add(key)
        else:
            output.append(line)
    if output and not output[-1].endswith(("\n", "\r")):
        output.append("\n")
    for key in PATH_VALUES:
        if key not in seen:
            output.append(f"{key}={replacements[key]}\n")
    return "".join(output).encode("utf-8")


def manifest_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in manifest.items() if key != "entries"}


def stage_private_file(parent: Path, prefix: str, payload: bytes) -> Path:
    ensure_private_directory(parent)
    descriptor, name = tempfile.mkstemp(prefix=prefix, dir=parent)
    path = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        return path
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        if os.path.lexists(path):
            path.unlink()
        raise


def atomic_json_replace(path: Path, value: dict[str, Any]) -> None:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = stage_private_file(path.parent, f".{path.name}.", payload)
    try:
        os.replace(temporary, path)
        path.chmod(0o600)
        fsync_directory(path.parent)
    finally:
        if os.path.lexists(temporary):
            temporary.unlink()


def install_staged_no_replace(staged: Path, destination: Path) -> None:
    """Atomically publish a private staged file without overwriting a race."""

    staged_metadata = staged.lstat()
    staged_hash = sha256_file(staged)
    published = False
    try:
        os.link(staged, destination, follow_symlinks=False)
        published = True
    except FileExistsError as error:
        raise EnvironmentAppearedError(
            f"production environment appeared during migration; refusing overwrite: {destination}"
        ) from error
    try:
        destination.chmod(0o600)
        fsync_directory(destination.parent)
        staged.unlink()
        fsync_directory(staged.parent)
    except BaseException as error:
        rollback_error: BaseException | None = None
        try:
            if published and os.path.lexists(destination):
                current = destination.lstat()
                if (
                    current.st_dev,
                    current.st_ino,
                    sha256_file(destination),
                ) != (staged_metadata.st_dev, staged_metadata.st_ino, staged_hash):
                    raise MigrationError(
                        "new environment changed after atomic publication; refusing automatic removal"
                    )
                destination.unlink()
                try:
                    fsync_directory(destination.parent)
                except OSError:
                    # The namespace rollback already succeeded. Preserve the
                    # original durability error without reintroducing the file.
                    pass
        except BaseException as caught:
            rollback_error = caught
        if rollback_error is not None:
            raise EnvironmentPublicationRollbackError(
                "environment publication failed and its no-replace rollback could not be verified"
            ) from error
        raise


def prepare_state_stage(
    *, legacy_state: Path, state_dir: Path
) -> tuple[Path, dict[str, Any], dict[str, Any], dict[str, Any]]:
    source_before = tree_manifest(legacy_state)
    ensure_private_directory(state_dir.parent)
    staging = Path(tempfile.mkdtemp(prefix=f".{state_dir.name}.migration-", dir=state_dir.parent))
    staging.chmod(0o700)
    try:
        copy_state_tree(legacy_state, staging)
        source_after = tree_manifest(legacy_state)
        copied = tree_manifest(staging)
        if source_after != source_before:
            raise MigrationError("legacy state changed during copy; destination was not replaced")
        if copied != source_before:
            raise MigrationError("staged state checksum/counts do not match the legacy source")

        augmentations: list[str] = []
        acme = staging / "acme"
        if not acme.exists():
            acme.mkdir(mode=0o700)
            augmentations.append("acme/")
        acme.chmod(0o700)
        for current, directories, files in os.walk(staging, topdown=False, followlinks=False):
            current_path = Path(current)
            for name in directories:
                (current_path / name).chmod(0o700)
            for name in files:
                (current_path / name).chmod(0o600)
            current_path.chmod(0o700)
            fsync_directory(current_path)
        destination_manifest = tree_manifest(staging)
        report = {
            "source": manifest_summary(source_before),
            "copied_legacy": manifest_summary(copied),
            "destination": manifest_summary(destination_manifest),
            "augmentations": augmentations,
        }
        return staging, source_before, destination_manifest, report
    except BaseException:
        if os.path.lexists(staging):
            shutil.rmtree(staging)
        raise


def reject_nested_paths(paths: list[tuple[str, Path]]) -> None:
    for index, (left_label, left) in enumerate(paths):
        for right_label, right in paths[index + 1 :]:
            if within(left, right) or within(right, left):
                raise MigrationError(
                    f"migration paths must not be nested: {left_label}={left}, {right_label}={right}"
                )


def commit_environment_only(
    *,
    env_file: Path,
    env_payload: bytes,
    legacy_bytes: bytes,
    legacy_env_hash: str,
    legacy_env: Path,
    legacy_env_snapshot: dict[str, Any],
    backup_dir: Path,
) -> dict[str, Any]:
    """Commit the preserved environment without reading mutable legacy state."""

    env_stage = stage_private_file(env_file.parent, f".{env_file.name}.migration-", env_payload)
    backup_stage = stage_private_file(backup_dir, ".legacy-console.env.", legacy_bytes)
    report = {
        "ok": True,
        "env_only": True,
        "sync_state_only": False,
        "environment_migrated": True,
        "legacy_environment_sha256": legacy_env_hash,
        "state": None,
    }
    manifest_stage = stage_private_file(
        backup_dir,
        ".migration-manifest.json.",
        (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    journal_path = backup_dir / "transaction.json"
    journal = {
        "version": 1,
        "status": "prepared",
        "env_only": True,
        "environment_sha256": hashlib.sha256(env_payload).hexdigest(),
    }
    atomic_json_replace(journal_path, journal)
    env_installed = False
    backup_committed = False
    manifest_committed = False
    backup_final = backup_dir / "legacy-console.env"
    manifest_final = backup_dir / "migration-manifest.json"
    try:
        require_file_snapshot(
            legacy_env,
            legacy_env_snapshot,
            "legacy Console environment",
        )
        install_staged_no_replace(env_stage, env_file)
        env_stage = Path()
        env_file.chmod(0o600)
        env_installed = True
        fsync_directory(env_file.parent)
        if hashlib.sha256(env_file.read_bytes()).hexdigest() != journal["environment_sha256"]:
            raise MigrationError("installed environment differs from its verified staging payload")
        journal["status"] = "environment_installed"
        atomic_json_replace(journal_path, journal)

        os.replace(backup_stage, backup_final)
        backup_stage = Path()
        backup_committed = True
        fsync_directory(backup_dir)
        os.replace(manifest_stage, manifest_final)
        manifest_stage = Path()
        manifest_committed = True
        fsync_directory(backup_dir)
        require_file_snapshot(
            legacy_env,
            legacy_env_snapshot,
            "legacy Console environment",
        )
        journal["status"] = "committed"
        atomic_json_replace(journal_path, journal)
        return report
    except BaseException as error:
        rollback_error: BaseException | None = None
        try:
            if env_installed and os.path.lexists(env_file):
                if hashlib.sha256(env_file.read_bytes()).hexdigest() != journal["environment_sha256"]:
                    raise MigrationError("installed environment changed; refusing automatic removal")
                env_file.unlink()
                fsync_directory(env_file.parent)
            if backup_committed and os.path.lexists(backup_final):
                backup_final.unlink()
            if manifest_committed and os.path.lexists(manifest_final):
                manifest_final.unlink()
            if isinstance(error, EnvironmentPublicationRollbackError):
                raise error
            journal["status"] = "rolled_back"
            journal["error_type"] = type(error).__name__
            atomic_json_replace(journal_path, journal)
        except BaseException as caught:
            rollback_error = caught
            journal["status"] = "rollback_failed"
            journal["rollback_error_type"] = type(caught).__name__
            try:
                atomic_json_replace(journal_path, journal)
            except BaseException:
                pass
        if rollback_error is not None:
            raise MigrationError(
                f"environment migration failed ({type(error).__name__}); rollback failed; inspect {backup_dir}"
            ) from error
        raise MigrationError(
            f"environment migration failed and was rolled back: {type(error).__name__}: {error}"
        ) from error
    finally:
        for temporary in (env_stage, backup_stage, manifest_stage):
            if temporary != Path() and os.path.lexists(temporary):
                temporary.unlink()


def migrate(
    *,
    legacy_env: Path,
    legacy_state: Path,
    env_file: Path,
    state_dir: Path,
    coordinator_home: Path,
    devcoordinator_root: Path,
    backup_dir: Path,
    sync_state_only: bool,
    env_only: bool = False,
) -> dict[str, Any]:
    if sync_state_only and env_only:
        raise MigrationError("--sync-state-only and --env-only are mutually exclusive")
    legacy_env = absolute_path(legacy_env, "legacy environment")
    legacy_state = absolute_path(legacy_state, "legacy state")
    env_file = absolute_path(env_file, "environment file")
    state_dir = absolute_path(state_dir, "state directory")
    coordinator_home = absolute_path(coordinator_home, "coordinator home")
    devcoordinator_root = absolute_path(devcoordinator_root, "DevCoordinator checkout")
    backup_dir = absolute_path(backup_dir, "backup directory")
    devcoordinator_root = require_directory(devcoordinator_root, "DevCoordinator checkout")
    for label, path in (
        ("state", state_dir),
        ("environment", env_file),
        ("coordinator", coordinator_home),
        ("backup", backup_dir),
    ):
        if within(path.resolve(strict=False), devcoordinator_root.resolve(strict=True)):
            raise MigrationError(f"{label} path must stay outside the DevCoordinator checkout: {path}")
    if not env_only:
        legacy_state = require_directory(legacy_state, "legacy Console state")
        reject_nested_paths(
            [
                ("legacy state", legacy_state.resolve(strict=True)),
                ("destination state", state_dir.resolve(strict=False)),
                ("backup", backup_dir.resolve(strict=False)),
            ]
        )
    if within(env_file.resolve(strict=False), backup_dir.resolve(strict=False)):
        raise MigrationError("environment file must not be inside the migration backup")
    coordinator_home = ensure_private_directory(coordinator_home)
    backup_existed = os.path.lexists(backup_dir)
    backup_dir = ensure_private_directory(backup_dir)
    if backup_existed and any(backup_dir.iterdir()):
        raise MigrationError(f"migration backup directory must be empty: {backup_dir}")
    ensure_private_directory(env_file.parent)
    ensure_private_directory(state_dir.parent)
    if backup_dir.stat().st_dev != state_dir.parent.stat().st_dev:
        raise MigrationError("state backup and destination must share a filesystem for atomic rollback")

    env_payload: bytes | None = None
    legacy_env_hash: str | None = None
    legacy_env_snapshot: dict[str, Any] | None = None
    if not sync_state_only:
        legacy_env = require_regular(legacy_env, "legacy Console environment")
        if os.path.lexists(env_file):
            raise MigrationError(f"refusing to overwrite existing production environment: {env_file}")
        legacy_env_snapshot = file_snapshot(legacy_env, "legacy Console environment")
        legacy_bytes = legacy_env.read_bytes()
        legacy_env_hash = legacy_env_snapshot["sha256"]
        if hashlib.sha256(legacy_bytes).hexdigest() != legacy_env_hash:
            raise MigrationError("legacy Console environment changed while it was read")
        env_payload = migrated_environment(
            legacy_bytes,
            state_dir=state_dir,
            coordinator_home=coordinator_home,
            devcoordinator_root=devcoordinator_root,
        )

    if env_only:
        assert env_payload is not None and legacy_env_hash is not None and legacy_env_snapshot is not None
        return commit_environment_only(
            env_file=env_file,
            env_payload=env_payload,
            legacy_bytes=legacy_bytes,
            legacy_env_hash=legacy_env_hash,
            legacy_env=legacy_env,
            legacy_env_snapshot=legacy_env_snapshot,
            backup_dir=backup_dir,
        )

    state_stage, source_manifest, destination_manifest, state_report = prepare_state_stage(
        legacy_state=legacy_state,
        state_dir=state_dir,
    )
    state_existed = os.path.lexists(state_dir)
    if state_existed:
        no_symlink_components(state_dir)
        if not stat.S_ISDIR(state_dir.lstat().st_mode):
            shutil.rmtree(state_stage)
            raise MigrationError(f"destination state must be a real directory: {state_dir}")
    state_before = backup_dir / "state-before"
    failed_new_state = backup_dir / "state-after-failed-transaction"
    if os.path.lexists(state_before) or os.path.lexists(failed_new_state):
        shutil.rmtree(state_stage)
        raise MigrationError("migration rollback paths already exist")

    env_stage = Path()
    legacy_env_stage = Path()
    if env_payload is not None:
        env_stage = stage_private_file(env_file.parent, f".{env_file.name}.migration-", env_payload)
        legacy_env_stage = stage_private_file(backup_dir, ".legacy-console.env.", legacy_bytes)

    report = {
        "ok": True,
        "sync_state_only": sync_state_only,
        "environment_migrated": env_payload is not None,
        "legacy_environment_sha256": legacy_env_hash,
        "state": {**state_report, "previous_state_preserved": state_existed},
    }
    manifest_stage = stage_private_file(
        backup_dir,
        ".migration-manifest.json.",
        (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    journal_path = backup_dir / "transaction.json"
    journal = {
        "version": 1,
        "status": "prepared",
        "sync_state_only": sync_state_only,
        "state_existed": state_existed,
        "state_source_sha256": state_report["source"]["sha256"],
        "state_destination_sha256": state_report["destination"]["sha256"],
        "environment_sha256": hashlib.sha256(env_payload).hexdigest() if env_payload is not None else None,
    }
    atomic_json_replace(journal_path, journal)

    state_backup_moved = False
    state_installed = False
    env_installed = False
    legacy_env_committed = False
    manifest_committed = False
    legacy_env_final = backup_dir / "legacy-console.env"
    manifest_final = backup_dir / "migration-manifest.json"
    try:
        journal["status"] = "applying"
        atomic_json_replace(journal_path, journal)
        if tree_manifest(legacy_state) != source_manifest:
            raise MigrationError("legacy state changed after staging; destination was not replaced")
        if legacy_env_snapshot is not None:
            require_file_snapshot(
                legacy_env,
                legacy_env_snapshot,
                "legacy Console environment",
            )
        if state_existed:
            os.replace(state_dir, state_before)
            state_backup_moved = True
            fsync_directory(state_dir.parent)
            fsync_directory(backup_dir)
            journal["status"] = "state_backup_moved"
            atomic_json_replace(journal_path, journal)

        os.replace(state_stage, state_dir)
        state_stage = Path()
        state_installed = True
        fsync_directory(state_dir.parent)
        if tree_manifest(state_dir) != destination_manifest:
            raise MigrationError("installed state differs from the verified staged state")
        journal["status"] = "state_installed"
        atomic_json_replace(journal_path, journal)

        if env_payload is not None:
            install_staged_no_replace(env_stage, env_file)
            env_stage = Path()
            env_file.chmod(0o600)
            env_installed = True
            fsync_directory(env_file.parent)
            if hashlib.sha256(env_file.read_bytes()).hexdigest() != journal["environment_sha256"]:
                raise MigrationError("installed environment differs from its verified staging payload")
            journal["status"] = "environment_installed"
            atomic_json_replace(journal_path, journal)

            os.replace(legacy_env_stage, legacy_env_final)
            legacy_env_stage = Path()
            legacy_env_committed = True
            fsync_directory(backup_dir)

        os.replace(manifest_stage, manifest_final)
        manifest_stage = Path()
        manifest_committed = True
        fsync_directory(backup_dir)
        if tree_manifest(legacy_state) != source_manifest:
            raise MigrationError("legacy state changed before migration commit")
        if legacy_env_snapshot is not None:
            require_file_snapshot(
                legacy_env,
                legacy_env_snapshot,
                "legacy Console environment",
            )
        journal["status"] = "committed"
        atomic_json_replace(journal_path, journal)
        return report
    except BaseException as error:
        rollback_errors: list[str] = []
        try:
            if env_installed and os.path.lexists(env_file):
                if hashlib.sha256(env_file.read_bytes()).hexdigest() != journal["environment_sha256"]:
                    raise MigrationError("installed environment changed; refusing automatic removal")
                env_file.unlink()
                fsync_directory(env_file.parent)
            if state_installed and os.path.lexists(state_dir):
                if tree_manifest(state_dir) != destination_manifest:
                    raise MigrationError("installed state changed; refusing automatic rollback")
                os.replace(state_dir, failed_new_state)
                fsync_directory(state_dir.parent)
                fsync_directory(backup_dir)
            if state_backup_moved and os.path.lexists(state_before):
                os.replace(state_before, state_dir)
                fsync_directory(state_dir.parent)
                fsync_directory(backup_dir)
            if legacy_env_committed and os.path.lexists(legacy_env_final):
                legacy_env_final.unlink()
            if manifest_committed and os.path.lexists(manifest_final):
                manifest_final.unlink()
            if isinstance(error, EnvironmentPublicationRollbackError):
                raise error
            journal["status"] = "rolled_back"
            journal["error_type"] = type(error).__name__
            atomic_json_replace(journal_path, journal)
        except BaseException as rollback_error:
            rollback_errors.append(f"{type(rollback_error).__name__}: {rollback_error}")
            journal["status"] = "rollback_failed"
            journal["error_type"] = type(error).__name__
            journal["rollback_error"] = rollback_errors[0]
            try:
                atomic_json_replace(journal_path, journal)
            except BaseException:
                pass
        if rollback_errors:
            raise MigrationError(
                f"migration failed ({type(error).__name__}); automatic rollback failed; inspect {backup_dir}"
            ) from error
        raise MigrationError(f"migration failed and was rolled back: {type(error).__name__}: {error}") from error
    finally:
        for temporary in (state_stage, env_stage, legacy_env_stage, manifest_stage):
            if temporary == Path() or not os.path.lexists(temporary):
                continue
            if temporary.is_dir() and not temporary.is_symlink():
                shutil.rmtree(temporary)
            else:
                temporary.unlink()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-env", required=True)
    parser.add_argument("--legacy-state", required=True)
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--coordinator-home", required=True)
    parser.add_argument("--devcoordinator-root", required=True)
    parser.add_argument("--backup-dir", required=True)
    phase = parser.add_mutually_exclusive_group()
    phase.add_argument("--sync-state-only", action="store_true")
    phase.add_argument("--env-only", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = migrate(
            legacy_env=absolute_path(args.legacy_env, "legacy environment"),
            legacy_state=absolute_path(args.legacy_state, "legacy state"),
            env_file=absolute_path(args.env_file, "environment file"),
            state_dir=absolute_path(args.state_dir, "state directory"),
            coordinator_home=absolute_path(args.coordinator_home, "coordinator home"),
            devcoordinator_root=absolute_path(args.devcoordinator_root, "DevCoordinator checkout"),
            backup_dir=absolute_path(args.backup_dir, "backup directory"),
            sync_state_only=args.sync_state_only,
            env_only=args.env_only,
        )
    except (MigrationError, OSError, UnicodeError) as error:
        print(f"legacy Console migration failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True) if args.json else "legacy Console runtime migration ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
