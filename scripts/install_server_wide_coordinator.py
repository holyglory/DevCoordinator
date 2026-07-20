#!/usr/bin/env python3
"""Install or roll back the server-wide DevCoordinator system boundary.

The installer deliberately does not start the broker.  Enroll exact users,
repositories, and server allowlists first, then enable the unit.  Runtime users
need no sudo after installation: they reach the service through the 0660 Unix
socket and their Codex/Claude skills are direct links to this repository.
The complete explicit client set also owns one replacement-style systemd
drop-in containing only those clients' canonical home write exceptions.
"""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
import uuid
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ACCESS_GROUP = "devcoordinator-clients"
SERVICE_USER = "root"
SYSTEM_FILES = {
    ROOT / "deploy/devcoordinator.sysusers.conf": Path(
        "/etc/sysusers.d/devcoordinator.conf"
    ),
    ROOT / "deploy/devcoordinator.tmpfiles.conf": Path(
        "/etc/tmpfiles.d/devcoordinator.conf"
    ),
    ROOT / "deploy/devcoordinator-broker.service": Path(
        "/etc/systemd/system/devcoordinator-broker.service"
    ),
}
BROKER_UNIT_SOURCE = ROOT / "deploy/devcoordinator-broker.service"
ENROLLED_HOME_DROPIN = Path(
    "/etc/systemd/system/devcoordinator-broker.service.d/80-enrolled-home-write-paths.conf"
)
ENROLLED_HOME_DROPIN_SOURCE = "generated:enrolled-home-write-paths"
BASE_READ_WRITE_PATHS = "/var/lib/devcoordinator /run/devcoordinator"
BROKER_UNIT_REQUIRED_SANDBOX = {
    "UMask": "UMask=0077",
    "NoNewPrivileges": "NoNewPrivileges=true",
    "PrivateTmp": "PrivateTmp=true",
    "ProtectSystem": "ProtectSystem=strict",
    "ProtectHome": "ProtectHome=read-only",
    "ReadWritePaths": f"ReadWritePaths={BASE_READ_WRITE_PATHS}",
}
SKILL_SOURCE = ROOT / "skills/codex-dev-coordinator"
JOURNAL_NAME = "install-journal.json"
LEGACY_DOCKER_DROPIN = Path(
    "/etc/systemd/system/devcoordinator-broker.service.d/90-docker-config.conf"
)
LEGACY_DOCKER_DROPIN_CONTENT = (
    b"[Service]\nEnvironment=DOCKER_CONFIG=/var/lib/devcoordinator/docker\n"
)
LEGACY_DOCKER_DROPIN_BACKUP_NAME = "legacy-broker-90-docker-config.conf"
RUNTIME_DEPENDENCY_ENVIRONMENT = {
    "DEVCOORDINATOR_AUTHORITY": "service",
    "DOCKER_CONFIG": "/var/lib/devcoordinator/docker",
    "HOME": "/root",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
}
SYSTEM_OWNER_UID = 0
SYSTEM_OWNER_GID = 0
SYSTEM_PYTHON = Path("/usr/bin/python3")
RUNTIME_DEPENDENCY_CHECK = (
    SKILL_SOURCE / "scripts/validate_runtime_dependencies.py"
)
RUNTIME_DEPENDENCY_CONTRACT = "devcoordinator-broker-runtime-v1"
COMPOSE_VERSION_REQUIREMENT = "stable >=2.17,<3 or >=5,<6"
AUTHORITY_DATABASE_PATH = Path("/var/lib/devcoordinator/coordinator.sqlite3")
CLIENT_PROFILE_PATH = Path("/etc/devcoordinator/client-profiles.json")
PROFILE_DATABASE_ENROLLMENT_DRIFT = "profile_database_enrollment_drift"


class InstallError(RuntimeError):
    pass


class ProfileDatabaseEnrollmentDrift(InstallError):
    """The protected client profile promises access absent from service state."""

    code = PROFILE_DATABASE_ENROLLMENT_DRIFT


def validate_broker_unit_source(path: Path = BROKER_UNIT_SOURCE) -> None:
    """Refuse to install a broker unit with a weakened production boundary."""

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise InstallError(f"cannot read broker unit source: {path}: {error}") from error
    current_section = ""
    located: dict[str, list[tuple[str, str]]] = {
        key: [] for key in BROKER_UNIT_REQUIRED_SANDBOX
    }
    capability_directives: list[tuple[str, str]] = []
    filesystem_override_directives: list[tuple[str, str]] = []
    for raw_line in lines:
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1]
            continue
        for key in located:
            if line.startswith(f"{key}="):
                located[key].append((current_section, line))
        if line.startswith(("AmbientCapabilities=", "CapabilityBoundingSet=")):
            capability_directives.append((current_section, line))
        if line.startswith(("ReadOnlyPaths=", "BindPaths=", "BindReadOnlyPaths=")):
            filesystem_override_directives.append((current_section, line))
    for key, expected in BROKER_UNIT_REQUIRED_SANDBOX.items():
        if located[key] != [("Service", expected)]:
            raise InstallError(
                f"broker unit must contain exactly one pinned {key} directive in Service"
            )
    if capability_directives:
        raise InstallError(
            "broker unit must inherit the manager capability ceiling with no ambient set"
        )
    if filesystem_override_directives:
        raise InstallError(
            "broker unit must not add bind/read-only filesystem overrides"
        )


def runtime_dependency_evidence() -> dict[str, Any]:
    """Capture bounded evidence from the exact isolated service preflight."""

    if not SYSTEM_PYTHON.is_file():
        return {"ok": False, "code": "system_python_missing"}
    if not RUNTIME_DEPENDENCY_CHECK.is_file() or RUNTIME_DEPENDENCY_CHECK.is_symlink():
        return {"ok": False, "code": "runtime_dependency_check_missing"}
    try:
        completed = subprocess.run(
            [str(SYSTEM_PYTHON), "-I", str(RUNTIME_DEPENDENCY_CHECK)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=dict(RUNTIME_DEPENDENCY_ENVIRONMENT),
            timeout=35,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"ok": False, "code": "runtime_dependency_check_unavailable"}
    try:
        evidence = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "code": "runtime_dependency_evidence_invalid"}
    if not isinstance(evidence, dict):
        return {"ok": False, "code": "runtime_dependency_evidence_invalid"}
    if completed.returncode and evidence.get("ok") is True:
        return {"ok": False, "code": "runtime_dependency_evidence_invalid"}
    return evidence


def runtime_dependency_failure(
    evidence: dict[str, Any] | None = None,
) -> str | None:
    """Explain a failed exact-system-Python and Compose capability proof."""

    current = runtime_dependency_evidence() if evidence is None else evidence
    if current.get("ok") is True:
        compose = current.get("docker_compose")
        pyyaml = current.get("pyyaml")
        requirements = current.get("requirements")
        required_capabilities = (
            "config_json",
            "multiple_explicit_env_files",
            "second_env_file_override",
            "implicit_dotenv_suppressed",
        )
        if (
            current.get("contract") == RUNTIME_DEPENDENCY_CONTRACT
            and requirements
            == {
                "pyyaml": "6.x",
                "docker_compose": COMPOSE_VERSION_REQUIREMENT,
            }
            and isinstance(pyyaml, dict)
            and pyyaml.get("detected_major") == "6"
            and isinstance(compose, dict)
            and isinstance(compose.get("docker_cli"), str)
            and Path(str(compose["docker_cli"])).is_absolute()
            and isinstance(compose.get("version"), str)
            and all(compose.get(name) is True for name in required_capabilities)
        ):
            return None
        return "the broker runtime dependency check returned invalid success evidence"
    code = str(current.get("code") or "")
    if code == "system_python_missing":
        return "the broker system Python /usr/bin/python3 is missing or unsafe"
    if code == "runtime_dependency_check_missing":
        return "the broker runtime dependency check is missing or unsafe"
    if code.startswith("pyyaml_"):
        return (
            "the broker system Python does not provide PyYAML 6.x; install the "
            "distribution python3-yaml package (or an equivalent system package)"
        )
    if code == "docker_cli_unavailable":
        return (
            "the broker cannot resolve an exact Docker CLI executable; install "
            "Docker or configure an absolute executable with CODEX_DOCKER_CLI"
        )
    if code.startswith("compose_version_"):
        return (
            "the Docker Compose plugin must be "
            f"{COMPOSE_VERSION_REQUIREMENT}; legacy v1, Compose 2.0-2.16, "
            "majors 3/4, unknown versions, and prereleases are unsupported"
        )
    if code.startswith("compose_capability_") or code in {
        "compose_second_env_file_override_unavailable",
        "compose_implicit_dotenv_not_suppressed",
    }:
        return (
            "the Docker Compose plugin did not prove the required non-mutating "
            "config contract: JSON output, two ordered explicit environment "
            "files, second-file override, and implicit .env suppression"
        )
    return "the broker runtime dependency check returned invalid evidence"


def require_runtime_dependencies() -> None:
    evidence = runtime_dependency_evidence()
    failure = runtime_dependency_failure(evidence)
    if failure is not None:
        raise InstallError(failure)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def require_real(path: Path, *, directory: bool) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    metadata = absolute.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raise InstallError(f"path must not be a symlink: {absolute}")
    if directory != stat.S_ISDIR(metadata.st_mode):
        raise InstallError(f"unexpected path type: {absolute}")
    if absolute.resolve(strict=True) != absolute:
        raise InstallError(f"path contains a symlink component: {absolute}")
    return absolute


def require_protected_directory(
    path: Path, *, label: str, private: bool = False
) -> Path:
    absolute = require_real(path, directory=True)
    metadata = absolute.lstat()
    if metadata.st_uid != SYSTEM_OWNER_UID or metadata.st_gid != SYSTEM_OWNER_GID:
        raise InstallError(f"{label} has an unexpected owner: {absolute}")
    forbidden_mode = 0o077 if private else 0o022
    if stat.S_IMODE(metadata.st_mode) & forbidden_mode:
        raise InstallError(f"{label} has unsafe permissions: {absolute}")
    return absolute


def require_private_regular(path: Path, *, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise InstallError(f"{label} is missing: {path}") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != SYSTEM_OWNER_UID
        or metadata.st_gid != SYSTEM_OWNER_GID
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or path.resolve(strict=True) != path
    ):
        raise InstallError(f"{label} is unsafe: {path}")
    return metadata


def path_lexists(path: Path) -> bool:
    return os.path.lexists(os.fspath(path))


def _read_descriptor(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 64 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _write_descriptor(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise InstallError("short write while preserving the legacy broker drop-in")
        remaining = remaining[written:]


def _legacy_dropin_parent() -> Path | None:
    """Return a proved-real drop-in parent, or None when it is absent."""

    destination = Path(os.path.abspath(os.fspath(LEGACY_DOCKER_DROPIN)))
    if destination != LEGACY_DOCKER_DROPIN:
        raise InstallError("legacy broker drop-in path must remain absolute and canonical")
    # Prove the fixed systemd unit directory even when the optional .d directory
    # does not exist. A symlinked .d path is never treated as harmless absence.
    require_protected_directory(
        destination.parent.parent,
        label="systemd unit directory",
    )
    if not path_lexists(destination.parent):
        return None
    return require_protected_directory(
        destination.parent,
        label="legacy broker drop-in directory",
    )


def inspect_legacy_docker_dropin() -> dict[str, int | str] | None:
    """Prove the one legacy file is the exact known migration input."""

    destination = LEGACY_DOCKER_DROPIN
    parent = _legacy_dropin_parent()
    if parent is None:
        return None
    if not path_lexists(destination):
        return None
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    file_flags |= getattr(os, "O_NOFOLLOW", 0)
    parent_descriptor = -1
    descriptor = -1
    try:
        parent_descriptor = os.open(parent, directory_flags)
        descriptor = os.open(destination.name, file_flags, dir_fd=parent_descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise InstallError(
                f"legacy broker drop-in must be a regular file: {destination}"
            )
        if (
            metadata.st_uid != SYSTEM_OWNER_UID
            or metadata.st_gid != SYSTEM_OWNER_GID
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise InstallError(
                f"legacy broker drop-in has unsafe ownership or permissions: {destination}"
            )
        payload = _read_descriptor(descriptor)
        current = os.stat(
            destination.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise InstallError(
                f"legacy broker drop-in changed during inspection: {destination}"
            )
        if destination.resolve(strict=True) != destination:
            raise InstallError(
                f"legacy broker drop-in contains a symlink component: {destination}"
            )
    except InstallError:
        raise
    except OSError as error:
        raise InstallError(f"legacy broker drop-in is unsafe: {destination}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)
    if payload != LEGACY_DOCKER_DROPIN_CONTENT:
        raise InstallError(
            "legacy broker Docker drop-in has drift or extra directives; refusing migration"
        )
    return {
        "destination": str(destination),
        "sha256": digest_bytes(payload),
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }


def _private_transaction(transaction: Path) -> Path:
    transaction = require_protected_directory(
        transaction,
        label="installation transaction",
        private=True,
    )
    require_protected_directory(
        transaction.parent,
        label="installation transaction parent",
    )
    return transaction


def prepare_legacy_docker_dropin_removal(
    transaction: Path,
) -> dict[str, int | str] | None:
    """Back up the exact legacy drop-in before journaling a removal intent."""

    transaction = _private_transaction(transaction)
    observed = inspect_legacy_docker_dropin()
    if observed is None:
        return None
    backup = transaction / LEGACY_DOCKER_DROPIN_BACKUP_NAME
    if path_lexists(backup):
        raise InstallError(f"legacy broker drop-in backup already exists: {backup}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(backup, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        _write_descriptor(descriptor, LEGACY_DOCKER_DROPIN_CONTENT)
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        backup.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    observed["backup"] = str(backup)
    return observed


def _validate_legacy_dropin_entry(
    entry: dict[str, Any], transaction: Path
) -> tuple[Path, bytes]:
    transaction = _private_transaction(transaction)
    expected_keys = {
        "destination",
        "backup",
        "sha256",
        "mode",
        "uid",
        "gid",
        "device",
        "inode",
    }
    if set(entry) != expected_keys:
        raise InstallError("legacy broker drop-in journal entry has unexpected fields")
    backup = transaction / LEGACY_DOCKER_DROPIN_BACKUP_NAME
    if entry.get("destination") != str(LEGACY_DOCKER_DROPIN) or entry.get(
        "backup"
    ) != str(backup):
        raise InstallError("legacy broker drop-in journal targets an unexpected path")
    if entry.get("sha256") != digest_bytes(LEGACY_DOCKER_DROPIN_CONTENT):
        raise InstallError("legacy broker drop-in journal has an unexpected digest")
    for key in ("mode", "uid", "gid", "device", "inode"):
        if type(entry.get(key)) is not int or int(entry[key]) < 0:
            raise InstallError(f"legacy broker drop-in journal has invalid {key}")
    if int(entry["mode"]) > 0o7777:
        raise InstallError("legacy broker drop-in journal has an invalid mode")
    require_private_regular(backup, label="legacy broker drop-in backup")
    payload = backup.read_bytes()
    if payload != LEGACY_DOCKER_DROPIN_CONTENT:
        raise InstallError(f"legacy broker drop-in backup has drifted: {backup}")
    return backup, payload


def remove_prepared_legacy_docker_dropin(
    entry: dict[str, Any], transaction: Path
) -> None:
    """Unlink only the same inode that was proved and privately backed up."""

    _validate_legacy_dropin_entry(entry, transaction)
    observed = inspect_legacy_docker_dropin()
    if observed is None:
        raise InstallError("legacy broker drop-in disappeared before removal")
    for key in ("destination", "sha256", "mode", "uid", "gid", "device", "inode"):
        if observed[key] != entry[key]:
            raise InstallError("legacy broker drop-in changed after it was backed up")
    parent = _legacy_dropin_parent()
    if parent is None:
        raise InstallError("legacy broker drop-in parent disappeared before removal")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(parent, directory_flags)
    try:
        current = os.stat(
            LEGACY_DOCKER_DROPIN.name,
            dir_fd=descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino)
            != (int(entry["device"]), int(entry["inode"]))
        ):
            raise InstallError("legacy broker drop-in changed immediately before removal")
        os.unlink(LEGACY_DOCKER_DROPIN.name, dir_fd=descriptor)
        os.fsync(descriptor)
    except InstallError:
        raise
    except OSError as error:
        raise InstallError("could not remove the proved legacy broker drop-in") from error
    finally:
        os.close(descriptor)


def restore_legacy_docker_dropin(
    entry: dict[str, Any], transaction: Path
) -> None:
    """Restore the one journaled drop-in without overwriting external drift."""

    _backup, payload = _validate_legacy_dropin_entry(entry, transaction)
    observed = inspect_legacy_docker_dropin()
    if observed is not None:
        for key in ("sha256", "mode", "uid", "gid"):
            if observed[key] != entry[key]:
                raise InstallError("existing legacy broker drop-in differs during rollback")
        return
    parent = _legacy_dropin_parent()
    if parent is None:
        raise InstallError("legacy broker drop-in parent is missing during rollback")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(parent, directory_flags)
    temporary_name = f".{LEGACY_DOCKER_DROPIN.name}.{uuid.uuid4().hex}.tmp"
    temporary_descriptor = -1
    linked = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        temporary_descriptor = os.open(
            temporary_name,
            flags,
            0o600,
            dir_fd=descriptor,
        )
        _write_descriptor(temporary_descriptor, payload)
        os.fchown(temporary_descriptor, int(entry["uid"]), int(entry["gid"]))
        os.fchmod(temporary_descriptor, int(entry["mode"]))
        os.fsync(temporary_descriptor)
        os.close(temporary_descriptor)
        temporary_descriptor = -1
        # A hard-link publication provides no-replace semantics: an external
        # file appearing after the absence check makes rollback fail closed.
        os.link(
            temporary_name,
            LEGACY_DOCKER_DROPIN.name,
            src_dir_fd=descriptor,
            dst_dir_fd=descriptor,
            follow_symlinks=False,
        )
        linked = True
        os.unlink(temporary_name, dir_fd=descriptor)
        os.fsync(descriptor)
    except OSError as error:
        raise InstallError("could not safely restore the legacy broker drop-in") from error
    finally:
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        if not linked:
            try:
                os.unlink(temporary_name, dir_fd=descriptor)
            except FileNotFoundError:
                pass
        os.close(descriptor)
    restored = inspect_legacy_docker_dropin()
    if restored is None or any(
        restored[key] != entry[key] for key in ("sha256", "mode", "uid", "gid")
    ):
        raise InstallError("legacy broker drop-in restoration did not verify")


def command(name: str) -> str:
    resolved = shutil.which(name)
    if not resolved:
        raise InstallError(f"required system command is unavailable: {name}")
    return resolved


def run(*arguments: str) -> None:
    completed = subprocess.run(
        list(arguments),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode:
        raise InstallError(
            f"command failed ({' '.join(arguments)}): {completed.stderr.strip()}"
        )


def capture(*arguments: str) -> bytes:
    completed = subprocess.run(
        list(arguments),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode:
        raise InstallError(
            f"command failed ({' '.join(arguments)}): "
            f"{completed.stderr.decode('utf-8', errors='replace').strip()}"
        )
    return completed.stdout


def client_records(names: list[str]) -> list[Any]:
    if not names:
        raise InstallError("at least one explicit --client-user is required")
    records = []
    for name in dict.fromkeys(names):
        try:
            record = pwd.getpwnam(name)
        except KeyError as error:
            raise InstallError(f"client account does not exist: {name}") from error
        home = require_real(Path(record.pw_dir), directory=True)
        records.append((record, home))
    return records


def validate_home_write_path_tokens(paths: list[Path]) -> list[Path]:
    normalized = sorted(set(paths), key=os.fspath)
    if not normalized:
        raise InstallError("at least one enrolled client home is required")
    if normalized != paths:
        raise InstallError("enrolled client homes must be unique and sorted")
    for home in normalized:
        if home.parent != Path("/home") or not re.fullmatch(
            r"[A-Za-z0-9._+-]+", home.name
        ):
            raise InstallError(
                f"enrolled client home is not one safe direct /home child: {home}"
            )
    return normalized


def enrolled_home_write_paths(clients: list[Any]) -> list[Path]:
    homes: list[Path] = []
    for record, home in clients:
        canonical = require_real(home, directory=True)
        metadata = canonical.lstat()
        if metadata.st_uid != record.pw_uid:
            raise InstallError(
                f"client home is not owned by its enrolled account: {canonical}"
            )
        homes.append(canonical)
    return validate_home_write_path_tokens(sorted(set(homes), key=os.fspath))


def render_enrolled_home_dropin(paths: list[Path]) -> bytes:
    homes = validate_home_write_path_tokens(paths)
    writable = " ".join([BASE_READ_WRITE_PATHS, *(os.fspath(path) for path in homes)])
    return (
        "[Service]\n"
        "# Generated transactionally from the complete explicit --client-user set.\n"
        "ReadWritePaths=\n"
        f"ReadWritePaths={writable}\n"
    ).encode("utf-8")


def _profile_database_issue(reason: str, **details: Any) -> dict[str, Any]:
    return {"reason": reason, **details}


def _protected_regular_metadata(
    path: Path,
    *,
    label: str,
    exact_mode: int | None = None,
) -> os.stat_result:
    """Prove a root-owned, non-replaceable regular-file trust boundary."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        parent = absolute.parent.lstat()
        metadata = absolute.lstat()
    except FileNotFoundError as error:
        raise InstallError(f"{label} is missing: {absolute}") from error
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != SYSTEM_OWNER_UID
        or stat.S_IMODE(parent.st_mode) & 0o022
        or absolute.parent.resolve(strict=True) != absolute.parent
    ):
        raise InstallError(f"{label} parent is unsafe: {absolute.parent}")
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != SYSTEM_OWNER_UID
        or mode & 0o022
        or (exact_mode is not None and mode != exact_mode)
        or absolute.resolve(strict=True) != absolute
    ):
        raise InstallError(f"{label} is unsafe: {absolute}")
    return metadata


def _read_protected_profile(path: Path) -> dict[str, Any]:
    expected = _protected_regular_metadata(
        path,
        label="broker client profile",
        exact_mode=0o640,
    )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise InstallError("broker client profile changed while it was opened")
        payload = _read_descriptor(descriptor)
        if len(payload) > 8 * 1024 * 1024:
            raise InstallError("broker client profile exceeds the bounded size")
        after = os.fstat(descriptor)
        current = path.lstat()
        if (
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise InstallError("broker client profile changed while it was read")
    finally:
        os.close(descriptor)
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InstallError("broker client profile is not valid JSON") from error
    if not isinstance(document, dict):
        raise InstallError("broker client profile root must be an object")
    return document


def _current_profile_repository_enrollments(
    document: dict[str, Any], *, now_epoch: int
) -> tuple[str | None, list[dict[str, Any]], int, list[dict[str, Any]]]:
    """Return only profile promises that are current and enabled.

    Disabled or expired profile entries deliberately make no runtime-access
    promise. They therefore do not require a database row and must not prevent
    a safe restart merely because their old database evidence was removed.
    """

    issues: list[dict[str, Any]] = []
    if document.get("version") != 1:
        return None, [], 0, [_profile_database_issue("profile_version_invalid")]
    clients = document.get("clients")
    if not isinstance(clients, dict):
        return None, [], 0, [_profile_database_issue("profile_clients_invalid")]
    current: list[dict[str, Any]] = []
    ignored = 0
    seen: set[tuple[int, str]] = set()
    for uid_raw, client in sorted(clients.items(), key=lambda item: str(item[0])):
        try:
            uid = int(uid_raw)
        except (TypeError, ValueError):
            issues.append(_profile_database_issue("profile_uid_invalid"))
            continue
        if uid < 0 or str(uid) != str(uid_raw) or not isinstance(client, dict):
            issues.append(_profile_database_issue("profile_client_invalid", uid=str(uid_raw)))
            continue
        account_id = client.get("account_id")
        client_issued_at = client.get("issued_at")
        client_expiry = client.get("valid_until_epoch")
        repositories = client.get("repositories")
        if not isinstance(account_id, str) or not account_id:
            issues.append(_profile_database_issue("profile_account_invalid", uid=uid))
            continue
        if not isinstance(client_issued_at, str) or not client_issued_at:
            issues.append(_profile_database_issue("profile_issued_at_invalid", uid=uid))
            continue
        if type(client_expiry) is not int or client_expiry <= 0:
            issues.append(_profile_database_issue("profile_expiry_invalid", uid=uid))
            continue
        if not isinstance(repositories, list):
            issues.append(_profile_database_issue("profile_repositories_invalid", uid=uid))
            continue
        if now_epoch >= client_expiry:
            ignored += len(repositories)
            continue
        for index, repository in enumerate(repositories):
            if not isinstance(repository, dict):
                issues.append(
                    _profile_database_issue(
                        "profile_repository_invalid", uid=uid, index=index
                    )
                )
                continue
            enabled = repository.get("enabled", True)
            valid_until_epoch = repository.get("valid_until_epoch", client_expiry)
            if type(enabled) is not bool or type(valid_until_epoch) is not int:
                issues.append(
                    _profile_database_issue(
                        "profile_repository_lifecycle_invalid", uid=uid, index=index
                    )
                )
                continue
            if not enabled or now_epoch >= valid_until_epoch:
                ignored += 1
                continue
            repository_account = repository.get("account_id", account_id)
            issued_at = repository.get("issued_at", client_issued_at)
            repo_id = repository.get("repo_id")
            canonical_root = repository.get("canonical_root")
            generation = repository.get("generation")
            if repository_account != account_id:
                issues.append(
                    _profile_database_issue(
                        "profile_repository_account_mismatch", uid=uid, index=index
                    )
                )
                continue
            if not isinstance(issued_at, str) or not issued_at:
                issues.append(
                    _profile_database_issue(
                        "profile_repository_issued_at_invalid", uid=uid, index=index
                    )
                )
                continue
            if not isinstance(repo_id, str) or not repo_id:
                issues.append(
                    _profile_database_issue("profile_repo_id_invalid", uid=uid, index=index)
                )
                continue
            if not isinstance(canonical_root, str) or not canonical_root:
                issues.append(
                    _profile_database_issue(
                        "profile_repository_root_invalid", uid=uid, repo_id=repo_id
                    )
                )
                continue
            if type(generation) is not int or generation < 0:
                issues.append(
                    _profile_database_issue(
                        "profile_repository_generation_invalid", uid=uid, repo_id=repo_id
                    )
                )
                continue
            identity = (uid, repo_id)
            if identity in seen:
                issues.append(
                    _profile_database_issue(
                        "profile_repository_duplicate", uid=uid, repo_id=repo_id
                    )
                )
                continue
            seen.add(identity)
            current.append(
                {
                    "uid": uid,
                    "account_id": account_id,
                    "repo_id": repo_id,
                    "canonical_root": canonical_root,
                    "generation": generation,
                    "issued_at": issued_at,
                    "valid_until_epoch": valid_until_epoch,
                }
            )
    service = document.get("service")
    service_generation = (
        service.get("database_generation") if isinstance(service, dict) else None
    )
    if current and (not isinstance(service_generation, str) or not service_generation):
        issues.append(_profile_database_issue("profile_database_generation_invalid"))
        service_generation = None
    return service_generation, current, ignored, issues


def profile_database_enrollment_check(
    *,
    profile_path: Path | None = None,
    database_path: Path | None = None,
    now_epoch: int | None = None,
) -> dict[str, Any]:
    """Compare every current protected profile promise with service SQLite.

    This is deliberately a read-only installer check. It never imports the
    broker persistence module, initializes schema, or repairs state; the
    administrator must run the explicit offline enrollment backfill first.
    """

    profile_path = CLIENT_PROFILE_PATH if profile_path is None else profile_path
    database_path = AUTHORITY_DATABASE_PATH if database_path is None else database_path
    now = int(time.time()) if now_epoch is None else int(now_epoch)
    result: dict[str, Any] = {
        "ok": True,
        "code": None,
        "profile": os.fspath(profile_path),
        "database": os.fspath(database_path),
        "checked_current_enrollments": 0,
        "checked_current_database_enrollments": 0,
        "ignored_inactive_profile_enrollments": 0,
        "issues": [],
    }
    profile_absent = not path_lexists(profile_path)
    service_generation: str | None = None
    repositories: list[dict[str, Any]] = []
    ignored = 0
    issues: list[dict[str, Any]] = []
    if not profile_absent:
        try:
            document = _read_protected_profile(profile_path)
            service_generation, repositories, ignored, issues = (
                _current_profile_repository_enrollments(document, now_epoch=now)
            )
        except (InstallError, OSError, ValueError) as error:
            issues = [
                _profile_database_issue("profile_unavailable", detail=str(error))
            ]
    result["ignored_inactive_profile_enrollments"] = ignored
    if repositories and not path_lexists(database_path):
        issues.append(_profile_database_issue("database_missing"))
    database_current_enrollments = 0
    if path_lexists(database_path):
        try:
            expected_database = _protected_regular_metadata(
                database_path,
                label="service authority database",
            )
            connection = sqlite3.connect(
                f"{database_path.resolve(strict=True).as_uri()}?mode=ro",
                uri=True,
                isolation_level=None,
                timeout=5.0,
            )
            connection.row_factory = sqlite3.Row
            try:
                connection.execute("PRAGMA query_only = ON")
                connection.execute("BEGIN")
                enrollment_table = connection.execute(
                    """
                    SELECT 1
                    FROM sqlite_master
                    WHERE type = 'table' AND name = 'broker_repository_enrollments'
                    """
                ).fetchone()
                if repositories:
                    generation_row = connection.execute(
                        "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
                    ).fetchone()
                    if generation_row is None:
                        issues.append(
                            _profile_database_issue("database_generation_missing")
                        )
                    elif str(generation_row["database_generation"]) != service_generation:
                        issues.append(
                            _profile_database_issue("database_generation_mismatch")
                        )
                    if enrollment_table is None:
                        issues.append(_profile_database_issue("enrollment_table_missing"))
                for repository in repositories:
                    uid = int(repository["uid"])
                    repo_id = str(repository["repo_id"])
                    principal = connection.execute(
                        "SELECT account_id, enabled FROM broker_acl_principals WHERE uid = ?",
                        (uid,),
                    ).fetchone()
                    if principal is None:
                        issues.append(
                            _profile_database_issue("principal_missing", uid=uid, repo_id=repo_id)
                        )
                    else:
                        if not bool(principal["enabled"]):
                            issues.append(
                                _profile_database_issue(
                                    "principal_disabled", uid=uid, repo_id=repo_id
                                )
                            )
                        if str(principal["account_id"]) != repository["account_id"]:
                            issues.append(
                                _profile_database_issue(
                                    "principal_account_mismatch", uid=uid, repo_id=repo_id
                                )
                            )
                    stored_repository = connection.execute(
                        """
                        SELECT r.canonical_root, r.state, r.generation,
                               i.status AS installation_status, i.startup_fenced
                        FROM repositories r
                        LEFT JOIN repository_installations i USING(repo_id)
                        WHERE r.repo_id = ?
                        """,
                        (repo_id,),
                    ).fetchone()
                    if stored_repository is None:
                        issues.append(
                            _profile_database_issue(
                                "repository_missing", uid=uid, repo_id=repo_id
                            )
                        )
                    else:
                        if (
                            str(stored_repository["canonical_root"])
                            != repository["canonical_root"]
                        ):
                            issues.append(
                                _profile_database_issue(
                                    "repository_root_mismatch", uid=uid, repo_id=repo_id
                                )
                            )
                        if str(stored_repository["state"]) != "active":
                            issues.append(
                                _profile_database_issue(
                                    "repository_state_mismatch", uid=uid, repo_id=repo_id
                                )
                            )
                        if int(stored_repository["generation"]) != repository["generation"]:
                            issues.append(
                                _profile_database_issue(
                                    "repository_generation_mismatch", uid=uid, repo_id=repo_id
                                )
                            )
                        if (
                            stored_repository["installation_status"] != "installed"
                            or bool(stored_repository["startup_fenced"])
                        ):
                            issues.append(
                                _profile_database_issue(
                                    "repository_installation_inactive", uid=uid, repo_id=repo_id
                                )
                            )
                    if enrollment_table is not None:
                        enrollment = connection.execute(
                            """
                            SELECT account_id, enabled, issued_at, valid_until_epoch
                            FROM broker_repository_enrollments
                            WHERE uid = ? AND repo_id = ?
                            """,
                            (uid, repo_id),
                        ).fetchone()
                        if enrollment is None:
                            issues.append(
                                _profile_database_issue(
                                    "enrollment_missing", uid=uid, repo_id=repo_id
                                )
                            )
                        else:
                            if not bool(enrollment["enabled"]):
                                issues.append(
                                    _profile_database_issue(
                                        "enrollment_disabled", uid=uid, repo_id=repo_id
                                    )
                                )
                            if (
                                str(enrollment["account_id"])
                                != repository["account_id"]
                            ):
                                issues.append(
                                    _profile_database_issue(
                                        "enrollment_account_mismatch",
                                        uid=uid,
                                        repo_id=repo_id,
                                    )
                                )
                            if str(enrollment["issued_at"]) != repository["issued_at"]:
                                issues.append(
                                    _profile_database_issue(
                                        "enrollment_issued_at_mismatch",
                                        uid=uid,
                                        repo_id=repo_id,
                                    )
                                )
                            enrollment_expiry = int(enrollment["valid_until_epoch"])
                            if now >= enrollment_expiry:
                                issues.append(
                                    _profile_database_issue(
                                        "enrollment_expired", uid=uid, repo_id=repo_id
                                    )
                                )
                            if enrollment_expiry != repository["valid_until_epoch"]:
                                issues.append(
                                    _profile_database_issue(
                                        "enrollment_expiry_mismatch",
                                        uid=uid,
                                        repo_id=repo_id,
                                    )
                                )
                if enrollment_table is not None:
                    profile_by_identity = {
                        (int(repository["uid"]), str(repository["repo_id"])): repository
                        for repository in repositories
                    }
                    database_enrollments = connection.execute(
                        """
                        SELECT uid, repo_id, account_id, issued_at, valid_until_epoch
                        FROM broker_repository_enrollments
                        WHERE enabled = 1 AND valid_until_epoch > ?
                        ORDER BY uid, repo_id
                        """,
                        (now,),
                    ).fetchall()
                    database_current_enrollments = len(database_enrollments)
                    for enrollment in database_enrollments:
                        uid = int(enrollment["uid"])
                        repo_id = str(enrollment["repo_id"])
                        repository = profile_by_identity.get((uid, repo_id))
                        if repository is None:
                            issues.append(
                                _profile_database_issue(
                                    "profile_enrollment_missing", uid=uid, repo_id=repo_id
                                )
                            )
                        elif str(enrollment["account_id"]) != repository["account_id"]:
                            # The forward comparison emits the same mismatch, but
                            # retaining this branch makes the reverse proof
                            # independently complete.
                            if not any(
                                issue.get("reason") == "enrollment_account_mismatch"
                                and issue.get("uid") == uid
                                and issue.get("repo_id") == repo_id
                                for issue in issues
                            ):
                                issues.append(
                                    _profile_database_issue(
                                        "enrollment_account_mismatch",
                                        uid=uid,
                                        repo_id=repo_id,
                                    )
                                )
                        else:
                            reverse_mismatches = (
                                (
                                    "enrollment_issued_at_mismatch",
                                    str(enrollment["issued_at"])
                                    != repository["issued_at"],
                                ),
                                (
                                    "enrollment_expiry_mismatch",
                                    int(enrollment["valid_until_epoch"])
                                    != repository["valid_until_epoch"],
                                ),
                            )
                            for reason, mismatched in reverse_mismatches:
                                if mismatched and not any(
                                    issue.get("reason") == reason
                                    and issue.get("uid") == uid
                                    and issue.get("repo_id") == repo_id
                                    for issue in issues
                                ):
                                    issues.append(
                                        _profile_database_issue(
                                            reason, uid=uid, repo_id=repo_id
                                        )
                                    )
                connection.execute("ROLLBACK")
            finally:
                connection.close()
            current_database = database_path.lstat()
            if (current_database.st_dev, current_database.st_ino) != (
                expected_database.st_dev,
                expected_database.st_ino,
            ):
                issues.append(_profile_database_issue("database_replaced_during_check"))
        except (InstallError, OSError, sqlite3.Error, TypeError, ValueError) as error:
            issues.append(
                _profile_database_issue("database_unavailable", detail=str(error))
            )
    result["checked_current_enrollments"] = len(repositories)
    result["checked_current_database_enrollments"] = database_current_enrollments
    if issues:
        result.update(
            {
                "ok": False,
                "code": PROFILE_DATABASE_ENROLLMENT_DRIFT,
                "status": "drift",
                "issues": issues,
            }
        )
    else:
        if profile_absent:
            result["status"] = "profile_absent"
        elif not repositories:
            result["status"] = "no_current_profile_enrollments"
        else:
            result["status"] = "matched"
    return result


def _profile_database_repair_guidance(result: dict[str, Any]) -> str:
    reasons = {
        str(issue.get("reason"))
        for issue in result.get("issues", [])
        if isinstance(issue, dict)
    }
    steps: list[str] = []
    if any("generation" in reason for reason in reasons):
        steps.append(
            "run exact offline profile-generation reconciliation for every reported "
            "database or repository generation issue"
        )
    if steps:
        steps.append("then run the explicit offline profile-enrollment backfill")
    else:
        steps.append(
            "run the explicit offline profile-enrollment backfill for absent rows and "
            "resolve any reported conflicting row through administrator "
            "enrollment or revocation"
        )
    steps.append("then rerun plan and verify")
    return ", ".join(steps)


def require_profile_database_enrollment_consistency() -> dict[str, Any]:
    result = profile_database_enrollment_check()
    if result["ok"]:
        return result
    reasons = ", ".join(
        sorted({str(issue.get("reason")) for issue in result["issues"]})
    )
    raise ProfileDatabaseEnrollmentDrift(
        f"{PROFILE_DATABASE_ENROLLMENT_DRIFT}: protected profile access is not "
        f"represented by current service database enrollment state ({reasons}); "
        f"{_profile_database_repair_guidance(result)} before restart"
    )


def desired_plan(names: list[str]) -> dict[str, Any]:
    validate_broker_unit_source()
    clients = client_records(names)
    home_write_paths = enrolled_home_write_paths(clients)
    restart_precondition = profile_database_enrollment_check()
    repair_guidance = _profile_database_repair_guidance(restart_precondition)
    restart_step = (
        "rerun verify, then start or restart devcoordinator-broker.service"
        if restart_precondition["ok"]
        else (
            f"stop before service restart; resolve {PROFILE_DATABASE_ENROLLMENT_DRIFT} "
            f"as follows: {repair_guidance}"
        )
    )
    plan = {
        "authority": {
            "database": str(AUTHORITY_DATABASE_PATH),
            "socket": "/run/devcoordinator/broker.sock",
            "profile": str(CLIENT_PROFILE_PATH),
            "service_user": SERVICE_USER,
            "access_group": ACCESS_GROUP,
        },
        "runtime_requirements": {
            "python": str(SYSTEM_PYTHON),
            "pyyaml": "6.x",
            "docker_compose": COMPOSE_VERSION_REQUIREMENT,
            "compose_capabilities": [
                "config --format json",
                "two ordered explicit --env-file options",
                "second explicit environment file overrides the first",
                "implicit .env is suppressed",
            ],
            "evidence_contract": RUNTIME_DEPENDENCY_CONTRACT,
            "preflight": str(RUNTIME_DEPENDENCY_CHECK),
        },
        "system_files": [
            {"source": str(source), "destination": str(destination)}
            for source, destination in SYSTEM_FILES.items()
        ]
        + [
            {
                "source": ENROLLED_HOME_DROPIN_SOURCE,
                "destination": str(ENROLLED_HOME_DROPIN),
                "home_write_paths": [os.fspath(path) for path in home_write_paths],
            }
        ],
        "clients": [
            {
                "user": record.pw_name,
                "uid": record.pw_uid,
                "journal": f"/var/lib/devcoordinator-clients/{record.pw_uid}",
                "skill_roots": [
                    str(home / ".codex/skills"),
                    str(home / ".claude/skills"),
                ],
            }
            for record, home in clients
        ],
        "migration": {
            "legacy_authorities_preserved": True,
            "steps": [
                "apply installation without starting the broker",
                (
                    "move the broker Docker configuration into the canonical unit and "
                    "transactionally remove only its exact legacy 90-docker-config.conf"
                ),
                (
                    "atomically replace the broker writable-home drop-in from the "
                    "complete explicit client set"
                ),
                "enroll every exact client UID, repository, and server allowlist",
                restart_step,
                "register each pre-existing listener from its owning non-root UID",
                "verify the listener in shared inventory and DevOps Console",
                "retain each legacy account store until host-wide verification succeeds",
            ],
            "rollback": (
                "stop the new broker, run this transaction's rollback action, "
                "and resume the preserved account authority"
            ),
        },
        "starts_service": False,
        "requires_service_restart_for_sandbox_changes": True,
        "restart_precondition": restart_precondition,
        "restart_allowed": bool(restart_precondition["ok"]),
    }
    if restart_precondition["ok"]:
        plan["next_step"] = (
            "Run broker enroll once per user/repository with repeated --server allowlists, "
            "then rerun verify immediately before safely enabling or restarting "
            "devcoordinator-broker.service so its mount namespace matches the replaced "
            "enrolled-home drop-in."
        )
    else:
        plan["next_step"] = (
            f"Resolve {PROFILE_DATABASE_ENROLLMENT_DRIFT}: {repair_guidance}. "
            "Do not restart the broker."
        )
    return plan


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def install_payload(
    payload: bytes,
    destination: Path,
    transaction: Path,
    *,
    source_label: str,
) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    if destination.parent.is_symlink():
        raise InstallError(f"system configuration parent is a symlink: {destination.parent}")
    parent_metadata = destination.parent.lstat()
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != SYSTEM_OWNER_UID
        or parent_metadata.st_gid != SYSTEM_OWNER_GID
        or stat.S_IMODE(parent_metadata.st_mode) & 0o022
    ):
        raise InstallError(
            f"system configuration parent has unsafe ownership or mode: {destination.parent}"
        )
    backup = transaction / "system-files" / destination.relative_to("/")
    before: dict[str, Any] = {"exists": destination.exists()}
    if destination.exists():
        metadata = destination.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != SYSTEM_OWNER_UID
            or metadata.st_gid != SYSTEM_OWNER_GID
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise InstallError(f"refusing non-regular system file: {destination}")
        backup.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copy2(destination, backup, follow_symlinks=False)
        before.update(
            {
                "sha256": digest(destination),
                "mode": stat.S_IMODE(metadata.st_mode),
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
            }
        )
    temporary = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        _write_descriptor(descriptor, payload)
        os.fchown(descriptor, SYSTEM_OWNER_UID, SYSTEM_OWNER_GID)
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, destination)
        parent_descriptor = os.open(
            destination.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    return {
        "source": source_label,
        "destination": str(destination),
        "installed_sha256": digest(destination),
        "backup": str(backup),
        "before": before,
    }


def install_file(source: Path, destination: Path, transaction: Path) -> dict[str, Any]:
    return install_payload(
        source.read_bytes(),
        destination,
        transaction,
        source_label=str(source),
    )


def restore_installed_system_file(entry: dict[str, Any]) -> None:
    destination = Path(str(entry["destination"]))
    if (
        not destination.is_file()
        or destination.is_symlink()
        or digest(destination) != entry["installed_sha256"]
    ):
        raise InstallError(
            f"installed system file changed; refusing rollback: {destination}"
        )
    before = entry["before"]
    if before["exists"]:
        backup = Path(str(entry["backup"]))
        if (
            not backup.is_file()
            or backup.is_symlink()
            or digest(backup) != before["sha256"]
        ):
            raise InstallError(
                f"system file rollback backup changed: {backup}"
            )
        shutil.copyfile(backup, destination, follow_symlinks=False)
        os.chown(
            destination,
            int(before.get("uid", SYSTEM_OWNER_UID)),
            int(before.get("gid", SYSTEM_OWNER_GID)),
        )
        os.chmod(destination, int(before["mode"]))
    else:
        destination.unlink()


def ensure_owned_directory(path: Path, *, uid: int, gid: int, mode: int) -> None:
    if path.exists() or path.is_symlink():
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise InstallError(f"required directory is unsafe: {path}")
    else:
        path.mkdir(parents=True, mode=mode)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def capture_source_acl(transaction: Path) -> Path:
    """Preserve every ACL the installation will extend before mutation."""

    source = require_real(SKILL_SOURCE, directory=True)
    skills_root = require_real(source.parent, directory=True)
    repository = require_real(ROOT, directory=True)
    backup = transaction / "canonical-skill-source.acl"
    getfacl = command("getfacl")
    payload = b"".join(
        (
            capture(getfacl, "--absolute-names", str(repository)),
            capture(getfacl, "--absolute-names", str(skills_root)),
            capture(getfacl, "--absolute-names", "--recursive", str(source)),
        )
    )
    descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        backup.unlink(missing_ok=True)
        raise
    return backup


def grant_source_acl() -> None:
    """Give clients live read/execute access without source write access."""

    source = require_real(SKILL_SOURCE, directory=True)
    skills_root = require_real(source.parent, directory=True)
    repository = require_real(ROOT, directory=True)
    setfacl = command("setfacl")
    run(setfacl, "--modify", f"g:{ACCESS_GROUP}:--x", str(repository))
    run(setfacl, "--modify", f"g:{ACCESS_GROUP}:--x", str(skills_root))
    run(
        setfacl,
        "--recursive",
        "--modify",
        f"g:{ACCESS_GROUP}:rX",
        str(source),
    )
    for directory, child_directories, _files in os.walk(source):
        child_directories.sort()
        run(
            setfacl,
            "--modify",
            f"d:g:{ACCESS_GROUP}:rX",
            str(directory),
        )


def restore_source_acl(backup: Path) -> None:
    if not backup.is_file() or backup.is_symlink():
        raise InstallError(f"canonical source ACL backup is missing or unsafe: {backup}")
    run(command("setfacl"), f"--restore={backup}")


def apply_install(names: list[str], transaction_raw: str, allow_noncanonical: bool) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise InstallError("apply requires root once; clients require no sudo afterward")
    validate_broker_unit_source()
    restart_precondition = require_profile_database_enrollment_consistency()
    require_runtime_dependencies()
    transaction = Path(transaction_raw)
    if not transaction.is_absolute() or transaction.exists() or transaction.is_symlink():
        raise InstallError("--transaction-dir must be one new absolute path")
    transaction.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    transaction.mkdir(mode=0o700)
    os.chown(transaction, SYSTEM_OWNER_UID, SYSTEM_OWNER_GID)
    os.chmod(transaction, 0o700)
    transaction = _private_transaction(transaction)
    clients = client_records(names)
    home_dropin = render_enrolled_home_dropin(
        enrolled_home_write_paths(clients)
    )
    journal: dict[str, Any] = {
        "version": 1,
        "status": "applying",
        "repo_root": str(ROOT),
        "system_files": [],
        "link_transactions": [],
        "group_members_added": [],
        "client_journals": [],
        "legacy_docker_dropin": None,
        "legacy_docker_dropin_removed": False,
        "restart_precondition": restart_precondition,
    }
    atomic_json(transaction / JOURNAL_NAME, journal)
    try:
        for source, destination in SYSTEM_FILES.items():
            journal["system_files"].append(
                install_file(source, destination, transaction)
            )
            atomic_json(transaction / JOURNAL_NAME, journal)

        journal["system_files"].append(
            install_payload(
                home_dropin,
                ENROLLED_HOME_DROPIN,
                transaction,
                source_label=ENROLLED_HOME_DROPIN_SOURCE,
            )
        )
        atomic_json(transaction / JOURNAL_NAME, journal)

        legacy_dropin = prepare_legacy_docker_dropin_removal(transaction)
        journal["legacy_docker_dropin"] = legacy_dropin
        atomic_json(transaction / JOURNAL_NAME, journal)
        if legacy_dropin is not None:
            remove_prepared_legacy_docker_dropin(legacy_dropin, transaction)
            journal["legacy_docker_dropin_removed"] = True
            atomic_json(transaction / JOURNAL_NAME, journal)

        run(command("systemd-sysusers"), "/etc/sysusers.d/devcoordinator.conf")
        run(command("systemd-tmpfiles"), "--create", "/etc/tmpfiles.d/devcoordinator.conf")
        try:
            service = pwd.getpwnam(SERVICE_USER)
            access = grp.getgrnam(ACCESS_GROUP)
        except KeyError as error:
            raise InstallError("system authority identity or access group is missing") from error

        acl_backup = capture_source_acl(transaction)
        journal["source_acl_backup"] = str(acl_backup)
        atomic_json(transaction / JOURNAL_NAME, journal)
        grant_source_acl()

        manager = ROOT / "scripts/manage_skill_links.py"
        for record, home in clients:
            current_groups = {group.gr_name for group in grp.getgrall() if record.pw_name in group.gr_mem}
            if record.pw_gid == access.gr_gid:
                current_groups.add(ACCESS_GROUP)
            if ACCESS_GROUP not in current_groups:
                run(command("usermod"), "-a", "-G", ACCESS_GROUP, record.pw_name)
                journal["group_members_added"].append(record.pw_name)

            client_journal = Path(f"/var/lib/devcoordinator-clients/{record.pw_uid}")
            ensure_owned_directory(
                client_journal,
                uid=record.pw_uid,
                gid=record.pw_gid,
                mode=0o700,
            )
            journal["client_journals"].append(str(client_journal))

            roots: list[Path] = []
            for relative in (Path(".codex/skills"), Path(".claude/skills")):
                root = home / relative
                root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if root.parent.is_symlink():
                    raise InstallError(f"agent configuration parent is a symlink: {root.parent}")
                if not root.exists():
                    root.mkdir(mode=0o700)
                metadata = root.lstat()
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                    raise InstallError(f"agent skill root is unsafe: {root}")
                os.chown(root.parent, record.pw_uid, record.pw_gid)
                os.chown(root, record.pw_uid, record.pw_gid)
                roots.append(root)

            link_transaction = transaction / f"skill-links-{record.pw_uid}"
            arguments = [
                sys.executable,
                str(manager),
                "apply",
                "--repo-root",
                str(ROOT),
                "--transaction-dir",
                str(link_transaction),
                "--skill",
                "codex-dev-coordinator",
            ]
            for root in roots:
                arguments.extend(("--target-root", str(root)))
            if allow_noncanonical:
                arguments.append("--allow-noncanonical")
            run(*arguments)
            journal["link_transactions"].append(str(link_transaction))
            atomic_json(transaction / JOURNAL_NAME, journal)

        # These ownership checks document the intended split after tmpfiles.
        authority = Path("/var/lib/devcoordinator").lstat()
        if authority.st_uid != service.pw_uid or stat.S_IMODE(authority.st_mode) != 0o700:
            raise InstallError("service authority directory failed ownership/mode verification")
        profile_parent = CLIENT_PROFILE_PATH.parent.lstat()
        if (
            profile_parent.st_uid != service.pw_uid
            or profile_parent.st_gid != access.gr_gid
            or stat.S_IMODE(profile_parent.st_mode) != 0o750
        ):
            raise InstallError("client profile directory failed ownership/mode verification")
        # Recheck after every installer mutation. The initial proof prevents
        # starting from known drift; this final proof prevents a concurrent
        # profile/database change from turning the returned restart guidance
        # into a stale authorization claim.
        journal["restart_precondition"] = (
            require_profile_database_enrollment_consistency()
        )
        atomic_json(transaction / JOURNAL_NAME, journal)
        run(command("systemctl"), "daemon-reload")
        journal["status"] = "applied"
        journal["starts_service"] = False
        journal["requires_service_restart_for_sandbox_changes"] = True
        atomic_json(transaction / JOURNAL_NAME, journal)
        return journal
    except BaseException:
        journal["status"] = "rollback_required"
        atomic_json(transaction / JOURNAL_NAME, journal)
        try:
            rollback_install(transaction)
        except BaseException as rollback_error:
            raise InstallError(
                f"installation failed and rollback also failed: {rollback_error}; inspect {transaction}"
            ) from rollback_error
        raise


def rollback_install(transaction: Path) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise InstallError("rollback requires root")
    transaction = _private_transaction(transaction)
    journal_path = transaction / JOURNAL_NAME
    require_private_regular(journal_path, label="installation journal")
    document = json.loads(journal_path.read_text(encoding="utf-8"))
    if document.get("repo_root") != str(ROOT):
        raise InstallError("transaction belongs to another repository")
    manager = ROOT / "scripts/manage_skill_links.py"
    for link_transaction in reversed(document.get("link_transactions", [])):
        run(
            sys.executable,
            str(manager),
            "rollback",
            "--transaction-dir",
            str(link_transaction),
        )
    source_acl_backup = document.get("source_acl_backup")
    if source_acl_backup:
        restore_source_acl(Path(str(source_acl_backup)))
    for entry in reversed(document.get("system_files", [])):
        restore_installed_system_file(entry)
    legacy_dropin = document.get("legacy_docker_dropin")
    if legacy_dropin is not None:
        if not isinstance(legacy_dropin, dict):
            raise InstallError("legacy broker drop-in journal entry is invalid")
        restore_legacy_docker_dropin(legacy_dropin, transaction)
    for user in reversed(document.get("group_members_added", [])):
        run(command("gpasswd"), "-d", str(user), ACCESS_GROUP)
    run(command("systemctl"), "daemon-reload")
    document["status"] = "rolled_back"
    atomic_json(journal_path, document)
    return document


def verify_install(names: list[str]) -> dict[str, Any]:
    plan = desired_plan(names)
    failures: list[str] = []
    failure_codes: list[str] = []
    restart_precondition = plan["restart_precondition"]
    if not restart_precondition["ok"]:
        failure_codes.append(PROFILE_DATABASE_ENROLLMENT_DRIFT)
        reasons = ", ".join(
            sorted(
                {
                    str(issue.get("reason"))
                    for issue in restart_precondition["issues"]
                }
            )
        )
        failures.append(
            f"{PROFILE_DATABASE_ENROLLMENT_DRIFT}: protected profile and service "
            f"database enrollment differ ({reasons}); do not restart the broker"
        )
    dependency_evidence = runtime_dependency_evidence()
    dependency_failure = runtime_dependency_failure(dependency_evidence)
    if dependency_failure is not None:
        failures.append(dependency_failure)
    try:
        access = grp.getgrnam(ACCESS_GROUP)
        service = pwd.getpwnam(SERVICE_USER)
    except KeyError:
        failures.append("service identity or access group is missing")
        access = None
        service = None
    for source, destination in SYSTEM_FILES.items():
        if not destination.is_file() or destination.is_symlink() or digest(destination) != digest(source):
            failures.append(f"system file does not match repository: {destination}")
    home_paths = [
        Path(str(value))
        for value in plan["system_files"][-1]["home_write_paths"]
    ]
    expected_home_dropin = render_enrolled_home_dropin(home_paths)
    try:
        home_dropin_metadata = ENROLLED_HOME_DROPIN.lstat()
    except FileNotFoundError:
        failures.append(
            f"enrolled-home writable-path drop-in is missing: {ENROLLED_HOME_DROPIN}"
        )
    else:
        if (
            stat.S_ISLNK(home_dropin_metadata.st_mode)
            or not stat.S_ISREG(home_dropin_metadata.st_mode)
            or home_dropin_metadata.st_uid != SYSTEM_OWNER_UID
            or home_dropin_metadata.st_gid != SYSTEM_OWNER_GID
            or stat.S_IMODE(home_dropin_metadata.st_mode) != 0o644
            or ENROLLED_HOME_DROPIN.read_bytes() != expected_home_dropin
        ):
            failures.append(
                "enrolled-home writable-path drop-in does not match the complete client set"
            )
    unit_guard = ROOT / "scripts/check_broker_shutdown_unit.py"
    completed_unit_guard = subprocess.run(
        [sys.executable, str(unit_guard)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed_unit_guard.returncode != 0:
        detail = completed_unit_guard.stderr.strip() or "loaded unit contract failed"
        failures.append(f"broker effective unit is unsafe: {detail}")
    try:
        legacy_dropin = inspect_legacy_docker_dropin()
    except InstallError as error:
        failures.append(str(error))
    else:
        if legacy_dropin is not None:
            failures.append(
                f"legacy broker Docker drop-in was not migrated: {LEGACY_DOCKER_DROPIN}"
            )
    profile_parent = CLIENT_PROFILE_PATH.parent
    if access is not None and service is not None:
        try:
            metadata = profile_parent.lstat()
        except FileNotFoundError:
            failures.append(f"client profile directory is missing: {profile_parent}")
        else:
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != service.pw_uid
                or metadata.st_gid != access.gr_gid
                or stat.S_IMODE(metadata.st_mode) != 0o750
            ):
                failures.append(f"client profile directory is unsafe: {profile_parent}")
    profile = CLIENT_PROFILE_PATH
    if profile.exists() or profile.is_symlink():
        metadata = profile.lstat()
        if (
            access is None
            or service is None
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != service.pw_uid
            or metadata.st_gid != access.gr_gid
            or stat.S_IMODE(metadata.st_mode) != 0o640
        ):
            failures.append(f"client profile is unsafe: {profile}")
    for client in plan["clients"]:
        record = pwd.getpwnam(client["user"])
        journal = Path(client["journal"])
        if not journal.is_dir() or journal.is_symlink():
            failures.append(f"client journal is missing or unsafe: {journal}")
        for root in client["skill_roots"]:
            destination = Path(root) / "codex-dev-coordinator"
            source = ROOT / "skills/codex-dev-coordinator"
            if not destination.is_symlink() or os.readlink(destination) != str(source):
                failures.append(f"skill is not a direct canonical link: {destination}")
        groups = {group.gr_gid for group in grp.getgrall() if record.pw_name in group.gr_mem}
        if access is not None and record.pw_gid != access.gr_gid and access.gr_gid not in groups:
            failures.append(f"client is not in the broker access group: {record.pw_name}")
    return {
        "ok": not failures,
        "failures": failures,
        "failure_codes": failure_codes,
        "plan": plan,
        "restart_precondition": restart_precondition,
        "runtime_dependency_evidence": dependency_evidence,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    for name in ("plan", "verify"):
        action = actions.add_parser(name)
        action.add_argument("--client-user", action="append", required=True)
    apply = actions.add_parser("apply")
    apply.add_argument("--client-user", action="append", required=True)
    apply.add_argument("--transaction-dir", required=True)
    apply.add_argument("--allow-noncanonical-skill-links", action="store_true")
    rollback = actions.add_parser("rollback")
    rollback.add_argument("--transaction-dir", required=True)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.action == "plan":
            result = desired_plan(args.client_user)
            if not result["restart_precondition"]["ok"]:
                print(json.dumps(result, indent=2, sort_keys=True))
                return 1
        elif args.action == "apply":
            result = apply_install(
                args.client_user,
                args.transaction_dir,
                bool(args.allow_noncanonical_skill_links),
            )
        elif args.action == "rollback":
            result = rollback_install(Path(args.transaction_dir))
        else:
            result = verify_install(args.client_user)
            if not result["ok"]:
                print(json.dumps(result, indent=2, sort_keys=True))
                return 1
    except (InstallError, OSError, ValueError, json.JSONDecodeError) as error:
        code = getattr(error, "code", None)
        if code is not None:
            print(
                json.dumps(
                    {"ok": False, "code": str(code), "error": str(error)},
                    indent=2,
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
        else:
            print(f"server-wide coordinator installation failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
