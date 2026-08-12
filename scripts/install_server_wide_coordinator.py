#!/usr/bin/env python3
"""Install, explicitly activate, or roll back the trusted-local server boundary.

Apply deliberately does not start the broker. Runtime users need no sudo after
installation: every local account reaches the service through the 0666 Unix
socket. Explicit user arguments select where canonical Codex/Claude skill links
are installed; they never grant broker or repository authority.
"""

from __future__ import annotations

import argparse
import ast
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import time
import uuid
from typing import Any

SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

from server_wide_installer_fence import (
    InstallerFenceError,
    InstallerFenceHandle,
    acquire_installer_mutex,
)


ROOT = SCRIPT_ROOT.parent
LEGACY_ACCESS_GROUP = "devcoordinator-clients"
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
BASE_READ_WRITE_PATHS = "/home /var/lib/devcoordinator -/run/devcoordinator"
BROKER_UNIT_REQUIRED_SANDBOX = {
    "UMask": "UMask=0077",
    "NoNewPrivileges": "NoNewPrivileges=true",
    "PrivateTmp": "PrivateTmp=true",
    "ProtectSystem": "ProtectSystem=strict",
    "ProtectHome": "ProtectHome=false",
    "ReadWritePaths": f"ReadWritePaths={BASE_READ_WRITE_PATHS}",
}
MANAGED_SKILLS = (
    "codex-dev-coordinator",
    "postgres-docker-backup",
)
AGENT_SKILL_ROOTS = (
    Path(".codex/skills"),
    Path(".claude/skills"),
)
SKILL_SOURCE = ROOT / "skills/codex-dev-coordinator"
JOURNAL_NAME = "install-journal.json"
BROKER_UNIT = "devcoordinator-broker.service"
BROKER_SOCKET = Path("/run/devcoordinator-authority.sock")
INSTALLER_LOCK = Path("/run/devcoordinator-installer.lock")
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
PROFILE_DATABASE_ROUTING_DRIFT = "profile_database_routing_drift"
AUTHORITY_SCHEMA_CUTOVER_REQUIRED = "authority_schema_cutover_required"
DIRECT_DOCKER_SOCKET_ACCESS = "direct_client_docker_socket_access"
DOCKER_ADMISSION_CONTRACT = "devcoordinator-docker-admission-observe-v1"
DOCKER_SOURCE_POLICY_CONTRACT = "devcoordinator-managed-docker-source-v1"
SYSTEM_DOCKER_SOCKET_CANDIDATES = (
    Path("/run/docker.sock"),
    Path("/var/run/docker.sock"),
)
DOCKER_SOURCE_POLICY_INTERNALS = (
    "scripts/dev_coordinator.py",
    "scripts/devcoordinator",
)
DOCKER_SOURCE_POLICY_VETTED_FIXTURES = (
    "scripts/capability_integration_test.py",
    "scripts/self_test.py",
    "scripts/self_test_broker_cross_uid.py",
    "scripts/self_test_cleanup_lifecycle.py",
    "scripts/self_test_host_lifecycle.py",
    "scripts/self_test_lifecycle_action_guard.py",
    "scripts/self_test_multi_runtime.py",
    "scripts/self_test_repository_lifecycle.py",
    "scripts/self_test_sqlite_cutover.py",
    "scripts/self_test_sqlite_lifecycle.py",
    "scripts/sqlite_store_test.py",
)
DOCKER_COMPOSE_MUTATIONS = frozenset(
    {
        "build",
        "create",
        "down",
        "kill",
        "pause",
        "pull",
        "push",
        "restart",
        "rm",
        "run",
        "start",
        "stop",
        "unpause",
        "up",
    }
)


class InstallError(RuntimeError):
    pass


class ProfileDatabaseRoutingDrift(InstallError):
    """The published route catalog differs from current service state."""

    code = PROFILE_DATABASE_ROUTING_DRIFT


class AuthoritySchemaCutoverRequired(InstallError):
    """Activation cannot safely start the installed broker contract yet."""

    code = AUTHORITY_SCHEMA_CUTOVER_REQUIRED
    classification = "cutover_required"
    action_required = (
        "Run the supported authority-schema migration, republish the host-wide "
        "route catalog, then rerun server-wide verify and activate."
    )

    def __init__(self, evidence: dict[str, Any]) -> None:
        self.evidence = evidence
        reasons = ", ".join(
            sorted(
                {
                    str(issue.get("reason"))
                    for issue in evidence.get("issues", [])
                    if isinstance(issue, dict)
                }
            )
        )
        super().__init__(
            f"{AUTHORITY_SCHEMA_CUTOVER_REQUIRED}: installed broker activation "
            f"requires an offline authority/profile cutover ({reasons or 'invalid evidence'}); "
            f"{self.action_required}"
        )


def install_test_admission_fence_schema(
    *,
    database_path: Path = AUTHORITY_DATABASE_PATH,
) -> dict[str, Any]:
    """Install the additive drain table only while the authority is offline.

    Broker startup deliberately does not perform this migration.  The
    service-lifetime flock proves that the installer cannot race a running
    authority writer, and SQLite keeps the DDL plus validation in one
    transaction.
    """

    if not path_lexists(database_path):
        return {
            "status": "deferred",
            "reason": "authority_database_missing",
            "database": os.fspath(database_path),
        }
    metadata = _protected_regular_metadata(
        database_path, label="service authority database"
    )
    if metadata.st_uid != SYSTEM_OWNER_UID:
        raise InstallError("service authority database has an unexpected owner")
    lock_path = database_path.parent / ".broker-service.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    lock_fd = os.open(lock_path, flags, 0o600)
    try:
        lock_info = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != SYSTEM_OWNER_UID
            or stat.S_IMODE(lock_info.st_mode) != 0o600
        ):
            raise InstallError("broker service lifetime lock is unsafe")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise InstallError(
                "authority service is active; stop it before the explicit test-admission schema migration"
            ) from error
        module_root = ROOT / "skills/codex-dev-coordinator/scripts"
        module_root_text = os.fspath(module_root)
        if module_root_text not in sys.path:
            sys.path.insert(0, module_root_text)
        from devcoordinator.universal_test_admission import (  # type: ignore[import-not-found]
            install_legacy_test_admission_schema,
        )

        connection = sqlite3.connect(
            os.fspath(database_path), isolation_level=None, timeout=5.0
        )
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("BEGIN IMMEDIATE")
            created = install_legacy_test_admission_schema(connection)
            integrity = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            if integrity != "ok":
                raise InstallError(
                    "authority database failed quick_check during admission schema migration"
                )
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        return {
            "status": "installed" if created else "present",
            "database": os.fspath(database_path),
            "table": "broker_test_admission_fences",
        }
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


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


def worker_runner_script_failure(script: Path | None = None) -> str | None:
    """Return the exact native-runner trust failure without mutating source."""

    candidate = (
        SKILL_SOURCE / "scripts/dev_coordinator.py" if script is None else script
    )
    try:
        metadata = candidate.lstat()
    except OSError as error:
        return f"worker runner script is unavailable: {candidate}: {error}"
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return f"worker runner script must be a regular non-symlink file: {candidate}"
    if metadata.st_mode & 0o022:
        return f"worker runner script must not be group/world writable: {candidate}"
    return None


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


def _acquire_installer_lock() -> InstallerFenceHandle:
    """Serialize all CLI system-boundary mutations on this host."""
    try:
        return acquire_installer_mutex(
            expected_uid=SYSTEM_OWNER_UID,
            expected_gid=SYSTEM_OWNER_GID,
            lock_path=INSTALLER_LOCK,
        )
    except InstallerFenceError as error:
        raise InstallError(str(error)) from error


def _systemd_unit_property(property_name: str) -> str:
    """Read one bounded systemd property for the fixed broker unit."""

    completed = subprocess.run(
        [
            command("systemctl"),
            "show",
            BROKER_UNIT,
            f"--property={property_name}",
            "--value",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
    )
    if completed.returncode:
        raise InstallError(
            f"could not inspect {BROKER_UNIT} {property_name}: "
            f"{completed.stderr.strip()[:2048]}"
        )
    value = completed.stdout.strip()
    if not value or "\n" in value or len(value) > 64:
        raise InstallError(
            f"systemd returned an invalid {property_name} for {BROKER_UNIT}"
        )
    return value


def _systemd_unit_active() -> bool:
    state = _systemd_unit_property("ActiveState")
    if state == "inactive":
        return False
    # Every other known state is non-quiescent for an exact lifecycle
    # transaction.  In particular ``activating/auto-restart`` frequently has
    # MainPID=0 between crash-loop attempts; treating it as inactive made the
    # baseline restore skip ``systemctl stop`` and allowed the loop to survive.
    if state in {
        "active",
        "failed",
        "activating",
        "deactivating",
        "reloading",
        "maintenance",
    }:
        return True
    raise InstallError(f"broker unit has an unsupported active state: {state}")


def _systemd_unit_enabled() -> bool:
    state = _systemd_unit_property("UnitFileState")
    if state in {"enabled", "enabled-runtime"}:
        return True
    if state == "disabled":
        return False
    raise InstallError(f"broker unit has an unsupported enablement state: {state}")


def _broker_socket_ready() -> bool:
    """Prove the fixed broker listener and its kernel peer identity."""

    try:
        before = BROKER_SOCKET.lstat()
    except FileNotFoundError:
        return False
    if (
        not stat.S_ISSOCK(before.st_mode)
        or before.st_uid != SYSTEM_OWNER_UID
        or before.st_gid != SYSTEM_OWNER_GID
        or stat.S_IMODE(before.st_mode) != 0o666
    ):
        raise InstallError("broker socket has unsafe identity or permissions")
    try:
        if BROKER_SOCKET.resolve(strict=True) != BROKER_SOCKET:
            raise InstallError("broker socket path contains a symlink component")
    except OSError as error:
        raise InstallError("broker socket path cannot be verified") from error
    if not hasattr(socket, "SO_PEERCRED"):
        raise InstallError("broker activation requires Linux peer credentials")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(0.5)
            connection.connect(os.fspath(BROKER_SOCKET))
            credentials = connection.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_PEERCRED,
                struct.calcsize("3i"),
            )
    except (ConnectionRefusedError, FileNotFoundError, socket.timeout):
        return False
    except OSError as error:
        raise InstallError("broker socket readiness probe failed") from error
    peer_pid, peer_uid, _peer_gid = struct.unpack("3i", credentials)
    if peer_pid <= 0 or peer_uid != SYSTEM_OWNER_UID:
        raise InstallError("broker socket peer is not the installed authority")
    try:
        after = BROKER_SOCKET.lstat()
    except FileNotFoundError:
        return False
    if (
        not stat.S_ISSOCK(after.st_mode)
        or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
    ):
        raise InstallError("broker socket identity changed during readiness probe")
    return True


def _wait_for_broker_ready(wait_seconds: int) -> None:
    if type(wait_seconds) is not int or not 1 <= wait_seconds <= 120:
        raise InstallError("--wait-seconds must be an integer from 1 through 120")
    deadline = time.monotonic() + wait_seconds
    while True:
        if _systemd_unit_active() and _broker_socket_ready():
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise InstallError("broker did not become active and ready before the timeout")
        time.sleep(min(0.1, remaining))


def _broker_start_failure_evidence() -> dict[str, Any]:
    """Capture bounded, private diagnostics before restoring a failed start."""

    properties: dict[str, str] = {}
    property_errors: dict[str, str] = {}
    for name in (
        "LoadState",
        "ActiveState",
        "SubState",
        "Result",
        "ExecMainCode",
        "ExecMainStatus",
        "MainPID",
        "InvocationID",
    ):
        try:
            properties[name] = _systemd_unit_property(name)
        except InstallError as error:
            property_errors[name] = str(error)[:1024]
    journal: dict[str, Any]
    try:
        completed = subprocess.run(
            [
                command("journalctl"),
                "--unit",
                BROKER_UNIT,
                "--no-pager",
                "--lines",
                "80",
                "--output",
                "short-iso",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=10,
        )
        stdout = completed.stdout[-64 * 1024 :]
        stderr = completed.stderr[-4096:]
        journal = {
            "returncode": completed.returncode,
            "tail": stdout,
            "stderr": stderr,
        }
    except (OSError, subprocess.TimeoutExpired) as error:
        journal = {"error": str(error)[:2048]}
    return {
        "captured_at_epoch": int(time.time()),
        "unit": properties,
        "property_errors": property_errors,
        "journal": journal,
    }


def _verify_broker_client_readiness(names: list[str]) -> list[dict[str, Any]]:
    """Prove the same host-wide inventory route is readable by every local agent."""

    clients = client_records(names)
    profile = _read_protected_profile(CLIENT_PROFILE_PATH)
    generation, repositories, issues = _profile_repository_routes(profile)
    if issues or not generation:
        raise InstallError("broker client readiness profile is invalid")
    if not repositories:
        raise InstallError("broker route catalog contains no repository anchor")
    repository = min(
        repositories,
        key=lambda item: (str(item["repo_id"]), str(item["canonical_root"])),
    )
    client_script = SKILL_SOURCE / "scripts/dev_coordinator.py"
    client_failure = worker_runner_script_failure(client_script)
    if client_failure is not None:
        raise InstallError(client_failure)
    client_sha256 = digest(client_script)
    evidence: list[dict[str, Any]] = []
    for record, _home in clients:
        arguments = [
            command("setpriv"),
            "--reuid",
            str(record.pw_uid),
            "--regid",
            str(record.pw_gid),
            "--init-groups",
            "--reset-env",
            os.fspath(SYSTEM_PYTHON),
            os.fspath(client_script),
            "inventory",
            "--project",
            str(repository["canonical_root"]),
            "--no-docker",
            "--compact-json",
        ]
        try:
            completed = subprocess.run(
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=15,
                env={
                    "PATH": "/usr/sbin:/usr/bin",
                    "LANG": "C.UTF-8",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise InstallError(
                f"broker client readiness probe could not run: {record.pw_name}"
            ) from error
        if (
            completed.returncode != 0
            or not completed.stdout
            or len(completed.stdout) > 32 * 1024 * 1024
            or len(completed.stderr) > 64 * 1024
        ):
            detail = completed.stderr.decode(
                "utf-8", errors="replace"
            ).strip()[:2048]
            raise InstallError(
                f"broker client readiness probe failed for {record.pw_name}: {detail}"
            )
        try:
            inventory = json.loads(completed.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise InstallError("broker client readiness returned invalid JSON") from error
        authority = inventory.get("authority") if isinstance(inventory, dict) else None
        inventory_repositories = (
            inventory.get("repositories") if isinstance(inventory, dict) else None
        )
        matching = (
            [
                item
                for item in inventory_repositories
                if isinstance(item, dict)
                and item.get("repo_id") == repository["repo_id"]
                and item.get("canonical_root") == repository["canonical_root"]
                and item.get("generation") == repository["generation"]
            ]
            if isinstance(inventory_repositories, list)
            else []
        )
        if (
            not isinstance(inventory, dict)
            or inventory.get("schema_version") != 3
            or not isinstance(authority, dict)
            or authority.get("scope") != "server-wide"
            or authority.get("transport") != "trusted-local-unix-socket"
            or authority.get("socket") != os.fspath(BROKER_SOCKET)
            or authority.get("service_uid") != SYSTEM_OWNER_UID
            or authority.get("database_generation") != generation
            or not isinstance(inventory_repositories, list)
            or len(inventory_repositories) != 1
            or len(matching) != 1
        ):
            raise InstallError(
                f"broker client readiness contract is invalid for {record.pw_name}"
            )
        evidence.append(
            {
                "user": record.pw_name,
                "uid": record.pw_uid,
                "repository_id": repository["repo_id"],
                "repository_generation": repository["generation"],
                "canonical_root": repository["canonical_root"],
                "authority_generation": generation,
                "client_sha256": client_sha256,
            }
        )
    return evidence


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


def run_json_command(
    *arguments: str,
    accepted_returncodes: tuple[int, ...] = (0,),
) -> tuple[int, dict[str, Any]]:
    """Run one bounded machine interface and require an object response."""

    completed = subprocess.run(
        list(arguments),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode not in accepted_returncodes:
        detail = completed.stderr.strip()[:2048]
        raise InstallError(
            f"command failed ({' '.join(arguments)}): {detail}"
        )
    if len(completed.stdout.encode("utf-8")) > 8 * 1024 * 1024:
        raise InstallError("command returned oversized JSON evidence")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise InstallError("command returned invalid JSON evidence") from error
    if not isinstance(value, dict):
        raise InstallError("command returned non-object JSON evidence")
    return completed.returncode, value


def _docker_mutation_operation(tokens: list[str]) -> str | None:
    """Classify a literal raw Docker creation/Compose mutation command."""

    remaining = [str(token) for token in tokens if str(token)]
    while remaining and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", remaining[0]):
        remaining.pop(0)
    if remaining and Path(remaining[0]).name in {"command", "exec", "sudo"}:
        remaining.pop(0)
    if remaining and Path(remaining[0]).name == "env":
        remaining.pop(0)
        while remaining and (
            remaining[0].startswith("-")
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", remaining[0])
        ):
            remaining.pop(0)
    if not remaining or Path(remaining[0]).name != "docker":
        return None
    arguments = remaining[1:]
    docker_options_with_values = {
        "--config",
        "--context",
        "--host",
        "--log-level",
        "-c",
        "-H",
        "-l",
    }
    while arguments and arguments[0].startswith("-"):
        option = arguments.pop(0)
        if "=" not in option and option in docker_options_with_values and arguments:
            arguments.pop(0)
    if not arguments:
        return None
    if arguments[0] in {"create", "run"}:
        return f"docker {arguments[0]}"
    if arguments[0] == "compose":
        compose_arguments = arguments[1:]
        compose_options_with_values = {
            "--ansi",
            "--env-file",
            "--file",
            "--parallel",
            "--profile",
            "--progress",
            "--project-directory",
            "--project-name",
            "-f",
            "-p",
        }
        while compose_arguments and compose_arguments[0].startswith("-"):
            option = compose_arguments.pop(0)
            if (
                "=" not in option
                and option in compose_options_with_values
                and compose_arguments
            ):
                compose_arguments.pop(0)
        if compose_arguments and compose_arguments[0] in DOCKER_COMPOSE_MUTATIONS:
            return f"docker compose {compose_arguments[0]}"
    return None


def _shell_line_docker_mutations(line: str) -> list[str]:
    stripped = line.strip()
    if stripped.startswith("$"):
        stripped = stripped[1:].lstrip()
    findings: list[str] = []
    for segment in re.split(r"(?:&&|\|\||[;|])", stripped):
        try:
            tokens = shlex.split(segment, comments=True, posix=True)
        except ValueError:
            continue
        operation = _docker_mutation_operation(tokens)
        if operation is not None:
            findings.append(operation)
    return findings


def _shell_source_raw_docker_mutations(source: str) -> list[tuple[int, str]]:
    findings: list[tuple[int, str]] = []
    for line_number, raw_line in enumerate(source.splitlines(), start=1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        for operation in _shell_line_docker_mutations(raw_line):
            findings.append((line_number, operation))
    return findings


def _python_raw_docker_mutations(source: str) -> list[tuple[int, str]]:
    tree = ast.parse(source)
    findings: set[tuple[int, str]] = set()
    docker_names = {
        "docker",
        "docker_cli",
        "docker_command",
        "docker_executable",
    }

    def literal_token(node: ast.AST, *, executable: bool = False) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if executable and isinstance(node, ast.Name) and node.id in docker_names:
            return "docker"
        return None

    for node in ast.walk(tree):
        sequences: list[tuple[int, list[ast.AST]]] = []
        if isinstance(node, (ast.List, ast.Tuple)):
            sequences.append((int(node.lineno), list(node.elts)))
        elif isinstance(node, ast.Call) and len(node.args) >= 2:
            sequences.append((int(node.lineno), list(node.args)))
        for line, elements in sequences:
            values = [
                literal_token(element, executable=index == 0)
                for index, element in enumerate(elements)
            ]
            if any(value is None for value in values):
                continue
            operation = _docker_mutation_operation([str(value) for value in values])
            if operation is not None:
                findings.add((line, operation))

        if not isinstance(node, ast.Call) or not node.args:
            continue
        first = node.args[0]
        if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
            continue
        function_name = ""
        if isinstance(node.func, ast.Name):
            function_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            function_name = node.func.attr
        if function_name not in {
            "Popen",
            "call",
            "check_call",
            "check_output",
            "run",
            "system",
        }:
            continue
        for operation in _shell_line_docker_mutations(first.value):
            findings.add((int(node.lineno), operation))
    return sorted(findings)


def _fenced_raw_docker_mutations(source: str) -> list[tuple[int, str]]:
    findings: list[tuple[int, str]] = []
    fence: str | None = None
    for line_number, raw_line in enumerate(source.splitlines(), start=1):
        marker = re.match(r"^\s*(```+|~~~+)", raw_line)
        if marker:
            token = marker.group(1)
            if fence is None:
                fence = token[0]
            elif token[0] == fence:
                fence = None
            continue
        if fence is None:
            continue
        for operation in _shell_line_docker_mutations(raw_line):
            findings.append((line_number, operation))
    return findings


def _yaml_raw_docker_mutations(source: str) -> list[tuple[int, str]]:
    """Inspect only executable YAML `run` values, not descriptive prose."""

    findings: list[tuple[int, str]] = []
    block_indent: int | None = None
    for line_number, raw_line in enumerate(source.splitlines(), start=1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if block_indent is not None:
            if indent > block_indent:
                for operation in _shell_line_docker_mutations(raw_line):
                    findings.append((line_number, operation))
                continue
            block_indent = None
        matched = re.match(r"^\s*(?:-\s*)?run\s*:\s*(.*)$", raw_line)
        if not matched:
            continue
        value = matched.group(1).strip()
        if value in {"|", ">", "|-", ">-", "|+", ">+"}:
            block_indent = indent
            continue
        for operation in _shell_line_docker_mutations(value):
            findings.append((line_number, operation))
    return findings


def managed_docker_source_policy_evidence(
    *, skill_root: Path | None = None
) -> dict[str, Any]:
    """Reject raw creation paths from canonical agent-facing skill surfaces."""

    source_root = require_real(
        SKILL_SOURCE if skill_root is None else skill_root,
        directory=True,
    )
    candidates: list[Path] = []
    for relative in (Path("SKILL.md"), Path("README.md"), Path("agents/openai.yaml")):
        path = source_root / relative
        if not path_lexists(path):
            raise InstallError(f"managed Docker policy source is missing: {path}")
        candidates.append(path)
    scripts_root = require_real(source_root / "scripts", directory=True)
    for path in sorted(scripts_root.iterdir(), key=os.fspath):
        if path.suffix not in {".bash", ".py", ".sh"}:
            continue
        relative = path.relative_to(source_root).as_posix()
        if relative in DOCKER_SOURCE_POLICY_VETTED_FIXTURES:
            continue
        candidates.append(path)

    findings: list[dict[str, Any]] = []
    checked: list[str] = []
    for path in sorted(set(candidates), key=os.fspath):
        relative = path.relative_to(source_root).as_posix()
        if relative == DOCKER_SOURCE_POLICY_INTERNALS[0] or relative.startswith(
            f"{DOCKER_SOURCE_POLICY_INTERNALS[1]}/"
        ):
            continue
        try:
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise InstallError(f"managed Docker policy source is unsafe: {path}")
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise InstallError(
                f"managed Docker policy source cannot be read: {path}: {error}"
            ) from error
        checked.append(relative)
        try:
            if path.suffix == ".py":
                located = _python_raw_docker_mutations(source)
            elif path.suffix in {".bash", ".sh"}:
                located = _shell_source_raw_docker_mutations(source)
            elif path.suffix in {".yaml", ".yml"}:
                located = _yaml_raw_docker_mutations(source)
            else:
                located = _fenced_raw_docker_mutations(source)
        except SyntaxError as error:
            raise InstallError(
                f"managed Docker policy Python source does not parse: {path}: {error}"
            ) from error
        for line, operation in located:
            findings.append(
                {"path": relative, "line": int(line), "operation": operation}
            )
    return {
        "ok": not findings,
        "contract": DOCKER_SOURCE_POLICY_CONTRACT,
        "scope": "canonical_agent_facing_coordinator_skill",
        "checked_files": checked,
        "excluded_coordinator_internals": list(DOCKER_SOURCE_POLICY_INTERNALS),
        "excluded_vetted_fixtures": list(DOCKER_SOURCE_POLICY_VETTED_FIXTURES),
        "findings": findings,
    }


def require_managed_docker_source_policy() -> dict[str, Any]:
    evidence = managed_docker_source_policy_evidence()
    if not evidence["ok"]:
        summary = ", ".join(
            f"{item['path']}:{item['line']} ({item['operation']})"
            for item in evidence["findings"]
        )
        raise InstallError(
            "raw Docker creation or Compose mutation is forbidden in canonical "
            f"agent-facing source; use a typed coordinator operation: {summary}"
        )
    return evidence


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


def _parse_posix_acl(payload: str) -> dict[tuple[str, str], frozenset[str]]:
    entries: dict[tuple[str, str], frozenset[str]] = {}
    for raw_line in payload.splitlines():
        line = raw_line.partition("#")[0].strip()
        if not line or line.startswith("default:"):
            continue
        parts = line.split(":")
        if len(parts) != 3 or parts[0] not in {"user", "group", "mask", "other"}:
            raise ValueError(f"unexpected ACL entry: {raw_line}")
        tag, qualifier, permissions = parts
        if not re.fullmatch(r"[r-][w-][x-]", permissions):
            raise ValueError(f"unexpected ACL permissions: {raw_line}")
        key = (tag, qualifier)
        if key in entries:
            raise ValueError(f"duplicate ACL entry: {raw_line}")
        entries[key] = frozenset(value for value in permissions if value != "-")
    for required in (("user", ""), ("group", ""), ("other", "")):
        if required not in entries:
            raise ValueError(f"ACL is missing {required[0]}::")
    return entries


def _read_posix_acl(
    path: Path,
) -> tuple[dict[tuple[str, str], frozenset[str]] | None, str | None]:
    resolved = shutil.which("getfacl")
    if not resolved:
        return None, "getfacl_unavailable"
    try:
        completed = subprocess.run(
            [resolved, "--absolute-names", "--numeric", "--omit-header", str(path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={"LC_ALL": "C", "PATH": RUNTIME_DEPENDENCY_ENVIRONMENT["PATH"]},
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, "acl_observation_unavailable"
    if completed.returncode:
        return None, "acl_observation_failed"
    try:
        return _parse_posix_acl(completed.stdout), None
    except ValueError:
        return None, "acl_evidence_invalid"


def _mode_permissions(
    metadata: os.stat_result, *, uid: int, gids: set[int]
) -> frozenset[str]:
    mode = stat.S_IMODE(metadata.st_mode)
    if uid == metadata.st_uid:
        value = (mode >> 6) & 0o7
    elif metadata.st_gid in gids:
        value = (mode >> 3) & 0o7
    else:
        value = mode & 0o7
    return frozenset(
        permission
        for permission, bit in (("r", 0o4), ("w", 0o2), ("x", 0o1))
        if value & bit
    )


def _acl_permissions(
    entries: dict[tuple[str, str], frozenset[str]],
    metadata: os.stat_result,
    *,
    uid: int,
    gids: set[int],
) -> frozenset[str]:
    if uid == metadata.st_uid:
        return entries[("user", "")]
    mask = entries.get(("mask", ""), frozenset({"r", "w", "x"}))
    named_user = entries.get(("user", str(uid)))
    if named_user is not None:
        return named_user & mask
    group_permissions: set[str] = set()
    group_matched = False
    if metadata.st_gid in gids:
        group_matched = True
        group_permissions.update(entries[("group", "")])
    for (tag, qualifier), permissions in entries.items():
        if tag != "group" or not qualifier:
            continue
        try:
            gid = int(qualifier)
        except ValueError:
            continue
        if gid in gids:
            group_matched = True
            group_permissions.update(permissions)
    if group_matched:
        return frozenset(group_permissions) & mask
    return entries[("other", "")]


def _identity_path_permission(
    path: Path, *, uid: int, gids: set[int], required: str
) -> dict[str, Any]:
    if uid == 0:
        return {"allowed": True, "source": "root_identity", "permissions": "rwx"}
    try:
        metadata = path.stat()
    except OSError as error:
        return {
            "allowed": None,
            "source": "metadata_unavailable",
            "permissions": None,
            "detail": error.__class__.__name__,
        }
    acl, acl_error = _read_posix_acl(path)
    if acl is not None:
        permissions = _acl_permissions(acl, metadata, uid=uid, gids=gids)
        return {
            "allowed": required in permissions,
            "source": "posix_acl",
            "permissions": "".join(value for value in "rwx" if value in permissions),
        }
    listxattr = getattr(os, "listxattr", None)
    if listxattr is None:
        extended_acl = None
    else:
        try:
            extended_acl = "system.posix_acl_access" in listxattr(path)
        except OSError:
            extended_acl = None
    if extended_acl is True:
        return {
            "allowed": None,
            "source": str(acl_error or "acl_observation_unavailable"),
            "permissions": None,
        }
    permissions = _mode_permissions(metadata, uid=uid, gids=gids)
    if extended_acl is None and uid != metadata.st_uid:
        return {
            "allowed": None,
            "source": str(acl_error or "acl_observation_unavailable"),
            "permissions": None,
        }
    return {
        "allowed": required in permissions,
        "source": "mode" if extended_acl is False else "owner_mode",
        "permissions": "".join(value for value in "rwx" if value in permissions),
    }


def _configured_client_gids(record: Any) -> tuple[set[int], list[str]]:
    gids = {int(record.pw_gid)}
    names: set[str] = set()
    try:
        names.add(grp.getgrgid(int(record.pw_gid)).gr_name)
    except KeyError:
        names.add(str(record.pw_gid))
    for group in grp.getgrall():
        if record.pw_name in group.gr_mem:
            gids.add(int(group.gr_gid))
            names.add(group.gr_name)
    return gids, sorted(names)


def _live_effective_gids(client_uids: set[int]) -> dict[int, set[int]]:
    """Collect retained supplementary groups from live processes read-only."""

    observed = {uid: set() for uid in client_uids}
    proc = Path("/proc")
    if proc.is_dir():
        for status_path in sorted(proc.glob("[0-9]*/status"), key=os.fspath):
            try:
                uid_values: list[int] | None = None
                group_values: set[int] | None = None
                with status_path.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        if line.startswith("Uid:"):
                            uid_values = [int(value) for value in line.split()[1:]]
                        elif line.startswith("Groups:"):
                            group_values = {
                                int(value) for value in line.split()[1:]
                            }
                        if uid_values is not None and group_values is not None:
                            break
            except (OSError, UnicodeError, ValueError):
                continue
            if not uid_values or group_values is None:
                continue
            effective_uid = uid_values[1] if len(uid_values) > 1 else uid_values[0]
            if effective_uid in observed:
                observed[effective_uid].update(group_values)
    current_uid = os.geteuid()
    if current_uid in observed:
        observed[current_uid].add(os.getegid())
        observed[current_uid].update(int(gid) for gid in os.getgroups())
    return observed


def _client_docker_socket_candidates(clients: list[Any]) -> list[Path]:
    candidates = list(SYSTEM_DOCKER_SOCKET_CANDIDATES)
    for record, home in clients:
        candidates.extend(
            (
                Path(f"/run/user/{record.pw_uid}/docker.sock"),
                home / ".docker/run/docker.sock",
                home / ".docker/desktop/docker.sock",
                home / ".orbstack/run/docker.sock",
            )
        )
    return list(dict.fromkeys(candidates))


def docker_socket_admission_evidence(
    clients: list[Any], *, socket_candidates: list[Path] | None = None
) -> dict[str, Any]:
    """Read socket metadata only; never connect, revoke access, or change groups."""

    candidates = (
        _client_docker_socket_candidates(clients)
        if socket_candidates is None
        else list(dict.fromkeys(socket_candidates))
    )
    sockets_by_identity: dict[tuple[int, int], dict[str, Any]] = {}
    observations: list[dict[str, Any]] = []
    for candidate in candidates:
        absolute = Path(os.path.abspath(os.fspath(candidate)))
        try:
            metadata = absolute.stat()
        except FileNotFoundError:
            observations.append({"path": str(absolute), "status": "absent"})
            continue
        except OSError as error:
            observations.append(
                {
                    "path": str(absolute),
                    "status": "unobservable",
                    "detail": error.__class__.__name__,
                }
            )
            continue
        if not stat.S_ISSOCK(metadata.st_mode):
            observations.append({"path": str(absolute), "status": "not_socket"})
            continue
        identity = (int(metadata.st_dev), int(metadata.st_ino))
        existing = sockets_by_identity.get(identity)
        if existing is not None:
            existing["aliases"].append(str(absolute))
            continue
        canonical = Path(os.path.realpath(absolute))
        sockets_by_identity[identity] = {
            "path": str(canonical),
            "aliases": [str(absolute)],
            "device": identity[0],
            "inode": identity[1],
            "uid": int(metadata.st_uid),
            "gid": int(metadata.st_gid),
            "mode": format(stat.S_IMODE(metadata.st_mode), "04o"),
        }

    sockets = sorted(sockets_by_identity.values(), key=lambda item: str(item["path"]))
    client_evidence: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    live_gids = _live_effective_gids(
        {int(record.pw_uid) for record, _home in clients}
    )
    for record, _home in clients:
        configured_gids, group_names = _configured_client_gids(record)
        retained_gids = live_gids.get(int(record.pw_uid), set())
        gids = configured_gids | retained_gids
        access_rows: list[dict[str, Any]] = []
        for socket_record in sockets:
            path = Path(str(socket_record["path"]))
            socket_access = _identity_path_permission(
                path, uid=int(record.pw_uid), gids=gids, required="w"
            )
            traversal_rows: list[dict[str, Any]] = []
            traversal_values: list[bool | None] = []
            for parent in reversed(path.parents):
                result = _identity_path_permission(
                    parent, uid=int(record.pw_uid), gids=gids, required="x"
                )
                traversal_rows.append({"path": str(parent), **result})
                traversal_values.append(result["allowed"])
            if socket_access["allowed"] is False or False in traversal_values:
                allowed: bool | None = False
            elif socket_access["allowed"] is None or None in traversal_values:
                allowed = None
            else:
                allowed = True
            access_rows.append(
                {
                    "socket": str(path),
                    "can_connect": allowed,
                    "socket_permission": socket_access,
                    "directory_traversal": traversal_rows,
                }
            )
        values = [row["can_connect"] for row in access_rows]
        if True in values:
            direct_access: bool | None = True
        elif None in values or any(
            row["status"] == "unobservable" for row in observations
        ):
            direct_access = None
        else:
            direct_access = False
        row = {
            "user": record.pw_name,
            "uid": int(record.pw_uid),
            "configured_gids": sorted(configured_gids),
            "configured_groups": group_names,
            "live_effective_gids": sorted(retained_gids),
            "evaluated_gids": sorted(gids),
            "direct_socket_access": direct_access,
            "sockets": access_rows,
        }
        client_evidence.append(row)
        if direct_access is True:
            blocker = {
                "code": DIRECT_DOCKER_SOCKET_ACCESS,
                "severity": "activation_blocker",
                "user": record.pw_name,
                "uid": int(record.pw_uid),
                "sockets": [
                    item["socket"]
                    for item in access_rows
                    if item["can_connect"] is True
                ],
                "message": (
                    f"enrolled client {record.pw_name} can still connect directly to "
                    "a Docker Unix socket"
                ),
            }
            blockers.append(blocker)
    return {
        "contract": DOCKER_ADMISSION_CONTRACT,
        "stage": "observe_only",
        "enforcement_enabled": False,
        "automatic_group_or_acl_mutation": False,
        "exclusive_admission_ready": False,
        "known_socket_exclusivity_ready": bool(sockets)
        and not blockers
        and all(row["direct_socket_access"] is not None for row in client_evidence),
        "activation_blockers": blockers,
        "clients": client_evidence,
        "sockets": sockets,
        "candidate_observations": observations,
        "coverage": (
            "system Docker sockets plus the enrolled users' standard rootless, "
            "Docker Desktop, and OrbStack Unix socket locations; custom Docker "
            "contexts remain outside this metadata-only check"
        ),
        "migration_guidance": (
            "Do not revoke Docker socket access automatically. First deploy and "
            "verify typed coordinator feature parity for ephemeral workloads; then "
            "an administrator may remove direct access in a separate rollback-safe "
            "activation transaction."
        ),
    }


def _docker_admission_warning_summary(
    evidence: dict[str, Any]
) -> tuple[list[str], list[str]]:
    blockers = evidence.get("activation_blockers")
    if not isinstance(blockers, list):
        raise InstallError("Docker admission evidence has invalid activation blockers")
    warnings: list[str] = []
    codes: set[str] = set()
    for blocker in blockers:
        if not isinstance(blocker, dict):
            raise InstallError("Docker admission activation blocker is invalid")
        code = blocker.get("code")
        message = blocker.get("message")
        if (
            not isinstance(code, str)
            or not code
            or not isinstance(message, str)
            or not message
        ):
            raise InstallError("Docker admission activation blocker is incomplete")
        warnings.append(message)
        codes.add(code)
    return warnings, sorted(codes)


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
    # ``paths`` selects skill-link destinations only. It must never narrow the
    # broker sandbox or become a per-account access list.
    validate_home_write_path_tokens(paths)
    return (
        "[Service]\n"
        "# Trusted-local global home access; user arguments install skill links only.\n"
        "ReadWritePaths=\n"
        f"ReadWritePaths={BASE_READ_WRITE_PATHS}\n"
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
        exact_mode=0o644,
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


def _profile_repository_routes(
    document: dict[str, Any],
) -> tuple[str | None, list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse the trusted-local routing catalog with the target client parser."""

    _schema, parse_profile, profile_error, _fields = _target_broker_activation_contract()
    try:
        parsed = parse_profile(document, effective_uid=0)
    except profile_error as error:
        return None, [], [_profile_database_issue("profile_routing_invalid", detail=str(error)[:1024])]
    except Exception as error:
        return None, [], [_profile_database_issue("profile_routing_unavailable", detail=str(error)[:1024])]
    routes = []
    for repository in sorted(parsed.repositories.values(), key=lambda item: (item.canonical_root, item.repo_id)):
        routes.append({
            "repo_id": repository.repo_id,
            "canonical_root": repository.canonical_root,
            "generation": repository.generation,
            "ephemeral_templates": dict(repository.ephemeral_templates),
            "ephemeral_secret_policies": {
                name: {"policy": policy.policy, "binding_id": policy.binding_id}
                for name, policy in repository.ephemeral_secret_policies.items()
            },
        })
    return parsed.service.database_generation, routes, []


def profile_database_routing_check(
    *,
    profile_path: Path = CLIENT_PROFILE_PATH,
    database_path: Path = AUTHORITY_DATABASE_PATH,
) -> dict[str, Any]:
    """Verify that the published route catalog matches current resources."""

    result: dict[str, Any] = {
        "ok": True,
        "code": "profile_database_routing_ready",
        "profile": os.fspath(profile_path),
        "database": os.fspath(database_path),
        "checked_routes": 0,
        "checked_ephemeral_templates": 0,
        "issues": [],
    }
    issues: list[dict[str, Any]] = result["issues"]
    if not path_lexists(profile_path):
        issues.append(_profile_database_issue("profile_missing"))
    if not path_lexists(database_path):
        issues.append(_profile_database_issue("database_missing"))
    if issues:
        result["ok"] = False
        result["code"] = "profile_database_routing_drift"
        return result
    try:
        document = _read_protected_profile(profile_path)
        service_generation, routes, parse_issues = _profile_repository_routes(
            document
        )
        issues.extend(parse_issues)
        expected_database = _protected_regular_metadata(
            database_path, label="service authority database"
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
            metadata = connection.execute(
                "SELECT schema_version, database_generation, migration_state "
                "FROM schema_metadata WHERE singleton = 1"
            ).fetchone()
            target_schema, _parser, _error, _fields = (
                _target_broker_activation_contract()
            )
            if (
                metadata is None
                or int(metadata["schema_version"]) != target_schema
                or str(metadata["migration_state"]) != "ready"
                or str(metadata["database_generation"]) != service_generation
            ):
                issues.append(
                    _profile_database_issue("database_generation_mismatch")
                )
            database_routes = connection.execute(
                """
                SELECT r.repo_id, r.canonical_root, r.generation
                FROM repositories r
                JOIN repository_installations i USING(repo_id)
                WHERE r.state = 'active' AND i.status = 'installed'
                  AND i.startup_fenced = 0
                ORDER BY r.canonical_root, r.repo_id
                """
            ).fetchall()
            route_index = {str(item["repo_id"]): item for item in routes}
            database_index = {
                str(item["repo_id"]): item for item in database_routes
            }
            if set(route_index) != set(database_index):
                issues.append(
                    _profile_database_issue("repository_catalog_mismatch")
                )
            for repo_id in sorted(set(route_index) & set(database_index)):
                route = route_index[repo_id]
                stored = database_index[repo_id]
                if (
                    route["canonical_root"] != str(stored["canonical_root"])
                    or route["generation"] != int(stored["generation"])
                ):
                    issues.append(
                        _profile_database_issue(
                            "repository_route_mismatch", repo_id=repo_id
                        )
                    )
                templates = connection.execute(
                    """
                    SELECT name, template_id, secret_policy_kind,
                           secret_binding_id
                    FROM ephemeral_container_templates
                    WHERE repo_id = ? AND enabled = 1
                    ORDER BY name
                    """,
                    (repo_id,),
                ).fetchall()
                expected_templates = {
                    str(item["name"]): str(item["template_id"])
                    for item in templates
                }
                expected_policies = {
                    str(item["name"]): {
                        "policy": str(item["secret_policy_kind"]),
                        "binding_id": str(item["secret_binding_id"]),
                    }
                    for item in templates
                    if item["secret_policy_kind"] is not None
                }
                if route["ephemeral_templates"] != expected_templates:
                    issues.append(
                        _profile_database_issue(
                            "ephemeral_template_catalog_mismatch",
                            repo_id=repo_id,
                        )
                    )
                if route["ephemeral_secret_policies"] != expected_policies:
                    issues.append(
                        _profile_database_issue(
                            "ephemeral_secret_catalog_mismatch",
                            repo_id=repo_id,
                        )
                    )
                result["checked_ephemeral_templates"] += len(templates)
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        current_database = database_path.lstat()
        if (current_database.st_dev, current_database.st_ino) != (
            expected_database.st_dev,
            expected_database.st_ino,
        ):
            issues.append(
                _profile_database_issue("database_replaced_during_check")
            )
        result["checked_routes"] = len(routes)
    except (InstallError, OSError, sqlite3.Error, ValueError) as error:
        issues.append(
            _profile_database_issue(
                "routing_check_unavailable", detail=str(error)[:1024]
            )
        )
    result["ok"] = not issues
    if issues:
        result["code"] = "profile_database_routing_drift"
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
    if any("ephemeral" in reason for reason in reasons):
        steps.append(
            "republish the host-wide route catalog with the exact ephemeral "
            "template and credential-policy identities"
        )
    if steps:
        steps.append("then republish the host-wide route catalog")
    else:
        steps.append(
            "republish the host-wide route catalog after resolving the reported "
            "resource identity conflict"
        )
    steps.append("then rerun plan and verify")
    return ", ".join(steps)


def require_profile_database_routing_consistency() -> dict[str, Any]:
    result = profile_database_routing_check()
    if result["ok"]:
        return result
    reasons = ", ".join(
        sorted({str(issue.get("reason")) for issue in result["issues"]})
    )
    raise ProfileDatabaseRoutingDrift(
        f"{PROFILE_DATABASE_ROUTING_DRIFT}: the published host route catalog "
        f"differs from current service state ({reasons}); "
        f"{_profile_database_repair_guidance(result)} before restart"
    )


def _target_broker_activation_contract(
) -> tuple[int, Any, type[Exception], frozenset[str]]:
    """Load the exact broker/profile contract that the installed unit executes."""

    module_root = ROOT / "skills/codex-dev-coordinator/scripts"
    module_root_text = os.fspath(module_root)
    if module_root_text not in sys.path:
        sys.path.insert(0, module_root_text)
    try:
        from devcoordinator.broker_profile import (  # type: ignore[import-not-found]
            BrokerProfileError,
            REPOSITORY_PROFILE_FIELDS,
            profile_from_document,
        )
        from devcoordinator.schema import (  # type: ignore[import-not-found]
            SCHEMA_VERSION,
        )
    except Exception as error:
        raise InstallError(
            "installed broker activation contract is unavailable"
        ) from error

    if (
        type(SCHEMA_VERSION) is not int
        or SCHEMA_VERSION <= 0
        or not callable(profile_from_document)
        or not isinstance(BrokerProfileError, type)
        or not issubclass(BrokerProfileError, Exception)
        or not isinstance(REPOSITORY_PROFILE_FIELDS, frozenset)
        or not REPOSITORY_PROFILE_FIELDS
    ):
        raise InstallError("installed broker authority schema contract is invalid")
    return (
        SCHEMA_VERSION,
        profile_from_document,
        BrokerProfileError,
        REPOSITORY_PROFILE_FIELDS,
    )


def _read_protected_authority_schema(path: Path) -> int:
    expected = _protected_regular_metadata(
        path,
        label="service authority database",
    )
    connection = sqlite3.connect(
        f"{path.resolve(strict=True).as_uri()}?mode=ro",
        uri=True,
        isolation_level=None,
        timeout=5.0,
    )
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        row = connection.execute(
            "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
        ).fetchone()
        if row is None or type(row[0]) is not int or int(row[0]) <= 0:
            raise InstallError("service authority database schema metadata is invalid")
        schema_version = int(row[0])
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()
    current = path.lstat()
    if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
        raise InstallError("service authority database changed while it was inspected")
    return schema_version


def activation_authority_contract_check(
    *,
    database_path: Path = AUTHORITY_DATABASE_PATH,
    profile_path: Path = CLIENT_PROFILE_PATH,
) -> dict[str, Any]:
    """Prove schema/profile compatibility before any activation lifecycle work.

    It executes the target host-wide route parser once and requires an existing
    authority database to match the target broker schema exactly.
    """

    target_schema, parse_profile, profile_error, _repository_fields = (
        _target_broker_activation_contract()
    )
    evidence: dict[str, Any] = {
        "ok": True,
        "code": "activation_authority_contract_ready",
        "database": os.fspath(database_path),
        "profile": os.fspath(profile_path),
        "target_broker_schema": target_schema,
        "authority_database_schema": None,
        "checked_profile_repositories": 0,
        "issues": [],
    }
    issues: list[dict[str, Any]] = evidence["issues"]

    if path_lexists(database_path):
        try:
            database_schema = _read_protected_authority_schema(database_path)
        except (InstallError, OSError, sqlite3.Error, ValueError) as error:
            issues.append(
                _profile_database_issue(
                    "authority_schema_unavailable",
                    detail=str(error)[:1024],
                )
            )
        else:
            evidence["authority_database_schema"] = database_schema
            if database_schema != target_schema:
                issues.append(
                    _profile_database_issue(
                        "authority_schema_mismatch",
                        database_schema=database_schema,
                        target_broker_schema=target_schema,
                    )
                )

    if path_lexists(profile_path):
        try:
            document = _read_protected_profile(profile_path)
        except (InstallError, OSError, ValueError) as error:
            issues.append(
                _profile_database_issue(
                    "profile_target_contract_unavailable",
                    detail=str(error)[:1024],
                )
            )
        else:
            try:
                parsed = parse_profile(document, effective_uid=0)
            except profile_error as error:
                issues.append(
                    _profile_database_issue(
                        "profile_target_contract_invalid", detail=str(error)[:1024]
                    )
                )
            except Exception as error:
                issues.append(
                    _profile_database_issue(
                        "profile_target_contract_invalid", detail=str(error)[:1024]
                    )
                )
            else:
                evidence["checked_profile_repositories"] = len(parsed.repositories)

    if issues:
        evidence["ok"] = False
        evidence["code"] = AUTHORITY_SCHEMA_CUTOVER_REQUIRED
        raise AuthoritySchemaCutoverRequired(evidence)
    return evidence


def managed_skill_sources() -> dict[str, Path]:
    """Return the fixed canonical skill set after proving every source."""

    skills_root = require_real(ROOT / "skills", directory=True)
    sources: dict[str, Path] = {}
    for name in MANAGED_SKILLS:
        source = require_real(skills_root / name, directory=True)
        skill_file = source / "SKILL.md"
        try:
            metadata = skill_file.lstat()
        except OSError as error:
            raise InstallError(f"canonical skill manifest is unavailable: {name}") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise InstallError(f"canonical skill manifest is unsafe: {name}")
        sources[name] = source
    return sources


def client_skill_link_expectations(record: Any, home: Path) -> list[dict[str, Any]]:
    """Describe every explicit runtime/skill destination without HOME inference."""

    sources = managed_skill_sources()
    return [
        {
            "user": record.pw_name,
            "uid": record.pw_uid,
            "runtime": relative.parts[0].removeprefix("."),
            "target_root": str(home / relative),
            "skill": skill,
            "source": str(sources[skill]),
            "destination": str(home / relative / skill),
        }
        for relative in AGENT_SKILL_ROOTS
        for skill in MANAGED_SKILLS
    ]


def desired_plan(names: list[str]) -> dict[str, Any]:
    validate_broker_unit_source()
    clients = client_records(names)
    source_policy = require_managed_docker_source_policy()
    docker_admission = docker_socket_admission_evidence(clients)
    home_write_paths = enrolled_home_write_paths(clients)
    restart_precondition = profile_database_routing_check()
    repair_guidance = _profile_database_repair_guidance(restart_precondition)
    restart_step = (
        "rerun verify, then start or restart devcoordinator-broker.service"
        if restart_precondition["ok"]
        else (
            f"stop before service restart; resolve {PROFILE_DATABASE_ROUTING_DRIFT} "
            f"as follows: {repair_guidance}"
        )
    )
    plan = {
        "authority": {
            "database": str(AUTHORITY_DATABASE_PATH),
            "socket": "/run/devcoordinator-authority.sock",
            "profile": str(CLIENT_PROFILE_PATH),
            "service_user": SERVICE_USER,
            "socket_gid": SYSTEM_OWNER_GID,
            "socket_mode": "0666",
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
        "docker_admission": docker_admission,
        "managed_docker_source_policy": source_policy,
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
        "managed_skills": [
            {"name": name, "source": str(source)}
            for name, source in managed_skill_sources().items()
        ],
        "clients": [
            {
                "user": record.pw_name,
                "uid": record.pw_uid,
                "journal": f"/var/lib/devcoordinator-clients/{record.pw_uid}",
                "skill_roots": [
                    str(home / relative)
                    for relative in AGENT_SKILL_ROOTS
                ],
                "skill_links": client_skill_link_expectations(record, home),
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
                "publish the broker's trusted-local global /home sandbox view"
                ),
                "publish the host-wide repository and resource route catalog",
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
            "Rerun verify immediately before the journal-bound activate action "
            "starts devcoordinator-broker.service."
        )
    else:
        plan["next_step"] = (
            f"Resolve {PROFILE_DATABASE_ROUTING_DRIFT}: {repair_guidance}. "
            "Do not restart the broker."
        )
    return plan


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_flags |= getattr(os, "O_CLOEXEC", 0)
        directory = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
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


def _directory_state(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {"exists": False}
    except OSError as error:
        raise InstallError(f"required directory cannot be inspected: {path}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise InstallError(f"required directory is unsafe: {path}")
    return {
        "exists": True,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": stat.S_IMODE(metadata.st_mode),
    }


def _same_directory_identity(state: dict[str, Any], metadata: os.stat_result) -> bool:
    return (
        state.get("exists") is True
        and state.get("device") == metadata.st_dev
        and state.get("inode") == metadata.st_ino
        and stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
    )


def install_owned_skill_directory(
    path: Path,
    *,
    uid: int,
    gid: int,
    journal: dict[str, Any],
    persist: Any,
) -> dict[str, Any]:
    """Create or normalize one exact agent directory with rollback evidence."""

    before = _directory_state(path)
    entry: dict[str, Any] = {
        "path": str(path),
        "before": before,
        "expected_uid": uid,
        "expected_gid": gid,
        "expected_mode": 0o700,
        "stage": "prepared",
    }
    journal["skill_root_directories"].append(entry)
    persist()
    if not before["exists"]:
        try:
            os.mkdir(path, 0o700)
        except OSError as error:
            raise InstallError(f"could not create agent skill directory: {path}") from error
        entry["created"] = _directory_state(path)
        persist()
    try:
        os.chown(path, uid, gid)
        os.chmod(path, 0o700)
    except OSError as error:
        raise InstallError(f"could not secure agent skill directory: {path}") from error
    entry["installed"] = _directory_state(path)
    entry["stage"] = "installed"
    persist()
    return entry


def install_client_skill_roots(
    record: Any,
    home: Path,
    *,
    journal: dict[str, Any],
    persist: Any,
) -> list[Path]:
    """Install only the two explicit per-account Codex/Claude skill roots."""

    roots: list[Path] = []
    for relative in AGENT_SKILL_ROOTS:
        root = home / relative
        parent = root.parent
        install_owned_skill_directory(
            parent,
            uid=record.pw_uid,
            gid=record.pw_gid,
            journal=journal,
            persist=persist,
        )
        install_owned_skill_directory(
            root,
            uid=record.pw_uid,
            gid=record.pw_gid,
            journal=journal,
            persist=persist,
        )
        roots.append(root)
    return roots


def rollback_skill_root_directories(entries: Any) -> None:
    """Restore metadata or remove only unchanged directories created here."""

    if not isinstance(entries, list):
        raise InstallError("skill-root directory journal is invalid")
    for raw in reversed(entries):
        if not isinstance(raw, dict):
            raise InstallError("skill-root directory journal entry is invalid")
        path = Path(str(raw.get("path", "")))
        before = raw.get("before")
        installed = raw.get("installed")
        if not path.is_absolute() or not isinstance(before, dict):
            raise InstallError("skill-root directory rollback target is invalid")
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            if before.get("exists") is False:
                continue
            raise InstallError(f"pre-existing skill directory disappeared: {path}")
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise InstallError(f"skill directory changed type before rollback: {path}")
        if isinstance(installed, dict) and not _same_directory_identity(
            installed, metadata
        ):
            raise InstallError(f"skill directory identity changed before rollback: {path}")
        if isinstance(installed, dict) and any(
            value != installed.get(key)
            for key, value in (
                ("uid", metadata.st_uid),
                ("gid", metadata.st_gid),
                ("mode", stat.S_IMODE(metadata.st_mode)),
            )
        ):
            raise InstallError(f"skill directory metadata changed before rollback: {path}")
        if before.get("exists") is True:
            if not _same_directory_identity(before, metadata):
                raise InstallError(f"skill directory identity changed before rollback: {path}")
            os.chown(path, int(before["uid"]), int(before["gid"]))
            os.chmod(path, int(before["mode"]))
            continue
        if not isinstance(installed, dict):
            raise InstallError(f"created skill directory changed before rollback: {path}")
        try:
            os.rmdir(path)
        except OSError as error:
            raise InstallError(
                f"created skill directory is not empty or cannot be rolled back: {path}"
            ) from error


def skill_manager_arguments(
    action: str,
    roots: list[Path],
    *,
    transaction: Path | None = None,
    allow_noncanonical: bool = False,
) -> list[str]:
    arguments = [
        sys.executable,
        str(ROOT / "scripts/manage_skill_links.py"),
        action,
        "--repo-root",
        str(ROOT),
    ]
    for skill in MANAGED_SKILLS:
        arguments.extend(("--skill", skill))
    for root in roots:
        arguments.extend(("--target-root", str(root)))
    if transaction is not None:
        arguments.extend(("--transaction-dir", str(transaction)))
    if allow_noncanonical:
        arguments.append("--allow-noncanonical")
    arguments.append("--json")
    return arguments


def verify_skill_links(roots: list[Path]) -> dict[str, Any]:
    """Return manager evidence plus explicit rows for missing/unsafe roots."""

    available: list[Path] = []
    entries: list[dict[str, Any]] = []
    sources = managed_skill_sources()
    for root in roots:
        try:
            metadata = root.lstat()
        except FileNotFoundError:
            status = "root_missing"
        except OSError:
            status = "root_unreadable"
        else:
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                status = "root_unsafe"
            else:
                available.append(root)
                continue
        entries.extend(
            {
                "target_root": str(root),
                "skill": skill,
                "source": str(source),
                "destination": str(root / skill),
                "status": status,
            }
            for skill, source in sources.items()
        )
    manager_evidence: dict[str, Any] | None = None
    if available:
        _returncode, manager_evidence = run_json_command(
            *skill_manager_arguments("verify", available),
            accepted_returncodes=(0, 1),
        )
        manager_entries = manager_evidence.get("entries")
        if not isinstance(manager_entries, list) or any(
            not isinstance(entry, dict) for entry in manager_entries
        ):
            raise InstallError("skill link manager returned invalid verification evidence")
        entries.extend(manager_entries)
    expected = len(roots) * len(MANAGED_SKILLS)
    if len(entries) != expected:
        raise InstallError("skill link verification did not cover every root and skill")
    return {
        "ok": all(entry.get("status") == "direct_link" for entry in entries),
        "skills": list(MANAGED_SKILLS),
        "target_roots": [str(root) for root in roots],
        "entries": entries,
        "manager": manager_evidence,
    }


def capture_source_acl(transaction: Path) -> Path:
    """Preserve every ACL the installation will extend before mutation."""

    sources = managed_skill_sources()
    skills_root = require_real(ROOT / "skills", directory=True)
    repository = require_real(ROOT, directory=True)
    backup = transaction / "canonical-skill-source.acl"
    getfacl = command("getfacl")
    payload = b"".join(
        [
            capture(getfacl, "--absolute-names", str(repository)),
            capture(getfacl, "--absolute-names", str(skills_root)),
            *[
                capture(
                    getfacl,
                    "--absolute-names",
                    "--recursive",
                    str(source),
                )
                for source in sources.values()
            ],
        ]
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
    """Give every trusted-local account read/execute access to linked skills."""

    sources = managed_skill_sources()
    skills_root = require_real(ROOT / "skills", directory=True)
    repository = require_real(ROOT, directory=True)
    setfacl = command("setfacl")
    run(setfacl, "--modify", "o::r-x", str(repository))
    run(setfacl, "--modify", "o::r-x", str(skills_root))
    for source in sources.values():
        run(
            setfacl,
            "--recursive",
            "--modify",
            "o::rX",
            str(source),
        )
        for directory, child_directories, _files in os.walk(source):
            child_directories.sort()
            run(
                setfacl,
                "--modify",
                "d:o::rX",
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
    require_managed_docker_source_policy()
    restart_precondition = require_profile_database_routing_consistency()
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
        "skill_link_evidence": [],
        "skill_root_directories": [],
        "group_members_added": [],
        "client_journals": [],
        "legacy_docker_dropin": None,
        "legacy_docker_dropin_removed": False,
        "test_admission_schema": None,
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
        journal["test_admission_schema"] = install_test_admission_fence_schema()
        atomic_json(transaction / JOURNAL_NAME, journal)
        try:
            pwd.getpwnam(SERVICE_USER)
        except KeyError as error:
            raise InstallError("system authority identity is missing") from error

        acl_backup = capture_source_acl(transaction)
        journal["source_acl_backup"] = str(acl_backup)
        atomic_json(transaction / JOURNAL_NAME, journal)
        grant_source_acl()

        persist_journal = lambda: atomic_json(transaction / JOURNAL_NAME, journal)
        for record, home in clients:
            client_journal = Path(f"/var/lib/devcoordinator-clients/{record.pw_uid}")
            ensure_owned_directory(
                client_journal,
                uid=record.pw_uid,
                gid=record.pw_gid,
                mode=0o700,
            )
            journal["client_journals"].append(str(client_journal))

            roots = install_client_skill_roots(
                record,
                home,
                journal=journal,
                persist=persist_journal,
            )

            link_transaction = transaction / f"skill-links-{record.pw_uid}"
            _returncode, preflight = run_json_command(
                *skill_manager_arguments("plan", roots)
            )
            evidence: dict[str, Any] = {
                "user": record.pw_name,
                "uid": record.pw_uid,
                "skills": list(MANAGED_SKILLS),
                "target_roots": [str(root) for root in roots],
                "preflight": preflight,
                "transaction": str(link_transaction),
            }
            journal["skill_link_evidence"].append(evidence)
            persist_journal()
            _returncode, applied = run_json_command(
                *skill_manager_arguments(
                    "apply",
                    roots,
                    transaction=link_transaction,
                    allow_noncanonical=allow_noncanonical,
                )
            )
            journal["link_transactions"].append(str(link_transaction))
            evidence["apply"] = applied
            persist_journal()
            verification = verify_skill_links(roots)
            evidence["verification"] = verification
            persist_journal()
            if not verification["ok"]:
                raise InstallError(
                    "skill link manager did not publish every canonical skill directly"
                )

        # These ownership checks document the intended split after tmpfiles.
        authority = Path("/var/lib/devcoordinator").lstat()
        if authority.st_uid != service.pw_uid or stat.S_IMODE(authority.st_mode) != 0o700:
            raise InstallError("service authority directory failed ownership/mode verification")
        profile_parent = CLIENT_PROFILE_PATH.parent.lstat()
        if (
            profile_parent.st_uid != service.pw_uid
            or profile_parent.st_gid != SYSTEM_OWNER_GID
            or stat.S_IMODE(profile_parent.st_mode) != 0o755
        ):
            raise InstallError("client profile directory failed ownership/mode verification")
        # Recheck after every installer mutation. The initial proof prevents
        # starting from known drift; this final proof prevents a concurrent
        # profile/database change from turning the returned restart guidance
        # into a stale authorization claim.
        journal["restart_precondition"] = (
            require_profile_database_routing_consistency()
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


def _canonical_install_operation_id(raw: str) -> str:
    try:
        value = str(uuid.UUID(str(raw)))
    except (ValueError, TypeError, AttributeError) as error:
        raise InstallError("--operation-id must be one canonical UUID") from error
    if value != raw:
        raise InstallError("--operation-id must be one canonical UUID")
    return value


def _load_install_journal(transaction: Path) -> tuple[Path, Path, dict[str, Any]]:
    transaction = _private_transaction(transaction)
    journal_path = transaction / JOURNAL_NAME
    require_private_regular(journal_path, label="installation journal")
    try:
        document = json.loads(journal_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InstallError("installation journal is invalid") from error
    if (
        not isinstance(document, dict)
        or document.get("version") != 1
        or document.get("repo_root") != str(ROOT)
    ):
        raise InstallError("transaction belongs to another installer contract")
    return transaction, journal_path, document


def _journal_client_names(document: dict[str, Any]) -> list[str]:
    evidence = document.get("skill_link_evidence")
    if not isinstance(evidence, list) or not evidence:
        raise InstallError("installation journal has no exact client evidence")
    names: list[str] = []
    for entry in evidence:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("user"), str)
            or not entry["user"]
        ):
            raise InstallError("installation journal client evidence is invalid")
        names.append(str(entry["user"]))
    if len(set(names)) != len(names):
        raise InstallError("installation journal contains duplicate clients")
    return sorted(names)


def _restore_activation_service_baseline(initial_enabled: bool) -> None:
    if _systemd_unit_active():
        run(command("systemctl"), "stop", BROKER_UNIT)
        if _systemd_unit_active():
            raise InstallError("broker remained active while restoring activation baseline")
    enabled = _systemd_unit_enabled()
    if initial_enabled and not enabled:
        run(command("systemctl"), "enable", BROKER_UNIT)
    elif not initial_enabled and enabled:
        run(command("systemctl"), "disable", BROKER_UNIT)
    if _systemd_unit_enabled() != initial_enabled:
        raise InstallError("broker enablement baseline could not be restored")


def activate_install(
    names: list[str],
    transaction: Path,
    operation_id: str,
    wait_seconds: int,
) -> dict[str, Any]:
    """Activate one exact applied installation through a durable state machine."""

    if os.geteuid() != 0:
        raise InstallError("activate requires root")
    operation_id = _canonical_install_operation_id(operation_id)
    if type(wait_seconds) is not int or not 1 <= wait_seconds <= 120:
        raise InstallError("--wait-seconds must be an integer from 1 through 120")
    transaction, journal_path, document = _load_install_journal(transaction)
    requested_clients = sorted(record.pw_name for record, _home in client_records(names))
    journal_clients = _journal_client_names(document)
    if requested_clients != journal_clients:
        raise InstallError("activation client set does not match the installation journal")
    if document.get("starts_service") is not False or document.get(
        "requires_service_restart_for_sandbox_changes"
    ) is not True:
        raise InstallError("installation journal does not authorize explicit activation")

    activation = document.get("activation")
    if activation is not None:
        if (
            not isinstance(activation, dict)
            or activation.get("operation_id") != operation_id
            or activation.get("clients") != requested_clients
            or activation.get("initial_active") is not False
            or type(activation.get("initial_enabled")) is not bool
        ):
            raise InstallError("activation replay does not match its durable intent")
    if document.get("status") not in {"applied", "activated"}:
        raise InstallError("installation transaction is not activation-ready")

    # This target-contract proof is intentionally activation-only and runs
    # before even the installed-unit verifier inspects systemd.  Staging an
    # installer transaction against schema 12 remains possible, but the target
    # A broker cannot reach lifecycle inspection or mutation until the exact
    # supported schema migration and host-wide route publication have completed.
    authority_contract = activation_authority_contract_check()
    verification = verify_install(requested_clients)
    if not verification.get("ok"):
        raise InstallError("current server-wide installation verification failed")
    current_precondition = require_profile_database_routing_consistency()
    if (
        current_precondition != document.get("restart_precondition")
        or current_precondition != verification.get("restart_precondition")
    ):
        raise InstallError("broker activation route proof changed after apply")

    if document.get("status") == "activated":
        if not isinstance(activation, dict) or activation.get("phase") != "ready":
            raise InstallError("activated installation journal is contradictory")
        if not _systemd_unit_active():
            raise InstallError("activated broker is no longer active")
        client_readiness = _verify_broker_client_readiness(requested_clients)
        if client_readiness != activation.get("client_readiness"):
            raise InstallError("activated broker client readiness evidence changed")
        replay = dict(document)
        replay["replayed"] = True
        return replay

    if isinstance(activation, dict) and activation.get("phase") in {
        "starting",
        "restoring_baseline",
    } and _systemd_unit_active():
        try:
            _wait_for_broker_ready(wait_seconds)
            client_readiness = _verify_broker_client_readiness(requested_clients)
        except BaseException:
            _restore_activation_service_baseline(bool(activation["initial_enabled"]))
            activation["phase"] = "failed"
            activation["status"] = "failed"
            document["status"] = "applied"
            atomic_json(journal_path, document)
            raise
        activation["phase"] = "ready"
        activation["status"] = "ready"
        activation["client_readiness"] = client_readiness
        activation["completed_at_epoch"] = int(time.time())
        document["status"] = "activated"
        atomic_json(journal_path, document)
        replay = dict(document)
        replay["replayed"] = True
        return replay

    initial_active = _systemd_unit_active()
    if initial_active:
        raise InstallError("activation requires the installed broker to be inactive")
    initial_enabled = _systemd_unit_enabled()
    if isinstance(activation, dict):
        if initial_enabled is not activation["initial_enabled"]:
            raise InstallError("broker enablement changed after failed activation")
        activation["attempts"] = int(activation.get("attempts", 1)) + 1
    else:
        activation = {
            "operation_id": operation_id,
            "clients": requested_clients,
            "initial_active": False,
            "initial_enabled": initial_enabled,
            "attempts": 1,
        }
        document["activation"] = activation
    activation["authority_contract"] = authority_contract
    activation["phase"] = "starting"
    activation["status"] = "starting"
    activation["started_at_epoch"] = int(time.time())
    activation.pop("error", None)
    activation.pop("client_readiness", None)
    atomic_json(journal_path, document)

    try:
        if not initial_enabled:
            run(command("systemctl"), "enable", BROKER_UNIT)
        run(command("systemctl"), "start", BROKER_UNIT)
        _wait_for_broker_ready(wait_seconds)
        client_readiness = _verify_broker_client_readiness(requested_clients)
    except BaseException as error:
        activation["phase"] = "restoring_baseline"
        activation["status"] = "failed"
        activation["error"] = str(error)[:2048]
        activation["failure_evidence"] = _broker_start_failure_evidence()
        atomic_json(journal_path, document)
        try:
            _restore_activation_service_baseline(initial_enabled)
        except BaseException as cleanup_error:
            activation["phase"] = "cleanup_failed"
            activation["cleanup_error"] = str(cleanup_error)[:2048]
            document["status"] = "activation_rollback_required"
            atomic_json(journal_path, document)
            raise InstallError(
                "broker activation failed and its service baseline could not be restored"
            ) from cleanup_error
        activation["phase"] = "failed"
        document["status"] = "applied"
        atomic_json(journal_path, document)
        if isinstance(error, InstallError):
            raise
        raise InstallError("broker activation failed") from error

    activation["phase"] = "ready"
    activation["status"] = "ready"
    activation["client_readiness"] = client_readiness
    activation["completed_at_epoch"] = int(time.time())
    document["status"] = "activated"
    atomic_json(journal_path, document)
    return document


def restore_activation_baseline(
    transaction: Path,
    operation_id: str,
) -> dict[str, Any]:
    """Reconcile only the service state owned by one activation attempt."""

    if os.geteuid() != 0:
        raise InstallError("restore-activation-baseline requires root")
    operation_id = _canonical_install_operation_id(operation_id)
    _transaction, journal_path, document = _load_install_journal(transaction)
    activation = document.get("activation")
    if (
        not isinstance(activation, dict)
        or activation.get("operation_id") != operation_id
        or activation.get("initial_active") is not False
        or type(activation.get("initial_enabled")) is not bool
        or document.get("status")
        not in {"applied", "activated", "activation_rollback_required"}
    ):
        raise InstallError("activation baseline reconciliation is not authorized")
    activation["phase"] = "restoring_baseline"
    activation["status"] = "restoring_baseline"
    atomic_json(journal_path, document)
    _restore_activation_service_baseline(bool(activation["initial_enabled"]))
    activation["phase"] = "failed"
    activation["status"] = "failed"
    activation["baseline_restored_at_epoch"] = int(time.time())
    document["status"] = "applied"
    atomic_json(journal_path, document)
    return document


def rollback_install(transaction: Path) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise InstallError("rollback requires root")
    transaction, journal_path, document = _load_install_journal(transaction)
    activation = document.get("activation")
    if activation is not None:
        if (
            not isinstance(activation, dict)
            or activation.get("initial_active") is not False
            or type(activation.get("initial_enabled")) is not bool
            or not isinstance(activation.get("operation_id"), str)
            or not isinstance(activation.get("clients"), list)
        ):
            raise InstallError("installation activation journal is invalid")
        document["status"] = "rolling_back"
        activation["phase"] = "restoring_baseline"
        atomic_json(journal_path, document)
        _restore_activation_service_baseline(bool(activation["initial_enabled"]))
        activation["phase"] = "rolled_back"
        activation["status"] = "rolled_back"
        atomic_json(journal_path, document)
    elif _systemd_unit_active():
        raise InstallError(
            "active broker is not owned by this installation transaction; stop it "
            "through its owning activation before rollback"
        )
    manager = ROOT / "scripts/manage_skill_links.py"
    for link_transaction in reversed(document.get("link_transactions", [])):
        run(
            sys.executable,
            str(manager),
            "rollback",
            "--transaction-dir",
            str(link_transaction),
        )
    rollback_skill_root_directories(document.get("skill_root_directories", []))
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
        run(command("gpasswd"), "-d", str(user), LEGACY_ACCESS_GROUP)
    run(command("systemctl"), "daemon-reload")
    document["status"] = "rolled_back"
    atomic_json(journal_path, document)
    return document


def verify_install(names: list[str]) -> dict[str, Any]:
    plan = desired_plan(names)
    failures: list[str] = []
    failure_codes: list[str] = []
    skill_link_evidence: list[dict[str, Any]] = []
    warnings, warning_codes = _docker_admission_warning_summary(
        plan["docker_admission"]
    )
    restart_precondition = plan["restart_precondition"]
    if not restart_precondition["ok"]:
        failure_codes.append(PROFILE_DATABASE_ROUTING_DRIFT)
        reasons = ", ".join(
            sorted(
                {
                    str(issue.get("reason"))
                    for issue in restart_precondition["issues"]
                }
            )
        )
        failures.append(
            f"{PROFILE_DATABASE_ROUTING_DRIFT}: published routes and current service "
            f"state differ ({reasons}); do not restart the broker"
        )
    dependency_evidence = runtime_dependency_evidence()
    dependency_failure = runtime_dependency_failure(dependency_evidence)
    if dependency_failure is not None:
        failures.append(dependency_failure)
    runner_script_failure = worker_runner_script_failure()
    if runner_script_failure is not None:
        failures.append(runner_script_failure)
    try:
        service = pwd.getpwnam(SERVICE_USER)
    except KeyError:
        failures.append("service identity is missing")
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
                "trusted-local home drop-in does not publish the global /home sandbox"
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
    if service is not None:
        try:
            metadata = profile_parent.lstat()
        except FileNotFoundError:
            failures.append(f"client profile directory is missing: {profile_parent}")
        else:
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != service.pw_uid
                or metadata.st_gid != SYSTEM_OWNER_GID
                or stat.S_IMODE(metadata.st_mode) != 0o755
            ):
                failures.append(f"client profile directory is unsafe: {profile_parent}")
    profile = CLIENT_PROFILE_PATH
    if profile.exists() or profile.is_symlink():
        metadata = profile.lstat()
        if (
            service is None
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != service.pw_uid
            or metadata.st_gid != SYSTEM_OWNER_GID
            or stat.S_IMODE(metadata.st_mode) != 0o644
        ):
            failures.append(f"client profile is unsafe: {profile}")
    for client in plan["clients"]:
        record = pwd.getpwnam(client["user"])
        journal = Path(client["journal"])
        if not journal.is_dir() or journal.is_symlink():
            failures.append(f"client journal is missing or unsafe: {journal}")
        roots = [Path(str(root)) for root in client["skill_roots"]]
        try:
            evidence = verify_skill_links(roots)
        except InstallError as error:
            evidence = {
                "ok": False,
                "skills": list(MANAGED_SKILLS),
                "target_roots": [str(root) for root in roots],
                "entries": [],
                "error": str(error),
            }
            failures.append(
                f"canonical skill link verification failed for UID {record.pw_uid}: {error}"
            )
        else:
            for entry in evidence["entries"]:
                if entry.get("status") != "direct_link":
                    failures.append(
                        "skill is not a direct canonical link "
                        f"({entry.get('status')}): {entry.get('destination')}"
                    )
        skill_link_evidence.append(
            {"user": record.pw_name, "uid": record.pw_uid, **evidence}
        )
    return {
        "ok": not failures,
        "failures": failures,
        "failure_codes": failure_codes,
        "warnings": warnings,
        "warning_codes": warning_codes,
        "plan": plan,
        "skill_link_evidence": skill_link_evidence,
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
    activate = actions.add_parser("activate")
    activate.add_argument("--client-user", action="append", required=True)
    activate.add_argument("--transaction-dir", required=True)
    activate.add_argument("--operation-id", required=True)
    activate.add_argument("--wait-seconds", type=int, default=30)
    restore_activation = actions.add_parser("restore-activation-baseline")
    restore_activation.add_argument("--transaction-dir", required=True)
    restore_activation.add_argument("--operation-id", required=True)
    rollback = actions.add_parser("rollback")
    rollback.add_argument("--transaction-dir", required=True)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    lock_descriptor: InstallerFenceHandle | None = None
    command_succeeded = False
    try:
        if args.action in {
            "apply",
            "activate",
            "restore-activation-baseline",
            "rollback",
        }:
            lock_descriptor = _acquire_installer_lock()
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
        elif args.action == "activate":
            result = activate_install(
                args.client_user,
                Path(args.transaction_dir),
                args.operation_id,
                args.wait_seconds,
            )
        elif args.action == "restore-activation-baseline":
            result = restore_activation_baseline(
                Path(args.transaction_dir),
                args.operation_id,
            )
        elif args.action == "rollback":
            result = rollback_install(Path(args.transaction_dir))
        else:
            result = verify_install(args.client_user)
            if not result["ok"]:
                print(json.dumps(result, indent=2, sort_keys=True))
                return 1
        command_succeeded = True
    except (InstallError, OSError, ValueError, json.JSONDecodeError) as error:
        code = getattr(error, "code", None)
        if code is not None:
            payload: dict[str, Any] = {
                "ok": False,
                "code": str(code),
                "error": str(error),
            }
            classification = getattr(error, "classification", None)
            action_required = getattr(error, "action_required", None)
            evidence = getattr(error, "evidence", None)
            if isinstance(classification, str) and classification:
                payload["classification"] = classification
            if isinstance(action_required, str) and action_required:
                payload["action_required"] = action_required
            if isinstance(evidence, dict):
                payload["evidence"] = evidence
            print(
                json.dumps(payload, indent=2, sort_keys=True),
                file=sys.stderr,
            )
        else:
            print(f"server-wide coordinator installation failed: {error}", file=sys.stderr)
        return 2
    finally:
        if lock_descriptor is not None:
            lock_descriptor.close(command_succeeded=command_succeeded)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
