#!/usr/bin/env python3
"""Switch the production graph to one immutable current-format release.

Retained control data stays at the fixed authority path. An incompatible
authority schema is replaced, while its writers are stopped, by the semantic
allowlist in ``devcoordinator.retained_control``. No in-place migration chain
or operational/test/history state crosses that boundary.

The switch installs the immutable unit set, refreshes systemd identities and
runtime directories, starts a second Console slot on two unused loopback
ports, promotes it through the existing slot-supervisor protocol, atomically
publishes the new edge target, and only then drains the old slot.  The exact
prior unit files are retained for automatic rollback.
"""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import time
from typing import Callable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import uuid


SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

import browser_lcp_acceptance as browser_lcp  # noqa: E402
import install_availability_release as installer  # noqa: E402
import server_wide_installer_fence as installer_fence  # noqa: E402
from devcoordinator.schema import SCHEMA_VERSION as COORDINATOR_SCHEMA_VERSION  # noqa: E402
from devcoordinator import retained_control  # noqa: E402
from devcoordinator.universal_test_store import (  # noqa: E402
    TEST_STORE_SCHEMA_VERSION as CURRENT_TEST_STORE_SCHEMA_VERSION,
)
from devcoordinator.server_credentials import (  # noqa: E402
    MAX_SERVER_CREDENTIAL_BYTES,
    SERVER_CREDENTIAL_FILE_SUFFIX,
    SERVER_CREDENTIAL_MATERIAL_ROOT,
    ServerCredentialError,
    staged_material_path,
    validate_server_credential_binding,
)
from devcoordinator.store import AccountStore  # noqa: E402
from devcoordinator.worker_control import (  # noqa: E402
    STARTUP_CONVERGENCE_SECONDS as WORKER_STARTUP_CONVERGENCE_SECONDS,
    STARTUP_NATIVE_COMMAND_MAX_SECONDS as WORKER_STARTUP_NATIVE_COMMAND_MAX_SECONDS,
    quiesce_worker_registration,
    WorkerControlError,
    WorkerController,
)
from devcoordinator.worker_native import (  # noqa: E402
    WorkerNativeError,
    native_worker_manager,
    project_repository_slice,
)
from devcoordinator.worker_runner import (  # noqa: E402
    _process_start_time as read_process_start_time,
    observe_worker_process_identity,
)


KIND = "devcoordinator-same-schema-release-switch"
VERSION = 1
RELEASE_RE = re.compile(r"^[0-9a-f]{64}$")
DELIVERY_FENCE_OWNER_KIND = "devcoordinator-software-owned-delivery"
DELIVERY_FENCE_IDENTITY_KIND = "devcoordinator-software-delivery-fence-identity"
DELIVERY_FENCE_TERMINAL_KIND = "devcoordinator-software-delivery-fence-terminal"
DELIVERY_FENCE_VERSION = 1
DELIVERY_FENCE_IDENTITY_NAME = "installer-fence-identity.json"
DELIVERY_FENCE_TERMINAL_NAME = "installer-fence-terminal.json"
DELIVERY_FENCE_UUID_NAMESPACE = uuid.UUID("59f68121-c619-40e8-a85f-a22ab0ae890d")
UNIT_ROOT = Path("/etc/systemd/system")
SYSUSERS_ROOT = Path("/etc/sysusers.d")
TMPFILES_ROOT = Path("/etc/tmpfiles.d")
MAIN_TMPFILES_RENDERED = "devcoordinator.tmpfiles.conf"
CODEX_ROOT = Path("/etc/codex")
CODEX_RULE_ROOT = CODEX_ROOT / "rules"
CLIENT_LAUNCHER = Path("/usr/local/bin/devcoordinator")
MCP_LAUNCHER = Path("/usr/local/bin/devcoordinator-mcp")
BUG_LAUNCHER = Path("/usr/local/bin/devcoordinator-bug")
TEST_LAUNCHER = Path("/usr/local/bin/devcoordinator-test")
CALL_LOG_LAUNCHER = Path("/usr/local/bin/devcoordinator-call-log")
SYSTEMD_UNIT_LAUNCHER = Path("/usr/local/bin/devcoordinator-systemd-unit")
IMAGE_LAUNCHER = Path("/usr/local/bin/devcoordinator-image")
EDGE_CERT_REFRESH_LAUNCHER = Path(
    "/usr/local/bin/devcoordinator-edge-cert-refresh"
)
READ_ONLY_RULE = CODEX_RULE_ROOT / "devcoordinator-read-only.rules"
TEST_RULE = CODEX_RULE_ROOT / "devcoordinator-test.rules"
CLIENT_LAUNCHER_RENDERED = "devcoordinator-launcher"
MCP_LAUNCHER_RENDERED = "devcoordinator-mcp-launcher"
BUG_LAUNCHER_RENDERED = "devcoordinator-bug-launcher"
TEST_LAUNCHER_RENDERED = "devcoordinator-test-launcher"
CALL_LOG_LAUNCHER_RENDERED = "devcoordinator-call-log-launcher"
SYSTEMD_UNIT_LAUNCHER_RENDERED = "devcoordinator-systemd-unit-launcher"
IMAGE_LAUNCHER_RENDERED = "devcoordinator-image-launcher"
EDGE_CERT_REFRESH_LAUNCHER_RENDERED = (
    "devcoordinator-edge-cert-refresh-launcher"
)
CERTBOT_HOOK_ROOT = Path("/etc/letsencrypt/renewal-hooks/deploy")
CERTBOT_HOOK = CERTBOT_HOOK_ROOT / "devcoordinator-edge"
CERTBOT_HOOK_RENDERED = "devcoordinator-edge-certbot-hook"
READ_ONLY_RULE_RENDERED = "devcoordinator-read-only.rules"
TEST_RULE_RENDERED = "devcoordinator-test.rules"
BROWSER_ACCOUNTING_CAPABILITY = "headless_browser_accounting"
BROWSER_ACCOUNTING_WRAPPER = "devcoordinator-browser-accounting"
BROWSER_LIFECYCLE_ROOT = Path("/var/lib/devcoordinator-browser-lifecycle")
BROWSER_LIFECYCLE_STATE = BROWSER_LIFECYCLE_ROOT / "browser-lifecycle.json"
BROWSER_LIFECYCLE_LOCK = Path(f"{BROWSER_LIFECYCLE_STATE}.lock")
LEGACY_BROKER_SERVICE = "devcoordinator-broker.service"
LEGACY_API_SERVICE = "dev-coordinator.service"
LEGACY_CONTROL_PLANE_SERVICES = (
    LEGACY_API_SERVICE,
    LEGACY_BROKER_SERVICE,
)
LEGACY_ENABLE_MARKER = Path("/run/devcoordinator-enable-legacy-control-plane")
LEGACY_RETIREMENT_DROPIN = "99-devcoordinator-retired.conf"
LEGACY_RETIREMENT_PAYLOAD = (
    "[Unit]\n"
    "# The socket-activated authority/API replaced this checkout-bound unit.\n"
    "# Keep stale project Wants= dependencies from reviving the retired stack.\n"
    f"ConditionPathExists={LEGACY_ENABLE_MARKER}\n"
).encode("utf-8")
BROWSER_RUNTIME_LOCK_PRIVATE = Path(
    "/var/lib/devcoordinator/browser/runtime-lock.json"
)
BROWSER_RUNTIME_LOCK_PUBLIC = Path(
    "/etc/devcoordinator/browser-runtime-lock.json"
)
BROWSER_RUNTIME_LOCK_MAX_BYTES = 1024 * 1024
BROWSER_CLEANUP_QUIESCENCE_SECONDS = 2
BROWSER_CLEANUP_RESULT_MAX_BYTES = 4096
STABLE_LAUNCHERS = {
    CLIENT_LAUNCHER_RENDERED: (CLIENT_LAUNCHER, "devcoordinator"),
    MCP_LAUNCHER_RENDERED: (MCP_LAUNCHER, "devcoordinator-mcp"),
    BUG_LAUNCHER_RENDERED: (BUG_LAUNCHER, "devcoordinator-bug"),
    TEST_LAUNCHER_RENDERED: (TEST_LAUNCHER, "devcoordinator-test"),
    CALL_LOG_LAUNCHER_RENDERED: (
        CALL_LOG_LAUNCHER,
        "devcoordinator-call-log",
    ),
    SYSTEMD_UNIT_LAUNCHER_RENDERED: (
        SYSTEMD_UNIT_LAUNCHER,
        "devcoordinator-systemd-unit",
    ),
    IMAGE_LAUNCHER_RENDERED: (IMAGE_LAUNCHER, "devcoordinator-image"),
    EDGE_CERT_REFRESH_LAUNCHER_RENDERED: (
        EDGE_CERT_REFRESH_LAUNCHER,
        "devcoordinator-edge-cert-refresh",
    ),
}
RETAINED_PREDECESSOR_OPTIONAL_LAUNCHERS = frozenset(
    {EDGE_CERT_REFRESH_LAUNCHER_RENDERED}
)
RETAINED_PREDECESSOR_REQUIRED_LAUNCHERS = frozenset(
    {
        CLIENT_LAUNCHER_RENDERED,
        MCP_LAUNCHER_RENDERED,
        BUG_LAUNCHER_RENDERED,
        TEST_LAUNCHER_RENDERED,
        CALL_LOG_LAUNCHER_RENDERED,
        SYSTEMD_UNIT_LAUNCHER_RENDERED,
        IMAGE_LAUNCHER_RENDERED,
    }
)
TEST_HISTORY_WRAPPER = "devcoordinator-test-store"
TESTD_USER = "devcoordinator-testd"
TESTD_SERVICE = "devcoordinator-testd.service"
TESTD_SOCKET = "devcoordinator-testd.socket"
TEST_DATABASE = Path("/var/lib/devcoordinator-testd/tests.sqlite3")
RETAINED_PREDECESSOR_TEST_STORE_SCHEMA_VERSION = 6
TEST_SPOOL = Path("/var/lib/devcoordinator-testd/spool")
TEST_SPOOL_QUEUES = (
    "pending",
    "processed",
    "result-pending",
    "result-processed",
    "active",
)
SLOT_ROOT = Path("/etc/devcoordinator/console-slots")
CLIENT_PROFILE = Path("/etc/devcoordinator/client-profiles.json")
AUTHORITY_DATABASE = Path("/var/lib/devcoordinator/authority.sqlite3")
CONSOLE_STATE_ROOT = Path("/var/lib/devcoordinator-console")
WORKER_UNIT = re.compile(
    r"^devcoordinator-worker-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12})\.service$"
)
CGROUP_ROOT = Path("/sys/fs/cgroup")
WORKER_CUTOVER_LIMIT = 4096
RETAINED_WORKER_STABILITY_SECONDS = 2.0
RETAINED_WORKER_OBSERVATION_MARGIN_SECONDS = 5.0
RETAINED_WORKER_CONVERGENCE_MARGIN_SECONDS = (
    WORKER_STARTUP_NATIVE_COMMAND_MAX_SECONDS
    + RETAINED_WORKER_STABILITY_SECONDS
    + RETAINED_WORKER_OBSERVATION_MARGIN_SECONDS
)
RETAINED_WORKER_CONVERGENCE_SECONDS = (
    WORKER_STARTUP_CONVERGENCE_SECONDS
    + RETAINED_WORKER_CONVERGENCE_MARGIN_SECONDS
)
AUTHORITY_WRITER_UNITS = (
    "devcoordinator-testd.socket",
    "devcoordinator-test-snapshotd.socket",
    "devcoordinator-api.socket",
    "devcoordinator-authority.socket",
    "devcoordinator-testd.service",
    "devcoordinator-test-snapshotd.service",
    "devcoordinator-api.service",
    "devcoordinator-authority.service",
)
AUTHORITY_SERVICE = "devcoordinator-authority.service"
AUTHORITY_SOCKET_PATH = "/run/devcoordinator-authority.sock"
AUTHORITY_STOP_COMMAND_TIMEOUT_SECONDS = 5.0
AUTHORITY_STOP_GRACE_SECONDS = 5.0
AUTHORITY_STOP_POLL_SECONDS = 0.1
AUTHORITY_READY_TIMEOUT_SECONDS = 90.0
AUTHORITY_READY_COMMAND_TIMEOUT_SECONDS = 5.0
AUTHORITY_READY_POLL_SECONDS = 0.1
AUTHORITY_READY_OUTPUT_MAX_BYTES = 64 * 1024
WRITER_STOP_SETTLE_SECONDS = 35.0
WRITER_STABLE_INACTIVE_SECONDS = 0.1
PUBLICATION_FILE = Path("/var/lib/devcoordinator-edge/routes.publication")
MAINTENANCE_ROOT = Path("/run/devcoordinator-maintenance")
MAINTENANCE_MARKER = MAINTENANCE_ROOT / "maintenance.json"
CONSOLE_HOST = "console.vr.ae"
PORT_MIN = 30000
PORT_MAX = 60999
SERVICE_ORDER = (
    "devcoordinator-authority.service",
    "devcoordinator-test-snapshotd.service",
    "devcoordinator-testd.service",
    "devcoordinator-api.service",
    "devcoordinator-observer.service",
    "devcoordinator-notifications.service",
    "devcoordinator-edge.service",
)
ROLLBACK_CRITICAL_SERVICES = (
    "devcoordinator-authority.service",
    "devcoordinator-api.service",
    "devcoordinator-edge.service",
)
ROLLBACK_BACKGROUND_SERVICES = tuple(
    unit for unit in SERVICE_ORDER if unit not in ROLLBACK_CRITICAL_SERVICES
)
ROLLBACK_CRITICAL_SOCKETS = (
    "devcoordinator-edge-http.socket",
    "devcoordinator-edge-https.socket",
    "devcoordinator-edge-publication.socket",
    "devcoordinator-api.socket",
    "devcoordinator-authority.socket",
)
ROLLBACK_BACKGROUND_SOCKETS = (
    "devcoordinator-test-snapshotd.socket",
    "devcoordinator-testd.socket",
)
RUNTIME_SOCKET_REBIND_ORDER = (
    "devcoordinator-test-snapshotd.socket",
    "devcoordinator-testd.socket",
)
TOPOLOGY_FILES = (
    "devcoordinator-api.service",
    "devcoordinator-api.socket",
    "devcoordinator-authority.service",
    "devcoordinator-authority.socket",
    "devcoordinator-background.slice",
    "devcoordinator-console@.service",
    "devcoordinator-control.slice",
    "devcoordinator-edge-http.socket",
    "devcoordinator-edge-https.socket",
    "devcoordinator-edge-publication.socket",
    "devcoordinator-edge.service",
    "devcoordinator-observer.service",
    "devcoordinator-notifications.service",
    "devcoordinator-projects.slice",
    "devcoordinator-test-snapshotd.service",
    "devcoordinator-test-snapshotd.socket",
    "devcoordinator-testd.service",
    "devcoordinator-testd.socket",
)
REQUIRED_SOCKETS = (
    "devcoordinator-edge-http.socket",
    "devcoordinator-edge-https.socket",
    "devcoordinator-edge-publication.socket",
    "devcoordinator-api.socket",
    "devcoordinator-authority.socket",
    "devcoordinator-testd.socket",
    "devcoordinator-test-snapshotd.socket",
)
API_SOCKET = "devcoordinator-api.socket"


class SwitchError(RuntimeError):
    """The same-schema switch could not safely continue."""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_json(path: Path, value: object) -> None:
    payload = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    atomic_bytes(path, payload, 0o600)


def atomic_bytes(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        parent = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_regular_copy(
    source: Path,
    destination: Path,
    *,
    mode: int,
    expected_sha256: str | None = None,
) -> dict[str, object]:
    """Stream one stable no-follow file into an fsynced atomic replacement."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(
        f".{destination.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    source_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_descriptor = os.open(source, source_flags)
    except OSError as error:
        raise SwitchError(f"atomic copy source is unavailable: {source}: {error}") from error
    try:
        before = os.fstat(source_descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SwitchError(f"atomic copy source is not a regular file: {source}")
        target_descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        digest = hashlib.sha256()
        size = 0
        try:
            with os.fdopen(target_descriptor, "wb", closefd=True) as target:
                while True:
                    block = os.read(source_descriptor, 1024 * 1024)
                    if not block:
                        break
                    target.write(block)
                    digest.update(block)
                    size += len(block)
                target.flush()
                os.fsync(target.fileno())
            after = os.fstat(source_descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ) or size != before.st_size:
                raise SwitchError(f"atomic copy source changed while reading: {source}")
            observed_sha256 = digest.hexdigest()
            if expected_sha256 is not None and observed_sha256 != expected_sha256:
                raise SwitchError(f"atomic copy source digest changed: {source}")
            os.chmod(temporary, mode)
            os.replace(temporary, destination)
            parent = os.open(
                destination.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
            return {
                "sha256": observed_sha256,
                "size": size,
                "source_uid": before.st_uid,
                "source_gid": before.st_gid,
                "source_mode": stat.S_IMODE(before.st_mode),
            }
        finally:
            temporary.unlink(missing_ok=True)
    finally:
        os.close(source_descriptor)


def fsync_file_and_parent(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def path_parent_identity(path: Path) -> dict[str, int | str]:
    """Return one canonical, non-writable parent identity for a fixed path."""

    if not path.is_absolute() or Path(os.path.abspath(path)) != path:
        raise SwitchError(f"retained-control path is not canonical: {path}")
    parent = path.parent
    try:
        info = parent.lstat()
        resolved = parent.resolve(strict=True)
    except OSError as error:
        raise SwitchError(f"retained-control parent is unavailable: {parent}: {error}") from error
    if (
        resolved != parent
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise SwitchError(f"retained-control parent is unsafe: {parent}")
    return {
        "path": str(parent),
        "device": info.st_dev,
        "inode": info.st_ino,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
    }


def exact_file_identity(path: Path) -> dict[str, object]:
    parent = path_parent_identity(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise SwitchError(f"retained-control file is unavailable: {path}: {error}") from error
    digest = hashlib.sha256()
    size = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SwitchError(f"retained-control file is not regular: {path}")
        if (before.st_uid, before.st_gid) != (parent["uid"], parent["gid"]):
            raise SwitchError(
                f"retained-control file is not owned by its parent identity: {path}"
            )
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or size != before.st_size
    ):
        raise SwitchError(f"retained-control file changed while hashing: {path}")
    return {
        "path": str(path),
        "present": True,
        "sha256": digest.hexdigest(),
        "bytes": size,
        "mode": stat.S_IMODE(before.st_mode),
        "uid": before.st_uid,
        "gid": before.st_gid,
        "device": before.st_dev,
        "inode": before.st_ino,
        "mtime_ns": before.st_mtime_ns,
        "parent": parent,
    }


def _private_owned_directory(path: Path, *, field: str) -> dict[str, int | str]:
    if not path.is_absolute() or Path(os.path.abspath(path)) != path:
        raise SwitchError(f"{field} is not canonical")
    try:
        info = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise SwitchError(f"{field} is unavailable") from error
    if (
        resolved != path
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_gid != os.getegid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise SwitchError(f"{field} is not mutation-owner mode 0700")
    return {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
    }


def _server_credential_destination(credential_id: str) -> Path:
    try:
        return staged_material_path(SERVER_CREDENTIAL_MATERIAL_ROOT, credential_id)
    except ServerCredentialError as error:
        raise SwitchError("retained server credential identity is invalid") from error


def _server_credential_id_from_destination(destination: object) -> str:
    path = Path(str(destination))
    if path.parent != SERVER_CREDENTIAL_MATERIAL_ROOT or not path.name.endswith(
        SERVER_CREDENTIAL_FILE_SUFFIX
    ):
        raise SwitchError("retained server credential destination is invalid")
    credential_id = path.name[: -len(SERVER_CREDENTIAL_FILE_SUFFIX)]
    try:
        expected = staged_material_path(SERVER_CREDENTIAL_MATERIAL_ROOT, credential_id)
    except ServerCredentialError as error:
        raise SwitchError("retained server credential destination is invalid") from error
    if path != expected:
        raise SwitchError("retained server credential destination is invalid")
    return credential_id


def _server_credential_backup_path(
    transaction_root: Path, credential_id: str
) -> Path:
    root = transaction_root / "retained-control-backups/server-credentials"
    try:
        return staged_material_path(root, credential_id)
    except ServerCredentialError as error:
        raise SwitchError("retained server credential backup identity is invalid") from error


def _server_credentials_from_manifest(
    manifest: Mapping[str, object], transaction_root: Path
) -> dict[str, dict[str, object]]:
    raw_credentials = manifest.get("server_credentials")
    if (
        not isinstance(raw_credentials, list)
        or len(raw_credentials) > retained_control.MAX_ROWS_PER_COLLECTION
    ):
        raise SwitchError("retained server credential manifest is invalid")
    staged_root = transaction_root / "retained-control/server-credentials"
    if raw_credentials:
        _private_owned_directory(
            staged_root, field="retained server credential staging root"
        )
    elif not staged_root.exists() and not staged_root.is_symlink():
        return {}
    else:
        _private_owned_directory(
            staged_root, field="retained server credential staging root"
        )

    result: dict[str, dict[str, object]] = {}
    expected_names: set[str] = set()
    ordering: list[tuple[str, str, str]] = []
    for raw in raw_credentials:
        if not isinstance(raw, Mapping) or set(raw) != {
            "server_definition_id",
            "name",
            "credential_id",
            "material",
        }:
            raise SwitchError("retained server credential fields are invalid")
        server_definition_id = raw.get("server_definition_id")
        material = raw.get("material")
        try:
            binding = validate_server_credential_binding(
                server_definition_id,
                {
                    "name": raw.get("name"),
                    "credential_id": raw.get("credential_id"),
                },
            )
        except ServerCredentialError as error:
            raise SwitchError("retained server credential binding is invalid") from error
        credential_id = binding.credential_id
        if not isinstance(material, Mapping):
            raise SwitchError("retained server credential binding is invalid")
        try:
            staged = staged_material_path(staged_root, credential_id)
        except ServerCredentialError as error:
            raise SwitchError("retained server credential material path is invalid") from error
        expected_names.add(staged.name)
        observed = exact_file_identity(staged)
        if (
            observed != dict(material)
            or observed.get("path") != str(staged)
            or observed.get("mode") != 0o600
            or observed.get("uid") != os.geteuid()
            or observed.get("gid") != os.getegid()
            or type(observed.get("bytes")) is not int
            or not 1 <= int(observed["bytes"]) <= MAX_SERVER_CREDENTIAL_BYTES
        ):
            raise SwitchError("retained server credential material changed")
        if credential_id in result:
            raise SwitchError("retained server credential evidence is duplicated")
        ordering.append((str(server_definition_id), binding.name, credential_id))
        result[credential_id] = {
            "server_definition_id": str(server_definition_id),
            "name": binding.name,
            "material": dict(material),
            "staged": staged,
            "destination": _server_credential_destination(credential_id),
        }
    if ordering != sorted(ordering):
        raise SwitchError("retained server credential evidence is not ordered")
    staged_names: set[str] = set()
    try:
        for index, entry in enumerate(staged_root.iterdir()):
            if index >= retained_control.MAX_ROWS_PER_COLLECTION:
                raise SwitchError(
                    "retained server credential staging root is excessive"
                )
            staged_names.add(entry.name)
    except OSError as error:
        raise SwitchError("retained server credential staging root is unavailable") from error
    if staged_names != expected_names:
        raise SwitchError("retained server credential staging contains extra material")
    return result


def _reject_server_credential_extras(
    credentials: Mapping[str, Mapping[str, object]],
) -> None:
    if not credentials:
        return
    _private_owned_directory(
        SERVER_CREDENTIAL_MATERIAL_ROOT, field="live server credential root"
    )
    affected = set(credentials)
    seen = 0
    try:
        entries = SERVER_CREDENTIAL_MATERIAL_ROOT.iterdir()
        for entry in entries:
            seen += 1
            if seen > retained_control.MAX_ROWS_PER_COLLECTION:
                raise SwitchError("live server credential root is excessive")
            matching = entry.name[:36] if entry.name[:36] in affected else None
            if matching is not None and entry.name != (
                f"{matching}{SERVER_CREDENTIAL_FILE_SUFFIX}"
            ):
                raise SwitchError(
                    "live server credential root contains extra affected material"
                )
    except OSError as error:
        raise SwitchError("live server credential root is unavailable") from error


def _cleanup_server_credential_temporaries(
    credentials: Mapping[str, Mapping[str, object]],
    transaction_root: Path,
) -> int:
    """Remove only exact affected atomic-copy remnants without reading bytes."""

    if not credentials:
        return 0
    affected = set(credentials)
    roots = (
        SERVER_CREDENTIAL_MATERIAL_ROOT,
        transaction_root / "retained-control-backups/server-credentials",
    )
    removed = 0
    for root in roots:
        if (
            root != SERVER_CREDENTIAL_MATERIAL_ROOT
            and not root.exists()
            and not root.is_symlink()
        ):
            continue
        _private_owned_directory(root, field="server credential atomic root")
        try:
            entries = root.iterdir()
            for index, entry in enumerate(entries):
                if index >= retained_control.MAX_ROWS_PER_COLLECTION:
                    raise SwitchError("server credential atomic root is excessive")
                name = entry.name
                if not name.startswith(".") or len(name) < 38:
                    continue
                credential_id = name[1:37]
                if credential_id not in affected:
                    continue
                expected = re.fullmatch(
                    r"\."
                    + re.escape(credential_id)
                    + re.escape(SERVER_CREDENTIAL_FILE_SUFFIX)
                    + r"\.[0-9]+\.[0-9a-f]{32}\.tmp",
                    name,
                )
                if expected is None:
                    raise SwitchError(
                        "affected server credential atomic remnant is invalid"
                    )
                try:
                    info = entry.lstat()
                except OSError as error:
                    raise SwitchError(
                        "affected server credential atomic remnant is unavailable"
                    ) from error
                if (
                    stat.S_ISLNK(info.st_mode)
                    or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_gid != os.getegid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_nlink != 1
                ):
                    raise SwitchError(
                        "affected server credential atomic remnant is unsafe"
                    )
                entry.unlink()
                fsync_parent(entry)
                removed += 1
        except OSError as error:
            raise SwitchError("server credential atomic root is unavailable") from error
    return removed


def require_parent_identity(path: Path, expected: object) -> None:
    if not isinstance(expected, Mapping) or path_parent_identity(path) != dict(expected):
        raise SwitchError(f"retained-control parent identity changed: {path.parent}")


def fsync_parent(path: Path) -> None:
    descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def unlink_regular_and_fsync(path: Path, *, parent_identity: object) -> None:
    require_parent_identity(path, parent_identity)
    try:
        info = path.lstat()
    except FileNotFoundError:
        fsync_parent(path)
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SwitchError(f"retained-control unlink target is unsafe: {path}")
    path.unlink()
    fsync_parent(path)


def load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SwitchError(f"cannot read {path}: {error}") from error
    if not isinstance(value, Mapping):
        raise SwitchError(f"JSON document is not an object: {path}")
    return dict(value)


def browser_runtime_lock_payload(path: Path) -> tuple[dict[str, object], bytes]:
    """Read and validate the bounded sealed browser runtime inventory."""

    try:
        before = path.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_size > BROWSER_RUNTIME_LOCK_MAX_BYTES
        ):
            raise SwitchError("browser runtime inventory source is unsafe")
        payload = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        raise SwitchError(f"browser runtime inventory is unavailable: {error}") from error
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise SwitchError("browser runtime inventory changed while it was read")
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SwitchError("browser runtime inventory is invalid JSON") from error
    if not isinstance(value, Mapping):
        raise SwitchError("browser runtime inventory is not an object")
    try:
        verified = browser_lcp.verify_runtime_lock_document(
            value,
            expected_uid=0,
            expected_gid=0,
        )
    except (OSError, ValueError, browser_lcp.BrowserLcpAcceptanceError) as error:
        raise SwitchError(f"browser runtime inventory is invalid: {error}") from error
    return dict(verified), payload


def publish_browser_runtime_inventory() -> dict[str, object]:
    """Project the non-secret runtime lock for actual-caller Playwright QA."""

    verified, payload = browser_runtime_lock_payload(BROWSER_RUNTIME_LOCK_PRIVATE)
    atomic_bytes(BROWSER_RUNTIME_LOCK_PUBLIC, payload, 0o644)
    evidence = verify_public_browser_runtime_inventory()
    if evidence["document_sha256"] != verified["document_sha256"]:
        raise SwitchError("published browser runtime inventory changed identity")
    return evidence


def verify_public_browser_runtime_inventory() -> dict[str, object]:
    source, source_payload = browser_runtime_lock_payload(BROWSER_RUNTIME_LOCK_PRIVATE)
    public, public_payload = browser_runtime_lock_payload(BROWSER_RUNTIME_LOCK_PUBLIC)
    info = BROWSER_RUNTIME_LOCK_PUBLIC.lstat()
    ok = (
        source_payload == public_payload
        and source["document_sha256"] == public["document_sha256"]
        and stat.S_IMODE(info.st_mode) == 0o644
    )
    if not ok:
        raise SwitchError("public browser runtime inventory is stale or unreadable")
    return {
        "ok": True,
        "path": str(BROWSER_RUNTIME_LOCK_PUBLIC),
        "mode": stat.S_IMODE(info.st_mode),
        "document_sha256": public["document_sha256"],
        "source_sha256": hashlib.sha256(source_payload).hexdigest(),
    }


def load_journal(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise SwitchError("same-schema journal ownership or mode is invalid")
    value = load_json(path)
    if value.get("kind") != KIND or value.get("schema_version") != VERSION:
        raise SwitchError("same-schema journal is invalid")
    return value


def require_transaction_root(path: Path, *, release_digest: str) -> Path:
    """Create or verify the exact root-owned digest transaction directory."""

    if os.geteuid() != 0:
        raise SwitchError("same-schema release mutation must run as root")
    absolute = path.expanduser().absolute()
    if absolute.name != release_digest or RELEASE_RE.fullmatch(release_digest) is None:
        raise SwitchError("same-schema transaction directory is not release-scoped")
    for directory in (absolute.parent, absolute):
        try:
            info = directory.lstat()
        except FileNotFoundError:
            directory.mkdir(mode=0o700)
            info = directory.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o700
            or directory.resolve(strict=True) != directory
        ):
            raise SwitchError(
                f"same-schema transaction directory is not root-owned and private: {directory}"
            )
    return absolute


def _read_delivery_fence_document(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
) -> dict[str, object]:
    """Reuse the installer's no-follow file validator for private evidence."""

    descriptor, before = installer_fence._claim_file(
        path, expected_uid=expected_uid, expected_gid=expected_gid
    )
    try:
        if not 1 <= before.st_size <= installer_fence.MAX_CLAIM_BYTES:
            raise SwitchError("software delivery fence document size is invalid")
        payload = os.read(descriptor, before.st_size)
        after = os.fstat(descriptor)
        if (
            len(payload) != before.st_size
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        ):
            raise SwitchError("software delivery fence document changed while reading")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SwitchError("software delivery fence document is invalid JSON") from error
    if not isinstance(value, dict):
        raise SwitchError("software delivery fence document must be an object")
    return value


def delivery_fence_binding(
    transaction_root: Path,
    *,
    release_digest: str,
    expected_uid: int,
    expected_gid: int,
) -> tuple[Path, Path, dict[str, object]]:
    """Publish or validate the reboot-stable identity for one delivery."""

    identity = {
        "schema_version": DELIVERY_FENCE_VERSION,
        "kind": DELIVERY_FENCE_IDENTITY_KIND,
        "operation_id": str(uuid.uuid5(
            DELIVERY_FENCE_UUID_NAMESPACE, f"{release_digest}\0{transaction_root}"
        )),
        "release_digest": release_digest,
    }
    identity_path = transaction_root / DELIVERY_FENCE_IDENTITY_NAME
    terminal_path = transaction_root / DELIVERY_FENCE_TERMINAL_NAME
    if not identity_path.exists() and not identity_path.is_symlink():
        atomic_json(identity_path, identity)
    if _read_delivery_fence_document(
        identity_path, expected_uid=expected_uid, expected_gid=expected_gid
    ) != identity:
        raise SwitchError("software delivery fence identity belongs to another release")
    return identity_path, terminal_path, identity


def delivery_fence_terminal(
    transaction_root: Path,
    identity: Mapping[str, object],
    *,
    expected_uid: int,
    expected_gid: int,
    publish_outcome: str | None = None,
    successor_release_digest: str | None = None,
    journal_sha256: str | None = None,
    live_evidence_sha256: str | None = None,
) -> dict[str, object] | None:
    path = transaction_root / DELIVERY_FENCE_TERMINAL_NAME
    published: dict[str, object] | None = None
    if publish_outcome is not None:
        if publish_outcome not in {
            "deployed",
            "rolled-back",
            "superseded-before-mutation",
        }:
            raise SwitchError("software delivery fence outcome is invalid")
        published = {
            "schema_version": DELIVERY_FENCE_VERSION,
            "kind": DELIVERY_FENCE_TERMINAL_KIND,
            "operation_id": identity["operation_id"],
            "release_digest": identity["release_digest"],
            "outcome": publish_outcome,
            "completed_at": now(),
        }
        if publish_outcome == "superseded-before-mutation":
            if (
                not isinstance(successor_release_digest, str)
                or RELEASE_RE.fullmatch(successor_release_digest) is None
                or successor_release_digest == identity.get("release_digest")
                or not isinstance(journal_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", journal_sha256) is None
                or not isinstance(live_evidence_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", live_evidence_sha256) is None
            ):
                raise SwitchError("software delivery supersession evidence is invalid")
            published.update(
                {
                    "successor_release_digest": successor_release_digest,
                    "journal_sha256": journal_sha256,
                    "live_evidence_sha256": live_evidence_sha256,
                }
            )
        elif any(
            value is not None
            for value in (
                successor_release_digest,
                journal_sha256,
                live_evidence_sha256,
            )
        ):
            raise SwitchError("ordinary fence terminal has supersession evidence")
        atomic_json(path, published)
    if not path.exists() and not path.is_symlink():
        return None
    value = _read_delivery_fence_document(
        path, expected_uid=expected_uid, expected_gid=expected_gid
    )
    ordinary_fields = {
        "schema_version",
        "kind",
        "operation_id",
        "release_digest",
        "outcome",
        "completed_at",
    }
    superseded_fields = ordinary_fields | {
        "successor_release_digest",
        "journal_sha256",
        "live_evidence_sha256",
    }
    outcome = value.get("outcome")
    if (
        set(value)
        != (
            superseded_fields
            if outcome == "superseded-before-mutation"
            else ordinary_fields
        )
        or value.get("schema_version") != DELIVERY_FENCE_VERSION
        or value.get("kind") != DELIVERY_FENCE_TERMINAL_KIND
        or value.get("operation_id") != identity.get("operation_id")
        or value.get("release_digest") != identity.get("release_digest")
        or outcome
        not in {"deployed", "rolled-back", "superseded-before-mutation"}
        or not isinstance(value.get("completed_at"), str)
        or not value["completed_at"]
        or len(value["completed_at"]) > 64
        or outcome == "superseded-before-mutation"
        and (
            RELEASE_RE.fullmatch(str(value.get("successor_release_digest") or ""))
            is None
            or value.get("successor_release_digest")
            == identity.get("release_digest")
            or re.fullmatch(r"[0-9a-f]{64}", str(value.get("journal_sha256") or ""))
            is None
            or re.fullmatch(
                r"[0-9a-f]{64}", str(value.get("live_evidence_sha256") or "")
            )
            is None
        )
    ):
        raise SwitchError("software delivery fence terminal evidence is invalid")
    if published is not None and value != published:
        raise SwitchError("software delivery fence terminal did not publish exactly")
    return value


def remove_delivery_fence_document(
    path: Path,
    expected: Mapping[str, object],
    *,
    expected_uid: int,
    expected_gid: int,
) -> None:
    if _read_delivery_fence_document(
        path, expected_uid=expected_uid, expected_gid=expected_gid
    ) != dict(expected):
        raise SwitchError("software delivery fence document changed before cleanup")
    path.unlink()
    fsync_parent(path)


def require_supersedable_prepared_journal(
    journal_path: Path,
    *,
    candidate_release: Path,
    successor_release_digest: str,
) -> tuple[dict[str, object], str]:
    before = exact_file_identity(journal_path)
    document = load_journal(journal_path)
    if document is None:
        raise SwitchError("prepared supersession journal is unavailable")
    rebaseline = document.get("retained_control_rebaseline")
    candidate_digest = candidate_release.name
    previous = document.get("previous_release_digest")
    if (
        RELEASE_RE.fullmatch(successor_release_digest) is None
        or successor_release_digest in {candidate_digest, previous}
        or document.get("phase") != "prepared"
        or document.get("release") != str(candidate_release)
        or document.get("release_digest") != candidate_digest
        or not isinstance(previous, str)
        or RELEASE_RE.fullmatch(previous) is None
        or document.get("backups") != {}
        or document.get("candidate_started") is not False
        or document.get("promoted") is not False
        or document.get("publication_switched") is not False
        or document.get("completed_at") is not None
        or document.get("test_history_reset") is not None
        or not isinstance(rebaseline, Mapping)
        or set(rebaseline)
        != {
            "required",
            "source_schema_version",
            "target_schema_version",
            "status",
        }
        or rebaseline.get("required") is not True
        or rebaseline.get("source_schema_version")
        != retained_control.REBASELINE_SOURCE_SCHEMA
        or rebaseline.get("target_schema_version") != COORDINATOR_SCHEMA_VERSION
        or rebaseline.get("status") != "planned"
    ):
        raise SwitchError("prepared supersession journal shows possible mutation")
    after = exact_file_identity(journal_path)
    if before != after:
        raise SwitchError("prepared supersession journal changed while reading")
    return document, str(before["sha256"])


def _read_bounded_stable_file(
    path: Path,
    *,
    maximum_bytes: int,
    description: str,
) -> bytes:
    if (
        not path.is_absolute()
        or type(maximum_bytes) is not int
        or maximum_bytes <= 0
    ):
        raise SwitchError(description + " read contract is invalid")
    descriptor = -1
    try:
        path_before = path.lstat()
        if (
            stat.S_ISLNK(path_before.st_mode)
            or not stat.S_ISREG(path_before.st_mode)
            or path_before.st_size <= 0
            or path_before.st_size > maximum_bytes
        ):
            raise SwitchError(description + " is not one bounded real file")
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        opened = os.fstat(descriptor)
        before_identity = (
            path_before.st_dev,
            path_before.st_ino,
            path_before.st_size,
            path_before.st_mtime_ns,
            path_before.st_ctime_ns,
        )
        opened_identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        if opened_identity != before_identity:
            raise SwitchError(description + " path changed before open")
        payload = bytearray()
        while len(payload) <= maximum_bytes:
            block = os.read(descriptor, min(65536, maximum_bytes + 1 - len(payload)))
            if not block:
                break
            payload.extend(block)
        opened_after = os.fstat(descriptor)
        path_after = path.lstat()
        if (
            len(payload) != opened.st_size
            or opened_identity
            != (
                opened_after.st_dev,
                opened_after.st_ino,
                opened_after.st_size,
                opened_after.st_mtime_ns,
                opened_after.st_ctime_ns,
            )
            or opened_identity
            != (
                path_after.st_dev,
                path_after.st_ino,
                path_after.st_size,
                path_after.st_mtime_ns,
                path_after.st_ctime_ns,
            )
        ):
            raise SwitchError(description + " changed while reading")
        return bytes(payload)
    except OSError as error:
        raise SwitchError(description + " is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_optional_bounded_stable_file(
    path: Path,
    *,
    maximum_bytes: int,
    description: str,
) -> bytes | None:
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    return _read_bounded_stable_file(
        path,
        maximum_bytes=maximum_bytes,
        description=description,
    )


def _current_live_release_snapshot(
    release: Path,
    *,
    schema_reader: Callable[[], int],
) -> dict[str, object]:
    digest = release.name
    publication_payload = _read_bounded_stable_file(
        PUBLICATION_FILE,
        maximum_bytes=2 * 1024 * 1024,
        description="edge publication",
    )
    try:
        envelope = json.loads(publication_payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SwitchError("edge publication is invalid JSON") from error
    publication = envelope.get("publication") if isinstance(envelope, Mapping) else None
    console = publication.get("console") if isinstance(publication, Mapping) else None
    upstream = console.get("upstream") if isinstance(console, Mapping) else None
    if (
        not isinstance(envelope, Mapping)
        or not isinstance(publication, Mapping)
        or not isinstance(upstream, Mapping)
        or envelope.get("schema_version") != 1
        or re.fullmatch(r"[0-9a-f]{64}", str(envelope.get("payload_sha256") or ""))
        is None
        or publication.get("release_digest") != digest
        or type(publication.get("generation")) is not int
        or type(upstream.get("port")) is not int
    ):
        raise SwitchError("edge publication names another current release")
    port = int(upstream["port"])
    slot = SLOT_ROOT / f"{digest}.env"
    try:
        slot_payload = _read_bounded_stable_file(
            slot,
            maximum_bytes=64 * 1024,
            description="current Console slot",
        )
        slot_values = parse_slot(slot_payload.decode("utf-8"))
    except UnicodeDecodeError as error:
        raise SwitchError("current Console slot is not UTF-8") from error
    if (
        slot_values["DEVCOORDINATOR_RELEASE_DIGEST"] != digest
        or int(slot_values["HTTPS_PORT"]) != port
    ):
        raise SwitchError("current Console slot contradicts publication")

    if set(STABLE_LAUNCHERS) != (
        RETAINED_PREDECESSOR_REQUIRED_LAUNCHERS
        | RETAINED_PREDECESSOR_OPTIONAL_LAUNCHERS
    ):
        raise SwitchError("retained predecessor launcher contract changed")
    launcher_sha256: dict[str, str | None] = {}
    for rendered_name, (destination, immutable_name) in STABLE_LAUNCHERS.items():
        expected = (
            "#!/bin/sh\n"
            "set -eu\n"
            f"exec '{release / 'bin' / immutable_name}' \"$@\"\n"
        ).encode("utf-8")
        if rendered_name in RETAINED_PREDECESSOR_OPTIONAL_LAUNCHERS:
            actual = _read_optional_bounded_stable_file(
                destination,
                maximum_bytes=64 * 1024,
                description="optional retained predecessor launcher",
            )
            if actual is None:
                launcher_sha256[str(destination)] = None
                continue
        else:
            actual = _read_bounded_stable_file(
                destination,
                maximum_bytes=64 * 1024,
                description="required retained predecessor launcher",
            )
        if actual != expected:
            raise SwitchError("stable launcher names another current release")
        launcher_sha256[str(destination)] = hashlib.sha256(actual).hexdigest()

    release_bound_units = {
        "devcoordinator-api.service",
        "devcoordinator-authority.service",
        "devcoordinator-edge.service",
        "devcoordinator-notifications.service",
        "devcoordinator-observer.service",
        "devcoordinator-test-snapshotd.service",
        "devcoordinator-testd.service",
    }
    unit_sha256: dict[str, str] = {}
    reference = re.compile(r"/opt/devcoordinator/releases/([0-9a-f]{64})(?:/|\b)")
    for name in sorted(release_bound_units):
        payload = _read_bounded_stable_file(
            UNIT_ROOT / name,
            maximum_bytes=1024 * 1024,
            description="current release unit",
        )
        try:
            references = set(reference.findall(payload.decode("utf-8")))
        except UnicodeDecodeError as error:
            raise SwitchError("current release unit is not UTF-8") from error
        if references != {digest}:
            raise SwitchError("current unit names another release: " + name)
        unit_sha256[name] = hashlib.sha256(payload).hexdigest()
    schema_version = schema_reader()
    if schema_version != retained_control.REBASELINE_SOURCE_SCHEMA:
        raise SwitchError("current live authority schema is not the retained predecessor")
    return {
        "release_digest": digest,
        "publication_file_sha256": hashlib.sha256(publication_payload).hexdigest(),
        "publication_payload_sha256": envelope["payload_sha256"],
        "publication_generation": publication["generation"],
        "console_slot_sha256": hashlib.sha256(slot_payload).hexdigest(),
        "authority_schema_version": schema_version,
        "launchers": launcher_sha256,
        "units": unit_sha256,
    }


def require_current_live_release_identity(
    release: Path,
    *,
    schema_reader: Callable[[], int] | None = None,
    release_verifier: Callable[[Path], Mapping[str, object]] = installer.verify_release,
) -> dict[str, object]:
    release = release.expanduser().resolve(strict=True)
    digest = release.name
    if RELEASE_RE.fullmatch(digest) is None:
        raise SwitchError("current live release identity is invalid")
    verified = release_verifier(release)
    if verified.get("release_digest") != digest:
        raise SwitchError("current immutable release verification changed identity")
    read_schema = _authority_schema_version if schema_reader is None else schema_reader
    evidence = _current_live_release_snapshot(release, schema_reader=read_schema)
    second = _current_live_release_snapshot(release, schema_reader=read_schema)
    if evidence != second:
        raise SwitchError("current live release changed between proof snapshots")
    return {
        **evidence,
        "evidence_sha256": hashlib.sha256(canonical(evidence)).hexdigest(),
    }


def acquire_delivery_fence(
    transaction_root: Path,
    *,
    release_digest: str,
    action: str,
    expected_uid: int = 0,
    expected_gid: int = 0,
    lock_path: Path = installer_fence.DEFAULT_INSTALLER_LOCK,
    claim_path: Path = installer_fence.DEFAULT_INSTALLER_CLAIM,
) -> tuple[installer_fence.InstallerFenceHandle, dict[str, object]]:
    identity_path, terminal_path, identity = delivery_fence_binding(
        transaction_root,
        release_digest=release_digest,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    handle = installer_fence.acquire_transaction_fence(
        owner_kind=DELIVERY_FENCE_OWNER_KIND,
        operation_id=str(identity["operation_id"]),
        transaction=identity_path,
        terminal=terminal_path,
        action=action,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        lock_path=lock_path,
        claim_path=claim_path,
    )
    return handle, identity


def testd_uid() -> int:
    try:
        account = pwd.getpwnam(TESTD_USER)
    except KeyError as error:
        raise SwitchError("test-history reset requires the testd service account") from error
    if account.pw_uid <= 0:
        raise SwitchError("test-history reset requires one non-root testd UID")
    return int(account.pw_uid)


def reviewed_previous_test_store_schema(source_authority_schema_version: int) -> int:
    if source_authority_schema_version == retained_control.REBASELINE_SOURCE_SCHEMA:
        return RETAINED_PREDECESSOR_TEST_STORE_SCHEMA_VERSION
    if source_authority_schema_version == COORDINATOR_SCHEMA_VERSION:
        return CURRENT_TEST_STORE_SCHEMA_VERSION
    raise SwitchError(
        "test-history reset has no reviewed predecessor Test Store contract"
    )


def test_history_reset_intent(
    release: Path,
    *,
    previous_release_digest: str,
    source_authority_schema_version: int,
) -> dict[str, object]:
    operation_id = str(uuid.uuid4())
    expected_previous_schema = reviewed_previous_test_store_schema(
        source_authority_schema_version
    )
    return {
        "requested": True,
        "status": "planned",
        "operation_id": operation_id,
        "test_database": str(TEST_DATABASE),
        "test_spool": str(TEST_SPOOL),
        "forward_discarded_spool": str(
            TEST_SPOOL.parent / f".{TEST_SPOOL.name}.{operation_id}.forward-discarded"
        ),
        "rollback_discarded_spool": str(
            TEST_SPOOL.parent / f".{TEST_SPOOL.name}.{operation_id}.rollback-discarded"
        ),
        "attestation": str(
            TEST_DATABASE.parent / f"schema-readiness-{operation_id}.json"
        ),
        "expected_test_uid": testd_uid(),
        "expected_previous_test_store_schema_version": expected_previous_schema,
        "forward_release": str(release),
        "previous_release": str(release.parent / previous_release_digest),
    }


def valid_test_spool_reset_evidence(
    value: object, *, discarded_path: str
) -> bool:
    return (
        isinstance(value, Mapping)
        and set(value)
        == {
            "test_spool",
            "discarded_path",
            "discarded_existing",
            "queues",
            "fresh",
        }
        and value.get("test_spool") == str(TEST_SPOOL)
        and value.get("discarded_path") == discarded_path
        and type(value.get("discarded_existing")) is bool
        and value.get("queues") == list(TEST_SPOOL_QUEUES)
        and value.get("fresh") is True
    )


def require_test_history_reset_mode(
    document: Mapping[str, object], *, requested: bool
) -> Mapping[str, object] | None:
    raw = document.get("test_history_reset")
    if raw is None:
        if requested:
            raise SwitchError(
                "same-schema transaction was prepared without test-history reset"
            )
        return None
    if (
        not isinstance(raw, Mapping)
        or raw.get("requested") is not True
        or raw.get("status")
        not in {"planned", "resetting", "complete", "rollback-resetting", "rolled-back"}
        or not isinstance(raw.get("operation_id"), str)
        or raw.get("test_database") != str(TEST_DATABASE)
        or raw.get("test_spool") != str(TEST_SPOOL)
        or not isinstance(raw.get("forward_discarded_spool"), str)
        or not isinstance(raw.get("rollback_discarded_spool"), str)
        or not isinstance(raw.get("attestation"), str)
        or type(raw.get("expected_test_uid")) is not int
        or type(raw.get("expected_previous_test_store_schema_version")) is not int
        or not isinstance(raw.get("forward_release"), str)
        or not isinstance(raw.get("previous_release"), str)
    ):
        raise SwitchError("same-schema test-history reset journal is invalid")
    if not requested:
        raise SwitchError(
            "same-schema transaction requires the explicit test-history reset flag"
        )
    try:
        operation_id = str(uuid.UUID(str(raw["operation_id"])))
    except (ValueError, AttributeError) as error:
        raise SwitchError("same-schema test-history reset operation ID is invalid") from error
    expected_attestation = TEST_DATABASE.parent / f"schema-readiness-{operation_id}.json"
    expected_forward_discard = (
        TEST_SPOOL.parent
        / f".{TEST_SPOOL.name}.{operation_id}.forward-discarded"
    )
    expected_rollback_discard = (
        TEST_SPOOL.parent
        / f".{TEST_SPOOL.name}.{operation_id}.rollback-discarded"
    )
    release = Path(str(document.get("release")))
    previous_digest = document.get("previous_release_digest")
    rebaseline = retained_rebaseline_intent(document)
    expected_previous_schema = reviewed_previous_test_store_schema(
        int(rebaseline["source_schema_version"])
    )
    if (
        operation_id != raw["operation_id"]
        or raw["attestation"] != str(expected_attestation)
        or raw["forward_discarded_spool"] != str(expected_forward_discard)
        or raw["rollback_discarded_spool"] != str(expected_rollback_discard)
        or raw["expected_test_uid"] != testd_uid()
        or raw["expected_previous_test_store_schema_version"]
        != expected_previous_schema
        or raw["forward_release"] != str(release)
        or raw["previous_release"] != str(release.parent / str(previous_digest))
    ):
        raise SwitchError("same-schema test-history reset binding is invalid")
    status = raw["status"]
    if status == "complete":
        evidence = raw.get("forward_evidence")
        if not isinstance(evidence, Mapping) or not valid_test_spool_reset_evidence(
            evidence.get("spool"),
            discarded_path=str(expected_forward_discard),
        ):
            raise SwitchError("same-schema forward spool reset evidence is invalid")
    if status == "rolled-back":
        evidence = raw.get("rollback_evidence")
        if not isinstance(evidence, Mapping) or not valid_test_spool_reset_evidence(
            evidence.get("spool"),
            discarded_path=str(expected_rollback_discard),
        ):
            raise SwitchError("same-schema rollback spool reset evidence is invalid")
    return raw


class Runner:
    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def run_bounded(
        self, argv: Sequence[str], *, timeout_seconds: float
    ) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=max(0.1, float(timeout_seconds)),
            )
        except subprocess.TimeoutExpired as error:
            raise SwitchError("bounded release command timed out") from error

    def require(self, argv: Sequence[str], label: str) -> str:
        result = self.run(argv)
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise SwitchError(f"{label} failed" + (f": {detail}" if detail else ""))
        return result.stdout

    def require_json(self, argv: Sequence[str], label: str) -> dict[str, object]:
        raw = self.require(argv, label)
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            raise SwitchError(f"{label} returned invalid JSON") from error
        if not isinstance(value, Mapping) or value.get("ok") is not True:
            raise SwitchError(f"{label} returned an unsuccessful result")
        return dict(value)


def release_capability(release: Path, capability: str) -> bool:
    verified = installer.verify_release(release)
    capabilities = verified.get("capabilities")
    if not isinstance(capabilities, Mapping):
        raise SwitchError("immutable release capability manifest is invalid")
    return capabilities.get(capability) is True


def retiring_release_capability(release: Path, capability: str) -> bool:
    """Read one content-bound capability without re-gating a running release.

    Historical releases can contain interpreter-generated ``__pycache__``
    directories from launchers that predate the bytecode-disabled wrappers.
    Those non-canonical cache entries must not block replacing the already
    running release.  The candidate still goes through ``verify_release``;
    this narrower reader validates the retiring release's manifest and derives
    the browser capability from the digest-bound file inventory instead of
    filesystem ownership, modes, or generated cache contents.
    """

    if capability != BROWSER_ACCOUNTING_CAPABILITY:
        raise SwitchError("retiring release capability is unsupported")
    release = release.expanduser().absolute()
    if RELEASE_RE.fullmatch(release.name) is None:
        raise SwitchError("retiring release identity is invalid")
    manifest_path = release / "release-manifest.json"
    try:
        manifest_info = manifest_path.lstat()
        if (
            stat.S_ISLNK(manifest_info.st_mode)
            or not stat.S_ISREG(manifest_info.st_mode)
            or manifest_info.st_size <= 0
            or manifest_info.st_size > 16 * 1024 * 1024
        ):
            raise SwitchError("retiring release manifest is invalid")
        document = json.loads(manifest_path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SwitchError("retiring release manifest is unavailable") from error
    entries = document.get("files") if isinstance(document, Mapping) else None
    capabilities = (
        document.get("capabilities") if isinstance(document, Mapping) else None
    )
    if (
        not isinstance(document, Mapping)
        or document.get("schema_version") != installer.RELEASE_SCHEMA
        or document.get("release_digest") != release.name
        or not isinstance(entries, list)
        or not entries
        or installer.release_digest(entries) != release.name
        or not isinstance(capabilities, Mapping)
    ):
        raise SwitchError("retiring release manifest contract is invalid")
    paths: set[str] = set()
    for entry in entries:
        if not isinstance(entry, Mapping) or not isinstance(entry.get("path"), str):
            raise SwitchError("retiring release file inventory is invalid")
        path = str(entry["path"])
        if not path or path in paths:
            raise SwitchError("retiring release file inventory is invalid")
        paths.add(path)
    derived = all(
        path in paths
        for path in (
            "bin/devcoordinator-browser-accounting",
            "skills/codex-dev-coordinator/scripts/devcoordinator/browser_lifecycle.py",
        )
    )
    if capabilities.get(capability) is not derived:
        raise SwitchError("retiring release capability contradicts its inventory")
    return derived


def require_previous_current_format_release(release: Path) -> None:
    """Require the predecessor's digest-bound current release capability.

    The retiring tree may contain generated bytecode, so this gate deliberately
    validates its manifest inventory rather than applying candidate cleanliness
    checks to the already-running release.
    """

    retiring_release_capability(release, BROWSER_ACCOUNTING_CAPABILITY)
    try:
        document = json.loads((release / "release-manifest.json").read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SwitchError("previous release manifest is unavailable") from error
    entries = document.get("files") if isinstance(document, Mapping) else None
    capabilities = (
        document.get("capabilities") if isinstance(document, Mapping) else None
    )
    if not isinstance(entries, list) or not isinstance(capabilities, Mapping):
        raise SwitchError("previous release manifest is invalid")
    paths = {
        str(entry["path"])
        for entry in entries
        if isinstance(entry, Mapping) and isinstance(entry.get("path"), str)
    }
    required = {
        "bin/devcoordinator-same-schema-switch",
        "scripts/switch_same_schema_release.py",
        "deploy/devcoordinator-api.socket",
        "deploy/devcoordinator-authority.socket",
        "deploy/devcoordinator-edge.service",
        "deploy/devcoordinator-console@.service",
    }
    if not required <= paths:
        raise SwitchError(
            "previous release is not one supported current-format package"
        )
    advertised = capabilities.get("current_format_delivery")
    if advertised is not None and advertised is not True:
        raise SwitchError(
            "previous release contradicts its current-format capability"
        )


def headless_browser_cleanup_plan(
    release: Path,
    *,
    previous_release_digest: str,
) -> dict[str, object]:
    previous_release = release.parent / previous_release_digest
    candidate_capable = release_capability(
        release, BROWSER_ACCOUNTING_CAPABILITY
    )
    previous_capable = retiring_release_capability(
        previous_release, BROWSER_ACCOUNTING_CAPABILITY
    )
    required = candidate_capable and not previous_capable
    return {
        "required": required,
        "status": "pending" if required else "not-required",
        "candidate_release": str(release),
        "previous_release": str(previous_release),
        "candidate_capable": candidate_capable,
        "previous_capable": previous_capable,
    }


def validate_headless_browser_cleanup_plan(
    document: Mapping[str, object],
    release: Path,
) -> dict[str, object]:
    raw = document.get("headless_browser_cleanup")
    if not isinstance(raw, Mapping):
        raise SwitchError("same-schema browser cleanup plan is unavailable")
    value = dict(raw)
    required = value.get("required")
    candidate_capable = value.get("candidate_capable")
    previous_capable = value.get("previous_capable")
    status = value.get("status")
    previous_release = release.parent / str(document.get("previous_release_digest"))
    actual_candidate_capable = release_capability(
        release, BROWSER_ACCOUNTING_CAPABILITY
    )
    actual_previous_capable = retiring_release_capability(
        previous_release, BROWSER_ACCOUNTING_CAPABILITY
    )
    if (
        type(required) is not bool
        or type(candidate_capable) is not bool
        or type(previous_capable) is not bool
        or value.get("candidate_release") != str(release)
        or value.get("previous_release") != str(previous_release)
        or candidate_capable != actual_candidate_capable
        or previous_capable != actual_previous_capable
        or required is not (candidate_capable and not previous_capable)
        or status not in {"not-required", "pending", "running", "complete", "failed"}
        or (not required and status != "not-required")
        or (required and status == "not-required")
    ):
        raise SwitchError("same-schema browser cleanup plan is invalid")
    if status == "complete":
        result = value.get("result")
        if (
            not isinstance(result, Mapping)
            or result.get("ok") is not True
            or result.get("remaining_session_count") != 0
            or len(canonical(result)) > BROWSER_CLEANUP_RESULT_MAX_BYTES
        ):
            raise SwitchError("same-schema browser cleanup evidence is invalid")
    return value


def bounded_browser_cleanup_result(value: Mapping[str, object]) -> dict[str, object]:
    remaining = value.get("remaining_session_count")
    if value.get("ok") is not True or type(remaining) is not int or remaining != 0:
        raise SwitchError(
            "headless browser cleanup did not remove every eligible session"
        )
    result: dict[str, object] = {
        "ok": True,
        "remaining_session_count": 0,
    }
    for field in (
        "observed_session_count",
        "terminated_session_count",
        "terminated_process_count",
        "reclaimed_memory_bytes",
        "already_stopped_session_count",
        "protected_session_count",
    ):
        item = value.get(field)
        if type(item) is int and item >= 0:
            result[field] = item
    sampled_at = value.get("sampled_at")
    if isinstance(sampled_at, str) and 0 < len(sampled_at) <= 64:
        result["sampled_at"] = sampled_at
    if len(canonical(result)) > BROWSER_CLEANUP_RESULT_MAX_BYTES:
        raise SwitchError("headless browser cleanup result is too large")
    return result


def perform_headless_browser_cleanup(
    release: Path,
    document: dict[str, object],
    journal_path: Path,
    runner: Runner,
) -> dict[str, object] | None:
    cleanup = validate_headless_browser_cleanup_plan(document, release)
    if cleanup["required"] is not True:
        return None
    status = cleanup["status"]
    if status == "complete":
        return dict(cleanup["result"])
    if status in {"running", "failed"}:
        raise SwitchError(
            "headless browser cleanup has an uncertain or failed prior outcome; "
            "start a new same-schema transaction instead of replaying it"
        )

    cleanup["status"] = "running"
    cleanup["started_at"] = now()
    document["headless_browser_cleanup"] = cleanup
    save_phase(journal_path, document, str(document["phase"]))
    command = [
        str(release / "bin" / BROWSER_ACCOUNTING_WRAPPER),
        "cleanup-all",
        "--state",
        str(BROWSER_LIFECYCLE_STATE),
        "--quiescence-seconds",
        str(BROWSER_CLEANUP_QUIESCENCE_SECONDS),
        "--json",
    ]
    try:
        result = bounded_browser_cleanup_result(
            runner.require_json(command, "one-time headless browser cleanup")
        )
    except SwitchError as error:
        cleanup["status"] = "failed"
        cleanup["completed_at"] = now()
        cleanup["error"] = " ".join(str(error).split())[:512]
        document["headless_browser_cleanup"] = cleanup
        save_phase(journal_path, document, str(document["phase"]))
        raise
    cleanup["status"] = "complete"
    cleanup["completed_at"] = now()
    cleanup["result"] = result
    document["headless_browser_cleanup"] = cleanup
    save_phase(journal_path, document, str(document["phase"]))
    return result


def active_console_units(runner: Runner) -> list[str]:
    output = runner.require(
        [
            "/usr/bin/systemctl",
            "list-units",
            "devcoordinator-console@*.service",
            "--state=active",
            "--no-legend",
            "--plain",
            "--no-pager",
        ],
        "active Console discovery",
    )
    return sorted(
        {
            line.split()[0]
            for line in output.splitlines()
            if line.strip() and line.split()[0].startswith("devcoordinator-console@")
        }
    )


def recover_published_console(runner: Runner) -> tuple[str, str]:
    """Recover the exact slot retained by the stable edge publication.

    A stopped Console instance cannot select a different release: the signed,
    atomically published edge snapshot and its immutable slot file remain the
    authority.  Recovery starts only that exact slot plus the stable API
    socket.  It never guesses from installed unit names and never resolves an
    ambiguous two-slot topology.
    """

    published = publication_snapshot()
    digest = str(published["release_digest"])
    if RELEASE_RE.fullmatch(digest) is None:
        raise SwitchError("published Console release identity is invalid")
    slot = SLOT_ROOT / f"{digest}.env"
    if not slot.is_file() or slot.is_symlink():
        raise SwitchError("published Console slot configuration is unavailable")
    values = parse_slot(slot.read_text(encoding="utf-8"))
    if (
        values["DEVCOORDINATOR_RELEASE_DIGEST"] != digest
        or int(values["HTTPS_PORT"]) != published["port"]
    ):
        raise SwitchError("published Console slot contradicts the edge publication")
    unit = f"devcoordinator-console@{digest}.service"
    runner.require(
        ["/usr/bin/systemctl", "start", API_SOCKET],
        "recover stable API socket",
    )
    runner.require(
        ["/usr/bin/systemctl", "start", unit],
        "recover published Console slot",
    )
    units = active_console_units(runner)
    if units != [unit]:
        raise SwitchError("published Console slot recovery did not converge")
    return unit, digest


def active_console(runner: Runner) -> tuple[str, str]:
    units = active_console_units(runner)
    if not units:
        return recover_published_console(runner)
    if len(units) != 1:
        raise SwitchError("same-schema switch requires exactly one active Console slot")
    match = re.fullmatch(r"devcoordinator-console@([0-9a-f]{64})\.service", units[0])
    if match is None:
        raise SwitchError("active Console slot is not an immutable release")
    return units[0], match.group(1)


def parse_slot(payload: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in payload.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key or key in result or "\x00" in value:
            raise SwitchError("Console slot configuration is invalid")
        result[key] = value
    required = {
        "BIND_HOST",
        "DEV_HTTP",
        "HTTP_PORT",
        "HTTPS_PORT",
        "DEVCOORDINATOR_RELEASE_DIGEST",
        "DEVCOORDINATOR_CONSOLE_INNER_PORT",
        "DEVCOORDINATOR_CONSOLE_CONTROL_SOCKET",
        "DEVCOORDINATOR_CONSOLE_SUPERVISOR_STATE",
        "DEVCOORDINATOR_CONSOLE_RUNTIME",
        "DEVCOORDINATOR_CONSOLE_BOOTSTRAP_ACTIVE",
    }
    if not required <= set(result):
        raise SwitchError("Console slot configuration is incomplete")
    try:
        ports = (int(result["HTTPS_PORT"]), int(result["DEVCOORDINATOR_CONSOLE_INNER_PORT"]))
    except ValueError as error:
        raise SwitchError("Console slot ports are invalid") from error
    if any(not PORT_MIN <= port <= PORT_MAX for port in ports) or ports[0] == ports[1]:
        raise SwitchError("Console slot ports are outside the production range")
    return result


def candidate_slot_payload(digest: str, outer_port: int, inner_port: int) -> bytes:
    if RELEASE_RE.fullmatch(digest) is None:
        raise SwitchError("candidate Console release digest is invalid")
    if (
        outer_port == inner_port
        or any(not PORT_MIN <= value <= PORT_MAX for value in (outer_port, inner_port))
    ):
        raise SwitchError("candidate Console ports are invalid")
    return (
        "# Generated same-schema Console candidate slot.\n"
        "BIND_HOST=127.0.0.1\n"
        "DEV_HTTP=0\n"
        "HTTP_PORT=0\n"
        f"HTTPS_PORT={outer_port}\n"
        f"DEVCOORDINATOR_RELEASE_DIGEST={digest}\n"
        f"DEVCOORDINATOR_CONSOLE_INNER_PORT={inner_port}\n"
        f"DEVCOORDINATOR_CONSOLE_CONTROL_SOCKET=/run/devcoordinator-console/{digest}.sock\n"
        "DEVCOORDINATOR_CONSOLE_SUPERVISOR_STATE=/var/lib/devcoordinator-console/supervisor\n"
        "DEVCOORDINATOR_CONSOLE_RUNTIME=/run/devcoordinator-console\n"
        "DEVCOORDINATOR_CONSOLE_BOOTSTRAP_ACTIVE=0\n"
    ).encode("utf-8")


def reserve_candidate_ports(excluded: set[int]) -> tuple[int, int]:
    reservations: list[socket.socket] = []
    values: list[int] = []
    try:
        for _ in range(64):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            listener.bind(("127.0.0.1", 0))
            port = int(listener.getsockname()[1])
            if not PORT_MIN <= port <= PORT_MAX or port in excluded or port in values:
                listener.close()
                continue
            reservations.append(listener)
            values.append(port)
            if len(values) == 2:
                return values[0], values[1]
        raise SwitchError("two unused Console loopback ports are unavailable")
    finally:
        for listener in reservations:
            listener.close()


def bind_exact_ports(ports: Sequence[int]) -> list[socket.socket]:
    listeners: list[socket.socket] = []
    try:
        for port in ports:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            listener.bind(("127.0.0.1", int(port)))
            listeners.append(listener)
        return listeners
    except OSError as error:
        for listener in listeners:
            listener.close()
        raise SwitchError("candidate Console ports are no longer available") from error


def certbot_hook_payload() -> bytes:
    """Render the stable, lineage-scoped TLS renewal hook."""

    return (
        "#!/bin/sh\n"
        "set -eu\n"
        'case "${RENEWED_LINEAGE:-/etc/letsencrypt/live/vr.ae}" in\n'
        "  /etc/letsencrypt/live/vr.ae) ;;\n"
        "  *) exit 0 ;;\n"
        "esac\n"
        f"exec '{EDGE_CERT_REFRESH_LAUNCHER}' "
        "--lineage /etc/letsencrypt/live/vr.ae --domain vr.ae\n"
    ).encode("utf-8")


def require_certbot_hook_root() -> None:
    """Require the existing root-owned certbot deploy-hook boundary."""

    try:
        info = CERTBOT_HOOK_ROOT.lstat()
    except OSError as error:
        raise SwitchError("certbot deploy-hook directory is unavailable") from error
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o022
        or CERTBOT_HOOK_ROOT.resolve(strict=True) != CERTBOT_HOOK_ROOT
    ):
        raise SwitchError("certbot deploy-hook directory is unsafe")


def render_release(release: Path, transaction_root: Path) -> dict[str, object]:
    verified = installer.verify_release(release)
    digest = str(verified["release_digest"])
    rendered = transaction_root / "rendered-units"
    if rendered.exists():
        raise SwitchError("same-schema rendered unit directory already exists")
    rendered.mkdir(parents=True)
    capacity = installer.derive_slice_capacity(installer.host_memory_bytes())
    for name in (
        *TOPOLOGY_FILES,
        "devcoordinator-availability.sysusers.conf",
        "devcoordinator-availability.tmpfiles.conf",
        MAIN_TMPFILES_RENDERED,
    ):
        source = release / "deploy" / name
        if not source.is_file() or source.is_symlink():
            raise SwitchError(f"immutable release template is unavailable: {name}")
        text = source.read_text(encoding="utf-8").replace("RELEASE_DIGEST", digest)
        for placeholder, field in installer.CAPACITY_PLACEHOLDERS.items():
            text = text.replace(placeholder, str(capacity[field]))
        if "RELEASE_DIGEST" in text or any(
            placeholder in text for placeholder in installer.CAPACITY_PLACEHOLDERS
        ):
            raise SwitchError(f"same-schema template retained a placeholder: {name}")
        atomic_bytes(rendered / name, text.encode("utf-8"), 0o644)
    for rendered_name, (_destination, immutable_name) in STABLE_LAUNCHERS.items():
        immutable = release / "bin" / immutable_name
        if not immutable.is_file() or immutable.is_symlink():
            raise SwitchError(
                f"immutable client wrapper is unavailable: {immutable_name}"
            )
        launcher = (
            "#!/bin/sh\n"
            "set -eu\n"
            f"exec '{immutable}' \"$@\"\n"
        ).encode("utf-8")
        atomic_bytes(rendered / rendered_name, launcher, 0o755)
    atomic_bytes(
        rendered / CERTBOT_HOOK_RENDERED,
        certbot_hook_payload(),
        0o700,
    )
    for rendered_name in (READ_ONLY_RULE_RENDERED, TEST_RULE_RENDERED):
        immutable_rule = release / "deploy" / rendered_name
        if not immutable_rule.is_file() or immutable_rule.is_symlink():
            raise SwitchError(
                f"immutable Codex client rule is unavailable: {rendered_name}"
            )
        atomic_bytes(rendered / rendered_name, immutable_rule.read_bytes(), 0o644)
    return {"release_digest": digest, "release": str(release), "rendered_units": str(rendered)}


def destinations(rendered: Path) -> dict[str, Path]:
    require_certbot_hook_root()
    result = {name: UNIT_ROOT / name for name in TOPOLOGY_FILES}
    result["devcoordinator-availability.sysusers.conf"] = (
        SYSUSERS_ROOT / "devcoordinator-availability.sysusers.conf"
    )
    result["devcoordinator-availability.tmpfiles.conf"] = (
        TMPFILES_ROOT / "devcoordinator-availability.tmpfiles.conf"
    )
    result[MAIN_TMPFILES_RENDERED] = TMPFILES_ROOT / "devcoordinator.conf"
    for rendered_name, (destination, _immutable_name) in STABLE_LAUNCHERS.items():
        result[rendered_name] = destination
    result[CERTBOT_HOOK_RENDERED] = CERTBOT_HOOK
    result[READ_ONLY_RULE_RENDERED] = READ_ONLY_RULE
    result[TEST_RULE_RENDERED] = TEST_RULE
    if any(not (rendered / name).is_file() for name in result):
        raise SwitchError("rendered same-schema unit set is incomplete")
    return result


def destination_mode(name: str) -> int:
    if name == CERTBOT_HOOK_RENDERED:
        return 0o700
    return 0o755 if name in STABLE_LAUNCHERS else 0o644


def codex_directory_mode(directory: Path) -> int:
    return 0o755


def codex_directory_states() -> dict[str, object]:
    result: dict[str, object] = {}
    for directory in (CODEX_ROOT, CODEX_RULE_ROOT):
        try:
            info = directory.lstat()
        except FileNotFoundError:
            result[str(directory)] = {"existed": False}
            continue
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise SwitchError(f"Codex configuration directory is unsafe: {directory}")
        result[str(directory)] = {
            "existed": True,
            "mode": stat.S_IMODE(info.st_mode),
        }
    return result


def prepare_codex_directories(states: Mapping[str, object]) -> None:
    for directory in (CODEX_ROOT, CODEX_RULE_ROOT):
        raw = states.get(str(directory))
        if not isinstance(raw, Mapping) or type(raw.get("existed")) is not bool:
            raise SwitchError("Codex configuration directory plan is invalid")
        if raw["existed"] is True:
            info = directory.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != raw.get("mode")
            ):
                raise SwitchError(
                    f"Codex configuration directory changed before apply: {directory}"
                )
        else:
            directory.mkdir(mode=codex_directory_mode(directory))
        os.chmod(directory, codex_directory_mode(directory))


def restore_codex_directories(states: Mapping[str, object]) -> None:
    for directory in (CODEX_RULE_ROOT, CODEX_ROOT):
        raw = states.get(str(directory))
        if not isinstance(raw, Mapping) or type(raw.get("existed")) is not bool:
            raise SwitchError("Codex configuration directory rollback plan is invalid")
        if raw["existed"] is True:
            os.chmod(directory, int(raw["mode"]))
        elif directory.exists():
            directory.rmdir()


def publication_snapshot() -> dict[str, object]:
    value = load_json(PUBLICATION_FILE)
    publication = value.get("publication")
    if not isinstance(publication, Mapping):
        raise SwitchError("edge publication payload is invalid")
    console = publication.get("console")
    upstream = console.get("upstream") if isinstance(console, Mapping) else None
    if (
        not isinstance(upstream, Mapping)
        or not isinstance(value.get("payload_sha256"), str)
        or not isinstance(publication.get("release_digest"), str)
        or type(publication.get("generation")) is not int
        or type(upstream.get("port")) is not int
    ):
        raise SwitchError("edge publication Console target is invalid")
    return {
        "payload_sha256": value["payload_sha256"],
        "release_digest": publication["release_digest"],
        "generation": publication["generation"],
        "port": upstream["port"],
    }


def prepare(
    release: Path,
    transaction_root: Path,
    runner: Runner,
    *,
    reset_test_history: bool = False,
) -> dict[str, object]:
    release = release.expanduser().resolve(strict=True)
    if (
        release.parent != Path("/opt/devcoordinator/releases")
        or RELEASE_RE.fullmatch(release.name) is None
    ):
        raise SwitchError("same-schema release is not one immutable production path")
    transaction_root = require_transaction_root(
        transaction_root,
        release_digest=release.name,
    )
    existing = load_journal(transaction_root / "journal.json")
    if existing is not None:
        if existing.get("release") != str(release):
            raise SwitchError("same-schema transaction belongs to another release")
        require_test_history_reset_mode(existing, requested=reset_test_history)
        retained_rebaseline_intent(existing)
        return existing
    current_unit, current_digest = active_console(runner)
    require_previous_current_format_release(release.parent / current_digest)
    authority_schema = _authority_schema_version()
    if authority_schema not in {
        retained_control.REBASELINE_SOURCE_SCHEMA,
        COORDINATOR_SCHEMA_VERSION,
    }:
        raise SwitchError("authority schema is outside the one reviewed 15 -> 16 rebaseline")
    retained_rebaseline = {
        "required": authority_schema != COORDINATOR_SCHEMA_VERSION,
        "source_schema_version": authority_schema,
        "target_schema_version": COORDINATOR_SCHEMA_VERSION,
        "status": "planned",
    }
    if current_digest == release.name and retained_rebaseline["required"] is True:
        raise SwitchError(
            "an already-active release cannot perform the one-time retained-control rebaseline"
        )
    current_slot = SLOT_ROOT / f"{current_digest}.env"
    if not current_slot.is_file() or current_slot.is_symlink():
        raise SwitchError("active Console slot configuration is unavailable")
    current_values = parse_slot(current_slot.read_text(encoding="utf-8"))
    if current_values["DEVCOORDINATOR_RELEASE_DIGEST"] != current_digest:
        raise SwitchError("active Console slot release identity is invalid")
    old_outer = int(current_values["HTTPS_PORT"])
    old_inner = int(current_values["DEVCOORDINATOR_CONSOLE_INNER_PORT"])
    published = publication_snapshot()
    if published["release_digest"] != current_digest or published["port"] != old_outer:
        raise SwitchError("active Console slot contradicts the edge publication")
    rendered = render_release(release, transaction_root)
    if current_digest == release.name:
        browser_cleanup = headless_browser_cleanup_plan(
            release,
            previous_release_digest=current_digest,
        )
        document = {
            "schema_version": VERSION,
            "kind": KIND,
            "phase": (
                "prepared"
                if reset_test_history or retained_rebaseline["required"] is True
                else "applied"
            ),
            "release": str(release),
            "release_digest": release.name,
            "previous_release_digest": current_digest,
            "previous_console_unit": current_unit,
            "candidate_console_unit": current_unit,
            "previous_console_slot": str(current_slot),
            "candidate_console_slot_source": str(current_slot),
            "previous_control_socket": current_values[
                "DEVCOORDINATOR_CONSOLE_CONTROL_SOCKET"
            ],
            "candidate_control_socket": current_values[
                "DEVCOORDINATOR_CONSOLE_CONTROL_SOCKET"
            ],
            "previous_outer_port": old_outer,
            "previous_inner_port": old_inner,
            "candidate_outer_port": old_outer,
            "candidate_inner_port": old_inner,
            "publication_before": published,
            "rendered_units": rendered["rendered_units"],
            "expected_destinations": {},
            "backups": {},
            "candidate_started": True,
            "promoted": True,
            "publication_switched": True,
            "already_active": True,
            "headless_browser_cleanup": browser_cleanup,
            "retained_control_rebaseline": retained_rebaseline,
        }
        if reset_test_history:
            document["test_history_reset"] = test_history_reset_intent(
                release,
                previous_release_digest=current_digest,
                source_authority_schema_version=authority_schema,
            )
        if not reset_test_history and retained_rebaseline["required"] is not True:
            document["completed_at"] = now()
        atomic_json(transaction_root / "journal.json", document)
        return document
    outer, inner = reserve_candidate_ports({old_outer, old_inner})
    browser_cleanup = headless_browser_cleanup_plan(
        release,
        previous_release_digest=current_digest,
    )
    new_slot = transaction_root / f"{release.name}.env"
    atomic_bytes(new_slot, candidate_slot_payload(release.name, outer, inner), 0o644)
    unit_sources = destinations(Path(str(rendered["rendered_units"])))
    expected = {
        str(destination): (
            digest_file(destination)
            if destination.is_file() and not destination.is_symlink()
            else None
        )
        for destination in unit_sources.values()
    }
    document: dict[str, object] = {
        "schema_version": VERSION,
        "kind": KIND,
        "phase": "prepared",
        "release": str(release),
        "release_digest": release.name,
        "previous_release_digest": current_digest,
        "previous_console_unit": current_unit,
        "candidate_console_unit": f"devcoordinator-console@{release.name}.service",
        "previous_console_slot": str(current_slot),
        "candidate_console_slot_source": str(new_slot),
        "previous_control_socket": current_values["DEVCOORDINATOR_CONSOLE_CONTROL_SOCKET"],
        "candidate_control_socket": f"/run/devcoordinator-console/{release.name}.sock",
        "previous_outer_port": old_outer,
        "previous_inner_port": old_inner,
        "candidate_outer_port": outer,
        "candidate_inner_port": inner,
        "publication_before": published,
        "rendered_units": rendered["rendered_units"],
        "expected_destinations": expected,
        "codex_directory_states": codex_directory_states(),
        "backups": {},
        "candidate_started": False,
        "promoted": False,
        "publication_switched": False,
        "headless_browser_cleanup": browser_cleanup,
        "retained_control_rebaseline": retained_rebaseline,
    }
    if reset_test_history:
        document["test_history_reset"] = test_history_reset_intent(
            release,
            previous_release_digest=current_digest,
            source_authority_schema_version=authority_schema,
        )
    atomic_json(transaction_root / "journal.json", document)
    return document


def backup_destinations(
    document: Mapping[str, object], transaction_root: Path
) -> dict[str, object]:
    rendered = Path(str(document["rendered_units"]))
    mapping = destinations(rendered)
    root = transaction_root / "backups"
    root.mkdir(parents=True, exist_ok=True)
    expected_destinations = document.get("expected_destinations")
    if not isinstance(expected_destinations, Mapping):
        raise SwitchError("same-schema destination plan is invalid")
    result: dict[str, object] = {}
    for name, destination in mapping.items():
        expected = expected_destinations.get(str(destination))
        if destination.exists() and (not destination.is_file() or destination.is_symlink()):
            raise SwitchError(f"same-schema destination is not a real file: {destination}")
        actual = digest_file(destination) if destination.exists() else None
        if actual != expected:
            raise SwitchError(f"same-schema destination changed before apply: {destination}")
        if destination.exists():
            backup = root / name
            atomic_bytes(backup, destination.read_bytes(), destination.stat().st_mode & 0o777)
            result[str(destination)] = {
                "existed": True,
                "backup": str(backup),
                "mode": destination.stat().st_mode & 0o777,
            }
        else:
            result[str(destination)] = {"existed": False}
    return result


def install_rendered_destinations(rendered: Path) -> None:
    """Atomically replace every destination in the prepared release graph."""

    for name, destination in destinations(rendered).items():
        atomic_bytes(
            destination,
            (rendered / name).read_bytes(),
            destination_mode(name),
        )


def restore_destination_backups(backups: Mapping[str, object]) -> None:
    """Restore or remove every destination exactly as the transaction found it."""

    for raw_destination, evidence in backups.items():
        if not isinstance(evidence, Mapping):
            raise SwitchError("same-schema rollback evidence is invalid")
        destination = Path(raw_destination)
        if evidence.get("existed") is True:
            backup = Path(str(evidence["backup"]))
            atomic_bytes(destination, backup.read_bytes(), int(evidence["mode"]))
        elif evidence.get("existed") is False:
            destination.unlink(missing_ok=True)
        else:
            raise SwitchError("same-schema rollback evidence is invalid")


def _authority_schema_version(path: Path = AUTHORITY_DATABASE) -> int:
    try:
        connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA query_only = ON")
            row = connection.execute(
                "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
            ).fetchone()
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise SwitchError(f"authority schema cannot be read: {error}") from error
    if row is None or type(row[0]) is not int or int(row[0]) <= 0:
        raise SwitchError("authority schema metadata is invalid")
    return int(row[0])


def require_current_authority_schema() -> int:
    """Require the current schema after any semantic retained-control rebaseline."""

    current = _authority_schema_version()
    if current != COORDINATOR_SCHEMA_VERSION:
        raise SwitchError(
            "authority schema is incompatible after retained-control preparation"
        )
    return current


def retained_rebaseline_intent(document: Mapping[str, object]) -> dict[str, object]:
    raw = document.get("retained_control_rebaseline")
    if (
        not isinstance(raw, Mapping)
        or type(raw.get("required")) is not bool
        or type(raw.get("source_schema_version")) is not int
        or raw.get("target_schema_version") != COORDINATOR_SCHEMA_VERSION
        or raw.get("status")
        not in {
            "planned",
            "backed-up",
            "prepared",
            "publishing",
            "published",
            "applied",
            "rolled-back",
        }
    ):
        raise SwitchError("retained-control rebaseline intent is invalid")
    if raw["required"] is True:
        if (
            raw["source_schema_version"] != retained_control.REBASELINE_SOURCE_SCHEMA
            or document.get("already_active") is True
        ):
            raise SwitchError("retained-control rebaseline is not an exact 15 -> 16 release switch")
        proof = raw.get("source_worker_quiescence")
        if proof is not None and not _valid_source_worker_quiescence(proof):
            raise SwitchError("retained-control source worker proof is invalid")
        if raw["status"] != "planned" and proof is None:
            raise SwitchError("retained-control source worker proof is missing")
    elif raw["source_schema_version"] != COORDINATOR_SCHEMA_VERSION:
        raise SwitchError("unneeded retained-control rebaseline has an incompatible source")
    return dict(raw)


def validate_retained_rebaseline_paths(
    intent: Mapping[str, object],
    transaction_root: Path,
) -> None:
    core_backups = {
        str(AUTHORITY_DATABASE): transaction_root
        / "retained-control-backups/authority.sqlite3",
        str(CLIENT_PROFILE): transaction_root
        / "retained-control-backups/client-profiles.json",
        **{
            str(CONSOLE_STATE_ROOT / name): transaction_root
            / "retained-control-backups"
            / f"console-{name}"
            for name in retained_control.CONSOLE_FILES
        },
    }
    backups = intent.get("backups")
    if backups is not None:
        if not isinstance(backups, Mapping) or not set(core_backups) <= set(backups):
            raise SwitchError("retained-control backup destinations are invalid")
        expected_backups = dict(core_backups)
        credential_destinations: set[str] = set()
        for destination in set(backups) - set(core_backups):
            credential_id = _server_credential_id_from_destination(destination)
            expected_backups[str(destination)] = _server_credential_backup_path(
                transaction_root, credential_id
            )
            credential_destinations.add(str(destination))
        for destination, expected_backup in expected_backups.items():
            evidence = backups[destination]
            if not isinstance(evidence, Mapping) or type(evidence.get("existed")) is not bool:
                raise SwitchError("retained-control backup evidence is invalid")
            source = evidence.get("source")
            if (
                not isinstance(source, Mapping)
                or source.get("path") != destination
                or source.get("present") is not evidence["existed"]
                or not isinstance(source.get("parent"), Mapping)
            ):
                raise SwitchError("retained-control source identity is invalid")
            require_parent_identity(Path(destination), source["parent"])
            if evidence["existed"] is True:
                backup = evidence.get("backup")
                if (
                    set(evidence) != {"existed", "source", "backup"}
                    or not isinstance(backup, Mapping)
                    or Path(str(backup.get("path") or "")) != expected_backup
                ):
                    raise SwitchError("retained-control backup escaped its transaction")
                if (
                    re.fullmatch(r"[0-9a-f]{64}", str(source.get("sha256") or "")) is None
                    or type(source.get("bytes")) is not int
                    or int(source["bytes"]) <= 0
                    or any(
                        type(source.get(field)) is not int
                        for field in ("mode", "uid", "gid", "device", "inode", "mtime_ns")
                    )
                    or exact_file_identity(expected_backup) != dict(backup)
                    or backup.get("sha256") != source.get("sha256")
                    or backup.get("bytes") != source.get("bytes")
                    or backup.get("mode") != 0o600
                    or backup.get("uid") != os.geteuid()
                    or backup.get("gid") != os.getegid()
                ):
                    raise SwitchError("retained-control backup identity is invalid")
            elif set(evidence) != {"existed", "source"} or set(source) != {
                "path",
                "present",
                "parent",
            }:
                raise SwitchError("absent retained-control backup has extra evidence")
            if destination in credential_destinations and evidence["existed"] is True:
                if (
                    source.get("uid") != os.geteuid()
                    or source.get("gid") != os.getegid()
                    or source.get("mode") != 0o600
                ):
                    raise SwitchError(
                        "retained server credential predecessor is not owner mode 0600"
                    )
    manifest = intent.get("manifest")
    if manifest is not None and Path(str(manifest)) != transaction_root / "retained-control/retained-control.json":
        raise SwitchError("retained-control manifest escaped its transaction")


def _writer_cgroup_populated(
    control_group: str,
    *,
    cgroup_root: Path,
    allow_missing: bool,
) -> bool:
    if (
        not isinstance(control_group, str)
        or not control_group.startswith("/")
        or "\x00" in control_group
        or any(part in {"", ".", ".."} for part in control_group.split("/")[1:])
    ):
        raise SwitchError("writer control-group identity is invalid")
    root = cgroup_root.expanduser().absolute()
    try:
        root_info = root.lstat()
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or stat.S_ISLNK(root_info.st_mode)
            or root.resolve(strict=True) != root
        ):
            raise SwitchError("writer cgroup root is not canonical")
        current = root
        for part in control_group.split("/")[1:]:
            current = current / part
            info = current.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise SwitchError("writer cgroup ancestry is unsafe")
    except FileNotFoundError:
        if allow_missing:
            return False
        raise SwitchError("writer cgroup ancestry is unavailable")
    except OSError as error:
        raise SwitchError("writer cgroup ancestry is unavailable") from error
    events = current / "cgroup.events"
    descriptor = -1
    try:
        path_before = events.lstat()
        if stat.S_ISLNK(path_before.st_mode) or not stat.S_ISREG(path_before.st_mode):
            raise SwitchError("writer cgroup.events is not a real file")
        descriptor = os.open(
            events,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except FileNotFoundError:
        if allow_missing:
            return False
        raise SwitchError("writer cgroup.events is unavailable")
    except OSError as error:
        raise SwitchError("writer cgroup.events is unavailable") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or (path_before.st_dev, path_before.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            raise SwitchError("writer cgroup path and descriptor differ")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, min(1024, 4097 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > 4096:
                raise SwitchError("writer cgroup evidence is excessive")
        after = os.fstat(descriptor)
        path_after = events.lstat()
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or stat.S_IFMT(before.st_mode) != stat.S_IFMT(after.st_mode)
            or (path_after.st_dev, path_after.st_ino)
            != (after.st_dev, after.st_ino)
        ):
            raise SwitchError("writer cgroup identity changed while reading")
    except OSError as error:
        raise SwitchError("writer cgroup evidence is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        lines = b"".join(chunks).decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise SwitchError("writer cgroup evidence is invalid") from error
    values: dict[str, str] = {}
    for line in lines:
        fields = line.split(" ", 1)
        if len(fields) != 2 or fields[0] in values:
            raise SwitchError("writer cgroup evidence is invalid")
        values[fields[0]] = fields[1]
    if list(key for key in values if key == "populated") != ["populated"] or values[
        "populated"
    ] not in {"0", "1"}:
        raise SwitchError("writer cgroup evidence is invalid")
    return values["populated"] == "1"


def _writer_unit_state(runner: Runner, unit: str) -> dict[str, object]:
    if unit not in AUTHORITY_WRITER_UNITS:
        raise SwitchError("writer unit identity is invalid")
    service = unit.endswith(".service")
    properties = ["LoadState", "ActiveState", "SubState"]
    if service:
        properties.extend(("MainPID", "ControlGroup"))
    completed = runner.run_bounded(
        [
            "/usr/bin/systemctl",
            "show",
            unit,
            *(f"--property={name}" for name in properties),
            "--no-pager",
        ],
        timeout_seconds=AUTHORITY_STOP_COMMAND_TIMEOUT_SECONDS,
    )
    if len((completed.stdout + completed.stderr).encode("utf-8")) > 64 * 1024:
        raise SwitchError("authority native evidence is excessive")
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        if "=" not in line:
            raise SwitchError("writer native status is malformed")
        key, value = line.split("=", 1)
        if key in values:
            raise SwitchError("writer native status duplicated a property")
        values[key] = value
    if completed.returncode != 0:
        raise SwitchError("writer native status failed")
    if set(values) != set(properties):
        raise SwitchError("writer native status is incomplete")
    if values["LoadState"] != "loaded":
        raise SwitchError("required writer unit is not loaded: " + unit)
    if values["ActiveState"] not in {
        "active",
        "activating",
        "deactivating",
        "reloading",
        "inactive",
        "failed",
    } or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", values["SubState"]) is None:
        raise SwitchError("writer native state is invalid")
    pid: int | None = None
    control_group: str | None = None
    if service:
        if not values["MainPID"].isdigit() or int(values["MainPID"]) > 2**31 - 1:
            raise SwitchError("writer native PID is invalid")
        pid = int(values["MainPID"]) or None
        control_group = values["ControlGroup"] or None
    active = values["ActiveState"] in {
        "active",
        "activating",
        "deactivating",
        "reloading",
    }
    if not active and pid is not None:
        raise SwitchError("inactive writer retained a main PID")
    return {
        "unit": unit,
        "active": active,
        "state": values["SubState"],
        "pid": pid,
        "control_group": control_group,
    }


def _bounded_systemctl(
    runner: Runner,
    argv: Sequence[str],
    *,
    label: str,
) -> bool:
    try:
        completed = runner.run_bounded(
            argv, timeout_seconds=AUTHORITY_STOP_COMMAND_TIMEOUT_SECONDS
        )
    except SwitchError:
        return False
    if len((completed.stdout + completed.stderr).encode("utf-8")) > 64 * 1024:
        raise SwitchError(label + " returned excessive output")
    return completed.returncode == 0


def _wait_writers_inactive(
    runner: Runner,
    *,
    units: Sequence[str],
    timeout_seconds: float,
    clock: Callable[[], float],
    sleeper: Callable[[float], None],
    raise_on_timeout: bool = True,
) -> dict[str, dict[str, object]]:
    selected = tuple(units)
    if (
        not selected
        or len(set(selected)) != len(selected)
        or any(unit not in AUTHORITY_WRITER_UNITS for unit in selected)
    ):
        raise SwitchError("writer wait identities are invalid")
    deadline = float(clock()) + max(0.1, float(timeout_seconds))
    while True:
        states = {unit: _writer_unit_state(runner, unit) for unit in selected}
        active = sorted(
            unit for unit, state in states.items() if state["active"] is True
        )
        if not active:
            return states
        if float(clock()) >= deadline:
            if raise_on_timeout:
                raise SwitchError(
                    "authority writers did not stop: " + ", ".join(active)
                )
            return states
        sleeper(
            min(
                AUTHORITY_STOP_POLL_SECONDS,
                max(0.0, deadline - float(clock())),
            )
        )


def _authority_terminal_proof(
    runner: Runner,
    *,
    pid: int,
    process_start: str,
    control_group: str,
    cgroup_root: Path,
    process_observer: Callable[[int, str], str],
) -> dict[str, object] | None:
    observed = _writer_unit_state(runner, AUTHORITY_SERVICE)
    if observed["active"] is True or _writer_cgroup_populated(
        control_group, cgroup_root=cgroup_root, allow_missing=True
    ):
        return None
    try:
        process_state = process_observer(pid, process_start)
    except (OSError, RuntimeError, ValueError) as error:
        raise SwitchError("authority process absence is unobservable") from error
    if process_state not in {"absent", "mismatch"}:
        return None
    return {
        "status": "stopped",
        "pid": pid,
        "process_start_time": process_start,
        "process": "pid-reused" if process_state == "mismatch" else "absent",
        "control_group": control_group,
    }


def stop_authority_service_bounded(
    runner: Runner,
    *,
    cgroup_root: Path = CGROUP_ROOT,
    process_start_reader: Callable[[int], str | None] = read_process_start_time,
    process_observer: Callable[[int, str], str] = observe_worker_process_identity,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
    grace_seconds: float = AUTHORITY_STOP_GRACE_SECONDS,
) -> dict[str, object]:
    """Stop the fixed authority unit without inheriting its 65-minute wait."""

    if (
        not isinstance(grace_seconds, (int, float))
        or isinstance(grace_seconds, bool)
        or not 0.1 <= float(grace_seconds) <= 30.0
    ):
        raise SwitchError("authority stop grace must be from 0.1 through 30 seconds")
    before = _writer_unit_state(runner, AUTHORITY_SERVICE)
    if before["active"] is not True:
        control_group = before.get("control_group")
        if isinstance(control_group, str) and _writer_cgroup_populated(
            control_group, cgroup_root=cgroup_root, allow_missing=True
        ):
            raise SwitchError("inactive authority retained a populated cgroup")
        return {
            "status": "inactive",
            "process": "not-running",
            "control_group": control_group,
        }
    pid = before.get("pid")
    control_group = before.get("control_group")
    if (
        type(pid) is not int
        or pid <= 1
        or not isinstance(control_group, str)
        or not _writer_cgroup_populated(
            control_group, cgroup_root=cgroup_root, allow_missing=False
        )
    ):
        raise SwitchError("active authority identity is incomplete")
    try:
        process_start = process_start_reader(pid)
    except (OSError, RuntimeError, ValueError) as error:
        raise SwitchError("authority process start identity is unavailable") from error
    if not isinstance(process_start, str) or not process_start:
        raise SwitchError("authority process start identity is unavailable")
    confirmed = _writer_unit_state(runner, AUTHORITY_SERVICE)
    if (
        confirmed.get("active") is not True
        or confirmed.get("pid") != pid
        or confirmed.get("control_group") != control_group
    ):
        raise SwitchError("authority identity changed before bounded stop")

    requested = _bounded_systemctl(
        runner,
        ["/usr/bin/systemctl", "--no-block", "stop", AUTHORITY_SERVICE],
        label="request bounded authority stop",
    )
    if not requested:
        terminal = _authority_terminal_proof(
            runner,
            pid=pid,
            process_start=process_start,
            control_group=control_group,
            cgroup_root=cgroup_root,
            process_observer=process_observer,
        )
        if terminal is not None:
            return terminal
        raise SwitchError("bounded authority stop reply failed before terminal proof")
    observed = _wait_writers_inactive(
        runner,
        units=(AUTHORITY_SERVICE,),
        timeout_seconds=grace_seconds,
        clock=clock,
        sleeper=sleeper,
        raise_on_timeout=False,
    )[AUTHORITY_SERVICE]
    for signal_name in ("TERM", "KILL"):
        if observed["active"] is not True:
            break
        signalled = _bounded_systemctl(
            runner,
            [
                "/usr/bin/systemctl",
                "kill",
                "--kill-whom=all",
                f"--signal={signal_name}",
                AUTHORITY_SERVICE,
            ],
            label=f"bounded authority {signal_name}",
        )
        if not signalled:
            terminal = _authority_terminal_proof(
                runner,
                pid=pid,
                process_start=process_start,
                control_group=control_group,
                cgroup_root=cgroup_root,
                process_observer=process_observer,
            )
            if terminal is not None:
                return terminal
            raise SwitchError(
                f"bounded authority {signal_name} failed before terminal proof"
            )
        observed = _wait_writers_inactive(
            runner,
            units=(AUTHORITY_SERVICE,),
            timeout_seconds=grace_seconds,
            clock=clock,
            sleeper=sleeper,
            raise_on_timeout=False,
        )[AUTHORITY_SERVICE]
    if observed["active"] is True:
        raise SwitchError("authority remained active after bounded KILL")
    terminal = _authority_terminal_proof(
        runner,
        pid=pid,
        process_start=process_start,
        control_group=control_group,
        cgroup_root=cgroup_root,
        process_observer=process_observer,
    )
    if terminal is None:
        raise SwitchError("authority process absence is unproven")
    return terminal


def _require_stable_authority_evidence(
    runner: Runner,
    evidence: Mapping[str, object],
    *,
    cgroup_root: Path,
    process_observer: Callable[[int, str], str],
) -> None:
    control_group = evidence.get("control_group")
    if isinstance(control_group, str) and _writer_cgroup_populated(
        control_group, cgroup_root=cgroup_root, allow_missing=True
    ):
        raise SwitchError("authority cgroup repopulated after stop")
    if evidence.get("pid") is not None and _authority_terminal_proof(
        runner,
        pid=int(evidence["pid"]),
        process_start=str(evidence["process_start_time"]),
        control_group=str(control_group),
        cgroup_root=cgroup_root,
        process_observer=process_observer,
    ) is None:
        raise SwitchError("authority terminal proof was not stable")


def stop_authority_writers(
    runner: Runner,
    *,
    cgroup_root: Path = CGROUP_ROOT,
    process_start_reader: Callable[[int], str | None] = read_process_start_time,
    process_observer: Callable[[int, str], str] = observe_worker_process_identity,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
    settle_seconds: float = WRITER_STOP_SETTLE_SECONDS,
) -> None:
    """Quiesce authority writers plus testd/snapshotd direct-generation readers."""

    if (
        not isinstance(settle_seconds, (int, float))
        or isinstance(settle_seconds, bool)
        or not 0.1 <= float(settle_seconds) <= 60.0
    ):
        raise SwitchError("writer settle timeout must be from 0.1 through 60 seconds")
    authority_evidence: dict[str, object] | None = None
    retained_service_cgroups: dict[str, str] = {}
    for unit in AUTHORITY_WRITER_UNITS:
        if unit == AUTHORITY_SERVICE:
            authority_evidence = stop_authority_service_bounded(
                runner,
                cgroup_root=cgroup_root,
                process_start_reader=process_start_reader,
                process_observer=process_observer,
                clock=clock,
                sleeper=sleeper,
            )
            continue
        before = _writer_unit_state(runner, unit)
        if unit.endswith(".service"):
            control_group = before.get("control_group")
            if before["active"] is True and not isinstance(control_group, str):
                raise SwitchError("active writer service has no control group: " + unit)
            if isinstance(control_group, str):
                retained_service_cgroups[unit] = control_group
        if before["active"] is not True:
            continue
        requested = _bounded_systemctl(
            runner,
            ["/usr/bin/systemctl", "--no-block", "stop", unit],
            label="request bounded writer stop",
        )
        if not requested and _writer_unit_state(runner, unit)["active"] is True:
            raise SwitchError("bounded writer stop failed before terminal proof: " + unit)

    first = _wait_writers_inactive(
        runner,
        units=AUTHORITY_WRITER_UNITS,
        timeout_seconds=settle_seconds,
        clock=clock,
        sleeper=sleeper,
    )
    if authority_evidence is not None:
        _require_stable_authority_evidence(
            runner,
            authority_evidence,
            cgroup_root=cgroup_root,
            process_observer=process_observer,
        )
    for unit, control_group in retained_service_cgroups.items():
        if unit != AUTHORITY_SERVICE and _writer_cgroup_populated(
            control_group, cgroup_root=cgroup_root, allow_missing=True
        ):
            raise SwitchError("writer service cgroup remained populated: " + unit)
    sleeper(WRITER_STABLE_INACTIVE_SECONDS)
    second = {
        unit: _writer_unit_state(runner, unit) for unit in AUTHORITY_WRITER_UNITS
    }
    restarted = sorted(
        unit for unit, state in second.items() if state["active"] is True
    )
    if restarted:
        raise SwitchError("authority writer restarted after stop: " + ", ".join(restarted))
    if canonical(first) != canonical(second):
        raise SwitchError("authority writer inactive state changed after stop")
    if authority_evidence is not None:
        _require_stable_authority_evidence(
            runner,
            authority_evidence,
            cgroup_root=cgroup_root,
            process_observer=process_observer,
        )
    for unit, control_group in retained_service_cgroups.items():
        if unit != AUTHORITY_SERVICE and _writer_cgroup_populated(
            control_group, cgroup_root=cgroup_root, allow_missing=True
        ):
            raise SwitchError("writer service cgroup repopulated after stop: " + unit)


def loaded_managed_worker_ids(runner: Runner) -> tuple[str, ...]:
    """Enumerate only exact managed-worker registrations, without mutation."""

    output = runner.require(
        [
            "/usr/bin/systemctl",
            "list-units",
            "--all",
            "--type=service",
            "--no-legend",
            "--plain",
            "devcoordinator-worker-*.service",
        ],
        "list managed worker units",
    )
    if len(output.encode("utf-8")) > 1024 * 1024:
        raise SwitchError("managed worker unit inventory is excessive")
    worker_ids: set[str] = set()
    for index, line in enumerate(output.splitlines()):
        if index >= WORKER_CUTOVER_LIMIT:
            raise SwitchError("managed worker unit inventory is excessive")
        fields = line.split()
        if not fields:
            continue
        unit = fields[1] if fields[0] == "●" and len(fields) > 1 else fields[0]
        if not unit.startswith("devcoordinator-worker-"):
            continue
        matched = WORKER_UNIT.fullmatch(unit)
        if matched is None:
            raise SwitchError(
                "managed worker unit inventory contains an invalid identity"
            )
        try:
            worker_id = str(uuid.UUID(matched.group(1)))
        except ValueError as error:
            raise SwitchError("managed worker unit identity is invalid") from error
        if unit != f"devcoordinator-worker-{worker_id}.service":
            raise SwitchError("managed worker unit identity is not canonical")
        worker_ids.add(worker_id)
    return tuple(sorted(worker_ids))


def require_no_managed_worker_units(runner: Runner) -> None:
    worker_ids = loaded_managed_worker_ids(runner)
    if worker_ids:
        raise SwitchError(
            "schema rebaseline requires these managed workers to stop first: "
            + ", ".join(worker_ids)
        )


def _read_source_worker_state(runner: Runner) -> dict[str, object]:
    """Read one bounded schema-15 worker snapshot without changing it."""

    unit_ids_before = loaded_managed_worker_ids(runner)
    try:
        connection = sqlite3.connect(
            f"{AUTHORITY_DATABASE.as_uri()}?mode=ro", uri=True, timeout=10.0
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            metadata = connection.execute(
                "SELECT schema_version,database_generation,state_revision "
                "FROM schema_metadata WHERE singleton=1"
            ).fetchone()
            policies = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT definition.server_definition_id,
                           definition.generation AS definition_generation,
                           definition.definition_fingerprint,
                           policy.generation AS policy_generation,
                           policy.repo_id,policy.execution_uid,policy.keep_alive,
                           policy.desired_state,policy.breaker_state
                    FROM worker_policies policy
                    JOIN server_definitions definition USING(server_definition_id)
                    ORDER BY definition.server_definition_id
                    """
                )
            ]
            supervisors = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT server_definition_id,state,supervisor_epoch,
                           supervisor_generation,current_attempt_id
                    FROM worker_supervisor_states
                    ORDER BY server_definition_id
                    """
                )
            ]
            attempts = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT attempt_id,server_definition_id,state,
                           definition_generation,policy_generation,
                           supervisor_generation,supervisor_epoch,pid,
                           process_start_time,process_fingerprint
                    FROM worker_attempts
                    WHERE state IN ('reserved','running')
                    ORDER BY server_definition_id,attempt_id
                    """
                )
            ]
            observations = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT policy.server_definition_id,
                           observation.lifecycle,observation.pid,
                           observation.process_start_time,
                           observation.process_fingerprint,
                           observation.listener_observable,
                           observation.health_classification,
                           observation.health_ok
                    FROM worker_policies policy
                    LEFT JOIN server_observations observation USING(server_definition_id)
                    ORDER BY policy.server_definition_id
                    """
                )
            ]
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise SwitchError("source worker quiescence cannot be read") from error
    if (
        metadata is None
        or metadata["schema_version"] != retained_control.REBASELINE_SOURCE_SCHEMA
        or not isinstance(metadata["database_generation"], str)
        or not metadata["database_generation"]
        or type(metadata["state_revision"]) is not int
        or int(metadata["state_revision"]) < 0
    ):
        raise SwitchError("source worker quiescence has incompatible authority identity")
    if any(
        len(values) > WORKER_CUTOVER_LIMIT
        for values in (policies, supervisors, attempts, observations)
    ):
        raise SwitchError("source worker quiescence is excessive")

    def canonical_worker_id(value: object) -> str:
        try:
            parsed = str(uuid.UUID(str(value)))
        except (ValueError, TypeError, AttributeError) as error:
            raise SwitchError("source worker identity is invalid") from error
        if parsed != value:
            raise SwitchError("source worker identity is not canonical")
        return parsed

    policy_ids: set[str] = set()
    for row in policies:
        worker_id = canonical_worker_id(row["server_definition_id"])
        if (
            worker_id in policy_ids
            or type(row["execution_uid"]) is not int
            or int(row["execution_uid"]) <= 0
            or type(row["definition_generation"]) is not int
            or type(row["policy_generation"]) is not int
        ):
            raise SwitchError("source worker policy evidence is invalid")
        policy_ids.add(worker_id)
    supervisor_ids = {
        canonical_worker_id(row["server_definition_id"])
        for row in supervisors
    }
    if supervisor_ids != policy_ids or len(supervisor_ids) != len(supervisors):
        raise SwitchError("source worker supervisor coverage is invalid")
    observation_ids = {
        canonical_worker_id(row["server_definition_id"])
        for row in observations
    }
    if observation_ids != policy_ids or len(observation_ids) != len(observations):
        raise SwitchError("source worker observation coverage is invalid")
    for row in attempts:
        canonical_worker_id(row["server_definition_id"])
        state = str(row["state"])
        pid = row["pid"]
        started = row["process_start_time"]
        if (
            (state == "reserved" and (pid is not None or started is not None))
            or (
                state == "running"
                and (
                    type(pid) is not int
                    or int(pid) <= 1
                    or not isinstance(started, str)
                    or not started
                )
            )
        ):
            raise SwitchError("source worker attempt evidence is invalid")
    attempt_by_id = {str(row["attempt_id"]): row for row in attempts}
    if len(attempt_by_id) != len(attempts):
        raise SwitchError("source worker attempt identity is duplicated")
    attempt_by_worker = {
        str(row["server_definition_id"]): row for row in attempts
    }
    if len(attempt_by_worker) != len(attempts):
        raise SwitchError("source worker has multiple current attempts")
    current_attempt_ids = {
        str(row["current_attempt_id"])
        for row in supervisors
        if row["current_attempt_id"] is not None
    }
    if current_attempt_ids != set(attempt_by_id):
        raise SwitchError("source worker current-attempt coverage is invalid")
    for row in supervisors:
        state = str(row["state"])
        current_attempt_id = row["current_attempt_id"]
        if (
            state in {"launching", "running", "stopping"}
            and current_attempt_id is None
        ):
            raise SwitchError("source worker active supervisor identity is incomplete")
    for row in observations:
        lifecycle = str(row["lifecycle"])
        pid = row["pid"]
        started = row["process_start_time"]
        active_observation = (
            pid is not None
            or lifecycle in {"starting", "running", "unhealthy", "stopping"}
        )
        if active_observation and (
            type(pid) is not int
            or int(pid) <= 1
            or not isinstance(started, str)
            or not started
        ):
            raise SwitchError("source worker observation identity is incomplete")
        if active_observation:
            attempt = attempt_by_worker.get(str(row["server_definition_id"]))
            if (
                attempt is None
                or attempt.get("state") != "running"
                or attempt.get("pid") != pid
                or attempt.get("process_start_time") != started
                or attempt.get("process_fingerprint")
                != row.get("process_fingerprint")
            ):
                raise SwitchError(
                    "source worker observation is not bound to its current attempt"
                )

    unit_ids_after = loaded_managed_worker_ids(runner)
    if unit_ids_before != unit_ids_after:
        raise SwitchError("source worker unit inventory changed while observed")
    active_supervisors = sorted(
        str(row["server_definition_id"])
        for row in supervisors
        if row["current_attempt_id"] is not None
        or str(row["state"]) in {"launching", "running", "stopping"}
    )
    active_attempts = sorted(
        str(row["server_definition_id"]) for row in attempts
    )
    active_observations = sorted(
        str(row["server_definition_id"])
        for row in observations
        if row["pid"] is not None
        or str(row["lifecycle"])
        in {"starting", "running", "unhealthy", "stopping"}
    )
    return {
        "metadata": dict(metadata),
        "policies": policies,
        "supervisors": supervisors,
        "attempts": attempts,
        "observations": observations,
        "worker_units": list(unit_ids_after),
        "active_supervisors": active_supervisors,
        "active_attempts": active_attempts,
        "active_observations": active_observations,
    }


def _terminal_process_state(
    observer: Callable[[int, str], str], pid: int, process_start_time: str
) -> str:
    try:
        state = observer(pid, process_start_time)
    except (OSError, RuntimeError, ValueError) as error:
        raise SwitchError("source worker process identity is unobservable") from error
    if state not in {"absent", "mismatch"}:
        raise SwitchError("source worker process absence is unproven")
    return state


def _require_quiesced_cgroup_empty(
    control_group: object, *, cgroup_root: Path
) -> None:
    if control_group is None:
        return
    if (
        not isinstance(control_group, str)
        or not control_group.startswith("/")
        or "\x00" in control_group
        or any(part in {"", ".", ".."} for part in control_group.split("/")[1:])
    ):
        raise SwitchError("source worker cgroup identity is invalid")
    events = cgroup_root.joinpath(*control_group.split("/")[1:]) / "cgroup.events"
    try:
        info = events.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise SwitchError("source worker cgroup evidence is unavailable") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SwitchError("source worker cgroup evidence is unsafe")
    try:
        payload = events.read_bytes()
    except OSError as error:
        raise SwitchError("source worker cgroup evidence is unavailable") from error
    if len(payload) > 4096:
        raise SwitchError("source worker cgroup evidence is excessive")
    try:
        values = dict(
            line.split(" ", 1)
            for line in payload.decode("ascii").splitlines()
            if " " in line
        )
    except UnicodeDecodeError as error:
        raise SwitchError("source worker cgroup evidence is invalid") from error
    if values.get("populated") not in {"0", "1"}:
        raise SwitchError("source worker cgroup evidence is invalid")
    if values["populated"] != "0":
        raise SwitchError("source worker cgroup remained populated")


def _absent_worker_receipt(policy: Mapping[str, object]) -> dict[str, object]:
    worker_id = str(policy["server_definition_id"])
    return {
        "worker_id": worker_id,
        "execution_uid": int(policy["execution_uid"]),
        "repository_id": str(policy["repo_id"]),
        "definition_generation": int(policy["definition_generation"]),
        "policy_generation": int(policy["policy_generation"]),
        "unit": f"devcoordinator-worker-{worker_id}.service",
        "expected_slice": None,
        "loaded_before": False,
        "active_before": False,
        "runner_pid_before": None,
        "control_group": None,
        "cgroup_populated_before": None,
        "removal_reply": "complete",
        "unit_unloaded": True,
        "cgroup_empty": True,
        "process_proofs": [],
    }


def source_worker_policy_expectations(runner: Runner) -> dict[str, object]:
    """Capture the retained schema-15 policy set without requiring quiescence."""

    state = _read_source_worker_state(runner)
    policies = list(state["policies"])
    return {
        "policy_expectations": policies,
        "policy_count": len(policies),
    }


def source_worker_quiescence_proof(
    runner: Runner,
    *,
    quiesced_workers: object = None,
    process_observer: Callable[[int, str], str] = observe_worker_process_identity,
    cgroup_root: Path = CGROUP_ROOT,
) -> dict[str, object]:
    """Prove schema-15 workers are absent while retaining policy unchanged."""

    state = _read_source_worker_state(runner)
    policies = list(state["policies"])
    if quiesced_workers is None:
        if (
            state["worker_units"]
            or state["active_supervisors"]
            or state["active_attempts"]
            or state["active_observations"]
        ):
            blockers = sorted(
                {
                    *state["worker_units"],
                    *state["active_supervisors"],
                    *state["active_attempts"],
                    *state["active_observations"],
                }
            )
            raise SwitchError(
                "schema rebaseline has unquiesced managed workers: "
                + ", ".join(blockers)
            )
        receipts = [_absent_worker_receipt(policy) for policy in policies]
    else:
        receipts = [dict(value) for value in quiesced_workers] if isinstance(
            quiesced_workers, list
        ) and all(isinstance(value, Mapping) for value in quiesced_workers) else []
        if not _valid_quiesced_workers(receipts, expected_policies=policies):
            raise SwitchError("source worker quiescence receipt is invalid")

    policy_ids = {str(row["server_definition_id"]) for row in policies}
    loaded = set(state["worker_units"])
    if loaded:
        raise SwitchError(
            "schema rebaseline retained managed worker registrations: "
            + ", ".join(sorted(loaded))
        )
    receipt_by_id = {str(row["worker_id"]): row for row in receipts}
    if set(receipt_by_id) != policy_ids:
        raise SwitchError("source worker quiescence coverage changed")
    for receipt in receipts:
        _require_quiesced_cgroup_empty(
            receipt.get("control_group"), cgroup_root=cgroup_root
        )

    proof_identities = {
        str(receipt["worker_id"]): {
            (int(item["pid"]), str(item["process_start_time"]))
            for item in receipt["process_proofs"]
        }
        for receipt in receipts
    }
    for row in [*state["attempts"], *state["observations"]]:
        worker_id = str(row["server_definition_id"])
        pid = row.get("pid")
        started = row.get("process_start_time")
        if pid is None:
            continue
        exact = (int(pid), str(started))
        if exact not in proof_identities.get(worker_id, set()):
            raise SwitchError("source worker process proof coverage is incomplete")
        _terminal_process_state(process_observer, exact[0], exact[1])

    metadata = state["metadata"]
    state_document = {
        "policies": policies,
        "supervisors": state["supervisors"],
        "current_attempts": state["attempts"],
        "worker_observations": state["observations"],
    }
    return {
        "schema_version": int(metadata["schema_version"]),
        "database_generation": str(metadata["database_generation"]),
        "state_revision": int(metadata["state_revision"]),
        "worker_units": [],
        "active_supervisors": [],
        "current_attempts": [],
        "active_observations": [],
        "policy_expectations": policies,
        "quiesced_workers": receipts,
        "policy_count": len(policies),
        "supervisor_count": len(state["supervisors"]),
        "observation_count": len(state["observations"]),
        "worker_state_sha256": hashlib.sha256(
            canonical(state_document)
        ).hexdigest(),
    }


def _valid_policy_expectations(value: object, *, expected_count: object) -> bool:
    if (
        not isinstance(value, list)
        or type(expected_count) is not int
        or len(value) != expected_count
        or len(value) > WORKER_CUTOVER_LIMIT
    ):
        return False
    seen: set[str] = set()
    expected_fields = {
        "server_definition_id",
        "definition_generation",
        "definition_fingerprint",
        "policy_generation",
        "repo_id",
        "execution_uid",
        "keep_alive",
        "desired_state",
        "breaker_state",
    }
    for row in value:
        if not isinstance(row, Mapping) or set(row) != expected_fields:
            return False
        try:
            worker_id = str(uuid.UUID(str(row["server_definition_id"])))
        except (ValueError, TypeError, AttributeError):
            return False
        if (
            worker_id != row["server_definition_id"]
            or worker_id in seen
            or type(row["definition_generation"]) is not int
            or int(row["definition_generation"]) < 0
            or type(row["policy_generation"]) is not int
            or int(row["policy_generation"]) < 0
            or not isinstance(row["definition_fingerprint"], str)
            or not row["definition_fingerprint"]
            or len(row["definition_fingerprint"].encode("utf-8")) > 512
            or type(row["execution_uid"]) is not int
            or int(row["execution_uid"]) <= 0
            or row["keep_alive"] not in {0, 1}
            or row["desired_state"] not in {"running", "stopped"}
            or row["breaker_state"] not in {"armed", "tripped"}
        ):
            return False
        seen.add(worker_id)
    return True


def _valid_quiesced_workers(
    value: object, *, expected_policies: object
) -> bool:
    if (
        not isinstance(value, list)
        or not isinstance(expected_policies, list)
        or len(value) != len(expected_policies)
        or len(value) > WORKER_CUTOVER_LIMIT
    ):
        return False
    policies = {
        str(row.get("server_definition_id")): row
        for row in expected_policies
        if isinstance(row, Mapping)
    }
    if len(policies) != len(expected_policies):
        return False
    expected_fields = {
        "worker_id",
        "execution_uid",
        "repository_id",
        "definition_generation",
        "policy_generation",
        "unit",
        "expected_slice",
        "loaded_before",
        "active_before",
        "runner_pid_before",
        "control_group",
        "cgroup_populated_before",
        "removal_reply",
        "unit_unloaded",
        "cgroup_empty",
        "process_proofs",
    }
    seen: set[str] = set()
    for receipt in value:
        if not isinstance(receipt, Mapping) or set(receipt) != expected_fields:
            return False
        worker_id = receipt.get("worker_id")
        policy = policies.get(str(worker_id))
        try:
            canonical_id = str(uuid.UUID(str(worker_id)))
        except (ValueError, TypeError, AttributeError):
            return False
        if (
            canonical_id != worker_id
            or worker_id in seen
            or policy is None
            or receipt.get("execution_uid") != policy.get("execution_uid")
            or receipt.get("repository_id") != policy.get("repo_id")
            or receipt.get("definition_generation")
            != policy.get("definition_generation")
            or receipt.get("policy_generation") != policy.get("policy_generation")
            or receipt.get("unit")
            != f"devcoordinator-worker-{worker_id}.service"
            or type(receipt.get("loaded_before")) is not bool
            or type(receipt.get("active_before")) is not bool
            or receipt.get("active_before") is True
            and receipt.get("loaded_before") is not True
            or receipt.get("unit_unloaded") is not True
            or receipt.get("cgroup_empty") is not True
            or receipt.get("removal_reply") not in {"complete", "reconciled"}
        ):
            return False
        expected_slice = receipt.get("expected_slice")
        if expected_slice is not None and (
            not isinstance(expected_slice, str)
            or not expected_slice
            or len(expected_slice.encode("utf-8")) > 512
            or any(character in expected_slice for character in "\x00\r\n")
        ):
            return False
        if receipt.get("loaded_before") is True:
            if expected_slice != project_repository_slice(
                uid=int(receipt["execution_uid"]),
                repository_id=str(receipt["repository_id"]),
            ):
                return False
        elif expected_slice is not None:
            return False
        runner_pid = receipt.get("runner_pid_before")
        if runner_pid is not None and (type(runner_pid) is not int or runner_pid <= 1):
            return False
        control_group = receipt.get("control_group")
        if control_group is not None and (
            not isinstance(control_group, str)
            or not control_group.startswith("/")
            or "\x00" in control_group
            or any(part in {"", ".", ".."} for part in control_group.split("/")[1:])
        ):
            return False
        populated_before = receipt.get("cgroup_populated_before")
        if populated_before is not None and type(populated_before) is not bool:
            return False
        processes = receipt.get("process_proofs")
        if not isinstance(processes, list) or len(processes) > 8:
            return False
        identities: set[tuple[int, str]] = set()
        for process in processes:
            if not isinstance(process, Mapping) or set(process) != {
                "pid",
                "process_start_time",
                "state",
            }:
                return False
            pid = process.get("pid")
            started = process.get("process_start_time")
            if (
                type(pid) is not int
                or pid <= 1
                or not isinstance(started, str)
                or not started
                or len(started.encode("utf-8")) > 256
                or any(character in started for character in "\x00\r\n")
                or process.get("state") not in {"absent", "pid_reused"}
                or (pid, started) in identities
            ):
                return False
            identities.add((pid, started))
        seen.add(str(worker_id))
    return seen == set(policies)


def _valid_source_worker_quiescence(value: object) -> bool:
    return bool(
        isinstance(value, Mapping)
        and set(value)
        == {
            "schema_version",
            "database_generation",
            "state_revision",
            "worker_units",
            "active_supervisors",
            "current_attempts",
            "active_observations",
            "policy_expectations",
            "quiesced_workers",
            "policy_count",
            "supervisor_count",
            "observation_count",
            "worker_state_sha256",
        }
        and value.get("schema_version")
        == retained_control.REBASELINE_SOURCE_SCHEMA
        and isinstance(value.get("database_generation"), str)
        and bool(value.get("database_generation"))
        and all(value.get(field) == [] for field in (
            "worker_units",
            "active_supervisors",
            "current_attempts",
            "active_observations",
        ))
        and _valid_policy_expectations(
            value.get("policy_expectations"),
            expected_count=value.get("policy_count"),
        )
        and _valid_quiesced_workers(
            value.get("quiesced_workers"),
            expected_policies=value.get("policy_expectations"),
        )
        and all(
            type(value.get(field)) is int and int(value[field]) >= 0
            for field in (
                "state_revision",
                "policy_count",
                "supervisor_count",
                "observation_count",
            )
        )
        and value.get("supervisor_count") == value.get("policy_count")
        and value.get("observation_count") == value.get("policy_count")
        and re.fullmatch(
            r"[0-9a-f]{64}", str(value.get("worker_state_sha256") or "")
        )
        is not None
    )


def quiesce_source_workers(
    document: Mapping[str, object],
    runner: Runner,
    *,
    process_observer: Callable[[int, str], str] = observe_worker_process_identity,
    cgroup_root: Path = CGROUP_ROOT,
) -> dict[str, object]:
    """Stop exact schema-15 runners while leaving retained policy untouched."""

    before = _read_source_worker_state(runner)
    policies = list(before["policies"])
    policy_ids = {str(row["server_definition_id"]) for row in policies}
    loaded = set(before["worker_units"])
    unattributed = sorted(loaded - policy_ids)
    if unattributed:
        raise SwitchError(
            "schema rebaseline found managed units without retained policy: "
            + ", ".join(unattributed)
        )
    attempts_by_worker: dict[str, list[dict[str, object]]] = {}
    for row in before["attempts"]:
        attempts_by_worker.setdefault(
            str(row["server_definition_id"]), []
        ).append(dict(row))
    script = _candidate_coordinator_script(document)
    manager_factory = _worker_native_factory(runner)
    receipts: list[dict[str, object]] = []
    for policy in policies:
        worker_id = str(policy["server_definition_id"])
        identities: list[dict[str, object]] = []
        for row in attempts_by_worker.get(worker_id, []):
            if row.get("pid") is not None:
                identities.append(
                    {
                        "pid": int(row["pid"]),
                        "process_start_time": str(row["process_start_time"]),
                    }
                )
        manager = manager_factory(coordinator_script=script, state_root=None)
        try:
            receipt = quiesce_worker_registration(
                manager=manager,
                worker_id=worker_id,
                execution_uid=int(policy["execution_uid"]),
                repository_id=str(policy["repo_id"]),
                process_identities=identities,
                timeout_seconds=45.0,
                observer=process_observer,
            )
        except (WorkerControlError, WorkerNativeError, OSError) as error:
            raise SwitchError(
                "schema rebaseline could not quiesce managed worker " + worker_id
            ) from error
        receipt.update(
            {
                "definition_generation": int(policy["definition_generation"]),
                "policy_generation": int(policy["policy_generation"]),
            }
        )
        receipts.append(receipt)

    proof = source_worker_quiescence_proof(
        runner,
        quiesced_workers=receipts,
        process_observer=process_observer,
        cgroup_root=cgroup_root,
    )
    if proof["policy_expectations"] != policies:
        raise SwitchError("source worker policy changed during release quiescence")
    return proof


def bind_source_worker_quiescence(
    document: dict[str, object],
    intent: dict[str, object],
    journal_path: Path,
    runner: Runner,
    *,
    process_observer: Callable[[int, str], str] = observe_worker_process_identity,
    cgroup_root: Path = CGROUP_ROOT,
) -> dict[str, object]:
    retained = intent.get("source_worker_quiescence")
    if retained is None:
        observed = quiesce_source_workers(
            document,
            runner,
            process_observer=process_observer,
            cgroup_root=cgroup_root,
        )
        intent["source_worker_quiescence"] = observed
        document["retained_control_rebaseline"] = intent
        save_phase(journal_path, document, str(document["phase"]))
        return observed
    if not _valid_source_worker_quiescence(retained):
        raise SwitchError("source worker quiescence journal proof is invalid")
    try:
        observed = source_worker_quiescence_proof(
            runner,
            quiesced_workers=retained["quiesced_workers"],
            process_observer=process_observer,
            cgroup_root=cgroup_root,
        )
    except SwitchError as error:
        raise SwitchError(
            "source worker quiescence changed before schema rebaseline"
        ) from error
    if dict(retained) != observed:
        raise SwitchError(
            "source worker quiescence changed before schema rebaseline"
        )
    return dict(retained)


def _managed_worker_native_state(
    runner: Runner,
    worker_id: str,
    *,
    cgroup_root: Path = CGROUP_ROOT,
) -> dict[str, object]:
    try:
        canonical_id = str(uuid.UUID(worker_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise SwitchError("credentialized worker identity is invalid") from error
    if canonical_id != worker_id:
        raise SwitchError("credentialized worker identity is not canonical")
    unit = f"devcoordinator-worker-{worker_id}.service"
    completed = runner.run(
        [
            "/usr/bin/systemctl",
            "show",
            unit,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=MainPID",
            "--property=ControlGroup",
            "--property=Slice",
            "--no-pager",
        ]
    )
    if len((completed.stdout + completed.stderr).encode("utf-8")) > 64 * 1024:
        raise SwitchError("credentialized worker native evidence is excessive")
    values = {
        key: value
        for line in completed.stdout.splitlines()
        if "=" in line
        for key, value in (line.split("=", 1),)
    }
    if completed.returncode != 0 or values.get("LoadState") == "not-found":
        return {
            "loaded": False,
            "active": False,
            "main_pid": None,
            "control_group": None,
            "slice": None,
            "cgroup_populated": False,
        }
    required = {
        "LoadState",
        "ActiveState",
        "SubState",
        "MainPID",
        "ControlGroup",
        "Slice",
    }
    if set(values) != required or values["LoadState"] != "loaded":
        raise SwitchError("credentialized worker native evidence is incomplete")
    active = values["ActiveState"] in {
        "active",
        "activating",
        "deactivating",
        "reloading",
    }
    raw_pid = values["MainPID"]
    main_pid = int(raw_pid) if raw_pid.isdigit() and int(raw_pid) > 1 else None
    control_group = values["ControlGroup"]
    if (
        not control_group.startswith("/")
        or "\x00" in control_group
        or any(part in {"", ".", ".."} for part in control_group.split("/")[1:])
    ):
        raise SwitchError("credentialized worker control group is invalid")
    events = cgroup_root.joinpath(*control_group.split("/")[1:]) / "cgroup.events"
    try:
        info = events.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
            raise SwitchError("credentialized worker cgroup evidence is unsafe")
        event_values = dict(
            line.split(" ", 1)
            for line in events.read_text(encoding="ascii").splitlines()
            if " " in line
        )
    except OSError as error:
        raise SwitchError("credentialized worker cgroup evidence is unavailable") from error
    if event_values.get("populated") not in {"0", "1"}:
        raise SwitchError("credentialized worker cgroup evidence is invalid")
    return {
        "loaded": True,
        "active": active,
        "main_pid": main_pid,
        "control_group": control_group,
        "slice": values["Slice"],
        "cgroup_populated": event_values["populated"] == "1",
    }


def _credentialized_worker_rows() -> tuple[
    dict[str, dict[str, object]], dict[str, set[tuple[str, str]]]
]:
    try:
        connection = sqlite3.connect(
            f"{AUTHORITY_DATABASE.as_uri()}?mode=ro", uri=True, timeout=10.0
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            rows = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT definition.server_definition_id,definition.name,
                           definition.repo_id,
                           definition.generation AS definition_generation,
                           repository.canonical_root,
                           policy.execution_uid,policy.keep_alive,
                           policy.desired_state,policy.breaker_state,
                           policy.generation AS policy_generation,
                           supervisor.state AS supervisor_state,
                           supervisor.supervisor_epoch,
                           supervisor.supervisor_generation,
                           supervisor.current_attempt_id,
                           attempt.state AS attempt_state,attempt.pid AS attempt_pid,
                           attempt.process_start_time AS attempt_process_start_time,
                           attempt.process_fingerprint AS attempt_process_fingerprint,
                           attempt.definition_generation AS attempt_definition_generation,
                           attempt.policy_generation AS attempt_policy_generation,
                           attempt.supervisor_generation AS attempt_supervisor_generation,
                           attempt.supervisor_epoch AS attempt_supervisor_epoch
                    FROM server_definitions definition
                    JOIN repositories repository USING(repo_id)
                    LEFT JOIN worker_policies policy USING(server_definition_id)
                    LEFT JOIN worker_supervisor_states supervisor USING(server_definition_id)
                    LEFT JOIN worker_attempts attempt
                      ON attempt.attempt_id=supervisor.current_attempt_id
                    WHERE EXISTS (
                        SELECT 1 FROM server_environment_credentials credential
                        WHERE credential.server_definition_id=definition.server_definition_id
                    )
                    ORDER BY definition.server_definition_id
                    """
                )
            ]
            binding_rows = list(
                connection.execute(
                    """
                    SELECT server_definition_id,name,credential_id
                    FROM server_environment_credentials
                    ORDER BY server_definition_id,name
                    """
                )
            )
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise SwitchError("credentialized worker convergence cannot be read") from error
    if (
        len(rows) > WORKER_CUTOVER_LIMIT
        or len(binding_rows) > retained_control.MAX_ROWS_PER_COLLECTION
    ):
        raise SwitchError("credentialized worker convergence is excessive")
    by_id = {str(row["server_definition_id"]): row for row in rows}
    if len(by_id) != len(rows):
        raise SwitchError("credentialized worker convergence is duplicated")
    bindings: dict[str, set[tuple[str, str]]] = {}
    for row in binding_rows:
        bindings.setdefault(str(row["server_definition_id"]), set()).add(
            (str(row["name"]), str(row["credential_id"]))
        )
    return by_id, bindings


def _credentialized_worker_blockers(
    manifest: Mapping[str, object],
    transaction_root: Path,
    runner: Runner,
    *,
    source_proof: Mapping[str, object],
    cgroup_root: Path = CGROUP_ROOT,
    process_observer: Callable[[int, str], str] = observe_worker_process_identity,
    observed_state: tuple[
        dict[str, dict[str, object]], dict[str, set[tuple[str, str]]]
    ] | None = None,
) -> tuple[tuple[str, ...], str]:
    credentials = _server_credentials_from_manifest(manifest, transaction_root)
    expected_bindings: dict[str, set[tuple[str, str]]] = {}
    for credential_id, value in credentials.items():
        expected_bindings.setdefault(
            str(value["server_definition_id"]), set()
        ).add((str(value["name"]), credential_id))
    rows, retained_bindings = (
        _credentialized_worker_rows() if observed_state is None else observed_state
    )
    loaded = set(loaded_managed_worker_ids(runner))
    raw_expectations = source_proof.get("policy_expectations")
    if not isinstance(raw_expectations, list):
        raise SwitchError("credentialized worker source expectations are invalid")
    source_expectations = {
        str(value["server_definition_id"]): value
        for value in raw_expectations
        if isinstance(value, Mapping)
        and isinstance(value.get("server_definition_id"), str)
    }
    if len(source_expectations) != len(raw_expectations):
        raise SwitchError("credentialized worker source expectations are invalid")
    blockers: set[str] = set()
    stability: list[dict[str, object]] = []
    for server_id, expected in expected_bindings.items():
        row = rows.get(server_id)
        source = source_expectations.get(server_id)
        if row is None or retained_bindings.get(server_id) != expected:
            blockers.add(server_id)
            continue
        policy_present = row.get("policy_generation") is not None
        if policy_present:
            if (
                source is None
                or row.get("definition_generation")
                != int(source["definition_generation"]) + 1
                or row.get("policy_generation")
                != int(source["policy_generation"]) + 1
            ):
                blockers.add(server_id)
                continue
        elif source is not None:
            blockers.add(server_id)
            continue
        expected_running = bool(
            policy_present
            and row.get("keep_alive") == 1
            and row.get("desired_state") == "running"
            and row.get("breaker_state") == "armed"
        )
        if not expected_running:
            if (
                server_id in loaded
                or row.get("current_attempt_id") is not None
                or row.get("attempt_state") in {"reserved", "running"}
            ):
                blockers.add(server_id)
            else:
                stability.append(
                    {
                        "server_definition_id": server_id,
                        "state": "absent",
                        "definition_generation": row["definition_generation"],
                        "policy_generation": row["policy_generation"],
                    }
                )
            continue
        try:
            native = _managed_worker_native_state(
                runner, server_id, cgroup_root=cgroup_root
            )
        except SwitchError:
            blockers.add(server_id)
            continue
        expected_slice = project_repository_slice(
            uid=int(row["execution_uid"]), repository_id=str(row["repo_id"])
        )
        attempt_pid = row.get("attempt_pid")
        attempt_start = row.get("attempt_process_start_time")
        try:
            process_alive = bool(
                type(attempt_pid) is int
                and isinstance(attempt_start, str)
                and attempt_start
                and process_observer(attempt_pid, attempt_start) == "alive"
            )
        except (OSError, RuntimeError, ValueError):
            process_alive = False
        if (
            row.get("supervisor_state") != "running"
            or row.get("current_attempt_id") is None
            or row.get("attempt_state") != "running"
            or row.get("attempt_definition_generation")
            != row.get("definition_generation")
            or row.get("attempt_policy_generation") != row.get("policy_generation")
            or row.get("attempt_supervisor_generation")
            != row.get("supervisor_generation")
            or row.get("attempt_supervisor_epoch") != row.get("supervisor_epoch")
            or server_id not in loaded
            or native.get("loaded") is not True
            or native.get("active") is not True
            or native.get("main_pid") is None
            or native.get("cgroup_populated") is not True
            or native.get("slice") != expected_slice
            or not process_alive
        ):
            blockers.add(server_id)
        else:
            stability.append(
                {
                    "server_definition_id": server_id,
                    "state": "running",
                    "definition_generation": row["definition_generation"],
                    "policy_generation": row["policy_generation"],
                    "supervisor_generation": row["supervisor_generation"],
                    "supervisor_epoch": row["supervisor_epoch"],
                    "attempt_id": row["current_attempt_id"],
                    "attempt_pid": attempt_pid,
                    "attempt_process_start_time": attempt_start,
                    "native_main_pid": native["main_pid"],
                    "native_control_group": native["control_group"],
                    "native_slice": native["slice"],
                }
            )
    extra_rows = set(rows) - set(expected_bindings)
    if extra_rows:
        blockers.update(extra_rows)
    return (
        tuple(sorted(blockers)),
        hashlib.sha256(
            canonical(
                sorted(
                    stability,
                    key=lambda item: str(item["server_definition_id"]),
                )
            )
        ).hexdigest(),
    )


def _credentialized_worker_refresh_targets(
    source_proof: Mapping[str, object],
) -> tuple[dict[str, object], ...]:
    raw_expectations = source_proof.get("policy_expectations")
    if not isinstance(raw_expectations, list):
        raise SwitchError("credentialized worker source expectations are invalid")
    source_expectations = {
        str(value["server_definition_id"]): value
        for value in raw_expectations
        if isinstance(value, Mapping)
        and isinstance(value.get("server_definition_id"), str)
    }
    if len(source_expectations) != len(raw_expectations):
        raise SwitchError("credentialized worker source expectations are invalid")
    rows, _bindings = _credentialized_worker_rows()
    targets: list[dict[str, object]] = []
    for server_id, source in source_expectations.items():
        if not (
            source.get("keep_alive") == 1
            and source.get("desired_state") == "running"
            and source.get("breaker_state") == "armed"
        ):
            continue
        row = rows.get(server_id)
        if row is not None:
            targets.append(row)
    return tuple(
        sorted(targets, key=lambda row: str(row["server_definition_id"]))
    )


def _refresh_credentialized_worker_status(
    runner: Runner,
    target: Mapping[str, object],
    *,
    timeout_seconds: float,
) -> dict[str, object]:
    """Refresh one exact worker through the supported bounded status client."""

    bounded = getattr(runner, "run_bounded", None)
    if not callable(bounded):
        raise SwitchError("credentialized worker status refresh is not bounded")
    server_id = str(target.get("server_definition_id") or "")
    name = str(target.get("name") or "")
    canonical_root = str(target.get("canonical_root") or "")
    repo_id = str(target.get("repo_id") or "")
    try:
        canonical_id = str(uuid.UUID(server_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise SwitchError("credentialized worker refresh identity is invalid") from error
    if (
        canonical_id != server_id
        or not name
        or not Path(canonical_root).is_absolute()
        or not repo_id
        or not 0.1 <= float(timeout_seconds) <= 20.0
    ):
        raise SwitchError("credentialized worker refresh target is invalid")
    completed = bounded(
        [
            str(CLIENT_LAUNCHER),
            "runtime",
            "status",
            server_id,
            "--kind",
            "service",
            "--project",
            canonical_root,
        ],
        timeout_seconds=float(timeout_seconds),
    )
    encoded_size = len((completed.stdout + completed.stderr).encode("utf-8"))
    if encoded_size > 8192:
        raise SwitchError(
            "credentialized worker exact status refresh failed: " + server_id
        )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise SwitchError(
            "credentialized worker exact status refresh was invalid: " + server_id
        ) from error
    resource = result.get("resource") if isinstance(result, Mapping) else None
    supervision = (
        result.get("supervision") if isinstance(result, Mapping) else None
    )
    if (
        not isinstance(result, Mapping)
        or completed.returncode != 0
        or result.get("action") != "status"
        or result.get("ok") is not True
        or result.get("outcome") != "certain"
        or result.get("mutation_performed") is not False
        or not isinstance(result.get("target"), Mapping)
        or result["target"].get("id") != server_id
        or result["target"].get("kind") != "service"
        or not isinstance(resource, Mapping)
        or resource.get("id") != server_id
        or resource.get("kind") != "service"
        or resource.get("repo_id") != repo_id
        or resource.get("name") != name
        or resource.get("state") != result.get("state")
        or resource.get("ready") != result.get("ready")
        or result.get("name") != name
        or not isinstance(supervision, Mapping)
        or supervision.get("current_attempt_id") is not None
        and not isinstance(supervision.get("current_attempt_id"), str)
        or type(supervision.get("keep_alive")) is not bool
        or supervision.get("desired_state") not in {"running", "stopped"}
        or supervision.get("breaker_state") not in {"armed", "tripped"}
        or not isinstance(supervision.get("supervisor_state"), str)
        or type(result.get("ready")) is not bool
        or type(result.get("supervision_ready")) is not bool
        or result.get("endpoint_ready") is not None
        and type(result.get("endpoint_ready")) is not bool
        or not isinstance(result.get("state"), str)
    ):
        raise SwitchError(
            "credentialized worker exact status refresh changed identity: "
            + server_id
        )
    return {
        "server_definition_id": server_id,
        "repo_id": repo_id,
        "name": name,
        "current_attempt_id": supervision.get("current_attempt_id"),
        "keep_alive": supervision["keep_alive"],
        "desired_state": supervision["desired_state"],
        "breaker_state": supervision["breaker_state"],
        "supervisor_state": supervision["supervisor_state"],
        "ready": result["ready"],
        "supervision_ready": result["supervision_ready"],
        "endpoint_ready": result.get("endpoint_ready"),
        "state": result["state"],
    }


def _credentialized_live_status_blockers(
    rows: Mapping[str, Mapping[str, object]],
    expected_running_ids: set[str],
    evidence: Mapping[str, Mapping[str, object]],
) -> tuple[tuple[str, ...], str]:
    blockers: set[str] = set()
    stability: list[dict[str, object]] = []
    for server_id in sorted(expected_running_ids):
        row = rows.get(server_id)
        status = evidence.get(server_id)
        if (
            row is None
            or status is None
            or status.get("server_definition_id") != server_id
            or status.get("repo_id") != row.get("repo_id")
            or status.get("name") != row.get("name")
            or status.get("current_attempt_id") != row.get("current_attempt_id")
            or status.get("keep_alive") is not True
            or status.get("desired_state") != "running"
            or status.get("breaker_state") != "armed"
            or status.get("supervisor_state") != "running"
            or status.get("supervision_ready") is not True
            or status.get("ready") is not True
            or status.get("state") != "running"
            or status.get("endpoint_ready") is False
        ):
            blockers.add(server_id)
            continue
        stability.append(
            {
                "server_definition_id": server_id,
                "definition_generation": row["definition_generation"],
                "policy_generation": row["policy_generation"],
                "supervisor_generation": row["supervisor_generation"],
                "supervisor_epoch": row["supervisor_epoch"],
                "attempt_id": row["current_attempt_id"],
                "ready": True,
                "supervision_ready": True,
                "endpoint_ready": status.get("endpoint_ready"),
            }
        )
    return (
        tuple(sorted(blockers)),
        hashlib.sha256(canonical(stability)).hexdigest(),
    )


def require_credentialized_worker_convergence(
    manifest: Mapping[str, object],
    transaction_root: Path,
    runner: Runner,
    *,
    source_proof: Mapping[str, object],
    timeout_seconds: float = 60.0,
    stable_seconds: float = 2.0,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
    cgroup_root: Path = CGROUP_ROOT,
    process_observer: Callable[[int, str], str] = observe_worker_process_identity,
    status_refresher: Callable[
        [Mapping[str, object], float], Mapping[str, object]
    ] | None = None,
) -> None:
    deadline = float(clock()) + max(0.1, float(timeout_seconds))
    refresh = (
        (lambda target, timeout: _refresh_credentialized_worker_status(
            runner, target, timeout_seconds=timeout
        ))
        if status_refresher is None
        else status_refresher
    )
    refresh_targets = _credentialized_worker_refresh_targets(source_proof)
    expected_running_ids = {
        str(target["server_definition_id"]) for target in refresh_targets
    }
    live_status: dict[str, Mapping[str, object]] = {}
    next_refresh_at = float(clock())
    stable_fingerprint: str | None = None
    stable_since: float | None = None
    while True:
        observed_before_refresh = float(clock())
        refreshed_now = False
        if refresh_targets and observed_before_refresh >= next_refresh_at:
            refreshed: dict[str, Mapping[str, object]] = {}
            for target in refresh_targets:
                remaining = deadline - float(clock())
                if remaining < 0.1:
                    raise SwitchError(
                        "credentialized worker status refresh exceeded convergence deadline"
                    )
                status = refresh(target, min(20.0, max(0.1, remaining)))
                if not isinstance(status, Mapping):
                    raise SwitchError(
                        "credentialized worker status refresh evidence is invalid"
                    )
                refreshed[str(target["server_definition_id"])] = status
            live_status = refreshed
            next_refresh_at = float(clock()) + 1.0
            refreshed_now = True
        observed_state = _credentialized_worker_rows()
        stored_blockers, stored_fingerprint = _credentialized_worker_blockers(
            manifest,
            transaction_root,
            runner,
            source_proof=source_proof,
            cgroup_root=cgroup_root,
            process_observer=process_observer,
            observed_state=observed_state,
        )
        live_blockers, live_fingerprint = _credentialized_live_status_blockers(
            observed_state[0], expected_running_ids, live_status
        )
        blockers = tuple(sorted({*stored_blockers, *live_blockers}))
        fingerprint = hashlib.sha256(
            canonical(
                {
                    "stored": stored_fingerprint,
                    "live": live_fingerprint,
                }
            )
        ).hexdigest()
        if not blockers:
            observed_at = float(clock())
            if (
                stable_fingerprint == fingerprint
                and stable_since is not None
                and observed_at - stable_since >= max(0.1, float(stable_seconds))
                and (not refresh_targets or refreshed_now)
            ):
                return
            if stable_fingerprint != fingerprint:
                stable_fingerprint = fingerprint
                stable_since = observed_at
        else:
            stable_fingerprint = None
            stable_since = None
        if float(clock()) >= deadline:
            raise SwitchError(
                "credentialized workers did not converge: " + ", ".join(blockers)
            )
        sleeper(min(0.1, max(0.0, deadline - float(clock()))))


def _retained_worker_rows() -> tuple[int, dict[str, dict[str, object]]]:
    """Read all retained worker policies and their current runtime evidence."""

    try:
        connection = sqlite3.connect(
            f"{AUTHORITY_DATABASE.as_uri()}?mode=ro", uri=True, timeout=10.0
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            metadata = connection.execute(
                "SELECT schema_version FROM schema_metadata WHERE singleton=1"
            ).fetchone()
            rows = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT definition.server_definition_id,definition.repo_id,
                           definition.generation AS definition_generation,
                           policy.execution_uid,policy.keep_alive,
                           policy.desired_state,policy.breaker_state,
                           policy.generation AS policy_generation,
                           supervisor.state AS supervisor_state,
                           supervisor.supervisor_epoch,
                           supervisor.supervisor_generation,
                           supervisor.current_attempt_id,
                           attempt.state AS attempt_state,attempt.pid AS attempt_pid,
                           attempt.process_start_time AS attempt_process_start_time,
                           attempt.process_fingerprint AS attempt_process_fingerprint,
                           attempt.definition_generation AS attempt_definition_generation,
                           attempt.policy_generation AS attempt_policy_generation,
                           attempt.supervisor_generation AS attempt_supervisor_generation,
                           attempt.supervisor_epoch AS attempt_supervisor_epoch
                    FROM worker_policies policy
                    JOIN server_definitions definition USING(server_definition_id)
                    JOIN worker_supervisor_states supervisor USING(server_definition_id)
                    LEFT JOIN worker_attempts attempt
                      ON attempt.attempt_id=supervisor.current_attempt_id
                    ORDER BY definition.server_definition_id
                    """
                )
            ]
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise SwitchError("retained worker convergence cannot be read") from error
    if (
        metadata is None
        or type(metadata["schema_version"]) is not int
        or len(rows) > WORKER_CUTOVER_LIMIT
    ):
        raise SwitchError("retained worker convergence metadata is invalid")
    by_id = {str(row["server_definition_id"]): row for row in rows}
    if len(by_id) != len(rows):
        raise SwitchError("retained worker convergence is duplicated")
    return int(metadata["schema_version"]), by_id


def _retained_worker_policy_blockers(
    runner: Runner,
    *,
    source_proof: Mapping[str, object],
    target_schema_version: int,
    generation_offset: int,
    cgroup_root: Path = CGROUP_ROOT,
    process_observer: Callable[[int, str], str] = observe_worker_process_identity,
) -> tuple[tuple[str, ...], str]:
    raw_expectations = source_proof.get("policy_expectations")
    if not _valid_policy_expectations(
        raw_expectations, expected_count=source_proof.get("policy_count")
    ):
        raise SwitchError("retained worker source expectations are invalid")
    if generation_offset not in {0, 1}:
        raise SwitchError("retained worker generation offset is invalid")
    expected = {
        str(value["server_definition_id"]): value
        for value in raw_expectations
    }
    schema_version, rows = _retained_worker_rows()
    if schema_version != target_schema_version:
        raise SwitchError("retained worker authority schema is incompatible")
    loaded = set(loaded_managed_worker_ids(runner))
    blockers: set[str] = (set(rows) ^ set(expected)) | (loaded - set(expected))
    stability: list[dict[str, object]] = []
    for worker_id, source in expected.items():
        row = rows.get(worker_id)
        if row is None:
            blockers.add(worker_id)
            continue
        desired_state = (
            "stopped"
            if source["breaker_state"] == "tripped" and generation_offset == 1
            else source["desired_state"]
        )
        if (
            row.get("repo_id") != source["repo_id"]
            or row.get("execution_uid") != source["execution_uid"]
            or row.get("keep_alive") != source["keep_alive"]
            or row.get("desired_state") != desired_state
            or row.get("breaker_state") != source["breaker_state"]
            or row.get("definition_generation")
            != int(source["definition_generation"]) + generation_offset
            or row.get("policy_generation")
            != int(source["policy_generation"]) + generation_offset
        ):
            blockers.add(worker_id)
            continue
        expected_running = bool(
            row["keep_alive"] == 1
            and row["desired_state"] == "running"
            and row["breaker_state"] == "armed"
        )
        if not expected_running:
            if (
                worker_id in loaded
                or row.get("current_attempt_id") is not None
                or row.get("attempt_state") in {"reserved", "running"}
            ):
                blockers.add(worker_id)
            else:
                stability.append(
                    {
                        "worker_id": worker_id,
                        "state": "absent",
                        "definition_generation": row["definition_generation"],
                        "policy_generation": row["policy_generation"],
                    }
                )
            continue
        try:
            native = _managed_worker_native_state(
                runner, worker_id, cgroup_root=cgroup_root
            )
        except SwitchError:
            blockers.add(worker_id)
            continue
        attempt_pid = row.get("attempt_pid")
        attempt_start = row.get("attempt_process_start_time")
        try:
            process_alive = bool(
                type(attempt_pid) is int
                and isinstance(attempt_start, str)
                and attempt_start
                and process_observer(attempt_pid, attempt_start) == "alive"
            )
        except (OSError, RuntimeError, ValueError):
            process_alive = False
        expected_slice = project_repository_slice(
            uid=int(row["execution_uid"]), repository_id=str(row["repo_id"])
        )
        if (
            row.get("supervisor_state") != "running"
            or row.get("current_attempt_id") is None
            or row.get("attempt_state") != "running"
            or row.get("attempt_definition_generation")
            != row.get("definition_generation")
            or row.get("attempt_policy_generation") != row.get("policy_generation")
            or row.get("attempt_supervisor_generation")
            != row.get("supervisor_generation")
            or row.get("attempt_supervisor_epoch") != row.get("supervisor_epoch")
            or worker_id not in loaded
            or native.get("loaded") is not True
            or native.get("active") is not True
            or native.get("main_pid") is None
            or native.get("cgroup_populated") is not True
            or native.get("slice") != expected_slice
            or not process_alive
        ):
            blockers.add(worker_id)
            continue
        stability.append(
            {
                "worker_id": worker_id,
                "state": "running",
                "definition_generation": row["definition_generation"],
                "policy_generation": row["policy_generation"],
                "supervisor_generation": row["supervisor_generation"],
                "supervisor_epoch": row["supervisor_epoch"],
                "attempt_id": row["current_attempt_id"],
                "attempt_pid": attempt_pid,
                "attempt_process_start_time": attempt_start,
                "native_main_pid": native["main_pid"],
                "native_control_group": native["control_group"],
                "native_slice": native["slice"],
            }
        )
    return (
        tuple(sorted(blockers)),
        hashlib.sha256(
            canonical(sorted(stability, key=lambda item: str(item["worker_id"])))
        ).hexdigest(),
    )


def require_retained_worker_policy_convergence(
    runner: Runner,
    *,
    source_proof: Mapping[str, object],
    target_schema_version: int,
    generation_offset: int,
    timeout_seconds: float = RETAINED_WORKER_CONVERGENCE_SECONDS,
    stable_seconds: float = RETAINED_WORKER_STABILITY_SECONDS,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
    cgroup_root: Path = CGROUP_ROOT,
    process_observer: Callable[[int, str], str] = observe_worker_process_identity,
) -> None:
    """Prove retained policy and the exact desired keep-alive set converged."""

    deadline = float(clock()) + max(0.1, float(timeout_seconds))
    stable_fingerprint: str | None = None
    stable_since: float | None = None
    blockers: tuple[str, ...] = ()
    while True:
        blockers, fingerprint = _retained_worker_policy_blockers(
            runner,
            source_proof=source_proof,
            target_schema_version=target_schema_version,
            generation_offset=generation_offset,
            cgroup_root=cgroup_root,
            process_observer=process_observer,
        )
        if not blockers:
            observed_at = float(clock())
            if (
                stable_fingerprint == fingerprint
                and stable_since is not None
                and observed_at - stable_since >= max(0.1, float(stable_seconds))
            ):
                return
            if stable_fingerprint != fingerprint:
                stable_fingerprint = fingerprint
                stable_since = observed_at
        else:
            stable_fingerprint = None
            stable_since = None
        if float(clock()) >= deadline:
            raise SwitchError(
                "retained workers did not converge: " + ", ".join(blockers)
            )
        sleeper(min(0.1, max(0.0, deadline - float(clock()))))


def _candidate_coordinator_script(document: Mapping[str, object]) -> Path:
    release = Path(str(document.get("release") or ""))
    script = release / "skills/codex-dev-coordinator/scripts/dev_coordinator.py"
    try:
        resolved = script.resolve(strict=True)
        info = resolved.lstat()
    except OSError as error:
        raise SwitchError("candidate worker controller script is unavailable") from error
    if resolved != script or stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SwitchError("candidate worker controller script is unsafe")
    return script


def _worker_native_factory(runner: Runner) -> Callable[..., object]:
    def manager_factory(
        *, coordinator_script: Path, state_root: Path | None = None
    ) -> object:
        def native_runner(
            argv: Sequence[str], **_values: object
        ) -> subprocess.CompletedProcess[str]:
            bounded = getattr(runner, "run_bounded", None)
            if callable(bounded):
                return bounded(argv, timeout_seconds=45.0)
            # Focused injected runners are already synchronous and bounded by
            # their test invocation; production always uses Runner above.
            return runner.run(argv)

        return native_worker_manager(
            coordinator_script=coordinator_script,
            state_root=state_root,
            runner=native_runner,
        )

    return manager_factory


def _candidate_worker_cleanup_rows() -> tuple[
    dict[str, dict[str, object]], tuple[str, ...]
]:
    try:
        connection = sqlite3.connect(
            f"{AUTHORITY_DATABASE.as_uri()}?mode=ro", uri=True, timeout=10.0
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            rows = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT definition.server_definition_id,definition.name,
                           repository.canonical_root,policy.execution_uid
                    FROM server_definitions definition
                    JOIN repositories repository USING(repo_id)
                    LEFT JOIN worker_policies policy USING(server_definition_id)
                    ORDER BY definition.server_definition_id
                    """
                )
            ]
            nonterminal = tuple(
                sorted(
                    {
                        str(row[0])
                        for row in connection.execute(
                            """
                            SELECT server_definition_id FROM worker_attempts
                            WHERE state IN ('reserved','running')
                            UNION
                            SELECT server_definition_id FROM worker_supervisor_states
                            WHERE current_attempt_id IS NOT NULL
                               OR state IN ('launching','running','stopping')
                            """
                        )
                    }
                )
            )
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise SwitchError("candidate worker cleanup state cannot be read") from error
    if len(rows) > WORKER_CUTOVER_LIMIT or len(nonterminal) > WORKER_CUTOVER_LIMIT:
        raise SwitchError("candidate worker cleanup state is excessive")
    by_id = {str(row["server_definition_id"]): row for row in rows}
    if len(by_id) != len(rows):
        raise SwitchError("candidate worker cleanup state is duplicated")
    return by_id, nonterminal


def stop_candidate_workers_for_rollback(
    document: Mapping[str, object],
    intent: Mapping[str, object],
    runner: Runner,
) -> tuple[str, ...]:
    """Stop only post-rebaseline workers, proven by source quiescence."""

    source_proof = intent.get("source_worker_quiescence")
    if not _valid_source_worker_quiescence(source_proof):
        raise SwitchError("candidate worker cleanup lacks source quiescence proof")
    loaded = set(loaded_managed_worker_ids(runner))
    rows, nonterminal = _candidate_worker_cleanup_rows()
    candidates = tuple(sorted(loaded | set(nonterminal)))
    script = _candidate_coordinator_script(document)
    manager_factory = _worker_native_factory(runner)
    for worker_id in candidates:
        row = rows.get(worker_id)
        if row is not None and row.get("execution_uid") is not None:
            try:
                with AccountStore.open(
                    AUTHORITY_DATABASE,
                    expected_uid=os.geteuid(),
                    busy_timeout_ms=10_000,
                ) as store:
                    WorkerController(
                        store,
                        coordinator_script=script,
                        manager_factory=manager_factory,
                        execution_uid=int(row["execution_uid"]),
                    ).stop(
                        worker_id=worker_id,
                        canonical_repository=str(row["canonical_root"]),
                        name=str(row["name"]),
                        actor="release:retained-control-rollback",
                        timeout_seconds=10.0,
                    )
            except (WorkerControlError, WorkerNativeError, OSError) as error:
                raise SwitchError(
                    "candidate worker cleanup failed: " + worker_id
                ) from error
            continue
        if worker_id not in loaded:
            raise SwitchError(
                "candidate worker without policy retained nonterminal state: "
                + worker_id
            )
        try:
            manager = manager_factory(
                coordinator_script=script,
                state_root=None,
            )
            removed = manager.remove(worker_id=worker_id)
        except (WorkerNativeError, OSError) as error:
            raise SwitchError(
                "candidate worker unit without policy could not be removed: "
                + worker_id
            ) from error
        if removed.loaded or removed.active:
            raise SwitchError(
                "candidate worker unit without policy remained loaded: " + worker_id
            )
    remaining_units = loaded_managed_worker_ids(runner)
    _rows, remaining_nonterminal = _candidate_worker_cleanup_rows()
    if remaining_units or remaining_nonterminal:
        raise SwitchError(
            "candidate worker cleanup remained incomplete: "
            + ", ".join(sorted({*remaining_units, *remaining_nonterminal}))
        )
    return candidates


def stop_console_writers(document: Mapping[str, object], runner: Runner) -> None:
    units = {
        str(document.get("previous_console_unit") or ""),
        str(document.get("candidate_console_unit") or ""),
    }
    units.discard("")
    for unit in sorted(units):
        if not re.fullmatch(r"devcoordinator-console@[0-9a-f]{64}\.service", unit):
            raise SwitchError("retained-control Console writer identity is invalid")
        runner.require(["/usr/bin/systemctl", "stop", unit], f"stop Console writer {unit}")
    active = [unit for unit in sorted(units) if unit_active(runner, unit)]
    if active:
        raise SwitchError("Console writers did not stop: " + ", ".join(active))


def _checkpoint_authority_database() -> None:
    try:
        connection = sqlite3.connect(str(AUTHORITY_DATABASE), timeout=10.0)
        try:
            result = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise SwitchError(f"authority checkpoint failed: {error}") from error
    if result is None or tuple(int(value) for value in result) != (0, 0, 0):
        raise SwitchError("authority checkpoint did not quiesce every WAL frame")


def _backup_exact_file(
    source: Path,
    destination: Path,
    *,
    required: bool,
) -> dict[str, object]:
    parent = path_parent_identity(source)
    try:
        info = source.lstat()
    except FileNotFoundError:
        if required:
            raise SwitchError(f"required retained-control source is missing: {source}")
        return {
            "existed": False,
            "source": {"path": str(source), "present": False, "parent": parent},
        }
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SwitchError(f"retained-control source is not a regular file: {source}")
    source_identity = exact_file_identity(source)
    destination_parent = path_parent_identity(destination)
    if destination_parent["uid"] != os.geteuid() or destination_parent["mode"] != 0o700:
        raise SwitchError("retained-control backup parent is not private")
    copied = atomic_regular_copy(source, destination, mode=0o600)
    if exact_file_identity(source) != source_identity:
        raise SwitchError(f"retained-control source changed while backing up: {source}")
    backup_identity = exact_file_identity(destination)
    if (
        backup_identity["sha256"] != copied["sha256"]
        or backup_identity["bytes"] != copied["size"]
        or backup_identity["mode"] != 0o600
        or backup_identity["uid"] != os.geteuid()
        or backup_identity["gid"] != os.getegid()
    ):
        raise SwitchError("retained-control exact backup identity is invalid")
    return {
        "existed": True,
        "source": source_identity,
        "backup": backup_identity,
    }


def _retained_backup_destinations(transaction_root: Path) -> dict[str, dict[str, object]]:
    root = transaction_root / "retained-control-backups"
    root.mkdir(mode=0o700, exist_ok=True)
    info = root.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise SwitchError("retained-control backup root is not root-owned mode 0700")
    sources = {
        AUTHORITY_DATABASE: (root / "authority.sqlite3", True),
        CLIENT_PROFILE: (root / "client-profiles.json", True),
        **{
            CONSOLE_STATE_ROOT / name: (root / f"console-{name}", False)
            for name in retained_control.CONSOLE_FILES
        },
    }
    return {
        str(source): _backup_exact_file(source, backup, required=required)
        for source, (backup, required) in sources.items()
    }


def _server_credential_backup_destinations(
    credentials: Mapping[str, Mapping[str, object]],
    transaction_root: Path,
) -> dict[str, dict[str, object]]:
    if not credentials:
        return {}
    _private_owned_directory(
        SERVER_CREDENTIAL_MATERIAL_ROOT, field="live server credential root"
    )
    _reject_server_credential_extras(credentials)
    backup_root = transaction_root / "retained-control-backups/server-credentials"
    backup_root.mkdir(mode=0o700, exist_ok=True)
    _private_owned_directory(
        backup_root, field="retained server credential backup root"
    )
    _cleanup_server_credential_temporaries(credentials, transaction_root)
    result: dict[str, dict[str, object]] = {}
    for credential_id in sorted(credentials):
        destination = _server_credential_destination(credential_id)
        backup_path = _server_credential_backup_path(
            transaction_root, credential_id
        )
        evidence = _backup_exact_file(
            destination,
            backup_path,
            required=False,
        )
        source = evidence.get("source")
        if not isinstance(source, Mapping):
            raise SwitchError("retained server credential backup identity is invalid")
        if evidence.get("existed") is True and (
            source.get("uid") != os.geteuid()
            or source.get("gid") != os.getegid()
            or source.get("mode") != 0o600
        ):
            raise SwitchError(
                "retained server credential predecessor is not owner mode 0600"
            )
        if evidence.get("existed") is False:
            unlink_regular_and_fsync(
                backup_path,
                parent_identity=path_parent_identity(backup_path),
            )
        result[str(destination)] = evidence
    return result


def _publish_owned_file(
    destination: Path,
    payload: bytes,
    evidence: Mapping[str, object],
) -> None:
    source_identity = evidence.get("source")
    if not isinstance(source_identity, Mapping):
        raise SwitchError("retained-control source identity is invalid")
    require_parent_identity(destination, source_identity.get("parent"))
    if evidence.get("existed") is not True:
        # Newly introduced current-format Console files inherit the fixed
        # service state directory identity.
        parent = path_parent_identity(destination)
        uid, gid, mode = int(parent["uid"]), int(parent["gid"]), 0o600
    else:
        try:
            uid = int(source_identity["uid"])
            gid = int(source_identity["gid"])
            mode = int(source_identity["mode"])
        except (KeyError, TypeError, ValueError) as error:
            raise SwitchError("retained-control ownership evidence is invalid") from error
    atomic_bytes(destination, payload, mode)
    os.chown(destination, uid, gid)
    os.chmod(destination, mode)
    fsync_file_and_parent(destination)
    current = exact_file_identity(destination)
    if (
        current["sha256"] != hashlib.sha256(payload).hexdigest()
        or current["bytes"] != len(payload)
        or (current["uid"], current["gid"], current["mode"]) != (uid, gid, mode)
    ):
        raise SwitchError("retained-control publication identity is invalid")


def _publish_owned_copy(
    destination: Path,
    source: Path,
    evidence: Mapping[str, object],
    *,
    expected_sha256: str,
) -> None:
    source_identity = evidence.get("source")
    if not isinstance(source_identity, Mapping):
        raise SwitchError("retained-control source identity is invalid")
    require_parent_identity(destination, source_identity.get("parent"))
    if evidence.get("existed") is True:
        try:
            uid = int(source_identity["uid"])
            gid = int(source_identity["gid"])
            mode = int(source_identity["mode"])
        except (KeyError, TypeError, ValueError) as error:
            raise SwitchError("retained-control ownership evidence is invalid") from error
    elif evidence.get("existed") is False:
        parent = path_parent_identity(destination)
        uid, gid, mode = int(parent["uid"]), int(parent["gid"]), 0o600
    else:
        raise SwitchError("retained-control destination existence evidence is invalid")
    copied = atomic_regular_copy(
        source,
        destination,
        mode=mode,
        expected_sha256=expected_sha256,
    )
    os.chown(destination, uid, gid)
    os.chmod(destination, mode)
    fsync_file_and_parent(destination)
    current = exact_file_identity(destination)
    if (
        current["sha256"] != expected_sha256
        or current["bytes"] != copied["size"]
        or (current["uid"], current["gid"], current["mode"]) != (uid, gid, mode)
    ):
        raise SwitchError("streamed retained-control publication identity is invalid")


def _restore_exact_file(destination: Path, evidence: Mapping[str, object]) -> None:
    if evidence.get("existed") is False:
        source = evidence.get("source")
        if not isinstance(source, Mapping):
            raise SwitchError("retained-control absent rollback identity is invalid")
        unlink_regular_and_fsync(destination, parent_identity=source.get("parent"))
        return
    if evidence.get("existed") is not True:
        raise SwitchError("retained-control rollback evidence is invalid")
    backup_identity = evidence.get("backup")
    if not isinstance(backup_identity, Mapping):
        raise SwitchError("retained-control rollback backup identity is invalid")
    backup = Path(str(backup_identity.get("path") or ""))
    if exact_file_identity(backup) != dict(backup_identity):
        raise SwitchError("retained-control rollback backup is unavailable")
    expected = backup_identity.get("sha256")
    if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise SwitchError("retained-control rollback digest is invalid")
    _publish_owned_copy(
        destination,
        backup,
        evidence,
        expected_sha256=expected,
    )


def _restore_server_credentials(
    credentials: Mapping[str, Mapping[str, object]],
    backups: Mapping[str, object],
) -> None:
    if not credentials:
        return
    _private_owned_directory(
        SERVER_CREDENTIAL_MATERIAL_ROOT, field="live server credential root"
    )
    for credential_id in sorted(credentials):
        destination = _server_credential_destination(credential_id)
        evidence = backups.get(str(destination))
        if not isinstance(evidence, Mapping):
            raise SwitchError(
                "retained server credential rollback evidence is incomplete"
            )
        _restore_exact_file(destination, evidence)


def _publish_server_credentials(
    credentials: Mapping[str, Mapping[str, object]],
    backups: Mapping[str, object],
) -> None:
    if not credentials:
        return
    _private_owned_directory(
        SERVER_CREDENTIAL_MATERIAL_ROOT, field="live server credential root"
    )
    _reject_server_credential_extras(credentials)
    for credential_id in sorted(credentials):
        value = credentials[credential_id]
        destination = _server_credential_destination(credential_id)
        evidence = backups.get(str(destination))
        material = value.get("material")
        staged = value.get("staged")
        if (
            not isinstance(evidence, Mapping)
            or not isinstance(material, Mapping)
            or not isinstance(staged, Path)
            or not isinstance(material.get("sha256"), str)
        ):
            raise SwitchError(
                "retained server credential publication evidence is incomplete"
            )
        _publish_owned_copy(
            destination,
            staged,
            evidence,
            expected_sha256=str(material["sha256"]),
        )
        current = exact_file_identity(destination)
        if (
            current.get("uid") != os.geteuid()
            or current.get("gid") != os.getegid()
            or current.get("mode") != 0o600
        ):
            raise SwitchError(
                "retained server credential publication ownership is invalid"
            )


def _unlink_authority_sidecars(database_evidence: Mapping[str, object]) -> None:
    source = database_evidence.get("source")
    if not isinstance(source, Mapping):
        raise SwitchError("authority rollback identity is unavailable")
    parent = source.get("parent")
    for sidecar in (Path(f"{AUTHORITY_DATABASE}-wal"), Path(f"{AUTHORITY_DATABASE}-shm")):
        unlink_regular_and_fsync(sidecar, parent_identity=parent)


def _restore_retained_files(
    backups: Mapping[str, object],
    credentials: Mapping[str, Mapping[str, object]],
) -> None:
    database = backups.get(str(AUTHORITY_DATABASE))
    if not isinstance(database, Mapping):
        raise SwitchError("retained-control database backup is unavailable")
    _restore_server_credentials(credentials, backups)
    _unlink_authority_sidecars(database)
    for destination in (
        AUTHORITY_DATABASE,
        CLIENT_PROFILE,
        *(CONSOLE_STATE_ROOT / name for name in retained_control.CONSOLE_FILES),
    ):
        evidence = backups.get(str(destination))
        if not isinstance(evidence, Mapping):
            raise SwitchError("retained-control rollback evidence is incomplete")
        _restore_exact_file(destination, evidence)


def _validate_manifest_backup_binding(
    manifest: Mapping[str, object],
    backups: Mapping[str, object],
    credentials: Mapping[str, Mapping[str, object]],
) -> None:
    source = manifest.get("source")
    if (
        not isinstance(source, Mapping)
        or source.get("schema_version") != retained_control.REBASELINE_SOURCE_SCHEMA
    ):
        raise SwitchError("retained-control source manifest is invalid")
    database = backups.get(str(AUTHORITY_DATABASE))
    profile = backups.get(str(CLIENT_PROFILE))
    if (
        not isinstance(database, Mapping)
        or not isinstance(profile, Mapping)
        or source.get("database") != database.get("source")
        or source.get("profile") != profile.get("source")
    ):
        raise SwitchError("retained-control source is not bound to its exact backups")
    console_sources = manifest.get("console_sources")
    if not isinstance(console_sources, Mapping) or set(console_sources) != set(
        retained_control.CONSOLE_FILES
    ):
        raise SwitchError("retained Console source manifest is invalid")
    for name in retained_control.CONSOLE_FILES:
        evidence = backups.get(str(CONSOLE_STATE_ROOT / name))
        if not isinstance(evidence, Mapping) or console_sources[name] != evidence.get("source"):
            raise SwitchError("retained Console source is not bound to its exact backup")
    core_destinations = {
        str(AUTHORITY_DATABASE),
        str(CLIENT_PROFILE),
        *(str(CONSOLE_STATE_ROOT / name) for name in retained_control.CONSOLE_FILES),
    }
    credential_destinations = {
        str(value["destination"]) for value in credentials.values()
    }
    if set(backups) - core_destinations != credential_destinations:
        raise SwitchError(
            "retained server credential manifest is not bound to exact backups"
        )
    for credential_id, value in credentials.items():
        destination = str(value["destination"])
        evidence = backups.get(destination)
        source = evidence.get("source") if isinstance(evidence, Mapping) else None
        if (
            not isinstance(evidence, Mapping)
            or not isinstance(source, Mapping)
            or source.get("path") != destination
            or _server_credential_id_from_destination(destination) != credential_id
        ):
            raise SwitchError(
                "retained server credential source is not bound to its exact backup"
            )


def _load_bound_retained_manifest(
    intent: Mapping[str, object],
    transaction_root: Path,
    backups: Mapping[str, object],
) -> dict[str, object]:
    manifest_path = Path(str(intent.get("manifest") or ""))
    if manifest_path != transaction_root / "retained-control/retained-control.json":
        raise SwitchError("retained-control manifest escaped its transaction")
    manifest = load_json(manifest_path)
    unsigned = dict(manifest)
    claimed_digest = unsigned.pop("document_sha256", None)
    if (
        manifest.get("schema_version") != retained_control.VERSION
        or manifest.get("kind") != retained_control.KIND
        or claimed_digest != intent.get("document_sha256")
        or not isinstance(claimed_digest, str)
        or hashlib.sha256(canonical(unsigned)).hexdigest() != claimed_digest
    ):
        raise SwitchError("retained-control manifest digest is invalid")
    target = manifest.get("target")
    if (
        not isinstance(target, Mapping)
        or target.get("schema_version") != COORDINATOR_SCHEMA_VERSION
    ):
        raise SwitchError("retained-control target is invalid")
    output_root = transaction_root / "retained-control"
    target_database = target.get("database")
    target_profile = target.get("profile")
    if not isinstance(target_database, Mapping) or not isinstance(target_profile, Mapping):
        raise SwitchError("retained-control staged target identities are invalid")
    if (
        Path(str(target_database.get("path") or "")) != output_root / "authority.sqlite3"
        or Path(str(target_profile.get("path") or ""))
        != output_root / "client-profiles.json"
        or exact_file_identity(Path(str(target_database["path"]))) != dict(target_database)
        or exact_file_identity(Path(str(target_profile["path"]))) != dict(target_profile)
    ):
        raise SwitchError("retained-control staged target changed")
    console_files = manifest.get("console_files")
    if not isinstance(console_files, Mapping) or set(console_files) != set(
        retained_control.CONSOLE_FILES
    ):
        raise SwitchError("retained Console staged evidence is invalid")
    for name in retained_control.CONSOLE_FILES:
        evidence = console_files[name]
        staged = output_root / "console" / name
        if (
            not isinstance(evidence, Mapping)
            or exact_file_identity(staged)["sha256"] != evidence.get("sha256")
            or exact_file_identity(staged)["bytes"] != evidence.get("bytes")
        ):
            raise SwitchError("retained Console staged target changed")
    credentials = _server_credentials_from_manifest(manifest, transaction_root)
    _validate_manifest_backup_binding(manifest, backups, credentials)
    source = manifest.get("source")
    source_proof = intent.get("source_worker_quiescence")
    if (
        not isinstance(source, Mapping)
        or not _valid_source_worker_quiescence(source_proof)
        or source.get("schema_version") != source_proof.get("schema_version")
        or source.get("database_generation")
        != source_proof.get("database_generation")
    ):
        raise SwitchError(
            "retained source manifest is not bound to worker quiescence proof"
        )
    return manifest


def _unbound_prepared_server_credentials(
    transaction_root: Path,
) -> dict[str, dict[str, object]]:
    """Recover affected IDs only to clean a pre-journal backup interruption."""

    manifest_path = transaction_root / "retained-control/retained-control.json"
    if not manifest_path.exists() and not manifest_path.is_symlink():
        return {}
    manifest = load_json(manifest_path)
    unsigned = dict(manifest)
    claimed = unsigned.pop("document_sha256", None)
    if (
        manifest.get("schema_version") != retained_control.VERSION
        or manifest.get("kind") != retained_control.KIND
        or not isinstance(claimed, str)
        or hashlib.sha256(canonical(unsigned)).hexdigest() != claimed
    ):
        raise SwitchError("unbound retained-control manifest is invalid")
    return _server_credentials_from_manifest(manifest, transaction_root)


def _require_exact_live_server_credentials(
    credentials: Mapping[str, Mapping[str, object]],
) -> None:
    if not credentials:
        return
    _private_owned_directory(
        SERVER_CREDENTIAL_MATERIAL_ROOT, field="live server credential root"
    )
    _reject_server_credential_extras(credentials)
    for value in credentials.values():
        destination = Path(str(value["destination"]))
        material = value.get("material")
        if not isinstance(material, Mapping):
            raise SwitchError("retained server credential target evidence is invalid")
        current = exact_file_identity(destination)
        if (
            current.get("sha256") != material.get("sha256")
            or current.get("bytes") != material.get("bytes")
            or current.get("uid") != os.geteuid()
            or current.get("gid") != os.getegid()
            or current.get("mode") != 0o600
        ):
            raise SwitchError("retained server credential live target changed")


def _retained_destination_owner(
    backup: Mapping[str, object],
) -> tuple[object, object, object]:
    source = backup.get("source")
    if not isinstance(source, Mapping):
        raise SwitchError("retained-control source ownership is unavailable")
    if backup.get("existed") is True:
        return source.get("uid"), source.get("gid"), source.get("mode")
    if backup.get("existed") is False:
        parent = source.get("parent")
        if not isinstance(parent, Mapping):
            raise SwitchError("retained-control source parent is unavailable")
        return parent.get("uid"), parent.get("gid"), 0o600
    raise SwitchError("retained-control destination existence evidence is invalid")


def _live_regular_file_contract(path: Path) -> dict[str, object]:
    parent = path_parent_identity(path)
    try:
        path_before = path.lstat()
    except OSError as error:
        raise SwitchError(f"retained-control live file is unavailable: {path}") from error
    if stat.S_ISLNK(path_before.st_mode) or not stat.S_ISREG(path_before.st_mode):
        raise SwitchError(f"retained-control live file is not regular: {path}")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError as error:
        raise SwitchError(f"retained-control live file is unavailable: {path}") from error
    try:
        opened = os.fstat(descriptor)
        path_info = path.lstat()
        opened_after = os.fstat(descriptor)
    except OSError as error:
        raise SwitchError(f"retained-control live file is unavailable: {path}") from error
    finally:
        os.close(descriptor)
    identity = (
        opened.st_dev,
        opened.st_ino,
        opened.st_uid,
        opened.st_gid,
        stat.S_IMODE(opened.st_mode),
    )
    if (
        not stat.S_ISREG(opened.st_mode)
        or identity
        != (
            path_before.st_dev,
            path_before.st_ino,
            path_before.st_uid,
            path_before.st_gid,
            stat.S_IMODE(path_before.st_mode),
        )
        or identity
        != (
            path_info.st_dev,
            path_info.st_ino,
            path_info.st_uid,
            path_info.st_gid,
            stat.S_IMODE(path_info.st_mode),
        )
        or identity
        != (
            opened_after.st_dev,
            opened_after.st_ino,
            opened_after.st_uid,
            opened_after.st_gid,
            stat.S_IMODE(opened_after.st_mode),
        )
    ):
        raise SwitchError(f"retained-control live file identity changed: {path}")
    return {
        "path": str(path),
        "uid": opened.st_uid,
        "gid": opened.st_gid,
        "mode": stat.S_IMODE(opened.st_mode),
        "device": opened.st_dev,
        "inode": opened.st_ino,
        "parent": parent,
    }


def _require_exact_live_retained_target(
    manifest: Mapping[str, object],
    backups: Mapping[str, object],
    transaction_root: Path,
) -> None:
    target = manifest.get("target")
    console_files = manifest.get("console_files")
    if not isinstance(target, Mapping) or not isinstance(console_files, Mapping):
        raise SwitchError("retained-control target evidence is unavailable")
    expected: tuple[tuple[Path, Mapping[str, object]], ...] = (
        (AUTHORITY_DATABASE, target["database"]),
        (CLIENT_PROFILE, target["profile"]),
        *tuple(
            (CONSOLE_STATE_ROOT / name, console_files[name])
            for name in retained_control.CONSOLE_FILES
        ),
    )
    for destination, staged in expected:
        backup = backups.get(str(destination))
        if not isinstance(staged, Mapping) or not isinstance(backup, Mapping):
            raise SwitchError("retained-control live target evidence is incomplete")
        current = exact_file_identity(destination)
        desired_owner = _retained_destination_owner(backup)
        if (
            current.get("sha256") != staged.get("sha256")
            or current.get("bytes") != staged.get("bytes")
            or (current.get("uid"), current.get("gid"), current.get("mode"))
            != desired_owner
        ):
            raise SwitchError(f"retained-control live target changed: {destination}")
    credentials = _server_credentials_from_manifest(manifest, transaction_root)
    _cleanup_server_credential_temporaries(credentials, transaction_root)
    _require_exact_live_server_credentials(credentials)
    require_current_authority_schema()


def _require_post_start_retained_target(
    manifest: Mapping[str, object],
    backups: Mapping[str, object],
    transaction_root: Path,
) -> None:
    target = manifest.get("target")
    console_files = manifest.get("console_files")
    if not isinstance(target, Mapping) or not isinstance(console_files, Mapping):
        raise SwitchError("retained-control target evidence is unavailable")
    database_backup = backups.get(str(AUTHORITY_DATABASE))
    if not isinstance(database_backup, Mapping):
        raise SwitchError("retained-control live authority evidence is incomplete")
    database_source = database_backup.get("source")
    if not isinstance(database_source, Mapping):
        raise SwitchError("retained-control source ownership is unavailable")
    require_parent_identity(AUTHORITY_DATABASE, database_source.get("parent"))
    authority = _live_regular_file_contract(AUTHORITY_DATABASE)
    if (
        authority.get("uid"),
        authority.get("gid"),
        authority.get("mode"),
    ) != _retained_destination_owner(database_backup):
        raise SwitchError("retained-control live authority ownership changed")

    exact_targets: tuple[tuple[Path, object], ...] = (
        (CLIENT_PROFILE, target.get("profile")),
        *tuple(
            (CONSOLE_STATE_ROOT / name, console_files.get(name))
            for name in retained_control.CONSOLE_FILES
        ),
    )
    for destination, staged in exact_targets:
        backup = backups.get(str(destination))
        if not isinstance(staged, Mapping) or not isinstance(backup, Mapping):
            raise SwitchError("retained-control live target evidence is incomplete")
        current = exact_file_identity(destination)
        if (
            current.get("sha256") != staged.get("sha256")
            or current.get("bytes") != staged.get("bytes")
            or (current.get("uid"), current.get("gid"), current.get("mode"))
            != _retained_destination_owner(backup)
        ):
            raise SwitchError(f"retained-control live target changed: {destination}")
    credentials = _server_credentials_from_manifest(manifest, transaction_root)
    _cleanup_server_credential_temporaries(credentials, transaction_root)
    _require_exact_live_server_credentials(credentials)
    _require_live_retained_generation(
        manifest, expected_authority_identity=authority
    )


def _require_live_retained_generation(
    manifest: Mapping[str, object],
    *,
    expected_authority_identity: Mapping[str, object],
) -> None:
    target = manifest.get("target")
    if not isinstance(target, Mapping):
        raise SwitchError("retained-control target generation is unavailable")
    generation = target.get("database_generation")
    if not isinstance(generation, str) or not generation:
        raise SwitchError("retained-control target generation is invalid")

    def require_bound_authority_path() -> None:
        observed = _live_regular_file_contract(AUTHORITY_DATABASE)
        fields = ("device", "inode", "uid", "gid", "mode")
        if any(
            observed.get(field) != expected_authority_identity.get(field)
            for field in fields
        ):
            raise SwitchError(
                "retained-control live authority changed during semantic proof"
            )

    require_bound_authority_path()
    try:
        connection = sqlite3.connect(f"{AUTHORITY_DATABASE.as_uri()}?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA query_only=ON")
            row = connection.execute(
                "SELECT schema_version,database_generation FROM schema_metadata WHERE singleton=1"
            ).fetchone()
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise SwitchError(f"published retained authority is unreadable: {error}") from error
    require_bound_authority_path()
    if row != (COORDINATOR_SCHEMA_VERSION, generation):
        raise SwitchError("published retained authority has another schema or generation")
    raw_profile, _profile_identity = retained_control._read_console(CLIENT_PROFILE, {})
    if not isinstance(raw_profile, Mapping):
        raise SwitchError("published retained profile is invalid")
    profile = raw_profile
    service = profile.get("service")
    if (
        profile.get("version") != 2
        or not isinstance(service, Mapping)
        or service.get("database_generation") != generation
    ):
        raise SwitchError("published retained profile has another authority generation")
    raw_routes, _routes_identity = retained_control._read_console(
        CONSOLE_STATE_ROOT / "routes.json", {"version": 1, "routes": {}}
    )
    routes = retained_control._validate_console_routes(raw_routes)
    raw_access, _access_identity = retained_control._read_console(
        CONSOLE_STATE_ROOT / "access-control.json",
        {"version": 3, "users": {}, "requests": {}},
    )
    retained_control._validate_console_access(raw_access, routes["routes"])
    raw_prefs, _prefs_identity = retained_control._read_console(
        CONSOLE_STATE_ROOT / "ui-prefs.json",
        {"version": 1, "hidden": {"servers": [], "docker": [], "projects": []}},
    )
    retained_control._validate_console_prefs(raw_prefs)


def apply_retained_control_rebaseline(
    document: dict[str, object],
    journal_path: Path,
    transaction_root: Path,
    runner: Runner,
) -> dict[str, object]:
    intent = retained_rebaseline_intent(document)
    validate_retained_rebaseline_paths(intent, transaction_root)
    if intent["required"] is not True:
        return intent
    if intent["status"] in {"published", "applied"}:
        backups = intent.get("backups")
        if not isinstance(backups, Mapping):
            raise SwitchError("applied retained-control transaction lost its backups")
        manifest = _load_bound_retained_manifest(intent, transaction_root, backups)
        _require_post_start_retained_target(
            manifest, backups, transaction_root
        )
        return intent

    source_status = intent["status"] in {"planned", "backed-up", "prepared"}
    stop_authority_writers(runner)
    if source_status:
        bind_source_worker_quiescence(document, intent, journal_path, runner)
    else:
        require_no_managed_worker_units(runner)
    if source_status:
        retained_proof = intent.get("source_worker_quiescence")
        if not _valid_source_worker_quiescence(retained_proof):
            raise SwitchError("source worker quiescence journal proof is invalid")
        post_stop_proof = source_worker_quiescence_proof(
            runner, quiesced_workers=retained_proof["quiesced_workers"]
        )
        if dict(retained_proof) != post_stop_proof:
            raise SwitchError(
                "source worker quiescence changed while authority writers stopped"
            )
    else:
        # Close the unit-start TOCTOU even when replay begins from a partially
        # published database whose schema cannot yet be read as schema 15.
        require_no_managed_worker_units(runner)
    stop_console_writers(document, runner)
    if intent["status"] == "planned":
        _checkpoint_authority_database()
        backups = _retained_backup_destinations(transaction_root)
        intent.update({"status": "backed-up", "backups": backups, "backed_up_at": now()})
        document["retained_control_rebaseline"] = intent
        save_phase(journal_path, document, "applying")
        validate_retained_rebaseline_paths(intent, transaction_root)
    backups = intent.get("backups")
    if not isinstance(backups, Mapping):
        raise SwitchError("retained-control backups are unavailable")

    output_root = transaction_root / "retained-control"
    if intent["status"] == "backed-up":
        try:
            prepared = retained_control.prepare_rebaseline(
                source_database=AUTHORITY_DATABASE,
                source_profile=CLIENT_PROFILE,
                console_state_root=CONSOLE_STATE_ROOT,
                output_root=output_root,
                expected_uid=0,
            )
        except retained_control.RetainedControlError as error:
            raise SwitchError(f"retained-control preparation failed: {error}") from error
        credentials = _server_credentials_from_manifest(prepared, transaction_root)
        credential_backups = _server_credential_backup_destinations(
            credentials, transaction_root
        )
        full_backups = dict(backups)
        if set(full_backups) & set(credential_backups):
            raise SwitchError("retained server credential backup collides with control data")
        full_backups.update(credential_backups)
        backups = full_backups
        intent.update(
            {
                "status": "prepared",
                "backups": full_backups,
                "manifest": str(output_root / "retained-control.json"),
                "document_sha256": prepared["document_sha256"],
                "target_database_generation": prepared["target"]["database_generation"],
                "prepared_at": now(),
            }
        )
        document["retained_control_rebaseline"] = intent
        save_phase(journal_path, document, "applying")
        validate_retained_rebaseline_paths(intent, transaction_root)

    manifest = _load_bound_retained_manifest(intent, transaction_root, backups)
    credentials = _server_credentials_from_manifest(manifest, transaction_root)
    _cleanup_server_credential_temporaries(credentials, transaction_root)
    target = manifest.get("target")
    if not isinstance(target, Mapping):
        raise SwitchError("retained-control target is invalid")
    target_database_evidence = target.get("database")
    target_profile_evidence = target.get("profile")
    if not isinstance(target_database_evidence, Mapping) or not isinstance(
        target_profile_evidence, Mapping
    ):
        raise SwitchError("retained-control staged target identities are invalid")
    target_database = Path(str(target_database_evidence["path"]))
    target_profile = Path(str(target_profile_evidence["path"]))
    database_backup = backups.get(str(AUTHORITY_DATABASE))
    profile_backup = backups.get(str(CLIENT_PROFILE))
    if not isinstance(database_backup, Mapping) or not isinstance(profile_backup, Mapping):
        raise SwitchError("retained-control exact backups are incomplete")
    intent.update({"status": "publishing", "publishing_at": now()})
    document["retained_control_rebaseline"] = intent
    save_phase(journal_path, document, "applying")
    try:
        # Always converge from the exact predecessor first.  This makes an
        # interrupted partial publish replayable even when the journal update
        # immediately after one os.replace never reached disk.
        _restore_retained_files(backups, credentials)
        retained_proof = intent.get("source_worker_quiescence")
        if not _valid_source_worker_quiescence(retained_proof):
            raise SwitchError("source worker quiescence journal proof is invalid")
        restored_proof = source_worker_quiescence_proof(
            runner, quiesced_workers=retained_proof["quiesced_workers"]
        )
        if dict(retained_proof) != restored_proof:
            raise SwitchError(
                "restored source worker quiescence differs from its journal proof"
            )
        _publish_server_credentials(credentials, backups)
        _publish_owned_copy(
            AUTHORITY_DATABASE,
            target_database,
            database_backup,
            expected_sha256=str(target_database_evidence["sha256"]),
        )
        _publish_owned_copy(
            CLIENT_PROFILE,
            target_profile,
            profile_backup,
            expected_sha256=str(target_profile_evidence["sha256"]),
        )
        console_evidence = manifest.get("console_files")
        if not isinstance(console_evidence, Mapping):
            raise SwitchError("retained Console target evidence is unavailable")
        for name in retained_control.CONSOLE_FILES:
            destination = CONSOLE_STATE_ROOT / name
            evidence = backups.get(str(destination))
            staged = output_root / "console" / name
            if not isinstance(evidence, Mapping):
                raise SwitchError("retained Console backup evidence is incomplete")
            _publish_owned_copy(
                destination,
                staged,
                evidence,
                expected_sha256=str(console_evidence[name]["sha256"]),
            )
        _require_exact_live_retained_target(
            manifest, backups, transaction_root
        )
    except BaseException as error:
        try:
            _restore_retained_files(backups, credentials)
            intent.update({"status": "prepared", "publication_recovered_at": now()})
            document["retained_control_rebaseline"] = intent
            save_phase(journal_path, document, "applying")
        except BaseException as rollback_error:
            raise SwitchError(
                "retained-control publication and exact rollback both failed: "
                f"publish={error}; rollback={rollback_error}"
            ) from rollback_error
        raise SwitchError(
            f"retained-control publication failed and exact files were restored: {error}"
        ) from error
    intent.update({"status": "published", "published_at": now()})
    document["retained_control_rebaseline"] = intent
    save_phase(journal_path, document, "applying")
    return intent


def complete_retained_control_rebaseline(
    document: dict[str, object],
    journal_path: Path,
    transaction_root: Path,
    runner: Runner,
) -> dict[str, object]:
    intent = retained_rebaseline_intent(document)
    if intent["required"] is not True:
        return intent
    if intent["status"] not in {"published", "applied"}:
        raise SwitchError("retained-control services started before publication completed")
    backups = intent.get("backups")
    if not isinstance(backups, Mapping):
        raise SwitchError("retained-control completion lost its exact backups")
    manifest = _load_bound_retained_manifest(intent, transaction_root, backups)
    _require_post_start_retained_target(manifest, backups, transaction_root)
    require_retained_worker_policy_convergence(
        runner,
        source_proof=intent["source_worker_quiescence"],
        target_schema_version=COORDINATOR_SCHEMA_VERSION,
        generation_offset=1,
    )
    require_credentialized_worker_convergence(
        manifest,
        transaction_root,
        runner,
        source_proof=intent["source_worker_quiescence"],
    )
    if intent["status"] == "published":
        intent.update({"status": "applied", "applied_at": now()})
        document["retained_control_rebaseline"] = intent
        save_phase(journal_path, document, "applying")
    return intent


def restore_retained_control_rebaseline(
    document: dict[str, object],
    journal_path: Path,
    transaction_root: Path,
    runner: Runner,
) -> None:
    intent = retained_rebaseline_intent(document)
    validate_retained_rebaseline_paths(intent, transaction_root)
    if intent["required"] is not True or intent["status"] in {"planned", "rolled-back"}:
        return
    backups = intent.get("backups")
    if not isinstance(backups, Mapping):
        raise SwitchError("retained-control rollback backups are unavailable")
    status = str(intent["status"])
    retained_proof = intent.get("source_worker_quiescence")
    if not _valid_source_worker_quiescence(retained_proof):
        raise SwitchError("source worker quiescence journal proof is invalid")
    if status in {"backed-up", "prepared"}:
        observed = source_worker_quiescence_proof(
            runner, quiesced_workers=retained_proof["quiesced_workers"]
        )
        if dict(retained_proof) != observed:
            raise SwitchError("source worker quiescence changed before rollback")
        stop_authority_writers(runner)
        observed = source_worker_quiescence_proof(
            runner, quiesced_workers=retained_proof["quiesced_workers"]
        )
        if dict(retained_proof) != observed:
            raise SwitchError("source worker quiescence changed while stopping writers")
    elif status == "publishing":
        require_no_managed_worker_units(runner)
        stop_authority_writers(runner)
        require_no_managed_worker_units(runner)
    elif status in {"published", "applied"}:
        # The journal proves the predecessor had no live worker at publication.
        # Every exact current attempt/unit was therefore created by candidate
        # startup and remains candidate-only rollback cleanup.
        stop_authority_writers(runner)
        stop_candidate_workers_for_rollback(document, intent, runner)
    else:
        raise SwitchError("retained-control rollback status is invalid")
    stop_console_writers(document, runner)
    if status == "backed-up":
        affected = _unbound_prepared_server_credentials(transaction_root)
        if affected:
            _cleanup_server_credential_temporaries(affected, transaction_root)
        credentials: Mapping[str, Mapping[str, object]] = {}
    else:
        manifest = _load_bound_retained_manifest(intent, transaction_root, backups)
        credentials = _server_credentials_from_manifest(manifest, transaction_root)
        _cleanup_server_credential_temporaries(credentials, transaction_root)
    _restore_retained_files(backups, credentials)
    restored_proof = source_worker_quiescence_proof(
        runner, quiesced_workers=retained_proof["quiesced_workers"]
    )
    if dict(retained_proof) != restored_proof:
        raise SwitchError("restored source worker quiescence differs from its journal proof")
    intent.update({"status": "rolled-back", "rolled_back_at": now()})
    document["retained_control_rebaseline"] = intent
    save_phase(journal_path, document, "rollback-retained-control-restored")


def restart_previous_console(
    release: Path,
    document: Mapping[str, object],
    runner: Runner,
) -> None:
    unit = str(document.get("previous_console_unit") or "")
    control = str(document.get("previous_control_socket") or "")
    if re.fullmatch(r"devcoordinator-console@[0-9a-f]{64}\.service", unit) is None:
        raise SwitchError("previous Console restart identity is invalid")
    runner.require(["/usr/bin/systemctl", "enable", "--now", unit], "restore active Console")
    status = wait_slot_status(
        runner,
        release,
        control,
        unit,
        "restored active Console status",
    )
    if status.get("mode") == "standby":
        runner.require_json(
            [
                str(release / "bin/devcoordinator-console-slot-control"),
                "promote",
                "--socket",
                control,
                "--timeout-seconds",
                "30",
            ],
            "restored active Console promotion",
        )
        status = wait_slot_status(
            runner,
            release,
            control,
            unit,
            "promoted active Console status",
        )
    if status.get("mode") != "active":
        raise SwitchError("restarted already-active Console is not active")
    require_probe(
        direct_https_health(int(document["previous_outer_port"]), "/healthz"),
        "restarted already-active Console health",
    )


def _authority_invocation_state(runner: Runner) -> dict[str, object]:
    completed = runner.run_bounded(
        [
            "/usr/bin/systemctl",
            "show",
            AUTHORITY_SERVICE,
            "--property=InvocationID",
            "--property=MainPID",
            "--property=ActiveState",
            "--property=SubState",
            "--no-pager",
        ],
        timeout_seconds=AUTHORITY_READY_COMMAND_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0 or completed.stderr:
        raise SwitchError("authority readiness status failed")
    if (
        len(completed.stdout.encode("utf-8"))
        + len(completed.stderr.encode("utf-8"))
        > AUTHORITY_READY_OUTPUT_MAX_BYTES
    ):
        raise SwitchError("authority readiness status is excessive")
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise SwitchError("authority readiness status is malformed")
        values[key] = value
    if set(values) != {"InvocationID", "MainPID", "ActiveState", "SubState"}:
        raise SwitchError("authority readiness status is incomplete")
    invocation_id = values["InvocationID"]
    pid_text = values["MainPID"]
    if (
        re.fullmatch(r"[0-9a-f]{32}", invocation_id) is None
        or not pid_text.isdigit()
        or int(pid_text) <= 1
        or values["ActiveState"] != "active"
        or values["SubState"] != "running"
    ):
        raise SwitchError("authority readiness identity is not active")
    return {
        "invocation_id": invocation_id,
        "main_pid": int(pid_text),
        "active_state": values["ActiveState"],
        "sub_state": values["SubState"],
    }


def wait_authority_ready(
    runner: Runner,
    *,
    timeout_seconds: float = AUTHORITY_READY_TIMEOUT_SECONDS,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not 0.1 <= float(timeout_seconds) <= AUTHORITY_READY_TIMEOUT_SECONDS
    ):
        raise SwitchError("authority readiness timeout is invalid")
    deadline = float(clock()) + float(timeout_seconds)
    expected = _authority_invocation_state(runner)

    def filtered_records(pattern: str, remaining: float) -> list[dict[str, object]]:
        completed = runner.run_bounded(
            [
                "/usr/bin/journalctl",
                "--unit",
                AUTHORITY_SERVICE,
                "_SYSTEMD_INVOCATION_ID=" + str(expected["invocation_id"]),
                "--grep=" + pattern,
                "--output=cat",
                "--no-pager",
                "--lines=2",
            ],
            timeout_seconds=min(
                AUTHORITY_READY_COMMAND_TIMEOUT_SECONDS,
                max(0.1, remaining),
            ),
        )
        if completed.returncode != 0 or completed.stderr:
            raise SwitchError("authority readiness journal failed")
        if (
            len(completed.stdout.encode("utf-8"))
            + len(completed.stderr.encode("utf-8"))
            > AUTHORITY_READY_OUTPUT_MAX_BYTES
        ):
            raise SwitchError("authority readiness journal is excessive")
        result: list[dict[str, object]] = []
        for line in completed.stdout.splitlines():
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise SwitchError("authority readiness journal is malformed") from error
            if not isinstance(value, Mapping):
                raise SwitchError("authority readiness journal is malformed")
            result.append(dict(value))
        if len(result) > 1:
            raise SwitchError("authority readiness record is duplicated")
        return result

    while True:
        remaining = deadline - float(clock())
        if remaining <= 0:
            raise SwitchError("authority readiness record timed out")
        schema_checks = filtered_records('"kind": "schema"', remaining)
        ready = filtered_records('"status": "ready"', remaining)
        observed = _authority_invocation_state(runner)
        if observed != expected:
            raise SwitchError("authority invocation changed before readiness")
        if ready:
            if len(schema_checks) != 1:
                raise SwitchError("authority schema readiness record is missing")
            schema = schema_checks[0]
            if (
                set(schema)
                != {"ok", "kind", "database", "schema_version", "read_only"}
                or schema.get("ok") is not True
                or schema.get("kind") != "schema"
                or schema.get("database") != str(AUTHORITY_DATABASE)
                or schema.get("schema_version") != COORDINATOR_SCHEMA_VERSION
                or schema.get("read_only") is not True
            ):
                raise SwitchError("authority schema readiness record is invalid")
            document = ready[0]
            if (
                set(document)
                != {
                    "status",
                    "service_uid",
                    "socket",
                    "socket_activated",
                    "database",
                    "wire_identity",
                }
                or document.get("service_uid") != 0
                or document.get("socket") != AUTHORITY_SOCKET_PATH
                or document.get("socket_activated") is not True
                or document.get("database") != str(AUTHORITY_DATABASE)
                or document.get("wire_identity") != "opaque_normalized_ids_only"
            ):
                raise SwitchError("authority readiness record is invalid")
            return {**expected, "ready": True}
        sleeper(min(AUTHORITY_READY_POLL_SECONDS, max(0.0, remaining)))


def restart_services(
    runner: Runner,
    *,
    ready_waiter: Callable[[Runner], object] = wait_authority_ready,
) -> None:
    # Routine replacement is also the repair path for a host whose required
    # unit was disabled out of band. Reassert the boot contract first, then
    # start each service exactly once through the ordered restart below.
    for unit in (*REQUIRED_SOCKETS, *SERVICE_ORDER):
        runner.require(
            ["/usr/bin/systemctl", "enable", unit],
            f"enable required unit {unit}",
        )
    runner.require(
        [
            "/usr/bin/systemctl",
            "restart",
            *REQUIRED_SOCKETS,
            *SERVICE_ORDER,
        ],
        "restart required service graph",
    )
    ready_waiter(runner)


def restore_rollback_control_plane(
    runner: Runner,
    *,
    ready_waiter: Callable[[Runner], object] = wait_authority_ready,
) -> None:
    """Restore stable authority before any background unit can block rollback.

    A background service may legitimately take its full start deadline.  The
    stable client and authority must already execute the same restored release
    before rollback attempts such a unit, otherwise an interrupted rollback
    leaves every agent behind a release-handshake failure.
    """

    for unit in (*ROLLBACK_CRITICAL_SOCKETS, *ROLLBACK_CRITICAL_SERVICES):
        runner.require(
            ["/usr/bin/systemctl", "enable", unit],
            f"rollback enable critical graph unit {unit}",
        )
    runner.require(
        [
            "/usr/bin/systemctl",
            "--job-mode=ignore-requirements",
            "restart",
            *ROLLBACK_CRITICAL_SOCKETS,
            *ROLLBACK_CRITICAL_SERVICES,
        ],
        "rollback restart critical graph",
    )
    ready_waiter(runner)


def restore_rollback_background_services(runner: Runner) -> None:
    """Restore non-critical units only after stable authority is coherent."""

    for unit in (*ROLLBACK_BACKGROUND_SOCKETS, *ROLLBACK_BACKGROUND_SERVICES):
        runner.require(
            ["/usr/bin/systemctl", "enable", unit],
            f"rollback enable background graph unit {unit}",
        )
    runner.require(
        [
            "/usr/bin/systemctl",
            "restart",
            *ROLLBACK_BACKGROUND_SOCKETS,
            *ROLLBACK_BACKGROUND_SERVICES,
        ],
        "rollback restart background graph",
    )


def complete_rollback_after_control_plane(
    document: dict[str, object],
    journal_path: Path,
    runner: Runner,
) -> dict[str, object]:
    """Resume only background/restart proof after previous publication is live."""

    phase = str(document.get("phase") or "")
    if phase == "rollback-control-plane-restored":
        restore_rollback_background_services(runner)
        save_phase(
            journal_path,
            document,
            "rollback-background-restored",
            rollback_background_restored_at=now(),
        )
    elif phase != "rollback-background-restored":
        raise SwitchError("rollback completion phase is invalid")
    rebaseline = retained_rebaseline_intent(document)
    if rebaseline["required"] is True:
        source_proof = rebaseline.get("source_worker_quiescence")
        if not _valid_source_worker_quiescence(source_proof):
            raise SwitchError("rollback worker restart proof is unavailable")
        require_retained_worker_policy_convergence(
            runner,
            source_proof=source_proof,
            target_schema_version=retained_control.REBASELINE_SOURCE_SCHEMA,
            generation_offset=0,
        )
    candidate_slot = SLOT_ROOT / f"{document['release_digest']}.env"
    candidate_slot.unlink(missing_ok=True)
    save_phase(journal_path, document, "rolled-back", completed_at=now())
    return document


def unix_socket_health(path: Path, timeout_seconds: float = 1.0) -> dict[str, object]:
    try:
        info = path.lstat()
        if not stat.S_ISSOCK(info.st_mode):
            raise OSError("path is not a Unix socket")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout_seconds)
            connection.connect(str(path))
        return {"ok": True, "path": str(path)}
    except OSError as error:
        return {
            "ok": False,
            "path": str(path),
            "error": " ".join(str(error).split())[:512],
        }


def unit_active(runner: Runner, unit: str) -> bool:
    return runner.run(["/usr/bin/systemctl", "is-active", "--quiet", unit]).returncode == 0


def unit_enabled(runner: Runner, unit: str) -> bool:
    return runner.run(["/usr/bin/systemctl", "is-enabled", "--quiet", unit]).returncode == 0


def test_history_wrapper(release: Path) -> Path:
    wrapper = release / "bin" / TEST_HISTORY_WRAPPER
    if not wrapper.is_file() or wrapper.is_symlink() or not os.access(wrapper, os.X_OK):
        raise SwitchError(
            f"immutable release lacks the test-history wrapper: {release}"
        )
    return wrapper


def stop_test_plane(runner: Runner) -> None:
    # Stop socket activation first so the service cannot reappear while the
    # isolated SQLite main/WAL/SHM triplet is replaced.
    runner.require(
        ["/usr/bin/systemctl", "stop", TESTD_SOCKET, TESTD_SERVICE],
        "stop isolated test plane",
    )
    require_test_plane_stopped(runner)


def require_test_plane_stopped(runner: Runner) -> None:
    if unit_active(runner, TESTD_SOCKET) or unit_active(runner, TESTD_SERVICE):
        raise SwitchError("test-history reset requires testd and its socket to be stopped")


def restart_test_plane(runner: Runner) -> None:
    runner.require(
        ["/usr/bin/systemctl", "restart", TESTD_SOCKET],
        "restart testd socket",
    )
    runner.require(
        ["/usr/bin/systemctl", "restart", TESTD_SERVICE],
        "restart testd service",
    )


def run_test_history_command(
    runner: Runner,
    release: Path,
    argv: Sequence[str],
    *,
    label: str,
) -> dict[str, object]:
    return runner.require_json(
        [
            "/usr/sbin/runuser",
            "--user",
            TESTD_USER,
            "--",
            str(test_history_wrapper(release)),
            *argv,
        ],
        label,
    )


def test_store_paths() -> tuple[Path, Path, Path]:
    return (
        Path(str(TEST_DATABASE) + "-shm"),
        Path(str(TEST_DATABASE) + "-wal"),
        TEST_DATABASE,
    )


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def require_real_directory(path: Path, *, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise SwitchError(f"{label} is unavailable: {path}") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SwitchError(f"{label} is not a real directory: {path}")
    return metadata


def create_fresh_test_spool(*, expected_test_uid: int) -> None:
    TEST_SPOOL.mkdir(mode=0o700)
    created = [TEST_SPOOL]
    try:
        for name in TEST_SPOOL_QUEUES:
            path = TEST_SPOOL / name
            path.mkdir(mode=0o700)
            created.append(path)
        for path in created:
            os.chown(path, expected_test_uid, -1)
        fsync_directory(TEST_SPOOL)
        fsync_directory(TEST_SPOOL.parent)
    except BaseException:
        shutil.rmtree(TEST_SPOOL, ignore_errors=True)
        raise


def verify_fresh_test_spool() -> None:
    require_real_directory(TEST_SPOOL, label="fresh test spool")
    observed = {entry.name for entry in TEST_SPOOL.iterdir()}
    if observed != set(TEST_SPOOL_QUEUES):
        raise SwitchError("fresh test spool has unexpected entries")
    for name in TEST_SPOOL_QUEUES:
        queue = TEST_SPOOL / name
        require_real_directory(queue, label="fresh test spool queue")
        if any(queue.iterdir()):
            raise SwitchError("fresh test spool queue is not empty")


def discard_test_spool(
    reset: Mapping[str, object], *, rollback: bool, runner: Runner
) -> dict[str, object]:
    require_test_plane_stopped(runner)
    discard_key = (
        "rollback_discarded_spool" if rollback else "forward_discarded_spool"
    )
    discarded_path = Path(str(reset[discard_key]))
    if discarded_path.parent != TEST_SPOOL.parent:
        raise SwitchError("test spool discard path leaves the service state directory")
    try:
        discarded_metadata = discarded_path.lstat()
    except FileNotFoundError:
        discarded_metadata = None
    if discarded_metadata is not None and (
        not stat.S_ISDIR(discarded_metadata.st_mode)
        or stat.S_ISLNK(discarded_metadata.st_mode)
    ):
        raise SwitchError("test spool discard target is not a real directory")

    # A retained discard directory is replay evidence that the prior spool
    # existed and was already atomically rotated before interruption.
    discarded_existing = discarded_metadata is not None
    if discarded_metadata is None:
        try:
            current_metadata = TEST_SPOOL.lstat()
        except FileNotFoundError:
            current_metadata = None
        if current_metadata is not None:
            if (
                not stat.S_ISDIR(current_metadata.st_mode)
                or stat.S_ISLNK(current_metadata.st_mode)
            ):
                raise SwitchError("test spool is not a real directory")
            os.replace(TEST_SPOOL, discarded_path)
            fsync_directory(TEST_SPOOL.parent)
            discarded_existing = True
    elif TEST_SPOOL.exists():
        # Replay after the old spool was rotated must see only the empty spool
        # created by this exact reset operation.  Nothing can legitimately add
        # entries while both testd and its activation socket are stopped.
        verify_fresh_test_spool()

    if not TEST_SPOOL.exists():
        create_fresh_test_spool(expected_test_uid=int(reset["expected_test_uid"]))
    verify_fresh_test_spool()

    if discarded_path.exists():
        shutil.rmtree(discarded_path)
        fsync_directory(TEST_SPOOL.parent)
    return {
        "test_spool": str(TEST_SPOOL),
        "discarded_path": str(discarded_path),
        "discarded_existing": discarded_existing,
        "queues": list(TEST_SPOOL_QUEUES),
        "fresh": True,
    }


def discard_test_store_triplet() -> list[str]:
    discarded: list[str] = []
    for path in test_store_paths():
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise SwitchError(f"test-history rollback path is not a regular file: {path}")
        path.unlink()
        discarded.append(str(path))
    fsync_directory(TEST_DATABASE.parent)
    return discarded


def reset_test_history_for_release(
    release: Path,
    document: dict[str, object],
    journal_path: Path,
    runner: Runner,
) -> None:
    reset = dict(require_test_history_reset_mode(document, requested=True) or {})
    if reset.get("status") == "complete":
        return
    if reset.get("status") not in {"planned", "resetting"}:
        raise SwitchError("test-history reset cannot run from the recorded state")
    reset.update({"status": "resetting", "started_at": reset.get("started_at") or now()})
    save_phase(journal_path, document, "applying", test_history_reset=reset)
    stop_test_plane(runner)
    spool_evidence = discard_test_spool(reset, rollback=False, runner=runner)
    result = run_test_history_command(
        runner,
        release,
        [
            "initialize-fresh",
            "--test-database",
            str(TEST_DATABASE),
            "--operation-id",
            str(reset["operation_id"]),
            "--attestation-output",
            str(reset["attestation"]),
            "--expected-test-uid",
            str(reset["expected_test_uid"]),
            "--confirm-discard-test-history",
            "discard-test-history",
        ],
        label="initialize fresh current Test Store",
    )
    fingerprint = result.get("attestation_fingerprint")
    if (
        result.get("action") != "test-store-initialize-fresh"
        or result.get("branch") != "attested-fresh"
        or result.get("attestation") != reset["attestation"]
        or not isinstance(fingerprint, str)
        or RELEASE_RE.fullmatch(fingerprint) is None
        or not isinstance(result.get("store_generation"), str)
    ):
        raise SwitchError("fresh Test Store evidence is invalid")
    reset.update(
        {
            "status": "complete",
            "completed_at": now(),
            "forward_evidence": {
                "action": result["action"],
                "schema_version": result["schema_version"],
                "branch": result["branch"],
                "attestation": result["attestation"],
                "attestation_fingerprint": fingerprint,
                "store_generation": result["store_generation"],
                "discarded_existing": result.get("discarded_existing"),
                "replayed": result.get("replayed"),
                "spool": spool_evidence,
            },
        }
    )
    save_phase(journal_path, document, "applying", test_history_reset=reset)


def reset_test_history_for_rollback(
    document: dict[str, object],
    journal_path: Path,
    runner: Runner,
) -> None:
    reset = dict(require_test_history_reset_mode(document, requested=True) or {})
    if reset.get("status") == "rolled-back":
        return
    if reset.get("status") not in {"resetting", "complete", "rollback-resetting"}:
        raise SwitchError("test-history rollback cannot run from the recorded state")
    reset.update(
        {
            "status": "rollback-resetting",
            "rollback_started_at": reset.get("rollback_started_at") or now(),
        }
    )
    save_phase(journal_path, document, "rolling-back", test_history_reset=reset)
    stop_test_plane(runner)
    spool_evidence = discard_test_spool(reset, rollback=True, runner=runner)
    discarded = discard_test_store_triplet()
    previous_release = Path(str(reset["previous_release"]))
    result = run_test_history_command(
        runner,
        previous_release,
        [
            "create",
            "--test-database",
            str(TEST_DATABASE),
            "--expected-test-uid",
            str(reset["expected_test_uid"]),
        ],
        label="initialize previous-release empty test history",
    )
    if (
        result.get("action") != "create"
        or result.get("test_database") != str(TEST_DATABASE)
        or result.get("schema_version")
        != reset["expected_previous_test_store_schema_version"]
        or not isinstance(result.get("store_generation"), str)
    ):
        raise SwitchError("previous release returned invalid empty-store evidence")
    reset.update(
        {
            "status": "rolled-back",
            "rollback_completed_at": now(),
            "rollback_evidence": {
                "action": result["action"],
                "schema_version": result["schema_version"],
                "store_generation": result["store_generation"],
                "test_database": result["test_database"],
                "discarded_paths": discarded,
                "spool": spool_evidence,
                "release": str(previous_release),
            },
        }
    )
    save_phase(journal_path, document, "rolling-back", test_history_reset=reset)


def slot_status(
    runner: Runner, release: Path, control: str, label: str
) -> dict[str, object]:
    return runner.require_json(
        [
            str(release / "bin/devcoordinator-console-slot-control"),
            "status",
            "--socket",
            control,
        ],
        label,
    )


def unit_diagnostics(runner: Runner, unit: str) -> dict[str, object]:
    """Return bounded startup evidence without turning diagnostics into policy."""

    commands = {
        "systemd": [
            "/usr/bin/systemctl",
            "show",
            unit,
            "--no-pager",
            "--property=Id,LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,StatusErrno",
        ],
        "journal": [
            "/usr/bin/journalctl",
            "--unit",
            unit,
            "--no-pager",
            "--output=short-iso",
            "--lines=80",
        ],
    }
    evidence: dict[str, object] = {}
    for name, argv in commands.items():
        result = runner.run(argv)
        combined = (result.stdout + result.stderr).strip()
        evidence[name] = {
            "returncode": result.returncode,
            "output": combined[-16_384:],
        }
    return evidence


def wait_slot_status(
    runner: Runner,
    release: Path,
    control: str,
    unit: str,
    label: str,
    *,
    timeout_seconds: float = 30.0,
) -> dict[str, object]:
    """Wait for the supervisor-owned socket after systemd executes the process."""

    deadline = time.monotonic() + timeout_seconds
    last_error = "control socket was not queried"
    while True:
        try:
            return slot_status(runner, release, control, label)
        except SwitchError as error:
            last_error = str(error)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            diagnostics = unit_diagnostics(runner, unit)
            raise SwitchError(
                f"{label} did not become ready within {timeout_seconds:g}s: "
                f"{last_error}; diagnostics={json.dumps(diagnostics, sort_keys=True)}"
            )
        time.sleep(min(0.1, remaining))


def http_health(url: str, timeout: float) -> dict[str, object]:
    started = time.monotonic()
    try:
        with urlopen(
            Request(url, headers={"Accept": "application/json"}), timeout=timeout
        ) as response:
            status = int(response.status)
            body = response.read(1024 * 1024)
    except HTTPError as error:
        return {"url": url, "ok": False, "status": int(error.code)}
    except (OSError, URLError):
        return {"url": url, "ok": False, "status": None}
    document: object | None = None
    try:
        document = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return {
        "url": url,
        "ok": 200 <= status < 300,
        "status": status,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "document": document,
    }


def wait_edge_publication(
    url: str,
    *,
    release_digest: str,
    generation: int,
    timeout_seconds: float = 8.0,
) -> dict[str, object]:
    """Wait for the running edge to adopt the root-published snapshot."""

    deadline = time.monotonic() + timeout_seconds
    last: dict[str, object] = {"url": url, "ok": False, "status": None}
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SwitchError(
                "running edge did not adopt Console publication "
                f"generation {generation} for release {release_digest}; "
                f"last={json.dumps(last, sort_keys=True)}"
            )
        last = http_health(url, min(2.0, remaining))
        document = last.get("document")
        if (
            last.get("ok") is True
            and isinstance(document, Mapping)
            and document.get("release") == release_digest
            and document.get("generation") == generation
        ):
            return last
        time.sleep(min(0.1, max(0.0, remaining)))


def direct_https_health(port: int, path: str, timeout: float = 8.0) -> dict[str, object]:
    started = time.monotonic()
    status: int | None = None
    body = b""
    try:
        context = ssl.create_default_context()
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=CONSOLE_HOST) as stream:
                request = (
                    f"GET {path} HTTP/1.1\r\nHost: {CONSOLE_HOST}\r\n"
                    "Accept: application/json\r\nConnection: close\r\n\r\n"
                ).encode("ascii")
                stream.sendall(request)
                chunks: list[bytes] = []
                while sum(len(item) for item in chunks) < 1024 * 1024:
                    block = stream.recv(65536)
                    if not block:
                        break
                    chunks.append(block)
                response = b"".join(chunks)
        head, _separator, body = response.partition(b"\r\n\r\n")
        first = head.splitlines()[0].decode("ascii")
        status = int(first.split()[1])
    except (OSError, ssl.SSLError, ValueError, IndexError, UnicodeError):
        pass
    return {
        "url": f"https://127.0.0.1:{port}{path}",
        "ok": status is not None and 200 <= status < 300,
        "status": status,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "body_sha256": hashlib.sha256(body).hexdigest() if body else None,
    }


def require_probe(result: Mapping[str, object], label: str) -> None:
    if result.get("ok") is not True:
        raise SwitchError(f"{label} failed with status {result.get('status')}")


def publication_cli(release: Path) -> Path:
    command = release / "bin/devcoordinator-edge-publication"
    if not command.is_file() or not os.access(command, os.X_OK):
        raise SwitchError("immutable release lacks edge publication tooling")
    return command


def switch_publication(
    runner: Runner,
    release: Path,
    *,
    digest: str,
    port: int,
) -> dict[str, object]:
    verified = runner.require_json(
        [
            str(publication_cli(release)),
            "verify",
            "--file",
            str(PUBLICATION_FILE),
            "--release-root",
            str(release.parent),
        ],
        "edge publication verification",
    )
    return runner.require_json(
        [
            str(publication_cli(release)),
            "switch-console",
            "--file",
            str(PUBLICATION_FILE),
            "--release-root",
            str(release.parent),
            "--expected-payload-sha256",
            str(verified["payload_sha256"]),
            "--release-digest",
            digest,
            "--port",
            str(port),
            "--published-at",
            now(),
        ],
        "edge Console publication switch",
    )


def legacy_retirement_path(unit: str) -> Path:
    return UNIT_ROOT / f"{unit}.d" / LEGACY_RETIREMENT_DROPIN


def legacy_retirement_guard_installed(unit: str) -> bool:
    path = legacy_retirement_path(unit)
    try:
        return path.is_file() and not path.is_symlink() and path.read_bytes() == LEGACY_RETIREMENT_PAYLOAD
    except OSError:
        return False


def retire_legacy_control_plane(runner: Runner) -> None:
    # Schema-13 authority/API replaced the checkout-bound schema-12 services.
    # Disabling alone is insufficient: an enabled Restart=always project unit
    # may retain Wants= edges to either legacy unit and reactivate it. Install
    # one persistent false condition before stopping both units so stale reverse
    # dependencies remain harmless across project restarts and host reboots.
    if LEGACY_ENABLE_MARKER.exists() or LEGACY_ENABLE_MARKER.is_symlink():
        if LEGACY_ENABLE_MARKER.is_dir():
            raise SwitchError("legacy control-plane enable marker is a directory")
        LEGACY_ENABLE_MARKER.unlink()
    for unit in LEGACY_CONTROL_PLANE_SERVICES:
        atomic_bytes(
            legacy_retirement_path(unit),
            LEGACY_RETIREMENT_PAYLOAD,
            0o644,
        )
    runner.require(
        ["/usr/bin/systemctl", "daemon-reload"],
        "load legacy control-plane retirement guards",
    )
    for unit in LEGACY_CONTROL_PLANE_SERVICES:
        runner.require(
            ["/usr/bin/systemctl", "disable", "--now", unit],
            f"retire legacy control-plane unit {unit}",
        )
        runner.require(
            ["/usr/bin/systemctl", "reset-failed", unit],
            f"clear retired control-plane failure state {unit}",
        )


def normalize_local_paths(runner: Runner) -> None:
    runner.require(
        [
            "/usr/bin/systemd-sysusers",
            str(SYSUSERS_ROOT / "devcoordinator-availability.sysusers.conf"),
        ],
        "systemd service identity preparation",
    )
    runner.require(
        [
            "/usr/bin/systemd-tmpfiles",
            "--create",
            str(TMPFILES_ROOT / "devcoordinator.conf"),
            str(TMPFILES_ROOT / "devcoordinator-availability.tmpfiles.conf"),
        ],
        "systemd runtime path preparation",
    )
    # Rollback can restore an older tmpfiles policy that predates the dedicated
    # lifecycle publication root.  Recreate the exact root here as well so a
    # post-promotion rollback remains replayable before the successor policy is
    # installed again.  Never accept a symlink or non-directory in its place.
    try:
        lifecycle_root = BROWSER_LIFECYCLE_ROOT.lstat()
    except FileNotFoundError:
        BROWSER_LIFECYCLE_ROOT.mkdir(mode=0o755)
        lifecycle_root = BROWSER_LIFECYCLE_ROOT.lstat()
    if stat.S_ISLNK(lifecycle_root.st_mode) or not stat.S_ISDIR(
        lifecycle_root.st_mode
    ):
        raise SwitchError(
            "browser lifecycle publication root is not a directory: "
            f"{BROWSER_LIFECYCLE_ROOT}"
        )
    os.chmod(BROWSER_LIFECYCLE_ROOT, 0o755)
    for publication in (BROWSER_LIFECYCLE_STATE, BROWSER_LIFECYCLE_LOCK):
        try:
            info = publication.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise SwitchError(
                f"browser lifecycle publication is not a regular file: {publication}"
            )
        os.chmod(publication, 0o644)
    if not CLIENT_PROFILE.is_file() or CLIENT_PROFILE.is_symlink():
        raise SwitchError("non-secret local client profile is unavailable")
    # Local Unix accounts are one trusted developer.  Publish this non-secret
    # profile for direct reads instead of relying on shared-group membership.
    os.chmod(CLIENT_PROFILE, 0o644)
    publish_browser_runtime_inventory()
    # Same-schema delivery never takes the authority database offline.  Any
    # inherited marker therefore belongs to an abandoned legacy cutover and
    # must not keep every local account fenced after this healthy switch.
    MAINTENANCE_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(MAINTENANCE_ROOT, 0o755)
    try:
        marker = MAINTENANCE_MARKER.lstat()
    except FileNotFoundError:
        pass
    else:
        if stat.S_ISDIR(marker.st_mode):
            raise SwitchError("stale maintenance marker path is a directory")
        MAINTENANCE_MARKER.unlink()


def verify_browser_lifecycle_publication() -> dict[str, object]:
    """Prove the actual caller can traverse and read lifecycle telemetry."""

    try:
        parent = BROWSER_LIFECYCLE_ROOT.lstat()
    except OSError as error:
        raise SwitchError(f"browser lifecycle parent is unavailable: {error}") from error
    parent_ok = (
        stat.S_ISDIR(parent.st_mode)
        and not stat.S_ISLNK(parent.st_mode)
        and stat.S_IMODE(parent.st_mode) == 0o755
    )
    publications: dict[str, object] = {}
    for path in (BROWSER_LIFECYCLE_STATE, BROWSER_LIFECYCLE_LOCK):
        try:
            info = path.lstat()
        except FileNotFoundError:
            publications[str(path)] = {"present": False, "ok": True}
            continue
        ok = (
            stat.S_ISREG(info.st_mode)
            and not stat.S_ISLNK(info.st_mode)
            and stat.S_IMODE(info.st_mode) == 0o644
        )
        publications[str(path)] = {
            "present": True,
            "mode": stat.S_IMODE(info.st_mode),
            "ok": ok,
        }
    ok = parent_ok and all(
        bool(item["ok"])
        for item in publications.values()
        if isinstance(item, Mapping)
    )
    return {
        "ok": ok,
        "parent": str(BROWSER_LIFECYCLE_ROOT),
        "parent_mode": stat.S_IMODE(parent.st_mode),
        "publications": publications,
    }


def save_phase(path: Path, document: dict[str, object], phase: str, **values: object) -> None:
    document.update(values)
    document["phase"] = phase
    atomic_json(path, document)


def apply(
    release: Path,
    transaction_root: Path,
    runner: Runner,
    *,
    reset_test_history: bool = False,
) -> dict[str, object]:
    release = release.resolve(strict=True)
    transaction_root = require_transaction_root(
        transaction_root,
        release_digest=release.name,
    )
    journal_path = transaction_root / "journal.json"
    document = load_journal(journal_path)
    if document is None:
        document = prepare(
            release,
            transaction_root,
            runner,
            reset_test_history=reset_test_history,
        )
    if document.get("release") != str(release):
        raise SwitchError("same-schema journal belongs to another release")
    reset = require_test_history_reset_mode(
        document, requested=reset_test_history
    )
    rebaseline = retained_rebaseline_intent(document)
    if document.get("phase") == "applied":
        validate_headless_browser_cleanup_plan(document, release)
        if reset is not None and reset.get("status") != "complete":
            raise SwitchError("applied same-schema reset lacks completion evidence")
        if rebaseline["required"] is True and rebaseline["status"] != "applied":
            raise SwitchError("applied release lacks retained-control rebaseline evidence")
        if rebaseline["required"] is True:
            apply_retained_control_rebaseline(
                document, journal_path, transaction_root, runner
            )
        return document
    if document.get("phase") not in {"prepared", "applying"}:
        raise SwitchError("same-schema journal cannot be applied from this phase")
    if rebaseline["required"] is True and rebaseline["status"] != "applied":
        if rebaseline["status"] in {"planned", "backed-up", "prepared"}:
            # Freeze every authority writer before the first worker unit or
            # process is removed. The resulting proof is therefore terminal
            # and exact before any candidate file reaches the live graph.
            stop_authority_writers(runner)
            bind_source_worker_quiescence(
                document, rebaseline, journal_path, runner
            )
        else:
            # A publishing replay can temporarily expose either schema; its
            # exact schema-15 proof is rechecked after predecessor restore.
            require_no_managed_worker_units(runner)

    if document.get("already_active") is True:
        validate_headless_browser_cleanup_plan(document, release)
        if reset is None:
            raise SwitchError("already-active same-schema transaction is incomplete")
        reset_test_history_for_release(release, document, journal_path, runner)
        restart_test_plane(runner)
        save_phase(journal_path, document, "applied", completed_at=now())
        return document

    candidate = str(document["candidate_console_unit"])
    candidate_already_active = unit_active(runner, candidate)
    if (
        candidate_already_active
        and rebaseline["required"] is True
        and rebaseline["status"] != "applied"
    ):
        raise SwitchError("active candidate predates retained-control completion")
    ports = [int(document["candidate_outer_port"]), int(document["candidate_inner_port"])]
    reservations = [] if candidate_already_active else bind_exact_ports(ports)
    try:
        if not document.get("backups"):
            document["backups"] = backup_destinations(document, transaction_root)
        save_phase(journal_path, document, "applying")
        directory_states = document.get("codex_directory_states")
        if not isinstance(directory_states, Mapping):
            raise SwitchError("Codex configuration directory plan is unavailable")
        prepare_codex_directories(directory_states)
        retire_legacy_control_plane(runner)
        rendered = Path(str(document["rendered_units"]))
        install_rendered_destinations(rendered)
        candidate_slot = SLOT_ROOT / f"{document['release_digest']}.env"
        atomic_bytes(
            candidate_slot,
            Path(str(document["candidate_console_slot_source"])).read_bytes(),
            0o644,
        )
        normalize_local_paths(runner)
        runner.require(["/usr/bin/systemctl", "daemon-reload"], "systemd daemon reload")
        if reset is not None:
            reset_test_history_for_release(release, document, journal_path, runner)
        perform_headless_browser_cleanup(
            release,
            document,
            journal_path,
            runner,
        )
        apply_retained_control_rebaseline(
            document, journal_path, transaction_root, runner
        )
        require_current_authority_schema()
        restart_services(runner)
        complete_retained_control_rebaseline(
            document, journal_path, transaction_root, runner
        )
    finally:
        for listener in reservations:
            listener.close()

    previous = str(document["previous_console_unit"])
    candidate_control = str(document["candidate_control_socket"])
    previous_control = str(document["previous_control_socket"])
    runner.require(["/usr/bin/systemctl", "enable", "--now", candidate], "candidate Console start")
    candidate_status = wait_slot_status(
        runner,
        release,
        candidate_control,
        candidate,
        "candidate Console status",
    )
    if candidate_status.get("release_digest") != document["release_digest"]:
        raise SwitchError("candidate Console status has another release")
    require_probe(
        direct_https_health(int(document["candidate_outer_port"]), "/_devcoordinator/slot-health"),
        "candidate Console supervisor health",
    )
    save_phase(journal_path, document, "applying", candidate_started=True)

    try:
        previous_status = wait_slot_status(
            runner,
            release,
            previous_control,
            previous,
            "previous Console status",
            timeout_seconds=2,
        )
    except SwitchError:
        previous_status = None
    candidate_status = slot_status(runner, release, candidate_control, "candidate Console status")
    live_before_promotion = publication_snapshot()
    previous_is_published = (
        live_before_promotion["release_digest"] == document["previous_release_digest"]
        and live_before_promotion["port"] == document["previous_outer_port"]
    )
    if (
        candidate_status.get("mode") == "active"
        and (previous_status is None or previous_status.get("mode") == "standby")
    ):
        promoted = True
    elif candidate_status.get("mode") == "standby" and (
        previous_status is not None and previous_status.get("mode") == "active"
        or previous_status is None and previous_is_published
    ):
        command = [
            str(release / "bin/devcoordinator-console-slot-control"),
            "promote",
            "--socket",
            candidate_control,
            "--timeout-seconds",
            "30",
        ]
        if previous_status is not None:
            command.extend(["--old-socket", previous_control])
        runner.require_json(command, "candidate Console promotion")
        promoted = True
    else:
        raise SwitchError("Console slots are not in one promotable state")
    require_probe(
        direct_https_health(int(document["candidate_outer_port"]), "/healthz"),
        "candidate Console direct health",
    )
    save_phase(journal_path, document, "applying", promoted=promoted)

    live = publication_snapshot()
    if live["release_digest"] == document["release_digest"] and live["port"] == document["candidate_outer_port"]:
        published = live
        switched = True
    elif live["release_digest"] == document["previous_release_digest"] and live["port"] == document["previous_outer_port"]:
        published = switch_publication(
            runner,
            release,
            digest=str(document["release_digest"]),
            port=int(document["candidate_outer_port"]),
        )
        switched = True
    else:
        raise SwitchError("edge publication has an unknown Console target")
    save_phase(journal_path, document, "applying", publication_switched=switched)
    wait_edge_publication(
        "https://console.vr.ae/healthz",
        release_digest=str(document["release_digest"]),
        generation=int(published["generation"]),
    )

    runner.require(["/usr/bin/systemctl", "stop", previous], "previous Console drain")
    runner.run(["/usr/bin/systemctl", "disable", previous])
    save_phase(
        journal_path,
        document,
        "applied",
        candidate_console_slot=str(candidate_slot),
        completed_at=now(),
    )
    return document


def verify(
    release: Path,
    transaction_root: Path,
    runner: Runner,
    *,
    public_url: str,
    api_url: str,
    reset_test_history: bool = False,
) -> dict[str, object]:
    release = release.resolve(strict=True)
    transaction_root = require_transaction_root(
        transaction_root,
        release_digest=release.name,
    )
    document = load_journal(transaction_root / "journal.json")
    if document is None or document.get("release") != str(release):
        raise SwitchError("same-schema switch journal is unavailable")
    if document.get("phase") != "applied":
        raise SwitchError("same-schema switch is not applied")
    reset = require_test_history_reset_mode(
        document, requested=reset_test_history
    )
    if reset is not None and reset.get("status") != "complete":
        raise SwitchError("same-schema test-history reset is incomplete")
    rebaseline = retained_rebaseline_intent(document)
    if rebaseline["required"] is True and rebaseline["status"] != "applied":
        raise SwitchError("retained-control rebaseline is incomplete")
    if rebaseline["required"] is True:
        backups = rebaseline.get("backups")
        if not isinstance(backups, Mapping):
            raise SwitchError("retained-control verification lost its exact backups")
        validate_retained_rebaseline_paths(rebaseline, transaction_root)
        manifest = _load_bound_retained_manifest(rebaseline, transaction_root, backups)
        _require_post_start_retained_target(
            manifest, backups, transaction_root
        )
    authority_schema = require_current_authority_schema()
    units = [*SERVICE_ORDER, *REQUIRED_SOCKETS, str(document["candidate_console_unit"])]
    states = {unit: unit_active(runner, unit) for unit in units}
    enabled_states = {unit: unit_enabled(runner, unit) for unit in units}
    legacy_control_plane = {
        unit: {
            "active": unit_active(runner, unit),
            "enabled": unit_enabled(runner, unit),
            "retirement_guard": legacy_retirement_guard_installed(unit),
        }
        for unit in LEGACY_CONTROL_PLANE_SERVICES
    }
    for evidence in legacy_control_plane.values():
        evidence["retired"] = (
            evidence["active"] is False
            and evidence["enabled"] is False
            and evidence["retirement_guard"] is True
        )
    legacy_control_plane_retired = (
        not LEGACY_ENABLE_MARKER.exists()
        and not LEGACY_ENABLE_MARKER.is_symlink()
        and all(bool(evidence["retired"]) for evidence in legacy_control_plane.values())
    )
    legacy_broker_retired = bool(
        legacy_control_plane[LEGACY_BROKER_SERVICE]["retired"]
    )
    probes = [
        http_health(api_url, 5.0),
        direct_https_health(int(document["candidate_outer_port"]), "/healthz"),
        unix_socket_health(Path("/run/devcoordinator-testd/testd.sock")),
        unix_socket_health(Path("/run/devcoordinator-test-snapshotd/snapshot.sock")),
    ]
    status = slot_status(
        runner,
        release,
        str(document["candidate_control_socket"]),
        "candidate Console status",
    )
    publication = runner.require_json(
        [
            str(publication_cli(release)),
            "verify",
            "--file",
            str(PUBLICATION_FILE),
            "--release-root",
            str(release.parent),
        ],
        "edge publication verification",
    )
    probes.append(
        wait_edge_publication(
            public_url,
            release_digest=str(document["release_digest"]),
            generation=int(publication["generation"]),
        )
    )
    profile_readable = False
    try:
        with CLIENT_PROFILE.open("rb") as handle:
            profile_readable = bool(handle.read(1))
    except OSError:
        profile_readable = False
    rendered = Path(str(document["rendered_units"]))
    browser_runtime_inventory = verify_public_browser_runtime_inventory()
    browser_lifecycle_publication = verify_browser_lifecycle_publication()
    installed_host_contracts: dict[str, object] = {}
    rendered_destinations = destinations(rendered)
    for name, expected_mode in (
        (MAIN_TMPFILES_RENDERED, 0o644),
        ("devcoordinator-availability.tmpfiles.conf", 0o644),
        (CERTBOT_HOOK_RENDERED, 0o700),
    ):
        destination = rendered_destinations[name]
        regular = destination.is_file() and not destination.is_symlink()
        mode = destination.stat().st_mode & 0o777 if regular else None
        installed_host_contracts[name] = {
            "destination": str(destination),
            "regular_file": regular,
            "mode": mode,
            "expected_mode": expected_mode,
            "sha256_matches": regular
            and digest_file(destination) == digest_file(rendered / name),
            "ok": regular
            and mode == expected_mode
            and digest_file(destination) == digest_file(rendered / name),
        }
    installed_client_access: dict[str, object] = {}
    for name in (
        *STABLE_LAUNCHERS,
        READ_ONLY_RULE_RENDERED,
        TEST_RULE_RENDERED,
    ):
        destination = destinations(rendered)[name]
        expected_mode = destination_mode(name)
        regular = destination.is_file() and not destination.is_symlink()
        actual_mode = destination.stat().st_mode & 0o777 if regular else None
        installed_client_access[name] = {
            "destination": str(destination),
            "regular_file": regular,
            "sha256_matches": regular
            and digest_file(destination) == digest_file(rendered / name),
            "mode": actual_mode,
            "expected_mode": expected_mode,
            "ok": regular
            and actual_mode == expected_mode
            and digest_file(destination) == digest_file(rendered / name),
        }
    launcher_results = {
        rendered_name: runner.run([str(destination), "--help"])
        for rendered_name, (destination, _immutable_name) in STABLE_LAUNCHERS.items()
    }
    launcher_healthy = all(
        result.returncode == 0 for result in launcher_results.values()
    )
    codex_directories: dict[str, object] = {}
    for directory in (CODEX_ROOT, CODEX_RULE_ROOT):
        regular_directory = directory.is_dir() and not directory.is_symlink()
        mode = directory.stat().st_mode & 0o777 if regular_directory else None
        owner_uid = directory.stat().st_uid if regular_directory else None
        expected_mode = codex_directory_mode(directory)
        codex_directories[str(directory)] = {
            "directory": regular_directory,
            "mode": mode,
            "expected_mode": expected_mode,
            "owner_uid": owner_uid,
            "expected_owner_uid": os.geteuid(),
            "ok": regular_directory
            and mode == expected_mode
            and owner_uid == os.geteuid(),
        }
    ok = (
        all(states.values())
        and all(enabled_states.values())
        and legacy_control_plane_retired
        and all(bool(item["ok"]) for item in probes)
        and status.get("mode") == "active"
        and status.get("release_digest") == document["release_digest"]
        and publication.get("release_digest") == document["release_digest"]
        and profile_readable
        and browser_runtime_inventory["ok"] is True
        and browser_lifecycle_publication["ok"] is True
        and all(bool(item["ok"]) for item in installed_host_contracts.values())
        and all(bool(item["ok"]) for item in installed_client_access.values())
        and launcher_healthy
        and all(bool(item["ok"]) for item in codex_directories.values())
        and authority_schema == COORDINATOR_SCHEMA_VERSION
    )
    result = {
        "ok": ok,
        "release_digest": document["release_digest"],
        "services": states,
        "services_enabled": enabled_states,
        "legacy_broker_retired": legacy_broker_retired,
        "legacy_control_plane_retired": legacy_control_plane_retired,
        "legacy_control_plane": legacy_control_plane,
        "probes": probes,
        "console_slot": status,
        "publication": publication,
        "client_profile_readable": profile_readable,
        "browser_runtime_inventory": browser_runtime_inventory,
        "browser_lifecycle_publication": browser_lifecycle_publication,
        "installed_host_contracts": installed_host_contracts,
        "codex_client_access": installed_client_access,
        "codex_read_only_access": {
            name: installed_client_access[name]
            for name in (
                CLIENT_LAUNCHER_RENDERED,
                BUG_LAUNCHER_RENDERED,
                CALL_LOG_LAUNCHER_RENDERED,
                READ_ONLY_RULE_RENDERED,
            )
        },
        "codex_test_access": {
            name: installed_client_access[name]
            for name in (TEST_LAUNCHER_RENDERED, TEST_RULE_RENDERED)
        },
        "client_launcher_help": {
            name: {
                "ok": completed.returncode == 0,
                "returncode": completed.returncode,
                "stderr": completed.stderr[-1000:],
            }
            for name, completed in launcher_results.items()
        },
        "test_launcher_help": {
            "ok": launcher_results[TEST_LAUNCHER_RENDERED].returncode == 0,
            "returncode": launcher_results[TEST_LAUNCHER_RENDERED].returncode,
            "stderr": launcher_results[TEST_LAUNCHER_RENDERED].stderr[-1000:],
        },
        "codex_rule_directories": codex_directories,
        "test_history_reset": dict(reset) if reset is not None else None,
        "retained_control_rebaseline": rebaseline,
        "authority_schema_version": authority_schema,
    }
    return result


def rollback(
    release: Path,
    transaction_root: Path,
    runner: Runner,
    *,
    reset_test_history: bool = False,
) -> dict[str, object]:
    release = release.resolve(strict=True)
    transaction_root = require_transaction_root(
        transaction_root,
        release_digest=release.name,
    )
    journal_path = transaction_root / "journal.json"
    document = load_journal(journal_path)
    if document is None or document.get("release") != str(release):
        raise SwitchError("same-schema rollback journal is unavailable")
    reset = require_test_history_reset_mode(
        document, requested=reset_test_history
    )
    if document.get("phase") == "rolled-back":
        return document
    backups = document.get("backups")
    if not isinstance(backups, Mapping) or not backups:
        # Apply failed before touching the installed graph.
        if reset is not None and reset.get("status") in {
            "resetting",
            "complete",
            "rollback-resetting",
        }:
            reset_test_history_for_rollback(document, journal_path, runner)
            restart_test_plane(runner)
        rebaseline = retained_rebaseline_intent(document)
        if rebaseline["required"] is True:
            rollback_worker_expectations = (
                rebaseline["source_worker_quiescence"]
                if _valid_source_worker_quiescence(
                    rebaseline.get("source_worker_quiescence")
                )
                else source_worker_policy_expectations(runner)
            )
            if rebaseline["status"] not in {"planned", "rolled-back"}:
                restore_retained_control_rebaseline(
                    document, journal_path, transaction_root, runner
                )
            restart_services(runner)
            require_retained_worker_policy_convergence(
                runner,
                source_proof=rollback_worker_expectations,
                target_schema_version=retained_control.REBASELINE_SOURCE_SCHEMA,
                generation_offset=0,
            )
            restart_previous_console(release, document, runner)
        save_phase(journal_path, document, "rolled-back", completed_at=now())
        return document

    candidate = str(document["candidate_console_unit"])
    previous = str(document["previous_console_unit"])
    candidate_control = str(document["candidate_control_socket"])
    previous_control = str(document["previous_control_socket"])

    live = publication_snapshot()
    live_is_candidate = (
        live["release_digest"] == document["release_digest"]
        and live["port"] == document["candidate_outer_port"]
    )
    live_is_previous = (
        live["release_digest"] == document["previous_release_digest"]
        and live["port"] == document["previous_outer_port"]
    )
    if not live_is_candidate and not live_is_previous:
        raise SwitchError("rollback found an unknown edge Console target")
    if document.get("phase") in {
        "rollback-control-plane-restored",
        "rollback-background-restored",
    }:
        if not live_is_previous:
            raise SwitchError(
                "resumed rollback found the previous Console publication absent"
            )
        return complete_rollback_after_control_plane(
            document, journal_path, runner
        )

    # Restore the schema-15 data before any previous binary or Console writer
    # is allowed to start.  This also converges a crash after any one of the
    # retained control or credential files was replaced.
    restore_retained_control_rebaseline(
        document, journal_path, transaction_root, runner
    )
    restore_destination_backups(backups)
    directory_states = document.get("codex_directory_states")
    if not isinstance(directory_states, Mapping):
        raise SwitchError("Codex configuration directory rollback plan is unavailable")
    restore_codex_directories(directory_states)
    retire_legacy_control_plane(runner)
    runner.require(["/usr/bin/systemctl", "daemon-reload"], "rollback daemon reload")
    if reset is not None and reset.get("status") in {
        "resetting",
        "complete",
        "rollback-resetting",
    }:
        reset_test_history_for_rollback(document, journal_path, runner)
    normalize_local_paths(runner)
    restore_rollback_control_plane(runner)

    # Both Console writers were stopped by retained-data restoration. Start
    # only the exact previous instance after the old units and authority are
    # coherent, then return the edge publication to it.
    runner.run(["/usr/bin/systemctl", "disable", candidate])
    runner.require(["/usr/bin/systemctl", "enable", "--now", previous], "previous Console restore")
    final_status = wait_slot_status(
        runner,
        release,
        previous_control,
        previous,
        "previous Console final status",
    )
    if final_status.get("mode") != "active":
        promotion = [
            str(release / "bin/devcoordinator-console-slot-control"),
            "promote",
            "--socket",
            previous_control,
            "--timeout-seconds",
            "30",
        ]
        runner.require_json(promotion, "previous Console promotion")
        final_status = wait_slot_status(
            runner,
            release,
            previous_control,
            previous,
            "previous Console promoted status",
        )
    if final_status.get("mode") != "active":
        raise SwitchError("restored previous Console slot is not active")
    if live_is_candidate:
        switch_publication(
            runner,
            release,
            digest=str(document["previous_release_digest"]),
            port=int(document["previous_outer_port"]),
        )
    require_probe(
        direct_https_health(int(document["previous_outer_port"]), "/healthz"),
        "restored Console final direct health",
    )
    require_probe(
        http_health("https://console.vr.ae/healthz", 8.0),
        "restored Console final public health",
    )
    save_phase(
        journal_path,
        document,
        "rollback-control-plane-restored",
        rollback_control_plane_restored_at=now(),
    )
    return complete_rollback_after_control_plane(
        document, journal_path, runner
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    actions = result.add_subparsers(dest="action", required=True)
    for name in (
        "prepare",
        "apply",
        "rollback",
        "verify",
        "acceptance-begin",
        "finalize",
        "supersede-prepared",
    ):
        action = actions.add_parser(name)
        action.add_argument("--release", type=Path, required=True)
        action.add_argument("--transaction-root", type=Path, required=True)
        if name == "supersede-prepared":
            action.add_argument("--expected-current-release-digest", required=True)
        else:
            action.add_argument(
                "--reset-test-history",
                action="store_true",
                help=(
                    "discard only the isolated test-history store and attempt spool, "
                    "then initialize an empty current-schema test plane while testd is stopped"
                ),
            )
        if name == "verify":
            action.add_argument("--public-url", default="https://console.vr.ae/healthz")
            action.add_argument("--api-url", default="http://127.0.0.1:29876/healthz")
    return result


def public_switch_result(action: str, value: Mapping[str, object]) -> dict[str, object]:
    """Return a bounded path-, backup-, and credential-evidence-free CLI result."""

    if action not in {
        "prepare",
        "apply",
        "rollback",
        "verify",
        "acceptance-begin",
        "finalize",
        "supersede-prepared",
    }:
        raise SwitchError("same-schema public result action is invalid")
    release_digest = value.get("release_digest")
    if not isinstance(release_digest, str) or RELEASE_RE.fullmatch(release_digest) is None:
        raise SwitchError("same-schema public result release identity is invalid")
    result: dict[str, object] = {
        "ok": (
            value.get("ok") is True
            if action in {"verify", "acceptance-begin"}
            else True
        ),
        "action": action,
        "release_digest": release_digest,
        "phase": str(value.get("phase") or ("verified" if action == "verify" else action)),
    }
    previous = value.get("previous_release_digest")
    if isinstance(previous, str) and RELEASE_RE.fullmatch(previous) is not None:
        result["previous_release_digest"] = previous
    rebaseline = value.get("retained_control_rebaseline")
    if isinstance(rebaseline, Mapping):
        result["retained_control_rebaseline"] = {
            field: rebaseline.get(field)
            for field in (
                "required",
                "status",
                "source_schema_version",
                "target_schema_version",
            )
        }
    reset = value.get("test_history_reset")
    if isinstance(reset, Mapping):
        result["test_history_reset"] = {
            field: reset.get(field) for field in ("required", "status")
        }
    authority_schema = value.get("authority_schema_version")
    if type(authority_schema) is int:
        result["authority_schema_version"] = authority_schema
    successor = value.get("successor_release_digest")
    if isinstance(successor, str) and RELEASE_RE.fullmatch(successor) is not None:
        result["successor_release_digest"] = successor
    return result


def require_live_rollback_identity(
    release: Path,
    transaction_root: Path,
    *,
    reset_test_history: bool,
) -> dict[str, object]:
    """Prove the exact published release without requiring healthy services."""

    document = load_journal(transaction_root / "journal.json")
    if (
        document is None
        or document.get("release") != str(release)
        or document.get("release_digest") != release.name
        or document.get("phase") != "applied"
    ):
        raise SwitchError("late rollback lacks its exact applied journal")
    require_test_history_reset_mode(document, requested=reset_test_history)
    unit = f"devcoordinator-console@{release.name}.service"
    slot = SLOT_ROOT / f"{release.name}.env"
    recorded_slot = document.get("candidate_console_slot")
    if (
        document.get("candidate_console_unit") != unit
        or (
            document.get("already_active") is not True
            and recorded_slot != str(slot)
        )
        or not slot.is_file()
        or slot.is_symlink()
    ):
        raise SwitchError("late rollback Console slot identity changed")
    values = parse_slot(slot.read_text(encoding="utf-8"))
    try:
        ports_match = (
            int(values["HTTPS_PORT"]) == int(document["candidate_outer_port"])
            and int(values["DEVCOORDINATOR_CONSOLE_INNER_PORT"])
            == int(document["candidate_inner_port"])
        )
    except (KeyError, TypeError, ValueError) as error:
        raise SwitchError("late rollback Console slot evidence is invalid") from error
    if (
        values.get("DEVCOORDINATOR_RELEASE_DIGEST") != release.name
        or values.get("DEVCOORDINATOR_CONSOLE_CONTROL_SOCKET")
        != document.get("candidate_control_socket")
        or not ports_match
    ):
        raise SwitchError("late rollback Console slot no longer names this release")
    published = publication_snapshot()
    if (
        published.get("release_digest") != release.name
        or published.get("port") != document.get("candidate_outer_port")
    ):
        raise SwitchError("late rollback release is no longer published")
    rendered = Path(str(document.get("rendered_units") or ""))
    template = "devcoordinator-console@.service"
    source = rendered / template
    installed = UNIT_ROOT / template
    if any(not path.is_file() or path.is_symlink() for path in (source, installed)):
        raise SwitchError("late rollback Console unit identity is unavailable")
    if digest_file(source) != digest_file(installed):
        raise SwitchError("late rollback Console unit belongs to another release")
    return document


def execute_fenced_switch_action(
    action: str,
    release: Path,
    transaction_root: Path,
    runner: Runner,
    *,
    public_url: str = "https://console.vr.ae/healthz",
    api_url: str = "http://127.0.0.1:29876/healthz",
    reset_test_history: bool = False,
    expected_current_release_digest: str | None = None,
    expected_uid: int = 0,
    expected_gid: int = 0,
    lock_path: Path = installer_fence.DEFAULT_INSTALLER_LOCK,
    claim_path: Path = installer_fence.DEFAULT_INSTALLER_CLAIM,
) -> dict[str, object]:
    """Run one switch phase beneath the exact durable software-delivery owner."""

    release = release.expanduser().resolve(strict=True)
    transaction_root = require_transaction_root(
        transaction_root, release_digest=release.name
    )
    prior_terminal: dict[str, object] | None = None
    if action == "acceptance-begin":
        _identity_path, _terminal_path, prior_identity = delivery_fence_binding(
            transaction_root,
            release_digest=release.name,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        prior_terminal = delivery_fence_terminal(
            transaction_root,
            prior_identity,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        if prior_terminal is None or prior_terminal.get("outcome") != "deployed":
            raise SwitchError(
                "software delivery acceptance requires one completed exact deployment"
            )
    fence_action = {
        "prepare": "prepare",
        "apply": "prepare",
        "verify": "recover",
        "rollback": "abort",
        "acceptance-begin": "recover",
        "finalize": "finalize",
        "supersede-prepared": "recover",
    }.get(action)
    if fence_action is None:
        raise SwitchError("same-schema fenced action is invalid")
    handle, identity = acquire_delivery_fence(
        transaction_root,
        release_digest=release.name,
        action=fence_action,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        lock_path=lock_path,
        claim_path=claim_path,
    )
    command_succeeded = False
    terminal_cleanup = False
    try:
        if action == "acceptance-begin":
            locked_terminal = delivery_fence_terminal(
                transaction_root,
                identity,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
            if (
                locked_terminal != prior_terminal
                or locked_terminal is None
                or locked_terminal.get("outcome") != "deployed"
            ):
                raise SwitchError(
                    "software delivery acceptance terminal changed before claim"
                )
            prior_terminal = locked_terminal
        elif prior_terminal is None:
            prior_terminal = delivery_fence_terminal(
                transaction_root,
                identity,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
        if (
            action in {"prepare", "apply"}
            and prior_terminal is not None
            and prior_terminal.get("outcome") == "superseded-before-mutation"
        ):
            if handle.created_claim:
                handle.mark_complete()
                terminal_cleanup = True
            raise SwitchError(
                "superseded prepared transaction cannot prepare or apply again"
            )
        if action in {"prepare", "apply"} and handle.created_claim:
            if prior_terminal is not None:
                remove_delivery_fence_document(
                    transaction_root / DELIVERY_FENCE_TERMINAL_NAME,
                    prior_terminal,
                    expected_uid=expected_uid,
                    expected_gid=expected_gid,
                )
        if action == "supersede-prepared":
            if (
                not isinstance(expected_current_release_digest, str)
                or RELEASE_RE.fullmatch(expected_current_release_digest) is None
            ):
                raise SwitchError("prepared supersession requires current release digest")
            document, journal_sha256 = require_supersedable_prepared_journal(
                transaction_root / "journal.json",
                candidate_release=release,
                successor_release_digest=expected_current_release_digest,
            )
            live = require_current_live_release_identity(
                release.parent / expected_current_release_digest
            )
            live_sha256 = str(live["evidence_sha256"])
            expected_terminal = {
                "operation_id": identity["operation_id"],
                "release_digest": identity["release_digest"],
                "outcome": "superseded-before-mutation",
                "successor_release_digest": expected_current_release_digest,
                "journal_sha256": journal_sha256,
                "live_evidence_sha256": live_sha256,
            }
            if prior_terminal is None:
                prior_terminal = delivery_fence_terminal(
                    transaction_root,
                    identity,
                    expected_uid=expected_uid,
                    expected_gid=expected_gid,
                    publish_outcome="superseded-before-mutation",
                    successor_release_digest=expected_current_release_digest,
                    journal_sha256=journal_sha256,
                    live_evidence_sha256=live_sha256,
                )
            if (
                prior_terminal is None
                or any(
                    prior_terminal.get(key) != expected
                    for key, expected in expected_terminal.items()
                )
            ):
                raise SwitchError("prepared supersession terminal changed identity")
            handle.mark_complete()
            value = {
                **document,
                "phase": "superseded-before-mutation",
                "successor_release_digest": expected_current_release_digest,
            }
        elif action == "prepare":
            value = prepare(
                release,
                transaction_root,
                runner,
                reset_test_history=reset_test_history,
            )
        elif action == "apply":
            value = apply(
                release,
                transaction_root,
                runner,
                reset_test_history=reset_test_history,
            )
        elif action == "rollback":
            if handle.created_claim and prior_terminal is not None:
                if prior_terminal.get("outcome") == "rolled-back":
                    value = load_journal(transaction_root / "journal.json")
                    if (
                        value is None
                        or value.get("release") != str(release)
                        or value.get("phase") != "rolled-back"
                    ):
                        raise SwitchError(
                            "idempotent rollback lacks exact terminal journal evidence"
                        )
                    require_test_history_reset_mode(
                        value, requested=reset_test_history
                    )
                    handle.mark_complete()
                    command_succeeded = True
                    return value
                try:
                    require_live_rollback_identity(
                        release,
                        transaction_root,
                        reset_test_history=reset_test_history,
                    )
                except BaseException:
                    handle.mark_complete()
                    terminal_cleanup = True
                    raise
            value = rollback(
                release,
                transaction_root,
                runner,
                reset_test_history=reset_test_history,
            )
            if value.get("phase") != "rolled-back":
                raise SwitchError("same-schema rollback lacks terminal journal evidence")
            delivery_fence_terminal(
                transaction_root,
                identity,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
                publish_outcome="rolled-back",
            )
            handle.mark_complete()
        elif action in {"verify", "acceptance-begin"}:
            value = verify(
                release,
                transaction_root,
                runner,
                public_url=public_url,
                api_url=api_url,
                reset_test_history=reset_test_history,
            )
            if action == "verify" and handle.created_claim:
                # A standalone read after a completed deployment borrows the
                # exact claim only for the duration of this verification.
                handle.mark_complete()
            elif (
                action == "acceptance-begin"
                and handle.created_claim
                and value.get("ok") is not True
            ):
                handle.mark_complete()
        else:
            document = load_journal(transaction_root / "journal.json")
            if (
                document is None
                or document.get("release") != str(release)
                or document.get("phase") != "applied"
            ):
                raise SwitchError(
                    "software delivery cannot finalize before the release is applied"
                )
            require_test_history_reset_mode(
                document, requested=reset_test_history
            )
            live = verify(
                release,
                transaction_root,
                runner,
                public_url=public_url,
                api_url=api_url,
                reset_test_history=reset_test_history,
            )
            if live.get("ok") is not True:
                raise SwitchError(
                    "software delivery cannot finalize a release that is no longer live"
                )
            delivery_fence_terminal(
                transaction_root,
                identity,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
                publish_outcome="deployed",
            )
            handle.mark_complete()
            value = {**document, "phase": "finalized"}
        command_succeeded = True
        return value
    except BaseException:
        journal = transaction_root / "journal.json"
        if (
            action in {"prepare", "apply"}
            and handle.created_claim
            and not journal.exists()
            and not journal.is_symlink()
        ):
            remove_delivery_fence_document(
                transaction_root / DELIVERY_FENCE_IDENTITY_NAME,
                identity,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
        elif (
            action
            in {"verify", "acceptance-begin", "finalize", "supersede-prepared"}
            and handle.created_claim
        ):
            terminal = delivery_fence_terminal(
                transaction_root,
                identity,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
            if terminal is not None:
                handle.mark_complete()
                terminal_cleanup = True
        raise
    finally:
        handle.close(command_succeeded=command_succeeded or terminal_cleanup)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise SwitchError("same-schema release switch must run as root")
        value = execute_fenced_switch_action(
            args.action,
            args.release,
            args.transaction_root,
            Runner(),
            public_url=getattr(args, "public_url", "https://console.vr.ae/healthz"),
            api_url=getattr(args, "api_url", "http://127.0.0.1:29876/healthz"),
            reset_test_history=getattr(args, "reset_test_history", False),
            expected_current_release_digest=getattr(
                args, "expected_current_release_digest", None
            ),
        )
    except (
        SwitchError,
        installer.ReleaseError,
        installer_fence.InstallerFenceError,
        OSError,
        ValueError,
    ) as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(public_switch_result(args.action, value), sort_keys=True))
    if args.action in {"verify", "acceptance-begin"} and value.get("ok") is not True:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
