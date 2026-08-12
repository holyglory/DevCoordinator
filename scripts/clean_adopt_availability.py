#!/usr/bin/env python3
"""Fast, explicit adoption of the availability graph onto empty stores.

This is the intentionally destructive alternative to the schema-12 history
bridge.  It retains only the four small Console control files, creates empty
current authority/inventory/test stores, catalogs canonical repositories from
their checked-in runtime manifests, and then uses the existing immutable
release and first-listener handoff primitives to install the availability
graph.  Repository worktrees and project databases/volumes are never inputs
to cleanup and are never removed by this program.

The command is root-only for ``apply``.  ``plan`` is read-only and may be run
before the maintenance window.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import quote
import uuid


ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = ROOT / "skills/codex-dev-coordinator/scripts"
for candidate in (ROOT / "scripts", MODULE_ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

import activate_availability_release as activation  # noqa: E402
import install_availability_release as installer  # noqa: E402
import orchestrate_availability_cutover as cutover  # noqa: E402
from devcoordinator.inventory_projection import (  # noqa: E402
    empty_inventory,
    envelope as inventory_envelope,
    initialize_inventory_store,
    publish_projection,
    read_inventory_store,
    verify_inventory_store,
)
from devcoordinator.normalized_server_lifecycle import (  # noqa: E402
    NormalizedPortLifecycle,
)
from devcoordinator.store import AccountStore, deterministic_id, utc_timestamp  # noqa: E402
from devcoordinator.schema import SCHEMA_VERSION  # noqa: E402
from devcoordinator.universal_test_store import UniversalTestStore  # noqa: E402
from devcoordinator.universal_test_transport import (  # noqa: E402
    TestPlaneTransportError,
    UnixTestPlaneClient,
)
from server_wide_installer_fence import acquire_installer_mutex  # noqa: E402


MANIFEST_VERSION = 2
MANIFEST_KIND = "devcoordinator-clean-adoption"
JOURNAL_KIND = "devcoordinator-clean-adoption-transaction"
CONSOLE_STATE_FILES = (
    "routes.json",
    "upstream-auth.json",
    "access-control.json",
    "telegram-control.json",
)
RELEASE_RE = re.compile(r"^[0-9a-f]{64}$")
CONSOLE_UNIT_RE = re.compile(
    r"^devcoordinator-console@[0-9a-f]{64}\.service$"
)
PORT_RANGE_RE = re.compile(r"^(\d{1,5})-(\d{1,5})$")
SERVER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
TEST_SETUP_CANARY_ATTEMPTS = 16
TEST_SETUP_CANARY_RETRY_DELAYS = (1, 2, 3, *(5 for _ in range(12)))
TEST_SETUP_CANARY_MAX_RETRY_SECONDS = 5
TRANSIENT_TEST_SETUP_CODES = frozenset({"test_repository_setup_unavailable"})
TEST_PLANE_SOCKET_OWNER_UID = 0

DEFAULT_DESTINATIONS = {
    "authority_database": "/var/lib/devcoordinator/authority.sqlite3",
    "test_database": "/var/lib/devcoordinator-testd/tests.sqlite3",
    "inventory_database": "/var/lib/devcoordinator-observer/inventory.sqlite3",
    "inventory_publication": "/var/lib/devcoordinator-observer/inventory.publication",
    "profile": "/etc/devcoordinator/client-profiles.json",
    "console_state": "/var/lib/devcoordinator-console",
    "edge_identity_state": "/var/lib/devcoordinator-edge",
    "console_config": "/etc/devcoordinator/console.env",
    "route_resolution": "/var/lib/devcoordinator/clean-adoption/route-resolution.json",
    "publication_input": "/var/lib/devcoordinator/clean-adoption/publication-input.json",
    "publication": "/var/lib/devcoordinator-edge/routes.publication",
    "telegram_destination": "/var/lib/devcoordinator-notifications/telegram-control.json",
}
DESTINATION_FIELDS = frozenset(DEFAULT_DESTINATIONS)
PORT_FIELDS = frozenset(
    {
        "console_outer",
        "console_inner",
        "handoff_http",
        "handoff_https",
        "handoff_api",
    }
)
MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "release",
        "rendered_units",
        "candidate_slot_source",
        "legacy_console_env",
        "legacy_console_state",
        "legacy_console_uid",
        "legacy_console_gid",
        "legacy_console_home",
        "background_project_root",
        "console_state_files",
        "destinations",
        "ports",
        "repositories",
    }
)
REPOSITORY_FIELDS = frozenset(
    {
        "canonical_root",
        "runtime_file",
        "port_range",
        "fixed_ports",
        "approve_compose_host_access",
        "compose_run_once_services",
    }
)
FIXED_PORT_FIELDS = frozenset({"name", "port"})


class CleanAdoptionError(RuntimeError):
    """The clean-adoption contract or transaction is invalid."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise CleanAdoptionError(f"manifest is not bounded JSON: {error}") from error


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _absolute(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise CleanAdoptionError(f"{label} must be one absolute path")
    path = Path(value)
    if not path.is_absolute() or os.path.normpath(value) != value:
        raise CleanAdoptionError(f"{label} must be one normalized absolute path")
    return path


def _normalize_maintenance_root(
    path: Path, *, expected_uid: int, expected_gid: int
) -> dict[str, object]:
    """Adopt the exact disposable /run directory into the current topology.

    Older installations used the retired shared service group and mode 0750.
    Clean adoption already owns the global installer mutex and runs as root, so
    requiring an administrator to repair this volatile directory by hand only
    makes a deterministic upgrade fail before maintenance can be published.
    Never replace an existing object: only create the missing directory or
    normalize an exact, root-owned real directory in place.
    """

    path = _absolute(str(path), "maintenance root")
    created = False
    try:
        before = path.lstat()
    except FileNotFoundError:
        try:
            os.mkdir(path, 0o755)
            created = True
        except FileExistsError:
            pass
        try:
            before = path.lstat()
        except OSError as error:
            raise CleanAdoptionError(
                "clean-adoption maintenance directory cannot be created"
            ) from error
    except OSError as error:
        raise CleanAdoptionError(
            "clean-adoption maintenance directory cannot be inspected"
        ) from error
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISDIR(before.st_mode)
        or before.st_uid != expected_uid
    ):
        raise CleanAdoptionError(
            "clean-adoption maintenance directory is not an owned real directory"
        )
    if before.st_gid != expected_gid:
        os.chown(path, -1, expected_gid)
    if stat.S_IMODE(before.st_mode) != 0o755:
        os.chmod(path, 0o755)
    marker = path / "maintenance.json"
    marker_mode: str | None = None
    try:
        marker_before = marker.lstat()
    except FileNotFoundError:
        marker_before = None
    except OSError as error:
        raise CleanAdoptionError(
            "clean-adoption maintenance marker cannot be inspected"
        ) from error
    if marker_before is not None:
        if (
            stat.S_ISLNK(marker_before.st_mode)
            or not stat.S_ISREG(marker_before.st_mode)
            or marker_before.st_uid != expected_uid
        ):
            raise CleanAdoptionError(
                "clean-adoption maintenance marker is not an owned real file"
            )
        if marker_before.st_gid != expected_gid:
            os.chown(marker, -1, expected_gid)
        if stat.S_IMODE(marker_before.st_mode) != 0o644:
            os.chmod(marker, 0o644)
        marker_after = marker.lstat()
        if (
            stat.S_ISLNK(marker_after.st_mode)
            or not stat.S_ISREG(marker_after.st_mode)
            or (marker_after.st_dev, marker_after.st_ino)
            != (marker_before.st_dev, marker_before.st_ino)
            or marker_after.st_uid != expected_uid
            or marker_after.st_gid != expected_gid
            or stat.S_IMODE(marker_after.st_mode) != 0o644
        ):
            raise CleanAdoptionError(
                "clean-adoption maintenance marker normalization did not converge"
            )
        marker_mode = "0644"
    after = path.lstat()
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISDIR(after.st_mode)
        or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
        or after.st_uid != expected_uid
        or after.st_gid != expected_gid
        or stat.S_IMODE(after.st_mode) != 0o755
    ):
        raise CleanAdoptionError(
            "clean-adoption maintenance directory normalization did not converge"
        )
    return {
        "path": str(path),
        "created": created,
        "owner_uid": after.st_uid,
        "owner_gid": after.st_gid,
        "mode": "0755",
        "marker_mode": marker_mode,
    }


def _positive_uid(value: object, label: str, *, allow_root: bool = False) -> int:
    minimum = 0 if allow_root else 1
    if type(value) is not int or int(value) < minimum:
        raise CleanAdoptionError(f"{label} is invalid")
    return int(value)


def _read_legacy_regular(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    maximum: int,
) -> tuple[bytes, dict[str, object]]:
    """Read one bounded, stable legacy regular file without UID/mode policy."""

    try:
        before = path.lstat()
    except OSError as error:
        raise CleanAdoptionError(f"cannot inspect {path}: {error}") from error
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 1
        or before.st_size > maximum
    ):
        raise CleanAdoptionError(f"private source file is unsafe: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            stat.S_IMODE(opened.st_mode),
        ) != (
            before.st_dev,
            before.st_ino,
            stat.S_IMODE(before.st_mode),
        ):
            raise CleanAdoptionError(f"legacy source changed before read: {path}")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = path.lstat()
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        opened_after.st_dev,
        opened_after.st_ino,
        opened_after.st_size,
        opened_after.st_mtime_ns,
    ) or (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise CleanAdoptionError(f"private source file changed while read: {path}")
    if len(payload) != before.st_size or len(payload) > maximum:
        raise CleanAdoptionError(f"private source file size changed while read: {path}")
    return payload, {
        "path": str(path),
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "owner_uid": before.st_uid,
        "owner_gid": before.st_gid,
        "mode": f"{stat.S_IMODE(before.st_mode):04o}",
    }

def _normalize_repository(value: object, *, index: int) -> dict[str, object]:
    label = f"repositories[{index}]"
    if not isinstance(value, Mapping) or set(value) != REPOSITORY_FIELDS:
        raise CleanAdoptionError(f"{label} fields are invalid")
    root = _absolute(value["canonical_root"], f"{label}.canonical_root")
    runtime = _absolute(value["runtime_file"], f"{label}.runtime_file")
    expected_runtime = root / ".codex/dev-runtime.json"
    if runtime != expected_runtime:
        raise CleanAdoptionError(
            f"{label}.runtime_file must be the canonical repo-local .codex/dev-runtime.json"
        )
    port_match = PORT_RANGE_RE.fullmatch(str(value["port_range"]))
    if port_match is None:
        raise CleanAdoptionError(f"{label}.port_range is invalid")
    port_start, port_end = (int(port_match.group(1)), int(port_match.group(2)))
    if not 1 <= port_start <= port_end <= 65535:
        raise CleanAdoptionError(f"{label}.port_range is invalid")
    fixed_value = value["fixed_ports"]
    if not isinstance(fixed_value, list) or len(fixed_value) > 1024:
        raise CleanAdoptionError(f"{label}.fixed_ports are invalid")
    fixed_ports: list[dict[str, object]] = []
    for fixed_index, fixed in enumerate(fixed_value):
        fixed_label = f"{label}.fixed_ports[{fixed_index}]"
        if not isinstance(fixed, Mapping) or set(fixed) != FIXED_PORT_FIELDS:
            raise CleanAdoptionError(f"{fixed_label} fields are invalid")
        name = fixed["name"]
        port = fixed["port"]
        if not isinstance(name, str) or SERVER_NAME_RE.fullmatch(name) is None:
            raise CleanAdoptionError(f"{fixed_label}.name is invalid")
        if type(port) is not int or not port_start <= int(port) <= port_end:
            raise CleanAdoptionError(f"{fixed_label}.port is outside the repository range")
        fixed_ports.append({"name": name, "port": int(port)})
    fixed_names = [str(item["name"]) for item in fixed_ports]
    fixed_values = [int(item["port"]) for item in fixed_ports]
    if (
        fixed_names != sorted(fixed_names)
        or len(fixed_names) != len(set(fixed_names))
        or len(fixed_values) != len(set(fixed_values))
    ):
        raise CleanAdoptionError(
            f"{label}.fixed_ports must be name-sorted with unique names and ports"
        )
    if type(value["approve_compose_host_access"]) is not bool:
        raise CleanAdoptionError(f"{label}.approve_compose_host_access is invalid")
    compose_services = value["compose_run_once_services"]
    if not isinstance(compose_services, list) or any(
        not isinstance(item, str) or not item or len(item.encode("utf-8")) > 256
        for item in compose_services
    ) or len(compose_services) != len(set(compose_services)):
        raise CleanAdoptionError(f"{label}.compose_run_once_services are invalid")
    return {
        "canonical_root": str(root),
        "runtime_file": str(runtime),
        "port_range": f"{port_start}-{port_end}",
        "fixed_ports": fixed_ports,
        "approve_compose_host_access": bool(value["approve_compose_host_access"]),
        "compose_run_once_services": list(compose_services),
    }


def validate_manifest(
    document: object,
    *,
    expected_uid: int | None = None,
    current_uid: int | None = None,
) -> dict[str, object]:
    """Normalize one exact clean-adoption request without touching live state."""

    if not isinstance(document, Mapping) or set(document) != MANIFEST_FIELDS:
        raise CleanAdoptionError("clean-adoption manifest fields are invalid")
    if document.get("schema_version") != MANIFEST_VERSION or document.get("kind") != MANIFEST_KIND:
        raise CleanAdoptionError("clean-adoption manifest discriminator is unsupported")
    if expected_uid is not None:
        actual = os.geteuid() if current_uid is None else int(current_uid)
        if actual != int(expected_uid):
            raise CleanAdoptionError("clean-adoption caller UID is invalid")
    release = _absolute(document["release"], "release")
    if release.parent != Path("/opt/devcoordinator/releases") or RELEASE_RE.fullmatch(release.name) is None:
        raise CleanAdoptionError("release must be one immutable production digest path")
    path_fields = (
        "rendered_units",
        "candidate_slot_source",
        "legacy_console_env",
        "legacy_console_state",
        "legacy_console_home",
        "background_project_root",
    )
    paths = {name: str(_absolute(document[name], name)) for name in path_fields}
    legacy_uid = _positive_uid(document["legacy_console_uid"], "legacy_console_uid")
    legacy_gid = _positive_uid(document["legacy_console_gid"], "legacy_console_gid")
    state_files = document["console_state_files"]
    if not isinstance(state_files, list) or tuple(state_files) != CONSOLE_STATE_FILES:
        raise CleanAdoptionError(
            "clean adoption preserves exactly routes, upstream auth, access, and Telegram state"
        )
    destinations_value = document["destinations"]
    if not isinstance(destinations_value, Mapping) or set(destinations_value) != DESTINATION_FIELDS:
        raise CleanAdoptionError("clean-adoption destination fields are invalid")
    destinations = {
        name: str(_absolute(destinations_value[name], f"destinations.{name}"))
        for name in sorted(DESTINATION_FIELDS)
    }
    if len(set(destinations.values())) != len(destinations):
        raise CleanAdoptionError("clean-adoption destinations must be distinct")
    ports_value = document["ports"]
    if not isinstance(ports_value, Mapping) or set(ports_value) != PORT_FIELDS:
        raise CleanAdoptionError("clean-adoption port fields are invalid")
    ports = {name: ports_value[name] for name in sorted(PORT_FIELDS)}
    if any(type(value) is not int or not 30000 <= int(value) <= 60999 for value in ports.values()) or len(set(ports.values())) != len(ports):
        raise CleanAdoptionError("clean-adoption ports must be distinct high ports")
    repositories_value = document["repositories"]
    if not isinstance(repositories_value, list) or not repositories_value or len(repositories_value) > 1024:
        raise CleanAdoptionError("clean-adoption repositories are invalid")
    repositories = [
        _normalize_repository(item, index=index)
        for index, item in enumerate(repositories_value)
    ]
    roots = [str(item["canonical_root"]) for item in repositories]
    if roots != sorted(roots) or len(roots) != len(set(roots)):
        raise CleanAdoptionError("clean-adoption repositories must be unique and sorted")
    fixed_ports = [
        int(fixed["port"])
        for repository in repositories
        for fixed in repository["fixed_ports"]
    ]
    if len(fixed_ports) != len(set(fixed_ports)):
        raise CleanAdoptionError(
            "clean-adoption fixed ports must be globally unique"
        )
    background = paths["background_project_root"]
    if background not in roots:
        raise CleanAdoptionError("background project must be one cataloged canonical repository")
    normalized = {
        "schema_version": MANIFEST_VERSION,
        "kind": MANIFEST_KIND,
        "release": str(release),
        **paths,
        "legacy_console_uid": legacy_uid,
        "legacy_console_gid": legacy_gid,
        "console_state_files": list(CONSOLE_STATE_FILES),
        "destinations": destinations,
        "ports": ports,
        "repositories": repositories,
    }
    if len(_canonical(normalized)) > 2 * 1024 * 1024:
        raise CleanAdoptionError("clean-adoption manifest exceeds its byte budget")
    return normalized


def fresh_store_plan(validated: Mapping[str, object]) -> dict[str, object]:
    manifest = validate_manifest(validated)
    destinations = manifest["destinations"]
    if not isinstance(destinations, Mapping):
        raise CleanAdoptionError("clean-adoption destinations disappeared")
    return {
        "authority_database": str(destinations["authority_database"]),
        "test_database": str(destinations["test_database"]),
        "inventory_database": str(destinations["inventory_database"]),
        "inventory_publication": str(destinations["inventory_publication"]),
        "discarded_history": [
            "authority/runtime history",
            "inventory/telemetry history",
            "test runs/cases/artifacts/rollups",
        ],
        "preserved_console_files": list(CONSOLE_STATE_FILES),
        "project_storage_mutated": False,
    }

def catalog_repositories_offline(
    validated: Mapping[str, object],
    *,
    expected_uid: int = 0,
) -> dict[str, object]:
    """Seed only host-wide repository routing records into a fresh authority."""

    manifest = validate_manifest(validated)
    if os.geteuid() != expected_uid or expected_uid != 0:
        raise CleanAdoptionError("offline repository cataloging must run as root")
    database = Path(str(manifest["destinations"]["authority_database"]))
    store = AccountStore.open(database, expected_uid=expected_uid)
    try:
        host_id = store.ensure_local_host()
        timestamp = utc_timestamp()
        repository_ids: dict[str, str] = {}
        with store.immediate_transaction() as connection:
            for repository in manifest["repositories"]:
                root = str(repository["canonical_root"])
                repo_id = deterministic_id("repository", host_id, root)
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name,
                        state, generation, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'active', 0, ?, ?)
                    """,
                    (repo_id, host_id, root, Path(root).name or root, timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation,
                        reason, actor, updated_at
                    ) VALUES (?, 'installed', 0, 0, ?, 'clean-adoption', ?)
                    """,
                    (repo_id, "trusted-local repository catalog", timestamp),
                )
                repository_ids[root] = repo_id
    finally:
        store.close()
    return {
        "host_id": host_id,
        "repository_ids": repository_ids,
        "repository_count": len(repository_ids),
        "access_model": "trusted-local",
    }


def replay_fixed_ports_offline(
    validated: Mapping[str, object],
    *,
    expected_uid: int = 0,
) -> dict[str, object]:
    """Seed retained assignments directly into the stopped fresh authority.

    Clean adoption deliberately runs behind the global maintenance fence.  A
    normal Broker client must remain fenced there, so fixed assignments are
    replayed through the normalized persistence service before the authority
    socket is started.  This helper is root-only in production and verifies the
    exact resulting active projection before returning.
    """

    manifest = validate_manifest(validated)
    if os.geteuid() != expected_uid or expected_uid != 0:
        raise CleanAdoptionError("offline fixed-port replay must run as root")
    database = Path(str(manifest["destinations"]["authority_database"]))
    store = AccountStore.open(database, expected_uid=expected_uid)
    try:
        lifecycle = NormalizedPortLifecycle(store)
        results = [
            lifecycle.assign(
                agent="clean-adoption",
                canonical_project=str(repository["canonical_root"]),
                name=str(fixed["name"]),
                port=int(fixed["port"]),
                force=True,
            )
            for repository in manifest["repositories"]
            for fixed in repository["fixed_ports"]
        ]
        expected = [
            (
                str(repository["canonical_root"]),
                str(fixed["name"]),
                int(fixed["port"]),
            )
            for repository in manifest["repositories"]
            for fixed in repository["fixed_ports"]
        ]
        retained = lifecycle.list_assignments(active_only=True)
    finally:
        store.close()
    actual = [
        (str(item["project"]), str(item["name"]), int(item["port"]))
        for item in results
    ]
    retained_exact = sorted(
        (str(item["project"]), str(item["name"]), int(item["port"]))
        for item in retained
    )
    if actual != expected or retained_exact != sorted(expected):
        raise CleanAdoptionError("offline fixed-port replay is contradictory")
    if any(item.get("status") != "active" for item in results):
        raise CleanAdoptionError("offline fixed-port replay is not active")
    return {"count": len(results), "assignments": results}


def activate_fresh_authority(
    database: Path | str, *, expected_uid: int
) -> dict[str, object]:
    """Activate a newly created authority without importing history."""

    store = AccountStore.open(database, expected_uid=expected_uid)
    try:
        metadata = store.connection.execute(
            "SELECT schema_version,database_generation,migration_state FROM schema_metadata WHERE singleton=1"
        ).fetchone()
        if metadata is not None and tuple(metadata)[::2] == (SCHEMA_VERSION, "empty"):
            activated_at = _now()
            with store.immediate_transaction(revision_kind=None) as connection:
                connection.execute(
                    """
                    UPDATE schema_metadata
                    SET authority_mode='sqlite', migration_state='ready',
                        first_sqlite_mutation_at=COALESCE(first_sqlite_mutation_at, ?),
                        updated_at=?
                    WHERE singleton=1 AND schema_version=?
                      AND migration_state='empty'
                    """,
                    (activated_at, activated_at, SCHEMA_VERSION),
                )
            metadata = store.connection.execute(
                "SELECT schema_version,database_generation,migration_state FROM schema_metadata WHERE singleton=1"
            ).fetchone()
    finally:
        store.close()
    if metadata is None or int(metadata[0]) != SCHEMA_VERSION or str(metadata[2]) != "ready":
        raise CleanAdoptionError(
            f"fresh authority did not initialize at ready schema {SCHEMA_VERSION}"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "database_generation": str(metadata[1]),
        "migration_state": "ready",
    }


def initialize_fresh_stores(
    plan: Mapping[str, object],
    *,
    current_uid: int | None = None,
    expected_uid: int | None = None,
) -> dict[str, object]:
    """Create empty current stores when all three are owned by this process.

    Production ``apply`` uses the immutable bootstrap helpers to create the
    testd/observer-owned stores.  This compact helper exists for validation,
    local installs where one UID owns every store, and focused regression
    tests; it still refuses every pre-existing destination.
    """

    actual_uid = os.geteuid() if current_uid is None else int(current_uid)
    wanted_uid = actual_uid if expected_uid is None else int(expected_uid)
    if actual_uid != wanted_uid or actual_uid != os.geteuid():
        raise CleanAdoptionError("fresh store initialization UID is invalid")
    required = {
        "authority_database",
        "test_database",
        "inventory_database",
        "inventory_publication",
    }
    if not isinstance(plan, Mapping) or not required <= set(plan):
        raise CleanAdoptionError("fresh store plan is incomplete")
    paths = {name: _absolute(plan[name], name) for name in required}
    if any(path.exists() or path.is_symlink() for path in paths.values()):
        raise CleanAdoptionError("fresh store destination already exists")
    for parent in {path.parent for path in paths.values()}:
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if parent.stat().st_uid != actual_uid or stat.S_IMODE(parent.stat().st_mode) & 0o077:
            raise CleanAdoptionError(f"fresh store parent is unsafe: {parent}")
    authority = activate_fresh_authority(
        paths["authority_database"], expected_uid=actual_uid
    )
    test_store = UniversalTestStore.create(
        paths["test_database"], expected_uid=actual_uid
    )
    test_summary = test_store.verify()
    initial = inventory_envelope(
        generation=1,
        inventory=empty_inventory(),
        published_at=_now(),
    )
    initialize_inventory_store(
        paths["inventory_database"],
        initial,
        owner_uid=actual_uid,
        owner_gid=os.getegid(),
    )
    publish_projection(
        paths["inventory_publication"],
        initial,
        owner_uid=actual_uid,
        owner_gid=os.getegid(),
        mode=0o600,
    )
    retained = verify_inventory_store(
        paths["inventory_database"],
        paths["inventory_publication"],
        expected_owner_uid=actual_uid,
    )
    return {
        "ok": True,
        "authority_schema_version": SCHEMA_VERSION,
        "authority_generation": authority["database_generation"],
        "test_schema_version": test_summary["schema_version"],
        "test_store_generation": test_summary["store_generation"],
        "inventory_generation": retained["generation"],
    }


def _load_manifest(path: Path, *, expected_uid: int | None = None) -> dict[str, object]:
    path = _absolute(str(path), "manifest")
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size < 1
        or info.st_size > 2 * 1024 * 1024
        or (expected_uid is not None and info.st_uid != expected_uid)
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise CleanAdoptionError("clean-adoption manifest file is unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CleanAdoptionError(f"clean-adoption manifest cannot be read: {error}") from error
    return validate_manifest(value)


def _source_evidence(manifest: Mapping[str, object]) -> dict[str, object]:
    uid = int(manifest["legacy_console_uid"])
    gid = int(manifest["legacy_console_gid"])
    state = Path(str(manifest["legacy_console_state"]))
    evidence: dict[str, object] = {}
    _payload, env_evidence = _read_legacy_regular(
        Path(str(manifest["legacy_console_env"])),
        expected_uid=uid,
        expected_gid=gid,
        maximum=256 * 1024,
    )
    evidence["console.env"] = env_evidence
    for name in CONSOLE_STATE_FILES:
        maximum = 16 * 1024 * 1024 if name == "telegram-control.json" else 2 * 1024 * 1024
        _payload, file_evidence = _read_legacy_regular(
            state / name,
            expected_uid=uid,
            expected_gid=gid,
            maximum=maximum,
        )
        evidence[name] = file_evidence
    for repository in manifest["repositories"]:
        root = Path(str(repository["canonical_root"]))
        runtime = Path(str(repository["runtime_file"]))
        root_info = root.lstat()
        if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
            raise CleanAdoptionError(f"canonical repository is unsafe: {root}")
        if root.resolve(strict=True) != root:
            raise CleanAdoptionError(f"canonical repository path resolves elsewhere: {root}")
        runtime_info = runtime.lstat()
        if stat.S_ISLNK(runtime_info.st_mode) or not stat.S_ISREG(runtime_info.st_mode):
            raise CleanAdoptionError(f"runtime manifest is unsafe: {runtime}")
    return evidence


def _stage_legacy_sources(
    manifest: Mapping[str, object], *, transaction_root: Path
) -> dict[str, object]:
    """Snapshot the stopped legacy writer's five inputs as root-owned 0600 files."""

    uid = int(manifest["legacy_console_uid"])
    gid = int(manifest["legacy_console_gid"])
    destination = transaction_root / "legacy-source-snapshot"
    destination.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(destination, 0o700)
    if destination.lstat().st_uid != 0:
        raise CleanAdoptionError("legacy source snapshot directory is not root-owned")
    sources = {
        "console.env": (
            Path(str(manifest["legacy_console_env"])),
            256 * 1024,
        ),
        **{
            name: (
                Path(str(manifest["legacy_console_state"])) / name,
                16 * 1024 * 1024
                if name == "telegram-control.json"
                else 2 * 1024 * 1024,
            )
            for name in CONSOLE_STATE_FILES
        },
    }
    files: dict[str, object] = {}
    for name, (source, maximum) in sources.items():
        payload, source_identity = _read_legacy_regular(
            source,
            expected_uid=uid,
            expected_gid=gid,
            maximum=maximum,
        )
        staged = destination / name
        if staged.exists() or staged.is_symlink():
            info = staged.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o600
                or staged.read_bytes() != payload
            ):
                raise CleanAdoptionError(
                    f"staged legacy source is contradictory: {staged}"
                )
        else:
            activation._atomic_private(staged, payload, expected_uid=0)
        files[name] = {
            "source": source_identity,
            "staged_path": str(staged),
            "staged_sha256": hashlib.sha256(payload).hexdigest(),
            "staged_owner_uid": 0,
            "staged_mode": "0600",
        }
    return {
        "directory": str(destination),
        "env": str(destination / "console.env"),
        "state": str(destination),
        "files": files,
        "source_files_mutated": False,
    }


def plan_adoption(manifest: Mapping[str, object]) -> dict[str, object]:
    checked = validate_manifest(manifest)
    release = installer.verify_release(Path(str(checked["release"])))
    source = _source_evidence(checked)
    return {
        "ok": True,
        "kind": "devcoordinator-clean-adoption-plan",
        "release_digest": release["release_digest"],
        "manifest_sha256": hashlib.sha256(_canonical(checked)).hexdigest(),
        "console_state": source,
        "fresh_stores": fresh_store_plan(checked),
        "repository_count": len(checked["repositories"]),
        "repository_catalog_count": len(checked["repositories"]),
        "project_worktrees_mutated": False,
        "project_databases_or_volumes_mutated": False,
        "schema12_bridge_used": False,
        "storage_split_used": False,
    }


def _seal_journal(payload: Mapping[str, object]) -> dict[str, object]:
    return cutover.seal(JOURNAL_KIND, dict(payload))


def _read_journal(path: Path, *, uid: int) -> dict[str, object] | None:
    if not (path.exists() or path.is_symlink()):
        return None
    return cutover.verify_seal(
        cutover.read_private_json(path, uid=uid),
        kind=JOURNAL_KIND,
        fields={
            "operation_id",
            "manifest_sha256",
            "phase",
            "steps",
            "created_at",
            "updated_at",
        },
    )


def _write_journal(path: Path, value: Mapping[str, object], *, uid: int) -> dict[str, object]:
    document = _seal_journal(value)
    activation._atomic_private(path, _canonical(document) + b"\n", expected_uid=uid)
    return document

def _rotate_disposable_state(
    manifest: Mapping[str, object], *, transaction_root: Path
) -> dict[str, object]:
    destinations = manifest["destinations"]
    names = (
        "authority_database",
        "test_database",
        "inventory_database",
        "inventory_publication",
        "profile",
        "console_config",
        "route_resolution",
        "publication_input",
        "publication",
        "telegram_destination",
    )
    candidates: list[Path] = []
    for name in names:
        path = Path(str(destinations[name]))
        candidates.append(path)
        if name.endswith("database"):
            candidates.extend((Path(f"{path}-wal"), Path(f"{path}-shm")))
    backup_root = transaction_root / "discarded-state"
    backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    moved: dict[str, str] = {}
    for path in candidates:
        if not (path.exists() or path.is_symlink()):
            continue
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise CleanAdoptionError(f"disposable state path is unsafe: {path}")
        destination = backup_root / f"{len(moved):03d}-{path.name}"
        if destination.exists() or destination.is_symlink():
            raise CleanAdoptionError("disposable state backup destination exists")
        os.replace(path, destination)
        moved[str(path)] = str(destination)
    # The spool and Test Store are one recovery generation.  Retaining active,
    # result, or exit envelopes while replacing the database makes testd replay
    # attempt IDs which cannot exist in the fresh store; that aborts scheduler
    # startup before it can serve catalog or plan requests.  Clean adoption is
    # explicitly destructive for test history, so rotate the whole spool with
    # the database and let tmpfiles/testd create a new empty one.
    directory_candidates = (
        Path(str(destinations["test_database"])).parent / "spool",
        Path(str(destinations["console_state"])),
        Path(str(destinations["edge_identity_state"])),
    )
    for path in directory_candidates:
        if not (path.exists() or path.is_symlink()):
            continue
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise CleanAdoptionError(f"disposable state directory is unsafe: {path}")
        destination = backup_root / f"{len(moved):03d}-{path.name}"
        if destination.exists() or destination.is_symlink():
            raise CleanAdoptionError("disposable state backup destination exists")
        os.replace(path, destination)
        moved[str(path)] = str(destination)
    return {"moved": moved, "project_storage_mutated": False}


def _synthetic_sealed_state(
    manifest: Mapping[str, object], *, testd_uid: int, transaction_root: Path
) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    destinations = manifest["destinations"]
    return cutover.seal(
        cutover.STATE_KIND,
        {
            "cutover_id": str(uuid.uuid4()),
            "phase": "sealed",
            "release": str(manifest["release"]),
            "release_digest": Path(str(manifest["release"])).name,
            "rendered_units": str(manifest["rendered_units"]),
            "authority_uid": 0,
            "testd_uid": testd_uid,
            "legacy_authority_database": str(destinations["authority_database"]),
            "authority_database": str(destinations["authority_database"]),
            "test_database": str(destinations["test_database"]),
            "inventory_canary_project": str(manifest["background_project_root"]),
            "authority_backup_directory": str(transaction_root / "authority-backups"),
            "test_backup_directory": str(transaction_root / "test-backups"),
            "migration_state": str(transaction_root / "migration.json"),
            "drain_proof": str(transaction_root / "drain.json"),
            "cutover_seal": str(transaction_root / "seal.json"),
            "reserve_bytes": 0,
            "retain_until": (now + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            "authority_backup_required": False,
            "evidence": {},
            "created_at": now.isoformat().replace("+00:00", "Z"),
            "updated_at": now.isoformat().replace("+00:00", "Z"),
            "state_generation": 0,
        },
    )


def _console_domain(env_path: Path, *, owner_uid: int) -> str:
    payload = activation._read_secret(
        env_path,
        label="legacy Console environment",
        expected_uid=owner_uid,
        maximum=activation.MAX_JSON_BYTES,
    ).decode("utf-8")
    for raw in payload.splitlines():
        line = raw.strip()
        if line.startswith("DOMAIN="):
            domain = line.split("=", 1)[1].strip()
            if re.fullmatch(r"[a-z0-9.-]+", domain):
                return domain
    raise CleanAdoptionError("legacy Console environment has no valid DOMAIN")


def _start_units(runner: activation.CommandRunner, units: Sequence[str]) -> dict[str, object]:
    return {"ready_units": activation._start_exact_units(runner, tuple(units))}


def _wait_for_authority_application(
    manifest: Mapping[str, object],
    *,
    maintenance_deployment_id: str,
    expected_repository_ids: Mapping[str, str],
    runner: activation.CommandRunner,
    max_attempts: int = 12,
    poll_interval_seconds: float = 0.25,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    """Wait for one trusted-local broker response, not merely systemd active.

    ``Type=exec`` becomes active before the authority has adopted and validated
    its inherited listener.  A bounded host-wide inventory request proves
    that the application has crossed that boundary.  The per-attempt coreutils
    timeout keeps an accepted-but-unserved socket from consuming the whole
    adoption transaction.
    """

    if type(max_attempts) is not int or not 1 <= max_attempts <= 60:
        raise CleanAdoptionError("authority readiness attempt limit is invalid")
    if (
        isinstance(poll_interval_seconds, bool)
        or not isinstance(poll_interval_seconds, (int, float))
        or not 0 <= float(poll_interval_seconds) <= 5
    ):
        raise CleanAdoptionError("authority readiness poll interval is invalid")
    repositories = manifest.get("repositories")
    destinations = manifest.get("destinations")
    if (
        not isinstance(repositories, Sequence)
        or isinstance(repositories, (str, bytes))
        or not repositories
        or not isinstance(destinations, Mapping)
    ):
        raise CleanAdoptionError("authority readiness manifest is incomplete")
    repository = repositories[0]
    if not isinstance(repository, Mapping):
        raise CleanAdoptionError("authority readiness repository is invalid")
    canonical_root = repository.get("canonical_root")
    if (
        not isinstance(canonical_root, str)
        or not canonical_root
    ):
        raise CleanAdoptionError("authority readiness canary is incomplete")
    expected_repository_id = expected_repository_ids.get(canonical_root)
    profile_path = destinations.get("profile")
    release = manifest.get("release")
    if (
        not isinstance(expected_repository_id, str)
        or not expected_repository_id
        or not isinstance(profile_path, str)
        or not profile_path
        or not isinstance(release, str)
        or not release
        or not isinstance(maintenance_deployment_id, str)
        or not maintenance_deployment_id
    ):
        raise CleanAdoptionError("authority readiness binding is incomplete")
    inventory_helper = (
        Path(release) / "skills/codex-dev-coordinator/scripts/dev_coordinator.py"
    )
    command = [
        "/usr/bin/timeout",
        "--signal=KILL",
        "5",
        "/usr/bin/env",
        "DEVCOORDINATOR_AUTHORITY=system",
        f"DEVCOORDINATOR_BROKER_PROFILE={profile_path}",
        "DEVCOORDINATOR_MAINTENANCE_DEPLOYMENT_ID="
        + maintenance_deployment_id,
        "PYTHONDONTWRITEBYTECODE=1",
        "/usr/bin/python3",
        "-I",
        "-B",
        str(inventory_helper),
        "inventory",
        "--project",
        canonical_root,
        "--no-docker",
        "--compact-json",
    ]
    for attempt in range(1, max_attempts + 1):
        active_before = (
            runner.status(
                [
                    "/usr/bin/systemctl",
                    "is-active",
                    "--quiet",
                    "devcoordinator-authority.service",
                ]
            )
            == 0
        )
        if active_before:
            try:
                document = json.loads(runner.text(command))
            except (activation.ActivationError, OSError, json.JSONDecodeError):
                document = None
            scoped = (
                document.get("repositories")
                if isinstance(document, Mapping)
                else None
            )
            if (
                isinstance(document, Mapping)
                and document.get("schema_version") == 2
                and isinstance(scoped, list)
                and len(scoped) == 1
                and isinstance(scoped[0], Mapping)
                and scoped[0].get("canonical_root") == canonical_root
                and scoped[0].get("repo_id") == expected_repository_id
                and runner.status(
                    [
                        "/usr/bin/systemctl",
                        "is-active",
                        "--quiet",
                        "devcoordinator-authority.service",
                    ]
                )
                == 0
            ):
                return {
                    "ready": True,
                    "attempts": attempt,
                    "canonical_root": canonical_root,
                    "repo_id": expected_repository_id,
                    "caller": "trusted-local-installer",
                    "schema_version": 2,
                }
        if attempt != max_attempts:
            sleeper(float(poll_interval_seconds))
    raise CleanAdoptionError(
        "authority did not reach trusted-local application readiness"
    )


def _stop_loaded_unit(
    runner: activation.CommandRunner, unit: str, *, label: str
) -> dict[str, object]:
    load_state = runner.text(
        ["/usr/bin/systemctl", "show", "--property=LoadState", "--value", unit]
    ).strip()
    if load_state == "not-found":
        return {"unit": unit, "loaded": False, "stopped": True}
    if load_state != "loaded":
        raise CleanAdoptionError(f"{label} has unsupported load state: {unit}")
    if unit.startswith("devcoordinator-console@"):
        # Console instances inherit the template's ``static`` enabled state;
        # ``systemctl is-enabled --quiet`` returns success for that state even
        # though no instance is enabled.  Stop the exact writer and verify
        # inactivity instead of treating static template metadata as a writer.
        if runner.status(["/usr/bin/systemctl", "stop", unit]) != 0:
            raise CleanAdoptionError(f"{label} could not be stopped: {unit}")
        if runner.status(
            ["/usr/bin/systemctl", "is-active", "--quiet", unit]
        ) == 0:
            raise CleanAdoptionError(f"{label} remained active: {unit}")
        return {"unit": unit, "loaded": True, "stopped": True}
    activation._disable_stop_exact_unit(runner, unit, label=label)
    return {"unit": unit, "loaded": True, "stopped": True}


def _loaded_console_units(runner: activation.CommandRunner) -> tuple[str, ...]:
    """Return every loaded immutable Console instance, fail-closed.

    A clean adoption can follow an interrupted adoption whose prior Console
    instance still owns the fixed inner listener.  The new release name alone
    cannot identify that predecessor, so enumerate only the tightly bounded
    immutable instance namespace before reserving ports.
    """

    output = runner.text(
        [
            "/usr/bin/systemctl",
            "list-units",
            "--all",
            "--type=service",
            "--plain",
            "--no-legend",
            "--full",
            "--no-pager",
            "devcoordinator-console@*.service",
        ]
    )
    units: set[str] = set()
    for raw in output.splitlines():
        fields = raw.split()
        if not fields:
            continue
        unit = fields[0]
        if CONSOLE_UNIT_RE.fullmatch(unit) is None:
            raise CleanAdoptionError(
                f"loaded Console instance has an invalid immutable identity: {unit}"
            )
        units.add(unit)
    return tuple(sorted(units))


def _stop_loaded_units(
    runner: activation.CommandRunner,
    units: Sequence[str],
    *,
    label: str,
) -> list[dict[str, object]]:
    """Disable the full graph before stopping it in one systemd transaction.

    Stopping one public socket at a time lets traffic reactivate its
    Restart=always edge dependency between calls.  Disable every non-static
    unit first, then stop all loaded services/sockets/Console slots together.
    """

    observations: list[tuple[str, bool]] = []
    loaded: list[str] = []
    ordinary: list[str] = []
    for unit in dict.fromkeys(units):
        load_state = runner.text(
            ["/usr/bin/systemctl", "show", "--property=LoadState", "--value", unit]
        ).strip()
        if load_state == "not-found":
            observations.append((unit, False))
            continue
        if load_state != "loaded":
            raise CleanAdoptionError(f"{label} has unsupported load state: {unit}")
        observations.append((unit, True))
        loaded.append(unit)
        if not unit.startswith("devcoordinator-console@"):
            ordinary.append(unit)

    for unit in ordinary:
        if runner.status(["/usr/bin/systemctl", "disable", unit]) != 0:
            raise CleanAdoptionError(f"{label} could not be disabled: {unit}")
    if loaded and runner.status(["/usr/bin/systemctl", "stop", *loaded]) != 0:
        raise CleanAdoptionError(f"{label} graph could not be stopped")

    results: list[dict[str, object]] = []
    for unit, was_loaded in observations:
        if not was_loaded:
            results.append({"unit": unit, "loaded": False, "stopped": True})
            continue
        if unit.startswith("devcoordinator-console@"):
            if runner.status(
                ["/usr/bin/systemctl", "is-active", "--quiet", unit]
            ) == 0:
                raise CleanAdoptionError(f"{label} remained active: {unit}")
        elif activation._systemd_unit_state(runner, unit) != (False, False):
            raise CleanAdoptionError(f"{label} remained active or enabled: {unit}")
        results.append({"unit": unit, "loaded": True, "stopped": True})
    return results


def _prepare_release_assets(
    manifest: Mapping[str, object],
    *,
    transaction_root: Path,
    operation_id: str,
) -> dict[str, object]:
    release = Path(str(manifest["release"]))
    bundle_path = transaction_root / "clean-port-reservations.json"
    bundle = installer.prepare_clean_port_reservations(
        release,
        bundle_path,
        operation_id=operation_id,
        ports=manifest["ports"],
    )
    rendered = Path(str(manifest["rendered_units"]))
    slot = Path(str(manifest["candidate_slot_source"]))
    if rendered.exists() or rendered.is_symlink():
        raise CleanAdoptionError("clean rendered-unit output already exists")
    rendered_result = installer.render_units(
        release,
        rendered,
        port_reservations=bundle_path,
        port_reservations_sha256=str(bundle["document_sha256"]),
    )
    slot_result = installer.render_console_slot(
        release,
        slot,
        port_reservations=bundle_path,
        port_reservations_sha256=str(bundle["document_sha256"]),
        bootstrap_active=True,
    )
    return {
        "port_reservations": str(bundle_path),
        "port_reservations_sha256": bundle["document_sha256"],
        "ports": {
            role: int(bundle["reservations"][role]["port"])
            for role in installer.PORT_RESERVATION_ROLES
        },
        "rendered_units": rendered_result,
        "candidate_slot": slot_result,
    }


def _prepare_route_state_parents(
    manifest: Mapping[str, object], *, expected_uid: int
) -> dict[str, object]:
    """Create the private parents required by first route publication.

    The route resolver deliberately refuses a missing or replaceable parent.
    Clean adoption owns these new destinations, so bootstrap them explicitly
    instead of relying on an unrelated tmpfiles entry or a prior deployment.
    """

    destinations = manifest.get("destinations")
    if not isinstance(destinations, Mapping):
        raise CleanAdoptionError("clean-adoption route destinations are invalid")
    parents = {
        Path(str(destinations[name])).parent
        for name in ("route_resolution", "publication_input")
    }
    prepared = [
        str(activation._private_directory(parent, expected_uid=expected_uid))
        for parent in sorted(parents, key=str)
    ]
    return {"private_parents": prepared}


def _test_plane_application_canary(
    expected_repository_ids: Mapping[str, str],
    *,
    setup_repository_id: str,
    setup_execution_uid: int,
    socket_path: Path = Path("/run/devcoordinator-testd/testd.sock"),
) -> dict[str, object]:
    """Prove testd, snapshotd, and Test Store writes before maintenance clears."""

    repository_ids = tuple(expected_repository_ids.values())
    if (
        not repository_ids
        or len(set(repository_ids)) != len(repository_ids)
        or setup_repository_id not in repository_ids
        or type(setup_execution_uid) is not int
        or setup_execution_uid <= 0
    ):
        raise CleanAdoptionError("clean-adoption test-plane canary scope is invalid")
    plane = UnixTestPlaneClient(
        socket_path,
        expected_server_uid=TEST_PLANE_SOCKET_OWNER_UID,
        timeout_seconds=30,
    )
    try:
        health = dict(plane.health())
        setup = dict(
            plane.setup(
                repository_id=setup_repository_id,
                owner_uid=setup_execution_uid,
            )
        )
        catalog = dict(plane.repository_catalog(repository_ids=repository_ids))
    except (OSError, TestPlaneTransportError) as error:
        code = getattr(error, "code", type(error).__name__)
        raise CleanAdoptionError(
            f"clean-adoption test-plane application canary failed: {code}"
        ) from error
    if (
        health.get("schema_version") != 1
        or health.get("status") != "ok"
        or health.get("test_store_schema_version") != 5
        or not isinstance(health.get("store_generation"), str)
        or not health["store_generation"]
    ):
        raise CleanAdoptionError("clean-adoption testd health is contradictory")
    if (
        setup.get("schema_version") != 1
        or setup.get("repository_id") != setup_repository_id
        or setup.get("status") != "ready"
        or setup.get("ok") is not True
    ):
        raise CleanAdoptionError("clean-adoption test setup is not ready")
    rows = catalog.get("repositories")
    if (
        catalog.get("schema_version") != 1
        or not isinstance(rows, list)
        or len(rows) != len(repository_ids)
        or any(
            not isinstance(row, Mapping)
            or row.get("repository_id") not in repository_ids
            or row.get("setup_status") not in {"ready", "missing", "invalid"}
            for row in rows
        )
        or {str(row["repository_id"]) for row in rows} != set(repository_ids)
    ):
        raise CleanAdoptionError("clean-adoption test catalog is contradictory")
    retained = next(
        row for row in rows if row.get("repository_id") == setup_repository_id
    )
    if retained.get("setup_status") != "ready" or retained.get("retained") is not True:
        raise CleanAdoptionError("clean-adoption test setup was not retained")
    return {
        "status": "ready",
        "schema_version": 1,
        "test_store_schema_version": 5,
        "store_generation": health["store_generation"],
        "repository_count": len(repository_ids),
        "setup_repository_id": setup_repository_id,
        "setup_retained": True,
    }


def _final_health_gate(
    manifest: Mapping[str, object],
    *,
    staged_legacy_env: Path,
    maintenance_deployment_id: str,
    expected_repository_ids: Mapping[str, str],
    observer_uid: int,
    testd_uid: int,
    canary_uid: int,
    canary_gid: int,
    runner: activation.CommandRunner,
) -> dict[str, object]:
    units = (
        "devcoordinator-authority.service",
        "devcoordinator-api.service",
        "devcoordinator-testd.service",
        "devcoordinator-test-snapshotd.service",
        "devcoordinator-observer.service",
        "devcoordinator-notifications.service",
        "devcoordinator-edge.service",
        f"devcoordinator-console@{Path(str(manifest['release'])).name}.service",
    )
    inactive = [
        unit
        for unit in units
        if runner.status(["/usr/bin/systemctl", "is-active", "--quiet", unit]) != 0
    ]
    if inactive:
        raise CleanAdoptionError(
            "clean-adoption final services are not ready: " + ", ".join(inactive)
        )
    if activation._probe_local_api(activation.SOCKET_PORTS["api"]) != 200:
        raise CleanAdoptionError("clean-adoption final API health check failed")
    inventory_canaries: list[dict[str, object]] = []
    profile_path = str(manifest["destinations"]["profile"])
    inventory_helper = (
        Path(str(manifest["release"]))
        / "skills/codex-dev-coordinator/scripts/dev_coordinator.py"
    )
    if canary_uid <= 0 or canary_gid <= 0:
        raise CleanAdoptionError("trusted-local canary identity is invalid")
    for repository in manifest["repositories"]:
        output = runner.text(
            [
                "/usr/bin/setpriv",
                "--reuid",
                str(canary_uid),
                "--regid",
                str(canary_gid),
                "--clear-groups",
                "--reset-env",
                "/usr/bin/env",
                "DEVCOORDINATOR_AUTHORITY=system",
                f"DEVCOORDINATOR_BROKER_PROFILE={profile_path}",
                "DEVCOORDINATOR_MAINTENANCE_DEPLOYMENT_ID="
                + maintenance_deployment_id,
                "PYTHONDONTWRITEBYTECODE=1",
                "/usr/bin/python3",
                "-I",
                "-B",
                str(inventory_helper),
                "inventory",
                "--project",
                str(repository["canonical_root"]),
                "--no-docker",
                "--compact-json",
            ]
        )
        try:
            inventory_document = json.loads(output)
        except json.JSONDecodeError as error:
            raise CleanAdoptionError("inventory canary returned invalid JSON") from error
        scoped = inventory_document.get("repositories")
        if (
            inventory_document.get("schema_version") != 3
            or not isinstance(scoped, list)
            or len(scoped) != 1
            or scoped[0].get("canonical_root")
            != str(repository["canonical_root"])
            or scoped[0].get("repo_id")
            != expected_repository_ids.get(str(repository["canonical_root"]))
        ):
            raise CleanAdoptionError("inventory canary returned contradictory scope")
        inventory_canaries.append(
            {
                "canonical_root": str(repository["canonical_root"]),
                "repo_id": str(scoped[0]["repo_id"]),
                "caller_uid": canary_uid,
                "schema_version": 2,
            }
        )
    destinations = manifest["destinations"]
    authority = AccountStore.open(destinations["authority_database"], expected_uid=0)
    try:
        authority_metadata = authority.connection.execute(
            "SELECT schema_version,migration_state FROM schema_metadata WHERE singleton=1"
        ).fetchone()
    finally:
        authority.close()
    if authority_metadata is None or tuple(authority_metadata) != (SCHEMA_VERSION, "ready"):
        raise CleanAdoptionError("clean-adoption final authority is not ready")
    inventory = verify_inventory_store(
        Path(str(destinations["inventory_database"])),
        Path(str(destinations["inventory_publication"])),
        expected_owner_uid=observer_uid,
    )
    test_path = Path(str(destinations["test_database"]))
    test_info = test_path.lstat()
    if (
        stat.S_ISLNK(test_info.st_mode)
        or not stat.S_ISREG(test_info.st_mode)
        or test_info.st_uid != testd_uid
        or stat.S_IMODE(test_info.st_mode) != 0o600
    ):
        raise CleanAdoptionError("clean-adoption final Test Store identity is invalid")
    setup_root = str(manifest["background_project_root"])
    setup_repository_id = expected_repository_ids.get(setup_root)
    if not isinstance(setup_repository_id, str):
        raise CleanAdoptionError("clean-adoption test setup canary identity is invalid")
    test_plane = _test_plane_application_canary(
        expected_repository_ids,
        setup_repository_id=setup_repository_id,
        setup_execution_uid=canary_uid,
    )
    domain = _console_domain(
        staged_legacy_env,
        owner_uid=0,
    )
    public_status, refused = activation._probe_url(
        f"https://console.{domain}/healthz"
    )
    if refused or public_status != 200:
        raise CleanAdoptionError("clean-adoption final public Console is not ready")
    return {
        "units": list(units),
        "api_status": 200,
        "inventory_canaries": inventory_canaries,
        "test_catalog": {
            "status": "pending-maintenance-clear",
            "repository_count": len(expected_repository_ids),
        },
        "test_plane": test_plane,
        "authority_schema_version": SCHEMA_VERSION,
        "inventory_generation": inventory["generation"],
        "test_schema_version": 5,
        "public_status": public_status,
    }


def _tests_catalog_api_canary(
    expected_repository_ids: Mapping[str, str],
    *,
    setup_repository_id: str,
) -> dict[str, object]:
    """Verify the catalog and one ready setup read after maintenance clears.

    The loopback API intentionally returns a typed maintenance response while
    the global marker is active. Requiring a 200 before clearing that marker
    creates an impossible cutover gate, so validate service/store health first
    and the API representation immediately after the exact marker is removed.
    The setup read also activates and verifies the testd/snapshotd path which a
    catalog-only probe does not exercise.
    """

    def read_api(path: str, *, label: str) -> tuple[int, bytes]:
        connection = http.client.HTTPConnection(
            "127.0.0.1", activation.SOCKET_PORTS["api"], timeout=3.0
        )
        try:
            connection.request("GET", path, headers={"Host": "127.0.0.1"})
            response = connection.getresponse()
            return (
                int(response.status),
                response.read(activation.MAX_JSON_BYTES + 1),
            )
        except OSError as error:
            raise CleanAdoptionError(f"{label} API canary was refused") from error
        finally:
            connection.close()

    expected_ids = set(expected_repository_ids.values())
    if setup_repository_id not in expected_ids:
        raise CleanAdoptionError("Tests setup canary repository is not cataloged")

    def read_catalog(*, label: str) -> list[Mapping[str, object]]:
        status, payload = read_api("/v1/test-repositories", label=label)
        if status != 200 or len(payload) > activation.MAX_JSON_BYTES:
            raise CleanAdoptionError("Tests catalog API canary failed")
        try:
            catalog = json.loads(payload)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise CleanAdoptionError("Tests catalog API returned invalid JSON") from error
        if not isinstance(catalog, Mapping):
            raise CleanAdoptionError("Tests catalog API contract is contradictory")
        rows = catalog.get("repositories")
        if (
            catalog.get("schema_version") != 1
            or not isinstance(rows, list)
            or len(rows) != len(expected_repository_ids)
            or any(
                not isinstance(row, Mapping)
                or not isinstance(row.get("repo_id"), str)
                for row in rows
            )
            or {row["repo_id"] for row in rows} != expected_ids
            or any(
                row.get("setup_status") not in {"ready", "missing", "invalid"}
                for row in rows
            )
        ):
            raise CleanAdoptionError("Tests catalog API contract is contradictory")
        return rows

    # The internal pre-clear canary has already retained the selected setup in a
    # healthy cutover. Repeat that exact setup through the public API to prove
    # the broker path after maintenance clears. Keeping ``missing`` valid here
    # also makes this check deterministic when an operator invokes it alone on
    # an otherwise fresh Test Store.
    initial_rows = read_catalog(label="Tests catalog")
    setup_path = (
        f"/v1/test-repositories/{quote(setup_repository_id, safe='')}/setup"
    )
    setup_status = 0
    setup: object = None
    for attempt in range(1, TEST_SETUP_CANARY_ATTEMPTS + 1):
        setup_status, setup_payload = read_api(
            setup_path, label="Tests repository setup"
        )
        if len(setup_payload) > activation.MAX_JSON_BYTES:
            raise CleanAdoptionError("Tests repository setup API response is too large")
        try:
            setup = json.loads(setup_payload)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise CleanAdoptionError(
                "Tests repository setup API returned invalid JSON"
            ) from error
        if setup_status == 200:
            if (
                not isinstance(setup, Mapping)
                or setup.get("schema_version") != 1
                or setup.get("repository_id") != setup_repository_id
                or setup.get("status") != "ready"
                or setup.get("ok") is not True
            ):
                raise CleanAdoptionError(
                    "Tests repository setup API contract is contradictory"
                )
            retained_rows = read_catalog(label="Retained Tests catalog")
            retained = next(
                row
                for row in retained_rows
                if row.get("repo_id") == setup_repository_id
            )
            if (
                retained.get("setup_status") != "ready"
                or retained.get("setup_retained") is not True
            ):
                raise CleanAdoptionError(
                    "Tests catalog did not retain the ready setup canary"
                )
            return {
                "status": 200,
                "repository_count": len(initial_rows),
                "schema_version": 1,
                "setup": {
                    "attempts": attempt,
                    "ok": True,
                    "repository_id": setup_repository_id,
                    "retained": True,
                    "schema_version": 1,
                    "status": "ready",
                },
            }
        transient = (
            setup_status in {502, 503}
            and isinstance(setup, Mapping)
            and setup.get("code") in TRANSIENT_TEST_SETUP_CODES
        )
        if not transient or attempt == TEST_SETUP_CANARY_ATTEMPTS:
            raise CleanAdoptionError("Tests repository setup API canary failed")
        retry_hint = setup.get("retry_after_seconds")
        retry_delay = (
            retry_hint
            if type(retry_hint) is int
            and 0 < retry_hint <= TEST_SETUP_CANARY_MAX_RETRY_SECONDS
            else TEST_SETUP_CANARY_RETRY_DELAYS[attempt - 1]
        )
        time.sleep(retry_delay)
    raise CleanAdoptionError("Tests repository setup API canary failed")


def _maintenance_boundary_recovery(
    current: Mapping[str, object],
    *,
    maintenance_record: Mapping[str, object],
    active_maintenance: object | None,
) -> dict[str, object] | None:
    """Validate the active/cleared fence or describe the one safe crash repair.

    Clearing the marker and sealing the journal are two distinct durable
    operations.  A crash between them leaves an absent marker at the exact
    post-health boundary.  Record that absence once so the transaction can
    resume its post-maintenance read canaries; absence at any earlier phase is
    still a hard failure.
    """

    steps = current.get("steps")
    deployment_id = maintenance_record.get("deployment_id")
    if (
        not isinstance(steps, Mapping)
        or not isinstance(deployment_id, str)
        or not deployment_id
    ):
        raise CleanAdoptionError("clean-adoption maintenance journal is invalid")

    if "maintenance_cleared" in steps:
        cleared = steps.get("maintenance_cleared")
        if not isinstance(cleared, Mapping):
            raise CleanAdoptionError("clean-adoption maintenance clear record is invalid")
        recovered = cleared.get("recovered_absence")
        expected_fields = (
            {"active", "deployment_id", "cleared", "recovered_absence"}
            if recovered is True
            else {"active", "deployment_id", "cleared"}
        )
        if (
            set(cleared) != expected_fields
            or cleared.get("active") is not False
            or cleared.get("deployment_id") != deployment_id
            or (
                recovered is True
                and cleared.get("cleared") is not False
            )
            or (
                recovered is not True
                and cleared.get("cleared") is not True
            )
            or active_maintenance is not None
        ):
            raise CleanAdoptionError("clean-adoption maintenance clear record changed")
        return None

    if active_maintenance is not None:
        if getattr(active_maintenance, "deployment_id", None) != deployment_id:
            raise CleanAdoptionError("clean-adoption maintenance fence changed")
        return None

    if (
        current.get("phase") != "health_verified"
        or "health_verified" not in steps
        or "post_maintenance_api_ready" in steps
        or "complete" in steps
    ):
        raise CleanAdoptionError("clean-adoption maintenance fence changed")
    return {
        "active": False,
        "deployment_id": deployment_id,
        "cleared": False,
        "recovered_absence": True,
    }


@contextmanager
def _installer_mutex():
    handle = acquire_installer_mutex(expected_uid=0, expected_gid=0)
    succeeded = False
    try:
        yield
        succeeded = True
    finally:
        handle.close(command_succeeded=succeeded)


def apply_adoption(
    manifest: Mapping[str, object],
    *,
    transaction_root: Path,
    journal_file: Path,
    expected_uid: int = 0,
    runner: activation.CommandRunner | None = None,
) -> dict[str, object]:
    """Run or resume the destructive clean-adoption transaction.

    The transaction deliberately has no legacy-database compatibility branch.
    A failed step leaves its exact journal and is resumed with the same manifest.
    """

    if os.geteuid() != expected_uid or expected_uid != 0:
        raise CleanAdoptionError("clean-adoption apply must run as root")
    checked = validate_manifest(manifest, expected_uid=expected_uid)
    release = Path(str(checked["release"]))
    destinations = checked["destinations"]
    transaction_root = _absolute(str(transaction_root), "transaction root")
    transaction_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(transaction_root, 0o700)
    if transaction_root.lstat().st_uid != expected_uid:
        raise CleanAdoptionError("clean-adoption transaction root owner is invalid")
    journal_file = _absolute(str(journal_file), "clean-adoption journal")
    if journal_file.parent != transaction_root:
        raise CleanAdoptionError("clean-adoption journal must be inside its transaction root")
    command = runner or activation.CommandRunner()
    manifest_sha = hashlib.sha256(_canonical(checked)).hexdigest()
    current = _read_journal(journal_file, uid=expected_uid)
    if current is None:
        plan = plan_adoption(checked)
        if plan.get("manifest_sha256") != manifest_sha:
            raise CleanAdoptionError("clean-adoption plan identity changed")
        current = _write_journal(
            journal_file,
            {
                "operation_id": str(uuid.uuid4()),
                "manifest_sha256": manifest_sha,
                "phase": "planned",
                "steps": {},
                "created_at": _now(),
                "updated_at": _now(),
            },
            uid=expected_uid,
        )
    else:
        installer.verify_release(release)
    if current["manifest_sha256"] != manifest_sha:
        raise CleanAdoptionError("clean-adoption journal belongs to another manifest")
    if current["phase"] == "complete":
        return current

    def advance(name: str, result: Mapping[str, object]) -> None:
        nonlocal current
        steps = current.get("steps")
        if not isinstance(steps, Mapping):
            raise CleanAdoptionError("clean-adoption journal steps are invalid")
        current = _write_journal(
            journal_file,
            {
                "operation_id": current["operation_id"],
                "manifest_sha256": manifest_sha,
                "phase": name,
                "steps": {**dict(steps), name: dict(result)},
                "created_at": current["created_at"],
                "updated_at": _now(),
            },
            uid=expected_uid,
        )

    def done(name: str) -> bool:
        return name in current.get("steps", {})

    with _installer_mutex():
        maintenance_gid = 0
        _normalize_maintenance_root(
            activation.CANONICAL_MAINTENANCE_ROOT,
            expected_uid=0,
            expected_gid=maintenance_gid,
        )
        maintenance = activation._maintenance_api(release)
        if not done("maintenance"):
            state = maintenance[4](
                expected_uid=0,
                expected_gid=maintenance_gid,
                maintenance_root=activation.CANONICAL_MAINTENANCE_ROOT,
            )
            preexisting = state is not None
            if state is None:
                state = maintenance[2](
                    expected_uid=0,
                    expected_gid=maintenance_gid,
                    deployment_id=str(current["operation_id"]),
                    scope=maintenance[0],
                    message=maintenance[1],
                    retry_after_seconds=60,
                    started_at=_now(),
                    maintenance_root=activation.CANONICAL_MAINTENANCE_ROOT,
                )
            advance(
                "maintenance",
                {
                    "active": True,
                    "deployment_id": state.deployment_id,
                    "message": state.message,
                    "retry_after_seconds": state.retry_after_seconds,
                    "started_at": state.started_at,
                    "preexisting": preexisting,
                },
            )
        maintenance_record = current["steps"]["maintenance"]
        active_maintenance = maintenance[4](
            expected_uid=0,
            expected_gid=maintenance_gid,
            maintenance_root=activation.CANONICAL_MAINTENANCE_ROOT,
        )
        recovered_clear = _maintenance_boundary_recovery(
            current,
            maintenance_record=maintenance_record,
            active_maintenance=active_maintenance,
        )
        if recovered_clear is not None:
            advance("maintenance_cleared", recovered_clear)
        if not done("writers_stopped"):
            prior_console_units = _loaded_console_units(command)
            units = tuple(
                dict.fromkeys(
                    (
                        *activation.SERVICE_UNITS,
                        *activation.SOCKET_UNITS,
                        *prior_console_units,
                        f"devcoordinator-console@{release.name}.service",
                        "devcoordinator-broker.service",
                        activation.LEGACY_API_SERVICE_UNIT,
                        "devops-console.service",
                    )
                )
            )
            stopped = _stop_loaded_units(
                command,
                units,
                label="clean-adoption control-plane writer",
            )
            advance(
                "writers_stopped",
                {
                    "units": stopped,
                    "project_units_stopped": False,
                    "legacy_console_stopped": True,
                    "legacy_api_stopped": True,
                },
            )
        if not done("legacy_sources_staged"):
            advance(
                "legacy_sources_staged",
                _stage_legacy_sources(checked, transaction_root=transaction_root),
            )
        staged = current["steps"]["legacy_sources_staged"]
        staged_env = Path(str(staged["env"]))
        staged_state = Path(str(staged["state"]))
        if not done("state_rotated"):
            advance(
                "state_rotated",
                _rotate_disposable_state(checked, transaction_root=transaction_root),
            )
        if not done("release_assets"):
            advance(
                "release_assets",
                _prepare_release_assets(
                    checked,
                    transaction_root=transaction_root,
                    operation_id=str(current["operation_id"]),
                ),
            )
        identities = cutover._availability_identities() if done("bootstrap") else None
        if not done("bootstrap"):
            bootstrap = cutover.bootstrap_first_deployment(
                release=release,
                rendered_units=Path(str(checked["rendered_units"])),
                authority_database=Path(str(destinations["authority_database"])),
                inventory_database=Path(str(destinations["inventory_database"])),
                test_database=Path(str(destinations["test_database"])),
                schema_attestation=(
                    Path(str(destinations["test_database"])).parent
                    / f"clean-adoption-{current['operation_id']}-schema.json"
                ),
                output=transaction_root / "bootstrap.json",
                operation_id=str(current["operation_id"]),
                authority_uid=0,
                command_status=command.status,
            )
            identities = bootstrap["attestation"]["service_identities"]
            advance("bootstrap", bootstrap)
        if identities is None:
            identities = current["steps"]["bootstrap"]["attestation"]["service_identities"]
        users = identities["users"]
        groups = identities["groups"]
        if not isinstance(groups, Mapping) or groups:
            raise CleanAdoptionError(
                "clean-adoption bootstrap retained an obsolete shared group"
            )
        testd = users["devcoordinator-testd"]
        observer = users["devcoordinator-observer"]
        console = users["devcoordinator-console"]
        edge = users["devcoordinator-edge"]
        notifications = users["devcoordinator-notifications"]
        api = users["devcoordinator-api"]
        if not done("credentials_migrated"):
            credentials = activation.migrate_credentials(
                legacy_env=staged_env,
                legacy_source_uid=0,
                rollback_directory=transaction_root / "credential-rollback",
                expected_uid=0,
            )
            advance("credentials_migrated", credentials)
        else:
            activation.verify_credential_migration(
                current["steps"]["credentials_migrated"],
                legacy_env=staged_env,
                legacy_source_uid=0,
                expected_uid=0,
            )
        if not done("fresh_authority"):
            advance(
                "fresh_authority",
                activate_fresh_authority(
                    destinations["authority_database"], expected_uid=0
                ),
            )
        if not done("fresh_inventory"):
            inventory = installer.initialize_observer_projection(
                release,
                Path(str(destinations["inventory_publication"])),
                database=Path(str(destinations["inventory_database"])),
                owner_uid=int(observer["uid"]),
                owner_gid=int(observer["gid"]),
            )
            advance("fresh_inventory", inventory)
        if not done("repositories_cataloged"):
            catalog = catalog_repositories_offline(checked, expected_uid=0)
            profile = cutover.reconstruct_api_profile_from_authority(
                authority_database=Path(str(destinations["authority_database"])),
                destination=Path(str(destinations["profile"])),
                validation_uid=int(api["uid"]),
                authority_uid=0,
            )
            advance(
                "repositories_cataloged",
                {**catalog, "profile": profile},
            )
        if not done("graph_installed"):
            synthetic = _synthetic_sealed_state(
                checked, testd_uid=int(testd["uid"]), transaction_root=transaction_root
            )
            graph, credential = activation.prepare_candidate(
                state=synthetic,
                candidate_slot_source=Path(str(checked["candidate_slot_source"])),
                legacy_console_env=staged_env,
                background_project_root=Path(str(checked["background_project_root"])),
                background_config_transaction=transaction_root / "background-config",
                project_isolation_audit=transaction_root / "project-isolation.json",
                project_isolation_ledger=transaction_root / "project-isolation-ledger.json",
                rollback_directory=transaction_root / "graph-rollback",
                expected_uid=0,
                legacy_console_uid=0,
                expected_port_reservations={
                    "console_outer": int(checked["ports"]["console_outer"]),
                    "console_inner": int(checked["ports"]["console_inner"]),
                },
                runner=command,
                first_adoption_defer_start=True,
                clean_adoption_defer_start=True,
                first_adoption_legacy_authority_database=Path(
                    str(destinations["authority_database"])
                ),
                first_adoption_journal=transaction_root / "graph-journal.json",
            )
            cutover._publish_evidence(transaction_root / "graph.json", graph, uid=0)
            cutover._publish_evidence(transaction_root / "credentials.json", credential, uid=0)
            authority_unit = Path(str(checked["rendered_units"])) / "devcoordinator-authority.service"
            if "--internal-testd-user devcoordinator-testd" not in authority_unit.read_text(
                encoding="utf-8"
            ):
                raise CleanAdoptionError("authority graph lacks the internal testd identity")
            advance(
                "graph_installed",
                {
                    "graph_sha256": graph["document_sha256"],
                    "credential_sha256": credential["document_sha256"],
                    "testd_internal_identity": {
                        "uid": int(testd["uid"]),
                        "transport": "unix-peer-uid",
                        "profile_required": False,
                    },
                },
            )
        if not done("snapshotd_ready"):
            advance(
                "snapshotd_ready",
                _start_units(
                    command,
                    (
                        "devcoordinator-test-snapshotd.socket",
                        "devcoordinator-test-snapshotd.service",
                    ),
                ),
            )
        if not done("fixed_ports"):
            advance(
                "fixed_ports",
                replay_fixed_ports_offline(checked, expected_uid=0),
            )
        if not done("authority_ready"):
            started = _start_units(
                command,
                (
                    "devcoordinator-authority.socket",
                    "devcoordinator-authority.service",
                ),
            )
            application_readiness = _wait_for_authority_application(
                checked,
                maintenance_deployment_id=str(
                    maintenance_record["deployment_id"]
                ),
                expected_repository_ids=current["steps"][
                    "repositories_cataloged"
                ]["repository_ids"],
                runner=command,
            )
            advance(
                "authority_ready",
                {**started, "application_readiness": application_readiness},
            )
        if not done("route_resolution"):
            _prepare_route_state_parents(checked, expected_uid=0)
            domain = _console_domain(staged_env, owner_uid=0)
            result = command.run_json(
                [
                    str(release / "bin/devcoordinator-first-adoption-route-resolution"),
                    "--release",
                    str(release),
                    "--legacy-routes",
                    str(staged_state / "routes.json"),
                    "--legacy-routes-owner-uid",
                    "0",
                    "--legacy-source-uid",
                    str(checked["legacy_console_uid"]),
                    "--legacy-source-gid",
                    str(checked["legacy_console_gid"]),
                    "--legacy-source-home",
                    str(checked["legacy_console_home"]),
                    "--domain",
                    domain,
                    "--output",
                    str(destinations["route_resolution"]),
                    "--broker-profile",
                    str(destinations["profile"]),
                    "--maintenance-deployment-id",
                    str(maintenance_record["deployment_id"]),
                    "--expected-uid",
                    "0",
                ]
            )
            advance("route_resolution", result)
        if not done("console_state"):
            migrated = activation.migrate_legacy_console_state(
                release=release,
                legacy_env=staged_env,
                legacy_state=staged_state,
                console_state=Path(str(destinations["console_state"])),
                edge_identity_state=Path(str(destinations["edge_identity_state"])),
                console_config=Path(str(destinations["console_config"])),
                route_resolution=Path(str(destinations["route_resolution"])),
                private_publication_input=Path(str(destinations["publication_input"])),
                console_port=int(checked["ports"]["console_outer"]),
                console_uid=int(console["uid"]),
                console_gid=int(console["gid"]),
                edge_uid=int(edge["uid"]),
                edge_gid=int(edge["gid"]),
                legacy_uid=0,
                rollback_directory=transaction_root / "console-rollback",
                journal_file=transaction_root / "console-migration.json",
                migrate_edge_identity=False,
                expected_uid=0,
                runner=command,
            )
            advance("console_state", migrated)
        if not done("control_plane_ready"):
            advance(
                "control_plane_ready",
                _start_units(
                    command,
                    (
                        "devcoordinator-testd.socket",
                        "devcoordinator-api.socket",
                        "devcoordinator-testd.service",
                        "devcoordinator-api.service",
                        "devcoordinator-observer.service",
                        f"devcoordinator-console@{release.name}.service",
                    ),
                ),
            )
        if not done("notifications_ready"):
            telegram_source = staged_state / "telegram-control.json"
            payload = activation._read_secret(
                telegram_source,
                label="staged Telegram state",
                expected_uid=0,
                maximum=16 * 1024 * 1024,
            )
            digest = "sha256:" + hashlib.sha256(payload).hexdigest()
            fence = {
                "schema_version": 1,
                "kind": "devcoordinator-notification-writer-fence",
                "deployment_id": str(current["operation_id"]),
                "captured_at": _now(),
                "legacy_writer_unit": "devops-console.service",
                "legacy_writer_inactive": True,
                "source_path": str(telegram_source),
                "source_sha256": digest,
            }
            activation._atomic_private(
                transaction_root / "telegram-writer-fence.json",
                _canonical(fence) + b"\n",
                expected_uid=0,
            )
            copied = command.run_json(
                [
                    str(release / "bin/devcoordinator-background-handoff"),
                    "copy-telegram-state",
                    "--source",
                    str(telegram_source),
                    "--destination",
                    str(destinations["telegram_destination"]),
                    "--rollback",
                    str(transaction_root / "telegram.rollback"),
                    "--fence-attestation",
                    str(transaction_root / "telegram-writer-fence.json"),
                    "--legacy-writer-unit",
                    "devops-console.service",
                    "--expected-source-sha256",
                    digest,
                    "--source-owner-uid",
                    "0",
                    "--destination-owner-uid",
                    str(notifications["uid"]),
                    "--destination-owner-gid",
                    str(notifications["gid"]),
                ]
            )
            ready = _start_units(command, ("devcoordinator-notifications.service",))
            advance("notifications_ready", {"copy": copied, **ready})
        if not done("public_ready"):
            publication = activation.bootstrap_edge_publication(
                release=release,
                publication_file=Path(str(destinations["publication"])),
                publication_input=Path(str(destinations["publication_input"])),
                edge_uid=int(edge["uid"]),
                edge_gid=int(edge["gid"]),
                expected_uid=0,
                runner=command,
            )
            ready = _start_units(command, activation.FINAL_EDGE_UNITS)
            advance("public_ready", {"publication": publication, **ready})
        if not done("health_verified"):
            advance(
                "health_verified",
                _final_health_gate(
                    {**checked, "legacy_console_env": str(staged_env)},
                    staged_legacy_env=staged_env,
                    maintenance_deployment_id=str(
                        maintenance_record["deployment_id"]
                    ),
                    expected_repository_ids=current["steps"][
                        "repositories_cataloged"
                    ]["repository_ids"],
                    observer_uid=int(observer["uid"]),
                    testd_uid=int(testd["uid"]),
                    canary_uid=int(api["uid"]),
                    canary_gid=int(api["gid"]),
                    runner=command,
                ),
            )
        if not done("maintenance_cleared"):
            cleared = maintenance[3](
                expected_uid=0,
                expected_gid=maintenance_gid,
                deployment_id=str(maintenance_record["deployment_id"]),
                maintenance_root=activation.CANONICAL_MAINTENANCE_ROOT,
            )
            if cleared is not True:
                # Do not bless an unexplained disappearance as a normal clear.
                # A process crash after a successful clear is recovered on the
                # next invocation only from the exact durable health boundary.
                raise CleanAdoptionError(
                    "clean-adoption maintenance marker disappeared before clear"
                )
            advance(
                "maintenance_cleared",
                {
                    "active": False,
                    "deployment_id": maintenance_record["deployment_id"],
                    "cleared": cleared,
                },
            )
        if not done("post_maintenance_api_ready"):
            repository_ids = current["steps"]["repositories_cataloged"][
                "repository_ids"
            ]
            advance(
                "post_maintenance_api_ready",
                _tests_catalog_api_canary(
                    repository_ids,
                    setup_repository_id=str(
                        repository_ids[str(checked["background_project_root"])]
                    ),
                ),
            )
        if not done("complete"):
            advance(
                "complete",
                {
                    "ok": True,
                    "release_digest": release.name,
                    "schema12_bridge_used": False,
                    "storage_split_used": False,
                    "project_worktrees_mutated": False,
                    "project_databases_or_volumes_mutated": False,
                },
            )
        return current

def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    plan = actions.add_parser("plan")
    plan.add_argument("--manifest", type=Path, required=True)
    apply = actions.add_parser("apply")
    apply.add_argument("--manifest", type=Path, required=True)
    apply.add_argument("--transaction-root", type=Path, required=True)
    apply.add_argument("--journal", type=Path, required=True)
    apply.add_argument("--expected-uid", type=int, default=0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        expected_uid = None if args.action == "plan" else int(args.expected_uid)
        manifest = _load_manifest(args.manifest, expected_uid=expected_uid)
        if args.action == "plan":
            result = plan_adoption(manifest)
        else:
            result = apply_adoption(
                manifest,
                transaction_root=args.transaction_root,
                journal_file=args.journal,
                expected_uid=expected_uid,
            )
    except (
        CleanAdoptionError,
        activation.ActivationError,
        cutover.CutoverError,
        installer.ReleaseError,
        OSError,
        RuntimeError,
        ValueError,
    ) as error:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error_code": "clean_adoption_failed",
                    "error": str(error),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
