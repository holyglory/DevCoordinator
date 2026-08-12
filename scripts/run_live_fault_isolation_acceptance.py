#!/usr/bin/env python3
"""Run or verify the immutable DevCoordinator live fault-isolation gate.

This command never launches project commands directly.  Its six fixed fault
drivers enter the broker-owned transient-test manager, and the slow-upstream
driver is placed in the repository's attributed project slice by the same
Coordinator primitive.  No Docker or service-manager lifecycle command is
accepted from the request.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import time
from typing import Callable, Mapping


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = ROOT / "skills/codex-dev-coordinator/scripts"
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import activate_availability_release as activation  # noqa: E402
import orchestrate_availability_cutover as cutover  # noqa: E402
from devcoordinator.inventory_projection import (  # noqa: E402
    InventoryProjectionError,
    read_projection,
)
from devcoordinator.live_fault_acceptance import (  # noqa: E402
    FaultAcceptanceAttemptManager,
    FaultAcceptanceError,
    NativeFaultRuntime,
    build_request as build_fault_request,
    read_private_json,
    run_acceptance,
    validate_attestation,
    validate_request,
    write_private_json,
)
from devcoordinator.universal_test_store import (  # noqa: E402
    TestStoreConflict,
    TestStoreContractError,
)


MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_RELEASE_MANIFEST_BYTES = 4 * 1024 * 1024
IMMUTABLE_RELEASE_ROOT = Path("/opt/devcoordinator/releases")
RELEASE_FILE_PATHS = {
    "executor": Path("scripts/run_live_fault_isolation_acceptance.py"),
    "fault_helper": Path(
        "skills/codex-dev-coordinator/scripts/devcoordinator/live_fault_driver.py"
    ),
    "runner": Path(
        "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_runner.py"
    ),
}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_OWNER_EVIDENCE_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_VOLATILE_KEYS = frozenset(
    {
        "cpu",
        "cpu_percent",
        "memory",
        "memory_bytes",
        "memory_mib",
        "usage",
        "observed_at",
        "updated_at",
        "published_at",
        "last_seen_at",
        "age_seconds",
    }
)


def _absolute_existing(path: Path, label: str) -> Path:
    path = path.expanduser()
    if not path.is_absolute() or ".." in path.parts:
        raise FaultAcceptanceError(f"{label} must be one absolute path")
    absolute = Path(os.path.abspath(path))
    try:
        if absolute.resolve(strict=True) != absolute:
            raise FaultAcceptanceError(f"{label} must already be canonical")
    except OSError as error:
        raise FaultAcceptanceError(f"{label} is unavailable") from error
    return absolute


def _read_release_manifest(
    path: Path, *, expected_uid: int, expected_gid: int
) -> dict[str, object]:
    try:
        before = path.lstat()
    except OSError as error:
        raise FaultAcceptanceError("release manifest is unavailable") from error
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != expected_uid
        or before.st_gid != expected_gid
        or stat.S_IMODE(before.st_mode) != 0o444
        or before.st_nlink != 1
        or not 1 <= before.st_size <= MAX_RELEASE_MANIFEST_BYTES
    ):
        raise FaultAcceptanceError("release manifest is unsafe")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        chunks: list[bytes] = []
        observed = 0
        while True:
            block = os.read(
                descriptor,
                min(65536, MAX_RELEASE_MANIFEST_BYTES + 1 - observed),
            )
            if not block:
                break
            chunks.append(block)
            observed += len(block)
            if observed > MAX_RELEASE_MANIFEST_BYTES:
                raise FaultAcceptanceError("release manifest exceeds its byte bound")
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = path.lstat()
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        len(payload) > MAX_RELEASE_MANIFEST_BYTES
        or identity
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or identity
        != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
    ):
        raise FaultAcceptanceError("release manifest changed while it was read")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FaultAcceptanceError("release manifest is invalid JSON") from error
    if not isinstance(value, dict):
        raise FaultAcceptanceError("release manifest must be one object")
    return value


def _derive_release_binding(
    release_root: Path,
    *,
    executable: Path,
    expected_uid: int = 0,
    expected_gid: int = 0,
    immutable_root: Path = IMMUTABLE_RELEASE_ROOT,
) -> dict[str, object]:
    """Bind the three immutable executors to the release manifest and tree."""

    release_root = _absolute_existing(release_root, "immutable release")
    immutable_root = _absolute_existing(immutable_root, "immutable release root")
    root_info = release_root.lstat()
    if (
        release_root.parent != immutable_root
        or _SHA256_RE.fullmatch(release_root.name) is None
        or stat.S_ISLNK(root_info.st_mode)
        or not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != expected_uid
        or root_info.st_gid != expected_gid
        or stat.S_IMODE(root_info.st_mode) != 0o555
    ):
        raise FaultAcceptanceError("fault acceptance release root is not immutable")
    manifest = _read_release_manifest(
        release_root / "release-manifest.json",
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if set(manifest) != {
        "schema_version",
        "release_digest",
        "release_directory",
        "source_identity",
        "files",
        "capabilities",
    }:
        raise FaultAcceptanceError("release manifest fields are invalid")
    entries = manifest["files"]
    capabilities = manifest["capabilities"]
    if (
        manifest["schema_version"] != 1
        or manifest["release_digest"] != release_root.name
        or manifest["release_directory"] is not None
        or not isinstance(entries, list)
        or not entries
        or len(entries) > 10_000
        or not isinstance(capabilities, Mapping)
        or capabilities.get("live_fault_isolation_acceptance") is not True
    ):
        raise FaultAcceptanceError("release manifest does not authorize live fault acceptance")
    normalized_entries: list[dict[str, object]] = []
    paths: set[str] = set()
    for raw in entries:
        if not isinstance(raw, Mapping) or set(raw) != {
            "path",
            "sha256",
            "size",
            "mode",
            "kind",
        }:
            raise FaultAcceptanceError("release manifest file entry is invalid")
        entry = dict(raw)
        relative = entry["path"]
        if (
            not isinstance(relative, str)
            or not relative
            or relative.startswith("/")
            or any(part in {"", ".", ".."} for part in Path(relative).parts)
            or relative in paths
            or not isinstance(entry["sha256"], str)
            or _SHA256_RE.fullmatch(entry["sha256"]) is None
            or type(entry["size"]) is not int
            or not 0 <= entry["size"] <= MAX_FILE_BYTES
            or entry["mode"] not in {"0444", "0555"}
            or entry["kind"] not in {"source", "wrapper", "copy"}
        ):
            raise FaultAcceptanceError("release manifest file entry is invalid")
        paths.add(relative)
        normalized_entries.append(entry)
    if [entry["path"] for entry in normalized_entries] != sorted(paths):
        raise FaultAcceptanceError("release manifest file inventory is not canonical")
    if _digest({"schema_version": 1, "files": normalized_entries}) != release_root.name:
        raise FaultAcceptanceError("release manifest digest does not match its directory")
    entries_by_path = {str(entry["path"]): entry for entry in normalized_entries}
    binding: dict[str, object] = {
        "root": str(release_root),
        "digest": release_root.name,
    }
    for name, relative in RELEASE_FILE_PATHS.items():
        entry = entries_by_path.get(relative.as_posix())
        path = release_root / relative
        if entry is None:
            raise FaultAcceptanceError(f"release omitted required {name}")
        try:
            info = path.lstat()
        except OSError as error:
            raise FaultAcceptanceError(f"release {name} is unavailable") from error
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_uid
            or info.st_gid != expected_gid
            or stat.S_IMODE(info.st_mode) != int(str(entry["mode"]), 8)
            or info.st_size != entry["size"]
        ):
            raise FaultAcceptanceError(f"release {name} metadata changed")
        digest = _sha256_file(path, expected_uid=expected_uid)
        if digest != entry["sha256"]:
            raise FaultAcceptanceError(f"release {name} digest changed")
        binding[name] = str(path)
        binding[f"{name}_sha256"] = digest
    if _absolute_existing(executable, "running executor") != Path(str(binding["executor"])):
        raise FaultAcceptanceError("build-request is not running from the selected release")
    return binding


def _sha256_file(path: Path, *, expected_uid: int = 0) -> str:
    try:
        before = path.lstat()
    except OSError as error:
        raise FaultAcceptanceError(f"release file is unavailable: {path}") from error
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != expected_uid
        or before.st_mode & 0o022
        or before.st_size > MAX_FILE_BYTES
    ):
        raise FaultAcceptanceError(f"release file is unsafe: {path}")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    digest = hashlib.sha256()
    observed = 0
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            observed += len(chunk)
            if observed > MAX_FILE_BYTES:
                raise FaultAcceptanceError("release file exceeds its byte bound")
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = path.lstat()
    if (
        observed != before.st_size
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
    ):
        raise FaultAcceptanceError("release file changed while it was hashed")
    return digest.hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _query_authority_snapshot(
    database: Path, *, integrity_check: bool
) -> tuple[dict[str, object], list[dict[str, object]]]:
    try:
        connection = sqlite3.connect(
            f"{database.as_uri()}?mode=ro", uri=True, timeout=10.0
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only = ON")
            connection.execute("BEGIN")
            if integrity_check:
                quick = [str(row[0]) for row in connection.execute("PRAGMA quick_check")]
                if quick != ["ok"] or connection.execute(
                    "PRAGMA foreign_key_check"
                ).fetchone() is not None:
                    raise FaultAcceptanceError(
                        "schema-13 authority database integrity failed"
                    )
            metadata_rows = connection.execute(
                """
                SELECT schema_version, database_generation, state_revision,
                       migration_state
                FROM schema_metadata WHERE singleton = 1
                """
            ).fetchall()
            active_count = int(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM repositories repository
                    JOIN repository_installations installation USING(repo_id)
                    WHERE repository.state = 'active'
                      AND installation.status = 'installed'
                      AND installation.startup_fenced = 0
                    """
                ).fetchone()[0]
            )
            rows = connection.execute(
                """
                SELECT repository.repo_id, repository.host_id,
                       repository.canonical_root, repository.generation,
                       owner.owner_uid, owner.repository_generation,
                       owner.authority_generation, owner.evidence_sha256,
                       owner.operation_id,
                       transfer.owner_uid AS ledger_owner_uid,
                       transfer.repository_generation AS ledger_repository_generation,
                       transfer.authority_generation AS ledger_authority_generation,
                       transfer.evidence_sha256 AS ledger_evidence_sha256,
                       transfer.operation_id AS ledger_operation_id
                FROM repositories repository
                JOIN hosts host ON host.host_id = repository.host_id
                JOIN repository_installations installation USING(repo_id)
                JOIN repository_owners owner USING(repo_id)
                JOIN repository_owner_transfers transfer
                  ON transfer.repo_id = owner.repo_id
                 AND transfer.authority_generation = owner.authority_generation
                WHERE repository.state = 'active'
                  AND installation.status = 'installed'
                  AND installation.startup_fenced = 0
                ORDER BY repository.repo_id
                """
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise FaultAcceptanceError(
            "schema-13 authority database could not be read"
        ) from error
    if len(metadata_rows) != 1:
        raise FaultAcceptanceError("schema-13 authority metadata is ambiguous")
    metadata_row = metadata_rows[0]
    metadata = {
        "schema_version": int(metadata_row[0]),
        "database_generation": str(metadata_row[1]),
        "state_revision": int(metadata_row[2]),
        "migration_state": str(metadata_row[3]),
        "active_repository_count": active_count,
    }
    return metadata, [dict(row) for row in rows]


def _read_authority_repository_binding(
    database: Path,
    *,
    repository_root: Path,
    expected_database_uid: int,
) -> tuple[dict[str, object], dict[str, object]]:
    """Read one stable schema-13 owner binding without mutating authority."""

    database = _absolute_existing(database, "authority database")
    repository_root = _absolute_existing(repository_root, "fault repository root")
    before = database.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != expected_database_uid
        or stat.S_IMODE(before.st_mode) & 0o077
        or before.st_nlink != 1
    ):
        raise FaultAcceptanceError("schema-13 authority database is unsafe")
    first = _query_authority_snapshot(database, integrity_check=True)
    second = _query_authority_snapshot(database, integrity_check=False)
    after = database.lstat()
    if (
        first != second
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        raise FaultAcceptanceError("schema-13 authority changed while it was read")
    metadata, rows = first
    if (
        metadata["schema_version"] != 13
        or metadata["migration_state"] != "ready"
        or not metadata["database_generation"]
        or len(str(metadata["database_generation"])) > 256
        or type(metadata["state_revision"]) is not int
        or int(metadata["state_revision"]) < 0
        or metadata["active_repository_count"] != len(rows)
    ):
        raise FaultAcceptanceError(
            "schema-13 authority is not ready or owner-complete"
        )
    normalized: list[dict[str, object]] = []
    for row in rows:
        try:
            owner_uid = int(row["owner_uid"])
            generation = int(row["generation"])
            owner_generation = int(row["repository_generation"])
            authority_generation = int(row["authority_generation"])
            ledger_owner_uid = int(row["ledger_owner_uid"])
            ledger_generation = int(row["ledger_repository_generation"])
            ledger_authority_generation = int(row["ledger_authority_generation"])
        except (TypeError, ValueError) as error:
            raise FaultAcceptanceError(
                "schema-13 repository owner binding is invalid"
            ) from error
        root_text = str(row["canonical_root"])
        root = Path(root_text)
        evidence = str(row["evidence_sha256"])
        operation_id = str(row["operation_id"])
        if (
            not root.is_absolute()
            or str(root) != (root_text.rstrip("/") or "/")
            or any(part in {".", ".."} for part in root.parts)
            or not 1 <= owner_uid < 2**31
            or generation < 1
            or owner_generation != generation
            or authority_generation < 1
            or ledger_owner_uid != owner_uid
            or ledger_generation != generation
            or ledger_authority_generation != authority_generation
            or str(row["ledger_evidence_sha256"]) != evidence
            or str(row["ledger_operation_id"]) != operation_id
            or _OWNER_EVIDENCE_RE.fullmatch(evidence) is None
            or not operation_id
        ):
            raise FaultAcceptanceError(
                "schema-13 repository owner binding is contradictory"
            )
        normalized.append(
            {
                "repository_id": str(row["repo_id"]),
                "host_id": str(row["host_id"]),
                "root": root_text,
                "generation": generation,
                "owner_uid": owner_uid,
            }
        )
    matches = [row for row in normalized if row["root"] == str(repository_root)]
    if len(matches) != 1:
        raise FaultAcceptanceError(
            "fault repository has no exact schema-13 owner binding"
        )
    selected = matches[0]
    root_info = repository_root.lstat()
    if (
        stat.S_ISLNK(root_info.st_mode)
        or not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != selected["owner_uid"]
    ):
        raise FaultAcceptanceError(
            "fault repository filesystem owner differs from schema-13 authority"
        )
    unrelated = sorted(
        str(row["repository_id"])
        for row in normalized
        if row["host_id"] == selected["host_id"]
        and row["repository_id"] != selected["repository_id"]
    )
    if not unrelated or len(unrelated) != len(set(unrelated)):
        raise FaultAcceptanceError(
            "fault acceptance requires unrelated repositories on the same host"
        )
    try:
        host_boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="ascii"
        ).strip()
    except OSError as error:
        raise FaultAcceptanceError("host boot identity is unavailable") from error
    authority = {
        "host_id": selected["host_id"],
        "host_boot_id": host_boot_id,
        "database_generation": metadata["database_generation"],
        "state_revision": metadata["state_revision"],
    }
    repository = {
        "repository_id": selected["repository_id"],
        "generation": selected["generation"],
        "owner_uid": selected["owner_uid"],
        "root": selected["root"],
        "unrelated_repository_ids": unrelated,
    }
    return authority, repository


def _read_cutover_binding(
    *,
    cutover_id: str,
    activation_path: Path,
    live_rollback_path: Path,
    release: Mapping[str, object],
    expected_uid: int,
) -> dict[str, object]:
    try:
        activated = cutover.verify_seal(
            read_private_json(activation_path, expected_uid=expected_uid),
            kind=cutover.ACTIVATION_KIND,
            fields=cutover.ACTIVATION_FIELDS,
        )
        live = cutover.verify_seal(
            read_private_json(live_rollback_path, expected_uid=expected_uid),
            kind=cutover.LIVE_ROLLBACK_REHEARSAL_KIND,
            fields=cutover.LIVE_ROLLBACK_REHEARSAL_FIELDS,
        )
    except (cutover.CutoverError, KeyError, TypeError) as error:
        raise FaultAcceptanceError(
            "activation or live rollback evidence is invalid"
        ) from error
    release_digest = release.get("digest")
    release_root = release.get("root")
    if (
        activated.get("release_digest") != release_digest
        or activated.get("executor_release") != release_root
        or live.get("release_digest") != release_digest
        or live.get("executor_release") != release_root
    ):
        raise FaultAcceptanceError(
            "activation or live rollback evidence binds another release"
        )
    if live.get("activation_sha256") != activated.get("document_sha256"):
        raise FaultAcceptanceError(
            "live rollback evidence binds another activation"
        )
    return {
        "cutover_id": cutover_id,
        "activation_sha256": activated["document_sha256"],
        "live_rollback_rehearsal_sha256": live["document_sha256"],
    }


def _inventory_binding(
    publication_path: Path,
    *,
    expected_owner_uid: int,
    repository: Mapping[str, object],
) -> dict[str, object]:
    publication_path = _absolute_existing(
        publication_path, "retained inventory publication"
    )
    try:
        projection = read_projection(
            publication_path, expected_owner_uid=expected_owner_uid
        )
    except InventoryProjectionError as error:
        raise FaultAcceptanceError(
            "retained inventory publication is invalid"
        ) from error
    inventory = projection.get("inventory")
    if not isinstance(inventory, Mapping):
        raise FaultAcceptanceError("retained inventory projection is invalid")
    repositories = inventory.get("repositories")
    if not isinstance(repositories, list):
        raise FaultAcceptanceError("retained repository inventory is unavailable")
    present = {
        str(row.get("repo_id"))
        for row in repositories
        if isinstance(row, Mapping) and isinstance(row.get("repo_id"), str)
    }
    expected = {
        str(repository["repository_id"]),
        *[str(item) for item in repository["unrelated_repository_ids"]],
    }
    if not expected <= present:
        raise FaultAcceptanceError(
            "retained inventory does not cover the authority-bound repositories"
        )
    return {
        "publication": str(publication_path),
        "expected_owner_uid": expected_owner_uid,
    }


def _fixed_control_and_probe_inputs(
    arguments: argparse.Namespace,
) -> tuple[dict[str, object], dict[str, object]]:
    cgroups: dict[str, object] = {
        "api": str(arguments.api_cgroup_procs),
        "authority": str(arguments.authority_cgroup_procs),
        "console": str(arguments.console_cgroup_procs),
        "edge": str(arguments.edge_cgroup_procs),
    }
    if arguments.console_standby_cgroup_procs is not None:
        cgroups["console-standby"] = str(arguments.console_standby_cgroup_procs)
    probes = {
        "http": [
            {"target_id": "api", "category": "api", "url": arguments.api_url},
            {
                "target_id": "board",
                "category": "board",
                "url": arguments.board_url,
            },
            {
                "target_id": "console",
                "category": "console",
                "url": arguments.console_url,
            },
            {
                "target_id": "project",
                "category": "project",
                "url": arguments.project_url,
            },
        ],
        "websocket": [
            {
                "target_id": "project-events",
                "category": "project",
                "url": arguments.websocket_url,
            }
        ],
    }
    return cgroups, probes


def _strip_volatile(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            str(key): _strip_volatile(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if str(key) not in _VOLATILE_KEYS
        }
    if isinstance(value, list):
        return [_strip_volatile(item) for item in value]
    return value


def _unrelated_state(
    inventory: Mapping[str, object], repository_ids: list[str]
) -> tuple[str, str]:
    wanted = set(repository_ids)
    trees = inventory.get("repository_trees")
    repositories = inventory.get("repositories")
    resources = inventory.get("resources")
    if not isinstance(trees, list) or not isinstance(repositories, list) or not isinstance(resources, Mapping):
        raise FaultAcceptanceError("retained inventory has no exact repository tree")
    matched_trees = []
    resource_ids: dict[str, set[str]] = {
        "servers": set(),
        "docker": set(),
        "databases": set(),
    }
    for tree in trees:
        if not isinstance(tree, Mapping):
            raise FaultAcceptanceError("retained repository tree is invalid")
        scopes = tree.get("scopes")
        if not isinstance(scopes, list):
            raise FaultAcceptanceError("retained repository scopes are invalid")
        selected = [scope for scope in scopes if isinstance(scope, Mapping) and scope.get("repo_id") in wanted]
        if not selected:
            continue
        matched_trees.append(_strip_volatile(tree))
        for scope in selected:
            for key, resource_kind in (
                ("server_ids", "servers"),
                ("container_resource_ids", "docker"),
                ("database_binding_ids", "databases"),
            ):
                raw_ids = scope.get(key)
                if not isinstance(raw_ids, list) or any(not isinstance(item, str) for item in raw_ids):
                    raise FaultAcceptanceError("retained repository association is invalid")
                resource_ids[resource_kind].update(raw_ids)
    present = {
        scope.get("repo_id")
        for tree in trees
        if isinstance(tree, Mapping)
        for scope in tree.get("scopes", [])
        if isinstance(scope, Mapping) and scope.get("repo_id") in wanted
    }
    if present != wanted:
        raise FaultAcceptanceError("one or more unrelated repositories disappeared")
    matched_repositories = [
        _strip_volatile(item)
        for item in repositories
        if isinstance(item, Mapping) and item.get("repo_id") in wanted
    ]
    matched_resources: dict[str, object] = {}
    identity_fields = {
        "servers": ("server_definition_id",),
        "docker": ("docker_resource_id", "host_resource_id"),
        "databases": ("database_binding_id",),
    }
    for kind, ids in resource_ids.items():
        rows = resources.get(kind)
        if not isinstance(rows, list):
            raise FaultAcceptanceError("retained resource catalog is invalid")
        matched_resources[kind] = [
            _strip_volatile(item)
            for item in rows
            if isinstance(item, Mapping)
            and any(item.get(field) in ids for field in identity_fields[kind])
        ]
    observed_servers = inventory.get("servers")
    docker_observation = inventory.get("docker")
    if not isinstance(observed_servers, list) or not isinstance(
        docker_observation, Mapping
    ):
        raise FaultAcceptanceError(
            "retained inventory has no observed server/container state"
        )
    observed_containers = docker_observation.get("containers")
    observed_databases = docker_observation.get("postgres")
    if not isinstance(observed_containers, list) or not isinstance(
        observed_databases, list
    ):
        raise FaultAcceptanceError(
            "retained inventory observed Docker state is invalid"
        )
    observations = {
        "servers": [
            _strip_volatile(item)
            for item in observed_servers
            if isinstance(item, Mapping)
            and item.get("id") in resource_ids["servers"]
        ],
        "containers": [
            _strip_volatile(item)
            for item in observed_containers
            if isinstance(item, Mapping)
            and any(
                item.get(field) in resource_ids["docker"]
                for field in (
                    "docker_resource_id",
                    "host_resource_id",
                    "id",
                    "container_id",
                )
            )
        ],
        "databases": [
            _strip_volatile(item)
            for item in observed_databases
            if isinstance(item, Mapping)
            and item.get("database_binding_id") in resource_ids["databases"]
        ],
    }
    state = {
        "repository_ids": repository_ids,
        "repositories": matched_repositories,
        "trees": matched_trees,
        "resources": matched_resources,
        "observations": observations,
    }
    required_attention = {"unassigned_resources", "lifecycle_violations"}
    if not required_attention <= set(inventory):
        raise FaultAcceptanceError(
            "retained inventory has no global attention-state projection"
        )
    attention = {
        key: _strip_volatile(inventory.get(key))
        for key in (
            "unassigned_resources",
            "lifecycle_violations",
            "warnings",
            "problems",
            "attention",
        )
        if key in inventory
    }
    return _digest(state), _digest(attention)


def _control_processes(cgroups: Mapping[str, object]) -> str:
    result: dict[str, list[str]] = {}
    for name, raw_path in sorted(cgroups.items()):
        path = Path(str(raw_path))
        try:
            raw = path.read_text(encoding="ascii")
        except OSError as error:
            raise FaultAcceptanceError(f"control cgroup is unavailable: {name}") from error
        identities: list[str] = []
        for line in raw.splitlines():
            if not line.isdigit() or int(line) <= 0:
                raise FaultAcceptanceError("control cgroup process identity is invalid")
            pid = int(line)
            try:
                stat_fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()
            except (OSError, IndexError) as error:
                raise FaultAcceptanceError("control process changed during observation") from error
            if len(stat_fields) < 20 or stat_fields[0] == "Z":
                raise FaultAcceptanceError("control process identity is invalid")
            identities.append(f"linux:{pid}:{stat_fields[19]}")
        if name in {"edge", "console"} and not identities:
            raise FaultAcceptanceError(f"required control process is not running: {name}")
        result[str(name)] = sorted(identities)
    return _digest(result)


class HostFaultObserver:
    """Read-only retained/public observations; never manages a native resource."""

    def __init__(self, request: Mapping[str, object]) -> None:
        self.request = request
        self._baseline: dict[str, int] = {}

    def capture(self, phase: str) -> Mapping[str, object]:
        targets = self.request["probe_targets"]
        repository = self.request["repository"]
        inventory_binding = self.request["inventory"]
        if not isinstance(targets, Mapping) or not isinstance(repository, Mapping) or not isinstance(inventory_binding, Mapping):
            raise FaultAcceptanceError("fault observer request is invalid")
        refused = 0
        project_failures = 0
        failures = 0
        http_count = 0
        websocket_count = 0
        for protocol, probe in (
            ("http", activation._probe_url),
            ("websocket", activation._probe_websocket),
        ):
            for target in targets[protocol]:
                if not isinstance(target, Mapping):
                    raise FaultAcceptanceError("fault observer target is invalid")
                started = time.monotonic_ns()
                status, was_refused = probe(str(target["url"]))
                latency_ms = (time.monotonic_ns() - started + 999_999) // 1_000_000
                target_id = f"{protocol}:{target['target_id']}"
                expected_status = 101 if protocol == "websocket" else self._baseline.get(target_id)
                if (
                    phase == "pre"
                    and protocol == "http"
                    and target_id not in self._baseline
                    and isinstance(status, int)
                    and status < 500
                ):
                    self._baseline[target_id] = status
                    expected_status = status
                failed = bool(was_refused) or status is None or latency_ms > 5_000
                if expected_status is None or status != expected_status:
                    failed = True
                refused += int(was_refused)
                failures += int(failed)
                project_failures += int(failed and target["category"] == "project")
                if protocol == "http":
                    http_count += 1
                else:
                    websocket_count += 1
        publication = read_projection(
            Path(str(inventory_binding["publication"])),
            expected_owner_uid=int(inventory_binding["expected_owner_uid"]),
        )
        inventory = publication.get("inventory")
        if not isinstance(inventory, Mapping):
            raise FaultAcceptanceError("retained inventory projection is invalid")
        unrelated, attention = _unrelated_state(
            inventory,
            [str(item) for item in repository["unrelated_repository_ids"]],
        )
        return {
            "phase": phase,
            "captured_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "http_sample_count": http_count,
            "websocket_sample_count": websocket_count,
            "connection_refused_count": refused,
            "project_route_failures": project_failures,
            "failed_sample_count": failures,
            "control_processes_sha256": _control_processes(self.request["control_cgroups"]),
            "socket_inodes_sha256": _digest(activation.socket_inodes()),
            "unrelated_project_state_sha256": unrelated,
            "global_attention_state_sha256": attention,
            "passed": failures == 0 and refused == 0 and project_failures == 0,
        }


def _verify_release_binding(request: Mapping[str, object], *, executable: Path) -> None:
    release = request["release"]
    authority = request["authority"]
    repository = request["repository"]
    if not isinstance(release, Mapping) or not isinstance(authority, Mapping) or not isinstance(repository, Mapping):
        raise FaultAcceptanceError("fault acceptance binding is invalid")
    resolved = executable.resolve(strict=True)
    if resolved != Path(str(release["executor"])):
        raise FaultAcceptanceError("running executor is not the request-bound immutable file")
    for name in ("executor", "fault_helper", "runner"):
        path = Path(str(release[name]))
        if _sha256_file(path) != release[f"{name}_sha256"]:
            raise FaultAcceptanceError(f"release {name} digest changed")
    try:
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except OSError as error:
        raise FaultAcceptanceError("host boot identity is unavailable") from error
    if boot_id != authority["host_boot_id"]:
        raise FaultAcceptanceError("fault acceptance request is stale across host boot")
    root = Path(str(repository["root"]))
    info = root.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != repository["owner_uid"]
    ):
        raise FaultAcceptanceError("fault repository ownership changed")


def _build_request(
    arguments: argparse.Namespace,
    *,
    effective_uid: int | None = None,
    executable: Path | None = None,
    created_at: datetime | None = None,
    request_builder: Callable[..., dict[str, object]] = build_fault_request,
) -> dict[str, object]:
    uid = os.geteuid() if effective_uid is None else effective_uid
    if uid != 0:
        raise FaultAcceptanceError("live fault request construction requires root authority")
    if arguments.authority_owner_uid < 0 or arguments.inventory_owner_uid < 0:
        raise FaultAcceptanceError("trusted owner UID is invalid")
    release = _derive_release_binding(
        arguments.release,
        executable=executable or Path(__file__),
        expected_uid=uid,
        expected_gid=0,
    )
    cutover_binding = _read_cutover_binding(
        cutover_id=arguments.cutover_id,
        activation_path=arguments.activation,
        live_rollback_path=arguments.live_rollback_rehearsal,
        release=release,
        expected_uid=uid,
    )
    authority, repository = _read_authority_repository_binding(
        arguments.authority_database,
        repository_root=arguments.repository_root,
        expected_database_uid=arguments.authority_owner_uid,
    )
    inventory = _inventory_binding(
        arguments.inventory_publication,
        expected_owner_uid=arguments.inventory_owner_uid,
        repository=repository,
    )
    cgroups, probes = _fixed_control_and_probe_inputs(arguments)
    request = request_builder(
        operation_id=arguments.operation_id,
        cutover=cutover_binding,
        release=release,
        authority=authority,
        repository=repository,
        inventory=inventory,
        control_cgroups=cgroups,
        probe_targets=probes,
        created_at=created_at,
    )
    write_private_json(arguments.output, request, expected_uid=uid)
    return {
        "ok": True,
        "request": str(arguments.output),
        "document_sha256": request["document_sha256"],
        "release_digest": release["digest"],
        "repository_id": repository["repository_id"],
        "repository_generation": repository["generation"],
        "owner_uid": repository["owner_uid"],
        "cutover_id": cutover_binding["cutover_id"],
    }


def _run(arguments: argparse.Namespace, *, effective_uid: int | None = None) -> dict[str, object]:
    uid = os.geteuid() if effective_uid is None else effective_uid
    if uid != 0:
        raise FaultAcceptanceError("live fault acceptance requires root authority")
    request = validate_request(read_private_json(arguments.request, expected_uid=uid))
    if arguments.attestation.exists() or arguments.attestation.is_symlink():
        existing = validate_attestation(
            read_private_json(arguments.attestation, expected_uid=uid),
            request=request,
            require_fresh=True,
        )
        return {"ok": True, "replayed": True, "attestation": existing}
    _verify_release_binding(request, executable=Path(__file__))
    release = request["release"]
    if not isinstance(release, Mapping):
        raise FaultAcceptanceError("release binding is invalid")
    manager = FaultAcceptanceAttemptManager(
        runner_script=Path(str(release["runner"])),
        snapshot_root=arguments.snapshot_root,
        attempt_root=arguments.attempt_root,
        artifact_root=arguments.artifact_root,
    )
    attestation = run_acceptance(
        request,
        runtime=NativeFaultRuntime(request=request, manager=manager),
        observer=HostFaultObserver(request),
    )
    write_private_json(arguments.attestation, attestation, expected_uid=uid)
    return {"ok": True, "replayed": False, "attestation": attestation}


def _verify(arguments: argparse.Namespace, *, effective_uid: int | None = None) -> dict[str, object]:
    uid = os.geteuid() if effective_uid is None else effective_uid
    if uid != 0:
        raise FaultAcceptanceError("live fault acceptance verification requires root authority")
    request = validate_request(read_private_json(arguments.request, expected_uid=uid))
    _verify_release_binding(request, executable=Path(__file__))
    attestation = validate_attestation(
        read_private_json(arguments.attestation, expected_uid=uid),
        request=request,
        require_fresh=arguments.require_fresh,
    )
    return {"ok": True, "attestation": attestation}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser(
        "build-request",
        help="derive and atomically publish one root-private fixed campaign request",
    )
    build.add_argument("--operation-id", required=True)
    build.add_argument("--cutover-id", required=True)
    build.add_argument("--release", type=Path, required=True)
    build.add_argument("--activation", type=Path, required=True)
    build.add_argument("--live-rollback-rehearsal", type=Path, required=True)
    build.add_argument("--authority-database", type=Path, required=True)
    build.add_argument("--authority-owner-uid", type=int, required=True)
    build.add_argument("--repository-root", type=Path, required=True)
    build.add_argument("--inventory-publication", type=Path, required=True)
    build.add_argument("--inventory-owner-uid", type=int, required=True)
    build.add_argument("--edge-cgroup-procs", type=Path, required=True)
    build.add_argument("--api-cgroup-procs", type=Path, required=True)
    build.add_argument("--authority-cgroup-procs", type=Path, required=True)
    build.add_argument("--console-cgroup-procs", type=Path, required=True)
    build.add_argument("--console-standby-cgroup-procs", type=Path)
    build.add_argument("--console-url", required=True)
    build.add_argument("--board-url", required=True)
    build.add_argument("--api-url", required=True)
    build.add_argument("--project-url", required=True)
    build.add_argument("--websocket-url", required=True)
    build.add_argument("--output", type=Path, required=True)
    run = commands.add_parser("run", help="run all fixed fault scenarios and publish evidence")
    run.add_argument("--request", type=Path, required=True)
    run.add_argument("--attestation", type=Path, required=True)
    run.add_argument("--snapshot-root", type=Path, default=Path("/var/lib/devcoordinator-test-snapshots"))
    run.add_argument("--attempt-root", type=Path, default=Path("/var/lib/devcoordinator-test-runs"))
    run.add_argument("--artifact-root", type=Path, default=Path("/var/lib/devcoordinator-test-artifacts"))
    verify = commands.add_parser("verify", help="verify one sealed fault attestation")
    verify.add_argument("--request", type=Path, required=True)
    verify.add_argument("--attestation", type=Path, required=True)
    verify.add_argument("--require-fresh", action="store_true")
    arguments = parser.parse_args(argv)
    for name, value in vars(arguments).items():
        if isinstance(value, Path):
            value = value.expanduser()
            if not value.is_absolute():
                parser.error(f"--{name.replace('_', '-')} must be absolute")
            value = value.absolute()
            setattr(arguments, name, value)
    return arguments


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(argv)
    try:
        if arguments.command == "build-request":
            result = _build_request(arguments)
        elif arguments.command == "run":
            result = _run(arguments)
        else:
            result = _verify(arguments)
    except (FaultAcceptanceError, TestStoreConflict, TestStoreContractError, OSError, ValueError) as error:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error_code": getattr(error, "code", "fault_acceptance_failed"),
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
