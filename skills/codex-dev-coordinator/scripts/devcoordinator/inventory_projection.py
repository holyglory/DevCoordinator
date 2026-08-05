"""Bounded retained inventory publication outside the authority database."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import tempfile
from typing import Any, Mapping


PROJECTION_SCHEMA = 1
MAX_PROJECTION_BYTES = 64 * 1024 * 1024
INVENTORY_STORE_SCHEMA = 1
MAX_RETAINED_GENERATIONS = 64
MAX_INVENTORY_STORE_LOGICAL_BYTES = 256 * 1024 * 1024
MIN_INVENTORY_STORE_FREE_BYTES = 16 * 1024 * 1024

_REQUIRED_NORMALIZED_LISTS = (
    "servers",
    "repositories",
    "repository_trees",
    "memberships",
    "unassigned_resources",
    "lifecycle_violations",
)
_REQUIRED_RESOURCE_LISTS = ("servers", "docker", "databases")
_REQUIRED_OBSERVATION_LISTS = ("servers", "docker", "databases")
_V1_COMPATIBILITY_KEYS = (
    "coordinator_home",
    "state_path",
    "project",
    "urls",
    "servers",
    "leases",
    "port_assignments",
    "recent_events",
    "docker",
    "postgres",
    "backups",
    "project_usage",
)


class InventoryProjectionError(RuntimeError):
    pass


_INVENTORY_STORE_SCHEMA_SQL = """
CREATE TABLE inventory_store_metadata (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_version INTEGER NOT NULL,
    active_generation INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE inventory_publications (
    generation INTEGER PRIMARY KEY CHECK(generation > 0),
    published_at TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    envelope_json BLOB NOT NULL,
    logical_bytes INTEGER NOT NULL CHECK(logical_bytes > 0),
    state TEXT NOT NULL CHECK(state IN ('pending', 'active', 'retained'))
);
CREATE UNIQUE INDEX one_active_inventory_publication
ON inventory_publications(state) WHERE state = 'active';
"""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise InventoryProjectionError(f"inventory is not bounded JSON: {error}") from error


def _digest(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(dict(payload))).hexdigest()


def _repository_contract_error(detail: str) -> None:
    raise InventoryProjectionError(
        f"inventory repository contract is invalid: {detail}"
    )


def _record_list(value: Any, *, name: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        _repository_contract_error(f"{name} is missing or malformed")
    return value


def _exact_string_ids(value: Any, *, name: str) -> list[str]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        _repository_contract_error(f"{name} is missing, malformed, or duplicated")
    return value


def _resource_index(
    rows: list[dict[str, Any]], *, id_key: str, name: str
) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for row in rows:
        resource_id = row.get(id_key)
        if not isinstance(resource_id, str) or not resource_id:
            _repository_contract_error(f"a {name} has no immutable ID")
        if resource_id in indexed:
            _repository_contract_error(f"a {name} immutable ID is duplicated")
        indexed[resource_id] = row
    return indexed


def _validate_repository_tree_contract(value: Mapping[str, Any]) -> None:
    """Reject a normalized graph the Console would have to fail closed on.

    Repository scopes and explicit ownership problems form one exhaustive,
    non-overlapping partition of current normalized resources.  Validating at
    publication keeps malformed observer output from replacing the retained
    last-known-good generation and makes the Python producer—not each UI—the
    owner of this invariant.
    """

    repositories = _record_list(value.get("repositories"), name="repositories")
    repository_trees = _record_list(
        value.get("repository_trees"), name="repository_trees"
    )
    memberships = _record_list(value.get("memberships"), name="memberships")
    unassigned = _record_list(
        value.get("unassigned_resources"), name="unassigned_resources"
    )
    lifecycle = _record_list(
        value.get("lifecycle_violations"), name="lifecycle_violations"
    )
    resources = value.get("resources")
    observations = value.get("observations")
    if not isinstance(resources, dict) or not isinstance(observations, dict):
        _repository_contract_error("normalized resource evidence is malformed")

    servers = _record_list(resources.get("servers"), name="resources.servers")
    docker = _record_list(resources.get("docker"), name="resources.docker")
    databases = _record_list(
        resources.get("databases"), name="resources.databases"
    )
    observed_docker = _record_list(
        observations.get("docker"), name="observations.docker"
    )
    observed_databases = _record_list(
        observations.get("databases"), name="observations.databases"
    )

    repositories_by_id: dict[str, dict[str, Any]] = {}
    repository_roots: set[str] = set()
    for repository in repositories:
        repo_id = repository.get("repo_id")
        canonical_root = repository.get("canonical_root")
        if (
            not isinstance(repo_id, str)
            or not repo_id
            or not isinstance(canonical_root, str)
            or not canonical_root.startswith("/")
            or repo_id in repositories_by_id
            or canonical_root in repository_roots
        ):
            _repository_contract_error(
                "repository identities are incomplete or duplicated"
            )
        repositories_by_id[repo_id] = repository
        repository_roots.add(canonical_root)

    servers_by_id = _resource_index(
        servers, id_key="server_definition_id", name="server"
    )
    docker_by_id = _resource_index(
        docker, id_key="docker_resource_id", name="container"
    )
    databases_by_id = _resource_index(
        databases, id_key="database_binding_id", name="database"
    )
    container_memberships: dict[str, dict[str, Any]] = {}
    for membership in memberships:
        if membership.get("resource_kind") != "container":
            continue
        resource_id = membership.get("host_resource_id")
        if not isinstance(resource_id, str) or not resource_id:
            _repository_contract_error(
                "a container membership has no immutable ID"
            )
        if resource_id in container_memberships:
            _repository_contract_error(
                "a container membership immutable ID is duplicated"
            )
        container_memberships[resource_id] = membership

    problem_ids = {"server": set(), "container": set(), "database": set()}
    seen_problem_ids: set[tuple[str, str]] = set()
    for problem in [*unassigned, *lifecycle]:
        kind = problem.get("resource_kind")
        resource_id = problem.get("resource_id")
        if (
            not isinstance(kind, str)
            or not kind
            or not isinstance(resource_id, str)
            or not resource_id
        ):
            _repository_contract_error(
                "an ownership problem has no immutable resource identity"
            )
        problem_key = (kind, resource_id)
        if problem_key in seen_problem_ids:
            _repository_contract_error(
                "an ownership problem immutable resource identity is duplicated"
            )
        if kind not in problem_ids:
            _repository_contract_error(
                "an ownership problem has an unknown normalized resource kind"
            )
        seen_problem_ids.add(problem_key)
        problem_ids[kind].add(resource_id)

    # Database ownership follows the immutable backing container. A database
    # may be outside a repository scope only when that exact parent container
    # is itself an explicit ownership/lifecycle problem. Accepting an isolated
    # database problem would let malformed producer output detach one binding
    # from an otherwise healthy assigned container.
    for resource_id in problem_ids["database"]:
        database = databases_by_id.get(resource_id)
        parent_id = None if database is None else database.get("docker_resource_id")
        if (
            not isinstance(parent_id, str)
            or not parent_id
            or parent_id not in docker_by_id
            or parent_id not in problem_ids["container"]
        ):
            _repository_contract_error(
                "a database ownership problem is not backed by its exact "
                "container ownership problem"
            )

    family_ids: set[str] = set()
    classified_repository_ids: set[str] = set()
    classified = {"server": set(), "container": set(), "database": set()}
    for tree in repository_trees:
        family_id = tree.get("family_id")
        root = tree.get("root_repository")
        if (
            not isinstance(family_id, str)
            or not family_id
            or family_id in family_ids
            or not isinstance(root, dict)
        ):
            _repository_contract_error(
                "a repository family identity is missing or duplicated"
            )
        family_ids.add(family_id)
        root_repository = repositories_by_id.get(str(root.get("repo_id") or ""))
        if (
            root_repository is None
            or root.get("canonical_root") != root_repository.get("canonical_root")
            or root.get("display_name") != root_repository.get("display_name")
        ):
            _repository_contract_error(
                "a repository family root contradicts its repository record"
            )
        scopes = _record_list(tree.get("scopes"), name="repository family scopes")
        if not scopes:
            _repository_contract_error("a repository family has no valid scopes")
        root_scopes = [scope for scope in scopes if scope.get("kind") == "root"]
        if len(root_scopes) != 1 or root_scopes[0].get("repo_id") != root.get("repo_id"):
            _repository_contract_error(
                "a repository family must contain exactly its own root scope"
            )
        for scope in scopes:
            if scope.get("kind") not in {"root", "temporary"}:
                _repository_contract_error("a repository scope has an unknown kind")
            repo_id = scope.get("repo_id")
            repository = repositories_by_id.get(str(repo_id or ""))
            if (
                repository is None
                or repo_id in classified_repository_ids
                or repository.get("host_id") != root_repository.get("host_id")
                or scope.get("canonical_root") != repository.get("canonical_root")
                or scope.get("display_name") != repository.get("display_name")
                or (scope.get("kind") == "temporary" and repo_id == root.get("repo_id"))
            ):
                _repository_contract_error(
                    "a repository scope is inconsistent or duplicated"
                )
            server_ids = _exact_string_ids(
                scope.get("server_ids"), name="scope.server_ids"
            )
            container_ids = _exact_string_ids(
                scope.get("container_resource_ids"),
                name="scope.container_resource_ids",
            )
            database_ids = _exact_string_ids(
                scope.get("database_binding_ids"),
                name="scope.database_binding_ids",
            )
            classified_repository_ids.add(str(repo_id))
            for resource_id in server_ids:
                row = servers_by_id.get(resource_id)
                if (
                    row is None
                    or row.get("repo_id") != repo_id
                    or resource_id in classified["server"]
                ):
                    _repository_contract_error(
                        "a server is missing, duplicated, or assigned to the "
                        "wrong repository scope"
                    )
                classified["server"].add(resource_id)
            for resource_id in container_ids:
                membership = container_memberships.get(resource_id)
                if (
                    resource_id not in docker_by_id
                    or membership is None
                    or membership.get("repo_id") != repo_id
                    or resource_id in classified["container"]
                ):
                    _repository_contract_error(
                        "a container is missing, duplicated, or assigned to the "
                        "wrong repository scope"
                    )
                classified["container"].add(resource_id)
            for resource_id in database_ids:
                row = databases_by_id.get(resource_id)
                if (
                    row is None
                    or row.get("repo_id") != repo_id
                    or row.get("docker_resource_id") not in container_ids
                    or resource_id in classified["database"]
                ):
                    _repository_contract_error(
                        "a database is missing, duplicated, or assigned to the "
                        "wrong repository scope"
                    )
                classified["database"].add(resource_id)

    if classified_repository_ids != set(repositories_by_id):
        _repository_contract_error(
            "the repository tree does not cover every repository exactly once"
        )

    normalized_ids = {
        "server": set(servers_by_id),
        "container": set(docker_by_id),
        "database": set(databases_by_id),
    }
    for kind in ("server", "container", "database"):
        if classified[kind] & problem_ids[kind]:
            _repository_contract_error(
                f"a {kind} is both repository-classified and an ownership problem"
            )
        if classified[kind] | problem_ids[kind] != normalized_ids[kind]:
            _repository_contract_error(
                "the repository tree and explicit ownership problems do not "
                "cover every normalized resource exactly once"
            )

    for rows, id_key, kind in (
        (observed_docker, "docker_resource_id", "container"),
        (observed_databases, "database_binding_id", "database"),
    ):
        observed_ids = _resource_index(rows, id_key=id_key, name=f"observed {kind}")
        if not set(observed_ids).issubset(normalized_ids[kind]):
            _repository_contract_error(
                f"an observed {kind} is absent from normalized resources"
            )


def _validate_inventory(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InventoryProjectionError("inventory projection must contain one object")
    encoded = _canonical(value)
    if len(encoded) > MAX_PROJECTION_BYTES - 4096:
        raise InventoryProjectionError("inventory projection exceeds its byte budget")
    if value.get("schema_version") not in {1, 2}:
        raise InventoryProjectionError("inventory schema is unsupported")
    for name in ("servers", "repositories"):
        if not isinstance(value.get(name), list):
            raise InventoryProjectionError(f"inventory.{name} must be a list")
    docker = value.get("docker")
    if not isinstance(docker, dict):
        raise InventoryProjectionError("inventory.docker must be an object")
    if not isinstance(docker.get("containers"), list):
        raise InventoryProjectionError("inventory.docker.containers must be a list")
    # Schema-1 publications remain readable so an already-installed minimal
    # first-deployment seed can be refreshed in place. New seeds are complete
    # (see ``empty_inventory`` below), while every normalized schema-2 source
    # is rejected before publication unless it carries the Console contract.
    normalized = value["schema_version"] == 2
    if normalized:
        for name in _REQUIRED_NORMALIZED_LISTS:
            if not isinstance(value.get(name), list):
                raise InventoryProjectionError(f"inventory.{name} must be a list")
        resources = value.get("resources")
        if not isinstance(resources, dict):
            raise InventoryProjectionError("inventory.resources must be an object")
        for name in _REQUIRED_RESOURCE_LISTS:
            if not isinstance(resources.get(name), list):
                raise InventoryProjectionError(f"inventory.resources.{name} must be a list")
        observations = value.get("observations")
        if not isinstance(observations, dict):
            raise InventoryProjectionError("inventory.observations must be an object")
        for name in _REQUIRED_OBSERVATION_LISTS:
            if not isinstance(observations.get(name), list):
                raise InventoryProjectionError(f"inventory.observations.{name} must be a list")
    if value["schema_version"] == 2:
        compatibility = value.get("v1_compatibility")
        if not isinstance(compatibility, dict):
            raise InventoryProjectionError(
                "inventory.v1_compatibility must be an object for schema 2"
            )
        missing = [name for name in _V1_COMPATIBILITY_KEYS if name not in compatibility]
        if missing:
            raise InventoryProjectionError(
                "inventory.v1_compatibility is missing required fields: "
                + ", ".join(missing)
            )
        _validate_repository_tree_contract(value)
    # Round-trip detaches mutable/custom mappings and rejects non-JSON values.
    return json.loads(encoded.decode("utf-8"))


def envelope(*, generation: int, inventory: Mapping[str, Any], published_at: str) -> dict[str, Any]:
    if type(generation) is not int or generation < 1:
        raise InventoryProjectionError("projection generation must be positive")
    payload = {
        "schema_version": PROJECTION_SCHEMA,
        "generation": generation,
        "published_at": str(published_at),
        "inventory": _validate_inventory(dict(inventory)),
    }
    return {**payload, "payload_sha256": _digest(payload)}


def validate_envelope(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "generation", "inventory", "payload_sha256", "published_at", "schema_version"
    }:
        raise InventoryProjectionError("inventory publication fields are invalid")
    if value.get("schema_version") != PROJECTION_SCHEMA:
        raise InventoryProjectionError("inventory publication schema is unsupported")
    if type(value.get("generation")) is not int or value["generation"] < 1:
        raise InventoryProjectionError("inventory publication generation is invalid")
    published_at = value.get("published_at")
    if not isinstance(published_at, str) or len(published_at) < 20 or len(published_at) > 40:
        raise InventoryProjectionError("inventory publication timestamp is invalid")
    inventory = _validate_inventory(value.get("inventory"))
    payload = {
        "schema_version": PROJECTION_SCHEMA,
        "generation": value["generation"],
        "published_at": published_at,
        "inventory": inventory,
    }
    if value.get("payload_sha256") != _digest(payload):
        raise InventoryProjectionError("inventory publication checksum is invalid")
    return {**payload, "payload_sha256": value["payload_sha256"]}


def read_projection(path: Path, *, expected_owner_uid: int | None = None) -> dict[str, Any]:
    del expected_owner_uid
    absolute = path.expanduser().absolute()
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise InventoryProjectionError("inventory publication no-follow open is unsupported")
    try:
        descriptor = os.open(
            absolute,
            os.O_RDONLY
            | nofollow
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError as error:
        raise InventoryProjectionError(f"cannot open inventory publication: {error}") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise InventoryProjectionError(
                "inventory publication must be a regular non-symlink file"
            )
        if info.st_size < 1 or info.st_size > MAX_PROJECTION_BYTES:
            raise InventoryProjectionError("inventory publication size is invalid")

        payload = bytearray()
        while len(payload) <= MAX_PROJECTION_BYTES:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, MAX_PROJECTION_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
    except OSError as error:
        raise InventoryProjectionError(
            f"inventory publication cannot be read: {error}"
        ) from error
    finally:
        os.close(descriptor)

    # Publication uses atomic path replacement.  The pathname may therefore
    # point at a newer valid generation while this descriptor continues to
    # provide the complete old generation.  Validate the opened object before
    # and after the bounded read; never compare it with the replaceable path.
    before_identity = (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    if before_identity != after_identity or len(payload) != info.st_size:
        raise InventoryProjectionError("inventory publication changed while it was read")
    if len(payload) > MAX_PROJECTION_BYTES:
        raise InventoryProjectionError("inventory publication size is invalid")
    try:
        value = json.loads(bytes(payload).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise InventoryProjectionError(
            f"inventory publication cannot be decoded: {error}"
        ) from error
    return validate_envelope(value)


def publish_projection(
    path: Path,
    value: Mapping[str, Any],
    *,
    owner_uid: int,
    owner_gid: int,
    mode: int = 0o644,
) -> None:
    absolute = path.expanduser().absolute()
    parent = absolute.parent
    parent_info = parent.lstat()
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise InventoryProjectionError("inventory publication parent is unsafe")
    payload = json.dumps(validate_envelope(dict(value)), indent=2, sort_keys=True).encode("utf-8") + b"\n"
    if len(payload) > MAX_PROJECTION_BYTES:
        raise InventoryProjectionError("inventory publication exceeds its byte budget")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{absolute.name}.", suffix=".tmp", dir=parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, absolute)
        parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def _inventory_store_path(
    path: Path, *, expected_owner_uid: int, allow_missing: bool
) -> Path:
    del expected_owner_uid
    absolute = path.expanduser().absolute()
    parent = absolute.parent.lstat()
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
    ):
        raise InventoryProjectionError("inventory store parent must be a non-symlink directory")
    try:
        info = absolute.lstat()
    except FileNotFoundError:
        if allow_missing:
            return absolute
        raise InventoryProjectionError("inventory store does not exist")
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
    ):
        raise InventoryProjectionError("inventory store must be a regular non-symlink file")
    return absolute


def _open_inventory_store(
    path: Path,
    *,
    expected_owner_uid: int,
    create: bool = False,
) -> sqlite3.Connection:
    absolute = _inventory_store_path(
        path, expected_owner_uid=expected_owner_uid, allow_missing=create
    )
    existed = absolute.exists()
    if not existed and not create:
        raise InventoryProjectionError("inventory store does not exist")
    connection = sqlite3.connect(str(absolute), timeout=5.0, isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA trusted_schema = OFF")
        if not existed:
            os.chmod(absolute, 0o600)
        row = connection.execute(
            "SELECT schema_version FROM inventory_store_metadata WHERE singleton = 1"
        ).fetchone() if connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' "
            "AND name = 'inventory_store_metadata'"
        ).fetchone() is not None else None
        if row is None:
            if not create:
                raise InventoryProjectionError("inventory store metadata is missing")
            connection.executescript(_INVENTORY_STORE_SCHEMA_SQL)
        elif int(row[0]) != INVENTORY_STORE_SCHEMA:
            raise InventoryProjectionError("inventory store schema is unsupported")
        return connection
    except BaseException:
        connection.close()
        if not existed:
            absolute.unlink(missing_ok=True)
            Path(f"{absolute}-wal").unlink(missing_ok=True)
            Path(f"{absolute}-shm").unlink(missing_ok=True)
        raise


def _open_sealed_inventory_store(
    path: Path,
    *,
    expected_owner_uid: int,
) -> sqlite3.Connection:
    """Open an immutable, already-checkpointed inventory store without writes.

    This path is intentionally separate from the observer's live connection:
    even a seemingly harmless ``PRAGMA journal_mode`` can alter a sealed store
    or create sidecars.  Split attestations use this reader so verification is
    repeatable and cannot mutate the object whose bytes were attested.
    """

    absolute = _inventory_store_path(
        path, expected_owner_uid=expected_owner_uid, allow_missing=False
    )
    connection = sqlite3.connect(
        f"file:{absolute}?mode=ro&immutable=1",
        uri=True,
        timeout=5.0,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        row = connection.execute(
            "SELECT schema_version FROM inventory_store_metadata WHERE singleton = 1"
        ).fetchone()
        if row is None or int(row[0]) != INVENTORY_STORE_SCHEMA:
            raise InventoryProjectionError("inventory store schema is unsupported")
        return connection
    except BaseException:
        connection.close()
        raise


def initialize_inventory_store(
    path: Path,
    initial: Mapping[str, Any],
    *,
    owner_uid: int,
    owner_gid: int,
) -> dict[str, Any]:
    """Create the observer-owned retained store with one active generation."""

    absolute = _inventory_store_path(path, expected_owner_uid=owner_uid, allow_missing=True)
    if absolute.exists() or absolute.is_symlink():
        return read_inventory_store(absolute, expected_owner_uid=owner_uid)
    descriptor = os.open(
        absolute,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    value = validate_envelope(dict(initial))
    encoded = _canonical(value)
    if shutil.disk_usage(absolute.parent).free < len(encoded) * 3 + MIN_INVENTORY_STORE_FREE_BYTES:
        raise InventoryProjectionError("insufficient capacity for retained inventory store")
    try:
        connection = _open_inventory_store(
            absolute, expected_owner_uid=owner_uid, create=True
        )
    except BaseException:
        absolute.unlink(missing_ok=True)
        raise
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO inventory_store_metadata(
                singleton, schema_version, active_generation, created_at, updated_at
            ) VALUES (1, ?, ?, ?, ?)
            """,
            (
                INVENTORY_STORE_SCHEMA,
                value["generation"],
                value["published_at"],
                value["published_at"],
            ),
        )
        connection.execute(
            """
            INSERT INTO inventory_publications(
                generation, published_at, payload_sha256, envelope_json,
                logical_bytes, state
            ) VALUES (?, ?, ?, ?, ?, 'active')
            """,
            (
                value["generation"],
                value["published_at"],
                value["payload_sha256"],
                encoded,
                len(encoded),
            ),
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        connection.close()
        absolute.unlink(missing_ok=True)
        Path(f"{absolute}-wal").unlink(missing_ok=True)
        Path(f"{absolute}-shm").unlink(missing_ok=True)
        raise
    else:
        connection.close()
    os.chmod(absolute, 0o600)
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{absolute}{suffix}")
        if sidecar.exists():
            os.chmod(sidecar, 0o600)
    return read_inventory_store(absolute, expected_owner_uid=owner_uid)


def _decoded_store_envelope(row: sqlite3.Row) -> dict[str, Any]:
    try:
        raw = bytes(row["envelope_json"])
        value = json.loads(raw.decode("utf-8"))
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise InventoryProjectionError("inventory store payload is invalid") from error
    validated = validate_envelope(value)
    if (
        int(row["generation"]) != validated["generation"]
        or str(row["payload_sha256"]) != validated["payload_sha256"]
        or int(row["logical_bytes"]) != len(_canonical(validated))
    ):
        raise InventoryProjectionError("inventory store payload metadata is contradictory")
    return validated


def read_inventory_store(
    path: Path, *, expected_owner_uid: int
) -> dict[str, Any]:
    connection = _open_inventory_store(
        path, expected_owner_uid=expected_owner_uid, create=False
    )
    try:
        check = connection.execute("PRAGMA quick_check").fetchone()
        if check is None or str(check[0]) != "ok":
            raise InventoryProjectionError("inventory store integrity check failed")
        metadata = connection.execute(
            "SELECT * FROM inventory_store_metadata WHERE singleton = 1"
        ).fetchone()
        if metadata is None or metadata["active_generation"] is None:
            raise InventoryProjectionError("inventory store has no active generation")
        row = connection.execute(
            "SELECT * FROM inventory_publications WHERE generation = ? AND state = 'active'",
            (metadata["active_generation"],),
        ).fetchone()
        if row is None:
            raise InventoryProjectionError("inventory store active pointer is invalid")
        value = _decoded_store_envelope(row)
        count, logical_bytes = connection.execute(
            "SELECT COUNT(*), COALESCE(SUM(logical_bytes), 0) FROM inventory_publications"
        ).fetchone()
        if int(count) > MAX_RETAINED_GENERATIONS:
            raise InventoryProjectionError("inventory store generation retention is unbounded")
        if int(logical_bytes) > MAX_INVENTORY_STORE_LOGICAL_BYTES:
            raise InventoryProjectionError("inventory store byte retention is unbounded")
        return {
            "schema_version": INVENTORY_STORE_SCHEMA,
            "generation": value["generation"],
            "payload_sha256": value["payload_sha256"],
            "retained_generations": int(count),
            "logical_bytes": int(logical_bytes),
            "envelope": value,
        }
    finally:
        connection.close()


def read_sealed_inventory_store(
    path: Path, *, expected_owner_uid: int
) -> dict[str, Any]:
    """Read a checkpointed immutable store without changing it or sidecars."""

    connection = _open_sealed_inventory_store(
        path, expected_owner_uid=expected_owner_uid
    )
    try:
        check = connection.execute("PRAGMA quick_check").fetchone()
        if check is None or str(check[0]) != "ok":
            raise InventoryProjectionError("inventory store integrity check failed")
        metadata = connection.execute(
            "SELECT * FROM inventory_store_metadata WHERE singleton = 1"
        ).fetchone()
        if metadata is None or metadata["active_generation"] is None:
            raise InventoryProjectionError("inventory store has no active generation")
        row = connection.execute(
            "SELECT * FROM inventory_publications WHERE generation = ? AND state = 'active'",
            (metadata["active_generation"],),
        ).fetchone()
        if row is None:
            raise InventoryProjectionError("inventory store active pointer is invalid")
        value = _decoded_store_envelope(row)
        count, logical_bytes = connection.execute(
            "SELECT COUNT(*), COALESCE(SUM(logical_bytes), 0) FROM inventory_publications"
        ).fetchone()
        if int(count) > MAX_RETAINED_GENERATIONS:
            raise InventoryProjectionError("inventory store generation retention is unbounded")
        if int(logical_bytes) > MAX_INVENTORY_STORE_LOGICAL_BYTES:
            raise InventoryProjectionError("inventory store byte retention is unbounded")
        return {
            "schema_version": INVENTORY_STORE_SCHEMA,
            "generation": value["generation"],
            "payload_sha256": value["payload_sha256"],
            "retained_generations": int(count),
            "logical_bytes": int(logical_bytes),
            "envelope": value,
        }
    finally:
        connection.close()


def _stage_inventory_generation(
    path: Path,
    value: Mapping[str, Any],
    *,
    expected_owner_uid: int,
    capacity_probe: Any = None,
) -> None:
    validated = validate_envelope(dict(value))
    encoded = _canonical(validated)
    free = int(
        shutil.disk_usage(path.parent).free
        if capacity_probe is None
        else capacity_probe(path.parent)
    )
    if free < len(encoded) * 3 + MIN_INVENTORY_STORE_FREE_BYTES:
        raise InventoryProjectionError("insufficient capacity for retained inventory generation")
    connection = _open_inventory_store(
        path, expected_owner_uid=expected_owner_uid, create=False
    )
    try:
        connection.execute("BEGIN IMMEDIATE")
        metadata = connection.execute(
            "SELECT active_generation FROM inventory_store_metadata WHERE singleton = 1"
        ).fetchone()
        if metadata is None or metadata[0] is None:
            raise InventoryProjectionError("inventory store active generation is missing")
        if validated["generation"] != int(metadata[0]) + 1:
            raise InventoryProjectionError("inventory generation is not the exact successor")
        connection.execute("DELETE FROM inventory_publications WHERE state = 'pending'")
        connection.execute(
            """
            INSERT INTO inventory_publications(
                generation, published_at, payload_sha256, envelope_json,
                logical_bytes, state
            ) VALUES (?, ?, ?, ?, ?, 'pending')
            """,
            (
                validated["generation"],
                validated["published_at"],
                validated["payload_sha256"],
                encoded,
                len(encoded),
            ),
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def _activate_inventory_generation(
    path: Path,
    value: Mapping[str, Any],
    *,
    expected_owner_uid: int,
) -> None:
    validated = validate_envelope(dict(value))
    connection = _open_inventory_store(
        path, expected_owner_uid=expected_owner_uid, create=False
    )
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM inventory_publications WHERE generation = ? AND state = 'pending'",
            (validated["generation"],),
        ).fetchone()
        if row is None or _decoded_store_envelope(row) != validated:
            raise InventoryProjectionError("staged inventory generation changed before activation")
        connection.execute("UPDATE inventory_publications SET state = 'retained' WHERE state = 'active'")
        connection.execute(
            "UPDATE inventory_publications SET state = 'active' WHERE generation = ?",
            (validated["generation"],),
        )
        connection.execute(
            "UPDATE inventory_store_metadata SET active_generation = ?, updated_at = ? WHERE singleton = 1",
            (validated["generation"], validated["published_at"]),
        )
        # Keep the newest generations by both count and aggregate logical
        # bytes.  The new active row is never eligible for pruning.
        connection.execute(
            """
            DELETE FROM inventory_publications
            WHERE generation IN (
                SELECT generation FROM inventory_publications
                WHERE generation != ?
                ORDER BY generation DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (validated["generation"], MAX_RETAINED_GENERATIONS - 1),
        )
        while int(
            connection.execute(
                "SELECT COALESCE(SUM(logical_bytes), 0) FROM inventory_publications"
            ).fetchone()[0]
        ) > MAX_INVENTORY_STORE_LOGICAL_BYTES:
            removed = connection.execute(
                "DELETE FROM inventory_publications WHERE generation = ("
                "SELECT MIN(generation) FROM inventory_publications WHERE generation != ?)",
                (validated["generation"],),
            ).rowcount
            if removed != 1:
                raise InventoryProjectionError("one inventory generation exceeds the store budget")
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def publish_retained_inventory(
    *,
    database: Path,
    publication: Path,
    value: Mapping[str, Any],
    owner_uid: int,
    owner_gid: int,
    capacity_probe: Any = None,
) -> None:
    """Stage, publish, and activate one crash-recoverable retained generation."""

    validated = validate_envelope(dict(value))
    _stage_inventory_generation(
        database,
        validated,
        expected_owner_uid=owner_uid,
        capacity_probe=capacity_probe,
    )
    try:
        publish_projection(
            publication,
            validated,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        _activate_inventory_generation(
            database, validated, expected_owner_uid=owner_uid
        )
    except BaseException:
        # A pending row is safe recovery evidence.  If publication succeeded
        # before a crash, verification below completes the exact activation;
        # if it did not, verification discards the unmatched pending row.
        raise


def verify_inventory_store(
    database: Path,
    publication: Path,
    *,
    expected_owner_uid: int,
) -> dict[str, Any]:
    """Verify and repair only the two bounded crash windows between files."""

    public = read_projection(publication, expected_owner_uid=expected_owner_uid)
    connection = _open_inventory_store(
        database, expected_owner_uid=expected_owner_uid, create=False
    )
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM inventory_publications WHERE generation = ?",
            (public["generation"],),
        ).fetchone()
        if row is None:
            raise InventoryProjectionError("publication generation is absent from inventory store")
        stored = _decoded_store_envelope(row)
        if stored != public:
            raise InventoryProjectionError("publication and inventory store digests differ")
        metadata = connection.execute(
            "SELECT active_generation FROM inventory_store_metadata WHERE singleton = 1"
        ).fetchone()
        if metadata is None:
            raise InventoryProjectionError("inventory store metadata is missing")
        if int(metadata[0]) != public["generation"]:
            if str(row["state"]) != "pending":
                raise InventoryProjectionError("inventory active pointer contradicts publication")
            connection.execute("UPDATE inventory_publications SET state = 'retained' WHERE state = 'active'")
            connection.execute(
                "UPDATE inventory_publications SET state = 'active' WHERE generation = ?",
                (public["generation"],),
            )
            connection.execute(
                "UPDATE inventory_store_metadata SET active_generation = ?, updated_at = ? WHERE singleton = 1",
                (public["generation"], public["published_at"]),
            )
        connection.execute(
            "DELETE FROM inventory_publications WHERE state = 'pending' AND generation != ?",
            (public["generation"],),
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()
    return read_inventory_store(database, expected_owner_uid=expected_owner_uid)


def empty_inventory() -> dict[str, Any]:
    """Return a contract-valid empty Console inventory for first publication.

    A fresh retained store can be visible before the observer's first source
    refresh.  That brief state is still an authoritative empty inventory, not
    a malformed legacy document: consumers must be able to render it without
    disabling every inventory-backed Console surface.
    """

    return {
        "schema_version": 1,
        "servers": [],
        "repositories": [],
        "repository_trees": [],
        "memberships": [],
        "resources": {
            "servers": [],
            "docker": [],
            "docker_ports": [],
            "databases": [],
        },
        "observations": {
            "servers": [],
            "docker": [],
            "databases": [],
            "snapshots": [],
            "telemetry": [],
        },
        "unassigned_resources": [],
        "lifecycle_violations": [],
        "docker": {"available": False, "containers": [], "postgres": []},
        "postgres": [],
        "backups": [],
        "project_usage": [],
        "projection_status": "initialized",
    }
