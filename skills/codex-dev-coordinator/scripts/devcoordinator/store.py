"""Private SQLite/WAL storage and transaction boundaries for DevCoordinator."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import socket
import sqlite3
import stat
import time
from typing import Any, Callable, Generator, Iterable
import uuid

from .schema import SCHEMA_VERSION, initialize_schema, invariant_violations


DEFAULT_DATABASE_NAME = "coordinator.sqlite3"
DEFAULT_BUSY_TIMEOUT_MS = 5_000
DEFAULT_MUTATION_SECONDS = 5.0
MAINTENANCE_LOCK_NAME = ".coordinator-maintenance.lock"


def _retry_sqlite_busy(
    operation: Callable[[], Any],
    *,
    timeout_ms: int,
) -> Any:
    """Retry SQLite setup operations whose PRAGMAs bypass busy_timeout.

    SQLite's WAL-mode PRAGMA can report SQLITE_BUSY immediately while another
    process is completing its own first-open schema transaction, even after a
    connection-level busy timeout has been configured. Keep the retry bounded
    by the caller's normal store-open timeout and never retry other failures.
    """

    deadline = time.monotonic() + (int(timeout_ms) / 1000.0)
    busy_codes = {
        value
        for value in (
            getattr(sqlite3, "SQLITE_BUSY", None),
            getattr(sqlite3, "SQLITE_LOCKED", None),
        )
        if value is not None
    }
    while True:
        try:
            return operation()
        except sqlite3.OperationalError as error:
            code = getattr(error, "sqlite_errorcode", None)
            message = str(error).lower()
            retryable = code in busy_codes or "locked" in message or "busy" in message
            remaining = deadline - time.monotonic()
            if not retryable or remaining <= 0:
                raise
            time.sleep(min(0.01, remaining))


class StoreError(RuntimeError):
    """Base error for the normalized store."""


class StoreInvariantError(StoreError):
    """A transaction would commit a cross-table invariant violation."""

    def __init__(self, violations: Iterable[Any]) -> None:
        self.violations = tuple(violations)
        detail = "; ".join(f"{item.code}: {item.detail}" for item in self.violations)
        super().__init__(f"coordinator store invariant violation: {detail}")


class MutationTimeout(StoreError):
    """A bounded mutation exceeded its allowed wall-clock interval."""


class TransactionBoundaryError(StoreError):
    """Caller tried to escape a store-owned transaction boundary."""


@dataclass(frozen=True)
class StoreMetadata:
    schema_version: int
    database_generation: str
    state_revision: int
    observation_revision: int
    authority_mode: str
    migration_state: str


def utc_timestamp(value: float | None = None) -> str:
    seconds = time.time() if value is None else float(value)
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


def canonical_json(value: Any) -> str:
    """Return the stable JSON encoding used only for evidence/protocol fields."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _projected_binding_fingerprint(row: Any) -> str | None:
    """Match the lifecycle engine's exact control-binding fingerprint."""

    binding_id = row["control_binding_id"]
    if binding_id is None:
        return None
    return "sha256:" + fingerprint(
        {
            "binding_id": binding_id,
            "resource_kind": row["binding_resource_kind"],
            "resource_id": row["binding_resource_id"],
            "source_id": row["binding_source_id"],
            "capability": row["binding_capability"],
            "provenance": row["binding_provenance"],
            "authority_state": row["authority_state"],
            "generation": row["binding_generation"],
        }
    )


def deterministic_id(namespace: str, *parts: object) -> str:
    material = "\x1f".join([namespace, *(str(part) for part in parts)])
    return str(uuid.uuid5(uuid.NAMESPACE_URL, material))


def _absolute_path(path: str | os.PathLike[str]) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        raise ValueError(f"coordinator store path must be absolute: {candidate}")
    return candidate


def _path_components(path: Path) -> list[Path]:
    components: list[Path] = []
    current = path
    while True:
        components.append(current)
        if current.parent == current:
            break
        current = current.parent
    components.reverse()
    return components


def refuse_symlink_components(path: Path, *, allow_missing_leaf: bool = False) -> None:
    """Reject an operator-supplied path if any existing component is a symlink."""

    absolute = _absolute_path(path)
    components = _path_components(absolute)
    for index, component in enumerate(components):
        try:
            metadata = component.lstat()
        except FileNotFoundError:
            if allow_missing_leaf and index == len(components) - 1:
                return
            raise FileNotFoundError(f"coordinator path component does not exist: {component}")
        if stat.S_ISLNK(metadata.st_mode):
            raise PermissionError(f"coordinator path must not contain a symbolic link: {component}")


def _validate_owned_directory(path: Path, expected_uid: int, *, require_private: bool) -> None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise PermissionError(f"coordinator store directory must be a real directory: {path}")
    if metadata.st_uid != expected_uid:
        raise PermissionError(
            f"coordinator store directory is owned by uid {metadata.st_uid}, "
            f"not expected uid {expected_uid}: {path}"
        )
    if require_private and stat.S_IMODE(metadata.st_mode) != 0o700:
        raise PermissionError(
            f"coordinator store directory must be mode 0700, got "
            f"{stat.S_IMODE(metadata.st_mode):04o}: {path}"
        )


def ensure_private_store_directory(path: Path, *, expected_uid: int) -> None:
    """Create missing final directories without changing any existing directory."""

    absolute = _absolute_path(path)
    missing: list[Path] = []
    current = absolute
    while not current.exists():
        if current.is_symlink():
            raise PermissionError(f"coordinator path must not be a symbolic link: {current}")
        missing.append(current)
        if current.parent == current:
            raise FileNotFoundError(f"no existing ancestor for coordinator path: {path}")
        current = current.parent
    refuse_symlink_components(current)
    if current != absolute:
        _validate_owned_directory(current, expected_uid, require_private=False)
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            # A concurrent same-UID process may win creation after discovery.
            # Accept only the exact private directory that we would have made.
            pass
        _validate_owned_directory(directory, expected_uid, require_private=True)
    _validate_owned_directory(absolute, expected_uid, require_private=True)


def _validate_private_file(path: Path, expected_uid: int) -> os.stat_result:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise PermissionError(f"coordinator database must be a real regular file: {path}")
    if metadata.st_uid != expected_uid:
        raise PermissionError(
            f"coordinator database is owned by uid {metadata.st_uid}, "
            f"not expected uid {expected_uid}: {path}"
        )
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise PermissionError(
            f"coordinator database must be mode 0600, got "
            f"{stat.S_IMODE(metadata.st_mode):04o}: {path}"
        )
    return metadata


def _validate_private_maintenance_lock(path: Path, expected_uid: int) -> os.stat_result:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise PermissionError(f"coordinator maintenance lock must be a real regular file: {path}")
    if metadata.st_uid != expected_uid:
        raise PermissionError(
            f"coordinator maintenance lock is owned by uid {metadata.st_uid}, "
            f"not expected uid {expected_uid}: {path}"
        )
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise PermissionError(
            f"coordinator maintenance lock must be mode 0600, got "
            f"{stat.S_IMODE(metadata.st_mode):04o}: {path}"
        )
    return metadata


def _validate_private_sqlite_sidecars(database_path: Path, expected_uid: int) -> None:
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{database_path}{suffix}")
        if not sidecar.exists() and not sidecar.is_symlink():
            continue
        refuse_symlink_components(sidecar)
        metadata = sidecar.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise PermissionError(f"SQLite sidecar must be a regular file: {sidecar}")
        if metadata.st_uid != expected_uid:
            raise PermissionError(f"SQLite sidecar has foreign ownership: {sidecar}")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise PermissionError(
                f"SQLite sidecar must be mode 0600, got "
                f"{stat.S_IMODE(metadata.st_mode):04o}: {sidecar}"
            )


def _sqlite_sidecars_exist(database_path: Path) -> bool:
    return any(
        sidecar.exists() or sidecar.is_symlink()
        for sidecar in (Path(f"{database_path}-wal"), Path(f"{database_path}-shm"))
    )


def _immutable_main_schema_version(database_path: Path) -> int | None:
    """Read only the main file without allowing SQLite to create WAL sidecars."""

    connection = sqlite3.connect(
        f"{database_path.as_uri()}?mode=ro&immutable=1",
        uri=True,
        isolation_level=None,
    )
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        row = connection.execute(
            "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
        ).fetchone()
        if row is None:
            return None
        try:
            return int(row[0])
        except (TypeError, ValueError):
            return None
    except sqlite3.DatabaseError:
        return None
    finally:
        connection.close()


def _precreate_private_file(path: Path, expected_uid: int) -> os.stat_result:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        return _validate_private_file(path, expected_uid)
    try:
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if metadata.st_uid != expected_uid or not stat.S_ISREG(metadata.st_mode):
            raise PermissionError(f"new coordinator database has unsafe ownership/type: {path}")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return _validate_private_file(path, expected_uid)


def _acquire_maintenance_descriptor(
    database_path: Path,
    *,
    expected_uid: int,
    exclusive: bool,
    timeout_seconds: float,
    create: bool = True,
) -> int:
    """Acquire the normalized store-maintenance lock, never legacy ``state.lock``.

    This lock serializes SQLite open/backup/restore maintenance and is retained
    as a private 0600 inode beside the normalized database.  Runtime mutation
    authority remains in SQLite transactions; the retired JSON backend's
    ``state.lock`` must not be created by normalized workflows.
    """

    lock_path = database_path.parent / MAINTENANCE_LOCK_NAME
    refuse_symlink_components(lock_path, allow_missing_leaf=create)
    before = (
        _precreate_private_file(lock_path, expected_uid)
        if create
        else _validate_private_maintenance_lock(lock_path, expected_uid)
    )
    flags = os.O_RDWR if create else os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_uid != expected_uid
            or not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise PermissionError("coordinator maintenance lock identity is unsafe")
        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        deadline = time.monotonic() + float(timeout_seconds)
        while True:
            try:
                fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise StoreError(
                        "coordinator store is busy with an incompatible maintenance operation"
                    )
                time.sleep(0.01)
        after = lock_path.lstat()
        if (
            (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
            or after.st_uid != expected_uid
            or not stat.S_ISREG(after.st_mode)
            or stat.S_IMODE(after.st_mode) != 0o600
        ):
            raise PermissionError("coordinator maintenance lock changed while opening")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _cleanup_failed_store_open(
    database_path: Path,
    expected_uid: int,
    connections: Iterable[tuple[str, Any]],
    maintenance_descriptor: int,
) -> list[tuple[str, BaseException]]:
    """Release every failed-open resource while retaining all cleanup errors."""

    failures: list[tuple[str, BaseException]] = []
    operations = [
        (
            "SQLite sidecar validation",
            lambda: _validate_private_sqlite_sidecars(database_path, expected_uid),
        ),
    ]
    for label, connection in connections:
        if connection is not None:
            operations.append((label, connection.close))
    operations.extend(
        [
            (
                "maintenance lock release",
                lambda: fcntl.flock(maintenance_descriptor, fcntl.LOCK_UN),
            ),
            ("maintenance descriptor close", lambda: os.close(maintenance_descriptor)),
        ]
    )
    for label, operation in operations:
        try:
            operation()
        except BaseException as error:
            failures.append((label, error))
    return failures


def _raise_combined_open_failure(
    primary_error: BaseException,
    cleanup_failures: list[tuple[str, BaseException]],
) -> None:
    detail = "; ".join(
        f"{label}: {type(error).__name__}: {error}"
        for label, error in cleanup_failures
    )
    raise StoreError(
        f"{type(primary_error).__name__}: {primary_error}; "
        f"coordinator store open cleanup also failed: {detail}"
    ) from primary_error


def _read_validated_journal_mode(
    connection: Any,
    database_path: Path,
    expected_uid: int,
) -> str:
    """Read WAL mode and validate any sidecars materialized by that access."""

    try:
        journal_row = connection.execute("PRAGMA journal_mode").fetchone()
    except BaseException as journal_error:
        try:
            _validate_private_sqlite_sidecars(database_path, expected_uid)
        except BaseException as validation_error:
            raise StoreError(
                "coordinator journal-mode read failed: "
                f"{type(journal_error).__name__}: {journal_error}; "
                "post-journal SQLite sidecar validation also failed: "
                f"{type(validation_error).__name__}: {validation_error}"
            ) from journal_error
        raise
    _validate_private_sqlite_sidecars(database_path, expected_uid)
    if journal_row is None:
        raise StoreError("coordinator database journal mode is missing")
    return str(journal_row[0]).lower()


@contextmanager
def exclusive_maintenance_lock(
    database_path: str | os.PathLike[str],
    *,
    expected_uid: int | None = None,
    timeout_seconds: float = 5.0,
) -> Generator[None, None, None]:
    """Exclude every normalized store connection during atomic restore."""

    path = _absolute_path(database_path)
    uid = os.geteuid() if expected_uid is None else int(expected_uid)
    if uid != os.geteuid():
        raise PermissionError("maintenance lock expected uid differs from effective uid")
    if not 0 < float(timeout_seconds) <= 60:
        raise ValueError("maintenance timeout must be greater than 0 and at most 60")
    ensure_private_store_directory(path.parent, expected_uid=uid)
    descriptor = _acquire_maintenance_descriptor(
        path,
        expected_uid=uid,
        exclusive=True,
        timeout_seconds=float(timeout_seconds),
    )
    try:
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


class CoordinatorStore:
    """One connection to a private normalized account database.

    A store owns transaction boundaries. Callbacks may execute SQL on the raw
    connection yielded by the context managers, but they may not commit,
    rollback, attach another database, or detach one.
    """

    def __init__(
        self,
        path: Path,
        connection: sqlite3.Connection,
        *,
        expected_uid: int,
        busy_timeout_ms: int,
        maintenance_descriptor: int,
        read_only: bool = False,
    ) -> None:
        self.path = path
        self.connection = connection
        self.expected_uid = expected_uid
        self.busy_timeout_ms = busy_timeout_ms
        self._maintenance_descriptor = maintenance_descriptor
        self._read_only = bool(read_only)
        self._closed = False

    @property
    def database_path(self) -> Path:
        """Expose the canonical store path to shared observation adapters."""

        return self.path

    @classmethod
    def open(
        cls,
        path: str | os.PathLike[str],
        *,
        expected_uid: int | None = None,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    ) -> "CoordinatorStore":
        database_path = _absolute_path(path)
        uid = os.geteuid() if expected_uid is None else int(expected_uid)
        if uid != os.geteuid():
            raise PermissionError(
                f"coordinator store expected uid {uid} does not match effective uid {os.geteuid()}"
            )
        if not 1 <= int(busy_timeout_ms) <= 60_000:
            raise ValueError("busy_timeout_ms must be between 1 and 60000")
        ensure_private_store_directory(database_path.parent, expected_uid=uid)
        maintenance_descriptor = _acquire_maintenance_descriptor(
            database_path,
            expected_uid=uid,
            exclusive=False,
            timeout_seconds=int(busy_timeout_ms) / 1000.0,
        )
        try:
            refuse_symlink_components(database_path, allow_missing_leaf=True)
            before = _precreate_private_file(database_path, uid)
            connection = sqlite3.connect(
                str(database_path),
                timeout=int(busy_timeout_ms) / 1000.0,
                isolation_level=None,
            )
        except BaseException:
            fcntl.flock(maintenance_descriptor, fcntl.LOCK_UN)
            os.close(maintenance_descriptor)
            raise
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            if int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
                raise StoreError("SQLite foreign key enforcement could not be enabled")
            connection.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)}")
            mode = str(
                _retry_sqlite_busy(
                    lambda: connection.execute("PRAGMA journal_mode = WAL"),
                    timeout_ms=int(busy_timeout_ms),
                ).fetchone()[0]
            ).lower()
            if mode != "wal":
                raise StoreError(f"SQLite WAL mode could not be enabled: {mode}")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA wal_autocheckpoint = 1000")
            after = _validate_private_file(database_path, uid)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise PermissionError("coordinator database identity changed while opening")

            connection.execute("BEGIN IMMEDIATE")
            try:
                initialize_schema(
                    connection,
                    database_generation=str(uuid.uuid4()),
                    timestamp=utc_timestamp(),
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
            store = cls(
                database_path,
                connection,
                expected_uid=uid,
                busy_timeout_ms=int(busy_timeout_ms),
                maintenance_descriptor=maintenance_descriptor,
            )
            store._secure_sidecars()
            return store
        except BaseException:
            connection.close()
            fcntl.flock(maintenance_descriptor, fcntl.LOCK_UN)
            os.close(maintenance_descriptor)
            raise

    @classmethod
    def open_read_only(
        cls,
        path: str | os.PathLike[str],
        *,
        expected_uid: int | None = None,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    ) -> "CoordinatorStore":
        """Open an existing current-schema store without logical-state mutation.

        This path never creates the database or maintenance lock, never runs
        schema initialization/upgrades, and never requests a journal-mode
        transition. The returned SQLite connection always uses ``mode=ro``.
        When a WAL-mode database has no WAL file, a temporary existing-only
        ``mode=rw`` connection lets SQLite create its coordination sidecars,
        establishes the real read-only connection, and closes before inventory
        code can run. ``query_only`` is the first SQL statement on both, and
        sidecars retain the writable opener's private security boundaries.
        """

        database_path = _absolute_path(path)
        uid = os.geteuid() if expected_uid is None else int(expected_uid)
        if uid != os.geteuid():
            raise PermissionError(
                f"coordinator store expected uid {uid} does not match effective uid {os.geteuid()}"
            )
        if not 1 <= int(busy_timeout_ms) <= 60_000:
            raise ValueError("busy_timeout_ms must be between 1 and 60000")
        refuse_symlink_components(database_path)
        _validate_owned_directory(database_path.parent, uid, require_private=True)
        before = _validate_private_file(database_path, uid)
        maintenance_descriptor = _acquire_maintenance_descriptor(
            database_path,
            expected_uid=uid,
            exclusive=False,
            timeout_seconds=int(busy_timeout_ms) / 1000.0,
            create=False,
        )
        bootstrap = None
        connection = None
        try:
            _validate_private_sqlite_sidecars(database_path, uid)
            if not _sqlite_sidecars_exist(database_path):
                # SQLite may create empty WAL/SHM files merely while opening a
                # WAL database read-only. Reject a stale main-file schema first
                # through an immutable connection, but trust that result only
                # if no writer created sidecars during the check. The normal
                # opener below still rechecks the live WAL-aware schema.
                main_schema_version = _immutable_main_schema_version(database_path)
                after_preflight = _validate_private_file(database_path, uid)
                if (
                    main_schema_version is not None
                    and main_schema_version != SCHEMA_VERSION
                    and not _sqlite_sidecars_exist(database_path)
                    and (before.st_dev, before.st_ino)
                    == (after_preflight.st_dev, after_preflight.st_ino)
                ):
                    raise StoreError(
                        f"unsupported coordinator database schema {main_schema_version}; "
                        f"expected {SCHEMA_VERSION}"
                    )
            wal_path = Path(f"{database_path}-wal")
            if not wal_path.exists():
                # Darwin cannot attach a read-only WAL connection when the WAL
                # file is absent. A temporary, unexposed connection lets SQLite
                # create its own locked sidecars without ad-hoc file races.
                bootstrap = sqlite3.connect(
                    f"{database_path.as_uri()}?mode=rw",
                    uri=True,
                    timeout=int(busy_timeout_ms) / 1000.0,
                    isolation_level=None,
                )
                bootstrap.execute("PRAGMA query_only = ON")
                bootstrap.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)}")
                bootstrap.execute("PRAGMA trusted_schema = OFF")
                bootstrap_mode = _read_validated_journal_mode(
                    bootstrap,
                    database_path,
                    uid,
                )
                if bootstrap_mode != "wal":
                    raise StoreError(
                        f"coordinator database journal mode is {bootstrap_mode}; expected wal"
                    )
            connection = sqlite3.connect(
                f"{database_path.as_uri()}?mode=ro",
                uri=True,
                timeout=int(busy_timeout_ms) / 1000.0,
                isolation_level=None,
            )
            _validate_private_sqlite_sidecars(database_path, uid)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            connection.execute("PRAGMA foreign_keys = ON")
            if int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
                raise StoreError("SQLite foreign key enforcement could not be enabled")
            connection.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)}")
            connection.execute("PRAGMA trusted_schema = OFF")
            mode = _read_validated_journal_mode(connection, database_path, uid)
            if mode != "wal":
                raise StoreError(f"coordinator database journal mode is {mode}; expected wal")
            # Keep the bootstrap alive until the real read-only connection has
            # attached to WAL. Its successful close precedes all schema/data
            # reads, and only the VFS-enforced read-only handle is returned.
            if bootstrap is not None:
                bootstrap.close()
                bootstrap = None
            try:
                row = connection.execute(
                    "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
                ).fetchone()
            except sqlite3.DatabaseError as error:
                raise StoreError(f"coordinator schema metadata is unreadable: {error}") from error
            if row is None:
                raise StoreError("coordinator schema metadata is missing")
            try:
                schema_version = int(row[0])
            except (TypeError, ValueError) as error:
                raise StoreError("coordinator database schema version is invalid") from error
            if schema_version != SCHEMA_VERSION:
                raise StoreError(
                    f"unsupported coordinator database schema {schema_version}; "
                    f"expected {SCHEMA_VERSION}"
                )
            after = _validate_private_file(database_path, uid)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise PermissionError("coordinator database identity changed while opening")
            store = cls(
                database_path,
                connection,
                expected_uid=uid,
                busy_timeout_ms=int(busy_timeout_ms),
                maintenance_descriptor=maintenance_descriptor,
                read_only=True,
            )
            store._secure_sidecars()
            return store
        except BaseException as primary_error:
            cleanup_failures = _cleanup_failed_store_open(
                database_path,
                uid,
                (
                    ("SQLite bootstrap connection close", bootstrap),
                    ("SQLite read-only connection close", connection),
                ),
                maintenance_descriptor,
            )
            if cleanup_failures:
                _raise_combined_open_failure(primary_error, cleanup_failures)
            raise

    def _require_open(self) -> None:
        if self._closed:
            raise StoreError("coordinator store is closed")

    def _secure_sidecars(self) -> None:
        _validate_private_sqlite_sidecars(self.path, self.expected_uid)

    @property
    def metadata(self) -> StoreMetadata:
        with self.read_transaction() as connection:
            row = connection.execute(
                """
                SELECT schema_version, database_generation, state_revision,
                       observation_revision, authority_mode, migration_state
                FROM schema_metadata WHERE singleton = 1
                """
            ).fetchone()
            if row is None:
                raise StoreError("coordinator schema metadata is missing")
            return StoreMetadata(**dict(row))

    @contextmanager
    def read_transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """Yield one consistent query-only snapshot without any state mutation."""

        self._require_open()
        if self.connection.in_transaction:
            raise TransactionBoundaryError("nested store transactions are not allowed")
        changes_before = self.connection.total_changes
        self.connection.execute("PRAGMA query_only = ON")
        self.connection.execute("BEGIN DEFERRED")
        try:
            yield self.connection
            if self.connection.total_changes != changes_before:
                raise TransactionBoundaryError("read transaction changed the database")
            self.connection.commit()
        except BaseException:
            if self.connection.in_transaction:
                self.connection.rollback()
            raise
        finally:
            if not self._read_only:
                self.connection.execute("PRAGMA query_only = OFF")

    @contextmanager
    def immediate_transaction(
        self,
        *,
        max_seconds: float = DEFAULT_MUTATION_SECONDS,
        revision_kind: str | None = "state",
        check_invariants: bool = True,
    ) -> Generator[sqlite3.Connection, None, None]:
        """Yield a bounded ``BEGIN IMMEDIATE`` mutation and commit atomically."""

        self._require_open()
        if self._read_only:
            raise StoreError("coordinator store was opened read-only")
        if self.connection.in_transaction:
            raise TransactionBoundaryError("nested store transactions are not allowed")
        if not 0 < float(max_seconds) <= 60.0:
            raise ValueError("max_seconds must be greater than 0 and at most 60")
        if revision_kind not in {"state", "observation", None}:
            raise ValueError("revision_kind must be 'state', 'observation', or None")
        started = time.monotonic()
        deadline = started + float(max_seconds)

        def progress() -> int:
            return 1 if time.monotonic() > deadline else 0

        self.connection.set_progress_handler(progress, 1_000)
        self.connection.execute("BEGIN IMMEDIATE")

        def transaction_authorizer(
            action: int,
            _argument1: str | None,
            _argument2: str | None,
            _database: str | None,
            _trigger: str | None,
        ) -> int:
            forbidden = {
                getattr(sqlite3, "SQLITE_TRANSACTION", -1),
                getattr(sqlite3, "SQLITE_ATTACH", -2),
                getattr(sqlite3, "SQLITE_DETACH", -3),
            }
            return sqlite3.SQLITE_DENY if action in forbidden else sqlite3.SQLITE_OK

        def allow_authorizer(
            _action: int,
            _argument1: str | None,
            _argument2: str | None,
            _database: str | None,
            _trigger: str | None,
        ) -> int:
            return sqlite3.SQLITE_OK

        self.connection.set_authorizer(transaction_authorizer)
        try:
            yield self.connection
            self.connection.set_authorizer(allow_authorizer)
            if not self.connection.in_transaction:
                raise TransactionBoundaryError("caller escaped the store-owned transaction")
            if time.monotonic() > deadline:
                raise MutationTimeout(
                    f"coordinator mutation exceeded {float(max_seconds):.3f} seconds"
                )
            if check_invariants:
                violations = invariant_violations(self.connection)
                if violations:
                    raise StoreInvariantError(violations)
            if revision_kind is not None:
                column = "state_revision" if revision_kind == "state" else "observation_revision"
                self.connection.execute(
                    f"""
                    UPDATE schema_metadata
                    SET {column} = {column} + 1, updated_at = ?
                    WHERE singleton = 1
                    """,
                    (utc_timestamp(),),
                )
            self.connection.commit()
            self._secure_sidecars()
        except BaseException:
            self.connection.set_authorizer(allow_authorizer)
            if self.connection.in_transaction:
                self.connection.rollback()
            raise
        finally:
            self.connection.set_authorizer(allow_authorizer)
            self.connection.set_progress_handler(None, 0)

    def check_invariants(self) -> tuple[Any, ...]:
        with self.read_transaction() as connection:
            return tuple(invariant_violations(connection))

    def close(self) -> None:
        if self._closed:
            return
        if self.connection.in_transaction:
            self.connection.rollback()
        self.connection.close()
        fcntl.flock(self._maintenance_descriptor, fcntl.LOCK_UN)
        os.close(self._maintenance_descriptor)
        self._closed = True
        _validate_private_file(self.path, self.expected_uid)

    def __enter__(self) -> "CoordinatorStore":
        return self

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        self.close()


class AccountStore(CoordinatorStore):
    """Account-scoped adapter used by the legacy cutover and v2 inventory."""

    @classmethod
    def open_default(
        cls,
        coordinator_home: str | os.PathLike[str] | None = None,
        *,
        effective_uid: int | None = None,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
        account_lookup: Callable[[int], Any] | None = None,
    ) -> "AccountStore":
        uid = os.geteuid() if effective_uid is None else int(effective_uid)
        if coordinator_home is None:
            lookup = pwd.getpwuid if account_lookup is None else account_lookup
            try:
                record = lookup(uid)
            except (KeyError, OSError) as error:
                raise StoreError(f"could not resolve POSIX account home for uid {uid}: {error}") from error
            raw_home = str(getattr(record, "pw_dir", "") or "")
            account_home = Path(raw_home)
            if not raw_home or not account_home.is_absolute():
                raise StoreError(f"POSIX account home for uid {uid} is not absolute")
            coordinator_home = account_home / ".codex" / "agent-coordinator"
        home = _absolute_path(coordinator_home)
        base = super().open(
            home / DEFAULT_DATABASE_NAME,
            expected_uid=uid,
            busy_timeout_ms=busy_timeout_ms,
        )
        base.__class__ = cls
        return base  # type: ignore[return-value]

    @classmethod
    def open_default_read_only(
        cls,
        coordinator_home: str | os.PathLike[str] | None = None,
        *,
        effective_uid: int | None = None,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
        account_lookup: Callable[[int], Any] | None = None,
    ) -> "AccountStore":
        uid = os.geteuid() if effective_uid is None else int(effective_uid)
        if coordinator_home is None:
            lookup = pwd.getpwuid if account_lookup is None else account_lookup
            try:
                record = lookup(uid)
            except (KeyError, OSError) as error:
                raise StoreError(f"could not resolve POSIX account home for uid {uid}: {error}") from error
            raw_home = str(getattr(record, "pw_dir", "") or "")
            account_home = Path(raw_home)
            if not raw_home or not account_home.is_absolute():
                raise StoreError(f"POSIX account home for uid {uid} is not absolute")
            coordinator_home = account_home / ".codex" / "agent-coordinator"
        home = _absolute_path(coordinator_home)
        base = super().open_read_only(
            home / DEFAULT_DATABASE_NAME,
            expected_uid=uid,
            busy_timeout_ms=busy_timeout_ms,
        )
        base.__class__ = cls
        return base  # type: ignore[return-value]

    def ensure_local_host(self) -> str:
        machine = f"{platform.system()}\x1f{platform.node()}\x1f{socket.gethostname()}"
        machine_fingerprint = hashlib.sha256(machine.encode("utf-8")).hexdigest()
        host_id = deterministic_id("host", machine_fingerprint)
        timestamp = utc_timestamp()
        with self.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO hosts(host_id, machine_fingerprint, platform, hostname, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(host_id) DO UPDATE SET updated_at = excluded.updated_at
                """,
                (host_id, machine_fingerprint, platform.system(), socket.gethostname(), timestamp, timestamp),
            )
        return host_id

    def import_legacy_homes(
        self,
        paths: Iterable[str | os.PathLike[str]],
        backup_root: str | os.PathLike[str],
        *,
        dry_run: bool = False,
        fault_injector: Callable[[str], None] | None = None,
    ) -> Any:
        from .legacy_import import import_legacy_homes

        return import_legacy_homes(
            self,
            paths,
            backup_root,
            dry_run=dry_run,
            fault_injector=fault_injector,
        )

    def load_legacy_state_projection(self) -> dict[str, Any]:
        from .legacy_import import load_legacy_state_projection

        return load_legacy_state_projection(self)

    def replace_legacy_state_projection(
        self,
        state: dict[str, Any],
        expected_revision: int | None = None,
    ) -> int:
        from .legacy_import import replace_legacy_state_projection

        return replace_legacy_state_projection(self, state, expected_revision=expected_revision)

    def detect_late_legacy_writers(self) -> tuple[str, ...]:
        from .legacy_import import detect_late_legacy_writers

        return detect_late_legacy_writers(self)

    def reconcile_imported_legacy_conflicts(self) -> Any:
        from .legacy_import import reconcile_imported_legacy_conflicts

        return reconcile_imported_legacy_conflicts(self)

    def inventory_v2(self) -> dict[str, Any]:
        """Build a normalized graph from one pure read transaction."""

        with self.read_transaction() as connection:
            metadata = dict(
                connection.execute(
                    """
                    SELECT schema_version, database_generation, state_revision,
                           observation_revision, authority_mode, migration_state, updated_at
                    FROM schema_metadata WHERE singleton = 1
                    """
                ).fetchone()
            )
            repositories = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT r.repo_id, r.host_id, r.canonical_root, r.display_name,
                           r.state, r.generation, i.status AS installation_status,
                           i.startup_fenced, i.generation AS installation_generation,
                           i.disabled_at, i.reinstalled_at, i.reason
                    FROM repositories r
                    JOIN repository_installations i USING(repo_id)
                    WHERE r.state = 'active' AND i.status != 'disabled'
                    ORDER BY lower(r.display_name), r.canonical_root
                    """
                )
            ]
            for repository in repositories:
                repository["startup_fenced"] = bool(repository["startup_fenced"])
            coordinator_sources = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT source_id, canonical_home, effective_uid, status
                    FROM coordinator_sources
                    ORDER BY effective_uid, canonical_home, source_id
                    """
                )
            ]
            docker_engines = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT engine_id, host_id, capability_state
                    FROM docker_engines
                    ORDER BY host_id, engine_id
                    """
                )
            ]
            memberships = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT membership_id, repo_id, resource_kind, host_resource_id,
                           immutable_fingerprint, control_binding_id
                    FROM repository_memberships m
                    JOIN repositories r USING(repo_id)
                    JOIN repository_installations i USING(repo_id)
                    WHERE r.state = 'active' AND i.status != 'disabled'
                    ORDER BY repo_id, resource_kind, host_resource_id
                    """
                )
            ]
            control_bindings = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT binding_id, repo_id, source_resource_id, resource_kind,
                           resource_id, source_id, capability, provenance,
                           authority_state, priority, generation
                    FROM control_bindings ORDER BY resource_kind, resource_id, source_id
                    """
                )
            ]
            unassigned: list[dict[str, Any]] = []
            reason_explanations = {
                "name_only": "The host resource has an exact controller, but only its name—not a repository path—was observed.",
                "not_git": "The observed path is not a Git repository, so it cannot identify a project.",
                "missing_repo": "The repository path recorded for this resource no longer exists.",
                "conflicting_claims": "More than one repository claim exists; no automatic owner was chosen.",
                "ambiguous_control": "The host resource was observed, but one authoritative repository controller was not proved.",
                "stale_observation": "The last ownership observation is stale and must be refreshed before mutation.",
                "start_fence_violated": "This resource is running even though its repository or standalone retirement fence is complete.",
            }
            for row in connection.execute(
                """
                SELECT u.unassigned_id, u.host_id, u.source_resource_id,
                       u.resource_kind, u.resource_id, u.display_name,
                       u.reason_code, u.suggested_root, u.status,
                       sr.payload_sha256 AS source_payload_fingerprint,
                       observed.canonical_home AS observed_home,
                       cb.binding_id AS control_binding_id,
                       cb.resource_kind AS binding_resource_kind,
                       cb.resource_id AS binding_resource_id,
                       cb.source_id AS binding_source_id,
                       cb.capability AS binding_capability,
                       cb.provenance AS binding_provenance,
                       cb.authority_state, cb.generation AS binding_generation,
                       controller.canonical_home AS controller_home,
                       m.immutable_fingerprint AS membership_fingerprint,
                       d.engine_id, d.full_container_id,
                       rr.status AS retirement_status
                FROM unassigned_resources u
                LEFT JOIN source_resources sr USING(source_resource_id)
                LEFT JOIN coordinator_sources observed ON observed.source_id = sr.source_id
                LEFT JOIN control_bindings cb
                  ON cb.resource_kind = u.resource_kind AND cb.resource_id = u.resource_id
                LEFT JOIN coordinator_sources controller ON controller.source_id = cb.source_id
                LEFT JOIN repository_memberships m
                  ON m.resource_kind = u.resource_kind AND m.host_resource_id = u.resource_id
                LEFT JOIN docker_resources d
                  ON u.resource_kind = 'container' AND d.docker_resource_id = u.resource_id
                LEFT JOIN resource_retirements rr
                  ON rr.resource_kind = u.resource_kind AND rr.host_resource_id = u.resource_id
                WHERE u.status = 'active'
                ORDER BY u.resource_kind, u.display_name, u.resource_id
                """
            ):
                item = dict(row)
                item.pop("source_payload_fingerprint")
                immutable_fingerprint = item.pop("membership_fingerprint")
                engine_id = item.pop("engine_id")
                full_container_id = item.pop("full_container_id")
                if immutable_fingerprint is None and engine_id and full_container_id:
                    immutable_fingerprint = "sha256:" + fingerprint(
                        {
                            "resource_kind": item["resource_kind"],
                            "resource_id": item["resource_id"],
                            "native_identity": {
                                "docker_resource_id": item["resource_id"],
                                "engine_id": engine_id,
                                "full_container_id": full_container_id,
                            },
                        }
                    )
                observed_home = item.pop("observed_home")
                controller_home = item.pop("controller_home")
                ownership_fingerprint = _projected_binding_fingerprint(item)
                authority_state = item.pop("authority_state")
                for key in (
                    "binding_resource_kind",
                    "binding_resource_id",
                    "binding_source_id",
                    "binding_capability",
                    "binding_provenance",
                    "binding_generation",
                ):
                    item.pop(key)
                retirement_status = item.pop("retirement_status")
                exact = bool(
                    item.get("source_resource_id")
                    and item.get("control_binding_id")
                    and ownership_fingerprint
                    and immutable_fingerprint
                    and item.get("reason_code") != "stale_observation"
                    and retirement_status is None
                )
                item.update(
                    {
                        "explanation": reason_explanations.get(
                            str(item.get("reason_code")),
                            "Repository attribution is unavailable.",
                        ),
                        "observed_by": [observed_home] if observed_home else [],
                        "controller": controller_home,
                        "host_resource_id": item.get("resource_id"),
                        "immutable_fingerprint": immutable_fingerprint,
                        "ownership_fingerprint": ownership_fingerprint,
                        "can_attach": exact and authority_state == "authoritative",
                        "can_retire": exact,
                    }
                )
                unassigned.append(item)
            lifecycle_violations: list[dict[str, Any]] = []

            def append_lifecycle_violation(
                row: Any,
                *,
                resource_kind: str,
                immutable_fingerprint: str,
            ) -> None:
                standalone = str(row["retirement_status"] or "") == "retired"
                ownership_fingerprint = _projected_binding_fingerprint(row)
                affected_name = str(row["repo_display_name"] or row["display_name"])
                if standalone:
                    next_step = (
                        "Resume the exact standalone retirement journey to stop the resource; "
                        "do not attach or start it while the retirement fence is active."
                    )
                    corrective_action = "standalone_retirement"
                else:
                    next_step = (
                        f"Run repository removal again for {affected_name} to stop the exact "
                        "resource and re-verify its completed start fence."
                    )
                    corrective_action = "repository_decommission"
                item = {
                    "unassigned_id": deterministic_id(
                        "start-fence-violation", resource_kind, row["resource_id"]
                    ),
                    "host_id": row["host_id"],
                    "source_resource_id": row["source_resource_id"],
                    "resource_kind": resource_kind,
                    "resource_id": row["resource_id"],
                    "display_name": row["display_name"],
                    "reason_code": "start_fence_violated",
                    "suggested_root": None,
                    "status": "violation",
                    "explanation": reason_explanations["start_fence_violated"],
                    "observed_by": [row["controller_home"]]
                    if row["controller_home"]
                    else [],
                    "controller": row["controller_home"],
                    "host_resource_id": row["resource_id"],
                    "immutable_fingerprint": immutable_fingerprint,
                    "control_binding_id": row["control_binding_id"],
                    "ownership_fingerprint": ownership_fingerprint,
                    "can_attach": False,
                    "can_retire": False,
                    "lifecycle_violation": True,
                    "recommended_next_step": next_step,
                    "corrective_action": corrective_action,
                    "affected_repo_id": row["repo_id"],
                    "affected_repository": row["repo_display_name"],
                    "affected_canonical_root": row["canonical_root"],
                }
                lifecycle_violations.append(item)
                unassigned.append(item)

            for row in connection.execute(
                """
                SELECT d.docker_resource_id AS resource_id,
                       d.current_name AS display_name, e.host_id,
                       m.immutable_fingerprint AS membership_fingerprint,
                       d.engine_id, d.full_container_id,
                       r.repo_id, r.display_name AS repo_display_name,
                       r.canonical_root, i.status AS installation_status,
                       rr.status AS retirement_status,
                       cb.source_resource_id, cb.binding_id AS control_binding_id,
                       cb.resource_kind AS binding_resource_kind,
                       cb.resource_id AS binding_resource_id,
                       cb.source_id AS binding_source_id,
                       cb.capability AS binding_capability,
                       cb.provenance AS binding_provenance,
                       cb.authority_state, cb.generation AS binding_generation,
                       controller.canonical_home AS controller_home
                FROM docker_resources d
                JOIN docker_engines e USING(engine_id)
                JOIN docker_observations o USING(docker_resource_id)
                LEFT JOIN repository_memberships m
                  ON m.resource_kind = 'container'
                 AND m.host_resource_id = d.docker_resource_id
                LEFT JOIN repositories r ON r.repo_id = m.repo_id
                LEFT JOIN repository_installations i ON i.repo_id = r.repo_id
                LEFT JOIN resource_retirements rr
                  ON rr.resource_kind = 'container'
                 AND rr.host_resource_id = d.docker_resource_id
                LEFT JOIN control_bindings cb ON cb.binding_id = COALESCE(
                    m.control_binding_id,
                    (SELECT b.binding_id FROM control_bindings b
                     WHERE b.resource_kind = 'container'
                       AND b.resource_id = d.docker_resource_id
                     ORDER BY b.priority DESC, b.binding_id LIMIT 1)
                )
                LEFT JOIN coordinator_sources controller ON controller.source_id = cb.source_id
                WHERE o.lifecycle = 'running'
                  AND (i.status = 'disabled' OR rr.status = 'retired')
                ORDER BY d.current_name, d.full_container_id
                """
            ):
                immutable = row["membership_fingerprint"]
                if immutable is None:
                    immutable = "sha256:" + fingerprint(
                        {
                            "resource_kind": "container",
                            "resource_id": row["resource_id"],
                            "native_identity": {
                                "docker_resource_id": row["resource_id"],
                                "engine_id": row["engine_id"],
                                "full_container_id": row["full_container_id"],
                            },
                        }
                    )
                append_lifecycle_violation(
                    row,
                    resource_kind="container",
                    immutable_fingerprint=str(immutable),
                )

            for row in connection.execute(
                """
                SELECT d.server_definition_id AS resource_id,
                       d.name AS display_name, r.host_id,
                       m.immutable_fingerprint AS membership_fingerprint,
                       o.pid, o.process_start_time, o.process_fingerprint,
                       o.listener_host, o.listener_port,
                       r.repo_id, r.display_name AS repo_display_name,
                       r.canonical_root, i.status AS installation_status,
                       rr.status AS retirement_status,
                       cb.source_resource_id, cb.binding_id AS control_binding_id,
                       cb.resource_kind AS binding_resource_kind,
                       cb.resource_id AS binding_resource_id,
                       cb.source_id AS binding_source_id,
                       cb.capability AS binding_capability,
                       cb.provenance AS binding_provenance,
                       cb.authority_state, cb.generation AS binding_generation,
                       controller.canonical_home AS controller_home
                FROM server_definitions d
                JOIN repositories r USING(repo_id)
                JOIN repository_installations i USING(repo_id)
                JOIN server_observations o USING(server_definition_id)
                LEFT JOIN repository_memberships m
                  ON m.resource_kind = 'server'
                 AND m.host_resource_id = d.server_definition_id
                LEFT JOIN resource_retirements rr
                  ON rr.resource_kind = 'server'
                 AND rr.host_resource_id = d.server_definition_id
                LEFT JOIN control_bindings cb ON cb.binding_id = COALESCE(
                    m.control_binding_id,
                    (SELECT b.binding_id FROM control_bindings b
                     WHERE b.resource_kind = 'server'
                       AND b.resource_id = d.server_definition_id
                     ORDER BY b.priority DESC, b.binding_id LIMIT 1)
                )
                LEFT JOIN coordinator_sources controller ON controller.source_id = cb.source_id
                WHERE o.lifecycle IN ('running', 'starting', 'unhealthy')
                  AND (i.status = 'disabled' OR rr.status = 'retired')
                ORDER BY d.name, d.server_definition_id
                """
            ):
                immutable = row["membership_fingerprint"]
                if immutable is None:
                    native_identity = {"server_definition_id": row["resource_id"]}
                    for key in (
                        "pid",
                        "process_start_time",
                        "process_fingerprint",
                        "listener_host",
                        "listener_port",
                    ):
                        if row[key] is not None:
                            native_identity[key] = str(row[key])
                    immutable = "sha256:" + fingerprint(
                        {
                            "resource_kind": "server",
                            "resource_id": row["resource_id"],
                            "native_identity": native_identity,
                        }
                    )
                append_lifecycle_violation(
                    row,
                    resource_kind="server",
                    immutable_fingerprint=str(immutable),
                )
            observations = {
                "servers": [dict(row) for row in connection.execute("SELECT * FROM server_observations")],
                "docker": [dict(row) for row in connection.execute("SELECT * FROM docker_observations")],
                "databases": [
                    dict(row)
                    for row in connection.execute(
                        """
                        SELECT o.* FROM database_observations o
                        JOIN database_bindings b USING(database_binding_id)
                        LEFT JOIN repository_installations i USING(repo_id)
                        LEFT JOIN docker_observations container_observation
                          ON container_observation.docker_resource_id = b.docker_resource_id
                        LEFT JOIN resource_retirements rr
                          ON rr.resource_kind = 'container'
                         AND rr.host_resource_id = b.docker_resource_id
                        WHERE (b.repo_id IS NULL OR i.status != 'disabled')
                           OR (
                               container_observation.lifecycle = 'running'
                               AND (i.status = 'disabled' OR rr.status = 'retired')
                           )
                        ORDER BY o.docker_resource_id, o.database_binding_id
                        """
                    )
                ],
                "telemetry": [
                    {
                        key: value
                        for key, value in dict(row).items()
                        if key != "resource_sample_ordinal"
                    }
                    for row in connection.execute(
                        """
                        SELECT * FROM (
                            SELECT t.*,
                                   ROW_NUMBER() OVER (
                                       PARTITION BY host_resource_kind, host_resource_id
                                       ORDER BY sampled_at DESC, sample_id DESC
                                   ) AS resource_sample_ordinal
                            FROM telemetry_samples t
                        )
                        WHERE resource_sample_ordinal <= 30
                        ORDER BY host_resource_kind, host_resource_id,
                                 sampled_at DESC, sample_id DESC
                        """
                    )
                ],
                "snapshots": [
                    dict(row)
                    for row in connection.execute(
                        "SELECT * FROM observation_snapshots ORDER BY started_at DESC"
                    )
                ],
            }
            lifecycle_violation_by_key = {
                (str(item["resource_kind"]), str(item["resource_id"])): item
                for item in lifecycle_violations
            }
            compatibility_servers: list[dict[str, Any]] = []
            for row in connection.execute(
                """
                SELECT d.server_definition_id, d.name, d.role, d.cwd,
                       d.health_url_template, d.log_path, d.updated_at AS definition_updated_at,
                       r.canonical_root,
                       o.lifecycle, o.pid, o.process_start_time, o.process_fingerprint,
                       o.listener_host, o.listener_port, o.listener_observable,
                       o.health_classification, o.health_ok, o.stopped_at,
                       o.stopped_reason, o.sampled_at,
                       l.lease_id AS latest_lease_id,
                       l.status AS latest_lease_status,
                       l.owner AS latest_lease_owner,
                       p.port AS assigned_port,
                       rr.status AS retirement_status
                FROM server_definitions d
                JOIN repositories r USING(repo_id)
                JOIN repository_installations i USING(repo_id)
                LEFT JOIN server_observations o USING(server_definition_id)
                LEFT JOIN leases l ON l.lease_id = (
                    SELECT candidate.lease_id FROM leases candidate
                    WHERE candidate.server_definition_id = d.server_definition_id
                    ORDER BY CASE candidate.status WHEN 'active' THEN 0 ELSE 1 END,
                             candidate.updated_at DESC, candidate.lease_id DESC
                    LIMIT 1
                )
                LEFT JOIN port_assignments p
                  ON p.repo_id = d.repo_id AND p.server_name = d.name
                 AND p.status = 'active'
                LEFT JOIN resource_retirements rr
                  ON rr.resource_kind = 'server'
                 AND rr.host_resource_id = d.server_definition_id
                WHERE i.status != 'disabled'
                   OR (
                       o.lifecycle IN ('running', 'starting', 'unhealthy')
                       AND (i.status = 'disabled' OR rr.status = 'retired')
                   )
                ORDER BY r.canonical_root, d.name
                """
            ):
                violation = lifecycle_violation_by_key.get(
                    ("server", str(row["server_definition_id"]))
                )
                arguments = [
                    str(value[0])
                    for value in connection.execute(
                        """
                        SELECT argument FROM server_command_arguments
                        WHERE server_definition_id = ? ORDER BY ordinal
                        """,
                        (row["server_definition_id"],),
                    )
                ]
                projected_port = (
                    row["listener_port"]
                    if row["listener_port"] is not None
                    else row["assigned_port"]
                )
                projected_pid = row["pid"]
                historical_owner = str(row["latest_lease_owner"] or "")
                if (
                    projected_pid is None
                    and row["lifecycle"] == "stopped"
                    and historical_owner.isdigit()
                    and int(historical_owner) > 1
                ):
                    projected_pid = int(historical_owner)
                endpoint = None
                if projected_port is not None and row["lifecycle"] in {"running", "starting", "unhealthy"}:
                    endpoint = f"http://{row['listener_host'] or '127.0.0.1'}:{projected_port}"
                item = {
                    "id": row["server_definition_id"],
                    "key": f"{row['canonical_root']}::{row['name']}",
                    "name": row["name"],
                    "role": row["role"],
                    "project": None if violation else row["canonical_root"],
                    "cwd": row["cwd"],
                    "argv": arguments,
                    "port": projected_port,
                    "host": row["listener_host"] or "127.0.0.1",
                    "url": endpoint,
                    "url_is_current": endpoint is not None,
                    "health_url": row["health_url_template"],
                    "log_path": row["log_path"],
                    "status": row["lifecycle"] or "unobserved",
                    "pid": projected_pid,
                    "lease_id": row["latest_lease_id"],
                    "process_start_time": row["process_start_time"],
                    "process_fingerprint": row["process_fingerprint"],
                    "metadata_source": "normalized-sqlite",
                    "identity_observable": (
                        None if row["listener_observable"] is None else bool(row["listener_observable"])
                    ),
                    "health": {
                        "classification": row["health_classification"] or "unobserved",
                        "ok": None if row["health_ok"] is None else bool(row["health_ok"]),
                        "pid_alive": (
                            False
                            if row["lifecycle"] == "stopped" and projected_pid is not None
                            else None
                        ),
                    },
                    "stopped_at": row["stopped_at"],
                    "stopped_reason": row["stopped_reason"],
                    "updated_at": row["sampled_at"],
                    "attribution": violation,
                }
                latest_operation = connection.execute(
                    """
                    SELECT o.kind, o.status, o.result_json, o.updated_at
                    FROM operations o
                    JOIN operation_targets t USING(operation_id)
                    WHERE t.target_kind = 'server' AND t.target_id = ?
                      AND o.status = 'succeeded'
                    ORDER BY o.updated_at DESC, o.rowid DESC
                    LIMIT 1
                    """,
                    (row["server_definition_id"],),
                ).fetchone()
                if (
                    latest_operation is not None
                    and latest_operation["kind"] == "port.relocate"
                    and item["status"] == "stopped"
                    and row["pid"] is None
                ):
                    try:
                        relocation = json.loads(latest_operation["result_json"])
                    except (TypeError, ValueError, UnicodeDecodeError):
                        relocation = None
                    if (
                        isinstance(relocation, dict)
                        and relocation.get("server_definition_id")
                        == row["server_definition_id"]
                        and relocation.get("new_project") == row["canonical_root"]
                        and relocation.get("port") == projected_port
                        and isinstance(relocation.get("old_project"), str)
                        and relocation["old_project"]
                        and relocation["old_project"] != row["canonical_root"]
                    ):
                        item.update(
                            {
                                "pid": None,
                                "lease_id": None,
                                "metadata_source": "port_relocate",
                                "relocated_from": relocation["old_project"],
                                "relocated_at": latest_operation["updated_at"],
                                "stopped_reason": (
                                    "Checkout ownership relocated; awaiting exact "
                                    "listener registration"
                                ),
                            }
                        )
                if item["status"] in {"running", "starting", "unhealthy"}:
                    usage = connection.execute(
                        """
                        SELECT sampled_at, cpu_percent, memory_bytes
                        FROM telemetry_samples
                        WHERE host_resource_kind = 'server'
                          AND host_resource_id = ?
                          AND sampled_at >= ?
                        ORDER BY sampled_at DESC, sample_id DESC
                        LIMIT 1
                        """,
                        (row["server_definition_id"], row["definition_updated_at"]),
                    ).fetchone()
                    if usage is not None:
                        item["process_usage"] = {
                            "source": "normalized_observation",
                            "sampled_at": usage["sampled_at"],
                            "cpu_percent": usage["cpu_percent"],
                            "memory_bytes": usage["memory_bytes"],
                            "rss_bytes": usage["memory_bytes"],
                        }
                compatibility_servers.append(item)
            compatibility_leases = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT l.lease_id AS id, r.canonical_root AS project, l.port,
                           l.owner, l.agent, l.purpose, l.status, l.expires_at,
                           l.process_fingerprint, l.deactivated_at, l.created_at, l.updated_at,
                           l.server_definition_id AS server_id,
                           CASE
                               WHEN l.owner != '' AND l.owner NOT GLOB '*[^0-9]*'
                               THEN CAST(l.owner AS INTEGER)
                               ELSE NULL
                           END AS owner_pid,
                           CASE
                               WHEN d.name IS NOT NULL
                               THEN r.canonical_root || '::' || d.name
                               ELSE NULL
                           END AS assignment_key
                    FROM leases l JOIN repositories r USING(repo_id)
                    JOIN repository_installations i USING(repo_id)
                    LEFT JOIN server_definitions d USING(server_definition_id)
                    WHERE i.status != 'disabled' AND l.status = 'active'
                    ORDER BY l.port, l.lease_id
                    """
                )
            ]
            compatibility_assignments = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT p.assignment_id AS id,
                           r.canonical_root || '::' || p.server_name AS key,
                           r.canonical_root AS project,
                           p.server_name AS name, p.port, p.status,
                           p.deactivated_at, p.updated_at,
                           COALESCE(o.lifecycle, 'unregistered') AS server_status
                    FROM port_assignments p JOIN repositories r USING(repo_id)
                    JOIN repository_installations i USING(repo_id)
                    LEFT JOIN server_definitions d
                      ON d.repo_id = p.repo_id AND d.name = p.server_name
                    LEFT JOIN server_observations o USING(server_definition_id)
                    WHERE i.status != 'disabled' AND p.status = 'active'
                    ORDER BY p.port, r.canonical_root, p.server_name
                    """
                )
            ]
            compatibility_containers: list[dict[str, Any]] = []
            containers_by_resource: dict[str, dict[str, Any]] = {}
            unassigned_by_resource = {
                str(row["resource_id"]): row for row in unassigned if row.get("resource_kind") == "container"
            }
            for row in connection.execute(
                """
                SELECT d.docker_resource_id, d.full_container_id,
                       d.current_name AS name, d.image, r.canonical_root AS project,
                       o.lifecycle AS status, o.health, o.restart_policy, o.sampled_at,
                       cb.provenance AS metadata_source
                FROM docker_resources d
                LEFT JOIN docker_observations o USING(docker_resource_id)
                LEFT JOIN repository_memberships m
                  ON m.resource_kind = 'container' AND m.host_resource_id = d.docker_resource_id
                LEFT JOIN repositories r ON r.repo_id = m.repo_id
                LEFT JOIN repository_installations i ON i.repo_id = r.repo_id
                LEFT JOIN control_bindings cb ON cb.binding_id = m.control_binding_id
                LEFT JOIN resource_retirements rr
                  ON rr.resource_kind = 'container' AND rr.host_resource_id = d.docker_resource_id
                WHERE (
                    (r.repo_id IS NULL OR i.status != 'disabled')
                    AND (rr.host_resource_id IS NULL OR rr.status != 'retired')
                ) OR (
                    o.lifecycle = 'running'
                    AND (i.status = 'disabled' OR rr.status = 'retired')
                )
                ORDER BY d.current_name, d.full_container_id
                """
            ):
                resource_id = str(row["docker_resource_id"])
                violation = lifecycle_violation_by_key.get(("container", resource_id))
                port_rows = connection.execute(
                    """
                    SELECT host_address, host_port, container_port, protocol
                    FROM docker_ports WHERE docker_resource_id = ? ORDER BY ordinal
                    """,
                    (resource_id,),
                ).fetchall()
                ports: list[str] = []
                for port in port_rows:
                    destination = f"{port['container_port']}/{port['protocol']}"
                    if port["host_port"] is None:
                        ports.append(destination)
                    else:
                        ports.append(
                            f"{port['host_address'] or '0.0.0.0'}:{port['host_port']}->{destination}"
                        )
                item = {
                    "id": row["full_container_id"],
                    "host_resource_id": resource_id,
                    "name": row["name"],
                    "image": row["image"],
                    "project": None if violation else row["project"],
                    "status": row["status"] or "unobserved",
                    "ports": ", ".join(ports) if ports else None,
                    "health": row["health"],
                    "restart_policy": row["restart_policy"],
                    "sampled_at": row["sampled_at"],
                    "metadata_source": row["metadata_source"] or "none",
                    "attribution": violation or unassigned_by_resource.get(resource_id),
                }
                compatibility_containers.append(item)
                containers_by_resource[resource_id] = item
            compatibility_postgres: list[dict[str, Any]] = []
            for row in connection.execute(
                """
                SELECT b.database_binding_id, b.database_name, b.engine_kind,
                       b.docker_resource_id, r.canonical_root AS project,
                       o.available AS database_available,
                       o.size_bytes AS database_size_bytes,
                       o.error_code AS database_error_code,
                       o.error_message AS database_error,
                       o.sampled_at AS database_sampled_at
                FROM database_bindings b
                LEFT JOIN database_observations o USING(database_binding_id)
                LEFT JOIN repositories r USING(repo_id)
                ORDER BY r.canonical_root, b.database_name
                """
            ):
                container = dict(containers_by_resource.get(str(row["docker_resource_id"]), {}))
                if not container:
                    continue
                if (container.get("attribution") or {}).get("lifecycle_violation"):
                    continue
                container.update(
                    {
                        "database_binding_id": row["database_binding_id"],
                        "database": row["database_name"],
                        "engine_kind": row["engine_kind"],
                        "database_available": (
                            None
                            if row["database_available"] is None
                            else bool(row["database_available"])
                        ),
                        "database_size_bytes": row["database_size_bytes"],
                        "database_error_code": row["database_error_code"],
                        "database_error": row["database_error"],
                        "database_sampled_at": row["database_sampled_at"],
                        "project": row["project"] or container.get("project"),
                    }
                )
                compatibility_postgres.append(container)
            compatibility_backups = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT b.database_backup_id AS id,
                           r.canonical_root AS project,
                           b.artifact_path AS path,
                           b.artifact_size_bytes AS size,
                           b.manifest_path AS manifest,
                           b.source_database_name AS database,
                           b.source_container_id AS container_id,
                           d.current_name AS container,
                           b.backup_format AS format,
                           b.artifact_sha256 AS sha256,
                           b.verification_status,
                           b.verification_mode,
                           b.status, b.created_at, b.verified_at,
                           b.last_restored_at, b.restore_count
                    FROM database_backups b
                    LEFT JOIN repositories r USING(repo_id)
                    LEFT JOIN repository_installations i USING(repo_id)
                    LEFT JOIN docker_resources d USING(docker_resource_id)
                    WHERE b.status != 'retired'
                      AND (r.repo_id IS NULL OR i.status != 'disabled')
                    ORDER BY b.created_at DESC, b.database_backup_id
                    """
                )
            ]
            compatibility_events = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT e.event_id AS id, e.event_kind AS type, e.code,
                           e.message, e.occurred_at AS at, r.canonical_root AS project
                    FROM events e LEFT JOIN repositories r USING(repo_id)
                    LEFT JOIN repository_installations i USING(repo_id)
                    WHERE r.repo_id IS NULL OR i.status != 'disabled'
                    ORDER BY e.occurred_at DESC LIMIT 40
                    """
                )
            ]
            compatibility_usage: list[dict[str, Any]] = []
            for repository in repositories:
                repo_id = repository["repo_id"]
                server_ids = [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT server_definition_id FROM server_definitions WHERE repo_id = ? ORDER BY name",
                        (repo_id,),
                    )
                ]
                container_names = [
                    str(row[0])
                    for row in connection.execute(
                        """
                        SELECT d.current_name FROM repository_memberships m
                        JOIN docker_resources d ON d.docker_resource_id = m.host_resource_id
                        WHERE m.repo_id = ? AND m.resource_kind = 'container'
                        ORDER BY d.current_name
                        """,
                        (repo_id,),
                    )
                ]
                usage_rows = list(
                    connection.execute(
                        """
                        SELECT t.cpu_percent, t.memory_bytes
                        FROM server_definitions d
                        JOIN server_observations o USING(server_definition_id)
                        JOIN telemetry_samples t
                          ON t.host_resource_kind = 'server'
                         AND t.host_resource_id = d.server_definition_id
                        WHERE d.repo_id = ?
                          AND o.lifecycle IN ('running', 'starting', 'unhealthy')
                          AND t.sampled_at >= d.updated_at
                          AND t.sample_id = (
                              SELECT newer.sample_id
                              FROM telemetry_samples newer
                              WHERE newer.host_resource_kind = 'server'
                                AND newer.host_resource_id = d.server_definition_id
                                AND newer.sampled_at >= d.updated_at
                              ORDER BY newer.sampled_at DESC, newer.sample_id DESC
                              LIMIT 1
                          )
                        """,
                        (repo_id,),
                    )
                )
                usage_rows.extend(
                    connection.execute(
                        """
                        SELECT t.cpu_percent, t.memory_bytes
                        FROM repository_memberships m
                        JOIN docker_observations o
                          ON o.docker_resource_id = m.host_resource_id
                        JOIN telemetry_samples t
                          ON t.host_resource_kind = 'docker'
                         AND t.host_resource_id = m.host_resource_id
                        WHERE m.repo_id = ? AND m.resource_kind = 'container'
                          AND o.lifecycle = 'running'
                          AND t.sample_id = (
                              SELECT newer.sample_id
                              FROM telemetry_samples newer
                              WHERE newer.host_resource_kind = 'docker'
                                AND newer.host_resource_id = m.host_resource_id
                              ORDER BY newer.sampled_at DESC, newer.sample_id DESC
                              LIMIT 1
                          )
                        """,
                        (repo_id,),
                    )
                )
                cpu_samples = [
                    float(row["cpu_percent"])
                    for row in usage_rows
                    if row["cpu_percent"] is not None
                ]
                memory_samples = [
                    int(row["memory_bytes"])
                    for row in usage_rows
                    if row["memory_bytes"] is not None
                ]
                compatibility_usage.append(
                    {
                        "usage_key": f"path:{repository['canonical_root']}",
                        "project": repository["canonical_root"],
                        "display_name": repository["display_name"],
                        "server_ids": server_ids,
                        "container_names": container_names,
                        "process_count": None,
                        "cpu_percent": sum(cpu_samples) if cpu_samples else None,
                        "memory_bytes": sum(memory_samples) if memory_samples else None,
                    }
                )
            compatibility_urls = [
                {
                    "name": row["name"],
                    "project": row["project"],
                    "url": row["url"],
                    "health_url": row["health_url"],
                    "status": row["status"],
                }
                for row in compatibility_servers
                if row["url"] is not None and row["url_is_current"]
            ]
            docker_capability = connection.execute(
                """
                SELECT capability_state
                FROM docker_engines
                WHERE context_identity != 'legacy-default'
                ORDER BY updated_at DESC,
                         CASE WHEN context_identity = 'default' THEN 0 ELSE 1 END,
                         engine_id
                LIMIT 1
                """
            ).fetchone()
            docker_available = (
                None if docker_capability is None else str(docker_capability[0]) == "available"
            )
            v1_compatibility = {
                "coordinator_home": str(self.path.parent),
                "state_path": str(self.path),
                "project": None,
                "urls": compatibility_urls,
                "servers": compatibility_servers,
                "leases": compatibility_leases,
                "port_assignments": compatibility_assignments,
                "recent_events": compatibility_events,
                "docker": {
                    "available": docker_available,
                    "containers": compatibility_containers,
                    "postgres": compatibility_postgres,
                },
                "postgres": compatibility_postgres,
                "backups": compatibility_backups,
                "project_usage": compatibility_usage,
            }
            server_resources: list[dict[str, Any]] = []
            for row in connection.execute(
                """
                SELECT d.server_definition_id, d.repo_id, d.name, d.role, d.cwd,
                       d.health_url_template, d.log_path,
                       d.definition_fingerprint, d.generation
                FROM server_definitions d
                JOIN repository_installations i USING(repo_id)
                LEFT JOIN server_observations o USING(server_definition_id)
                LEFT JOIN resource_retirements rr
                  ON rr.resource_kind = 'server'
                 AND rr.host_resource_id = d.server_definition_id
                WHERE i.status != 'disabled'
                   OR (
                       o.lifecycle IN ('running', 'starting', 'unhealthy')
                       AND (i.status = 'disabled' OR rr.status = 'retired')
                   )
                ORDER BY d.repo_id, d.name
                """
            ):
                server = dict(row)
                server["arguments"] = [
                    str(argument[0])
                    for argument in connection.execute(
                        """
                        SELECT argument FROM server_command_arguments
                        WHERE server_definition_id = ? ORDER BY ordinal
                        """,
                        (row["server_definition_id"],),
                    )
                ]
                server_resources.append(server)
            docker_resources = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT d.* FROM docker_resources d
                    LEFT JOIN repository_memberships m
                      ON m.resource_kind = 'container'
                     AND m.host_resource_id = d.docker_resource_id
                    LEFT JOIN repository_installations i ON i.repo_id = m.repo_id
                    LEFT JOIN resource_retirements rr
                      ON rr.resource_kind = 'container'
                     AND rr.host_resource_id = d.docker_resource_id
                    LEFT JOIN docker_observations o USING(docker_resource_id)
                    WHERE (
                        (m.repo_id IS NULL OR i.status != 'disabled')
                        AND (rr.host_resource_id IS NULL OR rr.status != 'retired')
                    ) OR (
                        o.lifecycle = 'running'
                        AND (i.status = 'disabled' OR rr.status = 'retired')
                    )
                    ORDER BY d.current_name, d.full_container_id
                    """
                )
            ]
            visible_docker_ids = {
                str(resource["docker_resource_id"]) for resource in docker_resources
            }
            docker_ports = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT docker_resource_id, ordinal, host_address, host_port,
                           container_port, protocol
                    FROM docker_ports
                    ORDER BY docker_resource_id, ordinal
                    """
                )
                if str(row["docker_resource_id"]) in visible_docker_ids
            ]
            database_resources = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT b.database_binding_id, b.docker_resource_id, b.repo_id,
                           b.database_name, b.engine_kind, b.created_at, b.updated_at
                    FROM database_bindings b
                    LEFT JOIN repository_installations i USING(repo_id)
                    LEFT JOIN docker_observations o USING(docker_resource_id)
                    LEFT JOIN resource_retirements rr
                      ON rr.resource_kind = 'container'
                     AND rr.host_resource_id = b.docker_resource_id
                    WHERE (b.repo_id IS NULL OR i.status != 'disabled')
                       OR (
                           o.lifecycle = 'running'
                           AND (i.status = 'disabled' OR rr.status = 'retired')
                       )
                    ORDER BY b.repo_id, b.database_name, b.database_binding_id
                    """
                )
                if str(row["docker_resource_id"]) in visible_docker_ids
            ]
            leases = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT l.lease_id, l.repo_id, l.server_definition_id,
                           l.source_id, l.port, l.owner, l.agent, l.purpose,
                           l.status, l.expires_at, l.process_fingerprint,
                           l.deactivated_at, l.created_at, l.updated_at
                    FROM leases l
                    JOIN repository_installations i USING(repo_id)
                    WHERE i.status != 'disabled'
                    ORDER BY l.port, l.lease_id
                    """
                )
            ]
            port_assignments = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT p.assignment_id, p.repo_id, p.server_name, p.port,
                           p.status, p.deactivated_at, p.created_at, p.updated_at
                    FROM port_assignments p
                    JOIN repository_installations i USING(repo_id)
                    WHERE i.status != 'disabled'
                    ORDER BY p.port, p.repo_id, p.server_name
                    """
                )
            ]
            backup_evidence = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT b.backup_id, b.repo_id, b.source_id, b.manifest_path,
                           b.manifest_sha256, b.verification_status,
                           b.created_at, b.verified_at
                    FROM backup_evidence b
                    LEFT JOIN repository_installations i USING(repo_id)
                    WHERE b.repo_id IS NULL OR i.status != 'disabled'
                    ORDER BY b.created_at DESC, b.backup_id
                    """
                )
            ]
            database_backups = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT b.database_backup_id, b.database_binding_id,
                           b.docker_resource_id, b.repo_id, b.source_id,
                           b.scope, b.source_container_id,
                           b.source_database_name,
                           b.source_identity_fingerprint,
                           b.artifact_path, b.artifact_size_bytes,
                           b.artifact_sha256, b.manifest_path,
                           b.manifest_sha256, b.backup_format,
                           b.verification_status, b.verification_mode,
                           b.created_at, b.verified_at, b.status,
                           b.last_restored_at, b.restore_count, b.updated_at
                    FROM database_backups b
                    LEFT JOIN repository_installations i USING(repo_id)
                    WHERE b.status != 'retired'
                      AND (b.repo_id IS NULL OR i.status != 'disabled')
                    ORDER BY b.created_at DESC, b.database_backup_id
                    """
                )
            ]
            database_restore_events = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT restore_event_id, database_backup_id,
                           target_database_binding_id,
                           target_docker_resource_id, target_container_id,
                           target_database_name, artifact_sha256,
                           safety_database_backup_id, result_fingerprint,
                           restored_at
                    FROM database_restore_events
                    ORDER BY restored_at DESC, restore_event_id DESC
                    LIMIT 200
                    """
                )
            ]
            events = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT e.event_id, e.repo_id, e.source_id, e.event_kind,
                           e.code, e.message, e.occurred_at
                    FROM events e
                    LEFT JOIN repository_installations i USING(repo_id)
                    WHERE e.repo_id IS NULL OR i.status != 'disabled'
                    ORDER BY e.occurred_at DESC, e.event_id DESC
                    LIMIT 200
                    """
                )
            ]
            graph = {
                "schema_version": 2,
                "store": metadata,
                "repositories": repositories,
                "coordinator_sources": coordinator_sources,
                "docker_engines": docker_engines,
                "memberships": memberships,
                "resources": {
                    "servers": server_resources,
                    "docker": docker_resources,
                    "docker_ports": docker_ports,
                    "databases": database_resources,
                },
                "leases": leases,
                "port_assignments": port_assignments,
                # Migration preservation evidence is intentionally separate
                # from real user-restorable PostgreSQL artifacts.
                "backup_evidence": backup_evidence,
                "database_backups": database_backups,
                "database_restore_events": database_restore_events,
                "events": events,
                "unassigned_resources": unassigned,
                "lifecycle_violations": lifecycle_violations,
                "observations": observations,
                "control_bindings": control_bindings,
                "v1_compatibility": v1_compatibility,
            }
            # Transitional callers can consume non-colliding legacy aliases
            # without a second read. Names shared by the normalized contract
            # (currently leases and port_assignments) must remain v2-shaped at
            # the top level; their legacy rows live only in v1_compatibility.
            for key, value in v1_compatibility.items():
                graph.setdefault(key, value)
            return graph
