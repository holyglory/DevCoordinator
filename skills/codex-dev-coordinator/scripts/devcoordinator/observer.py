"""Cross-process single-flight host observation.

Inventory reads are deliberately absent from this module.  Callers explicitly
request observation, one process owns the slow host sampler, and concurrent
callers join the durable ticket recorded in SQLite.  The supplied commit
callback writes normalized observations in the owner's short final transaction.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import sqlite3
import time
from typing import Any, Callable, Generator, Mapping, Protocol
import uuid


class ObservationError(RuntimeError):
    """An explicit observation failed or could not be joined safely."""


class ObservationStore(Protocol):
    def read_transaction(self):
        ...

    def immediate_transaction(
        self,
        *,
        max_seconds: float | None = None,
        revision_kind: str | None = "state",
    ):
        ...


@dataclass(frozen=True)
class ObservationTicket:
    snapshot_id: str
    host_id: str
    observer_domain: str
    owner: bool


@dataclass(frozen=True)
class ObservationOutcome:
    snapshot_id: str
    host_id: str
    observer_domain: str
    joined: bool
    material_fingerprint: str
    completed_at: str


@dataclass(frozen=True)
class ObservationOwnerContext:
    """Trusted broker-process ownership for one observation callback.

    Account-mode observers do not install this context.  The service broker
    uses it to bind only tickets physically owned by its current process to a
    durable shutdown-cleanup row.  Joiners never acquire ownership of another
    process's ticket.
    """

    owner_id: str
    cancelled: Callable[[], bool]


_OWNER_CONTEXT: ContextVar[ObservationOwnerContext | None] = ContextVar(
    "devcoordinator_observation_owner", default=None
)


@contextmanager
def observation_owner_scope(
    *, owner_id: str, cancelled: Callable[[], bool]
) -> Generator[None, None, None]:
    """Bind broker ownership/cancellation to nested SingleFlight observers."""

    _require_key("owner_id", owner_id)
    if not callable(cancelled):
        raise TypeError("cancelled must be callable")
    token = _OWNER_CONTEXT.set(
        ObservationOwnerContext(owner_id=owner_id, cancelled=cancelled)
    )
    try:
        yield
    finally:
        _OWNER_CONTEXT.reset(token)


class SingleFlightObserver:
    """Serialize one physical observer domain across all account processes."""

    def __init__(
        self,
        store: ObservationStore,
        *,
        clock: Callable[[], datetime] | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        id_factory: Callable[[], str] | None = None,
        stale_after: timedelta = timedelta(minutes=2),
        join_timeout: float = 30.0,
    ) -> None:
        self._store = store
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._sleep = sleeper
        self._id_factory = id_factory or (lambda: str(uuid.uuid4()))
        self._stale_after = stale_after
        self._join_timeout = max(0.1, float(join_timeout))

    def observe(
        self,
        *,
        host_id: str,
        observer_domain: str,
        sampler: Callable[[], Mapping[str, Any]],
        commit: Callable[[sqlite3.Connection, str, Mapping[str, Any]], None],
    ) -> ObservationOutcome:
        _require_key("host_id", host_id)
        _require_key("observer_domain", observer_domain)
        ticket = self._claim(host_id, observer_domain)
        if not ticket.owner:
            return self._join(ticket)
        try:
            sample = sampler()
            if not isinstance(sample, Mapping):
                raise ObservationError("host sampler returned a non-mapping result")
            fingerprint = _material_fingerprint(sample)
            completed_at = _timestamp(self._clock())
            with self._store.immediate_transaction(
                max_seconds=5.0,
                revision_kind="observation",
            ) as connection:
                status = connection.execute(
                    "SELECT status FROM observation_snapshots WHERE snapshot_id = ?",
                    (ticket.snapshot_id,),
                ).fetchone()
                if status is None or status[0] != "running":
                    raise ObservationError("observation ownership ticket changed before commit")
                commit(connection, ticket.snapshot_id, sample)
                connection.execute(
                    """
                    UPDATE observation_snapshots
                    SET status = 'completed', material_fingerprint = ?,
                        completed_at = ?, error_code = NULL, error_message = NULL
                    WHERE snapshot_id = ? AND status = 'running'
                    """,
                    (fingerprint, completed_at, ticket.snapshot_id),
                )
            return ObservationOutcome(
                snapshot_id=ticket.snapshot_id,
                host_id=host_id,
                observer_domain=observer_domain,
                joined=False,
                material_fingerprint=fingerprint,
                completed_at=completed_at,
            )
        except BaseException as error:
            self._record_failure(ticket, error)
            raise

    def _claim(self, host_id: str, observer_domain: str) -> ObservationTicket:
        snapshot_id = self._id_factory()
        started_at = _timestamp(self._clock())
        stale_before = self._clock().astimezone(timezone.utc) - self._stale_after
        owner = _OWNER_CONTEXT.get()
        with self._store.immediate_transaction(
            max_seconds=5.0,
            revision_kind=None,
        ) as connection:
            # This check occurs after BEGIN IMMEDIATE.  Shutdown sets the
            # cancellation flag before taking its own write transaction, so
            # either this claim commits its ownership first and shutdown marks
            # it failed, or shutdown wins and this claim is refused.  There is
            # no gap in which a new broker-owned ticket can appear afterward.
            if owner is not None and owner.cancelled():
                raise ObservationError(
                    "broker shutdown began before the host observation ticket was claimed"
                )
            running = connection.execute(
                """
                SELECT snapshot_id, started_at
                FROM observation_snapshots
                WHERE host_id = ? AND observer_domain = ? AND status = 'running'
                ORDER BY started_at DESC LIMIT 1
                """,
                (host_id, observer_domain),
            ).fetchone()
            if running is not None:
                started = _parse_timestamp(running[1])
                if started is not None and started >= stale_before:
                    return ObservationTicket(running[0], host_id, observer_domain, False)
                connection.execute(
                    """
                    UPDATE observation_snapshots
                    SET status = 'failed', completed_at = ?,
                        error_code = 'observer_owner_abandoned',
                        error_message = 'observation owner did not complete its bounded ticket'
                    WHERE snapshot_id = ? AND status = 'running'
                    """,
                    (started_at, running[0]),
                )
            try:
                connection.execute(
                    """
                    INSERT INTO observation_snapshots(
                        snapshot_id, host_id, observer_domain, status, started_at
                    ) VALUES (?, ?, ?, 'running', ?)
                    """,
                    (snapshot_id, host_id, observer_domain, started_at),
                )
                if owner is not None:
                    connection.execute(
                        """
                        INSERT INTO broker_host_observation_owners(
                            snapshot_id, broker_instance_id, claimed_at
                        ) VALUES (?, ?, ?)
                        """,
                        (snapshot_id, owner.owner_id, started_at),
                    )
            except sqlite3.IntegrityError:
                # The partial unique index is the final cross-process arbiter.
                winner = connection.execute(
                    """
                    SELECT snapshot_id FROM observation_snapshots
                    WHERE host_id = ? AND observer_domain = ? AND status = 'running'
                    """,
                    (host_id, observer_domain),
                ).fetchone()
                if winner is None:
                    raise
                return ObservationTicket(winner[0], host_id, observer_domain, False)
        return ObservationTicket(snapshot_id, host_id, observer_domain, True)

    def _join(self, ticket: ObservationTicket) -> ObservationOutcome:
        deadline = time.monotonic() + self._join_timeout
        delay = 0.02
        while True:
            with self._store.read_transaction() as connection:
                row = connection.execute(
                    """
                    SELECT status, material_fingerprint, completed_at,
                           error_code, error_message
                    FROM observation_snapshots WHERE snapshot_id = ?
                    """,
                    (ticket.snapshot_id,),
                ).fetchone()
            if row is None:
                raise ObservationError("joined observation ticket disappeared")
            if row[0] == "completed":
                if not row[1] or not row[2]:
                    raise ObservationError("completed observation lacks durable evidence")
                return ObservationOutcome(
                    snapshot_id=ticket.snapshot_id,
                    host_id=ticket.host_id,
                    observer_domain=ticket.observer_domain,
                    joined=True,
                    material_fingerprint=row[1],
                    completed_at=row[2],
                )
            if row[0] == "failed":
                raise ObservationError(
                    f"joined observation failed ({row[3] or 'observation_failed'}): "
                    f"{row[4] or 'no diagnostic was recorded'}"
                )
            if time.monotonic() >= deadline:
                raise ObservationError("timed out waiting for the in-flight host observation")
            self._sleep(delay)
            delay = min(delay * 1.5, 0.2)

    def _record_failure(self, ticket: ObservationTicket, error: BaseException) -> None:
        try:
            completed_at = _timestamp(self._clock())
            with self._store.immediate_transaction(
                max_seconds=5.0,
                revision_kind=None,
            ) as connection:
                connection.execute(
                    """
                    UPDATE observation_snapshots
                    SET status = 'failed', completed_at = ?, error_code = ?, error_message = ?
                    WHERE snapshot_id = ? AND status = 'running'
                    """,
                    (
                        completed_at,
                        _error_code(error),
                        str(error)[:4096],
                        ticket.snapshot_id,
                    ),
                )
        except BaseException as cleanup_error:
            if hasattr(error, "add_note"):
                error.add_note(
                    "observation failure could not be recorded: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )


def _material_fingerprint(sample: Mapping[str, Any]) -> str:
    try:
        payload = json.dumps(
            sample, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ObservationError(f"host sampler returned non-serializable evidence: {error}") from error
    # Normalized lifecycle persistence stores material fingerprints as the
    # canonical 64-hex digest. Capability fingerprints use the tagged
    # `sha256:` transport form and are intentionally a separate contract.
    return hashlib.sha256(payload).hexdigest()


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("observer clock must return a timezone-aware datetime")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (AttributeError, ValueError):
        return None


def _require_key(label: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise ValueError(f"{label} must be a bounded non-empty string")


def _error_code(error: BaseException) -> str:
    name = type(error).__name__
    result = []
    for index, char in enumerate(name):
        if index and char.isupper():
            result.append("_")
        result.append(char.lower())
    return "observer_" + "".join(result)


__all__ = [
    "ObservationError",
    "ObservationOutcome",
    "ObservationOwnerContext",
    "ObservationTicket",
    "SingleFlightObserver",
    "observation_owner_scope",
]
