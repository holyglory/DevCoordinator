"""Durable authority proof for the legacy-test submission drain.

The proof is not a client assertion: every security-relevant field and its
canonical fingerprint are stored in the root-owned authority database.  A
cutover process accepts a document only after exact read-only comparison with
that active row and the current authority generation.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import threading
import time
from types import MappingProxyType
from typing import Mapping
import uuid

from .universal_test_store import TestStoreContractError
from .store import CoordinatorStore


LEGACY_TEST_DRAIN_PURPOSE = "legacy-test-history-cutover"
LEGACY_TEST_DRAIN_SCHEMA_VERSION = 1
LEGACY_TEST_ADMISSION_SCHEMA = """
CREATE TABLE IF NOT EXISTS broker_test_admission_fences (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_version INTEGER NOT NULL CHECK(schema_version = 1),
    purpose TEXT NOT NULL CHECK(purpose = 'legacy-test-history-cutover'),
    drain_id TEXT NOT NULL UNIQUE,
    authority_generation TEXT NOT NULL,
    activated_at_epoch INTEGER NOT NULL CHECK(activated_at_epoch >= 0),
    activated_by_uid INTEGER NOT NULL CHECK(activated_by_uid >= 0),
    drained_at_epoch INTEGER NOT NULL
        CHECK(drained_at_epoch >= activated_at_epoch),
    broker_instance_id TEXT NOT NULL,
    observed_inflight_submissions INTEGER NOT NULL
        CHECK(observed_inflight_submissions = 0),
    active INTEGER NOT NULL CHECK(active = 1),
    proof_sha256 TEXT NOT NULL CHECK(length(proof_sha256) = 64)
)
"""
_FIELDS = frozenset(
    {
        "schema_version",
        "purpose",
        "drain_id",
        "authority_generation",
        "activated_at_epoch",
        "activated_by_uid",
        "drained_at_epoch",
        "broker_instance_id",
        "observed_inflight_submissions",
        "active",
        "proof_sha256",
    }
)


def _fingerprint(document: Mapping[str, object]) -> str:
    payload = json.dumps(
        {key: value for key, value in document.items() if key != "proof_sha256"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def normalize_legacy_test_admission_drain_proof(
    proof: Mapping[str, object],
) -> Mapping[str, object]:
    if not isinstance(proof, Mapping) or set(proof) != _FIELDS:
        raise TestStoreContractError("legacy test admission drain proof fields are invalid")
    if (
        proof["schema_version"] != LEGACY_TEST_DRAIN_SCHEMA_VERSION
        or proof["purpose"] != LEGACY_TEST_DRAIN_PURPOSE
        or proof["active"] != 1
        or proof["observed_inflight_submissions"] != 0
    ):
        raise TestStoreContractError("legacy test admission drain proof is not active and drained")
    try:
        drain_id = str(uuid.UUID(str(proof["drain_id"])))
    except (TypeError, ValueError, AttributeError) as error:
        raise TestStoreContractError("legacy test admission drain ID is invalid") from error
    values = {
        "schema_version": LEGACY_TEST_DRAIN_SCHEMA_VERSION,
        "purpose": LEGACY_TEST_DRAIN_PURPOSE,
        "drain_id": drain_id,
        "authority_generation": proof["authority_generation"],
        "activated_at_epoch": proof["activated_at_epoch"],
        "activated_by_uid": proof["activated_by_uid"],
        "drained_at_epoch": proof["drained_at_epoch"],
        "broker_instance_id": proof["broker_instance_id"],
        "observed_inflight_submissions": 0,
        "active": 1,
        "proof_sha256": proof["proof_sha256"],
    }
    for field in ("authority_generation", "broker_instance_id"):
        value = values[field]
        if (
            not isinstance(value, str)
            or not value
            or len(value) > 256
            or any(character in value for character in "\x00\r\n")
        ):
            raise TestStoreContractError(f"legacy test drain {field} is invalid")
    for field in (
        "activated_at_epoch",
        "activated_by_uid",
        "drained_at_epoch",
    ):
        value = values[field]
        if type(value) is not int or value < 0:
            raise TestStoreContractError(f"legacy test drain {field} is invalid")
    if values["drained_at_epoch"] < values["activated_at_epoch"]:
        raise TestStoreContractError("legacy test drain timestamps are contradictory")
    fingerprint = values["proof_sha256"]
    if (
        not isinstance(fingerprint, str)
        or len(fingerprint) != 64
        or any(character not in "0123456789abcdef" for character in fingerprint)
        or _fingerprint(values) != fingerprint
    ):
        raise TestStoreContractError("legacy test drain proof fingerprint is invalid")
    return MappingProxyType(values)


def verify_legacy_test_admission_drain_proof(
    authority_database: Path,
    proof: Mapping[str, object],
    *,
    expected_uid: int,
) -> Mapping[str, object]:
    """Return one immutable normalized proof only after exact DB comparison."""

    normalized = normalize_legacy_test_admission_drain_proof(proof)
    try:
        with CoordinatorStore.open_read_only(
            Path(authority_database), expected_uid=expected_uid
        ) as store:
            with store.read_transaction() as connection:
                generation = connection.execute(
                    "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
                ).fetchone()
                row = connection.execute(
                    """
                    SELECT schema_version, purpose, drain_id, authority_generation,
                           activated_at_epoch, activated_by_uid, drained_at_epoch,
                           broker_instance_id, observed_inflight_submissions,
                           active, proof_sha256
                    FROM broker_test_admission_fences
                    WHERE singleton = 1
                    """
                ).fetchone()
    except Exception as error:
        if isinstance(error, TestStoreContractError):
            raise
        raise TestStoreContractError("authority drain proof is unavailable") from error
    if generation is None or str(generation[0]) != normalized["authority_generation"]:
        raise TestStoreContractError("authority generation does not match drain proof")
    if row is None:
        raise TestStoreContractError("authority has no active test drain proof")
    persisted = normalize_legacy_test_admission_drain_proof(dict(row))
    if dict(persisted) != dict(normalized):
        raise TestStoreContractError("legacy test drain proof does not match authority")
    return persisted


def build_legacy_test_admission_drain_proof(
    *,
    drain_id: str,
    authority_generation: str,
    activated_at_epoch: int,
    activated_by_uid: int,
    drained_at_epoch: int,
    broker_instance_id: str,
) -> Mapping[str, object]:
    values: dict[str, object] = {
        "schema_version": LEGACY_TEST_DRAIN_SCHEMA_VERSION,
        "purpose": LEGACY_TEST_DRAIN_PURPOSE,
        "drain_id": drain_id,
        "authority_generation": authority_generation,
        "activated_at_epoch": activated_at_epoch,
        "activated_by_uid": activated_by_uid,
        "drained_at_epoch": drained_at_epoch,
        "broker_instance_id": broker_instance_id,
        "observed_inflight_submissions": 0,
        "active": 1,
        "proof_sha256": "",
    }
    values["proof_sha256"] = _fingerprint(values)
    return normalize_legacy_test_admission_drain_proof(values)


class TestSubmissionAdmissionGate:
    """In-process side of the durable legacy-submission drain.

    The gate is shared by the broker writer and its store-backed backend.  A
    submit either increments ``active_submissions`` before a drain takes the
    fence, or observes the fence and is rejected.  The broker persists the
    proof only after ``begin_drain`` has observed zero admitted submissions.
    """

    def __init__(self, *, initially_fenced: bool = False) -> None:
        self._condition = threading.Condition(threading.RLock())
        self._accepting = not initially_fenced
        self._active_submissions = 0
        self._activated_at_epoch: int | None = None

    @property
    def fenced(self) -> bool:
        with self._condition:
            return not self._accepting

    @property
    def active_submissions(self) -> int:
        with self._condition:
            return self._active_submissions

    def admit_submission(self) -> bool:
        with self._condition:
            if not self._accepting:
                return False
            self._active_submissions += 1
            return True

    def finish_submission(self) -> None:
        with self._condition:
            self._active_submissions -= 1
            if self._active_submissions < 0:
                raise RuntimeError("test submission admission count underflow")
            self._condition.notify_all()

    def begin_drain(self, *, timeout_seconds: float) -> Mapping[str, int]:
        if timeout_seconds < 0:
            raise ValueError("test admission drain timeout must be non-negative")
        with self._condition:
            if self._accepting:
                self._accepting = False
                self._activated_at_epoch = int(time.time())
            activated = self._activated_at_epoch
            if activated is None:
                # A broker restarted while a durable fence was already active.
                activated = int(time.time())
                self._activated_at_epoch = activated
            drained = self._condition.wait_for(
                lambda: self._active_submissions == 0,
                timeout=timeout_seconds,
            )
            if not drained:
                raise TimeoutError("test submissions did not drain before the deadline")
            return MappingProxyType(
                {
                    "activated_at_epoch": activated,
                    "drained_at_epoch": int(time.time()),
                    "observed_inflight_submissions": 0,
                }
            )

    def resume(self) -> None:
        with self._condition:
            if self._active_submissions != 0:
                raise RuntimeError("cannot resume while test submissions remain active")
            self._accepting = True
            self._activated_at_epoch = None
            self._condition.notify_all()


def install_legacy_test_admission_schema(connection: sqlite3.Connection) -> bool:
    """Install the additive fence table from an explicit offline migration.

    Returns ``True`` only when this call created the table.  The function does
    not commit; callers own the surrounding authority-schema transaction.
    """

    existed = connection.execute(
        """
        SELECT 1 FROM sqlite_master
        WHERE type = 'table' AND name = 'broker_test_admission_fences'
        """
    ).fetchone() is not None
    connection.execute(LEGACY_TEST_ADMISSION_SCHEMA)
    columns = {
        str(row[1]) for row in connection.execute(
            "PRAGMA table_info(broker_test_admission_fences)"
        )
    }
    expected = _FIELDS | {"singleton"}
    if columns != expected:
        raise TestStoreContractError("legacy test admission fence schema is invalid")
    return not existed


def read_legacy_test_admission_drain_proof(
    connection: sqlite3.Connection,
) -> Mapping[str, object] | None:
    table = connection.execute(
        """
        SELECT 1 FROM sqlite_master
        WHERE type = 'table' AND name = 'broker_test_admission_fences'
        """
    ).fetchone()
    if table is None:
        return None
    row = connection.execute(
        """
        SELECT schema_version, purpose, drain_id, authority_generation,
               activated_at_epoch, activated_by_uid, drained_at_epoch,
               broker_instance_id, observed_inflight_submissions,
               active, proof_sha256
        FROM broker_test_admission_fences WHERE singleton = 1
        """
    ).fetchone()
    if row is None:
        return None
    return normalize_legacy_test_admission_drain_proof(dict(row))


def persist_legacy_test_admission_drain_proof(
    connection: sqlite3.Connection,
    *,
    activated_at_epoch: int,
    activated_by_uid: int,
    drained_at_epoch: int,
    broker_instance_id: str,
) -> Mapping[str, object]:
    """Persist and return the one active generation-bound drain proof."""

    existing = read_legacy_test_admission_drain_proof(connection)
    if existing is not None:
        return existing
    table = connection.execute(
        """
        SELECT 1 FROM sqlite_master
        WHERE type = 'table' AND name = 'broker_test_admission_fences'
        """
    ).fetchone()
    if table is None:
        raise TestStoreContractError(
            "legacy test admission schema is not installed; run the offline installer migration"
        )
    generation = connection.execute(
        "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
    ).fetchone()
    if generation is None:
        raise TestStoreContractError("authority database generation is unavailable")
    proof = build_legacy_test_admission_drain_proof(
        drain_id=str(uuid.uuid4()),
        authority_generation=str(generation[0]),
        activated_at_epoch=activated_at_epoch,
        activated_by_uid=activated_by_uid,
        drained_at_epoch=drained_at_epoch,
        broker_instance_id=broker_instance_id,
    )
    connection.execute(
        """
        INSERT INTO broker_test_admission_fences(
            singleton, schema_version, purpose, drain_id,
            authority_generation, activated_at_epoch, activated_by_uid,
            drained_at_epoch, broker_instance_id,
            observed_inflight_submissions, active, proof_sha256
        ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1, ?)
        """,
        (
            proof["schema_version"],
            proof["purpose"],
            proof["drain_id"],
            proof["authority_generation"],
            proof["activated_at_epoch"],
            proof["activated_by_uid"],
            proof["drained_at_epoch"],
            proof["broker_instance_id"],
            proof["proof_sha256"],
        ),
    )
    return proof


def clear_legacy_test_admission_drain_proof(
    connection: sqlite3.Connection,
    *,
    drain_id: str,
    proof_sha256: str,
) -> Mapping[str, object]:
    existing = read_legacy_test_admission_drain_proof(connection)
    if existing is None:
        raise TestStoreContractError("legacy test admission fence is not active")
    if (
        existing["drain_id"] != drain_id
        or existing["proof_sha256"] != proof_sha256
    ):
        raise TestStoreContractError("legacy test admission clear proof is stale")
    deleted = connection.execute(
        """
        DELETE FROM broker_test_admission_fences
        WHERE singleton = 1 AND drain_id = ? AND proof_sha256 = ?
        """,
        (drain_id, proof_sha256),
    ).rowcount
    if deleted != 1:
        raise TestStoreContractError("legacy test admission clear lost its authority race")
    return existing


__all__ = [
    "LEGACY_TEST_ADMISSION_SCHEMA",
    "LEGACY_TEST_DRAIN_PURPOSE",
    "TestSubmissionAdmissionGate",
    "build_legacy_test_admission_drain_proof",
    "clear_legacy_test_admission_drain_proof",
    "install_legacy_test_admission_schema",
    "normalize_legacy_test_admission_drain_proof",
    "persist_legacy_test_admission_drain_proof",
    "read_legacy_test_admission_drain_proof",
    "verify_legacy_test_admission_drain_proof",
]
