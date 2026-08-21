"""Durable broker-authoritative state for supervised local workers.

This module performs no host process work.  A runner may launch or signal an
exact worker only after the broker commits the corresponding transition here.
Crash-loop decisions therefore survive broker and machine restarts and cannot
be inferred from lossy polling observations.
"""

from __future__ import annotations

import math
from pathlib import Path
import re
import sqlite3
import time
from typing import Any, Callable, Mapping

from .server_credentials import (
    ServerCredentialError,
    secret_environment_literal,
    validate_server_credential_bindings,
)
from .store import AccountStore, canonical_json, deterministic_id, fingerprint, utc_timestamp


DEFAULT_CRASH_LIMIT = 10
DEFAULT_CRASH_WINDOW_SECONDS = 300
_MAX_TEXT = 1024
_SHA256 = re.compile(r"(?:sha256:)?[0-9a-f]{64}")
_EXIT_KINDS = frozenset(
    {"exit_code", "signal", "launch_failure", "supervisor_lost", "unknown"}
)


class WorkerSupervisionError(RuntimeError):
    """Base error for durable worker supervision."""


class WorkerSupervisionConflict(WorkerSupervisionError):
    """A request used stale identity or conflicts with current authority."""


class WorkerNotConfigured(WorkerSupervisionError):
    """The exact server definition has no worker policy."""


class WorkerCircuitOpen(WorkerSupervisionError):
    """A tripped worker requires an explicit attributed rearm."""


class WorkerLaunchFenced(WorkerSupervisionError):
    """A reservation was durably cancelled before host launch."""

    def __init__(self, reason: str, attempt: Mapping[str, Any]) -> None:
        self.reason = reason
        self.attempt = dict(attempt)
        super().__init__(f"worker launch is fenced: {reason}")


def _text(name: str, value: object, *, maximum: int = _MAX_TEXT) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be text")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > maximum
        or any(character in normalized for character in "\x00\r\n")
    ):
        raise ValueError(f"{name} must be bounded non-empty single-line text")
    return normalized


def _generation(name: str, value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _positive(name: str, value: object, *, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f"{name} must be an integer from 1 through {maximum}")
    return value


def _boolean(name: str, value: object) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{name} must be a boolean")
    return value


def _artifact(
    artifact: Mapping[str, str] | None,
) -> tuple[str | None, str | None, str | None]:
    if artifact is None:
        return None, None, None
    if not isinstance(artifact, Mapping) or set(artifact) != {
        "artifact_id",
        "path",
        "sha256",
    }:
        raise ValueError("log_artifact must contain artifact_id, path, and sha256")
    artifact_id = _text("log_artifact.artifact_id", artifact["artifact_id"])
    path = _text("log_artifact.path", artifact["path"], maximum=4096)
    if not Path(path).is_absolute():
        raise ValueError("log_artifact.path must be absolute")
    sha256 = _text("log_artifact.sha256", artifact["sha256"])
    if _SHA256.fullmatch(sha256) is None:
        raise ValueError("log_artifact.sha256 must be an exact SHA-256 digest")
    return artifact_id, path, sha256


class WorkerSupervision:
    """Own policy, desired state, fencing tokens, and immutable attempts."""

    def __init__(
        self,
        store: AccountStore,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.store = store
        self._clock = time.time if clock is None else clock

    def _now(self, supplied: float | None = None) -> tuple[float, str]:
        seconds = float(self._clock() if supplied is None else supplied)
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError("worker event time must be a finite non-negative epoch")
        return seconds, utc_timestamp(seconds)

    def configure_policy(
        self,
        *,
        server_definition_id: str,
        actor: str,
        execution_uid: int,
        keep_alive: bool,
        crash_limit: int = DEFAULT_CRASH_LIMIT,
        crash_window_seconds: int = DEFAULT_CRASH_WINDOW_SECONDS,
        expected_generation: int | None = None,
        operation_id: str | None = None,
    ) -> dict[str, Any]:
        """Create or CAS-update the current policy without starting a worker."""

        server_id = _text("server_definition_id", server_definition_id)
        actor = _text("actor", actor)
        if type(execution_uid) is not int or execution_uid < 0:
            raise ValueError("execution_uid must be a non-negative integer")
        keep_alive = _boolean("keep_alive", keep_alive)
        crash_limit = _positive("crash_limit", crash_limit, maximum=1000)
        crash_window_seconds = _positive(
            "crash_window_seconds", crash_window_seconds, maximum=86400
        )
        if expected_generation is not None:
            expected_generation = _generation(
                "expected_generation", expected_generation
            )
        if operation_id is not None:
            operation_id = _text("operation_id", operation_id)
        _, timestamp = self._now()
        with self.store.immediate_transaction() as connection:
            context = self._server_context(connection, server_id)
            if context is None:
                raise WorkerSupervisionConflict("worker server definition does not exist")
            reason = self._fence_reason(connection, context)
            if reason is not None:
                raise WorkerSupervisionConflict(f"worker is fenced: {reason}")
            repo_id = str(context["repo_id"])
            self._require_operation(connection, operation_id, repo_id)
            existing = connection.execute(
                "SELECT * FROM worker_policies WHERE server_definition_id = ?",
                (server_id,),
            ).fetchone()
            if existing is None:
                if expected_generation not in (None, 0):
                    raise WorkerSupervisionConflict(
                        "worker policy generation does not exist"
                    )
                connection.execute(
                    """
                    INSERT INTO worker_policies(
                        server_definition_id, repo_id, execution_uid,
                        keep_alive, desired_state, breaker_state,
                        crash_limit, crash_window_seconds, generation,
                        requested_by, request_operation_id, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'stopped', 'armed', ?, ?, 0, ?, ?, ?, ?)
                    """,
                    (
                        server_id,
                        repo_id,
                        execution_uid,
                        int(keep_alive),
                        crash_limit,
                        crash_window_seconds,
                        actor,
                        operation_id,
                        timestamp,
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO worker_supervisor_states(
                        server_definition_id, repo_id, state,
                        supervisor_generation, updated_at
                    ) VALUES (?, ?, 'stopped', 0, ?)
                    """,
                    (server_id, repo_id, timestamp),
                )
            else:
                current = int(existing["generation"])
                unchanged = (
                    int(existing["execution_uid"]) == execution_uid
                    and bool(existing["keep_alive"]) is keep_alive
                    and int(existing["crash_limit"]) == crash_limit
                    and int(existing["crash_window_seconds"])
                    == crash_window_seconds
                )
                if unchanged:
                    return self._policy_payload(connection, server_id)
                if expected_generation is None or expected_generation != current:
                    raise WorkerSupervisionConflict(
                        f"worker policy generation changed; expected {expected_generation}, current {current}"
                    )
                active = self._active_attempt(connection, server_id)
                if active is not None and (
                    int(existing["execution_uid"]) != execution_uid
                    or int(existing["crash_limit"]) != crash_limit
                    or int(existing["crash_window_seconds"])
                    != crash_window_seconds
                ):
                    raise WorkerSupervisionConflict(
                        "stop the active worker before changing its execution identity or crash limits"
                    )
                changed = connection.execute(
                    """
                    UPDATE worker_policies
                    SET execution_uid = ?, keep_alive = ?, crash_limit = ?,
                        crash_window_seconds = ?, generation = generation + 1,
                        requested_by = ?, request_operation_id = ?, updated_at = ?
                    WHERE server_definition_id = ? AND generation = ?
                    """,
                    (
                        execution_uid,
                        int(keep_alive),
                        crash_limit,
                        crash_window_seconds,
                        actor,
                        operation_id,
                        timestamp,
                        server_id,
                        current,
                    ),
                ).rowcount
                if changed != 1:
                    raise WorkerSupervisionConflict(
                        "worker policy changed during configuration"
                    )
                policy = connection.execute(
                    "SELECT * FROM worker_policies WHERE server_definition_id = ?",
                    (server_id,),
                ).fetchone()
                if active is None:
                    state = self._resting_state(connection, context, policy)
                    connection.execute(
                        """
                        UPDATE worker_supervisor_states
                        SET state = ?, next_restart_at = NULL,
                            last_error_code = NULL, last_error_message = NULL,
                            updated_at = ?
                        WHERE server_definition_id = ?
                        """,
                        (state, timestamp, server_id),
                    )
                else:
                    # Keep-alive is independent from Stop: changing only this
                    # flag leaves the exact current attempt running. Its old
                    # policy token is fenced, so a later exit is traced but can
                    # restart only according to the newly committed flag.
                    connection.execute(
                        """
                        UPDATE worker_supervisor_states
                        SET next_restart_at = NULL, updated_at = ?
                        WHERE server_definition_id = ?
                        """,
                        (timestamp, server_id),
                    )
            return self._policy_payload(connection, server_id)

    def policy(self, server_definition_id: str) -> dict[str, Any]:
        """Return current policy, supervisor token, and recent crash count."""

        server_id = _text("server_definition_id", server_definition_id)
        with self.store.read_transaction() as connection:
            return self._policy_payload(connection, server_id)

    def request_start(
        self,
        *,
        server_definition_id: str,
        actor: str,
        operation_id: str,
        rearm: bool = False,
        expected_generation: int | None = None,
    ) -> dict[str, Any]:
        """Commit desired running state; ``rearm`` is required after a trip."""

        server_id = _text("server_definition_id", server_definition_id)
        actor = _text("actor", actor)
        operation_id = _text("operation_id", operation_id)
        rearm = _boolean("rearm", rearm)
        if expected_generation is not None:
            expected_generation = _generation(
                "expected_generation", expected_generation
            )
        _, timestamp = self._now()
        with self.store.immediate_transaction() as connection:
            context, policy = self._context_and_policy(connection, server_id)
            repo_id = str(context["repo_id"])
            self._require_operation(connection, operation_id, repo_id)
            reason = self._fence_reason(connection, context)
            if reason is not None:
                raise WorkerSupervisionConflict(f"worker is fenced: {reason}")
            generation = int(policy["generation"])
            if expected_generation is not None and expected_generation != generation:
                raise WorkerSupervisionConflict(
                    f"worker policy generation changed; expected {expected_generation}, current {generation}"
                )
            if str(policy["breaker_state"]) == "tripped" and not rearm:
                raise WorkerCircuitOpen(
                    "worker crash circuit is tripped; explicitly rearm after fixing it"
                )
            if rearm and str(policy["breaker_state"]) != "tripped":
                raise WorkerSupervisionConflict(
                    "worker is not tripped and cannot be rearmed"
                )
            active = self._active_attempt(connection, server_id)
            if active is not None:
                if rearm:
                    raise WorkerSupervisionConflict(
                        "cannot rearm while a worker attempt is active"
                    )
                return self._policy_payload(connection, server_id)
            if str(policy["desired_state"]) == "running" and not rearm:
                return self._policy_payload(connection, server_id)
            update = """
                UPDATE worker_policies
                SET desired_state = 'running', breaker_state = 'armed',
                    generation = generation + 1, requested_by = ?,
                    request_operation_id = ?, updated_at = ?
            """
            parameters: list[Any] = [actor, operation_id, timestamp]
            if rearm:
                update += """,
                    last_rearmed_at = ?, last_rearmed_by = ?,
                    last_rearm_operation_id = ?
                """
                parameters.extend([timestamp, actor, operation_id])
            update += " WHERE server_definition_id = ? AND generation = ?"
            parameters.extend([server_id, generation])
            if connection.execute(update, tuple(parameters)).rowcount != 1:
                raise WorkerSupervisionConflict("worker policy changed during start")
            connection.execute(
                """
                UPDATE worker_supervisor_states
                SET state = 'idle', current_attempt_id = NULL,
                    next_restart_at = NULL, last_error_code = NULL,
                    last_error_message = NULL, updated_at = ?
                WHERE server_definition_id = ?
                """,
                (timestamp, server_id),
            )
            self._append_event(
                connection,
                event_id=deterministic_id(
                    "worker-desired-state", operation_id, server_id, "rearm" if rearm else "start"
                ),
                repo_id=repo_id,
                operation_id=operation_id,
                event_kind="worker.rearmed" if rearm else "worker.start_requested",
                code="worker_rearmed" if rearm else "worker_start_requested",
                message=(
                    "Worker explicitly rearmed after crash-loop repair"
                    if rearm
                    else "Worker start requested"
                ),
                diagnostic={
                    "server_definition_id": server_id,
                    "actor": actor,
                    "previous_policy_generation": generation,
                },
                occurred_at=timestamp,
            )
            return self._policy_payload(connection, server_id)

    def request_stop(
        self,
        *,
        server_definition_id: str,
        actor: str,
        operation_id: str,
        expected_generation: int | None = None,
    ) -> dict[str, Any]:
        """Commit desired stopped state before the runner signals a process."""

        server_id = _text("server_definition_id", server_definition_id)
        actor = _text("actor", actor)
        operation_id = _text("operation_id", operation_id)
        if expected_generation is not None:
            expected_generation = _generation(
                "expected_generation", expected_generation
            )
        _, timestamp = self._now()
        with self.store.immediate_transaction() as connection:
            context, policy = self._context_and_policy(connection, server_id)
            repo_id = str(context["repo_id"])
            self._require_operation(connection, operation_id, repo_id)
            generation = int(policy["generation"])
            if expected_generation is not None and expected_generation != generation:
                raise WorkerSupervisionConflict(
                    f"worker policy generation changed; expected {expected_generation}, current {generation}"
                )
            active = self._active_attempt(connection, server_id)
            if str(policy["desired_state"]) == "stopped" and active is None:
                return self._policy_payload(connection, server_id)
            if connection.execute(
                """
                UPDATE worker_policies
                SET desired_state = 'stopped', generation = generation + 1,
                    requested_by = ?, request_operation_id = ?, updated_at = ?
                WHERE server_definition_id = ? AND generation = ?
                """,
                (actor, operation_id, timestamp, server_id, generation),
            ).rowcount != 1:
                raise WorkerSupervisionConflict("worker policy changed during stop")
            connection.execute(
                """
                UPDATE worker_supervisor_states
                SET state = CASE WHEN current_attempt_id IS NULL
                                 THEN 'stopped' ELSE 'stopping' END,
                    next_restart_at = NULL, updated_at = ?
                WHERE server_definition_id = ?
                """,
                (timestamp, server_id),
            )
            self._append_event(
                connection,
                event_id=deterministic_id(
                    "worker-desired-state", operation_id, server_id, "stop"
                ),
                repo_id=repo_id,
                operation_id=operation_id,
                event_kind="worker.stop_requested",
                code="worker_stop_requested",
                message="Worker stop requested",
                diagnostic={
                    "server_definition_id": server_id,
                    "actor": actor,
                    "previous_policy_generation": generation,
                },
                occurred_at=timestamp,
            )
            return self._policy_payload(connection, server_id)

    def fence_startup(self, *, supervisor_epoch: str) -> list[dict[str, Any]]:
        """Fence prior runner generations and return safe keep-alive candidates."""

        epoch = _text("supervisor_epoch", supervisor_epoch)
        _, timestamp = self._now()
        with self.store.immediate_transaction() as connection:
            rows = connection.execute(
                """
                SELECT policy.server_definition_id
                FROM worker_policies policy
                JOIN worker_supervisor_states supervisor USING(server_definition_id)
                ORDER BY policy.server_definition_id
                """
            ).fetchall()
            for row in rows:
                server_id = str(row["server_definition_id"])
                state = connection.execute(
                    "SELECT * FROM worker_supervisor_states WHERE server_definition_id = ?",
                    (server_id,),
                ).fetchone()
                if str(state["supervisor_epoch"] or "") == epoch:
                    continue
                context, policy = self._context_and_policy(connection, server_id)
                if state["current_attempt_id"] is not None:
                    resting = "fenced"
                else:
                    resting = self._resting_state(connection, context, policy)
                connection.execute(
                    """
                    UPDATE worker_supervisor_states
                    SET state = ?, supervisor_epoch = ?,
                        supervisor_generation = supervisor_generation + 1,
                        next_restart_at = NULL, updated_at = ?
                    WHERE server_definition_id = ?
                    """,
                    (resting, epoch, timestamp, server_id),
                )
            return self._startup_candidates(connection, epoch)

    def startup_candidates(
        self, *, supervisor_epoch: str
    ) -> list[dict[str, Any]]:
        """Read workers safe to auto-start under an already-fenced epoch."""

        epoch = _text("supervisor_epoch", supervisor_epoch)
        with self.store.read_transaction() as connection:
            return self._startup_candidates(connection, epoch)

    def normalize_startup_absence(
        self, *, server_definition_id: str, supervisor_epoch: str
    ) -> bool:
        """Make a desired keep-alive worker launchable after proven native absence.

        The caller owns the native-manager proof. This transaction only repairs
        a transient resting label after every old attempt has durably exited;
        it never clears an active attempt, circuit breaker, or lifecycle fence.
        """

        server_id = _text("server_definition_id", server_definition_id)
        epoch = _text("supervisor_epoch", supervisor_epoch)
        _, timestamp = self._now()
        with self.store.immediate_transaction() as connection:
            context, policy = self._context_and_policy(connection, server_id)
            state = connection.execute(
                "SELECT * FROM worker_supervisor_states WHERE server_definition_id = ?",
                (server_id,),
            ).fetchone()
            if state is None or str(state["supervisor_epoch"] or "") != epoch:
                raise WorkerSupervisionConflict(
                    "startup absence proof used the wrong supervisor epoch"
                )
            if state["current_attempt_id"] is not None or self._active_attempt(
                connection, server_id
            ) is not None:
                raise WorkerSupervisionConflict(
                    "startup absence cannot clear an active worker attempt"
                )
            eligible = bool(
                policy["keep_alive"]
                and str(policy["desired_state"]) == "running"
                and str(policy["breaker_state"]) == "armed"
                and self._fence_reason(connection, context) is None
            )
            if not eligible:
                return False
            connection.execute(
                """
                UPDATE worker_supervisor_states
                SET state = 'idle', next_restart_at = NULL,
                    last_error_code = NULL, last_error_message = NULL,
                    updated_at = ?
                WHERE server_definition_id = ? AND supervisor_epoch = ?
                  AND current_attempt_id IS NULL
                """,
                (timestamp, server_id, epoch),
            )
            return True

    def launch_candidate(
        self, *, server_definition_id: str, supervisor_epoch: str
    ) -> dict[str, Any]:
        """Return one exact manually or automatically launchable worker."""

        server_id = _text("server_definition_id", server_definition_id)
        epoch = _text("supervisor_epoch", supervisor_epoch)
        with self.store.read_transaction() as connection:
            return self._launch_candidate(connection, server_id, epoch)

    def begin_attempt(
        self,
        *,
        server_definition_id: str,
        begin_request_id: str,
        supervisor_epoch: str,
        expected_definition_generation: int,
        expected_policy_generation: int,
        expected_supervisor_generation: int,
    ) -> dict[str, Any]:
        """Reserve one launch using exact definition, policy, and runner tokens."""

        server_id = _text("server_definition_id", server_definition_id)
        request_id = _text("begin_request_id", begin_request_id)
        epoch = _text("supervisor_epoch", supervisor_epoch)
        definition_generation = _generation(
            "expected_definition_generation", expected_definition_generation
        )
        policy_generation = _generation(
            "expected_policy_generation", expected_policy_generation
        )
        supervisor_generation = _generation(
            "expected_supervisor_generation", expected_supervisor_generation
        )
        _, timestamp = self._now()
        with self.store.immediate_transaction() as connection:
            replay = connection.execute(
                "SELECT * FROM worker_attempts WHERE begin_request_id = ?",
                (request_id,),
            ).fetchone()
            if replay is not None:
                expected = (
                    server_id,
                    definition_generation,
                    policy_generation,
                    supervisor_generation,
                    epoch,
                )
                actual = (
                    str(replay["server_definition_id"]),
                    int(replay["definition_generation"]),
                    int(replay["policy_generation"]),
                    int(replay["supervisor_generation"]),
                    str(replay["supervisor_epoch"]),
                )
                if actual != expected:
                    raise WorkerSupervisionConflict(
                        "begin_request_id was already used for another worker token"
                    )
                return self._attempt_payload(replay)
            context, policy = self._context_and_policy(connection, server_id)
            reason = self._fence_reason(connection, context)
            if reason is not None:
                raise WorkerSupervisionConflict(f"worker is fenced: {reason}")
            if str(policy["desired_state"]) != "running":
                raise WorkerSupervisionConflict("worker desired state is stopped")
            if str(policy["breaker_state"]) != "armed":
                raise WorkerCircuitOpen("worker crash circuit is tripped")
            state = connection.execute(
                "SELECT * FROM worker_supervisor_states WHERE server_definition_id = ?",
                (server_id,),
            ).fetchone()
            actual_tokens = (
                int(context["definition_generation"]),
                int(policy["generation"]),
                int(state["supervisor_generation"]),
                str(state["supervisor_epoch"] or ""),
            )
            expected_tokens = (
                definition_generation,
                policy_generation,
                supervisor_generation,
                epoch,
            )
            if actual_tokens != expected_tokens:
                raise WorkerSupervisionConflict(
                    "worker definition, policy, or supervisor generation changed"
                )
            if str(state["state"]) not in {"idle", "backoff"}:
                raise WorkerSupervisionConflict(
                    f"worker supervisor is not launchable: {state['state']}"
                )
            if self._active_attempt(connection, server_id) is not None:
                raise WorkerSupervisionConflict("worker already has an active attempt")
            attempt_id = deterministic_id("worker-attempt", server_id, request_id)
            connection.execute(
                """
                INSERT INTO worker_attempts(
                    attempt_id, begin_request_id, server_definition_id, repo_id,
                    definition_generation, policy_generation,
                    supervisor_generation, supervisor_epoch, state,
                    reserved_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?, ?)
                """,
                (
                    attempt_id,
                    request_id,
                    server_id,
                    str(context["repo_id"]),
                    definition_generation,
                    policy_generation,
                    supervisor_generation,
                    epoch,
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )
            if connection.execute(
                """
                UPDATE worker_supervisor_states
                SET state = 'launching', current_attempt_id = ?,
                    last_attempt_id = ?, next_restart_at = NULL,
                    last_error_code = NULL, last_error_message = NULL,
                    updated_at = ?
                WHERE server_definition_id = ?
                  AND supervisor_generation = ? AND supervisor_epoch = ?
                  AND current_attempt_id IS NULL
                """,
                (
                    attempt_id,
                    attempt_id,
                    timestamp,
                    server_id,
                    supervisor_generation,
                    epoch,
                ),
            ).rowcount != 1:
                raise WorkerSupervisionConflict(
                    "worker supervisor changed during attempt reservation"
                )
            return self._attempt_payload(
                connection.execute(
                    "SELECT * FROM worker_attempts WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()
            )

    def mark_attempt_launched(
        self,
        *,
        attempt_id: str,
        launch_report_id: str,
        supervisor_epoch: str,
        supervisor_generation: int,
        pid: int,
        process_start_time: str,
        process_fingerprint: str,
    ) -> dict[str, Any]:
        """Commit exact live process identity, or durably cancel a fenced launch."""

        attempt_id = _text("attempt_id", attempt_id)
        report_id = _text("launch_report_id", launch_report_id)
        epoch = _text("supervisor_epoch", supervisor_epoch)
        supervisor_generation = _generation(
            "supervisor_generation", supervisor_generation
        )
        if type(pid) is not int or pid <= 1:
            raise ValueError("pid must be an integer greater than 1")
        process_start_time = _text("process_start_time", process_start_time)
        process_fingerprint = _text(
            "process_fingerprint", process_fingerprint, maximum=4096
        )
        seconds, timestamp = self._now()
        fenced: tuple[str, dict[str, Any]] | None = None
        with self.store.immediate_transaction() as connection:
            attempt = self._attempt(connection, attempt_id)
            expected_launch = (
                report_id,
                epoch,
                supervisor_generation,
                pid,
                process_start_time,
                process_fingerprint,
            )
            if str(attempt["state"]) in {"running", "exited"}:
                actual_launch = (
                    str(attempt["launch_report_id"] or ""),
                    str(attempt["supervisor_epoch"]),
                    int(attempt["supervisor_generation"]),
                    int(attempt["pid"] or 0),
                    str(attempt["process_start_time"] or ""),
                    str(attempt["process_fingerprint"] or ""),
                )
                if actual_launch == expected_launch:
                    return self._attempt_payload(attempt)
                raise WorkerSupervisionConflict(
                    "attempt already has different launch evidence"
                )
            if str(attempt["supervisor_epoch"]) != epoch or int(
                attempt["supervisor_generation"]
            ) != supervisor_generation:
                raise WorkerSupervisionConflict("launch report used the wrong runner token")
            context = self._server_context(
                connection, str(attempt["server_definition_id"])
            )
            policy = connection.execute(
                "SELECT * FROM worker_policies WHERE server_definition_id = ?",
                (str(attempt["server_definition_id"]),),
            ).fetchone()
            state = connection.execute(
                "SELECT * FROM worker_supervisor_states WHERE server_definition_id = ?",
                (str(attempt["server_definition_id"]),),
            ).fetchone()
            reason = self._launch_fence_reason(
                connection, attempt, context, policy, state
            )
            if reason is not None:
                cancelled = self._finalize_unlaunched(
                    connection,
                    attempt=attempt,
                    exit_report_id=deterministic_id(
                        "worker-launch-fenced", attempt_id, report_id
                    ),
                    classification=(
                        "intentional" if reason == "desired_stopped" else "fenced"
                    ),
                    timestamp=timestamp,
                    seconds=seconds,
                    reason=reason,
                )
                fenced = (reason, cancelled)
            else:
                if connection.execute(
                    """
                    UPDATE worker_attempts
                    SET state = 'running', launch_report_id = ?, pid = ?,
                        process_start_time = ?, process_fingerprint = ?,
                        launched_at = ?, updated_at = ?
                    WHERE attempt_id = ? AND state = 'reserved'
                    """,
                    (
                        report_id,
                        pid,
                        process_start_time,
                        process_fingerprint,
                        timestamp,
                        timestamp,
                        attempt_id,
                    ),
                ).rowcount != 1:
                    raise WorkerSupervisionConflict(
                        "worker attempt changed during launch commit"
                    )
                connection.execute(
                    """
                    UPDATE worker_supervisor_states
                    SET state = 'running', updated_at = ?
                    WHERE server_definition_id = ? AND current_attempt_id = ?
                    """,
                    (timestamp, str(attempt["server_definition_id"]), attempt_id),
                )
                self._record_launched_observation(
                    connection,
                    server_id=str(attempt["server_definition_id"]),
                    pid=pid,
                    process_start_time=process_start_time,
                    process_fingerprint=process_fingerprint,
                    timestamp=timestamp,
                )
                result = self._attempt_payload(
                    connection.execute(
                        "SELECT * FROM worker_attempts WHERE attempt_id = ?",
                        (attempt_id,),
                    ).fetchone()
                )
        if fenced is not None:
            raise WorkerLaunchFenced(fenced[0], fenced[1])
        return result

    def record_attempt_exit(
        self,
        *,
        attempt_id: str,
        exit_report_id: str,
        supervisor_epoch: str,
        supervisor_generation: int,
        exit_kind: str,
        exit_code: int | None = None,
        exit_signal: int | None = None,
        log_artifact: Mapping[str, str] | None = None,
        occurred_at_epoch: float | None = None,
    ) -> dict[str, Any]:
        """Append one idempotent exit and make the inclusive breaker decision."""

        attempt_id = _text("attempt_id", attempt_id)
        report_id = _text("exit_report_id", exit_report_id)
        epoch = _text("supervisor_epoch", supervisor_epoch)
        supervisor_generation = _generation(
            "supervisor_generation", supervisor_generation
        )
        exit_kind = _text("exit_kind", exit_kind)
        if exit_kind not in _EXIT_KINDS:
            raise ValueError("unsupported worker exit_kind")
        if exit_kind == "exit_code":
            if type(exit_code) is not int or exit_signal is not None:
                raise ValueError("exit_code exit requires only an integer exit_code")
        elif exit_kind == "signal":
            if type(exit_signal) is not int or exit_signal <= 0 or exit_code is not None:
                raise ValueError("signal exit requires only a positive integer signal")
        elif exit_code is not None or exit_signal is not None:
            raise ValueError("this exit_kind does not accept exit_code or exit_signal")
        artifact_id, artifact_path, artifact_sha256 = _artifact(log_artifact)
        seconds, timestamp = self._now(occurred_at_epoch)
        semantic_exit = {
            "attempt_id": attempt_id,
            "supervisor_epoch": epoch,
            "supervisor_generation": supervisor_generation,
            "exit_kind": exit_kind,
            "exit_code": exit_code,
            "exit_signal": exit_signal,
            "log_artifact_id": artifact_id,
            "log_artifact_path": artifact_path,
            "log_artifact_sha256": artifact_sha256,
            "exited_at_epoch": seconds,
        }
        exit_fingerprint = "sha256:" + fingerprint(semantic_exit)
        with self.store.immediate_transaction() as connection:
            attempt = self._attempt(connection, attempt_id)
            if str(attempt["supervisor_epoch"]) != epoch or int(
                attempt["supervisor_generation"]
            ) != supervisor_generation:
                raise WorkerSupervisionConflict("exit report used the wrong runner token")
            if (
                str(attempt["state"]) == "exited"
                and str(attempt["exit_report_id"] or "") == report_id
            ):
                replay_fields = (
                    str(attempt["exit_kind"]),
                    attempt["exit_code"],
                    attempt["exit_signal"],
                    attempt["log_artifact_id"],
                    attempt["log_artifact_path"],
                    attempt["log_artifact_sha256"],
                )
                supplied_fields = (
                    exit_kind,
                    exit_code,
                    exit_signal,
                    artifact_id,
                    artifact_path,
                    artifact_sha256,
                )
                same_time = occurred_at_epoch is None or float(
                    attempt["exited_at_epoch"]
                ) == seconds
                if replay_fields == supplied_fields and same_time:
                    return self._exit_payload(connection, attempt)
                raise WorkerSupervisionConflict(
                    "exit_report_id replay changed immutable exit evidence"
                )
            existing_report = connection.execute(
                "SELECT * FROM worker_attempts WHERE exit_report_id = ?",
                (report_id,),
            ).fetchone()
            if existing_report is not None and str(existing_report["attempt_id"]) != attempt_id:
                raise WorkerSupervisionConflict(
                    "exit_report_id was already used for another attempt"
                )
            if str(attempt["state"]) == "exited":
                if str(attempt["exit_fingerprint"]) == exit_fingerprint:
                    return self._exit_payload(connection, attempt)
                raise WorkerSupervisionConflict(
                    "attempt already has different immutable exit evidence"
                )
            if str(attempt["state"]) == "reserved" and exit_kind != "launch_failure":
                raise WorkerSupervisionConflict(
                    "an unlaunched attempt may only report launch_failure"
                )
            server_id = str(attempt["server_definition_id"])
            context = self._server_context(connection, server_id)
            policy = connection.execute(
                "SELECT * FROM worker_policies WHERE server_definition_id = ?",
                (server_id,),
            ).fetchone()
            state = connection.execute(
                "SELECT * FROM worker_supervisor_states WHERE server_definition_id = ?",
                (server_id,),
            ).fetchone()
            classification, expected, counts = self._classify_exit(
                connection, attempt, context, policy, state
            )
            event_id: str | None = None
            if not expected:
                event_id = deterministic_id("worker-crash", attempt_id)
                self._append_event(
                    connection,
                    event_id=event_id,
                    repo_id=str(attempt["repo_id"]),
                    operation_id=None,
                    event_kind="worker.crashed",
                    code=(
                        "worker_crashed"
                        if classification == "crash"
                        else "worker_exit_stale_generation"
                    ),
                    message=(
                        "Worker exited unexpectedly"
                        if classification == "crash"
                        else "Old worker generation exited after being fenced"
                    ),
                    diagnostic={
                        **semantic_exit,
                        "server_definition_id": server_id,
                        "definition_generation": int(
                            attempt["definition_generation"]
                        ),
                        "policy_generation": int(attempt["policy_generation"]),
                        "classification": classification,
                    },
                    occurred_at=timestamp,
                )
            if connection.execute(
                """
                UPDATE worker_attempts
                SET state = 'exited', exit_report_id = ?, exited_at = ?,
                    exited_at_epoch = ?, exit_kind = ?, exit_code = ?,
                    exit_signal = ?, exit_classification = ?,
                    expected_exit = ?, counts_toward_breaker = ?,
                    crash_event_id = ?, log_artifact_id = ?,
                    log_artifact_path = ?, log_artifact_sha256 = ?,
                    exit_fingerprint = ?, updated_at = ?
                WHERE attempt_id = ? AND state IN ('reserved', 'running')
                """,
                (
                    report_id,
                    timestamp,
                    seconds,
                    exit_kind,
                    exit_code,
                    exit_signal,
                    classification,
                    int(expected),
                    int(counts),
                    event_id,
                    artifact_id,
                    artifact_path,
                    artifact_sha256,
                    exit_fingerprint,
                    timestamp,
                    attempt_id,
                ),
            ).rowcount != 1:
                raise WorkerSupervisionConflict(
                    "worker attempt changed during exit commit"
                )
            crash_count = 0
            breaker_tripped = False
            if counts and policy is not None:
                crash_count = int(
                    connection.execute(
                        """
                        SELECT COUNT(*)
                        FROM worker_attempts
                        WHERE server_definition_id = ?
                          AND policy_generation = ?
                          AND counts_toward_breaker = 1
                          AND exited_at_epoch >= ?
                          AND exited_at_epoch <= ?
                        """,
                        (
                            server_id,
                            int(attempt["policy_generation"]),
                            seconds - int(policy["crash_window_seconds"]),
                            seconds,
                        ),
                    ).fetchone()[0]
                )
                if crash_count >= int(policy["crash_limit"]):
                    breaker_tripped = connection.execute(
                        """
                        UPDATE worker_policies
                        SET breaker_state = 'tripped', generation = generation + 1,
                            last_tripped_at = ?, last_trip_reason = ?,
                            last_trip_attempt_id = ?, last_trip_event_id = ?,
                            updated_at = ?
                        WHERE server_definition_id = ?
                          AND generation = ? AND breaker_state = 'armed'
                        """,
                        (
                            timestamp,
                            f"{crash_count} crashes in {int(policy['crash_window_seconds'])} seconds",
                            attempt_id,
                            event_id,
                            timestamp,
                            server_id,
                            int(attempt["policy_generation"]),
                        ),
                    ).rowcount == 1
            current_policy = connection.execute(
                "SELECT * FROM worker_policies WHERE server_definition_id = ?",
                (server_id,),
            ).fetchone()
            self._record_exited_observation(
                connection,
                attempt=attempt,
                classification=classification,
                timestamp=timestamp,
            )
            self._settle_supervisor_after_exit(
                connection,
                attempt=attempt,
                context=context,
                policy=current_policy,
                state=state,
                classification=classification,
                breaker_tripped=breaker_tripped,
                timestamp=timestamp,
            )
            restart_allowed = self._restart_allowed(connection, server_id)
            self._save_exit_decision(
                connection,
                attempt_id=attempt_id,
                server_id=server_id,
                policy_generation=int(attempt["policy_generation"]),
                crash_limit=(None if policy is None else int(policy["crash_limit"])),
                crash_window_seconds=(
                    None if policy is None else int(policy["crash_window_seconds"])
                ),
                crash_count_in_window=crash_count,
                breaker_tripped_now=breaker_tripped,
                restart_allowed=restart_allowed,
                timestamp=timestamp,
            )
            finalized = connection.execute(
                "SELECT * FROM worker_attempts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            payload = self._exit_payload(connection, finalized)
            return payload

    def attempt(self, attempt_id: str) -> dict[str, Any]:
        """Return immutable attempt evidence; useful for runner replay recovery."""

        attempt_id = _text("attempt_id", attempt_id)
        with self.store.read_transaction() as connection:
            return self._exit_payload(connection, self._attempt(connection, attempt_id))

    def _context_and_policy(
        self, connection: sqlite3.Connection, server_id: str
    ) -> tuple[sqlite3.Row, sqlite3.Row]:
        context = self._server_context(connection, server_id)
        if context is None:
            raise WorkerSupervisionConflict("worker server definition does not exist")
        policy = connection.execute(
            "SELECT * FROM worker_policies WHERE server_definition_id = ?",
            (server_id,),
        ).fetchone()
        if policy is None:
            raise WorkerNotConfigured(f"worker {server_id} has no supervision policy")
        return context, policy

    @staticmethod
    def _server_context(
        connection: sqlite3.Connection, server_id: str
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT definition.server_definition_id,
                   definition.repo_id,
                   definition.name,
                   definition.role,
                   definition.cwd,
                   definition.health_url_template,
                   definition.log_path,
                   definition.definition_fingerprint,
                   definition.generation AS definition_generation,
                   repository.host_id,
                   repository.canonical_root,
                   repository.display_name,
                   repository.state AS repository_state,
                   repository.generation AS repository_generation,
                   installation.status AS installation_status,
                   installation.startup_fenced,
                   scope.family_id,
                   scope.project_kind,
                   family.root_repo_id,
                   root.canonical_root AS root_canonical_root,
                   root.display_name AS root_display_name
            FROM server_definitions definition
            LEFT JOIN repositories repository ON repository.repo_id = definition.repo_id
            LEFT JOIN repository_installations installation
              ON installation.repo_id = definition.repo_id
            LEFT JOIN repository_scopes scope ON scope.repo_id = definition.repo_id
            LEFT JOIN repository_families family USING(family_id)
            LEFT JOIN repositories root ON root.repo_id = family.root_repo_id
            WHERE definition.server_definition_id = ?
            """,
            (server_id,),
        ).fetchone()

    @staticmethod
    def _fence_reason(
        connection: sqlite3.Connection, context: sqlite3.Row
    ) -> str | None:
        server_id = str(context["server_definition_id"])
        repo_id = context["repo_id"]
        if repo_id is None:
            return "unclassified_repository"
        if str(context["repository_state"] or "") != "active":
            return "repository_inactive"
        if str(context["installation_status"] or "") != "installed":
            return "repository_not_installed"
        if int(context["startup_fenced"] or 0) != 0:
            return "repository_startup_fenced"
        if context["family_id"] is None or context["root_repo_id"] is None:
            return "repository_scope_unclassified"
        if connection.execute(
            """
            SELECT 1 FROM cleanup_tombstones
            WHERE (target_kind = 'server' AND target_id = ?)
               OR (target_kind = 'project' AND target_id = ?
                   AND target_generation IN (?, ?))
               OR (target_kind = 'worktree' AND target_id = ?)
            LIMIT 1
            """,
            (
                server_id,
                str(repo_id),
                int(context["repository_generation"]) - 1,
                int(context["repository_generation"]),
                str(repo_id),
            ),
        ).fetchone() is not None:
            return "resource_removed"
        if connection.execute(
            """
            SELECT 1 FROM resource_retirements
            WHERE resource_kind = 'server' AND host_resource_id = ?
              AND status IN ('disabling', 'retired')
            LIMIT 1
            """,
            (server_id,),
        ).fetchone() is not None:
            return "resource_archived"
        return None

    def _launch_fence_reason(
        self,
        connection: sqlite3.Connection,
        attempt: sqlite3.Row,
        context: sqlite3.Row | None,
        policy: sqlite3.Row | None,
        state: sqlite3.Row | None,
    ) -> str | None:
        if context is None or policy is None or state is None:
            return "resource_removed"
        if str(policy["desired_state"]) != "running":
            return "desired_stopped"
        reason = self._fence_reason(connection, context)
        if reason is not None:
            return reason
        if str(policy["breaker_state"]) != "armed":
            return "circuit_tripped"
        if (
            int(context["definition_generation"])
            != int(attempt["definition_generation"])
            or int(policy["generation"]) != int(attempt["policy_generation"])
            or int(state["supervisor_generation"])
            != int(attempt["supervisor_generation"])
            or str(state["supervisor_epoch"] or "")
            != str(attempt["supervisor_epoch"])
            or str(state["current_attempt_id"] or "") != str(attempt["attempt_id"])
        ):
            return "stale_generation"
        return None

    @staticmethod
    def _active_attempt(
        connection: sqlite3.Connection, server_id: str
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT * FROM worker_attempts
            WHERE server_definition_id = ? AND state IN ('reserved', 'running')
            """,
            (server_id,),
        ).fetchone()

    @staticmethod
    def _attempt(connection: sqlite3.Connection, attempt_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM worker_attempts WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()
        if row is None:
            raise WorkerSupervisionConflict("worker attempt does not exist")
        return row

    @staticmethod
    def _require_operation(
        connection: sqlite3.Connection, operation_id: str | None, repo_id: str
    ) -> None:
        if operation_id is None:
            return
        operation = connection.execute(
            "SELECT repo_id FROM operations WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if operation is None or str(operation["repo_id"] or "") != repo_id:
            raise WorkerSupervisionConflict(
                "operation does not belong to the worker repository"
            )

    @staticmethod
    def _append_event(
        connection: sqlite3.Connection,
        *,
        event_id: str,
        repo_id: str,
        operation_id: str | None,
        event_kind: str,
        code: str,
        message: str,
        diagnostic: Mapping[str, Any],
        occurred_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT OR IGNORE INTO events(
                event_id, repo_id, source_id, operation_id, event_kind,
                code, message, diagnostic_json, occurred_at
            ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                repo_id,
                operation_id,
                event_kind,
                code,
                message,
                canonical_json(dict(diagnostic)),
                occurred_at,
            ),
        )

    @staticmethod
    def _worker_observation_context(
        connection: sqlite3.Connection, server_id: str
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT observation.*, assignment.port AS assigned_port
            FROM server_definitions definition
            LEFT JOIN server_observations observation
              USING(server_definition_id)
            LEFT JOIN port_assignments assignment
              ON assignment.repo_id = definition.repo_id
             AND assignment.server_name = definition.name
             AND assignment.status = 'active'
            WHERE definition.server_definition_id = ?
            """,
            (server_id,),
        ).fetchone()

    @classmethod
    def _write_worker_observation(
        cls,
        connection: sqlite3.Connection,
        *,
        server_id: str,
        evidence: Mapping[str, Any],
    ) -> None:
        payload = dict(evidence)
        observation_fingerprint = "sha256:" + fingerprint(payload)
        connection.execute(
            """
            INSERT INTO server_observations(
                server_definition_id, source_resource_id, lifecycle, pid,
                process_start_time, process_fingerprint, listener_host,
                listener_port, listener_observable, health_classification,
                health_ok, stopped_at, stopped_reason, sampled_at,
                observation_fingerprint
            ) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(server_definition_id) DO UPDATE SET
                lifecycle = excluded.lifecycle,
                pid = excluded.pid,
                process_start_time = excluded.process_start_time,
                process_fingerprint = excluded.process_fingerprint,
                listener_host = excluded.listener_host,
                listener_port = excluded.listener_port,
                listener_observable = excluded.listener_observable,
                health_classification = excluded.health_classification,
                health_ok = excluded.health_ok,
                stopped_at = excluded.stopped_at,
                stopped_reason = excluded.stopped_reason,
                sampled_at = excluded.sampled_at,
                observation_fingerprint = excluded.observation_fingerprint
            """,
            (
                server_id,
                payload["lifecycle"],
                payload["pid"],
                payload["process_start_time"],
                payload["process_fingerprint"],
                payload["listener_host"],
                payload["listener_port"],
                payload["listener_observable"],
                payload["health_classification"],
                payload["health_ok"],
                payload["stopped_at"],
                payload["stopped_reason"],
                payload["sampled_at"],
                observation_fingerprint,
            ),
        )

    @classmethod
    def _record_launched_observation(
        cls,
        connection: sqlite3.Connection,
        *,
        server_id: str,
        pid: int,
        process_start_time: str,
        process_fingerprint: str,
        timestamp: str,
    ) -> None:
        context = cls._worker_observation_context(connection, server_id)
        if context is None:
            raise WorkerSupervisionConflict(
                "worker definition disappeared before launch observation"
            )
        cls._write_worker_observation(
            connection,
            server_id=server_id,
            evidence={
                "lifecycle": "running",
                "pid": pid,
                "process_start_time": process_start_time,
                "process_fingerprint": process_fingerprint,
                "listener_host": context["listener_host"] or "127.0.0.1",
                "listener_port": (
                    context["listener_port"]
                    if context["listener_port"] is not None
                    else context["assigned_port"]
                ),
                "listener_observable": None,
                "health_classification": "supervised_process_running",
                "health_ok": True,
                "stopped_at": None,
                "stopped_reason": None,
                "sampled_at": timestamp,
            },
        )

    @classmethod
    def _record_exited_observation(
        cls,
        connection: sqlite3.Connection,
        *,
        attempt: sqlite3.Row,
        classification: str,
        timestamp: str,
    ) -> None:
        server_id = str(attempt["server_definition_id"])
        context = cls._worker_observation_context(connection, server_id)
        if context is None:
            return
        if (
            context["pid"] is not None
            and attempt["pid"] is not None
            and (
                int(context["pid"]) != int(attempt["pid"])
                or str(context["process_fingerprint"] or "")
                != str(attempt["process_fingerprint"] or "")
            )
        ):
            return
        reason = (
            "Stopped by attributed request"
            if classification == "intentional"
            else "Worker process exited; inspect the retained attempt log"
        )
        cls._write_worker_observation(
            connection,
            server_id=server_id,
            evidence={
                "lifecycle": "stopped",
                "pid": None,
                "process_start_time": None,
                "process_fingerprint": None,
                "listener_host": context["listener_host"] or "127.0.0.1",
                "listener_port": (
                    context["listener_port"]
                    if context["listener_port"] is not None
                    else context["assigned_port"]
                ),
                "listener_observable": None,
                "health_classification": classification,
                "health_ok": False,
                "stopped_at": timestamp,
                "stopped_reason": reason,
                "sampled_at": timestamp,
            },
        )

    def _resting_state(
        self,
        connection: sqlite3.Connection,
        context: sqlite3.Row,
        policy: sqlite3.Row,
    ) -> str:
        if str(policy["breaker_state"]) == "tripped":
            return "tripped"
        if str(policy["desired_state"]) == "stopped":
            return "stopped"
        if self._fence_reason(connection, context) is not None:
            return "fenced"
        return "idle"

    def _classify_exit(
        self,
        connection: sqlite3.Connection,
        attempt: sqlite3.Row,
        context: sqlite3.Row | None,
        policy: sqlite3.Row | None,
        state: sqlite3.Row | None,
    ) -> tuple[str, bool, bool]:
        if policy is None or context is None:
            return "fenced", True, False
        if str(policy["desired_state"]) == "stopped":
            return "intentional", True, False
        if self._fence_reason(connection, context) is not None:
            return "fenced", True, False
        current = (
            int(context["definition_generation"])
            == int(attempt["definition_generation"])
            and int(policy["generation"]) == int(attempt["policy_generation"])
            and state is not None
            and int(state["supervisor_generation"])
            == int(attempt["supervisor_generation"])
            and str(state["supervisor_epoch"] or "")
            == str(attempt["supervisor_epoch"])
        )
        if not current:
            return "stale_generation", False, False
        return "crash", False, bool(policy["keep_alive"])

    def _finalize_unlaunched(
        self,
        connection: sqlite3.Connection,
        *,
        attempt: sqlite3.Row,
        exit_report_id: str,
        classification: str,
        timestamp: str,
        seconds: float,
        reason: str,
    ) -> dict[str, Any]:
        exit_fingerprint = "sha256:" + fingerprint(
            {
                "attempt_id": str(attempt["attempt_id"]),
                "exit_kind": "launch_failure",
                "classification": classification,
                "reason": reason,
                "exited_at_epoch": seconds,
            }
        )
        connection.execute(
            """
            UPDATE worker_attempts
            SET state = 'exited', exit_report_id = ?, exited_at = ?,
                exited_at_epoch = ?, exit_kind = 'launch_failure',
                exit_classification = ?, expected_exit = 1,
                counts_toward_breaker = 0, exit_fingerprint = ?, updated_at = ?
            WHERE attempt_id = ? AND state = 'reserved'
            """,
            (
                exit_report_id,
                timestamp,
                seconds,
                classification,
                exit_fingerprint,
                timestamp,
                str(attempt["attempt_id"]),
            ),
        )
        connection.execute(
            """
            UPDATE worker_supervisor_states
            SET state = 'fenced', current_attempt_id = NULL,
                last_error_code = 'worker_launch_fenced',
                last_error_message = ?, updated_at = ?
            WHERE server_definition_id = ? AND current_attempt_id = ?
            """,
            (
                reason,
                timestamp,
                str(attempt["server_definition_id"]),
                str(attempt["attempt_id"]),
            ),
        )
        policy = connection.execute(
            "SELECT * FROM worker_policies WHERE server_definition_id = ?",
            (str(attempt["server_definition_id"]),),
        ).fetchone()
        self._save_exit_decision(
            connection,
            attempt_id=str(attempt["attempt_id"]),
            server_id=str(attempt["server_definition_id"]),
            policy_generation=int(attempt["policy_generation"]),
            crash_limit=None if policy is None else int(policy["crash_limit"]),
            crash_window_seconds=(
                None if policy is None else int(policy["crash_window_seconds"])
            ),
            crash_count_in_window=0,
            breaker_tripped_now=False,
            restart_allowed=False,
            timestamp=timestamp,
        )
        return self._attempt_payload(
            connection.execute(
                "SELECT * FROM worker_attempts WHERE attempt_id = ?",
                (str(attempt["attempt_id"]),),
            ).fetchone()
        )

    def _settle_supervisor_after_exit(
        self,
        connection: sqlite3.Connection,
        *,
        attempt: sqlite3.Row,
        context: sqlite3.Row | None,
        policy: sqlite3.Row | None,
        state: sqlite3.Row | None,
        classification: str,
        breaker_tripped: bool,
        timestamp: str,
    ) -> None:
        if state is None or str(state["current_attempt_id"] or "") != str(
            attempt["attempt_id"]
        ):
            return
        if breaker_tripped or (
            policy is not None and str(policy["breaker_state"]) == "tripped"
        ):
            target = "tripped"
            error_code = "worker_crash_loop"
            error_message = "Worker crash circuit is tripped; fix and explicitly rearm"
            restart_at = None
        elif classification == "crash" and policy is not None and bool(
            policy["keep_alive"]
        ):
            target = "backoff"
            error_code = "worker_crashed"
            error_message = "Worker exited unexpectedly; restart is allowed"
            restart_at = timestamp
        elif policy is not None and context is not None:
            target = self._resting_state(connection, context, policy)
            error_code = None
            error_message = None
            restart_at = None
        else:
            target = "fenced"
            error_code = "worker_removed"
            error_message = "Worker authority was removed"
            restart_at = None
        connection.execute(
            """
            UPDATE worker_supervisor_states
            SET state = ?, current_attempt_id = NULL, next_restart_at = ?,
                last_error_code = ?, last_error_message = ?, updated_at = ?
            WHERE server_definition_id = ? AND current_attempt_id = ?
            """,
            (
                target,
                restart_at,
                error_code,
                error_message,
                timestamp,
                str(attempt["server_definition_id"]),
                str(attempt["attempt_id"]),
            ),
        )

    def _restart_allowed(
        self, connection: sqlite3.Connection, server_id: str
    ) -> bool:
        context = self._server_context(connection, server_id)
        policy = connection.execute(
            "SELECT * FROM worker_policies WHERE server_definition_id = ?",
            (server_id,),
        ).fetchone()
        if context is None or policy is None:
            return False
        return bool(
            policy["keep_alive"]
            and str(policy["desired_state"]) == "running"
            and str(policy["breaker_state"]) == "armed"
            and self._fence_reason(connection, context) is None
        )

    def _startup_candidates(
        self, connection: sqlite3.Connection, epoch: str
    ) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        rows = connection.execute(
            """
            SELECT policy.server_definition_id
            FROM worker_policies policy
            JOIN worker_supervisor_states supervisor USING(server_definition_id)
            WHERE policy.keep_alive = 1
              AND policy.desired_state = 'running'
              AND policy.breaker_state = 'armed'
              AND supervisor.supervisor_epoch = ?
              AND supervisor.state IN ('idle', 'backoff')
              AND supervisor.current_attempt_id IS NULL
            ORDER BY policy.repo_id, policy.server_definition_id
            """,
            (epoch,),
        ).fetchall()
        for row in rows:
            server_id = str(row["server_definition_id"])
            try:
                candidates.append(
                    self._launch_candidate(connection, server_id, epoch)
                )
            except WorkerSupervisionError:
                # A lifecycle fence may commit after the initial candidate
                # query.  Omit it rather than leaking a stale launch token.
                continue
        return candidates

    def _launch_candidate(
        self, connection: sqlite3.Connection, server_id: str, epoch: str
    ) -> dict[str, Any]:
        context, policy = self._context_and_policy(connection, server_id)
        reason = self._fence_reason(connection, context)
        if reason is not None:
            raise WorkerSupervisionConflict(f"worker is fenced: {reason}")
        if str(policy["desired_state"]) != "running":
            raise WorkerSupervisionConflict("worker desired state is stopped")
        if str(policy["breaker_state"]) != "armed":
            raise WorkerCircuitOpen("worker crash circuit is tripped")
        supervisor = connection.execute(
            "SELECT * FROM worker_supervisor_states WHERE server_definition_id = ?",
            (server_id,),
        ).fetchone()
        if (
            supervisor is None
            or str(supervisor["supervisor_epoch"] or "") != epoch
            or str(supervisor["state"]) not in {"idle", "backoff"}
            or supervisor["current_attempt_id"] is not None
            or self._active_attempt(connection, server_id) is not None
        ):
            raise WorkerSupervisionConflict(
                "worker is not launchable under this supervisor epoch"
            )
        arguments = tuple(
            str(item["argument"])
            for item in connection.execute(
                """
                SELECT argument FROM server_command_arguments
                WHERE server_definition_id = ? ORDER BY ordinal
                """,
                (server_id,),
            )
        )
        environment = {
            str(item["name"]): str(item["value"])
            for item in connection.execute(
                """
                SELECT name, value FROM server_environment
                WHERE server_definition_id = ? ORDER BY name
                """,
                (server_id,),
            )
        }
        try:
            credential_bindings = validate_server_credential_bindings(
                server_id,
                [
                    {
                        "name": str(item["name"]),
                        "credential_id": str(item["credential_id"]),
                    }
                    for item in connection.execute(
                        """
                        SELECT name, credential_id
                        FROM server_environment_credentials
                        WHERE server_definition_id = ? ORDER BY name
                        """,
                        (server_id,),
                    )
                ],
            )
            if set(environment) & {binding.name for binding in credential_bindings}:
                raise ServerCredentialError(
                    "worker environment duplicates a credential binding"
                )
            if any(
                secret_environment_literal(name, value)
                for name, value in environment.items()
            ):
                raise ServerCredentialError(
                    "worker environment contains a secret literal"
                )
        except ServerCredentialError as error:
            raise WorkerSupervisionConflict(
                str(error)
            ) from error
        return {
            "server_definition_id": server_id,
            "repo_id": str(context["repo_id"]),
            "family_id": str(context["family_id"]),
            "root_repo_id": str(context["root_repo_id"]),
            "project_kind": str(context["project_kind"]),
            "root_repository": str(context["root_canonical_root"]),
            "repository": str(context["canonical_root"]),
            "name": str(context["name"]),
            "cwd": str(context["cwd"]),
            "argv": arguments,
            "environment": environment,
            "credential_bindings": [
                binding.to_document() for binding in credential_bindings
            ],
            "log_path": context["log_path"],
            "execution_uid": int(policy["execution_uid"]),
            "keep_alive": bool(policy["keep_alive"]),
            "definition_fingerprint": str(context["definition_fingerprint"]),
            "definition_generation": int(context["definition_generation"]),
            "policy_generation": int(policy["generation"]),
            "supervisor_epoch": epoch,
            "supervisor_generation": int(supervisor["supervisor_generation"]),
        }

    def _policy_payload(
        self, connection: sqlite3.Connection, server_id: str
    ) -> dict[str, Any]:
        row = connection.execute(
            """
            SELECT policy.*, supervisor.state AS supervisor_state,
                   supervisor.supervisor_epoch,
                   supervisor.supervisor_generation,
                   supervisor.current_attempt_id,
                   supervisor.last_attempt_id,
                   supervisor.next_restart_at,
                   supervisor.last_error_code,
                   supervisor.last_error_message
            FROM worker_policies policy
            JOIN worker_supervisor_states supervisor USING(server_definition_id)
            WHERE policy.server_definition_id = ?
            """,
            (server_id,),
        ).fetchone()
        if row is None:
            raise WorkerNotConfigured(f"worker {server_id} has no supervision policy")
        payload = dict(row)
        payload["keep_alive"] = bool(payload["keep_alive"])
        return payload

    @staticmethod
    def _attempt_payload(row: sqlite3.Row) -> dict[str, Any]:
        payload = dict(row)
        for key in ("expected_exit", "counts_toward_breaker"):
            if payload[key] is not None:
                payload[key] = bool(payload[key])
        payload["log_artifact"] = (
            None
            if payload["log_artifact_id"] is None
            else {
                "artifact_id": payload["log_artifact_id"],
                "path": payload["log_artifact_path"],
                "sha256": payload["log_artifact_sha256"],
            }
        )
        return payload

    def _exit_payload(
        self, connection: sqlite3.Connection, row: sqlite3.Row
    ) -> dict[str, Any]:
        payload = self._attempt_payload(row)
        event_id = payload.get("crash_event_id")
        if event_id is not None:
            event = connection.execute(
                """
                SELECT event_id, event_kind, code, message, occurred_at
                FROM events WHERE event_id = ?
                """,
                (event_id,),
            ).fetchone()
            payload["crash_event"] = None if event is None else dict(event)
        else:
            payload["crash_event"] = None
        if str(payload.get("state") or "") == "exited":
            decision = connection.execute(
                "SELECT * FROM worker_exit_decisions WHERE attempt_id = ?",
                (str(payload["attempt_id"]),),
            ).fetchone()
            if decision is None:
                # Pre-v10 exits have no trustworthy historical acknowledgement.
                # Never reconstruct one from mutable current policy.
                payload.update(
                    {
                        "exit_decision_known": False,
                        "crash_limit": None,
                        "crash_window_seconds": None,
                        "crash_count_in_window": None,
                        "breaker_tripped_now": None,
                        "restart_allowed": False,
                    }
                )
            else:
                payload.update(
                    {
                        "exit_decision_known": True,
                        "crash_limit": decision["crash_limit"],
                        "crash_window_seconds": decision["crash_window_seconds"],
                        "crash_count_in_window": int(
                            decision["crash_count_in_window"]
                        ),
                        "breaker_tripped_now": bool(
                            decision["breaker_tripped_now"]
                        ),
                        "restart_allowed": bool(decision["restart_allowed"]),
                    }
                )
        return payload

    @staticmethod
    def _save_exit_decision(
        connection: sqlite3.Connection,
        *,
        attempt_id: str,
        server_id: str,
        policy_generation: int,
        crash_limit: int | None,
        crash_window_seconds: int | None,
        crash_count_in_window: int,
        breaker_tripped_now: bool,
        restart_allowed: bool,
        timestamp: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO worker_exit_decisions(
                attempt_id, server_definition_id, policy_generation,
                crash_limit, crash_window_seconds, crash_count_in_window,
                breaker_tripped_now, restart_allowed, decided_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                attempt_id,
                server_id,
                policy_generation,
                crash_limit,
                crash_window_seconds,
                crash_count_in_window,
                int(breaker_tripped_now),
                int(restart_allowed),
                timestamp,
            ),
        )


__all__ = [
    "DEFAULT_CRASH_LIMIT",
    "DEFAULT_CRASH_WINDOW_SECONDS",
    "WorkerCircuitOpen",
    "WorkerLaunchFenced",
    "WorkerNotConfigured",
    "WorkerSupervision",
    "WorkerSupervisionConflict",
    "WorkerSupervisionError",
]
