"""Attributed runtime control for durable managed workers.

This layer joins the broker-authoritative policy state to the fixed native
runner.  It never launches a project command itself and never infers a worker
from a process name, port, or argv.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import time
from typing import Any, Callable, Mapping
import uuid

from .store import (
    AccountStore,
    canonical_json,
    deterministic_id,
    fingerprint,
    utc_timestamp,
)
from .worker_native import (
    LaunchdWorkerManager,
    NativeWorkerState,
    SystemdWorkerManager,
    WorkerNativeError,
    native_worker_manager,
)
from .worker_runner import observe_worker_process_identity
from .worker_supervision import (
    DEFAULT_CRASH_LIMIT,
    DEFAULT_CRASH_WINDOW_SECONDS,
    WorkerNotConfigured,
    WorkerSupervision,
    WorkerSupervisionConflict,
)


class WorkerControlError(RuntimeError):
    """An exact worker could not reach the requested durable state."""


class WorkerReplaceError(WorkerControlError):
    """A worker replacement failed with explicit rollback evidence."""

    def __init__(self, message: str, *, payload: Mapping[str, Any]) -> None:
        self.payload = dict(payload)
        super().__init__(message)


ManagerFactory = Callable[..., Any]
ProcessObserver = Callable[[int, str], str]


class WorkerController:
    """Coordinate one exact worker policy with its OS-owned fixed runner."""

    def __init__(
        self,
        store: AccountStore,
        *,
        coordinator_script: Path,
        manager_factory: ManagerFactory = native_worker_manager,
        state_root: Path | None = None,
        execution_uid: int | None = None,
        process_observer: ProcessObserver = observe_worker_process_identity,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.store = store
        self.supervision = WorkerSupervision(store)
        self.coordinator_script = coordinator_script.resolve(strict=True)
        self.manager_factory = manager_factory
        self.state_root = state_root
        current_uid = os.geteuid()
        requested_uid = (
            (None if current_uid == 0 else current_uid)
            if execution_uid is None
            else int(execution_uid)
        )
        if requested_uid is not None and requested_uid <= 0:
            raise WorkerControlError("worker execution UID must identify a non-root account")
        if (
            requested_uid is not None
            and requested_uid != current_uid
            and current_uid != 0
        ):
            raise WorkerControlError(
                "only system authority may control a worker for another UID"
            )
        self.execution_uid = requested_uid
        self.process_observer = process_observer
        self.clock = clock
        self.sleeper = sleeper
        self._manager: Any | None = None

    def status(
        self,
        *,
        worker_id: str,
        canonical_repository: str,
        name: str,
    ) -> dict[str, Any]:
        context = self._context(
            worker_id=worker_id,
            canonical_repository=canonical_repository,
            name=name,
        )
        policy = self._policy_or_none(worker_id)
        native = None
        native_error = None
        if policy is not None:
            try:
                native_state = self._native_status(
                    worker_id=worker_id, uid=int(policy["execution_uid"])
                )
                native = native_state.to_dict()
                self._require_native_isolation(
                    context=context,
                    uid=int(policy["execution_uid"]),
                    native=native_state,
                )
            except BaseException as error:
                native_error = f"{type(error).__name__}: {error}"
        return self._payload(
            context=context,
            policy=policy,
            native=native,
            native_error=native_error,
        )

    def start(
        self,
        *,
        worker_id: str,
        canonical_repository: str,
        name: str,
        actor: str,
        keep_alive: bool | None,
        crash_limit: int | None = None,
        crash_window_seconds: int | None = None,
        rearm: bool = False,
        timeout_seconds: float = 10.0,
    ) -> dict[str, Any]:
        context = self._context(
            worker_id=worker_id,
            canonical_repository=canonical_repository,
            name=name,
        )
        before = self._policy_or_none(worker_id)
        if before is None and keep_alive is None:
            raise WorkerControlError(
                "first supervised worker start requires an explicit keep_alive boolean"
            )
        if before is None and self._observed_process_active(context):
            raise WorkerControlError(
                "the worker is already running outside supervision; stop the exact service through the Coordinator server lifecycle before installing the fixed worker runner"
            )
        operation_id = self._begin_operation(
            context=context,
            actor=actor,
            action="start",
            request={
                "keep_alive": keep_alive,
                "crash_limit": crash_limit,
                "crash_window_seconds": crash_window_seconds,
                "rearm": rearm,
            },
        )
        try:
            policy = self._configure(
                context=context,
                actor=actor,
                operation_id=operation_id,
                existing=before,
                keep_alive=keep_alive,
                crash_limit=crash_limit,
                crash_window_seconds=crash_window_seconds,
            )
            policy = self.supervision.request_start(
                server_definition_id=worker_id,
                actor=actor,
                operation_id=operation_id,
                rearm=rearm,
                expected_generation=int(policy["generation"]),
            )
            self._ensure_epoch(worker_id)
            native_before = self._native_status(
                worker_id=worker_id, uid=int(policy["execution_uid"])
            )
            try:
                self._require_native_isolation(
                    context=context,
                    uid=int(policy["execution_uid"]),
                    native=native_before,
                )
            except WorkerNativeError:
                native_before = self._native_remove(
                    worker_id=worker_id,
                    uid=int(policy["execution_uid"]),
                )
            if not native_before.active:
                native = self._manager_instance().start(
                    worker_id=worker_id,
                    uid=int(policy["execution_uid"]),
                    gid=int(context["execution_gid"]),
                    repository_id=str(context["repo_id"]),
                )
            else:
                native = native_before
            policy = self._wait_for_policy_state(
                worker_id,
                accepted={"running", "backoff", "tripped"},
                timeout_seconds=timeout_seconds,
            )
            if str(policy["supervisor_state"]) != "running":
                raise WorkerControlError(
                    "the native runner did not prove the worker running; inspect the retained attempt log"
                )
            payload = self._payload(
                context=context,
                policy=policy,
                native=native.to_dict(),
                native_error=None,
            )
            self._finish_operation(operation_id, result=payload)
            return payload
        except BaseException as error:
            self._finish_operation(operation_id, error=error)
            raise

    def stop(
        self,
        *,
        worker_id: str,
        canonical_repository: str,
        name: str,
        actor: str,
        timeout_seconds: float = 10.0,
    ) -> dict[str, Any]:
        context = self._context(
            worker_id=worker_id,
            canonical_repository=canonical_repository,
            name=name,
        )
        policy = self._require_policy(worker_id)
        active_attempt = (
            None
            if policy.get("current_attempt_id") is None
            else self.supervision.attempt(str(policy["current_attempt_id"]))
        )
        operation_id = self._begin_operation(
            context=context, actor=actor, action="stop", request={}
        )
        try:
            policy = self.supervision.request_stop(
                server_definition_id=worker_id,
                actor=actor,
                operation_id=operation_id,
                expected_generation=int(policy["generation"]),
            )
            native = self._native_stop(
                worker_id=worker_id, uid=int(policy["execution_uid"])
            )
            if not native.active:
                self._settle_stopped_runner(
                    worker_id=worker_id, evidence_key=operation_id
                )
            policy = self._wait_for_policy_state(
                worker_id,
                accepted={"stopped"},
                timeout_seconds=timeout_seconds,
            )
            terminal_process_proof = self._terminal_process_proof(active_attempt)
            payload = self._payload(
                context=context,
                policy=policy,
                native=native.to_dict(),
                native_error=None,
            )
            payload["terminal_process_proof"] = terminal_process_proof
            self._finish_operation(operation_id, result=payload)
            return payload
        except BaseException as error:
            self._finish_operation(operation_id, error=error)
            raise

    def _terminal_process_proof(
        self, attempt: Mapping[str, Any] | None
    ) -> dict[str, Any]:
        """Prove the exact pre-stop process absent, including PID reuse."""

        if attempt is None or attempt.get("pid") is None:
            return {"certain": True, "state": "not_launched"}
        pid = int(attempt["pid"])
        started = attempt.get("process_start_time")
        if not isinstance(started, str) or not started:
            raise WorkerControlError(
                "stopped service has no immutable pre-stop process identity"
            )
        state = self.process_observer(pid, started)
        if state not in {"absent", "mismatch"}:
            raise WorkerControlError(
                "stopped service process absence is unproven; exact PID identity is "
                + str(state)
            )
        return {
            "certain": True,
            "state": "pid_reused" if state == "mismatch" else "absent",
            "pid": pid,
        }

    def restart(
        self,
        *,
        worker_id: str,
        canonical_repository: str,
        name: str,
        actor: str,
        keep_alive: bool | None,
        crash_limit: int | None = None,
        crash_window_seconds: int | None = None,
        rearm: bool = False,
        timeout_seconds: float = 10.0,
    ) -> dict[str, Any]:
        if self._policy_or_none(worker_id) is not None:
            self.stop(
                worker_id=worker_id,
                canonical_repository=canonical_repository,
                name=name,
                actor=actor,
                timeout_seconds=timeout_seconds,
            )
        return self.start(
            worker_id=worker_id,
            canonical_repository=canonical_repository,
            name=name,
            actor=actor,
            keep_alive=keep_alive,
            crash_limit=crash_limit,
            crash_window_seconds=crash_window_seconds,
            rearm=rearm,
            timeout_seconds=timeout_seconds,
        )

    def replace(
        self,
        *,
        worker_id: str,
        canonical_repository: str,
        name: str,
        actor: str,
        expected_generation: int,
        argv: list[str] | tuple[str, ...],
        cwd: str,
        environment: Mapping[str, str],
        keep_alive: bool | None,
        crash_limit: int | None = None,
        crash_window_seconds: int | None = None,
        rearm: bool = False,
        timeout_seconds: float = 10.0,
    ) -> dict[str, Any]:
        """Replace one stopped, exact worker definition and start it safely.

        Host stop/unregistration and process-absence proof precede the atomic
        definition CAS.  If later policy configuration or launch fails, the
        old definition is restored with another CAS before its prior desired
        state is reconstructed.  Immutable attempts remain as evidence.
        """

        if type(expected_generation) is not int or expected_generation < 0:
            raise WorkerControlError(
                "expected worker definition generation must be a non-negative integer"
            )
        if type(rearm) is not bool:
            raise WorkerControlError("rearm must be a boolean")
        context = self._context(
            worker_id=worker_id,
            canonical_repository=canonical_repository,
            name=name,
        )
        if int(context["generation"]) != expected_generation:
            raise WorkerControlError(
                "worker definition generation changed; "
                f"expected {expected_generation}, current {context['generation']}"
            )
        previous_policy = self._require_policy(worker_id)
        if str(previous_policy["breaker_state"]) == "tripped" and not rearm:
            raise WorkerControlError(
                "worker crash circuit is tripped; replacement requires explicit rearm"
            )
        if rearm and str(previous_policy["breaker_state"]) != "tripped":
            raise WorkerControlError(
                "worker is not tripped and cannot be rearmed during replacement"
            )
        replacement = self._validated_replacement(
            context=context,
            canonical_repository=canonical_repository,
            argv=argv,
            cwd=cwd,
            environment=environment,
        )
        previous_definition = self._definition_snapshot(
            worker_id=worker_id,
            expected_generation=expected_generation,
        )
        native_before = self._native_status(
            worker_id=worker_id, uid=int(previous_policy["execution_uid"])
        )
        operation_id = self._begin_operation(
            context=context,
            actor=actor,
            action="replace",
            request={
                "expected_generation": expected_generation,
                "replacement_fingerprint": replacement["definition_fingerprint"],
                "keep_alive": keep_alive,
                "crash_limit": crash_limit,
                "crash_window_seconds": crash_window_seconds,
                "rearm": rearm,
            },
        )
        definition_mutated = False
        replacement_generation: int | None = None
        absence_proved = False
        try:
            stopped_policy = self.supervision.request_stop(
                server_definition_id=worker_id,
                actor=actor,
                operation_id=operation_id,
                expected_generation=int(previous_policy["generation"]),
            )
            native_removed = self._native_remove(
                worker_id=worker_id,
                uid=int(stopped_policy["execution_uid"]),
            )
            if native_removed.active or native_removed.loaded:
                raise WorkerControlError(
                    "native worker runner remained registered after replacement stop"
                )
            self._settle_stopped_runner(
                worker_id=worker_id, evidence_key=operation_id
            )
            self._wait_for_policy_state(
                worker_id,
                accepted={"stopped"},
                timeout_seconds=timeout_seconds,
            )
            absence_proved = True
            replacement_generation = self._commit_replacement_definition(
                context=context,
                expected_generation=expected_generation,
                replacement=replacement,
            )
            definition_mutated = True
            policy = self._require_policy(worker_id)
            policy = self._configure(
                context=context,
                actor=actor,
                operation_id=operation_id,
                existing=policy,
                keep_alive=keep_alive,
                crash_limit=crash_limit,
                crash_window_seconds=crash_window_seconds,
            )
            policy = self.supervision.request_start(
                server_definition_id=worker_id,
                actor=actor,
                operation_id=operation_id,
                rearm=rearm,
                expected_generation=int(policy["generation"]),
            )
            self._ensure_epoch(worker_id)
            native = self._manager_instance().start(
                worker_id=worker_id,
                uid=int(policy["execution_uid"]),
                gid=int(context["execution_gid"]),
                repository_id=str(context["repo_id"]),
            )
            policy = self._wait_for_policy_state(
                worker_id,
                accepted={"running", "backoff", "tripped"},
                timeout_seconds=timeout_seconds,
            )
            if str(policy["supervisor_state"]) != "running":
                raise WorkerControlError(
                    "replacement runner did not prove the worker running; inspect its retained attempt log"
                )
            current_context = self._context(
                worker_id=worker_id,
                canonical_repository=canonical_repository,
                name=name,
            )
            payload = self._payload(
                context=current_context,
                policy=policy,
                native=native.to_dict(),
                native_error=None,
            )
            payload["replacement"] = {
                "previous_generation": expected_generation,
                "previous_definition_fingerprint": previous_definition[
                    "definition_fingerprint"
                ],
                "generation": replacement_generation,
                "definition_fingerprint": replacement[
                    "definition_fingerprint"
                ],
                "native_registration_replaced": True,
            }
            self._finish_operation(operation_id, result=payload)
            return payload
        except BaseException as error:
            rollback = self._rollback_replacement(
                context=context,
                actor=actor,
                operation_id=operation_id,
                previous_definition=previous_definition,
                previous_policy=previous_policy,
                native_before=native_before,
                definition_mutated=definition_mutated,
                replacement_generation=replacement_generation,
                absence_proved=absence_proved,
                timeout_seconds=timeout_seconds,
            )
            evidence = {
                "ok": False,
                "classification": (
                    "replacement_failed_rolled_back"
                    if rollback["ok"]
                    else "reconciliation_required"
                ),
                "worker_id": worker_id,
                "operation_id": operation_id,
                "replace_error": {
                    "type": type(error).__name__,
                    "message": str(error)[:4096],
                },
                "rollback": rollback,
            }
            wrapped = WorkerReplaceError(
                "worker replacement failed; "
                + (
                    "the previous definition and requested runtime state were restored"
                    if rollback["ok"]
                    else "automatic rollback was incomplete and reconciliation is required"
                ),
                payload=evidence,
            )
            self._finish_operation(operation_id, result=evidence, error=wrapped)
            raise wrapped from error

    def unregister(
        self,
        *,
        worker_id: str,
        canonical_repository: str,
        name: str,
        actor: str,
        timeout_seconds: float = 10.0,
    ) -> dict[str, Any]:
        """Stop a worker and remove its OS auto-start registration.

        This is the host-side preparation for archive or permanent removal.
        Catalog deletion remains a separately planned cleanup transaction.
        """

        context = self._context(
            worker_id=worker_id,
            canonical_repository=canonical_repository,
            name=name,
            allow_inactive=True,
        )
        policy = self._policy_or_none(worker_id)
        operation_id = self._begin_operation(
            context=context, actor=actor, action="unregister", request={}
        )
        try:
            if policy is not None:
                policy = self.supervision.request_stop(
                    server_definition_id=worker_id,
                    actor=actor,
                    operation_id=operation_id,
                    expected_generation=int(policy["generation"]),
                )
            native = self._native_remove(
                worker_id=worker_id, uid=int(context["execution_uid"])
            )
            if policy is not None and not native.active:
                self._settle_stopped_runner(
                    worker_id=worker_id, evidence_key=operation_id
                )
                policy = self._wait_for_policy_state(
                    worker_id,
                    accepted={"stopped"},
                    timeout_seconds=timeout_seconds,
                )
            payload = self._payload(
                context=context,
                policy=policy,
                native=native.to_dict(),
                native_error=None,
            )
            payload.update(
                {
                    "ok": True,
                    "status": "stopped",
                    "native_registration_removed": True,
                }
            )
            self._finish_operation(operation_id, result=payload)
            return payload
        except BaseException as error:
            self._finish_operation(operation_id, error=error)
            raise

    def reconcile_startup(self, *, supervisor_epoch: str) -> dict[str, Any]:
        """Fence the old authority generation, then start safe keep-alive workers."""

        registrations: list[tuple[str, int, str | None]] = []
        with self.store.read_transaction() as connection:
            for row in connection.execute(
                """
                SELECT policy.server_definition_id, policy.execution_uid,
                       supervisor.current_attempt_id
                FROM worker_policies policy
                JOIN worker_supervisor_states supervisor
                  USING(server_definition_id)
                """
            ):
                registrations.append(
                    (
                        str(row["server_definition_id"]),
                        int(row["execution_uid"]),
                        (
                            None
                            if row["current_attempt_id"] is None
                            else str(row["current_attempt_id"])
                        ),
                    )
                )
        self.supervision.fence_startup(supervisor_epoch=supervisor_epoch)
        stopped_old: list[str] = []
        errors: list[dict[str, str]] = []
        for worker_id, uid, attempt_id in registrations:
            try:
                removed = self._native_remove(worker_id=worker_id, uid=uid)
                if removed.loaded or removed.active:
                    raise WorkerControlError(
                        "native worker registration remained after startup fencing"
                    )
                if attempt_id is not None:
                    self._settle_stopped_runner(
                        worker_id=worker_id, evidence_key=supervisor_epoch
                    )
                stopped_old.append(worker_id)
            except BaseException as error:
                errors.append(
                    {
                        "worker_id": worker_id,
                        "phase": "fence_old_runner",
                        "error": f"{type(error).__name__}: {error}",
                    }
                )
        candidates = self.supervision.startup_candidates(
            supervisor_epoch=supervisor_epoch
        )
        started: list[dict[str, Any]] = []
        for candidate in candidates:
            worker_id = str(candidate["server_definition_id"])
            try:
                user = pwd.getpwuid(int(candidate["execution_uid"]))
                native = self._manager_instance().start(
                    worker_id=worker_id,
                    uid=int(candidate["execution_uid"]),
                    gid=int(user.pw_gid),
                    repository_id=str(candidate["repo_id"]),
                )
                started.append(native.to_dict())
            except BaseException as error:
                errors.append(
                    {
                        "worker_id": worker_id,
                        "phase": "autostart",
                        "error": f"{type(error).__name__}: {error}",
                    }
                )
        return {
            "ok": not errors,
            "supervisor_epoch": supervisor_epoch,
            "fenced_old_runners": stopped_old,
            "started": started,
            "errors": errors,
        }

    @staticmethod
    def _validated_replacement(
        *,
        context: Mapping[str, Any],
        canonical_repository: str,
        argv: list[str] | tuple[str, ...],
        cwd: str,
        environment: Mapping[str, str],
    ) -> dict[str, Any]:
        if (
            not isinstance(argv, (list, tuple))
            or not argv
            or len(argv) > 256
            or not all(
                isinstance(argument, str)
                and bool(argument)
                and "\x00" not in argument
                and len(argument.encode("utf-8")) <= 8192
                for argument in argv
            )
            or sum(len(argument.encode("utf-8")) for argument in argv) > 32768
        ):
            raise WorkerControlError(
                "replacement argv must be a bounded non-empty array of NUL-free strings"
            )
        if not isinstance(cwd, str) or not cwd or "\x00" in cwd:
            raise WorkerControlError("replacement cwd must be an absolute directory")
        requested_cwd = Path(cwd).expanduser()
        if not requested_cwd.is_absolute():
            raise WorkerControlError("replacement cwd must be an absolute directory")
        try:
            repository = Path(canonical_repository).resolve(strict=True)
            resolved_cwd = requested_cwd.resolve(strict=True)
        except OSError as error:
            raise WorkerControlError(
                f"replacement cwd could not be resolved: {error}"
            ) from error
        if not repository.is_dir() or not resolved_cwd.is_dir():
            raise WorkerControlError(
                "replacement repository and cwd must be existing directories"
            )
        try:
            resolved_cwd.relative_to(repository)
        except ValueError as error:
            raise WorkerControlError(
                "replacement cwd escapes the exact repository scope"
            ) from error
        if (
            not isinstance(environment, Mapping)
            or len(environment) > 128
            or not all(
                isinstance(key, str)
                and bool(key)
                and "=" not in key
                and "\x00" not in key
                and len(key.encode("utf-8")) <= 256
                and isinstance(value, str)
                and "\x00" not in value
                and len(value.encode("utf-8")) <= 8192
                for key, value in environment.items()
            )
            or sum(
                len(key.encode("utf-8")) + len(value.encode("utf-8"))
                for key, value in environment.items()
            )
            > 32768
        ):
            raise WorkerControlError(
                "replacement environment must be a bounded NUL-free string map"
            )
        normalized_argv = tuple(argv)
        normalized_environment = dict(sorted(environment.items()))
        definition = {
            "name": str(context["name"]),
            "role": "worker",
            "cwd": str(resolved_cwd),
            "argv": list(normalized_argv),
            "environment": normalized_environment,
            "health_url": context.get("health_url_template"),
        }
        return {
            "argv": normalized_argv,
            "cwd": str(resolved_cwd),
            "environment": normalized_environment,
            "definition_fingerprint": "sha256:" + fingerprint(definition),
        }

    def _definition_snapshot(
        self, *, worker_id: str, expected_generation: int
    ) -> dict[str, Any]:
        with self.store.read_transaction() as connection:
            row = connection.execute(
                """
                SELECT server_definition_id, repo_id, name, role, cwd,
                       health_url_template, log_path, definition_fingerprint,
                       generation
                FROM server_definitions
                WHERE server_definition_id = ?
                """,
                (worker_id,),
            ).fetchone()
            if row is None:
                raise WorkerControlError("worker definition disappeared before replacement")
            if int(row["generation"]) != expected_generation:
                raise WorkerControlError(
                    "worker definition generation changed before replacement snapshot"
                )
            arguments = tuple(
                str(item["argument"])
                for item in connection.execute(
                    """
                    SELECT argument FROM server_command_arguments
                    WHERE server_definition_id = ? ORDER BY ordinal
                    """,
                    (worker_id,),
                )
            )
            environment = {
                str(item["name"]): str(item["value"])
                for item in connection.execute(
                    """
                    SELECT name, value FROM server_environment
                    WHERE server_definition_id = ? ORDER BY name
                    """,
                    (worker_id,),
                )
            }
        snapshot = dict(row)
        snapshot["argv"] = arguments
        snapshot["environment"] = environment
        return snapshot

    def _commit_replacement_definition(
        self,
        *,
        context: Mapping[str, Any],
        expected_generation: int,
        replacement: Mapping[str, Any],
    ) -> int:
        worker_id = str(context["server_definition_id"])
        timestamp = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            row = connection.execute(
                """
                SELECT definition.repo_id, definition.name, definition.role,
                       definition.generation,
                       observation.lifecycle AS observed_lifecycle,
                       observation.pid AS observed_pid,
                       supervisor.current_attempt_id
                FROM server_definitions definition
                LEFT JOIN server_observations observation
                  USING(server_definition_id)
                LEFT JOIN worker_supervisor_states supervisor
                  USING(server_definition_id)
                WHERE definition.server_definition_id = ?
                """,
                (worker_id,),
            ).fetchone()
            if row is None:
                raise WorkerControlError("worker definition disappeared during replacement")
            if (
                str(row["repo_id"]) != str(context["repo_id"])
                or str(row["name"]) != str(context["name"])
                or str(row["role"] or "").lower() != "worker"
            ):
                raise WorkerControlError(
                    "worker immutable identity changed during replacement"
                )
            if int(row["generation"]) != expected_generation:
                raise WorkerControlError(
                    "worker definition changed concurrently after its runner was stopped"
                )
            if row["current_attempt_id"] is not None or self._observed_process_active(
                {
                    "observed_pid": row["observed_pid"],
                    "observed_lifecycle": row["observed_lifecycle"],
                }
            ):
                raise WorkerControlError(
                    "worker process absence is unproven; definition replacement was refused"
                )
            changed = connection.execute(
                """
                UPDATE server_definitions
                SET cwd = ?, definition_fingerprint = ?,
                    generation = generation + 1, updated_at = ?
                WHERE server_definition_id = ? AND repo_id = ?
                  AND name = ? AND lower(role) = 'worker' AND generation = ?
                """,
                (
                    str(replacement["cwd"]),
                    str(replacement["definition_fingerprint"]),
                    timestamp,
                    worker_id,
                    str(context["repo_id"]),
                    str(context["name"]),
                    expected_generation,
                ),
            ).rowcount
            if changed != 1:
                raise WorkerControlError(
                    "worker definition changed during atomic replacement"
                )
            connection.execute(
                "DELETE FROM server_command_arguments WHERE server_definition_id = ?",
                (worker_id,),
            )
            connection.executemany(
                """
                INSERT INTO server_command_arguments(
                    server_definition_id, ordinal, argument
                ) VALUES (?, ?, ?)
                """,
                [
                    (worker_id, ordinal, argument)
                    for ordinal, argument in enumerate(replacement["argv"])
                ],
            )
            connection.execute(
                "DELETE FROM server_environment WHERE server_definition_id = ?",
                (worker_id,),
            )
            connection.executemany(
                """
                INSERT INTO server_environment(server_definition_id, name, value)
                VALUES (?, ?, ?)
                """,
                [
                    (worker_id, key, value)
                    for key, value in replacement["environment"].items()
                ],
            )
            connection.execute(
                """
                UPDATE startup_policies
                SET immutable_fingerprint = ?, generation = generation + 1,
                    updated_at = ?
                WHERE resource_kind = 'server' AND resource_id = ?
                """,
                (replacement["definition_fingerprint"], timestamp, worker_id),
            )
            generation = connection.execute(
                """
                SELECT generation FROM server_definitions
                WHERE server_definition_id = ?
                """,
                (worker_id,),
            ).fetchone()
        return int(generation["generation"])

    def _rollback_replacement(
        self,
        *,
        context: Mapping[str, Any],
        actor: str,
        operation_id: str,
        previous_definition: Mapping[str, Any],
        previous_policy: Mapping[str, Any],
        native_before: NativeWorkerState,
        definition_mutated: bool,
        replacement_generation: int | None,
        absence_proved: bool,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        evidence: dict[str, Any] = {
            "ok": False,
            "definition_mutated": definition_mutated,
            "definition_restored": False,
            "policy_restored": False,
            "native_state_restored": False,
            "prior_native_active": bool(native_before.active),
            "prior_native_loaded": bool(native_before.loaded),
            "prior_desired_state": str(previous_policy["desired_state"]),
            "errors": [],
        }
        worker_id = str(context["server_definition_id"])
        if not definition_mutated:
            evidence["errors"].append(
                {
                    "phase": "definition",
                    "message": (
                        "definition was not mutated; concurrent or incomplete stop state "
                        "was left fenced for explicit reconciliation"
                    ),
                }
            )
            return evidence
        try:
            replacement_policy = self._require_policy(worker_id)
            self.supervision.request_stop(
                server_definition_id=worker_id,
                actor=actor,
                operation_id=operation_id,
                expected_generation=int(replacement_policy["generation"]),
            )
            native = self._native_remove(
                worker_id=worker_id, uid=int(previous_policy["execution_uid"])
            )
            if native.active or native.loaded:
                raise WorkerControlError(
                    "replacement native runner absence could not be proved"
                )
            self._settle_stopped_runner(
                worker_id=worker_id, evidence_key=f"{operation_id}-rollback"
            )
            self._wait_for_policy_state(
                worker_id,
                accepted={"stopped", "tripped"},
                timeout_seconds=timeout_seconds,
            )
            absence_proved = True
        except BaseException as error:
            evidence["errors"].append(
                {
                    "phase": "stop_replacement",
                    "type": type(error).__name__,
                    "message": str(error)[:4096],
                }
            )
            absence_proved = False
        if not absence_proved:
            evidence["errors"].append(
                {
                    "phase": "definition_restore",
                    "message": "old definition was not restored while a replacement process might remain",
                }
            )
            return evidence
        try:
            restored_generation = self._restore_definition_snapshot(
                context=context,
                snapshot=previous_definition,
                expected_generation=replacement_generation,
            )
            evidence["definition_restored"] = True
            evidence["restored_generation"] = restored_generation
        except BaseException as error:
            evidence["errors"].append(
                {
                    "phase": "definition_restore",
                    "type": type(error).__name__,
                    "message": str(error)[:4096],
                }
            )
            return evidence
        try:
            self._restore_policy_snapshot(
                worker_id=worker_id,
                actor=actor,
                operation_id=operation_id,
                snapshot=previous_policy,
            )
            evidence["policy_restored"] = True
            should_run = (
                str(previous_policy["desired_state"]) == "running"
                and str(previous_policy["breaker_state"]) == "armed"
            )
            if should_run:
                restored_policy = self._require_policy(worker_id)
                restored_policy = self.supervision.request_start(
                    server_definition_id=worker_id,
                    actor=actor,
                    operation_id=operation_id,
                    rearm=False,
                    expected_generation=int(restored_policy["generation"]),
                )
                self._ensure_epoch(worker_id)
                restored_native = self._manager_instance().start(
                    worker_id=worker_id,
                    uid=int(restored_policy["execution_uid"]),
                    gid=int(context["execution_gid"]),
                    repository_id=str(context["repo_id"]),
                )
                restored_policy = self._wait_for_policy_state(
                    worker_id,
                    accepted={"running"},
                    timeout_seconds=timeout_seconds,
                )
                evidence["restored_native_runner"] = restored_native.to_dict()
                evidence["native_state_restored"] = (
                    str(restored_policy["supervisor_state"]) == "running"
                )
            else:
                evidence["native_state_restored"] = (
                    not native_before.active and not native_before.loaded
                )
                if not evidence["native_state_restored"]:
                    evidence["errors"].append(
                        {
                            "phase": "native_state_restore",
                            "message": (
                                "the prior native registration was present without a "
                                "running desired state and could not be recreated safely"
                            ),
                        }
                    )
            evidence["ok"] = bool(
                evidence["definition_restored"]
                and evidence["policy_restored"]
                and evidence["native_state_restored"]
            )
        except BaseException as error:
            evidence["errors"].append(
                {
                    "phase": "runtime_state_restore",
                    "type": type(error).__name__,
                    "message": str(error)[:4096],
                }
            )
        return evidence

    def _restore_definition_snapshot(
        self,
        *,
        context: Mapping[str, Any],
        snapshot: Mapping[str, Any],
        expected_generation: int | None,
    ) -> int:
        if expected_generation is None:
            raise WorkerControlError(
                "replacement generation is unavailable for definition rollback"
            )
        worker_id = str(context["server_definition_id"])
        timestamp = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            row = connection.execute(
                """
                SELECT definition.repo_id, definition.name, definition.role,
                       definition.generation, observation.lifecycle,
                       observation.pid, supervisor.current_attempt_id
                FROM server_definitions definition
                LEFT JOIN server_observations observation
                  USING(server_definition_id)
                LEFT JOIN worker_supervisor_states supervisor
                  USING(server_definition_id)
                WHERE definition.server_definition_id = ?
                """,
                (worker_id,),
            ).fetchone()
            if row is None:
                raise WorkerControlError("replacement definition disappeared before rollback")
            if int(row["generation"]) != expected_generation:
                raise WorkerControlError(
                    "replacement definition changed concurrently; rollback refused"
                )
            if (
                row["current_attempt_id"] is not None
                or row["pid"] is not None
                or str(row["lifecycle"] or "")
                in {"starting", "running", "unhealthy", "stopping"}
            ):
                raise WorkerControlError(
                    "replacement process absence is unproven; rollback refused"
                )
            changed = connection.execute(
                """
                UPDATE server_definitions
                SET cwd = ?, health_url_template = ?, log_path = ?,
                    definition_fingerprint = ?, generation = generation + 1,
                    updated_at = ?
                WHERE server_definition_id = ? AND repo_id = ? AND name = ?
                  AND lower(role) = 'worker' AND generation = ?
                """,
                (
                    snapshot["cwd"],
                    snapshot["health_url_template"],
                    snapshot["log_path"],
                    snapshot["definition_fingerprint"],
                    timestamp,
                    worker_id,
                    context["repo_id"],
                    context["name"],
                    expected_generation,
                ),
            ).rowcount
            if changed != 1:
                raise WorkerControlError(
                    "worker definition changed during atomic rollback"
                )
            connection.execute(
                "DELETE FROM server_command_arguments WHERE server_definition_id = ?",
                (worker_id,),
            )
            connection.executemany(
                "INSERT INTO server_command_arguments VALUES (?, ?, ?)",
                [
                    (worker_id, ordinal, argument)
                    for ordinal, argument in enumerate(snapshot["argv"])
                ],
            )
            connection.execute(
                "DELETE FROM server_environment WHERE server_definition_id = ?",
                (worker_id,),
            )
            connection.executemany(
                "INSERT INTO server_environment VALUES (?, ?, ?)",
                [
                    (worker_id, key, value)
                    for key, value in snapshot["environment"].items()
                ],
            )
            connection.execute(
                """
                UPDATE startup_policies
                SET immutable_fingerprint = ?, generation = generation + 1,
                    updated_at = ?
                WHERE resource_kind = 'server' AND resource_id = ?
                """,
                (snapshot["definition_fingerprint"], timestamp, worker_id),
            )
            restored = connection.execute(
                "SELECT generation FROM server_definitions WHERE server_definition_id = ?",
                (worker_id,),
            ).fetchone()
        return int(restored["generation"])

    def _restore_policy_snapshot(
        self,
        *,
        worker_id: str,
        actor: str,
        operation_id: str,
        snapshot: Mapping[str, Any],
    ) -> None:
        timestamp = utc_timestamp()
        wants_running = (
            str(snapshot["desired_state"]) == "running"
            and str(snapshot["breaker_state"]) == "armed"
        )
        restored_desired = "stopped" if wants_running else str(
            snapshot["desired_state"]
        )
        restored_state = (
            "tripped" if str(snapshot["breaker_state"]) == "tripped" else "stopped"
        )
        with self.store.immediate_transaction() as connection:
            policy = connection.execute(
                "SELECT generation FROM worker_policies WHERE server_definition_id = ?",
                (worker_id,),
            ).fetchone()
            supervisor = connection.execute(
                """
                SELECT current_attempt_id FROM worker_supervisor_states
                WHERE server_definition_id = ?
                """,
                (worker_id,),
            ).fetchone()
            if policy is None or supervisor is None:
                raise WorkerControlError("worker supervision state disappeared during rollback")
            if supervisor["current_attempt_id"] is not None:
                raise WorkerControlError(
                    "worker attempt remained active during policy rollback"
                )
            changed = connection.execute(
                """
                UPDATE worker_policies
                SET execution_uid = ?, keep_alive = ?, desired_state = ?,
                    breaker_state = ?, crash_limit = ?,
                    crash_window_seconds = ?, generation = generation + 1,
                    requested_by = ?, request_operation_id = ?,
                    last_rearmed_at = ?, last_rearmed_by = ?,
                    last_rearm_operation_id = ?, last_tripped_at = ?,
                    last_trip_reason = ?, last_trip_attempt_id = ?,
                    last_trip_event_id = ?, updated_at = ?
                WHERE server_definition_id = ? AND generation = ?
                """,
                (
                    snapshot["execution_uid"],
                    int(bool(snapshot["keep_alive"])),
                    restored_desired,
                    snapshot["breaker_state"],
                    snapshot["crash_limit"],
                    snapshot["crash_window_seconds"],
                    actor,
                    operation_id,
                    snapshot.get("last_rearmed_at"),
                    snapshot.get("last_rearmed_by"),
                    snapshot.get("last_rearm_operation_id"),
                    snapshot.get("last_tripped_at"),
                    snapshot.get("last_trip_reason"),
                    snapshot.get("last_trip_attempt_id"),
                    snapshot.get("last_trip_event_id"),
                    timestamp,
                    worker_id,
                    int(policy["generation"]),
                ),
            ).rowcount
            if changed != 1:
                raise WorkerControlError("worker policy changed during rollback")
            connection.execute(
                """
                UPDATE worker_supervisor_states
                SET state = ?, current_attempt_id = NULL,
                    next_restart_at = NULL, last_error_code = ?,
                    last_error_message = ?, updated_at = ?
                WHERE server_definition_id = ? AND current_attempt_id IS NULL
                """,
                (
                    restored_state,
                    snapshot.get("last_error_code") if restored_state == "tripped" else None,
                    snapshot.get("last_error_message") if restored_state == "tripped" else None,
                    timestamp,
                    worker_id,
                ),
            )

    def _settle_stopped_runner(self, *, worker_id: str, evidence_key: str) -> None:
        """Close an attempt when the native manager proves its runner absent.

        Normally the runner reports its own final child evidence first. This
        fallback is reserved for a manager-level stop/fence where no runner is
        left to acknowledge; it is still an immutable, non-inferred
        ``supervisor_lost`` trace rather than silent state repair.
        """

        policy = self._require_policy(worker_id)
        attempt_id = policy.get("current_attempt_id")
        if attempt_id is None:
            return
        attempt = self.supervision.attempt(str(attempt_id))
        try:
            self.supervision.record_attempt_exit(
                attempt_id=str(attempt["attempt_id"]),
                exit_report_id=deterministic_id(
                    "worker-native-runner-absent", str(attempt_id), evidence_key
                ),
                supervisor_epoch=str(attempt["supervisor_epoch"]),
                supervisor_generation=int(attempt["supervisor_generation"]),
                exit_kind="supervisor_lost",
            )
        except WorkerSupervisionConflict:
            # A concurrent real runner report may have won the same atomic
            # boundary. It is safe only if that exact attempt is now exited.
            if str(self.supervision.attempt(str(attempt_id))["state"]) != "exited":
                raise

    def _manager_instance(self) -> Any:
        if self._manager is None:
            self._manager = self.manager_factory(
                coordinator_script=self.coordinator_script,
                state_root=self.state_root,
            )
        return self._manager

    def _native_status(self, *, worker_id: str, uid: int) -> NativeWorkerState:
        manager = self._manager_instance()
        if isinstance(manager, LaunchdWorkerManager):
            return manager.status(worker_id=worker_id, uid=uid)
        return manager.status(worker_id=worker_id, allow_missing=True)

    def _require_native_isolation(
        self,
        *,
        context: Mapping[str, Any],
        uid: int,
        native: NativeWorkerState,
    ) -> None:
        manager = self._manager_instance()
        if (
            isinstance(manager, SystemdWorkerManager)
            and native.loaded
        ):
            manager.require_project_isolation(
                worker_id=str(context["server_definition_id"]),
                uid=uid,
                repository_id=str(context["repo_id"]),
            )

    def _native_stop(self, *, worker_id: str, uid: int) -> NativeWorkerState:
        manager = self._manager_instance()
        if isinstance(manager, LaunchdWorkerManager):
            return manager.stop(worker_id=worker_id, uid=uid)
        return manager.stop(worker_id=worker_id)

    def _native_remove(self, *, worker_id: str, uid: int) -> NativeWorkerState:
        manager = self._manager_instance()
        if isinstance(manager, LaunchdWorkerManager):
            return manager.remove(worker_id=worker_id, uid=uid)
        return manager.remove(worker_id=worker_id)

    def _configure(
        self,
        *,
        context: Mapping[str, Any],
        actor: str,
        operation_id: str,
        existing: Mapping[str, Any] | None,
        keep_alive: bool | None,
        crash_limit: int | None,
        crash_window_seconds: int | None,
    ) -> dict[str, Any]:
        effective_keep_alive = (
            bool(existing["keep_alive"])
            if keep_alive is None and existing is not None
            else bool(keep_alive)
        )
        effective_limit = (
            int(existing["crash_limit"])
            if crash_limit is None and existing is not None
            else crash_limit or DEFAULT_CRASH_LIMIT
        )
        effective_window = (
            int(existing["crash_window_seconds"])
            if crash_window_seconds is None and existing is not None
            else crash_window_seconds or DEFAULT_CRASH_WINDOW_SECONDS
        )
        if (
            existing is not None
            and bool(existing["keep_alive"]) == effective_keep_alive
            and int(existing["crash_limit"]) == effective_limit
            and int(existing["crash_window_seconds"]) == effective_window
            and int(existing["execution_uid"]) == int(context["execution_uid"])
        ):
            return dict(existing)
        return self.supervision.configure_policy(
            server_definition_id=str(context["server_definition_id"]),
            actor=actor,
            execution_uid=int(context["execution_uid"]),
            keep_alive=effective_keep_alive,
            crash_limit=effective_limit,
            crash_window_seconds=effective_window,
            expected_generation=(None if existing is None else int(existing["generation"])),
            operation_id=operation_id,
        )

    def _ensure_epoch(self, worker_id: str) -> str:
        policy = self._require_policy(worker_id)
        current = policy.get("supervisor_epoch")
        if isinstance(current, str) and current:
            return current
        with self.store.read_transaction() as connection:
            epochs = {
                str(row[0])
                for row in connection.execute(
                    """
                    SELECT DISTINCT supervisor_epoch FROM worker_supervisor_states
                    WHERE supervisor_epoch IS NOT NULL AND supervisor_epoch != ''
                    """
                )
            }
        if len(epochs) > 1:
            raise WorkerControlError(
                "worker supervisor state contains multiple live epochs; startup reconciliation is required"
            )
        epoch = next(iter(epochs), str(uuid.uuid4()))
        self.supervision.fence_startup(supervisor_epoch=epoch)
        return epoch

    def _policy_or_none(self, worker_id: str) -> dict[str, Any] | None:
        try:
            return self.supervision.policy(worker_id)
        except WorkerNotConfigured:
            return None

    def _require_policy(self, worker_id: str) -> dict[str, Any]:
        policy = self._policy_or_none(worker_id)
        if policy is None:
            raise WorkerControlError("worker has no installed supervision policy")
        return policy

    def _wait_for_policy_state(
        self,
        worker_id: str,
        *,
        accepted: set[str],
        timeout_seconds: float,
    ) -> dict[str, Any]:
        deadline = self.clock() + max(0.05, float(timeout_seconds))
        while True:
            policy = self._require_policy(worker_id)
            if str(policy["supervisor_state"]) in accepted:
                return policy
            if self.clock() >= deadline:
                raise WorkerControlError(
                    "worker state did not reach "
                    + ", ".join(sorted(accepted))
                    + f"; current state is {policy['supervisor_state']}"
                )
            self.sleeper(0.05)

    def _context(
        self,
        *,
        worker_id: str,
        canonical_repository: str,
        name: str,
        allow_inactive: bool = False,
    ) -> dict[str, Any]:
        try:
            canonical_worker_id = str(uuid.UUID(worker_id))
        except (ValueError, TypeError, AttributeError) as error:
            raise WorkerControlError("worker ID must be a canonical UUID") from error
        if canonical_worker_id != worker_id:
            raise WorkerControlError("worker ID must be a canonical UUID")
        with self.store.read_transaction() as connection:
            row = connection.execute(
                """
                SELECT definition.*, repository.canonical_root,
                       repository.state AS repository_state,
                       installation.status AS installation_status,
                       installation.startup_fenced,
                       scope.family_id, scope.project_kind,
                       family.root_repo_id,
                       observation.lifecycle AS observed_lifecycle,
                       observation.pid AS observed_pid
                FROM server_definitions definition
                JOIN repositories repository USING(repo_id)
                JOIN repository_installations installation USING(repo_id)
                JOIN repository_scopes scope USING(repo_id)
                JOIN repository_families family USING(family_id)
                LEFT JOIN server_observations observation
                  USING(server_definition_id)
                WHERE definition.server_definition_id = ?
                  AND repository.host_id = ?
                """,
                (worker_id, self.store.local_host_id()),
            ).fetchone()
        if row is None:
            raise WorkerControlError(
                "worker is not an installed exact resource on this host"
            )
        context = dict(row)
        if str(context["canonical_root"]) != canonical_repository:
            raise WorkerControlError("worker belongs to another repository scope")
        if str(context["name"]) != name:
            raise WorkerControlError("worker name does not match its immutable ID")
        if not allow_inactive and (
            str(context["repository_state"]) != "active"
            or str(context["installation_status"]) != "installed"
            or bool(context["startup_fenced"])
        ):
            raise WorkerControlError(
                "supervised service repository is not installed and startable"
            )
        execution_uid = self.execution_uid
        if execution_uid is None:
            raise WorkerControlError(
                "system worker control requires the authenticated peer execution UID"
            )
        account = pwd.getpwuid(execution_uid)
        context["execution_uid"] = execution_uid
        context["execution_gid"] = int(account.pw_gid)
        return context

    @staticmethod
    def _observed_process_active(context: Mapping[str, Any]) -> bool:
        lifecycle = str(context.get("observed_lifecycle") or "")
        if lifecycle == "stopped":
            return False
        return lifecycle in {
            "starting",
            "running",
            "unhealthy",
            "stopping",
        } or context.get("observed_pid") is not None

    def _begin_operation(
        self,
        *,
        context: Mapping[str, Any],
        actor: str,
        action: str,
        request: Mapping[str, Any],
    ) -> str:
        operation_id = str(uuid.uuid4())
        timestamp = utc_timestamp()
        request_fingerprint = "sha256:" + fingerprint(
            {
                "worker_id": context["server_definition_id"],
                "action": action,
                "actor": actor,
                "request": dict(request),
            }
        )
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO operations(
                    operation_id, repo_id, source_id, kind, status, phase,
                    generation, request_fingerprint, owner_uid, actor,
                    created_at, updated_at
                ) VALUES (?, ?, NULL, ?, 'running', 'policy', 0, ?, ?, ?, ?, ?)
                """,
                (
                    operation_id,
                    str(context["repo_id"]),
                    f"worker.{action}",
                    request_fingerprint,
                    int(context["execution_uid"]),
                    actor,
                    timestamp,
                    timestamp,
                ),
            )
        return operation_id

    def _finish_operation(
        self,
        operation_id: str,
        *,
        result: Mapping[str, Any] | None = None,
        error: BaseException | None = None,
    ) -> None:
        timestamp = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                UPDATE operations
                SET status = ?, phase = ?, result_json = ?, error_code = ?,
                    error_message = ?, updated_at = ?
                WHERE operation_id = ? AND status = 'running'
                """,
                (
                    "succeeded" if error is None else "failed",
                    "complete" if error is None else "failed",
                    None if result is None else canonical_json(dict(result)),
                    None if error is None else type(error).__name__,
                    None if error is None else str(error)[:4096],
                    timestamp,
                    operation_id,
                ),
            )

    def _payload(
        self,
        *,
        context: Mapping[str, Any],
        policy: Mapping[str, Any] | None,
        native: Mapping[str, Any] | None,
        native_error: str | None,
    ) -> dict[str, Any]:
        state = (
            str(policy.get("supervisor_state") or "unconfigured")
            if policy is not None
            else "unconfigured"
        )
        attempt = None
        if policy is not None and policy.get("current_attempt_id") is not None:
            attempt = self.supervision.attempt(str(policy["current_attempt_id"]))
        running = state == "running" and attempt is not None
        return {
            "ok": policy is not None and state in {"running", "stopped"},
            "id": str(context["server_definition_id"]),
            "name": str(context["name"]),
            "project": str(context["canonical_root"]),
            "repo_id": str(context["repo_id"]),
            "root_repo_id": str(context["root_repo_id"]),
            "family_id": str(context["family_id"]),
            "project_kind": str(context["project_kind"]),
            "generation": int(context["generation"]),
            "status": "running" if running else "stopped" if state == "stopped" else state,
            "pid": None if attempt is None else attempt.get("pid"),
            "process_start_time": (
                None if attempt is None else attempt.get("process_start_time")
            ),
            "process_fingerprint": (
                None if attempt is None else attempt.get("process_fingerprint")
            ),
            "health": {
                "ok": bool(running),
                "classification": (
                    "supervised_process_running" if running else state
                ),
            },
            "supervision": None if policy is None else dict(policy),
            "native_runner": None if native is None else dict(native),
            "native_error": native_error,
        }


__all__ = ["WorkerControlError", "WorkerController", "WorkerReplaceError"]
