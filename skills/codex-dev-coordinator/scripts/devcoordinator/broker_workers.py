"""Authenticated, replay-safe broker operations for fixed worker runners."""

from __future__ import annotations

import json
from typing import Any, Mapping

from .broker import (
    AuthorizedBrokerRequest,
    BrokerBackendError,
    BrokerError,
    BrokerOperation,
    authenticated_request_fingerprint,
)
from .broker_persistence import BrokerPersistence
from .store import CoordinatorStore, canonical_json, utc_timestamp
from .worker_artifacts import (
    WorkerArtifactError,
    verify_worker_log_artifact,
)
from .worker_supervision import (
    WorkerCircuitOpen,
    WorkerLaunchFenced,
    WorkerNotConfigured,
    WorkerSupervision,
    WorkerSupervisionConflict,
)


WORKER_MUTATION_OPERATIONS = frozenset(
    {
        BrokerOperation.WORKER_LAUNCH_TICKET,
        BrokerOperation.WORKER_LAUNCHED,
        BrokerOperation.WORKER_EXIT,
    }
)
WORKER_READ_OPERATIONS = frozenset(
    {
        BrokerOperation.WORKER_POLICY_READ,
        BrokerOperation.WORKER_ATTEMPT_READ,
    }
)
WORKER_OPERATIONS = WORKER_MUTATION_OPERATIONS | WORKER_READ_OPERATIONS


class BrokerWorkerOperations:
    """Open only the service-owned store and apply durable worker transitions."""

    def __init__(self, persistence: BrokerPersistence) -> None:
        self._persistence = persistence

    def execute(self, authorized: AuthorizedBrokerRequest) -> Mapping[str, Any]:
        request = authorized.request
        if request.operation not in WORKER_OPERATIONS:
            raise ValueError("request is not a worker broker operation")
        # Recheck the live enrollment, exact server ACL, and execution UID at
        # the backend boundary, after transport authorization.
        self._persistence.authorize(authorized.peer, request)
        if request.operation in WORKER_READ_OPERATIONS:
            return self._execute_read(authorized)

        disposition = self._reserve(authorized)
        if disposition["status"] == "succeeded":
            return dict(disposition["result"])
        if disposition["status"] == "failed":
            raise BrokerBackendError(
                str(disposition["error_code"]),
                str(disposition["error_message"]),
                operation_id=request.operation_id,
            )

        try:
            result = self._execute_mutation(
                authorized, prepared=disposition.get("prepared")
            )
        except WorkerNotConfigured as error:
            self._fail(authorized, "worker_not_configured", str(error))
            raise BrokerBackendError(
                "worker_not_configured", str(error), operation_id=request.operation_id
            ) from None
        except WorkerCircuitOpen as error:
            self._fail(authorized, "worker_crash_loop_tripped", str(error))
            raise BrokerBackendError(
                "worker_crash_loop_tripped",
                str(error),
                operation_id=request.operation_id,
            ) from None
        except WorkerLaunchFenced as error:
            self._fail(authorized, "worker_launch_fenced", str(error))
            raise BrokerBackendError(
                "worker_launch_fenced", str(error), operation_id=request.operation_id
            ) from None
        except WorkerSupervisionConflict as error:
            self._fail(authorized, "worker_state_conflict", str(error))
            raise BrokerBackendError(
                "worker_state_conflict", str(error), operation_id=request.operation_id
            ) from None
        except WorkerArtifactError as error:
            self._fail(authorized, "worker_log_artifact_invalid", str(error))
            raise BrokerBackendError(
                "worker_log_artifact_invalid",
                str(error),
                operation_id=request.operation_id,
            ) from None
        except ValueError as error:
            self._fail(authorized, "worker_state_invalid", str(error))
            raise BrokerBackendError(
                "worker_state_invalid", str(error), operation_id=request.operation_id
            ) from None
        except BrokerError as error:
            self._fail(authorized, error.code, error.message)
            raise BrokerBackendError(
                error.code, error.message, operation_id=request.operation_id
            ) from None
        except Exception as error:
            # Leave the durable row running. A retry of the identical request
            # re-enters the idempotent WorkerSupervision transition.
            raise BrokerBackendError(
                "worker_operation_uncertain",
                "The worker transition did not durably settle; retry the identical operation ID.",
                operation_id=request.operation_id,
            ) from error
        try:
            return self._succeed(authorized, result)
        except BrokerError:
            raise
        except Exception as error:
            raise BrokerBackendError(
                "worker_operation_uncertain",
                "The worker transition committed but its broker result did not settle; retry the identical operation ID.",
                operation_id=request.operation_id,
            ) from error

    def _execute_read(
        self, authorized: AuthorizedBrokerRequest
    ) -> Mapping[str, Any]:
        request = authorized.request
        try:
            with self._store() as store:
                supervision = WorkerSupervision(store)
                policy = supervision.policy(request.resource_id)
                self._require_policy_identity(authorized, policy)
                if request.operation is BrokerOperation.WORKER_POLICY_READ:
                    candidate: Mapping[str, Any] | None = None
                    launch_blocker: dict[str, str] | None = None
                    epoch = policy.get("supervisor_epoch")
                    if isinstance(epoch, str) and epoch:
                        try:
                            candidate = supervision.launch_candidate(
                                server_definition_id=request.resource_id,
                                supervisor_epoch=epoch,
                            )
                            self._require_candidate_tokens(authorized, candidate)
                        except WorkerCircuitOpen as error:
                            launch_blocker = {
                                "code": "worker_crash_loop_tripped",
                                "message": str(error),
                            }
                        except WorkerSupervisionConflict as error:
                            launch_blocker = {
                                "code": "worker_not_launchable",
                                "message": str(error),
                            }
                    else:
                        launch_blocker = {
                            "code": "worker_supervisor_uninitialized",
                            "message": "worker supervisor epoch is not initialized",
                        }
                    return {
                        "status": "current",
                        "policy": policy,
                        "candidate": None if candidate is None else dict(candidate),
                        "launch_blocker": launch_blocker,
                    }
                attempt = supervision.attempt(str(request.arguments["attempt_id"]))
                self._require_attempt_identity(authorized, attempt)
                return {"status": "current", "policy": policy, "attempt": attempt}
        except WorkerNotConfigured as error:
            raise BrokerBackendError(
                "worker_not_configured", str(error), operation_id=request.operation_id
            ) from None
        except WorkerSupervisionConflict as error:
            raise BrokerBackendError(
                "worker_state_conflict", str(error), operation_id=request.operation_id
            ) from None

    def _execute_mutation(
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        prepared: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        request = authorized.request
        arguments = request.arguments
        with self._store() as store:
            supervision = WorkerSupervision(store)
            policy = supervision.policy(request.resource_id)
            self._require_policy_identity(authorized, policy)
            if request.operation is BrokerOperation.WORKER_LAUNCH_TICKET:
                expected = (
                    int(arguments["expected_definition_generation"]),
                    int(arguments["expected_policy_generation"]),
                    int(arguments["expected_supervisor_generation"]),
                )
                if prepared is None:
                    candidate = supervision.launch_candidate(
                        server_definition_id=request.resource_id,
                        supervisor_epoch=str(arguments["supervisor_epoch"]),
                    )
                    self._require_candidate_tokens(authorized, candidate)
                    prepared = self._prepare(
                        authorized,
                        {
                            "candidate": {
                                **dict(candidate),
                                "argv": list(candidate["argv"]),
                                "environment": dict(candidate["environment"]),
                            }
                        },
                    )
                candidate = self._prepared_candidate(authorized, prepared)
                self._require_candidate_tokens(authorized, candidate)
                actual = (
                    int(candidate["definition_generation"]),
                    int(candidate["policy_generation"]),
                    int(candidate["supervisor_generation"]),
                    str(candidate["supervisor_epoch"]),
                )
                if (*expected, str(arguments["supervisor_epoch"])) != actual:
                    raise WorkerSupervisionConflict(
                        "worker definition, policy, or supervisor generation changed"
                    )
                attempt = supervision.begin_attempt(
                    server_definition_id=request.resource_id,
                    begin_request_id=request.operation_id,
                    supervisor_epoch=str(arguments["supervisor_epoch"]),
                    expected_definition_generation=expected[0],
                    expected_policy_generation=expected[1],
                    expected_supervisor_generation=expected[2],
                )
                return {
                    "status": "reserved",
                    "operation_id": request.operation_id,
                    "attempt": attempt,
                    "candidate": dict(candidate),
                }

            attempt = supervision.attempt(str(arguments["attempt_id"]))
            self._require_attempt_identity(authorized, attempt)
            if request.operation is BrokerOperation.WORKER_LAUNCHED:
                result = supervision.mark_attempt_launched(
                    attempt_id=str(arguments["attempt_id"]),
                    launch_report_id=request.operation_id,
                    supervisor_epoch=str(arguments["supervisor_epoch"]),
                    supervisor_generation=int(arguments["supervisor_generation"]),
                    pid=int(arguments["pid"]),
                    process_start_time=str(arguments["process_start_time"]),
                    process_fingerprint=str(arguments["process_fingerprint"]),
                )
                return {
                    "status": str(result["state"]),
                    "operation_id": request.operation_id,
                    "attempt": result,
                }

            artifact_request = arguments["log_artifact"]
            artifact = None
            if artifact_request is not None:
                if prepared is None:
                    verified = verify_worker_log_artifact(
                        execution_uid=authorized.peer.uid,
                        artifact_id=str(artifact_request["artifact_id"]),
                        sha256=str(artifact_request["sha256"]),
                    )
                    prepared = self._prepare(
                        authorized, {"log_artifact": verified}
                    )
                artifact = self._prepared_log_artifact(prepared)
                if (
                    artifact["artifact_id"] != artifact_request["artifact_id"]
                    or artifact["sha256"] != artifact_request["sha256"]
                ):
                    raise BrokerBackendError(
                        "operation_evidence_corrupt",
                        "Durable worker log preparation does not match the request.",
                        operation_id=request.operation_id,
                    )
            result = supervision.record_attempt_exit(
                attempt_id=str(arguments["attempt_id"]),
                exit_report_id=request.operation_id,
                supervisor_epoch=str(arguments["supervisor_epoch"]),
                supervisor_generation=int(arguments["supervisor_generation"]),
                exit_kind=str(arguments["exit_kind"]),
                exit_code=arguments["exit_code"],
                exit_signal=arguments["exit_signal"],
                log_artifact=artifact,
                occurred_at_epoch=arguments["occurred_at_epoch"],
            )
            return {
                "status": "exited",
                "operation_id": request.operation_id,
                "attempt": result,
                "restart_allowed": bool(result["restart_allowed"]),
                "breaker_tripped_now": bool(result["breaker_tripped_now"]),
                "crash_count_in_window": int(result["crash_count_in_window"]),
            }

    def _require_policy_identity(
        self, authorized: AuthorizedBrokerRequest, policy: Mapping[str, Any]
    ) -> None:
        request = authorized.request
        if (
            str(policy["server_definition_id"]) != request.resource_id
            or str(policy["repo_id"]) != request.project_id
        ):
            raise WorkerSupervisionConflict(
                "worker policy does not match the exact broker target"
            )
        if int(policy["execution_uid"]) != authorized.peer.uid:
            raise BrokerError(
                "worker_execution_identity_mismatch",
                "The authenticated peer is not this worker's execution identity.",
                operation_id=request.operation_id,
            )

    def _require_candidate_tokens(
        self, authorized: AuthorizedBrokerRequest, candidate: Mapping[str, Any]
    ) -> None:
        request = authorized.request
        if (
            str(candidate["server_definition_id"]) != request.resource_id
            or str(candidate["repo_id"]) != request.project_id
            or int(candidate["execution_uid"]) != authorized.peer.uid
        ):
            raise WorkerSupervisionConflict(
                "worker launch candidate changed exact repository or execution identity"
            )

    @staticmethod
    def _require_attempt_identity(
        authorized: AuthorizedBrokerRequest, attempt: Mapping[str, Any]
    ) -> None:
        request = authorized.request
        if (
            str(attempt["server_definition_id"]) != request.resource_id
            or str(attempt["repo_id"]) != request.project_id
        ):
            raise BrokerError(
                "worker_attempt_access_denied",
                "The attempt does not belong to the exact broker worker target.",
                operation_id=request.operation_id,
            )

    def _reserve(self, authorized: AuthorizedBrokerRequest) -> dict[str, Any]:
        request = authorized.request
        request_fingerprint = authenticated_request_fingerprint(authorized)
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                row = connection.execute(
                    """
                    SELECT * FROM broker_worker_operation_requests
                    WHERE operation_id = ?
                    """,
                    (request.operation_id,),
                ).fetchone()
                if row is None:
                    connection.execute(
                        """
                        INSERT INTO broker_worker_operation_requests(
                            operation_id, uid, account_id, repo_id,
                            server_definition_id, operation,
                            request_fingerprint, status, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'running', ?, ?)
                        """,
                        (
                            request.operation_id,
                            authorized.peer.uid,
                            request.account_id,
                            request.project_id,
                            request.resource_id,
                            request.operation.value,
                            request_fingerprint,
                            now,
                            now,
                        ),
                    )
                    return {"status": "running", "prepared": None}
                identity = (
                    int(row["uid"]),
                    str(row["account_id"]),
                    str(row["repo_id"]),
                    str(row["server_definition_id"]),
                    str(row["operation"]),
                    str(row["request_fingerprint"]),
                )
                expected = (
                    authorized.peer.uid,
                    request.account_id,
                    request.project_id,
                    request.resource_id,
                    request.operation.value,
                    request_fingerprint,
                )
                if identity != expected:
                    raise BrokerError(
                        "operation_id_conflict",
                        "operation_id was already used for a different authenticated worker request.",
                        operation_id=request.operation_id,
                    )
                if str(row["status"]) == "succeeded":
                    result = json.loads(str(row["result_json"]))
                    if not isinstance(result, dict):
                        raise BrokerBackendError(
                            "operation_evidence_corrupt",
                            "Durable worker result evidence is invalid.",
                            operation_id=request.operation_id,
                        )
                    return {"status": "succeeded", "result": result}
                if str(row["status"]) == "failed":
                    return {
                        "status": "failed",
                        "error_code": str(row["error_code"]),
                        "error_message": str(row["error_message"]),
                    }
                prepared: dict[str, Any] | None = None
                if row["prepared_json"] is not None:
                    decoded = json.loads(str(row["prepared_json"]))
                    if not isinstance(decoded, dict):
                        raise BrokerBackendError(
                            "operation_evidence_corrupt",
                            "Durable worker preparation evidence is invalid.",
                            operation_id=request.operation_id,
                        )
                    prepared = decoded
                return {"status": "running", "prepared": prepared}

    def _prepare(
        self,
        authorized: AuthorizedBrokerRequest,
        prepared: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Commit external/pre-transition evidence before mutating worker state."""

        request = authorized.request
        encoded = canonical_json(dict(prepared))
        normalized = json.loads(encoded)
        if not isinstance(normalized, dict):
            raise RuntimeError("worker preparation did not encode as an object")
        with self._store() as store:
            with store.immediate_transaction() as connection:
                row = connection.execute(
                    """
                    SELECT status, prepared_json
                    FROM broker_worker_operation_requests
                    WHERE operation_id = ?
                    """,
                    (request.operation_id,),
                ).fetchone()
                if row is None or str(row["status"]) != "running":
                    raise BrokerError(
                        "operation_id_conflict",
                        "Worker operation is no longer available for preparation.",
                        operation_id=request.operation_id,
                    )
                existing = row["prepared_json"]
                if existing is None:
                    connection.execute(
                        """
                        UPDATE broker_worker_operation_requests
                        SET prepared_json = ?, updated_at = ?
                        WHERE operation_id = ? AND status = 'running'
                          AND prepared_json IS NULL
                        """,
                        (encoded, utc_timestamp(), request.operation_id),
                    )
                else:
                    decoded = json.loads(str(existing))
                    if not isinstance(decoded, dict):
                        raise BrokerBackendError(
                            "operation_evidence_corrupt",
                            "Durable worker preparation evidence is invalid.",
                            operation_id=request.operation_id,
                        )
                    return decoded
                committed = connection.execute(
                    """
                    SELECT status, prepared_json
                    FROM broker_worker_operation_requests
                    WHERE operation_id = ?
                    """,
                    (request.operation_id,),
                ).fetchone()
                if (
                    committed is None
                    or str(committed["status"]) != "running"
                    or str(committed["prepared_json"] or "") != encoded
                ):
                    raise BrokerError(
                        "operation_id_conflict",
                        "Worker operation preparation was not committed exactly once.",
                        operation_id=request.operation_id,
                    )
        return normalized

    @staticmethod
    def _prepared_candidate(
        authorized: AuthorizedBrokerRequest,
        prepared: Mapping[str, Any],
    ) -> dict[str, Any]:
        if set(prepared) != {"candidate"} or not isinstance(
            prepared.get("candidate"), dict
        ):
            raise BrokerBackendError(
                "operation_evidence_corrupt",
                "Durable worker launch preparation is invalid.",
                operation_id=authorized.request.operation_id,
            )
        candidate = dict(prepared["candidate"])
        required = {
            "server_definition_id",
            "repo_id",
            "execution_uid",
            "definition_generation",
            "policy_generation",
            "supervisor_epoch",
            "supervisor_generation",
            "cwd",
            "argv",
            "environment",
        }
        if (
            not required.issubset(candidate)
            or not isinstance(candidate["argv"], list)
            or not isinstance(candidate["environment"], dict)
        ):
            raise BrokerBackendError(
                "operation_evidence_corrupt",
                "Durable worker launch candidate is incomplete.",
                operation_id=authorized.request.operation_id,
            )
        return candidate

    @staticmethod
    def _prepared_log_artifact(prepared: Mapping[str, Any]) -> dict[str, str]:
        artifact = prepared.get("log_artifact")
        if set(prepared) != {"log_artifact"} or not isinstance(artifact, dict):
            raise BrokerBackendError(
                "operation_evidence_corrupt",
                "Durable worker log preparation is invalid.",
            )
        if set(artifact) != {"artifact_id", "path", "sha256"} or any(
            not isinstance(value, str) for value in artifact.values()
        ):
            raise BrokerBackendError(
                "operation_evidence_corrupt",
                "Durable worker log preparation is invalid.",
            )
        return dict(artifact)

    def _succeed(
        self, authorized: AuthorizedBrokerRequest, result: Mapping[str, Any]
    ) -> dict[str, Any]:
        request = authorized.request
        encoded = canonical_json(dict(result))
        with self._store() as store:
            with store.immediate_transaction() as connection:
                row = connection.execute(
                    "SELECT status, result_json FROM broker_worker_operation_requests WHERE operation_id = ?",
                    (request.operation_id,),
                ).fetchone()
                if row is None:
                    raise RuntimeError("durable worker operation reservation disappeared")
                if str(row["status"]) == "succeeded":
                    if str(row["result_json"]) != encoded:
                        raise BrokerError(
                            "operation_id_conflict",
                            "Worker operation replay produced different durable evidence.",
                            operation_id=request.operation_id,
                        )
                    return dict(result)
                if str(row["status"]) != "running":
                    raise BrokerError(
                        "operation_id_conflict",
                        "Worker operation already has a different terminal outcome.",
                        operation_id=request.operation_id,
                    )
                connection.execute(
                    """
                    UPDATE broker_worker_operation_requests
                    SET status = 'succeeded', result_json = ?, updated_at = ?
                    WHERE operation_id = ? AND status = 'running'
                    """,
                    (encoded, utc_timestamp(), request.operation_id),
                )
        return dict(result)

    def _fail(
        self, authorized: AuthorizedBrokerRequest, code: str, message: str
    ) -> None:
        request = authorized.request
        bounded_message = str(message)[:500]
        with self._store() as store:
            with store.immediate_transaction() as connection:
                row = connection.execute(
                    "SELECT status, error_code, error_message FROM broker_worker_operation_requests WHERE operation_id = ?",
                    (request.operation_id,),
                ).fetchone()
                if row is None:
                    raise RuntimeError("durable worker operation reservation disappeared")
                if str(row["status"]) == "failed":
                    if (
                        str(row["error_code"]) != code
                        or str(row["error_message"]) != bounded_message
                    ):
                        raise BrokerError(
                            "operation_id_conflict",
                            "Worker operation replay produced a different durable failure.",
                            operation_id=request.operation_id,
                        )
                    return
                if str(row["status"]) != "running":
                    raise BrokerError(
                        "operation_id_conflict",
                        "Worker operation already has a different terminal outcome.",
                        operation_id=request.operation_id,
                    )
                connection.execute(
                    """
                    UPDATE broker_worker_operation_requests
                    SET status = 'failed', error_code = ?, error_message = ?,
                        updated_at = ?
                    WHERE operation_id = ? AND status = 'running'
                    """,
                    (code, bounded_message, utc_timestamp(), request.operation_id),
                )

    def _store(self) -> CoordinatorStore:
        return CoordinatorStore.open(
            self._persistence.database_path,
            expected_uid=self._persistence.expected_uid,
            busy_timeout_ms=self._persistence.busy_timeout_ms,
        )


__all__ = [
    "BrokerWorkerOperations",
    "WORKER_MUTATION_OPERATIONS",
    "WORKER_OPERATIONS",
    "WORKER_READ_OPERATIONS",
]
