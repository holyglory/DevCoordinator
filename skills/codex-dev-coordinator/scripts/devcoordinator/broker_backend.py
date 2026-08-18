"""Production store-backed broker mutation routing.

The wire protocol never carries commands or filesystem paths. Most Docker work
is delegated through an exact typed host-action interface after live policy and
state validation. Developer-directed container deletion is deliberately
simpler: one catalog target resolves to a native ID and one fixed forced-remove
command, with no ownership, grant, archive, state, or fingerprint gate.
"""

from __future__ import annotations

import calendar
from dataclasses import dataclass
import hashlib
import logging
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading
import time
from typing import Any, Callable, Mapping, NoReturn, Optional, Protocol
import uuid

from .call_journal import (
    DEFAULT_CALL_JOURNAL_BACKUPS,
    DEFAULT_CALL_JOURNAL_MAX_BYTES,
    RollingCallJournal,
    sanitized_bounded_text,
)
from .capabilities import broker_capabilities, release_digest
from .broker import (
    AcceptedBrokerRequest,
    BrokerBackendError,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    BrokerService,
    BROKER_SHUTDOWN_DRAIN_TIMEOUT_SECONDS,
    PROTOCOL_VERSION,
    SerializedMutationWriter,
    UnixBrokerServer,
    TESTD_INTERNAL_OPERATIONS,
)
from .broker_persistence import (
    BrokerPersistence,
    ComposeMutationTarget,
    ComposeRunOnceMutationTarget,
    DatabaseMutationTarget,
    DockerMutationTarget,
    EphemeralImageTarget,
    RegisteredDatabaseBackup,
    RuntimeDockerMutationTarget,
    RuntimeServiceLogTarget,
    StoreBackedRequestAcceptor,
)
from .universal_test_runtime import (
    BrokerTestAttemptCoordinator,
    NativeTestAttemptManager,
    SystemdTestAttemptManager,
    TestAttemptDescriptor,
    TestAttemptLaunchUncertain,
)
from .universal_test_fixtures import BrokerSealedFixtureProvider
from .universal_test_credentials import (
    BrokerOperationalCredentialProvider,
    DEFAULT_TEST_CREDENTIAL_MATERIAL_ROOT,
    DEFAULT_TEST_CREDENTIAL_REGISTRY_PATH,
    DEFAULT_TEST_CREDENTIAL_RUNTIME_ROOT,
)
from .universal_test_admission import TestSubmissionAdmissionGate
from .broker_configuration import (
    DeclaredComposeConfigurationError,
    DeclaredRuntimeConfigurationError,
    reconcile_declared_compose_first_use,
    reconcile_declared_ephemeral_templates_first_use,
    reconcile_declared_servers_first_use,
    revoke_server_from_protected_profile,
)
from .broker_profile import configured_profile_path
from .broker_runtime import (
    build_broker_runtime_snapshot_report,
    execute_broker_runtime_request,
    load_broker_runtime_snapshot,
    unclassified_broker_runtime_report,
)
from .runtime_ensure import (
    RuntimeEnsureDecision,
    build_runtime_ensure_result,
    decide_runtime_ensure,
    observed_runtime_state,
    worker_result_observation,
)
from .runtime_sessions import (
    next_runtime_cleanup_at,
    reap_expired_runtime_sessions,
)
from .broker_workers import BrokerWorkerOperations, WORKER_OPERATIONS
from .worker_control import WorkerControlError, WorkerController, WorkerReplaceError
from .worker_cleanup import unregister_workers_for_plan
from .runtime_api import validate_runtime_terminal_state
from .temporary_dev_service import (
    TemporaryDevServiceError,
    TemporaryDevServiceManager,
    TemporaryDevServiceRequest,
    public_temporary_dev_service_error,
)
from .schema import SCHEMA_VERSION
from .runtime_artifacts import (
    load_latest_runtime_log_artifact,
    persist_runtime_log_artifact,
    persist_service_log_artifact,
    read_runtime_log_artifact,
)
from .host_lifecycle import CoordinatorHostLifecycleAdapter
from .cleanup_lifecycle import CleanupLifecycle, DockerCleanupBackend
from .observer import observation_owner_scope
from .broker_host import (
    ComposeMutationOutcomeUncertain,
    ComposeRunOnceOutputEvidence,
    EphemeralDockerContainerTarget,
    EphemeralDockerCreateTarget,
    EphemeralDockerIdentity,
    render_compose_effective_model,
)
from .compose_run_once import PublishedReceipt
from .ephemeral_containers import (
    EphemeralContainerCoordinator,
    EphemeralSecretDeliveryLease,
)
from .ephemeral_secrets import (
    EphemeralSecretError,
    SecretGrantExpired,
    SecretGrantNotFound,
    SecretGrantReplay,
    VolatileRunSecretManager,
)
from .observation_freshness import (
    FULL_DOCKER_OBSERVER_DOMAIN,
    ObservationFreshnessError,
    capture_observation_freshness_fence,
    require_exact_fresh_observation,
)
from .lifecycle_cli import (
    _apply_result,
    _confirmed_repository_plan,
    _confirmed_retirement_plan,
    _resource_catalog_contract,
    _repository_execution_plan,
    _require_plan_target_identity_unchanged,
    _require_repository_refresh_matches,
    _require_repository_semantically_unchanged,
    _require_resumable_repository_snapshot,
    _require_retirement_refresh_matches,
    _require_target_semantically_unchanged,
    _retirement_execution_plan,
)
from .repository_lifecycle import (
    ExactResourceRef,
    LifecycleError,
    OperationStatus,
    PlanDriftError,
    RepositoryDecommissionPlan,
    RepositoryLifecycle,
    ResourceKind,
    StandaloneRetirementPlan,
)
from .sqlite_lifecycle import SQLiteLifecyclePersistence
from .store import (
    AccountStore,
    CoordinatorStore,
    StoreError,
    StoreInvariantError,
)
from .test_records import CoordinatorTestRecords
from .universal_test_contract import (
    ManifestContractError,
    SourceMode,
    manifest_to_document,
    parse_test_manifest,
    safe_history_shard_ceiling,
)
from .universal_test_planner import TestPlanError, create_test_plan
from .universal_test_snapshot import public_snapshot_source_diagnostic
from .universal_test_service import (
    TestPlanPreviewUnavailable,
    TestPlaneClient,
    decode_test_plan_document,
    verified_text_artifact_content,
)
from .universal_test_transport import (
    TEST_CATALOG_READ_TIMEOUT_SECONDS,
    TEST_SETUP_READ_TIMEOUT_SECONDS,
    TestPlaneTransportError,
)
from .universal_test_store import (
    TargetResources,
    TestStoreConflict,
    TestStoreContractError,
    TestStoreNotFound,
)


def _test_target_resources(
    value: object, *, selected_targets: tuple[str, ...]
) -> Mapping[str, TargetResources]:
    if not isinstance(value, Mapping) or set(value) != set(selected_targets):
        raise TestStoreContractError("test target resources are incomplete")
    expected = set(TargetResources.__dataclass_fields__)
    result: dict[str, TargetResources] = {}
    for name, raw in value.items():
        if not isinstance(name, str) or not isinstance(raw, Mapping) or set(raw) != expected:
            raise TestStoreContractError("test target resource fields are invalid")
        result[name] = TargetResources(
            cpu_millis=raw["cpu_millis"],
            memory_mib=raw["memory_mib"],
            pids=raw["pids"],
            estimated_seconds=raw["estimated_seconds"],
            shard_count=raw["shard_count"],
            max_attempts=raw["max_attempts"],
            worktree_key=raw["worktree_key"],
            exclusive_resources=tuple(raw["exclusive_resources"]),
        )
    return result


_LIFECYCLE_OPERATIONS = frozenset(
    {
        BrokerOperation.REPOSITORY_PLAN_REMOVE,
        BrokerOperation.REPOSITORY_REMOVE,
        BrokerOperation.REPOSITORY_REINSTALL,
        BrokerOperation.RESOURCE_ATTACH,
        BrokerOperation.RESOURCE_PLAN_RETIRE,
        BrokerOperation.RESOURCE_RETIRE,
        BrokerOperation.RESOURCE_PLAN_ARCHIVE,
        BrokerOperation.RESOURCE_ARCHIVE,
        BrokerOperation.RESOURCE_RESTORE,
    }
)
_LIFECYCLE_PLAN_OPERATIONS = frozenset(
    {
        BrokerOperation.REPOSITORY_PLAN_REMOVE,
        BrokerOperation.RESOURCE_PLAN_RETIRE,
        BrokerOperation.RESOURCE_PLAN_ARCHIVE,
    }
)
_COMPOSE_OPERATIONS = frozenset(
    {
        BrokerOperation.COMPOSE_UP,
        BrokerOperation.COMPOSE_STOP,
        BrokerOperation.COMPOSE_RESTART,
        BrokerOperation.COMPOSE_DOWN,
    }
)
_EPHEMERAL_OPERATIONS = frozenset(
    {
        BrokerOperation.EPHEMERAL_START,
        BrokerOperation.EPHEMERAL_STATUS,
        BrokerOperation.EPHEMERAL_IMAGE_STATUS,
        BrokerOperation.EPHEMERAL_IMAGE_PREFETCH,
        BrokerOperation.EPHEMERAL_RENEW,
        BrokerOperation.EPHEMERAL_FINISH,
    }
)
_FULL_DOCKER_OBSERVER_DOMAIN = FULL_DOCKER_OBSERVER_DOMAIN
_ASYNC_TEST_OPERATIONS = frozenset(
    {
        BrokerOperation.TEST_STATS_READ,
        BrokerOperation.TEST_HEALTH,
        BrokerOperation.TEST_FLEET_STATS_READ,
        BrokerOperation.TEST_PLAN_PREVIEW,
        BrokerOperation.TEST_PLAN_REGISTER,
        BrokerOperation.TEST_RUN_SUBMIT,
        BrokerOperation.TEST_RUN_LIST,
        BrokerOperation.TEST_QUEUE_STATUS,
        BrokerOperation.TEST_RUN_STATUS,
        BrokerOperation.TEST_RUN_SUMMARY,
        BrokerOperation.TEST_RUN_FAILURES,
        BrokerOperation.TEST_RUN_ARTIFACTS,
        BrokerOperation.TEST_ARTIFACT_RESOLVE,
        BrokerOperation.TEST_RUN_CASES,
        BrokerOperation.TEST_RUN_CANCEL,
        BrokerOperation.TEST_RUN_RETRY,
        BrokerOperation.TEST_EVENTS_READ,
        BrokerOperation.TEST_REPOSITORY_SETUP,
        BrokerOperation.TEST_REPOSITORY_CATALOG,
        BrokerOperation.TEST_EVIDENCE_CHECK,
        BrokerOperation.TEST_EVIDENCE_CONSUME,
    }
)
_LOGGER = logging.getLogger(__name__)
_REPOSITORY_ADOPTION_MESSAGE_LIMIT = 512
_SERVICE_ENDPOINT_STARTUP_TIMEOUT_SECONDS = 30.0
_SERVICE_ENDPOINT_POLL_SECONDS = 0.1


def _repository_adoption_message(
    summary: str,
    action: str,
    *,
    cause: BaseException | None = None,
) -> str:
    """Return one bounded, path/credential-redacted adoption diagnostic.

    Recovery precedes the variable cause so truncation can never turn this
    back into the former unhelpful "inspect logs" response.
    """

    message = f"{summary} {action}"
    if cause is not None:
        detail = sanitized_bounded_text(cause, limit=256)
        message += f" Concrete cause: {detail}"
    return sanitized_bounded_text(
        message,
        limit=_REPOSITORY_ADOPTION_MESSAGE_LIMIT,
    )


def _test_contract_diagnostic(error: Exception) -> str:
    """Return one bounded line suitable for agents and operation logs."""

    detail = " ".join(str(error).split()) or type(error).__name__
    return detail[:512]
_TEST_ACTOR_DELEGATION_ACCOUNT = "devcoordinator-api"


def _test_run_actor(accepted: AcceptedBrokerRequest) -> str:
    """Resolve a durable run actor without treating it as request validation.

    The current mutation contract accepts one canonical local ``codex:``
    attribution from any same-developer account. Only the dedicated Console API
    account may forward the ``google:`` identity it already authenticated.
    Broker request validation still derives from exact repository and operation
    identity; this value is display/audit ownership, never an access claim.
    """

    request = accepted.request
    broker_actor = f"broker:{request.account_id}:uid:{accepted.peer.uid}"
    if request.operation not in {
        BrokerOperation.TEST_RUN_SUBMIT,
        BrokerOperation.TEST_RUN_CANCEL,
        BrokerOperation.TEST_RUN_RETRY,
    }:
        return broker_actor
    requested = request.arguments.get("actor")
    if requested is None:
        raise BrokerBackendError(
            "test_actor_invalid",
            "The governed test mutation omitted its canonical actor.",
            operation_id=request.operation_id,
        )
    from .test_actor import TestActorContractError, canonical_test_actor

    try:
        namespace, canonical = canonical_test_actor(requested)
    except TestActorContractError as error:
        raise BrokerBackendError(
            "test_actor_invalid",
            "The test actor is not a canonical codex or delegated Google identity.",
            operation_id=request.operation_id,
        ) from error
    if namespace == "codex":
        return canonical
    if request.account_id != _TEST_ACTOR_DELEGATION_ACCOUNT:
        raise BrokerBackendError(
            "test_google_actor_delegation_denied",
            "Only the protected Console API identity may delegate a test run actor.",
            operation_id=request.operation_id,
        )
    return canonical


def _require_preview_source_policy(
    plan: Any, *, allow_temporary: bool = False
) -> None:
    """Fail closed unless a server-produced preview matches its intent policy."""

    intent = plan.intent
    source = plan.source
    if intent in {"change", "checkpoint"}:
        if (
            source.mode is not SourceMode.LIVE
            or source.temporary_root is not None
            or source.snapshot_id is not None
        ):
            raise TestStoreContractError(
                "change and checkpoint previews must use the canonical live root"
            )
        return
    if intent in {"handoff", "release", "manual"}:
        if source.mode is not SourceMode.IMMUTABLE:
            raise TestStoreContractError(
                "handoff, release, and manual previews must use an immutable snapshot"
            )
    else:
        raise TestStoreContractError("test preview intent is invalid")
    if source.mode is SourceMode.LIVE:
        if (
            source.snapshot_id is not None
            or (source.temporary_root is not None and not allow_temporary)
        ):
            raise TestStoreContractError(
                "live preview source identity is invalid"
            )
        return
    if (
        (source.temporary_root is not None and not allow_temporary)
        or
        not isinstance(source.snapshot_id, str)
        or not source.snapshot_id.startswith("snapshot-")
        or len(source.snapshot_id) != 41
        or any(
            character not in "0123456789abcdef"
            for character in source.snapshot_id[9:]
        )
    ):
        raise TestStoreContractError("immutable preview snapshot identity is invalid")


class TypedHostMutationAPI(Protocol):
    """Exact host actions supplied by the coordinator service implementation."""

    def select_available_port(
        self, *, candidates: tuple[int, ...], protocol: str
    ) -> Optional[int]: ...

    def verify_owned_tcp_listener(
        self, *, port: int, canonical_root: str
    ) -> Mapping[str, Any]: ...

    def docker_start(self, target: DockerMutationTarget) -> Mapping[str, Any]: ...

    def docker_stop(self, target: DockerMutationTarget) -> Mapping[str, Any]: ...

    def docker_restart(self, target: DockerMutationTarget) -> Mapping[str, Any]: ...

    def docker_capture_logs(
        self, target: RuntimeDockerMutationTarget
    ) -> tuple[bytes, int]: ...

    def service_capture_logs(
        self, target: RuntimeServiceLogTarget
    ) -> tuple[bytes, int, str]: ...

    def docker_inspect_ephemeral_image(
        self, target: EphemeralImageTarget
    ) -> Mapping[str, Any]: ...

    def docker_prefetch_ephemeral_image(
        self, target: EphemeralImageTarget
    ) -> Mapping[str, Any]: ...

    def docker_create_ephemeral(
        self, target: EphemeralDockerCreateTarget
    ) -> Mapping[str, Any]: ...

    def docker_find_ephemeral(
        self, identity: EphemeralDockerIdentity
    ) -> Mapping[str, Any]: ...

    def docker_inspect_ephemeral(
        self, target: EphemeralDockerContainerTarget
    ) -> Mapping[str, Any]: ...

    def docker_start_ephemeral(
        self, target: EphemeralDockerContainerTarget
    ) -> Mapping[str, Any]: ...

    def docker_stop_ephemeral(
        self, target: EphemeralDockerContainerTarget
    ) -> Mapping[str, Any]: ...

    def docker_remove_ephemeral(
        self, target: EphemeralDockerContainerTarget
    ) -> Mapping[str, Any]: ...

    def compose_up(self, target: ComposeMutationTarget) -> Mapping[str, Any]: ...

    def compose_stop(self, target: ComposeMutationTarget) -> Mapping[str, Any]: ...

    def compose_restart(self, target: ComposeMutationTarget) -> Mapping[str, Any]: ...

    def compose_down(self, target: ComposeMutationTarget) -> Mapping[str, Any]: ...

    def compose_run_once_bind_image(
        self, target: ComposeRunOnceMutationTarget
    ) -> Mapping[str, Any]: ...

    def compose_run_once_find_container(
        self, target: ComposeRunOnceMutationTarget
    ) -> Mapping[str, Any] | None: ...

    def compose_run_once_create_container(
        self, target: ComposeRunOnceMutationTarget
    ) -> Mapping[str, Any]: ...

    def compose_run_once_inspect_container(
        self,
        target: ComposeRunOnceMutationTarget,
        *,
        full_container_id: str | None = None,
    ) -> Mapping[str, Any]: ...

    def compose_run_once_start_container(
        self, target: ComposeRunOnceMutationTarget
    ) -> Mapping[str, Any]: ...

    def compose_run_once_wait_container(
        self,
        target: ComposeRunOnceMutationTarget,
        *,
        timeout_seconds: float,
    ) -> Mapping[str, Any]: ...

    def compose_run_once_stop_container(
        self, target: ComposeRunOnceMutationTarget
    ) -> Mapping[str, Any]: ...

    def compose_run_once_capture_evidence(
        self, target: ComposeRunOnceMutationTarget
    ) -> ComposeRunOnceOutputEvidence: ...

    def compose_run_once_remove_container(
        self, target: ComposeRunOnceMutationTarget
    ) -> Mapping[str, Any]: ...

    def postgres_backup(
        self, target: DatabaseMutationTarget, *, output_root: str
    ) -> Mapping[str, Any]: ...

    def postgres_restore(
        self,
        target: DatabaseMutationTarget,
        backup: RegisteredDatabaseBackup,
        *, safety_output_root: str,
    ) -> Mapping[str, Any]: ...

    def postgres_reconcile_restore(
        self,
        target: DatabaseMutationTarget,
        backup: RegisteredDatabaseBackup,
        *,
        safety_output_root: str,
    ) -> Mapping[str, Any] | None: ...


class StoreBackedMutationBackend:
    """Durable broker backend with no client-controlled command boundary."""

    def __init__(
        self,
        persistence: BrokerPersistence,
        host_mutations: TypedHostMutationAPI,
        lifecycle_adapter: CoordinatorHostLifecycleAdapter | None = None,
        observe_before_lifecycle_plan: Callable[
            [AccountStore], Mapping[str, Any]
        ]
        | None = None,
        secret_manager: VolatileRunSecretManager | None = None,
        test_plane: TestPlaneClient | None = None,
        test_attempt_manager: NativeTestAttemptManager | None = None,
        test_submission_gate: TestSubmissionAdmissionGate | None = None,
        temporary_dev_services: TemporaryDevServiceManager | None = None,
        container_remover: Callable[[str], Mapping[str, Any]] | None = None,
    ) -> None:
        self._persistence = persistence
        self._host_mutations = host_mutations
        self._lifecycle_adapter = lifecycle_adapter or CoordinatorHostLifecycleAdapter()
        self._observe_before_lifecycle_plan = observe_before_lifecycle_plan
        self._host_observation_shutdown = threading.Event()
        self._runtime_session_mutation_lock = threading.RLock()
        self._runtime_reaper_stop = threading.Event()
        self._runtime_reaper_wake = threading.Event()
        self._runtime_reaper_thread: threading.Thread | None = None
        self._broker_instance_id = "broker-" + uuid.uuid4().hex
        self._secret_manager = secret_manager or VolatileRunSecretManager(
            expected_uid=persistence.expected_uid
        )
        self._ephemeral = EphemeralContainerCoordinator(
            persistence, host_mutations, secret_manager=self._secret_manager
        )
        self._worker_operations = BrokerWorkerOperations(persistence)
        self._test_plane = test_plane
        self._test_submission_gate = (
            test_submission_gate or TestSubmissionAdmissionGate()
        )
        self._temporary_dev_services = (
            temporary_dev_services or TemporaryDevServiceManager()
        )
        self._container_remover = (
            container_remover or DockerCleanupBackend().remove
        )
        self._test_attempts = (
            None
            if test_attempt_manager is None
            else BrokerTestAttemptCoordinator(test_attempt_manager)
        )
        provider = (
            getattr(test_attempt_manager, "fixture_provider", None)
            if test_attempt_manager is not None
            else None
        )
        self._test_fixture_provider = (
            provider if isinstance(provider, BrokerSealedFixtureProvider) else None
        )
        self._postgres_backup_root = _private_postgres_backup_root(
            persistence.database_path, expected_uid=persistence.expected_uid
        )
        self._runtime_log_root = _private_runtime_log_root(
            persistence.database_path, expected_uid=persistence.expected_uid
        )
        self._test_records = CoordinatorTestRecords(
            persistence.database_path,
            expected_uid=persistence.expected_uid,
            busy_timeout_ms=persistence.busy_timeout_ms,
        )

    def _retire_database_backup_files(
        self, backup: RegisteredDatabaseBackup
    ) -> dict[str, Any]:
        """Unlink only the exact registry-bound artifact and manifest."""

        root = self._postgres_backup_root.resolve(strict=True)
        paths = (
            (
                "artifact",
                Path(backup.artifact_path),
                backup.artifact_sha256,
                backup.artifact_size_bytes,
            ),
            ("manifest", Path(backup.manifest_path), backup.manifest_sha256, None),
        )
        if paths[0][1] == paths[1][1]:
            raise BrokerBackendError(
                "database_backup_evidence_invalid",
                "Registered backup artifact and manifest paths are identical.",
            )
        removed: list[str] = []
        already_absent: list[str] = []
        reclaimed_bytes = 0
        directories: set[Path] = set()
        for label, path, expected_sha256, expected_size in paths:
            if not path.is_absolute():
                raise BrokerBackendError(
                    "database_backup_evidence_invalid",
                    "Registered backup path is not absolute.",
                )
            try:
                parent = path.parent.resolve(strict=True)
            except OSError as error:
                raise BrokerBackendError(
                    "database_backup_evidence_invalid",
                    "Registered backup parent is unavailable.",
                ) from error
            if parent != root and root not in parent.parents:
                raise BrokerBackendError(
                    "database_backup_evidence_invalid",
                    "Registered backup path escapes the service-owned backup root.",
                )
            directories.add(parent)
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                already_absent.append(label)
                continue
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise BrokerBackendError(
                    "database_backup_evidence_invalid",
                    "Registered backup evidence is not a regular file.",
                )
            if expected_size is not None and metadata.st_size != expected_size:
                raise BrokerBackendError(
                    "database_backup_evidence_changed",
                    "Registered backup artifact size changed before retirement.",
                )
            digest = hashlib.sha256()
            size = 0
            with path.open("rb", buffering=0) as stream:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > metadata.st_size:
                        raise BrokerBackendError(
                            "database_backup_evidence_changed",
                            "Registered backup evidence grew during retirement.",
                        )
                    digest.update(chunk)
            if size != metadata.st_size or digest.hexdigest() != expected_sha256:
                raise BrokerBackendError(
                    "database_backup_evidence_changed",
                    "Registered backup evidence changed before retirement.",
                )
            reclaimed_bytes += int(metadata.st_size)
            path.unlink()
            removed.append(label)
        for directory in directories:
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return {
            "removed": removed,
            "already_absent": already_absent,
            "reclaimed_bytes": reclaimed_bytes,
        }

    def _execute_test_admission_admin(
        self, accepted: AcceptedBrokerRequest
    ) -> Mapping[str, Any]:
        request = accepted.request
        try:
            if request.operation is BrokerOperation.TEST_ADMISSION_DRAIN_STATUS:
                proof = self._persistence.active_test_admission_proof()
                return {
                    "state": "drained" if proof is not None else "open",
                    "proof": None if proof is None else dict(proof),
                }
            if request.operation is BrokerOperation.TEST_ADMISSION_DRAIN_BEGIN:
                timing = self._test_submission_gate.begin_drain(
                    timeout_seconds=0.0
                )
                proof = self._persistence.activate_test_admission_drain(
                    activated_at_epoch=int(timing["activated_at_epoch"]),
                    activated_by_uid=accepted.peer.uid,
                    drained_at_epoch=int(timing["drained_at_epoch"]),
                    broker_instance_id=self._broker_instance_id,
                )
                return {"state": "drained", "proof": dict(proof)}
            if request.operation is BrokerOperation.TEST_ADMISSION_DRAIN_CLEAR:
                proof = self._persistence.clear_test_admission_drain(
                    drain_id=str(request.arguments["drain_id"]),
                    proof_sha256=str(request.arguments["proof_sha256"]),
                )
                return {
                    "state": "open",
                    "cleared_proof": dict(proof),
                }
        except TestStoreContractError as error:
            raise BrokerBackendError(
                "test_admission_fence_conflict",
                str(error),
                operation_id=request.operation_id,
            ) from error
        raise BrokerBackendError(
            "unsupported_operation",
            "Unsupported test admission administration operation.",
            operation_id=request.operation_id,
        )

    def _execute_async_test(
        self, accepted: AcceptedBrokerRequest
    ) -> Mapping[str, Any]:
        """Route one accepted test-plane call without exposing its store."""

        plane = self._test_plane
        request = accepted.request
        if plane is None:
            raise BrokerBackendError(
                "test_scheduler_unavailable",
                "The asynchronous test scheduler is not connected; retry after testd is healthy.",
                operation_id=request.operation_id,
            )
        actor = _test_run_actor(accepted)
        resolving_run_id: str | None = None
        preview_operation_reserved = False

        def finish_preview_failure(code: str, message: str) -> None:
            if not preview_operation_reserved:
                return
            try:
                self._persistence.finish_operation(
                    request.operation_id,
                    error_code=code,
                    error_message=message,
                )
            except Exception:
                _LOGGER.exception(
                    "test preview failure could not be persisted operation_id=%s code=%s",
                    request.operation_id,
                    code,
                )

        try:
            if request.operation is BrokerOperation.TEST_HEALTH:
                result = dict(plane.health())
                if (
                    result.get("schema_version") != 1
                    or result.get("status") != "ok"
                    or type(result.get("test_store_schema_version")) is not int
                    or not isinstance(result.get("store_generation"), str)
                    or not result["store_generation"]
                ):
                    raise TestStoreContractError(
                        "testd health returned contradictory store identity"
                    )
                result["repository_id"] = request.project_id
                return result

            if request.operation is BrokerOperation.TEST_STATS_READ:
                result = dict(
                    plane.dashboard_stats(
                        repository_id=request.project_id,
                        days=int(request.arguments["days"]),
                        limit=int(request.arguments["limit"]),
                    )
                )
                self._require_test_repository(result, request.project_id)
                return result

            if request.operation is BrokerOperation.TEST_FLEET_STATS_READ:
                authority_rows = self._persistence.current_test_repositories(
                    accepted
                )
                if not authority_rows:
                    raise TestStoreContractError(
                        "test fleet requires at least one current repository"
                    )
                if len(authority_rows) > 50:
                    raise BrokerBackendError(
                        "test_fleet_scope_too_large",
                        "The current test fleet exceeds the bounded dashboard scope.",
                        operation_id=request.operation_id,
                    )
                repository_ids = tuple(
                    str(row["repo_id"]) for row in authority_rows
                )
                result = dict(
                    plane.dashboard_fleet(
                        repository_ids=repository_ids,
                        hours=int(request.arguments["hours"]),
                    )
                )
                raw_repositories = result.get("repositories")
                if not isinstance(raw_repositories, list):
                    raise TestStoreContractError(
                        "testd fleet projection is malformed"
                    )
                by_id: dict[str, dict[str, object]] = {}
                for item in raw_repositories:
                    if not isinstance(item, Mapping):
                        raise TestStoreContractError(
                            "testd fleet repository is malformed"
                        )
                    repository_id = str(
                        item.get("repo_id") or item.get("repository_id") or ""
                    )
                    if repository_id not in repository_ids or repository_id in by_id:
                        raise TestStoreContractError(
                            "testd fleet repository identity is contradictory"
                        )
                    by_id[repository_id] = dict(item)
                if set(by_id) != set(repository_ids):
                    raise TestStoreContractError(
                        "testd fleet projection does not cover the authority scope"
                    )
                enriched = []
                for authority in authority_rows:
                    repository_id = str(authority["repo_id"])
                    enriched.append(
                        {
                            **by_id[repository_id],
                            "repo_id": repository_id,
                            "repository_id": repository_id,
                            "display_name": authority["display_name"],
                        }
                    )
                result["repositories"] = enriched
                return result

            if request.operation is BrokerOperation.TEST_PLAN_PREVIEW:
                disposition = self._persistence.reserve_operation(accepted)
                if disposition.state == "completed":
                    return dict(disposition.result or {})
                if disposition.state == "failed":
                    raise BrokerBackendError(
                        disposition.error_code or "test_plan_preview_failed",
                        disposition.error_message
                        or "The durable test-plan preview failed.",
                        operation_id=request.operation_id,
                    )
                if disposition.state != "execute":
                    raise BrokerBackendError(
                        "operation_in_progress",
                        "The durable test-plan preview is still running; follow its exact operation handle.",
                        operation_id=request.operation_id,
                        retry_after_seconds=2,
                    )
                preview_operation_reserved = True
                execution_context = (
                    self._persistence.test_repository_execution_context(
                        repo_id=request.project_id,
                        execution_uid=accepted.attribution_uid,
                        operation_id=request.operation_id,
                    )
                )
                result = dict(
                    plane.preview(
                        repository_id=request.project_id,
                        intent=str(request.arguments["intent"]),
                        actor=actor,
                        owner_uid=execution_context.execution_uid,
                        access_uid=accepted.attribution_uid,
                        temporary_root=request.arguments.get("temporary_root"),
                        requested_targets=tuple(
                            request.arguments.get("requested_targets", ())
                        ),
                        execution_timeout_seconds=request.arguments[
                            "execution_timeout_seconds"
                        ],
                        launch_timeout_seconds=int(
                            request.arguments["launch_timeout_seconds"]
                        ),
                    )
                )
                self._require_test_repository(result, request.project_id)
                preview_plan = decode_test_plan_document(
                    result.get("plan")  # type: ignore[arg-type]
                )
                if (
                    result.get("intent") != request.arguments["intent"]
                    or preview_plan.repository_id != request.project_id
                    or preview_plan.intent != request.arguments["intent"]
                    or preview_plan.timeouts.execution_seconds
                    != request.arguments["execution_timeout_seconds"]
                    or preview_plan.timeouts.launch_seconds
                    != request.arguments["launch_timeout_seconds"]
                ):
                    raise TestStoreContractError(
                        "testd returned a plan with contradictory identity or timeouts"
                    )
                requested_targets = tuple(
                    request.arguments.get("requested_targets", ())
                )
                planned_requests = tuple(
                    target
                    for target, selection in preview_plan.selection.items()
                    if "requested" in selection.reasons
                )
                if set(planned_requests) != set(requested_targets):
                    raise TestStoreContractError(
                        "testd returned a plan with contradictory requested targets"
                    )
                requested_temporary_root = request.arguments.get("temporary_root")
                if preview_plan.source.temporary_root != requested_temporary_root:
                    raise TestStoreContractError(
                        "testd returned a plan with contradictory temporary source"
                    )
                _require_preview_source_policy(
                    preview_plan,
                    allow_temporary=requested_temporary_root is not None,
                )
                self._require_test_plan_source(
                    accepted,
                    preview_plan.source.to_document(),
                )
                capability_requests = result.get("capability_requests")
                if (
                    not isinstance(capability_requests, Mapping)
                    or set(capability_requests)
                    != {"networks", "fixtures", "credentials"}
                    or not isinstance(capability_requests["networks"], list)
                    or not isinstance(capability_requests["fixtures"], list)
                    or not isinstance(capability_requests["credentials"], list)
                ):
                    raise TestStoreContractError(
                        "testd omitted selected-target capability requests"
                    )
                preview_resources = _test_target_resources(
                    result.get("target_resources"),
                    selected_targets=preview_plan.selected_targets,
                )
                registration = dict(
                    plane.register_plan(
                        preview_plan.to_document(),
                        target_resources=preview_resources,
                    )
                )
                self._require_test_repository(registration, request.project_id)
                if registration.get("plan_id") != preview_plan.plan_id:
                    raise TestStoreContractError(
                        "testd registered a plan with contradictory identity"
                    )
                result["plan_id"] = preview_plan.plan_id
                result["snapshot_id"] = preview_plan.source.snapshot_id
                result["registered"] = bool(registration.get("registered"))
                self._persistence.finish_operation(
                    request.operation_id,
                    result={
                        "schema_version": 1,
                        "ok": True,
                        "classification": "test_plan_preview_completed",
                        "operation_id": request.operation_id,
                        "repository_id": request.project_id,
                        "intent": preview_plan.intent,
                        "plan_id": preview_plan.plan_id,
                        "snapshot_id": preview_plan.source.snapshot_id,
                        "registered": bool(registration.get("registered")),
                    },
                )
                return result

            if request.operation is BrokerOperation.TEST_PLAN_REGISTER:
                plan = decode_test_plan_document(request.arguments["plan"])
                manifest = parse_test_manifest(request.arguments["manifest"])
                if manifest.fingerprint != plan.manifest_fingerprint:
                    raise TestStoreContractError(
                        "plan manifest fingerprint does not match the validated manifest"
                    )
                requested_targets = tuple(
                    target
                    for target, selection in plan.selection.items()
                    if "requested" in selection.reasons
                )
                expected = create_test_plan(
                    manifest,
                    intent=plan.intent,
                    source=plan.source,
                    changes=plan.changes,
                    requested_targets=requested_targets,
                    execution_timeout_seconds=plan.timeouts.execution_seconds,
                    launch_timeout_seconds=plan.timeouts.launch_seconds,
                )
                if expected.to_document() != plan.to_document():
                    raise TestStoreContractError(
                        "plan selection does not match the validated manifest"
                    )
                self._require_test_plan_source(accepted, plan.source.to_document())
                if plan.source.mode is SourceMode.IMMUTABLE:
                    raise TestStoreContractError(
                        "immutable plans must be produced by repository-owned preview"
                    )
                worktree_key = plan.source.temporary_root or plan.source.original_root
                resources = {
                    name: TargetResources(
                        cpu_millis=manifest.targets[name].resources.cpu_millis,
                        memory_mib=manifest.targets[name].resources.memory_mib,
                        pids=manifest.targets[name].resources.pids,
                        estimated_seconds=float(
                            manifest.targets[name].timeout_seconds
                            if plan.timeouts.execution_seconds is None
                            else plan.timeouts.execution_seconds
                        ),
                        shard_count=safe_history_shard_ceiling(
                            manifest.targets[name]
                        ),
                        max_attempts=manifest.targets[name].retry.max_attempts,
                        worktree_key=worktree_key,
                        exclusive_resources=manifest.targets[
                            name
                        ].exclusive_resources,
                    )
                    for name in plan.selected_targets
                }
                result = dict(
                    plane.register_plan(
                        plan.to_document(), target_resources=resources
                    )
                )
                self._require_test_repository(result, request.project_id)
                # Client-supplied agent text is diagnostic only; the kernel UID
                # and account remain the durable actor.
                result["actor"] = actor
                return result

            if request.operation is BrokerOperation.TEST_RUN_SUBMIT:
                expected_repository_id = request.arguments.get(
                    "expected_repository_id"
                )
                if expected_repository_id != request.project_id:
                    raise BrokerBackendError(
                        "test_repository_mismatch",
                        "The test plan does not belong to the requested repository.",
                        operation_id=request.operation_id,
                    )
                repository_id = str(
                    plane.plan_repository(
                        plan_id=str(request.arguments["plan_id"]),
                        repository_id=request.project_id,
                    )
                )
                if expected_repository_id != repository_id:
                    raise BrokerBackendError(
                        "test_repository_mismatch",
                        "The test plan does not belong to the requested repository.",
                        operation_id=request.operation_id,
                    )
                self._persistence.retarget_test_repository(
                    accepted, repo_id=repository_id
                )
                execution_context = (
                    self._persistence.test_repository_execution_context(
                        repo_id=repository_id,
                        execution_uid=accepted.attribution_uid,
                        operation_id=request.operation_id,
                    )
                )
                result = dict(
                    plane.submit(
                        plan_id=str(request.arguments["plan_id"]),
                        repository_id=repository_id,
                        operation_id=request.operation_id,
                        actor=actor,
                        owner_uid=execution_context.execution_uid,
                    )
                )
                self._require_test_repository(result, repository_id)
                return result

            if request.operation is BrokerOperation.TEST_RUN_LIST:
                result = dict(
                    plane.runs(
                        repository_id=request.project_id,
                        after=request.arguments.get("after"),
                        limit=int(request.arguments["limit"]),
                        state=request.arguments.get("state"),
                    )
                )
                self._require_test_repository(result, request.project_id)
                self._require_test_run_page(
                    result,
                    expected_repo_id=request.project_id,
                    maximum_items=int(request.arguments["limit"]),
                )
                return result

            if request.operation is BrokerOperation.TEST_QUEUE_STATUS:
                expected_repository_id = str(
                    request.arguments.get("expected_repository_id")
                    or request.project_id
                )
                if expected_repository_id != request.project_id:
                    raise BrokerBackendError(
                        "test_repository_mismatch",
                        "The queue status repository is contradictory.",
                        operation_id=request.operation_id,
                    )
                result = dict(
                    plane.queue_status(repository_id=request.project_id)
                )
                self._require_test_repository(result, request.project_id)
                return result

            if request.operation is BrokerOperation.TEST_EVENTS_READ:
                result = dict(
                    plane.events(
                        repository_id=request.project_id,
                        after_event_id=int(request.arguments["after_event_id"]),
                        limit=int(request.arguments["limit"]),
                    )
                )
                self._require_test_repository(result, request.project_id)
                self._require_test_event_page(
                    result,
                    expected_repo_id=request.project_id,
                    after_event_id=int(request.arguments["after_event_id"]),
                    maximum_items=int(request.arguments["limit"]),
                )
                return result

            if request.operation is BrokerOperation.TEST_REPOSITORY_CATALOG:
                authority_rows = self._persistence.current_test_repositories(
                    accepted
                )
                repository_ids = tuple(
                    str(row["repo_id"]) for row in authority_rows
                )
                retained = dict(
                    plane.repository_catalog(
                        repository_ids=repository_ids,
                        timeout_seconds=TEST_CATALOG_READ_TIMEOUT_SECONDS,
                    )
                )
                raw_rows = retained.get("repositories")
                if not isinstance(raw_rows, list):
                    raise TestStoreContractError(
                        "testd repository catalog is malformed"
                    )
                by_id: dict[str, Mapping[str, object]] = {}
                for item in raw_rows:
                    if not isinstance(item, Mapping):
                        raise TestStoreContractError(
                            "testd repository catalog entry is malformed"
                        )
                    repository_id = str(item.get("repository_id") or "")
                    if (
                        repository_id not in repository_ids
                        or repository_id in by_id
                        or item.get("setup_status")
                        not in {"ready", "missing", "invalid"}
                    ):
                        raise TestStoreContractError(
                            "testd repository catalog identity is contradictory"
                        )
                    by_id[repository_id] = item
                if set(by_id) != set(repository_ids):
                    raise TestStoreContractError(
                        "testd repository catalog does not cover the authority scope"
                    )
                return {
                    "schema_version": 1,
                    "repositories": [
                        {
                            "repo_id": row["repo_id"],
                            "display_name": row["display_name"],
                            "setup_status": by_id[str(row["repo_id"])][
                                "setup_status"
                            ],
                            "setup_observed_at": by_id[str(row["repo_id"])].get(
                                "setup_observed_at"
                            ),
                            "setup_retained": bool(
                                by_id[str(row["repo_id"])].get("retained")
                            ),
                            "manifest_fingerprint": by_id[
                                str(row["repo_id"])
                            ].get("manifest_fingerprint"),
                        }
                        for row in authority_rows
                    ],
                }

            if request.operation is BrokerOperation.TEST_REPOSITORY_SETUP:
                execution_context = (
                    self._persistence.test_repository_execution_context(
                        repo_id=request.project_id,
                        execution_uid=accepted.attribution_uid,
                        operation_id=request.operation_id,
                    )
                )
                result = dict(
                    plane.setup(
                        repository_id=request.project_id,
                        owner_uid=execution_context.execution_uid,
                        timeout_seconds=TEST_SETUP_READ_TIMEOUT_SECONDS,
                    )
                )
                self._require_test_repository(result, request.project_id)
                return result

            run_id = str(request.arguments.get("run_id") or "")
            if run_id:
                # Opaque run identifiers never supply authority. Resolve the
                # protected binding and require it to match the repository the
                # caller supplied before returning data or mutating state.
                resolving_run_id = run_id
                expected_run_repository_id = str(
                    request.arguments.get("expected_repository_id")
                    or request.project_id
                )
                status = dict(
                    plane.status(
                        run_id=run_id,
                        repository_id=expected_run_repository_id,
                    )
                )
                resolving_run_id = None
                repository_id = self._require_test_run_result(
                    status,
                    expected_run_id=run_id,
                    expected_repo_id=expected_run_repository_id,
                )
                if repository_id != expected_run_repository_id:
                    raise BrokerBackendError(
                        "test_repository_mismatch",
                        "The test run does not belong to the requested repository.",
                        operation_id=request.operation_id,
                    )
                self._persistence.retarget_test_repository(
                    accepted, repo_id=repository_id
                )
            if request.operation is BrokerOperation.TEST_RUN_STATUS:
                return status
            if request.operation is BrokerOperation.TEST_RUN_SUMMARY:
                result = dict(
                    plane.summary(
                        run_id=run_id,
                        repository_id=repository_id,
                    )
                )
                # Agent summaries intentionally omit repository path details;
                # request validation was proved by the status read above.
                self._require_test_run_result(
                    result,
                    expected_run_id=run_id,
                    expected_repo_id=repository_id,
                )
                return result
            if request.operation is BrokerOperation.TEST_RUN_FAILURES:
                result = dict(
                    plane.failures(
                        run_id=run_id,
                        repository_id=repository_id,
                        after=request.arguments.get("after"),
                        limit=int(request.arguments["limit"]),
                    )
                )
                self._require_test_run_result(
                    result,
                    expected_run_id=run_id,
                    expected_repo_id=repository_id,
                )
                return result
            if request.operation is BrokerOperation.TEST_RUN_ARTIFACTS:
                result = dict(
                    plane.artifacts(
                        run_id=run_id,
                        repository_id=repository_id,
                        after=request.arguments.get("after"),
                        limit=int(request.arguments["limit"]),
                    )
                )
                self._require_test_run_result(
                    result,
                    expected_run_id=run_id,
                    expected_repo_id=repository_id,
                )
                return result
            if request.operation is BrokerOperation.TEST_ARTIFACT_RESOLVE:
                artifact_id = str(request.arguments["artifact_id"])
                result = dict(
                    plane.artifact(
                        run_id=run_id,
                        repository_id=repository_id,
                        artifact_id=artifact_id,
                    )
                )
                self._require_test_run_result(
                    result,
                    expected_run_id=run_id,
                    expected_repo_id=repository_id,
                )
                artifact = result.get("artifact")
                if (
                    not isinstance(artifact, Mapping)
                    or artifact.get("artifact_id") != artifact_id
                    or artifact.get("verified") not in {1, True}
                    or not isinstance(artifact.get("storage_handle"), str)
                    or not isinstance(artifact.get("sha256"), str)
                    or artifact["storage_handle"]
                    != f"test-artifact://{artifact_id}/{artifact['sha256']}"
                ):
                    raise TestStoreContractError(
                        "testd returned a contradictory artifact identity"
                    )
                content = verified_text_artifact_content(artifact)
                result["artifact_content"] = content
                if content is not None and (
                    not isinstance(content, Mapping)
                    or content.get("artifact_id") != artifact_id
                    or content.get("sha256") != artifact.get("sha256")
                    or content.get("size_bytes") != artifact.get("size_bytes")
                    or not isinstance(content.get("text"), str)
                    or type(content.get("retained_bytes")) is not int
                    or type(content.get("truncated")) is not bool
                ):
                    raise TestStoreContractError(
                        "testd returned contradictory artifact content evidence"
                    )
                return result
            if request.operation is BrokerOperation.TEST_RUN_CASES:
                result = dict(
                    plane.cases(
                        run_id=run_id,
                        repository_id=repository_id,
                        after=int(request.arguments["after"]),
                        limit=int(request.arguments["limit"]),
                    )
                )
                self._require_test_run_result(
                    result,
                    expected_run_id=run_id,
                    expected_repo_id=repository_id,
                )
                return result
            if request.operation is BrokerOperation.TEST_RUN_CANCEL:
                result = dict(
                    plane.cancel(
                        run_id=run_id,
                        repository_id=repository_id,
                        actor=actor,
                        reason=str(request.arguments["reason"]),
                        operation_id=request.operation_id,
                    )
                )
                self._require_test_run_result(
                    result,
                    expected_run_id=run_id,
                    expected_repo_id=repository_id,
                )
                return result
            if request.operation is BrokerOperation.TEST_RUN_RETRY:
                result = dict(
                    plane.retry(
                        run_id=run_id,
                        repository_id=repository_id,
                        actor=actor,
                        failed_only=bool(request.arguments["failed_only"]),
                        operation_id=request.operation_id,
                    )
                )
                retry_run_id = str(result.get("run_id") or "")
                if not retry_run_id:
                    raise BrokerBackendError(
                        "test_run_mismatch",
                        "The test-plane retry result omitted its exact run identity.",
                        operation_id=request.operation_id,
                    )
                retry_status = dict(
                    plane.status(
                        run_id=retry_run_id,
                        repository_id=repository_id,
                    )
                )
                self._require_test_run_result(
                    retry_status,
                    expected_run_id=retry_run_id,
                    expected_repo_id=repository_id,
                )
                self._require_test_run_result(
                    result,
                    expected_run_id=retry_run_id,
                    expected_repo_id=repository_id,
                )
                return result
            if request.operation is BrokerOperation.TEST_EVIDENCE_CHECK:
                result = dict(
                    plane.policy_check(
                        repository_id=request.project_id,
                        snapshot_id=str(request.arguments["snapshot_id"]),
                        policy_name=str(request.arguments["policy_name"]),
                    )
                )
                self._require_test_repository(result, request.project_id)
                return result
            if request.operation is BrokerOperation.TEST_EVIDENCE_CONSUME:
                snapshot_id = str(request.arguments["snapshot_id"])
                policy_name = str(request.arguments["policy_name"])
                result = dict(
                    plane.policy_consume(
                        repository_id=request.project_id,
                        snapshot_id=snapshot_id,
                        policy_name=policy_name,
                        operation_id=request.operation_id,
                    )
                )
                self._require_test_repository(result, request.project_id)
                if (
                    result.get("operation_id") != request.operation_id
                    or result.get("snapshot_id") != snapshot_id
                    or result.get("policy_name") != policy_name
                    or result.get("satisfied") is not True
                    or result.get("consumed") is not True
                    or result.get("reusable") is not False
                    or result.get("requires_consumption") is not True
                    or not isinstance(result.get("attestation_id"), str)
                    or not result["attestation_id"]
                    or not isinstance(result.get("consumption_id"), str)
                    or not result["consumption_id"]
                    or not isinstance(result.get("run_id"), str)
                    or not result["run_id"]
                ):
                    raise BrokerBackendError(
                        "test_evidence_consumption_mismatch",
                        "The test plane returned contradictory evidence-consumption identity.",
                        operation_id=request.operation_id,
                    )
                return result
        except TestPlanPreviewUnavailable as error:
            unavailable_code = getattr(error, "code", "test_plan_preview_unavailable")
            unavailable_message = (
                "Repository-owned test setup inspection is not connected; retry after testd is healthy."
                if unavailable_code == "test_repository_setup_unavailable"
                else "Repository-owned test planning is not connected; retry after testd is healthy."
            )
            finish_preview_failure(unavailable_code, unavailable_message)
            raise BrokerBackendError(
                unavailable_code,
                unavailable_message,
                operation_id=request.operation_id,
                retry_after_seconds=2,
            ) from error
        except TestPlaneTransportError as error:
            _LOGGER.warning(
                "test-plane transport failure operation=%s code=%s detail=%s",
                request.operation.value,
                error.code,
                " ".join(str(error.message).split())[:1024],
            )
            if error.code == "live_retry_replan_required":
                raise BrokerBackendError(
                    error.code,
                    "The retained run used live source and cannot be retried "
                    "after source changes. Create a fresh current-source plan; "
                    "no retry run was created.",
                    operation_id=request.operation_id,
                ) from error
            snapshot_transport_failure = error.code in {
                "snapshot_transport_unavailable",
                "snapshot_transport_timeout",
                "snapshot_response_invalid",
            }
            snapshot_source_failure = (
                error.code.startswith("snapshot_") and not snapshot_transport_failure
            )
            preview_unavailable = error.code in {
                "test_plan_preview_unavailable",
                "test_repository_setup_unavailable",
                "test_plan_source_invalid",
            } or snapshot_transport_failure or snapshot_source_failure
            if error.code == "not_found":
                if request.operation is BrokerOperation.TEST_PLAN_PREVIEW:
                    public_code = "test_plan_source_invalid"
                    public_message = (
                        "Repository source state disappeared during immutable "
                        "planning; retry after repository writes stop."
                    )
                    finish_preview_failure(public_code, public_message)
                    raise BrokerBackendError(
                        public_code,
                        public_message,
                        operation_id=request.operation_id,
                    ) from error
                if resolving_run_id is not None:
                    raise BrokerBackendError(
                        "test_run_not_found",
                        "The exact test run does not exist.",
                        operation_id=request.operation_id,
                    ) from error
                if request.operation is BrokerOperation.TEST_ARTIFACT_RESOLVE:
                    raise BrokerBackendError(
                        "test_artifact_not_found",
                        "The exact test artifact does not exist.",
                        operation_id=request.operation_id,
                    ) from error
                raise BrokerBackendError(
                    "test_result_not_found",
                    "The requested test result does not exist.",
                    operation_id=request.operation_id,
                ) from error
            public_code = (
                "test_plan_source_invalid"
                if snapshot_source_failure
                else "test_plan_preview_unavailable"
                if snapshot_transport_failure
                else error.code
                if preview_unavailable
                else "test_scheduler_unavailable"
            )
            public_message = (
                (
                    "Repository-owned test setup inspection is not connected; retry after testd is healthy."
                    if error.code == "test_repository_setup_unavailable"
                    else public_snapshot_source_diagnostic(error.message)
                    if error.code == "test_plan_source_invalid" or snapshot_source_failure
                    else "Repository source snapshot inspection is temporarily unavailable; retry shortly."
                    if snapshot_transport_failure
                    else "Repository-owned test planning is not connected; retry after testd is healthy."
                )
                if preview_unavailable
                else "The asynchronous test scheduler is unavailable; retry shortly."
            )
            finish_preview_failure(public_code, public_message)
            raise BrokerBackendError(
                public_code,
                public_message,
                operation_id=request.operation_id,
                retry_after_seconds=None
                if public_code == "test_plan_source_invalid"
                else 2,
            ) from error
        except (ManifestContractError, TestPlanError, TestStoreContractError) as error:
            detail = _test_contract_diagnostic(error)
            _LOGGER.warning(
                "test contract failure operation_id=%s operation=%s type=%s detail=%s",
                request.operation_id,
                request.operation.value,
                type(error).__name__,
                detail,
            )
            contract_message = "The test manifest or plan contract is invalid: " + detail
            finish_preview_failure("test_contract_invalid", contract_message)
            raise BrokerBackendError(
                "test_contract_invalid",
                contract_message,
                operation_id=request.operation_id,
            ) from error
        except TestStoreNotFound as error:
            finish_preview_failure(
                "test_run_not_found", "The exact test run does not exist."
            )
            raise BrokerBackendError(
                "test_run_not_found",
                "The exact test run does not exist.",
                operation_id=request.operation_id,
            ) from error
        except TestStoreConflict as error:
            finish_preview_failure(
                "test_state_conflict",
                "The test request conflicts with current scheduler state.",
            )
            raise BrokerBackendError(
                "test_state_conflict",
                "The test request conflicts with current scheduler state.",
                operation_id=request.operation_id,
            ) from error
        except Exception:
            finish_preview_failure(
                "test_plan_preview_failed",
                "The durable test-plan preview failed unexpectedly.",
            )
            raise
        raise BrokerBackendError(
            "unsupported_operation",
            "The asynchronous test operation is not supported.",
            operation_id=request.operation_id,
        )

    def _execute_test_attempt(
        self, accepted: AcceptedBrokerRequest
    ) -> Mapping[str, Any]:
        """Execute one fixed-identity testd request at the root launch boundary."""

        request = accepted.request
        coordinator = self._test_attempts
        if coordinator is None:
            raise BrokerBackendError(
                "test_attempt_runtime_unavailable",
                "The protected test-attempt runtime is not configured.",
                operation_id=request.operation_id,
            )
        try:
            if request.operation is BrokerOperation.TEST_ATTEMPT_TICKET:
                raw = request.arguments["descriptor"]
                if not isinstance(raw, Mapping):
                    raise TestStoreContractError("test attempt descriptor is invalid")
                owner_uid = raw.get("owner_uid")
                if type(owner_uid) is not int:
                    raise TestStoreContractError("test attempt owner UID is invalid")
                repository_context = self._persistence.test_attempt_repository_context(
                    repo_id=request.project_id,
                    execution_uid=owner_uid,
                    operation_id=request.operation_id,
                )
                descriptor = TestAttemptDescriptor.from_document(
                    raw, repository_generation=repository_context.generation
                )
                if (
                    descriptor.repository_id != request.project_id
                    or descriptor.attempt_id != request.resource_id
                    or descriptor.original_root != repository_context.canonical_root
                    or descriptor.owner_uid != repository_context.execution_uid
                ):
                    raise TestStoreConflict(
                        "test attempt descriptor contradicts broker repository authority"
                    )
                if descriptor.source_mode == "live":
                    if descriptor.temporary_root is not None:
                        self._persistence.require_test_temporary_root(
                            root_repo_id=request.project_id,
                            temporary_root=descriptor.temporary_root,
                            operation_id=request.operation_id,
                        )
                elif (
                    descriptor.snapshot_id is None
                    or Path(descriptor.execution_root).name != "root"
                    or Path(descriptor.execution_root).parent.name
                    != descriptor.snapshot_id
                ):
                    raise TestStoreConflict(
                        "immutable test attempt does not target an exact snapshot root"
                    )
                return coordinator.issue(
                    descriptor,
                    launch_timeout_seconds=int(
                        request.arguments["launch_timeout_seconds"]
                    ),
                )

            if request.operation is BrokerOperation.TEST_ATTEMPT_LAUNCH:
                return coordinator.launch(
                    ticket_id=str(request.arguments["ticket_id"]),
                    attempt_id=str(request.arguments["attempt_id"]),
                    generation=int(request.arguments["generation"]),
                    expected_repository_id=request.project_id,
                    expected_repository_generation=request.repository_generation,
                )

            if request.operation is BrokerOperation.TEST_ATTEMPT_CANCEL:
                # Cancellation can race a lost launch reply. Bind the exact
                # deterministic runtime to the broker request before asking
                # the coordinator for either a stopped-runtime result or a
                # typed native absence proof. Generic descriptor failures stay
                # errors and can never be interpreted as successful cleanup.
                return coordinator.cancel(
                    str(request.arguments["runtime_id"]),
                    reason=str(request.arguments["reason"]),
                    expected_attempt_id=request.resource_id,
                    expected_repository_id=request.project_id,
                    expected_repository_generation=request.repository_generation,
                )

            descriptor = coordinator.runtime_descriptor(
                str(request.arguments["runtime_id"])
            )
            self._require_internal_attempt_binding(request, descriptor)
            if request.operation is BrokerOperation.TEST_ATTEMPT_STATUS:
                return coordinator.observe(
                    str(request.arguments["runtime_id"]),
                    result_chunk_index=int(
                        request.arguments["result_chunk_index"]
                    ),
                )
            raise TestStoreContractError("unsupported internal test attempt operation")
        except TestAttemptLaunchUncertain as error:
            raise BrokerBackendError(
                "test_attempt_launch_uncertain",
                str(error),
                operation_id=request.operation_id,
            ) from error
        except OSError as error:
            raise BrokerBackendError(
                "test_attempt_runtime_unavailable",
                "The protected test-attempt runtime could not access its local "
                "state; retry after the authority runtime is healthy.",
                operation_id=request.operation_id,
            ) from error
        except (TestStoreConflict, TestStoreContractError) as error:
            raise BrokerBackendError(
                "test_attempt_contract_invalid",
                str(error),
                operation_id=request.operation_id,
            ) from error

    @staticmethod
    def _require_internal_attempt_binding(
        request: BrokerRequest, descriptor: TestAttemptDescriptor
    ) -> None:
        if (
            descriptor.repository_id != request.project_id
            or descriptor.repository_generation != request.repository_generation
            or descriptor.attempt_id != request.resource_id
        ):
            raise TestStoreConflict(
                "test attempt request does not belong to the exact ticketed resource"
            )

    @staticmethod
    def _require_test_repository(
        result: Mapping[str, Any], expected_repo_id: str
    ) -> None:
        if not expected_repo_id or str(result.get("repository_id") or "") != expected_repo_id:
            raise BrokerBackendError(
                "test_repository_mismatch",
                "The test-plane result does not belong to the accepted repository.",
            )

    @staticmethod
    def _require_test_run_result(
        result: Mapping[str, Any],
        *,
        expected_run_id: str,
        expected_repo_id: str,
    ) -> str:
        """Bind one testd result to the broker-accepted run and repository.

        Testd owns the high-volume store but it is not an request validation
        authority.  A malformed response must therefore fail at the broker
        boundary instead of allowing an exact run lookup to be cross-wired to
        another repository's evidence.
        """

        returned_run_id = result.get("run_id")
        if (
            not expected_run_id
            or not isinstance(returned_run_id, str)
            or returned_run_id != expected_run_id
        ):
            raise BrokerBackendError(
                "test_run_mismatch",
                "The test-plane result does not belong to the requested run.",
            )
        returned_repo_id = result.get("repository_id")
        if (
            not isinstance(returned_repo_id, str)
            or not returned_repo_id
            or returned_repo_id != expected_repo_id
        ):
            raise BrokerBackendError(
                "test_repository_mismatch",
                "The test-plane result does not belong to the accepted repository.",
            )
        return returned_repo_id

    @classmethod
    def _require_test_run_page(
        cls,
        result: Mapping[str, Any],
        *,
        expected_repo_id: str,
        maximum_items: int,
    ) -> None:
        raw_runs = result.get("runs")
        if not isinstance(raw_runs, list) or len(raw_runs) > maximum_items:
            raise BrokerBackendError(
                "test_result_malformed",
                "The test-plane run page is malformed or exceeds its bound.",
            )
        seen: set[str] = set()
        for item in raw_runs:
            if not isinstance(item, Mapping):
                raise BrokerBackendError(
                    "test_result_malformed",
                    "The test-plane run page contains a malformed item.",
                )
            run_id = item.get("run_id")
            if not isinstance(run_id, str) or not run_id or run_id in seen:
                raise BrokerBackendError(
                    "test_result_malformed",
                    "The test-plane run page contains a contradictory run identity.",
                )
            seen.add(run_id)
            cls._require_test_run_result(
                item,
                expected_run_id=run_id,
                expected_repo_id=expected_repo_id,
            )

    @staticmethod
    def _require_test_event_page(
        result: Mapping[str, Any],
        *,
        expected_repo_id: str,
        after_event_id: int,
        maximum_items: int,
    ) -> None:
        raw_events = result.get("events")
        if not isinstance(raw_events, list) or len(raw_events) > maximum_items:
            raise BrokerBackendError(
                "test_result_malformed",
                "The test-plane event page is malformed or exceeds its bound.",
            )
        previous = after_event_id
        for item in raw_events:
            if not isinstance(item, Mapping):
                raise BrokerBackendError(
                    "test_result_malformed",
                    "The test-plane event page contains a malformed item.",
                )
            event_id = item.get("event_id")
            if type(event_id) is not int or event_id <= previous:
                raise BrokerBackendError(
                    "test_result_malformed",
                    "The test-plane event page contains a contradictory cursor.",
                )
            previous = event_id
            if item.get("repository_id") != expected_repo_id:
                raise BrokerBackendError(
                    "test_repository_mismatch",
                    "The test-plane event does not belong to the accepted repository.",
                )

    def _require_test_plan_source(
        self,
        accepted: AcceptedBrokerRequest,
        source: Mapping[str, Any],
    ) -> None:
        """Prove original/temporary roots from authority, never path inference."""

        request = accepted.request
        original_root = str(source.get("original_root") or "")
        temporary_root = source.get("temporary_root")
        with CoordinatorStore.open(
            self._persistence.database_path,
            expected_uid=self._persistence.expected_uid,
            busy_timeout_ms=self._persistence.busy_timeout_ms,
        ) as store:
            with store.read_transaction() as connection:
                root = connection.execute(
                    "SELECT canonical_root, state FROM repositories WHERE repo_id = ?",
                    (request.project_id,),
                ).fetchone()
                if (
                    root is None
                    or str(root["state"]) != "active"
                    or str(root["canonical_root"]) != original_root
                ):
                    raise TestStoreContractError(
                        "plan source is not the exact accepted root repository"
                    )
                if temporary_root is None:
                    return
                temporary = connection.execute(
                    """
                    SELECT repository.state
                    FROM repository_families AS family
                    JOIN repository_scopes AS scope
                      ON scope.family_id = family.family_id
                    JOIN repositories AS repository
                      ON repository.repo_id = scope.repo_id
                    WHERE family.root_repo_id = ?
                      AND scope.project_kind = 'temporary'
                      AND repository.canonical_root = ?
                    """,
                    (request.project_id, str(temporary_root)),
                ).fetchone()
                if temporary is None or str(temporary["state"]) != "active":
                    raise TestStoreContractError(
                        "temporary test source is not an authoritative member of the root repository family"
                    )

    def _finish_repository_ensure_failure(
        self,
        *,
        operation_id: str,
        code: str,
        message: str,
    ) -> None:
        """Best-effort terminalize a reserved adoption without hiding its cause."""

        try:
            self._persistence.finish_operation(
                operation_id,
                error_code=code,
                error_message=message,
            )
        except Exception:
            # Context validation can fail before reserve_operation, and a
            # damaged/unavailable store may also reject the terminal write.
            # The original typed public failure remains more useful than a
            # secondary operation-state error; retain that secondary evidence
            # only in the protected service log.
            _LOGGER.exception(
                "repository adoption diagnostic could not be persisted operation_id=%s code=%s",
                operation_id,
                code,
            )

    def _raise_repository_ensure_failure(
        self,
        *,
        request: BrokerRequest,
        code: str,
        message: str,
        cause: BaseException,
        terminalize: bool = True,
    ) -> NoReturn:
        if terminalize:
            self._finish_repository_ensure_failure(
                operation_id=request.operation_id,
                code=code,
                message=message,
            )
        raise BrokerBackendError(
            code,
            message,
            operation_id=request.operation_id,
        ) from cause

    def _reconcile_repository_runtime_contract(
        self,
        *,
        request: BrokerRequest,
        repo_id: str,
        root: str,
        execution_uid: int,
        reconcile_scope: str = "runtime",
    ) -> Mapping[str, Any]:
        """Reconcile only the catalog family required by the start-like intent."""

        if reconcile_scope not in {"runtime", "test"}:
            raise TestStoreContractError("repository reconciliation scope is invalid")
        compose: Mapping[str, Any] = {
            "changed": False,
            "compose_definition_id": None,
            "compose_run_once_services": {},
        }
        servers: Mapping[str, Any] = {"changed": False, "servers": {}}
        compose_definition_id = (
            self._persistence.configured_compose_definition_id(repo_id=repo_id)
            if reconcile_scope == "runtime"
            else None
        )
        if reconcile_scope == "runtime" and compose_definition_id is not None:
            prior_operation_id = (
                self._persistence.reconcilable_compose_operation_for_definition(
                    repo_id=repo_id,
                    compose_definition_id=compose_definition_id,
                )
            )
            if prior_operation_id is not None:
                candidate = self._persistence.compose_reconciliation_candidate(
                    prior_operation_id
                )
                if (
                    candidate["repo_id"] != repo_id
                    or candidate["compose_definition_id"]
                    != compose_definition_id
                ):
                    raise BrokerBackendError(
                        "compose_reconciliation_identity_mismatch",
                        "The retained Compose operation no longer belongs to the exact repository definition.",
                        operation_id=request.operation_id,
                    )
                evidence = self._observe_fresh_full_docker(
                    request.operation_id,
                    project_id=repo_id,
                )
                self._persistence.reconcile_compose_operation(
                    prior_operation_id,
                    evidence=evidence,
                )
        if reconcile_scope == "runtime":
            compose = reconcile_declared_compose_first_use(
                self._persistence,
                repo_id=repo_id,
                root=Path(root),
            )
            servers = reconcile_declared_servers_first_use(
                self._persistence,
                repo_id=repo_id,
                root=Path(root),
                execution_uid=execution_uid,
            )
        ephemeral = reconcile_declared_ephemeral_templates_first_use(
            self._persistence,
            repo_id=repo_id,
            root=Path(root),
        )
        return {
            **dict(compose),
            **dict(ephemeral),
            "changed": bool(
                compose.get("changed")
                or servers.get("changed")
                or ephemeral.get("changed")
            ),
            "servers": dict(servers.get("servers") or {}),
        }

    def _execute_repository_ensure(
        self, accepted: AcceptedBrokerRequest
    ) -> Mapping[str, Any]:
        """Adopt one repository while preserving safe, actionable failures."""

        from .repository_context import (
            RepositoryContextError,
            resolve_effective_repository_context,
        )

        request = accepted.request
        try:
            context = resolve_effective_repository_context(
                project=str(request.arguments["canonical_root"])
            )
        except (OSError, RepositoryContextError, ValueError) as error:
            message = _repository_adoption_message(
                "Repository adoption could not prove one stable Git worktree.",
                "Correct the reported repository/context condition, then rerun the original structured runtime serve command; do not enable local fallback or bind the port directly.",
                cause=error,
            )
            self._raise_repository_ensure_failure(
                request=request,
                code="repository_context_invalid",
                message=message,
                cause=error,
                terminalize=False,
            )

        try:
            return self._persistence.ensure_repository_catalog_entry(
                accepted,
                context=context,
                reconcile_repository=lambda repo_id, root, execution_uid: (
                    self._reconcile_repository_runtime_contract(
                        request=request,
                        repo_id=repo_id,
                        root=root,
                        execution_uid=execution_uid,
                        reconcile_scope=str(request.arguments["reconcile_scope"]),
                    )
                ),
            )
        except BrokerError:
            # Deliberately typed policy/state failures already carry an exact
            # operation identity and must not be relabelled as storage faults.
            raise
        except (DeclaredComposeConfigurationError, DeclaredRuntimeConfigurationError) as error:
            failure_cause = error
            code = "repository_runtime_contract_invalid"
            message = _repository_adoption_message(
                "Repository adoption could not catalog its declared runtime.",
                "Correct the named .codex/dev-runtime.json or runtime dependency condition, then rerun the original runtime ensure command with a fresh operation ID.",
                cause=error,
            )
        except StoreInvariantError as error:
            failure_cause: BaseException = error
            code = "repository_adoption_invariant_failed"
            message = _repository_adoption_message(
                "Repository adoption was rejected by a Coordinator authority invariant.",
                "Correct the conflicting catalog state named below, then rerun the original structured runtime serve command with a fresh operation ID.",
                cause=error,
            )
        except sqlite3.IntegrityError as error:
            failure_cause = error
            code = "repository_adoption_constraint_failed"
            message = _repository_adoption_message(
                "Repository adoption was rejected by an authority database constraint.",
                "Correct the conflicting repository/configuration identity named below, then rerun the original structured runtime serve command with a fresh operation ID.",
                cause=error,
            )
        except (StoreError, sqlite3.DatabaseError, OSError) as error:
            failure_cause = error
            code = "repository_adoption_store_failed"
            message = _repository_adoption_message(
                "Repository adoption could not commit to the Coordinator authority store.",
                "Correct the reported store condition (or let its current writer finish), then rerun the original structured runtime serve command with a fresh operation ID.",
                cause=error,
            )
        except (ValueError, RuntimeError) as error:
            failure_cause = error
            code = "repository_catalog_registration_failed"
            message = _repository_adoption_message(
                "Repository adoption could not register its catalog and execution context.",
                "Correct the catalog conflict named below, then rerun the original structured runtime serve command with a fresh operation ID.",
                cause=error,
            )
        except Exception as error:
            failure_cause = error
            code = "repository_adoption_internal_error"
            message = _repository_adoption_message(
                "Repository adoption failed unexpectedly before it could complete.",
                "Do not retry blindly, enable local fallback, bind the port directly, or choose another port; report this operation ID and error code to the Coordinator task.",
            )
            _LOGGER.exception(
                "repository adoption failed unexpectedly operation_id=%s exception_type=%s",
                request.operation_id,
                type(error).__name__,
            )
        self._raise_repository_ensure_failure(
            request=request,
            code=code,
            message=message,
            cause=failure_cause,
        )

    def execute(self, accepted: AcceptedBrokerRequest) -> Mapping[str, Any]:
        request = accepted.request
        if request.operation in {
            BrokerOperation.TEST_ADMISSION_DRAIN_BEGIN,
            BrokerOperation.TEST_ADMISSION_DRAIN_STATUS,
            BrokerOperation.TEST_ADMISSION_DRAIN_CLEAR,
        }:
            return self._execute_test_admission_admin(accepted)
        if request.operation in TESTD_INTERNAL_OPERATIONS:
            return self._execute_test_attempt(accepted)
        if request.operation in _ASYNC_TEST_OPERATIONS:
            return self._execute_async_test(accepted)
        if request.operation in _EPHEMERAL_OPERATIONS:
            return self._ephemeral.execute(accepted)
        if request.operation == BrokerOperation.CAPABILITIES_READ:
            return broker_capabilities(
                protocol_version=PROTOCOL_VERSION,
                authority_schema_version=SCHEMA_VERSION,
                authority_generation=request.authority_generation,
                active_release_digest=release_digest(Path(__file__)),
            )
        if request.operation == BrokerOperation.REPOSITORY_RESOLVE:
            return self._persistence.resolve_repository_catalog_entry(accepted)
        if request.operation == BrokerOperation.REPOSITORY_ENSURE:
            return self._execute_repository_ensure(accepted)
        if request.operation == BrokerOperation.OPERATION_FOLLOW:
            return self._persistence.operation_follow(accepted)
        if request.operation == BrokerOperation.INVENTORY_READ:
            return self._persistence.inventory(accepted)
        if request.operation == BrokerOperation.EVENTS_READ:
            return self._persistence.events(accepted)
        if request.operation == BrokerOperation.HOST_OBSERVE:
            return self._observe_committed_host(request.operation_id)
        if request.operation == BrokerOperation.RUNTIME_ENSURE:
            return self._execute_runtime_ensure(accepted)
        if request.operation == BrokerOperation.RUNTIME_REQUEST:
            return self._execute_runtime_request(accepted)
        if request.operation == BrokerOperation.COMPOSE_RUN_ONCE:
            return self._execute_compose_run_once(accepted)
        if request.operation in WORKER_OPERATIONS:
            return self._worker_operations.execute(accepted)
        if request.operation == BrokerOperation.REPOSITORY_LIST_REMOVED:
            return {
                "repositories": self._persistence.list_removed_repository(accepted)
            }
        if request.operation == BrokerOperation.ARCHIVES_READ:
            with CoordinatorStore.open(
                self._persistence.database_path,
                expected_uid=self._persistence.expected_uid,
                busy_timeout_ms=self._persistence.busy_timeout_ms,
            ) as store:
                cleanup = CleanupLifecycle(
                    store,
                    lifecycle_adapter=self._lifecycle_adapter,
                )
                listing = cleanup.list_archives(
                    actor=f"broker:{request.account_id}:uid:{accepted.peer.uid}"
                )
                return {"archives": list(listing["archives"])}
        listener_preflight: tuple[
            tuple[int, ...], int, str, Mapping[str, Any]
        ] | None = None
        port_candidates_preflight: tuple[int, ...] | None = None
        compose_preflight: Mapping[str, Any] | None = None
        if request.operation == BrokerOperation.PORT_LEASE:
            existing = self._persistence.existing_operation_disposition(accepted)
            if existing is not None:
                if existing.state == "completed":
                    return dict(existing.result or {})
                if existing.state == "failed":
                    raise BrokerBackendError(
                        existing.error_code or "mutation_failed",
                        existing.error_message or "Broker mutation failed.",
                        operation_id=request.operation_id,
                    )
                raise BrokerBackendError(
                    "operation_in_progress",
                    "This durable operation is already running or requires reconciliation; it was not executed again.",
                    operation_id=request.operation_id,
                )
            port_candidates_preflight = self._persistence.port_lease_candidates(
                accepted
            )
        if (
            request.operation == BrokerOperation.PORT_LEASE
            and bool(request.arguments.get("adopt_existing_listener"))
        ):
            assert port_candidates_preflight is not None
            candidates = port_candidates_preflight
            selected_port, canonical_root = (
                self._persistence.listener_adoption_preflight_target(accepted)
            )
            if type(selected_port) is not int or selected_port not in candidates:
                raise BrokerBackendError(
                    "invalid_host_observation",
                    "Listener adoption target is outside the accepted port candidates.",
                    operation_id=request.operation_id,
                )
            listener_evidence = self._host_mutations.verify_owned_tcp_listener(
                port=selected_port, canonical_root=canonical_root
            )
            listener_preflight = (
                candidates,
                selected_port,
                canonical_root,
                listener_evidence,
            )
        if request.operation in _COMPOSE_OPERATIONS:
            existing = self._persistence.existing_operation_disposition(accepted)
            if existing is not None:
                if existing.state == "completed":
                    return dict(existing.result or {})
                if existing.state == "failed":
                    raise BrokerBackendError(
                        existing.error_code or "mutation_failed",
                        existing.error_message or "Broker mutation failed.",
                        operation_id=request.operation_id,
                    )
                raise BrokerBackendError(
                    "operation_in_progress",
                    "This durable operation is already running or requires reconciliation; it was not executed again.",
                    operation_id=request.operation_id,
                )
            try:
                self._persistence.require_no_active_compose_operation(accepted)
            except BrokerError as exc:
                if exc.code != "compose_operation_pending":
                    raise
                prior_operation_id = (
                    self._persistence.reconcilable_prior_compose_operation_id(
                        accepted
                    )
                )
                if prior_operation_id is None:
                    raise
                candidate = self._persistence.compose_reconciliation_candidate(
                    prior_operation_id
                )
                if (
                    candidate["repo_id"] != request.project_id
                    or candidate["compose_definition_id"] != request.resource_id
                ):
                    raise
                reconciliation_evidence = self._observe_fresh_full_docker(
                    request.operation_id,
                    project_id=request.project_id,
                )
                self._persistence.reconcile_compose_operation(
                    prior_operation_id,
                    evidence=reconciliation_evidence,
                    accepted=accepted,
                )
                self._persistence.require_no_active_compose_operation(accepted)
            compose_preflight = self._observe_fresh_full_docker(
                request.operation_id,
                project_id=request.project_id,
            )
            self._persistence.require_compose_mutation_safe(
                accepted,
                snapshot_id=str(compose_preflight["snapshot_id"]),
            )
        if compose_preflight is None:
            disposition = self._persistence.reserve_operation(accepted)
        else:
            disposition = self._persistence.reserve_operation(
                accepted,
                compose_preflight=compose_preflight,
            )
        replay_database_result: Mapping[str, Any] | None = None
        replay_database_retirement = False
        if disposition.state == "completed":
            return dict(disposition.result or {})
        if disposition.state == "failed":
            raise BrokerBackendError(
                disposition.error_code or "mutation_failed",
                disposition.error_message or "Broker mutation failed.",
                operation_id=request.operation_id,
            )
        if disposition.state == "pending":
            replay_database_retirement = (
                request.operation is BrokerOperation.DATABASE_BACKUP_RETIRE
            )
            if request.operation in {
                BrokerOperation.DATABASE_BACKUP,
                BrokerOperation.DATABASE_RESTORE,
            }:
                replay_database_result = self._persistence.database_host_result(
                    accepted
                )
            if (
                request.operation is BrokerOperation.DATABASE_BACKUP
                and replay_database_result is None
                and self._persistence.database_backup_was_interrupted(accepted)
            ):
                code = "database_backup_interrupted"
                message = (
                    "The prior broker stopped before the read-only PostgreSQL "
                    "backup produced durable host evidence; submit a new backup operation."
                )
                self._record_failure(
                    request.operation_id, code=code, message=message
                )
                raise BrokerBackendError(
                    code, message, operation_id=request.operation_id
                )
            if replay_database_result is None and not replay_database_retirement:
                raise BrokerBackendError(
                    "operation_in_progress",
                    "This durable operation is already running or requires reconciliation; it was not executed again.",
                    operation_id=request.operation_id,
                )

        try:
            if request.operation == BrokerOperation.TEST_RUN_START:
                result = self._test_records.start(accepted)
            elif request.operation == BrokerOperation.TEST_RUN_FINISH:
                result = self._test_records.finish(accepted)
            elif request.operation is BrokerOperation.CONTAINER_REMOVE:
                target = self._persistence.direct_container_removal_target(
                    accepted
                )
                removal = dict(
                    self._container_remover(target.full_container_id)
                )
                if (
                    type(removal.get("already_absent")) is not bool
                    or removal.get("full_container_id")
                    != target.full_container_id
                ):
                    raise BrokerBackendError(
                        "container_remove_reply_invalid",
                        "Direct Docker removal returned contradictory target evidence.",
                        operation_id=request.operation_id,
                    )
                result = {
                    "ok": True,
                    "status": (
                        "already_absent"
                        if removal["already_absent"]
                        else "removed"
                    ),
                    "action": "remove",
                    "target_kind": "container",
                    "target_id": target.docker_resource_id,
                    "full_container_id": target.full_container_id,
                    "reason": str(request.arguments["reason"]),
                    **removal,
                }
            elif request.operation in {
                BrokerOperation.CLEANUP_PLAN,
                BrokerOperation.CLEANUP_APPLY,
                BrokerOperation.LIFECYCLE_RESTORE,
            }:
                with CoordinatorStore.open(
                    self._persistence.database_path,
                    expected_uid=self._persistence.expected_uid,
                    busy_timeout_ms=self._persistence.busy_timeout_ms,
                ) as store:
                    cleanup = CleanupLifecycle(
                        store,
                        lifecycle_adapter=self._lifecycle_adapter,
                        prepare_apply=lambda plan, prepare_actor: self._prepare_worker_lifecycle_apply(
                            accepted,
                            store=store,
                            plan=plan,
                            actor=prepare_actor,
                        ),
                    )
                    actor = f"broker:{request.account_id}:uid:{accepted.peer.uid}"
                    if request.operation is BrokerOperation.CLEANUP_PLAN:
                        if request.arguments["action"] == "archive":
                            result = self._plan_generic_archive(
                                accepted, store=store, actor=actor
                            )
                        else:
                            target_kind = str(request.arguments["target_kind"])
                            if target_kind in {"server", "container"}:
                                self._resolve_generic_cleanup_resource(
                                    accepted,
                                    store=store,
                                    target_kind=target_kind,
                                    target_id=str(request.arguments["target_id"]),
                                    operation=BrokerOperation.CLEANUP_PLAN,
                                )
                            observation = self._observe_fresh_full_docker(
                                request.operation_id,
                                project_id=request.project_id,
                            )
                            if target_kind in {"server", "container"}:
                                # Observation can change controller or host
                                # truth.  Re-resolve and re-accept before
                                # committing the plan snapshot.
                                self._resolve_generic_cleanup_resource(
                                    accepted,
                                    store=store,
                                    target_kind=target_kind,
                                    target_id=str(request.arguments["target_id"]),
                                    operation=BrokerOperation.CLEANUP_PLAN,
                                )
                            result = cleanup.plan(
                                target_kind=str(request.arguments["target_kind"]),
                                target_id=str(request.arguments["target_id"]),
                                actor=actor,
                                reason=str(request.arguments["reason"]),
                            ).to_dict()
                            result["broker_observation"] = observation
                    elif request.operation is BrokerOperation.CLEANUP_APPLY:
                        result = self._apply_generic_lifecycle(
                            accepted, store=store, cleanup=cleanup, actor=actor
                        )
                    else:
                        # Recheck database freshness immediately before
                        # resolving and restoring the exact archived target.
                        self._persistence.accept(accepted.peer, accepted.request)
                        target_kind = str(request.arguments["target_kind"])
                        target_id = str(request.arguments["target_id"])
                        reason = str(request.arguments["reason"])
                        lifecycle_persistence = SQLiteLifecyclePersistence(store)
                        lifecycle = RepositoryLifecycle(
                            lifecycle_persistence, self._lifecycle_adapter
                        )
                        if target_kind == "project":
                            result = lifecycle.reinstall_repository(
                                request.project_id,
                                actor=actor,
                                reason=reason,
                                explicit=True,
                            ).to_dict()
                        else:
                            exact, repo_id = lifecycle_persistence.resolve_resource(
                                ResourceKind(target_kind),
                                target_id,
                                include_archived=True,
                            )
                            if repo_id != request.project_id:
                                raise LifecycleError(
                                    "archived resource belongs to another project"
                                )
                            result = dict(
                                lifecycle.restore_resource_archive(
                                    exact, actor=actor, reason=reason
                                )
                            )
            elif request.operation in _LIFECYCLE_OPERATIONS:
                observation_evidence: Mapping[str, Any] | None = None
                required_plan_observation: Mapping[str, Any] | None = None
                apply_observation: Mapping[str, Any] | None = None
                resource_plan_basis: ExactResourceRef | None = None
                if request.operation in _LIFECYCLE_PLAN_OPERATIONS:
                    if request.operation in {
                        BrokerOperation.RESOURCE_PLAN_RETIRE,
                        BrokerOperation.RESOURCE_PLAN_ARCHIVE,
                    }:
                        # Request validation just proved this exact active resource.
                        # Preserve that identity across the mandatory fresh
                        # observation so generation-only controller churn can
                        # be distinguished from a changed controller.
                        with CoordinatorStore.open(
                            self._persistence.database_path,
                            expected_uid=self._persistence.expected_uid,
                            busy_timeout_ms=self._persistence.busy_timeout_ms,
                        ) as store:
                            resource_plan_basis = self._exact_lifecycle_resource(
                                SQLiteLifecyclePersistence(store), request
                            )
                    observation_evidence = self._observe_fresh_full_docker(
                        request.operation_id,
                        project_id=request.project_id,
                    )
                if request.operation in {
                    BrokerOperation.REPOSITORY_REMOVE,
                    BrokerOperation.RESOURCE_RETIRE,
                    BrokerOperation.RESOURCE_ARCHIVE,
                }:
                    # The service must refresh host truth immediately before
                    # applying an older plan.  RepositoryLifecycle then
                    # compares the plan's repo/exact-target snapshots against
                    # this newly committed graph, avoiding false conflicts
                    # from unrelated host-global material changes.
                    apply_observation = self._observe_fresh_full_docker(
                        request.operation_id,
                        project_id=request.project_id,
                    )
                    required_plan_observation = (
                        self._persistence.require_lifecycle_plan_observation(
                            accepted
                        )
                    )
                elif request.operation == BrokerOperation.RESOURCE_RESTORE:
                    apply_observation = self._observe_fresh_full_docker(
                        request.operation_id,
                        project_id=request.project_id,
                    )
                result = self._execute_lifecycle(
                    accepted, resource_plan_basis=resource_plan_basis
                )
                if observation_evidence is not None:
                    plan_id = str(result.get("plan_id") or "")
                    result["broker_observation"] = (
                        self._persistence.bind_lifecycle_plan_observation(
                            accepted,
                            plan_id=plan_id,
                            evidence=observation_evidence,
                        )
                    )
                elif required_plan_observation is not None:
                    result["broker_observation"] = {
                        "plan_basis": dict(required_plan_observation),
                        "apply_time": dict(apply_observation or {}),
                    }
            elif request.operation == BrokerOperation.PORT_LEASE:
                protocol = str(request.arguments.get("protocol", "tcp"))
                listener_evidence: Mapping[str, Any] | None = None
                if listener_preflight is not None:
                    (
                        candidates,
                        selected_port,
                        canonical_root,
                        listener_evidence,
                    ) = listener_preflight
                    current_port, current_root = (
                        self._persistence.listener_adoption_target(accepted)
                    )
                    if current_port != selected_port or current_root != canonical_root:
                        raise BrokerBackendError(
                            "listener_identity_changed",
                            "Listener adoption target changed between broker preflight and reservation.",
                            operation_id=request.operation_id,
                        )
                    current_evidence = self._host_mutations.verify_owned_tcp_listener(
                        port=current_port, canonical_root=current_root
                    )
                    if dict(current_evidence) != dict(listener_evidence):
                        raise BrokerBackendError(
                            "listener_identity_changed",
                            "Listener identity changed between broker preflight and reservation.",
                            operation_id=request.operation_id,
                        )
                    listener_evidence = current_evidence
                else:
                    assert port_candidates_preflight is not None
                    candidates = port_candidates_preflight
                    if bool(request.arguments.get("adopt_existing_listener")):
                        selected_port, canonical_root = (
                            self._persistence.listener_adoption_target(accepted)
                        )
                        listener_evidence = self._host_mutations.verify_owned_tcp_listener(
                            port=selected_port, canonical_root=canonical_root
                        )
                    else:
                        selected_port = self._host_mutations.select_available_port(
                            candidates=candidates, protocol=protocol
                        )
                if selected_port is None:
                    raise BrokerBackendError(
                        "port_unavailable",
                        "No accepted port is currently free in host listener observations.",
                        operation_id=request.operation_id,
                    )
                if type(selected_port) is not int or selected_port not in candidates:
                    raise BrokerBackendError(
                        "invalid_host_observation",
                        "Typed host port observer returned a candidate it was not asked to inspect.",
                        operation_id=request.operation_id,
                    )
                return self._persistence.complete_port_lease(
                    accepted,
                    observed_available_port=selected_port,
                    listener_evidence=listener_evidence,
                )
            elif request.operation == BrokerOperation.PORT_RELEASE:
                return self._persistence.complete_port_release(accepted)
            elif request.operation == BrokerOperation.SERVER_PUBLISH:
                target = self._persistence.server_publication_target(accepted)
                lifecycle = str(request.arguments["lifecycle"])
                listener_evidence: Mapping[str, Any] | None = None
                if lifecycle == "stopped":
                    available = self._host_mutations.select_available_port(
                        candidates=(int(target["port"]),), protocol="tcp"
                    )
                    if available != int(target["port"]):
                        raise BrokerBackendError(
                            "listener_still_bound",
                            "The broker cannot publish a stopped server while its exact port remains bound.",
                            operation_id=request.operation_id,
                        )
                else:
                    listener_evidence = self._host_mutations.verify_owned_tcp_listener(
                        port=int(target["port"]),
                        canonical_root=str(target["canonical_root"]),
                    )
                    if int(listener_evidence.get("pid") or 0) != int(
                        request.arguments["pid"]
                    ):
                        raise BrokerBackendError(
                            "listener_process_mismatch",
                            "Published process identity does not own the exact configured listener.",
                            operation_id=request.operation_id,
                        )
                return self._persistence.complete_server_publication(
                    accepted, listener_evidence=listener_evidence
                )
            elif request.operation == BrokerOperation.PORT_ASSIGN:
                candidates = self._persistence.port_assignment_candidates(accepted)
                selected_port: Optional[int] = None
                if candidates:
                    selected_port = self._host_mutations.select_available_port(
                        candidates=candidates, protocol="tcp"
                    )
                    if selected_port is None:
                        raise BrokerBackendError(
                            "port_unavailable",
                            "The exact assignment port is already occupied on the host.",
                            operation_id=request.operation_id,
                        )
                    if type(selected_port) is not int or selected_port not in candidates:
                        raise BrokerBackendError(
                            "invalid_host_observation",
                            "Typed host port observer returned a candidate it was not asked to inspect.",
                            operation_id=request.operation_id,
                        )
                return self._persistence.complete_port_assignment(
                    accepted, observed_available_port=selected_port
                )
            elif request.operation == BrokerOperation.PORT_UNASSIGN:
                return self._persistence.complete_port_unassignment(accepted)
            elif request.operation in {
                BrokerOperation.COMPOSE_UP,
                BrokerOperation.COMPOSE_STOP,
                BrokerOperation.COMPOSE_RESTART,
                BrokerOperation.COMPOSE_DOWN,
            }:
                target = self._persistence.compose_target(accepted)
                previous_service: Mapping[str, Any] | None = None
                if target.recreate_service is not None:
                    previous_service = (
                        self._persistence.compose_service_observation(
                            accepted,
                            snapshot_id=str(compose_preflight["snapshot_id"]),
                            service=target.recreate_service,
                        )
                    )
                if request.operation == BrokerOperation.COMPOSE_UP:
                    raw_result = self._host_mutations.compose_up(target)
                elif request.operation == BrokerOperation.COMPOSE_STOP:
                    raw_result = self._host_mutations.compose_stop(target)
                elif request.operation == BrokerOperation.COMPOSE_RESTART:
                    raw_result = self._host_mutations.compose_restart(target)
                else:
                    raw_result = self._host_mutations.compose_down(target)
                result = _json_safe_mapping(raw_result)
                result["pre_action_broker_observation"] = dict(
                    compose_preflight or {}
                )
                observation: Mapping[str, Any] | None = None
                try:
                    observation = self._observe_fresh_full_docker(
                        request.operation_id,
                        project_id=request.project_id,
                    )
                    result["broker_observation"] = observation
                    result["observed_resources"] = (
                        self._persistence.repository_container_observations(
                            accepted,
                            snapshot_id=str(observation["snapshot_id"]),
                        )
                    )
                    result["compose_observation"] = (
                        self._persistence.compose_observation_result(
                            accepted,
                            evidence=observation,
                        )
                    )
                    if target.recreate_service is not None:
                        recreated = self._persistence.compose_service_observation(
                            accepted,
                            snapshot_id=str(observation["snapshot_id"]),
                            service=target.recreate_service,
                        )
                        if (
                            previous_service is None
                            or recreated["full_container_id"]
                            == previous_service["full_container_id"]
                            or recreated["lifecycle"] != "running"
                            or str(recreated.get("health") or "").lower()
                            in {"starting", "unhealthy"}
                        ):
                            raise BrokerBackendError(
                                "compose_service_recreate_unproven",
                                "Exact Compose recreation did not prove a new healthy container identity.",
                                operation_id=request.operation_id,
                            )
                        result["service_recreation"] = {
                            "service": target.recreate_service,
                            "previous": dict(previous_service),
                            "current": recreated,
                            "volumes_preserved_from_sealed_model": True,
                            "dependencies_recreated": False,
                        }
                except Exception as exc:
                    if (
                        isinstance(exc, BrokerError)
                        and exc.code == "compose_observation_mismatch"
                    ):
                        # The authoritative observation committed and proved a
                        # definite non-matching state. This is a typed failure,
                        # not an uncertain host outcome.
                        raise
                    failure_code = _observation_failure_code(exc)
                    try:
                        self._persistence.mark_compose_operation_reconciliation_required(
                            request.operation_id,
                            action=str(result["action"]),
                            failed_phase="observation",
                            completed_phases=tuple(result.get("phases") or ()),
                            cleanup_failed=False,
                            observation=observation,
                            failure_code=failure_code,
                        )
                    except Exception:
                        # If the authority itself is unavailable, the still-running
                        # reservation remains the retry fence. Startup recovery must
                        # settle that crash-left state while the service is offline.
                        pass
                    raise BrokerBackendError(
                        "operation_outcome_uncertain",
                        "Docker Compose action completed but authoritative service observation did not commit; reconciliation is required.",
                        operation_id=request.operation_id,
                    ) from exc
            elif request.operation in {
                BrokerOperation.DATABASE_BACKUP,
                BrokerOperation.DATABASE_RESTORE,
            }:
                target = self._persistence.database_target(accepted)
                if replay_database_result is None:
                    self._persistence.mark_database_host_execution(accepted)
                if request.operation == BrokerOperation.DATABASE_BACKUP:
                    if replay_database_result is None:
                        try:
                            raw_result = self._host_mutations.postgres_backup(
                                target, output_root=str(self._postgres_backup_root)
                            )
                        except BrokerError as exc:
                            if exc.code != "operation_outcome_uncertain":
                                raise
                            # The helper process group has been terminated and
                            # backup never mutates the source database. Treat
                            # its missing durable evidence as a terminal failed
                            # attempt rather than an indefinite mutation fence.
                            raise BrokerBackendError(
                                "database_backup_timeout",
                                "PostgreSQL backup exceeded its bounded phase deadline without durable evidence.",
                                operation_id=request.operation_id,
                            ) from exc
                        journal_result = _json_safe_mapping(raw_result)
                        try:
                            self._persistence.save_database_host_result(
                                accepted, journal_result
                            )
                        except Exception as exc:
                            raise BrokerBackendError(
                                "operation_outcome_uncertain",
                                "PostgreSQL backup completed but its replay evidence could not be committed; service reconciliation is required.",
                                operation_id=request.operation_id,
                            ) from exc
                    else:
                        journal_result = dict(replay_database_result)
                    try:
                        result = self._persistence.register_database_backup_result(
                            accepted, target, journal_result
                        )
                    except Exception as exc:
                        raise BrokerBackendError(
                            "operation_outcome_uncertain",
                            "PostgreSQL backup completed but its durable registry commit failed; service reconciliation is required.",
                            operation_id=request.operation_id,
                        ) from exc
                else:
                    backup = self._persistence.registered_database_backup(
                        accepted, target
                    )
                    if replay_database_result is None:
                        raw_result = self._host_mutations.postgres_restore(
                            target,
                            backup,
                            safety_output_root=str(
                                self._postgres_backup_root / "pre-restore"
                            ),
                        )
                        journal_result = _json_safe_mapping(raw_result)
                        try:
                            self._persistence.save_database_host_result(
                                accepted, journal_result
                            )
                        except Exception as exc:
                            raise BrokerBackendError(
                                "operation_outcome_uncertain",
                                "PostgreSQL restore completed but its replay evidence could not be committed; service reconciliation is required.",
                                operation_id=request.operation_id,
                            ) from exc
                    else:
                        journal_result = dict(replay_database_result)
                    try:
                        result = self._persistence.register_database_restore_result(
                            accepted,
                            target,
                            backup,
                            journal_result,
                        )
                    except Exception as exc:
                        raise BrokerBackendError(
                            "operation_outcome_uncertain",
                            "PostgreSQL restore completed but its durable registry commit failed; service reconciliation is required.",
                            operation_id=request.operation_id,
                        ) from exc
            elif request.operation is BrokerOperation.DATABASE_BACKUP_RETIRE:
                target = self._persistence.database_target(accepted)
                backup = self._persistence.database_backup_for_retirement(
                    accepted, target
                )
                removed = self._retire_database_backup_files(backup)
                retired = self._persistence.retire_database_backup_result(
                    accepted, backup
                )
                result = {
                    **retired,
                    **removed,
                    "database_name": target.database_name,
                    "replayed_cleanup": replay_database_retirement,
                }
            elif request.operation not in _LIFECYCLE_OPERATIONS:
                # Re-read the current catalog identity, immutable container ID,
                # and observation revision after reservation and immediately
                # before external work.
                target = self._persistence.docker_target(accepted)
                if request.operation == BrokerOperation.DOCKER_START:
                    raw_result = self._host_mutations.docker_start(target)
                elif request.operation == BrokerOperation.DOCKER_STOP:
                    raw_result = self._host_mutations.docker_stop(target)
                elif request.operation == BrokerOperation.DOCKER_RESTART:
                    raw_result = self._host_mutations.docker_restart(target)
                else:  # the wire enum should make this unreachable
                    raise BrokerBackendError(
                        "unknown_operation",
                        "Requested broker operation is not allowed.",
                        operation_id=request.operation_id,
                    )
                result = _json_safe_mapping(raw_result)
                try:
                    observation = self._observe_fresh_full_docker(
                        request.operation_id,
                        project_id=request.project_id,
                    )
                    result["broker_observation"] = observation
                    result["observed_resource"] = (
                        self._persistence.docker_observation_result(
                            accepted, target
                        )
                    )
                except Exception as exc:
                    if (
                        isinstance(exc, BrokerError)
                        and exc.code == "docker_observation_mismatch"
                    ):
                        raise
                    self._raise_runtime_outcome_uncertain(
                        request.operation_id,
                        action=request.operation.value.removeprefix("docker."),
                        failed_phase="observation",
                        failure_code=_observation_failure_code(exc),
                        message=(
                            "Docker action completed but authoritative service "
                            "observation did not commit; reconciliation is required."
                        ),
                        cause=exc,
                    )
        except ComposeMutationOutcomeUncertain as exc:
            reconciliation_observation: Mapping[str, Any] | None = None
            # An action may be completed by observation only when exactly one
            # host command was invoked and no sealed-input cleanup or input
            # identity check failed.  A partial restart, a cleanup failure, or
            # a source-path drift may happen to leave the desired containers
            # running but is not evidence that the requested transaction was
            # safely completed.
            can_settle_by_observation = (
                exc.action in {"up", "stop", "down"}
                and exc.failed_phase == exc.action
                and not exc.completed_phases
                and not exc.cleanup_failed
            )
            try:
                reconciliation_observation = self._observe_fresh_full_docker(
                    request.operation_id,
                    project_id=request.project_id,
                )
            except Exception:
                # The host outcome remains uncertain either way. Persist only
                # the bounded fact that reconciliation observation failed; no
                # subprocess or observer diagnostics can enter the journal.
                reconciliation_observation = None
            if can_settle_by_observation and reconciliation_observation is not None:
                try:
                    proof = self._persistence.compose_observation_result(
                        accepted,
                        evidence=reconciliation_observation,
                    )
                except Exception:
                    # The authoritative state did not prove the requested
                    # result. Preserve the existing reconciliation fence.
                    pass
                else:
                    # Keep the wrapper uncertainty as audit metadata, but do
                    # not make a user retry a stop that has already reached
                    # its exact requested state.
                    reconciled_result = {
                        "action": exc.action,
                        "status": "completed_by_observation",
                        "phases": list(exc.completed_phases),
                        "host_invocation_uncertain": True,
                        "failed_phase": exc.failed_phase,
                        "cleanup_failed": exc.cleanup_failed,
                        "broker_observation": dict(reconciliation_observation),
                        "compose_observation": proof,
                    }
                    try:
                        self._persistence.finish_operation(
                            request.operation_id,
                            result=reconciled_result,
                        )
                    except Exception:
                        # The externally proved state remains real, but the
                        # durable journal did not accept it. Keep the normal
                        # reconciliation path rather than claiming success.
                        pass
                    else:
                        return reconciled_result
            try:
                self._persistence.mark_compose_operation_reconciliation_required(
                    request.operation_id,
                    action=exc.action,
                    failed_phase=exc.failed_phase,
                    completed_phases=exc.completed_phases,
                    cleanup_failed=exc.cleanup_failed,
                    observation=reconciliation_observation,
                )
            except Exception:
                # A still-running durable reservation is itself a retry fence.
                # Never convert an uncertain host effect into terminal failure.
                pass
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "Docker Compose did not prove a complete host outcome; reconciliation is required before any retry.",
                operation_id=request.operation_id,
            ) from None
        except BrokerError as exc:
            if exc.code == "operation_outcome_uncertain":
                raise
            self._record_failure(
                request.operation_id,
                code=exc.code,
                message=exc.message,
            )
            raise BrokerBackendError(
                exc.code, exc.message, operation_id=request.operation_id
            ) from None
        except LifecycleError as exc:
            self._record_failure(
                request.operation_id,
                code="lifecycle_rejected",
                message=str(exc),
            )
            raise BrokerBackendError(
                "lifecycle_rejected", str(exc), operation_id=request.operation_id
            ) from None
        except Exception:
            self._record_failure(
                request.operation_id,
                code="mutation_failed",
                message="The typed host mutation failed; inspect broker service logs.",
            )
            raise

        try:
            self._persistence.finish_operation(
                request.operation_id, result=result
            )
        except Exception as exc:
            if request.operation in _COMPOSE_OPERATIONS:
                action = request.operation.value.removeprefix("compose.")
                try:
                    self._persistence.mark_compose_operation_reconciliation_required(
                        request.operation_id,
                        action=action,
                        failed_phase="journal_commit",
                        completed_phases=tuple(result.get("phases") or ()),
                        cleanup_failed=False,
                        observation=(
                            result.get("broker_observation")
                            if isinstance(result.get("broker_observation"), Mapping)
                            else None
                        ),
                    )
                except Exception:
                    pass
            # External work may already have completed.  The reserved durable
            # row intentionally remains pending so a retry cannot execute it
            # blindly; an observer/reconciler must establish the outcome.
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "Host mutation completed but its durable result could not be committed; reconciliation is required.",
                operation_id=request.operation_id,
            ) from exc
        return result

    def _execute_compose_run_once(
        self, accepted: AcceptedBrokerRequest
    ) -> Mapping[str, Any]:
        """Execute or resume one broker-owned, manifest-sealed Compose service."""

        request = accepted.request
        existing = self._persistence.existing_operation_disposition(accepted)
        if existing is None:
            self._persistence.require_no_active_compose_operation(accepted)
            preflight = self._observe_fresh_full_docker(
                request.operation_id,
                project_id=request.project_id,
            )
            self._persistence.require_compose_mutation_safe(
                accepted,
                snapshot_id=str(preflight["snapshot_id"]),
            )
            disposition = self._persistence.reserve_operation(
                accepted,
                compose_preflight=preflight,
            )
        else:
            disposition = existing
        if disposition.state == "completed":
            return dict(disposition.result or {})
        if disposition.state == "failed":
            raise BrokerBackendError(
                disposition.error_code or "mutation_failed",
                disposition.error_message or "Broker mutation failed.",
                operation_id=request.operation_id,
            )
        if disposition.state not in {"execute", "pending"}:
            raise BrokerBackendError(
                "operation_state_conflict",
                "Compose run-once operation has an unsupported durable state.",
                operation_id=request.operation_id,
            )

        fresh_create_intent = False
        empty_digest = "sha256:" + hashlib.sha256(b"").hexdigest()
        for _transition in range(32):
            target = self._persistence.compose_run_once_target(accepted)
            phase = target.phase
            if phase == "reserved":
                self._persistence.mark_compose_run_once_image_bind_intent(
                    accepted
                )
                continue
            if phase == "image_bind_intent":
                try:
                    raw_image = self._host_mutations.compose_run_once_bind_image(
                        target
                    )
                    image_id = _validated_compose_run_once_image(
                        raw_image,
                        image_ref=target.service_image_ref,
                    )
                except BrokerError as exc:
                    self._persistence.finish_operation(
                        request.operation_id,
                        error_code=exc.code,
                        error_message=exc.message,
                    )
                    raise
                except Exception as exc:
                    self._persistence.finish_operation(
                        request.operation_id,
                        error_code="compose_run_once_image_unavailable",
                        error_message=(
                            "Compose run-once image binding could not be proved."
                        ),
                    )
                    raise BrokerBackendError(
                        "compose_run_once_image_unavailable",
                        "Compose run-once image binding could not be proved.",
                        operation_id=request.operation_id,
                    ) from exc
                self._persistence.bind_compose_run_once_image(
                    accepted,
                    image_id=image_id,
                )
                continue
            if phase == "image_bound":
                self._persistence.mark_compose_run_once_create_intent(accepted)
                fresh_create_intent = True
                continue
            if phase == "create_intent":
                observed = self._host_mutations.compose_run_once_find_container(
                    target
                )
                if observed is None and fresh_create_intent:
                    try:
                        observed = (
                            self._host_mutations.compose_run_once_create_container(
                                target
                            )
                        )
                    except Exception:
                        # A successful exact lookup after a caller/CLI failure
                        # resolves the creation side effect. A proved absence
                        # fails closed; it is never recreated under the same ID.
                        observed = (
                            self._host_mutations.compose_run_once_find_container(
                                target
                            )
                        )
                        if observed is None:
                            self._persistence.record_compose_run_once_terminal(
                                accepted,
                                exit_code=None,
                                timed_out=False,
                                error_code=(
                                    "compose_run_once_creation_unresolved"
                                ),
                            )
                            fresh_create_intent = False
                            continue
                elif observed is None:
                    self._persistence.record_compose_run_once_terminal(
                        accepted,
                        exit_code=None,
                        timed_out=False,
                        error_code="compose_run_once_creation_ambiguous",
                    )
                    continue
                observation = _validated_compose_run_once_container(
                    observed,
                    expected_image_id=str(target.expected_image_id),
                )
                self._persistence.bind_compose_run_once_container(
                    accepted,
                    full_container_id=observation["full_container_id"],
                    image_id=observation["image_id"],
                )
                fresh_create_intent = False
                continue
            if phase == "container_bound":
                self._persistence.mark_compose_run_once_start_intent(accepted)
                continue
            if phase == "start_intent":
                try:
                    raw_observation = (
                        self._host_mutations.compose_run_once_start_container(
                            target
                        )
                    )
                    observation = _validated_compose_run_once_container(
                        raw_observation,
                        expected_image_id=str(target.expected_image_id),
                        expected_container_id=str(target.full_container_id),
                    )
                except Exception as exc:
                    raise BrokerBackendError(
                        "operation_outcome_uncertain",
                        "Compose run-once start remains resumable by its exact operation ID.",
                        operation_id=request.operation_id,
                    ) from exc
                if observation["status"] == "running":
                    self._persistence.mark_compose_run_once_started(accepted)
                    continue
                if observation["status"] in {"exited", "dead"}:
                    self._persistence.record_compose_run_once_terminal(
                        accepted,
                        exit_code=observation["exit_code"],
                        timed_out=False,
                    )
                    continue
                raise BrokerBackendError(
                    "operation_outcome_uncertain",
                    "Compose run-once start has not reached a safe resumable state.",
                    operation_id=request.operation_id,
                )
            if phase == "started":
                self._persistence.mark_compose_run_once_wait_intent(accepted)
                continue
            if phase == "wait_intent":
                remaining_seconds = target.deadline_epoch - time.time()
                if remaining_seconds <= 0:
                    self._persistence.mark_compose_run_once_stop_intent(
                        accepted
                    )
                    continue
                try:
                    raw_wait = (
                        self._host_mutations.compose_run_once_wait_container(
                            target,
                            timeout_seconds=min(
                                float(target.timeout_seconds),
                                max(0.001, remaining_seconds),
                            ),
                        )
                    )
                    observation = _validated_compose_run_once_container(
                        raw_wait,
                        expected_image_id=str(target.expected_image_id),
                        expected_container_id=str(target.full_container_id),
                        allow_timed_out=True,
                    )
                except Exception as exc:
                    raise BrokerBackendError(
                        "operation_outcome_uncertain",
                        "Compose run-once wait remains resumable by its exact operation ID.",
                        operation_id=request.operation_id,
                    ) from exc
                if observation["status"] in {"exited", "dead"}:
                    self._persistence.record_compose_run_once_terminal(
                        accepted,
                        exit_code=observation["exit_code"],
                        timed_out=False,
                    )
                    continue
                if observation.get("timed_out") is True:
                    self._persistence.mark_compose_run_once_stop_intent(
                        accepted
                    )
                    continue
                raise BrokerBackendError(
                    "operation_outcome_uncertain",
                    "Compose run-once wait returned a non-terminal state.",
                    operation_id=request.operation_id,
                )
            if phase == "stop_intent":
                try:
                    raw_observation = (
                        self._host_mutations.compose_run_once_stop_container(
                            target
                        )
                    )
                    observation = _validated_compose_run_once_container(
                        raw_observation,
                        expected_image_id=str(target.expected_image_id),
                        expected_container_id=str(target.full_container_id),
                    )
                except Exception as exc:
                    raise BrokerBackendError(
                        "operation_outcome_uncertain",
                        "Timed-out Compose run-once stop remains resumable by its exact operation ID.",
                        operation_id=request.operation_id,
                    ) from exc
                if observation["status"] not in {"exited", "dead"}:
                    raise BrokerBackendError(
                        "operation_outcome_uncertain",
                        "Timed-out Compose run-once container is not terminal.",
                        operation_id=request.operation_id,
                    )
                self._persistence.record_compose_run_once_terminal(
                    accepted,
                    exit_code=observation["exit_code"],
                    timed_out=True,
                )
                continue
            if phase == "terminal":
                self._persistence.mark_compose_run_once_evidence_intent(
                    accepted
                )
                continue
            if phase == "evidence_intent":
                if target.full_container_id is None:
                    evidence = ComposeRunOnceOutputEvidence(
                        published_receipt=PublishedReceipt(
                            "empty",
                            None,
                            None,
                            "receipt_empty",
                        ),
                        stdout_sha256=empty_digest,
                        stdout_byte_size=0,
                        stderr_sha256=empty_digest,
                        stderr_byte_size=0,
                    )
                else:
                    try:
                        evidence = (
                            self._host_mutations.compose_run_once_capture_evidence(
                                target
                            )
                        )
                    except Exception as exc:
                        raise BrokerBackendError(
                            "operation_outcome_uncertain",
                            "Compose run-once evidence capture remains resumable by its exact operation ID.",
                            operation_id=request.operation_id,
                        ) from exc
                if not isinstance(evidence, ComposeRunOnceOutputEvidence):
                    raise BrokerBackendError(
                        "invalid_backend_result",
                        "Compose run-once evidence result is invalid.",
                        operation_id=request.operation_id,
                    )
                self._persistence.record_compose_run_once_evidence(
                    accepted,
                    published_receipt=evidence.published_receipt,
                    stdout_sha256=evidence.stdout_sha256,
                    stdout_byte_size=evidence.stdout_byte_size,
                    stderr_sha256=evidence.stderr_sha256,
                    stderr_byte_size=evidence.stderr_byte_size,
                )
                continue
            if phase == "evidence_captured":
                self._persistence.mark_compose_run_once_cleanup_intent(
                    accepted
                )
                continue
            if phase == "cleanup_intent":
                if target.full_container_id is None:
                    cleanup_status = "not_created"
                else:
                    try:
                        cleanup = (
                            self._host_mutations.compose_run_once_remove_container(
                                target
                            )
                        )
                    except Exception as exc:
                        raise BrokerBackendError(
                            "operation_outcome_uncertain",
                            "Compose run-once cleanup remains resumable by its exact operation ID.",
                            operation_id=request.operation_id,
                        ) from exc
                    if (
                        not isinstance(cleanup, Mapping)
                        or cleanup.get("removed") is not True
                        or cleanup.get("full_container_id")
                        != target.full_container_id
                    ):
                        raise BrokerBackendError(
                            "invalid_backend_result",
                            "Compose run-once cleanup omitted exact removal proof.",
                            operation_id=request.operation_id,
                        )
                    cleanup_status = "removed"
                self._persistence.mark_compose_run_once_cleaned(
                    accepted,
                    cleanup_status=cleanup_status,
                )
                continue
            if phase == "cleaned":
                result = self._persistence.compose_run_once_public_result(
                    accepted
                )
                try:
                    self._persistence.finish_operation(
                        request.operation_id,
                        result=result,
                    )
                except Exception as exc:
                    raise BrokerBackendError(
                        "operation_outcome_uncertain",
                        "Compose run-once completed but its public receipt remains resumable for durable commit.",
                        operation_id=request.operation_id,
                    ) from exc
                return result
            raise BrokerBackendError(
                "compose_run_once_state_invalid",
                "Compose run-once operation reached an unknown durable phase.",
                operation_id=request.operation_id,
            )
        raise BrokerBackendError(
            "compose_run_once_state_invalid",
            "Compose run-once operation exceeded its bounded transition count.",
            operation_id=request.operation_id,
        )

    def _execute_runtime_ensure(
        self, accepted: AcceptedBrokerRequest
    ) -> Mapping[str, Any]:
        """Ensure one configured target state without delegating decisions."""

        request = accepted.request
        desired_state = str(request.arguments["desired_state"])
        target_kind = str(request.arguments["target_kind"])

        existing = self._persistence.existing_operation_disposition(accepted)
        if existing is not None:
            if existing.state == "completed":
                return dict(existing.result or {})
            if existing.state == "failed":
                raise BrokerBackendError(
                    existing.error_code or "runtime_ensure_failed",
                    existing.error_message or "Runtime ensure did not complete.",
                    operation_id=request.operation_id,
                )
            raise BrokerBackendError(
                "operation_in_progress",
                "This durable runtime ensure is pending or needs attention; "
                "it was not executed again.",
                operation_id=request.operation_id,
            )

        # Observation precedes reservation so an unavailable observer cannot
        # strand a durable mutation. The target state is then re-read and its
        # immutable identity rechecked inside the reserved root operation.
        host_evidence = self._observe_committed_host(request.operation_id)
        if target_kind in {"docker", "database_stack"}:
            prior = self._persistence.reconcilable_prior_runtime_operation(
                accepted
            )
            if prior is not None:
                if host_evidence.get("docker_available") is not True:
                    raise BrokerBackendError(
                        "docker_observer_unavailable",
                        "Fresh Docker evidence is required before reconciling the prior runtime action.",
                        operation_id=request.operation_id,
                    )
                current = self._persistence.runtime_ensure_observation(accepted)
                if (
                    current.get("exact") is not True
                    or current.get("docker_resource_id")
                    != prior["docker_resource_id"]
                    or current.get("sampled_at") is None
                ):
                    raise BrokerBackendError(
                        "runtime_reconciliation_observation_incomplete",
                        "Fresh exact target evidence did not match the prior runtime action.",
                        operation_id=request.operation_id,
                    )
                self._persistence.finish_runtime_reconciliation(
                    prior["operation_id"],
                    error_code="runtime_outcome_reconciled",
                    error_message=(
                        "Fresh exact state cannot prove the historical runtime action; "
                        "the prior operation was settled as a terminal failure without reexecution."
                    ),
                )
        disposition = self._persistence.reserve_operation(accepted)
        if disposition.state == "completed":
            return dict(disposition.result or {})
        if disposition.state == "failed":
            raise BrokerBackendError(
                disposition.error_code or "runtime_ensure_failed",
                disposition.error_message or "Runtime ensure did not complete.",
                operation_id=request.operation_id,
            )
        if disposition.state not in {"execute", "pending", "reconcile"}:
            raise BrokerBackendError(
                "operation_in_progress",
                "This durable runtime ensure is pending or needs attention; "
                "it was not executed again.",
                operation_id=request.operation_id,
            )

        try:
            context, _inventory, classification_evidence = (
                self._persistence.runtime_snapshot(accepted)
            )
            before = self._persistence.runtime_ensure_observation(
                accepted, require_reserved=True
            )
        except BrokerError as error:
            self._persistence.finish_operation(
                request.operation_id,
                error_code=error.code,
                error_message=error.message,
            )
            raise BrokerBackendError(
                error.code, error.message, operation_id=request.operation_id
            ) from None

        family_classified = not classification_evidence
        decision = decide_runtime_ensure(
            before,
            desired_state=desired_state,
            family_classified=family_classified,
        )
        if target_kind in {"docker", "database_stack"} and (
            host_evidence.get("docker_available") is not True
        ):
            decision = RuntimeEnsureDecision(
                desired_state,
                decision.observed_state,
                None,
                "attention_required",
                "docker_observer_unavailable",
            )

        if decision.action is None:
            result = build_runtime_ensure_result(
                operation_id=request.operation_id,
                repository_id=request.project_id,
                repository_generation=request.repository_generation,
                resource_kind=target_kind,
                resource_id=request.resource_id,
                desired_state=desired_state,
                decision=decision,
                mutation_performed=False,
                terminal_observation=before,
                snapshot_id=str(host_evidence["snapshot_id"]),
                proof_source="broker_host_observation",
                family_classified=family_classified,
            )
            return self._finish_runtime_ensure_result(request, result)

        if target_kind == "service":
            return self._execute_worker_runtime_ensure(
                accepted,
                context=context,
                before=before,
                decision=decision,
                family_classified=family_classified,
            )

        invoked = False
        try:
            target = self._persistence.runtime_docker_target(accepted)
            invoked = True
            if decision.action == "start":
                self._host_mutations.docker_start(target)
            else:
                self._host_mutations.docker_stop(target)
            (
                final_host_evidence,
                terminal,
                final_classification,
            ) = self._observe_runtime_ensure_convergence(
                accepted,
                desired_state=desired_state,
            )
            terminal_certain = (
                final_host_evidence.get("docker_available") is True
            )
        except Exception as error:
            preflight_rejected = (
                isinstance(error, BrokerBackendError)
                and error.code
                in {
                    "project_isolation_mismatch",
                    "project_isolation_unobservable",
                }
            )
            if invoked and not preflight_rejected:
                try:
                    (
                        final_host_evidence,
                        terminal,
                        final_classification,
                    ) = self._observe_runtime_ensure_convergence(
                        accepted,
                        desired_state=desired_state,
                    )
                except Exception:
                    pass
                else:
                    reconciled = build_runtime_ensure_result(
                        operation_id=request.operation_id,
                        repository_id=request.project_id,
                        repository_generation=request.repository_generation,
                        resource_kind=target_kind,
                        resource_id=request.resource_id,
                        desired_state=desired_state,
                        decision=decision,
                        mutation_performed=True,
                        terminal_observation=terminal,
                        snapshot_id=str(final_host_evidence["snapshot_id"]),
                        proof_source="broker_host_observation",
                        certain=(
                            final_host_evidence.get("docker_available") is True
                        ),
                        family_classified=not final_classification,
                    )
                    return self._finish_runtime_ensure_result(
                        request, reconciled
                    )
            failure_decision = decision
            if not invoked or preflight_rejected:
                failure_decision = RuntimeEnsureDecision(
                    desired_state,
                    decision.observed_state,
                    None,
                    "attention_required",
                    "mutation_preflight_failed",
                )
            uncertain = build_runtime_ensure_result(
                operation_id=request.operation_id,
                repository_id=request.project_id,
                repository_generation=request.repository_generation,
                resource_kind=target_kind,
                resource_id=request.resource_id,
                desired_state=desired_state,
                decision=failure_decision,
                mutation_performed=invoked and not preflight_rejected,
                terminal_observation=before,
                snapshot_id=str(host_evidence["snapshot_id"]),
                proof_source="broker_host_observation",
                certain=not invoked or preflight_rejected,
                family_classified=family_classified,
            )
            return self._finish_runtime_ensure_result(request, uncertain)

        result = build_runtime_ensure_result(
            operation_id=request.operation_id,
            repository_id=request.project_id,
            repository_generation=request.repository_generation,
            resource_kind=target_kind,
            resource_id=request.resource_id,
            desired_state=desired_state,
            decision=decision,
            mutation_performed=True,
            terminal_observation=terminal,
            snapshot_id=str(final_host_evidence["snapshot_id"]),
            proof_source="broker_host_observation",
            certain=terminal_certain,
            family_classified=not final_classification,
        )
        return self._finish_runtime_ensure_result(request, result)

    def _observe_runtime_ensure_convergence(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        desired_state: str,
    ) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
        """Boundedly re-observe a Docker mutation through readiness startup.

        ``docker start`` proves daemon acceptance, not that a container health
        check or PostgreSQL probe has completed.  Each turn is a new committed
        authority observation; transient observation failures are retried, and
        the final non-ready state remains truthful attention evidence.
        """

        last_error: Exception | None = None
        latest: tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]] | None = None
        for delay_seconds in (0.0, 0.25, 0.5, 1.0, 2.0):
            if delay_seconds:
                time.sleep(delay_seconds)
            try:
                host_evidence = self._observe_committed_host(
                    accepted.request.operation_id
                )
                _context, _inventory, classification = (
                    self._persistence.runtime_snapshot(accepted)
                )
                terminal = self._persistence.runtime_ensure_observation(
                    accepted, require_reserved=True
                )
                latest = (host_evidence, terminal, classification)
                last_error = None
                if (
                    host_evidence.get("docker_available") is True
                    and not classification
                    and observed_runtime_state(terminal) == desired_state
                ):
                    return latest
            except Exception as error:
                last_error = error
        if latest is not None:
            return latest
        assert last_error is not None
        raise last_error

    def _execute_worker_runtime_ensure(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        context: Mapping[str, Any],
        before: Mapping[str, Any],
        decision: RuntimeEnsureDecision,
        family_classified: bool,
    ) -> Mapping[str, Any]:
        """Invoke only fixed start/stop on an exact supervised worker."""

        request = accepted.request
        desired_state = str(request.arguments["desired_state"])
        canonical_repository = (
            context["temporary_repo"]
            if context["temporary_repo"] is not None
            else context["root_repo"]
        )
        name = before.get("name")
        invoked = False
        try:
            if not isinstance(canonical_repository, str) or not canonical_repository:
                raise WorkerControlError("worker repository context is unavailable")
            if not isinstance(name, str) or not name:
                raise WorkerControlError("worker name is unavailable")
            self._persistence.require_worker_runtime_operation_current(accepted)
            endpoint_target = self._persistence.runtime_service_endpoint_target(
                accepted
            )
            execution_uid = self._persistence.worker_execution_uid(accepted)
            with AccountStore.open(
                self._persistence.database_path,
                expected_uid=self._persistence.expected_uid,
                busy_timeout_ms=self._persistence.busy_timeout_ms,
            ) as store:
                controller = WorkerController(
                    store,
                    coordinator_script=(
                        Path(__file__).resolve().parent.parent
                        / "dev_coordinator.py"
                    ),
                    execution_uid=execution_uid,
                )
                identity = {
                    "worker_id": request.resource_id,
                    "canonical_repository": canonical_repository,
                    "name": name,
                }
                invoked = True
                if decision.action == "start":
                    controlled = controller.start(
                        **identity,
                        actor=str(request.arguments["agent"]),
                        keep_alive=(
                            False
                            if before.get("breaker_state") is None
                            else None
                        ),
                        crash_limit=None,
                        crash_window_seconds=None,
                        rearm=False,
                    )
                else:
                    controlled = controller.stop(
                        **identity,
                        actor=str(request.arguments["agent"]),
                    )
            self._persistence.require_worker_runtime_operation_current(accepted)
            try:
                endpoint_proof = self._runtime_service_endpoint_proof(
                    endpoint_target=endpoint_target,
                    action=str(decision.action),
                    controlled=controlled,
                    operation_id=request.operation_id,
                )
            except Exception:
                if decision.action != "start":
                    raise
                with AccountStore.open(
                    self._persistence.database_path,
                    expected_uid=self._persistence.expected_uid,
                    busy_timeout_ms=self._persistence.busy_timeout_ms,
                ) as rollback_store:
                    rollback = WorkerController(
                        rollback_store,
                        coordinator_script=(
                            Path(__file__).resolve().parent.parent
                            / "dev_coordinator.py"
                        ),
                        execution_uid=execution_uid,
                    ).stop(
                        **identity,
                        actor=str(request.arguments["agent"]),
                    )
                terminal = worker_result_observation(
                    resource_id=request.resource_id,
                    controlled=rollback,
                )
                result = build_runtime_ensure_result(
                    operation_id=request.operation_id,
                    repository_id=request.project_id,
                    repository_generation=request.repository_generation,
                    resource_kind="service",
                    resource_id=request.resource_id,
                    desired_state=desired_state,
                    decision=decision,
                    mutation_performed=True,
                    terminal_observation=terminal,
                    snapshot_id=None,
                    proof_source="broker_service_supervisor",
                    family_classified=family_classified,
                )
                return self._finish_runtime_ensure_result(request, result)
            controlled = {**dict(controlled), "endpoint_proof": endpoint_proof}
            terminal = worker_result_observation(
                resource_id=request.resource_id,
                controlled=controlled,
            )
        except Exception:
            failure_decision = decision
            if not invoked:
                failure_decision = RuntimeEnsureDecision(
                    desired_state,
                    decision.observed_state,
                    None,
                    "attention_required",
                    "mutation_preflight_failed",
                )
            uncertain = build_runtime_ensure_result(
                operation_id=request.operation_id,
                repository_id=request.project_id,
                repository_generation=request.repository_generation,
                resource_kind="service",
                resource_id=request.resource_id,
                desired_state=desired_state,
                decision=failure_decision,
                mutation_performed=invoked,
                terminal_observation=before,
                snapshot_id=None,
                proof_source="broker_worker_supervisor",
                certain=not invoked,
                family_classified=family_classified,
            )
            return self._finish_runtime_ensure_result(request, uncertain)

        result = build_runtime_ensure_result(
            operation_id=request.operation_id,
            repository_id=request.project_id,
            repository_generation=request.repository_generation,
            resource_kind="service",
            resource_id=request.resource_id,
            desired_state=desired_state,
            decision=decision,
            mutation_performed=True,
            terminal_observation=terminal,
            snapshot_id=None,
            proof_source="broker_worker_supervisor",
            family_classified=family_classified,
        )
        return self._finish_runtime_ensure_result(request, result)

    def _runtime_service_endpoint_proof(
        self,
        *,
        endpoint_target: Any,
        action: str,
        controlled: Mapping[str, Any],
        operation_id: str,
    ) -> dict[str, Any]:
        """Prove the sealed cwd and any promised TCP endpoint after control."""

        if not endpoint_target.listener_required:
            return {
                "certain": True,
                "listener_required": False,
                "cwd_binding": "sealed_definition",
            }
        port = endpoint_target.listener_port
        if type(port) is not int:
            raise BrokerBackendError(
                "service_endpoint_binding_unavailable",
                "Network service endpoint proof lost its exact port binding.",
                operation_id=operation_id,
            )
        if action in {"start", "restart", "replace"}:
            pid = controlled.get("pid")
            started = controlled.get("process_start_time")
            expected_identities = {
                f"linux:{pid}:{started}",
                f"process:{pid}:{started}",
            }
            deadline = time.monotonic() + _SERVICE_ENDPOINT_STARTUP_TIMEOUT_SECONDS
            while True:
                try:
                    evidence = self._host_mutations.verify_owned_tcp_listener(
                        port=port,
                        canonical_root=endpoint_target.canonical_root,
                    )
                except Exception as error:
                    available = self._host_mutations.select_available_port(
                        candidates=(port,), protocol="tcp"
                    )
                    if available != port:
                        raise
                    if time.monotonic() >= deadline:
                        raise BrokerBackendError(
                            "service_endpoint_startup_timeout",
                            "The supervised service did not bind its exact assigned listener before the startup deadline.",
                            operation_id=operation_id,
                        ) from error
                    time.sleep(_SERVICE_ENDPOINT_POLL_SECONDS)
                    continue
                observed_identity = evidence.get("process_identity")
                if (
                    type(pid) is not int
                    or pid <= 1
                    or not isinstance(started, str)
                    or not started
                    or evidence.get("pid") != pid
                    or evidence.get("cwd") != endpoint_target.cwd
                    or observed_identity not in expected_identities
                ):
                    raise BrokerBackendError(
                        "service_endpoint_identity_mismatch",
                        "The observed listener does not match the exact supervised process and sealed cwd.",
                        operation_id=operation_id,
                    )
                break
            return {
                "certain": True,
                "listener_required": True,
                "state": "listening",
                "port": port,
                "pid": pid,
                "process_identity": observed_identity,
                "cwd_binding": "exact",
            }
        if action == "status":
            try:
                evidence = self._host_mutations.verify_owned_tcp_listener(
                    port=port,
                    canonical_root=endpoint_target.canonical_root,
                )
            except Exception:
                available = self._host_mutations.select_available_port(
                    candidates=(port,), protocol="tcp"
                )
                return {
                    "certain": available == port,
                    "listener_required": True,
                    "ready": False,
                    "state": (
                        "not_listening"
                        if available == port
                        else "identity_unproven"
                    ),
                    "port": port,
                    "cwd_binding": "sealed_definition",
                }
            pid = controlled.get("pid")
            started = controlled.get("process_start_time")
            observed_identity = evidence.get("process_identity")
            matches = bool(
                type(pid) is int
                and pid > 1
                and isinstance(started, str)
                and started
                and evidence.get("pid") == pid
                and evidence.get("cwd") == endpoint_target.cwd
                and observed_identity
                in {
                    f"linux:{pid}:{started}",
                    f"process:{pid}:{started}",
                }
            )
            return {
                "certain": True,
                "listener_required": True,
                "ready": matches,
                "state": "listening" if matches else "identity_mismatch",
                "port": port,
                "pid": evidence.get("pid"),
                "process_identity": observed_identity,
                "cwd_binding": "exact" if matches else "mismatch",
            }
        if action == "stop":
            available = self._host_mutations.select_available_port(
                candidates=(port,), protocol="tcp"
            )
            process_proof = controlled.get("terminal_process_proof")
            if available != port or not (
                isinstance(process_proof, Mapping)
                and process_proof.get("certain") is True
                and process_proof.get("state")
                in {"absent", "pid_reused", "not_launched"}
            ):
                raise BrokerBackendError(
                    "service_stop_identity_unproven",
                    "Service stop did not prove both the exact process and listener absent.",
                    operation_id=operation_id,
                )
            return {
                "certain": True,
                "listener_required": True,
                "state": "stopped",
                "port": port,
                "process": dict(process_proof),
                "listener": "absent",
                "cwd_binding": "sealed_definition",
            }
        raise BrokerBackendError(
            "unsupported_runtime_action",
            "Service endpoint proof received an unsupported lifecycle action.",
            operation_id=operation_id,
        )

    def _finish_runtime_ensure_result(
        self, request: BrokerRequest, result: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        try:
            self._persistence.finish_runtime_ensure(
                request.operation_id, result=result
            )
        except Exception as error:
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "Runtime ensure reached a terminal broker result but its durable "
                "journal commit is uncertain; retry only this operation ID.",
                operation_id=request.operation_id,
            ) from error
        return result

    def _runtime_replacement_subrequest(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        operation_id: str,
        resource_id: str,
        operation: BrokerOperation,
        arguments: Mapping[str, Any],
    ) -> AcceptedBrokerRequest:
        """Create and accept one deterministic typed replacement phase."""

        parent = accepted.request
        request = BrokerRequest.create(
            operation_id=operation_id,
            authority_generation=parent.authority_generation,
            account_id=parent.account_id,
            project_id=parent.project_id,
            repository_generation=parent.repository_generation,
            resource_id=resource_id,
            operation=operation,
            arguments=arguments,
        )
        return self._persistence.accept(accepted.peer, request)

    def _execute_runtime_replacement(
        self, accepted: AcceptedBrokerRequest
    ) -> Mapping[str, Any]:
        """Replace one Compose-backed container with durable identity/data proof."""

        request = accepted.request
        existing = self._persistence.existing_operation_disposition(accepted)
        journal = self._persistence.runtime_replacement_record(accepted)
        if existing is not None and existing.state == "completed":
            return dict(existing.result or {})
        if existing is not None and existing.state == "failed":
            raise BrokerBackendError(
                existing.error_code or "runtime_replace_failed",
                existing.error_message or "Docker-backed replacement failed.",
                operation_id=request.operation_id,
            )

        before_observation: Mapping[str, Any] | None = None
        before_snapshot = None
        if journal is None:
            before_observation = self._observe_fresh_full_docker(
                request.operation_id, project_id=request.project_id
            )
            if before_observation.get("docker_available") is not True:
                raise BrokerBackendError(
                    "lifecycle_observation_incomplete",
                    "Replacement requires an available fresh service-owned Docker observation; no resource was changed.",
                    operation_id=request.operation_id,
                )
            before_snapshot = load_broker_runtime_snapshot(
                accepted, persistence=self._persistence
            )
            blocked = unclassified_broker_runtime_report(
                accepted,
                snapshot=before_snapshot,
                observation=before_observation,
            )
            if blocked is not None:
                return blocked
            if existing is None:
                disposition = self._persistence.reserve_operation(accepted)
                if disposition.state == "completed":
                    return dict(disposition.result or {})
                if disposition.state == "failed":
                    raise BrokerBackendError(
                        disposition.error_code or "runtime_replace_failed",
                        disposition.error_message
                        or "Docker-backed replacement failed.",
                        operation_id=request.operation_id,
                    )
                if disposition.state not in {"execute", "pending", "reconcile"}:
                    raise BrokerBackendError(
                        "operation_in_progress",
                        "Replacement durable reservation is not executable.",
                        operation_id=request.operation_id,
                    )
            try:
                target = self._persistence.runtime_docker_target(accepted)
                session_id = self._persistence.begin_broker_runtime_session(
                    accepted, target=target
                )
                journal = self._persistence.prepare_runtime_replacement(
                    accepted, evidence=before_observation
                )
                self._runtime_reaper_wake.set()
            except BrokerError as error:
                self._record_failure(
                    request.operation_id,
                    code=error.code,
                    message=error.message,
                )
                raise BrokerBackendError(
                    error.code,
                    error.message,
                    operation_id=request.operation_id,
                ) from None
        else:
            session_id = self._persistence.broker_runtime_session_id(
                request.operation_id
            )
            if session_id is None:
                raise BrokerBackendError(
                    "operation_state_conflict",
                    "Replacement lost its durable cleanup session.",
                    operation_id=request.operation_id,
                )

        assert journal is not None
        backup_result: Mapping[str, Any] | None = None
        if journal.resource_kind == "database_stack":
            if journal.database_backup_id is None:
                assert journal.backup_operation_id is not None
                assert journal.database_binding_id is not None
                assert journal.database_name is not None
                backup_request = self._runtime_replacement_subrequest(
                    accepted,
                    operation_id=journal.backup_operation_id,
                    resource_id=journal.database_binding_id,
                    operation=BrokerOperation.DATABASE_BACKUP,
                    arguments={"database_name": journal.database_name},
                )
                backup_result = self.execute(backup_request)
                backup_id = str(
                    backup_result.get("database_backup_id") or ""
                )
                journal = self._persistence.record_runtime_replacement_backup(
                    accepted, database_backup_id=backup_id
                )
            else:
                backup_result = {
                    "database_backup_id": journal.database_backup_id,
                    "verification_status": "strong",
                    "status": "available",
                    "replayed": True,
                }

        compose_request = self._runtime_replacement_subrequest(
            accepted,
            operation_id=journal.compose_operation_id,
            resource_id=journal.compose_definition_id,
            operation=BrokerOperation.COMPOSE_UP,
            arguments={
                "service": journal.compose_service,
                "force_recreate": True,
                "wait_timeout_seconds": 600,
            },
        )
        compose_result: Mapping[str, Any] | None = None
        replacement_observation: Mapping[str, Any] | None = None
        if journal.phase not in {
            "rebound",
            "restore_intent",
            "restore_complete",
            "terminal",
        }:
            try:
                compose_result = self.execute(compose_request)
            except BrokerBackendError as error:
                if error.code != "operation_outcome_uncertain":
                    raise
                # A lost Compose result is never reissued. Fresh exact state
                # may still prove the new identity required by replacement;
                # settle the nested generic operation as uncertain/failed and
                # let the parent replacement own the stronger identity proof.
                replacement_observation = self._observe_fresh_full_docker(
                    request.operation_id, project_id=request.project_id
                )
                self._persistence.reconcile_compose_operation(
                    journal.compose_operation_id,
                    evidence=replacement_observation,
                    accepted=compose_request,
                )
                compose_result = {
                    "action": "up",
                    "reconciled_without_reexecution": True,
                    "nested_operation_status": "uncertain_terminal_failure",
                }
            if replacement_observation is None:
                replacement_observation = self._observe_fresh_full_docker(
                    request.operation_id, project_id=request.project_id
                )
            journal = self._persistence.rebind_runtime_replacement(
                accepted, evidence=replacement_observation
            )
        else:
            replacement_observation = {
                "status": "already_rebound",
                "new_docker_resource_id": journal.new_docker_resource_id,
                "new_full_container_id": journal.new_full_container_id,
            }

        restore_result: Mapping[str, Any] | None = None
        if journal.resource_kind == "database_stack" and journal.phase not in {
            "restore_complete",
            "terminal",
        }:
            phase_before_restore = journal.phase
            target, backup, saved_restore = (
                self._persistence.begin_runtime_replacement_restore(accepted)
            )
            if saved_restore is None:
                recovered_restore: Mapping[str, Any] | None = None
                if phase_before_restore == "restore_intent":
                    recovered_restore = (
                        self._host_mutations.postgres_reconcile_restore(
                            target,
                            backup,
                            safety_output_root=str(
                                self._postgres_backup_root / "pre-restore"
                            ),
                        )
                    )
                    if recovered_restore is None:
                        raise BrokerBackendError(
                            "operation_outcome_uncertain",
                            "The prior PostgreSQL restore has no exact durable completion proof; it was not reexecuted.",
                            operation_id=request.operation_id,
                        )
                raw_restore = (
                    recovered_restore
                    if recovered_restore is not None
                    else self._host_mutations.postgres_restore(
                        target,
                        backup,
                        safety_output_root=str(
                            self._postgres_backup_root / "pre-restore"
                        ),
                    )
                )
                saved_restore = self._persistence.save_runtime_replacement_restore_result(
                    accepted, result=_json_safe_mapping(raw_restore)
                )
            restore_result = self._persistence.complete_runtime_replacement_restore(
                accepted,
                target=target,
                backup=backup,
                result=saved_restore,
            )
            journal = self._persistence.runtime_replacement_record(accepted)
            assert journal is not None
        elif journal.resource_kind == "database_stack":
            restore_result = {
                "database_backup_id": journal.database_backup_id,
                "status": "restored",
                "replayed": True,
            }

        if journal.new_docker_resource_id is None or journal.new_full_container_id is None:
            raise BrokerBackendError(
                "runtime_replace_identity_unproven",
                "Replacement has no exact new immutable container identity.",
                operation_id=request.operation_id,
            )
        current_resource_id = (
            journal.new_docker_resource_id
            if journal.resource_kind == "docker"
            else journal.requested_resource_id
        )
        report = {
            "schema_version": 1,
            "ok": True,
            "ready": True,
            "action": "replace",
            "classification": "ready",
            "authority": "broker",
            "operation_id": request.operation_id,
            "repository": {
                "root_repo_id": request.arguments["root_repo_id"],
                "effective_repo_id": request.project_id,
                "kind": (
                    "temporary"
                    if request.arguments["temporary_repo_id"] is not None
                    else "root"
                ),
            },
            # Preserve the submitted logical target for the wire reply. Docker
            # callers receive the new physical ID below and use it thereafter.
            "target": {
                "kind": journal.resource_kind,
                "id": journal.requested_resource_id,
            },
            "run_id": session_id,
            "replacement": {
                "state": "created",
                "compose_definition_id": journal.compose_definition_id,
                "compose_service": journal.compose_service,
                "previous": {
                    "docker_resource_id": journal.old_docker_resource_id,
                    "full_container_id": journal.old_full_container_id,
                },
                "current": {
                    "resource_id": current_resource_id,
                    "docker_resource_id": journal.new_docker_resource_id,
                    "full_container_id": journal.new_full_container_id,
                },
                "old_identity_absent": True,
                "volumes_preserved_from_sealed_model": True,
                "dependencies_recreated": False,
                "backup": None
                if backup_result is None
                else dict(backup_result),
                "restore": None
                if restore_result is None
                else dict(restore_result),
                "data_preservation_verified": (
                    journal.resource_kind == "docker"
                    or restore_result is not None
                ),
                "cleanup": {
                    "ttl_seconds": request.arguments["ttl_seconds"],
                    "kill_after_run": bool(
                        request.arguments["kill_after_run"]
                    ),
                    "created_resource_disposition": (
                        "remove"
                        if request.arguments["ttl_seconds"] is not None
                        or bool(request.arguments["kill_after_run"])
                        else "retain"
                    ),
                },
            },
            "observation": {
                "before": before_observation,
                "after": replacement_observation,
            },
            "compose": None
            if compose_result is None
            else dict(compose_result),
        }
        try:
            self._persistence.finish_runtime_replacement(
                accepted, result=report
            )
        except Exception as error:
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "Replacement completed but its durable terminal report did not commit; retry only this operation ID.",
                operation_id=request.operation_id,
            ) from error
        if bool(request.arguments["kill_after_run"]):
            # The session expiry is the operation creation time, so this turn
            # performs the same idempotent cleanup the background reaper will
            # recover after a crash or lost reply.
            self.reap_broker_runtime_sessions_once()
        return report

    def _execute_runtime_request(
        self, accepted: AcceptedBrokerRequest
    ) -> Mapping[str, Any]:
        """Execute an ID-only shared runtime request through broker authority."""

        request = accepted.request
        action = str(request.arguments["action"])
        target_kind = str(request.arguments["target_kind"])
        if action == "temporary_start":
            return self._execute_temporary_dev_service(accepted)
        if action == "capture_logs":
            if target_kind == "service":
                temporary = self._persistence.temporary_service_status(
                    accepted
                )
                if temporary is not None:
                    return self._execute_temporary_service_log_capture(
                        accepted, temporary=temporary
                    )
                return self._execute_runtime_service_log_capture(accepted)
            return self._execute_runtime_log_capture(accepted)
        if action == "status":
            if target_kind == "service":
                temporary = self._persistence.temporary_service_status(
                    accepted
                )
                if temporary is not None:
                    observed = self._temporary_dev_services.status(
                        unit=str(temporary["unit"]),
                        port=int(temporary["port"]),
                    )
                    expired = bool(temporary["expired"])
                    observed_state = str(observed["state"])
                    if expired:
                        state = (
                            "expired"
                            if observed_state == "stopped"
                            else "cleanup_pending"
                        )
                    else:
                        state = observed_state
                    ready = state == "running"
                    snapshot = load_broker_runtime_snapshot(
                        accepted, persistence=self._persistence
                    )
                    return build_broker_runtime_snapshot_report(
                        accepted,
                        snapshot=snapshot,
                        action_result={
                            "ok": True,
                            "classification": (
                                "ready"
                                if ready
                                else "expired"
                                if state == "expired"
                                else "cleanup_pending"
                                if state == "cleanup_pending"
                                else "observed_not_ready"
                            ),
                            "ready": ready,
                            "authority": "broker_temporary_service",
                            "operation_id": request.operation_id,
                            "state": state,
                            "resource_id": request.resource_id,
                            "name": temporary["name"],
                            "url": temporary["url"],
                            "expires_at": temporary["expires_at"],
                            "cleanup": temporary["cleanup"],
                            "session_id": temporary["session_id"],
                            "main_pid": observed["main_pid"],
                        },
                    )
                if self._persistence.runtime_service_has_supervision(accepted):
                    return self._execute_worker_runtime_request(
                        accepted,
                        service_role=self._persistence.runtime_service_role(
                            accepted
                        ),
                    )
            # Unsupervised service and container status remains an
            # authority-owned committed host observation.
            observation = self._observe_committed_host(request.operation_id)
            return execute_broker_runtime_request(
                accepted,
                persistence=self._persistence,
                observation=observation,
            )

        if target_kind == "service":
            role = self._persistence.runtime_service_role(accepted)
            if str(role or "").lower() == "temporary":
                temporary = self._persistence.temporary_service_status(
                    accepted
                )
                if temporary is None:
                    raise BrokerBackendError(
                        "temporary_service_catalog_invalid",
                        "The temporary service has no retained lifecycle identity.",
                        operation_id=request.operation_id,
                    )
                return self._execute_temporary_service_runtime_request(
                    accepted, temporary=temporary
                )
            return self._execute_worker_runtime_request(
                accepted, service_role=role
            )
        if action == "replace":
            return self._execute_runtime_replacement(accepted)
        existing = self._persistence.existing_operation_disposition(accepted)
        if existing is not None:
            if existing.state == "completed":
                return dict(existing.result or {})
            if existing.state == "reconcile":
                return self._reconcile_runtime_request(accepted)
            if existing.state == "failed":
                raise BrokerBackendError(
                    existing.error_code or "mutation_failed",
                    existing.error_message or "Broker runtime mutation failed.",
                    operation_id=request.operation_id,
                )
            raise BrokerBackendError(
                "operation_in_progress",
                "This durable runtime operation is pending or requires reconciliation; it was not executed again.",
                operation_id=request.operation_id,
            )

        before_observation = self._observe_fresh_full_docker(
            request.operation_id, project_id=request.project_id
        )
        if before_observation.get("docker_available") is not True:
            raise BrokerBackendError(
                "lifecycle_observation_incomplete",
                "Docker lifecycle requires an available fresh service-owned Docker observation; no resource was changed.",
                operation_id=request.operation_id,
            )
        before_snapshot = load_broker_runtime_snapshot(
            accepted, persistence=self._persistence
        )
        blocked = unclassified_broker_runtime_report(
            accepted,
            snapshot=before_snapshot,
            observation=before_observation,
        )
        if blocked is not None:
            return blocked

        disposition = self._persistence.reserve_operation(accepted)
        if disposition.state == "completed":
            return dict(disposition.result or {})
        if disposition.state == "failed":
            raise BrokerBackendError(
                disposition.error_code or "mutation_failed",
                disposition.error_message or "Broker runtime mutation failed.",
                operation_id=request.operation_id,
            )
        if disposition.state == "pending":
            raise BrokerBackendError(
                "operation_in_progress",
                "This durable runtime operation is pending or requires reconciliation; it was not executed again.",
                operation_id=request.operation_id,
            )

        try:
            target = self._persistence.runtime_docker_target(accepted)
            session_id = self._persistence.begin_broker_runtime_session(
                accepted, target=target
            )
            self._runtime_reaper_wake.set()
        except BrokerError as exc:
            self._record_failure(
                request.operation_id, code=exc.code, message=exc.message
            )
            raise BrokerBackendError(
                exc.code, exc.message, operation_id=request.operation_id
            ) from None

        try:
            with self._runtime_session_mutation_lock:
                if action == "start":
                    raw_result = self._host_mutations.docker_start(target)
                elif action == "stop":
                    raw_result = self._host_mutations.docker_stop(target)
                elif action == "restart":
                    raw_result = self._host_mutations.docker_restart(target)
                else:  # wire validation makes this unreachable
                    raise BrokerBackendError(
                        "unsupported_runtime_action",
                        "Unsupported shared runtime lifecycle action.",
                        operation_id=request.operation_id,
                    )
        except Exception:
            self._raise_runtime_outcome_uncertain(
                request.operation_id,
                action=action,
                failed_phase="host_invocation",
                message=(
                    "Docker runtime invocation did not prove a terminal host outcome; "
                    "fresh reconciliation is required."
                ),
            )

        try:
            after_observation = self._observe_fresh_full_docker(
                request.operation_id, project_id=request.project_id
            )
            after_snapshot = load_broker_runtime_snapshot(
                accepted, persistence=self._persistence
            )
        except Exception as exc:
            self._raise_runtime_outcome_uncertain(
                request.operation_id,
                action=action,
                failed_phase="observation",
                message=(
                    "Docker runtime action completed but authoritative final "
                    "observation did not commit; reconciliation is required."
                ),
                cause=exc,
                failure_code=_observation_failure_code(exc),
            )

        try:
            final_target = self._persistence.runtime_docker_target(accepted)
        except BrokerError as exc:
            if exc.code != "stale_resource_definition":
                self._record_failure(
                    request.operation_id, code=exc.code, message=exc.message
                )
                raise BrokerBackendError(
                    exc.code, exc.message, operation_id=request.operation_id
                ) from None
            code = "lifecycle_target_identity_changed"
            message = "Runtime target changed immutable Docker identity after the host action."
            self._record_failure(request.operation_id, code=code, message=message)
            raise BrokerBackendError(
                code, message, operation_id=request.operation_id
            ) from None
        stable_target = (
            target.resource_kind,
            target.resource_id,
            target.docker_resource_id,
            target.full_container_id,
            target.database_binding_id,
            target.database_name,
            target.immutable_fingerprint,
        )
        stable_final_target = (
            final_target.resource_kind,
            final_target.resource_id,
            final_target.docker_resource_id,
            final_target.full_container_id,
            final_target.database_binding_id,
            final_target.database_name,
            final_target.immutable_fingerprint,
        )
        if stable_final_target != stable_target:
            code = "lifecycle_target_identity_changed"
            message = "Runtime target changed immutable Docker identity after the host action."
            self._record_failure(request.operation_id, code=code, message=message)
            raise BrokerBackendError(
                code, message, operation_id=request.operation_id
            )

        final_blocked = unclassified_broker_runtime_report(
            accepted,
            snapshot=after_snapshot,
            observation=after_observation,
        )
        expected_database_stop_retirement = (
            action == "stop"
            and target.resource_kind == "database_stack"
            and not after_snapshot.classification_evidence
            and len(after_snapshot.matching_resources) == 0
        )
        if final_blocked is not None and not expected_database_stop_retirement:
            code = "unclassified_resource"
            message = "Runtime family became unclassified after the host action."
            self._record_failure(request.operation_id, code=code, message=message)
            raise BrokerBackendError(
                code, message, operation_id=request.operation_id
            )

        mutation_result = _json_safe_mapping(raw_result)
        mutation_result.update(
            {
                "ok": True,
                "terminal_state_pending": True,
                "authority": "broker",
                "operation_id": request.operation_id,
                "runtime_target": {
                    "resource_kind": target.resource_kind,
                    "resource_id": target.resource_id,
                    "docker_resource_id": target.docker_resource_id,
                    "full_container_id": target.full_container_id,
                },
                "observation": {
                    "before": before_observation,
                    "after": after_observation,
                },
            }
        )
        terminal = validate_runtime_terminal_state(
            request=after_snapshot.runtime_request,
            action_result=mutation_result,
            observation=after_observation,
            inventory=after_snapshot.inventory,
            pre_inventory=before_snapshot.inventory,
        )
        if terminal.get("ok") is not True:
            code = str(terminal.get("classification") or "runtime_terminal_state_mismatch")
            message = str(
                terminal.get("error")
                or "Runtime target did not reach the requested terminal state."
            )
            self._record_failure(request.operation_id, code=code, message=message)
            raise BrokerBackendError(
                code, message, operation_id=request.operation_id
            )
        report = build_broker_runtime_snapshot_report(
            accepted,
            snapshot=after_snapshot,
            action_result=terminal,
        )
        report["run_id"] = session_id
        try:
            self._persistence.finish_operation(
                request.operation_id, result=report
            )
        except Exception as exc:
            self._raise_runtime_outcome_uncertain(
                request.operation_id,
                action=action,
                failed_phase="journal_commit",
                message=(
                    "Runtime action completed but its durable result could not be "
                    "committed; reconciliation is required."
                ),
                cause=exc,
            )
        return report

    def _execute_temporary_dev_service(
        self, accepted: AcceptedBrokerRequest
    ) -> Mapping[str, Any]:
        """Start one repository-owned transient service with TTL cleanup."""

        request = accepted.request
        existing = self._persistence.existing_operation_disposition(accepted)
        if existing is not None:
            if existing.state == "completed":
                return dict(existing.result or {})
            if existing.state == "failed":
                raise BrokerBackendError(
                    existing.error_code or "mutation_failed",
                    existing.error_message or "Temporary service launch failed.",
                    operation_id=request.operation_id,
                )
            if existing.state not in {"pending", "reconcile"}:
                raise BrokerBackendError(
                    "operation_in_progress",
                    "This exact temporary-service operation is already in progress; follow its operation handle.",
                    operation_id=request.operation_id,
                )

        disposition = (
            existing
            if existing is not None
            else self._persistence.reserve_operation(accepted)
        )
        if disposition.state == "completed":
            return dict(disposition.result or {})
        if disposition.state == "failed":
            raise BrokerBackendError(
                disposition.error_code or "mutation_failed",
                disposition.error_message or "Temporary service launch failed.",
                operation_id=request.operation_id,
            )
        # A retry after the client lost the launch reply must converge through
        # the deterministic systemd unit.  ``TemporaryDevServiceManager.start``
        # proves and reuses that exact unit; returning operation_in_progress
        # here would strand the durable operation forever after any uncertain
        # transport outcome.
        if disposition.state not in {"execute", "pending", "reconcile"}:
            raise BrokerBackendError(
                "operation_in_progress",
                "This exact temporary-service operation is already in progress; follow its operation handle.",
                operation_id=request.operation_id,
            )

        try:
            expires_at, remaining_ttl_seconds = (
                self._persistence.temporary_service_launch_deadline(accepted)
            )
            predecessor = self._persistence.temporary_service_predecessor(
                accepted
            )
            if predecessor is not None:
                predecessor_state = self._temporary_dev_services.status(
                    unit=str(predecessor["unit"]),
                    port=int(predecessor["port"]),
                )
                if predecessor_state["state"] in {"running", "starting"}:
                    raise TemporaryDevServiceError(
                        "temporary_service_name_active",
                        "a temporary service with this repository/name identity is still active; use its exact status or wait for its TTL",
                    )
            execution = self._persistence.temporary_service_execution_context(
                accepted
            )
            if execution.generation != request.repository_generation:
                raise TemporaryDevServiceError(
                    "project_generation_stale",
                    "repository generation changed before temporary service launch",
                )
            descriptor = TemporaryDevServiceRequest(
                operation_id=request.operation_id,
                repository_id=request.project_id,
                repository_root=execution.canonical_root,
                repository_generation=execution.generation,
                execution_uid=execution.execution_uid,
                agent=str(request.arguments["agent"]),
                name=str(request.arguments["name"]),
                argv=tuple(str(item) for item in request.arguments["argv"]),
                cwd=str(request.arguments["cwd"]),
                port=int(request.arguments["port"]),
                ttl_seconds=remaining_ttl_seconds,
                kill_after_run=bool(request.arguments["kill_after_run"]),
                launch_timeout_seconds=int(
                    request.arguments["launch_timeout_seconds"]
                ),
            )
            result = dict(self._temporary_dev_services.start(descriptor))
            result["expires_at"] = expires_at
            result["cleanup"] = {
                **dict(result.get("cleanup") or {}),
                "ttl_seconds": int(request.arguments["ttl_seconds"]),
                "kill_after_run": bool(request.arguments["kill_after_run"]),
            }
            result["schema_version"] = 1
            result = self._persistence.finish_temporary_dev_service(
                accepted, result=result
            )
            return result
        except TemporaryDevServiceError as error:
            public_message = public_temporary_dev_service_error(error)
            self._record_failure(
                request.operation_id, code=error.code, message=public_message
            )
            raise BrokerBackendError(
                error.code,
                public_message,
                operation_id=request.operation_id,
            ) from error
        except BrokerError as error:
            self._record_failure(
                request.operation_id, code=error.code, message=error.message
            )
            raise BrokerBackendError(
                error.code,
                error.message,
                operation_id=request.operation_id,
            ) from error
        except Exception as error:
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "The temporary service launch or its durable result commit is uncertain; follow only this operation ID.",
                operation_id=request.operation_id,
            ) from error

    def _execute_runtime_log_capture(
        self, accepted: AcceptedBrokerRequest
    ) -> Mapping[str, Any]:
        """Capture and descriptor-verify one exact Docker-backed log artifact."""

        request = accepted.request
        before = self._persistence.runtime_docker_read_target(accepted)
        try:
            raw, discarded = self._host_mutations.docker_capture_logs(before)
            after = self._persistence.runtime_docker_read_target(accepted)
            if after.immutable_fingerprint != before.immutable_fingerprint:
                raise BrokerBackendError(
                    "runtime_resource_identity_changed",
                    "The exact runtime identity changed during log capture; no artifact was published.",
                    operation_id=request.operation_id,
                )
            capture = persist_runtime_log_artifact(
                root=self._runtime_log_root,
                artifact_kind=before.resource_kind,
                target_resource_id=before.resource_id,
                docker_resource_id=before.docker_resource_id,
                full_container_id=before.full_container_id,
                raw=raw,
                request=dict(request.arguments),
                input_discarded_bytes=discarded,
            )
        except BrokerBackendError as error:
            after = self._persistence.runtime_docker_read_target(accepted)
            if (
                after.immutable_fingerprint != before.immutable_fingerprint
                or error.code == "runtime_resource_identity_changed"
            ):
                raise BrokerBackendError(
                    "runtime_resource_identity_changed",
                    "The exact runtime identity changed during log capture; no retained artifact was returned.",
                    operation_id=request.operation_id,
                ) from error
            retained = load_latest_runtime_log_artifact(
                root=self._runtime_log_root,
                artifact_kind=before.resource_kind,
                target_resource_id=before.resource_id,
                docker_resource_id=before.docker_resource_id,
                full_container_id=before.full_container_id,
            )
            if retained is None:
                raise
            capture = retained

        manifest, payload = read_runtime_log_artifact(
            root=self._runtime_log_root,
            artifact_kind=before.resource_kind,
            artifact_id=str(capture["artifact_id"]),
        )
        if (
            manifest.get("target_resource_id") != before.resource_id
            or manifest.get("docker_resource_id") != before.docker_resource_id
            or str(manifest.get("full_container_id") or "").lower()
            != before.full_container_id
        ):
            raise BrokerBackendError(
                "runtime_log_artifact_identity_mismatch",
                "The runtime log artifact does not match the exact accepted target.",
                operation_id=request.operation_id,
            )
        public_artifact = {
            key: value for key, value in capture.items() if key != "path"
        }
        return {
            "schema_version": 1,
            "ok": True,
            "action": "capture_logs",
            "classification": (
                "retained" if capture.get("retained") is True else "available"
            ),
            "repository": {
                "root_repo_id": request.arguments["root_repo_id"],
                "effective_repo_id": request.project_id,
                "kind": (
                    "temporary"
                    if request.arguments["temporary_repo_id"] is not None
                    else "root"
                ),
            },
            "target": {
                "kind": before.resource_kind,
                "id": before.resource_id,
            },
            "artifact": public_artifact,
            "artifact_content": {
                "artifact_id": manifest["artifact_id"],
                "text": payload.decode("utf-8", errors="strict"),
            },
        }

    def _execute_temporary_service_log_capture(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        temporary: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Capture journal evidence for one exact retained transient unit."""

        request = accepted.request
        try:
            observed = self._temporary_dev_services.capture_logs(
                unit=str(temporary["unit"]), port=int(temporary["port"])
            )
        except TemporaryDevServiceError as error:
            raise BrokerBackendError(
                error.code,
                public_temporary_dev_service_error(error),
                operation_id=request.operation_id,
            ) from None
        capture = persist_service_log_artifact(
            root=self._runtime_log_root,
            target_resource_id=request.resource_id,
            definition_fingerprint=str(temporary["definition_fingerprint"]),
            source_file_identity=str(observed["source_identity"]),
            raw=bytes(observed["raw"]),
            request=dict(request.arguments),
        )
        manifest, payload = read_runtime_log_artifact(
            root=self._runtime_log_root,
            artifact_kind="service",
            artifact_id=str(capture["artifact_id"]),
        )
        public_artifact = {
            key: value for key, value in capture.items() if key != "path"
        }
        return {
            "schema_version": 1,
            "ok": True,
            "action": "capture_logs",
            "classification": "available",
            "repository": {
                "root_repo_id": request.arguments["root_repo_id"],
                "effective_repo_id": request.project_id,
                "kind": (
                    "temporary"
                    if request.arguments["temporary_repo_id"] is not None
                    else "root"
                ),
            },
            "target": {"kind": "service", "id": request.resource_id},
            "artifact": public_artifact,
            "artifact_content": {
                "artifact_id": manifest["artifact_id"],
                "text": payload.decode("utf-8", errors="strict"),
            },
        }

    def _execute_temporary_service_runtime_request(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        temporary: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Stop or restart one broker-created transient service by retained ID."""

        request = accepted.request
        action = str(request.arguments["action"])
        if action not in {"stop", "restart"}:
            raise BrokerBackendError(
                "temporary_service_action_unsupported",
                "Temporary services support status, capture_logs, stop, and restart.",
                operation_id=request.operation_id,
            )
        disposition = self._persistence.existing_operation_disposition(accepted)
        if disposition is None:
            disposition = self._persistence.reserve_operation(accepted)
        if disposition.state == "completed":
            return dict(disposition.result or {})
        if disposition.state == "failed":
            raise BrokerBackendError(
                disposition.error_code or "temporary_service_control_failed",
                disposition.error_message or "Temporary service control failed.",
                operation_id=request.operation_id,
            )
        if disposition.state != "execute":
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "The temporary service operation is pending; inspect exact status before retrying.",
                operation_id=request.operation_id,
            )
        try:
            if action == "stop":
                controlled = self._temporary_dev_services.stop(
                    unit=str(temporary["unit"]), port=int(temporary["port"])
                )
            else:
                if temporary.get("expired") is True:
                    raise TemporaryDevServiceError(
                        "temporary_service_expired",
                        "the retained temporary service TTL has expired; launch it again",
                    )
                controlled = self._temporary_dev_services.restart(
                    unit=str(temporary["unit"]),
                    port=int(temporary["port"]),
                    execution_uid=int(temporary["execution_uid"]),
                )
        except TemporaryDevServiceError as error:
            if error.code != "operation_outcome_uncertain":
                self._record_failure(
                    request.operation_id,
                    code=error.code,
                    message=public_temporary_dev_service_error(error),
                )
            raise BrokerBackendError(
                error.code,
                public_temporary_dev_service_error(error),
                operation_id=request.operation_id,
            ) from None
        state = str(controlled.get("state") or "unknown")
        ready = state == "running" and controlled.get("ready") is True
        snapshot = load_broker_runtime_snapshot(
            accepted, persistence=self._persistence
        )
        report = build_broker_runtime_snapshot_report(
            accepted,
            snapshot=snapshot,
            action_result={
                **dict(controlled),
                "ok": state == "stopped" if action == "stop" else ready,
                "ready": ready,
                "state": state,
                "classification": "ready" if ready else "stopped",
                "authority": "broker_temporary_service",
                "operation_id": request.operation_id,
            },
        )
        try:
            self._persistence.finish_operation(
                request.operation_id, result=report
            )
        except Exception as error:
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "Temporary service control completed but its durable result did not commit; inspect exact status.",
                operation_id=request.operation_id,
            ) from error
        return report

    def _execute_runtime_service_log_capture(
        self, accepted: AcceptedBrokerRequest
    ) -> Mapping[str, Any]:
        """Capture one service-definition log through root broker authority."""

        request = accepted.request
        before = self._persistence.runtime_service_log_target(accepted)
        raw, discarded, source_identity = self._host_mutations.service_capture_logs(
            before
        )
        after = self._persistence.runtime_service_log_target(accepted)
        if after != before:
            raise BrokerBackendError(
                "runtime_resource_identity_changed",
                "The exact service definition changed during log capture; no artifact was published.",
                operation_id=request.operation_id,
            )
        capture = persist_service_log_artifact(
            root=self._runtime_log_root,
            target_resource_id=before.server_definition_id,
            definition_fingerprint=before.definition_fingerprint,
            source_file_identity=source_identity,
            raw=raw,
            request=dict(request.arguments),
            input_discarded_bytes=discarded,
        )
        manifest, payload = read_runtime_log_artifact(
            root=self._runtime_log_root,
            artifact_kind="service",
            artifact_id=str(capture["artifact_id"]),
        )
        if (
            manifest.get("target_resource_id") != before.server_definition_id
            or manifest.get("definition_fingerprint")
            != before.definition_fingerprint
            or manifest.get("source_file_identity") != source_identity
        ):
            raise BrokerBackendError(
                "runtime_log_artifact_identity_mismatch",
                "The service log artifact does not match the exact accepted definition.",
                operation_id=request.operation_id,
            )
        public_artifact = {
            key: value for key, value in capture.items() if key != "path"
        }
        return {
            "schema_version": 1,
            "ok": True,
            "action": "capture_logs",
            "classification": "available",
            "repository": {
                "root_repo_id": request.arguments["root_repo_id"],
                "effective_repo_id": request.project_id,
                "kind": (
                    "temporary"
                    if request.arguments["temporary_repo_id"] is not None
                    else "root"
                ),
            },
            "target": {"kind": "service", "id": before.server_definition_id},
            "artifact": public_artifact,
            "artifact_content": {
                "artifact_id": manifest["artifact_id"],
                "text": payload.decode("utf-8", errors="strict"),
            },
        }

    def _execute_worker_runtime_request(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        service_role: str | None,
    ) -> Mapping[str, Any]:
        """Control one exact service under its configured execution owner."""

        request = accepted.request
        action = str(request.arguments["action"])
        if (
            action != "status"
            and (
                request.arguments["purpose"] != "development"
                or request.arguments["ttl_seconds"] is not None
                or request.arguments["kill_after_run"] is not False
            )
        ):
            raise BrokerBackendError(
                "supervised_service_purpose_conflict",
                "Persistent supervised services require purpose=development, ttl_seconds=null, and kill_after_run=false.",
                operation_id=request.operation_id,
            )

        snapshot = load_broker_runtime_snapshot(
            accepted, persistence=self._persistence
        )
        blocked = unclassified_broker_runtime_report(
            accepted,
            snapshot=snapshot,
            observation={"source": "broker_authoritative_inventory"},
        )
        if blocked is not None:
            return blocked
        target = snapshot.matching_resources[0]
        name = target.get("name")
        if not isinstance(name, str) or not name:
            raise BrokerBackendError(
                "worker_identity_unavailable",
                "The exact service has no immutable worker name.",
                operation_id=request.operation_id,
            )
        canonical_repository = (
            snapshot.context["temporary_repo"]
            if snapshot.context["temporary_repo"] is not None
            else snapshot.context["root_repo"]
        )
        if not isinstance(canonical_repository, str) or not canonical_repository:
            raise BrokerBackendError(
                "worker_identity_unavailable",
                "The exact worker repository path is unavailable to system authority.",
                operation_id=request.operation_id,
            )
        execution_uid = self._persistence.worker_execution_uid(accepted)
        replacement_definition: dict[str, Any] | None = None
        if action == "replace":
            replacement_definition = _validated_broker_worker_replacement(
                canonical_repository=canonical_repository,
                execution_uid=execution_uid,
                arguments=request.arguments,
                operation_id=request.operation_id,
            )
        endpoint_target = self._persistence.runtime_service_endpoint_target(
            accepted
        )

        if action != "status":
            existing = self._persistence.existing_operation_disposition(accepted)
            if existing is not None:
                if existing.state == "completed":
                    return dict(existing.result or {})
                if existing.state == "failed":
                    raise BrokerBackendError(
                        existing.error_code or "worker_control_failed",
                        existing.error_message or "Worker control failed.",
                        operation_id=request.operation_id,
                    )
                raise BrokerBackendError(
                    "worker_operation_uncertain",
                    "This exact worker control operation is pending; inspect status before issuing a new operation.",
                    operation_id=request.operation_id,
                )
            disposition = self._persistence.reserve_operation(accepted)
            if disposition.state == "completed":
                return dict(disposition.result or {})
            if disposition.state == "failed":
                raise BrokerBackendError(
                    disposition.error_code or "worker_control_failed",
                    disposition.error_message or "Worker control failed.",
                    operation_id=request.operation_id,
                )
            if disposition.state != "execute":
                raise BrokerBackendError(
                    "worker_operation_uncertain",
                    "This exact worker control operation is pending; inspect status before issuing a new operation.",
                    operation_id=request.operation_id,
                )
            try:
                self._persistence.require_worker_runtime_operation_current(
                    accepted
                )
            except BrokerError as error:
                self._record_failure(
                    request.operation_id,
                    code=error.code,
                    message=error.message,
                )
                raise BrokerBackendError(
                    error.code,
                    error.message,
                    operation_id=request.operation_id,
                ) from None

        try:
            with AccountStore.open(
                self._persistence.database_path,
                expected_uid=self._persistence.expected_uid,
                busy_timeout_ms=self._persistence.busy_timeout_ms,
            ) as store:
                controller = WorkerController(
                    store,
                    coordinator_script=(
                        Path(__file__).resolve().parent.parent
                        / "dev_coordinator.py"
                    ),
                    execution_uid=execution_uid,
                )
                identity = {
                    "worker_id": request.resource_id,
                    "canonical_repository": canonical_repository,
                    "name": name,
                }
                requested_keep_alive = request.arguments.get("keep_alive")
                if (
                    requested_keep_alive is None
                    and not isinstance(target.get("supervision"), Mapping)
                    and str(service_role or "").lower() != "worker"
                ):
                    requested_keep_alive = False
                if action == "status":
                    controlled = controller.status(**identity)
                elif action == "start":
                    controlled = controller.start(
                        **identity,
                        actor=str(request.arguments["agent"]),
                        keep_alive=requested_keep_alive,
                        crash_limit=request.arguments.get("restart_limit"),
                        crash_window_seconds=request.arguments.get(
                            "restart_window_seconds"
                        ),
                        rearm=bool(
                            request.arguments.get("rearm_crash_loop", False)
                        ),
                    )
                elif action == "stop":
                    controlled = controller.stop(
                        **identity,
                        actor=str(request.arguments["agent"]),
                    )
                elif action == "restart":
                    controlled = controller.restart(
                        **identity,
                        actor=str(request.arguments["agent"]),
                        keep_alive=requested_keep_alive,
                        crash_limit=request.arguments.get("restart_limit"),
                        crash_window_seconds=request.arguments.get(
                            "restart_window_seconds"
                        ),
                        rearm=bool(
                            request.arguments.get("rearm_crash_loop", False)
                        ),
                    )
                elif action == "replace":
                    if replacement_definition is None:  # pragma: no cover
                        raise RuntimeError("validated replacement definition is missing")
                    controlled = controller.replace(
                        **identity,
                        actor=str(request.arguments["agent"]),
                        expected_generation=int(
                            request.arguments["expected_definition_generation"]
                        ),
                        argv=replacement_definition["argv"],
                        cwd=replacement_definition["cwd"],
                        environment=replacement_definition["environment"],
                        keep_alive=request.arguments.get("keep_alive"),
                        crash_limit=request.arguments.get("restart_limit"),
                        crash_window_seconds=request.arguments.get(
                            "restart_window_seconds"
                        ),
                        rearm=bool(
                            request.arguments.get("rearm_crash_loop", False)
                        ),
                    )
                else:  # strict wire validation makes this unreachable
                    raise BrokerBackendError(
                        "unsupported_runtime_action",
                        "Unsupported supervised-worker action.",
                        operation_id=request.operation_id,
                    )
        except WorkerReplaceError as error:
            failure = {
                **dict(error.payload),
                "ok": False,
                "ready": False,
                "error": str(error),
                "authority": "broker_worker_supervisor",
                "broker_operation_id": request.operation_id,
            }
            try:
                after_failure = load_broker_runtime_snapshot(
                    accepted, persistence=self._persistence
                )
                report = build_broker_runtime_snapshot_report(
                    accepted,
                    snapshot=after_failure,
                    action_result=failure,
                )
                self._persistence.finish_operation(
                    request.operation_id, result=report
                )
            except Exception as commit_error:
                raise BrokerBackendError(
                    "worker_operation_uncertain",
                    "Worker replacement failed but its rollback evidence did not commit; inspect exact status before retrying.",
                    operation_id=request.operation_id,
                ) from commit_error
            return report
        except WorkerControlError as error:
            if action != "status":
                self._record_failure(
                    request.operation_id,
                    code="worker_control_rejected",
                    message=str(error),
                )
            raise BrokerBackendError(
                "worker_control_rejected",
                str(error),
                operation_id=request.operation_id,
            ) from None
        except BrokerError:
            raise
        except Exception as error:
            if action == "status":
                raise BrokerBackendError(
                    "worker_status_unavailable",
                    "System authority could not inspect the exact worker; inspect broker logs.",
                    operation_id=request.operation_id,
                ) from error
            raise BrokerBackendError(
                "worker_operation_uncertain",
                "Worker control may have changed host state but did not return complete evidence; inspect status before issuing a new operation.",
                operation_id=request.operation_id,
            ) from error

        state = str(controlled.get("status") or "unobserved").lower()
        ready = bool(
            state == "running"
            and isinstance(controlled.get("health"), Mapping)
            and controlled["health"].get("ok") is True
        )
        if action == "status":
            ok = state not in {"", "missing", "unobserved", "unknown"}
        elif action == "stop":
            ok = state == "stopped"
        else:
            ok = ready
        action_result = {
            **dict(controlled),
            "ok": ok,
            "ready": ready,
            "state": state,
            "classification": (
                "ready" if ready else "stopped" if state == "stopped" else "observed_not_ready"
            ),
            "authority": (
                "broker_worker_supervisor"
                if str(service_role or "").lower() == "worker"
                else "broker_service_supervisor"
            ),
            "operation_id": request.operation_id,
        }
        if action == "status":
            endpoint_proof = self._runtime_service_endpoint_proof(
                endpoint_target=endpoint_target,
                action="status",
                controlled=controlled,
                operation_id=request.operation_id,
            )
            endpoint_ready = bool(
                endpoint_proof.get("ready") is True
                or endpoint_proof.get("listener_required") is False
            )
            action_result.update(
                {
                    "supervision_ready": ready,
                    "endpoint_ready": endpoint_ready,
                    "endpoint_proof": endpoint_proof,
                    "ready": ready and endpoint_ready,
                    "classification": (
                        "ready"
                        if ready and endpoint_ready
                        else "observed_not_ready"
                    ),
                }
            )
        if action != "status":
            try:
                if action == "replace":
                    self._persistence.require_worker_runtime_replacement_committed(
                        accepted, replacement=controlled
                    )
                else:
                    self._persistence.require_worker_runtime_operation_current(
                        accepted
                    )
            except BrokerError as error:
                code = "lifecycle_target_identity_changed"
                message = (
                    "Worker definition or authority changed during the control action; "
                    "inspect exact worker status before retrying."
                )
                self._record_failure(
                    request.operation_id, code=code, message=message
                )
                raise BrokerBackendError(
                    code, message, operation_id=request.operation_id
                ) from error
            if action == "replace":
                endpoint_target = (
                    self._persistence.runtime_service_endpoint_target(accepted)
                )
            try:
                action_result["endpoint_proof"] = (
                    self._runtime_service_endpoint_proof(
                        endpoint_target=endpoint_target,
                        action=action,
                        controlled=controlled,
                        operation_id=request.operation_id,
                    )
                )
                endpoint_proof = action_result["endpoint_proof"]
                endpoint_ready = bool(
                    endpoint_proof.get("listener_required") is False
                    or endpoint_proof.get("state") == "listening"
                )
                action_result.update(
                    {
                        "supervision_ready": ready,
                        "endpoint_ready": endpoint_ready,
                        "ready": ready and endpoint_ready,
                        "classification": (
                            "ready"
                            if ready and endpoint_ready
                            else "observed_not_ready"
                        ),
                    }
                )
            except Exception as endpoint_error:
                rollback: Mapping[str, Any] | None = None
                if action in {"start", "restart"}:
                    try:
                        with AccountStore.open(
                            self._persistence.database_path,
                            expected_uid=self._persistence.expected_uid,
                            busy_timeout_ms=self._persistence.busy_timeout_ms,
                        ) as rollback_store:
                            rollback = WorkerController(
                                rollback_store,
                                coordinator_script=(
                                    Path(__file__).resolve().parent.parent
                                    / "dev_coordinator.py"
                                ),
                                execution_uid=execution_uid,
                            ).stop(
                                **identity,
                                actor=str(request.arguments["agent"]),
                            )
                    except Exception as rollback_error:
                        rollback = {
                            "ok": False,
                            "error_type": type(rollback_error).__name__,
                            "error": str(rollback_error),
                        }
                action_result.update(
                    {
                        "ok": False,
                        "ready": False,
                        "classification": "service_endpoint_identity_unproven",
                        "error": str(endpoint_error),
                        "endpoint_proof": {
                            "certain": False,
                            "error_type": type(endpoint_error).__name__,
                        },
                        "rollback": None if rollback is None else dict(rollback),
                    }
                )
        after = load_broker_runtime_snapshot(
            accepted, persistence=self._persistence
        )
        report = build_broker_runtime_snapshot_report(
            accepted,
            snapshot=after,
            action_result=action_result,
        )
        if action != "status":
            try:
                self._persistence.finish_operation(
                    request.operation_id, result=report
                )
            except Exception as error:
                raise BrokerBackendError(
                    "worker_operation_uncertain",
                    "Worker control completed but its durable broker result did not commit; retry only this operation ID.",
                    operation_id=request.operation_id,
                ) from error
        return report

    def _raise_runtime_outcome_uncertain(
        self,
        operation_id: str,
        *,
        action: str,
        failed_phase: str,
        message: str,
        cause: BaseException | None = None,
        failure_code: str | None = None,
    ) -> None:
        try:
            self._persistence.mark_runtime_operation_reconciliation_required(
                operation_id,
                action=action,
                failed_phase=failed_phase,
                failure_code=failure_code,
            )
        except Exception:
            # A still-running reservation remains a no-reexecution fence and
            # startup recovery promotes it to needs_attention.
            pass
        error = BrokerBackendError(
            "operation_outcome_uncertain", message, operation_id=operation_id
        )
        if cause is None:
            raise error
        raise error from cause

    def _reconcile_runtime_request(
        self, accepted: AcceptedBrokerRequest
    ) -> Mapping[str, Any]:
        """Settle an uncertain runtime operation from fresh state, never rerun it."""

        request = accepted.request
        action = str(request.arguments["action"])
        try:
            observation = self._observe_fresh_full_docker(
                request.operation_id, project_id=request.project_id
            )
            if observation.get("docker_available") is not True:
                raise RuntimeError("Docker observation is unavailable")
            snapshot = load_broker_runtime_snapshot(
                accepted, persistence=self._persistence
            )
            if unclassified_broker_runtime_report(
                accepted, snapshot=snapshot, observation=observation
            ) is not None:
                raise RuntimeError("runtime family is not exactly classified")
            target = self._persistence.runtime_docker_target(accepted)
        except BrokerError as exc:
            if exc.code == "stale_resource_definition":
                code = "lifecycle_target_identity_changed"
                message = "Runtime target changed immutable Docker identity before reconciliation."
                self._persistence.finish_runtime_reconciliation(
                    request.operation_id,
                    error_code=code,
                    error_message=message,
                )
                raise BrokerBackendError(
                    code, message, operation_id=request.operation_id
                ) from None
            raise
        except Exception as exc:
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "Runtime outcome remains uncertain because fresh exact reconciliation is unavailable.",
                operation_id=request.operation_id,
            ) from exc

        pending = {
            "ok": True,
            "terminal_state_pending": True,
            "authority": "broker",
            "operation_id": request.operation_id,
            "reconciled_without_reexecution": True,
            "runtime_target": {
                "resource_kind": target.resource_kind,
                "resource_id": target.resource_id,
                "docker_resource_id": target.docker_resource_id,
                "full_container_id": target.full_container_id,
            },
            "observation": {"after": observation},
        }
        terminal = validate_runtime_terminal_state(
            request=snapshot.runtime_request,
            action_result=pending,
            observation=observation,
            inventory=snapshot.inventory,
            pre_inventory=snapshot.inventory,
        )
        if terminal.get("ok") is not True:
            code = str(
                terminal.get("classification")
                or "runtime_terminal_state_mismatch"
            )
            message = str(
                terminal.get("error")
                or "Runtime reconciliation proved the requested state was not reached."
            )
            self._persistence.finish_runtime_reconciliation(
                request.operation_id,
                error_code=code,
                error_message=message,
            )
            raise BrokerBackendError(
                code, message, operation_id=request.operation_id
            )
        if action == "restart":
            # A fresh running state proves start, but it cannot distinguish a
            # completed restart from a restart request the daemon never
            # accepted.  Without durable transition evidence, settle neither
            # success nor failure and never reissue the host action.
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "The target is running, but fresh state alone cannot prove that the uncertain restart occurred; manual reconciliation is required.",
                operation_id=request.operation_id,
            )
        report = build_broker_runtime_snapshot_report(
            accepted, snapshot=snapshot, action_result=terminal
        )
        session_id = self._persistence.broker_runtime_session_id(
            request.operation_id
        )
        if session_id is not None:
            report["run_id"] = session_id
        try:
            self._persistence.finish_runtime_reconciliation(
                request.operation_id, result=report
            )
        except Exception as exc:
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "Runtime state was reconciled but its durable result did not commit.",
                operation_id=request.operation_id,
            ) from exc
        return report

    def _observe_committed_host(self, operation_id: str) -> dict[str, Any]:
        """Run or join an explicit host observation and verify its durable row."""

        if self._host_observation_shutdown.is_set():
            raise BrokerBackendError(
                "service_shutting_down",
                "The broker is shutting down and cannot start a host observation.",
                operation_id=operation_id,
            )
        observer = self._observe_before_lifecycle_plan
        if observer is None:
            raise BrokerBackendError(
                "lifecycle_observer_unavailable",
                "The service-owned host observer is unavailable.",
                operation_id=operation_id,
            )
        with AccountStore.open(
            self._persistence.database_path,
            expected_uid=self._persistence.expected_uid,
            busy_timeout_ms=self._persistence.busy_timeout_ms,
        ) as store:
            before = store.metadata.observation_revision
            with observation_owner_scope(
                owner_id=self._broker_instance_id,
                cancelled=self._host_observation_shutdown.is_set,
            ):
                evidence = observer(store)
            after = store.metadata.observation_revision
            state_revision = store.metadata.state_revision
            if isinstance(evidence, Mapping) and evidence.get("snapshot_id"):
                with store.read_transaction() as connection:
                    committed = connection.execute(
                        """
                        SELECT s.host_id, s.observer_domain, s.status,
                               s.material_fingerprint, s.completed_at,
                               c.observer_domain AS capability_domain,
                               c.docker_available, c.capability_fingerprint
                        FROM observation_snapshots s
                        JOIN observation_capabilities c USING(snapshot_id)
                        WHERE s.snapshot_id = ?
                        """,
                        (str(evidence["snapshot_id"]),),
                    ).fetchone()
            else:
                committed = None
        if (
            not isinstance(evidence, Mapping)
            or evidence.get("observer_domain") != _FULL_DOCKER_OBSERVER_DOMAIN
            or not evidence.get("snapshot_id")
            or not evidence.get("host_id")
            or not evidence.get("completed_at")
            or type(evidence.get("docker_available")) is not bool
            or not isinstance(evidence.get("capability_fingerprint"), str)
            or not isinstance(evidence.get("material_fingerprint"), str)
            or committed is None
            or committed["status"] != "completed"
            or str(committed["host_id"]) != str(evidence.get("host_id"))
            or committed["observer_domain"] != _FULL_DOCKER_OBSERVER_DOMAIN
            or committed["capability_domain"] != _FULL_DOCKER_OBSERVER_DOMAIN
            or bool(committed["docker_available"])
            is not bool(evidence.get("docker_available"))
            or committed["capability_fingerprint"]
            != evidence.get("capability_fingerprint")
            or committed["material_fingerprint"]
            != evidence.get("material_fingerprint")
            or committed["completed_at"] != evidence.get("completed_at")
        ):
            raise BrokerBackendError(
                "lifecycle_observation_incomplete",
                "Host observation did not return matching committed service-owned evidence.",
                operation_id=operation_id,
            )
        observed = after > before
        return {
            "schema_version": 2,
            "status": "completed" if observed else "fresh",
            "observed": observed,
            "joined": bool(evidence.get("joined")),
            "snapshot_id": str(evidence["snapshot_id"]),
            "host_id": str(committed["host_id"]),
            "observer_domain": str(committed["observer_domain"]),
            "docker_available": bool(committed["docker_available"]),
            "capability_fingerprint": str(committed["capability_fingerprint"]),
            "material_fingerprint": str(committed["material_fingerprint"]),
            "completed_at": str(committed["completed_at"]),
            "observation_revision": after,
            "state_revision": state_revision,
        }

    def _observe_fresh_full_docker(
        self,
        operation_id: str,
        *,
        project_id: str,
    ) -> dict[str, Any]:
        if self._host_observation_shutdown.is_set():
            raise BrokerBackendError(
                "service_shutting_down",
                "The broker is shutting down and cannot start a host observation.",
                operation_id=operation_id,
            )
        observer = self._observe_before_lifecycle_plan
        if observer is None:
            raise BrokerBackendError(
                "lifecycle_observer_unavailable",
                "This host mutation requires a fresh service-owned full-Docker observation.",
                operation_id=operation_id,
            )
        # The production observer builds the v2/v1 read projection before it
        # samples the host.  Open the schema-compatible service database with
        # the inventory adapter that owns that contract; a bare
        # CoordinatorStore intentionally exposes transactions only.
        with AccountStore.open(
            self._persistence.database_path,
            expected_uid=self._persistence.expected_uid,
            busy_timeout_ms=self._persistence.busy_timeout_ms,
        ) as store:
            host_id = self._persistence.repository_host_id(project_id)
            committed: dict[str, Any] | None = None
            last_error: ObservationFreshnessError | None = None
            evidence: Mapping[str, Any] | None = None
            for attempt in range(2):
                if self._host_observation_shutdown.is_set():
                    raise BrokerBackendError(
                        "service_shutting_down",
                        "The broker is shutting down and cannot start a host observation.",
                        operation_id=operation_id,
                    )
                fence = capture_observation_freshness_fence(
                    store,
                    host_id=host_id,
                )
                with observation_owner_scope(
                    owner_id=self._broker_instance_id,
                    cancelled=self._host_observation_shutdown.is_set,
                ):
                    evidence = observer(store)
                snapshot_id = (
                    str(evidence["snapshot_id"])
                    if isinstance(evidence, Mapping) and evidence.get("snapshot_id")
                    else None
                )
                joined_pre_boundary_ticket = (
                    snapshot_id is not None
                    and snapshot_id in fence.joinable_snapshot_ids
                )
                try:
                    committed = require_exact_fresh_observation(
                        store,
                        evidence=evidence,
                        fence=fence,
                        allow_joined_ticket=False,
                    )
                    break
                except ObservationFreshnessError as exc:
                    last_error = exc
                    if attempt == 0 and joined_pre_boundary_ticket:
                        continue
                    break
            if committed is None:
                raise BrokerBackendError(
                    "lifecycle_observation_incomplete",
                    "Fresh full-Docker observation did not commit bounded service-owned evidence; lifecycle planning was refused.",
                    operation_id=operation_id,
                ) from last_error
            state_revision = store.metadata.state_revision
        if committed is None:
            raise BrokerBackendError(
                "lifecycle_observation_incomplete",
                "Host observation did not return matching committed service-owned evidence.",
                operation_id=operation_id,
            )
        result = dict(committed)
        result.update(
            {
                "schema_version": 2,
                "status": "completed",
                "observed": True,
                "joined": bool(evidence.get("joined"))
                if isinstance(evidence, Mapping)
                else False,
                "host_id": host_id,
                "state_revision": state_revision,
            }
        )
        return result

    def begin_shutdown_host_observations(self) -> int:
        """Fence new claims, then durably fail this process's running tickets.

        The observer checks the same event from inside its BEGIN IMMEDIATE claim
        transaction.  Consequently a racing claim either commits its ownership
        before this cleanup transaction (and is failed here), or observes the
        fence after this transaction and is rejected.
        """

        self._host_observation_shutdown.set()
        return self._persistence.fail_instance_host_observations(
            broker_instance_id=self._broker_instance_id
        )

    def acquire_ephemeral_secret_fd_delivery(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        template_id: str,
        run_id: uuid.UUID,
        request_id: uuid.UUID,
    ) -> EphemeralSecretDeliveryLease:
        """Acquire one volatile credential under the coordinator mutation lock.

        The returned lease remains held until the socket layer closes its local
        descriptor after SCM_RIGHTS transfer. It never serializes the value,
        records it in an operation result, or exposes a path to a client.
        """

        request = accepted.request
        try:
            return self._ephemeral.acquire_secret_fd_delivery(
                accepted,
                template_id=template_id,
                run_id=run_id,
                request_id=request_id,
            )
        except SecretGrantReplay as exc:
            raise BrokerError(
                "secret_delivery_replay",
                "The runner credential delivery was already consumed; start a new isolated validation run instead of retrying.",
                operation_id=request.operation_id,
            ) from exc
        except SecretGrantExpired as exc:
            raise BrokerError(
                "secret_delivery_expired",
                "The ephemeral validation run expired before its credential could be delivered.",
                operation_id=request.operation_id,
            ) from exc
        except SecretGrantNotFound as exc:
            raise BrokerError(
                "secret_delivery_unavailable",
                "The broker no longer has volatile credential material for this run.",
                operation_id=request.operation_id,
            ) from exc
        except EphemeralSecretError as exc:
            raise BrokerError(
                "secret_delivery_unavailable",
                "The broker rejected volatile credential delivery for this run.",
                operation_id=request.operation_id,
            ) from exc

    def recover_ephemeral_runs(self) -> Mapping[str, Any]:
        ephemeral = self._ephemeral.recover_startup()
        if self._test_fixture_provider is None:
            return ephemeral
        fixtures = self._test_fixture_provider.recover_startup()
        return {**ephemeral, "test_fixtures": dict(fixtures)}

    def _cleanup_broker_runtime_resources(
        self,
        _request: dict[str, Any],
        resources: list[dict[str, Any]],
    ) -> dict[str, Any]:
        if len(resources) != 1:
            raise BrokerBackendError(
                "runtime_cleanup_identity_invalid",
                "Broker runtime cleanup requires exactly one sealed resource.",
            )
        with self._runtime_session_mutation_lock:
            cleanup = self._persistence.runtime_session_cleanup_target(
                resources[0]
            )
            if cleanup.cleanup_disposition == "removed":
                observation = self._observe_fresh_full_docker(
                    cleanup.operation_id,
                    project_id=cleanup.repo_id,
                )
                try:
                    terminal = self._persistence.verify_runtime_session_removed(
                        cleanup, evidence=observation
                    )
                    mutation = {
                        "action": "remove",
                        "already_absent": True,
                        "full_container_id": cleanup.target.full_container_id,
                    }
                except BrokerError as error:
                    if error.code != "runtime_cleanup_not_terminal":
                        raise
                    mutation = self._container_remover(
                        cleanup.target.full_container_id
                    )
                    observation = self._observe_fresh_full_docker(
                        cleanup.operation_id,
                        project_id=cleanup.repo_id,
                    )
                    terminal = self._persistence.verify_runtime_session_removed(
                        cleanup, evidence=observation
                    )
                state = "removed"
                classification = "created_runtime_removed_at_expiry"
            else:
                mutation = self._host_mutations.docker_stop(cleanup.target)
                observation = self._observe_fresh_full_docker(
                    cleanup.operation_id,
                    project_id=cleanup.repo_id,
                )
                terminal = self._persistence.verify_runtime_session_stopped(
                    cleanup
                )
                state = "retained"
                classification = "borrowed_runtime_stopped_at_expiry"
            if observation.get("docker_available") is not True:
                raise BrokerBackendError(
                    "runtime_cleanup_observation_incomplete",
                    "Runtime expiry cleanup could not prove Docker observation availability.",
                    operation_id=cleanup.operation_id,
                )
        return {
            "ok": True,
            "state": state,
            "classification": classification,
            "mutation": _json_safe_mapping(mutation),
            "terminal": terminal,
            "observation": observation,
        }

    def reap_broker_runtime_sessions_once(
        self, *, timestamp: str | None = None
    ) -> list[dict[str, Any]]:
        """Reap due broker-owned sessions without caller authentication."""

        with AccountStore.open(
            self._persistence.database_path,
            expected_uid=self._persistence.expected_uid,
            busy_timeout_ms=self._persistence.busy_timeout_ms,
        ) as store:
            return reap_expired_runtime_sessions(
                store,
                cleanup=self._cleanup_broker_runtime_resources,
                timestamp=timestamp,
            )

    def _runtime_reaper_main(self) -> None:
        while not self._runtime_reaper_stop.is_set():
            try:
                self.reap_broker_runtime_sessions_once()
                with AccountStore.open(
                    self._persistence.database_path,
                    expected_uid=self._persistence.expected_uid,
                    busy_timeout_ms=self._persistence.busy_timeout_ms,
                ) as store:
                    next_cleanup = next_runtime_cleanup_at(store)
                if next_cleanup is None:
                    delay = 300.0
                else:
                    deadline = calendar.timegm(
                        time.strptime(next_cleanup, "%Y-%m-%dT%H:%M:%SZ")
                    )
                    delay = max(0.05, min(300.0, deadline - time.time()))
            except BaseException:
                _LOGGER.exception("broker runtime-session reaper turn failed")
                delay = 60.0
            self._runtime_reaper_wake.wait(timeout=delay)
            self._runtime_reaper_wake.clear()

    def _start_runtime_reaper(self) -> None:
        thread = self._runtime_reaper_thread
        if thread is not None and thread.is_alive():
            return
        self._runtime_reaper_stop.clear()
        self._runtime_reaper_wake.clear()
        thread = threading.Thread(
            target=self._runtime_reaper_main,
            name="devcoordinator-runtime-session-reaper",
            daemon=True,
        )
        self._runtime_reaper_thread = thread
        thread.start()

    def start_ephemeral_reaper(self) -> None:
        self._ephemeral.start_reaper()
        if self._test_fixture_provider is not None:
            self._test_fixture_provider.start_reaper()
        self._start_runtime_reaper()

    def request_ephemeral_reaper_stop(self) -> None:
        self._ephemeral.request_reaper_stop()
        if self._test_fixture_provider is not None:
            self._test_fixture_provider.request_reaper_stop()
        self._runtime_reaper_stop.set()
        self._runtime_reaper_wake.set()

    def wait_ephemeral_reaper_stopped(self, timeout_seconds: float) -> None:
        deadline = time.monotonic() + float(timeout_seconds)
        self._ephemeral.wait_reaper_stopped(
            max(0.0, deadline - time.monotonic())
        )
        if self._test_fixture_provider is not None:
            self._test_fixture_provider.wait_reaper_stopped(
                max(0.0, deadline - time.monotonic())
            )
        thread = self._runtime_reaper_thread
        if thread is not None:
            thread.join(max(0.0, deadline - time.monotonic()))
            if thread.is_alive():
                raise TimeoutError("runtime-session reaper did not stop")

    def stop_ephemeral_reaper(self, timeout_seconds: float = 10.0) -> None:
        """Compatibility helper; production shutdown owns a shared deadline."""

        self.request_ephemeral_reaper_stop()
        self.wait_ephemeral_reaper_stopped(timeout_seconds)

    @staticmethod
    def _archive_plan_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
        result = dict(payload)
        target = result.get("target")
        if not isinstance(target, Mapping):
            raise LifecycleError("archive plan omitted its human target description")
        target_kind = str(target.get("target_kind") or "")
        target_id = str(target.get("target_id") or "")
        if target_kind not in {"project", "server", "container"} or not target_id:
            raise LifecycleError("archive plan target description is invalid")
        plan_fingerprint = str(result.get("fingerprint") or "")
        result.update(
            {
                "plan_fingerprint": plan_fingerprint,
                "action": "archive",
                "confirmation_phrase": "",
                "target_kind": target_kind,
                "target_id": target_id,
                "effects": (
                    [
                        "fence_project_startup",
                        "disable_captured_startup_policies",
                        "stop_exact_project_resources",
                        "deactivate_port_allocations",
                        "hide_from_active_inventory",
                    ]
                    if target_kind == "project"
                    else [
                        "disable_captured_startup_policies",
                        "stop_exact_resource",
                        "deactivate_port_allocations",
                        "hide_from_active_inventory",
                    ]
                ),
                "retained": list(result.get("retained_data") or []),
                "deleted": [],
                "blockers": [],
                "status": "planned",
            }
        )
        return result

    @staticmethod
    def _synthetic_lifecycle_request(
        request: BrokerRequest,
        *,
        operation: BrokerOperation,
        project_id: str,
        resource_id: str,
        arguments: Mapping[str, Any],
    ) -> BrokerRequest:
        return BrokerRequest.create(
            operation_id=request.operation_id,
            authority_generation=request.authority_generation,
            account_id=request.account_id,
            project_id=project_id,
            resource_id=resource_id,
            operation=operation,
            arguments=arguments,
        )

    @staticmethod
    def _lookup_generic_cleanup_resource(
        store: CoordinatorStore,
        *,
        target_kind: str,
        target_id: str,
        include_archived: bool,
    ) -> tuple[ExactResourceRef, str]:
        persistence = SQLiteLifecyclePersistence(store)
        exact, repo_id = persistence.resolve_resource(
            ResourceKind(target_kind),
            target_id,
            include_archived=include_archived,
        )
        if repo_id is None:
            raise LifecycleError("permanent cleanup target has no project boundary")
        return exact, repo_id

    def _resolve_generic_cleanup_resource(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        store: CoordinatorStore,
        target_kind: str,
        target_id: str,
        operation: BrokerOperation,
    ) -> tuple[ExactResourceRef, str]:
        exact, repo_id = self._lookup_generic_cleanup_resource(
            store,
            target_kind=target_kind,
            target_id=target_id,
            include_archived=True,
        )
        if repo_id != accepted.request.project_id:
            raise LifecycleError("cleanup target belongs to another project")
        del operation
        return exact, repo_id

    def _plan_generic_archive(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        store: CoordinatorStore,
        actor: str,
    ) -> dict[str, Any]:
        request = accepted.request
        target_kind = str(request.arguments["target_kind"])
        target_id = str(request.arguments["target_id"])
        reason = str(request.arguments["reason"])
        persistence = SQLiteLifecyclePersistence(store)
        resource_plan_basis: ExactResourceRef | None = None
        if target_kind == "project":
            synthetic_request = self._synthetic_lifecycle_request(
                request,
                operation=BrokerOperation.REPOSITORY_PLAN_REMOVE,
                project_id=request.project_id,
                resource_id=request.project_id,
                arguments={"reason": reason},
            )
        elif target_kind in {"server", "container"}:
            resource_plan_basis, repo_id = persistence.resolve_resource(
                ResourceKind(target_kind), target_id
            )
            if repo_id != request.project_id:
                raise LifecycleError("archive target belongs to another project")
            synthetic_request = self._synthetic_lifecycle_request(
                request,
                operation=BrokerOperation.RESOURCE_PLAN_ARCHIVE,
                project_id=repo_id,
                resource_id=target_id,
                arguments={
                    "resource_kind": target_kind,
                    "immutable_fingerprint": resource_plan_basis.immutable_fingerprint,
                    "observation_fingerprint": resource_plan_basis.observation_fingerprint,
                    "reason": reason,
                },
            )
        else:
            raise LifecycleError("linked worktrees cannot be archived")
        # Resolve the exact catalog identity above before committing an
        # observation for this plan.
        synthetic = self._persistence.accept(
            accepted.peer,
            synthetic_request,
        )
        observation = self._observe_fresh_full_docker(
            request.operation_id,
            project_id=request.project_id,
        )
        payload = self._execute_lifecycle(
            synthetic, resource_plan_basis=resource_plan_basis
        )
        payload["broker_observation"] = self._persistence.bind_lifecycle_plan_observation(
            synthetic,
            plan_id=str(payload.get("plan_id") or ""),
            evidence=observation,
        )
        return self._archive_plan_payload(payload)

    def _apply_generic_lifecycle(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        store: CoordinatorStore,
        cleanup: CleanupLifecycle,
        actor: str,
    ) -> dict[str, Any]:
        request = accepted.request
        plan_id = str(request.arguments["plan_id"])
        plan_fingerprint = str(request.arguments["plan_fingerprint"])
        confirmation_phrase = str(request.arguments["confirmation_phrase"])
        with store.read_transaction() as connection:
            cleanup_row = connection.execute(
                "SELECT status FROM cleanup_plans WHERE plan_id = ?", (plan_id,)
            ).fetchone()
        if cleanup_row is not None:
            if str(cleanup_row["status"]) == "succeeded":
                # Permanent cleanup intentionally deletes the exact live
                # resource. A later request with the same durable plan must
                # validate the plan and confirmation without trying to
                # resurrect or re-resolve the deleted resource identity.
                result = cleanup.apply(
                    plan_id=plan_id,
                    plan_fingerprint=plan_fingerprint,
                    confirmation_phrase=confirmation_phrase,
                    actor=actor,
                )
                result["pre_apply_observation"] = None
                result["replayed_after_completion"] = True
                return result
            cleanup_plan = cleanup.load_plan(plan_id)
            planned_identity: Mapping[str, Any] | None = None
            if cleanup_plan.target_kind in {"server", "container"}:
                identity = cleanup_plan.snapshot.get("identity")
                if not isinstance(identity, Mapping):
                    raise LifecycleError("cleanup plan exact identity is missing")
                planned_identity = identity
                exact, repo_id = self._resolve_generic_cleanup_resource(
                    accepted,
                    store=store,
                    target_kind=cleanup_plan.target_kind,
                    target_id=cleanup_plan.target_id,
                    operation=BrokerOperation.CLEANUP_APPLY,
                )
                if (
                    repo_id != cleanup_plan.repo_id
                    or exact.immutable_fingerprint
                    != str(identity.get("immutable_fingerprint") or "")
                    or exact.observation_fingerprint
                    != str(identity.get("observation_fingerprint") or "")
                ):
                    raise PlanDriftError(
                        "cleanup resource authority changed after planning"
                    )
            observation = self._observe_fresh_full_docker(
                request.operation_id,
                project_id=request.project_id,
            )
            if planned_identity is not None:
                exact, repo_id = self._resolve_generic_cleanup_resource(
                    accepted,
                    store=store,
                    target_kind=cleanup_plan.target_kind,
                    target_id=cleanup_plan.target_id,
                    operation=BrokerOperation.CLEANUP_APPLY,
                )
                if (
                    repo_id != cleanup_plan.repo_id
                    or exact.immutable_fingerprint
                    != str(planned_identity.get("immutable_fingerprint") or "")
                    or exact.observation_fingerprint
                    != str(planned_identity.get("observation_fingerprint") or "")
                ):
                    raise PlanDriftError(
                        "cleanup resource authority changed during observation"
                    )
            result = cleanup.apply(
                plan_id=plan_id,
                plan_fingerprint=plan_fingerprint,
                confirmation_phrase=confirmation_phrase,
                actor=actor,
            )
            result["pre_apply_observation"] = observation
            return result
        if confirmation_phrase:
            raise LifecycleError("archive apply requires an empty confirmation phrase")
        persistence = SQLiteLifecyclePersistence(store)
        plan = persistence.load_plan(plan_id)
        if plan.fingerprint != plan_fingerprint:
            raise PlanDriftError("archive plan fingerprint does not match durable plan")
        if isinstance(plan, RepositoryDecommissionPlan):
            synthetic_request = self._synthetic_lifecycle_request(
                request,
                operation=BrokerOperation.REPOSITORY_REMOVE,
                project_id=plan.repo_id,
                resource_id=plan.repo_id,
                arguments={
                    "plan_id": plan_id,
                    "plan_fingerprint": plan_fingerprint,
                },
            )
        elif isinstance(plan, StandaloneRetirementPlan) and plan.repo_id is not None:
            synthetic_request = self._synthetic_lifecycle_request(
                request,
                operation=BrokerOperation.RESOURCE_ARCHIVE,
                project_id=plan.repo_id,
                resource_id=plan.target.resource_id,
                arguments={
                    "resource_kind": plan.target.kind.value,
                    "immutable_fingerprint": plan.target.immutable_fingerprint,
                    "observation_fingerprint": plan.target.observation_fingerprint,
                    "plan_id": plan_id,
                    "plan_fingerprint": plan_fingerprint,
                },
            )
        else:
            raise LifecycleError("durable plan is not an HTTP archive or purge plan")
        # Re-validate the archive-specific durable plan identity.
        synthetic = self._persistence.accept(
            accepted.peer,
            synthetic_request,
        )
        observation = self._observe_fresh_full_docker(
            request.operation_id,
            project_id=request.project_id,
        )
        self._persistence.require_lifecycle_plan_observation(synthetic)
        result = self._execute_lifecycle(synthetic)
        status = str(result.get("status") or "")
        result.update(
            {
                "action": "archive",
                "partial": status == "needs_attention",
                "needs_attention": status == "needs_attention",
                "ok": status in {"succeeded", "already_complete"},
                "pre_apply_observation": observation,
            }
        )
        return result

    def _execute_lifecycle(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        resource_plan_basis: ExactResourceRef | None = None,
    ) -> dict[str, Any]:
        request = accepted.request
        actor = f"broker:{request.account_id}:uid:{accepted.peer.uid}"
        with CoordinatorStore.open(
            self._persistence.database_path,
            expected_uid=self._persistence.expected_uid,
            busy_timeout_ms=self._persistence.busy_timeout_ms,
        ) as store:
            persistence = SQLiteLifecyclePersistence(store)
            lifecycle = RepositoryLifecycle(
                persistence,
                self._lifecycle_adapter,
                prepare_apply=lambda plan, prepare_actor: self._prepare_worker_lifecycle_apply(
                    accepted,
                    store=store,
                    plan=plan,
                    actor=prepare_actor,
                ),
            )
            if request.operation == BrokerOperation.REPOSITORY_PLAN_REMOVE:
                plan = lifecycle.plan_repository_decommission(
                    request.project_id,
                    actor=actor,
                    reason=str(request.arguments["reason"]),
                )
                payload = plan.to_dict()
                with store.read_transaction() as connection:
                    repository_row = connection.execute(
                        "SELECT display_name, canonical_root FROM repositories WHERE repo_id = ?",
                        (request.project_id,),
                    ).fetchone()
                if repository_row is None:
                    raise LifecycleError("repository label disappeared during planning")
                payload.update(
                    {
                        "target_kind": "project",
                        "target_id": request.project_id,
                        "display_name": str(repository_row["display_name"]),
                        "canonical_root": str(repository_row["canonical_root"]),
                        "target": {
                            "target_kind": "project",
                            "target_id": request.project_id,
                            "display_name": str(repository_row["display_name"]),
                            "project_id": request.project_id,
                        },
                        "blockers": [],
                    }
                )
                return payload
            if request.operation == BrokerOperation.REPOSITORY_REMOVE:
                confirmed = _confirmed_repository_plan(
                    persistence,
                    plan_id=str(request.arguments["plan_id"]),
                    plan_fingerprint=str(request.arguments["plan_fingerprint"]),
                    repo_id=request.project_id,
                )
                execution = _repository_execution_plan(persistence, confirmed)
                progress = persistence.operation_progress(execution.plan_id)
                if progress.status is OperationStatus.SUCCEEDED:
                    result = lifecycle.apply_repository_decommission(
                        execution.plan_id, execution.fingerprint, actor=actor
                    )
                elif progress.status is not OperationStatus.PLANNED:
                    current = persistence.repository_snapshot(request.project_id)
                    _require_resumable_repository_snapshot(
                        execution, current, progress=progress
                    )
                    result = lifecycle.apply_repository_decommission(
                        execution.plan_id, execution.fingerprint, actor=actor
                    )
                else:
                    current = persistence.repository_snapshot(request.project_id)
                    bindings = _resource_catalog_contract(store, current.targets)
                    _require_repository_semantically_unchanged(
                        execution,
                        current,
                        before_bindings=bindings,
                        current_bindings=bindings,
                    )
                    refreshed = lifecycle.plan_repository_decommission(
                        request.project_id,
                        actor=actor,
                        reason=confirmed.reason,
                    )
                    _require_repository_refresh_matches(execution, refreshed)
                    persistence.bind_lifecycle_plan_successor(execution, refreshed)
                    result = lifecycle.apply_repository_decommission(
                        refreshed.plan_id, refreshed.fingerprint, actor=actor
                    )
                return _apply_result(
                    result.to_dict(), confirmed=confirmed, observation=None
                )
            if request.operation == BrokerOperation.REPOSITORY_REINSTALL:
                return lifecycle.reinstall_repository(
                    request.project_id,
                    actor=actor,
                    reason=str(request.arguments["reason"]),
                    explicit=bool(request.arguments["explicit"]),
                ).to_dict()

            if (
                request.operation in {
                    BrokerOperation.RESOURCE_PLAN_RETIRE,
                    BrokerOperation.RESOURCE_PLAN_ARCHIVE,
                }
                and resource_plan_basis is not None
            ):
                exact, attached_repo_id = persistence.resolve_resource(
                    resource_plan_basis.kind,
                    resource_plan_basis.resource_id,
                )
                _require_plan_target_identity_unchanged(resource_plan_basis, exact)
            else:
                exact = self._exact_lifecycle_resource(persistence, request)
                if request.operation in {
                    BrokerOperation.RESOURCE_RETIRE,
                    BrokerOperation.RESOURCE_ARCHIVE,
                }:
                    # Apply starts from the confirmed durable plan target.  Its
                    # generation may be stale by design; the guarded refresh
                    # below resolves current host/store truth, proves semantic
                    # identity, and binds a successor before any host effect.
                    # Strictly rebuilding the old target here would reject
                    # harmless generation churn before that safety path ran.
                    attached_repo_id = None
                else:
                    _snapshot = persistence.standalone_snapshot(exact)
                    attached_repo_id = _snapshot.attached_repo_id
            if request.operation == BrokerOperation.RESOURCE_ATTACH:
                return lifecycle.attach_resource(
                    request.project_id,
                    exact,
                    actor=actor,
                    reason=str(request.arguments["reason"]),
                ).to_dict()
            if request.operation == BrokerOperation.RESOURCE_PLAN_RETIRE:
                plan = lifecycle.plan_standalone_retirement(
                    exact,
                    actor=actor,
                    reason=str(request.arguments["reason"]),
                )
                payload = plan.to_dict()
                payload["target"] = persistence.describe_resource(exact, None)
                return payload
            if request.operation == BrokerOperation.RESOURCE_PLAN_ARCHIVE:
                plan = lifecycle.plan_resource_archive(
                    exact,
                    actor=actor,
                    reason=str(request.arguments["reason"]),
                    repo_id=attached_repo_id,
                )
                payload = plan.to_dict()
                payload["target"] = persistence.describe_resource(
                    exact, attached_repo_id
                )
                return payload
            if request.operation == BrokerOperation.RESOURCE_RESTORE:
                return dict(
                    lifecycle.restore_resource_archive(
                        exact,
                        actor=actor,
                        reason=str(request.arguments["reason"]),
                    )
                )
            if request.operation in {
                BrokerOperation.RESOURCE_RETIRE,
                BrokerOperation.RESOURCE_ARCHIVE,
            }:
                confirmed = _confirmed_retirement_plan(
                    persistence,
                    plan_id=str(request.arguments["plan_id"]),
                    plan_fingerprint=str(request.arguments["plan_fingerprint"]),
                    resource_kind=ResourceKind(str(request.arguments["resource_kind"])),
                    resource_id=request.resource_id,
                )
                execution = _retirement_execution_plan(persistence, confirmed)
                progress = persistence.operation_progress(execution.plan_id)
                if progress.status is OperationStatus.SUCCEEDED:
                    result = lifecycle.apply_standalone_retirement(
                        execution.plan_id, execution.fingerprint, actor=actor
                    )
                elif progress.status is not OperationStatus.PLANNED:
                    current, current_repo_id = persistence.resolve_resource(
                        execution.target.kind,
                        execution.target.resource_id,
                        include_archived=True,
                    )
                    if current_repo_id != execution.repo_id:
                        raise PlanDriftError("resource repository attachment changed")
                    _require_target_semantically_unchanged(execution.target, current)
                    result = lifecycle.apply_standalone_retirement(
                        execution.plan_id, execution.fingerprint, actor=actor
                    )
                else:
                    current, current_repo_id = persistence.resolve_resource(
                        execution.target.kind,
                        execution.target.resource_id,
                        include_archived=True,
                    )
                    if current_repo_id != execution.repo_id:
                        raise PlanDriftError("resource repository attachment changed")
                    _require_target_semantically_unchanged(execution.target, current)
                    if request.operation is BrokerOperation.RESOURCE_ARCHIVE:
                        refreshed = lifecycle.plan_resource_archive(
                            current,
                            actor=actor,
                            reason=confirmed.reason,
                            repo_id=confirmed.repo_id,
                        )
                    else:
                        refreshed = lifecycle.plan_standalone_retirement(
                            current, actor=actor, reason=confirmed.reason
                        )
                    _require_retirement_refresh_matches(execution, refreshed)
                    persistence.bind_lifecycle_plan_successor(execution, refreshed)
                    result = lifecycle.apply_standalone_retirement(
                        refreshed.plan_id, refreshed.fingerprint, actor=actor
                    )
                return _apply_result(
                    result.to_dict(), confirmed=confirmed, observation=None
                )
        raise BrokerBackendError(
            "unknown_operation",
            "Requested broker lifecycle operation is not allowed.",
            operation_id=request.operation_id,
        )

    @staticmethod
    def _exact_lifecycle_resource(
        persistence: SQLiteLifecyclePersistence,
        request: Any,
    ) -> ExactResourceRef:
        if request.operation in {
            BrokerOperation.RESOURCE_RETIRE,
            BrokerOperation.RESOURCE_ARCHIVE,
        }:
            plan = persistence.load_plan(str(request.arguments["plan_id"]))
            if not isinstance(plan, StandaloneRetirementPlan):
                raise LifecycleError("durable plan is not a standalone retirement")
            exact = plan.target
            expected = (
                str(request.arguments["resource_kind"]),
                request.resource_id,
                str(request.arguments["immutable_fingerprint"]),
            )
            observed = (
                exact.kind.value,
                exact.resource_id,
                exact.immutable_fingerprint,
            )
        else:
            exact, _repo_id = persistence.resolve_resource(
                ResourceKind(str(request.arguments["resource_kind"])),
                request.resource_id,
                include_archived=request.operation is BrokerOperation.RESOURCE_RESTORE,
            )
            expected = (
                str(request.arguments["resource_kind"]),
                request.resource_id,
                str(request.arguments["immutable_fingerprint"]),
                str(request.arguments["observation_fingerprint"]),
            )
            observed = (
                exact.kind.value,
                exact.resource_id,
                exact.immutable_fingerprint,
                exact.observation_fingerprint,
            )
        if observed != expected:
            raise LifecycleError(
                "standalone resource identity changed; refresh before acting"
            )
        return exact

    def _record_failure(self, operation_id: str, *, code: str, message: str) -> None:
        try:
            self._persistence.finish_operation(
                operation_id, error_code=code, error_message=message
            )
        except Exception as exc:
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "Broker failure and durable failure recording both failed; reconciliation is required.",
                operation_id=operation_id,
            ) from exc

    def _prepare_worker_lifecycle_apply(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        store: AccountStore,
        plan: Any,
        actor: str,
    ) -> dict[str, Any]:
        """Deregister exact workers after plan validation, before retirement."""

        def execution_uid_for_worker(worker_id: str, repo_id: str) -> int:
            return self._persistence.worker_execution_uid_for_resource(
                repo_id=repo_id,
                server_definition_id=worker_id,
                operation_id=str(plan.plan_id),
            )

        if (
            getattr(plan, "action", None) == "forget"
            and getattr(plan, "target_kind", None) == "project"
        ):
            repo_id = str(plan.target_id)
            identity = getattr(plan, "snapshot", {}).get("identity", {})
            repository_generation = identity.get("generation")
            if (
                getattr(plan, "repo_id", None) != repo_id
                or type(repository_generation) is not int
            ):
                raise BrokerBackendError(
                    "cleanup_plan_drift",
                    "Project cleanup lacks an exact repository-generation identity.",
                    operation_id=str(plan.plan_id),
                )
            service_revocation = (
                self._persistence.revoke_repository_for_permanent_cleanup(
                    repo_id=repo_id,
                    repository_generation=repository_generation,
                    cleanup_operation_id=str(plan.plan_id),
                    immutable_fingerprint=str(plan.target_fingerprint),
                    actor=actor,
                )
            )
            worker_evidence = unregister_workers_for_plan(
                store,
                plan=plan,
                actor=actor,
                coordinator_script=(
                    Path(__file__).resolve().parent.parent / "dev_coordinator.py"
                ),
                execution_uid_for_worker=execution_uid_for_worker,
            )
            removed_servers = (
                self._persistence.remove_revoked_repository_server_definitions(
                    repo_id=repo_id,
                    repository_generation=repository_generation,
                    cleanup_operation_id=str(plan.plan_id),
                )
            )
            # security-assumptions.md, “Explicitly unnecessary gates”:
            # repository association is routing/context, never membership or
            # permission. Permanent cleanup therefore updates canonical
            # service state and exact worker projections only; it must not
            # mutate a root-owned client routing profile as an access revoke.
            return {
                "status": "project_generation_revoked",
                "repository_revocation": {"service": service_revocation},
                "workers": worker_evidence["workers"],
                "server_projections": removed_servers,
            }

        revoke = None
        if (
            getattr(plan, "action", None) == "purge"
            and getattr(plan, "target_kind", None) == "server"
        ):
            plan_worker_id = str(plan.target_id)
            plan_repo_id = str(plan.repo_id)

            def revoke(
                worker_id: str, repo_id: str, revoke_actor: str
            ) -> dict[str, Any]:
                if worker_id != plan_worker_id or repo_id != plan_repo_id:
                    raise BrokerBackendError(
                        "cleanup_plan_drift",
                        "Worker revocation escaped the exact permanent-cleanup target.",
                        operation_id=str(plan.plan_id),
                    )
                service_revocation = self._persistence.revoke_server_for_permanent_cleanup(
                    repo_id=repo_id,
                    server_definition_id=worker_id,
                    cleanup_operation_id=str(plan.plan_id),
                    immutable_fingerprint=str(plan.target_fingerprint),
                    actor=revoke_actor,
                )
                profile_revocation = revoke_server_from_protected_profile(
                    profile_path=configured_profile_path(),
                    repo_id=repo_id,
                    server_name=str(service_revocation["server_name"]),
                    server_definition_id=worker_id,
                    cleanup_operation_id=str(plan.plan_id),
                    expected_database_generation=(
                        self._persistence.database_generation()
                    ),
                )
                return {
                    "service": service_revocation,
                    "protected_profile": profile_revocation,
                }

        return unregister_workers_for_plan(
            store,
            plan=plan,
            actor=actor,
            coordinator_script=(
                Path(__file__).resolve().parent.parent / "dev_coordinator.py"
            ),
            execution_uid_for_worker=execution_uid_for_worker,
            revoke=revoke,
        )


@dataclass(frozen=True)
class StoreBackedBrokerRuntime:
    """Fully wired service boundary; the caller owns server start/close."""

    persistence: BrokerPersistence
    backend: StoreBackedMutationBackend
    writer: SerializedMutationWriter
    service: BrokerService
    server: UnixBrokerServer
    shutdown_timeout_seconds: float = BROKER_SHUTDOWN_DRAIN_TIMEOUT_SECONDS
    coordinator_script: Path | None = None

    def reconcile_workers_on_startup(self) -> dict[str, Any]:
        """Fence prior worker authority and autostart each eligible worker once."""

        fenced = self.fence_workers_on_startup()
        return self.autostart_workers_after_admission(fenced=fenced)

    def fence_workers_on_startup(self) -> dict[str, Any]:
        """Fence old worker epochs before the server begins admission."""

        script = self.coordinator_script
        if script is None:
            script = Path(__file__).resolve().parent.parent / "dev_coordinator.py"
        supervisor_epoch = str(uuid.uuid4())
        with AccountStore.open(
            self.persistence.database_path,
            expected_uid=self.persistence.expected_uid,
            busy_timeout_ms=self.persistence.busy_timeout_ms,
        ) as store:
            return WorkerController(
                store,
                coordinator_script=script,
            ).fence_startup(supervisor_epoch=supervisor_epoch)

    def autostart_workers_after_admission(
        self, *, fenced: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Launch safe keep-alive workers only once broker calls can be served."""

        supervisor_epoch = fenced.get("supervisor_epoch")
        if not isinstance(supervisor_epoch, str) or not supervisor_epoch:
            raise BrokerError(
                "worker_reconciliation_invalid",
                "Worker startup fencing omitted its supervisor epoch.",
            )
        script = self.coordinator_script
        if script is None:
            script = Path(__file__).resolve().parent.parent / "dev_coordinator.py"
        with AccountStore.open(
            self.persistence.database_path,
            expected_uid=self.persistence.expected_uid,
            busy_timeout_ms=self.persistence.busy_timeout_ms,
        ) as store:
            autostarted = WorkerController(
                store,
                coordinator_script=script,
            ).autostart_fenced(
                supervisor_epoch=supervisor_epoch,
                expected_worker_ids=list(fenced.get("autostart_expected") or []),
            )
        errors = [
            *list(fenced.get("errors") or []),
            *list(autostarted.get("errors") or []),
        ]
        return {
            "ok": not errors,
            "supervisor_epoch": supervisor_epoch,
            "fenced_old_runners": list(fenced.get("fenced_old_runners") or []),
            "started": list(autostarted.get("started") or []),
            "errors": errors,
        }

    def begin_shutdown(self) -> int:
        """Fence mutation admission and request background stop without joining."""

        try:
            return self.writer.begin_shutdown()
        finally:
            # begin_shutdown() runs in the Python signal turn.  It must wake
            # the reaper, but it must never join a thread that can be blocked
            # in a bounded Docker host call.  close() performs that join using
            # the one broker-wide shutdown deadline.
            self.backend.request_ephemeral_reaper_stop()

    def close(self) -> None:
        """Fence all mutations, drain accepted work, then clean observation ownership."""

        failures: list[tuple[str, BaseException]] = []
        deadline = time.monotonic() + float(self.shutdown_timeout_seconds)
        try:
            self.begin_shutdown()
        except BaseException as error:
            failures.append(("mutation admission fence", error))
            _LOGGER.exception("broker mutation admission fence failed")
        try:
            self.server.close(
                timeout_seconds=max(0.0, deadline - time.monotonic())
            )
        except BaseException as error:
            failures.append(("server drain", error))
            _LOGGER.exception("broker server drain failed")
        try:
            if not self.writer.wait_for_drain(
                max(0.0, deadline - time.monotonic())
            ):
                raise BrokerError(
                    "shutdown_timeout",
                    "Broker mutations did not drain before the shutdown deadline.",
                )
        except BaseException as error:
            failures.append(("mutation drain", error))
            _LOGGER.exception("broker mutation drain failed")
        try:
            # The reaper mutates the same durable lifecycle state directly;
            # prove it has returned only after accepted request work has had a
            # chance to drain, and charge the join to the broker's single
            # published shutdown deadline.
            self.backend.wait_ephemeral_reaper_stopped(
                max(0.0, deadline - time.monotonic())
            )
        except BaseException as error:
            failures.append(("ephemeral reaper drain", error))
            _LOGGER.exception("ephemeral reaper drain failed")
        try:
            # Accepted host observations were allowed to finalize normally.
            # This idempotent cleanup now fences direct backend observation
            # calls and fails only orphaned process-owned tickets.
            self.backend.begin_shutdown_host_observations()
        except BaseException as error:
            failures.append(("initial observation cleanup", error))
            _LOGGER.exception("initial broker observation cleanup failed")
        try:
            # A second transaction is the recovery path for a transient first
            # cleanup failure and proves no process-owned ticket survives exit.
            self.backend.begin_shutdown_host_observations()
        except BaseException as final_cleanup_error:
            failures.append(("final observation cleanup", final_cleanup_error))
            _LOGGER.exception("final broker observation cleanup failed")
        if failures:
            summaries = []
            for stage, error in failures:
                if isinstance(error, BrokerError):
                    summaries.append(
                        f"{stage}: {error.code} ({error.message})"
                    )
                else:
                    summaries.append(
                        f"{stage}: {type(error).__name__} (inspect broker logs)"
                    )
            raise BrokerBackendError(
                "broker_shutdown_failed",
                "Broker shutdown encountered failures: " + "; ".join(summaries),
            )


def build_store_backed_broker_runtime(
    *,
    database_path: str | os.PathLike[str],
    socket_path: str | os.PathLike[str],
    host_mutations: TypedHostMutationAPI,
    service_uid: Optional[int] = None,
    socket_mode: int = 0o666,
    max_clients: int = 32,
    shutdown_timeout_seconds: float = BROKER_SHUTDOWN_DRAIN_TIMEOUT_SECONDS,
    lifecycle_adapter: CoordinatorHostLifecycleAdapter | None = None,
    observe_before_lifecycle_plan: Callable[
        [AccountStore], Mapping[str, Any]
    ]
    | None = None,
    test_plane: TestPlaneClient | None = None,
    internal_testd_uid: int | None = None,
    test_attempt_manager: NativeTestAttemptManager | None = None,
    test_credential_registry_path: str | os.PathLike[str] = (
        DEFAULT_TEST_CREDENTIAL_REGISTRY_PATH
    ),
    test_credential_material_root: str | os.PathLike[str] = (
        DEFAULT_TEST_CREDENTIAL_MATERIAL_ROOT
    ),
    test_credential_runtime_root: str | os.PathLike[str] = (
        DEFAULT_TEST_CREDENTIAL_RUNTIME_ROOT
    ),
    call_journal_path: str | os.PathLike[str] | None = None,
    call_journal_max_bytes: int = DEFAULT_CALL_JOURNAL_MAX_BYTES,
    call_journal_backups: int = DEFAULT_CALL_JOURNAL_BACKUPS,
) -> StoreBackedBrokerRuntime:
    """Construct the production service without exposing storage to clients."""

    # Compatibility-only input retained for older service command lines. The
    # harness is a product capability, not something enabled by a special Unix
    # caller UID; exact test operations and repository generations remain the
    # request validation boundary.
    del internal_testd_uid
    uid = os.geteuid() if service_uid is None else service_uid
    persistence = BrokerPersistence(
        database_path,
        expected_uid=uid,
        compose_model_renderer=render_compose_effective_model,
    )
    active_test_admission_proof = persistence.active_test_admission_proof()
    test_submission_gate = TestSubmissionAdmissionGate(
        initially_fenced=active_test_admission_proof is not None
    )
    secret_manager = VolatileRunSecretManager(expected_uid=uid)
    if test_attempt_manager is None:
        fixture_provider = BrokerSealedFixtureProvider(
            persistence,
            host_mutations,
            secret_manager=secret_manager,
        )
        credential_provider = BrokerOperationalCredentialProvider(
            registry_path=Path(test_credential_registry_path),
            material_root=Path(test_credential_material_root),
            runtime_root=Path(test_credential_runtime_root),
            expected_authority_uid=uid,
        )
        test_attempt_manager = SystemdTestAttemptManager(
            fixture_provider=fixture_provider,
            credential_provider=credential_provider,
        )
    backend = StoreBackedMutationBackend(
        persistence,
        host_mutations,
        lifecycle_adapter=lifecycle_adapter,
        observe_before_lifecycle_plan=observe_before_lifecycle_plan,
        test_plane=test_plane,
        test_attempt_manager=test_attempt_manager,
        test_submission_gate=test_submission_gate,
        secret_manager=secret_manager,
    )
    writer = SerializedMutationWriter(
        backend,
        max_concurrent_host_observations=max(0, min(4, max_clients - 1)),
        test_submission_gate=test_submission_gate,
    )
    call_journal = (
        None
        if call_journal_path is None
        else RollingCallJournal(
            Path(call_journal_path),
            max_bytes=call_journal_max_bytes,
            backups=call_journal_backups,
        )
    )
    service = BrokerService(
        StoreBackedRequestAcceptor(persistence),
        writer,
        secret_fd_retriever=backend,
        call_journal=call_journal,
    )
    server = UnixBrokerServer(
        Path(socket_path),
        service,
        socket_mode=socket_mode,
        max_clients=max_clients,
        shutdown_timeout_seconds=shutdown_timeout_seconds,
    )
    return StoreBackedBrokerRuntime(
        persistence=persistence,
        backend=backend,
        writer=writer,
        service=service,
        server=server,
        shutdown_timeout_seconds=shutdown_timeout_seconds,
    )


def _validated_compose_run_once_image(
    value: Any,
    *,
    image_ref: str,
) -> str:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"image_ref", "image_id"}
        or value.get("image_ref") != image_ref
        or not isinstance(value.get("image_id"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", str(value["image_id"])) is None
    ):
        raise BrokerBackendError(
            "invalid_backend_result",
            "Compose run-once image binding result is invalid.",
        )
    return str(value["image_id"])


def _validated_compose_run_once_container(
    value: Any,
    *,
    expected_image_id: str,
    expected_container_id: str | None = None,
    allow_timed_out: bool = False,
) -> dict[str, Any]:
    required = {"full_container_id", "image_id", "status", "exit_code"}
    allowed = required | ({"timed_out"} if allow_timed_out else set())
    keys = set(value) if isinstance(value, Mapping) else set()
    if (
        not isinstance(value, Mapping)
        or (keys != required and keys != allowed)
        or not isinstance(value.get("full_container_id"), str)
        or re.fullmatch(
            r"[0-9a-f]{64}", str(value["full_container_id"])
        )
        is None
        or value.get("image_id") != expected_image_id
        or value.get("status")
        not in {
            "created",
            "running",
            "paused",
            "restarting",
            "removing",
            "exited",
            "dead",
        }
        or type(value.get("exit_code")) is not int
        or (
            expected_container_id is not None
            and value.get("full_container_id") != expected_container_id
        )
        or (
            "timed_out" in value
            and type(value.get("timed_out")) is not bool
        )
    ):
        raise BrokerBackendError(
            "invalid_backend_result",
            "Compose run-once container observation is invalid.",
        )
    return dict(value)


def _json_safe_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise BrokerBackendError(
            "invalid_backend_result",
            "Typed host mutation returned an invalid result.",
        )
    # The writer applies the configured response-size bound.  This copy blocks
    # custom mapping objects from changing after the durable commit begins.
    return dict(value)


def _observation_failure_code(error: BaseException) -> str:
    """Return one bounded path-free identity for retained recovery evidence."""

    candidate = getattr(error, "code", None)
    if isinstance(candidate, str) and re.fullmatch(
        r"[a-z][a-z0-9_]{0,63}", candidate
    ):
        return candidate
    normalized = re.sub(
        r"[^a-z0-9]+", "_", type(error).__name__.lower()
    ).strip("_")
    return (normalized or "observation_failed")[:64]


def _validated_broker_worker_replacement(
    *,
    canonical_repository: str,
    execution_uid: int,
    arguments: Mapping[str, Any],
    operation_id: str,
) -> dict[str, Any]:
    """Anchor one structured replacement inside the configured repository."""

    del execution_uid

    try:
        repository = Path(canonical_repository).resolve(strict=True)
        requested_cwd = Path(str(arguments["cwd"]))
        cwd = requested_cwd.resolve(strict=True)
        cwd.relative_to(repository)
    except (KeyError, OSError, RuntimeError, ValueError) as error:
        raise BrokerBackendError(
            "worker_replacement_path_denied",
            "Worker replacement cwd must resolve to an existing directory inside the exact configured repository.",
            operation_id=operation_id,
        ) from error
    if (
        not repository.is_dir()
        or not cwd.is_dir()
    ):
        raise BrokerBackendError(
            "worker_replacement_path_denied",
            "Worker replacement repository and cwd must be existing directories.",
            operation_id=operation_id,
        )
    argv = arguments.get("argv")
    environment = arguments.get("environment")
    if not isinstance(argv, list) or not isinstance(environment, Mapping):
        raise BrokerBackendError(
            "invalid_arguments",
            "Worker replacement requires structured argv and environment values.",
            operation_id=operation_id,
        )
    return {
        "argv": list(argv),
        "cwd": str(cwd),
        "environment": dict(environment),
    }


def _private_postgres_backup_root(database_path: Path, *, expected_uid: int) -> Path:
    del expected_uid
    root = database_path.expanduser().absolute().parent / "postgres-backups"
    if root.exists():
        if root.is_symlink() or not root.is_dir():
            raise PermissionError("service PostgreSQL backup root must be a real directory")
    else:
        root.mkdir(mode=0o700)
    return root


def _private_runtime_log_root(database_path: Path, *, expected_uid: int) -> Path:
    del expected_uid
    root = database_path.expanduser().absolute().parent / "runtime-logs"
    if root.exists():
        if root.is_symlink() or not root.is_dir():
            raise PermissionError("service runtime log root must be a real directory")
    else:
        root.mkdir(mode=0o700)
    return root
