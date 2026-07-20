"""Production store-backed broker mutation routing.

The wire protocol never carries commands or filesystem paths.  Docker work is
delegated through an exact typed host-action interface after the store resolves
an immutable container ID and revalidates live ACL, membership, control, and
repository-fence state.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
import os
from pathlib import Path
import threading
import time
from typing import Any, Callable, Mapping, Optional, Protocol
import uuid

from .broker import (
    AuthorizedBrokerRequest,
    BrokerBackendError,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    BrokerService,
    BROKER_SHUTDOWN_DRAIN_TIMEOUT_SECONDS,
    SerializedMutationWriter,
    UnixBrokerServer,
)
from .broker_persistence import (
    BrokerPersistence,
    ComposeMutationTarget,
    DatabaseMutationTarget,
    DockerMutationTarget,
    RegisteredDatabaseBackup,
    StoreBackedAuthorizer,
)
from .host_lifecycle import CoordinatorHostLifecycleAdapter
from .cleanup_lifecycle import CleanupLifecycle
from .observer import observation_owner_scope
from .broker_host import ComposeMutationOutcomeUncertain
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
    _control_binding_contract,
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
from .store import AccountStore, CoordinatorStore


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
_FULL_DOCKER_OBSERVER_DOMAIN = FULL_DOCKER_OBSERVER_DOMAIN
_LOGGER = logging.getLogger(__name__)


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

    def compose_up(self, target: ComposeMutationTarget) -> Mapping[str, Any]: ...

    def compose_stop(self, target: ComposeMutationTarget) -> Mapping[str, Any]: ...

    def compose_restart(self, target: ComposeMutationTarget) -> Mapping[str, Any]: ...

    def compose_down(self, target: ComposeMutationTarget) -> Mapping[str, Any]: ...

    def postgres_backup(
        self, target: DatabaseMutationTarget, *, output_root: str
    ) -> Mapping[str, Any]: ...

    def postgres_restore(
        self,
        target: DatabaseMutationTarget,
        backup: RegisteredDatabaseBackup,
        *, safety_output_root: str,
    ) -> Mapping[str, Any]: ...


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
    ) -> None:
        self._persistence = persistence
        self._host_mutations = host_mutations
        self._lifecycle_adapter = lifecycle_adapter or CoordinatorHostLifecycleAdapter()
        self._observe_before_lifecycle_plan = observe_before_lifecycle_plan
        self._host_observation_shutdown = threading.Event()
        self._broker_instance_id = "broker-" + uuid.uuid4().hex
        self._postgres_backup_root = _private_postgres_backup_root(
            persistence.database_path, expected_uid=persistence.expected_uid
        )

    def execute(self, authorized: AuthorizedBrokerRequest) -> Mapping[str, Any]:
        request = authorized.request
        if request.operation == BrokerOperation.INVENTORY_READ:
            return self._persistence.inventory(authorized)
        if request.operation == BrokerOperation.EVENTS_READ:
            return self._persistence.events(authorized)
        if request.operation == BrokerOperation.HOST_OBSERVE:
            return self._observe_committed_host(request.operation_id)
        if request.operation == BrokerOperation.REPOSITORY_LIST_REMOVED:
            return {
                "repositories": self._persistence.list_removed_repository(authorized)
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
                    authorize=lambda _cap, _kind, _target, _actor: self._persistence.authorize(
                        authorized.peer, authorized.request
                    ),
                )
                listing = cleanup.list_archives(
                    actor=f"broker:{request.account_id}:uid:{authorized.peer.uid}"
                )
                return {
                    "archives": [
                        item
                        for item in listing["archives"]
                        if (
                            item.get("project_id") == request.project_id
                            or (
                                item.get("target_kind") == "project"
                                and item.get("target_id") == request.project_id
                            )
                        )
                    ]
                }
        listener_preflight: tuple[
            tuple[int, ...], int, str, Mapping[str, Any]
        ] | None = None
        compose_preflight: Mapping[str, Any] | None = None
        if (
            request.operation == BrokerOperation.PORT_LEASE
            and bool(request.arguments.get("adopt_existing_listener"))
        ):
            existing = self._persistence.existing_operation_disposition(authorized)
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
            candidates = self._persistence.port_lease_candidates(authorized)
            selected_port, canonical_root = (
                self._persistence.listener_adoption_preflight_target(authorized)
            )
            if type(selected_port) is not int or selected_port not in candidates:
                raise BrokerBackendError(
                    "invalid_host_observation",
                    "Listener adoption target is outside the authorized port candidates.",
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
            existing = self._persistence.existing_operation_disposition(authorized)
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
            self._persistence.require_no_active_compose_operation(authorized)
            compose_preflight = self._observe_fresh_full_docker(
                request.operation_id,
                project_id=request.project_id,
            )
            self._persistence.require_compose_mutation_safe(
                authorized,
                snapshot_id=str(compose_preflight["snapshot_id"]),
            )
        if compose_preflight is None:
            disposition = self._persistence.reserve_operation(authorized)
        else:
            disposition = self._persistence.reserve_operation(
                authorized,
                compose_preflight=compose_preflight,
            )
        replay_database_result: Mapping[str, Any] | None = None
        if disposition.state == "completed":
            return dict(disposition.result or {})
        if disposition.state == "failed":
            raise BrokerBackendError(
                disposition.error_code or "mutation_failed",
                disposition.error_message or "Broker mutation failed.",
                operation_id=request.operation_id,
            )
        if disposition.state == "pending":
            if request.operation in {
                BrokerOperation.DATABASE_BACKUP,
                BrokerOperation.DATABASE_RESTORE,
            }:
                replay_database_result = self._persistence.database_host_result(
                    authorized
                )
            if replay_database_result is None:
                raise BrokerBackendError(
                    "operation_in_progress",
                    "This durable operation is already running or requires reconciliation; it was not executed again.",
                    operation_id=request.operation_id,
                )

        try:
            if request.operation in {
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
                        authorize=lambda _cap, _kind, _target, _actor: self._persistence.authorize(
                            authorized.peer, authorized.request
                        ),
                    )
                    actor = f"broker:{request.account_id}:uid:{authorized.peer.uid}"
                    if request.operation is BrokerOperation.CLEANUP_PLAN:
                        if request.arguments["action"] == "archive":
                            result = self._plan_generic_archive(
                                authorized, store=store, actor=actor
                            )
                        else:
                            target_kind = str(request.arguments["target_kind"])
                            if target_kind in {"server", "container"}:
                                self._authorize_generic_cleanup_resource(
                                    authorized,
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
                                # truth.  Re-resolve and re-authorize before
                                # committing the plan snapshot.
                                self._authorize_generic_cleanup_resource(
                                    authorized,
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
                            authorized, store=store, cleanup=cleanup, actor=actor
                        )
                    else:
                        # Recheck live authorization at the service-owned DB
                        # immediately before resolving and restoring the exact
                        # archived target.
                        self._persistence.authorize(authorized.peer, authorized.request)
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
                            with store.read_transaction() as connection:
                                binding = connection.execute(
                                    """
                                    SELECT binding_id FROM control_bindings
                                    WHERE resource_kind = ? AND resource_id = ?
                                      AND authority_state = 'authoritative'
                                    ORDER BY priority DESC, binding_id LIMIT 1
                                    """,
                                    (target_kind, target_id),
                                ).fetchone()
                            if binding is None:
                                raise LifecycleError(
                                    "archived resource has no authoritative exact controller"
                                )
                            exact, repo_id = lifecycle_persistence.resolve_resource(
                                ResourceKind(target_kind),
                                target_id,
                                str(binding["binding_id"]),
                                include_archived=True,
                            )
                            if repo_id != request.project_id:
                                raise LifecycleError(
                                    "archived resource belongs to another project"
                                )
                            self._persistence.authorize_cleanup_resource(
                                authorized,
                                repo_id=repo_id,
                                resource_kind=target_kind,
                                resource_id=exact.resource_id,
                                control_binding_id=exact.control_binding_id,
                                immutable_fingerprint=exact.immutable_fingerprint,
                                ownership_fingerprint=exact.ownership_fingerprint,
                                operation=BrokerOperation.RESOURCE_RESTORE,
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
                        # Authorization just proved this exact active resource.
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
                            authorized
                        )
                    )
                elif request.operation == BrokerOperation.RESOURCE_RESTORE:
                    apply_observation = self._observe_fresh_full_docker(
                        request.operation_id,
                        project_id=request.project_id,
                    )
                result = self._execute_lifecycle(
                    authorized, resource_plan_basis=resource_plan_basis
                )
                if observation_evidence is not None:
                    plan_id = str(result.get("plan_id") or "")
                    result["broker_observation"] = (
                        self._persistence.bind_lifecycle_plan_observation(
                            authorized,
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
                        self._persistence.listener_adoption_target(authorized)
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
                    candidates = self._persistence.port_lease_candidates(authorized)
                    if bool(request.arguments.get("adopt_existing_listener")):
                        selected_port, canonical_root = (
                            self._persistence.listener_adoption_target(authorized)
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
                        "No authorized port is currently free in host listener observations.",
                        operation_id=request.operation_id,
                    )
                if type(selected_port) is not int or selected_port not in candidates:
                    raise BrokerBackendError(
                        "invalid_host_observation",
                        "Typed host port observer returned a candidate it was not asked to inspect.",
                        operation_id=request.operation_id,
                    )
                return self._persistence.complete_port_lease(
                    authorized,
                    observed_available_port=selected_port,
                    listener_evidence=listener_evidence,
                )
            elif request.operation == BrokerOperation.PORT_RELEASE:
                return self._persistence.complete_port_release(authorized)
            elif request.operation == BrokerOperation.SERVER_PUBLISH:
                target = self._persistence.server_publication_target(authorized)
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
                    if (
                        type(listener_evidence.get("owner_uid")) is not int
                        or int(listener_evidence["owner_uid"]) != authorized.peer.uid
                    ):
                        raise BrokerBackendError(
                            "listener_peer_mismatch",
                            "The exact listener is not owned by the authenticated operating-system account.",
                            operation_id=request.operation_id,
                        )
                    if int(listener_evidence.get("pid") or 0) != int(
                        request.arguments["pid"]
                    ):
                        raise BrokerBackendError(
                            "listener_process_mismatch",
                            "Published process identity does not own the exact enrolled listener.",
                            operation_id=request.operation_id,
                        )
                return self._persistence.complete_server_publication(
                    authorized, listener_evidence=listener_evidence
                )
            elif request.operation == BrokerOperation.PORT_ASSIGN:
                candidates = self._persistence.port_assignment_candidates(authorized)
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
                    authorized, observed_available_port=selected_port
                )
            elif request.operation == BrokerOperation.PORT_UNASSIGN:
                return self._persistence.complete_port_unassignment(authorized)
            elif request.operation in {
                BrokerOperation.COMPOSE_UP,
                BrokerOperation.COMPOSE_STOP,
                BrokerOperation.COMPOSE_RESTART,
                BrokerOperation.COMPOSE_DOWN,
            }:
                target = self._persistence.compose_target(authorized)
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
                            authorized,
                            snapshot_id=str(observation["snapshot_id"]),
                        )
                    )
                    result["compose_observation"] = (
                        self._persistence.compose_observation_result(
                            authorized,
                            evidence=observation,
                        )
                    )
                except Exception as exc:
                    try:
                        self._persistence.mark_compose_operation_reconciliation_required(
                            request.operation_id,
                            action=str(result["action"]),
                            failed_phase="observation",
                            completed_phases=tuple(result.get("phases") or ()),
                            cleanup_failed=False,
                            observation=observation,
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
                target = self._persistence.database_target(authorized)
                if request.operation == BrokerOperation.DATABASE_BACKUP:
                    if replay_database_result is None:
                        raw_result = self._host_mutations.postgres_backup(
                            target, output_root=str(self._postgres_backup_root)
                        )
                        journal_result = _json_safe_mapping(raw_result)
                        try:
                            self._persistence.save_database_host_result(
                                authorized, journal_result
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
                            authorized, target, journal_result
                        )
                    except Exception as exc:
                        raise BrokerBackendError(
                            "operation_outcome_uncertain",
                            "PostgreSQL backup completed but its durable registry commit failed; service reconciliation is required.",
                            operation_id=request.operation_id,
                        ) from exc
                else:
                    backup = self._persistence.registered_database_backup(
                        authorized, target
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
                                authorized, journal_result
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
                            authorized,
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
            elif request.operation not in _LIFECYCLE_OPERATIONS:
                # Re-read the live ACL, repository fence, exact membership,
                # control binding, immutable container ID, and observation
                # revision after reservation and immediately before external
                # work.
                target = self._persistence.docker_target(authorized)
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
                            authorized, target
                        )
                    )
                except Exception as exc:
                    raise BrokerBackendError(
                        "operation_outcome_uncertain",
                        "Docker action completed but authoritative service observation did not commit; reconciliation is required.",
                        operation_id=request.operation_id,
                    ) from exc
        except ComposeMutationOutcomeUncertain as exc:
            reconciliation_observation: Mapping[str, Any] | None = None
            try:
                reconciliation_observation = self._observe_fresh_full_docker(
                    request.operation_id,
                    project_id=request.project_id,
                )
            except Exception:
                # The host outcome remains uncertain either way.  Persist only
                # the bounded fact that reconciliation observation failed; no
                # subprocess or observer diagnostics can enter the journal.
                reconciliation_observation = None
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
        return self._persistence.fail_owned_host_observations(
            broker_instance_id=self._broker_instance_id
        )

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
    def _resolve_generic_cleanup_resource(
        store: CoordinatorStore,
        *,
        target_kind: str,
        target_id: str,
        include_archived: bool,
        control_binding_id: str | None = None,
    ) -> tuple[ExactResourceRef, str]:
        persistence = SQLiteLifecyclePersistence(store)
        binding_id = control_binding_id
        if binding_id is None:
            with store.read_transaction() as connection:
                binding = connection.execute(
                    """
                    SELECT binding_id FROM control_bindings
                    WHERE resource_kind = ? AND resource_id = ?
                      AND authority_state = 'authoritative'
                    ORDER BY priority DESC, binding_id LIMIT 1
                    """,
                    (target_kind, target_id),
                ).fetchone()
            if binding is None:
                raise LifecycleError(
                    "cleanup target has no authoritative exact controller"
                )
            binding_id = str(binding["binding_id"])
        exact, repo_id = persistence.resolve_resource(
            ResourceKind(target_kind),
            target_id,
            binding_id,
            include_archived=include_archived,
        )
        if repo_id is None:
            raise LifecycleError("permanent cleanup target has no project boundary")
        return exact, repo_id

    def _authorize_generic_cleanup_resource(
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        store: CoordinatorStore,
        target_kind: str,
        target_id: str,
        operation: BrokerOperation,
        control_binding_id: str | None = None,
    ) -> tuple[ExactResourceRef, str]:
        exact, repo_id = self._resolve_generic_cleanup_resource(
            store,
            target_kind=target_kind,
            target_id=target_id,
            include_archived=True,
            control_binding_id=control_binding_id,
        )
        if repo_id != authorized.request.project_id:
            raise LifecycleError("cleanup target belongs to another project")
        self._persistence.authorize_cleanup_resource(
            authorized,
            repo_id=repo_id,
            resource_kind=target_kind,
            resource_id=exact.resource_id,
            control_binding_id=exact.control_binding_id,
            immutable_fingerprint=exact.immutable_fingerprint,
            ownership_fingerprint=exact.ownership_fingerprint,
            operation=operation,
        )
        return exact, repo_id

    def _plan_generic_archive(
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        store: CoordinatorStore,
        actor: str,
    ) -> dict[str, Any]:
        request = authorized.request
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
            with store.read_transaction() as connection:
                binding = connection.execute(
                    """
                    SELECT binding_id FROM control_bindings
                    WHERE resource_kind = ? AND resource_id = ?
                      AND authority_state = 'authoritative'
                    ORDER BY priority DESC, binding_id LIMIT 1
                    """,
                    (target_kind, target_id),
                ).fetchone()
            if binding is None:
                raise LifecycleError(
                    "archive target has no authoritative exact controller"
                )
            resource_plan_basis, repo_id = persistence.resolve_resource(
                ResourceKind(target_kind), target_id, str(binding["binding_id"])
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
                    "control_binding_id": resource_plan_basis.control_binding_id,
                    "immutable_fingerprint": resource_plan_basis.immutable_fingerprint,
                    "ownership_fingerprint": resource_plan_basis.ownership_fingerprint,
                    "reason": reason,
                },
            )
        else:
            raise LifecycleError("linked worktrees cannot be archived")
        synthetic = AuthorizedBrokerRequest(
            peer=authorized.peer, request=synthetic_request
        )
        # The generic browser route never carries exact controller identity.
        # Resolve it above and require the corresponding exact archive grant
        # before committing even an observation for this plan.
        self._persistence.authorize(authorized.peer, synthetic_request)
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
        authorized: AuthorizedBrokerRequest,
        *,
        store: CoordinatorStore,
        cleanup: CleanupLifecycle,
        actor: str,
    ) -> dict[str, Any]:
        request = authorized.request
        plan_id = str(request.arguments["plan_id"])
        plan_fingerprint = str(request.arguments["plan_fingerprint"])
        confirmation_phrase = str(request.arguments["confirmation_phrase"])
        with store.read_transaction() as connection:
            cleanup_row = connection.execute(
                "SELECT 1 FROM cleanup_plans WHERE plan_id = ?", (plan_id,)
            ).fetchone()
        if cleanup_row is not None:
            cleanup_plan = cleanup.load_plan(plan_id)
            planned_identity: Mapping[str, Any] | None = None
            if cleanup_plan.target_kind in {"server", "container"}:
                identity = cleanup_plan.snapshot.get("identity")
                if not isinstance(identity, Mapping):
                    raise LifecycleError("cleanup plan exact identity is missing")
                planned_identity = identity
                exact, repo_id = self._authorize_generic_cleanup_resource(
                    authorized,
                    store=store,
                    target_kind=cleanup_plan.target_kind,
                    target_id=cleanup_plan.target_id,
                    control_binding_id=str(identity.get("control_binding_id") or ""),
                    operation=BrokerOperation.CLEANUP_APPLY,
                )
                if (
                    repo_id != cleanup_plan.repo_id
                    or exact.immutable_fingerprint
                    != str(identity.get("immutable_fingerprint") or "")
                    or exact.ownership_fingerprint
                    != str(identity.get("ownership_fingerprint") or "")
                ):
                    raise PlanDriftError(
                        "cleanup resource authority changed after planning"
                    )
            observation = self._observe_fresh_full_docker(
                request.operation_id,
                project_id=request.project_id,
            )
            if planned_identity is not None:
                exact, repo_id = self._authorize_generic_cleanup_resource(
                    authorized,
                    store=store,
                    target_kind=cleanup_plan.target_kind,
                    target_id=cleanup_plan.target_id,
                    control_binding_id=str(
                        planned_identity.get("control_binding_id") or ""
                    ),
                    operation=BrokerOperation.CLEANUP_APPLY,
                )
                if (
                    repo_id != cleanup_plan.repo_id
                    or exact.immutable_fingerprint
                    != str(planned_identity.get("immutable_fingerprint") or "")
                    or exact.ownership_fingerprint
                    != str(planned_identity.get("ownership_fingerprint") or "")
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
                    "control_binding_id": plan.target.control_binding_id,
                    "immutable_fingerprint": plan.target.immutable_fingerprint,
                    "ownership_fingerprint": plan.target.ownership_fingerprint,
                    "plan_id": plan_id,
                    "plan_fingerprint": plan_fingerprint,
                },
            )
        else:
            raise LifecycleError("durable plan is not an HTTP archive or purge plan")
        synthetic = AuthorizedBrokerRequest(
            peer=authorized.peer, request=synthetic_request
        )
        # Re-authorize the archive-specific project/resource capability using
        # only the durable plan identity resolved by the service authority.
        self._persistence.authorize(authorized.peer, synthetic_request)
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
        authorized: AuthorizedBrokerRequest,
        *,
        resource_plan_basis: ExactResourceRef | None = None,
    ) -> dict[str, Any]:
        request = authorized.request
        actor = f"broker:{request.account_id}:uid:{authorized.peer.uid}"
        with CoordinatorStore.open(
            self._persistence.database_path,
            expected_uid=self._persistence.expected_uid,
            busy_timeout_ms=self._persistence.busy_timeout_ms,
        ) as store:
            persistence = SQLiteLifecyclePersistence(store)
            lifecycle = RepositoryLifecycle(persistence, self._lifecycle_adapter)
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
                    bindings = _control_binding_contract(store, current.targets)
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
                    resource_plan_basis.control_binding_id,
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
                    control_binding_id=str(request.arguments["control_binding_id"]),
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
                        execution.target.control_binding_id,
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
                        execution.target.control_binding_id,
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
                str(request.arguments["control_binding_id"]),
                str(request.arguments["immutable_fingerprint"]),
            )
            observed = (
                exact.kind.value,
                exact.resource_id,
                exact.control_binding_id,
                exact.immutable_fingerprint,
            )
        else:
            exact, _repo_id = persistence.resolve_resource(
                ResourceKind(str(request.arguments["resource_kind"])),
                request.resource_id,
                str(request.arguments["control_binding_id"]),
                include_archived=request.operation is BrokerOperation.RESOURCE_RESTORE,
            )
            expected = (
                str(request.arguments["resource_kind"]),
                request.resource_id,
                str(request.arguments["control_binding_id"]),
                str(request.arguments["immutable_fingerprint"]),
                str(request.arguments["ownership_fingerprint"]),
            )
            observed = (
                exact.kind.value,
                exact.resource_id,
                exact.control_binding_id,
                exact.immutable_fingerprint,
                exact.ownership_fingerprint,
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


@dataclass(frozen=True)
class StoreBackedBrokerRuntime:
    """Fully wired service boundary; the caller owns server start/close."""

    persistence: BrokerPersistence
    backend: StoreBackedMutationBackend
    writer: SerializedMutationWriter
    service: BrokerService
    server: UnixBrokerServer
    shutdown_timeout_seconds: float = BROKER_SHUTDOWN_DRAIN_TIMEOUT_SECONDS

    def begin_shutdown(self) -> int:
        """Fence mutation admission immediately when the stop signal arrives."""

        return self.writer.begin_shutdown()

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
    access_gid: Optional[int] = None,
    max_clients: int = 32,
    shutdown_timeout_seconds: float = BROKER_SHUTDOWN_DRAIN_TIMEOUT_SECONDS,
    lifecycle_adapter: CoordinatorHostLifecycleAdapter | None = None,
    observe_before_lifecycle_plan: Callable[
        [AccountStore], Mapping[str, Any]
    ]
    | None = None,
) -> StoreBackedBrokerRuntime:
    """Construct the production service without exposing storage to clients."""

    uid = os.geteuid() if service_uid is None else service_uid
    gid = os.getegid() if access_gid is None else access_gid
    persistence = BrokerPersistence(database_path, expected_uid=uid)
    backend = StoreBackedMutationBackend(
        persistence,
        host_mutations,
        lifecycle_adapter=lifecycle_adapter,
        observe_before_lifecycle_plan=observe_before_lifecycle_plan,
    )
    writer = SerializedMutationWriter(
        backend,
        max_concurrent_host_observations=max(0, min(4, max_clients - 1)),
    )
    service = BrokerService(
        StoreBackedAuthorizer(persistence),
        writer,
    )
    server = UnixBrokerServer(
        Path(socket_path),
        service,
        expected_uid=uid,
        expected_gid=gid,
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


def _json_safe_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise BrokerBackendError(
            "invalid_backend_result",
            "Typed host mutation returned an invalid result.",
        )
    # The writer applies the configured response-size bound.  This copy blocks
    # custom mapping objects from changing after the durable commit begins.
    return dict(value)


def _private_postgres_backup_root(database_path: Path, *, expected_uid: int) -> Path:
    root = database_path.expanduser().absolute().parent / "postgres-backups"
    if root.exists():
        metadata = root.lstat()
        if root.is_symlink() or not root.is_dir():
            raise PermissionError("service PostgreSQL backup root must be a real directory")
        if metadata.st_uid != expected_uid:
            raise PermissionError("service PostgreSQL backup root has an unexpected owner")
        if metadata.st_mode & 0o077:
            raise PermissionError("service PostgreSQL backup root must not allow group or other access")
    else:
        root.mkdir(mode=0o700)
    return root
