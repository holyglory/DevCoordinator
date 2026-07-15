"""Production store-backed broker mutation routing.

The wire protocol never carries commands or filesystem paths.  Docker work is
delegated through an exact typed host-action interface after the store resolves
an immutable container ID and revalidates live ACL, membership, control, and
repository-fence state.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Protocol

from .broker import (
    AuthorizedBrokerRequest,
    BrokerBackendError,
    BrokerError,
    BrokerOperation,
    BrokerService,
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
    RepositoryDecommissionPlan,
    RepositoryLifecycle,
    ResourceKind,
    StandaloneRetirementPlan,
)
from .sqlite_lifecycle import SQLiteLifecyclePersistence
from .store import CoordinatorStore


_LIFECYCLE_OPERATIONS = frozenset(
    {
        BrokerOperation.REPOSITORY_PLAN_REMOVE,
        BrokerOperation.REPOSITORY_REMOVE,
        BrokerOperation.REPOSITORY_REINSTALL,
        BrokerOperation.RESOURCE_ATTACH,
        BrokerOperation.RESOURCE_PLAN_RETIRE,
        BrokerOperation.RESOURCE_RETIRE,
    }
)
_LIFECYCLE_PLAN_OPERATIONS = frozenset(
    {
        BrokerOperation.REPOSITORY_PLAN_REMOVE,
        BrokerOperation.RESOURCE_PLAN_RETIRE,
    }
)
_FULL_DOCKER_OBSERVER_DOMAIN = "host-runtime-v2:full-docker"


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
            [CoordinatorStore], Mapping[str, Any]
        ]
        | None = None,
    ) -> None:
        self._persistence = persistence
        self._host_mutations = host_mutations
        self._lifecycle_adapter = lifecycle_adapter or CoordinatorHostLifecycleAdapter()
        self._observe_before_lifecycle_plan = observe_before_lifecycle_plan
        self._postgres_backup_root = _private_postgres_backup_root(
            persistence.database_path, expected_uid=persistence.expected_uid
        )

    def execute(self, authorized: AuthorizedBrokerRequest) -> Mapping[str, Any]:
        request = authorized.request
        if request.operation == BrokerOperation.INVENTORY_READ:
            return self._persistence.inventory(authorized)
        if request.operation == BrokerOperation.REPOSITORY_LIST_REMOVED:
            return {
                "repositories": self._persistence.list_removed_repository(authorized)
            }
        disposition = self._persistence.reserve_operation(authorized)
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
            if request.operation in _LIFECYCLE_OPERATIONS:
                observation_evidence: Mapping[str, Any] | None = None
                required_plan_observation: Mapping[str, Any] | None = None
                apply_observation: Mapping[str, Any] | None = None
                resource_plan_basis: ExactResourceRef | None = None
                if request.operation in _LIFECYCLE_PLAN_OPERATIONS:
                    if request.operation == BrokerOperation.RESOURCE_PLAN_RETIRE:
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
                        request.operation_id
                    )
                if request.operation in {
                    BrokerOperation.REPOSITORY_REMOVE,
                    BrokerOperation.RESOURCE_RETIRE,
                }:
                    # The service must refresh host truth immediately before
                    # applying an older plan.  RepositoryLifecycle then
                    # compares the plan's repo/exact-target snapshots against
                    # this newly committed graph, avoiding false conflicts
                    # from unrelated host-global material changes.
                    apply_observation = self._observe_fresh_full_docker(
                        request.operation_id
                    )
                    required_plan_observation = (
                        self._persistence.require_lifecycle_plan_observation(
                            authorized
                        )
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
                candidates = self._persistence.port_lease_candidates(authorized)
                listener_evidence: Mapping[str, Any] | None = None
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
                BrokerOperation.COMPOSE_DOWN,
            }:
                target = self._persistence.compose_target(authorized)
                if request.operation == BrokerOperation.COMPOSE_UP:
                    raw_result = self._host_mutations.compose_up(target)
                else:
                    raw_result = self._host_mutations.compose_down(target)
                result = _json_safe_mapping(raw_result)
                try:
                    observation = self._observe_fresh_full_docker(
                        request.operation_id
                    )
                    result["broker_observation"] = observation
                    result["observed_resources"] = (
                        self._persistence.repository_container_observations(
                            authorized
                        )
                    )
                except Exception as exc:
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
                        request.operation_id
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
            # External work may already have completed.  The reserved durable
            # row intentionally remains pending so a retry cannot execute it
            # blindly; an observer/reconciler must establish the outcome.
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "Host mutation completed but its durable result could not be committed; reconciliation is required.",
                operation_id=request.operation_id,
            ) from exc
        return result

    def _observe_fresh_full_docker(self, operation_id: str) -> dict[str, Any]:
        observer = self._observe_before_lifecycle_plan
        if observer is None:
            raise BrokerBackendError(
                "lifecycle_observer_unavailable",
                "Repository and standalone retirement planning require a fresh service-owned full-Docker observation.",
                operation_id=operation_id,
            )
        with CoordinatorStore.open(
            self._persistence.database_path,
            expected_uid=self._persistence.expected_uid,
            busy_timeout_ms=self._persistence.busy_timeout_ms,
        ) as store:
            before = store.metadata.observation_revision
            evidence = observer(store)
            after = store.metadata.observation_revision
            if isinstance(evidence, Mapping) and evidence.get("snapshot_id"):
                with store.read_transaction() as connection:
                    committed = connection.execute(
                        """
                        SELECT s.observer_domain, s.status,
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
            or not evidence.get("completed_at")
            or evidence.get("docker_available") is not True
            or not isinstance(evidence.get("capability_fingerprint"), str)
            or not isinstance(evidence.get("material_fingerprint"), str)
            or after <= before
            or committed is None
            or committed["status"] != "completed"
            or committed["observer_domain"] != _FULL_DOCKER_OBSERVER_DOMAIN
            or committed["capability_domain"] != _FULL_DOCKER_OBSERVER_DOMAIN
            or bool(committed["docker_available"]) is not True
            or committed["capability_fingerprint"]
            != evidence.get("capability_fingerprint")
            or committed["material_fingerprint"]
            != evidence.get("material_fingerprint")
            or committed["completed_at"] != evidence.get("completed_at")
        ):
            raise BrokerBackendError(
                "lifecycle_observation_incomplete",
                "Fresh full-Docker observation did not commit bounded service-owned evidence; lifecycle planning was refused.",
                operation_id=operation_id,
            )
        return {
            "snapshot_id": str(evidence["snapshot_id"]),
            "observer_domain": str(committed["observer_domain"]),
            "docker_available": True,
            "capability_fingerprint": str(committed["capability_fingerprint"]),
            "material_fingerprint": str(committed["material_fingerprint"]),
            "completed_at": str(committed["completed_at"]),
            "observation_revision": after,
        }

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
                return plan.to_dict()
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
                request.operation == BrokerOperation.RESOURCE_PLAN_RETIRE
                and resource_plan_basis is not None
            ):
                exact = persistence.resolve_standalone_resource(
                    resource_plan_basis.kind,
                    resource_plan_basis.resource_id,
                    resource_plan_basis.control_binding_id,
                )
                _require_plan_target_identity_unchanged(resource_plan_basis, exact)
            else:
                exact = self._exact_lifecycle_resource(persistence, request)
            if request.operation == BrokerOperation.RESOURCE_ATTACH:
                return lifecycle.attach_resource(
                    request.project_id,
                    exact,
                    actor=actor,
                    reason=str(request.arguments["reason"]),
                ).to_dict()
            if request.operation == BrokerOperation.RESOURCE_PLAN_RETIRE:
                return lifecycle.plan_standalone_retirement(
                    exact,
                    actor=actor,
                    reason=str(request.arguments["reason"]),
                ).to_dict()
            if request.operation == BrokerOperation.RESOURCE_RETIRE:
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
                    current = persistence.resolve_standalone_resource(
                        execution.target.kind,
                        execution.target.resource_id,
                        execution.target.control_binding_id,
                    )
                    _require_target_semantically_unchanged(execution.target, current)
                    result = lifecycle.apply_standalone_retirement(
                        execution.plan_id, execution.fingerprint, actor=actor
                    )
                else:
                    current = persistence.resolve_standalone_resource(
                        execution.target.kind,
                        execution.target.resource_id,
                        execution.target.control_binding_id,
                    )
                    _require_target_semantically_unchanged(execution.target, current)
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
        if request.operation == BrokerOperation.RESOURCE_RETIRE:
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
            exact = persistence.resolve_standalone_resource(
                ResourceKind(str(request.arguments["resource_kind"])),
                request.resource_id,
                str(request.arguments["control_binding_id"]),
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
    service: BrokerService
    server: UnixBrokerServer


def build_store_backed_broker_runtime(
    *,
    database_path: str | os.PathLike[str],
    socket_path: str | os.PathLike[str],
    host_mutations: TypedHostMutationAPI,
    service_uid: Optional[int] = None,
    access_gid: Optional[int] = None,
    max_clients: int = 32,
    lifecycle_adapter: CoordinatorHostLifecycleAdapter | None = None,
    observe_before_lifecycle_plan: Callable[
        [CoordinatorStore], Mapping[str, Any]
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
    service = BrokerService(
        StoreBackedAuthorizer(persistence), SerializedMutationWriter(backend)
    )
    server = UnixBrokerServer(
        Path(socket_path),
        service,
        expected_uid=uid,
        expected_gid=gid,
        max_clients=max_clients,
    )
    return StoreBackedBrokerRuntime(
        persistence=persistence,
        backend=backend,
        service=service,
        server=server,
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
