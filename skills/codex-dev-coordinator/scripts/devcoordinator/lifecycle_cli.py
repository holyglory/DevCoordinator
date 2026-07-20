"""CLI contract for normalized repository and standalone-resource lifecycle."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Callable, Mapping

from .broker import BrokerOperation
from .broker_links import BrokerLinkStore
from .broker_profile import BrokerClientProfile, load_broker_profile
from .cleanup_lifecycle import CleanupLifecycle
from .host_lifecycle import CoordinatorHostLifecycleAdapter
from .repository_lifecycle import ExactResourceRef, RepositoryLifecycle, ResourceKind
from .repository_lifecycle import (
    OperationStatus,
    PlanDriftError,
    RepositoryDecommissionPlan,
    StandaloneRetirementPlan,
)
from .sqlite_lifecycle import SQLiteLifecyclePersistence
from .store import AccountStore


FULL_DOCKER_OBSERVER_DOMAIN = "host-runtime-v2:full-docker"

REPOSITORY_ACTION_ALIASES = {
    "plan-remove": "plan-remove",
    "plan-archive": "plan-remove",
    "remove": "remove",
    "archive": "remove",
    "list-removed": "list-removed",
    "list-archived": "list-removed",
    "reinstall": "reinstall",
    "restore": "reinstall",
}

RESOURCE_ACTION_ALIASES = {
    "plan-retire": "plan-retire",
    "plan-archive": "plan-archive",
    "retire": "retire",
    "archive": "archive",
    "restore": "restore",
    "attach": "attach",
}


def add_lifecycle_parsers(subparsers: Any) -> None:
    repository = subparsers.add_parser(
        "repository", help="plan and apply reversible repository installation lifecycle"
    )
    repository_sub = repository.add_subparsers(dest="action", required=True)

    for action_name in ("plan-remove", "plan-archive"):
        plan_remove = repository_sub.add_parser(action_name)
        _repository_identity_arguments(plan_remove)
        plan_remove.add_argument("--reason", required=True)

    for action_name in ("remove", "archive"):
        remove = repository_sub.add_parser(action_name)
        _repository_identity_arguments(remove)
        remove.add_argument("--plan-id", required=True)
        remove.add_argument("--plan-fingerprint", required=True)

    for action_name in ("list-removed", "list-archived"):
        list_removed = repository_sub.add_parser(action_name)
        list_removed.add_argument("--compact-json", action="store_true")

    for action_name in ("reinstall", "restore"):
        reinstall = repository_sub.add_parser(action_name)
        _repository_identity_arguments(reinstall)
        reinstall.add_argument("--reason", required=True)
        reinstall.add_argument(
            "--explicit",
            action="store_true",
            required=True,
            help="required acknowledgement; clears the fence but never starts resources",
        )

    resource = subparsers.add_parser(
        "resource", help="attach or retire an exact normalized unassigned host resource"
    )
    resource_sub = resource.add_subparsers(dest="action", required=True)

    attach = resource_sub.add_parser("attach")
    _exact_resource_arguments(attach)
    attach.add_argument("--project", required=True)
    attach.add_argument("--agent", required=True)
    attach.add_argument("--reason", required=True)

    plan_retire = resource_sub.add_parser("plan-retire")
    _exact_resource_arguments(plan_retire)
    plan_retire.add_argument("--request-project", required=True)
    plan_retire.add_argument("--agent", required=True)
    plan_retire.add_argument("--reason", required=True)

    retire = resource_sub.add_parser("retire")
    _exact_resource_arguments(retire)
    retire.add_argument("--request-project", required=True)
    retire.add_argument("--agent", required=True)
    retire.add_argument("--plan-id", required=True)
    retire.add_argument("--plan-fingerprint", required=True)

    plan_archive = resource_sub.add_parser("plan-archive")
    _exact_resource_arguments(plan_archive)
    plan_archive.add_argument("--request-project", required=True)
    plan_archive.add_argument("--agent", required=True)
    plan_archive.add_argument("--reason", required=True)

    archive = resource_sub.add_parser("archive")
    _exact_resource_arguments(archive)
    archive.add_argument("--request-project", required=True)
    archive.add_argument("--agent", required=True)
    archive.add_argument("--plan-id", required=True)
    archive.add_argument("--plan-fingerprint", required=True)

    restore_resource = resource_sub.add_parser("restore")
    _exact_resource_arguments(restore_resource)
    restore_resource.add_argument("--request-project", required=True)
    restore_resource.add_argument("--agent", required=True)
    restore_resource.add_argument("--reason", required=True)

    archives = subparsers.add_parser("archives", help="list durable archived and removed targets")
    archives_sub = archives.add_subparsers(dest="action", required=True)
    archive_list = archives_sub.add_parser("list")
    archive_list.add_argument("--agent", required=True)

    cleanup = subparsers.add_parser("cleanup", help="plan and apply permanent exact-target cleanup")
    cleanup_sub = cleanup.add_subparsers(dest="action", required=True)
    cleanup_plan = cleanup_sub.add_parser("plan")
    cleanup_plan.add_argument(
        "--action",
        dest="lifecycle_action",
        choices=["archive", "purge"],
        default="purge",
    )
    cleanup_plan.add_argument(
        "--target-kind",
        choices=["project", "repository", "server", "container", "worktree"],
        required=True,
    )
    cleanup_plan.add_argument("--target-id", required=True)
    cleanup_plan.add_argument("--agent", required=True)
    cleanup_plan.add_argument("--reason", required=True)
    cleanup_apply = cleanup_sub.add_parser("apply")
    cleanup_apply.add_argument("--plan-id", required=True)
    cleanup_apply.add_argument("--plan-fingerprint", required=True)
    cleanup_apply.add_argument("--confirmation-phrase", "--confirm", required=True)
    cleanup_apply.add_argument("--agent", required=True)


def handle_lifecycle_cli(
    args: argparse.Namespace,
    *,
    coordinator_home: Path,
    canonical_project: Callable[[str], str],
    bootstrap_legacy_import: Callable[[AccountStore], Mapping[str, Any]],
    observe_before_plan: Callable[[str, str], Mapping[str, Any]] | None = None,
    observe_before_apply: Callable[[str, str], Mapping[str, Any]] | None = None,
    adapter_factory: Callable[[], CoordinatorHostLifecycleAdapter] = CoordinatorHostLifecycleAdapter,
    broker_profile_loader: Callable[[], BrokerClientProfile | None] | None = None,
) -> Any:
    if args.group == "repository":
        args.action = REPOSITORY_ACTION_ALIASES[str(args.action)]
    # The top-level CLI injects its authority-aware resolver. Keeping the raw
    # profile loader as the default preserves this module's direct contract,
    # while explicit account/test authority cannot be redirected through an
    # installed server-wide profile.
    profile = (
        load_broker_profile()
        if broker_profile_loader is None
        else broker_profile_loader()
    )
    if args.group == "repository" and args.action == "list-removed":
        if profile is not None:
            removed: dict[str, dict[str, Any]] = {}
            for configured in profile.repositories.values():
                # repository() is also the expiry gate.  Iterating the raw
                # mapping must not let an expired root-issued profile bypass
                # the same validity check used by mutation routes.
                repository = profile.repository(configured.canonical_root)
                _operation_id, result = profile.call(
                    repository=repository,
                    resource_id=repository.repo_id,
                    operation=BrokerOperation.REPOSITORY_LIST_REMOVED,
                    arguments={},
                )
                rows = result.get("repositories")
                if not isinstance(rows, list) or any(
                    not isinstance(row, dict) for row in rows
                ):
                    raise RuntimeError(
                        "host broker returned an invalid removed-repository listing"
                    )
                for row in rows:
                    repo_id = str(row.get("repo_id") or "")
                    if not repo_id or repo_id != repository.repo_id:
                        raise RuntimeError(
                            "host broker returned a removed repository outside the enrolled authority"
                        )
                    removed[repo_id] = dict(row)
            return sorted(
                removed.values(),
                key=lambda row: (
                    str(row.get("disabled_at") or ""),
                    str(row.get("display_name") or "").lower(),
                ),
                reverse=True,
            )
        database = coordinator_home / "coordinator.sqlite3"
        if not database.exists():
            return []
        with AccountStore.open_default(coordinator_home) as store:
            return list(SQLiteLifecyclePersistence(store).list_removed_repositories())

    if args.group not in {"repository", "resource", "archives", "cleanup"}:
        raise ValueError("lifecycle CLI received an unrelated command")

    if args.group in {"archives", "cleanup"}:
        if profile is not None:
            return _handle_broker_cleanup(args, profile=profile)
        with AccountStore.open_default(coordinator_home) as store:
            cleanup = CleanupLifecycle(store)
            if args.group == "archives":
                return cleanup.list_archives(actor=str(args.agent))
            if args.action == "plan":
                project_root = _local_cleanup_project_root(
                    store,
                    target_kind=str(args.target_kind),
                    target_id=str(args.target_id),
                )
                if observe_before_plan is None:
                    raise RuntimeError(
                        "cleanup planning requires a current bounded host observation"
                    )
                observe_before_plan(project_root, str(args.agent))
                if str(args.lifecycle_action) == "archive":
                    return _local_archive_plan(
                        store,
                        target_kind=str(args.target_kind),
                        target_id=str(args.target_id),
                        actor=str(args.agent),
                        reason=str(args.reason),
                        adapter_factory=adapter_factory,
                    )
                return cleanup.plan(
                    target_kind=str(args.target_kind),
                    target_id=str(args.target_id),
                    actor=str(args.agent),
                    reason=str(args.reason),
                ).to_dict()
            project_root = _local_cleanup_plan_project_root(
                store, plan_id=str(args.plan_id)
            )
            require_fresh_lifecycle_observation(
                store,
                observe_before_apply,
                project=project_root,
                agent=str(args.agent),
            )
            return _local_generic_apply(
                store,
                cleanup=cleanup,
                plan_id=str(args.plan_id),
                plan_fingerprint=str(args.plan_fingerprint),
                confirmation_phrase=str(args.confirmation_phrase),
                actor=str(args.agent),
                adapter_factory=adapter_factory,
            )

    if profile is not None:
        return _handle_broker_lifecycle(
            args,
            coordinator_home=coordinator_home,
            canonical_project=canonical_project,
            profile=profile,
        )

    with AccountStore.open_default(coordinator_home) as store:
        import_result = dict(bootstrap_legacy_import(store))
        if import_result.get("attempted") and not import_result.get("committed"):
            raise RuntimeError(
                "same-UID legacy coordinator import did not commit; no lifecycle action was attempted"
            )
        late_writers = list(import_result.get("late_writer_sources") or [])
        if late_writers:
            raise RuntimeError(
                "a retired same-UID coordinator source changed after import; observe and reconcile before lifecycle mutation"
            )
        persistence = SQLiteLifecyclePersistence(store)
        lifecycle = RepositoryLifecycle(persistence, adapter_factory())

        if args.group == "repository":
            if args.action == "plan-remove":
                if observe_before_plan is None:
                    raise RuntimeError(
                        "repository removal planning requires a current bounded host observation"
                    )
                observe_before_plan(str(args.project), str(args.agent))
            repo_id, repository = _resolve_repository(
                store, canonical_project(str(args.project))
            )
            if args.action == "plan-remove":
                plan = lifecycle.plan_repository_decommission(
                    repo_id, actor=str(args.agent), reason=str(args.reason)
                )
                payload = plan.to_dict()
                payload.update(
                    {
                        "canonical_root": repository["canonical_root"],
                        "display_name": repository["display_name"],
                        "target_kind": "project",
                        "target_id": repo_id,
                        "target": {
                            "target_kind": "project",
                            "target_id": repo_id,
                            "display_name": repository["display_name"],
                            "project_id": repo_id,
                        },
                        "blockers": [],
                    }
                )
                return payload
            if args.action == "remove":
                confirmed = _confirmed_repository_plan(
                    persistence,
                    plan_id=str(args.plan_id),
                    plan_fingerprint=str(args.plan_fingerprint),
                    repo_id=repo_id,
                )
                execution = _repository_execution_plan(persistence, confirmed)
                progress = persistence.operation_progress(execution.plan_id)
                if progress.status is OperationStatus.SUCCEEDED:
                    result = lifecycle.apply_repository_decommission(
                        execution.plan_id,
                        execution.fingerprint,
                        actor=str(args.agent),
                    )
                    return _apply_result(
                        result.to_dict(), confirmed=confirmed, observation=None
                    )
                if progress.status is not OperationStatus.PLANNED:
                    before = persistence.repository_snapshot(repo_id)
                    _require_resumable_repository_snapshot(
                        execution, before, progress=progress
                    )
                    before_bindings = _control_binding_contract(
                        store, before.targets
                    )
                    observation = require_fresh_lifecycle_observation(
                        store,
                        observe_before_apply,
                        project=str(repository["canonical_root"]),
                        agent=str(args.agent),
                    )
                    current = persistence.repository_snapshot(repo_id)
                    _require_resumable_repository_snapshot(
                        execution, current, progress=progress
                    )
                    if before_bindings != _control_binding_contract(
                        store, current.targets
                    ):
                        raise PlanDriftError(
                            "repository controller changed during current observation"
                        )
                    result = lifecycle.apply_repository_decommission(
                        execution.plan_id,
                        execution.fingerprint,
                        actor=str(args.agent),
                    )
                    return _apply_result(
                        result.to_dict(),
                        confirmed=confirmed,
                        observation=observation,
                    )

                before = persistence.repository_snapshot(repo_id)
                before_bindings = _control_binding_contract(store, before.targets)
                _require_repository_semantically_unchanged(
                    execution,
                    before,
                    before_bindings=before_bindings,
                    current_bindings=before_bindings,
                )
                observation = require_fresh_lifecycle_observation(
                    store,
                    observe_before_apply,
                    project=str(repository["canonical_root"]),
                    agent=str(args.agent),
                )
                current = persistence.repository_snapshot(repo_id)
                _require_repository_semantically_unchanged(
                    execution,
                    current,
                    before_bindings=before_bindings,
                    current_bindings=_control_binding_contract(store, current.targets),
                )
                refreshed = lifecycle.plan_repository_decommission(
                    repo_id,
                    actor=str(args.agent),
                    reason=confirmed.reason,
                )
                _require_repository_refresh_matches(execution, refreshed)
                persistence.bind_lifecycle_plan_successor(execution, refreshed)
                result = lifecycle.apply_repository_decommission(
                    refreshed.plan_id,
                    refreshed.fingerprint,
                    actor=str(args.agent),
                )
                return _apply_result(
                    result.to_dict(),
                    confirmed=confirmed,
                    observation=observation,
                )
            if args.action == "reinstall":
                return lifecycle.reinstall_repository(
                    repo_id,
                    actor=str(args.agent),
                    reason=str(args.reason),
                    explicit=bool(args.explicit),
                ).to_dict()
            raise ValueError("unsupported repository lifecycle action")

        request_project = canonical_project(
            str(args.request_project if hasattr(args, "request_project") else args.project)
        )
        if args.action in {"retire", "archive"}:
            confirmed = _confirmed_retirement_plan(
                persistence,
                plan_id=str(args.plan_id),
                plan_fingerprint=str(args.plan_fingerprint),
                resource_kind=ResourceKind(str(args.resource_kind)),
                resource_id=str(args.resource_id),
                control_binding_id=str(args.control_binding_id),
            )
            _verify_cli_exact_identity(args, confirmed.target)
            execution = _retirement_execution_plan(persistence, confirmed)
            progress = persistence.operation_progress(execution.plan_id)
            if progress.status is OperationStatus.SUCCEEDED:
                result = lifecycle.apply_standalone_retirement(
                    execution.plan_id,
                    execution.fingerprint,
                    actor=str(args.agent),
                )
                return _apply_result(
                    result.to_dict(), confirmed=confirmed, observation=None
                )
            if progress.status is not OperationStatus.PLANNED:
                current_before, current_before_repo_id = persistence.resolve_resource(
                    execution.target.kind,
                    execution.target.resource_id,
                    execution.target.control_binding_id,
                    include_archived=True,
                )
                if current_before_repo_id != execution.repo_id:
                    raise PlanDriftError("resource repository attachment changed")
                _require_target_semantically_unchanged(
                    execution.target, current_before
                )
                before_bindings = _control_binding_contract(
                    store, (current_before,)
                )
                observation = require_fresh_lifecycle_observation(
                    store,
                    observe_before_apply,
                    project=request_project,
                    agent=str(args.agent),
                )
                current, current_repo_id = persistence.resolve_resource(
                    execution.target.kind,
                    execution.target.resource_id,
                    execution.target.control_binding_id,
                    include_archived=True,
                )
                if current_repo_id != execution.repo_id:
                    raise PlanDriftError("resource repository attachment changed")
                _require_target_semantically_unchanged(execution.target, current)
                if before_bindings != _control_binding_contract(store, (current,)):
                    raise PlanDriftError(
                        "standalone resource controller changed during current observation"
                    )
                result = lifecycle.apply_standalone_retirement(
                    execution.plan_id,
                    execution.fingerprint,
                    actor=str(args.agent),
                )
                return _apply_result(
                    result.to_dict(),
                    confirmed=confirmed,
                    observation=observation,
                )

            current_before, current_before_repo_id = persistence.resolve_resource(
                execution.target.kind,
                execution.target.resource_id,
                execution.target.control_binding_id,
                include_archived=True,
            )
            if current_before_repo_id != execution.repo_id:
                raise PlanDriftError("resource repository attachment changed")
            _require_target_semantically_unchanged(execution.target, current_before)
            before_bindings = _control_binding_contract(store, (current_before,))
            observation = require_fresh_lifecycle_observation(
                store,
                observe_before_apply,
                project=request_project,
                agent=str(args.agent),
            )
            current, current_repo_id = persistence.resolve_resource(
                execution.target.kind,
                execution.target.resource_id,
                execution.target.control_binding_id,
                include_archived=True,
            )
            if current_repo_id != execution.repo_id:
                raise PlanDriftError("resource repository attachment changed")
            _require_target_semantically_unchanged(execution.target, current)
            if before_bindings != _control_binding_contract(store, (current,)):
                raise PlanDriftError(
                    "standalone resource controller changed during current observation"
                )
            if confirmed.repo_id is not None or args.action == "archive":
                refreshed = lifecycle.plan_resource_archive(
                    current,
                    actor=str(args.agent),
                    reason=confirmed.reason,
                    repo_id=confirmed.repo_id,
                )
            else:
                refreshed = lifecycle.plan_standalone_retirement(
                    current,
                    actor=str(args.agent),
                    reason=confirmed.reason,
                )
            _require_retirement_refresh_matches(execution, refreshed)
            persistence.bind_lifecycle_plan_successor(execution, refreshed)
            result = lifecycle.apply_standalone_retirement(
                refreshed.plan_id,
                refreshed.fingerprint,
                actor=str(args.agent),
            )
            return _apply_result(
                result.to_dict(),
                confirmed=confirmed,
                observation=observation,
            )

        if args.action in {"plan-archive", "restore"}:
            exact, attached_repo_id = persistence.resolve_resource(
                ResourceKind(str(args.resource_kind)),
                str(args.resource_id),
                str(args.control_binding_id),
                include_archived=args.action == "restore",
            )
        else:
            exact = persistence.resolve_standalone_resource(
                ResourceKind(str(args.resource_kind)),
                str(args.resource_id),
                str(args.control_binding_id),
            )
            attached_repo_id = None
        _verify_cli_exact_identity(args, exact)
        if args.action in {"plan-retire", "plan-archive"}:
            if observe_before_plan is None:
                raise RuntimeError(
                    "standalone retirement planning requires a current bounded host observation"
                )
            observe_before_plan(request_project, str(args.agent))
            if args.action == "plan-archive":
                observed_exact, observed_repo_id = persistence.resolve_resource(
                    ResourceKind(str(args.resource_kind)),
                    str(args.resource_id),
                    str(args.control_binding_id),
                )
                if observed_repo_id != attached_repo_id:
                    raise PlanDriftError(
                        "resource repository attachment changed during observation"
                    )
            else:
                observed_exact = persistence.resolve_standalone_resource(
                    ResourceKind(str(args.resource_kind)),
                    str(args.resource_id),
                    str(args.control_binding_id),
                )
            _require_plan_target_identity_unchanged(exact, observed_exact)
            exact = observed_exact
        if args.action == "attach":
            repo_id, _repository = _resolve_repository(
                store, canonical_project(str(args.project))
            )
            return lifecycle.attach_resource(
                repo_id,
                exact,
                actor=str(args.agent),
                reason=str(args.reason),
            ).to_dict()
        if args.action == "plan-retire":
            plan = lifecycle.plan_standalone_retirement(
                exact,
                actor=str(args.agent),
                reason=str(args.reason),
            )
            payload = plan.to_dict()
            payload["target"] = persistence.describe_resource(exact, None)
            return payload
        if args.action == "plan-archive":
            plan = lifecycle.plan_resource_archive(
                exact,
                actor=str(args.agent),
                reason=str(args.reason),
                repo_id=attached_repo_id,
            )
            payload = plan.to_dict()
            payload["target"] = persistence.describe_resource(exact, attached_repo_id)
            return payload
        if args.action == "restore":
            return lifecycle.restore_resource_archive(
                exact,
                actor=str(args.agent),
                reason=str(args.reason),
            )
        raise ValueError("unsupported resource lifecycle action")


def _handle_broker_lifecycle(
    args: argparse.Namespace,
    *,
    coordinator_home: Path,
    canonical_project: Callable[[str], str],
    profile: Any,
) -> dict[str, Any]:
    """Route configured multi-user lifecycle through the service authority."""

    if args.group == "repository":
        repository = profile.repository(canonical_project(str(args.project)))
        if args.action == "plan-remove":
            operation = BrokerOperation.REPOSITORY_PLAN_REMOVE
            resource_id = repository.repo_id
            arguments = {"reason": str(args.reason)}
        elif args.action == "remove":
            operation = BrokerOperation.REPOSITORY_REMOVE
            resource_id = repository.repo_id
            arguments = {
                "plan_id": str(args.plan_id),
                "plan_fingerprint": str(args.plan_fingerprint),
            }
        elif args.action == "reinstall":
            operation = BrokerOperation.REPOSITORY_REINSTALL
            resource_id = repository.repo_id
            arguments = {
                "reason": str(args.reason),
                "explicit": bool(args.explicit),
            }
        else:
            raise ValueError("unsupported broker repository lifecycle action")
    else:
        anchor = canonical_project(
            str(args.project if args.action == "attach" else args.request_project)
        )
        repository = profile.repository(anchor)
        resource_id = str(args.resource_id)
        arguments = {
            "resource_kind": str(args.resource_kind),
            "control_binding_id": str(args.control_binding_id),
            "immutable_fingerprint": str(args.immutable_fingerprint),
            "ownership_fingerprint": str(args.ownership_fingerprint),
        }
        if args.action == "attach":
            operation = BrokerOperation.RESOURCE_ATTACH
            arguments["reason"] = str(args.reason)
        elif args.action == "plan-retire":
            operation = BrokerOperation.RESOURCE_PLAN_RETIRE
            arguments["reason"] = str(args.reason)
        elif args.action == "plan-archive":
            operation = BrokerOperation.RESOURCE_PLAN_ARCHIVE
            arguments["reason"] = str(args.reason)
        elif args.action == "retire":
            operation = BrokerOperation.RESOURCE_RETIRE
            arguments["plan_id"] = str(args.plan_id)
            arguments["plan_fingerprint"] = str(args.plan_fingerprint)
        elif args.action == "archive":
            operation = BrokerOperation.RESOURCE_ARCHIVE
            arguments["plan_id"] = str(args.plan_id)
            arguments["plan_fingerprint"] = str(args.plan_fingerprint)
        elif args.action == "restore":
            operation = BrokerOperation.RESOURCE_RESTORE
            arguments["reason"] = str(args.reason)
        else:
            raise ValueError("unsupported broker resource lifecycle action")

    operation_id, result = profile.call(
        repository=repository,
        resource_id=resource_id,
        operation=operation,
        arguments=arguments,
    )
    payload = dict(result)
    payload["broker"] = {
        "operation_id": operation_id,
        "operation": operation.value,
        "authority": "host_broker",
    }
    if operation == BrokerOperation.REPOSITORY_PLAN_REMOVE:
        payload.update(
            {
                "canonical_root": repository.canonical_root,
                "display_name": Path(repository.canonical_root).name
                or repository.canonical_root,
                "blockers": [],
            }
        )
        return payload
    if operation in {
        BrokerOperation.RESOURCE_PLAN_RETIRE,
        BrokerOperation.RESOURCE_PLAN_ARCHIVE,
    }:
        return payload

    if operation in {
        BrokerOperation.RESOURCE_ARCHIVE,
        BrokerOperation.RESOURCE_RESTORE,
    }:
        return payload

    with AccountStore.open_default(coordinator_home) as store:
        mirror = BrokerLinkStore(store).record_and_apply_lifecycle(
            profile=profile,
            repository=repository,
            operation=operation,
            resource_id=resource_id,
            operation_id=operation_id,
            arguments=arguments,
            result=result,
        )
    payload["broker"]["local_mirror"] = mirror
    return payload


def _local_cleanup_project_root(
    store: AccountStore, *, target_kind: str, target_id: str
) -> str:
    kind = "project" if target_kind == "repository" else target_kind
    with store.read_transaction() as connection:
        if kind in {"project", "worktree"}:
            row = connection.execute(
                "SELECT canonical_root FROM repositories WHERE repo_id = ?",
                (target_id,),
            ).fetchone()
        else:
            row = connection.execute(
                """
                SELECT r.canonical_root
                FROM repository_memberships m
                JOIN repositories r USING(repo_id)
                WHERE m.resource_kind = ? AND m.host_resource_id = ?
                """,
                (kind, target_id),
            ).fetchone()
    if row is None:
        raise RuntimeError("cleanup target has no observable project boundary")
    return str(row["canonical_root"])


def _local_cleanup_plan_project_root(store: AccountStore, *, plan_id: str) -> str:
    with store.read_transaction() as connection:
        row = connection.execute(
            """
            SELECT r.canonical_root
            FROM operations o JOIN repositories r USING(repo_id)
            WHERE o.operation_id = ?
            """,
            (plan_id,),
        ).fetchone()
    if row is None:
        raise RuntimeError("cleanup plan has no observable project boundary")
    return str(row["canonical_root"])


def _common_archive_plan_payload(
    plan: RepositoryDecommissionPlan | StandaloneRetirementPlan,
    target: Mapping[str, Any],
) -> dict[str, Any]:
    target_kind = "project" if isinstance(plan, RepositoryDecommissionPlan) else plan.target.kind.value
    payload = plan.to_dict()
    payload.update(
        {
            "plan_fingerprint": plan.fingerprint,
            "action": "archive",
            "confirmation_phrase": "",
            "target": dict(target),
            "target_kind": target_kind,
            "target_id": str(target["target_id"]),
            "effects": [
                "disable_captured_startup_policies",
                "stop_exact_resource" if target_kind != "project" else "stop_exact_project_resources",
                "deactivate_port_allocations",
                "hide_from_active_inventory",
            ],
            "retained": list(payload.get("retained_data") or []),
            "deleted": [],
            "blockers": [],
            "status": "planned",
        }
    )
    return payload


def _local_archive_plan(
    store: AccountStore,
    *,
    target_kind: str,
    target_id: str,
    actor: str,
    reason: str,
    adapter_factory: Callable[[], CoordinatorHostLifecycleAdapter],
) -> dict[str, Any]:
    kind = "project" if target_kind == "repository" else target_kind
    persistence = SQLiteLifecyclePersistence(store)
    lifecycle = RepositoryLifecycle(persistence, adapter_factory())
    if kind == "project":
        plan = lifecycle.plan_repository_decommission(
            target_id, actor=actor, reason=reason
        )
        with store.read_transaction() as connection:
            row = connection.execute(
                "SELECT display_name FROM repositories WHERE repo_id = ?", (target_id,)
            ).fetchone()
        if row is None:
            raise RuntimeError("archive target disappeared during planning")
        return _common_archive_plan_payload(
            plan,
            {
                "target_kind": "project",
                "target_id": target_id,
                "display_name": str(row["display_name"]),
                "project_id": target_id,
            },
        )
    if kind not in {"server", "container"}:
        raise ValueError("linked worktrees cannot be archived")
    with store.read_transaction() as connection:
        binding = connection.execute(
            """
            SELECT binding_id FROM control_bindings
            WHERE resource_kind = ? AND resource_id = ?
              AND authority_state = 'authoritative'
            ORDER BY priority DESC, binding_id LIMIT 1
            """,
            (kind, target_id),
        ).fetchone()
    if binding is None:
        raise RuntimeError("archive target has no authoritative exact controller")
    exact, repo_id = persistence.resolve_resource(
        ResourceKind(kind), target_id, str(binding["binding_id"])
    )
    plan = lifecycle.plan_resource_archive(
        exact, actor=actor, reason=reason, repo_id=repo_id
    )
    return _common_archive_plan_payload(plan, persistence.describe_resource(exact, repo_id))


def _local_generic_apply(
    store: AccountStore,
    *,
    cleanup: CleanupLifecycle,
    plan_id: str,
    plan_fingerprint: str,
    confirmation_phrase: str,
    actor: str,
    adapter_factory: Callable[[], CoordinatorHostLifecycleAdapter],
) -> dict[str, Any]:
    with store.read_transaction() as connection:
        is_purge = connection.execute(
            "SELECT 1 FROM cleanup_plans WHERE plan_id = ?", (plan_id,)
        ).fetchone() is not None
    if is_purge:
        return cleanup.apply(
            plan_id=plan_id,
            plan_fingerprint=plan_fingerprint,
            confirmation_phrase=confirmation_phrase,
            actor=actor,
        )
    if confirmation_phrase:
        raise ValueError("archive apply requires an empty confirmation phrase")
    persistence = SQLiteLifecyclePersistence(store)
    plan = persistence.load_plan(plan_id)
    lifecycle = RepositoryLifecycle(persistence, adapter_factory())
    if isinstance(plan, RepositoryDecommissionPlan):
        payload = lifecycle.apply_repository_decommission(
            plan_id, plan_fingerprint, actor=actor
        ).to_dict()
    elif isinstance(plan, StandaloneRetirementPlan) and plan.repo_id is not None:
        payload = lifecycle.apply_standalone_retirement(
            plan_id, plan_fingerprint, actor=actor
        ).to_dict()
    else:
        raise ValueError("plan is not an archive or purge plan")
    status = str(payload.get("status") or "")
    payload.update(
        {
            "action": "archive",
            "partial": status == "needs_attention",
            "needs_attention": status == "needs_attention",
            "ok": status in {"succeeded", "already_complete"},
        }
    )
    return payload


def _handle_broker_cleanup(
    args: argparse.Namespace,
    *,
    profile: BrokerClientProfile,
) -> dict[str, Any]:
    """Route cleanup only through enrolled service authority; never open its DB."""

    repositories = tuple(
        profile.repository(item.canonical_root)
        for item in sorted(
            profile.repositories.values(), key=lambda item: item.canonical_root
        )
    )
    if not repositories:
        raise RuntimeError("cleanup requires at least one enrolled broker repository")
    if args.group == "archives":
        archives: dict[tuple[str, str], dict[str, Any]] = {}
        for repository in repositories:
            _operation_id, result = profile.call(
                repository=repository,
                resource_id=repository.repo_id,
                operation=BrokerOperation.ARCHIVES_READ,
                arguments={},
            )
            rows = result.get("archives")
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise RuntimeError("host broker returned an invalid archive listing")
            for row in rows:
                project_id = str(row.get("project_id") or row.get("target_id") or "")
                if project_id != repository.repo_id:
                    raise RuntimeError("host broker returned an archive outside enrolled authority")
                key = (str(row.get("target_kind") or ""), str(row.get("target_id") or ""))
                archives[key] = dict(row)
        return {
            "archives": sorted(
                archives.values(),
                key=lambda item: (
                    str(item.get("archived_at") or ""),
                    str(item.get("display_name") or "").lower(),
                ),
                reverse=True,
            )
        }

    if args.action == "plan":
        kind = "project" if str(args.target_kind) == "repository" else str(args.target_kind)
        target_id = str(args.target_id)
        matches = []
        for repository in repositories:
            if kind in {"project", "worktree"} and repository.repo_id == target_id:
                matches.append(repository)
            elif kind == "server" and target_id in set(repository.server_ids.values()):
                matches.append(repository)
            elif kind == "container" and target_id in set(repository.container_ids.values()):
                matches.append(repository)
        if len(matches) != 1:
            raise RuntimeError(
                "cleanup target is not uniquely enrolled; refresh the root-issued broker profile"
            )
        repository = matches[0]
        operation = BrokerOperation.CLEANUP_PLAN
        arguments = {
            "action": str(args.lifecycle_action),
            "target_kind": kind,
            "target_id": target_id,
            "reason": str(args.reason),
        }
        resource_id = target_id
    else:
        # The service resolves the durable plan to its exact repository and
        # rechecks that repository's live cleanup grant.  The anchor only
        # authenticates the installed profile; no client DB lookup is used.
        repository = repositories[0]
        operation = BrokerOperation.CLEANUP_APPLY
        arguments = {
            "plan_id": str(args.plan_id),
            "plan_fingerprint": str(args.plan_fingerprint),
            "confirmation_phrase": str(args.confirmation_phrase),
        }
        resource_id = repository.repo_id
    operation_id, result = profile.call(
        repository=repository,
        resource_id=resource_id,
        operation=operation,
        arguments=arguments,
    )
    payload = dict(result)
    payload["broker"] = {
        "operation_id": operation_id,
        "operation": operation.value,
        "authority": "host_broker",
    }
    return payload


def _repository_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project", required=True)
    parser.add_argument("--agent", required=True)


def _exact_resource_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--resource-kind", choices=[item.value for item in ResourceKind], required=True
    )
    parser.add_argument("--resource-id", required=True)
    parser.add_argument("--immutable-fingerprint", required=True)
    parser.add_argument("--control-binding-id", required=True)
    parser.add_argument("--ownership-fingerprint", required=True)


def _resolve_repository(store: AccountStore, canonical_root: str) -> tuple[str, dict[str, Any]]:
    with store.read_transaction() as connection:
        row = connection.execute(
            """
            SELECT repo_id, canonical_root, display_name, state
            FROM repositories WHERE canonical_root = ?
            """,
            (canonical_root,),
        ).fetchone()
    if row is None:
        raise RuntimeError(
            "repository is not installed in the normalized coordinator; run observe or use the Coordinator installation journey"
        )
    if str(row["state"]) != "active":
        raise RuntimeError("repository is not an active canonical worktree")
    return str(row["repo_id"]), dict(row)


def _verify_cli_exact_identity(args: argparse.Namespace, exact: ExactResourceRef) -> None:
    if str(args.immutable_fingerprint) != exact.immutable_fingerprint:
        raise RuntimeError("host resource immutable fingerprint changed; refresh before acting")
    if str(args.ownership_fingerprint) != exact.ownership_fingerprint:
        raise RuntimeError("host resource controller fingerprint changed; refresh before acting")


def _confirmed_repository_plan(
    persistence: SQLiteLifecyclePersistence,
    *,
    plan_id: str,
    plan_fingerprint: str,
    repo_id: str,
) -> RepositoryDecommissionPlan:
    plan = persistence.load_plan(plan_id)
    if not isinstance(plan, RepositoryDecommissionPlan):
        raise RuntimeError(f"plan {plan_id} is not a repository decommission")
    if plan.fingerprint != plan_fingerprint:
        raise PlanDriftError("plan fingerprint does not match the durable plan")
    if plan.repo_id != repo_id:
        raise RuntimeError("stored removal plan belongs to another repository")
    return plan


def _confirmed_retirement_plan(
    persistence: SQLiteLifecyclePersistence,
    *,
    plan_id: str,
    plan_fingerprint: str,
    resource_kind: ResourceKind,
    resource_id: str,
    control_binding_id: str,
) -> StandaloneRetirementPlan:
    plan = persistence.load_plan(plan_id)
    if not isinstance(plan, StandaloneRetirementPlan):
        raise RuntimeError(f"plan {plan_id} is not a standalone retirement")
    if plan.fingerprint != plan_fingerprint:
        raise PlanDriftError("plan fingerprint does not match the durable plan")
    if (
        plan.target.kind is not resource_kind
        or plan.target.resource_id != resource_id
        or plan.target.control_binding_id != control_binding_id
    ):
        raise RuntimeError("stored retirement plan belongs to another host resource")
    return plan


def _repository_execution_plan(
    persistence: SQLiteLifecyclePersistence,
    confirmed: RepositoryDecommissionPlan,
) -> RepositoryDecommissionPlan:
    execution = persistence.resolve_lifecycle_plan(confirmed.plan_id)
    if not isinstance(execution, RepositoryDecommissionPlan):
        raise PlanDriftError("repository plan successor has the wrong operation kind")
    _require_repository_refresh_matches(confirmed, execution)
    return execution


def _retirement_execution_plan(
    persistence: SQLiteLifecyclePersistence,
    confirmed: StandaloneRetirementPlan,
) -> StandaloneRetirementPlan:
    execution = persistence.resolve_lifecycle_plan(confirmed.plan_id)
    if not isinstance(execution, StandaloneRetirementPlan):
        raise PlanDriftError("retirement plan successor has the wrong operation kind")
    _require_retirement_refresh_matches(confirmed, execution)
    if execution.reason != confirmed.reason:
        raise PlanDriftError("retirement plan successor changed the confirmed reason")
    return execution


def require_fresh_lifecycle_observation(
    store: AccountStore,
    callback: Callable[[str, str], Mapping[str, Any]] | None,
    *,
    project: str,
    agent: str,
) -> dict[str, Any]:
    if callback is None:
        raise RuntimeError(
            "lifecycle apply requires a fresh bounded full-Docker host observation"
        )
    result = callback(project, agent)
    if not isinstance(result, Mapping):
        raise RuntimeError("pre-apply host observation returned a malformed result")
    snapshot_id = str(result.get("snapshot_id") or "")
    observer_domain = str(result.get("observer_domain") or "")
    completed_at = str(result.get("completed_at") or "")
    material_fingerprint = str(result.get("material_fingerprint") or "")
    host_id = str(result.get("host_id") or "")
    max_age = result.get("max_age_seconds")
    request = result.get("request")
    if (
        result.get("status") != "completed"
        or result.get("observed") is not True
        or not isinstance(result.get("joined"), bool)
        or isinstance(max_age, bool)
        or not isinstance(max_age, (int, float))
        or float(max_age) != 0.0
        or observer_domain != FULL_DOCKER_OBSERVER_DOMAIN
        or not snapshot_id
        or not completed_at
        or not material_fingerprint
        or not host_id
        or not isinstance(request, Mapping)
        or str(request.get("project") or "") != project
        or str(request.get("agent") or "") != agent
    ):
        raise RuntimeError(
            "pre-apply host observation was not a fresh successful full-Docker observation"
        )
    with store.read_transaction() as connection:
        row = connection.execute(
            """
            SELECT s.host_id, s.observer_domain, s.status, s.material_fingerprint,
                   s.completed_at, c.observer_domain AS capability_domain,
                   c.docker_available, c.capability_fingerprint, c.committed_at
            FROM observation_snapshots s
            LEFT JOIN observation_capabilities c USING(snapshot_id)
            WHERE s.snapshot_id = ?
            """,
            (snapshot_id,),
        ).fetchone()
    if (
        row is None
        or str(row["host_id"]) != host_id
        or str(row["observer_domain"]) != FULL_DOCKER_OBSERVER_DOMAIN
        or str(row["status"]) != "completed"
        or str(row["material_fingerprint"] or "") != material_fingerprint
        or str(row["completed_at"] or "") != completed_at
        or str(row["capability_domain"] or "") != FULL_DOCKER_OBSERVER_DOMAIN
        or not str(row["capability_fingerprint"] or "")
        or not str(row["committed_at"] or "")
    ):
        raise RuntimeError(
            "pre-apply host observation lacks exact committed full-Docker capability evidence"
        )
    if int(row["docker_available"]) != 1:
        raise RuntimeError(
            "Docker is unavailable in the fresh pre-apply host observation; no lifecycle host effect was attempted"
        )
    return {
        "snapshot_id": snapshot_id,
        "observer_domain": observer_domain,
        "completed_at": completed_at,
        "material_fingerprint": material_fingerprint,
        "joined": bool(result["joined"]),
        "docker_available": True,
    }


def _require_repository_plan_current(
    plan: RepositoryDecommissionPlan, snapshot: Any
) -> None:
    if (
        snapshot.repository_fingerprint != plan.repository_fingerprint
        or snapshot.installation_generation != plan.installation_generation
        or tuple(sorted(snapshot.targets, key=lambda item: item.ledger_key))
        != plan.targets
        or tuple(
            sorted(
                snapshot.repository_allocations,
                key=lambda item: (item.kind.value, item.allocation_id),
            )
        )
        != plan.repository_allocations
    ):
        raise PlanDriftError("repository changed after the plan was recorded")


def _require_repository_semantically_unchanged(
    plan: RepositoryDecommissionPlan,
    snapshot: Any,
    *,
    before_bindings: Mapping[str, Any],
    current_bindings: Mapping[str, Any],
) -> None:
    if snapshot.installation_generation != plan.installation_generation:
        raise PlanDriftError("repository installation changed during current observation")
    if snapshot.installation_status != "installed" or snapshot.startup_fenced:
        raise PlanDriftError("repository became fenced during current observation")
    if snapshot.unresolved_conflicts:
        raise PlanDriftError(
            "repository control became ambiguous during current observation: "
            + ", ".join(snapshot.unresolved_conflicts)
        )
    if _target_contracts(snapshot.targets) != _target_contracts(plan.targets):
        raise PlanDriftError("repository resources changed during current observation")
    if tuple(
        sorted(
            snapshot.repository_allocations,
            key=lambda item: (item.kind.value, item.allocation_id),
        )
    ) != plan.repository_allocations:
        raise PlanDriftError("repository allocations changed during current observation")
    if dict(before_bindings) != dict(current_bindings):
        raise PlanDriftError("repository controller changed during current observation")


def _require_resumable_repository_snapshot(
    plan: RepositoryDecommissionPlan,
    snapshot: Any,
    *,
    progress: Any,
) -> None:
    """Reject new/replaced remaining work before a fenced operation resumes."""

    if snapshot.installation_status != "disabling" or not snapshot.startup_fenced:
        raise PlanDriftError("repository lifecycle fence changed before resume")
    if snapshot.unresolved_conflicts:
        raise PlanDriftError(
            "repository control became ambiguous before resume: "
            + ", ".join(snapshot.unresolved_conflicts)
        )
    planned = {target.ledger_key: target for target in plan.targets}
    current = {target.ledger_key: target for target in snapshot.targets}
    if set(current) != set(planned) or {
        key: _target_identity_contract(target) for key, target in current.items()
    } != {
        key: _target_identity_contract(target) for key, target in planned.items()
    }:
        raise PlanDriftError("repository resources changed before lifecycle resume")
    if set(progress.targets) != set(planned):
        raise PlanDriftError("repository target ledger changed before lifecycle resume")
    for key, target in current.items():
        planned_allocations = set(planned[key].allocations)
        if not set(target.allocations).issubset(planned_allocations):
            raise PlanDriftError(
                f"repository allocations changed for {key[0]}:{key[1]} before resume"
            )
    if not set(snapshot.repository_allocations).issubset(
        set(plan.repository_allocations)
    ):
        raise PlanDriftError("repository allocations changed before lifecycle resume")


def _require_repository_refresh_matches(
    confirmed: RepositoryDecommissionPlan,
    refreshed: RepositoryDecommissionPlan,
) -> None:
    if (
        refreshed.repo_id != confirmed.repo_id
        or refreshed.installation_generation != confirmed.installation_generation
        or refreshed.reason != confirmed.reason
        or _target_contracts(refreshed.targets) != _target_contracts(confirmed.targets)
        or refreshed.repository_allocations != confirmed.repository_allocations
    ):
        raise PlanDriftError("fresh repository plan does not match the confirmed target set")


def _require_retirement_refresh_matches(
    confirmed: StandaloneRetirementPlan,
    refreshed: StandaloneRetirementPlan,
) -> None:
    _require_target_semantically_unchanged(confirmed.target, refreshed.target)


def _require_target_semantically_unchanged(
    confirmed: ExactResourceRef, current: ExactResourceRef
) -> None:
    if _target_contract(current) != _target_contract(confirmed):
        raise PlanDriftError("standalone resource changed during current observation")


def _require_plan_target_identity_unchanged(
    before: ExactResourceRef, current: ExactResourceRef
) -> None:
    """Validate plan authority while allowing observation to add action data.

    A mandatory planning observation is expected to refresh startup policies
    (and any future plan-time allocations).  Those freshly observed values
    belong in the new plan.  Resource, native host identity, and controller
    authority must nevertheless remain the exact identity the caller was
    authorized to plan against.
    """

    if _plan_target_identity_contract(current) != _plan_target_identity_contract(
        before
    ):
        raise PlanDriftError("standalone resource changed during current observation")


def _target_contracts(targets: Any) -> tuple[Any, ...]:
    return tuple(
        sorted(
            (_target_contract(target) for target in targets),
            key=lambda item: (item[0], item[1]),
        )
    )


def _target_contract(target: ExactResourceRef) -> tuple[Any, ...]:
    """Immutable/actionable target identity, excluding observer generation churn."""

    return _target_identity_contract(target) + (
        tuple(
            sorted(
                (
                    allocation.kind.value,
                    allocation.allocation_id,
                    allocation.immutable_fingerprint,
                )
                for allocation in target.allocations
            )
        ),
    )


def _target_identity_contract(target: ExactResourceRef) -> tuple[Any, ...]:
    controller = _stable_controller_contract(target)
    return (
        target.kind.value,
        target.resource_id,
        target.immutable_fingerprint,
        target.control_binding_id,
        controller,
        tuple(
            sorted(
                (
                    policy.policy_id,
                    policy.kind.value,
                    policy.immutable_fingerprint,
                    policy.disabled_value,
                )
                for policy in target.policies
            )
        ),
        tuple(sorted(target.native_identity)),
    )


def _plan_target_identity_contract(target: ExactResourceRef) -> tuple[Any, ...]:
    controller = _stable_controller_contract(target)
    return (
        target.kind.value,
        target.resource_id,
        target.immutable_fingerprint,
        target.control_binding_id,
        controller,
        tuple(sorted(target.native_identity)),
    )


def _stable_controller_contract(target: ExactResourceRef) -> str:
    controller = target.control_contract_fingerprint
    if not controller:
        # Pre-contract plans fail closed on any generation change.  New plans
        # always carry the stable controller contract and can distinguish
        # harmless observation churn from a changed controller.
        controller = target.ownership_fingerprint
    return controller


def _control_binding_contract(
    store: AccountStore, targets: Any
) -> dict[str, tuple[Any, ...]]:
    result: dict[str, tuple[Any, ...]] = {}
    with store.read_transaction() as connection:
        for target in targets:
            row = connection.execute(
                """
                SELECT binding_id, repo_id, source_resource_id, resource_kind,
                       resource_id, source_id, capability, provenance,
                       authority_state, priority
                FROM control_bindings
                WHERE binding_id = ? AND resource_kind = ? AND resource_id = ?
                """,
                (
                    target.control_binding_id,
                    target.kind.value,
                    target.resource_id,
                ),
            ).fetchone()
            if row is None:
                raise PlanDriftError(
                    f"control binding {target.control_binding_id} disappeared"
                )
            result[target.control_binding_id] = tuple(row)
    return result


def _apply_result(
    payload: dict[str, Any],
    *,
    confirmed: RepositoryDecommissionPlan | StandaloneRetirementPlan,
    observation: Mapping[str, Any] | None,
) -> dict[str, Any]:
    payload["confirmed_plan"] = {
        "plan_id": confirmed.plan_id,
        "plan_fingerprint": confirmed.fingerprint,
    }
    payload["execution_plan"] = {
        "plan_id": str(payload.get("plan_id") or ""),
        "plan_fingerprint": str(payload.get("plan_fingerprint") or ""),
    }
    if observation is not None:
        payload["pre_apply_observation"] = dict(observation)
    return payload
