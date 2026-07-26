"""Exact worker deregistration prerequisite for archive and purge APPLY."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Optional

from .repository_lifecycle import RepositoryDecommissionPlan, ResourceKind
from .store import AccountStore
from .worker_control import WorkerController


WorkerRevoker = Callable[[str, str, str], Optional[Mapping[str, Any]]]


def unregister_workers_for_plan(
    store: AccountStore,
    *,
    plan: Any,
    actor: str,
    coordinator_script: Path,
    execution_uid: int,
    revoke: Optional[WorkerRevoker] = None,
) -> dict[str, Any]:
    """Revoke and unregister every exact worker named by one validated plan."""

    targets: list[tuple[str, Optional[str]]] = []
    if getattr(plan, "target_kind", None) == "server":
        targets.append((str(plan.target_id), getattr(plan, "repo_id", None)))
    elif getattr(plan, "target_kind", None) == "project":
        planned_repo_id = str(getattr(plan, "repo_id", None) or plan.target_id)
        if planned_repo_id != str(plan.target_id):
            raise RuntimeError(
                "validated project removal target changed repository before deregistration"
            )
        identity = getattr(plan, "snapshot", {}).get("identity", {})
        planned_generation = identity.get("generation")
        with store.read_transaction() as connection:
            repository = connection.execute(
                "SELECT generation FROM repositories WHERE repo_id = ?",
                (planned_repo_id,),
            ).fetchone()
            if (
                repository is None
                or type(planned_generation) is not int
                or int(repository["generation"]) != planned_generation
            ):
                raise RuntimeError(
                    "validated project generation changed before worker deregistration"
                )
            targets.extend(
                (str(row["server_definition_id"]), planned_repo_id)
                for row in connection.execute(
                    """
                    SELECT server_definition_id
                    FROM server_definitions
                    WHERE repo_id = ?
                    ORDER BY name, server_definition_id
                    """,
                    (planned_repo_id,),
                )
            )
    elif isinstance(plan, RepositoryDecommissionPlan):
        targets.extend(
            (target.resource_id, plan.repo_id)
            for target in plan.targets
            if target.kind is ResourceKind.SERVER
        )
    else:
        target = getattr(plan, "target", None)
        if target is not None and getattr(target, "kind", None) is ResourceKind.SERVER:
            targets.append((str(target.resource_id), getattr(plan, "repo_id", None)))

    prepared: list[dict[str, Any]] = []
    for worker_id, planned_repo_id in targets:
        with store.read_transaction() as connection:
            row = connection.execute(
                """
                SELECT definition.repo_id, definition.name, definition.role,
                       repository.canonical_root
                FROM server_definitions definition
                JOIN repositories repository USING(repo_id)
                WHERE definition.server_definition_id = ?
                """,
                (worker_id,),
            ).fetchone()
        if row is None:
            raise RuntimeError(
                "validated worker removal target disappeared before deregistration"
            )
        repo_id = str(row["repo_id"])
        if planned_repo_id is not None and repo_id != str(planned_repo_id):
            raise RuntimeError(
                "validated worker removal target changed repository before deregistration"
            )
        revocation = (
            None if revoke is None else revoke(worker_id, repo_id, actor)
        )
        if str(row["role"] or "").lower() != "worker":
            if revocation is not None:
                prepared.append(
                    {
                        "worker_id": worker_id,
                        "repo_id": repo_id,
                        "status": "not_a_native_worker",
                        "native_registration_removed": False,
                        "revocation": dict(revocation),
                    }
                )
            continue
        result = WorkerController(
            store,
            coordinator_script=coordinator_script,
            execution_uid=execution_uid,
        ).unregister(
            worker_id=worker_id,
            canonical_repository=str(row["canonical_root"]),
            name=str(row["name"]),
            actor=actor,
        )
        prepared.append(
            {
                "worker_id": worker_id,
                "repo_id": repo_id,
                "status": str(result.get("status") or "stopped"),
                "native_registration_removed": bool(
                    result.get("native_registration_removed")
                ),
                "revocation": None if revocation is None else dict(revocation),
            }
        )
    return {
        "status": "workers_unregistered",
        "workers": prepared,
    }


__all__ = ["WorkerRevoker", "unregister_workers_for_plan"]
