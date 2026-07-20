"""Archive catalogue and irreversible cleanup of exact coordinator resources.

The reversible archive fence remains owned by :mod:`repository_lifecycle`.
This module owns the deliberately narrower permanent-cleanup boundary:

* every target is a normalized opaque ID resolved by the service;
* planning and applying both perform live authorization and fresh observation;
* a UUID plan and SHA-256 fingerprint are durable before host mutation;
* apply requires the exact generated confirmation phrase;
* phase evidence and tombstones make replay and response loss inspectable;
* Docker removal is exact-ID only and never uses force, ``-v``, image, or
  volume deletion; and
* unsafe worktrees remain blocked instead of being force-removed.
"""

from __future__ import annotations

from dataclasses import dataclass
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
from typing import Any, Callable, Mapping, Sequence
import uuid

from .host_lifecycle import CoordinatorHostLifecycleAdapter
from .repository_lifecycle import (
    ExactResourceRef,
    LifecycleError,
    OwnershipError,
    PlanDriftError,
    ResourceKind,
    RunningState,
)
from .sqlite_lifecycle import SQLiteLifecyclePersistence
from .store import CoordinatorStore, canonical_json, fingerprint, utc_timestamp


TARGET_KINDS = frozenset({"project", "server", "container", "worktree"})
_FULL_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_GIT_OID = re.compile(r"^[0-9a-f]{40,64}$")
RETAINED_AUDIT = ("audit_history", "cleanup_tombstone", "operation_evidence")


class CleanupError(LifecycleError):
    """An expected permanent-cleanup refusal."""


class CleanupBlocked(CleanupError):
    """The exact target has one or more typed safety blockers."""

    def __init__(self, blockers: Sequence[Mapping[str, Any]]) -> None:
        self.blockers = tuple(dict(item) for item in blockers)
        super().__init__("cleanup is blocked: " + "; ".join(str(item["message"]) for item in blockers))


@dataclass(frozen=True)
class CleanupPlan:
    plan_id: str
    target_kind: str
    target_id: str
    repo_id: str | None
    action: str
    target_fingerprint: str
    plan_fingerprint: str
    confirmation_phrase: str
    actor: str
    reason: str
    created_at: str
    snapshot: Mapping[str, Any]

    @property
    def blockers(self) -> tuple[Mapping[str, Any], ...]:
        value = self.snapshot.get("blockers", [])
        return tuple(dict(item) for item in value if isinstance(item, Mapping))

    def to_dict(self) -> dict[str, Any]:
        target = dict(self.snapshot.get("target") or {})
        target.update(
            {
                "target_kind": self.target_kind,
                "target_id": self.target_id,
            }
        )
        return {
            "plan_id": self.plan_id,
            "plan_fingerprint": self.plan_fingerprint,
            "fingerprint": self.plan_fingerprint,
            "confirmation_phrase": self.confirmation_phrase,
            "action": self.action,
            "target": target,
            "effects": list(self.snapshot.get("effects") or []),
            "retained": list(self.snapshot.get("retained") or RETAINED_AUDIT),
            "deleted": list(self.snapshot.get("deleted") or []),
            "blockers": [dict(item) for item in self.blockers],
            "status": "blocked" if self.blockers else "planned",
        }


class DockerCleanupBackend:
    """Bounded exact-container inspection and removal."""

    def __init__(self, *, timeout: float = 15.0) -> None:
        self.timeout = float(timeout)
        # Archive listing and project/server/worktree cleanup must remain
        # usable on hosts that do not provide Docker.  Resolve the executable
        # only when an exact container operation actually crosses that host
        # boundary.
        self.executable: str | None = None

    def _executable(self) -> str:
        if self.executable is None:
            self.executable = _resolve_executable("docker")
        return self.executable

    def inspect(self, full_container_id: str) -> Mapping[str, Any] | None:
        _require_full_container_id(full_container_id)
        result = subprocess.run(
            [self._executable(), "inspect", "--type", "container", full_container_id],
            check=False,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            env=_sanitized_env(),
        )
        if result.returncode != 0:
            diagnostic = (result.stderr + "\n" + result.stdout).strip()
            if "No such object" in diagnostic or "No such container" in diagnostic:
                return None
            raise CleanupError("Docker inspect failed for the exact container identity")
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise CleanupError("Docker returned invalid inspect JSON") from error
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            raise CleanupError("Docker inspect did not return exactly one container")
        item = payload[0]
        observed_id = str(item.get("Id") or "").lower()
        if observed_id != full_container_id.lower():
            raise PlanDriftError("Docker resolved the target to another container identity")
        state = item.get("State") if isinstance(item.get("State"), dict) else {}
        config = item.get("Config") if isinstance(item.get("Config"), dict) else {}
        labels = config.get("Labels") if isinstance(config.get("Labels"), dict) else {}
        mounts = item.get("Mounts") if isinstance(item.get("Mounts"), list) else []
        return {
            "full_container_id": observed_id,
            "running": bool(state.get("Running")),
            "status": str(state.get("Status") or "unknown"),
            "mounts": [
                {
                    "type": str(mount.get("Type") or ""),
                    "name": str(mount.get("Name") or ""),
                    "source": str(mount.get("Source") or ""),
                    "destination": str(mount.get("Destination") or ""),
                    "rw": bool(mount.get("RW")),
                }
                for mount in mounts
                if isinstance(mount, dict)
            ],
            "labels": {str(key): str(value) for key, value in sorted(labels.items())},
        }

    def remove(self, full_container_id: str) -> Mapping[str, Any]:
        _require_full_container_id(full_container_id)
        result = subprocess.run(
            [self._executable(), "rm", full_container_id],
            check=False,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            env=_sanitized_env(),
        )
        if result.returncode != 0:
            diagnostic = (result.stderr + "\n" + result.stdout).strip()
            if "No such container" in diagnostic or "No such object" in diagnostic:
                return {"already_absent": True, "full_container_id": full_container_id}
            raise CleanupError("Docker refused exact stopped-container removal")
        if self.inspect(full_container_id) is not None:
            raise CleanupError("Docker reported removal but the exact container remains present")
        return {
            "already_absent": False,
            "full_container_id": full_container_id,
            "docker_argv_contract": ["docker", "rm", "<exact-full-container-id>"],
        }


class CleanupLifecycle:
    """Durable service layer for archive listing, restore, plan, and apply."""

    def __init__(
        self,
        store: CoordinatorStore,
        *,
        lifecycle_adapter: CoordinatorHostLifecycleAdapter | None = None,
        docker_backend: DockerCleanupBackend | None = None,
        authorize: Callable[[str, str, str, str], None] | None = None,
    ) -> None:
        self.store = store
        self.persistence = SQLiteLifecyclePersistence(store)
        self.lifecycle_adapter = lifecycle_adapter or CoordinatorHostLifecycleAdapter()
        self.docker_backend = docker_backend or DockerCleanupBackend()
        self._authorize = authorize or (lambda _cap, _kind, _target, _actor: None)

    def list_archives(self, *, actor: str) -> dict[str, Any]:
        self._authorize("archives.read", "project", "*", actor)
        with self.store.read_transaction() as connection:
            rows: list[dict[str, Any]] = []
            for row in connection.execute(
                """
                SELECT r.repo_id, r.display_name, r.canonical_root,
                       i.disabled_at, i.reason, i.actor
                FROM repositories r
                JOIN repository_installations i USING(repo_id)
                LEFT JOIN cleanup_tombstones t
                  ON t.target_kind = 'project' AND t.target_id = r.repo_id
                WHERE i.status = 'disabled' AND t.target_id IS NULL
                ORDER BY i.disabled_at DESC, lower(r.display_name), r.repo_id
                """
            ):
                blockers = self._project_static_blockers(connection, str(row["repo_id"]))
                rows.append(
                    {
                        "target_kind": "project",
                        "target_id": str(row["repo_id"]),
                        "project_id": str(row["repo_id"]),
                        "display_name": str(row["display_name"]),
                        "archived_at": row["disabled_at"],
                        "reason": row["reason"],
                        "actor": row["actor"],
                        "restorable": True,
                        "removable": not blockers,
                        "status": "archived",
                        "retained": ["repository_files", *RETAINED_AUDIT],
                        "effects": ["hidden_from_active_inventory", "startup_fenced"],
                        "blockers": blockers,
                    }
                )
                worktree_blockers = list(blockers)
                if connection.execute(
                    "SELECT 1 FROM cleanup_tombstones WHERE target_kind = 'project' AND target_id = ?",
                    (str(row["repo_id"]),),
                ).fetchone() is None:
                    worktree_blockers.append(
                        _blocker(
                            "project_catalog_retained",
                            "remove the archived project from the Coordinator catalog before removing its physical worktree",
                        )
                    )
                try:
                    _worktree_identity, host_blockers = _inspect_linked_worktree(
                        Path(str(row["canonical_root"]))
                    )
                    worktree_blockers.extend(host_blockers)
                except CleanupError as error:
                    worktree_blockers.append(
                        _blocker("not_removable_worktree", str(error))
                    )
                rows.append(
                    {
                        "target_kind": "worktree",
                        "target_id": str(row["repo_id"]),
                        "project_id": str(row["repo_id"]),
                        "project_display_name": str(row["display_name"]),
                        "display_name": f"{row['display_name']} worktree",
                        "archived_at": row["disabled_at"],
                        "reason": row["reason"],
                        "actor": row["actor"],
                        "restorable": False,
                        "removable": not worktree_blockers,
                        "status": "archived",
                        "retained": ["primary_repository", *RETAINED_AUDIT],
                        "effects": ["git_worktree_remove_without_force"],
                        "blockers": _deduplicate_blockers(worktree_blockers),
                    }
                )
            for row in connection.execute(
                """
                SELECT rr.resource_kind, rr.host_resource_id, rr.retired_at,
                       rr.reason, rr.actor, o.repo_id, rr.immutable_fingerprint,
                       COALESCE(sd.name, dr.current_name, rr.host_resource_id) AS display_name,
                       repositories.display_name AS project_display_name
                FROM resource_retirements rr
                LEFT JOIN operations o ON o.operation_id = rr.operation_id
                LEFT JOIN server_definitions sd
                  ON rr.resource_kind = 'server'
                 AND sd.server_definition_id = rr.host_resource_id
                LEFT JOIN docker_resources dr
                  ON rr.resource_kind = 'container'
                 AND dr.docker_resource_id = rr.host_resource_id
                LEFT JOIN cleanup_tombstones t
                  ON t.target_kind = rr.resource_kind
                 AND t.target_id = rr.host_resource_id
                LEFT JOIN repositories ON repositories.repo_id = o.repo_id
                WHERE rr.status = 'retired' AND t.target_id IS NULL
                ORDER BY rr.retired_at DESC, lower(display_name), rr.host_resource_id
                """
            ):
                kind = str(row["resource_kind"])
                if kind not in {"server", "container"}:
                    continue
                blockers = self._resource_static_blockers(
                    connection, kind, str(row["host_resource_id"])
                )
                repo_id = str(row["repo_id"]) if row["repo_id"] is not None else None
                item = {
                    "target_kind": kind,
                    "target_id": str(row["host_resource_id"]),
                    "display_name": str(row["display_name"]),
                    "archived_at": row["retired_at"],
                    "reason": row["reason"],
                    "actor": row["actor"],
                    "restorable": True,
                    "removable": not blockers,
                    "status": "archived",
                    "retained": list(RETAINED_AUDIT),
                    "effects": ["hidden_from_active_inventory", "start_fenced"],
                    "blockers": blockers,
                }
                if repo_id is not None:
                    item["project_id"] = repo_id
                    item["project_display_name"] = str(
                        row["project_display_name"] or repo_id
                    )
                    item["parent"] = {"target_kind": "project", "target_id": repo_id}
                rows.append(item)
            for row in connection.execute(
                """
                SELECT target_kind, target_id, repo_id, actor, reason,
                       evidence_json, removed_at
                FROM cleanup_tombstones
                ORDER BY removed_at DESC, target_kind, target_id
                """
            ):
                try:
                    evidence = json.loads(str(row["evidence_json"]))
                except json.JSONDecodeError:
                    evidence = {}
                plan_payload = evidence.get("plan") if isinstance(evidence, dict) else {}
                target_payload = (
                    plan_payload.get("target")
                    if isinstance(plan_payload, dict)
                    and isinstance(plan_payload.get("target"), dict)
                    else {}
                )
                kind = str(row["target_kind"])
                repo_id = str(row["repo_id"]) if row["repo_id"] is not None else None
                removed = {
                    "target_kind": kind,
                    "target_id": str(row["target_id"]),
                    "display_name": str(
                        target_payload.get("display_name")
                        or f"Removed {kind}"
                    ),
                    "archived_at": row["removed_at"],
                    "removed_at": row["removed_at"],
                    "reason": row["reason"],
                    "actor": row["actor"],
                    "restorable": False,
                    "removable": False,
                    "status": "removed",
                    "retained": list(RETAINED_AUDIT),
                    "effects": ["tombstone_retained"],
                    "blockers": [],
                }
                if repo_id is not None:
                    removed["project_id"] = repo_id
                    removed["project_display_name"] = str(
                        target_payload.get("project_display_name")
                        or target_payload.get("display_name")
                        or repo_id
                    )
                rows.append(removed)
                if kind == "project" and repo_id is not None:
                    snapshot_payload = (
                        evidence.get("snapshot")
                        if isinstance(evidence, dict)
                        and isinstance(evidence.get("snapshot"), dict)
                        else {}
                    )
                    identity_payload = (
                        snapshot_payload.get("identity")
                        if isinstance(snapshot_payload, dict)
                        and isinstance(snapshot_payload.get("identity"), dict)
                        else {}
                    )
                    root_text = str(identity_payload.get("canonical_root") or "")
                    worktree_tombstone = connection.execute(
                        """
                        SELECT 1 FROM cleanup_tombstones
                        WHERE target_kind = 'worktree' AND target_id = ?
                        """,
                        (repo_id,),
                    ).fetchone()
                    if root_text and worktree_tombstone is None:
                        retained_blockers = self._project_static_blockers(
                            connection, repo_id
                        )
                        try:
                            _identity, host_blockers = _inspect_linked_worktree(
                                Path(root_text)
                            )
                            retained_blockers.extend(host_blockers)
                        except CleanupError as error:
                            retained_blockers.append(
                                _blocker("not_removable_worktree", str(error))
                            )
                        rows.append(
                            {
                                "target_kind": "worktree",
                                "target_id": repo_id,
                                "project_id": repo_id,
                                "project_display_name": str(
                                    target_payload.get("display_name") or repo_id
                                ),
                                "display_name": f"{target_payload.get('display_name') or repo_id} worktree",
                                "archived_at": row["removed_at"],
                                "reason": row["reason"],
                                "actor": row["actor"],
                                "restorable": False,
                                "removable": not retained_blockers,
                                "status": "archived",
                                "retained": ["primary_repository", *RETAINED_AUDIT],
                                "effects": ["git_worktree_remove_without_force"],
                                "blockers": _deduplicate_blockers(retained_blockers),
                            }
                        )
            rows.sort(
                key=lambda item: (
                    str(item.get("archived_at") or ""),
                    str(item.get("display_name") or "").lower(),
                ),
                reverse=True,
            )
            return {"archives": rows}

    def plan(
        self,
        *,
        target_kind: str,
        target_id: str,
        actor: str,
        reason: str,
    ) -> CleanupPlan:
        target_kind = _canonical_target_kind(target_kind)
        _require_target(target_kind, target_id)
        self._authorize("cleanup.plan", target_kind, target_id, actor)
        snapshot = self._snapshot(target_kind, target_id)
        target_fingerprint = "sha256:" + fingerprint(snapshot["identity"])
        material = {
            "action": "forget" if target_kind == "project" else "purge",
            "target_kind": target_kind,
            "target_id": target_id,
            "repo_id": snapshot.get("repo_id"),
            "target_fingerprint": target_fingerprint,
            "snapshot": snapshot,
            "actor": actor,
            "reason": reason,
        }
        plan_fingerprint = "sha256:" + fingerprint(material)
        display_name = str((snapshot.get("target") or {}).get("display_name") or "")
        if not display_name:
            raise CleanupError("cleanup target has no human display name")
        confirmation_phrase = f"PURGE {target_kind.upper()} {display_name}"
        created_at = utc_timestamp()
        proposed = CleanupPlan(
            plan_id=str(uuid.uuid4()),
            target_kind=target_kind,
            target_id=target_id,
            repo_id=str(snapshot["repo_id"]) if snapshot.get("repo_id") else None,
            action="forget" if target_kind == "project" else "purge",
            target_fingerprint=target_fingerprint,
            plan_fingerprint=plan_fingerprint,
            confirmation_phrase=confirmation_phrase,
            actor=actor,
            reason=reason,
            created_at=created_at,
            snapshot=snapshot,
        )
        return self._save_plan(proposed)

    def apply(
        self,
        *,
        plan_id: str,
        plan_fingerprint: str,
        confirmation_phrase: str,
        actor: str,
    ) -> dict[str, Any]:
        _require_canonical_uuid(plan_id)
        _require_sha256(plan_fingerprint, "plan_fingerprint")
        plan = self.load_plan(plan_id)
        if not hmac.compare_digest(plan.plan_fingerprint, plan_fingerprint):
            raise PlanDriftError("cleanup plan fingerprint does not match durable plan")
        display_name = str((plan.snapshot.get("target") or {}).get("display_name") or "")
        expected_confirmation = f"PURGE {plan.target_kind.upper()} {display_name}"
        if (
            plan.action not in {"purge", "forget"}
            or not display_name
            or not hmac.compare_digest(plan.confirmation_phrase, expected_confirmation)
        ):
            raise CleanupError("durable cleanup confirmation is not target-bound")
        if not hmac.compare_digest(str(confirmation_phrase), expected_confirmation):
            raise CleanupError("exact cleanup confirmation phrase is required")
        # Authorization is deliberately rechecked at apply.  A grant revoked
        # after planning therefore fails before host or catalogue mutation.
        self._authorize("cleanup.apply", plan.target_kind, plan.target_id, actor)
        status = self._plan_status(plan.plan_id)
        if status == "succeeded":
            return self._apply_result(plan, partial=False, needs_attention=False)
        current = self._snapshot(plan.target_kind, plan.target_id, allow_absent=True)
        if current.get("absent"):
            host_phase = self._phase_status(plan.plan_id, "host_remove")
            if plan.target_kind not in {"container", "worktree"} or host_phase not in {
                "running",
                "succeeded",
            }:
                raise PlanDriftError("cleanup target disappeared without durable host-effect evidence")
            recovery_evidence: Mapping[str, Any] = {"target_absent": True}
            if plan.target_kind == "worktree":
                recovery_evidence = self._verify_worktree_absent(plan)
            if host_phase == "running":
                self._finish_phase(
                    plan.plan_id,
                    "host_remove",
                    {
                        "recovered_after_interruption": True,
                        "reconciled_absent": True,
                        "target_absent": True,
                        **dict(recovery_evidence),
                    },
                )
        else:
            current_fingerprint = "sha256:" + fingerprint(current["identity"])
            if current_fingerprint != plan.target_fingerprint:
                raise PlanDriftError("cleanup target identity changed after planning")
            blockers = list(current.get("blockers") or [])
            if blockers:
                self._mark_needs_attention(plan, blockers)
                raise CleanupBlocked(blockers)
        self._mark_running(plan, actor)
        try:
            if plan.target_kind == "container":
                if not self._phase_succeeded(plan.plan_id, "host_remove"):
                    full_id = str(plan.snapshot["identity"]["full_container_id"])
                    self._begin_phase(
                        plan.plan_id,
                        "host_remove",
                        {"target_kind": "container", "full_container_id": full_id},
                    )
                    evidence = self.docker_backend.remove(full_id)
                    self._finish_phase(plan.plan_id, "host_remove", evidence)
                self._finalize_container(plan, actor)
            elif plan.target_kind == "worktree":
                if not self._phase_succeeded(plan.plan_id, "host_remove"):
                    self._begin_phase(
                        plan.plan_id,
                        "host_remove",
                        {
                            "target_kind": "worktree",
                            "canonical_root": plan.snapshot["identity"]["canonical_root"],
                        },
                    )
                    evidence = self._remove_worktree(plan)
                    self._finish_phase(plan.plan_id, "host_remove", evidence)
                self._finalize_worktree(plan, actor)
            elif plan.target_kind == "server":
                self._finalize_server(plan, actor)
            else:
                self._finalize_project(plan, actor)
        except Exception as error:
            self._record_failure(plan, error)
            raise
        return self._apply_result(plan, partial=False, needs_attention=False)

    def load_plan(self, plan_id: str) -> CleanupPlan:
        _require_canonical_uuid(plan_id)
        with self.store.read_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM cleanup_plans WHERE plan_id = ?", (plan_id,)
            ).fetchone()
            if row is None:
                raise CleanupError("cleanup plan does not exist")
            snapshot = json.loads(str(row["snapshot_json"]))
            if not isinstance(snapshot, dict):
                raise CleanupError("cleanup plan snapshot is invalid")
            return CleanupPlan(
                plan_id=str(row["plan_id"]),
                target_kind=str(row["target_kind"]),
                target_id=str(row["target_id"]),
                repo_id=str(row["repo_id"]) if row["repo_id"] is not None else None,
                action=str(row["action"]),
                target_fingerprint=str(row["target_fingerprint"]),
                plan_fingerprint=str(row["plan_fingerprint"]),
                confirmation_phrase=str(row["confirmation_phrase"]),
                actor=str(row["actor"]),
                reason=str(row["reason"]),
                created_at=str(row["created_at"]),
                snapshot=snapshot,
            )

    def _snapshot(
        self, target_kind: str, target_id: str, *, allow_absent: bool = False
    ) -> dict[str, Any]:
        if target_kind == "project":
            return self._project_snapshot(target_id)
        if target_kind == "worktree":
            return self._worktree_snapshot(target_id, allow_absent=allow_absent)
        return self._resource_snapshot(target_kind, target_id, allow_absent=allow_absent)

    def _project_snapshot(self, repo_id: str) -> dict[str, Any]:
        with self.store.read_transaction() as connection:
            row = connection.execute(
                """
                SELECT r.repo_id, r.canonical_root, r.display_name, r.state,
                       r.generation, i.status, i.startup_fenced,
                       i.generation AS installation_generation
                FROM repositories r JOIN repository_installations i USING(repo_id)
                WHERE r.repo_id = ?
                """,
                (repo_id,),
            ).fetchone()
            if row is None:
                raise CleanupError("project target does not exist")
            if connection.execute(
                "SELECT 1 FROM cleanup_tombstones WHERE target_kind = 'project' AND target_id = ?",
                (repo_id,),
            ).fetchone() is not None:
                raise CleanupError("project is already removed")
            blockers = self._project_static_blockers(connection, repo_id)
            identity = {
                "repo_id": repo_id,
                "canonical_root": str(row["canonical_root"]),
                "state": str(row["state"]),
                "generation": int(row["generation"]),
                "installation_status": str(row["status"]),
                "startup_fenced": bool(row["startup_fenced"]),
                "installation_generation": int(row["installation_generation"]),
            }
            return {
                "identity": identity,
                "repo_id": repo_id,
                "target": {
                    "display_name": str(row["display_name"]),
                    "project_id": repo_id,
                },
                "effects": ["remove_from_project_catalog"],
                "retained": ["repository_files", *RETAINED_AUDIT],
                "deleted": ["active_project_catalog_entry"],
                "blockers": blockers,
            }

    def _resource_snapshot(
        self, target_kind: str, target_id: str, *, allow_absent: bool
    ) -> dict[str, Any]:
        kind = ResourceKind(target_kind)
        with self.store.read_transaction() as connection:
            retirement = connection.execute(
                """
                SELECT rr.*, o.repo_id FROM resource_retirements rr
                LEFT JOIN operations o ON o.operation_id = rr.operation_id
                WHERE rr.resource_kind = ? AND rr.host_resource_id = ?
                """,
                (target_kind, target_id),
            ).fetchone()
            if retirement is None:
                if allow_absent and connection.execute(
                    "SELECT 1 FROM cleanup_tombstones WHERE target_kind = ? AND target_id = ?",
                    (target_kind, target_id),
                ).fetchone() is not None:
                    return {"absent": True}
                raise CleanupError("resource must be archived before permanent removal")
            if str(retirement["status"]) != "retired":
                raise CleanupError("resource archive must complete before permanent removal")
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
                raise OwnershipError("archived resource has no authoritative exact controller")
            control_binding_id = str(binding["binding_id"])
        exact, repo_id = self.persistence.resolve_resource(
            kind, target_id, control_binding_id, include_archived=True
        )
        observation = self.lifecycle_adapter.observe_exact(exact)
        if not observation.identity_observable or not observation.ownership_observable:
            raise OwnershipError("current exact resource ownership is unobservable")
        if observation.immutable_fingerprint != exact.immutable_fingerprint:
            raise PlanDriftError("archived resource immutable identity changed")
        blockers: list[dict[str, Any]] = []
        if observation.running_state not in {RunningState.STOPPED, RunningState.ZOMBIE}:
            blockers.append(_blocker("resource_running", "resource is not proved stopped"))
        if target_kind == "server" and observation.listener_active is not False:
            blockers.append(
                _blocker(
                    "listener_not_absent",
                    "server listener is active or cannot be proved absent",
                )
            )
        identity: dict[str, Any] = {
            "resource_kind": target_kind,
            "resource_id": target_id,
            "immutable_fingerprint": exact.immutable_fingerprint,
            "control_binding_id": exact.control_binding_id,
            "ownership_fingerprint": exact.ownership_fingerprint,
            "native_identity": dict(exact.native_identity),
            "running_state": observation.running_state.value,
            "listener_active": observation.listener_active,
        }
        display_name = target_id
        if target_kind == "container":
            with self.store.read_transaction() as connection:
                row = connection.execute(
                    """
                    SELECT current_name, full_container_id FROM docker_resources
                    WHERE docker_resource_id = ?
                    """,
                    (target_id,),
                ).fetchone()
                if row is None:
                    if allow_absent:
                        return {"absent": True}
                    raise CleanupError("normalized Docker resource disappeared")
                display_name = str(row["current_name"])
                full_id = str(row["full_container_id"]).lower()
                _require_full_container_id(full_id)
                docker = self.docker_backend.inspect(full_id)
                if docker is None:
                    if allow_absent:
                        return {"absent": True}
                    raise CleanupError("exact Docker container is already absent")
                identity["full_container_id"] = full_id
                identity["docker"] = docker
                blockers.extend(self._resource_static_blockers(connection, target_kind, target_id))
                if docker["mounts"]:
                    blockers.append(
                        _blocker(
                            "mounted_container",
                            "containers with bind, volume, or other mounts are not removable",
                        )
                    )
                if bool(docker["running"]) or str(docker["status"]) not in {
                    "created",
                    "exited",
                    "dead",
                }:
                    blockers.append(
                        _blocker(
                            "container_not_stopped",
                            "live Docker inspect does not prove a removable stopped container",
                            status=str(docker["status"]),
                        )
                    )
                if any(
                    key.startswith("com.docker.compose.")
                    for key in dict(docker["labels"])
                ):
                    blockers.append(
                        _blocker(
                            "compose_owned",
                            "Compose-labelled containers require project-level Compose cleanup",
                        )
                    )
        else:
            with self.store.read_transaction() as connection:
                row = connection.execute(
                    "SELECT name FROM server_definitions WHERE server_definition_id = ?",
                    (target_id,),
                ).fetchone()
                if row is None:
                    if allow_absent:
                        return {"absent": True}
                    raise CleanupError("managed server definition disappeared")
                display_name = str(row["name"])
                blockers.extend(self._resource_static_blockers(connection, target_kind, target_id))
        project_display_name = None
        if repo_id is not None:
            with self.store.read_transaction() as connection:
                project_row = connection.execute(
                    "SELECT display_name FROM repositories WHERE repo_id = ?",
                    (repo_id,),
                ).fetchone()
                project_display_name = (
                    str(project_row["display_name"]) if project_row is not None else None
                )
        return {
            "identity": identity,
            "repo_id": repo_id,
            "target": {
                "display_name": display_name,
                "project_id": repo_id,
                "project_display_name": project_display_name,
                "target_kind": target_kind,
            },
            "effects": (
                ["docker_rm_exact_stopped_container", "remove_normalized_container_record"]
                if target_kind == "container"
                else ["retire_managed_server_from_active_projection", "deactivate_assignment"]
            ),
            "retained": list(RETAINED_AUDIT) + (["log_file"] if target_kind == "server" else []),
            "deleted": (
                ["container_object", "container_observation", "container_metadata"]
                if target_kind == "container"
                else ["server_command", "server_environment", "active_server_projection"]
            ),
            "blockers": _deduplicate_blockers(blockers),
        }

    def _worktree_snapshot(self, repo_id: str, *, allow_absent: bool) -> dict[str, Any]:
        with self.store.read_transaction() as connection:
            row = connection.execute(
                """
                SELECT r.repo_id, r.canonical_root, r.display_name, r.state,
                       i.status, i.startup_fenced
                FROM repositories r JOIN repository_installations i USING(repo_id)
                WHERE r.repo_id = ?
                """,
                (repo_id,),
            ).fetchone()
            if row is None:
                if allow_absent:
                    return {"absent": True}
                raise CleanupError("worktree project does not exist")
            blockers = self._project_static_blockers(connection, repo_id)
            project_catalog_removed = connection.execute(
                "SELECT 1 FROM cleanup_tombstones WHERE target_kind = 'project' AND target_id = ?",
                (repo_id,),
            ).fetchone() is not None
        root = Path(str(row["canonical_root"]))
        if not root.exists():
            if allow_absent:
                return {"absent": True}
            raise CleanupError("worktree path is already absent")
        identity, host_blockers = _inspect_linked_worktree(root)
        blockers.extend(host_blockers)
        if not project_catalog_removed:
            blockers.append(
                _blocker(
                    "project_catalog_retained",
                    "remove the archived project from the Coordinator catalog before removing its physical worktree",
                )
            )
        if str(row["status"]) != "disabled" or not bool(row["startup_fenced"]):
            blockers.append(_blocker("project_not_archived", "project must be archived first"))
        return {
            "identity": identity,
            "repo_id": repo_id,
            "target": {"display_name": str(row["display_name"]), "project_id": repo_id},
            "effects": ["git_worktree_remove_without_force"],
            "retained": ["primary_repository", *RETAINED_AUDIT],
            "deleted": ["secondary_worktree_files", "linked_worktree_admin_entry"],
            "blockers": _deduplicate_blockers(blockers),
        }

    def _save_plan(self, plan: CleanupPlan) -> CleanupPlan:
        with self.store.immediate_transaction() as connection:
            existing = connection.execute(
                """
                SELECT plan_id FROM cleanup_plans
                WHERE target_kind = ? AND target_id = ? AND plan_fingerprint = ?
                """,
                (plan.target_kind, plan.target_id, plan.plan_fingerprint),
            ).fetchone()
            if existing is not None:
                existing_id = str(existing["plan_id"])
            else:
                connection.execute(
                    """
                    INSERT INTO operations(
                        operation_id, repo_id, kind, status, phase, generation,
                        request_fingerprint, owner_uid, actor, created_at, updated_at
                    ) VALUES (?, ?, ?, 'planned', 'planned', 0, ?, ?, ?, ?, ?)
                    """,
                    (
                        plan.plan_id,
                        plan.repo_id,
                        f"cleanup:{plan.action}",
                        plan.plan_fingerprint,
                        os.geteuid(),
                        plan.actor,
                        plan.created_at,
                        plan.created_at,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO cleanup_plans(
                        plan_id, repo_id, target_kind, target_id, action,
                        target_fingerprint, plan_fingerprint, confirmation_phrase,
                        snapshot_json, status, phase, actor, reason,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'planned', 'planned', ?, ?, ?, ?)
                    """,
                    (
                        plan.plan_id,
                        plan.repo_id,
                        plan.target_kind,
                        plan.target_id,
                        plan.action,
                        plan.target_fingerprint,
                        plan.plan_fingerprint,
                        plan.confirmation_phrase,
                        canonical_json(dict(plan.snapshot)),
                        plan.actor,
                        plan.reason,
                        plan.created_at,
                        plan.created_at,
                    ),
                )
                existing_id = plan.plan_id
        return self.load_plan(existing_id)

    def _mark_running(self, plan: CleanupPlan, actor: str) -> None:
        timestamp = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            row = connection.execute(
                "SELECT status FROM cleanup_plans WHERE plan_id = ?", (plan.plan_id,)
            ).fetchone()
            if row is None:
                raise CleanupError("cleanup plan disappeared")
            if str(row["status"]) == "succeeded":
                return
            connection.execute(
                """
                UPDATE cleanup_plans SET status = 'running', phase = 'applying',
                    updated_at = ? WHERE plan_id = ?
                """,
                (timestamp, plan.plan_id),
            )
            connection.execute(
                """
                UPDATE operations SET status = 'running', phase = 'applying',
                    updated_at = ? WHERE operation_id = ?
                """,
                (timestamp, plan.plan_id),
            )
            connection.execute(
                """
                INSERT INTO cleanup_phase_evidence(
                    plan_id, phase, status, evidence_json, started_at
                ) VALUES (?, 'apply_authorized', 'succeeded', ?, ?)
                ON CONFLICT(plan_id, phase) DO UPDATE SET
                    status = 'succeeded', evidence_json = excluded.evidence_json
                """,
                (
                    plan.plan_id,
                    canonical_json({"applier": actor, "authorized_at": timestamp}),
                    timestamp,
                ),
            )

    def _begin_phase(
        self, plan_id: str, phase: str, evidence: Mapping[str, Any]
    ) -> None:
        timestamp = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            current = connection.execute(
                "SELECT status FROM cleanup_phase_evidence WHERE plan_id = ? AND phase = ?",
                (plan_id, phase),
            ).fetchone()
            if current is not None and str(current["status"]) == "succeeded":
                return
            connection.execute(
                """
                INSERT INTO cleanup_phase_evidence(
                    plan_id, phase, status, evidence_json, started_at
                ) VALUES (?, ?, 'running', ?, ?)
                ON CONFLICT(plan_id, phase) DO UPDATE SET
                    status = 'running', evidence_json = excluded.evidence_json,
                    error_json = NULL, finished_at = NULL
                """,
                (plan_id, phase, canonical_json(dict(evidence)), timestamp),
            )
            connection.execute(
                "UPDATE cleanup_plans SET phase = ?, updated_at = ? WHERE plan_id = ?",
                (phase, timestamp, plan_id),
            )
            connection.execute(
                "UPDATE operations SET phase = ?, updated_at = ? WHERE operation_id = ?",
                (phase, timestamp, plan_id),
            )

    def _finish_phase(self, plan_id: str, phase: str, evidence: Mapping[str, Any]) -> None:
        timestamp = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO cleanup_phase_evidence(
                    plan_id, phase, status, evidence_json, started_at, finished_at
                ) VALUES (?, ?, 'succeeded', ?, ?, ?)
                ON CONFLICT(plan_id, phase) DO UPDATE SET
                    status = 'succeeded', evidence_json = excluded.evidence_json,
                    error_json = NULL, finished_at = excluded.finished_at
                """,
                (plan_id, phase, canonical_json(dict(evidence)), timestamp, timestamp),
            )
            connection.execute(
                "UPDATE cleanup_plans SET phase = ?, updated_at = ? WHERE plan_id = ?",
                (phase, timestamp, plan_id),
            )
            connection.execute(
                "UPDATE operations SET phase = ?, updated_at = ? WHERE operation_id = ?",
                (phase, timestamp, plan_id),
            )

    def _phase_succeeded(self, plan_id: str, phase: str) -> bool:
        return self._phase_status(plan_id, phase) == "succeeded"

    def _phase_status(self, plan_id: str, phase: str) -> str | None:
        with self.store.read_transaction() as connection:
            row = connection.execute(
                "SELECT status FROM cleanup_phase_evidence WHERE plan_id = ? AND phase = ?",
                (plan_id, phase),
            ).fetchone()
            return str(row["status"]) if row is not None else None

    def _finalize_container(self, plan: CleanupPlan, actor: str) -> None:
        timestamp = utc_timestamp()
        full_id = str(plan.snapshot["identity"]["full_container_id"])
        with self.store.immediate_transaction() as connection:
            if self._tombstone_exists(connection, plan):
                self._complete_in_transaction(connection, plan, timestamp)
                return
            row = connection.execute(
                "SELECT full_container_id FROM docker_resources WHERE docker_resource_id = ?",
                (plan.target_id,),
            ).fetchone()
            if row is not None and str(row["full_container_id"]).lower() != full_id:
                raise PlanDriftError("normalized Docker identity changed before finalization")
            if connection.execute(
                "SELECT 1 FROM database_bindings WHERE docker_resource_id = ?",
                (plan.target_id,),
            ).fetchone() is not None:
                raise CleanupBlocked([_blocker("database_container", "database-bound containers cannot be removed")])
            connection.execute(
                "DELETE FROM repository_memberships WHERE resource_kind = 'container' AND host_resource_id = ?",
                (plan.target_id,),
            )
            connection.execute(
                "DELETE FROM unassigned_resources WHERE resource_kind = 'container' AND resource_id = ?",
                (plan.target_id,),
            )
            connection.execute(
                "DELETE FROM startup_policies WHERE resource_kind = 'container' AND resource_id = ?",
                (plan.target_id,),
            )
            connection.execute(
                "DELETE FROM docker_ownership_claims WHERE docker_resource_id = ?",
                (plan.target_id,),
            )
            connection.execute(
                "UPDATE control_bindings SET authority_state = 'retired', generation = generation + 1, updated_at = ? WHERE resource_kind = 'container' AND resource_id = ?",
                (timestamp, plan.target_id),
            )
            connection.execute(
                "DELETE FROM resource_retirements WHERE resource_kind = 'container' AND host_resource_id = ?",
                (plan.target_id,),
            )
            connection.execute(
                "DELETE FROM docker_resources WHERE docker_resource_id = ?",
                (plan.target_id,),
            )
            self._insert_tombstone(connection, plan, actor, timestamp)
            self._complete_in_transaction(connection, plan, timestamp)

    def _finalize_server(self, plan: CleanupPlan, actor: str) -> None:
        timestamp = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            if self._tombstone_exists(connection, plan):
                self._complete_in_transaction(connection, plan, timestamp)
                return
            definition = connection.execute(
                "SELECT log_path FROM server_definitions WHERE server_definition_id = ?",
                (plan.target_id,),
            ).fetchone()
            if definition is None:
                raise PlanDriftError("managed server definition disappeared before finalization")
            observation = connection.execute(
                "SELECT lifecycle, listener_observable FROM server_observations WHERE server_definition_id = ?",
                (plan.target_id,),
            ).fetchone()
            if observation is not None and str(observation["lifecycle"]) not in {"stopped", "unknown", "unobserved"}:
                raise CleanupBlocked([_blocker("resource_running", "server is not durably stopped")])
            connection.execute(
                "UPDATE port_assignments SET status = 'inactive', deactivated_at = COALESCE(deactivated_at, ?), updated_at = ? WHERE repo_id = ? AND server_name = (SELECT name FROM server_definitions WHERE server_definition_id = ?) AND status = 'active'",
                (timestamp, timestamp, plan.repo_id, plan.target_id),
            )
            connection.execute(
                "UPDATE leases SET status = 'released', deactivated_at = COALESCE(deactivated_at, ?), updated_at = ? WHERE server_definition_id = ? AND status = 'active'",
                (timestamp, timestamp, plan.target_id),
            )
            connection.execute(
                "DELETE FROM server_command_arguments WHERE server_definition_id = ?",
                (plan.target_id,),
            )
            connection.execute(
                "DELETE FROM server_environment WHERE server_definition_id = ?",
                (plan.target_id,),
            )
            connection.execute(
                "DELETE FROM repository_memberships WHERE resource_kind = 'server' AND host_resource_id = ?",
                (plan.target_id,),
            )
            connection.execute(
                "DELETE FROM unassigned_resources WHERE resource_kind = 'server' AND resource_id = ?",
                (plan.target_id,),
            )
            connection.execute(
                "DELETE FROM startup_policies WHERE resource_kind = 'server' AND resource_id = ?",
                (plan.target_id,),
            )
            connection.execute(
                "UPDATE control_bindings SET authority_state = 'retired', generation = generation + 1, updated_at = ? WHERE resource_kind = 'server' AND resource_id = ?",
                (timestamp, plan.target_id),
            )
            connection.execute(
                "DELETE FROM resource_retirements WHERE resource_kind = 'server' AND host_resource_id = ?",
                (plan.target_id,),
            )
            self._insert_tombstone(
                connection,
                plan,
                actor,
                timestamp,
                extra={"retained_log_path": definition["log_path"]},
            )
            self._complete_in_transaction(connection, plan, timestamp)

    def _finalize_project(self, plan: CleanupPlan, actor: str) -> None:
        timestamp = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            if self._tombstone_exists(connection, plan):
                self._complete_in_transaction(connection, plan, timestamp)
                return
            blockers = self._project_static_blockers(connection, plan.target_id)
            if blockers:
                raise CleanupBlocked(blockers)
            changed = connection.execute(
                "UPDATE repositories SET state = 'missing', generation = generation + 1, updated_at = ? WHERE repo_id = ? AND state = 'active'",
                (timestamp, plan.target_id),
            ).rowcount
            if changed != 1:
                raise PlanDriftError("project catalog identity changed before removal")
            self._insert_tombstone(connection, plan, actor, timestamp)
            self._complete_in_transaction(connection, plan, timestamp)

    def _remove_worktree(self, plan: CleanupPlan) -> Mapping[str, Any]:
        identity = plan.snapshot["identity"]
        root = Path(str(identity["canonical_root"]))
        common_dir = Path(str(identity["common_dir"]))
        primary_root = Path(str(identity["primary_root"]))
        current, blockers = _inspect_linked_worktree(root)
        if blockers:
            raise CleanupBlocked(blockers)
        if "sha256:" + fingerprint(current) != plan.target_fingerprint:
            raise PlanDriftError("linked worktree identity changed before removal")
        if Path(str(current["common_dir"])) != common_dir or Path(str(current["primary_root"])) != primary_root:
            raise PlanDriftError("linked worktree administrative identity changed")
        owner_uid = int(identity["owner_uid"])
        owner_gid = int(identity["owner_gid"])
        result = subprocess.run(
            [
                _resolve_executable("git"),
                "-C",
                str(primary_root),
                "worktree",
                "remove",
                "--",
                str(root),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30.0,
            env=_sanitized_env(),
            preexec_fn=_owner_preexec(owner_uid, owner_gid),
        )
        if result.returncode != 0:
            raise CleanupError("git worktree remove refused the exact clean secondary worktree")
        if root.exists() or root.is_symlink():
            raise CleanupError("git reported worktree removal but the path remains")
        verified = self._verify_worktree_absent(plan)
        return {
            "canonical_root": str(root),
            "common_dir": str(common_dir),
            "git_argv_contract": ["git", "worktree", "remove", "--", "<exact-secondary-root>"],
            **dict(verified),
        }

    def _verify_worktree_absent(self, plan: CleanupPlan) -> Mapping[str, Any]:
        identity = plan.snapshot["identity"]
        root = Path(str(identity["canonical_root"]))
        git_dir = Path(str(identity["git_dir"]))
        common_dir = Path(str(identity["common_dir"]))
        primary_root = Path(str(identity["primary_root"]))
        owner_uid = int(identity["owner_uid"])
        owner_gid = int(identity["owner_gid"])
        if root.exists() or root.is_symlink():
            raise CleanupError("removed worktree root is still present")
        if git_dir.exists() or git_dir.is_symlink():
            raise CleanupError(
                "worktree directory is absent but its exact Git administrative entry remains"
            )
        if not common_dir.is_dir() or not primary_root.is_dir():
            raise CleanupError("primary Git administrative boundary is no longer observable")
        primary_stat = primary_root.stat()
        if int(primary_stat.st_uid) != owner_uid or int(primary_stat.st_gid) != owner_gid:
            raise PlanDriftError("primary worktree owner changed during removal")
        result = subprocess.run(
            [
                _resolve_executable("git"),
                "-C",
                str(primary_root),
                "worktree",
                "list",
                "--porcelain",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15.0,
            env=_sanitized_env(),
            preexec_fn=_owner_preexec(owner_uid, owner_gid),
        )
        if result.returncode != 0:
            raise CleanupError("Git could not verify worktree administration after removal")
        if _worktree_list_entry(result.stdout, root) is not None:
            raise CleanupError("removed worktree remains registered in git worktree list")
        return {
            "target_absent": True,
            "admin_entry_absent": True,
            "worktree_list_entry_absent": True,
        }

    def _finalize_worktree(self, plan: CleanupPlan, actor: str) -> None:
        timestamp = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            if self._tombstone_exists(connection, plan):
                self._complete_in_transaction(connection, plan, timestamp)
                return
            connection.execute(
                "UPDATE repositories SET state = 'missing', generation = generation + 1, updated_at = ? WHERE repo_id = ?",
                (timestamp, plan.target_id),
            )
            self._insert_tombstone(connection, plan, actor, timestamp)
            self._complete_in_transaction(connection, plan, timestamp)

    def _insert_tombstone(
        self,
        connection: Any,
        plan: CleanupPlan,
        actor: str,
        timestamp: str,
        *,
        extra: Mapping[str, Any] | None = None,
    ) -> None:
        evidence = {"plan": plan.to_dict(), "snapshot": dict(plan.snapshot)}
        evidence["applied_by"] = actor
        if extra:
            evidence.update(dict(extra))
        connection.execute(
            """
            INSERT INTO cleanup_tombstones(
                target_kind, target_id, repo_id, immutable_fingerprint,
                operation_id, actor, reason, evidence_json, removed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(target_kind, target_id) DO NOTHING
            """,
            (
                plan.target_kind,
                plan.target_id,
                plan.repo_id,
                plan.target_fingerprint,
                plan.plan_id,
                plan.actor,
                plan.reason,
                canonical_json(evidence),
                timestamp,
            ),
        )
        if plan.target_kind in {"server", "container"}:
            connection.execute(
                """
                INSERT INTO resource_lifecycle_history(
                    history_id, repo_id, resource_kind, resource_id,
                    immutable_fingerprint, action, operation_id, actor,
                    reason, evidence_json, occurred_at
                ) VALUES (?, ?, ?, ?, ?, 'purged', ?, ?, ?, ?, ?)
                ON CONFLICT(history_id) DO NOTHING
                """,
                (
                    str(uuid.uuid5(uuid.NAMESPACE_URL, f"cleanup:{plan.plan_id}:purged")),
                    plan.repo_id,
                    plan.target_kind,
                    plan.target_id,
                    plan.target_fingerprint,
                    plan.plan_id,
                    plan.actor,
                    plan.reason,
                    canonical_json({"tombstone": True}),
                    timestamp,
                ),
            )

    @staticmethod
    def _tombstone_exists(connection: Any, plan: CleanupPlan) -> bool:
        return connection.execute(
            "SELECT 1 FROM cleanup_tombstones WHERE target_kind = ? AND target_id = ?",
            (plan.target_kind, plan.target_id),
        ).fetchone() is not None

    @staticmethod
    def _complete_in_transaction(connection: Any, plan: CleanupPlan, timestamp: str) -> None:
        result = {
            "status": "succeeded",
            "partial": False,
            "needs_attention": False,
            "ok": True,
            "errors": [],
            "target_kind": plan.target_kind,
            "target_id": plan.target_id,
        }
        connection.execute(
            "UPDATE cleanup_plans SET status = 'succeeded', phase = 'complete', updated_at = ? WHERE plan_id = ?",
            (timestamp, plan.plan_id),
        )
        connection.execute(
            "UPDATE operations SET status = 'succeeded', phase = 'complete', result_json = ?, error_code = NULL, error_message = NULL, updated_at = ? WHERE operation_id = ?",
            (canonical_json(result), timestamp, plan.plan_id),
        )
        connection.execute(
            """
            INSERT INTO cleanup_phase_evidence(
                plan_id, phase, status, evidence_json, started_at, finished_at
            ) VALUES (?, 'finalize', 'succeeded', ?, ?, ?)
            ON CONFLICT(plan_id, phase) DO UPDATE SET
                status = 'succeeded', evidence_json = excluded.evidence_json,
                error_json = NULL, finished_at = excluded.finished_at
            """,
            (plan.plan_id, canonical_json(result), timestamp, timestamp),
        )

    def _record_failure(self, plan: CleanupPlan, error: Exception) -> None:
        timestamp = utc_timestamp()
        code = "cleanup_blocked" if isinstance(error, CleanupBlocked) else "cleanup_failed"
        detail = {
            "code": code,
            "message": str(error),
            "blockers": list(error.blockers) if isinstance(error, CleanupBlocked) else [],
        }
        with self.store.immediate_transaction() as connection:
            connection.execute(
                "UPDATE cleanup_plans SET status = 'needs_attention', phase = 'failed', updated_at = ? WHERE plan_id = ? AND status != 'succeeded'",
                (timestamp, plan.plan_id),
            )
            connection.execute(
                "UPDATE operations SET status = 'needs_attention', phase = 'failed', error_code = ?, error_message = ?, result_json = ?, updated_at = ? WHERE operation_id = ? AND status != 'succeeded'",
                (code, str(error), canonical_json(detail), timestamp, plan.plan_id),
            )
            connection.execute(
                """
                INSERT INTO cleanup_phase_evidence(
                    plan_id, phase, status, error_json, started_at, finished_at
                ) VALUES (?, 'failure', 'failed', ?, ?, ?)
                ON CONFLICT(plan_id, phase) DO UPDATE SET
                    status = 'failed', error_json = excluded.error_json,
                    finished_at = excluded.finished_at
                """,
                (plan.plan_id, canonical_json(detail), timestamp, timestamp),
            )

    def _mark_needs_attention(
        self, plan: CleanupPlan, blockers: Sequence[Mapping[str, Any]]
    ) -> None:
        self._record_failure(plan, CleanupBlocked(blockers))

    def _plan_status(self, plan_id: str) -> str:
        with self.store.read_transaction() as connection:
            row = connection.execute(
                "SELECT status FROM cleanup_plans WHERE plan_id = ?", (plan_id,)
            ).fetchone()
            if row is None:
                raise CleanupError("cleanup plan disappeared")
            return str(row["status"])

    @staticmethod
    def _apply_result(
        plan: CleanupPlan, *, partial: bool, needs_attention: bool
    ) -> dict[str, Any]:
        return {
            "status": "needs_attention" if needs_attention else "succeeded",
            "partial": bool(partial),
            "needs_attention": bool(needs_attention),
            "ok": not partial and not needs_attention,
            "errors": [],
            "plan_id": plan.plan_id,
            "plan_fingerprint": plan.plan_fingerprint,
            "target": {
                "target_kind": plan.target_kind,
                "target_id": plan.target_id,
            },
        }

    @staticmethod
    def _resource_static_blockers(
        connection: Any, target_kind: str, target_id: str
    ) -> list[dict[str, Any]]:
        blockers: list[dict[str, Any]] = []
        if target_kind == "container":
            if connection.execute(
                "SELECT 1 FROM database_bindings WHERE docker_resource_id = ? LIMIT 1",
                (target_id,),
            ).fetchone() is not None:
                blockers.append(
                    _blocker(
                        "database_container",
                        "database-bound containers require a separately proven backup/removal workflow",
                    )
                )
            if connection.execute(
                """
                SELECT 1 FROM docker_ownership_claims
                WHERE docker_resource_id = ? AND provenance = 'compose'
                  AND conflict_state != 'retired' LIMIT 1
                """,
                (target_id,),
            ).fetchone() is not None:
                blockers.append(
                    _blocker(
                        "compose_owned",
                        "Compose-owned containers must be removed through a proven Compose project cleanup",
                    )
                )
            mounts = connection.execute(
                "SELECT full_container_id FROM docker_resources WHERE docker_resource_id = ?",
                (target_id,),
            ).fetchone()
            _ = mounts
        return blockers

    @staticmethod
    def _project_static_blockers(connection: Any, repo_id: str) -> list[dict[str, Any]]:
        blockers: list[dict[str, Any]] = []
        installation = connection.execute(
            "SELECT status, startup_fenced FROM repository_installations WHERE repo_id = ?",
            (repo_id,),
        ).fetchone()
        if installation is None or str(installation["status"]) != "disabled" or not bool(
            installation["startup_fenced"]
        ):
            blockers.append(_blocker("project_not_archived", "project must be archived first"))
        if connection.execute(
            "SELECT 1 FROM leases WHERE repo_id = ? AND status = 'active' LIMIT 1", (repo_id,)
        ).fetchone() is not None:
            blockers.append(_blocker("active_lease", "project still has an active port lease"))
        if connection.execute(
            "SELECT 1 FROM port_assignments WHERE repo_id = ? AND status = 'active' LIMIT 1",
            (repo_id,),
        ).fetchone() is not None:
            blockers.append(_blocker("active_assignment", "project still has an active port assignment"))
        if connection.execute(
            """
            SELECT 1 FROM repository_memberships m
            LEFT JOIN resource_retirements rr
              ON rr.resource_kind = m.resource_kind
             AND rr.host_resource_id = m.host_resource_id
            WHERE m.repo_id = ? AND rr.host_resource_id IS NULL
              AND EXISTS (
                SELECT 1 FROM server_observations so
                WHERE m.resource_kind = 'server'
                  AND so.server_definition_id = m.host_resource_id
                  AND so.lifecycle IN ('running','starting','unhealthy')
                UNION ALL
                SELECT 1 FROM docker_observations do
                WHERE m.resource_kind = 'container'
                  AND do.docker_resource_id = m.host_resource_id
                  AND do.lifecycle = 'running'
              ) LIMIT 1
            """,
            (repo_id,),
        ).fetchone() is not None:
            blockers.append(_blocker("active_child", "project still has a running child resource"))
        return blockers


def _canonical_target_kind(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized == "repository":
        return "project"
    if normalized not in TARGET_KINDS:
        raise CleanupError("target_kind must be project, server, container, or worktree")
    return normalized


def _require_target(kind: str, target_id: str) -> None:
    if kind not in TARGET_KINDS:
        raise CleanupError("unsupported cleanup target kind")
    value = str(target_id or "")
    if not value or len(value) > 512 or any(ord(character) < 32 for character in value):
        raise CleanupError("target_id is invalid")


def _require_canonical_uuid(value: str) -> None:
    try:
        parsed = uuid.UUID(str(value))
    except ValueError as error:
        raise CleanupError("plan_id must be a UUID") from error
    if str(parsed) != str(value).lower():
        raise CleanupError("plan_id must use canonical UUID form")


def _require_sha256(value: str, field: str) -> None:
    if re.fullmatch(r"sha256:[0-9a-f]{64}", str(value)) is None:
        raise CleanupError(f"{field} must be a sha256 fingerprint")


def _require_full_container_id(value: str) -> None:
    if _FULL_CONTAINER_ID.fullmatch(str(value).lower()) is None:
        raise CleanupError("Docker cleanup requires an exact 64-hex container ID")


def _blocker(code: str, message: str, **evidence: Any) -> dict[str, Any]:
    item: dict[str, Any] = {"code": code, "message": message}
    if evidence:
        item["evidence"] = evidence
    return item


def _deduplicate_blockers(values: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value in values:
        code = str(value.get("code") or "unknown")
        if code in seen:
            continue
        seen.add(code)
        result.append(dict(value))
    return result


def _run_git(root: Path, *arguments: str) -> str:
    owner = root.stat()
    result = subprocess.run(
        [_resolve_executable("git"), "-C", str(root), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=15.0,
        env=_sanitized_env(),
        preexec_fn=_owner_preexec(int(owner.st_uid), int(owner.st_gid)),
    )
    if result.returncode != 0:
        raise CleanupError("Git could not prove the linked worktree boundary")
    return result.stdout


def _inspect_linked_worktree(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    blockers: list[dict[str, Any]] = []
    if not root.is_absolute() or os.path.normpath(str(root)) != str(root):
        raise CleanupError("worktree catalog path is not canonical and absolute")
    canonical_root = root
    try:
        root_stat = canonical_root.lstat()
    except FileNotFoundError as error:
        raise CleanupError("worktree path is absent") from error
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        blockers.append(_blocker("unsafe_root", "worktree root is a symlink or not a directory"))
    current = Path(canonical_root.anchor)
    for part in canonical_root.parts[1:]:
        current = current / part
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                blockers.append(_blocker("symlink_component", "worktree path contains a symlink component"))
                break
        except OSError:
            blockers.append(_blocker("unobservable_path", "worktree path components cannot be inspected"))
            break
    marker = canonical_root / ".git"
    try:
        marker_stat = marker.lstat()
    except FileNotFoundError:
        marker_stat = None
    if marker_stat is None or not stat.S_ISREG(marker_stat.st_mode) or stat.S_ISLNK(marker_stat.st_mode):
        blockers.append(_blocker("not_linked_worktree", "target is not a linked secondary worktree"))
        marker_device = -1
        marker_inode = -1
    else:
        marker_device = int(marker_stat.st_dev)
        marker_inode = int(marker_stat.st_ino)
    top = Path(_run_git(canonical_root, "rev-parse", "--show-toplevel").strip()).absolute()
    git_dir_text = _run_git(canonical_root, "rev-parse", "--absolute-git-dir").strip()
    common_text = _run_git(canonical_root, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    git_dir = Path(git_dir_text).absolute()
    common_dir = Path(common_text).absolute()
    primary_root = common_dir.parent
    try:
        git_dir_stat = git_dir.lstat()
        common_dir_stat = common_dir.lstat()
        if (
            stat.S_ISLNK(git_dir_stat.st_mode)
            or not stat.S_ISDIR(git_dir_stat.st_mode)
            or stat.S_ISLNK(common_dir_stat.st_mode)
            or not stat.S_ISDIR(common_dir_stat.st_mode)
        ):
            blockers.append(
                _blocker(
                    "unsafe_git_admin",
                    "worktree Git administrative boundaries are symlinks or not directories",
                )
            )
    except OSError:
        git_dir_stat = None
        common_dir_stat = None
        blockers.append(
            _blocker(
                "git_admin_unobservable",
                "worktree Git administrative identities cannot be inspected",
            )
        )
    try:
        if canonical_root.resolve(strict=True) != canonical_root:
            blockers.append(_blocker("noncanonical_path", "worktree root is not its canonical path"))
    except OSError:
        blockers.append(_blocker("unobservable_path", "worktree canonical path cannot be proved"))
    try:
        primary_stat = primary_root.stat()
        if (
            int(primary_stat.st_uid) != int(root_stat.st_uid)
            or int(primary_stat.st_gid) != int(root_stat.st_gid)
        ):
            blockers.append(
                _blocker(
                    "owner_mismatch",
                    "primary and secondary worktrees do not have the same filesystem owner",
                )
            )
    except OSError:
        blockers.append(_blocker("primary_unobservable", "primary worktree ownership is unobservable"))
    if os.geteuid() not in {0, int(root_stat.st_uid)}:
        blockers.append(
            _blocker(
                "owner_authority",
                "coordinator cannot execute Git as the proved worktree owner",
            )
        )
    if int(root_stat.st_uid) == 0:
        blockers.append(
            _blocker(
                "root_owned_worktree",
                "root-owned worktrees are not eligible for automated removal",
            )
        )
    if top != canonical_root:
        blockers.append(_blocker("root_mismatch", "Git top-level does not match the catalog root"))
    if canonical_root == primary_root:
        blockers.append(_blocker("primary_worktree", "the primary worktree can never be removed here"))
    status_output = _run_git(
        canonical_root,
        "status",
        "--porcelain=v2",
        "--untracked-files=all",
        "--ignored=matching",
    )
    if status_output.strip():
        blockers.append(
            _blocker(
                "dirty_worktree",
                "worktree has tracked, untracked, or ignored content changes",
            )
        )
    if (canonical_root / ".gitmodules").exists():
        blockers.append(_blocker("submodules", "worktrees with submodule metadata are not removable"))
    listing = _run_git(primary_root, "worktree", "list", "--porcelain")
    entry = _worktree_list_entry(listing, canonical_root)
    if entry is None:
        blockers.append(_blocker("not_linked", "target is not registered in git worktree list"))
    else:
        if entry.get("locked") is not None or entry.get("prunable") is not None:
            blockers.append(_blocker("worktree_locked", "worktree is locked or prunable"))
        if "detached" in entry or "branch" not in entry:
            blockers.append(
                _blocker(
                    "detached_worktree",
                    "detached or unanchored worktrees require operator reconciliation",
                )
            )
    branch = str(entry.get("branch") or "") if entry is not None else ""
    head = _run_git(canonical_root, "rev-parse", "HEAD").strip().lower()
    if _GIT_OID.fullmatch(head) is None:
        blockers.append(_blocker("invalid_head", "worktree HEAD identity is invalid"))
    root_text = str(canonical_root)
    mountpoints, mount_unknown = _mountpoints()
    if mount_unknown:
        blockers.append(
            _blocker(
                "mount_observation_unavailable",
                "mounted filesystem boundaries cannot be completely observed",
                count=mount_unknown,
            )
        )
    for mountpoint in mountpoints:
        if _within(Path(mountpoint), canonical_root):
            blockers.append(_blocker("mount_boundary", "worktree contains a mounted filesystem", mountpoint=mountpoint))
            break
    process_cwds, proc_unknown = _process_cwds()
    if proc_unknown:
        blockers.append(
            _blocker(
                "process_cwd_unobservable",
                "one or more live process cwd boundaries are unobservable",
                count=proc_unknown,
            )
        )
    for pid, cwd in process_cwds:
        if _within(Path(cwd), canonical_root):
            blockers.append(_blocker("process_cwd", "a live process has its cwd inside the worktree", pid=pid))
            break
    process_fds, fd_unknown = _process_fds()
    if fd_unknown:
        blockers.append(
            _blocker(
                "process_fd_unobservable",
                "one or more live process file-descriptor boundaries are unobservable",
                count=fd_unknown,
            )
        )
    for pid, opened_path in process_fds:
        if _within(Path(opened_path), canonical_root):
            blockers.append(
                _blocker(
                    "process_fd",
                    "a live process holds an open file inside the worktree",
                    pid=pid,
                )
            )
            break
    identity = {
        "canonical_root": root_text,
        "git_dir": str(git_dir),
        "common_dir": str(common_dir),
        "git_dir_device": (
            int(git_dir_stat.st_dev) if git_dir_stat is not None else -1
        ),
        "git_dir_inode": (
            int(git_dir_stat.st_ino) if git_dir_stat is not None else -1
        ),
        "common_dir_device": (
            int(common_dir_stat.st_dev) if common_dir_stat is not None else -1
        ),
        "common_dir_inode": (
            int(common_dir_stat.st_ino) if common_dir_stat is not None else -1
        ),
        "primary_root": str(primary_root),
        "root_device": int(root_stat.st_dev),
        "root_inode": int(root_stat.st_ino),
        "marker_device": marker_device,
        "marker_inode": marker_inode,
        "head_oid": head,
        "branch": branch,
        "owner_uid": int(root_stat.st_uid),
        "owner_gid": int(root_stat.st_gid),
    }
    return identity, blockers


def _worktree_list_entry(text: str, root: Path) -> dict[str, str] | None:
    for block in text.strip().split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            key, _, value = line.partition(" ")
            fields[key] = value
        if fields.get("worktree") == str(root):
            return fields
    return None


def _mountpoints() -> tuple[tuple[str, ...], int]:
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError:
        return (), 1
    if not lines:
        return (), 1
    values: list[str] = []
    unknown = 0
    for line in lines:
        fields = line.split()
        if len(fields) > 4:
            values.append(fields[4].replace("\\040", " "))
        else:
            unknown += 1
    return tuple(values), unknown


def _process_cwds() -> tuple[tuple[tuple[int, str], ...], int]:
    proc = Path("/proc")
    if not proc.is_dir():
        return (), 1
    values: list[tuple[int, str]] = []
    unknown = 0
    try:
        entries = tuple(proc.iterdir())
    except OSError:
        return (), 1
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            cwd = os.readlink(entry / "cwd")
        except FileNotFoundError:
            continue
        except PermissionError:
            unknown += 1
            continue
        except OSError:
            unknown += 1
            continue
        values.append((int(entry.name), cwd))
    return tuple(values), unknown


def _process_fds() -> tuple[tuple[tuple[int, str], ...], int]:
    proc = Path("/proc")
    if not proc.is_dir():
        return (), 1
    values: list[tuple[int, str]] = []
    unknown = 0
    try:
        entries = tuple(proc.iterdir())
    except OSError:
        return (), 1
    for entry in entries:
        if not entry.name.isdigit():
            continue
        fd_root = entry / "fd"
        try:
            descriptors = tuple(fd_root.iterdir())
        except FileNotFoundError:
            continue
        except (PermissionError, OSError):
            unknown += 1
            continue
        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor)
            except FileNotFoundError:
                continue
            except (PermissionError, OSError):
                unknown += 1
                continue
            if target.endswith(" (deleted)"):
                target = target[: -len(" (deleted)")]
            if target.startswith("/"):
                values.append((int(entry.name), target))
    return tuple(values), unknown


def _within(candidate: Path, root: Path) -> bool:
    try:
        candidate.absolute().relative_to(root.absolute())
    except ValueError:
        return False
    return True


def _sanitized_env() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        "HOME": os.environ.get("HOME", "/"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }


def _resolve_executable(name: str) -> str:
    """Resolve once from a fixed system path and require a regular executable."""

    located = shutil.which(
        name,
        path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    )
    if not located:
        raise CleanupError(f"required host executable {name} is unavailable")
    canonical = os.path.realpath(located)
    try:
        mode = os.stat(canonical).st_mode
    except OSError as error:
        raise CleanupError(f"required host executable {name} is unobservable") from error
    if not stat.S_ISREG(mode) or not os.access(canonical, os.X_OK):
        raise CleanupError(f"required host executable {name} is not a regular executable")
    return canonical


def _owner_preexec(owner_uid: int, owner_gid: int) -> Callable[[], None] | None:
    if owner_uid == 0:
        raise CleanupBlocked(
            [
                _blocker(
                    "root_owned_worktree",
                    "root-owned worktrees are not eligible for automated removal",
                )
            ]
        )
    current = os.geteuid()
    if current == owner_uid:
        return None
    if current != 0:
        raise CleanupBlocked(
            [
                _blocker(
                    "owner_authority",
                    "coordinator cannot execute Git as the proved worktree owner",
                )
            ]
        )

    def assume_owner() -> None:
        os.setgroups([])
        os.setgid(owner_gid)
        os.setuid(owner_uid)

    return assume_owner
