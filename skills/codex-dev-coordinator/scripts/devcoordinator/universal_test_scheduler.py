"""Deterministic fair scheduling with empirical host-memory admission.

CPU, PID, manifest resource declarations, account identity, and repository
identity are not capacity gates on this single-developer server. Testd reads
``MemAvailable`` immediately before each scheduling turn, retains a small
control-plane/OS reserve, and admits against learned target peak memory. The
only non-memory gates preserve execution correctness: one live job per exact
worktree and declared exclusive resources.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from pathlib import Path
import time
from typing import Callable, Iterable, Mapping, Sequence

from .universal_test_store import RunnableTarget, TestStoreContractError


MIB = 1024 * 1024
DEFAULT_COLD_START_MIB = 512
MIN_HOST_RESERVE_MIB = 1024
MAX_HOST_RESERVE_MIB = 8192


@dataclass(frozen=True)
class HostMemorySnapshot:
    total_mib: int
    available_mib: int
    observed_at: float


@dataclass(frozen=True)
class ActiveAllocation:
    attempt_id: str
    target_id: str
    repository_id: str
    owner_uid: int
    worktree_key: str
    source_mode: str
    exclusive_resources: tuple[str, ...] = ()
    memory_commitment_mib: int = DEFAULT_COLD_START_MIB
    current_memory_bytes: int | None = None
    runtime_active: bool = True


@dataclass(frozen=True)
class AdmissionRejection:
    target_id: str
    reason: str
    required_mib: int | None = None
    available_mib: int | None = None
    reserve_mib: int | None = None
    observed_at: float | None = None
    source: str | None = None


@dataclass(frozen=True)
class ScheduleDecision:
    selected: tuple[RunnableTarget, ...]
    rejected: tuple[AdmissionRejection, ...]
    memory: HostMemorySnapshot
    reserve_mib: int
    active_memory_reservation_mib: int


def read_host_memory(
    path: Path = Path("/proc/meminfo"),
    *,
    clock: Callable[[], float] = time.time,
) -> HostMemorySnapshot:
    """Read Linux's current usable memory without estimating from totals."""

    try:
        fields: dict[str, int] = {}
        for raw in path.read_text(encoding="utf-8").splitlines():
            name, separator, rest = raw.partition(":")
            if not separator:
                continue
            parts = rest.strip().split()
            if len(parts) != 2 or parts[1] != "kB":
                continue
            fields[name] = int(parts[0])
        total_kib = fields["MemTotal"]
        available_kib = fields["MemAvailable"]
    except (OSError, KeyError, ValueError) as error:
        raise TestStoreContractError("host MemAvailable is unavailable") from error
    if total_kib <= 0 or available_kib < 0 or available_kib > total_kib:
        raise TestStoreContractError("host MemAvailable is invalid")
    return HostMemorySnapshot(
        total_mib=max(1, total_kib // 1024),
        available_mib=available_kib // 1024,
        observed_at=float(clock()),
    )


def host_memory_reserve_mib(total_mib: int) -> int:
    """Keep 5% for the OS/control plane, bounded to 1--8 GiB."""

    if type(total_mib) is not int or total_mib <= 0:
        raise TestStoreContractError("host total memory must be positive")
    return max(
        MIN_HOST_RESERVE_MIB,
        min(MAX_HOST_RESERVE_MIB, math.ceil(total_mib * 0.05)),
    )


def _weight(field: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TestStoreContractError(f"{field} must be numeric")
    number = float(value)
    if not math.isfinite(number) or not 0.01 <= number <= 100:
        raise TestStoreContractError(f"{field} must be from 0.01 through 100")
    return number


class WeightedFairScheduler:
    """Choose runnable targets fairly while using only real memory capacity."""

    def __init__(
        self,
        *,
        memory_probe: Callable[[], HostMemorySnapshot] = read_host_memory,
        uid_weights: Mapping[int, float] | None = None,
        repository_weights: Mapping[str, float] | None = None,
    ) -> None:
        if not callable(memory_probe):
            raise TestStoreContractError("memory_probe must be callable")
        self._memory_probe = memory_probe
        self._uid_weights = {
            int(uid): _weight(f"uid_weights.{uid}", value)
            for uid, value in (uid_weights or {}).items()
        }
        if any(type(uid) is not int or uid < 0 for uid in self._uid_weights):
            raise TestStoreContractError("uid weight keys must be non-negative integers")
        self._repo_weights = {
            str(repo): _weight(f"repository_weights.{repo}", value)
            for repo, value in (repository_weights or {}).items()
        }
        if any(not repo or len(repo) > 256 for repo in self._repo_weights):
            raise TestStoreContractError("repository weight keys must be bounded")
        self._uid_vruntime: dict[int, float] = {}
        self._repo_vruntime: dict[str, float] = {}

    def select(
        self,
        candidates: Sequence[RunnableTarget],
        *,
        active: Sequence[ActiveAllocation] = (),
        launch_batch: int | None = None,
    ) -> ScheduleDecision:
        """Return one exact launch turn without imposing an active-job quota."""

        if launch_batch is not None and (
            type(launch_batch) is not int or launch_batch <= 0
        ):
            raise TestStoreContractError("launch_batch must be a positive integer")
        snapshot = self._memory_probe()
        if not isinstance(snapshot, HostMemorySnapshot):
            raise TestStoreContractError("memory_probe returned an invalid snapshot")
        if (
            type(snapshot.total_mib) is not int
            or type(snapshot.available_mib) is not int
            or snapshot.total_mib <= 0
            or not 0 <= snapshot.available_mib <= snapshot.total_mib
            or not math.isfinite(snapshot.observed_at)
            or snapshot.observed_at < 0
        ):
            raise TestStoreContractError("memory_probe returned an invalid snapshot")
        reserve_mib = host_memory_reserve_mib(snapshot.total_mib)
        remaining_mib = max(0, snapshot.available_mib - reserve_mib)

        unique: dict[str, RunnableTarget] = {}
        for candidate in candidates:
            if not isinstance(candidate, RunnableTarget):
                raise TestStoreContractError("candidates must be RunnableTarget values")
            if candidate.target_id in unique:
                raise TestStoreContractError("candidate target_id is duplicated")
            self._validate_candidate(candidate)
            unique[candidate.target_id] = candidate
        active_items: list[ActiveAllocation] = []
        for allocation in active:
            if not isinstance(allocation, ActiveAllocation):
                raise TestStoreContractError("active values must be ActiveAllocation")
            self._validate_allocation(allocation)
            active_items.append(allocation)

        # ``MemAvailable`` already reflects memory an active test currently
        # consumes.  Reserve only the unmaterialized portion of its launch-time
        # learned commitment, otherwise every active RSS byte would be counted
        # twice and useful parallelism would collapse.  A just-launched or
        # recovered runtime without a current cgroup sample conservatively
        # retains its complete commitment until the next heartbeat observes it.
        active_memory_reservation_mib = sum(
            self._unrealized_memory_mib(item) for item in active_items
        )
        remaining_mib = max(0, remaining_mib - active_memory_reservation_mib)

        live_worktrees = {
            item.worktree_key for item in active_items if item.source_mode == "live"
        }
        exclusive = {
            resource
            for item in active_items
            for resource in item.exclusive_resources
        }
        pending = list(unique.values())
        selected: list[RunnableTarget] = []
        rejected: dict[str, AdmissionRejection] = {}
        capacity = launch_batch if launch_batch is not None else len(pending)
        while pending and len(selected) < capacity:
            pending.sort(key=self._fair_key)
            admitted = False
            next_pending: list[RunnableTarget] = []
            for candidate in pending:
                correctness_reason = self._correctness_rejection(
                    candidate,
                    live_worktrees=live_worktrees,
                    exclusive=exclusive,
                )
                if correctness_reason is not None:
                    rejected[candidate.target_id] = AdmissionRejection(
                        candidate.target_id, correctness_reason
                    )
                    next_pending.append(candidate)
                    continue
                estimate = candidate.memory_estimate_mib
                if estimate > remaining_mib:
                    rejected[candidate.target_id] = AdmissionRejection(
                        candidate.target_id,
                        "host_memory",
                        required_mib=estimate,
                        available_mib=remaining_mib,
                        reserve_mib=reserve_mib,
                        observed_at=snapshot.observed_at,
                        source=candidate.memory_estimate_source,
                    )
                    next_pending.append(candidate)
                    continue
                selected.append(candidate)
                rejected.pop(candidate.target_id, None)
                remaining_mib -= estimate
                if candidate.source_mode == "live":
                    live_worktrees.add(candidate.worktree_key)
                exclusive.update(candidate.exclusive_resources)
                cost = max(0.001, candidate.estimated_seconds)
                self._uid_vruntime[candidate.owner_uid] = (
                    self._uid_vruntime.get(candidate.owner_uid, 0.0)
                    + cost / self._uid_weights.get(candidate.owner_uid, 1.0)
                )
                self._repo_vruntime[candidate.repository_id] = (
                    self._repo_vruntime.get(candidate.repository_id, 0.0)
                    + cost / self._repo_weights.get(candidate.repository_id, 1.0)
                )
                next_pending.extend(
                    item
                    for item in pending
                    if item.target_id != candidate.target_id
                    and item.target_id
                    not in {entry.target_id for entry in next_pending}
                )
                admitted = True
                break
            pending = next_pending
            if not admitted:
                break
        return ScheduleDecision(
            selected=tuple(selected),
            rejected=tuple(rejected[key] for key in sorted(rejected)),
            memory=snapshot,
            reserve_mib=reserve_mib,
            active_memory_reservation_mib=active_memory_reservation_mib,
        )

    @staticmethod
    def _validate_candidate(item: RunnableTarget) -> None:
        if item.owner_uid < 0 or not item.repository_id or not item.worktree_key:
            raise TestStoreContractError("candidate identity is invalid")
        if item.source_mode not in {"live", "immutable"}:
            raise TestStoreContractError("candidate.source_mode is invalid")
        if (
            type(item.memory_estimate_mib) is not int
            or item.memory_estimate_mib <= 0
            or type(item.memory_sample_count) is not int
            or item.memory_sample_count < 0
            or not item.memory_estimate_source
        ):
            raise TestStoreContractError("candidate memory estimate is invalid")
        if not math.isfinite(item.estimated_seconds) or item.estimated_seconds <= 0:
            raise TestStoreContractError(
                "candidate.estimated_seconds must be finite and positive"
            )

    @staticmethod
    def _validate_allocation(item: ActiveAllocation) -> None:
        if item.owner_uid < 0 or not item.repository_id or not item.worktree_key:
            raise TestStoreContractError("active identity is invalid")
        if item.source_mode not in {"live", "immutable"}:
            raise TestStoreContractError("active.source_mode is invalid")
        if (
            type(item.memory_commitment_mib) is not int
            or item.memory_commitment_mib <= 0
            or (
                item.current_memory_bytes is not None
                and (
                    type(item.current_memory_bytes) is not int
                    or item.current_memory_bytes < 0
                )
            )
            or type(item.runtime_active) is not bool
        ):
            raise TestStoreContractError("active memory commitment is invalid")

    @staticmethod
    def _unrealized_memory_mib(item: ActiveAllocation) -> int:
        if not item.runtime_active:
            return 0
        if item.current_memory_bytes is None:
            return item.memory_commitment_mib
        current_mib = (
            item.current_memory_bytes + MIB - 1
        ) // MIB
        return max(0, item.memory_commitment_mib - current_mib)

    def _fair_key(self, candidate: RunnableTarget) -> tuple[object, ...]:
        return (
            -candidate.priority,
            self._uid_vruntime.get(candidate.owner_uid, 0.0),
            self._repo_vruntime.get(candidate.repository_id, 0.0),
            candidate.queued_at,
            candidate.repository_id,
            candidate.target_id,
        )

    @staticmethod
    def _correctness_rejection(
        candidate: RunnableTarget,
        *,
        live_worktrees: set[str],
        exclusive: set[str],
    ) -> str | None:
        if candidate.source_mode == "live" and candidate.worktree_key in live_worktrees:
            return "exact_worktree_busy"
        if set(candidate.exclusive_resources).intersection(exclusive):
            return "exclusive_resource_busy"
        return None


def allocations_from_store(
    values: Iterable[Mapping[str, object]],
) -> tuple[ActiveAllocation, ...]:
    """Convert the store's JSON-safe correctness projection explicitly."""

    return tuple(
        ActiveAllocation(
            attempt_id=str(value["attempt_id"]),
            target_id=str(value["target_id"]),
            repository_id=str(value["repository_id"]),
            owner_uid=int(value["owner_uid"]),
            worktree_key=str(value["worktree_key"]),
            exclusive_resources=tuple(value.get("exclusive_resources", ())),
            source_mode=str(value["source_mode"]),
            memory_commitment_mib=int(
                value.get("memory_commitment_mib", DEFAULT_COLD_START_MIB)
            ),
            current_memory_bytes=(
                None
                if value.get("current_memory_bytes") is None
                else int(value["current_memory_bytes"])
            ),
            runtime_active=bool(value.get("runtime_active", True)),
        )
        for value in values
    )


__all__ = [
    "ActiveAllocation",
    "AdmissionRejection",
    "DEFAULT_COLD_START_MIB",
    "HostMemorySnapshot",
    "ScheduleDecision",
    "WeightedFairScheduler",
    "allocations_from_store",
    "host_memory_reserve_mib",
    "read_host_memory",
]
