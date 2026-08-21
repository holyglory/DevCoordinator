from __future__ import annotations

import unittest

from devcoordinator.universal_test_scheduler import (
    ActiveAllocation,
    HostMemorySnapshot,
    WeightedFairScheduler,
)
from devcoordinator.universal_test_store import RunnableTarget


def target(
    name: str,
    *,
    memory: int = 512,
    repository: str = "repo-v8",
    exclusive: tuple[str, ...] = (),
) -> RunnableTarget:
    return RunnableTarget(
        target_id="target-" + name,
        run_id="run-" + name,
        repository_id=repository,
        owner_uid=1001,
        priority=0,
        queued_at=1.0,
        target_name=name,
        wave_index=0,
        shard_index=0,
        shard_count=1,
        estimated_seconds=1.0,
        worktree_key="/srv/snapshots/" + name,
        source_mode="immutable",
        exclusive_resources=exclusive,
        memory_estimate_mib=memory,
        memory_estimate_source="measured",
        memory_sample_count=1,
    )


class V8SchedulerTests(unittest.TestCase):
    def scheduler(self, available: int = 4096) -> WeightedFairScheduler:
        return WeightedFairScheduler(
            memory_probe=lambda: HostMemorySnapshot(
                total_mib=16_384,
                available_mib=available,
                observed_at=10.0,
            )
        )

    def test_admits_from_current_available_memory_without_job_quota(self) -> None:
        decision = self.scheduler().select(
            tuple(target(str(index), memory=256) for index in range(8))
        )
        self.assertEqual(len(decision.selected), 8)
        self.assertEqual(decision.rejected, ())

    def test_reports_truthful_memory_wait(self) -> None:
        decision = self.scheduler(available=1500).select((target("large", memory=600),))
        self.assertEqual(decision.selected, ())
        self.assertEqual(decision.rejected[0].reason, "host_memory")
        self.assertEqual(decision.rejected[0].source, "measured")

    def test_active_observed_memory_is_not_double_counted(self) -> None:
        active = ActiveAllocation(
            execution_id="execution-active",
            target_id="target-active",
            repository_id="repo-active",
            owner_uid=1001,
            worktree_key="/srv/snapshots/active",
            source_mode="immutable",
            memory_commitment_mib=1024,
            current_memory_bytes=800 * 1024 * 1024,
        )
        decision = self.scheduler(available=2400).select(
            (target("next", memory=1000),), active=(active,)
        )
        self.assertEqual([item.target_name for item in decision.selected], ["next"])
        self.assertEqual(decision.active_memory_reservation_mib, 224)

    def test_exact_exclusive_resource_blocks_only_the_conflicting_target(self) -> None:
        active = ActiveAllocation(
            execution_id="execution-active",
            target_id="target-active",
            repository_id="repo-active",
            owner_uid=1001,
            worktree_key="/srv/snapshots/active",
            source_mode="immutable",
            exclusive_resources=("database",),
            memory_commitment_mib=512,
            current_memory_bytes=512 * 1024 * 1024,
        )
        decision = self.scheduler().select(
            (
                target("conflict", exclusive=("database",)),
                target("independent"),
            ),
            active=(active,),
        )
        self.assertEqual(
            [item.target_name for item in decision.selected], ["independent"]
        )
        self.assertEqual(decision.rejected[0].reason, "exclusive_resource_busy")


if __name__ == "__main__":
    unittest.main()
