from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import tempfile
import unittest
import uuid
from typing import Mapping

from devcoordinator import live_fault_acceptance as acceptance
from devcoordinator.universal_test_runtime import (
    NativeTestAttemptState,
    _runtime_id_for_attempt,
)


NOW = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)
DIGEST = "a" * 64
RELEASE = Path("/opt/devcoordinator/releases") / DIGEST


def request_document() -> dict[str, object]:
    scenarios = []
    for index, scenario_id in enumerate(acceptance.SCENARIO_IDS, 1):
        policy = acceptance.SCENARIO_POLICIES[scenario_id]
        scenarios.append(
            {
                "scenario_id": scenario_id,
                "resource_id": f"fault-resource-{index}",
                "resource_generation": 7,
                "operation_id": str(uuid.UUID(int=100 + index)),
                "unit_scope": policy["unit_scope"],
                "ttl_seconds": policy["ttl_seconds"],
                "kill_after_run": True,
                "expected_terminal": policy["expected_terminal"],
            }
        )
    return acceptance._seal(
        acceptance.REQUEST_KIND,
        {
            "operation_id": str(uuid.UUID(int=1)),
            "cutover": {
                "cutover_id": "schema13-acceptance-test",
                "activation_sha256": "9" * 64,
                "live_rollback_rehearsal_sha256": "a" * 64,
            },
            "release": {
                "root": str(RELEASE),
                "digest": DIGEST,
                "executor": str(RELEASE / "scripts/run_live_fault_isolation_acceptance.py"),
                "executor_sha256": "b" * 64,
                "fault_helper": str(
                    RELEASE
                    / "skills/codex-dev-coordinator/scripts/devcoordinator/live_fault_driver.py"
                ),
                "fault_helper_sha256": "c" * 64,
                "runner": str(
                    RELEASE
                    / "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_runner.py"
                ),
                "runner_sha256": "d" * 64,
            },
            "authority": {
                "host_id": "host-one",
                "host_boot_id": str(uuid.UUID(int=2)),
                "database_generation": "generation-seven",
                "state_revision": 23,
            },
            "repository": {
                "repository_id": "repo-under-test",
                "generation": 7,
                "owner_uid": 501,
                "root": "/srv/repos/project",
                "unrelated_repository_ids": ["repo-a", "repo-z"],
            },
            "inventory": {
                "publication": "/var/lib/devcoordinator-observer/inventory.publication",
                "expected_owner_uid": 990,
            },
            "control_cgroups": {
                "api": "/sys/fs/cgroup/devcoordinator-control.slice/devcoordinator-api.service/cgroup.procs",
                "authority": "/sys/fs/cgroup/devcoordinator-control.slice/devcoordinator-authority.service/cgroup.procs",
                "console": "/sys/fs/cgroup/devcoordinator-control.slice/devcoordinator-console@slot.service/cgroup.procs",
                "edge": "/sys/fs/cgroup/devcoordinator-control.slice/devcoordinator-edge.service/cgroup.procs",
            },
            "probe_targets": {
                "http": [
                    {"target_id": "api", "category": "api", "url": "https://console.example/healthz"},
                    {"target_id": "board", "category": "board", "url": "https://board.example/healthz"},
                    {"target_id": "console", "category": "console", "url": "https://console.example/"},
                    {"target_id": "project", "category": "project", "url": "https://project.example/"},
                ],
                "websocket": [
                    {"target_id": "project-events", "category": "project", "url": "wss://project.example/events"},
                ],
            },
            "scenarios": scenarios,
            "created_at": NOW.isoformat().replace("+00:00", "Z"),
            "valid_until": (NOW + timedelta(minutes=15)).isoformat().replace("+00:00", "Z"),
        },
    )


def probe(phase: str, *, suffix: str = "") -> dict[str, object]:
    return {
        "phase": phase,
        "captured_at": NOW.isoformat().replace("+00:00", "Z"),
        "http_sample_count": 4,
        "websocket_sample_count": 1,
        "connection_refused_count": 0,
        "project_route_failures": 0,
        "failed_sample_count": 0,
        "control_processes_sha256": "1" * 64,
        "socket_inodes_sha256": "2" * 64,
        "unrelated_project_state_sha256": ("3" * 63) + (suffix or "3"),
        "global_attention_state_sha256": "4" * 64,
        "passed": True,
    }


class FakeObserver:
    def __init__(
        self,
        *,
        change_phase: str | None = None,
        change_after: int | None = None,
        change_field: str = "unrelated_project_state_sha256",
        fail_phase: str | None = None,
    ):
        self.change_phase = change_phase
        self.change_after = change_after
        self.change_field = change_field
        self.fail_phase = fail_phase
        self.calls: list[str] = []

    def capture(self, phase: str):
        self.calls.append(phase)
        result = probe(phase)
        if phase == self.change_phase or (
            self.change_after is not None and len(self.calls) > self.change_after
        ):
            result[self.change_field] = "5" * 64
        if phase == self.fail_phase:
            result.update(
                {
                    "connection_refused_count": 1,
                    "failed_sample_count": 1,
                    "passed": False,
                }
            )
        return result


class FakeRuntime:
    def __init__(self, *, cleanup_converges: bool = True, wrong_terminal: str | None = None):
        self.cleanup_converges = cleanup_converges
        self.wrong_terminal = wrong_terminal
        self.launched: list[Mapping[str, object]] = []
        self.cleaned: list[str] = []

    def launch(self, scenario):
        self.launched.append(dict(scenario))
        return {
            "scenario_id": scenario["scenario_id"],
            "runtime_id": "runtime-" + scenario["scenario_id"],
            "resource_id": scenario["resource_id"],
            "resource_generation": scenario["resource_generation"],
            "operation_id": scenario["operation_id"],
            "ticket_fingerprint": "5" * 64,
            "launch_ack_id": "launch-" + scenario["scenario_id"],
            "descriptor_sha256": "6" * 64,
            "unit_scope": scenario["unit_scope"],
            "ttl_seconds": scenario["ttl_seconds"],
            "kill_after_run": True,
        }

    def status(self, handle):
        scenario = self.launched[-1]
        malformed = scenario["scenario_id"] == "malformed_runner_output"
        oom = scenario["scenario_id"] == "cgroup_oom"
        return {
            "scenario_id": scenario["scenario_id"],
            "runtime_id": handle["runtime_id"],
            "active": False,
            "loaded": True,
            "terminal": self.wrong_terminal or scenario["expected_terminal"],
            "exit_status": None if oom else (1 if malformed else 0),
            "systemd_result": "oom-kill" if oom else ("exit-code" if malformed else "success"),
            "oom_killed": oom,
            "result_document_sha256": None if oom else "7" * 64,
            "result_chunks_sha256": "8" * 64,
            "reporter_complete": False if oom or malformed else True,
        }

    def cleanup(self, handle):
        self.cleaned.append(str(handle["runtime_id"]))
        return {
            "runtime_id": handle["runtime_id"],
            "converged": self.cleanup_converges,
            "loaded": False,
            "active": False,
            "state": "not-found",
        }


class FakeManager:
    def __init__(self):
        self.descriptor = None
        self.start_count = 0

    def start(self, descriptor):
        self.descriptor = descriptor
        self.start_count += 1
        return NativeTestAttemptState(
            _runtime_id_for_attempt(descriptor.attempt_id),
            True,
            True,
            "running",
            None,
        )

    def status(self, runtime_id):
        return NativeTestAttemptState(runtime_id, False, False, "not-found", 0, termination_reason="success")

    def read_result_chunk(self, runtime_id, chunk_index):
        return None

    def cancel(self, runtime_id):
        return self.status(runtime_id)

    def collect(self, runtime_id):
        return None


class LiveFaultAcceptanceTests(unittest.TestCase):
    def test_complete_acceptance_is_sealed_and_exact(self) -> None:
        request = request_document()
        runtime = FakeRuntime()
        observer = FakeObserver()
        document = acceptance.run_acceptance(
            request,
            runtime=runtime,
            observer=observer,
            now=lambda: NOW,
        )
        checked = acceptance.validate_attestation(
            document,
            request=request,
            now=NOW,
            require_fresh=True,
        )
        self.assertTrue(checked["aggregate"]["passed"])
        self.assertEqual(checked["aggregate"]["scenario_count"], 6)
        self.assertEqual(observer.calls, [phase for _ in range(6) for phase in ("pre", "during", "post")])
        self.assertEqual(len(runtime.cleaned), 6)

    def test_board_probe_is_mandatory_and_fail_closed(self) -> None:
        request = request_document()
        unsigned = dict(request)
        unsigned.pop("document_sha256")
        unsigned["probe_targets"] = deepcopy(request["probe_targets"])
        unsigned["probe_targets"]["http"] = [
            item for item in unsigned["probe_targets"]["http"] if item["category"] != "board"
        ]
        request = acceptance._seal(
            acceptance.REQUEST_KIND,
            {key: value for key, value in unsigned.items() if key not in {"schema_version", "kind"}},
        )
        with self.assertRaises(acceptance.FaultAcceptanceError) as raised:
            acceptance.validate_request(request, now=NOW)
        self.assertEqual(raised.exception.code, "board_continuity_unsupported")

    def test_scenario_policy_cannot_weaken_ttl_or_cleanup(self) -> None:
        request = request_document()
        for mutation in ("ttl", "kill"):
            raw = dict(request)
            raw.pop("document_sha256")
            raw["scenarios"] = deepcopy(request["scenarios"])
            if mutation == "ttl":
                raw["scenarios"][0]["ttl_seconds"] += 1
            else:
                raw["scenarios"][0]["kill_after_run"] = False
            forged = acceptance._seal(
                acceptance.REQUEST_KIND,
                {key: value for key, value in raw.items() if key not in {"schema_version", "kind"}},
            )
            with self.assertRaisesRegex(acceptance.FaultAcceptanceError, "safety policy"):
                acceptance.validate_request(forged, now=NOW)

        with self.assertRaisesRegex(acceptance.FaultAcceptanceError, "cleanup"):
            acceptance.run_acceptance(
                request,
                runtime=FakeRuntime(cleanup_converges=False),
                observer=FakeObserver(),
                now=lambda: NOW,
            )

    def test_unrelated_project_or_control_state_change_blocks_evidence(self) -> None:
        with self.assertRaisesRegex(acceptance.FaultAcceptanceError, "unrelated-project"):
            acceptance.run_acceptance(
                request_document(),
                runtime=FakeRuntime(),
                observer=FakeObserver(change_phase="during"),
                now=lambda: NOW,
            )

        with self.assertRaisesRegex(acceptance.FaultAcceptanceError, "campaign changed control"):
            acceptance.run_acceptance(
                request_document(),
                runtime=FakeRuntime(),
                observer=FakeObserver(
                    change_after=3,
                    change_field="control_processes_sha256",
                ),
                now=lambda: NOW,
            )

    def test_refused_connection_blocks_evidence(self) -> None:
        with self.assertRaisesRegex(acceptance.FaultAcceptanceError, "continuity failure"):
            acceptance.run_acceptance(
                request_document(),
                runtime=FakeRuntime(),
                observer=FakeObserver(fail_phase="during"),
                now=lambda: NOW,
            )

    def test_partial_forged_and_stale_attestations_are_rejected(self) -> None:
        request = request_document()
        document = acceptance.run_acceptance(
            request, runtime=FakeRuntime(), observer=FakeObserver(), now=lambda: NOW
        )
        partial = deepcopy(document)
        partial["scenarios"].pop()
        partial = acceptance._seal(
            acceptance.ATTESTATION_KIND,
            {key: value for key, value in partial.items() if key not in {"schema_version", "kind", "document_sha256"}},
        )
        with self.assertRaisesRegex(acceptance.FaultAcceptanceError, "incomplete"):
            acceptance.validate_attestation(partial, request=request, now=NOW)
        forged = deepcopy(document)
        forged["aggregate"]["control_restart_count"] = 1
        with self.assertRaisesRegex(acceptance.FaultAcceptanceError, "seal"):
            acceptance.validate_attestation(forged, request=request, now=NOW)
        cross_scenario = deepcopy(document)
        for observation in cross_scenario["scenarios"][1]["probes"].values():
            observation["control_processes_sha256"] = "5" * 64
        cross_scenario = acceptance._seal(
            acceptance.ATTESTATION_KIND,
            {
                key: value
                for key, value in cross_scenario.items()
                if key not in {"schema_version", "kind", "document_sha256"}
            },
        )
        with self.assertRaisesRegex(acceptance.FaultAcceptanceError, "campaign changed control"):
            acceptance.validate_attestation(cross_scenario, request=request, now=NOW)
        with self.assertRaises(acceptance.FaultAcceptanceError):
            acceptance.validate_attestation(
                document,
                request=request,
                now=NOW + timedelta(minutes=16),
                require_fresh=True,
            )

    def test_cross_cutover_and_cross_rehearsal_evidence_is_rejected(self) -> None:
        request = request_document()
        document = acceptance.run_acceptance(
            request, runtime=FakeRuntime(), observer=FakeObserver(), now=lambda: NOW
        )
        for field, replacement in (
            ("cutover_id", "schema13-another-cutover"),
            ("activation_sha256", "b" * 64),
            ("live_rollback_rehearsal_sha256", "c" * 64),
        ):
            raw = deepcopy(request)
            raw.pop("document_sha256")
            raw["cutover"] = dict(request["cutover"])
            raw["cutover"][field] = replacement
            other = acceptance._seal(
                acceptance.REQUEST_KIND,
                {
                    key: value
                    for key, value in raw.items()
                    if key not in {"schema_version", "kind"}
                },
            )
            with self.assertRaisesRegex(
                acceptance.FaultAcceptanceError,
                "another request or release",
            ):
                acceptance.validate_attestation(document, request=other, now=NOW)

    def test_wrong_oom_or_terminal_classification_is_rejected(self) -> None:
        with self.assertRaisesRegex(acceptance.FaultAcceptanceError, "expected terminal"):
            acceptance.run_acceptance(
                request_document(),
                runtime=FakeRuntime(wrong_terminal="systemd_failure"),
                observer=FakeObserver(),
                now=lambda: NOW,
            )

    def test_native_runtime_issues_exact_broker_ticket_and_accounting_only_slice(self) -> None:
        request = acceptance.validate_request(request_document(), now=NOW)
        manager = FakeManager()
        native = acceptance.NativeFaultRuntime(request=request, manager=manager, clock=lambda: 1.0)
        scenario = request["scenarios"][0]
        handle = native.launch(scenario)
        descriptor = manager.descriptor
        self.assertIsNotNone(descriptor)
        self.assertEqual(manager.start_count, 1)
        self.assertEqual(
            handle["runtime_id"],
            _runtime_id_for_attempt(descriptor.attempt_id),
        )
        self.assertEqual(descriptor.target_id, scenario["resource_id"])
        self.assertEqual(descriptor.repository_generation, 7)
        self.assertEqual(descriptor.ttl_seconds, scenario["ttl_seconds"])
        self.assertFalse(
            {"cpu_millis", "memory_mib", "pids"}
            & set(descriptor.to_document())
        )
        self.assertTrue(handle["kill_after_run"])
        slow = native._descriptor(request["scenarios"][4])
        self.assertEqual(
            acceptance.FaultAcceptanceAttemptManager._repository_slice(slow),
            acceptance.project_repository_slice(uid=501, repository_id="repo-under-test"),
        )
        self.assertIn(
            "devcoordinator-tests",
            acceptance.FaultAcceptanceAttemptManager._repository_slice(descriptor),
        )

    def test_private_attestation_publication_is_atomic_no_clobber(self) -> None:
        request = request_document()
        document = acceptance.run_acceptance(
            request, runtime=FakeRuntime(), observer=FakeObserver(), now=lambda: NOW
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            root.chmod(0o700)
            output = root / "attestation.json"
            acceptance.write_private_json(output, document, expected_uid=os.geteuid())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                acceptance.read_private_json(output, expected_uid=os.geteuid())["document_sha256"],
                document["document_sha256"],
            )
            with self.assertRaisesRegex(acceptance.FaultAcceptanceError, "already exists"):
                acceptance.write_private_json(output, document, expected_uid=os.geteuid())


if __name__ == "__main__":
    unittest.main()
