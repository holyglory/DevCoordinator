from __future__ import annotations

import copy
import json
import unittest

from devcoordinator.runtime_report import (
    MAX_EVIDENCE_ITEMS,
    RUNTIME_ARTIFACT_MAX_BYTES,
    RUNTIME_ARTIFACT_MAX_LINES,
    build_runtime_report,
)


def usage(cpu: float | None, memory: int | None, processes: int) -> dict[str, object]:
    return {
        "cpu_percent": cpu,
        "memory_bytes": memory,
        "process_count": processes,
        "server": {
            "resource_count": processes,
            "process_count": processes,
            "cpu_percent": cpu,
            "memory_bytes": memory,
        },
        "docker": {
            "resource_count": 0,
            "process_count": 0,
            "cpu_percent": None,
            "memory_bytes": None,
        },
    }


class RuntimeReportTests(unittest.TestCase):
    maxDiff = None

    def request(self, **changes: object) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": 1,
            "action": "status",
            "agent": "fixture-agent",
            "root_repo": "/repos/root",
            "temporary_repo": "/repos/temp",
            "purpose": "temporary",
            "ttl_seconds": 60,
            "kill_after_run": False,
            "target": {"kind": "service", "id": "service-temp", "name": "web"},
            "options": {},
        }
        result.update(changes)
        return result

    def inventory(self) -> dict[str, object]:
        return {
            "repository_trees": [
                {
                    "family_id": "family-root",
                    "root_repository": {
                        "repo_id": "repo-root",
                        "canonical_root": "/repos/root",
                        "display_name": "root",
                    },
                    "usage": usage(8.5, 8_500, 3),
                    "scopes": [
                        {
                            "repo_id": "repo-root",
                            "kind": "root",
                            "canonical_root": "/repos/root",
                            "display_name": "root",
                            "usage": usage(2.0, 2_000, 1),
                            "server_ids": ["service-root"],
                            "container_resource_ids": ["docker-root"],
                            "database_binding_ids": [],
                        },
                        {
                            "repo_id": "repo-temp",
                            "kind": "temporary",
                            "canonical_root": "/repos/temp",
                            "display_name": "temp",
                            "usage": usage(6.5, 6_500, 2),
                            "server_ids": ["service-temp"],
                            "container_resource_ids": ["docker-temp"],
                            "database_binding_ids": ["database-temp"],
                        },
                    ],
                }
            ],
            "resources": {
                "servers": [
                    {
                        "server_definition_id": "service-root",
                        "repo_id": "repo-root",
                        "name": "root-web",
                        "health_url_template": "http://root.test:3100/health?token=secret",
                        "log_path": "/private/logs/root-web.log",
                    },
                    {
                        "server_definition_id": "service-temp",
                        "repo_id": "repo-temp",
                        "name": "web",
                        "health_url_template": "http://temp.test:3200/health",
                        "log_path": "/private/logs/temp-web.log",
                    },
                    {
                        "server_definition_id": "service-outsider",
                        "repo_id": "repo-outsider",
                        "name": "outsider",
                        "log_path": "/private/logs/outsider.log",
                    },
                ],
                "docker": [
                    {"docker_resource_id": "docker-root", "current_name": "root-db"},
                    {"docker_resource_id": "docker-temp", "current_name": "temp-db"},
                    {"docker_resource_id": "docker-outsider", "current_name": "outsider"},
                ],
                "docker_ports": [
                    {"docker_resource_id": "docker-root", "host_port": 5432},
                    {"docker_resource_id": "docker-temp", "host_port": 5433},
                    {"docker_resource_id": "docker-outsider", "host_port": 6666},
                ],
                "databases": [
                    {
                        "database_binding_id": "database-temp",
                        "repo_id": "repo-temp",
                        "docker_resource_id": "docker-temp",
                        "database_name": "app",
                    }
                ],
            },
            "leases": [
                {
                    "server_definition_id": "service-root",
                    "repo_id": "repo-root",
                    "status": "active",
                    "port": 3100,
                },
                {
                    "server_definition_id": "service-temp",
                    "repo_id": "repo-temp",
                    "status": "active",
                    "port": 3200,
                },
                {
                    "server_definition_id": "service-outsider",
                    "repo_id": "repo-outsider",
                    "status": "active",
                    "port": 7777,
                },
            ],
            "port_assignments": [],
            "observations": {
                "servers": [
                    {
                        "server_definition_id": "service-root",
                        "lifecycle": "running",
                        "listener_host": "127.0.0.1",
                        "listener_port": 3100,
                    },
                    {
                        "server_definition_id": "service-temp",
                        "lifecycle": "running",
                        "listener_host": "127.0.0.1",
                        "listener_port": 3200,
                    },
                ],
                "docker": [
                    {"docker_resource_id": "docker-root", "lifecycle": "running"},
                    {"docker_resource_id": "docker-temp", "lifecycle": "running"},
                ],
                "databases": [
                    {"database_binding_id": "database-temp", "available": 1}
                ],
                "telemetry": [
                    {
                        "host_resource_kind": "server",
                        "host_resource_id": "service-temp",
                        # Raw history is deliberately newer/future and
                        # contradictory.  Reports must use the store's
                        # lineage-filtered compatibility projection instead.
                        "sampled_at": "2099-01-01T00:00:00Z",
                        "cpu_percent": 555.0,
                        "memory_bytes": 555_000,
                    },
                    {
                        "host_resource_kind": "docker",
                        "host_resource_id": "docker-temp",
                        "sampled_at": "1999-01-01T00:00:00Z",
                        "cpu_percent": 111.0,
                        "memory_bytes": 111_000,
                    },
                ],
            },
            "v1_compatibility": {
                "servers": [
                    {
                        "id": "service-temp",
                        # Deliberately wrong path: ID selection must still keep this
                        # selected service, but this path grants no membership.
                        "project": "/different/path",
                        "name": "web",
                        "status": "running",
                        "port": 3200,
                        "url": "http://temp.test:3200/?token=secret",
                        "url_is_current": True,
                        "process_usage": {
                            "cpu_percent": 5.5,
                            "memory_bytes": 5_500,
                            "sampled_at": "2026-07-25T12:00:00Z",
                        },
                    },
                    {
                        "id": "service-root",
                        "project": "/repos/root",
                        "name": "root-web",
                        "status": "running",
                    },
                    {
                        "id": "service-outsider",
                        # Deliberately matching the effective path: the old report
                        # selected this row even though the tree excludes its ID.
                        "project": "/repos/temp",
                        "name": "outsider",
                        "status": "running",
                        "port": 7777,
                        "url": "http://outsider.test:7777/",
                        "url_is_current": True,
                    },
                ],
                "docker": {
                    "containers": [
                        {
                            "host_resource_id": "docker-temp",
                            "project": "/wrong/path",
                            "name": "temp-db",
                            "status": "running",
                            "stats": {
                                "cpu_percent": 1.0,
                                "memory_usage_bytes": 1_000,
                                "timestamp": "2026-07-25T12:00:00Z",
                            },
                        },
                        {
                            "host_resource_id": "docker-outsider",
                            "project": "/repos/temp",
                            "name": "outsider",
                            "status": "running",
                        },
                    ]
                },
            },
            "unassigned_resources": [],
            "lifecycle_violations": [],
            "events": [],
        }

    def build(
        self,
        *,
        inventory: dict[str, object] | None = None,
        request: dict[str, object] | None = None,
        action_result: dict[str, object] | None = None,
    ) -> dict[str, object]:
        return build_runtime_report(
            request=request or self.request(),
            session_id="11111111-1111-1111-1111-111111111111",
            family_id="family-root",
            root_repo_id="repo-root",
            effective_repo_id="repo-temp",
            project_kind="temporary",
            inventory=inventory or self.inventory(),
            action_result=action_result or {"ok": True},
        )

    def test_tree_ids_are_the_only_membership_authority(self) -> None:
        report = self.build()
        resources = report["resources"]
        self.assertEqual(
            {item["id"] for item in resources},
            {
                "service-root",
                "service-temp",
                "docker-root",
                "docker-temp",
                "database-temp",
            },
        )
        self.assertNotIn("service-outsider", {item["id"] for item in resources})
        self.assertNotIn("docker-outsider", {item["id"] for item in resources})
        self.assertEqual(
            report["ports"],
            {
                "effective_repo": [3200, 5433],
                "root_repo": [3100, 5432],
                "root_family": [3100, 3200, 5432, 5433],
            },
        )
        self.assertEqual(
            report["domains"],
            {
                "effective_repo": ["127.0.0.1", "temp.test"],
                "root_repo": ["127.0.0.1", "root.test"],
                "root_family": ["127.0.0.1", "root.test", "temp.test"],
            },
        )
        self.assertEqual(report["totals"]["effective_repo"]["memory_bytes"], 6_500)
        self.assertEqual(report["totals"]["root_repo"]["memory_bytes"], 2_000)
        self.assertEqual(report["totals"]["root_family"]["memory_bytes"], 8_500)

    def test_per_resource_usage_is_explicit_and_unknown_is_null(self) -> None:
        report = self.build()
        by_id = {item["id"]: item for item in report["resources"]}
        self.assertEqual(
            by_id["service-temp"]["usage"],
            {
                "coverage": "complete",
                "source": "lineage_filtered_process_usage",
                "cpu_percent": 5.5,
                "memory_bytes": 5_500,
                "sampled_at": "2026-07-25T12:00:00Z",
            },
        )
        self.assertIsNone(by_id["service-root"]["usage"]["cpu_percent"])
        self.assertIsNone(by_id["service-root"]["usage"]["memory_bytes"])
        self.assertEqual(by_id["service-temp"]["usage"]["cpu_percent"], 5.5)
        self.assertEqual(by_id["docker-temp"]["usage"]["cpu_percent"], 1.0)
        self.assertIsNone(by_id["database-temp"]["usage"]["cpu_percent"])
        self.assertEqual(by_id["database-temp"]["ports"], [5433])

    def test_raw_future_or_stale_telemetry_never_fills_partial_current_usage(self) -> None:
        inventory = self.inventory()
        service = inventory["v1_compatibility"]["servers"][0]
        service["process_usage"] = {
            "cpu_percent": 5.5,
            "sampled_at": "2026-07-25T12:00:00Z",
        }
        report = self.build(inventory=inventory)
        usage_row = next(
            item["usage"]
            for item in report["resources"]
            if item["id"] == "service-temp"
        )
        self.assertEqual(usage_row["coverage"], "partial")
        self.assertEqual(usage_row["cpu_percent"], 5.5)
        self.assertIsNone(usage_row["memory_bytes"])
        self.assertNotEqual(usage_row["sampled_at"], "2099-01-01T00:00:00Z")

        service.pop("process_usage")
        report = self.build(inventory=inventory)
        usage_row = next(
            item["usage"]
            for item in report["resources"]
            if item["id"] == "service-temp"
        )
        self.assertEqual(usage_row["coverage"], "unavailable")
        self.assertIsNone(usage_row["sampled_at"])

    def test_complete_resource_usage_that_contradicts_scope_total_is_rejected(self) -> None:
        inventory = self.inventory()
        inventory["v1_compatibility"]["servers"][0]["process_usage"][
            "cpu_percent"
        ] = 55.0
        with self.assertRaisesRegex(RuntimeError, "CPU samples contradict"):
            self.build(inventory=inventory)

    def test_tree_resource_must_resolve_exactly_once(self) -> None:
        inventory = self.inventory()
        inventory["resources"]["servers"].append(
            copy.deepcopy(inventory["resources"]["servers"][1])
        )
        with self.assertRaisesRegex(RuntimeError, "resolves more than once"):
            self.build(inventory=inventory)

        inventory = self.inventory()
        inventory["resources"]["servers"] = [
            item
            for item in inventory["resources"]["servers"]
            if item["server_definition_id"] != "service-temp"
        ]
        with self.assertRaisesRegex(RuntimeError, "does not resolve exactly once"):
            self.build(inventory=inventory)

    def test_tree_resource_cannot_be_duplicated_within_or_across_scopes(self) -> None:
        inventory = self.inventory()
        inventory["repository_trees"][0]["scopes"][1]["server_ids"].append(
            "service-temp"
        )
        with self.assertRaisesRegex(RuntimeError, "claimed more than once"):
            self.build(inventory=inventory)

        inventory = self.inventory()
        inventory["repository_trees"][0]["scopes"][0]["server_ids"].append(
            "service-temp"
        )
        with self.assertRaisesRegex(RuntimeError, "claimed more than once"):
            self.build(inventory=inventory)

    def test_tree_resource_cannot_be_claimed_by_multiple_families(self) -> None:
        inventory = self.inventory()
        inventory["repository_trees"].append(
            {
                "family_id": "family-other",
                "root_repository": {"repo_id": "repo-other"},
                "usage": usage(None, None, 0),
                "scopes": [
                    {
                        "repo_id": "repo-other",
                        "kind": "root",
                        "usage": usage(None, None, 0),
                        "server_ids": ["service-temp"],
                        "container_resource_ids": [],
                        "database_binding_ids": [],
                    }
                ],
            }
        )
        with self.assertRaisesRegex(RuntimeError, "claimed more than once"):
            self.build(inventory=inventory)

    def test_success_without_exact_authoritative_target_is_reported_as_failure(self) -> None:
        inventory = self.inventory()
        inventory["repository_trees"][0]["scopes"][1]["server_ids"] = []
        report = self.build(inventory=inventory, action_result={"ok": True})
        self.assertFalse(report["ok"])
        self.assertEqual(report["classification"], "unclassified_resource")
        self.assertEqual(
            report["evidence"]["reason_code"], "missing_authoritative_resource"
        )

    def test_proved_database_stop_may_retire_the_target_from_the_current_tree(self) -> None:
        inventory = self.inventory()
        inventory["repository_trees"][0]["scopes"][1]["database_binding_ids"] = []
        inventory["resources"]["databases"] = []
        inventory["observations"]["databases"] = []
        inventory["observations"]["docker"][1]["lifecycle"] = "stopped"
        request = self.request(
            action="stop",
            target={"kind": "database_stack", "id": "database-temp"},
        )
        action_result = {
            "ok": True,
            "terminal_state": {
                "proof": "post_observation_inventory",
                "resource_kind": "database_stack",
                "resource_id": "database-temp",
                "observed_state": "stopped",
                "database_available": None,
                "database_resource_count": 0,
                "observation_proof": {
                    "observer_domain": "host-runtime-v2:full-docker",
                    "docker_available": True,
                },
            },
        }

        report = self.build(
            inventory=inventory,
            request=request,
            action_result=action_result,
        )

        self.assertTrue(report["ok"], report)
        self.assertFalse(any(item["id"] == "database-temp" for item in report["resources"]))

    def test_result_defaults_to_failure_without_inventing_missing_membership(self) -> None:
        inventory = self.inventory()
        inventory["repository_trees"][0]["scopes"][1]["server_ids"] = []
        inventory["resources"]["servers"] = [
            item
            for item in inventory["resources"]["servers"]
            if item["server_definition_id"] != "service-temp"
        ]
        request = self.request(
            action="run",
            target={"kind": "service", "id": "service-temp", "name": "web"},
            kill_after_run=True,
        )
        action_result = {
            "started": {
                "id": "service-temp",
                "status": "running",
                "port": 3200,
                "url": "http://temp.test:3200/path?token=do-not-leak",
            },
            "run": {
                "returncode": 9,
                "log_path": (
                    "/private/logs/runtime-run-"
                    "11111111-1111-1111-1111-111111111111.log"
                ),
                "argv": ["/usr/bin/test-runner", "--token", "do-not-leak"],
                "run_argv": ["/usr/bin/test-runner", "--password=do-not-leak"],
                "stdout": "x" * 100_000,
                "stderr": "password=do-not-leak",
                "env": {"SAFE": "visible", "TOKEN": "do-not-leak"},
            },
            "password": "do-not-leak",
            "classification": "crashed_process",
            "error_type": "FixtureFailure",
            "error": (
                "failed --token do-not-leak --password=do-not-leak "
                "TOKEN='do-not-leak' PASSWORD=\"do-not-leak\" "
                "at https://alice:do-not-leak@example.test/log?token=do-not-leak"
            ),
            "diagnostic": "retry --api-key 'do-not-leak' SECRET=do-not-leak",
        }
        report = self.build(
            inventory=inventory, request=request, action_result=action_result
        )
        self.assertFalse(report["ok"])
        self.assertEqual(report["classification"], "crashed_process")
        self.assertFalse(
            any(item["id"] == "service-temp" for item in report["resources"])
        )
        self.assertEqual(
            [
                item
                for item in report["artifacts"]
                if item["resource_kind"] == "run"
            ],
            [
                {
                    "kind": "log",
                    "resource_kind": "run",
                    "resource_id": "11111111-1111-1111-1111-111111111111",
                    "path": (
                        "/private/logs/runtime-run-"
                        "11111111-1111-1111-1111-111111111111.log"
                    ),
                    "href": "/api/runtime/artifacts/run/11111111-1111-1111-1111-111111111111",
                    "source": "runtime_command_capture",
                    "bounds": {
                        "tail_lines": RUNTIME_ARTIFACT_MAX_LINES,
                        "max_bytes": RUNTIME_ARTIFACT_MAX_BYTES,
                    },
                }
            ],
        )
        self.assertFalse(
            any(
                item["resource_id"] == "service-temp"
                for item in report["artifacts"]
            )
        )
        encoded = json.dumps(report, sort_keys=True)
        self.assertNotIn("do-not-leak", encoded)
        self.assertNotIn("x" * 1_000, encoded)
        self.assertEqual(report["result"]["password"], "[redacted]")
        self.assertEqual(report["result"]["error_type"], "FixtureFailure")
        self.assertEqual(report["result"]["classification"], "crashed_process")
        self.assertNotIn("alice", report["result"]["error"])
        self.assertNotIn("?", report["result"]["error"])
        self.assertEqual(report["result"]["run"]["stdout"]["inline"], False)
        self.assertEqual(report["result"]["run"]["stdout"]["bytes"], 100_000)
        self.assertEqual(report["result"]["run"]["env"]["names"], ["SAFE", "TOKEN"])
        self.assertEqual(
            report["result"]["run"]["argv"]["executable"], "test-runner"
        )
        self.assertEqual(report["result"]["run"]["argv"]["argument_count"], 2)
        self.assertNotIn("sha256", report["result"]["run"]["argv"])

    def test_artifacts_include_only_tree_selected_service_logs(self) -> None:
        report = self.build()
        self.assertEqual(
            {(item["resource_id"], item["href"]) for item in report["artifacts"]},
            {
                (
                    "service-root",
                    "/api/runtime/artifacts/service/service-root",
                ),
                (
                    "service-temp",
                    "/api/runtime/artifacts/service/service-temp",
                ),
            },
        )
        self.assertNotIn(
            "outsider.log", json.dumps(report["artifacts"], sort_keys=True)
        )

    def test_supervised_worker_crash_is_returned_with_exact_log_link(self) -> None:
        inventory = self.inventory()
        artifact_id = "22222222-2222-4222-8222-222222222222"
        supervision = {
            "keep_alive": True,
            "desired_state": "running",
            "state": "backoff",
            "breaker": {
                "state": "armed",
                "crash_limit": 10,
                "window_seconds": 300,
                "crash_count_in_window": 1,
            },
            "recent_crashes": [
                {
                    "attempt_id": "attempt-1",
                    "exited_at": "2026-07-25T12:00:00Z",
                    "exit_code": 9,
                    "log": {
                        "artifact_id": artifact_id,
                        "path": f"/private/logs/worker-attempt-{artifact_id}.log",
                        "sha256": "c" * 64,
                    },
                }
            ],
        }
        inventory["resources"]["servers"][1]["supervision"] = supervision
        report = self.build(inventory=inventory)
        worker = next(
            item for item in report["resources"] if item["id"] == "service-temp"
        )
        self.assertEqual(worker["supervision"], supervision)
        artifact = next(
            item
            for item in report["artifacts"]
            if item["resource_kind"] == "worker_attempt"
        )
        self.assertEqual(artifact["resource_id"], artifact_id)
        self.assertEqual(artifact["target_resource_id"], "service-temp")
        self.assertEqual(artifact["attempt_id"], "attempt-1")
        self.assertEqual(
            artifact["href"], f"/api/runtime/artifacts/worker_attempt/{artifact_id}"
        )
        self.assertEqual(report["crashes"]["count"], 1)
        self.assertFalse(report["crashes"]["truncated"])
        self.assertEqual(
            report["crashes"]["items"],
            [
                {
                    "classification": "crash",
                    "resource_kind": "service",
                    "resource_id": "service-temp",
                    "display_name": "web",
                    "attempt_id": "attempt-1",
                    "exit_code": 9,
                    "repo_id": "repo-temp",
                    "event_kind": "worker.crashed",
                    "code": "worker_crashed",
                    "message": "Worker exited unexpectedly",
                    "occurred_at": "2026-07-25T12:00:00Z",
                    "log_evidence": {
                        "availability": "available",
                        "source": "worker_attempt_log",
                        "artifact": artifact,
                    },
                }
            ],
        )

    def test_worker_crash_summary_preserves_truncation_and_missing_log_evidence(self) -> None:
        inventory = self.inventory()
        inventory["resources"]["servers"][1]["supervision"] = {
            "recent_crashes_truncated": True,
            "recent_crashes": [
                {
                    "attempt_id": "attempt-without-log",
                    "exited_at": "2026-07-25T12:00:00Z",
                    "exit_kind": "signal",
                    "exit_signal": 9,
                    "classification": "crash",
                    "crash_event_id": "worker-crash-event",
                    "log": None,
                }
            ],
        }

        report = self.build(inventory=inventory)

        self.assertEqual(report["crashes"]["count"], 1)
        self.assertTrue(report["crashes"]["truncated"])
        crash = report["crashes"]["items"][0]
        self.assertEqual(crash["attempt_id"], "attempt-without-log")
        self.assertEqual(crash["exit_signal"], 9)
        self.assertEqual(crash["crash_event_id"], "worker-crash-event")
        self.assertEqual(
            crash["log_evidence"]["reason_code"],
            "worker_attempt_log_unavailable",
        )

    def test_docker_failure_emits_only_a_session_scoped_diagnostic_link(self) -> None:
        request = self.request(
            action="restart",
            target={"kind": "docker", "id": "docker-temp"},
        )
        report = self.build(
            request=request,
            action_result={
                "ok": False,
                "classification": "docker_action_failed",
                "evidence": {
                    "log_path": (
                        "/private/logs/runtime-diagnostic-"
                        "11111111-1111-1111-1111-111111111111.log"
                    )
                },
            },
        )
        diagnostic = [
            item
            for item in report["artifacts"]
            if item["resource_kind"] == "diagnostic"
        ]
        self.assertEqual(
            diagnostic,
            [
                {
                    "kind": "log",
                    "resource_kind": "diagnostic",
                    "resource_id": "11111111-1111-1111-1111-111111111111",
                    "path": (
                        "/private/logs/runtime-diagnostic-"
                        "11111111-1111-1111-1111-111111111111.log"
                    ),
                    "href": (
                        "/api/runtime/artifacts/diagnostic/"
                        "11111111-1111-1111-1111-111111111111"
                    ),
                    "source": "runtime_failure_diagnostic",
                    "bounds": {
                        "tail_lines": RUNTIME_ARTIFACT_MAX_LINES,
                        "max_bytes": RUNTIME_ARTIFACT_MAX_BYTES,
                    },
                }
            ],
        )
        docker = next(
            item for item in report["resources"] if item["id"] == "docker-temp"
        )
        self.assertEqual(docker["log_evidence"]["availability"], "available")
        self.assertEqual(
            docker["log_evidence"]["artifact"]["href"],
            "/api/runtime/artifacts/diagnostic/11111111-1111-1111-1111-111111111111",
        )
        self.assertEqual(
            report["target_log_evidence"], docker["log_evidence"]
        )

    def test_database_failure_binds_only_the_exact_session_diagnostic(self) -> None:
        request = self.request(
            action="restart",
            target={"kind": "database_stack", "id": "database-temp"},
        )
        report = self.build(
            request=request,
            action_result={
                "ok": False,
                "classification": "database_action_failed",
                "evidence": {
                    "log_path": (
                        "/private/logs/runtime-diagnostic-"
                        "11111111-1111-1111-1111-111111111111.log"
                    )
                },
            },
        )
        database = next(
            item for item in report["resources"] if item["id"] == "database-temp"
        )
        self.assertEqual(database["log_evidence"]["availability"], "available")
        artifact = database["log_evidence"]["artifact"]
        self.assertEqual(artifact["resource_kind"], "diagnostic")
        self.assertEqual(artifact["source"], "runtime_failure_diagnostic")
        self.assertEqual(artifact["bounds"]["tail_lines"], 2_000)
        self.assertEqual(artifact["bounds"]["max_bytes"], 1_048_576)
        self.assertNotIn("database", artifact["href"].split("/artifacts/", 1)[1])

    def test_stopped_docker_and_unavailable_database_report_missing_capture(self) -> None:
        inventory = self.inventory()
        inventory["observations"]["docker"][1]["lifecycle"] = "stopped"
        inventory["observations"]["databases"][0]["available"] = 0
        request = self.request(
            action="status",
            target={"kind": "docker", "id": "docker-temp"},
        )
        report = self.build(
            inventory=inventory,
            request=request,
            action_result={
                "ok": True,
                "ready": False,
                "classification": "observed_not_ready",
            },
        )
        self.assertTrue(report["ok"])
        self.assertFalse(report["ready"])
        self.assertEqual(report["classification"], "observed_not_ready")
        by_id = {item["id"]: item for item in report["resources"]}
        docker_evidence = by_id["docker-temp"]["log_evidence"]
        database_evidence = by_id["database-temp"]["log_evidence"]
        self.assertEqual(docker_evidence["availability"], "unavailable")
        self.assertEqual(
            docker_evidence["reason_code"],
            "authoritative_docker_log_capture_unavailable",
        )
        self.assertEqual(database_evidence["availability"], "unavailable")
        self.assertEqual(
            database_evidence["reason_code"],
            "authoritative_database_log_capture_unavailable",
        )
        self.assertEqual(report["target_log_evidence"], docker_evidence)
        self.assertFalse(
            any(
                item["resource_kind"] in {"docker", "database", "database_stack"}
                for item in report["artifacts"]
            ),
            "status must not invent an on-demand name/path-based artifact",
        )
        self.assertNotIn("href", docker_evidence)
        self.assertNotIn("href", database_evidence)

    def test_exact_typed_docker_capture_replaces_generic_missing_evidence(self) -> None:
        inventory = self.inventory()
        inventory["observations"]["docker"][1]["lifecycle"] = "stopped"
        artifact_id = "44444444-4444-4444-8444-444444444444"
        report = self.build(
            inventory=inventory,
            request=self.request(
                action="status",
                target={"kind": "docker", "id": "docker-temp"},
            ),
            action_result={
                "ok": False,
                "classification": "lifecycle_target_not_ready",
                "_runtime_log_capture": {
                    "availability": "available",
                    "artifact_id": artifact_id,
                    "resource_kind": "docker",
                    "target_resource_id": "docker-temp",
                    "path": f"/private/logs/runtime-docker-{artifact_id}.log",
                    "source": "docker_logs_exact_container",
                    "captured_at": "2026-07-25T12:00:00Z",
                    "truncated": False,
                },
            },
        )
        evidence = report["target_log_evidence"]
        self.assertEqual(evidence["availability"], "available")
        self.assertEqual(
            evidence["artifact"]["href"],
            f"/api/runtime/artifacts/docker/{artifact_id}",
        )
        self.assertEqual(evidence["artifact"]["target_resource_id"], "docker-temp")
        self.assertNotIn("_runtime_log_capture", report["result"])

    def test_arbitrary_failure_log_path_does_not_advertise_an_artifact(self) -> None:
        request = self.request(
            action="restart",
            target={"kind": "docker", "id": "docker-temp"},
        )
        report = self.build(
            request=request,
            action_result={
                "ok": False,
                "classification": "docker_action_failed",
                "evidence": {"log_path": "/private/logs/plausible-container.log"},
            },
        )
        self.assertFalse(
            any(item["resource_kind"] == "diagnostic" for item in report["artifacts"])
        )
        self.assertEqual(
            report["target_log_evidence"]["reason_code"],
            "authoritative_docker_log_capture_unavailable",
        )

    def test_docker_crash_evidence_reuses_only_exact_target_capture(self) -> None:
        inventory = self.inventory()
        inventory["observations"]["docker"][1]["lifecycle"] = "stopped"
        inventory["events"] = [
            {
                "event_id": "docker-crash-1",
                "repo_id": "repo-temp",
                "resource_kind": "container",
                "resource_id": "docker-temp",
                "event_kind": "docker.stopped",
                "code": "docker_crashed",
                "message": "container stopped unexpectedly",
                "occurred_at": "2026-07-25T12:00:00Z",
            }
        ]
        request = self.request(
            action="restart",
            target={"kind": "docker", "id": "docker-temp"},
        )
        report = self.build(
            inventory=inventory,
            request=request,
            action_result={
                "ok": False,
                "classification": "docker_action_failed",
                "evidence": {
                    "log_path": (
                        "/private/logs/runtime-diagnostic-"
                        "11111111-1111-1111-1111-111111111111.log"
                    )
                },
            },
        )
        crash = report["crashes"]["items"][0]
        self.assertEqual(crash["resource_id"], "docker-temp")
        self.assertEqual(crash["log_evidence"]["availability"], "available")
        self.assertEqual(
            crash["log_evidence"]["artifact"]["resource_kind"], "diagnostic"
        )

        report = self.build(
            inventory=inventory,
            request=self.request(
                action="status",
                target={"kind": "docker", "id": "docker-temp"},
            ),
            action_result={"ok": True},
        )
        crash = report["crashes"]["items"][0]
        self.assertEqual(crash["log_evidence"]["availability"], "unavailable")
        self.assertNotIn("artifact", crash["log_evidence"])

    def test_public_docker_crash_without_resource_identity_is_explicitly_unavailable(self) -> None:
        inventory = self.inventory()
        # The current public event projection deliberately omits private
        # diagnostic_json, including its resource ID.  A repo-level crash must
        # not be guessed onto the only similarly named/located container.
        inventory["events"] = [
            {
                "event_id": "docker-crash-public",
                "repo_id": "repo-temp",
                "event_kind": "docker.stopped",
                "code": "docker_crashed",
                "message": "container stopped unexpectedly",
                "occurred_at": "2026-07-25T12:00:00Z",
            }
        ]
        report = self.build(inventory=inventory)
        evidence = report["crashes"]["items"][0]["log_evidence"]
        self.assertEqual(evidence["availability"], "unavailable")
        self.assertEqual(
            evidence["reason_code"], "crash_resource_identity_unavailable"
        )
        self.assertNotIn("artifact", evidence)

    def test_stale_and_crash_evidence_is_family_scoped_and_bounded_with_counts(self) -> None:
        inventory = self.inventory()
        inventory["lifecycle_violations"] = [
            {
                "repo_id": "repo-temp",
                "resource_kind": "server",
                "resource_id": f"stale-{index}",
                "reason_code": "stale_observation",
                "message": f"stale {index}",
                "pid": 10_000 + index,
                "lifecycle": "running",
                "detected_at": "2026-07-25T11:00:00Z",
                "updated_at": "2026-07-25T12:00:00Z",
                "process_fingerprint": "sha256:" + (str(index % 10) * 64),
            }
            for index in range(MAX_EVIDENCE_ITEMS + 7)
        ] + [
            {
                "repo_id": "repo-outsider",
                "resource_kind": "server",
                "resource_id": "foreign-stale",
                "reason_code": "stale_observation",
            }
        ]
        inventory["events"] = [
            {
                "event_id": f"crash-{index}",
                "repo_id": "repo-root",
                "event_kind": "server.stopped",
                "code": "server_crashed",
                "message": f"worker crashed token=secret-{index}",
                "occurred_at": f"2026-07-25T12:{index:02d}:00Z",
            }
            for index in range(MAX_EVIDENCE_ITEMS + 9)
        ] + [
            {
                "event_id": "foreign-crash",
                "repo_id": "repo-outsider",
                "code": "server_crashed",
            },
            {
                "event_id": "normal-stop",
                "repo_id": "repo-root",
                "code": "server_stopped",
            },
            {
                "event_id": "clean-exit",
                "repo_id": "repo-root",
                "code": "process_exited",
            },
        ]
        report = self.build(inventory=inventory)
        self.assertEqual(report["stale_processes"]["count"], MAX_EVIDENCE_ITEMS + 7)
        self.assertEqual(len(report["stale_processes"]["items"]), MAX_EVIDENCE_ITEMS)
        self.assertTrue(report["stale_processes"]["truncated"])
        first_stale = report["stale_processes"]["items"][0]
        self.assertEqual(first_stale["pid"], 10_000)
        self.assertEqual(first_stale["lifecycle"], "running")
        self.assertLessEqual(len(first_stale["process_fingerprint"]), 25)
        self.assertEqual(report["crashes"]["count"], MAX_EVIDENCE_ITEMS + 9)
        self.assertEqual(len(report["crashes"]["items"]), MAX_EVIDENCE_ITEMS)
        self.assertTrue(report["crashes"]["truncated"])
        self.assertNotIn("secret-", json.dumps(report["crashes"], sort_keys=True))

    def test_repository_tree_is_required_instead_of_falling_back_to_paths(self) -> None:
        inventory = self.inventory()
        inventory.pop("repository_trees")
        with self.assertRaisesRegex(RuntimeError, "repository_trees"):
            self.build(inventory=inventory)

    def test_read_only_status_without_session_has_null_run_id_and_no_run_artifact(self) -> None:
        report = build_runtime_report(
            request=self.request(temporary_repo=None),
            session_id=None,
            family_id="family-root",
            root_repo_id="repo-root",
            effective_repo_id="repo-temp",
            project_kind="temporary",
            inventory=self.inventory(),
            action_result={
                "ok": True,
                "log_path": "/private/logs/should-not-be-a-run-artifact.log",
            },
        )
        self.assertIsNone(report["run_id"])
        self.assertFalse(
            any(item["resource_kind"] == "run" for item in report["artifacts"])
        )


if __name__ == "__main__":
    unittest.main()
