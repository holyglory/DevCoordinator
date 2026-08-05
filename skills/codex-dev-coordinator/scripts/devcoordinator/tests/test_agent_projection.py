from __future__ import annotations

import json
import unittest

from devcoordinator.agent_projection import (
    AgentProjectionError,
    MAX_STATUS_RESULT_BYTES,
    MAX_TARGET_RESULT_BYTES,
    project_runtime_report,
    project_targets,
)


def inventory() -> dict:
    return {
        "repository_trees": [
            {
                "family_id": "family-1",
                "root_repository": {"repo_id": "repo-1"},
                "scopes": [
                    {
                        "repo_id": "repo-1",
                        "kind": "root",
                        "canonical_root": "/repo",
                        "server_ids": ["service-1", "service-2"],
                        "container_resource_ids": ["docker-1"],
                        "database_binding_ids": ["database-1"],
                    }
                ],
            }
        ],
        "resources": {
            "servers": [
                {"server_definition_id": "service-1", "name": "web"},
                {"server_definition_id": "service-2", "name": "worker"},
            ],
            "docker": [
                {"docker_resource_id": "docker-1", "current_name": "postgres"}
            ],
            "databases": [
                {"database_binding_id": "database-1", "database_name": "app"}
            ],
        },
        "observations": {
            "servers": [
                {"server_definition_id": "service-1", "lifecycle": "running"},
                {"server_definition_id": "service-2", "lifecycle": "stopped"},
            ],
            "docker": [{"docker_resource_id": "docker-1", "lifecycle": "running"}],
            "databases": [{"database_binding_id": "database-1", "available": 1}],
        },
    }


class AgentProjectionTests(unittest.TestCase):
    def test_target_projection_binds_unique_name_to_immutable_id(self) -> None:
        result = project_targets(inventory(), effective_root="/repo", selector="web")
        self.assertEqual(result["selected"]["id"], "service-1")
        self.assertTrue(result["selected"]["ready"])
        encoded = json.dumps(result, separators=(",", ":"), sort_keys=True).encode()
        self.assertLessEqual(len(encoded), MAX_TARGET_RESULT_BYTES)

    def test_exact_id_wins_over_display_alias(self) -> None:
        value = inventory()
        value["resources"]["servers"][1]["name"] = "service-1"
        result = project_targets(value, effective_root="/repo", selector="service-1")
        self.assertEqual(result["selected"]["name"], "web")

    def test_ambiguous_names_fail_without_selecting(self) -> None:
        value = inventory()
        value["resources"]["servers"][1]["name"] = "web"
        with self.assertRaises(AgentProjectionError) as raised:
            project_targets(value, effective_root="/repo", selector="web")
        self.assertEqual(raised.exception.code, "target_ambiguous")
        self.assertEqual(len(raised.exception.candidates), 2)

    def test_missing_scope_or_resource_fails_closed(self) -> None:
        with self.assertRaises(AgentProjectionError):
            project_targets(inventory(), effective_root="/other")
        value = inventory()
        value["resources"]["servers"].pop()
        with self.assertRaises(AgentProjectionError):
            project_targets(value, effective_root="/repo")

    def test_runtime_projection_is_small_and_carries_outcome(self) -> None:
        report = {
            "ok": True,
            "action": "status",
            "classification": "ready",
            "ready": True,
            "target": {"kind": "service", "id": "service-1"},
            "result": {"operation_id": "00000000-0000-4000-8000-000000000001"},
            "resources": [
                {
                    "kind": "service",
                    "id": "service-1",
                    "name": "web",
                    "state": "running",
                    "ready": True,
                    "repo_id": "repo-1",
                }
            ],
        }
        projected = project_runtime_report(report)
        self.assertTrue(projected["ok"])
        self.assertEqual(projected["resource"]["id"], "service-1")
        encoded = json.dumps(
            projected, separators=(",", ":"), sort_keys=True
        ).encode()
        self.assertLessEqual(len(encoded), MAX_STATUS_RESULT_BYTES)


if __name__ == "__main__":
    unittest.main()
