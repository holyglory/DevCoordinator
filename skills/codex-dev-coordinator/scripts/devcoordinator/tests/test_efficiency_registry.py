from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from devcoordinator import agent_cli, efficiency_registry


TOKEN_KEYS = efficiency_registry.TOKEN_KEYS
PHASES = efficiency_registry.PHASES
TOOL_CATEGORIES = efficiency_registry.TOOL_CATEGORIES


def counter(value: str | None = "0", tasks: int = 1) -> dict[str, object]:
    known = tasks if value is not None else 0
    return {
        "known_sum": value,
        "known_task_count": known,
        "task_count": tasks,
        "coverage": "complete" if known == tasks else "unknown",
    }


def summary(*, opportunities: int = 0) -> dict[str, object]:
    phases = {
        phase: {
            **{key: counter("1") for key in TOKEN_KEYS},
            "usage_event_count": 1 if phase == "implementation" else 0,
        }
        for phase in PHASES
    }
    opportunity = {
        "kind": "deterministic-workflow-candidate",
        "task_type": "implementation",
        "scope_size": "small",
        "current_method": "direct",
        "occurrence_count": 3,
        "input_tokens": counter("12", 3),
        "tool_category_counts": {key: 0 for key in TOOL_CATEGORIES},
        "basis": "at least three comparable non-automated terminal declarations",
        "recommendation": "review the repeated sequence for a script, harness, verifier, or reusable tool boundary",
    }
    return {
        "project_id": "id_" + "1" * 32,
        "task_count": 1,
        "complete_task_count": 1,
        "outcomes": {"complete": 1},
        "causes": {"not-applicable": 1},
        "tokens": {key: counter("1") for key in TOKEN_KEYS},
        "tokens_by_phase": phases,
        "request_to_delivery_ns": counter("10"),
        "execution_to_delivery_ns": counter("8"),
        "automation_opportunities": [dict(opportunity) for _ in range(opportunities)],
    }


class EfficiencyRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "accounts"
        self.root.mkdir()
        self.repository_id = "123e4567-e89b-42d3-a456-426614174000"

    def test_parse_and_atomic_publish_replace_one_account_snapshot(self) -> None:
        document = {"schema_version": 1, "summary": summary(opportunities=1)}
        parsed = efficiency_registry.parse_submission(
            json.dumps(document).encode("utf-8")
        )
        first = efficiency_registry.publish(
            repository_id=self.repository_id, summary=parsed, root=self.root
        )
        self.assertTrue(first["ok"])
        destination = (
            self.root
            / first["account_id"]
            / "repositories"
            / f"{self.repository_id}.json"
        )
        stored = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(stored["summary"]["task_count"], 1)
        updated = summary()
        updated["task_count"] = 2
        updated["complete_task_count"] = 1
        efficiency_registry.publish(
            repository_id=self.repository_id, summary=updated, root=self.root
        )
        self.assertEqual(
            json.loads(destination.read_text(encoding="utf-8"))["summary"]["task_count"],
            2,
        )
        self.assertFalse(any(path.name.startswith(".efficiency-") for path in destination.parent.iterdir()))

    def test_private_or_extra_fields_and_oversized_candidates_are_rejected(self) -> None:
        for field in ("repository_path", "prompt", "user_email"):
            invalid = summary()
            invalid[field] = "/home/private/repository"
            with self.assertRaises(efficiency_registry.EfficiencyRegistryError):
                efficiency_registry.validate_repository_summary(invalid)
        with self.assertRaises(efficiency_registry.EfficiencyRegistryError):
            efficiency_registry.validate_repository_summary(summary(opportunities=33))

    def test_unknown_counter_is_not_coerced_to_zero(self) -> None:
        value = summary()
        value["tokens"]["input"] = counter(None)
        normalized = efficiency_registry.validate_repository_summary(value)
        self.assertIsNone(normalized["tokens"]["input"]["known_sum"])
        self.assertEqual(normalized["tokens"]["input"]["coverage"], "unknown")

    def test_symlinked_account_target_is_rejected(self) -> None:
        account = self.root / f"uid-{__import__('os').geteuid()}"
        real = Path(self.temporary.name) / "elsewhere"
        real.mkdir()
        account.symlink_to(real, target_is_directory=True)
        with self.assertRaises(efficiency_registry.EfficiencyRegistryError):
            efficiency_registry.publish(
                repository_id=self.repository_id, summary=summary(), root=self.root
            )

    def test_agent_cli_ingest_is_capability_gated_and_repository_bound(self) -> None:
        namespace = agent_cli._parser().parse_args(
            ["efficiency", "ingest", "--project", "/repository"]
        )
        profile = mock.Mock()
        profile.resolve_repository.return_value = SimpleNamespace(
            repo_id=self.repository_id
        )
        document = {"schema_version": 1, "summary": summary()}
        stdin = mock.Mock()
        stdin.buffer = __import__("io").BytesIO(json.dumps(document).encode("utf-8"))
        published = {
            "schema_version": 1,
            "ok": True,
            "status": "published",
            "repository_id": self.repository_id,
            "account_id": "uid-1000",
        }
        with (
            mock.patch.object(agent_cli, "_repository_context", return_value=mock.Mock()),
            mock.patch.object(
                agent_cli,
                "_profile_and_capabilities",
                return_value=(profile, {"efficiency": {"actions": ["ingest"], "schema_version": 1}}),
            ),
            mock.patch.object(agent_cli.sys, "stdin", stdin),
            mock.patch.object(efficiency_registry, "publish", return_value=published) as publish,
        ):
            result = agent_cli._execute(namespace)
        self.assertEqual(result, published)
        publish.assert_called_once()
        self.assertEqual(publish.call_args.kwargs["repository_id"], self.repository_id)

    def test_agent_cli_does_not_read_submission_without_capability(self) -> None:
        namespace = agent_cli._parser().parse_args(
            ["efficiency", "ingest", "--project", "/repository"]
        )
        stdin = mock.Mock()
        stdin.buffer.read.side_effect = AssertionError("stdin must not be consumed")
        with (
            mock.patch.object(agent_cli, "_repository_context", return_value=mock.Mock()),
            mock.patch.object(
                agent_cli,
                "_profile_and_capabilities",
                return_value=(mock.Mock(), {}),
            ),
            mock.patch.object(agent_cli.sys, "stdin", stdin),
            self.assertRaises(agent_cli.AgentCliError) as raised,
        ):
            agent_cli._execute(namespace)
        self.assertEqual(raised.exception.code, "efficiency_capability_unavailable")


if __name__ == "__main__":
    unittest.main()
