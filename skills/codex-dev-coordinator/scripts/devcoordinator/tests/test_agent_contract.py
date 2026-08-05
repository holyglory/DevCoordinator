from __future__ import annotations

import json
import unittest
import uuid

from devcoordinator.agent_contract import (
    AgentContractError,
    MAX_AGENT_RESULT_BYTES,
    agent_error_result,
    bounded_text,
    continuation_handle,
    parse_continuation_handle,
    require_agent_result,
)


class AgentContractTests(unittest.TestCase):
    def test_continuations_are_bounded_service_references(self) -> None:
        operation_id = str(uuid.uuid4())
        handle = continuation_handle("operation", operation_id)
        self.assertEqual(
            parse_continuation_handle(handle), ("operation", operation_id)
        )
        self.assertEqual(
            parse_continuation_handle(continuation_handle("run", "run-123")),
            ("run", "run-123"),
        )
        for invalid in (
            "operation:" + operation_id,
            "dc1:operation:not-a-uuid",
            "dc1:run:../run",
            "dc1:unknown:value",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(AgentContractError):
                    parse_continuation_handle(invalid)

    def test_bounded_text_is_single_line_and_deterministic(self) -> None:
        value = "secret-looking\n" + "x" * 2_000
        first = bounded_text(value, maximum_bytes=128)
        second = bounded_text(value, maximum_bytes=128)
        self.assertEqual(first, second)
        self.assertNotIn("\n", first)
        self.assertLessEqual(len(first.encode("utf-8")), 128)
        self.assertIn("truncated sha256:", first)

    def test_result_bound_applies_to_final_serialization(self) -> None:
        accepted = require_agent_result(
            {"schema_version": 1, "ok": True, "value": "small"},
            surface="fixture",
        )
        self.assertTrue(accepted["ok"])
        with self.assertRaises(AgentContractError):
            require_agent_result(
                {"schema_version": 1, "ok": True, "value": "x" * 9_000},
                surface="fixture",
            )

    def test_typed_error_has_replay_and_next_action_context(self) -> None:
        operation_id = str(uuid.uuid4())
        handle = continuation_handle("operation", operation_id)
        result = agent_error_result(
            code="maintenance_in_progress",
            message="wait",
            classification="maintenance",
            phase="transport",
            operation_id=operation_id,
            continuation=handle,
            outcome="uncertain",
            retryable=True,
            retry_after_seconds=5,
            next_command=f"devcoordinator operation follow {handle}",
            next_action=(
                "Follow this exact operation; do not submit a replacement mutation."
            ),
        )
        self.assertFalse(result["ok"])
        self.assertFalse(result["mutation_performed"])
        self.assertEqual(result["outcome"], "uncertain")
        self.assertEqual(result["continuation"], handle)
        self.assertIn("Follow this exact operation", result["next_action"])
        encoded = json.dumps(
            result, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        self.assertLessEqual(len(encoded), MAX_AGENT_RESULT_BYTES)

    def test_contact_and_mutation_fields_distinguish_false_true_and_unknown(self) -> None:
        for broker_contacted in (False, True, None):
            for mutation_performed in (False, True, None):
                with self.subTest(
                    broker_contacted=broker_contacted,
                    mutation_performed=mutation_performed,
                ):
                    result = agent_error_result(
                        code="typed_failure",
                        message="failed",
                        classification="fixture",
                        phase="authority",
                        broker_contacted=broker_contacted,
                        mutation_performed=mutation_performed,
                        next_action="Correct the reported condition and retry.",
                    )
                    self.assertIs(result["broker_contacted"], broker_contacted)
                    self.assertIs(result["mutation_performed"], mutation_performed)
                    self.assertEqual(
                        result["next_action"],
                        "Correct the reported condition and retry.",
                    )

        with self.assertRaises(AgentContractError):
            agent_error_result(
                code="bad",
                message="bad",
                classification="fixture",
                phase="client",
                broker_contacted="no",  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
