from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from devcoordinator.broker import BrokerError, BrokerOperation, BrokerRequest
from devcoordinator.capabilities import (
    CapabilityMismatchError,
    broker_capabilities,
    release_digest,
    validate_client_capabilities,
)


class CapabilityContractTests(unittest.TestCase):
    def test_broker_operation_accepts_only_empty_capability_request(self) -> None:
        request = BrokerRequest.create(
            account_id="account",
            project_id="repo-1",
            resource_id="repo-1",
            operation=BrokerOperation.CAPABILITIES_READ,
            arguments={},
        )
        self.assertEqual(request.operation, BrokerOperation.CAPABILITIES_READ)
        with self.assertRaises(BrokerError) as raised:
            BrokerRequest.create(
                account_id="account",
                project_id="repo-1",
                resource_id="repo-1",
                operation=BrokerOperation.CAPABILITIES_READ,
                arguments={"probe": True},
            )
        self.assertEqual(raised.exception.code, "invalid_arguments")

    def test_capability_document_is_compact_and_conservative(self) -> None:
        document = broker_capabilities(
            protocol_version=1,
            authority_schema_version=13,
            authority_generation="g" * 64,
            active_release_digest="a" * 64,
        )
        self.assertEqual(document["runtime"]["ensure_states"], ["ready", "stopped"])
        self.assertEqual(
            document["tests"]["enqueue_intents"],
            ["change", "checkpoint", "handoff", "release", "manual"],
        )
        self.assertIn("queue-status", document["tests"]["actions"])
        self.assertEqual(document["database"]["actions"], ["backup"])
        self.assertEqual(document["compose"]["actions"], ["recreate-service"])
        self.assertEqual(
            document["image_publication"]["cli"], "devcoordinator-image"
        )
        self.assertTrue(document["runtime"]["operation_replay"])
        self.assertEqual(
            document["storage"]["actions"],
            ["apply", "inventory", "plan", "remove"],
        )
        self.assertEqual(
            document["storage"]["direct_remove_target_kinds"], ["container"]
        )
        self.assertEqual(
            document["storage"]["plan_apply_target_kinds"], ["volume"]
        )
        self.assertEqual(
            document["efficiency"],
            {
                "actions": ["ingest"],
                "schema_version": 1,
                "project_attribution": True,
                "per_account": True,
                "console_projection": True,
            },
        )
        self.assertNotIn("approval_classes", document)
        self.assertNotIn("remove", document["runtime"]["actions"])
        encoded = json.dumps(
            document, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        self.assertLessEqual(len(encoded), 2 * 1024)

    def test_release_digest_prefers_exact_environment_then_immutable_path(self) -> None:
        with mock.patch.dict(
            "os.environ", {"DEVCOORDINATOR_RELEASE_DIGEST": "b" * 64}, clear=False
        ):
            self.assertEqual(release_digest(Path(__file__)), "b" * 64)
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "module.py"
            source.write_text("pass\n", encoding="utf-8")
            with mock.patch.dict("os.environ", {}, clear=True):
                self.assertIsNone(release_digest(source))

    def test_client_handshake_rejects_generation_or_release_drift(self) -> None:
        document = broker_capabilities(
            protocol_version=1,
            authority_schema_version=13,
            authority_generation="generation-1",
            active_release_digest="a" * 64,
        )
        validated = validate_client_capabilities(
            document,
            expected_authority_generation="generation-1",
            client_release_digest="a" * 64,
        )
        self.assertEqual(validated["authority_generation"], "generation-1")
        with self.assertRaises(CapabilityMismatchError) as raised:
            validate_client_capabilities(
                document,
                expected_authority_generation="generation-2",
                client_release_digest="a" * 64,
            )
        self.assertEqual(raised.exception.code, "authority_generation_mismatch")
        with self.assertRaises(CapabilityMismatchError) as raised:
            validate_client_capabilities(
                document,
                expected_authority_generation="generation-1",
                client_release_digest="b" * 64,
            )
        self.assertEqual(raised.exception.code, "release_mismatch")

    def test_client_handshake_rejects_protocol_and_unbounded_documents(self) -> None:
        document = broker_capabilities(
            protocol_version=2,
            authority_schema_version=13,
            authority_generation="generation-1",
        )
        with self.assertRaises(CapabilityMismatchError) as raised:
            validate_client_capabilities(
                document,
                expected_authority_generation="generation-1",
            )
        self.assertEqual(raised.exception.code, "broker_protocol_unsupported")

        oversized = broker_capabilities(
            protocol_version=1,
            authority_schema_version=13,
            authority_generation="generation-1",
        )
        oversized["padding"] = "x" * 4096
        with self.assertRaises(CapabilityMismatchError) as raised:
            validate_client_capabilities(
                oversized,
                expected_authority_generation="generation-1",
            )
        self.assertEqual(raised.exception.code, "capability_reply_too_large")


if __name__ == "__main__":
    unittest.main()
