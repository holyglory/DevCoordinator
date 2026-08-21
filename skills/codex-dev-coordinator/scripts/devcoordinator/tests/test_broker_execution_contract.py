"""Focused v8 execution-identity broker wire tests."""

from __future__ import annotations

import hashlib
import unittest

from devcoordinator.broker import BrokerError, BrokerOperation, BrokerRequest


EXECUTION_ID = "execution-alpha"
SYSTEMD_UNIT = (
    "devcoordinator-test-"
    + hashlib.sha256(EXECUTION_ID.encode("utf-8")).hexdigest()[:32]
    + ".service"
)


def request(
    operation: BrokerOperation, arguments: dict[str, object]
) -> BrokerRequest:
    return BrokerRequest.create(
        account_id="devcoordinator-testd",
        project_id="repo-alpha",
        repository_generation=7,
        resource_id=EXECUTION_ID,
        operation=operation,
        arguments=arguments,
    )


class BrokerExecutionContractTests(unittest.TestCase):
    def test_ticket_descriptor_is_bound_to_execution_resource(self) -> None:
        parsed = request(
            BrokerOperation.TEST_ATTEMPT_TICKET,
            {
                "descriptor": {"execution_id": EXECUTION_ID},
                "launch_timeout_seconds": 30,
            },
        )

        self.assertEqual(
            parsed.arguments["descriptor"], {"execution_id": EXECUTION_ID}
        )
        for descriptor in (
            {"attempt_id": EXECUTION_ID},
            {"execution_id": "execution-substituted"},
        ):
            with self.subTest(descriptor=descriptor), self.assertRaises(
                BrokerError
            ) as raised:
                request(
                    BrokerOperation.TEST_ATTEMPT_TICKET,
                    {
                        "descriptor": descriptor,
                        "launch_timeout_seconds": 30,
                    },
                )
            self.assertEqual(raised.exception.code, "invalid_arguments")

    def test_launch_carries_the_complete_execution_fence(self) -> None:
        arguments = {
            "ticket_id": "ticket-alpha",
            "execution_id": EXECUTION_ID,
            "generation": 1,
            "systemd_unit": SYSTEMD_UNIT,
        }

        parsed = request(BrokerOperation.TEST_ATTEMPT_LAUNCH, arguments)

        self.assertEqual(dict(parsed.arguments), arguments)

    def test_observe_cancel_and_collect_share_one_execution_identity(self) -> None:
        identity = {
            "execution_id": EXECUTION_ID,
            "generation": 1,
            "systemd_unit": SYSTEMD_UNIT,
        }

        status = request(BrokerOperation.TEST_ATTEMPT_STATUS, identity)
        cancel = request(
            BrokerOperation.TEST_ATTEMPT_CANCEL,
            {**identity, "reason": "caller cancelled"},
        )
        collect = request(BrokerOperation.TEST_ATTEMPT_COLLECT, identity)

        self.assertEqual(dict(status.arguments), identity)
        self.assertEqual(
            dict(cancel.arguments), {**identity, "reason": "caller cancelled"}
        )
        self.assertEqual(dict(collect.arguments), identity)

    def test_attempt_and_runtime_aliases_are_rejected(self) -> None:
        legacy_documents = (
            (
                BrokerOperation.TEST_ATTEMPT_LAUNCH,
                {
                    "ticket_id": "ticket-alpha",
                    "attempt_id": EXECUTION_ID,
                    "generation": 1,
                },
            ),
            (
                BrokerOperation.TEST_ATTEMPT_STATUS,
                {"runtime_id": SYSTEMD_UNIT.removesuffix(".service")},
            ),
            (
                BrokerOperation.TEST_ATTEMPT_CANCEL,
                {
                    "runtime_id": SYSTEMD_UNIT.removesuffix(".service"),
                    "reason": "caller cancelled",
                },
            ),
            (
                BrokerOperation.TEST_ATTEMPT_COLLECT,
                {"runtime_id": SYSTEMD_UNIT.removesuffix(".service")},
            ),
        )
        for operation, arguments in legacy_documents:
            with self.subTest(operation=operation.value), self.assertRaises(
                BrokerError
            ) as raised:
                request(operation, arguments)
            self.assertEqual(raised.exception.code, "invalid_arguments")

    def test_generation_is_positive_and_bounded(self) -> None:
        for generation in (True, 0, -1, 1_000_001):
            with self.subTest(generation=generation), self.assertRaises(
                BrokerError
            ) as raised:
                request(
                    BrokerOperation.TEST_ATTEMPT_STATUS,
                    {
                        "execution_id": EXECUTION_ID,
                        "generation": generation,
                        "systemd_unit": SYSTEMD_UNIT,
                    },
                )
            self.assertEqual(raised.exception.code, "invalid_arguments")

    def test_systemd_unit_is_derived_from_execution_identity(self) -> None:
        with self.assertRaises(BrokerError) as raised:
            request(
                BrokerOperation.TEST_ATTEMPT_STATUS,
                {
                    "execution_id": EXECUTION_ID,
                    "generation": 1,
                    "systemd_unit": "devcoordinator-test-substituted.service",
                },
            )

        self.assertEqual(raised.exception.code, "invalid_arguments")

    def test_execution_identity_must_match_resource_id(self) -> None:
        substituted = "execution-substituted"
        substituted_unit = (
            "devcoordinator-test-"
            + hashlib.sha256(substituted.encode("utf-8")).hexdigest()[:32]
            + ".service"
        )
        with self.assertRaises(BrokerError) as raised:
            request(
                BrokerOperation.TEST_ATTEMPT_STATUS,
                {
                    "execution_id": substituted,
                    "generation": 1,
                    "systemd_unit": substituted_unit,
                },
            )

        self.assertEqual(raised.exception.code, "invalid_arguments")


if __name__ == "__main__":
    unittest.main()
