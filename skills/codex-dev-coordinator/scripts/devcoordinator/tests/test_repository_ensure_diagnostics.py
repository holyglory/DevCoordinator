from __future__ import annotations

from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
import uuid
from unittest import mock

from devcoordinator import agent_cli
from devcoordinator.broker import (
    AuthorizedBrokerRequest,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    BrokerService,
    PeerCredentials,
    SerializedMutationWriter,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend
from devcoordinator.call_journal import RollingCallJournal, read_call_records
from devcoordinator.store import StoreInvariantError


class _Authorizer:
    def authorize(
        self, peer: PeerCredentials, request: BrokerRequest
    ) -> AuthorizedBrokerRequest:
        return AuthorizedBrokerRequest(peer=peer, request=request)


class _FailingPersistence:
    def __init__(self, error: BaseException) -> None:
        self.error = error
        self.finished: list[tuple[str, str | None, str | None]] = []

    def ensure_repository_enrollment(
        self, authorized: AuthorizedBrokerRequest, *, context: object
    ) -> dict[str, object]:
        del authorized, context
        raise self.error

    def finish_operation(
        self,
        operation_id: str,
        *,
        result: object = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> None:
        del result
        self.finished.append((operation_id, error_code, error_message))


class RepositoryEnsureDiagnosticsTests(unittest.TestCase):
    def _request(self) -> BrokerRequest:
        return BrokerRequest.create(
            account_id="developer",
            project_id="anchor-repository",
            resource_id="anchor-repository",
            operation=BrokerOperation.REPOSITORY_ENSURE,
            operation_id=str(uuid.uuid4()),
            arguments={
                "agent": "codex:task:repository-adoption",
                "canonical_root": "/workspace/new-repository",
                "owner_uid": 1000,
                "project_kind": "primary",
            },
        )

    def _reply(
        self, error: BaseException
    ) -> tuple[BrokerRequest, dict[str, object], _FailingPersistence, list[dict[str, object]]]:
        request = self._request()
        persistence = _FailingPersistence(error)
        backend = object.__new__(StoreBackedMutationBackend)
        backend._persistence = persistence  # type: ignore[attr-defined]
        peer = PeerCredentials(uid=1000, gid=1000, pid=12345)
        with tempfile.TemporaryDirectory(
            prefix="repository-ensure-diagnostic-"
        ) as temporary:
            journal_path = Path(temporary) / "calls.jsonl"
            service = BrokerService(
                _Authorizer(),
                SerializedMutationWriter(backend),
                call_journal=RollingCallJournal(
                    journal_path,
                    max_bytes=16 * 1024,
                    backups=1,
                ),
            )
            with mock.patch(
                "devcoordinator.repository_context.resolve_effective_repository_context",
                return_value=object(),
            ):
                reply = service.reply_for_document(peer, request.to_wire())
            records = list(read_call_records(journal_path, backups=1))
        return request, reply, persistence, records

    def test_constraint_failure_retains_concrete_bounded_cause_and_recovery(self) -> None:
        request, reply, persistence, records = self._reply(
            sqlite3.IntegrityError(
                "UNIQUE constraint failed: broker_repository_enrollments.uid, "
                "broker_repository_enrollments.repo_id"
            )
        )

        self.assertFalse(reply["ok"])
        error = reply["error"]
        self.assertEqual(error["code"], "repository_adoption_constraint_failed")
        self.assertIn("UNIQUE constraint failed", error["message"])
        self.assertIn("fresh operation ID", error["message"])
        self.assertNotIn("inspect", error["message"].lower())
        self.assertLessEqual(len(error["message"]), 512)
        self.assertEqual(
            persistence.finished,
            [(request.operation_id, error["code"], error["message"])],
        )
        terminal = records[-1]
        self.assertEqual(terminal["code"], error["code"])
        self.assertEqual(terminal["message"], error["message"])

        client = agent_cli._failure(
            BrokerError(
                error["code"],
                error["message"],
                operation_id=request.operation_id,
            ),
            mutation_attempted=True,
            operation_id_hint=request.operation_id,
            broker_contacted=True,
            observed_mutation=False,
        )
        self.assertEqual(client["classification"], "repository_bootstrap_failed")
        self.assertEqual(client["message"], error["message"])
        self.assertEqual(client["operation_id"], request.operation_id)
        self.assertEqual(
            client["next_command"], "devcoordinator runtime serve --help"
        )
        self.assertIn("specific authority conflict", client["next_action"])
        self.assertNotIn("inspect logs", client["next_action"].lower())

    def test_store_invariant_failure_is_typed_instead_of_mutation_failed(self) -> None:
        violation = SimpleNamespace(
            code="repository_owner_generation_mismatch",
            detail="owner authority generation does not match repository generation",
        )
        _request, reply, _persistence, _records = self._reply(
            StoreInvariantError([violation])
        )

        error = reply["error"]
        self.assertEqual(error["code"], "repository_adoption_invariant_failed")
        self.assertIn("repository_owner_generation_mismatch", error["message"])
        self.assertIn("Correct the conflicting authority state", error["message"])
        self.assertLessEqual(len(error["message"]), 512)

    def test_unexpected_exception_is_operation_specific_redacted_and_bounded(self) -> None:
        secret = "never-expose-this-value"
        path = "/home/private/developer/repository.sqlite3"
        with self.assertLogs("devcoordinator.broker_backend", level="ERROR"):
            request, reply, persistence, records = self._reply(
                KeyError(f"password={secret} at {path} " + ("x" * 4096))
            )

        error = reply["error"]
        self.assertEqual(error["code"], "repository_adoption_internal_error")
        self.assertIn("failed unexpectedly", error["message"])
        self.assertIn("report this operation ID", error["message"])
        self.assertNotIn(secret, error["message"])
        self.assertNotIn(path, error["message"])
        self.assertNotIn("inspect logs", error["message"].lower())
        self.assertLessEqual(len(error["message"]), 512)
        self.assertEqual(
            persistence.finished,
            [(request.operation_id, error["code"], error["message"])],
        )
        self.assertEqual(records[-1]["code"], error["code"])
        self.assertNotIn(secret, str(records[-1]))
        self.assertNotIn(path, str(records[-1]))


if __name__ == "__main__":
    unittest.main()
