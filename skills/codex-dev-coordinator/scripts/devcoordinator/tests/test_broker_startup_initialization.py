"""Regression coverage for the bounded broker startup transaction."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import devcoordinator.broker_persistence as broker_persistence  # noqa: E402
from devcoordinator.broker_persistence import BrokerPersistence  # noqa: E402
import devcoordinator.store as store_module  # noqa: E402
from devcoordinator.store import (  # noqa: E402
    DEFAULT_MUTATION_SECONDS,
    CoordinatorStore,
)


class _Rows:
    def __init__(self, rows: list[object]) -> None:
        self._rows = rows

    def __iter__(self):
        return iter(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None


class _InitializationConnection:
    def execute(self, statement: str):
        compact = " ".join(statement.split())
        if (
            "SELECT sql FROM sqlite_master" in compact
            and "broker_cleanup_resource_acl" in compact
        ):
            return _Rows([("cleanup.plan",)])
        if "PRAGMA table_info(broker_compose_effective_model_evidence)" in compact:
            return _Rows([{"name": "service_replicas_json"}])
        if (
            "SELECT sql FROM sqlite_master" in compact
            and "broker_compose_acl" in compact
        ):
            return _Rows([("compose.stop compose.restart",)])
        return _Rows([])


class _InitializationStore:
    def __init__(self) -> None:
        self.connection = _InitializationConnection()
        self.transaction_kwargs: dict[str, object] | None = None

    def __enter__(self):
        return self

    def __exit__(self, _type, _value, _traceback) -> bool:
        return False

    @contextmanager
    def immediate_transaction(self, **kwargs):
        self.transaction_kwargs = kwargs
        yield self.connection


class BrokerStartupInitializationTests(unittest.TestCase):
    def test_initialization_uses_a_bounded_startup_specific_budget(self) -> None:
        store = _InitializationStore()
        persistence = BrokerPersistence.__new__(BrokerPersistence)
        persistence._store = lambda: store

        with (
            mock.patch.object(broker_persistence, "BROKER_SCHEMA", "SELECT 1;"),
            mock.patch.object(
                broker_persistence,
                "_migrate_legacy_compose_definition_fingerprints",
            ),
            mock.patch.object(
                broker_persistence,
                "_disable_legacy_unscoped_compose_definitions",
            ),
            mock.patch.object(
                broker_persistence,
                "_disable_unpinned_compose_definitions",
            ),
            mock.patch.object(
                broker_persistence,
                "_disable_unvalidated_effective_compose_definitions",
            ),
            mock.patch.object(
                broker_persistence,
                "_backfill_compose_project_claims",
            ),
        ):
            persistence.initialize()

        self.assertIsNotNone(store.transaction_kwargs)
        assert store.transaction_kwargs is not None
        self.assertEqual(
            store.transaction_kwargs["max_seconds"],
            broker_persistence.BROKER_INITIALIZATION_MAX_SECONDS,
        )
        self.assertGreater(
            broker_persistence.BROKER_INITIALIZATION_MAX_SECONDS,
            DEFAULT_MUTATION_SECONDS,
        )
        self.assertLessEqual(
            broker_persistence.BROKER_INITIALIZATION_MAX_SECONDS,
            60.0,
        )
        self.assertIsNone(store.transaction_kwargs["revision_kind"])
        self.assertFalse(store.transaction_kwargs["check_invariants"])


class MutationInvariantScopeTests(unittest.TestCase):
    def test_short_mutations_skip_only_the_full_foreign_key_scan(self) -> None:
        with tempfile.TemporaryDirectory(prefix="devcoordinator-invariant-scope-") as root:
            database = Path(root) / "coordinator.sqlite3"
            with CoordinatorStore.open(database) as store:
                with mock.patch.object(
                    store_module, "invariant_violations", return_value=[]
                ) as checker:
                    with store.immediate_transaction() as connection:
                        connection.execute("SELECT 1")
                    checker.assert_called_once_with(
                        store.connection, include_foreign_keys=False
                    )

                    checker.reset_mock()
                    self.assertEqual(store.check_invariants(), ())
                    checker.assert_called_once_with(store.connection)
