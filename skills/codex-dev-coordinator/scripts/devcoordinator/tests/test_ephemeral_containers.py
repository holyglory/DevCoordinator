"""Crash, authorization, and lifecycle tests for broker-owned ephemeral Docker."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
from pathlib import Path
import sqlite3
import stat
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
from typing import Any
from unittest import mock

from devcoordinator.broker import (
    BrokerBackendError,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    PeerCredentials,
)
from devcoordinator.broker_persistence import BrokerPersistence, StoreBackedRequestAcceptor
from devcoordinator.broker_host import (
    EPHEMERAL_DOCKER_LABELS,
    EphemeralDockerContainerTarget,
    LocalBrokerHostMutations,
)
from devcoordinator.ephemeral_secrets import VolatileRunSecretManager
from devcoordinator.ephemeral_containers import EphemeralContainerCoordinator
from devcoordinator.host_observation import commit_host_inventory_observation
from devcoordinator.observer import SingleFlightObserver
from devcoordinator.schema import (
    _upgrade_ephemeral_renewal_journal_to_v8,
    initialize_schema,
)
from devcoordinator.store import AccountStore, CoordinatorStore, utc_timestamp


ACCOUNT = "account-ephemeral"
REPO = "repo-ephemeral"
HOST = "host-ephemeral"
TEMPLATE = "ephemeral-template-artifact-postgres"
IMAGE = "postgres@sha256:" + "a" * 64
FULL_ID = "b" * 64


class FakeClock:
    def __init__(self) -> None:
        self.value = int(time.time())

    def __call__(self) -> int:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += seconds


class FakeEphemeralHost:
    def __init__(
        self,
        *,
        fail_after_create: bool = False,
        fail_without_create: bool = False,
        start_on_create: bool = False,
        full_container_id: str = FULL_ID,
        unsafe_on_inspect: bool = False,
        image_profile_unobservable: bool = False,
        image_cached: bool = True,
    ) -> None:
        self.fail_after_create = fail_after_create
        self.fail_without_create = fail_without_create
        self.start_on_create = start_on_create
        self.full_container_id = full_container_id
        self.unsafe_on_inspect = unsafe_on_inspect
        self.image_profile_unobservable = image_profile_unobservable
        self.image_cached = image_cached
        self.image_cache_proof: dict[str, object] | None = None
        self.image_cache_checks: list[object] = []
        self.image_prefetches: list[object] = []
        self.container: dict[str, object] | None = None
        self.calls: list[str] = []
        self.created_target = None
        self.container_targets: list[EphemeralDockerContainerTarget] = []

    def select_available_port(self, *, candidates: tuple[int, ...], protocol: str):
        self.calls.append("select_port")
        self.assert_protocol = protocol
        return candidates[0] if candidates else None

    def docker_inspect_ephemeral_image(self, target):
        self.image_cache_checks.append(target)
        if self.image_cache_proof is not None:
            return dict(self.image_cache_proof)
        if not self.image_cached:
            return {"cached": False, "image_ref": target.image_ref}
        return {
            "cached": True,
            "image_ref": target.image_ref,
            "image_id": "sha256:" + "c" * 64,
            "repo_digest": target.image_ref,
            "os": "linux",
            "architecture": "amd64",
        }

    def docker_prefetch_ephemeral_image(self, target):
        self.image_prefetches.append(target)
        self.image_cached = True
        return {
            **self.docker_inspect_ephemeral_image(target),
            "cache_origin": "pulled",
            "changed": True,
        }

    def docker_create_ephemeral(self, target):
        self.calls.append("create")
        self.created_target = target
        if self.fail_without_create:
            raise BrokerBackendError(
                "ephemeral_docker_create_failed",
                "injected create failure before a container exists",
            )
        self.container = {
            "identity": target.identity,
            "full_container_id": self.full_container_id,
            "running": self.start_on_create,
            "status": "running" if self.start_on_create else "created",
        }
        if self.fail_after_create:
            raise BrokerBackendError(
                "ephemeral_docker_create_outcome_unknown",
                "injected create reply loss",
            )
        if self.image_profile_unobservable:
            raise BrokerBackendError(
                "ephemeral_image_inspect_unobservable",
                "injected post-create image-proof failure",
            )
        return {
            "full_container_id": self.full_container_id,
            "running": False,
            "status": "created",
        }

    def docker_find_ephemeral(self, identity):
        self.calls.append("find")
        if self.container is None or self.container["identity"] != identity:
            return {"found": False}
        return {
            "found": True,
            "full_container_id": self.container["full_container_id"],
            "running": self.container["running"],
            "status": self.container["status"],
        }

    def docker_start_ephemeral(self, target):
        self.calls.append("start")
        self.container_targets.append(target)
        assert self.container is not None
        assert target.full_container_id == self.container["full_container_id"]
        assert target.identity == self.container["identity"]
        self.container["running"] = True
        self.container["status"] = "running"
        return {
            "full_container_id": target.full_container_id,
            "running": True,
            "status": "running",
        }

    def docker_inspect_ephemeral(self, target):
        self.calls.append("inspect")
        self.container_targets.append(target)
        assert self.container is not None
        assert target.full_container_id == self.container["full_container_id"]
        assert target.identity == self.container["identity"]
        if self.unsafe_on_inspect:
            raise BrokerBackendError(
                "ephemeral_docker_safety_profile_mismatch",
                "injected sealed safety-profile drift",
            )
        if self.image_profile_unobservable:
            raise BrokerBackendError(
                "ephemeral_image_inspect_unobservable",
                "injected image-profile proof failure",
            )
        return {
            "full_container_id": target.full_container_id,
            "running": self.container["running"],
            "status": self.container["status"],
        }

    def docker_stop_ephemeral(self, target):
        self.calls.append("stop")
        self.container_targets.append(target)
        assert self.container is not None
        assert target.full_container_id == self.container["full_container_id"]
        self.container["running"] = False
        self.container["status"] = "exited"
        return {
            "full_container_id": target.full_container_id,
            "running": False,
            "status": "exited",
        }

    def docker_remove_ephemeral(self, target):
        self.calls.append("remove")
        self.container_targets.append(target)
        assert self.container is not None
        assert self.container["running"] is False
        assert target.full_container_id == self.container["full_container_id"]
        self.container = None
        return {"full_container_id": target.full_container_id, "action": "remove"}


class MultiEphemeralHost:
    """Deterministic in-memory Docker boundary for multi-run startup recovery."""

    def __init__(self) -> None:
        self.containers: dict[str, dict[str, object]] = {}
        self.created_targets: dict[str, object] = {}
        self.calls: list[str] = []
        self.image_cache_checks: list[object] = []

    def docker_inspect_ephemeral_image(self, target):
        self.image_cache_checks.append(target)
        return {
            "cached": True,
            "image_ref": target.image_ref,
            "image_id": "sha256:" + "c" * 64,
            "repo_digest": target.image_ref,
            "os": "linux",
            "architecture": "amd64",
        }

    def select_available_port(self, *, candidates: tuple[int, ...], protocol: str):
        self.calls.append("select_port")
        assert protocol == "tcp"
        return candidates[0] if candidates else None

    def docker_create_ephemeral(self, target):
        self.calls.append("create")
        run_id = target.identity.run_id
        full_container_id = f"{len(self.containers) + 1:x}" * 64
        self.created_targets[run_id] = target
        self.containers[run_id] = {
            "identity": target.identity,
            "full_container_id": full_container_id,
            "running": False,
            "status": "created",
        }
        return {
            "full_container_id": full_container_id,
            "running": False,
            "status": "created",
        }

    def docker_find_ephemeral(self, identity):
        self.calls.append("find")
        container = self.containers.get(identity.run_id)
        if container is None or container["identity"] != identity:
            return {"found": False}
        return {
            "found": True,
            "full_container_id": container["full_container_id"],
            "running": container["running"],
            "status": container["status"],
        }

    def docker_inspect_ephemeral(self, target):
        self.calls.append("inspect")
        container = self.containers[target.identity.run_id]
        assert target.full_container_id == container["full_container_id"]
        assert target.identity == container["identity"]
        return {
            "full_container_id": target.full_container_id,
            "running": container["running"],
            "status": container["status"],
        }

    def docker_start_ephemeral(self, target):
        self.calls.append("start")
        container = self.containers[target.identity.run_id]
        assert target.full_container_id == container["full_container_id"]
        assert target.identity == container["identity"]
        container["running"] = True
        container["status"] = "running"
        return {
            "full_container_id": target.full_container_id,
            "running": True,
            "status": "running",
        }

    def docker_stop_ephemeral(self, target):
        self.calls.append("stop")
        container = self.containers[target.identity.run_id]
        assert target.full_container_id == container["full_container_id"]
        container["running"] = False
        container["status"] = "exited"
        return {
            "full_container_id": target.full_container_id,
            "running": False,
            "status": "exited",
        }

    def docker_remove_ephemeral(self, target):
        self.calls.append("remove")
        container = self.containers[target.identity.run_id]
        assert container["running"] is False
        assert target.full_container_id == container["full_container_id"]
        del self.containers[target.identity.run_id]
        return {"full_container_id": target.full_container_id, "action": "remove"}


class UncertainStopHost(FakeEphemeralHost):
    def __init__(self, *, change_before_error: bool) -> None:
        super().__init__()
        self.change_before_error = change_before_error
        self.stop_failure_injected = False

    def docker_stop_ephemeral(self, target):
        if self.stop_failure_injected:
            return super().docker_stop_ephemeral(target)
        self.stop_failure_injected = True
        self.calls.append("stop")
        assert self.container is not None
        assert target.full_container_id == self.container["full_container_id"]
        if self.change_before_error:
            self.container["running"] = False
            self.container["status"] = "exited"
        raise BrokerBackendError(
            "ephemeral_docker_stop_outcome_unknown",
            "injected stop reply loss",
        )


class CallbackAfterCreateHost(FakeEphemeralHost):
    def __init__(self, callback) -> None:
        super().__init__()
        self.callback = callback

    def docker_create_ephemeral(self, target):
        result = super().docker_create_ephemeral(target)
        self.callback()
        return result


class CallbackAfterPortSelectionHost(FakeEphemeralHost):
    def __init__(self, callback) -> None:
        super().__init__()
        self.callback = callback

    def select_available_port(self, *, candidates: tuple[int, ...], protocol: str):
        selected = super().select_available_port(
            candidates=candidates, protocol=protocol
        )
        self.callback(selected)
        return selected


class DelayedAbsenceHost(FakeEphemeralHost):
    """Return successful remove replies without proving absence until released."""

    def __init__(self) -> None:
        super().__init__()
        self.allow_absence = False

    def docker_remove_ephemeral(self, target):
        self.calls.append("remove")
        assert self.container is not None
        assert self.container["running"] is False
        assert target.full_container_id == self.container["full_container_id"]
        if self.allow_absence:
            self.container = None
        return {"full_container_id": target.full_container_id, "action": "remove"}


class DisablingTemplateAfterAttributionCoordinator(EphemeralContainerCoordinator):
    def _record_container(self, run_id, full_container_id, *, accepted=None):
        target = super()._record_container(
            run_id, full_container_id, accepted=accepted
        )
        self._persistence.disable_ephemeral_templates_except(
            repo_id=REPO, template_ids=()
        )
        return target


class CrashAtRenewalCheckpointCoordinator(EphemeralContainerCoordinator):
    """Simulate process death immediately after one durable transition."""

    def __init__(
        self,
        *args: Any,
        crash_phase: str,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._crash_phase = crash_phase

    def _renewal_checkpoint(self, phase: str) -> None:
        if phase == self._crash_phase:
            raise SystemExit(f"injected crash after {phase}")



class EphemeralFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="devcoordinator-ephemeral-", dir=str(Path("/tmp").resolve())
        )
        self.root = Path(self.temporary.name)
        self.database = self.root / "coordinator.sqlite3"
        self.persistence = BrokerPersistence(
            self.database, expected_uid=os.geteuid()
        )
        now = utc_timestamp()
        with CoordinatorStore.open(
            self.database, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO hosts(
                        host_id, machine_fingerprint, platform, hostname,
                        created_at, updated_at
                    ) VALUES (?, 'ephemeral-machine', 'test', 'host', ?, ?)
                    """,
                    (HOST, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (?, ?, ?, 'Ephemeral', 'active', 0, ?, ?)
                    """,
                    (REPO, HOST, str(self.root), now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation, actor, updated_at
                    ) VALUES (?, 'installed', 0, 0, 'test', ?)
                    """,
                    (REPO, now),
                )
                connection.execute(
                    "UPDATE schema_metadata SET migration_state = 'ready' WHERE singleton = 1"
                )
            self.generation = store.metadata.database_generation
        self.persistence.provision_ephemeral_template(
            template_id=TEMPLATE,
            repo_id=REPO,
            name="artifact-postgres",
            image_ref=IMAGE,
            command=("postgres", "-c", "fsync=off"),
            environment={"POSTGRES_HOST_AUTH_METHOD": "trust"},
            default_ttl_seconds=600,
            max_ttl_seconds=3600,
            container_tcp_port=5432,
            host_port_start=55400,
            host_port_end=55410,
            memory_bytes=256 * 1024 * 1024,
            cpu_millis=750,
        )
        self.authorizer = StoreBackedRequestAcceptor(self.persistence)

    def close(self) -> None:
        self.temporary.cleanup()

    def request(
        self,
        operation: BrokerOperation,
        resource_id: str,
        *,
        arguments=None,
        operation_id: str | None = None,
        uid: int | None = None,
        account_id: str = ACCOUNT,
    ):
        normalized_arguments = dict(arguments or {})
        if operation in {
            BrokerOperation.EPHEMERAL_START,
            BrokerOperation.EPHEMERAL_IMAGE_PREFETCH,
            BrokerOperation.EPHEMERAL_RENEW,
            BrokerOperation.EPHEMERAL_FINISH,
        }:
            normalized_arguments.setdefault("agent", "test-agent")
        request = BrokerRequest.create(
            account_id=account_id,
            project_id=REPO,
            resource_id=resource_id,
            operation=operation,
            arguments=normalized_arguments,
            operation_id=operation_id,
            authority_generation=self.generation,
        )
        return self.authorizer.accept(
            PeerCredentials(
                uid=os.geteuid() if uid is None else uid,
                gid=os.getegid(),
                pid=os.getpid(),
            ),
            request,
        )


class EphemeralContainerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = EphemeralFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def _provision_quota_template(
        self,
        *,
        template_id: str = TEMPLATE,
        name: str = "artifact-postgres",
        memory_bytes: int = 256 * 1024 * 1024,
        cpu_millis: int = 750,
        max_concurrent_runs: int = 4,
        max_concurrent_runs_per_uid: int = 2,
        repo_max_active_runs: int = 16,
        repo_memory_budget_bytes: int = 8 * 1024 * 1024 * 1024,
        repo_cpu_budget_millis: int = 16_000,
    ) -> None:
        self.fixture.persistence.provision_ephemeral_template(
            template_id=template_id,
            repo_id=REPO,
            name=name,
            image_ref=IMAGE,
            command=("postgres",),
            default_ttl_seconds=600,
            max_ttl_seconds=3600,
            memory_bytes=memory_bytes,
            cpu_millis=cpu_millis,
            max_concurrent_runs=max_concurrent_runs,
            max_concurrent_runs_per_uid=max_concurrent_runs_per_uid,
            repo_max_active_runs=repo_max_active_runs,
            repo_memory_budget_bytes=repo_memory_budget_bytes,
            repo_cpu_budget_millis=repo_cpu_budget_millis,
        )

    def _provision_postgres_password_file_template(
        self,
        *,
        max_concurrent_runs: int = 4,
        max_concurrent_runs_per_uid: int = 2,
        binding_id: str | None = None,
    ) -> str:
        resolved_binding_id = str(uuid.uuid4()) if binding_id is None else binding_id
        self.fixture.persistence.provision_ephemeral_template(
            template_id=TEMPLATE,
            repo_id=REPO,
            name="artifact-postgres",
            image_ref=IMAGE,
            command=("postgres", "-c", "fsync=off"),
            environment={"POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256"},
            secret_policy_kind="postgres_initdb_password_file_v1",
            secret_binding_id=resolved_binding_id,
            default_ttl_seconds=600,
            max_ttl_seconds=3600,
            container_tcp_port=5432,
            host_port_start=55400,
            host_port_end=55410,
            memory_bytes=256 * 1024 * 1024,
            cpu_millis=750,
            max_concurrent_runs=max_concurrent_runs,
            max_concurrent_runs_per_uid=max_concurrent_runs_per_uid,
        )
        return resolved_binding_id

    def _observe_ephemeral_containers(self, host: MultiEphemeralHost) -> None:
        containers: list[dict[str, object]] = []
        for run_id, target in host.created_targets.items():
            container = host.containers[run_id]
            identity = target.identity
            containers.append(
                {
                    "id": container["full_container_id"],
                    "full_id": container["full_container_id"],
                    "name": target.container_name,
                    "image": target.image_ref,
                    "status": "Up 1 minute",
                    "running": True,
                    "inspection_observable": True,
                    "restart_policy": "no",
                    "labels": dict(
                        zip(
                            EPHEMERAL_DOCKER_LABELS,
                            (
                                identity.run_id,
                                identity.creation_nonce,
                                identity.repository_id,
                                identity.template_id,
                                identity.definition_fingerprint,
                            ),
                        )
                    ),
                    "port_bindings": [],
                    "databases": [],
                }
            )
        sample = {
            "sampled_at": utc_timestamp(),
            "inventory": {
                "servers": [],
                "docker": {"available": True, "containers": containers, "postgres": []},
            },
        }
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store:
            SingleFlightObserver(store).observe(
                host_id=HOST,
                observer_domain="ephemeral-recovery-fence",
                sampler=lambda: sample,
                commit=lambda connection, snapshot_id, observed: commit_host_inventory_observation(
                    connection,
                    snapshot_id,
                    observed,
                    host_id=HOST,
                    coordinator_home=str(self.fixture.root),
                    effective_uid=os.geteuid(),
                ),
            )

    def _event_counts(self, run_id: str) -> dict[str, int]:
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store, store.read_transaction() as connection:
            rows = connection.execute(
                """SELECT event_kind, COUNT(*) AS event_count
                   FROM events
                   WHERE json_extract(diagnostic_json, '$.run_id') = ?
                   GROUP BY event_kind""",
                (run_id,),
            ).fetchall()
        return {str(row["event_kind"]): int(row["event_count"]) for row in rows}

    def _run_and_operation_state(self, operation_id: str) -> tuple[str, str]:
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store, store.read_transaction() as connection:
            row = connection.execute(
                """SELECT run.status AS run_status, operation.status AS operation_status
                   FROM ephemeral_container_runs run
                   JOIN operations operation ON operation.operation_id = run.run_id
                   WHERE run.run_id = ?""",
                (operation_id,),
            ).fetchone()
        self.assertIsNotNone(row)
        return str(row["run_status"]), str(row["operation_status"])

    def test_image_status_is_read_only_and_uses_only_the_sealed_template(self) -> None:
        host = FakeEphemeralHost()
        coordinator = EphemeralContainerCoordinator(self.fixture.persistence, host)

        result = coordinator.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_IMAGE_STATUS, TEMPLATE)
        )

        self.assertTrue(result["cached"])
        self.assertEqual(result["image_ref"], IMAGE)
        self.assertEqual(len(host.image_cache_checks), 1)
        self.assertEqual(host.calls, [])
        with sqlite3.connect(self.fixture.database) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM ephemeral_container_runs").fetchone(),
                (0,),
            )


    def test_cache_miss_and_malformed_proof_stop_before_run_or_secret_work(self) -> None:
        cases = (
            FakeEphemeralHost(image_cached=False),
            FakeEphemeralHost(),
        )
        cases[1].image_cache_proof = {
            "cached": True,
            "image_ref": IMAGE,
            "image_id": "sha256:" + "c" * 64,
            "repo_digest": IMAGE,
            "os": "darwin",
            "architecture": "amd64",
        }
        for host in cases:
            with self.subTest(host=host):
                coordinator = EphemeralContainerCoordinator(
                    self.fixture.persistence, host
                )
                with self.assertRaises(BrokerBackendError):
                    coordinator.execute(
                        self.fixture.request(
                            BrokerOperation.EPHEMERAL_START,
                            TEMPLATE,
                            operation_id=str(uuid.uuid4()),
                        )
                    )
                self.assertNotIn("select_port", host.calls)
                self.assertNotIn("create", host.calls)
                self.assertNotIn("start", host.calls)
        with sqlite3.connect(self.fixture.database) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM ephemeral_container_runs").fetchone(),
                (0,),
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM leases").fetchone(), (0,)
            )


    def test_write_ahead_create_record_start_renew_and_finish(self) -> None:
        host = FakeEphemeralHost()
        coordinator = EphemeralContainerCoordinator(
            self.fixture.persistence, host, reaper_interval_seconds=3600
        )
        start = self.fixture.request(
            BrokerOperation.EPHEMERAL_START,
            TEMPLATE,
            arguments={"ttl_seconds": 900},
        )
        result = coordinator.execute(start)
        run_id = result["run_id"]
        self.assertEqual(result["status"], "running")
        self.assertEqual(result["full_container_id"], FULL_ID)
        self.assertEqual(result["host_port"], 55400)
        self.assertEqual(host.calls[:3], ["select_port", "create", "start"])

        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store, store.read_transaction() as connection:
            row = connection.execute(
                """
                SELECT run.status, run.full_container_id, run.creation_nonce,
                       lease.status AS lease_status
                FROM ephemeral_container_runs run
                JOIN leases lease USING(lease_id)
                WHERE run.run_id = ?
                """,
                (run_id,),
            ).fetchone()
            self.assertEqual(row["status"], "running")
            self.assertEqual(row["full_container_id"], FULL_ID)
            self.assertEqual(row["lease_status"], "active")
            self.assertTrue(row["creation_nonce"])

        status = coordinator.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_STATUS, run_id)
        )
        self.assertEqual(status["ownership"], "precommitted_nonce_and_exact_labels")

        renewed = coordinator.execute(
            self.fixture.request(
                BrokerOperation.EPHEMERAL_RENEW,
                run_id,
                arguments={"ttl_seconds": 1200},
            )
        )
        self.assertEqual(renewed["action"], "renew")

        finished = coordinator.execute(
            self.fixture.request(
                BrokerOperation.EPHEMERAL_FINISH,
                run_id,
                arguments={"reason": "validation complete"},
            )
        )
        self.assertEqual(finished["status"], "cleaned")
        self.assertEqual(host.calls[-3:], ["stop", "remove", "find"])
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store, store.read_transaction() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT status FROM leases WHERE lease_id = ?",
                    ("ephemeral-lease-" + run_id,),
                ).fetchone()[0],
                "released",
            )

    def test_normal_lifecycle_targets_keep_the_persisted_image_ref(self) -> None:
        """Start and cleanup must retain the digest for profile validation."""

        host = FakeEphemeralHost()
        coordinator = EphemeralContainerCoordinator(
            self.fixture.persistence, host, reaper_interval_seconds=3600
        )
        started = coordinator.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
        )
        finished = coordinator.execute(
            self.fixture.request(
                BrokerOperation.EPHEMERAL_FINISH,
                started["run_id"],
                arguments={"reason": "validation complete"},
            )
        )

        self.assertEqual(finished["status"], "cleaned")
        self.assertEqual(
            [target.image_ref for target in host.container_targets],
            [IMAGE, IMAGE, IMAGE],
        )

    def test_typed_secret_policy_uses_private_password_file_and_removes_it_on_finish(
        self,
    ) -> None:
        """A sealed policy is mounted by path only and never retained in SQLite."""

        binding_id = str(uuid.uuid4())
        self.fixture.persistence.provision_ephemeral_template(
            template_id=TEMPLATE,
            repo_id=REPO,
            name="artifact-postgres",
            image_ref=IMAGE,
            command=("postgres", "-c", "fsync=off"),
            environment={"POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256"},
            secret_policy_kind="postgres_initdb_password_file_v1",
            secret_binding_id=binding_id,
            default_ttl_seconds=600,
            max_ttl_seconds=3600,
            container_tcp_port=5432,
            host_port_start=55400,
            host_port_end=55410,
            memory_bytes=256 * 1024 * 1024,
            cpu_millis=750,
        )
        manager = VolatileRunSecretManager(
            runtime_root=self.fixture.root / "runtime",
            expected_uid=os.geteuid(),
        )
        host = FakeEphemeralHost()
        coordinator = EphemeralContainerCoordinator(
            self.fixture.persistence,
            host,
            secret_manager=manager,
            reaper_interval_seconds=3600,
        )

        started = coordinator.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
        )
        self.assertEqual(started["status"], "running")
        self.assertIsNotNone(host.created_target)
        mount = host.created_target.secret_mount
        self.assertIsNotNone(mount)
        assert mount is not None
        self.assertEqual(
            dict(host.created_target.environment)["POSTGRES_PASSWORD_FILE"],
            "/run/devcoordinator-credentials/postgres-initdb-password",
        )
        self.assertEqual(
            stat.S_IMODE(mount.source_directory.stat().st_mode), 0o700
        )
        self.assertEqual(
            stat.S_IMODE((mount.source_directory / "postgres-initdb-password").stat().st_mode),
            0o400,
        )
        state = json.loads(
            (mount.source_directory.parent / "state.json").read_text(encoding="utf-8")
        )
        self.assertNotIn("value", state)
        self.assertNotIn("password", state)
        self.assertEqual(state["policy"], "postgres_initdb_password_file_v1")
        self.assertEqual(state["binding_id"], binding_id)
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store, store.read_transaction() as connection:
            retained = connection.execute(
                """
                SELECT secret_policy_kind, secret_binding_id
                FROM ephemeral_container_runs WHERE run_id = ?
                """,
                (started["run_id"],),
            ).fetchone()
        self.assertEqual(
            tuple(retained), ("postgres_initdb_password_file_v1", binding_id)
        )

        coordinator.execute(
            self.fixture.request(
                BrokerOperation.EPHEMERAL_FINISH,
                started["run_id"],
                arguments={"reason": "credential lifecycle test complete"},
            )
        )
        self.assertFalse(mount.source_directory.parent.exists())

    def test_reboot_missing_policy_material_cleans_running_container_without_regeneration(
        self,
    ) -> None:
        self._provision_postgres_password_file_template()
        issued: list[None] = []

        def password_factory() -> bytes:
            issued.append(None)
            return b"p" * 32

        runtime_root = self.fixture.root / "runtime"
        manager = VolatileRunSecretManager(
            runtime_root=runtime_root,
            expected_uid=os.geteuid(),
            password_factory=password_factory,
        )
        host = FakeEphemeralHost()
        coordinator = EphemeralContainerCoordinator(
            self.fixture.persistence,
            host,
            secret_manager=manager,
            reaper_interval_seconds=3600,
        )
        started = coordinator.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
        )
        self.assertEqual(len(issued), 1)
        host.calls.clear()

        shutil.rmtree(runtime_root)
        recovered_manager = VolatileRunSecretManager(
            runtime_root=runtime_root,
            expected_uid=os.geteuid(),
            password_factory=password_factory,
        )
        recovery_coordinator = EphemeralContainerCoordinator(
            self.fixture.persistence,
            host,
            secret_manager=recovered_manager,
            reaper_interval_seconds=3600,
        )
        recovered = recovery_coordinator.recover_startup()

        self.assertEqual(recovered["attention"], 0)
        self.assertEqual(recovered["run_ids"], [started["run_id"]])
        self.assertEqual(
            recovery_coordinator._target(started["run_id"]).status,
            "cleaned",
        )
        self.assertIsNone(host.container)
        self.assertNotIn("start", host.calls)
        self.assertIn("stop", host.calls)
        self.assertIn("remove", host.calls)
        self.assertEqual(len(issued), 1)
        self.assertFalse(runtime_root.exists())

    def test_startup_fences_every_lost_policy_material_run_before_bounded_recovery(
        self,
    ) -> None:
        """A fifth rebooted run may not leak as ready behind the Docker batch cap."""

        self._provision_postgres_password_file_template(
            max_concurrent_runs=8,
            max_concurrent_runs_per_uid=8,
        )
        clock = FakeClock()
        runtime_root = self.fixture.root / "runtime-many-lost-material"
        manager = VolatileRunSecretManager(
            runtime_root=runtime_root,
            expected_uid=os.geteuid(),
            clock=clock,
            password_factory=lambda: b"p" * 32,
        )
        host = MultiEphemeralHost()
        coordinator = EphemeralContainerCoordinator(
            self.fixture.persistence,
            host,
            secret_manager=manager,
            reaper_interval_seconds=3600,
            clock=clock,
        )
        run_ids = [
            str(
                coordinator.execute(
                    self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
                )["run_id"]
            )
            for _ in range(5)
        ]
        self._observe_ephemeral_containers(host)
        self.assertTrue(
            all(
                coordinator._target(run_id).next_reconcile_at_epoch > clock()
                for run_id in run_ids
            ),
            "must-catch: runs are deliberately not due before socket admission",
        )

        host.calls.clear()
        shutil.rmtree(runtime_root)
        recovering = EphemeralContainerCoordinator(
            self.fixture.persistence,
            host,
            secret_manager=VolatileRunSecretManager(
                runtime_root=runtime_root,
                expected_uid=os.geteuid(),
                clock=clock,
                password_factory=lambda: b"p" * 32,
            ),
            reaper_interval_seconds=3600,
            clock=clock,
        )
        recovered = recovering.recover_startup()

        self.assertEqual(recovered["batch_limit"], 4)
        self.assertEqual(recovered["recovered"], 4)
        self.assertEqual(recovered["deferred"], 1)
        self.assertEqual(recovered["policy_material_fenced"], 5)
        self.assertCountEqual(
            recovered["policy_material_fenced_run_ids"], run_ids
        )
        self.assertNotIn(
            "start",
            host.calls,
            "must-catch: missing material may never restart a policy container",
        )
        deferred = set(run_ids) - set(recovered["run_ids"])
        self.assertEqual(len(deferred), 1)
        deferred_run_id = deferred.pop()
        deferred_target = recovering._target(deferred_run_id)
        self.assertEqual(deferred_target.status, "cleanup_pending")
        self.assertTrue(deferred_target.cleanup_requested)
        self.assertIsNotNone(deferred_target.docker_resource_id)

        for run_id in run_ids:
            public = recovering.execute(
                self.fixture.request(BrokerOperation.EPHEMERAL_STATUS, run_id)
            )
            self.assertNotEqual(
                public["status"],
                "running",
                "must-catch: a lost credential cannot remain publicly ready",
            )

        with AccountStore.open_default(
            self.fixture.root, effective_uid=os.geteuid()
        ) as store:
            inventory = store.inventory_v2()
        resource_id = str(deferred_target.docker_resource_id)
        container = next(
            item
            for item in inventory["v1_compatibility"]["docker"]["containers"]
            if item["host_resource_id"] == resource_id
        )
        observation = next(
            item
            for item in inventory["observations"]["docker"]
            if item["docker_resource_id"] == resource_id
        )
        self.assertEqual(container["status"], "cleanup_pending")
        self.assertEqual(container["host_lifecycle"], "running")
        self.assertEqual(
            container["ephemeral_recovery"]["status"], "cleanup_pending"
        )
        self.assertEqual(observation["lifecycle"], "cleanup_pending")
        self.assertEqual(observation["host_lifecycle"], "running")

    def test_intact_policy_material_survives_controlled_restart_recovery(self) -> None:
        self._provision_postgres_password_file_template()
        issued: list[None] = []

        def password_factory() -> bytes:
            issued.append(None)
            return b"p" * 32

        runtime_root = self.fixture.root / "runtime"
        manager = VolatileRunSecretManager(
            runtime_root=runtime_root,
            expected_uid=os.geteuid(),
            password_factory=password_factory,
        )
        host = FakeEphemeralHost()
        coordinator = EphemeralContainerCoordinator(
            self.fixture.persistence,
            host,
            secret_manager=manager,
            reaper_interval_seconds=3600,
        )
        started = coordinator.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
        )
        host.calls.clear()

        recovery_coordinator = EphemeralContainerCoordinator(
            self.fixture.persistence,
            host,
            secret_manager=VolatileRunSecretManager(
                runtime_root=runtime_root,
                expected_uid=os.geteuid(),
                password_factory=password_factory,
            ),
            reaper_interval_seconds=3600,
        )
        recovered = recovery_coordinator.recover_startup()

        self.assertEqual(recovered["attention"], 0)
        self.assertEqual(recovered["run_ids"], [started["run_id"]])
        self.assertEqual(
            recovery_coordinator._target(started["run_id"]).status,
            "running",
        )
        self.assertEqual(host.calls, ["find", "inspect"])
        self.assertEqual(len(issued), 1)

    def test_policy_renewal_recovers_each_crash_boundary_without_regeneration(
        self,
    ) -> None:
        self._provision_postgres_password_file_template()

        cases = (
            ("durable_prepared", False, "prepared"),
            ("volatile_prepared", False, "prepared"),
            ("durable_committing", True, "committing"),
            ("volatile_committed", True, "committing"),
        )
        for ordinal, (phase, committed, expected_phase) in enumerate(cases, start=1):
            with self.subTest(phase=phase):
                clock = FakeClock()
                issued: list[None] = []

                def password_factory() -> bytes:
                    issued.append(None)
                    return b"p" * 32

                runtime_root = self.fixture.root / f"runtime-{phase}"
                manager = VolatileRunSecretManager(
                    runtime_root=runtime_root,
                    expected_uid=os.geteuid(),
                    password_factory=password_factory,
                )
                host = FakeEphemeralHost(
                    full_container_id=f"{ordinal:x}" * 64
                )
                crashing = CrashAtRenewalCheckpointCoordinator(
                    self.fixture.persistence,
                    host,
                    secret_manager=manager,
                    reaper_interval_seconds=3600,
                    clock=clock,
                    crash_phase=phase,
                )
                started = crashing.execute(
                    self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
                )
                run_id = str(started["run_id"])
                old_expiry = crashing._target(run_id).expires_at_epoch
                renewal = self.fixture.request(
                    BrokerOperation.EPHEMERAL_RENEW,
                    run_id,
                    arguments={"ttl_seconds": 900},
                )
                expected_expiry = clock() + 900

                with self.assertRaises(SystemExit):
                    crashing.execute(renewal)

                interrupted = crashing._target(run_id)
                self.assertEqual(
                    interrupted.credential_renewal_phase, expected_phase
                )
                self.assertEqual(
                    interrupted.credential_renewal_old_expires_at_epoch, old_expiry
                )
                self.assertEqual(
                    interrupted.credential_renewal_new_expires_at_epoch,
                    expected_expiry,
                )
                self.assertEqual(len(issued), 1)
                assert host.created_target is not None
                assert host.created_target.secret_mount is not None
                state_path = (
                    host.created_target.secret_mount.source_directory.parent
                    / "state.json"
                )
                interrupted_state = json.loads(state_path.read_text(encoding="utf-8"))
                if phase == "durable_prepared":
                    self.assertEqual(
                        interrupted_state["expires_at_epoch"], old_expiry
                    )
                    self.assertNotIn("expiry_renewal", interrupted_state)
                elif phase in {"volatile_prepared", "durable_committing"}:
                    self.assertEqual(
                        interrupted_state["expires_at_epoch"], old_expiry
                    )
                    self.assertEqual(
                        interrupted_state["expiry_renewal"],
                        {
                            "old_expires_at_epoch": old_expiry,
                            "new_expires_at_epoch": expected_expiry,
                        },
                    )
                else:
                    self.assertEqual(
                        interrupted_state["expires_at_epoch"], expected_expiry
                    )
                    self.assertNotIn("expiry_renewal", interrupted_state)

                host.calls.clear()
                recovering = EphemeralContainerCoordinator(
                    self.fixture.persistence,
                    host,
                    secret_manager=VolatileRunSecretManager(
                        runtime_root=runtime_root,
                        expected_uid=os.geteuid(),
                        password_factory=password_factory,
                    ),
                    reaper_interval_seconds=3600,
                    clock=clock,
                )
                recovered = recovering.recover_startup()
                self.assertEqual(recovered["attention"], 0)
                self.assertEqual(recovered["run_ids"], [run_id])
                final = recovering._target(run_id)
                self.assertEqual(final.status, "running")
                self.assertEqual(
                    final.expires_at_epoch,
                    expected_expiry if committed else old_expiry,
                )
                self.assertEqual(final.credential_renewal_phase, "none")
                self.assertIsNone(final.credential_renewal_old_expires_at_epoch)
                self.assertIsNone(final.credential_renewal_new_expires_at_epoch)
                self.assertIsNone(final.credential_renewal_operation_id)
                self.assertEqual(host.calls, ["find", "inspect"])
                self.assertEqual(len(issued), 1)

                final_state = json.loads(state_path.read_text(encoding="utf-8"))
                self.assertEqual(
                    final_state["expires_at_epoch"], final.expires_at_epoch
                )
                self.assertNotIn("expiry_renewal", final_state)
                with CoordinatorStore.open(
                    self.fixture.database, expected_uid=os.geteuid()
                ) as store, store.read_transaction() as connection:
                    operation = connection.execute(
                        """
                        SELECT status, result_json, error_code
                        FROM operations WHERE operation_id = ?
                        """,
                        (renewal.request.operation_id,),
                    ).fetchone()
                    lease = connection.execute(
                        "SELECT expires_at FROM leases WHERE lease_id = ?",
                        (final.lease_id,),
                    ).fetchone()
                self.assertIsNotNone(operation)
                self.assertIsNotNone(lease)
                self.assertEqual(
                    str(lease["expires_at"]),
                    utc_timestamp(final.expires_at_epoch),
                )
                if committed:
                    self.assertEqual(operation["status"], "succeeded")
                    self.assertIsNone(operation["error_code"])
                    self.assertEqual(
                        json.loads(str(operation["result_json"]))[
                            "expires_at_epoch"
                        ],
                        expected_expiry,
                    )
                else:
                    self.assertEqual(operation["status"], "failed")
                    self.assertEqual(
                        operation["error_code"], "ephemeral_renewal_interrupted"
                    )
                    self.assertIsNone(operation["result_json"])

                finished = recovering.execute(
                    self.fixture.request(
                        BrokerOperation.EPHEMERAL_FINISH,
                        run_id,
                        arguments={"reason": "crash-window test complete"},
                    )
                )
                self.assertEqual(finished["status"], "cleaned")

    def test_interrupted_policy_renewal_with_missing_material_cleans_without_regeneration(
        self,
    ) -> None:
        self._provision_postgres_password_file_template()
        clock = FakeClock()
        issued: list[None] = []

        def password_factory() -> bytes:
            issued.append(None)
            return b"p" * 32

        runtime_root = self.fixture.root / "runtime-missing-renewal"
        manager = VolatileRunSecretManager(
            runtime_root=runtime_root,
            expected_uid=os.geteuid(),
            password_factory=password_factory,
        )
        host = FakeEphemeralHost()
        crashing = CrashAtRenewalCheckpointCoordinator(
            self.fixture.persistence,
            host,
            secret_manager=manager,
            reaper_interval_seconds=3600,
            clock=clock,
            crash_phase="volatile_prepared",
        )
        started = crashing.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
        )
        renewal = self.fixture.request(
            BrokerOperation.EPHEMERAL_RENEW,
            str(started["run_id"]),
            arguments={"ttl_seconds": 900},
        )
        with self.assertRaises(SystemExit):
            crashing.execute(renewal)
        self.assertEqual(len(issued), 1)

        host.calls.clear()
        shutil.rmtree(runtime_root)
        recovering = EphemeralContainerCoordinator(
            self.fixture.persistence,
            host,
            secret_manager=VolatileRunSecretManager(
                runtime_root=runtime_root,
                expected_uid=os.geteuid(),
                password_factory=password_factory,
            ),
            reaper_interval_seconds=3600,
            clock=clock,
        )
        recovered = recovering.recover_startup()

        self.assertEqual(recovered["attention"], 0)
        self.assertEqual(recovered["run_ids"], [str(started["run_id"])])
        final = recovering._target(str(started["run_id"]))
        self.assertEqual(final.status, "cleaned")
        self.assertEqual(final.credential_renewal_phase, "none")
        self.assertIsNone(final.credential_renewal_operation_id)
        self.assertEqual(len(issued), 1)
        self.assertNotIn("start", host.calls)
        self.assertIn("stop", host.calls)
        self.assertIn("remove", host.calls)
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store, store.read_transaction() as connection:
            operation = connection.execute(
                "SELECT status, error_code FROM operations WHERE operation_id = ?",
                (renewal.request.operation_id,),
            ).fetchone()
        self.assertIsNotNone(operation)
        self.assertEqual(operation["status"], "failed")
        self.assertEqual(operation["error_code"], "secret_delivery_unavailable")


    def test_finish_after_interrupted_renewal_terminalizes_renewal_journal(
        self,
    ) -> None:
        self._provision_postgres_password_file_template()
        clock = FakeClock()
        manager = VolatileRunSecretManager(
            runtime_root=self.fixture.root / "runtime-finish-interrupted-renewal",
            expected_uid=os.geteuid(),
            password_factory=lambda: b"p" * 32,
        )
        host = FakeEphemeralHost()
        crashing = CrashAtRenewalCheckpointCoordinator(
            self.fixture.persistence,
            host,
            secret_manager=manager,
            reaper_interval_seconds=3600,
            clock=clock,
            crash_phase="volatile_prepared",
        )
        started = crashing.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
        )
        run_id = str(started["run_id"])
        renewal = self.fixture.request(
            BrokerOperation.EPHEMERAL_RENEW,
            run_id,
            arguments={"ttl_seconds": 900},
        )
        with self.assertRaises(SystemExit):
            crashing.execute(renewal)

        host.calls.clear()
        finishing = EphemeralContainerCoordinator(
            self.fixture.persistence,
            host,
            secret_manager=manager,
            reaper_interval_seconds=3600,
            clock=clock,
        )
        completed = finishing.execute(
            self.fixture.request(
                BrokerOperation.EPHEMERAL_FINISH,
                run_id,
                arguments={"reason": "operator ended interrupted renewal"},
            )
        )
        self.assertEqual(completed["status"], "cleaned")
        final = finishing._target(run_id)
        self.assertEqual(final.credential_renewal_phase, "none")
        self.assertIsNone(final.credential_renewal_operation_id)
        self.assertIn("stop", host.calls)
        self.assertIn("remove", host.calls)
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store, store.read_transaction() as connection:
            renewal_operation = connection.execute(
                "SELECT status, error_code FROM operations WHERE operation_id = ?",
                (renewal.request.operation_id,),
            ).fetchone()
        self.assertIsNotNone(renewal_operation)
        self.assertEqual(renewal_operation["status"], "failed")
        self.assertEqual(
            renewal_operation["error_code"], "ephemeral_renewal_interrupted"
        )

    def test_cleanup_intent_cancels_each_renewal_journal_before_docker_recovery(
        self,
    ) -> None:
        """A failed Docker find cannot turn cleanup-intended renewal back to running."""

        self._provision_postgres_password_file_template()
        for checkpoint in ("volatile_prepared", "volatile_committed"):
            with self.subTest(checkpoint=checkpoint):
                clock = FakeClock()
                runtime_root = self.fixture.root / f"runtime-cleanup-{checkpoint}"
                manager = VolatileRunSecretManager(
                    runtime_root=runtime_root,
                    expected_uid=os.geteuid(),
                    clock=clock,
                    password_factory=lambda: b"p" * 32,
                )
                host = FakeEphemeralHost(
                    full_container_id=(
                        "c" * 64 if checkpoint == "volatile_prepared" else "d" * 64
                    )
                )
                crashing = CrashAtRenewalCheckpointCoordinator(
                    self.fixture.persistence,
                    host,
                    secret_manager=manager,
                    reaper_interval_seconds=3600,
                    clock=clock,
                    crash_phase=checkpoint,
                )
                started = crashing.execute(
                    self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
                )
                run_id = str(started["run_id"])
                renewal = self.fixture.request(
                    BrokerOperation.EPHEMERAL_RENEW,
                    run_id,
                    arguments={"ttl_seconds": 900},
                )
                with self.assertRaises(SystemExit):
                    crashing.execute(renewal)
                self.assertIn(
                    crashing._target(run_id).credential_renewal_phase,
                    {"prepared", "committing"},
                )

                finish = self.fixture.request(
                    BrokerOperation.EPHEMERAL_FINISH,
                    run_id,
                    arguments={"reason": "operator requested cleanup during renewal"},
                )
                self.assertEqual(
                    self.fixture.persistence.reserve_operation(finish).state,
                    "execute",
                )
                crashing._prepare_cleanup(
                    finish, reason="operator requested cleanup during renewal"
                )
                host.calls.clear()
                recovering = EphemeralContainerCoordinator(
                    self.fixture.persistence,
                    host,
                    secret_manager=VolatileRunSecretManager(
                        runtime_root=runtime_root,
                        expected_uid=os.geteuid(),
                        clock=clock,
                        password_factory=lambda: b"p" * 32,
                    ),
                    reaper_interval_seconds=3600,
                    clock=clock,
                )
                with (
                    self.assertLogs(
                        "devcoordinator.ephemeral_containers", level="ERROR"
                    ),
                    mock.patch.object(
                        host,
                        "docker_find_ephemeral",
                        side_effect=BrokerBackendError(
                            "ephemeral_docker_find_unobservable",
                            "injected Docker-find outage",
                        ),
                    ),
                ):
                    recovered = recovering.recover_startup()

                self.assertEqual(recovered["attention_run_ids"], [run_id])
                fenced = recovering._target(run_id)
                self.assertNotEqual(
                    fenced.status,
                    "running",
                    "must-catch: cleanup intent may not republish a renewal as ready",
                )
                self.assertTrue(fenced.cleanup_requested)
                self.assertEqual(fenced.credential_renewal_phase, "none")
                self.assertIsNone(fenced.credential_renewal_old_expires_at_epoch)
                self.assertIsNone(fenced.credential_renewal_new_expires_at_epoch)
                self.assertIsNone(fenced.credential_renewal_operation_id)
                self.assertNotIn("start", host.calls)
                with CoordinatorStore.open(
                    self.fixture.database, expected_uid=os.geteuid()
                ) as store, store.read_transaction() as connection:
                    renewal_operation = connection.execute(
                        "SELECT status, error_code FROM operations WHERE operation_id = ?",
                        (renewal.request.operation_id,),
                    ).fetchone()
                    finish_operation = connection.execute(
                        "SELECT status FROM operations WHERE operation_id = ?",
                        (finish.request.operation_id,),
                    ).fetchone()
                self.assertEqual(renewal_operation["status"], "failed")
                self.assertEqual(
                    renewal_operation["error_code"], "ephemeral_renewal_interrupted"
                )
                self.assertEqual(
                    finish_operation["status"],
                    "running",
                    "must-catch: failed Docker observation must retain cleanup intent",
                )

                clock.advance(16)
                completed = recovering.reap_once()
                self.assertEqual(completed["run_ids"], [run_id])
                self.assertEqual(recovering._target(run_id).status, "cleaned")
                self.assertNotIn("start", host.calls)


    def test_typed_secret_policy_rejects_trust_or_non_scram_init_configuration(
        self,
    ) -> None:
        def provision(environment: dict[str, str]) -> None:
            self.fixture.persistence.provision_ephemeral_template(
                template_id=TEMPLATE,
                repo_id=REPO,
                name="artifact-postgres",
                image_ref=IMAGE,
                command=("postgres",),
                environment=environment,
                secret_policy_kind="postgres_initdb_password_file_v1",
                secret_binding_id=str(uuid.uuid4()),
                default_ttl_seconds=600,
                max_ttl_seconds=3600,
                memory_bytes=256 * 1024 * 1024,
                cpu_millis=750,
            )

        for environment, label in (
            ({}, "missing initdb configuration"),
            (
                {
                    "POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256",
                    "POSTGRES_HOST_AUTH_METHOD": "trust",
                },
                "trust override",
            ),
            ({"POSTGRES_INITDB_ARGS": "--auth-host=md5"}, "non-SCRAM initdb"),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, "SCRAM|auth method"):
                    provision(environment)

    def test_create_reply_loss_is_attributed_afterwards_by_nonce_and_labels(self) -> None:
        host = FakeEphemeralHost(fail_after_create=True, start_on_create=True)
        coordinator = EphemeralContainerCoordinator(
            self.fixture.persistence, host, reaper_interval_seconds=3600
        )
        operation_id = str(uuid.uuid4())
        authorized = self.fixture.request(
            BrokerOperation.EPHEMERAL_START,
            TEMPLATE,
            operation_id=operation_id,
        )
        with self.assertRaises(BrokerBackendError) as caught:
            coordinator.execute(authorized)
        self.assertEqual(caught.exception.code, "operation_outcome_uncertain")
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store, store.read_transaction() as connection:
            before = connection.execute(
                "SELECT status, full_container_id FROM ephemeral_container_runs WHERE run_id = ?",
                (operation_id,),
            ).fetchone()
            self.assertEqual(before["status"], "needs_attention")
            self.assertIsNone(before["full_container_id"])

        recovered = coordinator.recover_startup()
        self.assertEqual(recovered["run_ids"], [operation_id])
        status = coordinator.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_STATUS, operation_id)
        )
        self.assertEqual(status["status"], "running")
        self.assertEqual(status["full_container_id"], FULL_ID)
        disposition = self.fixture.persistence.existing_operation_disposition(authorized)
        self.assertIsNotNone(disposition)
        self.assertEqual(disposition.state, "completed")

    def test_unobservable_post_create_image_proof_removes_labeled_container(
        self,
    ) -> None:
        """A failed image proof after create must converge on identity-only cleanup."""

        host = FakeEphemeralHost(image_profile_unobservable=True)
        coordinator = EphemeralContainerCoordinator(
            self.fixture.persistence, host, reaper_interval_seconds=3600
        )
        operation_id = str(uuid.uuid4())
        authorized = self.fixture.request(
            BrokerOperation.EPHEMERAL_START,
            TEMPLATE,
            operation_id=operation_id,
        )

        with self.assertRaises(BrokerBackendError) as caught:
            coordinator.execute(authorized)
        self.assertEqual(caught.exception.code, "operation_outcome_uncertain")
        before = coordinator._target(operation_id)
        self.assertEqual(before.status, "needs_attention")
        self.assertIsNone(before.full_container_id)

        recovered = coordinator.recover_startup()

        self.assertEqual(recovered["run_ids"], [operation_id])
        self.assertEqual(coordinator._target(operation_id).status, "cleaned")
        self.assertIsNone(host.container)
        self.assertEqual(host.calls.count("start"), 0)
        self.assertIn("inspect", host.calls)
        self.assertEqual(host.calls[-1], "find")
        disposition = self.fixture.persistence.existing_operation_disposition(
            authorized
        )
        self.assertIsNotNone(disposition)
        assert disposition is not None
        self.assertEqual(disposition.state, "failed")
        self.assertEqual(
            disposition.error_code, "ephemeral_image_inspect_unobservable"
        )

    def _assert_cleanup_recovers_after_uncertain_stop(
        self, *, change_before_error: bool
    ) -> None:
        clock = FakeClock()
        host = UncertainStopHost(change_before_error=change_before_error)
        coordinator = EphemeralContainerCoordinator(
            self.fixture.persistence,
            host,
            reaper_interval_seconds=3600,
            clock=clock,
        )
        started = coordinator.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
        )
        finish = self.fixture.request(
            BrokerOperation.EPHEMERAL_FINISH,
            started["run_id"],
            arguments={"reason": "validation complete"},
        )

        with self.assertRaises(BrokerBackendError) as caught:
            coordinator.execute(finish)
        self.assertEqual(caught.exception.code, "operation_outcome_uncertain")
        pending = self.fixture.persistence.existing_operation_disposition(finish)
        self.assertIsNotNone(pending)
        self.assertEqual(pending.state, "pending")
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store, store.read_transaction() as connection:
            uncertain = connection.execute(
                """
                SELECT status, cleanup_requested, cleanup_reason
                FROM ephemeral_container_runs WHERE run_id = ?
                """,
                (started["run_id"],),
            ).fetchone()
            self.assertEqual(uncertain["status"], "needs_attention")
            self.assertEqual(uncertain["cleanup_requested"], 1)
            self.assertEqual(uncertain["cleanup_reason"], "validation complete")

        clock.advance(16)
        recovered = coordinator.reap_once()
        self.assertEqual(recovered["run_ids"], [started["run_id"]])
        completed = self.fixture.persistence.existing_operation_disposition(finish)
        self.assertIsNotNone(completed)
        self.assertEqual(completed.state, "completed")
        self.assertIsNone(host.container)
        self.assertEqual(host.calls[-1], "find")
        self.assertEqual(
            host.calls.count("start"),
            1,
            "cleanup recovery must never restart a run after Finish",
        )
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store, store.read_transaction() as connection:
            cleaned = connection.execute(
                """
                SELECT status, cleanup_requested
                FROM ephemeral_container_runs WHERE run_id = ?
                """,
                (started["run_id"],),
            ).fetchone()
            self.assertEqual(cleaned["status"], "cleaned")
            self.assertEqual(cleaned["cleanup_requested"], 1)

    def test_cleanup_intent_survives_stop_failure_before_host_change(self) -> None:
        self._assert_cleanup_recovers_after_uncertain_stop(change_before_error=False)

    def test_cleanup_intent_survives_stop_failure_after_host_change(self) -> None:
        self._assert_cleanup_recovers_after_uncertain_stop(change_before_error=True)

    def test_recovery_removes_running_container_with_safety_profile_drift(self) -> None:
        clock = FakeClock()
        host = FakeEphemeralHost()
        coordinator = EphemeralContainerCoordinator(
            self.fixture.persistence,
            host,
            reaper_interval_seconds=3600,
            clock=clock,
        )
        started = coordinator.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
        )
        host.unsafe_on_inspect = True
        clock.advance(61)

        recovered = coordinator.reap_once()
        self.assertEqual(recovered["run_ids"], [started["run_id"]])
        self.assertIsNone(host.container)
        self.assertIn("inspect", host.calls)
        self.assertEqual(host.calls.count("start"), 1)
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store, store.read_transaction() as connection:
            row = connection.execute(
                """
                SELECT status, cleanup_requested, cleanup_reason
                FROM ephemeral_container_runs WHERE run_id = ?
                """,
                (started["run_id"],),
            ).fetchone()
            self.assertEqual(row["status"], "cleaned")
            self.assertEqual(row["cleanup_requested"], 1)
            self.assertIn("safety profile", row["cleanup_reason"])

    def test_post_create_ttl_expiry_preserves_exact_start_failure(self) -> None:
        clock = FakeClock()
        host = CallbackAfterCreateHost(lambda: clock.advance(61))
        coordinator = EphemeralContainerCoordinator(
            self.fixture.persistence, host, clock=clock
        )
        authorized = self.fixture.request(
            BrokerOperation.EPHEMERAL_START,
            TEMPLATE,
            arguments={"ttl_seconds": 60},
        )
        with self.assertRaises(BrokerBackendError) as caught:
            coordinator.execute(authorized)
        self.assertEqual(caught.exception.code, "ephemeral_start_deadline_expired")
        replay = self.fixture.persistence.existing_operation_disposition(authorized)
        self.assertIsNotNone(replay)
        self.assertEqual(replay.state, "failed")
        self.assertEqual(replay.error_code, "ephemeral_start_deadline_expired")
        self.assertIsNone(host.container)

    def test_post_create_template_disable_preserves_exact_start_failure(self) -> None:
        host = FakeEphemeralHost()
        coordinator = DisablingTemplateAfterAttributionCoordinator(
            self.fixture.persistence, host
        )
        authorized = self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
        with self.assertRaises(BrokerBackendError) as caught:
            coordinator.execute(authorized)
        self.assertEqual(
            caught.exception.code, "ephemeral_start_no_longer_permitted"
        )
        replay = self.fixture.persistence.existing_operation_disposition(authorized)
        self.assertIsNotNone(replay)
        self.assertEqual(replay.state, "failed")
        self.assertEqual(
            replay.error_code, "ephemeral_start_no_longer_permitted"
        )
        self.assertIsNone(host.container)

    def test_over_max_ttl_terminalizes_without_creating_a_run(self) -> None:
        host = FakeEphemeralHost()
        coordinator = EphemeralContainerCoordinator(self.fixture.persistence, host)
        operation_id = str(uuid.uuid4())
        authorized = self.fixture.request(
            BrokerOperation.EPHEMERAL_START,
            TEMPLATE,
            operation_id=operation_id,
            arguments={"ttl_seconds": 3601},
        )

        with self.assertRaises(BrokerError) as caught:
            coordinator.execute(authorized)
        self.assertEqual(caught.exception.code, "ttl_policy_denied")
        disposition = self.fixture.persistence.existing_operation_disposition(
            authorized
        )
        self.assertIsNotNone(disposition)
        self.assertEqual(disposition.state, "failed")
        self.assertEqual(disposition.error_code, "ttl_policy_denied")
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store, store.read_transaction() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM ephemeral_container_runs WHERE run_id = ?",
                    (operation_id,),
                ).fetchone()[0],
                0,
            )
        self.assertEqual(host.calls, [])

        with self.assertRaises(BrokerBackendError) as replayed:
            coordinator.execute(authorized)
        self.assertEqual(replayed.exception.code, "ttl_policy_denied")

    def test_expired_run_cannot_renew_and_replays_the_same_failure(self) -> None:
        clock = FakeClock()
        host = FakeEphemeralHost()
        coordinator = EphemeralContainerCoordinator(
            self.fixture.persistence, host, clock=clock
        )
        started = coordinator.execute(
            self.fixture.request(
                BrokerOperation.EPHEMERAL_START,
                TEMPLATE,
                arguments={"ttl_seconds": 60},
            )
        )
        clock.advance(60)
        renewal = self.fixture.request(
            BrokerOperation.EPHEMERAL_RENEW,
            started["run_id"],
            arguments={"ttl_seconds": 60},
        )

        with self.assertRaises(BrokerError) as caught:
            coordinator.execute(renewal)
        self.assertEqual(caught.exception.code, "ephemeral_run_expired")
        with self.assertRaises(BrokerBackendError) as replayed:
            coordinator.execute(renewal)
        self.assertEqual(replayed.exception.code, "ephemeral_run_expired")
        disposition = self.fixture.persistence.existing_operation_disposition(
            renewal
        )
        self.assertIsNotNone(disposition)
        self.assertEqual(disposition.state, "failed")
        self.assertEqual(disposition.error_code, "ephemeral_run_expired")
        self.assertEqual(host.calls.count("start"), 1)

    def test_missing_exact_lease_cannot_renew_and_replays_the_same_failure(self) -> None:
        host = FakeEphemeralHost()
        coordinator = EphemeralContainerCoordinator(self.fixture.persistence, host)
        started = coordinator.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
        )
        now = utc_timestamp()
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store, store.immediate_transaction() as connection:
            connection.execute(
                """
                UPDATE leases SET status = 'released', deactivated_at = ?, updated_at = ?
                WHERE lease_id = ?
                """,
                (now, now, "ephemeral-lease-" + started["run_id"]),
            )
        renewal = self.fixture.request(
            BrokerOperation.EPHEMERAL_RENEW,
            started["run_id"],
            arguments={"ttl_seconds": 60},
        )

        with self.assertRaises(BrokerError) as caught:
            coordinator.execute(renewal)
        self.assertEqual(caught.exception.code, "ephemeral_lease_invariant_failed")
        with self.assertRaises(BrokerBackendError) as replayed:
            coordinator.execute(renewal)
        self.assertEqual(
            replayed.exception.code, "ephemeral_lease_invariant_failed"
        )
        disposition = self.fixture.persistence.existing_operation_disposition(
            renewal
        )
        self.assertIsNotNone(disposition)
        self.assertEqual(disposition.state, "failed")
        self.assertEqual(
            disposition.error_code, "ephemeral_lease_invariant_failed"
        )

    def test_run_seals_template_max_ttl_against_later_expansion(self) -> None:
        host = FakeEphemeralHost()
        coordinator = EphemeralContainerCoordinator(self.fixture.persistence, host)
        started = coordinator.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
        )
        self.fixture.persistence.provision_ephemeral_template(
            template_id=TEMPLATE,
            repo_id=REPO,
            name="artifact-postgres",
            image_ref=IMAGE,
            command=("postgres", "-c", "fsync=off"),
            environment={"POSTGRES_HOST_AUTH_METHOD": "trust"},
            default_ttl_seconds=600,
            max_ttl_seconds=7200,
            container_tcp_port=5432,
            host_port_start=55400,
            host_port_end=55410,
            memory_bytes=256 * 1024 * 1024,
            cpu_millis=750,
        )
        renewal = self.fixture.request(
            BrokerOperation.EPHEMERAL_RENEW,
            started["run_id"],
            arguments={"ttl_seconds": 4000},
        )

        with self.assertRaises(BrokerError) as caught:
            coordinator.execute(renewal)
        self.assertEqual(caught.exception.code, "ttl_policy_denied")
        with self.assertRaises(BrokerBackendError) as replayed:
            coordinator.execute(renewal)
        self.assertEqual(replayed.exception.code, "ttl_policy_denied")
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store, store.read_transaction() as connection:
            sealed = connection.execute(
                "SELECT max_ttl_seconds FROM ephemeral_container_runs WHERE run_id = ?",
                (started["run_id"],),
            ).fetchone()[0]
        self.assertEqual(sealed, 3600)

    def test_port_claim_race_fails_run_and_operation_before_docker(self) -> None:
        operation_id = str(uuid.uuid4())

        def claim_selected_port(selected_port: int | None) -> None:
            self.assertIsNotNone(selected_port)
            now = utc_timestamp()
            with CoordinatorStore.open(
                self.fixture.database, expected_uid=os.geteuid()
            ) as store, store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO port_assignments(
                        assignment_id, host_id, repo_id, server_name, port,
                        status, generation, created_at, updated_at
                    ) VALUES (?, ?, ?, 'concurrent-owner', ?, 'active', 0, ?, ?)
                    """,
                    (str(uuid.uuid4()), HOST, REPO, selected_port, now, now),
                )

        host = CallbackAfterPortSelectionHost(claim_selected_port)
        coordinator = EphemeralContainerCoordinator(self.fixture.persistence, host)
        authorized = self.fixture.request(
            BrokerOperation.EPHEMERAL_START,
            TEMPLATE,
            operation_id=operation_id,
        )

        with self.assertRaises(BrokerError) as caught:
            coordinator.execute(authorized)
        self.assertEqual(caught.exception.code, "port_unavailable")
        self.assertEqual(host.calls, ["select_port"])
        self.assertEqual(
            self._run_and_operation_state(operation_id), ("failed", "failed")
        )
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store, store.read_transaction() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM leases WHERE purpose = ? AND status = 'active'",
                    ("ephemeral:" + operation_id,),
                ).fetchone()[0],
                0,
            )
        self.assertEqual(self._event_counts(operation_id).get("ephemeral.failed"), 1)

        with self.assertRaises(BrokerBackendError) as replayed:
            coordinator.execute(authorized)
        self.assertEqual(replayed.exception.code, "port_unavailable")
        self.assertEqual(self._event_counts(operation_id).get("ephemeral.failed"), 1)

    def test_all_pending_finish_operations_complete_only_after_exact_absence(self) -> None:
        clock = FakeClock()
        host = DelayedAbsenceHost()
        coordinator = EphemeralContainerCoordinator(
            self.fixture.persistence,
            host,
            clock=clock,
            reaper_interval_seconds=3600,
        )
        started = coordinator.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
        )
        finishes = tuple(
            self.fixture.request(
                BrokerOperation.EPHEMERAL_FINISH,
                started["run_id"],
                arguments={"reason": f"finish request {index}"},
            )
            for index in range(2)
        )
        for finish in finishes:
            with self.assertRaises(BrokerBackendError) as caught:
                coordinator.execute(finish)
            self.assertEqual(caught.exception.code, "operation_outcome_uncertain")
            disposition = self.fixture.persistence.existing_operation_disposition(
                finish
            )
            self.assertIsNotNone(disposition)
            self.assertEqual(disposition.state, "pending")
        self.assertIsNotNone(host.container)
        self.assertEqual(
            self._event_counts(started["run_id"]).get("ephemeral.cleaned", 0), 0
        )

        host.allow_absence = True
        clock.advance(31)
        recovered = coordinator.reap_once()
        self.assertEqual(recovered["run_ids"], [started["run_id"]])
        self.assertIsNone(host.container)
        for finish in finishes:
            disposition = self.fixture.persistence.existing_operation_disposition(
                finish
            )
            self.assertIsNotNone(disposition)
            self.assertEqual(disposition.state, "completed")
            self.assertEqual(disposition.result["status"], "cleaned")
        self.assertEqual(
            self._event_counts(started["run_id"]).get("ephemeral.cleaned"), 1
        )

    def test_disabled_template_retains_existing_run_lifecycle(self) -> None:
        clock = FakeClock()
        host = FakeEphemeralHost()
        coordinator = EphemeralContainerCoordinator(
            self.fixture.persistence,
            host,
            clock=clock,
            reaper_interval_seconds=3600,
        )
        started = coordinator.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
        )
        self.fixture.persistence.disable_ephemeral_templates_except(
            repo_id=REPO, template_ids=()
        )
        status = coordinator.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_STATUS, started["run_id"])
        )
        self.assertEqual(status["status"], "running")
        renewed = coordinator.execute(
            self.fixture.request(
                BrokerOperation.EPHEMERAL_RENEW,
                started["run_id"],
                arguments={"ttl_seconds": 60},
            )
        )
        self.assertEqual(renewed["status"], "running")

        finished = coordinator.execute(
            self.fixture.request(
                BrokerOperation.EPHEMERAL_FINISH,
                started["run_id"],
                arguments={"reason": "caller confirms cleanup"},
            )
        )
        self.assertEqual(finished["status"], "cleaned")
        self.assertTrue(finished["changed"])
        self.assertIsNone(host.container)

    def test_external_disappearance_crashes_once_cleans_and_never_restarts(self) -> None:
        clock = FakeClock()
        host = FakeEphemeralHost()
        coordinator = EphemeralContainerCoordinator(
            self.fixture.persistence,
            host,
            clock=clock,
            reaper_interval_seconds=3600,
        )
        started = coordinator.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
        )
        host.container = None
        clock.advance(61)

        first = coordinator.reap_once()
        second = coordinator.reap_once()
        self.assertEqual(first["run_ids"], [started["run_id"]])
        self.assertEqual(second["run_ids"], [])
        self.assertEqual(host.calls.count("start"), 1)
        self.assertEqual(
            self._event_counts(started["run_id"]).get("ephemeral.crashed"), 1
        )
        self.assertEqual(
            self._event_counts(started["run_id"]).get("ephemeral.failed"), 1
        )
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store, store.read_transaction() as connection:
            row = connection.execute(
                """
                SELECT run.status, lease.status AS lease_status
                FROM ephemeral_container_runs run
                JOIN leases lease USING(lease_id)
                WHERE run.run_id = ?
                """,
                (started["run_id"],),
            ).fetchone()
        self.assertEqual((row["status"], row["lease_status"]), ("cleaned", "released"))

    def test_transient_reaper_failure_does_not_republish_running_start(self) -> None:
        clock = FakeClock()
        host = FakeEphemeralHost()
        coordinator = EphemeralContainerCoordinator(
            self.fixture.persistence,
            host,
            clock=clock,
            reaper_interval_seconds=3600,
        )
        started = coordinator.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
        )
        self.assertEqual(host.calls.count("start"), 1)
        self.assertEqual(
            self._event_counts(started["run_id"]).get("ephemeral.started"), 1
        )

        clock.advance(61)
        with (
            self.assertLogs(
                "devcoordinator.ephemeral_containers", level="ERROR"
            ),
            mock.patch.object(
                host,
                "docker_find_ephemeral",
                side_effect=BrokerBackendError(
                    "ephemeral_docker_find_unobservable",
                    "injected transient Docker observation failure",
                ),
            ),
        ):
            failed = coordinator.reap_once()
        self.assertEqual(failed["attention_run_ids"], [started["run_id"]])
        self.assertEqual(
            coordinator.execute(
                self.fixture.request(
                    BrokerOperation.EPHEMERAL_STATUS, started["run_id"]
                )
            )["status"],
            "needs_attention",
        )

        clock.advance(16)
        recovered = coordinator.reap_once()
        self.assertEqual(recovered["run_ids"], [started["run_id"]])
        status = coordinator.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_STATUS, started["run_id"])
        )
        self.assertEqual(status["status"], "running")
        self.assertEqual(status["phase"], "running")
        self.assertEqual(host.calls.count("start"), 1)
        self.assertEqual(
            self._event_counts(started["run_id"]).get("ephemeral.started"), 1
        )

    def test_persisted_run_material_crosses_the_real_host_create_boundary(self) -> None:
        coordinator = EphemeralContainerCoordinator(
            self.fixture.persistence, FakeEphemeralHost()
        )
        authorized = self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
        self.assertEqual(
            self.fixture.persistence.reserve_operation(authorized).state, "execute"
        )
        reserved = coordinator._prepare_start(authorized)
        reserved = coordinator._bind_port(authorized, reserved.run_id, 55400)
        target = coordinator._create_target(reserved)
        labels = {
            "io.devcoordinator.ephemeral.run_id": target.identity.run_id,
            "io.devcoordinator.ephemeral.creation_nonce": (
                target.identity.creation_nonce
            ),
            "io.devcoordinator.repository_id": target.identity.repository_id,
            "io.devcoordinator.ephemeral.template_id": target.identity.template_id,
            "io.devcoordinator.ephemeral.definition_fingerprint": (
                target.identity.definition_fingerprint
            ),
        }
        inspection = "\t".join(
            json.dumps(value, separators=(",", ":"))
            for value in (
                FULL_ID,
                "created",
                False,
                "no",
                labels,
                False,
                None,
                [],
                None,
                [],
                "bridge",
                "",
                0,
                {},
            )
        )
        calls: list[tuple[str, ...]] = []

        def runner(command: tuple[str, ...], timeout: float):
            calls.append(command)
            if command[1] == "create":
                return subprocess.CompletedProcess(
                    command, 0, stdout=FULL_ID + "\n", stderr=""
                )
            return subprocess.CompletedProcess(
                command, 0, stdout=inspection + "\n", stderr=""
            )

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker", docker_runner=runner
        )
        result = host.docker_create_ephemeral(target)
        self.assertEqual(result["full_container_id"], FULL_ID)
        self.assertEqual(
            target.container_name.rsplit("-", 1)[1],
            uuid.UUID(reserved.run_id).hex,
        )
        self.assertRegex(
            target.identity.definition_fingerprint, r"\Asha256:[0-9a-f]{64}\Z"
        )
        self.assertEqual(calls[0][1], "create")

    def test_failed_create_absence_terminally_fails_original_start(self) -> None:
        host = FakeEphemeralHost(fail_without_create=True)
        clock = FakeClock()
        coordinator = EphemeralContainerCoordinator(
            self.fixture.persistence,
            host,
            reaper_interval_seconds=3600,
            clock=clock,
        )
        operation_id = str(uuid.uuid4())
        authorized = self.fixture.request(
            BrokerOperation.EPHEMERAL_START,
            TEMPLATE,
            operation_id=operation_id,
        )
        with self.assertRaises(BrokerBackendError) as caught:
            coordinator.execute(authorized)
        self.assertEqual(caught.exception.code, "operation_outcome_uncertain")

        first = coordinator.recover_startup()
        self.assertEqual(first["run_ids"], [operation_id])
        self.assertEqual(
            self.fixture.persistence.existing_operation_disposition(authorized).state,
            "pending",
            "one point absence must not terminalize an uncertain Docker create",
        )
        clock.advance(61)
        recovered = coordinator.reap_once()
        self.assertEqual(recovered["run_ids"], [operation_id])
        disposition = self.fixture.persistence.existing_operation_disposition(
            authorized
        )
        self.assertIsNotNone(disposition)
        self.assertEqual(disposition.state, "failed")
        self.assertEqual(disposition.error_code, "ephemeral_create_not_found")
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store, store.read_transaction() as connection:
            run = connection.execute(
                "SELECT status FROM ephemeral_container_runs WHERE run_id = ?",
                (operation_id,),
            ).fetchone()
            self.assertEqual(run["status"], "failed")

    def test_startup_recovery_invokes_only_one_fixed_batch_then_defers_to_reaper(self) -> None:
        self._provision_quota_template(
            max_concurrent_runs=8,
            max_concurrent_runs_per_uid=8,
        )
        host = FakeEphemeralHost()
        coordinator = EphemeralContainerCoordinator(
            self.fixture.persistence, host, reaper_interval_seconds=3600
        )
        run_ids: list[str] = []
        for _ in range(5):
            authorized = self.fixture.request(
                BrokerOperation.EPHEMERAL_START, TEMPLATE
            )
            disposition = self.fixture.persistence.reserve_operation(authorized)
            self.assertEqual(disposition.state, "execute")
            run_ids.append(coordinator._prepare_start(authorized).run_id)

        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store, store.read_transaction() as connection:
            ordered = connection.execute(
                """
                SELECT run_id FROM ephemeral_container_runs
                WHERE status NOT IN ('cleaned', 'failed')
                ORDER BY created_at, run_id
                """
            ).fetchall()
        expected_order = [str(row["run_id"]) for row in ordered]

        recovered = coordinator.recover_startup()
        self.assertEqual(recovered["batch_limit"], 4)
        self.assertEqual(recovered["recovered"], 4)
        self.assertEqual(recovered["attention"], 0)
        self.assertEqual(recovered["deferred"], 1)
        self.assertCountEqual(expected_order, run_ids)
        self.assertEqual(recovered["run_ids"], expected_order[:4])
        self.assertEqual(host.calls, ["find"] * 4)
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store, store.read_transaction() as connection:
            remaining = connection.execute(
                """
                SELECT run_id FROM ephemeral_container_runs
                WHERE status NOT IN ('cleaned', 'failed')
                ORDER BY created_at, run_id
                """
            ).fetchall()
        self.assertEqual(
            [str(row["run_id"]) for row in remaining], expected_order[4:]
        )

        reaped = coordinator.reap_once()
        self.assertEqual(reaped["run_ids"], expected_order[4:])
        self.assertEqual(host.calls, ["find"] * 5)

    def test_start_wire_cannot_supply_docker_material(self) -> None:
        for injected in (
            {"image": "attacker/image:latest"},
            {"command": ["sh", "-c", "id"]},
            {"environment": {"A": "B"}},
            {"mounts": ["/run/docker.sock:/run/docker.sock"]},
        ):
            with self.subTest(injected=injected):
                with self.assertRaises(BrokerError) as caught:
                    BrokerRequest.create(
                        account_id=ACCOUNT,
                        project_id=REPO,
                        resource_id=TEMPLATE,
                        operation=BrokerOperation.EPHEMERAL_START,
                        arguments=injected,
                        authority_generation=self.fixture.generation,
                    )
                self.assertEqual(caught.exception.code, "invalid_arguments")

    def test_client_agent_is_persisted_in_durable_operation_actor(self) -> None:
        authorized = self.fixture.request(
            BrokerOperation.EPHEMERAL_START,
            TEMPLATE,
            arguments={"agent": "codex-a"},
        )
        disposition = self.fixture.persistence.reserve_operation(authorized)
        self.assertEqual(disposition.state, "execute")
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store:
            with store.read_transaction() as connection:
                row = connection.execute(
                    "SELECT actor, owner_uid FROM operations WHERE operation_id = ?",
                    (authorized.request.operation_id,),
                ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(
            row["actor"], "broker:account-ephemeral:client-agent:codex-a"
        )
        self.assertEqual(row["owner_uid"], os.geteuid())

    def test_local_peer_uid_is_attribution_but_unknown_run_is_denied(self) -> None:
        host = FakeEphemeralHost()
        coordinator = EphemeralContainerCoordinator(self.fixture.persistence, host)
        started = coordinator.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
        )

        alternate_peer = self.fixture.request(
            BrokerOperation.EPHEMERAL_STATUS,
            started["run_id"],
            uid=os.geteuid() + 10000,
        )
        self.assertEqual(
            coordinator.execute(alternate_peer)["run_id"],
            started["run_id"],
        )

        unknown_run_id = str(uuid.uuid4())
        with self.assertRaises(BrokerError) as caught:
            coordinator.execute(
                self.fixture.request(
                    BrokerOperation.EPHEMERAL_STATUS,
                    unknown_run_id,
                    uid=os.geteuid() + 10000,
                )
            )
        self.assertEqual(caught.exception.code, "resource_unavailable")

    def test_template_definition_is_sealed_into_reserved_run(self) -> None:
        host = FakeEphemeralHost()
        coordinator = EphemeralContainerCoordinator(self.fixture.persistence, host)
        authorized = self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
        disposition = self.fixture.persistence.reserve_operation(authorized)
        self.assertEqual(disposition.state, "execute")
        sealed = coordinator._prepare_start(authorized)
        replacement = "postgres@sha256:" + "c" * 64
        self.fixture.persistence.provision_ephemeral_template(
            template_id=TEMPLATE,
            repo_id=REPO,
            name="artifact-postgres",
            image_ref=replacement,
            default_ttl_seconds=600,
            max_ttl_seconds=3600,
            memory_bytes=128 * 1024 * 1024,
            cpu_millis=500,
        )
        loaded = coordinator._target(sealed.run_id)
        self.assertEqual(loaded.image_ref, IMAGE)
        self.assertEqual(loaded.command, ("postgres", "-c", "fsync=off"))
        self.assertIn(("POSTGRES_HOST_AUTH_METHOD", "trust"), loaded.environment)

    def test_per_user_template_quota_rejects_before_docker(self) -> None:
        self._provision_quota_template(
            max_concurrent_runs=2,
            max_concurrent_runs_per_uid=1,
        )
        host = FakeEphemeralHost()
        coordinator = EphemeralContainerCoordinator(self.fixture.persistence, host)
        coordinator.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
        )
        with self.assertRaises(BrokerError) as caught:
            coordinator.execute(
                self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
            )
        self.assertEqual(caught.exception.code, "ephemeral_quota_exceeded")
        self.assertIn("per-user", caught.exception.message)
        self.assertEqual(host.calls.count("create"), 1)

    def test_template_quota_applies_across_local_callers(self) -> None:
        self._provision_quota_template(
            max_concurrent_runs=1,
            max_concurrent_runs_per_uid=1,
        )
        other_uid = os.geteuid() + 10000
        other_account = "account-ephemeral-other"
        host = FakeEphemeralHost()
        coordinator = EphemeralContainerCoordinator(self.fixture.persistence, host)
        coordinator.execute(
            self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
        )
        with self.assertRaises(BrokerError) as caught:
            coordinator.execute(
                self.fixture.request(
                    BrokerOperation.EPHEMERAL_START,
                    TEMPLATE,
                    uid=other_uid,
                    account_id=other_account,
                )
            )
        self.assertEqual(caught.exception.code, "ephemeral_quota_exceeded")
        self.assertIn("this template", caught.exception.message)
        self.assertNotIn("per-user", caught.exception.message)
        self.assertEqual(host.calls.count("create"), 1)

    def test_repository_memory_and_cpu_budgets_reject_before_docker(self) -> None:
        for budget_kind in ("memory", "CPU"):
            with self.subTest(budget_kind=budget_kind):
                fixture = EphemeralFixture()
                try:
                    memory_budget = (
                        400 * 1024 * 1024
                        if budget_kind == "memory"
                        else 2 * 1024 * 1024 * 1024
                    )
                    cpu_budget = 4000 if budget_kind == "memory" else 1000
                    fixture.persistence.provision_ephemeral_template(
                        template_id=TEMPLATE,
                        repo_id=REPO,
                        name="artifact-postgres",
                        image_ref=IMAGE,
                        default_ttl_seconds=600,
                        max_ttl_seconds=3600,
                        memory_bytes=256 * 1024 * 1024,
                        cpu_millis=750,
                        max_concurrent_runs=4,
                        max_concurrent_runs_per_uid=4,
                        repo_max_active_runs=16,
                        repo_memory_budget_bytes=memory_budget,
                        repo_cpu_budget_millis=cpu_budget,
                    )
                    host = FakeEphemeralHost()
                    coordinator = EphemeralContainerCoordinator(
                        fixture.persistence, host
                    )
                    coordinator.execute(
                        fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
                    )
                    with self.assertRaises(BrokerError) as caught:
                        coordinator.execute(
                            fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE)
                        )
                    self.assertEqual(
                        caught.exception.code, "ephemeral_quota_exceeded"
                    )
                    self.assertIn(budget_kind, caught.exception.message)
                    self.assertEqual(host.calls.count("create"), 1)
                finally:
                    fixture.close()

    def test_repository_count_and_fixed_host_aggregate_are_enforced(self) -> None:
        second_template = "ephemeral-template-second"
        for scope in ("repository", "host"):
            with self.subTest(scope=scope):
                fixture = EphemeralFixture()
                try:
                    repo_max = 1 if scope == "repository" else 16
                    template_max = 1 if scope == "repository" else 4
                    for template_id, name in (
                        (TEMPLATE, "artifact-postgres"),
                        (second_template, "artifact-postgres-second"),
                    ):
                        fixture.persistence.provision_ephemeral_template(
                            template_id=template_id,
                            repo_id=REPO,
                            name=name,
                            image_ref=IMAGE,
                            default_ttl_seconds=600,
                            max_ttl_seconds=3600,
                            memory_bytes=64 * 1024 * 1024,
                            cpu_millis=100,
                            max_concurrent_runs=template_max,
                            max_concurrent_runs_per_uid=template_max,
                            repo_max_active_runs=repo_max,
                            repo_memory_budget_bytes=8 * 1024 * 1024 * 1024,
                            repo_cpu_budget_millis=16_000,
                        )
                    host = FakeEphemeralHost()
                    coordinator = EphemeralContainerCoordinator(
                        fixture.persistence, host
                    )
                    context = (
                        mock.patch(
                            "devcoordinator.ephemeral_containers._HOST_MAX_ACTIVE_EPHEMERAL_RUNS",
                            1,
                        )
                        if scope == "host"
                        else contextlib.nullcontext()
                    )
                    with context:
                        coordinator.execute(
                            fixture.request(
                                BrokerOperation.EPHEMERAL_START, TEMPLATE
                            )
                        )
                        with self.assertRaises(BrokerError) as caught:
                            coordinator.execute(
                                fixture.request(
                                    BrokerOperation.EPHEMERAL_START,
                                    second_template,
                                )
                            )
                    self.assertEqual(
                        caught.exception.code, "ephemeral_quota_exceeded"
                    )
                    self.assertIn(scope, caught.exception.message)
                    self.assertEqual(host.calls.count("create"), 1)
                finally:
                    fixture.close()

    def test_concurrent_starts_cannot_oversubscribe_per_user_quota(self) -> None:
        self._provision_quota_template(
            max_concurrent_runs=2,
            max_concurrent_runs_per_uid=1,
        )
        barrier = threading.Barrier(2)

        class BarrierCoordinator(EphemeralContainerCoordinator):
            def _prepare_start(self, authorized, **kwargs):
                barrier.wait(timeout=5)
                return super()._prepare_start(authorized, **kwargs)

        coordinators = (
            BarrierCoordinator(
                self.fixture.persistence,
                FakeEphemeralHost(full_container_id="c" * 64),
            ),
            BarrierCoordinator(
                self.fixture.persistence,
                FakeEphemeralHost(full_container_id="d" * 64),
            ),
        )
        requests = (
            self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE),
            self.fixture.request(BrokerOperation.EPHEMERAL_START, TEMPLATE),
        )
        outcomes: list[tuple[str, object]] = []
        outcome_lock = threading.Lock()

        def worker(index: int) -> None:
            try:
                value: tuple[str, object] = (
                    "success",
                    coordinators[index].execute(requests[index]),
                )
            except Exception as error:  # retained for diagnostic timeout output
                value = ("error", error)
            with outcome_lock:
                outcomes.append(value)

        workers = [
            threading.Thread(target=worker, args=(index,), daemon=True)
            for index in range(2)
        ]
        for worker_thread in workers:
            worker_thread.start()
        for worker_thread in workers:
            worker_thread.join(timeout=10)
        self.assertTrue(
            all(not worker_thread.is_alive() for worker_thread in workers),
            f"quota workers did not finish; outcomes={outcomes!r}",
        )
        self.assertEqual(len(outcomes), 2, outcomes)
        successes = [value for kind, value in outcomes if kind == "success"]
        errors = [value for kind, value in outcomes if kind == "error"]
        self.assertEqual(len(successes), 1, outcomes)
        self.assertEqual(len(errors), 1, outcomes)
        self.assertIsInstance(errors[0], BrokerError)
        self.assertEqual(errors[0].code, "ephemeral_quota_exceeded")
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store, store.read_transaction() as connection:
            active = connection.execute(
                """
                SELECT COUNT(*) FROM ephemeral_container_runs
                WHERE status NOT IN ('cleaned', 'failed')
                """
            ).fetchone()[0]
        self.assertEqual(active, 1)

    def test_v7_to_v8_schema_migration_adds_validated_renewal_journal(
        self,
    ) -> None:
        connection = sqlite3.connect(":memory:")
        try:
            connection.execute(
                "CREATE TABLE ephemeral_container_runs (run_id TEXT PRIMARY KEY)"
            )
            connection.execute(
                "INSERT INTO ephemeral_container_runs(run_id) VALUES ('run-v7')"
            )

            _upgrade_ephemeral_renewal_journal_to_v8(connection)

            columns = {
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(ephemeral_container_runs)"
                )
            }
            self.assertTrue(
                {
                    "credential_renewal_phase",
                    "credential_renewal_old_expires_at_epoch",
                    "credential_renewal_new_expires_at_epoch",
                    "credential_renewal_operation_id",
                }
                <= columns
            )
            untouched = connection.execute(
                """
                SELECT credential_renewal_phase,
                       credential_renewal_old_expires_at_epoch,
                       credential_renewal_new_expires_at_epoch,
                       credential_renewal_operation_id
                FROM ephemeral_container_runs WHERE run_id = 'run-v7'
                """
            ).fetchone()
            self.assertEqual(tuple(untouched), ("none", None, None, None))

            connection.execute(
                """
                UPDATE ephemeral_container_runs
                SET credential_renewal_phase = 'prepared',
                    credential_renewal_old_expires_at_epoch = 100,
                    credential_renewal_new_expires_at_epoch = 200,
                    credential_renewal_operation_id = 'renew-v7'
                WHERE run_id = 'run-v7'
                """
            )
            _upgrade_ephemeral_renewal_journal_to_v8(connection)

            connection.execute(
                """
                UPDATE ephemeral_container_runs
                SET credential_renewal_phase = 'none'
                WHERE run_id = 'run-v7'
                """
            )
            with self.assertRaisesRegex(RuntimeError, "invalid ephemeral"):
                _upgrade_ephemeral_renewal_journal_to_v8(connection)
        finally:
            connection.close()


    def test_v5_schema_requires_explicit_offline_migration_without_writes(self) -> None:
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        now = utc_timestamp()
        connection.executescript(
            """
            CREATE TABLE schema_metadata (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                schema_version INTEGER NOT NULL,
                database_generation TEXT NOT NULL UNIQUE,
                state_revision INTEGER NOT NULL DEFAULT 0,
                observation_revision INTEGER NOT NULL DEFAULT 0,
                authority_mode TEXT NOT NULL DEFAULT 'shadow',
                migration_state TEXT NOT NULL DEFAULT 'empty',
                first_sqlite_mutation_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE ephemeral_container_templates (
                template_id TEXT PRIMARY KEY,
                repo_id TEXT NOT NULL,
                name TEXT NOT NULL,
                image_ref TEXT NOT NULL,
                definition_fingerprint TEXT NOT NULL,
                default_ttl_seconds INTEGER NOT NULL,
                max_ttl_seconds INTEGER NOT NULL,
                container_tcp_port INTEGER,
                host_port_start INTEGER,
                host_port_end INTEGER,
                memory_bytes INTEGER,
                cpu_millis INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1,
                generation INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(repo_id, name)
            );
            CREATE TABLE ephemeral_container_runs (
                run_id TEXT PRIMARY KEY,
                template_id TEXT NOT NULL,
                repo_id TEXT NOT NULL,
                owner_uid INTEGER NOT NULL,
                account_id TEXT NOT NULL,
                creation_nonce TEXT NOT NULL UNIQUE,
                container_name TEXT NOT NULL UNIQUE,
                full_container_id TEXT UNIQUE,
                docker_resource_id TEXT UNIQUE,
                lease_id TEXT UNIQUE,
                host_port INTEGER,
                image_ref TEXT NOT NULL,
                memory_bytes INTEGER,
                cpu_millis INTEGER,
                container_tcp_port INTEGER,
                host_port_start INTEGER,
                host_port_end INTEGER,
                template_fingerprint TEXT NOT NULL,
                status TEXT NOT NULL,
                phase TEXT NOT NULL,
                expires_at_epoch INTEGER NOT NULL,
                generation INTEGER NOT NULL DEFAULT 0,
                cleanup_reason TEXT,
                error_code TEXT,
                error_message TEXT,
                result_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                finished_at TEXT
            );
            """
        )
        connection.execute(
            """
            INSERT INTO schema_metadata(
                singleton, schema_version, database_generation,
                created_at, updated_at
            ) VALUES (1, 5, 'generation-v5', ?, ?)
            """,
            (now, now),
        )
        connection.execute(
            """
            INSERT INTO ephemeral_container_templates(
                template_id, repo_id, name, image_ref,
                definition_fingerprint, default_ttl_seconds,
                max_ttl_seconds, memory_bytes, cpu_millis,
                created_at, updated_at
            ) VALUES (
                'template-v5', 'repo-v5', 'legacy-template', ?,
                ?, 600, 3600, 268435456, 750, ?, ?
            )
            """,
            (IMAGE, "sha256:" + "e" * 64, now, now),
        )
        connection.execute(
            """
            INSERT INTO ephemeral_container_runs(
                run_id, template_id, repo_id, owner_uid, account_id,
                creation_nonce, container_name, image_ref,
                memory_bytes, cpu_millis, template_fingerprint,
                status, phase, expires_at_epoch, cleanup_reason,
                created_at, updated_at
            ) VALUES (
                'run-v5', 'template-v5', 'repo-v5', 501, 'account-v5',
                'nonce-v5', 'container-v5', ?, 268435456, 750, ?,
                'needs_attention', 'cleanup_outcome_uncertain', 2000000000,
                'legacy cleanup intent', ?, ?
            )
            """,
            (IMAGE, "sha256:" + "e" * 64, now, now),
        )
        before = tuple(connection.iterdump())
        with self.assertRaisesRegex(
            RuntimeError, "unsupported coordinator database schema 5"
        ):
            initialize_schema(
                connection,
                database_generation="ignored-existing-generation",
                timestamp=utc_timestamp(),
            )
        self.assertEqual(tuple(connection.iterdump()), before)
        version = connection.execute(
            "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
        ).fetchone()[0]
        self.assertEqual(version, 5)
        policy_columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(ephemeral_container_templates)"
            )
        }
        run_policy_columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(ephemeral_container_runs)"
            )
        }
        self.assertFalse(
            {"secret_policy_kind", "secret_binding_id"} & policy_columns
        )
        self.assertFalse(
            {"secret_policy_kind", "secret_binding_id"} & run_policy_columns
        )
        self.assertNotIn("secret_value", policy_columns | run_policy_columns)
        quota_index = connection.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'index' AND name = 'ephemeral_runs_for_quota_admission'
            """
        ).fetchone()
        self.assertIsNone(quota_index)
        connection.close()


if __name__ == "__main__":
    unittest.main()
