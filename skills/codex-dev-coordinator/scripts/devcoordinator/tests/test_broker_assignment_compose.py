"""Broker-owned global assignments and opaque Compose mutation tests."""

from __future__ import annotations

import os
from pathlib import Path
import pwd
import subprocess
import tempfile
import unittest
import uuid
from typing import Any, Callable, Mapping, Optional

from devcoordinator.broker import (
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    BrokerService,
    PeerCredentials,
    SerializedMutationWriter,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend
from devcoordinator.broker_host import LocalBrokerHostMutations
from devcoordinator.broker_persistence import BrokerPersistence, StoreBackedAuthorizer
from devcoordinator.store import CoordinatorStore, utc_timestamp


ACCOUNT = "account-alpha"
FOREIGN_ACCOUNT = "account-foreign"
HOST = "host-global"
SOURCE = "source-service"
REPO_ALPHA = "repo-alpha"
REPO_BETA = "repo-beta"
SERVER_ALPHA = "server-alpha"
SERVER_BETA = "server-beta"
COMPOSE_ALPHA = "compose-alpha"


class ExtendedBrokerFixture:
    def __init__(self) -> None:
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir).resolve()
        self._temporary = tempfile.TemporaryDirectory(
            prefix=".broker-extended-", dir=str(home)
        )
        self.root = Path(self._temporary.name).resolve()
        self.alpha_root = self.root / "alpha"
        self.beta_root = self.root / "beta"
        self.alpha_root.mkdir()
        self.beta_root.mkdir()
        self.compose_one = self.alpha_root / "compose.yml"
        self.compose_two = self.alpha_root / "compose.override.yml"
        self.compose_one.write_text("services: {}\n", encoding="utf-8")
        self.compose_two.write_text("services: {}\n", encoding="utf-8")
        self.persistence = BrokerPersistence(
            self.root / "store" / "coordinator.sqlite3",
            expected_uid=os.geteuid(),
        )
        self.foreign_uid = os.geteuid() + 10_000
        now = utc_timestamp()
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO hosts(
                        host_id, machine_fingerprint, platform, hostname,
                        created_at, updated_at
                    ) VALUES (?, 'machine-global', 'test', 'test-host', ?, ?)
                    """,
                    (HOST, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO coordinator_sources(
                        source_id, host_id, canonical_home, state_path,
                        effective_uid, status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 'imported', ?, ?)
                    """,
                    (
                        SOURCE,
                        HOST,
                        str(self.root / "source"),
                        str(self.root / "source" / "state"),
                        os.geteuid(),
                        now,
                        now,
                    ),
                )
                for repo_id, root, display in (
                    (REPO_ALPHA, self.alpha_root, "Alpha"),
                    (REPO_BETA, self.beta_root, "Beta"),
                ):
                    connection.execute(
                        """
                        INSERT INTO repositories(
                            repo_id, host_id, canonical_root, display_name,
                            state, generation, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, 'active', 0, ?, ?)
                        """,
                        (repo_id, HOST, str(root), display, now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO repository_installations(
                            repo_id, status, startup_fenced, generation,
                            actor, updated_at
                        ) VALUES (?, 'installed', 0, 0, 'fixture', ?)
                        """,
                        (repo_id, now),
                    )
                for server_id, repo_id, name, root in (
                    (SERVER_ALPHA, REPO_ALPHA, "web", self.alpha_root),
                    (SERVER_BETA, REPO_BETA, "web", self.beta_root),
                ):
                    connection.execute(
                        """
                        INSERT INTO server_definitions(
                            server_definition_id, repo_id, name, cwd,
                            definition_fingerprint, generation,
                            created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, 0, ?, ?)
                        """,
                        (
                            server_id,
                            repo_id,
                            name,
                            str(root),
                            "definition-" + server_id,
                            now,
                            now,
                        ),
                    )
            self.generation = store.metadata.database_generation

        self.persistence.provision_principal(uid=os.geteuid(), account_id=ACCOUNT)
        self.persistence.provision_principal(
            uid=self.foreign_uid, account_id=FOREIGN_ACCOUNT
        )
        for uid, repo_id, server_id in (
            (os.geteuid(), REPO_ALPHA, SERVER_ALPHA),
            (os.geteuid(), REPO_BETA, SERVER_BETA),
            (self.foreign_uid, REPO_ALPHA, SERVER_ALPHA),
        ):
            for operation in (
                BrokerOperation.PORT_ASSIGN,
                BrokerOperation.PORT_UNASSIGN,
            ):
                self.persistence.grant_resource(
                    uid=uid,
                    repo_id=repo_id,
                    resource_kind="server",
                    resource_id=server_id,
                    operation=operation,
                )
            self.persistence.grant_port_range(
                uid=uid,
                repo_id=repo_id,
                server_definition_id=server_id,
                start_port=43_100,
                end_port=43_199,
            )
        self.persistence.provision_compose_definition(
            repo_id=REPO_ALPHA,
            compose_definition_id=COMPOSE_ALPHA,
            cwd=self.alpha_root,
            files=(self.compose_one, self.compose_two),
            services=("db", "web"),
            project_name="alpha-stack",
        )
        for operation in (BrokerOperation.COMPOSE_UP, BrokerOperation.COMPOSE_DOWN):
            self.persistence.grant_resource(
                uid=os.geteuid(),
                repo_id=REPO_ALPHA,
                resource_kind="compose",
                resource_id=COMPOSE_ALPHA,
                operation=operation,
            )

    def close(self) -> None:
        self._temporary.cleanup()

    def peer(self, *, foreign: bool = False) -> PeerCredentials:
        return PeerCredentials(
            self.foreign_uid if foreign else os.geteuid(),
            os.getegid(),
            os.getpid(),
        )

    def request(
        self,
        operation: BrokerOperation,
        *,
        repo_id: str = REPO_ALPHA,
        resource_id: str = SERVER_ALPHA,
        arguments: Optional[Mapping[str, Any]] = None,
        operation_id: Optional[str] = None,
        foreign: bool = False,
        generation: Optional[str] = None,
    ) -> BrokerRequest:
        return BrokerRequest.create(
            account_id=FOREIGN_ACCOUNT if foreign else ACCOUNT,
            project_id=repo_id,
            resource_id=resource_id,
            operation=operation,
            arguments=arguments,
            operation_id=operation_id,
            authority_generation=generation or self.generation,
        )

    def observe_full_docker(self, store: CoordinatorStore) -> Mapping[str, Any]:
        snapshot_id = "compose-snapshot-" + uuid.uuid4().hex
        completed_at = utc_timestamp()
        material = "7" * 64
        capability = "sha256:" + "8" * 64
        with store.immediate_transaction(revision_kind="observation") as connection:
            connection.execute(
                """
                INSERT INTO observation_snapshots(
                    snapshot_id, host_id, observer_domain, status,
                    material_fingerprint, started_at, completed_at
                ) VALUES (?, ?, 'host-runtime-v2:full-docker', 'completed',
                          ?, ?, ?)
                """,
                (snapshot_id, HOST, material, completed_at, completed_at),
            )
            connection.execute(
                """
                INSERT INTO observation_capabilities(
                    snapshot_id, observer_domain, docker_available,
                    capability_fingerprint, committed_at
                ) VALUES (?, 'host-runtime-v2:full-docker', 1, ?, ?)
                """,
                (snapshot_id, capability, completed_at),
            )
        return {
            "snapshot_id": snapshot_id,
            "observer_domain": "host-runtime-v2:full-docker",
            "docker_available": True,
            "capability_fingerprint": capability,
            "material_fingerprint": material,
            "completed_at": completed_at,
        }


def service_for(
    fixture: ExtendedBrokerFixture,
    *,
    port_probe: Optional[Callable[[int, str], bool]] = None,
    compose_runner: Optional[
        Callable[[tuple[str, ...], str, float], subprocess.CompletedProcess[str]]
    ] = None,
) -> tuple[BrokerService, LocalBrokerHostMutations]:
    host = LocalBrokerHostMutations(
        docker_executable="/trusted/docker",
        port_probe=port_probe or (lambda _port, _protocol: True),
        compose_runner=compose_runner,
    )
    backend = StoreBackedMutationBackend(
        fixture.persistence,
        host,
        observe_before_lifecycle_plan=fixture.observe_full_docker,
    )
    service = BrokerService(
        StoreBackedAuthorizer(fixture.persistence),
        SerializedMutationWriter(backend),
    )
    return service, host


class BrokerAssignmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = ExtendedBrokerFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_host_global_conflict_and_exact_owner_release(self) -> None:
        probes: list[tuple[int, str]] = []

        def probe(port: int, protocol: str) -> bool:
            probes.append((port, protocol))
            return True

        service, _ = service_for(self.fixture, port_probe=probe)
        assigned_request = self.fixture.request(
            BrokerOperation.PORT_ASSIGN, arguments={"port": 43_101}
        )
        assigned = service.reply_for_document(
            self.fixture.peer(), assigned_request.to_wire()
        )
        self.assertTrue(assigned["ok"], assigned)
        self.assertEqual(assigned["result"]["status"], "active")
        self.assertEqual(assigned["result"]["port"], 43_101)
        restarted_assignment_service, _ = service_for(
            self.fixture, port_probe=probe
        )
        assigned_replay = restarted_assignment_service.reply_for_document(
            self.fixture.peer(), assigned_request.to_wire()
        )
        self.assertEqual(assigned_replay, assigned)
        self.assertEqual(probes, [(43_101, "tcp")])

        conflicting = self.fixture.request(
            BrokerOperation.PORT_ASSIGN,
            repo_id=REPO_BETA,
            resource_id=SERVER_BETA,
            arguments={"port": 43_101},
        )
        conflict_reply = service.reply_for_document(
            self.fixture.peer(), conflicting.to_wire()
        )
        self.assertFalse(conflict_reply["ok"], conflict_reply)
        self.assertEqual(
            conflict_reply["error"]["code"], "port_assignment_conflict"
        )

        foreign_release = self.fixture.request(
            BrokerOperation.PORT_UNASSIGN, foreign=True
        )
        foreign_reply = service.reply_for_document(
            self.fixture.peer(foreign=True), foreign_release.to_wire()
        )
        self.assertFalse(foreign_reply["ok"], foreign_reply)
        self.assertEqual(foreign_reply["error"]["code"], "resource_access_denied")

        operation_id = str(uuid.uuid4())
        release_request = self.fixture.request(
            BrokerOperation.PORT_UNASSIGN, operation_id=operation_id
        )
        released = service.reply_for_document(
            self.fixture.peer(), release_request.to_wire()
        )
        self.assertTrue(released["ok"], released)
        self.assertEqual(released["result"]["status"], "released")
        self.assertEqual(
            released["result"]["assignment_id"],
            assigned["result"]["assignment_id"],
        )
        replay_service, _ = service_for(self.fixture)
        replay = replay_service.reply_for_document(
            self.fixture.peer(), release_request.to_wire()
        )
        self.assertEqual(replay, released)

    def test_occupied_port_and_stale_generation_fail_before_assignment(self) -> None:
        service, _ = service_for(
            self.fixture, port_probe=lambda port, _protocol: port != 43_105
        )
        occupied = self.fixture.request(
            BrokerOperation.PORT_ASSIGN, arguments={"port": 43_105}
        )
        occupied_reply = service.reply_for_document(
            self.fixture.peer(), occupied.to_wire()
        )
        self.assertFalse(occupied_reply["ok"], occupied_reply)
        self.assertEqual(occupied_reply["error"]["code"], "port_unavailable")

        stale = self.fixture.request(
            BrokerOperation.PORT_ASSIGN,
            arguments={"port": 43_106},
            generation="stale-generation",
        )
        stale_reply = service.reply_for_document(self.fixture.peer(), stale.to_wire())
        self.assertFalse(stale_reply["ok"], stale_reply)
        self.assertEqual(stale_reply["error"]["code"], "broker_generation_mismatch")
        with CoordinatorStore.open(
            self.fixture.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.read_transaction() as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT count(*) FROM port_assignments"
                    ).fetchone()[0],
                    0,
                )

    def test_server_definition_change_after_reservation_blocks_assignment(self) -> None:
        probes = 0

        def probe(_port: int, _protocol: str) -> bool:
            nonlocal probes
            probes += 1
            return True

        original_reserve = self.fixture.persistence.reserve_operation

        def reserve_then_change_definition(authorized: Any) -> Any:
            disposition = original_reserve(authorized)
            if disposition.state == "execute":
                with CoordinatorStore.open(
                    self.fixture.persistence.database_path,
                    expected_uid=os.geteuid(),
                ) as store:
                    with store.immediate_transaction() as connection:
                        connection.execute(
                            """
                            UPDATE server_definitions
                            SET definition_fingerprint = 'changed-after-reserve',
                                generation = generation + 1, updated_at = ?
                            WHERE server_definition_id = ?
                            """,
                            (utc_timestamp(), SERVER_ALPHA),
                        )
            return disposition

        self.fixture.persistence.reserve_operation = reserve_then_change_definition  # type: ignore[method-assign]
        service, _ = service_for(self.fixture, port_probe=probe)
        request = self.fixture.request(
            BrokerOperation.PORT_ASSIGN, arguments={"port": 43_107}
        )
        reply = service.reply_for_document(self.fixture.peer(), request.to_wire())
        self.assertFalse(reply["ok"], reply)
        self.assertEqual(reply["error"]["code"], "stale_resource_definition")
        self.assertEqual(probes, 0)


class BrokerComposeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = ExtendedBrokerFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_wire_cannot_supply_paths_names_argv_or_options(self) -> None:
        for argument in (
            {"cwd": str(self.fixture.alpha_root)},
            {"files": [str(self.fixture.compose_one)]},
            {"project_name": "spoof"},
            {"argv": ["docker", "compose", "up"]},
            {"detach": False},
        ):
            with self.subTest(argument=argument):
                with self.assertRaises(BrokerError) as raised:
                    self.fixture.request(
                        BrokerOperation.COMPOSE_UP,
                        resource_id=COMPOSE_ALPHA,
                        arguments=argument,
                    )
                self.assertEqual(raised.exception.code, "invalid_arguments")
        with self.assertRaises(BrokerError):
            self.fixture.request(
                BrokerOperation.COMPOSE_UP,
                resource_id=str(self.fixture.compose_one),
            )

    def test_exact_persisted_compose_execution_and_durable_idempotency(self) -> None:
        calls: list[tuple[tuple[str, ...], str, float]] = []

        def runner(
            command: tuple[str, ...], cwd: str, timeout: float
        ) -> subprocess.CompletedProcess[str]:
            calls.append((command, cwd, timeout))
            return subprocess.CompletedProcess(command, 0, stdout="started\n", stderr="")

        service, _ = service_for(self.fixture, compose_runner=runner)
        operation_id = str(uuid.uuid4())
        request = self.fixture.request(
            BrokerOperation.COMPOSE_UP,
            resource_id=COMPOSE_ALPHA,
            operation_id=operation_id,
        )
        first = service.reply_for_document(self.fixture.peer(), request.to_wire())
        self.assertTrue(first["ok"], first)
        self.assertEqual(first["result"]["compose_definition_id"], COMPOSE_ALPHA)
        self.assertEqual(first["result"]["action"], "up")
        self.assertEqual(first["result"]["status"], "completed")
        expected = (
            "/trusted/docker",
            "compose",
            "--project-directory",
            str(self.fixture.alpha_root),
            "--project-name",
            "alpha-stack",
            "--file",
            str(self.fixture.compose_one),
            "--file",
            str(self.fixture.compose_two),
            "up",
            "--detach",
            "db",
            "web",
        )
        self.assertEqual(calls[0][0], expected)
        self.assertEqual(calls[0][1], str(self.fixture.alpha_root))
        self.assertGreater(calls[0][2], 0)
        definitions = self.fixture.persistence.list_compose_definitions(
            repo_id=REPO_ALPHA
        )
        self.assertEqual(definitions[0]["compose_definition_id"], COMPOSE_ALPHA)
        self.assertEqual(definitions[0]["services"], ["db", "web"])

        replay_service, _ = service_for(self.fixture, compose_runner=runner)
        replay = replay_service.reply_for_document(
            self.fixture.peer(), request.to_wire()
        )
        self.assertEqual(replay, first)
        self.assertEqual(len(calls), 1)

    def test_failure_is_durable_and_never_reexecutes(self) -> None:
        calls = 0

        def runner(
            command: tuple[str, ...], cwd: str, timeout: float
        ) -> subprocess.CompletedProcess[str]:
            nonlocal calls
            calls += 1
            return subprocess.CompletedProcess(
                command, 1, stdout="", stderr="compose failed"
            )

        service, _ = service_for(self.fixture, compose_runner=runner)
        request = self.fixture.request(
            BrokerOperation.COMPOSE_DOWN,
            resource_id=COMPOSE_ALPHA,
            operation_id=str(uuid.uuid4()),
        )
        with self.assertLogs("devcoordinator.broker", level="ERROR"):
            first = service.reply_for_document(self.fixture.peer(), request.to_wire())
        self.assertFalse(first["ok"], first)
        self.assertEqual(first["error"]["code"], "mutation_failed")
        restarted, _ = service_for(self.fixture, compose_runner=runner)
        replay = restarted.reply_for_document(self.fixture.peer(), request.to_wire())
        self.assertFalse(replay["ok"], replay)
        self.assertEqual(replay["error"]["code"], "mutation_failed")
        self.assertEqual(calls, 1)

    def test_compose_file_drift_is_rejected_before_docker(self) -> None:
        calls = 0

        def runner(
            command: tuple[str, ...], cwd: str, timeout: float
        ) -> subprocess.CompletedProcess[str]:
            nonlocal calls
            calls += 1
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        self.fixture.compose_one.write_text(
            "services:\n  attacker-controlled: {}\n", encoding="utf-8"
        )
        service, _ = service_for(self.fixture, compose_runner=runner)
        request = self.fixture.request(
            BrokerOperation.COMPOSE_UP,
            resource_id=COMPOSE_ALPHA,
        )
        reply = service.reply_for_document(self.fixture.peer(), request.to_wire())
        self.assertFalse(reply["ok"], reply)
        self.assertEqual(reply["error"]["code"], "compose_definition_drift")
        self.assertEqual(calls, 0)
        self.fixture.persistence.provision_compose_definition(
            repo_id=REPO_ALPHA,
            compose_definition_id=COMPOSE_ALPHA,
            cwd=self.fixture.alpha_root,
            files=(self.fixture.compose_one, self.fixture.compose_two),
            services=("db", "web"),
            project_name="alpha-stack",
        )
        reprovisioned, _ = service_for(self.fixture, compose_runner=runner)
        accepted = reprovisioned.reply_for_document(
            self.fixture.peer(),
            self.fixture.request(
                BrokerOperation.COMPOSE_UP, resource_id=COMPOSE_ALPHA
            ).to_wire(),
        )
        self.assertTrue(accepted["ok"], accepted)
        self.assertEqual(calls, 1)

    def test_reprovision_after_reservation_is_stale_before_host_effect(self) -> None:
        calls = 0

        def runner(
            command: tuple[str, ...], cwd: str, timeout: float
        ) -> subprocess.CompletedProcess[str]:
            nonlocal calls
            calls += 1
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        original_reserve = self.fixture.persistence.reserve_operation

        def reserve_then_reprovision(authorized: Any) -> Any:
            disposition = original_reserve(authorized)
            if disposition.state == "execute":
                self.fixture.compose_one.write_text(
                    "services:\n  changed-after-reserve: {}\n", encoding="utf-8"
                )
                self.fixture.persistence.provision_compose_definition(
                    repo_id=REPO_ALPHA,
                    compose_definition_id=COMPOSE_ALPHA,
                    cwd=self.fixture.alpha_root,
                    files=(self.fixture.compose_one, self.fixture.compose_two),
                    services=("db", "web"),
                    project_name="alpha-stack",
                )
            return disposition

        self.fixture.persistence.reserve_operation = reserve_then_reprovision  # type: ignore[method-assign]
        service, _ = service_for(self.fixture, compose_runner=runner)
        request = self.fixture.request(
            BrokerOperation.COMPOSE_UP, resource_id=COMPOSE_ALPHA
        )
        reply = service.reply_for_document(self.fixture.peer(), request.to_wire())
        self.assertFalse(reply["ok"], reply)
        self.assertEqual(reply["error"]["code"], "stale_resource_definition")
        self.assertEqual(calls, 0)

    def test_start_fence_blocks_up_and_assign_but_allows_down_and_unassign(self) -> None:
        calls: list[str] = []

        def runner(
            command: tuple[str, ...], cwd: str, timeout: float
        ) -> subprocess.CompletedProcess[str]:
            calls.append(command[-1])
            return subprocess.CompletedProcess(command, 0, stdout="down\n", stderr="")

        service, _ = service_for(self.fixture, compose_runner=runner)
        assigned = service.reply_for_document(
            self.fixture.peer(),
            self.fixture.request(
                BrokerOperation.PORT_ASSIGN, arguments={"port": 43_110}
            ).to_wire(),
        )
        self.assertTrue(assigned["ok"], assigned)
        with CoordinatorStore.open(
            self.fixture.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE repository_installations
                    SET status = 'disabling', startup_fenced = 1,
                        generation = generation + 1, updated_at = ?
                    WHERE repo_id = ?
                    """,
                    (utc_timestamp(), REPO_ALPHA),
                )

        for request in (
            self.fixture.request(
                BrokerOperation.PORT_ASSIGN, arguments={"port": 43_111}
            ),
            self.fixture.request(
                BrokerOperation.COMPOSE_UP, resource_id=COMPOSE_ALPHA
            ),
        ):
            reply = service.reply_for_document(self.fixture.peer(), request.to_wire())
            self.assertFalse(reply["ok"], reply)
            self.assertEqual(reply["error"]["code"], "repository_startup_fenced")

        released = service.reply_for_document(
            self.fixture.peer(),
            self.fixture.request(BrokerOperation.PORT_UNASSIGN).to_wire(),
        )
        self.assertTrue(released["ok"], released)
        with CoordinatorStore.open(
            self.fixture.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE repository_installations
                    SET status = 'disabled', startup_fenced = 1,
                        generation = generation + 1, updated_at = ?
                    WHERE repo_id = ?
                    """,
                    (utc_timestamp(), REPO_ALPHA),
                )
        disabled_up = service.reply_for_document(
            self.fixture.peer(),
            self.fixture.request(
                BrokerOperation.COMPOSE_UP, resource_id=COMPOSE_ALPHA
            ).to_wire(),
        )
        self.assertFalse(disabled_up["ok"], disabled_up)
        self.assertEqual(
            disabled_up["error"]["code"], "repository_startup_fenced"
        )
        down = service.reply_for_document(
            self.fixture.peer(),
            self.fixture.request(
                BrokerOperation.COMPOSE_DOWN, resource_id=COMPOSE_ALPHA
            ).to_wire(),
        )
        self.assertTrue(down["ok"], down)
        self.assertEqual(down["result"]["action"], "down")
        self.assertEqual(calls, ["down"])

    def test_ungranted_compose_identity_is_rejected_before_host_effect(self) -> None:
        calls = 0

        def runner(
            command: tuple[str, ...], cwd: str, timeout: float
        ) -> subprocess.CompletedProcess[str]:
            nonlocal calls
            calls += 1
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        service, _ = service_for(self.fixture, compose_runner=runner)
        request = self.fixture.request(
            BrokerOperation.COMPOSE_DOWN,
            resource_id=COMPOSE_ALPHA,
            foreign=True,
        )
        reply = service.reply_for_document(
            self.fixture.peer(foreign=True), request.to_wire()
        )
        self.assertFalse(reply["ok"], reply)
        self.assertEqual(reply["error"]["code"], "operation_access_denied")
        self.assertEqual(calls, 0)


if __name__ == "__main__":
    unittest.main()
