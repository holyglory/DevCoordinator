"""Broker-owned global assignments and opaque Compose mutation tests."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock
import uuid
from typing import Any, Callable, Iterator, Mapping, Optional

from devcoordinator.broker import (
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    BrokerService,
    PeerCredentials,
    SerializedMutationWriter,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend
from devcoordinator import broker_enrollment
from devcoordinator import broker_host
from devcoordinator import broker_persistence
from devcoordinator.broker_host import LocalBrokerHostMutations
from devcoordinator.broker_persistence import BrokerPersistence, StoreBackedAuthorizer
from devcoordinator.compose_contract import (
    require_effective_compose_model,
    require_sealable_compose_payload,
)
from devcoordinator.observer import SingleFlightObserver
from devcoordinator.store import AccountStore, CoordinatorStore, utc_timestamp


ACCOUNT = "account-alpha"
FOREIGN_ACCOUNT = "account-foreign"
HOST = "host-global"
SOURCE = "source-service"
REPO_ALPHA = "repo-alpha"
REPO_BETA = "repo-beta"
SERVER_ALPHA = "server-alpha"
SERVER_BETA = "server-beta"
COMPOSE_ALPHA = "compose-alpha"


def rendered_fixture_model(**arguments: object) -> bytes:
    services = tuple(str(item) for item in arguments["declared_services"])
    profiles = tuple(str(item) for item in arguments["profiles"])
    model_services: dict[str, dict[str, object]] = {
        name: {"image": f"example.invalid/{name}:test"} for name in services
    }
    if profiles:
        model_services[services[0]]["profiles"] = list(profiles)
    return json.dumps({"services": model_services}).encode("utf-8")


def capture_sealed_compose_command(
    command: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[bytes, ...], tuple[bytes, ...], tuple[str, ...]]:
    normalized: list[str] = []
    env_payloads: list[bytes] = []
    compose_payloads: list[bytes] = []
    snapshot_paths: list[str] = []
    index = 0
    while index < len(command):
        token = command[index]
        normalized.append(token)
        if token in {"--env-file", "--file"}:
            path = command[index + 1]
            payload = Path(path).read_bytes()
            snapshot_paths.append(path)
            if token == "--env-file":
                ordinal = len(env_payloads)
                env_payloads.append(payload)
                normalized.append(f"<sealed-env-{ordinal}>")
            else:
                ordinal = len(compose_payloads)
                compose_payloads.append(payload)
                normalized.append(f"<sealed-compose-{ordinal}>")
            index += 2
            continue
        index += 1
    return (
        tuple(normalized),
        tuple(env_payloads),
        tuple(compose_payloads),
        tuple(snapshot_paths),
    )


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
        self.env_one = self.alpha_root / "runtime.env"
        self.env_two = self.alpha_root / "runtime.override.env"
        self.env_one.write_text(
            "RUNTIME_OPAQUE_VALUE=never-return-this-value\n", encoding="utf-8"
        )
        self.env_two.write_text(
            "CAPTURE_PROFILE=enabled\nCOMPOSE_REMOVE_ORPHANS=1\n",
            encoding="utf-8",
        )
        self.env_one.chmod(0o600)
        self.env_two.chmod(0o600)
        self.persistence = BrokerPersistence(
            self.root / "store" / "coordinator.sqlite3",
            expected_uid=os.geteuid(),
            compose_model_renderer=rendered_fixture_model,
        )
        self.observed_container_ids: tuple[str, ...] = ()
        self.after_snapshot_commit: Optional[
            Callable[[CoordinatorStore, str], None]
        ] = None
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
            self.persistence.provision_repository_enrollment(
                uid=uid,
                repo_id=repo_id,
                account_id=(FOREIGN_ACCOUNT if uid == self.foreign_uid else ACCOUNT),
                issued_at=utc_timestamp(),
                valid_until_epoch=int(time.time()) + 3_600,
            )
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
            active_compose = connection.execute(
                """
                SELECT operation.kind, target.target_id,
                       definition.repo_id, definition.project_name
                FROM operations operation
                JOIN operation_targets target USING(operation_id)
                JOIN broker_compose_definitions definition
                  ON definition.compose_definition_id = target.target_id
                WHERE operation.status = 'running'
                  AND target.target_kind = 'compose'
                ORDER BY operation.created_at DESC, operation.operation_id DESC
                LIMIT 1
                """
            ).fetchone()
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
            for resource_id in self.observed_container_ids:
                connection.execute(
                    """
                    INSERT INTO observation_snapshot_resources(
                        snapshot_id, resource_kind, resource_id,
                        observation_fingerprint
                    ) VALUES (?, 'container', ?, ?)
                    """,
                    (snapshot_id, resource_id, "snapshot-" + resource_id),
                )
            connection.execute(
                """
                INSERT INTO broker_observation_compose_scope(
                    snapshot_id, assets_complete, observed_asset_count,
                    evidence_fingerprint, recorded_at
                ) VALUES (?, 1, 0, 'scope-empty', ?)
                """,
                (snapshot_id, completed_at),
            )
            if active_compose is not None and str(active_compose["kind"]) in {
                "broker.compose.up",
                "broker.compose.restart",
            }:
                active_repo_id = str(active_compose["repo_id"])
                active_project_name = str(active_compose["project_name"])
                engine_id = "engine-" + snapshot_id
                connection.execute(
                    """
                    INSERT INTO docker_engines(
                        engine_id, host_id, context_identity, capability_state,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, 'available', ?, ?)
                    """,
                    (
                        engine_id,
                        HOST,
                        "context-" + snapshot_id,
                        completed_at,
                        completed_at,
                    ),
                )
                services = tuple(
                    str(row["service_name"])
                    for row in connection.execute(
                        """
                        SELECT service_name FROM broker_compose_services
                        WHERE compose_definition_id = ? ORDER BY ordinal
                        """,
                        (active_compose["target_id"],),
                    )
                )
                for service in services:
                    full_id = hashlib.sha256(
                        f"{snapshot_id}:{service}".encode("utf-8")
                    ).hexdigest()
                    resource_id = "container-" + full_id[:24]
                    connection.execute(
                        """
                        INSERT INTO docker_resources(
                            docker_resource_id, engine_id, full_container_id,
                            current_name, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            resource_id,
                            engine_id,
                            full_id,
                            f"{active_project_name}-{service}-1",
                            completed_at,
                            completed_at,
                        ),
                    )
                    container_evidence = {
                        "snapshot_id": snapshot_id,
                        "docker_resource_id": resource_id,
                        "full_container_id": full_id,
                        "project_name": active_project_name,
                        "service_name": service,
                        "lifecycle": "running",
                        "ownership_state": "exclusive",
                        "authoritative_owner_repo_id": active_repo_id,
                    }
                    connection.execute(
                        """
                        INSERT INTO broker_observed_compose_containers(
                            snapshot_id, docker_resource_id, full_container_id,
                            project_name, service_name, lifecycle,
                            ownership_state, authoritative_owner_repo_id,
                            observation_fingerprint
                        ) VALUES (?, ?, ?, ?, ?, 'running', 'exclusive', ?, ?)
                        """,
                        (
                            snapshot_id,
                            resource_id,
                            full_id,
                            active_project_name,
                            service,
                            active_repo_id,
                            "sha256:"
                            + hashlib.sha256(
                                json.dumps(
                                    container_evidence,
                                    sort_keys=True,
                                    separators=(",", ":"),
                                ).encode("utf-8")
                            ).hexdigest(),
                        ),
                    )
        if self.after_snapshot_commit is not None:
            self.after_snapshot_commit(store, snapshot_id)
        return {
            "snapshot_id": snapshot_id,
            "host_id": HOST,
            "observer_domain": "host-runtime-v2:full-docker",
            "docker_available": True,
            "capability_fingerprint": capability,
            "material_fingerprint": material,
            "started_at": completed_at,
            "completed_at": completed_at,
        }

    def observed_compose_snapshot(
        self, *, owner_repo_id: str | None, project_name: str
    ) -> str:
        token = uuid.uuid4().hex
        engine_id = "engine-" + token
        resource_id = "container-" + token
        snapshot_id = "snapshot-" + token
        now = utc_timestamp()
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction(revision_kind="observation") as connection:
                connection.execute(
                    """
                    INSERT INTO docker_engines(
                        engine_id, host_id, context_identity, capability_state,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, 'available', ?, ?)
                    """,
                    (engine_id, HOST, "context-" + token, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO docker_resources(
                        docker_resource_id, engine_id, full_container_id,
                        current_name, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        resource_id,
                        engine_id,
                        hashlib.sha256(token.encode("ascii")).hexdigest(),
                        "observed-" + token,
                        now,
                        now,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO docker_labels(docker_resource_id, name, value)
                    VALUES (?, 'com.docker.compose.project', ?)
                    """,
                    (resource_id, project_name),
                )
                if owner_repo_id is not None:
                    binding_id = "binding-" + token
                    connection.execute(
                        """
                        INSERT INTO control_bindings(
                            binding_id, repo_id, resource_kind, resource_id,
                            source_id, capability, provenance, authority_state,
                            priority, generation, created_at, updated_at
                        ) VALUES (?, ?, 'container', ?, ?, 'lifecycle',
                                  'fixture', 'authoritative', 100, 0, ?, ?)
                        """,
                        (binding_id, owner_repo_id, resource_id, SOURCE, now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO repository_memberships(
                            membership_id, repo_id, resource_kind,
                            host_resource_id, immutable_fingerprint,
                            control_binding_id, created_at
                        ) VALUES (?, ?, 'container', ?, ?, ?, ?)
                        """,
                        (
                            "membership-" + token,
                            owner_repo_id,
                            resource_id,
                            "immutable-" + token,
                            binding_id,
                            now,
                        ),
                    )
                connection.execute(
                    """
                    INSERT INTO observation_snapshots(
                        snapshot_id, host_id, observer_domain, status,
                        material_fingerprint, started_at, completed_at
                    ) VALUES (?, ?, 'host-runtime-v2:full-docker', 'completed',
                              ?, ?, ?)
                    """,
                    (snapshot_id, HOST, "material-" + token, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO observation_capabilities(
                        snapshot_id, observer_domain, docker_available,
                        capability_fingerprint, committed_at
                    ) VALUES (?, 'host-runtime-v2:full-docker', 1, ?, ?)
                    """,
                    (snapshot_id, "capability-" + token, now),
                )
                connection.execute(
                    """
                    INSERT INTO observation_snapshot_resources(
                        snapshot_id, resource_kind, resource_id,
                        observation_fingerprint
                    ) VALUES (?, 'container', ?, ?)
                    """,
                    (snapshot_id, resource_id, "observation-" + token),
                )
                connection.execute(
                    """
                    INSERT INTO broker_observation_compose_scope(
                        snapshot_id, assets_complete, observed_asset_count,
                        evidence_fingerprint, recorded_at
                    ) VALUES (?, 1, 0, ?, ?)
                    """,
                    (snapshot_id, "scope-" + token, now),
                )
                connection.execute(
                    """
                    INSERT INTO broker_observed_compose_containers(
                        snapshot_id, docker_resource_id, full_container_id,
                        project_name, service_name, lifecycle,
                        ownership_state, authoritative_owner_repo_id,
                        observation_fingerprint
                    ) VALUES (?, ?, ?, ?, 'web', 'running', ?, ?, ?)
                    """,
                    (
                        snapshot_id,
                        resource_id,
                        hashlib.sha256(token.encode("ascii")).hexdigest(),
                        project_name,
                        "missing" if owner_repo_id is None else "exclusive",
                        owner_repo_id,
                        "compose-container-" + token,
                    ),
                )
        return snapshot_id

    def observed_compose_asset_snapshot(
        self,
        *,
        asset_kind: str,
        project_name: str,
        working_dir: str | None,
    ) -> str:
        token = uuid.uuid4().hex
        snapshot_id = "asset-snapshot-" + token
        asset_id = f"{asset_kind}-{token}"
        now = utc_timestamp()
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction(revision_kind="observation") as connection:
                connection.execute(
                    """
                    INSERT INTO observation_snapshots(
                        snapshot_id, host_id, observer_domain, status,
                        material_fingerprint, started_at, completed_at
                    ) VALUES (?, ?, 'host-runtime-v2:full-docker', 'completed',
                              ?, ?, ?)
                    """,
                    (snapshot_id, HOST, "material-" + token, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO observation_capabilities(
                        snapshot_id, observer_domain, docker_available,
                        capability_fingerprint, committed_at
                    ) VALUES (?, 'host-runtime-v2:full-docker', 1, ?, ?)
                    """,
                    (snapshot_id, "capability-" + token, now),
                )
                connection.execute(
                    """
                    INSERT INTO broker_observation_compose_scope(
                        snapshot_id, assets_complete, observed_asset_count,
                        evidence_fingerprint, recorded_at
                    ) VALUES (?, 1, 1, ?, ?)
                    """,
                    (snapshot_id, "scope-" + token, now),
                )
                connection.execute(
                    """
                    INSERT INTO broker_observed_compose_assets(
                        snapshot_id, asset_kind, asset_id, project_name,
                        working_dir, observation_fingerprint
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        snapshot_id,
                        asset_kind,
                        asset_id,
                        project_name,
                        working_dir,
                        "asset-" + token,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO observation_snapshot_resources(
                        snapshot_id, resource_kind, resource_id,
                        observation_fingerprint
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (snapshot_id, asset_kind, asset_id, "asset-" + token),
                )
        return snapshot_id

    def snapshot_evidence(self, snapshot_id: str) -> Mapping[str, Any]:
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.read_transaction() as connection:
                row = connection.execute(
                    """
                    SELECT snapshot.observer_domain,
                           snapshot.material_fingerprint,
                           snapshot.started_at,
                           snapshot.completed_at,
                           capability.docker_available,
                           capability.capability_fingerprint
                    FROM observation_snapshots snapshot
                    JOIN observation_capabilities capability USING(snapshot_id)
                    WHERE snapshot.snapshot_id = ?
                    """,
                    (snapshot_id,),
                ).fetchone()
        if row is None:
            raise AssertionError("fixture snapshot was not committed")
        return {
            "snapshot_id": snapshot_id,
            "observer_domain": str(row["observer_domain"]),
            "docker_available": bool(row["docker_available"]),
            "capability_fingerprint": str(row["capability_fingerprint"]),
            "material_fingerprint": str(row["material_fingerprint"]),
            "started_at": str(row["started_at"]),
            "completed_at": str(row["completed_at"]),
        }


def service_for(
    fixture: ExtendedBrokerFixture,
    *,
    port_probe: Optional[Callable[[int, str], bool]] = None,
    compose_runner: Optional[
        Callable[
            [tuple[str, ...], str, float, Mapping[str, str]],
            subprocess.CompletedProcess[str],
        ]
    ] = None,
    compose_model_renderer: Optional[Callable[..., bytes]] = None,
    observer: Optional[Callable[[CoordinatorStore], Mapping[str, Any]]] = None,
) -> tuple[BrokerService, LocalBrokerHostMutations]:
    host = LocalBrokerHostMutations(
        docker_executable="/trusted/docker",
        port_probe=port_probe or (lambda _port, _protocol: True),
        compose_runner=compose_runner,
        compose_model_renderer=(
            rendered_fixture_model
            if compose_model_renderer is None
            else compose_model_renderer
        ),
    )
    backend = StoreBackedMutationBackend(
        fixture.persistence,
        host,
        observe_before_lifecycle_plan=observer or fixture.observe_full_docker,
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

    def test_never_started_enrolled_server_is_current_but_bare_definition_is_not(self) -> None:
        orphan_id = "server-bare-orphan"
        timestamp = utc_timestamp()
        with CoordinatorStore.open(
            self.fixture.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO server_definitions(
                        server_definition_id, repo_id, name, cwd,
                        definition_fingerprint, generation,
                        created_at, updated_at
                    ) VALUES (?, ?, 'bare-orphan', ?, ?, 0, ?, ?)
                    """,
                    (
                        orphan_id,
                        REPO_ALPHA,
                        str(self.fixture.alpha_root),
                        "definition-" + orphan_id,
                        timestamp,
                        timestamp,
                    ),
                )
        self.fixture.persistence.replace_server_access(
            uid=os.geteuid(),
            repo_id=REPO_ALPHA,
            server_definition_ids=(SERVER_ALPHA,),
            start_port=43_100,
            end_port=43_199,
        )

        with AccountStore.open(
            self.fixture.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            graph = store.inventory_v2()

        server_ids = {
            item["server_definition_id"]
            for item in graph["resources"]["servers"]
        }
        self.assertIn(
            SERVER_ALPHA,
            server_ids,
            "false-positive guard: exact broker enrollment keeps a never-started server usable",
        )
        self.assertNotIn(
            orphan_id,
            server_ids,
            "must-catch: a bare durable definition is history, not a current worker",
        )
        usage = next(
            item
            for item in graph["v1_compatibility"]["project_usage"]
            if item["project"] == str(self.fixture.alpha_root)
        )
        self.assertIn(SERVER_ALPHA, usage["server_ids"])
        self.assertNotIn(orphan_id, usage["server_ids"])

    def test_enrollment_compose_failure_precedes_all_authority_and_profile_mutation(
        self,
    ) -> None:
        (self.fixture.alpha_root / ".git").mkdir()
        database = self.fixture.root / "preflight.sqlite3"
        profile = self.fixture.root / "preflight-profile.json"
        database.write_bytes(b"prior-authority")
        profile.write_bytes(b"prior-profile")

        def fail_renderer(**_arguments: object) -> bytes:
            raise RuntimeError("fixture renderer rejected the model")

        with (
            mock.patch.object(broker_enrollment.os, "geteuid", return_value=0),
            mock.patch.object(
                broker_enrollment,
                "BrokerPersistence",
                side_effect=AssertionError("authority opened before preflight"),
            ),
            self.assertRaisesRegex(RuntimeError, "renderer rejected"),
        ):
            broker_enrollment.enroll_repository(
                database_path=database,
                socket_path=self.fixture.root / "broker.sock",
                socket_gid=0,
                client_uid=os.geteuid(),
                account_id="account-preflight",
                canonical_root=str(self.fixture.alpha_root),
                servers=(),
                port_start=41_000,
                port_end=41_010,
                profile_path=profile,
                compose={
                    "declared": True,
                    "files": [str(self.fixture.compose_one)],
                    "services": ["web"],
                    "project_name": "preflight-stack",
                },
                compose_model_renderer=fail_renderer,
                observe_host=lambda _store: {},
            )
        self.assertEqual(database.read_bytes(), b"prior-authority")
        self.assertEqual(profile.read_bytes(), b"prior-profile")

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
        restarted_assignment_service, _ = service_for(self.fixture, port_probe=probe)
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
        self.assertEqual(conflict_reply["error"]["code"], "port_assignment_conflict")

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

    def test_enrollment_container_grants_require_exact_snapshot_and_current_membership(
        self,
    ) -> None:
        snapshot_id = self.fixture.observed_compose_snapshot(
            owner_repo_id=REPO_ALPHA,
            project_name="alpha-stack",
        )

        granted = broker_enrollment._grant_observed_containers(
            self.fixture.persistence,
            repo_id=REPO_ALPHA,
            client_uid=os.geteuid(),
            snapshot_id=snapshot_id,
        )

        self.assertEqual(len(set(granted.values())), 1)
        resource_id = next(iter(granted.values()))
        self.fixture.persistence.revoke_observation_derived_access(
            uid=os.geteuid(),
            repo_id=REPO_ALPHA,
            containers=True,
        )
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    DELETE FROM repository_memberships
                    WHERE repo_id = ? AND host_resource_id = ?
                    """,
                    (REPO_ALPHA, resource_id),
                )

        with self.assertRaisesRegex(RuntimeError, "membership"):
            broker_enrollment._grant_observed_containers(
                self.fixture.persistence,
                repo_id=REPO_ALPHA,
                client_uid=os.geteuid(),
                snapshot_id=snapshot_id,
            )
        with self.assertRaisesRegex(RuntimeError, "exact completed"):
            broker_enrollment._grant_observed_containers(
                self.fixture.persistence,
                repo_id=REPO_ALPHA,
                client_uid=os.geteuid(),
                snapshot_id="snapshot-not-returned-by-enrollment",
            )
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.read_transaction() as connection:
                enabled = connection.execute(
                    """
                    SELECT count(*) FROM broker_resource_acl
                    WHERE uid = ? AND repo_id = ?
                      AND resource_kind = 'container' AND enabled = 1
                    """,
                    (os.geteuid(), REPO_ALPHA),
                ).fetchone()[0]
        self.assertEqual(enabled, 0)

    def test_reenrollment_reuses_identity_when_compose_file_set_changes(self) -> None:
        override = self.fixture.alpha_root / "compose.reenrolled.yml"
        override.write_text("services: {}\n", encoding="utf-8")
        compose_id = broker_enrollment._provision_compose(
            self.fixture.persistence,
            repo_id=REPO_ALPHA,
            client_uid=os.geteuid(),
            root=self.fixture.alpha_root,
            compose={
                "declared": True,
                "files": [str(self.fixture.compose_one), str(override)],
                "services": ["db", "api"],
                "project_name": "alpha-stack",
            },
        )
        self.assertEqual(compose_id, COMPOSE_ALPHA)
        definition = self.fixture.persistence.list_compose_definitions(
            repo_id=REPO_ALPHA
        )[0]
        self.assertEqual(
            definition["files"],
            [str(self.fixture.compose_one), str(override)],
        )
        self.assertEqual(definition["services"], ["db", "api"])
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.read_transaction() as connection:
                grants = list(
                    connection.execute(
                        """
                        SELECT operation, enabled FROM broker_compose_acl
                        WHERE uid = ? AND repo_id = ?
                          AND compose_definition_id = ?
                        ORDER BY operation
                        """,
                        (os.geteuid(), REPO_ALPHA, COMPOSE_ALPHA),
                    )
                )
        self.assertEqual(
            {str(row["operation"]) for row in grants if bool(row["enabled"])},
            {
                "compose.up",
                "compose.stop",
                "compose.restart",
                "compose.down",
            },
        )

    def test_running_operation_blocks_definition_reprovision_race(self) -> None:
        reprovision_errors: list[str] = []

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del cwd, timeout, environment
            try:
                self.fixture.persistence.provision_compose_definition(
                    repo_id=REPO_ALPHA,
                    compose_definition_id=COMPOSE_ALPHA,
                    cwd=self.fixture.alpha_root,
                    files=(self.fixture.compose_one,),
                    services=("changed",),
                    project_name="alpha-stack",
                )
            except BrokerError as exc:
                reprovision_errors.append(exc.code)
            try:
                self.fixture.persistence.disable_repository_compose(repo_id=REPO_ALPHA)
            except BrokerError as exc:
                reprovision_errors.append(exc.code)
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        service, _ = service_for(self.fixture, compose_runner=runner)
        request = self.fixture.request(
            BrokerOperation.COMPOSE_UP,
            resource_id=COMPOSE_ALPHA,
        )
        reply = service.reply_for_document(self.fixture.peer(), request.to_wire())
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(
            reprovision_errors,
            ["compose_operation_pending", "compose_operation_pending"],
        )
        definition = self.fixture.persistence.list_compose_definitions(
            repo_id=REPO_ALPHA
        )[0]
        self.assertEqual(definition["services"], ["db", "web"])
        self.assertTrue(definition["enabled"])

    def test_reenrollment_without_compose_revokes_old_opaque_authority(self) -> None:
        removed = broker_enrollment._provision_compose(
            self.fixture.persistence,
            repo_id=REPO_ALPHA,
            client_uid=os.geteuid(),
            root=self.fixture.alpha_root,
            compose=None,
        )
        self.assertIsNone(removed)
        definition = self.fixture.persistence.list_compose_definitions(
            repo_id=REPO_ALPHA
        )[0]
        self.assertFalse(definition["enabled"])
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.read_transaction() as connection:
                enabled_grants = connection.execute(
                    """
                    SELECT count(*) FROM broker_compose_acl
                    WHERE repo_id = ? AND enabled = 1
                    """,
                    (REPO_ALPHA,),
                ).fetchone()[0]
        self.assertEqual(enabled_grants, 0)
        request = self.fixture.request(
            BrokerOperation.COMPOSE_DOWN,
            resource_id=COMPOSE_ALPHA,
        )
        with self.assertRaises(BrokerError):
            self.fixture.persistence.authorize(self.fixture.peer(), request)

    def test_project_name_change_requires_old_observed_resources_retired(
        self,
    ) -> None:
        snapshot_id = self.fixture.observed_compose_snapshot(
            owner_repo_id=REPO_ALPHA,
            project_name="alpha-stack",
        )
        with self.assertRaisesRegex(BrokerError, "old Compose project name"):
            broker_enrollment._provision_compose(
                self.fixture.persistence,
                repo_id=REPO_ALPHA,
                client_uid=os.geteuid(),
                root=self.fixture.alpha_root,
                compose={
                    "declared": True,
                    "files": [str(self.fixture.compose_one)],
                    "services": ["db"],
                    "project_name": "renamed-stack",
                },
                observation_snapshot_id=snapshot_id,
            )
        definition = self.fixture.persistence.list_compose_definitions(
            repo_id=REPO_ALPHA
        )[0]
        self.assertEqual(definition["project_name"], "alpha-stack")

    def test_foreign_retained_network_or_volume_blocks_project_name(self) -> None:
        beta_compose = self.fixture.beta_root / "compose.yml"
        beta_compose.write_text("services: {}\n", encoding="utf-8")
        for asset_kind in ("network", "volume"):
            with self.subTest(asset_kind=asset_kind):
                snapshot_id = self.fixture.observed_compose_asset_snapshot(
                    asset_kind=asset_kind,
                    project_name="beta-stack",
                    working_dir=None,
                )
                with self.assertRaisesRegex(BrokerError, "no prior broker definition"):
                    self.fixture.persistence.provision_compose_definition(
                        repo_id=REPO_BETA,
                        compose_definition_id="compose-beta",
                        cwd=self.fixture.beta_root,
                        files=(beta_compose,),
                        services=("db",),
                        project_name="beta-stack",
                        observation_snapshot_id=snapshot_id,
                    )

    def test_same_repository_retained_asset_is_valid_collision_control(self) -> None:
        snapshot_id = self.fixture.observed_compose_asset_snapshot(
            asset_kind="volume",
            project_name="alpha-stack",
            working_dir=None,
        )
        result = self.fixture.persistence.provision_compose_definition(
            repo_id=REPO_ALPHA,
            compose_definition_id=COMPOSE_ALPHA,
            cwd=self.fixture.alpha_root,
            files=(self.fixture.compose_one,),
            services=("db",),
            project_name="alpha-stack",
            observation_snapshot_id=snapshot_id,
        )
        self.assertEqual(result["compose_definition_id"], COMPOSE_ALPHA)

    def test_retired_empty_project_name_can_transfer_to_another_repository(
        self,
    ) -> None:
        self.fixture.persistence.disable_repository_compose(repo_id=REPO_ALPHA)
        beta_compose = self.fixture.beta_root / "compose.yml"
        beta_compose.write_text("services: {}\n", encoding="utf-8")
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE broker_compose_acl
                    SET enabled = 1
                    WHERE compose_definition_id = ?
                      AND operation IN ('compose.stop', 'compose.down')
                    """,
                    (COMPOSE_ALPHA,),
                )
            evidence = self.fixture.observe_full_docker(store)
        with mock.patch.object(
            broker_persistence, "_service_administrator_uid", return_value=0
        ):
            released = self.fixture.persistence.release_compose_project_name(
                compose_definition_id=COMPOSE_ALPHA,
                observation_evidence=evidence,
                actor_uid=0,
            )
        self.assertFalse(released["claimed"])
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.read_transaction() as connection:
                active_acl_count = int(
                    connection.execute(
                        "SELECT count(*) FROM broker_compose_acl "
                        "WHERE compose_definition_id = ? AND enabled = 1",
                        (COMPOSE_ALPHA,),
                    ).fetchone()[0]
                )
        self.assertEqual(active_acl_count, 0)
        self.fixture.persistence.provision_compose_definition(
            repo_id=REPO_BETA,
            compose_definition_id="compose-beta",
            cwd=self.fixture.beta_root,
            files=(beta_compose,),
            services=("api",),
            project_name="alpha-stack",
            observation_snapshot_id=str(evidence["snapshot_id"]),
        )
        self.fixture.persistence.grant_resource(
            uid=os.geteuid(),
            repo_id=REPO_BETA,
            resource_kind="compose",
            resource_id="compose-beta",
            operation=BrokerOperation.COMPOSE_UP,
        )

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del cwd, timeout, environment
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        service, _ = service_for(self.fixture, compose_runner=runner)
        request = self.fixture.request(
            BrokerOperation.COMPOSE_UP,
            repo_id=REPO_BETA,
            resource_id="compose-beta",
        )
        reply = service.reply_for_document(self.fixture.peer(), request.to_wire())
        self.assertTrue(reply["ok"], reply)

    def test_project_name_release_requires_root_and_exact_complete_empty_evidence(
        self,
    ) -> None:
        self.fixture.persistence.disable_repository_compose(repo_id=REPO_ALPHA)
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            evidence = dict(self.fixture.observe_full_docker(store))

        with self.assertRaisesRegex(PermissionError, "root service administrator"):
            self.fixture.persistence.release_compose_project_name(
                compose_definition_id=COMPOSE_ALPHA,
                observation_evidence=evidence,
                actor_uid=os.geteuid(),
            )

        tampered = dict(evidence)
        tampered["material_fingerprint"] = "tampered"
        with (
            mock.patch.object(
                broker_persistence, "_service_administrator_uid", return_value=0
            ),
            self.assertRaisesRegex(BrokerError, "exact fresh full-Docker"),
        ):
            self.fixture.persistence.release_compose_project_name(
                compose_definition_id=COMPOSE_ALPHA,
                observation_evidence=tampered,
                actor_uid=0,
            )

        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            wrong_host_evidence = dict(self.fixture.observe_full_docker(store))
            now = utc_timestamp()
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO hosts(
                        host_id, machine_fingerprint, platform, hostname,
                        created_at, updated_at
                    ) VALUES ('foreign-host', 'foreign-machine', 'test',
                              'foreign', ?, ?)
                    """,
                    (now, now),
                )
                connection.execute(
                    "UPDATE observation_snapshots SET host_id = 'foreign-host' "
                    "WHERE snapshot_id = ?",
                    (wrong_host_evidence["snapshot_id"],),
                )
        with (
            mock.patch.object(
                broker_persistence, "_service_administrator_uid", return_value=0
            ),
            self.assertRaisesRegex(BrokerError, "exact fresh full-Docker"),
        ):
            self.fixture.persistence.release_compose_project_name(
                compose_definition_id=COMPOSE_ALPHA,
                observation_evidence=wrong_host_evidence,
                actor_uid=0,
            )

        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "DELETE FROM broker_observation_compose_scope "
                    "WHERE snapshot_id = ?",
                    (evidence["snapshot_id"],),
                )
        with (
            mock.patch.object(
                broker_persistence, "_service_administrator_uid", return_value=0
            ),
            self.assertRaisesRegex(BrokerError, "exhaustive Compose"),
        ):
            self.fixture.persistence.release_compose_project_name(
                compose_definition_id=COMPOSE_ALPHA,
                observation_evidence=evidence,
                actor_uid=0,
            )

    def test_project_name_release_rejects_retained_resources_and_unresolved_work(
        self,
    ) -> None:
        self.fixture.persistence.disable_repository_compose(repo_id=REPO_ALPHA)
        container_snapshot = self.fixture.observed_compose_snapshot(
            owner_repo_id=REPO_ALPHA,
            project_name="alpha-stack",
        )
        container_evidence = self.fixture.snapshot_evidence(container_snapshot)
        with (
            mock.patch.object(
                broker_persistence, "_service_administrator_uid", return_value=0
            ),
            self.assertRaisesRegex(BrokerError, "observed host resources"),
        ):
            self.fixture.persistence.release_compose_project_name(
                compose_definition_id=COMPOSE_ALPHA,
                observation_evidence=container_evidence,
                actor_uid=0,
            )

        for asset_kind in ("network", "volume"):
            retained_snapshot = self.fixture.observed_compose_asset_snapshot(
                asset_kind=asset_kind,
                project_name="alpha-stack",
                working_dir=str(self.fixture.alpha_root),
            )
            retained_evidence = self.fixture.snapshot_evidence(retained_snapshot)
            with (
                self.subTest(asset_kind=asset_kind),
                mock.patch.object(
                    broker_persistence,
                    "_service_administrator_uid",
                    return_value=0,
                ),
                self.assertRaisesRegex(BrokerError, "retained network or volume"),
            ):
                self.fixture.persistence.release_compose_project_name(
                    compose_definition_id=COMPOSE_ALPHA,
                    observation_evidence=retained_evidence,
                    actor_uid=0,
                )

        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            clean_evidence = self.fixture.observe_full_docker(store)
            now = utc_timestamp()
            operation_id = "release-blocker-" + uuid.uuid4().hex
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO operations(
                        operation_id, repo_id, kind, status, phase,
                        request_fingerprint, actor, created_at, updated_at
                    ) VALUES (?, ?, 'broker.compose.down', 'running',
                              'host_invoked', 'fixture', 'fixture', ?, ?)
                    """,
                    (operation_id, REPO_ALPHA, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO operation_targets(
                        operation_id, ordinal, target_kind, target_id,
                        action, immutable_fingerprint, phase, status
                    ) VALUES (?, 0, 'compose', ?, 'compose.down',
                              'fixture', 'host_invoked', 'running')
                    """,
                    (operation_id, COMPOSE_ALPHA),
                )
        with (
            mock.patch.object(
                broker_persistence, "_service_administrator_uid", return_value=0
            ),
            self.assertRaisesRegex(BrokerError, "completion or reconciliation"),
        ):
            self.fixture.persistence.release_compose_project_name(
                compose_definition_id=COMPOSE_ALPHA,
                observation_evidence=clean_evidence,
                actor_uid=0,
            )

    def test_transitive_compose_include_is_rejected_before_provisioning(self) -> None:
        included = self.fixture.alpha_root / "included.yml"
        included.write_text("services: {}\n", encoding="utf-8")
        unsafe = self.fixture.alpha_root / "unsafe-compose.yml"
        unsafe.write_text(
            "include:\n  - included.yml\nservices: {}\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "unsupported transitive key"):
            broker_enrollment._provision_compose(
                self.fixture.persistence,
                repo_id=REPO_ALPHA,
                client_uid=os.geteuid(),
                root=self.fixture.alpha_root,
                compose={
                    "declared": True,
                    "files": [str(unsafe)],
                    "services": ["db"],
                    "project_name": "alpha-stack",
                },
            )

    def test_parsed_transitive_keys_cannot_hide_behind_json_escaping(self) -> None:
        payload = ('{"services":{"web":{"\\u0065nv_file":["runtime.env"]}}}').encode(
            "utf-8"
        )
        with self.assertRaisesRegex(ValueError, "env_file"):
            require_sealable_compose_payload(payload)

    def test_block_scalar_key_text_is_not_misclassified_as_compose_input(self) -> None:
        require_sealable_compose_payload(
            b"""services:
  web:
    image: example.invalid/app@sha256:deadbeef
    command: |
      env_file: this is command text, not a mapping key
"""
        )

    def test_transitive_key_names_are_allowed_only_in_nonstructural_positions(
        self,
    ) -> None:
        require_sealable_compose_payload(
            b"""services:
  build:
    image: example.invalid/build@sha256:deadbeef
    environment:
      secrets: literal-value
      configs: literal-value
    labels:
      build: literal-value
x-metadata:
  env_file: documentation-only
volumes:
  configs: {}
"""
        )
        for label, payload in (
            ("top-level configs", b"services: {}\nconfigs: {}\n"),
            ("top-level secrets", b"services: {}\nsecrets: {}\n"),
            (
                "service build",
                b"services:\n  web:\n    build: .\n",
            ),
            (
                "service secrets",
                b"services:\n  web:\n    secrets: [token]\n",
            ),
        ):
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(ValueError, "unsupported transitive key"),
            ):
                require_sealable_compose_payload(payload)

    def test_yaml_aliases_and_duplicate_keys_fail_closed(self) -> None:
        with self.subTest("alias"):
            with self.assertRaisesRegex(ValueError, "strict safe YAML"):
                require_sealable_compose_payload(
                    b"defaults: &defaults\n  image: app\nservices:\n  web: *defaults\n"
                )
        with self.subTest("duplicate"):
            with self.assertRaisesRegex(ValueError, "strict safe YAML"):
                require_sealable_compose_payload(
                    b"services:\n  web:\n    image: one\n  web:\n    image: two\n"
                )
        with self.subTest("json duplicate"):
            with self.assertRaisesRegex(ValueError, "duplicate.*key"):
                require_sealable_compose_payload(
                    b'{"services":{},"services":{"web":{"image":"two"}}}'
                )
        with self.subTest("tagged non-string key"):
            with self.assertRaisesRegex(ValueError, "mapping keys must be strings"):
                require_sealable_compose_payload(
                    b"services:\n  web:\n    !!binary ZW52X2ZpbGU=: runtime.env\n"
                )
        with self.subTest("set scalar"):
            with self.assertRaisesRegex(ValueError, "unsupported scalar"):
                require_sealable_compose_payload(
                    b"services:\n  web:\n    command: !!set {one: null}\n"
                )
        with self.subTest("timestamp scalar"):
            with self.assertRaisesRegex(ValueError, "unsupported scalar"):
                require_sealable_compose_payload(
                    b"services:\n  web:\n    command: 2026-07-19\n"
                )
        with self.subTest("non-finite JSON"):
            with self.assertRaisesRegex(ValueError, "non-finite"):
                require_sealable_compose_payload(
                    b'{"services":{"web":{"command":NaN}}}'
                )
        with self.subTest("deep YAML"):
            nested = "value"
            for _index in range(140):
                nested = "- " + nested
            with self.assertRaisesRegex(ValueError, "strict safe YAML"):
                require_sealable_compose_payload(
                    ("services:\n  web:\n    command: " + nested + "\n").encode()
                )

    def test_effective_model_requires_exact_services_profiles_and_bounded_scale(
        self,
    ) -> None:
        valid = json.dumps(
            {
                "services": {
                    "db": {"image": "postgres:17"},
                    "web": {
                        "image": "example.invalid/web:test",
                        "profiles": ["display"],
                        "depends_on": {"db": {"condition": "service_started"}},
                        "volumes": [
                            {
                                "type": "volume",
                                "source": "web-data",
                                "target": "/data",
                            }
                        ],
                    },
                },
                "volumes": {"web-data": {}},
            }
        ).encode()
        evidence = require_effective_compose_model(
            valid,
            declared_services=("db", "web"),
            declared_profiles=("display",),
            project_name="alpha-stack",
            host_access_approved=False,
        )
        self.assertEqual(evidence.services, ("db", "web"))
        self.assertEqual(evidence.host_access_risks, ())
        self.assertEqual(evidence.replica_budget, 2)

        with self.assertRaisesRegex(ValueError, "exactly match"):
            require_effective_compose_model(
                valid,
                declared_services=("web",),
                declared_profiles=("display",),
                project_name="alpha-stack",
                host_access_approved=False,
            )
        with self.assertRaisesRegex(ValueError, "profile is absent"):
            require_effective_compose_model(
                valid,
                declared_services=("db", "web"),
                declared_profiles=("capture",),
                project_name="alpha-stack",
                host_access_approved=False,
            )
        oversized = json.dumps(
            {
                "services": {
                    "web": {
                        "image": "example.invalid/web:test",
                        "deploy": {"replicas": 17},
                    }
                }
            }
        ).encode()
        with self.assertRaisesRegex(ValueError, "replicas must be bounded"):
            require_effective_compose_model(
                oversized,
                declared_services=("web",),
                declared_profiles=(),
                project_name="alpha-stack",
                host_access_approved=True,
            )
        zero = json.dumps(
            {"services": {"web": {"image": "example.invalid/web:test", "scale": 0}}}
        ).encode()
        with self.assertRaisesRegex(ValueError, "one through 16"):
            require_effective_compose_model(
                zero,
                declared_services=("web",),
                declared_profiles=(),
                project_name="alpha-stack",
                host_access_approved=True,
            )

    def test_effective_model_fails_closed_for_cross_host_and_future_features(
        self,
    ) -> None:
        cases = {
            "api socket": ({"use_api_socket": True}, "docker_socket"),
            "container volumes": (
                {"volumes_from": ["container:foreign:ro"]},
                "external_container_reference",
            ),
            "container namespace": (
                {"network_mode": "container:foreign"},
                "external_container_reference",
            ),
            "gpu": ({"gpus": "all"}, "gpu_access"),
            "device reservation": (
                {
                    "deploy": {
                        "resources": {
                            "reservations": {
                                "devices": [
                                    {"driver": "nvidia", "capabilities": [["gpu"]]}
                                ]
                            }
                        }
                    }
                },
                "host_devices",
            ),
            "published port": (
                {
                    "ports": [
                        {"target": 8080, "published": "25001", "host_ip": "127.0.0.1"}
                    ]
                },
                "published_host_ports",
            ),
        }
        for label, (service_fields, expected_risk) in cases.items():
            with self.subTest(label=label):
                payload = json.dumps(
                    {
                        "services": {
                            "web": {
                                "image": "example.invalid/web:test",
                                **service_fields,
                            }
                        }
                    }
                ).encode()
                with self.assertRaisesRegex(PermissionError, "explicit administrator"):
                    require_effective_compose_model(
                        payload,
                        declared_services=("web",),
                        declared_profiles=(),
                        project_name="alpha-stack",
                        host_access_approved=False,
                    )
                evidence = require_effective_compose_model(
                    payload,
                    declared_services=("web",),
                    declared_profiles=(),
                    project_name="alpha-stack",
                    host_access_approved=True,
                )
                self.assertIn(expected_risk, evidence.host_access_risks)

        external = json.dumps(
            {
                "services": {
                    "web": {
                        "image": "example.invalid/web:test",
                        "networks": {"shared": None},
                        "volumes": [
                            {"type": "volume", "source": "shared", "target": "/data"}
                        ],
                    }
                },
                "networks": {"shared": {"external": True}},
                "volumes": {"shared": {"external": True}},
            }
        ).encode()
        evidence = require_effective_compose_model(
            external,
            declared_services=("web",),
            declared_profiles=(),
            project_name="alpha-stack",
            host_access_approved=True,
        )
        self.assertIn("external_network", evidence.host_access_risks)
        self.assertIn("external_volume", evidence.host_access_risks)
        with self.assertRaises(PermissionError):
            require_effective_compose_model(
                external,
                declared_services=("web",),
                declared_profiles=(),
                project_name="alpha-stack",
                host_access_approved=False,
            )

        safe_internal = json.dumps(
            {
                "name": "alpha-stack",
                "services": {
                    "web": {
                        "image": "example.invalid/web:test",
                        "networks": {"internal": None},
                        "volumes": [
                            {"type": "volume", "source": "data", "target": "/data"}
                        ],
                    }
                },
                "networks": {"internal": {"internal": True}},
                "volumes": {"data": {}},
            }
        ).encode()
        safe = require_effective_compose_model(
            safe_internal,
            declared_services=("web",),
            declared_profiles=(),
            project_name="alpha-stack",
            host_access_approved=False,
        )
        self.assertEqual(safe.host_access_risks, ())

        unknown = json.dumps(
            {"services": {"web": {"image": "x", "future_root_escape": True}}}
        ).encode()
        with self.assertRaisesRegex(ValueError, "unsupported keys"):
            require_effective_compose_model(
                unknown,
                declared_services=("web",),
                declared_profiles=(),
                project_name="alpha-stack",
                host_access_approved=True,
            )
        mismatched_name = json.dumps(
            {"name": "foreign", "services": {"web": {"image": "x"}}}
        ).encode()
        with self.assertRaisesRegex(ValueError, "project name"):
            require_effective_compose_model(
                mismatched_name,
                declared_services=("web",),
                declared_profiles=(),
                project_name="alpha-stack",
                host_access_approved=False,
            )

    def test_effective_model_host_access_needs_fingerprint_bound_admin_approval(
        self,
    ) -> None:
        risky = json.dumps(
            {
                "services": {
                    "web": {
                        "image": "example.invalid/web:test",
                        "privileged": True,
                        "network_mode": "host",
                        "volumes": [
                            {
                                "type": "bind",
                                "source": "/var/run/docker.sock",
                                "target": "/var/run/docker.sock",
                            }
                        ],
                    }
                }
            }
        ).encode()
        with self.assertRaisesRegex(PermissionError, "explicit administrator"):
            require_effective_compose_model(
                risky,
                declared_services=("web",),
                declared_profiles=(),
                project_name="alpha-stack",
                host_access_approved=False,
            )
        evidence = require_effective_compose_model(
            risky,
            declared_services=("web",),
            declared_profiles=(),
            project_name="alpha-stack",
            host_access_approved=True,
        )
        self.assertEqual(
            evidence.host_access_risks,
            (
                "docker_socket",
                "host_bind_mount",
                "host_namespace",
                "privileged",
            ),
        )

        self.fixture.persistence.compose_model_renderer = lambda **_arguments: risky
        with self.assertRaisesRegex(PermissionError, "explicit administrator"):
            self.fixture.persistence.provision_compose_definition(
                repo_id=REPO_ALPHA,
                compose_definition_id=COMPOSE_ALPHA,
                cwd=self.fixture.alpha_root,
                files=(self.fixture.compose_one,),
                services=("web",),
                project_name="alpha-stack",
            )
        with mock.patch.object(
            broker_persistence, "_service_administrator_uid", return_value=0
        ):
            approved = self.fixture.persistence.provision_compose_definition(
                repo_id=REPO_ALPHA,
                compose_definition_id=COMPOSE_ALPHA,
                cwd=self.fixture.alpha_root,
                files=(self.fixture.compose_one,),
                services=("web",),
                project_name="alpha-stack",
                host_access_approved=True,
            )
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.read_transaction() as connection:
                row = connection.execute(
                    """
                    SELECT evidence.definition_fingerprint,
                           evidence.host_access_approved,
                           evidence.approved_by_uid,
                           evidence.host_access_risks_json,
                           definition.definition_fingerprint AS current_fingerprint
                    FROM broker_compose_effective_model_evidence evidence
                    JOIN broker_compose_definitions definition
                      USING(compose_definition_id)
                    WHERE compose_definition_id = ?
                    """,
                    (COMPOSE_ALPHA,),
                ).fetchone()
        self.assertEqual(approved["definition_fingerprint"], row["current_fingerprint"])
        self.assertEqual(row["definition_fingerprint"], row["current_fingerprint"])
        self.assertEqual(row["host_access_approved"], 1)
        self.assertEqual(row["approved_by_uid"], 0)
        self.assertIn("docker_socket", json.loads(row["host_access_risks_json"]))

    def test_effective_renderer_seals_inputs_and_overrides_compose_controls(
        self,
    ) -> None:
        captured: dict[str, object] = {}

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            normalized, env_payloads, compose_payloads, paths = (
                capture_sealed_compose_command(command)
            )
            captured.update(
                command=normalized,
                cwd=cwd,
                timeout=timeout,
                environment=dict(environment),
                env_payloads=env_payloads,
                compose_payloads=compose_payloads,
                paths=paths,
            )
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps(
                    {"services": {"web": {"image": "example.invalid/web:test"}}}
                ),
                stderr="",
            )

        payload = broker_host.render_compose_effective_model(
            compose_payloads=(
                b"services:\n  web:\n    image: example.invalid/web:test\n",
            ),
            env_payloads=(b"IMAGE_TAG=test\nCOMPOSE_REMOVE_ORPHANS=1\n",),
            profiles=(),
            declared_services=("web",),
            project_name="alpha-stack",
            pinned_cwd=str(self.fixture.alpha_root),
            docker_executable="/trusted/docker",
            runner=runner,
        )
        self.assertIn(b'"web"', payload)
        self.assertEqual(
            captured["env_payloads"],
            (b"", b"IMAGE_TAG=test\nCOMPOSE_REMOVE_ORPHANS=1\n"),
        )
        environment = captured["environment"]
        self.assertIsInstance(environment, dict)
        self.assertEqual(environment["COMPOSE_REMOVE_ORPHANS"], "0")
        self.assertEqual(environment["COMPOSE_PARALLEL_LIMIT"], "4")
        self.assertEqual(captured["command"][-3:], ("config", "--format", "json"))
        self.assertTrue(all(not Path(path).exists() for path in captured["paths"]))

    def test_effective_renderer_default_path_invokes_the_bounded_runner(self) -> None:
        completed = subprocess.CompletedProcess(
            ("/trusted/docker",),
            0,
            stdout=json.dumps(
                {"services": {"web": {"image": "example.invalid/web:test"}}}
            ),
            stderr="",
        )
        with mock.patch.object(
            broker_host.subprocess, "run", return_value=completed
        ) as run:
            payload = broker_host.render_compose_effective_model(
                compose_payloads=(
                    b"services:\n  web:\n    image: example.invalid/web:test\n",
                ),
                env_payloads=(),
                profiles=(),
                declared_services=("web",),
                project_name="alpha-stack",
                pinned_cwd=str(self.fixture.alpha_root),
                docker_executable="/trusted/docker",
            )
        self.assertIn(b'"web"', payload)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.kwargs["cwd"], str(self.fixture.alpha_root))
        self.assertEqual(run.call_args.kwargs["env"]["COMPOSE_DISABLE_ENV_FILE"], "1")

    def test_startup_disables_legacy_definition_with_empty_service_scope(self) -> None:
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "DELETE FROM broker_compose_services WHERE compose_definition_id = ?",
                    (COMPOSE_ALPHA,),
                )
        migrated = BrokerPersistence(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        )
        definition = migrated.list_compose_definitions(repo_id=REPO_ALPHA)[0]
        self.assertFalse(definition["enabled"])
        with CoordinatorStore.open(
            migrated.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.read_transaction() as connection:
                enabled_grants = connection.execute(
                    """
                    SELECT count(*) FROM broker_compose_acl
                    WHERE compose_definition_id = ? AND enabled = 1
                    """,
                    (COMPOSE_ALPHA,),
                ).fetchone()[0]
        self.assertEqual(enabled_grants, 0)

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
        environments: list[dict[str, str]] = []
        environment_payloads: list[tuple[bytes, ...]] = []
        compose_payloads: list[tuple[bytes, ...]] = []
        snapshot_paths: list[tuple[str, ...]] = []

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            normalized, env_files, files, paths = capture_sealed_compose_command(
                command
            )
            for path in paths:
                descriptor = os.open(path, os.O_WRONLY)
                try:
                    with self.assertRaises(OSError):
                        os.write(descriptor, b"tamper")
                finally:
                    os.close(descriptor)
            self.assertEqual(
                (os.stat(cwd).st_dev, os.stat(cwd).st_ino),
                (
                    self.fixture.alpha_root.stat().st_dev,
                    self.fixture.alpha_root.stat().st_ino,
                ),
            )
            calls.append((normalized, "<pinned-cwd>", timeout))
            environments.append(dict(environment))
            environment_payloads.append(env_files)
            compose_payloads.append(files)
            snapshot_paths.append(paths)
            return subprocess.CompletedProcess(
                command, 0, stdout="started\n", stderr=""
            )

        service, _ = service_for(self.fixture, compose_runner=runner)
        operation_id = str(uuid.uuid4())
        request = self.fixture.request(
            BrokerOperation.COMPOSE_UP,
            resource_id=COMPOSE_ALPHA,
            operation_id=operation_id,
        )
        implicit_env = self.fixture.alpha_root / ".env"
        implicit_env.write_text("UNDECLARED_FROM_DOTENV=forbidden\n", encoding="utf-8")
        with mock.patch.dict(
            os.environ,
            {
                "COMPOSE_FILE": "/untrusted/compose.yml",
                "UNDECLARED_INTERPOLATION_SECRET": "must-not-reach-compose",
            },
            clear=False,
        ):
            first = service.reply_for_document(self.fixture.peer(), request.to_wire())
        self.assertTrue(first["ok"], first)
        self.assertEqual(first["result"]["compose_definition_id"], COMPOSE_ALPHA)
        self.assertEqual(first["result"]["action"], "up")
        self.assertEqual(first["result"]["status"], "completed")
        expected = (
            "/trusted/docker",
            "compose",
            "--project-directory",
            ".",
            "--project-name",
            "alpha-stack",
            "--env-file",
            "<sealed-env-0>",
            "--file",
            "<sealed-compose-0>",
            "--file",
            "<sealed-compose-1>",
            "up",
            "--detach",
            "--no-deps",
            "db",
            "web",
        )
        self.assertEqual(calls[0][0], expected)
        self.assertEqual(calls[0][1], "<pinned-cwd>")
        self.assertGreater(calls[0][2], 0)
        self.assertEqual(
            compose_payloads[0],
            (
                self.fixture.compose_one.read_bytes(),
                self.fixture.compose_two.read_bytes(),
            ),
        )
        self.assertEqual(environments[0]["COMPOSE_DISABLE_ENV_FILE"], "1")
        self.assertEqual(environments[0]["COMPOSE_REMOVE_ORPHANS"], "0")
        self.assertEqual(environments[0]["COMPOSE_PARALLEL_LIMIT"], "4")
        self.assertEqual(environments[0]["COMPOSE_ANSI"], "never")
        self.assertEqual(environments[0]["COMPOSE_PROGRESS"], "plain")
        self.assertEqual(environments[0]["COMPOSE_STATUS_STDOUT"], "0")
        self.assertEqual(environments[0]["COMPOSE_MENU"], "0")
        self.assertEqual(environment_payloads[0], (b"",))
        self.assertNotIn("COMPOSE_FILE", environments[0])
        self.assertNotIn("UNDECLARED_INTERPOLATION_SECRET", environments[0])
        self.assertNotIn(implicit_env.read_bytes(), compose_payloads[0])
        self.assertTrue(all(not Path(path).exists() for path in snapshot_paths[0]))
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

    def test_compose_reply_uses_exact_fresh_snapshot_not_retained_container_history(self) -> None:
        historical_id = "docker-historical"
        current_id = "docker-current"
        timestamp = utc_timestamp()
        with CoordinatorStore.open(
            self.fixture.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO docker_engines(
                        engine_id, host_id, context_identity, capability_state,
                        created_at, updated_at
                    ) VALUES (
                        'engine-fixture', ?, 'fixture', 'available', ?, ?
                    )
                    """,
                    (HOST, timestamp, timestamp),
                )
                for resource_id, full_id, name in (
                    (historical_id, "a" * 64, "historical-stopped"),
                    (current_id, "b" * 64, "current-running"),
                ):
                    binding_id = "binding-" + resource_id
                    connection.execute(
                        """
                        INSERT INTO docker_resources(
                            docker_resource_id, engine_id, full_container_id,
                            current_name, image, created_at, updated_at
                        ) VALUES (?, 'engine-fixture', ?, ?, 'fixture:latest', ?, ?)
                        """,
                        (resource_id, full_id, name, timestamp, timestamp),
                    )
                    connection.execute(
                        """
                        INSERT INTO docker_observations(
                            docker_resource_id, lifecycle, health,
                            restart_policy, sampled_at, observation_fingerprint
                        ) VALUES (?, ?, 'healthy', 'unless-stopped', ?, ?)
                        """,
                        (
                            resource_id,
                            "stopped" if resource_id == historical_id else "running",
                            timestamp,
                            "observation-" + resource_id,
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO control_bindings(
                            binding_id, repo_id, resource_kind, resource_id,
                            source_id, capability, provenance, authority_state,
                            priority, generation, created_at, updated_at
                        ) VALUES (
                            ?, ?, 'container', ?, ?, 'lifecycle',
                            'docker_labels', 'authoritative', 100, 0, ?, ?
                        )
                        """,
                        (
                            binding_id,
                            REPO_ALPHA,
                            resource_id,
                            SOURCE,
                            timestamp,
                            timestamp,
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO repository_memberships(
                            membership_id, repo_id, resource_kind,
                            host_resource_id, immutable_fingerprint,
                            control_binding_id, created_at
                        ) VALUES (?, ?, 'container', ?, ?, ?, ?)
                        """,
                        (
                            "membership-" + resource_id,
                            REPO_ALPHA,
                            resource_id,
                            "sha256:" + ("c" * 64),
                            binding_id,
                            timestamp,
                        ),
                    )

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del cwd, timeout, environment
            return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

        service, _ = service_for(self.fixture, compose_runner=runner)
        self.fixture.observed_container_ids = (current_id,)

        def mutate_latest_after_snapshot(
            store: CoordinatorStore, snapshot_id: str
        ) -> None:
            del snapshot_id
            self.fixture.after_snapshot_commit = None
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE docker_observations
                    SET lifecycle = 'stopped', health = 'mutated-after-snapshot',
                        restart_policy = 'no', sampled_at = ?,
                        observation_fingerprint = 'mutable-after-snapshot'
                    WHERE docker_resource_id = ?
                    """,
                    (utc_timestamp(), current_id),
                )

        self.fixture.after_snapshot_commit = mutate_latest_after_snapshot
        up = service.reply_for_document(
            self.fixture.peer(),
            self.fixture.request(
                BrokerOperation.COMPOSE_UP,
                resource_id=COMPOSE_ALPHA,
            ).to_wire(),
        )
        self.assertTrue(up["ok"], up)
        self.assertEqual(
            [item["docker_resource_id"] for item in up["result"]["observed_resources"]],
            [current_id],
            "must-catch: Compose up evidence is bound to the exact fresh snapshot",
        )
        exact = up["result"]["observed_resources"][0]
        self.assertEqual(
            exact["snapshot_id"],
            up["result"]["broker_observation"]["snapshot_id"],
        )
        self.assertEqual(
            exact["observation_fingerprint"],
            "snapshot-" + current_id,
            "must-catch: exact outcome identity comes from immutable snapshot membership",
        )
        self.assertEqual(exact["current_lifecycle"], "stopped")
        self.assertEqual(exact["current_health"], "mutated-after-snapshot")
        self.assertEqual(exact["current_restart_policy"], "no")
        self.assertEqual(
            exact["current_observation_fingerprint"], "mutable-after-snapshot"
        )
        self.assertNotIn(
            "lifecycle",
            exact,
            "mutable latest-row detail must be labeled current, not represented as snapshot fact",
        )

        self.fixture.observed_container_ids = ()
        down = service.reply_for_document(
            self.fixture.peer(),
            self.fixture.request(
                BrokerOperation.COMPOSE_DOWN,
                resource_id=COMPOSE_ALPHA,
            ).to_wire(),
        )
        self.assertTrue(down["ok"], down)
        self.assertEqual(
            down["result"]["observed_resources"],
            [],
            "must-catch: retained stopped rows cannot reappear after Compose down",
        )

    def test_compose_reobserves_when_first_ticket_sampled_before_mutation(self) -> None:
        current_id = "docker-post-mutation"
        timestamp = utc_timestamp()
        with CoordinatorStore.open(
            self.fixture.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO docker_engines(
                        engine_id, host_id, context_identity, capability_state,
                        created_at, updated_at
                    ) VALUES ('engine-race', ?, 'race', 'available', ?, ?)
                    """,
                    (HOST, timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO docker_resources(
                        docker_resource_id, engine_id, full_container_id,
                        current_name, image, created_at, updated_at
                    ) VALUES (?, 'engine-race', ?, 'post-mutation',
                              'fixture:latest', ?, ?)
                    """,
                    (current_id, "d" * 64, timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO docker_observations(
                        docker_resource_id, lifecycle, health,
                        restart_policy, sampled_at, observation_fingerprint
                    ) VALUES (?, 'running', 'healthy', 'unless-stopped', ?, ?)
                    """,
                    (current_id, timestamp, "current-" + current_id),
                )
                connection.execute(
                    """
                    INSERT INTO control_bindings(
                        binding_id, repo_id, resource_kind, resource_id,
                        source_id, capability, provenance, authority_state,
                        priority, generation, created_at, updated_at
                    ) VALUES ('binding-race', ?, 'container', ?, ?, 'lifecycle',
                              'docker_labels', 'authoritative', 100, 0, ?, ?)
                    """,
                    (REPO_ALPHA, current_id, SOURCE, timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO repository_memberships(
                        membership_id, repo_id, resource_kind,
                        host_resource_id, immutable_fingerprint,
                        control_binding_id, created_at
                    ) VALUES ('membership-race', ?, 'container', ?, ?,
                              'binding-race', ?)
                    """,
                    (REPO_ALPHA, current_id, "sha256:" + "e" * 64, timestamp),
                )

        pre_sample_captured = threading.Event()
        release_pre_sample = threading.Event()
        mutation_executed = threading.Event()
        join_detected = threading.Event()
        external_outcome: dict[str, Any] = {}
        external_errors: list[BaseException] = []
        post_sample_count = 0
        owner: threading.Thread | None = None
        capability_fingerprint = "sha256:" + "9" * 64

        def commit_snapshot(
            connection: Any, snapshot_id: str, sample: Mapping[str, Any]
        ) -> None:
            committed_at = utc_timestamp()
            connection.execute(
                """
                INSERT INTO observation_capabilities(
                    snapshot_id, observer_domain, docker_available,
                    capability_fingerprint, committed_at
                ) VALUES (?, 'host-runtime-v2:full-docker', 1, ?, ?)
                """,
                (snapshot_id, capability_fingerprint, committed_at),
            )
            connection.execute(
                """
                INSERT INTO broker_observation_compose_scope(
                    snapshot_id, assets_complete, observed_asset_count,
                    evidence_fingerprint, recorded_at
                ) VALUES (?, 1, 0, ?, ?)
                """,
                (snapshot_id, "scope-" + str(sample["phase"]), committed_at),
            )
            phase = str(sample["phase"])
            for resource_id in sample["resource_ids"]:
                connection.execute(
                    """
                    INSERT INTO observation_snapshot_resources(
                        snapshot_id, resource_kind, resource_id,
                        observation_fingerprint
                    ) VALUES (?, 'container', ?, ?)
                    """,
                    (snapshot_id, resource_id, f"snapshot-{phase}-{resource_id}"),
                )
            if phase == "post":
                for service_name in ("db", "web"):
                    full_id = hashlib.sha256(
                        f"{snapshot_id}:{service_name}".encode("utf-8")
                    ).hexdigest()
                    resource_id = f"compose-post-{service_name}-{full_id[:12]}"
                    connection.execute(
                        """
                        INSERT INTO docker_resources(
                            docker_resource_id, engine_id, full_container_id,
                            current_name, image, created_at, updated_at
                        ) VALUES (?, 'engine-race', ?, ?, 'fixture:latest', ?, ?)
                        """,
                        (
                            resource_id,
                            full_id,
                            f"alpha-stack-{service_name}-1",
                            committed_at,
                            committed_at,
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO broker_observed_compose_containers(
                            snapshot_id, docker_resource_id, full_container_id,
                            project_name, service_name, lifecycle,
                            ownership_state, authoritative_owner_repo_id,
                            observation_fingerprint
                        ) VALUES (?, ?, ?, 'alpha-stack', ?, 'running',
                                  'exclusive', ?, ?)
                        """,
                        (
                            snapshot_id,
                            resource_id,
                            full_id,
                            service_name,
                            REPO_ALPHA,
                            f"compose-post-{service_name}",
                        ),
                    )

        def pre_sampler() -> Mapping[str, Any]:
            pre_sample_captured.set()
            if not release_pre_sample.wait(5):
                raise RuntimeError("fixture timed out waiting for Compose mutation")
            return {"phase": "pre", "resource_ids": []}

        def own_pre_mutation_ticket() -> None:
            try:
                with AccountStore.open(
                    self.fixture.persistence.database_path,
                    expected_uid=os.geteuid(),
                ) as store:
                    outcome = SingleFlightObserver(store, join_timeout=5).observe(
                        host_id=HOST,
                        observer_domain="host-runtime-v2:full-docker",
                        sampler=pre_sampler,
                        commit=commit_snapshot,
                    )
                    external_outcome["snapshot_id"] = outcome.snapshot_id
            except BaseException as error:
                external_errors.append(error)

        def post_sampler() -> Mapping[str, Any]:
            nonlocal post_sample_count
            post_sample_count += 1
            if not mutation_executed.is_set():
                raise RuntimeError("post-mutation observer sampled too early")
            return {"phase": "post", "resource_ids": [current_id]}

        def preflight_sampler() -> Mapping[str, Any]:
            return {"phase": "preflight", "resource_ids": []}

        def join_sleeper(delay: float) -> None:
            join_detected.set()
            release_pre_sample.set()
            threading.Event().wait(delay)

        def observe_after_mutation(store: CoordinatorStore) -> Mapping[str, Any]:
            sampler = (
                post_sampler if mutation_executed.is_set() else preflight_sampler
            )
            outcome = SingleFlightObserver(
                store,
                join_timeout=5,
                sleeper=join_sleeper,
            ).observe(
                host_id=HOST,
                observer_domain="host-runtime-v2:full-docker",
                sampler=sampler,
                commit=commit_snapshot,
            )
            return {
                "snapshot_id": outcome.snapshot_id,
                "host_id": outcome.host_id,
                "observer_domain": outcome.observer_domain,
                "joined": outcome.joined,
                "docker_available": True,
                "capability_fingerprint": capability_fingerprint,
                "material_fingerprint": outcome.material_fingerprint,
                "completed_at": outcome.completed_at,
            }

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            nonlocal owner
            del cwd, timeout, environment
            owner = threading.Thread(target=own_pre_mutation_ticket, daemon=True)
            owner.start()
            if not pre_sample_captured.wait(3):
                raise RuntimeError(
                    "fixture did not capture its sample before Compose mutation"
                )
            mutation_executed.set()
            return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

        service, _ = service_for(
            self.fixture,
            compose_runner=runner,
            observer=observe_after_mutation,
        )
        request = self.fixture.request(
            BrokerOperation.COMPOSE_UP,
            resource_id=COMPOSE_ALPHA,
        )
        reply = service.reply_for_document(
            self.fixture.peer(),
            request.to_wire(),
        )
        self.assertIsNotNone(owner)
        assert owner is not None
        owner.join(3)

        self.assertFalse(owner.is_alive(), "pre-mutation observation owner must finish")
        self.assertEqual(external_errors, [])
        self.assertTrue(reply["ok"], reply)
        self.assertTrue(join_detected.is_set(), "first observer call must join the old ticket")
        self.assertEqual(post_sample_count, 1)
        self.assertNotEqual(
            reply["result"]["broker_observation"]["snapshot_id"],
            external_outcome["snapshot_id"],
            "must-catch: Compose result cannot reuse a snapshot sampled before mutation",
        )
        self.assertEqual(
            reply["result"]["observed_resources"][0]["observation_fingerprint"],
            "snapshot-post-" + current_id,
        )

    def test_invoked_failure_requires_reconciliation_and_never_reexecutes(self) -> None:
        calls = 0

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del timeout, environment
            self.assertEqual(
                (os.stat(cwd).st_dev, os.stat(cwd).st_ino),
                (
                    self.fixture.alpha_root.stat().st_dev,
                    self.fixture.alpha_root.stat().st_ino,
                ),
            )
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
        first = service.reply_for_document(self.fixture.peer(), request.to_wire())
        self.assertFalse(first["ok"], first)
        self.assertEqual(first["error"]["code"], "operation_outcome_uncertain")
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.read_transaction() as connection:
                operation = connection.execute(
                    """
                    SELECT status, phase, error_code, result_json
                    FROM operations WHERE operation_id = ?
                    """,
                    (request.operation_id,),
                ).fetchone()
                target = connection.execute(
                    """
                    SELECT status, phase, error_json
                    FROM operation_targets WHERE operation_id = ?
                    """,
                    (request.operation_id,),
                ).fetchone()
        self.assertEqual(operation["status"], "needs_attention")
        self.assertEqual(operation["phase"], "reconciliation_required")
        self.assertEqual(operation["error_code"], "operation_outcome_uncertain")
        outcome = json.loads(str(operation["result_json"]))
        self.assertEqual(outcome["action"], "down")
        self.assertEqual(outcome["failed_phase"], "down")
        self.assertEqual(outcome["completed_phases"], [])
        self.assertFalse(outcome["cleanup_failed"])
        self.assertEqual(outcome["reconciliation_observation"]["status"], "completed")
        self.assertEqual(target["status"], "failed")
        self.assertEqual(target["phase"], "reconciliation_required")
        self.assertEqual(
            json.loads(str(target["error_json"]))["code"],
            "operation_outcome_uncertain",
        )
        restarted, _ = service_for(self.fixture, compose_runner=runner)
        replay = restarted.reply_for_document(self.fixture.peer(), request.to_wire())
        self.assertFalse(replay["ok"], replay)
        self.assertEqual(replay["error"]["code"], "operation_outcome_uncertain")
        new_request = self.fixture.request(
            BrokerOperation.COMPOSE_DOWN,
            resource_id=COMPOSE_ALPHA,
            operation_id=str(uuid.uuid4()),
        )
        blocked = restarted.reply_for_document(
            self.fixture.peer(), new_request.to_wire()
        )
        self.assertFalse(blocked["ok"], blocked)
        self.assertEqual(blocked["error"]["code"], "compose_operation_pending")
        self.assertEqual(calls, 1)

    def test_missing_effective_model_evidence_requires_fingerprint_abandonment(
        self,
    ) -> None:
        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del cwd, timeout, environment
            return subprocess.CompletedProcess(
                command, 1, stdout="", stderr="compose failed"
            )

        service, _ = service_for(self.fixture, compose_runner=runner)
        request = self.fixture.request(
            BrokerOperation.COMPOSE_DOWN,
            resource_id=COMPOSE_ALPHA,
            operation_id=str(uuid.uuid4()),
        )
        first = service.reply_for_document(self.fixture.peer(), request.to_wire())
        self.assertFalse(first["ok"], first)
        self.assertEqual(first["error"]["code"], "operation_outcome_uncertain")

        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "DELETE FROM broker_compose_effective_model_evidence "
                    "WHERE compose_definition_id = ?",
                    (COMPOSE_ALPHA,),
                )
                connection.execute(
                    "UPDATE broker_compose_definitions SET enabled = 0 "
                    "WHERE compose_definition_id = ?",
                    (COMPOSE_ALPHA,),
                )
                connection.execute(
                    "UPDATE operations SET error_code = "
                    "'compose_effective_model_required' "
                    "WHERE operation_id = ?",
                    (request.operation_id,),
                )

        candidate = self.fixture.persistence.compose_reconciliation_candidate(
            request.operation_id
        )
        self.assertFalse(candidate["scope_recoverable"])
        self.assertEqual(candidate["service_replicas"], ())
        self.assertIn(
            "effective_model_evidence_invalid",
            str(candidate["scope_failure_reason"]),
        )

        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE operations SET error_code = "
                    "'compose_directory_identity_required' "
                    "WHERE operation_id = ?",
                    (request.operation_id,),
                )
        directory_candidate = (
            self.fixture.persistence.compose_reconciliation_candidate(
                request.operation_id
            )
        )
        self.assertFalse(directory_candidate["scope_recoverable"])
        self.assertEqual(
            directory_candidate["target_fingerprint"],
            candidate["target_fingerprint"],
        )

        effective_uid = os.geteuid()
        persistence = self.fixture.persistence

        @contextmanager
        def open_owned_store() -> Iterator[CoordinatorStore]:
            with mock.patch.object(
                broker_persistence.os,
                "geteuid",
                return_value=effective_uid,
            ):
                with CoordinatorStore.open(
                    persistence.database_path,
                    expected_uid=effective_uid,
                ) as owned_store:
                    yield owned_store

        with (
            mock.patch.object(broker_persistence.os, "geteuid", return_value=0),
            mock.patch.object(persistence, "expected_uid", 0),
            mock.patch.object(persistence, "_store", side_effect=open_owned_store),
        ):
            with self.assertRaisesRegex(BrokerError, "cannot be re-proven"):
                persistence.reconcile_compose_operation(
                    request.operation_id,
                    evidence={},
                )
            with self.assertRaisesRegex(BrokerError, "exact persisted target"):
                persistence.reconcile_compose_operation(
                    request.operation_id,
                    evidence=None,
                    abandon_as_failed=True,
                    confirm_definition_fingerprint="sha256:wrong",
                )

            with open_owned_store() as store:
                with store.read_transaction() as connection:
                    unchanged = connection.execute(
                        "SELECT status, phase FROM operations WHERE operation_id = ?",
                        (request.operation_id,),
                    ).fetchone()
            self.assertEqual(
                dict(unchanged),
                {
                    "status": "needs_attention",
                    "phase": "reconciliation_required",
                },
            )

            result = persistence.reconcile_compose_operation(
                request.operation_id,
                evidence=None,
                abandon_as_failed=True,
                confirm_definition_fingerprint=str(candidate["target_fingerprint"]),
            )
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["phase"], "reconciled")
        self.assertFalse(result["desired_state_observed"])
        self.assertEqual(
            result["reconciliation"]["mode"], "abandoned_as_failed"
        )

        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.read_transaction() as connection:
                reconciled = connection.execute(
                    "SELECT status, phase, error_code FROM operations "
                    "WHERE operation_id = ?",
                    (request.operation_id,),
                ).fetchone()
        self.assertEqual(
            dict(reconciled),
            {
                "status": "failed",
                "phase": "reconciled",
                "error_code": "compose_outcome_reconciled",
            },
        )

    def test_real_startup_migration_exposes_legacy_scope_for_abandonment(
        self,
    ) -> None:
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            evidence = self.fixture.observe_full_docker(store)
        request = self.fixture.request(
            BrokerOperation.COMPOSE_DOWN,
            resource_id=COMPOSE_ALPHA,
            operation_id=str(uuid.uuid4()),
        )
        authorized = self.fixture.persistence.authorize(
            self.fixture.peer(), request
        )
        self.assertEqual(
            self.fixture.persistence.reserve_operation(
                authorized,
                compose_preflight=evidence,
            ).state,
            "execute",
        )
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "DELETE FROM broker_compose_directory_identity "
                    "WHERE compose_definition_id = ?",
                    (COMPOSE_ALPHA,),
                )
                connection.execute(
                    "DELETE FROM broker_compose_effective_model_evidence "
                    "WHERE compose_definition_id = ?",
                    (COMPOSE_ALPHA,),
                )

        reopened = BrokerPersistence(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        )
        candidate = reopened.compose_reconciliation_candidate(
            request.operation_id
        )
        self.assertFalse(candidate["scope_recoverable"])
        self.assertEqual(candidate["service_replicas"], ())
        self.assertIn(
            "legacy_definition_migration",
            str(candidate["scope_failure_reason"]),
        )
        self.assertIn(
            "effective_model_evidence_invalid",
            str(candidate["scope_failure_reason"]),
        )
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.read_transaction() as connection:
                operation = connection.execute(
                    "SELECT status, phase, error_code FROM operations "
                    "WHERE operation_id = ?",
                    (request.operation_id,),
                ).fetchone()
                target = connection.execute(
                    "SELECT status, phase FROM operation_targets "
                    "WHERE operation_id = ?",
                    (request.operation_id,),
                ).fetchone()
        self.assertEqual(
            dict(operation),
            {
                "status": "needs_attention",
                "phase": "reconciliation_required",
                "error_code": "compose_directory_identity_required",
            },
        )
        self.assertEqual(
            dict(target), {"status": "running", "phase": "reconciliation_required"}
        )

    def test_reconciliation_rejects_corrupt_effective_model_evidence(self) -> None:
        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del cwd, timeout, environment
            return subprocess.CompletedProcess(
                command, 1, stdout="", stderr="compose failed"
            )

        service, _ = service_for(self.fixture, compose_runner=runner)
        request = self.fixture.request(
            BrokerOperation.COMPOSE_DOWN,
            resource_id=COMPOSE_ALPHA,
            operation_id=str(uuid.uuid4()),
        )
        first = service.reply_for_document(self.fixture.peer(), request.to_wire())
        self.assertFalse(first["ok"], first)

        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE broker_compose_definitions SET enabled = 0 "
                    "WHERE compose_definition_id = ?",
                    (COMPOSE_ALPHA,),
                )
                connection.execute(
                    "UPDATE broker_compose_effective_model_evidence "
                    "SET service_replicas_json = ? "
                    "WHERE compose_definition_id = ?",
                    ('{"db":0,"web":1}', COMPOSE_ALPHA),
                )

        with self.assertRaisesRegex(BrokerError, "replica evidence is invalid"):
            self.fixture.persistence.compose_reconciliation_candidate(
                request.operation_id
            )

    def test_startup_recovery_fences_crash_left_compose_reservation(self) -> None:
        operation_id = "crash-left-" + uuid.uuid4().hex
        now = utc_timestamp()
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO operations(
                        operation_id, repo_id, kind, status, phase,
                        request_fingerprint, actor, created_at, updated_at
                    ) VALUES (?, ?, 'broker.compose.restart', 'running',
                              'host_invoked', 'fixture', 'fixture', ?, ?)
                    """,
                    (operation_id, REPO_ALPHA, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO operation_targets(
                        operation_id, ordinal, target_kind, target_id,
                        action, immutable_fingerprint, phase, status
                    ) VALUES (?, 0, 'compose', ?, 'compose.restart',
                              'fixture', 'host_invoked', 'running')
                    """,
                    (operation_id, COMPOSE_ALPHA),
                )
        recovered = self.fixture.persistence.recover_interrupted_compose_operations()
        self.assertEqual(recovered["operation_ids"], [operation_id])
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.read_transaction() as connection:
                row = connection.execute(
                    "SELECT status, phase, error_code, result_json "
                    "FROM operations WHERE operation_id = ?",
                    (operation_id,),
                ).fetchone()
        self.assertEqual(row["status"], "needs_attention")
        self.assertEqual(row["phase"], "reconciliation_required")
        self.assertEqual(row["error_code"], "operation_outcome_uncertain")
        outcome = json.loads(str(row["result_json"]))
        self.assertTrue(outcome["completion_unknown"])
        self.assertEqual(outcome["failed_phase"], "broker_restart")

    def test_observation_proof_rejects_service_outside_persisted_scope(self) -> None:
        calls = 0
        snapshots: list[str] = []

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del cwd, timeout, environment
            nonlocal calls
            calls += 1
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        def observer(store: CoordinatorStore) -> Mapping[str, Any]:
            evidence = self.fixture.observe_full_docker(store)
            snapshots.append(str(evidence["snapshot_id"]))
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE broker_observed_compose_containers
                    SET service_name = 'undeclared-worker'
                    WHERE snapshot_id = ? AND service_name = 'web'
                    """,
                    (evidence["snapshot_id"],),
                )
            return evidence

        service, _host = service_for(
            self.fixture,
            compose_runner=runner,
            observer=observer,
        )
        reply = service.reply_for_document(
            self.fixture.peer(),
            self.fixture.request(
                BrokerOperation.COMPOSE_UP,
                resource_id=COMPOSE_ALPHA,
            ).to_wire(),
        )
        self.assertFalse(reply["ok"], reply)
        self.assertEqual(reply["error"]["code"], "operation_outcome_uncertain")
        self.assertEqual(calls, 1)
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.read_transaction() as connection:
                proof = broker_persistence._compose_action_observation_proof(
                    connection,
                    snapshot_id=snapshots[-1],
                    repo_id=REPO_ALPHA,
                    project_name="alpha-stack",
                    services=("db", "web"),
                    service_replicas=(("db", 1), ("web", 1)),
                    action="up",
                    uncertain_transition=False,
                )
        self.assertFalse(proof["desired_state_observed"])
        self.assertEqual(proof["unexpected_services"], ["undeclared-worker"])

    def test_observation_proof_rejects_excess_same_service_replicas(self) -> None:
        snapshot_id = self.fixture.observed_compose_snapshot(
            owner_repo_id=REPO_ALPHA,
            project_name="alpha-stack",
        )
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.immediate_transaction() as connection:
                engine_id = str(
                    connection.execute(
                        """
                        SELECT resource.engine_id
                        FROM broker_observed_compose_containers observed
                        JOIN docker_resources resource USING(docker_resource_id)
                        WHERE observed.snapshot_id = ?
                        """,
                        (snapshot_id,),
                    ).fetchone()[0]
                )
                extra_id = "container-extra-" + uuid.uuid4().hex
                full_id = hashlib.sha256(extra_id.encode()).hexdigest()
                connection.execute(
                    """
                    INSERT INTO docker_resources(
                        docker_resource_id, engine_id, full_container_id,
                        current_name, created_at, updated_at
                    ) VALUES (?, ?, ?, 'alpha-stack-web-2', ?, ?)
                    """,
                    (extra_id, engine_id, full_id, utc_timestamp(), utc_timestamp()),
                )
                connection.execute(
                    """
                    INSERT INTO broker_observed_compose_containers(
                        snapshot_id, docker_resource_id, full_container_id,
                        project_name, service_name, lifecycle,
                        ownership_state, authoritative_owner_repo_id,
                        observation_fingerprint
                    ) VALUES (?, ?, ?, 'alpha-stack', 'web', 'running',
                              'exclusive', ?, 'extra-observation')
                    """,
                    (snapshot_id, extra_id, full_id, REPO_ALPHA),
                )
            with store.read_transaction() as connection:
                proof = broker_persistence._compose_action_observation_proof(
                    connection,
                    snapshot_id=snapshot_id,
                    repo_id=REPO_ALPHA,
                    project_name="alpha-stack",
                    services=("web",),
                    service_replicas=(("web", 1),),
                    action="up",
                    uncertain_transition=False,
                )
        self.assertFalse(proof["desired_state_observed"])
        self.assertEqual(proof["excess_services"], ["web"])
        self.assertEqual(proof["expected_service_replicas"], {"web": 1})

    def test_restart_partial_phase_is_fenced_with_exact_completed_phases(self) -> None:
        calls: list[str] = []

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del cwd, timeout, environment
            phase = "stop" if "stop" in command else "up"
            calls.append(phase)
            return subprocess.CompletedProcess(
                command,
                0 if phase == "stop" else 1,
                stdout="",
                stderr="suppressed",
            )

        self.fixture.persistence.grant_resource(
            uid=os.geteuid(),
            repo_id=REPO_ALPHA,
            resource_kind="compose",
            resource_id=COMPOSE_ALPHA,
            operation=BrokerOperation.COMPOSE_RESTART,
        )
        service, _ = service_for(self.fixture, compose_runner=runner)
        request = self.fixture.request(
            BrokerOperation.COMPOSE_RESTART,
            resource_id=COMPOSE_ALPHA,
        )
        reply = service.reply_for_document(self.fixture.peer(), request.to_wire())
        self.assertFalse(reply["ok"], reply)
        self.assertEqual(reply["error"]["code"], "operation_outcome_uncertain")
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.read_transaction() as connection:
                row = connection.execute(
                    "SELECT status, result_json FROM operations WHERE operation_id = ?",
                    (request.operation_id,),
                ).fetchone()
        self.assertEqual(row["status"], "needs_attention")
        evidence = json.loads(str(row["result_json"]))
        self.assertEqual(evidence["failed_phase"], "up")
        self.assertEqual(evidence["completed_phases"], ["stop"])
        self.assertEqual(calls, ["stop", "up"])

    def test_body_and_sealed_cleanup_failure_preserve_both_redacted_facts(
        self,
    ) -> None:
        if not hasattr(os, "memfd_create") or not Path("/proc/self/fd").is_dir():
            self.skipTest("sealed anonymous Compose inputs require Linux memfd")

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del cwd, timeout, environment
            return subprocess.CompletedProcess(
                command, 1, stdout="secret-output", stderr="secret-error"
            )

        original_close = os.close
        failed_descriptors: set[int] = set()

        def close_with_memfd_failure(descriptor: int) -> None:
            try:
                target = os.readlink(f"/proc/self/fd/{descriptor}")
            except OSError:
                target = ""
            original_close(descriptor)
            if (
                "memfd:devcoordinator-" in target
                and descriptor not in failed_descriptors
            ):
                failed_descriptors.add(descriptor)
                raise OSError("injected sealed cleanup failure")

        service, _ = service_for(self.fixture, compose_runner=runner)
        request = self.fixture.request(
            BrokerOperation.COMPOSE_DOWN,
            resource_id=COMPOSE_ALPHA,
        )
        with mock.patch.object(
            broker_host.os, "close", side_effect=close_with_memfd_failure
        ):
            reply = service.reply_for_document(self.fixture.peer(), request.to_wire())
        self.assertFalse(reply["ok"], reply)
        self.assertEqual(reply["error"]["code"], "operation_outcome_uncertain")
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.read_transaction() as connection:
                row = connection.execute(
                    "SELECT result_json FROM operations WHERE operation_id = ?",
                    (request.operation_id,),
                ).fetchone()
        evidence = json.loads(str(row["result_json"]))
        self.assertEqual(evidence["failed_phase"], "down")
        self.assertEqual(evidence["completed_phases"], [])
        self.assertTrue(evidence["cleanup_failed"])
        encoded = json.dumps(evidence)
        self.assertNotIn("secret-output", encoded)
        self.assertNotIn("secret-error", encoded)

    def test_env_files_and_profiles_are_ordered_fingerprinted_and_redacted(
        self,
    ) -> None:
        first = self.fixture.persistence.provision_compose_definition(
            repo_id=REPO_ALPHA,
            compose_definition_id=COMPOSE_ALPHA,
            cwd=self.fixture.alpha_root,
            files=(self.fixture.compose_one, self.fixture.compose_two),
            env_files=(self.fixture.env_one, self.fixture.env_two),
            profiles=("capture", "display"),
            services=("db", "web"),
            project_name="alpha-stack",
        )
        definitions = self.fixture.persistence.list_compose_definitions(
            repo_id=REPO_ALPHA
        )
        self.assertEqual(len(definitions), 1)
        definition = definitions[0]
        self.assertEqual(
            definition["env_files"],
            [str(self.fixture.env_one), str(self.fixture.env_two)],
        )
        self.assertEqual(definition["profiles"], ["capture", "display"])
        self.assertEqual(
            definition["env_file_evidence"],
            [
                {
                    "content_sha256": hashlib.sha256(
                        self.fixture.env_one.read_bytes()
                    ).hexdigest(),
                    "byte_size": self.fixture.env_one.stat().st_size,
                },
                {
                    "content_sha256": hashlib.sha256(
                        self.fixture.env_two.read_bytes()
                    ).hexdigest(),
                    "byte_size": self.fixture.env_two.stat().st_size,
                },
            ],
        )
        serialized = json.dumps(definition, sort_keys=True)
        self.assertNotIn("never-return-this-value", serialized)
        self.assertNotIn("RUNTIME_OPAQUE_VALUE", serialized)
        opaque_bytes = b"RUNTIME_OPAQUE_VALUE=never-return-this-value"
        for suffix in ("", "-wal", "-shm"):
            database_artifact = Path(
                str(self.fixture.persistence.database_path) + suffix
            )
            if database_artifact.is_file():
                self.assertNotIn(opaque_bytes, database_artifact.read_bytes())

        changed = self.fixture.persistence.provision_compose_definition(
            repo_id=REPO_ALPHA,
            compose_definition_id=COMPOSE_ALPHA,
            cwd=self.fixture.alpha_root,
            files=(self.fixture.compose_one, self.fixture.compose_two),
            env_files=(self.fixture.env_one, self.fixture.env_two),
            profiles=("display", "capture"),
            services=("db", "web"),
            project_name="alpha-stack",
        )
        self.assertNotEqual(
            changed["definition_fingerprint"], first["definition_fingerprint"]
        )
        self.assertEqual(changed["generation"], first["generation"] + 1)

    def test_compose_env_file_validation_rejects_unsafe_paths_and_accepts_private_file(
        self,
    ) -> None:
        outside = self.fixture.beta_root / "outside.env"
        outside.write_text("OUTSIDE=value\n", encoding="utf-8")
        outside.chmod(0o600)
        public = self.fixture.alpha_root / "public.env"
        public.write_text("PUBLIC=value\n", encoding="utf-8")
        public.chmod(0o644)
        symlink = self.fixture.alpha_root / "linked.env"
        symlink.symlink_to(self.fixture.env_one)
        missing = self.fixture.alpha_root / "missing.env"

        for label, env_file in (
            ("missing", missing),
            ("symlink", symlink),
            ("outside", outside),
            ("non-private", public),
        ):
            with (
                self.subTest(label=label),
                self.assertRaises((ValueError, PermissionError)),
            ):
                self.fixture.persistence.provision_compose_definition(
                    repo_id=REPO_ALPHA,
                    compose_definition_id=f"compose-invalid-{label}",
                    cwd=self.fixture.alpha_root,
                    files=(self.fixture.compose_one,),
                    env_files=(env_file,),
                    profiles=("capture",),
                    services=("db",),
                    project_name=f"invalid-{label}",
                )

        accepted = self.fixture.persistence.provision_compose_definition(
            repo_id=REPO_ALPHA,
            compose_definition_id="compose-private-env",
            cwd=self.fixture.alpha_root,
            files=(self.fixture.compose_one,),
            env_files=(self.fixture.env_one,),
            profiles=("capture",),
            services=("db",),
            project_name="private-env-stack",
        )
        self.assertTrue(accepted["enabled"])

    def test_compose_env_file_drift_is_rejected_before_docker(self) -> None:
        calls = 0

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del cwd, timeout, environment
            nonlocal calls
            calls += 1
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        self.fixture.persistence.provision_compose_definition(
            repo_id=REPO_ALPHA,
            compose_definition_id=COMPOSE_ALPHA,
            cwd=self.fixture.alpha_root,
            files=(self.fixture.compose_one, self.fixture.compose_two),
            env_files=(self.fixture.env_one,),
            profiles=("capture",),
            services=("db", "web"),
            project_name="alpha-stack",
        )
        self.fixture.env_one.write_text(
            "RUNTIME_OPAQUE_VALUE=changed-after-enrollment\n", encoding="utf-8"
        )
        service, _ = service_for(self.fixture, compose_runner=runner)
        reply = service.reply_for_document(
            self.fixture.peer(),
            self.fixture.request(
                BrokerOperation.COMPOSE_UP, resource_id=COMPOSE_ALPHA
            ).to_wire(),
        )
        self.assertFalse(reply["ok"], reply)
        self.assertEqual(reply["error"]["code"], "compose_definition_drift")
        self.assertEqual(calls, 0)

    def test_compose_effective_model_drift_is_rejected_before_mutation(self) -> None:
        calls = 0

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del command, cwd, timeout, environment
            nonlocal calls
            calls += 1
            raise AssertionError("drifted effective model reached Compose mutation")

        def drifted_renderer(**arguments: object) -> bytes:
            services = tuple(str(item) for item in arguments["declared_services"])
            return json.dumps(
                {
                    "services": {
                        service: {"image": f"example.invalid/{service}:runtime-drift"}
                        for service in services
                    }
                }
            ).encode()

        service, _ = service_for(
            self.fixture,
            compose_runner=runner,
            compose_model_renderer=drifted_renderer,
        )
        reply = service.reply_for_document(
            self.fixture.peer(),
            self.fixture.request(
                BrokerOperation.COMPOSE_UP, resource_id=COMPOSE_ALPHA
            ).to_wire(),
        )
        self.assertFalse(reply["ok"], reply)
        self.assertEqual(reply["error"]["code"], "compose_effective_model_drift")
        self.assertEqual(calls, 0)

    def test_parent_symlink_swap_cannot_redirect_privileged_input_read(self) -> None:
        nested = self.fixture.alpha_root / "nested"
        nested.mkdir()
        compose = nested / "compose.yml"
        compose.write_text("services: {}\n", encoding="utf-8")
        environment = nested / "runtime.env"
        environment.write_text("SAFE=value\n", encoding="utf-8")
        environment.chmod(0o600)
        self.fixture.persistence.provision_compose_definition(
            repo_id=REPO_ALPHA,
            compose_definition_id=COMPOSE_ALPHA,
            cwd=self.fixture.alpha_root,
            files=(compose,),
            env_files=(environment,),
            services=("web",),
            project_name="alpha-stack",
        )
        outside = self.fixture.beta_root / "outside"
        outside.mkdir()
        (outside / "compose.yml").write_text("services: {}\n", encoding="utf-8")
        outside_secret = outside / "runtime.env"
        outside_secret.write_text("ROOT_ONLY=must-not-be-read\n", encoding="utf-8")
        outside_secret.chmod(0o600)
        original = self.fixture.alpha_root / "nested-original"
        nested.rename(original)
        nested.symlink_to(outside, target_is_directory=True)
        calls = 0

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del command, cwd, timeout, environment
            nonlocal calls
            calls += 1
            raise AssertionError("symlink-swapped Compose input reached Docker")

        service, _ = service_for(self.fixture, compose_runner=runner)
        reply = service.reply_for_document(
            self.fixture.peer(),
            self.fixture.request(
                BrokerOperation.COMPOSE_UP,
                resource_id=COMPOSE_ALPHA,
            ).to_wire(),
        )
        self.assertFalse(reply["ok"], reply)
        self.assertEqual(reply["error"]["code"], "compose_definition_invalid")
        self.assertEqual(calls, 0)

    def test_fifo_replacement_fails_without_entering_compose_runner(self) -> None:
        self.fixture.compose_one.unlink()
        os.mkfifo(self.fixture.compose_one, mode=0o600)
        calls = 0

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del command, cwd, timeout, environment
            nonlocal calls
            calls += 1
            raise AssertionError("FIFO-backed Compose input reached Docker")

        service, _ = service_for(self.fixture, compose_runner=runner)
        reply = service.reply_for_document(
            self.fixture.peer(),
            self.fixture.request(
                BrokerOperation.COMPOSE_UP,
                resource_id=COMPOSE_ALPHA,
            ).to_wire(),
        )
        self.assertFalse(reply["ok"], reply)
        self.assertEqual(reply["error"]["code"], "compose_definition_invalid")
        self.assertEqual(calls, 0)

    def test_repository_rename_during_runner_keeps_pinned_cwd_and_fences_result(
        self,
    ) -> None:
        moved = self.fixture.root / "alpha-moved"
        runner_cwd_identity: tuple[int, int] | None = None

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del timeout, environment
            nonlocal runner_cwd_identity
            self.assertEqual(command[2:4], ("--project-directory", "."))
            metadata = os.stat(cwd)
            runner_cwd_identity = (metadata.st_dev, metadata.st_ino)
            self.fixture.alpha_root.rename(moved)
            self.fixture.alpha_root.symlink_to(
                self.fixture.beta_root,
                target_is_directory=True,
            )
            self.assertEqual(
                runner_cwd_identity,
                (moved.stat().st_dev, moved.stat().st_ino),
            )
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        try:
            service, _ = service_for(self.fixture, compose_runner=runner)
            request = self.fixture.request(
                BrokerOperation.COMPOSE_UP,
                resource_id=COMPOSE_ALPHA,
            )
            reply = service.reply_for_document(self.fixture.peer(), request.to_wire())
            self.assertFalse(reply["ok"], reply)
            self.assertEqual(reply["error"]["code"], "operation_outcome_uncertain")
            self.assertIsNotNone(runner_cwd_identity)
        finally:
            if self.fixture.alpha_root.is_symlink():
                self.fixture.alpha_root.unlink()
            if moved.is_dir():
                moved.rename(self.fixture.alpha_root)

    def test_restart_path_drift_between_phases_is_uncertain(self) -> None:
        self.fixture.persistence.grant_resource(
            uid=os.geteuid(),
            repo_id=REPO_ALPHA,
            resource_kind="compose",
            resource_id=COMPOSE_ALPHA,
            operation=BrokerOperation.COMPOSE_RESTART,
        )
        calls: list[str] = []

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del cwd, timeout, environment
            calls.append("stop" if "stop" in command else "up")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        service, _ = service_for(self.fixture, compose_runner=runner)
        request = self.fixture.request(
            BrokerOperation.COMPOSE_RESTART,
            resource_id=COMPOSE_ALPHA,
        )
        with mock.patch.object(
            broker_host,
            "_compose_target_paths_are_current",
            side_effect=(True, True, False),
        ):
            reply = service.reply_for_document(self.fixture.peer(), request.to_wire())
        self.assertFalse(reply["ok"], reply)
        self.assertEqual(reply["error"]["code"], "operation_outcome_uncertain")
        self.assertEqual(calls, ["stop"])
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.read_transaction() as connection:
                result = connection.execute(
                    "SELECT result_json FROM operations WHERE operation_id = ?",
                    (request.operation_id,),
                ).fetchone()
        evidence = json.loads(str(result["result_json"]))
        self.assertEqual(evidence["failed_phase"], "up_path_precheck")
        self.assertEqual(evidence["completed_phases"], ["stop"])

    def test_stop_restart_and_down_use_only_the_persisted_compose_scope(self) -> None:
        calls: list[tuple[str, ...]] = []
        captured_inputs: list[tuple[tuple[bytes, ...], tuple[bytes, ...]]] = []

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del cwd, timeout, environment
            normalized, env_payloads, compose_payloads, _paths = (
                capture_sealed_compose_command(command)
            )
            calls.append(normalized)
            captured_inputs.append((env_payloads, compose_payloads))
            return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

        self.fixture.persistence.provision_compose_definition(
            repo_id=REPO_ALPHA,
            compose_definition_id=COMPOSE_ALPHA,
            cwd=self.fixture.alpha_root,
            files=(self.fixture.compose_one, self.fixture.compose_two),
            env_files=(self.fixture.env_one, self.fixture.env_two),
            profiles=("capture", "display"),
            services=("db", "web"),
            project_name="alpha-stack",
        )
        for operation in (
            BrokerOperation.COMPOSE_STOP,
            BrokerOperation.COMPOSE_RESTART,
        ):
            self.fixture.persistence.grant_resource(
                uid=os.geteuid(),
                repo_id=REPO_ALPHA,
                resource_kind="compose",
                resource_id=COMPOSE_ALPHA,
                operation=operation,
            )

        service, _ = service_for(self.fixture, compose_runner=runner)
        for operation in (
            BrokerOperation.COMPOSE_STOP,
            BrokerOperation.COMPOSE_RESTART,
            BrokerOperation.COMPOSE_DOWN,
        ):
            reply = service.reply_for_document(
                self.fixture.peer(),
                self.fixture.request(operation, resource_id=COMPOSE_ALPHA).to_wire(),
            )
            self.assertTrue(reply["ok"], reply)

        prefix = (
            "/trusted/docker",
            "compose",
            "--project-directory",
            ".",
            "--project-name",
            "alpha-stack",
            "--env-file",
            "<sealed-env-0>",
            "--env-file",
            "<sealed-env-1>",
            "--env-file",
            "<sealed-env-2>",
            "--profile",
            "capture",
            "--profile",
            "display",
            "--file",
            "<sealed-compose-0>",
            "--file",
            "<sealed-compose-1>",
        )
        self.assertEqual(
            calls,
            [
                (*prefix, "stop", "db", "web"),
                (*prefix, "stop", "db", "web"),
                (*prefix, "up", "--detach", "--no-deps", "db", "web"),
                (*prefix, "down"),
            ],
        )
        self.assertTrue(
            all(
                env_payloads
                == (
                    b"",
                    self.fixture.env_one.read_bytes(),
                    self.fixture.env_two.read_bytes(),
                )
                and compose_payloads
                == (
                    self.fixture.compose_one.read_bytes(),
                    self.fixture.compose_two.read_bytes(),
                )
                for env_payloads, compose_payloads in captured_inputs
            )
        )

    def test_fresh_observed_name_conflict_blocks_every_action_before_runner(
        self,
    ) -> None:
        for operation in (
            BrokerOperation.COMPOSE_UP,
            BrokerOperation.COMPOSE_STOP,
            BrokerOperation.COMPOSE_RESTART,
            BrokerOperation.COMPOSE_DOWN,
        ):
            self.fixture.persistence.grant_resource(
                uid=os.geteuid(),
                repo_id=REPO_ALPHA,
                resource_kind="compose",
                resource_id=COMPOSE_ALPHA,
                operation=operation,
            )
        calls = 0

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del command, cwd, timeout, environment
            nonlocal calls
            calls += 1
            raise AssertionError("conflicted Compose mutation reached Docker")

        def observe_unassigned(_store: CoordinatorStore) -> Mapping[str, Any]:
            snapshot_id = self.fixture.observed_compose_snapshot(
                owner_repo_id=None,
                project_name="alpha-stack",
            )
            return self.fixture.snapshot_evidence(snapshot_id)

        service, _host = service_for(
            self.fixture,
            compose_runner=runner,
            observer=observe_unassigned,
        )
        for operation in (
            BrokerOperation.COMPOSE_UP,
            BrokerOperation.COMPOSE_STOP,
            BrokerOperation.COMPOSE_RESTART,
            BrokerOperation.COMPOSE_DOWN,
        ):
            with self.subTest(operation=operation.value):
                reply = service.reply_for_document(
                    self.fixture.peer(),
                    self.fixture.request(
                        operation,
                        resource_id=COMPOSE_ALPHA,
                    ).to_wire(),
                )
                self.assertFalse(reply["ok"], reply)
                self.assertEqual(
                    reply["error"]["code"],
                    "compose_project_name_conflict",
                )
        self.assertEqual(calls, 0)

    def test_exact_owned_observation_allows_action_and_binds_preflight(self) -> None:
        calls = 0

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del cwd, timeout, environment
            nonlocal calls
            calls += 1
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        def observe_owned(store: CoordinatorStore) -> Mapping[str, Any]:
            return self.fixture.observe_full_docker(store)

        service, _host = service_for(
            self.fixture,
            compose_runner=runner,
            observer=observe_owned,
        )
        request = self.fixture.request(
            BrokerOperation.COMPOSE_UP,
            resource_id=COMPOSE_ALPHA,
        )
        reply = service.reply_for_document(self.fixture.peer(), request.to_wire())
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(calls, 1)
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            with store.read_transaction() as connection:
                preflight = connection.execute(
                    """
                    SELECT snapshot_id, material_fingerprint,
                           capability_fingerprint
                    FROM broker_compose_operation_preflights
                    WHERE operation_id = ?
                    """,
                    (request.operation_id,),
                ).fetchone()
        self.assertIsNotNone(preflight)
        self.assertTrue(str(preflight["snapshot_id"]).startswith("compose-snapshot-"))

    def test_disabled_persisted_duplicate_blocks_mutation_before_runner(self) -> None:
        beta_compose = self.fixture.beta_root / "compose.yml"
        beta_compose.write_text("services: {}\n", encoding="utf-8")
        self.fixture.persistence.provision_compose_definition(
            repo_id=REPO_BETA,
            compose_definition_id="compose-beta-disabled",
            cwd=self.fixture.beta_root,
            files=(beta_compose,),
            services=("web",),
            project_name="alpha-stack",
            enabled=False,
        )
        calls = 0

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del command, cwd, timeout, environment
            nonlocal calls
            calls += 1
            raise AssertionError("duplicate Compose definition reached Docker")

        service, _host = service_for(self.fixture, compose_runner=runner)
        reply = service.reply_for_document(
            self.fixture.peer(),
            self.fixture.request(
                BrokerOperation.COMPOSE_DOWN,
                resource_id=COMPOSE_ALPHA,
            ).to_wire(),
        )
        self.assertFalse(reply["ok"], reply)
        self.assertEqual(
            reply["error"]["code"],
            "compose_project_name_conflict",
        )
        self.assertEqual(calls, 0)

    def test_unresolved_prior_operation_blocks_before_observation_and_reservation(
        self,
    ) -> None:
        with CoordinatorStore.open(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        ) as store:
            evidence = self.fixture.observe_full_docker(store)
        first_request = self.fixture.request(
            BrokerOperation.COMPOSE_UP,
            resource_id=COMPOSE_ALPHA,
        )
        first_authorized = self.fixture.persistence.authorize(
            self.fixture.peer(), first_request
        )
        self.assertEqual(
            self.fixture.persistence.reserve_operation(
                first_authorized,
                compose_preflight=evidence,
            ).state,
            "execute",
        )

        observations = 0
        runner_calls = 0

        def observer(store: CoordinatorStore) -> Mapping[str, Any]:
            del store
            nonlocal observations
            observations += 1
            raise AssertionError("unresolved operation reached host observation")

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del command, cwd, timeout, environment
            nonlocal runner_calls
            runner_calls += 1
            raise AssertionError("unresolved operation reached Docker")

        service, _host = service_for(
            self.fixture,
            compose_runner=runner,
            observer=observer,
        )
        second_request = self.fixture.request(
            BrokerOperation.COMPOSE_DOWN,
            resource_id=COMPOSE_ALPHA,
        )
        reply = service.reply_for_document(
            self.fixture.peer(), second_request.to_wire()
        )
        self.assertFalse(reply["ok"], reply)
        self.assertEqual(reply["error"]["code"], "compose_operation_pending")
        self.assertEqual(observations, 0)
        self.assertEqual(runner_calls, 0)

        second_authorized = self.fixture.persistence.authorize(
            self.fixture.peer(), second_request
        )
        with self.assertRaises(BrokerError) as raised:
            self.fixture.persistence.reserve_operation(
                second_authorized,
                compose_preflight=evidence,
            )
        self.assertEqual(raised.exception.code, "compose_operation_pending")

    def test_compose_preflight_rejects_missing_stale_and_wrong_domain_evidence(
        self,
    ) -> None:
        calls = 0

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del command, cwd, timeout, environment
            nonlocal calls
            calls += 1
            raise AssertionError("invalid observation reached Docker")

        evidence_cases: tuple[Mapping[str, Any] | None, ...] = (
            None,
            {
                "snapshot_id": "missing-snapshot",
                "observer_domain": "host-runtime-v2:full-docker",
                "docker_available": True,
                "capability_fingerprint": "stale-capability",
                "material_fingerprint": "stale-material",
                "completed_at": utc_timestamp(),
            },
            {
                "snapshot_id": "wrong-domain-snapshot",
                "observer_domain": "partial-docker",
                "docker_available": True,
                "capability_fingerprint": "wrong-capability",
                "material_fingerprint": "wrong-material",
                "completed_at": utc_timestamp(),
            },
        )
        for evidence in evidence_cases:
            with self.subTest(evidence=evidence):

                def observer(
                    store: CoordinatorStore,
                    returned: Mapping[str, Any] | None = evidence,
                ) -> Mapping[str, Any]:
                    del store
                    return dict(returned or {})

                service, _host = service_for(
                    self.fixture,
                    compose_runner=runner,
                    observer=observer,
                )
                reply = service.reply_for_document(
                    self.fixture.peer(),
                    self.fixture.request(
                        BrokerOperation.COMPOSE_UP,
                        resource_id=COMPOSE_ALPHA,
                    ).to_wire(),
                )
                self.assertFalse(reply["ok"], reply)
                self.assertEqual(
                    reply["error"]["code"],
                    "lifecycle_observation_incomplete",
                )
        self.assertEqual(calls, 0)

    def test_global_enabled_project_name_collision_is_rejected_but_same_repo_reenrolls(
        self,
    ) -> None:
        before = self.fixture.persistence.list_compose_definitions(repo_id=REPO_ALPHA)[
            0
        ]
        same_repo = self.fixture.persistence.provision_compose_definition(
            repo_id=REPO_ALPHA,
            compose_definition_id=COMPOSE_ALPHA,
            cwd=self.fixture.alpha_root,
            files=(self.fixture.compose_one, self.fixture.compose_two),
            services=("db", "web"),
            project_name="alpha-stack",
        )
        self.assertEqual(
            same_repo["definition_fingerprint"], before["definition_fingerprint"]
        )
        self.assertEqual(same_repo["generation"], before["generation"])

        beta_compose = self.fixture.beta_root / "compose.yml"
        beta_compose.write_text("services: {}\n", encoding="utf-8")
        disabled = self.fixture.persistence.provision_compose_definition(
            repo_id=REPO_BETA,
            compose_definition_id="compose-beta",
            cwd=self.fixture.beta_root,
            files=(beta_compose,),
            services=("worker",),
            project_name="alpha-stack",
            enabled=False,
        )
        self.assertFalse(disabled["enabled"])
        with self.assertRaises(BrokerError) as raised:
            self.fixture.persistence.provision_compose_definition(
                repo_id=REPO_BETA,
                compose_definition_id="compose-beta",
                cwd=self.fixture.beta_root,
                files=(beta_compose,),
                services=("worker",),
                project_name="alpha-stack",
                enabled=True,
            )
        self.assertEqual(raised.exception.code, "compose_project_name_conflict")

    def test_observed_compose_project_name_requires_exact_repository_ownership(
        self,
    ) -> None:
        valid_snapshot = self.fixture.observed_compose_snapshot(
            owner_repo_id=REPO_ALPHA,
            project_name="alpha-stack",
        )
        accepted = self.fixture.persistence.provision_compose_definition(
            repo_id=REPO_ALPHA,
            compose_definition_id=COMPOSE_ALPHA,
            cwd=self.fixture.alpha_root,
            files=(self.fixture.compose_one, self.fixture.compose_two),
            services=("db", "web"),
            project_name="alpha-stack",
            observation_snapshot_id=valid_snapshot,
        )
        self.assertTrue(accepted["enabled"])

        for label, owner_repo_id in (
            ("foreign", REPO_BETA),
            ("unassigned", None),
        ):
            snapshot_id = self.fixture.observed_compose_snapshot(
                owner_repo_id=owner_repo_id,
                project_name="alpha-stack",
            )
            with self.subTest(label=label), self.assertRaises(BrokerError) as raised:
                self.fixture.persistence.provision_compose_definition(
                    repo_id=REPO_ALPHA,
                    compose_definition_id=COMPOSE_ALPHA,
                    cwd=self.fixture.alpha_root,
                    files=(self.fixture.compose_one, self.fixture.compose_two),
                    services=("db", "web"),
                    project_name="alpha-stack",
                    observation_snapshot_id=snapshot_id,
                )
            self.assertEqual(raised.exception.code, "compose_project_name_conflict")

    def test_legacy_compose_acl_schema_migrates_all_four_exact_operations(self) -> None:
        third_uid = os.geteuid() + 20_000
        self.fixture.persistence.provision_principal(
            uid=third_uid, account_id="account-third"
        )
        now = utc_timestamp()
        with CoordinatorStore.open(
            self.fixture.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute("DROP TABLE broker_compose_acl")
                connection.execute(
                    """
                    CREATE TABLE broker_compose_acl (
                        uid INTEGER NOT NULL
                            REFERENCES broker_acl_principals(uid) ON DELETE CASCADE,
                        repo_id TEXT NOT NULL
                            REFERENCES repositories(repo_id) ON DELETE CASCADE,
                        compose_definition_id TEXT NOT NULL
                            REFERENCES broker_compose_definitions(compose_definition_id)
                            ON DELETE CASCADE,
                        operation TEXT NOT NULL
                            CHECK(operation IN ('compose.up', 'compose.down')),
                        enabled INTEGER NOT NULL DEFAULT 1
                            CHECK(enabled IN (0, 1)),
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY(
                            uid, repo_id, compose_definition_id, operation
                        )
                    )
                    """
                )
                connection.executemany(
                    """
                    INSERT INTO broker_compose_acl(
                        uid, repo_id, compose_definition_id,
                        operation, enabled, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        (
                            os.geteuid(),
                            REPO_ALPHA,
                            COMPOSE_ALPHA,
                            "compose.up",
                            1,
                            now,
                        ),
                        (
                            os.geteuid(),
                            REPO_ALPHA,
                            COMPOSE_ALPHA,
                            "compose.down",
                            1,
                            now,
                        ),
                        (
                            self.fixture.foreign_uid,
                            REPO_ALPHA,
                            COMPOSE_ALPHA,
                            "compose.up",
                            1,
                            now,
                        ),
                        (
                            self.fixture.foreign_uid,
                            REPO_ALPHA,
                            COMPOSE_ALPHA,
                            "compose.down",
                            0,
                            now,
                        ),
                        (
                            third_uid,
                            REPO_ALPHA,
                            COMPOSE_ALPHA,
                            "compose.up",
                            0,
                            now,
                        ),
                        (
                            third_uid,
                            REPO_ALPHA,
                            COMPOSE_ALPHA,
                            "compose.down",
                            1,
                            now,
                        ),
                    ),
                )

        migrated = BrokerPersistence(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        )
        with CoordinatorStore.open(
            migrated.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.read_transaction() as connection:
                rows = list(
                    connection.execute(
                        """
                        SELECT uid, operation, enabled
                        FROM broker_compose_acl
                        WHERE repo_id = ? AND compose_definition_id = ?
                        ORDER BY uid, operation
                        """,
                        (REPO_ALPHA, COMPOSE_ALPHA),
                    )
                )
        grants = {
            (int(row["uid"]), str(row["operation"])): int(row["enabled"])
            for row in rows
        }
        self.assertEqual(
            {
                operation: grants[(os.geteuid(), operation)]
                for operation in (
                    "compose.up",
                    "compose.stop",
                    "compose.restart",
                    "compose.down",
                )
            },
            {
                "compose.up": 1,
                "compose.stop": 1,
                "compose.restart": 1,
                "compose.down": 1,
            },
        )
        self.assertEqual(grants[(self.fixture.foreign_uid, "compose.stop")], 0)
        self.assertEqual(grants[(self.fixture.foreign_uid, "compose.restart")], 0)
        self.assertEqual(grants[(third_uid, "compose.stop")], 1)
        self.assertEqual(grants[(third_uid, "compose.restart")], 0)

        fourth_uid = os.geteuid() + 30_000
        migrated.provision_principal(uid=fourth_uid, account_id="account-fourth")
        for operation in (
            BrokerOperation.COMPOSE_UP,
            BrokerOperation.COMPOSE_STOP,
            BrokerOperation.COMPOSE_RESTART,
            BrokerOperation.COMPOSE_DOWN,
        ):
            migrated.grant_resource(
                uid=fourth_uid,
                repo_id=REPO_ALPHA,
                resource_kind="compose",
                resource_id=COMPOSE_ALPHA,
                operation=operation,
            )
        with CoordinatorStore.open(
            migrated.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.read_transaction() as connection:
                accepted_operations = {
                    str(row["operation"])
                    for row in connection.execute(
                        """
                        SELECT operation FROM broker_compose_acl
                        WHERE uid = ? AND repo_id = ?
                          AND compose_definition_id = ? AND enabled = 1
                        """,
                        (fourth_uid, REPO_ALPHA, COMPOSE_ALPHA),
                    )
                }
        self.assertEqual(
            accepted_operations,
            {
                "compose.up",
                "compose.stop",
                "compose.restart",
                "compose.down",
            },
        )

    def test_legacy_compose_fingerprint_migrates_once_and_fences_pending_work(
        self,
    ) -> None:
        definition = self.fixture.persistence.list_compose_definitions(
            repo_id=REPO_ALPHA
        )[0]
        legacy_payload = json.dumps(
            {
                "repo_id": REPO_ALPHA,
                "cwd": definition["cwd"],
                "files": definition["files"],
                "file_evidence": definition["file_evidence"],
                "services": definition["services"],
                "project_name": definition["project_name"],
            },
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        legacy_fingerprint = "sha256:" + hashlib.sha256(legacy_payload).hexdigest()
        with CoordinatorStore.open(
            self.fixture.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE broker_compose_definitions
                    SET definition_fingerprint = ?, generation = 7
                    WHERE compose_definition_id = ?
                    """,
                    (legacy_fingerprint, COMPOSE_ALPHA),
                )
            evidence = self.fixture.observe_full_docker(store)

        request = self.fixture.request(
            BrokerOperation.COMPOSE_UP,
            resource_id=COMPOSE_ALPHA,
        )
        authorized = self.fixture.persistence.authorize(self.fixture.peer(), request)
        disposition = self.fixture.persistence.reserve_operation(
            authorized,
            compose_preflight=evidence,
        )
        self.assertEqual(disposition.state, "execute")

        migrated = BrokerPersistence(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        )
        migrated_definition = migrated.list_compose_definitions(repo_id=REPO_ALPHA)[0]
        self.assertNotEqual(
            migrated_definition["definition_fingerprint"], legacy_fingerprint
        )
        self.assertEqual(migrated_definition["generation"], 8)
        with CoordinatorStore.open(
            migrated.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.read_transaction() as connection:
                operation = connection.execute(
                    """
                    SELECT status, phase, error_code
                    FROM operations WHERE operation_id = ?
                    """,
                    (request.operation_id,),
                ).fetchone()
                target = connection.execute(
                    """
                    SELECT status, phase, error_json
                    FROM operation_targets WHERE operation_id = ?
                    """,
                    (request.operation_id,),
                ).fetchone()
        self.assertEqual(
            dict(operation),
            {
                "status": "needs_attention",
                "phase": "reconciliation_required",
                "error_code": "compose_definition_migrated",
            },
        )
        self.assertEqual(target["status"], "running")
        self.assertEqual(target["phase"], "reconciliation_required")
        self.assertEqual(
            json.loads(str(target["error_json"]))["code"],
            "compose_definition_migrated",
        )

        reopened = BrokerPersistence(
            self.fixture.persistence.database_path,
            expected_uid=os.geteuid(),
        )
        reopened_definition = reopened.list_compose_definitions(repo_id=REPO_ALPHA)[0]
        self.assertEqual(reopened_definition["generation"], 8)
        self.assertEqual(
            reopened_definition["definition_fingerprint"],
            migrated_definition["definition_fingerprint"],
        )

    def test_compose_file_drift_is_rejected_before_docker(self) -> None:
        calls = 0

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del cwd, timeout, environment
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

    def test_reprovision_after_reservation_is_blocked_before_host_effect(self) -> None:
        calls = 0

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del cwd, timeout, environment
            nonlocal calls
            calls += 1
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        original_reserve = self.fixture.persistence.reserve_operation

        def reserve_then_reprovision(
            authorized: Any,
            *,
            compose_preflight: Mapping[str, Any] | None = None,
        ) -> Any:
            disposition = original_reserve(
                authorized,
                compose_preflight=compose_preflight,
            )
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
        self.assertEqual(reply["error"]["code"], "compose_operation_pending")
        self.assertEqual(calls, 0)

    def test_start_fence_blocks_up_and_assign_but_allows_down_and_unassign(
        self,
    ) -> None:
        calls: list[str] = []

        def runner(
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del cwd, timeout, environment
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
            self.fixture.request(BrokerOperation.COMPOSE_UP, resource_id=COMPOSE_ALPHA),
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
        self.assertEqual(disabled_up["error"]["code"], "repository_startup_fenced")
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
            command: tuple[str, ...],
            cwd: str,
            timeout: float,
            environment: Mapping[str, str],
        ) -> subprocess.CompletedProcess[str]:
            del cwd, timeout, environment
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
