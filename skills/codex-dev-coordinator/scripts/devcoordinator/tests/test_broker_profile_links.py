"""Focused trust-profile and client-side broker linkage regression tests."""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
import pwd
import sqlite3
import tempfile
import time
import unittest
import uuid
from unittest import mock

import dev_coordinator
from devcoordinator.broker import BrokerOperation
from devcoordinator.broker_links import BrokerLinkStore
from devcoordinator.broker_profile import (
    BrokerClientProfile,
    BrokerProfileError,
    BrokerRepositoryProfile,
    BrokerServiceProfile,
    call_broker,
    load_broker_profile,
    profile_from_document,
)
import devcoordinator.broker_profile as broker_profile_module
from devcoordinator.normalized_server_lifecycle import (
    NormalizedPortLifecycle,
    PortLeaseRequest,
)
from devcoordinator.store import AccountStore, utc_timestamp


UID = os.geteuid()
REPO_ID = "repo-alpha"
DATABASE_GENERATION = "generation-alpha"


class CanonicalTemporaryDirectory:
    """Use a test-owned canonical root rather than a host symlink alias."""

    def __init__(self, prefix: str) -> None:
        home = Path(pwd.getpwuid(UID).pw_dir).resolve()
        self._temporary = tempfile.TemporaryDirectory(prefix=prefix, dir=str(home))
        self.path = Path(self._temporary.name).resolve()

    def __enter__(self) -> Path:
        return self.path

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self._temporary.cleanup()


def profile_document(
    repository_root: Path,
    *,
    client_uid: int = UID,
    valid_until_epoch: int | None = None,
) -> dict[str, object]:
    expiry = int(time.time()) + 3_600 if valid_until_epoch is None else valid_until_epoch
    return {
        "version": 1,
        "service": {
            "socket": "/run/devcoordinator/broker.sock",
            "uid": 0,
            "gid": 62000,
            "mode": "0660",
            "database_generation": DATABASE_GENERATION,
        },
        "clients": {
            str(client_uid): {
                "account_id": "account-alpha",
                "issued_at": "2026-07-14T00:00:00Z",
                "valid_until_epoch": expiry,
                "repositories": [
                    {
                        "canonical_root": str(repository_root),
                        "repo_id": REPO_ID,
                        "generation": 7,
                        "servers": {
                            "web": "server-web",
                            "worker": "server-worker",
                            "database": "server-database",
                        },
                        "containers": {"postgres": "container-postgres"},
                        "compose_definition_id": "compose-alpha",
                    }
                ],
            }
        },
    }


def parsed_profile(repository_root: Path) -> BrokerClientProfile:
    return profile_from_document(
        profile_document(repository_root), effective_uid=UID
    )


class BrokerProfileTrustTests(unittest.TestCase):
    def test_managed_health_requires_listener_in_isolated_launcher_group(self) -> None:
        server = {
            "pid": 111,
            "project": "/srv/repository",
            "host": "127.0.0.1",
            "port": 43100,
            "health_url": "http://127.0.0.1:43100/health",
            "registration_identity": {"source": "normalized_exact_listener"},
            "_managed_process_tree": True,
        }
        with (
            mock.patch.object(dev_coordinator, "pid_alive", return_value=True),
            mock.patch.object(
                dev_coordinator,
                "process_cwd_observation",
                return_value={"observable": True, "cwd": "/srv/repository"},
            ),
            mock.patch.object(
                dev_coordinator,
                "resolve_registration_pid",
                return_value=(222, {"ok": True, "pid": 222}),
            ) as resolve,
            mock.patch.object(dev_coordinator.os, "getpgid", return_value=111),
            mock.patch.object(dev_coordinator.os, "getsid", return_value=111),
            mock.patch.object(
                dev_coordinator, "http_health", return_value={"ok": True}
            ),
        ):
            health = dev_coordinator.server_health(server)

        resolve.assert_called_once_with(
            {}, host="127.0.0.1", port=43100, project="/srv/repository"
        )
        self.assertTrue(health["ok"])
        self.assertEqual(health["classification"], "healthy")
        self.assertEqual(health["identity"]["managed_launcher_pid"], 111)

        with (
            mock.patch.object(dev_coordinator, "pid_alive", return_value=True),
            mock.patch.object(
                dev_coordinator,
                "process_cwd_observation",
                return_value={"observable": True, "cwd": "/srv/repository"},
            ),
            mock.patch.object(
                dev_coordinator,
                "resolve_registration_pid",
                return_value=(333, {"ok": True, "pid": 333}),
            ),
            mock.patch.object(dev_coordinator.os, "getpgid", return_value=999),
            mock.patch.object(dev_coordinator.os, "getsid", return_value=999),
            mock.patch.object(
                dev_coordinator, "http_health", return_value={"ok": True}
            ),
        ):
            foreign = dev_coordinator.server_health(server)

        self.assertFalse(foreign["ok"])
        self.assertEqual(foreign["classification"], "wrong-listener")

    def test_running_publication_uses_exact_child_listener_pid(self) -> None:
        with CanonicalTemporaryDirectory(".broker-child-listener-") as root:
            repository_root = root / "repository"
            repository_root.mkdir(mode=0o700)
            profile = parsed_profile(repository_root)
            repository = profile.repository(str(repository_root))
            calls: list[dict[str, object]] = []

            def call(
                _profile: BrokerClientProfile,
                *,
                repository: BrokerRepositoryProfile,
                resource_id: str,
                operation: BrokerOperation,
                arguments: object = None,
                operation_id: str | None = None,
            ) -> tuple[str, dict[str, object]]:
                del _profile, repository, resource_id, operation, operation_id
                calls.append(dict(arguments or {}))
                return "operation-publish", {"status": "published"}

            with (
                mock.patch.object(BrokerClientProfile, "call", new=call),
                mock.patch.object(
                    dev_coordinator,
                    "resolve_registration_pid",
                    return_value=(222, {"pid": 222, "source": "proc_pid_fd"}),
                ) as resolve,
            ):
                result = dev_coordinator.publish_broker_server(
                    profile=profile,
                    repository=repository,
                    server_name="web",
                    broker_lease_id="broker-lease-web",
                    server={
                        "pid": 111,
                        "project": str(repository_root),
                        "host": "127.0.0.1",
                        "port": 43100,
                        "health": {"ok": True, "classification": "healthy"},
                    },
                )

            resolve.assert_called_once_with(
                {},
                host="127.0.0.1",
                port=43100,
                project=str(repository_root),
            )
            self.assertEqual(calls[0]["pid"], 222)
            self.assertEqual(result["status"], "published")

    def test_server_wide_registration_response_retains_exact_proof_and_broker_ids(self) -> None:
        with CanonicalTemporaryDirectory(".broker-register-response-") as root:
            repository_root = root / "repository"
            repository_root.mkdir(mode=0o700)
            profile = parsed_profile(repository_root)
            repository = profile.repository(str(repository_root))
            identity = {
                "ok": True,
                "observable": True,
                "pid": 111,
                "cwd": str(repository_root),
                "project": str(repository_root),
                "host": "127.0.0.1",
                "port": 43100,
                "source": "proc_pid_fd",
                "listener_inodes": ["123456"],
            }
            local_result = {
                "id": "server-web",
                "name": "web",
                "project": str(repository_root),
                "cwd": str(repository_root),
                "host": "127.0.0.1",
                "port": 43100,
                "pid": 111,
                "status": "running",
                "lease_id": "local-lease-web",
                "registration_identity": identity,
                "health": {
                    "ok": True,
                    "classification": "healthy",
                    "check": {"ok": True, "status": 200},
                    "identity": identity,
                },
            }
            reread_without_request_proof = {
                **local_result,
                "registration_identity": None,
                "health": {
                    "ok": True,
                    "classification": "healthy",
                    "identity": {"ok": True},
                },
            }
            link = mock.Mock(
                link_id="link-web",
                broker_resource_id="broker-lease-web",
                broker_operation_id="operation-lease-web",
                status="bound",
            )
            publication = {
                "operation_id": "operation-publish-web",
                "server_definition_id": "server-web",
                "lease_id": "broker-lease-web",
                "lifecycle": "running",
                "pid": 111,
                "port": 43100,
            }
            store = mock.MagicMock()
            store.__enter__.return_value = store
            store.__exit__.return_value = False
            with (
                mock.patch.object(
                    dev_coordinator,
                    "configured_broker_context",
                    return_value=(profile, repository),
                ),
                mock.patch.object(
                    dev_coordinator,
                    "acquire_broker_lease_link",
                    return_value=(link, {"listener_identity": identity}),
                ),
                mock.patch.object(
                    dev_coordinator,
                    "_coordinated_register_server_local",
                    return_value=local_result,
                ),
                mock.patch.object(
                    dev_coordinator,
                    "bind_broker_lease_link",
                    return_value=link,
                ),
                mock.patch.object(
                    dev_coordinator,
                    "state_backend",
                    return_value="sqlite",
                ),
                mock.patch.object(
                    AccountStore,
                    "open_default",
                    return_value=store,
                ),
                mock.patch.object(
                    NormalizedPortLifecycle,
                    "list_leases",
                    return_value=[{"id": "local-lease-web"}],
                ),
                mock.patch.object(
                    dev_coordinator.NormalizedServerLifecycle,
                    "server",
                    return_value=reread_without_request_proof,
                ),
                mock.patch.object(
                    dev_coordinator,
                    "publish_broker_server",
                    return_value=publication,
                ),
            ):
                result = dev_coordinator.coordinated_register_server(
                    {
                        "agent": "console-startup",
                        "project": str(repository_root),
                        "name": "web",
                        "cwd": str(repository_root),
                        "host": "127.0.0.1",
                        "port": 43100,
                        "pid": 111,
                    }
                )

            self.assertEqual(result["id"], "server-web")
            self.assertEqual(result["lease_id"], "broker-lease-web")
            self.assertEqual(result["status"], "running")
            self.assertEqual(result["registration_identity"], identity)
            self.assertEqual(result["health"], local_result["health"])
            self.assertEqual(result["broker"]["lease_id"], "broker-lease-web")

    def test_normalized_registration_response_retains_measured_health_proof(self) -> None:
        with CanonicalTemporaryDirectory(".normalized-register-response-") as root:
            repository_root = root / "repository"
            repository_root.mkdir(mode=0o700)
            identity = {
                "ok": True,
                "observable": True,
                "pid": 111,
                "cwd": str(repository_root),
                "project": str(repository_root),
                "host": "127.0.0.1",
                "port": 43100,
                "source": "proc_pid_fd",
                "listener_inodes": ["123456"],
            }
            measured_health = {
                "ok": True,
                "pid_alive": True,
                "classification": "healthy",
                "check": {"ok": True, "status": 200},
                "identity": identity,
            }
            projected_without_request_proof = {
                "id": "server-web",
                "name": "web",
                "project": str(repository_root),
                "cwd": str(repository_root),
                "host": "127.0.0.1",
                "port": 43100,
                "pid": 111,
                "status": "running",
                "lease_id": "local-lease-web",
                "health": {
                    "ok": True,
                    "classification": "healthy",
                    "identity": {"ok": True},
                },
            }
            store = mock.MagicMock()
            store.__enter__.return_value = store
            store.__exit__.return_value = False
            with (
                mock.patch.object(
                    dev_coordinator,
                    "resolve_registration_pid",
                    return_value=(111, identity),
                ),
                mock.patch.object(
                    dev_coordinator,
                    "wait_for_health",
                    return_value=measured_health,
                ),
                mock.patch.object(
                    dev_coordinator,
                    "registration_pid_identity",
                    return_value=identity,
                ),
                mock.patch.object(
                    dev_coordinator,
                    "normalized_process_instance_evidence",
                    return_value=("12345", "linux:111:12345"),
                ),
                mock.patch.object(
                    AccountStore,
                    "open_default",
                    return_value=store,
                ),
                mock.patch.object(
                    dev_coordinator.NormalizedServerLifecycle,
                    "commit_registration",
                    return_value=projected_without_request_proof,
                ),
                mock.patch.object(
                    dev_coordinator,
                    "normalized_public_server",
                    return_value=projected_without_request_proof,
                ),
            ):
                result = dev_coordinator._coordinated_register_server_normalized(
                    {
                        "agent": "console-startup",
                        "project": str(repository_root),
                        "name": "web",
                        "cwd": str(repository_root),
                        "host": "127.0.0.1",
                        "port": 43100,
                        "pid": 111,
                        "url": "http://127.0.0.1:43100",
                        "health_url": "http://127.0.0.1:43100/healthz",
                    }
                )

            self.assertEqual(result["registration_identity"], identity)
            self.assertEqual(result["health"], measured_health)

    def test_healthy_legacy_server_cannot_bypass_host_publication(self) -> None:
        with CanonicalTemporaryDirectory(".broker-legacy-server-") as root:
            repository_root = root / "repository"
            repository_root.mkdir(mode=0o700)
            (repository_root / ".git").mkdir(mode=0o700)
            profile = parsed_profile(repository_root)
            repository = profile.repository(str(repository_root))
            with (
                mock.patch.object(
                    dev_coordinator,
                    "configured_broker_context",
                    return_value=(profile, repository),
                ),
                mock.patch.object(
                    dev_coordinator,
                    "state_backend",
                    return_value=dev_coordinator.LEGACY_JSON_BACKEND,
                ),
                mock.patch.object(
                    dev_coordinator,
                    "locked_state",
                    return_value=contextlib.nullcontext({}),
                ),
                mock.patch.object(
                    dev_coordinator,
                    "find_server",
                    return_value=("server-web", {"name": "web"}),
                ),
                mock.patch.object(
                    dev_coordinator,
                    "find_port_assignment",
                    return_value=(None, None),
                ),
                mock.patch.object(
                    dev_coordinator,
                    "server_health",
                    return_value={"ok": True, "listener_observable": True},
                ),
                mock.patch.object(
                    dev_coordinator,
                    "require_listener_identity_observable",
                ),
                mock.patch.object(
                    dev_coordinator,
                    "broker_lease_link_for_server",
                    return_value=None,
                ),
                mock.patch.object(
                    dev_coordinator,
                    "_coordinated_start_server_local",
                    side_effect=AssertionError("legacy server returned as host-wide"),
                ),
                self.assertRaisesRegex(BrokerProfileError, "server register"),
            ):
                dev_coordinator.coordinated_start_server(
                    {
                        "agent": "codex-test",
                        "project": str(repository_root),
                        "name": "web",
                    }
                )

    def test_healthy_broker_linked_server_is_republished_to_host_inventory(self) -> None:
        with CanonicalTemporaryDirectory(".broker-linked-server-") as root:
            repository_root = root / "repository"
            repository_root.mkdir(mode=0o700)
            (repository_root / ".git").mkdir(mode=0o700)
            profile = parsed_profile(repository_root)
            repository = profile.repository(str(repository_root))
            link = mock.Mock(
                broker_resource_id="lease-host-web",
                link_id="link-web",
                status="bound",
            )
            local = {"id": "server-web", "name": "web", "status": "running"}
            with (
                mock.patch.object(
                    dev_coordinator,
                    "configured_broker_context",
                    return_value=(profile, repository),
                ),
                mock.patch.object(
                    dev_coordinator,
                    "state_backend",
                    return_value=dev_coordinator.LEGACY_JSON_BACKEND,
                ),
                mock.patch.object(
                    dev_coordinator,
                    "locked_state",
                    return_value=contextlib.nullcontext({}),
                ),
                mock.patch.object(
                    dev_coordinator,
                    "find_server",
                    return_value=("server-web", {"name": "web"}),
                ),
                mock.patch.object(
                    dev_coordinator,
                    "find_port_assignment",
                    return_value=(None, None),
                ),
                mock.patch.object(
                    dev_coordinator,
                    "server_health",
                    return_value={"ok": True, "listener_observable": True},
                ),
                mock.patch.object(
                    dev_coordinator,
                    "require_listener_identity_observable",
                ),
                mock.patch.object(
                    dev_coordinator,
                    "broker_lease_link_for_server",
                    return_value=link,
                ),
                mock.patch.object(
                    dev_coordinator,
                    "_coordinated_start_server_local",
                    return_value=local,
                ),
                mock.patch.object(
                    dev_coordinator,
                    "publish_broker_server",
                    return_value={"status": "published"},
                ) as publish,
            ):
                result = dev_coordinator.coordinated_start_server(
                    {
                        "agent": "codex-test",
                        "project": str(repository_root),
                        "name": "web",
                    }
                )

            publish.assert_called_once()
            self.assertEqual(result["broker"]["publication"]["status"], "published")

    def test_server_wide_inventory_uses_broker_without_opening_client_database(self) -> None:
        with CanonicalTemporaryDirectory(".broker-inventory-") as root:
            repository_root = root / "repository"
            repository_root.mkdir(mode=0o700)
            (repository_root / ".git").mkdir(mode=0o700)
            profile = parsed_profile(repository_root)
            payload = {
                "schema_version": 2,
                "repositories": [],
                "docker": {"available": None, "containers": [], "postgres": []},
                "postgres": [],
                "v1_compatibility": {
                    "servers": [
                        {
                            "id": "server-web",
                            "name": "web",
                            "status": "running",
                            "port": 3112,
                        }
                    ],
                    "leases": [],
                    "port_assignments": [],
                    "docker": {"available": None, "containers": [], "postgres": []},
                    "postgres": [],
                },
            }
            with (
                mock.patch.object(
                    dev_coordinator,
                    "configured_broker_profile",
                    return_value=profile,
                ),
                mock.patch.object(
                    BrokerClientProfile,
                    "inventory",
                    return_value=payload,
                ) as inventory,
                mock.patch.object(
                    AccountStore,
                    "open_default_read_only",
                    side_effect=AssertionError("client database opened for host inventory"),
                ),
            ):
                result = dev_coordinator.coordinated_build_inventory()

            inventory.assert_called_once_with()
            self.assertEqual(
                result["v1_compatibility"]["servers"][0]["name"], "web"
            )
            self.assertEqual(result["authority"]["scope"], "server-wide")

    def test_product_default_is_required_server_wide_authority(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
            dev_coordinator,
            "load_broker_profile",
            side_effect=BrokerProfileError("required profile missing"),
        ) as loader:
            self.assertEqual(dev_coordinator.authority_mode(), "system")
            self.assertEqual(
                dev_coordinator.coordinator_home(),
                dev_coordinator.SYSTEM_CLIENT_JOURNAL_ROOT / str(os.geteuid()),
            )
            with self.assertRaisesRegex(BrokerProfileError, "required profile"):
                dev_coordinator.configured_broker_profile()
            loader.assert_called_once_with(required=True)

        with mock.patch.dict(
            os.environ,
            {
                dev_coordinator.AUTHORITY_ENV: "account",
                "CODEX_AGENT_COORDINATOR_HOME": "/tmp/isolated-coordinator-test",
            },
            clear=True,
        ), mock.patch.object(
            dev_coordinator,
            "load_broker_profile",
            side_effect=AssertionError("isolated account mode consulted system profile"),
        ):
            self.assertEqual(dev_coordinator.authority_mode(), "account")
            self.assertEqual(
                dev_coordinator.coordinator_home(),
                Path("/tmp/isolated-coordinator-test"),
            )
            self.assertIsNone(dev_coordinator.configured_broker_profile())

    def test_missing_default_is_unconfigured_but_required_default_fails(self) -> None:
        missing = broker_profile_module.SYSTEM_PROFILE_PATH.parent / (
            ".devcoordinator-profile-intentionally-missing-for-test"
        )
        self.assertFalse(missing.exists() or missing.is_symlink())
        with mock.patch.object(
            broker_profile_module, "SYSTEM_PROFILE_PATH", missing
        ), mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(broker_profile_module.PROFILE_PATH_ENV, None)
            self.assertIsNone(load_broker_profile())
            with self.assertRaisesRegex(BrokerProfileError, "required.*missing"):
                load_broker_profile(required=True)

    def test_public_brokered_docker_and_compose_never_open_client_state(self) -> None:
        with CanonicalTemporaryDirectory(".broker-public-docker-") as root:
            repository_root = root / "repository"
            repository_root.mkdir(mode=0o700)
            (repository_root / ".git").mkdir(mode=0o700)
            profile = parsed_profile(repository_root)
            repository = profile.repository(str(repository_root))
            calls: list[tuple[str, str]] = []

            def call(
                _profile: BrokerClientProfile,
                *,
                repository: BrokerRepositoryProfile,
                resource_id: str,
                operation: BrokerOperation,
                arguments: object = None,
                operation_id: str | None = None,
            ) -> tuple[str, dict[str, object]]:
                del _profile, repository, arguments, operation_id
                calls.append((operation.value, resource_id))
                return (
                    f"operation-{len(calls)}",
                    {
                        "status": "succeeded",
                        "broker_observation": {
                            "snapshot_id": f"snapshot-{len(calls)}"
                        },
                    },
                )

            def client_state_poison(*_args: object, **_kwargs: object) -> object:
                raise AssertionError("brokered Docker reached client-local state")

            with (
                mock.patch.object(
                    dev_coordinator,
                    "configured_broker_context",
                    return_value=(profile, repository),
                ),
                mock.patch.object(BrokerClientProfile, "call", new=call),
                mock.patch.object(
                    dev_coordinator,
                    "_open_normalized_action_store",
                    side_effect=client_state_poison,
                ),
                mock.patch.object(
                    dev_coordinator,
                    "locked_state",
                    side_effect=client_state_poison,
                ),
            ):
                docker = dev_coordinator.coordinated_run_docker(
                    ["docker", "start", "postgres"],
                    project=str(repository_root),
                    agent="codex-test",
                    container="postgres",
                )
                compose = dev_coordinator.coordinated_run_docker(
                    ["docker", "compose", "up"],
                    cwd=str(repository_root),
                    project=str(repository_root),
                    agent="codex-test",
                )

            self.assertEqual(docker["broker"]["resource_id"], "container-postgres")
            self.assertEqual(
                compose["broker"]["resource_id"], "compose-alpha"
            )
            self.assertEqual(
                calls,
                [
                    ("docker.start", "container-postgres"),
                    ("compose.up", "compose-alpha"),
                ],
            )

    def test_trusted_file_loads_and_symlink_or_replaceable_ancestor_is_rejected(self) -> None:
        with CanonicalTemporaryDirectory(".broker-profile-trust-") as root:
            repository = root / "repository"
            repository.mkdir(mode=0o700)
            trusted = root / "trusted.json"
            trusted.write_text(
                json.dumps(profile_document(repository)), encoding="utf-8"
            )
            trusted.chmod(0o600)

            loaded = load_broker_profile(
                path=trusted,
                effective_uid=UID,
                required=True,
                trusted_owner_uid=UID,
            )
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.account_id, "account-alpha")

            symlink = root / "profile-link.json"
            symlink.symlink_to(trusted)
            with self.assertRaisesRegex(BrokerProfileError, "non-symlink"):
                load_broker_profile(
                    path=symlink,
                    effective_uid=UID,
                    required=True,
                    trusted_owner_uid=UID,
                )

            replaceable = root / "replaceable"
            replaceable.mkdir(mode=0o700)
            nested = replaceable / "profile.json"
            nested.write_text(
                json.dumps(profile_document(repository)), encoding="utf-8"
            )
            nested.chmod(0o600)
            replaceable.chmod(0o770)
            with self.assertRaisesRegex(BrokerProfileError, "replaceable ancestor"):
                load_broker_profile(
                    path=nested,
                    effective_uid=UID,
                    required=True,
                    trusted_owner_uid=UID,
                )

    def test_stale_enrollment_and_wrong_authenticated_uid_fail_closed(self) -> None:
        with CanonicalTemporaryDirectory(".broker-profile-expiry-") as root:
            repository = root / "repository"
            repository.mkdir()
            stale = profile_document(
                repository, valid_until_epoch=int(time.time()) - 1
            )
            with self.assertRaisesRegex(BrokerProfileError, "expired"):
                profile_from_document(stale, effective_uid=UID)

            current = profile_document(repository)
            with self.assertRaisesRegex(
                BrokerProfileError, "authenticated uid.*no valid broker enrollment"
            ):
                profile_from_document(current, effective_uid=UID + 100_000)

    def test_repository_lookup_and_resource_mappings_are_exact(self) -> None:
        with CanonicalTemporaryDirectory(".broker-profile-map-") as root:
            repository = root / "repository"
            repository.mkdir()
            profile = parsed_profile(repository)

            enrolled = profile.repository(str(repository / "."))
            self.assertEqual(enrolled.repo_id, REPO_ID)
            self.assertEqual(enrolled.server_id("web"), "server-web")
            self.assertEqual(enrolled.container_id("postgres"), "container-postgres")
            self.assertEqual(enrolled.compose_id(), "compose-alpha")

            with self.assertRaisesRegex(BrokerProfileError, "not enrolled"):
                profile.repository(str(root / "other-repository"))
            with self.assertRaisesRegex(BrokerProfileError, "server 'api'.*not enrolled"):
                enrolled.server_id("api")
            with self.assertRaisesRegex(BrokerProfileError, "Docker resource.*not enrolled"):
                enrolled.container_id("foreign-container")

    def test_call_binds_profile_database_generation_to_request(self) -> None:
        captured: list[object] = []
        constructor: list[tuple[object, dict[str, object]]] = []

        class FakeBrokerClient:
            def __init__(self, socket_path: object, **kwargs: object) -> None:
                constructor.append((socket_path, dict(kwargs)))

            def call(self, request: object) -> dict[str, object]:
                captured.append(request)
                return {"ok": True, "result": {"status": "accepted"}}

        operation_id = str(uuid.uuid4())
        service = BrokerServiceProfile(
            socket_path=Path("/run/devcoordinator/broker.sock"),
            service_uid=17,
            socket_gid=62000,
            socket_mode=0o660,
            database_generation=DATABASE_GENERATION,
        )
        with mock.patch.object(
            broker_profile_module, "BrokerClient", FakeBrokerClient
        ):
            returned_id, result = call_broker(
                service=service,
                account_id="account-alpha",
                repo_id=REPO_ID,
                resource_id="container-postgres",
                operation=BrokerOperation.DOCKER_STOP,
                operation_id=operation_id,
            )

        self.assertEqual(returned_id, operation_id)
        self.assertEqual(result, {"status": "accepted"})
        self.assertEqual(len(captured), 1)
        request = captured[0]
        self.assertEqual(request.authority_generation, DATABASE_GENERATION)
        self.assertEqual(request.account_id, "account-alpha")
        self.assertEqual(request.project_id, REPO_ID)
        self.assertEqual(
            constructor,
            [
                (
                    Path("/run/devcoordinator/broker.sock"),
                    {
                        "expected_broker_uid": 17,
                        "expected_socket_gid": 62000,
                        "expected_socket_mode": 0o660,
                        "timeout_seconds": 10.0,
                    },
                )
            ],
        )


class BrokerLinkStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = CanonicalTemporaryDirectory(".broker-links-")
        self.root = self._temporary.__enter__()
        self.repository_root = self.root / "repository"
        self.repository_root.mkdir()
        self.store = AccountStore.open_default(self.root / "account-store")
        self._seed_repository()
        self.profile = parsed_profile(self.repository_root)
        self.repository = self.profile.repository(str(self.repository_root))
        self.links = BrokerLinkStore(self.store)

    def tearDown(self) -> None:
        self.store.close()
        self._temporary.__exit__(None, None, None)

    def _seed_repository(self) -> None:
        now = utc_timestamp()
        host_id = "host-alpha"
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO hosts(
                    host_id, machine_fingerprint, platform, hostname,
                    created_at, updated_at
                ) VALUES (?, 'machine-alpha', 'test', 'test-host', ?, ?)
                """,
                (host_id, now, now),
            )
            connection.execute(
                """
                INSERT INTO repositories(
                    repo_id, host_id, canonical_root, display_name, state,
                    generation, created_at, updated_at
                ) VALUES (?, ?, ?, 'Alpha', 'active', 0, ?, ?)
                """,
                (REPO_ID, host_id, str(self.repository_root), now, now),
            )
            connection.execute(
                """
                INSERT INTO repository_installations(
                    repo_id, status, startup_fenced, generation, actor, updated_at
                ) VALUES (?, 'installed', 0, 0, 'fixture', ?)
                """,
                (REPO_ID, now),
            )

    def _reserve_lease(
        self,
        *,
        server_name: str = "web",
        server_id: str = "server-web",
        broker_lease_id: str = "broker-lease-web",
        port: int = 43100,
        operation_id: str = "operation-lease-web",
    ):
        return self.links.reserve_lease(
            profile=self.profile,
            repository=self.repository,
            server_name=server_name,
            server_definition_id=server_id,
            broker_lease_id=broker_lease_id,
            port=port,
            protocol="tcp",
            operation_id=operation_id,
            expires_at="2026-07-14T01:00:00Z",
        )

    def _reserve_assignment(
        self,
        *,
        server_name: str = "database",
        server_id: str = "server-database",
        broker_assignment_id: str = "broker-assignment-database",
        port: int = 43102,
        operation_id: str = "operation-assignment-database",
    ):
        return self.links.reserve_assignment(
            profile=self.profile,
            repository=self.repository,
            server_name=server_name,
            server_definition_id=server_id,
            broker_assignment_id=broker_assignment_id,
            port=port,
            operation_id=operation_id,
        )

    def test_first_broker_mutation_bootstraps_exact_profile_repository(self) -> None:
        with AccountStore.open_default(self.root / "empty-client-journal") as empty:
            links = BrokerLinkStore(empty)
            reserved = links.reserve_lease(
                profile=self.profile,
                repository=self.repository,
                server_name="web",
                server_definition_id="server-web",
                broker_lease_id="broker-lease-first-use",
                port=43109,
                protocol="tcp",
                operation_id="operation-first-use",
                expires_at=None,
            )
            with empty.read_transaction() as connection:
                repository = connection.execute(
                    """
                    SELECT r.repo_id, r.canonical_root, i.status
                    FROM repositories r
                    JOIN repository_installations i USING(repo_id)
                    """
                ).fetchone()
            self.assertEqual(reserved.repo_id, REPO_ID)
            self.assertEqual(
                tuple(repository),
                (REPO_ID, str(self.repository_root), "installed"),
            )

    def test_stopped_cleanup_accepts_an_already_inactive_local_lease(self) -> None:
        ports = NormalizedPortLifecycle(self.store)
        lease = ports.lease(
            PortLeaseRequest(
                agent="codex-test",
                canonical_project=str(self.repository_root),
                port_start=43108,
                port_end=43108,
                preferred=43108,
                ttl_seconds=3600,
                purpose="server:web",
            ),
            port_available=lambda _port: True,
        )
        ports.release(
            agent="codex-test",
            canonical_project=str(self.repository_root),
            lease_id=str(lease["id"]),
        )

        reconciled = dev_coordinator.release_normalized_local_lease_if_active(
            self.store,
            agent="codex-test",
            project=str(self.repository_root),
            lease_id=str(lease["id"]),
        )

        self.assertEqual(reconciled["status"], "released")

    def test_fresh_schema_lease_reserve_bind_release_is_idempotent(self) -> None:
        reserved = self._reserve_lease()
        repeated = self._reserve_lease()
        self.assertEqual(repeated, reserved)
        self.assertEqual(reserved.status, "reserved")
        self.assertEqual(reserved.broker_database_generation, DATABASE_GENERATION)

        active = self.links.bind_local_lease(reserved.link_id, "local-lease-web")
        repeated_active = self.links.bind_local_lease(
            reserved.link_id, "local-lease-web"
        )
        self.assertEqual(repeated_active, active)
        self.assertEqual(
            self.links.lease_for_local("local-lease-web"), repeated_active
        )
        self.assertEqual(
            self.links.lease_for_server(REPO_ID, "server-web"), repeated_active
        )

        pending = self.links.begin_lease_release(
            reserved.link_id, "operation-release-web"
        )
        repeated_pending = self.links.begin_lease_release(
            reserved.link_id, "operation-release-web"
        )
        self.assertEqual(repeated_pending, pending)
        released = self.links.complete_lease_release(reserved.link_id)
        self.assertEqual(released.status, "released")
        self.assertIsNone(self.links.lease_for_local("local-lease-web"))
        self.assertIsNone(self.links.lease_for_server(REPO_ID, "server-web"))

    def test_replacement_broker_lease_rebinds_only_a_released_local_link(self) -> None:
        prior = self._reserve_lease()
        self.links.bind_local_lease(prior.link_id, "local-lease-web")

        with self.assertRaises(sqlite3.IntegrityError):
            self._reserve_lease(
                broker_lease_id="broker-lease-competing",
                operation_id="operation-lease-competing",
            )

        self.links.begin_lease_release(prior.link_id, "operation-release-web")
        self.links.complete_lease_release(prior.link_id)
        competing = self._reserve_lease(
            broker_lease_id="broker-lease-competing",
            operation_id="operation-lease-competing",
        )
        replacement = self.links.bind_local_lease(
            competing.link_id, "local-lease-web"
        )

        self.assertEqual(replacement.status, "active")
        self.assertEqual(replacement.local_resource_id, "local-lease-web")
        self.assertEqual(replacement.broker_resource_id, "broker-lease-competing")
        with self.store.read_transaction() as connection:
            prior_local = connection.execute(
                "SELECT local_lease_id FROM broker_lease_links WHERE link_id = ?",
                (prior.link_id,),
            ).fetchone()[0]
        self.assertIsNone(prior_local)

    def test_renewed_broker_lease_rebinds_exact_stale_local_process_lease(self) -> None:
        reserved = self._reserve_lease()
        now = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO leases(
                    lease_id, host_id, repo_id, server_definition_id, port,
                    owner, agent, purpose, status, generation, created_at,
                    updated_at
                ) VALUES (
                    'local-lease-old', 'host-alpha', ?, 'server-web', 43100,
                    '1001', 'migration', 'server:web', 'active', 0, ?, ?
                )
                """,
                (REPO_ID, now, now),
            )
        self.links.bind_local_lease(reserved.link_id, "local-lease-old")
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                UPDATE leases
                SET status = 'stale', deactivated_at = ?, updated_at = ?
                WHERE lease_id = 'local-lease-old'
                """,
                (now, now),
            )
            connection.execute(
                """
                INSERT INTO leases(
                    lease_id, host_id, repo_id, server_definition_id, port,
                    owner, agent, purpose, status, generation, created_at,
                    updated_at
                ) VALUES (
                    'local-lease-new', 'host-alpha', ?, 'server-web', 43100,
                    '1002', 'codex-test', 'server:web', 'active', 0, ?, ?
                )
                """,
                (REPO_ID, now, now),
            )

        rebound = self.links.bind_local_lease(
            reserved.link_id, "local-lease-new"
        )

        self.assertEqual(rebound.status, "active")
        self.assertEqual(rebound.local_resource_id, "local-lease-new")
        self.assertEqual(rebound.broker_resource_id, "broker-lease-web")

    def test_renewed_broker_lease_rejects_foreign_local_replacement(self) -> None:
        reserved = self._reserve_lease()
        now = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO leases(
                    lease_id, host_id, repo_id, server_definition_id, port,
                    owner, agent, purpose, status, generation, created_at,
                    updated_at
                ) VALUES (
                    'local-lease-old', 'host-alpha', ?, 'server-web', 43100,
                    '1001', 'migration', 'server:web', 'stale', 0, ?, ?
                )
                """,
                (REPO_ID, now, now),
            )
            connection.execute(
                """
                INSERT INTO leases(
                    lease_id, host_id, repo_id, server_definition_id, port,
                    owner, agent, purpose, status, generation, created_at,
                    updated_at
                ) VALUES (
                    'local-lease-foreign', 'host-alpha', ?, 'server-web', 43101,
                    '1002', 'codex-test', 'server:web', 'active', 0, ?, ?
                )
                """,
                (REPO_ID, now, now),
            )
        self.links.bind_local_lease(reserved.link_id, "local-lease-old")

        with self.assertRaisesRegex(RuntimeError, "not bindable"):
            self.links.bind_local_lease(
                reserved.link_id, "local-lease-foreign"
            )

    def test_repository_removal_result_is_mirrored_and_hidden_idempotently(self) -> None:
        operation_id = str(uuid.uuid4())
        result = {
            "repo_id": REPO_ID,
            "plan_id": str(uuid.uuid4()),
            "status": "succeeded",
            "fence": "disabled",
            "hidden": True,
            "started": False,
        }
        first = self.links.record_and_apply_lifecycle(
            profile=self.profile,
            repository=self.repository,
            operation=BrokerOperation.REPOSITORY_REMOVE,
            resource_id=REPO_ID,
            operation_id=operation_id,
            arguments={
                "plan_id": result["plan_id"],
                "plan_fingerprint": "sha256:" + "a" * 64,
            },
            result=result,
        )
        repeated = self.links.record_and_apply_lifecycle(
            profile=self.profile,
            repository=self.repository,
            operation=BrokerOperation.REPOSITORY_REMOVE,
            resource_id=REPO_ID,
            operation_id=operation_id,
            arguments={
                "plan_id": result["plan_id"],
                "plan_fingerprint": "sha256:" + "a" * 64,
            },
            result=result,
        )
        self.assertEqual(first, repeated)
        self.assertEqual(first["status"], "applied")
        with self.store.read_transaction() as connection:
            installation = connection.execute(
                """
                SELECT status, startup_fenced FROM repository_installations
                WHERE repo_id = ?
                """,
                (REPO_ID,),
            ).fetchone()
            operation = connection.execute(
                """
                SELECT status, kind FROM operations
                WHERE kind = 'broker.mirror.repository.remove'
                """
            ).fetchone()
        self.assertEqual(tuple(installation), ("disabled", 1))
        self.assertEqual(tuple(operation), ("succeeded", "broker.mirror.repository.remove"))

    def test_repository_removal_local_mirror_failure_is_executable_reconciliation(self) -> None:
        operation_id = str(uuid.uuid4())
        result = {
            "repo_id": REPO_ID,
            "plan_id": str(uuid.uuid4()),
            "status": "succeeded",
            "fence": "disabled",
            "hidden": True,
            "started": False,
        }
        with mock.patch.object(
            self.links,
            "_apply_lifecycle_link",
            side_effect=RuntimeError("injected local commit gap"),
        ):
            with self.assertRaisesRegex(RuntimeError, "requires reconciliation"):
                self.links.record_and_apply_lifecycle(
                    profile=self.profile,
                    repository=self.repository,
                    operation=BrokerOperation.REPOSITORY_REMOVE,
                    resource_id=REPO_ID,
                    operation_id=operation_id,
                    arguments={
                        "plan_id": result["plan_id"],
                        "plan_fingerprint": "sha256:" + "b" * 64,
                    },
                    result=result,
                )
        reconciled = self.links.reconcile_pending()
        self.assertEqual(reconciled["resolved"], 1, reconciled)
        with self.store.read_transaction() as connection:
            link = connection.execute(
                "SELECT status, attempts FROM broker_lifecycle_links"
            ).fetchone()
            installation = connection.execute(
                "SELECT status, startup_fenced FROM repository_installations"
            ).fetchone()
        self.assertEqual(tuple(link), ("applied", 1))
        self.assertEqual(tuple(installation), ("disabled", 1))

    def test_lease_identity_reuse_and_local_binding_mismatch_are_rejected(self) -> None:
        reserved = self._reserve_lease()
        with self.assertRaisesRegex(RuntimeError, "conflicting linkage"):
            self._reserve_lease(port=43101)
        renewed = self.links.reserve_lease(
            profile=self.profile,
            repository=self.repository,
            server_name="web",
            server_definition_id="server-web",
            broker_lease_id="broker-lease-web",
            port=43100,
            protocol="tcp",
            operation_id="different-operation",
            expires_at="2026-07-14T02:00:00Z",
        )
        self.assertEqual(renewed.link_id, reserved.link_id)
        self.assertEqual(renewed.broker_operation_id, reserved.broker_operation_id)
        with self.store.read_transaction() as connection:
            expires_at = connection.execute(
                "SELECT expires_at FROM broker_lease_links WHERE link_id = ?",
                (reserved.link_id,),
            ).fetchone()[0]
        self.assertEqual(expires_at, "2026-07-14T02:00:00Z")

        self.links.bind_local_lease(reserved.link_id, "local-lease-web")
        with self.assertRaises(RuntimeError):
            self.links.bind_local_lease(reserved.link_id, "different-local-lease")

    def test_failed_lease_release_is_queued_once_and_later_resolved(self) -> None:
        link = self._reserve_lease(
            server_name="worker",
            server_id="server-worker",
            broker_lease_id="broker-lease-worker",
            port=43101,
            operation_id="operation-lease-worker",
        )
        self.links.begin_lease_release(link.link_id, "operation-release-worker")
        failed = self.links.fail_lease_release(
            link.link_id,
            operation_id="operation-release-worker",
            error_code="broker_unavailable",
            error_message="socket unavailable",
            rollback=False,
        )
        self.assertEqual(failed.status, "reconciliation_required")

        repeated = self.links.fail_lease_release(
            link.link_id,
            operation_id="operation-release-worker-retry",
            error_code="broker_unavailable",
            error_message="still unavailable",
            rollback=False,
        )
        self.assertEqual(repeated.status, "reconciliation_required")
        with self.store.read_transaction() as connection:
            queued = connection.execute(
                """
                SELECT link_kind, link_id, requested_action, status, attempts,
                       operation_id, error_message
                FROM broker_reconciliation_queue WHERE link_id = ?
                """,
                (link.link_id,),
            ).fetchall()
        self.assertEqual(len(queued), 1)
        self.assertEqual(
            tuple(queued[0]),
            (
                "lease",
                link.link_id,
                "release",
                "pending",
                1,
                "operation-release-worker",
                "still unavailable",
            ),
        )

        self.links.begin_lease_release(
            link.link_id, "operation-release-worker-success"
        )
        released = self.links.complete_lease_release(link.link_id)
        self.assertEqual(released.status, "released")
        with self.store.read_transaction() as connection:
            resolved = connection.execute(
                "SELECT status, resolved_at FROM broker_reconciliation_queue WHERE link_id = ?",
                (link.link_id,),
            ).fetchone()
        self.assertEqual(resolved["status"], "resolved")
        self.assertIsNotNone(resolved["resolved_at"])

    def test_reconciler_replays_exact_lease_release_and_finishes_local_state(self) -> None:
        link = self._reserve_lease(
            server_name="reconcile",
            server_id="server-reconcile",
            broker_lease_id="broker-lease-reconcile",
            port=43105,
            operation_id="operation-lease-reconcile",
        )
        now = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO leases(
                    lease_id, host_id, repo_id, server_definition_id, port,
                    status, generation, created_at, updated_at
                ) VALUES ('local-lease-reconcile', 'host-alpha', ?, ?, 43105,
                          'active', 0, ?, ?)
                """,
                (REPO_ID, "server-reconcile", now, now),
            )
        self.links.bind_local_lease(link.link_id, "local-lease-reconcile")
        release_operation_id = str(uuid.uuid4())
        self.links.begin_lease_release(link.link_id, release_operation_id)
        self.links.fail_lease_release(
            link.link_id,
            operation_id=release_operation_id,
            error_code="broker_timeout",
            error_message="first attempt timed out",
            rollback=False,
        )
        requests = []

        def caller(saved, request):
            requests.append((saved, request))
            return {
                "ok": True,
                "operation_id": request.operation_id,
                "result": {
                    "lease_id": "broker-lease-reconcile",
                    "port": 43105,
                    "protocol": "tcp",
                    "status": "released",
                },
            }

        result = self.links.reconcile_pending(caller=caller)

        self.assertEqual(result["resolved"], 1, result)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0][1].operation.value, "port.release")
        self.assertEqual(requests[0][1].operation_id, release_operation_id)
        self.assertEqual(requests[0][1].resource_id, "broker-lease-reconcile")
        with self.store.read_transaction() as connection:
            local = connection.execute(
                "SELECT status, deactivated_at FROM leases WHERE lease_id='local-lease-reconcile'"
            ).fetchone()
            queue = connection.execute(
                "SELECT status FROM broker_reconciliation_queue WHERE link_id=?",
                (link.link_id,),
            ).fetchone()
        self.assertEqual(local["status"], "released")
        self.assertIsNotNone(local["deactivated_at"])
        self.assertEqual(queue["status"], "resolved")

    def test_fresh_schema_assignment_bind_failure_queue_and_release(self) -> None:
        reserved = self._reserve_assignment()
        repeated = self._reserve_assignment()
        self.assertEqual(repeated, reserved)
        active = self.links.bind_local_assignment(
            reserved.link_id, "local-assignment-database"
        )
        repeated_active = self.links.bind_local_assignment(
            reserved.link_id, "local-assignment-database"
        )
        self.assertEqual(repeated_active, active)
        self.assertEqual(
            self.links.assignment_for_server(REPO_ID, "server-database"), active
        )

        self.links.begin_assignment_release(
            reserved.link_id, "operation-unassign-database"
        )
        failed = self.links.fail_assignment_release(
            reserved.link_id,
            operation_id="operation-unassign-database",
            error_code="broker_timeout",
            error_message="bounded broker timeout",
            rollback=True,
        )
        self.assertEqual(failed.status, "rollback_failed")
        with self.store.read_transaction() as connection:
            queued = connection.execute(
                """
                SELECT link_kind, requested_action, status
                FROM broker_reconciliation_queue WHERE link_id = ?
                """,
                (reserved.link_id,),
            ).fetchone()
        self.assertEqual(tuple(queued), ("assignment", "release", "pending"))

        self.links.begin_assignment_release(
            reserved.link_id, "operation-unassign-database-retry"
        )
        released = self.links.complete_assignment_release(reserved.link_id)
        self.assertEqual(released.status, "released")
        self.assertIsNone(
            self.links.assignment_for_server(REPO_ID, "server-database")
        )

    def test_reconciler_replays_exact_unassign_and_finishes_local_state(self) -> None:
        link = self._reserve_assignment(
            server_name="reconcile-db",
            server_id="server-reconcile-db",
            broker_assignment_id="broker-assignment-reconcile-db",
            port=43106,
            operation_id="operation-assignment-reconcile-db",
        )
        now = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO port_assignments(
                    assignment_id, host_id, repo_id, server_name, port,
                    status, generation, created_at, updated_at
                ) VALUES ('local-assignment-reconcile', 'host-alpha', ?,
                          'reconcile-db', 43106, 'active', 0, ?, ?)
                """,
                (REPO_ID, now, now),
            )
        self.links.bind_local_assignment(link.link_id, "local-assignment-reconcile")
        release_operation_id = str(uuid.uuid4())
        self.links.begin_assignment_release(link.link_id, release_operation_id)
        self.links.fail_assignment_release(
            link.link_id,
            operation_id=release_operation_id,
            error_code="broker_timeout",
            error_message="first attempt timed out",
            rollback=False,
        )
        requests = []

        def caller(saved, request):
            requests.append((saved, request))
            return {
                "ok": True,
                "operation_id": request.operation_id,
                "result": {
                    "assignment_id": "broker-assignment-reconcile-db",
                    "port": 43106,
                    "status": "released",
                    "changed": True,
                },
            }

        result = self.links.reconcile_pending(caller=caller)

        self.assertEqual(result["resolved"], 1, result)
        self.assertEqual(requests[0][1].operation.value, "port.unassign")
        self.assertEqual(requests[0][1].resource_id, "server-reconcile-db")
        with self.store.read_transaction() as connection:
            local = connection.execute(
                "SELECT status, deactivated_at FROM port_assignments WHERE assignment_id='local-assignment-reconcile'"
            ).fetchone()
        self.assertEqual(local["status"], "inactive")
        self.assertIsNotNone(local["deactivated_at"])

    def test_assignment_identity_reuse_and_local_binding_mismatch_are_rejected(self) -> None:
        reserved = self._reserve_assignment()
        with self.assertRaisesRegex(RuntimeError, "conflicting linkage"):
            self._reserve_assignment(port=43103)
        with self.assertRaisesRegex(RuntimeError, "conflicting linkage"):
            self._reserve_assignment(operation_id="different-operation")

        self.links.bind_local_assignment(
            reserved.link_id, "local-assignment-database"
        )
        with self.assertRaises(RuntimeError):
            self.links.bind_local_assignment(
                reserved.link_id, "different-local-assignment"
            )

    def test_repository_profile_mismatch_does_not_create_linkage(self) -> None:
        malformed = BrokerRepositoryProfile(
            canonical_root=str(self.repository_root),
            repo_id="repo-foreign",
            generation=0,
            server_ids={"web": "server-web"},
            container_ids={},
            compose_definition_id=None,
        )
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            self.links.reserve_lease(
                profile=self.profile,
                repository=malformed,
                server_name="web",
                server_definition_id="server-web",
                broker_lease_id="broker-lease-foreign",
                port=43105,
                protocol="tcp",
                operation_id="operation-foreign",
                expires_at=None,
            )
        with self.store.read_transaction() as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM broker_lease_links"
            ).fetchone()[0]
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
