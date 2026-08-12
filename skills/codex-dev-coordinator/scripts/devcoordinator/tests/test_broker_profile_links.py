"""Focused trust-profile and client-side broker linkage regression tests."""

from __future__ import annotations

import contextlib
from dataclasses import replace
import json
import os
from pathlib import Path
import pwd
import sqlite3
import tempfile
import threading
import time
from types import SimpleNamespace
from typing import Iterator
import unittest
import uuid
from unittest import mock

import dev_coordinator
from devcoordinator.broker import BrokerError, BrokerOperation
from devcoordinator.broker_links import BrokerLinkStore
from devcoordinator.broker_profile import (
    BrokerClientProfile,
    BrokerProfileError,
    BrokerRepositoryProfile,
    BrokerServiceProfile,
    call_broker,
    host_profile_from_document,
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
        home = Path(
            os.environ.get("DEVCOORDINATOR_TEST_TMP_ROOT")
            or pwd.getpwuid(UID).pw_dir
        ).resolve()
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
    del client_uid, valid_until_epoch
    return {
        "version": 2,
        "service": {
            "socket": "/run/devcoordinator-authority.sock",
            "database_generation": DATABASE_GENERATION,
        },
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
                "compose_container_ids": [],
                "compose_run_once_services": {},
                "ephemeral_templates": {},
                "ephemeral_secret_policies": {},
            }
        ],
    }


def parsed_profile(repository_root: Path) -> BrokerClientProfile:
    return profile_from_document(
        profile_document(repository_root), effective_uid=UID
    )


class BrokerProfileTrustTests(unittest.TestCase):
    def test_test_submission_uses_authoritative_plan_identity_without_local_lookup(
        self,
    ) -> None:
        with CanonicalTemporaryDirectory("profile-test-submit-") as repository_root:
            profile = parsed_profile(repository_root)
            operation_id = "00000000-0000-4000-8000-000000000095"
            existing = profile.repository(str(repository_root))
            duplicate = replace(
                existing,
                canonical_root=str(repository_root.parent / "duplicate-route"),
            )
            profile.repositories[duplicate.canonical_root] = duplicate
            expected = {
                "ok": True,
                "run_id": "run-one",
                "state": "queued",
                "repository_id": REPO_ID,
            }
            with (
                mock.patch.object(
                    BrokerClientProfile,
                    "repository_by_id",
                    side_effect=AssertionError("local profile lookup is forbidden"),
                ),
                mock.patch.object(
                    BrokerClientProfile,
                    "call",
                    return_value=(operation_id, expected),
                ) as call,
            ):
                result = profile.submit_test_plan(
                    repository=REPO_ID,
                    plan_id="plan-one",
                    operation_id=operation_id,
                    actor="codex:task:submit",
                )

            self.assertEqual(
                result,
                {**expected, "operation_id": operation_id},
            )
            call.assert_called_once()
            call_arguments = call.call_args.kwargs
            self.assertIs(call_arguments["repository"], existing)
            self.assertEqual(call_arguments["resource_id"], REPO_ID)
            self.assertEqual(
                call_arguments["operation"], BrokerOperation.TEST_RUN_SUBMIT
            )
            self.assertEqual(
                call_arguments["arguments"],
                {
                    "plan_id": "plan-one",
                    "expected_repository_id": REPO_ID,
                    "actor": "codex:task:submit",
                },
            )
            self.assertEqual(call_arguments["operation_id"], operation_id)
            self.assertEqual(
                call_arguments,
                {
                    "repository": existing,
                    "resource_id": REPO_ID,
                    "operation": BrokerOperation.TEST_RUN_SUBMIT,
                    "arguments": {
                        "plan_id": "plan-one",
                        "expected_repository_id": REPO_ID,
                        "actor": "codex:task:submit",
                    },
                    "operation_id": operation_id,
                },
            )

    def test_repository_if_configured_is_a_pure_exact_lookup(self) -> None:
        with CanonicalTemporaryDirectory("profile-unconfigured-read-") as repository_root:
            profile = parsed_profile(repository_root)
            missing = repository_root.parent / "new-repository"

            self.assertIsNone(profile.repository_if_configured(str(missing)))
            self.assertIs(
                profile.repository_if_configured(str(repository_root)),
                profile.repository(str(repository_root)),
            )

    def test_completed_run_uses_current_transport_without_current_run_repository(self) -> None:
        with CanonicalTemporaryDirectory("profile-retired-run-") as repository_root:
            profile = parsed_profile(repository_root)
            response = {
                "run_id": "run-retired",
                "repository_id": "repo-retired",
                "state": "failed",
            }
            with mock.patch.object(
                BrokerClientProfile,
                "call",
                return_value=(str(uuid.uuid4()), response),
            ) as call:
                result = profile.test_run_status(
                    repository="repo-retired", run_id="run-retired"
                )

            self.assertEqual(result, response)
            self.assertIs(
                call.call_args.kwargs["repository"],
                profile._current_transport_anchor(),
            )
            self.assertEqual(
                call.call_args.kwargs["resource_id"],
                profile._current_transport_anchor().repo_id,
            )

    def test_start_like_ensure_reconciles_an_already_visible_repository(self) -> None:
        with CanonicalTemporaryDirectory("profile-reconcile-existing-") as repository_root:
            profile = parsed_profile(repository_root)
            operation_id = "00000000-0000-4000-8000-000000000094"
            repository_document = dict(profile_document(repository_root)["repositories"][0])
            repository_document["execution_uid"] = UID
            reply = {
                "schema_version": 1,
                "ok": True,
                "operation_id": operation_id,
                "changed": True,
                "repository": repository_document,
            }

            with mock.patch.object(
                broker_profile_module,
                "call_broker",
                return_value=(operation_id, reply),
            ) as call:
                reconciled, changed = profile.ensure_repository_with_outcome(
                    canonical_root=str(repository_root),
                    project_kind="primary",
                    agent="codex:task:first-use-reconcile",
                    operation_id=operation_id,
                )

            self.assertTrue(changed)
            self.assertEqual(reconciled.repo_id, REPO_ID)
            self.assertEqual(reconciled.execution_uid, UID)
            call.assert_called_once()
            arguments = call.call_args.kwargs
            self.assertEqual(arguments["repo_id"], REPO_ID)
            self.assertEqual(arguments["resource_id"], REPO_ID)
            self.assertEqual(arguments["operation"], BrokerOperation.REPOSITORY_ENSURE)
            self.assertEqual(arguments["operation_id"], operation_id)

    def test_repository_profile_accepts_execution_attribution_only(self) -> None:
        with CanonicalTemporaryDirectory("profile-ensure-evidence-") as repository_root:
            document = profile_document(repository_root)
            document["repositories"][0]["execution_uid"] = UID
            parsed = profile_from_document(document, effective_uid=UID)
            self.assertEqual(parsed.repository(str(repository_root)).execution_uid, UID)

            obsolete = profile_document(repository_root)
            obsolete["repositories"][0]["owner_uid"] = UID
            with self.assertRaisesRegex(
                BrokerProfileError, "repository profile fields are invalid"
            ):
                profile_from_document(obsolete, effective_uid=UID)

            retired_prefetch_acl = profile_document(repository_root)
            retired_prefetch_acl["repositories"][0][
                "ephemeral_image_prefetch_templates"
            ] = []
            with self.assertRaisesRegex(
                BrokerProfileError, "repository profile fields are invalid"
            ):
                profile_from_document(retired_prefetch_acl, effective_uid=UID)

    def test_ensure_repository_uses_one_anchor_and_augments_only_memory(self) -> None:
        with CanonicalTemporaryDirectory("profile-bootstrap-anchor-") as repository_root:
            profile = parsed_profile(repository_root)
            new_root = repository_root.parent / "first-use-repository"
            operation_id = "00000000-0000-4000-8000-000000000091"
            document = profile_document(repository_root)
            repository_document = dict(
                document["repositories"][0]
            )
            repository_document.update(
                {
                    "canonical_root": str(new_root),
                    "repo_id": "repo-first-use",
                    "generation": 0,
                    "servers": {},
                    "containers": {},
                    "compose_definition_id": None,
                }
            )
            reply = {
                "schema_version": 1,
                "ok": True,
                "operation_id": operation_id,
                "changed": True,
                "repository": repository_document,
            }

            with mock.patch.object(
                broker_profile_module,
                "call_broker",
                side_effect=(
                    (
                        "00000000-0000-4000-8000-000000000090",
                        {
                            "schema_version": 1,
                            "ok": True,
                            "state": "unregistered",
                            "repository": None,
                        },
                    ),
                    (operation_id, reply),
                ),
            ) as call:
                adopted = profile.ensure_repository(
                    canonical_root=str(new_root),
                    project_kind="primary",
                    agent="codex:task:first-use",
                    operation_id=operation_id,
                )

            self.assertEqual(adopted.repo_id, "repo-first-use")
            self.assertIs(profile.repository(str(new_root)), adopted)
            self.assertEqual(call.call_count, 2)
            self.assertEqual(
                call.call_args_list[0],
                mock.call(
                    service=profile.service,
                    account_id="local",
                    repo_id=REPO_ID,
                    repository_generation=7,
                    resource_id=REPO_ID,
                    operation=BrokerOperation.REPOSITORY_RESOLVE,
                    arguments={"canonical_root": str(new_root)},
                    operation_id=None,
                ),
            )
            self.assertEqual(
                call.call_args_list[1],
                mock.call(
                    service=profile.service,
                    account_id="local",
                    repo_id=REPO_ID,
                    repository_generation=7,
                    resource_id=REPO_ID,
                    operation=BrokerOperation.REPOSITORY_ENSURE,
                    arguments={
                        "agent": "codex:task:first-use",
                        "canonical_root": str(new_root),
                        "project_kind": "primary",
                    },
                    operation_id=operation_id,
                ),
            )

    def test_resolve_repository_restores_broker_retained_dynamic_configuration(self) -> None:
        with CanonicalTemporaryDirectory("profile-dynamic-resolve-") as repository_root:
            profile = parsed_profile(repository_root)
            adopted_root = repository_root.parent / "adopted-in-prior-process"
            document = profile_document(repository_root)
            repository_document = dict(
                document["repositories"][0]
            )
            repository_document.update(
                {
                    "canonical_root": str(adopted_root),
                    "repo_id": "repo-prior-process",
                    "generation": 0,
                    "servers": {},
                    "containers": {},
                    "compose_definition_id": None,
                }
            )

            with mock.patch.object(
                broker_profile_module,
                "call_broker",
                return_value=(
                    "00000000-0000-4000-8000-000000000093",
                    {
                        "schema_version": 1,
                        "ok": True,
                        "state": "available",
                        "repository": repository_document,
                    },
                ),
            ) as call:
                resolved = profile.resolve_repository(str(adopted_root))

            self.assertIsNotNone(resolved)
            self.assertEqual(resolved.repo_id, "repo-prior-process")
            self.assertIs(profile.repository(str(adopted_root)), resolved)
            call.assert_called_once_with(
                service=profile.service,
                account_id="local",
                repo_id=REPO_ID,
                repository_generation=7,
                resource_id=REPO_ID,
                operation=BrokerOperation.REPOSITORY_RESOLVE,
                arguments={"canonical_root": str(adopted_root)},
                operation_id=None,
            )

    def test_dynamic_repository_resolution_never_traverses_an_absolute_authority_root(
        self,
    ) -> None:
        with CanonicalTemporaryDirectory("profile-opaque-dynamic-root-") as repository_root:
            profile = parsed_profile(repository_root)
            adopted_root = "/home/another-trusted-account/private-repository"
            document = profile_document(repository_root)
            repository_document = dict(
                document["repositories"][0]
            )
            repository_document.update(
                {
                    "canonical_root": adopted_root,
                    "repo_id": "repo-private-authority",
                    "generation": 0,
                    "servers": {},
                    "containers": {},
                    "compose_definition_id": None,
                }
            )

            with (
                mock.patch.object(
                    broker_profile_module,
                    "call_broker",
                    return_value=(
                        "00000000-0000-4000-8000-000000000095",
                        {
                            "schema_version": 1,
                            "ok": True,
                            "state": "available",
                            "repository": repository_document,
                        },
                    ),
                ) as call,
                mock.patch.object(
                    Path,
                    "resolve",
                    side_effect=PermissionError("authority root is not locally traversable"),
                ),
            ):
                resolved = profile.resolve_repository(adopted_root)

            self.assertIsNotNone(resolved)
            self.assertEqual(resolved.canonical_root, adopted_root)
            self.assertEqual(resolved.repo_id, "repo-private-authority")
            call.assert_called_once()

    def test_compose_container_scope_is_required_and_exact(self) -> None:
        with CanonicalTemporaryDirectory("profile-compose-scope-") as repository_root:
            empty_scope = profile_from_document(
                profile_document(repository_root), effective_uid=UID
            ).repository(str(repository_root))
            self.assertEqual(empty_scope.compose_container_ids, frozenset())

            missing = profile_document(repository_root)
            del missing["repositories"][0]["compose_container_ids"]
            with self.assertRaises(BrokerProfileError):
                profile_from_document(missing, effective_uid=UID)

            document = profile_document(repository_root)
            repository = document["repositories"][0]
            repository["containers"] = {
                "web": "container-web",
                "web-full-id": "container-web",
                "database": "container-postgres",
            }
            repository["compose_container_ids"] = ["container-web"]
            parsed = profile_from_document(
                document, effective_uid=UID
            ).repository(str(repository_root))
            self.assertEqual(parsed.compose_container_ids, {"container-web"})

    def test_compose_container_scope_rejects_unknown_or_duplicate_ids(self) -> None:
        with CanonicalTemporaryDirectory("profile-compose-scope-invalid-") as repository_root:
            for values in (["container-unknown"], ["container-postgres", "container-postgres"]):
                with self.subTest(values=values):
                    document = profile_document(repository_root)
                    document["repositories"][0][
                        "compose_container_ids"
                    ] = values
                    with self.assertRaises(BrokerProfileError):
                        profile_from_document(document, effective_uid=UID)

    def test_system_project_action_deduplicates_scope_and_child_ids(self) -> None:
        root = str(Path("/").joinpath("home", "private", "repository"))
        repository = BrokerRepositoryProfile(
            canonical_root=root,
            repo_id=REPO_ID,
            generation=4,
            server_ids={"worker": "server-worker", "web": "server-web"},
            container_ids={
                "compose": "container-compose",
                "compose-full": "container-compose",
                "standalone": "container-standalone",
            },
            compose_definition_id="compose-alpha",
            compose_container_ids=frozenset({"container-compose"}),
            compose_run_once_services={},
            ephemeral_templates={},
            ephemeral_secret_policies={},
        )
        inventory = {
            "resources": {
                "servers": [
                    {"server_definition_id": "server-worker", "repo_id": REPO_ID, "role": "worker"},
                    {"server_definition_id": "server-web", "repo_id": REPO_ID, "role": "web"},
                ],
                "docker": [
                    {"docker_resource_id": "container-compose"},
                    {"docker_resource_id": "container-standalone"},
                ],
            },
            "observations": {
                "servers": [
                    {"server_definition_id": "server-worker", "lifecycle": "running"},
                    {"server_definition_id": "server-web", "lifecycle": "running"},
                ],
                "docker": [
                    {"docker_resource_id": "container-compose", "lifecycle": "running"},
                    {"docker_resource_id": "container-standalone", "lifecycle": "running"},
                ],
            },
            "v1_compatibility": {
                "servers": [
                    {"id": "server-worker", "status": "running"},
                    {"id": "server-web", "status": "running"},
                ],
                "docker": {"containers": [
                    {"host_resource_id": "container-compose", "status": "running"},
                    {"host_resource_id": "container-standalone", "status": "running"},
                ]},
            },
        }
        profile = mock.Mock()
        profile.inventory.side_effect = [inventory, inventory]

        def call(**arguments: object) -> tuple[str, dict[str, object]]:
            operation = arguments["operation"]
            result = (
                {"compose_observation": {"desired_state_observed": True}}
                if operation is BrokerOperation.COMPOSE_RESTART
                else {"status": "running"}
            )
            return str(arguments["operation_id"]), result

        profile.call.side_effect = call
        parent_id = "7e436f2c-cdd7-4ce1-a926-499699ef32cd"
        with mock.patch.object(
            dev_coordinator,
            "_exact_broker_project_context",
            return_value=(profile, repository, "codex:test"),
        ):
            result = dev_coordinator.coordinated_broker_project_runtime_action(
                {"project": root, "agent": "codex:test", "operation_id": parent_id},
                action="restart",
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(
            [(item["operation"], item["resource_id"]) for item in result["actions"]],
            [
                ("compose.restart", "compose-alpha"),
                ("docker.restart", "container-standalone"),
                ("runtime.request", "server-worker"),
            ],
        )
        self.assertEqual(len({item["operation_id"] for item in result["actions"]}), 3)
        self.assertNotIn("server-web", {item["resource_id"] for item in result["actions"]})
        self.assertNotIn("container-compose", {item["resource_id"] for item in result["actions"]})

    def test_system_project_dry_run_reports_unverified_isolation(self) -> None:
        root = str(Path("/").joinpath("home", "private", "repository"))
        repository = BrokerRepositoryProfile(
            canonical_root=root,
            repo_id=REPO_ID,
            generation=4,
            server_ids={},
            container_ids={"standalone": "container-standalone"},
            compose_definition_id=None,
            compose_container_ids=frozenset(),
            compose_run_once_services={},
            ephemeral_templates={},
            ephemeral_secret_policies={},
        )
        inventory = {
            "resources": {"servers": [], "docker": [{"docker_resource_id": "container-standalone"}]},
            "observations": {"servers": [], "docker": [{"docker_resource_id": "container-standalone", "lifecycle": "running"}]},
            "v1_compatibility": {"servers": [], "docker": {"containers": [{"host_resource_id": "container-standalone", "status": "running"}]}},
        }
        profile = mock.Mock()
        profile.inventory.return_value = inventory
        with mock.patch.object(
            dev_coordinator,
            "_exact_broker_project_context",
            return_value=(profile, repository, "codex:test"),
        ):
            result = dev_coordinator.coordinated_broker_project_runtime_action(
                {"project": root, "agent": "codex:test", "dry_run": True},
                action="restart",
            )
        self.assertFalse(result["ok"], result)
        self.assertTrue(result["preflight_failed"])
        self.assertEqual(
            result["actions"][0]["readiness"]["status"], "unverified"
        )
        profile.call.assert_not_called()

    def test_exact_configured_root_does_not_require_filesystem_traversal(self) -> None:
        root = str(Path("/").joinpath("home", "private", "repository"))
        repository = BrokerRepositoryProfile(
            canonical_root=root,
            repo_id=REPO_ID,
            generation=1,
            server_ids={},
            container_ids={},
            compose_definition_id=None,
            compose_container_ids=frozenset(),
            compose_run_once_services={},
            ephemeral_templates={},
            ephemeral_secret_policies={},
        )
        profile = BrokerClientProfile(
            service=BrokerServiceProfile(
                socket_path=Path("/run/devcoordinator.sock"),
                database_generation=DATABASE_GENERATION,
            ),
            repositories={root: repository},
        )
        with mock.patch.object(
            Path,
            "resolve",
            side_effect=PermissionError("private home is not traversable"),
        ):
            selected = profile.repository(root)

        self.assertIs(selected, repository)

    def test_api_profile_watcher_keeps_listener_up_after_stable_atomic_publication(self) -> None:
        with tempfile.TemporaryDirectory(prefix="api-profile-watch-") as raw:
            root = Path(raw)
            profile = root / "client-profiles.json"
            profile.write_text('{"generation":1}\n', encoding="utf-8")
            baseline = dev_coordinator._api_profile_identity(profile)
            self.assertIsNotNone(baseline)

            stop = threading.Event()
            watcher = threading.Thread(
                target=dev_coordinator._watch_api_profile_changes,
                kwargs={
                    "path": profile,
                    "baseline": baseline,
                    "stop": stop,
                    "poll_interval_seconds": 0.01,
                    "stable_observations": 2,
                },
            )
            watcher.start()
            replacement = root / "client-profiles.next"
            replacement.write_text('{"generation":2}\n', encoding="utf-8")
            os.replace(replacement, profile)

            time.sleep(0.08)
            self.assertTrue(watcher.is_alive(),
                "a valid profile publication must not drop the API listener")
            stop.set()
            watcher.join(timeout=1.0)
            self.assertFalse(watcher.is_alive())

    def test_api_profile_watcher_ignores_unchanged_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="api-profile-stable-") as raw:
            profile = Path(raw) / "client-profiles.json"
            profile.write_text('{"generation":1}\n', encoding="utf-8")
            baseline = dev_coordinator._api_profile_identity(profile)
            self.assertIsNotNone(baseline)

            stop = threading.Event()
            watcher = threading.Thread(
                target=dev_coordinator._watch_api_profile_changes,
                kwargs={
                    "path": profile,
                    "baseline": baseline,
                    "stop": stop,
                    "poll_interval_seconds": 0.01,
                    "stable_observations": 2,
                },
            )
            watcher.start()
            time.sleep(0.06)
            stop.set()
            watcher.join(timeout=1.0)

            self.assertFalse(watcher.is_alive())

    def test_api_profile_preflight_retries_identity_race(self) -> None:
        with tempfile.TemporaryDirectory(prefix="api-profile-preflight-") as raw:
            root = Path(raw)
            profile = root / "client-profiles.json"
            profile.write_text('{"generation":1}\n', encoding="utf-8")
            replacement = root / "client-profiles.next"
            replacement.write_text('{"generation":2}\n', encoding="utf-8")
            loads = 0

            def load(**_kwargs: object) -> object:
                nonlocal loads
                loads += 1
                if loads == 1:
                    os.replace(replacement, profile)
                return object()

            with (
                mock.patch.object(dev_coordinator, "authority_mode", return_value="system"),
                mock.patch.object(
                    dev_coordinator, "configured_profile_path", return_value=profile
                ),
                mock.patch.object(
                    dev_coordinator, "load_broker_profile", side_effect=load
                ),
            ):
                watched_path, identity = (
                    dev_coordinator._validated_api_profile_identity() or (None, None)
                )

            self.assertEqual(watched_path, profile)
            self.assertEqual(identity, dev_coordinator._api_profile_identity(profile))
            self.assertEqual(loads, 2)

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

    def test_system_stop_rejects_host_visible_unconfigured_server_before_client_state(self) -> None:
        with CanonicalTemporaryDirectory(".broker-stop-access-") as root:
            configured_root = root / "prtzn-vpn"
            visible_root = root / "DevCoordinator"
            for repository_root in (configured_root, visible_root):
                repository_root.mkdir(mode=0o700)
                (repository_root / ".git").mkdir(mode=0o700)

            repository_denied = parsed_profile(configured_root)
            server_denied_document = profile_document(visible_root)
            server_denied_document["repositories"][0][
                "servers"
            ] = {"other-server": "server-other"}
            server_denied = profile_from_document(
                server_denied_document, effective_uid=UID
            )

            for profile, expected in (
                (repository_denied, "repository.*not configured"),
                (server_denied, "server 'devops-console'.*not configured"),
            ):
                with self.subTest(expected=expected):
                    with (
                        mock.patch.object(
                            dev_coordinator, "authority_mode", return_value="system"
                        ),
                        mock.patch.object(
                            dev_coordinator,
                            "load_broker_profile",
                            return_value=profile,
                        ) as load_profile,
                        mock.patch.object(
                            dev_coordinator,
                            "state_backend",
                            return_value="sqlite",
                        ),
                        mock.patch.object(
                            dev_coordinator,
                            "_normalized_server_from_options",
                            side_effect=AssertionError(
                                "unconfigured stop opened the client journal"
                            ),
                        ) as journal_lookup,
                        mock.patch.object(
                            AccountStore,
                            "open_default",
                            side_effect=AssertionError(
                                "unconfigured stop opened mutable client state"
                            ),
                        ) as client_store,
                        mock.patch.object(
                            dev_coordinator.NormalizedServerLifecycle,
                            "reserve_stop",
                            side_effect=AssertionError(
                                "unconfigured stop reserved a local lifecycle operation"
                            ),
                        ) as reserve_stop,
                        mock.patch.object(
                            dev_coordinator,
                            "stop_pid",
                            side_effect=AssertionError(
                                "unconfigured stop signaled a process"
                            ),
                        ) as stop_pid,
                    ):
                        with self.assertRaisesRegex(BrokerProfileError, expected) as raised:
                            dev_coordinator.coordinated_stop_server(
                                {
                                    "agent": "holygloryTT",
                                    "project": str(visible_root),
                                    "name": "devops-console",
                                }
                            )

                    maintenance = mock.Mock(
                        message=dev_coordinator.PUBLIC_MAINTENANCE_MESSAGE,
                        retry_after_seconds=37,
                    )
                    with (
                        mock.patch.object(
                            dev_coordinator,
                            "load_maintenance_state",
                            return_value=maintenance,
                        ) as maintenance_lookup,
                    ):
                        payload = dev_coordinator.coordinator_exception_payload(
                            raised.exception
                        )
                    self.assertEqual(payload["code"], "maintenance_in_progress")
                    self.assertEqual(payload["classification"], "maintenance")
                    self.assertEqual(payload["retry_after_seconds"], 37)
                    self.assertNotIn("matching server not found", payload["error"])
                    maintenance_lookup.assert_called_once_with()
                    with (
                        mock.patch.object(
                            dev_coordinator,
                            "load_maintenance_state",
                            return_value=None,
                        ),
                    ):
                        unfenced_payload = (
                            dev_coordinator.coordinator_exception_payload(
                                raised.exception
                            )
                        )
                    self.assertEqual(
                        unfenced_payload["code"], "broker_profile_invalid"
                    )
                    self.assertEqual(
                        unfenced_payload["classification"],
                        "broker_configuration_required",
                    )
                    load_profile.assert_called_once_with(required=True)
                    journal_lookup.assert_not_called()
                    client_store.assert_not_called()
                    reserve_stop.assert_not_called()
                    stop_pid.assert_not_called()

    def test_system_stop_allows_exact_configured_owner_to_reach_existing_lifecycle(self) -> None:
        class ExistingLifecycleReached(RuntimeError):
            pass

        with CanonicalTemporaryDirectory(".broker-stop-owner-") as root:
            repository_root = root / "DevCoordinator"
            repository_root.mkdir(mode=0o700)
            (repository_root / ".git").mkdir(mode=0o700)
            document = profile_document(repository_root)
            document["repositories"][0]["servers"] = {
                "devops-console": "server-console"
            }
            profile = profile_from_document(document, effective_uid=UID)
            events: list[str] = []
            snapshot = {
                "id": "server-console",
                "name": "devops-console",
                "project": str(repository_root),
                "generation": 11,
                "pid": None,
                "lease_id": None,
            }
            store = mock.MagicMock()
            store.__enter__.return_value = store
            store.__exit__.return_value = False

            def load_profile(*, required: bool = False) -> BrokerClientProfile:
                self.assertTrue(required)
                events.append("broker_configuration")
                return profile

            def journal_lookup(_options: object) -> dict[str, object]:
                events.append("journal_lookup")
                return snapshot

            def open_store(_home: object) -> object:
                events.append("journal_store")
                return store

            def reserve_stop(*_args: object, **_kwargs: object) -> object:
                events.append("reservation")
                raise ExistingLifecycleReached

            with (
                mock.patch.object(
                    dev_coordinator, "authority_mode", return_value="system"
                ),
                mock.patch.object(
                    dev_coordinator,
                    "load_broker_profile",
                    side_effect=load_profile,
                ),
                mock.patch.object(
                    dev_coordinator, "state_backend", return_value="sqlite"
                ),
                mock.patch.object(
                    dev_coordinator,
                    "_normalized_server_from_options",
                    side_effect=journal_lookup,
                ),
                mock.patch.object(
                    dev_coordinator, "prime_git_head_identity"
                ),
                mock.patch.object(
                    dev_coordinator,
                    "server_health",
                    return_value={"identity": {"ok": True}},
                ),
                mock.patch.object(
                    dev_coordinator, "require_listener_identity_observable"
                ),
                mock.patch.object(
                    AccountStore, "open_default", side_effect=open_store
                ),
                mock.patch.object(
                    dev_coordinator.NormalizedServerLifecycle,
                    "reserve_stop",
                    side_effect=reserve_stop,
                ),
                mock.patch.object(
                    dev_coordinator,
                    "stop_pid",
                    side_effect=AssertionError(
                        "fixture should stop at the existing reservation boundary"
                    ),
                ) as stop_pid,
            ):
                with self.assertRaises(ExistingLifecycleReached):
                    dev_coordinator.coordinated_stop_server(
                        {
                            "agent": "holyglory",
                            "project": str(repository_root),
                            "name": "devops-console",
                        }
                    )

            self.assertEqual(
                events,
                [
                    "broker_configuration",
                    "journal_lookup",
                    "journal_store",
                    "reservation",
                ],
            )
            stop_pid.assert_not_called()

    def test_server_wide_inventory_uses_broker_without_opening_client_database(self) -> None:
        with CanonicalTemporaryDirectory(".broker-inventory-") as root:
            repository_root = root / "repository"
            repository_root.mkdir(mode=0o700)
            (repository_root / ".git").mkdir(mode=0o700)
            profile = parsed_profile(repository_root)
            payload = {
                "schema_version": 3,
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

    def test_server_wide_inventory_rejects_host_observation_schema(self) -> None:
        with CanonicalTemporaryDirectory(".broker-inventory-schema-") as root:
            repository_root = root / "repository"
            repository_root.mkdir(mode=0o700)
            (repository_root / ".git").mkdir(mode=0o700)
            profile = parsed_profile(repository_root)
            with (
                mock.patch.object(
                    dev_coordinator,
                    "configured_broker_profile",
                    return_value=profile,
                ),
                mock.patch.object(
                    BrokerClientProfile,
                    "inventory",
                    return_value={"schema_version": 2},
                ),
                self.assertRaisesRegex(BrokerError, "schema-v3 graph"),
            ):
                dev_coordinator.broker_authority_inventory()

    def test_project_inventory_selects_the_requested_broker_configuration(self) -> None:
        with CanonicalTemporaryDirectory(".broker-project-inventory-") as root:
            repository_root = root / "GlobalFinance"
            repository_root.mkdir(mode=0o700)
            (repository_root / ".git").mkdir(mode=0o700)
            profile = parsed_profile(repository_root)
            payload = {
                "schema_version": 3,
                "repositories": [],
                "docker": {"available": None, "containers": [], "postgres": []},
                "postgres": [],
                "v1_compatibility": {
                    "servers": [],
                    "leases": [],
                    "port_assignments": [],
                    "docker": {
                        "available": None,
                        "containers": [],
                        "postgres": [],
                    },
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
                result = dev_coordinator.coordinated_build_inventory(
                    project=str(repository_root)
                )

            inventory.assert_called_once_with(canonical_root=str(repository_root))
            self.assertEqual(result["authority"]["scope"], "server-wide")

    def test_registration_inventory_preserves_stopped_health_while_reporting_new_listener(self) -> None:
        project = "/repos/alpha"
        stopped_health = {
            "classification": "stopped",
            "ok": False,
            "pid_alive": None,
        }
        payload = {
            "schema_version": 3,
            "v1_compatibility": {
                "urls": [],
                "servers": [
                    {
                        "id": "server-web",
                        "key": f"{project}::web",
                        "project": project,
                        "name": "web",
                        "host": "127.0.0.1",
                        "port": 443,
                        "pid": None,
                        "status": "stopped",
                        "metadata_source": "normalized-sqlite",
                        "health": stopped_health,
                        "url_is_current": False,
                    }
                ],
                "leases": [],
                "port_assignments": [
                    {
                        "id": "assignment-web",
                        "key": f"{project}::web",
                        "project": project,
                        "name": "web",
                        "port": 443,
                        "status": "active",
                    }
                ],
                "docker": {"available": None, "containers": [], "postgres": []},
                "postgres": [],
            },
        }
        live_health = {
            "classification": "healthy",
            "ok": True,
            "pid_alive": None,
            "identity": {"ok": True},
        }
        with (
            mock.patch.dict(
                os.environ,
                {
                    dev_coordinator.AUTHORITY_ENV: "account",
                    dev_coordinator.STATE_BACKEND_ENV: "sqlite",
                },
                clear=False,
            ),
            mock.patch.object(
                dev_coordinator,
                "pure_normalized_inventory",
                return_value=payload,
            ) as pure_inventory,
            mock.patch.object(
                dev_coordinator,
                "server_health",
                return_value=live_health,
            ),
            mock.patch.object(dev_coordinator, "port_open", return_value=True),
            mock.patch.object(
                dev_coordinator,
                "listener_owner_for_port",
                return_value={
                    "pid": 4242,
                    "cwd": project,
                    "project": project,
                },
            ),
        ):
            result = dev_coordinator.coordinated_build_registration_inventory(
                project=project,
                name="web",
                port=443,
            )

        pure_inventory.assert_called_once_with(
            project=project,
            include_docker=False,
        )

        server = result["v1_compatibility"]["servers"][0]
        self.assertEqual(server["status"], "stopped")
        self.assertEqual(server["health"], stopped_health)
        self.assertNotIn("registration_identity", server)
        self.assertTrue(server["port_reused"])
        self.assertEqual(
            server["port_reused_by"],
            {
                "type": "process",
                "pid": 4242,
                "cwd": project,
                "project": project,
            },
        )

    def test_registration_inventory_keeps_fresh_identity_for_running_server(self) -> None:
        project = "/repos/alpha"
        stale_health = {
            "classification": "unhealthy",
            "ok": False,
            "pid_alive": True,
        }
        identity = {
            "ok": True,
            "observable": True,
            "pid": 4242,
            "host": "127.0.0.1",
            "port": 443,
            "source": "proc_pid_fd",
            "listener_inodes": ["12345"],
        }
        live_health = {
            "classification": "healthy",
            "ok": True,
            "pid_alive": True,
            "identity": identity,
        }
        payload = {
            "schema_version": 3,
            "v1_compatibility": {
                "urls": [],
                "servers": [
                    {
                        "id": "server-web",
                        "key": f"{project}::web",
                        "project": project,
                        "name": "web",
                        "host": "127.0.0.1",
                        "port": 443,
                        "pid": 4242,
                        "status": "running",
                        "metadata_source": "normalized-sqlite",
                        "health": stale_health,
                    }
                ],
                "leases": [],
                "port_assignments": [
                    {
                        "id": "assignment-web",
                        "key": f"{project}::web",
                        "project": project,
                        "name": "web",
                        "port": 443,
                        "status": "active",
                    }
                ],
                "docker": {"available": None, "containers": [], "postgres": []},
                "postgres": [],
            },
        }
        with (
            mock.patch.dict(
                os.environ,
                {
                    dev_coordinator.AUTHORITY_ENV: "account",
                    dev_coordinator.STATE_BACKEND_ENV: "sqlite",
                },
                clear=False,
            ),
            mock.patch.object(
                dev_coordinator,
                "pure_normalized_inventory",
                return_value=payload,
            ) as pure_inventory,
            mock.patch.object(
                dev_coordinator,
                "server_health",
                return_value=live_health,
            ),
        ):
            result = dev_coordinator.coordinated_build_registration_inventory(
                project=project,
                name="web",
                port=443,
            )

        pure_inventory.assert_called_once_with(
            project=project,
            include_docker=False,
        )

        server = result["v1_compatibility"]["servers"][0]
        self.assertEqual(server["status"], "running")
        self.assertEqual(server["health"], live_health)
        self.assertEqual(server["registration_identity"], identity)

    def test_registration_inventory_uses_target_scoped_broker_in_system_mode(self) -> None:
        project = "/repos/alpha"
        payload = {
            "schema_version": 3,
            "v1_compatibility": {
                "urls": [],
                "servers": [],
                "leases": [],
                "port_assignments": [],
                "docker": {"available": None, "containers": [], "postgres": []},
                "postgres": [],
            },
        }
        with (
            mock.patch.dict(
                os.environ,
                {
                    dev_coordinator.AUTHORITY_ENV: "system",
                    dev_coordinator.STATE_BACKEND_ENV: "sqlite",
                },
                clear=False,
            ),
            mock.patch.object(
                dev_coordinator,
                "configured_broker_profile",
                return_value=mock.sentinel.profile,
            ),
            mock.patch.object(
                dev_coordinator,
                "broker_authority_inventory",
                return_value=payload,
            ) as broker_inventory,
            mock.patch.object(
                dev_coordinator,
                "pure_normalized_inventory",
                side_effect=AssertionError("system registration opened the account store"),
            ) as pure_inventory,
        ):
            dev_coordinator.coordinated_build_registration_inventory(
                project=project,
                name="web",
                port=443,
            )

        broker_inventory.assert_called_once_with(
            project=project,
            include_docker=False,
        )
        pure_inventory.assert_not_called()

    def test_registration_inventory_missing_system_profile_never_falls_back(self) -> None:
        with (
            mock.patch.dict(
                os.environ,
                {
                    dev_coordinator.AUTHORITY_ENV: "system",
                    dev_coordinator.STATE_BACKEND_ENV: "sqlite",
                },
                clear=False,
            ),
            mock.patch.object(
                dev_coordinator,
                "configured_broker_profile",
                side_effect=BrokerProfileError("required profile missing"),
            ),
            mock.patch.object(
                dev_coordinator,
                "broker_authority_inventory",
            ) as broker_inventory,
            mock.patch.object(
                dev_coordinator,
                "pure_normalized_inventory",
            ) as pure_inventory,
        ):
            with self.assertRaisesRegex(BrokerProfileError, "required profile"):
                dev_coordinator.coordinated_build_registration_inventory(
                    project="/repos/alpha",
                    name="web",
                    port=443,
                )

        broker_inventory.assert_not_called()
        pure_inventory.assert_not_called()

    def test_server_wide_observe_uses_broker_without_opening_client_database(self) -> None:
        with CanonicalTemporaryDirectory(".broker-observe-") as root:
            repository_root = root / "repository"
            repository_root.mkdir(mode=0o700)
            (repository_root / ".git").mkdir(mode=0o700)
            profile = parsed_profile(repository_root)
            repository = profile.repository(str(repository_root))
            payload = {
                "schema_version": 2,
                "status": "completed",
                "observed": True,
                "joined": False,
                "snapshot_id": "snapshot-service-owned",
                "host_id": "host-service-owned",
                "observer_domain": "host-runtime-v2:full-docker",
                "docker_available": True,
                "capability_fingerprint": "sha256:" + "2" * 64,
                "material_fingerprint": "1" * 64,
                "completed_at": "2026-07-18T12:49:29Z",
                "observation_revision": 233,
                "state_revision": 10480,
            }
            with (
                mock.patch.object(
                    dev_coordinator,
                    "authority_mode",
                    return_value="system",
                ),
                mock.patch.object(
                    dev_coordinator,
                    "configured_broker_profile",
                    return_value=profile,
                ),
                mock.patch.object(
                    BrokerClientProfile,
                    "call",
                    return_value=("observe-operation", payload),
                ) as broker_call,
                mock.patch.object(
                    AccountStore,
                    "open_default",
                    side_effect=AssertionError(
                        "client database opened for server-wide host observation"
                    ),
                ),
            ):
                result = dev_coordinator.coordinated_observe_host(
                    {
                        "agent": "agent-test",
                        "project": str(repository_root),
                        "max_age_seconds": 0,
                        "no_docker": False,
                        "backup_dir": None,
                        "legacy_home": [],
                        "legacy_backup_root": None,
                    }
                )

            broker_call.assert_called_once_with(
                repository=repository,
                resource_id=REPO_ID,
                operation=BrokerOperation.HOST_OBSERVE,
                arguments={},
            )
            self.assertEqual(result["snapshot_id"], "snapshot-service-owned")
            self.assertEqual(result["authority"]["scope"], "server-wide")
            self.assertEqual(result["request"]["agent"], "agent-test")
            self.assertEqual(result["request"]["project"], str(repository_root))
            self.assertEqual(result["max_age_seconds"], 0.0)

    def test_server_wide_observe_rejects_account_scoped_discovery_options(self) -> None:
        with CanonicalTemporaryDirectory(".broker-observe-options-") as root:
            repository_root = root / "repository"
            repository_root.mkdir(mode=0o700)
            (repository_root / ".git").mkdir(mode=0o700)
            profile = parsed_profile(repository_root)
            with (
                mock.patch.object(
                    dev_coordinator,
                    "authority_mode",
                    return_value="system",
                ),
                mock.patch.object(
                    dev_coordinator,
                    "configured_broker_profile",
                    return_value=profile,
                ),
                mock.patch.object(
                    BrokerClientProfile,
                    "call",
                    side_effect=AssertionError(
                        "invalid account-scoped observation reached broker"
                    ),
                ),
                mock.patch.object(
                    AccountStore,
                    "open_default",
                    side_effect=AssertionError(
                        "invalid server-wide observation opened client database"
                    ),
                ),
            ):
                for override in (
                    {"max_age_seconds": 300},
                    {"no_docker": True},
                    {"backup_dir": [str(root / "backups")]},
                    {"legacy_home": [str(root / "legacy")]},
                    {"legacy_backup_root": str(root / "legacy-backups")},
                ):
                    options = {
                        "agent": "agent-test",
                        "project": str(repository_root),
                        "max_age_seconds": 0,
                        "no_docker": False,
                        "backup_dir": None,
                        "legacy_home": [],
                        "legacy_backup_root": None,
                    }
                    options.update(override)
                    with self.assertRaisesRegex(
                        ValueError, "server-wide observation"
                    ):
                        dev_coordinator.coordinated_observe_host(options)

    def test_server_wide_observe_rejects_malformed_service_evidence(self) -> None:
        with CanonicalTemporaryDirectory(".broker-observe-evidence-") as root:
            repository_root = root / "repository"
            repository_root.mkdir(mode=0o700)
            (repository_root / ".git").mkdir(mode=0o700)
            profile = parsed_profile(repository_root)
            valid = {
                "schema_version": 2,
                "status": "completed",
                "observed": True,
                "joined": False,
                "snapshot_id": "snapshot-service-owned",
                "host_id": "host-service-owned",
                "observer_domain": "host-runtime-v2:full-docker",
                "docker_available": True,
                "capability_fingerprint": "sha256:" + "2" * 64,
                "material_fingerprint": "1" * 64,
                "completed_at": "2026-07-18T12:49:29Z",
                "observation_revision": 233,
                "state_revision": 10480,
            }
            malformed = (
                {**valid, "host_id": ""},
                {**valid, "joined": 1},
                {**valid, "docker_available": "yes"},
                {**valid, "capability_fingerprint": ""},
                {**valid, "material_fingerprint": "sha256:" + "1" * 64},
                {**valid, "completed_at": ""},
                {**valid, "observation_revision": -1},
                {**valid, "state_revision": True},
            )
            with (
                mock.patch.object(
                    dev_coordinator, "authority_mode", return_value="system"
                ),
                mock.patch.object(
                    dev_coordinator,
                    "configured_broker_profile",
                    return_value=profile,
                ),
                mock.patch.object(
                    AccountStore,
                    "open_default",
                    side_effect=AssertionError(
                        "malformed broker evidence opened a client database"
                    ),
                ),
            ):
                for payload in malformed:
                    with self.subTest(payload=payload), mock.patch.object(
                        BrokerClientProfile,
                        "call",
                        return_value=("observe-operation", payload),
                    ):
                        with self.assertRaises(BrokerError) as raised:
                            dev_coordinator.coordinated_observe_host(
                                {
                                    "agent": "agent-test",
                                    "project": str(repository_root),
                                    "max_age_seconds": 0,
                                    "no_docker": False,
                                    "backup_dir": None,
                                    "legacy_home": [],
                                    "legacy_backup_root": None,
                                }
                            )
                        self.assertEqual(raised.exception.code, "invalid_reply")

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

        with CanonicalTemporaryDirectory("isolated-coordinator-test-") as isolated_home:
            with mock.patch.dict(
                os.environ,
                {
                    dev_coordinator.AUTHORITY_ENV: "account",
                    "CODEX_AGENT_COORDINATOR_HOME": str(isolated_home),
                },
                clear=True,
            ), mock.patch.object(
                dev_coordinator,
                "load_broker_profile",
                side_effect=AssertionError(
                    "isolated account mode consulted system profile"
                ),
            ):
                self.assertEqual(dev_coordinator.authority_mode(), "account")
                self.assertEqual(dev_coordinator.coordinator_home(), isolated_home)
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

    def test_brokered_compose_maps_stop_restart_and_down_to_distinct_typed_operations(
        self,
    ) -> None:
        with CanonicalTemporaryDirectory(".broker-compose-actions-") as root:
            repository_root = root / "repository"
            repository_root.mkdir(mode=0o700)
            (repository_root / ".git").mkdir(mode=0o700)
            profile = parsed_profile(repository_root)
            repository = profile.repository(str(repository_root))
            calls: list[tuple[str, str, object]] = []

            def call(
                _profile: BrokerClientProfile,
                *,
                repository: BrokerRepositoryProfile,
                resource_id: str,
                operation: BrokerOperation,
                arguments: object = None,
                operation_id: str | None = None,
            ) -> tuple[str, dict[str, object]]:
                del _profile, repository, operation_id
                calls.append((operation.value, resource_id, arguments))
                return (
                    f"operation-{len(calls)}",
                    {"status": "succeeded", "action": operation.value},
                )

            def client_state_poison(*_args: object, **_kwargs: object) -> object:
                raise AssertionError("brokered Compose reached client-local state")

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
                results = [
                    dev_coordinator.coordinated_run_docker(
                        ["docker", "compose", "stop", "client-selected-service"],
                        cwd=str(repository_root),
                        project=str(repository_root),
                        agent="codex-test",
                    ),
                    dev_coordinator.coordinated_run_docker(
                        ["docker", "compose", "restart", "client-selected-service"],
                        cwd=str(repository_root),
                        project=str(repository_root),
                        agent="codex-test",
                    ),
                    dev_coordinator.coordinated_run_docker(
                        ["docker", "compose", "down"],
                        cwd=str(repository_root),
                        project=str(repository_root),
                        agent="codex-test",
                    ),
                ]

            self.assertTrue(
                all(result["broker"]["resource_id"] == "compose-alpha" for result in results)
            )
            self.assertEqual(
                calls,
                [
                    ("compose.stop", "compose-alpha", None),
                    ("compose.restart", "compose-alpha", None),
                    ("compose.down", "compose-alpha", None),
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
            )
            self.assertIsNotNone(loaded)
            self.assertEqual(len(loaded.repositories), 1)

            symlink = root / "profile-link.json"
            symlink.symlink_to(trusted)
            with self.assertRaisesRegex(BrokerProfileError, "non-symlink"):
                load_broker_profile(
                    path=symlink,
                    effective_uid=UID,
                    required=True,
                )

    def test_profile_metadata_is_not_a_local_authorization_gate(self) -> None:
        with CanonicalTemporaryDirectory(".broker-profile-unmapped-") as root:
            repository = root / "repository"
            repository.mkdir(mode=0o700)
            profile = root / "client-profiles.json"
            profile.write_text(
                json.dumps(profile_document(repository)), encoding="utf-8"
            )
            profile.chmod(0o600)
            real_lstat = Path.lstat

            def unmapped_owner(path: Path) -> os.stat_result:
                metadata = real_lstat(path)
                fields = list(metadata)
                fields[4] = 65534
                fields[5] = 65534
                return os.stat_result(fields)

            with mock.patch.object(
                broker_profile_module, "SYSTEM_PROFILE_PATH", profile
            ), mock.patch.dict(os.environ, {}, clear=False), mock.patch.object(
                Path, "lstat", new=unmapped_owner
            ):
                os.environ.pop(broker_profile_module.PROFILE_PATH_ENV, None)
                loaded = load_broker_profile(
                    effective_uid=UID,
                    required=True,
                )

                explicit = load_broker_profile(
                    path=profile,
                    effective_uid=UID,
                    required=True,
                )

                with mock.patch.dict(
                    os.environ,
                    {broker_profile_module.PROFILE_PATH_ENV: str(profile)},
                ):
                    configured = load_broker_profile(
                        effective_uid=UID,
                        required=True,
                    )

            self.assertIsNotNone(loaded)
            self.assertIsNotNone(explicit)
            self.assertIsNotNone(configured)
            self.assertEqual(len(loaded.repositories), 1)

            replaceable = root / "replaceable"
            replaceable.mkdir(mode=0o700)
            nested = replaceable / "profile.json"
            nested.write_text(
                json.dumps(profile_document(repository)), encoding="utf-8"
            )
            nested.chmod(0o666)
            replaceable.chmod(0o777)
            shared = load_broker_profile(
                path=nested,
                effective_uid=UID,
                required=True,
            )
            self.assertIsNotNone(shared)
            self.assertEqual(len(shared.repositories), 1)

    def test_profile_parsers_reject_one_malformed_repository_atomically(self) -> None:
        with CanonicalTemporaryDirectory(".broker-profile-atomic-") as root:
            first = root / "first"
            second = root / "second"
            first.mkdir()
            second.mkdir()
            document = profile_document(first)
            other_repository = json.loads(json.dumps(document["repositories"][0]))
            other_repository["canonical_root"] = str(second)
            other_repository["repo_id"] = "repo-other"
            del other_repository["ephemeral_secret_policies"]
            document["repositories"].append(other_repository)

            for parser in (profile_from_document, host_profile_from_document):
                with self.subTest(parser=parser.__name__), self.assertRaisesRegex(
                    BrokerProfileError, "repository profile fields are invalid"
                ):
                    parser(document, effective_uid=UID)

    def test_inventory_routes_only_through_explicit_configured_repository(self) -> None:
        with CanonicalTemporaryDirectory(".broker-inventory-route-") as root:
            unrelated = root / "DevCoordinator"
            requested = root / "GlobalFinance"
            unrelated.mkdir()
            requested.mkdir()
            document = profile_document(unrelated)
            repositories = document["repositories"]
            requested_repository = dict(repositories[0])
            requested_repository.update(
                {
                    "canonical_root": str(requested),
                    "repo_id": "repo-globalfinance",
                    "servers": {},
                    "containers": {},
                    "compose_definition_id": None,
                }
            )
            repositories.append(requested_repository)
            profile = profile_from_document(document, effective_uid=UID)
            calls: list[tuple[str, str, BrokerOperation, object]] = []

            def call(
                _profile: BrokerClientProfile,
                *,
                repository: BrokerRepositoryProfile,
                resource_id: str,
                operation: BrokerOperation,
                arguments: object = None,
                operation_id: str | None = None,
            ) -> tuple[str, dict[str, object]]:
                del _profile, operation_id
                calls.append(
                    (repository.repo_id, resource_id, operation, arguments)
                )
                if repository.repo_id != "repo-globalfinance":
                    raise AssertionError("inventory used an unrelated configuration")
                return "operation-inventory", {"routed_via": repository.repo_id}

            with mock.patch.object(BrokerClientProfile, "call", new=call):
                result = profile.inventory(canonical_root=str(requested))

            self.assertEqual(result, {"routed_via": "repo-globalfinance"})
            self.assertEqual(
                calls,
                [
                    (
                        "repo-globalfinance",
                        "repo-globalfinance",
                        BrokerOperation.INVENTORY_READ,
                        {},
                    )
                ],
            )

            with mock.patch.object(BrokerClientProfile, "call") as broker_call:
                with self.assertRaisesRegex(BrokerProfileError, "not configured"):
                    profile.inventory(canonical_root=str(root / "not-configured"))
            broker_call.assert_not_called()

    def test_repository_lookup_and_resource_mappings_are_exact(self) -> None:
        with CanonicalTemporaryDirectory(".broker-profile-map-") as root:
            repository = root / "repository"
            repository.mkdir()
            profile = parsed_profile(repository)

            configured = profile.repository(str(repository / "."))
            self.assertEqual(configured.repo_id, REPO_ID)
            self.assertEqual(configured.server_id("web"), "server-web")
            self.assertEqual(configured.container_id("postgres"), "container-postgres")
            self.assertEqual(configured.compose_id(), "compose-alpha")

            with self.assertRaisesRegex(BrokerProfileError, "not configured"):
                profile.repository(str(root / "other-repository"))
            with self.assertRaisesRegex(BrokerProfileError, "server 'api'.*not configured"):
                configured.server_id("api")
            with self.assertRaisesRegex(BrokerProfileError, "Docker resource.*not configured"):
                configured.container_id("foreign-container")

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
            socket_path=Path("/run/devcoordinator-authority.sock"),
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
                    Path("/run/devcoordinator-authority.sock"),
                    {"timeout_seconds": 10.0},
                )
            ],
        )

    def test_call_uses_operation_bounded_timeouts(self) -> None:
        self.assertGreater(
            broker_profile_module.HOST_OBSERVE_CLIENT_TIMEOUT_SECONDS,
            dev_coordinator.HOST_OBSERVATION_JOIN_TIMEOUT_SECONDS,
        )
        self.assertGreater(
            dev_coordinator.HOST_OBSERVATION_JOIN_TIMEOUT_SECONDS,
            dev_coordinator.HOST_OBSERVATION_BUDGET_SECONDS,
        )
        self.assertGreater(
            dev_coordinator.HOST_OBSERVATION_STALE_AFTER_SECONDS,
            dev_coordinator.HOST_OBSERVATION_BUDGET_SECONDS,
        )
        constructor: list[dict[str, object]] = []

        class FakeBrokerClient:
            def __init__(self, _socket_path: object, **kwargs: object) -> None:
                constructor.append(dict(kwargs))

            def call(self, request: object) -> dict[str, object]:
                return {
                    "ok": True,
                    "operation_id": request.operation_id,
                    "result": {"status": "accepted"},
                }

        service = BrokerServiceProfile(
            socket_path=Path("/run/devcoordinator-authority.sock"),
            database_generation=DATABASE_GENERATION,
        )
        cases = (
            (BrokerOperation.DOCKER_STOP, 10.0),
            (BrokerOperation.RUNTIME_REQUEST, 60.0),
            (BrokerOperation.COMPOSE_UP, 5 * 60.0),
            (
                BrokerOperation.INVENTORY_READ,
                broker_profile_module.INVENTORY_READ_CLIENT_TIMEOUT_SECONDS,
            ),
            (BrokerOperation.REPOSITORY_REMOVE, 60.0),
            (
                BrokerOperation.HOST_OBSERVE,
                broker_profile_module.HOST_OBSERVE_CLIENT_TIMEOUT_SECONDS,
            ),
            (
                BrokerOperation.DATABASE_BACKUP,
                broker_profile_module.DATABASE_BACKUP_CLIENT_TIMEOUT_SECONDS,
            ),
            (
                BrokerOperation.DATABASE_RESTORE,
                broker_profile_module.DATABASE_RESTORE_CLIENT_TIMEOUT_SECONDS,
            ),
        )
        with mock.patch.object(
            broker_profile_module, "BrokerClient", FakeBrokerClient
        ):
            for operation, expected_timeout in cases:
                with self.subTest(operation=operation.value):
                    call_broker(
                        service=service,
                        account_id="account-alpha",
                        repo_id=REPO_ID,
                        resource_id=(
                            REPO_ID
                            if operation
                            in {
                                BrokerOperation.REPOSITORY_REMOVE,
                                BrokerOperation.HOST_OBSERVE,
                            }
                            else "container-postgres"
                        ),
                        operation=operation,
                        arguments=(
                            {"database_name": "app"}
                            if operation == BrokerOperation.DATABASE_BACKUP
                            else (
                                {
                                    "database_name": "app",
                                    "database_backup_id": "backup-strong",
                                    "explicit": True,
                                }
                                if operation == BrokerOperation.DATABASE_RESTORE
                                else (
                                    {
                                        "plan_id": str(uuid.uuid4()),
                                        "plan_fingerprint": "sha256:" + "5" * 64,
                                    }
                                    if operation == BrokerOperation.REPOSITORY_REMOVE
                                    else (
                                        {
                                            "action": "stop",
                                            "agent": "runtime-test-agent",
                                            "root_repo_id": REPO_ID,
                                            "temporary_repo_id": None,
                                            "target_kind": "docker",
                                            "purpose": "development",
                                            "ttl_seconds": None,
                                            "kill_after_run": False,
                                        }
                                        if operation == BrokerOperation.RUNTIME_REQUEST
                                        else {}
                                    )
                                )
                            )
                        ),
                    )
                    self.assertEqual(
                        constructor[-1]["timeout_seconds"], expected_timeout
                    )
            self.assertEqual(
                broker_profile_module._broker_client_timeout_seconds(
                    BrokerOperation.TEST_PLAN_PREVIEW,
                    arguments={"launch_timeout_seconds": 987},
                ),
                1077.0,
            )
            self.assertEqual(
                broker_profile_module._broker_client_timeout_seconds(
                    BrokerOperation.REPOSITORY_ENSURE,
                    arguments={},
                ),
                60.0,
            )
            for invalid_arguments in (
                None,
                {},
                {"launch_timeout_seconds": True},
                {"launch_timeout_seconds": 0},
                {"launch_timeout_seconds": 3_601},
                {"launch_timeout_seconds": 30.0},
            ):
                with (
                    self.subTest(invalid_arguments=invalid_arguments),
                    self.assertRaisesRegex(
                        BrokerProfileError, "launch_timeout_seconds"
                    ),
                ):
                    broker_profile_module._broker_client_timeout_seconds(
                        BrokerOperation.TEST_PLAN_PREVIEW,
                        arguments=invalid_arguments,
                    )

    def test_call_accepts_one_explicit_transport_timeout_override(self) -> None:
        constructor: list[dict[str, object]] = []

        class FakeBrokerClient:
            def __init__(self, _socket_path: object, **kwargs: object) -> None:
                constructor.append(dict(kwargs))

            def call(self, request: object) -> dict[str, object]:
                return {
                    "ok": True,
                    "operation_id": request.operation_id,
                    "result": {"state": "running"},
                }

        service = BrokerServiceProfile(
            socket_path=Path("/run/devcoordinator-authority.sock"),
            database_generation=DATABASE_GENERATION,
        )
        with mock.patch.object(
            broker_profile_module, "BrokerClient", FakeBrokerClient
        ):
            call_broker(
                service=service,
                account_id="account-alpha",
                repo_id=REPO_ID,
                resource_id=REPO_ID,
                operation=BrokerOperation.TEST_RUN_STATUS,
                arguments={"run_id": "run-alpha"},
                transport_timeout_seconds=0.125,
            )

        self.assertEqual(constructor[-1]["timeout_seconds"], 0.125)
        for invalid in (True, 0, float("nan")):
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(BrokerProfileError, "timeout"),
            ):
                call_broker(
                    service=service,
                    account_id="account-alpha",
                    repo_id=REPO_ID,
                    resource_id=REPO_ID,
                    operation=BrokerOperation.TEST_RUN_STATUS,
                    arguments={"run_id": "run-alpha"},
                    transport_timeout_seconds=invalid,
                )


class SystemBrokerOnlyPortAndRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="system-broker-only-")
        self.repository_root = Path(self._temporary.name).resolve() / "repository"
        self.repository_root.mkdir()
        (self.repository_root / ".git").mkdir()
        self.profile = parsed_profile(self.repository_root)
        self.repository = self.profile.repository(str(self.repository_root))

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _no_client_store(self) -> contextlib.ExitStack:
        stack = contextlib.ExitStack()
        stack.enter_context(
            mock.patch.object(dev_coordinator, "authority_mode", return_value="system")
        )
        stack.enter_context(
            mock.patch.object(
                dev_coordinator,
                "configured_broker_context",
                return_value=(self.profile, self.repository),
            )
        )
        stack.enter_context(
            mock.patch.object(
                dev_coordinator,
                "configured_broker_profile",
                return_value=self.profile,
            )
        )
        stack.enter_context(
            mock.patch.object(
                AccountStore,
                "open_default",
                side_effect=AssertionError("system client opened a private authority store"),
            )
        )
        stack.enter_context(
            mock.patch.object(
                AccountStore,
                "open_default_read_only",
                side_effect=AssertionError("system client opened a private authority store"),
            )
        )
        return stack

    def test_port_mutations_call_only_the_broker(self) -> None:
        assignment_id = "assignment-web"
        lease_id = "lease-web"
        calls: list[dict[str, object]] = []

        def broker_call(**kwargs: object) -> tuple[str, dict[str, object]]:
            calls.append(dict(kwargs))
            operation = kwargs["operation"]
            if operation == BrokerOperation.PORT_LEASE:
                return "op-lease", {
                    "lease_id": lease_id,
                    "port": 26061,
                    "protocol": "tcp",
                    "expires_at": "2026-07-30T12:00:00Z",
                    "status": "active",
                }
            if operation == BrokerOperation.PORT_ASSIGN:
                return "op-assign", {
                    "assignment_id": assignment_id,
                    "repo_id": REPO_ID,
                    "server_definition_id": "server-web",
                    "port": 26061,
                    "status": "active",
                    "generation": 1,
                    "changed": True,
                }
            if operation == BrokerOperation.PORT_RELEASE:
                return "op-release", {
                    "lease_id": lease_id,
                    "port": 26061,
                    "protocol": "tcp",
                    "status": "released",
                }
            if operation == BrokerOperation.PORT_UNASSIGN:
                return "op-unassign", {
                    "assignment_id": assignment_id,
                    "repo_id": REPO_ID,
                    "server_definition_id": "server-web",
                    "port": 26061,
                    "status": "released",
                    "generation": 2,
                    "changed": True,
                }
            raise AssertionError(f"unexpected broker operation: {operation}")

        inventory = {
            "v1_compatibility": {
                "leases": [
                    {
                        "id": lease_id,
                        "project": str(self.repository_root),
                        "port": 26061,
                        "status": "active",
                    }
                ],
                "port_assignments": [
                    {
                        "id": assignment_id,
                        "project": str(self.repository_root),
                        "name": "web",
                        "port": 26061,
                        "status": "active",
                    }
                ],
            }
        }
        identity = {"agent": "codex-test", "project": str(self.repository_root)}
        with (
            self._no_client_store(),
            mock.patch.object(BrokerClientProfile, "call", side_effect=broker_call),
            mock.patch.object(
                dev_coordinator, "broker_authority_inventory", return_value=inventory
            ),
        ):
            leased = dev_coordinator.coordinated_lease_port(
                {**identity, "name": "web", "preferred": 26061, "ttl": 300}
            )
            assigned = dev_coordinator.coordinated_assign_port(
                {**identity, "name": "web", "port": 26061, "force": False}
            )
            released = dev_coordinator.coordinated_release_port(
                {**identity, "lease_id": lease_id}
            )
            unassigned = dev_coordinator.coordinated_unassign_port(
                {**identity, "name": "web"}
            )

        self.assertEqual(leased["id"], lease_id)
        self.assertEqual(assigned["id"], assignment_id)
        self.assertEqual(released["status"], "released")
        self.assertEqual(unassigned["status"], "unassigned")
        self.assertEqual(
            [call["operation"] for call in calls],
            [
                BrokerOperation.PORT_LEASE,
                BrokerOperation.PORT_ASSIGN,
                BrokerOperation.PORT_RELEASE,
                BrokerOperation.PORT_UNASSIGN,
            ],
        )

    def test_port_reads_use_broker_inventory_without_client_store(self) -> None:
        inventory = {
            "v1_compatibility": {
                "leases": [{"id": "lease-web", "port": 26061}],
                "port_assignments": [
                    {
                        "id": "assignment-web",
                        "project": str(self.repository_root),
                        "name": "web",
                        "port": 26061,
                    }
                ],
            }
        }
        with (
            self._no_client_store(),
            mock.patch.object(
                dev_coordinator, "broker_authority_inventory", return_value=inventory
            ) as broker_inventory,
        ):
            leases = dev_coordinator.handle_cli(
                SimpleNamespace(group="port", action="list")
            )
            assignments = dev_coordinator.handle_cli(
                SimpleNamespace(
                    group="port",
                    action="assignments",
                    project=str(self.repository_root),
                )
            )

        self.assertEqual(leases, inventory["v1_compatibility"]["leases"])
        self.assertEqual(
            assignments, inventory["v1_compatibility"]["port_assignments"]
        )
        self.assertEqual(broker_inventory.call_count, 2)

    def test_state_and_server_reads_use_broker_without_client_store(self) -> None:
        servers = [
            {
                "id": "server-web",
                "project": str(self.repository_root),
                "name": "web",
                "status": "unobserved",
            }
        ]
        inventory = {
            "schema_version": 3,
            "v1_compatibility": {
                "servers": servers,
                "leases": [],
                "port_assignments": [],
            },
        }
        runtime_result = {
            "schema_version": 1,
            "ok": True,
            "action": "status",
            "classification": "observed_not_ready",
            "repository": {
                "root_repo_id": REPO_ID,
                "effective_repo_id": REPO_ID,
            },
            "target": {"kind": "service", "id": "server-web"},
        }
        calls: list[dict[str, object]] = []

        def broker_call(**kwargs: object) -> tuple[str, dict[str, object]]:
            calls.append(dict(kwargs))
            self.assertEqual(kwargs["operation"], BrokerOperation.RUNTIME_REQUEST)
            self.assertEqual(kwargs["resource_id"], "server-web")
            arguments = kwargs["arguments"]
            self.assertIsInstance(arguments, dict)
            self.assertEqual(arguments["action"], "status")
            self.assertEqual(arguments["target_kind"], "service")
            return "operation-status", runtime_result

        with (
            self._no_client_store(),
            mock.patch.object(
                dev_coordinator,
                "broker_authority_inventory",
                return_value=inventory,
            ) as broker_inventory,
            mock.patch.object(BrokerClientProfile, "call", side_effect=broker_call),
        ):
            state = dev_coordinator.handle_cli(
                SimpleNamespace(group="state", action="show")
            )
            listed = dev_coordinator.handle_cli(
                SimpleNamespace(group="server", action="list")
            )
            status = dev_coordinator.handle_cli(
                SimpleNamespace(
                    group="server",
                    action="status",
                    agent=None,
                    project=str(self.repository_root),
                    name="web",
                    health_timeout=10,
                )
            )
            with self.assertRaises(
                dev_coordinator.StructuredCoordinatorError
            ) as logs_error:
                dev_coordinator.handle_cli(
                    SimpleNamespace(
                        group="server",
                        action="logs",
                        server_id="server-web",
                        project=None,
                        name=None,
                        tail="200",
                    )
                )

        self.assertIs(state, inventory)
        self.assertEqual(listed, servers)
        self.assertEqual(
            status,
            {**runtime_result, "operation_id": "operation-status"},
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(broker_inventory.call_count, 2)
        self.assertEqual(
            logs_error.exception.payload["code"],
            "broker_runtime_artifact_unsupported",
        )
        self.assertEqual(
            logs_error.exception.payload["classification"],
            "unsupported_safe_read",
        )

    def test_system_log_capture_uses_profile_ids_without_repository_traversal(self) -> None:
        artifact_id = "11111111-1111-4111-8111-111111111111"
        calls: list[dict[str, object]] = []

        def broker_call(**kwargs: object) -> tuple[str, dict[str, object]]:
            calls.append(dict(kwargs))
            arguments = kwargs["arguments"]
            self.assertIsInstance(arguments, dict)
            target_kind = str(arguments["target_kind"])
            resource_id = str(kwargs["resource_id"])
            return "operation-capture", {
                "schema_version": 1,
                "ok": True,
                "action": "capture_logs",
                "classification": "available",
                "repository": {
                    "root_repo_id": REPO_ID,
                    "effective_repo_id": REPO_ID,
                    "kind": "root",
                },
                "target": {"kind": target_kind, "id": resource_id},
                "artifact": {
                    "artifact_id": artifact_id,
                    "resource_kind": target_kind,
                    "target_resource_id": resource_id,
                    "captured_at": "2026-07-31T00:00:00Z",
                    "truncated": False,
                },
                "artifact_content": {
                    "artifact_id": artifact_id,
                    "text": f"{target_kind} log\n",
                },
            }

        with (
            self._no_client_store(),
            mock.patch.object(BrokerClientProfile, "call", side_effect=broker_call),
            mock.patch.object(
                Path,
                "resolve",
                side_effect=PermissionError("private home is not traversable"),
            ),
        ):
            results = []
            for target in (
                {"kind": "service", "id": "server-web", "name": "web"},
                {
                    "kind": "docker",
                    "id": "container-postgres",
                    "name": "alpha-postgres-1",
                },
            ):
                results.append(
                    dev_coordinator.coordinated_runtime_request(
                        {
                            "schema_version": 1,
                            "agent": "devops-console:operator@example.test",
                            "root_repo": str(self.repository_root),
                            "temporary_repo": None,
                            "target": target,
                            "action": "capture_logs",
                            "purpose": "development",
                            "ttl_seconds": None,
                            "kill_after_run": False,
                            "options": {},
                        }
                    )
                )

        self.assertEqual([result["ok"] for result in results], [True, True])
        self.assertEqual(
            [call["operation"] for call in calls],
            [BrokerOperation.RUNTIME_REQUEST, BrokerOperation.RUNTIME_REQUEST],
        )
        self.assertTrue(all(call["repository"] is self.repository for call in calls))
        self.assertEqual(
            [
                (
                    call["arguments"]["root_repo_id"],
                    call["arguments"]["temporary_repo_id"],
                    call["arguments"]["target_kind"],
                )
                for call in calls
            ],
            [
                (REPO_ID, None, "service"),
                (REPO_ID, None, "docker"),
            ],
        )

    def test_system_log_capture_refreshes_repository_adopted_after_profile_install(
        self,
    ) -> None:
        adopted_root = str(self.repository_root.parent / "design-doc-engine")
        document = profile_document(self.repository_root)
        repository_document = dict(
            document["repositories"][0]
        )
        repository_document.update(
            {
                "canonical_root": adopted_root,
                "repo_id": "repo-design-doc-engine",
                "generation": 0,
                "servers": {"design-doc": "server-design-doc"},
                "containers": {},
                "compose_definition_id": None,
            }
        )
        artifact_id = "55555555-5555-4555-8555-555555555555"
        calls: list[dict[str, object]] = []

        def broker_call(**kwargs: object) -> tuple[str, dict[str, object]]:
            calls.append(dict(kwargs))
            if kwargs["operation"] == BrokerOperation.REPOSITORY_RESOLVE:
                self.assertEqual(kwargs["account_id"], "local")
                self.assertEqual(kwargs["repo_id"], self.repository.repo_id)
                return "operation-resolve", {
                    "schema_version": 1,
                    "ok": True,
                    "state": "available",
                    "repository": repository_document,
                }
            self.assertEqual(kwargs["operation"], BrokerOperation.RUNTIME_REQUEST)
            self.assertEqual(kwargs["resource_id"], "server-design-doc")
            self.assertEqual(kwargs["repo_id"], "repo-design-doc-engine")
            self.assertEqual(kwargs["account_id"], "local")
            return "operation-capture", {
                "schema_version": 1,
                "ok": True,
                "action": "capture_logs",
                "classification": "available",
                "repository": {
                    "root_repo_id": "repo-design-doc-engine",
                    "effective_repo_id": "repo-design-doc-engine",
                    "kind": "root",
                },
                "target": {"kind": "service", "id": "server-design-doc"},
                "artifact": {
                    "artifact_id": artifact_id,
                    "resource_kind": "service",
                    "target_resource_id": "server-design-doc",
                    "captured_at": "2026-08-04T00:00:00Z",
                    "truncated": False,
                },
                "artifact_content": {
                    "artifact_id": artifact_id,
                    "text": "resolved authority log\n",
                },
            }

        with (
            self._no_client_store(),
            mock.patch.object(
                broker_profile_module,
                "call_broker",
                side_effect=broker_call,
            ),
        ):
            result = dev_coordinator.coordinated_runtime_request(
                {
                    "schema_version": 1,
                    "agent": "devops-console:operator@example.test",
                    "root_repo": adopted_root,
                    "temporary_repo": None,
                    "target": {
                        "kind": "service",
                        "id": "server-design-doc",
                        "name": "design-doc",
                    },
                    "action": "capture_logs",
                    "purpose": "development",
                    "ttl_seconds": None,
                    "kill_after_run": False,
                    "options": {},
                }
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(
            [call["operation"] for call in calls],
            [BrokerOperation.REPOSITORY_RESOLVE, BrokerOperation.RUNTIME_REQUEST],
        )
        self.assertEqual(calls[0]["account_id"], "local")
        self.assertEqual(calls[1]["account_id"], "local")
        self.assertEqual(self.profile.repository(adopted_root).repo_id, "repo-design-doc-engine")

    def test_system_runtime_remove_and_account_artifact_never_open_client_store(self) -> None:
        request = {
            "schema_version": 1,
            "agent": "codex-test",
            "root_repo": str(self.repository_root),
            "temporary_repo": None,
            "target": {"kind": "service", "id": "server-web", "name": "web"},
            "action": "remove",
            "purpose": "development",
            "ttl_seconds": None,
            "kill_after_run": False,
            "options": {"reason": "obsolete"},
        }
        with self._no_client_store():
            result = dev_coordinator.coordinated_runtime_request(request)
            with self.assertRaises(dev_coordinator.StructuredCoordinatorError) as raised:
                dev_coordinator.coordinated_runtime_artifact(
                    resource_kind="service", resource_id="server-web"
                )

        self.assertFalse(result["ok"])
        self.assertIn(
            result["evidence"]["code"],
            {"broker_runtime_options_forbidden", "unsupported_runtime_action"},
        )
        self.assertEqual(
            raised.exception.payload["code"], "broker_runtime_artifact_unsupported"
        )


class BrokerAwarePortReleaseFallbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="broker-port-release-")
        self.root = Path(self._temporary.name).resolve()
        self.repository_root = self.root / "repository"
        self.repository_root.mkdir()
        (self.repository_root / ".git").mkdir()
        self.client_home = self.root / "client-journal"
        self.profile = parsed_profile(self.repository_root)
        self.repository = self.profile.repository(str(self.repository_root))

    def tearDown(self) -> None:
        self._temporary.cleanup()

    @contextlib.contextmanager
    def _client_journal(self) -> Iterator[None]:
        with mock.patch.dict(
            os.environ,
            {
                dev_coordinator.AUTHORITY_ENV: "account",
                "CODEX_AGENT_COORDINATOR_HOME": str(self.client_home),
                dev_coordinator.STATE_BACKEND_ENV: "sqlite",
            },
            clear=False,
        ):
            yield

    def _release(self, lease_id: str) -> dict[str, object]:
        return dev_coordinator.coordinated_release_port(
            {
                "agent": "codex-test",
                "project": str(self.repository_root),
                "lease_id": lease_id,
            }
        )

    def test_broker_only_expired_lease_releases_with_the_current_profile(self) -> None:
        broker_lease_id = "broker-expired-lease"
        calls: list[dict[str, object]] = []

        def call_broker(**kwargs: object) -> tuple[str, dict[str, object]]:
            calls.append(dict(kwargs))
            return (
                "operation-release-broker-only",
                {
                    "lease_id": broker_lease_id,
                    "port": 26067,
                    "protocol": "tcp",
                    "status": "released",
                },
            )

        with (
            self._client_journal(),
            mock.patch.object(
                dev_coordinator,
                "configured_broker_context",
                return_value=(self.profile, self.repository),
            ),
            mock.patch.object(
                broker_profile_module,
                "call_broker",
                side_effect=call_broker,
            ),
        ):
            result = self._release(broker_lease_id)

        self.assertEqual(result["id"], broker_lease_id)
        self.assertEqual(result["port"], 26067)
        self.assertEqual(result["project"], str(self.repository_root))
        self.assertEqual(result["status"], "released")
        self.assertEqual(
            result["broker"],
            {
                "lease_id": broker_lease_id,
                "status": "released",
                "operation_id": "operation-release-broker-only",
                "result": {
                    "lease_id": broker_lease_id,
                    "port": 26067,
                    "protocol": "tcp",
                    "status": "released",
                },
            },
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["service"], self.profile.service)
        self.assertEqual(calls[0]["account_id"], "local")
        self.assertEqual(calls[0]["repo_id"], REPO_ID)
        self.assertEqual(calls[0]["resource_id"], broker_lease_id)
        self.assertEqual(calls[0]["operation"], BrokerOperation.PORT_RELEASE)
        self.assertIsNone(calls[0]["arguments"])

    def test_broker_only_release_refuses_missing_or_invalid_profile(self) -> None:
        with self._client_journal(), mock.patch.object(
            broker_profile_module, "call_broker"
        ) as call_broker:
            with mock.patch.object(
                dev_coordinator,
                "configured_broker_context",
                return_value=None,
            ), self.assertRaisesRegex(KeyError, "matching lease not found"):
                self._release("broker-missing-profile")
            with mock.patch.object(
                dev_coordinator,
                "configured_broker_context",
                side_effect=BrokerProfileError("profile owner is untrusted"),
            ), self.assertRaisesRegex(BrokerProfileError, "untrusted"):
                self._release("broker-invalid-profile")

        call_broker.assert_not_called()

    def test_local_release_never_uses_the_broker_only_fallback(self) -> None:
        with self._client_journal():
            with AccountStore.open_default(self.client_home) as store:
                host_id = store.ensure_local_host()
                timestamp = utc_timestamp()
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        INSERT INTO repositories(
                            repo_id, host_id, canonical_root, display_name, state,
                            generation, created_at, updated_at
                        ) VALUES ('local-repo', ?, ?, 'Local', 'active', 0, ?, ?)
                        """,
                        (host_id, str(self.repository_root), timestamp, timestamp),
                    )
                    connection.execute(
                        """
                        INSERT INTO repository_installations(
                            repo_id, status, startup_fenced, generation, actor, updated_at
                        ) VALUES ('local-repo', 'installed', 0, 0, 'fixture', ?)
                        """,
                        (timestamp,),
                    )
                lease = NormalizedPortLifecycle(store).lease(
                    PortLeaseRequest(
                        agent="codex-test",
                        canonical_project=str(self.repository_root),
                        port_start=26067,
                        port_end=26067,
                        preferred=26067,
                        ttl_seconds=600,
                        purpose="manual",
                    ),
                    port_available=lambda _port: True,
                )

            with mock.patch.object(
                dev_coordinator,
                "configured_broker_context",
                side_effect=AssertionError("local release reached broker fallback"),
            ):
                released = self._release(str(lease["id"]))
                with self.assertRaisesRegex(KeyError, "matching lease not found"):
                    self._release(str(lease["id"]))

        self.assertEqual(released["id"], lease["id"])
        self.assertEqual(released["status"], "released")


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
                ) VALUES (?, ?, ?, 'Alpha', 'active', 7, ?, ?)
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
        local_host_id = self.store.ensure_local_host()
        local_repo_id = "repo-local-lifecycle"
        now = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO repositories(
                    repo_id, host_id, canonical_root, display_name, state,
                    generation, created_at, updated_at
                ) VALUES (?, ?, ?, 'Local lifecycle', 'active', 0, ?, ?)
                """,
                (
                    local_repo_id,
                    local_host_id,
                    str(self.repository_root),
                    now,
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO repository_installations(
                    repo_id, status, startup_fenced, generation, actor,
                    updated_at
                ) VALUES (?, 'installed', 0, 0, 'fixture', ?)
                """,
                (local_repo_id, now),
            )
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
        with self.store.read_transaction() as connection:
            owner = connection.execute(
                "SELECT host_id, repo_id FROM leases WHERE lease_id = ?",
                (str(lease["id"]),),
            ).fetchone()
        self.assertEqual(tuple(owner), (local_host_id, local_repo_id))
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
        prior = self.links.bind_local_lease(prior.link_id, "local-lease-web")

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

    def test_listener_adoption_reconciles_superseded_active_link_first(self) -> None:
        prior = self._reserve_lease()
        prior = self.links.bind_local_lease(prior.link_id, "local-lease-web")
        order: list[str] = []
        store_root = self.root / "account-store"

        def release_existing(link: object, *, rollback: bool) -> dict[str, object]:
            self.assertEqual(link, prior)
            self.assertFalse(rollback)
            order.append("release")
            with AccountStore.open_default(store_root) as store:
                links = BrokerLinkStore(store)
                links.begin_lease_release(prior.link_id, "release-prior")
                links.complete_lease_release(prior.link_id)
            return {"status": "released"}

        def reserve_replacement(**_kwargs: object) -> tuple[str, dict[str, object]]:
            order.append("reserve")
            return (
                "operation-replacement",
                {
                    "lease_id": "broker-lease-replacement",
                    "port": 43100,
                    "protocol": "tcp",
                    "status": "active",
                    "expires_at": "2026-07-14T02:00:00Z",
                },
            )

        with mock.patch.object(
            dev_coordinator, "coordinator_home", return_value=store_root
        ), mock.patch.object(
            dev_coordinator,
            "release_broker_lease_link",
            side_effect=release_existing,
        ), mock.patch.object(
            BrokerClientProfile,
            "call",
            side_effect=reserve_replacement,
        ):
            replacement, result = dev_coordinator.acquire_broker_lease_link(
                profile=self.profile,
                repository=self.repository,
                server_name="web",
                requested_port=43100,
                ttl_seconds=600,
                adopt_existing_listener=True,
            )

        self.assertEqual(order, ["release", "reserve"])
        self.assertEqual(replacement.broker_resource_id, "broker-lease-replacement")
        self.assertEqual(result["lease_id"], "broker-lease-replacement")

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
            compose_container_ids=frozenset(),
            compose_run_once_services={},
            ephemeral_templates={},
            ephemeral_secret_policies={},
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

    def test_permanent_revocation_blocks_stale_profile_and_allows_new_incarnation(
        self,
    ) -> None:
        reserved = self._reserve_lease(
            server_name="worker",
            server_id="server-worker",
            broker_lease_id="broker-lease-worker-old",
            operation_id="operation-lease-worker-old",
        )
        with self.assertRaisesRegex(RuntimeError, "unresolved local lease"):
            self.links.revoke_server_materialization(
                profile=self.profile,
                repository=self.repository,
                server_name="worker",
                server_definition_id="server-worker",
                broker_operation_id="operation-purge-worker-old",
                immutable_fingerprint="sha256:" + "a" * 64,
            )
        with self.store.read_transaction() as connection:
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM broker_server_materialization_revocations WHERE repo_id = ? AND server_definition_id = 'server-worker'",
                    (REPO_ID,),
                ).fetchone()
            )
        self.links.begin_lease_release(
            reserved.link_id, "operation-release-worker-old"
        )
        self.links.complete_lease_release(reserved.link_id)

        revoked = self.links.revoke_server_materialization(
            profile=self.profile,
            repository=self.repository,
            server_name="worker",
            server_definition_id="server-worker",
            broker_operation_id="operation-purge-worker-old",
            immutable_fingerprint="sha256:" + "a" * 64,
        )
        self.assertTrue(revoked["active_projection_deleted"], revoked)
        self.assertFalse(revoked["already_revoked"], revoked)
        repeated = self.links.revoke_server_materialization(
            profile=self.profile,
            repository=self.repository,
            server_name="worker",
            server_definition_id="server-worker",
            broker_operation_id="operation-purge-worker-old",
            immutable_fingerprint="sha256:" + "a" * 64,
        )
        self.assertTrue(repeated["already_revoked"], repeated)

        with self.assertRaisesRegex(RuntimeError, "permanently removed"):
            self.links.reserve_lease(
                profile=self.profile,
                repository=self.repository,
                server_name="worker",
                server_definition_id="server-worker",
                broker_lease_id="broker-lease-worker-stale-profile",
                port=43100,
                protocol="tcp",
                operation_id="operation-stale-worker",
                expires_at=None,
            )
        with self.store.read_transaction() as connection:
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM server_definitions WHERE server_definition_id = 'server-worker'"
                ).fetchone()
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM broker_lease_links WHERE broker_lease_id = 'broker-lease-worker-stale-profile'"
                ).fetchone()
            )
        removal_inventory = self.store.inventory_v2()
        projected_after_removal = {
            str(row["server_definition_id"])
            for row in removal_inventory["resources"]["servers"]
        }
        self.assertNotIn("server-worker", projected_after_removal)
        self.assertTrue(
            all(
                "server-worker" not in set(scope.get("server_ids") or [])
                for tree in removal_inventory["repository_trees"]
                for scope in tree["scopes"]
            ),
            removal_inventory["repository_trees"],
        )

        replacement_repository = BrokerRepositoryProfile(
            canonical_root=self.repository.canonical_root,
            repo_id=self.repository.repo_id,
            generation=self.repository.generation,
            server_ids={**self.repository.server_ids, "worker": "server-worker-v2"},
            container_ids=self.repository.container_ids,
            compose_definition_id=self.repository.compose_definition_id,
            compose_container_ids=self.repository.compose_container_ids,
            compose_run_once_services=self.repository.compose_run_once_services,
            ephemeral_templates=self.repository.ephemeral_templates,
            ephemeral_secret_policies=self.repository.ephemeral_secret_policies,
        )
        replacement_profile = BrokerClientProfile(
            service=self.profile.service,
            repositories={
                replacement_repository.canonical_root: replacement_repository
            },
        )
        replacement = self.links.reserve_lease(
            profile=replacement_profile,
            repository=replacement_repository,
            server_name="worker",
            server_definition_id="server-worker-v2",
            broker_lease_id="broker-lease-worker-v2",
            port=43100,
            protocol="tcp",
            operation_id="operation-worker-v2",
            expires_at=None,
        )
        self.assertEqual(replacement.server_definition_id, "server-worker-v2")
        with self.store.read_transaction() as connection:
            visible = {
                str(row[0])
                for row in connection.execute(
                    "SELECT server_definition_id FROM server_definitions"
                )
            }
            retained = connection.execute(
                """
                SELECT broker_operation_id
                FROM broker_server_materialization_revocations
                WHERE repo_id = ? AND server_definition_id = 'server-worker'
                """,
                (REPO_ID,),
            ).fetchone()
        self.assertNotIn("server-worker", visible)
        self.assertIn("server-worker-v2", visible)
        projected_after_reinstall = {
            str(row["server_definition_id"])
            for row in self.store.inventory_v2()["resources"]["servers"]
        }
        self.assertNotIn("server-worker", projected_after_reinstall)
        self.assertEqual(
            str(retained["broker_operation_id"]), "operation-purge-worker-old"
        )


if __name__ == "__main__":
    unittest.main()
