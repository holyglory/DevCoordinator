from __future__ import annotations

import argparse
import contextlib
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

import dev_coordinator
from devcoordinator import broker_enrollment, broker_profile as broker_profile_module
from devcoordinator.broker import (
    AuthorizedBrokerRequest,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    PeerCredentials,
)
from devcoordinator.broker_persistence import _operation_actor
from devcoordinator.broker_profile import (
    BrokerClientProfile,
    BrokerProfileError,
    BrokerRepositoryProfile,
    BrokerServiceProfile,
    profile_from_document,
)
from devcoordinator.store import deterministic_id


_IMAGE = "postgres@sha256:" + "a" * 64
_QUOTAS = {
    "max_concurrent_runs": 4,
    "max_concurrent_runs_per_uid": 2,
    "repo_max_active_runs": 16,
    "repo_memory_budget_bytes": 8 * 1024 * 1024 * 1024,
    "repo_cpu_budget_millis": 16_000,
}


def _profile_document(root: str, *, ephemeral: bool) -> dict[str, object]:
    repository: dict[str, object] = {
        "canonical_root": root,
        "repo_id": "repo-alpha",
        "generation": 1,
        "servers": {},
        "containers": {},
        "compose_definition_id": None,
    }
    if ephemeral:
        repository.update(
            {
                "account_id": "account-alpha",
                "enabled": True,
                "issued_at": "2026-07-23T00:00:00Z",
                "valid_until_epoch": int(time.time()) + 3600,
                "ephemeral_templates": {"artifact-db": "template-opaque"},
            }
        )
    return {
        "version": 1,
        "service": {
            "socket": "/run/devcoordinator/broker.sock",
            "uid": 0,
            "gid": 100,
            "mode": "0660",
            "database_generation": "generation-alpha",
        },
        "clients": {
            "501": {
                "account_id": "account-alpha",
                "issued_at": "2026-07-23T00:00:00Z",
                "valid_until_epoch": int(time.time()) + 3600,
                "repositories": [repository],
            }
        },
    }


def _repository(
    root: str, *, repo_id: str = "repo-alpha"
) -> BrokerRepositoryProfile:
    return BrokerRepositoryProfile(
        canonical_root=root,
        repo_id=repo_id,
        generation=1,
        server_ids={},
        container_ids={},
        compose_definition_id=None,
        ephemeral_templates={"artifact-db": f"template-{repo_id}"},
        account_id="account-alpha",
        valid_until_epoch=int(time.time()) + 3600,
    )


class _FakeProfile:
    def __init__(self, repositories: tuple[BrokerRepositoryProfile, ...]) -> None:
        self.account_id = "account-alpha"
        self.repositories = {item.canonical_root: item for item in repositories}
        self.calls: list[dict[str, object]] = []

    def repository(self, canonical_root: str) -> BrokerRepositoryProfile:
        canonical = str(Path(canonical_root).resolve())
        repository = self.repositories.get(canonical)
        if repository is None:
            raise BrokerProfileError(f"repository {canonical} is not enrolled")
        repository.require_current(account_id=self.account_id)
        return repository

    def retained_ephemeral_repository(
        self, canonical_root: str
    ) -> BrokerRepositoryProfile:
        canonical = str(Path(canonical_root).resolve())
        repository = self.repositories.get(canonical)
        if repository is None:
            raise BrokerProfileError(f"repository {canonical} is not recorded")
        repository.require_account(account_id=self.account_id)
        return repository

    def call(self, **kwargs: object) -> tuple[str, dict[str, object]]:
        self.calls.append(dict(kwargs))
        return "operation-alpha", {"status": "ok"}


class EphemeralProfileTests(unittest.TestCase):
    def test_old_profile_remains_valid_and_new_profile_maps_only_opaque_ids(self) -> None:
        old = profile_from_document(
            _profile_document("/srv/old", ephemeral=False), effective_uid=501
        )
        self.assertEqual(old.repository("/srv/old").ephemeral_templates, {})

        new = profile_from_document(
            _profile_document("/srv/new", ephemeral=True), effective_uid=501
        )
        repository = new.repository("/srv/new")
        self.assertEqual(
            repository.ephemeral_template_id("artifact-db"), "template-opaque"
        )
        with self.assertRaises(BrokerProfileError):
            repository.ephemeral_template_id("missing")

    def test_profile_prefetch_opt_in_is_unique_and_subset_bound(self) -> None:
        document = _profile_document("/srv/new", ephemeral=True)
        repository = document["clients"]["501"]["repositories"][0]  # type: ignore[index]
        repository["ephemeral_image_prefetch_templates"] = ["template-opaque"]
        profile = profile_from_document(document, effective_uid=501)
        self.assertEqual(
            profile.repository("/srv/new").ephemeral_image_prefetch_template_id(
                "artifact-db"
            ),
            "template-opaque",
        )
        for invalid in (["template-opaque", "template-opaque"], ["other"]):
            with self.subTest(invalid=invalid):
                document = _profile_document("/srv/new", ephemeral=True)
                repository = document["clients"]["501"]["repositories"][0]  # type: ignore[index]
                repository["ephemeral_image_prefetch_templates"] = invalid
                with self.assertRaises(BrokerProfileError):
                    profile_from_document(document, effective_uid=501)

    def test_expired_profile_is_usable_only_for_retained_owner_cleanup(self) -> None:
        document = _profile_document("/srv/expired", ephemeral=True)
        client = document["clients"]["501"]  # type: ignore[index]
        client["valid_until_epoch"] = int(time.time()) - 1  # type: ignore[index]
        repository = client["repositories"][0]  # type: ignore[index]
        repository["enabled"] = False
        repository["valid_until_epoch"] = int(time.time()) - 1

        with self.assertRaisesRegex(BrokerProfileError, "expired"):
            profile_from_document(document, effective_uid=501)
        profile = profile_from_document(
            document,
            effective_uid=501,
            allow_expired_for_ephemeral_cleanup=True,
        )
        retained = profile.retained_ephemeral_repository("/srv/expired")
        with self.assertRaisesRegex(BrokerProfileError, "expired"):
            profile.repository("/srv/expired")
        with self.assertRaisesRegex(BrokerProfileError, "cannot discover"):
            profile.retained_ephemeral_repository("/srv/not-enrolled")

        with mock.patch.object(
            broker_profile_module,
            "call_broker",
            return_value=("operation-retained", {"status": "running"}),
        ) as call:
            operation_id, result = profile.call(
                repository=retained,
                resource_id="run-exact",
                operation=BrokerOperation.EPHEMERAL_STATUS,
                arguments={},
            )
        self.assertEqual(operation_id, "operation-retained")
        self.assertEqual(result, {"status": "running"})
        self.assertEqual(call.call_args.kwargs["repo_id"], "repo-alpha")
        self.assertEqual(call.call_args.kwargs["resource_id"], "run-exact")
        with self.assertRaisesRegex(BrokerProfileError, "expired"):
            profile.call(
                repository=retained,
                resource_id="template-opaque",
                operation=BrokerOperation.EPHEMERAL_START,
                arguments={"agent": "codex-a"},
            )


class EphemeralManifestTests(unittest.TestCase):
    def _specification(self, document: dict[str, object]) -> dict[str, object]:
        with tempfile.TemporaryDirectory(prefix="ephemeral-manifest-", dir="/tmp") as raw:
            root = Path(raw)
            (root / ".git").mkdir()
            runtime = root / ".codex"
            runtime.mkdir()
            (runtime / "dev-runtime.json").write_text(
                json.dumps(document), encoding="utf-8"
            )
            return dev_coordinator.build_project_runtime_spec(
                {"servers": {}}, project=str(root), include_docker=False
            )

    def test_manifest_accepts_one_fully_sealed_template(self) -> None:
        specification = self._specification(
            {
                "ephemeral_containers": [
                    {
                        "name": "artifact-db",
                        "image_ref": _IMAGE,
                        "argv": ["postgres", "-c", "fsync=off"],
                        "env": {"POSTGRES_DB": "artifact"},
                        "default_ttl_seconds": 900,
                        "max_ttl_seconds": 3600,
                        "container_tcp_port": 5432,
                        "host_port_start": 55000,
                        "host_port_end": 55010,
                        "memory_bytes": 256 * 1024 * 1024,
                        "cpu_millis": 500,
                        **_QUOTAS,
                    }
                ]
            }
        )
        template = specification["ephemeral_containers"][0]  # type: ignore[index]
        self.assertEqual(template["image_ref"], _IMAGE)
        self.assertEqual(template["argv"], ["postgres", "-c", "fsync=off"])
        self.assertEqual(template["max_concurrent_runs_per_uid"], 2)
        self.assertEqual(template["repo_cpu_budget_millis"], 16_000)

    def test_manifest_rejects_mutable_image_partial_ports_and_docker_options(self) -> None:
        base = {
            "name": "artifact-db",
            "image_ref": _IMAGE,
            "default_ttl_seconds": 900,
            "max_ttl_seconds": 3600,
            "memory_bytes": 256 * 1024 * 1024,
            "cpu_millis": 500,
            **_QUOTAS,
        }
        invalid = (
            {**base, "image_ref": "postgres:17"},
            {**base, "image_ref": "--privileged@sha256:" + "a" * 64},
            {**base, "container_tcp_port": 5432},
            {**base, "env": {"SECRET": "line-one\nline-two"}},
            {**base, "env": {"POSTGRES_PASSWORD": "would-be-plaintext"}},
            {**base, "privileged": True},
        )
        for template in invalid:
            with self.subTest(template=template):
                with self.assertRaises(ValueError):
                    self._specification({"ephemeral_containers": [template]})

    def test_manifest_requires_consistent_repository_wide_budgets(self) -> None:
        first = {
            "name": "artifact-db",
            "image_ref": _IMAGE,
            "default_ttl_seconds": 900,
            "max_ttl_seconds": 3600,
            "memory_bytes": 256 * 1024 * 1024,
            "cpu_millis": 500,
            **_QUOTAS,
        }
        second = {
            **first,
            "name": "artifact-db-second",
            "repo_memory_budget_bytes": _QUOTAS["repo_memory_budget_bytes"] * 2,
        }
        with self.assertRaisesRegex(ValueError, "same repo_max_active_runs"):
            self._specification({"ephemeral_containers": [first, second]})

    def test_provision_replaces_templates_and_exact_uid_access(self) -> None:
        templates = broker_enrollment._normalize_ephemeral_templates(
            [
                {
                    "name": "artifact-db",
                    "image_ref": _IMAGE,
                    "default_ttl_seconds": 900,
                    "max_ttl_seconds": 3600,
                    "memory_bytes": 256 * 1024 * 1024,
                    "cpu_millis": 500,
                    **_QUOTAS,
                }
            ]
        )
        persistence = mock.Mock()
        template_id = deterministic_id(
            "ephemeral-template", "repo-alpha", "artifact-db"
        )
        persistence.provision_ephemeral_template.return_value = {
            "template_id": template_id
        }
        result = broker_enrollment._provision_ephemeral_templates(
            persistence,
            repo_id="repo-alpha",
            client_uid=501,
            templates=templates,
        )
        self.assertEqual(result, {"artifact-db": template_id})
        provisioned = persistence.provision_ephemeral_template.call_args.kwargs
        self.assertEqual(provisioned["image_ref"], _IMAGE)
        self.assertEqual(provisioned["enabled"], True)
        self.assertEqual(provisioned["max_concurrent_runs"], 4)
        self.assertEqual(provisioned["repo_memory_budget_bytes"], 8 * 1024**3)
        self.assertEqual(
            tuple(
                persistence.disable_ephemeral_templates_except.call_args.kwargs[
                    "template_ids"
                ]
            ),
            (template_id,),
        )
        self.assertEqual(
            tuple(
                persistence.replace_ephemeral_access.call_args.kwargs["template_ids"]
            ),
            (template_id,),
        )
        self.assertEqual(
            tuple(
                persistence.replace_ephemeral_access.call_args.kwargs[
                    "prefetch_template_ids"
                ]
            ),
            (),
        )

        omitted = mock.Mock()
        self.assertEqual(
            broker_enrollment._provision_ephemeral_templates(
                omitted,
                repo_id="repo-alpha",
                client_uid=501,
                templates=(),
            ),
            {},
        )
        omitted.provision_ephemeral_template.assert_not_called()
        self.assertEqual(
            tuple(
                omitted.disable_ephemeral_templates_except.call_args.kwargs[
                    "template_ids"
                ]
            ),
            (),
        )
        self.assertEqual(
            tuple(omitted.replace_ephemeral_access.call_args.kwargs["template_ids"]),
            (),
        )
        self.assertEqual(
            tuple(
                omitted.replace_ephemeral_access.call_args.kwargs[
                    "prefetch_template_ids"
                ]
            ),
            (),
        )

    def test_broker_enroll_forwards_manifest_templates(self) -> None:
        template = {
            "name": "artifact-db",
            "image_ref": _IMAGE,
            "argv": [],
            "env": {},
            "default_ttl_seconds": 900,
            "max_ttl_seconds": 3600,
            "container_tcp_port": None,
            "host_port_start": None,
            "host_port_end": None,
            "memory_bytes": 256 * 1024 * 1024,
            "cpu_millis": 500,
            **_QUOTAS,
        }
        args = argparse.Namespace(
            project="/srv/repository",
            port_range="41000-41010",
            profile_output="/etc/devcoordinator/client-profiles.json",
            runtime_file=None,
            access_group=None,
            access_gid=100,
            all_servers=True,
            server=[],
            database="/var/lib/devcoordinator/coordinator.sqlite3",
            socket="/run/devcoordinator/broker.sock",
            client_uid=501,
            account_id="account-alpha",
            approve_compose_host_access=False,
            explicit_reinstall=False,
            grant_cleanup=False,
            profile_valid_days=30,
            agent="root",
        )
        with (
            mock.patch.object(
                dev_coordinator,
                "build_project_runtime_spec",
                return_value={
                    "servers": [],
                    "compose": None,
                    "ephemeral_containers": [template],
                },
            ),
            mock.patch.object(
                dev_coordinator,
                "exclusive_broker_service_lock",
                return_value=contextlib.nullcontext(),
            ),
            mock.patch.object(
                dev_coordinator,
                "enroll_repository",
                return_value={"status": "enrolled"},
            ) as enroll,
        ):
            dev_coordinator.coordinated_broker_enroll(args)
        self.assertEqual(
            enroll.call_args.kwargs["ephemeral_containers"], (template,)
        )

    def test_broker_enroll_forwards_explicit_image_prefetch_grant(self) -> None:
        args = argparse.Namespace(
            project="/srv/repository",
            port_range="41000-41010",
            profile_output="/etc/devcoordinator/client-profiles.json",
            runtime_file=None,
            access_group=None,
            access_gid=100,
            all_servers=True,
            server=[],
            database="/var/lib/devcoordinator/coordinator.sqlite3",
            socket="/run/devcoordinator/broker.sock",
            client_uid=501,
            account_id="account-alpha",
            approve_compose_host_access=False,
            explicit_reinstall=False,
            grant_cleanup=False,
            grant_ephemeral_image_prefetch=True,
            profile_valid_days=30,
            agent="root",
        )
        with (
            mock.patch.object(
                dev_coordinator,
                "build_project_runtime_spec",
                return_value={"servers": [], "compose": None, "ephemeral_containers": []},
            ),
            mock.patch.object(
                dev_coordinator,
                "exclusive_broker_service_lock",
                return_value=contextlib.nullcontext(),
            ),
            mock.patch.object(
                dev_coordinator,
                "enroll_repository",
                return_value={"status": "enrolled"},
            ) as enroll,
        ):
            dev_coordinator.coordinated_broker_enroll(args)
        self.assertTrue(enroll.call_args.kwargs["grant_ephemeral_image_prefetch"])


class EphemeralCliTests(unittest.TestCase):
    def test_image_prefetch_requires_profile_opt_in_and_never_accepts_an_image(self) -> None:
        operation_id = "33333333-3333-4333-8333-333333333333"
        command = [
            "ephemeral",
            "image-prefetch",
            "--agent",
            "codex-a",
            "--project",
            "/srv/repository",
            "--template",
            "artifact-db",
            "--operation-id",
            operation_id,
        ]
        denied = _repository("/srv/repository")
        profile = _FakeProfile((denied,))
        args = dev_coordinator.build_parser().parse_args(command)
        with (
            mock.patch.object(
                dev_coordinator, "configured_broker_profile", return_value=profile
            ),
            self.assertRaisesRegex(BrokerProfileError, "not explicitly enrolled"),
        ):
            dev_coordinator.coordinated_ephemeral_action(args)

        allowed = BrokerRepositoryProfile(
            **{
                **denied.__dict__,
                "ephemeral_image_prefetch_template_ids": frozenset(
                    {"template-repo-alpha"}
                ),
            }
        )
        profile = _FakeProfile((allowed,))
        with mock.patch.object(
            dev_coordinator, "configured_broker_profile", return_value=profile
        ):
            dev_coordinator.coordinated_ephemeral_action(args)
        self.assertEqual(
            profile.calls[0]["operation"], BrokerOperation.EPHEMERAL_IMAGE_PREFETCH
        )
        self.assertEqual(profile.calls[0]["resource_id"], "template-repo-alpha")
        self.assertEqual(profile.calls[0]["arguments"], {"agent": "codex-a"})
        self.assertEqual(profile.calls[0]["operation_id"], operation_id)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            dev_coordinator.build_parser().parse_args(command + ["--image", _IMAGE])

    def test_start_uses_only_profile_template_id_and_typed_ttl(self) -> None:
        repository = _repository("/srv/repository")
        profile = _FakeProfile((repository,))
        operation_id = "11111111-1111-4111-8111-111111111111"
        args = dev_coordinator.build_parser().parse_args(
            [
                "ephemeral",
                "start",
                "--agent",
                "codex-a",
                "--project",
                "/srv/repository",
                "--template",
                "artifact-db",
                "--ttl-seconds",
                "900",
                "--operation-id",
                operation_id,
            ]
        )
        with mock.patch.object(
            dev_coordinator, "configured_broker_profile", return_value=profile
        ):
            result = dev_coordinator.handle_cli(args)
        call = profile.calls[0]
        self.assertEqual(call["resource_id"], "template-repo-alpha")
        self.assertEqual(call["operation"], BrokerOperation.EPHEMERAL_START)
        self.assertEqual(
            call["arguments"], {"ttl_seconds": 900, "agent": "codex-a"}
        )
        self.assertEqual(call["operation_id"], operation_id)
        self.assertEqual(result["operation_id"], "operation-alpha")
        self.assertEqual(result["agent"], "codex-a")

    def test_mutation_retry_operation_id_is_canonical_and_forwarded(self) -> None:
        repository = _repository("/srv/repository")
        operation_ids = (
            "aaaaaaaa-1111-4111-8111-111111111111",
            "31111111-1111-4111-8111-111111111111",
        )
        commands = (
            [
                "ephemeral",
                "renew",
                "--agent",
                "codex-a",
                "--project",
                "/srv/repository",
                "--run-id",
                "run-exact",
                "--ttl-seconds",
                "900",
                "--operation-id",
                operation_ids[0],
            ],
            [
                "ephemeral",
                "finish",
                "--agent",
                "codex-a",
                "--project",
                "/srv/repository",
                "--run-id",
                "run-exact",
                "--reason",
                "finished",
                "--operation-id",
                operation_ids[1],
            ],
        )
        for command, expected in zip(commands, operation_ids):
            with self.subTest(command=command):
                profile = _FakeProfile((repository,))
                args = dev_coordinator.build_parser().parse_args(command)
                with mock.patch.object(
                    dev_coordinator,
                    "configured_broker_profile",
                    return_value=profile,
                ):
                    dev_coordinator.coordinated_ephemeral_action(args)
                self.assertEqual(profile.calls[0]["operation_id"], expected)

        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            dev_coordinator.build_parser().parse_args(
                [
                    "ephemeral",
                    "start",
                    "--agent",
                    "codex-a",
                    "--project",
                    "/srv/repository",
                    "--template",
                    "artifact-db",
                    "--operation-id",
                    operation_ids[0].upper(),
                ]
            )

    def test_renew_uses_only_the_explicit_repository_without_cross_repo_probe(self) -> None:
        first = _repository("/srv/first", repo_id="repo-first")
        second = _repository("/srv/second", repo_id="repo-second")
        profile = _FakeProfile((first, second))
        args = dev_coordinator.build_parser().parse_args(
            [
                "ephemeral",
                "renew",
                "--agent",
                "claude-b",
                "--project",
                "/srv/second",
                "--run-id",
                "run-opaque",
                "--ttl-seconds",
                "1800",
            ]
        )
        with mock.patch.object(
            dev_coordinator, "configured_broker_profile", return_value=profile
        ):
            result = dev_coordinator.coordinated_ephemeral_action(args)
        self.assertEqual(len(profile.calls), 1)
        self.assertIs(profile.calls[0]["repository"], second)
        self.assertEqual(
            profile.calls[0]["operation"], BrokerOperation.EPHEMERAL_RENEW
        )
        self.assertEqual(profile.calls[0]["resource_id"], "run-opaque")
        self.assertEqual(
            profile.calls[0]["arguments"],
            {"ttl_seconds": 1800, "agent": "claude-b"},
        )
        self.assertEqual(result["agent"], "claude-b")

    def test_status_is_read_only_and_scoped_to_one_explicit_repository(self) -> None:
        first = _repository("/srv/first", repo_id="repo-first")
        second = _repository("/srv/second", repo_id="repo-second")
        profile = _FakeProfile((first, second))
        args = dev_coordinator.build_parser().parse_args(
            [
                "ephemeral",
                "status",
                "--project",
                "/srv/second",
                "--run-id",
                "run-opaque",
            ]
        )
        with mock.patch.object(
            dev_coordinator, "configured_broker_profile", return_value=profile
        ) as configured:
            dev_coordinator.coordinated_ephemeral_action(args)
        configured.assert_called_once_with(
            allow_expired_for_ephemeral_cleanup=True
        )
        self.assertEqual(len(profile.calls), 1)
        self.assertIs(profile.calls[0]["repository"], second)
        self.assertEqual(
            profile.calls[0]["operation"], BrokerOperation.EPHEMERAL_STATUS
        )
        self.assertEqual(profile.calls[0]["arguments"], {})

    def test_finish_retains_exact_repo_access_but_renew_does_not(self) -> None:
        expired = BrokerRepositoryProfile(
            canonical_root="/srv/expired",
            repo_id="repo-expired",
            generation=1,
            server_ids={},
            container_ids={},
            compose_definition_id=None,
            ephemeral_templates={"artifact-db": "template-expired"},
            account_id="account-alpha",
            enabled=False,
            valid_until_epoch=int(time.time()) - 1,
        )
        profile = _FakeProfile((expired,))
        finish = dev_coordinator.build_parser().parse_args(
            [
                "ephemeral",
                "finish",
                "--agent",
                "codex-a",
                "--project",
                "/srv/expired",
                "--run-id",
                "run-exact",
            ]
        )
        with mock.patch.object(
            dev_coordinator, "configured_broker_profile", return_value=profile
        ) as configured:
            dev_coordinator.coordinated_ephemeral_action(finish)
        configured.assert_called_once_with(
            allow_expired_for_ephemeral_cleanup=True
        )
        self.assertEqual(profile.calls[0]["resource_id"], "run-exact")
        self.assertEqual(
            profile.calls[0]["operation"], BrokerOperation.EPHEMERAL_FINISH
        )

        renew = dev_coordinator.build_parser().parse_args(
            [
                "ephemeral",
                "renew",
                "--agent",
                "codex-a",
                "--project",
                "/srv/expired",
                "--run-id",
                "run-exact",
                "--ttl-seconds",
                "900",
            ]
        )
        with (
            mock.patch.object(
                dev_coordinator, "configured_broker_profile", return_value=profile
            ) as configured,
            self.assertRaisesRegex(BrokerProfileError, "disabled"),
        ):
            dev_coordinator.coordinated_ephemeral_action(renew)
        configured.assert_called_once_with(
            allow_expired_for_ephemeral_cleanup=False
        )
        self.assertEqual(len(profile.calls), 1)

    def test_mutations_require_agent_and_every_command_requires_project(self) -> None:
        parser = dev_coordinator.build_parser()
        invalid = (
            [
                "ephemeral",
                "start",
                "--project",
                "/srv/repository",
                "--template",
                "artifact-db",
            ],
            [
                "ephemeral",
                "start",
                "--agent",
                "codex",
                "--template",
                "artifact-db",
            ],
            ["ephemeral", "status", "--run-id", "run-opaque"],
            [
                "ephemeral",
                "renew",
                "--project",
                "/srv/repository",
                "--run-id",
                "run-opaque",
                "--ttl-seconds",
                "900",
            ],
            [
                "ephemeral",
                "finish",
                "--agent",
                "codex",
                "--run-id",
                "run-opaque",
            ],
        )
        for argv in invalid:
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    parser.parse_args(argv)

    def test_client_agent_is_normalized_into_durable_operation_actor(self) -> None:
        request = BrokerRequest.create(
            account_id="account-alpha",
            project_id="repo-alpha",
            resource_id="template-alpha",
            operation=BrokerOperation.EPHEMERAL_START,
            arguments={"agent": "codex-a"},
        )
        authorized = AuthorizedBrokerRequest(
            peer=PeerCredentials(uid=501, gid=100, pid=1234), request=request
        )
        self.assertEqual(
            _operation_actor(authorized),
            "broker:account-alpha:client-agent:codex-a",
        )
        with self.assertRaisesRegex(BrokerError, "bounded non-empty printable"):
            BrokerRequest.create(
                account_id="account-alpha",
                project_id="repo-alpha",
                resource_id="template-alpha",
                operation=BrokerOperation.EPHEMERAL_START,
                arguments={"agent": "codex-a\nforged-audit-line"},
            )

    def test_ephemeral_cli_fails_closed_without_broker_profile(self) -> None:
        args = dev_coordinator.build_parser().parse_args(
            [
                "ephemeral",
                "finish",
                "--agent",
                "codex-a",
                "--project",
                "/srv/repository",
                "--run-id",
                "run-opaque",
            ]
        )
        with (
            mock.patch.object(
                dev_coordinator, "configured_broker_profile", return_value=None
            ),
            self.assertRaisesRegex(
                BrokerProfileError, "direct Docker fallback is disabled"
            ),
        ):
            dev_coordinator.coordinated_ephemeral_action(args)


if __name__ == "__main__":
    unittest.main()
