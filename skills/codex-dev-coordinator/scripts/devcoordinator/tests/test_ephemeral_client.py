from __future__ import annotations

import argparse
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import dev_coordinator
from devcoordinator import broker_configuration
from devcoordinator.broker import (
    AcceptedBrokerRequest,
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
        "compose_container_ids": [],
        "compose_run_once_services": {},
        "ephemeral_templates": (
            {"artifact-db": "template-opaque"} if ephemeral else {}
        ),
        "ephemeral_secret_policies": {},
    }
    return {
        "version": 2,
        "service": {
            "socket": "/run/devcoordinator-authority.sock",
            "database_generation": "generation-alpha",
        },
        "repositories": [repository],
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
        compose_container_ids=frozenset(),
        compose_run_once_services={},
        ephemeral_templates={"artifact-db": f"template-{repo_id}"},
        ephemeral_secret_policies={},
    )


class _FakeProfile:
    def __init__(self, repositories: tuple[BrokerRepositoryProfile, ...]) -> None:
        self.repositories = {item.canonical_root: item for item in repositories}
        self.calls: list[dict[str, object]] = []

    def repository(self, canonical_root: str) -> BrokerRepositoryProfile:
        canonical = str(Path(canonical_root).resolve())
        repository = self.repositories.get(canonical)
        if repository is None:
            raise BrokerProfileError(f"repository {canonical} is not configured")
        return repository

    def call(self, **kwargs: object) -> tuple[str, dict[str, object]]:
        self.calls.append(dict(kwargs))
        return "operation-alpha", {"status": "ok"}


class EphemeralProfileTests(unittest.TestCase):
    def test_repository_profile_requires_the_exact_current_contract(self) -> None:
        repository_fields = set(
            _profile_document("/srv/current", ephemeral=True)["repositories"][0]  # type: ignore[index]
        )
        for missing in sorted(repository_fields):
            with self.subTest(missing=missing):
                document = _profile_document("/srv/current", ephemeral=True)
                repository = document["repositories"][0]  # type: ignore[index]
                del repository[missing]
                with self.assertRaises(BrokerProfileError):
                    profile_from_document(document, effective_uid=501)

        document = _profile_document("/srv/current", ephemeral=True)
        repository = document["repositories"][0]  # type: ignore[index]
        repository["legacy_extension"] = True
        with self.assertRaises(BrokerProfileError):
            profile_from_document(document, effective_uid=501)

    def test_profile_with_empty_ephemeral_templates_and_with_opaque_ids(self) -> None:
        without_ephemeral = profile_from_document(
            _profile_document("/srv/plain", ephemeral=False), effective_uid=501
        )
        self.assertEqual(
            without_ephemeral.repository("/srv/plain").ephemeral_templates, {}
        )

        with_ephemeral = profile_from_document(
            _profile_document("/srv/ephemeral", ephemeral=True), effective_uid=501
        )
        repository = with_ephemeral.repository("/srv/ephemeral")
        self.assertEqual(
            repository.ephemeral_template_id("artifact-db"), "template-opaque"
        )
        with self.assertRaises(BrokerProfileError):
            repository.ephemeral_template_id("missing")

    def test_profile_prefetch_uses_the_declared_template_identity(self) -> None:
        profile = profile_from_document(
            _profile_document("/srv/new", ephemeral=True), effective_uid=501
        )
        self.assertEqual(
            profile.repository("/srv/new").ephemeral_image_prefetch_template_id(
                "artifact-db"
            ),
            "template-opaque",
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
            database="/var/lib/devcoordinator/coordinator.sqlite3",
            socket="/run/devcoordinator-authority.sock",
            execution_uid=1000,
            approve_compose_host_access=False,
            explicit_reinstall=False,
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
                "configure_repository",
                return_value={"status": "configured"},
            ) as enroll,
        ):
            dev_coordinator.coordinated_broker_configure(args)
        self.assertEqual(
            enroll.call_args.kwargs["ephemeral_containers"], (template,)
        )

class EphemeralCliTests(unittest.TestCase):
    def test_image_prefetch_uses_declared_template_and_never_accepts_an_image(self) -> None:
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
        repository = _repository("/srv/repository")
        profile = _FakeProfile((repository,))
        args = dev_coordinator.build_parser().parse_args(command)
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
        configured.assert_called_once_with()
        self.assertEqual(len(profile.calls), 1)
        self.assertIs(profile.calls[0]["repository"], second)
        self.assertEqual(
            profile.calls[0]["operation"], BrokerOperation.EPHEMERAL_STATUS
        )
        self.assertEqual(profile.calls[0]["arguments"], {})

    def test_finish_and_renew_use_the_same_catalog_route(self) -> None:
        repository = BrokerRepositoryProfile(
            canonical_root="/srv/repository",
            repo_id="repo-test",
            generation=1,
            server_ids={},
            container_ids={},
            compose_definition_id=None,
            compose_container_ids=frozenset(),
            compose_run_once_services={},
            ephemeral_templates={"artifact-db": "template-test"},
            ephemeral_secret_policies={},
        )
        profile = _FakeProfile((repository,))
        finish = dev_coordinator.build_parser().parse_args(
            [
                "ephemeral",
                "finish",
                "--agent",
                "codex-a",
                "--project",
                "/srv/repository",
                "--run-id",
                "run-exact",
            ]
        )
        with mock.patch.object(
            dev_coordinator, "configured_broker_profile", return_value=profile
        ) as configured:
            dev_coordinator.coordinated_ephemeral_action(finish)
        configured.assert_called_once_with()
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
                "/srv/repository",
                "--run-id",
                "run-exact",
                "--ttl-seconds",
                "900",
            ]
        )
        with mock.patch.object(
            dev_coordinator, "configured_broker_profile", return_value=profile
        ) as configured:
            dev_coordinator.coordinated_ephemeral_action(renew)
        configured.assert_called_once_with()
        self.assertEqual(len(profile.calls), 2)
        self.assertEqual(profile.calls[1]["resource_id"], "run-exact")
        self.assertEqual(
            profile.calls[1]["operation"], BrokerOperation.EPHEMERAL_RENEW
        )

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
        authorized = AcceptedBrokerRequest(
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
