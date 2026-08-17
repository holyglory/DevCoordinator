from __future__ import annotations

import io
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest import mock

from devcoordinator import agent_cli
from devcoordinator.broker import BrokerError
from devcoordinator.broker_profile import BrokerProfileError
from devcoordinator.call_journal import RollingCallJournal, read_call_records


class _Scope:
    def __init__(self, root: str) -> None:
        self.canonical_root = root
        self.root_owner_uid = 1000


class _Context:
    root = _Scope("/repo")
    effective = _Scope("/repo")
    temporary = None
    project_kind = "primary"


class AgentCliTests(unittest.TestCase):
    def test_enqueue_emits_prompt_replay_safe_progress_before_execution(self) -> None:
        stdout = mock.Mock()
        stdout.buffer = io.BytesIO()
        stdout.flush = mock.Mock()
        stderr = mock.Mock()
        stderr.buffer = io.BytesIO()
        stderr.flush = mock.Mock()
        operation_id = "00000000-0000-4000-8000-000000000001"
        with (
            mock.patch.object(agent_cli.sys, "stdout", stdout),
            mock.patch.object(agent_cli.sys, "stderr", stderr),
            mock.patch(
                "devcoordinator.call_journal.configured_call_journal",
                return_value=None,
            ),
            mock.patch.object(
                agent_cli,
                "_execute",
                return_value={"schema_version": 1, "ok": True},
            ) as execute,
        ):
            returncode = agent_cli.main(
                [
                    "test",
                    "enqueue",
                    "--intent",
                    "manual",
                    "--target",
                    "web-verify",
                    "--operation-id",
                    operation_id,
                ]
            )

        self.assertEqual(returncode, 0)
        execute.assert_called_once()
        progress = json.loads(stderr.buffer.getvalue())
        self.assertEqual(progress["classification"], "test_enqueue_started")
        self.assertEqual(progress["status"], "snapshot_planning")
        self.assertEqual(progress["operation_id"], operation_id)
        self.assertIn(operation_id, progress["replay_command"])
        self.assertIn("queue-status", progress["queue_status_command"])

    def test_repository_context_uses_authority_published_immutable_route(self) -> None:
        namespace = mock.Mock(project="/snapshots/snapshot-a/root/subdirectory")
        binding = mock.Mock(original_root="/source/repository")
        context = _Context()
        context.root = _Scope("/source/repository")
        context.effective = context.root

        with (
            mock.patch(
                "devcoordinator.universal_test_repository_binding."
                "resolve_immutable_repository_binding",
                return_value=binding,
            ) as resolve_binding,
            mock.patch(
                "devcoordinator.universal_test_repository_binding."
                "immutable_repository_route_context",
                return_value=context,
            ) as route_context,
            mock.patch(
                "devcoordinator.repository_context.resolve_effective_repository_context"
            ) as git_context,
        ):
            resolved = agent_cli._repository_context(namespace)

        self.assertIs(resolved, context)
        self.assertEqual(namespace._resolved_project, "/source/repository")
        resolve_binding.assert_called_once_with(
            "/snapshots/snapshot-a/root/subdirectory"
        )
        route_context.assert_called_once_with(binding)
        git_context.assert_not_called()

    @staticmethod
    def _main_failure(argv: list[str]) -> dict[str, object]:
        stream = mock.Mock()
        stream.buffer = io.BytesIO()
        stream.flush = mock.Mock()
        with (
            mock.patch.object(agent_cli.sys, "stdout", stream),
            mock.patch(
                "devcoordinator.call_journal.configured_call_journal",
                return_value=None,
            ),
            mock.patch.object(agent_cli, "_execute") as execute,
        ):
            returncode = agent_cli.main(argv)
        if returncode != 1:
            raise AssertionError(f"expected failure, received exit {returncode}")
        execute.assert_not_called()
        return json.loads(stream.buffer.getvalue())

    def test_help_does_not_load_profile_or_broker(self) -> None:
        with mock.patch.object(agent_cli, "_execute") as execute:
            with self.assertRaises(SystemExit) as raised:
                agent_cli.main(["--help"])
        self.assertEqual(raised.exception.code, 0)
        execute.assert_not_called()

    def test_explicit_mutation_operation_id_is_preserved(self) -> None:
        value = "00000000-0000-4000-8000-000000000001"
        self.assertEqual(
            agent_cli._canonical_operation_id(value, mutate=True), value
        )

    def test_read_does_not_invent_replay_identity(self) -> None:
        self.assertIsNone(agent_cli._canonical_operation_id(None, mutate=False))

    def test_every_command_accepts_only_its_scoped_project_option(self) -> None:
        cases = (
            ["capabilities", "--project", "/repo"],
            ["targets", "--project", "/repo"],
            ["storage", "inventory", "--project", "/repo"],
            ["ephemeral", "image-status", "postgres", "--project", "/repo"],
            ["runtime", "status", "service-1", "--project", "/repo"],
            [
                "runtime",
                "ensure",
                "service-1",
                "--desired",
                "ready",
                "--project",
                "/repo",
            ],
            [
                "operation",
                "follow",
                "dc1:operation:00000000-0000-4000-8000-000000000001",
                "--project",
                "/repo",
            ],
            ["test", "enqueue", "--project", "/repo"],
            ["test", "submit", "plan-1", "--project", "/repo"],
            ["test", "follow", "run-1", "--project", "/repo"],
            ["test", "failures", "run-1", "--project", "/repo"],
            ["test", "artifact", "run-1", "artifact-1", "--project", "/repo"],
            ["test", "status", "run-1", "--project", "/repo"],
            ["test", "summary", "run-1", "--project", "/repo"],
            ["test", "wait", "run-1", "--timeout-seconds", "1", "--project", "/repo"],
        )
        for argv in cases:
            with self.subTest(argv=argv):
                self.assertEqual(agent_cli._parser().parse_args(argv).project, "/repo")

    def test_explicit_project_is_resolved_independently_of_process_cwd(self) -> None:
        namespace = agent_cli._parser().parse_args(
            ["capabilities", "--project", "/canonical/repo"]
        )
        with (
            mock.patch.object(agent_cli.os, "getcwd", return_value="/unrelated/cwd"),
            mock.patch(
                "devcoordinator.universal_test_repository_binding."
                "repository_route_context",
                return_value=_Context(),
            ) as resolve,
        ):
            context = agent_cli._repository_context(namespace)

        self.assertIs(context, resolve.return_value)
        resolve.assert_called_once_with("/canonical/repo")

    def test_retired_global_context_and_attribution_inputs_are_rejected(self) -> None:
        cases = (
            ["--project", "/repo", "capabilities"],
            ["--root-repo", "/repo", "capabilities"],
            ["--temporary-repo", "/repo", "capabilities"],
            ["--agent", "legacy-agent", "capabilities"],
            ["capabilities", "--root-repo", "/repo"],
            ["capabilities", "--temporary-repo", "/repo"],
            ["capabilities", "--agent", "legacy-agent"],
        )
        for argv in cases:
            with self.subTest(argv=argv), self.assertRaises(
                agent_cli.AgentCliError
            ):
                agent_cli._parser().parse_args(argv)

    def test_attribution_has_one_environment_owned_derivation(self) -> None:
        with mock.patch.dict(
            agent_cli.os.environ,
            {"CODEX_THREAD_ID": "thread-1", "CODEX_TASK_ID": "task-2"},
            clear=True,
        ):
            self.assertEqual(agent_cli._attribution(), "codex:thread-1")
        with (
            mock.patch.dict(agent_cli.os.environ, {}, clear=True),
            mock.patch.object(agent_cli.os, "geteuid", return_value=1234),
        ):
            self.assertEqual(agent_cli._attribution(), "codex:uid:1234")

    def test_emitter_bounds_the_final_newline(self) -> None:
        stream = mock.Mock()
        stream.buffer = io.BytesIO()
        stream.flush = mock.Mock()
        agent_cli._emit({"schema_version": 1, "ok": True}, stream=stream)
        raw = stream.buffer.getvalue()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertLessEqual(len(raw), 8192)
        self.assertTrue(json.loads(raw))

    def test_capabilities_command_is_one_bounded_document(self) -> None:
        capabilities = {
            "schema_version": 1,
            "status": "ok",
            "agent_result_schema_version": 1,
        }
        profile = mock.Mock()
        profile.resolve_repository.return_value = mock.Mock(
            repo_id="repo-1", generation=4
        )
        with (
            mock.patch.object(agent_cli, "_repository_context", return_value=_Context()),
            mock.patch.object(
                agent_cli,
                "_profile_and_capabilities",
                return_value=(profile, capabilities),
            ),
        ):
            namespace = agent_cli._parser().parse_args(["capabilities"])
            result = agent_cli._execute(namespace)
        self.assertTrue(result["ok"])
        self.assertEqual(result["repository"]["state"], "configured")
        self.assertEqual(result["repository"]["id"], "repo-1")
        self.assertNotIn("root", result["repository"])

    def test_ephemeral_image_prefetch_uses_only_the_sealed_template(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000001"
        repository = mock.Mock(repo_id="repo-1")
        repository.ephemeral_image_prefetch_template_id.return_value = "template-1"
        profile = mock.Mock()
        profile.resolve_repository.return_value = repository
        profile.call.return_value = (
            operation_id,
            {"cached": True, "cache_changed": True},
        )
        namespace = agent_cli._parser().parse_args(
            [
                "ephemeral",
                "image-prefetch",
                "postgres",
                "--operation-id",
                operation_id,
            ]
        )

        with mock.patch.object(
            agent_cli, "_attribution", return_value="codex:thread"
        ):
            result = agent_cli._ephemeral(
                namespace,
                profile=profile,
                capabilities={"ephemeral_image": ["prefetch", "status"]},
                context=_Context(),
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["operation_id"], operation_id)
        repository.ephemeral_image_prefetch_template_id.assert_called_once_with(
            "postgres"
        )
        profile.call.assert_called_once()
        call = profile.call.call_args.kwargs
        self.assertEqual(call["resource_id"], "template-1")
        self.assertEqual(call["arguments"], {"agent": "codex:thread"})

    def test_compose_recreate_reseals_the_current_repository_first(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000001"
        repository = mock.Mock(repo_id="repo-1")
        repository.compose_id.return_value = "compose-1"
        profile = mock.Mock()
        profile.resolve_repository.return_value = repository
        profile.call.return_value = (operation_id, {"ok": True})
        namespace = agent_cli._parser().parse_args(
            [
                "compose",
                "recreate-service",
                "worker",
                "--operation-id",
                operation_id,
            ]
        )

        with mock.patch.object(
            agent_cli, "_attribution", return_value="codex:thread"
        ):
            result = agent_cli._compose(
                namespace,
                profile=profile,
                capabilities={"compose": {"actions": ["recreate-service"]}},
                context=_Context(),
            )

        self.assertTrue(result["ok"])
        profile.ensure_repository_with_outcome.assert_called_once_with(
            canonical_root="/repo",
            project_kind="primary",
            agent="codex:thread",
            operation_id=str(
                uuid.uuid5(
                    uuid.UUID(operation_id), "repository.catalog:/repo"
                )
            ),
        )
        self.assertEqual(profile.call.call_args.kwargs["resource_id"], "compose-1")

    def test_unconfigured_capabilities_are_pure_and_advertise_bootstrap(self) -> None:
        profile = mock.Mock()
        profile.resolve_repository.return_value = None
        capabilities = {
            "schema_version": 1,
            "status": "ok",
            "agent_result_schema_version": 1,
        }
        with (
            mock.patch.object(agent_cli, "_repository_context", return_value=_Context()),
            mock.patch.object(
                agent_cli,
                "_profile_and_capabilities",
                return_value=(profile, capabilities),
            ),
        ):
            result = agent_cli._execute(
                agent_cli._parser().parse_args(["capabilities"])
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["repository"]["state"], "unconfigured")
        self.assertTrue(result["repository"]["bootstrap_supported"])
        self.assertNotIn("id", result["repository"])
        profile.repository.assert_not_called()
        profile.inventory.assert_not_called()

    def test_unconfigured_targets_are_empty_without_inventory_or_mutation(self) -> None:
        profile = mock.Mock()
        profile.resolve_repository.return_value = None

        result = agent_cli._target_projection(
            profile=profile,
            context=_Context(),
            selector=None,
            kind=None,
            limit=4,
        )

        self.assertEqual(result["repository"]["state"], "unconfigured")
        self.assertTrue(result["repository"]["bootstrap_supported"])
        self.assertEqual(result["target_count"], 0)
        self.assertEqual(result["targets"], [])
        profile.inventory.assert_not_called()

    def test_unconfigured_target_selector_explains_first_use_bootstrap(self) -> None:
        profile = mock.Mock()
        profile.resolve_repository.return_value = None

        with self.assertRaises(agent_cli.AgentCliError) as raised:
            agent_cli._target_projection(
                profile=profile,
                context=_Context(),
                selector="web",
                kind=None,
                limit=4,
            )

        self.assertEqual(raised.exception.code, "repository_unconfigured")
        self.assertEqual(
            raised.exception.classification, "repository_bootstrap_required"
        )
        profile.inventory.assert_not_called()

    def test_storage_inventory_returns_only_current_repository_attribution(self) -> None:
        repository = mock.Mock(repo_id="repo-1")
        profile = mock.Mock()
        profile.resolve_repository.return_value = repository
        profile.inventory.return_value = {
            "docker_storage": {
                "available": True,
                "sampled_at": "2026-08-09T00:00:00Z",
                "evidence_fingerprint": "sha256:" + "a" * 64,
                "projects": [
                    {
                        "repo_id": "repo-1",
                        "exclusive_physical_bytes": 10,
                        "referenced_shared_bytes": 2,
                        "components": {"container_writable_bytes": 10},
                    },
                    {"repo_id": "repo-2", "exclusive_physical_bytes": 999},
                ],
                "cleanup_plans": [
                    {
                        "target_kind": "container",
                        "target_id": "container-1",
                        "project_ids": ["repo-1"],
                        "reclaimable_bytes": 10,
                    },
                    {
                        "target_kind": "container",
                        "target_id": "container-2",
                        "project_ids": ["repo-2"],
                        "reclaimable_bytes": 999,
                    },
                ],
                "containers": [
                    {
                        "docker_resource_id": "container-stopped-repo-1",
                        "project_ids": ["repo-1"],
                        "running": False,
                    },
                    {
                        "docker_resource_id": "container-running-repo-1",
                        "project_ids": ["repo-1"],
                        "running": True,
                    },
                    {
                        "docker_resource_id": "container-stopped-repo-2",
                        "project_ids": ["repo-2"],
                        "running": False,
                    },
                ],
            }
        }

        result = agent_cli._storage(
            agent_cli._parser().parse_args(["storage", "inventory"]),
            profile=profile,
            context=_Context(),
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["repository"]["repo_id"], "repo-1")
        self.assertEqual(result["cleanup_plan_count"], 1)
        self.assertEqual(result["cleanup_plans"][0]["target_id"], "container-1")
        self.assertEqual(result["stopped_container_count"], 1)
        self.assertEqual(
            result["stopped_containers"], [{"id": "container-stopped-repo-1"}]
        )

    def test_storage_remove_deletes_one_selected_container_without_plan(self) -> None:
        from devcoordinator.broker import BrokerOperation

        operation_id = "00000000-0000-4000-8000-000000000123"
        repository = mock.Mock(repo_id="repo-1")
        profile = mock.Mock()
        profile.resolve_repository.return_value = repository
        profile.call.return_value = (
            operation_id,
            {
                "ok": True,
                "status": "removed",
                "target_kind": "container",
                "target_id": "container-1",
                "full_container_id": "b" * 64,
            },
        )

        execution_state = {
            "broker_contacted": False,
            "mutation_performed": False,
        }
        result = agent_cli._storage(
            agent_cli._parser().parse_args(
                [
                    "storage",
                    "remove",
                    "container",
                    "container-1",
                    "--reason",
                    "obsolete one-off",
                    "--operation-id",
                    operation_id,
                ]
            ),
            profile=profile,
            context=_Context(),
            execution_state=execution_state,
        )

        self.assertTrue(result["ok"])
        self.assertTrue(execution_state["broker_contacted"])
        self.assertTrue(execution_state["mutation_performed"])
        self.assertEqual(result["status"], "removed")
        profile.inventory.assert_not_called()
        profile.call.assert_called_once_with(
            repository=repository,
            resource_id="container-1",
            operation=BrokerOperation.CONTAINER_REMOVE,
            arguments={
                "target_id": "container-1",
                "reason": "obsolete one-off",
            },
            operation_id=operation_id,
        )

    def test_storage_plan_creates_one_durable_confirmation_bound_volume_plan(self) -> None:
        from devcoordinator.broker import BrokerOperation

        operation_id = "00000000-0000-4000-8000-000000000125"
        repository = mock.Mock(repo_id="repo-1")
        profile = mock.Mock()
        profile.resolve_repository.return_value = repository
        profile.inventory.return_value = {
            "docker_storage": {
                "available": True,
                "sampled_at": "2026-08-09T00:00:00Z",
                "evidence_fingerprint": "sha256:" + "a" * 64,
                "projects": [{"repo_id": "repo-1"}],
                "cleanup_plans": [
                    {
                        "target_kind": "volume",
                        "target_id": "example_data",
                        "project_ids": ["repo-1"],
                        "proof": [
                            "unreferenced_by_any_container",
                            "exclusive_project_ownership",
                            "exact_identity",
                        ],
                        "apply_supported": True,
                    }
                ],
            }
        }
        profile.call.return_value = (
            operation_id,
            {
                "plan_id": operation_id,
                "plan_fingerprint": "sha256:" + "c" * 64,
                "confirmation_phrase": "PURGE VOLUME example_data",
                "status": "planned",
            },
        )

        result = agent_cli._storage(
            agent_cli._parser().parse_args(
                [
                    "storage",
                    "plan",
                    "volume",
                    "example_data",
                    "--reason",
                    "retired project data",
                    "--operation-id",
                    operation_id,
                ]
            ),
            profile=profile,
            context=_Context(),
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["plan"]["confirmation_phrase"], "PURGE VOLUME example_data")
        profile.call.assert_called_once_with(
            repository=repository,
            resource_id="example_data",
            operation=BrokerOperation.CLEANUP_PLAN,
            arguments={
                "action": "purge",
                "target_kind": "volume",
                "target_id": "example_data",
                "reason": "retired project data",
            },
            operation_id=operation_id,
        )

    def test_storage_apply_uses_only_the_exact_durable_plan(self) -> None:
        from devcoordinator.broker import BrokerOperation

        operation_id = "00000000-0000-4000-8000-000000000124"
        plan_id = "00000000-0000-4000-8000-000000000123"
        plan_fingerprint = "sha256:" + "c" * 64
        confirmation = "PURGE CONTAINER example-run-1"
        repository = mock.Mock(repo_id="repo-1")
        profile = mock.Mock()
        profile.resolve_repository.return_value = repository
        profile.call.return_value = (
            operation_id,
            {"ok": True, "status": "succeeded", "target_absent": True},
        )

        result = agent_cli._storage(
            agent_cli._parser().parse_args(
                [
                    "storage",
                    "apply",
                    "--plan",
                    plan_id,
                    "--fingerprint",
                    plan_fingerprint,
                    "--confirm",
                    confirmation,
                    "--operation-id",
                    operation_id,
                ]
            ),
            profile=profile,
            context=_Context(),
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["continuation"], f"dc1:operation:{operation_id}")
        profile.inventory.assert_not_called()
        profile.call.assert_called_once_with(
            repository=repository,
            resource_id="repo-1",
            operation=BrokerOperation.CLEANUP_APPLY,
            arguments={
                "plan_id": plan_id,
                "plan_fingerprint": plan_fingerprint,
                "confirmation_phrase": confirmation,
            },
            operation_id=operation_id,
        )

    def test_unconfigured_error_is_actionable_without_claiming_broker_failure(self) -> None:
        error = agent_cli.AgentCliError(
            "repository_unconfigured",
            "first start-like use adopts this repository",
            classification="repository_bootstrap_required",
        )

        result = agent_cli._failure(error)

        self.assertFalse(result["ok"])
        self.assertEqual(result["classification"], "repository_bootstrap_required")
        self.assertEqual(result["stage"], "client")
        self.assertFalse(result["broker_contacted"])
        self.assertFalse(result["mutation_performed"])
        self.assertFalse(result["retryable"])
        self.assertEqual(result["action"], "run_start_like_repository_adoption")
        self.assertEqual(
            result["next_command"], "devcoordinator runtime serve --help"
        )
        self.assertIn("adopts the repository", result["next_action"])

    def test_local_fallback_boundary_is_typed_as_first_use_not_broker_outage(self) -> None:
        error = BrokerProfileError(
            "repository is not adopted; local fallback is intentionally disabled",
            code="repository_unconfigured",
            classification="repository_bootstrap_required",
        )

        result = agent_cli._failure(error)

        self.assertEqual(result["classification"], "repository_bootstrap_required")
        self.assertFalse(result["broker_contacted"])
        self.assertFalse(result["mutation_performed"])
        self.assertEqual(
            result["next_command"], "devcoordinator runtime serve --help"
        )
        self.assertNotEqual(result["classification"], "broker_unavailable")

    def test_temporary_service_rejection_is_a_launch_infrastructure_failure(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000123"
        error = BrokerError(
            "temporary_service_launch_failed",
            "systemd rejected the bounded temporary service; launch diagnostic: Failed at step CHDIR",
            operation_id=operation_id,
        )

        result = agent_cli._failure(
            error,
            mutation_attempted=True,
            operation_id_hint=operation_id,
            broker_contacted=True,
            observed_mutation=False,
        )

        self.assertEqual(result["classification"], "infrastructure_failure")
        self.assertEqual(result["phase"], "launch")
        self.assertEqual(result["stage"], "launch")
        self.assertTrue(result["broker_contacted"])
        self.assertFalse(result["mutation_performed"])
        self.assertEqual(result["outcome"], "certain")
        self.assertIn("launch diagnostic", result["message"])
        self.assertIn("systemd unit could not start", result["next_action"])

    def test_actual_root_execution_identity_is_an_invalid_launch_request(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000124"
        result = agent_cli._failure(
            BrokerError(
                "execution_identity_invalid",
                "temporary services require the actual non-root caller UID",
                operation_id=operation_id,
            ),
            mutation_attempted=True,
            operation_id_hint=operation_id,
            broker_contacted=True,
            observed_mutation=False,
        )

        self.assertEqual(result["classification"], "invalid_request")
        self.assertEqual(result["phase"], "launch")
        self.assertEqual(result["stage"], "launch")
        self.assertTrue(result["broker_contacted"])
        self.assertFalse(result["mutation_performed"])
        self.assertIn("valid non-root actual-caller UID", result["next_action"])
        self.assertIn("no repository command ran", result["next_action"])
        self.assertIn("not a project source defect", result["next_action"])

    def test_unavailable_execution_identity_is_a_launch_infrastructure_failure(self) -> None:
        cases = (
            (
                "execution_identity_unavailable",
                "temporary service caller account no longer exists",
                "host account lookup",
            ),
            (
                "temporary_service_execution_identity_unavailable",
                "temporary-service operation has no original non-root caller identity",
                "operation or repository state",
            ),
        )
        for index, (code, message, expected_action) in enumerate(cases, start=125):
            operation_id = f"00000000-0000-4000-8000-{index:012d}"
            with self.subTest(code=code):
                result = agent_cli._failure(
                    BrokerError(code, message, operation_id=operation_id),
                    mutation_attempted=True,
                    operation_id_hint=operation_id,
                    broker_contacted=True,
                    observed_mutation=False,
                )

                self.assertEqual(result["classification"], "infrastructure_failure")
                self.assertEqual(result["phase"], "launch")
                self.assertEqual(result["stage"], "launch")
                self.assertTrue(result["broker_contacted"])
                self.assertFalse(result["mutation_performed"])
                self.assertIn("no repository command ran", result["next_action"])
                self.assertIn(expected_action, result["next_action"])
                self.assertIn("not a project source defect", result["next_action"])
                self.assertNotIn("already stopped", result["next_action"])

    def test_execution_identity_mismatch_reports_stopped_unit_and_no_source_defect(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000127"
        result = agent_cli._failure(
            BrokerError(
                "temporary_service_execution_identity_mismatch",
                "actual-caller UID could not be proven",
                operation_id=operation_id,
            ),
            mutation_attempted=True,
            operation_id_hint=operation_id,
            broker_contacted=True,
            observed_mutation=True,
        )

        self.assertEqual(result["classification"], "infrastructure_failure")
        self.assertEqual(result["phase"], "launch")
        self.assertEqual(result["stage"], "launch")
        self.assertTrue(result["broker_contacted"])
        self.assertTrue(result["mutation_performed"])
        self.assertIn("already stopped the exact unit", result["next_action"])
        self.assertIn("not a project source defect", result["next_action"])

    def test_malformed_serve_parser_error_returns_scoped_help_without_contact(self) -> None:
        result = self._main_failure(["runtime", "serve"])

        self.assertEqual(result["code"], "invalid_arguments")
        self.assertEqual(result["stage"], "client")
        self.assertFalse(result["broker_contacted"])
        self.assertFalse(result["mutation_performed"])
        self.assertEqual(
            result["next_command"], "devcoordinator runtime serve --help"
        )
        self.assertIn("rejected locally", result["next_action"])

    def test_incomplete_serve_is_validated_before_profile_or_broker(self) -> None:
        result = self._main_failure(
            [
                "runtime",
                "serve",
                "prototype",
                "--cwd",
                ".",
                "--ttl-seconds",
                "60",
                "--kill-after-run",
                "false",
                "--",
                "npm",
                "run",
                "dev",
            ]
        )

        self.assertEqual(result["code"], "serve_definition_incomplete")
        self.assertFalse(result["broker_contacted"])
        self.assertFalse(result["mutation_performed"])
        self.assertEqual(
            result["next_command"], "devcoordinator runtime serve --help"
        )
        self.assertIn("--cwd", result["next_action"])
        self.assertIn("--port", result["next_action"])

    def test_first_use_adoption_failure_preserves_typed_cause_and_child_operation(self) -> None:
        outer_operation_id = "00000000-0000-4000-8000-000000000001"
        expected_adoption_id = str(
            uuid.uuid5(
                uuid.UUID(outer_operation_id),
                "repository.ensure:/repo",
            )
        )
        namespace = agent_cli._parser().parse_args(
            [
                "runtime",
                "serve",
                "prototype",
                "--cwd",
                ".",
                "--port",
                "4173",
                "--ttl-seconds",
                "60",
                "--kill-after-run",
                "false",
                "--operation-id",
                outer_operation_id,
            ]
        )
        namespace.argv = ["/usr/bin/npm", "run", "dev"]
        profile = mock.Mock()
        profile.repository_if_configured.return_value = None
        profile.ensure_repository_with_outcome.side_effect = BrokerError(
            "repository_context_changed",
            "The proven repository context changed before adoption.",
            operation_id=expected_adoption_id,
        )
        execution_state: dict[str, bool | None] = {
            "broker_contacted": False,
            "mutation_performed": False,
        }

        with self.assertRaises(BrokerError) as raised:
            agent_cli._runtime(
                namespace,
                profile=profile,
                capabilities={"runtime": {"actions": ["serve"]}},
                context=_Context(),
                execution_state=execution_state,
            )

        self.assertEqual(raised.exception.operation_id, expected_adoption_id)
        self.assertEqual(raised.exception.phase, "repository_adoption")
        self.assertTrue(execution_state["broker_contacted"])
        result = agent_cli._failure(
            raised.exception,
            mutation_attempted=True,
            operation_id_hint=outer_operation_id,
            broker_contacted=True,
            observed_mutation=False,
        )
        self.assertEqual(result["code"], "repository_context_changed")
        self.assertEqual(result["classification"], "repository_adoption_failed")
        self.assertEqual(
            result["message"],
            "The proven repository context changed before adoption.",
        )
        self.assertEqual(result["operation_id"], expected_adoption_id)
        self.assertEqual(
            result["continuation"],
            f"dc1:operation:{expected_adoption_id}",
        )
        self.assertEqual(
            result["next_command"],
            (
                "devcoordinator operation follow "
                f"dc1:operation:{expected_adoption_id}"
            ),
        )
        self.assertIn("retained broker evidence", result["next_action"])

    def test_agent_journal_keeps_typed_adoption_failure_and_child_operation(self) -> None:
        child_operation_id = "00000000-0000-4000-8000-000000000099"
        failure = BrokerError(
            "repository_context_changed",
            "The proven repository context changed before adoption.",
            operation_id=child_operation_id,
        )
        failure.phase = "repository_adoption"
        stream = mock.Mock()
        stream.buffer = io.BytesIO()
        stream.flush = mock.Mock()
        with tempfile.TemporaryDirectory(
            prefix="devcoordinator-agent-journal-", dir="/tmp"
        ) as directory:
            journal = RollingCallJournal(Path(directory) / "calls.jsonl")
            with (
                mock.patch.object(agent_cli.sys, "stdout", stream),
                mock.patch(
                    "devcoordinator.call_journal.configured_call_journal",
                    return_value=journal,
                ),
                mock.patch.object(agent_cli, "_execute", side_effect=failure),
            ):
                returncode = agent_cli.main(
                    [
                        "runtime",
                        "serve",
                        "prototype",
                        "--cwd",
                        ".",
                        "--port",
                        "4173",
                        "--ttl-seconds",
                        "60",
                        "--kill-after-run",
                        "false",
                        "--",
                        "/usr/bin/npm",
                        "run",
                        "dev",
                    ]
                )

            self.assertEqual(returncode, 1)
            completed = list(
                read_call_records(Path(directory) / "calls.jsonl")
            )[-1]
        self.assertEqual(completed["code"], "repository_context_changed")
        self.assertEqual(
            completed["message"],
            "The proven repository context changed before adoption.",
        )
        self.assertEqual(completed["operation_id"], child_operation_id)
        self.assertNotEqual(completed["code"], "mutation_failed")

    def test_test_mutations_receive_an_id_before_execution(self) -> None:
        namespace = agent_cli._parser().parse_args(["test", "enqueue"])
        self.assertIsNone(namespace.operation_id)
        namespace.operation_id = agent_cli._canonical_operation_id(
            namespace.operation_id, mutate=True
        )
        self.assertEqual(str(__import__("uuid").UUID(namespace.operation_id)), namespace.operation_id)

    def test_failure_page_preserves_a_cursor_while_enforcing_agent_bound(self) -> None:
        result = {
            "schema_version": 1,
            "repository_id": "repo-1",
            "run_id": "run-1",
            "failures": [
                {
                    "failure_id": f"failure-{index}",
                    "message": "x" * 2048,
                    "location": "y" * 2048,
                }
                for index in range(10)
            ],
            "next_cursor": None,
        }

        bounded = agent_cli._bounded_test_failure_page(result)

        self.assertTrue(bounded["ok"])
        self.assertGreaterEqual(len(bounded["failures"]), 1)
        self.assertLess(len(bounded["failures"]), 10)
        self.assertEqual(
            bounded["next_cursor"], bounded["failures"][-1]["failure_id"]
        )
        self.assertLessEqual(
            len(agent_cli.canonical_json_bytes(bounded)), 8 * 1024
        )
        self.assertEqual(result["next_cursor"], None)
        self.assertEqual(len(result["failures"]), 10)

    def test_successful_retry_without_broker_ok_still_exits_successfully(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000001"
        repository = mock.Mock(repo_id="repo-1")
        profile = mock.Mock()
        profile.resolve_repository.return_value = repository
        profile.retry_test_run.return_value = {
            "schema_version": 1,
            "repository_id": "repo-1",
            "run_id": "run-2",
            "state": "queued",
        }
        namespace = agent_cli._parser().parse_args(
            [
                "test",
                "retry",
                "run-1",
                "--failed-only",
                "--operation-id",
                operation_id,
            ]
        )

        with mock.patch.object(
            agent_cli, "_attribution", return_value="codex:thread"
        ):
            result = agent_cli._test(
                namespace,
                profile=profile,
                capabilities={"tests": {}},
                context=_Context(),
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["operation_id"], operation_id)

    def test_test_parser_exposes_every_advertised_agent_action(self) -> None:
        test_parser = agent_cli._parser()._subparsers._group_actions[0].choices["test"]
        actions = test_parser._subparsers._group_actions[0].choices
        self.assertEqual(
            set(actions),
            {
                "artifact",
                "cancel",
                "enqueue",
                "failures",
                "follow",
                "queue-status",
                "retry",
                "status",
                "submit",
                "summary",
                "wait",
            },
        )

    def test_test_mutation_failure_always_emits_structured_stdout(self) -> None:
        stream = mock.Mock()
        stream.buffer = io.BytesIO()
        stream.flush = mock.Mock()
        failure = BrokerError("mutation_failed", "mutation was rejected")
        with (
            mock.patch.object(agent_cli.sys, "stdout", stream),
            mock.patch(
                "devcoordinator.call_journal.configured_call_journal",
                return_value=None,
            ),
            mock.patch.object(agent_cli, "_execute", side_effect=failure),
        ):
            returncode = agent_cli.main(["test", "enqueue"])

        self.assertEqual(returncode, 1)
        result = json.loads(stream.buffer.getvalue())
        self.assertEqual(result["code"], "mutation_failed")
        self.assertFalse(result["ok"])

    def test_successful_test_follow_always_emits_one_decision_document(self) -> None:
        stream = mock.Mock()
        stream.buffer = io.BytesIO()
        stream.flush = mock.Mock()
        decision = {
            "schema_version": 1,
            "ok": True,
            "classification": "test_pending",
            "continuation": "dc1:run:run-follow-output",
            "run": {
                "id": "run-follow-output",
                "state": "running",
                "terminal": False,
                "conclusion": None,
                "wait_timed_out": True,
            },
        }
        with (
            mock.patch.object(agent_cli.sys, "stdout", stream),
            mock.patch(
                "devcoordinator.call_journal.configured_call_journal",
                return_value=None,
            ),
            mock.patch.object(agent_cli, "_execute", return_value=decision),
        ):
            returncode = agent_cli.main(
                ["test", "follow", "run-follow-output", "--wait-seconds", "1"]
            )

        self.assertEqual(returncode, 0)
        lines = stream.buffer.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0]), decision)

    def test_database_retire_uses_only_exact_registered_identity_and_confirmation(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000321"
        namespace = mock.Mock(
            action="retire",
            selector="postgres",
            database_name="appdb",
            database_backup_id="backup-exact",
            confirm_backup_id="backup-exact",
            operation_id=operation_id,
        )
        profile = mock.Mock()
        repository = mock.Mock(repo_id="repo-1")
        profile.call.return_value = (
            operation_id,
            {
                "status": "retired",
                "database_backup_id": "backup-exact",
                "database_binding_id": "database-1",
                "database_name": "appdb",
                "removed": ["artifact", "manifest"],
                "already_absent": [],
                "reclaimed_bytes": 123,
            },
        )
        with (
            mock.patch.object(
                agent_cli,
                "_runtime_target",
                return_value={"id": "database-1", "kind": "database_stack"},
            ),
            mock.patch.object(
                agent_cli, "_require_resolved_repository", return_value=repository
            ),
        ):
            result = agent_cli._database(
                namespace,
                profile=profile,
                capabilities={"database": ["backup", "retire"]},
                context=_Context(),
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["classification"], "database_backup_retired")
        profile.call.assert_called_once()
        self.assertEqual(
            profile.call.call_args.kwargs["arguments"],
            {
                "database_name": "appdb",
                "database_backup_id": "backup-exact",
                "confirm_backup_id": "backup-exact",
            },
        )

    def test_declared_compose_contract_failure_is_not_a_broker_outage(self) -> None:
        error = BrokerError(
            "repository_runtime_contract_invalid",
            "effective Compose model adds administrator-approved host access: "
            "volume_driver_bind",
        )

        result = agent_cli._failure(
            error,
            mutation_attempted=True,
            broker_contacted=True,
            observed_mutation=False,
        )

        self.assertEqual(
            result["classification"], "repository_configuration_invalid"
        )
        self.assertEqual(result["phase"], "authority")
        self.assertIn("host-access gate", result["next_action"])
        self.assertFalse(result["mutation_performed"])

    def test_operation_follow_uses_the_exact_handle_and_bounded_projection(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000001"
        profile = mock.Mock()
        profile.resolve_repository.return_value = mock.Mock(repo_id="repo-1")
        profile.operation_follow.return_value = {
            "operation_id": operation_id,
            "status": "running",
            "phase": "executing",
            "kind": "broker.docker.start",
            "target_ids": ["container-1"],
            "target_count": 1,
            "target_ids_truncated": False,
            "error_classification": None,
            "outcome_certainty": "pending",
            "next_transition": "wait",
        }
        namespace = agent_cli._parser().parse_args(
            ["operation", "follow", f"dc1:operation:{operation_id}"]
        )

        result = agent_cli._operation(
            namespace,
            profile=profile,
            capabilities={"continuations": {"operation_follow": True}},
            context=_Context(),
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["classification"], "operation_pending")
        self.assertEqual(result["operation"]["operation_id"], operation_id)
        self.assertEqual(
            result["next_command"],
            (
                "devcoordinator operation --project /repo follow "
                f"dc1:operation:{operation_id}"
            ),
        )
        profile.operation_follow.assert_called_once_with(
            repository=profile.resolve_repository.return_value,
            operation_id=operation_id,
        )

    def test_scoped_continuations_are_shell_safe_and_cwd_independent(self) -> None:
        handle = "dc1:operation:00000000-0000-4000-8000-000000000001"
        project = "/repo with spaces"

        operation = agent_cli._operation_follow_command(
            handle, project=project
        )
        test_result = agent_cli._scope_test_result(
            {"next_command": "devcoordinator test follow dc1:run:run-1"},
            project=project,
        )
        failure = agent_cli._failure(
            BrokerError(
                "operation_outcome_uncertain",
                "Host outcome requires reconciliation.",
                operation_id="00000000-0000-4000-8000-000000000001",
            ),
            mutation_attempted=True,
            broker_contacted=True,
            observed_mutation=True,
            project_hint=project,
        )

        self.assertEqual(
            operation,
            "devcoordinator operation --project '/repo with spaces' follow "
            + handle,
        )
        self.assertEqual(
            test_result["next_command"],
            "devcoordinator test follow dc1:run:run-1 --project '/repo with spaces'",
        )
        self.assertEqual(failure["next_command"], operation)

    def test_operation_follow_requires_advertised_capability(self) -> None:
        namespace = agent_cli._parser().parse_args(
            [
                "operation",
                "follow",
                "dc1:operation:00000000-0000-4000-8000-000000000001",
            ]
        )
        with self.assertRaises(agent_cli.AgentCliError) as raised:
            agent_cli._operation(
                namespace,
                profile=mock.Mock(),
                capabilities={"continuations": {"operation_follow": False}},
                context=_Context(),
            )
        self.assertEqual(raised.exception.code, "capability_unavailable")

    def test_operation_follow_preserves_partial_as_attention(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000001"
        profile = mock.Mock()
        profile.resolve_repository.return_value = mock.Mock(repo_id="repo-1")
        profile.operation_follow.return_value = {
            "operation_id": operation_id,
            "status": "partial",
            "phase": "partial",
            "kind": "broker.lifecycle.apply",
            "target_ids": ["resource-1"],
            "target_count": 1,
            "target_ids_truncated": False,
            "error_classification": "partial_failure",
            "outcome_certainty": "partial",
            "next_transition": "inspect",
        }
        namespace = agent_cli._parser().parse_args(
            ["operation", "follow", operation_id]
        )
        result = agent_cli._operation(
            namespace,
            profile=profile,
            capabilities={"continuations": {"operation_follow": True}},
            context=_Context(),
        )
        self.assertEqual(result["classification"], "operation_attention")
        self.assertEqual(result["operation"]["outcome_certainty"], "partial")

    def test_test_follow_anchors_the_opaque_run_to_the_current_repository(self) -> None:
        profile = mock.Mock()
        repository = mock.Mock(repo_id="repo-1")
        profile.resolve_repository.return_value = repository
        profile.test_run_status.return_value = {
            "run_id": "run-1",
            "repository_id": "repo-1",
            "state": "running",
        }
        namespace = agent_cli._parser().parse_args(
            ["test", "follow", "dc1:run:run-1"]
        )

        result = agent_cli._test(
            namespace,
            profile=profile,
            capabilities={"tests": {}},
            context=_Context(),
        )

        self.assertEqual(result["run"]["id"], "run-1")
        profile.test_run_status.assert_called_once_with(
            run_id="run-1", repository="repo-1"
        )
        profile.test_run_summary.assert_not_called()

    def test_mutation_transport_failure_preserves_recovery_identity(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000001"
        result = agent_cli._failure(
            OSError("socket disappeared"),
            mutation_attempted=True,
            operation_id_hint=operation_id,
        )
        self.assertEqual(result["code"], "transport_failure")
        self.assertEqual(result["classification"], "transport_failure")
        self.assertEqual(result["outcome"], "uncertain")
        self.assertIsNone(result["mutation_performed"])
        self.assertEqual(result["operation_id"], operation_id)
        self.assertEqual(
            result["continuation"], f"dc1:operation:{operation_id}"
        )

    def test_read_failure_never_invents_mutation_recovery(self) -> None:
        error = OSError("socket disappeared")
        error.operation_id = "00000000-0000-4000-8000-000000000001"
        result = agent_cli._failure(error, mutation_attempted=False)
        self.assertEqual(result["outcome"], "certain")
        self.assertFalse(result["mutation_performed"])
        self.assertNotIn("operation_id", result)
        self.assertNotIn("continuation", result)

    def test_runtime_ensure_is_one_exact_desired_state_call(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000001"
        profile = mock.Mock()
        root = mock.Mock(repo_id="repo-1")
        profile.resolve_repository.return_value = root
        profile.runtime_ensure.return_value = {
            "schema_version": 1,
            "ok": True,
            "classification": "already_ready",
            "operation_id": operation_id,
            "repository_id": "repo-1",
            "repository_generation": 4,
            "resource": {"kind": "docker", "id": "container-1"},
            "desired_state": "ready",
            "observed_state_before": "ready",
            "mutation_performed": False,
            "action": None,
            "terminal_proof": {
                "certain": True,
                "source": "docker.inspect",
                "snapshot_id": "snapshot-1",
                "observed_state": "ready",
            },
        }
        namespace = agent_cli._parser().parse_args(
            [
                "runtime",
                "ensure",
                "container-1",
                "--desired",
                "ready",
                "--operation-id",
                operation_id,
            ]
        )
        with mock.patch.object(
            agent_cli,
            "_target_projection",
            return_value={"selected": {"id": "container-1", "kind": "docker"}},
        ):
            result = agent_cli._runtime(
                namespace,
                profile=profile,
                capabilities={"runtime": {"ensure_states": ["ready", "stopped"]}},
                context=_Context(),
            )
        self.assertTrue(result["ok"])
        self.assertFalse(result["mutation_performed"])
        self.assertEqual(
            result["continuation"], f"dc1:operation:{operation_id}"
        )
        profile.runtime_ensure.assert_called_once_with(
            repository=root,
            resource_id="container-1",
            target_kind="docker",
            desired_state="ready",
            agent=mock.ANY,
            root_repo_id="repo-1",
            temporary_repo_id=None,
            operation_id=operation_id,
        )

    def test_runtime_ensure_bootstraps_exact_declared_compose_target(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000001"
        child_operation_id = str(
            uuid.uuid5(uuid.UUID(operation_id), "compose.bootstrap:postgres")
        )
        repository = mock.Mock(repo_id="repo-1")
        repository.compose_id.return_value = "compose-1"
        profile = mock.Mock()
        profile.resolve_repository.return_value = repository
        profile.call.return_value = (child_operation_id, {"ok": True})
        profile.runtime_ensure.return_value = {
            "schema_version": 1,
            "ok": True,
            "operation_id": operation_id,
        }
        namespace = agent_cli._parser().parse_args(
            [
                "runtime",
                "ensure",
                "postgres",
                "--desired",
                "ready",
                "--operation-id",
                operation_id,
            ]
        )
        namespace.argv = []

        with (
            mock.patch.object(
                agent_cli,
                "_declared_compose_selector",
                return_value=True,
            ),
            mock.patch.object(
                agent_cli,
                "_runtime_target",
                return_value={"id": "database-1", "kind": "database_stack"},
            ) as runtime_target,
        ):
            result = agent_cli._runtime(
                namespace,
                profile=profile,
                capabilities={"runtime": {"ensure_states": ["ready"]}},
                context=_Context(),
            )

        self.assertTrue(result["ok"])
        profile.call.assert_called_once_with(
            repository=repository,
            resource_id="compose-1",
            operation=mock.ANY,
            arguments={},
            operation_id=child_operation_id,
        )
        runtime_target.assert_called_once_with(
            profile=profile,
            context=mock.ANY,
            selector="postgres",
            kind=None,
            prefer_ready=True,
        )
        profile.runtime_ensure.assert_called_once_with(
            repository=repository,
            resource_id="database-1",
            target_kind="database_stack",
            desired_state="ready",
            agent=mock.ANY,
            root_repo_id="repo-1",
            temporary_repo_id=None,
            operation_id=operation_id,
        )

    def test_runtime_ensure_seals_missing_declared_compose_before_bootstrap(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000001"
        configuration_operation_id = str(
            uuid.uuid5(
                uuid.UUID(operation_id),
                "repository.compose.ensure:/repo",
            )
        )
        catalog_operation_id = str(
            uuid.uuid5(
                uuid.UUID(operation_id),
                "repository.catalog:/repo",
            )
        )
        bootstrap_operation_id = str(
            uuid.uuid5(uuid.UUID(operation_id), "compose.bootstrap:postgres")
        )
        initial = mock.Mock(repo_id="repo-1")
        initial.compose_id.side_effect = BrokerProfileError("missing Compose")
        refreshed = mock.Mock(repo_id="repo-1")
        refreshed.compose_id.return_value = "compose-1"
        profile = mock.Mock()
        profile.resolve_repository.side_effect = [initial, refreshed, refreshed]
        profile.refresh_repository.return_value = refreshed
        profile.ensure_repository_with_outcome.return_value = (refreshed, True)
        profile.call.return_value = (bootstrap_operation_id, {"ok": True})
        profile.runtime_ensure.return_value = {
            "schema_version": 1,
            "ok": True,
            "operation_id": operation_id,
        }
        namespace = agent_cli._parser().parse_args(
            [
                "runtime",
                "ensure",
                "postgres",
                "--desired",
                "ready",
                "--operation-id",
                operation_id,
            ]
        )
        namespace.argv = []

        with (
            mock.patch.object(
                agent_cli, "_declared_compose_selector", return_value=True
            ),
            mock.patch.object(
                agent_cli,
                "_runtime_target",
                return_value={"id": "database-1", "kind": "database_stack"},
            ),
        ):
            result = agent_cli._runtime(
                namespace,
                profile=profile,
                capabilities={"runtime": {"ensure_states": ["ready"]}},
                context=_Context(),
            )

        self.assertTrue(result["ok"])
        profile.ensure_repository_with_outcome.assert_has_calls(
            [
                mock.call(
                    canonical_root="/repo",
                    project_kind="primary",
                    agent=mock.ANY,
                    operation_id=catalog_operation_id,
                ),
                mock.call(
                    canonical_root="/repo",
                    project_kind="primary",
                    agent=mock.ANY,
                    operation_id=configuration_operation_id,
                ),
            ]
        )
        profile.refresh_repository.assert_called_once_with("/repo")
        profile.call.assert_called_once_with(
            repository=refreshed,
            resource_id="compose-1",
            operation=mock.ANY,
            arguments={},
            operation_id=bootstrap_operation_id,
        )

    def test_runtime_replace_forwards_complete_structured_definition(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000001"
        repository = mock.Mock(repo_id="repo-1")
        profile = mock.Mock()
        profile.resolve_repository.return_value = repository
        profile.call.return_value = (
            operation_id,
            {"operation_id": operation_id, "resources": [], "result": {}},
        )
        namespace = agent_cli._parser().parse_args(
            [
                "runtime",
                "replace",
                "worker-1",
                "--kind",
                "service",
                "--cwd",
                ".",
                "--expected-generation",
                "4",
                "--env",
                "MODE=dev",
                "--operation-id",
                operation_id,
            ]
        )
        namespace.argv = ["/usr/bin/python3", "worker.py"]
        with (
            mock.patch.object(
                agent_cli,
                "_runtime_target",
                return_value={"id": "worker-1", "kind": "service"},
            ),
            mock.patch(
                "devcoordinator.agent_projection.project_runtime_report",
                return_value={"schema_version": 1, "ok": True},
            ),
        ):
            result = agent_cli._runtime(
                namespace,
                profile=profile,
                capabilities={"runtime": {"actions": ["replace"]}},
                context=_Context(),
            )

        self.assertTrue(result["ok"])
        arguments = profile.call.call_args.kwargs["arguments"]
        self.assertEqual(arguments["action"], "replace")
        self.assertEqual(arguments["expected_definition_generation"], 4)
        self.assertEqual(arguments["argv"], ["/usr/bin/python3", "worker.py"])
        self.assertEqual(arguments["cwd"], ".")
        self.assertEqual(arguments["environment"], {"MODE": "dev"})

    def test_runtime_ensure_rejects_legacy_lifecycle_options(self) -> None:
        namespace = agent_cli._parser().parse_args(
            [
                "runtime",
                "ensure",
                "container-1",
                "--desired",
                "stopped",
                "--purpose",
                "development",
            ]
        )
        with self.assertRaises(agent_cli.AgentCliError) as raised:
            agent_cli._runtime(
                namespace,
                profile=mock.Mock(),
                capabilities={"runtime": {"ensure_states": ["ready", "stopped"]}},
                context=_Context(),
            )
        self.assertEqual(raised.exception.code, "ensure_option_forbidden")

    def test_runtime_ensure_rejects_replacement_definition_options(self) -> None:
        namespace = agent_cli._parser().parse_args(
            [
                "runtime",
                "ensure",
                "container-1",
                "--desired",
                "ready",
                "--expected-generation",
                "3",
                "--env",
                "MODE=dev",
            ]
        )
        namespace.argv = []
        with self.assertRaises(agent_cli.AgentCliError) as raised:
            agent_cli._runtime(
                namespace,
                profile=mock.Mock(),
                capabilities={"runtime": {"ensure_states": ["ready"]}},
                context=_Context(),
            )
        self.assertEqual(raised.exception.code, "ensure_option_forbidden")

    def test_exact_configured_runtime_id_skips_inventory_projection(self) -> None:
        profile = mock.Mock()
        repository = mock.Mock()
        repository.server_ids = {"api": "service-1"}
        repository.container_ids = {}
        repository.compose_container_ids = frozenset()
        profile.resolve_repository.return_value = repository
        with mock.patch.object(agent_cli, "_target_projection") as projection:
            selected = agent_cli._runtime_target(
                profile=profile,
                context=_Context(),
                selector="service-1",
                kind="service",
            )
        self.assertEqual(selected, {"kind": "service", "id": "service-1"})
        projection.assert_not_called()

    def test_ambiguous_target_error_exposes_only_bounded_exact_candidates(self) -> None:
        from devcoordinator.agent_projection import AgentProjectionError

        error = AgentProjectionError(
            "target_ambiguous",
            "target selector matched multiple authoritative resources",
            candidates=(
                {
                    "kind": "service",
                    "id": "service-1",
                    "name": "api",
                    "state": "running",
                    "canonical_root": "/private/repository",
                },
                {
                    "kind": "docker",
                    "id": "container-1",
                    "name": "api",
                    "state": "stopped",
                    "image": "private/image",
                },
            ),
        )
        result = agent_cli._failure(error)
        self.assertEqual(result["code"], "target_ambiguous")
        self.assertEqual(result["next_command"], "devcoordinator targets")
        self.assertEqual(len(result["evidence"]["candidates"]), 2)
        self.assertNotIn("canonical_root", result["evidence"]["candidates"][0])
        self.assertNotIn("image", result["evidence"]["candidates"][1])


if __name__ == "__main__":
    unittest.main()
