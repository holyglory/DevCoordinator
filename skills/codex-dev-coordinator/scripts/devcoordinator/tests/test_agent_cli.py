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
                "devcoordinator.repository_context.resolve_effective_repository_context",
                return_value=_Context(),
            ) as resolve,
        ):
            context = agent_cli._repository_context(namespace)

        self.assertIs(context, resolve.return_value)
        resolve.assert_called_once_with(project="/canonical/repo")

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
        self.assertEqual(result["repository"]["state"], "enrolled")
        self.assertEqual(result["repository"]["id"], "repo-1")
        self.assertNotIn("root", result["repository"])

    def test_unenrolled_capabilities_are_pure_and_advertise_bootstrap(self) -> None:
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
        self.assertEqual(result["repository"]["state"], "unenrolled")
        self.assertTrue(result["repository"]["bootstrap_supported"])
        self.assertNotIn("id", result["repository"])
        profile.repository.assert_not_called()
        profile.inventory.assert_not_called()

    def test_unenrolled_targets_are_empty_without_inventory_or_mutation(self) -> None:
        profile = mock.Mock()
        profile.resolve_repository.return_value = None

        result = agent_cli._target_projection(
            profile=profile,
            context=_Context(),
            selector=None,
            kind=None,
            limit=4,
        )

        self.assertEqual(result["repository"]["state"], "unenrolled")
        self.assertTrue(result["repository"]["bootstrap_supported"])
        self.assertEqual(result["target_count"], 0)
        self.assertEqual(result["targets"], [])
        profile.inventory.assert_not_called()

    def test_unenrolled_target_selector_explains_first_use_bootstrap(self) -> None:
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

        self.assertEqual(raised.exception.code, "repository_unenrolled")
        self.assertEqual(
            raised.exception.classification, "repository_bootstrap_required"
        )
        profile.inventory.assert_not_called()

    def test_unenrolled_error_is_actionable_without_claiming_broker_failure(self) -> None:
        error = agent_cli.AgentCliError(
            "repository_unenrolled",
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
            code="repository_unenrolled",
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

    def test_repository_access_preparation_failure_is_not_broker_outage(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000125"
        result = agent_cli._failure(
            BrokerError(
                "repository_access_normalization_failed",
                "authority sandbox cannot update the validated working tree",
                operation_id=operation_id,
            ),
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
        self.assertIn("/home write boundary", result["next_action"])
        self.assertNotEqual(result["classification"], "broker_unavailable")

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
        profile.repository_if_enrolled.return_value = None
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
            f"devcoordinator operation follow dc1:operation:{operation_id}",
        )
        profile.operation_follow.assert_called_once_with(
            repository=profile.resolve_repository.return_value,
            operation_id=operation_id,
        )

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

    def test_exact_enrolled_runtime_id_skips_inventory_projection(self) -> None:
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
