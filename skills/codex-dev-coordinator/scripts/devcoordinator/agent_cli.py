"""Stable, bounded, intent-oriented client for calling agents.

The broker and its full service documents remain authoritative.  This module
owns the low-entropy caller surface: it derives repository context, performs a
capability handshake, binds display selectors to immutable resource IDs, and
returns one compact JSON decision envelope.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import time
from typing import Any, Mapping, Sequence
import uuid

from .agent_contract import (
    AgentContractError,
    MAX_AGENT_RESULT_BYTES,
    agent_error_result,
    bounded_text,
    canonical_json_bytes,
    continuation_handle,
    require_agent_result,
)


MAX_CAPABILITIES_RESULT_BYTES = 3 * 1024
MAX_OPERATION_FOLLOW_RESULT_BYTES = 3 * 1024
_REPOSITORY_ADOPTION_FAILURE_CODES = frozenset(
    {
        "repository_adoption_constraint_failed",
        "repository_adoption_internal_error",
        "repository_adoption_invariant_failed",
        "repository_adoption_store_failed",
        "repository_context_invalid",
        "repository_catalog_registration_failed",
    }
)


class AgentCliError(RuntimeError):
    """One typed, pre-mutation client failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        classification: str = "invalid_request",
        phase: str = "client",
        evidence: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.classification = classification
        self.phase = phase
        self.evidence = None if evidence is None else dict(evidence)
        self.next_command: str | None = None


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise AgentCliError("invalid_arguments", message)


def _add_scoped_project(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--project",
        default=argparse.SUPPRESS,
        help="active Git worktree override for this command",
    )


def _operation_follow_command(handle: str, *, project: str | None) -> str:
    command = "devcoordinator operation"
    if isinstance(project, str) and project:
        command += f" --project {shlex.quote(project)}"
    return f"{command} follow {shlex.quote(handle)}"


def _scope_test_result(
    result: Mapping[str, Any], *, project: str
) -> dict[str, Any]:
    """Keep generated test continuations independent of the caller's cwd."""

    document = dict(result)
    next_command = document.get("next_command")
    if isinstance(next_command, str) and next_command.startswith(
        "devcoordinator test "
    ):
        document["next_command"] = (
            f"{next_command} --project {shlex.quote(project)}"
        )
    return document


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="devcoordinator",
        description=(
            "Bounded agent client for exact host-runtime and test intents. "
            "Repository context defaults to the current Git worktree."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    capabilities = commands.add_parser(
        "capabilities",
        help="read and validate the active broker/client contract",
    )
    _add_scoped_project(capabilities)

    targets = commands.add_parser(
        "targets", help="list or resolve repository-owned runtime targets"
    )
    targets.add_argument("selector", nargs="?", help="exact ID or unique display name")
    targets.add_argument(
        "--kind", choices=("service", "docker", "database_stack")
    )
    targets.add_argument("--limit", type=int, default=4)
    _add_scoped_project(targets)

    storage = commands.add_parser(
        "storage",
        help="read Docker storage, remove one selected container, or plan/apply volume deletion",
    )
    storage.add_argument(
        "action", choices=("inventory", "remove", "plan", "apply")
    )
    storage.add_argument(
        "target_kind",
        nargs="?",
        choices=("container", "image", "volume", "build_cache"),
    )
    storage.add_argument("target_id", nargs="?")
    storage.add_argument(
        "--reason",
        default=None,
        help="bounded reason for direct container removal or a volume cleanup plan",
    )
    storage.add_argument("--plan", help="durable cleanup plan UUID returned by storage plan")
    storage.add_argument(
        "--fingerprint",
        help="exact durable plan fingerprint returned by storage plan",
    )
    storage.add_argument(
        "--confirm",
        help="exact target-bound confirmation phrase returned by storage plan",
    )
    storage.add_argument(
        "--operation-id",
        help="canonical operation UUID for idempotent plan/apply replay",
    )
    _add_scoped_project(storage)

    runtime = commands.add_parser(
        "runtime", help="execute one exact configured runtime lifecycle action"
    )
    runtime.add_argument(
        "action",
        choices=(
            "status",
            "capture_logs",
            "ensure",
            "serve",
            "start",
            "stop",
            "restart",
            "replace",
        ),
    )
    runtime.add_argument(
        "selector",
        help="exact ID/display name, or the new temporary service name for serve",
    )
    runtime.add_argument(
        "--kind", choices=("service", "docker", "database_stack")
    )
    runtime.add_argument(
        "--purpose", choices=("development", "test", "temporary")
    )
    runtime.add_argument(
        "--desired",
        choices=("ready", "stopped"),
        help="desired terminal state for runtime ensure",
    )
    runtime.add_argument("--ttl-seconds", type=int)
    runtime.add_argument(
        "--cwd",
        help="repository-relative working directory for runtime serve or replace",
    )
    runtime.add_argument(
        "--port", type=int, help="exact fixed TCP port for runtime serve"
    )
    runtime.add_argument(
        "--launch-timeout-seconds",
        type=int,
        default=None,
        help="listener readiness deadline for runtime serve (default 30)",
    )
    runtime.add_argument(
        "--kill-after-run",
        choices=("true", "false"),
        help="explicit broker cleanup policy for runtime serve",
    )
    runtime.add_argument(
        "--keep-alive",
        choices=("true", "false"),
        help="explicit persistent-worker supervision policy on first start",
    )
    runtime.add_argument(
        "--rearm-crash-loop",
        action="store_true",
        help="explicitly re-arm a stopped worker crash loop",
    )
    runtime.add_argument(
        "--operation-id",
        help="canonical UUID to replay a prior mutation exactly",
    )
    runtime.add_argument(
        "--expected-generation",
        type=int,
        help="current service definition generation required by runtime replace",
    )
    runtime.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="one literal environment value for runtime replace; repeat as needed",
    )
    _add_scoped_project(runtime)

    operation = commands.add_parser(
        "operation", help="recover one exact durable operation outcome"
    )
    operation.add_argument("action", choices=("follow",))
    operation.add_argument(
        "operation", help="dc1:operation handle or exact canonical UUID"
    )
    _add_scoped_project(operation)

    tests = commands.add_parser(
        "test", help="plan, enqueue, submit, or follow asynchronous tests"
    )
    test_actions = tests.add_subparsers(dest="test_action", required=True)
    enqueue = test_actions.add_parser(
        "enqueue", help="register and enqueue one policy-derived test plan"
    )
    enqueue.add_argument(
        "--intent",
        choices=("change", "checkpoint", "handoff", "release", "manual"),
        default="change",
    )
    enqueue.add_argument(
        "--target",
        action="append",
        default=[],
        help="declared target for manual intent (repeatable)",
    )
    enqueue.add_argument("--execution-timeout-seconds", type=int)
    enqueue.add_argument("--launch-timeout-seconds", type=int, default=300)
    enqueue.add_argument("--operation-id")
    _add_scoped_project(enqueue)

    submit = test_actions.add_parser(
        "submit", help="submit one explicitly reviewed plan handle"
    )
    submit.add_argument("plan", help="dc1:plan handle or exact plan ID")
    submit.add_argument("--operation-id")
    _add_scoped_project(submit)

    follow = test_actions.add_parser(
        "follow", help="read or wait for one run and return a compact decision"
    )
    follow.add_argument("run", help="dc1:run handle or exact run ID")
    follow.add_argument(
        "--wait-seconds",
        type=int,
        default=0,
        help="broker-side status polling deadline, from 0 through 86400",
    )
    _add_scoped_project(follow)

    for action, help_text in (
        ("status", "read compact current state for one run"),
        ("summary", "read the bounded terminal summary for one run"),
    ):
        command = test_actions.add_parser(action, help=help_text)
        command.add_argument("run", help="dc1:run handle or exact run ID")
        _add_scoped_project(command)

    failures = test_actions.add_parser(
        "failures", help="read one cursor-bounded page of actionable failures"
    )
    failures.add_argument("run", help="dc1:run handle or exact run ID")
    failures.add_argument("--after")
    failures.add_argument("--limit", type=int, default=10)
    _add_scoped_project(failures)

    artifact = test_actions.add_parser(
        "artifact", help="resolve one exact verified test artifact"
    )
    artifact.add_argument("run", help="dc1:run handle or exact run ID")
    artifact.add_argument("artifact", help="exact artifact ID")
    _add_scoped_project(artifact)

    wait = test_actions.add_parser(
        "wait", help="wait for one run up to an explicit bounded deadline"
    )
    wait.add_argument("run", help="dc1:run handle or exact run ID")
    wait.add_argument("--timeout-seconds", type=int, required=True)
    _add_scoped_project(wait)

    cancel = test_actions.add_parser(
        "cancel", help="request cancellation of one exact run"
    )
    cancel.add_argument("run", help="dc1:run handle or exact run ID")
    cancel.add_argument("--reason", required=True)
    cancel.add_argument("--operation-id")
    _add_scoped_project(cancel)

    retry = test_actions.add_parser(
        "retry", help="retry only failed work from one exact run"
    )
    retry.add_argument("run", help="dc1:run handle or exact run ID")
    retry.add_argument("--failed-only", action="store_true", required=True)
    retry.add_argument("--operation-id")
    _add_scoped_project(retry)

    # Bug intake is intentionally registered on the stable agent client but
    # executes before repository/profile/authority discovery.  The dedicated
    # devcoordinator-bug wrapper exposes the same actions during a wider
    # control-plane outage.
    from .bug_registry import add_bug_parser

    add_bug_parser(commands)
    return parser


def _repository_context(namespace: argparse.Namespace) -> Any:
    from .repository_context import resolve_effective_repository_context

    context = resolve_effective_repository_context(
        project=getattr(namespace, "project", None) or os.getcwd()
    )
    # Preserve the resolved canonical scope for any failure/continuation
    # emitted after discovery.  The resulting command can be followed from a
    # different working directory without silently selecting another repo.
    namespace._resolved_project = context.effective.canonical_root
    return context


def _profile_and_capabilities(
    context: Any, *, execution_state: dict[str, bool | None] | None = None
) -> tuple[Any, dict[str, Any]]:
    from .broker_profile import load_broker_profile
    from .capabilities import (
        release_digest,
        validate_client_capabilities,
    )

    profile = load_broker_profile(required=True)
    if profile is None:  # defensive; required=True already excludes this
        raise AgentCliError(
            "broker_profile_required",
            "the protected broker profile is unavailable",
            classification="shared_authority_required",
        )
    # Capabilities describe the host authority, not repository configuration.
    # Route this read through any current transport anchor so a valid new Git
    # root can discover its truthful unconfigured/bootstrap state without a
    # mutation hidden inside a read command.
    if execution_state is not None:
        execution_state["broker_contacted"] = None
    try:
        capabilities = profile.capabilities()
    except BaseException as error:
        if execution_state is not None:
            execution_state["broker_contacted"] = _broker_contact_from_error(error)
        raise
    if execution_state is not None:
        execution_state["broker_contacted"] = True
    validated = validate_client_capabilities(
        capabilities,
        expected_authority_generation=profile.service.database_generation,
        client_release_digest=release_digest(Path(__file__)),
    )
    return profile, validated


def _attribution() -> str:
    from .test_actor import TestActorContractError, calling_codex_test_actor

    try:
        return calling_codex_test_actor()
    except TestActorContractError as error:
        raise AgentCliError(
            "agent_attribution_invalid",
            "agent attribution must be one canonical codex actor",
        ) from error


def _target_projection(
    *,
    profile: Any,
    context: Any,
    selector: str | None,
    kind: str | None,
    limit: int,
) -> dict[str, Any]:
    from .agent_projection import project_targets

    repository = profile.resolve_repository(
        context.effective.canonical_root
    )
    if repository is None:
        if selector is not None:
            raise AgentCliError(
                "repository_unconfigured",
                "runtime targets are unavailable until the first start-like mutation adopts this repository",
                classification="repository_bootstrap_required",
            )
        return require_agent_result(
            {
                "schema_version": 1,
                "ok": True,
                "repository": {
                    "state": "unconfigured",
                    "kind": context.project_kind,
                    "bootstrap_supported": True,
                },
                "target_count": 0,
                "targets": [],
                "truncated": False,
            },
            surface="target projection",
            maximum_bytes=2 * 1024,
        )

    inventory = profile.inventory(canonical_root=context.effective.canonical_root)
    return project_targets(
        inventory,
        effective_root=context.effective.canonical_root,
        selector=selector,
        kind=kind,
        limit=limit,
    )


def _runtime_target(
    *,
    profile: Any,
    context: Any,
    selector: str,
    kind: str | None,
) -> dict[str, Any]:
    """Resolve an exact configured ID locally, otherwise use fresh inventory.

    Protected profile values are immutable authority identities, not ownership
    guesses.  Display names, database bindings, and ambiguous cross-kind values
    still take the full Python-produced inventory path.
    """

    repository = _require_resolved_repository(
        profile, context.effective.canonical_root
    )
    candidates: list[dict[str, Any]] = []
    server_ids = getattr(repository, "server_ids", {})
    if isinstance(server_ids, Mapping) and selector in server_ids.values():
        candidates.append({"kind": "service", "id": selector})
    container_ids = getattr(repository, "container_ids", {})
    compose_ids = getattr(repository, "compose_container_ids", ())
    if (
        isinstance(container_ids, Mapping)
        and selector in container_ids.values()
    ) or (
        isinstance(compose_ids, (set, frozenset, tuple, list))
        and selector in compose_ids
    ):
        candidates.append({"kind": "docker", "id": selector})
    eligible = [
        candidate
        for candidate in candidates
        if kind is None or candidate["kind"] == kind
    ]
    if len(eligible) == 1:
        return eligible[0]

    # Temporary services intentionally disappear from the active inventory at
    # TTL, but their exact opaque ID remains status-addressable.  Refresh the
    # broker-issued repository identity only for an unresolved exact service
    # lookup; ordinary target listings continue to use the active projection.
    refresh = getattr(profile, "refresh_repository", None)
    if not candidates and kind in {None, "service"} and callable(refresh):
        refreshed = refresh(context.effective.canonical_root)
        refreshed_ids = getattr(refreshed, "server_ids", {})
        if isinstance(refreshed_ids, Mapping) and selector in refreshed_ids.values():
            return {"kind": "service", "id": selector}
    projection = _target_projection(
        profile=profile,
        context=context,
        selector=selector,
        kind=kind,
        limit=4,
    )
    selected = projection.get("selected")
    if not isinstance(selected, Mapping):
        raise AgentCliError("target_not_resolved", "runtime target was not resolved")
    return dict(selected)


def _require_resolved_repository(profile: Any, canonical_root: str) -> Any:
    repository = profile.resolve_repository(canonical_root)
    if repository is None:
        raise AgentCliError(
            "repository_unconfigured",
            "this repository has not been adopted; run one start-like runtime command first",
            classification="repository_bootstrap_required",
        )
    return repository


def _canonical_operation_id(value: str | None, *, mutate: bool) -> str | None:
    if value is None:
        return str(uuid.uuid4()) if mutate else None
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, AttributeError) as error:
        raise AgentCliError(
            "operation_id_invalid", "--operation-id must be a canonical UUID"
        ) from error
    if canonical != value:
        raise AgentCliError(
            "operation_id_invalid", "--operation-id must be a canonical UUID"
        )
    return canonical


def _validate_runtime_serve_namespace(
    namespace: argparse.Namespace,
) -> tuple[list[str], int, bool]:
    """Reject malformed serve calls before profile loading or broker contact."""

    from .temporary_dev_service import (
        TemporaryDevServiceError,
        validate_temporary_dev_service_definition,
    )

    if (
        namespace.kind is not None
        or namespace.desired is not None
        or namespace.keep_alive is not None
        or namespace.rearm_crash_loop
    ):
        raise AgentCliError(
            "serve_option_forbidden",
            "runtime serve does not accept target kind, desired state, or worker supervision options",
        )
    if namespace.purpose not in {None, "temporary"}:
        raise AgentCliError(
            "serve_purpose_invalid", "runtime serve has purpose=temporary"
        )
    if namespace.ttl_seconds is None or namespace.ttl_seconds <= 0:
        raise AgentCliError(
            "ttl_required", "runtime serve requires a positive --ttl-seconds"
        )
    if namespace.cwd is None or namespace.port is None:
        raise AgentCliError(
            "serve_definition_incomplete",
            "runtime serve requires --cwd and one exact --port",
        )
    if namespace.kill_after_run is None:
        raise AgentCliError(
            "kill_after_run_required",
            "runtime serve requires an explicit --kill-after-run policy",
        )
    argv = list(namespace.argv)
    if not argv:
        raise AgentCliError(
            "argv_required", "runtime serve requires structured argv after --"
        )
    launch_timeout_seconds = (
        30
        if namespace.launch_timeout_seconds is None
        else namespace.launch_timeout_seconds
    )
    kill_after_run = namespace.kill_after_run == "true"
    try:
        validate_temporary_dev_service_definition(
            name=namespace.selector,
            argv=argv,
            cwd=namespace.cwd,
            port=namespace.port,
            ttl_seconds=namespace.ttl_seconds,
            kill_after_run=kill_after_run,
            launch_timeout_seconds=launch_timeout_seconds,
        )
    except TemporaryDevServiceError as error:
        raise AgentCliError(error.code, str(error)) from error
    return argv, launch_timeout_seconds, kill_after_run


def _replacement_environment(values: Sequence[str]) -> dict[str, str]:
    environment: dict[str, str] = {}
    for item in values:
        key, separator, value = str(item).partition("=")
        if (
            not separator
            or not key
            or key in environment
            or "\x00" in key
            or "\x00" in value
        ):
            raise AgentCliError(
                "replacement_environment_invalid",
                "runtime replace requires unique literal --env KEY=VALUE entries",
            )
        environment[key] = value
    return environment


def _declared_compose_selector(root: str, selector: str) -> bool:
    """Return whether the exact selector is declared by the bounded manifest.

    This check only decides whether a missing target may trigger the already
    sealed Compose definition.  The authority remains the source of the files,
    environment, ownership and operation grant used for the mutation.
    """

    manifest = Path(root) / ".codex" / "dev-runtime.json"
    try:
        metadata = manifest.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or manifest.is_symlink()
            or metadata.st_size > 2 * 1024 * 1024
        ):
            return False
        document = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    if not isinstance(document, Mapping):
        return False
    declared: set[str] = set()
    docker = document.get("docker")
    if isinstance(docker, Mapping):
        services = docker.get("services")
        if isinstance(services, list):
            declared.update(
                value for value in services if isinstance(value, str) and value
            )
    dependencies = document.get("dependencies")
    if isinstance(dependencies, list):
        for dependency in dependencies:
            if not isinstance(dependency, Mapping):
                continue
            for field in ("name", "service", "container"):
                value = dependency.get(field)
                if isinstance(value, str) and value:
                    declared.add(value)
    return selector in declared


def _bootstrap_declared_compose_target(
    *, profile: Any, context: Any, selector: str, operation_id: str
) -> None:
    from .broker import BrokerOperation

    effective = _require_resolved_repository(
        profile, context.effective.canonical_root
    )
    if not _declared_compose_selector(
        context.effective.canonical_root, selector
    ):
        raise AgentCliError(
            "target_not_found",
            "target selector matched no authoritative resource and is not declared by this repository manifest",
        )
    try:
        compose_id = effective.compose_id()
    except BaseException:
        configuration_operation_id = str(
            uuid.uuid5(
                uuid.UUID(operation_id),
                "repository.compose.ensure:"
                + context.effective.canonical_root,
            )
        )
        profile.ensure_repository_with_outcome(
            canonical_root=context.effective.canonical_root,
            project_kind=(
                "temporary" if context.temporary is not None else "primary"
            ),
            agent=_attribution(),
            operation_id=configuration_operation_id,
        )
        effective = profile.refresh_repository(
            context.effective.canonical_root
        )
        if effective is None:
            raise AgentCliError(
                "compose_bootstrap_unavailable",
                "the repository was adopted but its declared Compose definition was not published",
                classification="repository_bootstrap_failed",
            )
        try:
            compose_id = effective.compose_id()
        except BaseException as error:
            raise AgentCliError(
                "compose_bootstrap_unavailable",
                "the repository was adopted but its declared Compose definition could not be sealed; correct the returned manifest or Compose error and retry",
                classification="repository_bootstrap_failed",
            ) from error
    child_operation_id = str(
        uuid.uuid5(uuid.UUID(operation_id), "compose.bootstrap:" + selector)
    )
    returned_id, report = profile.call(
        repository=effective,
        resource_id=compose_id,
        operation=BrokerOperation.COMPOSE_UP,
        arguments={},
        operation_id=child_operation_id,
    )
    if returned_id != child_operation_id or not isinstance(report, Mapping):
        raise AgentCliError(
            "compose_bootstrap_reply_invalid",
            "Compose bootstrap returned contradictory operation evidence",
            classification="invalid_reply",
            phase="transport",
        )


def _runtime(
    namespace: argparse.Namespace,
    *,
    profile: Any,
    capabilities: Mapping[str, Any],
    context: Any,
    execution_state: dict[str, bool | None] | None = None,
) -> dict[str, Any]:
    from .agent_projection import project_runtime_report
    from .broker import BrokerOperation

    runtime_caps = capabilities.get("runtime")
    if namespace.action == "serve":
        argv, launch_timeout_seconds, kill_after_run = (
            _validate_runtime_serve_namespace(namespace)
        )
        actions = (
            runtime_caps.get("actions")
            if isinstance(runtime_caps, Mapping)
            else None
        )
        if not isinstance(actions, list) or "serve" not in actions:
            raise AgentCliError(
                "capability_unavailable",
                "active authority does not advertise bounded temporary services",
                classification="unsupported_capability",
                phase="handshake",
            )
        operation_id = _canonical_operation_id(namespace.operation_id, mutate=True)
        namespace.operation_id = operation_id
        assert operation_id is not None
        agent = _attribution()

        # One agent command owns both first-use adoption and launch.  Separate
        # deterministic mutation IDs let each durable broker operation replay
        # exactly without asking the caller to orchestrate an configuration step.
        scopes = [(context.root, "primary")]
        if context.temporary is not None:
            scopes.append((context.effective, "temporary"))
        for scope, project_kind in scopes:
            was_configured = (
                profile.repository_if_configured(scope.canonical_root) is not None
            )
            ensure_operation_id = str(
                uuid.uuid5(
                    uuid.UUID(operation_id),
                    "repository.ensure:" + scope.canonical_root,
                )
            )
            if not was_configured and execution_state is not None:
                execution_state["broker_contacted"] = None
            try:
                _repository, configuration_changed = (
                    profile.ensure_repository_with_outcome(
                        canonical_root=scope.canonical_root,
                        project_kind=project_kind,
                        agent=agent,
                        operation_id=ensure_operation_id,
                        transport_timeout_seconds=float(
                            launch_timeout_seconds + 30
                        ),
                    )
                )
            except BaseException as error:
                if not was_configured and execution_state is not None:
                    execution_state["broker_contacted"] = _broker_contact_from_error(
                        error
                    )
                # The start-like command owns two durable mutations: first-use
                # repository adoption, then service launch.  Preserve the exact
                # adoption identity and stage on every failure so the public
                # envelope and rolling journal never substitute the outer
                # launch operation or flatten the cause into a generic outage.
                if not isinstance(getattr(error, "operation_id", None), str):
                    try:
                        error.operation_id = ensure_operation_id
                    except (AttributeError, TypeError):
                        pass
                if not isinstance(getattr(error, "phase", None), str):
                    try:
                        error.phase = "repository_adoption"
                    except (AttributeError, TypeError):
                        pass
                raise
            if not was_configured and execution_state is not None:
                execution_state["broker_contacted"] = True
            if configuration_changed and execution_state is not None:
                execution_state["mutation_performed"] = True

        root = _require_resolved_repository(
            profile, context.root.canonical_root
        )
        effective = _require_resolved_repository(
            profile, context.effective.canonical_root
        )
        if execution_state is not None:
            execution_state["broker_contacted"] = None
        try:
            returned_operation_id, report = profile.call(
                repository=effective,
                resource_id=effective.repo_id,
                operation=BrokerOperation.RUNTIME_REQUEST,
                arguments={
                    "action": "temporary_start",
                    "agent": agent,
                    "root_repo_id": root.repo_id,
                    "temporary_repo_id": (
                        effective.repo_id if context.temporary is not None else None
                    ),
                    "target_kind": "service",
                    "purpose": "temporary",
                    "ttl_seconds": namespace.ttl_seconds,
                    "kill_after_run": kill_after_run,
                    "name": namespace.selector,
                    "argv": argv,
                    "cwd": namespace.cwd,
                    "port": namespace.port,
                    "launch_timeout_seconds": launch_timeout_seconds,
                },
                operation_id=operation_id,
                transport_timeout_seconds=float(launch_timeout_seconds + 30),
            )
        except BaseException as error:
            if execution_state is not None:
                execution_state["broker_contacted"] = _broker_contact_from_error(
                    error
                )
            raise
        if execution_state is not None:
            execution_state["broker_contacted"] = True
            execution_state["mutation_performed"] = True
        if returned_operation_id != operation_id or not isinstance(report, Mapping):
            raise AgentCliError(
                "runtime_reply_invalid",
                "broker temporary-service response contradicted its operation identity",
                classification="invalid_reply",
                phase="transport",
            )
        result = dict(report)
        result.update(
            {
                "schema_version": 1,
                "operation_id": operation_id,
                "broker_contacted": True,
                "mutation_performed": True,
                "retryable": False,
                "continuation": continuation_handle("operation", operation_id),
            }
        )
        return require_agent_result(
            result, surface="runtime serve", maximum_bytes=3 * 1024
        )

    if namespace.action == "ensure":
        if namespace.desired is None:
            raise AgentCliError(
                "desired_state_required", "runtime ensure requires --desired"
            )
        ensure_states = (
            runtime_caps.get("ensure_states")
            if isinstance(runtime_caps, Mapping)
            else None
        )
        if (
            not isinstance(ensure_states, list)
            or namespace.desired not in ensure_states
        ):
            raise AgentCliError(
                "capability_unavailable",
                f"active authority does not advertise runtime ensure state {namespace.desired}",
                classification="unsupported_capability",
                phase="handshake",
            )
        if (
            namespace.purpose is not None
            or namespace.ttl_seconds is not None
            or namespace.keep_alive is not None
            or namespace.rearm_crash_loop
            or namespace.cwd is not None
            or namespace.port is not None
            or namespace.launch_timeout_seconds is not None
            or namespace.kill_after_run is not None
            or namespace.expected_generation is not None
            or namespace.env
            or getattr(namespace, "argv", [])
        ):
            raise AgentCliError(
                "ensure_option_forbidden",
                "runtime ensure accepts only selector, --desired, --kind, and --operation-id",
            )
        operation_id = _canonical_operation_id(namespace.operation_id, mutate=True)
        namespace.operation_id = operation_id
        assert operation_id is not None
        if namespace.desired == "ready":
            scopes = [(context.root, "primary")]
            if context.temporary is not None:
                scopes.append((context.effective, "temporary"))
            for scope, project_kind in scopes:
                catalog_operation_id = str(
                    uuid.uuid5(
                        uuid.UUID(operation_id),
                        "repository.catalog:" + scope.canonical_root,
                    )
                )
                profile.ensure_repository_with_outcome(
                    canonical_root=scope.canonical_root,
                    project_kind=project_kind,
                    agent=_attribution(),
                    operation_id=catalog_operation_id,
                )
        try:
            target = _runtime_target(
                profile=profile,
                context=context,
                selector=namespace.selector,
                kind=namespace.kind,
            )
        except BaseException as error:
            if (
                namespace.desired != "ready"
                or getattr(error, "code", None) != "target_not_found"
            ):
                raise
            _bootstrap_declared_compose_target(
                profile=profile,
                context=context,
                selector=namespace.selector,
                operation_id=operation_id,
            )
            target = _runtime_target(
                profile=profile,
                context=context,
                selector=namespace.selector,
                kind=namespace.kind,
            )
        root = _require_resolved_repository(
            profile, context.root.canonical_root
        )
        effective = _require_resolved_repository(
            profile, context.effective.canonical_root
        )
        report = profile.runtime_ensure(
            repository=effective,
            resource_id=str(target["id"]),
            target_kind=str(target["kind"]),
            desired_state=namespace.desired,
            agent=_attribution(),
            root_repo_id=root.repo_id,
            temporary_repo_id=(
                effective.repo_id if context.temporary is not None else None
            ),
            operation_id=operation_id,
        )
        if not isinstance(report, Mapping) or report.get("operation_id") != operation_id:
            raise AgentCliError(
                "runtime_reply_invalid",
                "runtime ensure reply contradicted its operation identity",
                classification="invalid_reply",
                phase="transport",
            )
        result = dict(report)
        operation_handle = continuation_handle("operation", operation_id)
        result["continuation"] = operation_handle
        if result.get("ok") is not True:
            result["next_command"] = _operation_follow_command(
                operation_handle,
                project=context.effective.canonical_root,
            )
        return require_agent_result(
            result, surface="runtime ensure", maximum_bytes=2 * 1024
        )

    if namespace.desired is not None:
        raise AgentCliError(
            "desired_state_forbidden", "--desired applies only to runtime ensure"
        )
    if namespace.action != "replace" and (
        namespace.cwd is not None
        or namespace.port is not None
        or namespace.launch_timeout_seconds is not None
        or namespace.kill_after_run is not None
        or getattr(namespace, "argv", [])
        or namespace.expected_generation is not None
        or namespace.env
    ):
        raise AgentCliError(
            "serve_option_forbidden",
            "--cwd, --port, --launch-timeout-seconds, --kill-after-run, --expected-generation, --env, and argv apply only to runtime serve or replace",
        )
    actions = runtime_caps.get("actions") if isinstance(runtime_caps, Mapping) else None
    if not isinstance(actions, list) or namespace.action not in actions:
        raise AgentCliError(
            "capability_unavailable",
            f"active authority does not advertise runtime {namespace.action}",
            classification="unsupported_capability",
            phase="handshake",
        )
    if namespace.action in {"status", "capture_logs"} and namespace.ttl_seconds is not None:
        raise AgentCliError(
            "ttl_forbidden", f"runtime {namespace.action} does not accept a TTL"
        )
    if (
        namespace.purpose in {"test", "temporary"}
        and namespace.action in {"start", "restart"}
        and namespace.ttl_seconds is None
    ):
        raise AgentCliError(
            "ttl_required",
            "test and temporary start-like runtime actions require --ttl-seconds",
        )
    if namespace.action not in {"start", "restart"} and (
        namespace.keep_alive is not None or namespace.rearm_crash_loop
    ):
        raise AgentCliError(
            "supervision_option_forbidden",
            "worker supervision options apply only to start or restart",
        )

    target = _runtime_target(
        profile=profile,
        context=context,
        selector=namespace.selector,
        kind=namespace.kind,
    )

    root = _require_resolved_repository(profile, context.root.canonical_root)
    effective = _require_resolved_repository(
        profile, context.effective.canonical_root
    )
    action = str(namespace.action)
    replacement_environment: dict[str, str] | None = None
    if action == "replace":
        if str(target["kind"]) != "service":
            raise AgentCliError(
                "replacement_target_invalid",
                "runtime replace accepts one exact configured service target",
            )
        if (
            namespace.cwd is None
            or namespace.expected_generation is None
            or namespace.expected_generation < 0
            or not getattr(namespace, "argv", [])
        ):
            raise AgentCliError(
                "replacement_definition_incomplete",
                "runtime replace requires --cwd, --expected-generation, and structured argv after --",
            )
        if (
            namespace.port is not None
            or namespace.launch_timeout_seconds is not None
            or namespace.kill_after_run is not None
            or namespace.purpose is not None
            or namespace.ttl_seconds is not None
            or namespace.keep_alive is not None
            or namespace.rearm_crash_loop
        ):
            raise AgentCliError(
                "replacement_option_forbidden",
                "runtime replace accepts only selector, --kind service, --cwd, --expected-generation, --env, --operation-id, and structured argv",
            )
        replacement_environment = _replacement_environment(namespace.env)
    mutate = action not in {"status", "capture_logs"}
    operation_id = _canonical_operation_id(namespace.operation_id, mutate=mutate)
    namespace.operation_id = operation_id
    options: dict[str, Any] = {}
    if namespace.keep_alive is not None:
        options["keep_alive"] = namespace.keep_alive == "true"
    if namespace.rearm_crash_loop:
        options["rearm_crash_loop"] = True
    arguments = {
        "action": action,
        "agent": _attribution(),
        "root_repo_id": root.repo_id,
        "temporary_repo_id": (
            effective.repo_id if context.temporary is not None else None
        ),
        "target_kind": str(target["kind"]),
        "purpose": namespace.purpose or "development",
        "ttl_seconds": namespace.ttl_seconds,
        "kill_after_run": False,
        "keep_alive": options.get("keep_alive"),
        "rearm_crash_loop": bool(options.get("rearm_crash_loop", False)),
        "restart_limit": None,
        "restart_window_seconds": None,
    }
    if action == "replace":
        arguments.update(
            {
                "expected_definition_generation": namespace.expected_generation,
                "argv": list(namespace.argv),
                "cwd": namespace.cwd,
                "environment": replacement_environment,
            }
        )
    returned_operation_id, report = profile.call(
        repository=effective,
        resource_id=str(target["id"]),
        operation=BrokerOperation.RUNTIME_REQUEST,
        arguments=arguments,
        operation_id=operation_id,
    )
    if operation_id is not None and returned_operation_id != operation_id:
        raise AgentCliError(
            "operation_identity_mismatch",
            "broker returned a different operation identity",
            classification="invalid_reply",
            phase="transport",
        )
    if not isinstance(report, Mapping):
        raise AgentCliError(
            "runtime_reply_invalid",
            "broker runtime response is not an object",
            classification="invalid_reply",
            phase="transport",
        )
    correlated = dict(report)
    correlated["operation_id"] = returned_operation_id
    result = project_runtime_report(correlated)
    if mutate:
        result["continuation"] = continuation_handle(
            "operation", returned_operation_id
        )
    return require_agent_result(result, surface="runtime result")


def _handle_identity(value: str, *, expected_kind: str) -> str:
    from .agent_contract import parse_continuation_handle

    if value.startswith("dc1:"):
        kind, identity = parse_continuation_handle(value)
        if kind != expected_kind:
            raise AgentCliError(
                "continuation_kind_invalid",
                f"expected a {expected_kind} continuation handle",
            )
        return identity
    if (
        not value
        or len(value.encode("utf-8")) > 256
        or value[0] in "_.:@-"
        or any(
            character
            not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:@-"
            for character in value
        )
    ):
        raise AgentCliError(
            "continuation_identity_invalid",
            f"{expected_kind} identity is invalid",
        )
    return value


def _operation(
    namespace: argparse.Namespace,
    *,
    profile: Any,
    capabilities: Mapping[str, Any],
    context: Any,
) -> dict[str, Any]:
    continuations = capabilities.get("continuations")
    if (
        not isinstance(continuations, Mapping)
        or continuations.get("operation_follow") is not True
    ):
        raise AgentCliError(
            "capability_unavailable",
            "active authority does not advertise operation follow",
            classification="unsupported_capability",
            phase="handshake",
        )
    operation_id = _handle_identity(
        namespace.operation, expected_kind="operation"
    )
    repository = _require_resolved_repository(
        profile, context.effective.canonical_root
    )
    followed = profile.operation_follow(
        repository=repository,
        operation_id=operation_id,
    )
    if not isinstance(followed, Mapping) or followed.get("operation_id") != operation_id:
        raise AgentCliError(
            "operation_reply_invalid",
            "operation follow reply contradicted its operation identity",
            classification="invalid_reply",
            phase="transport",
        )

    certainty = str(followed.get("outcome_certainty") or "")
    if certainty not in {"certain", "pending", "uncertain", "partial"}:
        raise AgentCliError(
            "operation_reply_invalid",
            "operation follow reply has an invalid outcome certainty",
            classification="invalid_reply",
            phase="transport",
        )
    handle = continuation_handle("operation", operation_id)
    operation_projection = {
        key: followed.get(key)
        for key in (
            "operation_id",
            "status",
            "phase",
            "kind",
            "target_ids",
            "target_count",
            "target_ids_truncated",
            "error_classification",
            "outcome_certainty",
            "next_transition",
        )
    }
    document: dict[str, Any] = {
        "schema_version": 1,
        "ok": True,
        "classification": (
            "operation_pending"
            if certainty == "pending"
            else "operation_attention"
            if certainty in {"uncertain", "partial"}
            else "operation_terminal"
        ),
        "continuation": handle,
        "operation": operation_projection,
    }
    run_id = followed.get("run_id")
    plan_id = followed.get("plan_id")
    if isinstance(run_id, str):
        run_handle = continuation_handle("run", run_id)
        document["run_handle"] = run_handle
    if isinstance(plan_id, str):
        document["plan_handle"] = continuation_handle("plan", plan_id)
    if certainty == "pending":
        document["next_command"] = _operation_follow_command(
            handle,
            project=context.effective.canonical_root,
        )
    elif isinstance(run_id, str):
        document["next_command"] = (
            f"devcoordinator test follow {shlex.quote(run_handle)}"
            f" --project {shlex.quote(context.root.canonical_root)}"
        )
    return require_agent_result(
        document,
        surface="operation follow",
        maximum_bytes=MAX_OPERATION_FOLLOW_RESULT_BYTES,
    )


def _storage(
    namespace: argparse.Namespace,
    *,
    profile: Any,
    context: Any,
    execution_state: dict[str, bool | None] | None = None,
) -> dict[str, Any]:
    from .broker import BrokerOperation

    repository = _require_resolved_repository(
        profile, context.effective.canonical_root
    )
    if namespace.action == "remove":
        if namespace.target_kind != "container" or namespace.target_id is None:
            raise AgentCliError(
                "storage_target_required",
                "storage remove requires container and one exact Coordinator target ID",
            )
        if namespace.plan or namespace.fingerprint or namespace.confirm:
            raise AgentCliError(
                "storage_remove_option_forbidden",
                "storage remove does not use a plan, fingerprint, or confirmation phrase",
            )
        operation_id = _canonical_operation_id(namespace.operation_id, mutate=True)
        if execution_state is not None:
            execution_state["broker_contacted"] = None
        try:
            returned_operation_id, result = profile.call(
                repository=repository,
                resource_id=namespace.target_id,
                operation=BrokerOperation.CONTAINER_REMOVE,
                arguments={
                    "target_id": namespace.target_id,
                    "reason": namespace.reason
                    or "developer-directed Docker container removal",
                },
                operation_id=operation_id,
            )
        except BaseException as error:
            if execution_state is not None:
                execution_state["broker_contacted"] = _broker_contact_from_error(
                    error
                )
            raise
        if execution_state is not None:
            execution_state["broker_contacted"] = True
            execution_state["mutation_performed"] = True
        if returned_operation_id != operation_id or not isinstance(result, Mapping):
            raise AgentCliError(
                "storage_remove_reply_invalid",
                "the authority did not return the exact correlated container-removal result",
                classification="invalid_reply",
                phase="transport",
            )
        payload = dict(result)
        payload.update(
            {
                "schema_version": 1,
                "ok": result.get("ok") is True,
                "operation_id": returned_operation_id,
                "continuation": continuation_handle(
                    "operation", returned_operation_id
                ),
            }
        )
        return require_agent_result(
            payload,
            surface="direct Docker container removal",
            maximum_bytes=4 * 1024,
        )
    if namespace.action == "apply":
        if namespace.target_kind is not None or namespace.target_id is not None:
            raise AgentCliError(
                "storage_target_forbidden",
                "storage apply uses only the exact durable --plan, --fingerprint, and --confirm values",
            )
        if namespace.reason is not None:
            raise AgentCliError(
                "storage_reason_forbidden", "--reason applies only to storage plan"
            )
        if not namespace.plan or not namespace.fingerprint or not namespace.confirm:
            raise AgentCliError(
                "storage_plan_required",
                "storage apply requires --plan, --fingerprint, and --confirm exactly as returned by storage plan",
            )
        operation_id = _canonical_operation_id(namespace.operation_id, mutate=True)
        if execution_state is not None:
            execution_state["broker_contacted"] = None
        try:
            returned_operation_id, result = profile.call(
                repository=repository,
                resource_id=repository.repo_id,
                operation=BrokerOperation.CLEANUP_APPLY,
                arguments={
                    "plan_id": namespace.plan,
                    "plan_fingerprint": namespace.fingerprint,
                    "confirmation_phrase": namespace.confirm,
                },
                operation_id=operation_id,
            )
        except BaseException as error:
            if execution_state is not None:
                execution_state["broker_contacted"] = _broker_contact_from_error(
                    error
                )
            raise
        if execution_state is not None:
            execution_state["broker_contacted"] = True
            execution_state["mutation_performed"] = True
        if returned_operation_id != operation_id or not isinstance(result, Mapping):
            raise AgentCliError(
                "storage_apply_reply_invalid",
                "the authority did not return the exact correlated storage-cleanup result",
                classification="invalid_reply",
                phase="transport",
            )
        payload = dict(result)
        payload.update(
            {
                "schema_version": 1,
                "ok": bool(
                    result.get(
                        "ok",
                        result.get("status") in {"succeeded", "already_complete"},
                    )
                ),
                "operation_id": returned_operation_id,
                "continuation": continuation_handle("operation", returned_operation_id),
            }
        )
        return require_agent_result(
            payload,
            surface="Docker storage reclaim apply",
            maximum_bytes=4 * 1024,
        )
    if namespace.plan or namespace.fingerprint or namespace.confirm:
        raise AgentCliError(
            "storage_apply_option_forbidden",
            "--plan, --fingerprint, and --confirm apply only to storage apply",
        )
    inventory = profile.inventory(canonical_root=context.effective.canonical_root)
    storage = inventory.get("docker_storage")
    if not isinstance(storage, Mapping):
        raise AgentCliError(
            "storage_inventory_unavailable",
            "the authority did not return Docker storage accounting",
            classification="unavailable",
        )
    if namespace.action == "inventory":
        if (
            namespace.target_kind is not None
            or namespace.target_id is not None
            or namespace.reason is not None
            or namespace.operation_id is not None
        ):
            raise AgentCliError(
                "storage_target_forbidden",
                "storage inventory does not accept cleanup targets, reasons, or operation IDs",
            )
        project = next(
            (
                dict(row)
                for row in storage.get("projects") or []
                if isinstance(row, Mapping)
                and str(row.get("repo_id") or "") == repository.repo_id
            ),
            None,
        )
        project_plans = [
            dict(row)
            for row in storage.get("cleanup_plans") or []
            if isinstance(row, Mapping)
            and repository.repo_id in (row.get("project_ids") or [])
        ]
        return require_agent_result(
            {
                "schema_version": 1,
                "ok": storage.get("available") is True,
                "status": storage.get("status") or (
                    "ready" if storage.get("available") is True else "unavailable"
                ),
                "error": bounded_text(storage.get("error"), maximum_bytes=512)
                if storage.get("error")
                else None,
                "sampled_at": storage.get("sampled_at"),
                "repository": project
                or {
                    "repo_id": repository.repo_id,
                    "exclusive_attributed_bytes": 0,
                    "referenced_shared_bytes": 0,
                    "components": {},
                },
                "accounting": storage.get("accounting"),
                "cleanup_plans": project_plans[:16],
                "cleanup_plan_count": len(project_plans),
                "truncated": len(project_plans) > 16,
                "evidence_fingerprint": storage.get("evidence_fingerprint"),
            },
            surface="project Docker storage",
            maximum_bytes=4 * 1024,
        )
    if namespace.target_kind is None or namespace.target_id is None:
        raise AgentCliError(
            "storage_target_required",
            "storage plan requires one exact target kind and target ID",
        )
    if namespace.target_kind == "container":
        raise AgentCliError(
            "storage_remove_required",
            "container deletion is direct; use `devcoordinator storage remove container TARGET --reason REASON`",
        )
    if namespace.target_kind not in {"container", "volume"}:
        raise AgentCliError(
            "storage_cleanup_kind_unsupported",
            "plan/apply is available only for an exclusively project-owned detached Compose volume; container deletion uses storage remove, while image and build-cache rows remain read-only accounting candidates",
            classification="unsupported_capability",
        )
    matches = [
        dict(row)
        for row in storage.get("cleanup_plans") or []
        if isinstance(row, Mapping)
        and row.get("target_kind") == namespace.target_kind
        and row.get("target_id") == namespace.target_id
        and row.get("apply_supported") is True
        and list(row.get("project_ids") or []) == [repository.repo_id]
    ]
    if len(matches) != 1:
        raise AgentCliError(
            "storage_cleanup_not_proven",
            "the current authority sample does not prove that exact storage object reclaimable",
        )
    operation_id = _canonical_operation_id(namespace.operation_id, mutate=True)
    if execution_state is not None:
        execution_state["broker_contacted"] = None
    try:
        returned_operation_id, durable = profile.call(
            repository=repository,
            resource_id=namespace.target_id,
            operation=BrokerOperation.CLEANUP_PLAN,
            arguments={
                "action": "purge",
                "target_kind": namespace.target_kind,
                "target_id": namespace.target_id,
                "reason": namespace.reason or "exact Docker storage reclaim",
            },
            operation_id=operation_id,
        )
    except BaseException as error:
        if execution_state is not None:
            execution_state["broker_contacted"] = _broker_contact_from_error(error)
        raise
    if execution_state is not None:
        execution_state["broker_contacted"] = True
        execution_state["mutation_performed"] = True
    if returned_operation_id != operation_id or not isinstance(durable, Mapping):
        raise AgentCliError(
            "storage_plan_reply_invalid",
            "the authority did not return the exact correlated durable cleanup plan",
            classification="invalid_reply",
            phase="transport",
        )
    return require_agent_result(
        {
            "schema_version": 1,
            "ok": True,
            "status": "planned",
            "sampled_at": storage.get("sampled_at"),
            "candidate": matches[0],
            "plan": dict(durable),
            "operation_id": returned_operation_id,
            "continuation": continuation_handle("operation", returned_operation_id),
            "evidence_fingerprint": storage.get("evidence_fingerprint"),
        },
        surface="Docker storage reclaim plan",
        maximum_bytes=4 * 1024,
    )


def _test(
    namespace: argparse.Namespace,
    *,
    profile: Any,
    capabilities: Mapping[str, Any],
    context: Any,
) -> dict[str, Any]:
    from .agent_test import (
        enqueue_test,
        project_test_follow,
        submit_test_plan,
    )

    test_caps = capabilities.get("tests")
    if not isinstance(test_caps, Mapping):
        raise AgentCliError(
            "capability_unavailable",
            "active authority does not publish test capabilities",
            classification="unsupported_capability",
            phase="handshake",
        )
    root = _require_resolved_repository(profile, context.root.canonical_root)
    effective = _require_resolved_repository(
        profile, context.effective.canonical_root
    )
    action = namespace.test_action
    if action == "enqueue":
        allowed = test_caps.get("enqueue_intents")
        if not isinstance(allowed, list) or namespace.intent not in allowed:
            raise AgentCliError(
                "capability_unavailable",
                f"active authority does not advertise test enqueue intent {namespace.intent}",
                classification="unsupported_capability",
                phase="handshake",
            )
        return _scope_test_result(enqueue_test(
            profile=profile,
            repository=root,
            temporary_repository=(effective if context.temporary is not None else None),
            intent=namespace.intent,
            requested_targets=tuple(namespace.target),
            execution_timeout_seconds=namespace.execution_timeout_seconds,
            launch_timeout_seconds=namespace.launch_timeout_seconds,
            actor=_attribution(),
            operation_id=namespace.operation_id,
        ), project=context.root.canonical_root)
    if action == "submit":
        return _scope_test_result(submit_test_plan(
            profile=profile,
            repository=root,
            plan_id=_handle_identity(namespace.plan, expected_kind="plan"),
            actor=_attribution(),
            operation_id=namespace.operation_id,
        ), project=context.root.canonical_root)
    if action in {"follow", "status", "summary", "wait"}:
        wait_seconds = (
            namespace.timeout_seconds
            if action == "wait"
            else namespace.wait_seconds
            if action == "follow"
            else 0
        )
        if not 0 <= wait_seconds <= 86_400:
            raise AgentCliError(
                "wait_deadline_invalid", "test wait deadline must be from 0 through 86400"
            )
        run_id = _handle_identity(namespace.run, expected_kind="run")
        status = (
            profile.test_run_status(run_id=run_id, repository=root.repo_id)
            if wait_seconds == 0
            else profile.wait_test_run(
                run_id=run_id,
                repository=root.repo_id,
                timeout_seconds=wait_seconds,
            )
        )
        if not isinstance(status, Mapping):
            raise AgentCliError(
                "test_reply_invalid",
                "test status reply is not an object",
                classification="invalid_reply",
                phase="transport",
            )
        state = str(status.get("state") or status.get("status") or "")
        from .agent_test import TERMINAL_STATES

        summary = (
            profile.test_run_summary(run_id=run_id, repository=root.repo_id)
            if action == "summary" or state in TERMINAL_STATES
            else None
        )
        return _scope_test_result(
            project_test_follow(status, run_id=run_id, summary=summary),
            project=context.root.canonical_root,
        )
    if action == "failures":
        if not 1 <= namespace.limit <= 50:
            raise AgentCliError(
                "failure_limit_invalid", "--limit must be from 1 through 50"
            )
        run_id = _handle_identity(namespace.run, expected_kind="run")
        result = profile.test_run_failures(
            repository=root.repo_id,
            run_id=run_id,
            after=namespace.after,
            limit=namespace.limit,
        )
        return require_agent_result(result, surface="test failures")
    if action == "artifact":
        run_id = _handle_identity(namespace.run, expected_kind="run")
        artifact_id = _handle_identity(namespace.artifact, expected_kind="artifact")
        return require_agent_result(
            profile.test_artifact(
                repository=root.repo_id,
                run_id=run_id,
                artifact_id=artifact_id,
            ),
            surface="test artifact",
        )
    if action in {"cancel", "retry"}:
        run_id = _handle_identity(namespace.run, expected_kind="run")
        operation_id = namespace.operation_id
        assert operation_id is not None
        if action == "cancel":
            if not namespace.reason.strip() or len(namespace.reason) > 500:
                raise AgentCliError(
                    "cancel_reason_invalid",
                    "--reason must be from 1 through 500 characters",
                )
            result = profile.cancel_test_run(
                repository=root.repo_id,
                run_id=run_id,
                reason=namespace.reason,
                operation_id=operation_id,
                actor=_attribution(),
            )
        else:
            result = profile.retry_test_run(
                repository=root.repo_id,
                run_id=run_id,
                failed_only=True,
                operation_id=operation_id,
                actor=_attribution(),
            )
        document = dict(result)
        document["operation_id"] = operation_id
        document["continuation"] = continuation_handle(
            "operation", operation_id
        )
        return require_agent_result(document, surface=f"test {action}")
    raise AgentCliError("command_unsupported", "test action is unsupported")


def _execute(
    namespace: argparse.Namespace,
    *,
    execution_state: dict[str, bool | None] | None = None,
) -> dict[str, Any]:
    if namespace.command == "bug":
        from .bug_registry import execute_namespace

        return execute_namespace(namespace)
    context = _repository_context(namespace)
    profile, capabilities = _profile_and_capabilities(
        context, execution_state=execution_state
    )
    if namespace.command == "capabilities":
        repository = profile.resolve_repository(
            context.effective.canonical_root
        )
        repository_result: dict[str, Any]
        if repository is None:
            repository_result = {
                "state": "unconfigured",
                "kind": context.project_kind,
                "bootstrap_supported": True,
            }
        else:
            repository_result = {
                "state": "configured",
                "id": repository.repo_id,
                "generation": repository.generation,
                "kind": context.project_kind,
                "bootstrap_supported": True,
            }
        return require_agent_result(
            {
                "schema_version": 1,
                "ok": True,
                "repository": repository_result,
                "capabilities": capabilities,
            },
            surface="capabilities",
            maximum_bytes=MAX_CAPABILITIES_RESULT_BYTES,
        )
    if namespace.command == "targets":
        return _target_projection(
            profile=profile,
            context=context,
            selector=namespace.selector,
            kind=namespace.kind,
            limit=namespace.limit,
        )
    if namespace.command == "storage":
        return _storage(
            namespace,
            profile=profile,
            context=context,
            execution_state=execution_state,
        )
    if namespace.command == "runtime":
        return _runtime(
            namespace,
            profile=profile,
            capabilities=capabilities,
            context=context,
            execution_state=execution_state,
        )
    if namespace.command == "operation":
        return _operation(
            namespace,
            profile=profile,
            capabilities=capabilities,
            context=context,
        )
    if namespace.command == "test":
        return _test(
            namespace,
            profile=profile,
            capabilities=capabilities,
            context=context,
        )
    raise AgentCliError("command_unsupported", "agent command is unsupported")


def _command_mutates(namespace: argparse.Namespace | None) -> bool:
    if namespace is None:
        return False
    # Bug reports mutate only the independent local open-file registry.  They
    # never submit a broker mutation and therefore must not manufacture an
    # uncertain broker operation/continuation when the registry is unavailable.
    if namespace.command == "bug":
        return False
    if namespace.command == "runtime":
        return namespace.action not in {"status", "capture_logs"}
    if namespace.command == "storage":
        return namespace.action in {"remove", "plan", "apply"}
    return namespace.command == "test" and namespace.test_action in {
        "cancel",
        "enqueue",
        "retry",
        "submit",
    }


def _error_classification(error: BaseException, code: str) -> str:
    explicit = getattr(error, "classification", None)
    if isinstance(explicit, str) and explicit:
        return explicit
    if code in {
        "invalid_arguments",
        "invalid_operation_id",
        "invalid_request",
        "invalid_json",
        "unknown_operation",
        "operation_id_invalid",
        "argv_invalid",
        "argv_required",
        "cwd_escape",
        "cwd_invalid",
        "cwd_unavailable",
        "execution_identity_invalid",
        "kill_after_run_invalid",
        "kill_after_run_required",
        "launch_timeout_invalid",
        "port_invalid",
        "service_name_invalid",
        "shell_forbidden",
        "ttl_invalid",
        "ttl_required",
    } or code.startswith("invalid_"):
        return "invalid_request"
    if code in {
        "port_in_use",
        "port_ownership_mismatch",
        "temporary_service_name_active",
    }:
        return "resource_conflict"
    if code in {
        "execution_identity_unavailable",
        "temporary_service_execution_identity_unavailable",
        "temporary_service_execution_identity_mismatch",
        "temporary_service_launch_failed",
        "temporary_service_exited",
        "temporary_service_readiness_timeout",
    }:
        return "infrastructure_failure"
    if code.startswith("maintenance_"):
        return "maintenance"
    if code in {"server_busy", "broker_busy", "request_timeout"}:
        return "broker_unavailable"
    if code in {
        "transport_failure",
        "empty_reply",
        "incomplete_reply",
        "invalid_reply",
    }:
        return "transport_failure"
    if code in {"operation_outcome_uncertain", "operation_in_progress"}:
        return "outcome_uncertain"
    if code in _REPOSITORY_ADOPTION_FAILURE_CODES:
        return "repository_bootstrap_failed"
    if code in {"unclassified_resource", "unknown_listener_ownership"}:
        return "safety_block"
    if code.endswith("_unavailable") or code.endswith("_not_found"):
        return "not_found"
    if any(fragment in code for fragment in ("denied", "forbidden", "unauthorized")):
        return "authorization_denied"
    if getattr(error, "phase", None) == "repository_adoption":
        return "repository_adoption_failed"
    return (
        "invalid_request"
        if isinstance(error, (AgentCliError, AgentContractError, ValueError))
        else "broker_unavailable"
    )


def _broker_contact_from_error(error: BaseException) -> bool | None:
    """Classify whether the failing call provably reached broker authority."""

    from .broker import BrokerError
    from .broker_profile import BrokerProfileError

    if isinstance(error, BrokerError):
        code = str(getattr(error, "code", ""))
        if code.startswith("maintenance_") or code == "broker_transport_forbidden":
            return False
        if code in {
            "empty_reply",
            "incomplete_reply",
            "incomplete_request",
            "request_timeout",
            "transport_failure",
        }:
            return None
        # A typed broker error survived reply validation. Raw connection and
        # receive failures are OSError/TimeoutError and remain unknown below.
        return True
    if isinstance(error, (AgentCliError, AgentContractError, BrokerProfileError)):
        return False
    return None


def _next_action_for_failure(
    *,
    code: str,
    broker_contacted: bool | None,
    continuation: str | None,
    outcome: str,
    phase: str,
) -> str:
    if code == "repository_unconfigured":
        return (
            "Submit one structured runtime serve command for this repository; "
            "that single command adopts the repository and starts the bounded service."
        )
    if code in {
        "repository_adoption_constraint_failed",
        "repository_adoption_invariant_failed",
        "repository_catalog_registration_failed",
    }:
        return (
            "The broker rejected repository adoption before launch and returned the "
            "specific catalog conflict in the message. Correct that conflict, then "
            "rerun the original structured runtime serve command with a fresh operation "
            "ID; do not enable local fallback, bind the port directly, or choose another port."
        )
    if code in {"repository_adoption_store_failed", "repository_context_invalid"}:
        return (
            "Correct the concrete repository/store condition in the message (or let the "
            "current authority writer finish), then rerun the original structured runtime "
            "serve command with a fresh operation ID."
        )
    if code == "repository_adoption_internal_error":
        return (
            "Repository adoption reached the broker but failed unexpectedly before launch. "
            "Do not retry blindly or bypass Coordinator; report the returned operation ID "
            "and error code to the Coordinator task."
        )
    if code == "invalid_arguments":
        return (
            "The command shape was rejected locally before any broker call or mutation. "
            "Run the returned help command, correct the options, and resubmit; do not "
            "change repository configuration or enable local fallback."
        )
    if code == "serve_definition_incomplete":
        return (
            "Provide both a repository-relative --cwd and one exact --port, then "
            "resubmit the structured runtime serve call."
        )
    if code == "serve_option_forbidden":
        return (
            "Remove existing-target lifecycle options from runtime serve and pass only "
            "its name, cwd, exact port, TTL, cleanup policy, timeout, and structured argv."
        )
    if code == "serve_purpose_invalid":
        return "Omit --purpose or set it to temporary for runtime serve, then resubmit."
    if code in {"ttl_required", "ttl_invalid"}:
        return "Provide a positive --ttl-seconds no greater than seven days and resubmit."
    if code in {"kill_after_run_required", "kill_after_run_invalid"}:
        return "Set --kill-after-run explicitly to true or false and resubmit."
    if code == "port_invalid":
        return "Provide one exact TCP --port from 1 through 65535 and resubmit."
    if code == "service_name_invalid":
        return "Use a bounded lowercase service name and resubmit."
    if code == "launch_timeout_invalid":
        return "Set --launch-timeout-seconds from 1 through 300 and resubmit."
    if code == "port_in_use":
        return (
            "The exact requested port is occupied and Coordinator did not choose another. "
            "Stop or wait for the known owner, then submit a new operation ID for the same port."
        )
    if code == "port_ownership_mismatch":
        return (
            "A different process won the exact-port race; the launched unit was stopped. "
            "Stop or wait for that owner, then submit a new operation ID for the same port."
        )
    if code == "execution_identity_invalid":
        return (
            "The temporary-service request did not contain a valid non-root actual-caller "
            "UID, so no repository command ran. Run the request from a non-root local "
            "developer account with a fresh operation ID; this is not a project source defect."
        )
    if code == "execution_identity_unavailable":
        return (
            "Coordinator could not resolve the actual caller account or its local groups "
            "before starting the unit, so no repository command ran. Repair the host account "
            "lookup, then submit a fresh operation ID; this is not a project source defect."
        )
    if code == "temporary_service_execution_identity_unavailable":
        return (
            "Coordinator could not recover the original non-root caller identity from the "
            "temporary-service operation, so no repository command ran. Repair the Coordinator "
            "operation or repository state, then submit a fresh operation ID; this is not a "
            "project source defect."
        )
    if code == "temporary_service_execution_identity_mismatch":
        return (
            "Coordinator could not prove that the launched process used the actual caller UID "
            "and already stopped the exact unit. Repair the Coordinator launch identity or "
            "process-observation path, then submit a fresh operation ID; this is not a project "
            "source defect."
        )
    if code == "temporary_service_launch_failed":
        return (
            "The bounded systemd unit could not start. Use the returned launch "
            "diagnostic to fix the missing executable, dependency, or command error, "
            "then submit a new operation ID."
        )
    if code == "temporary_service_exited":
        return (
            "The command exited before it opened the requested port. Fix the startup "
            "error shown in the bounded launch diagnostic, then submit a new operation ID."
        )
    if code == "temporary_service_readiness_timeout":
        return (
            "The command stayed alive but did not own the requested port before the "
            "readiness deadline. Verify its host and port arguments, or increase "
            "--launch-timeout-seconds when startup is genuinely slower, then submit a new operation ID."
        )
    if code in {"cwd_escape", "cwd_invalid", "cwd_unavailable"}:
        return "Choose an existing repository-relative working directory and resubmit."
    if code in {"shell_forbidden", "argv_invalid", "argv_required"}:
        return "Pass the executable and each argument separately after `--`; do not invoke a shell."
    if continuation is not None and outcome == "uncertain":
        return (
            "The mutation outcome is not proven. Follow this exact operation handle; "
            "do not create a replacement operation or launch the service directly."
        )
    if continuation is not None and phase == "repository_adoption":
        return (
            "Repository adoption did not complete. Follow this exact operation for "
            "the retained broker evidence, correct the reported condition, then issue "
            "a fresh runtime serve operation; do not bypass Coordinator or edit configuration files."
        )
    if broker_contacted is None:
        return (
            "Broker contact is uncertain. Retry only an idempotent read, or recover the "
            "exact mutation operation before deciding whether to submit another."
        )
    if broker_contacted is False:
        return "No broker request was proven; correct the reported local precondition and retry."
    return "Correct the reported condition, then retry the same intent through Coordinator."


def _failure(
    error: BaseException,
    *,
    mutation_attempted: bool = False,
    operation_id_hint: str | None = None,
    broker_contacted: bool | None = False,
    observed_mutation: bool | None = False,
    project_hint: str | None = None,
) -> dict[str, Any]:
    code = getattr(error, "code", None)
    if not isinstance(code, str) or not code:
        code = "transport_failure" if isinstance(error, OSError) else "agent_client_failed"
    classification = _error_classification(error, code)
    phase = getattr(error, "phase", None)
    if not isinstance(phase, str) or not phase:
        if code in {
            "execution_identity_invalid",
            "execution_identity_unavailable",
            "temporary_service_execution_identity_unavailable",
            "temporary_service_execution_identity_mismatch",
            "temporary_service_launch_failed",
            "temporary_service_exited",
            "temporary_service_readiness_timeout",
        }:
            phase = "launch"
        else:
            phase = (
                "client"
                if isinstance(error, (AgentCliError, AgentContractError, ValueError))
                else "transport"
                if classification in {"transport_failure", "broker_unavailable"}
                else "authority"
            )
    uncertain_codes = {
        "operation_outcome_uncertain",
        "invalid_reply",
        "transport_failure",
        "request_timeout",
        "empty_reply",
        "incomplete_reply",
    }
    attention_codes = {
        "operation_in_progress",
        "maintenance_in_progress",
        "unclassified_resource",
    }
    evidence = getattr(error, "evidence", None)
    if not isinstance(evidence, Mapping):
        candidates = getattr(error, "candidates", None)
        if isinstance(candidates, Sequence) and not isinstance(
            candidates, (str, bytes, bytearray)
        ):
            visible: list[dict[str, Any]] = []
            for candidate in candidates[:4]:
                if not isinstance(candidate, Mapping):
                    continue
                visible.append(
                    {
                        key: candidate[key]
                        for key in ("kind", "id", "name", "state")
                        if isinstance(candidate.get(key), (str, bool, int))
                    }
                )
            evidence = {
                "candidates": visible,
                "candidates_truncated": len(candidates) > len(visible),
            }
    outcome = (
        "uncertain"
        if mutation_attempted and code in uncertain_codes
        else "attention_required" if code in attention_codes else "certain"
    )
    operation_id = None
    if mutation_attempted:
        candidate = getattr(error, "operation_id", None)
        operation_id = candidate if isinstance(candidate, str) else operation_id_hint
        if operation_id is not None:
            try:
                continuation_handle("operation", operation_id)
            except AgentContractError:
                operation_id = None
    continuation = None
    if operation_id is not None and (
        outcome != "certain"
        or (phase == "repository_adoption" and broker_contacted is True)
    ):
        continuation = continuation_handle("operation", operation_id)
    explicit_next_command = getattr(error, "next_command", None)
    if not isinstance(explicit_next_command, str) or not explicit_next_command:
        explicit_next_command = None
    serve_contract_codes = {
        "argv_invalid",
        "argv_required",
        "cwd_escape",
        "cwd_invalid",
        "cwd_unavailable",
        "kill_after_run_invalid",
        "kill_after_run_required",
        "launch_timeout_invalid",
        "port_invalid",
        "repository_unconfigured",
        "serve_definition_incomplete",
        "serve_option_forbidden",
        "serve_purpose_invalid",
        "service_name_invalid",
        "shell_forbidden",
        "ttl_invalid",
        "ttl_required",
    }
    repository_adoption_codes = _REPOSITORY_ADOPTION_FAILURE_CODES
    next_command = (
        explicit_next_command
        if explicit_next_command is not None
        else _operation_follow_command(continuation, project=project_hint)
        if continuation is not None
        else "devcoordinator runtime serve --help"
        if code in serve_contract_codes or code in repository_adoption_codes
        else "devcoordinator --help"
        if code == "invalid_arguments"
        else "devcoordinator targets"
        if code in {"target_not_found", "target_ambiguous"}
        else "devcoordinator capabilities"
        if code.startswith("capability_") or code.endswith("_unsupported")
        else None
    )
    next_action = _next_action_for_failure(
        code=code,
        broker_contacted=broker_contacted,
        continuation=continuation,
        outcome=outcome,
        phase=phase,
    )
    decision_evidence = dict(evidence) if isinstance(evidence, Mapping) else {}
    if code == "repository_unconfigured":
        decision_evidence.update(
            {
                "discovery_is_pure": True,
                "adoption_trigger": "devcoordinator runtime serve",
            }
        )
    document = agent_error_result(
        code=code,
        message=str(error),
        classification=classification,
        phase=phase,
        operation_id=operation_id,
        continuation=continuation,
        broker_contacted=broker_contacted,
        mutation_performed=(
            True
            if observed_mutation is True
            else None
            if outcome != "certain"
            else observed_mutation
        ),
        outcome=outcome,
        retryable=code
        in {"maintenance_in_progress", "broker_busy", "server_busy", "request_timeout"},
        retry_after_seconds=getattr(error, "retry_after_seconds", None),
        next_command=next_command,
        next_action=next_action,
        evidence=decision_evidence or None,
    )
    document["stage"] = phase
    document["action"] = (
        "run_start_like_repository_adoption"
        if code == "repository_unconfigured"
        else "follow_operation"
        if continuation is not None
        else "run_next_command"
        if next_command is not None
        else "inspect_error"
    )
    return require_agent_result(document, surface="agent error")


def _emit(document: Mapping[str, Any], *, stream: Any) -> None:
    encoded = canonical_json_bytes(document)
    if len(encoded) + 1 > MAX_AGENT_RESULT_BYTES:
        raise AgentContractError(
            "final serialized output exceeds the 8192-byte agent contract"
        )
    stream.buffer.write(encoded + b"\n")
    stream.flush()


def main(argv: Sequence[str] | None = None) -> int:
    started = time.monotonic()
    call_id = str(uuid.uuid4())
    raw_arguments = list(argv) if argv is not None else sys.argv[1:]
    bug_command = raw_arguments[:1] == ["bug"]
    journal: Any = None
    event_record: Any = None
    diagnostic_for_exception: Any = None
    namespace: argparse.Namespace | None = None
    result: dict[str, Any] | None = None
    failure: BaseException | None = None
    execution_state = {
        "broker_contacted": False,
        "mutation_performed": False,
    }

    if not bug_command:
        try:
            from .call_journal import (
                configured_call_journal,
                diagnostic_for_exception as journal_diagnostic,
                event_record as build_event_record,
            )

            journal = configured_call_journal()
            event_record = build_event_record
            diagnostic_for_exception = journal_diagnostic
        except BaseException:
            journal = None

    def record(phase: str, outcome: str, *, error: BaseException | None = None) -> None:
        if journal is None or event_record is None:
            return
        command = getattr(namespace, "command", None)
        action = getattr(namespace, "action", None)
        if action is None:
            action = getattr(namespace, "test_action", None)
        if action is None:
            action = getattr(namespace, "bug_action", None)
        operation = "agent.unknown"
        if isinstance(command, str):
            operation = f"agent.{command}"
            if isinstance(action, str):
                operation += f".{action}"
        code = getattr(error, "code", None) if error is not None else None
        error_operation_id = (
            getattr(error, "operation_id", None) if error is not None else None
        )
        if not isinstance(error_operation_id, str):
            error_operation_id = None
        diagnostic = (
            diagnostic_for_exception(error, stage="agent_client")
            if error is not None and diagnostic_for_exception is not None
            else None
        )
        try:
            journal.record(
                event_record(
                    boundary="agent_cli",
                    phase=phase,
                    call_id=call_id,
                    operation=operation,
                    operation_id=(
                        error_operation_id
                        or (
                            getattr(namespace, "operation_id", None)
                            if namespace is not None
                            else None
                        )
                    ),
                    duration_seconds=(
                        None if phase == "received" else time.monotonic() - started
                    ),
                    outcome=outcome,
                    code=code if isinstance(code, str) else None,
                    message=str(error) if error is not None else None,
                    diagnostic=diagnostic,
                )
            )
        except BaseException:
            return

    try:
        structured_argv: list[str] = []
        if raw_arguments[:2] in (["runtime", "serve"], ["runtime", "replace"]):
            try:
                separator = raw_arguments.index("--", 3)
            except ValueError:
                separator = -1
            if separator >= 0:
                structured_argv = raw_arguments[separator + 1 :]
                raw_arguments = raw_arguments[:separator]
        try:
            namespace = _parser().parse_args(raw_arguments)
        except AgentCliError as error:
            if raw_arguments[:2] in (["runtime", "serve"], ["runtime", "replace"]):
                error.next_command = f"devcoordinator runtime {raw_arguments[1]} --help"
                namespace = argparse.Namespace(
                    command="runtime",
                    action="serve",
                    operation_id=None,
                )
                record("received", "received")
            raise
        if namespace.command == "runtime":
            namespace.argv = structured_argv
        if namespace.command == "runtime":
            namespace.operation_id = _canonical_operation_id(
                namespace.operation_id,
                mutate=namespace.action not in {"status", "capture_logs"},
            )
        elif namespace.command == "storage" and namespace.action in {
            "remove",
            "plan",
            "apply",
        }:
            namespace.operation_id = _canonical_operation_id(
                namespace.operation_id, mutate=True
            )
        elif namespace.command == "test" and namespace.test_action in {
            "cancel",
            "enqueue",
            "retry",
            "submit",
        }:
            namespace.operation_id = _canonical_operation_id(
                namespace.operation_id, mutate=True
            )
        # Record the generated mutation identity before repository discovery or
        # broker transport.  A caller can therefore recover a lost reply from
        # the bounded journal without inventing or guessing an operation ID.
        record("received", "received")
        if namespace.command == "runtime" and namespace.action == "serve":
            _validate_runtime_serve_namespace(namespace)
        result = _execute(namespace, execution_state=execution_state)
    except SystemExit as error:
        record("received", "received")
        record(
            "completed",
            "ok" if error.code == 0 else "rejected",
            error=None if error.code == 0 else error,
        )
        raise
    except BaseException as error:
        failure = error
        try:
            _emit(
                _failure(
                    error,
                    mutation_attempted=_command_mutates(namespace),
                    operation_id_hint=(
                        getattr(namespace, "operation_id", None)
                        if namespace is not None
                        else None
                    ),
                    broker_contacted=execution_state["broker_contacted"],
                    observed_mutation=execution_state["mutation_performed"],
                    project_hint=(
                        getattr(namespace, "_resolved_project", None)
                        or getattr(namespace, "project", None)
                        if namespace is not None
                        else None
                    ),
                ),
                stream=sys.stdout,
            )
        except BaseException as serialization_error:
            fallback = agent_error_result(
                code="agent_error_serialization_failed",
                message=bounded_text(serialization_error),
                classification="client_contract_failure",
                phase="serialization",
            )
            _emit(fallback, stream=sys.stdout)
        record("completed", "failed", error=failure)
        return 1
    assert result is not None
    _emit(result, stream=sys.stdout)
    succeeded = result.get("ok") is True
    record("completed", "ok" if succeeded else "failed")
    return 0 if succeeded else 1


if __name__ == "__main__":
    raise SystemExit(main())
