#!/usr/bin/env python3
"""Verify installed Codex discovery and immutable Coordinator test access."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from typing import Callable, Mapping, Sequence
import uuid


CODEX_ROOT = Path("/etc/codex")
RULE_ROOT = CODEX_ROOT / "rules"
RULE = RULE_ROOT / "devcoordinator-test.rules"
LAUNCHER = Path("/usr/local/bin/devcoordinator-test")
RUNNER_PROBE_TARGET = "software-delivery-runner-probe"
MAX_EXECUTION_TIMEOUT_SECONDS = 86_400
MAX_LAUNCH_TIMEOUT_SECONDS = 3_600
MAX_WAIT_TIMEOUT_SECONDS = 86_400


class VerificationError(RuntimeError):
    """Installed Codex test access does not satisfy its public contract."""


def regular(path: Path, mode: int) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise VerificationError(f"installed access artifact is not a regular file: {path}")
    if stat.S_IMODE(info.st_mode) != mode:
        raise VerificationError(f"installed access artifact has the wrong mode: {path}")


def directory(path: Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise VerificationError(f"Codex policy path is not a real directory: {path}")
    if stat.S_IMODE(info.st_mode) != 0o755:
        raise VerificationError(f"Codex policy directory is not readable: {path}")


def run(
    argv: Sequence[str],
    label: str,
    *,
    timeout_seconds: int | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise VerificationError(
            f"{label} exceeded its caller-defined {timeout_seconds}s deadline"
        ) from error
    if completed.returncode != 0:
        detail = (completed.stderr.strip() or completed.stdout.strip())[-1000:]
        raise VerificationError(f"{label} failed" + (f": {detail}" if detail else ""))
    return completed


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


def json_object(
    completed: subprocess.CompletedProcess[str], *, label: str
) -> dict[str, object]:
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise VerificationError(f"{label} returned invalid JSON") from error
    if not isinstance(value, Mapping) or value.get("ok") is not True:
        raise VerificationError(f"{label} did not return a ready result")
    return dict(value)


def timeout_argument(raw: str, *, label: str, maximum: int) -> int:
    try:
        value = int(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"{label} must be an integer") from error
    if not 1 <= value <= maximum:
        raise argparse.ArgumentTypeError(
            f"{label} must be from 1 through {maximum} seconds"
        )
    return value


def _non_negative_number(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and value >= 0
    )


def _selected_target_count(plan: Mapping[str, object]) -> int:
    """Normalize the full and compact public plan selection shapes."""

    has_count = "selected_target_count" in plan
    has_targets = "selected_targets" in plan
    if not has_count and not has_targets:
        raise VerificationError("test plan omitted its selected targets")

    count: int | None = None
    if has_count:
        raw_count = plan.get("selected_target_count")
        if isinstance(raw_count, bool) or not isinstance(raw_count, int):
            raise VerificationError("test plan selected target count is invalid")
        count = raw_count

    targets: list[object] | None = None
    if has_targets:
        raw_targets = plan.get("selected_targets")
        if (
            not isinstance(raw_targets, list)
            or any(
                not isinstance(target, str) or not target
                for target in raw_targets
            )
            or len(set(raw_targets)) != len(raw_targets)
        ):
            raise VerificationError("test plan selected targets are invalid")
        targets = raw_targets

    truncated = plan.get("truncated")
    targets_truncated = (
        isinstance(truncated, Mapping) and truncated.get("targets") is True
    )
    if count is not None and targets is not None:
        if targets_truncated:
            if len(targets) >= count:
                raise VerificationError(
                    "test plan selected target summary is contradictory"
                )
        elif len(targets) != count:
            raise VerificationError(
                "test plan selected target summary is contradictory"
            )
    elif targets_truncated:
        raise VerificationError(
            "test plan truncated selected targets without a complete count"
        )

    selected = count if count is not None else len(targets or ())
    if selected < 1:
        raise VerificationError("test plan selected no targets")
    return selected


def _governed_failure_detail(
    *,
    launcher: Path,
    repository_id: str,
    run_id: str,
    waited: Mapping[str, object],
    command_runner: CommandRunner,
) -> str:
    """Return one bounded, actionable terminal diagnostic without masking it."""

    parts = [f"run_id={run_id}"]
    classification = waited.get("failure_classification") or waited.get("conclusion")
    if isinstance(classification, str) and classification:
        parts.append(f"classification={classification}")
    try:
        page = json_object(
            command_runner(
                [
                    str(launcher),
                    "failures",
                    "--repository-id",
                    repository_id,
                    "--run-id",
                    run_id,
                    "--limit",
                    "1",
                ],
                "governed runner failures",
            ),
            label="governed runner failures",
        )
        failures = page.get("failures")
        if (
            isinstance(failures, list)
            and failures
            and isinstance(failures[0], Mapping)
        ):
            first = failures[0]
            location = first.get("location")
            message = first.get("message")
            if isinstance(location, str) and location:
                parts.append(f"location={location}")
            if isinstance(message, str) and message:
                parts.append("message=" + " ".join(message.split())[:700])
    except (OSError, ValueError, VerificationError):
        # The original terminal state is still authoritative. Failure-detail
        # retrieval is best-effort and must never replace or hide it.
        pass
    return "; ".join(parts)[:1000]


def exercise_cross_account_live_plan(
    root_repo: Path,
    *,
    execution_timeout_seconds: int,
    launch_timeout_seconds: int,
    launcher: Path = LAUNCHER,
    command_runner: CommandRunner = run,
    verification_uid: int | None = None,
) -> dict[str, object]:
    """Prove the installed plane can inspect and register a live foreign repo."""

    for value, label, maximum in (
        (
            execution_timeout_seconds,
            "execution timeout",
            MAX_EXECUTION_TIMEOUT_SECONDS,
        ),
        (launch_timeout_seconds, "launch timeout", MAX_LAUNCH_TIMEOUT_SECONDS),
    ):
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1 <= value <= maximum
        ):
            raise VerificationError(
                f"{label} must be from 1 through {maximum} seconds"
            )
    resolved = root_repo.resolve(strict=True)
    owner_uid = resolved.stat().st_uid
    verifier_uid = os.geteuid() if verification_uid is None else verification_uid
    if owner_uid == verifier_uid:
        raise VerificationError(
            "live-plan exercise is not cross-account: repository and verifier share a UID"
        )

    planned = json_object(
        command_runner(
            [
                str(launcher),
                "plan",
                "--agent",
                "software-owned-delivery",
                "--root-repo",
                str(resolved),
                "--no-temporary-repo",
                "--intent",
                "change",
                "--execution-timeout-seconds",
                str(execution_timeout_seconds),
                "--launch-timeout-seconds",
                str(launch_timeout_seconds),
                "--full",
                "--operation-id",
                str(uuid.uuid4()),
            ],
            "cross-account live test plan",
        ),
        label="cross-account live test plan",
    )
    plan = planned.get("plan")
    submission = planned.get("submission")
    if not isinstance(plan, Mapping):
        raise VerificationError("cross-account live plan omitted its plan document")
    source = plan.get("source")
    selected_target_count = _selected_target_count(plan)
    plan_id = plan.get("plan_id")
    if (
        not isinstance(source, Mapping)
        or source.get("mode") != "live"
        or not isinstance(plan_id, str)
        or not plan_id
        or not isinstance(submission, Mapping)
        or submission.get("available") is not True
    ):
        raise VerificationError(
            "cross-account live plan was not selectable and runnable"
        )
    registration = submission.get("registration")
    newly_registered = (
        registration.get("registered")
        if isinstance(registration, Mapping)
        else None
    )
    if (
        not isinstance(registration, Mapping)
        or not isinstance(newly_registered, bool)
        or registration.get("plan_id") != plan_id
    ):
        raise VerificationError("cross-account live plan was not durably registered")
    return {
        "plan_id": plan_id,
        "selected_target_count": selected_target_count,
        "repository_owner_uid": owner_uid,
        "verification_uid": verifier_uid,
        "source_mode": "live",
        "newly_registered": newly_registered,
        "submitted": False,
    }


def exercise_governed_runner(
    root_repo: Path,
    *,
    execution_timeout_seconds: int,
    launch_timeout_seconds: int,
    wait_timeout_seconds: int,
    launcher: Path = LAUNCHER,
    command_runner: CommandRunner = run,
    verification_uid: int | None = None,
) -> dict[str, object]:
    """Prove one immutable target launches and reports evidence as repo owner."""

    for value, label, maximum in (
        (
            execution_timeout_seconds,
            "execution timeout",
            MAX_EXECUTION_TIMEOUT_SECONDS,
        ),
        (launch_timeout_seconds, "launch timeout", MAX_LAUNCH_TIMEOUT_SECONDS),
        (wait_timeout_seconds, "wait timeout", MAX_WAIT_TIMEOUT_SECONDS),
    ):
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1 <= value <= maximum
        ):
            raise VerificationError(
                f"{label} must be from 1 through {maximum} seconds"
            )
    resolved = root_repo.resolve(strict=True)
    owner_uid = resolved.stat().st_uid
    verifier_uid = os.geteuid() if verification_uid is None else verification_uid
    if owner_uid == verifier_uid:
        raise VerificationError(
            "runner exercise is not cross-account: repository and verifier share a UID"
        )

    plan_operation_id = str(uuid.uuid4())
    plan = json_object(
        command_runner(
            [
                str(launcher),
                "plan",
                "--agent",
                "software-owned-delivery",
                "--root-repo",
                str(resolved),
                "--no-temporary-repo",
                "--intent",
                "manual",
                "--target",
                RUNNER_PROBE_TARGET,
                "--execution-timeout-seconds",
                str(execution_timeout_seconds),
                "--launch-timeout-seconds",
                str(launch_timeout_seconds),
                "--operation-id",
                plan_operation_id,
            ],
            "governed runner plan",
        ),
        label="governed runner plan",
    )
    plan_document = plan.get("plan")
    submission = plan.get("submission")
    if (
        not isinstance(plan_document, Mapping)
        or plan_document.get("selected_target_count") != 1
        or plan_document.get("selected_targets") != [RUNNER_PROBE_TARGET]
        or not isinstance(submission, Mapping)
        or submission.get("available") is not True
    ):
        raise VerificationError(
            "governed runner plan did not select exactly the delivery probe"
        )
    registration = submission.get("registration")
    plan_id = plan_document.get("plan_id")
    repository_id = plan_document.get("repository_id")
    if not isinstance(repository_id, str) or not repository_id:
        raise VerificationError("governed runner plan omitted its repository ID")
    newly_registered = (
        registration.get("registered")
        if isinstance(registration, Mapping)
        else None
    )
    if (
        not isinstance(plan_id, str)
        or not plan_id
        or not isinstance(registration, Mapping)
        or not isinstance(newly_registered, bool)
        or registration.get("plan_id") != plan_id
    ):
        raise VerificationError("governed runner plan was not durably registered")

    submitted = json_object(
        command_runner(
            [
                str(launcher),
                "submit",
                "--plan-id",
                plan_id,
                "--repository-id",
                repository_id,
                "--operation-id",
                str(uuid.uuid4()),
            ],
            "governed runner submission",
        ),
        label="governed runner submission",
    )
    run_id = submitted.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise VerificationError("governed runner submission omitted its run ID")

    waited = json_object(
        command_runner(
            [
                str(launcher),
                "wait",
                "--repository-id",
                repository_id,
                "--run-id",
                run_id,
                "--timeout-seconds",
                str(wait_timeout_seconds),
            ],
            "governed runner wait",
        ),
        label="governed runner wait",
    )
    if waited.get("wait_timed_out") is True:
        raise VerificationError(
            f"governed runner did not finish within the caller-defined "
            f"{wait_timeout_seconds}s wait deadline"
        )
    if waited.get("run_id") != run_id or waited.get("state") != "succeeded":
        raise VerificationError(
            "governed runner wait returned a non-success terminal state: "
            + _governed_failure_detail(
                launcher=launcher,
                repository_id=repository_id,
                run_id=run_id,
                waited=waited,
                command_runner=command_runner,
            )
        )

    status = json_object(
        command_runner(
            [
                str(launcher),
                "status",
                "--repository-id",
                repository_id,
                "--run-id",
                run_id,
            ],
            "governed runner status",
        ),
        label="governed runner status",
    )
    if status.get("run_id") != run_id or status.get("state") != "succeeded":
        detail = status.get("failure_classification") or status.get("conclusion")
        raise VerificationError(
            "governed runner did not succeed"
            + (f": {detail}" if isinstance(detail, str) and detail else "")
        )
    if status.get("source_mode") != "immutable":
        raise VerificationError("governed runner did not use an immutable source")
    targets = status.get("targets")
    if (
        not isinstance(targets, list)
        or len(targets) != 1
        or not isinstance(targets[0], Mapping)
        or targets[0].get("target_name") != RUNNER_PROBE_TARGET
        or targets[0].get("state") != "succeeded"
    ):
        raise VerificationError("governed runner status contradicted its probe target")
    usage = status.get("usage")
    if (
        not isinstance(usage, Mapping)
        or usage.get("available") is not True
        or not isinstance(usage.get("measured_attempts"), int)
        or int(usage["measured_attempts"]) < 1
        or not isinstance(usage.get("total_attempts"), int)
        or int(usage["total_attempts"]) < 1
        or not (
            _non_negative_number(usage.get("peak_memory_mib"))
            or _non_negative_number(usage.get("cpu_seconds"))
        )
    ):
        raise VerificationError("governed runner omitted measured CPU/memory usage")

    summary = json_object(
        command_runner(
            [
                str(launcher),
                "summary",
                "--repository-id",
                repository_id,
                "--run-id",
                run_id,
            ],
            "governed runner summary",
        ),
        label="governed runner summary",
    )
    counts = summary.get("counts")
    source = summary.get("source")
    artifact_count = summary.get("artifact_count")
    if (
        summary.get("run_id") != run_id
        or summary.get("conclusion") != "succeeded"
        or not isinstance(source, Mapping)
        or source.get("mode") != "immutable"
        or not isinstance(counts, Mapping)
        or not isinstance(counts.get("attempts"), int)
        or int(counts["attempts"]) < 1
        or not isinstance(counts.get("passed"), int)
        or int(counts["passed"]) < 1
        or counts.get("failed") != 0
        or counts.get("errors") != 0
        or summary.get("failure_count", 0) != 0
        or not isinstance(artifact_count, int)
        or artifact_count < 1
    ):
        raise VerificationError(
            "governed runner summary omitted passing case or artifact evidence"
        )

    return {
        "plan_id": plan_id,
        "run_id": run_id,
        "verification_uid": verifier_uid,
        "repository_owner_uid": owner_uid,
        "target": RUNNER_PROBE_TARGET,
        "newly_registered": newly_registered,
        "passed_cases": counts["passed"],
        "artifact_count": artifact_count,
        "usage": dict(usage),
        "timeouts": {
            "execution_seconds": execution_timeout_seconds,
            "launch_seconds": launch_timeout_seconds,
            "wait_seconds": wait_timeout_seconds,
        },
    }


def execpolicy_decision(codex: str, command: Sequence[str]) -> str | None:
    completed = run(
        [codex, "execpolicy", "check", "--rules", str(RULE), "--", *command],
        "Codex execution-policy check",
    )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise VerificationError("Codex execution-policy check returned invalid JSON") from error
    if not isinstance(value, dict):
        raise VerificationError("Codex execution-policy result is not an object")
    decision = value.get("decision")
    return decision if isinstance(decision, str) else None


def verify(
    root_repo: Path,
    *,
    exercise_runner: bool = False,
    execution_timeout_seconds: int | None = None,
    launch_timeout_seconds: int | None = None,
    wait_timeout_seconds: int | None = None,
) -> dict[str, object]:
    directory(CODEX_ROOT)
    directory(RULE_ROOT)
    regular(RULE, 0o644)
    regular(LAUNCHER, 0o755)
    with RULE.open("rb") as handle:
        if not handle.read(1):
            raise VerificationError("Codex execution-policy file is empty")
    codex = shutil.which("codex")
    if codex is None:
        raise VerificationError("Codex executable is unavailable to the agent account")
    if (
        execpolicy_decision(codex, ["devcoordinator-test", "submit", "--plan-id", "example"])
        != "allow"
    ):
        raise VerificationError("test submission is not allowed without a prompt")
    if execpolicy_decision(codex, ["devcoordinator-test", "manifest", "init"]) is not None:
        raise VerificationError("manifest authoring unexpectedly bypasses approval")
    if (
        execpolicy_decision(
            codex,
            [
                "python3",
                "skills/codex-dev-coordinator/scripts/dev_coordinator.py",
                "test",
                "submit",
            ],
        )
        is not None
    ):
        raise VerificationError("mutable source execution unexpectedly bypasses approval")
    catalog = run(
        [str(LAUNCHER), "catalog", "--root-repo", str(root_repo.resolve(strict=True))],
        "immutable test launcher catalog",
    )
    catalog_value = json_object(catalog, label="immutable test launcher catalog")
    result: dict[str, object] = {
        "ok": True,
        "verification_uid": os.geteuid(),
        "rule": str(RULE),
        "launcher": str(LAUNCHER),
        "root_repo": str(root_repo.resolve(strict=True)),
        "catalog_status": catalog_value.get("status"),
    }
    if exercise_runner:
        if (
            execution_timeout_seconds is None
            or launch_timeout_seconds is None
            or wait_timeout_seconds is None
        ):
            raise VerificationError(
                "runner exercise requires caller-defined execution, launch, and wait timeouts"
            )
        result["live_plan_probe"] = exercise_cross_account_live_plan(
            root_repo,
            execution_timeout_seconds=execution_timeout_seconds,
            launch_timeout_seconds=launch_timeout_seconds,
        )
        result["runner_probe"] = exercise_governed_runner(
            root_repo,
            execution_timeout_seconds=execution_timeout_seconds,
            launch_timeout_seconds=launch_timeout_seconds,
            wait_timeout_seconds=wait_timeout_seconds,
        )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root-repo", type=Path, required=True)
    parser.add_argument("--exercise-runner", action="store_true")
    parser.add_argument(
        "--execution-timeout-seconds",
        type=lambda raw: timeout_argument(
            raw, label="execution timeout", maximum=MAX_EXECUTION_TIMEOUT_SECONDS
        ),
    )
    parser.add_argument(
        "--launch-timeout-seconds",
        type=lambda raw: timeout_argument(
            raw, label="launch timeout", maximum=MAX_LAUNCH_TIMEOUT_SECONDS
        ),
    )
    parser.add_argument(
        "--wait-timeout-seconds",
        type=lambda raw: timeout_argument(
            raw, label="wait timeout", maximum=MAX_WAIT_TIMEOUT_SECONDS
        ),
    )
    args = parser.parse_args(argv)
    try:
        value = verify(
            args.root_repo,
            exercise_runner=args.exercise_runner,
            execution_timeout_seconds=args.execution_timeout_seconds,
            launch_timeout_seconds=args.launch_timeout_seconds,
            wait_timeout_seconds=args.wait_timeout_seconds,
        )
    except (OSError, ValueError, VerificationError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
