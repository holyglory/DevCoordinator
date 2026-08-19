#!/usr/bin/env python3
"""Fast, software-owned DevCoordinator test, package, deploy, and acceptance.

The workflow composes existing repository and immutable-release commands.  It
does not implement another migration engine.  Routine ``same-schema`` delivery
executes one administrator-authored command plan with an exact rollback path
and mandatory control-plane health probes.  The destructive clean-adoption
path is available only through the explicit ``reset`` mode.

Every subprocess receives its own stdout/stderr files.  Durable JSONL events,
state, and a compact report let one invocation collect all non-safety failures
instead of turning each small finding into another manual deploy cycle.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = ROOT / "skills/codex-dev-coordinator/scripts"
if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

from devcoordinator.repository_context import (  # noqa: E402
    RepositoryContextError,
    resolve_effective_repository_context,
)


SCHEMA_VERSION = 2
PLAN_KIND = "devcoordinator-software-delivery-plan"
STATE_KIND = "devcoordinator-software-delivery-state"
REPORT_KIND = "devcoordinator-software-delivery-report"
RELEASE_RE = re.compile(r"^[0-9a-f]{64}$")
TOKEN_RE = re.compile(
    r"\{(repo|canonical_repo|run_root|release|release_digest|transaction_root|caller_uid|caller_gid|"
    r"acceptance_execution_timeout_seconds|"
    r"acceptance_launch_timeout_seconds|acceptance_wait_timeout_seconds)\}"
)
MAX_EXECUTION_TIMEOUT_SECONDS = 86_400
MAX_LAUNCH_TIMEOUT_SECONDS = 3_600
MAX_WAIT_TIMEOUT_SECONDS = 86_400


class DeliveryError(RuntimeError):
    """A workflow contract or safety boundary failed."""


@contextmanager
def exclusive_run_root(run_root: Path):
    """Prevent two delivery controllers from mutating one durable run journal."""

    absolute = run_root.expanduser().absolute()
    absolute.mkdir(parents=True, exist_ok=True)
    lock_path = absolute / "delivery.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise DeliveryError(
                "another software-owned delivery is active for this run root; "
                "wait for its durable report instead of starting a second controller"
            ) from error
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _timeout_value(value: object, *, name: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise DeliveryError(f"{name} must be from 1 through {maximum} seconds")
    return value


def _timeout_argument(raw: str, *, name: str, maximum: int) -> int:
    try:
        value = int(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"{name} must be an integer") from error
    if not 1 <= value <= maximum:
        raise argparse.ArgumentTypeError(
            f"{name} must be from 1 through {maximum} seconds"
        )
    return value


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DeliveryError(f"cannot read JSON document {path}: {error}") from error


def step_from(value: object, *, default_blocking: bool) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) - {"name", "argv", "blocking"}:
        raise DeliveryError("delivery command step fields are invalid")
    name = value.get("name")
    argv = value.get("argv")
    if (
        not isinstance(name, str)
        or not name
        or len(name) > 96
        or not isinstance(argv, list)
        or not argv
        or len(argv) > 128
        or any(not isinstance(item, str) or not item for item in argv)
    ):
        raise DeliveryError("delivery command step is invalid")
    blocking = value.get("blocking", default_blocking)
    if not isinstance(blocking, bool):
        raise DeliveryError("delivery command blocking flag is invalid")
    return {"name": name, "argv": list(argv), "blocking": blocking}


def validate_plan(value: object) -> dict[str, object]:
    fields = {
        "schema_version",
        "kind",
        "source_checks",
        "same_schema",
        "acceptance_setup",
        "acceptance",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise DeliveryError("software delivery plan fields are invalid")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("kind") != PLAN_KIND:
        raise DeliveryError("software delivery plan discriminator is invalid")
    source = value.get("source_checks")
    acceptance_setup = value.get("acceptance_setup")
    acceptance = value.get("acceptance")
    same = value.get("same_schema")
    if (
        not isinstance(source, list)
        or not isinstance(acceptance_setup, list)
        or not isinstance(acceptance, list)
    ):
        raise DeliveryError("software delivery command lists are invalid")
    if not isinstance(same, Mapping) or set(same) != {
        "prepare",
        "apply",
        "rollback",
        "health",
    }:
        raise DeliveryError("same-schema delivery fields are invalid")
    normalized_same: dict[str, list[dict[str, object]]] = {}
    for field in ("prepare", "apply", "rollback", "health"):
        raw = same.get(field)
        if not isinstance(raw, list):
            raise DeliveryError(f"same-schema {field} commands are invalid")
        normalized_same[field] = [
            step_from(item, default_blocking=True) for item in raw
        ]
    if not normalized_same["apply"] or not normalized_same["rollback"]:
        raise DeliveryError("same-schema delivery requires apply and rollback commands")
    if not normalized_same["health"]:
        raise DeliveryError("same-schema delivery requires a control-plane health command")
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": PLAN_KIND,
        "source_checks": [
            step_from(item, default_blocking=True) for item in source
        ],
        "acceptance_setup": [
            step_from(item, default_blocking=True) for item in acceptance_setup
        ],
        "same_schema": normalized_same,
        "acceptance": [
            step_from(item, default_blocking=False) for item in acceptance
        ],
    }


def load_plan(path: Path | None) -> dict[str, object]:
    if path is None:
        path = ROOT / "deploy/software-owned-delivery.json"
    return validate_plan(read_json(path))


def same_schema_steps(
    steps: Sequence[Mapping[str, object]], *, reset_test_history: bool
) -> list[dict[str, object]]:
    normalized: list[dict[str, object]] = []
    switch_count = 0
    for step in steps:
        copied = dict(step)
        raw_argv = step.get("argv")
        if not isinstance(raw_argv, list):
            raise DeliveryError("same-schema delivery step is invalid")
        argv = list(raw_argv)
        is_switch = any(
            Path(value).name == "devcoordinator-same-schema-switch"
            for value in argv
            if isinstance(value, str)
        )
        if is_switch:
            switch_count += 1
            if reset_test_history:
                if "--reset-test-history" in argv:
                    raise DeliveryError(
                        "same-schema plan must not hard-code test-history reset"
                    )
                argv.append("--reset-test-history")
        copied["argv"] = argv
        normalized.append(copied)
    if reset_test_history and switch_count != 1:
        raise DeliveryError(
            "test-history reset requires exactly one same-schema switch per phase"
        )
    return normalized


@dataclass(frozen=True)
class CommandResult:
    name: str
    phase: str
    returncode: int
    blocking: bool
    stdout: str
    stderr: str
    duration_ms: int
    parsed: object | None

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class SubprocessExecutor:
    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        stdout: Path,
        stderr: Path,
    ) -> int:
        environment = dict(os.environ)
        environment.setdefault("PYTHONDONTWRITEBYTECODE", "1")
        with stdout.open("wb") as out, stderr.open("wb") as err:
            completed = subprocess.run(
                list(argv),
                cwd=str(cwd),
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                check=False,
            )
            out.flush()
            err.flush()
            os.fsync(out.fileno())
            os.fsync(err.fileno())
        return int(completed.returncode)


class Delivery:
    def __init__(
        self,
        *,
        repo: Path,
        run_root: Path,
        release_root: Path,
        transaction_root: Path,
        plan: Mapping[str, object],
        executor: Any | None = None,
        root_prefix: Sequence[str] | None = None,
        max_parallel: int = 4,
        acceptance_execution_timeout_seconds: int | None = None,
        acceptance_launch_timeout_seconds: int | None = None,
        acceptance_wait_timeout_seconds: int | None = None,
        canonical_repo: Path | None = None,
    ) -> None:
        self.repo = repo.expanduser().resolve()
        self.canonical_repo = (
            self.repo
            if canonical_repo is None
            else canonical_repo.expanduser().resolve()
        )
        self.run_root = run_root.expanduser().absolute()
        self.release_root = release_root.expanduser().absolute()
        self.transaction_root = transaction_root.expanduser().absolute()
        self.plan = dict(plan)
        self.executor = executor or SubprocessExecutor()
        self.root_prefix = list(
            root_prefix
            if root_prefix is not None
            else ([] if os.geteuid() == 0 else ["/usr/bin/sudo", "-n"])
        )
        self.max_parallel = max(1, min(int(max_parallel), 16))
        self.acceptance_execution_timeout_seconds = (
            None
            if acceptance_execution_timeout_seconds is None
            else _timeout_value(
                acceptance_execution_timeout_seconds,
                name="acceptance execution timeout",
                maximum=MAX_EXECUTION_TIMEOUT_SECONDS,
            )
        )
        self.acceptance_launch_timeout_seconds = (
            None
            if acceptance_launch_timeout_seconds is None
            else _timeout_value(
                acceptance_launch_timeout_seconds,
                name="acceptance launch timeout",
                maximum=MAX_LAUNCH_TIMEOUT_SECONDS,
            )
        )
        self.acceptance_wait_timeout_seconds = (
            None
            if acceptance_wait_timeout_seconds is None
            else _timeout_value(
                acceptance_wait_timeout_seconds,
                name="acceptance wait timeout",
                maximum=MAX_WAIT_TIMEOUT_SECONDS,
            )
        )
        self.run_root.mkdir(parents=True, exist_ok=True)
        self.logs = self.run_root / "logs"
        self.logs.mkdir(exist_ok=True)
        self.events_path = self.run_root / "events.jsonl"
        self.text_log_path = self.run_root / "delivery.log"
        self.state_path = self.run_root / "state.json"
        self.report_path = self.run_root / "report.json"
        self._lock = threading.Lock()
        state_value = read_json(self.state_path) if self.state_path.exists() else None
        if state_value is None:
            self.state: dict[str, object] = {
                "schema_version": SCHEMA_VERSION,
                "kind": STATE_KIND,
                "repo": str(self.repo),
                "run_root": str(self.run_root),
                "release_root": str(self.release_root),
                "transaction_root": str(self.transaction_root),
                "created_at": now(),
                "updated_at": now(),
                "steps": [],
                "release": None,
                "deployment": None,
            }
            self._save_state()
        elif not isinstance(state_value, Mapping):
            raise DeliveryError("delivery state is invalid")
        else:
            self.state = dict(state_value)
            expected = {
                "repo": str(self.repo),
                "run_root": str(self.run_root),
                "release_root": str(self.release_root),
                "transaction_root": str(self.transaction_root),
            }
            if any(self.state.get(key) != value for key, value in expected.items()):
                raise DeliveryError("delivery run root belongs to different inputs")
        raw_steps = self.state.get("steps", [])
        self._sequence = len(raw_steps) if isinstance(raw_steps, list) else 0

    def _save_state(self) -> None:
        self.state["updated_at"] = now()
        atomic_json(self.state_path, self.state)

    def _event(self, event: Mapping[str, object]) -> None:
        payload = {"at": now(), **dict(event)}
        line = json.dumps(payload, sort_keys=True) + "\n"
        message = f"{payload['at']} {payload.get('phase', '-')} {payload.get('name', '-')} {payload.get('status', '-')}\n"
        with self._lock:
            with self.events_path.open("a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
            with self.text_log_path.open("a", encoding="utf-8") as handle:
                handle.write(message)
                handle.flush()
                os.fsync(handle.fileno())

    def _tokens(self) -> dict[str, str]:
        release = self.state.get("release")
        release_path = ""
        release_digest = ""
        if isinstance(release, Mapping):
            release_path = str(release.get("path") or "")
            release_digest = str(release.get("digest") or "")
        release_transaction_root = self.transaction_root
        if RELEASE_RE.fullmatch(release_digest) is not None:
            release_transaction_root = self.transaction_root / release_digest
        return {
            "repo": str(self.repo),
            "canonical_repo": str(self.canonical_repo),
            "run_root": str(self.run_root),
            "release": release_path,
            "release_digest": release_digest,
            "transaction_root": str(release_transaction_root),
            "caller_uid": str(os.getuid()),
            "caller_gid": str(os.getgid()),
            "acceptance_execution_timeout_seconds": (
                ""
                if self.acceptance_execution_timeout_seconds is None
                else str(self.acceptance_execution_timeout_seconds)
            ),
            "acceptance_launch_timeout_seconds": (
                ""
                if self.acceptance_launch_timeout_seconds is None
                else str(self.acceptance_launch_timeout_seconds)
            ),
            "acceptance_wait_timeout_seconds": (
                ""
                if self.acceptance_wait_timeout_seconds is None
                else str(self.acceptance_wait_timeout_seconds)
            ),
        }

    def expand(self, argv: Sequence[str]) -> list[str]:
        tokens = self._tokens()

        def replace(match: re.Match[str]) -> str:
            value = tokens[match.group(1)]
            if not value:
                raise DeliveryError(f"command token {match.group(0)} is unavailable")
            return value

        return [TOKEN_RE.sub(replace, item) for item in argv]

    def run_step(
        self,
        *,
        phase: str,
        name: str,
        argv: Sequence[str],
        blocking: bool,
        root: bool = False,
    ) -> CommandResult:
        safe = re.sub(r"[^a-zA-Z0-9_.-]+", "-", name).strip("-") or "step"
        with self._lock:
            self._sequence += 1
            index = self._sequence
        prefix = f"{index:03d}-{phase}-{safe}"
        stdout = self.logs / f"{prefix}.stdout"
        stderr = self.logs / f"{prefix}.stderr"
        expanded = self.expand(argv)
        command = [*self.root_prefix, *expanded] if root else expanded
        self._event({"phase": phase, "name": name, "status": "started", "blocking": blocking})
        started = time.monotonic()
        try:
            returncode = self.executor.run(
                command, cwd=self.repo, stdout=stdout, stderr=stderr
            )
        except OSError as error:
            stderr.write_text(str(error) + "\n", encoding="utf-8")
            returncode = 127
        duration = int((time.monotonic() - started) * 1000)
        parsed: object | None = None
        try:
            raw = stdout.read_text(encoding="utf-8")
            if raw.strip():
                parsed = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError):
            parsed = None
        result = CommandResult(
            name=name,
            phase=phase,
            returncode=returncode,
            blocking=blocking,
            stdout=str(stdout),
            stderr=str(stderr),
            duration_ms=duration,
            parsed=parsed,
        )
        record = {
            "name": name,
            "phase": phase,
            "ok": result.ok,
            "blocking": blocking,
            "returncode": returncode,
            "duration_ms": duration,
            "stdout": str(stdout),
            "stderr": str(stderr),
        }
        with self._lock:
            steps = self.state.setdefault("steps", [])
            if not isinstance(steps, list):
                raise DeliveryError("delivery state steps are invalid")
            steps.append(record)
            self._save_state()
        self._event(
            {
                "phase": phase,
                "name": name,
                "status": "passed" if result.ok else "failed",
                "blocking": blocking,
                "returncode": returncode,
                "duration_ms": duration,
                "stdout": str(stdout),
                "stderr": str(stderr),
            }
        )
        return result

    def run_batch(
        self,
        *,
        phase: str,
        steps: Sequence[Mapping[str, object]],
        parallel: bool,
        root: bool = False,
    ) -> list[CommandResult]:
        if not steps:
            return []

        def invoke(step: Mapping[str, object]) -> CommandResult:
            return self.run_step(
                phase=phase,
                name=str(step["name"]),
                argv=step["argv"],
                blocking=bool(step["blocking"]),
                root=root,
            )

        if not parallel or len(steps) == 1:
            return [invoke(step) for step in steps]
        results: list[CommandResult] = []
        with ThreadPoolExecutor(max_workers=min(self.max_parallel, len(steps))) as pool:
            futures = {pool.submit(invoke, step): index for index, step in enumerate(steps)}
            ordered: dict[int, CommandResult] = {}
            for future in as_completed(futures):
                ordered[futures[future]] = future.result()
            results.extend(ordered[index] for index in range(len(steps)))
        return results

    def source_check(self) -> list[CommandResult]:
        builtins = [
            {
                "name": "diff-check",
                "argv": [
                    "/usr/bin/git",
                    "-c",
                    f"safe.directory={self.repo}",
                    "diff",
                    "--check",
                ],
                "blocking": True,
            },
            {
                "name": "delivery-self-test",
                "argv": [
                    sys.executable,
                    str(ROOT / "scripts/self_test_software_owned_delivery.py"),
                ],
                "blocking": True,
            },
            {
                "name": "codex-test-access-self-test",
                "argv": [
                    sys.executable,
                    str(ROOT / "scripts/self_test_verify_codex_test_access.py"),
                ],
                "blocking": True,
            },
            {
                "name": "same-schema-switch-self-test",
                "argv": [
                    sys.executable,
                    str(ROOT / "scripts/self_test_switch_same_schema_release.py"),
                ],
                "blocking": True,
            },
            {
                "name": "fast-repository-validation",
                "argv": [
                    sys.executable,
                    str(self.repo / "scripts/run_fast_repository_validation.py"),
                    "--skip-diff",
                ],
                "blocking": True,
            },
            {
                "name": "console-tests",
                "argv": [
                    sys.executable,
                    str(self.repo / "scripts/run_console_unit_tests.py"),
                ],
                "blocking": True,
            },
            *[
                {
                    "name": f"coordinator-{partition}",
                    "argv": [
                        sys.executable,
                        str(self.repo / "scripts/run_coordinator_test_partition.py"),
                        partition,
                    ],
                    "blocking": True,
                }
                for partition in (
                    "broker-authority",
                    "resources-storage",
                    "runtime-lifecycle",
                    "universal-harness",
                )
            ],
        ]
        configured = self.plan.get("source_checks", [])
        if not isinstance(configured, list):
            raise DeliveryError("source check plan is invalid")
        return self.run_batch(
            phase="source-check",
            steps=[*builtins, *configured],
            parallel=True,
        )

    @staticmethod
    def _blocking_failed(results: Sequence[CommandResult]) -> bool:
        return any(not result.ok and result.blocking for result in results)

    def package(self) -> list[CommandResult]:
        installer = str(ROOT / "scripts/install_availability_release.py")
        plan = self.run_step(
            phase="package",
            name="release-plan",
            argv=[
                sys.executable,
                installer,
                "plan",
                "--repo",
                str(self.repo),
                "--release-root",
                str(self.release_root),
            ],
            blocking=True,
            root=True,
        )
        if not plan.ok or not isinstance(plan.parsed, Mapping):
            return [plan]
        digest = plan.parsed.get("release_digest")
        destination = plan.parsed.get("release_directory")
        if (
            not isinstance(digest, str)
            or RELEASE_RE.fullmatch(digest) is None
            or not isinstance(destination, str)
        ):
            raise DeliveryError("release plan output is invalid")
        stage = self.run_step(
            phase="package",
            name="release-stage",
            argv=[
                sys.executable,
                installer,
                "stage",
                "--repo",
                str(self.repo),
                "--release-root",
                str(self.release_root),
            ],
            blocking=True,
            root=True,
        )
        if not stage.ok:
            return [plan, stage]
        verify = self.run_step(
            phase="package",
            name="release-verify",
            argv=[
                sys.executable,
                str(Path(destination) / "scripts/install_availability_release.py"),
                "verify",
                "--release",
                destination,
            ],
            blocking=True,
            root=True,
        )
        if verify.ok:
            self.state["release"] = {"digest": digest, "path": destination}
            self._save_state()
        return [plan, stage, verify]

    def _rollback(self, steps: Sequence[Mapping[str, object]]) -> list[CommandResult]:
        results: list[CommandResult] = []
        for step in steps:
            results.append(
                self.run_step(
                    phase="rollback",
                    name=str(step["name"]),
                    argv=step["argv"],
                    blocking=True,
                    root=True,
                )
            )
        return results

    def deploy_same_schema(
        self, *, reset_test_history: bool = False
    ) -> list[CommandResult]:
        same = self.plan.get("same_schema")
        if not isinstance(same, Mapping):
            raise DeliveryError("same-schema deployment plan is unavailable")
        for field in ("prepare", "apply", "rollback", "health"):
            if not isinstance(same.get(field), list):
                raise DeliveryError("same-schema deployment plan is invalid")
        if not same["apply"] or not same["rollback"] or not same["health"]:
            raise DeliveryError(
                "same-schema deploy needs apply, rollback, and health commands"
            )
        prepared_steps = same_schema_steps(
            same["prepare"], reset_test_history=reset_test_history
        )
        apply_steps = same_schema_steps(
            same["apply"], reset_test_history=reset_test_history
        )
        rollback_steps = same_schema_steps(
            same["rollback"], reset_test_history=reset_test_history
        )
        health_steps = same_schema_steps(
            same["health"], reset_test_history=reset_test_history
        )
        results: list[CommandResult] = []
        prepare = self.run_batch(
            phase="deploy-prepare", steps=prepared_steps, parallel=True, root=True
        )
        results.extend(prepare)
        if self._blocking_failed(prepare):
            self.state["deployment"] = {"status": "blocked-before-mutation"}
            self._save_state()
            return results
        mutated = False
        for step in apply_steps:
            mutated = True
            result = self.run_step(
                phase="deploy-apply",
                name=str(step["name"]),
                argv=step["argv"],
                blocking=True,
                root=True,
            )
            results.append(result)
            if not result.ok:
                rollback = self._rollback(rollback_steps)
                results.extend(rollback)
                self.state["deployment"] = {
                    "status": (
                        "rolled-back-after-apply-failure"
                        if all(item.ok for item in rollback)
                        else "rollback-incomplete"
                    )
                }
                self._save_state()
                return results
        health = self.run_batch(
            phase="control-plane-health", steps=health_steps, parallel=True, root=True
        )
        results.extend(health)
        if any(not result.ok for result in health):
            if mutated:
                rollback = self._rollback(rollback_steps)
                results.extend(rollback)
            else:
                rollback = []
            self.state["deployment"] = {
                "status": (
                    "rolled-back-after-health-failure"
                    if all(item.ok for item in rollback)
                    else "rollback-incomplete"
                )
            }
            self._save_state()
            return results
        self.state["deployment"] = {
            "status": "healthy",
            "mode": "same-schema",
            "test_history_reset": reset_test_history,
        }
        self._save_state()
        return results

    def _reset_manifest(self, template: Path) -> Path:
        document = read_json(template)
        if not isinstance(document, Mapping):
            raise DeliveryError("clean-adoption template is invalid")
        release = self.state.get("release")
        if not isinstance(release, Mapping):
            raise DeliveryError("reset requires a packaged release")
        patched = dict(document)
        # These are the only release-specific values.  Console settings,
        # grants, Telegram state, repositories, routes, and fixed ports remain
        # byte-for-byte inherited from the explicit template.
        patched["release"] = str(release["path"])
        release_digest = str(release["digest"])
        if RELEASE_RE.fullmatch(release_digest) is None:
            raise DeliveryError("reset requires a valid packaged release digest")
        release_transaction_root = self.transaction_root / release_digest
        patched["rendered_units"] = str(
            release_transaction_root / "rendered-units"
        )
        patched["candidate_slot_source"] = str(
            release_transaction_root / f"{release_digest}.env"
        )
        release_transaction_root.mkdir(parents=True, exist_ok=True)
        output = release_transaction_root / "manifest.json"
        atomic_json(output, patched)
        os.chmod(output, 0o600)
        return output

    def deploy_reset(self, template: Path) -> list[CommandResult]:
        manifest = self._reset_manifest(template)
        release = self.state.get("release")
        if not isinstance(release, Mapping):
            raise DeliveryError("reset requires a packaged release")
        release_digest = str(release.get("digest") or "")
        if RELEASE_RE.fullmatch(release_digest) is None:
            raise DeliveryError("reset requires a valid packaged release digest")
        release_transaction_root = self.transaction_root / release_digest
        helper = str(Path(str(release["path"])) / "bin/devcoordinator-clean-adoption")
        plan = self.run_step(
            phase="reset-prepare",
            name="clean-adoption-plan",
            argv=[helper, "plan", "--manifest", str(manifest)],
            blocking=True,
            root=True,
        )
        if not plan.ok:
            self.state["deployment"] = {"status": "blocked-before-mutation"}
            self._save_state()
            return [plan]
        apply = self.run_step(
            phase="reset-apply",
            name="clean-adoption-apply",
            argv=[
                helper,
                "apply",
                "--manifest",
                str(manifest),
                "--transaction-root",
                str(release_transaction_root),
                "--journal",
                str(release_transaction_root / "journal.json"),
                "--expected-uid",
                "0",
            ],
            blocking=True,
            root=True,
        )
        self.state["deployment"] = {
            "status": "healthy" if apply.ok else "reset-incomplete",
            "mode": "reset",
        }
        self._save_state()
        return [plan, apply]

    def acceptance(self) -> list[CommandResult]:
        setup = self.plan.get("acceptance_setup", [])
        steps = self.plan.get("acceptance", [])
        if not isinstance(setup, list) or not isinstance(steps, list):
            raise DeliveryError("acceptance plan is invalid")
        results = self.run_batch(
            phase="acceptance-setup", steps=setup, parallel=False, root=True
        )
        # Run every acceptance check even after a failure.  Sequential order
        # avoids Playwright/performance/harness checks distorting one another.
        # These are agent-facing acceptance journeys, including Codex policy
        # discovery.  They must run as the actual delivery caller, not through
        # the privileged prefix used only for package and host mutation.
        results.extend(
            self.run_batch(
                phase="acceptance", steps=steps, parallel=False, root=False
            )
        )
        return results

    def report(self) -> dict[str, object]:
        raw_steps = self.state.get("steps", [])
        steps = raw_steps if isinstance(raw_steps, list) else []
        failures = [item for item in steps if isinstance(item, Mapping) and not item.get("ok")]
        blocking = [item for item in failures if item.get("blocking") is True]
        health = [item for item in failures if item.get("phase") == "control-plane-health"]
        acceptance = [
            item
            for item in failures
            if item.get("phase") in {"acceptance-setup", "acceptance"}
        ]
        deployment = self.state.get("deployment")
        deployment_status = (
            deployment.get("status") if isinstance(deployment, Mapping) else None
        )
        if deployment_status in {
            "blocked-before-mutation",
            "rolled-back-after-apply-failure",
            "rolled-back-after-health-failure",
            "rollback-incomplete",
            "reset-incomplete",
        }:
            conclusion = "blocked"
        elif health or blocking or acceptance:
            conclusion = "failed"
        elif failures:
            conclusion = "passed-with-findings"
        else:
            conclusion = "passed"
        report = {
            "schema_version": SCHEMA_VERSION,
            "kind": REPORT_KIND,
            "conclusion": conclusion,
            "release": self.state.get("release"),
            "deployment": deployment,
            "counts": {
                "steps": len(steps),
                "failures": len(failures),
                "blocking_failures": len(blocking),
                "health_failures": len(health),
                "acceptance_failures": len(acceptance),
            },
            "failures": [
                {
                    "phase": item.get("phase"),
                    "name": item.get("name"),
                    "returncode": item.get("returncode"),
                    "stdout": item.get("stdout"),
                    "stderr": item.get("stderr"),
                }
                for item in failures
            ],
            "events": str(self.events_path),
            "text_log": str(self.text_log_path),
            "generated_at": now(),
        }
        atomic_json(self.report_path, report)
        return report


def common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument(
        "--release-root", type=Path, default=Path("/opt/devcoordinator/releases")
    )
    parser.add_argument("--transaction-root", type=Path)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--max-parallel", type=int, default=4)


def acceptance_timeouts(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--acceptance-execution-timeout-seconds",
        required=True,
        type=lambda raw: _timeout_argument(
            raw,
            name="acceptance execution timeout",
            maximum=MAX_EXECUTION_TIMEOUT_SECONDS,
        ),
        help="deadline for the governed probe process",
    )
    parser.add_argument(
        "--acceptance-launch-timeout-seconds",
        required=True,
        type=lambda raw: _timeout_argument(
            raw,
            name="acceptance launch timeout",
            maximum=MAX_LAUNCH_TIMEOUT_SECONDS,
        ),
        help="deadline for launch and launch reconciliation",
    )
    parser.add_argument(
        "--acceptance-wait-timeout-seconds",
        required=True,
        type=lambda raw: _timeout_argument(
            raw,
            name="acceptance wait timeout",
            maximum=MAX_WAIT_TIMEOUT_SECONDS,
        ),
        help="overall time the acceptance step may wait for a terminal run",
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    actions = result.add_subparsers(dest="action", required=True)
    for name in ("source-check", "package"):
        action = actions.add_parser(name)
        common(action)
    acceptance = actions.add_parser("acceptance")
    common(acceptance)
    acceptance_timeouts(acceptance)
    deploy = actions.add_parser("deploy")
    common(deploy)
    deploy.add_argument(
        "--deployment-mode", choices=("same-schema", "reset"), default="same-schema"
    )
    deploy.add_argument("--adoption-template", type=Path)
    deploy.add_argument(
        "--reset-test-history",
        action="store_true",
        help="discard only disposable test history during same-schema delivery",
    )
    full = actions.add_parser("run")
    common(full)
    acceptance_timeouts(full)
    full.add_argument(
        "--deployment-mode", choices=("same-schema", "reset"), default="same-schema"
    )
    full.add_argument("--adoption-template", type=Path)
    full.add_argument(
        "--reset-test-history",
        action="store_true",
        help="discard only disposable test history during same-schema delivery",
    )
    report = actions.add_parser("report")
    report.add_argument("--run-root", type=Path, required=True)
    return result


def make_delivery(args: argparse.Namespace) -> Delivery:
    run_root = args.run_root.expanduser().absolute()
    transaction = (
        args.transaction_root.expanduser().absolute()
        if args.transaction_root is not None
        else run_root / "transaction"
    )
    plan = load_plan(args.plan)
    source_repo = args.repo.expanduser().resolve()
    try:
        context = resolve_effective_repository_context(project=str(source_repo))
    except RepositoryContextError as error:
        raise DeliveryError(
            "delivery source is not one stable Git worktree"
        ) from error
    return Delivery(
        repo=args.repo,
        run_root=run_root,
        release_root=args.release_root,
        transaction_root=transaction,
        plan=plan,
        max_parallel=args.max_parallel,
        acceptance_execution_timeout_seconds=getattr(
            args, "acceptance_execution_timeout_seconds", None
        ),
        acceptance_launch_timeout_seconds=getattr(
            args, "acceptance_launch_timeout_seconds", None
        ),
        acceptance_wait_timeout_seconds=getattr(
            args, "acceptance_wait_timeout_seconds", None
        ),
        canonical_repo=Path(context.root.canonical_root),
    )


def concise(report: Mapping[str, object]) -> str:
    counts = report.get("counts") if isinstance(report.get("counts"), Mapping) else {}
    release = report.get("release") if isinstance(report.get("release"), Mapping) else {}
    return json.dumps(
        {
            "ok": report.get("conclusion") in {"passed", "passed-with-findings"},
            "conclusion": report.get("conclusion"),
            "release_digest": release.get("digest"),
            "steps": counts.get("steps"),
            "failures": counts.get("failures"),
            "report": str(report.get("events", "")).replace("events.jsonl", "report.json"),
        },
        sort_keys=True,
    )


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.action == "report":
        try:
            path = args.run_root.expanduser().absolute() / "report.json"
            if path.exists():
                value = read_json(path)
            else:
                state = read_json(args.run_root.expanduser().absolute() / "state.json")
                if not isinstance(state, Mapping) or state.get("kind") != STATE_KIND:
                    raise DeliveryError("delivery state is invalid")
                resumed = Delivery(
                    repo=Path(str(state["repo"])),
                    run_root=args.run_root.expanduser().absolute(),
                    release_root=Path(str(state["release_root"])),
                    transaction_root=Path(str(state["transaction_root"])),
                    plan=load_plan(None),
                )
                value = resumed.report()
            if not isinstance(value, Mapping):
                raise DeliveryError("delivery report is invalid")
            print(concise(value))
            return (
                0
                if value.get("conclusion") in {"passed", "passed-with-findings"}
                else 1
            )
        except (DeliveryError, OSError, ValueError) as error:
            print(
                json.dumps({"ok": False, "error": str(error)}, sort_keys=True),
                file=sys.stderr,
            )
            return 2
    try:
        with exclusive_run_root(args.run_root):
            delivery = make_delivery(args)
            if args.action == "source-check":
                delivery.source_check()
            elif args.action == "package":
                delivery.package()
            elif args.action == "acceptance":
                delivery.acceptance()
            elif args.action == "deploy":
                if args.deployment_mode == "reset":
                    if args.reset_test_history:
                        raise DeliveryError(
                            "--reset-test-history is only valid for same-schema delivery"
                        )
                    if args.adoption_template is None:
                        raise DeliveryError("reset mode requires --adoption-template")
                    delivery.deploy_reset(args.adoption_template)
                else:
                    delivery.deploy_same_schema(
                        reset_test_history=args.reset_test_history
                    )
            else:
                source = delivery.source_check()
                if not delivery._blocking_failed(source):
                    packaged = delivery.package()
                    if not delivery._blocking_failed(packaged):
                        if args.deployment_mode == "reset":
                            if args.reset_test_history:
                                raise DeliveryError(
                                    "--reset-test-history is only valid for same-schema delivery"
                                )
                            if args.adoption_template is None:
                                raise DeliveryError("reset mode requires --adoption-template")
                            delivery.deploy_reset(args.adoption_template)
                        else:
                            delivery.deploy_same_schema(
                                reset_test_history=args.reset_test_history
                            )
                        deployment = delivery.state.get("deployment")
                        if (
                            isinstance(deployment, Mapping)
                            and deployment.get("status") == "healthy"
                        ):
                            delivery.acceptance()
            report = delivery.report()
            print(concise(report))
            return (
                0
                if report["conclusion"] in {"passed", "passed-with-findings"}
                else 1
            )
    except (DeliveryError, OSError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
