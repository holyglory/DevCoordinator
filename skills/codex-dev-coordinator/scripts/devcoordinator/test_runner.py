"""Universal manifest-driven test execution with broker-owned result storage."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import time
from typing import Any, Mapping, Sequence
import uuid
from xml.etree import ElementTree

from .broker import BrokerOperation
from .broker_profile import BrokerClientProfile

MANIFEST_PATH = Path(".codex/tests.json")
_KINDS = frozenset({"pytest", "jsonl", "trx", "automation"})
UTC = timezone.utc


class TestHarnessError(RuntimeError):
    """A test declaration or execution contract is invalid."""


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


def _fingerprint(value: object) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _safe_child_directory(root: Path, raw: object) -> Path:
    value = str(raw or ".")
    candidate = (root / value).resolve()
    if candidate != root and root not in candidate.parents:
        raise TestHarnessError("test group cwd must remain inside the repository")
    if not candidate.is_dir():
        raise TestHarnessError(f"test group cwd does not exist: {value}")
    return candidate


def load_manifest(root: Path) -> dict[str, Any]:
    path = root / MANIFEST_PATH
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise TestHarnessError(
            f"repository test manifest is missing: {path}"
        ) from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise TestHarnessError(
            f"repository test manifest is unreadable: {error}"
        ) from error
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise TestHarnessError("test manifest schema_version must be 1")
    groups = document.get("groups")
    profiles = document.get("profiles")
    if not isinstance(groups, dict) or not groups:
        raise TestHarnessError("test manifest must declare at least one group")
    if not isinstance(profiles, dict) or not profiles:
        raise TestHarnessError("test manifest must declare at least one profile")
    for name, group in groups.items():
        if not isinstance(name, str) or not name or not isinstance(group, dict):
            raise TestHarnessError("test group names and definitions must be objects")
        argv = group.get("argv")
        default_selectors = group.get("selectors", [])
        if (
            group.get("kind") not in _KINDS
            or not isinstance(argv, list)
            or not argv
            or len(argv) > 256
            or any(
                not isinstance(item, str) or not item or len(item) > 4096
                for item in argv
            )
        ):
            raise TestHarnessError(f"test group {name!r} has an invalid kind or argv")
        if (
            not isinstance(default_selectors, list)
            or any(
                not isinstance(item, str) or not item or len(item) > 2048
                for item in default_selectors
            )
            or (default_selectors and group.get("kind") != "pytest")
        ):
            raise TestHarnessError(f"test group {name!r} has invalid default selectors")
        _safe_child_directory(root, group.get("cwd"))
    for name, members in profiles.items():
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(members, list)
            or not members
            or any(member not in groups for member in members)
            or len(set(members)) != len(members)
        ):
            raise TestHarnessError(f"test profile {name!r} is invalid")
    return document


def test_statistics(
    *, profile: BrokerClientProfile, project: str, days: int, limit: int
) -> dict[str, Any]:
    repository = profile.repository(project)
    _, result = profile.call(
        repository=repository,
        resource_id=repository.repo_id,
        operation=BrokerOperation.TEST_STATS_READ,
        arguments={"days": days, "limit": limit},
    )
    return result


class UniversalTestRunner:
    """Execute repository declarations while the broker owns every record."""

    def __init__(
        self,
        *,
        root: Path,
        profile: BrokerClientProfile,
        agent: str,
    ) -> None:
        self.root = root.resolve()
        self.profile = profile
        self.repository = profile.repository(str(self.root))
        self.agent = agent

    def run(
        self,
        *,
        profile_name: str | None = None,
        group_names: Sequence[str] = (),
        selectors: Sequence[str] = (),
    ) -> dict[str, Any]:
        manifest = load_manifest(self.root)
        groups = manifest["groups"]
        if profile_name is not None and group_names:
            raise TestHarnessError("choose either one profile or explicit groups")
        if profile_name is None and not group_names:
            raise TestHarnessError("choose a profile or at least one test group")
        if profile_name is not None:
            try:
                selected = list(manifest["profiles"][profile_name])
            except KeyError as error:
                raise TestHarnessError(
                    f"unknown test profile: {profile_name}"
                ) from error
            selection_label = profile_name
        else:
            selected = list(group_names)
            unknown = [name for name in selected if name not in groups]
            if unknown:
                raise TestHarnessError("unknown test groups: " + ", ".join(unknown))
            selection_label = ",".join(selected)
        if selectors and (
            len(selected) != 1 or groups[selected[0]]["kind"] != "pytest"
        ):
            raise TestHarnessError(
                "individual selectors require exactly one pytest group"
            )

        session_id = str(uuid.uuid4())
        session_started = _timestamp()
        session_clock = time.monotonic()
        self._start(
            run_id=session_id,
            suite=selection_label,
            run_kind="session",
            selection=list(selectors),
            command_fingerprint=_fingerprint(selected),
            started_at=session_started,
        )
        results: list[dict[str, Any]] = []
        overall = "passed"
        try:
            for name in selected:
                result = self._run_group(
                    name=name,
                    definition=groups[name],
                    selectors=list(selectors),
                    parent_run_id=session_id,
                )
                results.append(result)
                if result["status"] != "passed":
                    overall = "failed"
        except KeyboardInterrupt:
            overall = "cancelled"
            raise
        finally:
            self._finish(
                run_id=session_id,
                status=overall,
                started_at=session_started,
                started_clock=session_clock,
                exit_code=0 if overall == "passed" else 1,
                cases=[],
            )
        return {
            "schema_version": 1,
            "session_run_id": session_id,
            "repo_id": self.repository.repo_id,
            "status": overall,
            "groups": results,
        }

    def _run_group(
        self,
        *,
        name: str,
        definition: Mapping[str, Any],
        selectors: list[str],
        parent_run_id: str,
    ) -> dict[str, Any]:
        run_id = str(uuid.uuid4())
        started_at = _timestamp()
        started_clock = time.monotonic()
        kind = str(definition["kind"])
        effective_selectors = selectors or list(definition.get("selectors", []))
        with tempfile.TemporaryDirectory(prefix="devcoordinator-tests-") as temporary:
            temporary_path = Path(temporary)
            events = temporary_path / "events.jsonl"
            results = temporary_path / "results"
            results.mkdir()
            replacements = {
                "{python}": sys.executable,
                "{dotnet}": _dotnet_executable(),
                "{events}": str(events),
                "{results}": str(results),
            }
            argv = [replacements.get(item, item) for item in definition["argv"]]
            if kind == "pytest":
                argv.extend(
                    [
                        "-p",
                        "devcoordinator.pytest_reporter",
                        "--devcoordinator-test-events",
                        str(events),
                        *effective_selectors,
                    ]
                )
            environment = os.environ.copy()
            script_root = str(Path(__file__).resolve().parent.parent)
            environment["PYTHONPATH"] = script_root + (
                os.pathsep + environment["PYTHONPATH"]
                if environment.get("PYTHONPATH")
                else ""
            )
            event_environment = definition.get("event_env")
            if event_environment is not None:
                if not isinstance(
                    event_environment, str
                ) or not event_environment.startswith("DEVCOORDINATOR_"):
                    raise TestHarnessError(
                        f"test group {name!r} event_env must use DEVCOORDINATOR_ namespace"
                    )
                environment[event_environment] = str(events)
            command_fingerprint = _fingerprint(
                {"kind": kind, "argv": argv, "cwd": definition.get("cwd", ".")}
            )
            self._start(
                run_id=run_id,
                suite=name,
                run_kind="test" if kind != "automation" else "automation",
                selection=effective_selectors,
                command_fingerprint=command_fingerprint,
                parent_run_id=parent_run_id,
                started_at=started_at,
            )
            exit_code = 127
            status = "failed"
            cases: list[dict[str, Any]] = []
            try:
                with (temporary_path / "child-output.log").open("wb") as output:
                    completed = subprocess.run(
                        argv,
                        cwd=_safe_child_directory(self.root, definition.get("cwd")),
                        env=environment,
                        stdin=subprocess.DEVNULL,
                        stdout=output,
                        stderr=subprocess.STDOUT,
                        check=False,
                    )
                exit_code = int(completed.returncode)
                cases = _read_cases(kind, events=events, results=results)
                status = "passed" if exit_code == 0 else "failed"
                if kind != "automation" and not cases:
                    status = "incomplete"
            except KeyboardInterrupt:
                exit_code = 130
                status = "cancelled"
                raise
            except (json.JSONDecodeError, ElementTree.ParseError, TestHarnessError):
                # A reporter artifact that cannot be decoded is not evidence
                # that the underlying tests passed or failed. Persist the run
                # as incomplete while keeping child output private.
                exit_code = exit_code or 70
                status = "incomplete"
            except OSError:
                status = "failed"
            finally:
                recorded = self._finish(
                    run_id=run_id,
                    status=status,
                    started_at=started_at,
                    started_clock=started_clock,
                    exit_code=exit_code,
                    cases=cases,
                )
            return recorded

    def _start(
        self,
        *,
        run_id: str,
        suite: str,
        run_kind: str,
        selection: list[str],
        command_fingerprint: str,
        started_at: str,
        parent_run_id: str | None = None,
    ) -> dict[str, Any]:
        arguments: dict[str, Any] = {
            "agent": self.agent,
            "suite": suite,
            "run_kind": run_kind,
            "selection": selection,
            "command_fingerprint": command_fingerprint,
            "started_at": started_at,
        }
        if parent_run_id is not None:
            arguments["parent_run_id"] = parent_run_id
        _, result = self.profile.call(
            repository=self.repository,
            resource_id=self.repository.repo_id,
            operation=BrokerOperation.TEST_RUN_START,
            arguments=arguments,
            operation_id=run_id,
        )
        return result

    def _finish(
        self,
        *,
        run_id: str,
        status: str,
        started_at: str,
        started_clock: float,
        exit_code: int,
        cases: list[dict[str, Any]],
    ) -> dict[str, Any]:
        del started_at
        _, result = self.profile.call(
            repository=self.repository,
            resource_id=self.repository.repo_id,
            operation=BrokerOperation.TEST_RUN_FINISH,
            arguments={
                "run_id": run_id,
                "status": status,
                "finished_at": _timestamp(),
                "duration_seconds": max(time.monotonic() - started_clock, 0.0),
                "exit_code": exit_code,
                "cases": cases,
            },
        )
        return result


def _read_cases(kind: str, *, events: Path, results: Path) -> list[dict[str, Any]]:
    if kind in {"pytest", "jsonl"}:
        if not events.exists():
            return []
        parsed = []
        for line in events.read_text(encoding="utf-8").splitlines():
            value = json.loads(line)
            if not isinstance(value, dict):
                raise TestHarnessError("test reporter wrote a non-object event")
            parsed.append(value)
        return parsed
    if kind == "trx":
        files = sorted(results.glob("*.trx"))
        return [] if not files else _parse_trx(files[0])
    return []


def _dotnet_executable() -> str:
    configured = os.environ.get("DOTNET")
    candidates = [
        configured,
        shutil.which("dotnet"),
        str(Path.home() / ".dotnet" / "dotnet"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    return "dotnet"


def _parse_trx(path: Path) -> list[dict[str, Any]]:
    root = ElementTree.parse(path).getroot()
    parsed: list[dict[str, Any]] = []
    for item in root.findall(".//{*}UnitTestResult"):
        started = item.attrib.get("startTime")
        finished = item.attrib.get("endTime")
        if not started or not finished:
            continue
        outcome = item.attrib.get("outcome", "Failed")
        status = {
            "Passed": "passed",
            "NotExecuted": "skipped",
            "Failed": "failed",
        }.get(outcome, "error")
        start_value = datetime.fromisoformat(started.replace("Z", "+00:00"))
        finish_value = datetime.fromisoformat(finished.replace("Z", "+00:00"))
        name = item.attrib.get("testName") or item.attrib.get("testId") or "unknown"
        parsed.append(
            {
                "test_id": item.attrib.get("testId") or name,
                "display_name": name,
                "status": status,
                "started_at": start_value.isoformat(),
                "finished_at": finish_value.isoformat(),
                "duration_seconds": max(
                    (finish_value - start_value).total_seconds(), 0.0
                ),
            }
        )
    return parsed
