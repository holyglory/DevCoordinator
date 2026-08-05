#!/usr/bin/env python3
"""Run one deterministic partition of the Coordinator's unittest suite.

The universal harness invokes this file with an allowlisted partition name.
Keeping the ownership table here makes live change/checkpoint plans granular,
while immutable handoff/release/manual plans can still require every partition.
New tests fail toward the runtime partition until the manifest maps their input
family more precisely; ``--check`` proves that every discovered test is owned
exactly once.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sys
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = ROOT / "skills" / "codex-dev-coordinator" / "scripts"
TEST_ROOT = PACKAGE_ROOT / "devcoordinator" / "tests"
TEST_PACKAGE = "devcoordinator.tests"

# These modules preserve operator-invoked recovery coverage, but they are not
# part of normal change/handoff/release evidence. Production initializes an
# empty current-schema test store; legacy history migration runs only when an
# operator explicitly asks to retain history.
NON_GATE_COMPATIBILITY_MODULES = frozenset({"test_universal_test_migration"})


@dataclass(frozen=True)
class Partition:
    name: str
    owns: Callable[[str], bool]


def _has_prefix(*prefixes: str) -> Callable[[str], bool]:
    return lambda module: module.startswith(prefixes)


def _is_named(*names: str) -> Callable[[str], bool]:
    allowed = frozenset(names)
    return lambda module: module in allowed


PARTITIONS = (
    Partition("universal-harness", _has_prefix("test_universal_test")),
    Partition(
        "broker-authority",
        lambda module: _has_prefix("test_broker")(module)
        or _is_named(
            "test_enrollment_snapshot_fingerprints",
            "test_filesystem_acl",
            "test_maintenance",
            "test_project_profile_revocation",
            "test_repository_owner_authority",
        )(module),
    ),
    Partition(
        "resources-storage",
        _has_prefix(
            "test_database_backups",
            "test_docker_grouping_regressions",
            "test_ephemeral_",
            "test_storage_split",
            "test_store_backup",
        ),
    ),
    Partition("runtime-lifecycle", lambda _module: True),
)


def discovered_modules(test_root: Path = TEST_ROOT) -> tuple[str, ...]:
    return tuple(
        path.stem
        for path in sorted(test_root.glob("test_*.py"))
        if path.stem not in NON_GATE_COMPATIBILITY_MODULES
    )


def non_gate_compatibility_modules(
    test_root: Path = TEST_ROOT,
) -> tuple[str, ...]:
    present = {path.stem for path in test_root.glob("test_*.py")}
    return tuple(sorted(present & NON_GATE_COMPATIBILITY_MODULES))


def partitioned_modules(
    modules: Sequence[str] | None = None,
) -> dict[str, tuple[str, ...]]:
    discovered = discovered_modules() if modules is None else tuple(modules)
    result: dict[str, list[str]] = {partition.name: [] for partition in PARTITIONS}
    for module in discovered:
        for partition in PARTITIONS:
            if partition.owns(module):
                result[partition.name].append(module)
                break
        else:  # pragma: no cover - final partition is deliberately exhaustive.
            raise AssertionError(f"unowned Coordinator test module: {module}")
    return {name: tuple(values) for name, values in result.items()}


def partition_contract_errors(
    modules: Sequence[str] | None = None,
) -> tuple[str, ...]:
    discovered = discovered_modules() if modules is None else tuple(modules)
    grouped = partitioned_modules(discovered)
    errors: list[str] = []
    missing_compatibility = sorted(
        NON_GATE_COMPATIBILITY_MODULES - set(non_gate_compatibility_modules())
    )
    if missing_compatibility:
        errors.append(
            "declared non-gate compatibility module(s) missing: "
            + ", ".join(missing_compatibility)
        )
    empty = [name for name, values in grouped.items() if not values]
    if empty:
        errors.append("empty partition(s): " + ", ".join(empty))
    flattened = [module for values in grouped.values() for module in values]
    duplicates = sorted(
        module for module in set(flattened) if flattened.count(module) != 1
    )
    if duplicates:
        errors.append("multiply owned test module(s): " + ", ".join(duplicates))
    missing = sorted(set(discovered) - set(flattened))
    extra = sorted(set(flattened) - set(discovered))
    if missing:
        errors.append("unowned test module(s): " + ", ".join(missing))
    if extra:
        errors.append("unknown owned test module(s): " + ", ".join(extra))
    return tuple(errors)


class JsonlTestResult(unittest.TextTestResult):
    """Mirror unittest results into the harness's bounded JSONL case stream."""

    def __init__(self, *args: object, event_path: Path | None, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._event_path = event_path
        self._started: dict[str, float] = {}

    def startTest(self, test: unittest.case.TestCase) -> None:  # noqa: N802
        self._started[test.id()] = time.monotonic()
        super().startTest(test)

    def _emit(
        self,
        test: unittest.case.TestCase,
        status: str,
        *,
        message: str | None = None,
    ) -> None:
        if self._event_path is None:
            return
        identifier = test.id()
        payload: dict[str, object] = {
            "case_id": identifier,
            "name": identifier,
            "status": status,
            "duration_seconds": max(
                0.0, time.monotonic() - self._started.get(identifier, time.monotonic())
            ),
        }
        if message:
            payload["message"] = message[:8192]
        with self._event_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, sort_keys=True) + "\n")

    def addSuccess(self, test: unittest.case.TestCase) -> None:  # noqa: N802
        super().addSuccess(test)
        self._emit(test, "passed")

    def addFailure(  # noqa: N802
        self,
        test: unittest.case.TestCase,
        err: tuple[type[BaseException], BaseException, object],
    ) -> None:
        super().addFailure(test, err)
        self._emit(test, "failed", message=self._exc_info_to_string(err, test))

    def addError(  # noqa: N802
        self,
        test: unittest.case.TestCase,
        err: tuple[type[BaseException], BaseException, object],
    ) -> None:
        super().addError(test, err)
        self._emit(test, "error", message=self._exc_info_to_string(err, test))

    def addSkip(self, test: unittest.case.TestCase, reason: str) -> None:  # noqa: N802
        super().addSkip(test, reason)
        self._emit(test, "skipped", message=reason)


def _event_path() -> Path | None:
    raw = os.environ.get("DEVCOORDINATOR_TEST_EVENTS")
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        raise SystemExit("DEVCOORDINATOR_TEST_EVENTS must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")
    return path


def run_partition(name: str) -> int:
    errors = partition_contract_errors()
    if errors:
        raise SystemExit("; ".join(errors))
    modules = partitioned_modules()[name]
    sys.path.insert(0, str(PACKAGE_ROOT))
    suite = unittest.defaultTestLoader.loadTestsFromNames(
        [f"{TEST_PACKAGE}.{module}" for module in modules]
    )
    event_path = _event_path()

    def resultclass(*args: object, **kwargs: object) -> JsonlTestResult:
        return JsonlTestResult(*args, event_path=event_path, **kwargs)

    result = unittest.TextTestRunner(verbosity=2, resultclass=resultclass).run(suite)
    return 0 if result.wasSuccessful() else 1


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "partition",
        nargs="?",
        choices=[partition.name for partition in PARTITIONS],
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate and print the deterministic partition ownership table",
    )
    arguments = parser.parse_args(argv)
    if arguments.check == (arguments.partition is not None):
        parser.error("select exactly one partition or --check")
    return arguments


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    if arguments.check:
        errors = partition_contract_errors()
        if errors:
            raise SystemExit("; ".join(errors))
        print(json.dumps(partitioned_modules(), indent=2, sort_keys=True))
        return 0
    return run_partition(str(arguments.partition))


if __name__ == "__main__":
    raise SystemExit(main())
