"""Pytest reporter for the Coordinator-owned universal test harness."""

from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import time
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from _pytest.reports import TestReport

_CONFIG: pytest.Config | None = None


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--devcoordinator-test-events", action="store", default=None, metavar="PATH"
    )


def pytest_configure(config: pytest.Config) -> None:
    destination = config.getoption("devcoordinator_test_events")
    if destination is not None:
        config._devcoordinator_events_path = Path(destination)  # type: ignore[attr-defined]
        config._devcoordinator_case_start = {}  # type: ignore[attr-defined]
        config._devcoordinator_case_outcome = {}  # type: ignore[attr-defined]


@pytest.hookimpl(tryfirst=True)
def pytest_sessionstart(session: pytest.Session) -> None:
    global _CONFIG
    _CONFIG = session.config


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    del session, exitstatus
    global _CONFIG
    _CONFIG = None


def pytest_runtest_logstart(nodeid: str, location: tuple[str, int | None, str]) -> None:
    del location
    config = _CONFIG
    if config is not None and hasattr(config, "_devcoordinator_case_start"):
        config._devcoordinator_case_start[nodeid] = (  # type: ignore[attr-defined]
            datetime.now(UTC),
            time.monotonic(),
        )


def pytest_runtest_logreport(report: TestReport) -> None:
    config = _CONFIG
    if config is None:
        return
    destination = getattr(config, "_devcoordinator_events_path", None)
    starts = getattr(config, "_devcoordinator_case_start", None)
    outcomes = getattr(config, "_devcoordinator_case_outcome", None)
    if destination is None or starts is None or outcomes is None:
        return
    candidate = _case_outcome(report)
    outcomes[report.nodeid] = _worse_outcome(outcomes.get(report.nodeid), candidate)
    if report.when != "teardown":
        return
    started_at, started_monotonic = starts.pop(
        report.nodeid, (datetime.now(UTC), time.monotonic())
    )
    finished_at = datetime.now(UTC)
    event = {
        "test_id": report.nodeid,
        "display_name": report.nodeid,
        "status": outcomes.pop(report.nodeid, "error"),
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": max(time.monotonic() - started_monotonic, 0.0),
    }
    with destination.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, separators=(",", ":")) + "\n")


def _case_outcome(report: TestReport) -> str:
    if report.outcome == "passed":
        return "passed"
    if report.outcome == "skipped":
        return "skipped"
    return "error" if report.when in {"setup", "teardown"} else "failed"


def _worse_outcome(current: str | None, candidate: str) -> str:
    rank = {"passed": 0, "skipped": 1, "failed": 2, "error": 3}
    return candidate if current is None or rank[candidate] >= rank[current] else current
