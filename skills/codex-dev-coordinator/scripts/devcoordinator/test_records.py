"""Coordinator-owned repository test-run journal and statistics queries."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .broker import AuthorizedBrokerRequest, BrokerBackendError
from .store import CoordinatorStore, utc_timestamp


def _canonical_fingerprint(value: object) -> str:
    def mutable(item: object) -> object:
        if isinstance(item, Mapping):
            return {str(key): mutable(nested) for key, nested in item.items()}
        if isinstance(item, (list, tuple)):
            return [mutable(nested) for nested in item]
        return item

    encoded = json.dumps(
        mutable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _parsed_timestamp(value: object, field: str) -> str:
    text = str(value or "")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise BrokerBackendError(
            "invalid_test_result", f"{field} must be an ISO-8601 timestamp."
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise BrokerBackendError(
            "invalid_test_result", f"{field} must include an explicit UTC offset."
        )
    return parsed.isoformat()


class CoordinatorTestRecords:
    """Typed access to the service-owned test tables.

    Test processes remain children of the authenticated client account. The
    broker owns admission, repository attribution, lifecycle, idempotency, and
    every durable result row; no client receives a database handle.
    """

    def __init__(
        self,
        database_path: Path,
        *,
        expected_uid: int,
        busy_timeout_ms: int,
    ) -> None:
        self.database_path = database_path
        self.expected_uid = expected_uid
        self.busy_timeout_ms = busy_timeout_ms

    def start(self, authorized: AuthorizedBrokerRequest) -> dict[str, Any]:
        request = authorized.request
        arguments = request.arguments
        run_id = request.operation_id
        now = utc_timestamp()
        started_at = _parsed_timestamp(arguments["started_at"], "started_at")
        selection = list(arguments.get("selection") or [])
        with CoordinatorStore.open(
            self.database_path,
            expected_uid=self.expected_uid,
            busy_timeout_ms=self.busy_timeout_ms,
        ) as store:
            with store.immediate_transaction() as connection:
                existing = connection.execute(
                    "SELECT * FROM test_runs WHERE run_id = ?", (run_id,)
                ).fetchone()
                identity = {
                    "repo_id": request.project_id,
                    "owner_uid": authorized.peer.uid,
                    "account_id": request.account_id,
                    "suite": arguments["suite"],
                    "run_kind": arguments["run_kind"],
                    "selection": selection,
                    "command_fingerprint": arguments["command_fingerprint"],
                    "started_at": started_at,
                    "parent_run_id": arguments.get("parent_run_id"),
                }
                if existing is not None:
                    existing_identity = {
                        "repo_id": existing["repo_id"],
                        "owner_uid": existing["owner_uid"],
                        "account_id": existing["account_id"],
                        "suite": existing["suite"],
                        "run_kind": existing["run_kind"],
                        "selection": json.loads(existing["selection_json"]),
                        "command_fingerprint": existing["command_fingerprint"],
                        "started_at": existing["client_started_at"],
                        "parent_run_id": existing["parent_run_id"],
                    }
                    if existing_identity != identity:
                        raise BrokerBackendError(
                            "test_run_identity_conflict",
                            "This test run ID is already bound to different immutable inputs.",
                            operation_id=request.operation_id,
                        )
                    return self._run_result(existing)

                parent_run_id = arguments.get("parent_run_id")
                if parent_run_id is not None:
                    parent = connection.execute(
                        """
                        SELECT repo_id, owner_uid, account_id, run_kind
                        FROM test_runs WHERE run_id = ?
                        """,
                        (parent_run_id,),
                    ).fetchone()
                    if (
                        parent is None
                        or parent["repo_id"] != request.project_id
                        or int(parent["owner_uid"]) != authorized.peer.uid
                        or parent["account_id"] != request.account_id
                        or parent["run_kind"] != "session"
                    ):
                        raise BrokerBackendError(
                            "test_parent_access_denied",
                            "The parent test session is unavailable to this repository principal.",
                            operation_id=request.operation_id,
                        )
                connection.execute(
                    """
                    INSERT INTO test_runs(
                        run_id, repo_id, parent_run_id, owner_uid, account_id,
                        actor, suite, run_kind, selection_json,
                        command_fingerprint, status, client_started_at,
                        admitted_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        request.project_id,
                        parent_run_id,
                        authorized.peer.uid,
                        request.account_id,
                        f"broker:{request.account_id}:client-agent:{arguments['agent']}",
                        arguments["suite"],
                        arguments["run_kind"],
                        json.dumps(selection, separators=(",", ":")),
                        arguments["command_fingerprint"],
                        started_at,
                        now,
                        now,
                        now,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM test_runs WHERE run_id = ?", (run_id,)
                ).fetchone()
                return self._run_result(row)

    def finish(self, authorized: AuthorizedBrokerRequest) -> dict[str, Any]:
        request = authorized.request
        arguments = request.arguments
        run_id = str(arguments["run_id"])
        finished_at = _parsed_timestamp(arguments["finished_at"], "finished_at")
        cases = list(arguments.get("cases") or [])
        payload_fingerprint = _canonical_fingerprint(arguments)
        counts = {"passed": 0, "failed": 0, "skipped": 0, "error": 0}
        case_rows: list[tuple[object, ...]] = []
        for ordinal, case in enumerate(cases):
            started = _parsed_timestamp(case["started_at"], "case.started_at")
            finished = _parsed_timestamp(case["finished_at"], "case.finished_at")
            if datetime.fromisoformat(finished) < datetime.fromisoformat(started):
                raise BrokerBackendError(
                    "invalid_test_result",
                    "An individual test finished before it started.",
                    operation_id=request.operation_id,
                )
            status = str(case["status"])
            counts[status] += 1
            case_rows.append(
                (
                    run_id,
                    ordinal,
                    case["test_id"],
                    case["display_name"],
                    status,
                    started,
                    finished,
                    float(case["duration_seconds"]),
                )
            )
        if arguments["status"] == "passed":
            if int(arguments["exit_code"]) != 0:
                raise BrokerBackendError(
                    "invalid_test_result",
                    "A passed test run must have a zero exit code.",
                    operation_id=request.operation_id,
                )
            if counts["failed"] > 0 or counts["error"] > 0:
                raise BrokerBackendError(
                    "invalid_test_result",
                    "A passed test run cannot contain failed or errored test cases.",
                    operation_id=request.operation_id,
                )

        now = utc_timestamp()
        with CoordinatorStore.open(
            self.database_path,
            expected_uid=self.expected_uid,
            busy_timeout_ms=self.busy_timeout_ms,
        ) as store:
            with store.immediate_transaction() as connection:
                row = connection.execute(
                    "SELECT * FROM test_runs WHERE run_id = ?", (run_id,)
                ).fetchone()
                if (
                    row is None
                    or row["repo_id"] != request.project_id
                    or int(row["owner_uid"]) != authorized.peer.uid
                    or row["account_id"] != request.account_id
                ):
                    raise BrokerBackendError(
                        "test_run_access_denied",
                        "The test run does not belong to this repository principal.",
                        operation_id=request.operation_id,
                    )
                if row["status"] != "running":
                    if row["result_fingerprint"] != payload_fingerprint:
                        raise BrokerBackendError(
                            "test_run_result_conflict",
                            "The completed test run is bound to a different result.",
                            operation_id=request.operation_id,
                        )
                    return self._run_result(row)
                if datetime.fromisoformat(finished_at) < datetime.fromisoformat(
                    str(row["client_started_at"])
                ):
                    raise BrokerBackendError(
                        "invalid_test_result",
                        "The test run finished before it started.",
                        operation_id=request.operation_id,
                    )
                connection.executemany(
                    """
                    INSERT INTO test_case_results(
                        run_id, ordinal, test_id, display_name, status,
                        started_at, finished_at, duration_seconds
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    case_rows,
                )
                connection.execute(
                    """
                    UPDATE test_runs SET
                        status = ?, client_finished_at = ?,
                        recorded_finished_at = ?, duration_seconds = ?,
                        exit_code = ?, case_count = ?, passed_count = ?,
                        failed_count = ?, skipped_count = ?, error_count = ?,
                        finished_operation_id = ?, result_fingerprint = ?,
                        updated_at = ?
                    WHERE run_id = ? AND status = 'running'
                    """,
                    (
                        arguments["status"],
                        finished_at,
                        now,
                        float(arguments["duration_seconds"]),
                        int(arguments["exit_code"]),
                        len(cases),
                        counts["passed"],
                        counts["failed"],
                        counts["skipped"],
                        counts["error"],
                        request.operation_id,
                        payload_fingerprint,
                        now,
                        run_id,
                    ),
                )
                completed = connection.execute(
                    "SELECT * FROM test_runs WHERE run_id = ?", (run_id,)
                ).fetchone()
                return self._run_result(completed)

    def stats(self, authorized: AuthorizedBrokerRequest) -> dict[str, Any]:
        request = authorized.request
        return self.stats_for_repository(
            repo_id=request.project_id,
            days=int(request.arguments.get("days", 30)),
            limit=int(request.arguments.get("limit", 25)),
        )

    def stats_for_repository(
        self, *, repo_id: str, days: int = 30, limit: int = 25
    ) -> dict[str, Any]:
        """Read one bounded repository projection from the service store."""

        if not 1 <= days <= 3_650 or not 1 <= limit <= 500:
            raise ValueError("test statistics bounds are invalid")
        window = f"-{days} days"
        with CoordinatorStore.open_read_only(
            self.database_path,
            expected_uid=self.expected_uid,
            busy_timeout_ms=self.busy_timeout_ms,
        ) as store:
            with store.read_transaction() as connection:
                summary = dict(
                    connection.execute(
                        """
                        WITH recent_runs AS (
                            SELECT * FROM test_runs
                            WHERE repo_id = ?
                              AND julianday(client_started_at) >= julianday('now', ?)
                        ), recent_cases AS (
                            SELECT c.* FROM test_case_results c
                            JOIN recent_runs r USING(run_id)
                        )
                        SELECT
                            (SELECT COUNT(*) FROM recent_runs WHERE run_kind != 'session') AS run_count,
                            (SELECT COUNT(*) FROM recent_runs WHERE run_kind = 'session') AS session_count,
                            (SELECT COUNT(*) FROM recent_runs WHERE status = 'running') AS running_count,
                            (SELECT COALESCE(SUM(duration_seconds), 0) FROM recent_runs
                             WHERE run_kind != 'session') AS run_seconds,
                            (SELECT COUNT(*) FROM recent_cases) AS test_count,
                            (SELECT COALESCE(SUM(duration_seconds), 0) FROM recent_cases) AS test_seconds,
                            (SELECT COALESCE(SUM(status = 'passed'), 0) FROM recent_cases) AS passed_count,
                            (SELECT COALESCE(SUM(status = 'failed'), 0) FROM recent_cases) AS failed_count,
                            (SELECT COALESCE(SUM(status = 'skipped'), 0) FROM recent_cases) AS skipped_count,
                            (SELECT COALESCE(SUM(status = 'error'), 0) FROM recent_cases) AS error_count
                        """,
                        (repo_id, window),
                    ).fetchone()
                )
                daily = [
                    dict(row)
                    for row in connection.execute(
                        """
                        WITH recent_runs AS (
                            SELECT * FROM test_runs WHERE repo_id = ?
                              AND julianday(client_started_at) >= julianday('now', ?)
                        ), run_daily AS (
                            SELECT substr(client_started_at, 1, 10) AS day,
                                   COUNT(*) AS run_count,
                                   COALESCE(SUM(duration_seconds), 0) AS run_seconds
                            FROM recent_runs WHERE run_kind != 'session' GROUP BY day
                        ), case_daily AS (
                            SELECT substr(r.client_started_at, 1, 10) AS day,
                                   COUNT(*) AS test_count,
                                   COALESCE(SUM(c.duration_seconds), 0) AS test_seconds
                            FROM test_case_results c JOIN recent_runs r USING(run_id)
                            GROUP BY day
                        )
                        SELECT run_daily.day, run_count,
                               COALESCE(test_count, 0) AS test_count,
                               run_seconds, COALESCE(test_seconds, 0) AS test_seconds
                        FROM run_daily LEFT JOIN case_daily USING(day)
                        ORDER BY day DESC
                        """,
                        (repo_id, window),
                    )
                ]
                suite_rows = [
                    dict(row)
                    for row in connection.execute(
                        """
                        SELECT suite, COUNT(*) AS run_count,
                               COALESCE(SUM(duration_seconds), 0) AS total_seconds,
                               COALESCE(AVG(duration_seconds), 0) AS average_seconds,
                               COALESCE(MAX(duration_seconds), 0) AS max_seconds
                        FROM test_runs
                        WHERE repo_id = ? AND status != 'running'
                          AND run_kind != 'session'
                          AND julianday(client_started_at) >= julianday('now', ?)
                        GROUP BY suite ORDER BY total_seconds DESC, suite
                        """,
                        (repo_id, window),
                    )
                ]
                test_rows = [
                    dict(row)
                    for row in connection.execute(
                        """
                        SELECT c.test_id, MAX(c.display_name) AS display_name,
                               COUNT(*) AS executions,
                               SUM(c.duration_seconds) AS total_seconds,
                               AVG(c.duration_seconds) AS average_seconds,
                               MAX(c.duration_seconds) AS max_seconds,
                               SUM(c.status IN ('failed', 'error')) AS failure_count
                        FROM test_case_results c JOIN test_runs r USING(run_id)
                        WHERE r.repo_id = ?
                          AND julianday(r.client_started_at) >= julianday('now', ?)
                        GROUP BY c.test_id
                        ORDER BY total_seconds DESC, c.test_id LIMIT ?
                        """,
                        (repo_id, window, limit),
                    )
                ]
                recent_runs = [
                    self._run_result(row)
                    for row in connection.execute(
                        """
                        SELECT * FROM test_runs WHERE repo_id = ?
                        ORDER BY client_started_at DESC, run_id DESC LIMIT ?
                        """,
                        (repo_id, limit),
                    )
                ]
        total_run_seconds = float(summary["run_seconds"] or 0)
        total_test_seconds = float(summary["test_seconds"] or 0)
        for row in suite_rows:
            row["percent_of_run_time"] = (
                0.0
                if total_run_seconds == 0
                else round(100 * float(row["total_seconds"]) / total_run_seconds, 3)
            )
        for row in test_rows:
            row["percent_of_test_time"] = (
                0.0
                if total_test_seconds == 0
                else round(100 * float(row["total_seconds"]) / total_test_seconds, 3)
            )
        return {
            "schema_version": 1,
            "repo_id": repo_id,
            "days": days,
            "summary": summary,
            "daily": daily,
            "suites": suite_rows,
            "slow_tests": test_rows,
            "recent_runs": recent_runs,
        }

    @staticmethod
    def _run_result(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: row[key]
            for key in (
                "run_id",
                "repo_id",
                "parent_run_id",
                "suite",
                "run_kind",
                "status",
                "client_started_at",
                "admitted_at",
                "client_finished_at",
                "recorded_finished_at",
                "duration_seconds",
                "exit_code",
                "case_count",
                "passed_count",
                "failed_count",
                "skipped_count",
                "error_count",
            )
        }
