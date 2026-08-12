"""Coordinator-owned repository test-run journal and statistics queries."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Iterable, Mapping

from .broker import AcceptedBrokerRequest, BrokerBackendError
from .store import CoordinatorStore, utc_timestamp


MAX_FLEET_REPOSITORIES = 500
MAX_FLEET_HOURS = 168
MAX_FLEET_ATTENTION_ROWS = 25


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


def _utc_datetime(value: object) -> datetime:
    """Parse a stored, already-validated test timestamp into UTC."""

    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _hourly_case_statistics(
    rows: list[Mapping[str, Any]], *, now: datetime | None = None
) -> list[dict[str, Any]]:
    """Aggregate the seven-day heatmap in one pass over relevant cases.

    The previous SQL joined every case to every generated hour before testing
    interval overlap. On a busy repository that multiplied tens of thousands
    of case rows by 168 buckets and tied up a Coordinator request thread for
    several seconds. Keep the same interval semantics while making the work
    linear in the number of relevant cases.
    """

    current = (now or datetime.now(UTC)).astimezone(UTC)
    window_start = current.replace(
        hour=0, minute=0, second=0, microsecond=0
    ) - timedelta(days=6)
    window_end = window_start + timedelta(days=7)
    buckets: dict[datetime, dict[str, Any]] = {}
    cursor = window_start
    while cursor < window_end:
        buckets[cursor] = {
            "day": cursor.date().isoformat(),
            "hour": cursor.hour,
            "test_seconds": 0.0,
            "failure_count": 0,
        }
        cursor += timedelta(hours=1)

    for row in rows:
        started = _utc_datetime(row["started_at"])
        finished = _utc_datetime(row["finished_at"])
        overlap_start = max(started, window_start)
        overlap_end = min(finished, window_end)
        if overlap_end <= overlap_start:
            continue
        bucket = overlap_start.replace(minute=0, second=0, microsecond=0)
        while bucket < overlap_end:
            bucket_end = bucket + timedelta(hours=1)
            seconds = (
                min(overlap_end, bucket_end) - max(overlap_start, bucket)
            ).total_seconds()
            if seconds > 0:
                buckets[bucket]["test_seconds"] += seconds
            bucket = bucket_end
        if (
            row["status"] in {"failed", "error"}
            and window_start <= started < window_end
        ):
            failure_bucket = started.replace(minute=0, second=0, microsecond=0)
            buckets[failure_bucket]["failure_count"] += 1

    return [
        {
            **bucket,
            "test_seconds": round(float(bucket["test_seconds"]), 3),
        }
        for bucket in buckets.values()
    ]


def _iso_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _nearest_rank_percentile(values: Iterable[float], percentile: float) -> float | None:
    ordered = sorted(float(value) for value in values if float(value) >= 0)
    if not ordered:
        return None
    rank = max(1, math.ceil(percentile * len(ordered)))
    return round(ordered[rank - 1], 3)


def _ratio(numerator: float, denominator: float) -> float | None:
    if denominator <= 0:
        return None
    return round(numerator / denominator, 4)


def _rate(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(numerator / denominator, 6)


def _empty_avoided_work() -> dict[str, Any]:
    # The legacy runner does not record plan candidates which were intentionally
    # not selected. Returning an explicit unavailable metric keeps the Console
    # honest until the asynchronous planner starts emitting that evidence.
    return {
        "available": False,
        "test_count": None,
        "test_seconds": None,
        "reason": "selection telemetry is not recorded for these runs",
    }


class CoordinatorTestRecords:
    """Typed access to the service-owned test tables.

    Test processes use configured repository execution authority. The broker
    retains the local caller UID only as audit attribution and owns admission,
    repository attribution, lifecycle, idempotency, and every durable result
    row; no client receives a database handle.
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

    def start(self, accepted: AcceptedBrokerRequest) -> dict[str, Any]:
        request = accepted.request
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
                        accepted.peer.uid,
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

    def finish(self, accepted: AcceptedBrokerRequest) -> dict[str, Any]:
        request = accepted.request
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

    def stats(self, accepted: AcceptedBrokerRequest) -> dict[str, Any]:
        request = accepted.request
        return self.stats_for_repository(
            repo_id=request.project_id,
            days=int(request.arguments.get("days", 30)),
            limit=int(request.arguments.get("limit", 25)),
        )

    def fleet(self, accepted: AcceptedBrokerRequest) -> dict[str, Any]:
        request = accepted.request
        with CoordinatorStore.open_read_only(
            self.database_path,
            expected_uid=self.expected_uid,
            busy_timeout_ms=self.busy_timeout_ms,
        ) as store:
            with store.read_transaction() as connection:
                repository_ids = tuple(
                    str(row["repo_id"])
                    for row in connection.execute(
                        """
                        SELECT repository.repo_id
                        FROM repositories AS repository
                        WHERE repository.state = 'active'
                        ORDER BY repository.repo_id
                        """,
                    )
                )
        return self.fleet_overview(
            hours=int(request.arguments.get("hours", 24)),
            repository_ids=repository_ids,
        )

    def fleet_overview(
        self,
        *,
        hours: int = 24,
        now: datetime | None = None,
        repository_ids: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        """Return one bounded host-wide test projection without per-repo reads.

        Case intervals are split at exact UTC hour boundaries. Their durations
        add, so one bucket may legitimately exceed 3,600 seconds when tests run
        in parallel. The response contains no paths, commands, logs, or case
        identities and is bounded by repository/hour/attention limits.
        """

        if not 1 <= hours <= MAX_FLEET_HOURS:
            raise ValueError(f"fleet test hours must be 1-{MAX_FLEET_HOURS}")
        current = (now or datetime.now(UTC)).astimezone(UTC)
        window_end = current.replace(minute=0, second=0, microsecond=0) + timedelta(
            hours=1
        )
        window_start = window_end - timedelta(hours=hours)
        hour_starts = [window_start + timedelta(hours=index) for index in range(hours)]

        scoped_ids = (
            tuple(dict.fromkeys(str(repo_id) for repo_id in repository_ids))
            if repository_ids is not None
            else None
        )
        with CoordinatorStore.open_read_only(
            self.database_path,
            expected_uid=self.expected_uid,
            busy_timeout_ms=self.busy_timeout_ms,
        ) as store:
            with store.read_transaction() as connection:
                scope_clause = ""
                scope_arguments: tuple[object, ...] = ()
                if scoped_ids is not None:
                    if scoped_ids:
                        placeholders = ",".join("?" for _ in scoped_ids)
                        scope_clause = f" AND r.repo_id IN ({placeholders})"
                        scope_arguments = tuple(scoped_ids)
                    else:
                        scope_clause = " AND 0 = 1"
                total_repository_count = int(
                    connection.execute(
                        """
                        SELECT COUNT(*)
                        FROM repositories r
                        LEFT JOIN repository_installations i USING(repo_id)
                        WHERE r.state = 'active'
                          AND COALESCE(i.status, 'installed') != 'disabled'
                        """
                        + scope_clause,
                        scope_arguments,
                    ).fetchone()[0]
                )
                repository_rows = [
                    dict(row)
                    for row in connection.execute(
                        """
                        SELECT r.repo_id, r.display_name
                        FROM repositories r
                        LEFT JOIN repository_installations i USING(repo_id)
                        WHERE r.state = 'active'
                          AND COALESCE(i.status, 'installed') != 'disabled'
                        """
                        + scope_clause
                        + " ORDER BY lower(r.display_name), r.repo_id LIMIT ?",
                        (*scope_arguments, MAX_FLEET_REPOSITORIES),
                    )
                ]
                truncated = total_repository_count > len(repository_rows)
                repo_ids = [str(row["repo_id"]) for row in repository_rows]
                if repo_ids:
                    placeholders = ",".join("?" for _ in repo_ids)
                    run_rows = [
                        dict(row)
                        for row in connection.execute(
                            f"""
                            SELECT repo_id, run_id, run_kind, status,
                                   client_started_at, admitted_at,
                                   client_finished_at, duration_seconds,
                                   passed_count, failed_count, error_count,
                                   updated_at
                            FROM test_runs
                            WHERE repo_id IN ({placeholders})
                              AND julianday(client_started_at) >= julianday(?)
                              AND julianday(client_started_at) < julianday(?)
                            ORDER BY client_started_at, run_id
                            """,
                            (*repo_ids, _iso_utc(window_start), _iso_utc(window_end)),
                        )
                    ]
                    case_rows = [
                        dict(row)
                        for row in connection.execute(
                            f"""
                            SELECT r.repo_id, c.test_id, c.status,
                                   c.started_at, c.finished_at
                            FROM test_case_results c
                            JOIN test_runs r USING(run_id)
                            WHERE r.repo_id IN ({placeholders})
                              AND julianday(c.finished_at) > julianday(?)
                              AND julianday(c.started_at) < julianday(?)
                            ORDER BY c.started_at, c.run_id, c.ordinal
                            """,
                            (*repo_ids, _iso_utc(window_start), _iso_utc(window_end)),
                        )
                    ]
                else:
                    run_rows = []
                    case_rows = []

        def empty_summary() -> dict[str, Any]:
            return {
                "run_count": 0,
                "running_count": 0,
                "test_count": 0,
                "test_seconds": 0.0,
                "wall_seconds": 0.0,
                "passed_count": 0,
                "failure_count": 0,
                "failed_run_count": 0,
                "queue_waits": [],
                "test_statuses": {},
                "last_activity_at": None,
                "stalled_running": False,
            }

        summaries = {repo_id: empty_summary() for repo_id in repo_ids}
        hourly_by_repo: dict[str, dict[datetime, dict[str, Any]]] = {
            repo_id: {} for repo_id in repo_ids
        }
        queue_waits_by_hour: dict[datetime, list[float]] = {
            hour_start: [] for hour_start in hour_starts
        }
        observed_through: datetime | None = None
        for row in run_rows:
            repo_id = str(row["repo_id"])
            summary = summaries[repo_id]
            updated = _utc_datetime(row["updated_at"])
            observed_through = max(observed_through, updated) if observed_through else updated
            started = _utc_datetime(row["client_started_at"])
            finished_value = row.get("client_finished_at")
            activity = _utc_datetime(finished_value) if finished_value else started
            prior_activity = summary["last_activity_at"]
            if prior_activity is None or activity > prior_activity:
                summary["last_activity_at"] = activity
            if row["run_kind"] == "session":
                continue
            summary["run_count"] += 1
            if row["status"] == "running":
                summary["running_count"] += 1
                if current - started >= timedelta(hours=2):
                    summary["stalled_running"] = True
            else:
                summary["wall_seconds"] += float(row.get("duration_seconds") or 0)
            if row["status"] in {"failed", "incomplete"}:
                summary["failed_run_count"] += 1
            admitted = _utc_datetime(row["admitted_at"])
            queue_wait = max(0.0, (admitted - started).total_seconds())
            summary["queue_waits"].append(queue_wait)
            run_hour = started.replace(minute=0, second=0, microsecond=0)
            if run_hour in queue_waits_by_hour:
                queue_waits_by_hour[run_hour].append(queue_wait)

        for row in case_rows:
            repo_id = str(row["repo_id"])
            summary = summaries[repo_id]
            started = _utc_datetime(row["started_at"])
            finished = _utc_datetime(row["finished_at"])
            overlap_start = max(started, window_start)
            overlap_end = min(finished, window_end)
            if overlap_end <= overlap_start:
                continue
            summary["test_count"] += 1
            status = str(row["status"])
            if status == "passed":
                summary["passed_count"] += 1
            elif status in {"failed", "error"}:
                summary["failure_count"] += 1
            summary["test_statuses"].setdefault(str(row["test_id"]), set()).add(status)
            bucket_start = overlap_start.replace(minute=0, second=0, microsecond=0)
            while bucket_start < overlap_end:
                bucket_end = bucket_start + timedelta(hours=1)
                seconds = (
                    min(overlap_end, bucket_end) - max(overlap_start, bucket_start)
                ).total_seconds()
                if seconds > 0:
                    cell = hourly_by_repo[repo_id].setdefault(
                        bucket_start,
                        {
                            "hour_start": _iso_utc(bucket_start),
                            "test_seconds": 0.0,
                            "test_count": 0,
                            "failure_count": 0,
                        },
                    )
                    cell["test_seconds"] += seconds
                bucket_start = bucket_end
            if window_start <= started < window_end:
                start_bucket = started.replace(minute=0, second=0, microsecond=0)
                cell = hourly_by_repo[repo_id].setdefault(
                    start_bucket,
                    {
                        "hour_start": _iso_utc(start_bucket),
                        "test_seconds": 0.0,
                        "test_count": 0,
                        "failure_count": 0,
                    },
                )
                cell["test_count"] += 1
                if status in {"failed", "error"}:
                    cell["failure_count"] += 1

        queue_waits: list[float] = []
        fleet_statuses: dict[tuple[str, str], set[str]] = {}
        fleet = empty_summary()
        repository_payloads: list[dict[str, Any]] = []
        attention: list[dict[str, Any]] = []
        for repository in repository_rows:
            repo_id = str(repository["repo_id"])
            raw = summaries[repo_id]
            test_seconds = round(
                sum(float(cell["test_seconds"]) for cell in hourly_by_repo[repo_id].values()),
                3,
            )
            raw["test_seconds"] = test_seconds
            statuses = raw.pop("test_statuses")
            distinct_test_count = len(statuses)
            flaky_test_count = sum(
                1
                for values in statuses.values()
                if "passed" in values and bool(values & {"failed", "error"})
            )
            queue_waits.extend(raw["queue_waits"])
            for test_id, values in statuses.items():
                fleet_statuses[(repo_id, test_id)] = values
            health_denominator = raw["passed_count"] + raw["failure_count"]
            last_activity = raw["last_activity_at"]
            state = (
                "failing"
                if raw["failure_count"] or raw["failed_run_count"]
                else "stale"
                if raw["stalled_running"]
                else "healthy"
                if raw["run_count"] or raw["test_count"]
                else "idle"
            )
            summary = {
                "run_count": raw["run_count"],
                "running_count": raw["running_count"],
                "test_count": raw["test_count"],
                "test_seconds": test_seconds,
                "wall_seconds": round(float(raw["wall_seconds"]), 3),
                "parallel_efficiency_ratio": _ratio(test_seconds, raw["wall_seconds"]),
                "p95_queue_wait_seconds": _nearest_rank_percentile(
                    raw["queue_waits"], 0.95
                ),
                "passed_count": raw["passed_count"],
                "failure_count": raw["failure_count"],
                "failed_run_count": raw["failed_run_count"],
                "pass_rate": _rate(raw["passed_count"], health_denominator),
                "distinct_test_count": distinct_test_count,
                "flaky_test_count": flaky_test_count,
                "flake_rate": _rate(flaky_test_count, distinct_test_count),
            }
            cells = sorted(
                (
                    {
                        **cell,
                        "test_seconds": round(float(cell["test_seconds"]), 3),
                    }
                    for cell in hourly_by_repo[repo_id].values()
                ),
                key=lambda cell: cell["hour_start"],
            )
            repository_payloads.append(
                {
                    "repo_id": repo_id,
                    "display_name": str(repository["display_name"]),
                    "last_activity_at": _iso_utc(last_activity) if last_activity else None,
                    "state": state,
                    "summary": summary,
                    "hourly": cells,
                }
            )
            if state == "failing":
                attention.append(
                    {
                        "repo_id": repo_id,
                        "severity": "error",
                        "code": "recent_test_failures",
                        "title": f"{repository['display_name']} has recent test failures",
                        "detail": (
                            f"{raw['failure_count']} failed cases across "
                            f"{raw['failed_run_count']} failed or incomplete runs"
                        ),
                        "observed_at": _iso_utc(last_activity) if last_activity else None,
                    }
                )
            elif state == "stale":
                attention.append(
                    {
                        "repo_id": repo_id,
                        "severity": "warning",
                        "code": "stalled_test_run",
                        "title": f"{repository['display_name']} has a long-running test",
                        "detail": "A test run has remained active for at least two hours.",
                        "observed_at": _iso_utc(last_activity) if last_activity else None,
                    }
                )
            for key in (
                "run_count",
                "running_count",
                "test_count",
                "passed_count",
                "failure_count",
                "failed_run_count",
            ):
                fleet[key] += raw[key]
            fleet["test_seconds"] += test_seconds
            fleet["wall_seconds"] += float(raw["wall_seconds"])
            if last_activity and (
                fleet["last_activity_at"] is None or last_activity > fleet["last_activity_at"]
            ):
                fleet["last_activity_at"] = last_activity

        capacity: list[dict[str, Any]] = []
        for hour_start in hour_starts:
            cells = [
                hourly_by_repo[repo_id].get(hour_start)
                for repo_id in repo_ids
            ]
            populated = [cell for cell in cells if cell is not None]
            capacity.append(
                {
                    "hour_start": _iso_utc(hour_start),
                    "test_seconds": round(
                        sum(float(cell["test_seconds"]) for cell in populated), 3
                    ),
                    "test_count": sum(int(cell["test_count"]) for cell in populated),
                    "failure_count": sum(
                        int(cell["failure_count"]) for cell in populated
                    ),
                    "active_repository_count": len(
                        [cell for cell in populated if float(cell["test_seconds"]) > 0]
                    ),
                    "p95_queue_wait_seconds": _nearest_rank_percentile(
                        queue_waits_by_hour[hour_start], 0.95
                    ),
                }
            )

        fleet_distinct = len(fleet_statuses)
        fleet_flaky = sum(
            1
            for values in fleet_statuses.values()
            if "passed" in values and bool(values & {"failed", "error"})
        )
        fleet_health_denominator = fleet["passed_count"] + fleet["failure_count"]
        generated_at = _iso_utc(current)
        observed_at = _iso_utc(observed_through) if observed_through else None
        summary = {
            "repository_count": total_repository_count,
            "returned_repository_count": len(repository_payloads),
            "repositories_with_activity": sum(
                1
                for repository in repository_payloads
                if repository["state"] != "idle"
            ),
            "run_count": fleet["run_count"],
            "running_count": fleet["running_count"],
            "test_count": fleet["test_count"],
            "test_seconds": round(float(fleet["test_seconds"]), 3),
            "wall_seconds": round(float(fleet["wall_seconds"]), 3),
            "parallel_efficiency_ratio": _ratio(
                fleet["test_seconds"], fleet["wall_seconds"]
            ),
            "p95_queue_wait_seconds": _nearest_rank_percentile(queue_waits, 0.95),
            "passed_count": fleet["passed_count"],
            "failure_count": fleet["failure_count"],
            "failed_run_count": fleet["failed_run_count"],
            "pass_rate": _rate(fleet["passed_count"], fleet_health_denominator),
            "distinct_test_count": fleet_distinct,
            "flaky_test_count": fleet_flaky,
            "flake_rate": _rate(fleet_flaky, fleet_distinct),
            "last_activity_at": (
                _iso_utc(fleet["last_activity_at"])
                if fleet["last_activity_at"]
                else None
            ),
            "avoided_work": _empty_avoided_work(),
        }
        snapshot_identity = {
            "window_start": _iso_utc(window_start),
            "window_end": _iso_utc(window_end),
            "observed_through": observed_at,
            "repositories": [
                {
                    "repo_id": row["repo_id"],
                    "last_activity_at": row["last_activity_at"],
                    "test_count": row["summary"]["test_count"],
                }
                for row in repository_payloads
            ],
        }
        return {
            "schema_version": 2,
            "window": {
                "hours": hours,
                "start": _iso_utc(window_start),
                "end": _iso_utc(window_end),
                "timezone": "UTC",
            },
            "snapshot": {
                "generated_at": generated_at,
                "observed_through": observed_at,
                "source": "coordinator-test-store",
                "source_revision": _canonical_fingerprint(snapshot_identity),
                "retention": {"eligible": True, "max_age_seconds": 86_400},
            },
            "summary": summary,
            "hours": [_iso_utc(hour_start) for hour_start in hour_starts],
            "repositories": repository_payloads,
            "capacity": capacity,
            "attention": sorted(
                attention,
                key=lambda row: (
                    0 if row["severity"] == "error" else 1,
                    row["repo_id"],
                ),
            )[:MAX_FLEET_ATTENTION_ROWS],
            "truncated": truncated,
        }

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
                comparison_summary = dict(
                    connection.execute(
                        """
                        WITH previous_runs AS (
                            SELECT * FROM test_runs
                            WHERE repo_id = ?
                              AND julianday(client_started_at) >= julianday('now', ?)
                              AND julianday(client_started_at) < julianday('now', ?)
                        ), previous_cases AS (
                            SELECT c.* FROM test_case_results c
                            JOIN previous_runs r USING(run_id)
                        )
                        SELECT
                            (SELECT COUNT(*) FROM previous_runs WHERE run_kind != 'session') AS run_count,
                            (SELECT COALESCE(SUM(duration_seconds), 0) FROM previous_runs
                             WHERE run_kind != 'session') AS run_seconds,
                            (SELECT COUNT(*) FROM previous_cases) AS test_count,
                            (SELECT COALESCE(SUM(duration_seconds), 0) FROM previous_cases) AS test_seconds,
                            (SELECT COALESCE(SUM(status = 'passed'), 0) FROM previous_cases) AS passed_count,
                            (SELECT COALESCE(SUM(status = 'failed'), 0) FROM previous_cases) AS failed_count,
                            (SELECT COALESCE(SUM(status = 'skipped'), 0) FROM previous_cases) AS skipped_count,
                            (SELECT COALESCE(SUM(status = 'error'), 0) FROM previous_cases) AS error_count,
                            (SELECT COUNT(*) FROM previous_runs
                             WHERE run_kind != 'session'
                               AND status IN ('failed', 'incomplete')) AS failed_run_count
                        """,
                        (repo_id, f"-{days * 2} days", window),
                    ).fetchone()
                )
                summary["failed_run_count"] = int(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM test_runs
                        WHERE repo_id = ?
                          AND run_kind != 'session'
                          AND status IN ('failed', 'incomplete')
                          AND julianday(client_started_at) >= julianday('now', ?)
                        """,
                        (repo_id, window),
                    ).fetchone()[0]
                )
                queue_waits = [
                    max(
                        0.0,
                        (
                            _utc_datetime(row["admitted_at"])
                            - _utc_datetime(row["client_started_at"])
                        ).total_seconds(),
                    )
                    for row in connection.execute(
                        """
                        SELECT client_started_at, admitted_at
                        FROM test_runs
                        WHERE repo_id = ? AND run_kind != 'session'
                          AND julianday(client_started_at) >= julianday('now', ?)
                        """,
                        (repo_id, window),
                    )
                ]
                flake_rows = [
                    dict(row)
                    for row in connection.execute(
                        """
                        SELECT c.test_id,
                               MAX(c.status = 'passed') AS has_pass,
                               MAX(c.status IN ('failed', 'error')) AS has_failure
                        FROM test_case_results c
                        JOIN test_runs r USING(run_id)
                        WHERE r.repo_id = ?
                          AND julianday(r.client_started_at) >= julianday('now', ?)
                        GROUP BY c.test_id
                        """,
                        (repo_id, window),
                    )
                ]
                daily_flakes = {
                    str(row["day"]): dict(row)
                    for row in connection.execute(
                        """
                        WITH identities AS (
                            SELECT substr(r.client_started_at, 1, 10) AS day,
                                   c.test_id,
                                   MAX(c.status = 'passed') AS has_pass,
                                   MAX(c.status IN ('failed', 'error')) AS has_failure
                            FROM test_case_results c JOIN test_runs r USING(run_id)
                            WHERE r.repo_id = ?
                              AND julianday(r.client_started_at) >= julianday('now', ?)
                            GROUP BY day, c.test_id
                        )
                        SELECT day, COUNT(*) AS distinct_test_count,
                               SUM(has_pass AND has_failure) AS flaky_test_count
                        FROM identities GROUP BY day
                        """,
                        (repo_id, window),
                    )
                }
                previous_daily_flakes = {
                    str(row["day"]): dict(row)
                    for row in connection.execute(
                        """
                        WITH identities AS (
                            SELECT substr(r.client_started_at, 1, 10) AS day,
                                   c.test_id,
                                   MAX(c.status = 'passed') AS has_pass,
                                   MAX(c.status IN ('failed', 'error')) AS has_failure
                            FROM test_case_results c JOIN test_runs r USING(run_id)
                            WHERE r.repo_id = ?
                              AND julianday(r.client_started_at) >= julianday('now', ?)
                              AND julianday(r.client_started_at) < julianday('now', ?)
                            GROUP BY day, c.test_id
                        )
                        SELECT day, COUNT(*) AS distinct_test_count,
                               SUM(has_pass AND has_failure) AS flaky_test_count
                        FROM identities GROUP BY day
                        """,
                        (repo_id, f"-{days * 2} days", window),
                    )
                }
                observed_through = connection.execute(
                    """
                    SELECT MAX(updated_at) FROM test_runs WHERE repo_id = ?
                    """,
                    (repo_id,),
                ).fetchone()[0]
                # Split exact case intervals across UTC clock-hour buckets.
                # Parallel cases intentionally add together, so aggregate test
                # time can exceed 3,600 seconds in one wall-clock hour. Read
                # each relevant case once; the old case x 168-hour SQL join
                # let one large project monopolize the shared API for seconds.
                hourly = _hourly_case_statistics(
                    [
                        dict(row)
                        for row in connection.execute(
                            """
                            SELECT c.started_at, c.finished_at, c.status
                            FROM test_case_results c
                            JOIN test_runs r USING(run_id)
                            WHERE r.repo_id = ?
                              AND julianday(c.finished_at) > julianday('now', 'start of day', '-6 days')
                              AND julianday(c.started_at) < julianday('now', 'start of day', '+1 day')
                            """,
                            (repo_id,),
                        )
                    ]
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
                                   COALESCE(SUM(c.duration_seconds), 0) AS test_seconds,
                                   COALESCE(SUM(c.status = 'passed'), 0) AS passed_count,
                                   COALESCE(SUM(c.status IN ('failed', 'error')), 0)
                                       AS failure_count
                            FROM test_case_results c JOIN recent_runs r USING(run_id)
                            GROUP BY day
                        )
                        SELECT run_daily.day, run_count,
                               COALESCE(test_count, 0) AS test_count,
                               run_seconds, COALESCE(test_seconds, 0) AS test_seconds,
                               COALESCE(passed_count, 0) AS passed_count,
                               COALESCE(failure_count, 0) AS failure_count
                        FROM run_daily LEFT JOIN case_daily USING(day)
                        ORDER BY day DESC
                        """,
                        (repo_id, window),
                    )
                ]
                previous_daily = [
                    dict(row)
                    for row in connection.execute(
                        """
                        WITH previous_runs AS (
                            SELECT * FROM test_runs WHERE repo_id = ?
                              AND julianday(client_started_at) >= julianday('now', ?)
                              AND julianday(client_started_at) < julianday('now', ?)
                        ), run_daily AS (
                            SELECT substr(client_started_at, 1, 10) AS day,
                                   COUNT(*) AS run_count,
                                   COALESCE(SUM(duration_seconds), 0) AS run_seconds
                            FROM previous_runs WHERE run_kind != 'session' GROUP BY day
                        ), case_daily AS (
                            SELECT substr(r.client_started_at, 1, 10) AS day,
                                   COUNT(*) AS test_count,
                                   COALESCE(SUM(c.duration_seconds), 0) AS test_seconds,
                                   COALESCE(SUM(c.status = 'passed'), 0) AS passed_count,
                                   COALESCE(SUM(c.status IN ('failed', 'error')), 0)
                                       AS failure_count
                            FROM test_case_results c JOIN previous_runs r USING(run_id)
                            GROUP BY day
                        )
                        SELECT run_daily.day, run_count,
                               COALESCE(test_count, 0) AS test_count,
                               run_seconds, COALESCE(test_seconds, 0) AS test_seconds,
                               COALESCE(passed_count, 0) AS passed_count,
                               COALESCE(failure_count, 0) AS failure_count
                        FROM run_daily LEFT JOIN case_daily USING(day)
                        ORDER BY day DESC
                        """,
                        (repo_id, f"-{days * 2} days", window),
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
                dynamics = [
                    dict(row)
                    for row in connection.execute(
                        """
                        WITH current_suites AS (
                            SELECT r.suite,
                                   COALESCE(SUM(c.duration_seconds), 0) AS current_seconds,
                                   COALESCE(SUM(c.status IN ('failed', 'error')), 0) AS failure_count,
                                   MAX(r.client_started_at) AS last_run
                            FROM test_case_results c JOIN test_runs r USING(run_id)
                            WHERE r.repo_id = ?
                              AND julianday(r.client_started_at) >= julianday('now', ?)
                            GROUP BY r.suite
                        ), previous_suites AS (
                            SELECT r.suite,
                                   COALESCE(SUM(c.duration_seconds), 0) AS previous_seconds
                            FROM test_case_results c JOIN test_runs r USING(run_id)
                            WHERE r.repo_id = ?
                              AND julianday(r.client_started_at) >= julianday('now', ?)
                              AND julianday(r.client_started_at) < julianday('now', ?)
                            GROUP BY r.suite
                        ), suite_names AS (
                            SELECT suite FROM current_suites
                            UNION SELECT suite FROM previous_suites
                        )
                        SELECT names.suite,
                               COALESCE(current_seconds, 0) AS current_seconds,
                               COALESCE(previous_seconds, 0) AS previous_seconds,
                               CASE WHEN COALESCE(previous_seconds, 0) = 0 THEN NULL
                                    ELSE ROUND(100.0 * (COALESCE(current_seconds, 0) - previous_seconds)
                                               / previous_seconds, 3)
                               END AS change_percent,
                               COALESCE(failure_count, 0) AS failure_count,
                               last_run
                        FROM suite_names names
                        LEFT JOIN current_suites USING(suite)
                        LEFT JOIN previous_suites USING(suite)
                        ORDER BY ABS(COALESCE(current_seconds, 0) - COALESCE(previous_seconds, 0)) DESC,
                                 names.suite
                        LIMIT ?
                        """,
                        (
                            repo_id,
                            window,
                            repo_id,
                            f"-{days * 2} days",
                            window,
                            limit,
                        ),
                    )
                ]
                regression_row = connection.execute(
                    """
                    WITH current_tests AS (
                        SELECT c.test_id, MAX(c.display_name) AS display_name,
                               COUNT(*) AS executions,
                               AVG(c.duration_seconds) AS average_seconds,
                               SUM(c.status IN ('failed', 'error')) AS failure_count,
                               MAX(r.client_started_at) AS last_run
                        FROM test_case_results c JOIN test_runs r USING(run_id)
                        WHERE r.repo_id = ?
                          AND julianday(r.client_started_at) >= julianday('now', ?)
                        GROUP BY c.test_id
                    ), previous_tests AS (
                        SELECT c.test_id,
                               AVG(c.duration_seconds) AS average_seconds,
                               SUM(c.status IN ('failed', 'error')) AS failure_count
                        FROM test_case_results c JOIN test_runs r USING(run_id)
                        WHERE r.repo_id = ?
                          AND julianday(r.client_started_at) >= julianday('now', ?)
                          AND julianday(r.client_started_at) < julianday('now', ?)
                        GROUP BY c.test_id
                    )
                    SELECT current.test_id, current.display_name,
                           current.executions,
                           current.failure_count AS current_failure_count,
                           COALESCE(previous.failure_count, 0) AS previous_failure_count,
                           current.average_seconds AS current_average_seconds,
                           previous.average_seconds AS previous_average_seconds,
                           CASE WHEN previous.average_seconds IS NULL
                                     OR previous.average_seconds = 0 THEN NULL
                                ELSE ROUND(
                                    100.0 * (current.average_seconds - previous.average_seconds)
                                    / previous.average_seconds,
                                    3
                                )
                           END AS duration_change_percent,
                           current.last_run
                    FROM current_tests current
                    LEFT JOIN previous_tests previous USING(test_id)
                    WHERE current.failure_count > 0
                       OR (previous.average_seconds > 0
                           AND current.average_seconds > previous.average_seconds * 1.25)
                    ORDER BY
                        (current.failure_count - COALESCE(previous.failure_count, 0)) DESC,
                        current.failure_count DESC,
                        (current.average_seconds - COALESCE(previous.average_seconds, 0)) DESC,
                        current.test_id
                    LIMIT 1
                    """,
                    (
                        repo_id,
                        window,
                        repo_id,
                        f"-{days * 2} days",
                        window,
                    ),
                ).fetchone()
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
        for rows, flake_by_day in (
            (daily, daily_flakes),
            (previous_daily, previous_daily_flakes),
        ):
            for row in rows:
                run_seconds = float(row["run_seconds"] or 0)
                test_seconds = float(row["test_seconds"] or 0)
                passed_count = int(row["passed_count"] or 0)
                failure_count = int(row["failure_count"] or 0)
                flake = flake_by_day.get(str(row["day"]), {})
                distinct = int(flake.get("distinct_test_count") or 0)
                flaky = int(flake.get("flaky_test_count") or 0)
                row["parallel_efficiency_ratio"] = _ratio(
                    test_seconds, run_seconds
                )
                row["pass_rate"] = _rate(
                    passed_count, passed_count + failure_count
                )
                row["distinct_test_count"] = distinct
                row["flaky_test_count"] = flaky
                row["flake_rate"] = _rate(flaky, distinct)

        failed_or_error = int(summary["failed_count"] or 0) + int(
            summary["error_count"] or 0
        )
        passed = int(summary["passed_count"] or 0)
        distinct_test_count = len(flake_rows)
        flaky_test_count = sum(
            1
            for row in flake_rows
            if bool(row["has_pass"]) and bool(row["has_failure"])
        )
        efficiency = {
            "test_seconds": round(total_test_seconds, 3),
            "wall_seconds": round(total_run_seconds, 3),
            "parallel_efficiency_ratio": _ratio(
                total_test_seconds, total_run_seconds
            ),
            "p95_queue_wait_seconds": _nearest_rank_percentile(
                queue_waits, 0.95
            ),
        }
        health = {
            "passed_count": passed,
            "failure_count": failed_or_error,
            "pass_rate": _rate(passed, passed + failed_or_error),
            "distinct_test_count": distinct_test_count,
            "flaky_test_count": flaky_test_count,
            "flake_rate": _rate(flaky_test_count, distinct_test_count),
        }
        regression = dict(regression_row) if regression_row is not None else None
        if regression is not None:
            regression["kind"] = (
                "test_failure"
                if int(regression["current_failure_count"] or 0) > 0
                else "duration_regression"
            )
            regression["name"] = (
                str(regression["display_name"] or "").strip()
                or str(regression["test_id"])
            )
            regression["failure_count"] = int(
                regression["current_failure_count"] or 0
            )
            if regression["kind"] == "test_failure":
                regression["detail"] = (
                    f"{regression['failure_count']} failures in the current period; "
                    f"{int(regression['previous_failure_count'] or 0)} in the previous period"
                )
            else:
                regression["detail"] = (
                    f"Average duration increased by "
                    f"{float(regression['duration_change_percent'] or 0):.1f}%"
                )
        generated_at = _iso_utc(datetime.now(UTC))
        snapshot_identity = {
            "repo_id": repo_id,
            "days": days,
            "observed_through": observed_through,
            "run_count": summary["run_count"],
            "test_count": summary["test_count"],
        }
        return {
            "schema_version": 1,
            "repo_id": repo_id,
            "days": days,
            "snapshot": {
                "generated_at": generated_at,
                "observed_through": observed_through,
                "source": "coordinator-test-store",
                "source_revision": _canonical_fingerprint(snapshot_identity),
                "retention": {"eligible": True, "max_age_seconds": 86_400},
            },
            "summary": summary,
            "comparison_summary": comparison_summary,
            "efficiency": efficiency,
            "health": health,
            "avoided_work": _empty_avoided_work(),
            "hourly": hourly,
            "daily": daily,
            "previous_daily": previous_daily,
            "series": {"daily": daily, "previous_daily": previous_daily},
            "suites": suite_rows,
            "slow_tests": test_rows,
            "recent_runs": recent_runs,
            "dynamics": dynamics,
            "top_actionable_regression": regression,
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
