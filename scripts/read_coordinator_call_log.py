#!/usr/bin/env python3
"""Read a bounded, sanitized view of retained Coordinator call records."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = ROOT / "skills" / "codex-dev-coordinator" / "scripts"
sys.path.insert(0, str(MODULE_ROOT))

from devcoordinator.call_journal import (  # noqa: E402
    CallJournalPageError,
    DEFAULT_CALL_JOURNAL_PAGE_RECORDS,
    DEFAULT_CALL_JOURNAL_BACKUPS,
    DEFAULT_CALL_JOURNAL_PATH,
    MAX_CALL_JOURNAL_PAGE_BYTES,
    MAX_CALL_JOURNAL_PAGE_RECORDS,
    bounded_call_record_page,
    read_call_snapshot,
)


def _bounded_limit(value: str) -> int:
    parsed = int(value)
    if not 1 <= parsed <= MAX_CALL_JOURNAL_PAGE_RECORDS:
        raise argparse.ArgumentTypeError(
            f"must be from 1 through {MAX_CALL_JOURNAL_PAGE_RECORDS}"
        )
    return parsed


def _bounded_backups(value: str) -> int:
    parsed = int(value)
    if not 0 <= parsed <= 32:
        raise argparse.ArgumentTypeError("must be from 0 through 32")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--log",
        type=Path,
        default=DEFAULT_CALL_JOURNAL_PATH,
        help="base JSONL path (default: %(default)s)",
    )
    parser.add_argument(
        "--backups",
        type=_bounded_backups,
        default=DEFAULT_CALL_JOURNAL_BACKUPS,
        help="number of numbered rotations to inspect (default: %(default)s)",
    )
    parser.add_argument(
        "--limit",
        type=_bounded_limit,
        default=DEFAULT_CALL_JOURNAL_PAGE_RECORDS,
        help="return at most the newest N matching records (default: %(default)s)",
    )
    parser.add_argument(
        "--before",
        help="continue with records older than the prior page's next_cursor",
    )
    parser.add_argument("--failures-only", action="store_true")
    parser.add_argument("--boundary")
    parser.add_argument("--call-id")
    parser.add_argument("--operation-id")
    parser.add_argument("--request-id")
    parser.add_argument("--operation")
    parser.add_argument("--project-id")
    parser.add_argument("--repository-id")
    parser.add_argument("--run-id")
    parser.add_argument("--attempt-id")
    parser.add_argument("--code")
    parser.add_argument("--peer-uid", type=int)
    parser.add_argument(
        "--format",
        choices=("json", "jsonl"),
        default="json",
    )
    return parser


def _filters(arguments: argparse.Namespace) -> dict[str, object]:
    return {
        key: value
        for key, value in (
            ("boundary", arguments.boundary),
            ("call_id", arguments.call_id),
            ("operation_id", arguments.operation_id),
            ("request_id", arguments.request_id),
            ("operation", arguments.operation),
            ("project_id", arguments.project_id),
            ("repository_id", arguments.repository_id),
            ("run_id", arguments.run_id),
            ("attempt_id", arguments.attempt_id),
            ("code", arguments.code),
            ("peer_uid", arguments.peer_uid),
        )
        if value is not None
    }


def _bounded_error(error: BaseException) -> bytes:
    message = " ".join(str(error).replace("\x00", " ").split())[:512]
    return (
        json.dumps(
            {
                "schema_version": 1,
                "ok": False,
                "classification": "coordinator_call_journal_error",
                "code": "call_journal_page_invalid",
                "message": message,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if not arguments.log.is_absolute():
        raise SystemExit("--log must be absolute")
    snapshot, files = read_call_snapshot(
        arguments.log,
        backups=arguments.backups,
    )
    try:
        encoded = bounded_call_record_page(
            snapshot,
            filters=_filters(arguments),
            failures_only=arguments.failures_only,
            limit=arguments.limit,
            before=arguments.before,
            retained_byte_count=sum(int(item["bytes"]) for item in files),
            retained_file_count=len(files),
            output_format=arguments.format,
        )
    except CallJournalPageError as error:
        encoded = _bounded_error(error)
        if len(encoded) > MAX_CALL_JOURNAL_PAGE_BYTES:
            raise AssertionError("call journal error exceeded its output byte bound")
        sys.stdout.buffer.write(encoded)
        return 2
    if len(encoded) > MAX_CALL_JOURNAL_PAGE_BYTES or not encoded.endswith(b"\n"):
        raise AssertionError("call journal reader violated its final output contract")
    sys.stdout.buffer.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
