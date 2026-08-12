#!/usr/bin/env python3
"""Capture and verify exact-ID project-runtime isolation migration evidence.

This administrator tool is deliberately read-only with respect to systemd,
Docker, and the Coordinator authority database.  It can publish signed audit
documents and update a private migration ledger only after an independently
performed, explicitly attributed lifecycle operation has changed the runtime
identity.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
COORDINATOR_SCRIPTS = ROOT / "skills/codex-dev-coordinator/scripts"
if str(COORDINATOR_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(COORDINATOR_SCRIPTS))

from devcoordinator.project_runtime_isolation import (  # noqa: E402
    ProjectIsolationError,
    capture_isolation_audit,
    create_migration_ledger,
    inspect_docker_cgroups,
    read_private_document,
    record_migration,
    validate_isolation_audit,
    validate_migration_ledger,
    verify_live_authority_binding,
    write_private_document,
)


def _absolute(value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return path


def _positive_hours(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("hours must be numeric") from error
    if not 0 < parsed <= 24 * 30:
        raise argparse.ArgumentTypeError("hours must be greater than zero and at most 720")
    return parsed


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    capture = commands.add_parser("capture", help="capture one exact live audit")
    capture.add_argument("--database", type=_absolute, required=True)
    capture.add_argument("--output", type=_absolute, required=True)
    capture.add_argument(
        "--docker-executable", type=_absolute, default=Path("/usr/bin/docker")
    )

    initialize = commands.add_parser(
        "ledger-init", help="create a no-clobber migration ledger from an audit"
    )
    initialize.add_argument("--audit", type=_absolute, required=True)
    initialize.add_argument("--output", type=_absolute, required=True)
    initialize.add_argument("--deadline-hours", type=_positive_hours, required=True)

    update = commands.add_parser(
        "ledger-record", help="record independent migration evidence in place"
    )
    update.add_argument("--ledger", type=_absolute, required=True)
    update.add_argument("--audit", type=_absolute, required=True)
    update.add_argument("--resource-kind", choices=("docker", "service"), required=True)
    update.add_argument("--resource-id", required=True)
    update.add_argument("--operation-id", required=True)
    update.add_argument("--outcome", choices=("completed", "retired"), required=True)
    update.add_argument("--expected-ledger-sha256", required=True)

    verify = commands.add_parser("verify", help="verify audit and optional ledger")
    verify.add_argument("--audit", type=_absolute, required=True)
    verify.add_argument("--database", type=_absolute)
    verify.add_argument("--ledger", type=_absolute)
    verify.add_argument("--require-fresh", action="store_true")
    return parser.parse_args(argv)


def _capture(args: argparse.Namespace) -> dict[str, object]:
    audit = capture_isolation_audit(
        database_path=args.database,
        docker_cgroup_reader=lambda identities: inspect_docker_cgroups(
            identities, docker_executable=args.docker_executable
        ),
    )
    write_private_document(args.output, audit)
    return {
        "ok": True,
        "kind": "project-runtime-isolation-audit",
        "output": str(args.output),
        "evidence_sha256": audit["evidence_sha256"],
        "source_schema_version": audit["source_schema_version"],
        "counts": audit["counts"],
        "project_isolation_complete": audit["project_isolation_complete"],
        "valid_until": audit["valid_until"],
    }


def _ledger_init(args: argparse.Namespace) -> dict[str, object]:
    audit = validate_isolation_audit(read_private_document(args.audit))
    now = datetime.now(timezone.utc)
    ledger = create_migration_ledger(
        audit,
        deadline=now + timedelta(hours=args.deadline_hours),
        now=now,
    )
    write_private_document(args.output, ledger)
    return {
        "ok": True,
        "kind": "project-runtime-isolation-migration-ledger",
        "output": str(args.output),
        "evidence_sha256": ledger["evidence_sha256"],
        "counts": ledger["counts"],
        "deadline": ledger["deadline"],
    }


def _ledger_record(args: argparse.Namespace) -> dict[str, object]:
    ledger = validate_migration_ledger(read_private_document(args.ledger))
    if ledger["evidence_sha256"] != args.expected_ledger_sha256:
        raise ProjectIsolationError("migration ledger changed before update")
    audit = validate_isolation_audit(read_private_document(args.audit))
    updated = record_migration(
        ledger,
        audit=audit,
        resource_kind=args.resource_kind,
        resource_id=args.resource_id,
        operation_id=args.operation_id,
        outcome=args.outcome,
    )
    write_private_document(
        args.ledger,
        updated,
        replace=True,
        expected_sha256=args.expected_ledger_sha256,
    )
    return {
        "ok": True,
        "kind": "project-runtime-isolation-migration-ledger",
        "output": str(args.ledger),
        "evidence_sha256": updated["evidence_sha256"],
        "counts": updated["counts"],
        "project_isolation_complete": (
            updated["counts"]["pending"] == 0
            and audit["project_isolation_complete"]
        ),
    }


def _verify(args: argparse.Namespace) -> dict[str, object]:
    audit = validate_isolation_audit(
        read_private_document(args.audit), require_fresh=args.require_fresh
    )
    if args.database is not None:
        audit = verify_live_authority_binding(
            audit,
            database_path=args.database,
        )
    result: dict[str, object] = {
        "ok": True,
        "kind": "project-runtime-isolation-verification",
        "audit_sha256": audit["evidence_sha256"],
        "source_schema_version": audit["source_schema_version"],
        "audit_counts": audit["counts"],
        "project_isolation_complete": audit["project_isolation_complete"],
    }
    if args.ledger is not None:
        ledger = validate_migration_ledger(
            read_private_document(args.ledger), audit=audit
        )
        result.update(
            {
                "ledger_sha256": ledger["evidence_sha256"],
                "ledger_counts": ledger["counts"],
                "project_isolation_complete": bool(
                    audit["project_isolation_complete"]
                    and ledger["counts"]["pending"] == 0
                ),
            }
        )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "capture":
            result = _capture(args)
        elif args.command == "ledger-init":
            result = _ledger_init(args)
        elif args.command == "ledger-record":
            result = _ledger_record(args)
        else:
            result = _verify(args)
    except (OSError, ValueError, ProjectIsolationError) as error:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error_code": "project_runtime_isolation_failed",
                    "error": str(error),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
