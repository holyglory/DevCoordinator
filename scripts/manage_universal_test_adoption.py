#!/usr/bin/python3
"""Evidence-gated root administrator for fleet test-manifest adoption."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from typing import Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = ROOT / "skills" / "codex-dev-coordinator" / "scripts"
if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

from devcoordinator.universal_test_adoption import (  # noqa: E402
    TestManifestAdoptionManager,
)
from devcoordinator.store import refuse_symlink_components  # noqa: E402
from devcoordinator.universal_test_snapshot_service import (  # noqa: E402
    SnapshotAuthority,
    UIDHelperRunner,
)
from devcoordinator.universal_test_store import TestStoreContractError  # noqa: E402


MAX_REQUEST_BYTES = 64 * 1024 * 1024


def _read_bounded(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, MAX_REQUEST_BYTES + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_REQUEST_BYTES:
            raise TestStoreContractError("manifest adoption request is too large")


def _private_request_payload(path: Path, *, expected_uid: int) -> bytes:
    path = path.absolute()
    refuse_symlink_components(path)
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_mode & 0o077
        or metadata.st_size > MAX_REQUEST_BYTES
    ):
        raise TestStoreContractError("manifest adoption request file is unsafe")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
            raise TestStoreContractError("manifest adoption request identity changed")
        payload = _read_bounded(descriptor)
    finally:
        os.close(descriptor)
    if len(payload) != metadata.st_size:
        raise TestStoreContractError("manifest adoption request changed while reading")
    return payload


def _private_request(path: Path, *, expected_uid: int) -> Mapping[str, object]:
    payload = _private_request_payload(path, expected_uid=expected_uid)
    value = json.loads(payload)
    if not isinstance(value, Mapping):
        raise TestStoreContractError("manifest adoption request must be an object")
    return value


def _write_private_once(
    path: Path, value: Mapping[str, object], *, expected_uid: int
) -> str:
    path = path.absolute()
    parent = path.parent
    refuse_symlink_components(parent)
    metadata = parent.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_mode & 0o077
    ):
        raise TestStoreContractError(
            "manifest adoption request output parent is unsafe"
        )
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if not payload or len(payload) > MAX_REQUEST_BYTES:
        raise TestStoreContractError("manifest adoption request is too large")
    digest = hashlib.sha256(payload).hexdigest()
    if path.exists() or path.is_symlink():
        existing = _private_request_payload(
            path, expected_uid=expected_uid
        )
        if existing != payload:
            raise TestStoreContractError(
                "manifest adoption request output belongs to another request"
            )
        return hashlib.sha256(existing).hexdigest()
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".manifest-adoption-request-", dir=parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary, path, follow_symlinks=False)
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError as error:
        raise TestStoreContractError(
            "manifest adoption request output appeared concurrently"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    return digest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="manage-universal-test-adoption")
    parser.add_argument(
        "--authority-database",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--helper",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--evidence-root",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--execution-uid",
        type=int,
        required=True,
        help="positive local account used for repository-side file changes",
    )
    actions = parser.add_subparsers(dest="action", required=True)
    catalog = actions.add_parser("catalog")
    catalog.add_argument("--authority-export", type=Path, required=True)
    prepare = actions.add_parser("prepare-request")
    prepare.add_argument("--authority-export", type=Path, required=True)
    prepare.add_argument("--manifest-set", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    plan = actions.add_parser("plan")
    plan.add_argument("--request", type=Path, required=True)
    apply = actions.add_parser("apply")
    apply.add_argument("--plan-id", required=True)
    apply.add_argument("--plan-sha256", required=True)
    rollback = actions.add_parser("rollback")
    rollback.add_argument("--plan-id", required=True)
    rollback.add_argument("--result-sha256", required=True)
    return parser


def run(arguments: argparse.Namespace) -> Mapping[str, object]:
    uid = os.geteuid()
    if uid != 0:
        raise TestStoreContractError("fleet test-manifest adoption requires root")
    manager = TestManifestAdoptionManager(
        authority=SnapshotAuthority(arguments.authority_database, expected_uid=uid),
        helper=UIDHelperRunner(arguments.helper, expected_helper_uid=uid),
        evidence_root=arguments.evidence_root,
        execution_uid=arguments.execution_uid,
        expected_evidence_uid=uid,
    )
    if arguments.action == "catalog":
        return manager.catalog(
            _private_request(arguments.authority_export, expected_uid=uid)
        )
    if arguments.action == "prepare-request":
        request = manager.prepare_request(
            _private_request(arguments.authority_export, expected_uid=uid),
            _private_request(arguments.manifest_set, expected_uid=uid),
        )
        digest = _write_private_once(arguments.output, request, expected_uid=uid)
        return {
            "schema_version": 1,
            "ok": True,
            "request_path": str(arguments.output.absolute()),
            "request_sha256": digest,
            "repository_count": len(request["repositories"]),
        }
    if arguments.action == "plan":
        return manager.plan(_private_request(arguments.request, expected_uid=uid))
    if arguments.action == "apply":
        return manager.apply(
            plan_id=arguments.plan_id, plan_sha256=arguments.plan_sha256
        )
    return manager.rollback(
        plan_id=arguments.plan_id, result_sha256=arguments.result_sha256
    )


def main(argv: Sequence[str] | None = None) -> int:
    try:
        result = run(build_parser().parse_args(argv))
    except Exception as error:
        result = {
            "schema_version": 1,
            "ok": False,
            "error": str(error)[:2048],
        }
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
