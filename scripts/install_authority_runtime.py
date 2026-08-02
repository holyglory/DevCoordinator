#!/usr/bin/env python3
"""Transactionally build, activate, verify, or roll back the authority runtime."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
from typing import Any, Iterable
import uuid


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = Path("/opt/devcoordinator-authority")
MANIFEST = Path("/etc/devcoordinator/authority-runtime-manifest.json")
REQUIREMENTS = (
    ROOT
    / "skills"
    / "codex-dev-coordinator"
    / "requirements-infrastructure-ingress.txt"
)
DEPENDENCY_CHECK = (
    ROOT
    / "skills"
    / "codex-dev-coordinator"
    / "scripts"
    / "validate_runtime_dependencies.py"
)
VERIFIER_PATH = ROOT / "scripts/verify_authority_runtime.py"
SYSTEM_PYTHON = Path("/usr/bin/python3.14")
LOCK_PATH = Path("/run/devcoordinator-authority-runtime-install.lock")
JOURNAL_NAME = "authority-runtime-journal.json"
JOURNAL_SCHEMA = "devcoordinator.authority-runtime-transaction.v1"
CONSUMER_UNITS = (
    "devcoordinator-broker.service",
    "devcoordinator-infrastructure-ingress.service",
)
MAX_WHEELS = 128
MAX_WHEEL_BYTES = 128 * 1024 * 1024
SAFE_ENVIRONMENT = {
    "DEVCOORDINATOR_AUTHORITY": "service",
    "DOCKER_CONFIG": "/var/lib/devcoordinator/docker",
    "HOME": "/root",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "PYTHONDONTWRITEBYTECODE": "1",
}


class RuntimeInstallError(RuntimeError):
    """The authority runtime transaction could not preserve its contract."""


def _load_verifier() -> Any:
    specification = importlib.util.spec_from_file_location(
        "devcoordinator_authority_runtime_verifier",
        VERIFIER_PATH,
    )
    if specification is None or specification.loader is None:
        raise RuntimeInstallError("authority runtime verifier cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


VERIFIER = _load_verifier()


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_private_directory(path: Path) -> Path:
    absolute = path.expanduser().absolute()
    if (
        not absolute.is_absolute()
        or ".." in absolute.parts
        or absolute.is_symlink()
        or absolute.resolve() != absolute
    ):
        raise RuntimeInstallError("transaction path is not one real absolute path")
    metadata = absolute.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise RuntimeInstallError(
            "transaction directory must be root-owned mode 0700"
        )
    return absolute


def _create_transaction(path: Path) -> Path:
    absolute = path.expanduser().absolute()
    if not absolute.is_absolute() or ".." in absolute.parts:
        raise RuntimeInstallError("transaction path must be absolute")
    if os.path.lexists(absolute):
        raise RuntimeInstallError("transaction path must be create-new")
    absolute.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = absolute.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != 0
        or stat.S_IMODE(parent.st_mode) & 0o077
    ):
        raise RuntimeInstallError(
            "transaction parent must be private and root-owned"
        )
    absolute.mkdir(mode=0o700)
    os.chown(absolute, 0, 0)
    os.chmod(absolute, 0o700)
    _fsync_directory(absolute.parent)
    return _require_private_directory(absolute)


def _write_journal(transaction: Path, document: dict[str, Any]) -> None:
    destination = transaction / JOURNAL_NAME
    temporary = transaction / f".{JOURNAL_NAME}.{uuid.uuid4()}.tmp"
    raw = _canonical_json(document)
    descriptor = os.open(
        temporary,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise RuntimeInstallError("journal write made no progress")
            offset += written
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, destination)
    _fsync_directory(transaction)


def _read_journal(transaction: Path) -> dict[str, Any]:
    transaction = _require_private_directory(transaction)
    path = transaction / JOURNAL_NAME
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > 1024 * 1024
    ):
        raise RuntimeInstallError("authority runtime journal is untrusted")
    raw = path.read_bytes()
    document = json.loads(raw)
    if (
        not isinstance(document, dict)
        or document.get("schema") != JOURNAL_SCHEMA
        or _canonical_json(document) != raw
        or document.get("transaction") != str(transaction)
    ):
        raise RuntimeInstallError("authority runtime journal is invalid")
    return document


def _run(
    arguments: list[str],
    *,
    timeout: int = 300,
    check: bool = True,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
        env=dict(SAFE_ENVIRONMENT if environment is None else environment),
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeInstallError(
            f"command failed ({arguments[0]}): {detail or completed.returncode}"
        )
    return completed


def _sha256_regular(
    path: Path,
    *,
    maximum: int,
    expected_uid: int | None = 0,
) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    size = 0
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (
                expected_uid is not None
                and metadata.st_uid != expected_uid
            )
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise RuntimeInstallError(f"untrusted file: {path}")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > maximum:
                raise RuntimeInstallError(f"file exceeds bound: {path}")
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return {"sha256": digest.hexdigest(), "size": size}


def _wheelhouse_evidence(path: Path) -> dict[str, Any]:
    absolute = path.expanduser().absolute()
    if (
        not absolute.is_absolute()
        or ".." in absolute.parts
        or absolute.is_symlink()
        or absolute.resolve() != absolute
    ):
        raise RuntimeInstallError("wheelhouse must be one real absolute path")
    metadata = absolute.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RuntimeInstallError("wheelhouse must be root-owned and non-writable")
    entries: list[dict[str, Any]] = []
    for child in sorted(absolute.iterdir(), key=lambda item: item.name):
        if child.name.startswith(".") or child.suffix != ".whl":
            raise RuntimeInstallError(
                "wheelhouse may contain only reviewed wheel files"
            )
        evidence = _sha256_regular(child, maximum=MAX_WHEEL_BYTES)
        entries.append({"name": child.name, **evidence})
        if len(entries) > MAX_WHEELS:
            raise RuntimeInstallError("wheelhouse file count exceeds bound")
    if not entries:
        raise RuntimeInstallError("wheelhouse contains no wheels")
    return {
        "path": str(absolute),
        "files": entries,
        "set_sha256": hashlib.sha256(
            _canonical_json(entries)
        ).hexdigest(),
    }


def _unit_state(unit: str) -> dict[str, str]:
    completed = _run(
        [
            "/usr/bin/systemctl",
            "show",
            unit,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=UnitFileState",
        ],
        timeout=30,
        check=False,
    )
    values = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    return {
        "load_state": values.get("LoadState", "not-found"),
        "active_state": values.get("ActiveState", "inactive"),
        "sub_state": values.get("SubState", "dead"),
        "unit_file_state": values.get("UnitFileState", ""),
    }


def _capture_services() -> dict[str, dict[str, str]]:
    return {unit: _unit_state(unit) for unit in CONSUMER_UNITS}


def _stop_consumers() -> None:
    for unit in CONSUMER_UNITS:
        state = _unit_state(unit)
        if state["load_state"] == "not-found":
            continue
        _run(["/usr/bin/systemctl", "stop", unit], timeout=120)
        if _unit_state(unit)["active_state"] not in {"inactive", "failed"}:
            raise RuntimeInstallError(f"authority runtime consumer did not stop: {unit}")


def _restore_services(states: dict[str, Any]) -> None:
    for unit in CONSUMER_UNITS:
        expected = states.get(unit)
        if not isinstance(expected, dict):
            raise RuntimeInstallError("saved authority consumer state is invalid")
        current = _unit_state(unit)
        if expected.get("active_state") == "active":
            if current["load_state"] == "not-found":
                raise RuntimeInstallError(
                    f"previously active authority consumer is now missing: {unit}"
                )
            _run(["/usr/bin/systemctl", "start", unit], timeout=120)
            if _unit_state(unit)["active_state"] != "active":
                raise RuntimeInstallError(
                    f"authority runtime consumer did not recover: {unit}"
                )
        elif current["load_state"] != "not-found" and current["active_state"] not in {
            "inactive",
            "failed",
        }:
            _run(["/usr/bin/systemctl", "stop", unit], timeout=120)


def _prepare_runtime_parent(path: Path, *, mode: int) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RuntimeInstallError(f"unsafe authority runtime parent: {path}")


def _remove_expected_venv_link(candidate: Path) -> None:
    lib64 = candidate / "lib64"
    if lib64.is_symlink():
        lib64.unlink()
    for entry in candidate.rglob("*"):
        if entry.is_symlink():
            raise RuntimeInstallError(
                f"candidate authority runtime retains a symlink: {entry}"
            )


def _normalize_runtime_ownership(candidate: Path) -> None:
    for entry in [candidate, *candidate.rglob("*")]:
        if entry.is_symlink():
            raise RuntimeInstallError("authority runtime contains a symlink")
        metadata = entry.lstat()
        os.chown(entry, 0, 0)
        os.chmod(entry, stat.S_IMODE(metadata.st_mode) & ~0o022)


def _build_candidate(
    *,
    candidate: Path,
    candidate_manifest: Path,
    builder: Path,
    wheelhouse: Path,
) -> dict[str, Any]:
    if not SYSTEM_PYTHON.is_file() or SYSTEM_PYTHON.is_symlink():
        raise RuntimeInstallError("approved /usr/bin/python3.14 is missing or linked")
    if not REQUIREMENTS.is_file() or REQUIREMENTS.is_symlink():
        raise RuntimeInstallError("production authority requirements lock is missing")
    _run(
        [
            str(SYSTEM_PYTHON),
            "-I",
            "-B",
            "-m",
            "venv",
            "--copies",
            str(candidate),
        ],
        timeout=120,
    )
    _run(
        [
            str(SYSTEM_PYTHON),
            "-I",
            "-B",
            "-m",
            "venv",
            "--copies",
            str(builder),
        ],
        timeout=120,
    )
    builder_python = builder / "bin/python"
    _run(
        [
            str(builder_python),
            "-I",
            "-B",
            "-m",
            "pip",
            "--isolated",
            "--python",
            str(candidate),
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--no-index",
            "--find-links",
            str(wheelhouse),
            "--no-deps",
            "--only-binary=:all:",
            "--require-hashes",
            "--requirement",
            str(REQUIREMENTS),
        ],
        timeout=300,
    )
    _remove_expected_venv_link(candidate)
    _normalize_runtime_ownership(candidate)
    VERIFIER.create_manifest(
        candidate,
        REQUIREMENTS,
        candidate_manifest,
        recorded_runtime_root=RUNTIME_ROOT,
    )
    manifest_evidence = _sha256_regular(
        candidate_manifest,
        maximum=VERIFIER.MAX_MANIFEST_BYTES,
    )
    VERIFIER.verify_manifest(
        candidate,
        REQUIREMENTS,
        candidate_manifest,
        recorded_runtime_root=RUNTIME_ROOT,
    )
    # Candidate execution is permitted only after its full static file set was
    # hashed into the root-owned create-new manifest above.
    dependency = _run(
        [
            str(candidate / "bin/python"),
            "-I",
            "-B",
            str(DEPENDENCY_CHECK),
        ],
        timeout=60,
        environment={
            **SAFE_ENVIRONMENT,
            "DEVCOORDINATOR_AUTHORITY": "candidate",
        },
    )
    try:
        dependency_evidence = json.loads(dependency.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeInstallError(
            "candidate dependency verifier returned invalid JSON"
        ) from error
    if not isinstance(dependency_evidence, dict) or dependency_evidence.get("ok") is not True:
        raise RuntimeInstallError("candidate dependency verifier did not pass")
    return {
        "manifest": manifest_evidence,
        "dependency": dependency_evidence,
    }


def _live_pair_state() -> str:
    runtime_exists = os.path.lexists(RUNTIME_ROOT)
    manifest_exists = os.path.lexists(MANIFEST)
    if runtime_exists != manifest_exists:
        raise RuntimeInstallError(
            "live authority runtime and manifest are not one complete pair"
        )
    if not runtime_exists:
        return "absent"
    VERIFIER.verify_manifest(RUNTIME_ROOT, REQUIREMENTS, MANIFEST)
    return "verified"


def _verify_live() -> dict[str, Any]:
    VERIFIER.verify_manifest(RUNTIME_ROOT, REQUIREMENTS, MANIFEST)
    manifest = _sha256_regular(
        MANIFEST,
        maximum=VERIFIER.MAX_MANIFEST_BYTES,
    )
    completed = _run(
        [
            str(RUNTIME_ROOT / "bin/python"),
            "-I",
            "-B",
            str(DEPENDENCY_CHECK),
        ],
        timeout=60,
    )
    dependency = json.loads(completed.stdout)
    if not isinstance(dependency, dict) or dependency.get("ok") is not True:
        raise RuntimeInstallError("active authority dependency verifier did not pass")
    return {"manifest": manifest, "dependency": dependency}


def _rename(source: Path, destination: Path) -> None:
    if os.path.lexists(destination):
        raise RuntimeInstallError(f"atomic activation destination exists: {destination}")
    os.rename(source, destination)
    _fsync_directory(destination.parent)


def _retained_path(path: Path, operation_id: str, label: str) -> Path:
    return path.parent / f".{path.name}.{label}.{operation_id}"


def _rollback_generation(
    document: dict[str, Any],
    *,
    restore_services: bool,
) -> None:
    operation_id = str(document["operation_id"])
    previous_runtime = Path(str(document["paths"]["previous_runtime"]))
    previous_manifest = Path(str(document["paths"]["previous_manifest"]))
    failed_runtime = _retained_path(RUNTIME_ROOT, operation_id, "failed")
    failed_manifest = _retained_path(MANIFEST, operation_id, "failed")
    _stop_consumers()
    previous_state = str(document["previous_generation"])
    if previous_state == "verified":
        if os.path.lexists(previous_runtime):
            if os.path.lexists(RUNTIME_ROOT):
                _rename(RUNTIME_ROOT, failed_runtime)
            _rename(previous_runtime, RUNTIME_ROOT)
        elif not os.path.lexists(RUNTIME_ROOT):
            raise RuntimeInstallError("previous authority runtime is missing")
        if os.path.lexists(previous_manifest):
            if os.path.lexists(MANIFEST):
                _rename(MANIFEST, failed_manifest)
            _rename(previous_manifest, MANIFEST)
        elif not os.path.lexists(MANIFEST):
            raise RuntimeInstallError("previous authority manifest is missing")
        VERIFIER.verify_manifest(RUNTIME_ROOT, REQUIREMENTS, MANIFEST)
    elif previous_state == "absent":
        if os.path.lexists(RUNTIME_ROOT):
            _rename(RUNTIME_ROOT, failed_runtime)
        if os.path.lexists(MANIFEST):
            _rename(MANIFEST, failed_manifest)
    else:
        raise RuntimeInstallError("saved previous authority generation is invalid")
    if restore_services:
        _restore_services(document["service_states"])


def apply_runtime(
    *,
    wheelhouse: Path,
    transaction_path: Path,
    restore_services: bool = True,
) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise PermissionError("authority runtime activation requires root")
    transaction = _create_transaction(transaction_path)
    operation_id = str(uuid.uuid4())
    _prepare_runtime_parent(RUNTIME_ROOT.parent, mode=0o755)
    _prepare_runtime_parent(MANIFEST.parent, mode=0o750)
    candidate = _retained_path(RUNTIME_ROOT, operation_id, "candidate")
    previous_runtime = _retained_path(RUNTIME_ROOT, operation_id, "previous")
    candidate_manifest = _retained_path(MANIFEST, operation_id, "candidate")
    previous_manifest = _retained_path(MANIFEST, operation_id, "previous")
    builder = transaction / "builder"
    wheelhouse_proof = _wheelhouse_evidence(wheelhouse)
    document: dict[str, Any] = {
        "schema": JOURNAL_SCHEMA,
        "status": "building",
        "operation_id": operation_id,
        "transaction": str(transaction),
        "requirements": {
            "path": str(REQUIREMENTS),
            **_sha256_regular(
                REQUIREMENTS,
                maximum=1024 * 1024,
                expected_uid=None,
            ),
        },
        "wheelhouse": wheelhouse_proof,
        "service_states": _capture_services(),
        "previous_generation": None,
        "paths": {
            "candidate_runtime": str(candidate),
            "candidate_manifest": str(candidate_manifest),
            "previous_runtime": str(previous_runtime),
            "previous_manifest": str(previous_manifest),
        },
        "restore_services": bool(restore_services),
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    _write_journal(transaction, document)
    activation_started = False
    try:
        document["candidate"] = _build_candidate(
            candidate=candidate,
            candidate_manifest=candidate_manifest,
            builder=builder,
            wheelhouse=wheelhouse,
        )
        document["status"] = "candidate-verified"
        _write_journal(transaction, document)
        previous_state = _live_pair_state()
        document["previous_generation"] = previous_state
        document["status"] = "consumers-stopping"
        _write_journal(transaction, document)
        _stop_consumers()
        document["status"] = "consumers-stopped"
        _write_journal(transaction, document)
        activation_started = True
        if previous_state == "verified":
            _rename(RUNTIME_ROOT, previous_runtime)
            document["status"] = "previous-runtime-retained"
            _write_journal(transaction, document)
            _rename(MANIFEST, previous_manifest)
            document["status"] = "previous-generation-retained"
            _write_journal(transaction, document)
        _rename(candidate, RUNTIME_ROOT)
        document["status"] = "runtime-activated"
        _write_journal(transaction, document)
        _rename(candidate_manifest, MANIFEST)
        document["status"] = "generation-activated"
        _write_journal(transaction, document)
        document["active"] = _verify_live()
        document["status"] = "active-verified"
        _write_journal(transaction, document)
        if restore_services:
            _restore_services(document["service_states"])
        document["status"] = "applied"
        document["completed_at"] = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(),
        )
        _write_journal(transaction, document)
        return document
    except BaseException as error:
        document["failure"] = f"{type(error).__name__}: {error}"
        if activation_started:
            try:
                _rollback_generation(
                    document,
                    restore_services=restore_services,
                )
                document["status"] = "failed-rolled-back"
            except BaseException as rollback_error:
                document["status"] = "rollback-failed"
                document["rollback_failure"] = (
                    f"{type(rollback_error).__name__}: {rollback_error}"
                )
        else:
            document["status"] = "build-failed"
            if restore_services:
                try:
                    _restore_services(document["service_states"])
                except BaseException as restore_error:
                    document["status"] = "service-restore-failed"
                    document["rollback_failure"] = (
                        f"{type(restore_error).__name__}: {restore_error}"
                    )
        _write_journal(transaction, document)
        raise


def rollback_runtime(
    transaction_path: Path,
    *,
    restore_services: bool = True,
) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise PermissionError("authority runtime rollback requires root")
    transaction = _require_private_directory(transaction_path)
    document = _read_journal(transaction)
    if document.get("status") != "applied":
        raise RuntimeInstallError(
            "authority runtime rollback requires one applied transaction"
        )
    active = _verify_live()
    expected = document.get("active", {}).get("manifest")
    if not isinstance(expected, dict) or active["manifest"] != expected:
        raise RuntimeInstallError(
            "active authority generation drifted; refusing rollback overwrite"
        )
    _rollback_generation(document, restore_services=restore_services)
    document["status"] = "rolled-back"
    document["rolled_back_at"] = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(),
    )
    _write_journal(transaction, document)
    return document


def verify_runtime() -> dict[str, Any]:
    if os.geteuid() != 0:
        raise PermissionError("authority runtime verification requires root")
    return {
        "schema": JOURNAL_SCHEMA,
        "status": "verified",
        **_verify_live(),
    }


def _lock() -> Any:
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    descriptor = os.open(
        LOCK_PATH,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    os.fchmod(descriptor, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return os.fdopen(descriptor, "r+")


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    apply = actions.add_parser("apply")
    apply.add_argument("--wheelhouse", type=Path, required=True)
    apply.add_argument("--transaction-dir", type=Path, required=True)
    apply.add_argument("--leave-services-stopped", action="store_true")
    rollback = actions.add_parser("rollback")
    rollback.add_argument("--transaction-dir", type=Path, required=True)
    rollback.add_argument("--leave-services-stopped", action="store_true")
    actions.add_parser("verify")
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        with _lock():
            if args.action == "apply":
                result = apply_runtime(
                    wheelhouse=args.wheelhouse,
                    transaction_path=args.transaction_dir,
                    restore_services=not args.leave_services_stopped,
                )
            elif args.action == "rollback":
                result = rollback_runtime(
                    args.transaction_dir,
                    restore_services=not args.leave_services_stopped,
                )
            else:
                result = verify_runtime()
    except (
        OSError,
        PermissionError,
        RuntimeInstallError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
    ) as error:
        print(
            json.dumps(
                {
                    "ok": False,
                    "schema": JOURNAL_SCHEMA,
                    "error": str(error),
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps({"ok": True, "result": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
