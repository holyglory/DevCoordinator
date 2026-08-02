#!/usr/bin/env python3
"""Create or verify the root-owned DevCoordinator authority runtime manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any, Iterable


SCHEMA = "devcoordinator.authority-runtime-manifest.v1"
DEFAULT_RUNTIME_ROOT = Path("/opt/devcoordinator-authority")
DEFAULT_REQUIREMENTS = Path(
    "/home/DevCoordinator/skills/codex-dev-coordinator/"
    "requirements-infrastructure-ingress.txt"
)
DEFAULT_MANIFEST = Path(
    "/etc/devcoordinator/authority-runtime-manifest.json"
)
MAX_FILES = 20_000
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
APPROVED_INTERPRETER = {
    "implementation": "cpython",
    "python": "3.14",
    "platform": "linux",
    "machine": "x86_64",
}


class RuntimeVerificationError(RuntimeError):
    """The authority interpreter or its immutable dependency tree drifted."""


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _sha256_file(
    path: Path,
    *,
    maximum: int,
    expected_uid: int | None = 0,
) -> tuple[str, int]:
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
            raise RuntimeVerificationError(
                f"untrusted authority runtime file: {path}"
            )
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > maximum:
                raise RuntimeVerificationError(
                    f"authority runtime file exceeds bound: {path}"
                )
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest(), size


def _require_trusted_directory(path: Path) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RuntimeVerificationError(
            f"untrusted authority runtime directory: {path}"
        )


def _require_trusted_components(path: Path) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise RuntimeVerificationError("authority runtime path is not absolute")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        _require_trusted_directory(current)


def _runtime_files(root: Path) -> list[dict[str, Any]]:
    _require_trusted_components(root)
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        metadata = path.lstat()
        relative = path.relative_to(root).as_posix()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise RuntimeVerificationError(
                f"authority runtime entry is writable or linked: {relative}"
            )
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RuntimeVerificationError(
                f"authority runtime entry is not one regular file: {relative}"
            )
        digest, size = _sha256_file(path, maximum=MAX_FILE_BYTES)
        records.append(
            {
                "path": relative,
                "sha256": digest,
                "size": size,
                "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            }
        )
        if len(records) > MAX_FILES:
            raise RuntimeVerificationError(
                "authority runtime file count exceeds bound"
            )
    python_record = next(
        (item for item in records if item["path"] == "bin/python"),
        None,
    )
    if python_record is None or not int(str(python_record["mode"]), 8) & 0o111:
        raise RuntimeVerificationError(
            "authority runtime has no trusted executable bin/python"
        )
    return records


def _interpreter_contract(python: Path) -> dict[str, str]:
    probe = (
        "import json,platform,sys;"
        "print(json.dumps({"
        "'implementation':sys.implementation.name,"
        "'major':sys.version_info.major,'minor':sys.version_info.minor,"
        "'platform':sys.platform,'machine':platform.machine()"
        "},sort_keys=True,separators=(',',':')))"
    )
    completed = subprocess.run(
        [str(python), "-I", "-B", "-c", probe],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        check=False,
        env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    if completed.returncode or completed.stderr:
        raise RuntimeVerificationError(
            "authority interpreter contract probe failed"
        )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeVerificationError(
            "authority interpreter contract is invalid"
        ) from error
    expected = {
        "implementation": "cpython",
        "major": 3,
        "minor": 14,
        "platform": "linux",
        "machine": "x86_64",
    }
    if value != expected:
        raise RuntimeVerificationError(
            "authority interpreter is not approved CPython 3.14/Linux x86_64"
        )
    return dict(APPROVED_INTERPRETER)


def _trusted_manifest(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o400
        or metadata.st_size > MAX_MANIFEST_BYTES
    ):
        raise RuntimeVerificationError("authority runtime manifest is untrusted")
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeVerificationError(
            "authority runtime manifest is invalid JSON"
        ) from error
    if (
        not isinstance(document, dict)
        or _canonical_json(document).encode("utf-8") + b"\n" != raw
    ):
        raise RuntimeVerificationError(
            "authority runtime manifest is not canonical"
        )
    return document


def _build_static_manifest(root: Path, requirements: Path) -> dict[str, Any]:
    """Hash and inspect the entire runtime without executing any runtime byte."""

    records = _runtime_files(root)
    requirements_digest, requirements_size = _sha256_file(
        requirements,
        maximum=1024 * 1024,
        expected_uid=None,
    )
    return {
        "schema": SCHEMA,
        "runtime_root": str(root),
        "requirements": {
            "path": str(requirements),
            "sha256": requirements_digest,
            "size": requirements_size,
        },
        "files": records,
    }


def build_manifest(root: Path, requirements: Path) -> dict[str, Any]:
    document = _build_static_manifest(root, requirements)
    document["interpreter"] = _interpreter_contract(root / "bin/python")
    return document


def create_manifest(
    root: Path,
    requirements: Path,
    output: Path,
    *,
    recorded_runtime_root: Path | None = None,
) -> None:
    if os.geteuid() != 0:
        raise PermissionError("authority runtime manifest creation requires root")
    _require_trusted_directory(output.parent)
    # Persist the complete static approval boundary before the first execution
    # of any candidate byte. The approved interpreter contract is a policy
    # constant; verify_manifest rehashes the whole candidate against this
    # create-new file and only then executes bin/python to prove the contract.
    document = _build_static_manifest(root, requirements)
    document["interpreter"] = dict(APPROVED_INTERPRETER)
    if recorded_runtime_root is not None:
        if not recorded_runtime_root.is_absolute() or ".." in recorded_runtime_root.parts:
            raise RuntimeVerificationError(
                "recorded authority runtime root is not absolute"
            )
        document["runtime_root"] = str(recorded_runtime_root)
    raw = _canonical_json(document).encode("utf-8") + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(output, flags, 0o400)
    try:
        offset = 0
        view = memoryview(raw)
        while offset < len(raw):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise RuntimeVerificationError(
                    "authority runtime manifest write was incomplete"
                )
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
    finally:
        os.close(descriptor)
    verify_manifest(
        root,
        requirements,
        output,
        recorded_runtime_root=recorded_runtime_root,
    )


def verify_manifest(
    root: Path,
    requirements: Path,
    manifest: Path,
    *,
    recorded_runtime_root: Path | None = None,
) -> None:
    document = _trusted_manifest(manifest)
    expected = _build_static_manifest(root, requirements)
    if recorded_runtime_root is not None:
        if not recorded_runtime_root.is_absolute() or ".." in recorded_runtime_root.parts:
            raise RuntimeVerificationError(
                "recorded authority runtime root is not absolute"
            )
        expected["runtime_root"] = str(recorded_runtime_root)
    expected["interpreter"] = dict(APPROVED_INTERPRETER)
    if document != expected:
        raise RuntimeVerificationError(
            "authority runtime does not match its approved manifest"
        )
    # Only now is execution allowed: every runtime file, including bin/python,
    # has already matched the root-owned create-new manifest byte for byte.
    observed_interpreter = _interpreter_contract(root / "bin/python")
    if observed_interpreter != document["interpreter"]:
        raise RuntimeVerificationError(
            "authority interpreter differs from its approved manifest"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("create", "verify"))
    parser.add_argument("--runtime-root", type=Path, default=DEFAULT_RUNTIME_ROOT)
    parser.add_argument("--requirements", type=Path, default=DEFAULT_REQUIREMENTS)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.action == "create":
            create_manifest(args.runtime_root, args.requirements, args.manifest)
        else:
            verify_manifest(args.runtime_root, args.requirements, args.manifest)
    except (OSError, PermissionError, RuntimeVerificationError) as error:
        print(
            _canonical_json(
                {
                    "ok": False,
                    "schema": SCHEMA,
                    "error": str(error),
                }
            )
        )
        return 1
    print(_canonical_json({"ok": True, "schema": SCHEMA}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
