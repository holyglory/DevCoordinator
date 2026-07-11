#!/usr/bin/env python3
"""Create one durable, private, no-follow cutover phase marker."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from secure_cutover_io import SecureIOError, open_private_parent, read_at


class MarkerError(RuntimeError):
    pass


def write_marker(path: Path, phase: str) -> dict[str, object]:
    if phase not in {"state-migration-attempted", "relocation-attempted"}:
        raise MarkerError(f"unsupported cutover phase: {phase}")
    payload_object = {
        "schema_version": 1,
        "phase": phase,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    payload = (json.dumps(payload_object, indent=2, sort_keys=True) + "\n").encode("utf-8")
    parent, absolute, name = open_private_parent(path)
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=parent)
        except FileExistsError as error:
            raise MarkerError(f"cutover phase marker already exists: {absolute}") from error
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.fsync(parent)
        if read_at(parent, name, label="cutover phase marker") != payload:
            raise MarkerError(f"cutover phase marker verification failed: {absolute}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)
    return payload_object


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--marker", required=True)
    parser.add_argument(
        "--phase",
        required=True,
        choices=("state-migration-attempted", "relocation-attempted"),
    )
    args = parser.parse_args(argv)
    try:
        report = write_marker(Path(args.marker), args.phase)
    except (MarkerError, SecureIOError, OSError) as error:
        print(f"cutover phase marker failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, **report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
