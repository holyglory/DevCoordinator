"""Socket-activated root snapshot service entrypoint."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import pwd
import socket
from typing import Sequence

from .universal_test_snapshot_service import (
    RootSnapshotService,
    SnapshotAuthority,
    UIDHelperRunner,
    UnixSnapshotServiceServer,
)
from .universal_test_store import TestStoreContractError
from .systemd_activation import take_systemd_listener
from .call_journal import configured_call_journal


def _listener() -> socket.socket:
    try:
        return take_systemd_listener(
            descriptor_name="snapshotd",
            family=socket.AF_UNIX,
            expected_address="/run/devcoordinator-test-snapshotd/snapshot.sock",
        )
    except Exception as error:
        raise TestStoreContractError(
            f"inherited snapshotd listener is invalid: {error}"
        ) from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="devcoordinator-test-snapshotd")
    parser.add_argument("--authority-database", type=Path, required=True)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--snapshot-root", type=Path, required=True)
    parser.add_argument("--catalog-root", type=Path, required=True)
    parser.add_argument("--testd-user", required=True)
    parser.add_argument("--check", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if os.geteuid() != 0:
        raise TestStoreContractError("snapshotd must run as root")
    try:
        testd_uid = int(pwd.getpwnam(arguments.testd_user).pw_uid)
    except KeyError as error:
        raise TestStoreContractError("snapshotd testd user does not exist") from error
    helper = UIDHelperRunner(arguments.helper)
    authority = SnapshotAuthority(arguments.authority_database)
    service = RootSnapshotService(
        authority=authority,
        helper=helper,
        snapshot_root=arguments.snapshot_root,
        catalog_root=arguments.catalog_root,
    )
    if arguments.check:
        return 0
    call_journal = configured_call_journal()
    UnixSnapshotServiceServer(
        _listener(),
        service,
        allowed_peer_uid=testd_uid,
        call_journal=call_journal,
    ).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
