"""Process entrypoint for the isolated DevCoordinator test-plane daemon.

Startup validates the existing test database and proves that it can begin a
write transaction without persisting data.  The database must already have
been created by an explicit offline migration.  A production composition can
inject a ``RepositoryUIDPlanPreviewer`` before serving; absent that helper,
preview is a typed unavailable operation rather than privileged repository
parsing.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import socket
import time
from typing import Sequence

from .universal_test_service import RepositoryUIDPlanPreviewer, StoreTestPlaneAdapter
from .universal_test_store import TestStoreContractError, UniversalTestStore
from .universal_test_spool import DurableAttemptSpool
from .universal_test_scheduler import WeightedFairScheduler
from .universal_test_broker import (
    BrokerConnection,
    CoordinatorBrokerTicketIssuer,
    CoordinatorRuntimeRequestSubmitter,
    SYSTEM_AUTHORITY_SOCKET_GID,
    SYSTEM_AUTHORITY_SOCKET_MODE,
    SYSTEM_AUTHORITY_SOCKET_UID,
)
from .universal_test_snapshot_service import UnixSnapshotServiceClient
from .universal_testd import TestdEngine, TestdEngineLoop, TestdLaunchAdapter
from .universal_test_transport import UnixTestPlaneServer
from .systemd_activation import take_systemd_listener
from .call_journal import RollingCallJournal, configured_call_journal


SYSTEMD_LISTEN_FD_START = 3


def _nonnegative_uid(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("UID must be an integer") from error
    if parsed < 0:
        raise argparse.ArgumentTypeError("UID must be non-negative")
    return parsed


def _socket_mode(value: str) -> int:
    try:
        parsed = int(value, 8)
    except ValueError as error:
        raise argparse.ArgumentTypeError("socket mode must be octal") from error
    if parsed < 0 or parsed > 0o777:
        raise argparse.ArgumentTypeError("socket mode must be between 0000 and 0777")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="devcoordinator-testd")
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument(
        "--socket", type=Path, default=Path("/run/devcoordinator-testd/testd.sock")
    )
    parser.add_argument(
        "--broker-uid", type=_nonnegative_uid, default=SYSTEM_AUTHORITY_SOCKET_UID
    )
    parser.add_argument(
        "--broker-socket-gid",
        type=_nonnegative_uid,
        default=SYSTEM_AUTHORITY_SOCKET_GID,
    )
    parser.add_argument(
        "--broker-socket-mode",
        type=_socket_mode,
        default=SYSTEM_AUTHORITY_SOCKET_MODE,
    )
    parser.add_argument("--broker-socket", type=Path)
    parser.add_argument("--snapshot-socket", type=Path)
    parser.add_argument("--spool", type=Path)
    parser.add_argument("--launch-batch", type=int, default=64)
    parser.add_argument("--interval-seconds", type=float, default=1.0)
    parser.add_argument("--check", action="store_true")
    return parser


def inherited_systemd_listener(
    environment: dict[str, str] | None = None,
    *,
    expected_address: Path = Path("/run/devcoordinator-testd/testd.sock"),
) -> socket.socket | None:
    values = os.environ if environment is None else environment
    try:
        listen_pid = int(values.get("LISTEN_PID", "0"))
        listen_fds = int(values.get("LISTEN_FDS", "0"))
    except ValueError as error:
        raise TestStoreContractError("systemd listener environment is invalid") from error
    if listen_fds == 0:
        return None
    if listen_pid != os.getpid() or listen_fds != 1:
        raise TestStoreContractError("testd requires exactly one inherited listener")
    try:
        return take_systemd_listener(
            descriptor_name="testd",
            family=socket.AF_UNIX,
            expected_address=str(expected_address),
            environment=values,
        )
    except Exception as error:
        raise TestStoreContractError(
            f"inherited testd listener is invalid: {error}"
        ) from error


def build_testd_server(
    *,
    database: Path,
    broker_uid: int,
    listener: socket.socket,
    previewer: RepositoryUIDPlanPreviewer | None = None,
    call_journal: RollingCallJournal | None = None,
) -> UnixTestPlaneServer:
    """Build the daemon from injected authority and listener dependencies."""

    store = UniversalTestStore.open(Path(database))
    service = StoreTestPlaneAdapter(store, previewer=previewer)
    return UnixTestPlaneServer(
        listener,
        service,
        allowed_peer_uids=(broker_uid,),
        call_journal=call_journal,
    )


def run(
    *,
    database: Path,
    socket_path: Path,
    broker_uid: int,
    previewer: RepositoryUIDPlanPreviewer | None = None,
    engine_loop: TestdEngineLoop | None = None,
    call_journal: RollingCallJournal | None = None,
) -> int:
    store = UniversalTestStore.open(Path(database))
    inherited = inherited_systemd_listener(expected_address=socket_path)
    if inherited is None:
        server = UnixTestPlaneServer.bind(
            Path(socket_path),
            StoreTestPlaneAdapter(store, previewer=previewer),
            allowed_peer_uids=(broker_uid,),
            socket_mode=0o600,
            call_journal=call_journal,
        )
    else:
        server = UnixTestPlaneServer(
            inherited,
            StoreTestPlaneAdapter(store, previewer=previewer),
            allowed_peer_uids=(broker_uid,),
            call_journal=call_journal,
        )

    def stop(_signum: int, _frame: object) -> None:
        server.close()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        if engine_loop is not None:
            engine_loop.start()
        server.serve_forever()
    finally:
        server.close()
        if engine_loop is not None:
            engine_loop.close()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.check:
        store = UniversalTestStore.open(arguments.database)
        store.verify_writable()
        if arguments.spool is not None:
            DurableAttemptSpool.open(arguments.spool)
        return 0
    if arguments.broker_socket is None or arguments.snapshot_socket is None or arguments.spool is None:
        raise TestStoreContractError(
            "production testd requires broker, snapshot, and spool paths"
        )
    store = UniversalTestStore.open(arguments.database)
    call_journal = configured_call_journal()
    snapshot_client = UnixSnapshotServiceClient(
        arguments.snapshot_socket,
        call_journal=call_journal,
    )
    broker_connection = BrokerConnection(
        arguments.broker_socket,
        authority_generation="broker-current-testd",
        expected_broker_uid=arguments.broker_uid,
        expected_socket_gid=arguments.broker_socket_gid,
        expected_socket_mode=arguments.broker_socket_mode,
    )
    scheduler = WeightedFairScheduler()
    engine = TestdEngine(
        store=store,
        scheduler=scheduler,
        ticket_issuer=CoordinatorBrokerTicketIssuer(
            broker_connection,
            snapshot_client,
            call_journal=call_journal,
        ),
        launcher=TestdLaunchAdapter(
            CoordinatorRuntimeRequestSubmitter(
                broker_connection,
                call_journal=call_journal,
            )
        ),
        spool=DurableAttemptSpool.open(arguments.spool),
        clock=time.time,
    )
    return run(
        database=arguments.database,
        socket_path=arguments.socket,
        broker_uid=arguments.broker_uid,
        previewer=snapshot_client,
        call_journal=call_journal,
        engine_loop=TestdEngineLoop(
            engine,
            interval_seconds=arguments.interval_seconds,
            launch_batch=arguments.launch_batch,
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "build_parser",
    "build_testd_server",
    "inherited_systemd_listener",
    "main",
    "run",
]
