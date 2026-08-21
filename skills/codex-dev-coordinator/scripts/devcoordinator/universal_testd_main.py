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
from .universal_test_scheduler import WeightedFairScheduler
from .universal_test_broker import (
    BrokerConnection,
    CoordinatorBrokerTicketIssuer,
    CoordinatorRuntimeRequestSubmitter,
)
from .universal_test_snapshot_service import UnixSnapshotServiceClient
from .universal_testd import TestdEngine, TestdEngineLoop, TestdLaunchAdapter
from .universal_test_transport import UnixTestPlaneServer
from .systemd_activation import take_systemd_listener
from .call_journal import RollingCallJournal, configured_call_journal


SYSTEMD_LISTEN_FD_START = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="devcoordinator-testd")
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument(
        "--socket", type=Path, default=Path("/run/devcoordinator-testd/testd.sock")
    )
    parser.add_argument("--broker-socket", type=Path)
    parser.add_argument("--snapshot-socket", type=Path)
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
        call_journal=call_journal,
    )


def run(
    *,
    database: Path,
    socket_path: Path,
    previewer: RepositoryUIDPlanPreviewer | None = None,
    engine_loop: TestdEngineLoop | None = None,
    call_journal: RollingCallJournal | None = None,
) -> int:
    store = UniversalTestStore.open(Path(database))
    service = StoreTestPlaneAdapter(
        store,
        previewer=previewer,
        canceller=(
            None if engine_loop is None else engine_loop.engine.cancel_run
        ),
    )
    inherited = inherited_systemd_listener(expected_address=socket_path)
    if inherited is None:
        server = UnixTestPlaneServer.bind(
            Path(socket_path),
            service,
            socket_mode=0o600,
            call_journal=call_journal,
        )
    else:
        server = UnixTestPlaneServer(
            inherited,
            service,
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
        store = UniversalTestStore.open(
            arguments.database, verify_integrity=False
        )
        store.verify_writable()
        return 0
    if arguments.broker_socket is None or arguments.snapshot_socket is None:
        raise TestStoreContractError(
            "production testd requires broker and snapshot paths"
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
        clock=time.time,
    )
    return run(
        database=arguments.database,
        socket_path=arguments.socket,
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
