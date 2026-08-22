"""Administrative service and opaque-ID client CLI for the host broker."""

from __future__ import annotations

import argparse
import errno
import fcntl
import json
import os
import signal
import socket
import stat
import sys
import threading
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable

from .call_journal import (
    DEFAULT_CALL_JOURNAL_BACKUPS,
    DEFAULT_CALL_JOURNAL_MAX_BYTES,
    DEFAULT_CALL_JOURNAL_PATH,
    RollingCallJournal,
)
from .broker import (
    BrokerClient,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    UnixBrokerServer,
    SYSTEM_BROKER_SOCKET_PATH,
    _validate_socket_path,
    validate_runtime_directory,
)
from .broker_backend import build_store_backed_broker_runtime
from .broker_host import LocalBrokerHostMutations
from .broker_links import BrokerLinkStore
from .broker_persistence import BrokerPersistence
from .broker_profile import SYSTEM_PROFILE_PATH
from .store import AccountStore
from .store_backup import (
    create_store_backup,
    create_store_export,
    recover_corrupt_store_backup,
    restore_store_backup,
    restore_store_export,
)
from .universal_test_transport import UnixTestPlaneClient
from .systemd_activation import take_systemd_listener

BROKER_SERVICE_LOCK_NAME = ".broker-service.lock"


def _socket_mode(value: str) -> int:
    try:
        mode = int(str(value), 8)
    except ValueError as error:
        raise argparse.ArgumentTypeError("socket mode must be octal") from error
    if mode not in {0o660, 0o666}:
        raise argparse.ArgumentTypeError("socket mode must be 0660 or 0666")
    return mode


@contextmanager
def exclusive_broker_service_lock(
    database_path: Path,
) -> Generator[None, None, None]:
    """Hold the private lifetime lock that excludes a second broker/abandoner."""

    database = database_path.expanduser().absolute()
    parent = database.parent
    if not parent.is_dir() or parent.is_symlink() or parent.resolve() != parent:
        raise PermissionError("broker service database parent is missing or unsafe")
    lock_path = parent / BROKER_SERVICE_LOCK_NAME
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        opened = os.fstat(descriptor)
        after = lock_path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise PermissionError("broker service lifetime lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError(
                "broker service is active; offline broker administration is refused"
            ) from exc
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def add_broker_parser(subparsers: Any) -> None:
    broker = subparsers.add_parser(
        "broker",
        help="operate the service-owned cross-user port and Docker authority",
        description=(
            "The broker accepts opaque normalized repository/resource IDs only. "
            "Its service-owned database must first be populated by the service account's "
            "normalized observe/import workflow; client paths and names are never resolved."
        ),
    )
    actions = broker.add_subparsers(dest="action", required=True)

    serve = actions.add_parser("serve")
    _database_argument(serve)
    serve_socket = serve.add_mutually_exclusive_group(required=True)
    serve_socket.add_argument("--socket")
    serve_socket.add_argument(
        "--systemd-socket",
        action="store_true",
        help="Adopt the sole systemd descriptor named authority.",
    )
    serve.add_argument("--max-clients", type=int, default=32)
    serve.add_argument(
        "--call-log",
        default=str(DEFAULT_CALL_JOURNAL_PATH),
        help="bounded structured JSONL journal for every authority call",
    )
    serve.add_argument(
        "--call-log-max-bytes",
        type=int,
        default=DEFAULT_CALL_JOURNAL_MAX_BYTES,
        help="maximum bytes retained in each active or rotated call-log file",
    )
    serve.add_argument(
        "--call-log-backups",
        type=int,
        default=DEFAULT_CALL_JOURNAL_BACKUPS,
        help="number of rotated call-log files retained alongside the active file",
    )
    serve.add_argument(
        "--test-plane-socket",
        help="Protected AF_UNIX socket for the separately supervised testd service.",
    )
    configure = actions.add_parser(
        "configure",
        help="synchronize one repository's routing and runtime catalog",
    )
    _database_argument(configure)
    configure.add_argument("--socket", required=True)
    configure.add_argument(
        "--execution-uid",
        type=int,
        required=True,
        help="non-root execution identity used for repository processes",
    )
    configure.add_argument("--project", required=True)
    configure.add_argument("--agent", required=True)
    configure.add_argument("--runtime-file")
    configure.add_argument("--port-range", default="3000-3999")
    configure.add_argument("--profile-output")
    configure.add_argument(
        "--explicit-reinstall",
        action="store_true",
        help=(
            "deliberately reinstall a removed repository or worker as a new "
            "immutable incarnation; ordinary configuration refuses tombstoned resources"
        ),
    )
    configure.add_argument(
        "--approve-compose-host-access",
        action="store_true",
        help=(
            "Explicitly approve the exact rendered Compose definition to use "
            "still-gated host access such as non-loopback publication, devices, "
            "privileged mode, host namespaces, Docker-socket access, "
            "external resources, or unconfined security. "
            "Service-level bind mounts, local volume-driver binds, and cap_add "
            "remain sealed risk evidence but do not require this flag. "
            "Approval is fingerprint-bound."
        ),
    )

    approve_compose = actions.add_parser(
        "approve-compose-host-access",
        help=(
            "approve the exact current repository-declared Compose host-access "
            "risk set that remains approval-required through the live authority"
        ),
    )
    approve_compose.add_argument("--project", required=True)
    approve_compose.add_argument("--agent", required=True)
    approve_compose.add_argument("--operation-id")
    approve_compose.add_argument(
        "--approve-compose-host-access",
        action="store_true",
        required=True,
        help=(
            "explicitly approve the current fingerprinted approval-required "
            "risk set"
        ),
    )

    port_range = actions.add_parser(
        "configure-port-range",
        help="configure the allocatable port range for one server definition",
    )
    _database_argument(port_range)
    port_range.add_argument("--repo-id", required=True)
    port_range.add_argument("--server-definition-id", required=True)
    port_range.add_argument("--start-port", type=int, required=True)
    port_range.add_argument("--end-port", type=int, required=True)
    port_range.add_argument("--protocol", choices=("tcp", "udp"), default="tcp")
    port_range.add_argument("--max-ttl-seconds", type=int, default=3600)
    port_range.add_argument("--disable", action="store_true")

    migrate_store = actions.add_parser(
        "migrate-store",
        help="offline idempotent migration to the current trusted-local schema",
    )
    _database_argument(migrate_store)

    reconcile = actions.add_parser(
        "reconcile-links",
        help="replay exact pending client-side broker lease/assignment releases",
    )
    reconcile.add_argument("--coordinator-home")
    reconcile.add_argument("--limit", type=int, default=100)

    reconcile_compose = actions.add_parser(
        "reconcile-compose",
        help="resolve one uncertain Compose outcome from fresh service evidence",
    )
    _database_argument(reconcile_compose)
    reconcile_compose.add_argument("--operation-id", required=True)
    reconcile_mode = reconcile_compose.add_mutually_exclusive_group()
    reconcile_mode.add_argument("--plan", action="store_true")
    reconcile_mode.add_argument("--abandon-as-failed", action="store_true")
    reconcile_compose.add_argument("--confirm-definition-fingerprint")

    reconcile_docker = actions.add_parser(
        "reconcile-docker",
        help="resolve one uncertain direct Docker outcome from fresh service evidence",
    )
    _database_argument(reconcile_docker)
    reconcile_docker.add_argument("--operation-id", required=True)
    reconcile_docker.add_argument("--plan", action="store_true")
    reconcile_docker.add_argument("--confirm-container-id")

    release_compose_name = actions.add_parser(
        "release-compose-project-name",
        help=(
            "release one disabled Compose project-name claim after a new "
            "exhaustive full-Docker empty-host observation"
        ),
    )
    _database_argument(release_compose_name)
    release_compose_name.add_argument(
        "--compose-definition-id", required=True
    )

    publish_image = actions.add_parser(
        "publish-image",
        help=(
            "root-only snapshot-bound image publication; this is not exposed through "
            "the client broker socket"
        ),
    )
    publish_image.add_argument(
        "--mode", choices=("plan", "build", "apply", "status", "rollback"), required=True
    )
    publish_image.add_argument("--project", required=True)
    publish_image.add_argument("--runtime-file")
    publish_image.add_argument("--publication")
    publish_image.add_argument("--operation-id")
    publish_image.add_argument("--confirm-plan-fingerprint")
    publish_image.add_argument("--confirm-previous-image-id")
    _database_argument(publish_image)

    store_backup = actions.add_parser(
        "store-backup",
        help="create a WAL-consistent verified account or service store backup",
    )
    _store_artifact_create_arguments(store_backup)

    store_export = actions.add_parser(
        "store-export",
        help="create a restorable verified logical account or service store export",
    )
    _store_artifact_create_arguments(store_export)

    store_restore = actions.add_parser(
        "store-restore",
        help="restore a verified binary store backup after taking a safety backup",
    )
    _store_artifact_restore_arguments(store_restore)

    store_import = actions.add_parser(
        "store-import",
        help="import a verified logical store export after taking a safety backup",
    )
    _store_artifact_restore_arguments(store_import)

    store_recover = actions.add_parser(
        "store-recover",
        help="recover an unreadable store after capturing exact forensic bytes",
    )
    _database_argument(store_recover)
    store_recover.add_argument(
        "--store-role", choices=("account", "service"), required=True
    )
    store_recover.add_argument("--manifest", required=True)
    store_recover.add_argument("--forensic-root", required=True)
    store_recover.add_argument("--timeout-seconds", type=float, default=5.0)
    store_recover.add_argument(
        "--confirm-corrupt-recovery",
        action="store_true",
        help="confirm service-offline recovery after exact DB/WAL/SHM capture",
    )

    call = actions.add_parser("call")
    call.add_argument("--socket", required=True)
    call.add_argument("--timeout-seconds", type=float, default=10.0)
    call.add_argument("--run-once-timeout-seconds", type=int)
    call.add_argument("--database-generation", required=True)
    call.add_argument("--project-id", required=True)
    call.add_argument("--resource-id", required=True)
    call.add_argument(
        "--operation", choices=[item.value for item in BrokerOperation], required=True
    )
    call.add_argument("--operation-id")
    call.add_argument("--requested-port", type=int)
    call.add_argument("--protocol", choices=("tcp", "udp"))
    call.add_argument("--ttl-seconds", type=int)
    call.add_argument("--agent")
    call.add_argument("--service")
    call.add_argument("--reason")
    call.add_argument("--expected-observation-revision", type=int)
    call.add_argument("--database-name")
    call.add_argument("--database-backup-id")
    call.add_argument("--explicit", action="store_true")


def handle_broker_cli(args: argparse.Namespace) -> Any:
    if args.group != "broker" or args.action in {
        "serve",
        "configure",
        "reconcile-compose",
        "reconcile-docker",
        "release-compose-project-name",
    }:
        raise ValueError("broker CLI handler received an unsupported command")
    if args.action == "call":
        operation = BrokerOperation(str(args.operation))
        request = BrokerRequest.create(
            account_id="local",
            project_id=str(args.project_id),
            resource_id=str(args.resource_id),
            operation=operation,
            arguments=_request_arguments(args, operation),
            operation_id=args.operation_id,
            authority_generation=str(args.database_generation),
        )
        client = BrokerClient(
            Path(args.socket),
            timeout_seconds=float(args.timeout_seconds),
        )
        reply = client.call(request)
        if not bool(reply.get("ok")):
            error = reply.get("error")
            if not isinstance(error, dict):
                raise BrokerError(
                    "invalid_reply",
                    "Broker returned an invalid failure payload.",
                    operation_id=request.operation_id,
                )
            raise BrokerError(
                str(error.get("code") or "invalid_reply"),
                str(error.get("message") or "Broker mutation failed."),
                operation_id=request.operation_id,
            )
        result = reply.get("result")
        if not isinstance(result, dict):
            raise BrokerError(
                "invalid_reply",
                "Broker returned an invalid success payload.",
                operation_id=request.operation_id,
            )
        return {
            "operation_id": request.operation_id,
            "operation": operation.value,
            "project_id": request.project_id,
            "resource_id": request.resource_id,
            "result": result,
        }

    if args.action == "reconcile-links":
        with AccountStore.open_default(args.coordinator_home) as store:
            return BrokerLinkStore(store).reconcile_pending(limit=int(args.limit))

    if args.action == "store-backup":
        return create_store_backup(
            args.database,
            args.output_root,
            store_role=str(args.store_role),
        )
    if args.action == "store-export":
        return create_store_export(
            args.database,
            args.output_root,
            store_role=str(args.store_role),
        )
    if args.action == "store-restore":
        return restore_store_backup(
            args.database,
            args.manifest,
            args.safety_root,
            store_role=str(args.store_role),
            confirm=bool(args.confirm),
            timeout_seconds=float(args.timeout_seconds),
        )
    if args.action == "store-import":
        return restore_store_export(
            args.database,
            args.manifest,
            args.safety_root,
            store_role=str(args.store_role),
            confirm=bool(args.confirm),
            timeout_seconds=float(args.timeout_seconds),
        )
    if args.action == "store-recover":
        return recover_corrupt_store_backup(
            args.database,
            args.manifest,
            args.forensic_root,
            store_role=str(args.store_role),
            confirm=bool(args.confirm_corrupt_recovery),
            timeout_seconds=float(args.timeout_seconds),
        )

    if args.action == "migrate-store":
        database_path = Path(args.database).expanduser().absolute()
        with exclusive_broker_service_lock(database_path):
            BrokerPersistence(database_path)
            with CoordinatorStore.open_read_only(
                database_path, expected_uid=os.geteuid()
            ) as store:
                return {
                    "status": "current",
                    "schema_version": store.metadata.schema_version,
                    "database_generation": store.metadata.database_generation,
                }

    persistence = BrokerPersistence(Path(args.database))
    if args.action == "configure-port-range":
        persistence.set_server_port_range(
            repo_id=str(args.repo_id),
            server_definition_id=str(args.server_definition_id),
            start_port=int(args.start_port),
            end_port=int(args.end_port),
            protocol=str(args.protocol),
            max_ttl_seconds=int(args.max_ttl_seconds),
            enabled=not bool(args.disable),
        )
        return {
            "status": "configured",
            "repo_id": str(args.repo_id),
            "server_definition_id": str(args.server_definition_id),
            "start_port": int(args.start_port),
            "end_port": int(args.end_port),
            "protocol": str(args.protocol),
            "max_ttl_seconds": int(args.max_ttl_seconds),
            "enabled": not bool(args.disable),
        }
    raise ValueError("unsupported broker action")


def _store_artifact_create_arguments(parser: argparse.ArgumentParser) -> None:
    _database_argument(parser)
    parser.add_argument("--store-role", choices=("account", "service"), required=True)
    parser.add_argument("--output-root", required=True)


def _store_artifact_restore_arguments(parser: argparse.ArgumentParser) -> None:
    _database_argument(parser)
    parser.add_argument("--store-role", choices=("account", "service"), required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--safety-root", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=5.0)
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="confirm replacement after a verified safety backup is created",
    )


def serve_broker(
    args: argparse.Namespace,
    *,
    host_mutations_factory: Callable[[], LocalBrokerHostMutations] = LocalBrokerHostMutations,
    observe_before_lifecycle_plan: Callable[[AccountStore], dict[str, Any]]
    | None = None,
) -> None:
    inherited_listener = None
    if bool(getattr(args, "systemd_socket", False)):
        socket_path = SYSTEM_BROKER_SOCKET_PATH
        inherited_listener = take_systemd_listener(
            descriptor_name="authority",
            family=socket.AF_UNIX,
            expected_address=str(socket_path),
        )
    else:
        socket_path = Path(args.socket)
    call_journal_path = Path(
        getattr(args, "call_log", str(DEFAULT_CALL_JOURNAL_PATH))
    )
    call_journal_max_bytes = int(
        getattr(args, "call_log_max_bytes", DEFAULT_CALL_JOURNAL_MAX_BYTES)
    )
    call_journal_backups = int(
        getattr(args, "call_log_backups", DEFAULT_CALL_JOURNAL_BACKUPS)
    )
    test_plane = None
    test_plane_socket = getattr(args, "test_plane_socket", None)
    if test_plane_socket:
        test_plane = UnixTestPlaneClient(
            Path(test_plane_socket),
            call_journal=RollingCallJournal(
                call_journal_path,
                max_bytes=call_journal_max_bytes,
                backups=call_journal_backups,
            ),
        )
    database_path = Path(args.database).expanduser().absolute()
    with exclusive_broker_service_lock(database_path):
        runtime = build_store_backed_broker_runtime(
            database_path=database_path,
            socket_path=socket_path,
            host_mutations=host_mutations_factory(),
            socket_mode=0o666,
            max_clients=int(args.max_clients),
            initially_accepting_mutations=False,
            observe_before_lifecycle_plan=observe_before_lifecycle_plan,
            test_plane=test_plane,
            call_journal_path=call_journal_path,
            call_journal_max_bytes=call_journal_max_bytes,
            call_journal_backups=call_journal_backups,
        )
        def reclaim_stale_socket_before_admission() -> None:
            """Reclaim only a proven-dead socket while this function holds flock.

            This function is intentionally lexical to the successful service-lock
            block. There is no issuable, mutable, or replayable capability object:
            control reaches it only after the context manager has acquired the
            real exclusive lock.
            """

            server = runtime.server
            socket_path = Path(server.socket_path)
            _validate_socket_path(socket_path)
            runtime_info = validate_runtime_directory(socket_path.parent)
            try:
                initial = os.lstat(str(socket_path))
            except FileNotFoundError:
                return
            except OSError:
                raise BrokerError(
                    "unsafe_socket_path",
                    "Broker socket path could not be inspected.",
                ) from None
            if not stat.S_ISSOCK(initial.st_mode):
                raise BrokerError(
                    "unsafe_socket_path",
                    "Existing broker path is not an AF_UNIX socket; it was not replaced.",
                )
            initial_identity = (
                initial.st_dev,
                initial.st_ino,
                initial.st_ctime_ns,
            )
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                    probe.settimeout(0.2)
                    probe.connect(str(socket_path))
            except socket.timeout:
                outcome = "timeout"
            except BlockingIOError:
                outcome = "would_block"
            except OSError as error:
                if error.errno == errno.ECONNREFUSED:
                    outcome = "refused"
                elif error.errno in {errno.EAGAIN, errno.EWOULDBLOCK}:
                    outcome = "would_block"
                else:
                    outcome = "error"
            else:
                outcome = "live"
            if outcome == "live":
                raise BrokerError(
                    "socket_path_exists",
                    "Broker socket path accepted a connection; it was not replaced.",
                )
            if outcome != "refused":
                raise BrokerError(
                    "socket_path_reclaim_unproven",
                    "Broker socket liveness could not be proven dead; it was "
                    "not replaced.",
                )
            try:
                current = os.lstat(str(socket_path))
            except FileNotFoundError:
                raise BrokerError(
                    "socket_path_reclaim_unproven",
                    "Broker socket path changed during dead-service verification.",
                ) from None
            except OSError:
                raise BrokerError(
                    "socket_path_reclaim_unproven",
                    "Broker socket path could not be rechecked before stale recovery.",
                ) from None
            runtime_after = validate_runtime_directory(socket_path.parent)
            current_identity = (
                current.st_dev,
                current.st_ino,
                current.st_ctime_ns,
            )
            if (
                not stat.S_ISSOCK(current.st_mode)
                or current_identity != initial_identity
                or (runtime_after.st_dev, runtime_after.st_ino)
                != (runtime_info.st_dev, runtime_info.st_ino)
            ):
                raise BrokerError(
                    "socket_path_reclaim_unproven",
                    "Broker socket changed during dead-service verification; it "
                    "was not removed.",
                )
            try:
                os.unlink(str(socket_path))
            except OSError:
                raise BrokerError(
                    "socket_path_reclaim_failed",
                    "Broker stale socket could not be removed.",
                ) from None

        worker_fencing: dict[str, Any] = {
            "ok": True,
            "supervisor_epoch": None,
            "fenced_old_runners": [],
            "started": [],
            "errors": [],
        }
        stop = threading.Event()
        previous: dict[int, Any] = {}
        shutdown_requested = False
        worker_autostart_thread: threading.Thread | None = None

        def report_worker_reconciliation(
            worker_reconciliation: dict[str, Any],
        ) -> None:
            print(
                json.dumps(
                    {
                        "event": "worker.startup_reconciled",
                        "ok": worker_reconciliation.get("ok") is True,
                        "supervisor_epoch": worker_reconciliation.get(
                            "supervisor_epoch"
                        ),
                        "fenced_old_runners": worker_reconciliation.get(
                            "fenced_old_runners", []
                        ),
                        "started": worker_reconciliation.get("started", []),
                        "failure_count": len(
                            worker_reconciliation.get("errors", [])
                        ),
                    },
                    sort_keys=True,
                ),
                file=(
                    sys.stdout
                    if worker_reconciliation.get("ok") is True
                    else sys.stderr
                ),
                flush=True,
            )
            for failure in worker_reconciliation.get("errors", []):
                worker_id = str(failure.get("worker_id") or "unknown")[:128]
                phase = str(failure.get("phase") or "unknown")[:128]
                detail = str(failure.get("error") or "inspect broker logs")[:4096]
                print(
                    json.dumps(
                        {
                            "event": "worker.startup_failed",
                            "worker_id": worker_id,
                            "phase": phase,
                            "error": detail,
                            "action_required": (
                                "Inspect this worker's retained attempt/native-runner logs, "
                                "fix its installed definition or host service state, then "
                                "explicitly start it again."
                            ),
                        },
                        sort_keys=True,
                    ),
                    file=sys.stderr,
                    flush=True,
                )

        def reconcile_workers_after_admission() -> None:
            try:
                worker_reconciliation = runtime.autostart_workers_after_admission(
                    fenced=worker_fencing
                )
            except BaseException as error:
                worker_reconciliation = {
                    **worker_fencing,
                    "ok": False,
                    "started": [],
                    "errors": [
                        *list(worker_fencing.get("errors") or []),
                        {
                            "worker_id": "unknown",
                            "phase": "autostart_reconciliation",
                            "error": f"{type(error).__name__}: {error}"[:4096],
                        },
                    ],
                }
            report_worker_reconciliation(worker_reconciliation)

        def request_stop(_signum: int, _frame: Any) -> None:
            nonlocal shutdown_requested
            # Fence mutation admission in the signal turn itself. Waiting for
            # the serve loop would leave a post-SIGTERM reservation window.
            # The plain main-thread guard also makes repeated signals safe.
            if shutdown_requested:
                return
            shutdown_requested = True
            try:
                runtime.begin_shutdown()
            finally:
                stop.set()

        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, request_stop)
        try:
            if isinstance(runtime.server, UnixBrokerServer) and inherited_listener is None:
                reclaim_stale_socket_before_admission()
            if inherited_listener is None:
                runtime.server.start()
            else:
                runtime.server.start(listener=inherited_listener)
            if shutdown_requested:
                report_worker_reconciliation(
                    {
                        **worker_fencing,
                        "ok": worker_fencing.get("ok") is True,
                        "started": [],
                    }
                )
            else:
                # Accept the inherited socket before potentially long durable
                # recovery and worker fencing. The writer starts mutation-
                # fenced, so only compatible reads are served in this phase.
                runtime.persistence.recover_interrupted_docker_operations()
                runtime.persistence.recover_interrupted_compose_operations()
                runtime.backend.recover_ephemeral_runs()
                runtime.backend.start_ephemeral_reaper()
                worker_fencing = runtime.fence_workers_on_startup()
                if shutdown_requested:
                    report_worker_reconciliation(
                        {
                            **worker_fencing,
                            "ok": worker_fencing.get("ok") is True,
                            "started": [],
                        }
                    )
                    stop.set()
                else:
                    runtime.begin_mutation_admission()
                    # Repository startup remains fenced until the release manager
                    # observes this broker as ready. Reconcile in the background so
                    # admission can become observable first, then converge every
                    # expected keep-alive worker once that temporary fence clears.
                    worker_autostart_thread = threading.Thread(
                        target=reconcile_workers_after_admission,
                        name="devcoordinator-worker-startup",
                        daemon=True,
                    )
                    worker_autostart_thread.start()
            print(
                json.dumps(
                    {
                        "status": "ready",
                        "service_uid": os.geteuid(),
                        "socket": str(socket_path),
                        "socket_activated": inherited_listener is not None,
                        "database": str(database_path),
                        "wire_identity": "opaque_normalized_ids_only",
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            while not stop.wait(0.5):
                pass
        finally:
            try:
                if worker_autostart_thread is not None:
                    worker_autostart_thread.join(timeout=1.0)
                runtime.close()
            finally:
                for signum, handler in previous.items():
                    signal.signal(signum, handler)


def _database_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--database",
        required=True,
        help="service-owned normalized SQLite database populated before broker provisioning",
    )


def _octal_mode(raw: str) -> int:
    try:
        value = int(raw, 8)
    except ValueError as error:
        raise argparse.ArgumentTypeError("socket mode must be octal, for example 0660") from error
    if value < 0 or value > 0o7777:
        raise argparse.ArgumentTypeError("socket mode is out of range")
    return value


def _request_arguments(
    args: argparse.Namespace, operation: BrokerOperation
) -> dict[str, Any]:
    if operation is BrokerOperation.EPHEMERAL_SECRET_FD:
        raise ValueError(
            "ephemeral.secret_fd is in-process descriptor transport only; "
            "the generic broker CLI never prints or forwards credentials"
        )
    if operation is BrokerOperation.COMPOSE_RUN_ONCE:
        if (
            not args.agent
            or not args.service
            or args.reason
            or args.run_once_timeout_seconds is None
            or args.requested_port is not None
            or args.protocol is not None
            or args.ttl_seconds is not None
            or args.expected_observation_revision is not None
            or args.database_name
            or args.database_backup_id
            or args.explicit
        ):
            raise ValueError(
                "compose.run_once requires --agent, --service, and "
                "--run-once-timeout-seconds only"
            )
        return {
            "agent": str(args.agent),
            "service": str(args.service),
            "timeout_seconds": int(args.run_once_timeout_seconds),
        }
    if args.run_once_timeout_seconds is not None:
        raise ValueError(
            "--run-once-timeout-seconds is valid only for compose.run_once"
        )
    port_fields = (args.requested_port, args.protocol, args.ttl_seconds)
    if operation in {
        BrokerOperation.EPHEMERAL_START,
        BrokerOperation.EPHEMERAL_STATUS,
        BrokerOperation.EPHEMERAL_IMAGE_STATUS,
        BrokerOperation.EPHEMERAL_IMAGE_PREFETCH,
        BrokerOperation.EPHEMERAL_RENEW,
        BrokerOperation.EPHEMERAL_FINISH,
    }:
        if (
            args.requested_port is not None
            or args.protocol is not None
            or args.expected_observation_revision is not None
            or args.database_name
            or args.database_backup_id
            or args.explicit
            or args.service
        ):
            raise ValueError(
                "ephemeral operations do not accept port, Docker-observation, or database arguments"
            )
        if operation in {
            BrokerOperation.EPHEMERAL_STATUS,
            BrokerOperation.EPHEMERAL_IMAGE_STATUS,
        }:
            if args.agent or args.reason or args.ttl_seconds is not None:
                raise ValueError("ephemeral status reads accept no mutation arguments")
            return {}
        if not args.agent:
            raise ValueError("ephemeral mutations require --agent")
        result: dict[str, Any] = {"agent": str(args.agent)}
        if operation is BrokerOperation.EPHEMERAL_START:
            if args.reason:
                raise ValueError("ephemeral.start does not accept --reason")
            if args.ttl_seconds is not None:
                result["ttl_seconds"] = int(args.ttl_seconds)
            return result
        if operation is BrokerOperation.EPHEMERAL_IMAGE_PREFETCH:
            if args.reason or args.ttl_seconds is not None:
                raise ValueError(
                    "ephemeral.image_prefetch requires only --agent"
                )
            return result
        if operation is BrokerOperation.EPHEMERAL_RENEW:
            if args.reason or args.ttl_seconds is None:
                raise ValueError(
                    "ephemeral.renew requires --agent and --ttl-seconds"
                )
            result["ttl_seconds"] = int(args.ttl_seconds)
            return result
        if not args.reason or args.ttl_seconds is not None:
            raise ValueError("ephemeral.finish requires --agent and --reason")
        result["reason"] = str(args.reason)
        return result
    if operation is BrokerOperation.DATABASE_BACKUP:
        if not args.database_name or args.database_backup_id or args.explicit:
            raise ValueError(
                "database.backup requires --database-name and accepts no backup ID or explicit flag"
            )
        if any(value is not None for value in port_fields) or args.expected_observation_revision is not None:
            raise ValueError("database.backup does not accept port or Docker observation arguments")
        return {"database_name": str(args.database_name)}
    if operation is BrokerOperation.DATABASE_RESTORE:
        if not args.database_name or not args.database_backup_id or not args.explicit:
            raise ValueError(
                "database.restore requires --database-name, --database-backup-id, and --explicit"
            )
        if any(value is not None for value in port_fields) or args.expected_observation_revision is not None:
            raise ValueError("database.restore does not accept port or Docker observation arguments")
        return {
            "database_name": str(args.database_name),
            "database_backup_id": str(args.database_backup_id),
            "explicit": True,
        }
    if args.database_name or args.database_backup_id or args.explicit:
        raise ValueError("only PostgreSQL database operations accept database arguments")
    if args.agent or args.service or args.reason:
        raise ValueError("only ephemeral mutations accept agent or reason arguments")
    if operation is BrokerOperation.PORT_LEASE:
        if args.expected_observation_revision is not None:
            raise ValueError("port.lease does not accept a Docker observation revision")
        result: dict[str, Any] = {}
        if args.requested_port is not None:
            result["requested_port"] = int(args.requested_port)
        if args.protocol is not None:
            result["protocol"] = str(args.protocol)
        if args.ttl_seconds is not None:
            result["ttl_seconds"] = int(args.ttl_seconds)
        return result
    if operation is BrokerOperation.PORT_RELEASE:
        if any(value is not None for value in port_fields) or args.expected_observation_revision is not None:
            raise ValueError("port.release accepts no mutation arguments")
        return {}
    if any(value is not None for value in port_fields):
        raise ValueError("Docker broker operations do not accept port arguments")
    if args.expected_observation_revision is None:
        return {}
    if int(args.expected_observation_revision) < 0:
        raise ValueError("expected observation revision must be non-negative")
    return {"expected_observation_revision": int(args.expected_observation_revision)}
