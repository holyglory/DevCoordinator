"""Administrative service and opaque-ID client CLI for the host broker."""

from __future__ import annotations

import argparse
import grp
import json
import os
from pathlib import Path
import signal
import threading
from typing import Any, Callable

from .broker import BrokerClient, BrokerError, BrokerOperation, BrokerRequest
from .broker_backend import build_store_backed_broker_runtime
from .broker_host import LocalBrokerHostMutations
from .broker_links import BrokerLinkStore
from .broker_persistence import BrokerPersistence
from .store import AccountStore
from .store_backup import (
    create_store_backup,
    create_store_export,
    recover_corrupt_store_backup,
    restore_store_backup,
    restore_store_export,
)


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
    serve.add_argument("--socket", required=True)
    serve_access = serve.add_mutually_exclusive_group()
    serve_access.add_argument("--access-gid", type=int)
    serve_access.add_argument(
        "--access-group",
        help="Resolve this system group to the broker socket GID at service startup.",
    )
    serve.add_argument("--max-clients", type=int, default=32)

    enroll = actions.add_parser(
        "enroll",
        help="synchronize one repository and install its root-owned client profile",
    )
    _database_argument(enroll)
    enroll.add_argument("--socket", required=True)
    enroll_access = enroll.add_mutually_exclusive_group(required=True)
    enroll_access.add_argument("--access-gid", type=int)
    enroll_access.add_argument(
        "--access-group",
        help="Resolve this system group to the broker socket GID during enrollment.",
    )
    enroll.add_argument("--client-uid", type=int, required=True)
    enroll.add_argument("--account-id", required=True)
    enroll.add_argument("--project", required=True)
    enroll.add_argument("--agent", required=True)
    enroll.add_argument("--runtime-file")
    server_access = enroll.add_mutually_exclusive_group()
    server_access.add_argument(
        "--server",
        action="append",
        default=None,
        help=(
            "Grant this authenticated UID control of one declared server; repeat for an exact allowlist. "
            "Omit to grant no servers."
        ),
    )
    server_access.add_argument(
        "--all-servers",
        action="store_true",
        help="Explicitly grant this UID every server declared by the repository.",
    )
    enroll.add_argument("--port-range", default="3000-3999")
    enroll.add_argument("--profile-output")
    enroll.add_argument("--profile-valid-days", type=int, default=30)
    enroll.add_argument("--explicit-reinstall", action="store_true")

    principal = actions.add_parser("provision-principal")
    _database_argument(principal)
    principal.add_argument("--uid", type=int, required=True)
    principal.add_argument("--account-id", required=True)
    principal.add_argument("--disable", action="store_true")

    grant = actions.add_parser("grant-resource")
    _database_argument(grant)
    grant.add_argument("--uid", type=int, required=True)
    grant.add_argument("--repo-id", required=True)
    grant.add_argument("--resource-kind", choices=("server", "container"), required=True)
    grant.add_argument("--resource-id", required=True)
    grant.add_argument(
        "--operation", choices=[item.value for item in BrokerOperation], required=True
    )
    grant.add_argument("--disable", action="store_true")

    grant_database = actions.add_parser("grant-database")
    _database_argument(grant_database)
    grant_database.add_argument("--uid", type=int, required=True)
    grant_database.add_argument("--repo-id", required=True)
    grant_database.add_argument("--database-binding-id", required=True)
    grant_database.add_argument(
        "--operation",
        choices=(
            BrokerOperation.DATABASE_BACKUP.value,
            BrokerOperation.DATABASE_RESTORE.value,
        ),
        required=True,
    )
    grant_database.add_argument("--disable", action="store_true")

    port_range = actions.add_parser("grant-port-range")
    _database_argument(port_range)
    port_range.add_argument("--uid", type=int, required=True)
    port_range.add_argument("--repo-id", required=True)
    port_range.add_argument("--server-definition-id", required=True)
    port_range.add_argument("--start-port", type=int, required=True)
    port_range.add_argument("--end-port", type=int, required=True)
    port_range.add_argument("--protocol", choices=("tcp", "udp"), default="tcp")
    port_range.add_argument("--max-ttl-seconds", type=int, default=3600)
    port_range.add_argument("--disable", action="store_true")

    reconcile = actions.add_parser(
        "reconcile-links",
        help="replay exact pending client-side broker lease/assignment releases",
    )
    reconcile.add_argument("--coordinator-home")
    reconcile.add_argument("--limit", type=int, default=100)

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
    call.add_argument("--expected-broker-uid", type=int, required=True)
    call.add_argument("--expected-socket-gid", type=int)
    call.add_argument("--expected-socket-mode", type=_octal_mode, default=0o660)
    call.add_argument("--timeout-seconds", type=float, default=10.0)
    call.add_argument("--account-id", required=True)
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
    call.add_argument("--expected-observation-revision", type=int)
    call.add_argument("--database-name")
    call.add_argument("--database-backup-id")
    call.add_argument("--explicit", action="store_true")


def handle_broker_cli(args: argparse.Namespace) -> Any:
    if args.group != "broker" or args.action in {"serve", "enroll"}:
        raise ValueError("broker CLI handler received an unsupported command")
    if args.action == "call":
        operation = BrokerOperation(str(args.operation))
        request = BrokerRequest.create(
            account_id=str(args.account_id),
            project_id=str(args.project_id),
            resource_id=str(args.resource_id),
            operation=operation,
            arguments=_request_arguments(args, operation),
            operation_id=args.operation_id,
            authority_generation=str(args.database_generation),
        )
        client = BrokerClient(
            Path(args.socket),
            expected_broker_uid=int(args.expected_broker_uid),
            expected_socket_gid=args.expected_socket_gid,
            expected_socket_mode=int(args.expected_socket_mode),
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

    persistence = BrokerPersistence(Path(args.database))
    if args.action == "provision-principal":
        persistence.provision_principal(
            uid=int(args.uid),
            account_id=str(args.account_id),
            enabled=not bool(args.disable),
        )
        return {
            "status": "configured",
            "principal": {"uid": int(args.uid), "account_id": str(args.account_id)},
            "enabled": not bool(args.disable),
        }
    if args.action == "grant-resource":
        operation = BrokerOperation(str(args.operation))
        persistence.grant_resource(
            uid=int(args.uid),
            repo_id=str(args.repo_id),
            resource_kind=str(args.resource_kind),
            resource_id=str(args.resource_id),
            operation=operation,
            enabled=not bool(args.disable),
        )
        return {
            "status": "configured",
            "uid": int(args.uid),
            "repo_id": str(args.repo_id),
            "resource_kind": str(args.resource_kind),
            "resource_id": str(args.resource_id),
            "operation": operation.value,
            "enabled": not bool(args.disable),
        }
    if args.action == "grant-database":
        operation = BrokerOperation(str(args.operation))
        persistence.grant_database(
            uid=int(args.uid),
            repo_id=str(args.repo_id),
            database_binding_id=str(args.database_binding_id),
            operation=operation,
            enabled=not bool(args.disable),
        )
        return {
            "status": "configured",
            "uid": int(args.uid),
            "repo_id": str(args.repo_id),
            "database_binding_id": str(args.database_binding_id),
            "operation": operation.value,
            "enabled": not bool(args.disable),
        }
    if args.action == "grant-port-range":
        persistence.grant_port_range(
            uid=int(args.uid),
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
            "uid": int(args.uid),
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
    if args.access_group:
        try:
            access_gid = int(grp.getgrnam(str(args.access_group)).gr_gid)
        except KeyError as error:
            raise RuntimeError(
                f"broker access group does not exist: {args.access_group}"
            ) from error
    else:
        access_gid = args.access_gid
    runtime = build_store_backed_broker_runtime(
        database_path=Path(args.database),
        socket_path=Path(args.socket),
        host_mutations=host_mutations_factory(),
        access_gid=access_gid,
        max_clients=int(args.max_clients),
        observe_before_lifecycle_plan=observe_before_lifecycle_plan,
    )
    stop = threading.Event()
    previous: dict[int, Any] = {}

    def request_stop(_signum: int, _frame: Any) -> None:
        stop.set()

    for signum in (signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, request_stop)
    try:
        runtime.server.start()
        print(
            json.dumps(
                {
                    "status": "ready",
                    "service_uid": os.geteuid(),
                    "access_gid": os.getegid() if access_gid is None else int(access_gid),
                    "socket": str(Path(args.socket)),
                    "database": str(Path(args.database)),
                    "wire_identity": "opaque_normalized_ids_only",
                },
                sort_keys=True,
            ),
            flush=True,
        )
        while not stop.wait(0.5):
            pass
    finally:
        runtime.server.close()
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
    port_fields = (args.requested_port, args.protocol, args.ttl_seconds)
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
