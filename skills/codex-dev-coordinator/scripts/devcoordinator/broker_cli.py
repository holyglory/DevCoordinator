"""Administrative service and opaque-ID client CLI for the host broker."""

from __future__ import annotations

import argparse
import errno
import fcntl
import grp
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

from .broker import (
    BrokerClient,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    UnixBrokerServer,
    _validate_socket_path,
    validate_runtime_directory,
)
from .broker_backend import build_store_backed_broker_runtime
from .broker_host import LocalBrokerHostMutations
from .broker_links import BrokerLinkStore
from .broker_persistence import BrokerPersistence
from .broker_profile import SYSTEM_PROFILE_PATH
from .broker_profile_enrollment_migration import (
    migrate_protected_profile_enrollments,
    reconcile_protected_profile_repository_generation,
)
from .store import AccountStore
from .store_backup import (
    create_store_backup,
    create_store_export,
    recover_corrupt_store_backup,
    restore_store_backup,
    restore_store_export,
)

BROKER_SERVICE_LOCK_NAME = ".broker-service.lock"


@contextmanager
def exclusive_broker_service_lock(
    database_path: Path,
) -> Generator[None, None, None]:
    """Hold the private lifetime lock that excludes a second broker/abandoner."""

    database = database_path.expanduser().absolute()
    parent = database.parent
    if not parent.is_dir() or parent.is_symlink() or parent.resolve() != parent:
        raise PermissionError("broker service database parent is missing or unsafe")
    parent_metadata = parent.stat()
    if (
        parent_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(parent_metadata.st_mode) & 0o022
    ):
        raise PermissionError(
            "broker service database parent must be service-owned and not group/other writable"
        )
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
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
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
    enroll.add_argument(
        "--explicit-reinstall",
        action="store_true",
        help=(
            "deliberately reinstall a removed repository or worker as a new "
            "immutable incarnation; ordinary enrollment refuses tombstoned resources"
        ),
    )
    enroll.add_argument(
        "--grant-ephemeral-image-prefetch",
        action="store_true",
        help=(
            "explicitly grant cache-pull authority only for this repository's "
            "current administrator-sealed ephemeral template images"
        ),
    )
    enroll.add_argument(
        "--grant-cleanup",
        action="store_true",
        help=(
            "explicitly grant this UID default-deny archive, restore, and permanent cleanup capabilities for this project"
        ),
    )
    enroll.add_argument(
        "--approve-compose-host-access",
        action="store_true",
        help=(
            "Explicitly approve the exact rendered Compose definition to use "
            "host-equivalent capabilities such as bind mounts, devices, host "
            "namespaces, or added capabilities. Approval is fingerprint-bound."
        ),
    )

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

    grant_runtime = actions.add_parser(
        "grant-runtime",
        help="grant one exact typed runtime action for an enrolled resource",
    )
    _database_argument(grant_runtime)
    grant_runtime.add_argument("--uid", type=int, required=True)
    grant_runtime.add_argument("--repo-id", required=True)
    grant_runtime.add_argument(
        "--resource-kind",
        choices=("service", "docker", "database_stack"),
        required=True,
    )
    grant_runtime.add_argument("--resource-id", required=True)
    grant_runtime.add_argument(
        "--runtime-action",
        choices=("status", "start", "stop", "restart", "replace"),
        required=True,
    )
    grant_runtime.add_argument("--disable", action="store_true")

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

    grant_cleanup = actions.add_parser("grant-cleanup")
    _database_argument(grant_cleanup)
    grant_cleanup.add_argument("--uid", type=int, required=True)
    grant_cleanup.add_argument("--repo-id", required=True)
    grant_cleanup.add_argument(
        "--operation",
        choices=(
            BrokerOperation.ARCHIVES_READ.value,
            BrokerOperation.CLEANUP_PLAN.value,
            BrokerOperation.CLEANUP_APPLY.value,
            BrokerOperation.LIFECYCLE_RESTORE.value,
            BrokerOperation.REPOSITORY_PLAN_REMOVE.value,
            BrokerOperation.REPOSITORY_REMOVE.value,
            BrokerOperation.REPOSITORY_REINSTALL.value,
            BrokerOperation.RESOURCE_PLAN_RETIRE.value,
            BrokerOperation.RESOURCE_RETIRE.value,
            BrokerOperation.RESOURCE_PLAN_ARCHIVE.value,
            BrokerOperation.RESOURCE_ARCHIVE.value,
            BrokerOperation.RESOURCE_RESTORE.value,
        ),
        required=True,
    )
    grant_cleanup.add_argument("--disable", action="store_true")

    grant_cleanup_resource = actions.add_parser("grant-cleanup-resource")
    _database_argument(grant_cleanup_resource)
    grant_cleanup_resource.add_argument("--uid", type=int, required=True)
    grant_cleanup_resource.add_argument("--repo-id", required=True)
    grant_cleanup_resource.add_argument(
        "--resource-kind", choices=("server", "container", "supervisor"), required=True
    )
    grant_cleanup_resource.add_argument("--resource-id", required=True)
    grant_cleanup_resource.add_argument("--control-binding-id", required=True)
    grant_cleanup_resource.add_argument("--immutable-fingerprint", required=True)
    grant_cleanup_resource.add_argument("--ownership-fingerprint", required=True)
    grant_cleanup_resource.add_argument(
        "--operation",
        choices=(
            BrokerOperation.CLEANUP_PLAN.value,
            BrokerOperation.CLEANUP_APPLY.value,
            BrokerOperation.RESOURCE_PLAN_ARCHIVE.value,
            BrokerOperation.RESOURCE_ARCHIVE.value,
            BrokerOperation.RESOURCE_RESTORE.value,
        ),
        required=True,
    )
    grant_cleanup_resource.add_argument("--disable", action="store_true")

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

    reconcile_profile_generation = actions.add_parser(
        "reconcile-profile-repository-generation",
        help=(
            "offline exact forward reconciliation of one protected-profile repository generation"
        ),
    )
    _database_argument(reconcile_profile_generation)
    reconcile_profile_generation.add_argument(
        "--profile",
        default=str(SYSTEM_PROFILE_PATH),
        help="protected root-owned broker client profile",
    )
    reconcile_profile_generation.add_argument(
        "--client-uid", type=int, required=True
    )
    reconcile_profile_generation.add_argument("--account-id", required=True)
    reconcile_profile_generation.add_argument("--repo-id", required=True)
    reconcile_profile_generation.add_argument("--canonical-root", required=True)
    reconcile_profile_generation.add_argument(
        "--rollback-root",
        required=True,
        help="existing root:root 0700 private transaction directory for rollback evidence",
    )
    reconcile_profile_generation.add_argument(
        "--from-generation", type=int, required=True
    )
    reconcile_profile_generation.add_argument(
        "--to-generation", type=int, required=True
    )

    migrate_enrollments = actions.add_parser(
        "migrate-profile-enrollments",
        help=(
            "offline backfill of missing repository enrollments from the protected client profile"
        ),
    )
    _database_argument(migrate_enrollments)
    migrate_enrollments.add_argument(
        "--profile",
        default=str(SYSTEM_PROFILE_PATH),
        help="protected root-owned broker client profile",
    )

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
    call.add_argument("--agent")
    call.add_argument("--reason")
    call.add_argument("--expected-observation-revision", type=int)
    call.add_argument("--database-name")
    call.add_argument("--database-backup-id")
    call.add_argument("--explicit", action="store_true")


def handle_broker_cli(args: argparse.Namespace) -> Any:
    if args.group != "broker" or args.action in {
        "serve",
        "enroll",
        "reconcile-compose",
        "reconcile-docker",
        "release-compose-project-name",
    }:
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

    if args.action == "migrate-profile-enrollments":
        if os.geteuid() != 0:
            raise PermissionError(
                "broker profile enrollment migration requires the root service administrator"
            )
        database_path = Path(args.database).expanduser().absolute()
        with exclusive_broker_service_lock(database_path):
            return migrate_protected_profile_enrollments(
                database_path=database_path,
                profile_path=Path(args.profile).expanduser(),
                expected_service_uid=0,
                trusted_profile_owner_uid=0,
            )

    if args.action == "reconcile-profile-repository-generation":
        if os.geteuid() != 0:
            raise PermissionError(
                "profile repository generation reconciliation requires the root service administrator"
            )
        database_path = Path(args.database).expanduser().absolute()
        with exclusive_broker_service_lock(database_path):
            return reconcile_protected_profile_repository_generation(
                database_path=database_path,
                profile_path=Path(args.profile).expanduser(),
                client_uid=int(args.client_uid),
                account_id=str(args.account_id),
                repo_id=str(args.repo_id),
                canonical_root=str(args.canonical_root),
                from_generation=int(args.from_generation),
                to_generation=int(args.to_generation),
                rollback_root=Path(args.rollback_root).expanduser(),
                expected_service_uid=0,
                trusted_profile_owner_uid=0,
                trusted_rollback_owner_gid=0,
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
    if args.action == "grant-runtime":
        persistence.grant_runtime(
            uid=int(args.uid),
            repo_id=str(args.repo_id),
            resource_kind=str(args.resource_kind),
            resource_id=str(args.resource_id),
            action=str(args.runtime_action),
            enabled=not bool(args.disable),
        )
        return {
            "status": "configured",
            "uid": int(args.uid),
            "repo_id": str(args.repo_id),
            "resource_kind": str(args.resource_kind),
            "resource_id": str(args.resource_id),
            "runtime_action": str(args.runtime_action),
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
    if args.action == "grant-cleanup":
        operation = BrokerOperation(str(args.operation))
        persistence.grant_cleanup(
            uid=int(args.uid),
            repo_id=str(args.repo_id),
            operation=operation,
            enabled=not bool(args.disable),
        )
        return {
            "status": "configured",
            "uid": int(args.uid),
            "repo_id": str(args.repo_id),
            "operation": operation.value,
            "enabled": not bool(args.disable),
        }
    if args.action == "grant-cleanup-resource":
        operation = BrokerOperation(str(args.operation))
        persistence.grant_cleanup_resource(
            uid=int(args.uid),
            repo_id=str(args.repo_id),
            resource_kind=str(args.resource_kind),
            resource_id=str(args.resource_id),
            control_binding_id=str(args.control_binding_id),
            immutable_fingerprint=str(args.immutable_fingerprint),
            ownership_fingerprint=str(args.ownership_fingerprint),
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
    database_path = Path(args.database).expanduser().absolute()
    with exclusive_broker_service_lock(database_path):
        runtime = build_store_backed_broker_runtime(
            database_path=database_path,
            socket_path=Path(args.socket),
            host_mutations=host_mutations_factory(),
            access_gid=access_gid,
            max_clients=int(args.max_clients),
            observe_before_lifecycle_plan=observe_before_lifecycle_plan,
        )
        runtime.persistence.recover_interrupted_docker_operations()
        runtime.persistence.recover_interrupted_compose_operations()
        runtime.backend.recover_ephemeral_runs()

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
            runtime_info = validate_runtime_directory(
                socket_path.parent,
                expected_uid=server._expected_uid,
                expected_gid=server._expected_gid,
            )
            if server._socket_mode & 0o060 and not (
                stat.S_IMODE(runtime_info.st_mode) & stat.S_IXGRP
            ):
                raise BrokerError(
                    "unsafe_runtime_directory",
                    "Broker runtime directory must grant traversal to its "
                    "configured access group.",
                )
            try:
                initial = os.lstat(str(socket_path))
            except FileNotFoundError:
                return
            except OSError:
                raise BrokerError(
                    "unsafe_socket_path",
                    "Broker socket path could not be inspected.",
                ) from None
            if not (
                stat.S_ISSOCK(initial.st_mode)
                and initial.st_uid == server._expected_uid
                and initial.st_gid == server._expected_gid
                and stat.S_IMODE(initial.st_mode) == server._socket_mode
            ):
                raise BrokerError(
                    "unsafe_socket_path",
                    "Existing broker socket is not an expected service-owned "
                    "AF_UNIX socket; it was not replaced.",
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
            runtime_after = validate_runtime_directory(
                socket_path.parent,
                expected_uid=server._expected_uid,
                expected_gid=server._expected_gid,
            )
            current_identity = (
                current.st_dev,
                current.st_ino,
                current.st_ctime_ns,
            )
            if (
                not (
                    stat.S_ISSOCK(current.st_mode)
                    and current.st_uid == server._expected_uid
                    and current.st_gid == server._expected_gid
                    and stat.S_IMODE(current.st_mode) == server._socket_mode
                )
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

        worker_reconciliation = runtime.reconcile_workers_on_startup()
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
                    "failure_count": len(worker_reconciliation.get("errors", [])),
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
        stop = threading.Event()
        previous: dict[int, Any] = {}
        shutdown_requested = False

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
            runtime.backend.start_ephemeral_reaper()
            if isinstance(runtime.server, UnixBrokerServer):
                reclaim_stale_socket_before_admission()
            runtime.server.start()
            print(
                json.dumps(
                    {
                        "status": "ready",
                        "service_uid": os.geteuid(),
                        "access_gid": (
                            os.getegid()
                            if access_gid is None
                            else int(access_gid)
                        ),
                        "socket": str(Path(args.socket)),
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
    if args.agent or args.reason:
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
