"""Root-only, fail-closed central readiness export for a Windows observer.

The receipt is deliberately short lived.  It does not enroll anything and it
does not replace live ingress qualification.  It proves that the exact
schema-v14 enrollment, fixed ingress authority, public PKI material and
configuration were mutually consistent at one instant before the disabled
Windows scheduled task may be enabled.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import socket
import sqlite3
import stat
import time
from typing import Any, Callable, Mapping
import unicodedata
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.verification import (
    DNSName,
    PolicyBuilder,
    Store,
    VerificationError,
)

from .broker import BrokerOperation
from .broker_persistence import (
    INFRASTRUCTURE_INGRESS_ACCESS_RECEIPT_SCHEMA,
    INFRASTRUCTURE_INGRESS_BROKER_ACCOUNT_ID,
    INFRASTRUCTURE_INGRESS_SERVICE_ACCOUNT,
    INFRASTRUCTURE_READER_ACCESS_RECEIPT_SCHEMA,
    INFRASTRUCTURE_READER_ACCESS_REQUEST_SCHEMA,
    _require_infrastructure_principal_isolated,
)
from .infrastructure_ingress import (
    InfrastructureIngressError,
    build_tls_context,
    load_ingress_config,
    validate_peer_certificate,
    validate_server_certificate_identity,
    _verify_x509_signature,
)
from .infrastructure_observation import (
    InfrastructureValidationError,
    MAX_VIRTUAL_MACHINES,
    infrastructure_scope_sha256,
    normalize_ps256_spki,
)
from .schema import SCHEMA_VERSION
from .store import CoordinatorStore, canonical_json, refuse_symlink_components


CENTRAL_READINESS_SCHEMA = (
    "spectre.infrastructure.observer-central-readiness.v1"
)
CENTRAL_READINESS_MAX_VALIDITY_SECONDS = 15 * 60
CENTRAL_READINESS_ENDPOINT = (
    "https://spectre.classified.guru:9443/v1/infrastructure/observations"
)
CENTRAL_READINESS_PUBLIC_HOST = "spectre.classified.guru:9443"
MAX_RECEIPT_BYTES = 1024 * 1024
MAX_CERTIFICATE_BYTES = 2 * 1024 * 1024
_SHA256 = frozenset("0123456789abcdef")
_INGRESS_OPERATIONS = frozenset(
    {
        BrokerOperation.INFRASTRUCTURE_INGEST.value,
        BrokerOperation.INFRASTRUCTURE_VERIFICATION_CONTEXT.value,
    }
)


class InfrastructureReadinessError(RuntimeError):
    """A local administrator preflight rejection."""


@dataclass(frozen=True)
class TrustedFile:
    path: Path
    raw: bytes
    sha256: str


@dataclass(frozen=True)
class CentralReadinessInputs:
    database: Path
    host_provision_receipt: Path
    agent_provision_receipt: Path
    certificate_provision_receipt: Path
    ingress_access_receipt: Path
    reader_access_receipt: Path
    ingress_configuration: Path
    client_certificate: Path
    server_trust_root: Path
    output: Path
    validity_seconds: int = CENTRAL_READINESS_MAX_VALIDITY_SECONDS


def export_observer_central_readiness(
    inputs: CentralReadinessInputs,
    *,
    now_epoch: int | None = None,
    expected_uid: int = 0,
    listener_probe: Callable[[str, int], None] | None = None,
) -> dict[str, Any]:
    """Validate exact live authority inputs and create one canonical receipt."""

    if os.geteuid() != expected_uid or expected_uid != 0:
        raise PermissionError(
            "observer central readiness requires the root service owner"
        )
    now = int(time.time()) if now_epoch is None else int(now_epoch)
    if not 1 <= int(inputs.validity_seconds) <= (
        CENTRAL_READINESS_MAX_VALIDITY_SECONDS
    ):
        raise InfrastructureReadinessError(
            "readiness validity must be between one and 900 seconds"
        )
    valid_until_epoch = now + int(inputs.validity_seconds)
    database = _require_root_schema14_database(inputs.database)

    host_file, host_receipt = _read_trusted_json(
        inputs.host_provision_receipt,
        subject="host provision receipt",
    )
    agent_file, agent_receipt = _read_trusted_json(
        inputs.agent_provision_receipt,
        subject="agent provision receipt",
    )
    certificate_file, certificate_receipt = _read_trusted_json(
        inputs.certificate_provision_receipt,
        subject="certificate provision receipt",
    )
    ingress_file, ingress_receipt = _read_trusted_json(
        inputs.ingress_access_receipt,
        subject="ingress access receipt",
    )
    reader_file, reader_receipt = _read_trusted_json(
        inputs.reader_access_receipt,
        subject="reader access receipt",
    )
    configuration_file = _read_trusted_file(
        inputs.ingress_configuration,
        subject="ingress configuration",
        maximum_bytes=64 * 1024,
        allowed_modes={0o400, 0o440, 0o600, 0o640},
    )
    config = load_ingress_config(
        configuration_file.path,
        trusted_owner_uid=expected_uid,
    )
    if (
        config.public_host != CENTRAL_READINESS_PUBLIC_HOST
        or config.listen_port != 9443
        or config.listen_host != "0.0.0.0"
        or config.expected_broker_uid != 0
        or config.account_id != INFRASTRUCTURE_INGRESS_BROKER_ACCOUNT_ID
    ):
        raise InfrastructureReadinessError(
            "ingress is not on the exact externally promoted v1 configuration"
        )
    _require_broker_socket(config)

    try:
        _tls_context, trust = build_tls_context(
            config,
            now_epoch=now,
            trusted_public_owner_uid=expected_uid,
        )
    except InfrastructureIngressError as error:
        raise InfrastructureReadinessError(
            f"ingress TLS preflight failed: {error.code}"
        ) from None

    client_file = _read_trusted_file(
        inputs.client_certificate,
        subject="observer client certificate",
        maximum_bytes=MAX_CERTIFICATE_BYTES,
        allowed_modes={0o400, 0o440, 0o444, 0o600, 0o640, 0o644},
    )
    client_certificates = _load_exact_pem_certificates(
        client_file.raw,
        subject="observer client certificate",
    )
    if len(client_certificates) != 1:
        raise InfrastructureReadinessError(
            "observer client certificate input must contain exactly one leaf"
        )
    client_leaf = client_certificates[0]
    client_der = client_leaf.public_bytes(serialization.Encoding.DER)
    try:
        peer = validate_peer_certificate(
            client_der,
            [client_der, trust.ca_der],
            trust,
            now_epoch=now,
        )
    except InfrastructureIngressError as error:
        raise InfrastructureReadinessError(
            f"observer client certificate preflight failed: {error.code}"
        ) from None
    client_tls_spki = _spki_sha256(client_leaf)

    server_chain_file = _read_trusted_file(
        config.server_certificate_path,
        subject="ingress server certificate chain",
        maximum_bytes=MAX_CERTIFICATE_BYTES,
        allowed_modes={0o400, 0o440, 0o444, 0o600, 0o640, 0o644},
    )
    server_root_file = _read_trusted_file(
        inputs.server_trust_root,
        subject="ingress server trust root",
        maximum_bytes=MAX_CERTIFICATE_BYTES,
        allowed_modes={0o400, 0o440, 0o444, 0o600, 0o640, 0o644},
    )
    server_chain = _load_exact_pem_certificates(
        server_chain_file.raw,
        subject="ingress server certificate chain",
    )
    server_roots = _load_exact_pem_certificates(
        server_root_file.raw,
        subject="ingress server trust root",
    )
    if len(server_roots) != 1:
        raise InfrastructureReadinessError(
            "ingress server trust input must contain exactly one root"
        )
    server_root = server_roots[0]
    server_leaf = validate_server_certificate_identity(
        server_chain_file.raw,
        public_host=config.public_host,
        now_epoch=now,
    )
    _validate_server_chain(
        server_leaf,
        server_chain[1:],
        server_root,
        now_epoch=now,
    )
    server_root_sha256 = _certificate_sha256(server_root)
    server_spki_sha256 = _spki_sha256(server_leaf)

    probe = listener_probe or _probe_listener
    probe("127.0.0.1", config.listen_port)

    with CoordinatorStore.open_read_only(
        database,
        expected_uid=expected_uid,
    ) as store:
        with store.read_transaction() as connection:
            metadata = connection.execute(
                """
                SELECT schema_version, database_generation
                FROM schema_metadata WHERE singleton = 1
                """
            ).fetchone()
            if (
                metadata is None
                or int(metadata["schema_version"]) != 14
                or SCHEMA_VERSION != 14
            ):
                raise InfrastructureReadinessError(
                    "central authority is not exact schema 14"
                )
            authority_generation = _canonical_uuid(
                str(metadata["database_generation"]),
                "authority_generation",
            )
            if (
                config.authority_generation != authority_generation
            ):
                raise InfrastructureReadinessError(
                    "ingress configuration belongs to another authority generation"
                )

            host_result = _validate_admin_receipt(
                connection,
                host_receipt,
                expected_action="host.provision",
            )
            agent_result = _validate_admin_receipt(
                connection,
                agent_receipt,
                expected_action="agent.provision",
            )
            certificate_result = _validate_admin_receipt(
                connection,
                certificate_receipt,
                expected_action="certificate.provision",
            )
            ingress_result = _validate_ingress_access_receipt(
                connection,
                ingress_receipt,
                now_epoch=now,
                authority_generation=authority_generation,
            )
            reader_result = _validate_reader_access_receipt(
                connection,
                reader_receipt,
                now_epoch=now,
                authority_generation=authority_generation,
            )
            enrollment = _validate_current_enrollment(
                connection,
                host_result=host_result,
                agent_result=agent_result,
                certificate_result=certificate_result,
            )

    if (
        ingress_result["authority_generation"] != authority_generation
        or int(ingress_result["valid_until_epoch"]) <= valid_until_epoch
    ):
        raise InfrastructureReadinessError(
            "ingress access does not remain valid for the readiness window"
        )
    if (
        reader_result["authority_generation"] != authority_generation
        or int(reader_result["valid_until_epoch"]) <= valid_until_epoch
    ):
        raise InfrastructureReadinessError(
            "reader access does not remain valid for the readiness window"
        )
    if (
        peer.fingerprint_sha256
        != enrollment["certificate_fingerprint_sha256"]
        or peer.valid_from_epoch != enrollment["valid_from_epoch"]
        or peer.valid_until_epoch != enrollment["valid_until_epoch"]
        or enrollment["valid_from_epoch"] > now
        or enrollment["valid_until_epoch"] <= valid_until_epoch
        or trust.crl_next_update_epoch <= valid_until_epoch
        or int(server_leaf.not_valid_after_utc.timestamp())
        <= valid_until_epoch
        or int(server_root.not_valid_after_utc.timestamp())
        <= valid_until_epoch
    ):
        raise InfrastructureReadinessError(
            "PKI or enrollment validity does not cover the readiness window"
        )

    checked_at = _utc_second(now)
    receipt = {
        "schema": CENTRAL_READINESS_SCHEMA,
        "readiness_id": str(uuid.uuid4()),
        "status": "ready",
        "cell_id": enrollment["cell_id"],
        "host_id": enrollment["host_id"],
        "agent_id": enrollment["agent_id"],
        "scope_sha256": enrollment["scope_sha256"],
        "certificate_generation": enrollment["certificate_generation"],
        "client_certificate_sha256": peer.fingerprint_sha256,
        "jws_key_id": enrollment["jws_key_id"],
        "jws_spki_sha256": enrollment["jws_spki_sha256"],
        "tls_spki_sha256": client_tls_spki,
        "endpoint_uri": CENTRAL_READINESS_ENDPOINT,
        "authority_schema_version": 14,
        "authority_generation": authority_generation,
        "host_provision_receipt_sha256": host_file.sha256,
        "agent_provision_receipt_sha256": agent_file.sha256,
        "certificate_provision_receipt_sha256": certificate_file.sha256,
        "ingress_access_receipt_sha256": ingress_file.sha256,
        "reader_access_receipt_sha256": reader_file.sha256,
        "ingress_configuration_sha256": configuration_file.sha256,
        "client_ca_sha256": trust.ca_sha256,
        "server_trust_root_sha256": server_root_sha256,
        "ingress_server_spki_sha256": server_spki_sha256,
        "ingress_server_certificate_sha256": (
            config.server_certificate_sha256
        ),
        "ingress_server_certificate_generation": (
            config.server_certificate_generation
        ),
        "ingress_server_certificate_valid_from_epoch": (
            config.server_certificate_valid_from_epoch
        ),
        "ingress_server_certificate_valid_until_epoch": (
            config.server_certificate_valid_until_epoch
        ),
        "client_crl_sha256": trust.crl_sha256,
        "checked_at": checked_at,
        "valid_until": _utc_second(valid_until_epoch),
    }
    _validate_readiness_receipt_shape(receipt)
    output = _write_canonical_create_new(
        inputs.output,
        canonical_json(receipt).encode("utf-8"),
        expected_uid=expected_uid,
    )
    return {
        "status": "ready",
        "schema": CENTRAL_READINESS_SCHEMA,
        "readiness_id": receipt["readiness_id"],
        "checked_at": checked_at,
        "valid_until": receipt["valid_until"],
        "output_path": str(output.path),
        "output_sha256": output.sha256,
    }


def _require_root_schema14_database(path: Path) -> Path:
    database = Path(path).expanduser().absolute()
    try:
        refuse_symlink_components(database)
        metadata = database.lstat()
    except (OSError, PermissionError) as error:
        raise InfrastructureReadinessError(
            "central authority database is missing or unsafe"
        ) from error
    if (
        database.resolve() != database
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or metadata.st_nlink != 1
    ):
        raise InfrastructureReadinessError(
            "central authority database must be a stable root-owned regular file"
        )
    uri = database.as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        row = connection.execute(
            "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
        ).fetchone()
    if row is None or int(row[0]) != 14 or SCHEMA_VERSION != 14:
        raise InfrastructureReadinessError(
            "central authority must already be exact schema 14"
        )
    return database


def _read_trusted_json(
    path: Path,
    *,
    subject: str,
) -> tuple[TrustedFile, Mapping[str, Any]]:
    snapshot = _read_trusted_file(
        path,
        subject=subject,
        maximum_bytes=MAX_RECEIPT_BYTES,
        allowed_modes={0o400, 0o600},
    )

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise InfrastructureReadinessError(
                    f"{subject} contains a duplicate JSON key"
                )
            result[key] = value
        return result

    def reject_number(_value: str) -> Any:
        raise InfrastructureReadinessError(
            f"{subject} contains a non-integer JSON number"
        )

    try:
        value = json.loads(
            snapshot.raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InfrastructureReadinessError(
            f"{subject} is not strict UTF-8 JSON"
        ) from error
    _require_nfc_json(value, subject=subject)
    if not isinstance(value, Mapping):
        raise InfrastructureReadinessError(f"{subject} must be a JSON object")
    return snapshot, value


def _read_trusted_file(
    path: Path,
    *,
    subject: str,
    maximum_bytes: int,
    allowed_modes: set[int],
) -> TrustedFile:
    candidate = Path(path).expanduser().absolute()
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise InfrastructureReadinessError(f"{subject} path is unsafe")
    try:
        refuse_symlink_components(candidate)
    except (OSError, PermissionError) as error:
        raise InfrastructureReadinessError(
            f"{subject} path is missing or contains a symbolic link"
        ) from error
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise InfrastructureReadinessError(
            "O_NOFOLLOW is required for central readiness evidence"
        )
    flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(candidate, flags)
    except OSError as error:
        raise InfrastructureReadinessError(
            f"{subject} cannot be opened safely"
        ) from error
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or mode not in allowed_modes
            or before.st_nlink != 1
            or not 1 <= before.st_size <= maximum_bytes
        ):
            raise InfrastructureReadinessError(
                f"{subject} owner, mode, links, type, or size is invalid"
            )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise InfrastructureReadinessError(
                    f"{subject} was truncated during read"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise InfrastructureReadinessError(
                f"{subject} grew during read"
            )
        after = os.fstat(descriptor)
        path_after = candidate.lstat()
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            before.st_uid,
            before.st_gid,
            mode,
            before.st_nlink,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_uid,
            after.st_gid,
            stat.S_IMODE(after.st_mode),
            after.st_nlink,
        )
        if (
            identity_before != identity_after
            or (after.st_dev, after.st_ino)
            != (path_after.st_dev, path_after.st_ino)
        ):
            raise InfrastructureReadinessError(
                f"{subject} changed during verification"
            )
        raw = b"".join(chunks)
        return TrustedFile(
            path=candidate,
            raw=raw,
            sha256=hashlib.sha256(raw).hexdigest(),
        )
    finally:
        os.close(descriptor)


def _validate_admin_receipt(
    connection: sqlite3.Connection,
    receipt: Mapping[str, Any],
    *,
    expected_action: str,
) -> Mapping[str, Any]:
    expected = {
        "receipt_schema",
        "request_id",
        "request_schema",
        "action",
        "request_sha256",
        "result_sha256",
        "operator_uid",
        "authority_schema_version",
        "created_at",
        "replayed",
        "result",
    }
    if (
        set(receipt) != expected
        or receipt.get("receipt_schema")
        != "spectre.infrastructure.admin-receipt.v1"
        or receipt.get("request_schema")
        != "spectre.infrastructure.admin.v1"
        or receipt.get("action") != expected_action
        or receipt.get("operator_uid") != 0
        or receipt.get("authority_schema_version") != 14
        or type(receipt.get("replayed")) is not bool
        or not isinstance(receipt.get("result"), Mapping)
    ):
        raise InfrastructureReadinessError(
            f"{expected_action} receipt is outside the closed contract"
        )
    request_id = _canonical_uuid(receipt["request_id"], "admin request_id")
    _require_sha256(receipt["request_sha256"], "admin request_sha256")
    _require_sha256(receipt["result_sha256"], "admin result_sha256")
    row = connection.execute(
        """
        SELECT request_schema, action, request_sha256, result_json,
               result_sha256, operator_uid, authority_schema_version,
               created_at
        FROM infrastructure_admin_receipts WHERE request_id = ?
        """,
        (request_id,),
    ).fetchone()
    if row is None:
        raise InfrastructureReadinessError(
            f"{expected_action} receipt is absent from the authority"
        )
    result_json = canonical_json(receipt["result"])
    if (
        str(row["request_schema"]) != receipt["request_schema"]
        or str(row["action"]) != expected_action
        or str(row["request_sha256"]) != receipt["request_sha256"]
        or str(row["result_json"]) != result_json
        or str(row["result_sha256"]) != receipt["result_sha256"]
        or hashlib.sha256(result_json.encode("utf-8")).hexdigest()
        != receipt["result_sha256"]
        or int(row["operator_uid"]) != 0
        or int(row["authority_schema_version"]) != 14
        or str(row["created_at"]) != receipt["created_at"]
    ):
        raise InfrastructureReadinessError(
            f"{expected_action} receipt differs from immutable authority evidence"
        )
    return receipt["result"]


def _validate_ingress_access_receipt(
    connection: sqlite3.Connection,
    receipt: Mapping[str, Any],
    *,
    now_epoch: int,
    authority_generation: str,
) -> Mapping[str, Any]:
    expected = {
        "schema",
        "request_id",
        "action",
        "request_sha256",
        "result",
        "result_sha256",
        "operator_uid",
        "authority_schema_version",
        "created_at",
        "replayed",
    }
    if (
        set(receipt) != expected
        or receipt.get("schema") != INFRASTRUCTURE_INGRESS_ACCESS_RECEIPT_SCHEMA
        or receipt.get("action") != "ingress.replace"
        or receipt.get("operator_uid") != 0
        or receipt.get("authority_schema_version") != 14
        or type(receipt.get("replayed")) is not bool
        or not isinstance(receipt.get("result"), Mapping)
    ):
        raise InfrastructureReadinessError(
            "ingress access receipt is outside the closed contract"
        )
    request_id = _canonical_uuid(
        receipt["request_id"],
        "ingress access request_id",
    )
    _require_sha256(
        receipt["request_sha256"],
        "ingress access request_sha256",
    )
    _require_sha256(
        receipt["result_sha256"],
        "ingress access result_sha256",
    )
    result = receipt["result"]
    result_expected = {
        "status",
        "role",
        "service_account",
        "uid",
        "account_id",
        "operations",
        "valid_until_epoch",
        "authority_generation",
    }
    if (
        set(result) != result_expected
        or result.get("status") != "configured"
        or result.get("role") != "infrastructure-ingress"
        or result.get("service_account") != INFRASTRUCTURE_INGRESS_SERVICE_ACCOUNT
        or result.get("account_id") != INFRASTRUCTURE_INGRESS_BROKER_ACCOUNT_ID
        or not isinstance(result.get("operations"), list)
        or set(result.get("operations", ())) != _INGRESS_OPERATIONS
        or len(result.get("operations", ())) != len(_INGRESS_OPERATIONS)
        or type(result.get("uid")) is not int
        or type(result.get("valid_until_epoch")) is not int
        or result.get("valid_until_epoch") <= now_epoch
        or result.get("authority_generation") != authority_generation
    ):
        raise InfrastructureReadinessError(
            "ingress access receipt is not one current exact fixed grant"
        )
    try:
        actual_uid = int(
            pwd.getpwnam(INFRASTRUCTURE_INGRESS_SERVICE_ACCOUNT).pw_uid
        )
    except KeyError as error:
        raise InfrastructureReadinessError(
            "dedicated ingress system account is missing"
        ) from error
    if actual_uid == 0 or actual_uid != result["uid"]:
        raise InfrastructureReadinessError(
            "dedicated ingress system account UID differs from its receipt"
        )
    row = connection.execute(
        """
        SELECT request_schema, action, request_sha256, result_json,
               result_sha256, operator_uid, authority_schema_version,
               created_at
        FROM broker_infrastructure_ingress_access_receipts
        WHERE request_id = ?
        """,
        (request_id,),
    ).fetchone()
    result_json = canonical_json(result)
    if (
        row is None
        or str(row["request_schema"])
        != "spectre.infrastructure.ingress-access.v1"
        or str(row["action"]) != "ingress.replace"
        or str(row["request_sha256"]) != receipt["request_sha256"]
        or str(row["result_json"]) != result_json
        or str(row["result_sha256"]) != receipt["result_sha256"]
        or hashlib.sha256(result_json.encode("utf-8")).hexdigest()
        != receipt["result_sha256"]
        or int(row["operator_uid"]) != 0
        or int(row["authority_schema_version"]) != 14
        or str(row["created_at"]) != receipt["created_at"]
    ):
        raise InfrastructureReadinessError(
            "ingress access receipt differs from immutable authority evidence"
        )
    principal = connection.execute(
        """
        SELECT account_id, enabled FROM broker_acl_principals WHERE uid = ?
        """,
        (actual_uid,),
    ).fetchone()
    grants = list(
        connection.execute(
            """
            SELECT account_id, operation, enabled, valid_until_epoch
            FROM broker_infrastructure_service_acl
            WHERE uid = ? ORDER BY operation
            """,
            (actual_uid,),
        )
    )
    enabled = [row for row in grants if bool(row["enabled"])]
    if (
        principal is None
        or not bool(principal["enabled"])
        or str(principal["account_id"])
        != INFRASTRUCTURE_INGRESS_BROKER_ACCOUNT_ID
        or {str(row["operation"]) for row in enabled} != _INGRESS_OPERATIONS
        or any(
            str(row["account_id"]) != INFRASTRUCTURE_INGRESS_BROKER_ACCOUNT_ID
            or int(row["valid_until_epoch"]) != result["valid_until_epoch"]
            for row in enabled
        )
    ):
        raise InfrastructureReadinessError(
            "current ingress principal or grants differ from the receipt"
        )
    try:
        _require_infrastructure_principal_isolated(
            connection,
            uid=actual_uid,
        )
    except Exception as error:
        raise InfrastructureReadinessError(
            "ingress principal no longer has dedicated fixed authority"
        ) from error
    return result


def _validate_reader_access_receipt(
    connection: sqlite3.Connection,
    receipt: Mapping[str, Any],
    *,
    now_epoch: int,
    authority_generation: str,
) -> Mapping[str, Any]:
    """Bind central readiness to one live, expiring Console read grant."""

    expected = {
        "schema",
        "request_id",
        "action",
        "request_sha256",
        "result",
        "result_sha256",
        "operator_uid",
        "authority_schema_version",
        "created_at",
        "replayed",
    }
    if (
        set(receipt) != expected
        or receipt.get("schema") != INFRASTRUCTURE_READER_ACCESS_RECEIPT_SCHEMA
        or receipt.get("action") != "reader.replace"
        or receipt.get("operator_uid") != 0
        or receipt.get("authority_schema_version") != 14
        or type(receipt.get("replayed")) is not bool
        or not isinstance(receipt.get("result"), Mapping)
    ):
        raise InfrastructureReadinessError(
            "reader access receipt is outside the closed contract"
        )
    request_id = _canonical_uuid(
        receipt["request_id"],
        "reader access request_id",
    )
    _require_sha256(
        receipt["request_sha256"],
        "reader access request_sha256",
    )
    _require_sha256(
        receipt["result_sha256"],
        "reader access result_sha256",
    )
    result = receipt["result"]
    result_expected = {
        "status",
        "role",
        "service_account",
        "uid",
        "account_id",
        "operations",
        "valid_until_epoch",
        "authority_generation",
    }
    if (
        set(result) != result_expected
        or result.get("status") != "configured"
        or result.get("role") != "infrastructure-reader"
        or not isinstance(result.get("service_account"), str)
        or not result.get("service_account")
        or not isinstance(result.get("account_id"), str)
        or not result.get("account_id")
        or result.get("operations") != [
            BrokerOperation.INFRASTRUCTURE_READ.value
        ]
        or type(result.get("uid")) is not int
        or type(result.get("valid_until_epoch")) is not int
        or result.get("valid_until_epoch") <= now_epoch
        or result.get("authority_generation") != authority_generation
    ):
        raise InfrastructureReadinessError(
            "reader access receipt is not one current exact read grant"
        )
    try:
        actual_uid = int(pwd.getpwnam(result["service_account"]).pw_uid)
    except KeyError as error:
        raise InfrastructureReadinessError(
            "infrastructure reader operating-system account is missing"
        ) from error
    if actual_uid == 0 or actual_uid != result["uid"]:
        raise InfrastructureReadinessError(
            "infrastructure reader account UID differs from its receipt"
        )
    row = connection.execute(
        """
        SELECT request_schema, action, request_sha256, result_json,
               result_sha256, operator_uid, authority_schema_version,
               created_at
        FROM broker_infrastructure_reader_access_receipts
        WHERE request_id = ?
        """,
        (request_id,),
    ).fetchone()
    result_json = canonical_json(result)
    if (
        row is None
        or str(row["request_schema"])
        != INFRASTRUCTURE_READER_ACCESS_REQUEST_SCHEMA
        or str(row["action"]) != "reader.replace"
        or str(row["request_sha256"]) != receipt["request_sha256"]
        or str(row["result_json"]) != result_json
        or str(row["result_sha256"]) != receipt["result_sha256"]
        or hashlib.sha256(result_json.encode("utf-8")).hexdigest()
        != receipt["result_sha256"]
        or int(row["operator_uid"]) != 0
        or int(row["authority_schema_version"]) != 14
        or str(row["created_at"]) != receipt["created_at"]
    ):
        raise InfrastructureReadinessError(
            "reader access receipt differs from immutable authority evidence"
        )
    principal = connection.execute(
        """
        SELECT account_id, enabled FROM broker_acl_principals WHERE uid = ?
        """,
        (actual_uid,),
    ).fetchone()
    grants = list(
        connection.execute(
            """
            SELECT account_id, operation, enabled, valid_until_epoch
            FROM broker_infrastructure_service_acl
            WHERE uid = ? ORDER BY operation
            """,
            (actual_uid,),
        )
    )
    enabled = [row for row in grants if bool(row["enabled"])]
    if (
        principal is None
        or not bool(principal["enabled"])
        or str(principal["account_id"]) != result["account_id"]
        or len(enabled) != 1
        or str(enabled[0]["account_id"]) != result["account_id"]
        or str(enabled[0]["operation"])
        != BrokerOperation.INFRASTRUCTURE_READ.value
        or int(enabled[0]["valid_until_epoch"])
        != result["valid_until_epoch"]
    ):
        raise InfrastructureReadinessError(
            "current reader principal or grant differs from the receipt"
        )
    return result


def _validate_current_enrollment(
    connection: sqlite3.Connection,
    *,
    host_result: Mapping[str, Any],
    agent_result: Mapping[str, Any],
    certificate_result: Mapping[str, Any],
) -> dict[str, Any]:
    if set(host_result) != {
        "host_id",
        "cell_id",
        "scope_sha256",
        "approved_vm_count",
    }:
        raise InfrastructureReadinessError(
            "host provision result is outside the closed contract"
        )
    if set(agent_result) != {
        "agent_id",
        "host_id",
        "assigned_scope_sha256",
    }:
        raise InfrastructureReadinessError(
            "agent provision result is outside the closed contract"
        )
    certificate_fields = {
        "agent_id",
        "certificate_generation",
        "certificate_fingerprint_sha256",
        "jws_key_id",
        "jws_algorithm",
        "jws_spki_der_base64",
        "jws_spki_sha256",
        "valid_from_epoch",
        "valid_until_epoch",
    }
    if set(certificate_result) != certificate_fields:
        raise InfrastructureReadinessError(
            "certificate provision result is outside the closed contract"
        )
    host_id = _canonical_uuid(host_result["host_id"], "host_id")
    cell_id = _canonical_uuid(host_result["cell_id"], "cell_id")
    agent_id = _canonical_uuid(agent_result["agent_id"], "agent_id")
    scope_sha256 = _require_sha256(host_result["scope_sha256"], "scope_sha256")
    approved_vm_count = host_result["approved_vm_count"]
    certificate_generation = certificate_result["certificate_generation"]
    if (
        type(approved_vm_count) is not int
        or not 0 <= approved_vm_count <= MAX_VIRTUAL_MACHINES
        or agent_result["host_id"] != host_id
        or agent_result["assigned_scope_sha256"] != scope_sha256
        or certificate_result["agent_id"] != agent_id
        or certificate_result["jws_algorithm"] != "PS256"
        or type(certificate_generation) is not int
        or not 1 <= certificate_generation <= 2_147_483_647
        or type(certificate_result["valid_from_epoch"]) is not int
        or type(certificate_result["valid_until_epoch"]) is not int
        or certificate_result["valid_until_epoch"]
        <= certificate_result["valid_from_epoch"]
        or certificate_result["jws_key_id"]
        != f"spectre-hv:{agent_id}:g{certificate_generation}"
    ):
        raise InfrastructureReadinessError(
            "host, agent, certificate receipts do not form one enrollment"
        )
    try:
        signing_material = normalize_ps256_spki(
            certificate_result["jws_spki_der_base64"],
            certificate_result["jws_spki_sha256"],
            code="invalid_central_readiness",
        )
    except InfrastructureValidationError as error:
        raise InfrastructureReadinessError(
            "certificate receipt does not contain one canonical PS256 key"
        ) from error
    row = connection.execute(
        """
        SELECT certificate.certificate_fingerprint_sha256,
               certificate.jws_key_id, certificate.jws_algorithm,
               certificate.jws_spki_der_base64,
               certificate.jws_spki_sha256,
               certificate.valid_from_epoch, certificate.valid_until_epoch,
               certificate.revoked_at,
               agent.host_id, agent.assigned_scope_sha256,
               agent.enabled AS agent_enabled,
               host.cell_id, host.scope_sha256,
               host.enabled AS host_enabled,
               cell.enabled AS cell_enabled
        FROM infrastructure_agent_certificates certificate
        JOIN infrastructure_observer_agents agent USING(agent_id)
        JOIN infrastructure_hosts host USING(host_id)
        JOIN infrastructure_cells cell USING(cell_id)
        WHERE certificate.agent_id = ?
          AND certificate.certificate_generation = ?
        """,
        (agent_id, certificate_generation),
    ).fetchone()
    scope_rows = list(
        connection.execute(
            """
            SELECT vm_id, approved_role
            FROM infrastructure_host_vm_scope
            WHERE host_id = ? ORDER BY vm_id
            """,
            (host_id,),
        )
    )
    calculated_scope = infrastructure_scope_sha256(
        host_id,
        {
            str(item["vm_id"]): str(item["approved_role"])
            for item in scope_rows
        },
    )
    if (
        row is None
        or not bool(row["agent_enabled"])
        or not bool(row["host_enabled"])
        or not bool(row["cell_enabled"])
        or row["revoked_at"] is not None
        or str(row["host_id"]) != host_id
        or str(row["cell_id"]) != cell_id
        or str(row["assigned_scope_sha256"]) != scope_sha256
        or str(row["scope_sha256"]) != scope_sha256
        or calculated_scope != scope_sha256
        or len(scope_rows) != approved_vm_count
        or str(row["certificate_fingerprint_sha256"])
        != certificate_result["certificate_fingerprint_sha256"]
        or str(row["jws_key_id"]) != certificate_result["jws_key_id"]
        or str(row["jws_algorithm"]) != "PS256"
        or str(row["jws_spki_der_base64"])
        != signing_material["jws_spki_der_base64"]
        or str(row["jws_spki_sha256"])
        != signing_material["jws_spki_sha256"]
        or int(row["valid_from_epoch"])
        != certificate_result["valid_from_epoch"]
        or int(row["valid_until_epoch"])
        != certificate_result["valid_until_epoch"]
    ):
        raise InfrastructureReadinessError(
            "current enrollment differs from its immutable receipts"
        )
    _require_sha256(
        certificate_result["certificate_fingerprint_sha256"],
        "certificate fingerprint",
    )
    jws_spki_sha256 = signing_material["jws_spki_sha256"]
    return {
        "cell_id": cell_id,
        "host_id": host_id,
        "agent_id": agent_id,
        "scope_sha256": scope_sha256,
        "certificate_generation": certificate_generation,
        "certificate_fingerprint_sha256": certificate_result[
            "certificate_fingerprint_sha256"
        ],
        "jws_key_id": str(certificate_result["jws_key_id"]),
        "jws_spki_sha256": jws_spki_sha256,
        "valid_from_epoch": certificate_result["valid_from_epoch"],
        "valid_until_epoch": certificate_result["valid_until_epoch"],
    }


def _require_broker_socket(config: Any) -> None:
    try:
        refuse_symlink_components(config.broker_socket_path)
        metadata = config.broker_socket_path.lstat()
    except (OSError, PermissionError) as error:
        raise InfrastructureReadinessError(
            "configured broker socket is missing or unsafe"
        ) from error
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != config.expected_broker_uid
        or metadata.st_gid != config.expected_socket_gid
        or stat.S_IMODE(metadata.st_mode) != config.expected_socket_mode
    ):
        raise InfrastructureReadinessError(
            "configured broker socket identity differs from ingress policy"
        )


def _load_exact_pem_certificates(
    raw: bytes,
    *,
    subject: str,
) -> list[x509.Certificate]:
    try:
        certificates = x509.load_pem_x509_certificates(raw)
    except ValueError as error:
        raise InfrastructureReadinessError(
            f"{subject} cannot be parsed"
        ) from error
    if not certificates:
        raise InfrastructureReadinessError(f"{subject} is empty")
    return certificates


def _validate_server_chain(
    leaf: x509.Certificate,
    intermediates: list[x509.Certificate],
    root: x509.Certificate,
    *,
    now_epoch: int,
) -> None:
    try:
        constraints = root.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
        key_usage = root.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        ).value
    except x509.ExtensionNotFound as error:
        raise InfrastructureReadinessError(
            "server trust root lacks required CA extensions"
        ) from error
    if (
        not constraints.ca
        or not key_usage.key_cert_sign
        or root.issuer != root.subject
        or not (
            int(root.not_valid_before_utc.timestamp())
            <= now_epoch
            < int(root.not_valid_after_utc.timestamp())
        )
    ):
        raise InfrastructureReadinessError(
            "server trust root is not one current self-signed CA"
        )
    try:
        _verify_x509_signature(root.public_key(), root)
        root_der = root.public_bytes(serialization.Encoding.DER)
        filtered = [
            certificate
            for certificate in intermediates
            if certificate.public_bytes(serialization.Encoding.DER) != root_der
        ]
        verifier = (
            PolicyBuilder()
            .store(Store([root]))
            .time(datetime.fromtimestamp(now_epoch, tz=timezone.utc))
            .max_chain_depth(8)
            .build_server_verifier(DNSName("spectre.classified.guru"))
        )
        verified = verifier.verify(leaf, filtered)
    except (ValueError, TypeError, VerificationError) as error:
        raise InfrastructureReadinessError(
            "server certificate chain does not terminate at the exact trust root"
        ) from error
    if (
        not verified
        or verified[0].public_bytes(serialization.Encoding.DER)
        != leaf.public_bytes(serialization.Encoding.DER)
        or verified[-1].public_bytes(serialization.Encoding.DER)
        != root.public_bytes(serialization.Encoding.DER)
    ):
        raise InfrastructureReadinessError(
            "server certificate verifier returned an unexpected chain"
        )


def _probe_listener(host: str, port: int) -> None:
    try:
        with socket.create_connection((host, int(port)), timeout=3.0):
            pass
    except OSError as error:
        raise InfrastructureReadinessError(
            "external-promoted ingress listener is not accepting local TCP"
        ) from error


def _validate_readiness_receipt_shape(receipt: Mapping[str, Any]) -> None:
    expected = {
        "schema",
        "readiness_id",
        "status",
        "cell_id",
        "host_id",
        "agent_id",
        "scope_sha256",
        "certificate_generation",
        "client_certificate_sha256",
        "jws_key_id",
        "jws_spki_sha256",
        "tls_spki_sha256",
        "endpoint_uri",
        "authority_schema_version",
        "authority_generation",
        "host_provision_receipt_sha256",
        "agent_provision_receipt_sha256",
        "certificate_provision_receipt_sha256",
        "ingress_access_receipt_sha256",
        "reader_access_receipt_sha256",
        "ingress_configuration_sha256",
        "client_ca_sha256",
        "server_trust_root_sha256",
        "ingress_server_spki_sha256",
        "ingress_server_certificate_sha256",
        "ingress_server_certificate_generation",
        "ingress_server_certificate_valid_from_epoch",
        "ingress_server_certificate_valid_until_epoch",
        "client_crl_sha256",
        "checked_at",
        "valid_until",
    }
    if (
        set(receipt) != expected
        or receipt.get("schema") != CENTRAL_READINESS_SCHEMA
        or receipt.get("status") != "ready"
        or receipt.get("endpoint_uri") != CENTRAL_READINESS_ENDPOINT
        or receipt.get("authority_schema_version") != 14
    ):
        raise InfrastructureReadinessError(
            "generated readiness receipt is outside its closed contract"
        )
    for field in ("readiness_id", "cell_id", "host_id", "agent_id"):
        _canonical_uuid(receipt[field], field)
    _canonical_uuid(
        receipt["authority_generation"],
        "authority_generation",
    )
    for field in (
        "scope_sha256",
        "client_certificate_sha256",
        "jws_spki_sha256",
        "tls_spki_sha256",
        "host_provision_receipt_sha256",
        "agent_provision_receipt_sha256",
        "certificate_provision_receipt_sha256",
        "ingress_access_receipt_sha256",
        "reader_access_receipt_sha256",
        "ingress_configuration_sha256",
        "client_ca_sha256",
        "server_trust_root_sha256",
        "ingress_server_spki_sha256",
        "ingress_server_certificate_sha256",
        "client_crl_sha256",
    ):
        _require_sha256(receipt[field], field)
    if (
        type(receipt["certificate_generation"]) is not int
        or not 1 <= receipt["certificate_generation"] <= (1 << 31) - 1
        or receipt["jws_key_id"]
        != (
            f"spectre-hv:{receipt['agent_id']}:"
            f"g{receipt['certificate_generation']}"
        )
        or type(receipt["ingress_server_certificate_generation"]) is not int
        or not 1
        <= receipt["ingress_server_certificate_generation"]
        <= (1 << 31) - 1
        or type(receipt["ingress_server_certificate_valid_from_epoch"])
        is not int
        or type(receipt["ingress_server_certificate_valid_until_epoch"])
        is not int
        or receipt["ingress_server_certificate_valid_until_epoch"]
        <= receipt["ingress_server_certificate_valid_from_epoch"]
        or receipt["ingress_server_certificate_valid_until_epoch"]
        - receipt["ingress_server_certificate_valid_from_epoch"]
        > 7 * 24 * 60 * 60
    ):
        raise InfrastructureReadinessError(
            "generated server certificate generation is outside its bound"
        )


def _write_canonical_create_new(
    path: Path,
    payload: bytes,
    *,
    expected_uid: int,
) -> TrustedFile:
    output = Path(path).expanduser().absolute()
    parent = output.parent
    try:
        refuse_symlink_components(parent)
        parent_metadata = parent.lstat()
    except (OSError, PermissionError) as error:
        raise InfrastructureReadinessError(
            "readiness output parent is missing or unsafe"
        ) from error
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != expected_uid
        or stat.S_IMODE(parent_metadata.st_mode) & 0o022
    ):
        raise InfrastructureReadinessError(
            "readiness output parent must be root-owned and not writable by others"
        )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(output, flags, 0o600)
    committed = False
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise InfrastructureReadinessError(
                    "readiness output write made no progress"
                )
            view = view[written:]
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != len(payload)
        ):
            raise InfrastructureReadinessError(
                "readiness output postcondition failed"
            )
        committed = True
    finally:
        os.close(descriptor)
        if not committed:
            try:
                output.unlink()
            except FileNotFoundError:
                pass
    directory_fd = os.open(
        parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return TrustedFile(
        path=output,
        raw=payload,
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def _certificate_sha256(certificate: x509.Certificate) -> str:
    return hashlib.sha256(
        certificate.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def _spki_sha256(certificate: x509.Certificate) -> str:
    return hashlib.sha256(
        certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()


def _canonical_uuid(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise InfrastructureReadinessError(f"{field} must be a UUID")
    try:
        parsed = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError) as error:
        raise InfrastructureReadinessError(f"{field} must be a UUID") from error
    if parsed != value:
        raise InfrastructureReadinessError(
            f"{field} must be a canonical lowercase UUID"
        )
    return value


def _require_sha256(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or not set(value) <= _SHA256
    ):
        raise InfrastructureReadinessError(
            f"{field} must be 64 lowercase hexadecimal characters"
        )
    return value


def _require_nfc_json(value: Any, *, subject: str) -> None:
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise InfrastructureReadinessError(
                f"{subject} contains a non-NFC string"
            )
        return
    if isinstance(value, list):
        for item in value:
            _require_nfc_json(item, subject=subject)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            _require_nfc_json(key, subject=subject)
            _require_nfc_json(item, subject=subject)
        return
    if value is None or type(value) in {bool, int}:
        return
    raise InfrastructureReadinessError(
        f"{subject} contains a value outside the closed JSON contract"
    )


def _utc_second(epoch: int) -> str:
    return datetime.fromtimestamp(
        int(epoch),
        tz=timezone.utc,
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "CENTRAL_READINESS_ENDPOINT",
    "CENTRAL_READINESS_MAX_VALIDITY_SECONDS",
    "CENTRAL_READINESS_SCHEMA",
    "CentralReadinessInputs",
    "InfrastructureReadinessError",
    "export_observer_central_readiness",
]
