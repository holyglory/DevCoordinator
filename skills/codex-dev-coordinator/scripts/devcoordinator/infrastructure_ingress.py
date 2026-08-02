"""Dedicated mTLS/JWS network ingress for remote infrastructure observations.

The ingress is intentionally a narrow adapter.  It owns no inventory state and
cannot enumerate enrollment.  Every connection gets a freshly built TLS 1.3
context with the exact private client CA and current authenticated CRL, accepts
one strict POST, verifies the leaf and compact JWS, stages the exact signed
bytes, and calls the peer-authenticated Coordinator broker.
"""

from __future__ import annotations

import base64
import binascii
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from importlib import metadata as importlib_metadata
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import threading
import time
from typing import Any, Callable, Mapping, Protocol, Sequence
import uuid

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed25519,
    ed448,
    padding,
    rsa,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

from .broker import BrokerClient, BrokerError, BrokerOperation, BrokerRequest
from .infrastructure_artifacts import (
    MAX_SIGNED_ENVELOPE_BYTES,
    SYSTEM_INGRESS_STAGING_ROOT,
    stage_signed_envelope,
)
from .infrastructure_observation import (
    INFRASTRUCTURE_BROKER_PROJECT_ID,
    INFRASTRUCTURE_INGEST_RESOURCE_ID,
    INFRASTRUCTURE_JWS_ALGORITHM,
    INFRASTRUCTURE_JWS_TYPE,
    INFRASTRUCTURE_VERIFICATION_CONTEXT_RESOURCE_ID,
    InfrastructureValidationError,
    parse_canonical_observation_payload,
)
from .schema import INFRASTRUCTURE_CERTIFICATE_MAX_VALIDITY_SECONDS
from .store import canonical_json, refuse_symlink_components


INGRESS_CONFIG_SCHEMA = "spectre.infrastructure.ingress-config.v1"
INGRESS_PATH = "/v1/infrastructure/observations"
INGRESS_RESPONSE_SCHEMA = "spectre.infrastructure.ingress-response.v1"
CRYPTOGRAPHY_REQUIRED_VERSION = "49.0.0"
RUNTIME_REQUIRED_VERSIONS = {
    "cryptography": CRYPTOGRAPHY_REQUIRED_VERSION,
    "cffi": "2.0.0",
    "pycparser": "2.22",
}
JWS_OPERATION_NAMESPACE = uuid.UUID("eb965d2e-2cb7-4eb6-8a16-f60f1a6afaa2")
MAX_CONFIG_BYTES = 64 * 1024
MAX_CA_OR_CRL_BYTES = 2 * 1024 * 1024
MAX_PROTECTED_HEADER_BYTES = 4 * 1024
MAX_HTTP_LINE_BYTES = 8 * 1024
MAX_HTTP_HEADER_COUNT = 16
RATE_LIMIT_KEY_CAP = 4096
MAX_SERVER_CERTIFICATE_VALIDITY_SECONDS = 7 * 24 * 60 * 60

_LOGGER = logging.getLogger("devcoordinator.infrastructure_ingress")
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:@-]{1,128}")
_CERTIFICATE_PEM = re.compile(
    rb"\s*(-----BEGIN CERTIFICATE-----\r?\n"
    rb"[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----)\s*",
    re.DOTALL,
)
_CRL_PEM = re.compile(
    rb"\s*(-----BEGIN X509 CRL-----\r?\n"
    rb"[A-Za-z0-9+/=\r\n]+-----END X509 CRL-----)\s*",
    re.DOTALL,
)
_HEADER_NAME = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}")
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")


class InfrastructureIngressError(RuntimeError):
    """Safe typed ingress rejection."""

    def __init__(self, code: str, message: str, *, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = int(status)


@dataclass(frozen=True)
class IngressLimits:
    handshake_timeout_seconds: float
    request_timeout_seconds: float
    max_header_bytes: int
    max_body_bytes: int
    max_concurrency: int
    rate_per_certificate_per_minute: int
    rate_per_ip_per_minute: int
    crl_max_age_seconds: int


@dataclass(frozen=True)
class IngressConfig:
    listen_host: str
    listen_port: int
    public_host: str
    server_certificate_path: Path
    server_private_key_path: Path
    server_certificate_generation: int
    server_certificate_sha256: str
    server_certificate_valid_from_epoch: int
    server_certificate_valid_until_epoch: int
    client_ca_certificate_path: Path
    client_crl_path: Path
    artifact_root: Path
    broker_socket_path: Path
    expected_broker_uid: int
    expected_socket_gid: int
    expected_socket_mode: int
    authority_generation: str
    account_id: str
    limits: IngressLimits


@dataclass(frozen=True)
class TrustSnapshot:
    ca_certificate: x509.Certificate
    ca_der: bytes
    ca_sha256: str
    crl: x509.CertificateRevocationList
    crl_sha256: str
    crl_last_update_epoch: int
    crl_next_update_epoch: int


@dataclass(frozen=True)
class PeerCertificate:
    certificate: x509.Certificate
    der: bytes
    fingerprint_sha256: str
    valid_from_epoch: int
    valid_until_epoch: int


@dataclass(frozen=True)
class AdmittedTransport:
    peer: PeerCertificate
    source_ip: str
    admitted_epoch: int


@dataclass(frozen=True)
class ParsedJWS:
    compact: bytes
    observation: dict[str, Any]
    payload_sha256: str
    certificate_generation: int
    key_id: str
    spki_sha256: str
    signing_input: bytes
    signature: bytes


class InfrastructureBroker(Protocol):
    def verification_context(
        self, *, fingerprint_sha256: str, generation: int
    ) -> Mapping[str, Any]: ...

    def ingest(
        self, *, arguments: Mapping[str, Any], operation_id: str
    ) -> Mapping[str, Any]: ...


def require_cryptography_runtime() -> str:
    """Fail startup unless the reviewed cryptographic runtime and APIs exist."""

    observed: dict[str, str] = {}
    for package, expected_version in RUNTIME_REQUIRED_VERSIONS.items():
        try:
            version = importlib_metadata.version(package)
        except importlib_metadata.PackageNotFoundError as error:
            raise InfrastructureIngressError(
                (
                    "cryptography_dependency_missing"
                    if package == "cryptography"
                    else "cryptography_runtime_dependency_missing"
                ),
                "A pinned cryptographic runtime dependency is not installed.",
                status=503,
            ) from error
        if (
            re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?(?:[.+-].*)?", version)
            is None
        ):
            raise InfrastructureIngressError(
                (
                    "cryptography_version_invalid"
                    if package == "cryptography"
                    else "cryptography_runtime_dependency_version_invalid"
                ),
                "A cryptographic runtime dependency version cannot be validated.",
                status=503,
            )
        if version != expected_version:
            raise InfrastructureIngressError(
                (
                    "cryptography_version_unsupported"
                    if package == "cryptography"
                    else "cryptography_runtime_dependency_version_unsupported"
                ),
                "The cryptographic runtime does not match its exact reviewed closure.",
                status=503,
            )
        observed[package] = version
    capabilities = (
        hasattr(x509, "load_pem_x509_certificate"),
        hasattr(x509, "load_pem_x509_crl"),
        hasattr(x509.Certificate, "not_valid_before_utc"),
        hasattr(x509.CertificateRevocationList, "last_update_utc"),
        hasattr(ssl, "VERIFY_CRL_CHECK_CHAIN"),
        hasattr(ssl.SSLSocket, "get_verified_chain"),
    )
    if not all(capabilities):
        raise InfrastructureIngressError(
            "cryptography_capability_missing",
            "The TLS/X.509 runtime lacks a reviewed ingress capability.",
            status=503,
        )
    return observed["cryptography"]


def load_ingress_config(
    path: Path,
    *,
    trusted_owner_uid: int = 0,
) -> IngressConfig:
    """Read one root-owned, closed, bounded JSON service configuration."""

    raw = _read_trusted_file(
        path,
        expected_uid=trusted_owner_uid,
        expected_gid=os.getegid(),
        maximum_bytes=MAX_CONFIG_BYTES,
        allowed_modes={0o400, 0o440, 0o600, 0o640},
        subject="ingress configuration",
    )
    try:
        document = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InfrastructureIngressError(
            "configuration_invalid",
            "Ingress configuration is not strict JSON.",
            status=503,
        ) from error
    if not isinstance(document, dict) or set(document) != {
        "schema",
        "listen",
        "tls",
        "artifact_root",
        "broker",
        "limits",
    }:
        raise InfrastructureIngressError(
            "configuration_invalid",
            "Ingress configuration fields are not the closed v1 contract.",
            status=503,
        )
    if document.get("schema") != INGRESS_CONFIG_SCHEMA:
        raise InfrastructureIngressError(
            "configuration_invalid",
            "Ingress configuration schema is unsupported.",
            status=503,
        )
    listen = _exact_object(
        document["listen"],
        {"host", "port", "public_host"},
        subject="listen configuration",
    )
    tls = _exact_object(
        document["tls"],
        {
            "server_certificate_path",
            "server_private_key_path",
            "server_certificate_generation",
            "server_certificate_sha256",
            "server_certificate_valid_from_epoch",
            "server_certificate_valid_until_epoch",
            "client_ca_certificate_path",
            "client_crl_path",
        },
        subject="TLS configuration",
    )
    broker = _exact_object(
        document["broker"],
        {
            "socket_path",
            "expected_broker_uid",
            "expected_socket_gid",
            "expected_socket_mode",
            "authority_generation",
            "account_id",
        },
        subject="broker configuration",
    )
    limits = _exact_object(
        document["limits"],
        {
            "handshake_timeout_seconds",
            "request_timeout_seconds",
            "max_header_bytes",
            "max_body_bytes",
            "max_concurrency",
            "rate_per_certificate_per_minute",
            "rate_per_ip_per_minute",
            "crl_max_age_seconds",
        },
        subject="limit configuration",
    )
    listen_host = _ipv4_literal(listen["host"], "listen.host")
    port = _integer(listen["port"], "listen.port", 1024, 65535)
    public_host = _bounded_ascii(listen["public_host"], "listen.public_host", 3, 253)
    expected_public_host = public_host.lower()
    if public_host != expected_public_host or any(
        character in public_host for character in "/?#@"
    ):
        raise InfrastructureIngressError(
            "configuration_invalid",
            "listen.public_host must be a canonical lowercase host[:port].",
            status=503,
        )
    host_name, separator, host_port = public_host.rpartition(":")
    if (
        separator != ":"
        or not host_name
        or not re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\."
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
            host_name,
        )
        or host_port != str(port)
    ):
        raise InfrastructureIngressError(
            "configuration_invalid",
            "listen.public_host must bind the exact DNS name and listen port.",
            status=503,
        )
    expected_mode_raw = broker["expected_socket_mode"]
    if not isinstance(expected_mode_raw, str) or not re.fullmatch(
        r"0[0-7]{3}", expected_mode_raw
    ):
        raise InfrastructureIngressError(
            "configuration_invalid",
            "broker.expected_socket_mode must be four canonical octal digits.",
            status=503,
        )
    parsed_limits = IngressLimits(
        handshake_timeout_seconds=_number(
            limits["handshake_timeout_seconds"],
            "limits.handshake_timeout_seconds",
            1.0,
            15.0,
        ),
        request_timeout_seconds=_number(
            limits["request_timeout_seconds"],
            "limits.request_timeout_seconds",
            2.0,
            30.0,
        ),
        max_header_bytes=_integer(
            limits["max_header_bytes"],
            "limits.max_header_bytes",
            1024,
            32 * 1024,
        ),
        max_body_bytes=_integer(
            limits["max_body_bytes"],
            "limits.max_body_bytes",
            1024,
            MAX_SIGNED_ENVELOPE_BYTES,
        ),
        max_concurrency=_integer(
            limits["max_concurrency"], "limits.max_concurrency", 1, 128
        ),
        rate_per_certificate_per_minute=_integer(
            limits["rate_per_certificate_per_minute"],
            "limits.rate_per_certificate_per_minute",
            1,
            600,
        ),
        rate_per_ip_per_minute=_integer(
            limits["rate_per_ip_per_minute"],
            "limits.rate_per_ip_per_minute",
            1,
            1200,
        ),
        crl_max_age_seconds=_integer(
            limits["crl_max_age_seconds"],
            "limits.crl_max_age_seconds",
            60,
            24 * 60 * 60,
        ),
    )
    if parsed_limits.max_body_bytes != MAX_SIGNED_ENVELOPE_BYTES:
        raise InfrastructureIngressError(
            "configuration_invalid",
            "limits.max_body_bytes must equal the reviewed 786432-byte bound.",
            status=503,
        )
    server_certificate_generation = _integer(
        tls["server_certificate_generation"],
        "tls.server_certificate_generation",
        1,
        (1 << 31) - 1,
    )
    server_certificate_sha256 = tls["server_certificate_sha256"]
    if (
        not isinstance(server_certificate_sha256, str)
        or _HEX_SHA256.fullmatch(server_certificate_sha256) is None
    ):
        raise InfrastructureIngressError(
            "configuration_invalid",
            "tls.server_certificate_sha256 must be lowercase hexadecimal.",
            status=503,
        )
    server_certificate_valid_from_epoch = _integer(
        tls["server_certificate_valid_from_epoch"],
        "tls.server_certificate_valid_from_epoch",
        0,
        (1 << 63) - 1,
    )
    server_certificate_valid_until_epoch = _integer(
        tls["server_certificate_valid_until_epoch"],
        "tls.server_certificate_valid_until_epoch",
        1,
        (1 << 63) - 1,
    )
    if (
        server_certificate_valid_until_epoch
        <= server_certificate_valid_from_epoch
        or server_certificate_valid_until_epoch
        - server_certificate_valid_from_epoch
        > MAX_SERVER_CERTIFICATE_VALIDITY_SECONDS
    ):
        raise InfrastructureIngressError(
            "configuration_invalid",
            "The ingress server certificate generation exceeds seven days.",
            status=503,
        )
    return IngressConfig(
        listen_host=listen_host,
        listen_port=port,
        public_host=public_host,
        server_certificate_path=_absolute_path(
            tls["server_certificate_path"], "tls.server_certificate_path"
        ),
        server_private_key_path=_absolute_path(
            tls["server_private_key_path"], "tls.server_private_key_path"
        ),
        server_certificate_generation=server_certificate_generation,
        server_certificate_sha256=server_certificate_sha256,
        server_certificate_valid_from_epoch=(
            server_certificate_valid_from_epoch
        ),
        server_certificate_valid_until_epoch=(
            server_certificate_valid_until_epoch
        ),
        client_ca_certificate_path=_absolute_path(
            tls["client_ca_certificate_path"], "tls.client_ca_certificate_path"
        ),
        client_crl_path=_absolute_path(
            tls["client_crl_path"], "tls.client_crl_path"
        ),
        artifact_root=_absolute_path(document["artifact_root"], "artifact_root"),
        broker_socket_path=_absolute_path(
            broker["socket_path"], "broker.socket_path"
        ),
        expected_broker_uid=_integer(
            broker["expected_broker_uid"],
            "broker.expected_broker_uid",
            0,
            (1 << 31) - 1,
        ),
        expected_socket_gid=_integer(
            broker["expected_socket_gid"],
            "broker.expected_socket_gid",
            0,
            (1 << 31) - 1,
        ),
        expected_socket_mode=int(expected_mode_raw, 8),
        authority_generation=_identifier(
            broker["authority_generation"], "broker.authority_generation"
        ),
        account_id=_identifier(broker["account_id"], "broker.account_id"),
        limits=parsed_limits,
    )


def build_tls_context(
    config: IngressConfig,
    *,
    now_epoch: int | None = None,
    trusted_public_owner_uid: int = 0,
) -> tuple[ssl.SSLContext, TrustSnapshot]:
    """Build a fresh TLS 1.3 context and authenticated CRL snapshot."""

    require_cryptography_runtime()
    now = int(time.time()) if now_epoch is None else int(now_epoch)
    ca_pem = _read_trusted_file(
        config.client_ca_certificate_path,
        expected_uid=trusted_public_owner_uid,
        expected_gid=os.getegid(),
        maximum_bytes=MAX_CA_OR_CRL_BYTES,
        allowed_modes={0o400, 0o440, 0o444, 0o600, 0o640, 0o644},
        subject="private client CA certificate",
    )
    crl_pem = _read_trusted_file(
        config.client_crl_path,
        expected_uid=trusted_public_owner_uid,
        expected_gid=os.getegid(),
        maximum_bytes=MAX_CA_OR_CRL_BYTES,
        allowed_modes={0o400, 0o440, 0o444, 0o600, 0o640, 0o644},
        subject="private client CA CRL",
    )
    snapshot = validate_private_ca_and_crl(
        ca_pem,
        crl_pem,
        now_epoch=now,
        crl_max_age_seconds=config.limits.crl_max_age_seconds,
    )
    server_certificate_pem = _require_tls_file(
        config.server_certificate_path,
        trusted_owner_uid=trusted_public_owner_uid,
        private=False,
    )
    _require_tls_file(
        config.server_private_key_path,
        trusted_owner_uid=trusted_public_owner_uid,
        private=True,
    )
    server_leaf = validate_server_certificate_identity(
        server_certificate_pem,
        public_host=config.public_host,
        now_epoch=now,
    )
    server_leaf_der = server_leaf.public_bytes(serialization.Encoding.DER)
    server_valid_from = _epoch(server_leaf.not_valid_before_utc)
    server_valid_until = _epoch(server_leaf.not_valid_after_utc)
    if (
        hashlib.sha256(server_leaf_der).hexdigest()
        != config.server_certificate_sha256
        or server_valid_from != config.server_certificate_valid_from_epoch
        or server_valid_until != config.server_certificate_valid_until_epoch
        or server_valid_until - server_valid_from
        > MAX_SERVER_CERTIFICATE_VALIDITY_SECONDS
    ):
        raise InfrastructureIngressError(
            "server_certificate_generation_mismatch",
            "The ingress server leaf differs from its exact configured generation.",
            status=503,
        )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False
    context.verify_flags = ssl.VERIFY_X509_STRICT | ssl.VERIFY_CRL_CHECK_CHAIN
    if hasattr(ssl, "OP_NO_COMPRESSION"):
        context.options |= ssl.OP_NO_COMPRESSION
    context.num_tickets = 0
    try:
        context.load_verify_locations(
            cadata=(ca_pem + b"\n" + crl_pem).decode("ascii", errors="strict")
        )
        context.load_cert_chain(
            certfile=str(config.server_certificate_path),
            keyfile=str(config.server_private_key_path),
        )
    except (OSError, UnicodeError, ssl.SSLError) as error:
        raise InfrastructureIngressError(
            "tls_configuration_invalid",
            "Ingress TLS identity or private trust material cannot be loaded.",
            status=503,
        ) from error
    return context, snapshot


def validate_server_certificate_identity(
    certificate_pem: bytes,
    *,
    public_host: str,
    now_epoch: int,
) -> x509.Certificate:
    """Require one current exact-DNS TLS server leaf before listener bind."""

    host_name, separator, _port = public_host.rpartition(":")
    if separator != ":" or not host_name:
        raise InfrastructureIngressError(
            "server_certificate_identity_invalid",
            "The configured public TLS identity is invalid.",
            status=503,
        )
    try:
        certificates = x509.load_pem_x509_certificates(certificate_pem)
    except ValueError as error:
        raise InfrastructureIngressError(
            "server_certificate_invalid",
            "The ingress server certificate chain cannot be parsed.",
            status=503,
        ) from error
    if not certificates:
        raise InfrastructureIngressError(
            "server_certificate_invalid",
            "The ingress server certificate chain is empty.",
            status=503,
        )
    leaf = certificates[0]
    valid_from = _epoch(leaf.not_valid_before_utc)
    valid_until = _epoch(leaf.not_valid_after_utc)
    if not valid_from <= now_epoch < valid_until:
        raise InfrastructureIngressError(
            "server_certificate_not_current",
            "The ingress server certificate is not currently valid.",
            status=503,
        )
    try:
        constraints = leaf.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        eku = leaf.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        )
        key_usage = leaf.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        )
        names = leaf.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound as error:
        raise InfrastructureIngressError(
            "server_certificate_usage_invalid",
            "The ingress server certificate lacks a required extension.",
            status=503,
        ) from error
    general_names = list(names.value)
    if (
        constraints.value.ca
        or set(eku.value) != {ExtendedKeyUsageOID.SERVER_AUTH}
        or not key_usage.value.digital_signature
        or key_usage.value.key_cert_sign
        or key_usage.value.crl_sign
        or len(general_names) != 1
        or not isinstance(general_names[0], x509.DNSName)
        or general_names[0].value != host_name
    ):
        raise InfrastructureIngressError(
            "server_certificate_identity_invalid",
            "The ingress server certificate is not the exact DNS server leaf.",
            status=503,
        )
    return leaf


def validate_private_ca_and_crl(
    ca_pem: bytes,
    crl_pem: bytes,
    *,
    now_epoch: int,
    crl_max_age_seconds: int,
) -> TrustSnapshot:
    """Validate one exact self-signed private CA and its current CRL."""

    certificate_match = _CERTIFICATE_PEM.fullmatch(ca_pem)
    crl_match = _CRL_PEM.fullmatch(crl_pem)
    if certificate_match is None:
        raise InfrastructureIngressError(
            "client_ca_invalid",
            "The client trust file must contain exactly one PEM certificate.",
            status=503,
        )
    if crl_match is None:
        raise InfrastructureIngressError(
            "crl_invalid",
            "The revocation file must contain exactly one PEM X.509 CRL.",
            status=503,
        )
    try:
        ca = x509.load_pem_x509_certificate(certificate_match.group(1))
        crl = x509.load_pem_x509_crl(crl_match.group(1))
    except ValueError as error:
        raise InfrastructureIngressError(
            "private_trust_invalid",
            "The private CA or CRL cannot be parsed.",
            status=503,
        ) from error
    ca_der = ca.public_bytes(serialization.Encoding.DER)
    if ca.issuer != ca.subject:
        raise InfrastructureIngressError(
            "client_ca_invalid",
            "The v1 client CA must be one exact self-signed root.",
            status=503,
        )
    _verify_x509_signature(ca.public_key(), ca)
    ca_not_before = _epoch(ca.not_valid_before_utc)
    ca_not_after = _epoch(ca.not_valid_after_utc)
    if not ca_not_before <= now_epoch < ca_not_after:
        raise InfrastructureIngressError(
            "client_ca_not_current",
            "The private client CA is not currently valid.",
            status=503,
        )
    try:
        constraints = ca.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        key_usage = ca.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        ca_ski = ca.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        ).value.digest
    except x509.ExtensionNotFound as error:
        raise InfrastructureIngressError(
            "client_ca_invalid",
            "The private client CA lacks required critical capabilities.",
            status=503,
        ) from error
    if (
        not constraints.critical
        or not constraints.value.ca
        or not key_usage.critical
        or not key_usage.value.key_cert_sign
        or not key_usage.value.crl_sign
    ):
        raise InfrastructureIngressError(
            "client_ca_invalid",
            "The private client CA basic constraints or key usage is invalid.",
            status=503,
        )
    if crl.issuer != ca.subject:
        raise InfrastructureIngressError(
            "crl_wrong_issuer",
            "The CRL issuer does not equal the exact private client CA.",
            status=503,
        )
    _verify_x509_signature(ca.public_key(), crl)
    try:
        crl_aki = crl.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        ).value.key_identifier
    except x509.ExtensionNotFound as error:
        raise InfrastructureIngressError(
            "crl_invalid",
            "The CRL lacks an authority key identifier.",
            status=503,
        ) from error
    if crl_aki != ca_ski:
        raise InfrastructureIngressError(
            "crl_wrong_issuer",
            "The CRL authority key does not match the private client CA.",
            status=503,
        )
    last_update = _epoch(crl.last_update_utc)
    next_update_value = crl.next_update_utc
    if next_update_value is None:
        raise InfrastructureIngressError(
            "crl_expiry_missing",
            "The private client CRL must have a nextUpdate bound.",
            status=503,
        )
    next_update = _epoch(next_update_value)
    if last_update > now_epoch:
        raise InfrastructureIngressError(
            "crl_not_yet_valid",
            "The private client CRL is not yet valid.",
            status=503,
        )
    if now_epoch >= next_update:
        raise InfrastructureIngressError(
            "crl_expired",
            "The private client CRL is expired.",
            status=503,
        )
    if now_epoch - last_update > int(crl_max_age_seconds):
        raise InfrastructureIngressError(
            "crl_stale",
            "The private client CRL exceeds the configured freshness bound.",
            status=503,
        )
    return TrustSnapshot(
        ca_certificate=ca,
        ca_der=ca_der,
        ca_sha256=hashlib.sha256(ca_der).hexdigest(),
        crl=crl,
        crl_sha256=hashlib.sha256(
            crl.public_bytes(serialization.Encoding.DER)
        ).hexdigest(),
        crl_last_update_epoch=last_update,
        crl_next_update_epoch=next_update,
    )


def validate_peer_certificate(
    leaf_der: bytes,
    verified_chain_der: Sequence[bytes],
    trust: TrustSnapshot,
    *,
    now_epoch: int,
) -> PeerCertificate:
    """Require the exact leaf→single-private-root chain and clientAuth leaf."""

    if not isinstance(leaf_der, bytes) or not leaf_der:
        raise InfrastructureIngressError(
            "client_certificate_missing",
            "A client certificate is required.",
            status=401,
        )
    if (
        len(verified_chain_der) != 2
        or verified_chain_der[0] != leaf_der
        or verified_chain_der[1] != trust.ca_der
    ):
        raise InfrastructureIngressError(
            "client_chain_mismatch",
            "The client chain is not the exact enrolled private CA chain.",
            status=401,
        )
    try:
        certificate = x509.load_der_x509_certificate(leaf_der)
    except ValueError as error:
        raise InfrastructureIngressError(
            "client_certificate_invalid",
            "The client certificate cannot be parsed.",
            status=401,
        ) from error
    if certificate.issuer != trust.ca_certificate.subject:
        raise InfrastructureIngressError(
            "client_chain_mismatch",
            "The client leaf issuer does not match the private CA.",
            status=401,
        )
    _verify_x509_signature(trust.ca_certificate.public_key(), certificate)
    valid_from = _epoch(certificate.not_valid_before_utc)
    valid_until = _epoch(certificate.not_valid_after_utc)
    if not valid_from <= now_epoch < valid_until:
        raise InfrastructureIngressError(
            (
                "client_certificate_not_yet_valid"
                if now_epoch < valid_from
                else "client_certificate_expired"
            ),
            "The client certificate is not currently valid.",
            status=401,
        )
    if valid_until - valid_from > INFRASTRUCTURE_CERTIFICATE_MAX_VALIDITY_SECONDS:
        raise InfrastructureIngressError(
            "client_certificate_lifetime_invalid",
            "The client certificate lifetime exceeds 30 days.",
            status=401,
        )
    try:
        constraints = certificate.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        eku = certificate.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        )
        key_usage = certificate.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        )
    except x509.ExtensionNotFound as error:
        raise InfrastructureIngressError(
            "client_certificate_usage_invalid",
            "The client certificate lacks required usage extensions.",
            status=401,
        ) from error
    if constraints.value.ca:
        raise InfrastructureIngressError(
            "client_certificate_usage_invalid",
            "A client leaf cannot be a certificate authority.",
            status=401,
        )
    if set(eku.value) != {ExtendedKeyUsageOID.CLIENT_AUTH}:
        raise InfrastructureIngressError(
            "client_certificate_eku_invalid",
            "The client certificate EKU must be exactly Client Authentication.",
            status=401,
        )
    if (
        not key_usage.value.digital_signature
        or key_usage.value.key_cert_sign
        or key_usage.value.crl_sign
    ):
        raise InfrastructureIngressError(
            "client_certificate_usage_invalid",
            "The client certificate key usage is not a signing leaf.",
            status=401,
        )
    for revoked in trust.crl:
        if revoked.serial_number == certificate.serial_number:
            raise InfrastructureIngressError(
                "client_certificate_revoked",
                "The client certificate is revoked by the current private CA CRL.",
                status=401,
            )
    return PeerCertificate(
        certificate=certificate,
        der=leaf_der,
        fingerprint_sha256=hashlib.sha256(leaf_der).hexdigest(),
        valid_from_epoch=valid_from,
        valid_until_epoch=valid_until,
    )


def parse_compact_jws(compact: bytes) -> ParsedJWS:
    """Parse a closed, canonical, detached-free compact JWS envelope."""

    if (
        not isinstance(compact, bytes)
        or not compact
        or len(compact) > MAX_SIGNED_ENVELOPE_BYTES
    ):
        raise InfrastructureIngressError(
            "signed_envelope_oversized",
            "The signed envelope is empty or exceeds the byte bound.",
            status=413,
        )
    try:
        text = compact.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise InfrastructureIngressError(
            "jws_invalid",
            "The signed envelope is not ASCII compact JWS.",
        ) from error
    parts = text.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise InfrastructureIngressError(
            "jws_invalid",
            "The signed envelope must be a three-segment compact JWS.",
        )
    header_bytes = _base64url_decode(
        parts[0], "protected header", maximum=MAX_PROTECTED_HEADER_BYTES
    )
    payload_bytes = _base64url_decode(
        parts[1], "payload", maximum=MAX_SIGNED_ENVELOPE_BYTES
    )
    signature = _base64url_decode(parts[2], "signature", maximum=1024)
    header = _strict_canonical_json(
        header_bytes,
        subject="JWS protected header",
        maximum=MAX_PROTECTED_HEADER_BYTES,
    )
    if set(header) != {
        "alg",
        "typ",
        "kid",
        "x5t#S256",
        "cert_generation",
        "spki_sha256",
    }:
        raise InfrastructureIngressError(
            "jws_header_invalid",
            "JWS protected header fields are not the closed v1 contract.",
        )
    if header.get("alg") != INFRASTRUCTURE_JWS_ALGORITHM:
        raise InfrastructureIngressError(
            "jws_algorithm_invalid", "JWS alg must be exactly PS256."
        )
    if header.get("typ") != INFRASTRUCTURE_JWS_TYPE:
        raise InfrastructureIngressError(
            "jws_type_invalid", "JWS typ is not the infrastructure v1 type."
        )
    key_id = _identifier(header.get("kid"), "JWS kid", public_status=400)
    generation = _integer(
        header.get("cert_generation"),
        "JWS cert_generation",
        1,
        (1 << 31) - 1,
        public_status=400,
    )
    spki_sha256 = header.get("spki_sha256")
    if not isinstance(spki_sha256, str) or not _HEX_SHA256.fullmatch(
        spki_sha256
    ):
        raise InfrastructureIngressError(
            "jws_header_invalid", "JWS spki_sha256 is invalid."
        )
    thumbprint = header.get("x5t#S256")
    if (
        not isinstance(thumbprint, str)
        or len(_base64url_decode(thumbprint, "x5t#S256", maximum=32)) != 32
    ):
        raise InfrastructureIngressError(
            "jws_header_invalid", "JWS x5t#S256 is invalid."
        )
    try:
        observation, payload_sha256 = parse_canonical_observation_payload(
            payload_bytes
        )
    except InfrastructureValidationError as error:
        raise InfrastructureIngressError(
            error.code, error.message, status=400
        ) from None
    return ParsedJWS(
        compact=compact,
        observation=observation,
        payload_sha256=payload_sha256,
        certificate_generation=generation,
        key_id=key_id,
        spki_sha256=spki_sha256,
        signing_input=f"{parts[0]}.{parts[1]}".encode("ascii"),
        signature=signature,
    )


def verify_jws_and_context(
    parsed: ParsedJWS,
    *,
    peer: PeerCertificate,
    broker: InfrastructureBroker,
    now_epoch: int,
) -> Mapping[str, Any]:
    """Resolve one non-enumerating context and verify all JWS bindings."""

    header = json.loads(
        _base64url_decode(
            parsed.signing_input.split(b".", 1)[0].decode("ascii"),
            "protected header",
            maximum=MAX_PROTECTED_HEADER_BYTES,
        )
    )
    expected_thumbprint = _base64url_encode(
        bytes.fromhex(peer.fingerprint_sha256)
    )
    if header.get("x5t#S256") != expected_thumbprint:
        raise InfrastructureIngressError(
            "certificate_fingerprint_mismatch",
            "JWS certificate thumbprint does not match the mTLS leaf.",
            status=401,
        )
    context = broker.verification_context(
        fingerprint_sha256=peer.fingerprint_sha256,
        generation=parsed.certificate_generation,
    )
    required_context = {
        "schema",
        "certificate_fingerprint_sha256",
        "certificate_generation",
        "jws_key_id",
        "jws_algorithm",
        "jws_spki_der_base64",
        "jws_spki_sha256",
        "agent_id",
        "host_id",
        "cell_id",
        "assigned_scope_sha256",
        "host_scope_sha256",
        "valid_from_epoch",
        "valid_until_epoch",
        "revoked",
        "revoked_at",
        "revocation_reason",
        "agent_enabled",
        "host_enabled",
        "cell_enabled",
        "scope_current",
        "valid_at_lookup",
        "eligible_at_lookup",
        "lookup_epoch",
    }
    if not isinstance(context, Mapping) or set(context) != required_context:
        raise InfrastructureIngressError(
            "verification_context_invalid",
            "Broker verification context is not the closed v1 contract.",
            status=503,
        )
    if (
        context.get("schema")
        != "spectre.infrastructure.verification-context.v1"
        or context.get("certificate_fingerprint_sha256")
        != peer.fingerprint_sha256
        or context.get("certificate_generation")
        != parsed.certificate_generation
        or context.get("jws_key_id") != parsed.key_id
        or context.get("jws_algorithm") != INFRASTRUCTURE_JWS_ALGORITHM
        or context.get("jws_spki_sha256") != parsed.spki_sha256
    ):
        raise InfrastructureIngressError(
            "verification_context_mismatch",
            "JWS identity does not match the enrolled broker context.",
            status=403,
        )
    valid_from = context.get("valid_from_epoch")
    valid_until = context.get("valid_until_epoch")
    if type(valid_from) is not int or type(valid_until) is not int:
        raise InfrastructureIngressError(
            "verification_context_invalid",
            "Broker certificate validity context is invalid.",
            status=503,
        )
    if (
        valid_from != peer.valid_from_epoch
        or valid_until != peer.valid_until_epoch
        or valid_until - valid_from
        > INFRASTRUCTURE_CERTIFICATE_MAX_VALIDITY_SECONDS
    ):
        raise InfrastructureIngressError(
            "certificate_validity_binding_mismatch",
            "mTLS leaf validity does not equal its enrolled generation.",
            status=403,
        )
    if not valid_from <= now_epoch < valid_until:
        raise InfrastructureIngressError(
            "certificate_not_current",
            "The enrolled certificate generation is not currently valid.",
            status=403,
        )
    if (
        context.get("revoked") is not False
        or context.get("agent_enabled") is not True
        or context.get("host_enabled") is not True
        or context.get("cell_enabled") is not True
        or context.get("scope_current") is not True
        or context.get("valid_at_lookup") is not True
        or context.get("eligible_at_lookup") is not True
    ):
        raise InfrastructureIngressError(
            "enrollment_not_eligible",
            "The exact infrastructure enrollment is disabled, stale, revoked, or expired.",
            status=403,
        )
    observation = parsed.observation
    if (
        observation.get("agent_id") != context.get("agent_id")
        or observation.get("host_id") != context.get("host_id")
        or observation.get("cell_id") != context.get("cell_id")
        or not isinstance(observation.get("evidence"), dict)
        or observation["evidence"].get("scope_sha256")
        != context.get("assigned_scope_sha256")
        or context.get("assigned_scope_sha256")
        != context.get("host_scope_sha256")
    ):
        raise InfrastructureIngressError(
            "scope_mismatch",
            "Signed observation identity or scope does not match enrollment.",
            status=403,
        )
    try:
        spki_der = base64.b64decode(
            str(context["jws_spki_der_base64"]), validate=True
        )
    except (binascii.Error, ValueError) as error:
        raise InfrastructureIngressError(
            "verification_context_invalid",
            "Broker JWS public material is invalid.",
            status=503,
        ) from error
    if (
        base64.b64encode(spki_der).decode("ascii")
        != context["jws_spki_der_base64"]
        or hashlib.sha256(spki_der).hexdigest() != parsed.spki_sha256
    ):
        raise InfrastructureIngressError(
            "verification_context_invalid",
            "Broker JWS public material digest is invalid.",
            status=503,
        )
    try:
        public_key = serialization.load_der_public_key(spki_der)
    except ValueError as error:
        raise InfrastructureIngressError(
            "verification_context_invalid",
            "Broker JWS public material cannot be parsed.",
            status=503,
        ) from error
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise InfrastructureIngressError(
            "verification_context_invalid",
            "PS256 requires an RSA public key.",
            status=503,
        )
    numbers = public_key.public_numbers()
    if (
        not 3072 <= numbers.n.bit_length() <= 8192
        or numbers.n % 2 == 0
        or numbers.e != 65_537
        or len(parsed.signature) != (numbers.n.bit_length() + 7) // 8
    ):
        raise InfrastructureIngressError(
            "verification_context_invalid",
            "Enrolled PS256 RSA parameters are outside the reviewed contract.",
            status=503,
        )
    try:
        public_key.verify(
            parsed.signature,
            parsed.signing_input,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
    except InvalidSignature as error:
        raise InfrastructureIngressError(
            "jws_signature_invalid",
            "The PS256 signature is invalid.",
            status=401,
        ) from error
    return context


class BrokerGateway:
    """Exact fixed-scope calls through the authenticated Python BrokerClient."""

    def __init__(self, config: IngressConfig) -> None:
        self.config = config
        self.client = BrokerClient(
            config.broker_socket_path,
            expected_broker_uid=config.expected_broker_uid,
            expected_socket_gid=config.expected_socket_gid,
            expected_socket_mode=config.expected_socket_mode,
            timeout_seconds=15.0,
        )

    def verification_context(
        self, *, fingerprint_sha256: str, generation: int
    ) -> Mapping[str, Any]:
        return self._call(
            operation=BrokerOperation.INFRASTRUCTURE_VERIFICATION_CONTEXT,
            resource_id=INFRASTRUCTURE_VERIFICATION_CONTEXT_RESOURCE_ID,
            operation_id=str(uuid.uuid4()),
            arguments={
                "certificate_fingerprint_sha256": fingerprint_sha256,
                "certificate_generation": generation,
            },
        )

    def ingest(
        self, *, arguments: Mapping[str, Any], operation_id: str
    ) -> Mapping[str, Any]:
        return self._call(
            operation=BrokerOperation.INFRASTRUCTURE_INGEST,
            resource_id=INFRASTRUCTURE_INGEST_RESOURCE_ID,
            operation_id=operation_id,
            arguments=arguments,
        )

    def _call(
        self,
        *,
        operation: BrokerOperation,
        resource_id: str,
        operation_id: str,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        request = BrokerRequest.create(
            account_id=self.config.account_id,
            project_id=INFRASTRUCTURE_BROKER_PROJECT_ID,
            repository_generation=0,
            resource_id=resource_id,
            operation=operation,
            arguments=arguments,
            operation_id=operation_id,
            authority_generation=self.config.authority_generation,
        )
        try:
            reply = self.client.call(request)
        except (BrokerError, OSError, TimeoutError) as error:
            code = (
                error.code if isinstance(error, BrokerError) else "broker_unavailable"
            )
            status = (
                409
                if code
                in {
                    "sequence_out_of_order",
                    "observation_replay",
                    "agent_boot_replay",
                    "operation_id_conflict",
                }
                else 403
                if code
                in {
                    "certificate_not_enrolled",
                    "certificate_revoked",
                    "certificate_expired",
                    "enrollment_disabled",
                    "enrollment_scope_stale",
                    "scope_mismatch",
                    "vm_scope_mismatch",
                    "vm_role_mismatch",
                }
                else 503
            )
            raise InfrastructureIngressError(
                code,
                self._public_broker_rejection_message(status),
                status=status,
            ) from None
        if not isinstance(reply, dict) or set(reply) != {
            "version",
            "ok",
            "operation_id",
            "result",
        }:
            # Broker failures carry ``error`` instead of ``result``.
            if (
                isinstance(reply, dict)
                and reply.get("ok") is False
                and isinstance(reply.get("error"), dict)
            ):
                error = reply["error"]
                code = str(error.get("code") or "broker_rejected")
                status = 409 if "replay" in code or "sequence" in code else 403
                raise InfrastructureIngressError(
                    code,
                    self._public_broker_rejection_message(status),
                    status=status,
                )
            raise InfrastructureIngressError(
                "broker_reply_invalid",
                "The Coordinator returned an invalid reply.",
                status=503,
            )
        if reply["ok"] is not True or reply["operation_id"] != operation_id:
            raise InfrastructureIngressError(
                "broker_reply_invalid",
                "The Coordinator reply identity is invalid.",
                status=503,
            )
        result = reply["result"]
        if not isinstance(result, dict):
            raise InfrastructureIngressError(
                "broker_reply_invalid",
                "The Coordinator result is invalid.",
                status=503,
            )
        return result

    @staticmethod
    def _public_broker_rejection_message(status: int) -> str:
        """Return a fixed network-safe description for trusted broker failures."""

        if status == 409:
            return (
                "The Coordinator rejected the report because its identity or "
                "ordering conflicts with current state."
            )
        if status == 403:
            return (
                "The Coordinator rejected the report for enrollment, identity, "
                "or scope."
            )
        return "The Coordinator authority is temporarily unavailable."


class FixedWindowRateLimiter:
    """Bounded in-memory admission limits; broker replay remains authoritative."""

    def __init__(
        self,
        *,
        certificate_limit: int,
        ip_limit: int,
        key_cap: int = RATE_LIMIT_KEY_CAP,
    ) -> None:
        self.certificate_limit = int(certificate_limit)
        self.ip_limit = int(ip_limit)
        self.key_cap = int(key_cap)
        if not 1 <= self.key_cap <= RATE_LIMIT_KEY_CAP:
            raise ValueError("rate-limiter key cap is outside the reviewed bound")
        self._certificate_events: dict[str, deque[float]] = {}
        self._ip_events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def admit(self, *, certificate: str, source_ip: str, now: float) -> None:
        with self._lock:
            boundary = now - 60.0
            certificate_queue = self._prepare_queue(
                self._certificate_events,
                certificate,
                self.certificate_limit,
                boundary,
            )
            ip_queue = self._prepare_queue(
                self._ip_events, source_ip, self.ip_limit, boundary
            )
            if certificate_queue is None or ip_queue is None:
                raise InfrastructureIngressError(
                    "rate_limited",
                    "The infrastructure ingress rate limit was exceeded.",
                    status=429,
                )
            if certificate not in self._certificate_events:
                self._certificate_events[certificate] = certificate_queue
            if source_ip not in self._ip_events:
                self._ip_events[source_ip] = ip_queue
            certificate_queue.append(now)
            ip_queue.append(now)

    def _prepare_queue(
        self,
        events: dict[str, deque[float]],
        key: str,
        limit: int,
        boundary: float,
    ) -> deque[float] | None:
        queue = events.get(key)
        if queue is None:
            if len(events) >= self.key_cap:
                self._purge_expired_keys(events, boundary=boundary)
            if len(events) >= self.key_cap:
                return None
            queue = deque()
        else:
            self._trim_queue(queue, boundary=boundary)
        if len(queue) >= limit:
            return None
        return queue

    @staticmethod
    def _trim_queue(queue: deque[float], *, boundary: float) -> None:
        while queue and queue[0] <= boundary:
            queue.popleft()

    @classmethod
    def _purge_expired_keys(
        cls,
        events: dict[str, deque[float]],
        *,
        boundary: float,
    ) -> None:
        for candidate, queue in tuple(events.items()):
            cls._trim_queue(queue, boundary=boundary)
            if not queue:
                del events[candidate]


class IngressApplication:
    """One verified request → one staged artifact → one broker operation."""

    def __init__(
        self,
        config: IngressConfig,
        *,
        broker: InfrastructureBroker | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self.broker = broker or BrokerGateway(config)
        self.clock = clock
        self.rate_limiter = FixedWindowRateLimiter(
            certificate_limit=(
                config.limits.rate_per_certificate_per_minute
            ),
            ip_limit=config.limits.rate_per_ip_per_minute,
        )

    def admit_transport(
        self,
        *,
        leaf_der: bytes,
        verified_chain_der: Sequence[bytes],
        trust: TrustSnapshot,
        source_ip: str,
    ) -> AdmittedTransport:
        """Validate and charge one TLS peer before reading its HTTP body."""

        now = int(self.clock())
        try:
            canonical_source = str(ipaddress.ip_address(source_ip))
        except ValueError as error:
            raise InfrastructureIngressError(
                "source_identity_invalid",
                "The transport source address is invalid.",
                status=400,
            ) from error
        peer = validate_peer_certificate(
            leaf_der, verified_chain_der, trust, now_epoch=now
        )
        self.rate_limiter.admit(
            certificate=peer.fingerprint_sha256,
            source_ip=canonical_source,
            now=float(now),
        )
        return AdmittedTransport(
            peer=peer,
            source_ip=canonical_source,
            admitted_epoch=now,
        )

    def process(
        self,
        compact_jws: bytes,
        *,
        leaf_der: bytes,
        verified_chain_der: Sequence[bytes],
        trust: TrustSnapshot,
        source_ip: str,
    ) -> dict[str, Any]:
        admission = self.admit_transport(
            leaf_der=leaf_der,
            verified_chain_der=verified_chain_der,
            trust=trust,
            source_ip=source_ip,
        )
        return self.process_admitted(compact_jws, admission=admission)

    def process_admitted(
        self,
        compact_jws: bytes,
        *,
        admission: AdmittedTransport,
    ) -> dict[str, Any]:
        """Process one body whose exact TLS transport was already admitted."""

        if type(admission) is not AdmittedTransport:
            raise InfrastructureIngressError(
                "transport_admission_invalid",
                "The transport admission context is invalid.",
                status=503,
            )
        now = admission.admitted_epoch
        peer = admission.peer
        parsed = parse_compact_jws(compact_jws)
        context = verify_jws_and_context(
            parsed,
            peer=peer,
            broker=self.broker,
            now_epoch=now,
        )
        artifact = stage_signed_envelope(
            self.config.artifact_root,
            compact_jws,
            expected_uid=os.geteuid(),
        )
        operation_id = str(
            uuid.uuid5(JWS_OPERATION_NAMESPACE, artifact.sha256)
        )
        result = self.broker.ingest(
            operation_id=operation_id,
            arguments={
                "transport": {
                    "mtls_verified": True,
                    "jws_verified": True,
                    "certificate_fingerprint_sha256": (
                        peer.fingerprint_sha256
                    ),
                    "certificate_generation": parsed.certificate_generation,
                    "jws_key_id": parsed.key_id,
                    "jws_algorithm": INFRASTRUCTURE_JWS_ALGORITHM,
                    "jws_spki_sha256": parsed.spki_sha256,
                    "canonical_payload_sha256": parsed.payload_sha256,
                },
                "observation": parsed.observation,
                "artifact": artifact.to_dict(),
            },
        )
        if (
            result.get("status") != "accepted"
            or result.get("evidence_available") is not True
            or result.get("signed_envelope_sha256") != artifact.sha256
            or result.get("signed_envelope_locator")
            != "sha256:" + artifact.sha256
        ):
            raise InfrastructureIngressError(
                "broker_acceptance_invalid",
                "The Coordinator did not return an evidence-bound acceptance.",
                status=503,
            )
        return {
            "schema": INGRESS_RESPONSE_SCHEMA,
            "status": "accepted",
            "operation_id": operation_id,
            "observation_id": result.get("observation_id"),
            "accepted_at": result.get("accepted_at"),
            "artifact_sha256": artifact.sha256,
            "certificate_generation": context["certificate_generation"],
        }


def read_strict_http_request(
    connection: ssl.SSLSocket,
    config: IngressConfig,
) -> bytes:
    """Read one unambiguous HTTP/1.1 POST under one absolute deadline."""

    deadline = time.monotonic() + config.limits.request_timeout_seconds
    buffer = bytearray()
    marker = b"\r\n\r\n"
    while marker not in buffer:
        if len(buffer) >= config.limits.max_header_bytes:
            raise InfrastructureIngressError(
                "headers_oversized",
                "HTTP headers exceed the ingress bound.",
                status=431,
            )
        chunk = _recv_before_deadline(
            connection,
            min(4096, config.limits.max_header_bytes - len(buffer)),
            deadline=deadline,
        )
        if not chunk:
            raise InfrastructureIngressError(
                "request_truncated", "HTTP request headers are truncated."
            )
        buffer.extend(chunk)
    header_end = buffer.index(marker) + len(marker)
    if header_end > config.limits.max_header_bytes:
        raise InfrastructureIngressError(
            "headers_oversized",
            "HTTP headers exceed the ingress bound.",
            status=431,
        )
    header_block = bytes(buffer[: header_end - len(marker)])
    remainder = bytes(buffer[header_end:])
    try:
        header_text = header_block.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise InfrastructureIngressError(
            "http_syntax_invalid", "HTTP headers must be strict ASCII."
        ) from error
    lines = header_text.split("\r\n")
    if (
        not lines
        or "\n" in header_text.replace("\r\n", "")
        or len(lines) > MAX_HTTP_HEADER_COUNT + 1
        or any(len(line.encode("ascii")) > MAX_HTTP_LINE_BYTES for line in lines)
    ):
        raise InfrastructureIngressError(
            "http_syntax_invalid", "HTTP header framing is invalid."
        )
    request_parts = lines[0].split(" ")
    if len(request_parts) != 3:
        raise InfrastructureIngressError(
            "http_syntax_invalid", "HTTP request line is invalid."
        )
    method, target, version = request_parts
    if method != "POST":
        raise InfrastructureIngressError(
            "method_not_allowed",
            "Only POST is supported by this ingress.",
            status=405,
        )
    if target != INGRESS_PATH or version != "HTTP/1.1":
        raise InfrastructureIngressError(
            "request_target_invalid",
            "The HTTP target or protocol version is unsupported.",
            status=404,
        )
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if (
            not line
            or line[0] in " \t"
            or ":" not in line
        ):
            raise InfrastructureIngressError(
                "http_syntax_invalid", "HTTP header syntax is invalid."
            )
        raw_name, raw_value = line.split(":", 1)
        if not _HEADER_NAME.fullmatch(raw_name):
            raise InfrastructureIngressError(
                "http_syntax_invalid", "HTTP header name is invalid."
            )
        name = raw_name.lower()
        value = raw_value.strip(" \t")
        if name in headers or len(value) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            raise InfrastructureIngressError(
                "http_header_ambiguous",
                "Duplicate or unsafe HTTP headers are rejected.",
            )
        headers[name] = value
    forbidden = {
        "transfer-encoding",
        "content-encoding",
        "te",
        "trailer",
        "expect",
        "upgrade",
    }
    if set(headers) & forbidden:
        raise InfrastructureIngressError(
            "transfer_ambiguity",
            "Compression, chunking, trailers, upgrades, and expectations are rejected.",
        )
    allowed = {"host", "content-type", "content-length", "connection", "user-agent"}
    if set(headers) - allowed:
        raise InfrastructureIngressError(
            "http_header_unsupported",
            "The request contains an unsupported HTTP header.",
        )
    required = {"host", "content-type", "content-length", "connection"}
    if not required <= set(headers):
        raise InfrastructureIngressError(
            "http_header_missing",
            "The request lacks a required HTTP header.",
        )
    if headers["host"] != config.public_host:
        raise InfrastructureIngressError(
            "host_header_invalid", "The Host header is not the configured ingress."
        )
    if headers["content-type"] != "application/jose":
        raise InfrastructureIngressError(
            "content_type_invalid",
            "Content-Type must be exactly application/jose.",
            status=415,
        )
    if headers["connection"].lower() != "close":
        raise InfrastructureIngressError(
            "connection_reuse_rejected",
            "Every report requires a new TLS connection with Connection: close.",
        )
    raw_length = headers["content-length"]
    if (
        not re.fullmatch(r"(?:0|[1-9][0-9]*)", raw_length)
        or len(raw_length) > 7
    ):
        raise InfrastructureIngressError(
            "content_length_invalid", "Content-Length is not canonical."
        )
    content_length = int(raw_length)
    if content_length < 1 or content_length > config.limits.max_body_bytes:
        raise InfrastructureIngressError(
            "signed_envelope_oversized",
            "The signed envelope is empty or exceeds the byte bound.",
            status=413,
        )
    if len(remainder) > content_length:
        raise InfrastructureIngressError(
            "request_pipelining_rejected",
            "A TLS connection may carry exactly one request.",
        )
    body = bytearray(remainder)
    while len(body) < content_length:
        chunk = _recv_before_deadline(
            connection,
            min(64 * 1024, content_length - len(body)),
            deadline=deadline,
        )
        if not chunk:
            raise InfrastructureIngressError(
                "request_truncated", "The signed envelope body is truncated."
            )
        body.extend(chunk)
    if connection.pending() > 0:
        raise InfrastructureIngressError(
            "request_pipelining_rejected",
            "A TLS connection may carry exactly one request.",
        )
    return bytes(body)


def write_http_response(
    connection: ssl.SSLSocket,
    *,
    status: int,
    document: Mapping[str, Any],
) -> None:
    payload = canonical_json(document).encode("utf-8")
    reason = {
        202: "Accepted",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        408: "Request Timeout",
        409: "Conflict",
        413: "Content Too Large",
        415: "Unsupported Media Type",
        429: "Too Many Requests",
        431: "Request Header Fields Too Large",
        503: "Service Unavailable",
    }.get(int(status), "Error")
    headers = (
        f"HTTP/1.1 {int(status)} {reason}\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        f"Content-Length: {len(payload)}\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "\r\n"
    ).encode("ascii")
    connection.sendall(headers + payload)


class InfrastructureIngressServer:
    """Bounded threaded TLS listener; every worker handles one connection."""

    def __init__(
        self,
        config: IngressConfig,
        *,
        application: IngressApplication | None = None,
        trusted_public_owner_uid: int = 0,
    ) -> None:
        self.config = config
        self.application = application or IngressApplication(config)
        self.trusted_public_owner_uid = int(trusted_public_owner_uid)
        self._stop = threading.Event()
        self._semaphore = threading.BoundedSemaphore(
            config.limits.max_concurrency
        )
        self._listener: socket.socket | None = None
        self._workers: set[threading.Thread] = set()
        self._worker_lock = threading.Lock()

    def validate_startup(self) -> dict[str, Any]:
        version = require_cryptography_runtime()
        _context, trust = build_tls_context(
            self.config,
            trusted_public_owner_uid=self.trusted_public_owner_uid,
        )
        _require_private_artifact_root(
            self.config.artifact_root, expected_uid=os.geteuid()
        )
        return {
            "ok": True,
            "schema": INGRESS_CONFIG_SCHEMA,
            "cryptography_version": version,
            "client_ca_sha256": trust.ca_sha256,
            "crl_sha256": trust.crl_sha256,
            "server_certificate_generation": (
                self.config.server_certificate_generation
            ),
            "server_certificate_sha256": (
                self.config.server_certificate_sha256
            ),
            "listen": f"{self.config.listen_host}:{self.config.listen_port}",
        }

    def serve_forever(self) -> None:
        self.validate_startup()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.config.listen_host, self.config.listen_port))
        listener.listen(min(128, self.config.limits.max_concurrency * 2))
        listener.settimeout(1.0)
        self._listener = listener
        try:
            while not self._stop.is_set():
                try:
                    raw_connection, address = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._stop.is_set():
                        break
                    raise
                if not self._semaphore.acquire(blocking=False):
                    raw_connection.close()
                    continue
                worker = threading.Thread(
                    target=self._handle_connection,
                    args=(raw_connection, address),
                    daemon=True,
                    name="infrastructure-ingress-request",
                )
                with self._worker_lock:
                    self._workers.add(worker)
                worker.start()
        finally:
            listener.close()
            self._listener = None
            deadline = time.monotonic() + 30.0
            while time.monotonic() < deadline:
                with self._worker_lock:
                    workers = [worker for worker in self._workers if worker.is_alive()]
                if not workers:
                    break
                for worker in workers:
                    worker.join(timeout=0.1)

    def stop(self) -> None:
        self._stop.set()
        listener = self._listener
        if listener is not None:
            try:
                listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            listener.close()

    def _handle_connection(
        self, raw_connection: socket.socket, address: tuple[Any, ...]
    ) -> None:
        tls_connection: ssl.SSLSocket | None = None
        try:
            raw_connection.settimeout(
                self.config.limits.handshake_timeout_seconds
            )
            context, trust = build_tls_context(
                self.config,
                trusted_public_owner_uid=self.trusted_public_owner_uid,
            )
            tls_connection = context.wrap_socket(
                raw_connection,
                server_side=True,
                do_handshake_on_connect=False,
            )
            tls_connection.do_handshake()
            leaf_der = tls_connection.getpeercert(binary_form=True)
            verified_chain = _verified_chain_der(tls_connection)
            admission = self.application.admit_transport(
                leaf_der=leaf_der,
                verified_chain_der=verified_chain,
                trust=trust,
                source_ip=str(address[0]),
            )
            body = read_strict_http_request(tls_connection, self.config)
            response = self.application.process_admitted(
                body,
                admission=admission,
            )
            write_http_response(tls_connection, status=202, document=response)
            _safe_log(
                "accepted",
                operation_id=response.get("operation_id"),
                artifact_sha256=response.get("artifact_sha256"),
            )
        except InfrastructureIngressError as error:
            if tls_connection is not None:
                try:
                    write_http_response(
                        tls_connection,
                        status=error.status,
                        document={
                            "schema": INGRESS_RESPONSE_SCHEMA,
                            "status": "rejected",
                            "code": error.code,
                            "message": error.message,
                        },
                    )
                except (OSError, ssl.SSLError):
                    pass
            _safe_log("rejected", code=error.code)
        except (OSError, ssl.SSLError, TimeoutError):
            _safe_log("transport_rejected", code="tls_or_transport_failure")
        except BaseException:
            _LOGGER.exception(
                canonical_json(
                    {
                        "event": "internal_failure",
                        "code": "ingress_internal_failure",
                    }
                )
            )
        finally:
            try:
                if tls_connection is not None:
                    tls_connection.close()
                else:
                    raw_connection.close()
            finally:
                with self._worker_lock:
                    self._workers.discard(threading.current_thread())
                self._semaphore.release()


def run_ingress(
    config_path: Path,
    *,
    check_only: bool = False,
    trusted_owner_uid: int = 0,
) -> dict[str, Any] | None:
    config = load_ingress_config(
        config_path, trusted_owner_uid=trusted_owner_uid
    )
    server = InfrastructureIngressServer(
        config, trusted_public_owner_uid=trusted_owner_uid
    )
    startup = server.validate_startup()
    if check_only:
        return startup

    previous: dict[int, Any] = {}

    def request_stop(_signum: int, _frame: Any) -> None:
        server.stop()

    for signum in (signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.signal(signum, request_stop)
    try:
        server.serve_forever()
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    return None


def _verified_chain_der(connection: ssl.SSLSocket) -> list[bytes]:
    try:
        chain = connection.get_verified_chain()
    except (AttributeError, ssl.SSLError) as error:
        raise InfrastructureIngressError(
            "client_chain_unavailable",
            "The verified client certificate chain is unavailable.",
            status=401,
        ) from error
    result: list[bytes] = []
    for item in chain:
        if isinstance(item, bytes):
            result.append(item)
            continue
        try:
            encoded = item.public_bytes()
        except (AttributeError, ValueError) as error:
            raise InfrastructureIngressError(
                "client_chain_unavailable",
                "The verified client certificate chain is unreadable.",
                status=401,
            ) from error
        if isinstance(encoded, str):
            try:
                result.append(
                    ssl.PEM_cert_to_DER_cert(encoded)
                )
            except ValueError as error:
                raise InfrastructureIngressError(
                    "client_chain_unavailable",
                    "The verified client certificate chain is malformed.",
                    status=401,
                ) from error
        elif isinstance(encoded, bytes):
            result.append(encoded)
        else:
            raise InfrastructureIngressError(
                "client_chain_unavailable",
                "The verified client certificate chain has an unsupported representation.",
                status=401,
            )
    return result


def _verify_x509_signature(public_key: Any, signed: Any) -> None:
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            parameters = signed.signature_algorithm_parameters
            if not isinstance(parameters, (padding.PKCS1v15, padding.PSS)):
                raise InfrastructureIngressError(
                    "x509_signature_algorithm_invalid",
                    "The X.509 RSA signature parameters are unsupported.",
                    status=503,
                )
            public_key.verify(
                signed.signature,
                signed.tbs_certlist_bytes
                if isinstance(signed, x509.CertificateRevocationList)
                else signed.tbs_certificate_bytes,
                parameters,
                signed.signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signed.signature,
                signed.tbs_certlist_bytes
                if isinstance(signed, x509.CertificateRevocationList)
                else signed.tbs_certificate_bytes,
                ec.ECDSA(signed.signature_hash_algorithm),
            )
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(
                signed.signature,
                signed.tbs_certlist_bytes
                if isinstance(signed, x509.CertificateRevocationList)
                else signed.tbs_certificate_bytes,
            )
        else:
            raise InfrastructureIngressError(
                "x509_key_algorithm_invalid",
                "The private CA public-key algorithm is unsupported.",
                status=503,
            )
    except InvalidSignature as error:
        raise InfrastructureIngressError(
            "x509_signature_invalid",
            "The X.509 signature cannot be authenticated.",
            status=503,
        ) from error


def _strict_canonical_json(
    payload: bytes, *, subject: str, maximum: int
) -> dict[str, Any]:
    if not payload or len(payload) > maximum:
        raise InfrastructureIngressError(
            "jws_header_invalid", f"{subject} exceeds its byte bound."
        )

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise InfrastructureIngressError(
                    "jws_header_invalid", f"{subject} duplicates a field."
                )
            result[key] = value
        return result

    def reject_number(_value: str) -> Any:
        raise InfrastructureIngressError(
            "jws_header_invalid", f"{subject} contains an unsupported number."
        )

    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=object_pairs,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InfrastructureIngressError(
            "jws_header_invalid", f"{subject} is not strict JSON."
        ) from error
    if not isinstance(value, dict):
        raise InfrastructureIngressError(
            "jws_header_invalid", f"{subject} must be an object."
        )
    _require_nfc(value, subject=subject)
    if canonical_json(value).encode("utf-8") != payload:
        raise InfrastructureIngressError(
            "jws_header_invalid", f"{subject} is not canonical JSON."
        )
    return value


def _require_nfc(value: Any, *, subject: str) -> None:
    import unicodedata

    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise InfrastructureIngressError(
                "jws_header_invalid", f"{subject} contains non-NFC text."
            )
    elif isinstance(value, list):
        for item in value:
            _require_nfc(item, subject=subject)
    elif isinstance(value, dict):
        for key, item in value.items():
            _require_nfc(key, subject=subject)
            _require_nfc(item, subject=subject)


def _base64url_decode(value: str, field: str, *, maximum: int) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or "=" in value
        or any(
            character
            not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for character in value
        )
    ):
        raise InfrastructureIngressError(
            "jws_encoding_invalid", f"JWS {field} is not canonical base64url."
        )
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as error:
        raise InfrastructureIngressError(
            "jws_encoding_invalid", f"JWS {field} cannot be decoded."
        ) from error
    if len(decoded) > maximum or _base64url_encode(decoded) != value:
        raise InfrastructureIngressError(
            "jws_encoding_invalid",
            f"JWS {field} exceeds bounds or is not canonical.",
        )
    return decoded


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _recv_before_deadline(
    connection: socket.socket, maximum: int, *, deadline: float
) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise InfrastructureIngressError(
            "request_timeout",
            "The request exceeded its absolute ingress deadline.",
            status=408,
        )
    connection.settimeout(remaining)
    try:
        return connection.recv(maximum)
    except socket.timeout as error:
        raise InfrastructureIngressError(
            "request_timeout",
            "The request exceeded its absolute ingress deadline.",
            status=408,
        ) from error


def _read_trusted_file(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int | None,
    maximum_bytes: int,
    allowed_modes: set[int],
    subject: str,
) -> bytes:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise InfrastructureIngressError(
            "trusted_file_invalid",
            f"{subject} path is not absolute and traversal-free.",
            status=503,
        )
    try:
        refuse_symlink_components(candidate)
    except (OSError, PermissionError) as error:
        raise InfrastructureIngressError(
            "trusted_file_invalid",
            f"{subject} path is missing or contains a symbolic link.",
            status=503,
        ) from error
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise InfrastructureIngressError(
            "trusted_file_invalid",
            "O_NOFOLLOW is required for trusted ingress files.",
            status=503,
        )
    flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(candidate, flags)
    except OSError as error:
        raise InfrastructureIngressError(
            "trusted_file_invalid",
            f"{subject} cannot be opened safely.",
            status=503,
        ) from error
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or (
                mode & 0o070
                and not mode & 0o007
                and (
                    expected_gid is None
                    or before.st_gid != int(expected_gid)
                )
            )
            or mode not in allowed_modes
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > maximum_bytes
        ):
            raise InfrastructureIngressError(
                "trusted_file_invalid",
                f"{subject} owner, mode, links, type, or size is invalid.",
                status=503,
            )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise InfrastructureIngressError(
                    "trusted_file_invalid",
                    f"{subject} was truncated during read.",
                    status=503,
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise InfrastructureIngressError(
                "trusted_file_invalid",
                f"{subject} grew during read.",
                status=503,
            )
        after = os.fstat(descriptor)
        if (
            (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            or after.st_uid != expected_uid
            or stat.S_IMODE(after.st_mode) != mode
            or after.st_nlink != 1
        ):
            raise InfrastructureIngressError(
                "trusted_file_invalid",
                f"{subject} changed while it was read.",
                status=503,
            )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _require_tls_file(
    path: Path, *, trusted_owner_uid: int, private: bool
) -> bytes:
    allowed = {0o400, 0o440, 0o600, 0o640} if private else {
        0o400,
        0o440,
        0o444,
        0o600,
        0o640,
        0o644,
    }
    return _read_trusted_file(
        path,
        expected_uid=trusted_owner_uid,
        expected_gid=os.getegid(),
        maximum_bytes=MAX_CA_OR_CRL_BYTES,
        allowed_modes=allowed,
        subject="server private key" if private else "server certificate",
    )


def _require_private_artifact_root(path: Path, *, expected_uid: int) -> None:
    try:
        refuse_symlink_components(path)
        metadata = path.lstat()
    except (OSError, PermissionError) as error:
        raise InfrastructureIngressError(
            "artifact_root_invalid",
            "The ingress artifact root is missing or unsafe.",
            status=503,
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise InfrastructureIngressError(
            "artifact_root_invalid",
            "The ingress artifact root must be a private service-owned directory.",
            status=503,
        )


def _safe_log(event: str, **values: Any) -> None:
    allowed: dict[str, Any] = {"event": event}
    for key in ("code", "operation_id", "artifact_sha256"):
        value = values.get(key)
        if isinstance(value, str) and len(value) <= 128:
            allowed[key] = value
    _LOGGER.info(canonical_json(allowed))


def _epoch(value: datetime) -> int:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return int(value.timestamp())


def _exact_object(
    value: Any, fields: set[str], *, subject: str
) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise InfrastructureIngressError(
            "configuration_invalid",
            f"{subject} fields are invalid.",
            status=503,
        )
    return value


def _absolute_path(value: Any, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise InfrastructureIngressError(
            "configuration_invalid", f"{field} must be an absolute path.", status=503
        )
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise InfrastructureIngressError(
            "configuration_invalid",
            f"{field} must be absolute and traversal-free.",
            status=503,
        )
    return path


def _identifier(value: Any, field: str, *, public_status: int = 503) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise InfrastructureIngressError(
            (
                "jws_header_invalid"
                if public_status < 500
                else "configuration_invalid"
            ),
            f"{field} is invalid.",
            status=public_status,
        )
    return value


def _integer(
    value: Any,
    field: str,
    minimum: int,
    maximum: int,
    *,
    public_status: int = 503,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise InfrastructureIngressError(
            (
                "jws_header_invalid"
                if public_status < 500
                else "configuration_invalid"
            ),
            f"{field} is outside its integer bound.",
            status=public_status,
        )
    return value


def _number(
    value: Any, field: str, minimum: float, maximum: float
) -> float:
    if type(value) not in {int, float} or not minimum <= float(value) <= maximum:
        raise InfrastructureIngressError(
            "configuration_invalid",
            f"{field} is outside its numeric bound.",
            status=503,
        )
    return float(value)


def _ipv4_literal(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise InfrastructureIngressError(
            "configuration_invalid", f"{field} must be IPv4.", status=503
        )
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise InfrastructureIngressError(
            "configuration_invalid", f"{field} must be IPv4.", status=503
        ) from error
    if not isinstance(address, ipaddress.IPv4Address):
        raise InfrastructureIngressError(
            "configuration_invalid", f"{field} must be IPv4.", status=503
        )
    return str(address)


def _bounded_ascii(
    value: Any, field: str, minimum: int, maximum: int
) -> str:
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or not value.isascii()
        or any(ord(character) < 33 or ord(character) > 126 for character in value)
    ):
        raise InfrastructureIngressError(
            "configuration_invalid", f"{field} is invalid.", status=503
        )
    return value


__all__ = [
    "AdmittedTransport",
    "BrokerGateway",
    "FixedWindowRateLimiter",
    "INGRESS_CONFIG_SCHEMA",
    "INGRESS_PATH",
    "IngressApplication",
    "IngressConfig",
    "IngressLimits",
    "InfrastructureIngressError",
    "InfrastructureIngressServer",
    "ParsedJWS",
    "PeerCertificate",
    "TrustSnapshot",
    "build_tls_context",
    "load_ingress_config",
    "parse_compact_jws",
    "read_strict_http_request",
    "require_cryptography_runtime",
    "run_ingress",
    "validate_peer_certificate",
    "validate_private_ca_and_crl",
    "validate_server_certificate_identity",
    "verify_jws_and_context",
]
