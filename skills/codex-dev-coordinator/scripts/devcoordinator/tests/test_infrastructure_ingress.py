"""Failure-shaped tests for the dedicated infrastructure network ingress."""

from __future__ import annotations

import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from devcoordinator.infrastructure_artifacts import (
    InfrastructureArtifactError,
    _read_private_file,
    publish_staged_signed_envelope,
    stage_signed_envelope,
)
from devcoordinator.infrastructure_ingress import (
    BrokerGateway,
    INGRESS_PATH,
    FixedWindowRateLimiter,
    IngressApplication,
    IngressConfig,
    IngressLimits,
    InfrastructureIngressError,
    InfrastructureIngressServer,
    build_tls_context,
    parse_compact_jws,
    read_strict_http_request,
    require_cryptography_runtime,
    validate_peer_certificate,
    validate_private_ca_and_crl,
    validate_server_certificate_identity,
    verify_jws_and_context,
    _read_trusted_file,
)
from devcoordinator.broker import BrokerError
from devcoordinator.infrastructure_observation import (
    INFRASTRUCTURE_JWS_TYPE,
    INFRASTRUCTURE_SCHEMA,
    infrastructure_scope_sha256,
)
from devcoordinator.store import canonical_json, utc_timestamp


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _pem_private_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


class FakeBroker:
    def __init__(self, context: dict) -> None:
        self.context = dict(context)
        self.verification_calls: list[tuple[str, int]] = []
        self.ingest_calls: list[tuple[str, dict]] = []
        self.accepted_by_operation: dict[str, dict] = {}
        self.fail_after_commit_once = False
        self.reject_code: str | None = None

    def verification_context(
        self, *, fingerprint_sha256: str, generation: int
    ) -> dict:
        self.verification_calls.append((fingerprint_sha256, generation))
        return dict(self.context)

    def ingest(self, *, arguments: dict, operation_id: str) -> dict:
        self.ingest_calls.append((operation_id, dict(arguments)))
        if self.reject_code is not None:
            raise InfrastructureIngressError(
                self.reject_code, "fixture rejection", status=409
            )
        result = self.accepted_by_operation.setdefault(
            operation_id,
            {
                "status": "accepted",
                "observation_id": arguments["observation"]["observation_id"],
                "accepted_at": "2026-07-29T12:00:00Z",
                "evidence_available": True,
                "signed_envelope_sha256": arguments["artifact"]["sha256"],
                "signed_envelope_locator": (
                    "sha256:" + arguments["artifact"]["sha256"]
                ),
            },
        )
        if self.fail_after_commit_once:
            self.fail_after_commit_once = False
            raise InfrastructureIngressError(
                "broker_unavailable",
                "fixture lost response after commit",
                status=503,
            )
        return dict(result)


class MemorySocket:
    def __init__(
        self, payload: bytes, *, timeout_on_recv: bool = False, pending: int = 0
    ) -> None:
        self.payload = bytearray(payload)
        self.timeout_on_recv = timeout_on_recv
        self._pending = pending
        self.timeouts: list[float] = []

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def recv(self, maximum: int) -> bytes:
        if self.timeout_on_recv:
            raise socket.timeout()
        if not self.payload:
            return b""
        chunk = bytes(self.payload[:maximum])
        del self.payload[:maximum]
        return chunk

    def pending(self) -> int:
        return self._pending


class InfrastructureIngressTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.now = int(datetime.now(tz=timezone.utc).timestamp())
        cls.ca_key, cls.ca_certificate = cls._make_ca("SPECTRE Test Client CA")
        cls.other_ca_key, cls.other_ca_certificate = cls._make_ca(
            "Wrong Test Client CA"
        )
        cls.jws_key = rsa.generate_private_key(
            public_exponent=65537, key_size=3072
        )
        cls.other_jws_key = rsa.generate_private_key(
            public_exponent=65537, key_size=3072
        )

    @classmethod
    def _make_ca(cls, name: str) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(
                datetime.fromtimestamp(cls.now - 3600, tz=timezone.utc)
            )
            .not_valid_after(
                datetime.fromtimestamp(
                    cls.now + 365 * 24 * 60 * 60, tz=timezone.utc
                )
            )
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        return key, certificate

    @classmethod
    def _make_crl(
        cls,
        *,
        issuer_key: rsa.RSAPrivateKey | None = None,
        issuer_certificate: x509.Certificate | None = None,
        last_offset: int = -60,
        next_offset: int = 3600,
        revoked_serial: int | None = None,
    ) -> x509.CertificateRevocationList:
        key = issuer_key or cls.ca_key
        certificate = issuer_certificate or cls.ca_certificate
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(certificate.subject)
            .last_update(
                datetime.fromtimestamp(cls.now + last_offset, tz=timezone.utc)
            )
            .next_update(
                datetime.fromtimestamp(cls.now + next_offset, tz=timezone.utc)
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    key.public_key()
                ),
                critical=False,
            )
        )
        if revoked_serial is not None:
            revoked = (
                x509.RevokedCertificateBuilder()
                .serial_number(revoked_serial)
                .revocation_date(
                    datetime.fromtimestamp(cls.now - 30, tz=timezone.utc)
                )
                .build()
            )
            builder = builder.add_revoked_certificate(revoked)
        return builder.sign(key, hashes.SHA256())

    @classmethod
    def _make_leaf(
        cls,
        *,
        valid_from: int | None = None,
        valid_until: int | None = None,
        eku: list[x509.ObjectIdentifier] | None = None,
        server_name: str | None = None,
        issuer_key: rsa.RSAPrivateKey | None = None,
        issuer_certificate: x509.Certificate | None = None,
    ) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        issuer_key = issuer_key or cls.ca_key
        issuer_certificate = issuer_certificate or cls.ca_certificate
        subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "SPECTRE observer fixture")]
        )
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_certificate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(
                datetime.fromtimestamp(
                    valid_from if valid_from is not None else cls.now - 60,
                    tz=timezone.utc,
                )
            )
            .not_valid_after(
                datetime.fromtimestamp(
                    valid_until if valid_until is not None else cls.now + 3600,
                    tz=timezone.utc,
                )
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(
                x509.ExtendedKeyUsage(
                    eku
                    if eku is not None
                    else [ExtendedKeyUsageOID.CLIENT_AUTH]
                ),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        )
        if server_name is not None:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(server_name)]),
                critical=False,
            )
        certificate = builder.sign(issuer_key, hashes.SHA256())
        return key, certificate

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".infrastructure-ingress-", dir="/tmp"
        )
        self.root = Path(self.temporary.name)
        self.artifact_root = self.root / "artifacts"
        self.broker_artifact_root = self.root / "broker-artifacts"
        self.artifact_root.mkdir(mode=0o700)
        self.broker_artifact_root.mkdir(mode=0o700)
        self.leaf_key, self.leaf = self._make_leaf()
        self.leaf_der = self.leaf.public_bytes(serialization.Encoding.DER)
        self.crl = self._make_crl()
        self.ca_pem = self.ca_certificate.public_bytes(
            serialization.Encoding.PEM
        )
        self.crl_pem = self.crl.public_bytes(serialization.Encoding.PEM)
        self.trust = validate_private_ca_and_crl(
            self.ca_pem,
            self.crl_pem,
            now_epoch=self.now,
            crl_max_age_seconds=600,
        )
        self.peer = validate_peer_certificate(
            self.leaf_der,
            [self.leaf_der, self.trust.ca_der],
            self.trust,
            now_epoch=self.now,
        )
        self.vm_id = str(uuid.uuid4())
        self.host_id = str(uuid.uuid4())
        self.agent_id = str(uuid.uuid4())
        self.cell_id = str(uuid.uuid4())
        self.scope_sha256 = infrastructure_scope_sha256(
            self.host_id, {self.vm_id: "ingress"}
        )
        self.observation = {
            "schema": INFRASTRUCTURE_SCHEMA,
            "observation_id": str(uuid.uuid4()),
            "cell_id": self.cell_id,
            "host_id": self.host_id,
            "agent_id": self.agent_id,
            "agent_boot_id": str(uuid.uuid4()),
            "sequence": 1,
            "captured_at": utc_timestamp(self.now),
            "roster_complete": True,
            "roster_error_code": None,
            "host": {
                "hostname": "SPECTRE-HV",
                "platform": "windows-hyperv",
                "platform_version": "Windows Server 2022",
                "management_addresses": ["10.0.10.211"],
                "logical_cpu": 40,
                "physical_memory_bytes": 128 * 1024**3,
                "uptime_seconds": 100,
            },
            "virtual_machines": [
                {
                    "vm_id": self.vm_id,
                    "name": "SPECTRE-LAB-INGRESS-01",
                    "role": "ingress",
                    "state": "off",
                    "generation": 2,
                    "vcpu": 2,
                    "startup_memory_bytes": 2 * 1024**3,
                    "assigned_memory_bytes": 0,
                    "ip_addresses": [],
                    "heartbeat": "not-running",
                    "automatic_checkpoints": False,
                    "replication": "disabled",
                }
            ],
            "evidence": {
                "observer_version": "1.0.0",
                "scope_sha256": self.scope_sha256,
            },
        }
        self.spki_der = self.jws_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.spki_sha256 = hashlib.sha256(self.spki_der).hexdigest()
        self.context = {
            "schema": "spectre.infrastructure.verification-context.v1",
            "certificate_fingerprint_sha256": self.peer.fingerprint_sha256,
            "certificate_generation": 1,
            "jws_key_id": "fixture-key-generation-1",
            "jws_algorithm": "PS256",
            "jws_spki_der_base64": base64.b64encode(self.spki_der).decode(
                "ascii"
            ),
            "jws_spki_sha256": self.spki_sha256,
            "agent_id": self.agent_id,
            "host_id": self.host_id,
            "cell_id": self.cell_id,
            "assigned_scope_sha256": self.scope_sha256,
            "host_scope_sha256": self.scope_sha256,
            "valid_from_epoch": self.peer.valid_from_epoch,
            "valid_until_epoch": self.peer.valid_until_epoch,
            "revoked": False,
            "revoked_at": None,
            "revocation_reason": None,
            "agent_enabled": True,
            "host_enabled": True,
            "cell_enabled": True,
            "scope_current": True,
            "valid_at_lookup": True,
            "eligible_at_lookup": True,
            "lookup_epoch": self.now,
        }
        self.config = IngressConfig(
            listen_host="127.0.0.1",
            listen_port=19443,
            public_host="spectre.classified.guru:9443",
            server_certificate_path=self.root / "server.pem",
            server_private_key_path=self.root / "server.key",
            server_certificate_generation=1,
            server_certificate_sha256="0" * 64,
            server_certificate_valid_from_epoch=0,
            server_certificate_valid_until_epoch=1,
            client_ca_certificate_path=self.root / "ca.pem",
            client_crl_path=self.root / "ca.crl",
            artifact_root=self.artifact_root,
            broker_socket_path=self.root / "broker.sock",
            expected_broker_uid=os.geteuid(),
            expected_socket_gid=os.getegid(),
            expected_socket_mode=0o660,
            authority_generation="fixture-generation",
            account_id="fixture-ingress",
            limits=IngressLimits(
                handshake_timeout_seconds=5,
                request_timeout_seconds=5,
                max_header_bytes=16 * 1024,
                max_body_bytes=768 * 1024,
                max_concurrency=2,
                rate_per_certificate_per_minute=10,
                rate_per_ip_per_minute=20,
                crl_max_age_seconds=600,
            ),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def compact_jws(
        self,
        *,
        observation: dict | None = None,
        key: rsa.RSAPrivateKey | None = None,
        key_id: str = "fixture-key-generation-1",
        generation: int = 1,
        fingerprint: str | None = None,
        spki_sha256: str | None = None,
        canonical_payload: bool = True,
        signature_flip: bool = False,
    ) -> bytes:
        document = observation or self.observation
        header = {
            "alg": "PS256",
            "typ": INFRASTRUCTURE_JWS_TYPE,
            "kid": key_id,
            "x5t#S256": _b64url(
                bytes.fromhex(fingerprint or self.peer.fingerprint_sha256)
            ),
            "cert_generation": generation,
            "spki_sha256": spki_sha256 or self.spki_sha256,
        }
        header_segment = _b64url(canonical_json(header).encode("utf-8"))
        payload_text = canonical_json(document)
        if not canonical_payload:
            payload_text = json.dumps(document, sort_keys=True, indent=2)
        payload_segment = _b64url(payload_text.encode("utf-8"))
        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
        signature = (key or self.jws_key).sign(
            signing_input,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        if signature_flip:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        return (
            signing_input
            + b"."
            + _b64url(signature).encode("ascii")
        )

    def test_pinned_cryptography_runtime_is_available(self) -> None:
        version = require_cryptography_runtime()
        self.assertEqual(version, "49.0.0")

    def test_runtime_rejects_dependency_version_drift(self) -> None:
        versions = {
            "cryptography": "49.0.0",
            "cffi": "2.0.1",
            "pycparser": "2.22",
        }
        with mock.patch(
            "devcoordinator.infrastructure_ingress.importlib_metadata.version",
            side_effect=lambda package: versions[package],
        ):
            with self.assertRaises(InfrastructureIngressError) as caught:
                require_cryptography_runtime()
        self.assertEqual(
            caught.exception.code,
            "cryptography_runtime_dependency_version_unsupported",
        )

    def test_deployment_dependency_closure_is_exact_and_hash_locked(self) -> None:
        lock = (
            Path(__file__).resolve().parents[3]
            / "requirements-infrastructure-ingress.txt"
        ).read_text(encoding="utf-8")
        for requirement, digest in {
            "cryptography==49.0.0": (
                "cbc77da8c523d5abd028635ba850a6966"
                "fcee2c82e2bf65a41d1d8afe0f98be9"
            ),
            "cffi==2.0.0": (
                "afb8db5439b81cf9c9d0c80404b60c3"
                "cc9c3add93e114dcae767f1477cb53775"
            ),
            "pycparser==2.22": (
                "c3702b6d3dd8c7abc1afa565d7e63d53"
                "a1d0bd86cdc24edd75470f4de499cfcc"
            ),
        }.items():
            self.assertIn(requirement, lock)
            self.assertIn(f"--hash=sha256:{digest}", lock)
        self.assertNotIn("cryptography==46.0.5", lock)

    def test_tls_context_is_tls13_client_required_and_crl_chain_checked(self) -> None:
        server_key, server_certificate = self._make_leaf(
            eku=[ExtendedKeyUsageOID.SERVER_AUTH],
            server_name="spectre.classified.guru",
        )
        self.config.server_certificate_path.write_bytes(
            server_certificate.public_bytes(serialization.Encoding.PEM)
        )
        self.config.server_private_key_path.write_bytes(
            _pem_private_key(server_key)
        )
        self.config.client_ca_certificate_path.write_bytes(self.ca_pem)
        self.config.client_crl_path.write_bytes(self.crl_pem)
        self.config.server_certificate_path.chmod(0o600)
        self.config.server_private_key_path.chmod(0o600)
        self.config.client_ca_certificate_path.chmod(0o600)
        self.config.client_crl_path.chmod(0o600)
        server_der = server_certificate.public_bytes(
            serialization.Encoding.DER
        )
        server_config = replace(
            self.config,
            server_certificate_sha256=hashlib.sha256(server_der).hexdigest(),
            server_certificate_valid_from_epoch=int(
                server_certificate.not_valid_before_utc.timestamp()
            ),
            server_certificate_valid_until_epoch=int(
                server_certificate.not_valid_after_utc.timestamp()
            ),
        )
        context, snapshot = build_tls_context(
            server_config,
            now_epoch=self.now,
            trusted_public_owner_uid=os.geteuid(),
        )
        self.assertEqual(context.minimum_version.name, "TLSv1_3")
        self.assertEqual(context.maximum_version.name, "TLSv1_3")
        self.assertEqual(context.verify_mode.name, "CERT_REQUIRED")
        self.assertTrue(context.verify_flags & ssl.VERIFY_CRL_CHECK_CHAIN)
        self.assertEqual(snapshot.crl_sha256, self.trust.crl_sha256)

        with self.assertRaises(InfrastructureIngressError) as mismatch:
            build_tls_context(
                replace(
                    server_config,
                    server_certificate_sha256="0" * 64,
                ),
                now_epoch=self.now,
                trusted_public_owner_uid=os.geteuid(),
            )
        self.assertEqual(
            mismatch.exception.code,
            "server_certificate_generation_mismatch",
        )

    def test_server_leaf_generation_cannot_exceed_seven_days(self) -> None:
        server_key, server_certificate = self._make_leaf(
            valid_from=self.now - 60,
            valid_until=self.now + 8 * 24 * 60 * 60,
            eku=[ExtendedKeyUsageOID.SERVER_AUTH],
            server_name="spectre.classified.guru",
        )
        self.config.server_certificate_path.write_bytes(
            server_certificate.public_bytes(serialization.Encoding.PEM)
        )
        self.config.server_private_key_path.write_bytes(
            _pem_private_key(server_key)
        )
        self.config.client_ca_certificate_path.write_bytes(self.ca_pem)
        self.config.client_crl_path.write_bytes(self.crl_pem)
        for path in (
            self.config.server_certificate_path,
            self.config.server_private_key_path,
            self.config.client_ca_certificate_path,
            self.config.client_crl_path,
        ):
            path.chmod(0o600)
        server_der = server_certificate.public_bytes(
            serialization.Encoding.DER
        )
        long_generation = replace(
            self.config,
            server_certificate_sha256=hashlib.sha256(server_der).hexdigest(),
            server_certificate_valid_from_epoch=int(
                server_certificate.not_valid_before_utc.timestamp()
            ),
            server_certificate_valid_until_epoch=int(
                server_certificate.not_valid_after_utc.timestamp()
            ),
        )
        with self.assertRaises(InfrastructureIngressError) as rejected:
            build_tls_context(
                long_generation,
                now_epoch=self.now,
                trusted_public_owner_uid=os.geteuid(),
            )
        self.assertEqual(
            rejected.exception.code,
            "server_certificate_generation_mismatch",
        )

    def test_server_identity_rejects_client_leaf_and_wrong_dns(self) -> None:
        with self.assertRaises(InfrastructureIngressError) as caught:
            validate_server_certificate_identity(
                self.leaf.public_bytes(serialization.Encoding.PEM),
                public_host="spectre.classified.guru:9443",
                now_epoch=self.now,
            )
        self.assertEqual(
            caught.exception.code,
            "server_certificate_usage_invalid",
        )

        _key, wrong_dns = self._make_leaf(
            eku=[ExtendedKeyUsageOID.SERVER_AUTH],
            server_name="wrong.classified.guru",
        )
        with self.assertRaises(InfrastructureIngressError) as caught:
            validate_server_certificate_identity(
                wrong_dns.public_bytes(serialization.Encoding.PEM),
                public_host="spectre.classified.guru:9443",
                now_epoch=self.now,
            )
        self.assertEqual(
            caught.exception.code,
            "server_certificate_identity_invalid",
        )

    def test_valid_mtls_jws_artifact_and_broker_acceptance(self) -> None:
        broker = FakeBroker(self.context)
        application = IngressApplication(
            self.config, broker=broker, clock=lambda: self.now
        )
        compact = self.compact_jws()
        result = application.process(
            compact,
            leaf_der=self.leaf_der,
            verified_chain_der=[self.leaf_der, self.trust.ca_der],
            trust=self.trust,
            source_ip="10.0.10.211",
        )
        digest = hashlib.sha256(compact).hexdigest()
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["artifact_sha256"], digest)
        self.assertEqual(len(broker.verification_calls), 1)
        self.assertEqual(len(broker.ingest_calls), 1)
        operation_id, arguments = broker.ingest_calls[0]
        self.assertEqual(
            operation_id,
            str(
                uuid.uuid5(
                    uuid.UUID("eb965d2e-2cb7-4eb6-8a16-f60f1a6afaa2"),
                    digest,
                )
            ),
        )
        self.assertEqual(arguments["artifact"]["sha256"], digest)
        retained = (
            self.artifact_root
            / "sha256"
            / digest[:2]
            / f"{digest}.jws"
        )
        self.assertEqual(retained.read_bytes(), compact)
        self.assertEqual(retained.stat().st_mode & 0o777, 0o400)

    def test_wrong_ca_chain_eku_validity_and_revocation_fail_closed(self) -> None:
        with self.subTest("wrong-ca"):
            wrong_der = self.other_ca_certificate.public_bytes(
                serialization.Encoding.DER
            )
            with self.assertRaises(InfrastructureIngressError) as error:
                validate_peer_certificate(
                    self.leaf_der,
                    [self.leaf_der, wrong_der],
                    self.trust,
                    now_epoch=self.now,
                )
            self.assertEqual(error.exception.code, "client_chain_mismatch")

        with self.subTest("wrong-eku"):
            _key, wrong_eku = self._make_leaf(
                eku=[ExtendedKeyUsageOID.SERVER_AUTH]
            )
            wrong_eku_der = wrong_eku.public_bytes(serialization.Encoding.DER)
            with self.assertRaises(InfrastructureIngressError) as error:
                validate_peer_certificate(
                    wrong_eku_der,
                    [wrong_eku_der, self.trust.ca_der],
                    self.trust,
                    now_epoch=self.now,
                )
            self.assertEqual(error.exception.code, "client_certificate_eku_invalid")

        for label, valid_from, valid_until, expected in (
            (
                "not-yet-valid",
                self.now + 60,
                self.now + 3600,
                "client_certificate_not_yet_valid",
            ),
            (
                "expired",
                self.now - 3600,
                self.now,
                "client_certificate_expired",
            ),
            (
                "too-long",
                self.now - 60,
                self.now + 30 * 24 * 60 * 60 + 60,
                "client_certificate_lifetime_invalid",
            ),
        ):
            with self.subTest(label):
                _key, certificate = self._make_leaf(
                    valid_from=valid_from, valid_until=valid_until
                )
                encoded = certificate.public_bytes(serialization.Encoding.DER)
                with self.assertRaises(InfrastructureIngressError) as error:
                    validate_peer_certificate(
                        encoded,
                        [encoded, self.trust.ca_der],
                        self.trust,
                        now_epoch=self.now,
                    )
                self.assertEqual(error.exception.code, expected)

        revoked_trust = validate_private_ca_and_crl(
            self.ca_pem,
            self._make_crl(revoked_serial=self.leaf.serial_number).public_bytes(
                serialization.Encoding.PEM
            ),
            now_epoch=self.now,
            crl_max_age_seconds=600,
        )
        with self.assertRaises(InfrastructureIngressError) as revoked:
            validate_peer_certificate(
                self.leaf_der,
                [self.leaf_der, revoked_trust.ca_der],
                revoked_trust,
                now_epoch=self.now,
            )
        self.assertEqual(revoked.exception.code, "client_certificate_revoked")

    def test_crl_missing_stale_future_expired_and_wrong_issuer_rejected(self) -> None:
        cases = (
            (
                "missing",
                b"",
                "crl_invalid",
            ),
            (
                "stale",
                self._make_crl(last_offset=-601).public_bytes(
                    serialization.Encoding.PEM
                ),
                "crl_stale",
            ),
            (
                "future",
                self._make_crl(last_offset=1).public_bytes(
                    serialization.Encoding.PEM
                ),
                "crl_not_yet_valid",
            ),
            (
                "expired",
                self._make_crl(last_offset=-3600, next_offset=0).public_bytes(
                    serialization.Encoding.PEM
                ),
                "crl_expired",
            ),
            (
                "wrong-issuer",
                self._make_crl(
                    issuer_key=self.other_ca_key,
                    issuer_certificate=self.other_ca_certificate,
                ).public_bytes(serialization.Encoding.PEM),
                "crl_wrong_issuer",
            ),
        )
        for label, crl_pem, expected in cases:
            with self.subTest(label):
                with self.assertRaises(InfrastructureIngressError) as error:
                    validate_private_ca_and_crl(
                        self.ca_pem,
                        crl_pem,
                        now_epoch=self.now,
                        crl_max_age_seconds=600,
                    )
                self.assertEqual(error.exception.code, expected)

    def test_jws_wrong_fingerprint_key_kid_generation_signature_and_scope(self) -> None:
        cases: list[tuple[str, bytes, str]] = [
            (
                "fingerprint",
                self.compact_jws(fingerprint="f" * 64),
                "certificate_fingerprint_mismatch",
            ),
            (
                "key",
                self.compact_jws(key=self.other_jws_key),
                "jws_signature_invalid",
            ),
            (
                "kid",
                self.compact_jws(key_id="wrong-kid"),
                "verification_context_mismatch",
            ),
            (
                "generation",
                self.compact_jws(generation=2),
                "verification_context_mismatch",
            ),
            (
                "signature",
                self.compact_jws(signature_flip=True),
                "jws_signature_invalid",
            ),
        ]
        wrong_scope = dict(self.observation)
        wrong_scope["evidence"] = dict(self.observation["evidence"])
        wrong_scope["evidence"]["scope_sha256"] = "f" * 64
        cases.append(
            ("scope", self.compact_jws(observation=wrong_scope), "scope_mismatch")
        )
        for label, compact, expected in cases:
            with self.subTest(label):
                parsed = parse_compact_jws(compact)
                with self.assertRaises(InfrastructureIngressError) as error:
                    verify_jws_and_context(
                        parsed,
                        peer=self.peer,
                        broker=FakeBroker(self.context),
                        now_epoch=self.now,
                    )
                self.assertEqual(error.exception.code, expected)

    def test_noncanonical_payload_and_closed_header_are_rejected(self) -> None:
        with self.assertRaises(InfrastructureIngressError) as noncanonical:
            parse_compact_jws(self.compact_jws(canonical_payload=False))
        self.assertEqual(
            noncanonical.exception.code, "noncanonical_json_payload"
        )

        compact = self.compact_jws()
        header_segment, payload_segment, _signature = compact.decode().split(".")
        header = json.loads(
            base64.urlsafe_b64decode(header_segment + "==").decode("utf-8")
        )
        header["extra"] = True
        new_header = _b64url(canonical_json(header).encode("utf-8"))
        signing_input = f"{new_header}.{payload_segment}".encode("ascii")
        signature = self.jws_key.sign(
            signing_input,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        with self.assertRaises(InfrastructureIngressError) as closed:
            parse_compact_jws(signing_input + b"." + _b64url(signature).encode())
        self.assertEqual(closed.exception.code, "jws_header_invalid")

    def test_context_expiry_revocation_and_validity_mismatch_fail_closed(self) -> None:
        cases = []
        revoked = dict(self.context)
        revoked.update(
            {
                "revoked": True,
                "revoked_at": "2026-07-29T00:00:00Z",
                "revocation_reason": "fixture",
                "eligible_at_lookup": False,
            }
        )
        cases.append(("revoked", revoked, "enrollment_not_eligible"))
        mismatch = dict(self.context)
        mismatch["valid_until_epoch"] += 1
        cases.append(
            (
                "validity",
                mismatch,
                "certificate_validity_binding_mismatch",
            )
        )
        parsed = parse_compact_jws(self.compact_jws())
        for label, context, expected in cases:
            with self.subTest(label):
                with self.assertRaises(InfrastructureIngressError) as error:
                    verify_jws_and_context(
                        parsed,
                        peer=self.peer,
                        broker=FakeBroker(context),
                        now_epoch=self.now,
                    )
                self.assertEqual(error.exception.code, expected)

    def http_request(
        self,
        body: bytes,
        *,
        extra_headers: list[tuple[str, str]] | None = None,
        content_length: str | None = None,
        connection: str = "close",
    ) -> bytes:
        headers = [
            ("Host", self.config.public_host),
            ("Content-Type", "application/jose"),
            (
                "Content-Length",
                str(len(body)) if content_length is None else content_length,
            ),
            ("Connection", connection),
        ]
        headers.extend(extra_headers or [])
        lines = [f"POST {INGRESS_PATH} HTTP/1.1"]
        lines.extend(f"{name}: {value}" for name, value in headers)
        return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body

    def test_http_post_is_exact_and_rejects_transfer_ambiguity(self) -> None:
        body = self.compact_jws()
        parsed = read_strict_http_request(
            MemorySocket(self.http_request(body)), self.config
        )
        self.assertEqual(parsed, body)
        cases = (
            (
                "chunked",
                self.http_request(
                    body, extra_headers=[("Transfer-Encoding", "chunked")]
                ),
                "transfer_ambiguity",
            ),
            (
                "compressed",
                self.http_request(
                    body, extra_headers=[("Content-Encoding", "gzip")]
                ),
                "transfer_ambiguity",
            ),
            (
                "duplicate-length",
                self.http_request(
                    body, extra_headers=[("Content-Length", str(len(body)))]
                ),
                "http_header_ambiguous",
            ),
            (
                "keep-alive",
                self.http_request(body, connection="keep-alive"),
                "connection_reuse_rejected",
            ),
            (
                "leading-zero",
                self.http_request(body, content_length=f"0{len(body)}"),
                "content_length_invalid",
            ),
        )
        for label, request, expected in cases:
            with self.subTest(label):
                with self.assertRaises(InfrastructureIngressError) as error:
                    read_strict_http_request(MemorySocket(request), self.config)
                self.assertEqual(error.exception.code, expected)

    def test_http_oversize_slowloris_and_pipelining_are_bounded(self) -> None:
        body = b"x"
        oversized = self.http_request(
            body, content_length=str(self.config.limits.max_body_bytes + 1)
        )
        with self.assertRaises(InfrastructureIngressError) as error:
            read_strict_http_request(MemorySocket(oversized), self.config)
        self.assertEqual(error.exception.code, "signed_envelope_oversized")

        with self.assertRaises(InfrastructureIngressError) as slow:
            read_strict_http_request(
                MemorySocket(b"", timeout_on_recv=True), self.config
            )
        self.assertEqual(slow.exception.code, "request_timeout")
        self.assertEqual(slow.exception.status, 408)

        pipelined = self.http_request(body) + b"GET / HTTP/1.1\r\n\r\n"
        with self.assertRaises(InfrastructureIngressError) as pipeline:
            read_strict_http_request(MemorySocket(pipelined), self.config)
        self.assertEqual(
            pipeline.exception.code, "request_pipelining_rejected"
        )

    def test_rate_and_concurrency_bounds_fail_closed(self) -> None:
        limiter = FixedWindowRateLimiter(certificate_limit=2, ip_limit=3)
        limiter.admit(certificate="a" * 64, source_ip="10.0.0.1", now=10.0)
        limiter.admit(certificate="a" * 64, source_ip="10.0.0.1", now=11.0)
        with self.assertRaises(InfrastructureIngressError) as limited:
            limiter.admit(
                certificate="a" * 64, source_ip="10.0.0.1", now=12.0
            )
        self.assertEqual(limited.exception.code, "rate_limited")
        limiter.admit(certificate="a" * 64, source_ip="10.0.0.1", now=71.0)

        server = InfrastructureIngressServer(
            self.config,
            application=IngressApplication(
                self.config, broker=FakeBroker(self.context)
            ),
            trusted_public_owner_uid=os.geteuid(),
        )
        self.assertTrue(server._semaphore.acquire(blocking=False))
        self.assertTrue(server._semaphore.acquire(blocking=False))
        self.assertFalse(server._semaphore.acquire(blocking=False))
        server._semaphore.release()
        server._semaphore.release()

    def test_tls_peer_is_charged_before_a_slow_http_body_uses_worker_time(
        self,
    ) -> None:
        config = replace(
            self.config,
            limits=replace(
                self.config.limits,
                rate_per_certificate_per_minute=1,
                rate_per_ip_per_minute=1,
            ),
        )
        application = IngressApplication(
            config,
            broker=FakeBroker(self.context),
            clock=lambda: self.now,
        )
        server = InfrastructureIngressServer(
            config,
            application=application,
            trusted_public_owner_uid=os.geteuid(),
        )
        context = mock.Mock()
        tls_connection = mock.Mock()
        tls_connection.getpeercert.return_value = self.leaf_der
        context.wrap_socket.return_value = tls_connection
        events: list[str] = []
        original_admit = application.admit_transport

        def admit(**arguments: object):
            events.append("admit")
            return original_admit(**arguments)

        def slow_read(*_arguments: object, **_keywords: object) -> bytes:
            events.append("read")
            raise InfrastructureIngressError(
                "request_timeout",
                "fixture slow client",
                status=408,
            )

        with mock.patch(
            "devcoordinator.infrastructure_ingress.build_tls_context",
            return_value=(context, self.trust),
        ), mock.patch(
            "devcoordinator.infrastructure_ingress._verified_chain_der",
            return_value=[self.leaf_der, self.trust.ca_der],
        ), mock.patch.object(
            application,
            "admit_transport",
            side_effect=admit,
        ), mock.patch(
            "devcoordinator.infrastructure_ingress.read_strict_http_request",
            side_effect=slow_read,
        ), mock.patch(
            "devcoordinator.infrastructure_ingress.write_http_response"
        ):
            for _attempt in range(2):
                self.assertTrue(server._semaphore.acquire(blocking=False))
                server._handle_connection(
                    mock.Mock(),
                    ("10.0.10.211", 43123),
                )

        self.assertEqual(events, ["admit", "read", "admit"])
        self.assertEqual(
            list(application.rate_limiter._certificate_events),
            [self.peer.fingerprint_sha256],
        )
        self.assertEqual(
            list(application.rate_limiter._ip_events),
            ["10.0.10.211"],
        )

    def test_rate_limiter_key_cap_is_strict_and_existing_keys_still_work(
        self,
    ) -> None:
        limiter = FixedWindowRateLimiter(
            certificate_limit=2,
            ip_limit=2,
            key_cap=3,
        )
        for index in range(3):
            limiter.admit(
                certificate=f"cert-{index}",
                source_ip=f"10.0.0.{index + 1}",
                now=10.0,
            )
        with self.assertRaises(InfrastructureIngressError) as capped:
            limiter.admit(
                certificate="cert-3",
                source_ip="10.0.0.4",
                now=11.0,
            )
        self.assertEqual(capped.exception.code, "rate_limited")
        self.assertEqual(len(limiter._certificate_events), 3)
        self.assertEqual(len(limiter._ip_events), 3)

        limiter.admit(
            certificate="cert-0",
            source_ip="10.0.0.1",
            now=11.0,
        )
        self.assertEqual(len(limiter._certificate_events), 3)
        self.assertEqual(len(limiter._ip_events), 3)

        limiter.admit(
            certificate="cert-new",
            source_ip="10.0.0.99",
            now=71.0,
        )
        self.assertEqual(set(limiter._certificate_events), {"cert-new"})
        self.assertEqual(set(limiter._ip_events), {"10.0.0.99"})

    def test_rate_rejection_does_not_charge_the_other_identity(self) -> None:
        limiter = FixedWindowRateLimiter(
            certificate_limit=1,
            ip_limit=1,
            key_cap=8,
        )
        limiter.admit(
            certificate="cert-a",
            source_ip="10.0.0.1",
            now=10.0,
        )
        with self.assertRaises(InfrastructureIngressError):
            limiter.admit(
                certificate="cert-b",
                source_ip="10.0.0.1",
                now=11.0,
            )
        self.assertNotIn("cert-b", limiter._certificate_events)
        limiter.admit(
            certificate="cert-b",
            source_ip="10.0.0.2",
            now=12.0,
        )

        with self.assertRaises(InfrastructureIngressError):
            limiter.admit(
                certificate="cert-b",
                source_ip="10.0.0.3",
                now=13.0,
            )
        self.assertNotIn("10.0.0.3", limiter._ip_events)
        limiter.admit(
            certificate="cert-c",
            source_ip="10.0.0.3",
            now=14.0,
        )

    def test_lost_response_restart_and_replay_use_one_stable_operation(self) -> None:
        broker = FakeBroker(self.context)
        broker.fail_after_commit_once = True
        compact = self.compact_jws()
        first = IngressApplication(
            self.config, broker=broker, clock=lambda: self.now
        )
        with self.assertRaises(InfrastructureIngressError) as lost:
            first.process(
                compact,
                leaf_der=self.leaf_der,
                verified_chain_der=[self.leaf_der, self.trust.ca_der],
                trust=self.trust,
                source_ip="10.0.10.211",
            )
        self.assertEqual(lost.exception.code, "broker_unavailable")

        restarted = IngressApplication(
            self.config, broker=broker, clock=lambda: self.now
        )
        recovered = restarted.process(
            compact,
            leaf_der=self.leaf_der,
            verified_chain_der=[self.leaf_der, self.trust.ca_der],
            trust=self.trust,
            source_ip="10.0.10.211",
        )
        self.assertEqual(recovered["status"], "accepted")
        self.assertEqual(len(broker.accepted_by_operation), 1)
        self.assertEqual(
            {operation for operation, _arguments in broker.ingest_calls},
            set(broker.accepted_by_operation),
        )

    def test_broker_failure_messages_are_not_exposed_to_network_clients(self) -> None:
        gateway = BrokerGateway(self.config)
        gateway.client = mock.Mock()
        gateway.client.call.side_effect = BrokerError(
            "certificate_not_enrolled",
            "private authority path /srv/secret and internal database detail",
        )

        with self.assertRaises(InfrastructureIngressError) as rejected:
            gateway.verification_context(
                fingerprint_sha256="0" * 64,
                generation=1,
            )

        self.assertEqual(rejected.exception.code, "certificate_not_enrolled")
        self.assertEqual(rejected.exception.status, 403)
        self.assertEqual(
            rejected.exception.message,
            (
                "The Coordinator rejected the report for enrollment, identity, "
                "or scope."
            ),
        )
        self.assertNotIn("secret", rejected.exception.message)

        gateway.client.call.side_effect = None
        gateway.client.call.return_value = {
            "version": 1,
            "ok": False,
            "operation_id": "ignored",
            "error": {
                "code": "sequence_out_of_order",
                "message": "private replay-state row and internal database detail",
            },
        }
        with self.assertRaises(InfrastructureIngressError) as conflict:
            gateway.verification_context(
                fingerprint_sha256="0" * 64,
                generation=1,
            )
        self.assertEqual(conflict.exception.code, "sequence_out_of_order")
        self.assertEqual(conflict.exception.status, 409)
        self.assertNotIn("database", conflict.exception.message)

    def test_trusted_file_read_rejects_ctime_change(self) -> None:
        trusted = self.root / "trusted.pem"
        trusted.write_bytes(b"trusted")
        trusted.chmod(0o600)
        actual = trusted.stat()
        before = SimpleNamespace(
            st_mode=actual.st_mode,
            st_uid=actual.st_uid,
            st_gid=actual.st_gid,
            st_nlink=actual.st_nlink,
            st_size=actual.st_size,
            st_dev=actual.st_dev,
            st_ino=actual.st_ino,
            st_mtime_ns=actual.st_mtime_ns,
            st_ctime_ns=actual.st_ctime_ns,
        )
        after = SimpleNamespace(
            **{
                **vars(before),
                "st_ctime_ns": before.st_ctime_ns + 1,
            }
        )

        with mock.patch(
            "devcoordinator.infrastructure_ingress.os.fstat",
            side_effect=[before, after],
        ):
            with self.assertRaises(InfrastructureIngressError) as changed:
                _read_trusted_file(
                    trusted,
                    expected_uid=os.geteuid(),
                    expected_gid=os.getegid(),
                    maximum_bytes=1024,
                    allowed_modes={0o600},
                    subject="fixture",
                )

        self.assertEqual(changed.exception.code, "trusted_file_invalid")

    def test_signed_artifact_read_rejects_ctime_change(self) -> None:
        artifact = self.root / "artifact.jws"
        artifact.write_bytes(b"signed")
        artifact.chmod(0o400)
        actual = artifact.stat()
        before = SimpleNamespace(
            st_mode=actual.st_mode,
            st_uid=actual.st_uid,
            st_nlink=actual.st_nlink,
            st_size=actual.st_size,
            st_dev=actual.st_dev,
            st_ino=actual.st_ino,
            st_mtime_ns=actual.st_mtime_ns,
            st_ctime_ns=actual.st_ctime_ns,
        )
        after = SimpleNamespace(
            **{
                **vars(before),
                "st_ctime_ns": before.st_ctime_ns + 1,
            }
        )
        directory_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with mock.patch(
                "devcoordinator.infrastructure_artifacts.os.fstat",
                side_effect=[before, after],
            ):
                with self.assertRaises(InfrastructureArtifactError):
                    _read_private_file(
                        directory_fd,
                        artifact.name,
                        expected_uid=os.geteuid(),
                        maximum_bytes=1024,
                    )
        finally:
            os.close(directory_fd)

    def test_broker_rejection_retains_orphan_staging_artifact(self) -> None:
        broker = FakeBroker(self.context)
        broker.reject_code = "sequence_out_of_order"
        application = IngressApplication(
            self.config, broker=broker, clock=lambda: self.now
        )
        compact = self.compact_jws()
        digest = hashlib.sha256(compact).hexdigest()
        with self.assertRaises(InfrastructureIngressError) as rejected:
            application.process(
                compact,
                leaf_der=self.leaf_der,
                verified_chain_der=[self.leaf_der, self.trust.ca_der],
                trust=self.trust,
                source_ip="10.0.10.211",
            )
        self.assertEqual(rejected.exception.code, "sequence_out_of_order")
        retained = (
            self.artifact_root
            / "sha256"
            / digest[:2]
            / f"{digest}.jws"
        )
        self.assertEqual(retained.read_bytes(), compact)
        self.assertEqual(retained.stat().st_mode & 0o777, 0o400)

    def test_artifact_owner_mode_hash_and_broker_copy_are_proved(self) -> None:
        compact = self.compact_jws()
        artifact = stage_signed_envelope(self.artifact_root, compact)
        published = publish_staged_signed_envelope(
            staging_root=self.artifact_root,
            broker_artifact_root=self.broker_artifact_root,
            descriptor=artifact.to_dict(),
            staging_uid=os.geteuid(),
            broker_uid=os.geteuid(),
        )
        self.assertEqual(published.sha256, artifact.sha256)
        broker_path = (
            self.broker_artifact_root
            / "sha256"
            / artifact.sha256[:2]
            / f"{artifact.sha256}.jws"
        )
        before = broker_path.stat()
        self.assertEqual(before.st_mode & 0o777, 0o400)
        self.assertEqual(before.st_nlink, 1)
        self.assertEqual(broker_path.read_bytes(), compact)

        source = (
            self.artifact_root
            / "sha256"
            / artifact.sha256[:2]
            / f"{artifact.sha256}.jws"
        )
        source.chmod(0o600)
        with self.assertRaises(InfrastructureArtifactError):
            publish_staged_signed_envelope(
                staging_root=self.artifact_root,
                broker_artifact_root=self.broker_artifact_root,
                descriptor=artifact.to_dict(),
                staging_uid=os.geteuid(),
                broker_uid=os.geteuid(),
            )

    def test_broker_creates_only_missing_private_cas_leaf(self) -> None:
        self.broker_artifact_root.rmdir()
        compact = self.compact_jws()
        artifact = stage_signed_envelope(self.artifact_root, compact)
        published = publish_staged_signed_envelope(
            staging_root=self.artifact_root,
            broker_artifact_root=self.broker_artifact_root,
            descriptor=artifact.to_dict(),
            staging_uid=os.geteuid(),
            broker_uid=os.geteuid(),
        )
        self.assertEqual(published.payload, compact)
        self.assertTrue(self.broker_artifact_root.is_dir())
        self.assertEqual(
            self.broker_artifact_root.stat().st_mode & 0o777, 0o700
        )

    def test_concurrent_same_artifact_publication_is_idempotent(self) -> None:
        compact = self.compact_jws()
        errors: list[BaseException] = []
        results: list[str] = []
        barrier = threading.Barrier(8)
        lock = threading.Lock()

        def publish() -> None:
            try:
                barrier.wait(timeout=5)
                artifact = stage_signed_envelope(self.artifact_root, compact)
                with lock:
                    results.append(artifact.sha256)
            except BaseException as error:
                with lock:
                    errors.append(error)

        threads = [threading.Thread(target=publish) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertEqual(len(set(results)), 1)


if __name__ == "__main__":
    unittest.main()
